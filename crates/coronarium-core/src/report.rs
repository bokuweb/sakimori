//! Writes the aggregate [`Stats`] out in three forms:
//! - JSON audit log (machine-readable)
//! - human-readable summary (suitable for `$GITHUB_STEP_SUMMARY`)
//! - optional HTML report (via [`crate::html`])

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use anyhow::Result;

use crate::{events::Event, html, policy::Policy, stats::Stats};

/// How many rows we surface per breakdown table in the step summary.
/// Picked to fit comfortably in a GitHub run page without scrolling
/// while still showing the long tail of "wait, what's that"
/// destinations that motivate a human to look at the policy.
const SUMMARY_TOP_N: usize = 10;

pub struct ReportArgs<'a> {
    /// Destination for the JSON log. `"-"` means stdout.
    pub log: &'a str,
    /// Optional human-readable summary (markdown). Typically set to
    /// `$GITHUB_STEP_SUMMARY` so the line appears on the run page.
    pub summary: Option<&'a Path>,
    /// Optional self-contained HTML report.
    pub html: Option<&'a Path>,
    /// What the supervised process was — used as the report title.
    pub command: &'a str,
    /// Effective mode after any CLI override.
    pub mode: crate::policy::Mode,
    /// Policy passed through to the HTML "Effective policy" section.
    pub policy: &'a Policy,
}

pub fn write(args: &ReportArgs<'_>, stats: &Stats) -> Result<()> {
    // --- JSON ---
    let payload = serde_json::json!({
        "observed": stats.observed,
        "denied": stats.denied,
        "lost": stats.lost,
        "samples": stats.samples,
    });
    let serialized = serde_json::to_string_pretty(&payload)?;

    if args.log == "-" {
        writeln!(io::stdout(), "{serialized}")?;
    } else {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(args.log)?;
        writeln!(f, "{serialized}")?;
    }

    // --- stderr warning on ringbuf overflow ---
    if stats.lost > 0 {
        eprintln!(
            "warning: dropped {} events (ring buffer overflow). Numbers \
             in the summary may undercount activity.",
            stats.lost
        );
    }

    // --- $GITHUB_STEP_SUMMARY markdown ---
    if let Some(path) = args.summary {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        let body = render_step_summary(args.command, stats);
        writeln!(f, "{body}")?;
    }

    // --- HTML ---
    if let Some(path) = args.html {
        let meta = html::ReportMeta {
            title: args.command,
            mode: args.mode,
            command: args.command,
        };
        let rendered = html::render(args.policy, stats, meta);
        std::fs::write(path, rendered)?;
    }

    Ok(())
}

/// Build the markdown blob written to `$GITHUB_STEP_SUMMARY`.
///
/// The previous version was just a totals table. Real harden-runner
/// users want to see *what* the supervised step talked to, so this
/// adds three top-N breakdown tables (network destinations, file
/// paths, exec'd binaries) with denied rows flagged. Sample buffer
/// caps live in `stats::PER_KIND_CAP` — the tables can undercount
/// if a single kind floods, but `stats.observed` / `stats.denied`
/// totals are exact and shown above.
pub fn render_step_summary(command: &str, stats: &Stats) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "## coronarium\n");
    let _ = writeln!(out, "Command: `{}`\n", escape_pipe(command));
    let _ = writeln!(out, "| metric | count |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| observed | **{}** |", stats.observed);
    let _ = writeln!(out, "| denied   | **{}** |", stats.denied);
    let _ = writeln!(out, "| lost     | {} |", stats.lost);
    if stats.lost > 0 {
        let _ = writeln!(
            out,
            "\n> ⚠️ {} events were dropped due to ring-buffer overflow; \
             totals above are accurate but the breakdown tables below \
             may undercount.",
            stats.lost
        );
    }

    push_breakdown_table(
        &mut out,
        "Network — outbound connects",
        "destination",
        connect_breakdown(&stats.samples),
    );
    push_breakdown_table(
        &mut out,
        "Files — opened paths",
        "path",
        path_breakdown(&stats.samples),
    );
    push_breakdown_table(
        &mut out,
        "Processes — execve targets",
        "binary",
        exec_breakdown(&stats.samples),
    );
    out
}

/// One row in a breakdown table: label, total occurrences, and how
/// many of those were denied. The denied count is what makes the
/// row worth surfacing — a row of `(github.com:443, 12, 0)` reads
/// very differently from `(some-cdn.cn:443, 12, 12)`.
#[derive(Debug, Clone)]
struct BreakdownRow {
    label: String,
    count: u64,
    denied: u64,
}

fn push_breakdown_table(out: &mut String, title: &str, col: &str, rows: Vec<BreakdownRow>) {
    if rows.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n### {title}\n");
    let _ = writeln!(out, "| | {col} | count | denied |");
    let _ = writeln!(out, "|:-:|---|---:|---:|");
    for r in rows.iter().take(SUMMARY_TOP_N) {
        let mark = if r.denied > 0 { "❌" } else { "·" };
        let _ = writeln!(
            out,
            "| {mark} | `{}` | {} | {} |",
            escape_pipe(&r.label),
            r.count,
            r.denied,
        );
    }
    if rows.len() > SUMMARY_TOP_N {
        let _ = writeln!(
            out,
            "\n_… {} more rows omitted; full list is in the JSON log._",
            rows.len() - SUMMARY_TOP_N
        );
    }
}

fn connect_breakdown(samples: &[Event]) -> Vec<BreakdownRow> {
    let mut acc: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for ev in samples {
        if let Event::Connect {
            daddr,
            dport,
            denied,
            hostname,
            ..
        } = ev
        {
            let host = hostname.as_deref().unwrap_or(daddr.as_str());
            let key = format!("{host}:{dport}");
            let e = acc.entry(key).or_default();
            e.0 += 1;
            if *denied {
                e.1 += 1;
            }
        }
    }
    finalise(acc)
}

fn path_breakdown(samples: &[Event]) -> Vec<BreakdownRow> {
    let mut acc: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for ev in samples {
        if let Event::Open {
            filename, denied, ..
        } = ev
        {
            let e = acc.entry(filename.clone()).or_default();
            e.0 += 1;
            if *denied {
                e.1 += 1;
            }
        }
    }
    finalise(acc)
}

fn exec_breakdown(samples: &[Event]) -> Vec<BreakdownRow> {
    let mut acc: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for ev in samples {
        if let Event::Exec {
            filename, denied, ..
        } = ev
        {
            let e = acc.entry(filename.clone()).or_default();
            e.0 += 1;
            if *denied {
                e.1 += 1;
            }
        }
    }
    finalise(acc)
}

/// Sort breakdown rows: denied-first (so offenders bubble to the
/// top of the truncated table), then by raw count desc, then label
/// asc for stable output.
fn finalise(acc: BTreeMap<String, (u64, u64)>) -> Vec<BreakdownRow> {
    let mut rows: Vec<BreakdownRow> = acc
        .into_iter()
        .map(|(label, (count, denied))| BreakdownRow {
            label,
            count,
            denied,
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.denied > 0)
            .cmp(&(a.denied > 0))
            .then(b.count.cmp(&a.count))
            .then(a.label.cmp(&b.label))
    });
    rows
}

/// Markdown table cells are pipe-delimited; escape any literal `|`
/// in commands or paths so a malicious filename can't break the
/// table layout (or, more realistically, so a `bash -c "foo | bar"`
/// command line renders correctly).
fn escape_pipe(s: &str) -> String {
    s.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev_connect(host: Option<&str>, daddr: &str, dport: u16, denied: bool) -> Event {
        Event::Connect {
            pid: 1,
            uid: 0,
            comm: "x".into(),
            daddr: daddr.into(),
            dport,
            protocol: 6,
            denied,
            hostname: host.map(|s| s.into()),
        }
    }
    fn ev_open(filename: &str, denied: bool) -> Event {
        Event::Open {
            pid: 1,
            uid: 0,
            comm: "x".into(),
            filename: filename.into(),
            flags: 0,
            denied,
        }
    }
    fn ev_exec(filename: &str, denied: bool) -> Event {
        Event::Exec {
            pid: 1,
            uid: 0,
            comm: "x".into(),
            filename: filename.into(),
            argv0: filename.into(),
            denied,
        }
    }

    #[test]
    fn summary_includes_totals_and_breakdown_tables() {
        let mut stats = Stats::default();
        stats.ingest(ev_connect(Some("api.github.com"), "1.1.1.1", 443, false));
        stats.ingest(ev_connect(Some("api.github.com"), "1.1.1.1", 443, false));
        stats.ingest(ev_connect(None, "8.8.8.8", 53, true));
        stats.ingest(ev_open("/etc/hosts", false));
        stats.ingest(ev_exec("/bin/sh", false));

        let s = render_step_summary("npm install", &stats);
        // Header + command line.
        assert!(s.contains("## coronarium"));
        assert!(s.contains("`npm install`"));
        // Totals.
        assert!(s.contains("| observed | **5** |"));
        assert!(s.contains("| denied   | **1** |"));
        // All three breakdowns rendered.
        assert!(s.contains("### Network"));
        assert!(s.contains("`api.github.com:443`"));
        assert!(s.contains("### Files"));
        assert!(s.contains("`/etc/hosts`"));
        assert!(s.contains("### Processes"));
        assert!(s.contains("`/bin/sh`"));
    }

    #[test]
    fn denied_rows_get_marker_and_sort_first() {
        let mut stats = Stats::default();
        // Two benign rows with high count, one denied with low count.
        // Denied must still appear ahead of the benign row.
        for _ in 0..5 {
            stats.ingest(ev_connect(Some("good.example"), "1.1.1.1", 443, false));
        }
        stats.ingest(ev_connect(Some("evil.example"), "9.9.9.9", 443, true));

        let s = render_step_summary("cmd", &stats);
        let evil_pos = s.find("evil.example").expect("evil row present");
        let good_pos = s.find("good.example").expect("good row present");
        assert!(
            evil_pos < good_pos,
            "denied row must sort before benign row in step summary"
        );
        assert!(s.contains("❌"));
    }

    #[test]
    fn empty_breakdowns_are_skipped() {
        // Only one kind of event — the other two tables should not
        // appear at all (avoid noisy "Files\n| | path |" empty
        // headers in the summary).
        let mut stats = Stats::default();
        stats.ingest(ev_open("/x", false));
        let s = render_step_summary("cmd", &stats);
        assert!(s.contains("### Files"));
        assert!(!s.contains("### Network"));
        assert!(!s.contains("### Processes"));
    }

    #[test]
    fn pipe_in_command_is_escaped_so_table_doesnt_break() {
        let stats = Stats::default();
        let s = render_step_summary("bash -c 'foo | bar'", &stats);
        assert!(s.contains(r"bash -c 'foo \| bar'"));
    }

    #[test]
    fn top_n_truncates_with_remainder_note() {
        let mut stats = Stats::default();
        for i in 0..(SUMMARY_TOP_N + 5) {
            stats.ingest(ev_open(&format!("/tmp/file-{i}"), false));
        }
        let s = render_step_summary("cmd", &stats);
        assert!(s.contains("more rows omitted"));
    }

    #[test]
    fn lost_events_get_warning_banner() {
        let mut stats = Stats {
            lost: 7,
            ..Stats::default()
        };
        stats.ingest(ev_open("/x", false));
        let s = render_step_summary("cmd", &stats);
        assert!(s.contains("⚠️"));
        assert!(s.contains("7 events were dropped"));
    }
}

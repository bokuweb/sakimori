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

use crate::{cloud_secrets, events::Event, html, iocs, policy::Policy, stats::Stats, tamper::Diff};

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
    /// Optional workspace tamper-detection diff. When `Some` and
    /// non-empty, surfaces in the JSON log under `workspace_drift`
    /// and in the step summary as a "Workspace drift" section. The
    /// supervisor sets this only when the user passed
    /// `--snapshot-workspace`.
    pub workspace_drift: Option<&'a Diff>,
    /// Known-IOC findings against the drift's added/modified paths.
    /// When `Some` and non-empty, surfaces in the JSON log under
    /// `workspace_iocs` and in the step summary as a "Known-IOC
    /// hits" section flagged with ❌. Separate from `workspace_drift`
    /// because a High-severity IOC must fail the supervised step
    /// even when the user passed `--allow-drift` for generic noise.
    pub workspace_iocs: Option<&'a iocs::Report>,
}

pub fn write(args: &ReportArgs<'_>, stats: &Stats) -> Result<()> {
    // --- JSON ---
    let mut payload = serde_json::json!({
        "observed": stats.observed,
        "denied": stats.denied,
        "lost": stats.lost,
        "samples": stats.samples,
    });
    // Only emit `workspace_drift` when the user actually opted into
    // a snapshot AND something changed — empty diffs would just
    // bloat every audit log with noise.
    if let Some(drift) = args.workspace_drift
        && !drift.is_clean()
    {
        payload["workspace_drift"] = serde_json::to_value(drift)?;
    }
    if let Some(iocs) = args.workspace_iocs
        && !iocs.is_clean()
    {
        payload["workspace_iocs"] = serde_json::to_value(iocs)?;
    }
    // Cloud-secret egress tripwire: derived purely from the sampled
    // events, no extra config required. Emits only when at least one
    // Connect event from a package-manager subtree hit a known
    // metadata / secret-store endpoint — quiet by default on clean
    // runs the same way `workspace_drift` is.
    let cloud_secret_hits = cloud_secrets::scan_events(&stats.samples);
    if !cloud_secret_hits.is_empty() {
        payload["cloud_secret_egress"] = serde_json::to_value(&cloud_secret_hits)?;
    }
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
        let body = render_step_summary(
            args.command,
            stats,
            args.workspace_drift,
            args.workspace_iocs,
            &cloud_secret_hits,
        );
        writeln!(f, "{body}")?;
    }

    // --- HTML ---
    if let Some(path) = args.html {
        let meta = html::ReportMeta {
            title: args.command,
            mode: args.mode,
            command: args.command,
        };
        let rendered = html::render(
            args.policy,
            stats,
            meta,
            args.workspace_drift,
            args.workspace_iocs,
        );
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
pub fn render_step_summary(
    command: &str,
    stats: &Stats,
    drift: Option<&Diff>,
    ioc_report: Option<&iocs::Report>,
    cloud_secret_hits: &[cloud_secrets::Hit],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "## sakimori\n");
    let _ = writeln!(out, "Command: `{}`\n", escape_pipe(command));
    let _ = writeln!(out, "| metric | count |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| observed | **{}** |", stats.observed);
    let _ = writeln!(out, "| denied   | **{}** |", stats.denied);
    let _ = writeln!(out, "| lost     | {} |", stats.lost);
    if let Some(d) = drift {
        let _ = writeln!(out, "| drift    | **{}** |", d.total());
    }
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
    push_breakdown_table(
        &mut out,
        "Sources — events grouped by originating package manager",
        "source",
        source_breakdown(&stats.samples),
    );
    if let Some(d) = drift {
        push_drift_section(&mut out, d);
    }
    if let Some(r) = ioc_report
        && !r.is_clean()
    {
        push_ioc_section(&mut out, r);
    }
    if !cloud_secret_hits.is_empty() {
        push_cloud_secret_section(&mut out, cloud_secret_hits);
    }
    out
}

fn push_cloud_secret_section(out: &mut String, hits: &[cloud_secrets::Hit]) {
    let _ = writeln!(
        out,
        "\n### 🛑 Cloud-secret egress — package-manager subtree reached for credentials\n",
    );
    let _ = writeln!(
        out,
        "_Connect events whose destination matched the cloud-metadata / secret-store \
         allowlist **and** whose originating PID's ancestor chain includes a known package \
         manager. The {} entries below are the high-confidence \"this install just tried to \
         steal your creds\" signal; the generic connect log carries any other allowed traffic._\n",
        hits.len(),
    );
    let _ = writeln!(out, "| verdict | category | target | pid | comm | source |");
    let _ = writeln!(out, "|:-:|---|---|---:|---|---|");
    for h in hits {
        let verdict = if h.denied { "❌ DENY" } else { "⚠️ ALLOW" };
        let _ = writeln!(
            out,
            "| {verdict} | `{}` | `{}` | {} | `{}` | `{}` |",
            h.category,
            escape_pipe(&h.target),
            h.pid,
            escape_pipe(&h.comm),
            escape_pipe(&h.package_manager),
        );
    }
}

fn push_ioc_section(out: &mut String, report: &iocs::Report) {
    let _ = writeln!(
        out,
        "\n### ❌ Known-IOC hits — workspace fingerprints from current supply-chain campaigns\n",
    );
    let _ = writeln!(out, "_Catalog version: `{}`._\n", report.catalog_version);
    let _ = writeln!(out, "| severity | path | rule | description |");
    let _ = writeln!(out, "|:-:|---|---|---|");
    for f in &report.findings {
        let sev = match f.severity {
            iocs::Severity::High => "🛑 HIGH",
            iocs::Severity::Medium => "⚠️ MED",
        };
        let _ = writeln!(
            out,
            "| {sev} | `{}` | `{}` | {} |",
            escape_pipe(&f.path.display().to_string()),
            f.rule_id,
            escape_pipe(f.description),
        );
    }
}

/// How many drift rows to surface per category (added / modified /
/// removed) before the table gets a "… N more" footnote.
const DRIFT_TOP_N: usize = 25;

fn push_drift_section(out: &mut String, drift: &Diff) {
    if drift.is_clean() {
        return;
    }
    let _ = writeln!(
        out,
        "\n### Workspace drift — files changed by the supervised step\n",
    );
    let _ = writeln!(out, "| | | path | note |\n|:-:|---|---|---|",);
    for p in drift.added.iter().take(DRIFT_TOP_N) {
        let _ = writeln!(
            out,
            "| ➕ | added    | `{}` |  |",
            escape_pipe(&p.display().to_string())
        );
    }
    for m in drift.modified.iter().take(DRIFT_TOP_N) {
        let _ = writeln!(
            out,
            "| 🔧 | modified | `{}` | {} |",
            escape_pipe(&m.path.display().to_string()),
            modification_note(m),
        );
    }
    for p in drift.removed.iter().take(DRIFT_TOP_N) {
        let _ = writeln!(
            out,
            "| ➖ | removed  | `{}` |  |",
            escape_pipe(&p.display().to_string())
        );
    }
    let total = drift.total();
    let shown = drift.added.len().min(DRIFT_TOP_N)
        + drift.modified.len().min(DRIFT_TOP_N)
        + drift.removed.len().min(DRIFT_TOP_N);
    if total > shown {
        let _ = writeln!(
            out,
            "\n_… {} more rows omitted; full diff is in `workspace_drift` of the JSON log._",
            total - shown,
        );
    }
}

fn modification_note(m: &crate::tamper::ModifiedEntry) -> String {
    use crate::tamper::Entry;
    match (&m.before, &m.after) {
        (
            Entry::File {
                size: a,
                sha256: ha,
            },
            Entry::File {
                size: b,
                sha256: hb,
            },
        ) => {
            if a != b {
                format!("{} → {} bytes", a, b)
            } else if ha != hb {
                "contents changed".to_string()
            } else {
                "metadata changed".to_string()
            }
        }
        (Entry::Symlink { target: a }, Entry::Symlink { target: b }) => {
            format!("link target {} → {}", a, b)
        }
        _ => "type changed".to_string(),
    }
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

/// Group events by the package manager that ultimately spawned them
/// (if any). Events without source attribution — either the
/// supervisor wasn't given a [`Lookup`], the pid had already
/// exited, or no package manager was found in the chain — collapse
/// into a single `(unattributed)` row so they're still visible.
/// Empty when no event in the sample carries source info, in which
/// case the table is suppressed entirely (see push_breakdown_table).
fn source_breakdown(samples: &[Event]) -> Vec<BreakdownRow> {
    // If nothing carries attribution at all, return empty so the
    // table is hidden — saves the user from a useless "all
    // unattributed" row on macOS / Windows.
    if !samples.iter().any(|e| e.source().is_some()) {
        return Vec::new();
    }
    let mut acc: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for ev in samples {
        let label = ev
            .source()
            .and_then(|a| a.package_manager)
            .map(|pm| pm.label().to_string())
            .unwrap_or_else(|| "(unattributed)".to_string());
        let e = acc.entry(label).or_default();
        e.0 += 1;
        if ev.denied() {
            e.1 += 1;
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
            source: None,
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
            source: None,
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
            source: None,
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

        let s = render_step_summary("npm install", &stats, None, None, &[]);
        // Header + command line.
        assert!(s.contains("## sakimori"));
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

        let s = render_step_summary("cmd", &stats, None, None, &[]);
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
        let s = render_step_summary("cmd", &stats, None, None, &[]);
        assert!(s.contains("### Files"));
        assert!(!s.contains("### Network"));
        assert!(!s.contains("### Processes"));
    }

    #[test]
    fn pipe_in_command_is_escaped_so_table_doesnt_break() {
        let stats = Stats::default();
        let s = render_step_summary("bash -c 'foo | bar'", &stats, None, None, &[]);
        assert!(s.contains(r"bash -c 'foo \| bar'"));
    }

    #[test]
    fn top_n_truncates_with_remainder_note() {
        let mut stats = Stats::default();
        for i in 0..(SUMMARY_TOP_N + 5) {
            stats.ingest(ev_open(&format!("/tmp/file-{i}"), false));
        }
        let s = render_step_summary("cmd", &stats, None, None, &[]);
        assert!(s.contains("more rows omitted"));
    }

    #[test]
    fn lost_events_get_warning_banner() {
        let mut stats = Stats {
            lost: 7,
            ..Stats::default()
        };
        stats.ingest(ev_open("/x", false));
        let s = render_step_summary("cmd", &stats, None, None, &[]);
        assert!(s.contains("⚠️"));
        assert!(s.contains("7 events were dropped"));
    }

    #[test]
    fn sources_table_appears_only_when_any_event_has_attribution() {
        use crate::attribution::{Attribution, PackageManager, ProcInfo};

        // No source attribution anywhere → table suppressed.
        let mut stats = Stats::default();
        stats.ingest(ev_connect(Some("a.example"), "1.1.1.1", 443, false));
        let s = render_step_summary("cmd", &stats, None, None, &[]);
        assert!(
            !s.contains("### Sources"),
            "with zero attribution the section must be hidden, got:\n{s}"
        );

        // Two attributed events (npm + pip) plus one unattributed —
        // table renders all three rows, npm + pip + (unattributed).
        let mut stats = Stats::default();
        let mut e1 = ev_connect(Some("registry.npmjs.org"), "1.1.1.1", 443, false);
        e1.set_source(Some(Attribution {
            chain: vec![ProcInfo {
                pid: 10,
                argv0: "npm".into(),
                argv: "npm install foo".into(),
            }],
            package_manager: Some(PackageManager::Npm),
            root_argv: Some("npm install foo".into()),
        }));
        let mut e2 = ev_open("/tmp/whl", true);
        e2.set_source(Some(Attribution {
            chain: vec![ProcInfo {
                pid: 11,
                argv0: "pip".into(),
                argv: "pip install bar".into(),
            }],
            package_manager: Some(PackageManager::Pip),
            root_argv: Some("pip install bar".into()),
        }));
        let e3 = ev_exec("/bin/sh", false); // no source attached
        stats.ingest(e1);
        stats.ingest(e2);
        stats.ingest(e3);

        let s = render_step_summary("cmd", &stats, None, None, &[]);
        assert!(s.contains("### Sources"), "section header missing");
        assert!(s.contains("`npm`"));
        assert!(s.contains("`pip`"));
        assert!(s.contains("(unattributed)"));
    }

    #[test]
    fn drift_section_renders_added_modified_removed() {
        use crate::tamper::{Diff, Entry, ModifiedEntry};
        use std::path::PathBuf;

        let drift = Diff {
            added: vec![PathBuf::from("src/new.rs")],
            modified: vec![ModifiedEntry {
                path: PathBuf::from("src/lib.rs"),
                before: Entry::File {
                    size: 100,
                    sha256: Some("a".repeat(64)),
                },
                after: Entry::File {
                    size: 100,
                    sha256: Some("b".repeat(64)),
                },
            }],
            removed: vec![PathBuf::from("src/old.rs")],
        };
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, Some(&drift), None, &[]);

        assert!(s.contains("| drift    | **3** |"), "drift count missing");
        assert!(s.contains("### Workspace drift"), "drift section missing");
        assert!(s.contains("`src/new.rs`"));
        assert!(s.contains("`src/lib.rs`"));
        assert!(s.contains("`src/old.rs`"));
        // Modification note for same-size, different-hash file.
        assert!(s.contains("contents changed"), "expected note: {s}");
    }

    #[test]
    fn drift_section_suppressed_when_clean() {
        use crate::tamper::Diff;
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, Some(&Diff::default()), None, &[]);
        assert!(!s.contains("### Workspace drift"));
        // Clean diff still gets a "drift | 0" row so the user knows
        // the snapshot ran.
        assert!(s.contains("| drift    | **0** |"));
    }

    #[test]
    fn drift_section_truncates_with_remainder_note() {
        use crate::tamper::Diff;
        use std::path::PathBuf;

        let drift = Diff {
            added: (0..(DRIFT_TOP_N + 5))
                .map(|i| PathBuf::from(format!("a-{i}")))
                .collect(),
            modified: vec![],
            removed: vec![],
        };
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, Some(&drift), None, &[]);
        assert!(s.contains("more rows omitted"), "{s}");
    }

    #[test]
    fn ioc_section_renders_when_findings_present() {
        use crate::iocs::{Finding, Report, Severity};
        use std::path::PathBuf;
        let report = Report::new(vec![Finding {
            path: PathBuf::from(".claude/setup.mjs"),
            rule_id: "shai-hulud.claude-setup-mjs",
            family: "shai-hulud",
            severity: Severity::High,
            description: "Shai-Hulud dropper",
        }]);
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, None, Some(&report), &[]);
        assert!(s.contains("Known-IOC hits"), "{s}");
        assert!(s.contains("🛑 HIGH"), "{s}");
        assert!(s.contains(".claude/setup.mjs"), "{s}");
        assert!(s.contains("shai-hulud.claude-setup-mjs"), "{s}");
    }

    #[test]
    fn ioc_section_omitted_when_report_clean() {
        use crate::iocs::Report;
        let report = Report::new(vec![]);
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, None, Some(&report), &[]);
        assert!(!s.contains("Known-IOC hits"), "{s}");
    }

    #[test]
    fn cloud_secret_section_renders_when_hits_present() {
        let hits = vec![cloud_secrets::Hit {
            category: "cloud-metadata-imds",
            target: "169.254.169.254".into(),
            pid: 1234,
            comm: "node".into(),
            denied: true,
            package_manager: "npm".into(),
        }];
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, None, None, &hits);
        assert!(s.contains("Cloud-secret egress"), "{s}");
        assert!(s.contains("cloud-metadata-imds"), "{s}");
        assert!(s.contains("169.254.169.254"), "{s}");
        assert!(s.contains("❌ DENY"), "{s}");
    }

    #[test]
    fn cloud_secret_section_omitted_when_no_hits() {
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, None, None, &[]);
        assert!(!s.contains("Cloud-secret egress"), "{s}");
    }

    #[test]
    fn cloud_secret_section_marks_allow_distinctly_from_deny() {
        // An allowed hit (user hasn't deployed the deny preset yet)
        // should still appear — the signal is "the install tried",
        // not "the install succeeded". The verdict column makes the
        // distinction visible without burying the deny rows.
        let hits = vec![cloud_secrets::Hit {
            category: "cloud-secret-store",
            target: "sts.amazonaws.com".into(),
            pid: 1,
            comm: "node".into(),
            denied: false,
            package_manager: "npm".into(),
        }];
        let stats = Stats::default();
        let s = render_step_summary("cmd", &stats, None, None, &hits);
        assert!(s.contains("⚠️ ALLOW"), "{s}");
        assert!(!s.contains("❌ DENY"), "{s}");
    }

    #[test]
    fn modification_note_size_change_overrides_hash_check() {
        use crate::tamper::{Entry, ModifiedEntry};
        use std::path::PathBuf;

        let m = ModifiedEntry {
            path: PathBuf::from("p"),
            before: Entry::File {
                size: 100,
                sha256: Some("a".into()),
            },
            after: Entry::File {
                size: 200,
                sha256: Some("b".into()),
            },
        };
        let note = modification_note(&m);
        assert!(note.contains("100 → 200"), "{note}");
    }
}

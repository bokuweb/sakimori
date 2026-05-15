//! Job-scoped supervised mode (Phase 1).
//!
//! `sakimori run -- <cmd>` ties supervision to a single child process tree.
//! GitHub Actions composite actions run each `step:` as a fresh process the
//! runner forks directly, so they fall outside that tree. The daemon mode
//! decouples observation from the child:
//!
//!   1. `sakimori daemon start --observe-cgroup-of <pid> --pid-file …` attaches
//!      the eBPF programs to an existing cgroup v2 hierarchy (typically the
//!      pid of the GitHub Actions runner) and parks until SIGTERM.
//!   2. Every process the runner spawns from then on — `actions/checkout`,
//!      `pnpm install`, `cargo test`, the user's `run:` steps — inherits
//!      that cgroup and fires our connect4 / connect6 / tracepoint programs.
//!   3. `sakimori daemon stop --pid-file …` sends SIGTERM, waits for the
//!      daemon to flush stats + JSON log + step summary + HTML, and exits.
//!
//! No process migration: we attach to the cgroup the target pid is *already*
//! in, leaving systemd / the runner's own cgroup management untouched. See
//! [`crate::cgroup::Cgroup::observe_existing`].

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};

use sakimori_core::report::ReportArgs;

use crate::{
    cgroup::Cgroup,
    loader::Supervisor,
    policy::{self, Mode, Policy},
};

/// Parameters for `sakimori daemon start`.
pub struct DaemonStartArgs {
    pub policy_path: Option<PathBuf>,
    pub mode_override: Option<Mode>,
    pub log: String,
    pub summary: Option<PathBuf>,
    pub html: Option<PathBuf>,
    pub pid_file: PathBuf,
    /// PID whose cgroup v2 hierarchy we attach to. Required: the whole
    /// point of daemon mode is to observe an existing process tree.
    pub observe_cgroup_of: u32,
    pub allow_root_cgroup: bool,
    pub dns_refresh: Duration,
    /// Label written to the JSON log / HTML report's `command` field.
    /// Daemon mode doesn't exec anything itself; this is a free-form
    /// description of what the surrounding job is doing.
    pub command_label: String,
    /// Path to a pre-taken workspace snapshot (as produced by
    /// `sakimori workspace snapshot`). When set, the daemon takes a
    /// fresh snapshot of [`workspace_dir`](Self::workspace_dir) at
    /// shutdown and surfaces the diff in the report under
    /// `workspace_drift`. Required to be set alongside
    /// `workspace_dir`; either both or neither.
    ///
    /// Unlike `sakimori run --snapshot-workspace`, the baseline is
    /// *not* taken by the daemon — the daemon's whole point is to
    /// start observing before checkout happens, so the workspace
    /// is empty at start time. Callers (typically the JS action
    /// wrapper or a CI step) take the baseline themselves after
    /// checkout and hand the file path here.
    pub workspace_baseline: Option<PathBuf>,
    /// Directory the daemon re-snapshots at shutdown to compute the
    /// drift diff. Must match whatever directory produced
    /// `workspace_baseline`.
    pub workspace_dir: Option<PathBuf>,
    /// Extra directory basenames to skip during the workspace
    /// snapshot, on top of the built-in build-artefact list. Must
    /// match what was passed to `sakimori workspace snapshot`
    /// when the baseline was taken.
    pub workspace_skip: Vec<String>,
}

/// Parameters for `sakimori daemon stop`.
pub struct DaemonStopArgs {
    pub pid_file: PathBuf,
    pub timeout: Duration,
}

/// Entry point for `sakimori daemon start`. Runs in the foreground until
/// SIGTERM / SIGINT; callers (the action wrapper, a shell script) are
/// responsible for backgrounding via `setsid … &` or equivalent.
#[cfg(target_os = "linux")]
pub async fn start(args: DaemonStartArgs) -> Result<()> {
    let policy = load_policy(args.policy_path.as_deref())?;
    let mode = args.mode_override.unwrap_or(policy.mode);
    policy.validate(mode)?;
    for w in policy.lint() {
        log::warn!("{w}");
    }

    // Refuse to start if a live daemon already owns the pid-file. Two
    // daemons attaching to the same cgroup wouldn't *break* anything
    // (the second would just attach the same programs again) but the
    // output paths would collide and we'd have no clean way to stop
    // them individually. Loud-fail.
    check_pidfile_unused(&args.pid_file)?;

    // Validate workspace-tamper args eagerly: either both or neither.
    // Note we *don't* require the baseline file to exist yet — the
    // expected wrapper flow is "daemon start before checkout, take
    // baseline after checkout, diff at shutdown". So the baseline
    // file is allowed to be absent here; it's read at shutdown, and
    // `compute_workspace_drift` fails soft (warn + drop drift section)
    // if it still isn't there. That keeps audit logs flowing even
    // when the user forgets the snapshot step.
    if args.workspace_baseline.is_some() != args.workspace_dir.is_some() {
        anyhow::bail!(
            "--workspace-baseline and --workspace-dir must be set together \
             (either both or neither). The baseline is read at shutdown from \
             --workspace-baseline and diffed against a fresh snapshot of \
             --workspace-dir."
        );
    }

    let cgroup = Cgroup::observe_existing(args.observe_cgroup_of, args.allow_root_cgroup)
        .context("attaching to existing cgroup")?;
    log::info!(
        "daemon: attached to cgroup {} (observing pid {} and descendants)",
        cgroup.path.display(),
        args.observe_cgroup_of,
    );

    let supervisor =
        Supervisor::start_with_cgroup(policy.clone(), mode, args.dns_refresh, Some(cgroup)).await?;

    // Write pid-file *after* a successful attach. A caller polling for
    // pid-file existence can then assume "if it's there, we're ready".
    write_pidfile(&args.pid_file)?;
    // Tell the caller we're up — they're allowed to start the rest of the
    // job once they see this line on stderr.
    eprintln!("sakimori daemon: ready (pid {})", std::process::id());

    // Park until SIGTERM. Best-effort cleanup of the pid-file on the way
    // out so the next `daemon start` doesn't see stale state.
    let wait_res = supervisor.wait_for_shutdown().await;
    let _ = std::fs::remove_file(&args.pid_file);
    wait_res?;

    let mut stats = supervisor.shutdown().await?;
    crate::resolve_hostnames::resolve(&mut stats).await;

    // Workspace tamper diff. Non-fatal: log + summary still go out
    // without `workspace_drift` if the snapshot or read fails — same
    // policy as `sakimori run`.
    let drift = compute_workspace_drift(
        args.workspace_baseline.as_deref(),
        args.workspace_dir.as_deref(),
        &args.workspace_skip,
    );
    let ioc_report = drift.as_ref().map(scan_drift_for_iocs);

    let report = ReportArgs {
        log: &args.log,
        summary: args.summary.as_deref(),
        html: args.html.as_deref(),
        command: args.command_label.as_str(),
        mode,
        policy: &policy,
        workspace_drift: drift.as_ref().filter(|d| !d.is_clean()),
        workspace_iocs: ioc_report.as_ref().filter(|r| !r.is_clean()),
    };
    sakimori_core::report::write(&report, &stats)?;

    let drift_violation = drift.as_ref().map(|d| !d.is_clean()).unwrap_or(false);
    let ioc_high = ioc_report.as_ref().map(|r| r.has_high()).unwrap_or(false);

    // Block-mode parity with `sakimori run`: any denied event flips the
    // exit code so the surrounding job fails.
    if stats.denied > 0 && matches!(mode, Mode::Block) {
        eprintln!(
            "::error title=sakimori::policy violation: {} events denied in block mode",
            stats.denied
        );
        std::process::exit(1);
    }
    if drift_violation && matches!(mode, Mode::Block) {
        let n = drift.as_ref().map(|d| d.total()).unwrap_or(0);
        eprintln!(
            "::error title=sakimori::workspace tamper detected: {n} files added/modified/removed during the supervised job"
        );
        std::process::exit(1);
    }
    // High-severity IOC fails the job in *any* mode — the fingerprint
    // is "this is a known supply-chain worm artefact", not a policy
    // call the user might want to override.
    if ioc_high {
        let n = ioc_report.as_ref().map(|r| r.findings.len()).unwrap_or(0);
        eprintln!(
            "::error title=sakimori::known-IOC hit: {n} workspace path(s) match a known supply-chain campaign fingerprint"
        );
        std::process::exit(1);
    }
    Ok(())
}

/// Run the IOC catalog against `drift.added` + `drift.modified`. Files
/// that were already in the baseline get no re-check (the baseline-
/// snapshot opportunity is the snapshot itself; pre-existing infections
/// are caught by `workspace scan-iocs` before the run).
fn scan_drift_for_iocs(drift: &sakimori_core::tamper::Diff) -> sakimori_core::iocs::Report {
    let paths: Vec<&std::path::Path> = drift
        .added
        .iter()
        .map(|p| p.as_path())
        .chain(drift.modified.iter().map(|m| m.path.as_path()))
        .collect();
    sakimori_core::iocs::Report::new(sakimori_core::iocs::scan_paths(paths.iter().copied()))
}

/// Take a fresh snapshot of `dir`, diff against the baseline file. Returns
/// `None` (and logs) on any error so a bad-config / bad-fs situation doesn't
/// silently drop the entire audit log.
fn compute_workspace_drift(
    baseline_path: Option<&Path>,
    workspace_dir: Option<&Path>,
    skip_extra: &[String],
) -> Option<sakimori_core::tamper::Diff> {
    let (baseline_path, workspace_dir) = match (baseline_path, workspace_dir) {
        (Some(b), Some(d)) => (b, d),
        _ => return None,
    };
    let baseline_json = match std::fs::read_to_string(baseline_path) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "workspace tamper: reading baseline {} failed: {e}",
                baseline_path.display()
            );
            return None;
        }
    };
    let baseline = match sakimori_core::tamper::Snapshot::from_json(&baseline_json) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "workspace tamper: parsing baseline {} failed: {e}",
                baseline_path.display()
            );
            return None;
        }
    };
    let opts = sakimori_core::tamper::Options {
        skip_extra: skip_extra.to_vec(),
        ..Default::default()
    };
    let current = match sakimori_core::tamper::Snapshot::take(workspace_dir, &opts) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "workspace tamper: snapshotting {} failed: {e}",
                workspace_dir.display()
            );
            return None;
        }
    };
    Some(sakimori_core::tamper::diff(&baseline, &current))
}

#[cfg(not(target_os = "linux"))]
pub async fn start(_args: DaemonStartArgs) -> Result<()> {
    anyhow::bail!("sakimori daemon is Linux-only (requires cgroup v2 + eBPF)")
}

/// Entry point for `sakimori daemon stop`. Reads the pid from `--pid-file`,
/// sends SIGTERM, and polls until the daemon exits or the timeout fires.
pub fn stop(args: DaemonStopArgs) -> Result<()> {
    let pid = match read_pidfile(&args.pid_file) {
        Ok(p) => p,
        Err(e) => {
            // Idempotent: if the pid-file is missing the daemon already
            // exited (or never started); there's nothing to do.
            eprintln!(
                "sakimori daemon stop: pid-file {} unreadable ({e:#}); assuming already stopped",
                args.pid_file.display()
            );
            return Ok(());
        }
    };

    if !pid_is_alive(pid) {
        eprintln!(
            "sakimori daemon stop: pid {pid} from {} is no longer alive; cleaning up pid-file",
            args.pid_file.display()
        );
        let _ = std::fs::remove_file(&args.pid_file);
        return Ok(());
    }

    send_sigterm(pid)?;

    let deadline = std::time::Instant::now() + args.timeout;
    while std::time::Instant::now() < deadline {
        if !pid_is_alive(pid) {
            // Daemon should remove its own pid-file, but defensively
            // clean it up if it didn't.
            let _ = std::fs::remove_file(&args.pid_file);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!(
        "sakimori daemon (pid {pid}) did not exit within {:?}; not escalating to SIGKILL — \
         report may be incomplete. Inspect the daemon's stderr to diagnose.",
        args.timeout
    );
}

fn load_policy(path: Option<&Path>) -> Result<Policy> {
    match path {
        Some(p) => {
            policy::Policy::from_file(p).with_context(|| format!("loading policy {}", p.display()))
        }
        None => Ok(policy::Policy::permissive_audit()),
    }
}

fn write_pidfile(path: &Path) -> Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating pid-file parent {}", parent.display()))?;
    }
    // Atomic write: tempfile in the same directory + rename. Same-fs
    // rename is atomic on Linux, so a concurrent reader sees either the
    // old contents or the new — never a half-written pid.
    let tmp = path.with_extension("pid.tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        writeln!(f, "{}", std::process::id())?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

fn read_pidfile(path: &Path) -> Result<u32> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("reading pid-file {}", path.display()))?;
    parse_pidfile(&s)
        .ok_or_else(|| anyhow::anyhow!("pid-file {} is empty or malformed", path.display()))
}

pub(crate) fn parse_pidfile(s: &str) -> Option<u32> {
    s.trim().parse::<u32>().ok()
}

fn check_pidfile_unused(path: &Path) -> Result<()> {
    let Ok(s) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    let Some(pid) = parse_pidfile(&s) else {
        // Garbage — overwrite is fine.
        return Ok(());
    };
    if pid_is_alive(pid) {
        anyhow::bail!(
            "pid-file {} already exists and pid {pid} is still alive. \
             Stop the running daemon first with `sakimori daemon stop \
             --pid-file {}` or pick a different --pid-file.",
            path.display(),
            path.display(),
        );
    }
    // Stale (process gone) — caller will overwrite atomically.
    Ok(())
}

#[cfg(target_os = "linux")]
fn pid_is_alive(pid: u32) -> bool {
    // Guard the i32 cast: `libc::pid_t` is `i32`, so `as` truncation
    // would turn `u32` values >= 2^31 into negative pid_t. kill(2)
    // treats negative pids as process-group identifiers (and `-1` as
    // "every process the caller may signal") — a completely different
    // syscall from "is pid N alive". Anything outside positive i32 is
    // not a real pid; report it as dead.
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // kill(pid, 0) returns 0 if the signal could be sent (i.e. the
    // process exists and we have permission), or -1 with errno set.
    // ESRCH means "no such process"; EPERM means "exists but we can't
    // signal it" — which still counts as alive.
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if r == 0 {
        return true;
    }
    let errno = unsafe { *libc::__errno_location() };
    errno == libc::EPERM
}

#[cfg(not(target_os = "linux"))]
fn pid_is_alive(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn send_sigterm(pid: u32) -> Result<()> {
    let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if r != 0 {
        let errno = unsafe { *libc::__errno_location() };
        anyhow::bail!("kill({pid}, SIGTERM) failed: errno {errno}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn send_sigterm(_pid: u32) -> Result<()> {
    anyhow::bail!("sakimori daemon stop is Linux-only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pidfile_with_trailing_newline() {
        assert_eq!(parse_pidfile("12345\n"), Some(12345));
    }

    #[test]
    fn parses_pidfile_without_newline() {
        assert_eq!(parse_pidfile("99"), Some(99));
    }

    #[test]
    fn rejects_garbage_pidfile() {
        assert_eq!(parse_pidfile(""), None);
        assert_eq!(parse_pidfile("not-a-pid"), None);
        assert_eq!(parse_pidfile("-1"), None); // u32 can't hold negatives
    }

    #[test]
    fn write_and_read_pidfile_roundtrip() {
        let tmp = tempdir();
        let path = tmp.join("daemon.pid");
        write_pidfile(&path).unwrap();
        let pid = read_pidfile(&path).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn check_pidfile_unused_ignores_missing_file() {
        let tmp = tempdir();
        let path = tmp.join("nope.pid");
        check_pidfile_unused(&path).expect("missing pid-file should be fine");
    }

    #[test]
    fn check_pidfile_unused_ignores_stale_pid() {
        // Pick a pid that's safely above any reasonable Linux pid_max
        // (default 2^22 = 4194304) but still within positive i32 so it
        // exercises the kill→ESRCH path rather than the range guard.
        // If this ever fails on a weird system it's a real race, not a
        // flake.
        const STALE: u32 = 2_000_000_000;
        let tmp = tempdir();
        let path = tmp.join("stale.pid");
        std::fs::write(&path, format!("{STALE}\n")).unwrap();
        check_pidfile_unused(&path).expect("stale pid should not block startup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_pidfile_unused_rejects_out_of_range_pid() {
        // u32::MAX cast to pid_t (i32) wraps to -1, which kill(2) reads
        // as "every process the caller may signal" — a completely
        // different operation. Guard must treat that as "not a real
        // pid → dead" rather than letting it through to kill().
        let tmp = tempdir();
        let path = tmp.join("oor.pid");
        std::fs::write(&path, format!("{}\n", u32::MAX)).unwrap();
        check_pidfile_unused(&path)
            .expect("out-of-range pid must be treated as dead and not block startup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_pidfile_unused_rejects_live_pid() {
        let tmp = tempdir();
        let path = tmp.join("live.pid");
        // Our own pid is definitely alive.
        std::fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        let err = check_pidfile_unused(&path).expect_err("live pid must block startup");
        let msg = format!("{err:#}");
        assert!(msg.contains("already exists"), "got: {msg}");
    }

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir();
        let unique = format!(
            "sakimori-daemon-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let p = base.join(unique);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn workspace_drift_returns_none_when_args_unset() {
        // Both unset: feature is off, return None (no warning).
        let r = compute_workspace_drift(None, None, &[]);
        assert!(r.is_none());
    }

    #[test]
    fn workspace_drift_returns_none_when_baseline_missing() {
        let tmp = tempdir();
        let missing = tmp.join("nope.json");
        let r = compute_workspace_drift(Some(&missing), Some(&tmp), &[]);
        assert!(r.is_none(), "missing baseline must fail soft, not panic");
    }

    #[test]
    fn workspace_drift_returns_none_when_baseline_malformed() {
        let tmp = tempdir();
        let bogus = tmp.join("bogus.json");
        std::fs::write(&bogus, "not json").unwrap();
        let r = compute_workspace_drift(Some(&bogus), Some(&tmp), &[]);
        assert!(r.is_none(), "unparseable baseline must fail soft");
    }

    #[test]
    fn workspace_drift_detects_added_file_against_real_baseline() {
        // End-to-end: take a real snapshot via the public API, write
        // a new file, compute drift, assert the new file shows up.
        let tmp = tempdir();
        std::fs::write(tmp.join("a"), b"hello").unwrap();
        let opts = sakimori_core::tamper::Options::default();
        let baseline = sakimori_core::tamper::Snapshot::take(&tmp, &opts).unwrap();
        let baseline_path = tmp.join("baseline.json");
        std::fs::write(&baseline_path, baseline.to_json_pretty().unwrap()).unwrap();

        // Add a file post-baseline.
        std::fs::write(tmp.join("b"), b"new").unwrap();

        let diff = compute_workspace_drift(Some(&baseline_path), Some(&tmp), &[])
            .expect("drift should be Some when both args valid");
        assert!(!diff.is_clean(), "must detect drift");
        assert!(
            diff.added.iter().any(|p| p.ends_with("b")),
            "added: {:?}",
            diff.added
        );
    }
}

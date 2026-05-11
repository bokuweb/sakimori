//! `sakimori doctor` — one-command diagnostic for the install-gate
//! and proxy setup. When users say "it doesn't work", this is the
//! first thing they (or we) run.
//!
//! The checks below are ordered roughly from "most likely to be the
//! root cause" to "least likely". Each check is pure-ish (takes its
//! inputs as references, returns a `Report`) so we can unit-test the
//! rendering without hitting the real filesystem or network.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    /// One-line human-readable explanation.
    pub detail: String,
    /// Optional fix hint — an exact command or file the user can
    /// touch. Shown after a ↳.
    pub hint: Option<String>,
}

impl CheckResult {
    pub fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Ok,
            detail: detail.into(),
            hint: None,
        }
    }
    pub fn warn(name: &str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
    pub fn fail(name: &str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
}

/// Plain-text, ANSI-friendly rendering. Safe for unit tests and for
/// non-TTY stdout (pipes, CI logs). The caller is expected to print.
pub fn render_report(results: &[CheckResult]) -> String {
    let mut out = String::new();
    out.push_str("sakimori doctor\n");
    out.push_str(&"─".repeat(60));
    out.push('\n');
    for r in results {
        let mark = match r.status {
            CheckStatus::Ok => "✓",
            CheckStatus::Warn => "!",
            CheckStatus::Fail => "✗",
        };
        out.push_str(&format!("{mark} {:<28} {}\n", r.name, r.detail));
        if let Some(h) = &r.hint {
            out.push_str(&format!("  ↳ {h}\n"));
        }
    }
    out.push_str(&"─".repeat(60));
    out.push('\n');
    let fails = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let warns = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    out.push_str(&format!(
        "{} check(s): {fails} fail, {warns} warn\n",
        results.len()
    ));
    out
}

/// Overall exit code for the doctor command. Fails are the only
/// thing we exit non-zero on — warnings are informational.
pub fn exit_code(results: &[CheckResult]) -> i32 {
    if results.iter().any(|r| r.status == CheckStatus::Fail) {
        1
    } else {
        0
    }
}

// ---------------- individual checks ----------------

pub struct DoctorInputs {
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    /// Expected proxy listen address. `sakimori proxy` default
    /// is `127.0.0.1:8910`.
    pub proxy_addr: SocketAddr,
    /// `$HTTPS_PROXY` as the user's shell sees it right now
    /// (read from our own process env at invocation time).
    pub https_proxy_env: Option<String>,
    /// Expected value for `HTTPS_PROXY` assuming the install-gate
    /// block is active (derived from `proxy_addr`).
    pub expected_https_proxy: String,
    /// Path to the shell rc file (for the marker-presence check).
    /// `None` means "skip this check" — useful on Windows or when
    /// `$HOME` is unset.
    pub rc_path: Option<PathBuf>,
    /// Path to the daemon unit (launchd plist / systemd unit).
    /// `None` means "skip this check".
    pub daemon_unit_path: Option<PathBuf>,
    /// Path to a `sakimori daemon start --pid-file` file. When set,
    /// doctor reads the pid and reports whether the daemon process
    /// is still alive — useful for catching "the daemon died mid-job
    /// and nothing told me" situations on long-running runners.
    /// `None` means "skip this check".
    pub daemon_pidfile: Option<PathBuf>,
}

/// Run every check with the given inputs. Pure-ish — does read the
/// filesystem and attempt a TCP connect, but nothing that mutates.
pub fn run_checks(inp: &DoctorInputs) -> Vec<CheckResult> {
    let mut out = Vec::with_capacity(6);
    out.push(check_ca_file(&inp.ca_cert));
    out.push(check_ca_key(&inp.ca_key));
    out.push(check_proxy_listening(inp.proxy_addr));
    out.push(check_env_https_proxy(
        inp.https_proxy_env.as_deref(),
        &inp.expected_https_proxy,
    ));
    if let Some(rc) = &inp.rc_path {
        out.push(check_install_gate_marker(rc));
    }
    if let Some(d) = &inp.daemon_unit_path {
        out.push(check_daemon_unit(d));
    }
    if let Some(p) = &inp.daemon_pidfile {
        out.push(check_daemon_pidfile(p));
    }
    out
}

fn check_daemon_pidfile(path: &Path) -> CheckResult {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return CheckResult::warn(
                "sakimori daemon",
                format!("no pid-file at {}", path.display()),
                "start it from the action's pre-step or `sakimori daemon start`",
            );
        }
        Err(e) => {
            return CheckResult::fail(
                "sakimori daemon",
                format!("reading {}: {e}", path.display()),
                "check filesystem permissions",
            );
        }
    };
    let pid: u32 = match contents.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            return CheckResult::fail(
                "sakimori daemon",
                format!("pid-file {} is malformed: {:?}", path.display(), contents),
                "remove the file and restart the daemon",
            );
        }
    };
    if daemon_pid_is_alive(pid) {
        CheckResult::ok(
            "sakimori daemon",
            format!("pid {pid} alive ({})", path.display()),
        )
    } else {
        CheckResult::fail(
            "sakimori daemon",
            format!(
                "pid {pid} from {} is no longer alive — daemon crashed or was killed",
                path.display()
            ),
            "inspect the daemon's stderr log (next to the pid-file) and restart",
        )
    }
}

#[cfg(target_os = "linux")]
fn daemon_pid_is_alive(pid: u32) -> bool {
    // Mirrors `daemon::pid_is_alive` — kept as a private dup to avoid
    // exposing that function publicly. See its comment for the i32-wrap
    // / EPERM rationale.
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if r == 0 {
        return true;
    }
    let errno = unsafe { *libc::__errno_location() };
    errno == libc::EPERM
}

#[cfg(not(target_os = "linux"))]
fn daemon_pid_is_alive(_pid: u32) -> bool {
    // No daemon on non-Linux yet; report dead so the doctor check fires
    // a clear "daemon not running" message instead of a misleading OK.
    false
}

fn check_ca_file(path: &Path) -> CheckResult {
    if !path.exists() {
        return CheckResult::fail(
            "CA certificate",
            format!("missing at {}", path.display()),
            "run `sakimori proxy start` once to generate the CA, then `sakimori proxy install-ca` to trust it",
        );
    }
    match std::fs::metadata(path) {
        Ok(m) if m.len() > 0 => CheckResult::ok(
            "CA certificate",
            format!("{} ({} bytes)", path.display(), m.len()),
        ),
        _ => CheckResult::fail(
            "CA certificate",
            format!("{} exists but is empty", path.display()),
            "delete it and re-run `sakimori proxy start`",
        ),
    }
}

fn check_ca_key(path: &Path) -> CheckResult {
    if !path.exists() {
        return CheckResult::fail(
            "CA private key",
            format!("missing at {}", path.display()),
            "re-run `sakimori proxy start` to regenerate the keypair",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path) {
            let mode = m.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return CheckResult::warn(
                    "CA private key",
                    format!(
                        "{} mode is 0{mode:o} (group/world readable)",
                        path.display()
                    ),
                    format!("chmod 600 {}", path.display()),
                );
            }
        }
    }
    CheckResult::ok("CA private key", path.display().to_string())
}

fn check_proxy_listening(addr: SocketAddr) -> CheckResult {
    match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        Ok(_) => CheckResult::ok("Proxy reachable", format!("accepted TCP on {addr}")),
        Err(e) => CheckResult::fail(
            "Proxy reachable",
            format!("no listener on {addr}: {e}"),
            "start it: `sakimori proxy start` (or, for background: `sakimori proxy install-daemon`)",
        ),
    }
}

fn check_env_https_proxy(actual: Option<&str>, expected: &str) -> CheckResult {
    match actual {
        None => CheckResult::warn(
            "$HTTPS_PROXY",
            "unset in this shell",
            "run `sakimori install-gate install` and open a new shell",
        ),
        Some(s) if s == expected => CheckResult::ok("$HTTPS_PROXY", s.to_string()),
        Some(s) => CheckResult::warn(
            "$HTTPS_PROXY",
            format!("set to {s:?} (expected {expected:?})"),
            "double-check `--listen` matches on both proxy + install-gate",
        ),
    }
}

fn check_install_gate_marker(rc: &Path) -> CheckResult {
    if !rc.exists() {
        return CheckResult::warn(
            "install-gate rc",
            format!("{} does not exist yet", rc.display()),
            "run `sakimori install-gate install`",
        );
    }
    let Ok(text) = std::fs::read_to_string(rc) else {
        return CheckResult::warn(
            "install-gate rc",
            format!("couldn't read {}", rc.display()),
            "check permissions",
        );
    };
    if text.contains("# >>> sakimori install-gate >>>") {
        CheckResult::ok("install-gate rc", rc.display().to_string())
    } else {
        CheckResult::warn(
            "install-gate rc",
            format!("{} has no sakimori block", rc.display()),
            "run `sakimori install-gate install`",
        )
    }
}

fn check_daemon_unit(path: &Path) -> CheckResult {
    if path.exists() {
        CheckResult::ok("Daemon unit", path.display().to_string())
    } else {
        CheckResult::warn(
            "Daemon unit",
            format!("{} missing", path.display()),
            "run `sakimori proxy install-daemon` so the proxy auto-starts",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir() -> PathBuf {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sakimori-doctor-{id}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn ca_file_missing_is_fail() {
        let r = check_ca_file(&PathBuf::from("/no/such/thing"));
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(r.hint.unwrap().contains("proxy start"));
    }

    #[test]
    fn ca_file_present_is_ok() {
        let d = tmpdir();
        let p = d.join("ca.pem");
        fs::write(
            &p,
            b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let r = check_ca_file(&p);
        assert_eq!(r.status, CheckStatus::Ok);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn env_https_proxy_matches_is_ok() {
        let r = check_env_https_proxy(Some("http://127.0.0.1:8910"), "http://127.0.0.1:8910");
        assert_eq!(r.status, CheckStatus::Ok);
    }

    #[test]
    fn env_https_proxy_unset_is_warn_with_install_gate_hint() {
        let r = check_env_https_proxy(None, "http://127.0.0.1:8910");
        assert_eq!(r.status, CheckStatus::Warn);
        assert!(r.hint.unwrap().contains("install-gate install"));
    }

    #[test]
    fn env_https_proxy_mismatch_is_warn() {
        let r = check_env_https_proxy(Some("http://127.0.0.1:8910"), "http://127.0.0.1:9999");
        assert_eq!(r.status, CheckStatus::Warn);
    }

    #[test]
    fn install_gate_marker_detected() {
        let d = tmpdir();
        let rc = d.join(".zshrc");
        fs::write(
            &rc,
            "# existing\n# >>> sakimori install-gate >>>\neval ...\n# <<< sakimori install-gate <<<\n",
        )
        .unwrap();
        let r = check_install_gate_marker(&rc);
        assert_eq!(r.status, CheckStatus::Ok);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn install_gate_marker_absent_is_warn() {
        let d = tmpdir();
        let rc = d.join(".zshrc");
        fs::write(&rc, "alias foo=bar\n").unwrap();
        let r = check_install_gate_marker(&rc);
        assert_eq!(r.status, CheckStatus::Warn);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn rendering_includes_footer_with_counts() {
        let results = vec![
            CheckResult::ok("a", "fine"),
            CheckResult::warn("b", "meh", "try harder"),
            CheckResult::fail("c", "nope", "do the thing"),
        ];
        let s = render_report(&results);
        assert!(s.contains("✓ a"));
        assert!(s.contains("! b"));
        assert!(s.contains("✗ c"));
        assert!(s.contains("↳ try harder"));
        assert!(s.contains("↳ do the thing"));
        assert!(s.contains("3 check(s): 1 fail, 1 warn"));
    }

    #[test]
    fn exit_code_is_1_when_any_fails() {
        assert_eq!(exit_code(&[CheckResult::ok("x", "")]), 0);
        assert_eq!(
            exit_code(&[CheckResult::warn("x", "", "y")]),
            0,
            "warnings alone don't fail exit"
        );
        assert_eq!(exit_code(&[CheckResult::fail("x", "", "y")]), 1);
    }

    #[test]
    fn proxy_unreachable_port_is_fail() {
        // Pick a wildly unlikely port.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = check_proxy_listening(addr);
        assert_eq!(r.status, CheckStatus::Fail);
    }

    #[test]
    fn daemon_pidfile_missing_is_warn_not_fail() {
        // Daemon is intentionally ephemeral (only running during a job),
        // so absence is informational, not an error.
        let d = std::env::temp_dir().join(format!(
            "sakimori-doctor-test-{}-pid-missing",
            std::process::id()
        ));
        let r = check_daemon_pidfile(&d);
        assert_eq!(r.status, CheckStatus::Warn);
    }

    #[test]
    fn daemon_pidfile_malformed_is_fail() {
        let d = std::env::temp_dir().join(format!(
            "sakimori-doctor-test-{}-pid-bad",
            std::process::id()
        ));
        std::fs::write(&d, "not-a-pid\n").unwrap();
        let r = check_daemon_pidfile(&d);
        assert_eq!(r.status, CheckStatus::Fail);
        std::fs::remove_file(&d).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_pidfile_with_live_pid_is_ok() {
        // Our own pid is alive — the check should report OK.
        let d = std::env::temp_dir().join(format!(
            "sakimori-doctor-test-{}-pid-live",
            std::process::id()
        ));
        std::fs::write(&d, format!("{}\n", std::process::id())).unwrap();
        let r = check_daemon_pidfile(&d);
        assert_eq!(r.status, CheckStatus::Ok);
        std::fs::remove_file(&d).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_pidfile_with_dead_pid_is_fail() {
        // Same sentinel as daemon::tests::check_pidfile_unused_ignores_stale_pid
        // — comfortably above Linux pid_max but inside positive i32.
        const STALE: u32 = 2_000_000_000;
        let d = std::env::temp_dir().join(format!(
            "sakimori-doctor-test-{}-pid-stale",
            std::process::id()
        ));
        std::fs::write(&d, format!("{STALE}\n")).unwrap();
        let r = check_daemon_pidfile(&d);
        assert_eq!(r.status, CheckStatus::Fail);
        std::fs::remove_file(&d).ok();
    }
}

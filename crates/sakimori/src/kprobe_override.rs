//! Runtime detection of `CONFIG_BPF_KPROBE_OVERRIDE`.
//!
//! Background — CLAUDE.md roadmap #4: today `file.deny` in `mode:
//! block` is a "tripwire" (`bpf_send_signal(SIGKILL)` on the
//! offending process after the open syscall has been issued). The
//! file descriptor may briefly exist; the process dies before it
//! can read from it. A clean pre-syscall block would attach a
//! kprobe to `do_sys_openat2` and call `bpf_override_return(ctx,
//! -EPERM)` so the syscall fails outright — but that helper is
//! only available when the kernel was built with
//! `CONFIG_BPF_KPROBE_OVERRIDE=y`.
//!
//! This module gives the rest of the codebase a *cheap, runtime*
//! answer to "can we use kprobe override on this kernel?" so we
//! can (a) light up the kprobe path opportunistically when it's
//! available and (b) tell users via `sakimori doctor` how strong
//! their block enforcement actually is.
//!
//! Detection strategy:
//! 1. Try `/boot/config-$(uname -r)` — the canonical place
//!    distros drop the kernel build config.
//! 2. (Future) `/proc/config.gz` — gz-compressed text. Skipped for
//!    now to avoid adding `flate2` as a dep; can be layered in
//!    later behind a feature flag without changing the public API.
//!
//! When neither is readable we return `Unknown` rather than
//! pretending the feature is off — the doctor surface treats
//! that as a `warn` (informational) rather than a `fail`.
//!
//! The whole detection path is `cfg(target_os = "linux")`. On
//! other platforms the public API still compiles but always
//! returns `Unknown` so callers don't need their own cfg gates.

use std::path::{Path, PathBuf};

/// Result of probing the running kernel for `bpf_override_return`
/// support. Surfaced both to the loader (gates whether we try to
/// attach the kprobe at all) and to `sakimori doctor` (informs
/// the user about block strength).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KprobeOverrideStatus {
    /// `CONFIG_BPF_KPROBE_OVERRIDE=y` was found in a kernel config
    /// we could read. `bpf_override_return` should work — provided
    /// the target function (`do_sys_openat2`, `__x64_sys_execve`,
    /// etc.) is in the kernel's error-injection allow-list, which
    /// we check separately at attach time.
    Available { config_path: PathBuf },
    /// Kernel config was readable and explicitly says
    /// `CONFIG_BPF_KPROBE_OVERRIDE` is not set (= n / = m / absent
    /// entirely). `bpf_override_return` will be rejected by the
    /// verifier — we must fall back to the SIGKILL tripwire.
    Unsupported { config_path: PathBuf },
    /// No readable kernel config in any expected location.
    /// Block strength is genuinely unknown; the loader should
    /// optimistically attempt the kprobe attach and degrade on
    /// `EPERM` / verifier-reject rather than refuse outright.
    Unknown { reason: String },
}

impl KprobeOverrideStatus {
    pub fn is_available(&self) -> bool {
        matches!(self, KprobeOverrideStatus::Available { .. })
    }
}

/// Probe the current kernel. Pure-ish — reads files but mutates
/// nothing. Cheap enough to call from `sakimori doctor` /
/// startup paths without caching.
#[cfg(target_os = "linux")]
pub fn detect() -> KprobeOverrideStatus {
    let release = match kernel_release() {
        Some(r) => r,
        None => {
            return KprobeOverrideStatus::Unknown {
                reason: "uname() failed".into(),
            };
        }
    };
    let path = PathBuf::from(format!("/boot/config-{release}"));
    detect_from_config_file(&path)
}

#[cfg(not(target_os = "linux"))]
pub fn detect() -> KprobeOverrideStatus {
    KprobeOverrideStatus::Unknown {
        reason: "kprobe override is Linux-only".into(),
    }
}

/// Test seam: scan a specific config file path. Exposed so the
/// unit tests can feed in a synthetic kernel config without
/// touching `/boot`.
pub fn detect_from_config_file(path: &Path) -> KprobeOverrideStatus {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return KprobeOverrideStatus::Unknown {
                reason: format!("reading {}: {e}", path.display()),
            };
        }
    };
    classify(&text, path)
}

/// Inspect kernel-config text for `CONFIG_BPF_KPROBE_OVERRIDE`.
/// Public for direct unit testing without filesystem access.
pub fn classify(config_text: &str, path: &Path) -> KprobeOverrideStatus {
    // Distro kernel configs are line-oriented `KEY=VALUE` or
    // `# KEY is not set`. We accept both `=y` and `=m` as
    // "Available" — the helper itself doesn't care about module
    // vs built-in. Anything else (explicit `not set`, missing
    // entirely, garbled) → `Unsupported`.
    for line in config_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("CONFIG_BPF_KPROBE_OVERRIDE=") {
            let val = rest.trim();
            if val.eq_ignore_ascii_case("y") || val.eq_ignore_ascii_case("m") {
                return KprobeOverrideStatus::Available {
                    config_path: path.to_path_buf(),
                };
            } else {
                return KprobeOverrideStatus::Unsupported {
                    config_path: path.to_path_buf(),
                };
            }
        }
    }
    KprobeOverrideStatus::Unsupported {
        config_path: path.to_path_buf(),
    }
}

#[cfg(target_os = "linux")]
fn kernel_release() -> Option<String> {
    // SAFETY: `utsname` is a POD whose every field is a fixed
    // C-string buffer; `uname()` writes into it and returns 0
    // on success. The buffer is owned by us for the duration of
    // the read; we copy the NUL-terminated `release` field out
    // immediately.
    use std::ffi::CStr;
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::uname(&mut buf) };
    if r != 0 {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(buf.release.as_ptr()) };
    Some(cstr.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_y_is_available() {
        let cfg = "# noise\nCONFIG_BPF=y\nCONFIG_BPF_KPROBE_OVERRIDE=y\nCONFIG_OTHER=n\n";
        let r = classify(cfg, Path::new("/boot/config-x"));
        assert!(r.is_available(), "got {r:?}");
    }

    #[test]
    fn classify_m_is_also_available() {
        // The helper doesn't care about module vs built-in.
        let cfg = "CONFIG_BPF_KPROBE_OVERRIDE=m\n";
        let r = classify(cfg, Path::new("/boot/config-x"));
        assert!(r.is_available(), "got {r:?}");
    }

    #[test]
    fn classify_not_set_is_unsupported() {
        let cfg = "# CONFIG_BPF_KPROBE_OVERRIDE is not set\nCONFIG_OTHER=y\n";
        let r = classify(cfg, Path::new("/boot/config-x"));
        assert!(
            matches!(r, KprobeOverrideStatus::Unsupported { .. }),
            "got {r:?}"
        );
    }

    #[test]
    fn classify_absent_is_unsupported() {
        // Older kernels (pre-4.16) never had the symbol at all.
        let cfg = "CONFIG_BPF=y\nCONFIG_TRACING=y\n";
        let r = classify(cfg, Path::new("/boot/config-x"));
        assert!(
            matches!(r, KprobeOverrideStatus::Unsupported { .. }),
            "got {r:?}"
        );
    }

    #[test]
    fn classify_n_value_is_unsupported() {
        let cfg = "CONFIG_BPF_KPROBE_OVERRIDE=n\n";
        let r = classify(cfg, Path::new("/boot/config-x"));
        assert!(
            matches!(r, KprobeOverrideStatus::Unsupported { .. }),
            "got {r:?}"
        );
    }

    #[test]
    fn detect_from_missing_file_is_unknown() {
        let r = detect_from_config_file(Path::new("/definitely/no/such/path"));
        match r {
            KprobeOverrideStatus::Unknown { reason } => assert!(
                reason.contains("/definitely/no/such/path"),
                "reason should name the path: {reason:?}"
            ),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn detect_from_present_config_round_trips() {
        let d = std::env::temp_dir().join(format!(
            "sakimori-kprobe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("config-fake");
        std::fs::write(&p, "CONFIG_BPF_KPROBE_OVERRIDE=y\n").unwrap();
        assert!(detect_from_config_file(&p).is_available());
        std::fs::remove_dir_all(&d).ok();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_always_unknown() {
        assert!(matches!(detect(), KprobeOverrideStatus::Unknown { .. }));
    }
}

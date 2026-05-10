//! Userspace-side policy matching for events that reach the aggregator.
//!
//! The eBPF tracepoint ships the filename (and the connect programs ship
//! daddr / dport), but doesn't apply file policy itself — doing the scan
//! in-kernel blew the verifier's complexity budget. We stamp the verdict
//! here, just before the event is counted.

use crate::policy::{DefaultDecision, FilePolicy, ProcessPolicy};

pub struct FileMatcher {
    pub default: DefaultDecision,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl FileMatcher {
    pub fn from_policy(p: &FilePolicy) -> Self {
        Self {
            default: p.default,
            allow: p.allow.clone(),
            deny: p.deny.clone(),
        }
    }

    /// Returns true when opening `path` should be treated as denied.
    /// Deny entries win over allow entries (same precedence as the
    /// network map).
    pub fn is_denied(&self, path: &str) -> bool {
        // The eBPF ringbuf occasionally emits open events with an
        // empty filename — typically anonymous mmaps, deleted files,
        // or memfd-style opens where the kernel can't recover an
        // absolute path. Empty isn't actually a path we can
        // meaningfully police, but with `default: deny` it would
        // fall through every prefix check and get tagged as denied,
        // inflating `stats.denied` and tripping block-mode exits on
        // runs where nothing real was blocked. Treat as not-denied.
        if path.is_empty() {
            return false;
        }
        for pat in &self.deny {
            if prefix_match(path, pat) {
                return true;
            }
        }
        for pat in &self.allow {
            if prefix_match(path, pat) {
                return false;
            }
        }
        matches!(self.default, DefaultDecision::Deny)
    }
}

/// Matches exec events against `process.deny_exec`. Userspace-only for now
/// (kernel-side deny would need `bpf_override_return`, which is kernel-config
/// dependent). A match stamps the event as denied in the audit log; in
/// `mode: block` the run exits non-zero because `stats.denied > 0`, but the
/// child process itself is **not** prevented from exec'ing. See README
/// "Limitations".
pub struct ExecMatcher {
    patterns: Vec<String>,
}

impl ExecMatcher {
    pub fn from_policy(p: &ProcessPolicy) -> Self {
        Self {
            patterns: p.deny_exec.clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns true when an exec of `filename` (absolute path) or `argv0`
    /// matches any deny pattern. Two matching modes based on the pattern:
    ///
    /// - **Pattern with `/` or `\\`** (e.g. `/usr/bin/nc`) — directory-
    ///   boundary-aware prefix match on both `filename` and `argv0`.
    /// - **Pattern without a separator** (e.g. `whoami`, `nc`) — basename
    ///   match, case-insensitive, `.exe` tolerated. Makes
    ///   `...\\System32\\whoami.exe` match `whoami`.
    pub fn is_denied(&self, filename: &str, argv0: &str) -> bool {
        self.patterns
            .iter()
            .any(|p| exec_one_match(filename, argv0, p))
    }
}

fn exec_one_match(filename: &str, argv0: &str, pattern: &str) -> bool {
    let has_sep = pattern.contains('/') || pattern.contains('\\');
    if has_sep {
        return prefix_match(filename, pattern) || prefix_match(argv0, pattern);
    }
    basename_match(filename, pattern) || basename_match(argv0, pattern)
}

fn basename_match(path: &str, pattern: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if base.eq_ignore_ascii_case(pattern) {
        return true;
    }
    if let Some(stripped) = base.strip_suffix(".exe")
        && stripped.eq_ignore_ascii_case(pattern)
    {
        return true;
    }
    false
}

fn prefix_match(path: &str, pattern: &str) -> bool {
    // Exact prefix, with a boundary check so `/etc/shadow` doesn't match
    // `/etc/shadowed`. A trailing slash in the pattern forces directory
    // semantics explicitly.
    if !path.starts_with(pattern) {
        return false;
    }
    match path.as_bytes().get(pattern.len()) {
        None => true,                              // exact match
        Some(b'/') => true,                        // directory boundary
        Some(_) if pattern.ends_with('/') => true, // explicit dir pattern
        _ => path.len() == pattern.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(default: DefaultDecision, allow: &[&str], deny: &[&str]) -> FileMatcher {
        FileMatcher {
            default,
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn exact_and_child_prefix_matches() {
        let fm = m(DefaultDecision::Allow, &[], &["/etc/shadow", "/root/.ssh"]);
        assert!(fm.is_denied("/etc/shadow"));
        assert!(fm.is_denied("/root/.ssh/id_rsa"));
        assert!(!fm.is_denied("/etc/shadowed")); // boundary check
        assert!(!fm.is_denied("/etc/passwd"));
    }

    #[test]
    fn allow_list_with_default_deny() {
        let fm = m(DefaultDecision::Deny, &["/usr", "/lib", "/proc"], &[]);
        assert!(!fm.is_denied("/usr/bin/curl"));
        assert!(!fm.is_denied("/proc/self/maps"));
        assert!(fm.is_denied("/etc/passwd"));
    }

    #[test]
    fn deny_wins_over_allow() {
        let fm = m(DefaultDecision::Allow, &["/etc"], &["/etc/shadow"]);
        assert!(fm.is_denied("/etc/shadow"));
        assert!(!fm.is_denied("/etc/hostname"));
    }

    #[test]
    fn empty_path_is_not_denied_under_default_deny() {
        // anonymous mmap / deleted file / memfd opens come through
        // the ringbuf with an empty filename. With default-deny,
        // those would otherwise fall through allow checks and get
        // tagged as denied — flooding `stats.denied` and tripping
        // block-mode exit on runs where nothing real was denied.
        let fm = m(DefaultDecision::Deny, &["/usr", "/lib"], &["/etc/shadow"]);
        assert!(!fm.is_denied(""));
    }

    fn em(patterns: &[&str]) -> ExecMatcher {
        ExecMatcher {
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn exec_matcher_matches_filename_or_argv0() {
        let nc = em(&["/usr/bin/nc"]);
        assert!(nc.is_denied("/usr/bin/nc", "nc"));
        assert!(nc.is_denied("/usr/bin/nc", ""));
        // `argv0` alone can match too — shells often launch tools by name.
        let curl = em(&["curl"]);
        assert!(curl.is_denied("", "curl"));
    }

    #[test]
    fn exec_matcher_ignores_unrelated() {
        let em = em(&["/usr/bin/nc"]);
        assert!(!em.is_denied("/usr/bin/ncat", ""));
        assert!(!em.is_denied("/bin/bash", "bash"));
    }

    #[test]
    fn exec_basename_match_is_case_insensitive_and_exe_tolerant() {
        let em = em(&["whoami"]);
        // Windows: full NT path with .exe suffix should still match.
        assert!(em.is_denied(r"\Device\HarddiskVolume4\Windows\System32\whoami.exe", ""));
        // Case-insensitive.
        assert!(em.is_denied("/usr/bin/WHOAMI", ""));
        // Doesn't match substrings.
        assert!(!em.is_denied("/usr/bin/whoamimisc", ""));
    }

    #[test]
    fn exec_full_path_pattern_keeps_prefix_semantics() {
        let em = em(&["/usr/bin/nc"]);
        assert!(em.is_denied("/usr/bin/nc", ""));
        assert!(!em.is_denied("/usr/bin/ncat", ""));
    }
}

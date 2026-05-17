//! Cloud-credential exfiltration tripwire — classification half.
//!
//! The Shai-Hulud playbook reaches for cloud metadata services and
//! secret-store APIs in the first 30 seconds of post-install
//! execution, because that's where the *transferable* credentials
//! live (the user's local checkout already has any source-code
//! secrets the attacker wants). The `policy preset
//! cloud-secret-egress` rule already denies these destinations at
//! the network layer; this module adds the **observability** half:
//! every Connect event whose target matches the canonical list AND
//! whose originating PID's attribution names a package manager
//! ancestor is tagged a "cloud-secret egress attempt" so the JSON
//! log + step summary surface it as a distinct, high-signal event
//! category instead of burying it in the generic "denied connect"
//! pile.
//!
//! Single source of truth: the host/IP lists live here and are
//! consumed both by [`crate::presets`] (which emits them as YAML
//! deny rules) and by the supervisor's post-run classifier (this
//! module). Keeping them in one place means a new region or a new
//! provider only needs one edit.

use serde::Serialize;

use crate::attribution::Attribution;
use crate::events::Event;

/// Coarse provider grouping — kept as a `&'static str` rather than
/// an enum so JSON output is forward-compatible: adding a new
/// category later doesn't break consumers that match on string.
pub type Category = &'static str;

/// IPv4 / IPv6 literal targets that match by exact daddr. Today the
/// only literal is the link-local IMDS magic IP (AWS, GCP, Azure all
/// share it).
pub const CLOUD_SECRET_IPS: &[(&str, Category)] = &[("169.254.169.254", "cloud-metadata-imds")];

/// Hostnames (including hostname-suffix matches) — matched against
/// the resolved PTR hostname of the Connect event when present.
/// Substring-match the `daddr` too, in case the kernel decoder
/// already gave us a hostname-like string (e.g. some sidecars send
/// the SNI through). Lower-cased before compare.
pub const CLOUD_SECRET_HOSTS: &[(&str, Category)] = &[
    ("metadata.google.internal", "cloud-metadata-imds"),
    ("sts.amazonaws.com", "cloud-secret-store"),
    (
        "secretsmanager.us-east-1.amazonaws.com",
        "cloud-secret-store",
    ),
    ("ssm.us-east-1.amazonaws.com", "cloud-secret-store"),
    ("vault.service.consul", "cloud-secret-store"),
    (
        "vstoken.actions.githubusercontent.com",
        "cloud-oidc-token-mint",
    ),
];

/// Decide whether the (`daddr`, optional `hostname`) tuple resolves
/// to a known cloud-secret destination. Returns the category label
/// on a hit, `None` otherwise.
///
/// Hostname match is suffix-anchored on a `.`-boundary so
/// `attacker-sts.amazonaws.com.evil.tld` does NOT collide with
/// `sts.amazonaws.com`. The IP match is exact — link-local IMDS is
/// never a CNAME/SNI thing.
pub fn classify_target(daddr: &str, hostname: Option<&str>) -> Option<Category> {
    for (ip, cat) in CLOUD_SECRET_IPS {
        if daddr == *ip {
            return Some(*cat);
        }
    }
    let candidates = [Some(daddr), hostname].into_iter().flatten();
    for cand in candidates {
        let lc = cand.to_ascii_lowercase();
        for (host, cat) in CLOUD_SECRET_HOSTS {
            if host_matches(&lc, host) {
                return Some(*cat);
            }
        }
    }
    None
}

/// Component-aligned suffix match: `host` matches `pattern` if it
/// equals the pattern, or if it ends with `.<pattern>`. Prevents the
/// `.evil.tld` suffix-extension trick.
fn host_matches(host: &str, pattern: &str) -> bool {
    if host == pattern {
        return true;
    }
    if host.len() > pattern.len() + 1
        && host.ends_with(pattern)
        && host.as_bytes()[host.len() - pattern.len() - 1] == b'.'
    {
        return true;
    }
    false
}

/// Per-event classification result. The supervisor walks
/// [`crate::stats::Stats::samples`] post-run and emits a
/// [`Hit`] for every Connect event that matches.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Hit {
    /// Provider grouping ([`CLOUD_SECRET_IPS`] /
    /// [`CLOUD_SECRET_HOSTS`] right-hand column).
    pub category: Category,
    /// The literal destination string we matched on — `daddr` for an
    /// IP hit, `hostname` (or `daddr` if `daddr` itself looked
    /// hostname-shaped) for a host hit. Surfaces in the audit log so
    /// reviewers see exactly what tripped the rule.
    pub target: String,
    pub pid: u32,
    pub comm: String,
    pub denied: bool,
    /// The package-manager name from attribution (`"npm"`,
    /// `"cargo"`, …). The classifier only emits a `Hit` when this
    /// is `Some` — egress attempts from non-pkg-manager processes
    /// (a manually-invoked `curl`, the user's own script) carry
    /// different threat-model weight and stay in the generic
    /// connect log.
    pub package_manager: String,
}

/// Scan an iterator of events and pull out cloud-secret egress
/// attempts attributed to a package-manager subtree. Pure compute —
/// no IO, no side effects.
pub fn scan_events<'a, I>(events: I) -> Vec<Hit>
where
    I: IntoIterator<Item = &'a Event>,
{
    let mut out = Vec::new();
    for ev in events {
        if let Event::Connect {
            pid,
            comm,
            daddr,
            denied,
            hostname,
            source,
            ..
        } = ev
            && let Some(category) = classify_target(daddr, hostname.as_deref())
            && let Some(pm) = pkg_manager_label(source.as_ref())
        {
            let target = hostname
                .as_deref()
                .filter(|h| !h.is_empty())
                .unwrap_or(daddr.as_str())
                .to_string();
            out.push(Hit {
                category,
                target,
                pid: *pid,
                comm: comm.clone(),
                denied: *denied,
                package_manager: pm,
            });
        }
    }
    out
}

fn pkg_manager_label(attr: Option<&Attribution>) -> Option<String> {
    let pm = attr?.package_manager?;
    Some(format!("{pm:?}").to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::{Attribution, PackageManager, ProcInfo};

    fn connect_event(
        daddr: &str,
        hostname: Option<&str>,
        attr: Option<Attribution>,
        denied: bool,
    ) -> Event {
        Event::Connect {
            pid: 42,
            uid: 1000,
            comm: "node".into(),
            daddr: daddr.into(),
            dport: 443,
            protocol: 6,
            denied,
            hostname: hostname.map(String::from),
            source: attr,
        }
    }

    fn npm_attribution() -> Attribution {
        Attribution {
            chain: vec![ProcInfo {
                pid: 1,
                argv0: "npm".into(),
                argv: "npm install something".into(),
            }],
            package_manager: Some(PackageManager::Npm),
            root_argv: Some("npm install something".into()),
        }
    }

    #[test]
    fn classifies_imds_ip_literal() {
        assert_eq!(
            classify_target("169.254.169.254", None),
            Some("cloud-metadata-imds")
        );
    }

    #[test]
    fn classifies_known_hostname() {
        assert_eq!(
            classify_target("1.2.3.4", Some("sts.amazonaws.com")),
            Some("cloud-secret-store")
        );
    }

    #[test]
    fn classifies_via_daddr_when_hostname_missing() {
        // Some collectors put the hostname directly in `daddr` (rare,
        // but happens with SNI sniffers). Suffix-match should still
        // catch it.
        assert_eq!(
            classify_target("metadata.google.internal", None),
            Some("cloud-metadata-imds")
        );
    }

    #[test]
    fn rejects_suffix_extension_attack() {
        // `attacker-sts.amazonaws.com.evil.tld` must NOT match
        // `sts.amazonaws.com` — that's a classic dot-boundary trap.
        assert_eq!(
            classify_target("1.2.3.4", Some("sts.amazonaws.com.evil.tld")),
            None
        );
        // Substring without `.` boundary also misses.
        assert_eq!(
            classify_target("1.2.3.4", Some("faketsts.amazonaws.com")),
            None
        );
    }

    #[test]
    fn accepts_proper_subdomain_match() {
        // Subdomain of a known endpoint counts — a malicious worker
        // hitting `regional.sts.amazonaws.com` is the same threat.
        assert_eq!(
            classify_target("1.2.3.4", Some("internal.sts.amazonaws.com")),
            Some("cloud-secret-store")
        );
    }

    #[test]
    fn case_insensitive_hostname() {
        assert_eq!(
            classify_target("1.2.3.4", Some("STS.AMAZONAWS.COM")),
            Some("cloud-secret-store")
        );
    }

    #[test]
    fn scan_emits_hit_for_npm_attributed_imds() {
        let events = vec![connect_event(
            "169.254.169.254",
            None,
            Some(npm_attribution()),
            true,
        )];
        let hits = scan_events(&events);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "cloud-metadata-imds");
        assert_eq!(hits[0].target, "169.254.169.254");
        assert_eq!(hits[0].package_manager, "npm");
        assert!(hits[0].denied);
    }

    #[test]
    fn scan_skips_when_no_package_manager_attribution() {
        // User curl with no pm ancestor → not in scope for this
        // tripwire (different threat model; classifier docs explain
        // why). Generic "denied connect" still surfaces elsewhere.
        let events = vec![connect_event(
            "169.254.169.254",
            None,
            Some(Attribution {
                chain: vec![],
                package_manager: None,
                root_argv: None,
            }),
            true,
        )];
        assert!(scan_events(&events).is_empty());
    }

    #[test]
    fn scan_skips_when_no_attribution_at_all() {
        let events = vec![connect_event("169.254.169.254", None, None, true)];
        assert!(scan_events(&events).is_empty());
    }

    #[test]
    fn scan_skips_non_cloud_secret_destinations() {
        let events = vec![connect_event(
            "1.2.3.4",
            Some("registry.npmjs.org"),
            Some(npm_attribution()),
            false,
        )];
        assert!(scan_events(&events).is_empty());
    }

    #[test]
    fn scan_emits_for_both_denied_and_allowed_attempts() {
        // An *allowed* connect to IMDS from npm should still raise a
        // flag — the user hasn't installed the cloud-secret-egress
        // preset yet, but the attempt is the signal. The `denied`
        // bit lets the report colour the severity.
        let events = vec![connect_event(
            "169.254.169.254",
            None,
            Some(npm_attribution()),
            false,
        )];
        let hits = scan_events(&events);
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].denied);
    }

    #[test]
    fn target_string_prefers_hostname_when_present() {
        let events = vec![connect_event(
            "1.2.3.4",
            Some("sts.amazonaws.com"),
            Some(npm_attribution()),
            true,
        )];
        let hits = scan_events(&events);
        assert_eq!(hits[0].target, "sts.amazonaws.com");
    }
}

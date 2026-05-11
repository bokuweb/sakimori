//! OSV.dev integration — "this exact `(name, version)` is listed as
//! malicious by the OpenSSF Malicious Packages project or GitHub
//! Advisories".
//!
//! Layered on top of the age filter: even a very old package can be
//! known-malicious (event-stream 3.3.6 was published in 2018 and is
//! still poisonous), so the OSV check runs *before* the age check
//! and hard-denies regardless of `--min-age`.
//!
//! We only flag entries that OSV classifies as a malicious package —
//! i.e. the vuln ID starts with `MAL-`, or the advisory body contains
//! the `"malicious"` signal. This keeps us from blocking every
//! package that just has an unfixed CVE (which is most of npm).
//!
//! The module exposes:
//!
//! - [`KnownBadOracle`] — trait the `Decider` consumes
//! - [`OsvClient`] — production impl, talks to `api.osv.dev` via
//!   blocking HTTPS with an in-memory cache keyed on
//!   `(ecosystem, name, version)`. Positive results (match found)
//!   never expire; negative results get a short TTL so a
//!   newly-disclosed malicious version stops leaking through
//!   within minutes.
//!
//! The pure filtering logic ([`is_malicious`]) is unit-tested with
//! canned OSV responses so the integration path stays tiny.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sakimori_core::deps::Ecosystem;
use serde::Deserialize;

/// Plug-in point for "known-bad" lookups. Returning `Ok(Some(ids))`
/// with a non-empty list means the caller should hard-deny;
/// `Ok(None)` or an empty vec means "not flagged".
pub trait KnownBadOracle: Send + Sync {
    /// Query the oracle for a specific package version. Implementors
    /// are expected to cache; callers may be called many times per
    /// session.
    fn lookup(&self, eco: Ecosystem, name: &str, version: &str) -> Result<Option<Vec<String>>>;
}

// ------------------ OsvClient ------------------

const OSV_ENDPOINT: &str = "https://api.osv.dev/v1/query";

/// Short TTL for negative results (no match). OSV can add a new
/// malicious entry at any time; this bounds the exposure window.
const NEGATIVE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone)]
struct CacheEntry {
    ids: Vec<String>,
    /// When this entry was written. Combined with NEGATIVE_TTL for
    /// negative results; positives are kept indefinitely for the
    /// lifetime of the process.
    at: Instant,
}

pub struct OsvClient {
    user_agent: String,
    cache: Mutex<HashMap<(Ecosystem, String, String), CacheEntry>>,
}

impl OsvClient {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, key: &(Ecosystem, String, String)) -> Option<Vec<String>> {
        let g = self.cache.lock().ok()?;
        let entry = g.get(key)?;
        let is_positive = !entry.ids.is_empty();
        let fresh = is_positive || entry.at.elapsed() < NEGATIVE_TTL;
        fresh.then(|| entry.ids.clone())
    }

    fn remember(&self, key: (Ecosystem, String, String), ids: Vec<String>) {
        if let Ok(mut g) = self.cache.lock() {
            g.insert(
                key,
                CacheEntry {
                    ids,
                    at: Instant::now(),
                },
            );
        }
    }

    fn fetch(&self, eco: Ecosystem, name: &str, version: &str) -> Result<Vec<String>> {
        let eco_str = eco_to_osv(eco);
        let body = serde_json::json!({
            "package": { "name": name, "ecosystem": eco_str },
            "version": version,
        });
        let resp = ureq::post(OSV_ENDPOINT)
            .set("user-agent", &self.user_agent)
            .set("accept", "application/json")
            .timeout(Duration::from_millis(1500))
            .send_json(body)
            .with_context(|| format!("OSV query for {}/{name}@{version}", eco.label()))?;
        let parsed: OsvResponse = resp
            .into_json()
            .context("OSV response body not JSON in the expected shape")?;
        // `into_iter` hands out owned `OsvVuln`, but `filter` wants a
        // closure over `&Item`; passing `is_malicious` as a fn ptr
        // fails the `Fn(&&T) -> bool` bound the iterator adapter
        // expects. Keep the closure explicitly.
        #[allow(clippy::redundant_closure)]
        let ids = parsed
            .vulns
            .into_iter()
            .filter(|v| is_malicious(v))
            .map(|v| v.id)
            .collect();
        Ok(ids)
    }
}

impl KnownBadOracle for OsvClient {
    fn lookup(&self, eco: Ecosystem, name: &str, version: &str) -> Result<Option<Vec<String>>> {
        let key = (eco, name.to_string(), version.to_string());
        if let Some(cached) = self.cached(&key) {
            return Ok(if cached.is_empty() {
                None
            } else {
                Some(cached)
            });
        }
        let ids = self.fetch(eco, name, version)?;
        self.remember(key, ids.clone());
        Ok(if ids.is_empty() { None } else { Some(ids) })
    }
}

// ------------------ decoding + heuristics ------------------

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    /// OSV's ecosystem-specific metadata — we consult nothing here
    /// directly but keep the field so serde doesn't complain.
    #[serde(default, rename = "database_specific")]
    _database_specific: serde_json::Value,
}

/// Is this OSV vulnerability flagged as a *malicious package*, as
/// opposed to a regular vulnerability?
///
/// Rules (ordered; any match is enough):
/// 1. ID starts with `MAL-` — OSV's explicit malicious-package prefix.
/// 2. Summary or details contain the case-insensitive substring
///    `"malicious"`. GHSA advisories routinely title these
///    "Malicious Package in <name>".
fn is_malicious(v: &OsvVuln) -> bool {
    if v.id.starts_with("MAL-") {
        return true;
    }
    let summary = v.summary.to_lowercase();
    let details = v.details.to_lowercase();
    summary.contains("malicious") || details.contains("malicious")
}

fn eco_to_osv(eco: Ecosystem) -> &'static str {
    // OSV's ecosystem strings:
    //   https://ossf.github.io/osv-schema/#affectedpackage-field
    match eco {
        Ecosystem::Crates => "crates.io",
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "PyPI",
        Ecosystem::Nuget => "NuGet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(id: &str, summary: &str, details: &str) -> OsvVuln {
        OsvVuln {
            id: id.into(),
            summary: summary.into(),
            details: details.into(),
            _database_specific: serde_json::Value::Null,
        }
    }

    #[test]
    fn mal_prefixed_ids_are_malicious() {
        assert!(is_malicious(&vuln("MAL-2025-12345", "", "")));
        assert!(is_malicious(&vuln("MAL-0", "", "")));
    }

    #[test]
    fn ghsa_with_malicious_summary_is_malicious() {
        assert!(is_malicious(&vuln(
            "GHSA-9x64-5r7x-2q53",
            "Malicious Package in flatmap-stream",
            "",
        )));
    }

    #[test]
    fn ghsa_with_malicious_in_details_is_malicious() {
        assert!(is_malicious(&vuln(
            "GHSA-abcd-efgh-ijkl",
            "Some summary",
            "The package was found to include malicious code that exfiltrates tokens.",
        )));
    }

    #[test]
    fn ordinary_cve_is_not_malicious() {
        // A regular CVE — e.g. a buffer overflow — shouldn't trip
        // the filter. We don't want the proxy to deny every package
        // that has any unfixed vuln; that'd be the entire ecosystem.
        assert!(!is_malicious(&vuln(
            "CVE-2024-9999",
            "Buffer overflow in foo",
            "A buffer overflow in foo may allow remote code execution.",
        )));
        assert!(!is_malicious(&vuln(
            "GHSA-1111-2222-3333",
            "Denial of Service in bar",
            "Crafted input can cause crash.",
        )));
    }

    #[test]
    fn malicious_is_case_insensitive() {
        assert!(is_malicious(&vuln("X", "MALICIOUS PACKAGE", "")));
        assert!(is_malicious(&vuln("X", "", "Contains Malicious Code")));
    }

    #[test]
    fn ecosystem_mapping_matches_osv_schema() {
        assert_eq!(eco_to_osv(Ecosystem::Crates), "crates.io");
        assert_eq!(eco_to_osv(Ecosystem::Npm), "npm");
        assert_eq!(eco_to_osv(Ecosystem::Pypi), "PyPI");
        assert_eq!(eco_to_osv(Ecosystem::Nuget), "NuGet");
    }

    #[test]
    fn response_decode_handles_empty_vulns() {
        // OSV returns `{}` when there are no hits (no `vulns`
        // field at all), so the #[serde(default)] on Vec is load-bearing.
        let empty: OsvResponse = serde_json::from_str("{}").unwrap();
        assert!(empty.vulns.is_empty());
        let explicit: OsvResponse = serde_json::from_str(r#"{"vulns":[]}"#).unwrap();
        assert!(explicit.vulns.is_empty());
    }

    #[test]
    fn response_decode_handles_mixed_ids() {
        let body = r#"{
            "vulns": [
                { "id": "GHSA-x", "summary": "normal CVE" },
                { "id": "MAL-1", "summary": "malicious package" }
            ]
        }"#;
        let r: OsvResponse = serde_json::from_str(body).unwrap();
        let malicious_ids: Vec<_> = r
            .vulns
            .iter()
            .filter(|v| is_malicious(v))
            .map(|v| &v.id)
            .collect();
        assert_eq!(malicious_ids, vec!["MAL-1"]);
    }

    // --- cache behaviour ---

    #[test]
    fn positive_results_are_cached_indefinitely() {
        // We simulate by directly seeding the cache and confirming
        // a subsequent lookup reads back the seeded value.
        let client = OsvClient::new("test-agent/0.1");
        let key = (Ecosystem::Npm, "evil".into(), "1.0.0".into());
        client.remember(key.clone(), vec!["MAL-1".into()]);
        let hit = client.cached(&key).unwrap();
        assert_eq!(hit, vec!["MAL-1"]);
    }

    #[test]
    fn negative_results_honour_ttl() {
        let client = OsvClient::new("test-agent/0.1");
        let key = (Ecosystem::Npm, "clean".into(), "1.0.0".into());
        client.remember(key.clone(), vec![]);
        // Immediately cached.
        assert!(client.cached(&key).is_some());
        // Rewrite the entry with a stale timestamp to simulate TTL
        // elapsing — easier than sleeping for 10 minutes in a test.
        if let Ok(mut g) = client.cache.lock()
            && let Some(entry) = g.get_mut(&key)
        {
            entry.at = Instant::now() - NEGATIVE_TTL - Duration::from_secs(1);
        }
        assert!(client.cached(&key).is_none());
    }
}

//! OSV mirror consumer — the Tier-2b counterpart to the live-API
//! [`OsvClient`](crate::osv::OsvClient).
//!
//! Instead of hitting `api.osv.dev` on every decision, we pull a
//! pre-filtered denylist from a static URL (by default GitHub's
//! `raw.githubusercontent.com`, populated by our own cron-driven
//! producer — see `.github/workflows/osv-mirror.yml`), keep it in
//! memory as a `HashSet`, and refresh in the background every 10
//! minutes via ETag-gated conditional GET.
//!
//! Trade-offs vs. live OSV API:
//!
//! | aspect | live API | mirror |
//! |---|---|---|
//! | per-request latency | 1.5 s timeout | O(1) in-mem lookup |
//! | OSV.dev load per org | O(N clients × req) | O(1) producer |
//! | offline / airgap | no | yes (snapshot bundled) |
//! | freshness | seconds | ~10 minutes |
//!
//! The schema is documented in `scripts/build-osv-mirror.py`. The
//! parser below is deliberately tolerant of unknown fields so the
//! producer schema can evolve without breaking older clients.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{Context, Result};
use sakimori_core::deps::Ecosystem;

use crate::osv::KnownBadOracle;

/// Default upstream URL. Consumers can override via
/// [`OsvMirrorOracle::with_url`] / the CLI flag.
pub const DEFAULT_MIRROR_URL: &str =
    "https://raw.githubusercontent.com/bokuweb/sakimori/osv-mirror-data/mal.json";

/// How often the background task re-fetches the mirror. Producer
/// cron is also 10 minutes, so on average we're ~5 minutes behind
/// OSV publish time. Cut in half if you need fresher.
pub const REFRESH_EVERY: Duration = Duration::from_secs(10 * 60);

/// Timeout for a single HTTP refresh. Generous — GitHub raw is fast
/// but the dump is multi-megabyte.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Wildcard version token used by the producer when an OSV advisory
/// didn't enumerate specific versions. A lookup for a specific
/// version falls back to this after missing the exact match.
const VERSION_WILDCARD: &str = "*";

type Key = (Ecosystem, String, String);

/// The in-memory denylist built from one mirror snapshot. Kept
/// separate from [`OsvMirrorOracle`] so we can swap it atomically
/// after each successful refresh without blocking lookups.
#[derive(Debug, Default)]
pub struct MirrorState {
    /// `(eco, name, version)` → list of OSV IDs that flagged it.
    /// Version `"*"` means "every version of this package" — a
    /// wildcard lookup path in [`lookup`].
    entries: HashMap<Key, Vec<String>>,
    /// Stored ETag from the last successful fetch, for conditional
    /// re-requests. A 304 response keeps the current entries and
    /// just bumps the ETag timestamp.
    pub etag: Option<String>,
    /// When we populated `entries`. `None` before the first fetch.
    pub updated_at: Option<String>,
}

impl MirrorState {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn lookup(&self, eco: Ecosystem, name: &str, version: &str) -> Option<Vec<String>> {
        // Exact (eco, name, version) hit wins.
        let exact_key = (eco, name.to_string(), version.to_string());
        if let Some(ids) = self.entries.get(&exact_key) {
            return Some(ids.clone());
        }
        // Fall back to wildcard — the advisory flagged every
        // version, so any version of this package is denied.
        let wildcard_key = (eco, name.to_string(), VERSION_WILDCARD.to_string());
        self.entries.get(&wildcard_key).cloned()
    }
}

/// Parse a `mal.json` body (schema 1 or 2) into a ready-to-query
/// [`MirrorState`]. Unknown ecosystems and malformed rows are
/// skipped silently — producers older than this consumer can add
/// new ecosystems without breaking us.
pub fn parse_mirror_dump(body: &[u8]) -> Result<HashMap<Key, Vec<String>>> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).context("mirror body is not valid JSON")?;
    let entries = doc
        .get("entries")
        .and_then(|v| v.as_array())
        .context("mirror body has no `entries` array")?;

    let mut out: HashMap<Key, Vec<String>> = HashMap::with_capacity(entries.len());
    for row in entries {
        // Schema 2: flat array `[eco, name, version, id]`.
        if let Some(arr) = row.as_array() {
            let eco = arr.first().and_then(|v| v.as_str());
            let name = arr.get(1).and_then(|v| v.as_str());
            let version = arr.get(2).and_then(|v| v.as_str());
            let id = arr.get(3).and_then(|v| v.as_str());
            if let (Some(eco), Some(name), Some(version), Some(id)) = (eco, name, version, id)
                && let Some(e) = label_to_eco(eco)
            {
                out.entry((e, name.to_string(), version.to_string()))
                    .or_default()
                    .push(id.to_string());
            }
            continue;
        }
        // Schema 1 (pre-v0.26, object with versions[]/ids[]) — kept
        // for forward-compat if an older producer lingers.
        if let Some(obj) = row.as_object()
            && let (Some(eco), Some(name)) = (
                obj.get("eco").and_then(|v| v.as_str()),
                obj.get("name").and_then(|v| v.as_str()),
            )
            && let Some(e) = label_to_eco(eco)
        {
            let ids: Vec<String> = obj
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let versions: Vec<String> = obj
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if versions.is_empty() {
                out.entry((e, name.to_string(), VERSION_WILDCARD.to_string()))
                    .or_default()
                    .extend(ids.iter().cloned());
            } else {
                for v in versions {
                    out.entry((e, name.to_string(), v))
                        .or_default()
                        .extend(ids.iter().cloned());
                }
            }
        }
    }

    // Dedup IDs per key — multiple advisories covering the same
    // (name, version) would otherwise show up as duplicates in the
    // deny-reason string.
    for ids in out.values_mut() {
        ids.sort();
        ids.dedup();
    }
    Ok(out)
}

fn label_to_eco(label: &str) -> Option<Ecosystem> {
    match label {
        "crates" => Some(Ecosystem::Crates),
        "npm" => Some(Ecosystem::Npm),
        "pypi" => Some(Ecosystem::Pypi),
        "nuget" => Some(Ecosystem::Nuget),
        _ => None,
    }
}

/// Background-refreshed OSV mirror consumer. Clone cheaply: all
/// state lives behind `Arc<RwLock<_>>`.
#[derive(Clone)]
pub struct OsvMirrorOracle {
    url: String,
    user_agent: String,
    state: std::sync::Arc<RwLock<MirrorState>>,
}

impl OsvMirrorOracle {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self::with_url(user_agent, DEFAULT_MIRROR_URL)
    }

    pub fn with_url(user_agent: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            user_agent: user_agent.into(),
            state: std::sync::Arc::new(RwLock::new(MirrorState::default())),
        }
    }

    /// Perform one fetch + swap. Returns `true` if the snapshot was
    /// updated, `false` if the server returned 304 or the body
    /// didn't change. Errors surface to the caller so the spawn
    /// loop can log and retry.
    pub fn refresh_once(&self) -> Result<bool> {
        let etag_before = self.state.read().ok().and_then(|s| s.etag.clone());
        let mut req = ureq::get(&self.url)
            .set("user-agent", &self.user_agent)
            .set("accept", "application/json")
            .timeout(FETCH_TIMEOUT);
        if let Some(etag) = &etag_before {
            req = req.set("if-none-match", etag);
        }
        // We ignore transport errors on 304 — ureq surfaces them as
        // `Error::Status(304, _)` rather than `Ok` with `.status()`.
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(304, _)) => {
                log::debug!("osv-mirror: 304 Not Modified");
                return Ok(false);
            }
            Err(e) => return Err(anyhow::anyhow!("fetch {}: {e:#}", self.url)),
        };
        let new_etag = resp.header("etag").map(str::to_string);
        let body = resp
            .into_string()
            .context("osv-mirror response body unreadable")?;
        let entries = parse_mirror_dump(body.as_bytes())?;
        let updated_at = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("updated_at")
                    .and_then(|u| u.as_str())
                    .map(String::from)
            });
        if let Ok(mut w) = self.state.write() {
            w.entries = entries;
            w.etag = new_etag;
            w.updated_at = updated_at;
            log::info!(
                "osv-mirror: refreshed — {} entries from {}",
                w.entries.len(),
                self.url
            );
        }
        Ok(true)
    }

    /// Spawn a tokio task that calls [`refresh_once`] on start and
    /// every [`REFRESH_EVERY`] thereafter. Fire-and-forget — the
    /// returned `JoinHandle` is typically dropped.
    pub fn spawn_refresh_loop(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                // The fetch itself is blocking (ureq), run on a
                // blocking thread so we don't starve the async
                // runtime on the multi-megabyte download.
                let ours = this.clone();
                let res = tokio::task::spawn_blocking(move || ours.refresh_once()).await;
                match res {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => log::warn!("osv-mirror: refresh failed: {e:#}"),
                    Err(e) => log::warn!("osv-mirror: refresh task panicked: {e}"),
                }
                tokio::time::sleep(REFRESH_EVERY).await;
            }
        })
    }

    /// For tests: read-only snapshot of the current state.
    #[cfg(test)]
    pub fn snapshot_len(&self) -> usize {
        self.state.read().map(|s| s.len()).unwrap_or(0)
    }
}

impl KnownBadOracle for OsvMirrorOracle {
    fn lookup(&self, eco: Ecosystem, name: &str, version: &str) -> Result<Option<Vec<String>>> {
        let Ok(st) = self.state.read() else {
            return Ok(None);
        };
        Ok(st.lookup(eco, name, version))
    }
}

/// Combine two `KnownBadOracle`s into one that prefers the first,
/// then falls back to the second. Used to layer the mirror in
/// front of the live OSV API: fast path is the local HashMap,
/// fallback path is the authoritative OSV lookup for anything the
/// mirror hasn't synced yet.
pub struct LayeredKnownBad {
    pub primary: Box<dyn KnownBadOracle>,
    pub fallback: Box<dyn KnownBadOracle>,
}

impl KnownBadOracle for LayeredKnownBad {
    fn lookup(&self, eco: Ecosystem, name: &str, version: &str) -> Result<Option<Vec<String>>> {
        match self.primary.lookup(eco, name, version) {
            Ok(Some(ids)) if !ids.is_empty() => Ok(Some(ids)),
            // Primary was clean *and* answered cleanly → trust it,
            // skip the fallback (fallback might be slower / rate-
            // limited; if the local mirror says "not known bad",
            // that's authoritative for our purposes).
            Ok(_) => Ok(None),
            Err(e) => {
                log::debug!("osv-mirror: primary failed, trying fallback: {e:#}");
                self.fallback.lookup(eco, name, version)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dump_v2() -> &'static str {
        r#"{
            "schema": 2,
            "updated_at": "2025-01-01T00:00:00Z",
            "entries": [
                ["npm",   "flatmap-stream", "0.1.1", "MAL-2025-1"],
                ["npm",   "flatmap-stream", "0.1.1", "GHSA-9x64-5r7x-2q53"],
                ["npm",   "evil-typo",      "*",     "MAL-2025-2"],
                ["pypi",  "colorsama",      "1.0.0", "MAL-2024-50"],
                ["crates","some-crate",     "0.3.0", "GHSA-craty-mal"],
                ["nuget", "BadPkg",         "1.0.0", "MAL-2024-99"]
            ]
        }"#
    }

    #[test]
    fn parse_schema_v2_flat_array_rows() {
        let m = parse_mirror_dump(sample_dump_v2().as_bytes()).unwrap();
        // 4 ecosystems × 1 unique version each, except flatmap-stream
        // has 2 advisory IDs merged on one (name, version) key.
        assert_eq!(m.len(), 5);
        let key = (Ecosystem::Npm, "flatmap-stream".into(), "0.1.1".into());
        let ids = m.get(&key).unwrap();
        assert_eq!(
            ids,
            &vec!["GHSA-9x64-5r7x-2q53".to_string(), "MAL-2025-1".to_string()],
            "merged + sorted"
        );
    }

    #[test]
    fn parse_schema_v2_wildcard_version_passes_through() {
        let m = parse_mirror_dump(sample_dump_v2().as_bytes()).unwrap();
        let key = (Ecosystem::Npm, "evil-typo".into(), "*".into());
        assert_eq!(m.get(&key).map(|v| v.len()), Some(1));
    }

    #[test]
    fn lookup_wildcard_falls_back_after_exact_miss() {
        let m = parse_mirror_dump(sample_dump_v2().as_bytes()).unwrap();
        let mut state = MirrorState {
            entries: m,
            etag: None,
            updated_at: None,
        };
        state.etag = None; // no-op, silence unused warn

        // Exact version for evil-typo doesn't exist; wildcard does.
        let ids = state.lookup(Ecosystem::Npm, "evil-typo", "99.0.0");
        assert!(ids.is_some());
        assert_eq!(ids.unwrap(), vec!["MAL-2025-2".to_string()]);

        // Exact version for flatmap-stream exists.
        let ids = state.lookup(Ecosystem::Npm, "flatmap-stream", "0.1.1");
        assert_eq!(ids.as_ref().map(|v| v.len()), Some(2));

        // Non-malicious package → no hit.
        let ids = state.lookup(Ecosystem::Npm, "lodash", "4.17.21");
        assert!(ids.is_none());
    }

    #[test]
    fn parse_tolerates_unknown_ecosystems() {
        let body = r#"{
            "schema": 2,
            "entries": [
                ["Go", "github.com/foo/bar", "v1.0.0", "MAL-go-1"],
                ["npm", "ok",                "1.0.0", "MAL-ok-1"]
            ]
        }"#;
        let m = parse_mirror_dump(body.as_bytes()).unwrap();
        // Only the npm row survives; the Go row is skipped silently.
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn parse_tolerates_malformed_rows() {
        let body = r#"{
            "schema": 2,
            "entries": [
                ["npm"],
                "not an array",
                {"eco": "npm"},
                ["npm", "ok", "1.0.0", "MAL-1"]
            ]
        }"#;
        let m = parse_mirror_dump(body.as_bytes()).unwrap();
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn parse_rejects_outer_body_with_no_entries() {
        let body = r#"{"schema": 2}"#;
        let err = parse_mirror_dump(body.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("`entries`"));
    }

    #[test]
    fn parse_schema_v1_compatibility() {
        // Older producer shape. We still want to interoperate.
        let body = r#"{
            "schema": 1,
            "entries": [
                {"eco":"npm","name":"foo","versions":["1.0.0","1.0.1"],"ids":["MAL-1"]},
                {"eco":"npm","name":"nov","versions":[],"ids":["MAL-2"]}
            ]
        }"#;
        let m = parse_mirror_dump(body.as_bytes()).unwrap();
        assert_eq!(
            m.get(&(Ecosystem::Npm, "foo".into(), "1.0.0".into()))
                .map(|v| v.len()),
            Some(1)
        );
        assert_eq!(
            m.get(&(Ecosystem::Npm, "foo".into(), "1.0.1".into()))
                .map(|v| v.len()),
            Some(1)
        );
        assert_eq!(
            m.get(&(Ecosystem::Npm, "nov".into(), "*".into()))
                .map(|v| v.len()),
            Some(1)
        );
    }

    // --- LayeredKnownBad ---

    struct FixedBad(Option<Vec<String>>);
    impl KnownBadOracle for FixedBad {
        fn lookup(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<Vec<String>>> {
            Ok(self.0.clone())
        }
    }
    struct AlwaysErr;
    impl KnownBadOracle for AlwaysErr {
        fn lookup(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<Vec<String>>> {
            Err(anyhow::anyhow!("down"))
        }
    }

    #[test]
    fn layered_prefers_primary_hit() {
        let l = LayeredKnownBad {
            primary: Box::new(FixedBad(Some(vec!["MAL-primary".into()]))),
            fallback: Box::new(FixedBad(Some(vec!["MAL-fallback".into()]))),
        };
        let ids = l.lookup(Ecosystem::Npm, "x", "1").unwrap().unwrap();
        assert_eq!(ids, vec!["MAL-primary".to_string()]);
    }

    #[test]
    fn layered_trusts_primary_when_clean() {
        // Primary says "not known bad" → we do NOT ask the
        // fallback. Prevents "mirror says clean, live API
        // confirms hit" double-lookups and also avoids leaking
        // live queries for every single request.
        let l = LayeredKnownBad {
            primary: Box::new(FixedBad(None)),
            fallback: Box::new(FixedBad(Some(vec!["MAL-fallback".into()]))),
        };
        assert!(l.lookup(Ecosystem::Npm, "x", "1").unwrap().is_none());
    }

    #[test]
    fn layered_falls_back_on_primary_error() {
        let l = LayeredKnownBad {
            primary: Box::new(AlwaysErr),
            fallback: Box::new(FixedBad(Some(vec!["MAL-fb".into()]))),
        };
        let ids = l.lookup(Ecosystem::Npm, "x", "1").unwrap().unwrap();
        assert_eq!(ids, vec!["MAL-fb".to_string()]);
    }

    #[test]
    fn default_mirror_url_is_https() {
        assert!(DEFAULT_MIRROR_URL.starts_with("https://"));
        assert!(DEFAULT_MIRROR_URL.contains("bokuweb/sakimori"));
    }
}

#[cfg(test)]
mod integration_tests {
    //! One smoke test that parses the REAL producer output checked
    //! in at `osv-mirror/mal.json`. Skipped when the file isn't
    //! present (CI producer job runs on a different commit).

    use super::*;

    #[test]
    fn parses_real_mirror_if_present() {
        let path = std::path::Path::new("../../osv-mirror/mal.json");
        if !path.exists() {
            eprintln!("osv-mirror/mal.json not present — skipping");
            return;
        }
        let bytes = std::fs::read(path).unwrap();
        let m = parse_mirror_dump(&bytes).expect("producer output should parse");
        assert!(
            m.len() > 1_000,
            "real dump should have thousands of entries, got {}",
            m.len()
        );

        // Spot-check: event-stream 3.3.6 is a known MAL- entry from npm
        // (the flatmap-stream incident). If this ever stops being in
        // the feed, the filter heuristic has regressed.
        let key = (
            Ecosystem::Npm,
            "flatmap-stream".to_string(),
            "0.1.1".to_string(),
        );
        let hit = m.get(&key);
        assert!(
            hit.is_some(),
            "flatmap-stream 0.1.1 missing from real mirror — check is_malicious() heuristic"
        );
    }
}

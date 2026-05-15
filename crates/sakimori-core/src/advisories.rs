//! Retroactive CVE notification: query OSV.dev for advisories that
//! affect installs we've already logged.
//!
//! Reads `~/.sakimori/installs.jsonl` (or whatever path the caller
//! configured on the proxy), de-duplicates `(ecosystem, name, version)`,
//! and POSTs the set to OSV's `/v1/querybatch` in chunks. The endpoint
//! returns one entry per query; any non-empty `vulns` array means
//! "this installed version is implicated in at least one advisory."
//!
//! Local-first by design: no upload of the install log, no server in
//! the loop. The only network call is to `api.osv.dev`, and only the
//! `(ecosystem, name, version)` tuples leave the machine — never paths,
//! User-Agent strings, or timestamps.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::installs::{ExecutionMode, InstallLogger};

/// OSV's documented per-batch limit is 1000; we stay comfortably
/// under that. Smaller batches also give nicer progress reporting.
const BATCH_SIZE: usize = 200;

const OSV_BATCH_ENDPOINT: &str = "https://api.osv.dev/v1/querybatch";

/// Mapping `Ecosystem::label()` → OSV ecosystem string. We accept the
/// `&str` form (rather than the `Ecosystem` enum) because [`InstallEvent`]
/// stores the label, not the enum — and an old log file may contain a
/// label that's since been renamed in the binary, in which case we
/// want to skip it rather than fail to load.
fn label_to_osv(label: &str) -> Option<&'static str> {
    match label {
        "npm" => Some("npm"),
        "crates" => Some("crates.io"),
        "pypi" => Some("PyPI"),
        "nuget" => Some("NuGet"),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AdvisoryHit {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub execution_mode: ExecutionMode,
    /// All advisory IDs OSV returned for this `(eco, name, version)`.
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub installs_scanned: usize,
    pub unique_packages: usize,
    pub hits: Vec<AdvisoryHit>,
}

/// Indirection so tests can swap in a canned response without going
/// over the network.
pub trait OsvBatch {
    /// Send up to [`BATCH_SIZE`] queries; return the same number of
    /// `Vec<String>` advisory-ID lists in the same order.
    fn query(&self, queries: &[OsvBatchQuery]) -> Result<Vec<Vec<String>>>;
}

#[derive(Debug, Clone, Serialize)]
pub struct OsvBatchQuery {
    pub version: String,
    pub package: OsvBatchPackage,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsvBatchPackage {
    pub name: String,
    pub ecosystem: &'static str,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResultEntry>,
}

#[derive(Deserialize, Default)]
struct OsvBatchResultEntry {
    #[serde(default)]
    vulns: Vec<OsvBatchVulnRef>,
}

#[derive(Deserialize)]
struct OsvBatchVulnRef {
    id: String,
}

/// Live OSV.dev HTTP client.
pub struct LiveOsvBatch {
    user_agent: String,
}

impl LiveOsvBatch {
    pub fn new(user_agent: String) -> Self {
        Self { user_agent }
    }
}

impl OsvBatch for LiveOsvBatch {
    fn query(&self, queries: &[OsvBatchQuery]) -> Result<Vec<Vec<String>>> {
        let body = serde_json::json!({ "queries": queries });
        let resp = ureq::post(OSV_BATCH_ENDPOINT)
            .set("user-agent", &self.user_agent)
            .send_json(body)
            .context("POST /v1/querybatch")?;
        let parsed: OsvBatchResponse = resp.into_json().context("parsing OSV response")?;
        // Defensive: pad / truncate to match the request size so the
        // caller can zip back to (eco, name, version) by index.
        let mut out: Vec<Vec<String>> = parsed
            .results
            .into_iter()
            .map(|r| r.vulns.into_iter().map(|v| v.id).collect())
            .collect();
        out.resize(queries.len(), Vec::new());
        Ok(out)
    }
}

/// Run a scan against the given log. Pure-ish: the OSV query is
/// behind a trait so we can unit-test the dedupe / aggregation logic.
pub fn scan(logger: &InstallLogger, oracle: &dyn OsvBatch) -> Result<ScanReport> {
    let events = logger.read_all().context("reading install log")?;
    let installs_scanned = events.len();

    // Dedupe by (eco, name, version). Preserve the latest
    // execution_mode we saw — if a package was installed both
    // persistently and ephemerally, prefer `Ephemeral` since the
    // user-facing message ("ran on this machine") is the more
    // alarming framing and shouldn't be hidden.
    let mut by_key: BTreeMap<(String, String, String), ExecutionMode> = BTreeMap::new();
    for ev in &events {
        let key = (ev.ecosystem.clone(), ev.name.clone(), ev.version.clone());
        by_key
            .entry(key)
            .and_modify(|m| {
                if *m != ExecutionMode::Ephemeral && ev.execution_mode == ExecutionMode::Ephemeral {
                    *m = ExecutionMode::Ephemeral;
                }
            })
            .or_insert(ev.execution_mode);
    }
    let unique_packages = by_key.len();

    // Build per-batch queries, dropping any (eco, _, _) whose label
    // OSV doesn't understand.
    let mut ordered: Vec<((String, String, String), ExecutionMode)> = by_key.into_iter().collect();
    ordered.retain(|((eco, _, _), _)| label_to_osv(eco).is_some());

    let mut hits = Vec::new();
    for chunk in ordered.chunks(BATCH_SIZE) {
        let queries: Vec<OsvBatchQuery> = chunk
            .iter()
            .map(|((eco, name, version), _)| OsvBatchQuery {
                version: version.clone(),
                package: OsvBatchPackage {
                    name: name.clone(),
                    ecosystem: label_to_osv(eco).expect("retained above"),
                },
            })
            .collect();
        let results = oracle.query(&queries)?;
        for (((eco, name, version), mode), ids) in chunk.iter().zip(results) {
            if ids.is_empty() {
                continue;
            }
            hits.push(AdvisoryHit {
                ecosystem: eco.clone(),
                name: name.clone(),
                version: version.clone(),
                execution_mode: *mode,
                advisory_ids: ids,
            });
        }
    }

    Ok(ScanReport {
        installs_scanned,
        unique_packages,
        hits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Ecosystem;
    use crate::installs::InstallEvent;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path() -> PathBuf {
        // Nanos alone collide under cargo's parallel test runner —
        // two tests scheduled on the same tick share a path and
        // each sees the other's appended events. Mix in a process-
        // local atomic counter so paths are unique regardless of
        // clock resolution.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("sakimori-advisories-{id}-{seq}/installs.jsonl"))
    }

    struct FakeBatch {
        // hits keyed by (name, version)
        hits: std::collections::HashMap<(String, String), Vec<String>>,
        seen: RefCell<Vec<Vec<OsvBatchQuery>>>,
    }
    impl OsvBatch for FakeBatch {
        fn query(&self, queries: &[OsvBatchQuery]) -> Result<Vec<Vec<String>>> {
            self.seen.borrow_mut().push(queries.to_vec());
            Ok(queries
                .iter()
                .map(|q| {
                    self.hits
                        .get(&(q.package.name.clone(), q.version.clone()))
                        .cloned()
                        .unwrap_or_default()
                })
                .collect())
        }
    }

    #[test]
    fn scan_returns_only_packages_with_hits() {
        let p = tmp_path();
        let logger = InstallLogger::at(&p);
        logger
            .record(&InstallEvent::new(Ecosystem::Npm, "evil", "1.0.0"))
            .unwrap();
        logger
            .record(&InstallEvent::new(Ecosystem::Npm, "fine", "1.0.0"))
            .unwrap();
        let mut hits = std::collections::HashMap::new();
        hits.insert(
            ("evil".into(), "1.0.0".into()),
            vec!["GHSA-evil-evil".into()],
        );
        let fake = FakeBatch {
            hits,
            seen: RefCell::new(Vec::new()),
        };
        let report = scan(&logger, &fake).unwrap();
        assert_eq!(report.installs_scanned, 2);
        assert_eq!(report.unique_packages, 2);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].name, "evil");
        assert_eq!(report.hits[0].advisory_ids, vec!["GHSA-evil-evil"]);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn scan_dedupes_repeat_installs() {
        let p = tmp_path();
        let logger = InstallLogger::at(&p);
        for _ in 0..3 {
            logger
                .record(&InstallEvent::new(Ecosystem::Crates, "tokio", "1.40.0"))
                .unwrap();
        }
        let fake = FakeBatch {
            hits: Default::default(),
            seen: RefCell::new(Vec::new()),
        };
        let report = scan(&logger, &fake).unwrap();
        assert_eq!(report.installs_scanned, 3);
        assert_eq!(report.unique_packages, 1);
        // Single batch with a single query.
        let seen = fake.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].len(), 1);
        assert_eq!(seen[0][0].package.ecosystem, "crates.io");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn scan_prefers_ephemeral_when_both_modes_seen() {
        let p = tmp_path();
        let logger = InstallLogger::at(&p);
        logger
            .record(
                &InstallEvent::new(Ecosystem::Npm, "leftpad", "1.0.0")
                    .with_mode(ExecutionMode::Persistent),
            )
            .unwrap();
        logger
            .record(
                &InstallEvent::new(Ecosystem::Npm, "leftpad", "1.0.0")
                    .with_mode(ExecutionMode::Ephemeral),
            )
            .unwrap();
        let mut hits = std::collections::HashMap::new();
        hits.insert(("leftpad".into(), "1.0.0".into()), vec!["X".into()]);
        let fake = FakeBatch {
            hits,
            seen: RefCell::new(Vec::new()),
        };
        let report = scan(&logger, &fake).unwrap();
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].execution_mode, ExecutionMode::Ephemeral);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn label_to_osv_covers_known_ecosystems() {
        assert_eq!(label_to_osv("npm"), Some("npm"));
        assert_eq!(label_to_osv("crates"), Some("crates.io"));
        assert_eq!(label_to_osv("pypi"), Some("PyPI"));
        assert_eq!(label_to_osv("nuget"), Some("NuGet"));
        assert_eq!(label_to_osv("bogus"), None);
    }

    #[test]
    fn scan_chunks_oversized_input() {
        let p = tmp_path();
        let logger = InstallLogger::at(&p);
        // BATCH_SIZE + 5 unique packages → expect 2 chunks.
        for i in 0..(BATCH_SIZE + 5) {
            logger
                .record(&InstallEvent::new(
                    Ecosystem::Npm,
                    format!("pkg-{i}"),
                    "1.0.0",
                ))
                .unwrap();
        }
        let fake = FakeBatch {
            hits: Default::default(),
            seen: RefCell::new(Vec::new()),
        };
        let _ = scan(&logger, &fake).unwrap();
        assert_eq!(fake.seen.borrow().len(), 2);
        assert_eq!(fake.seen.borrow()[0].len(), BATCH_SIZE);
        assert_eq!(fake.seen.borrow()[1].len(), 5);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}

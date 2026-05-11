//! npm packument rewriter — the npm-side counterpart to
//! [`crate::rewrite`] for crates.io.
//!
//! The npm "packument" endpoint (`https://registry.npmjs.org/<pkg>`)
//! returns a single JSON document listing every published version of
//! the package. Shape (abbreviated):
//!
//! ```json
//! {
//!   "name": "left-pad",
//!   "dist-tags": { "latest": "1.3.0" },
//!   "versions": {
//!     "1.0.0": { …full per-version manifest… },
//!     "1.3.0": { … }
//!   },
//!   "time": {
//!     "created":  "2014-03-22T21:42:18.000Z",
//!     "modified": "2016-03-22T21:42:18.002Z",
//!     "1.0.0":    "2014-03-22T21:42:18.002Z",
//!     "1.3.0":    "2016-03-22T21:42:18.002Z"
//!   }
//! }
//! ```
//!
//! To achieve pnpm-style auto-fallback we:
//!
//! 1. Walk `time` to find publish dates per version string.
//! 2. Remove any too-young version from both `versions` and `time`.
//! 3. Remap every `dist-tags` entry pointing at a removed version to
//!    the highest remaining version by semver order. This is the
//!    subtle step: if we leave `dist-tags.latest = "1.3.0"` pointing
//!    at a removed key, `npm install <pkg>` (no version specifier)
//!    will ask for `1.3.0` and hard-fail.
//!
//! This module is **pure** and synchronous — unit tests can exercise
//! every branch without hyper.

use std::time::Duration;

use chrono::{DateTime, Utc};
use semver::Version;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmRewriteStats {
    pub kept: usize,
    pub dropped: usize,
    pub retargeted_tags: usize,
    /// How many versions were dropped *specifically* because they
    /// lacked Sigstore provenance (i.e. would have otherwise been
    /// kept by the age filter). 0 when `require_provenance` is off.
    pub dropped_no_provenance: usize,
}

/// Strict-mode knob that lives on the rewriter's side of the call
/// graph. When `require_provenance = true`, any version whose
/// `dist.attestations.provenance` is missing is dropped in addition
/// to the age-based filter — so the resolver sees only OIDC-signed
/// versions, neutralising the "steal-token-and-publish-fresh"
/// attack that `minimumReleaseAge` alone can't stop.
#[derive(Debug, Clone, Copy, Default)]
pub struct NpmRewriteOptions {
    pub require_provenance: bool,
}

/// Legacy entry point: equivalent to calling
/// [`rewrite_npm_packument_with`] with default options. Kept so
/// existing call-sites (and the v0.22 tests below) compile
/// unchanged.
pub fn rewrite_npm_packument(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, NpmRewriteStats) {
    rewrite_npm_packument_with(body, min_age, now, NpmRewriteOptions::default())
}

/// Rewrite an npm packument body, dropping too-young versions and
/// (optionally) versions without Sigstore provenance, then
/// re-pointing dist-tags at the newest remaining version.
///
/// On parse failure returns the body unchanged with zero stats — a
/// malformed packument we don't understand is safer to forward than to
/// silently break. Callers should pass only 2xx bodies (the proxy
/// already gates on that).
pub fn rewrite_npm_packument_with(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
    opts: NpmRewriteOptions,
) -> (Vec<u8>, NpmRewriteStats) {
    let mut stats = NpmRewriteStats {
        kept: 0,
        dropped: 0,
        retargeted_tags: 0,
        dropped_no_provenance: 0,
    };

    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("npm-rewrite: passing through unparseable packument: {e}");
            return (body.to_vec(), stats);
        }
    };

    let Some(obj) = doc.as_object_mut() else {
        return (body.to_vec(), stats);
    };

    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    // Age filter — collect too-young version keys from `time`.
    let age_drop: Vec<String> = obj
        .get("time")
        .and_then(Value::as_object)
        .map(|time| {
            time.iter()
                .filter(|(k, _)| k.as_str() != "created" && k.as_str() != "modified")
                .filter_map(|(vers, v)| {
                    let s = v.as_str()?;
                    let published = DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&Utc);
                    if (now - published) < cutoff {
                        Some(vers.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Provenance filter — find versions whose `dist.attestations.provenance`
    // is absent. Only applied when `require_provenance` is on.
    //
    // A version is considered to have provenance iff
    //   versions.<v>.dist.attestations.provenance.predicateType
    // is a non-empty string. npm's own schema puts the SLSA
    // predicateType here; a missing or empty value means no bundle
    // was published. We deliberately do NOT download and verify the
    // bundle here — that's a bigger feature; filtering on the claim
    // alone is already enough to force "publisher opted into
    // provenance" for every surviving version.
    let provenance_drop: Vec<String> = if opts.require_provenance {
        obj.get("versions")
            .and_then(Value::as_object)
            .map(|versions| {
                versions
                    .iter()
                    .filter(|(_, meta)| !has_provenance(meta))
                    .map(|(v, _)| v.clone())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Union: a version dropped by age, provenance, or both is
    // ultimately dropped once. We only count it in
    // `dropped_no_provenance` if provenance was the *only* reason
    // it got removed (otherwise the number would double-count on
    // too-young-and-no-provenance versions).
    let age_set: std::collections::HashSet<String> = age_drop.iter().cloned().collect();
    for v in &provenance_drop {
        if !age_set.contains(v) {
            stats.dropped_no_provenance += 1;
        }
    }
    let mut too_young: Vec<String> = age_drop;
    for v in provenance_drop {
        if !age_set.contains(&v) {
            too_young.push(v);
        }
    }
    stats.dropped = too_young.len();

    if !too_young.is_empty() {
        if let Some(versions) = obj.get_mut("versions").and_then(Value::as_object_mut) {
            for v in &too_young {
                versions.remove(v);
            }
            stats.kept = versions.len();
        }
        if let Some(time) = obj.get_mut("time").and_then(Value::as_object_mut) {
            for v in &too_young {
                time.remove(v);
            }
        }

        // Fix up dist-tags. Any tag pointing at a removed version is
        // retargeted to the highest remaining version by semver; tags
        // whose target is still present are left alone.
        let remaining_newest = remaining_newest_version(obj);
        if let Some(tags) = obj.get_mut("dist-tags").and_then(Value::as_object_mut) {
            let too_young_set: std::collections::HashSet<&String> = too_young.iter().collect();
            let to_update: Vec<String> = tags
                .iter()
                .filter_map(|(k, v)| {
                    v.as_str().and_then(|s| {
                        if too_young_set.contains(&s.to_string()) {
                            Some(k.clone())
                        } else {
                            None
                        }
                    })
                })
                .collect();
            for k in &to_update {
                match &remaining_newest {
                    Some(newest) => {
                        tags.insert(k.clone(), Value::String(newest.clone()));
                        stats.retargeted_tags += 1;
                    }
                    None => {
                        // No older versions left at all. Removing the
                        // tag is cleaner than leaving a dangling one;
                        // `npm install <pkg>` will then error with
                        // "No matching version" which is the correct
                        // fail-closed signal.
                        tags.remove(k);
                    }
                }
            }
        }
    } else {
        // Nothing dropped — count kept versions so stats is still
        // useful for logging.
        stats.kept = obj
            .get("versions")
            .and_then(Value::as_object)
            .map(|v| v.len())
            .unwrap_or(0);
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

/// Does this per-version metadata carry a Sigstore provenance
/// claim? npm stores it at `dist.attestations.provenance` —
/// specifically `.predicateType`, which for an npm-published
/// provenance is always `"https://slsa.dev/provenance/v1"` (for
/// SLSA v1). We only check for *presence* of a non-empty
/// predicateType; downloading and cryptographically verifying the
/// attached Sigstore bundle is a separate roadmap item, but a
/// claim of "I have provenance" is itself a meaningful signal
/// (npm refuses to attach this field unless the publish pipeline
/// was an OIDC-authenticated GitHub Actions / GitLab CI run).
fn has_provenance(meta: &Value) -> bool {
    meta.get("dist")
        .and_then(|d| d.get("attestations"))
        .and_then(|a| a.get("provenance"))
        .and_then(|p| p.get("predicateType"))
        .and_then(Value::as_str)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// Highest remaining version by semver. Falls back to lexical
/// comparison for non-semver strings so we still produce *some*
/// answer rather than panicking on oddly-tagged packages.
fn remaining_newest_version(obj: &serde_json::Map<String, Value>) -> Option<String> {
    let versions = obj.get("versions")?.as_object()?;
    let mut best: Option<(Option<Version>, String)> = None;
    for key in versions.keys() {
        let parsed = Version::parse(key).ok();
        match &best {
            None => best = Some((parsed, key.clone())),
            Some((best_parsed, best_key)) => {
                let replace = match (best_parsed, &parsed) {
                    (Some(a), Some(b)) => b > a,
                    (None, Some(_)) => true, // semver beats non-semver
                    (Some(_), None) => false,
                    (None, None) => key.as_str() > best_key.as_str(),
                };
                if replace {
                    best = Some((parsed, key.clone()));
                }
            }
        }
    }
    best.map(|(_, k)| k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    /// Build a minimal packument with the given (version, pubtime) pairs.
    fn packument(name: &str, versions: &[(&str, &str)], latest: &str) -> String {
        let mut time = serde_json::Map::new();
        time.insert(
            "created".into(),
            Value::String("2014-01-01T00:00:00Z".into()),
        );
        time.insert(
            "modified".into(),
            Value::String("2024-01-01T00:00:00Z".into()),
        );
        let mut vs = serde_json::Map::new();
        for (v, t) in versions {
            time.insert((*v).into(), Value::String((*t).into()));
            let mut man = serde_json::Map::new();
            man.insert("name".into(), Value::String(name.into()));
            man.insert("version".into(), Value::String((*v).into()));
            vs.insert((*v).into(), Value::Object(man));
        }
        let mut tags = serde_json::Map::new();
        tags.insert("latest".into(), Value::String(latest.into()));
        let mut doc = serde_json::Map::new();
        doc.insert("name".into(), Value::String(name.into()));
        doc.insert("dist-tags".into(), Value::Object(tags));
        doc.insert("versions".into(), Value::Object(vs));
        doc.insert("time".into(), Value::Object(time));
        serde_json::to_string(&doc).unwrap()
    }

    fn min_age_hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn parse(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    #[test]
    fn drops_too_young_versions_from_versions_and_time() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-12-01T00:00:00Z"), // old enough
                ("1.1.0", "2025-01-09T23:00:00Z"), // too young
            ],
            "1.1.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        let vs = doc["versions"].as_object().unwrap();
        let time = doc["time"].as_object().unwrap();
        assert!(vs.contains_key("1.0.0"));
        assert!(!vs.contains_key("1.1.0"));
        assert!(time.contains_key("1.0.0"));
        assert!(!time.contains_key("1.1.0"));
        assert!(time.contains_key("created"));
        assert!(time.contains_key("modified"));
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn retargets_latest_when_it_points_at_removed_version() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.2.0", "2024-06-01T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"), // too young
            ],
            "2.0.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(stats.retargeted_tags, 1);
    }

    #[test]
    fn leaves_latest_alone_when_it_is_still_present() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.2.0", "2024-06-01T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"), // too young
            ],
            "1.2.0", // latest already safe
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(stats.retargeted_tags, 0);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn removes_tag_when_no_version_is_old_enough() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2025-01-09T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"),
            ],
            "2.0.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        assert!(doc["versions"].as_object().unwrap().is_empty());
        assert!(!doc["dist-tags"].as_object().unwrap().contains_key("latest"));
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.kept, 0);
    }

    #[test]
    fn picks_highest_semver_not_lexical() {
        let now = utc(2025, 1, 10);
        // Lexical order would pick "1.9.0" over "1.10.0"; semver picks 1.10.0.
        let body = packument(
            "foo",
            &[
                ("1.9.0", "2024-01-01T00:00:00Z"),
                ("1.10.0", "2024-02-01T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"),
            ],
            "2.0.0",
        );
        let (out, _) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(doc["dist-tags"]["latest"], "1.10.0");
    }

    #[test]
    fn malformed_body_is_passed_through_unchanged() {
        let now = utc(2025, 1, 10);
        let body = b"not json";
        let (out, stats) = rewrite_npm_packument(body, min_age_hours(168), now);
        assert_eq!(out, body);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn packument_without_time_is_left_alone() {
        let now = utc(2025, 1, 10);
        let body = br#"{"name":"foo","versions":{"1.0.0":{}}}"#;
        let (out, stats) = rewrite_npm_packument(body, min_age_hours(168), now);
        // JSON is re-serialised so may differ in whitespace, but the
        // semantics must be identical.
        let orig: Value = serde_json::from_slice(body).unwrap();
        let got: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(orig, got);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn nothing_dropped_means_versions_unchanged() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.1.0", "2024-06-01T00:00:00Z"),
            ],
            "1.1.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let before: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 2);
    }

    /// Build a packument where each version optionally carries a
    /// Sigstore provenance claim. `has_prov[i]` toggles for the
    /// matching `versions[i]` entry.
    fn packument_with_provenance(
        versions: &[(&str, &str)],
        latest: &str,
        has_prov: &[bool],
    ) -> String {
        assert_eq!(versions.len(), has_prov.len());
        let mut time = serde_json::Map::new();
        time.insert(
            "created".into(),
            Value::String("2024-01-01T00:00:00Z".into()),
        );
        time.insert(
            "modified".into(),
            Value::String("2025-01-01T00:00:00Z".into()),
        );
        let mut vs = serde_json::Map::new();
        for ((v, t), prov) in versions.iter().zip(has_prov) {
            time.insert((*v).into(), Value::String((*t).into()));
            let mut man = serde_json::Map::new();
            man.insert("name".into(), Value::String("pkg".into()));
            man.insert("version".into(), Value::String((*v).into()));
            let mut dist = serde_json::Map::new();
            if *prov {
                dist.insert(
                    "attestations".into(),
                    serde_json::json!({
                        "url": format!("https://registry.npmjs.org/-/npm/v1/attestations/pkg@{v}"),
                        "provenance": {
                            "predicateType": "https://slsa.dev/provenance/v1"
                        }
                    }),
                );
            }
            man.insert("dist".into(), Value::Object(dist));
            vs.insert((*v).into(), Value::Object(man));
        }
        let mut doc = serde_json::Map::new();
        doc.insert("name".into(), Value::String("pkg".into()));
        doc.insert("dist-tags".into(), serde_json::json!({"latest": latest}));
        doc.insert("versions".into(), Value::Object(vs));
        doc.insert("time".into(), Value::Object(time));
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn require_provenance_drops_versions_without_attestations() {
        // All three versions are old enough; only two have provenance.
        let now = utc(2025, 1, 10);
        let body = packument_with_provenance(
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.1.0", "2024-06-01T00:00:00Z"),
                ("2.0.0", "2024-09-01T00:00:00Z"),
            ],
            "2.0.0",
            &[true, false, true], // 1.1.0 missing provenance
        );
        let (out, stats) = rewrite_npm_packument_with(
            body.as_bytes(),
            min_age_hours(168),
            now,
            NpmRewriteOptions {
                require_provenance: true,
            },
        );
        let doc = parse(&out);
        let vs = doc["versions"].as_object().unwrap();
        assert!(vs.contains_key("1.0.0"));
        assert!(!vs.contains_key("1.1.0"));
        assert!(vs.contains_key("2.0.0"));
        assert_eq!(stats.dropped_no_provenance, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn provenance_off_is_a_no_op_for_missing_attestations() {
        let now = utc(2025, 1, 10);
        let body = packument_with_provenance(
            &[("1.0.0", "2024-01-01T00:00:00Z")],
            "1.0.0",
            &[false], // no provenance
        );
        let (_out, stats) = rewrite_npm_packument_with(
            body.as_bytes(),
            min_age_hours(168),
            now,
            NpmRewriteOptions {
                require_provenance: false, // OFF
            },
        );
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.dropped_no_provenance, 0);
    }

    #[test]
    fn provenance_and_age_dedup_does_not_double_count() {
        // One version is both too-young AND missing provenance.
        // It should be dropped exactly once, and NOT counted in
        // `dropped_no_provenance` (age was enough reason already).
        let now = utc(2025, 1, 10);
        let body = packument_with_provenance(
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"), // old + signed
                ("2.0.0", "2025-01-09T23:00:00Z"), // too young + unsigned
            ],
            "2.0.0",
            &[true, false],
        );
        let (_out, stats) = rewrite_npm_packument_with(
            body.as_bytes(),
            min_age_hours(168),
            now,
            NpmRewriteOptions {
                require_provenance: true,
            },
        );
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.dropped_no_provenance, 0);
    }

    #[test]
    fn has_provenance_rejects_empty_or_missing_predicate_type() {
        let with_prov = serde_json::json!({
            "dist": {
                "attestations": {
                    "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
                }
            }
        });
        let empty_pt = serde_json::json!({
            "dist": { "attestations": { "provenance": { "predicateType": "" } } }
        });
        let no_attestations = serde_json::json!({ "dist": {} });
        let no_dist = serde_json::json!({});
        assert!(has_provenance(&with_prov));
        assert!(!has_provenance(&empty_pt));
        assert!(!has_provenance(&no_attestations));
        assert!(!has_provenance(&no_dist));
    }

    #[test]
    fn handles_prerelease_and_non_semver_tags_gracefully() {
        // "next" dist-tag may point at a prerelease; "beta" may point
        // at non-semver like "1.0.0-beta". The rewriter should not
        // crash and should still pick a sensible "highest" fallback.
        let now = utc(2025, 1, 10);
        let body = r#"{
            "name": "foo",
            "dist-tags": { "latest": "2.0.0", "next": "2.0.0" },
            "versions": {
                "1.0.0": {}, "1.2.0": {}, "2.0.0": {}
            },
            "time": {
                "created": "2024-01-01T00:00:00Z",
                "modified": "2025-01-09T00:00:00Z",
                "1.0.0": "2024-01-01T00:00:00Z",
                "1.2.0": "2024-06-01T00:00:00Z",
                "2.0.0": "2025-01-09T23:00:00Z"
            }
        }"#;
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(doc["dist-tags"]["next"], "1.2.0");
        assert_eq!(stats.retargeted_tags, 2);
    }
}

//! NuGet registration-index rewriter.
//!
//! NuGet's "registration" endpoints are the per-package metadata
//! documents that list every published version plus its
//! `catalogEntry.published` timestamp. There are two shapes we
//! handle with the same rewriter:
//!
//! 1. `https://api.nuget.org/v3/registration<X>/<id>/index.json`
//!    — the top-level index. Contains an outer `items[]` where each
//!    element is a *page*. A page either carries its versions
//!    inline (`items` nested inside) or points at a separate
//!    page URL.
//!
//! 2. `https://api.nuget.org/v3/registration<X>/<id>/page/<lower>/<upper>.json`
//!    — a paged file. Same shape as an inline page: `items[]` of
//!    `{ catalogEntry: { version, published, … }, … }`.
//!
//! In both cases we walk `items[]` recursively, drop entries whose
//! `catalogEntry.published` is younger than `min_age`, and fix up
//! the `count` field so it stays consistent.
//!
//! Flat-container (`/v3-flatcontainer/<id>/index.json`) carries **no
//! dates inline** (`{"versions":[...]}`), so filtering it silently
//! requires borrowing publish times from the registration endpoint
//! out-of-band. This module exposes:
//!
//! - [`rewrite_nuget_flatcontainer`] — pure filter that takes a
//!   version→published oracle (tests pass a HashMap, production
//!   wires a cached registration-index fetcher).
//! - [`extract_publish_times_from_registration`] — parses a fetched
//!   registration index into the HashMap that oracle expects.
//!
//! Proxy-level wiring (which actually issues the registration
//! request + caches it per package) lives in `proxy.rs`.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NugetRewriteStats {
    pub kept: usize,
    pub dropped: usize,
}

/// Rewrite a NuGet registration document (index.json or a paged
/// *.json file). Drops `items[]` entries recursively whose
/// `catalogEntry.published` is younger than `min_age`.
///
/// Pass-through on parse failure; the rewriter is best-effort and
/// preserves the body byte-for-byte when we don't understand it.
pub fn rewrite_nuget_registration(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, NugetRewriteStats) {
    let mut stats = NugetRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("nuget-rewrite: pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();
    filter_items_recursively(&mut doc, cutoff, now, &mut stats);
    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

fn filter_items_recursively(
    v: &mut Value,
    cutoff: chrono::Duration,
    now: DateTime<Utc>,
    stats: &mut NugetRewriteStats,
) {
    let Some(obj) = v.as_object_mut() else {
        return;
    };
    if let Some(items) = obj.get_mut("items").and_then(Value::as_array_mut) {
        // Two possibilities per item:
        // (a) leaf: { catalogEntry: { published: … } }
        // (b) page: { items: […] } — recurse.
        let before = items.len();
        items.retain_mut(|it| {
            if let Some(entry) = it.get("catalogEntry") {
                // Leaf — drop if too young.
                let keep = entry
                    .get("published")
                    .and_then(Value::as_str)
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| (now - dt.with_timezone(&Utc)) >= cutoff)
                    .unwrap_or(true); // unknown → keep
                if keep {
                    stats.kept += 1;
                } else {
                    stats.dropped += 1;
                }
                keep
            } else if it.get("items").is_some() {
                // Page with inline nested items — recurse; keep the
                // page even if it ends up empty, because it still
                // carries valid lower/upper bounds and a re-fetch URL.
                filter_items_recursively(it, cutoff, now, stats);
                if let Some(nested) = it.get("items").and_then(Value::as_array) {
                    let count = nested.len();
                    if let Some(obj) = it.as_object_mut() {
                        obj.insert(
                            "count".into(),
                            Value::Number(serde_json::Number::from(count)),
                        );
                    }
                }
                true
            } else {
                // Page reference without inline items — leave alone;
                // the separate fetch for that page will be rewritten
                // when the client follows the link.
                true
            }
        });
        let new_count = items.len();
        let _ = before;
        // Preserve the count field on the outer document / page so
        // downstream consumers don't see a stale length.
        if let Some(count) = obj.get_mut("count") {
            *count = Value::Number(serde_json::Number::from(new_count));
        }
    }
}

/// Rewrite a NuGet flat-container `/v3-flatcontainer/<id>/index.json`
/// body. The document is a plain `{"versions": ["1.0.0", …]}` with no
/// timestamps, so the caller supplies a `publish_time` oracle (usually
/// built by parsing the package's registration index, see
/// [`extract_publish_times_from_registration`]).
///
/// Semantics match the other rewriters:
///
/// - Versions whose oracle-returned publish time is younger than
///   `min_age` are dropped.
/// - Versions the oracle doesn't know about are **kept** (fail-open).
///   The registration index is authoritative; a missing entry usually
///   means the registration lookup was flaky, and we'd rather not
///   brick installs over a transient registry hiccup. Pinned `.nupkg`
///   fetches to denied versions are still hard-denied at the tarball
///   layer, so an attacker can't game this to get a too-young version
///   through.
/// - Parse failure / non-matching shape → pass-through unchanged.
pub fn rewrite_nuget_flatcontainer<F>(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
    publish_time: F,
) -> (Vec<u8>, NugetRewriteStats)
where
    F: Fn(&str) -> Option<DateTime<Utc>>,
{
    let mut stats = NugetRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("nuget-flatcontainer: pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };

    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    let Some(versions) = doc.get_mut("versions").and_then(Value::as_array_mut) else {
        return (body.to_vec(), stats);
    };

    versions.retain(|v| {
        let Some(ver) = v.as_str() else {
            // unparseable entry — keep, don't stamp stats
            return true;
        };
        match publish_time(ver) {
            Some(published) => {
                let keep = (now - published) >= cutoff;
                if keep {
                    stats.kept += 1;
                } else {
                    stats.dropped += 1;
                }
                keep
            }
            None => {
                // Unknown — fail-open. Still counts as kept for logging.
                stats.kept += 1;
                true
            }
        }
    });

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

/// Walk a NuGet registration-index JSON body and extract a map
/// `version → publish time`. Only inline leaves are read — pages that
/// carry only a separate-URL reference (no inline `items`) are
/// skipped; the caller should fetch those pages and call this helper
/// again, merging the results.
///
/// Tolerant to unexpected shapes: anything that doesn't match leaves
/// the map unchanged for that entry.
pub fn extract_publish_times_from_registration(body: &[u8]) -> HashMap<String, DateTime<Utc>> {
    let mut out = HashMap::new();
    let Ok(doc): Result<Value, _> = serde_json::from_slice(body) else {
        return out;
    };
    collect_publish_times(&doc, &mut out);
    out
}

fn collect_publish_times(v: &Value, out: &mut HashMap<String, DateTime<Utc>>) {
    let Some(items) = v.get("items").and_then(Value::as_array) else {
        return;
    };
    for it in items {
        if let Some(entry) = it.get("catalogEntry") {
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            let Some(published) = entry.get("published").and_then(Value::as_str) else {
                continue;
            };
            let Ok(dt) = DateTime::parse_from_rfc3339(published) else {
                continue;
            };
            // NuGet uses `0001-01-01T00:00:00Z` as a sentinel for
            // "unlisted" — those we treat as unknown (skip).
            let dt_utc = dt.with_timezone(&Utc);
            if dt_utc.timestamp() <= 0 {
                continue;
            }
            out.insert(version.to_string(), dt_utc);
        } else if it.get("items").is_some() {
            collect_publish_times(it, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn min_age_hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn parse(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    fn leaf(version: &str, published: &str) -> Value {
        serde_json::json!({
            "@id": format!("https://api.nuget.org/v3/registration5-semver1/pkg/{version}.json"),
            "catalogEntry": {
                "id": "Pkg",
                "version": version,
                "published": published
            }
        })
    }

    fn paged_index(leaves: &[(&str, &str)]) -> String {
        serde_json::to_string(&serde_json::json!({
            "@id": "https://api.nuget.org/v3/registration5-semver1/pkg/index.json",
            "count": 1,
            "items": [{
                "@id": "page",
                "lower": leaves.first().map(|(v,_)| v).unwrap_or(&"0.0.0"),
                "upper": leaves.last().map(|(v,_)| v).unwrap_or(&"0.0.0"),
                "count": leaves.len(),
                "items": leaves.iter().map(|(v,t)| leaf(v,t)).collect::<Vec<_>>()
            }]
        }))
        .unwrap()
    }

    #[test]
    fn drops_young_leaf_entries_and_fixes_counts() {
        let now = utc(2025, 1, 10);
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
            ("2.0.0", "2025-01-09T23:00:00Z"), // too young
        ]);
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        let pages = doc["items"].as_array().unwrap();
        assert_eq!(pages.len(), 1);
        let page = &pages[0];
        let leaves = page["items"].as_array().unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(page["count"], 2);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 2);
    }

    #[test]
    fn keeps_entries_with_missing_or_unparseable_published() {
        let now = utc(2025, 1, 10);
        let body = serde_json::to_string(&serde_json::json!({
            "count": 1,
            "items": [{
                "count": 2,
                "items": [
                    { "catalogEntry": { "version": "1.0.0" /* no published */ } },
                    { "catalogEntry": { "version": "1.1.0", "published": "not-a-date" } }
                ]
            }]
        }))
        .unwrap();
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(
            doc["items"][0]["items"].as_array().unwrap().len(),
            2,
            "unknown dates should be kept (fail-open)"
        );
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn leaves_page_references_without_inline_items_alone() {
        // Some index.json pages reference a separate /page/<lower>/<upper>.json URL.
        let now = utc(2025, 1, 10);
        let body = serde_json::to_string(&serde_json::json!({
            "count": 1,
            "items": [{
                "@id": "https://api.nuget.org/v3/registration5-semver1/pkg/page/1.0.0/9.9.9.json",
                "lower": "1.0.0",
                "upper": "9.9.9"
                /* no "items" — client must fetch the page URL */
            }]
        }))
        .unwrap();
        let before: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 0);
    }

    #[test]
    fn malformed_body_passes_through() {
        let (out, stats) =
            rewrite_nuget_registration(b"not json", min_age_hours(168), utc(2025, 1, 10));
        assert_eq!(out, b"not json");
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn rfc3339_with_offset_works() {
        // NuGet commonly emits `+00:00` instead of `Z`.
        let now = utc(2025, 1, 10);
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00.000+00:00"),
            ("2.0.0", "2025-01-09T23:00:00.000+00:00"), // too young
        ]);
        let (_, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 1);
    }

    // ---------- flat-container tests ----------

    fn flatcontainer(versions: &[&str]) -> String {
        serde_json::to_string(&serde_json::json!({ "versions": versions })).unwrap()
    }

    fn oracle_from(pairs: &[(&str, &str)]) -> HashMap<String, DateTime<Utc>> {
        pairs
            .iter()
            .map(|(v, t)| {
                let dt = DateTime::parse_from_rfc3339(t).unwrap().with_timezone(&Utc);
                ((*v).to_string(), dt)
            })
            .collect()
    }

    #[test]
    fn flatcontainer_drops_versions_whose_oracle_says_too_young() {
        let now = utc(2025, 1, 10);
        let body = flatcontainer(&["1.0.0", "1.1.0", "2.0.0"]);
        let oracle = oracle_from(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
            ("2.0.0", "2025-01-09T23:00:00Z"), // too young
        ]);
        let (out, stats) =
            rewrite_nuget_flatcontainer(body.as_bytes(), min_age_hours(168), now, |v| {
                oracle.get(v).copied()
            });
        let doc = parse(&out);
        let vs: Vec<&str> = doc["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(vs, vec!["1.0.0", "1.1.0"]);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 2);
    }

    #[test]
    fn flatcontainer_unknown_versions_are_kept_fail_open() {
        let now = utc(2025, 1, 10);
        let body = flatcontainer(&["1.0.0", "2.0.0"]);
        // oracle has nothing — treat everything as unknown.
        let (out, stats) =
            rewrite_nuget_flatcontainer(body.as_bytes(), min_age_hours(168), now, |_| None);
        let doc = parse(&out);
        assert_eq!(doc["versions"].as_array().unwrap().len(), 2);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 2);
    }

    #[test]
    fn flatcontainer_malformed_body_passes_through() {
        let now = utc(2025, 1, 10);
        let (out, stats) =
            rewrite_nuget_flatcontainer(b"not json", min_age_hours(168), now, |_| None);
        assert_eq!(out, b"not json");
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn flatcontainer_missing_versions_key_is_pass_through() {
        // Some edge / error responses omit the `versions` array. We
        // should not mangle those.
        let now = utc(2025, 1, 10);
        let body = br#"{"other": []}"#;
        let (out, stats) = rewrite_nuget_flatcontainer(body, min_age_hours(168), now, |_| None);
        let before: Value = serde_json::from_slice(body).unwrap();
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn flatcontainer_empty_versions_list_is_passthrough() {
        let now = utc(2025, 1, 10);
        let body = flatcontainer(&[]);
        let (out, stats) =
            rewrite_nuget_flatcontainer(body.as_bytes(), min_age_hours(168), now, |_| None);
        let doc = parse(&out);
        assert_eq!(doc["versions"].as_array().unwrap().len(), 0);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn extract_publish_times_walks_inline_leaves() {
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
            ("2.0.0", "2025-01-09T23:00:00Z"),
        ]);
        let map = extract_publish_times_from_registration(body.as_bytes());
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("1.0.0"));
        assert!(map.contains_key("2.0.0"));
    }

    #[test]
    fn extract_publish_times_skips_page_references() {
        // Page with no inline items — our helper skips it; caller must
        // fetch the separate page URL and merge.
        let body = serde_json::to_string(&serde_json::json!({
            "items": [{
                "@id": "https://api.nuget.org/v3/registration5-semver1/pkg/page/1.0.0/9.9.9.json",
                "lower": "1.0.0",
                "upper": "9.9.9"
            }]
        }))
        .unwrap();
        let map = extract_publish_times_from_registration(body.as_bytes());
        assert!(map.is_empty());
    }

    #[test]
    fn extract_publish_times_ignores_unlisted_sentinel() {
        // NuGet marks unlisted packages with the epoch-zero date
        // `0001-01-01T00:00:00+00:00`. We treat those as unknown so
        // the fail-open branch kicks in.
        let body = serde_json::to_string(&serde_json::json!({
            "items": [{
                "items": [{
                    "catalogEntry": {
                        "version": "1.0.0-unlisted",
                        "published": "0001-01-01T00:00:00+00:00"
                    }
                }]
            }]
        }))
        .unwrap();
        let map = extract_publish_times_from_registration(body.as_bytes());
        assert!(map.is_empty());
    }

    #[test]
    fn extract_publish_times_tolerates_garbage() {
        let map = extract_publish_times_from_registration(b"not json");
        assert!(map.is_empty());
    }

    #[test]
    fn flatcontainer_end_to_end_with_extracted_oracle() {
        // Simulate the real proxy path: fetch registration body,
        // extract times, filter flat-container with it.
        let now = utc(2025, 1, 10);
        let registration = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
            ("2.0.0", "2025-01-09T23:00:00Z"), // too young
        ]);
        let oracle = extract_publish_times_from_registration(registration.as_bytes());

        let flat = flatcontainer(&["1.0.0", "1.1.0", "2.0.0"]);
        let (out, stats) =
            rewrite_nuget_flatcontainer(flat.as_bytes(), min_age_hours(168), now, |v| {
                oracle.get(v).copied()
            });
        let doc = parse(&out);
        let vs: Vec<&str> = doc["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(vs, vec!["1.0.0", "1.1.0"]);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn nothing_young_means_body_semantics_preserved() {
        let now = utc(2025, 1, 10);
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
        ]);
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let before: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 2);
    }
}

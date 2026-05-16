//! OSV advisory ingest + JOIN against the install inventory.
//!
//! This is the hub-side counterpart to the proxy's
//! `sakimori_core::advisories` (which hits OSV.dev's live
//! `/v1/querybatch` for a single laptop). Here we **store**
//! advisories locally and JOIN them against the team-wide install
//! inventory so the dispatcher slice can fire push notifications
//! when a past install matches a newly-disclosed vulnerability.
//!
//! ## Matching modes
//!
//! Findings can come from two paths:
//!
//! 1. **Exact-version match** — `affected[].versions[]`. Every
//!    listed string is recorded verbatim and JOINed against
//!    `installs.version` literally. Cheap, no parser, no false
//!    positives.
//! 2. **SEMVER range match** — `affected[].ranges[]` entries of
//!    `type: SEMVER` (and `type: ECOSYSTEM` for the npm/crates
//!    ecosystems, which both use SemVer 2.0 semantics). Events
//!    `introduced` and `fixed` are extracted into half-open
//!    intervals `[introduced, fixed)`. An install is a match iff
//!    its parsed version sits inside any such interval. PyPI's
//!    PEP 440 and NuGet's variant of SemVer aren't standard
//!    SemVer 2.0; ranges for those ecosystems are intentionally
//!    skipped rather than mis-applied. (Their exact-version
//!    `affected[].versions[]` entries still match.)
//!
//! The current matching mode is surfaced as the constant
//! `crate::store::MATCHING_MODE`
//! (`"exact_versions_and_semver_ranges"`) so subscribers can
//! branch on what kind of "no match" they're looking at.
//!
//! ## Out of scope (next slice)
//!
//! - Automatic OSV mirror sync (download from
//!   `gs://osv-vulnerabilities`). For now, advisories enter via
//!   `POST /advisories`.
//! - Email / Slack adapters on top of the existing webhook
//!   substrate.
//! - PEP 440 / NuGet range semantics.
//! - KEV / known-exploited gating.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Coarse severity bucket. Driven by OSV's heterogenous severity
/// shape (GHSA convention vs. CVSS v3 vector vs. nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Moderate,
    Low,
    Unknown,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Moderate => "moderate",
            Severity::Low => "low",
            Severity::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "moderate" | "medium" => Some(Severity::Moderate),
            "low" => Some(Severity::Low),
            "unknown" | "" => Some(Severity::Unknown),
            _ => None,
        }
    }

    /// OSV's `database_specific.severity` is GHSA-shaped
    /// (`"CRITICAL" | "HIGH" | "MODERATE" | "LOW"`). Be lenient
    /// with case; fall back to `Unknown` if unrecognised.
    fn from_database_specific(raw: &str) -> Self {
        Self::parse(raw).unwrap_or(Severity::Unknown)
    }

    /// CVSS v3 base scores map to severity per the spec:
    /// 0.0 None, 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High,
    /// 9.0-10.0 Critical.
    fn from_cvss_base_score(score: f64) -> Self {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Moderate
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }
}

/// Minimal subset of the OSV schema we deserialize. We use
/// `serde(rename_all = "snake_case")` ergonomically but most
/// OSV-shipped JSON uses lowerCamel/snake mixed — explicit
/// `#[serde(rename)]` per field is more reliable.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvAdvisory {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub published: Option<DateTime<Utc>>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub severity: Vec<OsvSeverityEntry>,
    #[serde(default, rename = "database_specific")]
    pub database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    pub package: OsvPackage,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

/// One entry inside `range.events`. OSV uses a "list of events"
/// shape (`{introduced: "1.0.0"}`, `{fixed: "1.2.3"}`,
/// `{last_affected: "1.2.2"}`, `{limit: "*"}`) which forms a
/// half-open interval `[introduced, fixed)`.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvRangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverityEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvDatabaseSpecific {
    #[serde(default)]
    pub severity: Option<String>,
}

impl OsvAdvisory {
    /// Best-effort severity extraction. Prefer
    /// `database_specific.severity` (GHSA's flavor and the easiest
    /// to interpret deterministically); fall back to a CVSS v3
    /// base score parsed out of the first `severity[]` entry of
    /// type `CVSS_V3` or `CVSS_V4`.
    pub fn severity(&self) -> Severity {
        if let Some(ds) = &self.database_specific
            && let Some(s) = &ds.severity
        {
            let parsed = Severity::from_database_specific(s);
            if parsed != Severity::Unknown {
                return parsed;
            }
        }
        for entry in &self.severity {
            let kind = entry.kind.to_ascii_uppercase();
            if (kind == "CVSS_V3" || kind == "CVSS_V4")
                && let Some(score) = extract_cvss_base_score(&entry.score)
            {
                return Severity::from_cvss_base_score(score);
            }
        }
        Severity::Unknown
    }

    /// Normalise the affected list into one row per
    /// `(ecosystem, name, version)` we should record from the
    /// explicit `versions[]` entries. SEMVER `ranges[]` are
    /// surfaced separately via [`affected_ranges`].
    pub fn affected_versions(&self) -> Vec<AffectedVersion> {
        let mut out = Vec::new();
        for aff in &self.affected {
            for v in &aff.versions {
                out.push(AffectedVersion {
                    ecosystem: osv_to_label(&aff.package.ecosystem)
                        .unwrap_or(&aff.package.ecosystem)
                        .to_string(),
                    name: aff.package.name.clone(),
                    version: v.clone(),
                });
            }
        }
        out
    }

    /// Normalise the affected list into half-open SemVer ranges.
    ///
    /// Only ranges whose ecosystem uses SemVer 2.0 semantics get
    /// projected — npm and crates today. PyPI (PEP 440) and
    /// NuGet (its own SemVer dialect) are left for a follow-up
    /// slice rather than mis-matched here.
    ///
    /// A range is dropped if neither its `introduced` nor any
    /// candidate upper bound (`fixed`, `last_affected`, `limit`)
    /// parses as a [`semver::Version`]; we'd rather under-detect
    /// than fabricate a match.
    pub fn affected_ranges(&self) -> Vec<AffectedRange> {
        let mut out = Vec::new();
        for aff in &self.affected {
            let Some(eco_label) = osv_to_label(&aff.package.ecosystem) else {
                continue;
            };
            if !ecosystem_uses_semver(eco_label) {
                continue;
            }
            for range in &aff.ranges {
                if !range_kind_is_semver(&range.kind, eco_label) {
                    continue;
                }
                // OSV's events list is sequence-sensitive: an
                // `introduced` opens an interval, and a later
                // `fixed`/`last_affected`/`limit` closes it.
                // Many advisories ship at most one pair; rather
                // than build a full segment tree, walk the events
                // and emit one range per `introduced`, paired
                // with the next closing event.
                let mut introduced: Option<semver::Version> = None;
                for ev in &range.events {
                    if let Some(s) = &ev.introduced {
                        if let Some(v) = parse_introduced(s) {
                            introduced = Some(v);
                        }
                    } else if let Some(open) = introduced.take() {
                        match classify_close(ev) {
                            CloseEvent::Exclusive(upper) => out.push(AffectedRange {
                                ecosystem: eco_label.to_string(),
                                name: aff.package.name.clone(),
                                introduced: open,
                                upper: Some(upper),
                                upper_inclusive: false,
                            }),
                            CloseEvent::Inclusive(upper) => out.push(AffectedRange {
                                ecosystem: eco_label.to_string(),
                                name: aff.package.name.clone(),
                                introduced: open,
                                upper: Some(upper),
                                upper_inclusive: true,
                            }),
                            CloseEvent::Unbounded => out.push(AffectedRange {
                                ecosystem: eco_label.to_string(),
                                name: aff.package.name.clone(),
                                introduced: open,
                                upper: None,
                                upper_inclusive: false,
                            }),
                            // A close event was present but its
                            // payload failed to parse. Dropping
                            // the open interval entirely is the
                            // conservative choice: emitting an
                            // unbounded range here would
                            // *fabricate* a "matches every version
                            // above introduced" claim that the
                            // advisory never made.
                            CloseEvent::Malformed => {}
                        }
                    }
                }
                // Trailing `introduced` with no closing event →
                // unbounded affected range. This is OSV's
                // shorthand for "no fix yet"; explicit.
                if let Some(open) = introduced {
                    out.push(AffectedRange {
                        ecosystem: eco_label.to_string(),
                        name: aff.package.name.clone(),
                        introduced: open,
                        upper: None,
                        upper_inclusive: false,
                    });
                }
            }
        }
        out
    }
}

fn ecosystem_uses_semver(label: &str) -> bool {
    matches!(label, "npm" | "crates")
}

fn range_kind_is_semver(kind: &str, eco_label: &str) -> bool {
    let upper = kind.to_ascii_uppercase();
    if upper == "SEMVER" {
        return true;
    }
    // OSV's `type: ECOSYSTEM` is "use the ecosystem's own
    // ordering". For npm/crates that ordering *is* SemVer 2.0,
    // so we accept it.
    upper == "ECOSYSTEM" && ecosystem_uses_semver(eco_label)
}

fn parse_introduced(s: &str) -> Option<semver::Version> {
    if s == "0" {
        return Some(semver::Version::new(0, 0, 0));
    }
    parse_version_loose(s)
}

/// `semver::Version::parse` is strict about three-segment form.
/// OSV in the wild ships shapes like `"1.0"` or `"1"`; pad them
/// before parsing so the matcher's coverage stays useful.
fn parse_version_loose(s: &str) -> Option<semver::Version> {
    if let Ok(v) = semver::Version::parse(s) {
        return Some(v);
    }
    let core = s.split(['+', '-']).next().unwrap_or(s);
    let dots = core.chars().filter(|c| *c == '.').count();
    let padded = match dots {
        0 => format!("{s}.0.0"),
        1 => format!("{s}.0"),
        _ => return None,
    };
    semver::Version::parse(&padded).ok()
}

/// How a close event mapped to a range bound.
enum CloseEvent {
    /// `fixed` / `limit` — `[introduced, upper)`.
    Exclusive(semver::Version),
    /// `last_affected` — `[introduced, upper]`. Stored inclusive
    /// so the scanner uses `<=` rather than fabricating an
    /// exclusive bump (which would over-match around prereleases).
    Inclusive(semver::Version),
    /// `limit: "*"` — explicitly unbounded above.
    Unbounded,
    /// Close event present but no payload parsed: drop the open
    /// rather than silently fabricating an unbounded range.
    Malformed,
}

fn classify_close(ev: &OsvRangeEvent) -> CloseEvent {
    if let Some(s) = ev.fixed.as_deref() {
        return match parse_version_loose(s) {
            Some(v) => CloseEvent::Exclusive(v),
            None => CloseEvent::Malformed,
        };
    }
    if let Some(s) = ev.last_affected.as_deref() {
        return match parse_version_loose(s) {
            Some(v) => CloseEvent::Inclusive(v),
            None => CloseEvent::Malformed,
        };
    }
    if let Some(s) = ev.limit.as_deref() {
        if s == "*" {
            return CloseEvent::Unbounded;
        }
        return match parse_version_loose(s) {
            Some(v) => CloseEvent::Exclusive(v),
            None => CloseEvent::Malformed,
        };
    }
    // Truly empty close event (shouldn't happen per the OSV
    // schema, but be defensive).
    CloseEvent::Malformed
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedVersion {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// SemVer 2.0 range projected out of an [`OsvRange`].
/// `[introduced, upper)` when `inclusive_upper = false`,
/// `[introduced, upper]` when `inclusive_upper = true`.
/// `upper = None` means "unbounded above" (no patched release
/// yet). `introduced = None` would mean "from the dawn of time"
/// but we always materialise it as `0.0.0` so downstream
/// comparisons stay total.
#[derive(Debug, Clone, PartialEq)]
pub struct AffectedRange {
    pub ecosystem: String,
    pub name: String,
    pub introduced: semver::Version,
    pub upper: Option<semver::Version>,
    /// `true` iff this range came from `last_affected` (inclusive
    /// upper); `false` for `fixed` / `limit` and for unbounded.
    pub upper_inclusive: bool,
}

/// A CVSS vector looks like `CVSS:3.1/AV:N/AC:L/...`. OSV stores
/// the full vector; the *base score* is computed from it. Rather
/// than vendor a CVSS calculator (heavy), we accept advisories
/// that ship a base score inline as the score string. When the
/// score string is a plain number, parse it directly.
fn extract_cvss_base_score(raw: &str) -> Option<f64> {
    // If it's a plain number, parse and use directly.
    if let Ok(n) = raw.trim().parse::<f64>() {
        return Some(n);
    }
    // Otherwise look for a trailing `/BASE/<num>` annotation OSV
    // sometimes ships alongside the vector (non-standard but seen
    // in the wild for older entries).
    for part in raw.split('/') {
        if let Some(rest) = part.strip_prefix("BASE:")
            && let Ok(n) = rest.parse::<f64>()
        {
            return Some(n);
        }
    }
    None
}

/// Map an OSV ecosystem label (e.g. `"npm"`, `"crates.io"`,
/// `"PyPI"`, `"NuGet"`) to the [`sakimori_core::deps::Ecosystem`]
/// label we use as the canonical storage form. Unknown OSV
/// ecosystems pass through unchanged (we still want to record the
/// advisory, even if no installs of that ecosystem could match
/// today's enum).
pub fn osv_to_label(osv: &str) -> Option<&'static str> {
    match osv.to_ascii_lowercase().as_str() {
        "npm" => Some("npm"),
        "crates.io" | "crates" => Some("crates"),
        "pypi" => Some("pypi"),
        "nuget" => Some("nuget"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_buckets_from_database_specific() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-x",
            "database_specific": {"severity": "HIGH"},
        }))
        .unwrap();
        assert_eq!(adv.severity(), Severity::High);
    }

    #[test]
    fn severity_falls_back_to_cvss_score() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-x",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        }))
        .unwrap();
        assert_eq!(adv.severity(), Severity::Critical);
    }

    #[test]
    fn severity_unknown_when_nothing_parseable() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-x",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        }))
        .unwrap();
        assert_eq!(adv.severity(), Severity::Unknown);
    }

    #[test]
    fn affected_versions_normalises_ecosystem_labels() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [
                {"package": {"ecosystem": "crates.io", "name": "tokio"}, "versions": ["1.0.0"]},
                {"package": {"ecosystem": "PyPI",      "name": "django"}, "versions": ["4.2.0", "4.2.1"]},
                {"package": {"ecosystem": "Maven",     "name": "p"},      "versions": ["1"]},
            ],
        }))
        .unwrap();
        let av = adv.affected_versions();
        assert_eq!(av.len(), 4);
        assert!(
            av.iter()
                .any(|v| v.ecosystem == "crates" && v.version == "1.0.0")
        );
        assert!(
            av.iter()
                .any(|v| v.ecosystem == "pypi" && v.version == "4.2.1")
        );
        // Unknown ecosystem passes through verbatim.
        assert!(av.iter().any(|v| v.ecosystem == "Maven"));
    }

    #[test]
    fn affected_versions_does_not_include_range_only_entries() {
        // No `versions` array → no row produced from
        // affected_versions (ranges live in affected_ranges).
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
            }],
        }))
        .unwrap();
        assert!(adv.affected_versions().is_empty());
    }

    #[test]
    fn affected_ranges_extracts_introduced_fixed_pairs() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-1",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.21"}
                ]}]
            }],
        }))
        .unwrap();
        let ranges = adv.affected_ranges();
        assert_eq!(ranges.len(), 1);
        let r = &ranges[0];
        assert_eq!(r.ecosystem, "npm");
        assert_eq!(r.name, "lodash");
        assert_eq!(r.introduced, semver::Version::new(0, 0, 0));
        assert_eq!(r.upper.as_ref().unwrap(), &semver::Version::new(4, 17, 21));
    }

    #[test]
    fn affected_ranges_handles_ecosystem_kind_for_npm_and_crates() {
        for eco in ["npm", "crates.io"] {
            let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
                "id": "x",
                "affected": [{
                    "package": {"ecosystem": eco, "name": "p"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "1.0.0"}, {"fixed": "1.0.5"}
                    ]}]
                }],
            }))
            .unwrap();
            let ranges = adv.affected_ranges();
            assert_eq!(
                ranges.len(),
                1,
                "{eco}: ECOSYSTEM kind should parse for SemVer ecosystems"
            );
        }
    }

    #[test]
    fn affected_ranges_skips_pypi_and_nuget_for_now() {
        for eco in ["PyPI", "NuGet"] {
            let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
                "id": "x",
                "affected": [{
                    "package": {"ecosystem": eco, "name": "p"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "1.0"}, {"fixed": "2.0"}
                    ]}]
                }],
            }))
            .unwrap();
            assert!(
                adv.affected_ranges().is_empty(),
                "{eco}: ECOSYSTEM kind is not SemVer 2.0 — skip rather than mis-match"
            );
        }
    }

    #[test]
    fn affected_ranges_last_affected_is_inclusive_upper() {
        // last_affected = 1.2.3 ⇒ upper bound 1.2.3 INCLUSIVE
        // (not bumped to 1.2.4, which would over-match prereleases
        // of the patched release).
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"last_affected": "1.2.3"}
                ]}]
            }],
        }))
        .unwrap();
        let r = &adv.affected_ranges()[0];
        assert_eq!(r.upper.as_ref().unwrap(), &semver::Version::new(1, 2, 3));
        assert!(r.upper_inclusive);
    }

    #[test]
    fn affected_ranges_malformed_close_drops_the_open() {
        // Regression: an unparseable `fixed` (or `last_affected`)
        // must NOT silently turn into an unbounded "everything >=
        // introduced" range — that fabricates findings.
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"fixed": "not-a-version"}
                ]}]
            }],
        }))
        .unwrap();
        assert!(
            adv.affected_ranges().is_empty(),
            "malformed close => drop the open, not unbounded"
        );
    }

    #[test]
    fn affected_ranges_limit_star_is_explicit_unbounded() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"limit": "*"}
                ]}]
            }],
        }))
        .unwrap();
        let r = &adv.affected_ranges()[0];
        assert_eq!(r.introduced, semver::Version::new(1, 0, 0));
        assert!(r.upper.is_none());
        assert!(!r.upper_inclusive);
    }

    #[test]
    fn affected_ranges_unbounded_when_no_close_event() {
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}]
            }],
        }))
        .unwrap();
        let r = &adv.affected_ranges()[0];
        assert_eq!(r.introduced, semver::Version::new(1, 0, 0));
        assert!(r.upper.is_none(), "no fix yet => unbounded upper");
    }

    #[test]
    fn affected_ranges_tolerates_partial_versions() {
        // `1` and `1.2` should pad to `1.0.0` / `1.2.0`.
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "x",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1"}, {"fixed": "1.2"}
                ]}]
            }],
        }))
        .unwrap();
        let r = &adv.affected_ranges()[0];
        assert_eq!(r.introduced, semver::Version::new(1, 0, 0));
        assert_eq!(r.upper.as_ref().unwrap(), &semver::Version::new(1, 2, 0));
    }

    #[test]
    fn severity_parse_accepts_medium_and_moderate() {
        assert_eq!(Severity::parse("medium"), Some(Severity::Moderate));
        assert_eq!(Severity::parse("MODERATE"), Some(Severity::Moderate));
    }

    #[test]
    fn cvss_extract_handles_plain_number_and_base_annotation() {
        assert_eq!(extract_cvss_base_score("9.8"), Some(9.8));
        assert_eq!(extract_cvss_base_score("CVSS:3.1/AV:N/BASE:7.5"), Some(7.5));
        assert_eq!(extract_cvss_base_score("CVSS:3.1/AV:N"), None);
    }
}

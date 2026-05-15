//! Known-IOC scanner for the workspace surface.
//!
//! Distinct from [`crate::tamper`] generic drift detection: this module
//! elevates a small, curated set of *specific* file paths from "something
//! changed" to "this is the fingerprint of a known supply-chain worm".
//! False positives are tolerable; false negatives are the failure mode
//! we care about, because by the time these files exist the attacker
//! has already written to disk.
//!
//! The first slice ships **path-based** indicators only. Content-based
//! fingerprints (specific opening bytes of a known dropper, suspicious
//! webhook URLs in `.npmrc`, etc.) are valuable but require reading
//! every file — we punt on that until there's a real reproducible
//! sample to match against.
//!
//! The catalog is statically compiled into the binary today. The
//! roadmap calls for a `sakimori iocs update` that refreshes from a
//! signed YAML; the catalog API (`Catalog::default()` + an explicit
//! `version`) is shaped so a future loader can swap in a runtime
//! catalog without changing callers.

use std::path::{Component, Path, PathBuf};

use serde::Serialize;

/// Version of the bundled catalog. Bump whenever the rule set changes
/// so JSON consumers can tell which fingerprints were active.
pub const CATALOG_VERSION: &str = "2026.05.15";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// High-confidence fingerprint of a known campaign. Treat as a
    /// strong signal that the workspace is compromised — investigate
    /// before continuing the run.
    High,
    /// Suggestive but not conclusive on its own. The file is rarely
    /// legitimate in a CI checkout but isn't a campaign-specific name.
    Medium,
}

/// A single path-based indicator. `pattern` is interpreted by `kind`.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Stable identifier — appears in JSON output. `family.short_name`.
    pub id: &'static str,
    /// Campaign / family the indicator belongs to. Used to group
    /// findings in human-readable output.
    pub family: &'static str,
    pub severity: Severity,
    pub kind: RuleKind,
    pub pattern: &'static str,
    /// One-line human description. Shown in text output next to the
    /// path so reviewers don't have to remember what `setup.mjs` is.
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub enum RuleKind {
    /// Match when the relative path ends with `pattern`, split on
    /// path components. `pattern = ".claude/setup.mjs"` matches
    /// `.claude/setup.mjs` and `subdir/.claude/setup.mjs` but not
    /// `claude/setup.mjs`.
    PathSuffix,
    /// Match when the basename equals `pattern` (case-sensitive).
    Basename,
}

/// The bundled catalog. Ordered so higher-confidence indicators appear
/// first; downstream renderers may rely on stability when comparing
/// runs but should not depend on it for correctness.
pub fn catalog() -> &'static [Rule] {
    &[
        Rule {
            id: "shai-hulud.claude-setup-mjs",
            family: "shai-hulud",
            severity: Severity::High,
            kind: RuleKind::PathSuffix,
            pattern: ".claude/setup.mjs",
            description: "Shai-Hulud dropper — writes a `.claude/setup.mjs` \
                          hook that re-executes on next Claude Code session.",
        },
        Rule {
            id: "shai-hulud.data-json",
            family: "shai-hulud",
            severity: Severity::High,
            kind: RuleKind::Basename,
            pattern: "shai-hulud-data.json",
            description: "Shai-Hulud staging artefact — exfiltrated \
                          credentials are spooled to this file before \
                          being POSTed to the C2.",
        },
        Rule {
            id: "shai-hulud.workflow-yaml",
            family: "shai-hulud",
            severity: Severity::High,
            kind: RuleKind::PathSuffix,
            pattern: ".github/workflows/shai-hulud-workflow.yml",
            description: "Shai-Hulud persistence — adds a workflow that \
                          re-runs the dropper on every push.",
        },
        Rule {
            id: "supplychain.suspicious-codeql",
            family: "supplychain-generic",
            severity: Severity::Medium,
            kind: RuleKind::PathSuffix,
            pattern: ".github/workflows/codeql_analysis.yml",
            description: "Workflow file with the CodeQL-analysis name \
                          observed as a cover for malicious workflow \
                          additions. False-positive when the repo \
                          legitimately uses CodeQL — verify the \
                          contents before reacting.",
        },
        Rule {
            id: "supplychain.npmrc-token",
            family: "supplychain-generic",
            severity: Severity::Medium,
            kind: RuleKind::Basename,
            pattern: ".npmrc",
            description: "An `.npmrc` appearing in a workspace where \
                          none existed before commonly indicates a \
                          token-exfiltration or registry-redirection \
                          attempt. Inspect for `//*:_authToken=` or a \
                          non-default `registry=` line.",
        },
    ]
}

/// Decide whether `path` matches any catalog rule. `path` should be
/// **relative** to the workspace root — callers using
/// [`crate::tamper::Snapshot::files`] already get relative paths
/// because the snapshot keys on them.
pub fn matches(path: &Path) -> Vec<&'static Rule> {
    let normalised = normalise(path);
    let basename = normalised
        .components()
        .next_back()
        .and_then(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .unwrap_or("");

    let mut out = Vec::new();
    for rule in catalog() {
        let hit = match rule.kind {
            RuleKind::Basename => basename == rule.pattern,
            RuleKind::PathSuffix => path_ends_with(&normalised, rule.pattern),
        };
        if hit {
            out.push(rule);
        }
    }
    out
}

/// Scan an iterator of paths against the catalog. Findings are
/// returned in the order they're matched (which is `paths` × catalog
/// order, so deterministic given a sorted input).
pub fn scan_paths<'a, I, P>(paths: I) -> Vec<Finding>
where
    I: IntoIterator<Item = &'a P>,
    P: AsRef<Path> + 'a + ?Sized,
{
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        for rule in matches(p) {
            out.push(Finding {
                path: p.to_path_buf(),
                rule_id: rule.id,
                family: rule.family,
                severity: rule.severity,
                description: rule.description,
            });
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: PathBuf,
    pub rule_id: &'static str,
    pub family: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub catalog_version: &'static str,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            catalog_version: CATALOG_VERSION,
            findings,
        }
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// True when at least one finding is High-severity. Block-mode
    /// callers should treat this as a non-zero exit signal.
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::High)
    }
}

/// Normalise the input path: strip a leading `./`, collapse any
/// duplicate separators, drop trailing `/`. We do not resolve `..`
/// because we want to refuse to match across a parent-dir hop — an
/// attacker who somehow gets `foo/../.claude/setup.mjs` into the diff
/// is still a hit if we leave `..` in place (it's nonsense as a
/// filesystem path) and a miss if we resolve it (changes the
/// semantics). Leaving as-is keeps the suffix match honest.
fn normalise(path: &Path) -> PathBuf {
    let mut buf = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            other => buf.push(other.as_os_str()),
        }
    }
    buf
}

/// Suffix match on path **components** (not bytes). `path_ends_with(
/// "a/b/c.txt", "b/c.txt")` is `true`; `path_ends_with("ab/c.txt",
/// "b/c.txt")` is `false`.
fn path_ends_with(path: &Path, suffix: &str) -> bool {
    let suffix_path = Path::new(suffix);
    let pcs: Vec<_> = path.components().collect();
    let scs: Vec<_> = suffix_path.components().collect();
    if scs.len() > pcs.len() {
        return false;
    }
    let tail = &pcs[pcs.len() - scs.len()..];
    tail.iter()
        .zip(scs.iter())
        .all(|(a, b)| a.as_os_str() == b.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shai_hulud_setup_mjs_matches_at_root_and_nested() {
        assert_eq!(matches(Path::new(".claude/setup.mjs")).len(), 1);
        assert_eq!(matches(Path::new("foo/.claude/setup.mjs")).len(), 1);
        assert_eq!(matches(Path::new("./.claude/setup.mjs")).len(), 1);
    }

    #[test]
    fn near_misses_do_not_match() {
        // Sibling directory name — must not match.
        assert!(matches(Path::new("claude/setup.mjs")).is_empty());
        // Same basename in an unrelated dir.
        assert!(matches(Path::new(".claude-bak/setup.mjs")).is_empty());
        // Different basename inside the right dir.
        assert!(matches(Path::new(".claude/init.mjs")).is_empty());
    }

    #[test]
    fn basename_rule_matches_anywhere() {
        let hits = matches(Path::new("deep/nested/.npmrc"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "supplychain.npmrc-token");
    }

    #[test]
    fn shai_hulud_data_json_basename_match() {
        assert_eq!(matches(Path::new("anywhere/shai-hulud-data.json")).len(), 1);
        // The basename rule is exact — a similar but distinct name
        // must not collide.
        assert!(matches(Path::new("anywhere/shai-hulud-data.json.bak")).is_empty());
    }

    #[test]
    fn scan_paths_collects_findings() {
        let paths = [
            PathBuf::from(".claude/setup.mjs"),
            PathBuf::from("src/main.rs"), // benign
            PathBuf::from(".github/workflows/shai-hulud-workflow.yml"),
        ];
        let findings = scan_paths(paths.iter());
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn report_severity_flags() {
        let medium_only = Report::new(vec![Finding {
            path: PathBuf::from("a/.npmrc"),
            rule_id: "supplychain.npmrc-token",
            family: "supplychain-generic",
            severity: Severity::Medium,
            description: "",
        }]);
        assert!(!medium_only.is_clean());
        assert!(!medium_only.has_high());

        let high = Report::new(vec![Finding {
            path: PathBuf::from(".claude/setup.mjs"),
            rule_id: "shai-hulud.claude-setup-mjs",
            family: "shai-hulud",
            severity: Severity::High,
            description: "",
        }]);
        assert!(high.has_high());
    }

    #[test]
    fn catalog_ids_are_unique() {
        let mut ids: Vec<&str> = catalog().iter().map(|r| r.id).collect();
        ids.sort();
        let original = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original, "catalog rule ids must be unique");
    }
}

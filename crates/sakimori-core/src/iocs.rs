//! Known-IOC workspace scanner.
//!
//! Walks a workspace root looking for files whose existence is a
//! known supply-chain-compromise fingerprint (see roadmap item 18).
//! Distinct from [`crate::tamper`]: tamper diff says "something
//! changed during the build"; this says "this specific file is a
//! known attacker marker, regardless of whether it changed."
//!
//! The catalog is shipped bundled in the binary (loaded from
//! `iocs/coronarium-iocs.yml` via [`include_str!`]); callers can
//! override with a file path for testing or private feeds.
//!
//! Conservatively scoped:
//! - Hits surface as a structured report; the CLI exits non-zero on
//!   any `Severity::Error` hit so it composes with CI gates.
//! - No auto-quarantine, no auto-delete.
//! - The walker honours the same skip list as [`crate::tamper`] so
//!   build-artefact churn doesn't drown the signal.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::tamper::DEFAULT_SKIP_DIRS;

/// Bundled IOC index. Refreshed by editing
/// `crates/sakimori-core/iocs/coronarium-iocs.yml`; a future
/// `sakimori iocs update` will do this from an upstream feed.
pub const BUNDLED_CATALOG_YAML: &str = include_str!("../iocs/coronarium-iocs.yml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// CI-gate fail. Reserved for IOCs we have high confidence are
    /// real compromise markers in any context.
    Error,
    /// Surface but don't fail. Used for fingerprints that have a
    /// plausible benign explanation (e.g. a legitimate CodeQL job
    /// confusable with the worm-dropped lookalike).
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatchSpec {
    /// Path relative to the workspace root, matched exactly after
    /// normalising both sides to forward slashes.
    RelativePath { path: String },
    /// File basename, matched anywhere in the tree.
    Basename { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pattern {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    pub version: u32,
    pub patterns: Vec<Pattern>,
}

impl Catalog {
    /// Parse the bundled YAML index. Always succeeds for releases —
    /// the test [`tests::bundled_catalog_parses`] guards against
    /// breakage on the way in.
    pub fn bundled() -> Result<Self> {
        Self::from_yaml(BUNDLED_CATALOG_YAML)
    }

    pub fn from_yaml(text: &str) -> Result<Self> {
        let cat: Catalog = serde_yaml::from_str(text).context("parsing IOC catalog YAML")?;
        cat.validate()?;
        Ok(cat)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading IOC catalog {}", path.display()))?;
        Self::from_yaml(&text)
    }

    fn validate(&self) -> Result<()> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for p in &self.patterns {
            if !seen.insert(p.id.as_str()) {
                anyhow::bail!("duplicate IOC pattern id `{}`", p.id);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub pattern_id: String,
    pub description: String,
    pub severity: Severity,
    /// Path relative to the scanned root, with forward slashes.
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanReport {
    pub root: PathBuf,
    pub hits: Vec<Hit>,
}

impl ScanReport {
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty()
    }

    /// True if any hit is at [`Severity::Error`]. The CLI maps this
    /// to its non-zero exit code so it gates a CI step.
    pub fn has_error(&self) -> bool {
        self.hits.iter().any(|h| h.severity == Severity::Error)
    }
}

/// Walk `root` and report every IOC that matches. `allow_ids` is a
/// set of pattern ids the caller has already triaged as false
/// positives — they're skipped silently.
pub fn scan(root: &Path, catalog: &Catalog, allow_ids: &BTreeSet<String>) -> Result<ScanReport> {
    let canon = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let skip: BTreeSet<&str> = DEFAULT_SKIP_DIRS.iter().copied().collect();

    let mut report = ScanReport {
        root: canon.clone(),
        hits: Vec::new(),
    };

    // For relative_path patterns we can stat() the absolute path
    // directly and skip the walk; that's both faster and avoids
    // false negatives when a parent dir happens to be on the skip
    // list (e.g. an attacker-dropped `node_modules/.bin/postinstall`
    // wouldn't matter today but the skip list might shrink later).
    for pat in &catalog.patterns {
        if allow_ids.contains(&pat.id) {
            continue;
        }
        if let MatchSpec::RelativePath { path } = &pat.match_spec {
            let abs = canon.join(path);
            if abs.exists() {
                report.hits.push(Hit {
                    pattern_id: pat.id.clone(),
                    description: pat.description.clone(),
                    severity: pat.severity,
                    path: normalise_rel(path),
                });
            }
        }
    }

    // Basename patterns require a walk. Only walk if at least one
    // such pattern is present and unallowed — saves the IO cost
    // when the catalog only has relative_path entries.
    let basename_patterns: Vec<&Pattern> = catalog
        .patterns
        .iter()
        .filter(|p| !allow_ids.contains(&p.id))
        .filter(|p| matches!(p.match_spec, MatchSpec::Basename { .. }))
        .collect();

    if !basename_patterns.is_empty() {
        walk_for_basenames(&canon, &canon, &skip, &basename_patterns, &mut report.hits);
    }

    // Stable order: pattern id then path. Useful both for human
    // readability and for snapshot-style assertions.
    report
        .hits
        .sort_by(|a, b| (&a.pattern_id, &a.path).cmp(&(&b.pattern_id, &b.path)));

    Ok(report)
}

fn walk_for_basenames(
    root: &Path,
    dir: &Path,
    skip: &BTreeSet<&str>,
    patterns: &[&Pattern],
    hits: &mut Vec<Hit>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(it) => it,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            if skip.contains(name_str.as_ref()) {
                continue;
            }
            walk_for_basenames(root, &path, skip, patterns, hits);
        } else if ft.is_file() || ft.is_symlink() {
            for pat in patterns {
                if let MatchSpec::Basename { name: target } = &pat.match_spec
                    && name_str == target.as_str()
                {
                    let rel = path
                        .strip_prefix(root)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| path.to_string_lossy().to_string());
                    hits.push(Hit {
                        pattern_id: pat.id.clone(),
                        description: pat.description.clone(),
                        severity: pat.severity,
                        path: normalise_rel(&rel),
                    });
                }
            }
        }
    }
}

fn normalise_rel(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Minimal tmpdir helper; mirrors what `tamper.rs` does. Atomic
    /// counter so parallel tests don't collide.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let pid = std::process::id();
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("sakimori-iocs-test-{pid}-{n}"));
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn bundled_catalog_parses() {
        let cat = Catalog::bundled().expect("bundled YAML must parse");
        assert!(!cat.patterns.is_empty());
        // Spot-check: the headline Shai-Hulud entry is there.
        assert!(
            cat.patterns
                .iter()
                .any(|p| p.id == "shai-hulud-claude-setup")
        );
    }

    #[test]
    fn duplicate_pattern_id_rejected() {
        let bad = "version: 1\npatterns:\n\
                   - id: dup\n  description: x\n  severity: error\n  match: {kind: basename, name: a}\n\
                   - id: dup\n  description: y\n  severity: warn\n  match: {kind: basename, name: b}\n";
        let err = Catalog::from_yaml(bad).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn relative_path_pattern_hits_when_file_present() {
        let tmp = Tmp::new();
        fs::create_dir_all(tmp.0.join(".claude")).unwrap();
        fs::write(tmp.0.join(".claude/setup.mjs"), b"// pwn\n").unwrap();

        let cat = Catalog::bundled().unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        assert!(
            report
                .hits
                .iter()
                .any(|h| h.pattern_id == "shai-hulud-claude-setup")
        );
        assert!(report.has_error());
    }

    #[test]
    fn relative_path_pattern_silent_when_file_absent() {
        let tmp = Tmp::new();
        fs::write(tmp.0.join("README.md"), b"# clean\n").unwrap();
        let cat = Catalog::bundled().unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        assert!(report.is_clean());
        assert!(!report.has_error());
    }

    #[test]
    fn allow_id_suppresses_a_hit() {
        let tmp = Tmp::new();
        fs::create_dir_all(tmp.0.join(".claude")).unwrap();
        fs::write(tmp.0.join(".claude/setup.mjs"), b"x").unwrap();
        let cat = Catalog::bundled().unwrap();
        let mut allow = BTreeSet::new();
        allow.insert("shai-hulud-claude-setup".to_string());
        let report = scan(&tmp.0, &cat, &allow).unwrap();
        assert!(
            report.is_clean(),
            "allow-list must suppress matching hits, got {:?}",
            report.hits
        );
    }

    #[test]
    fn basename_pattern_walks_subdirs_but_skips_build_artefacts() {
        let tmp = Tmp::new();
        // Two copies of a basename: one inside `node_modules` (must
        // be skipped) and one in real source (must be found).
        fs::create_dir_all(tmp.0.join("node_modules/evil")).unwrap();
        fs::write(tmp.0.join("node_modules/evil/dropper.js"), b"x").unwrap();
        fs::create_dir_all(tmp.0.join("src/util")).unwrap();
        fs::write(tmp.0.join("src/util/dropper.js"), b"x").unwrap();

        let cat = Catalog::from_yaml(
            "version: 1\npatterns:\n\
             - id: test-basename\n  description: t\n  severity: warn\n  \
             match: {kind: basename, name: dropper.js}\n",
        )
        .unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        assert_eq!(report.hits.len(), 1, "must skip node_modules/");
        assert!(report.hits[0].path.starts_with("src/"));
        assert!(!report.has_error(), "warn-only hits don't gate CI");
    }

    #[test]
    fn hits_sort_stably_by_id_then_path() {
        let tmp = Tmp::new();
        fs::create_dir_all(tmp.0.join("a")).unwrap();
        fs::create_dir_all(tmp.0.join("b")).unwrap();
        fs::write(tmp.0.join("a/x.txt"), b"").unwrap();
        fs::write(tmp.0.join("b/x.txt"), b"").unwrap();
        let cat = Catalog::from_yaml(
            "version: 1\npatterns:\n\
             - id: zzz\n  description: t\n  severity: warn\n  match: {kind: basename, name: x.txt}\n\
             - id: aaa\n  description: t\n  severity: warn\n  match: {kind: basename, name: x.txt}\n",
        ).unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        let ids: Vec<&str> = report.hits.iter().map(|h| h.pattern_id.as_str()).collect();
        assert_eq!(ids, vec!["aaa", "aaa", "zzz", "zzz"]);
        for id in ["aaa", "zzz"] {
            let paths: Vec<&str> = report
                .hits
                .iter()
                .filter(|h| h.pattern_id == id)
                .map(|h| h.path.as_str())
                .collect();
            assert_eq!(paths, vec!["a/x.txt", "b/x.txt"]);
        }
    }
}

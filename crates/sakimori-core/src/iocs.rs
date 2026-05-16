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
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tamper::DEFAULT_SKIP_DIRS;

/// Bundled IOC index. Always present in the binary as a fallback;
/// `sakimori iocs update` writes a refreshed copy to
/// [`default_override_path`] which the scanner prefers when present.
pub const BUNDLED_CATALOG_YAML: &str = include_str!("../iocs/coronarium-iocs.yml");

/// User-writable IOC override location. Honoured by
/// [`Catalog::load_with_fallback`]: present + parseable = used;
/// absent or unparseable = fall back to bundled. Resolved at call
/// time, not compile time, so tests with a tmp `HOME` don't
/// accidentally read the developer's real cache.
///
/// Resolution order (first hit wins):
/// 1. `$XDG_DATA_HOME/sakimori/iocs.yml` (Linux/XDG-aware setups)
/// 2. `$HOME/.sakimori/iocs.yml` (macOS + traditional Unix)
/// 3. `%LOCALAPPDATA%\sakimori\iocs.yml` (Windows, matches the
///    convention already used by `deps verify-cache` for the npm
///    cacache root)
/// 4. `%USERPROFILE%\.sakimori\iocs.yml` (Windows last-resort —
///    older shells / Cygwin-like envs where LOCALAPPDATA is unset)
///
/// Returns `None` only when every candidate env var is unset, in
/// which case the CLI tells the operator to pass `--output`.
pub fn default_override_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(xdg).join("sakimori").join("iocs.yml"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home).join(".sakimori").join("iocs.yml"));
    }
    if let Some(la) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(la).join("sakimori").join("iocs.yml"));
    }
    if let Some(up) = std::env::var_os("USERPROFILE") {
        return Some(PathBuf::from(up).join(".sakimori").join("iocs.yml"));
    }
    None
}

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
    /// Content fingerprint — SHA-256 of the file contents in lowercase
    /// hex. Walks the tree like `Basename` does. Optional `basename`
    /// narrows which files are hashed so the catalog can stay cheap
    /// (a bare `Sha256` with no `basename` would force hashing every
    /// regular file under the root). Files larger than
    /// [`MAX_HASH_BYTES`] are skipped without being hashed.
    Sha256 {
        sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        basename: Option<String>,
    },
}

/// Hard cap on file size for content-fingerprint matches. The scanner
/// silently skips bigger files rather than spending unbounded IO; in
/// practice every worm dropper observed in the wild has been < 1 MiB,
/// and an attacker who pads a 16 MiB blob is also one a `Basename`
/// pattern would catch. 16 MiB is a generous margin over that.
pub const MAX_HASH_BYTES: u64 = 16 * 1024 * 1024;

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

    /// Production loader: tries `override_path` first (typically the
    /// `~/.sakimori/iocs.yml` cache written by `sakimori iocs update`),
    /// falls back to the bundled catalog on any error. Returns the
    /// catalog plus a `loaded_from` enum so the CLI can tell the user
    /// which one is in effect.
    ///
    /// Fall-through on parse error is deliberate: a corrupted cache
    /// (truncated download, malformed feed) must not brick the
    /// scanner. The error is surfaced through `loaded_from` so the
    /// caller can warn loudly without aborting.
    pub fn load_with_fallback(override_path: Option<&Path>) -> (Self, LoadedFrom) {
        if let Some(path) = override_path
            && path.exists()
        {
            match Self::from_file(path) {
                Ok(cat) => return (cat, LoadedFrom::Override(path.to_path_buf())),
                Err(err) => {
                    return (
                        Self::bundled().expect("bundled catalog parses"),
                        LoadedFrom::BundledAfterOverrideError {
                            path: path.to_path_buf(),
                            error: err.to_string(),
                        },
                    );
                }
            }
        }
        (
            Self::bundled().expect("bundled catalog parses"),
            LoadedFrom::Bundled,
        )
    }

    fn validate(&self) -> Result<()> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for p in &self.patterns {
            if !seen.insert(p.id.as_str()) {
                anyhow::bail!("duplicate IOC pattern id `{}`", p.id);
            }
            if let MatchSpec::Sha256 { sha256, .. } = &p.match_spec {
                // 64 lowercase hex chars. Reject early so a typo in
                // the catalog surfaces at load time, not at scan time
                // (where it would silently never match).
                if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                    anyhow::bail!(
                        "IOC pattern `{}`: sha256 must be 64 hex chars, got `{}` (len {})",
                        p.id,
                        sha256,
                        sha256.len()
                    );
                }
                if sha256.chars().any(|c| c.is_ascii_uppercase()) {
                    anyhow::bail!("IOC pattern `{}`: sha256 must be lowercase hex", p.id);
                }
            }
        }
        Ok(())
    }
}

/// Tells the CLI which on-disk source the catalog came from. Surfaced
/// to the operator so a stale override that fails to parse can be
/// noticed and fixed.
#[derive(Debug, Clone)]
pub enum LoadedFrom {
    /// `BUNDLED_CATALOG_YAML` — the compile-time copy.
    Bundled,
    /// On-disk override (typically `~/.sakimori/iocs.yml`), parsed
    /// cleanly.
    Override(PathBuf),
    /// On-disk override exists but failed to parse; the bundled
    /// catalog was used as a fallback. Surface this loudly — the
    /// override is silently stale until the operator fixes it.
    BundledAfterOverrideError { path: PathBuf, error: String },
}

/// Fetcher abstraction so `update_from` can be unit-tested without a
/// live HTTP request. Implementations: [`HttpFetcher`] for production,
/// inline closures via [`FnFetcher`] for tests.
pub trait Fetcher {
    fn fetch(&self, url: &str) -> Result<String>;
}

pub struct HttpFetcher {
    pub user_agent: String,
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &str) -> Result<String> {
        let resp = ureq::get(url)
            .set("user-agent", &self.user_agent)
            .call()
            .with_context(|| format!("GET {url}"))?;
        resp.into_string()
            .with_context(|| format!("reading body from {url}"))
    }
}

/// Test-friendly fetcher built from a closure.
pub struct FnFetcher<F: Fn(&str) -> Result<String>>(pub F);
impl<F: Fn(&str) -> Result<String>> Fetcher for FnFetcher<F> {
    fn fetch(&self, url: &str) -> Result<String> {
        (self.0)(url)
    }
}

/// Fetch + validate + atomically write an IOC catalog. Returns the
/// parsed catalog so the CLI can report the new version. The write is
/// atomic (tempfile + rename) so a half-written cache can never leave
/// a corrupted override on disk.
///
/// Validation happens *before* the write — a malformed upstream feed
/// must not clobber a working local override.
pub fn update_from(fetcher: &dyn Fetcher, url: &str, dest: &Path) -> Result<Catalog> {
    let body = fetcher.fetch(url)?;
    let cat = Catalog::from_yaml(&body)
        .with_context(|| format!("fetched catalog from {url} did not validate"))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating IOC cache dir {}", parent.display()))?;
    }
    // Atomic rename: write the validated bytes to a sibling tempfile
    // first, then rename over the target. Rename is atomic within a
    // filesystem on every platform we ship to.
    let tmp = dest.with_extension("yml.tmp");
    std::fs::write(&tmp, body.as_bytes())
        .with_context(|| format!("writing temp {}", tmp.display()))?;
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), dest.display()))?;
    Ok(cat)
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
///
/// Errors when `root` does not exist or is not a directory. The
/// loud failure is deliberate: a CI gate fed a stale or mistyped
/// `$GITHUB_WORKSPACE` would otherwise see "0 hits, exit 0" and
/// silently pass — exactly the worst behaviour for a tool whose
/// job is to fail noisy.
pub fn scan(root: &Path, catalog: &Catalog, allow_ids: &BTreeSet<String>) -> Result<ScanReport> {
    let meta = std::fs::metadata(root)
        .with_context(|| format!("scan root {} is not accessible", root.display()))?;
    if !meta.is_dir() {
        anyhow::bail!("scan root {} exists but is not a directory", root.display());
    }
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

    // Basename + sha256 patterns require a walk. Only walk if at
    // least one such pattern is present and unallowed — saves the
    // IO cost when the catalog only has relative_path entries.
    let walk_patterns: Vec<&Pattern> = catalog
        .patterns
        .iter()
        .filter(|p| !allow_ids.contains(&p.id))
        .filter(|p| {
            matches!(
                p.match_spec,
                MatchSpec::Basename { .. } | MatchSpec::Sha256 { .. }
            )
        })
        .collect();

    if !walk_patterns.is_empty() {
        walk_for_content(&canon, &canon, &skip, &walk_patterns, &mut report.hits);
    }

    // Stable order: pattern id then path. Useful both for human
    // readability and for snapshot-style assertions.
    report
        .hits
        .sort_by(|a, b| (&a.pattern_id, &a.path).cmp(&(&b.pattern_id, &b.path)));

    Ok(report)
}

fn walk_for_content(
    root: &Path,
    dir: &Path,
    skip: &BTreeSet<&str>,
    patterns: &[&Pattern],
    hits: &mut Vec<Hit>,
) {
    let entries = match fs::read_dir(dir) {
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
            walk_for_content(root, &path, skip, patterns, hits);
            continue;
        }

        // Basename matches fire on both regular files and symlinks
        // — a worm dropping a marker file as a symlink (e.g. into
        // a tmpfs decoy) must still be flagged by name. Sha256
        // matches only fire on regular files: following a symlink
        // would let an attacker point at a benign target and evade
        // the content hash.
        if !ft.is_file() && !ft.is_symlink() {
            continue;
        }
        let mut hash: Option<String> = None;
        for pat in patterns {
            match &pat.match_spec {
                MatchSpec::Basename { name: target } if name_str == target.as_str() => {
                    push_hit(pat, root, &path, hits);
                }
                MatchSpec::Sha256 {
                    sha256: expected,
                    basename,
                } if ft.is_file() => {
                    if let Some(b) = basename
                        && name_str != b.as_str()
                    {
                        continue;
                    }
                    if hash.is_none() {
                        hash = hash_file_capped(&path, MAX_HASH_BYTES);
                    }
                    if let Some(h) = &hash
                        && h == expected
                    {
                        push_hit(pat, root, &path, hits);
                    }
                }
                _ => {}
            }
        }
    }
}

fn push_hit(pat: &Pattern, root: &Path, path: &Path, hits: &mut Vec<Hit>) {
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

fn hash_file_capped(path: &Path, max_bytes: u64) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > max_bytes {
        return None;
    }
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
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
    fn nonexistent_root_errors_loudly_not_silently_clean() {
        // Regression for the codex review finding: a CI gate fed
        // an unset / mistyped $GITHUB_WORKSPACE must fail loudly,
        // not return "0 hits, exit 0".
        let cat = Catalog::bundled().unwrap();
        let err = scan(
            Path::new("/definitely/does/not/exist/sakimori-iocs-test"),
            &cat,
            &BTreeSet::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not accessible"), "got: {err}");
    }

    #[test]
    fn file_root_errors_not_silently_clean() {
        let tmp = Tmp::new();
        let f = tmp.0.join("not-a-dir.txt");
        fs::write(&f, b"x").unwrap();
        let cat = Catalog::bundled().unwrap();
        let err = scan(&f, &cat, &BTreeSet::new()).unwrap_err().to_string();
        assert!(err.contains("not a directory"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn basename_pattern_matches_symlink_by_name_sha256_skips_it() {
        // Regression for the codex review on 87f2a24: switching the
        // walker from `is_file() || is_symlink()` to `is_file()`
        // had silently dropped basename matches on symlinks. The
        // sha256 path must still skip them (no symlink-following).
        use std::os::unix::fs::symlink;
        let tmp = Tmp::new();
        let target = tmp.0.join("real-target.txt");
        let link = tmp.0.join("dropper.js");
        fs::write(&target, b"payload\n").unwrap();
        symlink(&target, &link).unwrap();

        let expected_hash = {
            let mut h = Sha256::new();
            h.update(b"payload\n");
            format!("{:x}", h.finalize())
        };
        let yaml = format!(
            "version: 1\npatterns:\n\
             - id: by-name\n  description: t\n  severity: warn\n  \
             match: {{kind: basename, name: dropper.js}}\n\
             - id: by-hash\n  description: t\n  severity: warn\n  \
             match: {{kind: sha256, sha256: {expected_hash}}}\n"
        );
        let cat = Catalog::from_yaml(&yaml).unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();

        let by_name: Vec<_> = report
            .hits
            .iter()
            .filter(|h| h.pattern_id == "by-name")
            .collect();
        assert_eq!(
            by_name.len(),
            1,
            "basename must match the symlink, got {:?}",
            report.hits
        );
        assert_eq!(by_name[0].path, "dropper.js");

        // The real target ("real-target.txt") is the only regular
        // file matching the hash. The symlink is not followed and
        // does not double-count.
        let by_hash: Vec<_> = report
            .hits
            .iter()
            .filter(|h| h.pattern_id == "by-hash")
            .collect();
        assert_eq!(
            by_hash.len(),
            1,
            "sha256 must fire once (the regular file only)"
        );
        assert_eq!(by_hash[0].path, "real-target.txt");
    }

    #[test]
    fn sha256_pattern_matches_by_content_not_path() {
        let tmp = Tmp::new();
        let body = b"// shai-hulud dropper payload\n";
        // Same payload at two different paths — both must hit.
        fs::create_dir_all(tmp.0.join("a")).unwrap();
        fs::create_dir_all(tmp.0.join("b/nested")).unwrap();
        fs::write(tmp.0.join("a/innocent-name.js"), body).unwrap();
        fs::write(tmp.0.join("b/nested/another.js"), body).unwrap();
        fs::write(tmp.0.join("decoy.js"), b"// completely different\n").unwrap();

        let expected = {
            let mut h = Sha256::new();
            h.update(body);
            format!("{:x}", h.finalize())
        };
        let yaml = format!(
            "version: 1\npatterns:\n\
             - id: known-dropper\n  description: t\n  severity: error\n  \
             match: {{kind: sha256, sha256: {expected}}}\n"
        );
        let cat = Catalog::from_yaml(&yaml).unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        assert_eq!(
            report.hits.len(),
            2,
            "both copies must hit, got {:?}",
            report.hits
        );
        assert!(report.has_error());
    }

    #[test]
    fn sha256_with_basename_scope_skips_other_filenames() {
        // Same bytes at two paths. Catalog scopes to one basename
        // → only that file is hashed + matched.
        let tmp = Tmp::new();
        let body = b"payload\n";
        fs::write(tmp.0.join("dropper.js"), body).unwrap();
        fs::write(tmp.0.join("README.md"), body).unwrap();
        let expected = {
            let mut h = Sha256::new();
            h.update(body);
            format!("{:x}", h.finalize())
        };
        let yaml = format!(
            "version: 1\npatterns:\n\
             - id: scoped\n  description: t\n  severity: warn\n  \
             match: {{kind: sha256, sha256: {expected}, basename: dropper.js}}\n"
        );
        let cat = Catalog::from_yaml(&yaml).unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].path, "dropper.js");
    }

    #[test]
    fn sha256_mismatch_does_not_fire() {
        let tmp = Tmp::new();
        fs::write(tmp.0.join("a.txt"), b"hello").unwrap();
        // 64 zeros — won't match anything real.
        let cat = Catalog::from_yaml(
            "version: 1\npatterns:\n\
             - id: never\n  description: t\n  severity: error\n  \
             match: {kind: sha256, sha256: 0000000000000000000000000000000000000000000000000000000000000000}\n",
        )
        .unwrap();
        let report = scan(&tmp.0, &cat, &BTreeSet::new()).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn sha256_catalog_rejects_short_or_uppercase_hex() {
        let short = "version: 1\npatterns:\n\
                     - id: x\n  description: t\n  severity: warn\n  \
                     match: {kind: sha256, sha256: deadbeef}\n";
        let err = Catalog::from_yaml(short).unwrap_err().to_string();
        assert!(err.contains("64 hex chars"), "got: {err}");

        let upper = format!(
            "version: 1\npatterns:\n\
             - id: y\n  description: t\n  severity: warn\n  \
             match: {{kind: sha256, sha256: {}}}\n",
            "A".repeat(64)
        );
        let err = Catalog::from_yaml(&upper).unwrap_err().to_string();
        assert!(err.contains("lowercase"), "got: {err}");
    }

    #[test]
    fn sha256_skips_files_over_size_cap() {
        // Build a catalog whose sha256 we'll never compute (the
        // file is > MAX_HASH_BYTES so the hasher short-circuits).
        // Match is by-basename in addition so the test is fast.
        let tmp = Tmp::new();
        // Write a small placeholder; we'll override MAX_HASH_BYTES
        // by checking the hash_file_capped helper directly because
        // 16 MiB writes would make the test slow.
        let f = tmp.0.join("payload");
        fs::write(&f, b"abc").unwrap();
        // 1-byte cap → 3-byte file is over the cap → returns None.
        assert!(hash_file_capped(&f, 1).is_none());
        // Plenty-large cap → hashes fine.
        let h = hash_file_capped(&f, 1024).expect("hash should succeed under the cap");
        assert_eq!(h.len(), 64);
    }

    /// Drives `default_override_path` with a known env state to
    /// exercise the resolution order without depending on the
    /// developer machine's real env. Each candidate gets `var` (set
    /// to a tmp value) or `remove`d for the test.
    ///
    /// `std::env::set_var` is process-global and `cargo test` runs
    /// these in parallel, so we serialise via a mutex.
    fn run_with_env(env: &[(&str, Option<&str>)], f: impl FnOnce()) {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let to_restore: Vec<(&str, Option<std::ffi::OsString>)> =
            env.iter().map(|(k, _)| (*k, std::env::var_os(k))).collect();
        for (k, v) in env {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, v) in to_restore {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
    }

    #[test]
    fn default_override_path_resolution_order() {
        // XDG wins when set.
        run_with_env(
            &[
                ("XDG_DATA_HOME", Some("/xdg")),
                ("HOME", Some("/home")),
                ("LOCALAPPDATA", Some("C:/la")),
                ("USERPROFILE", Some("C:/up")),
            ],
            || {
                assert_eq!(
                    default_override_path(),
                    Some(PathBuf::from("/xdg/sakimori/iocs.yml"))
                );
            },
        );
        // HOME wins over Windows vars when XDG is unset.
        run_with_env(
            &[
                ("XDG_DATA_HOME", None),
                ("HOME", Some("/home")),
                ("LOCALAPPDATA", Some("C:/la")),
                ("USERPROFILE", Some("C:/up")),
            ],
            || {
                assert_eq!(
                    default_override_path(),
                    Some(PathBuf::from("/home/.sakimori/iocs.yml"))
                );
            },
        );
        // Windows path: LOCALAPPDATA preferred over USERPROFILE.
        run_with_env(
            &[
                ("XDG_DATA_HOME", None),
                ("HOME", None),
                ("LOCALAPPDATA", Some("C:/la")),
                ("USERPROFILE", Some("C:/up")),
            ],
            || {
                assert_eq!(
                    default_override_path(),
                    Some(PathBuf::from("C:/la/sakimori/iocs.yml"))
                );
            },
        );
        // USERPROFILE last-resort.
        run_with_env(
            &[
                ("XDG_DATA_HOME", None),
                ("HOME", None),
                ("LOCALAPPDATA", None),
                ("USERPROFILE", Some("C:/up")),
            ],
            || {
                assert_eq!(
                    default_override_path(),
                    Some(PathBuf::from("C:/up/.sakimori/iocs.yml"))
                );
            },
        );
        // Nothing → None.
        run_with_env(
            &[
                ("XDG_DATA_HOME", None),
                ("HOME", None),
                ("LOCALAPPDATA", None),
                ("USERPROFILE", None),
            ],
            || {
                assert_eq!(default_override_path(), None);
            },
        );
    }

    #[test]
    fn load_with_fallback_uses_bundled_when_no_override() {
        let (cat, src) = Catalog::load_with_fallback(None);
        assert!(!cat.patterns.is_empty());
        assert!(matches!(src, LoadedFrom::Bundled));
    }

    #[test]
    fn load_with_fallback_uses_override_when_present() {
        let tmp = Tmp::new();
        let path = tmp.0.join("iocs.yml");
        fs::write(
            &path,
            "version: 42\npatterns:\n\
             - id: just-one\n  description: t\n  severity: warn\n  \
             match: {kind: basename, name: x}\n",
        )
        .unwrap();
        let (cat, src) = Catalog::load_with_fallback(Some(&path));
        assert_eq!(cat.version, 42);
        assert_eq!(cat.patterns.len(), 1);
        assert!(matches!(src, LoadedFrom::Override(p) if p == path));
    }

    #[test]
    fn load_with_fallback_falls_back_on_parse_error_and_surfaces_it() {
        // A corrupted override must not brick the scanner: bundled
        // must still load, and the error has to be visible in
        // LoadedFrom so the CLI can warn.
        let tmp = Tmp::new();
        let path = tmp.0.join("iocs.yml");
        fs::write(&path, "this: [is, not: valid yaml at all").unwrap();
        let (cat, src) = Catalog::load_with_fallback(Some(&path));
        assert!(!cat.patterns.is_empty(), "bundled fallback must populate");
        match src {
            LoadedFrom::BundledAfterOverrideError { path: p, error } => {
                assert_eq!(p, path);
                assert!(!error.is_empty());
            }
            other => panic!("expected BundledAfterOverrideError, got {other:?}"),
        }
    }

    #[test]
    fn update_from_writes_only_valid_upstream() {
        let tmp = Tmp::new();
        let dest = tmp.0.join("nested/iocs.yml"); // exercise mkdir
        let upstream = "version: 7\npatterns:\n\
                        - id: from-upstream\n  description: t\n  severity: error\n  \
                        match: {kind: basename, name: y.js}\n";
        let fetcher = FnFetcher(|_| Ok(upstream.to_string()));
        let cat = update_from(&fetcher, "https://example.invalid/iocs.yml", &dest).unwrap();
        assert_eq!(cat.version, 7);
        // File on disk matches what we fetched.
        let on_disk = fs::read_to_string(&dest).unwrap();
        assert_eq!(on_disk, upstream);
    }

    #[test]
    fn update_from_rejects_invalid_upstream_without_clobbering_existing() {
        // Pre-existing good override + a bad upstream → the override
        // is preserved untouched. This is the "don't trust the feed"
        // safety we documented in update_from.
        let tmp = Tmp::new();
        let dest = tmp.0.join("iocs.yml");
        let good = "version: 1\npatterns:\n\
                    - id: keep-me\n  description: t\n  severity: warn\n  \
                    match: {kind: basename, name: a}\n";
        fs::write(&dest, good).unwrap();

        let fetcher = FnFetcher(|_| Ok("this is not yaml: : :".to_string()));
        let err = update_from(&fetcher, "https://example.invalid", &dest).unwrap_err();
        // Either the YAML parser or the sha256 validator should refuse it.
        assert!(format!("{err:#}").contains("validate") || format!("{err:#}").contains("parsing"));

        // Original file is intact (atomic write means we never touched
        // it because validation failed before the tempfile was renamed).
        let after = fs::read_to_string(&dest).unwrap();
        assert_eq!(after, good, "valid override must survive a failed update");
    }

    #[test]
    fn update_from_surfaces_fetcher_errors() {
        let tmp = Tmp::new();
        let dest = tmp.0.join("iocs.yml");
        let fetcher = FnFetcher(|_| Err(anyhow::anyhow!("network down")));
        let err = update_from(&fetcher, "https://x", &dest).unwrap_err();
        assert!(format!("{err:#}").contains("network down"));
        assert!(!dest.exists(), "no file should be written on fetch failure");
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

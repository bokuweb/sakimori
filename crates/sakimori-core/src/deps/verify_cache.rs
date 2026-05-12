//! Cache integrity verifier — re-hash the package manager's local
//! cache against the lockfile's `integrity:` fields before install.
//!
//! Threat model: an attacker poisons a content-addressed store (most
//! commonly via the GitHub Actions cache, à la TanStack 2025) by
//! restoring tampered bytes into a path the package manager will
//! trust. Lockfiles ship SRI-style integrity hashes per resolved
//! `(name, version)`; this module re-hashes every store entry the
//! lockfile names and reports mismatches before install runs.
//!
//! Supported stores:
//!
//! - **npm cacache** (`package-lock.json`): each blob's filename is
//!   the hex digest of its content under `<cache>/content-v2/
//!   <algo>/<aa>/<bb>/<rest>`. Verification is "re-hash file, compare
//!   to lockfile integrity".
//! - **pnpm store v3** (`pnpm-lock.yaml`): the lockfile carries the
//!   *tarball* SRI; on disk that keys a `<store>/v3/files/<aa>/<rest>-index.json`
//!   whose entries enumerate per-file integrity + mode pairs. We
//!   walk the index and re-hash every blob (`<rest>` or `<rest>-exec`
//!   depending on mode bits). Honest weakness: a fully coordinated
//!   rewrite of both the index and every blob it references would
//!   verify clean — we can't re-derive the tarball hash without the
//!   .tgz, which pnpm discards. Catches realistic single-file
//!   tampering. pnpm v10's SQLite `index.db` layout is not yet
//!   supported.
//! - **cargo registry** (`Cargo.lock`): each `[[package]]` from a
//!   registry source carries `checksum = "<hex>"` — SHA-256 of the
//!   `.crate` tarball. We hash `<cargo_home>/registry/cache/<reg>/<name>-<version>.crate`
//!   and compare. Cargo itself re-verifies per-file hashes at build
//!   time via `.cargo-checksum.json`, so the tarball check is the
//!   bit that adds defence against cache-layer tampering.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use sha2::Digest;

/// A `(name, version, integrity)` triple extracted from a lockfile.
/// `integrity` is the raw SRI value as written in the lockfile
/// (e.g. `sha512-AAAA...==`). Multi-algo strings are accepted by
/// the parser but only the first algorithm is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityEntry {
    pub name: String,
    pub version: String,
    pub integrity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok,
    Missing,
    Mismatch,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageVerdict {
    pub name: String,
    pub version: String,
    pub outcome: Outcome,
    /// Absolute path the verifier expected to find. `None` when the
    /// integrity string was unparseable — in that case `outcome` is
    /// `Unsupported` and `message` carries the reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_path: Option<PathBuf>,
    /// On `Mismatch`: the SHA the lockfile claimed (hex, lowercase).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha_hex: Option<String>,
    /// On `Mismatch`: the SHA we computed from the on-disk bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_sha_hex: Option<String>,
    /// Free-form context: "unsupported algo `sha1`", IO errors, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifyReport {
    pub checked: usize,
    pub ok: usize,
    pub missing: usize,
    pub mismatched: usize,
    pub unsupported: usize,
    pub packages: Vec<PackageVerdict>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.mismatched == 0 && self.missing == 0
    }
}

/// Verify every entry against an npm cacache store rooted at `root`.
/// Typical root: `~/.npm/_cacache`. The verifier does **not** require
/// every cache entry to be in the lockfile — it only checks the
/// other direction (lockfile claims must match what's on disk). A
/// poisoned cache that adds *new* entries is detected at install
/// time by npm's own integrity check, not here.
pub fn verify_npm_cacache(entries: &[IntegrityEntry], root: &Path) -> VerifyReport {
    let mut report = VerifyReport::default();
    for entry in entries {
        let verdict = verify_one_npm(entry, root);
        match verdict.outcome {
            Outcome::Ok => report.ok += 1,
            Outcome::Missing => report.missing += 1,
            Outcome::Mismatch => report.mismatched += 1,
            Outcome::Unsupported => report.unsupported += 1,
        }
        report.checked += 1;
        report.packages.push(verdict);
    }
    report
}

fn verify_one_npm(entry: &IntegrityEntry, root: &Path) -> PackageVerdict {
    let parsed = match parse_sri(&entry.integrity) {
        Ok(p) => p,
        Err(msg) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: None,
                expected_sha_hex: None,
                actual_sha_hex: None,
                message: Some(msg),
            };
        }
    };
    let path = cacache_path(root, &parsed);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Missing,
                cache_path: Some(path),
                expected_sha_hex: Some(hex(&parsed.digest)),
                actual_sha_hex: None,
                message: None,
            };
        }
        Err(e) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: Some(path),
                expected_sha_hex: Some(hex(&parsed.digest)),
                actual_sha_hex: None,
                message: Some(format!("read failed: {e}")),
            };
        }
    };
    let actual = hash_with(parsed.algo, &bytes);
    if actual == parsed.digest {
        PackageVerdict {
            name: entry.name.clone(),
            version: entry.version.clone(),
            outcome: Outcome::Ok,
            cache_path: Some(path),
            expected_sha_hex: None,
            actual_sha_hex: None,
            message: None,
        }
    } else {
        PackageVerdict {
            name: entry.name.clone(),
            version: entry.version.clone(),
            outcome: Outcome::Mismatch,
            cache_path: Some(path),
            expected_sha_hex: Some(hex(&parsed.digest)),
            actual_sha_hex: Some(hex(&actual)),
            message: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    Sha256,
    Sha512,
}

impl Algo {
    fn dir_name(self) -> &'static str {
        match self {
            Algo::Sha256 => "sha256",
            Algo::Sha512 => "sha512",
        }
    }
}

#[derive(Debug)]
struct ParsedSri {
    algo: Algo,
    digest: Vec<u8>,
}

/// Parse a Subresource Integrity string. The lockfile form is
/// `<algo>-<base64-padded>`; multi-algo strings (space-separated)
/// pick the first recognised value. Returns a stable error message
/// when nothing matches — callers surface it as `Unsupported`.
fn parse_sri(sri: &str) -> Result<ParsedSri, String> {
    for token in sri.split_whitespace() {
        let Some((algo_s, b64)) = token.split_once('-') else {
            continue;
        };
        let algo = match algo_s {
            "sha512" => Algo::Sha512,
            "sha256" => Algo::Sha256,
            _ => continue,
        };
        let digest = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| format!("base64 decode of `{token}` failed: {e}"))?;
        let want_len = match algo {
            Algo::Sha256 => 32,
            Algo::Sha512 => 64,
        };
        if digest.len() != want_len {
            return Err(format!(
                "{algo_s} digest length {} != {want_len}",
                digest.len()
            ));
        }
        return Ok(ParsedSri { algo, digest });
    }
    Err(format!(
        "no supported algorithm in integrity `{sri}` (need sha256 or sha512)"
    ))
}

/// cacache content-v2 layout: `<root>/content-v2/<algo>/<aa>/<bb>/<rest>`
/// where `aa`/`bb` are the first two pairs of hex chars and `rest`
/// is the remainder of the lower-case hex digest. Mirrors what
/// `@npmcli/cacache` writes on Linux/macOS/Windows alike.
fn cacache_path(root: &Path, parsed: &ParsedSri) -> PathBuf {
    let hex = hex(&parsed.digest);
    let (aa, rest) = hex.split_at(2);
    let (bb, rest) = rest.split_at(2);
    root.join("content-v2")
        .join(parsed.algo.dir_name())
        .join(aa)
        .join(bb)
        .join(rest)
}

fn hash_with(algo: Algo, bytes: &[u8]) -> Vec<u8> {
    match algo {
        Algo::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
        Algo::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Extract `(name, version, integrity)` triples from an npm
/// `package-lock.json` (lockfileVersion >= 2). Entries with no
/// integrity field (workspace links, git/file deps, or anything
/// pre-resolved to a non-registry URL) are skipped — they can't be
/// verified against a content-addressed store anyway.
pub fn npm_integrity_entries(path: &Path) -> Result<Vec<IntegrityEntry>> {
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Lock {
        #[serde(rename = "lockfileVersion")]
        version: u32,
        #[serde(default)]
        packages: std::collections::BTreeMap<String, PkgEntry>,
    }
    #[derive(Deserialize)]
    struct PkgEntry {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        integrity: Option<String>,
        #[serde(default)]
        link: bool,
    }

    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as package-lock.json", path.display()))?;
    if lock.version < 2 {
        anyhow::bail!("lockfileVersion={} not supported (need >=2)", lock.version);
    }
    let mut out = Vec::new();
    for (key, e) in &lock.packages {
        if key.is_empty() || e.link {
            continue;
        }
        let (Some(version), Some(integrity)) = (e.version.as_deref(), e.integrity.as_deref())
        else {
            continue;
        };
        let name = e
            .name
            .clone()
            .or_else(|| name_from_key(key))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(IntegrityEntry {
            name,
            version: version.to_string(),
            integrity: integrity.to_string(),
        });
    }
    Ok(out)
}

fn name_from_key(key: &str) -> Option<String> {
    let last = key.rsplit("node_modules/").next()?;
    if last.is_empty() {
        return None;
    }
    Some(last.trim_end_matches('/').to_string())
}

// --- pnpm store v3 -------------------------------------------------------
//
// Verification chain (per package):
//   lockfile `resolution.integrity` (tarball SRI, base64 SHA-512)
//     → hex decode (128 chars)
//     → `<store>/v3/files/<aa>/<rest>-index.json`  (per-tarball index)
//     → for each file entry { integrity, mode }:
//        per-file SRI → hex → `<store>/v3/files/<aa>/<rest>[-exec]`
//        → re-hash and compare
//
// Weakness vs perfect tampering: we cannot re-derive the tarball hash
// from the extracted files (the tarball is not on disk), so a fully
// coordinated rewrite of both the index.json and every blob it points
// at would verify clean. We catch the realistic cache-poisoning
// pattern — bytes of one blob swapped without index update.

/// Extract `(name, version, integrity)` triples from a
/// `pnpm-lock.yaml`. The integrity here is the **tarball** SRI as
/// recorded under `packages.<spec>.resolution.integrity`. Entries
/// without an integrity field (git deps, link: deps, workspace
/// projects) are skipped.
pub fn pnpm_integrity_entries(path: &Path) -> Result<Vec<IntegrityEntry>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as YAML", path.display()))?;
    let packages = doc
        .get("packages")
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| anyhow::anyhow!("no `packages:` block in {}", path.display()))?;

    let mut out = Vec::new();
    for (spec_key, pkg_val) in packages {
        let Some(spec) = spec_key.as_str() else {
            continue;
        };
        let Some(pkg_map) = pkg_val.as_mapping() else {
            continue;
        };
        // v6-v8: `resolution.integrity`. Some entries may carry
        // `resolution.type: 'git'|'directory'` and no integrity.
        let integrity = pkg_map
            .get(serde_yaml::Value::String("resolution".into()))
            .and_then(|v| v.as_mapping())
            .and_then(|res| res.get(serde_yaml::Value::String("integrity".into())))
            .and_then(|v| v.as_str());
        let Some(integrity) = integrity else {
            continue;
        };
        let Some((name, version)) = parse_pnpm_spec(spec) else {
            continue;
        };
        out.push(IntegrityEntry {
            name,
            version,
            integrity: integrity.to_string(),
        });
    }
    Ok(out)
}

/// Parse a pnpm lockfile package spec to `(name, version)`. Handles
/// both pnpm v6–v8 (`/foo/1.2.3` or `/@scope/bar/1.2.3`) and pnpm v9
/// (`foo@1.2.3` or `@scope/bar@1.2.3`). Peer-deps suffixes are
/// stripped from the *version* portion only — package names can
/// legally contain `_`, so we cannot strip them spec-wide.
fn parse_pnpm_spec(spec: &str) -> Option<(String, String)> {
    // pnpm v6-v8: leading slash, name/version separated by the last `/`.
    if let Some(rest) = spec.strip_prefix('/') {
        let (name, ver_full) = rest.rsplit_once('/')?;
        let version = strip_peer_suffix_from_version(ver_full);
        if name.is_empty() || version.is_empty() {
            return None;
        }
        return Some((name.to_string(), version.to_string()));
    }
    // pnpm v9: `name@1.2.3[(peer@ver)...]`. Drop the parenthesised
    // peer-deps annotation first; the remaining string has the
    // version-separating `@` as the only `@` past position 0
    // (a leading `@` would belong to the scope prefix).
    let core = spec.split('(').next().unwrap_or(spec);
    let bytes = core.as_bytes();
    let split = (1..bytes.len()).find(|&i| bytes[i] == b'@')?;
    let name = &core[..split];
    let version = &core[split + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Trim pnpm's peer-deps annotations from a version segment. Both
/// the v8 form (`1.2.3_react@18.0.0`) and the v9 form
/// (`1.2.3(react@18.0.0)`) are unambiguous here because a semver
/// version never contains `_` or `(`.
fn strip_peer_suffix_from_version(ver: &str) -> String {
    ver.split(['_', '(']).next().unwrap_or(ver).to_string()
}

/// Verify every entry against a pnpm store v3 rooted at `store_root`.
/// Typical roots:
///   Linux:   `~/.local/share/pnpm/store/v3`
///   macOS:   `~/Library/pnpm/store/v3`
///   Windows: `~/AppData/Local/pnpm/store/v3`
///
/// Caller passes the full path including the `v3` segment.
///
/// pnpm v10 replaced per-package `<rest>-index.json` files with a
/// single SQLite database at `<store>/index.db`. We detect that
/// layout and short-circuit every entry to `Unsupported` with a
/// pointed message rather than silently reporting everything as
/// missing — the user gets an actionable error instead of a false
/// negative.
pub fn verify_pnpm_store(entries: &[IntegrityEntry], store_root: &Path) -> VerifyReport {
    let mut report = VerifyReport::default();

    if is_pnpm_v10_store(store_root) {
        for entry in entries {
            report.unsupported += 1;
            report.checked += 1;
            report.packages.push(PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: Some(store_root.join("index.db")),
                expected_sha_hex: None,
                actual_sha_hex: None,
                message: Some(
                    "pnpm v10 SQLite store (`index.db`) not yet supported — see CLAUDE.md \
                     roadmap #14. Re-run against a pnpm v8/v9 store or pin pnpm to <10."
                        .into(),
                ),
            });
        }
        return report;
    }

    for entry in entries {
        let verdict = verify_one_pnpm(entry, store_root);
        match verdict.outcome {
            Outcome::Ok => report.ok += 1,
            Outcome::Missing => report.missing += 1,
            Outcome::Mismatch => report.mismatched += 1,
            Outcome::Unsupported => report.unsupported += 1,
        }
        report.checked += 1;
        report.packages.push(verdict);
    }
    report
}

fn verify_one_pnpm(entry: &IntegrityEntry, store_root: &Path) -> PackageVerdict {
    let parsed = match parse_sri(&entry.integrity) {
        Ok(p) => p,
        Err(msg) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: None,
                expected_sha_hex: None,
                actual_sha_hex: None,
                message: Some(msg),
            };
        }
    };
    let index_path = pnpm_index_path(store_root, &parsed);
    let index_bytes = match std::fs::read(&index_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Missing,
                cache_path: Some(index_path),
                expected_sha_hex: Some(hex(&parsed.digest)),
                actual_sha_hex: None,
                message: Some("index.json not present in store".into()),
            };
        }
        Err(e) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: Some(index_path),
                expected_sha_hex: Some(hex(&parsed.digest)),
                actual_sha_hex: None,
                message: Some(format!("read failed: {e}")),
            };
        }
    };
    let index: PackageFilesIndex = match serde_json::from_slice(&index_bytes) {
        Ok(i) => i,
        Err(e) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: Some(index_path),
                expected_sha_hex: Some(hex(&parsed.digest)),
                actual_sha_hex: None,
                message: Some(format!("malformed index.json: {e}")),
            };
        }
    };

    // Walk every file entry; first failure wins.
    for (file_path, info) in &index.files {
        let per_file = match verify_pnpm_file(store_root, file_path, info) {
            Ok(()) => continue,
            Err(v) => v,
        };
        return PackageVerdict {
            name: entry.name.clone(),
            version: entry.version.clone(),
            outcome: per_file.outcome,
            cache_path: Some(per_file.path),
            expected_sha_hex: per_file.expected_hex,
            actual_sha_hex: per_file.actual_hex,
            message: Some(per_file.message),
        };
    }

    PackageVerdict {
        name: entry.name.clone(),
        version: entry.version.clone(),
        outcome: Outcome::Ok,
        cache_path: Some(index_path),
        expected_sha_hex: None,
        actual_sha_hex: None,
        message: None,
    }
}

#[derive(serde::Deserialize)]
struct PackageFilesIndex {
    #[serde(default)]
    files: std::collections::BTreeMap<String, PackageFileInfo>,
}

#[derive(serde::Deserialize)]
struct PackageFileInfo {
    integrity: String,
    /// POSIX mode bits. Executable iff `mode & 0o111 != 0`.
    mode: u32,
}

struct PerFileFailure {
    outcome: Outcome,
    path: PathBuf,
    expected_hex: Option<String>,
    actual_hex: Option<String>,
    message: String,
}

fn verify_pnpm_file(
    store_root: &Path,
    rel_path: &str,
    info: &PackageFileInfo,
) -> Result<(), PerFileFailure> {
    let parsed = match parse_sri(&info.integrity) {
        Ok(p) => p,
        Err(msg) => {
            return Err(PerFileFailure {
                outcome: Outcome::Unsupported,
                path: PathBuf::from(rel_path),
                expected_hex: None,
                actual_hex: None,
                message: format!("file `{rel_path}`: {msg}"),
            });
        }
    };
    let path = pnpm_blob_path(store_root, &parsed, info.mode);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PerFileFailure {
                outcome: Outcome::Missing,
                path,
                expected_hex: Some(hex(&parsed.digest)),
                actual_hex: None,
                message: format!("file `{rel_path}` missing in store"),
            });
        }
        Err(e) => {
            return Err(PerFileFailure {
                outcome: Outcome::Unsupported,
                path,
                expected_hex: Some(hex(&parsed.digest)),
                actual_hex: None,
                message: format!("file `{rel_path}` read failed: {e}"),
            });
        }
    };
    let actual = hash_with(parsed.algo, &bytes);
    if actual == parsed.digest {
        Ok(())
    } else {
        Err(PerFileFailure {
            outcome: Outcome::Mismatch,
            path,
            expected_hex: Some(hex(&parsed.digest)),
            actual_hex: Some(hex(&actual)),
            message: format!("file `{rel_path}` bytes don't match claimed integrity"),
        })
    }
}

/// Heuristic: pnpm v10 writes `<store>/index.db` (SQLite) and stops
/// writing the per-package `<rest>-index.json` files. The presence
/// of `index.db` is a strong-enough signal — pnpm v8/v9 never write
/// it. We don't try to detect mixed stores; a user mid-migration
/// should pass `--cache` explicitly to a known-good store.
fn is_pnpm_v10_store(store_root: &Path) -> bool {
    store_root.join("index.db").is_file()
}

fn pnpm_index_path(store_root: &Path, parsed: &ParsedSri) -> PathBuf {
    let hex = hex(&parsed.digest);
    let (aa, rest) = hex.split_at(2);
    store_root
        .join("files")
        .join(aa)
        .join(format!("{rest}-index.json"))
}

fn pnpm_blob_path(store_root: &Path, parsed: &ParsedSri, mode: u32) -> PathBuf {
    let hex = hex(&parsed.digest);
    let (aa, rest) = hex.split_at(2);
    let name = if mode & 0o111 != 0 {
        format!("{rest}-exec")
    } else {
        rest.to_string()
    };
    store_root.join("files").join(aa).join(name)
}

// --- cargo registry cache -----------------------------------------------
//
// Verification chain (per crate):
//   Cargo.lock `[[package]] checksum = "<hex>"`  (SHA-256 of the .crate)
//     → find `<cargo_home>/registry/cache/<reg>/<name>-<version>.crate`
//     → SHA-256 the bytes
//     → compare to lockfile checksum
//
// Cargo also writes a per-crate `.cargo-checksum.json` under
// `src/<reg>/<name>-<version>/` that lists per-file hashes — but cargo
// itself re-verifies those on every build, so duplicating that here
// would only repeat the existing defence. The .crate tarball check
// catches the *cache* attack: someone replaces a tarball under
// `cache/` while leaving lockfile/index alone. That's the equivalent
// of the TanStack vector for cargo.

/// Parse a `Cargo.lock` and extract `(name, version, checksum)`
/// triples for every registry package. Git / path / replaced
/// packages have no `checksum` field and are skipped — they're not
/// reachable from the registry cache anyway.
pub fn cargo_integrity_entries(lockfile: &Path) -> Result<Vec<IntegrityEntry>> {
    let text = std::fs::read_to_string(lockfile)
        .with_context(|| format!("reading {}", lockfile.display()))?;
    let doc: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing {} as TOML", lockfile.display()))?;
    let packages = doc
        .get("package")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("no [[package]] entries in {}", lockfile.display()))?;
    let mut out = Vec::new();
    for pkg in packages {
        let Some(t) = pkg.as_table() else {
            continue;
        };
        let (Some(name), Some(version), Some(checksum)) = (
            t.get("name").and_then(|v| v.as_str()),
            t.get("version").and_then(|v| v.as_str()),
            t.get("checksum").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        out.push(IntegrityEntry {
            name: name.to_string(),
            version: version.to_string(),
            // Stash the bare hex string; the cargo verifier handles
            // it directly rather than routing through `parse_sri`.
            integrity: checksum.to_string(),
        });
    }
    Ok(out)
}

/// Verify every entry against the cargo registry cache under
/// `cargo_home` (typically `~/.cargo`). The verifier walks every
/// `registry/cache/<reg>/` subdirectory and looks for
/// `<name>-<version>.crate`; the registry subdir name has an opaque
/// suffix hash (e.g. `index.crates.io-<8-byte-hex>`) so we don't
/// hard-code it.
///
/// Strongest single check: SHA-256 of the .crate must equal the
/// lockfile's `checksum`. Cargo itself does per-file verification
/// against `.cargo-checksum.json` at build time, so we don't repeat
/// that — replicating it would catch nothing cargo doesn't already.
pub fn verify_cargo_registry(entries: &[IntegrityEntry], cargo_home: &Path) -> VerifyReport {
    let mut report = VerifyReport::default();

    // Enumerate registry cache subdirs once. Multiple registries
    // (crates.io sparse + legacy git + alt registries) can coexist.
    let cache_root = cargo_home.join("registry").join("cache");
    let reg_dirs: Vec<PathBuf> = std::fs::read_dir(&cache_root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();

    for entry in entries {
        let verdict = verify_one_cargo(entry, &reg_dirs);
        match verdict.outcome {
            Outcome::Ok => report.ok += 1,
            Outcome::Missing => report.missing += 1,
            Outcome::Mismatch => report.mismatched += 1,
            Outcome::Unsupported => report.unsupported += 1,
        }
        report.checked += 1;
        report.packages.push(verdict);
    }
    report
}

fn verify_one_cargo(entry: &IntegrityEntry, reg_dirs: &[PathBuf]) -> PackageVerdict {
    // Cargo.lock stores raw lowercase hex SHA-256. Validate shape
    // before hashing anything.
    let expected = match decode_cargo_checksum(&entry.integrity) {
        Ok(b) => b,
        Err(msg) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: None,
                expected_sha_hex: None,
                actual_sha_hex: None,
                message: Some(msg),
            };
        }
    };

    let filename = format!("{}-{}.crate", entry.name, entry.version);
    let mut found_path: Option<PathBuf> = None;
    for reg in reg_dirs {
        let candidate = reg.join(&filename);
        if candidate.is_file() {
            found_path = Some(candidate);
            break;
        }
    }
    let Some(path) = found_path else {
        return PackageVerdict {
            name: entry.name.clone(),
            version: entry.version.clone(),
            outcome: Outcome::Missing,
            cache_path: Some(PathBuf::from(filename)),
            expected_sha_hex: Some(entry.integrity.to_ascii_lowercase()),
            actual_sha_hex: None,
            message: Some("no `<name>-<version>.crate` under registry/cache/*".into()),
        };
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return PackageVerdict {
                name: entry.name.clone(),
                version: entry.version.clone(),
                outcome: Outcome::Unsupported,
                cache_path: Some(path),
                expected_sha_hex: Some(entry.integrity.to_ascii_lowercase()),
                actual_sha_hex: None,
                message: Some(format!("read failed: {e}")),
            };
        }
    };
    let actual = sha2::Sha256::digest(&bytes).to_vec();
    if actual == expected {
        PackageVerdict {
            name: entry.name.clone(),
            version: entry.version.clone(),
            outcome: Outcome::Ok,
            cache_path: Some(path),
            expected_sha_hex: None,
            actual_sha_hex: None,
            message: None,
        }
    } else {
        PackageVerdict {
            name: entry.name.clone(),
            version: entry.version.clone(),
            outcome: Outcome::Mismatch,
            cache_path: Some(path),
            expected_sha_hex: Some(hex(&expected)),
            actual_sha_hex: Some(hex(&actual)),
            message: None,
        }
    }
}

fn decode_cargo_checksum(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!(
            "expected 64-char SHA-256 hex, got {}-char `{s}`",
            s.len()
        ));
    }
    let mut out = Vec::with_capacity(32);
    let mut iter = s.as_bytes().chunks_exact(2);
    for pair in iter.by_ref() {
        let hi = hex_digit(pair[0]).ok_or_else(|| format!("non-hex char in `{s}`"))?;
        let lo = hex_digit(pair[1]).ok_or_else(|| format!("non-hex char in `{s}`"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(tag: &str) -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sakimori-verify-{tag}-{id}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Write `bytes` into the cacache layout under `root` and return
    /// (path, sri-string). Caller picks the algo via `algo_dir`.
    fn write_cacache_blob(root: &Path, bytes: &[u8]) -> (PathBuf, String) {
        let digest = sha2::Sha512::digest(bytes);
        let hex_digest = super::hex(&digest);
        let (aa, rest) = hex_digest.split_at(2);
        let (bb, rest) = rest.split_at(2);
        let path = root
            .join("content-v2")
            .join("sha512")
            .join(aa)
            .join(bb)
            .join(rest);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        (path, format!("sha512-{b64}"))
    }

    #[test]
    fn parse_sri_decodes_sha512_b64() {
        let bytes = b"hello world";
        let digest = sha2::Sha512::digest(bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        let p = parse_sri(&format!("sha512-{b64}")).unwrap();
        assert_eq!(p.algo, Algo::Sha512);
        assert_eq!(p.digest, digest.as_slice());
    }

    #[test]
    fn parse_sri_picks_first_known_algo_from_multi() {
        // SRI strings can list multiple algorithms space-separated.
        // We pick the first one we recognise.
        let bytes = b"x";
        let s512 = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes));
        let multi = format!("sha1-deadbeef sha512-{s512}");
        let p = parse_sri(&multi).unwrap();
        assert_eq!(p.algo, Algo::Sha512);
    }

    #[test]
    fn parse_sri_rejects_unknown_algo() {
        let err = parse_sri("md5-abc").unwrap_err();
        assert!(err.contains("no supported algorithm"));
    }

    #[test]
    fn cacache_path_shards_hex_into_aa_bb_rest() {
        let parsed = ParsedSri {
            algo: Algo::Sha512,
            // 64 bytes; first 4 bytes = 0xaa 0xbb 0xcc 0xdd
            digest: {
                let mut v = vec![0xaa, 0xbb, 0xcc, 0xdd];
                v.extend(std::iter::repeat_n(0u8, 60));
                v
            },
        };
        let p = cacache_path(Path::new("/tmp/root"), &parsed);
        let expected =
            Path::new("/tmp/root/content-v2/sha512/aa/bb").join(format!("ccdd{}", "00".repeat(60)));
        assert_eq!(p, expected);
    }

    #[test]
    fn verify_returns_ok_for_matching_blob() {
        let root = tmpdir("ok");
        let bytes = b"tarball bytes pretending to be a real package";
        let (path, sri) = write_cacache_blob(&root, bytes);
        let entries = vec![IntegrityEntry {
            name: "foo".into(),
            version: "1.2.3".into(),
            integrity: sri,
        }];
        let report = verify_npm_cacache(&entries, &root);
        assert!(report.is_clean(), "{report:#?}");
        assert_eq!(report.ok, 1);
        assert_eq!(report.packages[0].outcome, Outcome::Ok);
        assert_eq!(
            report.packages[0].cache_path.as_deref(),
            Some(path.as_path())
        );
    }

    #[test]
    fn verify_flags_mismatch_when_blob_was_tampered() {
        // This is the headline case: cache restored from GHA cache
        // poisoning contains attacker bytes, not the bytes the
        // lockfile pinned.
        let root = tmpdir("mismatch");
        let original = b"legit package contents";
        let (path, sri) = write_cacache_blob(&root, original);
        // Overwrite in place with tampered bytes.
        std::fs::write(&path, b"// attacker payload").unwrap();
        let entries = vec![IntegrityEntry {
            name: "foo".into(),
            version: "1.0.0".into(),
            integrity: sri,
        }];
        let report = verify_npm_cacache(&entries, &root);
        assert!(!report.is_clean());
        assert_eq!(report.mismatched, 1);
        let v = &report.packages[0];
        assert_eq!(v.outcome, Outcome::Mismatch);
        assert!(v.expected_sha_hex.is_some());
        assert!(v.actual_sha_hex.is_some());
        assert_ne!(v.expected_sha_hex, v.actual_sha_hex);
    }

    #[test]
    fn verify_flags_missing_when_blob_absent() {
        let root = tmpdir("missing");
        // Don't write anything — just claim a hash exists.
        let bytes = b"never written";
        let digest = sha2::Sha512::digest(bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        let entries = vec![IntegrityEntry {
            name: "ghost".into(),
            version: "0.0.0".into(),
            integrity: format!("sha512-{b64}"),
        }];
        let report = verify_npm_cacache(&entries, &root);
        assert_eq!(report.missing, 1);
        assert_eq!(report.packages[0].outcome, Outcome::Missing);
    }

    #[test]
    fn verify_marks_unsupported_when_sri_unparseable() {
        let root = tmpdir("unsupported");
        let entries = vec![IntegrityEntry {
            name: "weird".into(),
            version: "1.0.0".into(),
            integrity: "md5-abcdef==".into(),
        }];
        let report = verify_npm_cacache(&entries, &root);
        assert_eq!(report.unsupported, 1);
        assert_eq!(report.packages[0].outcome, Outcome::Unsupported);
        assert!(
            report.packages[0]
                .message
                .as_deref()
                .unwrap()
                .contains("no supported algorithm")
        );
    }

    #[test]
    fn verify_aggregates_mixed_outcomes_into_one_report() {
        let root = tmpdir("mixed");
        let good = b"good";
        let (_, sri_good) = write_cacache_blob(&root, good);

        let bad = b"original";
        let (bad_path, sri_bad) = write_cacache_blob(&root, bad);
        std::fs::write(&bad_path, b"poisoned").unwrap();

        let missing = b"never written";
        let missing_digest = sha2::Sha512::digest(missing);
        let missing_b64 = base64::engine::general_purpose::STANDARD.encode(missing_digest);

        let entries = vec![
            IntegrityEntry {
                name: "good".into(),
                version: "1".into(),
                integrity: sri_good,
            },
            IntegrityEntry {
                name: "bad".into(),
                version: "1".into(),
                integrity: sri_bad,
            },
            IntegrityEntry {
                name: "missing".into(),
                version: "1".into(),
                integrity: format!("sha512-{missing_b64}"),
            },
        ];
        let report = verify_npm_cacache(&entries, &root);
        assert_eq!(report.checked, 3);
        assert_eq!(report.ok, 1);
        assert_eq!(report.mismatched, 1);
        assert_eq!(report.missing, 1);
        assert!(!report.is_clean());
    }

    #[test]
    fn npm_integrity_entries_extracts_name_version_integrity() {
        let body = r#"{
  "name":"x","version":"0","lockfileVersion":3,"requires":true,
  "packages":{
    "":{"name":"x","version":"0"},
    "node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-AAAA"},
    "node_modules/@scope/pkg":{"version":"1.2.3","resolved":"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz","integrity":"sha512-BBBB"},
    "node_modules/git-dep":{"version":"0.0.1","resolved":"git+https://github.com/x/y.git"},
    "packages/ws":{"link":true}
  }
}"#;
        let dir = tmpdir("npm-entries");
        let p = dir.join("package-lock.json");
        std::fs::write(&p, body).unwrap();
        let mut got = npm_integrity_entries(&p).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "@scope/pkg");
        assert_eq!(got[0].integrity, "sha512-BBBB");
        assert_eq!(got[1].name, "lodash");
        assert_eq!(got[1].version, "4.17.21");
    }

    // --- pnpm-specific tests ---------------------------------------------

    #[test]
    fn parse_pnpm_spec_handles_v6_v8_slash_form() {
        assert_eq!(
            parse_pnpm_spec("/lodash/4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            parse_pnpm_spec("/@scope/pkg/1.2.3"),
            Some(("@scope/pkg".into(), "1.2.3".into()))
        );
    }

    #[test]
    fn parse_pnpm_spec_handles_v9_at_form() {
        assert_eq!(
            parse_pnpm_spec("lodash@4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            parse_pnpm_spec("@scope/pkg@1.2.3"),
            Some(("@scope/pkg".into(), "1.2.3".into()))
        );
    }

    #[test]
    fn parse_pnpm_spec_strips_peer_dep_suffixes() {
        // v9 paren form
        assert_eq!(
            parse_pnpm_spec("react-dom@18.2.0(react@18.2.0)"),
            Some(("react-dom".into(), "18.2.0".into()))
        );
        // v8 underscore form, slash-prefixed
        assert_eq!(
            parse_pnpm_spec("/foo/1.0.0_bar@2.0.0"),
            Some(("foo".into(), "1.0.0".into()))
        );
    }

    /// Write a file into the pnpm CAS at the right path for its
    /// content + mode and return (path, SRI string).
    fn write_pnpm_blob(store_root: &Path, bytes: &[u8], mode: u32) -> (PathBuf, String) {
        let digest = sha2::Sha512::digest(bytes);
        let hex_d = super::hex(&digest);
        let (aa, rest) = hex_d.split_at(2);
        let name = if mode & 0o111 != 0 {
            format!("{rest}-exec")
        } else {
            rest.to_string()
        };
        let path = store_root.join("files").join(aa).join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        (path, format!("sha512-{b64}"))
    }

    /// Write a fabricated tarball-index.json into the CAS at the
    /// path keyed by `tarball_sri`. Returns the index path.
    fn write_pnpm_index(
        store_root: &Path,
        tarball_sri: &str,
        files: &[(&str, &str, u32)],
    ) -> PathBuf {
        let parsed = parse_sri(tarball_sri).unwrap();
        let path = pnpm_index_path(store_root, &parsed);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut obj = serde_json::Map::new();
        let mut files_obj = serde_json::Map::new();
        for (rel, integrity, mode) in files {
            files_obj.insert(
                (*rel).into(),
                serde_json::json!({
                    "integrity": integrity,
                    "mode": mode,
                    "size": 0,
                }),
            );
        }
        obj.insert("files".into(), serde_json::Value::Object(files_obj));
        std::fs::write(&path, serde_json::to_vec(&obj).unwrap()).unwrap();
        path
    }

    /// Build a fake tarball SRI from arbitrary bytes — pnpm verifier
    /// only uses it as the index-file lookup key, so any unique
    /// SHA-512 will do.
    fn fake_tarball_sri(label: &[u8]) -> String {
        let d = sha2::Sha512::digest(label);
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(d)
        )
    }

    #[test]
    fn verify_pnpm_store_ok_when_all_blobs_match() {
        let root = tmpdir("pnpm-ok");
        let pkg_json = b"{\"name\":\"foo\",\"version\":\"1.0.0\"}";
        let (_, pkg_sri) = write_pnpm_blob(&root, pkg_json, 0o644);
        let index_js = b"module.exports = 1";
        let (_, idx_sri) = write_pnpm_blob(&root, index_js, 0o644);

        let tarball_sri = fake_tarball_sri(b"foo-1.0.0");
        write_pnpm_index(
            &root,
            &tarball_sri,
            &[
                ("package.json", &pkg_sri, 0o644),
                ("index.js", &idx_sri, 0o644),
            ],
        );

        let entries = vec![IntegrityEntry {
            name: "foo".into(),
            version: "1.0.0".into(),
            integrity: tarball_sri,
        }];
        let report = verify_pnpm_store(&entries, &root);
        assert!(report.is_clean(), "{report:#?}");
        assert_eq!(report.ok, 1);
    }

    #[test]
    fn verify_pnpm_store_detects_tampered_blob() {
        // This is the headline case: cache restored a poisoned file,
        // its bytes no longer hash to the per-file integrity claim.
        let root = tmpdir("pnpm-tamper");
        let original = b"original code";
        let (blob_path, blob_sri) = write_pnpm_blob(&root, original, 0o644);
        let tarball_sri = fake_tarball_sri(b"victim-1.0.0");
        write_pnpm_index(&root, &tarball_sri, &[("index.js", &blob_sri, 0o644)]);
        // Attacker overwrites the blob in place.
        std::fs::write(&blob_path, b"// PWNED").unwrap();

        let entries = vec![IntegrityEntry {
            name: "victim".into(),
            version: "1.0.0".into(),
            integrity: tarball_sri,
        }];
        let report = verify_pnpm_store(&entries, &root);
        assert!(!report.is_clean());
        assert_eq!(report.mismatched, 1);
        let v = &report.packages[0];
        assert_eq!(v.outcome, Outcome::Mismatch);
        assert!(v.message.as_deref().unwrap().contains("index.js"));
    }

    #[test]
    fn verify_pnpm_store_missing_when_index_absent() {
        let root = tmpdir("pnpm-noindex");
        let tarball_sri = fake_tarball_sri(b"ghost");
        let entries = vec![IntegrityEntry {
            name: "ghost".into(),
            version: "1.0.0".into(),
            integrity: tarball_sri,
        }];
        let report = verify_pnpm_store(&entries, &root);
        assert_eq!(report.missing, 1);
        assert!(
            report.packages[0]
                .message
                .as_deref()
                .unwrap()
                .contains("index.json not present")
        );
    }

    #[test]
    fn verify_pnpm_store_missing_when_referenced_blob_absent() {
        let root = tmpdir("pnpm-noblob");
        let tarball_sri = fake_tarball_sri(b"holey");
        // Write the index but never the actual blob.
        let fake_blob_sri = fake_tarball_sri(b"phantom-content");
        write_pnpm_index(&root, &tarball_sri, &[("gone.js", &fake_blob_sri, 0o644)]);
        let entries = vec![IntegrityEntry {
            name: "holey".into(),
            version: "1.0.0".into(),
            integrity: tarball_sri,
        }];
        let report = verify_pnpm_store(&entries, &root);
        assert_eq!(report.missing, 1);
        assert!(
            report.packages[0]
                .message
                .as_deref()
                .unwrap()
                .contains("gone.js")
        );
    }

    #[test]
    fn verify_pnpm_store_picks_exec_path_for_executable_files() {
        // Executable mode → `-exec` suffix on the CAS filename.
        let root = tmpdir("pnpm-exec");
        let script = b"#!/bin/sh\necho hi";
        let (path, sri) = write_pnpm_blob(&root, script, 0o755);
        assert!(path.to_string_lossy().ends_with("-exec"));
        let tarball_sri = fake_tarball_sri(b"runner-1.0.0");
        write_pnpm_index(&root, &tarball_sri, &[("bin/run", &sri, 0o755)]);

        let entries = vec![IntegrityEntry {
            name: "runner".into(),
            version: "1.0.0".into(),
            integrity: tarball_sri,
        }];
        let report = verify_pnpm_store(&entries, &root);
        assert!(report.is_clean(), "{report:#?}");
    }

    #[test]
    fn verify_pnpm_store_flags_v10_sqlite_layout_explicitly() {
        // pnpm v10 writes <store>/index.db and drops the per-package
        // -index.json files. We don't yet parse SQLite/msgpack; the
        // detector must short-circuit with a clear message rather
        // than silently report everything as missing.
        let root = tmpdir("pnpm-v10");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.db"), b"fake sqlite").unwrap();

        let entries = vec![IntegrityEntry {
            name: "anything".into(),
            version: "1.0.0".into(),
            integrity: "sha512-AAAA==".into(),
        }];
        let report = verify_pnpm_store(&entries, &root);
        assert_eq!(report.unsupported, 1);
        let v = &report.packages[0];
        assert_eq!(v.outcome, Outcome::Unsupported);
        assert!(v.message.as_deref().unwrap().contains("pnpm v10"));
    }

    #[test]
    fn pnpm_integrity_entries_parses_v8_lockfile() {
        let body = r#"lockfileVersion: '6.0'
packages:
  /lodash/4.17.21:
    resolution:
      integrity: sha512-AAAA==
      tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
    dev: false
  /@scope/pkg/1.2.3:
    resolution:
      integrity: sha512-BBBB==
    dev: false
  /git-dep/0.0.1:
    resolution:
      type: git
      repo: https://github.com/x/y.git
"#;
        let dir = tmpdir("pnpm-lock-v8");
        let p = dir.join("pnpm-lock.yaml");
        std::fs::write(&p, body).unwrap();
        let mut got = pnpm_integrity_entries(&p).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "@scope/pkg");
        assert_eq!(got[0].version, "1.2.3");
        assert_eq!(got[0].integrity, "sha512-BBBB==");
        assert_eq!(got[1].name, "lodash");
    }

    #[test]
    fn pnpm_integrity_entries_parses_v9_lockfile() {
        let body = r#"lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution:
      integrity: sha512-AAAA==
  '@scope/pkg@1.2.3':
    resolution:
      integrity: sha512-BBBB==
  'react-dom@18.2.0(react@18.2.0)':
    resolution:
      integrity: sha512-CCCC==
"#;
        let dir = tmpdir("pnpm-lock-v9");
        let p = dir.join("pnpm-lock.yaml");
        std::fs::write(&p, body).unwrap();
        let mut got = pnpm_integrity_entries(&p).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].name, "@scope/pkg");
        assert_eq!(got[1].name, "lodash");
        // peer-deps suffix stripped from version
        assert_eq!(got[2].name, "react-dom");
        assert_eq!(got[2].version, "18.2.0");
    }

    // --- cargo-specific tests --------------------------------------------

    fn cargo_home_with_crate(
        cargo_home: &Path,
        reg: &str,
        name: &str,
        version: &str,
        bytes: &[u8],
    ) -> PathBuf {
        let dir = cargo_home.join("registry").join("cache").join(reg);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}-{version}.crate"));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(64);
        for b in sha2::Sha256::digest(bytes) {
            use std::fmt::Write;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    #[test]
    fn verify_cargo_registry_ok_when_crate_matches_checksum() {
        let home = tmpdir("cargo-ok");
        let bytes = b"fake .crate gzipped tarball bytes";
        cargo_home_with_crate(&home, "index.crates.io-abc123", "serde", "1.0.0", bytes);
        let entries = vec![IntegrityEntry {
            name: "serde".into(),
            version: "1.0.0".into(),
            integrity: sha256_hex(bytes),
        }];
        let report = verify_cargo_registry(&entries, &home);
        assert!(report.is_clean(), "{report:#?}");
        assert_eq!(report.ok, 1);
    }

    #[test]
    fn verify_cargo_registry_detects_tampered_crate() {
        // This is the headline case: someone replaced the .crate
        // under registry/cache while leaving Cargo.lock untouched.
        let home = tmpdir("cargo-tamper");
        let original = b"original crate bytes";
        let path = cargo_home_with_crate(
            &home,
            "index.crates.io-deadbeef",
            "victim",
            "1.0.0",
            original,
        );
        let original_hex = sha256_hex(original);
        // Attacker overwrites in place.
        std::fs::write(&path, b"// PWNED .crate").unwrap();

        let entries = vec![IntegrityEntry {
            name: "victim".into(),
            version: "1.0.0".into(),
            integrity: original_hex,
        }];
        let report = verify_cargo_registry(&entries, &home);
        assert!(!report.is_clean());
        assert_eq!(report.mismatched, 1);
        let v = &report.packages[0];
        assert_eq!(v.outcome, Outcome::Mismatch);
        assert!(v.expected_sha_hex.is_some());
        assert!(v.actual_sha_hex.is_some());
        assert_ne!(v.expected_sha_hex, v.actual_sha_hex);
    }

    #[test]
    fn verify_cargo_registry_missing_when_crate_absent() {
        let home = tmpdir("cargo-missing");
        // Don't write the .crate at all.
        let entries = vec![IntegrityEntry {
            name: "ghost".into(),
            version: "1.0.0".into(),
            integrity: sha256_hex(b"never written"),
        }];
        let report = verify_cargo_registry(&entries, &home);
        assert_eq!(report.missing, 1);
        assert_eq!(report.packages[0].outcome, Outcome::Missing);
    }

    #[test]
    fn verify_cargo_registry_searches_multiple_registry_dirs() {
        // sparse + legacy git + alt registry can coexist; the
        // verifier must look in every cache/<reg>/ subdir.
        let home = tmpdir("cargo-multi");
        let bytes = b"alt-registry payload";
        cargo_home_with_crate(&home, "my-alt-reg-9876", "pkg", "0.1.0", bytes);
        // also put an empty dir to confirm we don't crash on it
        std::fs::create_dir_all(
            home.join("registry")
                .join("cache")
                .join("github.com-1ecc6299db9ec823"),
        )
        .unwrap();

        let entries = vec![IntegrityEntry {
            name: "pkg".into(),
            version: "0.1.0".into(),
            integrity: sha256_hex(bytes),
        }];
        let report = verify_cargo_registry(&entries, &home);
        assert!(report.is_clean(), "{report:#?}");
    }

    #[test]
    fn verify_cargo_registry_unsupported_for_malformed_checksum() {
        let home = tmpdir("cargo-bad-cksum");
        let entries = vec![IntegrityEntry {
            name: "weird".into(),
            version: "1.0.0".into(),
            integrity: "not-hex".into(),
        }];
        let report = verify_cargo_registry(&entries, &home);
        assert_eq!(report.unsupported, 1);
        assert!(
            report.packages[0]
                .message
                .as_deref()
                .unwrap()
                .contains("64-char SHA-256 hex")
        );
    }

    #[test]
    fn cargo_integrity_entries_parses_registry_packages_only() {
        let body = r#"# Auto-generated by Cargo
version = 3

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5e7d3c8c1e9b3f7c0a5f1d2b3c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"

[[package]]
name = "local-thing"
version = "0.1.0"
# no source, no checksum — path dep

[[package]]
name = "git-dep"
version = "0.0.1"
source = "git+https://github.com/x/y.git#abc123"
# git deps carry source but no checksum
"#;
        let dir = tmpdir("cargo-lock");
        let p = dir.join("Cargo.lock");
        std::fs::write(&p, body).unwrap();
        let got = cargo_integrity_entries(&p).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "serde");
        assert_eq!(got[0].version, "1.0.0");
        assert!(got[0].integrity.starts_with("5e7d"));
    }

    #[test]
    fn npm_integrity_entries_skips_entries_without_integrity() {
        // Git deps and tarball URLs without integrity must not appear
        // — verify-cache has nothing to compare them against.
        let body = r#"{
  "name":"x","version":"0","lockfileVersion":2,
  "packages":{
    "":{"name":"x","version":"0"},
    "node_modules/with":{"version":"1.0.0","integrity":"sha512-zz"},
    "node_modules/without":{"version":"1.0.0"}
  }
}"#;
        let dir = tmpdir("npm-noint");
        let p = dir.join("package-lock.json");
        std::fs::write(&p, body).unwrap();
        let got = npm_integrity_entries(&p).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "with");
    }
}

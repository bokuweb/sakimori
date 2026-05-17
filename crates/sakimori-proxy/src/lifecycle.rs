//! Lifecycle-script gate for npm tarballs (Shai-Hulud-class defence).
//!
//! npm's `preinstall` / `install` / `postinstall` / `prepare` script
//! hooks are the primary RCE vector for worm-style supply-chain
//! attacks: once a malicious version has aged past `min-release-age`,
//! `npm install` runs those scripts before any other defence in the
//! stack gets a chance. This module inspects the tarball **at the
//! proxy fetch boundary** — before npm has even seen the bytes — so we
//! can audit-log or hard-deny the install.
//!
//! Scope of this slice:
//! - **npm tarballs** (`*.tgz`, gzipped POSIX tar with a single
//!   top-level `package/` directory) — full Audit + Block via
//!   [`inspect_npm_tarball`].
//! - **PyPI sdists** (`*.tar.gz`, gzipped POSIX tar with a single
//!   top-level `<name>-<version>/` directory) — Audit + Block via
//!   [`inspect_pypi_sdist`]. Block fires when the sdist ships
//!   `setup.py` (legacy unbounded install-time hook) regardless of
//!   what `pyproject.toml` declares; the build-backend name is
//!   recorded for audit log triage. Wheels (`.whl`) carry no
//!   install-time hooks (pip just file-copies them into site-packages)
//!   so the gate deliberately doesn't touch them — wheel pinning is
//!   the right defence shape there.
//! - `Audit` and `Block` policies only. `Strip` (rewriting the tarball
//!   to drop the scripts entries) is the third roadmap mode and is
//!   genuinely larger — see the module docs roadmap note.
//! - Scripts at the **root** `package.json` only. We intentionally do
//!   not recurse into bundled deps under `node_modules/` inside the
//!   tarball: those run with the parent package's scripts already
//!   inspected, and a malicious bundled dep is a separate threat model
//!   that lockfile pinning is supposed to cover.

use std::io::Read;

use flate2::read::GzDecoder;
use serde::Deserialize;
use tar::Archive;

/// npm's install-time lifecycle script keys. Sorted by execution order
/// so audit output reads naturally. `prepare` is included even though
/// it isn't strictly install-time (it runs on `npm pack` and on
/// `npm install` for git deps) because supply-chain droppers have used
/// it as a "less-watched" alternative to `postinstall`.
pub const LIFECYCLE_KEYS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePolicy {
    /// Don't touch the tarball; log script bodies on hit. Default.
    Audit,
    /// Refuse the tarball fetch with 403 when any lifecycle script is
    /// present. Stops the install before npm runs anything.
    Block,
    /// Rewrite the tarball to drop install-time script keys from
    /// `package.json`, recompute integrity, and arrange for the
    /// packument to advertise the new hash. Best-effort: lockfile-
    /// pinned fetches (where the proxy never saw a packument for
    /// `(name, version)` in the same connection) fall back to Block
    /// because we cannot rewrite the on-disk lockfile.
    Strip,
}

impl LifecyclePolicy {
    /// Parse the CLI string form.
    pub fn parse(s: &str) -> Result<Self, ParsePolicyError> {
        match s {
            "audit" => Ok(Self::Audit),
            "block" => Ok(Self::Block),
            "strip" => Ok(Self::Strip),
            other => Err(ParsePolicyError::Unknown(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePolicyError {
    Unknown(String),
}

impl std::fmt::Display for ParsePolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(s) => write!(
                f,
                "unknown lifecycle policy {s:?}; expected one of: audit, block, strip"
            ),
        }
    }
}

impl std::error::Error for ParsePolicyError {}

/// What the strip path does when the tarball rewriter itself fails
/// (corrupt bytes, exceeded resource limit, timeout). The default is
/// `Block` — having opted into strip mode the user expects scripts
/// neutralised, so silently shipping the original bytes would be a
/// security regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StripFailurePolicy {
    #[default]
    Block,
    Passthrough,
}

impl StripFailurePolicy {
    pub fn parse(s: &str) -> Result<Self, ParsePolicyError> {
        match s {
            "block" => Ok(Self::Block),
            "passthrough" => Ok(Self::Passthrough),
            other => Err(ParsePolicyError::Unknown(other.to_string())),
        }
    }
}

/// One script the inspector found in `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleScript {
    pub stage: &'static str,
    pub body: String,
}

/// Outcome of inspecting a single tarball.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inspection {
    /// Empty when the tarball doesn't contain a recognisable
    /// `package.json`, when `package.json` has no `scripts` object, or
    /// when `scripts` has only keys outside [`LIFECYCLE_KEYS`].
    pub scripts: Vec<LifecycleScript>,
}

impl Inspection {
    pub fn has_scripts(&self) -> bool {
        !self.scripts.is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct PackageJson {
    #[serde(default)]
    scripts: Option<serde_json::Value>,
}

/// Inspect a gzipped npm tarball.
///
/// Returns `Ok(Inspection { scripts: vec![] })` for any tarball that
/// parses but contains no install-time scripts — this is the
/// overwhelmingly common case and must be cheap. Returns `Err` only
/// when the bytes don't look like a gzipped tar at all; a tarball with
/// no `package.json` is treated as "no scripts" so we fail open on
/// malformed-but-fetchable artefacts rather than breaking installs of
/// non-standard packages.
///
/// Tarball size cap: the caller is responsible for not feeding
/// pathological inputs. The decoder limits per-entry reads to the
/// declared tar entry size, so a 100 MiB tarball costs ~one
/// `package.json`-worth of memory in practice.
pub fn inspect_npm_tarball(body: &[u8]) -> Result<Inspection, InspectError> {
    if !looks_like_gzip(body) {
        return Err(InspectError::NotGzip);
    }
    let mut archive = Archive::new(GzDecoder::new(body));
    let entries = archive
        .entries()
        .map_err(|e| InspectError::Tar(e.to_string()))?;
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Malformed entry header — keep walking, don't abort
                // the whole inspection. A real malicious tarball that
                // tries to evade us by corrupting an earlier header
                // still has to ship a valid `package.json` for npm to
                // install at all.
                log::debug!("lifecycle: skipping malformed tar entry: {e}");
                continue;
            }
        };
        let path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };
        // npm tarballs always have a single top-level `package/` dir.
        // The `package.json` we care about lives directly under it.
        let is_root_package_json = path
            .file_name()
            .map(|n| n == "package.json")
            .unwrap_or(false)
            && path.components().count() == 2;
        if !is_root_package_json {
            continue;
        }
        let mut buf = Vec::new();
        if let Err(e) = entry.read_to_end(&mut buf) {
            return Err(InspectError::Read(e.to_string()));
        }
        return Ok(parse_package_json(&buf));
    }
    Ok(Inspection::default())
}

#[derive(Debug)]
pub enum InspectError {
    NotGzip,
    Tar(String),
    Read(String),
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGzip => write!(f, "body is not gzipped"),
            Self::Tar(s) => write!(f, "tar parse error: {s}"),
            Self::Read(s) => write!(f, "tar read error: {s}"),
        }
    }
}

impl std::error::Error for InspectError {}

fn looks_like_gzip(b: &[u8]) -> bool {
    b.len() >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

fn parse_package_json(body: &[u8]) -> Inspection {
    let pkg: PackageJson = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(_) => return Inspection::default(),
    };
    let Some(scripts) = pkg.scripts else {
        return Inspection::default();
    };
    let Some(obj) = scripts.as_object() else {
        return Inspection::default();
    };
    let mut found = Vec::new();
    for key in LIFECYCLE_KEYS {
        if let Some(v) = obj.get(*key)
            && let Some(body) = v.as_str()
            && !body.trim().is_empty()
        {
            found.push(LifecycleScript {
                stage: key,
                body: body.to_string(),
            });
        }
    }
    Inspection { scripts: found }
}

// --- npm tarball strip ----------------------------------------------------

/// Hard caps for the strip path. Defaults are sized to comfortably
/// admit every legitimate npm package (the largest popular packages
/// are well under 32 MiB compressed) while refusing pathological
/// inputs that would let a malicious tarball DoS the proxy.
#[derive(Debug, Clone, Copy)]
pub struct StripLimits {
    pub max_compressed_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub max_entries: usize,
    pub max_single_entry_bytes: u64,
}

impl Default for StripLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: 64 * 1024 * 1024,
            max_decompressed_bytes: 256 * 1024 * 1024,
            max_entries: 16_384,
            max_single_entry_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Result of a successful strip pass. The caller is expected to serve
/// `bytes` in place of the original tarball and use `sha512_b64` +
/// `sha1_hex` to update the packument's `dist.integrity` /
/// `dist.shasum` so npm's verifier agrees.
#[derive(Debug, Clone)]
pub struct StripOutcome {
    pub bytes: Vec<u8>,
    pub stripped_stages: Vec<&'static str>,
    pub sha512_b64: String,
    pub sha1_hex: String,
}

#[derive(Debug)]
pub enum StripError {
    NotGzip,
    TooLarge { kind: &'static str, size: u64 },
    TooManyEntries(usize),
    BadPath(String),
    Tar(String),
    Json(String),
    Io(String),
}

impl std::fmt::Display for StripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGzip => write!(f, "body is not gzipped"),
            Self::TooLarge { kind, size } => {
                write!(f, "tarball exceeds {kind} limit at {size} bytes")
            }
            Self::TooManyEntries(n) => write!(f, "tarball has {n} entries (over cap)"),
            Self::BadPath(p) => write!(f, "rejected unsafe tar entry path: {p}"),
            Self::Tar(s) => write!(f, "tar parse error: {s}"),
            Self::Json(s) => write!(f, "package.json rewrite error: {s}"),
            Self::Io(s) => write!(f, "io error during strip: {s}"),
        }
    }
}

impl std::error::Error for StripError {}

/// Rewrite an npm tarball so that its root `package/package.json` no
/// longer carries any of [`LIFECYCLE_KEYS`]. Returns `Ok(None)` when
/// the tarball had no lifecycle scripts to begin with — the caller
/// should serve the original bytes unchanged in that case so the
/// packument's existing integrity remains valid.
///
/// The function is deliberately self-contained and pure (no async, no
/// IO). It enforces `limits` to refuse gzip bombs, oversize tarballs,
/// pathological entry counts, and unsafe path components. The caller
/// is expected to time-box the invocation (e.g. via
/// `tokio::time::timeout` or `spawn_blocking`).
pub fn strip_npm_tarball(
    body: &[u8],
    limits: &StripLimits,
) -> Result<Option<StripOutcome>, StripError> {
    if (body.len() as u64) > limits.max_compressed_bytes {
        return Err(StripError::TooLarge {
            kind: "compressed",
            size: body.len() as u64,
        });
    }
    if !looks_like_gzip(body) {
        return Err(StripError::NotGzip);
    }

    // Decompress into memory under a cap so a gzip bomb is rejected
    // before we spend further work on it.
    let decompressed = decompress_capped(body, limits.max_decompressed_bytes)?;

    // Two-pass: first pass scans for the root package.json to decide
    // whether any work is needed at all. Avoids paying re-encoding
    // cost on the 99% benign case.
    let Some((root_idx, mutated_pkg_json)) = rewrite_root_package_json(&decompressed, limits)?
    else {
        return Ok(None);
    };

    let stripped_stages = mutated_pkg_json.stripped_stages.clone();

    // Second pass: rebuild the tar with the rewritten package.json in
    // place of entry index `root_idx`.
    let new_tar = rebuild_tar(&decompressed, root_idx, &mutated_pkg_json.bytes, limits)?;

    let mut gz_out = Vec::with_capacity(new_tar.len() / 3);
    {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(&mut gz_out, Compression::default());
        enc.write_all(&new_tar)
            .map_err(|e| StripError::Io(e.to_string()))?;
        enc.finish().map_err(|e| StripError::Io(e.to_string()))?;
    }

    let sha512_b64 = {
        use base64::Engine;
        use sha2::Digest;
        let mut h = sha2::Sha512::new();
        h.update(&gz_out);
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    };
    let sha1_hex = {
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(&gz_out);
        hex_lower(&h.finalize())
    };

    Ok(Some(StripOutcome {
        bytes: gz_out,
        stripped_stages,
        sha512_b64,
        sha1_hex,
    }))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn decompress_capped(gz: &[u8], cap: u64) -> Result<Vec<u8>, StripError> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(gz);
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| StripError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        if (out.len() as u64) + (n as u64) > cap {
            return Err(StripError::TooLarge {
                kind: "decompressed",
                size: cap + 1,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

struct MutatedPackageJson {
    bytes: Vec<u8>,
    stripped_stages: Vec<&'static str>,
}

/// Scan tar entries to locate the root `package/package.json`. On hit
/// returns the entry index and a rewritten body with lifecycle keys
/// removed. Returns `Ok(None)` when nothing needs to change (no root
/// package.json, no scripts object, no lifecycle keys present).
///
/// This also performs path validation on every entry as it walks so a
/// malformed tarball is rejected here rather than during rebuild.
fn rewrite_root_package_json(
    decompressed: &[u8],
    limits: &StripLimits,
) -> Result<Option<(usize, MutatedPackageJson)>, StripError> {
    use std::io::Read;
    let mut archive = tar::Archive::new(decompressed);
    let entries = archive
        .entries()
        .map_err(|e| StripError::Tar(e.to_string()))?;

    let mut found: Option<(usize, MutatedPackageJson)> = None;
    for (count, entry) in entries.enumerate() {
        if count >= limits.max_entries {
            return Err(StripError::TooManyEntries(count));
        }
        let mut entry = entry.map_err(|e| StripError::Tar(e.to_string()))?;
        let entry_size = entry.header().size().unwrap_or(0);
        if entry_size > limits.max_single_entry_bytes {
            return Err(StripError::TooLarge {
                kind: "entry",
                size: entry_size,
            });
        }
        let path = entry
            .path()
            .map_err(|e| StripError::Tar(e.to_string()))?
            .into_owned();
        validate_entry_path(&path)?;

        if found.is_some() {
            continue;
        }
        let is_root_package_json = path
            .file_name()
            .map(|n| n == "package.json")
            .unwrap_or(false)
            && path.components().count() == 2;
        if !is_root_package_json {
            continue;
        }
        let mut buf = Vec::with_capacity(entry_size as usize);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| StripError::Io(e.to_string()))?;
        if let Some(mutated) = mutate_package_json(&buf)? {
            found = Some((count, mutated));
        } else {
            // package.json exists but no lifecycle scripts to remove.
            return Ok(None);
        }
    }
    Ok(found)
}

fn mutate_package_json(body: &[u8]) -> Result<Option<MutatedPackageJson>, StripError> {
    // serde_json with the `preserve_order` feature (enabled in
    // workspace Cargo.toml) keeps the object key order, so the
    // re-serialised package.json differs only in the removed keys.
    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let Some(obj) = value.as_object_mut() else {
        return Ok(None);
    };
    let Some(scripts_val) = obj.get_mut("scripts") else {
        return Ok(None);
    };
    let Some(scripts) = scripts_val.as_object_mut() else {
        return Ok(None);
    };
    let mut stripped = Vec::new();
    for key in LIFECYCLE_KEYS {
        if scripts.remove(*key).is_some() {
            stripped.push(*key);
        }
    }
    if stripped.is_empty() {
        return Ok(None);
    }
    let new_bytes = serde_json::to_vec(&value).map_err(|e| StripError::Json(e.to_string()))?;
    Ok(Some(MutatedPackageJson {
        bytes: new_bytes,
        stripped_stages: stripped,
    }))
}

fn rebuild_tar(
    decompressed: &[u8],
    swap_idx: usize,
    new_pkg_json: &[u8],
    limits: &StripLimits,
) -> Result<Vec<u8>, StripError> {
    use std::io::Read;
    let mut archive = tar::Archive::new(decompressed);
    let entries = archive
        .entries()
        .map_err(|e| StripError::Tar(e.to_string()))?;

    let mut out_bytes = Vec::with_capacity(decompressed.len());
    {
        let mut builder = tar::Builder::new(&mut out_bytes);
        for (idx, entry) in entries.enumerate() {
            if idx >= limits.max_entries {
                return Err(StripError::TooManyEntries(idx));
            }
            let mut entry = entry.map_err(|e| StripError::Tar(e.to_string()))?;
            let entry_size = entry.header().size().unwrap_or(0);
            if entry_size > limits.max_single_entry_bytes {
                return Err(StripError::TooLarge {
                    kind: "entry",
                    size: entry_size,
                });
            }
            let path = entry
                .path()
                .map_err(|e| StripError::Tar(e.to_string()))?
                .into_owned();
            validate_entry_path(&path)?;
            let mut header = entry.header().clone();

            if idx == swap_idx {
                header.set_size(new_pkg_json.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, &path, new_pkg_json)
                    .map_err(|e| StripError::Io(e.to_string()))?;
            } else {
                // Preserve all non-regular entry types (directories,
                // symlinks, hardlinks) by writing the header verbatim
                // with an empty body. Regular files copy bytes through.
                let entry_type = header.entry_type();
                if entry_type.is_symlink() || entry_type.is_hard_link() {
                    let link_name = header
                        .link_name()
                        .map_err(|e| StripError::Tar(e.to_string()))?
                        .map(|c| c.into_owned());
                    let mut h2 = header.clone();
                    h2.set_size(0);
                    h2.set_cksum();
                    let link_name = link_name
                        .ok_or_else(|| StripError::Tar("link entry missing target".into()))?;
                    builder
                        .append_link(&mut h2, &path, &link_name)
                        .map_err(|e| StripError::Io(e.to_string()))?;
                } else if entry_type.is_dir() {
                    let mut h2 = header.clone();
                    h2.set_size(0);
                    h2.set_cksum();
                    builder
                        .append_data(&mut h2, &path, std::io::empty())
                        .map_err(|e| StripError::Io(e.to_string()))?;
                } else {
                    let mut buf = Vec::with_capacity(entry_size as usize);
                    entry
                        .read_to_end(&mut buf)
                        .map_err(|e| StripError::Io(e.to_string()))?;
                    header.set_size(buf.len() as u64);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, &path, buf.as_slice())
                        .map_err(|e| StripError::Io(e.to_string()))?;
                }
            }
        }
        builder
            .finish()
            .map_err(|e| StripError::Io(e.to_string()))?;
    }
    Ok(out_bytes)
}

fn validate_entry_path(path: &std::path::Path) -> Result<(), StripError> {
    use std::path::Component;
    if path.is_absolute() {
        return Err(StripError::BadPath(path.display().to_string()));
    }
    let mut depth: i32 = 0;
    for c in path.components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(StripError::BadPath(path.display().to_string()));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(StripError::BadPath(path.display().to_string()));
            }
        }
    }
    Ok(())
}

// --- PyPI sdist inspection ------------------------------------------------

/// Outcome of inspecting a PyPI source distribution.
///
/// `has_setup_py` is the high-signal field — a legacy `setup.py`
/// runs arbitrary Python at install time with the user's privileges
/// and is the closest analogue to npm's `postinstall`. `build_backend`
/// records what `pyproject.toml` declared (`setuptools.build_meta`,
/// `hatchling.build`, `poetry.core.masonry.api`, `flit_core.buildapi`,
/// `pdm.backend`, `maturin`, `scikit_build_core.build`, …) so the
/// audit log can rank "boring build-backend, no setup.py" against
/// "unfamiliar build-backend, also setup.py present" without a
/// human re-running inspection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PypiInspection {
    pub has_setup_py: bool,
    /// `None` means no `pyproject.toml` (legacy-only project) or one
    /// without a `[build-system]` table; we don't try to guess the
    /// implicit default (`setuptools.build_meta:__legacy__`) here.
    pub build_backend: Option<String>,
    pub build_requires: Vec<String>,
}

impl PypiInspection {
    /// Sdist is "definitely going to run code from this package at
    /// install time". Today that's anchored to `setup.py` presence;
    /// modern PEP 517 / 518 backends still execute the backend's
    /// `build_*` hooks, but those run in an isolated environment with
    /// only the declared `build-requires` available, which is a much
    /// smaller attack surface than `setup.py`'s "anything on
    /// sys.path".
    pub fn is_legacy_install_hook(&self) -> bool {
        self.has_setup_py
    }

    pub fn is_clean(&self) -> bool {
        !self.has_setup_py && self.build_backend.is_none()
    }
}

/// Inspect a PyPI source distribution. Same fail-open contract as
/// [`inspect_npm_tarball`]: a tarball we can't decode returns `Err`,
/// a decodable tarball without the markers we care about returns an
/// empty `PypiInspection` (caller should pass-through the bytes
/// rather than invent a denial).
///
/// We walk the tar entries looking for:
/// - any `<root>/setup.py` (legacy installer hook → `has_setup_py`)
/// - any `<root>/pyproject.toml` (parsed for the build backend)
///
/// `<root>` is the single top-level directory PyPI sdists carry,
/// typically `<name>-<version>/` — we don't enforce that exact form
/// because legitimate sdists from `flit`, `hatch`, etc. occasionally
/// trim the version suffix, but we do require a single leading path
/// component so a `node_modules/`-style nested file can't poison
/// the inspection.
pub fn inspect_pypi_sdist(body: &[u8]) -> Result<PypiInspection, InspectError> {
    if !looks_like_gzip(body) {
        return Err(InspectError::NotGzip);
    }
    let mut archive = Archive::new(GzDecoder::new(body));
    let entries = archive
        .entries()
        .map_err(|e| InspectError::Tar(e.to_string()))?;
    let mut out = PypiInspection::default();
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log::debug!("lifecycle(pypi): skipping malformed tar entry: {e}");
                continue;
            }
        };
        let path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };
        // Same single-top-level-dir guard as the npm inspector: the
        // file must live exactly one directory below the root, so
        // `<pkg>/setup.py` matches but `<pkg>/vendor/foo/setup.py`
        // doesn't. Vendored installer hooks aren't a real attack
        // shape today — pip only runs the top-level one — and
        // matching them would inflate false positives.
        let is_root_child = path.components().count() == 2;
        if !is_root_child {
            continue;
        }
        match path.file_name().and_then(|n| n.to_str()) {
            Some("setup.py") => {
                out.has_setup_py = true;
            }
            Some("pyproject.toml") => {
                let mut buf = Vec::new();
                if let Err(e) = entry.read_to_end(&mut buf) {
                    return Err(InspectError::Read(e.to_string()));
                }
                if let Some((backend, requires)) = parse_pyproject(&buf) {
                    out.build_backend = backend;
                    out.build_requires = requires;
                }
            }
            _ => continue,
        }
        // Early exit if we've seen everything we care about.
        if out.has_setup_py && out.build_backend.is_some() {
            break;
        }
    }
    Ok(out)
}

/// Parse `pyproject.toml` and return `(build-backend, requires)` from
/// the `[build-system]` table. Returns `None` if the file doesn't
/// parse as TOML — fail-open same as the npm side.
fn parse_pyproject(body: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let text = std::str::from_utf8(body).ok()?;
    let doc: toml::Value = toml::from_str(text).ok()?;
    let build_system = doc.get("build-system")?.as_table()?;
    let backend = build_system
        .get("build-backend")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let requires = build_system
        .get("requires")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some((backend, requires))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    /// Build a one-file npm-shaped tarball with `package.json` as the
    /// only entry under `package/`.
    fn pack_tarball(package_json: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(package_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/package.json", package_json)
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn detects_postinstall() {
        let pkg = br#"{"name":"x","version":"1.0.0","scripts":{"postinstall":"node steal.js"}}"#;
        let tgz = pack_tarball(pkg);
        let out = inspect_npm_tarball(&tgz).unwrap();
        assert!(out.has_scripts());
        assert_eq!(out.scripts.len(), 1);
        assert_eq!(out.scripts[0].stage, "postinstall");
        assert_eq!(out.scripts[0].body, "node steal.js");
    }

    #[test]
    fn benign_package_returns_no_scripts() {
        // Plenty of `scripts` keys, but none install-time.
        let pkg = br#"{"name":"x","scripts":{"test":"jest","lint":"eslint ."}}"#;
        let tgz = pack_tarball(pkg);
        let out = inspect_npm_tarball(&tgz).unwrap();
        assert!(!out.has_scripts());
    }

    #[test]
    fn no_scripts_object_at_all() {
        let pkg = br#"{"name":"x","version":"1.0.0"}"#;
        let tgz = pack_tarball(pkg);
        let out = inspect_npm_tarball(&tgz).unwrap();
        assert!(!out.has_scripts());
    }

    #[test]
    fn all_four_stages_detected_in_order() {
        let pkg = br#"{
            "scripts": {
                "postinstall": "c",
                "preinstall":  "a",
                "prepare":     "d",
                "install":     "b",
                "test":        "ignored"
            }
        }"#;
        let tgz = pack_tarball(pkg);
        let out = inspect_npm_tarball(&tgz).unwrap();
        // Output order follows LIFECYCLE_KEYS, not source order.
        let stages: Vec<_> = out.scripts.iter().map(|s| s.stage).collect();
        assert_eq!(
            stages,
            vec!["preinstall", "install", "postinstall", "prepare"]
        );
    }

    #[test]
    fn empty_script_body_is_ignored() {
        let pkg = br#"{"scripts":{"postinstall":"   "}}"#;
        let tgz = pack_tarball(pkg);
        let out = inspect_npm_tarball(&tgz).unwrap();
        assert!(!out.has_scripts());
    }

    #[test]
    fn not_gzip_returns_error() {
        let err = inspect_npm_tarball(b"not a tarball at all").unwrap_err();
        assert!(matches!(err, InspectError::NotGzip));
    }

    #[test]
    fn tarball_without_package_json_fails_open() {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            let body = b"hello";
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/README", &body[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let tgz = gz.finish().unwrap();
        let out = inspect_npm_tarball(&tgz).unwrap();
        assert!(!out.has_scripts());
    }

    #[test]
    fn nested_package_json_is_ignored() {
        // A bundled dep's package.json must not be inspected — only the
        // root `package/package.json`. Build a tarball with both.
        let root = br#"{"name":"x"}"#;
        let nested = br#"{"scripts":{"postinstall":"evil"}}"#;
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (path, body) in [
                ("package/package.json", &root[..]),
                ("package/node_modules/dep/package.json", &nested[..]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, body).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let tgz = gz.finish().unwrap();
        let out = inspect_npm_tarball(&tgz).unwrap();
        assert!(!out.has_scripts());
    }

    // --- PyPI sdist tests -------------------------------------------------

    /// Build a PyPI-shaped sdist tarball with the given `<root>/`
    /// directory and an iterable of `(relative_path, bytes)` entries.
    fn pack_sdist(root: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (rel, body) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                let path = format!("{root}/{rel}");
                builder.append_data(&mut header, &path, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn pypi_detects_setup_py() {
        let tgz = pack_sdist(
            "foo-1.0.0",
            &[("setup.py", b"from setuptools import setup\n")],
        );
        let out = inspect_pypi_sdist(&tgz).unwrap();
        assert!(out.has_setup_py);
        assert!(out.is_legacy_install_hook());
        assert!(!out.is_clean());
        assert!(out.build_backend.is_none());
    }

    #[test]
    fn pypi_extracts_build_backend_from_pyproject() {
        let pyproject = br#"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
"#;
        let tgz = pack_sdist("foo-1.0.0", &[("pyproject.toml", pyproject)]);
        let out = inspect_pypi_sdist(&tgz).unwrap();
        assert_eq!(out.build_backend.as_deref(), Some("hatchling.build"));
        assert_eq!(out.build_requires, vec!["hatchling".to_string()]);
        // No setup.py → not "legacy install hook" even though the build
        // backend will still execute. Block mode deliberately doesn't
        // fire here in the first slice.
        assert!(!out.is_legacy_install_hook());
        assert!(!out.is_clean());
    }

    #[test]
    fn pypi_modern_project_with_both_setup_and_pyproject() {
        // Real-world: scientific packages often ship both for compat
        // with older pip versions. setup.py presence still pokes the
        // legacy hook so we should flag it.
        let pyproject = br#"
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"
"#;
        let tgz = pack_sdist(
            "numpy-2.0.0",
            &[
                ("setup.py", b"import setuptools; setuptools.setup()\n"),
                ("pyproject.toml", pyproject),
            ],
        );
        let out = inspect_pypi_sdist(&tgz).unwrap();
        assert!(out.has_setup_py);
        assert_eq!(out.build_backend.as_deref(), Some("setuptools.build_meta"));
    }

    #[test]
    fn pypi_clean_modern_sdist_is_clean() {
        // pyproject-only project with no build-system table — perfectly
        // possible (flit's old default). Should return clean.
        let tgz = pack_sdist(
            "foo-1.0.0",
            &[("pyproject.toml", b"[project]\nname = \"foo\"\n")],
        );
        let out = inspect_pypi_sdist(&tgz).unwrap();
        assert!(out.is_clean(), "got: {out:?}");
    }

    #[test]
    fn pypi_ignores_nested_setup_py_in_vendored_tree() {
        // Vendored installer hook inside a subdirectory must not be
        // mistaken for the root one — only the top-level setup.py
        // actually runs at install time.
        let tgz = pack_sdist(
            "foo-1.0.0",
            &[("vendor/bar/setup.py", b"raise RuntimeError('pwned')\n")],
        );
        let out = inspect_pypi_sdist(&tgz).unwrap();
        assert!(!out.has_setup_py, "nested setup.py must not trip the gate");
        assert!(out.is_clean());
    }

    #[test]
    fn pypi_malformed_pyproject_fails_open_to_no_backend() {
        // Garbage TOML → no backend reported; rest of inspection
        // proceeds. We never fail-closed on parse errors.
        let tgz = pack_sdist(
            "foo-1.0.0",
            &[
                ("setup.py", b"setup()\n"),
                ("pyproject.toml", b"not [ valid toml ]\n"),
            ],
        );
        let out = inspect_pypi_sdist(&tgz).unwrap();
        assert!(out.has_setup_py);
        assert!(out.build_backend.is_none());
    }

    #[test]
    fn pypi_inspect_rejects_non_gzip() {
        let err = inspect_pypi_sdist(b"this is not gzipped").unwrap_err();
        assert!(matches!(err, InspectError::NotGzip));
    }

    #[test]
    fn parse_policy_string() {
        assert_eq!(LifecyclePolicy::parse("audit"), Ok(LifecyclePolicy::Audit));
        assert_eq!(LifecyclePolicy::parse("block"), Ok(LifecyclePolicy::Block));
        assert_eq!(LifecyclePolicy::parse("strip"), Ok(LifecyclePolicy::Strip));
        assert!(matches!(
            LifecyclePolicy::parse("nope"),
            Err(ParsePolicyError::Unknown(_))
        ));
    }

    // --- strip_npm_tarball tests -----------------------------------------

    fn pack_multi(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (path, body) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn strip_removes_lifecycle_keys_only() {
        let pkg = br#"{"name":"x","version":"1.0.0","scripts":{"preinstall":"a","postinstall":"b","test":"jest"}}"#;
        let tgz = pack_tarball(pkg);
        let out = strip_npm_tarball(&tgz, &StripLimits::default())
            .unwrap()
            .expect("expected scripts to be stripped");
        let mut stages = out.stripped_stages.clone();
        stages.sort();
        assert_eq!(stages, vec!["postinstall", "preinstall"]);
        // Round-trip: re-inspect the stripped tarball; no lifecycle
        // scripts should remain.
        let after = inspect_npm_tarball(&out.bytes).unwrap();
        assert!(!after.has_scripts(), "post-strip still has scripts");
        // And the non-lifecycle script must survive — decode the
        // re-emitted tarball and check.
        let mut a = tar::Archive::new(flate2::read::GzDecoder::new(std::io::Cursor::new(
            &out.bytes,
        )));
        let mut pkg_after: Vec<u8> = Vec::new();
        for entry in a.entries().unwrap() {
            let mut e = entry.unwrap();
            if e.path().unwrap().ends_with("package.json") {
                use std::io::Read;
                e.read_to_end(&mut pkg_after).unwrap();
            }
        }
        let v: serde_json::Value = serde_json::from_slice(&pkg_after).unwrap();
        assert_eq!(v["scripts"]["test"], "jest");
        assert!(v["scripts"].get("preinstall").is_none());
    }

    #[test]
    fn strip_returns_none_when_no_lifecycle_scripts() {
        let pkg = br#"{"name":"x","scripts":{"test":"jest"}}"#;
        let tgz = pack_tarball(pkg);
        let out = strip_npm_tarball(&tgz, &StripLimits::default()).unwrap();
        assert!(out.is_none(), "expected None for benign package");
    }

    #[test]
    fn strip_returns_none_when_no_package_json() {
        let tgz = pack_multi(&[("package/README.md", b"hi")]);
        let out = strip_npm_tarball(&tgz, &StripLimits::default()).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn strip_hashes_are_consistent() {
        let pkg = br#"{"scripts":{"postinstall":"x"}}"#;
        let tgz = pack_tarball(pkg);
        let out = strip_npm_tarball(&tgz, &StripLimits::default())
            .unwrap()
            .unwrap();
        // sha512 base64 of a non-empty input is always 88 chars
        // (standard padded) — sanity check the encoder.
        assert_eq!(out.sha512_b64.len(), 88);
        // sha1 hex is always 40 chars.
        assert_eq!(out.sha1_hex.len(), 40);
        // And recomputing them by hand on the returned bytes must
        // match exactly.
        use sha2::Digest;
        let mut h512 = sha2::Sha512::new();
        h512.update(&out.bytes);
        use base64::Engine;
        let expect_512 = base64::engine::general_purpose::STANDARD.encode(h512.finalize());
        assert_eq!(out.sha512_b64, expect_512);
        let mut h1 = sha1::Sha1::new();
        sha1::Digest::update(&mut h1, &out.bytes);
        let expect_1 = hex_lower(&h1.finalize());
        assert_eq!(out.sha1_hex, expect_1);
    }

    #[test]
    fn strip_rejects_non_gzip() {
        let err = strip_npm_tarball(b"not a tarball", &StripLimits::default()).unwrap_err();
        assert!(matches!(err, StripError::NotGzip));
    }

    #[test]
    fn strip_enforces_compressed_cap() {
        let pkg = br#"{"scripts":{"postinstall":"x"}}"#;
        let tgz = pack_tarball(pkg);
        let limits = StripLimits {
            max_compressed_bytes: 10,
            ..StripLimits::default()
        };
        let err = strip_npm_tarball(&tgz, &limits).unwrap_err();
        assert!(matches!(
            err,
            StripError::TooLarge {
                kind: "compressed",
                ..
            }
        ));
    }

    #[test]
    fn strip_enforces_decompressed_cap() {
        let pkg = br#"{"scripts":{"postinstall":"x"}}"#;
        let tgz = pack_tarball(pkg);
        let limits = StripLimits {
            max_decompressed_bytes: 16,
            ..StripLimits::default()
        };
        let err = strip_npm_tarball(&tgz, &limits).unwrap_err();
        assert!(matches!(
            err,
            StripError::TooLarge {
                kind: "decompressed",
                ..
            }
        ));
    }

    #[test]
    fn validate_entry_path_rejects_traversal() {
        let p = std::path::Path::new("package/../../etc/passwd");
        assert!(matches!(
            validate_entry_path(p),
            Err(StripError::BadPath(_))
        ));
        // Normal nested path under package/ is fine.
        let ok = std::path::Path::new("package/lib/foo.js");
        assert!(validate_entry_path(ok).is_ok());
    }
}

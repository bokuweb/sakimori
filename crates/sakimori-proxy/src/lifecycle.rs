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
//! Scope of this first slice:
//! - **npm tarballs only** (`*.tgz`, gzipped POSIX tar with a single
//!   top-level `package/` directory). PyPI's `setup.py` / build-backend
//!   surface is structurally different and lands in a follow-up.
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
}

impl LifecyclePolicy {
    /// Parse the CLI string form. Returns `Err(unknown)` for anything
    /// other than the two implemented modes; `strip` returns a distinct
    /// error so callers can surface "not yet implemented" rather than
    /// "unknown policy".
    pub fn parse(s: &str) -> Result<Self, ParsePolicyError> {
        match s {
            "audit" => Ok(Self::Audit),
            "block" => Ok(Self::Block),
            "strip" => Err(ParsePolicyError::StripNotImplemented),
            other => Err(ParsePolicyError::Unknown(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePolicyError {
    Unknown(String),
    StripNotImplemented,
}

impl std::fmt::Display for ParsePolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(s) => write!(
                f,
                "unknown lifecycle policy {s:?}; expected one of: audit, block"
            ),
            Self::StripNotImplemented => write!(
                f,
                "lifecycle policy 'strip' is on the roadmap but not yet \
                 implemented — use 'audit' or 'block' for now"
            ),
        }
    }
}

impl std::error::Error for ParsePolicyError {}

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

    #[test]
    fn parse_policy_string() {
        assert_eq!(LifecyclePolicy::parse("audit"), Ok(LifecyclePolicy::Audit));
        assert_eq!(LifecyclePolicy::parse("block"), Ok(LifecyclePolicy::Block));
        assert!(matches!(
            LifecyclePolicy::parse("strip"),
            Err(ParsePolicyError::StripNotImplemented)
        ));
        assert!(matches!(
            LifecyclePolicy::parse("nope"),
            Err(ParsePolicyError::Unknown(_))
        ));
    }
}

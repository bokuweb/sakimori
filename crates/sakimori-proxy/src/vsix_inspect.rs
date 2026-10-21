//! `.vsix` (VS Code Extension package) inspector — the editor-
//! extension counterpart to [`crate::lifecycle::inspect_npm_tarball`].
//!
//! A `.vsix` is a zip archive (OPC-flavoured) containing an
//! `extension/` root with a `package.json` manifest. The fields we
//! care about for supply-chain audit are:
//!
//! - `activationEvents`: the VS Code primitive controlling when an
//!   extension's code runs. `["*"]` means "activate immediately on
//!   editor startup" — the highest-blast-radius value, and the one
//!   recent supply-chain droppers favour because it removes the
//!   need to convince a victim to invoke any specific command.
//!   `onStartupFinished` is a softer version of the same thing.
//! - `main`: the entry point JS the extension host runs.
//!   References to `child_process` / `node:vm` / `eval` inside that
//!   JS are obvious red flags, but the entry point first surfaces
//!   here.
//!
//! This module is **pure** — input bytes → result struct, no IO
//! beyond zip decoding. The proxy will call it on `.vsix` download
//! responses; CLI auditors can call it on locally cached `.vsix`
//! files to vet sideloads.
//!
//! Roadmap #25 + #26 extend the inspector to also walk the bundled
//! `node_modules/` tree (package identities → `bundled_dependencies`,
//! consumed by the proxy as one `InstallEvent` per dep so the existing
//! OSV / typosquat / install-inventory machinery sees them) and to run
//! the `sakimori-core::iocs` content-needle catalog over text-shaped
//! entries inside the zip (`ioc_hits`). Both extensions piggyback on
//! the single zip decode so cost stays bounded.
//!
//! Out of scope (still, per CLAUDE.md roadmap):
//!
//! - **`strip` mode** (rewrite `activationEvents: ["*"]` to `[]`
//!   and re-emit the zip). Substantially larger because we'd have
//!   to recompute the Marketplace integrity hash the editor then
//!   verifies. Audit / block are the load-bearing first slice.
//! - **`.crx`** (Chrome extensions). Chrome packages are signed
//!   end-to-end so strip is impossible by design; we'll wire `.crx`
//!   audit later (roadmap #28).
//! - **Bundled-bytes byte-identity check**. We audit *which* deps a
//!   publisher bundled by name + version, not whether the bundled
//!   tarball matches public-registry bytes — legitimate publishers
//!   patch deps before vendoring, which isn't a smell.

use std::io::{Cursor, Read};

use sakimori_core::iocs;
use serde::Deserialize;

/// Hard ceilings on the per-vsix walk so a malicious archive can't
/// stall the proxy. Both values are deliberately generous compared
/// to legitimate extensions (the biggest Marketplace extensions
/// are ~50 MiB compressed; `package.json` is at most a few KiB)
/// so they only fire on attack inputs.
pub const MAX_VSIX_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_PACKAGE_JSON_BYTES: usize = 1024 * 1024;

/// Maximum number of bundled `node_modules/**/package.json` entries
/// we'll parse out of a single `.vsix`. A clean extension's bundled
/// tree is at most a few hundred packages; 4096 leaves comfortable
/// headroom while preventing a pathological zip with millions of
/// fake manifest entries from blocking the proxy thread.
pub const MAX_BUNDLED_DEP_ENTRIES: usize = 4096;

/// Maximum number of zip entries we'll feed to the IOC content-needle
/// scanner. Independent of [`MAX_BUNDLED_DEP_ENTRIES`] because the
/// scanner reads text-shaped files (`*.js`, `*.json`, …) rather than
/// just `package.json`; a single bundled package can carry many such
/// files. 2048 is enough to cover any sane extension's first-party JS
/// without becoming a thread-burn vector.
pub const MAX_SCANNED_ENTRIES: usize = 2048;

/// What the inspector found in a `.vsix`.
///
/// `PartialEq`/`Eq` are intentionally absent: `iocs::Finding`
/// doesn't carry them (it's transport-shaped, with `PathBuf` and
/// `&'static str` fields whose equality semantics we don't want to
/// commit to). Tests that need to confirm "empty inspection" use
/// `is_empty_inspection`.
#[derive(Debug, Clone, Default)]
pub struct VsixInspection {
    /// `name` from `extension/package.json`. Empty when the manifest
    /// is missing or malformed.
    pub name: String,
    /// `publisher` from `extension/package.json`.
    pub publisher: String,
    /// `version` from `extension/package.json`.
    pub version: String,
    /// Raw `activationEvents` array from the manifest.
    pub activation_events: Vec<String>,
    /// `main` field — the JS entry the extension host loads.
    pub main: Option<String>,
    /// True when `activationEvents` contains the wildcard `"*"`
    /// or `onStartupFinished` — both fire without any user
    /// interaction. The block-mode decision keys off this.
    pub fires_on_startup: bool,
    /// `name` + `version` pairs harvested from
    /// `extension/node_modules/**/package.json`. Per roadmap #25,
    /// the proxy emits one `InstallEvent { Ecosystem::Npm }` per
    /// entry so the existing OSV / typosquat / install-inventory
    /// machinery audits bundled transitive deps the same way it
    /// audits top-level npm installs. Empty when the `.vsix` has
    /// no bundled tree or the walk bottomed out at the cap.
    pub bundled_dependencies: Vec<BundledDep>,
    /// IOC content-needle hits anywhere inside the `.vsix`. Per
    /// roadmap #26, paths are prefixed with the extension's archive-
    /// internal path (e.g. `extension/out/extension.js`) so the
    /// proxy can render them without ambiguity. High-severity hits
    /// trip a block in Block mode regardless of `fires_on_startup`.
    pub ioc_hits: Vec<iocs::Finding>,
    /// True iff the bundled-dep walk hit [`MAX_BUNDLED_DEP_ENTRIES`]
    /// and stopped early. Surfaced in logs so an operator seeing
    /// suspiciously short audits can correlate.
    pub bundled_dependencies_truncated: bool,
    /// True iff the IOC scan hit [`MAX_SCANNED_ENTRIES`] and stopped
    /// early.
    pub ioc_scan_truncated: bool,
}

/// One bundled transitive dependency inside a `.vsix`. Identity-
/// only (no integrity hash) — see the module docstring for why we
/// deliberately don't byte-compare against the public registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundledDep {
    /// `name` from the nested `package.json`. May be a scoped name
    /// like `@foo/bar`.
    pub name: String,
    /// `version` from the nested `package.json`. Empty when the
    /// manifest omits it (rare but legal — we still emit the entry
    /// so an operator can see what was shipped).
    pub version: String,
    /// Archive-internal path of the manifest, e.g.
    /// `extension/node_modules/foo/package.json`. Useful when two
    /// copies of the same package at different versions are
    /// bundled at different depths.
    pub manifest_path: String,
}

impl VsixInspection {
    /// Cheap accessor used by the block decision.
    pub fn has_startup_autorun(&self) -> bool {
        self.fires_on_startup
    }

    /// True when any IOC hit is High severity. Block-mode treats
    /// this as a deny independent of startup-autorun.
    pub fn has_high_severity_ioc(&self) -> bool {
        self.ioc_hits
            .iter()
            .any(|f| f.severity == iocs::Severity::High)
    }

    /// Test helper: true when this inspection carries no extracted
    /// information (no manifest fields, no bundled deps, no IOC
    /// hits). Replaces the previous `PartialEq` against
    /// `VsixInspection::default()` (impossible now that
    /// `iocs::Finding` doesn't implement `PartialEq`).
    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
            && self.publisher.is_empty()
            && self.version.is_empty()
            && self.activation_events.is_empty()
            && self.main.is_none()
            && !self.fires_on_startup
            && self.bundled_dependencies.is_empty()
            && self.ioc_hits.is_empty()
    }
}

#[derive(Debug)]
pub enum VsixInspectError {
    /// Body exceeded [`MAX_VSIX_BYTES`] — we refuse to walk it.
    TooLarge { size: usize },
    /// Bytes don't open as a zip archive.
    NotZip(String),
    /// `extension/package.json` exists but is past
    /// [`MAX_PACKAGE_JSON_BYTES`]; an honest extension manifest is
    /// at most a few KiB.
    ManifestTooLarge { size: u64 },
    /// IO error while reading the manifest entry.
    ManifestRead(String),
}

impl std::fmt::Display for VsixInspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { size } => {
                write!(
                    f,
                    "vsix body too large: {size} bytes (cap {MAX_VSIX_BYTES})"
                )
            }
            Self::NotZip(s) => write!(f, "vsix is not a valid zip: {s}"),
            Self::ManifestTooLarge { size } => {
                write!(
                    f,
                    "extension/package.json too large: {size} bytes (cap {MAX_PACKAGE_JSON_BYTES})"
                )
            }
            Self::ManifestRead(s) => write!(f, "reading extension/package.json: {s}"),
        }
    }
}

impl std::error::Error for VsixInspectError {}

#[derive(Debug, Deserialize)]
struct ManifestSlice {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "activationEvents")]
    activation_events: Option<Vec<String>>,
    #[serde(default)]
    main: Option<String>,
}

/// Inspect a `.vsix` body. Returns the structured manifest fields
/// plus a derived `fires_on_startup` flag the proxy uses to decide
/// audit / block.
///
/// Fail-open shape: a `.vsix` we can't *parse* (corrupt zip, missing
/// manifest, manifest that doesn't deserialise) returns the default
/// [`VsixInspection`] and the policy layer treats it as "no startup
/// autorun observed". This matches the npm inspector's behaviour —
/// defence shouldn't fabricate denials on malformed-but-legitimate
/// artefacts, and the editor itself will reject a truly broken
/// `.vsix` regardless. The errors returned are the
/// definitely-malicious shape: oversized body, oversized manifest.
pub fn inspect_vsix(body: &[u8]) -> Result<VsixInspection, VsixInspectError> {
    if body.len() > MAX_VSIX_BYTES {
        return Err(VsixInspectError::TooLarge { size: body.len() });
    }
    // `zip` requires Seek; wrap a Cursor.
    let cursor = Cursor::new(body);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => return Err(VsixInspectError::NotZip(e.to_string())),
    };

    // Single pass over zip entry names — pulling out the top-level
    // manifest path, every bundled `node_modules/**/package.json`,
    // and every IOC-eligible text-shaped path. We collect names
    // (and indices) first because `ZipArchive::by_index` mutably
    // borrows the archive, which would otherwise conflict with
    // iterating over `file_names`.
    let mut top_manifest_idx: Option<usize> = None;
    let mut bundled_idxs: Vec<usize> = Vec::new();
    let mut bundled_paths: Vec<String> = Vec::new();
    let mut ioc_candidate_idxs: Vec<usize> = Vec::new();
    let mut ioc_candidate_paths: Vec<String> = Vec::new();
    let mut bundled_truncated = false;
    let mut ioc_truncated = false;

    for i in 0..archive.len() {
        let raw_name = match archive
            .by_index_raw(i)
            .and_then(|f| f.name().map(|n| n.into_owned()))
        {
            Ok(name) => name,
            Err(_) => continue,
        };
        if raw_name == "extension/package.json" {
            top_manifest_idx = Some(i);
            continue;
        }
        if is_bundled_manifest_path(&raw_name) {
            if bundled_idxs.len() >= MAX_BUNDLED_DEP_ENTRIES {
                bundled_truncated = true;
            } else {
                bundled_idxs.push(i);
                bundled_paths.push(raw_name.clone());
            }
        }
        if is_ioc_candidate_path(&raw_name) {
            if ioc_candidate_idxs.len() >= MAX_SCANNED_ENTRIES {
                ioc_truncated = true;
            } else {
                ioc_candidate_idxs.push(i);
                ioc_candidate_paths.push(raw_name);
            }
        }
    }

    let mut inspection = if let Some(idx) = top_manifest_idx {
        let mut entry = archive
            .by_index(idx)
            .map_err(|e| VsixInspectError::NotZip(e.to_string()))?;
        if entry.size() > MAX_PACKAGE_JSON_BYTES as u64 {
            return Err(VsixInspectError::ManifestTooLarge { size: entry.size() });
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        if let Err(e) = entry.read_to_end(&mut buf) {
            return Err(VsixInspectError::ManifestRead(e.to_string()));
        }
        parse_manifest(&buf)
    } else {
        // Same fail-open shape as the npm inspector: a zip without
        // a recognisable manifest yields a default Inspection.
        // Don't punish weird-but-valid packages.
        VsixInspection::default()
    };

    // Bundled-dep walk (#25). Each entry that parses as a manifest
    // becomes a `BundledDep`; entries that fail to parse are
    // silently skipped (fail-open).
    for (idx, path) in bundled_idxs.iter().zip(bundled_paths.iter()) {
        let Ok(mut entry) = archive.by_index(*idx) else {
            continue;
        };
        if entry.size() > MAX_PACKAGE_JSON_BYTES as u64 {
            // A bundled manifest past the cap is almost certainly
            // garbage / adversarial — skip rather than abort the
            // whole inspection. The top-level cap stays a hard error
            // because that file is required for the proxy to
            // function at all.
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }
        if let Some(dep) = parse_bundled_manifest(&buf, path) {
            inspection.bundled_dependencies.push(dep);
        }
    }
    inspection.bundled_dependencies_truncated = bundled_truncated;

    // IOC content scan (#26). Read each candidate up to the iocs
    // module's per-file cap; match against the content-needle
    // catalog. Path prefixed with the extension's archive-internal
    // path so the proxy log surfaces "vsix:foo.bar@1.0.0/<path>"
    // unambiguously (the prefix is added by the proxy, not here —
    // we keep raw archive paths).
    for (idx, path) in ioc_candidate_idxs.iter().zip(ioc_candidate_paths.iter()) {
        let Ok(mut entry) = archive.by_index(*idx) else {
            continue;
        };
        let cap = iocs::MAX_CONTENT_BYTES.min(entry.size() as usize);
        let mut buf = vec![0u8; 0];
        buf.reserve(cap);
        // Read at most MAX_CONTENT_BYTES — same ceiling the path-
        // rooted scanner uses on disk. Past 64 KiB the threat model
        // (substring of an exfil URL) doesn't extend usefully.
        if (&mut entry)
            .take(iocs::MAX_CONTENT_BYTES as u64)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }
        let basename = path.rsplit('/').next().unwrap_or(path);
        for rule in iocs::matches_content(basename, &buf) {
            inspection.ioc_hits.push(iocs::Finding {
                path: std::path::PathBuf::from(path),
                rule_id: rule.id,
                family: rule.family,
                severity: rule.severity,
                description: rule.description,
            });
        }
    }
    inspection.ioc_scan_truncated = ioc_truncated;

    Ok(inspection)
}

/// True iff `path` is a `package.json` nested inside the
/// `extension/node_modules/` tree at any depth. Rejects the
/// extension's own top-level manifest, `.bin` stubs, and anything
/// outside the `extension/` root (defence against zip-slip-flavoured
/// `../node_modules/...` paths even though we never extract to disk).
fn is_bundled_manifest_path(path: &str) -> bool {
    if !path.starts_with("extension/node_modules/") {
        return false;
    }
    if !path.ends_with("/package.json") {
        return false;
    }
    // Reject any path containing `..` — defence in depth.
    if path.split('/').any(|c| c == ".." || c.is_empty()) {
        return false;
    }
    true
}

/// True iff `path` should be fed to the IOC content scanner. Bound
/// to text-shaped extensions so we don't read multi-MB binary blobs
/// (icons, sourcemaps, native `.node` addons).
fn is_ioc_candidate_path(path: &str) -> bool {
    if !path.starts_with("extension/") {
        return false;
    }
    if path.ends_with('/') {
        return false; // directory entry
    }
    let lower = path.to_ascii_lowercase();
    const TEXT_EXTS: &[&str] = &[
        ".js", ".mjs", ".cjs", ".json", ".ts", ".mts", ".cts", ".sh", ".bash", ".zsh", ".ps1",
        ".bat", ".cmd",
    ];
    TEXT_EXTS.iter().any(|ext| lower.ends_with(ext))
}

fn parse_manifest(body: &[u8]) -> VsixInspection {
    let m: ManifestSlice = match serde_json::from_slice(body) {
        Ok(m) => m,
        Err(_) => return VsixInspection::default(),
    };
    let activation_events = m.activation_events.unwrap_or_default();
    let fires_on_startup = activation_events
        .iter()
        .any(|e| e == "*" || e == "onStartupFinished");
    VsixInspection {
        name: m.name.unwrap_or_default(),
        publisher: m.publisher.unwrap_or_default(),
        version: m.version.unwrap_or_default(),
        activation_events,
        main: m.main,
        fires_on_startup,
        bundled_dependencies: Vec::new(),
        ioc_hits: Vec::new(),
        bundled_dependencies_truncated: false,
        ioc_scan_truncated: false,
    }
}

#[derive(Debug, Deserialize)]
struct BundledManifestSlice {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

fn parse_bundled_manifest(body: &[u8], path: &str) -> Option<BundledDep> {
    let m: BundledManifestSlice = serde_json::from_slice(body).ok()?;
    let name = m.name.unwrap_or_default();
    if name.is_empty() {
        // A nested `package.json` without a `name` field is almost
        // certainly malformed; skip rather than emit a placeholder
        // InstallEvent the OSV scanner can't do anything with.
        return None;
    }
    Some(BundledDep {
        name,
        version: m.version.unwrap_or_default(),
        manifest_path: path.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Build a synthetic `.vsix`: a zip containing
    /// `extension/package.json` (the only entry the inspector
    /// cares about) plus a junk entry to confirm extra files are
    /// ignored.
    fn build_vsix(manifest_json: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("[Content_Types].xml", opts).unwrap();
            zw.write_all(b"<types/>").unwrap();
            zw.start_file("extension/package.json", opts).unwrap();
            zw.write_all(manifest_json.as_bytes()).unwrap();
            zw.start_file("extension/README.md", opts).unwrap();
            zw.write_all(b"# noise").unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_manifest_fields_and_flags_wildcard_activation() {
        let body = build_vsix(
            r#"{
                "name": "evil-ext",
                "publisher": "attacker",
                "version": "1.0.0",
                "main": "./out/extension.js",
                "activationEvents": ["*"]
            }"#,
        );
        let i = inspect_vsix(&body).unwrap();
        assert_eq!(i.name, "evil-ext");
        assert_eq!(i.publisher, "attacker");
        assert_eq!(i.version, "1.0.0");
        assert_eq!(i.main.as_deref(), Some("./out/extension.js"));
        assert_eq!(i.activation_events, vec!["*".to_string()]);
        assert!(i.fires_on_startup, "wildcard `*` must flag startup autorun");
        assert!(i.has_startup_autorun());
    }

    #[test]
    fn on_startup_finished_also_flags_startup_autorun() {
        let body = build_vsix(
            r#"{
                "name": "x", "publisher": "y", "version": "1.0.0",
                "activationEvents": ["onStartupFinished"]
            }"#,
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(i.fires_on_startup);
    }

    #[test]
    fn lazy_activation_events_do_not_flag_startup_autorun() {
        // `onCommand`, `onLanguage`, `workspaceContains`, etc. are
        // user/file-triggered — they don't run code until the user
        // does something specific. These must NOT trip the block
        // signal.
        let body = build_vsix(
            r#"{
                "name": "x", "publisher": "y", "version": "1.0.0",
                "activationEvents": [
                  "onCommand:foo.bar",
                  "onLanguage:rust",
                  "workspaceContains:**/Cargo.toml"
                ]
            }"#,
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(!i.fires_on_startup);
        assert_eq!(i.activation_events.len(), 3);
    }

    #[test]
    fn missing_activation_events_field_is_safe() {
        // Modern VSCode extensions can omit `activationEvents`
        // entirely (the `contributes` keys imply lazy activation).
        // Inspector must treat absence as "no startup autorun".
        let body = build_vsix(r#"{ "name": "x", "publisher": "y", "version": "1.0.0" }"#);
        let i = inspect_vsix(&body).unwrap();
        assert!(!i.fires_on_startup);
        assert!(i.activation_events.is_empty());
    }

    #[test]
    fn missing_manifest_yields_default_inspection_not_error() {
        // A zip that's parseable but doesn't contain `extension/
        // package.json` returns a default Inspection. Some
        // hand-crafted .vsix variants legitimately omit fields;
        // we don't want to false-positive on weird-but-valid.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            zw.start_file("misc.txt", SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"hi").unwrap();
            zw.finish().unwrap();
        }
        let i = inspect_vsix(&buf).unwrap();
        assert!(i.is_empty(), "expected empty inspection, got {i:?}");
    }

    #[test]
    fn malformed_manifest_json_yields_default_inspection() {
        let body = build_vsix("{not json");
        let i = inspect_vsix(&body).unwrap();
        assert!(i.is_empty(), "expected empty inspection, got {i:?}");
    }

    #[test]
    fn non_zip_input_returns_err_not_zip() {
        let body = b"this is not a zip file";
        let err = inspect_vsix(body).unwrap_err();
        assert!(matches!(err, VsixInspectError::NotZip(_)), "got {err:?}");
    }

    #[test]
    fn oversized_body_is_rejected_before_walking() {
        // The check is a length comparison — we can use a Vec of
        // any byte content past the cap, no need for it to be
        // valid zip data.
        let body = vec![0u8; MAX_VSIX_BYTES + 1];
        let err = inspect_vsix(&body).unwrap_err();
        assert!(
            matches!(err, VsixInspectError::TooLarge { .. }),
            "got {err:?}"
        );
    }

    /// Build a synthetic `.vsix` that ships a top-level manifest plus
    /// the named files (path → bytes) — exercises the bundled-dep
    /// walker (#25) and the IOC content scanner (#26) in one shot.
    fn build_vsix_with_files(manifest_json: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("[Content_Types].xml", opts).unwrap();
            zw.write_all(b"<types/>").unwrap();
            zw.start_file("extension/package.json", opts).unwrap();
            zw.write_all(manifest_json.as_bytes()).unwrap();
            for (path, bytes) in files {
                zw.start_file(*path, opts).unwrap();
                zw.write_all(bytes).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn bundled_node_modules_manifests_are_extracted_as_install_events() {
        // Two bundled packages at different depths: top-level `foo`
        // and `bar` nested inside `foo`. Both must surface so the
        // proxy can emit one InstallEvent per dep into the inventory.
        let body = build_vsix_with_files(
            r#"{ "name": "ext", "publisher": "pub", "version": "1.0.0" }"#,
            &[
                (
                    "extension/node_modules/foo/package.json",
                    br#"{ "name": "foo", "version": "1.2.3" }"#,
                ),
                (
                    "extension/node_modules/foo/node_modules/bar/package.json",
                    br#"{ "name": "bar", "version": "0.0.1" }"#,
                ),
                (
                    "extension/node_modules/@scope/baz/package.json",
                    br#"{ "name": "@scope/baz", "version": "9.9.9" }"#,
                ),
            ],
        );
        let i = inspect_vsix(&body).unwrap();
        assert_eq!(i.bundled_dependencies.len(), 3);
        let names: Vec<_> = i.bundled_dependencies.iter().map(|d| &d.name).collect();
        assert!(names.iter().any(|n| n.as_str() == "foo"));
        assert!(names.iter().any(|n| n.as_str() == "bar"));
        assert!(names.iter().any(|n| n.as_str() == "@scope/baz"));
        assert!(!i.bundled_dependencies_truncated);
    }

    #[test]
    fn bundled_walk_skips_manifests_without_name_field() {
        // A nested package.json without `name` is almost certainly
        // malformed; emitting an InstallEvent with an empty name
        // would pollute the inventory and the OSV scan can't do
        // anything with it.
        let body = build_vsix_with_files(
            r#"{ "name": "ext", "publisher": "pub", "version": "1.0.0" }"#,
            &[
                (
                    "extension/node_modules/foo/package.json",
                    br#"{ "version": "1.2.3" }"#,
                ),
                (
                    "extension/node_modules/bar/package.json",
                    br#"{ "name": "bar", "version": "1.0.0" }"#,
                ),
            ],
        );
        let i = inspect_vsix(&body).unwrap();
        assert_eq!(i.bundled_dependencies.len(), 1);
        assert_eq!(i.bundled_dependencies[0].name, "bar");
    }

    #[test]
    fn bundled_walk_ignores_paths_outside_extension_node_modules() {
        // `package.json` files that aren't under the bundled tree
        // (the top-level manifest, a `package.json` sample sitting
        // in `extension/test/`) must not show up as bundled deps.
        let body = build_vsix_with_files(
            r#"{ "name": "ext", "publisher": "pub", "version": "1.0.0" }"#,
            &[(
                "extension/test/package.json",
                br#"{ "name": "should-not-appear", "version": "1.0.0" }"#,
            )],
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(i.bundled_dependencies.is_empty());
    }

    #[test]
    fn ioc_content_scan_flags_webhook_site_in_bundled_js() {
        // The iocs catalog ships a webhook.site needle (High severity).
        // Stash it inside a bundled JS file and confirm the inspector
        // surfaces a finding the proxy can act on.
        let body = build_vsix_with_files(
            r#"{ "name": "ext", "publisher": "pub", "version": "1.0.0" }"#,
            &[(
                "extension/out/extension.js",
                b"fetch('https://webhook.site/abc-def-123');",
            )],
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(
            !i.ioc_hits.is_empty(),
            "webhook.site content needle should fire on bundled JS"
        );
        assert!(i.has_high_severity_ioc());
        assert_eq!(
            i.ioc_hits[0].path.to_string_lossy(),
            "extension/out/extension.js"
        );
    }

    #[test]
    fn ioc_content_scan_skips_binary_extensions() {
        // Native addons / sourcemaps / icons must not be fed to the
        // scanner. Even if they happened to contain the needle as a
        // substring, reading multi-MB binary blobs on the hot path
        // is a thread-burn vector we explicitly bound.
        let body = build_vsix_with_files(
            r#"{ "name": "ext", "publisher": "pub", "version": "1.0.0" }"#,
            &[(
                "extension/native/addon.node",
                b"webhook.site -- but binary, never read",
            )],
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(
            i.ioc_hits.is_empty(),
            "binary entries must not be scanned for content needles"
        );
    }

    #[test]
    fn is_bundled_manifest_path_rejects_traversal_and_non_nm_paths() {
        assert!(is_bundled_manifest_path(
            "extension/node_modules/foo/package.json"
        ));
        assert!(is_bundled_manifest_path(
            "extension/node_modules/@scope/foo/package.json"
        ));
        assert!(!is_bundled_manifest_path("extension/package.json"));
        assert!(!is_bundled_manifest_path("node_modules/foo/package.json"));
        assert!(!is_bundled_manifest_path(
            "extension/node_modules/../etc/passwd/package.json"
        ));
        assert!(!is_bundled_manifest_path(
            "extension/node_modules/foo/package.json.bak"
        ));
    }
}

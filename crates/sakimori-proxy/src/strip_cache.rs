//! Strip cache shared between the tarball handler and the packument
//! rewriter (Phase 2 of lifecycle `strip` mode).
//!
//! The cache holds, per `(name, version, orig_integrity)` key, either
//! the rewritten tarball bytes + new hashes (for versions whose
//! `package.json` shipped install-time scripts) or a "no-strip needed"
//! marker (for benign versions we've already inspected). The
//! packument rewriter consults the cache to update `dist.integrity` /
//! `dist.shasum` and drop `dist.attestations` for stripped entries
//! before npm sees the metadata; the tarball handler consults the
//! cache to decide whether to ship the rewritten bytes or pass the
//! upstream tarball through unchanged.
//!
//! Phase 2b: optional **on-disk persistence** at
//! `~/.sakimori/strip-cache/` (or wherever the operator points the
//! `--lifecycle-strip-cache-dir` flag). Layout is flat: each entry is
//! a `<sha256-of-key>.json` metadata file paired with a
//! `<sha256-of-key>.tgz` body file (the latter only for `Stripped`
//! entries). Writes are atomic — `tmp` + rename — so a crashed proxy
//! can never leave a half-written entry that loads back as a torn
//! record. The cache loads any existing entries on construction so a
//! restarted proxy hits the same `(name, version)` warm; this is
//! what makes lockfile-pinned re-installs and `npx`-style ephemeral
//! flows succeed without `EINTEGRITY` between proxy runs.
//!
//! No eviction in v0 — operators that need bounded growth can
//! `rm -rf` the cache directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Cache key. `orig_integrity` is the SRI string that the upstream
/// packument advertised for this `(name, version)` *before* any
/// rewriting (e.g. `sha512-<base64>`). Including it in the key
/// guarantees that a mirror serving different bytes for the same
/// `(name, version)` does not pull a stale cache entry.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StripKey {
    pub name: String,
    pub version: String,
    pub orig_integrity: String,
}

impl StripKey {
    /// Stable file basename for this key — sha-256 of
    /// `name|version|orig_integrity` rendered as lowercase hex.
    /// Chosen over plain `name/version/orig_integrity` because npm
    /// names may contain `@/`, versions may contain prerelease
    /// punctuation, and orig_integrity is base64 (slashes). The
    /// metadata file inside carries the original key so a human
    /// reading the cache can still see the package identity.
    fn basename(&self) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(self.name.as_bytes());
        h.update(b"|");
        h.update(self.version.as_bytes());
        h.update(b"|");
        h.update(self.orig_integrity.as_bytes());
        let digest = h.finalize();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
        out
    }
}

#[derive(Debug, Clone)]
pub enum StripCacheEntry {
    /// Tarball was rewritten. Serve `bytes` from the tarball handler;
    /// packument rewriter swaps in `new_integrity` / `new_shasum` and
    /// drops `dist.attestations`.
    Stripped {
        new_integrity: String, // "sha512-<base64>"
        new_shasum: String,    // hex
        bytes: Arc<Vec<u8>>,   // Arc so packument/tarball clones are cheap
    },
    /// We inspected this version and it carries no install-time
    /// lifecycle scripts. Serve the original tarball unchanged;
    /// packument integrity is correct as-is.
    NoStripNeeded,
}

impl StripCacheEntry {
    /// Returns the rewritten SRI string when this entry represents a
    /// stripped tarball, otherwise `None` (the original integrity
    /// stays correct for `NoStripNeeded` entries).
    pub fn new_integrity(&self) -> Option<&str> {
        match self {
            Self::Stripped { new_integrity, .. } => Some(new_integrity),
            Self::NoStripNeeded => None,
        }
    }

    pub fn new_shasum(&self) -> Option<&str> {
        match self {
            Self::Stripped { new_shasum, .. } => Some(new_shasum),
            Self::NoStripNeeded => None,
        }
    }
}

/// On-disk metadata format. Versioned so future schema changes can
/// detect-and-skip rather than mis-decode. The bytes (for `Stripped`
/// entries) live in a sibling `.tgz` file rather than embedded here
/// — npm tarballs are typically 10 KiB–5 MiB and base64-in-JSON
/// would inflate the file 33% on top of having to re-parse on every
/// load.
#[derive(Debug, Serialize, Deserialize)]
struct OnDiskMetadata {
    v: u32,
    name: String,
    version: String,
    orig_integrity: String,
    #[serde(flatten)]
    kind: OnDiskKind,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum OnDiskKind {
    #[serde(rename = "stripped")]
    Stripped {
        new_integrity: String,
        new_shasum: String,
    },
    #[serde(rename = "no_strip_needed")]
    NoStripNeeded,
}

const ON_DISK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Default)]
pub struct StripCache {
    inner: Mutex<HashMap<StripKey, StripCacheEntry>>,
    /// `None` = in-memory only (the test default + the
    /// `--lifecycle-no-strip-cache` opt-out). `Some(path)` = every
    /// `insert` also writes through to `<path>/<basename>.{json,tgz}`
    /// atomically, and `with_persist_dir` loads any existing entries
    /// at startup.
    persist_dir: Option<PathBuf>,
}

impl StripCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a persistent cache rooted at `dir`. The directory
    /// is created if missing. Any existing valid entries are loaded
    /// into memory eagerly. Entries whose schema version doesn't
    /// match or whose paired `.tgz` is missing are skipped with a
    /// warn log — the proxy then re-derives them on the next install.
    pub fn with_persist_dir(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let mut map: HashMap<StripKey, StripCacheEntry> = HashMap::new();
        load_dir_into(&dir, &mut map);
        Ok(Self {
            inner: Mutex::new(map),
            persist_dir: Some(dir),
        })
    }

    pub fn get(&self, key: &StripKey) -> Option<StripCacheEntry> {
        self.inner
            .lock()
            .expect("strip cache poisoned")
            .get(key)
            .cloned()
    }

    /// Insert into the in-memory map and, when persistence is on,
    /// also write through to disk. Disk write failures are logged
    /// at warn level but do not propagate — a broken persist layer
    /// must not break installs; we just lose the cross-restart
    /// benefit.
    pub fn insert(&self, key: StripKey, entry: StripCacheEntry) {
        if let Some(dir) = self.persist_dir.as_ref()
            && let Err(e) = persist_entry(dir, &key, &entry)
        {
            log::warn!(
                "strip-cache: persist failed for {}@{}: {e}",
                key.name,
                key.version,
            );
        }
        self.inner
            .lock()
            .expect("strip cache poisoned")
            .insert(key, entry);
    }

    /// Number of cached entries — exposed for tests and the doctor
    /// path. O(1) under the Mutex.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("strip cache poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pure-in-memory test helper. Equivalent to `new()` but spelt
    /// out so test code reads obviously.
    #[cfg(test)]
    pub(crate) fn in_memory_only() -> Self {
        Self::new()
    }
}

/// Write `<basename>.tgz` (for `Stripped`) then `<basename>.json`
/// last, both via tmp + rename. Ordering matters on load: a
/// half-written run that crashed after the `.tgz` rename but before
/// the `.json` rename leaves an orphan `.tgz` (cheap to clean up
/// out-of-band) but no torn metadata. A crash between `.json.tmp`
/// write and rename leaves a `.json.tmp` file the load step
/// recognises and skips.
fn persist_entry(dir: &Path, key: &StripKey, entry: &StripCacheEntry) -> std::io::Result<()> {
    let basename = key.basename();
    let json_path = dir.join(format!("{basename}.json"));
    let tgz_path = dir.join(format!("{basename}.tgz"));
    let (kind, body): (OnDiskKind, Option<&Arc<Vec<u8>>>) = match entry {
        StripCacheEntry::Stripped {
            new_integrity,
            new_shasum,
            bytes,
        } => (
            OnDiskKind::Stripped {
                new_integrity: new_integrity.clone(),
                new_shasum: new_shasum.clone(),
            },
            Some(bytes),
        ),
        StripCacheEntry::NoStripNeeded => (OnDiskKind::NoStripNeeded, None),
    };
    if let Some(bytes) = body {
        atomic_write(&tgz_path, bytes.as_slice())?;
    } else {
        // Remove a stale .tgz if we're overwriting a previously-
        // Stripped entry with a NoStripNeeded verdict (rare but
        // possible if the upstream re-published the tarball).
        let _ = std::fs::remove_file(&tgz_path);
    }
    let meta = OnDiskMetadata {
        v: ON_DISK_SCHEMA_VERSION,
        name: key.name.clone(),
        version: key.version.clone(),
        orig_integrity: key.orig_integrity.clone(),
        kind,
    };
    let json = serde_json::to_vec(&meta).map_err(std::io::Error::other)?;
    atomic_write(&json_path, &json)?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_data()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Walk `dir` for `<basename>.json` files, decode each, pair with
/// the sibling `.tgz` when the metadata declares a `Stripped` entry,
/// and insert into `map`. Quiet on missing/unknown files; warns on
/// schema-mismatch + body-missing because those represent a real
/// data-quality issue worth surfacing.
fn load_dir_into(dir: &Path, map: &mut HashMap<StripKey, StripCacheEntry>) {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("strip-cache: read_dir({}) failed: {e}", dir.display());
            return;
        }
    };
    let mut loaded = 0usize;
    for ent in read.flatten() {
        let path = ent.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if ext != "json" {
            continue;
        }
        // Skip half-written tmp files.
        if stem.ends_with(".json") {
            continue;
        }
        let json = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("strip-cache: read {} failed: {e}", path.display());
                continue;
            }
        };
        let meta: OnDiskMetadata = match serde_json::from_slice(&json) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("strip-cache: skipping malformed {}: {e}", path.display());
                continue;
            }
        };
        if meta.v != ON_DISK_SCHEMA_VERSION {
            log::warn!(
                "strip-cache: skipping {} — schema version {} != {ON_DISK_SCHEMA_VERSION}",
                path.display(),
                meta.v,
            );
            continue;
        }
        let key = StripKey {
            name: meta.name,
            version: meta.version,
            orig_integrity: meta.orig_integrity,
        };
        // Cross-check: the basename on disk must match the one we'd
        // re-derive from the key. Defends against a manually edited
        // metadata file pointing the wrong way.
        if stem != key.basename() {
            log::warn!(
                "strip-cache: skipping {} — basename {stem} doesn't match recomputed {}",
                path.display(),
                key.basename(),
            );
            continue;
        }
        let entry = match meta.kind {
            OnDiskKind::Stripped {
                new_integrity,
                new_shasum,
            } => {
                let tgz_path = dir.join(format!("{stem}.tgz"));
                let bytes = match std::fs::read(&tgz_path) {
                    Ok(b) => b,
                    Err(e) => {
                        log::warn!(
                            "strip-cache: skipping {} — missing/unreadable body {}: {e}",
                            path.display(),
                            tgz_path.display(),
                        );
                        continue;
                    }
                };
                StripCacheEntry::Stripped {
                    new_integrity,
                    new_shasum,
                    bytes: Arc::new(bytes),
                }
            }
            OnDiskKind::NoStripNeeded => StripCacheEntry::NoStripNeeded,
        };
        map.insert(key, entry);
        loaded += 1;
    }
    if loaded > 0 {
        log::info!(
            "strip-cache: loaded {loaded} entr{} from {}",
            if loaded == 1 { "y" } else { "ies" },
            dir.display(),
        );
    }
}

/// Default persist directory under the user's home dir. Returns
/// `None` if `$HOME` is unresolvable (rare — sandboxed environments
/// without a home). Callers should then fall back to the in-memory
/// constructor with a warn log.
pub fn default_persist_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push(".sakimori");
    p.push("strip-cache");
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("sakimori-strip-cache-{tag}-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn get_returns_inserted_entry() {
        let cache = StripCache::in_memory_only();
        let key = StripKey {
            name: "left-pad".into(),
            version: "1.3.0".into(),
            orig_integrity: "sha512-abcd".into(),
        };
        let entry = StripCacheEntry::Stripped {
            new_integrity: "sha512-xyz".into(),
            new_shasum: "deadbeef".into(),
            bytes: Arc::new(vec![1, 2, 3]),
        };
        cache.insert(key.clone(), entry);
        let got = cache.get(&key).expect("cache hit");
        assert_eq!(got.new_integrity(), Some("sha512-xyz"));
        assert_eq!(got.new_shasum(), Some("deadbeef"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn no_strip_needed_returns_no_new_integrity() {
        let cache = StripCache::in_memory_only();
        let key = StripKey {
            name: "x".into(),
            version: "1.0.0".into(),
            orig_integrity: "sha512-a".into(),
        };
        cache.insert(key.clone(), StripCacheEntry::NoStripNeeded);
        let got = cache.get(&key).unwrap();
        assert_eq!(got.new_integrity(), None);
        assert_eq!(got.new_shasum(), None);
    }

    #[test]
    fn key_includes_orig_integrity() {
        let cache = StripCache::in_memory_only();
        let base = StripKey {
            name: "x".into(),
            version: "1.0.0".into(),
            orig_integrity: "sha512-a".into(),
        };
        let mut alt = base.clone();
        alt.orig_integrity = "sha512-b".into();
        cache.insert(base.clone(), StripCacheEntry::NoStripNeeded);
        assert!(cache.get(&alt).is_none());
        assert!(cache.get(&base).is_some());
    }

    #[test]
    fn persistent_cache_round_trips_stripped_entry() {
        let dir = tmpdir("roundtrip-stripped");
        let key = StripKey {
            name: "@scope/pkg".into(),
            version: "2.0.0-beta.1".into(),
            orig_integrity: "sha512-Original==".into(),
        };
        let bytes = b"the rewritten gzipped tarball bytes go here".to_vec();
        {
            let cache = StripCache::with_persist_dir(dir.clone()).unwrap();
            cache.insert(
                key.clone(),
                StripCacheEntry::Stripped {
                    new_integrity: "sha512-NewValue==".into(),
                    new_shasum: "abc123".into(),
                    bytes: Arc::new(bytes.clone()),
                },
            );
        }
        let cache2 = StripCache::with_persist_dir(dir.clone()).unwrap();
        let got = cache2
            .get(&key)
            .expect("entry should persist across constructions");
        match got {
            StripCacheEntry::Stripped {
                new_integrity,
                new_shasum,
                bytes: b,
            } => {
                assert_eq!(new_integrity, "sha512-NewValue==");
                assert_eq!(new_shasum, "abc123");
                assert_eq!(*b, bytes);
            }
            other => panic!("expected Stripped, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistent_cache_round_trips_no_strip_needed_entry() {
        let dir = tmpdir("roundtrip-nostrip");
        let key = StripKey {
            name: "boring".into(),
            version: "1.0.0".into(),
            orig_integrity: "sha512-X".into(),
        };
        {
            let cache = StripCache::with_persist_dir(dir.clone()).unwrap();
            cache.insert(key.clone(), StripCacheEntry::NoStripNeeded);
        }
        let cache2 = StripCache::with_persist_dir(dir.clone()).unwrap();
        let got = cache2.get(&key).expect("hit");
        assert!(matches!(got, StripCacheEntry::NoStripNeeded));
        // No .tgz expected for NoStripNeeded entries.
        let basename = key.basename();
        assert!(!dir.join(format!("{basename}.tgz")).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistent_cache_skips_missing_tgz() {
        let dir = tmpdir("orphan-meta");
        let key = StripKey {
            name: "p".into(),
            version: "1.0.0".into(),
            orig_integrity: "sha512-Z".into(),
        };
        {
            let cache = StripCache::with_persist_dir(dir.clone()).unwrap();
            cache.insert(
                key.clone(),
                StripCacheEntry::Stripped {
                    new_integrity: "sha512-N".into(),
                    new_shasum: "ff".into(),
                    bytes: Arc::new(vec![0; 32]),
                },
            );
        }
        // Drop just the body file — simulates a partial cleanup.
        let basename = key.basename();
        std::fs::remove_file(dir.join(format!("{basename}.tgz"))).unwrap();
        let cache2 = StripCache::with_persist_dir(dir.clone()).unwrap();
        assert!(cache2.get(&key).is_none(), "missing tgz should skip entry");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistent_cache_skips_wrong_schema_version() {
        let dir = tmpdir("wrong-schema");
        let key = StripKey {
            name: "p".into(),
            version: "1.0.0".into(),
            orig_integrity: "sha512-Z".into(),
        };
        let basename = key.basename();
        let bad = serde_json::json!({
            "v": ON_DISK_SCHEMA_VERSION + 99,
            "name": key.name,
            "version": key.version,
            "orig_integrity": key.orig_integrity,
            "kind": "no_strip_needed",
        });
        std::fs::write(
            dir.join(format!("{basename}.json")),
            serde_json::to_vec(&bad).unwrap(),
        )
        .unwrap();
        let cache = StripCache::with_persist_dir(dir.clone()).unwrap();
        assert!(
            cache.get(&key).is_none(),
            "future-schema entry must be skipped"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistent_cache_skips_basename_mismatch() {
        let dir = tmpdir("basename-mismatch");
        let actual_key = StripKey {
            name: "real".into(),
            version: "1.0.0".into(),
            orig_integrity: "sha512-Z".into(),
        };
        // Write metadata under the WRONG basename (somebody hand-
        // edited or renamed). Cache must refuse rather than admit a
        // pair that wouldn't re-derive consistently.
        let bad_basename = "0000000000000000000000000000000000000000000000000000000000000000";
        let meta = serde_json::json!({
            "v": ON_DISK_SCHEMA_VERSION,
            "name": actual_key.name,
            "version": actual_key.version,
            "orig_integrity": actual_key.orig_integrity,
            "kind": "no_strip_needed",
        });
        std::fs::write(
            dir.join(format!("{bad_basename}.json")),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        let cache = StripCache::with_persist_dir(dir.clone()).unwrap();
        assert!(cache.get(&actual_key).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn default_persist_dir_uses_home() {
        // Don't assert specific path because test environments
        // vary; just check the structure when HOME is set.
        if std::env::var_os("HOME").is_some() {
            let p = default_persist_dir().expect("HOME present");
            assert!(p.ends_with(".sakimori/strip-cache"));
        }
    }
}

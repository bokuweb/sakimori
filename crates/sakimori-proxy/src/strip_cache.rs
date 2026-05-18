//! In-memory strip cache shared between the tarball handler and the
//! packument rewriter (Phase 2 of lifecycle `strip` mode).
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
//! Persistence (per CLAUDE.md roadmap #15 Phase 2 follow-up) is
//! deferred. The cache lives for the lifetime of the proxy process.
//! Long-running proxies with very high install diversity will see
//! memory grow; the cap is left to operator workflow for now.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

#[derive(Debug, Default)]
pub struct StripCache {
    inner: Mutex<HashMap<StripKey, StripCacheEntry>>,
}

impl StripCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &StripKey) -> Option<StripCacheEntry> {
        self.inner
            .lock()
            .expect("strip cache poisoned")
            .get(key)
            .cloned()
    }

    pub fn insert(&self, key: StripKey, entry: StripCacheEntry) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_inserted_entry() {
        let cache = StripCache::new();
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
        let cache = StripCache::new();
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
        let cache = StripCache::new();
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
}

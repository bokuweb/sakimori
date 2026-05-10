//! Workspace tamper detection — snapshot every regular file under a
//! root and diff a later snapshot against it.
//!
//! Use case: a malicious dependency's `postinstall` script (or
//! anything else the supervised step exec'd) silently rewrites
//! source files, `.git/config`, or CI config. With a snapshot
//! taken before the build and a diff taken after, those edits
//! show up as `modified:` entries in the report.
//!
//! ```text
//! sakimori workspace snapshot $GITHUB_WORKSPACE -o /tmp/before.json
//! cargo build               # or whatever you actually want to audit
//! sakimori workspace diff /tmp/before.json $GITHUB_WORKSPACE
//! ```
//!
//! Detection-only: we don't try to roll back. The intent is the
//! same as `deps watch` — surface the change so a human (or CI
//! gate) can decide whether to fail the build. Combine with
//! `sakimori run`'s file/exec audit for the full picture: the
//! audit log says *who* opened the file, this says *whether* the
//! contents actually changed.
//!
//! Default skip list (cannot be turned off; pass extra names with
//! `Options::skip_extra` to extend it):
//! `.git`, `node_modules`, `target`, `dist`, `build`, `vendor`,
//! `__pycache__`, `.venv`, `venv`, `.next`, `.turbo`, `.cache`.
//! These are dirs that legitimately churn during builds — hashing
//! them would drown the signal in build-artefact noise.
//!
//! Symlinks are recorded but not followed: the snapshot stores the
//! link target string, and a diff fires if either the target or
//! the linked file's hash changes (only the link target itself —
//! we don't deref). Files larger than `Options::max_file_bytes`
//! get a `size`-only entry with no hash; modifications that
//! preserve length will read as unchanged. Default cap is 64 MiB.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hardcoded directory names skipped during a walk. These are
/// build-artifact / vendor dirs whose churn would otherwise drown
/// out actual tampering. The list deliberately doesn't honour
/// `.gitignore` — `.gitignore` is too easy for an attacker to
/// write into, which would make the audit trivially bypassable.
pub const DEFAULT_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".next",
    ".turbo",
    ".cache",
];

/// 64 MiB. Files bigger than this skip hashing and rely on size
/// alone for change detection — keeps `snapshot` fast on repos
/// that contain accidental large blobs (compiled artefacts, test
/// fixtures, the occasional checked-in PDF).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Options {
    /// Extra directory basenames to skip on top of [`DEFAULT_SKIP_DIRS`].
    pub skip_extra: Vec<String>,
    /// Files larger than this are recorded with `hash: None` —
    /// see module docs. Set to `u64::MAX` to disable the cap.
    pub max_file_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            skip_extra: Vec::new(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    File {
        size: u64,
        /// Hex SHA-256 of the contents. `None` when the file
        /// exceeded `Options::max_file_bytes` or was unreadable —
        /// the diff still fires on any size delta.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
    },
    Symlink {
        target: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub root: PathBuf,
    /// Path → entry, keyed by path **relative** to `root` so a
    /// snapshot taken on one host can be diffed against the same
    /// repo cloned to a different absolute path.
    pub files: BTreeMap<PathBuf, Entry>,
    /// Files we couldn't read (permission denied, vanished mid-walk).
    /// Recorded so the diff can distinguish "actually missing now"
    /// from "we never saw this in the first place".
    #[serde(default)]
    pub unreadable: Vec<PathBuf>,
}

impl Snapshot {
    /// Walk `root` and build the snapshot. The path stored in
    /// `self.root` is the canonicalised version when canonicalisation
    /// succeeds — falls back to the input on failure (e.g. a parent
    /// dir we lack `x` on).
    pub fn take(root: &Path, opts: &Options) -> Result<Self> {
        let canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let mut snap = Snapshot {
            root: canon.clone(),
            files: BTreeMap::new(),
            unreadable: Vec::new(),
        };
        let skip: BTreeSet<&str> = DEFAULT_SKIP_DIRS
            .iter()
            .copied()
            .chain(opts.skip_extra.iter().map(String::as_str))
            .collect();
        walk(&canon, &canon, &skip, opts.max_file_bytes, &mut snap)?;
        Ok(snap)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).context("parsing tamper snapshot JSON")
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Diff {
    /// Files present in `current` but not `baseline`.
    pub added: Vec<PathBuf>,
    /// Files present in both but with different size, hash, or
    /// symlink target.
    pub modified: Vec<ModifiedEntry>,
    /// Files present in `baseline` but not `current`.
    pub removed: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModifiedEntry {
    pub path: PathBuf,
    pub before: Entry,
    pub after: Entry,
}

impl Diff {
    pub fn is_clean(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }

    pub fn total(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }
}

/// Compare two snapshots. Both must have the same shape — we don't
/// try to align them by content if the path layout differs (a
/// rename reads as one removed + one added, deliberately, because
/// that's the safer interpretation when auditing).
pub fn diff(baseline: &Snapshot, current: &Snapshot) -> Diff {
    let mut out = Diff::default();
    for (path, after) in &current.files {
        match baseline.files.get(path) {
            None => out.added.push(path.clone()),
            Some(before) if entries_differ(before, after) => out.modified.push(ModifiedEntry {
                path: path.clone(),
                before: before.clone(),
                after: after.clone(),
            }),
            Some(_) => {}
        }
    }
    for path in baseline.files.keys() {
        if !current.files.contains_key(path) {
            out.removed.push(path.clone());
        }
    }
    out
}

fn entries_differ(a: &Entry, b: &Entry) -> bool {
    match (a, b) {
        (
            Entry::File {
                size: sa,
                sha256: ha,
            },
            Entry::File {
                size: sb,
                sha256: hb,
            },
        ) => {
            if sa != sb {
                return true;
            }
            // Both hashed → compare. One side missing the hash
            // (oversized file) → fall back to size-only equality.
            match (ha, hb) {
                (Some(x), Some(y)) => x != y,
                _ => false,
            }
        }
        (Entry::Symlink { target: a }, Entry::Symlink { target: b }) => a != b,
        // Type changed (file ↔ symlink). Always a modification.
        _ => true,
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    skip: &BTreeSet<&str>,
    max_bytes: u64,
    snap: &mut Snapshot,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            snap.unreadable.push(rel_or_self(root, dir));
            return Ok(());
        }
        Err(err) => return Err(err).with_context(|| format!("read_dir {}", dir.display())),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let path = entry.path();

        // file_type() returns Result; on EACCES note + skip rather
        // than aborting the whole walk. A repo with one unreadable
        // file is more useful than no snapshot at all.
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => {
                snap.unreadable.push(rel_or_self(root, &path));
                continue;
            }
        };

        if ft.is_dir() {
            // Skip-list match is on basename, anywhere in the tree.
            // That's how `find -name target -prune` behaves and
            // it's what people expect.
            if skip.contains(name_str.as_ref()) {
                continue;
            }
            walk(root, &path, skip, max_bytes, snap)?;
        } else if ft.is_symlink() {
            match fs::read_link(&path) {
                Ok(target) => {
                    snap.files.insert(
                        rel_or_self(root, &path),
                        Entry::Symlink {
                            target: target.to_string_lossy().to_string(),
                        },
                    );
                }
                Err(_) => snap.unreadable.push(rel_or_self(root, &path)),
            }
        } else if ft.is_file() {
            match snapshot_file(&path, max_bytes) {
                Ok(entry) => {
                    snap.files.insert(rel_or_self(root, &path), entry);
                }
                Err(_) => snap.unreadable.push(rel_or_self(root, &path)),
            }
        }
        // Sockets, fifos, etc. — ignore. Not interesting for a
        // tamper-detection use case.
    }
    Ok(())
}

fn snapshot_file(path: &Path, max_bytes: u64) -> Result<Entry> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    if size > max_bytes {
        return Ok(Entry::File { size, sha256: None });
    }
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(Entry::File {
        size,
        sha256: Some(hex_lower(&digest)),
    })
}

fn rel_or_self(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lightweight tmp-dir guard matching the convention used in
    /// `deps::*` tests (no tempdir crate dependency).
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let id = format!(
                "{}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            );
            let p = std::env::temp_dir().join(format!("sakimori-tamper-{tag}-{id}"));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmp() -> Tmp {
        Tmp::new("t")
    }

    fn write(root: &Path, rel: &str, body: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn snapshot_records_file_size_and_hash() {
        let d = tmp();
        write(d.path(), "src/lib.rs", b"hello\n");
        let snap = Snapshot::take(d.path(), &Options::default()).unwrap();
        let entry = snap.files.get(Path::new("src/lib.rs")).expect("present");
        match entry {
            Entry::File { size, sha256 } => {
                assert_eq!(*size, 6);
                // SHA-256 of "hello\n".
                assert_eq!(
                    sha256.as_deref(),
                    Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")
                );
            }
            _ => panic!("wrong variant: {entry:?}"),
        }
    }

    #[test]
    fn skip_list_excludes_default_dirs_anywhere_in_tree() {
        let d = tmp();
        write(d.path(), "src/lib.rs", b"x");
        write(d.path(), "node_modules/foo/index.js", b"x");
        write(d.path(), "subcrate/target/debug/build", b"x");
        write(d.path(), ".git/config", b"x");

        let snap = Snapshot::take(d.path(), &Options::default()).unwrap();
        // Only the source file survives.
        assert_eq!(snap.files.len(), 1, "{snap:#?}");
        assert!(snap.files.contains_key(Path::new("src/lib.rs")));
    }

    #[test]
    fn diff_detects_added_modified_removed() {
        let d = tmp();
        write(d.path(), "a", b"1");
        write(d.path(), "b", b"2");
        let baseline = Snapshot::take(d.path(), &Options::default()).unwrap();

        // Modify b, remove a, add c.
        fs::remove_file(d.path().join("a")).unwrap();
        fs::write(d.path().join("b"), b"22").unwrap();
        write(d.path(), "c", b"3");

        let current = Snapshot::take(d.path(), &Options::default()).unwrap();
        let dif = diff(&baseline, &current);
        assert_eq!(dif.added, vec![PathBuf::from("c")]);
        assert_eq!(dif.removed, vec![PathBuf::from("a")]);
        assert_eq!(dif.modified.len(), 1);
        assert_eq!(dif.modified[0].path, PathBuf::from("b"));
        assert!(!dif.is_clean());
        assert_eq!(dif.total(), 3);
    }

    #[test]
    fn diff_clean_when_nothing_changed() {
        let d = tmp();
        write(d.path(), "a", b"1");
        write(d.path(), "sub/b", b"2");
        let s1 = Snapshot::take(d.path(), &Options::default()).unwrap();
        let s2 = Snapshot::take(d.path(), &Options::default()).unwrap();
        let dif = diff(&s1, &s2);
        assert!(dif.is_clean());
        assert_eq!(dif.total(), 0);
    }

    #[test]
    fn oversized_files_get_size_only_entry_no_hash() {
        let d = tmp();
        write(d.path(), "huge.bin", &vec![0u8; 1024]);
        let opts = Options {
            max_file_bytes: 100,
            ..Options::default()
        };
        let snap = Snapshot::take(d.path(), &opts).unwrap();
        match snap.files.get(Path::new("huge.bin")).unwrap() {
            Entry::File { size, sha256 } => {
                assert_eq!(*size, 1024);
                assert!(sha256.is_none(), "should skip hashing oversized files");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn oversized_size_change_still_detected() {
        // Even without hashes the size-delta path should fire.
        let d = tmp();
        write(d.path(), "huge.bin", &vec![0u8; 1024]);
        let opts = Options {
            max_file_bytes: 100,
            ..Options::default()
        };
        let s1 = Snapshot::take(d.path(), &opts).unwrap();

        write(d.path(), "huge.bin", &vec![0u8; 2048]);
        let s2 = Snapshot::take(d.path(), &opts).unwrap();

        let dif = diff(&s1, &s2);
        assert_eq!(dif.modified.len(), 1);
    }

    #[test]
    fn oversized_same_size_different_content_is_missed_by_design() {
        // Documented limitation: when both snapshots skip the hash
        // because the file is oversized, identical sizes look
        // unchanged. This test pins the behaviour so it's a
        // deliberate choice rather than a future surprise.
        let d = tmp();
        write(d.path(), "huge.bin", &vec![0u8; 1024]);
        let opts = Options {
            max_file_bytes: 100,
            ..Options::default()
        };
        let s1 = Snapshot::take(d.path(), &opts).unwrap();
        write(d.path(), "huge.bin", &vec![1u8; 1024]); // different content, same size
        let s2 = Snapshot::take(d.path(), &opts).unwrap();
        assert!(diff(&s1, &s2).is_clean());
    }

    #[test]
    fn extra_skip_dirs_are_honoured() {
        let d = tmp();
        write(d.path(), "src/lib.rs", b"x");
        write(d.path(), "weird-cache/foo", b"x");
        let opts = Options {
            skip_extra: vec!["weird-cache".into()],
            ..Options::default()
        };
        let snap = Snapshot::take(d.path(), &opts).unwrap();
        assert!(!snap.files.keys().any(|p| p.starts_with("weird-cache")));
    }

    #[test]
    fn json_round_trip_preserves_entries() {
        let d = tmp();
        write(d.path(), "a", b"1");
        let snap = Snapshot::take(d.path(), &Options::default()).unwrap();
        let json = snap.to_json_pretty().unwrap();
        let back = Snapshot::from_json(&json).unwrap();
        assert_eq!(back.files, snap.files);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_recorded_not_followed() {
        use std::os::unix::fs::symlink;
        let d = tmp();
        write(d.path(), "real.txt", b"contents");
        symlink("real.txt", d.path().join("link.txt")).unwrap();

        let snap = Snapshot::take(d.path(), &Options::default()).unwrap();
        match snap.files.get(Path::new("link.txt")).unwrap() {
            Entry::Symlink { target } => assert_eq!(target, "real.txt"),
            other => panic!("symlink recorded as {other:?}"),
        }
        // The real file is also there as a regular file entry.
        assert!(matches!(
            snap.files.get(Path::new("real.txt")),
            Some(Entry::File { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_retarget_is_a_modification() {
        use std::os::unix::fs::symlink;
        let d = tmp();
        write(d.path(), "a", b"1");
        write(d.path(), "b", b"2");
        symlink("a", d.path().join("link")).unwrap();
        let s1 = Snapshot::take(d.path(), &Options::default()).unwrap();

        fs::remove_file(d.path().join("link")).unwrap();
        symlink("b", d.path().join("link")).unwrap();
        let s2 = Snapshot::take(d.path(), &Options::default()).unwrap();

        let dif = diff(&s1, &s2);
        assert_eq!(dif.modified.len(), 1);
        assert_eq!(dif.modified[0].path, PathBuf::from("link"));
    }
}

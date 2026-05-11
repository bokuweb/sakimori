//! Find lockfiles inside a directory tree.

use std::path::{Path, PathBuf};

/// Lockfile basenames the watch mode recognises. Must match what
/// `deps::lockfile::detect` accepts.
pub const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "Cargo.lock",
    "uv.lock",
    "poetry.lock",
    "requirements.txt",
    "packages.lock.json",
];

/// Walk `root` (up to `max_depth`) and return paths to every known
/// lockfile. Skips `.git`, `node_modules`, `target`, and any directory
/// whose name starts with `.` (dotdirs) to keep scans fast on large
/// workspaces.
pub fn scan_lockfiles(root: &Path) -> Vec<PathBuf> {
    scan_with_depth(root, 12)
}

pub fn scan_with_depth(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, max_depth, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if is_skipped_dir(&path) {
                continue;
            }
            walk(&path, depth - 1, out);
        } else if (ft.is_file() || ft.is_symlink())
            && let Some(name) = path.file_name().and_then(|s| s.to_str())
            && LOCKFILE_NAMES.contains(&name)
        {
            out.push(path);
        }
    }
}

fn is_skipped_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if name.starts_with('.') {
        return true;
    }
    matches!(
        name,
        "node_modules" | "target" | "dist" | "build" | "__pycache__" | ".venv" | "venv" | ".tox"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("sakimori-watch-{tag}-{id}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn finds_all_known_lockfiles_at_root() {
        let d = tmpdir("root");
        for name in LOCKFILE_NAMES {
            fs::write(d.join(name), "").unwrap();
        }
        let found = scan_lockfiles(&d);
        assert_eq!(found.len(), LOCKFILE_NAMES.len());
    }

    #[test]
    fn walks_into_nested_dirs() {
        let d = tmpdir("nested");
        fs::create_dir_all(d.join("a/b/c")).unwrap();
        fs::write(d.join("a/b/c/Cargo.lock"), "").unwrap();
        fs::write(d.join("a/package-lock.json"), "").unwrap();
        let found = scan_lockfiles(&d);
        let names: Vec<String> = found
            .iter()
            .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(str::to_string))
            .collect();
        assert!(names.contains(&"Cargo.lock".to_string()));
        assert!(names.contains(&"package-lock.json".to_string()));
    }

    #[test]
    fn skips_vendor_build_and_hidden_dirs() {
        let d = tmpdir("skip");
        for skip in ["node_modules", "target", ".git", ".venv"] {
            let sub = d.join(skip);
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join("Cargo.lock"), "").unwrap();
        }
        let found = scan_lockfiles(&d);
        assert!(
            found.is_empty(),
            "expected no lockfiles to be found inside vendor dirs, got {found:?}"
        );
    }

    #[test]
    fn max_depth_respected() {
        let d = tmpdir("depth");
        // Construct 3 nested dirs with a lockfile at the deepest level.
        let deep = d.join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("Cargo.lock"), "").unwrap();
        assert!(scan_with_depth(&d, 4).len() == 1);
        assert!(scan_with_depth(&d, 2).is_empty());
    }

    #[test]
    fn unknown_filenames_ignored() {
        let d = tmpdir("unknown");
        fs::write(d.join("Cargo.toml"), "").unwrap();
        fs::write(d.join("pyproject.toml"), "").unwrap();
        fs::write(d.join("Gemfile.lock"), "").unwrap();
        assert!(scan_lockfiles(&d).is_empty());
    }
}

//! Parse `Cargo.lock`. Only `source = "registry+https://github.com/rust-lang/crates.io-index"`
//! entries (or no `source` when pointing at crates.io via the sparse index) are
//! checkable — git / path deps don't have registry publish dates.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::deps::{Ecosystem, Package};

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(rename = "package", default)]
    packages: Vec<PkgEntry>,
}

#[derive(Debug, Deserialize)]
struct PkgEntry {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

pub fn parse(path: &Path) -> Result<Vec<Package>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: CargoLock = toml::from_str(&text)
        .with_context(|| format!("parsing {} as Cargo.lock", path.display()))?;

    let mut out = Vec::new();
    for p in lock.packages {
        let Some(source) = p.source.as_deref() else {
            // Workspace member / path dep — skip.
            continue;
        };
        // "registry+https://github.com/rust-lang/crates.io-index"
        // or       "sparse+https://index.crates.io/"
        if !source.contains("crates.io") {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Crates,
            name: p.name,
            version: p.version,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sakimori-cargo-{id}-{name}"));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn picks_up_registry_entries_skips_workspace_and_git() {
        let body = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-ws-crate"
version = "0.1.0"
# workspace member: no `source`

[[package]]
name = "some-git-dep"
version = "0.1.0"
source = "git+https://github.com/x/y.git#abcdef"

[[package]]
name = "sparse-dep"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
"#;
        let p = tmp("Cargo.lock", body);
        let pkgs = parse(&p).unwrap();
        let names: Vec<String> = pkgs.iter().map(|x| x.name.clone()).collect();
        assert_eq!(names, vec!["serde".to_string(), "sparse-dep".to_string()]);
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Crates));
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let p = tmp("Cargo.lock-empty", "version = 3\n");
        assert!(parse(&p).unwrap().is_empty());
    }
}

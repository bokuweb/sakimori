//! Parse npm's `package-lock.json` (lockfile v2/v3).
//!
//! The modern shape is `{ "packages": { "<path>": { "name", "version", "resolved", ... } } }`
//! where `<path>` is e.g. `"node_modules/foo"` or `"node_modules/@scope/bar"`.
//! The root entry (`""`) is the project itself and must be skipped.
//!
//! We also skip anything marked as a workspace (`link: true`) or a
//! git/file dep (no `resolved` URL or no version).

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::deps::{Ecosystem, Package};

#[derive(Debug, Deserialize)]
struct PackageLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u32,
    #[serde(default)]
    packages: std::collections::BTreeMap<String, PkgEntry>,
}

#[derive(Debug, Deserialize)]
struct PkgEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    link: bool,
}

pub fn parse(path: &Path) -> Result<Vec<Package>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PackageLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as package-lock.json", path.display()))?;
    if lock.lockfile_version < 2 {
        anyhow::bail!(
            "package-lock.json lockfileVersion={} not supported (need >=2). Run `npm install` with npm >= 7.",
            lock.lockfile_version
        );
    }

    let mut out = Vec::new();
    for (key, entry) in &lock.packages {
        if key.is_empty() || entry.link {
            continue;
        }
        let Some(version) = entry.version.as_deref() else {
            continue;
        };
        // Skip git / tarball deps — their "version" is meaningless for
        // a registry age check.
        let is_registry = entry
            .resolved
            .as_deref()
            .map(|r| r.contains("registry.npmjs.org") || r.contains("registry.yarnpkg.com"))
            .unwrap_or(true); // if no `resolved` we optimistically treat as registry
        if !is_registry {
            continue;
        }

        // Recover the npm package name from the node_modules path rather
        // than trusting the entry's `name` field (which can be absent).
        let name = entry
            .name
            .clone()
            .or_else(|| package_name_from_path(key))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        out.push(Package {
            ecosystem: Ecosystem::Npm,
            name,
            version: version.to_string(),
        });
    }
    Ok(out)
}

fn package_name_from_path(key: &str) -> Option<String> {
    // "node_modules/foo" → "foo"
    // "node_modules/@scope/bar" → "@scope/bar"
    // "node_modules/foo/node_modules/@scope/bar" → "@scope/bar"
    let last = key.rsplit("node_modules/").next()?;
    if last.is_empty() {
        return None;
    }
    Some(last.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_name_from_various_paths() {
        assert_eq!(
            package_name_from_path("node_modules/foo"),
            Some("foo".into())
        );
        assert_eq!(
            package_name_from_path("node_modules/@scope/bar"),
            Some("@scope/bar".into())
        );
        assert_eq!(
            package_name_from_path("node_modules/foo/node_modules/@scope/bar"),
            Some("@scope/bar".into())
        );
    }

    fn tmp(body: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sakimori-npm-{id}/package-lock.json"));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn parses_v3_lockfile_with_scoped_and_nested_deps() {
        let body = r#"{
  "name":"x","version":"0.0.0","lockfileVersion":3,"requires":true,
  "packages": {
    "": {"name":"x","version":"0.0.0"},
    "node_modules/lodash": {"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"x"},
    "node_modules/@scope/pkg": {"version":"1.2.3","resolved":"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz","integrity":"x"},
    "node_modules/foo/node_modules/lodash": {"version":"4.17.10","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.10.tgz","integrity":"x"},
    "packages/my-workspace": {"link":true, "resolved":"packages/my-workspace"},
    "node_modules/git-dep": {"version":"0.0.1","resolved":"git+https://github.com/x/y.git"}
  }
}"#;
        let p = tmp(body);
        let pkgs = parse(&p).unwrap();
        let mut keys: Vec<String> = pkgs
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "@scope/pkg@1.2.3".to_string(),
                "lodash@4.17.10".to_string(),
                "lodash@4.17.21".to_string(),
            ]
        );
    }

    #[test]
    fn v1_lockfile_is_rejected() {
        let body = r#"{"name":"x","version":"0.0.0","lockfileVersion":1}"#;
        let p = tmp(body);
        assert!(parse(&p).is_err());
    }
}

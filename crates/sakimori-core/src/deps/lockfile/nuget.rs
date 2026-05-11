//! NuGet `packages.lock.json`.
//!
//! Shape (version 1 and 2):
//!
//! ```json
//! {
//!   "version": 1,
//!   "dependencies": {
//!     "net6.0": {
//!       "Newtonsoft.Json": {
//!         "type": "Direct" | "Transitive" | "Project" | ...,
//!         "resolved": "13.0.1",
//!         "contentHash": "..."
//!       },
//!       ...
//!     },
//!     "net8.0": { ... }
//!   }
//! }
//! ```
//!
//! We collect the union of `(name, resolved)` across all target
//! frameworks and skip entries whose `type` is `Project` (intra-solution
//! project references, not registry packages).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::deps::{Ecosystem, Package};

#[derive(Debug, Deserialize)]
struct Lock {
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, Entry>>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
}

pub fn parse(path: &Path) -> Result<Vec<Package>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as packages.lock.json", path.display()))?;

    let mut out = Vec::new();
    for packages in lock.dependencies.values() {
        for (name, entry) in packages {
            if matches!(entry.r#type.as_deref(), Some("Project")) {
                continue;
            }
            let Some(version) = entry.resolved.as_deref() else {
                continue;
            };
            out.push(Package {
                ecosystem: Ecosystem::Nuget,
                name: name.clone(),
                version: version.to_string(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(body: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sakimori-nuget-{id}.lock.json"));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn unions_across_target_frameworks_skips_project_refs() {
        let body = r#"{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.1",
        "contentHash": "x"
      },
      "MySolutionLib": {
        "type": "Project"
      }
    },
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.1",
        "contentHash": "x"
      },
      "Serilog": {
        "type": "Transitive",
        "resolved": "3.1.0",
        "contentHash": "y"
      }
    }
  }
}"#;
        let p = tmp(body);
        let pkgs = parse(&p).unwrap();
        // Sort for stable comparison (may appear dup'd across TFMs).
        let mut names: Vec<String> = pkgs.iter().map(|p| p.name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "Newtonsoft.Json".to_string(),
                "Newtonsoft.Json".to_string(),
                "Serilog".to_string(),
            ]
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Nuget));
        assert!(pkgs.iter().all(|p| !p.version.is_empty()));
    }

    #[test]
    fn missing_resolved_is_skipped() {
        let body = r#"{"version":1,"dependencies":{"net6.0":{"Foo":{"type":"Direct"}}}}"#;
        let p = tmp(body);
        assert!(parse(&p).unwrap().is_empty());
    }
}

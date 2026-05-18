//! Per-ecosystem registry-host configuration.
//!
//! By default the proxy MITMs the canonical public hosts
//! (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`,
//! `api.nuget.org`, `crates.io`, `index.crates.io`). Teams that route
//! installs through an internal mirror (Verdaccio, GitHub Packages,
//! Artifactory, Takumi Guard, etc.) need to teach the proxy about
//! those hosts so the same rewriters / lifecycle gate fire. This
//! struct is the single source of truth for that mapping.
//!
//! Resolution order for the final list of hosts the proxy watches:
//! built-in defaults → optional TOML config file → CLI flags. Each
//! step *appends* (with case-insensitive dedupe). To exclude a
//! default upstream entirely, layer in a `network_allow` list — the
//! egress filter then 403s every host that isn't on it.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Per-ecosystem host lists. Empty vectors mean "no hosts for this
/// ecosystem"; the proxy simply skips that parser. The fields are
/// `pub` so the caller can append before constructing parsers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryHosts {
    /// npm packument + tarball host(s). Default: `registry.npmjs.org`.
    pub npm: Vec<String>,
    /// PyPI metadata host(s) (Warehouse JSON, PEP 503 / 691 Simple
    /// index). Default: `pypi.org`.
    pub pypi_index: Vec<String>,
    /// PyPI artefact host(s) (sdist / wheel downloads). Default:
    /// `files.pythonhosted.org`.
    pub pypi_files: Vec<String>,
    /// crates.io API host(s) — the `api/v1/crates/<n>/<v>/download`
    /// endpoint. Default: `crates.io`.
    pub crates: Vec<String>,
    /// crates.io sparse-index host(s). Default: `index.crates.io`.
    pub crates_sparse: Vec<String>,
    /// NuGet v3 host(s) (registration + flat-container endpoints).
    /// Default: `api.nuget.org`.
    pub nuget: Vec<String>,
}

impl Default for RegistryHosts {
    fn default() -> Self {
        Self {
            npm: vec!["registry.npmjs.org".into()],
            pypi_index: vec!["pypi.org".into()],
            pypi_files: vec!["files.pythonhosted.org".into()],
            crates: vec!["crates.io".into()],
            crates_sparse: vec!["index.crates.io".into()],
            nuget: vec!["api.nuget.org".into()],
        }
    }
}

/// Wrapper matching the on-disk TOML layout:
///
/// ```toml
/// [registries]
/// npm = ["registry.npmjs.org", "npm.flatt.tech"]
/// pypi_index = ["pypi.org"]
/// pypi_files = ["files.pythonhosted.org"]
/// crates = ["crates.io"]
/// crates_sparse = ["index.crates.io"]
/// nuget = ["api.nuget.org"]
/// ```
///
/// Keeping the `[registries]` wrapper means future versions can grow
/// other sections in the same file without a migration.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    registries: RegistryHosts,
}

impl RegistryHosts {
    /// Load a `RegistryHosts` from a TOML file. The file's contents
    /// fully populate the struct; merge with defaults / CLI happens
    /// in the caller (use [`Self::extend_from`] or [`Self::merge`]).
    pub fn load_toml(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading registries config {}: {e}", path.display()))?;
        let cfg: ConfigFile = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing registries config {}: {e}", path.display()))?;
        Ok(cfg.registries)
    }

    /// Append every host in `other` into `self`, normalising and
    /// deduping case-insensitively. Order is preserved (first
    /// occurrence wins).
    pub fn extend_from(&mut self, other: &Self) {
        extend(&mut self.npm, &other.npm);
        extend(&mut self.pypi_index, &other.pypi_index);
        extend(&mut self.pypi_files, &other.pypi_files);
        extend(&mut self.crates, &other.crates);
        extend(&mut self.crates_sparse, &other.crates_sparse);
        extend(&mut self.nuget, &other.nuget);
    }

    /// Convenience: start from `Default::default()`, then layer in
    /// `file` (if any), then `extra`. Each step deduplicates against
    /// what's already there.
    pub fn merge(file: Option<Self>, extra: Self) -> Self {
        let mut out = Self::default();
        if let Some(f) = file {
            out.extend_from(&f);
        }
        out.extend_from(&extra);
        out
    }

    /// Normalise a single user-supplied entry to a bare hostname.
    /// Accepts:
    /// - `registry.npmjs.org`             — bare host, passed through
    ///   (lowercased)
    /// - `https://npm.flatt.tech/`        — URL form, host extracted
    /// - `https://npm.flatt.tech:8443/x`  — port is stripped (the
    ///   proxy matches by hostname; CONNECT carries the port
    ///   separately)
    ///
    /// Rejects empty input. Anything else (e.g. embedded `*`) is
    /// considered a bare host and passed through lowercased — the
    /// validation cost of stricter parsing isn't worth it; bad hosts
    /// simply won't match incoming traffic.
    pub fn normalize_host(input: &str) -> anyhow::Result<String> {
        let input = input.trim();
        if input.is_empty() {
            anyhow::bail!("empty registry host");
        }
        // Strip an optional scheme + path.
        let rest = if let Some(after) = input.split_once("://").map(|(_, r)| r) {
            after
        } else {
            input
        };
        // Drop path / query.
        let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        // Drop port.
        let host = host_port.split(':').next().unwrap_or(host_port);
        if host.is_empty() {
            anyhow::bail!("could not extract host from `{input}`");
        }
        Ok(host.to_ascii_lowercase())
    }
}

fn extend(dst: &mut Vec<String>, src: &[String]) {
    for h in src {
        let lowered = h.to_ascii_lowercase();
        if !dst.iter().any(|x| x.eq_ignore_ascii_case(&lowered)) {
            dst.push(lowered);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_cover_canonical_public_hosts() {
        let d = RegistryHosts::default();
        assert!(d.npm.iter().any(|h| h == "registry.npmjs.org"));
        assert!(d.pypi_index.iter().any(|h| h == "pypi.org"));
        assert!(d.pypi_files.iter().any(|h| h == "files.pythonhosted.org"));
        assert!(d.crates.iter().any(|h| h == "crates.io"));
        assert!(d.crates_sparse.iter().any(|h| h == "index.crates.io"));
        assert!(d.nuget.iter().any(|h| h == "api.nuget.org"));
    }

    #[test]
    fn extend_dedupes_case_insensitively() {
        let mut a = RegistryHosts::default();
        let b = RegistryHosts {
            npm: vec!["REGISTRY.NPMJS.ORG".into(), "npm.flatt.tech".into()],
            ..RegistryHosts::default()
        };
        a.extend_from(&b);
        // The default `registry.npmjs.org` should still be a single
        // entry (case-insensitive dedupe); flatt should be appended.
        let count = a
            .npm
            .iter()
            .filter(|h| h.eq_ignore_ascii_case("registry.npmjs.org"))
            .count();
        assert_eq!(count, 1, "duplicate canonical host: {:?}", a.npm);
        assert!(a.npm.iter().any(|h| h == "npm.flatt.tech"));
    }

    #[test]
    fn merge_layers_file_then_cli() {
        let file = RegistryHosts {
            npm: vec!["npm.flatt.tech".into()],
            ..RegistryHosts::default()
        };
        let cli = RegistryHosts {
            npm: vec!["npm.internal".into()],
            ..RegistryHosts::default()
        };
        let out = RegistryHosts::merge(Some(file), cli);
        assert!(out.npm.iter().any(|h| h == "registry.npmjs.org"));
        assert!(out.npm.iter().any(|h| h == "npm.flatt.tech"));
        assert!(out.npm.iter().any(|h| h == "npm.internal"));
    }

    #[test]
    fn normalize_host_accepts_bare_host_and_url() {
        assert_eq!(
            RegistryHosts::normalize_host("registry.npmjs.org").unwrap(),
            "registry.npmjs.org"
        );
        assert_eq!(
            RegistryHosts::normalize_host("https://npm.flatt.tech/").unwrap(),
            "npm.flatt.tech"
        );
        assert_eq!(
            RegistryHosts::normalize_host("https://npm.flatt.tech:8443/path").unwrap(),
            "npm.flatt.tech"
        );
        assert_eq!(
            RegistryHosts::normalize_host("NPM.Flatt.Tech").unwrap(),
            "npm.flatt.tech"
        );
        assert!(RegistryHosts::normalize_host("").is_err());
        assert!(RegistryHosts::normalize_host("   ").is_err());
    }

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "sakimori-registries-{tag}-{}-{nanos}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn load_toml_parses_full_file() {
        let p = tmp_path("full");
        std::fs::write(
            &p,
            r#"
[registries]
npm = ["registry.npmjs.org", "npm.flatt.tech"]
pypi_index = ["pypi.org"]
pypi_files = ["files.pythonhosted.org"]
crates = ["crates.io"]
crates_sparse = ["index.crates.io"]
nuget = ["api.nuget.org"]
"#,
        )
        .unwrap();
        let cfg = RegistryHosts::load_toml(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert!(cfg.npm.iter().any(|h| h == "npm.flatt.tech"));
        assert_eq!(cfg.pypi_index, vec!["pypi.org".to_string()]);
    }

    #[test]
    fn load_toml_accepts_partial_file() {
        let p = tmp_path("partial");
        std::fs::write(
            &p,
            r#"
[registries]
npm = ["npm.flatt.tech"]
"#,
        )
        .unwrap();
        let cfg = RegistryHosts::load_toml(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(cfg.npm, vec!["npm.flatt.tech".to_string()]);
        // Unset sections fall back to RegistryHosts::default() via
        // #[serde(default)] on each field — same canonical hosts.
        assert!(cfg.pypi_index.iter().any(|h| h == "pypi.org"));
    }

    #[test]
    fn extend_preserves_first_occurrence_order() {
        let mut a = RegistryHosts {
            npm: vec!["a.example".into()],
            ..RegistryHosts::default()
        };
        let b = RegistryHosts {
            npm: vec!["A.EXAMPLE".into(), "b.example".into()],
            ..RegistryHosts::default()
        };
        a.extend_from(&b);
        assert_eq!(a.npm, vec!["a.example".to_string(), "b.example".into()]);
    }

    #[test]
    fn merge_layers_in_order_defaults_then_file_then_cli() {
        let file = RegistryHosts {
            npm: vec!["mid.example".into()],
            ..RegistryHosts::default()
        };
        let cli = RegistryHosts {
            npm: vec!["late.example".into()],
            ..RegistryHosts::default()
        };
        let out = RegistryHosts::merge(Some(file), cli);
        let positions: Vec<usize> = ["registry.npmjs.org", "mid.example", "late.example"]
            .iter()
            .map(|target| out.npm.iter().position(|h| h == target).expect("present"))
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "expected defaults < file < cli, got {positions:?} from {:?}",
            out.npm
        );
    }

    #[test]
    fn merge_with_no_file_yields_defaults_plus_cli() {
        let cli = RegistryHosts {
            npm: vec!["only-cli.example".into()],
            ..RegistryHosts::default()
        };
        let out = RegistryHosts::merge(None, cli);
        assert!(out.npm.iter().any(|h| h == "registry.npmjs.org"));
        assert!(out.npm.iter().any(|h| h == "only-cli.example"));
    }

    #[test]
    fn normalize_host_rejects_inputs_that_become_empty() {
        assert!(RegistryHosts::normalize_host("https://").is_err());
        assert!(RegistryHosts::normalize_host(":443").is_err());
    }

    #[test]
    fn normalize_host_passes_through_weird_but_nonempty_input() {
        // We deliberately don't validate hostname syntax — a bogus
        // entry simply never matches incoming traffic, which is
        // cheaper than maintaining a parser for every edge of RFC
        // 1123 / IDN.
        let h = RegistryHosts::normalize_host("not_a_valid_host!").unwrap();
        assert_eq!(h, "not_a_valid_host!");
    }

    #[test]
    fn load_toml_rejects_unknown_fields() {
        // `deny_unknown_fields` is the early-warning system for
        // typos like `npmjs = [...]` (should be `npm`).
        let p = tmp_path("unknown");
        std::fs::write(
            &p,
            r#"
[registries]
npmjs = ["wrong-key.example"]
"#,
        )
        .unwrap();
        let err = RegistryHosts::load_toml(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        let msg = format!("{err:#}");
        assert!(msg.contains("npmjs"), "{msg}");
    }

    #[test]
    fn load_toml_reports_missing_file_with_path() {
        let missing = std::env::temp_dir().join(format!(
            "sakimori-registries-missing-{}.toml",
            std::process::id()
        ));
        let err = RegistryHosts::load_toml(&missing).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(&missing.display().to_string()), "{msg}");
    }

    #[test]
    fn load_toml_empty_file_yields_defaults() {
        let p = tmp_path("empty");
        std::fs::write(&p, "").unwrap();
        let cfg = RegistryHosts::load_toml(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(cfg, RegistryHosts::default());
    }

    #[test]
    fn load_toml_top_level_table_missing_is_defaults() {
        // The wrapping `[registries]` table itself can be omitted —
        // useful when a host might later grow other sections in the
        // same file. With no `[registries]` table we still want the
        // canonical defaults back.
        let p = tmp_path("no-section");
        std::fs::write(&p, "# just a comment\n").unwrap();
        let cfg = RegistryHosts::load_toml(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(cfg, RegistryHosts::default());
    }
}

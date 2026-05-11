//! PyPI lockfile parsing.
//!
//! Supports three shapes, dispatched on filename:
//!
//! - `uv.lock` — TOML. `[[package]]` entries with `name`, `version`,
//!   `source.registry = "https://pypi.org/simple"`.
//! - `poetry.lock` — TOML. `[[package]]` with `name`, `version`. Poetry
//!   is quieter about "source" — assume PyPI unless `source.type` is
//!   `git` / `file` / `url`.
//! - `requirements.txt` — plain text. Only lines matching `name==version`
//!   (optionally with extras / environment markers we strip) are
//!   considered pins; ranges, VCS URLs, `-r` includes, editable installs,
//!   and comments are skipped.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::deps::{Ecosystem, Package};

pub fn parse(path: &Path) -> Result<Vec<Package>> {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match fname {
        "uv.lock" => parse_uv(path),
        "poetry.lock" => parse_poetry(path),
        "requirements.txt" => parse_requirements(path),
        other => anyhow::bail!("unsupported pypi lockfile '{other}'"),
    }
}

// -------- uv.lock / poetry.lock (both TOML, same shape for our needs) --------

#[derive(Debug, Deserialize)]
struct TomlLock {
    #[serde(rename = "package", default)]
    packages: Vec<TomlPkg>,
}

#[derive(Debug, Deserialize)]
struct TomlPkg {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<TomlSource>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TomlSource {
    // poetry.lock: { type = "legacy" | "git" | "file" | "url", ... }
    // uv.lock:     { registry = "https://pypi.org/simple" } or { git = "...", ... }
    Struct(TomlSourceStruct),
    // Bare strings or other shapes: ignored for matching purposes.
    #[allow(dead_code)]
    Other(toml::Value),
}

#[derive(Debug, Deserialize, Default)]
struct TomlSourceStruct {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    registry: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

fn parse_uv(path: &Path) -> Result<Vec<Package>> {
    parse_toml_pypi(path)
}

fn parse_poetry(path: &Path) -> Result<Vec<Package>> {
    parse_toml_pypi(path)
}

fn parse_toml_pypi(path: &Path) -> Result<Vec<Package>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: TomlLock =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

    let mut out = Vec::new();
    for p in lock.packages {
        if !is_pypi_source(p.source.as_ref()) {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Pypi,
            name: p.name,
            version: p.version,
        });
    }
    Ok(out)
}

fn is_pypi_source(src: Option<&TomlSource>) -> bool {
    match src {
        None => true, // default: assume PyPI
        Some(TomlSource::Struct(s)) => {
            // git/url/file deps → not on PyPI
            if s.git.is_some() || s.url.is_some() {
                return false;
            }
            match s.r#type.as_deref() {
                Some("git") | Some("file") | Some("url") | Some("directory") => false,
                _ => {
                    // uv: registry = "https://pypi.org/simple" (or some mirror).
                    // Accept anything that mentions pypi OR that has no registry
                    // specified (poetry default).
                    match s.registry.as_deref() {
                        None => true,
                        Some(r) => r.contains("pypi.org") || r.contains("simple"),
                    }
                }
            }
        }
        Some(TomlSource::Other(_)) => true,
    }
}

// -------- requirements.txt --------

fn parse_requirements(path: &Path) -> Result<Vec<Package>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        if let Some((name, version)) = parse_requirement_line(raw) {
            out.push(Package {
                ecosystem: Ecosystem::Pypi,
                name,
                version,
            });
        } else {
            log::trace!(
                "{}:{} skipped (not an exact pin)",
                path.display(),
                lineno + 1
            );
        }
    }
    Ok(out)
}

/// Accept strict `name[extras]==X.Y.Z[; markers]`. Anything else (ranges,
/// VCS, editable, includes, comments) is skipped — the whole point of a
/// publish-age check is reproducibility, so ranges aren't actionable here
/// anyway.
fn parse_requirement_line(raw: &str) -> Option<(String, String)> {
    // Strip comment / whitespace / line-continuation.
    let line = raw.split('#').next()?.trim();
    if line.is_empty() {
        return None;
    }
    // Skip option flags and non-pip-installable-from-index forms.
    if line.starts_with('-')
        || line.starts_with("git+")
        || line.starts_with("http://")
        || line.starts_with("https://")
        || line.starts_with("file://")
    {
        return None;
    }
    // Strip environment markers after `;`.
    let body = line.split(';').next()?.trim();
    // Must contain `==`.
    let (lhs, rhs) = body.split_once("==")?;
    // Strip extras [foo,bar] from LHS.
    let name = match lhs.split_once('[') {
        Some((head, _)) => head,
        None => lhs,
    };
    // RHS may have multiple versions comma-separated (unusual) — take first.
    let version = rhs.split(',').next()?.trim();

    let name = name.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // Validate version loosely (must contain at least one digit).
    if !version.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_line_parses_exact_pins() {
        assert_eq!(
            parse_requirement_line("requests==2.31.0"),
            Some(("requests".into(), "2.31.0".into()))
        );
        assert_eq!(
            parse_requirement_line("Django[argon2]==4.2.7"),
            Some(("Django".into(), "4.2.7".into()))
        );
        assert_eq!(
            parse_requirement_line("numpy==1.26.0 ; python_version >= '3.9'"),
            Some(("numpy".into(), "1.26.0".into()))
        );
        assert_eq!(parse_requirement_line("  # a comment"), None);
        assert_eq!(parse_requirement_line(""), None);
        assert_eq!(parse_requirement_line("-r other.txt"), None);
        assert_eq!(parse_requirement_line("foo>=1.0,<2.0"), None);
        assert_eq!(
            parse_requirement_line("git+https://github.com/x/y@v1"),
            None
        );
    }
}

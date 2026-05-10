//! Parse incoming HTTPS requests into a `(ecosystem, name, version)`
//! triple we can age-check. Unrecognised URLs return `Unknown` and the
//! proxy passes them through untouched.

use sakimori_core::deps::Ecosystem;

/// Result of inspecting one registry-bound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    /// The request is downloading a specific version — we know
    /// enough to age-check.
    Pinned {
        ecosystem: Ecosystem,
        name: String,
        version: String,
    },
    /// The request is metadata (index lookup, search, etc.) — harmless
    /// even for a young package. Always allow.
    Metadata,
    /// Not a request we care about.
    Unknown,
}

pub trait RegistryParser: Send + Sync {
    /// The authority part this parser is responsible for (for routing).
    fn host(&self) -> &'static str;
    /// Parse the path + query of a request already known to be for
    /// [`Self::host`].
    fn parse(&self, path: &str) -> ParseResult;
}

/// Parser for `crates.io` + its sparse index host.
///
/// URL shapes we handle:
/// - `GET /api/v1/crates/<name>/<version>/download` — the tarball fetch.
///   This is the one we actually need to 403.
/// - `GET <shard>/<name>` (sparse index at index.crates.io) — returns
///   a newline-delimited JSON stream of ALL versions. The client uses
///   this for resolution. We currently treat it as Metadata and let it
///   through; we'll rewrite this to omit too-young versions in a
///   follow-up (that's the pnpm-style auto-fallback story).
/// - anything else → Unknown, pass through.
pub struct CratesIoParser;

impl RegistryParser for CratesIoParser {
    fn host(&self) -> &'static str {
        "crates.io"
    }
    fn parse(&self, path: &str) -> ParseResult {
        // Strip query string.
        let path = path.split('?').next().unwrap_or(path);
        let mut segs = path.trim_start_matches('/').split('/');
        match (segs.next(), segs.next(), segs.next()) {
            (Some("api"), Some("v1"), Some("crates")) => {
                let name = segs.next().unwrap_or_default();
                let version = segs.next().unwrap_or_default();
                let tail = segs.next().unwrap_or_default();
                if !name.is_empty() && !version.is_empty() && tail == "download" {
                    return ParseResult::Pinned {
                        ecosystem: Ecosystem::Crates,
                        name: name.to_string(),
                        version: version.to_string(),
                    };
                }
                ParseResult::Metadata
            }
            _ => ParseResult::Unknown,
        }
    }
}

/// Parser for the sparse index at `index.crates.io`. Entries look
/// like `GET /1/s/serde` (shard) → JSONL metadata. We treat these
/// as Metadata for now.
pub struct CratesIoSparseParser;

impl RegistryParser for CratesIoSparseParser {
    fn host(&self) -> &'static str {
        "index.crates.io"
    }
    fn parse(&self, _path: &str) -> ParseResult {
        ParseResult::Metadata
    }
}

// ---------------- npm (registry.npmjs.org) ----------------

/// Parser for `registry.npmjs.org`.
///
/// Tarball download URL shapes we handle:
/// - `GET /<name>/-/<basename>-<version>.tgz`
///   — unscoped, e.g. `/lodash/-/lodash-4.17.21.tgz`
/// - `GET /@<scope>/<name>/-/<basename>-<version>.tgz`
///   — scoped, e.g. `/@types/node/-/node-20.0.0.tgz`
///
/// Note the tarball **basename** is the package name *without* the
/// `@scope/` prefix, which is why we match `basename-version.tgz`
/// against only the last segment after stripping the scope.
///
/// Anything else (metadata docs at `/<name>` or `/<name>/<version>`)
/// is Metadata — those describe available versions but don't actually
/// transfer a tarball, so blocking them would only break resolution
/// without buying security.
pub struct NpmParser;

impl RegistryParser for NpmParser {
    fn host(&self) -> &'static str {
        "registry.npmjs.org"
    }
    fn parse(&self, path: &str) -> ParseResult {
        let path = path.split('?').next().unwrap_or(path);
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        // Recognise two tarball shapes.
        let (full_name, basename, tarball): (String, &str, &str) = match segs.as_slice() {
            // unscoped: ["<name>", "-", "<basename>-<version>.tgz"]
            [name, dash, tb] if *dash == "-" && !name.is_empty() && !tb.is_empty() => {
                (name.to_string(), *name, *tb)
            }
            // scoped: ["@scope", "<name>", "-", "<basename>-<version>.tgz"]
            [scope, name, dash, tb]
                if *dash == "-" && scope.starts_with('@') && !name.is_empty() && !tb.is_empty() =>
            {
                (format!("{scope}/{name}"), *name, *tb)
            }
            _ => return ParseResult::Metadata,
        };

        let Some(stem) = tarball.strip_suffix(".tgz") else {
            return ParseResult::Metadata;
        };
        let prefix = format!("{basename}-");
        let Some(version) = stem.strip_prefix(&prefix) else {
            return ParseResult::Metadata;
        };
        if version.is_empty() {
            return ParseResult::Metadata;
        }
        ParseResult::Pinned {
            ecosystem: Ecosystem::Npm,
            name: full_name,
            version: version.to_string(),
        }
    }
}

// ---------------- PyPI (files.pythonhosted.org) ----------------

/// Parser for `files.pythonhosted.org`, which is where pip / uv /
/// poetry actually fetch sdists and wheels from.
///
/// File names follow PEP 427 (wheels) / PEP 625 (sdists):
/// - sdist: `<name>-<version>.tar.gz` (or `.zip`)
/// - wheel: `<name>-<version>-<python>-<abi>-<platform>.whl`
///
/// PEP 503: package names must not start with a digit. PEP 440:
/// versions always start with a digit (or `v` + digit). So the
/// "first segment starting with a digit" is the version — we use
/// that as our delimiter. This handles names with hyphens
/// (`my-cool-pkg-1.0.0.tar.gz`) correctly.
pub struct PypiParser;

impl RegistryParser for PypiParser {
    fn host(&self) -> &'static str {
        "files.pythonhosted.org"
    }
    fn parse(&self, path: &str) -> ParseResult {
        let path = path.split('?').next().unwrap_or(path);
        let filename = path.rsplit('/').next().unwrap_or("");
        if filename.is_empty() {
            return ParseResult::Metadata;
        }

        // Strip known extensions.
        let stem = if let Some(s) = filename.strip_suffix(".whl") {
            s
        } else if let Some(s) = filename.strip_suffix(".tar.gz") {
            s
        } else if let Some(s) = filename.strip_suffix(".zip") {
            s
        } else {
            return ParseResult::Metadata;
        };

        let parts: Vec<&str> = stem.split('-').collect();
        // Find the first segment that starts with a digit — that's the version.
        let mut version_idx = None;
        for (i, p) in parts.iter().enumerate().skip(1) {
            if p.starts_with(|c: char| c.is_ascii_digit()) {
                version_idx = Some(i);
                break;
            }
        }
        let Some(i) = version_idx else {
            return ParseResult::Metadata;
        };
        let name = parts[..i].join("-");
        let version = parts[i].to_string();
        if name.is_empty() || version.is_empty() {
            return ParseResult::Metadata;
        }
        ParseResult::Pinned {
            ecosystem: Ecosystem::Pypi,
            name,
            version,
        }
    }
}

// ---------------- PyPI metadata host (pypi.org) ----------------

/// Parser for `pypi.org`, the PyPI **metadata** host.
///
/// Every request to `pypi.org` is metadata (JSON API, Simple index
/// HTML/JSON, project pages). The tarballs themselves live on
/// `files.pythonhosted.org` and are handled by [`PypiParser`]. This
/// parser exists purely so `should_intercept` returns `true` for
/// `pypi.org` and the proxy MITMs the TLS so we can rewrite metadata
/// responses. It never produces a `Pinned` result.
pub struct PypiOrgParser;

impl RegistryParser for PypiOrgParser {
    fn host(&self) -> &'static str {
        "pypi.org"
    }
    fn parse(&self, _path: &str) -> ParseResult {
        ParseResult::Metadata
    }
}

// ---------------- NuGet (api.nuget.org) ----------------

/// Parser for `api.nuget.org`. Tarball download URL:
///
/// ```text
/// GET /v3-flatcontainer/<id-lower>/<version>/<id-lower>.<version>.nupkg
/// ```
///
/// Name and version are cleanly in the path as separate segments,
/// so no filename-splitting heuristics needed.
pub struct NugetParser;

impl RegistryParser for NugetParser {
    fn host(&self) -> &'static str {
        "api.nuget.org"
    }
    fn parse(&self, path: &str) -> ParseResult {
        let path = path.split('?').next().unwrap_or(path);
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        // ["v3-flatcontainer", "<name>", "<version>", "<name>.<version>.nupkg"]
        if segs.len() == 4
            && segs[0] == "v3-flatcontainer"
            && !segs[1].is_empty()
            && !segs[2].is_empty()
            && segs[3].ends_with(".nupkg")
        {
            return ParseResult::Pinned {
                ecosystem: Ecosystem::Nuget,
                name: segs[1].to_string(),
                version: segs[2].to_string(),
            };
        }
        ParseResult::Metadata
    }
}

pub fn default_parsers() -> Vec<Box<dyn RegistryParser>> {
    vec![
        Box::new(CratesIoParser),
        Box::new(CratesIoSparseParser),
        Box::new(NpmParser),
        Box::new(PypiParser),
        Box::new(PypiOrgParser),
        Box::new(NugetParser),
    ]
}

pub fn parse_for_host(parsers: &[Box<dyn RegistryParser>], host: &str, path: &str) -> ParseResult {
    for p in parsers {
        if host.eq_ignore_ascii_case(p.host()) {
            return p.parse(path);
        }
    }
    ParseResult::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_download_url_is_pinned() {
        let p = CratesIoParser;
        let r = p.parse("/api/v1/crates/serde/1.0.0/download");
        assert_eq!(
            r,
            ParseResult::Pinned {
                ecosystem: Ecosystem::Crates,
                name: "serde".into(),
                version: "1.0.0".into(),
            }
        );
    }

    #[test]
    fn crates_download_strips_query() {
        let p = CratesIoParser;
        let r = p.parse("/api/v1/crates/tokio/1.35.0/download?token=abc");
        if let ParseResult::Pinned { name, version, .. } = r {
            assert_eq!(name, "tokio");
            assert_eq!(version, "1.35.0");
        } else {
            panic!("expected Pinned, got {r:?}");
        }
    }

    #[test]
    fn crates_non_download_paths_are_metadata() {
        let p = CratesIoParser;
        assert_eq!(p.parse("/api/v1/crates/serde"), ParseResult::Metadata);
        assert_eq!(p.parse("/api/v1/crates"), ParseResult::Metadata);
        assert_eq!(p.parse("/api/v1/crates/serde/1.0.0"), ParseResult::Metadata);
    }

    #[test]
    fn unknown_paths_are_unknown() {
        let p = CratesIoParser;
        assert_eq!(p.parse("/"), ParseResult::Unknown);
        assert_eq!(p.parse("/api/v2/whatever"), ParseResult::Unknown);
    }

    #[test]
    fn sparse_index_is_metadata_for_now() {
        let p = CratesIoSparseParser;
        assert_eq!(p.parse("/1/s/serde"), ParseResult::Metadata);
        assert_eq!(p.parse("/3/t/tokio"), ParseResult::Metadata);
    }

    #[test]
    fn router_dispatches_on_host_case_insensitively() {
        let ps = default_parsers();
        let r = parse_for_host(&ps, "CRATES.IO", "/api/v1/crates/x/1.0/download");
        assert!(matches!(r, ParseResult::Pinned { .. }));
        let r = parse_for_host(&ps, "other.example", "/");
        assert_eq!(r, ParseResult::Unknown);
    }

    // ---------------- npm tests ----------------

    #[test]
    fn npm_unscoped_tarball_is_pinned() {
        let p = NpmParser;
        assert_eq!(
            p.parse("/lodash/-/lodash-4.17.21.tgz"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Npm,
                name: "lodash".into(),
                version: "4.17.21".into(),
            }
        );
    }

    #[test]
    fn npm_scoped_tarball_is_pinned_with_full_name() {
        let p = NpmParser;
        assert_eq!(
            p.parse("/@types/node/-/node-20.0.0.tgz"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Npm,
                name: "@types/node".into(),
                version: "20.0.0".into(),
            }
        );
    }

    #[test]
    fn npm_prerelease_version_with_hyphens_preserved() {
        let p = NpmParser;
        // react 18.0.0-rc.0 style: tarball is "react-18.0.0-rc.0.tgz"
        assert_eq!(
            p.parse("/react/-/react-18.0.0-rc.0.tgz"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Npm,
                name: "react".into(),
                version: "18.0.0-rc.0".into(),
            }
        );
    }

    #[test]
    fn npm_metadata_paths_are_not_pinned() {
        let p = NpmParser;
        assert_eq!(p.parse("/lodash"), ParseResult::Metadata);
        assert_eq!(p.parse("/lodash/4.17.21"), ParseResult::Metadata);
        assert_eq!(p.parse("/@types/node"), ParseResult::Metadata);
        assert_eq!(p.parse("/"), ParseResult::Metadata);
    }

    #[test]
    fn npm_malformed_tarball_is_metadata() {
        let p = NpmParser;
        // Wrong basename in filename.
        assert_eq!(p.parse("/foo/-/bar-1.0.0.tgz"), ParseResult::Metadata);
        // Missing extension.
        assert_eq!(p.parse("/foo/-/foo-1.0.0"), ParseResult::Metadata);
    }

    // ---------------- pypi tests ----------------

    #[test]
    fn pypi_sdist_tar_gz_is_pinned() {
        let p = PypiParser;
        assert_eq!(
            p.parse("/packages/aa/bb/cc/requests-2.31.0.tar.gz"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Pypi,
                name: "requests".into(),
                version: "2.31.0".into(),
            }
        );
    }

    #[test]
    fn pypi_wheel_is_pinned() {
        let p = PypiParser;
        assert_eq!(
            p.parse("/packages/aa/bb/cc/numpy-1.26.0-cp311-cp311-macosx_11_0_arm64.whl"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Pypi,
                name: "numpy".into(),
                version: "1.26.0".into(),
            }
        );
    }

    #[test]
    fn pypi_hyphenated_name_splits_at_first_digit_segment() {
        let p = PypiParser;
        assert_eq!(
            p.parse("/packages/x/y/z/python-dateutil-2.8.2.tar.gz"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Pypi,
                name: "python-dateutil".into(),
                version: "2.8.2".into(),
            }
        );
    }

    #[test]
    fn pypi_unknown_extension_is_metadata() {
        let p = PypiParser;
        assert_eq!(p.parse("/packages/x/y/z/foo.txt"), ParseResult::Metadata);
        assert_eq!(p.parse("/"), ParseResult::Metadata);
    }

    // ---------------- nuget tests ----------------

    #[test]
    fn nuget_nupkg_is_pinned() {
        let p = NugetParser;
        assert_eq!(
            p.parse("/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"),
            ParseResult::Pinned {
                ecosystem: Ecosystem::Nuget,
                name: "newtonsoft.json".into(),
                version: "13.0.1".into(),
            }
        );
    }

    #[test]
    fn nuget_non_flatcontainer_paths_are_metadata() {
        let p = NugetParser;
        assert_eq!(
            p.parse("/v3/registration5-semver1/newtonsoft.json/index.json"),
            ParseResult::Metadata
        );
        assert_eq!(p.parse("/"), ParseResult::Metadata);
    }

    #[test]
    fn router_dispatches_to_new_ecosystems() {
        let ps = default_parsers();
        let r = parse_for_host(&ps, "registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz");
        if let ParseResult::Pinned { ecosystem, .. } = r {
            assert_eq!(ecosystem, Ecosystem::Npm);
        } else {
            panic!("expected Pinned for npm");
        }
        let r = parse_for_host(
            &ps,
            "files.pythonhosted.org",
            "/packages/x/y/z/requests-2.31.0.tar.gz",
        );
        assert!(matches!(
            r,
            ParseResult::Pinned {
                ecosystem: Ecosystem::Pypi,
                ..
            }
        ));
        let r = parse_for_host(
            &ps,
            "api.nuget.org",
            "/v3-flatcontainer/x/1.0.0/x.1.0.0.nupkg",
        );
        assert!(matches!(
            r,
            ParseResult::Pinned {
                ecosystem: Ecosystem::Nuget,
                ..
            }
        ));
    }
}

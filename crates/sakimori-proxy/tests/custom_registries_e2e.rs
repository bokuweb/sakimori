//! End-to-end integration: every layer that the custom-registry
//! feature relies on, exercised together against synthetic
//! upstream responses.
//!
//! The unit tests in `src/` cover each module in isolation.
//! This file proves the modules compose for the use case the
//! README + CLAUDE.md document: a team adds an internal mirror
//! (Verdaccio, Takumi Guard, …) via TOML or CLI flag, and every
//! rewriter / lifecycle gate / dispatch path treats that mirror
//! identically to the canonical public host.
//!
//! Boundaries crossed in each test:
//!
//! 1. `registries.rs`     — TOML parse + merge
//! 2. `parser.rs`         — `parsers_from_hosts` + `parse_for_host`
//! 3. `rewrite_*.rs`      — packument / JSON API / simple / registration / sparse
//!
//! If a future change breaks the wiring between any two of those
//! (e.g. parser stops being host-aware, registries struct grows a
//! field rewriters don't read, …) these tests fail.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use sakimori_core::deps::Ecosystem;
use sakimori_proxy::parser::{ParseResult, parse_for_host, parsers_from_hosts};
use sakimori_proxy::registries::RegistryHosts;
use sakimori_proxy::{
    NpmRewriteStats, NugetRewriteStats, PypiRewriteStats, RewriteStats, rewrite_crates_index_jsonl,
    rewrite_npm_packument, rewrite_nuget_flatcontainer, rewrite_nuget_registration,
    rewrite_pypi_json_api, rewrite_pypi_simple_json,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp_toml(tag: &str, body: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!(
        "sakimori-e2e-{tag}-{}-{nanos}.toml",
        std::process::id()
    ));
    std::fs::write(&p, body).unwrap();
    p
}

/// `now` for the synthetic packument fixtures — chosen so the
/// 30-day threshold cleanly slices the "young" / "old" half.
fn frozen_now() -> DateTime<Utc> {
    "2026-05-18T00:00:00Z".parse().unwrap()
}

fn min_age_30d() -> Duration {
    Duration::from_secs(30 * 86_400)
}

// ---------------------------------------------------------------------------
// Layer 1+2 — config → parser routing for every ecosystem
// ---------------------------------------------------------------------------

#[test]
fn toml_config_routes_custom_hosts_for_every_ecosystem() {
    let p = tmp_toml(
        "toml-routes",
        r#"
[registries]
npm           = ["npm.corp.internal"]
pypi_index    = ["pypi.corp.internal"]
pypi_files    = ["files.corp.internal"]
crates        = ["crates.corp.internal"]
crates_sparse = ["sparse.corp.internal"]
nuget         = ["nuget.corp.internal"]
"#,
    );
    let file_hosts = RegistryHosts::load_toml(&p).unwrap();
    let _ = std::fs::remove_file(&p);
    let merged = RegistryHosts::merge(Some(file_hosts), RegistryHosts::default());
    let parsers = parsers_from_hosts(&merged);

    // npm packument (Metadata) + tarball (Pinned) under custom host.
    assert_eq!(
        parse_for_host(&parsers, "npm.corp.internal", "/lodash"),
        ParseResult::Metadata
    );
    let r = parse_for_host(
        &parsers,
        "npm.corp.internal",
        "/lodash/-/lodash-4.17.21.tgz",
    );
    assert!(matches!(
        r,
        ParseResult::Pinned {
            ecosystem: Ecosystem::Npm,
            ..
        }
    ));

    // PyPI metadata host returns Metadata; files host pins.
    assert_eq!(
        parse_for_host(&parsers, "pypi.corp.internal", "/pypi/requests/json"),
        ParseResult::Metadata
    );
    let r = parse_for_host(
        &parsers,
        "files.corp.internal",
        "/packages/aa/bb/cc/requests-2.31.0.tar.gz",
    );
    assert!(matches!(
        r,
        ParseResult::Pinned {
            ecosystem: Ecosystem::Pypi,
            ..
        }
    ));

    // cargo download endpoint + sparse index.
    let r = parse_for_host(
        &parsers,
        "crates.corp.internal",
        "/api/v1/crates/serde/1.0.0/download",
    );
    assert!(matches!(
        r,
        ParseResult::Pinned {
            ecosystem: Ecosystem::Crates,
            ..
        }
    ));
    assert_eq!(
        parse_for_host(&parsers, "sparse.corp.internal", "/1/s/serde"),
        ParseResult::Metadata
    );

    // NuGet flat-container .nupkg.
    let r = parse_for_host(
        &parsers,
        "nuget.corp.internal",
        "/v3-flatcontainer/serilog/3.0.0/serilog.3.0.0.nupkg",
    );
    assert!(matches!(
        r,
        ParseResult::Pinned {
            ecosystem: Ecosystem::Nuget,
            ..
        }
    ));

    // The canonical hosts ALSO still route correctly — the merge
    // must not have stripped them out.
    for (host, path) in [
        ("registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz"),
        ("files.pythonhosted.org", "/x/y/z/requests-2.31.0.tar.gz"),
        ("crates.io", "/api/v1/crates/serde/1.0.0/download"),
    ] {
        assert!(
            matches!(
                parse_for_host(&parsers, host, path),
                ParseResult::Pinned { .. }
            ),
            "{host} {path} should remain Pinned after merge"
        );
    }
}

// ---------------------------------------------------------------------------
// Layer 3 — rewriters: identical behaviour on canonical and custom
// hosts.  These prove the rewrite stage is host-agnostic: it gets a
// body, not a hostname.  The host-membership check happens in the
// dispatcher, and we tested that in Layer 1+2.  Together this is the
// "what if I point cargo at a custom mirror?" end-to-end story.
// ---------------------------------------------------------------------------

#[test]
fn npm_packument_rewrite_drops_young_versions_regardless_of_host() {
    // Body is the only input — `rewrite_npm_packument` doesn't
    // know about hosts, which is precisely why the per-host
    // configuration above is the load-bearing piece for custom
    // registries.  This test pins that property.
    let packument = serde_json::json!({
        "name": "demo",
        "dist-tags": { "latest": "1.0.1" },
        "versions": {
            "1.0.0": { "name": "demo", "version": "1.0.0", "dist": {} },
            "1.0.1": { "name": "demo", "version": "1.0.1", "dist": {} },
        },
        "time": {
            // older than 30d → kept
            "1.0.0": "2026-01-01T00:00:00Z",
            // 5d old → dropped
            "1.0.1": "2026-05-13T00:00:00Z",
        }
    });
    let body = serde_json::to_vec(&packument).unwrap();
    let (rewritten, stats): (Vec<u8>, NpmRewriteStats) =
        rewrite_npm_packument(&body, min_age_30d(), frozen_now());
    assert_eq!(stats.kept, 1);
    assert_eq!(stats.dropped, 1);
    let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    let versions = parsed["versions"].as_object().unwrap();
    assert!(versions.contains_key("1.0.0"));
    assert!(!versions.contains_key("1.0.1"));
    // dist-tag retargeted to the surviving newest.
    assert_eq!(parsed["dist-tags"]["latest"], "1.0.0");
}

#[test]
fn pypi_json_api_rewrite_drops_young_releases() {
    let body = serde_json::json!({
        "info": { "name": "demo", "version": "1.0.1" },
        "releases": {
            "1.0.0": [{
                "upload_time_iso_8601": "2026-01-01T00:00:00Z",
                "filename": "demo-1.0.0.tar.gz",
                "url": "https://files.pythonhosted.org/demo-1.0.0.tar.gz",
            }],
            "1.0.1": [{
                "upload_time_iso_8601": "2026-05-13T00:00:00Z",
                "filename": "demo-1.0.1.tar.gz",
                "url": "https://files.pythonhosted.org/demo-1.0.1.tar.gz",
            }],
        }
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let (rewritten, stats): (Vec<u8>, PypiRewriteStats) =
        rewrite_pypi_json_api(&bytes, min_age_30d(), frozen_now());
    assert!(stats.dropped >= 1);
    let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    let releases = parsed["releases"].as_object().unwrap();
    assert!(releases.contains_key("1.0.0"));
    assert!(!releases.contains_key("1.0.1"));
}

#[test]
fn pypi_simple_json_rewrite_strips_young_files() {
    let body = serde_json::json!({
        "name": "demo",
        "files": [
            {
                "filename": "demo-1.0.0.tar.gz",
                "url": "https://files.pythonhosted.org/demo-1.0.0.tar.gz",
                "upload-time": "2026-01-01T00:00:00Z",
                "hashes": {}
            },
            {
                "filename": "demo-1.0.1.tar.gz",
                "url": "https://files.pythonhosted.org/demo-1.0.1.tar.gz",
                "upload-time": "2026-05-13T00:00:00Z",
                "hashes": {}
            }
        ],
        "versions": ["1.0.0", "1.0.1"]
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let (rewritten, stats) = rewrite_pypi_simple_json(&bytes, min_age_30d(), frozen_now());
    assert_eq!(stats.dropped, 1);
    assert_eq!(stats.kept, 1);
    let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    let files: Vec<&str> = parsed["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["filename"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["demo-1.0.0.tar.gz"]);
}

#[test]
fn nuget_registration_rewrite_drops_young_leaves() {
    // Minimal registration index shape: a single page with two
    // catalog leaves.
    let body = serde_json::json!({
        "count": 1,
        "items": [{
            "count": 2,
            "items": [
                {
                    "catalogEntry": {
                        "id": "Demo.Pkg",
                        "version": "1.0.0",
                        "published": "2026-01-01T00:00:00Z"
                    }
                },
                {
                    "catalogEntry": {
                        "id": "Demo.Pkg",
                        "version": "1.0.1",
                        "published": "2026-05-13T00:00:00Z"
                    }
                }
            ]
        }]
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let (rewritten, stats): (Vec<u8>, NugetRewriteStats) =
        rewrite_nuget_registration(&bytes, min_age_30d(), frozen_now());
    assert_eq!(stats.dropped, 1);
    assert_eq!(stats.kept, 1);
    let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    let page0 = &parsed["items"][0];
    assert_eq!(page0["count"], 1);
    let leaves = page0["items"].as_array().unwrap();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0]["catalogEntry"]["version"], "1.0.0");
}

#[test]
fn nuget_flatcontainer_rewrite_uses_oracle_for_publish_times() {
    // Flat-container index carries no inline times — the rewriter
    // gets a closure that's normally backed by an out-of-band
    // lookup to the registration endpoint.  Synthetic oracle here.
    let body = serde_json::json!({
        "versions": ["1.0.0", "1.0.1", "1.0.2"]
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let publish_times: std::collections::HashMap<&str, DateTime<Utc>> = [
        ("1.0.0", "2026-01-01T00:00:00Z".parse().unwrap()),
        ("1.0.1", "2026-05-13T00:00:00Z".parse().unwrap()),
        // 1.0.2 deliberately omitted → fail-open keeps it.
    ]
    .into_iter()
    .collect();
    let (rewritten, stats) =
        rewrite_nuget_flatcontainer(&bytes, min_age_30d(), frozen_now(), |v| {
            publish_times.get(v).copied()
        });
    assert_eq!(stats.dropped, 1);
    let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    let versions: Vec<&str> = parsed["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(versions, vec!["1.0.0", "1.0.2"]);
}

#[test]
fn crates_sparse_jsonl_drops_young_lines() {
    // Sparse-index line per version, newline-delimited JSON.
    let old = serde_json::json!({
        "name": "demo",
        "vers": "1.0.0",
        "deps": [],
        "cksum": "abc",
        "features": {},
        "yanked": false
    });
    let young = serde_json::json!({
        "name": "demo",
        "vers": "1.0.1",
        "deps": [],
        "cksum": "def",
        "features": {},
        "yanked": false
    });
    let body = format!("{old}\n{young}\n");

    struct FakeOracle;
    impl sakimori_proxy::AgeOracle for FakeOracle {
        fn published(
            &self,
            _eco: Ecosystem,
            _name: &str,
            version: &str,
        ) -> anyhow::Result<Option<DateTime<Utc>>> {
            Ok(match version {
                "1.0.0" => Some("2026-01-01T00:00:00Z".parse().unwrap()),
                "1.0.1" => Some("2026-05-13T00:00:00Z".parse().unwrap()),
                _ => None,
            })
        }
    }
    let decider = sakimori_proxy::Decider {
        oracle: Box::new(FakeOracle) as Box<dyn sakimori_proxy::AgeOracle>,
        min_age: min_age_30d(),
        fail_on_missing: false,
        known_bad: None,
        typosquat: None,
    };
    let (rewritten, stats): (Vec<u8>, RewriteStats) =
        rewrite_crates_index_jsonl(body.as_bytes(), &decider, frozen_now());
    assert_eq!(stats.dropped, 1);
    assert_eq!(stats.kept, 1);
    let s = std::str::from_utf8(&rewritten).unwrap();
    assert!(s.contains("\"vers\":\"1.0.0\""));
    assert!(!s.contains("\"vers\":\"1.0.1\""));
}

// ---------------------------------------------------------------------------
// Layer 1+2 negative tests — disabling an ecosystem in TOML must
// make canonical traffic invisible, and unknown hosts must be Unknown.
// These guard against accidentally re-introducing hardcoded host
// checks downstream of the registries config.
// ---------------------------------------------------------------------------

#[test]
fn empty_npm_section_in_toml_disables_npm_routing() {
    let p = tmp_toml(
        "no-npm",
        r#"
[registries]
npm = []
"#,
    );
    let cfg = RegistryHosts::load_toml(&p).unwrap();
    let _ = std::fs::remove_file(&p);
    let ps = parsers_from_hosts(&cfg);
    assert_eq!(
        parse_for_host(&ps, "registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz"),
        ParseResult::Unknown
    );
    // Other ecosystems still default — only npm was emptied.
    assert!(matches!(
        parse_for_host(&ps, "crates.io", "/api/v1/crates/serde/1.0.0/download"),
        ParseResult::Pinned { .. }
    ));
}

#[test]
fn unknown_host_is_unknown_even_when_path_looks_canonical() {
    let cfg = RegistryHosts::default();
    let ps = parsers_from_hosts(&cfg);
    assert_eq!(
        parse_for_host(
            &ps,
            "evil.example",
            "/v3-flatcontainer/x/1.0.0/x.1.0.0.nupkg"
        ),
        ParseResult::Unknown,
    );
}

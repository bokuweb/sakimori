//! HTTPS MITM proxy that enforces `minimumReleaseAge` at the fetch
//! layer. See the crate README for design + status.

pub mod ca;
pub mod daemon;
pub mod decision;
pub mod install;
pub mod nuget_flatcontainer_client;
pub mod osv;
pub mod osv_mirror;
pub mod parser;
pub mod proxy;
pub mod pypi_simple_client;
pub mod rewrite;
pub mod rewrite_npm;
pub mod rewrite_nuget;
pub mod rewrite_pypi;
pub mod sigstore_verify;
pub mod typosquat;

pub use decision::{AgeOracle, Decider, Decision, RegistryOracle};
pub use parser::{
    CratesIoParser, CratesIoSparseParser, ParseResult, RegistryParser, default_parsers,
    parse_for_host,
};
pub use proxy::{ProxyConfig, run};
pub use rewrite::{RewriteStats, rewrite_crates_index_jsonl};
pub use rewrite_npm::{NpmRewriteStats, rewrite_npm_packument};
pub use rewrite_nuget::{
    NugetRewriteStats, extract_publish_times_from_registration, rewrite_nuget_flatcontainer,
    rewrite_nuget_registration,
};
pub use rewrite_pypi::{
    PypiRewriteStats, extract_publish_times_from_pypi_json, rewrite_pypi_json_api,
    rewrite_pypi_simple_html, rewrite_pypi_simple_json,
};

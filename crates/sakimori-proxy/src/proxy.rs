//! hudsucker-based MITM proxy. Wires the URL parser + age decider
//! into an HTTP request hook.
//!
//! The hook only MITM's traffic for hosts we have a parser for;
//! everything else is CONNECT-tunnelled through unchanged (see
//! [`should_intercept`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response, StatusCode},
    rcgen::KeyPair,
};

use sakimori_core::installs::{ExecutionMode, InstallEvent, InstallLogger};

use crate::ca::{CaFiles, ensure_ca, trust_instructions};
use crate::decision::{AgeOracle, Decider, Decision};
use crate::nuget_flatcontainer_client::NugetFlatContainerClient;
#[cfg(test)]
use crate::parser::default_parsers;
use crate::parser::{ParseResult, RegistryParser, parse_for_host, parsers_from_hosts};
use crate::pypi_simple_client::PypiSimpleClient;
use crate::registries::RegistryHosts;
use crate::rewrite::rewrite_crates_index_jsonl;
use crate::rewrite_npm::{NpmRewriteOptions, rewrite_npm_packument_with};
use crate::rewrite_nuget::{rewrite_nuget_flatcontainer, rewrite_nuget_registration};
use crate::rewrite_pypi::{
    rewrite_pypi_json_api, rewrite_pypi_simple_html, rewrite_pypi_simple_json,
};

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub min_age: Duration,
    pub fail_on_missing: bool,
    /// Strict mode: when `true`, npm packument rewriting drops every
    /// version without a Sigstore provenance claim (see
    /// [`crate::rewrite_npm::NpmRewriteOptions`]). This is the
    /// strongest single knob against "stolen publish token" attacks
    /// that `minimumReleaseAge` alone can't catch.
    pub require_provenance: bool,
    /// When `true`, consult OSV.dev before every age check. Versions
    /// flagged as malicious packages (MAL-* IDs or advisories whose
    /// summary/details contain "malicious") are hard-denied
    /// regardless of `--min-age`.
    pub osv: bool,
    /// When `true`, additionally consume the sakimori-hosted OSV
    /// mirror (pre-filtered to malicious-package advisories) for
    /// O(1) local lookups. Layered in front of live OSV: mirror
    /// hit short-circuits, miss cascades to live when `osv` is
    /// also on.
    pub osv_mirror: bool,
    /// Override URL for `osv_mirror`. Defaults to
    /// [`crate::osv_mirror::DEFAULT_MIRROR_URL`].
    pub osv_mirror_url: Option<String>,
    /// Typosquat detection mode: `None` disables, `Some(Warn)` logs
    /// close-match warnings, `Some(Block)` hard-denies typosquat
    /// candidates.
    pub typosquat: Option<crate::decision::TyposquatMode>,
    /// When `true`, use the sakimori-hosted top-N-per-ecosystem
    /// mirror (~1000 names each) instead of the hard-coded top-100
    /// baked into the binary. Only meaningful when `typosquat` is
    /// also set. Refreshes daily in the background.
    pub typosquat_mirror: bool,
    /// Override URL for `typosquat_mirror`. Defaults to
    /// [`crate::typosquat::DEFAULT_TYPOSQUAT_MIRROR_URL`].
    pub typosquat_mirror_url: Option<String>,
    pub ca_files: CaFiles,
    pub user_agent: String,
    /// Override to inject a fake oracle in tests.
    pub oracle: Option<Box<dyn AgeOracle>>,
    /// Optional egress allow-list. When `Some` and non-empty, the
    /// proxy default-denies every host not on the list (including
    /// CONNECT requests for non-MITM'd hosts). When `None`, egress
    /// is unrestricted — current behaviour. See
    /// [`crate::host_allow::HostMatcher`] for pattern grammar.
    pub network_allow: Option<crate::host_allow::HostMatcher>,
    /// Append-only install log. `Some(path)` overrides the location;
    /// `None` uses [`InstallLogger::default_path`]. To disable
    /// logging entirely, set [`Self::install_log_enabled`] to `false`.
    pub install_log_path: Option<std::path::PathBuf>,
    /// Master switch for the install logger. Defaults to `true` —
    /// the local-first audit log is the foundation of
    /// `sakimori advisories scan`.
    pub install_log_enabled: bool,
    /// Optional OTLP/HTTP logs endpoint. When `Some`, every allowed
    /// install dispatches a fire-and-forget `LogRecord` (with
    /// `package.*` attributes) to this URL in addition to the local
    /// install log. The URL must include the OTLP path (typically
    /// `…/v1/logs`); we don't auto-suffix because collectors may
    /// mount OTLP on a custom path.
    pub otlp_endpoint: Option<String>,
    /// Extra headers attached to every OTLP request — typically
    /// `Authorization: Bearer …` for vendor backends. Ignored when
    /// `otlp_endpoint` is `None`.
    pub otlp_headers: Vec<(String, String)>,
    /// Lifecycle-script policy for npm tarballs. `None` disables the
    /// gate (current default). `Some(Audit)` logs script bodies for
    /// every fetched tarball that ships an `install` / `preinstall` /
    /// `postinstall` / `prepare` hook; `Some(Block)` 403s the tarball
    /// fetch when any of those keys is present, stopping the install
    /// before npm gets to run them. `strip` is on the roadmap but not
    /// yet implemented — the CLI rejects it at parse time.
    pub lifecycle_policy: Option<crate::lifecycle::LifecyclePolicy>,
    /// Per-package allow-list — installs of names on this list bypass
    /// the lifecycle gate entirely. Necessary for legitimate native
    /// addons whose `install` script compiles bindings (e.g.
    /// `sharp`, `bcrypt`, `node-sass`). Patterns are exact npm names,
    /// case-sensitive; no globbing.
    pub lifecycle_allow: Vec<String>,
    /// What `strip` mode does when the tarball rewriter itself fails
    /// (corrupt bytes, exceeded a resource limit, timed out). Default
    /// is `Block`: having opted into strip, the user expects scripts
    /// neutralised, so silently shipping original bytes would be a
    /// security regression. `Passthrough` is available for the rare
    /// case where install completion outweighs the guarantee.
    pub lifecycle_strip_on_failure: crate::lifecycle::StripFailurePolicy,
    /// Hard caps for the strip rewriter (gzip-bomb / oversize / entry
    /// count). Default sizes admit every legitimate npm package while
    /// refusing pathological inputs that would DoS the proxy.
    pub lifecycle_strip_limits: crate::lifecycle::StripLimits,
    /// On-disk strip-cache directory (Phase 2b). `None` = pure
    /// in-memory cache; restarting the proxy loses every entry.
    /// `Some` = entries are persisted atomically and loaded back on
    /// construction so `npm install <pkg>` after a proxy restart
    /// reuses the warm cache instead of needing another speculative
    /// pre-fetch (or worse, EINTEGRITY on the first attempt). The
    /// CLI default is `~/.sakimori/strip-cache/` when strip policy
    /// is active; pass `--lifecycle-no-strip-cache` to disable.
    pub lifecycle_strip_cache_dir: Option<std::path::PathBuf>,
    /// Per-ecosystem registry hosts. Defaults cover the canonical
    /// public registries (`registry.npmjs.org`, `pypi.org` +
    /// `files.pythonhosted.org`, `crates.io` + `index.crates.io`,
    /// `api.nuget.org`). Append additional hosts (Verdaccio, GitHub
    /// Packages, Artifactory, Takumi Guard, …) here so the same
    /// rewriters / lifecycle gate fire on internal-mirror traffic.
    /// See [`RegistryHosts`].
    pub registries: RegistryHosts,
}

impl ProxyConfig {
    pub fn default_dev() -> Result<Self> {
        Ok(Self {
            listen: "127.0.0.1:0".parse().unwrap(),
            min_age: Duration::from_secs(7 * 24 * 3600),
            fail_on_missing: false,
            require_provenance: false,
            osv: false,
            osv_mirror: false,
            osv_mirror_url: None,
            typosquat: None,
            typosquat_mirror: false,
            typosquat_mirror_url: None,
            ca_files: CaFiles::at_default_location()?,
            user_agent: format!("sakimori-proxy/{}", env!("CARGO_PKG_VERSION")),
            oracle: None,
            network_allow: None,
            install_log_path: None,
            install_log_enabled: true,
            otlp_endpoint: None,
            otlp_headers: Vec::new(),
            lifecycle_policy: None,
            lifecycle_allow: Vec::new(),
            lifecycle_strip_on_failure: crate::lifecycle::StripFailurePolicy::Block,
            lifecycle_strip_limits: crate::lifecycle::StripLimits::default(),
            lifecycle_strip_cache_dir: None,
            registries: RegistryHosts::default(),
        })
    }
}

/// Best-effort classification of how the package was being installed.
/// Falls back to `Unknown` when the User-Agent doesn't give us enough
/// signal. Per CLAUDE.md roadmap #6, we default ambiguous cases to
/// `Unknown` rather than mis-classify as `Ephemeral` — the host UI
/// can surface unknowns to the user separately.
pub(crate) fn classify_execution_mode(user_agent: &str) -> ExecutionMode {
    let ua = user_agent.to_ascii_lowercase();
    // Known one-shot runners. Order matters only for readability:
    // each substring is unambiguous.
    if ua.contains("npx")
        || ua.contains("pnpm/dlx")
        || ua.contains("yarn dlx")
        || ua.contains("uvx")
        || ua.contains("pipx")
        || ua.contains("cargo-install")
    {
        return ExecutionMode::Ephemeral;
    }
    // Known persistent package managers. UA strings vary across
    // versions; we look for a stable prefix.
    if ua.starts_with("npm/")
        || ua.starts_with("pnpm/")
        || ua.starts_with("yarn/")
        || ua.starts_with("cargo ")
        || ua.starts_with("cargo/")
        || ua.starts_with("pip/")
        || ua.starts_with("poetry/")
        || ua.starts_with("uv/")
        || ua.starts_with("nuget")
        || ua.contains("nuget command line")
        || ua.contains("nuget xplat command line")
        || ua.contains("dotnet")
    {
        return ExecutionMode::Persistent;
    }
    ExecutionMode::Unknown
}

/// Start the proxy and run until it errors.
pub async fn run(cfg: ProxyConfig) -> Result<()> {
    // Ensure root CA exists, warn on first-run + print trust
    // instructions. Parsing them at startup is cheaper than failing
    // mid-request.
    let (cert_pem, key_pem, generated) = ensure_ca(&cfg.ca_files)?;
    if generated {
        eprintln!(
            "sakimori-proxy: generated root CA at {}\n\n\
             Trust this CA before running package managers through the proxy:\n\n{}",
            cfg.ca_files.cert_pem.display(),
            trust_instructions(&cfg.ca_files)
        );
    }

    let key = KeyPair::from_pem(&String::from_utf8_lossy(&key_pem))
        .context("loading CA key into rcgen")?;
    let ca_cert = rcgen_cert_from_pem(&cert_pem)?;
    let authority = RcgenAuthority::new(key, ca_cert, 1_000);

    let oracle: Box<dyn AgeOracle> = cfg
        .oracle
        .unwrap_or_else(|| Box::new(crate::decision::RegistryOracle::new(cfg.user_agent.clone())));
    // Compose the known-bad oracle chain. Up to three layers:
    //   mirror (local HashMap) → live OSV API → None
    // Only the `osv_mirror` layer runs a background task; the live
    // client is a lazy-per-request HTTP lookup.
    let known_bad: Option<Box<dyn crate::osv::KnownBadOracle>> = match (cfg.osv_mirror, cfg.osv) {
        (false, false) => None,
        (true, false) => {
            let url = cfg
                .osv_mirror_url
                .clone()
                .unwrap_or_else(|| crate::osv_mirror::DEFAULT_MIRROR_URL.to_string());
            log::info!("OSV known-malicious check: mirror only ({url})");
            let mirror = crate::osv_mirror::OsvMirrorOracle::with_url(cfg.user_agent.clone(), url);
            mirror.spawn_refresh_loop();
            Some(Box::new(mirror))
        }
        (false, true) => {
            log::info!("OSV known-malicious check: live API only (api.osv.dev)");
            Some(Box::new(crate::osv::OsvClient::new(cfg.user_agent.clone())))
        }
        (true, true) => {
            let url = cfg
                .osv_mirror_url
                .clone()
                .unwrap_or_else(|| crate::osv_mirror::DEFAULT_MIRROR_URL.to_string());
            log::info!("OSV known-malicious check: mirror ({url}) + live API fallback");
            let mirror = crate::osv_mirror::OsvMirrorOracle::with_url(cfg.user_agent.clone(), url);
            mirror.spawn_refresh_loop();
            Some(Box::new(crate::osv_mirror::LayeredKnownBad {
                primary: Box::new(mirror),
                fallback: Box::new(crate::osv::OsvClient::new(cfg.user_agent.clone())),
            }))
        }
    };
    let typosquat = cfg.typosquat.map(|mode| {
        // Pick the detector variant based on `typosquat_mirror`.
        // Mirror mode spawns a background refresh task now — the
        // first decision after startup may still see the baseline
        // list (mirror HTTP fetch hasn't completed yet), which is
        // fine since the fallback is semantically identical.
        let detector = if cfg.typosquat_mirror {
            let url = cfg
                .typosquat_mirror_url
                .clone()
                .unwrap_or_else(|| crate::typosquat::DEFAULT_TYPOSQUAT_MIRROR_URL.to_string());
            log::info!("typosquat detection: {mode:?} (mirror: {url})");
            let mirror = crate::typosquat::MirroredDetector::with_url(cfg.user_agent.clone(), url);
            mirror.spawn_refresh_loop();
            crate::decision::TyposquatDetector::Mirrored(mirror)
        } else {
            log::info!("typosquat detection: {mode:?} (baseline only)");
            crate::decision::TyposquatDetector::Static(crate::typosquat::Detector::new())
        };
        crate::decision::TyposquatHook { detector, mode }
    });
    let decider = Arc::new(Decider {
        oracle,
        min_age: cfg.min_age,
        fail_on_missing: cfg.fail_on_missing,
        known_bad,
        typosquat,
    });

    if let Some(matcher) = cfg.network_allow.as_ref()
        && !matcher.is_empty()
    {
        log::info!(
            "egress allow-list active: {} pattern(s) — non-matching CONNECT/HTTP returns 403",
            matcher.len(),
        );
    }
    let install_logger = if cfg.install_log_enabled {
        let path = cfg
            .install_log_path
            .clone()
            .unwrap_or_else(InstallLogger::default_path);
        log::info!("install log: {}", path.display());
        Some(Arc::new(InstallLogger::at(path)))
    } else {
        None
    };
    let otlp_exporter = cfg.otlp_endpoint.as_ref().map(|endpoint| {
        log::info!("OTLP log export → {endpoint}");
        Arc::new(crate::otlp::OtlpExporter::new(
            endpoint.clone(),
            cfg.otlp_headers.clone(),
            cfg.user_agent.clone(),
        ))
    });
    let registries = Arc::new(cfg.registries.clone());
    let handler = SakimoriHandler {
        parsers: Arc::new(parsers_from_hosts(&cfg.registries)),
        registries: registries.clone(),
        decider,
        last_host: None,
        last_path: None,
        last_npm_tarball: None,
        last_pypi_sdist: None,
        require_provenance: cfg.require_provenance,
        nuget_flat: NugetFlatContainerClient::new(cfg.user_agent.clone()),
        pypi_simple: PypiSimpleClient::new(cfg.user_agent.clone()),
        network_allow: cfg.network_allow.map(Arc::new),
        install_logger,
        otlp_exporter,
        lifecycle_policy: cfg.lifecycle_policy,
        lifecycle_allow: Arc::new(cfg.lifecycle_allow.into_iter().collect()),
        lifecycle_strip_on_failure: cfg.lifecycle_strip_on_failure,
        lifecycle_strip_limits: cfg.lifecycle_strip_limits,
        strip_cache: Arc::new(match cfg.lifecycle_strip_cache_dir.as_ref() {
            Some(dir) => match crate::strip_cache::StripCache::with_persist_dir(dir.clone()) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!(
                        "strip-cache: could not open persist dir {}: {e} — falling back to in-memory",
                        dir.display(),
                    );
                    crate::strip_cache::StripCache::new()
                }
            },
            None => crate::strip_cache::StripCache::new(),
        }),
        upstream_user_agent: cfg.user_agent.clone(),
    };

    // `.build()` in hudsucker 0.22 returns Proxy<…> directly; no Result.
    let proxy = Proxy::builder()
        .with_addr(cfg.listen)
        .with_rustls_client()
        .with_ca(authority)
        .with_http_handler(handler)
        .build();

    log::info!("sakimori-proxy listening on {}", cfg.listen);
    proxy.start().await.context("proxy.start()")
}

fn rcgen_cert_from_pem(pem: &[u8]) -> Result<rcgen::Certificate> {
    let text = String::from_utf8_lossy(pem).to_string();
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(&text).context("parsing CA cert PEM")?;
    let key = rcgen::KeyPair::generate().context("regen keypair for rcgen cert")?;
    let cert = params.self_signed(&key).context("re-sign CA cert")?;
    Ok(cert)
}

/// Only MITM traffic bound for hosts we care about. Everything else
/// gets passed through as an opaque TCP tunnel.
fn should_intercept(host: &str, parsers: &[Box<dyn RegistryParser>]) -> bool {
    parsers
        .iter()
        .any(|p| p.hosts().iter().any(|h| host.eq_ignore_ascii_case(h)))
}

/// Decide whether an incoming request should be denied by the
/// hostname allow-list. Returns `None` to allow (or when the
/// matcher is empty / disabled), `Some(reason)` to deny.
///
/// CONNECT requests carry the target host in `req.uri().authority()`;
/// plain HTTP requests in the `Host:` header. Picking the right one
/// matters because hudsucker invokes `handle_request` for the
/// CONNECT itself — a denied CONNECT must short-circuit before the
/// upstream tunnel opens.
///
/// Extracted so the deny decision can be unit-tested without
/// constructing hudsucker's `HttpContext`.
fn egress_deny_reason(
    matcher: &crate::host_allow::HostMatcher,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> Option<String> {
    if matcher.is_empty() {
        return None;
    }
    let target = if method == http::Method::CONNECT {
        uri.authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_default()
    } else {
        headers
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
            .unwrap_or_default()
    };
    if matcher.allows(&target) {
        None
    } else {
        Some(format!(
            "egress denied: host `{target}` not on the allow-list"
        ))
    }
}

#[derive(Clone)]
struct SakimoriHandler {
    parsers: Arc<Vec<Box<dyn RegistryParser>>>,
    /// Same host configuration the parsers were built from; consulted
    /// by `classify_response` so the rewriters fire on user-configured
    /// internal mirrors and not only the canonical public hosts.
    registries: Arc<RegistryHosts>,
    decider: Arc<Decider<dyn AgeOracle>>,
    /// Host of the in-flight request, captured in `handle_request` so
    /// `handle_response` knows whether to rewrite the body. hudsucker
    /// guarantees the same handler instance sees the matching pair.
    last_host: Option<String>,
    /// Path of the in-flight request. Used to decide whether an
    /// `registry.npmjs.org` response is a packument (bare `/<pkg>`) —
    /// per-version endpoints and tarballs must be left untouched.
    last_path: Option<String>,
    /// Forwarded from [`ProxyConfig::require_provenance`]. Consulted
    /// by the npm rewrite path.
    require_provenance: bool,
    /// Looks up per-package publish times from the registration
    /// endpoint so we can silently filter the flat-container index
    /// (which has no dates inline).
    nuget_flat: NugetFlatContainerClient,
    /// Looks up per-package publish times from the Warehouse JSON
    /// API so we can silently filter the PEP 503 HTML Simple index
    /// (which has no dates inline).
    pypi_simple: PypiSimpleClient,
    /// Append-only install log. `None` disables logging.
    install_logger: Option<Arc<InstallLogger>>,
    /// Optional OTLP/HTTP log exporter. `None` disables OTLP fan-out.
    /// Coexists with `install_logger`: per CLAUDE.md roadmap #6 the
    /// two transports complement each other (`/ingest` is for
    /// sakimori-hub push notifications, OTLP is for generic
    /// observability backends).
    otlp_exporter: Option<Arc<crate::otlp::OtlpExporter>>,
    /// Hostname allow-list. `None` (or empty) → unrestricted egress.
    /// `Some(non-empty)` → default-deny: any CONNECT or plain-HTTP
    /// request whose target host doesn't match returns 403 before
    /// hudsucker tunnels or MITMs anything.
    network_allow: Option<Arc<crate::host_allow::HostMatcher>>,
    /// `Some((name, version))` when the in-flight request was a
    /// pinned npm tarball. `handle_response` consults this to decide
    /// whether to run the lifecycle gate. Reset to `None` on every
    /// request so an earlier tarball's identity can't bleed across.
    last_npm_tarball: Option<(String, String)>,
    /// As above for pinned PyPI source distributions (`.tar.gz` /
    /// `.zip` ending). Wheels (`.whl`) are not tagged — they carry
    /// no install-time hook surface to inspect.
    last_pypi_sdist: Option<(String, String)>,
    /// Forwarded from [`ProxyConfig::lifecycle_policy`]. `None`
    /// disables the gate entirely (no tarball buffering, no inspect).
    lifecycle_policy: Option<crate::lifecycle::LifecyclePolicy>,
    /// Pre-built set of package names that bypass the gate. Wrapped
    /// in `Arc` so cloning the handler is O(1) — hudsucker may clone
    /// the handler per connection.
    lifecycle_allow: Arc<std::collections::HashSet<String>>,
    /// Forwarded from [`ProxyConfig::lifecycle_strip_on_failure`].
    lifecycle_strip_on_failure: crate::lifecycle::StripFailurePolicy,
    /// Forwarded from [`ProxyConfig::lifecycle_strip_limits`]. Pure
    /// data so `Copy`-cloned on every strip invocation.
    lifecycle_strip_limits: crate::lifecycle::StripLimits,
    /// Shared in-memory cache of stripped tarballs. Indexed by
    /// `(name, version, orig_integrity)`. Populated by the
    /// speculative pre-strip in the packument response path and by
    /// lazy strips in the tarball response path; read by the
    /// packument rewriter (to inject new integrity / shasum) and the
    /// tarball handler (to decide whether to serve cached rewritten
    /// bytes or do a fresh strip).
    strip_cache: Arc<crate::strip_cache::StripCache>,
    /// User-Agent the proxy uses when it fetches tarballs upstream
    /// itself for speculative pre-strip. Reuses the same string
    /// configured on `ProxyConfig` so the upstream sees a consistent
    /// caller identity (npm's registry tolerates anything but it's
    /// useful for log triage).
    upstream_user_agent: String,
}

impl SakimoriHandler {
    /// Buffer the tarball body, inspect `package.json` for
    /// install-time lifecycle scripts, then either audit-log + pass
    /// through (Audit) or return 403 (Block).
    ///
    /// On any failure to parse the body as a gzipped tarball, we
    /// fail open: pass the body through unchanged. The proxy's job
    /// is to defend, not to invent rejections that would break
    /// installs of legitimately-non-npm-shaped artefacts the parser
    /// nonetheless tagged as Pinned. The log line records the
    /// fail-open so it's still auditable.
    async fn lifecycle_inspect_npm_tarball(
        &self,
        res: Response<Body>,
        policy: crate::lifecycle::LifecyclePolicy,
        name: &str,
        version: &str,
    ) -> Response<Body> {
        use http_body_util::BodyExt;
        let (mut parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                log::warn!("lifecycle: failed to buffer tarball body for {name}@{version}: {e}");
                return Response::from_parts(parts, Body::empty());
            }
        };
        let pass_through = || -> Response<Body> {
            // Re-emit unchanged. Strip Content-Length so hyper
            // recomputes it (the bytes are the same length, but
            // hudsucker's re-framing path is happier when we do).
            let mut parts2 = parts.clone();
            parts2.headers.remove(http::header::CONTENT_LENGTH);
            Response::from_parts(
                parts2,
                Body::from(http_body_util::Full::new(collected.clone())),
            )
        };
        let inspection = match crate::lifecycle::inspect_npm_tarball(&collected) {
            Ok(i) => i,
            Err(e) => {
                log::warn!(
                    "lifecycle: fail-open on {name}@{version} — could not inspect tarball: {e}"
                );
                return pass_through();
            }
        };
        if !inspection.has_scripts() {
            log::debug!("lifecycle: {name}@{version} — no install-time scripts");
            return pass_through();
        }
        let stages: Vec<&str> = inspection.scripts.iter().map(|s| s.stage).collect();
        match policy {
            crate::lifecycle::LifecyclePolicy::Audit => {
                log::warn!(
                    "lifecycle(audit): {name}@{version} ships {} install-time script(s): {}",
                    stages.len(),
                    stages.join(", ")
                );
                for s in &inspection.scripts {
                    log::info!(
                        "lifecycle(audit): {name}@{version} [{stage}]: {body}",
                        stage = s.stage,
                        body = s.body
                    );
                }
                pass_through()
            }
            crate::lifecycle::LifecyclePolicy::Block => {
                let reason = format!(
                    "lifecycle: blocking {name}@{version} — ships install-time script(s): {}. \
                     Add `{name}` to the lifecycle allow-list if this install is expected, \
                     or relax to `--lifecycle-policy audit` to log without blocking.",
                    stages.join(", ")
                );
                log::warn!("{reason}");
                parts.headers.remove(http::header::CONTENT_LENGTH);
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-sakimori-deny", "lifecycle-script")
                    .body(Body::from(format!("{reason}\n")))
                    .expect("static lifecycle deny response")
            }
            crate::lifecycle::LifecyclePolicy::Strip => {
                // Phase 2: actually rewrite the tarball in place,
                // populate the strip cache so a subsequent packument
                // response sees the new integrity, and serve the
                // rewritten bytes. The cache key includes the
                // *original* SRI hash of the upstream bytes, derived
                // here from the buffered body — this is what the
                // packument also advertised pre-rewrite, so the
                // tarball handler and the packument rewriter agree
                // on the lookup key.
                let orig_integrity = sri_sha512_of(&collected);
                let key = crate::strip_cache::StripKey {
                    name: name.to_string(),
                    version: version.to_string(),
                    orig_integrity: orig_integrity.clone(),
                };
                let stripped = match crate::lifecycle::strip_npm_tarball(
                    &collected,
                    &self.lifecycle_strip_limits,
                ) {
                    Ok(Some(out)) => out,
                    Ok(None) => {
                        // package.json carried no install-time keys
                        // after all (rare — inspect found scripts
                        // but strip's mutate pass disagrees — only
                        // possible when LIFECYCLE_KEYS values are
                        // empty strings or the JSON shape is exotic).
                        // Pass original bytes through and remember
                        // the verdict so the packument rewriter
                        // doesn't try to rewrite this version.
                        self.strip_cache
                            .insert(key, crate::strip_cache::StripCacheEntry::NoStripNeeded);
                        return pass_through();
                    }
                    Err(e) => {
                        return strip_failure_response(
                            &mut parts,
                            self.lifecycle_strip_on_failure,
                            name,
                            version,
                            &e,
                            collected,
                        );
                    }
                };
                log::warn!(
                    "lifecycle(strip): {name}@{version} removed [{}]; new integrity sha512=<…>{}",
                    stripped.stripped_stages.join(", "),
                    // Keep the suffix short in the warn log; full
                    // value is available on the cache entry.
                    &stripped.sha512_b64[..stripped.sha512_b64.len().min(8)],
                );
                let new_integrity = format!("sha512-{}", stripped.sha512_b64);
                let new_shasum = stripped.sha1_hex.clone();
                let bytes = std::sync::Arc::new(stripped.bytes.clone());
                self.strip_cache.insert(
                    key,
                    crate::strip_cache::StripCacheEntry::Stripped {
                        new_integrity,
                        new_shasum,
                        bytes: bytes.clone(),
                    },
                );
                parts.headers.remove(http::header::CONTENT_LENGTH);
                parts.headers.remove(http::header::CONTENT_ENCODING);
                Response::from_parts(
                    parts,
                    Body::from(http_body_util::Full::new(bytes::Bytes::from(
                        stripped.bytes,
                    ))),
                )
            }
        }
    }

    /// PyPI counterpart to [`Self::lifecycle_inspect_npm_tarball`].
    /// Block mode fires on `setup.py` presence — that's the
    /// PEP-517-era legacy unbounded install hook with the same threat
    /// model as npm's `postinstall`. Modern `pyproject.toml`-only
    /// projects still execute the declared build backend, but the
    /// scope is bounded by the backend's `build-requires` and the
    /// audit log records what backend ran so a human can triage.
    async fn lifecycle_inspect_pypi_sdist(
        &self,
        res: Response<Body>,
        policy: crate::lifecycle::LifecyclePolicy,
        name: &str,
        version: &str,
    ) -> Response<Body> {
        use http_body_util::BodyExt;
        let (mut parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                log::warn!(
                    "lifecycle(pypi): failed to buffer sdist body for {name}@{version}: {e}"
                );
                return Response::from_parts(parts, Body::empty());
            }
        };
        let pass_through = || -> Response<Body> {
            let mut parts2 = parts.clone();
            parts2.headers.remove(http::header::CONTENT_LENGTH);
            Response::from_parts(
                parts2,
                Body::from(http_body_util::Full::new(collected.clone())),
            )
        };
        let inspection = match crate::lifecycle::inspect_pypi_sdist(&collected) {
            Ok(i) => i,
            Err(e) => {
                log::warn!(
                    "lifecycle(pypi): fail-open on {name}@{version} — could not inspect sdist: {e}"
                );
                return pass_through();
            }
        };
        if inspection.is_clean() {
            log::debug!(
                "lifecycle(pypi): {name}@{version} — no setup.py and no declared build backend"
            );
            return pass_through();
        }
        // Audit always records what we found so the log captures the
        // backend even on a pass-through.
        let backend_desc = inspection.build_backend.as_deref().unwrap_or("<none>");
        log::warn!(
            "lifecycle(pypi,{mode:?}): {name}@{version} — setup.py={setup}, build-backend={backend}",
            mode = policy,
            setup = inspection.has_setup_py,
            backend = backend_desc,
        );
        if !inspection.build_requires.is_empty() {
            log::info!(
                "lifecycle(pypi): {name}@{version} declared build-requires: {}",
                inspection.build_requires.join(", "),
            );
        }
        match policy {
            crate::lifecycle::LifecyclePolicy::Audit => pass_through(),
            crate::lifecycle::LifecyclePolicy::Strip => {
                // Strip is npm-only. For PyPI sdists, `setup.py`
                // removal generally breaks the build (the legacy
                // backend has no `pyproject.toml`-only fallback path
                // for most projects), so Strip falls back to Block
                // semantics on the PyPI side. Documented in
                // CLAUDE.md roadmap #15.
                if !inspection.is_legacy_install_hook() {
                    return pass_through();
                }
                let reason = format!(
                    "lifecycle(pypi,strip→block): {name}@{version} — sdist ships `setup.py`. \
                     Strip mode does not rewrite PyPI sdists (setup.py removal would break the \
                     install); falling back to Block. Prefer a wheel or allow-list `{name}`."
                );
                log::warn!("{reason}");
                parts.headers.remove(http::header::CONTENT_LENGTH);
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-sakimori-deny", "lifecycle-script")
                    .body(Body::from(format!("{reason}\n")))
                    .expect("static lifecycle deny response")
            }
            crate::lifecycle::LifecyclePolicy::Block => {
                if !inspection.is_legacy_install_hook() {
                    // Modern PEP 517 backends only — audit-log and let
                    // it through. We deliberately don't extend Block
                    // to backend-name matching in the first slice;
                    // there's no clean denylist and the false-positive
                    // cost would be high (every Hatch-built scientific
                    // package would 403).
                    return pass_through();
                }
                let reason = format!(
                    "lifecycle(pypi): blocking {name}@{version} — sdist ships `setup.py`, a \
                     legacy installer hook that runs arbitrary Python with the user's privileges. \
                     Prefer a wheel (`pip install --only-binary=:all:`) if upstream publishes \
                     one, add `{name}` to the lifecycle allow-list if this install is expected, \
                     or relax to `--lifecycle-policy audit` to log without blocking."
                );
                log::warn!("{reason}");
                parts.headers.remove(http::header::CONTENT_LENGTH);
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-sakimori-deny", "lifecycle-script")
                    .body(Body::from(format!("{reason}\n")))
                    .expect("static lifecycle deny response")
            }
        }
    }
}

/// Recognise PyPI source distribution URLs by file extension. We
/// only gate sdists because wheels carry no install-time hooks —
/// pip's wheel installer is a deterministic file-copy + RECORD update.
/// `.zip` sdists are rare (almost all of PyPI is `.tar.gz` now) but
/// included for completeness; the inspector still requires a gzip
/// magic byte so a real `.zip` will fail-open as "not gzip" and
/// pass through with a warn log.
fn path_is_pypi_sdist(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".zip")
}

impl HttpHandler for SakimoriHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // Hostname egress allow-list — runs before everything else.
        if let Some(matcher) = self.network_allow.as_deref()
            && let Some(reason) =
                egress_deny_reason(matcher, req.method(), req.uri(), req.headers())
        {
            log::warn!("egress deny: {} {}", req.method(), reason);
            self.last_host = None;
            self.last_path = None;
            return RequestOrResponse::Response(deny_response(&reason));
        }

        // Host header is required; without it we can't route.
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();
        if !should_intercept(&host, &self.parsers) {
            self.last_host = None;
            self.last_path = None;
            self.last_npm_tarball = None;
            self.last_pypi_sdist = None;
            return RequestOrResponse::Request(req);
        }
        self.last_host = Some(host.clone());
        // Reset per-request; the `Pinned` branch below may set it back.
        self.last_npm_tarball = None;
        self.last_pypi_sdist = None;
        let path: String = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        self.last_path = Some(path.clone());
        // Force upstream to send us plain-body responses so our
        // rewriters see JSON / JSONL directly. Without this, npm
        // and pypi will gzip-encode and we'd have to decode+reencode
        // to filter — hudsucker doesn't decode response bodies for
        // us. Tarballs are content-encoded, not transfer-encoded,
        // so this flag doesn't inflate their wire size.
        let mut req = req;
        req.headers_mut().insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("identity"),
        );
        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        match parse_for_host(&self.parsers, &host, &path) {
            ParseResult::Pinned {
                ecosystem,
                name,
                version,
            } => {
                // Remember npm-pinned identity so the lifecycle gate
                // in `handle_response` can attribute findings without
                // re-parsing the path.
                if self.lifecycle_policy.is_some()
                    && matches!(ecosystem, sakimori_core::deps::Ecosystem::Npm)
                    && !self.lifecycle_allow.contains(&name)
                {
                    self.last_npm_tarball = Some((name.clone(), version.clone()));
                }
                // Same tagging for PyPI, but only for source
                // distributions — wheels (`.whl`) are install-time
                // hook-free, so subjecting them to the gate would
                // burn cycles and risk false positives without any
                // defensive value.
                if self.lifecycle_policy.is_some()
                    && matches!(ecosystem, sakimori_core::deps::Ecosystem::Pypi)
                    && !self.lifecycle_allow.contains(&name)
                    && path_is_pypi_sdist(&path)
                {
                    self.last_pypi_sdist = Some((name.clone(), version.clone()));
                }
                let now = Utc::now();
                match self.decider.decide(ecosystem, &name, &version, now) {
                    Decision::Allow => {
                        if self.install_logger.is_some() || self.otlp_exporter.is_some() {
                            let mode = classify_execution_mode(&user_agent);
                            let mut ev =
                                InstallEvent::new(ecosystem, &name, &version).with_mode(mode);
                            if !user_agent.is_empty() {
                                ev = ev.with_user_agent(&user_agent);
                            }
                            if let Some(logger) = self.install_logger.as_ref()
                                && let Err(e) = logger.record(&ev)
                            {
                                // Non-fatal: an unwritable install log
                                // must not break package installs.
                                log::warn!("install log write failed: {e:#}");
                            }
                            if let Some(exporter) = self.otlp_exporter.as_ref() {
                                exporter.dispatch(&ev);
                            }
                        }
                        RequestOrResponse::Request(req)
                    }
                    Decision::Deny { reason } => {
                        log::warn!("deny {host}{path}: {reason}");
                        RequestOrResponse::Response(deny_response(&reason))
                    }
                }
            }
            ParseResult::Metadata | ParseResult::Unknown => RequestOrResponse::Request(req),
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // Lifecycle gate runs first because tarballs don't show up in
        // `classify_response` (which only knows about metadata
        // endpoints). Only buffer + inspect when the gate is active
        // AND this response is for a pinned npm tarball we tagged in
        // `handle_request`. Take()-style — a clone-then-clear semantic
        // would also work but Option::take is what we want.
        if let Some(policy) = self.lifecycle_policy
            && let Some((name, version)) = self.last_npm_tarball.take()
            && res.status().is_success()
        {
            return self
                .lifecycle_inspect_npm_tarball(res, policy, &name, &version)
                .await;
        }
        if let Some(policy) = self.lifecycle_policy
            && let Some((name, version)) = self.last_pypi_sdist.take()
            && res.status().is_success()
        {
            return self
                .lifecycle_inspect_pypi_sdist(res, policy, &name, &version)
                .await;
        }

        // Decide whether and how to rewrite based on host + path. Only
        // endpoints we specifically understand get touched; everything
        // else flows through byte-for-byte.
        let Some(target) = classify_response(
            self.last_host.as_deref(),
            self.last_path.as_deref(),
            &self.registries,
        ) else {
            return res;
        };
        // 2xx only — preserve 404 / 304 / etc. as-is.
        if !res.status().is_success() {
            return res;
        }

        use http_body_util::BodyExt;
        let (mut parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                log::warn!("rewrite: failed to buffer response body: {e}");
                return Response::from_parts(parts, Body::empty());
            }
        };

        // If the upstream used gzip/br etc. the filter would see
        // opaque bytes (hudsucker doesn't auto-decode), so refuse to
        // rewrite encoded bodies — pass them through instead.
        if let Some(enc) = parts.headers.get(http::header::CONTENT_ENCODING)
            && !enc.as_bytes().eq_ignore_ascii_case(b"identity")
        {
            log::debug!("rewrite: skipping non-identity Content-Encoding");
            return Response::from_parts(parts, Body::from(http_body_util::Full::new(collected)));
        }

        let now = Utc::now();
        let rewritten = match target {
            RewriteTarget::CratesSparse => {
                let (out, stats) = rewrite_crates_index_jsonl(&collected, &self.decider, now);
                if stats.dropped > 0 {
                    log::info!(
                        "sparse-rewrite: dropped {} version(s), kept {} (crates.io)",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
            RewriteTarget::NpmPackument => {
                let (out, stats) = rewrite_npm_packument_with(
                    &collected,
                    self.decider.min_age,
                    now,
                    NpmRewriteOptions {
                        require_provenance: self.require_provenance,
                        strip_cache: Some(self.strip_cache.clone()),
                    },
                );
                if stats.dropped > 0 {
                    log::info!(
                        "npm-rewrite: dropped {} version(s) ({} for missing provenance), kept {}, retargeted {} tag(s)",
                        stats.dropped,
                        stats.dropped_no_provenance,
                        stats.kept,
                        stats.retargeted_tags
                    );
                }
                if matches!(
                    self.lifecycle_policy,
                    Some(crate::lifecycle::LifecyclePolicy::Strip)
                ) {
                    speculative_pre_strip_packument(
                        out,
                        self.strip_cache.clone(),
                        self.lifecycle_allow.clone(),
                        self.lifecycle_strip_limits,
                        self.upstream_user_agent.clone(),
                    )
                    .await
                } else {
                    out
                }
            }
            RewriteTarget::PypiJsonApi => {
                let (out, stats) = rewrite_pypi_json_api(&collected, self.decider.min_age, now);
                if stats.dropped > 0 {
                    log::info!(
                        "pypi-rewrite(json): dropped {} version(s), kept {}",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
            RewriteTarget::PypiSimpleIndex(pkg) => {
                // PEP 691 JSON vs PEP 503 HTML share the same path;
                // Content-Type is the source of truth.
                let ct = parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                if ct.contains("application/vnd.pypi.simple.v1+json")
                    || ct.contains("application/vnd.pypi.simple.latest+json")
                {
                    let (out, stats) =
                        rewrite_pypi_simple_json(&collected, self.decider.min_age, now);
                    if stats.dropped > 0 {
                        log::info!(
                            "pypi-rewrite(simple-json): dropped {} file(s), kept {}",
                            stats.dropped,
                            stats.kept
                        );
                    }
                    out
                } else if ct.contains("text/html") || ct.contains("application/xhtml") {
                    // PEP 503 HTML: no inline publish times. Look them
                    // up out-of-band from the Warehouse JSON API,
                    // cached per package. A failed lookup yields an
                    // empty map, so the filter fails open — the
                    // downstream `files.pythonhosted.org` tarball-deny
                    // path still catches too-young pins.
                    let oracle = self.pypi_simple.lookup(&pkg).await;
                    let (out, stats) =
                        rewrite_pypi_simple_html(&collected, self.decider.min_age, now, |v| {
                            oracle.get(v).copied()
                        });
                    if stats.dropped > 0 {
                        log::info!(
                            "pypi-rewrite(simple-html): dropped {} anchor(s), kept {} for {pkg}",
                            stats.dropped,
                            stats.kept
                        );
                    }
                    out
                } else {
                    log::debug!("pypi-rewrite(simple): pass-through (unknown Content-Type {ct:?})");
                    return Response::from_parts(
                        parts,
                        Body::from(http_body_util::Full::new(collected)),
                    );
                }
            }
            RewriteTarget::NugetRegistration => {
                let (out, stats) =
                    rewrite_nuget_registration(&collected, self.decider.min_age, now);
                if stats.dropped > 0 {
                    log::info!(
                        "nuget-rewrite: dropped {} version(s), kept {}",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
            RewriteTarget::NugetFlatContainerIndex(id) => {
                // Look up publish times from the registration endpoint.
                // Cached per package; a failed lookup yields an empty
                // map which makes the filter fail-open (pinned `.nupkg`
                // fetches still hard-deny at the tarball layer, so
                // fail-open doesn't silently admit young versions into
                // a build).
                let oracle = self.nuget_flat.lookup(&id).await;
                let (out, stats) =
                    rewrite_nuget_flatcontainer(&collected, self.decider.min_age, now, |v| {
                        oracle.get(v).copied()
                    });
                if stats.dropped > 0 {
                    log::info!(
                        "nuget-flat: dropped {} version(s), kept {} for {id}",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
        };

        // Strip Content-Length so hyper recomputes it from the new body.
        parts.headers.remove(http::header::CONTENT_LENGTH);
        Response::from_parts(
            parts,
            Body::from(http_body_util::Full::new(bytes::Bytes::from(rewritten))),
        )
    }
}

/// SRI string (`sha512-<base64>`) of the input bytes — matches the
/// shape npm uses for `dist.integrity`. Used to key the strip cache
/// off the upstream tarball's hash so a mirror serving different
/// bytes for the same `(name, version)` cannot poison the cache.
fn sri_sha512_of(bytes: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    let mut h = sha2::Sha512::new();
    h.update(bytes);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    )
}

/// Build the response served when the strip rewriter itself fails
/// (corrupt bytes / exceeded a resource cap / etc.). `Block`
/// returns 403 with a strip-specific deny header; `Passthrough`
/// ships the original upstream bytes with a warn log.
fn strip_failure_response(
    parts: &mut http::response::Parts,
    policy: crate::lifecycle::StripFailurePolicy,
    name: &str,
    version: &str,
    err: &crate::lifecycle::StripError,
    collected: bytes::Bytes,
) -> Response<Body> {
    match policy {
        crate::lifecycle::StripFailurePolicy::Block => {
            let reason = format!(
                "lifecycle(strip): rewriter failed on {name}@{version}: {err}. \
                 Pass --lifecycle-strip-on-failure passthrough to serve the original bytes \
                 anyway (security regression — opt in deliberately)."
            );
            log::warn!("{reason}");
            parts.headers.remove(http::header::CONTENT_LENGTH);
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "text/plain; charset=utf-8")
                .header("x-sakimori-deny", "lifecycle-strip-failed")
                .body(Body::from(format!("{reason}\n")))
                .expect("static lifecycle strip-fail response")
        }
        crate::lifecycle::StripFailurePolicy::Passthrough => {
            log::warn!(
                "lifecycle(strip,passthrough): rewriter failed on {name}@{version}: {err} — serving original bytes",
            );
            parts.headers.remove(http::header::CONTENT_LENGTH);
            Response::from_parts(
                parts.clone(),
                Body::from(http_body_util::Full::new(collected)),
            )
        }
    }
}

/// Speculative pre-strip on the post-rewrite packument. Called from
/// the npm packument response branch when `--lifecycle-policy strip`
/// is on. Finds the version that `dist-tags.latest` resolves to,
/// fetches its tarball directly from the upstream registry (bypassing
/// the proxy itself to avoid a recursion), runs `strip_npm_tarball`,
/// populates the strip cache, and reapplies the cache to the
/// packument so npm receives integrity values that match the bytes
/// the tarball handler will serve. Bounded by a 10-second wall-clock
/// budget — on any failure we leave the packument unchanged and let
/// the lazy tarball-path strip take over.
///
/// Only the `latest` tag is pre-stripped. Explicit pinned-version
/// installs (`npm install pkg@1.2.3` for a non-latest version) hit
/// the tarball handler's lazy path, populate the cache there, and
/// then succeed on retry — the first attempt fails with EINTEGRITY
/// because the packument advertised the original hash. Documented
/// in CLAUDE.md roadmap #15.
async fn speculative_pre_strip_packument(
    rewritten: Vec<u8>,
    strip_cache: std::sync::Arc<crate::strip_cache::StripCache>,
    lifecycle_allow: std::sync::Arc<std::collections::HashSet<String>>,
    strip_limits: crate::lifecycle::StripLimits,
    user_agent: String,
) -> Vec<u8> {
    let mut doc: serde_json::Value = match serde_json::from_slice(&rewritten) {
        Ok(v) => v,
        Err(_) => return rewritten,
    };
    let Some(obj) = doc.as_object_mut() else {
        return rewritten;
    };
    let Some(name) = obj.get("name").and_then(|v| v.as_str()).map(String::from) else {
        return rewritten;
    };
    if lifecycle_allow.contains(&name) {
        return rewritten;
    }
    let Some(latest) = obj
        .get("dist-tags")
        .and_then(|t| t.get("latest"))
        .and_then(|v| v.as_str())
        .map(String::from)
    else {
        return rewritten;
    };
    let (tarball_url, orig_integrity) = {
        let Some(versions) = obj.get("versions").and_then(|v| v.as_object()) else {
            return rewritten;
        };
        let Some(meta) = versions.get(&latest) else {
            return rewritten;
        };
        let Some(dist) = meta.get("dist") else {
            return rewritten;
        };
        let url = dist
            .get("tarball")
            .and_then(|v| v.as_str())
            .map(String::from);
        let integ = dist
            .get("integrity")
            .and_then(|v| v.as_str())
            .map(String::from);
        match (url, integ) {
            (Some(u), Some(i)) => (u, i),
            _ => return rewritten,
        }
    };
    let key = crate::strip_cache::StripKey {
        name: name.clone(),
        version: latest.clone(),
        orig_integrity: orig_integrity.clone(),
    };
    if strip_cache.get(&key).is_none() {
        let url = tarball_url.clone();
        let ua = user_agent.clone();
        let fetch = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || -> std::result::Result<Vec<u8>, String> {
                use std::io::Read;
                let agent = ureq::AgentBuilder::new()
                    .user_agent(&ua)
                    .timeout(Duration::from_secs(8))
                    .build();
                let resp = agent.get(&url).call().map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                // Cap reads so a malicious upstream cannot bleed
                // memory by sending an unbounded body.
                resp.into_reader()
                    .take(128 * 1024 * 1024)
                    .read_to_end(&mut buf)
                    .map_err(|e| e.to_string())?;
                Ok(buf)
            }),
        )
        .await;
        let bytes = match fetch {
            Ok(Ok(Ok(b))) => b,
            Ok(Ok(Err(e))) => {
                log::warn!(
                    "lifecycle(strip,speculative): upstream fetch failed for {name}@{latest}: {e}",
                );
                return rewritten;
            }
            Ok(Err(e)) => {
                log::warn!(
                    "lifecycle(strip,speculative): spawn_blocking join failed for {name}@{latest}: {e}",
                );
                return rewritten;
            }
            Err(_) => {
                log::warn!(
                    "lifecycle(strip,speculative): upstream fetch timed out for {name}@{latest} (10s budget)",
                );
                return rewritten;
            }
        };
        let actual = sri_sha512_of(&bytes);
        if actual != orig_integrity {
            log::warn!(
                "lifecycle(strip,speculative): {name}@{latest} bytes don't match advertised integrity (got {}, expected {}); skipping cache write",
                actual,
                orig_integrity,
            );
            return rewritten;
        }
        let entry = match crate::lifecycle::strip_npm_tarball(&bytes, &strip_limits) {
            Ok(Some(out)) => {
                log::info!(
                    "lifecycle(strip,speculative): cached {name}@{latest} (removed [{}])",
                    out.stripped_stages.join(", "),
                );
                crate::strip_cache::StripCacheEntry::Stripped {
                    new_integrity: format!("sha512-{}", out.sha512_b64),
                    new_shasum: out.sha1_hex,
                    bytes: std::sync::Arc::new(out.bytes),
                }
            }
            Ok(None) => {
                log::debug!(
                    "lifecycle(strip,speculative): {name}@{latest} carries no lifecycle scripts"
                );
                crate::strip_cache::StripCacheEntry::NoStripNeeded
            }
            Err(e) => {
                log::warn!(
                    "lifecycle(strip,speculative): rewriter error for {name}@{latest}: {e} — leaving packument untouched (lazy path will apply --lifecycle-strip-on-failure)",
                );
                return rewritten;
            }
        };
        strip_cache.insert(key, entry);
    }
    crate::rewrite_npm::apply_strip_cache_to_packument(obj, &strip_cache);
    serde_json::to_vec(&doc).unwrap_or(rewritten)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RewriteTarget {
    CratesSparse,
    NpmPackument,
    PypiJsonApi,
    /// Simple index (`/simple/<pkg>/`) — PEP 691 JSON *or* PEP 503
    /// HTML, decided at response time by Content-Type. The String is
    /// the un-normalized package name from the URL path; the HTML
    /// path hands it to [`PypiSimpleClient`] for the out-of-band
    /// publish-time lookup.
    PypiSimpleIndex(String),
    NugetRegistration,
    /// Flat-container index (`/v3-flatcontainer/<id>/index.json`).
    /// The String is the lower-cased package id, captured here so the
    /// handler can feed it to the out-of-band registration fetcher
    /// without re-parsing the path.
    NugetFlatContainerIndex(String),
}

/// Match the in-flight `(host, path)` to a rewriter. Returning `None`
/// means "pass the response through unchanged".
///
/// For npm we only rewrite the bare packument endpoint `/<pkg>` or
/// `/@scope/<pkg>`. Per-version manifests (`/<pkg>/<version>`) and
/// tarballs (`/<pkg>/-/<tgz>`) are not packuments and would be
/// corrupted by packument-shaped filtering.
fn classify_response(
    host: Option<&str>,
    path: Option<&str>,
    registries: &RegistryHosts,
) -> Option<RewriteTarget> {
    let host = host?;
    let path = path?;
    if host_in(&registries.crates_sparse, host) {
        return Some(RewriteTarget::CratesSparse);
    }
    if host_in(&registries.npm, host) && is_npm_packument_path(path) {
        return Some(RewriteTarget::NpmPackument);
    }
    if host_in(&registries.pypi_index, host) {
        if is_pypi_json_api_path(path) {
            return Some(RewriteTarget::PypiJsonApi);
        }
        if let Some(pkg) = parse_pypi_simple_pkg(path) {
            // We can't distinguish HTML vs JSON by path alone — the
            // client's Accept header decides, and the upstream
            // response's Content-Type confirms. The handler inspects
            // Content-Type at rewrite time and dispatches HTML vs
            // JSON vs pass-through accordingly.
            return Some(RewriteTarget::PypiSimpleIndex(pkg));
        }
    }
    if host_in(&registries.nuget, host) {
        if is_nuget_registration_path(path) {
            return Some(RewriteTarget::NugetRegistration);
        }
        if let Some(id) = parse_nuget_flatcontainer_index_path(path) {
            return Some(RewriteTarget::NugetFlatContainerIndex(id));
        }
    }
    None
}

fn host_in(set: &[String], host: &str) -> bool {
    set.iter().any(|h| host.eq_ignore_ascii_case(h))
}

/// NuGet flat-container index: `/v3-flatcontainer/<id>/index.json`.
/// The body is a `{"versions":[…]}` with no timestamps; we look them
/// up out-of-band from the registration endpoint. Returns the lower-
/// cased package id on match, `None` otherwise.
fn parse_nuget_flatcontainer_index_path(path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix("/v3-flatcontainer/")?;
    // Expect exactly `<id>/index.json`.
    let (id, tail) = rest.split_once('/')?;
    if id.is_empty() || tail != "index.json" {
        return None;
    }
    Some(id.to_ascii_lowercase())
}

/// NuGet registration endpoints:
/// - `/v3/registration<X>*/<id>/index.json` (top-level index)
/// - `/v3/registration<X>*/<id>/page/<lower>/<upper>.json` (paged)
///
/// `<X>*` is one of the many versioned URL bases NuGet publishes
/// (`registration5-semver1`, `registration5-gz-semver2`, …). We match
/// any prefix starting with `registration` so new endpoints added by
/// NuGet don't require a code change.
fn is_nuget_registration_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let rest = match path.strip_prefix("/v3/") {
        Some(r) => r,
        None => return false,
    };
    let mut parts = rest.splitn(2, '/');
    let base = parts.next().unwrap_or("");
    let tail = parts.next().unwrap_or("");
    if !base.starts_with("registration") {
        return false;
    }
    // index.json or page/<lower>/<upper>.json anywhere in the tail.
    tail.ends_with("/index.json") || (tail.contains("/page/") && tail.ends_with(".json"))
}

/// `GET /pypi/<pkg>/json` — the Warehouse legacy JSON API.
fn is_pypi_json_api_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    // Accept both `/pypi/<pkg>/json` and `/pypi/<pkg>/<version>/json`.
    path.starts_with("/pypi/") && path.trim_end_matches('/').ends_with("/json")
}

/// `GET /simple/<pkg>/` — PEP 503 simple index (HTML) or PEP 691 JSON.
/// Returns the raw `<pkg>` segment from the path so the handler can
/// pass it to the out-of-band publish-time lookup client.
fn parse_pypi_simple_pkg(path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix("/simple/")?;
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest.to_string())
}

fn is_npm_packument_path(path: &str) -> bool {
    // Strip query string and trim trailing slash.
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');
    let trimmed = match path.strip_prefix('/') {
        Some(p) => p,
        None => return false,
    };
    if trimmed.is_empty() {
        return false;
    }
    // Scoped packages: "/@scope/name" — exactly one slash after the
    // leading "@". Unscoped packages: "/name" — zero slashes.
    if let Some(rest) = trimmed.strip_prefix('@') {
        // "scope/name" — exactly one remaining '/', no further path parts
        let mut parts = rest.splitn(3, '/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        let extra = parts.next();
        !scope.is_empty() && !name.is_empty() && extra.is_none()
    } else {
        // Unscoped: must not contain any '/'
        !trimmed.contains('/')
    }
}

fn deny_response(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-sakimori-deny", "minimum-release-age")
        .body(Body::from(format!("{reason}\n")))
        .expect("static response builder")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_execution_mode_recognises_one_shot_runners() {
        for ua in [
            "npx/1.0",
            "node npx mode",
            "uvx/0.3",
            "pipx/1.2",
            "cargo-install 0.1",
            "pnpm/dlx 9",
            "yarn dlx",
        ] {
            assert_eq!(
                classify_execution_mode(ua),
                ExecutionMode::Ephemeral,
                "{ua} should be ephemeral"
            );
        }
    }

    #[test]
    fn classify_execution_mode_recognises_persistent_managers() {
        for ua in [
            "npm/10.0.0 node/20.0.0",
            "pnpm/9.0.0",
            "yarn/1.22.0",
            "cargo 1.80.0 (1.80.0)",
            "cargo/1.80",
            "pip/24.0",
            "poetry/1.8",
            "uv/0.4",
            "NuGet/6.10.0",
            "NuGet xplat command line/6.10",
            "dotnet/8.0",
        ] {
            assert_eq!(
                classify_execution_mode(ua),
                ExecutionMode::Persistent,
                "{ua} should be persistent"
            );
        }
    }

    #[test]
    fn classify_execution_mode_defaults_unknown_for_strange_ua() {
        assert_eq!(classify_execution_mode(""), ExecutionMode::Unknown);
        assert_eq!(
            classify_execution_mode("Mozilla/5.0 just a browser"),
            ExecutionMode::Unknown
        );
    }

    #[test]
    fn should_intercept_matches_known_hosts_case_insensitively() {
        let ps = default_parsers();
        for host in [
            "crates.io",
            "CRATES.IO",
            "index.crates.io",
            "registry.npmjs.org",
            "files.pythonhosted.org",
            "pypi.org",
            "api.nuget.org",
        ] {
            assert!(should_intercept(host, &ps), "should intercept {host}");
        }
        for host in ["evil.example.com", "www.nuget.org"] {
            assert!(!should_intercept(host, &ps), "should NOT intercept {host}");
        }
    }

    #[test]
    fn npm_packument_path_matches_unscoped_and_scoped_names_only() {
        // Packument endpoints.
        assert!(is_npm_packument_path("/lodash"));
        assert!(is_npm_packument_path("/lodash/"));
        assert!(is_npm_packument_path("/@types/node"));
        assert!(is_npm_packument_path("/@types/node/"));

        // Per-version manifests — NOT packuments.
        assert!(!is_npm_packument_path("/lodash/4.17.21"));
        assert!(!is_npm_packument_path("/@types/node/20.0.0"));

        // Tarballs — NOT packuments.
        assert!(!is_npm_packument_path("/lodash/-/lodash-4.17.21.tgz"));
        assert!(!is_npm_packument_path("/@types/node/-/node-20.0.0.tgz"));

        // Malformed.
        assert!(!is_npm_packument_path(""));
        assert!(!is_npm_packument_path("/"));
        assert!(!is_npm_packument_path("/@scope"));
    }

    #[test]
    fn pypi_json_api_path_matches_warehouse_shape() {
        assert!(is_pypi_json_api_path("/pypi/requests/json"));
        assert!(is_pypi_json_api_path("/pypi/requests/json/"));
        assert!(is_pypi_json_api_path("/pypi/requests/2.32.4/json"));
        assert!(!is_pypi_json_api_path("/simple/requests/"));
        assert!(!is_pypi_json_api_path("/pypi/requests/"));
        assert!(!is_pypi_json_api_path("/"));
    }

    #[test]
    fn pypi_simple_path_matches_index_shape() {
        assert_eq!(
            parse_pypi_simple_pkg("/simple/requests/").as_deref(),
            Some("requests")
        );
        assert_eq!(
            parse_pypi_simple_pkg("/simple/requests").as_deref(),
            Some("requests")
        );
        assert_eq!(
            parse_pypi_simple_pkg("/simple/Flask-SQLAlchemy/").as_deref(),
            Some("Flask-SQLAlchemy"),
            "raw casing preserved — client normalizes on lookup"
        );
        assert_eq!(parse_pypi_simple_pkg("/simple/requests/2.32.4/"), None);
        assert_eq!(parse_pypi_simple_pkg("/simple/"), None);
        assert_eq!(parse_pypi_simple_pkg("/pypi/requests/json"), None);
    }

    #[test]
    fn nuget_registration_path_matches_index_and_page_shapes() {
        assert!(is_nuget_registration_path(
            "/v3/registration5-semver1/newtonsoft.json/index.json"
        ));
        assert!(is_nuget_registration_path(
            "/v3/registration5-gz-semver2/serilog/index.json"
        ));
        assert!(is_nuget_registration_path(
            "/v3/registration5-semver1/pkg/page/1.0.0/9.9.9.json"
        ));
        // Not registration.
        assert!(!is_nuget_registration_path(
            "/v3-flatcontainer/pkg/index.json"
        ));
        assert!(!is_nuget_registration_path("/v3/search-query"));
        assert!(!is_nuget_registration_path("/"));
    }

    #[test]
    fn parse_nuget_flatcontainer_index_path_is_lenient_on_casing() {
        assert_eq!(
            parse_nuget_flatcontainer_index_path("/v3-flatcontainer/Newtonsoft.Json/index.json"),
            Some("newtonsoft.json".into())
        );
        assert_eq!(
            parse_nuget_flatcontainer_index_path("/v3-flatcontainer/serilog/index.json"),
            Some("serilog".into())
        );
        // Not an index.json — `.nupkg` or a version directory.
        assert_eq!(
            parse_nuget_flatcontainer_index_path(
                "/v3-flatcontainer/serilog/3.0.0/serilog.3.0.0.nupkg"
            ),
            None
        );
        // Registration endpoint — different path family.
        assert_eq!(
            parse_nuget_flatcontainer_index_path("/v3/registration5-semver1/serilog/index.json"),
            None
        );
        // Empty id.
        assert_eq!(
            parse_nuget_flatcontainer_index_path("/v3-flatcontainer//index.json"),
            None
        );
        // Query string tolerated.
        assert_eq!(
            parse_nuget_flatcontainer_index_path("/v3-flatcontainer/pkg/index.json?ts=1"),
            Some("pkg".into())
        );
    }

    #[test]
    fn classify_response_routes_to_correct_rewriter() {
        let r = RegistryHosts::default();
        assert_eq!(
            classify_response(Some("index.crates.io"), Some("/anything"), &r),
            Some(RewriteTarget::CratesSparse)
        );
        assert_eq!(
            classify_response(Some("registry.npmjs.org"), Some("/lodash"), &r),
            Some(RewriteTarget::NpmPackument)
        );
        // tarball path — npm but not a packument
        assert_eq!(
            classify_response(
                Some("registry.npmjs.org"),
                Some("/lodash/-/lodash-4.17.21.tgz"),
                &r,
            ),
            None
        );
        // PyPI endpoints
        assert_eq!(
            classify_response(Some("pypi.org"), Some("/pypi/requests/json"), &r),
            Some(RewriteTarget::PypiJsonApi)
        );
        assert_eq!(
            classify_response(Some("pypi.org"), Some("/simple/requests/"), &r),
            Some(RewriteTarget::PypiSimpleIndex("requests".into()))
        );
        assert_eq!(classify_response(Some("pypi.org"), Some("/"), &r), None);
        // NuGet registration.
        assert_eq!(
            classify_response(
                Some("api.nuget.org"),
                Some("/v3/registration5-semver1/newtonsoft.json/index.json"),
                &r,
            ),
            Some(RewriteTarget::NugetRegistration)
        );
        // NuGet flat-container index: handled via registration lookup.
        assert_eq!(
            classify_response(
                Some("api.nuget.org"),
                Some("/v3-flatcontainer/newtonsoft.json/index.json"),
                &r,
            ),
            Some(RewriteTarget::NugetFlatContainerIndex(
                "newtonsoft.json".into()
            ))
        );
        // Pinned `.nupkg` fetches under flat-container still fall
        // through to the pin decider — not rewritten here.
        assert_eq!(
            classify_response(
                Some("api.nuget.org"),
                Some("/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"),
                &r,
            ),
            None
        );
        // unrecognised host
        assert_eq!(
            classify_response(Some("evil.example.com"), Some("/foo"), &r),
            None
        );
        assert_eq!(classify_response(None, Some("/foo"), &r), None);
    }

    #[test]
    fn classify_response_honours_custom_npm_host() {
        let mut r = RegistryHosts::default();
        r.npm.push("npm.flatt.tech".into());
        assert_eq!(
            classify_response(Some("npm.flatt.tech"), Some("/lodash"), &r),
            Some(RewriteTarget::NpmPackument)
        );
        // Original canonical host still works.
        assert_eq!(
            classify_response(Some("registry.npmjs.org"), Some("/lodash"), &r),
            Some(RewriteTarget::NpmPackument)
        );
    }

    #[test]
    fn classify_response_honours_custom_pypi_index_host() {
        let mut r = RegistryHosts::default();
        r.pypi_index.push("pypi.flatt.tech".into());
        assert_eq!(
            classify_response(Some("pypi.flatt.tech"), Some("/pypi/requests/json"), &r),
            Some(RewriteTarget::PypiJsonApi)
        );
        assert_eq!(
            classify_response(Some("pypi.flatt.tech"), Some("/simple/requests/"), &r),
            Some(RewriteTarget::PypiSimpleIndex("requests".into()))
        );
    }

    #[test]
    fn classify_response_honours_custom_nuget_host() {
        let mut r = RegistryHosts::default();
        r.nuget.push("nuget.flatt.tech".into());
        assert_eq!(
            classify_response(
                Some("nuget.flatt.tech"),
                Some("/v3/registration5-semver1/newtonsoft.json/index.json"),
                &r,
            ),
            Some(RewriteTarget::NugetRegistration)
        );
        assert_eq!(
            classify_response(
                Some("nuget.flatt.tech"),
                Some("/v3-flatcontainer/newtonsoft.json/index.json"),
                &r,
            ),
            Some(RewriteTarget::NugetFlatContainerIndex(
                "newtonsoft.json".into()
            ))
        );
    }

    #[test]
    fn classify_response_honours_custom_crates_sparse_host() {
        let mut r = RegistryHosts::default();
        r.crates_sparse.push("crates.flatt.tech".into());
        assert_eq!(
            classify_response(Some("crates.flatt.tech"), Some("/1/s/serde"), &r),
            Some(RewriteTarget::CratesSparse)
        );
    }

    #[test]
    fn classify_response_with_empty_ecosystem_yields_none() {
        // Disabling an ecosystem (empty host list) must also prevent
        // its rewriter from firing on the canonical host.
        let r = RegistryHosts {
            npm: vec![],
            ..RegistryHosts::default()
        };
        assert_eq!(
            classify_response(Some("registry.npmjs.org"), Some("/lodash"), &r),
            None
        );
    }

    #[test]
    fn should_intercept_picks_up_custom_hosts() {
        let mut h = RegistryHosts::default();
        h.npm.push("npm.flatt.tech".into());
        h.pypi_index.push("pypi.flatt.tech".into());
        h.nuget.push("nuget.flatt.tech".into());
        let ps = parsers_from_hosts(&h);
        for host in [
            "npm.flatt.tech",
            "NPM.FLATT.TECH",
            "pypi.flatt.tech",
            "nuget.flatt.tech",
        ] {
            assert!(should_intercept(host, &ps), "should intercept {host}");
        }
        for host in ["evil.example", "registry.npmjs.com"] {
            assert!(!should_intercept(host, &ps), "should NOT intercept {host}");
        }
    }

    #[test]
    fn deny_response_has_expected_shape() {
        let r = deny_response("nope");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            r.headers()
                .get("x-sakimori-deny")
                .and_then(|v| v.to_str().ok()),
            Some("minimum-release-age")
        );
    }

    fn matcher(pats: &[&str]) -> crate::host_allow::HostMatcher {
        crate::host_allow::HostMatcher::from_patterns(pats.iter().copied()).unwrap()
    }

    #[test]
    fn egress_deny_reason_passes_when_matcher_empty() {
        let m = crate::host_allow::HostMatcher::default();
        let mut h = http::HeaderMap::new();
        h.insert(http::header::HOST, "anywhere.example".parse().unwrap());
        let r = egress_deny_reason(&m, &http::Method::GET, &"/".parse().unwrap(), &h);
        assert!(r.is_none(), "empty matcher = feature off, must allow");
    }

    #[test]
    fn egress_deny_reason_uses_uri_authority_for_connect() {
        // CONNECT requests put the target in the URI's authority,
        // not in the Host header. Filtering on Host would let
        // every CONNECT through.
        let m = matcher(&["api.github.com"]);
        let h = http::HeaderMap::new();
        // Allowed CONNECT.
        let allowed = egress_deny_reason(
            &m,
            &http::Method::CONNECT,
            &"api.github.com:443".parse().unwrap(),
            &h,
        );
        assert!(allowed.is_none());
        // Denied CONNECT.
        let denied = egress_deny_reason(
            &m,
            &http::Method::CONNECT,
            &"evil.example:443".parse().unwrap(),
            &h,
        );
        let reason = denied.expect("expected deny");
        assert!(reason.contains("evil.example:443"), "{reason}");
    }

    #[test]
    fn egress_deny_reason_uses_host_header_for_plain_http() {
        let m = matcher(&["api.github.com"]);
        let mut h = http::HeaderMap::new();
        h.insert(http::header::HOST, "evil.example".parse().unwrap());
        let denied = egress_deny_reason(&m, &http::Method::GET, &"/".parse().unwrap(), &h);
        assert!(denied.is_some());

        h.insert(http::header::HOST, "api.github.com".parse().unwrap());
        let allowed = egress_deny_reason(&m, &http::Method::GET, &"/".parse().unwrap(), &h);
        assert!(allowed.is_none());
    }

    #[test]
    fn egress_deny_reason_treats_missing_host_as_deny() {
        // Missing/blank Host with a non-empty allow-list must NOT
        // silently slip through. Empty target falls through to
        // `matcher.allows("")` which is false → deny.
        let m = matcher(&["api.github.com"]);
        let h = http::HeaderMap::new();
        let denied = egress_deny_reason(&m, &http::Method::GET, &"/".parse().unwrap(), &h);
        assert!(
            denied.is_some(),
            "missing Host with allow-list active must deny"
        );
    }

    #[test]
    fn egress_deny_reason_honours_wildcard_subdomain() {
        let m = matcher(&["*.githubusercontent.com"]);
        let allowed = egress_deny_reason(
            &m,
            &http::Method::CONNECT,
            &"avatars.githubusercontent.com:443".parse().unwrap(),
            &http::HeaderMap::new(),
        );
        assert!(allowed.is_none());
    }
}

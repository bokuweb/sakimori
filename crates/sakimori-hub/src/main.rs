//! `sakimori-hub` — bind a TCP listener and serve the inventory API.
//!
//! See [`sakimori_hub`] for the protocol shape. Defaults are
//! deliberately conservative: bind to localhost (`127.0.0.1:8787`)
//! and store the SQLite file in the user's home, so a fresh
//! `sakimori-hub` run on a workstation never accidentally exposes
//! data on a LAN interface.
//!
//! ## Security
//!
//! Three independent credentials are accepted on write endpoints:
//!
//! 1. **GitHub OAuth session cookie** — minted by
//!    `/auth/github/login` → `/auth/github/callback` when
//!    `--github-client-id` + `--github-client-secret` +
//!    `--external-base-url` + `--session-secret` +
//!    `--allowed-github-logins` are all set.
//! 2. **Personal API token** — minted by a logged-in user via
//!    `POST /api/tokens`, sent as `Authorization: Bearer shp_…`.
//!    Allowlist-gated on every request so offboarding is
//!    immediate.
//! 3. **Actions OIDC token** — workflows POST their `id-token:
//!    write` JWT to `/auth/actions/exchange` and receive a
//!    short-lived `sha_…` bearer token. Enabled by
//!    `--allowed-actions-repositories` + an OIDC audience
//!    (defaults to `--external-base-url`).
//! 4. **Legacy shared bearer** (`--ingest-token` /
//!    `SAKIMORI_HUB_INGEST_TOKEN`) — CI bootstrap before any
//!    user logs in to mint a personal token.
//!
//! Read endpoints default to ALSO requiring the bearer/session
//! (secure-by-default for a public Cloudflare Containers
//! deploy); `--public-reads` opts out when an upstream auth
//! proxy is in front. `/healthz` is always open for liveness
//! probes.
//!
//! To make accidental exposure hard, binding to anything other
//! than the loopback interface is refused unless `--allow-remote`
//! is set. `--allow-public` is additionally required for the
//! unrestricted `0.0.0.0` / `::` shapes. Non-loopback binds
//! also require AT LEAST ONE of the four auth paths above —
//! otherwise the hub would put a wide-open write API on the
//! network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use sakimori_hub::server::{AppState, ServerConfig, router};
use sakimori_hub::store::Store;

#[derive(Parser, Debug)]
#[command(
    name = "sakimori-hub",
    about = "Self-hostable inventory + advisory-JOIN companion for sakimori-proxy",
    version
)]
struct Cli {
    /// Address to bind. Defaults to loopback — change explicitly to
    /// expose the service on a LAN/VPN interface, and pair with
    /// `--allow-remote` to acknowledge there is no built-in authn.
    #[arg(long, default_value = "127.0.0.1:8787", env = "SAKIMORI_HUB_BIND")]
    bind: SocketAddr,
    /// Where to persist the SQLite inventory. Use `:memory:` for a
    /// throwaway test instance.
    #[arg(long, env = "SAKIMORI_HUB_DB")]
    db: Option<PathBuf>,
    /// Maximum allowed body size for any request, in bytes.
    /// Defaults to 1 MiB.
    #[arg(long, default_value_t = 1024 * 1024)]
    body_limit_bytes: usize,
    /// Maximum events accepted in a single `/ingest` batch.
    #[arg(long, default_value_t = 1000)]
    max_batch: usize,
    /// Acknowledge that binding to a non-loopback interface exposes
    /// the unauthenticated API to the LAN/VPN. Without this flag,
    /// non-loopback `--bind` values are refused.
    #[arg(long)]
    allow_remote: bool,
    /// Acknowledge that binding to the unrestricted `0.0.0.0` /
    /// `::` exposes the API to every interface. Requires
    /// `--allow-remote`.
    #[arg(long)]
    allow_public: bool,
    /// Allow registering webhook targets whose URL host is a
    /// loopback / private / link-local address. Off by default to
    /// block the common SSRF pivot. Flip on for localhost test
    /// receivers.
    #[arg(long)]
    allow_private_webhooks: bool,
    /// Shared bearer token required on every endpoint except
    /// `/healthz`. Clients send it as
    /// `Authorization: Bearer <token>`. Mandatory when binding
    /// non-loopback in production — without it the hub would
    /// have no authentication between the bind address and the
    /// public internet.
    ///
    /// Writes (`POST /ingest`, `POST /advisories`, `POST /scan`,
    /// `POST /dispatch-targets`, `DELETE /dispatch-targets/:id`,
    /// `POST /dispatch/run`) are ALWAYS gated when a token is
    /// set. Reads (`GET /installs` / `/findings` / `/advisories`
    /// / `/dispatch-targets` / `/`) are gated by default too;
    /// opt out with `--public-reads` when an upstream auth proxy
    /// covers them.
    #[arg(long, env = "SAKIMORI_HUB_INGEST_TOKEN")]
    ingest_token: Option<String>,
    /// Acknowledge that an *upstream* auth proxy (Cloudflare
    /// Access, oauth2-proxy, mTLS, etc.) is handling
    /// authentication for the read endpoints, and leave them open
    /// at the hub layer. Without this flag, reads also require
    /// the bearer token when one is configured.
    #[arg(long, env = "SAKIMORI_HUB_PUBLIC_READS")]
    public_reads: bool,
    /// GitHub OAuth App client_id. Required for browser login;
    /// pairs with `--github-client-secret`. Enables
    /// `/auth/github/login` and `/auth/github/callback`.
    #[arg(long, env = "SAKIMORI_HUB_GITHUB_CLIENT_ID")]
    github_client_id: Option<String>,
    /// GitHub OAuth App client_secret (env-only — never accept
    /// secrets on the command line where they'd land in shell
    /// history and `ps aux`).
    #[arg(long, env = "SAKIMORI_HUB_GITHUB_CLIENT_SECRET", hide = true)]
    github_client_secret: Option<String>,
    /// Public URL the hub is reachable at. Used to build the
    /// OAuth `redirect_uri` (must match the value registered on
    /// the GitHub OAuth App). e.g. `https://hub.example.com`.
    #[arg(long, env = "SAKIMORI_HUB_EXTERNAL_BASE_URL")]
    external_base_url: Option<String>,
    /// Server secret (32+ bytes) used to HMAC-sign session
    /// cookies. Generate with `openssl rand -base64 48`. Rotate
    /// to invalidate every live session instantly.
    #[arg(long, env = "SAKIMORI_HUB_SESSION_SECRET", hide = true)]
    session_secret: Option<String>,
    /// Drop the `Secure` flag from `Set-Cookie`. Useful for
    /// local loopback testing over plain HTTP; **NEVER** flip on
    /// in production — a man-in-the-middle on an http endpoint
    /// can steal the session cookie.
    #[arg(long)]
    insecure_cookies: bool,
    /// Comma-separated GitHub logins permitted to sign in via
    /// OAuth. Required when `--github-client-id` is set —
    /// otherwise *any* GitHub account could log in and operate
    /// the hub. Case-insensitive. Example:
    /// `--allowed-github-logins ada,linus`.
    #[arg(
        long,
        env = "SAKIMORI_HUB_ALLOWED_GITHUB_LOGINS",
        value_delimiter = ','
    )]
    allowed_github_logins: Vec<String>,
    /// Comma-separated repository patterns permitted to call
    /// `POST /auth/actions/exchange`. Patterns are `org/repo`
    /// (exact) or `org/*` (org-wide). Enables Actions OIDC
    /// exchange — leave empty to disable the endpoint.
    #[arg(
        long,
        env = "SAKIMORI_HUB_ALLOWED_ACTIONS_REPOSITORIES",
        value_delimiter = ','
    )]
    allowed_actions_repositories: Vec<String>,
    /// Required `aud` claim on Actions OIDC JWTs. Workflows
    /// must request the token with `?audience=<value>` matching
    /// this. Defaults to `--external-base-url` when unset.
    #[arg(long, env = "SAKIMORI_HUB_ACTIONS_OIDC_AUDIENCE")]
    actions_oidc_audience: Option<String>,
    /// Max lifetime of `sha_` tokens minted by the exchange
    /// endpoint. Capped against the inbound JWT's `exp`.
    #[arg(long, default_value_t = 15 * 60)]
    actions_token_ttl_secs: i64,
    /// Background dispatcher cadence in seconds. The hub runs a
    /// dispatch pass every `N` seconds (sharing the same mutex
    /// as `POST /dispatch/run`, so the two paths can't race).
    /// Set to `0` to disable the loop and require
    /// operator/cron-triggered runs.
    #[arg(long, default_value_t = 60)]
    dispatch_interval_secs: u64,
    /// Per-pass batch size for the background dispatcher.
    #[arg(long, default_value_t = 100)]
    dispatch_batch: u32,
    /// Attempt cap for the background dispatcher. A `(finding,
    /// target)` pair stops being retried after this many attempts
    /// to keep a permanently-broken target from filling the
    /// attempts table.
    #[arg(long, default_value_t = sakimori_hub::dispatch::DEFAULT_ATTEMPT_CAP)]
    dispatch_attempt_cap: i64,
}

fn default_db_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h).join(".sakimori").join("hub.sqlite"),
        None => PathBuf::from("hub.sqlite"),
    }
}

fn check_bind_safety(bind: &SocketAddr, allow_remote: bool, allow_public: bool) -> Result<()> {
    let ip = bind.ip();
    if is_unspecified(&ip) {
        if !(allow_remote && allow_public) {
            anyhow::bail!(
                "refusing to bind to {ip} without both --allow-remote and --allow-public; \
                 the bearer-token gate alone is not enough — the operator must \
                 explicitly opt into exposing every interface"
            );
        }
        return Ok(());
    }
    if !is_loopback(&ip) && !allow_remote {
        anyhow::bail!(
            "refusing to bind to non-loopback address {ip} without --allow-remote; \
             non-loopback also requires --ingest-token (the bearer-token gate is \
             the only auth between this address and the public internet)"
        );
    }
    Ok(())
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == &Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6 == &Ipv6Addr::UNSPECIFIED,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    check_bind_safety(&cli.bind, cli.allow_remote, cli.allow_public)?;
    let db = cli.db.unwrap_or_else(default_db_path);
    let store = if db.to_string_lossy() == ":memory:" {
        Store::open_in_memory()
    } else {
        Store::open(&db)
    }
    .with_context(|| format!("opening store at {}", db.display()))?;
    let non_loopback = !cli.bind.ip().is_loopback();
    if let Some(t) = &cli.ingest_token {
        if t.len() < 16 {
            anyhow::bail!("--ingest-token must be at least 16 chars");
        }
        // `shp_` is reserved for personal API tokens. A legacy
        // ingest token using that prefix would be misrouted to
        // the personal-token DB lookup, fail there, and never
        // get a chance to match the constant-time compare. Reject
        // at config time so the failure is loud, not silent.
        for reserved in [
            sakimori_hub::API_TOKEN_PREFIX,
            sakimori_hub::ACTIONS_TOKEN_PREFIX,
        ] {
            if t.starts_with(reserved) {
                anyhow::bail!(
                    "--ingest-token must not start with `{}` (that prefix is reserved \
                     for sakimori-issued tokens — personal via POST /api/tokens or \
                     Actions via POST /auth/actions/exchange)",
                    reserved,
                );
            }
        }
    }
    // Validate the OAuth flag set as a group: either all three
    // are present (login enabled) or none are (login disabled).
    // Partial config is the worst kind — looks right, silently
    // 404s on /auth/github/login.
    let oauth_fields = [
        cli.github_client_id.is_some(),
        cli.github_client_secret.is_some(),
        cli.external_base_url.is_some(),
    ];
    let oauth_enabled = match oauth_fields.iter().filter(|b| **b).count() {
        0 => false,
        3 => {
            if cli.session_secret.is_none() {
                anyhow::bail!(
                    "GitHub OAuth flags set but --session-secret / \
                     SAKIMORI_HUB_SESSION_SECRET is missing; sessions can't be signed"
                );
            }
            if cli.allowed_github_logins.is_empty() {
                anyhow::bail!(
                    "GitHub OAuth enabled but --allowed-github-logins is empty; \
                     anyone with a GitHub account would be able to sign in. \
                     Set SAKIMORI_HUB_ALLOWED_GITHUB_LOGINS=ada,linus,..."
                );
            }
            true
        }
        _ => anyhow::bail!(
            "GitHub OAuth requires all of --github-client-id, \
             --github-client-secret, --external-base-url to be set together"
        ),
    };
    let session_secret = cli.session_secret.as_ref().map(|s| s.as_bytes().to_vec());
    if let Some(s) = &session_secret
        && s.len() < 32
    {
        anyhow::bail!("--session-secret must be at least 32 bytes");
    }
    // Auth-layer guard: a non-loopback bind must have SOMETHING
    // gating writes — either the legacy shared-secret bearer
    // token, or the full OAuth/session/allowlist bundle. Without
    // either, every write endpoint would be wide open.
    let actions_enabled = !cli.allowed_actions_repositories.is_empty();
    if non_loopback && cli.ingest_token.is_none() && !oauth_enabled && !actions_enabled {
        anyhow::bail!(
            "refusing to bind {} without an auth path: pass any of: \
             --ingest-token (shared secret), \
             the full --github-client-id / --github-client-secret / \
             --external-base-url / --session-secret / --allowed-github-logins bundle (browser OAuth), \
             or --allowed-actions-repositories with an audience (Actions OIDC).",
            cli.bind
        );
    }
    // Validate Actions OIDC patterns up front so a typo doesn't
    // silently let nothing through.
    for pat in &cli.allowed_actions_repositories {
        if let Err(e) = sakimori_hub::auth::validate_repository_pattern(pat) {
            anyhow::bail!("--allowed-actions-repositories: {e}");
        }
    }
    let actions_oidc_audience = cli
        .actions_oidc_audience
        .clone()
        .or_else(|| cli.external_base_url.clone());
    if !cli.allowed_actions_repositories.is_empty() && actions_oidc_audience.is_none() {
        anyhow::bail!(
            "--allowed-actions-repositories set but neither \
             --actions-oidc-audience nor --external-base-url is configured; \
             can't validate the JWT `aud` claim"
        );
    }
    if cli.actions_token_ttl_secs < 1 {
        anyhow::bail!("--actions-token-ttl-secs must be >= 1");
    }
    let config = ServerConfig {
        body_limit_bytes: cli.body_limit_bytes,
        max_batch: cli.max_batch,
        allow_private_webhooks: cli.allow_private_webhooks,
        ingest_token: cli.ingest_token.clone(),
        public_reads: cli.public_reads,
        session_secret,
        cookie_secure: !cli.insecure_cookies,
        external_base_url: cli.external_base_url.clone(),
        github_client_id: cli.github_client_id.clone(),
        allowed_github_logins: cli
            .allowed_github_logins
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        allowed_actions_repositories: cli.allowed_actions_repositories.clone(),
        actions_oidc_audience: actions_oidc_audience.clone(),
        actions_token_ttl_secs: cli.actions_token_ttl_secs,
        session_ttl_secs: 60 * 60 * 24 * 7,
    };
    let mut state = AppState::new(Arc::new(store), config);
    if oauth_enabled {
        state.oauth = Some(Arc::new(sakimori_hub::auth::GitHubOAuthClient::new(
            cli.github_client_id.clone().unwrap(),
            cli.github_client_secret.clone().unwrap(),
        )));
        log::info!(
            "GitHub OAuth login enabled (client_id={}, redirect={})",
            cli.github_client_id.as_deref().unwrap_or(""),
            cli.external_base_url.as_deref().unwrap_or(""),
        );
    } else {
        log::info!("GitHub OAuth login disabled (--github-client-id not set)");
    }
    if !cli.allowed_actions_repositories.is_empty() {
        state.actions_verifier = Some(Arc::new(sakimori_hub::auth::DefaultActionsVerifier::new(
            actions_oidc_audience.clone().unwrap(),
        )));
        log::info!(
            "Actions OIDC exchange enabled (audience={}, repositories={})",
            actions_oidc_audience.as_deref().unwrap_or(""),
            cli.allowed_actions_repositories.join(","),
        );
    } else {
        log::info!("Actions OIDC exchange disabled (--allowed-actions-repositories empty)");
    }
    let dispatcher = if cli.dispatch_interval_secs > 0 {
        // Clamp footguns: a batch of 0 silently does nothing
        // every tick; a negative attempt cap classifies every
        // pending pair as over-cap and never dispatches. Surface
        // both as errors so a typo in the CLI is loud, not silent.
        if cli.dispatch_batch == 0 {
            anyhow::bail!("--dispatch-batch must be >= 1");
        }
        if cli.dispatch_attempt_cap < 1 {
            anyhow::bail!("--dispatch-attempt-cap must be >= 1");
        }
        log::info!(
            "background dispatcher every {}s (batch={}, attempt_cap={})",
            cli.dispatch_interval_secs,
            cli.dispatch_batch,
            cli.dispatch_attempt_cap,
        );
        Some(sakimori_hub::dispatch::spawn_loop(
            state.store.clone(),
            state.webhook.clone(),
            state.dispatch_lock.clone(),
            std::time::Duration::from_secs(cli.dispatch_interval_secs),
            cli.dispatch_batch,
            cli.dispatch_attempt_cap,
        ))
    } else {
        log::info!("background dispatcher disabled (--dispatch-interval-secs=0)");
        None
    };
    let app = router(state);
    log::info!(
        "sakimori-hub listening on http://{} (db={})",
        cli.bind,
        db.display()
    );
    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    if let Some(d) = dispatcher {
        d.shutdown().await;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_bind_is_always_ok() {
        check_bind_safety(&sa("127.0.0.1:8787"), false, false).unwrap();
        check_bind_safety(&sa("[::1]:8787"), false, false).unwrap();
    }

    #[test]
    fn non_loopback_requires_allow_remote() {
        let r = check_bind_safety(&sa("10.0.0.5:8787"), false, false);
        assert!(r.is_err(), "should require --allow-remote");
        check_bind_safety(&sa("10.0.0.5:8787"), true, false).unwrap();
    }

    #[test]
    fn unspecified_requires_both_flags() {
        assert!(check_bind_safety(&sa("0.0.0.0:8787"), false, false).is_err());
        assert!(check_bind_safety(&sa("0.0.0.0:8787"), true, false).is_err());
        assert!(check_bind_safety(&sa("0.0.0.0:8787"), false, true).is_err());
        check_bind_safety(&sa("0.0.0.0:8787"), true, true).unwrap();
        check_bind_safety(&sa("[::]:8787"), true, true).unwrap();
    }
}

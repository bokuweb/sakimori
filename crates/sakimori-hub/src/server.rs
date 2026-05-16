//! HTTP surface — the actual ingest + read API.
//!
//! Endpoints:
//!
//! - `POST /ingest` — accepts either a single ingest record JSON
//!   object or an array of them. Each record is an
//!   [`sakimori_core::installs::InstallEvent`] plus an optional
//!   explicit `source` override the proxy can set when it knows its
//!   runtime context with more certainty than the hub's heuristics
//!   could infer. The whole batch commits atomically inside one
//!   SQLite transaction.
//! - `GET /installs` — JSON list, filtered by `?ecosystem=&name=&
//!   version=&source=&since=&limit=`.
//! - `GET /healthz` — liveness probe; returns `"ok"` and an integer
//!   `count` of stored events so a simple curl confirms the DB works.
//! - `GET /` — minimal server-rendered HTML inventory view: the
//!   single-page "what's in our supply chain?" answer described in
//!   roadmap item #6.
//!
//! Request body size is capped (default 1 MiB, overridable via
//! [`ServerConfig::body_limit_bytes`]) and ingest batches are capped
//! (default 1000 records, overridable via [`ServerConfig::max_batch`])
//! to keep a single malicious / runaway client from exhausting
//! memory.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{self, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sakimori_core::installs::InstallEvent;

use crate::Source;
use crate::advisories::{OsvAdvisory, Severity};
use crate::dispatch::{
    DEFAULT_ATTEMPT_CAP, DispatchReport, UreqClient, WebhookClient, run_once, validate_target,
};
use crate::store::{
    DeviceCodeStatus, DevicePollOutcome, FindingFilter, IngestRecord, ListFilter, MATCHING_MODE,
    ScanReport, Store, StoredAdvisory, StoredApiToken, StoredEvent, StoredFinding, StoredTarget,
    StoredUser, TargetSpec, UpsertUserSpec, validate_advisory,
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub config: ServerConfig,
    /// The webhook client used by `/dispatch/run`. Pluggable so
    /// tests can swap in a stub; default is [`UreqClient`].
    pub webhook: Arc<dyn WebhookClient>,
    /// Process-wide mutex serializing `/dispatch/run` calls so
    /// two concurrent requests can't both claim the same
    /// `(finding, target)` and double-fire. See
    /// `dispatch::run_once` doc-comment for the contract.
    pub dispatch_lock: Arc<tokio::sync::Mutex<()>>,
    /// GitHub OAuth exchange backend. `None` disables browser
    /// login (and the `/auth/github/*` routes 404). Production
    /// uses [`crate::auth::GitHubOAuthClient`]; tests inject a
    /// stub that returns canned `GitHubUser` values.
    pub oauth: Option<Arc<dyn crate::auth::OAuthExchange>>,
    /// GitHub Actions OIDC verifier. `None` disables the
    /// exchange endpoint. Production uses
    /// [`crate::auth::actions::DefaultVerifier`]; tests inject
    /// a stub.
    pub actions_verifier: Option<Arc<dyn crate::auth::ActionsOidcVerifier>>,
}

impl AppState {
    pub fn new(store: Arc<Store>, config: ServerConfig) -> Self {
        let allow_private = config.allow_private_webhooks;
        Self {
            store,
            config,
            webhook: Arc::new(UreqClient::new(allow_private)),
            dispatch_lock: Arc::new(tokio::sync::Mutex::new(())),
            oauth: None,
            actions_verifier: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Maximum allowed JSON body size for any endpoint, in bytes.
    /// Axum returns 413 on overflow.
    pub body_limit_bytes: usize,
    /// Maximum events accepted in a single `/ingest` batch.
    /// Excess returns 400 with a clear message.
    pub max_batch: usize,
    /// Allow `POST /dispatch-targets` to accept URLs whose host
    /// resolves to a private / loopback / link-local address.
    /// Off by default — blocks the most common SSRF pivot
    /// (`http://169.254.169.254/...`, `http://10.0.0.5/...`).
    /// Operators running a localhost receiver in tests can flip
    /// this on explicitly.
    pub allow_private_webhooks: bool,
    /// Shared secret required on protected endpoints when set.
    /// Clients prove possession with
    /// `Authorization: Bearer <token>`. `None` disables the
    /// check entirely — fine for loopback dev, but mandatory
    /// once the hub is exposed on a non-loopback bind.
    pub ingest_token: Option<String>,
    /// Leave the **read** endpoints (`GET /`, `/installs`,
    /// `/findings`, `/advisories`, `/dispatch-targets`) outside
    /// the bearer-token gate so an upstream auth proxy
    /// (Cloudflare Access, oauth2-proxy, etc.) can authenticate
    /// browsers separately from API clients.
    ///
    /// **Default `false`** — secure by default: when
    /// `ingest_token` is set, every endpoint except `/healthz`
    /// requires the bearer token, so a default `wrangler deploy`
    /// to Cloudflare Containers does NOT leak inventory.
    /// Operators who explicitly want to layer Access in front of
    /// reads opt in with `--public-reads`.
    pub public_reads: bool,
    /// Server-side HMAC key for session cookies (32+ random
    /// bytes). When `None`, browser-login endpoints reject every
    /// request with 500 — the bin sets one before serving.
    pub session_secret: Option<Vec<u8>>,
    /// `Secure;` flag on `Set-Cookie`. `true` for production
    /// (https), `false` only for local loopback testing.
    pub cookie_secure: bool,
    /// External base URL the hub is served at, used to build the
    /// `redirect_uri` for the GitHub OAuth callback. e.g.
    /// `https://hub.example.com`. `None` disables browser login.
    pub external_base_url: Option<String>,
    /// GitHub OAuth App client_id. Required for browser login.
    /// Paired with the OAuth client on `AppState.oauth` which
    /// owns the matching client_secret (kept off `ServerConfig`
    /// so secrets don't accidentally land in debug-printed
    /// config dumps).
    pub github_client_id: Option<String>,
    /// Lower-cased GitHub login allowlist. An empty Vec means
    /// "nobody allowed in" — when OAuth is enabled, `main.rs`
    /// hard-bails if the operator didn't set this, so a public
    /// deploy can't accidentally accept arbitrary GitHub accounts
    /// as operators. (Slice-7 design: until the team/RBAC slice
    /// lands, every authenticated user gets full operator
    /// powers; the allowlist is the only thing standing between a
    /// public OAuth App and an attacker registering a free
    /// GitHub account.)
    pub allowed_github_logins: Vec<String>,
    /// Repository allowlist for the Actions OIDC exchange.
    /// Patterns are either `org/repo` (exact) or `org/*`
    /// (org-wide). Empty Vec disables `/auth/actions/exchange`
    /// entirely (returns 404) rather than accepting anything —
    /// same secure-by-default posture as `allowed_github_logins`.
    pub allowed_actions_repositories: Vec<String>,
    /// Required `aud` claim on incoming GitHub Actions OIDC
    /// JWTs. Workflows pass this via `audience=<value>` when
    /// requesting the token; operators typically use the hub's
    /// external URL. Required when Actions OIDC is enabled.
    pub actions_oidc_audience: Option<String>,
    /// Max lifetime of the minted `sha_` token from
    /// `/auth/actions/exchange`. Capped against the inbound
    /// JWT's own `exp` — whichever is sooner wins. Defaults
    /// to 15 minutes.
    pub actions_token_ttl_secs: i64,
    /// Session lifetime in seconds. Defaults to 7 days.
    pub session_ttl_secs: i64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            body_limit_bytes: 1024 * 1024,
            max_batch: 1000,
            allow_private_webhooks: false,
            ingest_token: None,
            public_reads: false,
            session_secret: None,
            cookie_secure: true,
            external_base_url: None,
            github_client_id: None,
            allowed_github_logins: Vec::new(),
            allowed_actions_repositories: Vec::new(),
            actions_oidc_audience: None,
            actions_token_ttl_secs: 15 * 60,    // 15min
            session_ttl_secs: 60 * 60 * 24 * 7, // 7d
        }
    }
}

pub fn router(state: AppState) -> Router {
    let limit = state.config.body_limit_bytes;
    // Writes are always behind the bearer-token gate (when a
    // token is configured).
    let writes = Router::new()
        .route("/ingest", post(ingest))
        .route("/advisories", post(advisories_import))
        .route("/scan", post(scan))
        .route("/dispatch-targets", post(targets_create))
        .route(
            "/dispatch-targets/{id}",
            axum::routing::delete(targets_delete),
        )
        .route("/dispatch/run", post(dispatch_run));
    // Reads default to gated too (secure-by-default for a public
    // Containers deploy). Operators who put an auth proxy in
    // front of reads opt into the open behaviour with
    // `--public-reads`, which moves these routes out of the
    // bearer-token layer.
    let reads = Router::new()
        .route("/installs", get(list))
        .route("/advisories", get(advisories_list))
        .route("/findings", get(findings_list))
        .route("/dispatch-targets", get(targets_list))
        .route("/", get(index_html));
    let (protected, public_extras) = if state.config.public_reads {
        (writes, reads)
    } else {
        (writes.merge(reads), Router::new())
    };
    let protected = protected.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        require_bearer_token,
    ));
    // `/healthz` is always open — liveness/readiness probes can't
    // carry a bearer token and would otherwise force operators
    // into ugly cf-access shenanigans.
    // Browser auth endpoints. `/auth/github/login` + `callback`
    // run the OAuth dance; `/auth/logout` clears the session;
    // `/auth/me` returns the logged-in user (handy for the
    // browser to discover whether to show a "Log in" link).
    // None of these are gated by the bearer-token middleware —
    // the login endpoints can't be (chicken-and-egg) and
    // `/auth/me` is intentionally non-sensitive (it returns 401
    // when there's no session).
    let auth = Router::new()
        .route("/auth/github/login", get(auth_github_login))
        .route("/auth/github/callback", get(auth_github_callback))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/me", get(auth_me))
        .route("/auth/actions/exchange", post(auth_actions_exchange))
        .route("/auth/device/code", post(auth_device_code))
        .route("/auth/device/token", post(auth_device_token));
    // Personal API tokens — list/mint/revoke. Always gated by a
    // valid session cookie (not the legacy shared-secret bearer:
    // tokens are per-user, so a session that can't be tied to
    // one user has no business minting them). The
    // `require_session_user` middleware is *separate* from
    // `require_bearer_token` because it always demands a session
    // and never accepts the legacy bearer.
    // Nest under `/api` so the token routes' `{id}` placeholder
    // doesn't collide with `/dispatch-targets/{id}` at axum's
    // matchit layer when merging routers with overlapping
    // parameter shapes.
    // POST-based revoke instead of DELETE on a parameterized
    // path. axum 0.7's router has a quirk where merging a router
    // that registers `DELETE /a/{id}` alongside another router
    // that also has `{id}` placeholders (e.g. our existing
    // `/dispatch-targets/{id}`) silently swallows the second one
    // — both routes return 404 at runtime. POST/body keeps the
    // matchit tree single-segment-deep here and side-steps the
    // bug entirely.
    let tokens = Router::new()
        .route("/api/tokens", post(tokens_create).get(tokens_list))
        .route("/api/tokens/revoke", post(tokens_revoke))
        // Device-flow approve UI + action endpoint share the
        // `require_session_user` layer: only a browser-
        // authenticated operator can confirm a device login
        // request, and CSRF is checked via the same Origin/
        // Referer rule as the rest of the session-cookie surface.
        .route("/auth/device", get(auth_device_page))
        .route("/auth/device/approve", post(auth_device_approve))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_session_user,
        ));
    let public = Router::new()
        .route("/healthz", get(healthz))
        .merge(public_extras)
        .merge(auth);
    public
        .merge(tokens)
        .merge(protected)
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

/// Middleware that gates write endpoints with **either** a valid
/// `Authorization: Bearer <token>` matching
/// `ServerConfig.ingest_token` **or** a valid signed session
/// cookie pointing at a live `users` row. Browser users get in
/// via the cookie (plus an Origin/Referer CSRF check); CI /
/// `sakimori-proxy` keeps using bearer.
///
/// The middleware is a no-op only when **both** `ingest_token`
/// and `session_secret` are unset — the loopback-default
/// `main.rs` posture. With only one of them set, the other
/// path is explicitly rejected (e.g. an OAuth-only deploy
/// returns 401 on `Authorization: Bearer ...`, never 200).
async fn require_bearer_token(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, ApiError> {
    let bearer_configured = state.config.ingest_token.is_some();
    let session_configured = state.config.session_secret.is_some();
    // Use the config alone (not the live verifier) as the
    // source of truth for "Actions auth is configured". A caller
    // that sets `allowed_actions_repositories` but forgets to
    // attach `actions_verifier` would otherwise turn the middleware
    // into a no-op and silently open every write — instead, writes
    // stay locked (no sha_ token could have been minted, so they
    // can't pass) and the `/auth/actions/exchange` endpoint 404s
    // for being unwired.
    let actions_configured = !state.config.allowed_actions_repositories.is_empty();
    if !bearer_configured && !session_configured && !actions_configured {
        return Ok(next.run(req).await);
    }
    // Cookie path first. A valid session is sufficient on its own
    // (that's how a browser user POSTs `/dispatch/run` from the
    // inventory page without ever holding the shared secret), but
    // cookie-authenticated requests ALSO need a CSRF origin check:
    // SameSite=Lax does NOT prevent top-level form POSTs from
    // cross-site pages. Bearer-authenticated requests skip the
    // check — an attacker can't set custom headers from cross-site
    // browser contexts.
    if let Some(secret) = state.config.session_secret.as_deref()
        && cookie_session_user(&state, secret, req.headers())
            .await?
            .is_some()
    {
        if !cookie_origin_ok(&state, req.headers()) {
            return Err(ApiError::unauthorized(
                "cookie-authenticated request without matching Origin/Referer",
            ));
        }
        return Ok(next.run(req).await);
    }
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim());
    let Some(presented) = header else {
        return Err(ApiError::unauthorized(
            "missing `Authorization: Bearer <token>` or session cookie",
        ));
    };
    // Personal API tokens are recognisable by the `shp_` prefix
    // — a fast-fail so noise traffic doesn't hit the DB hash
    // lookup. Anything else falls through to the legacy
    // shared-secret comparison.
    if presented.starts_with(crate::store::ACTIONS_TOKEN_PREFIX) {
        // Actions OIDC-exchanged token. No GitHub-login allowlist
        // re-check here: the repository allowlist was already
        // enforced at mint time, and the underlying GitHub
        // identity (the workflow itself) has no
        // `allowed_github_logins` analogue. Operators revoke by
        // either (a) flipping the repository off
        // `allowed_actions_repositories` (no new tokens) or
        // (b) waiting out the short TTL. The latter is why TTLs
        // default to 15 minutes.
        let token_hash = crate::store::hash_actions_token(presented);
        let principal = state
            .store
            .actions_token_principal(token_hash)
            .await
            .map_err(ApiError::internal)?;
        if let Some(p) = principal {
            let store = state.store.clone();
            let tid = p.token_id;
            tokio::spawn(async move {
                if let Err(e) = store.touch_actions_token(tid).await {
                    log::warn!(
                        target: "sakimori_hub::auth",
                        "touch_actions_token({tid}) failed: {e:#}",
                    );
                }
            });
            return Ok(next.run(req).await);
        }
        return Err(ApiError::unauthorized(
            "invalid, revoked, or expired actions token",
        ));
    }
    if presented.starts_with(crate::store::API_TOKEN_PREFIX) {
        let token_hash = crate::store::hash_api_token(presented);
        let row = state
            .store
            .api_token_user(token_hash)
            .await
            .map_err(ApiError::internal)?;
        if let Some((user, token_id)) = row {
            // Re-check the GitHub allowlist on every request, not
            // just at OAuth callback time. Otherwise an offboarded
            // user's long-lived `shp_` tokens (default no expiry)
            // would keep working until each one was individually
            // revoked. With this check, removing the login from
            // `SAKIMORI_HUB_ALLOWED_GITHUB_LOGINS` immediately
            // disables every token they hold.
            if !state.config.allowed_github_logins.is_empty()
                && !state
                    .config
                    .allowed_github_logins
                    .contains(&user.github_login.to_ascii_lowercase())
            {
                return Err(ApiError::unauthorized(
                    "owning github user is no longer on the allowlist",
                ));
            }
            // Best-effort `last_used_at` update — spawn so a slow
            // DB write can't drag out the request path.
            let store = state.store.clone();
            tokio::spawn(async move {
                if let Err(e) = store.touch_api_token(token_id).await {
                    log::warn!(
                        target: "sakimori_hub::auth",
                        "touch_api_token({token_id}) failed: {e:#}",
                    );
                }
            });
            return Ok(next.run(req).await);
        }
        return Err(ApiError::unauthorized("invalid or revoked api token"));
    }
    let Some(expected) = state.config.ingest_token.as_deref() else {
        // Bearer presented but no shared secret configured — this
        // is an OAuth-only deploy. Don't pretend the token might
        // be right.
        return Err(ApiError::unauthorized(
            "bearer auth disabled on this deploy; use a session cookie",
        ));
    };
    use subtle::ConstantTimeEq;
    let ok =
        presented.len() == expected.len() && presented.as_bytes().ct_eq(expected.as_bytes()).into();
    if !ok {
        return Err(ApiError::unauthorized("invalid bearer token"));
    }
    Ok(next.run(req).await)
}

/// Stricter middleware for `/api/tokens` routes — requires a
/// live session cookie + matching CSRF origin. Personal-token
/// auth is deliberately NOT accepted here: a long-lived token
/// shouldn't be able to mint new long-lived tokens (would let a
/// leaked token persist past revoke). The session cookie is the
/// only thing that proves "a human is at the keyboard".
async fn require_session_user(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, ApiError> {
    let secret = state
        .config
        .session_secret
        .as_deref()
        .ok_or_else(|| ApiError::not_found("personal tokens require GitHub OAuth login"))?;
    let user = cookie_session_user(&state, secret, req.headers())
        .await?
        .ok_or_else(|| ApiError::unauthorized("session required"))?;
    // CSRF origin check ONLY for unsafe methods. GETs of e.g.
    // `/auth/device?code=...` are linkable / bookmarkable / typed
    // into a fresh tab, so requiring an Origin/Referer match
    // would 401 the operator before they ever see the confirm
    // form. Reads are non-mutating, so the SameSite=Lax cookie
    // contract is enough.
    if is_unsafe_method(req.method()) && !cookie_origin_ok(&state, req.headers()) {
        return Err(ApiError::unauthorized(
            "cookie-authenticated request without matching Origin/Referer",
        ));
    }
    // Hand the user object down to the handler via request
    // extensions so it doesn't have to re-do the lookup.
    let mut req = req;
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

fn is_unsafe_method(m: &axum::http::Method) -> bool {
    !matches!(
        *m,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

/// CSRF origin check for cookie-authenticated mutating requests.
/// Returns `true` iff `Origin` (preferred) or `Referer` (fallback)
/// matches `external_base_url`. When `external_base_url` is unset
/// we accept everything — the loopback dev posture; production
/// deploys MUST set it (and `main.rs` does, in tandem with the
/// OAuth flag bundle).
fn cookie_origin_ok(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let Some(base) = state.config.external_base_url.as_deref() else {
        return true;
    };
    let base = base.trim_end_matches('/');
    if let Some(origin) = headers
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        return origin.trim_end_matches('/') == base;
    }
    if let Some(referer) = headers
        .get(http::header::REFERER)
        .and_then(|v| v.to_str().ok())
    {
        // A naïve `referer.starts_with(base)` would accept
        // `https://hub.example.com.attacker.tld/x` for
        // `base = https://hub.example.com`. Require either an
        // exact match or a `base/...` prefix so an attacker
        // can't append more characters to the host portion.
        let with_slash = format!("{base}/");
        return referer == base || referer.starts_with(&with_slash);
    }
    // Neither header — refuse. A legitimate browser request
    // always sets at least one; an intentional `curl --cookie ...`
    // would too. Lacking both is the shape of a clickjacked /
    // form-action CSRF attempt.
    false
}

/// Extract the session cookie from request headers, verify the
/// signature, and resolve it to a [`StoredUser`]. Returns
/// `Ok(None)` for "no cookie, bad cookie, expired, or revoked"
/// — every failure mode is indistinguishable to the caller so
/// timing/wording can't differentiate them.
async fn cookie_session_user(
    state: &AppState,
    secret: &[u8],
    headers: &axum::http::HeaderMap,
) -> Result<Option<StoredUser>, ApiError> {
    let Some(cookie_header) = headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return Ok(None);
    };
    let Some(cookie_value) = crate::auth::session::extract_session_cookie(cookie_header) else {
        return Ok(None);
    };
    let Some(parsed) = crate::auth::verify_cookie(secret, cookie_value) else {
        return Ok(None);
    };
    state
        .store
        .session_user(parsed.token_hash)
        .await
        .map_err(ApiError::internal)
}

/// Wire shape of a single ingest record. Flattens the full
/// `InstallEvent` JSON and adds an optional `source` override that
/// the proxy can set when it knows the runtime context for sure.
/// When `source` is omitted the hub falls back to its heuristic
/// classifier — see [`crate::classify::classify`].
#[derive(Debug, Deserialize)]
pub struct IngestItem {
    #[serde(flatten)]
    pub event: InstallEvent,
    pub source: Option<Source>,
}

impl From<IngestItem> for IngestRecord {
    fn from(it: IngestItem) -> Self {
        IngestRecord {
            event: it.event,
            source: it.source,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IngestPayload {
    One(Box<IngestItem>),
    Many(Vec<IngestItem>),
}

#[derive(Serialize)]
struct IngestResp {
    accepted: usize,
}

async fn ingest(
    State(state): State<AppState>,
    Json(payload): Json<IngestPayload>,
) -> Result<Json<IngestResp>, ApiError> {
    let items: Vec<IngestItem> = match payload {
        IngestPayload::One(e) => vec![*e],
        IngestPayload::Many(v) => v,
    };
    if items.len() > state.config.max_batch {
        return Err(ApiError::bad_request(format!(
            "batch size {} exceeds max_batch={}",
            items.len(),
            state.config.max_batch
        )));
    }
    let records: Vec<IngestRecord> = items.into_iter().map(Into::into).collect();
    let accepted = records.len();
    state
        .store
        .insert_many(records)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(IngestResp { accepted }))
}

#[derive(Deserialize)]
struct ListQuery {
    ecosystem: Option<String>,
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    since: Option<String>,
    limit: Option<u32>,
}

#[derive(Serialize)]
struct ListResp {
    events: Vec<StoredEvent>,
}

async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResp>, ApiError> {
    let filter = build_filter(q)?;
    let events = state.store.list(filter).await.map_err(ApiError::internal)?;
    Ok(Json(ListResp { events }))
}

fn build_filter(q: ListQuery) -> Result<ListFilter, ApiError> {
    let source = match q.source.as_deref() {
        Some(s) => Some(Source::parse(s).ok_or_else(|| {
            ApiError::bad_request(format!(
                "invalid `source`: {s}; expected one of actions|desktop|unknown"
            ))
        })?),
        None => None,
    };
    let since = match q.since.as_deref() {
        Some(s) => Some(parse_since(s)?),
        None => None,
    };
    Ok(ListFilter {
        ecosystem: q.ecosystem,
        name: q.name,
        version: q.version,
        source,
        since,
        limit: q.limit,
    })
}

fn parse_since(s: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| ApiError::bad_request(format!("invalid `since` (need RFC3339): {e}")))
}

#[derive(Serialize)]
struct Healthz {
    status: &'static str,
    count: i64,
    schema_version: i32,
    matching_mode: &'static str,
}

async fn healthz(State(state): State<AppState>) -> Result<Json<Healthz>, ApiError> {
    let count = state.store.count().await.map_err(ApiError::internal)?;
    let schema_version = state
        .store
        .schema_version()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(Healthz {
        status: "ok",
        count,
        schema_version,
        matching_mode: MATCHING_MODE,
    }))
}

async fn index_html(State(state): State<AppState>) -> Result<Html<String>, ApiError> {
    let events = state
        .store
        .list(ListFilter {
            limit: Some(200),
            ..Default::default()
        })
        .await
        .map_err(ApiError::internal)?;
    Ok(Html(render_index(&events)))
}

fn render_index(events: &[StoredEvent]) -> String {
    let mut rows = String::new();
    for e in events {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&e.resolved_at.to_rfc3339()),
            html_escape(&e.ecosystem),
            html_escape(&e.name),
            html_escape(&e.version),
            html_escape(e.source.as_str()),
            html_escape(execution_mode_label(e)),
            html_escape(e.project_path.as_deref().unwrap_or("")),
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>sakimori-hub — install inventory</title>\
         <style>\
           body{{font-family:system-ui,sans-serif;margin:1.5rem}}\
           table{{border-collapse:collapse;font-size:.85rem;width:100%}}\
           th,td{{border:1px solid #ccc;padding:.3rem .5rem;text-align:left}}\
           th{{background:#f4f4f4}}\
           caption{{caption-side:top;text-align:left;font-weight:600;padding:.4rem 0}}\
         </style></head><body>\
         <h1>sakimori-hub</h1>\
         <p>Showing the {n} most recent install events. Use \
         <code>GET /installs</code> for filtered JSON.</p>\
         <table><caption>Recent installs</caption>\
         <thead><tr><th>resolved_at</th><th>ecosystem</th><th>name</th>\
         <th>version</th><th>source</th><th>execution</th><th>project_path</th></tr></thead>\
         <tbody>{rows}</tbody></table></body></html>",
        n = events.len(),
        rows = rows,
    )
}

fn execution_mode_label(e: &StoredEvent) -> &'static str {
    use sakimori_core::installs::ExecutionMode::*;
    match e.execution_mode {
        Persistent => "persistent",
        Ephemeral => "ephemeral",
        Unknown => "unknown",
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------- advisories / scan / findings ----------------

#[derive(Serialize)]
struct AdvisoryImportResp {
    created: usize,
    refreshed: usize,
    matching_mode: &'static str,
}

/// Accept the advisory body as a raw `serde_json::Value` so the
/// original JSON value (including fields the typed `OsvAdvisory`
/// view doesn't model) is what we durably store. The shape may
/// be either a single advisory object or an array.
async fn advisories_import(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<AdvisoryImportResp>, ApiError> {
    let raw_items: Vec<serde_json::Value> = match payload {
        serde_json::Value::Array(arr) => arr,
        v => vec![v],
    };
    if raw_items.len() > state.config.max_batch {
        return Err(ApiError::bad_request(format!(
            "batch size {} exceeds max_batch={}",
            raw_items.len(),
            state.config.max_batch
        )));
    }
    let mut typed = Vec::with_capacity(raw_items.len());
    for (idx, raw) in raw_items.into_iter().enumerate() {
        let adv: OsvAdvisory = serde_json::from_value(raw.clone())
            .map_err(|e| ApiError::bad_request(format!("advisory[{idx}]: invalid OSV: {e}")))?;
        validate_advisory(&adv)
            .map_err(|e| ApiError::bad_request(format!("advisory[{idx}]: {e}")))?;
        typed.push((adv, Some(raw)));
    }
    let (created, refreshed) = state
        .store
        .upsert_advisories(typed)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(AdvisoryImportResp {
        created,
        refreshed,
        matching_mode: MATCHING_MODE,
    }))
}

#[derive(Deserialize)]
struct AdvisoryListQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct AdvisoryListResp {
    advisories: Vec<StoredAdvisory>,
}

async fn advisories_list(
    State(state): State<AppState>,
    Query(q): Query<AdvisoryListQuery>,
) -> Result<Json<AdvisoryListResp>, ApiError> {
    let advisories = state
        .store
        .list_advisories(q.limit)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(AdvisoryListResp { advisories }))
}

async fn scan(State(state): State<AppState>) -> Result<Json<ScanReport>, ApiError> {
    let report = state
        .store
        .scan_findings()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(report))
}

#[derive(Deserialize)]
struct FindingListQuery {
    min_severity: Option<String>,
    source: Option<String>,
    limit: Option<u32>,
}

#[derive(Serialize)]
struct FindingListResp {
    findings: Vec<StoredFinding>,
}

async fn findings_list(
    State(state): State<AppState>,
    Query(q): Query<FindingListQuery>,
) -> Result<Json<FindingListResp>, ApiError> {
    let min_severity = match q.min_severity.as_deref() {
        Some(s) => Some(Severity::parse(s).ok_or_else(|| {
            ApiError::bad_request(format!(
                "invalid `min_severity`: {s}; expected critical|high|moderate|low|unknown"
            ))
        })?),
        None => None,
    };
    let source = match q.source.as_deref() {
        Some(s) => Some(Source::parse(s).ok_or_else(|| {
            ApiError::bad_request(format!(
                "invalid `source`: {s}; expected actions|desktop|unknown"
            ))
        })?),
        None => None,
    };
    let findings = state
        .store
        .list_findings(FindingFilter {
            min_severity,
            source,
            limit: q.limit,
        })
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(FindingListResp { findings }))
}

// ---------------- dispatch targets / run ----------------

/// Wire shape for `POST /dispatch-targets`. We accept the secret
/// from the operator (rather than generating one) because the
/// receiver also needs to know it — anything we generate would
/// just have to be displayed back, and round-tripping the secret
/// through our response body is exactly what we want to avoid.
#[derive(Debug, Deserialize)]
pub struct TargetCreateBody {
    pub label: String,
    pub url: String,
    pub secret: String,
    pub min_severity: Severity,
    #[serde(default)]
    pub source_filter: Option<Source>,
}

#[derive(Serialize)]
struct TargetCreateResp {
    id: i64,
    label: String,
}

async fn targets_create(
    State(state): State<AppState>,
    Json(body): Json<TargetCreateBody>,
) -> Result<Json<TargetCreateResp>, ApiError> {
    let spec = TargetSpec {
        label: body.label,
        url: body.url,
        secret: body.secret,
        min_severity: body.min_severity,
        source_filter: body.source_filter,
    };
    validate_target(&spec, state.config.allow_private_webhooks)
        .map_err(|e| ApiError::bad_request(format!("invalid target: {e}")))?;
    let label = spec.label.clone();
    let id = state
        .store
        .register_target(spec)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(TargetCreateResp { id, label }))
}

#[derive(Serialize)]
struct TargetListResp {
    targets: Vec<StoredTarget>,
}

async fn targets_list(State(state): State<AppState>) -> Result<Json<TargetListResp>, ApiError> {
    let targets = state
        .store
        .list_targets()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(TargetListResp { targets }))
}

async fn targets_delete(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<StatusCode, ApiError> {
    let removed = state
        .store
        .delete_target(id)
        .await
        .map_err(ApiError::internal)?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("no target with id {id}")))
    }
}

#[derive(Deserialize)]
struct DispatchRunQuery {
    batch: Option<u32>,
    attempt_cap: Option<i64>,
}

async fn dispatch_run(
    State(state): State<AppState>,
    Query(q): Query<DispatchRunQuery>,
) -> Result<Json<DispatchReport>, ApiError> {
    let batch = q.batch.unwrap_or(100).min(10_000);
    let cap = q.attempt_cap.unwrap_or(DEFAULT_ATTEMPT_CAP).max(1);
    // Hold the lock for the whole pass so two concurrent
    // `POST /dispatch/run` calls can't both pull the same pending
    // rows. The lock is process-local; the deploy model is one
    // hub per team, so process-local is sufficient.
    let _guard = state.dispatch_lock.lock().await;
    let report = run_once(state.store.clone(), state.webhook.clone(), batch, cap)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(report))
}

// ---------------- browser auth (GitHub OAuth) ----------------

const OAUTH_STATE_COOKIE: &str = "sakimori_hub_oauth_state";

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
}

async fn auth_github_login(State(state): State<AppState>) -> Result<Response, ApiError> {
    let oauth = state
        .oauth
        .as_ref()
        .ok_or_else(|| ApiError::not_found("github oauth not configured"))?;
    let _ = oauth; // we only need the existence check at this layer
    let client_id = require_oauth_client_id(&state)?;
    let base = state
        .config
        .external_base_url
        .as_deref()
        .ok_or_else(|| ApiError::internal("external_base_url not configured"))?;
    let secret = state
        .config
        .session_secret
        .as_deref()
        .ok_or_else(|| ApiError::internal("session_secret not configured"))?;
    // CSRF state: random 32 bytes, base64url, dropped on the
    // browser as a short-lived signed cookie. The callback
    // verifies the value GitHub echoes back matches the cookie
    // value bit-for-bit.
    let state_token = crate::auth::session::mint_session_token(secret);
    let redirect_uri = format!("{}/auth/github/callback", base.trim_end_matches('/'));
    let url = crate::auth::github::authorize_url(
        client_id,
        &redirect_uri,
        // The browser-visible part of the cookie value is the
        // signed token; the callback only needs the *cookie* to
        // match, so we send that string as the OAuth `state`.
        &state_token.cookie_value,
        &["read:user"],
    );
    let cookie = state_oauth_set_cookie(&state_token.cookie_value, state.config.cookie_secure)
        .map_err(ApiError::internal)?;
    let mut resp = Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, url)
        .header(http::header::SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .map_err(ApiError::internal)?;
    // Don't cache the redirect — GitHub clamps state to the
    // login attempt that minted it.
    resp.headers_mut().insert(
        http::header::CACHE_CONTROL,
        "no-store".parse().expect("static header value"),
    );
    Ok(resp)
}

async fn auth_github_callback(
    State(state): State<AppState>,
    Query(q): Query<OAuthCallbackQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let oauth = state
        .oauth
        .as_ref()
        .ok_or_else(|| ApiError::not_found("github oauth not configured"))?
        .clone();
    let secret = state
        .config
        .session_secret
        .as_deref()
        .ok_or_else(|| ApiError::internal("session_secret not configured"))?;
    // CSRF check: the `state` query param must equal the value
    // we stashed in OAUTH_STATE_COOKIE on /login. Mismatch ⇒
    // 400 — every flow without the matching cookie is an
    // attacker drive-by.
    let cookie_state = headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| extract_named_cookie(h, OAUTH_STATE_COOKIE))
        .ok_or_else(|| ApiError::bad_request("missing oauth state cookie"))?;
    if cookie_state.len() != q.state.len()
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            cookie_state.as_bytes(),
            q.state.as_bytes(),
        ))
    {
        return Err(ApiError::bad_request("oauth state mismatch"));
    }
    // Also verify the cookie's own HMAC — even though we don't
    // *use* the inner token, validating the signature shuts down
    // an attacker who could otherwise paste a same-length string
    // they made up.
    if crate::auth::verify_cookie(secret, cookie_state).is_none() {
        return Err(ApiError::bad_request("oauth state failed signature check"));
    }
    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let code = q.code.clone();
    let gh_user = tokio::task::spawn_blocking(move || oauth.exchange_code(&code))
        .await
        .map_err(ApiError::internal)?
        .map_err(|e| ApiError::bad_request(format!("oauth exchange: {e}")))?;
    // Authorization gate: the operator's `allowed_github_logins`
    // determines who can hold a session. Until the team/RBAC
    // slice lands, "logged in" == "operator", so an empty
    // allowlist would let anyone with a GitHub account take
    // over the hub. main.rs hard-bails if OAuth is enabled
    // without an allowlist, but defence-in-depth re-checks here.
    let login_lower = gh_user.login.to_ascii_lowercase();
    if !state.config.allowed_github_logins.contains(&login_lower) {
        log::warn!(
            target: "sakimori_hub::auth",
            "rejecting OAuth login for github user {} (not on allowed_github_logins)",
            gh_user.login,
        );
        return Err(ApiError::unauthorized(
            "this GitHub user is not allowed on this hub",
        ));
    }
    let user_id = state
        .store
        .upsert_user(UpsertUserSpec {
            github_user_id: gh_user.id,
            github_login: gh_user.login.clone(),
            display_name: gh_user.name.clone(),
            avatar_url: gh_user.avatar_url.clone(),
        })
        .await
        .map_err(ApiError::internal)?;
    // Mint the *session* cookie (separate from the oauth-state
    // cookie which we now clear).
    let session = crate::auth::session::mint_session_token(secret);
    state
        .store
        .create_session(
            user_id,
            session.token_hash,
            state.config.session_ttl_secs,
            user_agent,
        )
        .await
        .map_err(ApiError::internal)?;
    let session_cookie = crate::auth::session::build_set_cookie(
        &session.cookie_value,
        state.config.session_ttl_secs,
        state.config.cookie_secure,
    )
    .map_err(ApiError::internal)?;
    let clear_state = state_oauth_clear_cookie(state.config.cookie_secure);
    let mut resp = Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, "/")
        .body(axum::body::Body::empty())
        .map_err(ApiError::internal)?;
    let h = resp.headers_mut();
    h.append(
        http::header::SET_COOKIE,
        session_cookie.parse().map_err(ApiError::internal)?,
    );
    h.append(
        http::header::SET_COOKIE,
        clear_state.parse().map_err(ApiError::internal)?,
    );
    Ok(resp)
}

async fn auth_logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(secret) = state.config.session_secret.as_deref()
        && let Some(cookie_header) = headers
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
        && let Some(value) = crate::auth::session::extract_session_cookie(cookie_header)
        && let Some(parsed) = crate::auth::verify_cookie(secret, value)
    {
        // Best-effort revoke — even if the DB call errors, we
        // still tell the browser to drop the cookie. Don't leak
        // the cause via response status.
        let _ = state.store.revoke_session(parsed.token_hash).await;
    }
    let clear = crate::auth::session::build_clear_cookie(state.config.cookie_secure);
    let mut resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .map_err(ApiError::internal)?;
    resp.headers_mut().insert(
        http::header::SET_COOKIE,
        clear.parse().map_err(ApiError::internal)?,
    );
    Ok(resp)
}

#[derive(Serialize)]
struct MeResp {
    user: StoredUser,
}

async fn auth_me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<MeResp>, ApiError> {
    let secret = state
        .config
        .session_secret
        .as_deref()
        .ok_or_else(|| ApiError::unauthorized("not signed in"))?;
    let user = cookie_session_user(&state, secret, &headers)
        .await?
        .ok_or_else(|| ApiError::unauthorized("not signed in"))?;
    Ok(Json(MeResp { user }))
}

fn require_oauth_client_id(state: &AppState) -> Result<&str, ApiError> {
    state
        .config
        .github_client_id
        .as_deref()
        .ok_or_else(|| ApiError::internal("github_client_id not configured"))
}

fn state_oauth_set_cookie(value: &str, secure: bool) -> anyhow::Result<String> {
    if value.contains([';', '\r', '\n']) {
        anyhow::bail!("oauth state cookie value contained a control character");
    }
    let mut s =
        format!("{OAUTH_STATE_COOKIE}={value}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=600");
    if secure {
        s.push_str("; Secure");
    }
    Ok(s)
}

fn state_oauth_clear_cookie(secure: bool) -> String {
    let mut s = format!("{OAUTH_STATE_COOKIE}=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        s.push_str("; Secure");
    }
    s
}

fn extract_named_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{name}=")) {
            return Some(value);
        }
    }
    None
}

// ---------------- actions oidc exchange ----------------

#[derive(Debug, Deserialize)]
pub struct ActionsExchangeBody {
    /// Raw OIDC JWT obtained inside the workflow via
    /// `$ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`.
    pub jwt: String,
}

#[derive(Serialize)]
struct ActionsExchangeResp {
    token: String,
    record: crate::store::StoredActionsToken,
}

async fn auth_actions_exchange(
    State(state): State<AppState>,
    Json(body): Json<ActionsExchangeBody>,
) -> Result<Json<ActionsExchangeResp>, ApiError> {
    let verifier = state
        .actions_verifier
        .as_ref()
        .ok_or_else(|| ApiError::not_found("actions oidc exchange disabled"))?
        .clone();
    let audience = state
        .config
        .actions_oidc_audience
        .as_deref()
        .ok_or_else(|| ApiError::internal("actions_oidc_audience not configured"))?
        .to_string();
    if state.config.allowed_actions_repositories.is_empty() {
        return Err(ApiError::not_found("actions oidc exchange disabled"));
    }
    // Verification is sync (jsonwebtoken doesn't have an async
    // shape) and the JWKS fetch path may block on the network —
    // off the runtime thread.
    let jwt = body.jwt;
    let claims = tokio::task::spawn_blocking(move || verifier.verify(&jwt))
        .await
        .map_err(ApiError::internal)?
        .map_err(|e| ApiError::unauthorized(format!("oidc verify: {e}")))?;
    // Audience defence in depth — the verifier already checked,
    // but `ActionsClaims` is a pub deserialise target so a future
    // refactor that swaps the verifier could regress quietly.
    if claims.aud != audience {
        return Err(ApiError::unauthorized(format!(
            "audience mismatch (expected {audience:?}, got {:?})",
            claims.aud
        )));
    }
    if !crate::auth::repository_matches(
        &state.config.allowed_actions_repositories,
        &claims.repository,
    ) {
        log::warn!(
            target: "sakimori_hub::auth",
            "rejecting actions exchange for repository {} (not on allowlist)",
            claims.repository,
        );
        return Err(ApiError::unauthorized(
            "this repository is not allowed on this hub",
        ));
    }
    // TTL = min(JWT `exp` - now, configured cap). The cap stops
    // a future-dated JWT from minting a 4-hour token; the JWT
    // bound stops a long cap from outliving the JWT itself (the
    // workflow's authorising moment).
    let now_secs = Utc::now().timestamp();
    let jwt_remaining = claims.exp.saturating_sub(now_secs);
    if jwt_remaining <= 0 {
        return Err(ApiError::unauthorized("oidc jwt already expired"));
    }
    let ttl = jwt_remaining.min(state.config.actions_token_ttl_secs);
    let minted = state
        .store
        .mint_actions_token(crate::store::ActionsTokenSpec {
            repository: claims.repository,
            repository_owner: claims.repository_owner,
            workflow_ref: claims.workflow_ref.or(claims.workflow),
            subject: claims.sub,
            ttl_secs: ttl,
        })
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(ActionsExchangeResp {
        token: minted.cleartext,
        record: minted.record,
    }))
}

// ---------------- device authorization flow ----------------

#[derive(Debug, Deserialize)]
pub struct DeviceCodeReq {
    /// Operator-supplied label that ends up on the minted
    /// personal token (e.g. "sakimori CLI on ada-laptop").
    pub label: String,
}

#[derive(Serialize)]
struct DeviceCodeResp {
    device_code: String,
    user_code: String,
    verification_uri: String,
    /// Pre-built URL operators can scan/click — same content as
    /// `verification_uri` with the user_code pre-filled as the
    /// `?code=` query param.
    verification_uri_complete: String,
    expires_in: i64,
    /// Min seconds between consecutive `POST /auth/device/token`
    /// polls. Sub-`interval` polls get `slow_down`.
    interval: i64,
}

const DEVICE_CODE_TTL_SECS: i64 = 600;
const DEVICE_CODE_MIN_POLL_INTERVAL_SECS: i64 = 5;

async fn auth_device_code(
    State(state): State<AppState>,
    Json(body): Json<DeviceCodeReq>,
) -> Result<Json<DeviceCodeResp>, ApiError> {
    // Browser login must be configured — without it there's no
    // way for an operator to approve the request.
    if state.oauth.is_none() {
        return Err(ApiError::not_found("device flow requires browser login"));
    }
    let base = state
        .config
        .external_base_url
        .as_deref()
        .ok_or_else(|| ApiError::internal("external_base_url not configured"))?
        .trim_end_matches('/');
    let minted = state
        .store
        .mint_device_code(body.label, DEVICE_CODE_TTL_SECS)
        .await
        .map_err(|e| ApiError::bad_request(format!("device code: {e}")))?;
    let verification_uri = format!("{base}/auth/device");
    let verification_uri_complete = format!(
        "{base}/auth/device?code={}",
        urlencoding::encode(&minted.user_code)
    );
    Ok(Json(DeviceCodeResp {
        device_code: minted.device_code,
        user_code: minted.user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_CODE_TTL_SECS,
        interval: DEVICE_CODE_MIN_POLL_INTERVAL_SECS,
    }))
}

#[derive(Deserialize)]
struct DevicePageQuery {
    #[serde(default)]
    code: Option<String>,
}

async fn auth_device_page(
    State(state): State<AppState>,
    Query(q): Query<DevicePageQuery>,
    axum::Extension(user): axum::Extension<StoredUser>,
) -> Result<Html<String>, ApiError> {
    // Three states:
    //   - no code in URL: blank form to paste one in.
    //   - code in URL, lookup succeeds + pending: confirm form.
    //   - code in URL, anything else: error page.
    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Approve a CLI sign-in</h1><p>Signed in as <code>{}</code>.</p>",
        html_escape(&user.github_login),
    ));
    if let Some(code) = q.code.as_deref() {
        match state.store.find_device_code_by_user_code(code).await {
            Ok(Some(row)) if row.status == DeviceCodeStatus::Pending => {
                body.push_str(&format!(
                    "<p>Authorize CLI client <code>{}</code> with code \
                     <strong>{}</strong>?</p>\
                     <form method=\"post\" action=\"/auth/device/approve\">\
                       <input type=\"hidden\" name=\"user_code\" value=\"{}\">\
                       <button type=\"submit\" name=\"decision\" value=\"approve\">\
                         Approve\
                       </button>\
                       <button type=\"submit\" name=\"decision\" value=\"deny\">\
                         Deny\
                       </button>\
                     </form>",
                    html_escape(&row.label),
                    html_escape(&row.user_code),
                    html_escape(&row.user_code),
                ));
            }
            Ok(Some(_)) => body.push_str(
                "<p>That code is no longer pending — it may have been \
                 approved, denied, expired, or already consumed.</p>",
            ),
            Ok(None) => body.push_str("<p>Unknown code. Check for typos and try again.</p>"),
            Err(e) => return Err(ApiError::internal(e)),
        }
    } else {
        body.push_str(
            "<form method=\"get\" action=\"/auth/device\">\
               <label>Code: \
                 <input name=\"code\" autocomplete=\"off\" autofocus required>\
               </label>\
               <button type=\"submit\">Continue</button>\
             </form>",
        );
    }
    Ok(Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>sakimori-hub device flow</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:32rem}}\
         input,button{{font-size:1rem;padding:.3rem .5rem;margin:.2rem 0}}\
         code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:.2rem}}\
         </style></head><body>{body}</body></html>"
    )))
}

#[derive(Deserialize)]
struct DeviceApproveBody {
    user_code: String,
    decision: String,
}

async fn auth_device_approve(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<StoredUser>,
    axum::Form(body): axum::Form<DeviceApproveBody>,
) -> Result<Html<String>, ApiError> {
    let Some(row) = state
        .store
        .find_device_code_by_user_code(&body.user_code)
        .await
        .map_err(ApiError::internal)?
    else {
        return Err(ApiError::not_found("unknown user_code"));
    };
    if row.status != DeviceCodeStatus::Pending {
        return Err(ApiError::bad_request("code is no longer pending"));
    }
    let decided = match body.decision.as_str() {
        "approve" => {
            // Race window: between `find_device_code_by_user_code`
            // and `approve_device_code` the row could expire or
            // be flipped by another tab. The store update guards
            // against pending+unexpired; if it returns false, we
            // surface 400 instead of cheerfully claiming success.
            let ok = state
                .store
                .approve_device_code(row.id, user.id)
                .await
                .map_err(ApiError::internal)?;
            if !ok {
                return Err(ApiError::bad_request("code is no longer pending"));
            }
            "approved"
        }
        "deny" => {
            let ok = state
                .store
                .deny_device_code(row.id)
                .await
                .map_err(ApiError::internal)?;
            if !ok {
                return Err(ApiError::bad_request("code is no longer pending"));
            }
            "denied"
        }
        other => {
            return Err(ApiError::bad_request(format!(
                "unknown decision {other:?} (expected approve|deny)"
            )));
        }
    };
    Ok(Html(format!(
        "<!doctype html><html><body style=\"font-family:system-ui,sans-serif;margin:2rem\">\
         <h1>Code {decided}</h1>\
         <p>You can close this tab — your CLI will pick up the change on its next poll.</p>\
         </body></html>"
    )))
}

#[derive(Debug, Deserialize)]
pub struct DeviceTokenReq {
    pub device_code: String,
}

#[derive(Serialize)]
struct DeviceTokenOk {
    token: String,
}

async fn auth_device_token(
    State(state): State<AppState>,
    Json(body): Json<DeviceTokenReq>,
) -> Result<Response, ApiError> {
    let outcome = state
        .store
        .poll_device_code(body.device_code, DEVICE_CODE_MIN_POLL_INTERVAL_SECS)
        .await
        .map_err(ApiError::internal)?;
    // The HTTP shape mirrors RFC 8628 — `{error: "..."}` for the
    // non-terminal "keep waiting" states, plus the final
    // success/error shapes. We use 400 for the polling errors
    // (per RFC) and 200 only on success.
    match outcome {
        DevicePollOutcome::Approved { cleartext } => {
            Ok(Json(DeviceTokenOk { token: cleartext }).into_response())
        }
        DevicePollOutcome::Pending { slow_down } => Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            message: if slow_down {
                "slow_down".into()
            } else {
                "authorization_pending".into()
            },
        }),
        DevicePollOutcome::Denied => Err(ApiError::bad_request("access_denied")),
        DevicePollOutcome::Expired => Err(ApiError::bad_request("expired_token")),
        DevicePollOutcome::AlreadyConsumed => Err(ApiError::bad_request("expired_token")),
    }
}

// ---------------- personal api tokens ----------------

#[derive(Debug, Deserialize)]
pub struct TokenCreateBody {
    pub label: String,
    /// Optional expiry, RFC3339. `None` = never expires.
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
struct TokenCreateResp {
    /// One-shot cleartext. The server never holds this again; the
    /// user MUST capture it on this response or lose it forever.
    token: String,
    record: StoredApiToken,
}

async fn tokens_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<StoredUser>,
    Json(body): Json<TokenCreateBody>,
) -> Result<Json<TokenCreateResp>, ApiError> {
    let expires_at = match body.expires_at.as_deref() {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| ApiError::bad_request(format!("invalid `expires_at`: {e}")))?,
        ),
        None => None,
    };
    let minted = state
        .store
        .create_api_token(user.id, body.label, expires_at)
        .await
        .map_err(|e| ApiError::bad_request(format!("create token: {e}")))?;
    Ok(Json(TokenCreateResp {
        token: minted.cleartext,
        record: minted.record,
    }))
}

#[derive(Serialize)]
struct TokenListResp {
    tokens: Vec<StoredApiToken>,
}

async fn tokens_list(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<StoredUser>,
) -> Result<Json<TokenListResp>, ApiError> {
    let tokens = state
        .store
        .list_api_tokens(user.id)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(TokenListResp { tokens }))
}

#[derive(Deserialize)]
pub struct TokenRevokeBody {
    pub id: i64,
}

async fn tokens_revoke(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<StoredUser>,
    Json(body): Json<TokenRevokeBody>,
) -> Result<StatusCode, ApiError> {
    let revoked = state
        .store
        .revoke_api_token(body.id, user.id)
        .await
        .map_err(ApiError::internal)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "no active token {} for this user",
            body.id
        )))
    }
}

// ---------------- error type ----------------

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn internal(e: impl std::fmt::Display) -> Self {
        // Sanitise so a multi-line `anyhow::Error::Display` chain
        // (e.g. embedded newlines from a SQL error) can't smuggle
        // a fake log line via splitting tooling.
        let msg = e.to_string().replace(['\n', '\r'], " ");
        log::error!(target: "sakimori_hub::api", "internal error: {msg}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".into(),
        }
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message }).to_string();
        (
            self.status,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SESSION_COOKIE_NAME;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use sakimori_core::deps::Ecosystem;
    use sakimori_core::installs::ExecutionMode;
    use tower::ServiceExt;

    fn state_with(config: ServerConfig) -> AppState {
        AppState::new(Arc::new(Store::open_in_memory().unwrap()), config)
    }
    fn state() -> AppState {
        state_with(ServerConfig::default())
    }

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn healthz_reports_ok_and_schema_version() {
        let app = router(state());
        let resp = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"count\":0"));
        assert!(body.contains("\"schema_version\":9"));
        assert!(body.contains("\"matching_mode\":\"exact_versions_and_semver_ranges\""));
    }

    #[tokio::test]
    async fn ingest_single_then_list() {
        let st = state();
        let app = router(st.clone());
        let ev = InstallEvent::new(Ecosystem::Crates, "serde", "1.0.0")
            .with_mode(ExecutionMode::Persistent)
            .with_project_path("/home/runner/work/r/r");
        let resp = app
            .clone()
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"accepted\":1"));

        let resp = app
            .oneshot(
                Request::get("/installs?ecosystem=crates")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"name\":\"serde\""));
        assert!(body.contains("\"source\":\"actions\""));
    }

    #[tokio::test]
    async fn ingest_batch_is_atomic() {
        let st = state();
        let app = router(st.clone());
        let batch = vec![
            InstallEvent::new(Ecosystem::Npm, "a", "1"),
            InstallEvent::new(Ecosystem::Npm, "b", "2"),
        ];
        let resp = app
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"accepted\":2"));
        assert_eq!(st.store.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn ingest_explicit_source_override() {
        let st = state();
        let app = router(st.clone());
        // Path looks like a desktop but the proxy supplies the
        // explicit source — the hub must trust it.
        let body = serde_json::json!({
            "ecosystem": "npm",
            "name": "a",
            "version": "1",
            "resolved_at": Utc::now().to_rfc3339(),
            "execution_mode": "persistent",
            "project_path": "/Users/alice/proj",
            "source": "actions",
        });
        let resp = app
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rows = st.store.list(ListFilter::default()).await.unwrap();
        assert_eq!(rows[0].source, Source::Actions);
    }

    #[tokio::test]
    async fn ingest_rejects_oversized_batch() {
        let st = state_with(ServerConfig {
            max_batch: 2,
            ..ServerConfig::default()
        });
        let app = router(st.clone());
        let batch: Vec<_> = (0..5)
            .map(|i| InstallEvent::new(Ecosystem::Npm, format!("p{i}"), "1"))
            .collect();
        let resp = app
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(st.store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn ingest_rejects_oversized_body() {
        let st = state_with(ServerConfig {
            body_limit_bytes: 64,
            ..ServerConfig::default()
        });
        let app = router(st);
        // Pad past 64 B with a noisy field value so the request
        // body exceeds the configured limit.
        let big = "x".repeat(2048);
        let body = serde_json::json!({
            "ecosystem": "npm",
            "name": big,
            "version": "1",
            "resolved_at": Utc::now().to_rfc3339(),
            "execution_mode": "persistent",
        });
        let resp = app
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // axum's DefaultBodyLimit returns 413 on overflow.
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn list_rejects_bad_source() {
        let app = router(state());
        let resp = app
            .oneshot(
                Request::get("/installs?source=bogus")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_rejects_bad_since() {
        let app = router(state());
        let resp = app
            .oneshot(
                Request::get("/installs?since=not-a-date")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn advisory_import_scan_then_list_findings() {
        let st = state();
        let app = router(st.clone());

        // Seed an install via the API.
        let ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0");
        app.clone()
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Import a matching advisory.
        let adv = serde_json::json!({
            "id": "GHSA-test",
            "summary": "test",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                          "versions": ["1.3.0"]}],
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/advisories")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&adv).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"created\":1"));

        // Run scan.
        let resp = app
            .clone()
            .oneshot(Request::post("/scan").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let scan_body = body_string(resp).await;
        assert!(scan_body.contains("\"new_findings\":1"));

        // GET /findings returns the match.
        let resp = app
            .clone()
            .oneshot(Request::get("/findings").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("GHSA-test"));
        assert!(body.contains("left-pad"));
        assert!(body.contains("\"severity\":\"critical\""));

        // Filter by min_severity above the only match → empty.
        // (No severity higher than critical, so use a name filter
        // via source: the only finding has source=unknown.)
        let resp = app
            .oneshot(
                Request::get("/findings?source=actions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"findings\":[]"));
    }

    #[tokio::test]
    async fn advisories_import_returns_400_on_range_with_huge_name() {
        let app = router(state());
        // Range-only advisory whose package name exceeds the cap.
        // Pre-range-validation slice would have inserted it
        // because validate_advisory walked affected_versions only.
        let body = serde_json::json!({
            "id": "GHSA-rangeval",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "x".repeat(1024)},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"fixed": "2.0.0"}
                ]}]
            }],
        });
        let resp = app
            .oneshot(
                Request::post("/advisories")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn advisories_import_returns_400_on_empty_id() {
        let app = router(state());
        let body = serde_json::json!({"id": ""});
        let resp = app
            .oneshot(
                Request::post("/advisories")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = body_string(resp).await;
        assert!(text.contains("advisory id is empty"));
    }

    #[tokio::test]
    async fn advisories_import_returns_400_on_oversized_summary() {
        let app = router(state());
        let body = serde_json::json!({
            "id": "GHSA-1",
            "summary": "x".repeat(9000),
        });
        let resp = app
            .oneshot(
                Request::post("/advisories")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn findings_rejects_bad_min_severity() {
        let app = router(state());
        let resp = app
            .oneshot(
                Request::get("/findings?min_severity=bogus")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn advisories_import_batch_and_list() {
        let st = state();
        let app = router(st.clone());
        let batch = serde_json::json!([
            {"id": "A", "database_specific": {"severity": "HIGH"},
             "affected": [{"package": {"ecosystem": "npm", "name": "p1"}, "versions": ["1"]}]},
            {"id": "B", "database_specific": {"severity": "LOW"},
             "affected": [{"package": {"ecosystem": "npm", "name": "p2"}, "versions": ["1"]}]}
        ]);
        let resp = app
            .clone()
            .oneshot(
                Request::post("/advisories")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .oneshot(Request::get("/advisories").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_string(resp).await;
        assert!(body.contains("\"osv_id\":\"A\""));
        assert!(body.contains("\"osv_id\":\"B\""));
    }

    // ---------- dispatch endpoints ----------

    use std::sync::Mutex;

    type RecordedCall = (String, Vec<(String, String)>, Vec<u8>);

    struct RecordingClient {
        calls: Mutex<Vec<RecordedCall>>,
        status: u16,
    }

    impl crate::dispatch::WebhookClient for RecordingClient {
        fn post(
            &self,
            url: &str,
            headers: &[(String, String)],
            body: &[u8],
        ) -> std::result::Result<u16, String> {
            self.calls
                .lock()
                .unwrap()
                .push((url.into(), headers.to_vec(), body.to_vec()));
            Ok(self.status)
        }
    }

    fn state_with_client(client: Arc<dyn crate::dispatch::WebhookClient>) -> AppState {
        AppState {
            store: Arc::new(Store::open_in_memory().unwrap()),
            config: ServerConfig::default(),
            webhook: client,
            dispatch_lock: Arc::new(tokio::sync::Mutex::new(())),
            oauth: None,
            actions_verifier: None,
        }
    }

    async fn seed_one_finding(st: &AppState) {
        st.store
            .insert(crate::store::IngestRecord {
                event: InstallEvent::new(Ecosystem::Npm, "p", "1.0.0")
                    .with_mode(ExecutionMode::Persistent)
                    .with_project_path("/home/runner/work/r/r"),
                source: None,
            })
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-x",
            "summary": "boom",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}],
        }))
        .unwrap();
        st.store.upsert_advisory(adv, None).await.unwrap();
        st.store.scan_findings().await.unwrap();
    }

    #[tokio::test]
    async fn target_create_then_dispatch_delivers_signed_post() {
        let recorder = Arc::new(RecordingClient {
            calls: Mutex::new(Vec::new()),
            status: 202,
        });
        let st = state_with_client(recorder.clone());
        let app = router(st.clone());
        seed_one_finding(&st).await;

        let body = serde_json::json!({
            "label": "ops",
            "url": "https://ops.example.com/hook",
            "secret": "0123456789abcdef0123",
            "min_severity": "high",
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/dispatch-targets")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(Request::post("/dispatch/run").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let report = body_string(resp).await;
        assert!(report.contains("\"considered\":1"));
        assert!(report.contains("\"delivered\":1"));

        // Snapshot under the lock, then drop it before any further
        // `.await` so clippy's `await_holding_lock` stays quiet.
        let snapshot: Vec<RecordedCall> = recorder.calls.lock().unwrap().clone();
        assert_eq!(snapshot.len(), 1);
        let (url, headers, body_bytes) = &snapshot[0];
        assert_eq!(url, "https://ops.example.com/hook");
        let sig = headers
            .iter()
            .find(|(k, _)| k == "X-Sakimori-Signature")
            .unwrap();
        let recomputed = crate::dispatch::sign(b"0123456789abcdef0123", body_bytes);
        assert_eq!(sig.1, recomputed);
        let label_hdr = headers
            .iter()
            .find(|(k, _)| k == "X-Sakimori-Target")
            .unwrap();
        assert_eq!(label_hdr.1, "ops");

        // Idempotency: second run produces zero deliveries.
        let resp = app
            .clone()
            .oneshot(Request::post("/dispatch/run").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let report = body_string(resp).await;
        assert!(report.contains("\"considered\":0"));
    }

    #[tokio::test]
    async fn dispatch_non_2xx_records_failure_and_retries() {
        let recorder = Arc::new(RecordingClient {
            calls: Mutex::new(Vec::new()),
            status: 500,
        });
        let st = state_with_client(recorder.clone());
        let app = router(st.clone());
        seed_one_finding(&st).await;
        st.store
            .register_target(crate::store::TargetSpec {
                label: "t".into(),
                url: "https://t/".into(),
                secret: "0123456789abcdef0123".into(),
                min_severity: Severity::Low,
                source_filter: None,
            })
            .await
            .unwrap();
        // First run: one failure recorded.
        let r1 = app
            .clone()
            .oneshot(Request::post("/dispatch/run").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(body_string(r1).await.contains("\"failed\":1"));
        // Second run: still pending (no success), so re-attempts.
        let r2 = app
            .clone()
            .oneshot(Request::post("/dispatch/run").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(body_string(r2).await.contains("\"considered\":1"));
    }

    #[tokio::test]
    async fn concurrent_dispatch_runs_do_not_double_fire() {
        // Slow client that holds the call open long enough that a
        // second `/dispatch/run` racing the first would re-pull
        // the same pending row if the dispatch lock weren't doing
        // its job.
        struct SlowClient {
            calls: Mutex<Vec<RecordedCall>>,
        }
        impl crate::dispatch::WebhookClient for SlowClient {
            fn post(
                &self,
                url: &str,
                headers: &[(String, String)],
                body: &[u8],
            ) -> std::result::Result<u16, String> {
                std::thread::sleep(std::time::Duration::from_millis(150));
                self.calls
                    .lock()
                    .unwrap()
                    .push((url.into(), headers.to_vec(), body.to_vec()));
                Ok(200)
            }
        }
        let client = Arc::new(SlowClient {
            calls: Mutex::new(Vec::new()),
        });
        let st = state_with_client(client.clone());
        let app = router(st.clone());
        seed_one_finding(&st).await;
        st.store
            .register_target(crate::store::TargetSpec {
                label: "t".into(),
                url: "https://t.example.com/".into(),
                secret: "0123456789abcdef0123".into(),
                min_severity: Severity::Low,
                source_filter: None,
            })
            .await
            .unwrap();

        let app1 = app.clone();
        let app2 = app.clone();
        let h1 = tokio::spawn(async move {
            app1.oneshot(Request::post("/dispatch/run").body(Body::empty()).unwrap())
                .await
                .unwrap()
        });
        // Stagger slightly so the second request unambiguously arrives
        // while the first is mid-flight.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let h2 = tokio::spawn(async move {
            app2.oneshot(Request::post("/dispatch/run").body(Body::empty()).unwrap())
                .await
                .unwrap()
        });
        let _ = h1.await.unwrap();
        let _ = h2.await.unwrap();

        let calls = client.calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "dispatch lock must serialise concurrent runs"
        );
    }

    #[tokio::test]
    async fn target_create_rejects_short_secret() {
        let app = router(state());
        let body = serde_json::json!({
            "label": "ops",
            "url": "https://ops.example/",
            "secret": "tiny",
            "min_severity": "high",
        });
        let resp = app
            .oneshot(
                Request::post("/dispatch-targets")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---------- bearer token ----------

    fn state_with_token(token: &str) -> AppState {
        AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                ingest_token: Some(token.into()),
                // Disable Secure so tests can compose without a TLS terminator.
                cookie_secure: false,
                ..ServerConfig::default()
            },
        )
    }

    // ---------- GitHub OAuth (stub) ----------

    struct StubExchange {
        user: crate::auth::GitHubUser,
    }
    impl crate::auth::OAuthExchange for StubExchange {
        fn exchange_code(
            &self,
            _code: &str,
        ) -> std::result::Result<crate::auth::GitHubUser, crate::auth::GitHubAuthError> {
            Ok(self.user.clone())
        }
    }

    fn state_with_oauth(user: crate::auth::GitHubUser) -> AppState {
        // Tests pre-allow whatever login the stub returns so the
        // happy-path callbacks succeed. The "denied" test
        // constructs its own state with an empty allowlist.
        let login = user.login.to_ascii_lowercase();
        let mut st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                ingest_token: Some("0123456789abcdef0123".into()),
                session_secret: Some(b"server-secret-1234567890abcdef-xyz".to_vec()),
                external_base_url: Some("https://hub.example.com".into()),
                github_client_id: Some("client-abc".into()),
                allowed_github_logins: vec![login],
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        st.oauth = Some(Arc::new(StubExchange { user }));
        st
    }

    /// Pull the `Set-Cookie` value for `name` out of a response.
    fn extract_set_cookie(resp: &Response, name: &str) -> Option<String> {
        for h in resp.headers().get_all(http::header::SET_COOKIE).iter() {
            let s = h.to_str().ok()?;
            if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
                // value is up to the first `;`.
                return Some(rest.split(';').next().unwrap_or("").to_string());
            }
        }
        None
    }

    #[tokio::test]
    async fn oauth_login_redirects_and_sets_state_cookie() {
        let app = router(state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        }));
        let resp = app
            .oneshot(
                Request::get("/auth/github/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp
            .headers()
            .get(http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(loc.contains("client_id=client-abc"));
        assert!(
            loc.contains("redirect_uri=https%3A%2F%2Fhub.example.com%2Fauth%2Fgithub%2Fcallback")
        );
        let state_cookie = extract_set_cookie(&resp, OAUTH_STATE_COOKIE).unwrap();
        assert!(!state_cookie.is_empty());
        // The state cookie value must appear as the `state` query param.
        let needle = format!("state={}", urlencoding::encode(&state_cookie));
        assert!(loc.contains(&needle), "loc={loc} state={state_cookie}");
    }

    #[tokio::test]
    async fn oauth_callback_creates_session_on_state_match() {
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 42,
            login: "ada".into(),
            name: Some("Ada Lovelace".into()),
            avatar_url: None,
        });
        let app = router(st.clone());
        // Step 1: /login to obtain the state cookie.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/auth/github/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let state_value = extract_set_cookie(&resp, OAUTH_STATE_COOKIE).unwrap();
        // Step 2: /callback with the matching state.
        let resp = app
            .oneshot(
                Request::get(format!(
                    "/auth/github/callback?code=ignored&state={}",
                    urlencoding::encode(&state_value),
                ))
                .header("cookie", format!("{OAUTH_STATE_COOKIE}={state_value}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let session_cookie = extract_set_cookie(&resp, SESSION_COOKIE_NAME).unwrap();
        assert!(!session_cookie.is_empty());
        // Session should resolve to the upserted user.
        let secret = st.config.session_secret.as_deref().unwrap();
        let parsed = crate::auth::verify_cookie(secret, &session_cookie).unwrap();
        let user = st
            .store
            .session_user(parsed.token_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.github_user_id, 42);
        assert_eq!(user.github_login, "ada");
    }

    #[tokio::test]
    async fn oauth_callback_rejects_state_mismatch() {
        let app = router(state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        }));
        // Obtain a legitimate state cookie.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/auth/github/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let state_value = extract_set_cookie(&resp, OAUTH_STATE_COOKIE).unwrap();
        // Use a *different* `state` query value — attacker drive-by.
        let resp = app
            .oneshot(
                Request::get("/auth/github/callback?code=ignored&state=attacker-controlled")
                    .header("cookie", format!("{OAUTH_STATE_COOKIE}={state_value}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oauth_callback_rejects_user_not_on_allowlist() {
        // Operator allowlist = ["ada"], OAuth returns user "mallory".
        let mut st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                session_secret: Some(b"server-secret-1234567890abcdef-xyz".to_vec()),
                external_base_url: Some("https://hub.example.com".into()),
                github_client_id: Some("client-abc".into()),
                allowed_github_logins: vec!["ada".into()],
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        st.oauth = Some(Arc::new(StubExchange {
            user: crate::auth::GitHubUser {
                id: 99,
                login: "mallory".into(),
                name: None,
                avatar_url: None,
            },
        }));
        let app = router(st.clone());
        let resp = app
            .clone()
            .oneshot(
                Request::get("/auth/github/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let state_value = extract_set_cookie(&resp, OAUTH_STATE_COOKIE).unwrap();
        let resp = app
            .oneshot(
                Request::get(format!(
                    "/auth/github/callback?code=ignored&state={}",
                    urlencoding::encode(&state_value),
                ))
                .header("cookie", format!("{OAUTH_STATE_COOKIE}={state_value}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // No session row created.
        assert!(extract_set_cookie(&resp, SESSION_COOKIE_NAME).is_none());
    }

    #[tokio::test]
    async fn cookie_csrf_rejects_cross_site_origin() {
        // Valid cookie + wrong Origin = 401 (CSRF defence).
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 1,
                github_login: "ada".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE_NAME}={}", s.cookie_value),
                    )
                    .header("origin", "https://attacker.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cookie_csrf_referer_prefix_bypass_is_rejected() {
        // Regression: a naïve `referer.starts_with(base)` would
        // accept `https://hub.example.com.attacker.tld/x` for
        // `base = https://hub.example.com`. Require a `/`
        // separator (or exact match).
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 1,
                github_login: "ada".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE_NAME}={}", s.cookie_value),
                    )
                    .header("referer", "https://hub.example.com.attacker.tld/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "host suffix attack must NOT pass referer check"
        );
    }

    #[tokio::test]
    async fn cookie_csrf_rejects_missing_origin_and_referer() {
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 1,
                github_login: "ada".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE_NAME}={}", s.cookie_value),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "cookie request without Origin or Referer must be refused"
        );
    }

    #[tokio::test]
    async fn oauth_only_deploy_rejects_bearer_token() {
        // session_secret set, ingest_token unset — operator wants
        // OAuth only. A `Authorization: Bearer ...` request must
        // NOT succeed, even with a syntactically valid header.
        let st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                session_secret: Some(b"server-secret-1234567890abcdef-xyz".to_vec()),
                external_base_url: Some("https://hub.example.com".into()),
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header("authorization", "Bearer any-old-string-abcdef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_cookie_unlocks_protected_endpoint() {
        // Browser path: a valid session cookie should authorize
        // `POST /scan` without an Authorization header.
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let user_id = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 1,
                github_login: "ada".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let session = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(user_id, session.token_hash, 3600, None)
            .await
            .unwrap();
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE_NAME}={}", session.cookie_value),
                    )
                    // Matching Origin satisfies the CSRF guard.
                    .header("origin", "https://hub.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "valid session cookie + matching Origin must satisfy the bearer-token gate"
        );
    }

    #[tokio::test]
    async fn auth_me_returns_user_when_signed_in() {
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 7,
            login: "linus".into(),
            name: Some("Linus".into()),
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 7,
                github_login: "linus".into(),
                display_name: Some("Linus".into()),
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let app = router(st);
        let resp = app
            .clone()
            .oneshot(
                Request::get("/auth/me")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE_NAME}={}", s.cookie_value),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"github_login\":\"linus\""));

        // Without the cookie, 401.
        let resp = app
            .oneshot(Request::get("/auth/me").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---------- actions oidc exchange ----------

    struct StubActionsVerifier {
        claims: Mutex<crate::auth::ActionsClaims>,
        err: Mutex<Option<crate::auth::ActionsAuthError>>,
    }

    impl crate::auth::ActionsOidcVerifier for StubActionsVerifier {
        fn verify(
            &self,
            _jwt: &str,
        ) -> std::result::Result<crate::auth::ActionsClaims, crate::auth::ActionsAuthError>
        {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(self.claims.lock().unwrap().clone())
        }
    }

    fn state_with_actions(
        repos: Vec<&str>,
        audience: &str,
        claims: crate::auth::ActionsClaims,
    ) -> (AppState, Arc<StubActionsVerifier>) {
        let verifier = Arc::new(StubActionsVerifier {
            claims: Mutex::new(claims),
            err: Mutex::new(None),
        });
        let mut st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                allowed_actions_repositories: repos.iter().map(|s| (*s).into()).collect(),
                actions_oidc_audience: Some(audience.into()),
                actions_token_ttl_secs: 900,
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        st.actions_verifier = Some(verifier.clone());
        (st, verifier)
    }

    fn fresh_actions_claims(repo: &str, audience: &str) -> crate::auth::ActionsClaims {
        crate::auth::ActionsClaims {
            iss: crate::auth::GITHUB_ACTIONS_ISSUER.into(),
            aud: audience.into(),
            sub: format!("repo:{repo}:ref:refs/heads/main"),
            repository: repo.into(),
            repository_owner: repo.split('/').next().unwrap_or("").into(),
            workflow: Some(".github/workflows/ci.yml".into()),
            workflow_ref: None,
            exp: chrono::Utc::now().timestamp() + 3600,
        }
    }

    #[tokio::test]
    async fn actions_exchange_mints_short_lived_token() {
        let (st, _v) = state_with_actions(
            vec!["org/repo"],
            "https://hub.example.com",
            fresh_actions_claims("org/repo", "https://hub.example.com"),
        );
        let app = router(st.clone());
        let resp = app
            .oneshot(
                Request::post("/auth/actions/exchange")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"jwt": "stub"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let token = parsed["token"].as_str().unwrap();
        assert!(token.starts_with("sha_"));
        // record carries repository + expires_at
        assert_eq!(parsed["record"]["repository"], "org/repo");
    }

    #[tokio::test]
    async fn actions_exchange_rejects_repo_not_on_allowlist() {
        let (st, _) = state_with_actions(
            vec!["org/other"],
            "https://hub.example.com",
            fresh_actions_claims("org/repo", "https://hub.example.com"),
        );
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/auth/actions/exchange")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"jwt": "stub"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn actions_exchange_rejects_audience_mismatch() {
        // Verifier returns claims with aud != configured.
        let (st, _) = state_with_actions(
            vec!["org/repo"],
            "https://hub.example.com",
            fresh_actions_claims("org/repo", "wrong-audience"),
        );
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/auth/actions/exchange")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"jwt": "stub"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn actions_exchange_disabled_when_no_repositories() {
        let mut st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                actions_oidc_audience: Some("hub".into()),
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        let verifier: Arc<dyn crate::auth::ActionsOidcVerifier> = Arc::new(StubActionsVerifier {
            claims: Mutex::new(fresh_actions_claims("org/repo", "hub")),
            err: Mutex::new(None),
        });
        st.actions_verifier = Some(verifier);
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/auth/actions/exchange")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"jwt": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn actions_token_unlocks_protected_endpoint() {
        let (st, _) = state_with_actions(
            vec!["org/repo"],
            "https://hub.example.com",
            fresh_actions_claims("org/repo", "https://hub.example.com"),
        );
        let app = router(st.clone());
        // Exchange.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/actions/exchange")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"jwt": "stub"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let token =
            serde_json::from_str::<serde_json::Value>(&body_string(resp).await).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_string();
        // Without ANY auth — must be 401 (proves the middleware
        // isn't no-op'ing in an Actions-only deploy).
        let resp = app
            .clone()
            .oneshot(Request::post("/scan").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Actions-only deploy must NOT leave writes ungated"
        );
        // With the minted sha_ token — 200.
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn actions_exchange_rejects_already_expired_jwt() {
        let mut claims = fresh_actions_claims("org/repo", "hub");
        claims.exp = chrono::Utc::now().timestamp() - 10;
        let (st, _) = state_with_actions(vec!["org/repo"], "hub", claims);
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/auth/actions/exchange")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"jwt": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---------- personal api tokens ----------

    /// Convenience: log a fresh user in (oauth stubbed) and
    /// return `(state, cookie_header)` ready for `/api/tokens`.
    // ---------- device authorization flow ----------

    #[tokio::test]
    async fn device_flow_end_to_end() {
        let (st, cookie) = device_flow_signed_in().await;
        let app = router(st);

        // 1. CLI requests a device + user code.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/code")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "sakimori CLI ada"}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let device_code = parsed["device_code"].as_str().unwrap().to_string();
        let user_code = parsed["user_code"].as_str().unwrap().to_string();
        assert!(
            parsed["verification_uri"]
                .as_str()
                .unwrap()
                .ends_with("/auth/device")
        );
        assert!(
            parsed["verification_uri_complete"]
                .as_str()
                .unwrap()
                .contains("code=")
        );
        assert_eq!(parsed["interval"], 5);

        // 2. CLI polls — should be pending.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": &device_code}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("authorization_pending"));

        // 3. Operator browses to /auth/device with the code and clicks Approve.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(format!(
                        "user_code={}&decision=approve",
                        urlencoding::encode(&user_code)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("approved"));

        // 4. CLI polls again — should get the cleartext token.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": &device_code}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token =
            serde_json::from_str::<serde_json::Value>(&body_string(resp).await).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_string();
        assert!(token.starts_with("shp_"));

        // 5. Re-poll should be `expired_token` (one-shot).
        let resp = app
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": &device_code}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("expired_token"));
    }

    #[tokio::test]
    async fn device_flow_deny_returns_access_denied() {
        let (st, cookie) = device_flow_signed_in().await;
        let app = router(st);
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/code")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let device_code = parsed["device_code"].as_str().unwrap().to_string();
        let user_code = parsed["user_code"].as_str().unwrap().to_string();
        app.clone()
            .oneshot(
                Request::post("/auth/device/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(format!(
                        "user_code={}&decision=deny",
                        urlencoding::encode(&user_code)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = app
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": device_code}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("access_denied"));
    }

    #[tokio::test]
    async fn device_flow_slow_down_on_fast_poll() {
        let (st, _cookie) = device_flow_signed_in().await;
        let app = router(st);
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/code")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let device_code = serde_json::from_str::<serde_json::Value>(&body_string(resp).await)
            .unwrap()["device_code"]
            .as_str()
            .unwrap()
            .to_string();
        // First poll: authorization_pending.
        let r1 = app
            .clone()
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": &device_code}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(body_string(r1).await.contains("authorization_pending"));
        // Immediate second poll inside the 5s window: slow_down.
        let r2 = app
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": &device_code}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(body_string(r2).await.contains("slow_down"));
    }

    #[tokio::test]
    async fn device_flow_unknown_device_code_is_expired() {
        let (st, _) = device_flow_signed_in().await;
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/auth/device/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"device_code": "garbage"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("expired_token"));
    }

    #[tokio::test]
    async fn device_flow_get_page_works_without_origin_or_referer() {
        // Regression: GET /auth/device must NOT require an
        // Origin/Referer header — operators open the
        // verification link from terminals, fresh tabs, or
        // bookmarks, none of which set them. CSRF is only an
        // issue on POSTs.
        let (st, cookie) = device_flow_signed_in().await;
        let app = router(st);
        let resp = app
            .oneshot(
                Request::get("/auth/device")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn device_flow_approve_race_returns_400_when_already_consumed() {
        // Same user_code approved twice (form-resubmit / race
        // tab): the second POST must NOT pretend it succeeded.
        let (st, cookie) = device_flow_signed_in().await;
        let app = router(st);
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/device/code")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let user_code = parsed["user_code"].as_str().unwrap().to_string();
        let approve_req = || {
            Request::post("/auth/device/approve")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", &cookie)
                .header("origin", "https://hub.example.com")
                .body(Body::from(format!(
                    "user_code={}&decision=approve",
                    urlencoding::encode(&user_code)
                )))
                .unwrap()
        };
        // First click → ok.
        let r1 = app.clone().oneshot(approve_req()).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        // Second click on the same form (now the row is approved,
        // not pending) → 400, not a fake "approved".
        let r2 = app.oneshot(approve_req()).await.unwrap();
        assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(r2).await.contains("no longer pending"));
    }

    #[tokio::test]
    async fn device_flow_code_requires_browser_oauth_configured() {
        // No oauth on AppState → /auth/device/code 404s.
        let st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                external_base_url: Some("https://hub.example.com".into()),
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        let app = router(st);
        let resp = app
            .oneshot(
                Request::post("/auth/device/code")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Logged-in operator state used by the device-flow tests
    /// above. Reuses `state_with_oauth` for the stub, then mints
    /// a session for "ada".
    async fn device_flow_signed_in() -> (AppState, String) {
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 1,
                github_login: "ada".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE_NAME}={}", s.cookie_value);
        (st, cookie)
    }

    async fn signed_in_state(login: &str) -> (AppState, String) {
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 1,
            login: login.into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 1,
                github_login: login.into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE_NAME}={}", s.cookie_value);
        (st, cookie)
    }

    #[tokio::test]
    async fn personal_token_create_list_revoke_happy_path() {
        let (st, cookie) = signed_in_state("ada").await;
        let app = router(st.clone());

        // Create.
        let body = serde_json::json!({"label": "laptop-ci"});
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/tokens")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body_text = body_string(resp).await;
        assert_eq!(status, StatusCode::OK, "create body: {body_text}");
        let parsed: serde_json::Value = serde_json::from_str(&body_text).unwrap();
        let token = parsed["token"].as_str().unwrap().to_string();
        let id = parsed["record"]["id"].as_i64().unwrap();
        assert!(token.starts_with("shp_"));
        assert_eq!(parsed["record"]["label"], "laptop-ci");

        // List shows it.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/tokens")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_string(resp).await;
        assert!(body.contains("\"label\":\"laptop-ci\""));
        // Cleartext token must NOT appear in the list response.
        assert!(!body.contains(&token));

        // Revoke (POST body for the id — see router comment).
        let resp = app
            .oneshot(
                Request::post("/api/tokens/revoke")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"id": id})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn personal_token_authenticates_protected_endpoint() {
        // The point of personal tokens: a CLI / Actions workflow
        // hits `POST /scan` with `Authorization: Bearer shp_...`
        // and gets in (no shared secret needed, no cookie needed).
        let (st, cookie) = signed_in_state("ada").await;
        let app = router(st.clone());
        // Mint a token via the API.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/tokens")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "ci"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let token =
            serde_json::from_str::<serde_json::Value>(&body_string(resp).await).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_string();
        // Hit /scan with the token. No cookie. No Origin.
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn personal_token_revoked_token_is_rejected() {
        let (st, cookie) = signed_in_state("ada").await;
        let app = router(st.clone());
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/tokens")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let token = parsed["token"].as_str().unwrap().to_string();
        let id = parsed["record"]["id"].as_i64().unwrap();
        // Revoke directly via the store to keep the test focused
        // on the middleware's behaviour for a stale token.
        st.store.revoke_api_token(id, 1).await.unwrap();
        let resp = app
            .oneshot(
                Request::post("/scan")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn personal_token_blocked_after_user_removed_from_allowlist() {
        // Offboarding regression: a personal token minted by
        // user "ada" must stop working as soon as "ada" leaves
        // SAKIMORI_HUB_ALLOWED_GITHUB_LOGINS, even before each
        // token is individually revoked.
        let (st, cookie) = signed_in_state("ada").await;
        let app = router(st.clone());
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/tokens")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let token =
            serde_json::from_str::<serde_json::Value>(&body_string(resp).await).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_string();
        // Token works while ada is on the allowlist.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/scan")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Operator removes ada from the allowlist (simulate by
        // building a fresh AppState reusing the same store).
        let mut st2 = AppState::new(
            st.store.clone(),
            ServerConfig {
                ingest_token: Some("0123456789abcdef0123".into()),
                session_secret: Some(b"server-secret-1234567890abcdef-xyz".to_vec()),
                external_base_url: Some("https://hub.example.com".into()),
                github_client_id: Some("client-abc".into()),
                allowed_github_logins: vec!["someone-else".into()],
                cookie_secure: false,
                ..ServerConfig::default()
            },
        );
        st2.oauth = st.oauth.clone();
        let app2 = router(st2);
        let resp = app2
            .oneshot(
                Request::post("/scan")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "offboarded user's tokens must stop working without per-token revoke"
        );
    }

    #[tokio::test]
    async fn personal_token_endpoints_require_session_not_bearer() {
        // Operator who only has the legacy shared secret must NOT
        // be able to mint personal tokens (those are per-user).
        let app = router(state_with_token("0123456789abcdef0123"));
        let resp = app
            .oneshot(
                Request::post("/api/tokens")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer 0123456789abcdef0123")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Without session_secret configured the tokens routes
        // return 404 (the surface is unavailable), with it but
        // no session 401. Either way: NOT 200.
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn personal_token_revoke_other_users_token_returns_404() {
        // User A mints a token; user B tries to revoke it via id.
        let (st_a, cookie_a) = signed_in_state("ada").await;
        // Manually create a second user + their token in the
        // same store, then build a session for them.
        let uid_b = st_a
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 2,
                github_login: "linus".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let secret = st_a.config.session_secret.as_deref().unwrap().to_vec();
        let s = crate::auth::session::mint_session_token(&secret);
        st_a.store
            .create_session(uid_b, s.token_hash, 3600, None)
            .await
            .unwrap();
        let cookie_b = format!("{SESSION_COOKIE_NAME}={}", s.cookie_value);
        let app = router(st_a.clone());
        // Ada mints.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/tokens")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie_a)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"label": "ada's"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let id = parsed["record"]["id"].as_i64().unwrap();
        // Linus tries to revoke Ada's token.
        let resp = app
            .oneshot(
                Request::post("/api/tokens/revoke")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie_b)
                    .header("origin", "https://hub.example.com")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"id": id})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Must be NOT FOUND, not NO_CONTENT — Linus has no
        // visibility into Ada's tokens.
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn logout_revokes_session() {
        let st = state_with_oauth(crate::auth::GitHubUser {
            id: 3,
            login: "ada".into(),
            name: None,
            avatar_url: None,
        });
        let secret = st.config.session_secret.as_deref().unwrap().to_vec();
        let uid = st
            .store
            .upsert_user(crate::store::UpsertUserSpec {
                github_user_id: 3,
                github_login: "ada".into(),
                display_name: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let s = crate::auth::session::mint_session_token(&secret);
        st.store
            .create_session(uid, s.token_hash, 3600, None)
            .await
            .unwrap();
        let app = router(st.clone());
        let resp = app
            .oneshot(
                Request::post("/auth/logout")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE_NAME}={}", s.cookie_value),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            st.store.session_user(s.token_hash).await.unwrap().is_none(),
            "session must be revoked"
        );
    }

    #[tokio::test]
    async fn writes_require_bearer_token_when_configured() {
        let app = router(state_with_token("0123456789abcdef0123"));
        // No header → 401.
        let ev = InstallEvent::new(Ecosystem::Npm, "p", "1");
        let resp = app
            .clone()
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token → 401.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer wrong-secret-abcdef")
                    .body(Body::from(serde_json::to_vec(&ev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Right token → 200.
        let resp = app
            .oneshot(
                Request::post("/ingest")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer 0123456789abcdef0123")
                    .body(Body::from(serde_json::to_vec(&ev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reads_are_gated_by_default_when_token_set() {
        // Secure-by-default: a vanilla `wrangler deploy` to
        // Cloudflare Containers must not leak inventory just
        // because the operator forgot a `--public-reads` flag.
        // Only `/healthz` stays open for probes.
        let app = router(state_with_token("0123456789abcdef0123"));
        for path in [
            "/installs",
            "/findings",
            "/advisories",
            "/dispatch-targets",
            "/",
        ] {
            let resp = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must require the bearer token by default"
            );
        }
        let resp = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/healthz must always stay open for probes"
        );
    }

    #[tokio::test]
    async fn reads_open_when_public_reads_opt_in() {
        // Opt-in for operators who put Cloudflare Access (or
        // equivalent) in front of the read surface.
        let st = AppState::new(
            Arc::new(Store::open_in_memory().unwrap()),
            ServerConfig {
                ingest_token: Some("0123456789abcdef0123".into()),
                public_reads: true,
                ..ServerConfig::default()
            },
        );
        let app = router(st);
        for path in [
            "/healthz",
            "/installs",
            "/findings",
            "/advisories",
            "/dispatch-targets",
            "/",
        ] {
            let resp = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path} must be public");
        }
    }

    #[tokio::test]
    async fn dispatch_target_delete_also_requires_token() {
        // Catches a regression where adding a new write endpoint
        // forgets to add it to the `protected` sub-router.
        let app = router(state_with_token("0123456789abcdef0123"));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/dispatch-targets/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn target_delete_returns_404_when_missing() {
        let app = router(state());
        let resp = app
            .oneshot(
                Request::delete("/dispatch-targets/9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn index_html_escapes_user_supplied_fields() {
        let st = state();
        let app = router(st.clone());
        st.store
            .insert(IngestRecord {
                event: InstallEvent::new(Ecosystem::Npm, "<script>", "\"1\"&v")
                    .with_project_path("</td><td>x"),
                source: None,
            })
            .await
            .unwrap();
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("<table"));
        // Every dangerous character is escaped in the rendered cells.
        assert!(body.contains("&lt;script&gt;"));
        assert!(body.contains("&quot;1&quot;&amp;v"));
        assert!(body.contains("&lt;/td&gt;&lt;td&gt;x"));
        // And the raw injection attempt does NOT appear as live markup.
        assert!(!body.contains("<script>1"));
    }
}

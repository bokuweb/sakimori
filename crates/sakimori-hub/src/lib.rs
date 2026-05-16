//! sakimori-hub — optional self-hostable companion service.
//!
//! This crate is the foundation for the **team-wide install inventory**
//! described in roadmap item #6 of CLAUDE.md. It accepts
//! `InstallEvent`s posted by every `sakimori proxy` on a developer
//! laptop or CI runner, stores them durably, and exposes a small read
//! API so operators can answer:
//!
//! > "Who installed `<pkg>@<ver>`, and when, across CI and developer
//! > laptops?"
//!
//! ## Authentication
//!
//! Three independent credentials are accepted by write endpoints
//! (`/ingest`, `/advisories`, `/scan`, `/dispatch-targets`,
//! `/dispatch/run`):
//!
//! 1. **Browser session cookie** — minted by the GitHub OAuth
//!    Authorization Code Flow at `/auth/github/login` →
//!    `/auth/github/callback`. HMAC-signed (`subtle::ConstantTimeEq`),
//!    HttpOnly+Secure+SameSite=Lax. Cookie-authenticated writes
//!    also pass an Origin/Referer CSRF check against
//!    `external_base_url`.
//! 2. **Personal API token** — minted via `POST /api/tokens`
//!    while session-authenticated, returned as cleartext exactly
//!    once. Carry as `Authorization: Bearer shp_<43chars>`.
//!    Per-user, revocable, allowlist-gated on every request
//!    (offboarding via `SAKIMORI_HUB_ALLOWED_GITHUB_LOGINS` takes
//!    effect immediately).
//! 3. **Legacy shared-secret bearer** — `--ingest-token` /
//!    `SAKIMORI_HUB_INGEST_TOKEN`. Useful for CI bootstrapping
//!    before any user has logged in to mint a personal token.
//!    Cannot start with `shp_` (reserved for personal tokens).
//!
//! Read endpoints (`GET /installs` / `/findings` / `/advisories`
//! / `/dispatch-targets` / `/`) are gated identically by default;
//! `--public-reads` opts out (for deployments with an upstream
//! auth proxy in front of reads). `/healthz` is always open.
//!
//! ## What it does **not** do yet
//!
//! - **Team / RBAC.** Every authenticated user currently has
//!   full operator powers on a single shared dataset. The
//!   team/`team_id`/invite slice (#11 in the slice plan) carves
//!   the data tables by team and introduces owner/member roles.
//! - **GitHub Actions OIDC exchange** (#9) — short-lived
//!   per-Actions tokens via `id-token: write` JWT exchange.
//! - **Device Authorization Flow** (#10) — `sakimori login` CLI
//!   for the personal-laptop path so developers don't have to
//!   paste tokens manually.
//! - **R2 backup per team** (#12).
//! - **Stripe billing** (#13, design only).
//!
//! ## Schema
//!
//! Stored shape mirrors [`sakimori_core::installs::InstallEvent`] plus
//! a hub-side derived [`Source`] classifier (CI runner vs developer
//! laptop) so the read API can split CI and desktop activity without
//! re-deriving from User-Agent at every query.

pub mod advisories;
pub mod auth;
pub mod classify;
pub mod dispatch;
pub mod server;
pub mod store;

pub use advisories::{OsvAdvisory, Severity};
pub use classify::Source;
pub use dispatch::{DispatchReport, DispatcherHandle, UreqClient, WebhookClient, spawn_loop};
pub use store::{
    ACTIONS_TOKEN_PREFIX, API_TOKEN_PREFIX, ActionsPrincipal, ActionsTokenSpec, DeviceCodeStatus,
    DevicePollOutcome, MintedActionsToken, MintedApiToken, MintedDeviceCode, ScanReport, Store,
    StoredActionsToken, StoredAdvisory, StoredApiToken, StoredDeviceCode, StoredEvent,
    StoredFinding, StoredTarget, StoredUser, TargetSpec, UpsertUserSpec, hash_actions_token,
    hash_api_token,
};

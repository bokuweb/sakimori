//! Identity for sakimori-hub.
//!
//! Three auth paths are planned (see the slice-7 design note in
//! conversation history). This module implements path 1:
//!
//! 1. **Browser login** — GitHub OAuth Authorization Code Flow.
//!    Returns an HMAC-signed session cookie. *This slice.*
//! 2. **GitHub Actions** — `id-token: write` OIDC JWT, exchanged
//!    for a short-lived team-scoped API token. (slice 9)
//! 3. **Personal laptop CLI** — OAuth Device Authorization Flow,
//!    returns a long-lived per-user API token. (slice 10)
//!
//! The bearer-token middleware from slice 6 stays for legacy CI
//! that doesn't (yet) want to wire OAuth — it just becomes one of
//! several accepted credentials, not the only one.

pub mod actions;
pub mod github;
pub mod session;

pub use actions::{
    ActionsAuthError, ActionsClaims, ActionsOidcVerifier,
    DefaultVerifier as DefaultActionsVerifier, GITHUB_ACTIONS_ISSUER, repository_matches,
    validate_repository_pattern,
};

pub use github::{GitHubAuthError, GitHubOAuthClient, GitHubUser, OAuthExchange};
pub use session::{
    SESSION_COOKIE_NAME, SessionCookie, SessionToken, hash_session_token, mint_session_token,
    verify_cookie,
};

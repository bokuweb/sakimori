//! GitHub Actions OIDC exchange.
//!
//! GitHub gives every workflow with `permissions: id-token: write`
//! a signed JWT via `$ACTIONS_ID_TOKEN_REQUEST_URL` /
//! `$ACTIONS_ID_TOKEN_REQUEST_TOKEN`. The workflow POSTs that JWT
//! to `/auth/actions/exchange`; the hub verifies it against
//! GitHub's JWKS and mints a short-lived `sha_*` API token tied to
//! the JWT's `repository` claim. Workflows then carry the
//! `sha_*` token in `Authorization: Bearer` for the same write
//! surface as the personal-token path.
//!
//! ## What we verify
//!
//! - **Signature** — RS256 against GitHub's published JWKS at
//!   `https://token.actions.githubusercontent.com/.well-known/jwks`.
//!   The verifier caches the JWKS for a small window so a flood
//!   of exchanges doesn't beat up GitHub's endpoint.
//! - **`iss` claim** — exact match against
//!   `https://token.actions.githubusercontent.com`.
//! - **`aud` claim** — exact match against the operator-configured
//!   audience. GitHub lets the workflow set this when calling the
//!   token endpoint (`?audience=<value>`); the operator must pick
//!   a value they document for the workflow side. Defaults to
//!   the hub's `external_base_url`.
//! - **`exp` claim** — must be in the future.
//! - **`repository` claim** — must match the operator's allowlist.
//!
//! We do NOT verify `nbf` (GitHub omits it), `iat`, or the rest
//! of the schema beyond the fields above. The minted hub-side
//! token gets its own TTL bounded by `min(jwt.exp - now,
//! actions_token_ttl_secs)`.

use serde::Deserialize;

/// Claims we actually consume from the JWT. GitHub's tokens
/// include many more (environment, run_id, job_workflow_ref,
/// etc.); we keep the surface intentionally narrow because
/// every field we read is a field we'd have to keep working
/// across schema bumps on GitHub's side.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ActionsClaims {
    pub iss: String,
    /// `serde` accepts the OIDC `aud` claim as either string or
    /// `[string]`. GitHub usually emits the string form; we
    /// canonicalise to the first element for comparison.
    #[serde(deserialize_with = "deserialize_aud")]
    pub aud: String,
    pub sub: String,
    pub repository: String,
    pub repository_owner: String,
    #[serde(default)]
    pub workflow: Option<String>,
    #[serde(default)]
    pub workflow_ref: Option<String>,
    pub exp: i64,
}

fn deserialize_aud<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum AudShape {
        One(String),
        Many(Vec<String>),
    }
    match AudShape::deserialize(d)? {
        AudShape::One(s) => Ok(s),
        AudShape::Many(v) => v
            .into_iter()
            .next()
            .ok_or_else(|| D::Error::custom("empty aud")),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActionsAuthError {
    #[error("jwt malformed: {0}")]
    Malformed(String),
    #[error("jwt signature verification failed: {0}")]
    Signature(String),
    #[error("jwt issuer mismatch: got {0}")]
    Issuer(String),
    #[error("jwt audience mismatch: got {0}")]
    Audience(String),
    #[error("jwt expired at {0}")]
    Expired(i64),
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
    #[error("no JWKS key matched kid {0}")]
    UnknownKid(String),
}

/// Pluggable verifier so handler tests don't need real JWTs.
pub trait ActionsOidcVerifier: Send + Sync {
    fn verify(&self, jwt: &str) -> Result<ActionsClaims, ActionsAuthError>;
}

pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Match `repository` ("org/repo") against operator allowlist
/// patterns. Two shapes:
///
/// - `org/repo` exact (case-insensitive on owner half — GitHub
///   treats owner names case-insensitively).
/// - `org/*` org-wide wildcard.
///
/// Anything else parses to a bad-pattern error; we'd rather
/// hard-fail at config time than silently mismatch.
pub fn repository_matches(allowed: &[String], repository: &str) -> bool {
    let repo_lower = repository.to_ascii_lowercase();
    for pat in allowed {
        let pat_lower = pat.to_ascii_lowercase();
        if let Some(owner) = pat_lower.strip_suffix("/*") {
            // `org/*` — match if the repository starts with
            // `org/` and has no further slashes (so `org/sub/x`
            // doesn't slip through; GitHub repos are exactly
            // `owner/name`).
            if let Some(rest) = repo_lower.strip_prefix(&format!("{owner}/"))
                && !rest.contains('/')
                && !rest.is_empty()
            {
                return true;
            }
        } else if pat_lower == repo_lower {
            return true;
        }
    }
    false
}

pub fn validate_repository_pattern(pat: &str) -> Result<(), String> {
    if pat.is_empty() {
        return Err("empty repository pattern".into());
    }
    let body = pat.strip_suffix("/*").unwrap_or(pat);
    let slashes = body.matches('/').count();
    let allows_wildcard = pat.ends_with("/*");
    if allows_wildcard {
        if slashes != 0 {
            return Err(format!(
                "wildcard pattern {pat:?} must be `<owner>/*`, not nested"
            ));
        }
    } else if slashes != 1 {
        return Err(format!(
            "pattern {pat:?} must be `<owner>/<repo>` or `<owner>/*`"
        ));
    }
    Ok(())
}

// ---------------- production verifier (jsonwebtoken + cached JWKS) ----------------

pub use prod::GitHubActionsVerifier;
pub use prod::GitHubActionsVerifier as DefaultVerifier;

mod prod {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Production verifier — hits `${issuer}/.well-known/jwks`,
    /// caches the JWKS in-process, validates RS256.
    pub struct GitHubActionsVerifier {
        agent: ureq::Agent,
        audience: String,
        jwks_url: String,
        cache: Mutex<JwksCache>,
        ttl: Duration,
    }

    struct JwksCache {
        keys: Vec<JwksKey>,
        fetched_at: Option<Instant>,
        /// Last "we tried to refresh because of a kid miss"
        /// timestamp. Lets us throttle miss-driven refreshes
        /// even inside the normal TTL window — `/auth/actions/
        /// exchange` is unauthenticated, so a flood of attacker-
        /// chosen `kid`s would otherwise pin a network call per
        /// request.
        last_miss_refresh: Option<Instant>,
    }

    #[derive(Clone, Deserialize)]
    struct JwksKey {
        kid: String,
        n: String, // base64url modulus
        e: String, // base64url exponent
    }

    #[derive(Deserialize)]
    struct JwksResp {
        keys: Vec<JwksKey>,
    }

    impl GitHubActionsVerifier {
        pub fn new(audience: String) -> Self {
            Self::with_issuer(audience, GITHUB_ACTIONS_ISSUER.to_string())
        }

        pub fn with_issuer(audience: String, issuer: String) -> Self {
            Self {
                agent: ureq::AgentBuilder::new()
                    .timeout(Duration::from_secs(10))
                    .user_agent(concat!("sakimori-hub/", env!("CARGO_PKG_VERSION")))
                    .build(),
                audience,
                jwks_url: format!("{}/.well-known/jwks", issuer.trim_end_matches('/')),
                cache: Mutex::new(JwksCache {
                    keys: Vec::new(),
                    fetched_at: None,
                    last_miss_refresh: None,
                }),
                ttl: Duration::from_secs(300),
            }
        }

        /// Min interval between two successive miss-driven JWKS
        /// refreshes. 30s gives ~10s slack around realistic key
        /// rotation propagation while keeping the per-call worst
        /// case at one network round-trip per 30s, not per
        /// request.
        const MISS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

        fn refresh_jwks(&self) -> Result<Vec<JwksKey>, ActionsAuthError> {
            let resp = self
                .agent
                .get(&self.jwks_url)
                .set("accept", "application/json")
                .call()
                .map_err(|e| ActionsAuthError::Jwks(e.to_string()))?;
            let parsed: JwksResp = resp
                .into_json()
                .map_err(|e| ActionsAuthError::Jwks(e.to_string()))?;
            Ok(parsed.keys)
        }

        fn key_for_kid(&self, kid: &str) -> Result<JwksKey, ActionsAuthError> {
            let now = Instant::now();
            // Decide what to do based solely on cache state.
            #[derive(Clone)]
            enum Action {
                UseCachedHit(JwksKey),
                ReturnUnknownKid,
                Refresh,
            }
            let action = {
                let cache = self.cache.lock().expect("jwks cache mutex poisoned");
                let fresh = cache
                    .fetched_at
                    .map(|t| now.duration_since(t) < self.ttl)
                    .unwrap_or(false);
                let hit = cache.keys.iter().find(|k| k.kid == kid).cloned();
                match (fresh, hit) {
                    // Fresh hit: serve from cache (fast path).
                    (true, Some(k)) => Action::UseCachedHit(k),
                    // Stale hit OR stale miss: refresh so a
                    // rotated-out key can't keep validating
                    // tokens past the TTL.
                    (false, _) => Action::Refresh,
                    // Fresh miss: throttle refresh —
                    // /auth/actions/exchange is unauthenticated,
                    // so a stream of attacker-chosen kids would
                    // otherwise force a network call per request.
                    (true, None) => {
                        let throttled = cache
                            .last_miss_refresh
                            .map(|t| now.duration_since(t) < Self::MISS_REFRESH_INTERVAL)
                            .unwrap_or(false);
                        if throttled {
                            Action::ReturnUnknownKid
                        } else {
                            Action::Refresh
                        }
                    }
                }
            };
            match action {
                Action::UseCachedHit(k) => Ok(k),
                Action::ReturnUnknownKid => Err(ActionsAuthError::UnknownKid(kid.to_string())),
                Action::Refresh => {
                    let keys = self.refresh_jwks()?;
                    {
                        let mut cache = self.cache.lock().expect("jwks cache mutex poisoned");
                        cache.keys = keys.clone();
                        cache.fetched_at = Some(now);
                        cache.last_miss_refresh = Some(now);
                    }
                    keys.into_iter()
                        .find(|k| k.kid == kid)
                        .ok_or_else(|| ActionsAuthError::UnknownKid(kid.to_string()))
                }
            }
        }
    }

    impl ActionsOidcVerifier for GitHubActionsVerifier {
        fn verify(&self, jwt: &str) -> Result<ActionsClaims, ActionsAuthError> {
            let header = jsonwebtoken::decode_header(jwt)
                .map_err(|e| ActionsAuthError::Malformed(e.to_string()))?;
            let kid = header
                .kid
                .as_deref()
                .ok_or_else(|| ActionsAuthError::Malformed("missing `kid`".into()))?;
            let key_meta = self.key_for_kid(kid)?;
            let decoding = jsonwebtoken::DecodingKey::from_rsa_components(&key_meta.n, &key_meta.e)
                .map_err(|e| ActionsAuthError::Signature(e.to_string()))?;
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.set_audience(&[&self.audience]);
            validation.set_issuer(&[GITHUB_ACTIONS_ISSUER]);
            // `exp` validation is on by default; leave the rest
            // disabled — claim shape varies between GHA env types.
            validation.required_spec_claims = ["exp", "iss", "aud"]
                .into_iter()
                .map(String::from)
                .collect();
            let data = jsonwebtoken::decode::<ActionsClaims>(jwt, &decoding, &validation).map_err(
                |e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        ActionsAuthError::Expired(0)
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                        ActionsAuthError::Issuer(String::new())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        ActionsAuthError::Audience(String::new())
                    }
                    _ => ActionsAuthError::Signature(e.to_string()),
                },
            )?;
            Ok(data.claims)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_matches_exact() {
        assert!(repository_matches(&["org/repo".into()], "org/repo"));
        assert!(!repository_matches(&["org/repo".into()], "org/other"));
    }

    #[test]
    fn repository_matches_org_wildcard() {
        let allow = vec!["org/*".into()];
        assert!(repository_matches(&allow, "org/repo"));
        assert!(repository_matches(&allow, "org/other-repo"));
        assert!(!repository_matches(&allow, "other-org/repo"));
        // `/*` doesn't cross slashes — paranoia.
        assert!(!repository_matches(&allow, "org/sub/x"));
        // No trailing empty
        assert!(!repository_matches(&allow, "org/"));
    }

    #[test]
    fn repository_matches_case_insensitive_owner() {
        // GitHub normalises owner case.
        assert!(repository_matches(&["Org/Repo".into()], "org/repo"));
        assert!(repository_matches(&["ORG/*".into()], "Org/Whatever"));
    }

    #[test]
    fn validate_repository_pattern_rejects_garbage() {
        assert!(validate_repository_pattern("org/repo").is_ok());
        assert!(validate_repository_pattern("org/*").is_ok());
        assert!(validate_repository_pattern("").is_err());
        assert!(validate_repository_pattern("just-an-owner").is_err());
        assert!(validate_repository_pattern("org/repo/extra").is_err());
        assert!(validate_repository_pattern("org/sub/*").is_err());
    }

    #[test]
    fn aud_deserialize_accepts_string_and_array() {
        let v: ActionsClaims = serde_json::from_value(serde_json::json!({
            "iss": "x",
            "aud": "hub",
            "sub": "s",
            "repository": "org/repo",
            "repository_owner": "org",
            "exp": 99999,
        }))
        .unwrap();
        assert_eq!(v.aud, "hub");
        let v: ActionsClaims = serde_json::from_value(serde_json::json!({
            "iss": "x",
            "aud": ["hub"],
            "sub": "s",
            "repository": "org/repo",
            "repository_owner": "org",
            "exp": 99999,
        }))
        .unwrap();
        assert_eq!(v.aud, "hub");
    }
}

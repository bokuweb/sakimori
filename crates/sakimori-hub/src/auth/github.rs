//! GitHub OAuth Authorization Code Flow.
//!
//! Two responsibilities live here:
//!
//! 1. Build the `authorize` redirect URL given a freshly-minted
//!    CSRF `state` token.
//! 2. Exchange the callback `code` for an access token and pull
//!    the authenticated user's profile out of `GET /user`.
//!
//! Both surfaces are gated behind the [`OAuthExchange`] trait so
//! the handler tests don't need real network access — the test
//! suite injects a stub that returns canned responses.

use serde::Deserialize;

/// Identity returned by the GitHub `/user` endpoint that we
/// actually consume. GitHub returns *much* more than this; we
/// deliberately project to a small surface so we don't accumulate
/// fields we have no use for (privacy minimum-collection).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GitHubUser {
    pub id: i64,
    pub login: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum GitHubAuthError {
    #[error("OAuth token exchange failed: HTTP {status}: {body}")]
    TokenExchange { status: u16, body: String },
    #[error("OAuth token exchange transport error: {0}")]
    Transport(String),
    #[error("user lookup failed: HTTP {status}: {body}")]
    UserLookup { status: u16, body: String },
    #[error("user response decode: {0}")]
    Decode(String),
}

/// Pluggable shim so tests can avoid the real GitHub endpoints.
/// `code` is the value GitHub redirected with on
/// `/auth/github/callback`; the impl is responsible for hitting
/// the GitHub token endpoint, then `/user`, and returning the
/// profile.
pub trait OAuthExchange: Send + Sync {
    fn exchange_code(&self, code: &str) -> std::result::Result<GitHubUser, GitHubAuthError>;
}

/// Production [`OAuthExchange`] backed by `ureq`. Mirrors the
/// `dispatch::UreqClient` pattern (10-second timeout, explicit
/// User-Agent — GitHub's API rejects requests without one).
pub struct GitHubOAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub agent: ureq::Agent,
}

impl GitHubOAuthClient {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(concat!("sakimori-hub/", env!("CARGO_PKG_VERSION")))
                .build(),
        }
    }
}

impl OAuthExchange for GitHubOAuthClient {
    fn exchange_code(&self, code: &str) -> std::result::Result<GitHubUser, GitHubAuthError> {
        // Step 1: code -> access_token.
        let body = format!(
            "client_id={}&client_secret={}&code={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.client_secret),
            urlencoding::encode(code),
        );
        let resp = self
            .agent
            .post("https://github.com/login/oauth/access_token")
            .set("accept", "application/json")
            .set("content-type", "application/x-www-form-urlencoded")
            .send_string(&body);
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(status, r)) => {
                return Err(GitHubAuthError::TokenExchange {
                    status,
                    body: r.into_string().unwrap_or_default(),
                });
            }
            Err(e) => return Err(GitHubAuthError::Transport(e.to_string())),
        };
        #[derive(Deserialize)]
        struct TokenResp {
            access_token: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        }
        let token: TokenResp = resp
            .into_json()
            .map_err(|e| GitHubAuthError::Decode(e.to_string()))?;
        let access = match (token.access_token, token.error) {
            (Some(t), _) => t,
            (None, Some(err)) => {
                return Err(GitHubAuthError::TokenExchange {
                    status: 200,
                    body: format!("{err}: {}", token.error_description.unwrap_or_default()),
                });
            }
            _ => {
                return Err(GitHubAuthError::Decode(
                    "token response had neither access_token nor error".into(),
                ));
            }
        };
        // Step 2: access_token -> /user. Bearer auth with the user
        // access token; we never persist this token — only the
        // profile fields below.
        let resp = self
            .agent
            .get("https://api.github.com/user")
            .set("accept", "application/vnd.github+json")
            .set("authorization", &format!("Bearer {access}"))
            .call();
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(status, r)) => {
                return Err(GitHubAuthError::UserLookup {
                    status,
                    body: r.into_string().unwrap_or_default(),
                });
            }
            Err(e) => return Err(GitHubAuthError::Transport(e.to_string())),
        };
        resp.into_json::<GitHubUser>()
            .map_err(|e| GitHubAuthError::Decode(e.to_string()))
    }
}

/// Build the URL we redirect the browser to for step 1 of the
/// flow. `state` is the CSRF token the caller generated and
/// stashed in a short-lived signed cookie / server-side store.
/// `scopes` is the OAuth scope set; for read-only profile a
/// blank scope is enough (the default `read:user` is implicit on
/// /user lookup).
pub fn authorize_url(client_id: &str, redirect_uri: &str, state: &str, scopes: &[&str]) -> String {
    let mut url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
    );
    if !scopes.is_empty() {
        url.push_str(&format!(
            "&scope={}",
            urlencoding::encode(&scopes.join(" "))
        ));
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_includes_required_params() {
        let url = authorize_url(
            "abcd1234",
            "https://hub.example.com/auth/github/callback",
            "csrf-state-token",
            &["read:user"],
        );
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=abcd1234"));
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fhub.example.com%2Fauth%2Fgithub%2Fcallback")
        );
        assert!(url.contains("state=csrf-state-token"));
        assert!(url.contains("scope=read%3Auser"));
    }

    #[test]
    fn authorize_url_omits_scope_when_empty() {
        let url = authorize_url("c", "https://x/cb", "s", &[]);
        assert!(!url.contains("scope="));
    }

    #[test]
    fn authorize_url_url_encodes_unsafe_characters() {
        let url = authorize_url("a&b=c", "https://x/cb?x=1", "s/t", &["a b"]);
        assert!(url.contains("client_id=a%26b%3Dc"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fx%2Fcb%3Fx%3D1"));
        assert!(url.contains("state=s%2Ft"));
        assert!(url.contains("scope=a%20b"));
    }

    #[test]
    fn github_user_decodes_minimum_shape() {
        let v: GitHubUser = serde_json::from_value(serde_json::json!({
            "id": 42,
            "login": "ada",
        }))
        .unwrap();
        assert_eq!(v.login, "ada");
        assert!(v.name.is_none());
    }

    #[test]
    fn github_user_ignores_unmodelled_fields() {
        let v: GitHubUser = serde_json::from_value(serde_json::json!({
            "id": 1,
            "login": "x",
            "email": "ignored@example.com",
            "company": "ignored",
            "twitter_username": "ignored",
        }))
        .unwrap();
        assert_eq!(v.id, 1);
    }
}

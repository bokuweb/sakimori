//! Session cookies for browser-authenticated users.
//!
//! ## Wire shape
//!
//! ```text
//! Set-Cookie: sakimori_hub_session=<base64url(token)>.<base64url(hmac)>;
//!     HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<seconds>
//! ```
//!
//! The cookie value is `<token>.<hmac>` where:
//!
//! - `token` is 32 random bytes, base64url-encoded (43 chars).
//!   The DB row stores SHA-256 of `token`, never the cleartext —
//!   so a DB dump can't impersonate a live user, only revoke them.
//! - `hmac` is HMAC-SHA256(server_secret, token) truncated to
//!   16 bytes (128 bits), base64url-encoded. A forged or modified
//!   cookie fails the signature check before any DB lookup, so the
//!   token-hash index never sees attacker-controlled values.
//!
//! Why HMAC on top of the random-token-with-DB-hash pattern? Two
//! reasons:
//!
//! 1. Rejects garbage at the edge — typo'd cookies, expired
//!    `Secure` flag transitions, etc. — without one DB round-trip
//!    per request.
//! 2. Lets us rotate the server secret to invalidate every live
//!    session instantly (e.g. after a suspected compromise),
//!    without a `DELETE FROM sessions`.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE_NAME: &str = "sakimori_hub_session";
const TOKEN_LEN: usize = 32;
const HMAC_TRUNC_LEN: usize = 16;

/// A freshly-minted session token. The `cookie_value` is what
/// gets sent in `Set-Cookie`; the `token_hash` is what gets
/// inserted into `sessions.token_hash`. They never leave this
/// struct together except via the matching pair returned by
/// [`mint_session_token`].
#[derive(Debug)]
pub struct SessionToken {
    pub cookie_value: String,
    pub token_hash: [u8; 32],
}

/// A cookie value that's been signature-checked and split back
/// into its components.
#[derive(Debug)]
pub struct SessionCookie {
    pub token_hash: [u8; 32],
}

/// Generate 32 random bytes, base64url-encode them, sign with
/// the server secret, and return both the cookie value (token +
/// signature, joined with `.`) and the SHA-256 of the token for
/// the DB row.
pub fn mint_session_token(server_secret: &[u8]) -> SessionToken {
    let mut raw = [0u8; TOKEN_LEN];
    rand::thread_rng().fill_bytes(&mut raw);
    let token_b64 = URL_SAFE_NO_PAD.encode(raw);
    let sig = sign(server_secret, token_b64.as_bytes());
    let cookie_value = format!("{token_b64}.{sig}");
    let mut h = Sha256::new();
    h.update(token_b64.as_bytes());
    let token_hash: [u8; 32] = h.finalize().into();
    SessionToken {
        cookie_value,
        token_hash,
    }
}

/// Verify the HMAC, then return the SHA-256 token hash so the
/// caller can look the session up. `None` for any
/// shape/signature failure — the caller treats every failure
/// uniformly as "no session", so an attacker can't distinguish
/// "bad signature" from "expired" from "revoked" via response
/// timing/wording.
pub fn verify_cookie(server_secret: &[u8], cookie_value: &str) -> Option<SessionCookie> {
    let (token, sig) = cookie_value.split_once('.')?;
    // Length-check before constant-time compare so a stupendously
    // wrong cookie shape doesn't drag in a 64-byte CT loop.
    let expected_sig = sign(server_secret, token.as_bytes());
    if sig.len() != expected_sig.len() {
        return None;
    }
    if !bool::from(sig.as_bytes().ct_eq(expected_sig.as_bytes())) {
        return None;
    }
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let token_hash: [u8; 32] = h.finalize().into();
    Some(SessionCookie { token_hash })
}

/// Standalone helper for callers that already have the cleartext
/// token (e.g. the freshly-minted one) and want to recompute the
/// row hash without going through cookie parsing.
pub fn hash_session_token(cookie_token_part: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cookie_token_part.as_bytes());
    h.finalize().into()
}

/// HMAC-SHA256 truncated to [`HMAC_TRUNC_LEN`] bytes,
/// base64url-encoded. 128 bits is enough to make forgery
/// infeasible at the per-request budget while keeping the cookie
/// compact.
pub fn sign(server_secret: &[u8], body: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("hmac accepts any key length");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&tag[..HMAC_TRUNC_LEN])
}

/// Build the `Set-Cookie` value for [`SESSION_COOKIE_NAME`].
/// `secure` flips the `Secure` flag — set `false` only for local
/// loopback testing, every production deploy must keep it `true`.
pub fn build_set_cookie(value: &str, max_age_secs: i64, secure: bool) -> Result<String> {
    if value.contains([';', '\r', '\n']) {
        anyhow::bail!("session cookie value contained a control character");
    }
    let mut s = format!(
        "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
    );
    if secure {
        s.push_str("; Secure");
    }
    Ok(s)
}

/// `Set-Cookie` value that clears the session client-side. The
/// server should also revoke the DB row in the same handler.
pub fn build_clear_cookie(secure: bool) -> String {
    let mut s = format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        s.push_str("; Secure");
    }
    s
}

/// Pull `SESSION_COOKIE_NAME` out of a `Cookie:` header value.
/// We do the parsing ourselves rather than pulling in
/// `tower-cookies` because the surface is one cookie and the
/// `Cookie` header is just `;`-separated `name=value` pairs.
pub fn extract_session_cookie(cookie_header: &str) -> Option<&str> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minted_cookie_verifies() {
        let secret = b"server-secret-1234567890abcdef";
        let t = mint_session_token(secret);
        let parsed = verify_cookie(secret, &t.cookie_value).expect("must verify");
        assert_eq!(parsed.token_hash, t.token_hash);
    }

    #[test]
    fn cookie_with_wrong_secret_rejects() {
        let t = mint_session_token(b"server-secret-1234567890abcdef");
        assert!(verify_cookie(b"wrong-secret-doesntmatch", &t.cookie_value).is_none());
    }

    #[test]
    fn tampered_token_rejects() {
        let secret = b"server-secret-1234567890abcdef";
        let t = mint_session_token(secret);
        // Flip one char of the token portion; signature should fail.
        let (token, sig) = t.cookie_value.split_once('.').unwrap();
        let mut chars: Vec<char> = token.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", chars.into_iter().collect::<String>(), sig);
        assert!(verify_cookie(secret, &tampered).is_none());
    }

    #[test]
    fn tampered_signature_rejects() {
        let secret = b"server-secret-1234567890abcdef";
        let t = mint_session_token(secret);
        let (token, sig) = t.cookie_value.split_once('.').unwrap();
        let mut sig_chars: Vec<char> = sig.chars().collect();
        sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", token, sig_chars.into_iter().collect::<String>());
        assert!(verify_cookie(secret, &tampered).is_none());
    }

    #[test]
    fn cookie_without_dot_rejects() {
        assert!(verify_cookie(b"k1234567890abcdef", "no-dot-anywhere").is_none());
    }

    #[test]
    fn extract_finds_named_cookie_among_many() {
        let h = "foo=bar; sakimori_hub_session=abc.def; baz=qux";
        assert_eq!(extract_session_cookie(h), Some("abc.def"));
    }

    #[test]
    fn extract_returns_none_when_missing() {
        assert!(extract_session_cookie("foo=bar; baz=qux").is_none());
    }

    #[test]
    fn build_set_cookie_rejects_control_chars() {
        // Defence in depth — every caller should be passing a
        // value from `mint_session_token`, but if a buggy caller
        // ever passes user-controlled bytes we must not let CRLF
        // through (header injection).
        assert!(build_set_cookie("evil\r\nLocation: http://x/", 60, true).is_err());
        // `;` in value would prematurely close the cookie and let an
        // attacker append attributes like `Domain=evil.example`.
        assert!(build_set_cookie("ok;Domain=evil", 60, true).is_err());
        let v = mint_session_token(b"secret-1234567890abcdef").cookie_value;
        assert!(build_set_cookie(&v, 60, true).is_ok());
    }

    #[test]
    fn set_cookie_includes_secure_only_when_requested() {
        let v = "abc.def";
        assert!(build_set_cookie(v, 60, true).unwrap().contains("; Secure"));
        assert!(!build_set_cookie(v, 60, false).unwrap().contains("; Secure"));
    }

    #[test]
    fn clear_cookie_uses_max_age_zero() {
        assert!(build_clear_cookie(true).contains("Max-Age=0"));
    }

    #[test]
    fn hash_helper_matches_mint() {
        let secret = b"server-secret-1234567890abcdef";
        let t = mint_session_token(secret);
        let token_part = t.cookie_value.split_once('.').unwrap().0;
        assert_eq!(hash_session_token(token_part), t.token_hash);
    }
}

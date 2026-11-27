//! Opt-in `sakimori-hub` ingest exporter.
//!
//! Parallel to [`crate::otlp::OtlpExporter`]: every allowed install
//! also fires a fire-and-forget POST against a self-hosted hub's
//! `/v1/{team}/_team|_user|{project}/events` endpoint. The hub side
//! is documented in `bokuweb/sakimori-hub` —
//! `packages/schemas/src/install-event.ts` is the source of truth
//! for the wire shape this module produces.
//!
//! Wire format:
//! - Method: `POST`
//! - Headers: `Authorization: Bearer <token>`, `Content-Type:
//!   application/json`, `User-Agent: <proxy ua>`
//! - Body: a JSON array (`InstallEventBatch`) of `InstallEvent`
//!   objects matching the valibot schema, with `v: 1` injected.
//!
//! Best-effort: any failure (no env, hub down, 5xx, schema reject)
//! is a `log::warn!` and never blocks the install path. The token
//! is held in [`HubIngestExporter`] with a custom [`Debug`] that
//! redacts the bytes so a stray `{:?}` in logs cannot leak it.
//!
//! Schema mapping is opinionated:
//! - `crates` ecosystem (the sakimori-core label) is rewritten to
//!   `cargo` (the hub schema label).
//! - `vscode-extension` (sakimori-core label) is rewritten to
//!   `vscode` (the hub schema label, as of sakimori-hub PR #87).
//!   Other ecosystems pass through unchanged.
//! - `git` is NOT supported by the hub schema today; events for
//!   that ecosystem are dropped before POST rather than producing
//!   a 400 the operator has to debug.
//! - `user_agent` is required by the hub schema but optional on
//!   the local `InstallEvent`; when absent we substitute the proxy
//!   user-agent so the wire payload is always valid.

use std::sync::Arc;

use anyhow::Result;
use serde_json::{Value, json};

use sakimori_core::installs::{ExecutionMode, InstallEvent};

/// Best-effort sakimori-hub ingest exporter. Cheap to clone via `Arc`.
pub struct HubIngestExporter {
    endpoint: String,
    /// Bearer credential. Never logged; see custom `Debug` impl
    /// below.
    token: SakimoriToken,
    user_agent: String,
    access: Option<HubAccessCredentials>,
}

/// Optional Cloudflare Access service-token pair. Kept separate from
/// the Hub bearer token; an Access credential grants no Hub scope.
#[derive(Clone)]
pub struct HubAccessCredentials {
    client_id: String,
    client_secret: String,
}

impl std::fmt::Debug for HubAccessCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubAccessCredentials(<redacted>)")
    }
}

impl HubAccessCredentials {
    pub fn new(client_id: String, client_secret: String) -> Result<Self> {
        for value in [&client_id, &client_secret] {
            if value.is_empty() || value.len() > 4096 || http::HeaderValue::from_str(value).is_err()
            {
                anyhow::bail!(
                    "Access credentials must be nonempty valid HTTP header values (max 4096 bytes)"
                );
            }
        }
        Ok(Self {
            client_id,
            client_secret,
        })
    }
}

/// Service credentials require HTTPS, except for loopback-only test workers.
pub fn validate_access_endpoint(endpoint: &str) -> Result<()> {
    validate_endpoint(endpoint).map_err(anyhow::Error::msg)?;
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid Access endpoint"))?;
    let loopback = uri.host().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if uri.scheme_str() != Some("https") && !(uri.scheme_str() == Some("http") && loopback) {
        anyhow::bail!("Access credentials require an HTTPS Hub endpoint");
    }
    Ok(())
}

/// Bearer token wrapper. Sole purpose: keep the plaintext out of
/// any accidental `{:?}` output. The hub validates this against
/// an argon2id hash on every request; we never compare it on the
/// CLI side, so no `Eq` / constant-time-compare surface here.
#[derive(Clone)]
pub struct SakimoriToken(String);

impl SakimoriToken {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    fn as_bearer_value(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl std::fmt::Debug for SakimoriToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Surface non-emptiness only; never the bytes.
        write!(f, "SakimoriToken(<redacted, {} bytes>)", self.0.len())
    }
}

/// Reject endpoints that aren't safe to POST a bearer token to.
///
/// - Scheme must be `http` or `https`.
/// - Userinfo (`user:pass@host`) is rejected — credentials in
///   URL would clash with the Authorization header and tend to
///   show up in logs / shell history.
/// - Control chars (CR/LF/NUL/…) are rejected — they'd let the
///   env value forge log lines (codex round-1 low/medium).
///
/// Returns the input unchanged on success. Diagnostic strings
/// are constants (no echo of the bad URL) so this function is
/// itself safe to use in a startup log.
pub fn validate_endpoint(endpoint: &str) -> Result<(), &'static str> {
    if endpoint.is_empty() {
        return Err("hub ingest URL is empty");
    }
    if endpoint.chars().any(|c| c.is_control()) {
        return Err("hub ingest URL contains control characters");
    }
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or("hub ingest URL must be http:// or https://")?;
    if !matches!(scheme, "http" | "https") {
        return Err("hub ingest URL must be http:// or https://");
    }
    // The hostport segment ends at the first `/`, `?`, or `#`.
    let host_segment = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host_segment.contains('@') {
        return Err("hub ingest URL must not embed userinfo (user:pass@host)");
    }
    if host_segment.is_empty() {
        return Err("hub ingest URL is missing a host");
    }
    Ok(())
}

impl HubIngestExporter {
    pub fn new(endpoint: String, token: SakimoriToken, user_agent: String) -> Self {
        Self {
            endpoint,
            token,
            user_agent,
            access: None,
        }
    }

    pub fn with_access(mut self, access: HubAccessCredentials) -> Result<Self> {
        validate_access_endpoint(&self.endpoint)?;
        self.access = Some(access);
        Ok(self)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build the `InstallEventBatch` JSON for a single event, or
    /// `None` if the event's ecosystem is unsupported by the hub
    /// (`git`). `crates` and `vscode-extension` are rewritten to
    /// the hub-spelled `cargo` / `vscode` labels.
    ///
    /// Public so unit tests can pin the wire shape without
    /// spinning up the proxy.
    pub fn build_payload(&self, event: &InstallEvent) -> Option<Value> {
        let wire = build_wire_event(event, &self.user_agent)?;
        Some(json!([wire]))
    }

    /// Fire-and-forget dispatch. Returns immediately; the actual
    /// HTTP POST runs on a `spawn_blocking` worker. Failure is
    /// logged at `warn` level. Drops the event silently when the
    /// ecosystem can't be expressed on the hub schema (so the
    /// proxy doesn't spam warnings for `git:` deps).
    pub fn dispatch(self: &Arc<Self>, event: &InstallEvent) {
        let Some(batch) = self.build_payload(event) else {
            return;
        };
        let endpoint = self.endpoint.clone();
        let auth = self.token.as_bearer_value();
        let ua = self.user_agent.clone();
        let access = self.access.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = post_hub_with_access(&endpoint, &auth, &ua, &batch, access.as_ref()) {
                // The endpoint is non-secret and useful for triage.
                // `e` carries the HTTP status / ureq error
                // message — never the bearer value, which is held
                // only in `auth` (a local), so a `{e:#}` is safe.
                // Sanitize the URL: an attacker-controlled env
                // could inject CR/LF to forge log lines.
                let endpoint_safe = sanitize_for_log(&endpoint);
                log::warn!("hub ingest POST to {endpoint_safe} failed: {e:#}");
            }
        });
    }
}

#[cfg(test)]
fn post_hub(endpoint: &str, authorization: &str, user_agent: &str, body: &Value) -> Result<()> {
    post_hub_with_access(endpoint, authorization, user_agent, body, None)
}

fn post_hub_with_access(
    endpoint: &str,
    authorization: &str,
    user_agent: &str,
    body: &Value,
    access: Option<&HubAccessCredentials>,
) -> Result<()> {
    use std::io::Read;
    // An Access login page is not an ingest acknowledgement. Never
    // follow redirects with credentials, even to the same origin.
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut request = agent
        .post(endpoint)
        .set("authorization", authorization)
        .set("content-type", "application/json")
        .set("user-agent", user_agent)
        // Per-batch provenance the hub records as columns on
        // install_events / audit_events (migration 0013). Each
        // header is loose-validated server-side; a malformed
        // value drops the column but never 4xx's the batch.
        .set("x-sakimori-os", HUB_PROVENANCE_OS)
        .set("x-sakimori-arch", HUB_PROVENANCE_ARCH)
        .set("x-sakimori-agent-version", HUB_PROVENANCE_AGENT_VERSION)
        .timeout(std::time::Duration::from_millis(3000));
    if let Some(access) = access {
        validate_access_endpoint(endpoint)?;
        request = request
            .set("CF-Access-Client-Id", &access.client_id)
            .set("CF-Access-Client-Secret", &access.client_secret);
    }
    let resp = request.send_json(body.clone()).map_err(|err| match err {
        ureq::Error::Status(status, _) => anyhow::anyhow!("hub endpoint returned {status}"),
        ureq::Error::Transport(err) => anyhow::anyhow!("hub transport failed ({:?})", err.kind()),
    })?;
    let status = resp.status();
    if status != 202 {
        anyhow::bail!(
            "hub endpoint returned {status}; expected an ingest 202 receipt (check endpoint and Access authentication)"
        );
    }
    if !resp.header("content-type").is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
    }) {
        anyhow::bail!(
            "hub receipt is not application/json; check endpoint and Access authentication"
        );
    }
    const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("could not read hub receipt"))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        anyhow::bail!("hub receipt exceeds size limit");
    }
    #[derive(serde::Deserialize)]
    struct Receipt {
        accepted: usize,
        rejected: Vec<Value>,
    }
    let receipt: Receipt = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("hub receipt has an invalid schema"))?;
    let sent = body.as_array().map_or(0, Vec::len);
    if sent == 0 || receipt.accepted != sent || !receipt.rejected.is_empty() {
        anyhow::bail!(
            "hub did not accept the complete batch (sent={sent}, accepted={}, rejected={})",
            receipt.accepted,
            receipt.rejected.len()
        );
    }
    Ok(())
}

/// OS string the hub accepts (closed allowlist: `linux` / `macos`
/// / `windows`). Resolved at compile time from `cfg!(target_os)`
/// so a Linux build always reports `linux`, a Darwin build always
/// reports `macos`, etc. Unknown targets emit an empty string —
/// the hub treats that as "no header" and lands the row with
/// NULL, which is correct (we don't want to lie about the OS).
#[cfg(target_os = "linux")]
const HUB_PROVENANCE_OS: &str = "linux";
#[cfg(target_os = "macos")]
const HUB_PROVENANCE_OS: &str = "macos";
#[cfg(target_os = "windows")]
const HUB_PROVENANCE_OS: &str = "windows";
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const HUB_PROVENANCE_OS: &str = "";

/// Architecture string the hub accepts (`x86_64` / `aarch64`).
/// macOS reports `arm64` from rustc — the hub aliases that to
/// `aarch64`, but we emit the canonical form here.
#[cfg(target_arch = "x86_64")]
const HUB_PROVENANCE_ARCH: &str = "x86_64";
#[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
const HUB_PROVENANCE_ARCH: &str = "aarch64";
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec"
)))]
const HUB_PROVENANCE_ARCH: &str = "";

/// The crate version, set at compile time by Cargo.
const HUB_PROVENANCE_AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn build_wire_event(event: &InstallEvent, fallback_user_agent: &str) -> Option<Value> {
    let ecosystem = map_ecosystem(&event.ecosystem)?;
    let mode_str = match event.execution_mode {
        ExecutionMode::Persistent => "persistent",
        ExecutionMode::Ephemeral => "ephemeral",
        ExecutionMode::Unknown => "unknown",
    };
    // Hub schema requires `user_agent` as a non-empty string (up
    // to 512 chars). Local event leaves it optional; substitute
    // the proxy UA when absent so the wire is always valid.
    let user_agent = event
        .user_agent
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_user_agent);
    // Hub schema caps user_agent at 512 bytes; truncate at the
    // last UTF-8 char boundary inside that budget. A naive
    // `&s[..512]` would panic on multi-byte sequences (codex
    // round-1 medium finding).
    const CI_MARKER: &str = " ci=github-actions";
    let user_agent = if fallback_user_agent.contains("ci=github-actions") {
        format!(
            "{}{}",
            truncate_on_char_boundary(user_agent, 512 - CI_MARKER.len()),
            CI_MARKER
        )
    } else {
        truncate_on_char_boundary(user_agent, 512).to_string()
    };

    let mut obj = serde_json::Map::new();
    obj.insert("v".into(), Value::from(1u8));
    obj.insert("ecosystem".into(), Value::from(ecosystem));
    obj.insert("name".into(), Value::from(event.name.clone()));
    obj.insert("version".into(), Value::from(event.version.clone()));
    obj.insert(
        "resolved_at".into(),
        Value::from(event.resolved_at.to_rfc3339()),
    );
    obj.insert("execution_mode".into(), Value::from(mode_str));
    obj.insert("user_agent".into(), Value::from(user_agent.to_string()));
    if let Some(p) = event.project_path.as_deref() {
        // Hub schema caps project_path at 1024 bytes. Mirror the
        // user_agent truncation so a long CI workspace path
        // (e.g. nested runner home dir) doesn't 400 the whole
        // batch (codex round-1 medium finding).
        let p = truncate_on_char_boundary(p, 1024);
        obj.insert("project_path".into(), Value::from(p.to_string()));
    }
    Some(Value::Object(obj))
}

/// Return `s` truncated to at most `max_bytes`, never splitting a
/// UTF-8 multi-byte sequence. Walks back from the cap to the last
/// boundary so the result is always valid UTF-8.
fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Replace control chars that could be used to forge log lines
/// (newline, carriage return, NUL, …) with `?`. Used wherever an
/// operator-supplied env value (URL, etc.) is interpolated into a
/// `log::*!` macro (codex round-1 low/medium finding).
fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn map_ecosystem(local_label: &str) -> Option<&'static str> {
    match local_label {
        "npm" => Some("npm"),
        // sakimori-core's `Crates.label() == "crates"`; the hub
        // schema spells it `cargo`. Rewrite here so the operator
        // doesn't get a confusing 400.
        "crates" => Some("cargo"),
        "pypi" => Some("pypi"),
        "nuget" => Some("nuget"),
        // Same shape as the `crates`→`cargo` rewrite: sakimori-core
        // emits the longer `vscode-extension`, hub PR #87 accepts
        // the shorter `vscode`. Keep the rename pinned here so a
        // future enum label change can't silently desync.
        "vscode-extension" => Some("vscode"),
        // `git` has no hub-schema equivalent and is deliberately
        // dropped. Returning None lets dispatch skip the event
        // silently instead of producing a 400.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use sakimori_core::deps::Ecosystem;

    fn post_with_response(status: u16, content_type: &str, response: &str) -> Result<()> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/events", listener.local_addr().unwrap());
        let reply = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len(),
        );
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            let len: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            socket.read_exact(&mut vec![0; len]).unwrap();
            socket.write_all(reply.as_bytes()).unwrap();
        });
        let result = post_hub(&endpoint, "Bearer test", "test", &json!([{"v": 1}]));
        server.join().unwrap();
        result
    }

    #[test]
    fn hub_delivery_requires_a_complete_202_json_receipt() {
        assert!(
            post_with_response(
                202,
                "application/json; charset=utf-8",
                r#"{"accepted":1,"rejected":[]}"#
            )
            .is_ok()
        );
        for (status, content_type, body) in [
            (200, "text/html", "<html>Login</html>"),
            (202, "text/html", r#"{"accepted":1,"rejected":[]}"#),
            (202, "application/json", "not JSON"),
            (
                202,
                "application/json",
                r#"{"accepted":0,"rejected":[{"index":0,"reason":"bad event"}]}"#,
            ),
            (202, "application/json", r#"{"accepted":0,"rejected":[]}"#),
            (202, "application/json", r#"{"accepted":2,"rejected":[]}"#),
            (202, "application/json", r#"{"accepted":1}"#),
        ] {
            assert!(
                post_with_response(status, content_type, body).is_err(),
                "status={status}, type={content_type}"
            );
        }
    }

    #[test]
    fn hub_delivery_bounds_receipt_size_and_does_not_echo_its_body() {
        let secret_body = format!("credential-secret{}", "x".repeat(70_000));
        let err = post_with_response(202, "application/json", &secret_body).unwrap_err();
        assert!(!format!("{err:#}").contains("credential-secret"));
    }

    #[test]
    fn access_headers_reject_injection_and_remote_cleartext() {
        for (id, secret) in [
            ("", "secret"),
            ("id", ""),
            ("id\r\nInjected: 1", "secret"),
            ("id", "secret\n"),
        ] {
            assert!(HubAccessCredentials::new(id.into(), secret.into()).is_err());
        }
        assert!(HubAccessCredentials::new("id".into(), "x".repeat(4097)).is_err());
        assert!(validate_access_endpoint("https://hub.example/events").is_ok());
        assert!(validate_access_endpoint("http://hub.example/events").is_err());
        assert!(validate_access_endpoint("http://localhost.evil.example/events").is_err());
        assert!(validate_access_endpoint("http://127.0.0.1:8787/events").is_ok());
        assert!(validate_access_endpoint("http://[::1]:8787/events").is_ok());
    }

    #[test]
    fn redirect_is_rejected_without_contacting_the_login_target() {
        use std::io::{Read, Write};
        let login = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let login_url = format!("http://{}/login", login.local_addr().unwrap());
        login.set_nonblocking(true).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/events", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut byte = [0];
            while !bytes.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
            }
            let headers = String::from_utf8(bytes).unwrap();
            let len: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            socket.read_exact(&mut vec![0; len]).unwrap();
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {login_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(reply.as_bytes()).unwrap();
        });
        let result = post_hub(&endpoint, "Bearer test", "test", &json!([{"v":1}]));
        server.join().unwrap();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("302"), "{err}");
        assert!(matches!(login.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }

    fn sample_event() -> InstallEvent {
        let mut ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")
            .with_mode(ExecutionMode::Persistent)
            .with_user_agent("npm/10.0.0 node/20.0.0");
        ev.resolved_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        ev
    }

    #[test]
    fn payload_is_a_one_event_batch_with_v1() {
        let exp = HubIngestExporter::new(
            "https://hub.example/v1/acme/_team/events".into(),
            SakimoriToken::new("skm_team_x"),
            "sakimori-test/0".into(),
        );
        let p = exp.build_payload(&sample_event()).expect("npm event");
        let arr = p.as_array().expect("batch must be a JSON array");
        assert_eq!(arr.len(), 1, "one event in, one event out");
        let ev = &arr[0];
        assert_eq!(ev["v"], 1);
        assert_eq!(ev["ecosystem"], "npm");
        assert_eq!(ev["name"], "left-pad");
        assert_eq!(ev["version"], "1.3.0");
        assert_eq!(ev["resolved_at"], "2026-01-02T03:04:05+00:00");
        assert_eq!(ev["execution_mode"], "persistent");
        assert_eq!(ev["user_agent"], "npm/10.0.0 node/20.0.0");
        assert!(ev.get("project_path").is_none(), "absent path is absent");
    }

    #[test]
    fn cratesio_ecosystem_is_rewritten_to_cargo() {
        // Hub schema uses `cargo`; sakimori-core spells it `crates`.
        // The rewriter is the only place that knows the mapping —
        // pin it so a future enum rename doesn't silently break the
        // wire.
        let exp = HubIngestExporter::new("http://x".into(), SakimoriToken::new("t"), "ua".into());
        let mut ev = sample_event();
        ev.ecosystem = Ecosystem::Crates.label().to_string();
        ev.name = "serde".into();
        let p = exp.build_payload(&ev).expect("crates event accepted");
        assert_eq!(p[0]["ecosystem"], "cargo");
    }

    #[test]
    fn vscode_extension_ecosystem_is_rewritten_to_vscode() {
        // Hub schema (sakimori-hub PR #87) accepts the shorter
        // `vscode` label; sakimori-core's
        // `Ecosystem::VscodeExtension.label()` is the longer
        // `vscode-extension`. The rewriter is the only place
        // that knows the mapping — pin it so the wire stays
        // round-trippable with the hub's valibot picklist.
        let exp = HubIngestExporter::new("http://x".into(), SakimoriToken::new("t"), "ua".into());
        let mut ev = sample_event();
        ev.ecosystem = Ecosystem::VscodeExtension.label().to_string();
        ev.name = "ms-python.python".into();
        ev.version = "2026.4.0".into();
        let p = exp
            .build_payload(&ev)
            .expect("vscode-extension event accepted");
        assert_eq!(p[0]["ecosystem"], "vscode");
        assert_eq!(p[0]["name"], "ms-python.python");
    }

    #[test]
    fn unsupported_ecosystems_are_dropped() {
        // `git` has no hub-schema equivalent and is deliberately
        // dropped. Returning None here lets dispatch drop the
        // event silently instead of producing a 400 the operator
        // has to debug.
        let exp = HubIngestExporter::new("http://x".into(), SakimoriToken::new("t"), "ua".into());
        for label in ["git", "rubygems"] {
            let mut ev = sample_event();
            ev.ecosystem = label.to_string();
            assert!(
                exp.build_payload(&ev).is_none(),
                "ecosystem={label} must be dropped from the wire",
            );
        }
    }

    #[test]
    fn missing_user_agent_falls_back_to_proxy_ua() {
        // Hub schema requires user_agent. Local InstallEvent
        // makes it optional. The exporter substitutes the proxy
        // UA so the wire is always valid.
        let exp = HubIngestExporter::new(
            "http://x".into(),
            SakimoriToken::new("t"),
            "sakimori-proxy/0.9.9".into(),
        );
        let mut ev = sample_event();
        ev.user_agent = None;
        let p = exp.build_payload(&ev).unwrap();
        assert_eq!(p[0]["user_agent"], "sakimori-proxy/0.9.9");
    }

    #[test]
    fn ci_marker_survives_a_real_package_manager_user_agent() {
        let exp = HubIngestExporter::new(
            "http://x".into(),
            SakimoriToken::new("t"),
            "sakimori-proxy/test ci=github-actions".into(),
        );
        let payload = exp.build_payload(&sample_event()).unwrap();
        assert_eq!(
            payload[0]["user_agent"],
            "npm/10.0.0 node/20.0.0 ci=github-actions"
        );
        let mut long = sample_event();
        long.user_agent = Some("あ".repeat(300));
        let payload = exp.build_payload(&long).unwrap();
        let ua = payload[0]["user_agent"].as_str().unwrap();
        assert!(ua.len() <= 512);
        assert!(ua.ends_with(" ci=github-actions"));
    }

    #[test]
    fn long_user_agent_is_truncated_to_512_chars() {
        // Hub schema caps user_agent at 512; an oversize value
        // would 400 the whole batch. Truncate defensively so a
        // pathological UA can't poison the ingest path.
        let exp = HubIngestExporter::new(
            "http://x".into(),
            SakimoriToken::new("t"),
            "fallback".into(),
        );
        let mut ev = sample_event();
        ev.user_agent = Some("x".repeat(600));
        let p = exp.build_payload(&ev).unwrap();
        let ua = p[0]["user_agent"].as_str().unwrap();
        assert_eq!(ua.len(), 512);
    }

    #[test]
    fn project_path_is_serialised_when_present() {
        let exp = HubIngestExporter::new("http://x".into(), SakimoriToken::new("t"), "ua".into());
        let mut ev = sample_event();
        ev.project_path = Some("/home/octocat/repo".into());
        let p = exp.build_payload(&ev).unwrap();
        assert_eq!(p[0]["project_path"], "/home/octocat/repo");
    }

    #[test]
    fn token_debug_redacts_plaintext() {
        // A stray {:?} in logs must never leak the token bytes.
        // Pin the redaction so a future refactor that derives
        // Debug on `SakimoriToken` breaks this test loudly.
        let tok = SakimoriToken::new("skm_team_supersecretvaluewith43chars1234567");
        let printed = format!("{tok:?}");
        assert!(!printed.contains("supersecret"), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
    }

    #[test]
    fn long_non_ascii_user_agent_does_not_panic() {
        // Codex round-1 medium: a naive `&s[..512]` panics on a
        // multi-byte char boundary. Pin the safe truncation by
        // throwing a UA that's all 3-byte UTF-8 codepoints.
        let exp = HubIngestExporter::new(
            "http://x".into(),
            SakimoriToken::new("t"),
            "fallback".into(),
        );
        let mut ev = sample_event();
        // 300 × 'あ' (3 bytes each) = 900 bytes — well over 512.
        ev.user_agent = Some("あ".repeat(300));
        let p = exp.build_payload(&ev).unwrap();
        let ua = p[0]["user_agent"].as_str().unwrap();
        assert!(ua.len() <= 512, "ua exceeded cap: {} bytes", ua.len());
        // Truncation must land on a char boundary — the result
        // is still valid UTF-8 (the test asserts on a `str` via
        // `as_str()`, which is itself the proof).
        assert!(ua.chars().all(|c| c == 'あ'));
    }

    #[test]
    fn long_project_path_is_truncated() {
        // Codex round-1 medium: hub caps project_path at 1024.
        let exp = HubIngestExporter::new("http://x".into(), SakimoriToken::new("t"), "ua".into());
        let mut ev = sample_event();
        ev.project_path = Some("a".repeat(2000));
        let p = exp.build_payload(&ev).unwrap();
        let path = p[0]["project_path"].as_str().unwrap();
        assert_eq!(path.len(), 1024);
    }

    #[test]
    fn endpoint_validation_accepts_http_and_https_hosts() {
        assert!(validate_endpoint("http://hub.example/v1/acme/_team/events").is_ok());
        assert!(validate_endpoint("https://hub.example/v1/acme/_team/events").is_ok());
        assert!(validate_endpoint("https://127.0.0.1:8787/v1/acme/_team/events").is_ok());
    }

    #[test]
    fn endpoint_validation_rejects_unsafe_inputs() {
        // Pin the rejected classes. Each `expect_err` is a
        // single assertion so a regression points at the exact
        // bypass.
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("ftp://hub.example/").is_err());
        assert!(validate_endpoint("file:///etc/passwd").is_err());
        // Embedded userinfo: would clash with Authorization
        // header and tends to leak via shell history.
        assert!(validate_endpoint("http://user:pass@hub.example/v1/x").is_err());
        // Control characters — log-injection vector.
        assert!(validate_endpoint("http://hub.example/v1\r\nX-Inj: bad").is_err());
        assert!(validate_endpoint("http://hub.example/\nfoo").is_err());
        // Missing host.
        assert!(validate_endpoint("http:///v1/x").is_err());
    }

    #[test]
    fn sanitize_for_log_neutralises_control_chars() {
        assert_eq!(sanitize_for_log("hub.example/foo"), "hub.example/foo");
        assert_eq!(sanitize_for_log("hub\r\nX-Inj"), "hub??X-Inj");
        assert_eq!(sanitize_for_log("hub\0foo"), "hub?foo");
    }

    #[test]
    fn execution_mode_unknown_serialises_as_unknown() {
        let exp = HubIngestExporter::new("http://x".into(), SakimoriToken::new("t"), "ua".into());
        let mut ev = sample_event();
        ev.execution_mode = ExecutionMode::Unknown;
        let p = exp.build_payload(&ev).unwrap();
        assert_eq!(p[0]["execution_mode"], "unknown");
    }
}

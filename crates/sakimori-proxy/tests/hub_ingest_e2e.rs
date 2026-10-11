//! End-to-end check for the sakimori-hub ingest exporter.
//!
//! Unit tests in `src/hub_ingest.rs::tests` pin the payload
//! shape; this file pins the *wire surface*: HTTP method, path,
//! Authorization header, Content-Type, and body parse against
//! the hub schema. A regression where the dispatcher silently
//! stopped posting (e.g. spawn_blocking task panicked, ureq
//! timeout misconfigured) would pass the unit tests and silently
//! drop every install — exactly the failure mode this file
//! catches.
//!
//! We bypass the full proxy harness here on purpose: spinning up
//! hudsucker + a mock npm tarball is the OTLP e2e's job. What we
//! want at this layer is "the exporter dispatch dispatches".

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use sakimori_core::deps::Ecosystem;
use sakimori_core::installs::{ExecutionMode, InstallEvent};
use sakimori_proxy::hub_ingest::{HubAccessCredentials, HubIngestExporter, SakimoriToken};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Minimal HTTP/1.1 capturing server. Returns a valid 202 receipt on every
/// request and stores the raw bytes (request line + headers +
/// body) in a shared Vec for assertions.
async fn spawn_capturing_http_server() -> (std::net::SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let records: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let r2 = records.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let records = r2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(8 * 1024);
                let mut tmp = [0u8; 4096];
                let hdr_end = loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break pos + 4;
                            }
                            if buf.len() > 256 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                };
                let header_str = std::str::from_utf8(&buf[..hdr_end]).unwrap_or("");
                let content_len = header_str
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.splitn(2, ':');
                        let k = parts.next()?.trim();
                        let v = parts.next()?.trim();
                        if k.eq_ignore_ascii_case("content-length") {
                            v.parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                while buf.len() - hdr_end < content_len {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                {
                    let mut g = records.lock().unwrap();
                    g.push(buf.clone());
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: 28\r\nConnection: close\r\n\r\n{\"accepted\":1,\"rejected\":[]}")
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, records)
}

/// Redact the bearer token before printing headers in an
/// assertion failure — CI logs can become artifacts and we don't
/// want the token bytes copied around even from a test.
/// (Codex round-1 nit.)
fn redact_auth(headers: &str) -> String {
    headers
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if [
                "authorization:",
                "cf-access-client-id:",
                "cf-access-client-secret:",
            ]
            .iter()
            .any(|name| trimmed.to_ascii_lowercase().starts_with(name))
            {
                "Authorization: <redacted>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn split_request(captured: &[u8]) -> (String, Vec<u8>) {
    let pos = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("captured request must have end-of-headers");
    let headers = String::from_utf8_lossy(&captured[..pos]).to_string();
    let body = captured[pos + 4..].to_vec();
    (headers, body)
}

fn sample_event() -> InstallEvent {
    let mut ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")
        .with_mode(ExecutionMode::Persistent)
        .with_user_agent("npm/10.0.0 node/20.0.0")
        .with_project_path("/work/repo");
    ev.resolved_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&Utc);
    ev
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_posts_to_configured_endpoint_with_bearer() {
    // Mark `_now` unused — we don't currently inspect timestamps
    // beyond what the payload carries.
    let _ = SystemTime::now().duration_since(UNIX_EPOCH);
    let (addr, captured) = spawn_capturing_http_server().await;
    let endpoint = format!("http://{addr}/v1/acme/_team/events");
    let exporter = Arc::new(HubIngestExporter::new(
        endpoint.clone(),
        SakimoriToken::new("skm_team_supersecretvaluewith43chars1234567"),
        "sakimori-proxy/test".into(),
    ));

    exporter.dispatch(&sample_event());

    // dispatch is spawn_blocking; poll up to ~3s for the request
    // to land. Lock is taken in a tight scope to satisfy
    // clippy::await_holding_lock.
    let cap = {
        let mut last = None;
        for _ in 0..60 {
            let snap = {
                let g = captured.lock().unwrap();
                if g.is_empty() { None } else { Some(g.clone()) }
            };
            if let Some(s) = snap {
                last = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        last.expect("exporter must POST within 3s of dispatch")
    };
    assert_eq!(cap.len(), 1, "exactly one POST per dispatch");
    let (headers, body) = split_request(&cap[0]);

    assert!(
        headers.starts_with("POST /v1/acme/_team/events HTTP/1.1\r\n"),
        "hub ingest must POST to the configured path; got:\n{redacted_headers}",
        redacted_headers = redact_auth(&headers)
    );
    let lc_headers = headers.to_ascii_lowercase();
    assert!(
        lc_headers.contains("authorization: bearer skm_team_supersecretvaluewith43chars1234567"),
        "Authorization header must carry the Bearer token; got:\n{redacted_headers}",
        redacted_headers = redact_auth(&headers)
    );
    assert!(
        lc_headers.contains("content-type: application/json"),
        "hub ingest body must be JSON; got:\n{redacted_headers}",
        redacted_headers = redact_auth(&headers)
    );
    assert!(
        lc_headers.contains("user-agent: sakimori-proxy/test"),
        "User-Agent must match the configured proxy UA; got:\n{redacted_headers}",
        redacted_headers = redact_auth(&headers)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&body).expect("body must parse as JSON");
    let arr = payload.as_array().expect("body must be a JSON array");
    assert_eq!(arr.len(), 1, "one event per single-event dispatch");
    let ev = &arr[0];
    assert_eq!(ev["v"], 1);
    assert_eq!(ev["ecosystem"], "npm");
    assert_eq!(ev["name"], "left-pad");
    assert_eq!(ev["version"], "1.3.0");
    assert_eq!(ev["execution_mode"], "persistent");
    assert_eq!(ev["user_agent"], "npm/10.0.0 node/20.0.0");
    assert_eq!(ev["project_path"], "/work/repo");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_drops_unsupported_ecosystem_silently() {
    // `git` deps never reach the hub — the exporter drops them
    // before posting so the operator doesn't see 400s. Pin that
    // contract: zero requests must arrive at the mock server.
    let (addr, captured) = spawn_capturing_http_server().await;
    let exporter = Arc::new(HubIngestExporter::new(
        format!("http://{addr}/v1/acme/_team/events"),
        SakimoriToken::new("skm_team_x"),
        "ua".into(),
    ));
    let mut ev = sample_event();
    ev.ecosystem = Ecosystem::Git.label().to_string();
    exporter.dispatch(&ev);

    // Wait briefly to make sure no request lands.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let g = captured.lock().unwrap();
    assert!(
        g.is_empty(),
        "git ecosystem must not produce a POST; got {} request(s)",
        g.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_credentials_are_separate_headers_and_ci_reaches_the_payload() {
    let (addr, captured) = spawn_capturing_http_server().await;
    let access =
        HubAccessCredentials::new("access-test-id".into(), "access-test-secret".into()).unwrap();
    assert!(!format!("{access:?}").contains("access-test-secret"));
    let exporter = Arc::new(
        HubIngestExporter::new(
            format!("http://{addr}/v1/acme/_team/events"),
            SakimoriToken::new("hub-test-token"),
            "sakimori-test ci=github-actions".into(),
        )
        .with_access(access)
        .unwrap(),
    );
    exporter.dispatch(&sample_event());
    let record = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let record = captured.lock().unwrap().first().cloned();
            if let Some(record) = record {
                break record;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let (headers, body) = split_request(&record);
    let headers = headers.to_ascii_lowercase();
    assert!(headers.contains("cf-access-client-id: access-test-id"));
    assert!(headers.contains("cf-access-client-secret: access-test-secret"));
    assert!(headers.contains("authorization: bearer hub-test-token"));
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        payload[0]["user_agent"]
            .as_str()
            .unwrap()
            .ends_with(" ci=github-actions")
    );
}

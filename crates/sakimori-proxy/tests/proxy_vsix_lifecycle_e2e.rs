//! End-to-end: `.vsix` lifecycle gate exercised through the proxy.
//!
//!   client ── HTTP_PROXY ── sakimori_proxy ── upstream (vsix bytes)
//!
//! Builds a synthetic `.vsix` (zip with `extension/package.json`),
//! serves it from a mock upstream on a path matching the canonical
//! Marketplace `vspackage` URL shape, and asserts:
//!
//! 1. Startup-autorun extension (`activationEvents: ["*"]`) under
//!    `lifecycle_policy: Block` returns 403 with the
//!    `x-sakimori-deny: lifecycle-vsix` header.
//! 2. Lazy-activation extension (`activationEvents: ["onCommand:…"]`)
//!    flows through untouched.
//! 3. Startup-autorun extension on the lifecycle allow-list flows
//!    through untouched (canonical `publisher.name` identifier).
//!
//! Unit tests in `vsix_inspect.rs` cover the inspector's algorithmic
//! branches; this file covers the full hyper / hudsucker request
//! lifecycle dispatch.

use std::io::{Cursor, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sakimori_proxy::{ProxyConfig, RegistryHosts, ca::CaFiles};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use zip::write::SimpleFileOptions;

fn tmp_config_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "sakimori-vsix-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

fn build_vsix(manifest_json: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zw.start_file("[Content_Types].xml", opts).unwrap();
        zw.write_all(b"<types/>").unwrap();
        zw.start_file("extension/package.json", opts).unwrap();
        zw.write_all(manifest_json.as_bytes()).unwrap();
        zw.finish().unwrap();
    }
    buf
}

async fn spawn_mock_upstream(
    response_body: Vec<u8>,
    content_type: &'static str,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(response_body);
    let ct = content_type.to_string();
    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let body = body.clone();
            let ct = ct.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(2048);
                let mut tmp = [0u8; 1024];
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                            if buf.len() > 64 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

async fn spawn_proxy(cfg_mutator: impl FnOnce(&mut ProxyConfig)) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = tmp_config_dir("proxy");
    std::fs::create_dir_all(&config_dir).unwrap();
    let ca_files = CaFiles::at(config_dir);

    let mut cfg = ProxyConfig::default_dev().unwrap();
    cfg.listen = addr;
    cfg.ca_files = ca_files;
    cfg.install_log_enabled = false;
    cfg.registries = RegistryHosts {
        vscode_marketplace: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    cfg.lifecycle_policy = Some(sakimori_proxy::lifecycle::LifecyclePolicy::Block);
    cfg_mutator(&mut cfg);

    tokio::spawn(async move {
        if let Err(e) = sakimori_proxy::run(cfg).await {
            eprintln!("proxy exited: {e:#}");
        }
    });

    let ready = Arc::new(Notify::new());
    let ready2 = ready.clone();
    tokio::spawn(async move {
        for _ in 0..150 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready2.notify_one();
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    tokio::time::timeout(Duration::from_secs(5), ready.notified())
        .await
        .expect("proxy never came up");
    addr
}

/// GET through the proxy and return (status, response body, the
/// `x-sakimori-deny` header if present).
fn http_get_through_proxy(
    proxy: std::net::SocketAddr,
    target_url: &str,
) -> (u16, Vec<u8>, Option<String>) {
    let proxy_spec = format!("http://{proxy}");
    let agent = ureq::AgentBuilder::new()
        .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
        .timeout(Duration::from_secs(10))
        .build();
    let resp = match agent.get(target_url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("client GET through proxy: {e}"),
    };
    let status = resp.status();
    let deny = resp.header("x-sakimori-deny").map(str::to_string);
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(4 * 1024 * 1024)
        .read_to_end(&mut buf)
        .unwrap();
    (status, buf, deny)
}

const VSPACKAGE_PATH: &str =
    "/_apis/public/gallery/publishers/attacker/vsextensions/evil-ext/1.0.0/vspackage";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vsix_with_wildcard_activation_blocked() {
    let vsix = build_vsix(
        r#"{
            "name": "evil-ext",
            "publisher": "attacker",
            "version": "1.0.0",
            "main": "./out/extension.js",
            "activationEvents": ["*"]
        }"#,
    );
    let upstream = spawn_mock_upstream(vsix, "application/octet-stream").await;
    let proxy = spawn_proxy(|_| {}).await;

    let url = format!("http://{upstream}{VSPACKAGE_PATH}");
    let (status, _body, deny) =
        tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
            .await
            .unwrap();
    assert_eq!(status, 403);
    assert_eq!(deny.as_deref(), Some("lifecycle-vsix"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vsix_with_lazy_activation_passes_through() {
    let vsix = build_vsix(
        r#"{
            "name": "ok-ext",
            "publisher": "trusted",
            "version": "1.0.0",
            "activationEvents": ["onCommand:foo.bar", "onLanguage:rust"]
        }"#,
    );
    let upstream = spawn_mock_upstream(vsix.clone(), "application/octet-stream").await;
    let proxy = spawn_proxy(|_| {}).await;

    let url = format!(
        "http://{upstream}/_apis/public/gallery/publishers/trusted/vsextensions/ok-ext/1.0.0/vspackage"
    );
    let (status, body, deny) =
        tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
            .await
            .unwrap();
    assert_eq!(status, 200);
    assert!(
        deny.is_none(),
        "lazy-activation extension should not be blocked"
    );
    assert_eq!(body, vsix, "body should be the unmodified vsix bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vsix_install_is_logged_with_publisher_dot_name_identity() {
    // Roadmap #22: every `.vsix` fetched through the proxy lands in
    // `installs.jsonl` with `ecosystem: vscode-extension` and name =
    // canonical `publisher.extension`. This holds regardless of
    // lifecycle policy — the inventory needs to be complete so a
    // post-hoc CVE scan covers what was actually installed.
    let vsix = build_vsix(
        r#"{
            "name": "ok-ext",
            "publisher": "trusted",
            "version": "2.5.0",
            "activationEvents": ["onCommand:foo.bar"]
        }"#,
    );
    let upstream = spawn_mock_upstream(vsix, "application/octet-stream").await;

    let log_dir = tmp_config_dir("installog");
    std::fs::create_dir_all(&log_dir).unwrap();
    let log_path = log_dir.join("installs.jsonl");
    let log_path_for_cfg = log_path.clone();
    let proxy = spawn_proxy(move |cfg| {
        cfg.lifecycle_policy = None;
        cfg.install_log_enabled = true;
        cfg.install_log_path = Some(log_path_for_cfg);
    })
    .await;

    let url = format!(
        "http://{upstream}/_apis/public/gallery/publishers/trusted/vsextensions/ok-ext/2.5.0/vspackage"
    );
    let (status, _body, _deny) =
        tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
            .await
            .unwrap();
    assert_eq!(status, 200);

    // Give the proxy a beat to flush; the logger writes synchronously
    // but the response runs on another task.
    for _ in 0..50 {
        if log_path.exists() && std::fs::metadata(&log_path).unwrap().len() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let raw = std::fs::read_to_string(&log_path).expect("install log was written");
    let line = raw.lines().next().expect("at least one log line");
    let ev: serde_json::Value = serde_json::from_str(line).expect("log line is valid JSON");
    assert_eq!(ev["ecosystem"], "vscode-extension");
    assert_eq!(ev["name"], "trusted.ok-ext");
    assert_eq!(ev["version"], "2.5.0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vsix_on_lifecycle_allow_list_bypasses_block() {
    // Same wildcard manifest as the block test, but the
    // `publisher.name` is on the allow-list, so the gate must not
    // fire.
    let vsix = build_vsix(
        r#"{
            "name": "evil-ext",
            "publisher": "attacker",
            "version": "1.0.0",
            "activationEvents": ["*"]
        }"#,
    );
    let upstream = spawn_mock_upstream(vsix.clone(), "application/octet-stream").await;
    let proxy = spawn_proxy(|cfg| {
        cfg.lifecycle_allow.push("attacker.evil-ext".into());
    })
    .await;

    let url = format!("http://{upstream}{VSPACKAGE_PATH}");
    let (status, body, deny) =
        tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
            .await
            .unwrap();
    assert_eq!(status, 200);
    assert!(deny.is_none());
    assert_eq!(body, vsix);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vsix_reaches_hub_when_local_logging_is_disabled() {
    let vsix = build_vsix(
        r#"{"name":"ok-ext","publisher":"trusted","version":"2.5.0","activationEvents":["onCommand:foo.bar"]}"#,
    );
    let upstream = spawn_mock_upstream(vsix, "application/octet-stream").await;
    let hub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/events", hub.local_addr().unwrap());
    let (send, receive) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut sock, _) = hub.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            sock.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let headers = String::from_utf8(request).unwrap();
        let len: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        let mut body = vec![0; len];
        sock.read_exact(&mut body).await.unwrap();
        sock.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: 28\r\nConnection: close\r\n\r\n{\"accepted\":1,\"rejected\":[]}").await.unwrap();
        send.send(body).unwrap();
    });
    let proxy = spawn_proxy(move |cfg| {
        cfg.lifecycle_policy = None;
        cfg.hub_ingest_endpoint = Some(endpoint);
        cfg.hub_ingest_token = Some(sakimori_proxy::hub_ingest::SakimoriToken::new("test"));
    })
    .await;
    let url = format!(
        "http://{upstream}/_apis/public/gallery/publishers/trusted/vsextensions/ok-ext/2.5.0/vspackage"
    );
    let (status, _, _) = tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
        .await
        .unwrap();
    assert_eq!(status, 200);
    let body = tokio::time::timeout(Duration::from_secs(3), receive)
        .await
        .expect("VSIX never reached Hub")
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(events[0]["ecosystem"], "vscode");
    assert_eq!(events[0]["name"], "trusted.ok-ext");
    assert_eq!(events[0]["version"], "2.5.0");
}

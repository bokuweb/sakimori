//! Real-network end-to-end with **HTTPS upstream**.
//!
//! Companion to `proxy_http_e2e.rs`. The HTTP file covers the
//! plain-HTTP forwarding path. This file covers the TLS path that
//! production npm / cargo / pip traffic actually uses: a CONNECT
//! tunnel, hudsucker MITM with a leaf cert signed by the proxy's
//! own CA, an HTTPS handshake against the upstream, and the npm
//! packument rewriter still firing on the streamed body.
//!
//! Why a feature lives here too: the test depends on the proxy
//! being willing to trust a self-signed upstream. That's also a
//! genuine production gap (Verdaccio / Artifactory / GitHub
//! Packages internal / Takumi Guard behind a private CA), so this
//! PR also lands `ProxyConfig.extra_upstream_roots` + the
//! `--upstream-ca-file` CLI flag. The two tests below double as
//! load-bearing checks for that feature:
//!
//! - **positive**: with the extra root configured, the npm
//!   packument is rewritten as expected.
//! - **negative**: with no extra root, the same self-signed
//!   upstream produces an upstream-failure status. Proves the
//!   field is actually consulted (a regression that always
//!   trusts self-signed upstreams would silently pass the
//!   positive test).
//!
//! Plan reviewed + approved by Codex (3 rounds).

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hudsucker::rustls as hud_rustls;
use sakimori_proxy::ca::CaFiles;
use sakimori_proxy::{ProxyConfig, RegistryHosts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// `spawn_proxy` must release its ephemeral-port reservation before
// hudsucker binds the same address. Serialise the two tests in this
// binary so they cannot claim each other's briefly-unbound port.
static PROXY_PORT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "sakimori-https-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// rcgen-generated self-signed cert + key for `127.0.0.1`. Returns
/// (PEM cert path, DER cert bytes, DER key bytes). The PEM path is
/// what gets handed to `--upstream-ca-file`; the DER halves are
/// what tokio-rustls needs to configure the mock upstream.
struct SelfSigned {
    cert_pem_path: std::path::PathBuf,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn generate_self_signed_for_loopback(tag: &str) -> SelfSigned {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "sakimori-test-upstream");
    params.subject_alt_names = vec![
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::DnsName("localhost".try_into().unwrap()),
    ];
    // Make the cert valid for the next year, starting yesterday
    // so wall-clock drift can't bite us.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    // Leaf-only cert (no CA); self-signed via `params.self_signed`.
    params.is_ca = IsCa::NoCa;

    let key = KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key).expect("rcgen self-signed cert");

    let dir = tmp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let cert_pem_path = dir.join("upstream-ca.pem");
    std::fs::write(&cert_pem_path, cert.pem()).unwrap();
    SelfSigned {
        cert_pem_path,
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

/// Spawn a TLS mock upstream on a random `127.0.0.1` port that
/// serves the given JSON body for every request. Uses
/// `tokio-rustls 0.26` + `hudsucker::rustls` (0.23) so the cert
/// types match the proxy side.
async fn spawn_mock_tls_upstream(cert: &SelfSigned, body: Vec<u8>) -> std::net::SocketAddr {
    use hud_rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_chain = vec![CertificateDer::from(cert.cert_der.clone())];
    let key =
        PrivateKeyDer::try_from(cert.key_der.clone()).expect("PrivateKeyDer accepts PKCS#8 DER");

    let server_config = hud_rustls::ServerConfig::builder_with_provider(Arc::new(
        hud_rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .expect("rustls server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let acc = acceptor.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(sock).await else {
                    return;
                };
                // Read the request until end-of-headers.
                let mut buf = Vec::with_capacity(2048);
                let mut tmp = [0u8; 1024];
                loop {
                    match tls.read(&mut tmp).await {
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
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// Start `sakimori_proxy::run` on a random port. Returns
/// `(proxy_addr, proxy_ca_pem_path)` — the second piece is what
/// the test client must trust for the MITM leaf certs.
async fn spawn_proxy(
    extra_upstream_roots: Vec<std::path::PathBuf>,
    npm_hosts: Vec<String>,
) -> (std::net::SocketAddr, std::path::PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = tmp_dir("proxy");
    std::fs::create_dir_all(&config_dir).unwrap();
    // `CaFiles` is not Clone, so build it twice — once for the
    // ProxyConfig and once for the return value the test client
    // needs to point at.
    let ca_pem_path = CaFiles::at(config_dir.clone()).cert_pem;

    let mut cfg = ProxyConfig::default_dev().unwrap();
    cfg.listen = addr;
    cfg.min_age = Duration::from_secs(30 * 86_400);
    cfg.ca_files = CaFiles::at(config_dir);
    cfg.install_log_enabled = false;
    cfg.registries = RegistryHosts {
        npm: npm_hosts,
        ..RegistryHosts::default()
    };
    cfg.extra_upstream_roots = extra_upstream_roots;

    tokio::spawn(async move {
        if let Err(e) = sakimori_proxy::run(cfg).await {
            eprintln!("proxy exited: {e:#}");
        }
    });

    // Wait for the listener.
    let ready = Arc::new(Notify::new());
    let ready2 = ready.clone();
    tokio::spawn(async move {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready2.notify_one();
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    tokio::time::timeout(Duration::from_secs(6), ready.notified())
        .await
        .expect("proxy did not come up");

    (addr, ca_pem_path)
}

/// Synchronous HTTPS GET through `proxy_addr`, trusting only the
/// MITM CA at `proxy_ca_pem`. The connector accepts any name in
/// the leaf cert because hudsucker re-signs upstream names with
/// the proxy CA, so the leaf's SAN exactly matches `target_url`'s
/// host.
fn https_get_through_proxy(
    proxy_addr: std::net::SocketAddr,
    proxy_ca_pem: &std::path::Path,
    target_url: &str,
) -> Result<(u16, Vec<u8>), String> {
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let pem_bytes = std::fs::read(proxy_ca_pem).map_err(|e| e.to_string())?;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem_bytes) {
        let cert = cert.map_err(|e| e.to_string())?;
        roots.add(cert).map_err(|e| e.to_string())?;
    }

    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();

    let proxy_spec = format!("http://{proxy_addr}");
    let agent = ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls))
        .proxy(ureq::Proxy::new(&proxy_spec).map_err(|e| e.to_string())?)
        .timeout(Duration::from_secs(10))
        .build();

    match agent.get(target_url).call() {
        Ok(r) => {
            let status = r.status();
            let mut buf = Vec::new();
            use std::io::Read;
            r.into_reader()
                .take(4 * 1024 * 1024)
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            Ok((status, buf))
        }
        Err(ureq::Error::Status(code, r)) => {
            let mut buf = Vec::new();
            use std::io::Read;
            let _ = r.into_reader().take(4 * 1024 * 1024).read_to_end(&mut buf);
            Ok((code, buf))
        }
        Err(other) => Err(format!("transport:{other:?}")),
    }
}

fn synthetic_packument() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": "demo",
        "dist-tags": { "latest": "1.0.1" },
        "versions": {
            "1.0.0": { "name": "demo", "version": "1.0.0", "dist": {} },
            "1.0.1": { "name": "demo", "version": "1.0.1", "dist": {} },
        },
        "time": {
            "1.0.0": "2025-12-15T00:00:00Z",
            "1.0.1": (chrono::Utc::now() - chrono::Duration::days(5))
                .to_rfc3339(),
        }
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_packument_rewritten_when_upstream_ca_is_trusted() {
    let _port_guard = PROXY_PORT_LOCK.lock().await;

    // Use `localhost` (DnsName SAN) rather than `127.0.0.1` (IP
    // SAN) because hudsucker's per-host MITM leaf-signer issues
    // certificates with a DnsName SAN derived from the CONNECT
    // target — rustls 0.23 rejects an IP-literal client request
    // against a DnsName SAN. `localhost` OS-resolves to
    // 127.0.0.1 so the upstream and the proxy still find each
    // other.
    let cert = generate_self_signed_for_loopback("ca-pos");
    let upstream = spawn_mock_tls_upstream(&cert, synthetic_packument()).await;

    let (proxy_addr, proxy_ca_pem) =
        spawn_proxy(vec![cert.cert_pem_path.clone()], vec!["localhost".into()]).await;

    let url = format!("https://localhost:{}/demo", upstream.port());
    let (status, body) = tokio::task::spawn_blocking(move || {
        https_get_through_proxy(proxy_addr, &proxy_ca_pem, &url)
    })
    .await
    .unwrap()
    .expect("HTTPS GET should succeed when extra root is trusted");

    assert_eq!(
        status,
        200,
        "expected 200 OK, body: {:?}",
        std::str::from_utf8(&body).unwrap_or("<binary>")
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("body should be valid JSON");
    let versions = parsed["versions"].as_object().unwrap();
    assert!(versions.contains_key("1.0.0"));
    assert!(
        !versions.contains_key("1.0.1"),
        "young version must be dropped over HTTPS too"
    );
    assert_eq!(parsed["dist-tags"]["latest"], "1.0.0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_upstream_handshake_fails_without_extra_root() {
    let _port_guard = PROXY_PORT_LOCK.lock().await;

    let cert = generate_self_signed_for_loopback("ca-neg");
    let upstream = spawn_mock_tls_upstream(&cert, synthetic_packument()).await;

    // Same setup as the positive test, MINUS the
    // `extra_upstream_roots` argument. The self-signed upstream
    // cert isn't in webpki-roots, so the proxy's handshake to the
    // upstream must fail.
    let (proxy_addr, proxy_ca_pem) = spawn_proxy(vec![], vec!["localhost".into()]).await;

    let url = format!("https://localhost:{}/demo", upstream.port());
    let (status, _body) = tokio::task::spawn_blocking(move || {
        https_get_through_proxy(proxy_addr, &proxy_ca_pem, &url)
    })
    .await
    .unwrap()
    .expect("HTTPS GET should return an upstream-failure status, not a transport error");

    // Hudsucker maps an upstream handshake failure to a 5xx
    // bad-gateway-ish response. We don't pin the exact code
    // because the error chain wording is unstable across rustls
    // versions; the 5xx-shape assertion is what matters: the
    // client never gets the upstream's body because the proxy
    // couldn't trust the upstream cert.
    assert!(
        (500..=599).contains(&status),
        "expected 5xx upstream-failure status when extra root is missing, got {status}"
    );
}

// Silence "unused import" on Write if a future refactor stops
// needing it — the helper currently does use `tls.write_all`.
#[allow(dead_code)]
fn _ensure_imports_used() -> std::io::Result<()> {
    let mut sink = std::io::sink();
    sink.write_all(b"")?;
    Ok(())
}

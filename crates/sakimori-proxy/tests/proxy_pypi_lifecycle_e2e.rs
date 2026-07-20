//! PyPI sdist lifecycle gate, end-to-end via HTTPS.
//!
//! Companion to `proxy_lifecycle_e2e.rs` (which covers the npm
//! side). The PyPI side has its own threat model — `setup.py` in
//! an sdist is the legacy installer hook that pip runs with
//! user-level privileges, same shape as npm's `postinstall`. Block
//! mode 403s those fetches; Audit logs but passes through; Strip
//! falls back to Block on PyPI because `setup.py` removal breaks
//! most legacy-backend installs (documented in CLAUDE.md
//! roadmap #15).
//!
//! Unit tests in `lifecycle.rs::tests` exercise `inspect_pypi_sdist`
//! in isolation. This file proves the proxy's PyPI gate fires
//! correctly when an actual sdist is fetched over the wire:
//! the host must be on `pypi_files`, the URL must end in
//! `.tar.gz`/`.tgz`/`.zip`, the body must be a real gzipped tar,
//! `setup.py` must be at exactly the right depth.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use hudsucker::rustls as hud_rustls;
use sakimori_proxy::ca::CaFiles;
use sakimori_proxy::lifecycle::LifecyclePolicy;
use sakimori_proxy::{ProxyConfig, RegistryHosts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Sdist fixtures
// ---------------------------------------------------------------------------

/// Build an sdist `<name>-<version>.tar.gz` with the requested
/// top-level entries under a single root directory (PyPI sdist
/// convention).
fn build_sdist(name: &str, version: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let root = format!("{name}-{version}");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (rel, body) in files {
            let path = format!("{root}/{rel}");
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, &path, *body).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

/// Legacy sdist: ships `setup.py`. Block mode must 403.
fn sdist_with_setup_py() -> Vec<u8> {
    build_sdist(
        "demopkg",
        "1.0.0",
        &[
            (
                "setup.py",
                b"from setuptools import setup\nsetup(name='demopkg')\n",
            ),
            (
                "PKG-INFO",
                b"Metadata-Version: 2.1\nName: demopkg\nVersion: 1.0.0\n",
            ),
        ],
    )
}

/// Modern sdist: only `pyproject.toml`, no `setup.py`. The block
/// path must NOT fire — backend-name denylisting is intentionally
/// not implemented (would false-positive on every Hatch/Maturin
/// package).
fn sdist_pyproject_only() -> Vec<u8> {
    let pyproject =
        b"[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n";
    build_sdist(
        "demopkg",
        "1.0.0",
        &[
            ("pyproject.toml", pyproject),
            (
                "PKG-INFO",
                b"Metadata-Version: 2.1\nName: demopkg\nVersion: 1.0.0\n",
            ),
        ],
    )
}

// ---------------------------------------------------------------------------
// TLS harness (same shape as proxy_lifecycle_e2e.rs)
// ---------------------------------------------------------------------------

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sakimori-pypi-e2e-{tag}-{}-{nanos}-{seq}",
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
        .push(DnType::CommonName, "sakimori-test-pypi");
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

async fn spawn_mock_sdist_upstream(cert: &SelfSigned, body: Vec<u8>) -> std::net::SocketAddr {
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

async fn spawn_proxy_for_pypi(
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
        pypi_files: vec!["localhost".into()],
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
    match agent.get(url).call() {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pypi_block_403s_sdist_with_setup_py() {
    let cert = self_signed_for_localhost("ca-block");
    let upstream = spawn_mock_sdist_upstream(&cert, sdist_with_setup_py()).await;
    let (proxy_addr, ca_pem) = spawn_proxy_for_pypi(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Block),
    )
    .await;

    let url = format!(
        "https://localhost:{}/packages/aa/bb/cc/demopkg-1.0.0.tar.gz",
        upstream.port()
    );
    let (status, _body, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("block mode returns 403, not a transport error");

    assert_eq!(status, 403, "block must 403 on setup.py-shipping sdist");
    assert_eq!(
        deny.as_deref(),
        Some("lifecycle-script"),
        "block must set x-sakimori-deny: lifecycle-script, got {deny:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pypi_block_lets_modern_pyproject_only_sdist_through() {
    let cert = self_signed_for_localhost("ca-modern");
    let body = sdist_pyproject_only();
    let upstream = spawn_mock_sdist_upstream(&cert, body.clone()).await;
    let (proxy_addr, ca_pem) = spawn_proxy_for_pypi(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Block),
    )
    .await;

    let url = format!(
        "https://localhost:{}/packages/aa/bb/cc/demopkg-1.0.0.tar.gz",
        upstream.port()
    );
    let (status, got, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("modern-backend sdist must serve cleanly under block");

    assert_eq!(status, 200, "modern PEP 517 sdist must not be blocked");
    assert!(deny.is_none(), "no deny header on a clean sdist");
    assert_eq!(
        got, body,
        "modern sdist body must be byte-identical (no rewrite path on PyPI)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pypi_audit_lets_setup_py_sdist_through_with_no_deny_header() {
    let cert = self_signed_for_localhost("ca-audit");
    let body = sdist_with_setup_py();
    let upstream = spawn_mock_sdist_upstream(&cert, body.clone()).await;
    let (proxy_addr, ca_pem) = spawn_proxy_for_pypi(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Audit),
    )
    .await;

    let url = format!(
        "https://localhost:{}/packages/aa/bb/cc/demopkg-1.0.0.tar.gz",
        upstream.port()
    );
    let (status, got, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("audit mode passes the sdist through");

    assert_eq!(status, 200);
    assert!(
        deny.is_none(),
        "audit mode must not block, got deny={deny:?}"
    );
    assert_eq!(
        got, body,
        "audit mode must pass the sdist through byte-for-byte"
    );
}

// Wheels (`.whl`) carry no install-time hook surface; the proxy
// must not tag them for inspection even when they happen to ship
// from a configured pypi_files host. Pins the documented contract
// in proxy.rs:1001-1005 (`path_is_pypi_sdist` excludes `.whl`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pypi_block_does_not_touch_wheels() {
    // Wheel bytes are opaque to the test — we just need them to
    // *not* be tagged for inspection. A non-tarball body suffices
    // since the lifecycle gate would only fire on a Pinned tagged
    // entry, and `.whl` paths aren't tagged.
    let cert = self_signed_for_localhost("ca-wheel");
    let opaque = b"PK\x03\x04 this is not really a wheel but should pass anyway".to_vec();
    let upstream = spawn_mock_sdist_upstream(&cert, opaque.clone()).await;
    let (proxy_addr, ca_pem) = spawn_proxy_for_pypi(
        vec![cert.cert_pem_path.clone()],
        Some(LifecyclePolicy::Block),
    )
    .await;

    let url = format!(
        "https://localhost:{}/packages/aa/bb/cc/demopkg-1.0.0-py3-none-any.whl",
        upstream.port()
    );
    let (status, got, deny) =
        tokio::task::spawn_blocking(move || https_get(proxy_addr, &ca_pem, &url))
            .await
            .unwrap()
            .expect("wheel must pass through");

    assert_eq!(status, 200);
    assert!(
        deny.is_none(),
        "wheels must not be inspected, got deny={deny:?}"
    );
    assert_eq!(got, opaque, "wheel body must pass through byte-for-byte");
}

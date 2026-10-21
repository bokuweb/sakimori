//! Offline regression for the October 2026 eMudhra CA compromise.
//! Exercise the rustls verifier shared by the proxy and ureq clients.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

fn certificates(name: &str) -> Vec<CertificateDer<'static>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/emudhra")
        .join(name);
    let bytes = std::fs::read(path).unwrap();
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .unwrap()
}

fn verifier(roots: RootCertStore) -> Arc<WebPkiServerVerifier> {
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .unwrap()
}

fn assert_compromised_chains_rejected(roots: RootCertStore) {
    let verifier = verifier(roots);
    for kind in ["dv", "ov", "ev"] {
        for generation in ["g3b", "g3c"] {
            for cross_sign in ["", "-aaa"] {
                let hostname =
                    format!("{kind}-{generation}{cross_sign}-emudhra.we-have-a-problem.com");
                let chain = certificates(&format!("{hostname}.pem"));
                assert_eq!(chain.len(), if cross_sign.is_empty() { 3 } else { 2 });
                // Freeze time inside the fixture validity window so future
                // expiration cannot make an insecure verifier pass this test.
                let result = verifier.verify_server_cert(
                    &chain[0],
                    &chain[1..],
                    &ServerName::try_from(hostname.as_str()).unwrap(),
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(1_792_627_200)),
                );
                // Require explicit key distrust, so a
                // malformed, expired, or hostname-mismatched fixture cannot
                // hide a regression in trust handling.
                assert!(
                    format!("{result:?}").contains("CertDistrusted"),
                    "expected distrust for {hostname}, got {result:?}"
                );
            }
        }
    }
}

#[test]
fn bundled_roots_exclude_emsign_ecc_root() {
    let mut affected = RootCertStore::empty();
    affected
        .add(certificates("emSign_ECC_Root_CA_-_G3.pem").remove(0))
        .unwrap();
    assert!(
        !webpki_roots::TLS_SERVER_ROOTS.iter().any(|root| {
            root.subject_public_key_info == affected.roots[0].subject_public_key_info
        })
    );
}

#[test]
fn bundled_roots_reject_all_compromised_tls_chains() {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    assert_compromised_chains_rejected(roots);
}

#[test]
fn compromised_keys_are_rejected_even_with_explicit_upstream_roots() {
    // Model --upstream-ca-file and downstream callers with old root stores.
    // Updating only webpki-roots cannot protect these trust paths: the
    // rustls-webpki SPKI distrust list must reject the intermediates too.
    let mut roots = RootCertStore::empty();
    for name in [
        "AAA_Certificate_Services.pem",
        "emSign_ECC_Root_CA_-_G3.pem",
        "emSign_Root_TLS_CA_-_G3.pem",
    ] {
        for cert in certificates(name) {
            roots.add(cert).unwrap();
        }
    }
    assert_compromised_chains_rejected(roots);
}

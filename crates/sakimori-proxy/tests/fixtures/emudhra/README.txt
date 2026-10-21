Public certificate fixtures for the October 2026 eMudhra CA compromise.
These files contain certificates only; no private keys.

The twelve leaf-first chains were downloaded unchanged from:
https://emudhra.we-have-a-problem.com/chains.zip
Archive SHA-256: 8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95
Captured by the incident site on 2026-10-20; retrieved on 2026-10-22.
The three root PEM files were extracted from the "pem" fields in:
https://emudhra.we-have-a-problem.com/roots.json

Each dv/ov/ev and g3b/g3c combination has two chains:
  * -aaa-emudhra: leaf, compromised intermediate cross-signed by AAA.
  * -emudhra: leaf, compromised intermediate, emSign Root TLS CA - G3
    cross-signed by emSign ECC Root CA - G3.

emudhra_distrust.rs verifies all twelve at 2026-10-22 00:00:00 UTC,
both with bundled roots and with the affected roots explicitly trusted.
The latter proves SPKI distrust works even when custom roots are added.
Existing proxy_https_e2e tests cover successful TLS with a private CA.

Incident report: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449

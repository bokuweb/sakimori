//! Sigstore bundle verification — stage 1 of 2.
//!
//! # What this module does today (semantic layer)
//!
//! npm attestations API returns a Sigstore bundle per published
//! version. The bundle wraps a DSSE envelope whose payload is an
//! in-toto v1 statement. This module:
//!
//! 1. Parses the bundle JSON (both the `v0.2` and `v0.3` media types).
//! 2. Base64-decodes the DSSE payload into an in-toto statement.
//! 3. Asserts `subject[0].digest.sha512` matches the npm-reported
//!    `dist.integrity` (SHA-512 of the tarball).
//! 4. Asserts `predicateType == https://slsa.dev/provenance/v1`.
//! 5. Applies a small built-in policy on `predicate.buildDefinition`
//!    (builder id must be a recognised OIDC-backed CI).
//!
//! Catching a subject-digest mismatch alone closes a real gap: the
//! "attacker steals a publish token, publishes a malicious tarball,
//! and attaches an attestation from an unrelated build" attack. npm
//! enforces digest matching at publish time, so any mismatch we see
//! means the bundle was re-used from a different artifact.
//!
//! # What this module does NOT do yet (crypto layer — stage 2)
//!
//! - DSSE signature verification with the Fulcio-issued ephemeral key.
//! - Fulcio certificate chain validation against the Sigstore trust
//!   root.
//! - Rekor SET (Signed Entry Timestamp) / inclusion-proof verification.
//!
//! Those require embedding the Sigstore public-good trust root and
//! pulling in ECDSA + X.509 crates. Tracked as P0-1b.
//!
//! Everything here is pure (no IO) and synchronous — the proxy's
//! rewrite path calls it with an already-fetched bundle body.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha512};

/// Every failure reason the verifier can produce. Structured so the
/// proxy can bucket stats cleanly and the user sees *why* a given
/// version was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Bundle JSON didn't parse at all, or the expected fields were
    /// missing. Forwarded as "cannot trust".
    Malformed(String),
    /// DSSE payload base64 decode failed.
    PayloadDecode(String),
    /// DSSE payload wasn't a JSON in-toto statement.
    PayloadShape(String),
    /// `subject[0].digest.sha512` didn't match the tarball integrity
    /// the npm packument advertised. Strong evidence of a stolen
    /// token + reused attestation.
    SubjectDigestMismatch {
        expected_sha512_hex: String,
        actual_sha512_hex: String,
    },
    /// `predicateType` wasn't an accepted SLSA provenance URI.
    UnexpectedPredicateType(String),
    /// The builder identity doesn't match any allowlisted OIDC
    /// issuer. Configurable in a later revision; hardcoded for now.
    DisallowedBuilder(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed bundle: {m}"),
            Self::PayloadDecode(m) => write!(f, "DSSE payload base64 decode failed: {m}"),
            Self::PayloadShape(m) => write!(f, "DSSE payload shape error: {m}"),
            Self::SubjectDigestMismatch {
                expected_sha512_hex,
                actual_sha512_hex,
            } => write!(
                f,
                "subject digest mismatch: expected sha512={expected_sha512_hex}, attestation sha512={actual_sha512_hex}"
            ),
            Self::UnexpectedPredicateType(t) => write!(f, "unexpected predicateType {t}"),
            Self::DisallowedBuilder(b) => write!(f, "builder {b} not in allowlist"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Parsed, semantically-validated provenance statement. The crypto
/// layer (P0-1b) will add a `verified_by: CertIdentity` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProvenance {
    pub predicate_type: String,
    pub subject_name: String,
    pub subject_sha512_hex: String,
    pub builder_id: String,
    /// The raw in-toto statement JSON, kept so callers can surface
    /// fields without re-parsing.
    pub statement: Value,
}

/// Accepted SLSA provenance predicate types. v1 is what npm /
/// GitHub publish; v0.2 still shows up in older bundles.
const ACCEPTED_PREDICATE_TYPES: &[&str] = &[
    "https://slsa.dev/provenance/v1",
    "https://slsa.dev/provenance/v0.2",
];

/// Allowlisted `builder.id` prefixes. An attacker who manages to get
/// *some* Sigstore bundle attached to a stolen-token publish will
/// trip this unless they also control one of these CI surfaces and
/// can pass the subject-digest check — which is a much larger
/// attack than "stole an npm token".
const ALLOWED_BUILDER_PREFIXES: &[&str] = &[
    "https://github.com/actions/runner/",
    "https://github.com/slsa-framework/",
    "https://gitlab.com/",
];

/// npm attestations API returns a JSON document of this shape:
///
/// ```json
/// {
///   "attestations": [
///     { "predicateType": "...", "bundle": { …sigstore bundle… } }
///   ]
/// }
/// ```
///
/// Pick the first attestation whose `predicateType` is SLSA
/// provenance and hand back its `bundle`.
pub fn pick_slsa_bundle(attestations_body: &[u8]) -> Result<Value, VerifyError> {
    let doc: Value = serde_json::from_slice(attestations_body)
        .map_err(|e| VerifyError::Malformed(format!("attestations JSON: {e}")))?;
    let list = doc
        .get("attestations")
        .and_then(Value::as_array)
        .ok_or_else(|| VerifyError::Malformed("no `attestations` array".into()))?;
    for att in list {
        let pt = att
            .get("predicateType")
            .and_then(Value::as_str)
            .unwrap_or("");
        if ACCEPTED_PREDICATE_TYPES.contains(&pt)
            && let Some(bundle) = att.get("bundle")
        {
            return Ok(bundle.clone());
        }
    }
    Err(VerifyError::Malformed(
        "no SLSA-provenance attestation in list".into(),
    ))
}

/// Convert an npm `dist.integrity` string (`sha512-<base64>`) into the
/// hex-encoded digest. Returns None for anything we don't recognise
/// (e.g. a weaker `sha1-` prefix, which npm still emits for very old
/// packages — callers should refuse to verify those and drop them).
pub fn integrity_to_sha512_hex(integrity: &str) -> Option<String> {
    let rest = integrity.strip_prefix("sha512-")?;
    let raw = BASE64.decode(rest.as_bytes()).ok()?;
    if raw.len() != 64 {
        return None;
    }
    Some(hex_encode(&raw))
}

/// Verify a Sigstore bundle (already JSON-parsed) against the
/// expected tarball integrity claim. Returns a
/// [`VerifiedProvenance`] on success or a [`VerifyError`] variant
/// explaining what failed.
///
/// `expected_integrity` is npm's `dist.integrity` string
/// (`sha512-<base64>`); if it is missing or uses a non-sha512
/// algorithm, the caller should drop the version before reaching
/// us (we require sha512 for digest matching).
pub fn verify_bundle_semantics(
    bundle: &Value,
    expected_integrity: &str,
) -> Result<VerifiedProvenance, VerifyError> {
    let expected_hex = integrity_to_sha512_hex(expected_integrity).ok_or_else(|| {
        VerifyError::Malformed(format!(
            "unsupported or malformed dist.integrity: {expected_integrity}"
        ))
    })?;

    // Both bundle v0.2 and v0.3 place the DSSE envelope at the same
    // JSON path; only the outer `mediaType` differs.
    let dsse = bundle
        .get("dsseEnvelope")
        .ok_or_else(|| VerifyError::Malformed("bundle missing dsseEnvelope".into()))?;

    let payload_b64 = dsse
        .get("payload")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::Malformed("dsseEnvelope.payload missing".into()))?;
    let payload = BASE64
        .decode(payload_b64.as_bytes())
        .map_err(|e| VerifyError::PayloadDecode(e.to_string()))?;

    // payloadType must be in-toto. DSSE allows other types in theory;
    // for npm we expect exactly this.
    let payload_type = dsse
        .get("payloadType")
        .and_then(Value::as_str)
        .unwrap_or("");
    if payload_type != "application/vnd.in-toto+json" {
        return Err(VerifyError::PayloadShape(format!(
            "payloadType={payload_type}, expected application/vnd.in-toto+json"
        )));
    }

    let statement: Value = serde_json::from_slice(&payload)
        .map_err(|e| VerifyError::PayloadShape(format!("in-toto JSON: {e}")))?;

    let predicate_type = statement
        .get("predicateType")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::PayloadShape("no predicateType".into()))?
        .to_string();
    if !ACCEPTED_PREDICATE_TYPES.contains(&predicate_type.as_str()) {
        return Err(VerifyError::UnexpectedPredicateType(predicate_type));
    }

    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .ok_or_else(|| VerifyError::PayloadShape("no subject[]".into()))?;
    let subject = subjects
        .first()
        .ok_or_else(|| VerifyError::PayloadShape("empty subject[]".into()))?;
    let subject_name = subject
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let subject_sha512 = subject
        .get("digest")
        .and_then(|d| d.get("sha512"))
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::PayloadShape("no subject[0].digest.sha512".into()))?
        .to_lowercase();

    if subject_sha512 != expected_hex {
        return Err(VerifyError::SubjectDigestMismatch {
            expected_sha512_hex: expected_hex,
            actual_sha512_hex: subject_sha512,
        });
    }

    // Builder id. SLSA v1 path: predicate.runDetails.builder.id
    // SLSA v0.2 path: predicate.builder.id. Try both.
    let builder_id = statement
        .pointer("/predicate/runDetails/builder/id")
        .and_then(Value::as_str)
        .or_else(|| {
            statement
                .pointer("/predicate/builder/id")
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_string();
    if !ALLOWED_BUILDER_PREFIXES
        .iter()
        .any(|p| builder_id.starts_with(p))
    {
        return Err(VerifyError::DisallowedBuilder(builder_id));
    }

    Ok(VerifiedProvenance {
        predicate_type,
        subject_name,
        subject_sha512_hex: subject_sha512,
        builder_id,
        statement,
    })
}

/// Compute SHA-512 of a tarball byte slice and return the hex digest,
/// for when the caller has the actual tarball in hand (e.g. proxy
/// sees the `.tgz` response). Used by a future phase where we also
/// catch divergence between the attestation and the bytes actually
/// being served.
pub fn sha512_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha512::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Minimal typed view over the subset of the bundle we care about —
/// useful for deserialise-and-dispatch callers. Kept `pub` so the
/// crypto-layer (P0-1b) module can reuse it.
#[derive(Debug, Deserialize)]
pub struct BundleShape {
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    #[serde(rename = "dsseEnvelope")]
    pub dsse_envelope: Option<DsseEnvelope>,
    #[serde(rename = "verificationMaterial")]
    pub verification_material: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct DsseEnvelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
pub struct DsseSignature {
    pub sig: String,
    #[serde(default)]
    pub keyid: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a synthetic Sigstore bundle whose DSSE payload is a
    /// minimal in-toto v1 statement with the given subject digest
    /// and builder id. Crypto fields are stubbed — the semantic
    /// layer doesn't read them.
    fn bundle_with(
        subject_name: &str,
        subject_sha512_hex: &str,
        predicate_type: &str,
        builder_id: &str,
    ) -> Value {
        let statement = json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": subject_name,
                "digest": { "sha512": subject_sha512_hex }
            }],
            "predicateType": predicate_type,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                },
                "runDetails": {
                    "builder": { "id": builder_id }
                }
            }
        });
        let payload_b64 = BASE64.encode(serde_json::to_vec(&statement).unwrap());
        json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": { "certificate": { "rawBytes": "stub" } },
            "dsseEnvelope": {
                "payload": payload_b64,
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": "stub"}]
            }
        })
    }

    /// Byte string whose sha512 we can compute once and reuse below.
    fn known_tarball() -> &'static [u8] {
        b"sakimori-test-tarball-fixture-please-do-not-depend-on-me"
    }

    fn known_integrity() -> String {
        let hex = sha512_hex(known_tarball());
        // reverse-engineer the npm `sha512-<base64>` form.
        let raw: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        format!("sha512-{}", BASE64.encode(raw))
    }

    #[test]
    fn integrity_round_trip() {
        let integ = known_integrity();
        let hex = integrity_to_sha512_hex(&integ).unwrap();
        assert_eq!(hex, sha512_hex(known_tarball()));
    }

    #[test]
    fn integrity_rejects_sha1() {
        assert!(integrity_to_sha512_hex("sha1-abcdef").is_none());
    }

    #[test]
    fn integrity_rejects_wrong_length() {
        // sha512 base64 of 63 bytes — shorter than 64.
        let short = BASE64.encode([0u8; 63]);
        assert!(integrity_to_sha512_hex(&format!("sha512-{short}")).is_none());
    }

    #[test]
    fn verifies_happy_path() {
        let hex = sha512_hex(known_tarball());
        let bundle = bundle_with(
            "pkg:npm/foo@1.0.0",
            &hex,
            "https://slsa.dev/provenance/v1",
            "https://github.com/actions/runner/github-hosted",
        );
        let v = verify_bundle_semantics(&bundle, &known_integrity()).unwrap();
        assert_eq!(v.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(v.subject_sha512_hex, hex);
        assert!(
            v.builder_id
                .starts_with("https://github.com/actions/runner/")
        );
    }

    #[test]
    fn rejects_digest_mismatch() {
        let bundle = bundle_with(
            "pkg:npm/foo@1.0.0",
            &"aa".repeat(64), // wrong digest
            "https://slsa.dev/provenance/v1",
            "https://github.com/actions/runner/github-hosted",
        );
        let err = verify_bundle_semantics(&bundle, &known_integrity()).unwrap_err();
        match err {
            VerifyError::SubjectDigestMismatch { .. } => (),
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_predicate_type() {
        let hex = sha512_hex(known_tarball());
        let bundle = bundle_with(
            "pkg:npm/foo@1.0.0",
            &hex,
            "https://example.com/made-up/v1",
            "https://github.com/actions/runner/github-hosted",
        );
        let err = verify_bundle_semantics(&bundle, &known_integrity()).unwrap_err();
        assert!(matches!(err, VerifyError::UnexpectedPredicateType(_)));
    }

    #[test]
    fn rejects_disallowed_builder() {
        let hex = sha512_hex(known_tarball());
        let bundle = bundle_with(
            "pkg:npm/foo@1.0.0",
            &hex,
            "https://slsa.dev/provenance/v1",
            "https://evil.example.com/runner/",
        );
        let err = verify_bundle_semantics(&bundle, &known_integrity()).unwrap_err();
        assert!(matches!(err, VerifyError::DisallowedBuilder(_)));
    }

    #[test]
    fn rejects_missing_dsse_envelope() {
        let bundle = json!({"mediaType": "x", "verificationMaterial": {}});
        let err = verify_bundle_semantics(&bundle, &known_integrity()).unwrap_err();
        assert!(matches!(err, VerifyError::Malformed(_)));
    }

    #[test]
    fn rejects_wrong_payload_type() {
        let statement = json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v1"
        });
        let payload_b64 = BASE64.encode(serde_json::to_vec(&statement).unwrap());
        let bundle = json!({
            "dsseEnvelope": {
                "payload": payload_b64,
                "payloadType": "application/vnd.not-in-toto+json",
                "signatures": []
            }
        });
        let err = verify_bundle_semantics(&bundle, &known_integrity()).unwrap_err();
        assert!(matches!(err, VerifyError::PayloadShape(_)));
    }

    #[test]
    fn slsa_v0_2_builder_path_still_works() {
        // SLSA v0.2 bundles nest builder.id one level shallower.
        let hex = sha512_hex(known_tarball());
        let statement = json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "x", "digest": {"sha512": hex}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": { "id": "https://github.com/actions/runner/v1" }
            }
        });
        let payload_b64 = BASE64.encode(serde_json::to_vec(&statement).unwrap());
        let bundle = json!({
            "dsseEnvelope": {
                "payload": payload_b64,
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": "stub"}]
            }
        });
        let v = verify_bundle_semantics(&bundle, &known_integrity()).unwrap();
        assert_eq!(v.predicate_type, "https://slsa.dev/provenance/v0.2");
    }

    #[test]
    fn pick_slsa_bundle_selects_correct_entry() {
        let hex = sha512_hex(known_tarball());
        let bundle = bundle_with(
            "x",
            &hex,
            "https://slsa.dev/provenance/v1",
            "https://github.com/actions/runner/v1",
        );
        let attestations = json!({
            "attestations": [
                { "predicateType": "https://something.else/v1", "bundle": {} },
                { "predicateType": "https://slsa.dev/provenance/v1", "bundle": bundle }
            ]
        });
        let body = serde_json::to_vec(&attestations).unwrap();
        let b = pick_slsa_bundle(&body).unwrap();
        assert!(b.get("dsseEnvelope").is_some());
    }

    #[test]
    fn pick_slsa_bundle_errors_when_no_slsa() {
        let body = br#"{"attestations":[{"predicateType":"other/v1","bundle":{}}]}"#;
        assert!(pick_slsa_bundle(body).is_err());
    }
}

//! Negative PQC test vectors — integration tests that generate malformed
//! or tampered cryptographic material, persist the vectors as JSON under
//! `tmp/` (gitignored), and verify that the hybrid signature scheme rejects them.

use serde_json::json;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use std::path::PathBuf;

fn tmp_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp");
    std::fs::create_dir_all(&dir).expect("failed to create tmp/ directory");
    dir.canonicalize()
        .expect("tmp/ directory must be resolvable")
}

#[allow(clippy::cast_possible_truncation)]
fn from_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must have even length");
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
        out.push((hi << 4) | lo);
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Vector generators — each returns the JSON value AND writes the file.
// ---------------------------------------------------------------------------

/// Vector 002: valid signature, but the Ed25519 component of the public key
/// has a corrupted byte, so the ownership proof is broken.
fn generate_and_write_vector_002() -> serde_json::Value {
    let scheme = HybridEd25519MlDsa;
    let (pk, sk) = scheme.keypair_generate().unwrap();
    let message = b"shekyl-pqc-v3-test-vector-002-tampered-ownership";
    let sig = scheme.sign(&sk, message).unwrap();

    // Canonical public-key layout:
    //   [0] version  [1] scheme  [2..3] reserved
    //   [4..7] ed25519_len  [8..39] ed25519 bytes
    //   [40..43] ml_dsa_len  [44..] ml_dsa bytes
    let mut pk_bytes = pk.to_canonical_bytes().unwrap();
    pk_bytes[8] ^= 0x01; // flip one bit of the ed25519 public key

    let sig_bytes = sig.to_canonical_bytes().unwrap();

    let vector = json!({
        "scheme": "ed25519_ml_dsa_65",
        "message_utf8": std::str::from_utf8(message).unwrap(),
        "message_hex": to_hex(message),
        "hybrid_public_key_hex": to_hex(&pk_bytes),
        "hybrid_signature_hex": to_hex(&sig_bytes),
        "hybrid_public_key_len": pk_bytes.len(),
        "hybrid_signature_len": sig_bytes.len(),
        "verify_result": false,
        "failure_reason": "Ed25519 public key byte 8 XOR 0x01 — corrupted ownership material"
    });

    let path = tmp_dir().join("PQC_TEST_VECTOR_002_tampered_ownership.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
    vector
}

/// Vector 003: valid key and signature, but scheme_id byte in the canonical
/// public-key encoding changed from 0x01 to 0x02.
fn generate_and_write_vector_003() -> serde_json::Value {
    let scheme = HybridEd25519MlDsa;
    let (pk, sk) = scheme.keypair_generate().unwrap();
    let message = b"shekyl-pqc-v3-test-vector-003-wrong-scheme-id";
    let sig = scheme.sign(&sk, message).unwrap();

    let mut pk_bytes = pk.to_canonical_bytes().unwrap();
    assert_eq!(pk_bytes[1], 0x01, "expected scheme_id 0x01 before mutation");
    pk_bytes[1] = 0x02;

    let sig_bytes = sig.to_canonical_bytes().unwrap();

    let vector = json!({
        "scheme": "ed25519_ml_dsa_65",
        "message_utf8": std::str::from_utf8(message).unwrap(),
        "message_hex": to_hex(message),
        "hybrid_public_key_hex": to_hex(&pk_bytes),
        "hybrid_signature_hex": to_hex(&sig_bytes),
        "hybrid_public_key_len": pk_bytes.len(),
        "hybrid_signature_len": sig_bytes.len(),
        "verify_result": false,
        "failure_reason": "scheme_id byte changed from 0x01 to 0x02 — from_canonical_bytes must reject"
    });

    let path = tmp_dir().join("PQC_TEST_VECTOR_003_wrong_scheme_id.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
    vector
}

/// Vector 004: valid header but the ML-DSA length field in the signature
/// claims 256 more bytes than actually present (truncated blob).
fn generate_and_write_vector_004() -> serde_json::Value {
    let scheme = HybridEd25519MlDsa;
    let (pk, sk) = scheme.keypair_generate().unwrap();
    let message = b"shekyl-pqc-v3-test-vector-004-oversized-blob";
    let sig = scheme.sign(&sk, message).unwrap();

    let pk_bytes = pk.to_canonical_bytes().unwrap();
    let mut sig_bytes = sig.to_canonical_bytes().unwrap();

    // Canonical signature layout:
    //   [0] version  [1] scheme  [2..3] reserved
    //   [4..7] ed25519_len (u32 LE)  [8..8+ed_len-1] ed25519 data
    //   [8+ed_len..8+ed_len+3] ml_dsa_len (u32 LE)  then ml_dsa data
    let ed_len = u32::from_le_bytes(sig_bytes[4..8].try_into().unwrap()) as usize;
    let ml_len_offset = 8 + ed_len;
    let original_ml_len = u32::from_le_bytes(
        sig_bytes[ml_len_offset..ml_len_offset + 4]
            .try_into()
            .unwrap(),
    );
    let inflated = original_ml_len + 256;
    sig_bytes[ml_len_offset..ml_len_offset + 4].copy_from_slice(&inflated.to_le_bytes());

    let vector = json!({
        "scheme": "ed25519_ml_dsa_65",
        "message_utf8": std::str::from_utf8(message).unwrap(),
        "message_hex": to_hex(message),
        "hybrid_public_key_hex": to_hex(&pk_bytes),
        "hybrid_signature_hex": to_hex(&sig_bytes),
        "hybrid_public_key_len": pk_bytes.len(),
        "hybrid_signature_len": sig_bytes.len(),
        "verify_result": false,
        "failure_reason": "ml_dsa length field inflated by 256 beyond actual data — truncated blob"
    });

    let path = tmp_dir().join("PQC_TEST_VECTOR_004_oversized_blob.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
    vector
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn vector_002_tampered_ownership_rejected() {
    let v = generate_and_write_vector_002();

    let pk_bytes = from_hex(v["hybrid_public_key_hex"].as_str().unwrap());
    let sig_bytes = from_hex(v["hybrid_signature_hex"].as_str().unwrap());
    let message = from_hex(v["message_hex"].as_str().unwrap());

    let sig = HybridSignature::from_canonical_bytes(&sig_bytes).unwrap();

    if let Ok(pk) = HybridPublicKey::from_canonical_bytes(&pk_bytes) {
        if let Ok(true) = HybridEd25519MlDsa.verify(&pk, &message, &sig) {
            panic!("tampered ownership must NOT verify as Ok(true)");
        }
    }
}

#[test]
fn vector_003_wrong_scheme_id_rejected() {
    let v = generate_and_write_vector_003();

    let pk_bytes = from_hex(v["hybrid_public_key_hex"].as_str().unwrap());

    let result = HybridPublicKey::from_canonical_bytes(&pk_bytes);
    assert!(
        result.is_err(),
        "wrong scheme_id must be rejected by from_canonical_bytes; got {result:?}",
    );
}

#[test]
fn vector_004_oversized_blob_rejected() {
    let v = generate_and_write_vector_004();

    let sig_bytes = from_hex(v["hybrid_signature_hex"].as_str().unwrap());

    let result = HybridSignature::from_canonical_bytes(&sig_bytes);
    assert!(
        result.is_err(),
        "oversized/truncated blob must be rejected by from_canonical_bytes; got {result:?}",
    );
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pinned vectors for the Ed25519 + FN-DSA-1024 hybrid scheme (scheme byte
//! 3), one per signing surface (rule 30).
//!
//! Three operations are pinned, because three things can move:
//!
//! - **key generation from seeds → public key bytes.** Integer-only in the
//!   `fn-dsa` crate. Moves if the crate's generator changes, if the seed →
//!   ChaCha20 → generator composition changes, or if the canonical key
//!   encoding does.
//! - **signing with a seeded RNG → signature bytes.** The one operation
//!   that uses hardware `f64`. Moves with any of the above, with the
//!   combiner's framing, or — the case this file exists to catch — if two
//!   supported architectures ever round differently.
//! - **verification of the pinned signature.** Integer-only. A build that
//!   moved sign and verify together passes every round-trip and fails here.
//!
//! This binary is run on x86_64 by the workspace test and **under aarch64**
//! by `.github/workflows/depends-aarch64-kats.yml`. The same fixture must
//! pass on both. If the signing assertion fails on one architecture only,
//! that is a determinism finding to report (`fn_dsa_hybrid.rs`, "Floating
//! point"); it is not a reason to pin per architecture.
//!
//! The `fn-dsa` crate is pre-standard and pinned exact; a version bump is
//! expected to move every byte here, by the crate's own statement. That is
//! what the regenerator's decision gate is for:
//!
//! ```text
//! SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-crypto-pq --test kat_fn_dsa_hybrid_v1 -- --ignored
//! ```

use serde_json::{json, Value};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{
    HybridSignature, SignatureScheme, HYBRID_SCHEME_ID_ED25519_FN_DSA_1024, SCHEME_DOMAIN_RECEIPT,
    SCHEME_DOMAIN_WITNESS_CARRIER,
};
use std::path::{Path, PathBuf};

/// Every surface that signs under scheme 3. A new one is added here; the
/// pinned test counts the fixture's vectors against this table.
const SURFACES: [(&str, &[u8]); 2] = [
    ("receipt", SCHEME_DOMAIN_RECEIPT),
    ("witness_carrier", SCHEME_DOMAIN_WITNESS_CARRIER),
];

/// Frozen with the pinned signatures.
const KAT_MESSAGE: &[u8] = b"shekyl-fn-dsa-hybrid-v1-kat: one message, every surface";
/// The two key-generation seeds and the signer's RNG seed. Arbitrary and
/// distinct; frozen with the vectors.
const ED25519_SEED: [u8; 32] = [0x11; 32];
const FN_DSA_SEED: [u8; 32] = [0x22; 32];
const RNG_SEED: [u8; 32] = [0x33; 32];

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/FN_DSA_HYBRID_V1_KAT.json")
}

fn read_fixture() -> Value {
    let raw = std::fs::read_to_string(fixture_path()).expect("FN_DSA_HYBRID_V1_KAT.json readable");
    serde_json::from_str(&raw).expect("FN_DSA_HYBRID_V1_KAT.json parses")
}

fn hex_field(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} present")),
    )
    .unwrap_or_else(|_| panic!("{field} is hex"))
}

/// The spec's sizes, as numbers, against the sizes the code derives from
/// the crate (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §6.2). A disagreement is a
/// defect in one of them, to be reported rather than adjusted.
#[test]
fn canonical_lengths_are_the_specified_ones() {
    assert_eq!(FnDsaHybridPublicKey::CANONICAL_LEN, 1_837);
    assert_eq!(FnDsaHybridSignature::CANONICAL_LEN, 1_356);
}

#[test]
fn pinned_vectors_reproduce_and_verify() {
    let kat = read_fixture();
    assert_eq!(
        kat["scheme_byte"].as_u64(),
        Some(u64::from(HYBRID_SCHEME_ID_ED25519_FN_DSA_1024))
    );
    assert_eq!(hex_field(&kat, "ed25519_seed_hex"), ED25519_SEED);
    assert_eq!(hex_field(&kat, "fn_dsa_seed_hex"), FN_DSA_SEED);
    assert_eq!(hex_field(&kat, "rng_seed_hex"), RNG_SEED);
    assert_eq!(hex_field(&kat, "message_hex"), KAT_MESSAGE);

    // Key generation: the seeds give the pinned key, byte for byte.
    let (public_key, secret_key) =
        HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).expect("keygen");
    let pinned_key = hex_field(&kat, "hybrid_public_key_hex");
    assert_eq!(pinned_key.len(), FnDsaHybridPublicKey::CANONICAL_LEN);
    assert_eq!(
        public_key.to_canonical_bytes(),
        pinned_key,
        "key generation from the pinned seeds moved"
    );
    let parsed_key =
        FnDsaHybridPublicKey::from_canonical_bytes(&pinned_key).expect("the pinned key parses");
    assert_eq!(parsed_key, public_key);

    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(
        vectors.len(),
        SURFACES.len(),
        "one pinned vector per surface — regenerate after adding a surface"
    );
    let scheme = HybridEd25519FnDsa;
    for (i, ((surface, domain), vector)) in SURFACES.iter().zip(vectors).enumerate() {
        assert_eq!(vector["surface"].as_str(), Some(*surface), "vector {i}");
        assert_eq!(
            vector["domain_utf8"].as_str().map(str::as_bytes),
            Some(*domain),
            "vector {i} ({surface}): the domain constant drifted from the pinned string"
        );
        let pinned_signature = hex_field(vector, "hybrid_signature_hex");
        assert_eq!(pinned_signature.len(), FnDsaHybridSignature::CANONICAL_LEN);

        // Signing: the seeded signer gives the pinned signature, byte for
        // byte. This is the assertion that must hold on every architecture.
        let signature = scheme
            .sign_with_rng_seed(&secret_key, domain, KAT_MESSAGE, &RNG_SEED)
            .expect("sign");
        assert_eq!(
            signature.to_canonical_bytes(),
            pinned_signature,
            "vector {i} ({surface}): seeded signing moved"
        );

        // Verification of bytes minted by an earlier build.
        let parsed = FnDsaHybridSignature::from_canonical_bytes(&pinned_signature)
            .expect("the pinned signature parses");
        scheme
            .verify(&parsed_key, domain, KAT_MESSAGE, &parsed)
            .unwrap_or_else(|e| panic!("vector {i} ({surface}): pinned signature verifies: {e:?}"));

        // And it is dead under every other surface's domain.
        for (other_surface, other_domain) in &SURFACES {
            if other_domain == domain {
                continue;
            }
            assert!(
                scheme
                    .verify(&parsed_key, other_domain, KAT_MESSAGE, &parsed)
                    .is_err(),
                "vector {i} ({surface}): must not verify under {other_surface}"
            );
        }
    }
}

/// The pinned signature against everything that is not it: another message,
/// one flipped byte in either half, and the two encodings of a valid object
/// that the crate must refuse as non-canonical.
#[test]
fn pinned_signature_refuses_every_near_miss() {
    let kat = read_fixture();
    let scheme = HybridEd25519FnDsa;
    let key_bytes = hex_field(&kat, "hybrid_public_key_hex");
    let key = FnDsaHybridPublicKey::from_canonical_bytes(&key_bytes).expect("key parses");
    let signature_bytes = hex_field(&kat["vectors"][0], "hybrid_signature_hex");
    let verify = |bytes: &[u8], message: &[u8]| {
        FnDsaHybridSignature::from_canonical_bytes(bytes)
            .and_then(|sig| scheme.verify(&key, SCHEME_DOMAIN_RECEIPT, message, &sig))
    };
    verify(&signature_bytes, KAT_MESSAGE).expect("the control verifies");

    assert!(verify(&signature_bytes, b"another message").is_err());

    // The frame is 4 header bytes, a 4-byte length, 64 Ed25519 bytes, a
    // 4-byte length, then the FN-DSA signature.
    let ed25519_at = 8;
    let fn_dsa_at = 8 + 64 + 4;
    for (name, at) in [("Ed25519", ed25519_at + 10), ("FN-DSA", fn_dsa_at + 100)] {
        let mut flipped = signature_bytes.clone();
        flipped[at] ^= 0x01;
        assert!(
            verify(&flipped, KAT_MESSAGE).is_err(),
            "a flipped byte in the {name} half must not verify"
        );
    }

    // Non-canonical signature: the compressed value is padded with zero
    // bits to the fixed length, and the crate refuses any other padding.
    // The value encoded is untouched, so this is the canonical-form rule
    // and not the "wrong signature" rule above.
    let last = signature_bytes.len() - 1;
    assert_eq!(
        signature_bytes[last], 0,
        "the fixture's signature ends in padding, or this case tests nothing"
    );
    let mut padded = signature_bytes.clone();
    padded[last] = 0x01;
    assert!(
        verify(&padded, KAT_MESSAGE).is_err(),
        "a signature with non-zero padding is a second encoding and must be refused"
    );

    // Non-canonical key: coefficients are 14-bit values below q = 12289,
    // and the crate refuses a value outside that range. Sixteen one-bits
    // after the FN-DSA key's header byte set the first coefficient to
    // 16383.
    let key_fn_dsa_at = 8 + 32 + 4;
    let mut out_of_range = key_bytes.clone();
    out_of_range[key_fn_dsa_at + 1] = 0xFF;
    out_of_range[key_fn_dsa_at + 2] = 0xFF;
    assert!(
        FnDsaHybridPublicKey::from_canonical_bytes(&out_of_range).is_err(),
        "a key with a coefficient outside [0, q) must not parse"
    );
}

/// Bytes of one scheme are not bytes of the other, in either direction and
/// under either header.
#[test]
fn the_two_schemes_do_not_parse_each_others_objects() {
    let kat = read_fixture();
    let fn_dsa_signature = hex_field(&kat["vectors"][0], "hybrid_signature_hex");

    // An ML-DSA hybrid signature, minted by an earlier build.
    let ml_dsa_kat: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/test_vectors/PQC_HYBRID_V2_KAT.json"),
        )
        .expect("PQC_HYBRID_V2_KAT.json readable"),
    )
    .expect("parses");
    let ml_dsa_signature = hex_field(&ml_dsa_kat["vectors"][0], "hybrid_signature_hex");
    HybridSignature::from_canonical_bytes(&ml_dsa_signature).expect("the ML-DSA control parses");

    assert!(FnDsaHybridSignature::from_canonical_bytes(&ml_dsa_signature).is_err());
    assert!(HybridSignature::from_canonical_bytes(&fn_dsa_signature).is_err());

    // Re-heading does not help: each parser also holds its own lengths.
    let mut reheaded = ml_dsa_signature.clone();
    reheaded[1] = HYBRID_SCHEME_ID_ED25519_FN_DSA_1024;
    assert!(FnDsaHybridSignature::from_canonical_bytes(&reheaded).is_err());
    let mut reheaded = fn_dsa_signature.clone();
    reheaded[1] = shekyl_crypto_pq::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65;
    assert!(HybridSignature::from_canonical_bytes(&reheaded).is_err());
}

/// Regenerate the fixture in place. Armed: it refuses unless
/// `SHEKYL_PINNED_REGEN_DECISION` cites the decision that moved the bytes
/// (a `fn-dsa` version bump, or a construction change). Everything is
/// derived from the frozen seeds, so a rerun with nothing changed rewrites
/// the file byte-identically.
#[test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regenerate_fn_dsa_hybrid_v1_kat() {
    let decision =
        shekyl_crypto_pq::test_support::regen_decision_or_refuse("FN_DSA_HYBRID_V1_KAT.json");
    eprintln!("regenerating the FN-DSA hybrid KAT under decision: {decision}");
    let scheme = HybridEd25519FnDsa;
    let (public_key, secret_key) =
        HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).expect("keygen");
    let vectors: Vec<Value> = SURFACES
        .iter()
        .map(|(surface, domain)| {
            let signature = scheme
                .sign_with_rng_seed(&secret_key, domain, KAT_MESSAGE, &RNG_SEED)
                .expect("sign");
            scheme
                .verify(&public_key, domain, KAT_MESSAGE, &signature)
                .expect("a fresh signature verifies");
            json!({
                "surface": surface,
                "domain_utf8": std::str::from_utf8(domain).expect("domains are ASCII"),
                "hybrid_signature_hex": hex::encode(signature.to_canonical_bytes()),
            })
        })
        .collect();
    let fixture = json!({
        "description": "Ed25519 + FN-DSA-1024 hybrid (scheme byte 3): key generation from seeds, seeded signing, and verification, one vector per surface. The fn-dsa crate is pre-standard and pinned exact (rust/shekyl-crypto-pq/Cargo.toml); a version bump is expected to move every byte here. Run on x86_64 and aarch64; the same bytes must hold on both.",
        "scheme": "Ed25519 + FN-DSA-1024, nested combiner (hybrid signature version 2)",
        "scheme_byte": HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
        "fn_dsa_crate": "fn-dsa =0.4.0",
        "ed25519_seed_hex": hex::encode(ED25519_SEED),
        "fn_dsa_seed_hex": hex::encode(FN_DSA_SEED),
        "rng_seed_hex": hex::encode(RNG_SEED),
        "message_utf8": std::str::from_utf8(KAT_MESSAGE).expect("ASCII"),
        "message_hex": hex::encode(KAT_MESSAGE),
        "hybrid_public_key_hex": hex::encode(public_key.to_canonical_bytes()),
        "vectors": vectors,
    });
    let mut out = serde_json::to_string_pretty(&fixture).expect("serialize");
    out.push('\n');
    std::fs::write(fixture_path(), out).expect("write fixture");
}

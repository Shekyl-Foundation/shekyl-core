// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Integration tests for [`shekyl_crypto_pq::output::recover_combined_ss`].
//!
//! `recover_combined_ss` is the cryptographic re-decap primitive (Layer 1
//! per `STAGE_1_PR_3_M3B_PREFLIGHT.md` §2 D1) that the engine's
//! deterministic-handle pathway calls to re-derive output secrets from a
//! stored [`shekyl_crypto_pq::kem::HybridCiphertext`] plus the wallet's
//! private view material.
//!
//! These tests assert two byte-identity properties that the engine's
//! re-decap path relies on:
//!
//! 1. **Encap-decap byte-identity.** The 64-byte combined shared secret
//!    produced by `recover_combined_ss` against `(secret_key, ciphertext)`
//!    matches the shared secret produced by the corresponding
//!    [`shekyl_crypto_pq::kem::HybridX25519MlKem::encapsulate`] call. This
//!    is the foundational correctness property: the re-decap chain inverts
//!    the encap chain.
//!
//! 2. **`scan_output_recover` prefix byte-identity.** For an output
//!    constructed via `construct_output` and re-recovered via
//!    `scan_output_recover`, the `combined_ss` carried on the recovered
//!    output equals `recover_combined_ss` invoked with the same inputs.
//!    This is the M3b property at Layer 1: the engine's re-decap path
//!    produces the same combined secret as the legacy scan path's prefix.
//!    M3b's downstream Layer 2 byte-identity test
//!    (`engine-core/tests/byte_identical_derivation.rs`) builds on this.

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as G, X25519_BASEPOINT},
    scalar::Scalar,
};

use shekyl_crypto_pq::error::CryptoError;
use shekyl_crypto_pq::kem::{
    HybridCiphertext, HybridKemPublicKey, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation,
    SharedSecret, ML_KEM_768_CT_LEN,
};
use shekyl_crypto_pq::output::{construct_output, recover_combined_ss, scan_output_recover};

fn random_keypair() -> (HybridKemPublicKey, HybridKemSecretKey) {
    HybridX25519MlKem
        .keypair_generate()
        .expect("keypair generate")
}

#[test]
fn encap_decap_byte_identical_combined_ss() {
    let (pk, sk) = random_keypair();
    let (ss_encap, ct): (SharedSecret, HybridCiphertext) = HybridX25519MlKem
        .encapsulate(&pk)
        .expect("encapsulate against fresh pk");

    let ss_decap = recover_combined_ss(&sk.x25519, &sk.ml_kem, &ct.x25519, &ct.ml_kem)
        .expect("recover_combined_ss against the same (sk, ct) pair");

    assert_eq!(
        ss_encap.0, ss_decap.0,
        "recover_combined_ss must invert HybridX25519MlKem::encapsulate \
         on the same (sk, ct) pair"
    );
}

#[test]
fn scan_output_recover_prefix_byte_identical() {
    let (recipient_pk, recipient_sk) = random_keypair();

    let tx_key = Scalar::random(&mut rand::rngs::OsRng).to_bytes();
    let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
        .compress()
        .to_bytes();

    let amount = 7_777_777u64;
    let output_index = 3u64;

    let out = construct_output(
        &tx_key,
        &recipient_pk.x25519,
        &recipient_pk.ml_kem,
        &spend_key,
        amount,
        output_index,
    )
    .expect("construct_output");

    let recovered = scan_output_recover(
        &recipient_sk.x25519,
        &recipient_sk.ml_kem,
        &out.kem_ciphertext_x25519,
        &out.kem_ciphertext_ml_kem,
        &out.output_key,
        &out.commitment,
        &out.enc_amount,
        out.amount_tag,
        out.view_tag_x25519,
        output_index,
    )
    .expect("scan_output_recover against own keys");

    let combined_ss = recover_combined_ss(
        &recipient_sk.x25519,
        &recipient_sk.ml_kem,
        &out.kem_ciphertext_x25519,
        &out.kem_ciphertext_ml_kem,
    )
    .expect("recover_combined_ss against own keys");

    assert_eq!(
        recovered.combined_ss, combined_ss.0,
        "recover_combined_ss must produce the same 64-byte combined secret \
         as scan_output_recover's internal X25519+ML-KEM+combine sub-chain"
    );
}

#[test]
fn distinct_outputs_yield_distinct_combined_ss() {
    let (recipient_pk, recipient_sk) = random_keypair();
    let tx_key = Scalar::random(&mut rand::rngs::OsRng).to_bytes();
    let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
        .compress()
        .to_bytes();

    let mut secrets: Vec<[u8; 64]> = Vec::with_capacity(4);
    for output_index in 0..4u64 {
        let out = construct_output(
            &tx_key,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &spend_key,
            1_000 * (output_index + 1),
            output_index,
        )
        .expect("construct_output");

        let combined_ss = recover_combined_ss(
            &recipient_sk.x25519,
            &recipient_sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
        )
        .expect("recover_combined_ss");

        secrets.push(combined_ss.0);
    }

    // Sanity: 4 distinct (output_index, ciphertext) pairs must yield 4
    // distinct combined secrets. This protects against a primitive that
    // accidentally drops `output_index` or `ciphertext` from its derivation.
    for i in 0..secrets.len() {
        for j in (i + 1)..secrets.len() {
            assert_ne!(
                secrets[i], secrets[j],
                "combined_ss[{i}] and combined_ss[{j}] must differ across distinct outputs"
            );
        }
    }
}

#[test]
fn low_order_x25519_ephemeral_rejected() {
    let (_, sk) = random_keypair();
    let dummy_ml_ct = vec![0u8; ML_KEM_768_CT_LEN];

    // u = 0 is the identity on the Montgomery curve and the canonical
    // small-subgroup test vector — `recover_combined_ss` must reject it
    // before the X25519 ECDH would leak `view_scalar mod 8`.
    let zero_u = [0u8; 32];

    let result = recover_combined_ss(&sk.x25519, &sk.ml_kem, &zero_u, &dummy_ml_ct);
    match result {
        Err(CryptoError::LowOrderPoint) => {}
        Err(other) => panic!("expected LowOrderPoint, got {other:?}"),
        Ok(_) => panic!("low-order point u=0 must be rejected"),
    }
}

#[test]
fn invalid_ml_kem_dk_length_rejected() {
    let (_, sk) = random_keypair();
    let dummy_ml_ct = vec![0u8; ML_KEM_768_CT_LEN];
    // Use the X25519 Montgomery basepoint directly so the constructed
    // u-coordinate is unambiguously a prime-order Montgomery point.
    // An Edwards-basepoint scalar multiple converted via
    // `to_montgomery()` is also prime-order (the Edwards basepoint
    // generates the prime-order subgroup; the Edwards→Montgomery
    // isogeny preserves prime-order images), but using the X25519
    // basepoint directly aligns the test fixture with the production
    // primitive's domain and removes the Edwards→Montgomery
    // bookkeeping from the test's invariant chain.
    let scalar = Scalar::random(&mut rand::rngs::OsRng);
    let kem_ct_x25519 = (scalar * X25519_BASEPOINT).to_bytes();

    // Truncated decap key: same prefix bytes, missing tail.
    let mut short_dk = sk.ml_kem.clone();
    short_dk.truncate(short_dk.len() - 1);

    let result = recover_combined_ss(&sk.x25519, &short_dk, &kem_ct_x25519, &dummy_ml_ct);
    match result {
        Err(CryptoError::InvalidKeyMaterial) => {}
        Err(other) => panic!("expected InvalidKeyMaterial, got {other:?}"),
        Ok(_) => panic!("truncated ML-KEM-768 decap key must be rejected"),
    }
}

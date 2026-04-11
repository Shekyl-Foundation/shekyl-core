// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Gate 1: Property-based round-trip test for output construction → scan → key image.
//!
//! Tests the full pipeline: construct_output → scan_output_recover →
//! derive_output_secrets → compute_output_key_image, asserting:
//!
//! 1. Round-trip succeeds for all valid inputs (random spend keys, amounts 0..u64::MAX).
//! 2. Cross-cycle determinism: same inputs produce byte-identical outputs on every run.
//! 3. Amount=0 boundary: zero-amount outputs are legal and round-trip correctly.
//! 4. All derived secrets (ho, y, z, k_amount, key_image) are non-zero.
//!
//! Run with `cargo test --release -p shekyl-crypto-pq --test prop_round_trip` for CI.

use proptest::prelude::*;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    scalar::Scalar,
};
use shekyl_crypto_pq::{
    kem::{HybridX25519MlKem, KeyEncapsulation},
    output::{construct_output, scan_output_recover, compute_output_key_image},
    derivation::derive_output_secrets,
};
use shekyl_generators::hash_to_point;

fn scalar_from_u64s(a: u64, b: u64, c: u64, d: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..16].copy_from_slice(&b.to_le_bytes());
    bytes[16..24].copy_from_slice(&c.to_le_bytes());
    bytes[24..32].copy_from_slice(&d.to_le_bytes());
    Scalar::from_bytes_mod_order(bytes)
}

fn run_round_trip(spend_scalar: Scalar, amount: u64, output_index: u64) -> RoundTripResult {
    let kem = HybridX25519MlKem;
    let (recipient_pk, recipient_sk) = kem.keypair_generate().unwrap();

    let tx_key_scalar = Scalar::from_bytes_mod_order([42u8; 32]);
    let tx_key = tx_key_scalar.to_bytes();

    let spend_point = G * spend_scalar;
    let spend_key = spend_point.compress().to_bytes();

    let out = construct_output(
        &tx_key,
        &recipient_pk.x25519,
        &recipient_pk.ml_kem,
        &spend_key,
        amount,
        output_index,
    )
    .expect("construct_output failed");

    let recovered = scan_output_recover(
        &recipient_sk.x25519,
        &recipient_sk.ml_kem,
        &out.kem_ct[..32].try_into().unwrap(),
        &out.kem_ct[32..],
        &out.output_key,
        &out.commitment,
        &out.enc_amount,
        out.amount_tag,
        out.view_tag,
        output_index,
    )
    .expect("scan_output_recover failed");

    assert_eq!(recovered.amount, amount, "amount mismatch after recovery");

    let secrets = derive_output_secrets(&recovered.combined_ss, output_index);

    let hp_bytes = hash_to_point(out.output_key).compress().to_bytes();
    let ki_result = compute_output_key_image(
        &recovered.combined_ss,
        output_index,
        &spend_scalar.to_bytes(),
        &hp_bytes,
    )
    .expect("compute_output_key_image failed");

    assert_ne!(secrets.ho, [0u8; 32], "ho must not be zero");
    assert_ne!(secrets.y, [0u8; 32], "y must not be zero");
    assert_ne!(secrets.z, [0u8; 32], "z must not be zero");
    assert_ne!(secrets.k_amount, [0u8; 32], "k_amount must not be zero");
    assert_ne!(ki_result.key_image, [0u8; 32], "key_image must not be zero");

    RoundTripResult {
        output_key: out.output_key,
        commitment: out.commitment,
        ho: secrets.ho,
        y: secrets.y,
        z: secrets.z,
        k_amount: secrets.k_amount,
        key_image: ki_result.key_image,
        amount: recovered.amount,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RoundTripResult {
    output_key: [u8; 32],
    commitment: [u8; 32],
    ho: [u8; 32],
    y: [u8; 32],
    z: [u8; 32],
    k_amount: [u8; 32],
    key_image: [u8; 32],
    amount: u64,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn round_trip_succeeds_and_is_deterministic(
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        d in any::<u64>(),
        amount in 0u64..=u64::MAX,
        output_index in 0u64..16,
    ) {
        let spend_scalar = scalar_from_u64s(a, b, c, d);
        if spend_scalar == Scalar::ZERO {
            return Ok(());
        }

        let result_1 = run_round_trip(spend_scalar, amount, output_index);
        let result_2 = run_round_trip(spend_scalar, amount, output_index);

        prop_assert_eq!(
            result_1, result_2,
            "determinism violation: same inputs produced different outputs"
        );
    }
}

#[test]
fn amount_zero_round_trip() {
    let spend_scalar = Scalar::from_bytes_mod_order([7u8; 32]);
    let result = run_round_trip(spend_scalar, 0, 0);
    assert_eq!(result.amount, 0, "zero-amount output should round-trip");
    eprintln!("[Gate 1] amount=0 round-trip passed: key_image={}", hex::encode(result.key_image));
}

#[test]
fn amount_max_round_trip() {
    let spend_scalar = Scalar::from_bytes_mod_order([11u8; 32]);
    let result = run_round_trip(spend_scalar, u64::MAX, 3);
    assert_eq!(result.amount, u64::MAX);
    eprintln!("[Gate 1] amount=MAX round-trip passed: key_image={}", hex::encode(result.key_image));
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! EXIT CRITERION: tx_proof V3 10-point round-trip.
//!
//! Tests 1-8: Pure Rust, exercising the proof crate directly.
//! Tests 9-10: Wallet-state tests. Stubbed here for checklist completeness;
//! the definitive implementations are C++/FFI core_tests that exercise
//! wallet2's tx_key absence error paths.
//!
//! Wire format size assertions are inline.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    scalar::Scalar,
};
use rand_core::OsRng;

use shekyl_crypto_pq::{
    kem::{HybridX25519MlKem, KeyEncapsulation},
    output::{
        construct_output, compute_output_key_image, derive_proof_secrets,
        rederive_combined_ss, scan_output_recover, OutputData,
    },
};
use shekyl_proofs::{
    tx_proof::{
        self, generate_outbound_proof, verify_outbound_proof,
        generate_inbound_proof, verify_inbound_proof, OnChainOutput,
    },
    reserve_proof::{
        self, generate_reserve_proof, verify_reserve_proof,
        ReserveOutputEntry, ReserveOnChainOutput,
    },
};

struct TestContext {
    spend_secret: [u8; 32],
    spend_pubkey: [u8; 32],
    view_secret: [u8; 32],
    view_pubkey: [u8; 32],
    tx_key_secret: [u8; 32],
    kem_pk_x25519: [u8; 32],
    kem_pk_ml_kem: Vec<u8>,
    kem_sk_x25519: [u8; 32],
    kem_sk_ml_kem: Vec<u8>,
    txid: [u8; 32],
    address_bytes: Vec<u8>,
    user_message: Vec<u8>,
    outputs: Vec<OutputData>,
    on_chain: Vec<OnChainOutput>,
}

fn setup(num_outputs: usize, amount_base: u64) -> TestContext {
    let b = Scalar::random(&mut OsRng);
    let b_point = b * G;
    let spend_secret = b.to_bytes();
    let spend_pubkey = b_point.compress().to_bytes();

    let v = Scalar::random(&mut OsRng);
    let v_point = v * G;
    let view_secret = v.to_bytes();
    let view_pubkey = v_point.compress().to_bytes();

    let tx_key = Scalar::random(&mut OsRng).to_bytes();

    let kem = HybridX25519MlKem;
    let (pk, sk) = kem.keypair_generate().expect("KEM keygen");

    let mut txid = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut txid[..]);
    let address_bytes = b"shekyl1qtest_address_placeholder".to_vec();
    let user_message = b"proof-test-message".to_vec();

    let mut outputs = Vec::with_capacity(num_outputs);
    let mut on_chain = Vec::with_capacity(num_outputs);

    for i in 0..num_outputs {
        let amount = amount_base + i as u64;
        let od = construct_output(
            &tx_key,
            &pk.x25519,
            &pk.ml_kem,
            &spend_pubkey,
            amount,
            i as u64,
        )
        .expect("construct_output");

        on_chain.push(OnChainOutput {
            output_key: od.output_key,
            commitment: od.commitment,
            enc_amount: od.enc_amount,
            x25519_eph_pk: od.kem_ciphertext_x25519,
            ml_kem_ct: od.kem_ciphertext_ml_kem.clone(),
        });
        outputs.push(od);
    }

    TestContext {
        spend_secret,
        spend_pubkey,
        view_secret,
        view_pubkey,
        tx_key_secret: tx_key,
        kem_pk_x25519: pk.x25519,
        kem_pk_ml_kem: pk.ml_kem.clone(),
        kem_sk_x25519: sk.x25519,
        kem_sk_ml_kem: sk.ml_kem.clone(),
        txid,
        address_bytes,
        user_message,
        outputs,
        on_chain,
    }
}

// --------------------------------------------------------------------------
// Test 1: Construct V3 tx, generate outbound proof, third-party verifies.
// --------------------------------------------------------------------------
#[test]
fn test_01_outbound_proof_round_trip() {
    let ctx = setup(1, 1_000_000);

    let proof = generate_outbound_proof(
        &ctx.tx_key_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &[0],
    )
    .expect("generate outbound proof");

    let expected_size = tx_proof::outbound_proof_size(1);
    assert_eq!(proof.len(), expected_size,
        "outbound proof size: expected {expected_size}, got {}", proof.len());
    assert_eq!(expected_size, 101 + 128 * 1, "wire format: 101 + 128*N");

    let verified = verify_outbound_proof(
        &proof,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &ctx.on_chain,
    )
    .expect("verify outbound proof");

    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].output_index, 0);
    assert_eq!(verified[0].amount, 1_000_000);
    eprintln!("[test_01] outbound proof round-trip OK, amount={}", verified[0].amount);
}

// --------------------------------------------------------------------------
// Test 2: Generate inbound proof from recipient, verifier confirms.
// --------------------------------------------------------------------------
#[test]
fn test_02_inbound_proof_round_trip() {
    let ctx = setup(1, 2_000_000);

    let recovered = scan_output_recover(
        &ctx.kem_sk_x25519,
        &ctx.kem_sk_ml_kem,
        &ctx.on_chain[0].x25519_eph_pk,
        &ctx.on_chain[0].ml_kem_ct,
        &ctx.on_chain[0].output_key,
        &ctx.on_chain[0].commitment,
        &ctx.on_chain[0].enc_amount,
        ctx.outputs[0].amount_tag,
        ctx.outputs[0].view_tag_x25519,
        0,
    )
    .expect("scan_output_recover");

    let ps = derive_proof_secrets(
        &recovered.combined_ss.try_into().expect("64 bytes"),
        0,
    );

    let proof = generate_inbound_proof(
        &ctx.view_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &[ps],
    )
    .expect("generate inbound proof");

    let expected_size = tx_proof::inbound_proof_size(1);
    assert_eq!(proof.len(), expected_size);
    assert_eq!(expected_size, 69 + 128 * 1, "wire format: 69 + 128*N");

    let verified = verify_inbound_proof(
        &proof,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.view_pubkey,
        &ctx.spend_pubkey,
        &ctx.on_chain,
    )
    .expect("verify inbound proof");

    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].amount, 2_000_000);
    eprintln!("[test_02] inbound proof round-trip OK, amount={}", verified[0].amount);
}

// --------------------------------------------------------------------------
// Test 3: Inbound proof returns same result as outbound proof.
// --------------------------------------------------------------------------
#[test]
fn test_03_outbound_inbound_consistency() {
    let ctx = setup(2, 5_000_000);
    let indices: Vec<u64> = (0..2).collect();

    let outbound = generate_outbound_proof(
        &ctx.tx_key_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &indices,
    )
    .expect("outbound");

    let outbound_verified = verify_outbound_proof(
        &outbound,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &ctx.on_chain,
    )
    .expect("verify outbound");

    let mut per_output_secrets = Vec::new();
    for i in 0..2usize {
        let recovered = scan_output_recover(
            &ctx.kem_sk_x25519,
            &ctx.kem_sk_ml_kem,
            &ctx.on_chain[i].x25519_eph_pk,
            &ctx.on_chain[i].ml_kem_ct,
            &ctx.on_chain[i].output_key,
            &ctx.on_chain[i].commitment,
            &ctx.on_chain[i].enc_amount,
            ctx.outputs[i].amount_tag,
            ctx.outputs[i].view_tag_x25519,
            i as u64,
        )
        .expect("scan");
        per_output_secrets.push(derive_proof_secrets(
            &recovered.combined_ss.try_into().expect("64"),
            i as u64,
        ));
    }

    let inbound = generate_inbound_proof(
        &ctx.view_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &per_output_secrets,
    )
    .expect("inbound");

    let inbound_verified = verify_inbound_proof(
        &inbound,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.view_pubkey,
        &ctx.spend_pubkey,
        &ctx.on_chain,
    )
    .expect("verify inbound");

    assert_eq!(outbound_verified.len(), inbound_verified.len());
    for (ov, iv) in outbound_verified.iter().zip(&inbound_verified) {
        assert_eq!(ov.output_index, iv.output_index);
        assert_eq!(ov.amount, iv.amount,
            "outbound/inbound amount mismatch at output {}", ov.output_index);
    }
    eprintln!("[test_03] outbound/inbound consistency OK for {} outputs", outbound_verified.len());
}

// --------------------------------------------------------------------------
// Test 4: Reserve proof round-trip.
// --------------------------------------------------------------------------
#[test]
fn test_04_reserve_proof_round_trip() {
    let ctx = setup(3, 10_000_000);

    let mut entries = Vec::new();
    let mut reserve_on_chain = Vec::new();

    for i in 0..3usize {
        let (combined_ss, _, _) = rederive_combined_ss(
            &ctx.tx_key_secret,
            &ctx.kem_pk_x25519,
            &ctx.kem_pk_ml_kem,
            i as u64,
        )
        .expect("rederive");

        let ps = derive_proof_secrets(&combined_ss.0, i as u64);

        let hp_point = shekyl_generators::biased_hash_to_point(ctx.on_chain[i].output_key);
        let hp_bytes = hp_point.compress().to_bytes();

        let ki_result = compute_output_key_image(
            &combined_ss.0,
            i as u64,
            &ctx.spend_secret,
            &hp_bytes,
        )
        .expect("key image");

        entries.push(ReserveOutputEntry {
            proof_secrets: ps,
            key_image: ki_result.key_image,
            spend_secret: *ki_result.spend_secret_x,
            output_key: ctx.on_chain[i].output_key,
        });

        reserve_on_chain.push(ReserveOnChainOutput {
            output_key: ctx.on_chain[i].output_key,
            commitment: ctx.on_chain[i].commitment,
            enc_amount: ctx.on_chain[i].enc_amount,
        });
    }

    let proof = generate_reserve_proof(
        &ctx.spend_secret,
        &ctx.address_bytes,
        &ctx.user_message,
        &entries,
    )
    .expect("generate reserve proof");

    let expected_size = reserve_proof::reserve_proof_size(3);
    assert_eq!(proof.len(), expected_size);
    assert_eq!(expected_size, 69 + 192 * 3, "wire format: 69 + 192*N");

    let verified = verify_reserve_proof(
        &proof,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &reserve_on_chain,
    )
    .expect("verify reserve proof");

    assert_eq!(verified.len(), 3);
    let mut total = 0u64;
    for v in &verified {
        total += v.amount;
        eprintln!("[test_04] output {}: amount={}, ki={}", v.output_index, v.amount,
            hex::encode(&v.key_image[..8]));
    }
    assert_eq!(total, 10_000_000 + 10_000_001 + 10_000_002);
    eprintln!("[test_04] reserve proof round-trip OK, total={total}");
}

// --------------------------------------------------------------------------
// Test 5: Tampered ProofSecrets (flip one bit in ho) -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
fn test_05_tampered_proof_secrets_rejected() {
    let ctx = setup(1, 1_000_000);

    let mut proof = generate_outbound_proof(
        &ctx.tx_key_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &[0],
    )
    .expect("generate");

    // Flip one bit in the first byte of ho (starts at offset 101 in outbound proof)
    proof[101] ^= 0x01;

    let result = verify_outbound_proof(
        &proof,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &ctx.on_chain,
    );

    assert!(result.is_err(), "tampered ho must be rejected");
    eprintln!("[test_05] tampered ProofSecrets correctly rejected: {:?}",
        result.unwrap_err());
}

// --------------------------------------------------------------------------
// Test 6: Swapped ProofSecrets between two outputs -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
fn test_06_swapped_proof_secrets_rejected() {
    let ctx = setup(2, 3_000_000);

    let mut proof = generate_outbound_proof(
        &ctx.tx_key_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &[0, 1],
    )
    .expect("generate");

    // Swap per-output entries (128 bytes each, starting at offset 101)
    let header = 101;
    let entry_size = 128;
    let mut entry0 = [0u8; 128];
    let mut entry1 = [0u8; 128];
    entry0.copy_from_slice(&proof[header..header + entry_size]);
    entry1.copy_from_slice(&proof[header + entry_size..header + 2 * entry_size]);
    proof[header..header + entry_size].copy_from_slice(&entry1);
    proof[header + entry_size..header + 2 * entry_size].copy_from_slice(&entry0);

    let result = verify_outbound_proof(
        &proof,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &ctx.on_chain,
    );

    assert!(result.is_err(), "swapped ProofSecrets must be rejected");
    eprintln!("[test_06] swapped ProofSecrets correctly rejected: {:?}",
        result.unwrap_err());
}

// --------------------------------------------------------------------------
// Test 7: Valid proof for tx A replayed against tx B -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
fn test_07_cross_tx_replay_rejected() {
    let ctx = setup(1, 1_000_000);

    let proof = generate_outbound_proof(
        &ctx.tx_key_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &[0],
    )
    .expect("generate");

    // Verify against a different txid
    let mut wrong_txid = ctx.txid;
    wrong_txid[0] ^= 0xFF;

    let result = verify_outbound_proof(
        &proof,
        &wrong_txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &ctx.on_chain,
    );

    assert!(result.is_err(), "cross-tx replay must be rejected (Schnorr is txid-bound)");
    eprintln!("[test_07] cross-tx replay correctly rejected: {:?}",
        result.unwrap_err());
}

// --------------------------------------------------------------------------
// Test 8: Inbound proof signed with wrong view key -> verifier rejects.
// --------------------------------------------------------------------------
#[test]
fn test_08_wrong_view_key_inbound_rejected() {
    let ctx = setup(1, 1_000_000);

    let recovered = scan_output_recover(
        &ctx.kem_sk_x25519,
        &ctx.kem_sk_ml_kem,
        &ctx.on_chain[0].x25519_eph_pk,
        &ctx.on_chain[0].ml_kem_ct,
        &ctx.on_chain[0].output_key,
        &ctx.on_chain[0].commitment,
        &ctx.on_chain[0].enc_amount,
        ctx.outputs[0].amount_tag,
        ctx.outputs[0].view_tag_x25519,
        0,
    )
    .expect("scan");

    let ps = derive_proof_secrets(
        &recovered.combined_ss.try_into().expect("64"),
        0,
    );

    let wrong_view_secret = Scalar::random(&mut OsRng).to_bytes();

    let proof = generate_inbound_proof(
        &wrong_view_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &[ps],
    )
    .expect("generate with wrong view key");

    let result = verify_inbound_proof(
        &proof,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.view_pubkey, // correct view pubkey — doesn't match signer
        &ctx.spend_pubkey,
        &ctx.on_chain,
    );

    assert!(result.is_err(), "wrong view key must be rejected");
    eprintln!("[test_08] wrong view key correctly rejected: {:?}",
        result.unwrap_err());
}

// --------------------------------------------------------------------------
// Test 9: Watch-only wallet attempts outbound proof -> human-readable error.
//
// NOTE: Wallet-state test. The definitive implementation is a C++/FFI
// core_test that exercises wallet2's m_tx_keys absence path.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: C++/FFI test -- wallet2 tx_key absence (watch-only)"]
fn test_09_watch_only_outbound_proof_error() {
    todo!("Phase 5 C++: watch-only wallet outbound proof → clear error message");
}

// --------------------------------------------------------------------------
// Test 10: Restored wallet attempts outbound proof on pre-restore tx.
//
// NOTE: Wallet-state test, same as test 9 — C++/FFI definitive.
// --------------------------------------------------------------------------
#[test]
#[ignore = "Phase 5: C++/FFI test -- wallet2 tx_key absence (restored)"]
fn test_10_restored_wallet_outbound_proof_error() {
    todo!("Phase 5 C++: restored wallet outbound proof → clear error, suggest inbound");
}

// --------------------------------------------------------------------------
// Wire format size assertions
// --------------------------------------------------------------------------
#[test]
fn test_wire_format_sizes() {
    for n in [0, 1, 2, 5, 10, 100] {
        assert_eq!(
            tx_proof::outbound_proof_size(n),
            101 + 128 * n,
            "outbound size for N={n}"
        );
        assert_eq!(
            tx_proof::inbound_proof_size(n),
            69 + 128 * n,
            "inbound size for N={n}"
        );
        assert_eq!(
            reserve_proof::reserve_proof_size(n),
            69 + 192 * n,
            "reserve size for N={n}"
        );
    }
    eprintln!("[wire_format] all size assertions passed");
}

// --------------------------------------------------------------------------
// Multi-output outbound proof
// --------------------------------------------------------------------------
#[test]
fn test_multi_output_outbound() {
    let ctx = setup(5, 100_000);
    let indices: Vec<u64> = (0..5).collect();

    let proof = generate_outbound_proof(
        &ctx.tx_key_secret,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &indices,
    )
    .expect("multi-output outbound");

    assert_eq!(proof.len(), tx_proof::outbound_proof_size(5));

    let verified = verify_outbound_proof(
        &proof,
        &ctx.txid,
        &ctx.address_bytes,
        &ctx.user_message,
        &ctx.spend_pubkey,
        &ctx.kem_pk_x25519,
        &ctx.kem_pk_ml_kem,
        &ctx.on_chain,
    )
    .expect("verify multi-output");

    assert_eq!(verified.len(), 5);
    for (i, v) in verified.iter().enumerate() {
        assert_eq!(v.amount, 100_000 + i as u64);
    }
    eprintln!("[multi_output] 5-output outbound proof verified");
}

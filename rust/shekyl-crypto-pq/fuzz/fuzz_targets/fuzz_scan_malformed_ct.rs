// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::{
    kem::{HybridX25519MlKem, KeyEncapsulation, ML_KEM_768_CT_LEN},
    output::{construct_output, scan_output_recover},
};

// Exercises scan_output_recover with corrupted ML-KEM ciphertexts against a
// valid wallet KEM decapsulation key. ML-KEM uses implicit rejection
// (returns a pseudorandom shared secret on corrupt ciphertext), so the
// scanner must fail closed via downstream checks (amount_tag, commitment,
// or output_key mismatch) — never panic, never leak timing.
fuzz_target!(|data: &[u8]| {
    // Minimum: 32 (tx_key) + 32 (spend_key) + 1 (corruption seed)
    if data.len() < 65 {
        return;
    }

    let mut tx_key = [0u8; 32];
    tx_key.copy_from_slice(&data[..32]);

    let mut spend_key_bytes = [0u8; 32];
    spend_key_bytes.copy_from_slice(&data[32..64]);

    let kem = HybridX25519MlKem;
    let (pk, sk) = match kem.keypair_generate() {
        Ok(pair) => pair,
        Err(_) => return,
    };

    // Build a valid output so we have real on-chain values
    let amount = 1_000_000u64;
    let output_index = 0u64;
    let od = match construct_output(
        &tx_key,
        &pk.x25519,
        &pk.ml_kem,
        &spend_key_bytes,
        amount,
        output_index,
    ) {
        Ok(od) => od,
        Err(_) => return,
    };

    // --- Test 1: Corrupt the ML-KEM ciphertext bytes using fuzz data ---
    let corruption_bytes = &data[64..];
    let mut bad_ct = od.kem_ct.ml_kem.clone();
    for (i, &b) in corruption_bytes.iter().enumerate() {
        if i < bad_ct.len() {
            bad_ct[i] ^= b;
        }
    }
    // ML-KEM implicit rejection: decaps succeeds with wrong SS, downstream fails
    let _ = scan_output_recover(
        &sk.x25519,
        &sk.ml_kem,
        &od.kem_ct.x25519,
        &bad_ct,
        &od.output_key,
        &od.commitment,
        &od.enc_amount,
        od.amount_tag,
        od.view_tag_x25519,
        output_index,
    );

    // --- Test 2: Truncated ML-KEM ciphertext ---
    if corruption_bytes.len() >= 2 {
        let trunc_len = (corruption_bytes[0] as usize) % ML_KEM_768_CT_LEN;
        if trunc_len > 0 {
            let truncated = &od.kem_ct.ml_kem[..trunc_len];
            let _ = scan_output_recover(
                &sk.x25519,
                &sk.ml_kem,
                &od.kem_ct.x25519,
                truncated,
                &od.output_key,
                &od.commitment,
                &od.enc_amount,
                od.amount_tag,
                od.view_tag_x25519,
                output_index,
            );
        }
    }

    // --- Test 3: Corrupt X25519 ephemeral public key ---
    let mut bad_x25519_ct = od.kem_ct.x25519;
    for (i, &b) in corruption_bytes.iter().enumerate() {
        if i < 32 {
            bad_x25519_ct[i] ^= b;
        }
    }
    let _ = scan_output_recover(
        &sk.x25519,
        &sk.ml_kem,
        &bad_x25519_ct,
        &od.kem_ct.ml_kem,
        &od.output_key,
        &od.commitment,
        &od.enc_amount,
        od.amount_tag,
        od.view_tag_x25519,
        output_index,
    );

    // --- Test 4: Completely random ciphertext bytes ---
    if corruption_bytes.len() >= ML_KEM_768_CT_LEN {
        let random_ct = &corruption_bytes[..ML_KEM_768_CT_LEN];
        let _ = scan_output_recover(
            &sk.x25519,
            &sk.ml_kem,
            &od.kem_ct.x25519,
            random_ct,
            &od.output_key,
            &od.commitment,
            &od.enc_amount,
            od.amount_tag,
            od.view_tag_x25519,
            output_index,
        );
    }
});

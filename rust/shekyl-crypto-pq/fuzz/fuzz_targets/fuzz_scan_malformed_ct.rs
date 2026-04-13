// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::{
    kem::{HybridX25519MlKem, KeyEncapsulation, ML_KEM_768_CT_LEN},
    output::{construct_output, scan_output_recover},
};

fuzz_target!(|data: &[u8]| {
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

    let corruption_bytes = &data[64..];

    // Test 1: Corrupt the ML-KEM ciphertext bytes
    let mut bad_ct = od.kem_ciphertext_ml_kem.clone();
    for (i, &b) in corruption_bytes.iter().enumerate() {
        if i < bad_ct.len() {
            bad_ct[i] ^= b;
        }
    }
    let _ = scan_output_recover(
        &sk.x25519,
        &sk.ml_kem,
        &od.kem_ciphertext_x25519,
        &bad_ct,
        &od.output_key,
        &od.commitment,
        &od.enc_amount,
        od.amount_tag,
        od.view_tag_x25519,
        output_index,
    );

    // Test 2: Truncated ML-KEM ciphertext
    if corruption_bytes.len() >= 2 {
        let trunc_len = (corruption_bytes[0] as usize) % ML_KEM_768_CT_LEN;
        if trunc_len > 0 {
            let truncated = &od.kem_ciphertext_ml_kem[..trunc_len];
            let _ = scan_output_recover(
                &sk.x25519,
                &sk.ml_kem,
                &od.kem_ciphertext_x25519,
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

    // Test 3: Corrupt X25519 ephemeral public key
    let mut bad_x25519_ct = od.kem_ciphertext_x25519;
    for (i, &b) in corruption_bytes.iter().enumerate() {
        if i < 32 {
            bad_x25519_ct[i] ^= b;
        }
    }
    let _ = scan_output_recover(
        &sk.x25519,
        &sk.ml_kem,
        &bad_x25519_ct,
        &od.kem_ciphertext_ml_kem,
        &od.output_key,
        &od.commitment,
        &od.enc_amount,
        od.amount_tag,
        od.view_tag_x25519,
        output_index,
    );

    // Test 4: Completely random ciphertext bytes
    if corruption_bytes.len() >= ML_KEM_768_CT_LEN {
        let random_ct = &corruption_bytes[..ML_KEM_768_CT_LEN];
        let _ = scan_output_recover(
            &sk.x25519,
            &sk.ml_kem,
            &od.kem_ciphertext_x25519,
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

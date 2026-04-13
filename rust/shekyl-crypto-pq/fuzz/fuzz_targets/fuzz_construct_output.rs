// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::{
    kem::{HybridX25519MlKem, KeyEncapsulation},
    output::{construct_output, scan_output},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 + 8 + 32 + 32 {
        return;
    }

    let amount = u64::from_le_bytes(data[..8].try_into().unwrap());
    let output_index = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 256;

    let mut tx_key = [0u8; 32];
    tx_key.copy_from_slice(&data[16..48]);

    let mut spend_key = [0u8; 32];
    spend_key.copy_from_slice(&data[48..80]);

    let kem = HybridX25519MlKem;
    let (pk, sk) = match kem.keypair_generate() {
        Ok(pair) => pair,
        Err(_) => return,
    };

    let od = match construct_output(
        &tx_key,
        &pk.x25519,
        &pk.ml_kem,
        &spend_key,
        amount,
        output_index,
    ) {
        Ok(od) => od,
        Err(_) => return,
    };

    let _ = scan_output(
        &sk.x25519,
        &sk.ml_kem,
        &od.kem_ciphertext_x25519,
        &od.kem_ciphertext_ml_kem,
        &od.output_key,
        &od.commitment,
        &od.enc_amount,
        od.amount_tag,
        od.view_tag_x25519,
        &spend_key,
        output_index,
    );

    if data.len() >= 48 + 8 {
        let mut bad_enc = od.enc_amount;
        for (i, &b) in data[48..].iter().take(8).enumerate() {
            bad_enc[i] ^= b;
        }
        let _ = scan_output(
            &sk.x25519,
            &sk.ml_kem,
            &od.kem_ciphertext_x25519,
            &od.kem_ciphertext_ml_kem,
            &od.output_key,
            &od.commitment,
            &bad_enc,
            od.amount_tag,
            od.view_tag_x25519,
            &spend_key,
            output_index,
        );
    }

    let _ = scan_output(
        &sk.x25519,
        &sk.ml_kem,
        &od.kem_ciphertext_x25519,
        &od.kem_ciphertext_ml_kem,
        &od.output_key,
        &od.commitment,
        &od.enc_amount,
        od.amount_tag.wrapping_add(1),
        od.view_tag_x25519,
        &spend_key,
        output_index,
    );
});

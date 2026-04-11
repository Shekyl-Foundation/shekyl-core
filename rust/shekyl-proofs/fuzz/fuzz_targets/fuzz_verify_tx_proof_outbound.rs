// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_proofs::tx_proof::{verify_outbound_proof, OnChainOutput};

fuzz_target!(|data: &[u8]| {
    // Minimum usable: 32 (txid) + 32 (spend) + 32 (x25519) + 1 (proof_byte)
    if data.len() < 97 {
        return;
    }

    let mut txid = [0u8; 32];
    txid.copy_from_slice(&data[..32]);
    let mut spend_pubkey = [0u8; 32];
    spend_pubkey.copy_from_slice(&data[32..64]);
    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(&data[64..96]);

    let proof_bytes = &data[96..];
    let address = b"fuzz-address";
    let msg = b"fuzz-msg";

    // Use 1184 bytes of ML-KEM EK (all zeros — invalid but shouldn't panic)
    let ml_kem_ek = vec![0u8; 1184];

    let on_chain = vec![OnChainOutput {
        output_key: [0u8; 32],
        commitment: [0u8; 32],
        enc_amount: [0u8; 8],
        x25519_eph_pk: [0u8; 32],
        ml_kem_ct: vec![0u8; 1088],
    }];

    let _ = verify_outbound_proof(
        proof_bytes,
        &txid,
        address,
        msg,
        &spend_pubkey,
        &x25519_pk,
        &ml_kem_ek,
        &on_chain,
    );
});

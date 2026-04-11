// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_proofs::reserve_proof::{verify_reserve_proof, ReserveOnChainOutput};

fuzz_target!(|data: &[u8]| {
    if data.len() < 65 {
        return;
    }

    let mut spend_pubkey = [0u8; 32];
    spend_pubkey.copy_from_slice(&data[..32]);

    let proof_bytes = &data[32..];
    let address = b"fuzz-address";
    let msg = b"fuzz-msg";

    let on_chain = vec![ReserveOnChainOutput {
        output_key: [0u8; 32],
        commitment: [0u8; 32],
        enc_amount: [0u8; 8],
    }];

    let _ = verify_reserve_proof(
        proof_bytes,
        address,
        msg,
        &spend_pubkey,
        &on_chain,
    );
});

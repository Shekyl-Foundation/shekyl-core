// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::{
    kem::ML_KEM_768_EK_LEN,
    output::construct_output,
};

// Exercises construct_output with arbitrary (potentially malformed) KEM public key bytes.
// The ML-KEM-768 encapsulation key is 1184 bytes; this harness feeds raw fuzzer data as
// both the x25519 public key and the ML-KEM encapsulation key. The function must return
// Err on invalid keys, never panic. This catches panics inside ml-kem's try_from_bytes
// or try_encaps on malformed ciphertext layouts.
fuzz_target!(|data: &[u8]| {
    // Need: 8 (amount) + 8 (index) + 32 (tx_key) + 32 (x25519_pk) + 1184 (ml_kem_ek)
    const MIN_LEN: usize = 8 + 8 + 32 + 32 + ML_KEM_768_EK_LEN;
    if data.len() < MIN_LEN {
        return;
    }

    let amount = u64::from_le_bytes(data[..8].try_into().unwrap());
    let output_index = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 256;

    let tx_key: [u8; 32] = data[16..48].try_into().unwrap();
    let x25519_pk: [u8; 32] = data[48..80].try_into().unwrap();
    let ml_kem_ek = &data[80..80 + ML_KEM_768_EK_LEN];

    let spend_key = [0x42u8; 32];

    let _ = construct_output(&tx_key, &x25519_pk, ml_kem_ek, &spend_key, amount, output_index);

    // Also test with wrong-length ML-KEM key (truncated)
    if data.len() >= 80 + 100 {
        let short_ek = &data[80..80 + 100];
        let _ = construct_output(&tx_key, &x25519_pk, short_ek, &spend_key, amount, output_index);
    }

    // Also test with oversized ML-KEM key
    if data.len() >= 80 + ML_KEM_768_EK_LEN + 64 {
        let long_ek = &data[80..80 + ML_KEM_768_EK_LEN + 64];
        let _ = construct_output(&tx_key, &x25519_pk, long_ek, &spend_key, amount, output_index);
    }
});

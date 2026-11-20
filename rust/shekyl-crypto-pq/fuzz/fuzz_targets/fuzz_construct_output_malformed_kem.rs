// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::{kem::ML_KEM_768_EK_LEN, output::construct_output, TxKey};

// Exercises construct_output with arbitrary (potentially malformed) KEM public key bytes.
// The ML-KEM-768 encapsulation key is 1184 bytes; this harness feeds raw fuzzer data as
// both the x25519 public key and the ML-KEM encapsulation key. The function must return
// Err on invalid keys, never panic. This catches panics inside ml-kem's try_from_bytes
// or try_encaps on malformed ciphertext layouts.
//
// The spend key is fixed and must be a valid point, or every input is
// refused as invalid key material before the KEM key is read. It was
// `[0x42; 32]`, which is not a point: the first nightly dispatch ran 22
// million inputs that all stopped there. This is the Ed25519 base point,
// compressed.
const SPEND_KEY: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fuzz_target!(|data: &[u8]| {
    // Need: 8 (amount) + 8 (index) + 32 (tx_key) + 32 (x25519_pk) + 1184 (ml_kem_ek)
    const MIN_LEN: usize = 8 + 8 + 32 + 32 + ML_KEM_768_EK_LEN;
    if data.len() < MIN_LEN {
        return;
    }

    let amount = u64::from_le_bytes(data[..8].try_into().unwrap());
    let output_index = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 256;

    let tx_key = TxKey::seeded(data[16..48].try_into().unwrap());
    let x25519_pk: [u8; 32] = data[48..80].try_into().unwrap();
    let ml_kem_ek = &data[80..80 + ML_KEM_768_EK_LEN];

    let spend_key = SPEND_KEY;

    let _ = construct_output(
        &tx_key,
        &x25519_pk,
        ml_kem_ek,
        &spend_key,
        amount,
        output_index,
    );

    // Also test with wrong-length ML-KEM key (truncated)
    if data.len() >= 80 + 100 {
        let short_ek = &data[80..80 + 100];
        let _ = construct_output(
            &tx_key,
            &x25519_pk,
            short_ek,
            &spend_key,
            amount,
            output_index,
        );
    }

    // Also test with oversized ML-KEM key
    if data.len() >= 80 + ML_KEM_768_EK_LEN + 64 {
        let long_ek = &data[80..80 + ML_KEM_768_EK_LEN + 64];
        let _ = construct_output(
            &tx_key,
            &x25519_pk,
            long_ek,
            &spend_key,
            amount,
            output_index,
        );
    }
});

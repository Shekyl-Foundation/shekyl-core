// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::kem::{
    HybridCiphertext, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation,
    ML_KEM_768_CT_LEN, ML_KEM_768_DK_LEN,
};

fuzz_target!(|data: &[u8]| {
    let kem = HybridX25519MlKem;

    // Test 1: Feed completely random bytes as ciphertext with a valid key
    if data.len() >= 32 + ML_KEM_768_CT_LEN {
        let mut x25519_ct = [0u8; 32];
        x25519_ct.copy_from_slice(&data[..32]);

        let ct = HybridCiphertext {
            x25519: x25519_ct,
            ml_kem: data[32..32 + ML_KEM_768_CT_LEN].to_vec(),
        };

        // Generate a fresh keypair and try decapsulating garbage
        if let Ok((_pk, sk)) = kem.keypair_generate() {
            let _ = kem.decapsulate(&sk, &ct);
        }
    }

    // Test 2: Wrong-length ciphertext
    if data.len() >= 33 {
        let mut x25519_ct = [0u8; 32];
        x25519_ct.copy_from_slice(&data[..32]);

        let ct = HybridCiphertext {
            x25519: x25519_ct,
            ml_kem: data[32..].to_vec(),
        };

        if let Ok((_pk, sk)) = kem.keypair_generate() {
            let _ = kem.decapsulate(&sk, &ct);
        }
    }

    // Test 3: Corrupt a valid ciphertext
    if let Ok((pk, sk)) = kem.keypair_generate() {
        if let Ok((_ss, mut ct)) = kem.encapsulate(&pk) {
            // Apply corruption from fuzz data
            for (i, &b) in data.iter().enumerate() {
                if i < ct.ml_kem.len() {
                    ct.ml_kem[i] ^= b;
                } else if i - ct.ml_kem.len() < 32 {
                    ct.x25519[i - ct.ml_kem.len()] ^= b;
                }
            }
            // Decapsulation with corrupted ciphertext should succeed
            // (ML-KEM implicit rejection) but produce a different secret
            let _ = kem.decapsulate(&sk, &ct);
        }
    }

    // Test 4: Wrong-length secret key
    if data.len() >= 32 {
        let bad_sk = HybridKemSecretKey {
            x25519: data[..32].try_into().unwrap(),
            ml_kem: data[32..].to_vec(),
        };
        let ct = HybridCiphertext {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; ML_KEM_768_CT_LEN],
        };
        let _ = kem.decapsulate(&bad_sk, &ct);
    }
});

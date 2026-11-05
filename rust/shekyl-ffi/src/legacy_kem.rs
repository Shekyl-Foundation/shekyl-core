// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hybrid KEM keypair FFI a C++ serialization test builds fixtures
//! with.

use super::legacy_types::*;

/// Generate a hybrid X25519 + ML-KEM-768 keypair.
#[no_mangle]
pub extern "C" fn shekyl_kem_keypair_generate() -> ShekylPqcKeypair {
    use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};

    let fail = ShekylPqcKeypair {
        public_key: ShekylBuffer::null(),
        secret_key: ShekylBuffer::null(),
        success: false,
    };

    let kem = HybridX25519MlKem;
    match kem.keypair_generate() {
        Ok((pk, sk)) => {
            let mut pk_bytes = Vec::new();
            pk_bytes.extend_from_slice(&pk.x25519);
            pk_bytes.extend_from_slice(&pk.ml_kem);

            let mut sk_bytes = Vec::new();
            sk_bytes.extend_from_slice(&sk.x25519);
            sk_bytes.extend_from_slice(&sk.ml_kem);

            ShekylPqcKeypair {
                public_key: ShekylBuffer::from_vec(pk_bytes),
                secret_key: ShekylBuffer::from_vec(sk_bytes),
                success: true,
            }
        }
        Err(_) => fail,
    }
}

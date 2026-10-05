// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 2: skip construction entirely and write the struct literal.
//!
//! The wire fields are parameters, not tuple-struct constructions: that
//! way this fixture tests `OutputData` field privacy (`E0451`) and the
//! byte-constructor fixture tests the type. A field-privacy error aborts
//! compilation before later bodies are type-checked, so a single fixture
//! holding both routes reports only the first.

use shekyl_crypto_pq::leaf_commitment::PqcLeafCommitment;
use shekyl_crypto_pq::output::{EncryptedOutputField, OutputData};

pub fn literal(
    enc_amount: EncryptedOutputField,
    enc_label: EncryptedOutputField,
) -> OutputData {
    OutputData {
        output_key: [0u8; 32],
        commitment: [0u8; 32],
        enc_amount,
        enc_label,
        view_tag_prefilter: 0,
        kem_ciphertext_x25519: [0u8; 32],
        kem_ciphertext_ml_kem: Vec::new(),
        pqc_public_key: Vec::new(),
        pqc_leaf: PqcLeafCommitment {
            point: [0u8; 32],
            record: [0u8; 32],
            blind: [0u8; 32],
            record_blind: [0u8; 32],
            counter: 0,
        },
        y: [0u8; 32],
        z: [0u8; 32],
        k_amount: [0u8; 32],
        k_label: [0u8; 32],
    }
}

fn main() {}

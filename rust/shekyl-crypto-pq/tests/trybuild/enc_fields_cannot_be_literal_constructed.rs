// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 2: skip construction entirely and write the struct literal.
//!
//! A separate fixture from route 1 on purpose. Field-privacy errors abort
//! the compilation before later bodies are type-checked, so a single fixture
//! holding both routes reports only the first — and would keep passing if
//! the literal route alone were opened up.

use shekyl_crypto_pq::output::OutputData;

pub fn literal() -> OutputData {
    OutputData {
        output_key: [0u8; 32],
        commitment: [0u8; 32],
        enc_amount: [0u8; 8],
        amount_tag: 0,
        enc_label: [0u8; 8],
        label_tag: 0,
        view_tag_prefilter: 0,
        kem_ciphertext_x25519: [0u8; 32],
        kem_ciphertext_ml_kem: Vec::new(),
        pqc_public_key: Vec::new(),
        h_pqc: [0u8; 32],
        y: [0u8; 32],
        z: [0u8; 32],
        k_amount: [0u8; 32],
        k_label: [0u8; 32],
    }
}

fn main() {}

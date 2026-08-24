// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 1: take a legitimately constructed `OutputData` and overwrite the
//! ciphertext/tag bytes with chosen constants, then spend them through
//! `enc_label_wire()` / `enc_amount_wire()`.
//!
//! All four fields are written deliberately: the `.stderr` snapshot then
//! names all four, so widening *any one* of them back to `pub` changes the
//! output and turns this test red. Writing only the label pair would leave
//! the amount pair unguarded.

use shekyl_crypto_pq::output::OutputData;

pub fn overwrite(od: &mut OutputData) {
    od.enc_label = [0u8; 8];
    od.label_tag = 0;
    od.enc_amount = [0u8; 8];
    od.amount_tag = 0;
}

fn main() {}

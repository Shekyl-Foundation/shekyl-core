// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 1: take a legitimately constructed `OutputData` and overwrite the
//! stored wire fields with a value this crate already holds.
//!
//! The forged value is a parameter, not a tuple-struct construction: that
//! way this fixture tests *field privacy* and the byte-constructor fixture
//! tests the type. Both fields are written so the `.stderr` snapshot names
//! both; widening either back to `pub` changes the output and turns this
//! red.

use shekyl_crypto_pq::output::{EncryptedOutputField, OutputData};

pub fn overwrite(od: &mut OutputData, forged: EncryptedOutputField) {
    od.enc_label = forged;
    od.enc_amount = forged;
}

fn main() {}

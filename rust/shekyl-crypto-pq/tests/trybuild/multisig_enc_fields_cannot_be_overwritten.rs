// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 1 for a multisig output: take a legitimately constructed
//! `MultisigOutputData` and overwrite its stored wire fields with a value
//! this crate already holds. Both fields are written so the `.stderr`
//! snapshot names both; widening either to `pub` turns this red.

use shekyl_crypto_pq::multisig_output::MultisigOutputData;
use shekyl_crypto_pq::output::EncryptedOutputField;

pub fn overwrite(od: &mut MultisigOutputData, forged: EncryptedOutputField) {
    od.enc_label = forged;
    od.enc_amount = forged;
}

fn main() {}

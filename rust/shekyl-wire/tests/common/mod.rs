// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared helpers for the wire crate's integration tests.

use shekyl_wire::tx_extra::{serialize, TxExtraField, HYBRID_KEM_CT_BYTES, PQC_LEAF_HASH_BYTES};

/// The `tx_extra` every transaction with outputs must carry (CEN-I19,
/// `GENESIS_TX_WIRE_FORMAT.md` §9.6a): exactly one `0x06` of `1120·n` bytes and
/// one `0x07` of `32·n`, and neither when `n == 0`.
///
/// The shape rule reads counts and lengths only, so the payload bytes are
/// arbitrary filler — a fixture needs a *valid* transaction in every respect
/// except the one thing its test is about, and before this rule existed these
/// fixtures were quietly building transactions consensus would reject.
#[must_use]
pub fn conforming_pqc_extra(n_outputs: usize) -> Vec<u8> {
    if n_outputs == 0 {
        return Vec::new();
    }
    serialize(&[
        TxExtraField::PqcKemCiphertext(vec![0x6a; HYBRID_KEM_CT_BYTES * n_outputs]),
        TxExtraField::PqcLeafHashes(vec![0x7b; PQC_LEAF_HASH_BYTES * n_outputs]),
    ])
    .expect("conforming PQC tx_extra serializes")
}

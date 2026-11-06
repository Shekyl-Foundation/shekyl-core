// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CT base hash binds every byte of every output's encrypted label and
//! encrypted amount.
//!
//! `fcmp_base_hash` is `H(base)`, the component of the signing message that
//! carries the outputs' encrypted fields; a byte the hash did not cover
//! could be changed after signing without invalidating the signature. The
//! full preimage is pinned elsewhere (`pqc_signing_preimage_kat.rs`), but a
//! pin of the whole does not show which bytes reach it. The C++
//! `enc_label_binds_ctsig_base_prehash` flipped one label byte and one
//! amount byte of the C++ hash; this flips each byte of both fields, for
//! two outputs, through the Rust hash the signer and verifier use.

use shekyl_types::BlockHash;
use shekyl_wire::transaction::{fcmp_base_hash, CT_ENC_FIELD_LEN};
use shekyl_wire::CtBase;

const OUTPUTS: usize = 2;

fn base() -> CtBase {
    CtBase {
        enc_amounts: (0..OUTPUTS)
            .map(|o| std::array::from_fn(|i| (0x10 + 16 * o + i) as u8))
            .collect(),
        enc_labels: (0..OUTPUTS)
            .map(|o| std::array::from_fn(|i| (0xA0 + 16 * o + i) as u8))
            .collect(),
        commitments: (0..OUTPUTS).map(|o| [0x50 + o as u8; 32]).collect(),
    }
}

fn hash(base: &CtBase) -> [u8; 32] {
    fcmp_base_hash(1_000_000, &BlockHash::from_bytes([0xCD; 32]), base).to_bytes()
}

#[test]
fn every_enc_label_byte_moves_the_base_hash() {
    let original = hash(&base());
    for output in 0..OUTPUTS {
        for byte in 0..CT_ENC_FIELD_LEN {
            let mut tampered = base();
            tampered.enc_labels[output][byte] ^= 0x01;
            assert_ne!(
                hash(&tampered),
                original,
                "output {output}, enc_label byte {byte}"
            );
        }
    }
}

#[test]
fn every_enc_amount_byte_moves_the_base_hash() {
    let original = hash(&base());
    for output in 0..OUTPUTS {
        for byte in 0..CT_ENC_FIELD_LEN {
            let mut tampered = base();
            tampered.enc_amounts[output][byte] ^= 0x01;
            assert_ne!(
                hash(&tampered),
                original,
                "output {output}, enc_amount byte {byte}"
            );
        }
    }
}

/// A label byte and the same amount byte are distinct positions: moving the
/// same bit in each gives two different hashes, so the two arrays are not
/// read as one.
#[test]
fn a_label_flip_and_an_amount_flip_are_different_messages() {
    let mut label = base();
    label.enc_labels[0][0] ^= 0x01;
    let mut amount = base();
    amount.enc_amounts[0][0] ^= 0x01;
    assert_ne!(hash(&label), hash(&amount));
}

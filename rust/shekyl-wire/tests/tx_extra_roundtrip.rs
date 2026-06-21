// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx_extra` parser tests (GENESIS_TX_WIRE_FORMAT.md §9.6a).
//!
//! The coinbase case is **live-oracle** validated (the real `extra` blob must
//! parse and re-serialize byte-identically, and its 0x06/0x07 fields split by
//! output count). A synthetic case exercises the other field kinds.

use shekyl_wire::tx_extra::{
    self, PqcOwnershipEntry, TxExtraField, HYBRID_KEM_CT_BYTES, ML_KEM_768_CT_BYTES,
    PQC_LEAF_HASH_BYTES, TX_EXTRA_TAG_NONCE,
};
use shekyl_wire::Block;

#[test]
fn coinbase_tx_extra_round_trips_and_splits_per_output() {
    let blk = Block::from_bytes(include_bytes!("vectors/regtest_coinbase_h0.block"))
        .expect("parse coinbase block");
    let extra = &blk.miner_transaction.prefix.extra;

    let fields = tx_extra::parse(extra).expect("parse coinbase tx_extra");
    assert_eq!(
        tx_extra::serialize(&fields).expect("re-serialize coinbase tx_extra"),
        *extra,
        "tx_extra must re-serialize byte-identically to the oracle blob"
    );

    // Structure: tx pubkey, then the per-output PQC scan fields.
    assert!(
        matches!(fields.first(), Some(TxExtraField::PubKey(_))),
        "first field is the tx pubkey"
    );

    let n_out = blk.miner_transaction.prefix.outputs.len();
    let mut saw_kem = false;
    let mut saw_leaf = false;
    for f in &fields {
        match f {
            TxExtraField::PqcKemCiphertext(blob) => {
                assert_eq!(blob.len(), n_out * HYBRID_KEM_CT_BYTES);
                let cts = tx_extra::pqc_kem_per_output(blob).unwrap();
                assert_eq!(cts.len(), n_out);
                assert_eq!(cts[0].ml_kem.len(), ML_KEM_768_CT_BYTES);
                saw_kem = true;
            }
            TxExtraField::PqcLeafHashes(blob) => {
                assert_eq!(blob.len(), n_out * PQC_LEAF_HASH_BYTES);
                assert_eq!(
                    tx_extra::pqc_leaf_hashes_per_output(blob).unwrap().len(),
                    n_out
                );
                saw_leaf = true;
            }
            _ => {}
        }
    }
    assert!(saw_kem && saw_leaf, "coinbase extra carries 0x06 and 0x07");
}

#[test]
fn synthetic_tx_extra_field_kinds_round_trip() {
    let fields = vec![
        TxExtraField::PubKey([0x11; 32]),
        TxExtraField::AdditionalPubKeys(vec![[0x22; 32], [0x23; 32]]),
        TxExtraField::PqcOwnership(vec![PqcOwnershipEntry {
            output_index: 0,
            scheme_id: 1,
            group_id: [0u8; 32],
        }]),
        TxExtraField::Nonce(vec![0xAB, 0xCD, 0xEF]),
        // two outputs' worth of 0x06 / 0x07 payloads
        TxExtraField::PqcKemCiphertext(vec![0x44; HYBRID_KEM_CT_BYTES * 2]),
        TxExtraField::PqcLeafHashes(vec![0x55; PQC_LEAF_HASH_BYTES * 2]),
        // padding is last (consumes to end)
        TxExtraField::Padding(5),
    ];
    let bytes = tx_extra::serialize(&fields).expect("serialize valid field kinds");
    assert_eq!(
        tx_extra::parse(&bytes).unwrap(),
        fields,
        "field kinds must round-trip"
    );

    // The 2-output 0x06 blob splits into two hybrid KEM ciphertexts.
    if let TxExtraField::PqcKemCiphertext(blob) = &fields[4] {
        assert_eq!(tx_extra::pqc_kem_per_output(blob).unwrap().len(), 2);
    }
}

#[test]
fn unknown_tag_is_rejected() {
    let err = tx_extra::parse(&[0xFE, 0x01, 0x02]).expect_err("unknown tag must be rejected");
    assert!(err.to_string().contains("unknown tag"), "unexpected: {err}");
}

#[test]
fn oversized_padding_and_nonce_rejected_on_serialize() {
    // Oracle parity: C++ caps padding and nonce at 255 (tx_extra.h). serialize() is
    // symmetric with parse() — it rejects a self-invalid field rather than emitting a
    // blob parse would reject.
    let err = tx_extra::serialize(&[TxExtraField::Padding(256)])
        .expect_err("padding > 255 must be rejected at serialize");
    assert!(err.to_string().contains("padding run"), "{err}");

    let err = tx_extra::serialize(&[TxExtraField::Nonce(vec![0u8; 256])])
        .expect_err("nonce > 255 must be rejected at serialize");
    assert!(err.to_string().contains("nonce"), "{err}");
}

#[test]
fn padding_must_be_last_on_serialize() {
    // Padding consumes to end on parse, so a non-last padding field is self-invalid.
    let err = tx_extra::serialize(&[TxExtraField::Padding(2), TxExtraField::PubKey([0u8; 32])])
        .expect_err("non-last padding must be rejected");
    assert!(err.to_string().contains("last field"), "{err}");
}

#[test]
fn oversized_nonce_rejected_before_allocation_on_parse() {
    // A hostile nonce length is rejected at parse before the payload is allocated:
    // tag 0x02, varint(1_000_000), no payload — must error on the length, not EOF.
    let mut blob = vec![TX_EXTRA_TAG_NONCE];
    shekyl_wire::varint::write_varint(1_000_000usize, &mut blob).unwrap();
    let err = tx_extra::parse(&blob).expect_err("oversized nonce length must be rejected");
    assert!(err.to_string().contains("nonce"), "{err}");
}

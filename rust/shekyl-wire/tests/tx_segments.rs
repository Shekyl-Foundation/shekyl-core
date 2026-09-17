// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Transaction::write_segments` — the chain store's three-way cut of a
//! transaction blob (S-CHAIN-W SCW-9; `db_lmdb.cpp` `add_transaction_data`).
//!
//! The cut is layout, not consensus: the segments concatenate to exactly
//! `Transaction::write`, and the first two concatenate to exactly the C++
//! `serialize_base` framing (the `pruned_hex` the parity fixture pins), so
//! `txs_pruned` / `txs_pqc_auths` / `txs_prunable` hold byte-identical rows
//! on both engines. Three shapes: a full FCMP++ spend (both fixtures), and
//! the coinbase (no pqc_auths, no prunable).

use std::path::PathBuf;

use serde_json::Value;
use shekyl_types::PrunableHash;
use shekyl_wire::{Block, Transaction};

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixture(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture")).expect("json")
}

#[test]
fn spend_segments_concatenate_to_the_blob_and_the_first_two_to_serialize_base() {
    let pin = fixture("tests/fixtures/pruned_tx_hash_parity_v1.json");
    let tx_bytes = hex_bytes(pin["tx_hex"].as_str().expect("tx_hex"));
    let pruned_bytes = hex_bytes(pin["pruned_hex"].as_str().expect("pruned_hex"));
    let tx = Transaction::from_bytes(&tx_bytes).expect("parse spend");

    let segments = tx.write_segments().expect("segments");
    assert_eq!(segments.concat(), tx_bytes, "concat == Transaction::write");
    assert_eq!(segments.concat(), tx.serialize());

    // C++ `unprunable_size` is the end of the tx-level pqc_auths, so the
    // pruned form the daemon serves is exactly `pruned ‖ pqc_auths`.
    let mut unprunable = segments.pruned.clone();
    unprunable.extend_from_slice(&segments.pqc_auths);
    assert_eq!(
        unprunable, pruned_bytes,
        "pruned ‖ pqc_auths == serialize_base"
    );

    assert!(
        !segments.pqc_auths.is_empty(),
        "a spend carries per-input PQC auths"
    );
    assert!(
        !segments.prunable.is_empty(),
        "a full spend carries a prunable region"
    );
    assert_eq!(
        segments.prunable,
        tx_bytes[pruned_bytes.len()..],
        "prunable is the tail past unprunable_size"
    );
}

#[test]
fn prunable_hash_is_keccak_of_the_prunable_segment_on_both_shapes() {
    // Spend: the pinned `prunable_hash_hex` (C++ `calculate_transaction_prunable_hash`).
    let pin = fixture("tests/fixtures/pruned_tx_hash_parity_v1.json");
    let tx = Transaction::from_bytes(&hex_bytes(pin["tx_hex"].as_str().expect("tx_hex")))
        .expect("parse spend");
    let want = hex_bytes(
        pin["prunable_hash_hex"]
            .as_str()
            .expect("prunable_hash_hex"),
    );
    assert_eq!(tx.prunable_hash().as_bytes().as_slice(), want.as_slice());
    assert_eq!(
        tx.prunable_hash().to_bytes(),
        shekyl_crypto_hash::keccak256(&tx.write_segments().expect("segments").prunable)
    );

    // Coinbase: an empty region hashes to keccak256(""), which is what the
    // C++ store writes to `txs_prunable_hash` — NOT the null hash the txid
    // substitutes for its third component.
    let block =
        Block::from_bytes(include_bytes!("vectors/regtest_coinbase_h1.block")).expect("block");
    let miner = &block.miner_transaction;
    assert_eq!(
        miner.prunable_hash().to_bytes(),
        shekyl_crypto_hash::keccak256(&[])
    );
    assert_ne!(miner.prunable_hash().to_bytes(), [0u8; 32]);
    // And the txid is unchanged by having factored the digest out.
    assert_eq!(
        miner.hash(),
        miner.hash_with_supplied_prunable(PrunableHash::from_bytes([0x77; 32])),
        "a coinbase txid ignores any supplied digest (Null arm)"
    );
}

#[test]
fn live_oracle_spend_segments_concatenate_to_the_daemon_accepted_bytes() {
    let pin = fixture("tests/fixtures/live_oracle_spend_v1.json");
    let tx_bytes = hex_bytes(pin["tx_hex"].as_str().expect("tx_hex"));
    let tx = Transaction::from_bytes(&tx_bytes).expect("parse live spend");
    let segments = tx.write_segments().expect("segments");
    assert_eq!(segments.concat(), tx_bytes);
    assert!(!segments.pqc_auths.is_empty());
    assert!(!segments.prunable.is_empty());
}

#[test]
fn coinbase_segments_are_the_whole_blob_and_two_empty_tails() {
    for (height, blob) in [
        (
            0u64,
            include_bytes!("vectors/regtest_coinbase_h0.block").as_slice(),
        ),
        (
            1,
            include_bytes!("vectors/regtest_coinbase_h1.block").as_slice(),
        ),
        (
            2,
            include_bytes!("vectors/regtest_coinbase_h2.block").as_slice(),
        ),
    ] {
        let block = Block::from_bytes(blob).expect("block");
        let miner = &block.miner_transaction;
        let segments = miner.write_segments().expect("segments");
        assert_eq!(segments.pruned, miner.serialize(), "height {height}");
        assert!(
            segments.pqc_auths.is_empty(),
            "height {height}: a coinbase has no pqc_auths segment (no row in LMDB)"
        );
        assert!(
            segments.prunable.is_empty(),
            "height {height}: a coinbase's prunable segment is empty (an empty row in LMDB)"
        );
        assert_eq!(segments.concat(), miner.serialize());
    }
}

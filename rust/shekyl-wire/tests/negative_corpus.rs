// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative / boundary corpus for the coinbase slice.
//!
//! A serializer's freeze surface is **accept *and* reject** (GENESIS_TX_WIRE_FORMAT.md
//! §7: "identical accept/reject", not round-trip). These pin the rejects the
//! coinbase path must enforce: the §12 exact-consumption cut (trailing bytes —
//! the deliberate creation cut over the C++ oracle's malleability gap),
//! truncation, and unknown tags (parser-differential surface). Canonical-varint
//! rejects are unit-tested in `src/varint.rs`.

use shekyl_wire::transaction::{CT_TYPE_NULL, TAG_INPUT_GEN, TAG_OUTPUT_TAGGED_KEY};
use shekyl_wire::Block;

/// Build a minimal, fully-controlled coinbase blob (timestamp/nonce/keys zeroed)
/// so individual fields can be made invalid in isolation.
fn minimal_coinbase(input_tag: u8, ct_type: u8, include_null_base: bool) -> Vec<u8> {
    let mut b = Vec::new();
    // BlockHeader: major=1, minor=0, timestamp=0, prev[32], nonce[4], root[32].
    b.push(0x01);
    b.push(0x00);
    b.push(0x00);
    b.extend_from_slice(&[0u8; 32]);
    b.extend_from_slice(&[0u8; 4]);
    b.extend_from_slice(&[0u8; 32]);
    // Transaction: version=3, unlock_time=0.
    b.push(0x03);
    b.push(0x00);
    // inputs: count=1, [tag] gen-height=0.
    b.push(0x01);
    b.push(input_tag);
    b.push(0x00);
    // outputs: count=1, amount=0, tagged_key, key[32], view_tag=0.
    b.push(0x01);
    b.push(0x00);
    b.push(TAG_OUTPUT_TAGGED_KEY);
    b.extend_from_slice(&[0u8; 32]);
    b.push(0x00);
    // extra: len=0.
    b.push(0x00);
    // ct: type, then (for Null) the committed base for one output (9+9+32).
    b.push(ct_type);
    if include_null_base {
        b.extend_from_slice(&[0u8; 9]);
        b.extend_from_slice(&[0u8; 9]);
        b.extend_from_slice(&[0u8; 32]);
    }
    // block tail: n_tx=0.
    b.push(0x00);
    b
}

#[test]
fn minimal_synthetic_coinbase_round_trips() {
    let bytes = minimal_coinbase(TAG_INPUT_GEN, CT_TYPE_NULL, true);
    let block = Block::from_bytes(&bytes).expect("valid synthetic coinbase");
    assert_eq!(block.number(), Some(0));
    assert_eq!(block.serialize(), bytes);
}

#[test]
fn rejects_trailing_bytes() {
    // §12 exact-consumption: a valid blob plus one appended byte must be rejected.
    let mut bytes = include_bytes!("vectors/regtest_coinbase_h0.block").to_vec();
    bytes.push(0x00);
    let err = Block::from_bytes(&bytes).expect_err("trailing byte must be rejected");
    assert!(
        err.to_string().contains("trailing"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_truncation() {
    let blob = include_bytes!("vectors/regtest_coinbase_h0.block");
    // Truncated mid-ct-base (one byte short).
    assert!(
        Block::from_bytes(&blob[..blob.len() - 1]).is_err(),
        "one-byte-short blob must be rejected"
    );
    // Truncated mid-header.
    assert!(
        Block::from_bytes(&blob[..40]).is_err(),
        "mid-header truncation must be rejected"
    );
}

#[test]
fn rejects_unknown_input_tag() {
    let bytes = minimal_coinbase(0xAB, CT_TYPE_NULL, true);
    let err = Block::from_bytes(&bytes).expect_err("unknown input tag must be rejected");
    assert!(
        err.to_string().contains("input tag"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_unsupported_ct_type() {
    // 0x05 is neither Null (0x00) nor Fcmp (0x01) — an unknown ct type must reject.
    let bytes = minimal_coinbase(TAG_INPUT_GEN, 0x05, false);
    let err = Block::from_bytes(&bytes).expect_err("unsupported ct type must be rejected");
    assert!(
        err.to_string().contains("ct type"),
        "unexpected error: {err}"
    );
}

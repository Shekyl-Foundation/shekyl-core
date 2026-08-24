// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte parity with epee for the `.bin` methods.
//!
//! The JSON vectors are compared *parsed*, because two JSON documents can
//! differ in whitespace and mean the same thing. portable_storage has no
//! such slack: the wire is the bytes. So these compare `Vec<u8>` to
//! `Vec<u8>`, and the vectors are the exact output of
//! `epee::serialization::store_t_to_binary` captured before the C++ struct
//! was deleted (`tests/unit_tests/rpc_oracle_vectors.cpp` at the capture
//! commit).

use shekyl_rpc_types::{GetOIndexesRequest, GetOIndexesResponse, RpcStatus};

/// The emitter's `tagged_hash(31)`: byte i = (i*7 + 31) & 0xff.
fn tagged_txid() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let i = u8::try_from(i).expect("32 fits u8");
        *byte = i.wrapping_mul(7).wrapping_add(31);
    }
    out
}

fn assert_bytes(vector: &[u8], ours: &[u8], name: &str) {
    assert_eq!(
        ours.len(),
        vector.len(),
        "{name}: length differs from epee's ({} vs {})",
        ours.len(),
        vector.len()
    );
    assert_eq!(
        ours,
        vector,
        "{name}: bytes differ from epee's capture\n  ours   = {}\n  oracle = {}",
        hex::encode(ours),
        hex::encode(vector)
    );
}

/// The request, whose `txid` is POD-as-blob: 32 raw bytes, not 64 hex
/// characters. Encoding it as hex would produce a document epee accepts and
/// a daemon reads as a different transaction — the failure this vector
/// exists to make loud.
#[test]
fn get_o_indexes_request_matches_the_oracle_bytes() {
    let built = GetOIndexesRequest {
        txid: tagged_txid(),
    }
    .to_bin()
    .expect("encode");
    let oracle = include_bytes!("vectors/rpc/get_o_indexes_request_v1.bin");
    assert_bytes(oracle, &built, "get_o_indexes request");
    assert!(
        built.windows(32).any(|w| w == tagged_txid()),
        "the txid must appear as raw bytes in the document"
    );

    let back = GetOIndexesRequest::from_bin(oracle).expect("decode epee's own bytes");
    assert_eq!(back.txid, tagged_txid());
}

/// The response, over values that catch a varint or width mistake: 0, 1, a
/// small number, 2^32, and u64::MAX.
#[test]
fn get_o_indexes_response_matches_the_oracle_bytes() {
    let built = GetOIndexesResponse {
        status: RpcStatus::ok(),
        o_indexes: vec![0, 1, 42, 4_294_967_296, u64::MAX],
    }
    .to_bin()
    .expect("encode");
    let oracle = include_bytes!("vectors/rpc/get_o_indexes_response_v1.bin");
    assert_bytes(oracle, &built, "get_o_indexes response");

    let back = GetOIndexesResponse::from_bin(oracle).expect("decode epee's own bytes");
    assert!(back.status.is_ok());
    assert_eq!(back.o_indexes, vec![0, 1, 42, 4_294_967_296, u64::MAX]);
}

/// A transaction with no indices. epee drops the empty sequence from the
/// document, so writing `o_indexes: []` would produce bytes epee never
/// emits — and the wallet client, which reads a missing key as empty, would
/// still work, hiding the divergence until something stricter read it.
/// Removing the `is_empty` guard in `to_bin` turns this red.
#[test]
fn an_empty_index_list_is_absent_not_an_empty_array() {
    let built = GetOIndexesResponse {
        status: RpcStatus::ok(),
        o_indexes: Vec::new(),
    }
    .to_bin()
    .expect("encode");
    let oracle = include_bytes!("vectors/rpc/get_o_indexes_response_empty_v1.bin");
    assert_bytes(oracle, &built, "get_o_indexes empty response");
    assert!(
        !built.windows(9).any(|w| w == b"o_indexes"),
        "an empty list must not put the key in the document at all"
    );

    let back = GetOIndexesResponse::from_bin(oracle).expect("decode");
    assert!(back.o_indexes.is_empty(), "absence decodes as empty");
}

/// Documents that are not this message are refused rather than half-read.
#[test]
fn malformed_documents_are_refused() {
    assert!(GetOIndexesRequest::from_bin(b"not portable storage").is_err());
    // A well-formed document missing the field it is named for.
    let empty = GetOIndexesResponse {
        status: RpcStatus::ok(),
        o_indexes: Vec::new(),
    }
    .to_bin()
    .expect("encode");
    assert!(
        GetOIndexesRequest::from_bin(&empty).is_err(),
        "a response is not a request"
    );
}

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

use shekyl_portable_storage::{load_from_binary, store_to_binary, Array, Limits, Section, Value};
use shekyl_rpc_types::{
    BlockEntry, BlockTx, BlockTxSkeleton, GetBlocksByHeightRequest, GetBlocksByHeightResponse,
    GetOIndexesRequest, GetOIndexesResponse, RpcStatus,
};

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

// ── /get_blocks_by_height.bin ───────────────────────────────────────────────

fn tagged_blob(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            u8::try_from(i & 0xff)
                .expect("masked")
                .wrapping_mul(7)
                .wrapping_add(tag)
        })
        .collect()
}

fn tagged_hash(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&tagged_blob(tag, 32));
    out
}

/// The request without `prune`: the switch is off by default and absent
/// from the document when off (IG-4), so epee's capture is still this
/// request's bytes.
#[test]
fn get_blocks_by_height_request_matches_the_oracle_bytes() {
    let built = GetBlocksByHeightRequest {
        heights: vec![0, 1, 4_294_967_296, u64::MAX],
        prune: false,
    }
    .to_bin()
    .expect("encode");
    let oracle = include_bytes!("vectors/rpc/get_blocks_by_height_request_v1.bin");
    assert_bytes(oracle, &built, "get_blocks_by_height request");
    assert!(
        !built.windows(5).any(|w| w == b"prune"),
        "an off switch must not put the key in the document"
    );

    let back = GetBlocksByHeightRequest::from_bin(oracle).expect("decode epee's own bytes");
    assert_eq!(back.heights, vec![0, 1, 4_294_967_296, u64::MAX]);
    assert!(!back.prune);
}

/// The request with `prune` (`SB-Q2`): a case the oracle never emitted, so
/// this vector is the 3.64 encoder's own, pinned so a later change to the
/// switch's key or type is a decision and not a drift.
#[test]
fn get_blocks_by_height_pruned_request_matches_the_pinned_bytes() {
    let built = GetBlocksByHeightRequest {
        heights: vec![0, 1],
        prune: true,
    }
    .to_bin()
    .expect("encode");
    let pinned = include_bytes!("vectors/rpc/get_blocks_by_height_request_prune_v1.bin");
    assert_bytes(pinned, &built, "get_blocks_by_height pruned request");

    let back = GetBlocksByHeightRequest::from_bin(pinned).expect("decode");
    assert_eq!(back.heights, vec![0, 1]);
    assert!(back.prune);
}

/// The fixture `_v1` captured and `_v2` carries: two blocks, one with two
/// whole bodies and one with none.
fn two_blocks_whole() -> GetBlocksByHeightResponse {
    GetBlocksByHeightResponse {
        status: RpcStatus::ok(),
        blocks: vec![
            BlockEntry {
                block: tagged_blob(11, 24),
                txs: vec![
                    BlockTx::Full(tagged_blob(31, 16)),
                    BlockTx::Full(tagged_blob(41, 8)),
                ],
            },
            BlockEntry {
                block: tagged_blob(53, 12),
                txs: Vec::new(),
            },
        ],
    }
}

/// Two blocks, one with transactions and one without. `_v2` is the 3.64
/// shape (`SB-Q2`): each listed transaction is a section tagged by `form`
/// so the slot can carry a skeleton or an archived state in the block's
/// order. None of `pruned`, `block_weight` or `attestation_witness`
/// appears — C++'s `block_complete_entry` members this wire never carried.
#[test]
fn get_blocks_by_height_response_matches_the_v2_bytes() {
    let built = two_blocks_whole().to_bin().expect("encode");
    let vector = include_bytes!("vectors/rpc/get_blocks_by_height_response_v2.bin");
    assert_bytes(vector, &built, "get_blocks_by_height response");

    for absent in ["pruned", "block_weight", "attestation_witness"] {
        assert!(
            !built.windows(absent.len()).any(|w| w == absent.as_bytes()),
            "{absent} must not reach this wire"
        );
    }

    let back = GetBlocksByHeightResponse::from_bin(vector).expect("decode");
    assert_eq!(back, two_blocks_whole());
    assert!(
        back.blocks[1].txs.is_empty(),
        "a block with no transactions decodes as empty, not as an error"
    );
}

/// `_v2` is `_v1` reshaped and nothing else: every string in a `_v1` `txs`
/// array becomes the section `{form: 1, blob}`, the keys around it
/// untouched. The reshaping is written as code over `_v1`'s own bytes and
/// must produce `_v2`'s exactly, so a hand-edited `_v2` fails here rather
/// than standing as its own authority.
#[test]
fn blocks_by_height_v2_is_v1_with_each_body_reshaped_into_a_full_slot() {
    let v1 = include_bytes!("vectors/rpc/get_blocks_by_height_response_v1.bin");
    let v2 = include_bytes!("vectors/rpc/get_blocks_by_height_response_v2.bin");
    let root = load_from_binary(v1, Limits::HTTP_BIN).expect("v1 decodes");
    let Some(Value::Array(Array::Object(blocks))) = root.get("blocks") else {
        panic!("v1 carries a block list");
    };
    let mut reshaped_blocks = Vec::with_capacity(blocks.len());
    let mut bodies = 0;
    for block in blocks {
        let mut out = Section::new();
        for (key, value) in block.iter() {
            match (key, value) {
                ("txs", Value::Array(Array::Bytes(blobs))) => {
                    let slots = blobs
                        .iter()
                        .map(|blob| {
                            bodies += 1;
                            let mut slot = Section::new();
                            slot.insert("form", Value::UInt8(1));
                            slot.insert("blob", Value::Bytes(blob.clone()));
                            slot
                        })
                        .collect();
                    out.insert("txs", Value::Array(Array::Object(slots)));
                }
                (other, value) => out.insert(other, value.clone()),
            }
        }
        reshaped_blocks.push(out);
    }
    assert_eq!(
        bodies, 2,
        "v1 carries exactly the two bodies the fixture has"
    );
    let mut reshaped = Section::new();
    for (key, value) in root.iter() {
        match key {
            "blocks" => reshaped.insert(
                "blocks",
                Value::Array(Array::Object(reshaped_blocks.clone())),
            ),
            other => reshaped.insert(other, value.clone()),
        }
    }
    let derived = store_to_binary(&reshaped).expect("encode");
    assert_bytes(v2, &derived, "get_blocks_by_height v2 derived from v1");
}

/// The pruned form (`SB-Q2`): every slot is its skeleton. A case `_v1`
/// could not express — epee's `txs` were strings — so this vector is the
/// 3.64 encoder's own. Two skeletons, one whose txid has the third
/// operand and one whose does not (`pqc_auth_hash` absent from its
/// section).
#[test]
fn get_blocks_by_height_pruned_response_matches_the_pinned_bytes() {
    let reply = GetBlocksByHeightResponse {
        status: RpcStatus::ok(),
        blocks: vec![BlockEntry {
            block: tagged_blob(11, 24),
            txs: vec![
                BlockTx::Skeleton(BlockTxSkeleton {
                    unprunable: tagged_blob(31, 16),
                    prunable_hash: tagged_hash(61),
                    pqc_auth_hash: Some(tagged_hash(71)),
                    archival_len: 4_294_967_296,
                }),
                BlockTx::Skeleton(BlockTxSkeleton {
                    unprunable: tagged_blob(41, 8),
                    prunable_hash: tagged_hash(81),
                    pqc_auth_hash: None,
                    archival_len: 0,
                }),
            ],
        }],
    };
    let built = reply.to_bin().expect("encode");
    let pinned = include_bytes!("vectors/rpc/get_blocks_by_height_response_skeleton_v1.bin");
    assert_bytes(pinned, &built, "get_blocks_by_height pruned response");
    assert_eq!(
        built.windows(13).filter(|w| *w == b"pqc_auth_hash").count(),
        1,
        "the key appears once: on the slot whose txid has the operand"
    );
    assert_eq!(
        GetBlocksByHeightResponse::from_bin(pinned).expect("decode"),
        reply
    );
}

/// The full form past the horizon (`PDM-Q10`): a body this node discarded
/// is the slot state `archived` with its shard, beside a whole body, in
/// the block's order; the height does not fail. A case no predecessor
/// could express, pinned as the 3.64 encoder's own.
#[test]
fn get_blocks_by_height_archived_response_matches_the_pinned_bytes() {
    let reply = GetBlocksByHeightResponse {
        status: RpcStatus::ok(),
        blocks: vec![BlockEntry {
            block: tagged_blob(11, 24),
            txs: vec![
                BlockTx::Full(tagged_blob(31, 16)),
                BlockTx::Archived {
                    tx_hash: tagged_hash(91),
                    shard: 7,
                },
            ],
        }],
    };
    let built = reply.to_bin().expect("encode");
    let pinned = include_bytes!("vectors/rpc/get_blocks_by_height_response_archived_v1.bin");
    assert_bytes(pinned, &built, "get_blocks_by_height archived response");
    assert_eq!(
        GetBlocksByHeightResponse::from_bin(pinned).expect("decode"),
        reply
    );
}

/// A slot whose `form` tag names no form is refused, not read as empty.
#[test]
fn an_unknown_slot_form_is_refused() {
    let mut slot = Section::new();
    slot.insert("form", Value::UInt8(9));
    slot.insert("blob", Value::Bytes(vec![1, 2, 3]));
    let mut block = Section::new();
    block.insert("block", Value::Bytes(vec![4, 5]));
    block.insert("txs", Value::Array(Array::Object(vec![slot])));
    let mut root = Section::new();
    root.insert("status", Value::Bytes(b"OK".to_vec()));
    root.insert("blocks", Value::Array(Array::Object(vec![block])));
    let bytes = store_to_binary(&root).expect("encode");
    assert!(GetBlocksByHeightResponse::from_bin(&bytes).is_err());
}

/// No blocks at all: `blocks` is dropped from the document, like every other
/// empty sequence. Removing the `is_empty` guard turns this red.
#[test]
fn an_empty_block_list_is_absent_not_an_empty_array() {
    let built = GetBlocksByHeightResponse {
        status: RpcStatus::ok(),
        blocks: Vec::new(),
    }
    .to_bin()
    .expect("encode");
    let oracle = include_bytes!("vectors/rpc/get_blocks_by_height_response_empty_v1.bin");
    assert_bytes(oracle, &built, "get_blocks_by_height empty response");
    assert!(
        !built.windows(6).any(|w| w == b"blocks"),
        "an empty block list must not put the key in the document"
    );
}

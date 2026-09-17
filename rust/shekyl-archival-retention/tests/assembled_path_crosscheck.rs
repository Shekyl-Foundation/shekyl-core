// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-check `verify_segment_path` against the CT-4 assembled-path KAT.

use serde_json::Value;
use shekyl_archival_retention::{challenged_leaf_bytes, verify_segment_path, SegmentPathOpening};
use shekyl_curve_tree::{
    AssembleInput, BlockHash, BlockHeight, BlockLeaves, ChunkLeaf, CurveTreeClient, CurveTreeRoot,
    Gindex, RawOutput, ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::{ed25519_point_to_selene_scalar, leaf_from_chunk_entry};

const FIXTURE: &str = include_str!("../../shekyl-curve-tree/tests/fixtures/ct2_tier_a.json");

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    assert_eq!(v.len(), 32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

struct Block {
    height: u64,
    root: [u8; 32],
    blob: Vec<u8>,
    outputs: Vec<RawOutput>,
}

fn decode_block(b: &Value) -> Block {
    let mt = &b["miner_tx"];
    let outputs = mt["outputs"]
        .as_array()
        .expect("outputs array")
        .iter()
        .map(|o| RawOutput {
            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(decode_hex32(
                o["output_key"].as_str().expect("O hex"),
            )),
            commitment: o["commitment"]
                .as_str()
                .map(decode_hex32)
                .map(shekyl_curve_tree::CommitmentBytes::from_bytes),
            target: TargetKind::TaggedKey,
        })
        .collect();
    Block {
        height: b["height"].as_u64().expect("height"),
        root: decode_hex32(b["curve_tree_root"].as_str().expect("root hex")),
        blob: decode_hex(mt["pqc_leaf_hashes"].as_str().expect("0x07 blob hex")),
        outputs,
    }
}

fn main_chain() -> Vec<Block> {
    let f: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    f["chains"]
        .as_array()
        .expect("chains")
        .iter()
        .find(|c| c["name"].as_str() == Some("main"))
        .expect("main chain present")["blocks"]
        .as_array()
        .expect("blocks array")
        .iter()
        .map(decode_block)
        .collect()
}

/// Coinbase gindex of `target_height`: the cumulative count of every vout in
/// earlier blocks (the chain is consecutive from genesis; every coinbase output
/// is leaf-eligible), so it equals the client's drain-order `next_output_seq`.
fn coinbase_gindex(blocks: &[Block], target_height: u64) -> u64 {
    blocks
        .iter()
        .filter(|b| b.height < target_height)
        .map(|b| b.outputs.len() as u64)
        .sum()
}

/// The [`AssembleInput`] for `target_height`'s coinbase: its `gindex` (X3
/// resolution key) plus the `(output_key, commitment)` the post-resolution
/// check verifies.
fn coinbase_input(blocks: &[Block], target_height: u64) -> AssembleInput {
    let block = blocks
        .iter()
        .find(|b| b.height == target_height)
        .unwrap_or_else(|| panic!("block {target_height} in fixture"));
    let raw = block.outputs[0];
    AssembleInput {
        gindex: Gindex::from_raw(coinbase_gindex(blocks, target_height)),
        output_key: raw.output_key,
        commitment: raw.commitment.expect("coinbase output has a commitment"),
    }
}

fn leaf_layer_scalars(chunk: &[ChunkLeaf]) -> Vec<[u8; 32]> {
    let mut scalars = Vec::with_capacity(chunk.len() * 4);
    for cl in chunk {
        scalars.push(ed25519_point_to_selene_scalar(cl.output_key.as_bytes()).expect("O.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.key_image_gen).expect("I.x"));
        scalars.push(ed25519_point_to_selene_scalar(cl.commitment.as_bytes()).expect("C.x"));
        scalars.push(cl.cm_x);
    }
    scalars
}

#[test]
fn assembled_path_verifies_as_segment_opening() {
    let blocks = main_chain();
    let mut client = CurveTreeClient::new();
    for blk in &blocks {
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_entry_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(blk.height),
                txs: &txs,
            })
            .unwrap();
    }

    let tip = blocks.last().expect("non-empty chain");
    // Distinctive, non-zero, and distinct from the root: lets the assertion
    // below confirm `block_hash` survives the cross-crate round-trip (built
    // here, echoed back through `AssembledPath.tree.reference_block`) intact —
    // a value drop or root swap would not pass.
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(tip.height),
        curve_tree_root: CurveTreeRoot::from_bytes(tip.root),
        block_hash: BlockHash::from_bytes([0xC7u8; 32]),
    };
    let last_drained = reference.height.to_raw().saturating_sub(61);
    let founder = coinbase_input(&blocks, last_drained);

    let path = client
        .assemble_path(&founder, &reference)
        .expect("assemble founder path");

    // The caller-supplied block hash crosses the crate boundary intact.
    assert_eq!(
        path.tree.reference_block, reference.block_hash,
        "assembled path must echo the caller-supplied ReferenceBlock::block_hash",
    );

    // RF-D8: the verifier selects the challenged leaf from its own chunk by
    // offset; nothing about the leaf travels. The offset is where the founder
    // sits in the chunk.
    let leaf_offset = path
        .leaf_chunk
        .iter()
        .position(|cl| cl.output_key == founder.output_key)
        .expect("founder in leaf chunk");
    let cl = &path.leaf_chunk[leaf_offset];
    // The chunk carries the 4th scalar (CM.x), not the commitment point.
    let leaf_bytes = leaf_from_chunk_entry(
        cl.output_key.as_bytes(),
        &cl.key_image_gen,
        cl.commitment.as_bytes(),
        &cl.cm_x,
    )
    .expect("construct 128-byte leaf");

    let opening = SegmentPathOpening {
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    };
    let layer_scalars = leaf_layer_scalars(&path.leaf_chunk);
    assert_eq!(
        challenged_leaf_bytes(&layer_scalars, leaf_offset),
        Some(leaf_bytes),
        "the leaf selected by offset is the founder's constructed leaf"
    );

    verify_segment_path(
        &layer_scalars,
        leaf_offset,
        &opening,
        &reference.curve_tree_root.to_bytes(),
    )
    .expect("assembled path verifies to consensus root");
}

/// TJ-F soundness face (GREEN — frozen now): responder-supplied material must
/// not verify against leaves that are not the committed ones. Post-pruning
/// this is the whole soundness — `R_k` is all that stands between a supplied
/// response and an accepted lie. Two forgeries, both rejected today at the
/// pure-function level; this test pins that behaviour so the TJ-A rewire
/// inherits it rather than re-deriving it.
#[test]
fn tj_f_forged_material_does_not_verify() {
    let blocks = main_chain();
    let mut client = CurveTreeClient::new();
    for blk in &blocks {
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_entry_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(blk.height),
                txs: &txs,
            })
            .unwrap();
    }
    let tip = blocks.last().expect("non-empty chain");
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(tip.height),
        curve_tree_root: CurveTreeRoot::from_bytes(tip.root),
        block_hash: BlockHash::from_bytes([0xC7u8; 32]),
    };
    let last_drained = reference.height.to_raw().saturating_sub(61);
    let founder = coinbase_input(&blocks, last_drained);
    let path = client
        .assemble_path(&founder, &reference)
        .expect("assemble founder path");
    let leaf_offset = path
        .leaf_chunk
        .iter()
        .position(|cl| cl.output_key == founder.output_key)
        .expect("founder in leaf chunk");
    let opening = SegmentPathOpening {
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    };
    let layer_scalars = leaf_layer_scalars(&path.leaf_chunk);

    // Forgery 1: tampered leaf-layer material — the supplied chunk no longer
    // contains the challenged leaf's scalars coherently.
    let mut tampered = layer_scalars.clone();
    tampered[0][0] ^= 0x01;
    assert!(
        verify_segment_path(
            &tampered,
            leaf_offset,
            &opening,
            reference.curve_tree_root.as_bytes()
        )
        .is_err(),
        "tampered leaf-layer material must not verify"
    );

    // Forgery 2: consistent material against the wrong commitment — the
    // response is internally coherent but R_k is not the committed sub-root.
    let mut wrong_rk = reference.curve_tree_root.to_bytes();
    wrong_rk[0] ^= 0x01;
    assert!(
        verify_segment_path(&layer_scalars, leaf_offset, &opening, &wrong_rk).is_err(),
        "coherent material against a non-committed R_k must not verify"
    );
}

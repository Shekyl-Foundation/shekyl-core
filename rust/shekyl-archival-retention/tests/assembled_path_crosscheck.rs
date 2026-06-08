// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-check `verify_segment_path` against the CT-4 assembled-path KAT.

use serde_json::Value;
use shekyl_archival_retention::{verify_segment_path, SegmentPathOpening};
use shekyl_curve_tree::{
    BlockLeaves, ChunkLeaf, CurveTreeClient, OutputIdentity, RawOutput, ReferenceBlock, TargetKind,
    TxLeafInputs,
};
use shekyl_fcmp::tree::{construct_leaf, ed25519_point_to_selene_scalar};

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
            output_key: decode_hex32(o["output_key"].as_str().expect("O hex")),
            commitment: o["commitment"].as_str().map(decode_hex32),
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

fn coinbase_identity(block: &Block) -> OutputIdentity {
    let leaf_hashes = shekyl_curve_tree::recon::extract_leaf_hashes(Some(&block.blob));
    let raw = block.outputs[0];
    OutputIdentity {
        output_key: raw.output_key,
        commitment: raw.commitment,
        h_pqc: shekyl_curve_tree::recon::per_output_h_pqc(&leaf_hashes, 0),
        target: raw.target,
    }
}

fn leaf_layer_scalars(chunk: &[ChunkLeaf]) -> Vec<[u8; 32]> {
    let mut scalars = Vec::with_capacity(chunk.len() * 4);
    for cl in chunk {
        scalars.push(ed25519_point_to_selene_scalar(&cl.output_key).expect("O.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.key_image_gen).expect("I.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.commitment).expect("C.x"));
        scalars.push(cl.h_pqc);
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
            leaf_hash_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client.ingest_block(BlockLeaves {
            height: blk.height,
            txs: &txs,
        });
    }

    let tip = blocks.last().expect("non-empty chain");
    let reference = ReferenceBlock {
        height: tip.height,
        curve_tree_root: tip.root,
    };
    let last_drained = reference.height.saturating_sub(61);
    let drained_block = blocks
        .iter()
        .find(|b| b.height == last_drained)
        .unwrap_or_else(|| panic!("block {last_drained} in fixture"));
    let founder = coinbase_identity(drained_block);

    let path = client
        .assemble_path(&founder, &reference, [0u8; 32])
        .expect("assemble founder path");

    let cl = path
        .leaf_chunk
        .iter()
        .find(|cl| cl.output_key == founder.output_key)
        .expect("founder in leaf chunk");
    let leaf_bytes =
        construct_leaf(&cl.output_key, &cl.commitment, &cl.h_pqc).expect("construct 128-byte leaf");

    let opening = SegmentPathOpening {
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    };
    let layer_scalars = leaf_layer_scalars(&path.leaf_chunk);

    verify_segment_path(
        &leaf_bytes,
        &layer_scalars,
        &opening,
        &reference.curve_tree_root,
    )
    .expect("assembled path verifies to consensus root");
}

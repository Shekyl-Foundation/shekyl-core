// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-4 membership-path assembly KAT (Tier A): an assembled path's branches,
//! re-hashed bottom-up, reproduce the consensus header root.
//!
//! Reuses the CT-2 Tier-A oracle (`tests/fixtures/ct2_tier_a.json`). For a
//! drained coinbase output it builds the [`shekyl_curve_tree::AssembledPath`]
//! via the production [`CurveTreeClient::assemble_path`], then **independently**
//! recomputes the root by `hash_grow`-ing each branch chunk (not `build_layers`,
//! which `assemble_path` uses internally) and asserts:
//!
//! - the recomputed root byte-equals the recorded consensus `curve_tree_root`;
//! - the C3 invariant `c1_layers.len() + c2_layers.len() + 1 == tree_depth`;
//! - the leaf chunk, hashed to its Selene node, appears (as its x-coordinate)
//!   in the first Helios branch — closing the loop between `leaf_chunk` and the
//!   branch layers.
//!
//! This pins the FCMP++ `Path` layout (`prover/mod.rs`: C1 = Selene, C2 =
//! Helios; odd tree layers → `c2_layers`, even internal layers → `c1_layers`;
//! full child chunks; root point excluded) against a real header root, the
//! same way the CT-2 KAT pins reconstruction.

use serde_json::Value;
use shekyl_curve_tree::{
    AssembleInput, AssembledPath, BlockHeight, BlockLeaves, ChunkLeaf, CurveTreeClient, Gindex,
    RawOutput, ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::{
    ed25519_point_to_selene_scalar, hash_grow_helios, hash_grow_selene, helios_hash_init,
    layer_is_selene, selene_hash_init, selene_point_to_helios_scalar,
};

const FIXTURE: &str = include_str!("fixtures/ct2_tier_a.json");
const ZERO: [u8; 32] = [0u8; 32];

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    assert_eq!(v.len(), 32, "expected 32 bytes, got {}", v.len());
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn target_kind(s: &str) -> TargetKind {
    match s {
        "tagged_key" => TargetKind::TaggedKey,
        "key" => TargetKind::Key,
        other => panic!("unexpected Tier-A target kind: {other}"),
    }
}

/// One decoded block kept in the raw shape the production client consumes
/// (pre-`h_pqc` `RawOutput`s + the raw `0x07` blob), so the client resolves
/// `h_pqc` and threads the index itself.
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
            target: target_kind(o["target"].as_str().expect("target")),
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

/// Build a client over the whole main chain.
fn client_over(blocks: &[Block]) -> CurveTreeClient {
    let mut client = CurveTreeClient::new();
    for blk in blocks {
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight(blk.height),
                txs: &txs,
            })
            .unwrap();
    }
    client
}

/// Global output index (gindex) of `target_height`'s coinbase output: the
/// cumulative count of every vout in earlier blocks, in drain order. The
/// fixture's blocks are consecutive from genesis and every coinbase output is
/// leaf-eligible, so this equals the client's `next_output_seq` assignment —
/// which is exactly the numbering equivalence the post-resolution check guards
/// (the scanner-side half of that equivalence is covered engine-side, where the
/// scanner's `global_output_index` exists; X3 §5.1 / Q3).
fn coinbase_gindex(blocks: &[Block], target_height: u64) -> u64 {
    blocks
        .iter()
        .filter(|b| b.height < target_height)
        .map(|b| b.outputs.len() as u64)
        .sum()
}

/// The [`AssembleInput`] for `target_height`'s coinbase: its `gindex` (the X3
/// resolution key) plus the `(output_key, commitment)` the post-resolution
/// consistency check verifies.
fn coinbase_input(blocks: &[Block], target_height: u64) -> AssembleInput {
    let block = blocks
        .iter()
        .find(|b| b.height == target_height)
        .unwrap_or_else(|| panic!("block {target_height} in fixture"));
    let raw = block.outputs[0];
    AssembleInput {
        gindex: Gindex(coinbase_gindex(blocks, target_height)),
        output_key: raw.output_key,
        commitment: raw.commitment.expect("coinbase output has a commitment"),
    }
}

/// Hash a leaf chunk's outputs to its Selene leaf-node point, mirroring
/// `construct_leaf`'s scalar layout (`O.x, I.x, C.x, h_pqc` per output).
fn leaf_node_point(chunk: &[ChunkLeaf]) -> [u8; 32] {
    let mut scalars = Vec::with_capacity(chunk.len() * 4);
    for cl in chunk {
        scalars.push(ed25519_point_to_selene_scalar(&cl.output_key).expect("O.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.key_image_gen).expect("I.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.commitment).expect("C.x"));
        scalars.push(cl.h_pqc);
    }
    hash_grow_selene(&selene_hash_init(), 0, &ZERO, &scalars).expect("leaf node")
}

/// Re-hash each branch chunk bottom-up; the topmost branch is the root's
/// children, so its hash is the root. Independent of `build_layers` (uses the
/// raw `hash_grow` primitives), so agreement with the consensus root is a
/// genuine cross-check of the branch extraction, not a tautology.
fn recompute_root(path: &AssembledPath) -> [u8; 32] {
    let mut c1 = path.c1_layers.iter();
    let mut c2 = path.c2_layers.iter();
    let mut root = None;
    for layer in 1..path.tree.tree_depth {
        let point = if layer_is_selene(layer) {
            let chunk = c1.next().expect("c1 branch for an even (Selene) layer");
            hash_grow_selene(&selene_hash_init(), 0, &ZERO, chunk).expect("selene node")
        } else {
            let chunk = c2.next().expect("c2 branch for an odd (Helios) layer");
            hash_grow_helios(&helios_hash_init(), 0, &ZERO, chunk).expect("helios node")
        };
        root = Some(point);
    }
    root.expect("a non-empty path has at least one branch")
}

/// Assemble `target`'s path at `reference` and run all three checks.
fn check_path(client: &CurveTreeClient, target: &AssembleInput, reference: &ReferenceBlock) {
    let path = client
        .assemble_path(target, reference)
        .expect("assemble path for a drained coinbase output");

    // C3 invariant.
    assert_eq!(
        path.c1_layers.len() + path.c2_layers.len() + 1,
        usize::from(path.tree.tree_depth),
        "C3: c1 + c2 + 1 (leaf) == tree_depth",
    );
    assert!(path.tree.tree_depth >= 2, "non-empty tree is depth >= 2");

    // The branches re-hash to the consensus root.
    assert_eq!(
        recompute_root(&path),
        reference.curve_tree_root,
        "recomputed root must equal the consensus header root at height {}",
        reference.height.0,
    );
    assert_eq!(path.tree.tree_root, reference.curve_tree_root);

    // The caller-supplied block hash is threaded verbatim into the tree
    // context for the eventual `rctSig.referenceBlock` (the CT-4 anchor
    // contract, §5). A distinctive non-zero `block_hash` in the caller's
    // `ReferenceBlock` (set below) makes this catch both a dropped/zeroed value
    // and a silent swap with the root.
    assert_eq!(
        path.tree.reference_block, reference.block_hash,
        "assembled path must echo the caller-supplied ReferenceBlock::block_hash",
    );

    // Leaf chunk ↔ first branch consistency: the leaf node's x-coordinate is
    // one of the Helios branch's children.
    let leaf_x = selene_point_to_helios_scalar(&leaf_node_point(&path.leaf_chunk))
        .expect("leaf node x-coordinate");
    assert!(
        path.c2_layers[0].contains(&leaf_x),
        "the leaf node must appear in the first (Helios) branch",
    );

    // The resolved output is actually present in the returned leaf chunk.
    assert!(
        path.leaf_chunk
            .iter()
            .any(|cl| cl.output_key == target.output_key && cl.commitment == target.commitment),
        "the target output must be in its own leaf chunk",
    );
}

#[test]
fn assembled_path_recomputes_to_consensus_root() {
    let blocks = main_chain();
    let client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    // Distinctive, non-zero, and distinct from the root so the round-trip
    // assertion in `check_path` is a genuine check (not satisfied by a zeroed
    // or root-swapped value).
    let reference = ReferenceBlock {
        height: BlockHeight(tip.height),
        curve_tree_root: tip.root,
        block_hash: [0xABu8; 32],
    };

    // A coinbase at block `b` is drained at `reference.height` iff
    // `b <= reference.height - 61`. Pick the founder (leaf position 0, the
    // first leaf node) and a mid-tree output (a non-zero leaf-node index that
    // exercises the internal-layer branch slicing).
    let last_drained = reference.height.0.saturating_sub(61);
    assert!(
        last_drained >= 1,
        "fixture must mine past the freeze lag so a non-empty tree exists",
    );
    let mid = last_drained / 2;

    for target_height in [0u64, mid, last_drained] {
        let target = coinbase_input(&blocks, target_height);
        check_path(&client, &target, &reference);
    }
}

#[test]
fn assemble_path_rejects_undrained_output() {
    let blocks = main_chain();
    let client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    let reference = ReferenceBlock {
        height: BlockHeight(tip.height),
        curve_tree_root: tip.root,
        block_hash: [0u8; 32],
    };

    // The tip's own coinbase has not matured (let alone drained) at the tip, so
    // its gindex is not among the drained leaves at the reference: a lookup
    // miss, not a bad path.
    let undrained = coinbase_input(&blocks, tip.height);
    match client.assemble_path(&undrained, &reference) {
        Err(shekyl_curve_tree::ClientError::OutputNotDrained { gindex, output_key }) => {
            assert_eq!(gindex, undrained.gindex);
            assert_eq!(output_key, undrained.output_key);
        }
        other => panic!("expected OutputNotDrained, got {other:?}"),
    }
}

#[test]
fn assemble_path_rejects_root_mismatch() {
    let blocks = main_chain();
    let client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    let founder = coinbase_input(&blocks, blocks[0].height);
    // A reference carrying the wrong consensus root must fail the integrity
    // gate before any path is assembled.
    let bad = ReferenceBlock {
        height: BlockHeight(tip.height),
        curve_tree_root: [0xFFu8; 32],
        block_hash: [0u8; 32],
    };
    match client.assemble_path(&founder, &bad) {
        Err(shekyl_curve_tree::ClientError::RootMismatch { height, .. }) => {
            assert_eq!(height, BlockHeight(tip.height));
        }
        other => panic!("expected RootMismatch, got {other:?}"),
    }
}

#[test]
fn assemble_path_rejects_identity_mismatch() {
    let blocks = main_chain();
    let client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    let reference = ReferenceBlock {
        height: BlockHeight(tip.height),
        curve_tree_root: tip.root,
        block_hash: [0u8; 32],
    };

    // A genuinely drained coinbase, but with the expected output_key tampered:
    // the gindex resolves to the real leaf, then the post-resolution (O, C)
    // check rejects it (X3 — the tree-vs-scanner numbering-desync guard).
    let last_drained = reference.height.0.saturating_sub(61);
    let mut tampered = coinbase_input(&blocks, last_drained);
    let real_key = tampered.output_key;
    tampered.output_key = [0x99u8; 32];
    assert_ne!(tampered.output_key, real_key, "tamper must change the key");

    match client.assemble_path(&tampered, &reference) {
        Err(shekyl_curve_tree::ClientError::IdentityMismatch {
            gindex,
            expected_output_key,
            got_output_key,
            ..
        }) => {
            assert_eq!(gindex, tampered.gindex);
            assert_eq!(expected_output_key, [0x99u8; 32]);
            assert_eq!(got_output_key, real_key);
        }
        other => panic!("expected IdentityMismatch, got {other:?}"),
    }
}

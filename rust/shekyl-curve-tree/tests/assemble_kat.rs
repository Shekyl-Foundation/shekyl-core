// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-4 membership-path assembly KAT (Tier A): an assembled path against the
//! consensus header root.
//!
//! Reuses the CT-2 Tier-A oracle (`tests/fixtures/ct2_tier_a.json`). For a
//! drained coinbase output it builds the path via
//! [`CurveTreeClient::assemble_path`]. The reference root is the fixture's
//! header root. `assemble_path` folds the path's own branches onto that root
//! before returning ([`shekyl_curve_tree::PathRootFault`]), so a path that
//! comes back has already hashed to the header. This file does not carry a
//! second copy of that fold.
//!
//! What it still pins, against that header:
//!
//! - the C3 invariant `c1_layers.len() + c2_layers.len() + 1 == tree_depth`;
//! - `tree_root` is the header root, and `reference_block` is the
//!   caller-supplied block hash;
//! - the target output is present in its leaf chunk.
//!
//! The FCMP++ `Path` layout (`prover/mod.rs`: C1 = Selene, C2 = Helios; odd
//! tree layers → `c2_layers`, even internal layers → `c1_layers`; full child
//! chunks; root point excluded) is what the production fold walks. The
//! membership link inside that fold is pinned in `client::ct6_oracle`.

use serde_json::Value;
use shekyl_curve_tree::{
    AssembleInput, BlockHash, BlockHeight, BlockLeaves, CommitmentBytes, CurveTreeClient,
    CurveTreeRoot, Gindex, OneTimePubkey, RawOutput, ReferenceBlock, TargetKind, TxLeafInputs,
};

const FIXTURE: &str = include_str!("fixtures/ct2_tier_a.json");

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
            output_key: OneTimePubkey::from_bytes(decode_hex32(
                o["output_key"].as_str().expect("O hex"),
            )),
            commitment: o["commitment"]
                .as_str()
                .map(decode_hex32)
                .map(CommitmentBytes::from_bytes),
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
        gindex: Gindex::from_raw(coinbase_gindex(blocks, target_height)),
        output_key: raw.output_key,
        commitment: raw.commitment.expect("coinbase output has a commitment"),
    }
}

/// Assemble `target`'s path at `reference` and pin the layout the fold does
/// not cover.
///
/// `assemble_path` has already folded the branches onto `reference`'s header
/// root, so a returned path committed to that root.
/// Register `inputs` with the client, as the curve-tree actor does before it
/// assembles a batch. Assembly reads captures only — there is no rebuild —
/// so a direct caller registers first or is refused by name.
fn register(client: &mut CurveTreeClient, inputs: &[AssembleInput]) {
    let pairs: Vec<_> = inputs.iter().map(|i| (i.gindex, i.output_key)).collect();
    let sync = client.sync_owned(&pairs).expect("a live client syncs");
    assert!(
        sync.stale.is_empty(),
        "the fixture's inputs are its own outputs"
    );
}

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

    // The fold compared the branches to `tree_root`. This checks that value
    // is the header root the reference carried, not some other root the
    // fold was willing to accept.
    assert_eq!(path.tree.tree_root, reference.curve_tree_root);

    // The caller-supplied block hash is threaded verbatim into the tree
    // context for the eventual `CtSig.referenceBlock` (the CT-4 anchor
    // contract, §5). A distinctive non-zero `block_hash` in the caller's
    // `ReferenceBlock` (set below) makes this catch both a dropped/zeroed value
    // and a silent swap with the root.
    assert_eq!(
        path.tree.reference_block, reference.block_hash,
        "assembled path must echo the caller-supplied ReferenceBlock::block_hash",
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
    let mut client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    // Distinctive, non-zero, and distinct from the root so the round-trip
    // assertion in `check_path` is a genuine check (not satisfied by a zeroed
    // or root-swapped value).
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(tip.height),
        curve_tree_root: CurveTreeRoot::from_bytes(tip.root),
        block_hash: BlockHash::from_bytes([0xABu8; 32]),
    };

    // A coinbase at block `b` is drained at `reference.height` iff
    // `b <= reference.height - 61`. Pick the founder (leaf position 0, the
    // first leaf node) and a mid-tree output (a non-zero leaf-node index that
    // exercises the internal-layer branch slicing).
    let last_drained = reference.height.to_raw().saturating_sub(61);
    assert!(
        last_drained >= 1,
        "fixture must mine past the freeze lag so a non-empty tree exists",
    );
    let mid = last_drained / 2;

    for target_height in [0u64, mid, last_drained] {
        let target = coinbase_input(&blocks, target_height);
        register(&mut client, &[target]);
        check_path(&client, &target, &reference);
    }
}

#[test]
fn assemble_path_rejects_undrained_output() {
    let blocks = main_chain();
    let mut client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(tip.height),
        curve_tree_root: CurveTreeRoot::from_bytes(tip.root),
        block_hash: BlockHash::NULL,
    };

    // The tip's own coinbase has not matured (let alone drained) at the tip, so
    // its gindex is not among the drained leaves at the reference: a lookup
    // miss, not a bad path. Registered — the wallet owns it — but with no
    // resolved position yet, which is exactly what "not drained" means on
    // the capture path.
    let undrained = coinbase_input(&blocks, tip.height);
    register(&mut client, &[undrained]);
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
        height: BlockHeight::from_raw(tip.height),
        curve_tree_root: CurveTreeRoot::from_bytes([0xFFu8; 32]),
        block_hash: BlockHash::NULL,
    };
    match client.assemble_path(&founder, &bad) {
        Err(shekyl_curve_tree::ClientError::RootMismatch { height, .. }) => {
            assert_eq!(height, BlockHeight::from_raw(tip.height));
        }
        other => panic!("expected RootMismatch, got {other:?}"),
    }
}

#[test]
fn assemble_path_rejects_identity_mismatch() {
    let blocks = main_chain();
    let mut client = client_over(&blocks);

    let tip = blocks.last().expect("non-empty chain");
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(tip.height),
        curve_tree_root: CurveTreeRoot::from_bytes(tip.root),
        block_hash: BlockHash::NULL,
    };

    // A genuinely drained coinbase, but with the expected output_key tampered:
    // the gindex resolves to the real leaf, then the post-resolution (O, C)
    // check rejects it (X3 — the tree-vs-scanner numbering-desync guard).
    let last_drained = reference.height.to_raw().saturating_sub(61);
    let mut tampered = coinbase_input(&blocks, last_drained);
    // Registered with the REAL key — the registry is right; it is the
    // caller's input that disagrees, which is the X3 guard's case.
    register(&mut client, &[tampered]);
    let real_key = tampered.output_key;
    tampered.output_key = OneTimePubkey::from_bytes([0x99u8; 32]);
    assert_ne!(tampered.output_key, real_key, "tamper must change the key");

    match client.assemble_path(&tampered, &reference) {
        Err(shekyl_curve_tree::ClientError::IdentityMismatch {
            gindex,
            expected_output_key,
            got_output_key,
            ..
        }) => {
            assert_eq!(gindex, tampered.gindex);
            assert_eq!(expected_output_key, OneTimePubkey::from_bytes([0x99u8; 32]));
            assert_eq!(got_output_key, real_key);
        }
        other => panic!("expected IdentityMismatch, got {other:?}"),
    }
}

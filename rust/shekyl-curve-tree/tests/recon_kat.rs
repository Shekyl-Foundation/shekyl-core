// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-2 reconstruct-root KAT (Tier A): the wallet's block-derived
//! `build_layers` root byte-equals the C++ consensus header root.
//!
//! The oracle is `tests/fixtures/ct2_tier_a.json`, generated offline from
//! a regtest `shekyld` by `gen_ct2_fixture.py` (see the fixtures README).
//! Each chain carries, per block, the header `curve_tree_root` and the
//! coinbase leaf inputs (`O`, `C`, and the `tx_extra 0x07` blob). This
//! test replays each chain through `recon` and asserts equality at every
//! height — pinning S1 (index order), the S2 drain boundary, and S3
//! (reorg position-stability) against consensus (`CT2_DRAIN_ORDER.md` §8).
//!
//! What is exercised end-to-end here: the real `0x07` blob validation
//! ([`extract_leaf_hashes`]), per-output `h_pqc` resolution, leaf
//! construction via the shared `construct_leaf` FFI, the `(maturity,
//! gindex)` drain sort, and `build_layers`. The raw `tx_extra` → blob
//! *parse* (scanner `Extra`) is the decode boundary (CT-3) and its
//! adversarial parity is a Tier-B obligation (`CT2_DRAIN_ORDER.md` §3.1).

use serde_json::Value;
use shekyl_curve_tree::recon::{
    assemble_leaf_stream, collect_block_leaves, extract_leaf_hashes, per_output_h_pqc,
    root_from_scalars, TxOutputs,
};
use shekyl_curve_tree::{
    BlockHeight, BlockLeaves, CurveTreeClient, OutputIdentity, RawOutput, ReferenceBlock,
    TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::selene_hash_init;

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

/// One decoded block: its height, the recorded consensus root, and the
/// coinbase outputs with `h_pqc` already resolved from the `0x07` blob.
struct Block {
    height: u64,
    root: [u8; 32],
    outputs: Vec<OutputIdentity>,
}

fn decode_block(b: &Value) -> Block {
    let height = b["height"].as_u64().expect("height");
    let root = decode_hex32(b["curve_tree_root"].as_str().expect("root hex"));
    let mt = &b["miner_tx"];
    let blob = decode_hex(mt["pqc_leaf_hashes"].as_str().expect("0x07 blob hex"));
    // Real post-parse validation/slicing — the recon-owned half of the
    // daemon's extract_leaf_hashes (the %32 check + per-output slice).
    let leaf_hashes = extract_leaf_hashes(Some(&blob));
    let outputs = mt["outputs"]
        .as_array()
        .expect("outputs array")
        .iter()
        .enumerate()
        .map(|(i, o)| OutputIdentity {
            output_key: decode_hex32(o["output_key"].as_str().expect("O hex")),
            commitment: o["commitment"].as_str().map(decode_hex32),
            h_pqc: per_output_h_pqc(&leaf_hashes, i),
            target: target_kind(o["target"].as_str().expect("target")),
        })
        .collect();
    Block {
        height,
        root,
        outputs,
    }
}

fn decode_chain(chain: &Value) -> Vec<Block> {
    chain["blocks"]
        .as_array()
        .expect("blocks array")
        .iter()
        .map(decode_block)
        .collect()
}

/// Reconstruct the per-height roots for one chain by replaying its blocks
/// in order, threading the global output index and accumulating leaves.
///
/// The reference-height → drain-cutoff mapping is `drained_through =
/// height - 1`: a coinbase at block `b` matures at `b + 60` but only
/// enters the tree at the *next* block (`b + 61`). The founder coinbase
/// (block 0) is therefore first visible at height 61, not 60 — the S2
/// inclusive/exclusive boundary, pinned here against consensus.
fn reconstruct_roots(blocks: &[Block]) -> Vec<[u8; 32]> {
    let mut entries = Vec::new();
    let mut gindex = 0u64;
    let mut roots = Vec::with_capacity(blocks.len());
    for blk in blocks {
        let txs = [TxOutputs {
            is_miner: true,
            outputs: &blk.outputs,
        }];
        gindex = collect_block_leaves(blk.height, &txs, gindex, &mut entries);
        let drained_through = blk.height.saturating_sub(1);
        let scalars = assemble_leaf_stream(&entries, drained_through);
        roots.push(root_from_scalars(&scalars));
    }
    roots
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

fn chain<'a>(f: &'a Value, name: &str) -> &'a Value {
    f["chains"]
        .as_array()
        .expect("chains")
        .iter()
        .find(|c| c["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("chain {name} not in fixture"))
}

/// The core obligation: for every chain and every height, the
/// reconstructed root equals the recorded consensus header root.
#[test]
fn reconstructed_root_matches_consensus_at_every_height() {
    let f = fixture();
    for c in f["chains"].as_array().expect("chains") {
        let name = c["name"].as_str().unwrap();
        let blocks = decode_chain(c);
        let recon = reconstruct_roots(&blocks);
        let mut mismatches = Vec::new();
        for (blk, got) in blocks.iter().zip(&recon) {
            if blk.root != *got {
                mismatches.push(blk.height);
            }
        }
        assert!(
            mismatches.is_empty(),
            "chain {name}: root mismatch at heights {:?} (first {} shown)",
            &mismatches[..mismatches.len().min(10)],
            mismatches.len().min(10),
        );
    }
}

/// S2 boundary pin: heights 0..=60 are the empty tree (founder coinbase
/// matures at +60 but drains at +61); height 61 is the first non-empty
/// root. Guards against an off-by-one in the drain trigger.
#[test]
fn empty_window_then_first_drain_at_61() {
    const LAST_EMPTY: usize = 60;
    const FIRST_DRAIN: usize = 61;

    let f = fixture();
    let blocks = decode_chain(chain(&f, "main"));
    let recon = reconstruct_roots(&blocks);
    let init = selene_hash_init();

    for (h, root) in recon.iter().enumerate().take(FIRST_DRAIN) {
        assert_eq!(*root, init, "height {h} must be selene_hash_init");
    }
    assert_eq!(
        recon[LAST_EMPTY], blocks[LAST_EMPTY].root,
        "last empty height must match consensus header root"
    );
    assert_ne!(
        recon[FIRST_DRAIN], init,
        "height {FIRST_DRAIN} is the first drained leaf"
    );
    assert_eq!(
        recon[FIRST_DRAIN], blocks[FIRST_DRAIN].root,
        "first drain height must match consensus header root"
    );
}

/// S3 position-stability + freeze-lag: a reorg leaves the pre-fork prefix
/// frozen, and the re-mined tail cannot perturb the root until its first
/// coinbase *drains*. A re-mined block at height `fork + 1` carries a
/// coinbase that matures at `+60` and enters the tree at `+61`, so every
/// reference height through `fork + 61` reconstructs from shared-prefix
/// leaves only and is byte-identical across the two chains — the freeze-lag
/// rule (`CT2_DRAIN_ORDER.md` §6) made executable. (A coinbase-only regtest
/// reorg re-mines deterministic outputs, so the tail beyond the lag is *not*
/// guaranteed to diverge; "tail churns" is fixture-dependent and therefore
/// not asserted. Consensus-equality of each reorg chain at every height is
/// covered by `reconstructed_root_matches_consensus_at_every_height`.)
#[test]
fn reorg_prefix_and_freeze_lag_are_frozen() {
    let f = fixture();
    let main_tip = f["main_tip"].as_u64().unwrap();
    let deep_pop = f["deep_pop"].as_u64().unwrap();
    let shallow_pop = f["shallow_pop"].as_u64().unwrap();

    let main = decode_chain(chain(&f, "main"));
    let deep = decode_chain(chain(&f, "reorg_deep"));
    let shallow = decode_chain(chain(&f, "reorg_shallow"));

    // Deep reorg (pop > COINBASE_LOCK_WINDOW, i.e. pops blocks whose coinbase
    // had already drained) forked from main after `main_tip - deep_pop`:
    // re-mined leaves exist but drain only past the freeze-lag, so the frozen
    // window extends `fork + 61` deep.
    let fork_deep = usize::try_from(main_tip - deep_pop).expect("fork height fits usize");
    assert_frozen_through_lag(&main, &deep, fork_deep, "main/reorg_deep");

    // Shallow reorg (pop < COINBASE_LOCK_WINDOW, so every popped block's
    // coinbase was still pending) forked from reorg_deep after its
    // tip - shallow_pop: nothing had drained, so the pending-only branch
    // mutates nothing — roots identical across the entire overlap.
    let deep_tip = deep.last().unwrap().height;
    let fork_shallow = usize::try_from(deep_tip - shallow_pop).expect("fork height fits usize");
    assert_frozen_through_lag(&shallow, &deep, fork_shallow, "reorg_deep/reorg_shallow");
}

/// One decoded block for the *production* client path: like [`Block`] but
/// keeping the raw `0x07` blob and pre-`h_pqc` [`RawOutput`]s, so the
/// `CurveTreeClient` (not the test) resolves `h_pqc` and threads the index.
struct ClientBlock {
    height: u64,
    root: [u8; 32],
    blob: Vec<u8>,
    outputs: Vec<RawOutput>,
}

fn decode_client_block(b: &Value) -> ClientBlock {
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
    ClientBlock {
        height: b["height"].as_u64().expect("height"),
        root: decode_hex32(b["curve_tree_root"].as_str().expect("root hex")),
        blob: decode_hex(mt["pqc_leaf_hashes"].as_str().expect("0x07 blob hex")),
        outputs,
    }
}

fn decode_client_chain(chain: &Value) -> Vec<ClientBlock> {
    chain["blocks"]
        .as_array()
        .expect("blocks array")
        .iter()
        .map(decode_client_block)
        .collect()
}

fn ingest_client_block(client: &mut CurveTreeClient, blk: &ClientBlock) {
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

/// End-to-end CT-3 obligation: the **production** `CurveTreeClient` —
/// ingesting reduced blocks, resolving `h_pqc` from the raw `0x07` blob,
/// threading the global index, and applying its own reference-height →
/// drain-cutoff mapping — reproduces the consensus header root at every
/// height, and its integrity gate (`verify_root`) accepts each one. This
/// is the same equality the recon-direct test proves, routed through the
/// wallet-facing API instead of the bare `recon` functions.
#[test]
fn client_reconstructs_consensus_root_at_every_height() {
    let f = fixture();
    for c in f["chains"].as_array().expect("chains") {
        let name = c["name"].as_str().unwrap();
        let blocks = decode_client_chain(c);

        // Ingest block-by-block (the live sync shape) and verify the
        // integrity gate at each connected height.
        let mut client = CurveTreeClient::new();
        let mut mismatches = Vec::new();
        for blk in &blocks {
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
            let reference = ReferenceBlock {
                height: BlockHeight(blk.height),
                curve_tree_root: blk.root,
                block_hash: [0u8; 32],
            };
            if client.verify_root(&reference).is_err() {
                mismatches.push(blk.height);
            }
        }
        assert!(
            mismatches.is_empty(),
            "chain {name}: client root mismatch at heights {:?}",
            &mismatches[..mismatches.len().min(10)],
        );
    }
}

/// The production client path and the bare-`recon` path agree height-for-
/// height: promoting the KAT to the `CurveTreeClient` API changed the
/// orchestration surface, not the reconstructed values.
#[test]
fn client_path_matches_recon_path() {
    let f = fixture();
    for c in f["chains"].as_array().expect("chains") {
        let recon_blocks = decode_chain(c);
        let recon = reconstruct_roots(&recon_blocks);

        let client_blocks = decode_client_chain(c);
        let mut client = CurveTreeClient::new();
        for (blk, recon_root) in client_blocks.iter().zip(&recon) {
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
            assert_eq!(
                client
                    .root_at(BlockHeight(blk.height))
                    .expect("store hot path"),
                *recon_root,
                "client/recon divergence at height {}",
                blk.height,
            );
        }
    }
}

/// CT-3c persistent-path corroboration: reorg_deep goes through
/// `CurveTreeClient::rollback_to_fork` and then re-syncs the new suffix.
/// Direct pending-row equality is asserted in the client unit KAT; this
/// fixture pins the file-backed rollback path against a fresh replay and
/// the consensus oracle roots.
#[test]
fn persistent_rollback_reorg_deep_matches_fresh_replay() {
    let f = fixture();
    let main_tip = f["main_tip"].as_u64().unwrap();
    let deep_pop = f["deep_pop"].as_u64().unwrap();
    assert!(
        deep_pop <= main_tip,
        "malformed fixture: deep_pop ({deep_pop}) exceeds main_tip ({main_tip})",
    );
    let fork = main_tip - deep_pop;
    let fork_index = usize::try_from(fork).expect("fork height fits usize");
    let main = decode_client_chain(chain(&f, "main"));
    let deep = decode_client_chain(chain(&f, "reorg_deep"));
    assert_eq!(main[fork_index].height, fork);
    assert_eq!(deep[fork_index].height, fork);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ct3c-reorg.redb");
    let mut persistent = CurveTreeClient::open(&path).unwrap();
    for blk in &main {
        ingest_client_block(&mut persistent, blk);
    }

    persistent.rollback_to_fork(BlockHeight(fork)).unwrap();
    for blk in deep.iter().skip(fork_index + 1) {
        ingest_client_block(&mut persistent, blk);
    }

    let mut fresh = CurveTreeClient::new();
    for blk in &deep {
        ingest_client_block(&mut fresh, blk);
    }

    assert_eq!(
        persistent.root_at(BlockHeight(fork)).unwrap(),
        fresh.root_at(BlockHeight(fork)).unwrap(),
        "shared-prefix root at fork"
    );
    for blk in deep.iter().skip(fork_index + 1) {
        let height = BlockHeight(blk.height);
        let persistent_root = persistent.root_at(height).unwrap();
        assert_eq!(
            persistent_root,
            fresh.root_at(height).unwrap(),
            "persistent/fresh divergence at height {}",
            blk.height
        );
        assert_eq!(
            persistent_root, blk.root,
            "persistent root must match consensus oracle at height {}",
            blk.height
        );
    }
}

/// Assert `a` and `b` have byte-identical roots from genesis through the end
/// of the freeze-lag window (`fork + 61`), clamped to the shorter chain. A
/// re-mined leaf at `fork + 1` drains at `fork + 62`, so this window is
/// reconstructed from shared-prefix leaves alone.
fn assert_frozen_through_lag(a: &[Block], b: &[Block], fork: usize, label: &str) {
    // COINBASE_LOCK_WINDOW (60, coinbase maturity) + 1 (a matured leaf enters
    // the tree on connection of the next block).
    const FREEZE_LAG: usize = 61;
    let common_tip = a.len().min(b.len()) - 1;
    let frozen_through = (fork + FREEZE_LAG).min(common_tip);
    for h in 0..=frozen_through {
        assert_eq!(
            a[h].root, b[h].root,
            "{label}: root differs at height {h} (≤ fork {fork} + freeze-lag); \
             position/freeze-lag not honored",
        );
    }
}

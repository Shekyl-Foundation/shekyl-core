// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-2 Tier-B reconstruct-root obligations (`CT2_DRAIN_ORDER.md` §8.2).
//!
//! Tier-A (`recon_kat.rs`) pins coinbase-only chains. Tier-B adds the richer
//! maturity classes that a single-class chain can't expose: a **multi-tx block**
//! (coinbase + spend), a **mixed-maturity collision** (a spend's `+10` regular
//! outputs interleaving with `+60` coinbases at the same drain height), and a
//! **reorg-with-spend** (a chain produced by a rollback + re-mine + re-spend).
//! The oracle `fixtures/ct2_tier_b.json` is generated from a live regtest by
//! `shekyl-engine-core`'s `generate_ct2_tier_b_fixture` via the keystone spend
//! path; each block carries the consensus header `curve_tree_root` and the
//! deterministic per-output leaf identity (`O`, `C`, `0x07`→`h_pqc`, target). The
//! tests reconstruct the root from those inputs, in drain order `(maturity,
//! gindex)`, and assert it equals consensus at every height.
//!
//! Two obligations remain `#[ignore]`d (no fake passes): a **staked** output
//! (`max(stake_lock, +10)` maturity) — the engine's staking *send* path is being
//! built separately, so the regtest can't yet mint one — and the adversarial
//! duplicate/malformed `0x07` case, which needs a hand-crafted C++ daemon oracle
//! (no regtest). Their bodies reference the APIs they will use so signature drift
//! fails compile before they resume.

use serde_json::Value;
use shekyl_curve_tree::recon::{
    assemble_leaf_stream, collect_block_leaves, extract_leaf_hashes, per_output_h_pqc,
    root_from_scalars, TxOutputs,
};
use shekyl_curve_tree::{OutputIdentity, TargetKind};

const FIXTURE_B: &str = include_str!("fixtures/ct2_tier_b.json");

fn fixture_b() -> Value {
    serde_json::from_str(FIXTURE_B).expect("tier-b fixture parses")
}

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
        other => panic!("unexpected Tier-B target kind: {other}"),
    }
}

/// One decoded transaction: whether it is the coinbase, and its outputs with
/// `h_pqc` already resolved from the tx's `0x07` blob.
struct TxFix {
    is_miner: bool,
    outputs: Vec<OutputIdentity>,
}

/// One decoded block: height, the recorded consensus root, and the block's
/// transactions in block order (coinbase first).
struct BlockFix {
    height: u64,
    root: [u8; 32],
    txs: Vec<TxFix>,
}

fn decode_tx(t: &Value) -> TxFix {
    let blob = decode_hex(t["pqc_leaf_hashes"].as_str().expect("0x07 blob hex"));
    // The recon-owned half of the daemon's extract_leaf_hashes (%32 check +
    // per-output slice).
    let leaf_hashes = extract_leaf_hashes(Some(&blob));
    let outputs = t["outputs"]
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
    TxFix {
        is_miner: t["is_miner"].as_bool().expect("is_miner bool"),
        outputs,
    }
}

fn decode_block(b: &Value) -> BlockFix {
    BlockFix {
        height: b["height"].as_u64().expect("height"),
        root: decode_hex32(b["curve_tree_root"].as_str().expect("root hex")),
        txs: b["txs"]
            .as_array()
            .expect("txs array")
            .iter()
            .map(decode_tx)
            .collect(),
    }
}

fn decode_chain(chain: &Value) -> Vec<BlockFix> {
    chain["blocks"]
        .as_array()
        .expect("blocks array")
        .iter()
        .map(decode_block)
        .collect()
}

fn chain<'a>(f: &'a Value, name: &str) -> &'a Value {
    f["chains"]
        .as_array()
        .expect("chains")
        .iter()
        .find(|c| c["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("chain {name} not in fixture"))
}

/// Reconstruct the per-height roots for one chain by replaying its blocks in
/// order, threading the global output index across **all** of a block's
/// transactions (coinbase first, then non-miner txs in block order) and draining
/// matured leaves at `drained_through = height - 1` (the S2 boundary, as in
/// Tier-A). The drain order is `(maturity, gindex)`: a coinbase matures at `+60`,
/// a regular output at `+10` — the mixed-maturity interleave a coinbase-only
/// chain can never produce.
fn reconstruct_roots(blocks: &[BlockFix]) -> Vec<[u8; 32]> {
    let mut entries = Vec::new();
    let mut gindex = 0u64;
    let mut roots = Vec::with_capacity(blocks.len());
    for blk in blocks {
        let txs: Vec<TxOutputs> = blk
            .txs
            .iter()
            .map(|t| TxOutputs {
                is_miner: t.is_miner,
                outputs: &t.outputs,
            })
            .collect();
        gindex = collect_block_leaves(blk.height, &txs, gindex, &mut entries);
        let drained_through = blk.height.saturating_sub(1);
        let scalars = assemble_leaf_stream(&entries, drained_through);
        roots.push(root_from_scalars(&scalars));
    }
    roots
}

fn assert_reconstructs(blocks: &[BlockFix], name: &str) {
    let recon = reconstruct_roots(blocks);
    let mismatches: Vec<u64> = blocks
        .iter()
        .zip(&recon)
        .filter(|(b, r)| b.root != **r)
        .map(|(b, _)| b.height)
        .collect();
    assert!(
        mismatches.is_empty(),
        "chain {name}: root mismatch at heights {:?} ({} total)",
        &mismatches[..mismatches.len().min(10)],
        mismatches.len(),
    );
}

/// The mixed-maturity collision: the `main` chain carries a spend whose `+10`
/// regular outputs drain interleaved with the `+60` coinbases. The reconstruct
/// orders leaves by `(maturity, gindex)`; a matching root at every height proves
/// the wallet drains the collision exactly as the daemon's `grow_curve_tree`.
#[test]
fn mixed_maturity_collision_orders_by_gindex() {
    let f = fixture_b();
    let blocks = decode_chain(chain(&f, "main"));
    assert!(
        blocks
            .iter()
            .any(|b| b.txs.iter().any(|t| !t.is_miner && !t.outputs.is_empty())),
        "main chain must contain a spend (regular `+10` outputs) for the collision"
    );
    assert_reconstructs(&blocks, "main");
}

/// A spend block is multi-tx (coinbase first, then the spend). The reconstruct
/// collects the coinbase's leaves before the spend's within the block; a correct
/// per-height root proves the coinbase-first + block-order leaf sequence.
#[test]
fn multi_tx_block_respects_coinbase_first_and_tx_hashes_order() {
    let f = fixture_b();
    let blocks = decode_chain(chain(&f, "main"));
    assert!(
        blocks.iter().any(|b| b.txs.len() > 1 && b.txs[0].is_miner),
        "main chain must contain a multi-tx block (coinbase + spend)"
    );
    assert_reconstructs(&blocks, "main");
}

/// Reorg-with-spend: the `reorg` chain was produced by rolling the daemon back
/// below a spend, re-mining a divergent tail, and re-spending. Its per-height
/// roots must still reconstruct — the daemon's `pop_block` deferred-insertion
/// rollback and the wallet recon agree on the post-reorg leaf set.
#[test]
fn reorg_with_spend_mixed_leaves() {
    let f = fixture_b();
    let blocks = decode_chain(chain(&f, "reorg"));
    assert!(
        blocks
            .iter()
            .any(|b| b.txs.iter().any(|t| !t.is_miner && !t.outputs.is_empty())),
        "reorg chain must contain a spend"
    );
    assert_reconstructs(&blocks, "reorg");
}

/// Drift canary for the deferred staked obligation: references the
/// `StakedKey { lock_blocks }` maturity path the test will assert once the
/// engine can mint a staked output.
fn _staked_drift_canary() {
    let out = OutputIdentity {
        output_key: [0u8; 32],
        commitment: Some([0u8; 32]),
        h_pqc: [0u8; 32],
        target: TargetKind::StakedKey { lock_blocks: 0 },
    };
    let txs = [TxOutputs {
        is_miner: false,
        outputs: std::slice::from_ref(&out),
    }];
    let mut entries = Vec::new();
    let gindex = collect_block_leaves(0, &txs, 0, &mut entries);
    let root = root_from_scalars(&assemble_leaf_stream(&entries, gindex));
    std::hint::black_box((gindex, root));
}

#[test]
#[ignore = "Tier B: needs the engine staking SEND path (built separately) to mint a staked output + a ct2_tier_b staked chain"]
fn staked_output_uses_max_lock_and_spendable() {
    _staked_drift_canary();
    todo!(
        "staked send path pending; max(stake_lock, +10) maturity not yet mintable on the regtest"
    );
}

#[test]
#[ignore = "Tier B: needs a hand-crafted C++ daemon duplicate/malformed 0x07 oracle (no regtest)"]
fn scanner_extra_0x07_matches_daemon_on_adversarial_extra() {
    // Scanner parse is `shekyl_scanner::extra::Extra`; validate stage is
    // `recon::extract_leaf_hashes` (the %32 check). Cross-crate seam — no scanner
    // dep here.
    let hashes = extract_leaf_hashes(Some(&[0u8; 33]));
    std::hint::black_box(hashes);
    todo!("daemon duplicate/malformed 0x07 oracle pending");
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! W9 **leaf-stuffer** cost model (A4, §12.2 / DQ-2C).
//!
//! **Shape, stated so no future reader imports the wrong threat model:** the
//! stuffer's transaction is **1-in / 16-out** — a *max-leaves-per-fee geometry*,
//! **not** a black-marble/decoy construct. FCMP++ has **no rings**; the 16
//! outputs are curve-tree **leaves** that inflate `frozen_segment_count` (and so
//! the D2 escalation share), they do **not** poison a decoy pool (the ring-side
//! half of the Rucknium report that FCMP++ deletes and A4 does not model). 16 =
//! `MAX_OUTPUTS` = `2^4` (zero Bp+ padding waste) maximises leaves/tx; 1 input
//! minimises the per-input FCMP membership proof (the FCMP++-adapted shape —
//! Monero's stuffer used 2-in because a ring is cheap per input; a membership
//! proof is not).
//!
//! **DQ-2G / DQ-2C — cost is single-sourced through the production predictor.**
//! The per-tx weight comes from `shekyl_tx_weight::predict_weight` (the
//! byte-mirror of `Transaction::write`, hoisted D-1), not a hand byte-model;
//! `tree_depth` rides the scenario's `n` via the production
//! [`shekyl_curve_tree::segment::outputs_per_node`], so early-chain shallow-tree
//! proofs are correctly cheaper (the binding direction, §11.3). The Monero
//! March-2024 figures are an order-of-magnitude anchor + proof-of-willingness
//! (§12.3 DQ-2C), re-derived on Shekyl's own schedule below — never hard-coded.

use shekyl_archival_retention::SEGMENT_LEAF_COUNT;
use shekyl_curve_tree::segment::outputs_per_node;
use shekyl_tx_weight::{predict_weight, InputCount, OutputCount, MAX_OUTPUTS, MAX_TREE_DEPTH};

/// Minimum weight-fee, atomic units per byte (`cryptonote_config.h:66`
/// `FEE_PER_BYTE = 300`). Genesis-provisional; the stuffer pays this floor
/// (DQ-2C directive 1). A boundary constant (scenario layer, DQ-2G).
pub const FEE_PER_BYTE_ATOMIC: u64 = 300;

/// Outputs per stuffer tx — the max-leaves-per-fee shape. Single-sourced from
/// the consensus `MAX_OUTPUTS` (16) so the shape can't drift from the wire cap.
pub const STUFFER_OUTPUTS_PER_TX: u64 = MAX_OUTPUTS as u64;

// ── Rucknium March-2024 anchor (DQ-2C; report/calibration only) ──────────────
/// Sustained duration of the incident, days (report §6). Weeks, not a burst.
pub const RUCKNIUM_DURATION_DAYS: u64 = 23;
/// Total spam fees paid, XMR (report §6). ~a quarter-cent per output at the time.
pub const RUCKNIUM_SPAM_FEES_XMR: f64 = 61.5;
/// Total spam bytes, GB (report §6). `20 nanonero/byte × 3.08 GB ≈ 61.6 XMR`.
pub const RUCKNIUM_SPAM_BYTES_GB: f64 = 3.08;
/// Spam outputs (~3.2 M) as Shekyl shards' worth of leaves — the replication row.
#[must_use]
pub fn rucknium_shards_equivalent() -> u64 {
    // ~1.6 M 1in/2out txs ⇒ ~3.2 M outputs.
    3_200_000 / SEGMENT_LEAF_COUNT
}

/// Curve-tree depth needed to hold `n` leaves — the smallest layer whose
/// production capacity ([`outputs_per_node`]) covers `n`, clamped to the proof
/// system's max. Deps the real width logic (DQ-2G dep-don't-mirror), so the
/// stuffer's FCMP proof cost rides real chain depth: shallow (cheap) early,
/// deeper (dearer) late.
#[must_use]
pub fn tree_depth_for_leaves(n: u64) -> u8 {
    let n = n.max(1);
    for j in 0..=MAX_TREE_DEPTH {
        if outputs_per_node(j) as u64 >= n {
            return j.max(1);
        }
    }
    MAX_TREE_DEPTH
}

/// Weight-fee (atomic) of one 1-in/16-out stuffer tx at `tree_depth`, via the
/// **converge fixpoint** the build path runs (fee feeds `varint(fee)` into the
/// weight, so it is circular by a few bytes; two iterations from the fee floor
/// settle it — cheaper than approximating, now that the real predictor is a
/// dep). Integer throughout (DQ-2G): `fee = predict_weight × FEE_PER_BYTE`.
#[must_use]
pub fn stuffer_tx_fee_atomic(tree_depth: u8) -> u64 {
    let n_in = InputCount::clamped(1);
    let n_out = OutputCount::clamped(STUFFER_OUTPUTS_PER_TX as usize);
    let mut fee = 0u64;
    for _ in 0..2 {
        let weight = predict_weight(n_in, n_out, tree_depth, fee) as u64;
        fee = weight * FEE_PER_BYTE_ATOMIC;
    }
    fee
}

/// Attacker cost (atomic) to inflate the corpus by one shard's worth of leaves
/// (`SEGMENT_LEAF_COUNT` outputs) when the chain is at `n_at_attack` leaves.
/// Each 1-in/16-out tx adds 16 leaves; `ceil(SEGMENT_LEAF_COUNT / 16)` txs, each
/// at the converged min-fee for the chain's depth. Integer (DQ-2G).
#[must_use]
pub fn leaf_stuffer_cost_per_shard_atomic(n_at_attack: u64) -> u128 {
    let depth = tree_depth_for_leaves(n_at_attack);
    let tx_fee = u128::from(stuffer_tx_fee_atomic(depth));
    let txs_per_shard = u128::from(SEGMENT_LEAF_COUNT).div_ceil(u128::from(STUFFER_OUTPUTS_PER_TX));
    txs_per_shard * tx_fee
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_depth_monotone_and_bounded() {
        // Deeper chains need deeper trees; always in [1, MAX].
        let d_small = tree_depth_for_leaves(1_000);
        let d_big = tree_depth_for_leaves(5_000_000_000);
        assert!((1..=MAX_TREE_DEPTH).contains(&d_small));
        assert!(d_big >= d_small);
        // SEGMENT_LEAF_COUNT (25,992) is exactly outputs_per_node(2), so a chain
        // at one shard sits at depth 2.
        assert_eq!(tree_depth_for_leaves(SEGMENT_LEAF_COUNT), 2);
    }

    #[test]
    fn stuffer_cost_positive_and_cheaper_when_shallow() {
        // A shallow (early-chain) tree yields a smaller FCMP proof ⇒ a cheaper
        // stuffer tx than a deep (late-chain) tree — the binding direction (§11.3).
        let early = stuffer_tx_fee_atomic(tree_depth_for_leaves(30_000)); // ~depth 3
        let late = stuffer_tx_fee_atomic(tree_depth_for_leaves(5_000_000_000)); // ~depth 6
        assert!(early > 0 && late > 0);
        assert!(
            early < late,
            "shallow tree must be cheaper per tx: early={early} late={late}"
        );
    }

    #[test]
    fn cost_per_shard_is_txs_times_fee() {
        let n = 100_000;
        let depth = tree_depth_for_leaves(n);
        let expected = (u128::from(SEGMENT_LEAF_COUNT).div_ceil(16))
            * u128::from(stuffer_tx_fee_atomic(depth));
        assert_eq!(leaf_stuffer_cost_per_shard_atomic(n), expected);
        assert!(expected > 0);
    }
}

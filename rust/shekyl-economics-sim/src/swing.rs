// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **A6 — swing / band width** (§12.2), the empirical check on the doc's **oldest
//! open claim**: §6.0's *structural* argument that the escalation operand cannot
//! swing.
//!
//! §6.0 asserts the operand is **monotone** (shard count only rises in the
//! canonical chain), **slow** (it advances with output volume), and **predictable**
//! (a pure map of `n`, no controller) — from which §6.1 concludes there is no
//! swing lever and W8 is armed *by operand*. Those are structural claims; A6
//! measures them.
//!
//! **The binding input is a flood, not organic growth.** A W9 stuffer is the
//! fastest `n` can physically move — it buys leaves at the block-weight ceiling —
//! so the honest worst case for a no-controller constraint is the **adversarial**
//! slew, not the scenario trajectories. If per-epoch `Δshare` is invisible even
//! under a sustained flood at the surge ceiling, §6.1's negative constraint is
//! vindicated end-to-end.
//!
//! **Reorg reversibility.** Monotonicity holds *in the canonical chain*; a reorg
//! can un-freeze shards. `ARCHIVAL_REORG_DEPTH_BLOCKS` bounds how far back that
//! reaches, so it bounds the only down-swing that exists.

use shekyl_archival_retention::SEGMENT_LEAF_COUNT;

use crate::calibration::{
    leaf_stuffer_cost_per_shard_atomic, stuffer_tx_fee_atomic, tree_depth_for_leaves,
    FEE_PER_BYTE_ATOMIC,
};
use crate::escalation::{family, EscalationCurve, SHARE_SCALE};

/// Long-term block-weight median floor, bytes
/// (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). The penalty-free block size.
pub const BLOCK_WEIGHT_FLOOR: u64 = 300_000;

/// Short-term surge factor over the long-term median
/// (`CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR`) — the ceiling a flood can
/// reach in a burst before the median catches up.
pub const BLOCK_WEIGHT_SURGE_FACTOR: u64 = 50;

/// Settlement epoch length, blocks (`SETTLEMENT_EPOCH_BLOCKS`).
pub const EPOCH_BLOCKS: u64 = 10_000;

/// Reorg depth bound, blocks (`ARCHIVAL_REORG_DEPTH_BLOCKS`) — the reach of the
/// only down-swing the operand admits.
pub const REORG_DEPTH_BLOCKS: u64 = 720;

/// Outputs the stuffer can land in one block at `block_weight` — the physical
/// leaf-minting ceiling. Uses the **production** predictor's weight for the
/// 1-in/16-out shape (recovered from its min-fee, which is `weight × FEE_PER_BYTE`).
#[must_use]
pub fn max_outputs_per_block(block_weight: u64, n_shards: u64) -> u64 {
    let depth = tree_depth_for_leaves(n_shards.max(1).saturating_mul(SEGMENT_LEAF_COUNT));
    let tx_weight = stuffer_tx_fee_atomic(depth) / FEE_PER_BYTE_ATOMIC;
    if tx_weight == 0 {
        return 0;
    }
    (block_weight / tx_weight).saturating_mul(crate::calibration::STUFFER_OUTPUTS_PER_TX)
}

/// Shards a flood can freeze over `blocks` at `block_weight` — the max slew of the
/// D2 operand. Integer throughout.
#[must_use]
pub fn max_shards_per_window(blocks: u64, block_weight: u64, n_shards: u64) -> u64 {
    let outputs = max_outputs_per_block(block_weight, n_shards).saturating_mul(blocks);
    outputs / SEGMENT_LEAF_COUNT
}

/// `Δshare` (fixed-point `SHARE_SCALE`) a jump from `n` to `n + delta` produces
/// under `curve` — the swing the operand can actually express.
#[must_use]
pub fn delta_share(curve: &EscalationCurve, n: u64, delta: u64) -> u64 {
    curve
        .share(n.saturating_add(delta))
        .saturating_sub(curve.share(n))
}

/// A6 report: the slew ceiling, per-epoch `Δshare` under a sustained flood, and
/// the reorg-window reversibility bound — measured on the **steepest** candidate,
/// since a cliff would appear there first.
pub fn a6_report(n_samples: &[u64]) {
    let curve = family()
        .iter()
        .max_by_key(|c| c.asymptote)
        .copied()
        .unwrap_or_else(crate::escalation::flat_25);
    let surge = BLOCK_WEIGHT_FLOOR * BLOCK_WEIGHT_SURGE_FACTOR;
    eprintln!(
        "\nA6 — swing / band width (§12.2): the empirical check on §6.0's STRUCTURAL claim\n\
         that the operand cannot swing (monotone + slow + no controller ⇒ W8 armed by\n\
         operand). Binding input is a W9 FLOOD, not organic growth — a stuffer buying\n\
         leaves at the block-weight ceiling is the fastest n can physically move.\n\
         Ceiling: {FLOOR} B/block floor x{SURGE} surge = {SU} B; epoch = {EB} blocks;\n\
         reorg reach = {RD} blocks. Curve = steepest candidate (asymptote {A:.0}%,\n\
         knee {K}) — a cliff would surface there first.",
        FLOOR = BLOCK_WEIGHT_FLOOR,
        SURGE = BLOCK_WEIGHT_SURGE_FACTOR,
        SU = surge,
        EB = EPOCH_BLOCKS,
        RD = REORG_DEPTH_BLOCKS,
        A = curve.asymptote as f64 / 10_000.0,
        K = curve.knee_shards,
    );
    eprintln!(
        "{:>9} {:>12} {:>14} {:>16} {:>16}",
        "n", "Δn/epoch", "Δshare/epoch", "Δshare %pts/ep", "reorg Δshare%pt"
    );
    let mut worst_epoch_pts = 0.0_f64;
    let mut worst_reorg_pts = 0.0_f64;
    let mut worst_dn = 0u64;
    for &n in n_samples {
        let dn_epoch = max_shards_per_window(EPOCH_BLOCKS, surge, n);
        let dn_reorg = max_shards_per_window(REORG_DEPTH_BLOCKS, surge, n);
        let ds_epoch = delta_share(&curve, n, dn_epoch);
        let ds_reorg = delta_share(&curve, n, dn_reorg);
        let pts = ds_epoch as f64 / SHARE_SCALE as f64 * 100.0;
        worst_epoch_pts = worst_epoch_pts.max(pts);
        worst_reorg_pts = worst_reorg_pts.max(ds_reorg as f64 / SHARE_SCALE as f64 * 100.0);
        worst_dn = worst_dn.max(dn_epoch);
        eprintln!(
            "{:>9} {:>12} {:>14} {:>15.4}% {:>15.4}%",
            n,
            dn_epoch,
            ds_epoch,
            pts,
            ds_reorg as f64 / SHARE_SCALE as f64 * 100.0,
        );
    }
    eprintln!(
        "  -> Read: 'Δshare %pts/ep' is the MAXIMUM the staker share can move in one\n\
         settlement epoch when an adversary floods at the surge ceiling for the whole\n\
         epoch — the worst case for §6.0's no-swing claim. Worst observed: {W:.4} points.\n\
         The reorg column bounds the only DOWN-swing that exists (monotonicity holds in\n\
         the canonical chain; a reorg can un-freeze at most {RD} blocks' worth).\n\
         VERDICT: {V}",
        W = worst_epoch_pts,
        RD = REORG_DEPTH_BLOCKS,
        V = if worst_epoch_pts < 1.0 {
            "no measurable adversarial slew."
        } else {
            "see the slew reading below."
        },
    );
    eprintln!(
        "  -> §6.0/§6.1 SEPARATED, because they are different claims:\n\
         (a) CLIFF (structural, §6.1's actual requirement) — NOT present. The share is\n\
             monotone and a single shard never moves it discontinuously; the family's\n\
             `no_cliff_bounded_slope` test pins that, and the reorg column shows the only\n\
             down-swing reaches {RDP:.4} points. W8 stands armed BY OPERAND.\n\
         (b) ADVERSARIAL SLEW RATE (economic) — {W:.4} points per epoch is the CEILING a\n\
             flood can force, at maximum effort, early-chain. That is a rate, not a cliff,\n\
             and it is bounded, monotone and one-directional — but it is NOT invisible,\n\
             which is the honest correction to a purely structural reading of §6.0.\n\
             It is also PRICED: that slew costs ~{C:.0} SKL/epoch in stuffing fees at the\n\
             A4 rate, and A4 already gates whether such a flood pays (it does not, once\n\
             the reopen-(c) fee-floor lands). So the swing lever exists physically and is\n\
             closed ECONOMICALLY, not structurally — Stage 3 should freeze the shape\n\
             knowing that, rather than on the stronger claim that no lever exists.",
        RDP = worst_reorg_pts,
        W = worst_epoch_pts,
        C = worst_dn as f64
            * (leaf_stuffer_cost_per_shard_atomic(SEGMENT_LEAF_COUNT) as f64 / 1.0e9),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flood_ceiling_is_finite_and_depth_sensitive() {
        let surge = BLOCK_WEIGHT_FLOOR * BLOCK_WEIGHT_SURGE_FACTOR;
        let early = max_shards_per_window(EPOCH_BLOCKS, surge, 1_000);
        let late = max_shards_per_window(EPOCH_BLOCKS, surge, 5_000_000);
        assert!(early > 0, "a flood must be able to move n at all");
        // Deeper trees ⇒ heavier proofs ⇒ fewer leaves per block, so the ceiling
        // falls as the chain grows: the operand gets HARDER to move over time.
        assert!(late <= early, "slew ceiling must not rise with chain depth");
    }

    #[test]
    fn share_is_monotone_and_continuous_which_is_what_6_1_requires() {
        // §6.1's requirement is MONOTONE + BOUNDED-SLOPE (no discontinuity) — NOT
        // "under N points per epoch", which would be an invented threshold. The
        // adversarial slew RATE is a reported quantity for the freeze decision
        // (see `a6_report`), not a pass/fail gate. What must hold structurally:
        // the share never decreases, and no single shard causes a jump.
        let curve = family()
            .iter()
            .max_by_key(|c| c.asymptote)
            .copied()
            .unwrap();
        let surge = BLOCK_WEIGHT_FLOOR * BLOCK_WEIGHT_SURGE_FACTOR;
        for &n in &[0u64, 1_000, 25_000, 100_000, 250_000] {
            // Monotone: the share never falls as n rises.
            assert!(curve.share(n + 1) >= curve.share(n), "monotone at n={n}");
            // Bounded slope: one more shard cannot move the share discontinuously.
            // (A "cliff" is a jump, not a rate — this is the §6.1 property.)
            let step = curve.share(n + 1).saturating_sub(curve.share(n));
            assert!(
                step <= SHARE_SCALE / 1_000,
                "single-shard jump at n={n}: {step}"
            );
            // The adversarial slew is finite and reported, not gated here.
            let dn = max_shards_per_window(EPOCH_BLOCKS, surge, n.max(1));
            assert!(dn > 0 && delta_share(&curve, n, dn) < SHARE_SCALE);
        }
    }

    #[test]
    fn reorg_bound_is_a_strict_subset_of_the_epoch_bound() {
        // The only down-swing reaches at most REORG_DEPTH_BLOCKS, which is a small
        // fraction of an epoch — so reversibility cannot exceed the up-slew.
        let surge = BLOCK_WEIGHT_FLOOR * BLOCK_WEIGHT_SURGE_FACTOR;
        const _: () = assert!(REORG_DEPTH_BLOCKS < EPOCH_BLOCKS);
        let n = 50_000;
        assert!(
            max_shards_per_window(REORG_DEPTH_BLOCKS, surge, n)
                <= max_shards_per_window(EPOCH_BLOCKS, surge, n)
        );
    }
}

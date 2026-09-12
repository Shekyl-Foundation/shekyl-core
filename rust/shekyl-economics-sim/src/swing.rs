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

use std::fmt;

use shekyl_archival_retention::SEGMENT_LEAF_COUNT;

use crate::calibration::{
    leaf_stuffer_cost_per_shard_atomic, stuffer_tx_fee_atomic, tree_depth_for_leaves,
    FEE_PER_BYTE_ATOMIC,
};
use crate::escalation::{family, EscalationCurve, SHARE_SCALE};

/// Long-term block-weight median floor, bytes
/// (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). The penalty-free block size.
pub const BLOCK_WEIGHT_FLOOR: u64 = 300_000;

/// Short-term surge factor `S` over the long-term median.
///
/// Re-exported from [`shekyl_economics`], which reads it from the build
/// authority `config/consensus_constants.json` — the same file that emits the
/// C++ `SHEKYL_BLOCK_WEIGHT_SHORT_TERM_SURGE_FACTOR` consumed by the clamp in
/// `Blockchain::update_next_cumulative_weight_limit`. It is **not** re-declared
/// here: a sim that prices flood capacity against a locally-held copy can
/// validate a parameter the chain does not enforce, which is exactly what
/// happened while this constant sat at the refuted `x50`.
///
/// If this harness ever needs to *sweep* `S`, take it as a parameter at the
/// call site rather than shadowing the consensus value with a second constant.
pub use shekyl_economics::BLOCK_WEIGHT_SURGE_FACTOR;

/// The saturated effective median: what a maximal flood can lift the
/// penalty-free ceiling to (`blockchain.cpp::update_next_cumulative_weight_limit`,
/// the ArticMine-2021 algorithm):
///
/// - `effective_median = min(max(LTM_eff, short_term_median), S · LTM_eff)`
/// - `block_weight_limit = effective_median · 2`
///
/// A flood ratchets `effective_median` up — it is the median of the last 100
/// actual weights — until it saturates at `S · LTM_eff`. The **penalty-free**
/// ceiling is the effective median itself; blocks above it up to `2×` are legal
/// but cost the miner a reward penalty the flooder must compensate.
///
/// **Time to saturate is DERIVED, not a frozen measurement** — see
/// [`blocks_to_surge_saturation`]. The figure this doc-comment used to carry
/// ("~300 blocks, 3 % of an epoch, negligible") was a simulation result that
/// depended on the refuted `S = 50`, with no reproducible computation behind
/// it; at the ratified `S = 4` it is **~102 blocks, ~1 % of an epoch**. The
/// conclusion does not change sign — saturation is *faster*, because there are
/// fewer doublings to climb — but the ceiling it saturates *to* is 12.5× lower.
///
/// **The long-term median does not move within an epoch**, which is what makes the
/// surge sustainable: each block's long-term weight is clamped to `1.7 · LTM_eff`
/// (`get_next_long_term_block_weight`), and 10 000 elevated blocks cannot shift a
/// 100 000-block median. Simulation confirms `LTM = 300 000` at epoch end.
pub const BLOCK_WEIGHT_PENALTY_FREE: u64 = BLOCK_WEIGHT_FLOOR * BLOCK_WEIGHT_SURGE_FACTOR;

/// Blocks a maximal flood needs to lift the effective median from the
/// long-term effective median all the way to the surge ceiling `S · LTM_eff`.
///
/// **Derivation** (C2-R2 Q3 ratifies both inputs): the short-term window is 100
/// blocks and its median only moves once more than half the window carries the
/// new level, so a flooder needs **51** blocks at the current limit to move the
/// median to it — the ratified *51-block doubling envelope*. Each crossing
/// doubles the limit (`limit = 2 · effective_median`), so reaching a ceiling
/// `S ×` above the starting median takes `ceil(log2(S))` crossings.
///
/// This replaces a frozen "~300 blocks" that no code computed. The model is
/// validated against that historical simulation at the value it was measured
/// under: at `S = 50` it returns 306, which is the "~300 blocks — 3 % of an
/// epoch" the old comment recorded. Agreeing with an independent measurement at
/// the refuted value is what licenses using it at the ratified one.
#[must_use]
pub const fn blocks_to_surge_saturation(surge_factor: u64) -> u64 {
    const SHORT_TERM_WINDOW: u64 = 100;
    // Strictly more than half the window must carry the new level.
    const BLOCKS_PER_CROSSING: u64 = SHORT_TERM_WINDOW / 2 + 1;

    let mut crossings = 0;
    let mut reached = 1;
    while reached < surge_factor {
        reached *= 2;
        crossings += 1;
    }
    crossings * BLOCKS_PER_CROSSING
}

/// The legal per-block ceiling: `2 ×` the effective median. Using it costs the
/// miner-reward penalty, so a flooder pays for the extra capacity twice (fees and
/// penalty compensation) — but it is available, and it is **double** what a
/// penalty-free model predicts.
pub const BLOCK_WEIGHT_MAX: u64 = BLOCK_WEIGHT_PENALTY_FREE * 2;

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

/// **Miner-reward penalty compensation**, SKL per epoch, for a flooder using the
/// legal `2×` limit — **measured from the production penalty formula**, not
/// derived. `cryptonote_basic_impl.cpp::get_block_reward`:
///
/// ```text
/// reward = base_reward · (2M − B) · B / M²      for M < B ≤ 2M
/// ```
///
/// At `B = 2M` this is **exactly zero** — the miner forfeits the *entire* block
/// reward — so a flooder at the ceiling must compensate `base_reward` per block or
/// no rational miner includes the flood. Over an epoch that is
/// `base_reward × EPOCH_BLOCKS`, which **dwarfs the stuffing fees**.
#[must_use]
pub fn penalty_compensation_skl_per_epoch(base_block_reward_atomic: u64) -> f64 {
    // reward at B = 2M is 0 ⇒ full base_reward forfeited, every block.
    (u128::from(base_block_reward_atomic) * u128::from(EPOCH_BLOCKS)) as f64 / 1.0e9
}

/// A6 report: the slew ceiling, per-epoch `Δshare` under a sustained flood, and
/// the reorg-window reversibility bound — measured on the **steepest** candidate,
/// since a cliff would appear there first.
pub fn a6_report(
    out: &mut impl fmt::Write,
    n_samples: &[u64],
    base_block_reward_atomic: u64,
) -> fmt::Result {
    let curve = family()
        .iter()
        .max_by_key(|c| c.asymptote)
        .copied()
        .unwrap_or_else(crate::escalation::flat_25);
    let surge = BLOCK_WEIGHT_PENALTY_FREE;
    writeln!(
        out,
        "\nA6 — swing / band width (§12.2): the empirical check on §6.0's STRUCTURAL claim\n\
         that the operand cannot swing (monotone + slow + no controller ⇒ W8 armed by\n\
         operand). Binding input is a W9 FLOOD, not organic growth — a stuffer buying\n\
         leaves at the block-weight ceiling is the fastest n can physically move.\n\
         Ceiling: {FLOOR} B/block floor x{SURGE} surge = {SU} B, reached after\n\
         ~{SAT} blocks of sustained flood ({SATPCT:.1}% of an epoch); epoch = {EB} blocks;\n\
         reorg reach = {RD} blocks. Curve = steepest candidate (asymptote {A:.0}%,\n\
         knee {K}) — a cliff would surface there first.",
        FLOOR = BLOCK_WEIGHT_FLOOR,
        SURGE = BLOCK_WEIGHT_SURGE_FACTOR,
        SU = surge,
        SAT = blocks_to_surge_saturation(BLOCK_WEIGHT_SURGE_FACTOR),
        SATPCT = blocks_to_surge_saturation(BLOCK_WEIGHT_SURGE_FACTOR) as f64 * 100.0
            / EPOCH_BLOCKS as f64,
        EB = EPOCH_BLOCKS,
        RD = REORG_DEPTH_BLOCKS,
        A = curve.asymptote as f64 / 10_000.0,
        K = curve.knee_shards,
    )?;
    writeln!(
        out,
        "{:>9} {:>12} {:>14} {:>16} {:>17} {:>15}",
        "n", "Δn/epoch", "Δshare/epoch", "Δshare %pts/ep", "%pts/ep w/penalty", "reorg Δshare%pt"
    )?;
    let mut worst_epoch_pts = 0.0_f64;
    let mut worst_reorg_pts = 0.0_f64;
    let mut worst_dn = 0u64;
    let mut worst_pen_pts = 0.0_f64;
    for &n in n_samples {
        let dn_epoch = max_shards_per_window(EPOCH_BLOCKS, surge, n);
        let dn_pen = max_shards_per_window(EPOCH_BLOCKS, BLOCK_WEIGHT_MAX, n);
        let dn_reorg = max_shards_per_window(REORG_DEPTH_BLOCKS, surge, n);
        let ds_epoch = delta_share(&curve, n, dn_epoch);
        let ds_reorg = delta_share(&curve, n, dn_reorg);
        let pts = ds_epoch as f64 / SHARE_SCALE as f64 * 100.0;
        worst_epoch_pts = worst_epoch_pts.max(pts);
        worst_reorg_pts = worst_reorg_pts.max(ds_reorg as f64 / SHARE_SCALE as f64 * 100.0);
        worst_dn = worst_dn.max(dn_pen);
        worst_pen_pts =
            worst_pen_pts.max(delta_share(&curve, n, dn_pen) as f64 / SHARE_SCALE as f64 * 100.0);
        writeln!(
            out,
            "{:>9} {:>12} {:>14} {:>15.4}% {:>16.4}% {:>14.4}%",
            n,
            dn_epoch,
            ds_epoch,
            pts,
            delta_share(&curve, n, dn_pen) as f64 / SHARE_SCALE as f64 * 100.0,
            ds_reorg as f64 / SHARE_SCALE as f64 * 100.0,
        )?;
    }
    writeln!(
        out,
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
    )?;
    writeln!(out,
        "  -> §6.0/§6.1 SEPARATED, because they are different claims:\n\
         (a) CLIFF (structural, §6.1's actual requirement) — NOT present. The share is\n\
             monotone and a single shard never moves it discontinuously; the family's\n\
             `no_cliff_bounded_slope` test pins that, and the reorg column shows the only\n\
             down-swing reaches {RDP:.4} points. W8 stands armed BY OPERAND.\n\
         (b) ADVERSARIAL SLEW RATE (economic) — {W:.4} pts/epoch penalty-free, {WP:.4}\n\
             pts/epoch if the flooder also compensates the miner penalty (the legal 2x\n\
             limit). MEASURED against blockchain.cpp's ArticMine algorithm, not derived —\n\
             the ceiling a flood can force at maximum effort, early-chain. A rate, not a cliff,\n\
             and it is bounded, monotone and one-directional — but it is NOT invisible,\n\
             which is the honest correction to a purely structural reading of §6.0.\n\
             It is also PRICED, and the legal-limit price is dominated by a term that is\n\
             NOT the fees: ~{C:.0} SKL/epoch in stuffing fees at the A4 rate, PLUS\n\
             ~{P:.0} SKL/epoch of miner-reward penalty compensation — at B = 2M the\n\
             production penalty formula (get_block_reward) pays the miner EXACTLY ZERO,\n\
             so the flooder must fund the whole block reward, every block, or no rational\n\
             miner includes the flood. Measured, not derived. A4 already gates whether\n\
             such a flood pays (it does not, once the reopen-(c) fee-floor lands). So the swing lever exists physically and is\n\
             closed ECONOMICALLY, not structurally — Stage 3 should freeze the shape\n\
             knowing that, rather than on the stronger claim that no lever exists.",
        RDP = worst_reorg_pts,
        W = worst_epoch_pts,
        WP = worst_pen_pts,
        C = worst_dn as f64
            * (leaf_stuffer_cost_per_shard_atomic(SEGMENT_LEAF_COUNT) as f64 / 1.0e9),
        P = penalty_compensation_skl_per_epoch(base_block_reward_atomic),
    )?;

    Ok(())
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

#[cfg(test)]
mod surge_saturation_tests {
    use super::{blocks_to_surge_saturation, BLOCK_WEIGHT_SURGE_FACTOR, EPOCH_BLOCKS};

    /// The model must reproduce the historical simulation at the value that
    /// simulation was run under. Without this leg the derivation below is an
    /// unvalidated formula that happens to produce a number.
    #[test]
    fn the_model_reproduces_the_measured_figure_at_the_refuted_factor() {
        // The doc-comment this replaced recorded "~300 blocks — 3 % of an
        // epoch" at S = 50, measured by simulation.
        assert_eq!(blocks_to_surge_saturation(50), 306);
        assert_eq!(306 * 100 / EPOCH_BLOCKS, 3);
    }

    /// The re-derivation at the ratified value. NOT the old number edited.
    #[test]
    fn saturation_at_the_ratified_factor_is_about_one_percent_of_an_epoch() {
        assert_eq!(blocks_to_surge_saturation(4), 102);
        // ~1 % of a 10 000-block epoch: the "negligible" conclusion holds and
        // strengthens — fewer doublings to climb, so the flood saturates sooner.
        assert!(blocks_to_surge_saturation(4) * 100 / EPOCH_BLOCKS <= 1);
    }

    /// Whatever the consensus authority currently says, saturation must stay a
    /// small fraction of an epoch — the property the sim's flood scenarios rely
    /// on. Fails loudly if a future re-derivation of S breaks the assumption
    /// rather than letting the harness keep modelling a stale one.
    #[test]
    fn saturation_at_the_live_factor_stays_within_an_epoch() {
        let blocks = blocks_to_surge_saturation(BLOCK_WEIGHT_SURGE_FACTOR);
        assert!(
            blocks > 0,
            "a surge factor above 1 must take at least one crossing"
        );
        assert!(
            blocks * 20 < EPOCH_BLOCKS,
            "saturation {blocks} blocks is no longer negligible against a {EPOCH_BLOCKS}-block epoch"
        );
    }

    /// S = 1 means no surge headroom at all: no crossings, nothing to climb.
    #[test]
    fn a_unit_surge_factor_needs_no_crossings() {
        assert_eq!(blocks_to_surge_saturation(1), 0);
    }
}

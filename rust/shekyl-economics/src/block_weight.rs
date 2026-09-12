// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How the effective block-weight median `M` is built.
//!
//! This is the ArticMine weight governor, not the fee-lane transaction-count
//! SMA. Long-term median `Mlw` over 100 000 blocks, short-term median over
//! 100, effective median clamped to `[Mlw, S·Mlw]`. The fee ladder *prices
//! against* `M`; it never ruled on how `M` is assembled. `S` is consensus
//! (C2-R2 Q3).
//!
//! **Changing `S` does not move a fee number**, but not for the reason this
//! comment first gave. It cited the ladder taking `Mfw = min(Mnw, Mlw)` with
//! the clamp's lower arm forcing `Mnw ≥ Mlw`; FL-R20 then deleted that
//! two-median computation, so there is no `min` left to select anything. The
//! conclusion survives on the operand instead: the fee estimate reads the
//! **long-term** effective median directly, and the surge clamp applies to the
//! short-term median, which never reaches that path.
//!
//! The block-weight *penalty* still prices against the effective median, so
//! during a surge the penalty and the fee floor price the same expansion off
//! operands that differ by up to `S` — the divergence recorded in
//! `FOLLOWUPS.md`.

use crate::params::GENERATED_BLOCK_WEIGHT_SURGE_FACTOR;

/// Short-term surge factor `S` — ceiling of the fast governor.
///
/// `config/consensus_constants.json` `block_weight_short_term_surge_factor`.
/// Ratified `S = 4` (`CONSENSUS_C2_R2_WEIGHT_FEES.md` Q3). Loosening `S`
/// reopens Q2: for the first ~100 000 blocks this bound is the only
/// protection against early-chain weight growth.
pub const BLOCK_WEIGHT_SURGE_FACTOR: u64 = GENERATED_BLOCK_WEIGHT_SURGE_FACTOR;

/// Effective median: `short_term` bounded to `[long_term, S · long_term]`.
///
/// `long_term` is the already-floored long-term effective median (`≥` the
/// penalty-free zone). `S · long_term` saturates at `u64::MAX` rather than
/// wrapping: a wrapped ceiling would clamp *down* and reject legal blocks.
#[must_use]
pub fn effective_median(long_term: u64, short_term: u64) -> u64 {
    let ceiling = long_term.saturating_mul(BLOCK_WEIGHT_SURGE_FACTOR);
    short_term.max(long_term).min(ceiling)
}

/// Blocks a maximal flood needs to lift the effective median from the
/// long-term effective median to the surge ceiling `S · LTEM`.
///
/// The short-term window is 100 blocks; its median moves once more than
/// half the window carries the new level, so each doubling costs 51
/// blocks (C2-R2 Q3's 51-block doubling envelope). Reaching a ceiling
/// `S ×` above the starting median takes `ceil(log2(S))` crossings.
///
/// Validated against the historical simulation at the refuted `S = 50`
/// (returns 306, the "~300 blocks — 3 % of an epoch" that simulation
/// recorded) before being applied at the ratified `S = 4` (102).
#[must_use]
pub const fn blocks_to_surge_saturation(surge_factor: u64) -> u64 {
    const SHORT_TERM_WINDOW: u64 = 100;
    const BLOCKS_PER_CROSSING: u64 = SHORT_TERM_WINDOW / 2 + 1;

    let mut crossings = 0u64;
    let mut reached = 1u64;
    while reached < surge_factor {
        let next = reached.saturating_mul(2);
        if next == reached {
            break;
        }
        reached = next;
        crossings += 1;
    }
    crossings.saturating_mul(BLOCKS_PER_CROSSING)
}

#[cfg(test)]
mod tests {
    use super::{blocks_to_surge_saturation, effective_median, BLOCK_WEIGHT_SURGE_FACTOR};

    const ZONE: u64 = 300_000;
    const RATIFIED: u64 = 4;

    #[test]
    fn the_live_factor_is_the_ratified_value() {
        assert_eq!(BLOCK_WEIGHT_SURGE_FACTOR, RATIFIED);
    }

    #[test]
    fn a_short_term_median_far_above_the_ceiling_clamps_to_s_times_long_term() {
        assert_eq!(effective_median(ZONE, ZONE * 100), RATIFIED * ZONE);
    }

    #[test]
    fn a_short_term_median_inside_the_band_passes_through() {
        let inside = ZONE * 2;
        assert!(inside > ZONE && inside < RATIFIED * ZONE);
        assert_eq!(effective_median(ZONE, inside), inside);
    }

    #[test]
    fn a_short_term_median_below_long_term_does_not_pull_the_floor_down() {
        assert_eq!(effective_median(ZONE, ZONE / 10), ZONE);
    }

    #[test]
    fn the_lower_arm_holds_in_every_clamp_state_including_saturation() {
        // The clamp's lower arm: the effective median is NEVER below the
        // long-term median, whatever the short-term median does — swept
        // across both clamp arms and the saturating ceiling, which the
        // single-case test above does not cover.
        //
        // Renamed from `the_fee_ladder_operand_is_the_long_term_median_...`:
        // the property is real, but the name and its comment described a
        // consumer that no longer exists. It read the assertion as proving
        // the ladder's `Mfw = min(Mnw, Mlw)` selects `Mlw`, and FL-R20
        // deleted that computation. A test named for a dead caller invites
        // the next reader to delete it with the caller; named for the
        // invariant, it survives on its own terms.
        for st in [0, ZONE / 10, ZONE, ZONE * 2, ZONE * 100, u64::MAX] {
            assert!(effective_median(ZONE, st) >= ZONE, "st={st}");
        }
    }

    #[test]
    fn a_saturating_ceiling_does_not_wrap_and_clamp_down() {
        assert_eq!(effective_median(u64::MAX, 0), u64::MAX);
        assert_eq!(effective_median(u64::MAX / 2, u64::MAX), u64::MAX);
    }

    #[test]
    fn the_model_reproduces_the_measured_figure_at_the_refuted_factor() {
        assert_eq!(blocks_to_surge_saturation(50), 306);
    }

    #[test]
    fn saturation_at_the_ratified_factor_is_two_crossings() {
        assert_eq!(blocks_to_surge_saturation(RATIFIED), 102);
    }

    #[test]
    fn saturation_at_the_live_factor_stays_within_an_epoch() {
        const EPOCH_BLOCKS: u64 = 10_000;
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

    #[test]
    fn a_unit_surge_factor_needs_no_crossings() {
        assert_eq!(blocks_to_surge_saturation(1), 0);
        assert_eq!(blocks_to_surge_saturation(0), 0);
    }
}

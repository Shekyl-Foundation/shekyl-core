// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How the effective block-weight median `M` is built.
//!
//! This is the ArticMine weight governor, not the fee-lane transaction-count
//! SMA. Long-term median `Mlw` over
//! [`BLOCK_WEIGHT_LONG_TERM_WINDOW`](crate::params::BLOCK_WEIGHT_LONG_TERM_WINDOW)
//! blocks, short-term median over [`BLOCK_WEIGHT_SHORT_TERM_WINDOW`],
//! effective median clamped to `[Mlw, S·Mlw]`. The fee ladder *prices
//! against* `M`; it never ruled on how `M` is assembled. `S` and both
//! windows are consensus (C2-R2 Q2/Q3; `config/consensus_constants.json`).
//! The medians themselves are built by the validator
//! (`shekyl_chain_rules::rules::block_weight`, CEN-G6); this module holds
//! the clamps they feed.
//!
//! Changing `S` does not move a fee number: the fee estimate reads the
//! long-term effective median, and the surge clamp applies to the short-term
//! median. The block-weight *penalty* still prices against the effective
//! median, so during a surge the two paths differ by up to `S` — recorded in
//! `FOLLOWUPS.md`.

use crate::params::{
    EconomicParams, BLOCK_WEIGHT_SHORT_TERM_WINDOW, GENERATED_BLOCK_WEIGHT_SURGE_FACTOR, SCALE,
};

/// Short-term surge factor `S` at the shipped parameters — the default of
/// [`EconomicParams::block_weight_surge_factor`].
///
/// `config/consensus_constants.json` `block_weight_short_term_surge_factor`.
/// Ratified `S = 4` (`CONSENSUS_C2_R2_WEIGHT_FEES.md` Q3). Loosening `S`
/// reopens Q2: for the first ~100 000 blocks this bound is the only
/// protection against early-chain weight growth. Production reads the
/// field.
pub const BLOCK_WEIGHT_SURGE_FACTOR: u64 = GENERATED_BLOCK_WEIGHT_SURGE_FACTOR;

/// The largest block-weight limit multiple a set may carry: four times the
/// effective median, in [`SCALE`] units. With the grain below, the reduced
/// excess `e` (`k − 1 = e / s`) is at most 30, which keeps the penalty's
/// refusal threshold within a factor of 30 of the shipped one
/// (`apply_weight_penalty` in [`crate::emission`] states it).
pub const MAX_BLOCK_WEIGHT_LIMIT_MULTIPLE: u64 = 4 * SCALE;

/// The limit multiple's grain: tenths of [`SCALE`]. Reduced to lowest
/// terms over [`SCALE`], a multiple on this grain has a denominator of at
/// most ten, which bounds the penalty's checked product
/// ([`crate::emission`], `apply_weight_penalty`).
pub const BLOCK_WEIGHT_LIMIT_MULTIPLE_GRAIN: u64 = SCALE / 10;

/// The largest long-term weight clamp a set may carry, in [`SCALE`] units.
pub const MAX_LONG_TERM_WEIGHT_CLAMP: u64 = 10 * SCALE;

/// A block-weight governor the chain cannot run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockWeightShapeError {
    /// `S = 0` clamps every effective median to zero.
    #[error("block-weight surge factor {0} is below 1")]
    SurgeFactor(u64),
    /// The limit multiple is at or below one median, above
    /// [`MAX_BLOCK_WEIGHT_LIMIT_MULTIPLE`], or off the
    /// [`BLOCK_WEIGHT_LIMIT_MULTIPLE_GRAIN`].
    #[error("block-weight limit multiple {0} is not in (SCALE, 4·SCALE] on a grain of SCALE/10")]
    LimitMultiple(u64),
    /// The long-term clamp is below one (its lower bound would exceed the
    /// median) or above [`MAX_LONG_TERM_WEIGHT_CLAMP`].
    #[error("long-term weight clamp {0} is not in [SCALE, 10·SCALE]")]
    LongTermClamp(u64),
}

/// The block-weight governor's three numbers, checked: the surge factor,
/// the limit multiple and the long-term clamp.
/// [`EconomicParams::try_block_weight_governor`] is the door, and
/// [`EconomicParams::validate`] runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockWeightGovernor {
    surge_factor: u64,
    limit_multiple: u64,
    long_term_clamp: u64,
}

impl BlockWeightGovernor {
    /// Check the three numbers.
    ///
    /// # Errors
    ///
    /// [`BlockWeightShapeError`] naming the first number outside its range.
    pub const fn try_new(
        surge_factor: u64,
        limit_multiple: u64,
        long_term_clamp: u64,
    ) -> Result<Self, BlockWeightShapeError> {
        if surge_factor == 0 {
            return Err(BlockWeightShapeError::SurgeFactor(surge_factor));
        }
        if limit_multiple <= SCALE
            || limit_multiple > MAX_BLOCK_WEIGHT_LIMIT_MULTIPLE
            || !limit_multiple.is_multiple_of(BLOCK_WEIGHT_LIMIT_MULTIPLE_GRAIN)
        {
            return Err(BlockWeightShapeError::LimitMultiple(limit_multiple));
        }
        if long_term_clamp < SCALE || long_term_clamp > MAX_LONG_TERM_WEIGHT_CLAMP {
            return Err(BlockWeightShapeError::LongTermClamp(long_term_clamp));
        }
        Ok(Self {
            surge_factor,
            limit_multiple,
            long_term_clamp,
        })
    }

    /// `S`.
    #[must_use]
    pub const fn surge_factor(self) -> u64 {
        self.surge_factor
    }

    /// The limit multiple, [`SCALE`] units.
    #[must_use]
    pub const fn limit_multiple(self) -> u64 {
        self.limit_multiple
    }

    /// The long-term clamp, [`SCALE`] units.
    #[must_use]
    pub const fn long_term_clamp(self) -> u64 {
        self.long_term_clamp
    }
}

/// Effective median: `short_term` bounded to `[long_term, S · long_term]`,
/// `S` the set's [`EconomicParams::block_weight_surge_factor`].
///
/// `long_term` is the already-floored long-term effective median (`≥` the
/// penalty-free zone). `S · long_term` saturates at `u64::MAX` rather than
/// wrapping: a wrapped ceiling would clamp *down* and reject legal blocks.
#[must_use]
pub fn effective_median(long_term: u64, short_term: u64, params: &EconomicParams) -> u64 {
    let ceiling = long_term.saturating_mul(params.block_weight_surge_factor);
    short_term.max(long_term).min(ceiling)
}

/// Bound a block's contribution to the long-term median to
/// `[long_term · SCALE / c, long_term · c / SCALE]`, `c` the set's
/// [`EconomicParams::long_term_weight_clamp`].
///
/// At the shipped `c = 1.7` these are `long_term · 10 / 17` and
/// `long_term + ⌊long_term · 7 / 10⌋` exactly: `SCALE / c` reduces to
/// `10 / 17`, and `⌊1.7 · x⌋ = x + ⌊0.7 · x⌋` for a whole `x`. The upper
/// bound saturates at `u64::MAX`; wrapping it would clamp *down*.
#[must_use]
pub fn long_term_weight(
    long_term_effective: u64,
    block_weight: u64,
    params: &EconomicParams,
) -> u64 {
    let ltem = u128::from(long_term_effective);
    let clamp = u128::from(params.long_term_weight_clamp);
    let scale = u128::from(SCALE);
    let lower = u64::try_from(ltem * scale / clamp).unwrap_or(u64::MAX);
    let upper = u64::try_from(ltem * clamp / scale).unwrap_or(u64::MAX);
    block_weight.max(lower).min(upper)
}

/// Blocks a maximal flood needs to lift the effective median from the
/// long-term effective median to the surge ceiling `S · LTEM`.
///
/// The short-term window is [`BLOCK_WEIGHT_SHORT_TERM_WINDOW`] blocks; its
/// median moves once more than half the window carries the new level, so
/// each doubling costs `window / 2 + 1` blocks — 51 at the ratified 100
/// (C2-R2 Q3's 51-block doubling envelope). Reaching a ceiling `S ×` above
/// the starting median takes `ceil(log2(S))` crossings. At `S = 50` this
/// returns 306; at `S = 4` it returns 102.
#[must_use]
pub const fn blocks_to_surge_saturation(surge_factor: u64) -> u64 {
    const BLOCKS_PER_CROSSING: u64 = BLOCK_WEIGHT_SHORT_TERM_WINDOW / 2 + 1;

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
    use super::{
        blocks_to_surge_saturation, effective_median, long_term_weight, BlockWeightGovernor,
        BlockWeightShapeError, BLOCK_WEIGHT_SURGE_FACTOR,
    };
    use crate::params::{EconomicParams, SCALE};

    const ZONE: u64 = 300_000;
    const RATIFIED: u64 = 4;

    fn shipped() -> EconomicParams {
        EconomicParams::default()
    }

    #[test]
    fn the_live_factor_is_the_ratified_value() {
        assert_eq!(BLOCK_WEIGHT_SURGE_FACTOR, RATIFIED);
    }

    /// The two windows as C2-R2 Q2 ratified them and as the C++ header
    /// carried them before they were generated
    /// (`CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE` 100 000,
    /// `CRYPTONOTE_REWARD_BLOCKS_WINDOW` 100). A retune fails here first,
    /// so the JSON edit is made knowing which readers move.
    #[test]
    fn the_live_windows_are_the_ratified_values() {
        use crate::params::{BLOCK_WEIGHT_LONG_TERM_WINDOW, BLOCK_WEIGHT_SHORT_TERM_WINDOW};
        assert_eq!(BLOCK_WEIGHT_LONG_TERM_WINDOW, 100_000);
        assert_eq!(BLOCK_WEIGHT_SHORT_TERM_WINDOW, 100);
    }

    #[test]
    fn a_short_term_median_far_above_the_ceiling_clamps_to_s_times_long_term() {
        assert_eq!(
            effective_median(ZONE, ZONE * 100, &shipped()),
            RATIFIED * ZONE
        );
    }

    #[test]
    fn a_short_term_median_inside_the_band_passes_through() {
        let inside = ZONE * 2;
        assert!(inside > ZONE && inside < RATIFIED * ZONE);
        assert_eq!(effective_median(ZONE, inside, &shipped()), inside);
    }

    #[test]
    fn a_short_term_median_below_long_term_does_not_pull_the_floor_down() {
        assert_eq!(effective_median(ZONE, ZONE / 10, &shipped()), ZONE);
    }

    #[test]
    fn the_lower_arm_holds_in_every_clamp_state_including_saturation() {
        for st in [0, ZONE / 10, ZONE, ZONE * 2, ZONE * 100, u64::MAX] {
            assert!(effective_median(ZONE, st, &shipped()) >= ZONE, "st={st}");
        }
    }

    #[test]
    fn a_saturating_ceiling_does_not_wrap_and_clamp_down() {
        assert_eq!(effective_median(u64::MAX, 0, &shipped()), u64::MAX);
        assert_eq!(
            effective_median(u64::MAX / 2, u64::MAX, &shipped()),
            u64::MAX
        );
    }

    #[test]
    fn long_term_weight_matches_the_integer_17_10_form() {
        // lower = 300_000 * 10 / 17 = 176_470; upper = 300_000 + 210_000.
        assert_eq!(long_term_weight(ZONE, ZONE, &shipped()), ZONE);
        assert_eq!(long_term_weight(ZONE, 100_000, &shipped()), 176_470);
        assert_eq!(long_term_weight(ZONE, 1_000_000, &shipped()), 510_000);
    }

    #[test]
    fn long_term_weight_upper_bound_saturates() {
        assert_eq!(long_term_weight(u64::MAX, u64::MAX, &shipped()), u64::MAX);
        assert_eq!(long_term_weight(0, 1_000, &shipped()), 0);
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

    /// The shipped governor is the ratified one: `S = 4`, the limit at
    /// twice the median, the long-term clamp at 1.7.
    #[test]
    fn the_shipped_governor_is_the_ratified_one() {
        let g = shipped()
            .try_block_weight_governor()
            .expect("shipped governor");
        assert_eq!(g.surge_factor(), RATIFIED);
        assert_eq!(g.limit_multiple(), 2 * SCALE);
        assert_eq!(g.long_term_clamp(), 17 * SCALE / 10);
    }

    #[test]
    fn the_governor_refuses_what_the_chain_cannot_run() {
        let ok = |s, k, c| BlockWeightGovernor::try_new(s, k, c);
        assert_eq!(
            ok(0, 2 * SCALE, 17 * SCALE / 10),
            Err(BlockWeightShapeError::SurgeFactor(0))
        );
        for k in [SCALE, SCALE - 1, 4 * SCALE + SCALE / 10, 2 * SCALE + 1] {
            assert_eq!(
                ok(4, k, 17 * SCALE / 10),
                Err(BlockWeightShapeError::LimitMultiple(k)),
                "k = {k}"
            );
        }
        for c in [SCALE - 1, 10 * SCALE + 1] {
            assert_eq!(
                ok(4, 2 * SCALE, c),
                Err(BlockWeightShapeError::LongTermClamp(c)),
                "c = {c}"
            );
        }
        assert!(ok(4, 25 * SCALE / 10, SCALE).is_ok());
        assert!(ok(4, 4 * SCALE, 10 * SCALE).is_ok());
    }

    /// E16-7: the surge factor is read from the set. A different `S` moves
    /// the ceiling.
    #[test]
    fn the_surge_ceiling_reads_the_sets_factor() {
        let p = EconomicParams {
            block_weight_surge_factor: 6,
            ..shipped()
        };
        assert_eq!(effective_median(ZONE, ZONE * 100, &p), 6 * ZONE);
    }

    /// E16-7: the long-term clamp is read from the set. At 2.0 the bounds
    /// are a half and a double of the median.
    #[test]
    fn the_long_term_clamp_reads_the_sets_clamp() {
        let p = EconomicParams {
            long_term_weight_clamp: 2 * SCALE,
            ..shipped()
        };
        assert_eq!(long_term_weight(ZONE, 0, &p), ZONE / 2);
        assert_eq!(long_term_weight(ZONE, u64::MAX, &p), 2 * ZONE);
    }

    /// The `SCALE`-unit form against the integer form it replaced, at the
    /// shipped 1.7, over a spread of medians and weights.
    #[test]
    fn the_scaled_clamp_equals_the_17_10_form_at_the_shipped_clamp() {
        let old = |ltem: u64, w: u64| {
            let l = u128::from(ltem);
            let lower = u64::try_from(l * 10 / 17).unwrap_or(u64::MAX);
            let upper = u64::try_from(l + l * 7 / 10).unwrap_or(u64::MAX);
            w.max(lower).min(upper)
        };
        let p = shipped();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let ltem = x >> (x % 40);
            let w = x.rotate_left(17) >> (x % 23);
            assert_eq!(
                long_term_weight(ltem, w, &p),
                old(ltem, w),
                "ltem {ltem}, w {w}"
            );
        }
        for ltem in [0, 1, 16, 17, ZONE, u64::MAX / 2, u64::MAX] {
            for w in [0, 1, ltem, u64::MAX] {
                assert_eq!(long_term_weight(ltem, w, &p), old(ltem, w));
            }
        }
    }
}

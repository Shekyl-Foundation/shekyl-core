//! Component 4: the staker emission share, decaying from block 1.
//!
//! Each block from [`EMISSION_SPLIT_EPOCH`] onward, a fraction of the
//! block emission accrues to the staker pool instead of the miner. The
//! fraction is the shipped initial share at that block and then decays
//! by the shipped annual rate, a bootstrap subsidy that fades as fee
//! income grows. Height 0 pays the miner the whole emission.
//!
//! ```text
//! σ(h) = 0                                              when h < epoch
//! σ(h) = initial · decay ^ ((h − epoch) / blocks_per_year)   otherwise
//! staker_emission = block_emission · σ(h)
//! miner_emission  = block_emission − staker_emission
//! ```
//!
//! One schedule. [`decayed_share`] is the elapsed-time kernel.
//! [`emission_share`] closes it over [`EMISSION_SPLIT_EPOCH`].
//! [`emission_share_at`] closes that over the shipped constants.
//! [`compute_emission_split`] applies the shipped share to one block.

use crate::params::{BLOCKS_PER_YEAR, SCALE, STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE};

/// The miner and staker legs of one block's emission (CEN-F16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionSplit {
    /// What the coinbase may pay (the only leg it may pay).
    pub miner_emission: u64,
    /// What accrues to the staker pool (CEN-G11's accrual operand).
    pub staker_emission: u64,
}

/// CEN-F21: the height the staker emission share starts at.
///
/// The genesis block (height 0) pays no staker share. The share begins at
/// block 1, and its decay is measured from there.
///
/// One owner. [`emission_share`] reads it, and no caller passes an epoch:
/// a caller-supplied origin is how two folds once disagreed about the
/// split at the same height.
pub const EMISSION_SPLIT_EPOCH: u64 = 1;

/// The share after `elapsed_blocks` of decay, measured from the block the
/// share turns on.
///
/// Elapsed 0 is `initial_share`. A zero `blocks_per_year` is the same: the
/// schedule has no decay axis, so the share does not move. Whole years
/// multiply by `annual_decay / SCALE`; the leftover blocks interpolate
/// linearly to the next year's share. The multiplications truncate, and
/// that truncation is the value the year-boundary pins hold.
#[allow(clippy::cast_possible_truncation)]
fn decayed_share(
    elapsed_blocks: u64,
    initial_share: u64,
    annual_decay: u64,
    blocks_per_year: u64,
) -> u64 {
    if elapsed_blocks == 0 || blocks_per_year == 0 {
        return initial_share;
    }

    let whole_years = elapsed_blocks / blocks_per_year;
    let remaining_blocks = elapsed_blocks % blocks_per_year;

    let mut share = u128::from(initial_share);
    let decay = u128::from(annual_decay);
    let scale = u128::from(SCALE);

    for _ in 0..whole_years {
        share = share * decay / scale;
        if share == 0 {
            return 0;
        }
    }

    // next = share · decay / SCALE
    // result = share − (share − next) · remaining / blocks_per_year
    //        = share − share · (SCALE − decay) · remaining / (SCALE · blocks_per_year)
    if remaining_blocks > 0 {
        let decay_delta = scale - decay;
        let fractional_loss = share * decay_delta * u128::from(remaining_blocks)
            / (scale * u128::from(blocks_per_year));
        share = share.saturating_sub(fractional_loss);
    }

    share as u64
}

/// The staker emission share at `height` for a schedule that turns on at
/// [`EMISSION_SPLIT_EPOCH`], in [`SCALE`] units.
///
/// Zero below the epoch. From the epoch, [`decayed_share`] of
/// `height − EMISSION_SPLIT_EPOCH`. A sweep of the initial share or the
/// annual decay passes those here; it does not pass an epoch.
#[must_use]
pub fn emission_share(
    height: u64,
    initial_share: u64,
    annual_decay: u64,
    blocks_per_year: u64,
) -> u64 {
    match height.checked_sub(EMISSION_SPLIT_EPOCH) {
        Some(elapsed) => decayed_share(elapsed, initial_share, annual_decay, blocks_per_year),
        None => 0,
    }
}

/// The shipped staker emission share at `height`: [`emission_share`] of
/// [`STAKER_EMISSION_SHARE`], [`STAKER_EMISSION_DECAY`] and
/// [`BLOCKS_PER_YEAR`].
#[must_use]
pub fn emission_share_at(height: u64) -> u64 {
    emission_share(
        height,
        STAKER_EMISSION_SHARE,
        STAKER_EMISSION_DECAY,
        BLOCKS_PER_YEAR,
    )
}

/// The emission split (CEN-F16): [`emission_share_at`] the height, then
/// [`split_block_emission`].
///
/// Below [`EMISSION_SPLIT_EPOCH`] the share is zero and the whole emission
/// is the miner's. Zero emission is the split at zero: both legs are zero.
#[must_use]
pub fn compute_emission_split(block_emission: u64, current_height: u64) -> EmissionSplit {
    let (miner_emission, staker_emission) =
        split_block_emission(block_emission, emission_share_at(current_height));
    EmissionSplit {
        miner_emission,
        staker_emission,
    }
}

/// Split block emission between miner and staker pool.
///
/// Returns `(miner_emission, staker_emission)`.
#[allow(clippy::cast_possible_truncation)]
pub fn split_block_emission(block_emission: u64, effective_share: u64) -> (u64, u64) {
    if effective_share == 0 || block_emission == 0 {
        return (block_emission, 0);
    }
    let staker =
        (u128::from(block_emission) * u128::from(effective_share) / u128::from(SCALE)) as u64;
    let miner = block_emission.saturating_sub(staker);
    (miner, staker)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero emission is the split at zero: both legs are zero.
    #[test]
    fn zero_emission_splits_to_nothing() {
        let split = compute_emission_split(0, 1_000_000);
        assert_eq!(
            split,
            EmissionSplit {
                miner_emission: 0,
                staker_emission: 0
            }
        );
    }

    /// The ruling, as behaviour: genesis pays no staker share, and block 1
    /// pays the initial share undecayed.
    #[test]
    fn genesis_pays_no_staker_share_and_block_one_pays_the_initial_share() {
        let emission = 1_638_400_000_000;
        assert_eq!(emission_share_at(0), 0);
        assert_eq!(
            compute_emission_split(emission, 0),
            EmissionSplit {
                miner_emission: emission,
                staker_emission: 0
            }
        );
        assert_eq!(emission_share_at(1), STAKER_EMISSION_SHARE);
        let first = compute_emission_split(emission, 1);
        assert_eq!(
            first.staker_emission,
            split_block_emission(emission, STAKER_EMISSION_SHARE).1
        );
        assert!(first.staker_emission > 0);
        assert_eq!(
            u128::from(emission_share_at(EMISSION_SPLIT_EPOCH + BLOCKS_PER_YEAR)),
            u128::from(STAKER_EMISSION_SHARE) * u128::from(STAKER_EMISSION_DECAY)
                / u128::from(SCALE),
            "one year of decay ends one year after block 1, not after genesis"
        );
    }

    /// The shipped function is the schedule closed over the shipped constants.
    #[test]
    fn emission_share_at_is_the_shipped_schedule() {
        for height in [
            0,
            EMISSION_SPLIT_EPOCH,
            EMISSION_SPLIT_EPOCH + BLOCKS_PER_YEAR / 2,
            30 * BLOCKS_PER_YEAR,
        ] {
            assert_eq!(
                emission_share_at(height),
                emission_share(
                    height,
                    STAKER_EMISSION_SHARE,
                    STAKER_EMISSION_DECAY,
                    BLOCKS_PER_YEAR
                ),
                "height {height}"
            );
        }
    }

    /// The composition the C++ shim owned (S6): the effective share at the
    /// height feeds the split; the legs sum to the emission; the staker leg
    /// decays with the height (CEN-F16 as the shipped constants define it).
    #[test]
    fn emission_split_composes_the_share_at_the_height() {
        let emission = 1_638_400_000_000;
        let at_epoch = compute_emission_split(emission, EMISSION_SPLIT_EPOCH);
        assert_eq!(at_epoch.miner_emission + at_epoch.staker_emission, emission);
        assert_eq!(
            at_epoch.staker_emission,
            split_block_emission(emission, STAKER_EMISSION_SHARE).1,
            "at the epoch the share is the initial share"
        );
        let a_decade_on =
            compute_emission_split(emission, EMISSION_SPLIT_EPOCH + 10 * BLOCKS_PER_YEAR);
        assert!(
            a_decade_on.staker_emission < at_epoch.staker_emission,
            "the staker leg decays"
        );
        assert_eq!(
            a_decade_on.miner_emission + a_decade_on.staker_emission,
            emission
        );
    }

    const INITIAL_SHARE: u64 = 150_000; // 15%
    const ANNUAL_DECAY: u64 = 900_000; // 0.90
    const BLOCKS_PER_YEAR: u64 = 262_800;

    fn share_after(elapsed_blocks: u64) -> u64 {
        decayed_share(elapsed_blocks, INITIAL_SHARE, ANNUAL_DECAY, BLOCKS_PER_YEAR)
    }

    #[test]
    fn elapsed_zero_is_the_initial_share() {
        assert_eq!(share_after(0), 150_000);
    }

    #[test]
    fn test_year_1() {
        // 15% * 0.90 = 13.5% = 135_000
        assert_eq!(share_after(BLOCKS_PER_YEAR), 135_000);
    }

    #[test]
    fn test_year_2() {
        // 15% * 0.90^2 = 12.15% = 121_500
        assert_eq!(share_after(2 * BLOCKS_PER_YEAR), 121_500);
    }

    #[test]
    fn test_year_5() {
        // 15% * 0.90^5 = 15% * 0.59049 = 8.85735% ≈ 88_573
        assert_eq!(share_after(5 * BLOCKS_PER_YEAR), 88_573);
    }

    #[test]
    fn test_year_10() {
        // 15% * 0.90^10 ≈ 5.23% — integer truncation over 10 iterations
        assert_eq!(share_after(10 * BLOCKS_PER_YEAR), 52_299);
    }

    #[test]
    fn test_year_20() {
        // 15% * 0.90^20 ≈ 1.82% — integer truncation over 20 iterations
        assert_eq!(share_after(20 * BLOCKS_PER_YEAR), 18_233);
    }

    #[test]
    #[allow(clippy::cast_possible_wrap)]
    fn test_year_30() {
        // 15% * 0.90^30 ≈ 0.635% ≈ 6_354
        let share = share_after(30 * BLOCKS_PER_YEAR);
        let expected = 6_354u64;
        assert!((share as i64 - expected as i64).unsigned_abs() <= 2);
    }

    #[test]
    fn test_half_year_interpolation() {
        let half_year = BLOCKS_PER_YEAR / 2;
        // Between 150_000 (year 0) and 135_000 (year 1).
        // Linear interpolation: 150_000 - (150_000 - 135_000) * 0.5 = 142_500
        assert_eq!(share_after(half_year), 142_500);
    }

    #[test]
    fn test_split_at_epoch() {
        let (miner, staker) = split_block_emission(1_000_000_000, 150_000);
        // 15% to stakers = 150M, 85% to miners = 850M
        assert_eq!(staker, 150_000_000);
        assert_eq!(miner, 850_000_000);
    }

    #[test]
    fn test_split_zero_emission() {
        let (miner, staker) = split_block_emission(0, 150_000);
        assert_eq!(miner, 0);
        assert_eq!(staker, 0);
    }

    #[test]
    fn test_split_zero_share() {
        let (miner, staker) = split_block_emission(1_000_000_000, 0);
        assert_eq!(miner, 1_000_000_000);
        assert_eq!(staker, 0);
    }

    #[test]
    fn test_eventual_convergence_to_zero() {
        // After 100 years the share should be negligible.
        assert!(share_after(100 * BLOCKS_PER_YEAR) < 10);
    }

    /// There is no caller-supplied origin. Below the epoch the share is
    /// zero for any schedule; one year after the epoch is one year of decay.
    #[test]
    fn the_share_is_zero_below_the_epoch_and_decays_from_it() {
        assert_eq!(
            emission_share(0, INITIAL_SHARE, ANNUAL_DECAY, BLOCKS_PER_YEAR),
            0
        );
        assert_eq!(
            emission_share(
                EMISSION_SPLIT_EPOCH,
                INITIAL_SHARE,
                ANNUAL_DECAY,
                BLOCKS_PER_YEAR
            ),
            INITIAL_SHARE
        );
        assert_eq!(
            emission_share(
                EMISSION_SPLIT_EPOCH + BLOCKS_PER_YEAR,
                INITIAL_SHARE,
                ANNUAL_DECAY,
                BLOCKS_PER_YEAR
            ),
            135_000
        );
    }

    #[test]
    fn test_share_is_non_increasing_over_time() {
        let mut prev = INITIAL_SHARE;
        for year in 0..=30u64 {
            let share = share_after(year * BLOCKS_PER_YEAR);
            assert!(
                share <= prev,
                "share increased at year {year}: {share} > {prev}"
            );
            prev = share;
        }
    }
}

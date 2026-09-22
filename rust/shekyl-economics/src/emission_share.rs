//! Component 4: Staker emission share with exponential yearly decay.
//!
//! Each block, a fraction of the total emission is directed to the staker
//! reward pool instead of the miner. This fraction decays multiplicatively
//! each year, creating a bootstrap subsidy that fades as fee income grows.
//!
//! ```text
//! effective_share = STAKER_EMISSION_SHARE * STAKER_EMISSION_DECAY ^ years_since_genesis
//! staker_emission = block_emission * effective_share
//! miner_emission  = block_emission - staker_emission
//! ```

use crate::params::{BLOCKS_PER_YEAR, SCALE, STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE};

/// The miner and staker legs of one block's emission (CEN-F16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionSplit {
    /// What the coinbase may pay (the only leg it may pay).
    pub miner_emission: u64,
    /// What accrues to the staker pool (CEN-G11's accrual operand).
    pub staker_emission: u64,
}

/// The emission split (CEN-F16): the effective share at `current_height`,
/// measured from `epoch`, then [`split_block_emission`].
///
/// The share constants are this crate's generated params, not caller
/// arguments. `epoch` is CEN-F21's `genesis_ng_height` (1 on every shipped
/// network). Zero emission is the split at zero: both legs are zero,
/// because [`split_block_emission`] returns the emission unchanged and a
/// zero staker leg when the emission is zero.
#[must_use]
pub fn compute_emission_split(
    block_emission: u64,
    current_height: u64,
    epoch: u64,
) -> EmissionSplit {
    let effective_share = calc_effective_emission_share(
        current_height,
        epoch,
        STAKER_EMISSION_SHARE,
        STAKER_EMISSION_DECAY,
        BLOCKS_PER_YEAR,
    );
    let (miner_emission, staker_emission) = split_block_emission(block_emission, effective_share);
    EmissionSplit {
        miner_emission,
        staker_emission,
    }
}

/// Compute the effective staker emission share at a given block height.
///
/// Uses per-block decay derived from the annual decay rate:
///   per_block_decay = annual_decay ^ (1 / blocks_per_year)
///
/// To avoid floating-point, we use repeated fixed-point multiplication
/// over whole years plus a fractional-year correction.
///
/// Returns a fixed-point value in SCALE (e.g., 150_000 = 15%).
#[allow(clippy::cast_possible_truncation)]
pub fn calc_effective_emission_share(
    current_height: u64,
    genesis_height: u64,
    initial_share: u64,
    annual_decay: u64,
    blocks_per_year: u64,
) -> u64 {
    if current_height <= genesis_height || blocks_per_year == 0 {
        return initial_share;
    }

    let elapsed = current_height - genesis_height;
    let whole_years = elapsed / blocks_per_year;
    let remaining_blocks = elapsed % blocks_per_year;

    // Apply annual decay for each whole year: share *= (decay/SCALE) per year
    let mut share = u128::from(initial_share);
    let decay = u128::from(annual_decay);
    let scale = u128::from(SCALE);

    for _ in 0..whole_years {
        share = share * decay / scale;
        if share == 0 {
            return 0;
        }
    }

    // Fractional year: linear interpolation between current and next decay step
    // next_year_share = share * decay / SCALE
    // fraction = remaining_blocks / blocks_per_year
    // result = share - (share - next_year_share) * fraction
    //        = share - share * (SCALE - decay) * remaining_blocks / (SCALE * blocks_per_year)
    if remaining_blocks > 0 {
        let decay_delta = scale - decay; // how much is lost per year
        let fractional_loss = share * decay_delta * u128::from(remaining_blocks)
            / (scale * u128::from(blocks_per_year));
        share = share.saturating_sub(fractional_loss);
    }

    share as u64
}

/// Split block emission between miner and staker pool.
///
/// Returns (miner_emission, staker_emission).
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
        let split = compute_emission_split(0, 1_000_000, 1);
        assert_eq!(
            split,
            EmissionSplit {
                miner_emission: 0,
                staker_emission: 0
            }
        );
    }

    /// The composition the C++ shim owned (S6): the effective share at the
    /// height feeds the split; the legs sum to the emission; the staker leg
    /// decays with the height (CEN-F16 as the shipped constants define it).
    #[test]
    fn emission_split_composes_the_share_at_the_height() {
        let emission = 1_638_400_000_000;
        let at_genesis = compute_emission_split(emission, 1, 1);
        assert_eq!(
            at_genesis.miner_emission + at_genesis.staker_emission,
            emission
        );
        assert_eq!(
            at_genesis.staker_emission,
            split_block_emission(emission, STAKER_EMISSION_SHARE).1,
            "at the epoch the share is the initial share"
        );
        let a_decade_on = compute_emission_split(emission, 1 + 10 * BLOCKS_PER_YEAR, 1);
        assert!(
            a_decade_on.staker_emission < at_genesis.staker_emission,
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

    #[test]
    fn test_genesis_block_returns_initial_share() {
        let share =
            calc_effective_emission_share(0, 0, INITIAL_SHARE, ANNUAL_DECAY, BLOCKS_PER_YEAR);
        assert_eq!(share, 150_000);
    }

    #[test]
    fn test_year_1() {
        let share = calc_effective_emission_share(
            BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // 15% * 0.90 = 13.5% = 135_000
        assert_eq!(share, 135_000);
    }

    #[test]
    fn test_year_2() {
        let share = calc_effective_emission_share(
            2 * BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // 15% * 0.90^2 = 12.15% = 121_500
        assert_eq!(share, 121_500);
    }

    #[test]
    fn test_year_5() {
        let share = calc_effective_emission_share(
            5 * BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // 15% * 0.90^5 = 15% * 0.59049 = 8.85735% ≈ 88_573
        assert_eq!(share, 88_573); // 0.15 * 0.9^5 * 10^6
    }

    #[test]
    fn test_year_10() {
        let share = calc_effective_emission_share(
            10 * BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // 15% * 0.90^10 ≈ 5.23% — integer truncation over 10 iterations
        assert_eq!(share, 52_299);
    }

    #[test]
    fn test_year_20() {
        let share = calc_effective_emission_share(
            20 * BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // 15% * 0.90^20 ≈ 1.82% — integer truncation over 20 iterations
        assert_eq!(share, 18_233);
    }

    #[test]
    #[allow(clippy::cast_possible_wrap)]
    fn test_year_30() {
        let share = calc_effective_emission_share(
            30 * BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // 15% * 0.90^30 ≈ 0.635% ≈ 6_354
        let expected = 6_354u64;
        assert!((share as i64 - expected as i64).unsigned_abs() <= 2);
    }

    #[test]
    fn test_half_year_interpolation() {
        let half_year = BLOCKS_PER_YEAR / 2;
        let share = calc_effective_emission_share(
            half_year,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        // Should be between 150_000 (year 0) and 135_000 (year 1)
        // Linear interpolation: 150_000 - (150_000 - 135_000) * 0.5 = 142_500
        assert_eq!(share, 142_500);
    }

    #[test]
    fn test_split_at_genesis() {
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
        // After 100 years the share should be negligible
        let share = calc_effective_emission_share(
            100 * BLOCKS_PER_YEAR,
            0,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        assert!(share < 10); // effectively zero
    }

    #[test]
    fn test_non_zero_genesis_height() {
        let genesis = 100_000u64;
        let share = calc_effective_emission_share(
            genesis + BLOCKS_PER_YEAR,
            genesis,
            INITIAL_SHARE,
            ANNUAL_DECAY,
            BLOCKS_PER_YEAR,
        );
        assert_eq!(share, 135_000);
    }

    #[test]
    fn test_share_is_non_increasing_over_time() {
        let mut prev = INITIAL_SHARE;
        for year in 0..=30u64 {
            let share = calc_effective_emission_share(
                year * BLOCKS_PER_YEAR,
                0,
                INITIAL_SHARE,
                ANNUAL_DECAY,
                BLOCKS_PER_YEAR,
            );
            assert!(
                share <= prev,
                "share increased at year {year}: {share} > {prev}"
            );
            prev = share;
        }
    }
}

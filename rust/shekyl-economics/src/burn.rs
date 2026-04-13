//! Adaptive fee burn mechanism.
//!
//! A percentage of each transaction fee is permanently destroyed. The burn rate
//! adjusts algorithmically based on transaction volume, circulating supply ratio,
//! and stake ratio.
//!
//! ```text
//! burn_pct = min(BURN_CAP,
//!     BURN_BASE_RATE * sqrt(tx_volume / tx_baseline)
//!                    * (circulating_supply / total_supply)
//!                    * (1 + stake_ratio))
//! ```
//!
//! Fee distribution per block:
//! ```text
//! burned_amount     = total_fees * burn_pct
//! staker_pool       = burned_amount * STAKER_POOL_SHARE
//! actually_destroyed = burned_amount - staker_pool
//! miner_fee_income  = total_fees - burned_amount
//! ```

use crate::params::{clamp, isqrt, mul_scale, SCALE};

/// Result of the fee burn split calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnSplit {
    pub miner_fee_income: u64,
    pub staker_pool_amount: u64,
    pub actually_destroyed: u64,
}

/// Calculate the burn percentage (fixed-point, SCALE = 1_000_000).
///
/// # Arguments
/// * `tx_volume` - Transaction count over the volume window
/// * `tx_baseline` - Baseline transaction volume
/// * `circulating_supply` - Currently circulating atomic units
/// * `total_supply` - Total MONEY_SUPPLY in atomic units
/// * `stake_ratio` - total_staked / circulating_supply (fixed-point SCALE)
/// * `burn_base_rate` - Base burn coefficient (fixed-point SCALE)
/// * `burn_cap` - Maximum burn percentage (fixed-point SCALE)
///
/// # Returns
/// Burn percentage in fixed-point SCALE units (e.g. 400_000 = 40%).
#[allow(clippy::cast_possible_truncation)]
pub fn calc_burn_pct(
    tx_volume: u64,
    tx_baseline: u64,
    circulating_supply: u64,
    total_supply: u64,
    stake_ratio: u64,
    burn_base_rate: u64,
    burn_cap: u64,
) -> u64 {
    if tx_baseline == 0 || total_supply == 0 {
        return 0;
    }

    // sqrt(tx_volume / tx_baseline) scaled to SCALE
    // = sqrt(tx_volume * SCALE^2 / tx_baseline) but we do it step by step
    let volume_ratio_scaled = (u128::from(tx_volume) * u128::from(SCALE) * u128::from(SCALE)
        / u128::from(tx_baseline)) as u64;
    let sqrt_volume = isqrt(volume_ratio_scaled); // result is in SCALE units

    // circulating_supply / total_supply scaled to SCALE
    let supply_ratio =
        (u128::from(circulating_supply) * u128::from(SCALE) / u128::from(total_supply)) as u64;

    // (1 + stake_ratio) in SCALE units
    let stake_factor = SCALE.saturating_add(stake_ratio);

    // burn_pct = burn_base_rate * sqrt_volume * supply_ratio * stake_factor / SCALE^3
    // We chain mul_scale to keep things in SCALE units:
    let step1 = mul_scale(burn_base_rate, sqrt_volume);
    let step2 = mul_scale(step1, supply_ratio);
    let result = mul_scale(step2, stake_factor);

    clamp(result, 0, burn_cap)
}

/// Compute the three-way fee split for a block.
///
/// # Arguments
/// * `total_fees` - Sum of all tx fees in the block (atomic units)
/// * `burn_pct` - Burn percentage (fixed-point SCALE)
/// * `staker_pool_share` - Fraction of burn redirected to stakers (fixed-point SCALE)
pub fn compute_burn_split(
    total_fees: u64,
    burn_pct: u64,
    staker_pool_share: u64,
) -> BurnSplit {
    let burned_amount = mul_scale(total_fees, burn_pct);
    let staker_pool_amount = mul_scale(burned_amount, staker_pool_share);
    let actually_destroyed = burned_amount.saturating_sub(staker_pool_amount);
    let miner_fee_income = total_fees.saturating_sub(burned_amount);

    BurnSplit {
        miner_fee_income,
        staker_pool_amount,
        actually_destroyed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_baseline() {
        assert_eq!(calc_burn_pct(100, 0, 1000, 10000, 0, 400_000, 900_000), 0);
    }

    #[test]
    fn test_zero_supply() {
        assert_eq!(calc_burn_pct(100, 100, 1000, 0, 0, 400_000, 900_000), 0);
    }

    #[test]
    fn test_early_chain_low_burn() {
        // Early chain: 10% circulating, no staking, baseline volume
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply / 10; // 10%
        let burn = calc_burn_pct(100, 100, circulating, supply, 0, 400_000, 900_000);
        // burn_base(0.4) * sqrt(1.0)(1.0) * supply_ratio(0.1) * stake_factor(1.0)
        // = 0.4 * 1.0 * 0.1 * 1.0 = 0.04 = 4%
        assert_eq!(burn, 40_000);
    }

    #[test]
    fn test_mature_chain_high_burn() {
        // Mature: 80% circulating, 30% staked, 3x volume
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply / 100 * 80;
        let stake_ratio = 300_000; // 0.3
        let burn = calc_burn_pct(300, 100, circulating, supply, stake_ratio, 400_000, 900_000);
        // burn_base(0.4) * sqrt(3.0)(~1.732) * 0.8 * 1.3
        // = 0.4 * 1.732 * 0.8 * 1.3 ≈ 0.72
        assert!(burn > 600_000 && burn < 800_000, "burn was {burn}");
    }

    #[test]
    fn test_burn_cap_enforced() {
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply; // 100% circulating
        let stake_ratio = 500_000; // 50%
        // Extreme volume: 10x baseline
        let burn = calc_burn_pct(1000, 100, circulating, supply, stake_ratio, 400_000, 900_000);
        assert_eq!(burn, 900_000); // capped at 90%
    }

    #[test]
    fn test_compute_burn_split_basic() {
        let total_fees = 1_000_000_000u64; // 1 SHEKYL in fees
        let burn_pct = 400_000; // 40%
        let staker_share = 200_000; // 20%
        let split = compute_burn_split(total_fees, burn_pct, staker_share);

        assert_eq!(split.miner_fee_income, 600_000_000);     // 60% of fees
        assert_eq!(split.staker_pool_amount, 80_000_000);     // 20% of 40%
        assert_eq!(split.actually_destroyed, 320_000_000);     // 80% of 40%
        assert_eq!(
            split.miner_fee_income + split.staker_pool_amount + split.actually_destroyed,
            total_fees
        );
    }

    #[test]
    fn test_burn_split_zero_fees() {
        let split = compute_burn_split(0, 400_000, 200_000);
        assert_eq!(split.miner_fee_income, 0);
        assert_eq!(split.staker_pool_amount, 0);
        assert_eq!(split.actually_destroyed, 0);
    }

    #[test]
    fn test_burn_split_zero_burn() {
        let split = compute_burn_split(1_000_000, 0, 200_000);
        assert_eq!(split.miner_fee_income, 1_000_000);
        assert_eq!(split.staker_pool_amount, 0);
        assert_eq!(split.actually_destroyed, 0);
    }

    #[test]
    fn test_staking_increases_burn() {
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply / 2;
        let burn_no_stake = calc_burn_pct(100, 100, circulating, supply, 0, 400_000, 900_000);
        let burn_with_stake =
            calc_burn_pct(100, 100, circulating, supply, 300_000, 400_000, 900_000);
        assert!(burn_with_stake > burn_no_stake);
    }

    #[test]
    fn test_burn_pct_always_within_bounds() {
        let supply = 4_294_967_296_000_000_000u64;
        let cap = 900_000u64;
        let cases = [
            (0u64, 50u64, 0u64),
            (10, 50, 50_000),
            (50, 50, 100_000),
            (200, 50, 200_000),
            (500, 50, 400_000),
        ];
        for (tx_volume, tx_baseline, stake_ratio) in cases {
            let burn = calc_burn_pct(
                tx_volume,
                tx_baseline,
                supply / 2,
                supply,
                stake_ratio,
                500_000,
                cap,
            );
            assert!(burn <= cap, "burn exceeds cap: {burn}");
        }
    }
}

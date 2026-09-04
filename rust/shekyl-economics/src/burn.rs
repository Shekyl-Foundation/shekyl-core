//! Adaptive fee burn mechanism.
//!
//! A percentage of each transaction fee is permanently destroyed. The burn rate
//! adjusts algorithmically based on transaction volume and circulating supply
//! ratio.
//!
//! ```text
//! burn_pct = min(BURN_CAP,
//!     BURN_BASE_RATE * sqrt(tx_volume / tx_baseline)
//!                    * (circulating_supply / total_supply))
//! ```
//!
//! The historical `× (1 + stake_ratio)` factor was **deleted**
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` F-D): it was a burn-*rate* lever
//! keyed on stake **participation** — the wrong axis, conflated with the
//! reward-*share* lever `staker_pool_share`, and dead by design under the
//! bonds-only close (`stake_ratio` was pinned to `0` at every production call
//! site). Burn rate is now `activity × supply`; staker share is `archival work`.
//! One lever, one honest measure.
//!
//! Fee distribution per block:
//! ```text
//! burned_amount     = total_fees * burn_pct
//! staker_pool       = burned_amount * staker_pool_share(n)
//! actually_destroyed = burned_amount - staker_pool
//! miner_fee_income  = total_fees - burned_amount
//! ```
//!
//! **Consensus entry:** [`compute_burn_split_at`] — maps parent-state
//! [`FrozenSegmentCount`] through the D2 escalation and splits. Prefer it over
//! composing [`compute_burn_split`] with a hand-picked share.

use crate::escalation::{staker_pool_share_at, FrozenSegmentCount, ScaledShare};
use crate::params::{clamp, isqrt, mul_scale, EconomicParams, SCALE};

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

    // circulating_supply / total_supply scaled to SCALE, saturated at 1.0
    // (FL-R16c): under the perpetual tail gross issuance passes the
    // curve's asymptote, and an unsaturated ratio would silently drift
    // the burn toward its cap on a quantity that stopped meaning
    // "fraction emitted" at that point.
    let supply_ratio = (u128::from(circulating_supply) * u128::from(SCALE)
        / u128::from(total_supply))
    .min(u128::from(SCALE)) as u64;

    // burn_pct = burn_base_rate * sqrt_volume * supply_ratio / SCALE^2
    // We chain mul_scale to keep things in SCALE units:
    let step1 = mul_scale(burn_base_rate, sqrt_volume);
    let result = mul_scale(step1, supply_ratio);

    clamp(result, 0, burn_cap)
}

/// Burn percentage from raw activity inputs.
pub fn calc_burn_pct_from_activity(
    tx_volume: u64,
    tx_baseline: u64,
    circulating_supply: u64,
    params: &crate::params::EconomicParams,
) -> u64 {
    calc_burn_pct(
        tx_volume,
        tx_baseline,
        circulating_supply,
        params.money_supply,
        params.burn_base_rate,
        params.burn_cap,
    )
}

/// Compute the three-way fee split for a block with an explicit staker share.
///
/// Prefer [`compute_burn_split_at`] on consensus paths: it is the escalated
/// composition. This entry remains for the flat-share differential oracle and
/// for tests that pin a specific share.
pub fn compute_burn_split(
    total_fees: u64,
    burn_pct: u64,
    staker_pool_share: ScaledShare,
) -> BurnSplit {
    let burned_amount = mul_scale(total_fees, burn_pct);
    let staker_pool_amount = mul_scale(burned_amount, staker_pool_share.to_raw());
    let actually_destroyed = burned_amount.saturating_sub(staker_pool_amount);
    let miner_fee_income = total_fees.saturating_sub(burned_amount);

    BurnSplit {
        miner_fee_income,
        staker_pool_amount,
        actually_destroyed,
    }
}

/// **Canonical consensus burn split:** fees × burn% × D2-escalated share at `n`.
///
/// `n` is parent-block [`FrozenSegmentCount`]. The share is derived from
/// `params` via [`staker_pool_share_at`] — numerics never need to cross FFI as
/// a free parameter. This is the single Rust function C++, the sim ledger, and
/// future daemon paths should call.
#[must_use]
pub fn compute_burn_split_at(
    total_fees: u64,
    burn_pct: u64,
    n: FrozenSegmentCount,
    params: &EconomicParams,
) -> BurnSplit {
    let share = staker_pool_share_at(n, &params.escalation());
    compute_burn_split(total_fees, burn_pct, share)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_baseline() {
        assert_eq!(calc_burn_pct(100, 0, 1000, 10000, 400_000, 900_000), 0);
    }

    #[test]
    fn test_zero_supply() {
        assert_eq!(calc_burn_pct(100, 100, 1000, 0, 400_000, 900_000), 0);
    }

    #[test]
    fn test_early_chain_low_burn() {
        // Early chain: 10% circulating, baseline volume
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply / 10; // 10%
        let burn = calc_burn_pct(100, 100, circulating, supply, 400_000, 900_000);
        // burn_base(0.4) * sqrt(1.0)(1.0) * supply_ratio(0.1) = 0.04 = 4%
        assert_eq!(burn, 40_000);
    }

    #[test]
    fn test_mature_chain_high_burn() {
        // Mature: 80% circulating, 3x volume (stake no longer a burn input — F-D)
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply / 100 * 80;
        let burn = calc_burn_pct(300, 100, circulating, supply, 400_000, 900_000);
        // burn_base(0.4) * sqrt(3.0)(~1.732) * 0.8 ≈ 0.554
        assert!(burn > 500_000 && burn < 600_000, "burn was {burn}");
    }

    #[test]
    fn test_burn_cap_enforced() {
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply; // 100% circulating
                                  // Extreme volume: 10x baseline → 0.4·sqrt(10)·1.0 ≈ 1.26, capped
        let burn = calc_burn_pct(1000, 100, circulating, supply, 400_000, 900_000);
        assert_eq!(burn, 900_000); // capped at 90%
    }

    #[test]
    fn test_compute_burn_split_basic() {
        let total_fees = 1_000_000_000u64; // 1 SHEKYL in fees
        let burn_pct = 400_000; // 40%
        let staker_share = ScaledShare::from_raw(200_000); // 20%
        let split = compute_burn_split(total_fees, burn_pct, staker_share);

        assert_eq!(split.miner_fee_income, 600_000_000); // 60% of fees
        assert_eq!(split.staker_pool_amount, 80_000_000); // 20% of 40%
        assert_eq!(split.actually_destroyed, 320_000_000); // 80% of 40%
        assert_eq!(
            split.miner_fee_income + split.staker_pool_amount + split.actually_destroyed,
            total_fees
        );
    }

    #[test]
    fn test_burn_split_zero_fees() {
        let split = compute_burn_split(0, 400_000, ScaledShare::from_raw(200_000));
        assert_eq!(split.miner_fee_income, 0);
        assert_eq!(split.staker_pool_amount, 0);
        assert_eq!(split.actually_destroyed, 0);
    }

    #[test]
    fn test_burn_split_zero_burn() {
        let split = compute_burn_split(1_000_000, 0, ScaledShare::from_raw(200_000));
        assert_eq!(split.miner_fee_income, 1_000_000);
        assert_eq!(split.staker_pool_amount, 0);
        assert_eq!(split.actually_destroyed, 0);
    }

    /// Canonical entry agrees with explicit share at the genesis-neutral set.
    #[test]
    fn compute_burn_split_at_matches_flat_at_genesis_neutral() {
        let params = EconomicParams::default();
        assert_eq!(
            params.escalation_asymptote_share, params.staker_pool_share,
            "fixture assumes neutral asymptote"
        );
        let fees = 1_000_000_000u64;
        let burn_pct = 500_000;
        let flat = compute_burn_split(
            fees,
            burn_pct,
            ScaledShare::from_raw(params.staker_pool_share),
        );
        for n in [0u64, 1, 100_000, u64::MAX] {
            let esc = compute_burn_split_at(fees, burn_pct, FrozenSegmentCount::new(n), &params);
            assert_eq!(esc, flat, "n={n}");
        }
    }

    #[test]
    fn test_burn_is_independent_of_stake() {
        // F-D: staking no longer feeds the burn rate. There is no stake input to
        // vary, so burn is a pure function of (volume, supply). This pins that
        // the two "was it staked?" scenarios that once diverged now coincide.
        let supply = 4_294_967_296_000_000_000u64;
        let circulating = supply / 2;
        let burn = calc_burn_pct(100, 100, circulating, supply, 400_000, 900_000);
        // 0.4 * sqrt(1.0) * 0.5 = 0.20 = 20%, regardless of any stake level.
        assert_eq!(burn, 200_000);
    }

    #[test]
    fn test_burn_pct_always_within_bounds() {
        let supply = 4_294_967_296_000_000_000u64;
        let cap = 900_000u64;
        let cases = [(0u64, 50u64), (10, 50), (50, 50), (200, 50), (500, 50)];
        for (tx_volume, tx_baseline) in cases {
            let burn = calc_burn_pct(tx_volume, tx_baseline, supply / 2, supply, 500_000, cap);
            assert!(burn <= cap, "burn exceeds cap: {burn}");
        }
    }
}

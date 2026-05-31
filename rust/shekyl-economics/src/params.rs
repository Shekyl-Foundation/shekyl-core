//! Economic system parameters — mirrors constants from cryptonote_config.h.

use serde::{Deserialize, Serialize};

include!(concat!(env!("OUT_DIR"), "/params_generated.rs"));

pub const SCALE: u64 = GENERATED_SCALE;

/// Total coin supply ceiling in atomic units (`money_supply` from
/// `config/economics_params.json`). Exposed for structural-invariant
/// validation in [`crate::activity::ActivityMetric::new`]
/// (`circulating_supply ≤ MONEY_SUPPLY`).
pub const MONEY_SUPPLY: u64 = GENERATED_MONEY_SUPPLY;

/// Base staker emission share in fixed-point [`SCALE`] units
/// (`shekyl_staker_emission_share`; `150_000` = 15%). This is the
/// **base** share before the height-dependent decay in
/// [`crate::emission_share::calc_effective_emission_share`]; consumers
/// that need the effective share apply the decay themselves. Surfaced
/// for the `EconomicsParametersSnapshot` rulebook (PR 7 §5.3 R2).
pub const STAKER_EMISSION_SHARE: u64 = GENERATED_STAKER_EMISSION_SHARE;

/// Per-year staker emission decay factor in fixed-point [`SCALE`] units
/// (`shekyl_staker_emission_decay`; `900_000` = 0.90/year). Snapshot
/// rulebook constant (PR 7 §5.3 R2).
pub const STAKER_EMISSION_DECAY: u64 = GENERATED_STAKER_EMISSION_DECAY;

/// Blocks per year at the configured DAA target
/// (`shekyl_blocks_per_year`). Used with [`STAKER_EMISSION_DECAY`] to
/// project the effective staker emission share at a height.
pub const BLOCKS_PER_YEAR: u64 = GENERATED_BLOCKS_PER_YEAR;

/// Calibration generation index for the resolved economic parameter set
/// (**CALIBRATION-PENDING**).
///
/// The monotonic configuration-epoch tag surfaced through
/// `CalibrationStamp::generation` (PR 7 §6.3 G5). At V3.0 it is a
/// build-time constant, **not** a chain height: it increments on each
/// pre-genesis testnet recalibration of `config/economics_params.json`,
/// so a consumer holding an older snapshot can detect "estimate from
/// generation N; current is N+1" without a bit-exact digest compare.
///
/// Pre-genesis the parameter set is still under calibration, so this
/// starts at `0`. Bump it whenever the resolved `EconomicParams` change
/// in a way operators should treat as a new epoch.
///
/// **Reopening criteria (`21-reversion-clause-discipline.mdc`):** at V3.x
/// Component 3 adaptive burn may bind calibration epochs to heights
/// (`generation_active_at(height)`); that is a FOLLOWUPS item and would
/// move the generation out of this build-time constant into engine-held
/// state. Until then it stays a constant.
pub const CALIBRATION_GENERATION: u32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicParams {
    pub release_min: u64,
    pub release_max: u64,
    pub tx_volume_baseline: u64,
    pub burn_base_rate: u64,
    pub burn_cap: u64,
    pub staker_pool_share: u64,
    pub money_supply: u64,
    pub emission_speed_factor_per_minute: u64,
    pub final_subsidy_per_minute: u64,
    pub daa_target_seconds: u64,
}

impl Default for EconomicParams {
    fn default() -> Self {
        Self {
            release_min: GENERATED_RELEASE_MIN,
            release_max: GENERATED_RELEASE_MAX,
            tx_volume_baseline: GENERATED_TX_VOLUME_BASELINE,
            burn_base_rate: GENERATED_BURN_BASE_RATE,
            burn_cap: GENERATED_BURN_CAP,
            staker_pool_share: GENERATED_STAKER_POOL_SHARE,
            money_supply: GENERATED_MONEY_SUPPLY,
            emission_speed_factor_per_minute: GENERATED_EMISSION_SPEED_FACTOR_PER_MINUTE,
            final_subsidy_per_minute: GENERATED_FINAL_SUBSIDY_PER_MINUTE,
            daa_target_seconds: GENERATED_DAA_TARGET_SECONDS,
        }
    }
}

/// `stake_ratio = total_staked / circulating_supply` in fixed-point SCALE units.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub fn calc_stake_ratio(total_staked: u64, circulating_supply: u64) -> u64 {
    if circulating_supply == 0 {
        return 0;
    }
    (u128::from(total_staked) * u128::from(SCALE) / u128::from(circulating_supply)) as u64
}

/// Clamp a value to [lo, hi].
#[inline]
pub fn clamp(value: u64, lo: u64, hi: u64) -> u64 {
    if value < lo {
        lo
    } else if value > hi {
        hi
    } else {
        value
    }
}

/// Multiply two u64 values and divide by SCALE, using u128 intermediary to avoid overflow.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub fn mul_scale(a: u64, b: u64) -> u64 {
    let product = u128::from(a) * u128::from(b);
    (product / u128::from(SCALE)) as u64
}

/// Integer square root via Newton's method (floor).
pub fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(500_000, 800_000, 1_300_000), 800_000);
        assert_eq!(clamp(1_000_000, 800_000, 1_300_000), 1_000_000);
        assert_eq!(clamp(2_000_000, 800_000, 1_300_000), 1_300_000);
    }

    #[test]
    fn test_mul_scale() {
        assert_eq!(mul_scale(2_000_000, 500_000), 1_000_000); // 2.0 * 0.5 = 1.0
        assert_eq!(mul_scale(1_000_000, 1_000_000), 1_000_000); // 1.0 * 1.0 = 1.0
        assert_eq!(mul_scale(1_300_000, 1_000_000), 1_300_000); // 1.3 * 1.0 = 1.3
    }

    #[test]
    fn test_mul_scale_no_overflow() {
        let big = u64::MAX;
        let result = mul_scale(big, SCALE);
        assert_eq!(result, big);
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(10), 3);
        assert_eq!(isqrt(1_000_000), 1000);
    }
}

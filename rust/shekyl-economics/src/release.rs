//! Transaction-responsive release rate multiplier.
//!
//! The release multiplier adjusts how quickly the CryptoNote emission curve
//! releases coins from the fixed supply. It does NOT create additional coins.
//!
//! ```text
//! release_multiplier = clamp(tx_volume_avg / tx_volume_baseline, RELEASE_MIN, RELEASE_MAX)
//! effective_reward = base_reward * release_multiplier / SCALE
//! ```

use crate::params::{clamp, SCALE};

/// Calculate the release rate multiplier from transaction volume.
///
/// # Arguments
/// * `tx_volume_avg` - Rolling average tx count over the volume window
/// * `tx_volume_baseline` - Reference transaction volume (from config)
/// * `release_min` - Minimum multiplier (fixed-point, e.g. 800_000 = 0.8)
/// * `release_max` - Maximum multiplier (fixed-point, e.g. 1_300_000 = 1.3)
///
/// # Returns
/// Fixed-point multiplier in SCALE units. 1_000_000 = 1.0x release rate.
pub fn calc_release_multiplier(
    tx_volume_avg: u64,
    tx_volume_baseline: u64,
    release_min: u64,
    release_max: u64,
) -> u64 {
    if tx_volume_baseline == 0 {
        return SCALE; // 1.0x if baseline is unconfigured
    }

    // ratio = tx_volume_avg / tx_volume_baseline, scaled to SCALE
    let ratio = (tx_volume_avg as u128 * SCALE as u128 / tx_volume_baseline as u128) as u64;

    clamp(ratio, release_min, release_max)
}

/// Apply the release multiplier to a base reward.
///
/// Uses u128 intermediate to prevent overflow.
pub fn apply_release_multiplier(base_reward: u64, multiplier: u64) -> u64 {
    ((base_reward as u128 * multiplier as u128) / SCALE as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_volume_returns_1x() {
        let m = calc_release_multiplier(100, 100, 800_000, 1_300_000);
        assert_eq!(m, 1_000_000);
    }

    #[test]
    fn test_low_volume_clamps_to_min() {
        let m = calc_release_multiplier(10, 100, 800_000, 1_300_000);
        assert_eq!(m, 800_000);
    }

    #[test]
    fn test_high_volume_clamps_to_max() {
        let m = calc_release_multiplier(500, 100, 800_000, 1_300_000);
        assert_eq!(m, 1_300_000);
    }

    #[test]
    fn test_zero_baseline_returns_1x() {
        let m = calc_release_multiplier(100, 0, 800_000, 1_300_000);
        assert_eq!(m, SCALE);
    }

    #[test]
    fn test_proportional_scaling() {
        // 150 / 100 = 1.5, clamped to 1.3
        let m = calc_release_multiplier(150, 100, 800_000, 1_300_000);
        assert_eq!(m, 1_300_000);

        // 120 / 100 = 1.2, within bounds
        let m = calc_release_multiplier(120, 100, 800_000, 1_300_000);
        assert_eq!(m, 1_200_000);
    }

    #[test]
    fn test_apply_release_multiplier() {
        let reward = apply_release_multiplier(1_000_000_000, 1_300_000);
        assert_eq!(reward, 1_300_000_000);

        let reward = apply_release_multiplier(1_000_000_000, 800_000);
        assert_eq!(reward, 800_000_000);
    }

    #[test]
    fn test_apply_no_overflow_large_reward() {
        let large_reward = 4_294_967_296_000_000_000u64; // full money supply
        let result = apply_release_multiplier(large_reward, 1_300_000);
        let expected = (large_reward as u128 * 1_300_000u128 / 1_000_000u128) as u64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_zero_volume() {
        let m = calc_release_multiplier(0, 100, 800_000, 1_300_000);
        assert_eq!(m, 800_000);
    }
}

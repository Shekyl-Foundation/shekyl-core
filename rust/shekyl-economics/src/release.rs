//! Transaction-responsive release rate multiplier.
//!
//! The multiplier paces how quickly the emission CURVE releases what
//! remains, toward demand. It is applied to the curve, and the perpetual
//! tail floors the result afterward (FL-R12′):
//!
//! ```text
//! M_r  = clamp(tx_volume / tx_volume_baseline, RELEASE_MIN, RELEASE_MAX)
//! paid = max(M_r · curve(remaining), TAIL) · penalty(x)
//! ```
//!
//! **The multiplier never scales an already-floored reward.**
//! [`crate::base_block_reward`] is `max(curve, TAIL)`, so multiplying THAT
//! is the composition FL-R12′ retired: at a perpetual tail there is
//! nothing left to defer, and a multiplied floor would pay least exactly
//! when fees are lowest — the dormancy case the floor exists for. The one
//! place the composition is formed is `emission::effective_emission`.
//!
//! Nor is emission bounded by a fixed supply any longer: FL-R12′ retired
//! the remaining-supply cap, so the accumulator runs THROUGH the curve's
//! asymptote and the tail is perpetual. The asymptote is a landmark, not
//! an end.

use crate::params::{clamp, SCALE};
use crate::volume::TxVolume;

/// Calculate the release rate multiplier from transaction volume.
///
/// # Arguments
/// * `tx_volume` - The trailing-window transaction volume as the exact
///   ratio `tx_count_sum : blocks` ([`TxVolume`], FL-R24)
/// * `tx_volume_baseline` - Reference transaction volume (from config)
/// * `release_min` - Minimum multiplier (fixed-point, e.g. 800_000 = 0.8)
/// * `release_max` - Maximum multiplier (fixed-point, e.g. 1_300_000 = 1.3)
///
/// # Returns
/// Fixed-point multiplier in SCALE units. 1_000_000 = 1.0x release rate.
pub fn calc_release_multiplier(
    tx_volume: TxVolume,
    tx_volume_baseline: u64,
    release_min: u64,
    release_max: u64,
) -> u64 {
    if tx_volume_baseline == 0 {
        return SCALE; // 1.0x if baseline is unconfigured
    }

    // ratio = tx_volume / tx_volume_baseline in SCALE units, one division
    // with the baseline and the window length both in the denominator
    // (FL-R24: nothing truncated before the ratio). Saturating past the
    // rail — the reasoning is on `TxVolume::ratio_scaled`.
    clamp(
        tx_volume.ratio_scaled(tx_volume_baseline),
        release_min,
        release_max,
    )
}

/// Apply the release multiplier to a CURVE emission.
///
/// Crate-internal on purpose. The only correct operand is
/// `curve_emission`'s output, and the only caller that composes it
/// correctly is `effective_emission`; a public export invited the
/// retired composition — multiplying the already-tail-floored
/// [`crate::base_block_reward`] — which is exactly what this module's own
/// documentation used to describe. Nothing outside the crate called it.
///
/// Saturating rather than truncating, matching
/// [`calc_release_multiplier`]: unreachable for any curve emission, and a
/// wrapped reward is the one failure this must never produce quietly.
pub(crate) fn apply_release_multiplier(base_reward: u64, multiplier: u64) -> u64 {
    u64::try_from(u128::from(base_reward) * u128::from(multiplier) / u128::from(SCALE))
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ratio past the `u64` rail must clamp to `release_max`. The
    /// wrapping cast this replaces landed on `release_min` instead — the
    /// far end of the range — because truncation makes a huge ratio look
    /// small and `clamp` cannot tell the difference.
    ///
    /// The input is chosen to DISCRIMINATE, which most inputs past the
    /// rail do not: `u64::MAX` wraps to `2⁶⁴ − 10⁶`, still enormous, so
    /// both the wrapping and the saturating form clamp to `release_max`
    /// and a test built on it passes either way. `⌈2⁶⁴/SCALE⌉` puts the
    /// product just past the rail, so it wraps to 448 384 — below
    /// `release_min` — and the two forms separate: 800 000 wrapping,
    /// 1 300 000 saturating.
    #[test]
    fn a_ratio_past_the_rail_clamps_to_the_top_not_the_bottom() {
        let just_past_the_rail = 18_446_744_073_710u64; // ⌈2⁶⁴ / SCALE⌉
        let got = calc_release_multiplier(
            TxVolume::per_block(just_past_the_rail),
            1,
            800_000,
            1_300_000,
        );
        assert_eq!(
            got, 1_300_000,
            "a ratio past the rail belongs at release_max; \
             a wrapping cast puts it at release_min instead"
        );
    }

    #[test]
    fn test_baseline_volume_returns_1x() {
        let m = calc_release_multiplier(TxVolume::per_block(100), 100, 800_000, 1_300_000);
        assert_eq!(m, 1_000_000);
    }

    #[test]
    fn test_low_volume_clamps_to_min() {
        let m = calc_release_multiplier(TxVolume::per_block(10), 100, 800_000, 1_300_000);
        assert_eq!(m, 800_000);
    }

    #[test]
    fn test_high_volume_clamps_to_max() {
        let m = calc_release_multiplier(TxVolume::per_block(500), 100, 800_000, 1_300_000);
        assert_eq!(m, 1_300_000);
    }

    #[test]
    fn test_zero_baseline_returns_1x() {
        let m = calc_release_multiplier(TxVolume::per_block(100), 0, 800_000, 1_300_000);
        assert_eq!(m, SCALE);
    }

    #[test]
    fn test_proportional_scaling() {
        // 150 / 100 = 1.5, clamped to 1.3
        let m = calc_release_multiplier(TxVolume::per_block(150), 100, 800_000, 1_300_000);
        assert_eq!(m, 1_300_000);

        // 120 / 100 = 1.2, within bounds
        let m = calc_release_multiplier(TxVolume::per_block(120), 100, 800_000, 1_300_000);
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
    #[allow(clippy::cast_possible_truncation)]
    fn test_apply_no_overflow_large_reward() {
        let large_reward = 4_294_967_296_000_000_000u64; // full money supply
        let result = apply_release_multiplier(large_reward, 1_300_000);
        let expected = (u128::from(large_reward) * 1_300_000u128 / 1_000_000u128) as u64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_zero_volume() {
        let m = calc_release_multiplier(TxVolume::per_block(0), 100, 800_000, 1_300_000);
        assert_eq!(m, 800_000);
    }

    #[test]
    fn test_multiplier_monotonic_with_volume() {
        let baseline = 100u64;
        let min = 800_000u64;
        let max = 1_300_000u64;

        let samples = [0u64, 10, 25, 50, 75, 100, 120, 150, 500];
        let mut prev = 0u64;
        for s in samples {
            let m = calc_release_multiplier(TxVolume::per_block(s), baseline, min, max);
            assert!(
                m >= prev,
                "multiplier regressed at volume {s}: {m} < {prev}"
            );
            assert!(
                m >= min && m <= max,
                "multiplier out of bounds at volume {s}: {m}"
            );
            prev = m;
        }
    }
}

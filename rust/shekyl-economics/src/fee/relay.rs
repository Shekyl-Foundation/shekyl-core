// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Relay floor `F = R·C·w_ref/M²` and lookback-min admission.

use super::correction::FeeCorrection;
use crate::params::SCALE;

/// Lookback depth `G`, in blocks. Admission takes `min F` over `h′−G ..= h′`,
/// so a quote at `F(h)` is admitted at every node whose tip lies in
/// `[h, h+G]`.
///
/// Derived from the hot-session quote-to-broadcast gap (0–2) + the network
/// height spread at relay (2) + one block of slack.
pub const RELAY_FLOOR_LOOKBACK: usize = 5;

/// `G + 1` — the ring / FFI window length.
pub const RELAY_FLOOR_WINDOW: usize = RELAY_FLOOR_LOOKBACK + 1;

/// Admission slack, basis points. Pinned at zero: the lookback closes the
/// quote-to-broadcast gap exactly. Re-introducing a buffer is this constant
/// and its KAT. What makes zero safe is `shekyl-tx-weight`'s weight gate.
pub const RELAY_ADMISSION_SLACK_BP: u32 = 0;

/// Fee median `M` every rung and the relay floor divide by.
pub(super) fn clamped_median(median: u64, full_reward_zone: u64) -> u64 {
    median.max(full_reward_zone).max(1)
}

/// `F = R·C·w_ref/M²`, floored at 1. `None` only outside the `u128` domain.
///
/// Raw `C`, no rounding. `max(1)` is kept: a zero floor admits everything,
/// and `get_current_fee_per_byte`'s contract that `0` is the
/// block-reward-failure arm is load-bearing at the C++ call site.
#[must_use]
pub fn checked_relay_fee_floor(
    base_reward: u64,
    median: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c: FeeCorrection,
) -> Option<u64> {
    let mfw = u128::from(clamped_median(median, full_reward_zone));
    let ms = mfw.checked_mul(u128::from(SCALE))?;
    let m2s = mfw.checked_mul(ms)?;
    let num = u128::from(base_reward)
        .checked_mul(u128::from(ref_tx_weight))?
        .checked_mul(u128::from(c.as_scaled()))?;
    Some(u64::try_from(num / m2s).unwrap_or(u64::MAX).max(1))
}

/// [`checked_relay_fee_floor`], saturating outside the domain.
#[must_use]
pub fn relay_fee_floor(
    base_reward: u64,
    median: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c: FeeCorrection,
) -> u64 {
    checked_relay_fee_floor(base_reward, median, full_reward_zone, ref_tx_weight, c)
        .unwrap_or(u64::MAX)
}

/// Admit iff `fee >= mask_round_up(weight · min(floors))` less `slack_bp`
/// basis points.
///
/// `floors` is the `(h′−G ..= h′)` window; only the minimum is read, so
/// order carries no meaning. A short window is stricter, never looser.
/// Empty `floors` refuses: no floor is not a floor of zero.
///
/// Reopening (rule 21): FL-R23 reopens if any operand with a per-block
/// response enters `F` — a fast term would be amplified by the window
/// for `G` blocks.
#[must_use]
pub fn relay_floor_admits(fee: u64, weight: u64, mask: u64, floors: &[u64], slack_bp: u32) -> bool {
    let Some(&min_floor) = floors.iter().min() else {
        return false;
    };
    let mask = u128::from(mask.max(1));
    let needed = {
        let raw = u128::from(weight) * u128::from(min_floor);
        raw.div_ceil(mask) * mask
    };
    let threshold = needed - needed * u128::from(slack_bp) / 10_000;
    u128::from(fee) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_floor_matches_the_migrated_heritage_grid() {
        const COIN: u64 = 1_000_000_000;
        const ZONE: u64 = 300_000;
        const W_REF: u64 = 3_000;

        // (reward, median, old 0.95 value, new FL-R20 value)
        let grid: [(u64, u64, u64, u64); 18] = [
            (10 * COIN, ZONE, 317, 333),
            (10 * COIN, ZONE / 2, 317, 333),
            (10 * COIN, 1, 317, 333),
            (10 * COIN, 100_000, 317, 333),
            (10 * COIN, 600_000, 79, 83),
            (10 * COIN, 3_000_000, 3, 3),
            (10 * COIN, 6_000_000, 1, 1),
            (COIN, ZONE, 32, 33),
            (COIN, ZONE / 2, 32, 33),
            (COIN, 1, 32, 33),
            (COIN, 600_000, 8, 8),
            (COIN, 3_000_000, 1, 1),
            (3 * COIN / 10, ZONE, 10, 10),
            (3 * COIN / 10, ZONE / 2, 10, 10),
            (3 * COIN / 10, 1, 10, 10),
            (3 * COIN / 10, 600_000, 2, 2),
            (3 * COIN / 10, 3_000_000, 1, 1),
            (1, ZONE, 1, 1),
        ];

        let mut moved = 0usize;
        for &(reward, median, old, new) in &grid {
            assert_eq!(
                relay_fee_floor(reward, median, ZONE, W_REF, FeeCorrection::UNITY),
                new,
                "FL-R20 floor at reward={reward} median={median} (C = 1)"
            );
            assert_eq!(new - new / 20, old, "0.95 relation at median={median}");
            if new != old {
                moved += 1;
            }
        }
        assert_eq!(moved, 8, "exactly eight rows move when the 0.95 goes");

        assert_eq!(
            relay_fee_floor(COIN, 100_000 * ZONE, ZONE, W_REF, FeeCorrection::UNITY),
            1,
            "max(1) is kept: a zero floor admits everything"
        );
    }

    #[test]
    fn the_admission_slack_is_zero() {
        assert_eq!(
            RELAY_ADMISSION_SLACK_BP, 0,
            "FL-R23 admits at the floor exactly"
        );
        assert_eq!(RELAY_FLOOR_LOOKBACK, 5, "G = 5 (review A-1)");
        assert_eq!(RELAY_FLOOR_WINDOW, RELAY_FLOOR_LOOKBACK + 1);
    }

    #[test]
    fn a_fee_at_the_floor_exactly_is_admitted() {
        let floor = 333u64;
        let weight = 11_097u64;
        let exact = weight * floor;
        assert!(relay_floor_admits(
            exact,
            weight,
            1,
            &[floor],
            RELAY_ADMISSION_SLACK_BP
        ));
        assert!(!relay_floor_admits(
            exact - 1,
            weight,
            1,
            &[floor],
            RELAY_ADMISSION_SLACK_BP
        ));
    }

    #[test]
    fn the_lookback_admits_a_quote_from_the_oldest_block_in_the_window() {
        let weight = 1_000u64;
        let window: Vec<u64> = (0..=RELAY_FLOOR_LOOKBACK as u64)
            .map(|k| 100 + k * 7)
            .collect();
        let oldest = *window.first().expect("window is non-empty");
        let newest = *window.last().expect("window is non-empty");
        assert!(newest > oldest, "the fixture must actually rise");

        assert!(relay_floor_admits(weight * oldest, weight, 1, &window, 0));
        assert!(!relay_floor_admits(
            weight * oldest,
            weight,
            1,
            &[newest],
            0
        ));
    }

    #[test]
    fn a_short_window_only_ever_refuses_more() {
        let weight = 1_000u64;
        let full = [140u64, 133, 127, 121, 115, 110];
        for cut in 1..full.len() {
            let partial = &full[..cut];
            for fee_per_weight in 100..=145u64 {
                let fee = weight * fee_per_weight;
                let full_admits = relay_floor_admits(fee, weight, 1, &full, 0);
                let partial_admits = relay_floor_admits(fee, weight, 1, partial, 0);
                assert!(
                    !partial_admits || full_admits,
                    "a {cut}-entry window admitted a fee the full window refused"
                );
            }
        }
        let fee = weight * 115;
        assert!(relay_floor_admits(fee, weight, 1, &full, 0));
        assert!(!relay_floor_admits(fee, weight, 1, &full[..1], 0));
    }

    #[test]
    fn an_empty_window_refuses_everything() {
        assert!(!relay_floor_admits(u64::MAX, 1, 1, &[], 0));
        assert!(!relay_floor_admits(0, 0, 1, &[], 0));
    }

    #[test]
    fn the_requirement_is_rounded_up_to_the_mask() {
        let weight = 10u64;
        let floor = 7u64;
        assert!(relay_floor_admits(70, weight, 1, &[floor], 0));
        assert!(!relay_floor_admits(70, weight, 100, &[floor], 0));
        assert!(!relay_floor_admits(99, weight, 100, &[floor], 0));
        assert!(relay_floor_admits(100, weight, 100, &[floor], 0));
        assert!(relay_floor_admits(70, weight, 0, &[floor], 0));
    }

    #[test]
    fn slack_lowers_the_requirement_when_it_is_not_zero() {
        let weight = 1_000u64;
        let floor = 100u64;
        assert!(!relay_floor_admits(99_000, weight, 1, &[floor], 0));
        assert!(relay_floor_admits(98_000, weight, 1, &[floor], 200));
        assert!(!relay_floor_admits(97_999, weight, 1, &[floor], 200));
    }
}

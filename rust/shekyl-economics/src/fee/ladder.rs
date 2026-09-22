// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Three-tier ladder. Economy is the relay floor; standard is `4F`;
//! priority is `max(2RC/M, 4F)` so the slots are monotone by construction.

use super::correction::FeeCorrection;
use super::relay::{checked_relay_fee_floor, clamped_median};
use crate::params::{EconomicParams, SCALE};

/// `round_money_up(v, 2)` — round UP to 2 significant decimal digits.
///
/// Off the served path (FL-R21). Kept as the production owner of the
/// rounding rule: wallet cap and the FL instrument import this rather
/// than carrying a third copy. Saturation is unreachable for any fee
/// the ladder can emit.
#[must_use]
pub fn round_money_up_2(v: u64) -> u64 {
    if v < 100 {
        return v;
    }
    let mut unit = 1u64;
    let mut head = v;
    while head >= 100 {
        head /= 10;
        unit *= 10;
    }
    v.div_ceil(unit).saturating_mul(unit)
}

/// Wallet-side emission-claim value floor, atomic units
/// (`ENGINE_CADENCE_DRIVER.md` §4): hold settled epochs until Σreward
/// clears this. Genesis economy × claim envelope, rounded up to 3.6 SKL
/// so the floor errs toward holding one more epoch. Uniform across
/// wallets (anti-fingerprint). Not consensus.
pub const EMISSION_CLAIM_FEE_FLOOR: u64 = 3_600_000_000;

/// The three priced rungs. [`Self::as_slots`] is the wire projection:
/// `[economy, standard, priority]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeLadder {
    pub economy: u64,
    pub standard: u64,
    pub priority: u64,
}

impl FeeLadder {
    /// Every rung at the `u64` rail. Saturation
    /// [`corrected_fee_ladder`] takes outside its `u128` domain.
    pub const SATURATED: Self = Self {
        economy: u64::MAX,
        standard: u64::MAX,
        priority: u64::MAX,
    };

    /// Wire shape `[economy, standard, priority]`.
    #[must_use]
    pub const fn as_slots(self) -> [u64; 3] {
        [self.economy, self.standard, self.priority]
    }
}

/// Three-tier ladder: economy = [`super::relay_fee_floor`], standard = `4F`,
/// priority = `max(2RC/M, 4F)`.
///
/// `base_reward` is the M_r-neutral total (`max(curve(remaining), TAIL)`);
/// `median` is the long-term fee median; `c` is raw [`FeeCorrection`].
/// Saturates outside the `u128` domain — see [`checked_corrected_fee_ladder`].
#[must_use]
pub fn corrected_fee_ladder(
    base_reward: u64,
    median: u64,
    ref_tx_weight: u64,
    c: FeeCorrection,
    params: &EconomicParams,
) -> FeeLadder {
    checked_corrected_fee_ladder(base_reward, median, ref_tx_weight, c, params)
        .unwrap_or(FeeLadder::SATURATED)
}

/// [`corrected_fee_ladder`], or `None` when the scalars cannot form the
/// rungs' products in `u128`. The fallible arm exists for the `extern "C"`
/// boundary (rule 40): operands near `u64::MAX` overflow `u128` before any
/// conversion fallback can see it.
#[must_use]
pub fn checked_corrected_fee_ladder(
    base_reward: u64,
    median: u64,
    ref_tx_weight: u64,
    c: FeeCorrection,
    params: &EconomicParams,
) -> Option<FeeLadder> {
    let mfw = u128::from(clamped_median(median, params));
    let base = u128::from(base_reward);
    let cq = u128::from(c.as_scaled());
    let ms = mfw.checked_mul(u128::from(SCALE))?;

    let economy = checked_relay_fee_floor(base_reward, median, ref_tx_weight, c, params)?;
    // `4F` in u128, saturating at the u64 rail. Not `economy.checked_mul(4)`:
    // that multiplies in u64 and would refuse a ladder the pre-FL-R20 shape
    // still priced (BLOCK_REWARD_OVERESTIMATE fallback).
    let standard = u64::try_from(u128::from(economy) * 4).unwrap_or(u64::MAX);
    // Raised to `standard` so the ladder is monotone by construction. At a
    // reward small enough to truncate every quotient to zero, economy is
    // `max(1)` = 1, standard is 4, and an unfloored priority is 0.
    let priority = u64::try_from(base.checked_mul(cq)?.checked_mul(2)? / ms)
        .unwrap_or(u64::MAX)
        .max(standard);
    Some(FeeLadder {
        economy,
        standard,
        priority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_block_reward;
    use crate::fee::relay::relay_fee_floor;

    fn shipped() -> EconomicParams {
        EconomicParams::default()
    }

    #[test]
    fn neutral_ladder_matches_heritage_vectors_with_signed_shape() {
        let params = shipped();
        let zone = params.full_reward_zone;
        let coin = 1_000_000_000u64;
        assert_eq!(
            corrected_fee_ladder(10 * coin, zone, 3_000, FeeCorrection::UNITY, &params).as_slots(),
            [333, 1332, 66_666]
        );
        // Heritage case 2 used to pass Mnw = 15 MB over Mlw = the zone. The
        // median is one operand now; that pair always reduced to the zone.
        assert_eq!(
            corrected_fee_ladder(10 * coin, zone, 3_000, FeeCorrection::UNITY, &params).as_slots(),
            [333, 1332, 66_666]
        );
        assert_eq!(
            corrected_fee_ladder(10 * coin, 5 * zone, 3_000, FeeCorrection::UNITY, &params)
                .as_slots(),
            [13, 52, 13_333]
        );
    }

    #[test]
    fn the_domain_covers_each_rung_separately() {
        let params = shipped();
        let z = params.full_reward_zone;
        assert!(checked_corrected_fee_ladder(
            u64::MAX,
            z,
            0,
            FeeCorrection::from_scaled(u64::MAX),
            &params,
        )
        .is_none());
        assert!(
            checked_corrected_fee_ladder(u64::MAX, z, 0, FeeCorrection::UNITY, &params).is_some()
        );
        assert!(checked_corrected_fee_ladder(
            u64::MAX,
            z,
            u64::MAX,
            FeeCorrection::from_scaled(2),
            &params,
        )
        .is_none());
        assert!(checked_corrected_fee_ladder(
            u64::MAX,
            z,
            u64::MAX,
            FeeCorrection::from_scaled(1),
            &params,
        )
        .is_some());
        assert!(checked_corrected_fee_ladder(
            1,
            u64::MAX,
            1,
            FeeCorrection::from_scaled(1),
            &params,
        )
        .is_none());
        assert!(checked_corrected_fee_ladder(
            10_000_000_000,
            z,
            3_000,
            FeeCorrection::UNITY,
            &params
        )
        .is_some());
    }

    #[test]
    fn the_infallible_entry_saturates_outside_the_domain() {
        let params = shipped();
        assert_eq!(
            corrected_fee_ladder(
                u64::MAX,
                params.full_reward_zone,
                0,
                FeeCorrection::from_scaled(u64::MAX),
                &params,
            ),
            FeeLadder::SATURATED
        );
        assert_eq!(FeeLadder::SATURATED.as_slots(), [u64::MAX; 3]);
    }

    #[test]
    fn correction_lives_in_the_numerator() {
        let params = shipped();
        let coin = 1_000_000_000u64;
        let ladder = corrected_fee_ladder(
            10 * coin,
            5 * params.full_reward_zone,
            3_000,
            FeeCorrection::from_scaled(16 * SCALE),
            &params,
        );
        assert_eq!(ladder.economy, 213);
        assert_eq!(13 * 16, 208, "the rescale-after value this rung must beat");
        assert_eq!(
            ladder.as_slots(),
            [ladder.economy, ladder.standard, ladder.priority]
        );
    }

    #[test]
    fn genesis_top_rung_anchors() {
        let p = shipped();
        let zone = p.full_reward_zone;
        let base = base_block_reward(0, &p).unwrap();
        assert_eq!(
            corrected_fee_ladder(base, zone, 3_000, FeeCorrection::UNITY, &p).priority,
            13_653_333
        );
        assert_eq!(
            corrected_fee_ladder(base, zone, 3_000, FeeCorrection::from_scaled(2 * SCALE), &p)
                .priority,
            27_306_666
        );
    }

    #[test]
    fn economy_rung_is_the_relay_floor() {
        let params = shipped();
        let zone = params.full_reward_zone;
        let coin = 1_000_000_000u64;
        let mut floored = 0usize;
        for &reward in &[1u64, 1_000, 10 * coin, 2_048_000_000_000] {
            for &median in &[zone, 5 * zone, 50 * zone, 50_000_000] {
                for &c in &[SCALE * 68 / 100, SCALE, 2 * SCALE, 16 * SCALE] {
                    let c = FeeCorrection::from_scaled(c);
                    let ladder = corrected_fee_ladder(reward, median, 3_000, c, &params);
                    let floor = relay_fee_floor(reward, median, 3_000, c, &params);
                    assert_eq!(
                        ladder.economy, floor,
                        "economy != relay floor at reward={reward} median={median} c={c:?}",
                    );
                    assert_eq!(ladder.standard, floor * 4, "standard must be 4F");
                    if floor == 1 {
                        floored += 1;
                    }
                }
            }
        }
        assert!(floored > 0, "the sweep must reach the max(1) floor");
    }

    #[test]
    fn the_served_ladder_is_monotone() {
        let params = shipped();
        let zone = params.full_reward_zone;
        let coin = 1_000_000_000u64;
        for &reward in &[1u64, 1_000, 10 * coin, 2_048_000_000_000] {
            for &m in &[zone, 5 * zone, 50 * zone, 50_000_000] {
                for &c in &[SCALE * 68 / 100, SCALE, 16 * SCALE] {
                    let ladder = corrected_fee_ladder(
                        reward,
                        m,
                        3_000,
                        FeeCorrection::from_scaled(c),
                        &params,
                    );
                    assert!(
                        ladder.economy <= ladder.standard,
                        "economy {} above standard {} at reward={reward} m={m} c={c}",
                        ladder.economy,
                        ladder.standard
                    );
                    assert!(
                        ladder.standard <= ladder.priority,
                        "standard {} above priority {} at reward={reward} m={m} c={c}",
                        ladder.standard,
                        ladder.priority
                    );
                }
            }
        }

        let degenerate = corrected_fee_ladder(1, zone, 3_000, FeeCorrection::UNITY, &params);
        assert_eq!(
            degenerate.as_slots(),
            [1, 4, 4],
            "every rung truncates to zero here; the floors must still leave a ladder"
        );
    }

    #[test]
    fn round_money_up_two_places_matches_cpp() {
        assert_eq!(round_money_up_2(0), 0);
        assert_eq!(round_money_up_2(99), 99);
        assert_eq!(round_money_up_2(101), 110);
        assert_eq!(round_money_up_2(27_810), 28_000);
        assert_eq!(round_money_up_2(13_653_333), 14_000_000);
    }
}

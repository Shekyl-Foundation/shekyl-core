// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Three-tier ladder. Economy is the relay floor; standard is the policy's
//! [`RelayPolicy::standard_over_economy`] times that floor; high is
//! `max(f·RC/M, standard)`, `f` the policy's
//! [`RelayPolicy::high_factor`], so the slots are monotone by
//! construction. At the shipped policy these are 4 and 2.

use super::correction::FeeCorrection;
use super::relay::{checked_relay_fee_floor, clamped_median};
use crate::params::{EconomicParams, SCALE};
use crate::RelayPolicy;

/// Wallet-side emission-claim hold, atomic units
/// (`ENGINE_CADENCE_DRIVER.md` §4): hold settled epochs until Σreward
/// clears it and the live fee. Derived (ruling 9): the claim leg's priced
/// weight at the chain's genesis Economy rung, on the shipped lattice —
/// `config/relay_policy.json` `emission_claim_fee_floor_atomic`, recomputed
/// by `shekyl-engine-core`'s test. Uniform across wallets
/// (anti-fingerprint). Not consensus. The shipped
/// [`RelayPolicy::emission_claim_fee_floor`](crate::RelayPolicy::emission_claim_fee_floor).
pub const EMISSION_CLAIM_FEE_FLOOR: u64 = crate::params::GENERATED_EMISSION_CLAIM_FEE_FLOOR;

/// Standard rung over the economy rung at the shipped policy. The served
/// ladder is `standard = 4F`. Generated from `config/relay_policy.json`
/// `standard_rung_over_economy`; a policy's is
/// [`RelayPolicy::standard_over_economy`](crate::RelayPolicy::standard_over_economy).
pub const STANDARD_RUNG_OVER_ECONOMY: u64 = crate::params::GENERATED_STANDARD_RUNG_OVER_ECONOMY;

/// The three priced rungs. [`Self::as_slots`] is the wire projection:
/// `[economy, standard, high]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeLadder {
    pub economy: u64,
    pub standard: u64,
    pub high: u64,
}

impl FeeLadder {
    /// Every rung at the `u64` rail. Saturation
    /// [`corrected_fee_ladder`] takes outside its `u128` domain.
    pub const SATURATED: Self = Self {
        economy: u64::MAX,
        standard: u64::MAX,
        high: u64::MAX,
    };

    /// Wire shape `[economy, standard, high]`.
    #[must_use]
    pub const fn as_slots(self) -> [u64; 3] {
        [self.economy, self.standard, self.high]
    }

    /// The rung a payer at `priority` pays.
    #[must_use]
    pub const fn rung(self, priority: FeePriority) -> u64 {
        match priority {
            FeePriority::Economy => self.economy,
            FeePriority::Standard => self.standard,
            FeePriority::High => self.high,
        }
    }
}

/// Which of the ladder's three rungs a payer pays: the one fee tier set
/// (IG-Q52). Every wallet surface, the engine, the preferences file, the
/// wallet RPC and the CLI, names a tier by this type; the wire and the
/// preferences file spell it lowercase.
///
/// There is no per-wallet rate. The fee is cleartext on chain, and a
/// wallet that pays one of three values every conforming wallet derives
/// from chain state hides in that tier's cohort; a rate of its own choosing
/// marks it (`FEE_LADDER_DERIVATION.md` W3, ruled 2026-11-15). If `High`
/// misses its confirmation target under measured congestion, the fix is in
/// the derivation of the top rung, so every wallet still pays the same rate.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum FeePriority {
    /// The relay floor: the cheapest rung.
    Economy,
    /// [`STANDARD_RUNG_OVER_ECONOMY`] times the floor. The default.
    #[default]
    Standard,
    /// The top rung, `max(f·R·C/M, standard)`.
    High,
}

impl FeePriority {
    /// Every tier, cheapest first: the order [`FeeLadder::as_slots`] holds
    /// the rungs in.
    pub const ALL: [Self; 3] = [Self::Economy, Self::Standard, Self::High];

    /// Every tier's name, in [`Self::ALL`]'s order: the closed keyword set
    /// the wire, the preferences file and the CLI accept.
    pub const NAMES: [&'static str; 3] = ["economy", "standard", "high"];

    /// The tier's name, as the wire, the preferences file and the CLI
    /// spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        Self::NAMES[self as usize]
    }

    /// The tier a name spells, or `None`. Lowercase only: the grammar's
    /// keywords have one spelling (IG-1).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tier| tier.name() == name)
    }
}

impl core::fmt::Display for FeePriority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Three-tier ladder: economy = [`super::relay_fee_floor`], standard =
/// `policy`'s ratio times that floor, high = `max(f·RC/M, standard)`.
///
/// `base_reward` is the M_r-neutral total (`max(curve(remaining), TAIL)`);
/// `median` is the long-term fee median; `c` is raw [`FeeCorrection`].
/// Saturates outside the `u128` domain ([`super::fee_ladder_from`] refuses there).
#[must_use]
pub fn corrected_fee_ladder(
    base_reward: u64,
    median: u64,
    ref_tx_weight: u64,
    c: FeeCorrection,
    params: &EconomicParams,
    policy: &RelayPolicy,
) -> FeeLadder {
    checked_corrected_fee_ladder(base_reward, median, ref_tx_weight, c, params, policy)
        .unwrap_or(FeeLadder::SATURATED)
}

/// [`corrected_fee_ladder`], or `None` when the scalars cannot form the
/// rungs' products in `u128`. [`super::fee_ladder_from`] serves the ladder
/// through this arm: operands near `u64::MAX` overflow `u128` before any
/// conversion fallback can see it.
#[must_use]
pub(super) fn checked_corrected_fee_ladder(
    base_reward: u64,
    median: u64,
    ref_tx_weight: u64,
    c: FeeCorrection,
    params: &EconomicParams,
    policy: &RelayPolicy,
) -> Option<FeeLadder> {
    let mfw = u128::from(clamped_median(median, params));
    let base = u128::from(base_reward);
    let cq = u128::from(c.as_scaled());
    let ms = mfw.checked_mul(u128::from(SCALE))?;

    let economy = checked_relay_fee_floor(base_reward, median, ref_tx_weight, c, params)?;
    // The Standard multiple in u128, saturating at the u64 rail. Not
    // `economy.checked_mul(STANDARD_RUNG_OVER_ECONOMY)`: that multiplies in
    // u64 and would refuse a ladder the pre-FL-R20 shape still priced
    // (BLOCK_REWARD_OVERESTIMATE fallback).
    let standard = u64::try_from(u128::from(economy) * u128::from(policy.standard_over_economy))
        .unwrap_or(u64::MAX);
    // Raised to `standard` so the ladder is monotone by construction. At a
    // reward small enough to truncate every quotient to zero, economy is
    // `max(1)` = 1, standard is that times the policy's ratio, and an
    // unfloored high is 0.
    let high = u64::try_from(
        base.checked_mul(cq)?
            .checked_mul(u128::from(policy.high_factor))?
            / ms,
    )
    .unwrap_or(u64::MAX)
    .max(standard);
    Some(FeeLadder {
        economy,
        standard,
        high,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_block_reward;
    use crate::fee::relay::relay_fee_floor;
    use crate::RELAY_FLOOR_REFERENCE_TX_WEIGHT as W_REF;

    fn shipped() -> EconomicParams {
        EconomicParams::default()
    }

    #[test]
    fn neutral_ladder_matches_heritage_vectors_with_signed_shape() {
        let params = shipped();
        let zone = params.full_reward_zone;
        let coin = 1_000_000_000u64;
        assert_eq!(
            corrected_fee_ladder(
                10 * coin,
                zone,
                W_REF,
                FeeCorrection::UNITY,
                &params,
                &crate::RelayPolicy::SHIPPED
            )
            .as_slots(),
            [333, 1332, 66_666]
        );
        // Heritage case 2 used to pass Mnw = 15 MB over Mlw = the zone. The
        // median is one operand now; that pair always reduced to the zone.
        assert_eq!(
            corrected_fee_ladder(
                10 * coin,
                zone,
                W_REF,
                FeeCorrection::UNITY,
                &params,
                &crate::RelayPolicy::SHIPPED
            )
            .as_slots(),
            [333, 1332, 66_666]
        );
        assert_eq!(
            corrected_fee_ladder(
                10 * coin,
                5 * zone,
                W_REF,
                FeeCorrection::UNITY,
                &params,
                &crate::RelayPolicy::SHIPPED
            )
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
            &crate::RelayPolicy::SHIPPED,
        )
        .is_none());
        assert!(checked_corrected_fee_ladder(
            u64::MAX,
            z,
            0,
            FeeCorrection::UNITY,
            &params,
            &crate::RelayPolicy::SHIPPED
        )
        .is_some());
        assert!(checked_corrected_fee_ladder(
            u64::MAX,
            z,
            u64::MAX,
            FeeCorrection::from_scaled(2),
            &params,
            &crate::RelayPolicy::SHIPPED,
        )
        .is_none());
        assert!(checked_corrected_fee_ladder(
            u64::MAX,
            z,
            u64::MAX,
            FeeCorrection::from_scaled(1),
            &params,
            &crate::RelayPolicy::SHIPPED,
        )
        .is_some());
        assert!(checked_corrected_fee_ladder(
            1,
            u64::MAX,
            1,
            FeeCorrection::from_scaled(1),
            &params,
            &crate::RelayPolicy::SHIPPED,
        )
        .is_none());
        assert!(checked_corrected_fee_ladder(
            10_000_000_000,
            z,
            W_REF,
            FeeCorrection::UNITY,
            &params,
            &crate::RelayPolicy::SHIPPED
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
                &crate::RelayPolicy::SHIPPED,
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
            W_REF,
            FeeCorrection::from_scaled(16 * SCALE),
            &params,
            &crate::RelayPolicy::SHIPPED,
        );
        assert_eq!(ladder.economy, 213);
        assert_eq!(13 * 16, 208, "the rescale-after value this rung must beat");
        assert_eq!(
            ladder.as_slots(),
            [ladder.economy, ladder.standard, ladder.high]
        );
    }

    /// One spelling per tier: [`FeePriority::name`], the serde form the
    /// wire and the preferences file carry, and [`FeePriority::from_name`]
    /// agree, and a name in any other case is no tier.
    #[test]
    fn a_tier_has_one_spelling() {
        for tier in FeePriority::ALL {
            let json = serde_json::to_string(&tier).expect("serialize");
            assert_eq!(json, format!("\"{}\"", tier.name()));
            assert_eq!(FeePriority::from_name(tier.name()), Some(tier));
            assert_eq!(FeePriority::from_name(&tier.name().to_uppercase()), None);
        }
        assert_eq!(FeePriority::from_name("priority"), None);
        assert_eq!(FeePriority::default(), FeePriority::Standard);
    }

    #[test]
    fn genesis_top_rung_anchors() {
        let p = shipped();
        let zone = p.full_reward_zone;
        let base = base_block_reward(0, &p).unwrap();
        assert_eq!(
            corrected_fee_ladder(
                base,
                zone,
                W_REF,
                FeeCorrection::UNITY,
                &p,
                &crate::RelayPolicy::SHIPPED
            )
            .high,
            6_826_666
        );
        assert_eq!(
            corrected_fee_ladder(
                base,
                zone,
                W_REF,
                FeeCorrection::from_scaled(2 * SCALE),
                &p,
                &crate::RelayPolicy::SHIPPED
            )
            .high,
            13_653_333
        );
    }

    #[test]
    fn standard_rung_over_economy_is_four() {
        // The ratio the ladder multiplies by. `economy_rung_is_the_relay_floor`
        // keeps `floor * 4` as an independent check that the product is that
        // multiple, so this pin and that assertion are not the same line.
        assert_eq!(STANDARD_RUNG_OVER_ECONOMY, 4);
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
                    let ladder = corrected_fee_ladder(
                        reward,
                        median,
                        W_REF,
                        c,
                        &params,
                        &crate::RelayPolicy::SHIPPED,
                    );
                    let floor = relay_fee_floor(reward, median, W_REF, c, &params);
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
                        W_REF,
                        FeeCorrection::from_scaled(c),
                        &params,
                        &crate::RelayPolicy::SHIPPED,
                    );
                    assert!(
                        ladder.economy <= ladder.standard,
                        "economy {} above standard {} at reward={reward} m={m} c={c}",
                        ladder.economy,
                        ladder.standard
                    );
                    assert!(
                        ladder.standard <= ladder.high,
                        "standard {} above high {} at reward={reward} m={m} c={c}",
                        ladder.standard,
                        ladder.high
                    );
                }
            }
        }

        let degenerate = corrected_fee_ladder(
            1,
            zone,
            W_REF,
            FeeCorrection::UNITY,
            &params,
            &crate::RelayPolicy::SHIPPED,
        );
        assert_eq!(
            degenerate.as_slots(),
            [1, 4, 4],
            "every rung truncates to zero here; the floors must still leave a ladder"
        );
    }

    /// E16-7: each of the policy's ladder fields moves the rung that reads
    /// it, and `w_ref` moves the floor.
    #[test]
    fn each_policy_field_moves_its_rung() {
        let p = shipped();
        let zone = p.full_reward_zone;
        let base = 10 * 1_000_000_000u64;
        let shipped_policy = crate::RelayPolicy::SHIPPED;
        let ladder = |policy: &crate::RelayPolicy| {
            corrected_fee_ladder(
                base,
                zone,
                policy.ref_tx_weight,
                FeeCorrection::UNITY,
                &p,
                policy,
            )
        };
        let at = ladder(&shipped_policy);
        assert_eq!(at.as_slots(), [333, 1332, 66_666]);

        let standard = crate::RelayPolicy {
            standard_over_economy: 5,
            ..shipped_policy
        };
        assert_eq!(ladder(&standard).standard, 5 * at.economy);

        let high = crate::RelayPolicy {
            high_factor: 3,
            ..shipped_policy
        };
        // One floor of 3·R·C/M (2·R·C/M is 66 666.6…), not 3 × ⌊R·C/M⌋.
        assert_eq!(ladder(&high).high, 100_000);

        let heavier = crate::RelayPolicy {
            ref_tx_weight: 6_000,
            ..shipped_policy
        };
        assert_eq!(ladder(&heavier).economy, 666);
    }
}

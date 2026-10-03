// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What an ordinary transaction pays in a run
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-1).
//!
//! The fee is an arm of the run, not a property of a scenario: every
//! scenario reads it from [`crate::engine::SimParams::fee`], so one value at
//! the top of a run decides what every fold charges, and a report cannot mix
//! two fees without saying so.
//!
//! The production arm prices nothing itself. The per-byte rate is
//! [`shekyl_economics::corrected_fee_ladder`] at the block's own reward and
//! correction; the weight it multiplies is
//! [`shekyl_tx_weight::predict_weight`] for the ordinary shape at the chain's
//! depth. What this module adds is the order of the calls and the three
//! places the run still departs from the chain, each named in the type or
//! below so that none is silent:
//!
//! - the block-weight median is [`MedianModel`], not the validator's fold;
//! - the fee is paid **unrounded** — the wallet rounds up to the daemon's
//!   quantization mask (1 000 atomic), which has no Rust owner, and the
//!   fee-floor instrument in this crate already pays exactly (FL-R22);
//! - the volume, split and burn operands are the fold's own, so they carry
//!   whatever that fold carries (the design document's ESR-3 and ESR-4).

use serde::Serialize;
use shekyl_economics::{
    base_block_reward, corrected_fee_ladder, fee_correction, EconomicParams, FeeLadder, TxVolume,
};
use shekyl_tx_weight::predict_weight;

use crate::burden::normal_tx_shape;
use crate::calibration::tree_depth_for_leaves;
use crate::fee_ladder::REF_TX_WEIGHT;

/// The block-weight median the ladder divides by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MedianModel {
    /// **A declared divergence** (§4 of the design document): the median is
    /// held at the penalty-free zone, the highest the floor can be. The
    /// validator's median rises when traffic exceeds the zone, and the floor
    /// falls as `1/M²` with it; this run does not model that. ESR-6 replaces
    /// this variant with the validator's fold.
    PenaltyFreeZone,
}

/// How a run prices an ordinary transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeModel {
    /// **Control arm — a declared divergence from production** (§4 of the
    /// design document). One flat fee per transaction at every height.
    ///
    /// The chain charges no such fee: its relay floor is
    /// `F = R·C·w_ref/M²`, proportional to the block reward. This arm
    /// exists because the tables in
    /// `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13–§12.14 were
    /// measured on it, and a control that reproduces them is what shows a
    /// later difference is the fee and nothing else.
    FlatControl {
        /// Atomic units per transaction.
        per_tx_atomic: u64,
        /// What admission costs per byte on this arm — the rate a stuffer
        /// pays. Flat as well, and for the same reason.
        admission_rate: PerByteRate,
    },
    /// The Standard rung of the production ladder — four times the relay
    /// floor, the wallet's default (`FEE_LADDER_DERIVATION.md` §5.5) — at
    /// the block's own state, times a multiplier.
    ProductionStandard {
        /// Thousandths: `1_000` is the rung exactly. Anything else is a
        /// declared divergence standing in for what users pay above the
        /// default, which is not knowable before launch.
        multiplier_milli: u64,
        median: MedianModel,
    },
}

/// The flat fee the §12.13–§12.14 tables were measured on: `0.1 SKL`.
pub const SECTION_12_14_FLAT_FEE_ATOMIC: u64 = 100_000_000;

/// The admission rate the §12.13 stuffer was priced at: 300 atomic per
/// byte. Nothing in the chain charges it — the chain's admission rate is
/// the relay floor. Kept as the control arm's value and nowhere else.
pub const SECTION_12_13_ADMISSION_RATE: PerByteRate = PerByteRate::from_atomic(300);

/// A fee rate: atomic units per byte of transaction weight. A type of its
/// own so that a rate cannot be passed where a leaf count, a depth or a
/// shard count is expected — the functions that take one take several
/// other integers beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PerByteRate(u64);

impl PerByteRate {
    #[must_use]
    pub const fn from_atomic(atomic_per_byte: u64) -> Self {
        Self(atomic_per_byte)
    }

    #[must_use]
    pub const fn atomic(self) -> u64 {
        self.0
    }
}

/// Thousandths in one: the multiplier that leaves a rung unchanged.
const MILLI: u64 = 1_000;

/// The block state a fee is priced at. Every field is a quantity the fold
/// calling this already holds for the same block; nothing here is computed
/// twice.
#[derive(Debug, Clone, Copy)]
pub struct FeePoint<'a> {
    /// `already_generated_coins` entering the block.
    pub already_generated: u64,
    /// The volume operand the fold feeds the burn and the release multiplier.
    pub volume: TxVolume,
    /// The staker emission share at this height, `SCALE` units.
    pub sigma_scaled: u64,
    /// The burn fraction at this block, `SCALE` units.
    pub burn_pct_scaled: u64,
    /// Outputs in the curve tree, which sets the proof size and so the
    /// ordinary transaction's weight.
    pub chain_leaves: u64,
    pub params: &'a EconomicParams,
}

impl FeeModel {
    /// The control arm at the §12.13–§12.14 fee.
    pub const SECTION_12_14_CONTROL: Self = Self::FlatControl {
        per_tx_atomic: SECTION_12_14_FLAT_FEE_ATOMIC,
        admission_rate: SECTION_12_13_ADMISSION_RATE,
    };

    /// What the chain's wallets pay by default: the Standard rung, unscaled.
    pub const PRODUCTION_DEFAULT: Self = Self::ProductionStandard {
        multiplier_milli: MILLI,
        median: MedianModel::PenaltyFreeZone,
    };

    /// The flat fee, if this arm charges one. `None` for an arm whose fee
    /// depends on height — which is every arm but the control.
    #[must_use]
    pub const fn flat_per_tx_atomic(self) -> Option<u64> {
        match self {
            Self::FlatControl { per_tx_atomic, .. } => Some(per_tx_atomic),
            Self::ProductionStandard { .. } => None,
        }
    }

    /// Atomic units one ordinary transaction pays at `at`.
    #[must_use]
    pub fn per_tx_atomic(self, at: &FeePoint<'_>) -> u64 {
        match self {
            Self::FlatControl { per_tx_atomic, .. } => per_tx_atomic,
            Self::ProductionStandard {
                multiplier_milli,
                median,
            } => {
                let fee = ordinary_tx_fee_atomic(ladder_at(median, at).standard, at.chain_leaves);
                u64::try_from(u128::from(fee) * u128::from(multiplier_milli) / u128::from(MILLI))
                    .unwrap_or(u64::MAX)
            }
        }
    }

    /// What admission costs per byte at `at`: the Economy rung, which is the
    /// relay floor. A stuffer pays this and no more — it needs its
    /// transactions relayed, not prioritised — so the multiplier that stands
    /// for what ordinary users pay above the default does not apply to it.
    #[must_use]
    pub fn admission_rate(self, at: &FeePoint<'_>) -> PerByteRate {
        match self {
            Self::FlatControl { admission_rate, .. } => admission_rate,
            Self::ProductionStandard { median, .. } => {
                PerByteRate::from_atomic(ladder_at(median, at).economy)
            }
        }
    }

    /// One line naming the arm, for the head of a report.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::FlatControl { per_tx_atomic, .. } => format!(
                "FEE ARM: CONTROL — flat {:.3} SKL per transaction at every height. A declared \
                 divergence: the chain charges no flat fee (ECONOMICS_SIM_PRODUCTION_REBASE.md §4).",
                per_tx_atomic as f64 / 1.0e9
            ),
            Self::ProductionStandard {
                multiplier_milli,
                median,
            } => format!(
                "FEE ARM: production ladder — Standard rung x{:.3} (corrected_fee_ladder at each \
                 block's R and C), ordinary 1in/2out weight at chain depth, paid unrounded; {}.",
                multiplier_milli as f64 / MILLI as f64,
                match median {
                    MedianModel::PenaltyFreeZone =>
                        "median HELD at the penalty-free zone (declared divergence, ESR-6)",
                }
            ),
        }
    }
}

/// The production ladder at `at`: every rung comes from this one call, so
/// the ordinary fee and the admission rate are priced at the same state by
/// construction.
fn ladder_at(median: MedianModel, at: &FeePoint<'_>) -> FeeLadder {
    // The ladder prices against the reward with the release multiplier taken
    // out (`fee_floor.rs` reads the same operand); the multiplier re-enters
    // through `C`.
    let base_reward = base_block_reward(at.already_generated, at.params)
        .expect("sim neutral trajectory stays within the arithmetic domain");
    let correction = fee_correction(at.volume, at.sigma_scaled, at.burn_pct_scaled, at.params);
    let median = match median {
        MedianModel::PenaltyFreeZone => at.params.full_reward_zone,
    };
    corrected_fee_ladder(base_reward, median, REF_TX_WEIGHT, correction, at.params)
}

/// Fee of one ordinary-shape transaction at `rate_per_byte` when the curve
/// tree holds `chain_leaves` outputs. The fee's own varint is in the weight,
/// so the two are solved together — the two-pass fixpoint the build path
/// runs (`calibration::Shape::tx_weight` is the stuffer's copy of it).
fn ordinary_tx_fee_atomic(rate_per_byte: u64, chain_leaves: u64) -> u64 {
    let (n_in, n_out) = normal_tx_shape();
    let depth = tree_depth_for_leaves(chain_leaves);
    let mut fee = 0u64;
    for _ in 0..2 {
        let weight = predict_weight(n_in, n_out, depth, fee) as u64;
        fee = weight.saturating_mul(rate_per_byte);
    }
    fee
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::{calc_effective_emission_share, relay_fee_floor, FeeCorrection};

    fn point(already_generated: u64, params: &EconomicParams) -> FeePoint<'_> {
        FeePoint {
            already_generated,
            volume: TxVolume::per_block(params.tx_volume_baseline),
            sigma_scaled: 0,
            burn_pct_scaled: 0,
            chain_leaves: 1,
            params,
        }
    }

    /// The production arm is four relay floors times the weight, with
    /// nothing in between. `σ = 0`, `b = 0` and baseline volume make `C = 1`,
    /// so the expected value is `4 × relay_fee_floor` — the Standard rung's
    /// definition (`fee/ladder.rs`), with the floor's owner called on the
    /// other side of the comparison rather than re-derived here.
    #[test]
    fn the_production_arm_is_four_relay_floors_times_the_predicted_weight() {
        let params = EconomicParams::default();
        let at = point(0, &params);
        let base = base_block_reward(0, &params).expect("genesis reward");
        let floor = relay_fee_floor(
            base,
            params.full_reward_zone,
            REF_TX_WEIGHT,
            FeeCorrection::UNITY,
            &params,
        );
        let (n_in, n_out) = normal_tx_shape();
        let paid = FeeModel::PRODUCTION_DEFAULT.per_tx_atomic(&at);
        let weight = predict_weight(n_in, n_out, tree_depth_for_leaves(1), paid) as u64;
        assert_eq!(paid, weight * 4 * floor, "standard = 4 x floor x weight");
    }

    /// The multiplier scales the fee and nothing else: the fact a report's
    /// "x2" column rests on.
    #[test]
    fn the_multiplier_scales_the_fee() {
        let params = EconomicParams::default();
        let at = point(0, &params);
        let arm = |multiplier_milli| FeeModel::ProductionStandard {
            multiplier_milli,
            median: MedianModel::PenaltyFreeZone,
        };
        let standard = arm(MILLI).per_tx_atomic(&at);
        assert_eq!(arm(2 * MILLI).per_tx_atomic(&at), 2 * standard);
        assert_eq!(arm(MILLI / 2).per_tx_atomic(&at), standard / 2);
    }

    /// The property the whole re-base exists for: the production fee follows
    /// the block reward down, and the control does not. A year-30 state
    /// (σ decayed, supply nearly emitted) must charge far less than genesis.
    #[test]
    fn the_production_fee_falls_with_the_reward_and_the_control_does_not() {
        let params = EconomicParams::default();
        let late_generated = params.emission_curve_asymptote / 100 * 98;
        let late_sigma = calc_effective_emission_share(
            30 * shekyl_economics::BLOCKS_PER_YEAR,
            1,
            shekyl_economics::STAKER_EMISSION_SHARE,
            shekyl_economics::STAKER_EMISSION_DECAY,
            shekyl_economics::BLOCKS_PER_YEAR,
        );
        let early = point(0, &params);
        let late = FeePoint {
            sigma_scaled: late_sigma,
            ..point(late_generated, &params)
        };
        let production = FeeModel::PRODUCTION_DEFAULT;
        let (fee_early, fee_late) = (
            production.per_tx_atomic(&early),
            production.per_tx_atomic(&late),
        );
        assert!(
            fee_late * 10 < fee_early,
            "production fee must fall with the reward: early {fee_early}, late {fee_late}"
        );
        let control = FeeModel::SECTION_12_14_CONTROL;
        assert_eq!(control.per_tx_atomic(&early), control.per_tx_atomic(&late));
        assert_eq!(
            control.flat_per_tx_atomic(),
            Some(SECTION_12_14_FLAT_FEE_ATOMIC)
        );
        assert_eq!(production.flat_per_tx_atomic(), None);
    }
}

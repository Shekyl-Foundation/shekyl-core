// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The paid-reward composition: one function, two callers.
//!
//! [`paid_block_reward`], [`compute_emission_split`], [`compute_fee_burn`]
//! and [`advance_already_generated`] each own one step. [`price_emission`]
//! owns the order they run in, so the block template and the validator's
//! derived arm cannot price two figures. The inputs are already derived —
//! a median, a weight, a fee sum, a [`CirculatingSupply`] — and this module
//! reads no chain.
//!
//! # Two genesis arms
//!
//! Height [`GENESIS_HEIGHT`] on [`price_emission`] is the **producer's**
//! arm (CEN-G13): [`paid_block_reward`] runs, and the whole paid reward
//! goes to the miner. [`compute_emission_split`] at height 0 would apply
//! the initial staker share, which neither the producer nor the validator
//! accrues there.
//!
//! The **validator** at genesis does not call [`price_emission`]. The
//! coinbase sum stands (CEN-F11, `validate_miner_transaction` returns
//! before `get_block_reward`). That arm is [`configured_emission`]: no
//! weight bound, no fee split, no staker leg, and the paid reward is the
//! amount the coinbase already carries.

use crate::burn::{compute_fee_burn, BurnSplit};
use crate::emission::{advance_already_generated, paid_block_reward, EmissionError};
use crate::emission_share::{compute_emission_split, EmissionSplit};
use crate::escalation::ClosedShardCount;
use crate::params::EconomicParams;
use crate::supply::CirculatingSupply;
use crate::volume::TxVolume;
use shekyl_units::AtomicUnits;

/// The connecting height at which the producer pays the paid reward whole
/// (CEN-G13). Genesis is height 0 on every issued chain.
pub const GENESIS_HEIGHT: u64 = 0;

/// How many times a producer may re-price a coinbase while its amount's
/// varint changes the block weight.
///
/// The C++ `try_count != 10` (`blockchain.cpp:1830`). One constant: the
/// template and the harness settle loop both read it, so a varint-boundary
/// two-cycle is refused by both producers at the same budget.
pub const REPRICING_PASSES: usize = 10;

/// Operands of [`price_emission`].
///
/// Supply, the fee sum, the median and the block weight are the caller's:
/// a fee the arithmetic cannot sum, and a burned fold above the parent's
/// emission, are refused before this function runs (the validator on
/// CEN-F17 and as a corrupt read; the template as its own errors).
#[derive(Clone, Copy, Debug)]
pub struct EmissionInputs<'a> {
    /// Connecting height. [`GENESIS_HEIGHT`] selects the producer's
    /// whole-to-miner arm.
    pub height: u64,
    /// Effective median weight the penalty is priced against (CEN-G6).
    pub median_weight: u64,
    /// Block weight the penalty is priced at, coinbase included (CEN-F14).
    pub block_weight: u64,
    /// The parent's `already_generated_coins` (zero at genesis).
    pub already_generated: u64,
    /// The volume window the release multiplier reads (CEN-F20).
    pub tx_volume: TxVolume,
    /// Listed bodies' fees, already summed.
    pub total_fees: u64,
    /// Circulating supply the burn ratio reads (CEN-F17).
    pub supply: CirculatingSupply,
    /// Closed transaction-shard count the burn share escalates on (CEN-F17).
    pub closed_shards: ClosedShardCount,
    /// Height the staker share's decay is measured from (CEN-F21).
    pub split_epoch: u64,
    /// The parameter set. A reference: the set is resolved once by the caller.
    pub params: &'a EconomicParams,
}

/// The reward chain's figures for one block.
///
/// Every field is a value the composition had to compute. The validator
/// carries this on the verdict; `connect` records `coins_generated` and
/// [`Self::burned`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidEmission {
    /// The paid (penalised) reward. At the validator's genesis arm, the
    /// configured coinbase total.
    pub paid: AtomicUnits,
    /// The miner and staker legs of `paid`. The coinbase pays
    /// `miner_emission` plus its fee income and nothing else.
    pub split: EmissionSplit,
    /// The listed fees split three ways. All zero where nothing is listed,
    /// including the validator's genesis arm.
    pub fee_burn: BurnSplit,
    /// What the coinbase is held to: `miner_emission + miner_fee_income`.
    pub owed: AtomicUnits,
    /// The staker inflow this block accrues: `staker_emission +
    /// staker_pool_amount`. Zero on both genesis arms.
    pub accrual: AtomicUnits,
    /// `already_generated_coins` through this block: the parent's plus
    /// `paid`, saturating as [`advance_already_generated`] saturates.
    pub coins_generated: AtomicUnits,
}

impl PaidEmission {
    /// This block's destroyed amount — the fee split's `actually_destroyed`.
    #[must_use]
    pub const fn burned(&self) -> AtomicUnits {
        AtomicUnits::from_raw(self.fee_burn.actually_destroyed)
    }
}

/// Arithmetic the composition cannot form.
///
/// Each arm is a consensus refusal for the caller that maps it: the
/// validator onto its census row, the template onto the error its callers
/// already match. None of them is a view fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RewardArithmetic {
    /// The block is heavier than twice the effective median.
    #[error("block weight exceeds twice the effective median")]
    BlockTooBig,
    /// [`paid_block_reward`] overflowed.
    #[error("the paid reward's arithmetic overflowed")]
    RewardOverflow,
    /// `miner_emission + miner_fee_income` does not fit `u64`.
    #[error("miner emission plus miner fee income overflows u64")]
    OwedOverflow,
    /// `staker_emission + staker_pool_amount` does not fit `u64`.
    ///
    /// Each leg is bounded by the paid reward or the fees; the sum of the
    /// two bounds is not, so the addition is checked.
    #[error("staker emission plus staker pool overflows u64")]
    AccrualOverflow,
}

impl RewardArithmetic {
    /// The two arms that are [`paid_block_reward`]'s own errors, so a
    /// caller that already surfaces [`EmissionError`] can keep that type.
    #[must_use]
    pub const fn emission_error(self) -> Option<EmissionError> {
        match self {
            Self::BlockTooBig => Some(EmissionError::BlockTooBig),
            Self::RewardOverflow => Some(EmissionError::Overflow),
            Self::OwedOverflow | Self::AccrualOverflow => None,
        }
    }
}

/// Price the block's emission from derived operands.
///
/// At [`GENESIS_HEIGHT`] the paid reward goes whole to the miner. Above it
/// the reward is split from `split_epoch`. The fee burn runs at every
/// height, including genesis: a producer listing nothing passes a zero fee
/// sum and the three burn legs are zero.
///
/// # Errors
///
/// [`RewardArithmetic`]: the weight bound, an overflow in the paid reward,
/// or an owed or accrual sum that does not fit.
pub fn price_emission(inputs: &EmissionInputs<'_>) -> Result<PaidEmission, RewardArithmetic> {
    let paid = paid_block_reward(
        inputs.median_weight,
        inputs.block_weight,
        inputs.already_generated,
        inputs.tx_volume,
        inputs.params,
    )
    .map_err(|err| match err {
        EmissionError::BlockTooBig => RewardArithmetic::BlockTooBig,
        EmissionError::Overflow => RewardArithmetic::RewardOverflow,
    })?;
    let split = if inputs.height == GENESIS_HEIGHT {
        EmissionSplit {
            miner_emission: paid,
            staker_emission: 0,
        }
    } else {
        compute_emission_split(paid, inputs.height, inputs.split_epoch)
    };
    let fee_burn = compute_fee_burn(
        inputs.total_fees,
        inputs.tx_volume,
        inputs.supply,
        inputs.closed_shards,
        inputs.params,
    );
    let owed = split
        .miner_emission
        .checked_add(fee_burn.miner_fee_income)
        .ok_or(RewardArithmetic::OwedOverflow)?;
    let accrual = split
        .staker_emission
        .checked_add(fee_burn.staker_pool_amount)
        .ok_or(RewardArithmetic::AccrualOverflow)?;
    Ok(PaidEmission {
        paid: AtomicUnits::from_raw(paid),
        split,
        fee_burn,
        owed: AtomicUnits::from_raw(owed),
        accrual: AtomicUnits::from_raw(accrual),
        coins_generated: AtomicUnits::from_raw(advance_already_generated(
            inputs.already_generated,
            paid,
        )),
    })
}

/// The validator's genesis emission: `configured` is the coinbase sum and
/// stands whole (CEN-F11).
///
/// No weight bound, no fee split, no staker leg. Infallible: the owed
/// figure is `configured` itself and the accrual is zero.
#[must_use]
pub fn configured_emission(configured: u64, already_generated: u64) -> PaidEmission {
    PaidEmission {
        paid: AtomicUnits::from_raw(configured),
        split: EmissionSplit {
            miner_emission: configured,
            staker_emission: 0,
        },
        fee_burn: BurnSplit {
            miner_fee_income: 0,
            staker_pool_amount: 0,
            actually_destroyed: 0,
        },
        owed: AtomicUnits::from_raw(configured),
        accrual: AtomicUnits::ZERO,
        coins_generated: AtomicUnits::from_raw(advance_already_generated(
            already_generated,
            configured,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission_share::compute_emission_split;

    /// The shipped split epoch. Chain-rules names it `EMISSION_SPLIT_EPOCH`;
    /// this crate takes the height as data.
    const SHIPPED_SPLIT_EPOCH: u64 = 1;

    fn inputs(params: &EconomicParams, height: u64, total_fees: u64) -> EmissionInputs<'_> {
        let supply = CirculatingSupply::derive(AtomicUnits::ZERO, AtomicUnits::ZERO)
            .expect("zero burn does not exceed zero emission");
        EmissionInputs {
            height,
            median_weight: params.full_reward_zone,
            block_weight: params.full_reward_zone,
            already_generated: 0,
            tx_volume: TxVolume::ZERO,
            total_fees,
            supply,
            closed_shards: ClosedShardCount::ZERO,
            split_epoch: SHIPPED_SPLIT_EPOCH,
            params,
        }
    }

    #[test]
    fn the_producer_pays_genesis_whole_and_the_split_function_does_not() {
        let params = EconomicParams::default();
        let whole = price_emission(&inputs(&params, GENESIS_HEIGHT, 0)).expect("under the median");
        assert_eq!(whole.split.miner_emission, whole.paid.to_raw());
        assert_eq!(whole.split.staker_emission, 0);
        assert_eq!(whole.owed, whole.paid);
        assert_eq!(whole.accrual, AtomicUnits::ZERO);
        assert_eq!(whole.coins_generated, whole.paid);
        assert_eq!(whole.burned(), AtomicUnits::ZERO);
        // The defect the arm exists to close: `compute_emission_split` at
        // height 0 applies the initial share. The producer must not.
        let shared =
            compute_emission_split(whole.paid.to_raw(), GENESIS_HEIGHT, SHIPPED_SPLIT_EPOCH);
        assert_ne!(whole.split, shared);
        assert!(shared.staker_emission > 0);

        let later =
            price_emission(&inputs(&params, SHIPPED_SPLIT_EPOCH, 0)).expect("under the median");
        assert_eq!(later.paid, whole.paid);
        assert!(later.split.staker_emission > 0);
        assert!(later.split.miner_emission < later.paid.to_raw());
    }

    #[test]
    fn the_configured_arm_stands_the_coinbase_and_does_not_reprice_it() {
        let stood = configured_emission(50, 7);
        assert_eq!(stood.paid.to_raw(), 50);
        assert_eq!(stood.split.staker_emission, 0);
        assert_eq!(stood.owed.to_raw(), 50);
        assert_eq!(stood.accrual, AtomicUnits::ZERO);
        assert_eq!(stood.coins_generated.to_raw(), 57);
        assert_eq!(stood.burned(), AtomicUnits::ZERO);
    }

    #[test]
    fn a_block_over_twice_the_median_is_the_weight_bound() {
        let params = EconomicParams::default();
        let mut over = inputs(&params, SHIPPED_SPLIT_EPOCH, 0);
        over.block_weight = params
            .full_reward_zone
            .checked_mul(2)
            .expect("the zone fits")
            .checked_add(1)
            .expect("the bound fits");
        assert_eq!(price_emission(&over), Err(RewardArithmetic::BlockTooBig));
        assert_eq!(
            RewardArithmetic::BlockTooBig.emission_error(),
            Some(EmissionError::BlockTooBig)
        );
    }

    #[test]
    fn a_fee_the_miner_cannot_be_paid_beside_the_emission_is_owed_overflow() {
        let params = EconomicParams::default();
        // Zero volume burns nothing, so the miner is owed every fee. The
        // paid reward is non-zero under the median, and the sum does not fit.
        let err =
            price_emission(&inputs(&params, GENESIS_HEIGHT, u64::MAX)).expect_err("overflows");
        assert_eq!(err, RewardArithmetic::OwedOverflow);
        assert!(err.emission_error().is_none());
    }

    #[test]
    fn the_repricing_budget_is_the_cpp_try_count() {
        assert_eq!(REPRICING_PASSES, 10);
    }
}

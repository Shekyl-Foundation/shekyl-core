// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The economics of the chain at its tip, as one projection.
//!
//! A status reader — the daemon's `get_info` — wants the same handful of
//! figures consensus derives from the same operands: how fast the curve is
//! releasing, what the next coinbase burns, what share of emission goes to
//! stakers. It should not assemble them from parts, because the assembling
//! is where two readers come to disagree. [`project_at_tip`] is the one
//! place those figures are put together
//! (`docs/design/DAEMON_RPC_KV_GET_INFO.md` §4.3, RK-D19).
//!
//! The projection decides nothing about how its result is shown. In
//! particular a broken supply invariant is returned as the violation it is,
//! not folded into a number.

use shekyl_units::AtomicUnits;

use crate::burn::calc_burn_pct_at;
use crate::emission_share::emission_share_at;
use crate::params::EconomicParams;
use crate::release::calc_release_multiplier;
use crate::supply::{CirculatingSupply, SupplyInvariantViolation};
use crate::volume::TxVolume;

/// What the store says at the tip: the operands of [`project_at_tip`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipOperands {
    /// Gross coins emitted through the tip.
    pub coins_generated: AtomicUnits,
    /// Cumulative coins destroyed through the tip.
    pub total_burned: AtomicUnits,
    /// The trailing transaction-volume window ending at the tip.
    pub tx_volume: TxVolume,
    /// The chain count: the top block's height plus one, which is the
    /// height of the block the figures apply to.
    pub chain_height: u64,
}

/// The economics at the tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipEconomics {
    /// Gross coins emitted through the tip, as given.
    pub coins_generated: AtomicUnits,
    /// Cumulative coins destroyed through the tip, as given.
    pub total_burned: AtomicUnits,
    /// The release-rate multiplier, fixed-point at `SCALE`.
    pub release_multiplier: u64,
    /// The percentage the next coinbase burns, fixed-point at `SCALE`, over
    /// the derived circulating supply.
    ///
    /// `Err` when more has been burned than generated: the store has
    /// contradicted itself, and there is no percentage to report.
    pub burn_pct: Result<u64, SupplyInvariantViolation>,
    /// The staker emission share at [`TipOperands::chain_height`],
    /// fixed-point at `SCALE`.
    pub staker_emission_share: u64,
}

/// Project the economics at the tip from the store's operands and `params`.
#[must_use]
pub fn project_at_tip(operands: &TipOperands, params: &EconomicParams) -> TipEconomics {
    let release_multiplier = calc_release_multiplier(
        operands.tx_volume,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    let burn_pct = CirculatingSupply::derive(operands.coins_generated, operands.total_burned)
        .map(|supply| calc_burn_pct_at(operands.tx_volume, supply, params));
    TipEconomics {
        coins_generated: operands.coins_generated,
        total_burned: operands.total_burned,
        release_multiplier,
        burn_pct,
        staker_emission_share: emission_share_at(operands.chain_height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands() -> TipOperands {
        TipOperands {
            coins_generated: AtomicUnits::from_raw(1_444_065_674_085_133),
            total_burned: AtomicUnits::from_raw(4_200_000_000),
            tx_volume: TxVolume::window(6000, 100),
            chain_height: 1_234_567,
        }
    }

    /// The figures the C++ `get_info` handler computed from these operands,
    /// captured in `get_info_synced_v1.json`. The handler called three
    /// boundary functions; this is the same three results from one call.
    #[test]
    fn projects_the_figures_the_handler_reported() {
        let tip = project_at_tip(&operands(), &EconomicParams::default());
        assert_eq!(tip.release_multiplier, 1_200_000);
        assert_eq!(tip.burn_pct, Ok(184));
        assert_eq!(tip.staker_emission_share, 91_549);
        assert_eq!(tip.coins_generated, operands().coins_generated);
        assert_eq!(tip.total_burned, operands().total_burned);
    }

    /// Each figure is the function consensus calls, not a restatement of it.
    #[test]
    fn each_figure_is_its_consensus_function() {
        let op = operands();
        let params = EconomicParams::default();
        let tip = project_at_tip(&op, &params);
        assert_eq!(
            tip.release_multiplier,
            calc_release_multiplier(
                op.tx_volume,
                params.tx_volume_baseline,
                params.release_min,
                params.release_max
            )
        );
        let supply = CirculatingSupply::derive(op.coins_generated, op.total_burned).unwrap();
        assert_eq!(
            tip.burn_pct,
            Ok(calc_burn_pct_at(op.tx_volume, supply, &params))
        );
        assert_eq!(
            tip.staker_emission_share,
            emission_share_at(op.chain_height)
        );
    }

    /// More burned than generated is returned as the violation, carrying
    /// both operands, and the other figures are still projected.
    #[test]
    fn a_broken_supply_invariant_is_returned_not_folded_into_a_number() {
        let mut op = operands();
        op.total_burned = AtomicUnits::from_raw(op.coins_generated.to_raw() + 1);
        let tip = project_at_tip(&op, &EconomicParams::default());
        let violation = tip.burn_pct.expect_err("the supply invariant is broken");
        assert_eq!(violation.coins_generated, op.coins_generated);
        assert_eq!(violation.total_burned, op.total_burned);
        assert_eq!(tip.release_multiplier, 1_200_000);
        assert_eq!(tip.staker_emission_share, 91_549);
    }

    /// Burned exactly equal to generated is a supply of zero, not a
    /// violation.
    #[test]
    fn burned_equal_to_generated_is_a_supply_of_zero() {
        let mut op = operands();
        op.total_burned = op.coins_generated;
        assert!(project_at_tip(&op, &EconomicParams::default())
            .burn_pct
            .is_ok());
    }
}

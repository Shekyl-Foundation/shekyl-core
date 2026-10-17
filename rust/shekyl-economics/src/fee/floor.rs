// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay floor and the served ladder from one block's operands: the
//! one composition of `σ`, `b`, `C`, `R` and `F`.
//!
//! `FEE_LADDER_DERIVATION.md` §11.6 ("economics" item) and PR C §6. The
//! daemon's estimate and its relay floor used to be composed in C++
//! (`relay_floor_at` / `fee_correction_from` in `relay_floor_ring.cpp`)
//! out of four Rust calls, and that composition priced the burn on
//! **gross** `already_generated_coins` where the validator prices it on
//! the **net** circulating supply (FL-R16c): the floor's `b`, and so its
//! `C`, differed from what the miner is paid as soon as anything had
//! burned, and the FL-V1 identity was broken in the C++. Here there is
//! one composition, and its supply operand is the validator's
//! [`CirculatingSupply`].
//!
//! The operands are a block's chain state: its height, the parent's gross
//! emission, the derived circulating supply, the volume window and the
//! long-term effective median in force for it. `shekyl-chain-rules`
//! reads them off a `ChainView` (`relay_floor_at`, `relay_floor_window`);
//! this module does not know where they came from.

use super::correction::{fee_correction, FeeCorrection};
use super::ladder::{checked_corrected_fee_ladder, FeeLadder};
use super::relay::checked_relay_fee_floor;
use crate::burn::calc_burn_pct_at;
use crate::emission::base_block_reward;
use crate::emission_share::emission_share_at;
use crate::params::EconomicParams;
use crate::release::calc_release_multiplier;
use crate::supply::CirculatingSupply;
use crate::volume::TxVolume;

/// Reference transaction weight `w_ref` the floor and every rung fold in.
///
/// The basis question (FL-R13) is EUP-5 G's. Until that ruling derives the
/// weight from a Shekyl ordinary transaction, the value is the inherited
/// 3 000. The FFI entries, the wallet's absolute cap and the economics sim
/// read this constant. The scalar entries stay parameterized, so a domain
/// test can pass `0` and `u64::MAX`.
pub const RELAY_FLOOR_REFERENCE_TX_WEIGHT: u64 = 3_000;

/// One block's fee operands: the chain state the floor and the ladder at
/// that block are a function of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeOperands {
    /// The block's height — `σ`'s operand (`emission_share_at`).
    pub height: u64,
    /// The parent's gross emission (`block_info.coins_generated` at
    /// `height − 1`; zero at genesis) — `R`'s operand.
    pub parent_coins_generated: u64,
    /// The circulating supply at parent state — `b`'s operand, derived by
    /// its one owner and never a caller's choice of numerator (FL-R16c).
    pub supply: CirculatingSupply,
    /// CEN-F20's volume window at the block — `M_r`'s and `b`'s operand.
    pub tx_volume: TxVolume,
    /// The long-term effective median in force for the block — `M`.
    pub long_term_effective_median: u64,
}

/// `σ`, `b`, `M_r` and the `C` they compose, from the owners.
///
/// `C` does not read a median, and it reads the parent's coins only
/// through [`CirculatingSupply`]. A caller that has no median does not
/// invent one to ask for `C`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionFactors {
    /// `M_r` in [`crate::params::SCALE`] units.
    pub release_multiplier: u64,
    /// `b` in [`crate::params::SCALE`] units, on the derived supply.
    pub burn_pct: u64,
    /// `σ` in [`crate::params::SCALE`] units, at the height.
    pub emission_share: u64,
    /// `C = (1−σ)·M_r/(1−b)`.
    pub correction: FeeCorrection,
}

/// The one composition of the correction factors.
///
/// [`fee_correction`] recomputes `M_r` from this same volume and these
/// same release rails, so the reported multiplier and `correction` cannot
/// be two formulas.
#[must_use]
pub fn correction_factors_at(
    height: u64,
    supply: CirculatingSupply,
    tx_volume: TxVolume,
    params: &EconomicParams,
) -> CorrectionFactors {
    let emission_share = emission_share_at(height);
    let burn_pct = calc_burn_pct_at(tx_volume, supply, params);
    let release_multiplier = calc_release_multiplier(
        tx_volume,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    CorrectionFactors {
        release_multiplier,
        burn_pct,
        emission_share,
        correction: fee_correction(tx_volume, emission_share, burn_pct, params),
    }
}

/// Raw `C` at the operands: [`correction_factors_at`]'s `correction`.
#[must_use]
pub fn fee_correction_at(operands: FeeOperands, params: &EconomicParams) -> FeeCorrection {
    correction_factors_at(operands.height, operands.supply, operands.tx_volume, params).correction
}

/// The M_r-neutral base reward at the operands: `max(curve(remaining),
/// TAIL)` on the parent's accumulator (FL-R12′). `M_r` lives inside `C`.
/// `None` only when the parameters cannot price the tail.
fn base_reward_at(operands: FeeOperands, params: &EconomicParams) -> Option<u64> {
    base_block_reward(operands.parent_coins_generated, params).ok()
}

/// The relay floor at the operands: `F = R·C·w_ref/M²`, floored at 1
/// ([`checked_relay_fee_floor`]). `None` when the parameters cannot price
/// the tail or the scalars leave the `u128` domain.
#[must_use]
pub fn relay_floor_from(operands: FeeOperands, params: &EconomicParams) -> Option<u64> {
    checked_relay_fee_floor(
        base_reward_at(operands, params)?,
        operands.long_term_effective_median,
        RELAY_FLOOR_REFERENCE_TX_WEIGHT,
        fee_correction_at(operands, params),
        params,
    )
}

/// The served three-rung ladder at the same operands. Its economy rung
/// is [`relay_floor_from`]'s value by construction (FL-R6): one
/// derivation serves the quote and admits against it.
#[must_use]
pub fn fee_ladder_from(operands: FeeOperands, params: &EconomicParams) -> Option<FeeLadder> {
    checked_corrected_fee_ladder(
        base_reward_at(operands, params)?,
        operands.long_term_effective_median,
        RELAY_FLOOR_REFERENCE_TX_WEIGHT,
        fee_correction_at(operands, params),
        params,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::{projected_already_generated, tail_subsidy_per_block};
    use crate::params::{BLOCKS_PER_YEAR, FULL_REWARD_ZONE, SCALE};
    use shekyl_units::AtomicUnits;

    fn operands(
        height: u64,
        parent_coins: u64,
        burned: u64,
        tx_volume: TxVolume,
        median: u64,
    ) -> FeeOperands {
        FeeOperands {
            height,
            parent_coins_generated: parent_coins,
            supply: CirculatingSupply::derive(
                AtomicUnits::from_raw(parent_coins),
                AtomicUnits::from_raw(burned),
            )
            .expect("burned ≤ generated"),
            tx_volume,
            long_term_effective_median: median,
        }
    }

    /// The §1.8 grid: the registered ages on the projected trajectory, at
    /// the registered volumes and medians, `C` raw. Pinned from the code;
    /// a parameter change moves these loudly.
    #[test]
    fn the_floor_at_the_registered_grid() {
        let p = EconomicParams::default();
        let zone = FULL_REWARD_ZONE;
        let at = |age: u64, v: u64, median: u64| {
            let height = age * BLOCKS_PER_YEAR;
            let ag = projected_already_generated(height, &p).expect("projected");
            relay_floor_from(operands(height, ag, 0, TxVolume::per_block(v), median), &p)
                .expect("priced")
        };
        // Genesis: σ = 0, R₀ = 1 024 SKL, C = 1 at the baseline, so
        // F = R₀·w_ref/Zm² = 34 133.
        assert_eq!(at(0, 50, zone), 34_133);
        // Genesis, quiet: M_r at its low rail, C = 0.8.
        assert_eq!(at(0, 0, zone), 27_306);
        // Year 1 congested (v = 200), year 12 quiet (v = 5), year 12
        // congested at 3·Zm, year 30 at 10·Zm and v = 500 — the
        // `--fee-ladder` rung tables' economy rungs.
        assert_eq!(at(1, 200, zone), 38_382);
        assert_eq!(at(12, 5, zone), 13_453);
        assert_eq!(at(12, 200, 3 * zone), 4_721);
        assert_eq!(at(30, 500, 10 * zone), 672);
    }

    /// The §4.6 degenerates, pinned: at exhaustion `R` is the tail (600 SKL
    /// per block), `σ` is a tenth of a percent, and the floor at the zone
    /// is tens of atomic units per byte; a wide median truncates it to the
    /// `max(1)` floor; a median below the zone is floored to the zone.
    #[test]
    fn the_floor_at_the_degenerates() {
        let p = EconomicParams::default();
        let s = p.emission_curve_asymptote;
        let height = 80 * BLOCKS_PER_YEAR;
        assert_eq!(
            tail_subsidy_per_block(&p).expect("tail"),
            600_000_000,
            "the tail the degenerates price on"
        );
        let at = |v: u64, median: u64| operands(height, s, 0, TxVolume::per_block(v), median);
        // Baseline volume at the zone: C ≈ 2.0 (b ≈ 0.5 at the saturated
        // supply ratio, M_r = 1, σ ≈ 0), F = 39.
        assert_eq!(
            fee_correction_at(at(50, FULL_REWARD_ZONE), &p).as_scaled(),
            1_999_942
        );
        assert_eq!(relay_floor_from(at(50, FULL_REWARD_ZONE), &p), Some(39));
        assert_eq!(
            fee_ladder_from(at(50, FULL_REWARD_ZONE), &p).map(FeeLadder::as_slots),
            Some([39, 156, 7_999])
        );
        // Quiet: M_r at its low rail, no burn, C = 0.8, F = 15.
        assert_eq!(
            fee_correction_at(at(0, FULL_REWARD_ZONE), &p).as_scaled(),
            799_976
        );
        assert_eq!(relay_floor_from(at(0, FULL_REWARD_ZONE), &p), Some(15));
        // Congested: M_r at its high rail and b at its cap, C = 13.0, F = 259.
        assert_eq!(
            fee_correction_at(at(500, FULL_REWARD_ZONE), &p).as_scaled(),
            12_999_623
        );
        assert_eq!(relay_floor_from(at(500, FULL_REWARD_ZONE), &p), Some(259));
        // Wider medians: 3·Zm truncates to 4, 10·Zm to the `max(1)` floor,
        // and a median no block can carry still answers 1.
        assert_eq!(relay_floor_from(at(50, 3 * FULL_REWARD_ZONE), &p), Some(4));
        assert_eq!(relay_floor_from(at(50, 10 * FULL_REWARD_ZONE), &p), Some(1));
        assert_eq!(
            relay_floor_from(at(50, 100_000 * FULL_REWARD_ZONE), &p),
            Some(1)
        );
        // A median below the zone is floored to it.
        assert_eq!(
            relay_floor_from(operands(0, 0, 0, TxVolume::per_block(50), 1), &p),
            relay_floor_from(
                operands(0, 0, 0, TxVolume::per_block(50), FULL_REWARD_ZONE),
                &p
            ),
        );
    }

    /// The economy rung is the floor at the same operands: one derivation
    /// serves and admits (FL-R6 as an identity).
    #[test]
    fn the_ladders_economy_rung_is_the_floor() {
        let p = EconomicParams::default();
        for (age, v, median, burned_permille) in [
            (0u64, 50u64, FULL_REWARD_ZONE, 0u64),
            (4, 200, 3 * FULL_REWARD_ZONE, 5),
            (12, 5, FULL_REWARD_ZONE, 50),
            (30, 500, 10 * FULL_REWARD_ZONE, 100),
        ] {
            let height = age * BLOCKS_PER_YEAR;
            let ag = projected_already_generated(height, &p).expect("projected");
            let ops = operands(
                height,
                ag,
                ag / 1000 * burned_permille,
                TxVolume::per_block(v),
                median,
            );
            let ladder = fee_ladder_from(ops, &p).expect("priced");
            assert_eq!(Some(ladder.economy), relay_floor_from(ops, &p));
            assert_eq!(ladder.standard, 4 * ladder.economy);
        }
    }

    /// The supply operand is the NET supply: a burned total lowers `b`
    /// and so lowers `C` and the floor, where the gross operand the C++
    /// composition used would have left both where they were (FL-R16c).
    #[test]
    fn the_burn_is_priced_on_the_net_supply() {
        let p = EconomicParams::default();
        let height = 12 * BLOCKS_PER_YEAR;
        let ag = projected_already_generated(height, &p).expect("projected");
        let volume = TxVolume::per_block(200);
        let gross = operands(height, ag, 0, volume, FULL_REWARD_ZONE);
        let net = operands(height, ag, ag / 10, volume, FULL_REWARD_ZONE);
        let c_gross = fee_correction_at(gross, &p);
        let c_net = fee_correction_at(net, &p);
        assert!(
            c_net < c_gross,
            "a tenth of the emission burned lowers the burn ratio's operand, so b falls and C with it"
        );
        assert!(relay_floor_from(net, &p) < relay_floor_from(gross, &p));
        // The factors are that composition, not a second one: `C` at a
        // zero burn is `fee_correction` of the same three owners.
        let factors = correction_factors_at(height, gross.supply, volume, &p);
        assert_eq!(factors.emission_share, emission_share_at(height));
        assert_eq!(factors.burn_pct, calc_burn_pct_at(volume, gross.supply, &p));
        assert_eq!(
            factors.release_multiplier,
            crate::calc_release_multiplier(
                volume,
                p.tx_volume_baseline,
                p.release_min,
                p.release_max,
            )
        );
        assert_eq!(factors.correction, c_gross);
        assert_eq!(
            correction_factors_at(height, net.supply, volume, &p).correction,
            c_net
        );
        assert_eq!(
            c_gross,
            fee_correction(
                volume,
                emission_share_at(height),
                calc_burn_pct_at(volume, gross.supply, &p).min(SCALE),
                &p
            )
        );
    }
}

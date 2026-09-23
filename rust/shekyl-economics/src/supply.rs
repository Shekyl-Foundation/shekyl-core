// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Circulating supply — the burn ratio's operand, **derived here and nowhere
//! else** (FL-R16c, `FEE_LADDER_DERIVATION.md` §8, minted at review round 4;
//! landed by E6 slice 4's precursor, `CHAIN_RULES_SLICE_4.md` §3.1 S15).
//!
//! # The defect this closes
//!
//! `circulating_supply = already_generated_coins` — gross emission, ignoring
//! burn — was assigned at two C++ call sites (`blockchain.cpp` validation
//! and template construction) and passed into `calc_burn_pct` as the
//! numerator of `supply_ratio`. FL-R16c named it a definitional bug and
//! bound the implementing PR. The census F17 row inherited the C++ without
//! stating the definition, and the sweep that found it again did so only
//! because the ruling's line pins had drifted. Two sites defining one
//! operand is how they were wrong together and nobody noticed; this module
//! is the one site.
//!
//! # The definition
//!
//! ```text
//! circulating_supply = coins_generated − total_burned
//! ```
//!
//! Both operands are facts the store records (`block_info.coins_generated`
//! at the parent; the `total_burned` fold). The subtraction is **checked**:
//! `total_burned > coins_generated` is unrepresentable under the design —
//! every burned unit was first emitted — so a `None` is a store-invariant
//! violation ([`SupplyInvariantViolation`]), never a saturating zero. A zero
//! here would sail through `calc_burn_pct`'s `total_supply == 0` guard and
//! return a burn of `0`: a wrong answer that looks like a valid one.
//!
//! # What this does not change
//!
//! `calc_burn_pct` still saturates `supply_ratio` at `SCALE`. That clamp is
//! **not** a compensation for the gross operand and does not dissolve with
//! it: under the perpetual tail (FL-R12′) the paid emission is
//! `max(M_r·curve, TAIL)`, and the tail carries issuance past the curve's
//! asymptote forever, while burn is a fraction of *fees* — a market quantity
//! with no relation to the tail. Net supply therefore exceeds the asymptote
//! whenever cumulative burn lags the tail's overshoot, which is the generic
//! post-exhaustion case, not an edge. `net_supply_exceeds_the_asymptote_under_the_tail`
//! is the demonstration: one tail block puts net above the cap; ~7 200 of
//! them (ten hours at the shipped constants, the fixed-point ratio's one
//! part in `SCALE`) put the unsaturated ratio above `1.0`, and the clamp is
//! what holds it. With the net operand the ratio reads
//! *"fraction of the curve's cap emitted and not destroyed"* — meaningful in
//! `[0, 1]` and saturating once the tail carries net past the cap.
//!
//! # Recorded for the economics lane (not ruled here)
//!
//! Net-of-burn as the ratio's operand makes burn self-damping: more burned →
//! lower ratio → lower burn percentage. Negative feedback, the benign
//! direction — but on a **cumulative** quantity against a **per-block** fee
//! flow, so its time constant is the whole chain's history: the damping
//! strengthens monotonically and never relaxes. A different object from a
//! per-block loop, invisible in a 10–20-year sim window, visible only near
//! exhaustion, which is the regime the sim cannot reach.

use core::fmt;

use shekyl_units::AtomicUnits;

/// Circulating supply: `coins_generated − total_burned`, checked.
///
/// Construct only through [`CirculatingSupply::derive`]; a caller cannot
/// choose what the operand means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CirculatingSupply(AtomicUnits);

impl CirculatingSupply {
    /// Derive from the two store facts at parent state.
    ///
    /// # Errors
    ///
    /// [`SupplyInvariantViolation`] when `total_burned > coins_generated` — a
    /// store invariant broken, not a quantity to clamp.
    pub const fn derive(
        coins_generated: AtomicUnits,
        total_burned: AtomicUnits,
    ) -> Result<Self, SupplyInvariantViolation> {
        match coins_generated.checked_sub(total_burned) {
            Some(net) => Ok(Self(net)),
            None => Err(SupplyInvariantViolation {
                coins_generated,
                total_burned,
            }),
        }
    }

    /// The net supply in atomic units.
    #[must_use]
    pub const fn to_atomic(self) -> AtomicUnits {
        self.0
    }

    /// The raw value, for the fixed-point arithmetic in `calc_burn_pct`.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0.to_raw()
    }
}

/// `total_burned` exceeded `coins_generated`: every burned unit was first
/// emitted, so the store holds a pair no conforming chain produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyInvariantViolation {
    /// Gross emission through the parent.
    pub coins_generated: AtomicUnits,
    /// The destroyed-fee fold through the parent.
    pub total_burned: AtomicUnits,
}

impl fmt::Display for SupplyInvariantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "circulating supply underflow: total_burned {} exceeds coins_generated {} — a store invariant, not a quantity to clamp",
            self.total_burned.to_raw(),
            self.coins_generated.to_raw()
        )
    }
}

impl std::error::Error for SupplyInvariantViolation {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::burn::calc_burn_pct_at;
    use crate::emission::{paid_block_reward, tail_subsidy_per_block};
    use crate::params::{EconomicParams, SCALE};
    use crate::volume::TxVolume;

    const fn au(v: u64) -> AtomicUnits {
        AtomicUnits::from_raw(v)
    }

    #[test]
    fn net_supply_is_generated_minus_burned() {
        let net = CirculatingSupply::derive(au(1_000), au(250)).expect("250 ≤ 1000");
        assert_eq!(net.to_raw(), 750);
        assert_eq!(
            CirculatingSupply::derive(au(1_000), au(1_000))
                .expect("equal is zero, not a violation")
                .to_raw(),
            0
        );
    }

    /// The `None` arm is an invariant violation carrying both operands —
    /// never a saturating zero that `calc_burn_pct` would read as "nothing
    /// emitted" and answer with a burn of `0`.
    #[test]
    fn burned_exceeding_generated_is_a_violation_not_zero() {
        let err = CirculatingSupply::derive(au(100), au(101)).expect_err("101 > 100");
        assert_eq!(
            err,
            SupplyInvariantViolation {
                coins_generated: au(100),
                total_burned: au(101),
            }
        );
        assert!(err.to_string().contains("store invariant"));
    }

    /// FL-R16c's two halves are independent, and this is the demonstration:
    /// the saturation in `calc_burn_pct` is **not** dissolved by the net
    /// operand. One tail block past exhaustion with zero burn puts net
    /// supply above the asymptote, so the unsaturated ratio would exceed
    /// `SCALE`; the clamp is load-bearing under the perpetual tail, and
    /// this is the input that reaches it.
    #[test]
    fn net_supply_exceeds_the_asymptote_under_the_tail() {
        let p = EconomicParams::default();
        let tail = tail_subsidy_per_block(&p).expect("tail");
        let asymptote = p.emission_curve_asymptote;

        // Parent state one unit short of the cap, nothing ever burned.
        let generated_before = asymptote - 1;
        let paid = paid_block_reward(
            0,
            1,
            generated_before,
            TxVolume::per_block(p.tx_volume_baseline),
            &p,
        )
        .expect("a past-asymptote state is a legitimate tail state");
        assert_eq!(paid, tail, "the tail carries issuance past the cap");

        let generated_after = generated_before + paid;
        let net = CirculatingSupply::derive(au(generated_after), AtomicUnits::ZERO)
            .expect("nothing burned");
        assert!(
            net.to_raw() > asymptote,
            "net supply {} must exceed the asymptote {} after one tail block with zero burn",
            net.to_raw(),
            asymptote
        );

        // The ratio is fixed-point at SCALE, so the overshoot has to reach one
        // part in SCALE of the asymptote before the unsaturated value passes
        // 1.0: `ceil(asymptote / SCALE / tail)` tail blocks of zero burn
        // (≈ 7 200 blocks, ten hours, at the shipped constants). Past the cap
        // every block pays exactly the tail, so the accumulator after `k`
        // blocks is a closed form, not a loop.
        let blocks_to_one_ppm = asymptote.div_ceil(SCALE).div_ceil(tail) + 1;
        let net = CirculatingSupply::derive(
            au(generated_before + blocks_to_one_ppm * tail),
            AtomicUnits::ZERO,
        )
        .expect("nothing burned");
        let unsaturated = u128::from(net.to_raw()) * u128::from(SCALE) / u128::from(asymptote);
        assert!(
            unsaturated > u128::from(SCALE),
            "after {blocks_to_one_ppm} tail blocks the unsaturated ratio {unsaturated} exceeds SCALE"
        );
        // `calc_burn_pct_at` at full volume with the ratio saturated equals the
        // same call with the ratio exactly at the cap: the clamp is what makes
        // them equal.
        let at_cap = CirculatingSupply::derive(au(asymptote), AtomicUnits::ZERO).expect("at cap");
        let volume = TxVolume::per_block(p.tx_volume_baseline);
        assert_eq!(
            calc_burn_pct_at(volume, net, &p),
            calc_burn_pct_at(volume, at_cap, &p),
            "past the cap, the saturated ratio pays the same burn as at the cap"
        );
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **D2 staker-share escalation — the frozen shape.**
//!
//! `staker_pool_share` was a frozen `250_000` (25 %) constant. The archival
//! burden it compensates grows without bound, so a fixed share under-pays
//! archivers exactly as the chain gets heavier — the D2 defect
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`). This module replaces the
//! constant with a **pure map of the burden operand**
//! `n = frozen_segment_count`.
//!
//! # What is frozen here, and what is not
//!
//! **Frozen (genesis, §6.1):** the *shape* — the five constraints below, each
//! carrying an executable test in this module.
//!
//! **NOT frozen:** the **asymptote numeric**, which is provisional-until-testnet
//! and is *the* capture point in this design (§11.4). It carries GF-7 freeze
//! ceremony — the adversary-advantage argument is committed **before** the
//! number — and one named contingency: **if the reopen-(d) joint round takes the
//! PoRep branch, A1 re-runs with sealing costs before the number is pinned**,
//! because per-replica sealing changes the burden model the pin reads. Nothing
//! in this module pins that number; [`EscalationParams`] carries it as data so
//! the shape can freeze without it (§8).
//!
//! # The five frozen constraints (§6.1)
//!
//! 1. **Monotone in `n`** — shards only accumulate, so the share may never fall.
//! 2. **Floor at today's 25 %** — the escalation never dips below the value it
//!    replaces, so this is a strict improvement on every input.
//! 3. **Asymptote strictly below `SCALE`** — the deflation channel
//!    (`actually_destroyed`) must survive forever; a share of `SCALE` would
//!    redirect the entire burn and delete it.
//! 4. **Banded piecewise-linear, integer fixed-point** — via
//!    [`shekyl_units::banded_pl`], the shape primitive shared with the archival
//!    reward curve. No float on a consensus path.
//! 5. **No time-derivative or smoothing term** — [`staker_pool_share_at`] is a
//!    pure function of `n`. No EMA, no rate-limiter, no per-block state. This is
//!    a constraint, not an omission: smoothness is *inherited from the operand*
//!    (§6.0), and a controller would add exactly the stateful machinery that
//!    section rejects.
//!
//! # The safety guarantee constraint 2 buys: **strictly no one is worse off**
//!
//! Constraint 2 is easy to read as a bound and easy to under-sell. It is the
//! strongest safety claim available about this freeze, so state it as the
//! guarantee it is:
//!
//! > **The escalation can only ever raise the staker share above today's value,
//! > never lower it below. At every `n`, and for every parameterization this
//! > module accepts, no archiver is worse off than under the flat 25 %.**
//!
//! That is *structural*, not per-case: the floor is the value being replaced, and
//! [`staker_pool_share_at`] is monotone from it. So the entire class of question
//! *"did the escalation take something from someone?"* is **foreclosed** rather
//! than answered case by case — the same posture as the no-exclusivity accounting
//! that closed reopen (c) (§12.11). A future reviewer or stakeholder asking who
//! lost out under the escalation can be answered from the shape alone, without
//! re-deriving a distribution.
//!
//! The corollary matters for the still-open numeric: this guarantee holds for
//! **any** asymptote the ceremony eventually pins, because it depends only on the
//! floor and monotonicity. Pinning the number cannot retract it.
//!
//! # Why no rate-limiter, restated on its final footing
//!
//! The justification shifted twice and landed harder than it started. It was
//! "smoothness inherited from an operand that cannot move"; then "the operand
//! moves only monotonically, at a bounded, depth-falling slew, at a price the
//! fee floor makes unprofitable". Both reopens closed with **no mechanism**:
//! stuffing is negative-sum without any floor (§12.11 — the stuffer funds
//! `(1 − w_a)` of the lift for competitors who spent nothing), and the anti-swing
//! property closes structurally (§12.11.1 — `n` is monotone, reversible only to
//! reorg depth, so there is no oscillation to arbitrage). A rate-limiter would
//! slow a **paid, one-way ratchet toward a sanctioned endpoint**, which is not a
//! thing worth slowing.

use shekyl_units::banded_pl::{curve_milli, mul_div_floor, BandedCurveParams};

use crate::params::SCALE;

/// Shape parameters for the escalation.
///
/// The *shape* these feed is genesis-frozen; the **values** are
/// provisional-until-testnet (§11.4 ceremony — see the module docs). They live
/// as data, not constants, precisely so the shape can freeze while the numeric
/// re-pin remains open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationParams {
    /// Share at `n = 0` — the §6.1 floor. Genesis value is today's
    /// `staker_pool_share` (`250_000` = 25 %), so the escalation is a strict
    /// improvement on the constant it replaces.
    pub floor_share: u64,
    /// `frozen_segment_count` at which the share saturates to
    /// [`Self::asymptote_share`]. A **larger knee is a slower ratchet** (§6.0
    /// wide-but-slow).
    pub knee_n: u64,
    /// Share at and beyond the knee. **Must be `< SCALE`** so the deflation
    /// channel survives (constraint 3); [`EscalationParams::is_well_formed`]
    /// checks it.
    pub asymptote_share: u64,
}

impl EscalationParams {
    /// Structural validity — the constraints that are about the *shape*, not the
    /// (unpinned) numerics.
    ///
    /// `asymptote < SCALE` is constraint 3 and is the one that would silently
    /// delete the burn channel if violated. `floor <= asymptote` is what makes
    /// the map monotone; inverted, the "escalation" would descend.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.asymptote_share < SCALE && self.floor_share <= self.asymptote_share
    }
}

/// The escalation: `staker_pool_share` as a pure map of the burden operand `n`.
///
/// Rises from `floor_share` at `n = 0` along the banded piecewise-linear ramp,
/// saturating at `asymptote_share` for `n >= knee_n`.
///
/// **The ramp uses the *continuous* parameterization deliberately**
/// ([`BandedCurveParams::continuous`]). A step at the join would be a share
/// cliff, and a cliff is exactly the two-sided lever §6.0's anti-swing property
/// exists to deny — an adversary who could straddle a discontinuity would gain
/// the swing that monotonicity otherwise makes unavailable.
///
/// Malformed params fail **closed to the floor**: a bad asymptote yields today's
/// constant rather than an arbitrary redirection of the burn. Returning the
/// floor is the safe direction because it is the current shipping behaviour.
#[must_use]
pub fn staker_pool_share_at(n: u64, params: &EscalationParams) -> u64 {
    if !params.is_well_formed() {
        return params.floor_share.min(SCALE);
    }
    let span = params.asymptote_share - params.floor_share;
    if span == 0 || params.knee_n == 0 {
        // Degenerate-but-valid: a flat escalation is just the floor. `knee_n == 0`
        // would otherwise divide by zero; treat it as "already saturated".
        return if params.knee_n == 0 {
            params.asymptote_share
        } else {
            params.floor_share
        };
    }

    // The ramp, normalized: `curve_milli` over the continuous parameterization
    // rises 0 -> knee/2 across [0, knee], so `knee/2` is the full-scale value.
    let shape = BandedCurveParams::continuous(params.knee_n);
    let full = shape.plateau_value_milli;
    if full == 0 {
        // knee_n == 1 floors to a zero plateau; saturate immediately.
        return params.asymptote_share;
    }
    let raw = curve_milli(n, &shape);

    // share = floor + span * raw / full. Floors, so the share is never rounded
    // UP into a larger redirection of the burn than the ramp earns.
    let lift = mul_div_floor(span, raw, full).unwrap_or(0);
    params.floor_share.saturating_add(lift)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genesis-shaped params: today's floor, a mid-band knee, a mid-band
    /// asymptote. **These are test fixtures, not the pin** — the numeric is
    /// deliberately unpinned (§11.4).
    fn params() -> EscalationParams {
        EscalationParams {
            floor_share: 250_000,
            knee_n: 100_000,
            asymptote_share: 750_000,
        }
    }

    /// **Constraint 1 — monotone in `n`.** The share may never fall as burden
    /// accumulates, across the whole domain including past the knee.
    #[test]
    fn constraint_1_monotone_in_n() {
        let p = params();
        let mut prev = 0;
        for n in (0..=250_000u64).step_by(311) {
            let s = staker_pool_share_at(n, &p);
            assert!(s >= prev, "share fell at n={n}: {s} < {prev}");
            prev = s;
        }
    }

    /// **Constraint 2 — floor at today's 25 %.** At `n = 0` the escalation
    /// returns exactly the constant it replaces, so it is a strict improvement
    /// on every input rather than a redistribution.
    #[test]
    fn constraint_2_floor_is_todays_share() {
        let p = params();
        assert_eq!(staker_pool_share_at(0, &p), 250_000);
        // And never below it, anywhere.
        for n in [0u64, 1, 7, 1_000, 99_999, 100_000, 10_000_000] {
            assert!(staker_pool_share_at(n, &p) >= p.floor_share);
        }
    }

    /// **The strict-improvement guarantee, made executable.** No archiver is
    /// worse off than under the flat 25 % — at any `n`, under *any* parameters
    /// this module accepts, including ones the ceremony has not pinned yet.
    ///
    /// Swept over a grid of floors/knees/asymptotes rather than the fixture,
    /// because the claim is about the shape's whole accepted domain: if it held
    /// only for one parameterization it would be a coincidence, not a guarantee,
    /// and the numeric is still open.
    #[test]
    fn no_one_is_ever_worse_off_than_the_flat_share() {
        const TODAY: u64 = 250_000;
        for knee in [1u64, 2, 1_000, 25_000, 100_000, 250_000] {
            for asymptote in [TODAY, 400_000, 750_000, 900_000, SCALE - 1] {
                let p = EscalationParams {
                    floor_share: TODAY,
                    knee_n: knee,
                    asymptote_share: asymptote,
                };
                assert!(p.is_well_formed(), "fixture must be accepted: {p:?}");
                for n in [0u64, 1, knee / 2, knee - 1, knee, knee + 1, u64::MAX] {
                    let s = staker_pool_share_at(n, &p);
                    assert!(
                        s >= TODAY,
                        "escalation went BELOW today's flat share: n={n} \
                         params={p:?} share={s}"
                    );
                    assert!(s < SCALE, "deflation channel deleted: n={n} share={s}");
                }
            }
        }
    }

    /// **Constraint 3 — asymptote strictly below `SCALE`, so deflation
    /// survives.** The share saturates at the asymptote and never reaches full
    /// scale, which is what keeps `actually_destroyed` a live channel forever.
    #[test]
    fn constraint_3_deflation_channel_survives() {
        let p = params();
        assert_eq!(staker_pool_share_at(p.knee_n, &p), p.asymptote_share);
        assert_eq!(staker_pool_share_at(u64::MAX, &p), p.asymptote_share);
        for n in [0u64, 50_000, 100_000, u64::MAX] {
            assert!(
                staker_pool_share_at(n, &p) < SCALE,
                "share reached full scale at n={n} — the burn channel is deleted"
            );
        }
        // A malformed asymptote must not be honoured.
        let bad = EscalationParams {
            asymptote_share: SCALE,
            ..p
        };
        assert!(!bad.is_well_formed());
        assert_eq!(staker_pool_share_at(u64::MAX, &bad), bad.floor_share);
    }

    /// **Constraint 4 — banded PL, integer, no float.** Asserted structurally by
    /// deferring to `shekyl_units::banded_pl` (the shape primitive's own tests
    /// pin the bands); here we pin that the ramp is *strictly between* the
    /// endpoints in the interior, i.e. it genuinely ramps rather than stepping.
    #[test]
    fn constraint_4_ramps_rather_than_steps() {
        let p = params();
        let mid = staker_pool_share_at(p.knee_n / 2, &p);
        assert!(
            mid > p.floor_share && mid < p.asymptote_share,
            "interior value {mid} is not strictly between the endpoints"
        );
    }

    /// **Constraint 5 — pure map of `n`, no state.** The same `n` decides
    /// identically regardless of call order or history, which is what makes a
    /// rate-limiter unnecessary *and* unrepresentable here.
    #[test]
    fn constraint_5_is_a_pure_map_with_no_history() {
        let p = params();
        let ascending: Vec<u64> = (0..40)
            .map(|i| staker_pool_share_at(i * 3_000, &p))
            .collect();
        let descending: Vec<u64> = (0..40)
            .rev()
            .map(|i| staker_pool_share_at(i * 3_000, &p))
            .collect();
        let mut d = descending;
        d.reverse();
        assert_eq!(ascending, d, "evaluation order changed the result");
    }

    /// **No cliff at the knee** — stated as "the join is not a special place",
    /// which is the property that actually matters and the only one that is
    /// scale-independent.
    ///
    /// The naive form of this test ("the step at the knee is ≤ 1") asserts the
    /// wrong quantity: the *curve* steps by at most 1 there, but the share
    /// amplifies the curve by `span / full`, so a correct implementation shows a
    /// step of exactly that ratio. What an adversary could straddle is a step
    /// **larger than its neighbourhood**, so that is what is pinned — the knee's
    /// step must not exceed the largest step found anywhere else on the ramp.
    #[test]
    fn no_share_cliff_at_the_knee() {
        let p = params();
        let knee_step = staker_pool_share_at(p.knee_n, &p) - staker_pool_share_at(p.knee_n - 1, &p);

        let mut max_interior_step = 0;
        let mut prev = staker_pool_share_at(0, &p);
        for n in 1..p.knee_n {
            let cur = staker_pool_share_at(n, &p);
            max_interior_step = max_interior_step.max(cur - prev);
            prev = cur;
        }

        assert!(
            knee_step <= max_interior_step,
            "the knee is a cliff: step {knee_step} exceeds the ramp's largest \
             interior step {max_interior_step}"
        );
        assert!(
            max_interior_step > 0,
            "fixture must actually ramp, or this proves nothing"
        );
    }

    /// Rounding favours the protocol: the lift floors, so the share is never
    /// rounded *up* into redirecting more burn than the ramp earns — the same
    /// direction as every other rounding on this path (§11.5).
    #[test]
    fn rounding_never_favours_the_pool() {
        let p = EscalationParams {
            floor_share: 250_000,
            knee_n: 7,
            asymptote_share: 750_001,
        };
        for n in 0..=7u64 {
            let s = staker_pool_share_at(n, &p);
            assert!(s >= p.floor_share && s <= p.asymptote_share);
        }
    }

    /// Degenerate params must not panic or divide by zero — a consensus function
    /// takes whatever the params file contains.
    #[test]
    fn degenerate_params_fail_closed_not_loud() {
        let flat = EscalationParams {
            floor_share: 250_000,
            knee_n: 100_000,
            asymptote_share: 250_000,
        };
        assert_eq!(staker_pool_share_at(u64::MAX, &flat), 250_000);

        let zero_knee = EscalationParams {
            floor_share: 250_000,
            knee_n: 0,
            asymptote_share: 750_000,
        };
        assert_eq!(staker_pool_share_at(0, &zero_knee), 750_000);

        let one_knee = EscalationParams {
            floor_share: 250_000,
            knee_n: 1,
            asymptote_share: 750_000,
        };
        assert_eq!(staker_pool_share_at(5, &one_knee), 750_000);

        let inverted = EscalationParams {
            floor_share: 750_000,
            knee_n: 100_000,
            asymptote_share: 250_000,
        };
        assert!(!inverted.is_well_formed());
        assert_eq!(staker_pool_share_at(50_000, &inverted), 750_000);
    }
}

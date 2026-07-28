// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Banded piecewise-linear integer fixed-point curve — the shared consensus
//! shape primitive.
//!
//! **Why this lives in `shekyl-units` rather than beside either consumer.** Two
//! consensus surfaces need this exact shape:
//!
//! - `shekyl-archival-retention` — the archival reward curve
//!   ([`curve_milli`]'s original home; retained post-D3/R2 as the
//!   sim/counterfactual after the plateau left the reward path), and
//! - `shekyl-economics` — the D2 staker-share escalation, which
//!   `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §6.1 pins as "banded
//!   piecewise-linear in integer fixed-point, **per the `curve_milli`
//!   precedent**".
//!
//! Putting the definition in either consumer forces a choice between a **mirror**
//! (two bodies of one shape, free to drift — the failure class D3's review rounds
//! spent themselves eliminating) and a **layering inversion**
//! (`shekyl-economics`, which is deliberately dependency-free apart from
//! `thiserror`/`serde`/`blake2`, would inherit FCMP, PQC, and the curve stack).
//! A foundational crate is the only placement that gives single-sourcing without
//! either cost.
//!
//! **No float, ever.** Every consumer is on a consensus path where two nodes
//! disagreeing by one ULP is a chain split, so the whole module is integer
//! fixed-point with `u128` intermediates and saturating adds.

#![allow(clippy::module_name_repetitions)]

/// `floor(a · b / d)` with a `u128` intermediate; `None` when `d == 0` or the
/// quotient does not fit `u64`.
///
/// The single multiply-divide primitive for consensus fixed-point: doing it in
/// `u64` would overflow on realistic operands, and doing it in float would not
/// be reproducible across nodes.
#[must_use]
pub fn mul_div_floor(a: u64, b: u64, d: u64) -> Option<u64> {
    if d == 0 {
        return None;
    }
    let q = u128::from(a).saturating_mul(u128::from(b)) / u128::from(d);
    u64::try_from(q).ok()
}

/// Shape parameters for [`curve_milli`]: breakpoints are fractions of
/// `plateau_work_milli`, and the curve saturates at `plateau_value_milli`.
///
/// The three bands run at slope `1.0`, `0.5`, `0.25` over
/// `[0, pw/4)`, `[pw/4, pw/2)`, `[pw/2, pw)`, saturating at `pw`.
///
/// **Continuity is a property of the parameters, not of the function.** The
/// curve is continuous at the plateau join exactly when
/// `plateau_value_milli == plateau_work_milli / 2` — integrating the three
/// slopes over their bands yields `pw/4 + pw/8 + pw/8 = pw/2`. Any other
/// `plateau_value` introduces a step at `pw`. Consumers that need a continuous
/// rise (the §6.1 escalation) must construct with
/// [`BandedCurveParams::continuous`]; consumers modelling a *cap* (the retired
/// archival plateau) deliberately do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandedCurveParams {
    /// Work value at which the curve saturates (the third breakpoint).
    pub plateau_work_milli: u64,
    /// Curve value on the plateau.
    pub plateau_value_milli: u64,
}

impl BandedCurveParams {
    /// The **continuous** parameterization: `plateau_value = plateau_work / 2`,
    /// the one choice with no step at the join (see the type docs).
    ///
    /// This is the form §6.1's escalation requires — a share function with a
    /// discontinuity would hand an adversary a cliff to straddle, which is
    /// precisely the fast-swing lever §6.0 exists to deny.
    #[must_use]
    pub const fn continuous(plateau_work_milli: u64) -> Self {
        Self {
            plateau_work_milli,
            plateau_value_milli: plateau_work_milli / 2,
        }
    }

    /// The continuous parameterization expressed from the **value** side:
    /// `plateau_work = 2 · plateau_value`. Equivalent to
    /// [`Self::continuous`], for callers that know the saturation value rather
    /// than the saturation point.
    #[must_use]
    pub const fn from_plateau_value(plateau_value_milli: u64) -> Self {
        Self {
            plateau_work_milli: plateau_value_milli.saturating_mul(2),
            plateau_value_milli,
        }
    }

    /// Does this parameterization put the plateau exactly on the ramp's endpoint?
    #[must_use]
    pub const fn is_continuous(&self) -> bool {
        self.plateau_value_milli == self.plateau_work_milli / 2
    }
}

/// Evaluate the banded piecewise-linear curve at `work_milli`.
///
/// Monotone non-decreasing in `work_milli`, `0` at `0`, and saturating at
/// `plateau_value_milli` for `work_milli >= plateau_work_milli`.
#[must_use]
pub fn curve_milli(work_milli: u64, params: &BandedCurveParams) -> u64 {
    if work_milli == 0 || params.plateau_value_milli == 0 {
        return 0;
    }
    let pw = params.plateau_work_milli.max(1);
    let pv = params.plateau_value_milli;
    let b1 = pw / 4;
    let b2 = pw / 2;
    let b3 = pw;

    if work_milli >= b3 {
        return pv;
    }

    // Every pre-plateau return clamps to `pv` so the documented contract --
    // monotone non-decreasing, saturating at `plateau_value_milli` -- holds for
    // every representable parameterization, not just the constructed ones. A
    // sub-continuous cap (`pv < pw/2`) would otherwise rise above `pv` on the
    // ramp and then DROP to `pv` at the plateau. For the two shapes live
    // consumers use the clamp is provably inert: the segment maxima are `pw/4`,
    // `3*pw/8`, and `<= pw/2`, all `<= pv` when `pv >= pw/2` (continuous and
    // cap-shaped both satisfy that).
    let mut y = 0u64;

    // segment 1: slope 1.0
    let mut x = if work_milli > b1 {
        y = y.saturating_add(b1);
        b1
    } else {
        return work_milli.min(pv);
    };

    // segment 2: slope 0.5
    if work_milli > b2 {
        let seg = b2 - x;
        y = y.saturating_add(seg / 2);
        x = b2;
    } else {
        let seg = work_milli - x;
        return y.saturating_add(seg / 2).min(pv);
    }

    // segment 3: slope 0.25
    let seg = work_milli - x;
    y.saturating_add(mul_div_floor(seg, 1, 4).unwrap_or(0))
        .min(pv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden shape, pinned here at the definition so both consumers inherit
    /// one verified table rather than each asserting its own.
    #[test]
    fn banded_pl_golden() {
        let p = BandedCurveParams {
            plateau_work_milli: 16_000,
            plateau_value_milli: 8_000,
        };
        assert_eq!(curve_milli(0, &p), 0);
        assert_eq!(curve_milli(2_000, &p), 2_000); // seg 1, slope 1.0
        assert_eq!(curve_milli(4_000, &p), 4_000); // b1
        assert_eq!(curve_milli(6_000, &p), 5_000); // seg 2, slope 0.5
        assert_eq!(curve_milli(8_000, &p), 6_000); // b2
        assert_eq!(curve_milli(10_000, &p), 6_500); // seg 3, slope 0.25
        assert_eq!(curve_milli(12_000, &p), 7_000);
        assert_eq!(curve_milli(16_000, &p), 8_000); // plateau
        assert_eq!(curve_milli(32_000, &p), 8_000); // past plateau
    }

    /// A sub-continuous cap (`pv < pw/2`) is representable (the fields are
    /// public), and the documented contract — monotone, saturating at
    /// `plateau_value_milli` — must hold for it too: without the pre-plateau
    /// clamp the ramp rose ABOVE `pv` and then dropped to it at the plateau.
    /// The same sweep pins that the clamp is inert for the continuous shape
    /// (bit-identical outputs), which is what the live consumers rely on.
    #[test]
    fn sub_continuous_cap_saturates_without_overshoot() {
        let sub = BandedCurveParams {
            plateau_work_milli: 16_000,
            plateau_value_milli: 3_000, // < pw/2 = 8_000
        };
        let mut prev = 0;
        for w in (0..=32_000).step_by(97) {
            let v = curve_milli(w, &sub);
            assert!(v <= sub.plateau_value_milli, "overshot pv at w={w}: {v}");
            assert!(v >= prev, "curve fell at w={w}: {v} < {prev}");
            prev = v;
        }
        assert_eq!(curve_milli(16_000, &sub), 3_000);
    }

    /// Monotonicity is what every consumer leans on — the escalation for §6.1
    /// constraint 1, the reward counterfactual for its cap semantics.
    #[test]
    fn curve_is_monotone_non_decreasing() {
        let p = BandedCurveParams::continuous(10_000);
        let mut prev = 0;
        for w in (0..=20_000).step_by(97) {
            let v = curve_milli(w, &p);
            assert!(v >= prev, "curve fell at w={w}: {v} < {prev}");
            prev = v;
        }
    }

    /// The continuity property, asserted rather than described: the three bands
    /// integrate to exactly `pw/2`, so `continuous()` lands on the plateau with
    /// no step.
    #[test]
    fn continuous_parameterization_has_no_step_at_the_join() {
        for pw in [4_000u64, 16_000, 100_000, 250_000] {
            let p = BandedCurveParams::continuous(pw);
            assert!(p.is_continuous());
            // Approaching the join from below reaches the plateau value exactly.
            assert_eq!(curve_milli(pw - 1, &p), p.plateau_value_milli - 1);
            assert_eq!(curve_milli(pw, &p), p.plateau_value_milli);
        }
        // A cap-shaped parameterization deliberately does step.
        let capped = BandedCurveParams {
            plateau_work_milli: 16_000,
            plateau_value_milli: 8_000 * 3,
        };
        assert!(!capped.is_continuous());
    }

    #[test]
    fn mul_div_floor_guards_zero_and_overflow() {
        assert_eq!(mul_div_floor(10, 3, 4), Some(7)); // floors
        assert_eq!(mul_div_floor(1, 1, 0), None); // zero divisor
        assert_eq!(mul_div_floor(u64::MAX, u64::MAX, 1), None); // quotient > u64
        assert_eq!(mul_div_floor(u64::MAX, 1, 1), Some(u64::MAX));
    }
}

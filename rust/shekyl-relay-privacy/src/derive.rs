// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corrected embargo derivation — exact, deterministic, and
//! transcendental-free.
//!
//! # Why the closed form had to go
//!
//! [`crate::params::DandelionParams::average_embargo_secs`] evaluates the
//! Dandelion++ appendix B.5 closed form. That form is
//!
//! ```text
//! Tbase = (-k * (k - 1) * hop) / (2 * ln(1 - ep))
//! ```
//!
//! and it is derived by asking: if `k` nodes each arm a memoryless timer, what
//! mean makes the probability that none fires early equal `1 - ep`? The step
//! that breaks is substituting the *expected* stem length `k` into an
//! expression in `k(k - 1)`. Stem length is not fixed — it is geometric — and
//! for a geometric `K`,
//!
//! ```text
//! E[K(K-1)] = 2 * E[K] * (E[K] - 1)
//! ```
//!
//! exactly, for every fluff probability. So the closed form is solving for the
//! wrong quantity by a factor of two before Jensen's inequality is even
//! reached; the survival probability is `E[exp(-c·K(K-1))]`, not
//! `exp(-c·E[K(K-1)])`, and neither substitution is the answer.
//!
//! There is no clean closed form for the true quantity — it is a theta-like
//! sum. But there is an exact one, and it is cheap.
//!
//! # The exact survival equation
//!
//! Take the discrete memoryless embargo this design uses ([`crate::geometric`])
//! at tick `τ` and success probability `p`. A stem of `h` hops has nodes
//! `0..=h`; node `i` armed its timer at `i·hop` and the natural fluff happens
//! at `h·hop`, so node `i`'s timer must exceed a slack of `(h - i)·hop`. For a
//! geometric timer that survival probability is `(1-p)^ceil(slack/τ)`, and the
//! timers are independent, so
//!
//! ```text
//! P(full travel) = Σ_h  (1-q)^h · q · (1-p)^S(h),   S(h) = Σ_{j=0}^{h} ceil(j·hop/τ)
//! ```
//!
//! Every term is a product of powers of `(1-q)` and `(1-p)`. Computed by
//! running multiplication — no `exp`, no `ln`, no `pow` — the whole derivation
//! is bit-identical on every platform, exactly like the distribution tables.
//! The answer is then found by bisecting on the mean, which is monotone.
//!
//! # What this buys
//!
//! The embargo is no longer a constant, and no longer a constant produced by a
//! formula that does not describe the system. It is the solution to the actual
//! survival equation for the actual distribution at the actual timer
//! granularity — recomputed whenever any input moves, so it cannot drift from
//! its justification the way a `#define` did.
#![allow(clippy::cast_precision_loss)]
// ^ Small integer parameters widen to `f64` for the survival sum. Every value
//   involved is far below 2^53.

use crate::params::DandelionParams;

/// Below this remaining stem-length mass, further terms cannot move the sum at
/// `f64` resolution. `(1-q)^h < 1e-18` is reached by h ≈ 186 at q = 20% and by
/// h ≈ 4,100 at q = 1%.
const TAIL_MASS_CUTOFF: f64 = 1e-18;

/// Hard bound on the number of stem lengths summed, so the loop is total for
/// any input including a pathological fluff probability.
const MAX_STEM_TERMS: u32 = 100_000;

/// A derived embargo: the answer plus enough context to audit it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmbargoDerivation {
    /// Mean embargo, in ticks.
    pub mean_ticks: u32,
    /// Tick size the derivation was solved at. The answer is only valid at
    /// this granularity — a coarser timer needs a longer mean to hit the same
    /// target, which is why the tick is an input and not an afterthought.
    pub tick_millis: u64,
    /// Full-travel probability the solution actually achieves. Always at or
    /// just above the target, never below.
    pub achieved: f64,
    /// The target it was solved for.
    pub target: f64,
}

impl EmbargoDerivation {
    /// Mean embargo in whole seconds, rounded up.
    ///
    /// A convenience for reporting only — the authoritative value is
    /// [`Self::mean_ticks`] at [`Self::tick_millis`], because that is what the
    /// derivation solved for. Rounding to seconds and then back to ticks does
    /// not round-trip.
    #[must_use]
    pub fn mean_secs(&self) -> u32 {
        let ms = u64::from(self.mean_ticks) * self.tick_millis;
        u32::try_from(ms.div_ceil(1_000)).unwrap_or(u32::MAX)
    }
}

/// Exact probability that a transaction completes its stem before any node's
/// memoryless embargo fires.
///
/// Transcendental-free: the sum is built from running products only, so the
/// result is bit-identical across architectures.
///
/// # Panics
///
/// Panics if `mean_ticks` or `tick_millis` is zero, or if the fluff
/// probability is zero or above 100 — each of which makes the equation
/// meaningless rather than merely extreme.
#[must_use]
pub fn full_travel_probability(params: &DandelionParams, mean_ticks: u32, tick_millis: u64) -> f64 {
    assert!(mean_ticks > 0, "embargo mean must be non-zero");
    assert!(tick_millis > 0, "embargo tick must be non-zero");
    assert!(
        params.fluff_probability_pct > 0 && params.fluff_probability_pct <= 100,
        "fluff probability must be a percentage in 1..=100"
    );

    let q = f64::from(params.fluff_probability_pct) / 100.0;
    let stem_survives = 1.0 - q; // P(a node stems rather than fluffs)
    let p = 1.0 / (f64::from(mean_ticks) + 1.0);
    let timer_survives = 1.0 - p; // P(a geometric timer outlives one tick)

    let hop_ms = u64::from(params.time_between_hop_ms);

    let mut total = 0.0_f64;
    // (1-q)^h, by running product.
    let mut stem_mass = 1.0_f64;
    // (1-p)^S(h), by running product. S(0) = 0, so this starts at 1.
    let mut timer_mass = 1.0_f64;

    for h in 0..MAX_STEM_TERMS {
        total += stem_mass * q * timer_mass;

        if stem_mass < TAIL_MASS_CUTOFF {
            break;
        }

        // Advance to h+1. The stem gains one node, and *every* node's required
        // slack grows by one hop, so the new cumulative exponent is
        // S(h+1) = S(h) + ceil((h+1)·hop/τ) — an addition, not a difference.
        // (Getting this wrong understates the exponent and silently inflates
        // the survival probability, which is the failure this comment exists
        // to prevent recurring.)
        let slack_ticks = div_ceil(u64::from(h + 1) * hop_ms, tick_millis);
        timer_mass *= pow_exact(timer_survives, slack_ticks);
        stem_mass *= stem_survives;
    }

    total
}

/// `base^exp` by binary exponentiation — multiplication only, so the result is
/// deterministic across architectures in a way `f64::powf` is not.
fn pow_exact(base: f64, mut exp: u64) -> f64 {
    let mut result = 1.0_f64;
    let mut factor = base;
    while exp > 0 {
        if exp & 1 == 1 {
            result *= factor;
        }
        factor *= factor;
        exp >>= 1;
    }
    result
}

/// Smallest embargo mean, in ticks, whose exact full-travel probability
/// reaches `target`.
///
/// Bisects; [`full_travel_probability`] is monotone increasing in the mean, so
/// the search is exact rather than approximate. Returns `None` only if the
/// target is unreachable at any representable mean, which cannot happen for a
/// target strictly below 1.
///
/// # Panics
///
/// Panics if `target` is not strictly inside `(0, 1)`, or if `tick_millis` is
/// zero.
#[must_use]
pub fn derive_embargo(
    params: &DandelionParams,
    tick_millis: u64,
    target: f64,
) -> Option<EmbargoDerivation> {
    assert!(
        target > 0.0 && target < 1.0,
        "target must be a probability strictly inside (0, 1)"
    );
    assert!(tick_millis > 0, "embargo tick must be non-zero");

    // Expand until the target is bracketed.
    let mut hi = 1_u32;
    while full_travel_probability(params, hi, tick_millis) < target {
        hi = hi.checked_mul(2)?;
        if hi > 1 << 28 {
            return None;
        }
    }
    let mut lo = hi / 2 + 1;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if full_travel_probability(params, mid, tick_millis) < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    Some(EmbargoDerivation {
        mean_ticks: hi,
        tick_millis,
        achieved: full_travel_probability(params, hi, tick_millis),
        target,
    })
}

/// Integer ceiling division.
const fn div_ceil(numerator: u64, denominator: u64) -> u64 {
    numerator.div_ceil(denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EMBARGO_FULL_TRAVEL_PROBABILITY;
    use crate::schedule::DEFAULT_EMBARGO_TICK_MILLIS;

    #[test]
    fn derivation_hits_its_target_and_the_step_below_misses() {
        // The defining property of a *smallest* solution: it clears the
        // target and its predecessor does not. Anything weaker would pass for
        // a solver that simply returned a large number.
        let params = DandelionParams::inherited();
        let d = derive_embargo(
            &params,
            DEFAULT_EMBARGO_TICK_MILLIS,
            EMBARGO_FULL_TRAVEL_PROBABILITY,
        )
        .expect("target is reachable");

        assert!(d.achieved >= EMBARGO_FULL_TRAVEL_PROBABILITY);
        assert!(d.mean_ticks > 1);
        let below = full_travel_probability(&params, d.mean_ticks - 1, d.tick_millis);
        assert!(
            below < EMBARGO_FULL_TRAVEL_PROBABILITY,
            "mean_ticks-1 also clears the target ({below:.6}) — not the smallest solution"
        );
    }

    #[test]
    fn survival_is_monotone_in_the_mean() {
        let params = DandelionParams::inherited();
        let mut previous = 0.0_f64;
        for mean_ticks in (4..400).step_by(4) {
            let p = full_travel_probability(&params, mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);
            assert!(
                p >= previous,
                "survival fell from {previous:.6} to {p:.6} at mean={mean_ticks}"
            );
            previous = p;
        }
    }

    #[test]
    fn the_closed_form_under_provisions_at_every_fluff_probability() {
        // Finding 3, pinned across the parameter space rather than at one
        // point: the paper's closed form never reaches its own target.
        for pct in 1..=50_u32 {
            let params = DandelionParams {
                fluff_probability_pct: pct,
                ..DandelionParams::inherited()
            };
            let closed_form_secs = params.average_embargo_secs();
            if closed_form_secs == 0 {
                continue;
            }
            let ticks =
                u32::try_from(u64::from(closed_form_secs) * 1_000 / DEFAULT_EMBARGO_TICK_MILLIS)
                    .expect("fits");
            let achieved =
                full_travel_probability(&params, ticks.max(1), DEFAULT_EMBARGO_TICK_MILLIS);
            assert!(
                achieved < EMBARGO_FULL_TRAVEL_PROBABILITY,
                "q={pct}%: closed form reached {achieved:.4}, expected it to fall short"
            );
        }
    }

    #[test]
    fn derived_embargo_clears_the_target_at_every_fluff_probability() {
        for pct in 1..=50_u32 {
            let params = DandelionParams {
                fluff_probability_pct: pct,
                ..DandelionParams::inherited()
            };
            let d = derive_embargo(
                &params,
                DEFAULT_EMBARGO_TICK_MILLIS,
                EMBARGO_FULL_TRAVEL_PROBABILITY,
            )
            .expect("reachable");
            assert!(
                d.achieved >= EMBARGO_FULL_TRAVEL_PROBABILITY,
                "q={pct}%: derived {} ticks achieved only {:.4}",
                d.mean_ticks,
                d.achieved
            );
        }
    }

    #[test]
    fn a_coarser_tick_needs_a_longer_mean() {
        // The tick is a real input, not a formatting detail: a coarse timer
        // rounds sub-tick embargoes down to zero and so must be compensated.
        let params = DandelionParams::inherited();
        let fine = derive_embargo(&params, 50, EMBARGO_FULL_TRAVEL_PROBABILITY).expect("reachable");
        let coarse =
            derive_embargo(&params, 1_000, EMBARGO_FULL_TRAVEL_PROBABILITY).expect("reachable");
        assert!(
            coarse.mean_secs() > fine.mean_secs(),
            "coarse tick derived {}s, fine tick {}s",
            coarse.mean_secs(),
            fine.mean_secs()
        );
    }

    #[test]
    fn a_longer_hop_needs_a_longer_embargo() {
        let base = DandelionParams::inherited();
        let slow = DandelionParams {
            time_between_hop_ms: 500,
            ..base
        };
        let a = derive_embargo(&base, DEFAULT_EMBARGO_TICK_MILLIS, 0.90).expect("reachable");
        let b = derive_embargo(&slow, DEFAULT_EMBARGO_TICK_MILLIS, 0.90).expect("reachable");
        assert!(b.mean_ticks > a.mean_ticks);
    }

    #[test]
    fn a_stricter_target_needs_a_longer_embargo() {
        let params = DandelionParams::inherited();
        let loose = derive_embargo(&params, DEFAULT_EMBARGO_TICK_MILLIS, 0.90).expect("reachable");
        let tight = derive_embargo(&params, DEFAULT_EMBARGO_TICK_MILLIS, 0.99).expect("reachable");
        assert!(tight.mean_ticks > loose.mean_ticks);
    }

    #[test]
    fn probability_is_bounded() {
        let params = DandelionParams::inherited();
        for mean_ticks in [1_u32, 10, 100, 10_000] {
            let p = full_travel_probability(&params, mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);
            assert!((0.0..=1.0).contains(&p), "probability {p} out of range");
        }
        // An enormous embargo approaches certainty; a tiny one does not.
        let huge = full_travel_probability(&params, 1_000_000, DEFAULT_EMBARGO_TICK_MILLIS);
        assert!(huge > 0.999, "huge embargo gave {huge}");
    }

    #[test]
    fn always_fluffing_is_a_degenerate_but_valid_input() {
        // q = 100%: every node fluffs immediately, the stem is one node long
        // and there is no slack for any embargo to preempt. Survival is
        // certain, and the derivation must not loop or divide by zero.
        let params = DandelionParams {
            fluff_probability_pct: 100,
            ..DandelionParams::inherited()
        };
        let p = full_travel_probability(&params, 4, DEFAULT_EMBARGO_TICK_MILLIS);
        assert!((p - 1.0).abs() < 1e-12, "expected certainty, got {p}");
    }
}

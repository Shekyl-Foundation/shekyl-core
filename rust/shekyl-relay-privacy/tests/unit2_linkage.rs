// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//! Q-11 Unit 2: does the covert cadence's shape change linkability, and does
//! the answer depend on how strong the observer is?
//!
//! **This asserts, it does not only print.** A `#[test]` that emits a table
//! and checks nothing passes unless it panics — it cannot catch a regression,
//! which is the §50.3 class in its plainest form. The table is still printed,
//! because the shape decision reads the numbers; the assertions are what make
//! it a test.
#![allow(clippy::cast_precision_loss)]
use shekyl_relay_privacy::conformance::linkage::{
    simulate_cadence_linkage, CadenceShape, MatcherStrength,
};
use shekyl_relay_privacy::params::carrier;
use shekyl_relay_privacy::SplitMix64;

const M: usize = 20;
const CHANCE: f64 = 1.0 / M as f64;
const TRIALS: usize = 2_000;
/// Trials for the one assertion whose effect the cadence change shrank to
/// ~0.008 over chance. σ ≈ 0.0015 here, so a 3σ band is 0.0046 — resolvable.
/// The sweep table stays at [`TRIALS`]: it is a readout, not a decision.
const TRIALS_DECISIVE: usize = 20_000;

fn rate(shape: CadenceShape, matcher: MatcherStrength, blackout_s: u64) -> f64 {
    let mut rng = SplitMix64::new(0x5732 + blackout_s);
    simulate_cadence_linkage(shape, matcher, M, blackout_s * 1_000, TRIALS, &mut rng).match_rate
}

/// The three properties the shape decision (§56) rests on.
#[test]
fn unit2_shape_separation_holds_under_the_strong_matcher() {
    let strong = MatcherStrength::MarginalizedOverK;

    // 1. The metronome is perfectly linkable at every gap. A deterministic
    //    emitter's phase is a permanent per-stream identifier.
    for b in [10_u64, 60, 150] {
        let r = rate(CadenceShape::Metronome, strong, b);
        assert!(
            r > 0.95,
            "metronome at {b}s read {r:.3}; a fixed period is a permanent tag \
             and must re-identify near-perfectly"
        );
    }

    // 2. Memoryless sits at chance regardless of gap — the defining property,
    //    not a margin.
    for b in [10_u64, 60, 150] {
        let r = rate(CadenceShape::Memoryless, strong, b);
        assert!(
            (r - CHANCE).abs() < 0.02,
            "memoryless at {b}s read {r:.3} vs chance {CHANCE:.3}; the residual \
             must carry no information about which stream it was"
        );
    }

    // 3. Bounded separates from memoryless at a short gap. This is the arm
    //    that decides the shape: if it ever reads at chance under the strong
    //    matcher, §56's answer flips back and the assert should say so.
    //
    //    THE MARGIN MOVED WITH THE CADENCE, THE PROPERTY DID NOT (2026-08-28).
    //    At the 12.5 s mean this read 0.120 against chance 0.050 — an excess
    //    of 0.070, which a `CHANCE + 0.02` threshold caught at 600 trials.
    //    At the 5 s mean it reads 0.058: an excess of 0.008, roughly SEVEN
    //    TIMES smaller. The shorter cadence hides more emissions in the same
    //    blackout and widens the relative spread of the elapsed sum
    //    (0.193/√k against 0.115/√k), so `k` is harder to identify and the
    //    residual phase inside it is a smaller share of the interval.
    //
    //    A 0.008 excess is not resolvable at 600 trials — 1.6σ, which is why
    //    the threshold is re-derived from the sample size rather than lowered
    //    until it passes. `TRIALS_DECISIVE` gives σ ≈ 0.0015, so the 3σ band
    //    below sits at 0.0046 and the measured excess clears it by ~1.7×.
    //
    //    IT IS REDUCED, NOT CLOSED, and that distinction is §56.5's whole
    //    basis: memorylessness removes the channel BY CONSTRUCTION (the wait
    //    from blackout-end is Exp(µ), independent of everything prior), while
    //    bounded merely leaks less at these constants. A cadence that closed
    //    the measured gap would not have changed the family's structure — and
    //    reading "at chance" off a sample too small to see 0.008 is the exact
    //    trap §56.5 named, where a green result grades the observer.
    let mut rng = SplitMix64::new(0x5732 + 10);
    let bounded = simulate_cadence_linkage(
        CadenceShape::BoundedUniform,
        strong,
        M,
        10_000,
        TRIALS_DECISIVE,
        &mut rng,
    )
    .match_rate;
    #[allow(clippy::cast_precision_loss)]
    let sigma = (CHANCE * (1.0 - CHANCE) / TRIALS_DECISIVE as f64).sqrt();
    assert!(
        bounded > CHANCE + 3.0 * sigma,
        "bounded at 10s read {bounded:.4} vs chance {CHANCE:.3} (3σ = {:.4}); \
         §56.5 chose memoryless BECAUSE the bounded family carries a residual \
         channel here. If this now reads at chance, the shape decision wants \
         re-taking rather than the threshold lowering",
        3.0 * sigma,
    );
}

/// The weak matcher misses all of it — which is why `MatcherStrength` is a
/// permanent arm and not a detail (§56.4).
///
/// Pinned as a property because it is the instrument's own failure mode: a
/// `k = 1` matcher reported "bounded and memoryless are indistinguishable"
/// *and* read the metronome — the obvious case — at zero.
///
/// # The blackout must NOT be a multiple of the cadence mean
///
/// This probe sat at 60 s, which was 4.8 periods at the old 12.5 s mean and is
/// exactly **12** at the 5 s mean — and on-multiple the weak matcher reads the
/// metronome at **1.000** instead of 0.000. Measured across the sweep: 0.000
/// at 13, 27, 47, 63 and 88 s, 1.000 at 10 and 150 s. Every one of the 1.000s
/// is an exact multiple.
///
/// The mechanism is §56.2's, applied to the instrument rather than to one
/// cell. On-multiple, `last + mean` is wrong by the *same* whole number of
/// periods for every stream, so the ordering it induces is still correct and
/// the assignment is perfect; off-multiple the streams land at unrelated
/// offsets and it scrambles. §56.2 recorded exactly this about the −0.250 at
/// `D` = 30 s and §56.4 noted the tell had not been generalised — so a probe
/// whose alignment is left to chance is the same omission a third time.
///
/// 47 s is chosen for being coprime to the mean rather than for its result.
#[test]
fn the_weak_matcher_misses_what_the_strong_one_finds() {
    const BLACKOUT_S: u64 = 47;
    assert!(
        !(BLACKOUT_S * 1_000).is_multiple_of(u64::from(carrier::MEAN_CADENCE_MS)),
        "the probe must be off-multiple: on an exact multiple of the mean the \
         weak matcher reads the metronome perfectly, and this test would be \
         measuring alignment rather than matcher strength"
    );

    let weak = MatcherStrength::NearestPredicted;
    let strong = MatcherStrength::MarginalizedOverK;

    let (weak_metro, strong_metro) = (
        rate(CadenceShape::Metronome, weak, BLACKOUT_S),
        rate(CadenceShape::Metronome, strong, BLACKOUT_S),
    );
    assert!(
        strong_metro > 0.95 && weak_metro < 0.5,
        "expected the weak matcher to miss the metronome (weak {weak_metro:.3}, \
         strong {strong_metro:.3}) — if the weak arm now finds it, the lesson \
         this arm exists to record no longer reproduces"
    );
}

/// The table §56 reports. Printed, not asserted — the assertions above are
/// the gate; this is the readout the shape decision was taken against.
#[test]
fn unit2_shape_sweep_table() {
    for matcher in [
        MatcherStrength::NearestPredicted,
        MatcherStrength::MarginalizedOverK,
    ] {
        println!("\n=== matcher: {matcher:?}   (M={M}, chance={CHANCE:.3})");
        println!(
            "{:>10} {:>12} {:>14} {:>12}",
            "blackout", "bounded", "memoryless", "metronome"
        );
        for b in [10_u64, 13, 20, 30, 45, 60, 90, 150] {
            println!(
                "{b:>9}s {:>12.3} {:>14.3} {:>12.3}",
                rate(CadenceShape::BoundedUniform, matcher, b),
                rate(CadenceShape::Memoryless, matcher, b),
                rate(CadenceShape::Metronome, matcher, b),
            );
        }
    }
}

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
use shekyl_relay_privacy::SplitMix64;

const M: usize = 20;
const CHANCE: f64 = 1.0 / M as f64;
const TRIALS: usize = 600;

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
    let bounded = rate(CadenceShape::BoundedUniform, strong, 10);
    assert!(
        bounded > CHANCE + 0.02,
        "bounded at 10s read {bounded:.3} vs chance {CHANCE:.3}; §56.5 chose \
         memoryless BECAUSE the bounded family carries a residual channel here"
    );
}

/// The weak matcher misses all of it — which is why `MatcherStrength` is a
/// permanent arm and not a detail (§56.4).
///
/// Pinned as a property because it is the instrument's own failure mode: a
/// `k = 1` matcher reported "bounded and memoryless are indistinguishable"
/// *and* read the metronome — the obvious case — at zero.
#[test]
fn the_weak_matcher_misses_what_the_strong_one_finds() {
    let weak = MatcherStrength::NearestPredicted;
    let strong = MatcherStrength::MarginalizedOverK;

    let (weak_metro, strong_metro) = (
        rate(CadenceShape::Metronome, weak, 60),
        rate(CadenceShape::Metronome, strong, 60),
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
        for b in [10_u64, 20, 30, 45, 60, 90, 150] {
            println!(
                "{b:>9}s {:>12.3} {:>14.3} {:>12.3}",
                rate(CadenceShape::BoundedUniform, matcher, b),
                rate(CadenceShape::Memoryless, matcher, b),
                rate(CadenceShape::Metronome, matcher, b),
            );
        }
    }
}

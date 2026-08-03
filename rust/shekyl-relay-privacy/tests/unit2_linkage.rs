// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//! Q-11 Unit 2: does the covert cadence's shape change linkability, and does
//! the answer depend on how strong the observer is?
#![allow(clippy::cast_precision_loss)]
use shekyl_relay_privacy::conformance::linkage::{
    simulate_cadence_linkage, CadenceShape, MatcherStrength,
};
use shekyl_relay_privacy::SplitMix64;

#[test]
fn unit2_shape_sweep() {
    const M: usize = 20;
    const TRIALS: usize = 1_500;
    for matcher in [
        MatcherStrength::NearestPredicted,
        MatcherStrength::MarginalizedOverK,
    ] {
        println!(
            "\n=== matcher: {matcher:?}   (M={M}, chance={:.3})",
            1.0 / M as f64
        );
        println!(
            "{:>10} {:>12} {:>14} {:>12}",
            "blackout", "bounded", "memoryless", "metronome"
        );
        for b in [10_u64, 20, 30, 45, 60, 90, 150] {
            let mut row = format!("{b:>9}s");
            for shape in [
                CadenceShape::BoundedUniform,
                CadenceShape::Memoryless,
                CadenceShape::Metronome,
            ] {
                let mut rng = SplitMix64::new(0x5732 + b);
                let r = simulate_cadence_linkage(shape, matcher, M, b * 1_000, TRIALS, &mut rng);
                row.push_str(&format!(" {:>13.3}", r.match_rate));
            }
            println!("{row}");
        }
    }
}

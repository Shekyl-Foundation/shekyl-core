// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//! Q-11 Unit 2: does the covert cadence's shape change linkability?
#![allow(clippy::cast_precision_loss)]
use shekyl_relay_privacy::conformance::linkage::{simulate_cadence_linkage, CadenceShape};
use shekyl_relay_privacy::SplitMix64;

#[test]
fn unit2_shape_sweep() {
    println!("\nQ-11 Unit 2 — re-identification across a blackout (matching test)");
    println!(
        "{:>14} {:>7} {:>10} {:>9} {:>10}",
        "shape", "M", "match", "chance", "advantage"
    );
    println!("{}", "-".repeat(56));
    for blackout_s in [0_u64, 30, 300] {
        println!("  blackout = {blackout_s}s");
        for (shape, name) in [
            (CadenceShape::Metronome, "Metronome"),
            (CadenceShape::BoundedUniform, "Bounded U"),
            (CadenceShape::Memoryless, "Memoryless"),
        ] {
            for m in [4_usize, 16] {
                let mut rng = SplitMix64::new(0x5732_u64 + m as u64 + blackout_s);
                let r = simulate_cadence_linkage(shape, m, blackout_s * 1_000, 4_000, &mut rng);
                println!(
                    "{name:>14} {m:>7} {:>9.3} {:>9.3} {:>+10.3}",
                    r.match_rate, r.chance, r.advantage
                );
            }
        }
    }
}

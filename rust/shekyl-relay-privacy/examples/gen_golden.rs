// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Regenerate the frozen reference values in `tests/golden_vector.rs`.
//!
//! ```text
//! cargo run -p shekyl-relay-privacy --example gen_golden
//! ```
//!
//! Emitting the values rather than hand-transcribing them keeps a re-freeze
//! from quietly introducing a typo that the vector would then enshrine. The
//! deliberate friction is that you still have to paste them: a vector that
//! rewrote itself would pass forever and pin nothing.

use shekyl_relay_privacy::{
    bounded_uniform, DandelionParams, EpochScheduler, GeometricTable, PoissonTable, RelayRng,
    SplitMix64,
};

fn main() {
    println!("// Paste into tests/golden_vector.rs, and explain what moved.\n");

    println!("Poisson tables (lambda, fingerprint, max support):");
    for lambda in [10_u32, 17, 20, 39] {
        let t = PoissonTable::new(lambda);
        println!(
            "    ({lambda}, 0x{:016x}, {}),",
            t.fingerprint(),
            t.max_support()
        );
    }

    println!("\nGeometric tables (mean in ticks, fingerprint, max support):");
    for mean in [17_u32, 32, 39, 68, 128] {
        let t = GeometricTable::new(mean);
        assert!(!t.is_truncated(), "mean={mean} clipped its tail");
        println!(
            "    ({mean}, 0x{:016x}, {}),",
            t.fingerprint(),
            t.max_support()
        );
    }

    println!("\nSplitMix64 reference sequence (seed 0x5EED_5EED):");
    let mut rng = SplitMix64::new(0x5EED_5EED);
    for _ in 0..8 {
        println!("    0x{:016x},", rng.next_u64());
    }

    println!("\nPoisson lambda=20 draw sequence (seed 0x1234_5678):");
    let t = PoissonTable::new(20);
    let mut rng = SplitMix64::new(0x1234_5678);
    let draws: Vec<u64> = (0..16).map(|_| t.draw(&mut rng)).collect();
    println!("    {draws:?}");

    println!("\nGeometric mean=68 draw sequence (seed 0x1234_5678):");
    let g = GeometricTable::new(68);
    let mut rng = SplitMix64::new(0x1234_5678);
    let draws: Vec<u64> = (0..16).map(|_| g.draw(&mut rng)).collect();
    println!("    {draws:?}");

    println!("\nUniform [0, 30000] draw sequence (seed 0xABCD):");
    let mut rng = SplitMix64::new(0xABCD);
    let draws: Vec<u64> = (0..8).map(|_| bounded_uniform(&mut rng, 30_000)).collect();
    println!("    {draws:?}");

    println!("\nEpoch sequence under inherited params (seed 0xE9C0):");
    let s = EpochScheduler::new(DandelionParams::inherited());
    let mut rng = SplitMix64::new(0xE9C0);
    for _ in 0..6 {
        let e = s.start(0, &mut rng);
        println!("    ({}, {}),", e.fluffing, e.ends_at);
    }
}

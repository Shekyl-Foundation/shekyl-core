// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Frozen reference vectors for every draw in the relay path.
//!
//! # What is frozen, and why it can be
//!
//! The inherited timers cannot have a vector like this. They draw through
//! `std::poisson_distribution` and `std::uniform_int_distribution`, both
//! implementation-defined, so the same entropy yields different sequences on
//! different standard libraries — there is nothing stable to freeze.
//!
//! The draws here are stable by construction. Both distribution tables are
//! built from a recurrence using only `+`, `*` and `/` — no `exp`, no `pow`,
//! no `ln` — all of which IEEE-754 pins exactly, and every draw after
//! construction is integer. So a table fingerprint and a draw sequence are
//! genuinely bit-identical on every platform, and this file runs on the
//! aarch64 lane as meaningfully as on x86.
//!
//! # What a failure here means
//!
//! Not "the draw is wrong" — these are reference values, not a correctness
//! oracle; `conformance_grading.rs` grades correctness. A failure means the
//! *distribution moved*, and the reader needs to know whether that was
//! intentional. Re-freezing without understanding which change moved it
//! defeats the entire point of the file.
//!
//! Regenerate with `cargo run -p shekyl-relay-privacy --example gen_golden`.

use shekyl_relay_privacy::{
    bounded_uniform, DandelionParams, EpochScheduler, GeometricTable, PoissonTable, RelayRng,
    SplitMix64,
};

/// The reference generator itself. If SplitMix64 drifts, every other vector in
/// this file moves with it, so it is pinned first and separately — a failure
/// here tells the reader to stop reading the rest.
#[test]
fn splitmix64_reference_sequence() {
    let mut rng = SplitMix64::new(0x5EED_5EED);
    let got: Vec<u64> = (0..8).map(|_| rng.next_u64()).collect();
    assert_eq!(
        got,
        vec![
            0x99a4_143d_3458_5f45,
            0xfc18_d87f_cc9c_a7a3,
            0x7220_ff96_60d1_3a72,
            0x64ff_c884_7b7f_23c0,
            0x9e03_b1a5_3ea6_991e,
            0x6a5c_6824_6b38_f20a,
            0x0692_240c_de3f_b540,
            0xf490_46fa_81c7_12b0,
        ]
    );
}

/// Poisson tables for every λ the relay path uses: the two fluff delays
/// (λ = 20 and 10 quarter-seconds), the derived embargo (17 s) and the
/// inherited one (39 s).
#[test]
fn poisson_table_fingerprints() {
    let cases: [(u32, u64, u64); 4] = [
        // (λ, fingerprint, max support)
        (10, 0x6b79_4da0_b9b0_a3e1, 55),
        (17, 0x2448_f2d6_e64e_74d7, 72),
        (20, 0x9df3_bf63_a533_8890, 78),
        (39, 0x178a_f2fe_01a6_b2b1, 115),
    ];
    for (lambda, fingerprint, support) in cases {
        let t = PoissonTable::new(lambda);
        assert_eq!(
            t.fingerprint(),
            fingerprint,
            "Poisson λ={lambda} table moved (got 0x{:016x})",
            t.fingerprint()
        );
        assert_eq!(t.max_support(), support, "Poisson λ={lambda} support moved");
    }
}

/// Geometric tables at the means the measurement harness exercises, including
/// the quarter-second-tick embargo (17 s = 68 ticks).
#[test]
fn geometric_table_fingerprints() {
    let cases: [(u32, u64, u64); 5] = [
        // (mean in ticks, fingerprint, max support)
        (17, 0x37c9_70f5_8b5e_5141, 486),
        (32, 0xa2e7_6861_23cb_ca78, 902),
        (39, 0xd855_2540_9074_7cf6, 1_096),
        (68, 0x5218_f6b9_0678_3524, 1_900),
        (128, 0x41d2_651a_a919_b265, 3_563),
    ];
    for (mean, fingerprint, support) in cases {
        let t = GeometricTable::new(mean);
        assert_eq!(
            t.fingerprint(),
            fingerprint,
            "geometric mean={mean} table moved (got 0x{:016x})",
            t.fingerprint()
        );
        assert_eq!(
            t.max_support(),
            support,
            "geometric mean={mean} support moved"
        );
        assert!(
            !t.is_truncated(),
            "geometric mean={mean} table is tail-clipped — the vector would pin a biased draw"
        );
    }
}

/// A realized draw sequence, not just a table fingerprint. The fingerprint
/// pins the distribution; this pins that the *draw* reads it correctly — a
/// binary-search or clamping bug would leave the fingerprint untouched.
#[test]
fn poisson_draw_sequence() {
    let t = PoissonTable::new(20);
    let mut rng = SplitMix64::new(0x1234_5678);
    let got: Vec<u64> = (0..16).map(|_| t.draw(&mut rng)).collect();
    assert_eq!(
        got,
        vec![17, 25, 16, 17, 14, 25, 20, 21, 19, 20, 21, 19, 26, 20, 26, 21]
    );
}

/// The same for the geometric draw, at the 68-tick (17 s at a quarter-second
/// tick) embargo mean. Note how much wider the spread is than the Poisson
/// sequence above at a comparable mean — that difference is finding 2, visible
/// in the raw numbers.
#[test]
fn geometric_draw_sequence() {
    let g = GeometricTable::new(68);
    let mut rng = SplitMix64::new(0x1234_5678);
    let got: Vec<u64> = (0..16).map(|_| g.draw(&mut rng)).collect();
    assert_eq!(
        got,
        vec![17, 142, 14, 19, 6, 129, 49, 66, 35, 47, 68, 36, 152, 47, 152, 56]
    );
}

/// The unbiased uniform over the epoch-jitter range.
#[test]
fn uniform_draw_sequence() {
    let mut rng = SplitMix64::new(0xABCD);
    let got: Vec<u64> = (0..8).map(|_| bounded_uniform(&mut rng, 30_000)).collect();
    assert_eq!(
        got,
        vec![22_110, 28_130, 27_626, 7_664, 14_469, 24_968, 15_332, 10_176]
    );
}

/// End to end: six consecutive epochs under the inherited parameters, pinning
/// both the fluff coin and the jittered boundary together. This is the
/// composed behaviour, so it catches a change in draw *ordering* that no
/// single-quantity vector above would see.
#[test]
fn epoch_sequence() {
    let s = EpochScheduler::new(DandelionParams::inherited());
    let mut rng = SplitMix64::new(0xE9C0);
    let got: Vec<(bool, u64)> = (0..6)
        .map(|_| {
            let e = s.start(0, &mut rng);
            (e.fluffing, e.ends_at)
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (true, 619_821),
            (false, 627_377),
            (false, 628_630),
            (false, 619_005),
            (false, 623_339),
            (true, 605_227),
        ]
    );
    // Every boundary must land inside the configured band, independent of the
    // frozen values — a vector that pins an out-of-band value is worse than no
    // vector at all.
    for (_, ends_at) in &got {
        assert!(
            (600_000..=630_000).contains(ends_at),
            "epoch end {ends_at} out of band"
        );
    }
}

/// The parameter derivation is part of the frozen surface: if someone changes
/// `EMBARGO_FULL_TRAVEL_PROBABILITY` or the formula, the derived embargo moves
/// and this says so.
#[test]
fn derived_parameters() {
    let p = DandelionParams::inherited();
    assert!((p.expected_stem_length() - 5.0).abs() < 1e-12);
    assert_eq!(p.closed_form_embargo_secs(), 17);
    assert_eq!(p.stem_count(), 2);
    assert_eq!(DandelionParams::INHERITED_EMBARGO_SECS, 39);
}

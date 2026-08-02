// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Goodness-of-fit grades for every randomized quantity in the relay path,
//! each paired with a **negative control** that proves the instrument bites.
//!
//! A conformance test that only ever sees correct input is decoration: it
//! passes whether or not it can detect anything. Every grade below is run
//! twice — once against the real draw, which must pass, and once against a
//! deliberately corrupted draw, which must fail. Without the second half there
//! is no evidence the first half means anything.
//!
//! This is the test surface the inherited C++ has no counterpart for at any
//! strength: `tests/unit_tests/levin.cpp` cancels every timer before it can
//! elapse, so no delay is ever observed, let alone graded.

#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use shekyl_relay_privacy::conformance::{
    grade_bernoulli, grade_poisson, grade_stem_balance, grade_uniform, sample_poisson,
    sample_uniform,
};
use shekyl_relay_privacy::params::inherited;
use shekyl_relay_privacy::{
    bernoulli, ConnectionId, DandelionParams, EpochScheduler, NoiseCadence, PoissonTable, RelayRng,
    SplitMix64, StemMap,
};

const N: usize = 200_000;

/// An RNG with deliberate modulo bias, for the uniform negative control: it
/// takes the low bits of a counter rather than a uniform word, so residues are
/// not equiprobable over a range that does not divide the period.
struct BiasedRng {
    inner: SplitMix64,
}

impl RelayRng for BiasedRng {
    fn next_u64(&mut self) -> u64 {
        // Squash the top bits: the result is uniform over a 2^32 window, so
        // `% range` for a non-power-of-two range over-weights low residues in
        // a way the rejection sampler is designed to prevent.
        self.inner.next_u64() >> 32
    }
}

#[test]
fn poisson_draws_match_their_claimed_distribution() {
    for lambda in [10_u32, 17, 20, 39] {
        let table = PoissonTable::new(lambda);
        let mut rng = SplitMix64::new(0x0F01 + u64::from(lambda));
        let samples = sample_poisson(&table, N, &mut rng);
        let g = grade_poisson(&samples, lambda);
        assert!(
            g.passed,
            "λ={lambda}: chi-square {:.2} exceeded critical {:.2} at {} df",
            g.statistic, g.critical, g.degrees_of_freedom
        );
    }
}

#[test]
fn poisson_grade_rejects_a_shifted_distribution() {
    // Negative control: draw from λ=20 but grade against λ=17. A one-unit
    // shift in the mean is a subtle error, and the instrument must still see
    // it at this sample size.
    let table = PoissonTable::new(20);
    let mut rng = SplitMix64::new(4242);
    let samples = sample_poisson(&table, N, &mut rng);
    let g = grade_poisson(&samples, 17);
    assert!(
        !g.passed,
        "grading λ=20 samples against λ=17 passed with statistic {:.2} \
         (critical {:.2}) — the instrument cannot detect a shifted mean",
        g.statistic, g.critical
    );
}

#[test]
fn uniform_draws_are_unbiased() {
    // The epoch jitter range: 30 seconds in milliseconds. Not a power of two,
    // which is precisely when modulo bias would show.
    let max = u64::from(DandelionParams::inherited().epoch_jitter_secs) * 1_000;
    let mut rng = SplitMix64::new(777);
    let samples = sample_uniform(max, N, &mut rng);
    let g = grade_uniform(&samples, max, 60);
    assert!(
        g.passed,
        "epoch jitter failed uniformity: {:.2} > {:.2}",
        g.statistic, g.critical
    );
}

#[test]
fn uniform_grade_rejects_modulo_bias() {
    // Negative control: a range chosen so that truncating to 32 bits leaves a
    // visibly uneven residue distribution.
    let max = (1_u64 << 32) / 3 * 2; // ~2.86e9, does not divide 2^32
    let mut rng = BiasedRng {
        inner: SplitMix64::new(31337),
    };
    let samples: Vec<u64> = (0..N).map(|_| rng.next_u64() % (max + 1)).collect();
    let g = grade_uniform(&samples, max, 60);
    assert!(
        !g.passed,
        "modulo-biased sample passed uniformity with {:.2} (critical {:.2}) — \
         the instrument cannot detect the bias the rejection sampler prevents",
        g.statistic, g.critical
    );
}

#[test]
fn fluff_coin_matches_its_rate() {
    let params = DandelionParams::inherited();
    let scheduler = EpochScheduler::new(params);
    let mut rng = SplitMix64::new(0x0C01);
    let trials = N;
    let fluffing = (0..trials)
        .filter(|_| scheduler.start(0, &mut rng).fluffing)
        .count();
    let g = grade_bernoulli(
        fluffing,
        trials,
        u64::from(params.fluff_probability_pct),
        100,
    );
    assert!(
        g.passed,
        "fluff coin rate off: {fluffing}/{trials}, chi-square {:.2} > {:.2}",
        g.statistic, g.critical
    );
}

#[test]
fn bernoulli_grade_rejects_a_wrong_rate() {
    // Negative control: draw at 20%, grade against 25%.
    let mut rng = SplitMix64::new(0xBEEF);
    let trials = N;
    let hits = (0..trials).filter(|_| bernoulli(&mut rng, 20, 100)).count();
    let g = grade_bernoulli(hits, trials, 25, 100);
    assert!(
        !g.passed,
        "20% sample graded against 25% passed with {:.2} (critical {:.2})",
        g.statistic, g.critical
    );
}

#[test]
fn stem_selection_balances_across_slots() {
    // Many independent epochs, each assigning a fresh set of sources; the
    // aggregate usage across slots must be even.
    let mut rng = SplitMix64::new(0x57EA);
    let mut totals = vec![0_usize; 2];
    for epoch in 0..2_000_u32 {
        let peers: Vec<ConnectionId> = (0..16_u8)
            .map(|i| {
                let mut b = [0_u8; 16];
                b[0] = i;
                b[1] = (epoch & 0xff) as u8;
                b[2] = (epoch >> 8) as u8;
                ConnectionId::from_bytes(b)
            })
            .collect();
        let mut map = StemMap::new(peers.clone(), 2, &mut rng);
        for p in &peers {
            let _ = map.stem_for(Some(*p), &mut rng);
        }
        for (slot, used) in map.usage().iter().enumerate() {
            totals[slot] += used;
        }
    }
    let g = grade_stem_balance(&totals);
    assert!(
        g.passed,
        "stem usage unbalanced across slots {totals:?}: {:.2} > {:.2}",
        g.statistic, g.critical
    );
}

#[test]
fn stem_balance_grade_rejects_a_skewed_map() {
    // Negative control: a 55/45 split over the same total. Lowest-usage
    // selection should never produce this, and the grade must say so.
    let total = 40_000_usize;
    let skewed = vec![total * 55 / 100, total * 45 / 100];
    let g = grade_stem_balance(&skewed);
    assert!(
        !g.passed,
        "a 55/45 stem split passed the balance grade with {:.2} (critical {:.2})",
        g.statistic, g.critical
    );
}

#[test]
fn fluff_delay_draws_match_their_claimed_means() {
    // Both fluff tables, graded against the λ the design states for each.
    for (lambda, label) in [
        (inherited::FLUFF_AVERAGE_IN_QUARTER_SECS, "inbound"),
        (inherited::FLUFF_AVERAGE_OUT_QUARTER_SECS, "outbound"),
    ] {
        let table = PoissonTable::new(lambda);
        let mut rng = SplitMix64::new(0xF10F + u64::from(lambda));
        let samples = sample_poisson(&table, N, &mut rng);
        let g = grade_poisson(&samples, lambda);
        assert!(
            g.passed,
            "{label} fluff delay (λ={lambda}) failed: {:.2} > {:.2}",
            g.statistic, g.critical
        );
    }
}

/// The covert cadence's jitter, graded **through production** — every sample
/// below is a real [`NoiseCadence::next_send`] draw, not a conformance-helper
/// draw.
///
/// **Re-aimed at Q-11 Unit 0, and the history is the warning.** This test's
/// first version called `sample_uniform` — the conformance crate's own
/// helper — so it graded the grader's sampler against the grader while
/// production was never in the loop: deleting `next_send`'s randomness
/// entirely left it green, in the one test whose name claims to grade the
/// cadence, in a file whose own module doc demands production draws.
/// Vacuous by missing input, and invisible until the reference census walked
/// every `NoiseCadence` consumer in the tree and found none that graded it.
///
/// Verified at re-aim (run and observed to fail): pinning `next_send`'s
/// jitter to a constant fails this grade. Note what the landed controls below
/// are NOT: `BiasedRng` through `next_send` — `bounded_uniform` is a
/// rejection sampler, and rejection launders **modulo bias specifically**
/// (the truncation-residue class `BiasedRng` manufactures), so that control
/// would pass. This is not a claim that no RNG-level control can bite the
/// production path: a generator with structured word output — even-only
/// words, say — survives rejection and skews the residues. `BiasedRng` is
/// the wrong control here; the landed pair are the wrong-band grade and the
/// wrong-family grade.
/// Shared setup for the three cadence-jitter grades: the inherited cadence,
/// its deterministic offset (min delay, ms), the jitter band top (ms), and the
/// seeded RNG every cadence grade draws from — one place, so the three tests
/// cannot drift onto different bands or seeds.
fn cadence_jitter_setup() -> (NoiseCadence, u64, u64, SplitMix64) {
    (
        NoiseCadence::inherited(),
        u64::from(inherited::NOISE_MIN_DELAY_SECS) * 1_000,
        u64::from(inherited::NOISE_DELAY_JITTER_SECS) * 1_000,
        SplitMix64::new(0x0157),
    )
}

#[test]
fn noise_cadence_jitter_is_uniform() {
    let (c, min_ms, max, mut rng) = cadence_jitter_setup();
    // `next_send(from)` = from + min_delay + jitter; subtracting the
    // deterministic part leaves the jitter draw itself, on [0, max].
    let samples: Vec<u64> = (0..N).map(|_| c.next_send(0, &mut rng) - min_ms).collect();
    let g = grade_uniform(&samples, max, 50);
    assert!(
        g.passed,
        "noise cadence jitter failed uniformity: {:.2} > {:.2}",
        g.statistic, g.critical
    );
}

#[test]
fn noise_cadence_grade_rejects_a_wrong_band() {
    // Negative control through the SAME production path as the positive
    // half: identical `next_send` draws, graded against a band 20 % wider
    // than the one the cadence actually spans. The top bins are then
    // structurally empty and the chi-square must explode — proving the
    // positive test's pass is a property of the draws matching THEIR band,
    // not of the grade passing anything it is handed. (A `BiasedRng` control
    // cannot do this job here: rejection sampling launders modulo bias
    // specifically, so `BiasedRng`'s truncation-residue skew never reaches
    // the draw — the file's existing modulo-bias control bypasses the
    // sampler for exactly that reason.)
    //
    // Band sensitivity is HALF the instrument's job; the wrong-family
    // control below is the other half.
    let (c, min_ms, max, mut rng) = cadence_jitter_setup();
    let wrong = max + max / 5;
    let samples: Vec<u64> = (0..N).map(|_| c.next_send(0, &mut rng) - min_ms).collect();
    let g = grade_uniform(&samples, wrong, 50);
    assert!(
        !g.passed,
        "production draws spanning [0, {max}] passed a grade against \
         [0, {wrong}] with statistic {:.2} (critical {:.2}) — the grade is \
         not band-sensitive",
        g.statistic, g.critical
    );
}

#[test]
fn noise_cadence_grade_rejects_right_support_wrong_family() {
    // The durable form of the injection control run at the re-aim (jitter
    // pinned to a constant — observed to fail at chi-square 9.8e6, then
    // reverted): the wrong-band control above proves BAND sensitivity only,
    // and the defect §20.9 names as the live threat is right-support,
    // wrong-FAMILY. Min-of-two production draws is that defect in the shape
    // this arc has already named — CV-3's resampling fold keeps the minimum
    // — so its support is exactly [0, max], its density is not uniform, and
    // every ingredient is a real `next_send` draw. The grade must see the
    // density skew, or the positive test above is a support pin wearing a
    // distribution oracle's name.
    let (c, min_ms, max, mut rng) = cadence_jitter_setup();
    let samples: Vec<u64> = (0..N)
        .map(|_| {
            let a = c.next_send(0, &mut rng);
            let b = c.next_send(0, &mut rng);
            a.min(b) - min_ms
        })
        .collect();
    let g = grade_uniform(&samples, max, 50);
    assert!(
        !g.passed,
        "min-of-two production draws (right support, wrong family — the CV-3 \
         resampling shape) passed the uniform grade with statistic {:.2} \
         (critical {:.2}) — the instrument is band-only",
        g.statistic, g.critical
    );
}

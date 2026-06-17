//! Published KAT — float goodness-of-fit grading and the self-certification
//! harness. Compiled only under the `conformance` feature; **x86-only** because
//! float is not bit-identical across architectures, so the cross-arch guarantee
//! belongs to `golden_vector.rs` (the integer sequence), not to these
//! graded-by-margin probes.
//!
//! These are the staking-sim's conformance tests, relocated and promoted into
//! the single-sourced crate: a positive uniformity check, three
//! instrument-validity negatives (the draw machinery must *reject* the
//! triangular trap, the correlated weak-PRNG walk, and the epoch-snapped anchor
//! cluster), and the RNG-generic self-certification harness a wallet runs
//! against its own CSPRNG.
#![cfg(feature = "conformance")]
#![allow(clippy::cast_precision_loss)]
// ^ test code: gap counts widen to f64 for the negative-control autocorrelation;
//   the counts are far below 2^53 so the widening is exact.

mod common;

use common::SplitMix64;
use shekyl_standoff::conformance::{
    certify_draw, chi_square_uniform, correlated_walk, draw_entry_gap_double_jitter_trap,
    grade_sample, lag1_autocorr_u64, max_bin_share, shared_anchor_population, summarize_gaps,
};
use shekyl_standoff::draw_entry_gap;
use shekyl_stats::{chi_square_upper_crit, Z_ALPHA_1E6};

#[test]
fn correct_draw_is_well_distributed() {
    // A large sample of the realized (spread, order) must be uniform in spread
    // and balanced in order — well-distributed, not merely within ±window.
    let window = 600u64;
    let mut rng = SplitMix64(0xC0FF_EE12_3456_789A);
    let sample: Vec<(u64, bool)> = (0..200_000)
        .map(|_| draw_entry_gap(window, &mut rng))
        .collect();
    let st = summarize_gaps(&sample, window);
    assert!(
        (st.mean_spread - 300.0).abs() < 6.0,
        "mean_spread = {}",
        st.mean_spread
    );
    assert!(
        (st.bond_first_frac - 0.5).abs() < 0.01,
        "order = {}",
        st.bond_first_frac
    );
    assert!(
        (st.first_decile_frac - 0.10).abs() < 0.01,
        "first decile = {}",
        st.first_decile_frac
    );
    assert!(
        st.max_decile_dev < 0.02,
        "max decile dev = {}",
        st.max_decile_dev
    );
    assert_eq!(st.max_spread, window);
}

#[test]
fn double_jitter_trap_fails_the_same_check() {
    // The triangular trap satisfies the ±window bound but its separation is
    // zero-peaked; the conformance summary must reject it.
    let window = 600u64;
    let mut rng = SplitMix64(0xC0FF_EE12_3456_789A);
    let sample: Vec<(u64, bool)> = (0..200_000)
        .map(|_| draw_entry_gap_double_jitter_trap(window, &mut rng))
        .collect();
    let st = summarize_gaps(&sample, window);
    assert!(
        st.mean_spread < 250.0,
        "trap mean_spread = {} (should be << 300)",
        st.mean_spread
    );
    assert!(
        st.first_decile_frac > 0.15,
        "trap first decile = {} (should spike)",
        st.first_decile_frac
    );
    assert!(
        st.max_decile_dev > 0.05,
        "trap max decile dev = {}",
        st.max_decile_dev
    );
    // The order coin can still look fair — order-balance alone is insufficient.
    assert!(
        (st.bond_first_frac - 0.5).abs() < 0.02,
        "trap order = {}",
        st.bond_first_frac
    );
}

#[test]
fn chi_square_grades_uniform_at_strict_alpha() {
    // Discrete chi-square at a strict alpha: a correct draw sits well under the
    // gate; the triangular trap fails by orders of magnitude.
    let window = 600u64;
    let n_bins = 60;
    let crit = chi_square_upper_crit((n_bins - 1) as f64, Z_ALPHA_1E6);
    let mut rng = SplitMix64(0x5EED_1234_ABCD_0001);
    let good: Vec<(u64, bool)> = (0..200_000)
        .map(|_| draw_entry_gap(window, &mut rng))
        .collect();
    let bad: Vec<(u64, bool)> = (0..200_000)
        .map(|_| draw_entry_gap_double_jitter_trap(window, &mut rng))
        .collect();
    let chi_good = chi_square_uniform(&good, window, n_bins);
    let chi_bad = chi_square_uniform(&bad, window, n_bins);
    assert!(
        chi_good < crit,
        "correct chi2 {chi_good} should be < crit {crit}"
    );
    assert!(
        chi_bad > 10.0 * crit,
        "trap chi2 {chi_bad} should blow past crit {crit}"
    );
}

#[test]
fn population_anchor_independence_disperses_shared_trigger_clusters() {
    // The catastrophic mode the marginal cannot see: the gap is drawn correctly
    // in both arms; only the anchor differs. Independent intents disperse the
    // absolute bond times; an epoch-snapped population piles into one bin.
    let window = 600u64;
    let span = 1_000_000u64;
    let bin = 4 * window; // >= the inversion search width, so a cluster sits in one bin
    let boundary = 120_000u64; // a multiple of bin ⇒ the cluster sits cleanly inside it
    let n = 5_000usize;
    let mut rng = SplitMix64(0xA11C_E5B0_1234_5678);
    let indep = shared_anchor_population(&mut rng, window, span, boundary, false, n);
    let shared = shared_anchor_population(&mut rng, window, span, boundary, true, n);
    let share_indep = max_bin_share(&indep, bin);
    let share_shared = max_bin_share(&shared, bin);
    assert!(
        share_indep < 0.05,
        "independent anchors should disperse, got {share_indep}"
    );
    assert!(
        share_shared > 0.9,
        "shared trigger should cluster, got {share_shared}"
    );
}

#[test]
fn serial_independence_reference_passes_correlated_fails() {
    // A weak PRNG can yield a uniform marginal with correlated successive draws
    // — invisible to a marginal GoF, linkable across a P's recurring bond ops.
    // The lag-1 probe sees it; the reference draw passes.
    let window = 600u64;
    let m = 20_000usize;
    let mut rng = SplitMix64(0x5E11_A1B2_C3D4_E5F6);
    let reference: Vec<u64> = (0..m).map(|_| draw_entry_gap(window, &mut rng).0).collect();
    let correlated = correlated_walk(&mut rng, window, m);
    let r_ref = lag1_autocorr_u64(&reference).abs();
    let r_corr = lag1_autocorr_u64(&correlated).abs();
    assert!(
        r_ref < 0.05,
        "reference lag-1 autocorr {r_ref} should be ~0"
    );
    assert!(
        r_corr > 0.5,
        "correlated lag-1 autocorr {r_corr} should be large"
    );
}

#[test]
fn self_cert_passes_reference_rng() {
    // The RNG-generic self-certification a wallet runs against its own CSPRNG:
    // the reference stream passes all three property grades.
    let mut rng = SplitMix64(0x90DE_4242_7777_0001);
    let report = certify_draw(&mut rng, 600, 200_000);
    assert!(report.uniform_ok, "uniform grade failed: {report:?}");
    assert!(report.order_balanced, "order grade failed: {report:?}");
    assert!(report.serial_independent, "serial grade failed: {report:?}");
    assert!(report.passed(), "overall self-cert failed: {report:?}");
}

#[test]
fn self_cert_rejects_trap_and_correlated_samples() {
    // grade_sample on a non-conforming sample must fail the relevant property —
    // the negatives a wallet test reuses to prove its grader bites.
    let window = 600u64;
    let mut rng = SplitMix64(0x90DE_4242_7777_0002);

    // Triangular trap: spread is non-uniform.
    let trap: Vec<(u64, bool)> = (0..200_000)
        .map(|_| draw_entry_gap_double_jitter_trap(window, &mut rng))
        .collect();
    let trap_report = grade_sample(&trap, window);
    assert!(
        !trap_report.uniform_ok,
        "trap should fail uniformity: {trap_report:?}"
    );
    assert!(
        !trap_report.passed(),
        "trap should not pass self-cert: {trap_report:?}"
    );

    // Correlated walk paired with a fair coin: marginal ~uniform, serial-dependent.
    let walk = correlated_walk(&mut rng, window, 20_000);
    let correlated: Vec<(u64, bool)> = walk.iter().map(|&s| (s, true)).collect();
    let corr_report = grade_sample(&correlated, window);
    assert!(
        !corr_report.serial_independent,
        "correlated should fail serial: {corr_report:?}"
    );
    assert!(
        !corr_report.passed(),
        "correlated should not pass self-cert: {corr_report:?}"
    );
}

#[test]
fn empty_sample_summary_does_not_manufacture_a_shape() {
    // An empty sample has no distribution; the summary must report explicit zeros
    // rather than the `denom = 1.0` fallback artifact (which read `max_decile_dev`
    // as 0.10 — a real-looking failing shape — for no data). Copilot PR#150.
    let st = summarize_gaps(&[], 600);
    assert_eq!(st.n, 0);
    assert_eq!(st.mean_spread, 0.0);
    assert_eq!(st.max_spread, 0);
    assert_eq!(st.bond_first_frac, 0.0);
    assert_eq!(st.first_decile_frac, 0.0);
    assert_eq!(
        st.max_decile_dev, 0.0,
        "empty sample must not report a non-zero decile deviation"
    );
}

#[test]
fn no_observations_cannot_claim_uniformity() {
    // A chi-square uniformity claim needs observations: an empty (or single-point)
    // sample gives chi-square 0, which clears the critical value and would otherwise
    // report `uniform_ok = true` for no data — a false positive. Copilot PR#150.
    let window = 600u64;
    let empty = grade_sample(&[], window);
    assert!(
        !empty.uniform_ok,
        "empty sample must not claim uniformity: {empty:?}"
    );
    assert!(
        !empty.passed(),
        "empty sample must not self-certify: {empty:?}"
    );

    let single = grade_sample(&[(123u64, true)], window);
    assert!(
        !single.uniform_ok,
        "a single draw cannot evidence a distribution shape: {single:?}"
    );
    assert!(
        !single.passed(),
        "single-sample must not self-certify: {single:?}"
    );
}

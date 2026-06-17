//! Generic goodness-of-fit (GoF) instruments over plain sample slices.
//!
//! Dependency-free statistical primitives shared by Shekyl's simulation and
//! conformance harnesses: the Wilson-Hilferty chi-square upper-tail critical
//! value, a discrete-uniform chi-square statistic over a histogram, and a
//! lag-1 autocorrelation. None of these carry domain semantics — there is no
//! standoff, label, or funding-seam vocabulary here. This is the
//! topic-coherent home for reusable GoF math (rule 18 type-placement): a
//! consumer such as `shekyl-standoff` (funding-seam conformance) or
//! `shekyl-crypto-pq` (label-indistinguishability test) depends on
//! *statistics*, not on another consumer's domain crate.
//!
//! These are statistics utilities, never a production hot path; the crate
//! honestly carries its float-cast allow at the crate boundary rather than
//! claiming a pure-integer contract it does not need.
#![allow(clippy::cast_precision_loss)]
// ^ sample counts (`u64`/`usize`) widen to `f64` in the GoF sums; the counts
//   are far below 2^53, so the widening is exact in practice and the precision
//   note is immaterial. This is the only float-cast class the crate uses.

/// Upper-tail standard-normal quantile for alpha = 1e-6 (z ~ 4.7534).
///
/// This is the strict **conformance-gate** alpha: chosen so a correct sample
/// never false-fails against a *gross* antipattern (the deviations the gate
/// exists to catch exceed the critical value by orders of magnitude, so the
/// margin is free). It is **not** tuned for statistical power against subtle
/// bias — a test guarding against a small derivation bias would want a
/// less-strict (more powerful) alpha. A consumer reusing this constant should
/// confirm 1e-6 matches its test's actual sensitivity need rather than
/// inheriting it by convenience.
pub const Z_ALPHA_1E6: f64 = 4.753_424;

/// Wilson-Hilferty chi-square upper-tail critical value for `df` degrees of
/// freedom at normal upper quantile `z`. Dependency-free and accurate well
/// past the margin a strict alpha needs. Reject the null hypothesis (e.g.
/// uniformity) when an observed statistic exceeds this value.
#[must_use]
pub fn chi_square_upper_crit(df: f64, z: f64) -> f64 {
    // `df` is degrees of freedom (>= 1 in all valid use: `k - 1` for `k >= 2` bins).
    // A non-positive or NaN `df` is a caller bug; return NaN so a downstream
    // `statistic < crit` comparison is `false` — the conformance cert fails closed
    // rather than passing on a bogus (infinite/NaN) critical value.
    if df <= 0.0 || df.is_nan() {
        return f64::NAN;
    }
    let a = 2.0 / (9.0 * df);
    let t = 1.0 - a + z * a.sqrt();
    df * t * t * t
}

/// Pearson chi-square statistic for a histogram against the **discrete uniform**
/// over its bins: `sum (oi - n/k)^2 / (n/k)`, where `k = observed.len()` and
/// `n = sum oi`. Degrees of freedom are `k - 1`; reject uniformity when the
/// statistic exceeds [`chi_square_upper_crit`]`(k - 1, z)`.
///
/// Returns `0.0` for a histogram with fewer than two bins or zero total count
/// (no uniformity question to ask).
#[must_use]
pub fn chi_square_uniform_counts(observed: &[u64]) -> f64 {
    let k = observed.len();
    if k < 2 {
        return 0.0;
    }
    let n: u64 = observed.iter().sum();
    if n == 0 {
        return 0.0;
    }
    let expected = n as f64 / k as f64;
    observed
        .iter()
        .map(|&o| {
            let d = o as f64 - expected;
            d * d / expected
        })
        .sum()
}

/// Lag-1 autocorrelation of a real-valued series — the serial-independence
/// probe. Approximately `0` (order `1/sqrt(m)`) for independent draws; large in
/// magnitude for a correlated sequence (e.g. a weak-PRNG walk) even when its
/// marginal distribution is uniform, which a marginal goodness-of-fit cannot
/// see. Returns `0.0` for a series shorter than two elements or with zero
/// variance.
#[must_use]
pub fn lag1_autocorr(series: &[f64]) -> f64 {
    let m = series.len();
    if m < 2 {
        return 0.0;
    }
    let mean = series.iter().sum::<f64>() / m as f64;
    let mut num = 0.0_f64;
    let mut den = 0.0_f64;
    for w in series.windows(2) {
        let d = w[0] - mean;
        den += d * d;
        num += d * (w[1] - mean);
    }
    // `windows(2)` omits the final element's own deviation from `den`.
    let last = series[m - 1] - mean;
    den += last * last;
    if den <= 0.0 {
        return 0.0;
    }
    num / den
}

#[cfg(test)]
mod tests {
    // These functions document *exact* `0.0` returns for degenerate inputs
    // (empty/short/zero-variance), so the tests assert exact equality with 0.0.
    #![allow(clippy::float_cmp)]
    use super::*;

    #[test]
    fn critical_value_matches_known_df255_alpha1e6() {
        // df = 255, alpha = 1e-6 -> ~377.3 (the label-indistinguishability gate).
        let crit = chi_square_upper_crit(255.0, Z_ALPHA_1E6);
        assert!((crit - 377.3).abs() < 1.0, "crit = {crit}");
    }

    #[test]
    fn critical_value_fails_closed_for_invalid_df() {
        // A non-positive or NaN `df` is a caller bug; the critical value must be NaN
        // so a downstream `statistic < crit` comparison is false (cert fails closed).
        // NaN crit makes any `statistic < crit` false (a language guarantee), so a
        // downstream uniformity check fails closed rather than passing on a bogus value.
        assert!(chi_square_upper_crit(0.0, Z_ALPHA_1E6).is_nan());
        assert!(chi_square_upper_crit(-1.0, Z_ALPHA_1E6).is_nan());
        assert!(chi_square_upper_crit(f64::NAN, Z_ALPHA_1E6).is_nan());
    }

    #[test]
    fn uniform_counts_zero_for_degenerate_inputs() {
        assert_eq!(chi_square_uniform_counts(&[]), 0.0);
        assert_eq!(chi_square_uniform_counts(&[5]), 0.0);
        assert_eq!(chi_square_uniform_counts(&[0, 0, 0]), 0.0);
    }

    #[test]
    fn uniform_counts_zero_for_flat_histogram() {
        assert_eq!(chi_square_uniform_counts(&[10, 10, 10, 10]), 0.0);
    }

    #[test]
    fn uniform_counts_large_for_skewed_histogram() {
        // All mass in one bin of four -> 3*expected^2/expected + (n-e)^2/e.
        let chi = chi_square_uniform_counts(&[400, 0, 0, 0]);
        assert!(chi > 100.0, "chi = {chi}");
    }

    #[test]
    fn lag1_zero_for_short_or_constant() {
        assert_eq!(lag1_autocorr(&[]), 0.0);
        assert_eq!(lag1_autocorr(&[1.0]), 0.0);
        assert_eq!(lag1_autocorr(&[3.0, 3.0, 3.0]), 0.0);
    }

    #[test]
    fn lag1_negative_for_alternating_series() {
        let series = [0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0];
        assert!(lag1_autocorr(&series) < -0.5);
    }

    #[test]
    fn lag1_positive_for_monotone_series() {
        let series: Vec<f64> = (0..100).map(f64::from).collect();
        assert!(lag1_autocorr(&series) > 0.9);
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Diagnostic-only float math; excluded from the default build.

use shekyl_stats::{chi_square_counts_expected, chi_square_upper_crit, Z_ALPHA_1E6};

#[derive(Debug, Clone, PartialEq)]
pub struct Grade {
    /// Realized chi-square statistic.
    pub statistic: f64,
    /// Critical value at the gate's alpha.
    pub critical: f64,
    /// Degrees of freedom the statistic was computed over.
    pub degrees_of_freedom: usize,
    /// True when the sample is consistent with the claimed distribution.
    pub passed: bool,
}

impl Grade {
    fn new(statistic: f64, degrees_of_freedom: usize) -> Self {
        let critical = chi_square_upper_crit(degrees_of_freedom as f64, Z_ALPHA_1E6);
        Self {
            statistic,
            critical,
            degrees_of_freedom,
            passed: statistic.is_finite() && statistic <= critical,
        }
    }
}

/// Minimum expected count per bin for the chi-square approximation to hold.
/// Bins thinner than this are pooled into their neighbours.
const MIN_EXPECTED: f64 = 5.0;

/// Grade a sample of [`PoissonTable`] draws against the ideal Poisson pmf for
/// `lambda`.
///
/// This is the test the inherited `std::poisson_distribution` never gets: it
/// asserts that what the timer actually draws is the distribution the design
/// says it draws. Bins with an expected count below [`MIN_EXPECTED`] are
/// pooled from both tails inward.
///
/// # Panics
///
/// Panics if `samples` is empty — there is no distribution to grade.
#[must_use]
pub fn grade_poisson(samples: &[u64], lambda: u32) -> Grade {
    assert!(!samples.is_empty(), "cannot grade an empty sample");
    let n = samples.len() as f64;
    let lam = f64::from(lambda);

    // Ideal pmf by the same recurrence the table uses, normalized over a
    // support wide enough that the truncated mass is negligible.
    let max_k = samples
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
        .max(u64::from(lambda) * 4);
    let support = usize::try_from(max_k)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let mut weights = Vec::with_capacity(support);
    let mut w = 1.0_f64;
    weights.push(w);
    for k in 1..support {
        w = w * lam / (k as f64);
        weights.push(w);
    }
    let total: f64 = weights.iter().sum();

    let mut observed = vec![0_u64; support];
    for s in samples {
        let idx = usize::try_from(*s).unwrap_or(support - 1).min(support - 1);
        observed[idx] += 1;
    }
    let expected: Vec<f64> = weights.iter().map(|w| w / total * n).collect();

    let (obs, exp) = pool_thin_bins(&observed, &expected);
    let statistic = chi_square_counts_expected(&obs, &exp);
    // One constraint: the sample size is fixed. lambda is not estimated from
    // the sample, it is the claim under test, so it costs no further df.
    Grade::new(statistic, exp.len().saturating_sub(1))
}

/// Grade a sample of [`bounded_uniform`] draws over `[0, max]` for uniformity.
///
/// Applied to the epoch jitter and the noise cadence: a skewed offset is a
/// fingerprint, and modulo bias is exactly the failure mode the rejection
/// sampler exists to prevent.
///
/// # Panics
///
/// Panics if `samples` is empty or `bins` is zero.
#[must_use]
pub fn grade_uniform(samples: &[u64], max: u64, bins: usize) -> Grade {
    assert!(!samples.is_empty(), "cannot grade an empty sample");
    assert!(bins > 0, "need at least one bin");
    let range = max.saturating_add(1);
    let bins = bins.min(usize::try_from(range).unwrap_or(bins));

    let mut observed = vec![0_u64; bins];
    for s in samples {
        // Scale into bins without overflowing: u128 keeps the product exact.
        let idx = ((u128::from(*s) * bins as u128) / u128::from(range)) as usize;
        observed[idx.min(bins - 1)] += 1;
    }
    let per_bin = samples.len() as f64 / bins as f64;
    let expected = vec![per_bin; bins];
    let statistic = chi_square_counts_expected(&observed, &expected);
    Grade::new(statistic, bins.saturating_sub(1))
}

/// Grade a Bernoulli sample (the per-epoch fluff coin) against its claimed
/// rate `numerator / denominator`.
///
/// # Panics
///
/// Panics if `trials` is zero or `denominator` is zero.
#[must_use]
pub fn grade_bernoulli(successes: usize, trials: usize, numerator: u64, denominator: u64) -> Grade {
    assert!(trials > 0, "cannot grade zero trials");
    assert!(denominator > 0, "rate denominator must be non-zero");
    let p = numerator as f64 / denominator as f64;
    let n = trials as f64;
    let observed = [successes as u64, (trials - successes) as u64];
    let expected = [n * p, n * (1.0 - p)];
    let statistic = chi_square_counts_expected(&observed, &expected);
    Grade::new(statistic, 1)
}

/// Grade stem-slot usage for balance.
///
/// Lowest-usage selection with a random tiebreak should spread sources evenly
/// across live slots. A slot that accumulates sources is a better guess for an
/// adversary correlating stem traffic, so imbalance is a privacy finding, not
/// a performance one.
///
/// # Panics
///
/// Panics if `usage` is empty.
#[must_use]
pub fn grade_stem_balance(usage: &[usize]) -> Grade {
    assert!(!usage.is_empty(), "cannot grade an empty stem map");
    let observed: Vec<u64> = usage.iter().map(|u| *u as u64).collect();
    let total: u64 = observed.iter().sum();
    let per_slot = total as f64 / usage.len() as f64;
    let expected = vec![per_slot; usage.len()];
    let statistic = chi_square_counts_expected(&observed, &expected);
    Grade::new(statistic, usage.len().saturating_sub(1))
}

/// Pool bins whose expected count falls below [`MIN_EXPECTED`] into their
/// neighbours, working inward from both tails.
fn pool_thin_bins(observed: &[u64], expected: &[f64]) -> (Vec<u64>, Vec<f64>) {
    debug_assert_eq!(observed.len(), expected.len());
    let mut lo = 0_usize;
    let mut hi = expected.len();

    let mut head_obs = 0_u64;
    let mut head_exp = 0.0_f64;
    while lo < hi && head_exp + expected[lo] < MIN_EXPECTED {
        head_obs += observed[lo];
        head_exp += expected[lo];
        lo += 1;
    }
    let mut tail_obs = 0_u64;
    let mut tail_exp = 0.0_f64;
    while hi > lo && tail_exp + expected[hi - 1] < MIN_EXPECTED {
        tail_obs += observed[hi - 1];
        tail_exp += expected[hi - 1];
        hi -= 1;
    }

    let mut obs = Vec::with_capacity(hi - lo + 2);
    let mut exp = Vec::with_capacity(hi - lo + 2);
    if head_exp > 0.0 {
        obs.push(head_obs);
        exp.push(head_exp);
    }
    obs.extend_from_slice(&observed[lo..hi]);
    exp.extend_from_slice(&expected[lo..hi]);
    if tail_exp > 0.0 {
        obs.push(tail_obs);
        exp.push(tail_exp);
    }

    // Fold a still-thin head or tail into its neighbour rather than leaving a
    // bin that violates the approximation the statistic rests on.
    if exp.len() > 1 && exp[0] < MIN_EXPECTED {
        let (o, e) = (obs.remove(0), exp.remove(0));
        obs[0] += o;
        exp[0] += e;
    }
    if exp.len() > 1 && exp[exp.len() - 1] < MIN_EXPECTED {
        let (o, e) = (obs.pop().unwrap(), exp.pop().unwrap());
        *obs.last_mut().unwrap() += o;
        *exp.last_mut().unwrap() += e;
    }

    (obs, exp)
}

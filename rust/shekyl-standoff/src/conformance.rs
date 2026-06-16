//! Standoff conformance instruments and an RNG-generic self-certification
//! harness — feature-gated (`conformance`), float-bearing, never compiled into
//! a wallet's production (default-feature) build.
//!
//! Two layers:
//!
//! - **Granular instruments** ([`summarize_gaps`], [`chi_square_uniform`],
//!   [`draw_entry_gap_double_jitter_trap`], [`population_bond_time`] /
//!   [`shared_anchor_population`], [`max_bin_share`]) — the building blocks the
//!   published KAT asserts on, and the negative references that prove the
//!   instruments actually bite (a marginal goodness-of-fit alone passes the
//!   triangular double-jitter trap and the epoch-snapped anchor cluster).
//! - **Self-certification** ([`certify_draw`] / [`grade_sample`]) — the
//!   RNG-generic tool a wallet runs against **its own** CSPRNG to grade the
//!   draw property (uniform spread, fair order, serial independence), not just
//!   the reference. The anchor-independence demonstration stays a separate,
//!   consumer-side instrument because the anchor is consensus-unenforceable.
//!
//! Grading uses a strict alpha (1e-6, via [`shekyl_stats::Z_ALPHA_1E6`]): a
//! correct draw never false-fails, and the gross deviations these instruments
//! exist to catch fail by orders of magnitude, so the margin is free.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
// ^ goodness-of-fit grading is float math over sample statistics and a small
//   signed walk in the serial-independence negative control. This module is
//   diagnostic/test-only and is never in a wallet's production build (it is
//   gated behind the `conformance` feature, which the default build omits), so
//   the float casts are honest here and machine-excluded from the shipped path.

use std::collections::HashMap;

use shekyl_stats::{chi_square_uniform_counts, chi_square_upper_crit, lag1_autocorr, Z_ALPHA_1E6};

use crate::draw::{bounded_uniform, draw_entry_gap, GapRng};

/// Fixed bin count for the spread-uniformity grade (clamped to the number of
/// distinct outcomes when `window` is small).
const UNIFORM_BINS: usize = 60;

/// Distribution summary of a `(spread, bond_first)` sample — the quantities the
/// conformance vector asserts on. A correct (uniform) draw gives
/// `mean_spread ~ window/2`, `bond_first_frac ~ 0.5`, `first_decile_frac ~ 0.10`,
/// and a small `max_decile_dev`; the triangular double-jitter trap collapses
/// `mean_spread` toward `window/3` and spikes `first_decile_frac` /
/// `max_decile_dev`.
#[derive(Debug, Clone)]
pub struct GapSampleStats {
    pub n: usize,
    pub mean_spread: f64,
    pub max_spread: u64,
    pub bond_first_frac: f64,
    /// Mass in the first decile `[0, window/10)`; uniform ⇒ ~0.10.
    pub first_decile_frac: f64,
    /// Largest `|decile bucket share - 0.10|` over the 10 deciles (a coarse
    /// uniformity probe).
    pub max_decile_dev: f64,
}

/// Summarize a realized sample. `window` defines the decile bucketing.
#[must_use]
pub fn summarize_gaps(samples: &[(u64, bool)], window: u64) -> GapSampleStats {
    let n = samples.len();
    let mut deciles = [0usize; 10];
    let mut spread_sum = 0u128;
    let mut bond_first = 0usize;
    let mut max_spread = 0u64;
    for &(s, bf) in samples {
        spread_sum += u128::from(s);
        max_spread = max_spread.max(s);
        if bf {
            bond_first += 1;
        }
        let idx = ((s as f64 / (window as f64 + 1.0)) * 10.0) as usize;
        deciles[idx.min(9)] += 1;
    }
    let denom = if n == 0 { 1.0 } else { n as f64 };
    let max_decile_dev = deciles
        .iter()
        .map(|&c| (c as f64 / denom - 0.10).abs())
        .fold(0.0_f64, f64::max);
    GapSampleStats {
        n,
        mean_spread: spread_sum as f64 / denom,
        max_spread,
        bond_first_frac: bond_first as f64 / denom,
        first_decile_frac: deciles[0] as f64 / denom,
        max_decile_dev,
    }
}

/// Chi-square goodness-of-fit against the **discrete** uniform on `[0, window]`
/// with `n_bins` equal-width bins; returns the statistic (df = `n_bins - 1`).
/// Reject uniformity when it exceeds
/// [`shekyl_stats::chi_square_upper_crit`]`(n_bins - 1, Z_ALPHA_1E6)`. Bins the
/// sample, then delegates the statistic to [`shekyl_stats`].
#[must_use]
pub fn chi_square_uniform(samples: &[(u64, bool)], window: u64, n_bins: usize) -> f64 {
    if n_bins == 0 {
        return 0.0;
    }
    let mut counts = vec![0u64; n_bins];
    for &(s, _) in samples {
        let idx = ((s as f64 / (window as f64 + 1.0)) * n_bins as f64) as usize;
        counts[idx.min(n_bins - 1)] += 1;
    }
    chi_square_uniform_counts(&counts)
}

/// The conformance **trap**, kept here so the vector is validated to *reject* it
/// rather than merely to pass the correct shape: independently jitter both
/// event-times in `[0, window]` around a common anchor; the realized separation
/// is `|a - b|` — triangular, peaked at zero — which still satisfies the ±window
/// bound a naive check would accept.
#[must_use]
pub fn draw_entry_gap_double_jitter_trap<R: GapRng + ?Sized>(
    window: u64,
    rng: &mut R,
) -> (u64, bool) {
    let a = bounded_uniform(rng, window);
    let b = bounded_uniform(rng, window);
    (a.abs_diff(b), a >= b)
}

/// Lag-1 autocorrelation over an integer gap sequence — the serial-independence
/// probe in the units the draw produces. Thin wrapper over
/// [`shekyl_stats::lag1_autocorr`].
#[must_use]
pub fn lag1_autocorr_u64(gaps: &[u64]) -> f64 {
    let series: Vec<f64> = gaps.iter().map(|&g| g as f64).collect();
    lag1_autocorr(&series)
}

/// One wallet's realized absolute bond-post time under the population anchor
/// model. `shared` snaps the private intent `t0` to the common `boundary` (the
/// catastrophic shared-trigger mode); otherwise `t0` is independent over
/// `[0, span)`. The gap is drawn **correctly** in both arms — the demonstrated
/// bug is in the anchor, not the gap.
#[must_use]
pub fn population_bond_time<R: GapRng + ?Sized>(
    window: u64,
    span: u64,
    boundary: u64,
    shared: bool,
    rng: &mut R,
) -> u64 {
    let t0 = if shared {
        boundary
    } else {
        bounded_uniform(rng, span.saturating_sub(1))
    };
    let (s, bond_first) = draw_entry_gap(window, rng);
    if bond_first {
        t0
    } else {
        t0 + s
    }
}

/// Reusable anchor-independence demonstration / negative control: a population
/// of absolute bond-post times. `shared = true` snaps every `P` to `boundary`
/// (the catastrophic shared-trigger mode); `shared = false` draws independent
/// intents over `[0, span)`. The gap is drawn correctly in both arms; the bug
/// being shown is in the anchor and is **consumer-side and
/// consensus-unenforceable** (funding is FCMP++-hidden). Pair with
/// [`max_bin_share`]: independent anchors disperse (small share), a shared
/// trigger clusters (share → 1).
#[must_use]
pub fn shared_anchor_population<R: GapRng + ?Sized>(
    rng: &mut R,
    window: u64,
    span: u64,
    boundary: u64,
    shared: bool,
    n: usize,
) -> Vec<u64> {
    (0..n)
        .map(|_| population_bond_time(window, span, boundary, shared, rng))
        .collect()
}

/// Reusable serial-independence **negative control**: a small-step wrapped walk
/// over `[0, window]`. Its marginal is roughly uniform but successive draws
/// differ by at most 20, so its lag-1 autocorrelation is large — the weak-PRNG
/// failure a marginal goodness-of-fit cannot see. A wallet test runs this and
/// asserts [`lag1_autocorr_u64`] is large, proving its serial-independence
/// check actually bites.
#[must_use]
pub fn correlated_walk<R: GapRng + ?Sized>(rng: &mut R, window: u64, m: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(m);
    let mut prev = bounded_uniform(rng, window);
    let modulus = window as i64 + 1;
    for _ in 0..m {
        let step = bounded_uniform(rng, 40) as i64 - 20; // [-20, 20]
        prev = (prev as i64 + step).rem_euclid(modulus) as u64;
        out.push(prev);
    }
    out
}

/// Concentration of a population's bond times: the share in the most-occupied
/// `bin_width`-wide bin. Dispersed (independent anchors) ⇒ small; clustered
/// (shared trigger) ⇒ → 1.
#[must_use]
pub fn max_bin_share(times: &[u64], bin_width: u64) -> f64 {
    if times.is_empty() || bin_width == 0 {
        return 0.0;
    }
    let mut bins: HashMap<u64, usize> = HashMap::new();
    for &t in times {
        *bins.entry(t / bin_width).or_insert(0) += 1;
    }
    let max = bins.values().copied().max().unwrap_or(0);
    max as f64 / times.len() as f64
}

/// Grade of a realized draw against the three properties the conformance vector
/// asserts. [`passed`](CertifyReport::passed) is the wallet-facing verdict.
#[derive(Debug, Clone)]
pub struct CertifyReport {
    pub n: usize,
    pub window: u64,
    /// Discrete-uniform chi-square of the spread and its critical value.
    pub chi_square: f64,
    pub chi_square_crit: f64,
    pub uniform_ok: bool,
    /// Share of draws with the bond appearing first; fair ⇒ ~0.5.
    pub bond_first_frac: f64,
    pub order_balanced: bool,
    /// Lag-1 autocorrelation of the spread sequence; independent ⇒ ~0.
    pub lag1: f64,
    pub serial_independent: bool,
}

impl CertifyReport {
    /// Overall verdict: all three properties hold.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.uniform_ok && self.order_balanced && self.serial_independent
    }
}

/// Order-balance / serial-independence tolerance, scaled to sample size. A fair
/// coin's observed frequency has standard error `0.5/sqrt(n)`; an independent
/// series' lag-1 is order `1/sqrt(n)`. `8/sqrt(n)` is many standard errors —
/// generous enough that a correct RNG never false-fails, tight enough that
/// gross bias (≳ 0.1) fails for any `n` beyond a few thousand.
fn tolerance(n: usize) -> f64 {
    if n == 0 {
        return f64::INFINITY;
    }
    8.0 / (n as f64).sqrt()
}

/// Grade a realized `(spread, bond_first)` sample produced by **any** source
/// against spread-uniformity (discrete chi-square at alpha = 1e-6),
/// order-balance, and serial independence (lag-1). A wallet calls this on its
/// own CSPRNG's output to self-certify; the grade is on the *property*, not on
/// emitting any particular sequence.
#[must_use]
pub fn grade_sample(samples: &[(u64, bool)], window: u64) -> CertifyReport {
    let n = samples.len();
    let n_bins = UNIFORM_BINS.min(window as usize + 1).max(1);

    let mut counts = vec![0u64; n_bins];
    let mut bond_first = 0usize;
    let mut spreads = Vec::with_capacity(n);
    for &(s, bf) in samples {
        let idx = ((s as f64 / (window as f64 + 1.0)) * n_bins as f64) as usize;
        counts[idx.min(n_bins - 1)] += 1;
        if bf {
            bond_first += 1;
        }
        spreads.push(s as f64);
    }

    let chi_square = chi_square_uniform_counts(&counts);
    let chi_square_crit = chi_square_upper_crit((n_bins as f64 - 1.0).max(1.0), Z_ALPHA_1E6);
    let uniform_ok = n_bins >= 2 && chi_square < chi_square_crit;

    let bond_first_frac = if n == 0 {
        0.0
    } else {
        bond_first as f64 / n as f64
    };
    let order_balanced = n > 0 && (bond_first_frac - 0.5).abs() < tolerance(n);

    let lag1 = lag1_autocorr(&spreads);
    let serial_independent = n >= 2 && lag1.abs() < tolerance(n);

    CertifyReport {
        n,
        window,
        chi_square,
        chi_square_crit,
        uniform_ok,
        bond_first_frac,
        order_balanced,
        lag1,
        serial_independent,
    }
}

/// Draw `n` gaps from the caller's RNG via the reference [`draw_entry_gap`] and
/// [`grade_sample`] them. A wallet self-certifies its CSPRNG by passing it here
/// and checking [`CertifyReport::passed`].
#[must_use]
pub fn certify_draw<R: GapRng + ?Sized>(rng: &mut R, window: u64, n: usize) -> CertifyReport {
    let samples: Vec<(u64, bool)> = (0..n).map(|_| draw_entry_gap(window, rng)).collect();
    grade_sample(&samples, window)
}

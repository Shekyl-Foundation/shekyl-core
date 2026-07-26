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

use crate::poisson::PoissonTable;
use crate::rng::{bounded_uniform, RelayRng};

/// How precisely an adversary can invert a relay delay.
///
/// This is the instrument for the fluff-delay finding, and it measures the
/// attack the delay exists to prevent rather than a distributional property
/// that stands in for it.
///
/// The setting: an adversary observes when a node *relays* a transaction and
/// wants to know when it *received* it — because receipt time is what locates
/// the node on the stem, and ultimately what points at the origin. The node
/// interposes a randomized delay `D`. The adversary's best strategy is to
/// subtract a fixed estimate `D̂` chosen to maximize the chance of landing
/// within a tolerance `window`; that is the width-`2·window` interval of the
/// delay distribution carrying the most mass.
///
/// Returns that maximum — the probability the adversary pins receipt time to
/// within `±window` ticks. Lower is better; `1.0` means the delay is a
/// constant and provides no cover at all.
///
/// Computed exactly from the quantized masses, so the answer describes the
/// draw as shipped rather than a sample of it.
///
/// # Panics
///
/// Panics if `masses` is empty.
#[must_use]
pub fn inference_precision(masses: &[u64], window: u64) -> f64 {
    assert!(!masses.is_empty(), "cannot analyse an empty distribution");

    let total: u128 = masses.iter().map(|m| u128::from(*m)).sum();
    if total == 0 {
        return 0.0;
    }

    // Slide a window of width 2*window+1 ticks and take the heaviest position.
    let width = usize::try_from(window.saturating_mul(2).saturating_add(1))
        .unwrap_or(usize::MAX)
        .min(masses.len());

    let mut running: u128 = masses[..width].iter().map(|m| u128::from(*m)).sum();
    let mut best = running;
    for start in 1..=masses.len().saturating_sub(width) {
        running -= u128::from(masses[start - 1]);
        running += u128::from(masses[start + width - 1]);
        best = best.max(running);
    }

    // `total` is at most 2^64, so the ratio is exact enough in f64.
    (best as f64) / (total as f64)
}

/// Coefficient of variation of a quantized distribution — standard deviation
/// over mean.
///
/// A compact summary of how much cover a delay actually provides: an
/// exponential (and its discrete twin, the geometric) sits at ~1.0, while a
/// Poisson at mean λ sits at `1/√λ`. The inherited fluff delay draws a Poisson
/// at λ = 20, i.e. CV ≈ 0.22 — the delay is nearly a constant.
///
/// # Panics
///
/// Panics if `masses` is empty.
#[must_use]
pub fn coefficient_of_variation(masses: &[u64]) -> f64 {
    assert!(!masses.is_empty(), "cannot analyse an empty distribution");
    let total: f64 = masses.iter().map(|m| *m as f64).sum();
    if total == 0.0 {
        return 0.0;
    }
    let mean: f64 = masses
        .iter()
        .enumerate()
        .map(|(k, m)| k as f64 * (*m as f64))
        .sum::<f64>()
        / total;
    if mean == 0.0 {
        return 0.0;
    }
    let variance: f64 = masses
        .iter()
        .enumerate()
        .map(|(k, m)| (k as f64 - mean).powi(2) * (*m as f64))
        .sum::<f64>()
        / total;
    variance.sqrt() / mean
}

/// Convenience: draw `n` samples from a Poisson table.
pub fn sample_poisson<R: RelayRng + ?Sized>(
    table: &PoissonTable,
    n: usize,
    rng: &mut R,
) -> Vec<u64> {
    (0..n).map(|_| table.draw(rng)).collect()
}

/// Convenience: draw `n` uniform samples over `[0, max]`.
pub fn sample_uniform<R: RelayRng + ?Sized>(max: u64, n: usize, rng: &mut R) -> Vec<u64> {
    (0..n).map(|_| bounded_uniform(rng, max)).collect()
}

/// Condition a delay distribution on having already survived `phase` ticks,
/// and re-express it as the *residual* delay from that point.
///
/// **RD-2.** This is the instrument that makes D-3's real argument measurable,
/// and it exists because the inherited fluff timer is a **re-armed batching
/// flush**, not a per-transaction delay. `levin_notify.cpp`'s `fluff_notify`
/// draws a deadline only when a peer's batch is *empty*; a transaction
/// arriving mid-window joins the pending batch and goes out at the
/// already-drawn deadline. What such a transaction actually experiences is the
/// **residual** of a draw that has already survived `phase` ticks — not a
/// fresh draw.
///
/// Only the memoryless family has residual ≡ full. For any other shape the
/// inversion analysis is arrival-phase-dependent, so a headline inversion
/// number computed at phase 0 does not describe most transactions. That, and
/// not raw inversion precision, is why D-3 chooses memorylessness: a uniform
/// delay scores *better* at phase 0 and falls apart everywhere else.
///
/// # Panics
///
/// Panics if `masses` is empty.
#[must_use]
pub fn residual_masses(masses: &[u64], phase: u64) -> Vec<u64> {
    assert!(!masses.is_empty(), "cannot condition an empty distribution");
    let start = usize::try_from(phase).unwrap_or(usize::MAX);
    if start >= masses.len() {
        // The window always elapses before this phase; nothing survives to
        // condition on. An empty residual is reported as a single certain
        // zero-delay outcome, which is the honest reading.
        return vec![u64::MAX];
    }
    masses[start..].to_vec()
}

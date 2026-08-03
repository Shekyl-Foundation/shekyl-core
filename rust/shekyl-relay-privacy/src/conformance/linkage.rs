// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Q-11 Unit 2 — the linkage instrument for the covert cadence's *shape*.
//!
//! # The question this exists to answer, and the one it does not
//!
//! §31 fixed the goal as **non-enumerability**, and §32.6's grid split it in
//! two: **payload-independence denies recall** (the observer cannot recover
//! *how many* transactions a node sent, because emissions do not depend on
//! them), and **memorylessness denies assembly** (the observer cannot *link*
//! one observation window to another across a perturbation).
//!
//! The Loopix reading (§25.3) settled the first half negatively for
//! randomness: **payload-independence alone does count-denial, and a
//! metronome has it.** A constant-rate carrier emits the same sequence whether
//! the node originated a thousand transactions or none. So the *only* reason
//! to randomise the cadence is the second half — linkability — and that is
//! what this measures.
//!
//! **It is a matching test, not a prediction test**, and the distinction is
//! load-bearing. "Can the observer predict the next emission?" is answerable
//! *yes* for any non-degenerate law and tells us nothing about enumeration.
//! The enumeration-relevant question is "given `M` streams before a
//! perturbation and the same `M` after, can the observer say **which is
//! which**?" — advantage over `1/M` is exactly the assembly step §31 names.
//!
//! # Why a perturbation, and why the two laws differ under it
//!
//! The residual — time from *now* until a stream's next emission — is the
//! only quantity an observer holds at the moment a blackout ends.
//!
//! - Under the **bounded** family the daemon ships (`10 s + U[0, 5 s]`), the
//!   residual is a function of elapsed-since-last: after 10 s of silence an
//!   emission is certain within 5 s. Each stream therefore carries a *phase*,
//!   and phase survives a short blackout. That is a per-stream feature to
//!   match on.
//! - Under a **memoryless** family the residual is independent of elapsed
//!   time by definition. There is no phase, so there is nothing that persists
//!   across the blackout to match on.
//!
//! # What a null result would mean
//!
//! If the bounded family also matches at chance, then (b) has no measurable
//! channel at this observer's capability, and §32.6's grid is satisfied by
//! payload-independence alone — which would make the metronome the correct
//! shape and randomisation unjustified. **That outcome is a real possibility
//! and the instrument is built to be able to return it**; an instrument that
//! could only confirm the need for randomness would be assuming its answer.

use crate::rng::RelayRng;
use crate::schedule::{Millis, NoiseCadence};

/// Which inter-emission law a stream draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadenceShape {
    /// A fixed interval — no draw at all. The payload-independent floor:
    /// it denies recall completely and is the shape randomness must beat.
    Metronome,
    /// What the daemon ships: `NOISE_MIN_DELAY + U[0, NOISE_JITTER]`, drawn
    /// through **production** [`NoiseCadence::next_send`], not a re-derived
    /// copy of it.
    BoundedUniform,
    /// Memoryless: residual independent of elapsed time. Geometric on a
    /// millisecond grid, mean matched to the bounded family's so the two arms
    /// differ in *shape* and not in rate.
    Memoryless,
}

/// How strong an observer the matching runs against.
///
/// **This is an axis of the instrument, not a detail**, and keeping the weak
/// arm is deliberate: the first Unit 2 run reported "bounded and memoryless
/// are indistinguishable" when that was a property of the *matcher*, not of
/// the families. A green result from a weak observer measures the observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherStrength {
    /// Predicts `last + mean` and takes the nearest post-blackout emission.
    /// Only ever tests `k = 1` — it assumes exactly one emission was missed.
    /// **Retained as a control**, because it is what produced the original
    /// null and its failure is the finding.
    NearestPredicted,
    /// Marginalises over `k`, the number of emissions the blackout hid.
    /// Both the blackout duration and the family are public, so this is the
    /// observer the scope rule (§28) actually admits — the same reasoning that
    /// rejected the metronome's apparent −0.250 as an invertible artifact,
    /// applied to the matcher rather than to one data point.
    MarginalizedOverK,
}

/// Log-density of the sum of `k` inter-emission intervals landing on `delta`.
///
/// The observer knows the family; this is its likelihood for "`k` emissions
/// were missed". Bounded support concentrates — mean `k·µ`, sd `σ√k`, so the
/// *relative* spread shrinks as `k` grows and `k` becomes identifiable, which
/// is what lets residual phase be read within it. Under an exponential
/// `σ = µ`, the components never separate, and by memorylessness the residual
/// from blackout-end is independent of everything prior — the D++ §4.4 lemma
/// (b) was pinned to, showing up as a flat likelihood.
fn log_density_k(shape: CadenceShape, delta_ms: f64, k: u32, mean_ms: f64) -> f64 {
    let kf = f64::from(k);
    match shape {
        CadenceShape::Metronome => {
            // Point mass: score by proximity to k·µ. No spread to marginalise.
            -(delta_ms - kf * mean_ms).abs()
        }
        CadenceShape::BoundedUniform => {
            let lo = f64::from(crate::params::inherited::NOISE_MIN_DELAY_SECS) * 1_000.0;
            let hi = lo + f64::from(crate::params::inherited::NOISE_DELAY_JITTER_SECS) * 1_000.0;
            // Outside the k-fold support the component contributes nothing —
            // that hard cutoff is most of the discriminating power at small k.
            if delta_ms < kf * lo || delta_ms > kf * hi {
                return f64::NEG_INFINITY;
            }
            let sd = (hi - lo) / 12.0_f64.sqrt() * kf.sqrt();
            let z = (delta_ms - kf * mean_ms) / sd;
            -0.5 * z * z - sd.ln()
        }
        CadenceShape::Memoryless => {
            // Erlang(k, 1/µ), exact.
            if delta_ms <= 0.0 {
                return f64::NEG_INFINITY;
            }
            let lambda = 1.0 / mean_ms;
            let log_fact: f64 = (1..k).map(|i| f64::from(i).ln()).sum();
            kf * lambda.ln() + (kf - 1.0) * delta_ms.ln() - lambda * delta_ms - log_fact
        }
    }
}

/// Marginal log-likelihood of `delta`, summing over how many emissions the
/// blackout could have hidden.
fn log_likelihood(shape: CadenceShape, delta_ms: f64, mean_ms: f64, k_max: u32) -> f64 {
    let mut best = f64::NEG_INFINITY;
    let mut acc = 0.0_f64;
    for k in 1..=k_max {
        let l = log_density_k(shape, delta_ms, k, mean_ms);
        if l == f64::NEG_INFINITY {
            continue;
        }
        // log-sum-exp, streaming.
        if l > best {
            acc = acc * (best - l).exp() + 1.0;
            best = l;
        } else {
            acc += (l - best).exp();
        }
    }
    if best == f64::NEG_INFINITY {
        f64::NEG_INFINITY
    } else {
        best + acc.ln()
    }
}

/// Result of one matching trial set.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkageSummary {
    /// Streams per trial — the `M` in `1/M`.
    pub streams: usize,
    /// Fraction of streams correctly matched across the blackout.
    pub match_rate: f64,
    /// `1.0 / streams` — what a coin flip achieves.
    pub chance: f64,
    /// `match_rate - chance`. **This is the number the shape decision reads.**
    pub advantage: f64,
}

/// Draw one inter-emission interval under `shape`.
fn interval<R: RelayRng + ?Sized>(shape: CadenceShape, rng: &mut R, mean_ms: u64) -> Millis {
    match shape {
        CadenceShape::Metronome => mean_ms,
        // Production path: the instrument must not re-derive the law it is
        // grading, or it measures its own copy (the shim-oracle failure).
        CadenceShape::BoundedUniform => NoiseCadence::inherited().next_send(0, rng),
        CadenceShape::Memoryless => {
            // Geometric on a 250 ms grid keeps the table small while leaving
            // the residual elapsed-independent, which is the property under
            // test. Mean matched to `mean_ms`.
            const GRID_MS: u64 = 250;
            let table = crate::geometric::GeometricTable::new(
                u32::try_from(mean_ms / GRID_MS).unwrap_or(1).max(1),
            );
            table.draw(rng) * GRID_MS
        }
    }
}

/// Can an observer re-identify `streams` covert channels across a blackout?
///
/// Each trial: run every stream to steady state, blackout for `blackout_ms`,
/// then record each stream's **first emission after the blackout**. The
/// observer matches pre-streams to post-streams by predicted residual, and we
/// score how often it is right.
///
/// The observer is given the *strongest* form of the capability the scope rule
/// (§28) admits: it knows each stream's last pre-blackout emission time and
/// the law itself. Handing it less would understate the channel and let a
/// weak result pass for a safe one.
///
/// # Panics
/// Panics if `streams` is under two or `trials` is zero.
#[must_use]
pub fn simulate_cadence_linkage<R: RelayRng + ?Sized>(
    shape: CadenceShape,
    matcher: MatcherStrength,
    streams: usize,
    blackout_ms: Millis,
    trials: usize,
    rng: &mut R,
) -> LinkageSummary {
    assert!(streams >= 2, "matching needs at least two streams");
    assert!(trials > 0, "trials must be non-zero");
    let mean_ms = u64::from(crate::params::inherited::NOISE_MIN_DELAY_SECS) * 1_000
        + u64::from(crate::params::inherited::NOISE_DELAY_JITTER_SECS) * 1_000 / 2;

    // How many emissions the blackout could plausibly have hidden. Generous:
    // an observer that truncated too early would be handicapped by the
    // instrument rather than by the law.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let k_max = ((blackout_ms / mean_ms) as u32 + 8).max(4);

    let mut correct = 0_usize;
    let mut total = 0_usize;

    for _ in 0..trials {
        // Warm each stream to a steady state, staggered so phases differ —
        // otherwise every stream shares one phase and the test is vacuous by
        // construction rather than by the law.
        let mut last: Vec<Millis> = Vec::with_capacity(streams);
        for s in 0..streams {
            let mut t = (s as u64 * mean_ms) / streams as u64; // stagger
            for _ in 0..8 {
                t += interval(shape, rng, mean_ms);
            }
            last.push(t);
        }
        let blackout_end = last.iter().copied().max().unwrap_or(0) + blackout_ms;

        // First emission after the blackout, per stream.
        let mut first_after: Vec<Millis> = Vec::with_capacity(streams);
        for &l in &last {
            let mut t = l;
            while t <= blackout_end {
                t += interval(shape, rng, mean_ms);
            }
            first_after.push(t);
        }

        // Score every (pre, post) pair, then assign globally best-first. The
        // per-`i` greedy the first version used is itself an observer
        // weakness — it commits stream 0's match before seeing stream 1's
        // better claim on the same emission.
        #[allow(clippy::cast_precision_loss)]
        let score = |i: usize, j: usize| -> f64 {
            let delta = first_after[j].saturating_sub(last[i]) as f64;
            match matcher {
                MatcherStrength::NearestPredicted => -(delta - mean_ms as f64).abs(),
                MatcherStrength::MarginalizedOverK => {
                    log_likelihood(shape, delta, mean_ms as f64, k_max)
                }
            }
        };
        let mut pairs: Vec<(usize, usize)> = (0..streams)
            .flat_map(|i| (0..streams).map(move |j| (i, j)))
            .collect();
        pairs.sort_by(|&(ai, aj), &(bi, bj)| {
            score(bi, bj)
                .partial_cmp(&score(ai, aj))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut pre_taken = vec![false; streams];
        let mut post_taken = vec![false; streams];
        for (i, j) in pairs {
            if pre_taken[i] || post_taken[j] {
                continue;
            }
            pre_taken[i] = true;
            post_taken[j] = true;
            if i == j {
                correct += 1;
            }
            total += 1;
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let match_rate = correct as f64 / total as f64;
    let chance = 1.0 / streams as f64;
    LinkageSummary {
        streams,
        match_rate,
        chance,
        advantage: match_rate - chance,
    }
}

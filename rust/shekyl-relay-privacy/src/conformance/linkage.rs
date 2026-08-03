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
    streams: usize,
    blackout_ms: Millis,
    trials: usize,
    rng: &mut R,
) -> LinkageSummary {
    assert!(streams >= 2, "matching needs at least two streams");
    assert!(trials > 0, "trials must be non-zero");
    let mean_ms = u64::from(crate::params::inherited::NOISE_MIN_DELAY_SECS) * 1_000
        + u64::from(crate::params::inherited::NOISE_DELAY_JITTER_SECS) * 1_000 / 2;

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

        // The observer predicts each stream's next emission from its last one
        // plus the law's mean, then matches greedily to the nearest unclaimed
        // post-blackout emission. Under a phase-bearing law the prediction
        // tracks the stream; under a memoryless one it cannot.
        let mut taken = vec![false; streams];
        for (i, &l) in last.iter().enumerate() {
            let predicted = l + mean_ms;
            let mut best: Option<(usize, u64)> = None;
            for (j, &f) in first_after.iter().enumerate() {
                if taken[j] {
                    continue;
                }
                let d = f.abs_diff(predicted);
                if best.is_none_or(|(_, bd)| d < bd) {
                    best = Some((j, d));
                }
            }
            if let Some((j, _)) = best {
                taken[j] = true;
                if j == i {
                    correct += 1;
                }
                total += 1;
            }
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

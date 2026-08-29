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
//! - Under the **bounded** family the daemon ships
//!   (`NOISE_MIN_DELAY_MS + U[0, NOISE_DELAY_JITTER_MS]`, today
//!   `3.333 s + U[0, 3.334 s]`), the residual is a function of
//!   elapsed-since-last: once the minimum has passed, an emission is certain
//!   within the jitter width. Each stream therefore carries a *phase*, and
//!   phase survives a short blackout. That is a per-stream feature to match
//!   on.
//!
//!   Written against the constants rather than their values because this
//!   instrument grades the **shipped** law: a cadence change that left this
//!   paragraph behind would leave the instrument describing a law it is no
//!   longer measuring, which is the one failure a conformance harness cannot
//!   afford. (It did, once — the 2026-08-28 cadence change, caught in
//!   review.)
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
            let lo = f64::from(crate::params::carrier::NOISE_MIN_DELAY_MS);
            let hi = lo + f64::from(crate::params::carrier::NOISE_DELAY_JITTER_MS);
            // Outside the k-fold support the component contributes nothing —
            // that hard cutoff is most of the discriminating power at small k.
            if delta_ms < kf * lo || delta_ms > kf * hi {
                return f64::NEG_INFINITY;
            }
            // `hi > lo` is guaranteed by the non-zero-jitter invariant asserted
            // at `NOISE_DELAY_JITTER_MS`, so `sd > 0` and neither the
            // division nor `ln` below can degenerate. That invariant is
            // enforced where the constant lives rather than defended here:
            // at zero jitter this arm would not merely divide by zero, it
            // would silently *become* the metronome arm and the sweep would
            // compare a law with itself.
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
///
/// The geometric table is built **once per run** and passed in: constructing
/// it per draw is `O(mean)` each time and dominated the instrument's runtime.
///
/// **The memoryless arm is shifted by one grid step.** An unshifted geometric
/// has a ~2 % atom at zero, which would let that arm emit twice at the same
/// instant — something the bounded arm (whose gaps start at
/// `NOISE_MIN_DELAY_MS`) and the metronome arm cannot do.
/// That is an asymmetry *between the arms*, not a property of memorylessness,
/// and it would show up as a difference the shape question would then have to
/// explain. The table is built for `mean − 1` so the shift leaves the mean
/// where it belongs, keeping the arms matched in rate and differing only in
/// shape — which is the whole point of the comparison.
fn interval<R: RelayRng + ?Sized>(
    shape: CadenceShape,
    rng: &mut R,
    mean_ms: u64,
    table: Option<&crate::geometric::GeometricTable>,
) -> Millis {
    match shape {
        CadenceShape::Metronome => mean_ms,
        // Production path: the instrument must not re-derive the law it is
        // grading, or it measures its own copy (the shim-oracle failure).
        CadenceShape::BoundedUniform => NoiseCadence::shipped().next_send(0, rng),
        CadenceShape::Memoryless => {
            let t = table.expect("memoryless arm requires its table");
            (t.draw(rng) + 1) * MEMORYLESS_GRID_MS
        }
    }
}

/// Grid for the memoryless arm. Fine enough that discretisation does not
/// blunt the residual, coarse enough to keep the table small.
const MEMORYLESS_GRID_MS: u64 = 250;

/// Maximum-weight assignment, so the "strong observer" arm actually computes
/// the best global matching rather than a greedy approximation.
///
/// **This is not a refinement, it is the difference between grading the
/// mechanism and grading the matcher.** A greedy best-first assignment can
/// only *understate* matchability — it commits an early pair before seeing a
/// later, better claim on the same emission — and understating is exactly how
/// §56.2 reported a null that was a property of its observer. An instrument
/// whose docstring claims the strongest admissible observer has to compute
/// one.
///
/// `O(n³)` Kuhn–Munkres with potentials, minimising `-score`. Verified
/// against brute force at `n = 5` in this module's tests, because an
/// *incorrectly* optimal matcher is worse than an honestly greedy one.
fn max_weight_assignment(score: &[Vec<f64>]) -> Vec<usize> {
    let n = score.len();
    let inf = f64::INFINITY;
    let mut u = vec![0.0_f64; n + 1];
    let mut v = vec![0.0_f64; n + 1];
    let mut p = vec![0_usize; n + 1];
    let mut way = vec![0_usize; n + 1];

    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0_usize;
        let mut minv = vec![inf; n + 1];
        let mut used = vec![false; n + 1];
        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = inf;
            let mut j1 = 0_usize;
            for j in 1..=n {
                if used[j] {
                    continue;
                }
                let cur = -score[i0 - 1][j - 1] - u[i0] - v[j];
                if cur < minv[j] {
                    minv[j] = cur;
                    way[j] = j0;
                }
                if minv[j] < delta {
                    delta = minv[j];
                    j1 = j;
                }
            }
            for j in 0..=n {
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }
        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 {
                break;
            }
        }
    }

    let mut assign = vec![0_usize; n];
    for j in 1..=n {
        if p[j] != 0 {
            assign[p[j] - 1] = j - 1;
        }
    }
    assign
}

/// Can an observer re-identify/// Can an observer re-identify `streams` covert channels across a blackout?
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
    let mean_ms = u64::from(crate::params::carrier::MEAN_CADENCE_MS);

    // How many emissions the blackout could plausibly have hidden.
    //
    // DERIVED FROM THE TAIL, NOT A CONSTANT MARGIN — and the 2026-08-28
    // cadence change is what exposed why. The hidden count has mean
    // `blackout / mean` and spread growing as its square root, so a fixed
    // `+ 8` covered 2.3 sd at the 12.5 s mean and only **1.5 sd** at 5 s:
    // ~7% of the count mass sat above the cutoff at the 150 s probe.
    //
    // Truncating there is not a neutral approximation. The memoryless
    // likelihood is flat *because* every Erlang component is summed; dropping
    // the tail leaves a delta-dependent remainder, which manufactures exactly
    // the signal this arm exists to show is absent. A cutoff that scales with
    // the mean but not its spread grades the instrument rather than the law —
    // §56.5's own lesson, arriving through the observer's other side.
    //
    // `lambda + 8*sqrt(lambda)` is an 8 sd bound, whose tail is far below the
    // `1/trials` resolution of any run this instrument does. The bounded and
    // metronome arms self-truncate through their support check, so the extra
    // components cost only time there.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let k_max = {
        let lambda = blackout_ms as f64 / mean_ms as f64;
        ((lambda + 8.0 * lambda.sqrt()).ceil() as u32).max(4)
    };

    // Built once, not per draw.
    let table = (shape == CadenceShape::Memoryless).then(|| {
        crate::geometric::GeometricTable::new(
            u32::try_from(mean_ms / MEMORYLESS_GRID_MS)
                .unwrap_or(2)
                .saturating_sub(1)
                .max(1),
        )
    });

    let mut correct = 0_usize;
    let mut total = 0_usize;

    for _ in 0..trials {
        // Warm each stream to steady state, staggered so phases differ —
        // otherwise every stream shares one phase and the test is vacuous by
        // construction rather than by the law.
        let mut t: Vec<Millis> = (0..streams)
            .map(|s| (s as u64 * mean_ms) / streams as u64)
            .collect();
        for slot in &mut t {
            for _ in 0..8 {
                *slot += interval(shape, rng, mean_ms, table.as_ref());
            }
        }

        // **One common blackout start for every stream.** Deriving it from
        // `max(last)` and then treating each stream's warm-up endpoint as its
        // last pre-blackout emission was wrong: the earlier streams go on
        // emitting up to the blackout, and the observer would have seen those.
        // Recording a stale `last` handed the matcher a residual no observer
        // could hold, distorting exactly the quantity under measurement.
        let blackout_start = t.iter().copied().max().unwrap_or(0) + mean_ms;
        let blackout_end = blackout_start + blackout_ms;

        let mut last: Vec<Millis> = Vec::with_capacity(streams);
        let mut first_after: Vec<Millis> = Vec::with_capacity(streams);
        for slot in &mut t {
            // Advance to the true last emission at or before the blackout.
            let mut prev = *slot;
            while *slot <= blackout_start {
                prev = *slot;
                *slot += interval(shape, rng, mean_ms, table.as_ref());
            }
            last.push(prev);
            // Then to the first emission after the blackout ends.
            while *slot <= blackout_end {
                *slot += interval(shape, rng, mean_ms, table.as_ref());
            }
            first_after.push(*slot);
        }

        // Score every (pre, post) pair ONCE into a matrix — recomputing inside
        // a comparator called O(n² log n) times dominated the runtime — then
        // assign optimally.
        #[allow(clippy::cast_precision_loss)]
        let matrix: Vec<Vec<f64>> = (0..streams)
            .map(|i| {
                (0..streams)
                    .map(|j| {
                        let delta = first_after[j].saturating_sub(last[i]) as f64;
                        match matcher {
                            MatcherStrength::NearestPredicted => -(delta - mean_ms as f64).abs(),
                            MatcherStrength::MarginalizedOverK => {
                                let l = log_likelihood(shape, delta, mean_ms as f64, k_max);
                                if l.is_finite() {
                                    l
                                } else {
                                    -1.0e18
                                }
                            }
                        }
                    })
                    .collect()
            })
            .collect();

        for (i, j) in max_weight_assignment(&matrix).into_iter().enumerate() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SplitMix64;

    /// The assignment really is optimal — checked against brute force.
    ///
    /// **An incorrectly "optimal" matcher is worse than an honestly greedy
    /// one**: it would report a number nobody could reproduce and carry the
    /// authority of the word. So the algorithm is verified against an
    /// independent exhaustive oracle rather than trusted for being standard.
    #[test]
    fn the_assignment_matches_brute_force_optimum() {
        fn brute(score: &[Vec<f64>]) -> f64 {
            let n = score.len();
            let mut idx: Vec<usize> = (0..n).collect();
            let mut best = f64::NEG_INFINITY;
            // Heap's algorithm over all n! permutations.
            fn go(k: usize, idx: &mut Vec<usize>, score: &[Vec<f64>], best: &mut f64) {
                if k == 1 {
                    let s: f64 = idx.iter().enumerate().map(|(i, &j)| score[i][j]).sum();
                    if s > *best {
                        *best = s;
                    }
                    return;
                }
                for i in 0..k {
                    go(k - 1, idx, score, best);
                    if k.is_multiple_of(2) {
                        idx.swap(i, k - 1);
                    } else {
                        idx.swap(0, k - 1);
                    }
                }
            }
            go(n, &mut idx, score, &mut best);
            best
        }

        let mut rng = SplitMix64::new(0xA55);
        for _ in 0..40 {
            const N: usize = 5;
            #[allow(clippy::cast_precision_loss)]
            let m: Vec<Vec<f64>> = (0..N)
                .map(|_| {
                    (0..N)
                        .map(|_| (rng.next_u64() % 1_000) as f64 / 10.0)
                        .collect()
                })
                .collect();
            let got: f64 = max_weight_assignment(&m)
                .into_iter()
                .enumerate()
                .map(|(i, j)| m[i][j])
                .sum();
            let want = brute(&m);
            assert!(
                (got - want).abs() < 1e-9,
                "assignment {got} is not the optimum {want}"
            );
        }
    }

    /// The memoryless arm never emits twice at one instant.
    ///
    /// An unshifted geometric has a ~2 % atom at zero, which the bounded and
    /// metronome arms cannot produce. Left in, that is an asymmetry *between
    /// the arms* which the shape comparison would then have to explain away.
    #[test]
    fn the_memoryless_arm_draws_no_zero_interval() {
        let table = crate::geometric::GeometricTable::new(49);
        let mut rng = SplitMix64::new(0x2E80);
        for _ in 0..200_000 {
            let d = interval(CadenceShape::Memoryless, &mut rng, 12_500, Some(&table));
            assert!(d > 0, "zero-length interval: two emissions at one instant");
        }
    }
}

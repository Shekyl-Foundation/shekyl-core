// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Goodness-of-fit instruments and the stem-propagation simulator —
//! feature-gated (`conformance`), float-bearing, never part of a default
//! build.
//!
//! Two layers, the same split `shekyl-standoff` uses:
//!
//! - **Distribution grades** ([`grade_poisson`], [`grade_uniform`],
//!   [`grade_bernoulli`], [`grade_stem_balance`]) — chi-square tests that a
//!   realized sample matches the distribution its draw claims. These are what
//!   the inherited C++ has no equivalent of at all: `tests/unit_tests/levin.cpp`
//!   drives the relay path through `run_epoch()` / `run_stems()` /
//!   `run_fluff()`, all of which *cancel the timer* to force immediate
//!   execution, so not one of its 33 cases observes a delay.
//! - **The propagation simulator** ([`simulate_propagation`]) — the instrument
//!   that answers the question a distribution grade cannot: given these
//!   parameters, does a transaction actually complete its stem before somebody's
//!   embargo fires? That is the Dandelion++ appendix B.5 property the embargo
//!   is solving for, measured rather than assumed.
//!
//! Grading uses the strict alpha the workspace standardized on
//! ([`shekyl_stats::Z_ALPHA_1E6`]): a correct draw never false-fails, and the
//! gross deviations these instruments exist to catch fail by orders of
//! magnitude.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Goodness-of-fit grading is float math over sample counts. This module is
//   diagnostic-only and excluded from the default build.

use shekyl_stats::{chi_square_counts_expected, chi_square_upper_crit, Z_ALPHA_1E6};

use crate::params::DandelionParams;
use crate::poisson::PoissonTable;
use crate::rng::{bernoulli, bounded_uniform, RelayRng};
use crate::schedule::EmbargoTimer;

/// Outcome of a goodness-of-fit grade.
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

/// Hard cap on simulated stem length, so a pathological fluff probability
/// cannot make a trial run forever. Far above any reachable stem: at the
/// inherited q = 20% the expected length is 5.
const MAX_SIMULATED_HOPS: usize = 4_096;

/// What one simulated transaction did on its way through the stem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Propagation {
    /// Number of stem hops before a node fluffed of its own accord.
    pub stem_hops: usize,
    /// Monotonic time at which the natural fluff happened, in milliseconds
    /// from broadcast.
    pub natural_fluff_ms: u64,
    /// Earliest embargo deadline among every node that saw the transaction.
    pub earliest_embargo_ms: u64,
    /// True when an embargo fired before the natural fluff — the failure the
    /// embargo parameter is tuned to keep rare.
    pub embargo_preempted: bool,
}

/// Aggregate over a simulation run.
#[derive(Debug, Clone, PartialEq)]
pub struct PropagationSummary {
    /// Trials run.
    pub trials: usize,
    /// Mean stem length in hops.
    pub mean_stem_hops: f64,
    /// Mean time from broadcast to natural fluff, in milliseconds.
    pub mean_natural_fluff_ms: f64,
    /// 99th-percentile time to natural fluff, in milliseconds.
    pub p99_natural_fluff_ms: u64,
    /// Fraction of trials in which an embargo fired first.
    pub preemption_rate: f64,
    /// Fraction of trials that completed the stem before any embargo — the
    /// quantity [`crate::params::EMBARGO_FULL_TRAVEL_PROBABILITY`] targets.
    pub full_travel_rate: f64,
}

/// Simulate stem propagation under a parameter set and an embargo choice.
///
/// Each trial walks a transaction hop by hop: the node holding it draws an
/// embargo deadline, then decides (with probability `q`) to fluff. If it
/// stems, the transaction moves on after `time_between_hop_ms`. The trial ends
/// at the first natural fluff; the earliest embargo drawn anywhere along the
/// path is compared against that time.
///
/// This is deliberately the paper's model, not the daemon's implementation: it
/// measures whether the *parameters* deliver the property, which is the
/// question a design round needs answered before anything is ported.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_propagation<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    trials: usize,
    rng: &mut R,
) -> PropagationSummary {
    assert!(trials > 0, "simulation needs at least one trial");
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);

    // RD-1: a stem node's embargo is disarmed when the fluff *reaches it*, not
    // when the terminal node emits it. The terminal node is the exception --
    // it disarms at emission, because it is the one fluffing.
    let return_ms = u64::from(params.fluff_return_ms);

    let mut outcomes = Vec::with_capacity(trials);
    for _ in 0..trials {
        let mut t = 0_u64;
        let mut earliest_embargo = u64::MAX;
        let mut hops = 0_usize;

        loop {
            // The node currently holding the transaction arms its embargo.
            let deadline = embargo.deadline(t, rng);

            // RD-4: the origin (hops == 0) always stems its own transaction, so
            // the fluff coin is flipped only from the first relay onward. A node
            // that fluffs discards its own embargo — `upgrade_relay_method`
            // clears it at emission, so the terminal node can never preempt.
            if hops >= 1 && bernoulli(rng, q, 100) {
                break;
            }
            earliest_embargo = earliest_embargo.min(deadline);

            hops += 1;
            if hops >= MAX_SIMULATED_HOPS {
                break;
            }
            t = t.saturating_add(hop_ms);
        }

        let disarm_ms = t.saturating_add(return_ms);
        outcomes.push(Propagation {
            stem_hops: hops,
            natural_fluff_ms: t,
            earliest_embargo_ms: earliest_embargo,
            embargo_preempted: earliest_embargo < disarm_ms,
        });
    }

    summarize(&outcomes)
}

fn summarize(outcomes: &[Propagation]) -> PropagationSummary {
    let n = outcomes.len();
    let trials = n as f64;
    let mean_stem_hops = outcomes.iter().map(|o| o.stem_hops as f64).sum::<f64>() / trials;
    let mean_natural_fluff_ms = outcomes
        .iter()
        .map(|o| o.natural_fluff_ms as f64)
        .sum::<f64>()
        / trials;

    let mut times: Vec<u64> = outcomes.iter().map(|o| o.natural_fluff_ms).collect();
    times.sort_unstable();
    // Index of the 99th percentile, clamped into range for small samples.
    let p99_idx = ((n as f64) * 0.99).ceil() as usize;
    let p99_natural_fluff_ms = times[p99_idx.min(n - 1)];

    let preempted = outcomes.iter().filter(|o| o.embargo_preempted).count();
    let preemption_rate = preempted as f64 / trials;

    PropagationSummary {
        trials: n,
        mean_stem_hops,
        mean_natural_fluff_ms,
        p99_natural_fluff_ms,
        preemption_rate,
        full_travel_rate: 1.0 - preemption_rate,
    }
}

/// Search for the smallest embargo mean, in seconds, whose measured
/// full-travel rate reaches `target`.
///
/// This is the number a design round actually needs and that no amount of
/// re-reading the inherited `#define` can produce. The closed-form derivation
/// in [`crate::params`] substitutes the *expected* stem length `k` into an
/// expression in `k(k-1)`, which is not linear — and the realized stem length
/// is geometric, with `E[K(K-1)]` twice `E[K](E[K]-1)` at any fluff
/// probability. The formula therefore under-provisions, and by a factor that
/// no correction to the constant reveals. Measuring is the only honest route.
///
/// Bisects over the integer second, using the same trial count at every probe
/// so the comparison is like-for-like. The RNG is re-seeded per probe from
/// `seed` so the search is deterministic and free of the drift a shared,
/// advancing RNG would introduce between probes.
///
/// # Panics
///
/// Panics if `target` is not in `(0, 1)`, or if `trials` is zero.
#[must_use]
pub fn solve_embargo_secs_for_target(
    params: &DandelionParams,
    target: f64,
    distribution: crate::schedule::EmbargoDistribution,
    trials: usize,
    seed: u64,
) -> Option<u32> {
    assert!(
        target > 0.0 && target < 1.0,
        "target must be a probability strictly inside (0, 1)"
    );
    assert!(trials > 0, "search needs at least one trial per probe");

    let measure = |secs: u32| -> f64 {
        let embargo = EmbargoTimer::new(secs, distribution);
        let mut rng = crate::rng::SplitMix64::new(seed);
        simulate_propagation(params, &embargo, trials, &mut rng).full_travel_rate
    };

    // Expand until the target is bracketed, so the bisection below is not
    // searching a range that cannot contain the answer.
    let mut hi = 1_u32;
    while measure(hi) < target {
        hi = hi.saturating_mul(2);
        if hi >= 1 << 20 {
            return None; // target unreachable in any sane embargo
        }
    }
    let mut lo = hi / 2;

    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if measure(mid) < target {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(hi)
}

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

/// Topology inputs for the fluff-flood first-passage measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodParams {
    /// Nodes in the simulated network.
    pub nodes: usize,
    /// Fluff peers each node relays to.
    pub peers: usize,
}

impl Default for FloodParams {
    fn default() -> Self {
        // A small network is the conservative choice: fewer parallel paths
        // means a slower flood and a longer return term. Peer count matches
        // the daemon's default outbound target.
        Self {
            nodes: 512,
            peers: 8,
        }
    }
}

/// First-passage statistics for a fluff flood, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FloodSummary {
    /// Node-reachings observed.
    pub samples: usize,
    /// Mean time for the flood to reach an arbitrary node.
    pub mean_ms: f64,
    /// Median.
    pub p50_ms: u64,
    /// 90th percentile — the conservative choice for a derivation input.
    pub p90_ms: u64,
}

/// Measure how long a fluff flood takes to travel back to an arbitrary node.
///
/// This is the quantity **RD-1** identified as missing from the embargo
/// derivation. A stem node's embargo is not disarmed when the terminal node
/// *emits* the fluff — it is disarmed when that fluff *reaches it* and
/// `upgrade_relay_method` transitions the transaction out of stem state
/// (`tx_pool.cpp` `set_relayed` / `add_tx`). Every edge of the return flood
/// carries a fluff delay, so the stem node's true exposure window is
/// `(h-i)·hop + F_i`, not `(h-i)·hop`.
///
/// The flood is modelled as a first-passage problem on a random graph: each
/// node relays to `peers` others, and the delay on each edge is an independent
/// draw from the fluff distribution — which is what the daemon does, since a
/// node draws one flush deadline per peer connection.
///
/// The distribution choice matters enormously here, and in the *helpful*
/// direction. First passage is a minimum over many parallel paths. Under a
/// memoryless delay the minimum of `n` draws collapses toward `mean/n`, so the
/// flood is fast; under the inherited near-deterministic Poisson every path
/// costs about the same, so the minimum buys nothing and the flood is slow.
/// **Fixing F-4 substantially repairs the gap that counting `F_i` opens.**
///
/// # Panics
///
/// Panics if `trials` is zero, if `nodes` is under two, or if `peers` is zero.
#[must_use]
pub fn simulate_fluff_return<R: RelayRng + ?Sized>(
    flood: FloodParams,
    mean_quarter_secs: u32,
    distribution: crate::schedule::EmbargoDistribution,
    trials: usize,
    rng: &mut R,
) -> FloodSummary {
    assert!(trials > 0, "simulation needs at least one trial");
    assert!(flood.nodes >= 2, "a flood needs at least two nodes");
    assert!(flood.peers >= 1, "a flood needs at least one peer per node");

    let poisson = matches!(distribution, crate::schedule::EmbargoDistribution::Poisson)
        .then(|| PoissonTable::new(mean_quarter_secs));
    let geometric = matches!(
        distribution,
        crate::schedule::EmbargoDistribution::Geometric
    )
    .then(|| crate::geometric::GeometricTable::new(mean_quarter_secs));
    let draw_ms = |rng: &mut R| -> u64 {
        let quarter_secs = match (&poisson, &geometric) {
            (Some(t), _) => t.draw(rng),
            (_, Some(t)) => t.draw(rng),
            _ => unreachable!("exactly one table is built"),
        };
        quarter_secs.saturating_mul(250)
    };

    let peers = flood.peers.min(flood.nodes - 1);
    let mut arrivals: Vec<u64> = Vec::with_capacity(trials * flood.nodes);

    for _ in 0..trials {
        // Adjacency drawn fresh per trial: peer sets rotate, and averaging over
        // topologies is more honest than pinning one lucky graph.
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::with_capacity(peers); flood.nodes];
        for node in 0..flood.nodes {
            for _ in 0..peers {
                let other = usize_from(bounded_uniform(rng, (flood.nodes - 1) as u64));
                if other != node {
                    adjacency[node].push(other);
                    adjacency[other].push(node); // fluff travels both ways
                }
            }
        }

        // Dijkstra from the fluffing node, edge weights drawn lazily.
        let mut best = vec![u64::MAX; flood.nodes];
        let mut frontier = std::collections::BinaryHeap::new();
        best[0] = 0;
        frontier.push(std::cmp::Reverse((0_u64, 0_usize)));
        while let Some(std::cmp::Reverse((at, node))) = frontier.pop() {
            if at > best[node] {
                continue;
            }
            // Each outgoing edge draws its own delay: a node arms one flush
            // deadline per peer connection, which is what the daemon does.
            let neighbours = adjacency[node].clone();
            for next in neighbours {
                let arrival = at.saturating_add(draw_ms(rng));
                if arrival < best[next] {
                    best[next] = arrival;
                    frontier.push(std::cmp::Reverse((arrival, next)));
                }
            }
        }

        // Node 0 is the source; every other reached node is a sample.
        arrivals.extend(best.iter().skip(1).filter(|t| **t != u64::MAX));
    }

    arrivals.sort_unstable();
    let samples = arrivals.len();
    assert!(
        samples > 0,
        "flood reached no node — check the topology inputs"
    );
    let mean_ms = arrivals.iter().map(|t| *t as f64).sum::<f64>() / samples as f64;
    let idx = |q: f64| arrivals[(((samples as f64) * q) as usize).min(samples - 1)];

    FloodSummary {
        samples,
        mean_ms,
        p50_ms: idx(0.50),
        p90_ms: idx(0.90),
    }
}

fn usize_from(v: u64) -> usize {
    usize::try_from(v).expect("draw was bounded by a usize-derived range")
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

/// The preemption profile: **who** preempts, not just how often.
///
/// **Q-8's first-class instrument.** The total preemption rate says the
/// embargo fires on ~10% of transactions; it does not say *which stem node*
/// does the fluffing, and that is the entire question, because a preemption by
/// the origin leaks the origin while a preemption by a late relay leaks almost
/// nothing. Once the profile is a first-class output, any leakage-weight
/// vector `w(i)` is a downstream dot product ([`Self::weighted_leakage`]) and a
/// design round can compare targets without re-deriving anything.
#[derive(Debug, Clone, PartialEq)]
pub struct PreemptionProfile {
    /// Trials run.
    pub trials: usize,
    /// Fraction of trials in which some stem node preempted.
    pub p_preempt: f64,
    /// `first[i]` = P(the *first* (earliest-firing) preempter is at separation
    /// `i` from the origin | a preemption occurred). Separation 0 is the origin
    /// itself. This is the distribution a leakage weighting acts on: the first
    /// node to fluff early is the one that reveals itself.
    pub first: Vec<f64>,
    /// `marginal[i]` = P(the node at separation `i` fires before its own
    /// disarm), per trial, unconditional. The analytic cross-check anchor
    /// ([`crate::derive::marginal_preemption_profile`]) targets this, because
    /// unlike the first-preempter order statistic it is a clean running
    /// product.
    pub marginal: Vec<f64>,
}

impl PreemptionProfile {
    /// Expected leakage under a per-separation weight vector, as a fraction of
    /// the no-Dandelion baseline (every transaction fluffs at its origin, so
    /// baseline leakage is `w[0]`).
    ///
    /// This is the number Q-8 is actually about: `w` encodes how much an
    /// adversary learns from a preemption at each separation, and the ratio
    /// says how much of the un-protected leakage survives the design. `w[0]`
    /// must be the origin weight and non-zero.
    ///
    /// # Panics
    ///
    /// Panics if `weights` is empty or `weights[0]` is zero.
    #[must_use]
    pub fn weighted_leakage(&self, weights: &[f64]) -> f64 {
        assert!(!weights.is_empty(), "need at least the origin weight");
        assert!(weights[0] != 0.0, "baseline weight w[0] must be non-zero");
        let weighted: f64 = self
            .first
            .iter()
            .zip(weights.iter())
            .map(|(share, w)| share * w)
            .sum();
        self.p_preempt * weighted / weights[0]
    }

    /// Separation carrying the largest share of first-preemptions.
    #[must_use]
    pub fn modal_separation(&self) -> usize {
        self.first
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).expect("finite shares"))
            .map_or(0, |(i, _)| i)
    }
}

/// Measure the preemption profile at a parameter set and embargo.
///
/// Walks the stem exactly as [`simulate_propagation`] does — same
/// disarm-on-observation model (RD-1), same terminal-node-discards-its-embargo
/// rule — but records each stem node's embargo deadline so it can attribute
/// the preemption to a position rather than only counting it.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_preemption_profile<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    trials: usize,
    rng: &mut R,
) -> PreemptionProfile {
    assert!(trials > 0, "profile needs at least one trial");
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);

    let mut first_counts: Vec<u64> = Vec::new();
    let mut marginal_counts: Vec<u64> = Vec::new();
    let mut preempted = 0_u64;

    // Reused across trials to avoid per-trial allocation.
    let mut deadlines: Vec<u64> = Vec::new();

    for _ in 0..trials {
        deadlines.clear();
        let mut t = 0_u64;
        loop {
            let deadline = embargo.deadline(t, rng);
            // RD-4: the origin always stems; the fluff coin applies from the
            // first relay. `deadlines.len()` is the position about to be armed,
            // so 0 is the origin. A fluffing node discards its own embargo.
            if !deadlines.is_empty() && bernoulli(rng, q, 100) {
                break;
            }
            deadlines.push(deadline);
            if deadlines.len() >= MAX_SIMULATED_HOPS {
                break;
            }
            t = t.saturating_add(hop_ms);
        }

        let natural_fluff = deadlines.len() as u64 * hop_ms;
        let disarm = natural_fluff.saturating_add(return_ms);

        if deadlines.len() > marginal_counts.len() {
            marginal_counts.resize(deadlines.len(), 0);
            first_counts.resize(deadlines.len(), 0);
        }

        let mut earliest: Option<(u64, usize)> = None;
        for (i, deadline) in deadlines.iter().enumerate() {
            if *deadline < disarm {
                marginal_counts[i] += 1; // this node fires before its disarm
                if earliest.is_none_or(|(best, _)| *deadline < best) {
                    earliest = Some((*deadline, i));
                }
            }
        }
        if let Some((_, sep)) = earliest {
            preempted += 1;
            first_counts[sep] += 1;
        }
    }

    let denom = trials as f64;
    let p_preempt = preempted as f64 / denom;
    let first = if preempted == 0 {
        vec![0.0; first_counts.len()]
    } else {
        first_counts
            .iter()
            .map(|c| *c as f64 / preempted as f64)
            .collect()
    };
    let marginal = marginal_counts.iter().map(|c| *c as f64 / denom).collect();

    PreemptionProfile {
        trials,
        p_preempt,
        first,
        marginal,
    }
}

/// The gap an adversary with an earlier sighting sees between that sighting and
/// the fluff, split by whether the fluff was natural or embargo-induced.
///
/// **The C1×C3 crux (Round 2).** A fluff-only observer has no reference time,
/// so an embargo fluff's lateness is invisible to it and the preemption channel
/// pools into the ~20% per-epoch q-channel's deniability. But an adversary with
/// *any* earlier sighting — a single stem spy anywhere on the path — sees the
/// gap Δ between its sighting and the fluff. A natural fluff puts Δ at
/// stem-completion scale (sub-second to a few seconds); an embargo fluff puts Δ
/// at the embargo mean (~112 s). If the two are separable, a classified embargo
/// fluff has *no* q-channel deniability, and its source is a stem-prefix member
/// — the origin with the profile's conditional probability. This measures the
/// separation.
#[derive(Debug, Clone, PartialEq)]
pub struct SightingSeparation {
    /// Trials in which at least one stem node was a spy (Δ observable).
    pub observed: usize,
    /// Median natural-fluff gap, in ms.
    pub natural_p50_ms: u64,
    /// 99th-percentile natural-fluff gap, in ms — the upper edge of the
    /// natural band.
    pub natural_p99_ms: u64,
    /// 1st-percentile embargo-fluff gap, in ms — the lower edge of the embargo
    /// band.
    pub embargo_p01_ms: u64,
    /// Median embargo-fluff gap, in ms.
    pub embargo_p50_ms: u64,
    /// Fraction of observed trials the adversary misclassifies at the optimal
    /// single threshold between the two bands. Near zero ⇒ the channel is
    /// separable and C3 loses its deniability.
    pub misclassification_rate: f64,
}

/// Measure [`SightingSeparation`] at a spy fraction `f`.
///
/// Each stem node is an independent spy with probability `f`; the relevant
/// sighting is the earliest (lowest-position) spy, matching "one stem spy
/// anywhere on the path". The gap is from that spy's sighting to the
/// stem-ending fluff; a fixed marginal return term is added for realism but is
/// negligible against the embargo scale.
///
/// # Panics
///
/// Panics if `trials` is zero or `spy_fraction` is not in `(0, 1]`.
#[must_use]
pub fn simulate_sighting_separability<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    spy_fraction: f64,
    trials: usize,
    rng: &mut R,
) -> SightingSeparation {
    assert!(trials > 0, "need at least one trial");
    assert!(
        spy_fraction > 0.0 && spy_fraction <= 1.0,
        "spy fraction must be in (0, 1]"
    );
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    // A stem spy observes the fluff after one flood-return hop; use the
    // marginal return, which is ~1.5 s and immaterial against the embargo.
    let return_ms = u64::from(params.fluff_return_ms);
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;
    let is_spy = |rng: &mut R| (rng.next_u64() as u32) < spy_threshold;

    let mut natural: Vec<u64> = Vec::new();
    let mut embargo_gaps: Vec<u64> = Vec::new();

    for _ in 0..trials {
        // Walk the stem, recording per-position embargo deadlines and the
        // lowest spy position.
        let mut deadlines: Vec<u64> = Vec::new();
        let mut first_spy: Option<u64> = None; // absolute sighting time
        let mut t = 0_u64;
        loop {
            if first_spy.is_none() && is_spy(rng) {
                first_spy = Some(t);
            }
            let deadline = embargo.deadline(t, rng);
            // RD-4: the origin always stems; fluff coin from the first relay.
            if !deadlines.is_empty() && bernoulli(rng, q, 100) {
                break; // terminal fluffer
            }
            deadlines.push(deadline);
            if deadlines.len() >= MAX_SIMULATED_HOPS {
                break;
            }
            t = t.saturating_add(hop_ms);
        }

        let Some(sighting) = first_spy else {
            continue; // no spy on this stem; Δ unobservable
        };

        let natural_fluff = deadlines.len() as u64 * hop_ms;
        let disarm = natural_fluff.saturating_add(return_ms);
        let earliest_embargo = deadlines.iter().copied().filter(|d| *d < disarm).min();

        // The stem-ending fluff is the earlier of the terminal's natural fluff
        // and the first embargo fire; the spy sees it one return hop later.
        let (fluff_time, is_embargo) = match earliest_embargo {
            Some(e) if e < natural_fluff => (e, true),
            _ => (natural_fluff, false),
        };
        let observed_at = fluff_time.saturating_add(return_ms);
        let gap = observed_at.saturating_sub(sighting);
        if is_embargo {
            embargo_gaps.push(gap);
        } else {
            natural.push(gap);
        }
    }

    let observed = natural.len() + embargo_gaps.len();
    assert!(
        observed > 0,
        "no spy ever landed on a stem — raise f or trials"
    );
    natural.sort_unstable();
    embargo_gaps.sort_unstable();

    let pct = |v: &[u64], p: f64| -> u64 {
        if v.is_empty() {
            return 0;
        }
        v[(((v.len() as f64) * p) as usize).min(v.len() - 1)]
    };
    let natural_p99 = pct(&natural, 0.99);
    let embargo_p01 = pct(&embargo_gaps, 0.01);

    // Optimal threshold sits between the bands; misclassification counts
    // natural gaps above it plus embargo gaps below it.
    let threshold = natural_p99
        .max(1)
        .midpoint(embargo_p01.max(natural_p99 + 1));
    let mis_natural = natural.iter().filter(|g| **g >= threshold).count();
    let mis_embargo = embargo_gaps.iter().filter(|g| **g < threshold).count();
    let misclassification_rate = (mis_natural + mis_embargo) as f64 / observed as f64;

    SightingSeparation {
        observed,
        natural_p50_ms: pct(&natural, 0.50),
        natural_p99_ms: natural_p99,
        embargo_p01_ms: embargo_p01,
        embargo_p50_ms: pct(&embargo_gaps, 0.50),
        misclassification_rate,
    }
}

/// First-spy source-attribution precision in the fluff (diffusion) phase.
///
/// **π₀ (Round 2).** When a transaction fluffs, it floods; the first spy to
/// receive it guesses the source is the peer it received from (its
/// predecessor). This is the Fanti et al. first-spy estimator. π₀ is the
/// probability that guess is correct, and it is the precision the *stem* phase
/// exists to defend against — it also prices the q-channel and any classified
/// embargo fluff, whose source is attacked by exactly this estimator. Measured
/// under our memoryless flood so the number reflects the fixed distribution,
/// not the inherited near-deterministic one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FirstSpyPrecision {
    /// Floods in which at least one spy received the fluff.
    pub observed: usize,
    /// P(the first spy's predecessor is the true source | a spy saw it).
    pub precision: f64,
    /// Mean hop distance from source to the first spy.
    pub mean_first_spy_hops: f64,
}

/// Measure [`FirstSpyPrecision`] on a random graph with spy fraction `f`.
///
/// The source is node 0; each node relays to `peers` others with independent
/// memoryless edge delays (the flood [`simulate_fluff_return`] already models),
/// and each non-source node is a spy with probability `f`. The first spy to
/// receive the fluff is the one whose arrival time is least.
///
/// # Panics
///
/// Panics if `trials` is zero, `spy_fraction` is not in `(0, 1]`, or the
/// topology is degenerate.
#[must_use]
pub fn simulate_diffusion_first_spy<R: RelayRng + ?Sized>(
    flood: FloodParams,
    mean_quarter_secs: u32,
    distribution: crate::schedule::EmbargoDistribution,
    spy_fraction: f64,
    trials: usize,
    rng: &mut R,
) -> FirstSpyPrecision {
    assert!(trials > 0, "need at least one trial");
    assert!(flood.nodes >= 2 && flood.peers >= 1, "degenerate topology");
    assert!(
        spy_fraction > 0.0 && spy_fraction <= 1.0,
        "spy fraction must be in (0, 1]"
    );

    let poisson = matches!(distribution, crate::schedule::EmbargoDistribution::Poisson)
        .then(|| PoissonTable::new(mean_quarter_secs));
    let geometric = matches!(
        distribution,
        crate::schedule::EmbargoDistribution::Geometric
    )
    .then(|| crate::geometric::GeometricTable::new(mean_quarter_secs));
    let draw_ms = |rng: &mut R| -> u64 {
        match (&poisson, &geometric) {
            (Some(t), _) => t.draw(rng),
            (_, Some(t)) => t.draw(rng),
            _ => unreachable!("exactly one table"),
        }
        .saturating_mul(250)
    };

    let peers = flood.peers.min(flood.nodes - 1);
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;

    let mut correct = 0_usize;
    let mut observed = 0_usize;
    let mut first_spy_hops_total = 0_u64;

    for _ in 0..trials {
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::with_capacity(peers); flood.nodes];
        for node in 0..flood.nodes {
            for _ in 0..peers {
                let other = usize::try_from(bounded_uniform(rng, (flood.nodes - 1) as u64))
                    .expect("bounded");
                if other != node {
                    adjacency[node].push(other);
                    adjacency[other].push(node);
                }
            }
        }
        let spies: Vec<bool> = (0..flood.nodes)
            .map(|n| n != 0 && (rng.next_u64() as u32) < spy_threshold)
            .collect();

        // Dijkstra from source, tracking predecessor and hop count.
        let mut best = vec![u64::MAX; flood.nodes];
        let mut pred = vec![usize::MAX; flood.nodes];
        let mut hops = vec![0_u64; flood.nodes];
        let mut heap = std::collections::BinaryHeap::new();
        best[0] = 0;
        heap.push(std::cmp::Reverse((0_u64, 0_usize)));
        let mut first_spy: Option<(u64, usize)> = None;
        while let Some(std::cmp::Reverse((at, node))) = heap.pop() {
            if at > best[node] {
                continue;
            }
            if spies[node] {
                first_spy = Some((at, node));
                break; // Dijkstra pops in time order, so this is the first spy
            }
            for next in adjacency[node].clone() {
                let arrival = at.saturating_add(draw_ms(rng));
                if arrival < best[next] {
                    best[next] = arrival;
                    pred[next] = node;
                    hops[next] = hops[node] + 1;
                    heap.push(std::cmp::Reverse((arrival, next)));
                }
            }
        }

        if let Some((_, spy)) = first_spy {
            observed += 1;
            first_spy_hops_total += hops[spy];
            // The spy guesses its predecessor is the source; correct iff the
            // predecessor is node 0.
            if pred[spy] == 0 {
                correct += 1;
            }
        }
    }

    assert!(
        observed > 0,
        "no spy ever received the flood — raise f or trials"
    );
    FirstSpyPrecision {
        observed,
        precision: correct as f64 / observed as f64,
        mean_first_spy_hops: first_spy_hops_total as f64 / observed as f64,
    }
}

/// The Dandelion++ black-hole attack: an adversarial stem node drops a
/// transaction it has sighted, forcing an upstream embargo to fire and reveal
/// a stem-prefix member.
///
/// **The corrected C1×C3 (Round 2).** Building the passive-spy Δ instrument
/// ([`simulate_sighting_separability`]) surfaced a correction to the review's
/// framing: absent a black hole, an embargo fire that becomes the *first* fluff
/// must be a small draw (it has to beat the ~0.7 s natural completion), so it
/// lands at seconds scale and is a redundant race, not a 112 s-late leak. The
/// genuinely leaky C3 event needs an actual black hole — which is
/// *adversary-triggered*, and the adversary that drops the tx is the same one
/// with the sighting. So C1×C3 is not a coincidental composition; it is the
/// classic black-hole attack.
///
/// Here the adversary knows the fluff is forced (it caused it), so
/// Δ-separability is moot — the leak is the *source attribution*: the forced
/// fluff comes from `argmin` over the honest prefix's timers, which by the
/// preemption profile is origin-dominant. The instrument measures that profile,
/// and (the payoff) how it moves with the embargo mean.
#[derive(Debug, Clone, PartialEq)]
pub struct BlackHoleOutcome {
    /// Trials in which an adversary sighted the tx on the stem before it fluffed
    /// naturally (i.e. the attack was possible).
    pub attacks: usize,
    /// P(the forced fluff's source is the origin | an attack occurred). The
    /// attribution leak: the adversary learns the source is a prefix member,
    /// and this is how often that member is the origin.
    pub source_is_origin: f64,
    /// Full source-separation profile of the forced fluff (share by separation
    /// from origin), conditional on an attack.
    pub source_profile: Vec<f64>,
    /// Mean time the adversary waits from its sighting to the forced fluff, in
    /// ms — the adversary's cost, which *does* scale with the embargo mean.
    pub mean_wait_ms: f64,
}

/// Measure [`BlackHoleOutcome`] at spy fraction `f`.
///
/// The first spy on the stem is the adversary; it black-holes at its position
/// `b`. The honest prefix `0..b` arms embargoes and the earliest fires, flooding
/// the forced fluff. The attack requires `b >= 1` (a prefix to reveal); a spy at
/// the origin is the source itself, not an adversary, and is skipped.
///
/// # Panics
///
/// Panics if `trials` is zero or `spy_fraction` is not in `(0, 1]`.
#[must_use]
pub fn simulate_blackhole_attack<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    spy_fraction: f64,
    trials: usize,
    rng: &mut R,
) -> BlackHoleOutcome {
    assert!(trials > 0, "need at least one trial");
    assert!(
        spy_fraction > 0.0 && spy_fraction <= 1.0,
        "spy fraction must be in (0, 1]"
    );
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;

    let mut source_counts: Vec<u64> = Vec::new();
    let mut attacks = 0_u64;
    let mut wait_total = 0_u64;

    for _ in 0..trials {
        // Walk the stem, recording each honest node's absolute embargo
        // deadline, until a spy is reached (the adversary) or the tx fluffs.
        let mut deadlines: Vec<u64> = Vec::new(); // deadlines[i] = position i's fire time
        let mut adversary: Option<usize> = None;
        let mut t = 0_u64;
        let mut position = 0_usize;
        loop {
            let spy = (rng.next_u64() as u32) < spy_threshold;
            let deadline = embargo.deadline(t, rng);
            // RD-4: the origin always stems, so the natural fluff coin applies
            // from the first relay (position >= 1) onward.
            let fluffs = position >= 1 && bernoulli(rng, q, 100);
            if spy && position >= 1 {
                // The adversary sits here and black-holes. Positions 0..position
                // are the honest prefix that armed embargoes.
                adversary = Some(position);
                break;
            }
            if fluffs {
                break; // escaped: natural fluff before any adversary
            }
            deadlines.push(deadline); // honest node keeps its embargo
            if deadlines.len() >= MAX_SIMULATED_HOPS {
                break;
            }
            position += 1;
            t = t.saturating_add(hop_ms);
        }

        let Some(b) = adversary else {
            continue; // no attack this trial
        };
        // Honest prefix is positions 0..b; the earliest embargo fires and is the
        // forced fluff source. (deadlines has an entry per honest node passed,
        // i.e. positions 0..b.)
        let prefix = &deadlines[..b.min(deadlines.len())];
        let Some((fire_time, source)) = prefix
            .iter()
            .enumerate()
            .map(|(i, d)| (*d, i))
            .min_by_key(|(d, _)| *d)
        else {
            continue;
        };

        attacks += 1;
        if source >= source_counts.len() {
            source_counts.resize(source + 1, 0);
        }
        source_counts[source] += 1;
        // Adversary sighted at b*hop; forced fluff reaches it one return later.
        let sighting = b as u64 * hop_ms;
        let observed = fire_time.saturating_add(return_ms);
        wait_total += observed.saturating_sub(sighting);
    }

    assert!(attacks > 0, "no attack ever occurred — raise f or trials");
    let source_profile = source_counts
        .iter()
        .map(|c| *c as f64 / attacks as f64)
        .collect::<Vec<_>>();
    BlackHoleOutcome {
        attacks: attacks as usize,
        source_is_origin: source_profile.first().copied().unwrap_or(0.0),
        source_profile,
        mean_wait_ms: wait_total as f64 / attacks as f64,
    }
}

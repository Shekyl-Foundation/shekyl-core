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
/// **Zone:** models the public (clearnet) zone, where fluff reaches inbound and
/// outbound peers (`levin_notify.cpp:448`). On I2P/Tor fluff is outbound-only, so
/// the return flood is sparser and `F` larger — a Tor variant is a build item
/// (design §6.3, §10.8).
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
/// **Zone:** public-zone only — the inbound-spy sighting it models does not
/// exist on the outbound-only Tor topology (design §6.3, §10.8).
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
///
/// **Zone:** public-zone flood (fluff reaches inbound peers). On Tor the spy
/// must be an outbound successor, a different and costlier position (§6.3).
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

/// Which transport zone the origin relays over — the distinction
/// [`levin_notify.cpp:448`] gates fluff visibility on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Public zone: a node fluffs to **all** peers, inbound and outbound. An
    /// inbound sybil edge receives the fluff.
    Clearnet,
    /// I2P/Tor zone: a node fluffs to **outbound connections only**. An inbound
    /// sybil edge receives nothing, and a spy cannot force honest nodes to dial
    /// it (Dandelion++ Prop. 2), so the supernode observer collapses.
    Anonymity,
}

/// What a supernode observer learns from the diffusion phase, per transport —
/// the *quantified* clearnet-vs-Tor security delta for this mechanism.
///
/// The adversary is a supernode: it opens cheap **inbound** edges to a fraction
/// `dial_fraction` of honest nodes (the direction the paper says spies can
/// create freely). It cannot make honest nodes dial *it* (Prop. 2), so it has
/// no outbound presence. On clearnet those inbound edges receive fluff; on Tor
/// they do not. This measures the difference the source fact
/// ([`levin_notify.cpp:448`]) produces, so the Tor recommendation rests on a
/// number rather than on "Tor is more private."
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SupernodeObservation {
    /// Transport measured.
    pub transport: Transport,
    /// Fraction of transactions whose fluff the supernode observes at all.
    pub observed_fraction: f64,
    /// Among observed floods, P(the supernode's first-received predecessor is
    /// the true source) — the **inbound-fluff** first-spy attribution precision.
    ///
    /// The Tor `0.000` here means "zero via the cheap inbound direction," not
    /// "zero first-spy precision on Tor": a supernode over Tor can still spend
    /// the expensive resource it cannot create for free — an on-path *outbound*
    /// stem-successor position — and there its reach is the black-hole channel's
    /// (measured separately by [`simulate_blackhole_attack`]), not zero. This
    /// field is only the inbound observable.
    pub first_spy_precision: f64,
}

/// Measure [`SupernodeObservation`] under a transport.
///
/// Honest topology: `flood.nodes` nodes, each dialing `flood.peers` random
/// others (directed edges). Fluff from a source propagates over *all* edges on
/// clearnet and over *outbound* edges only on Tor. The supernode dials
/// `dial_fraction · nodes` honest nodes (its inbound edges to them) and is
/// dialed by none.
///
/// # Panics
///
/// Panics on a degenerate topology, a `dial_fraction` outside `(0, 1]`, or zero
/// trials.
#[must_use]
pub fn simulate_transport_observation<R: RelayRng + ?Sized>(
    flood: FloodParams,
    mean_quarter_secs: u32,
    distribution: crate::schedule::EmbargoDistribution,
    dial_fraction: f64,
    transport: Transport,
    trials: usize,
    rng: &mut R,
) -> SupernodeObservation {
    assert!(trials > 0, "need at least one trial");
    assert!(flood.nodes >= 3 && flood.peers >= 1, "degenerate topology");
    assert!(
        dial_fraction > 0.0 && dial_fraction <= 1.0,
        "dial fraction must be in (0, 1]"
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

    let n = flood.nodes;
    let peers = flood.peers.min(n - 1);
    let dial_threshold = (dial_fraction * f64::from(u32::MAX)) as u32;

    let mut observed = 0_usize;
    let mut correct = 0_usize;

    for _ in 0..trials {
        // Honest directed edges u -> v. `out[u]` = nodes u dialed. For the
        // clearnet flood we also need the reverse (who dialed u).
        let mut out: Vec<Vec<usize>> = vec![Vec::with_capacity(peers); n];
        let mut inbound: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (u, out_u) in out.iter_mut().enumerate() {
            for _ in 0..peers {
                let v = usize::try_from(bounded_uniform(rng, (n - 1) as u64)).expect("bounded");
                if v != u {
                    out_u.push(v);
                    inbound[v].push(u);
                }
            }
        }
        // The supernode's inbound edges: the honest nodes it dialed. On
        // clearnet these deliver fluff to it; on Tor they do not.
        let watched: Vec<bool> = (0..n)
            .map(|_| (rng.next_u64() as u32) < dial_threshold)
            .collect();

        // Source is node 0; Dijkstra over the transport-appropriate edge set.
        let source = 0_usize;
        let mut best = vec![u64::MAX; n];
        let mut pred = vec![usize::MAX; n];
        let mut heap = std::collections::BinaryHeap::new();
        best[source] = 0;
        heap.push(std::cmp::Reverse((0_u64, source)));

        // The supernode observes node w's fluff when w relays and the adversary
        // holds an edge that carries it: clearnet = any peer of w (so w's
        // inbound-watched status); Tor = only if w dialed the adversary, which
        // it never does. So on Tor the supernode observes nothing — modelled by
        // gating the observation on the transport below.
        let mut first_obs: Option<usize> = None; // the honest node whose fluff the adversary first caught

        while let Some(std::cmp::Reverse((at, node))) = heap.pop() {
            if at > best[node] {
                continue;
            }
            // Does the adversary catch this node's fluff?
            let caught = match transport {
                // Clearnet: the adversary dialed `node` (its inbound edge to
                // `node`), and `node` fluffs to inbound peers.
                Transport::Clearnet => watched[node] && node != source,
                // Tor: the adversary would need `node` to have dialed it. It
                // never does (Prop. 2) — structurally zero.
                Transport::Anonymity => false,
            };
            if caught {
                first_obs = Some(node);
                break;
            }
            for &next in &out[node] {
                let arrival = at.saturating_add(draw_ms(rng));
                if arrival < best[next] {
                    best[next] = arrival;
                    pred[next] = node;
                    heap.push(std::cmp::Reverse((arrival, next)));
                }
            }
            // Clearnet fluff also traverses inbound edges (a node fluffs to
            // peers that dialed it). Model that reverse spread too.
            if matches!(transport, Transport::Clearnet) {
                for &next in &inbound[node] {
                    let arrival = at.saturating_add(draw_ms(rng));
                    if arrival < best[next] {
                        best[next] = arrival;
                        pred[next] = node;
                        heap.push(std::cmp::Reverse((arrival, next)));
                    }
                }
            }
        }

        if let Some(node) = first_obs {
            observed += 1;
            // The supernode guesses the source is `node`'s predecessor in the
            // flood — its own first-spy estimator. Correct iff that is node 0.
            if pred[node] == source || node == source {
                correct += 1;
            }
        }
    }

    let observed_fraction = observed as f64 / trials as f64;
    let first_spy_precision = if observed == 0 {
        0.0
    } else {
        correct as f64 / observed as f64
    };
    SupernodeObservation {
        transport,
        observed_fraction,
        first_spy_precision,
    }
}

/// The **W3 residual**: how often an adversary occupies *both* of the origin's
/// outbound stem slots (`out_mapping_`) — the one exposure reshape cannot route
/// around, and therefore the `δ` a `ρ` decision is taken against (§12, §13.4).
/// This is *not* the demoted §13 table: that measured the leak of a mechanism we
/// replace; this measures the leak that *survives* the replacement.
///
/// **Grounded as an OUTBOUND-occupancy channel, not the inbound reach.**
/// [`dandelionpp.cpp:103-122`] builds `out_mapping_` by selecting `STEMS = 2`
/// distinct peers, *without replacement*, from the origin's **outbound** pool
/// (`P2P_DEFAULT_CONNECTIONS_COUNT = 12`, `cryptonote_config.h:134`). An adversary
/// enters that pool only by being *selected* as an outbound peer — a *different*
/// capability than the cheap inbound dialing that gives
/// [`simulate_transport_observation`]'s `dial_fraction`, so importing that inbound
/// reach here would measure a phantom (a channel the capability cannot reach). But
/// this capability is **not** necessarily costly: the outbound pool is 70 %
/// white-list + 2 anchors (`P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT`,
/// `P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT`), and the white list is gossip-fed, so an
/// eclipse-capable adversary drives `g` **above** the network fraction `f` by cheap
/// peerlist poisoning. This instrument measures `W3(g)` but does **not** bound `g`
/// — that bound is owed by the anti-eclipse peer-selection grounding (§12.6, Q-10),
/// and `ρ` is blocked on it, not decidable against `g = f`.
///
/// Reshape (`retry_cap = STEMS − 1 = 1`) routes around an adversarial primary
/// *iff* the alternate slot is honest, so the residual it cannot remove is exactly
/// `P(both slots adversarial)`. W3b (the adversary pinning the origin to one live
/// slot via induced churn) is a *cheaper*, capability-gated case bounded above by
/// the single-slot occupancy reported here; it needs an eviction capability this
/// instrument does not grant for free.
///
/// **Single-draw occupancy — a lower bound under churn.** This measures one stable
/// epoch map. Mid-epoch, `connection_map::update()` re-rolls a churned slot with a
/// *fresh* draw (`dandelionpp.cpp:160`), so an adversary who induces churn re-rolls
/// the enriched draw repeatedly (W3c, `DAEMON_RELAY_PRIVACY.md` §12.6). The
/// effective per-epoch occupancy under adversary-induced churn is therefore
/// *higher* than this single-draw number, and Q-10's `g`-bound must hold under
/// repeated refills — this instrument does not model churn.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TwoSlotOccupancy {
    /// `g` — the adversary's share of the origin's outbound pool.
    pub outbound_share: f64,
    /// `D_out` — the origin's outbound degree (daemon default 12).
    pub outbound_degree: usize,
    /// **W3.** `P(both stem slots adversarial)` — the exposure that survives
    /// reshape, and the number a `ρ` decision is taken against.
    pub both_slots: f64,
    /// `P(≥ 1 stem slot adversarial)` — the pre-reshape single-slot exposure, and
    /// the ceiling for the churn-gated W3b case.
    pub at_least_one_slot: f64,
    /// `(a/D_out)²` — the with-replacement reference at the *effective* integer
    /// adversary share `a = round(g·D_out)`. `both_slots` sits *below* it:
    /// choosing two *distinct* peers from a finite pool is anti-correlated
    /// (`both_slots = both_slots_with_replacement · (a−1)/a · D_out/(D_out−1)`),
    /// so W3 is bounded above by the independent draw, not merely equal to it.
    pub independent_reference: f64,
}

/// Measure [`TwoSlotOccupancy`] at outbound share `g` over a pool of
/// `outbound_degree` peers, mirroring the partial Fisher-Yates selection of
/// `out_mapping_` at [`dandelionpp.cpp:113-118`].
///
/// The integer rounding of `g · D_out` is deliberate, not a modelling shortcut: a
/// real adversary holds an integer number of the origin's outbound slots, and at
/// `D_out = 12` that granularity *is* the result — `g = 0.10` is ~1 peer, which
/// cannot fill two slots at all, so baseline `both_slots ≈ 0` until enrichment
/// lifts `g` well above the raw node fraction `f`.
///
/// # Panics
///
/// Panics if `trials` is zero, `outbound_degree < 2`, or `outbound_share` is
/// outside `[0, 1]`.
#[must_use]
pub fn simulate_two_slot_occupancy<R: RelayRng + ?Sized>(
    outbound_share: f64,
    outbound_degree: usize,
    trials: usize,
    rng: &mut R,
) -> TwoSlotOccupancy {
    assert!(trials > 0, "need at least one trial");
    assert!(
        outbound_degree >= 2,
        "need at least two outbound peers to fill two stem slots"
    );
    assert!(
        (0.0..=1.0).contains(&outbound_share),
        "outbound share must be in [0, 1]"
    );

    let d = outbound_degree;
    // The adversary holds the first `a` of the `d` outbound peers.
    let a = (outbound_share * d as f64).round() as usize;

    let mut both = 0_usize;
    let mut at_least_one = 0_usize;
    for _ in 0..trials {
        // Two distinct slot indices in `[0, d)`, mirroring the swap-and-pick of
        // dandelionpp.cpp:116 (second draw taken from the remaining `d − 1` and
        // mapped around the first). `bounded_uniform` is inclusive [0, max], so the
        // first draw uses `d - 1` (→ [0, d)) and the second uses `d - 2` (→ the
        // remaining `d − 1` values, mapped around `s0`).
        let s0 = usize_from(bounded_uniform(rng, (d - 1) as u64));
        let r = usize_from(bounded_uniform(rng, (d - 2) as u64));
        let s1 = if r < s0 { r } else { r + 1 };
        let adv0 = s0 < a;
        let adv1 = s1 < a;
        both += usize::from(adv0 && adv1);
        at_least_one += usize::from(adv0 || adv1);
    }

    let effective_share = a as f64 / d as f64;
    TwoSlotOccupancy {
        outbound_share,
        outbound_degree: d,
        both_slots: both as f64 / trials as f64,
        at_least_one_slot: at_least_one as f64 / trials as f64,
        independent_reference: effective_share * effective_share,
    }
}

/// **Q1 layering discriminator (§12.8):** how an adversary holding `adversary_peers`
/// slots in the origin's stem-eligible set is exposed across epochs, as a function
/// of the set size — the number that decides "pin the set of `K`" vs. the current
/// ~12-peer pool, turning the layering call from an argument into a measurement.
///
/// Each epoch the origin's `nil`-keyed stem successor is drawn uniformly from the
/// eligible set (the `change_channels` rebuild, §12.8 G-2). The **pool** regime is
/// `eligible_set_size = D_out` (≈12); the **pinned** regime is `= K`. Holding the
/// adversary's *peer count* `a` fixed (not its share), this isolates the two axes
/// that pull opposite ways under pinning:
///
/// - **Direct-successor exposure** — the occupancy / C1 axis, and the *dominant*
///   one, because a captured successor identifies the origin at precision 1. The
///   per-epoch presence is `a / set`, so shrinking `D → K` **amplifies** a captured
///   slot's presence by `D/K`. This is the advisor-flagged risk: a single pinned
///   adversary's cross-epoch presence rises from `~1/D` to `~1/K`.
/// - **Cross-epoch successor diversity** — the intersection axis (§6.8). A smaller
///   set yields fewer distinct successors, which *slows* the intersection's collapse
///   toward `{origin}` — protective, but secondary to the direct-successor axis.
///
/// The decision this feeds: pinning to a small `K` is net-harmful on the dominant
/// axis unless the pin-admission bound (`g_max`, Q4) makes holding `a` slots in `K`
/// harder than in `D` by **more than the `D/K` amplification**.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpochLayering {
    /// The eligible set size (`D_out` for pool, `K` for pinned).
    pub eligible_set_size: usize,
    /// Adversary slots held in the eligible set (held fixed across the comparison).
    pub adversary_peers: usize,
    /// Epochs observed.
    pub epochs: usize,
    /// Per-epoch `P(adversary is the origin's successor)` = `a / eligible_set_size`.
    pub direct_successor_rate: f64,
    /// `P(adversary is the origin's successor in ≥ 1 of `epochs` epochs)`.
    pub p_identified_direct: f64,
    /// Mean number of distinct successors the origin uses across `epochs` epochs —
    /// the cross-epoch diversity that governs the intersection collapse.
    pub distinct_successors: f64,
}

/// Measure [`EpochLayering`] for `adversary_peers` of `eligible_set_size` over
/// `epochs` epochs. Adversary holds indices `0..adversary_peers`.
///
/// # Panics
///
/// Panics if `trials`/`epochs` is zero, the set is empty, or `adversary_peers`
/// exceeds `eligible_set_size`.
#[must_use]
pub fn simulate_epoch_layering<R: RelayRng + ?Sized>(
    eligible_set_size: usize,
    adversary_peers: usize,
    epochs: usize,
    trials: usize,
    rng: &mut R,
) -> EpochLayering {
    assert!(trials > 0, "need at least one trial");
    assert!(eligible_set_size >= 1, "eligible set must be non-empty");
    assert!(epochs >= 1, "need at least one epoch");
    assert!(
        adversary_peers <= eligible_set_size,
        "adversary cannot hold more slots than the set has"
    );

    let mut present_epochs_total = 0_u64;
    let mut identified_trials = 0_usize;
    let mut distinct_total = 0_u64;

    for _ in 0..trials {
        let mut present_this_trial = false;
        let mut seen = vec![false; eligible_set_size];
        let mut distinct = 0_u64;
        for _ in 0..epochs {
            // `bounded_uniform` is inclusive [0, max], so draw over set_size - 1.
            let s = usize_from(bounded_uniform(rng, (eligible_set_size - 1) as u64));
            if s < adversary_peers {
                present_this_trial = true;
                present_epochs_total += 1;
            }
            if !seen[s] {
                seen[s] = true;
                distinct += 1;
            }
        }
        identified_trials += usize::from(present_this_trial);
        distinct_total += distinct;
    }

    EpochLayering {
        eligible_set_size,
        adversary_peers,
        epochs,
        direct_successor_rate: present_epochs_total as f64 / (trials as f64 * epochs as f64),
        p_identified_direct: identified_trials as f64 / trials as f64,
        distinct_successors: distinct_total as f64 / trials as f64,
    }
}

/// The clearnet passive inbound-neighbour channel: how often a supernode's
/// inbound edge to a stem-prefix node catches that node's *embargo-fired* fluff
/// before the natural diffusion, and attributes the source to a prefix member.
///
/// **The mean-DEPENDENT channel (Round 3).** Unlike the black-hole
/// ([`simulate_blackhole_attack`], mean-invariant), the passive channel's leaky
/// event is a *real* preemption — a prefix node's embargo firing before it is
/// disarmed — and `P(preempt)` scales *down* with the embargo mean. So a longer
/// (correctly-provisioned) embargo reduces this leak, which is precisely what
/// makes correct embargo provisioning (`ε`) a live lever *on clearnet*. On Tor
/// the channel is structurally zero: fluff never traverses the supernode's
/// inbound edges ([`levin_notify.cpp:448`], §6.3), so there is nothing to catch.
///
/// This is the instrument §10.8 deferred; it is built because the frozen default
/// supports clearnet origins, so the channel is in scope by policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PassiveNeighborLeak {
    /// Transport measured.
    pub transport: Transport,
    /// Fraction of transactions where a neighboured prefix node's embargo fires
    /// before its disarm and so is caught by the supernode as an early fluff.
    pub leak_rate: f64,
    /// Among leaked transactions, P(the earliest such prefix node is the
    /// origin) — origin-biased, per the preemption profile.
    pub origin_share_of_leaks: f64,
}

/// Measure [`PassiveNeighborLeak`] at supernode reach `dial_fraction`.
///
/// Each stem-prefix node is neighboured by the supernode with probability
/// `dial_fraction` (a cheap inbound edge). A neighboured node leaks when its
/// embargo fires before its disarm (`natural_fluff + F`) — the same preemption
/// condition the survival equation counts — because on clearnet the supernode
/// receives that fluff directly, before the natural diffusion reaches it. The
/// origin always stems (RD-4).
///
/// # Panics
///
/// Panics if `trials` is zero or `dial_fraction` is outside `(0, 1]`.
#[must_use]
pub fn simulate_passive_neighbor_leak<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    dial_fraction: f64,
    transport: Transport,
    trials: usize,
    rng: &mut R,
) -> PassiveNeighborLeak {
    assert!(trials > 0, "need at least one trial");
    assert!(
        dial_fraction > 0.0 && dial_fraction <= 1.0,
        "dial fraction must be in (0, 1]"
    );
    let clearnet = matches!(transport, Transport::Clearnet);
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);
    let dial_threshold = (dial_fraction * f64::from(u32::MAX)) as u32;

    let mut leaks = 0_u64;
    let mut origin_leaks = 0_u64;

    for _ in 0..trials {
        // (absolute fire time, neighboured?) per stem-prefix position.
        let mut prefix: Vec<(u64, bool)> = Vec::new();
        let mut t = 0_u64;
        loop {
            // On Tor the inbound edge never delivers fluff, so no position is
            // observable — modelled by never marking a node neighboured.
            let neighboured = clearnet && (rng.next_u64() as u32) < dial_threshold;
            let deadline = embargo.deadline(t, rng);
            // RD-4: origin always stems; fluff coin from the first relay.
            if !prefix.is_empty() && bernoulli(rng, q, 100) {
                break;
            }
            prefix.push((deadline, neighboured));
            if prefix.len() >= MAX_SIMULATED_HOPS {
                break;
            }
            t = t.saturating_add(hop_ms);
        }

        let natural_fluff = prefix.len() as u64 * hop_ms;
        let disarm = natural_fluff.saturating_add(return_ms);

        // Earliest neighboured prefix node whose embargo fires before disarm.
        let mut earliest: Option<(u64, usize)> = None;
        for (i, (fire, neighboured)) in prefix.iter().enumerate() {
            if *neighboured && *fire < disarm && earliest.is_none_or(|(best, _)| *fire < best) {
                earliest = Some((*fire, i));
            }
        }
        if let Some((_, i)) = earliest {
            leaks += 1;
            if i == 0 {
                origin_leaks += 1;
            }
        }
    }

    let leak_rate = leaks as f64 / trials as f64;
    let origin_share_of_leaks = if leaks == 0 {
        0.0
    } else {
        origin_leaks as f64 / leaks as f64
    };
    PassiveNeighborLeak {
        transport,
        leak_rate,
        origin_share_of_leaks,
    }
}

/// Origin exposure to a **whole-prefix** supernode — the worst-case passive
/// leak, with the reshape (re-stem-on-embargo) lever.
///
/// **Round 3 — the composed leak, worst case.** `simulate_passive_neighbor_leak`
/// uses independent per-position neighbouring (each prefix node observed with
/// probability φ) — the *lower* reading. A single supernode that makes enough
/// inbound edges to cover the whole prefix observes **every** origin fluff, so
/// its origin-exposure is the full `P(origin fires) × 1`, not φ-scaled. That is
/// the upper bound an exposure-*risk* target must be measured against.
///
/// Two levers act here without touching the embargo mean:
/// - **F** (`fluff_return_ms`): the origin's disarm window is `h·hop + F`, so a
///   larger F lengthens the window and raises exposure. F is downstream of F-4
///   (the memoryless fix made the return flood ~7× faster, §10.6), so F-4 was a
///   *second* independent correction to this channel.
/// - **Reshape** (`retry_cap`): re-stem-on-embargo emits a stem forward (unicast
///   to one outbound successor, invisible to the passive inbound supernode)
///   instead of a fluff. The origin becomes observable only after exhausting
///   `retry_cap` re-stems, so each retry multiplies the residual exposure by
///   roughly the per-window fire probability — a geometric drop in `retry_cap`
///   with **no** embargo-length (liveness) cost.
///
/// The origin's embargo is modelled as a renewal process over its disarm window
/// `[0, h·hop + F)`: it fires whenever a memoryless interval elapses inside the
/// window, and fluffs observably iff it fires more than `retry_cap` times.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OriginExposure {
    /// Reshape retry cap (0 = fluff on first embargo fire, the current design).
    pub retry_cap: u32,
    /// P(the origin emits an observable fluff to a whole-prefix supernode).
    pub exposure_rate: f64,
}

/// Measure [`OriginExposure`] at a reshape `retry_cap`.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_origin_exposure<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    retry_cap: u32,
    trials: usize,
    rng: &mut R,
) -> OriginExposure {
    assert!(trials > 0, "need at least one trial");
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);

    let mut exposed = 0_u64;
    for _ in 0..trials {
        // Stem length h (RD-4: origin always stems; geometric on {1,2,…}).
        let mut h = 1_u64;
        while !bernoulli(rng, q, 100) {
            h += 1;
            if h >= MAX_SIMULATED_HOPS as u64 {
                break;
            }
        }
        let window = h.saturating_mul(hop_ms).saturating_add(return_ms);

        // Renewal count of embargo fires inside the origin's disarm window.
        let mut elapsed = 0_u64;
        let mut fires = 0_u32;
        loop {
            let interval = embargo.deadline(0, rng); // one memoryless interval, ms
            if elapsed.saturating_add(interval) >= window {
                break;
            }
            elapsed = elapsed.saturating_add(interval);
            fires += 1;
            if fires > retry_cap {
                break; // already observable; no need to keep counting
            }
        }
        if fires > retry_cap {
            exposed += 1;
        }
    }

    OriginExposure {
        retry_cap,
        exposure_rate: exposed as f64 / trials as f64,
    }
}

/// The δ increment-form adopt-criterion (§13), measured end-to-end rather than
/// composed by hand.
///
/// **Not a decision variable (§13 banner, §14).** This measures the leak of
/// *fluff-on-expiry* — the mechanism §14 *replaces* with reshape because it
/// spends privacy for performance. The number is kept and tested per RD-4
/// (*measure your numbers*), but that does not make it a tuning target: do not
/// pick `ρ`/`δ_max` against it, because reshape drives it to ~0. The live `δ` a
/// decision is taken against is the W3 residual, measured by the two-slot
/// occupancy instrument (§12.5), not this.
///
/// `δ := Precision_joint(C1 + C3) − Precision_joint(C1)`, where a
/// `Precision_joint` is `P(the adversary's single best origin-guess is correct,
/// per transaction)`:
///
/// - **C1** — the stem-spy channel: the origin's stem successor (position 1) is
///   a spy, so it received the tx directly from the origin and names it
///   correctly. `Precision(C1) = P(position 1 is a spy) = f`.
/// - **C3** — the forced-fluff channel our embargo adds: the origin's own
///   embargo fires before disarm (a preemption) *and* a spy observes the
///   resulting fluff. Independent-neighbour model (the §6.6 lower reading, and
///   the reviewer's): a spy neighbours the origin with probability `f`. Under
///   the whole-prefix / supernode enrichment (W3, §12) this rises — this
///   instrument is the lower bound the two-slot instrument tightens.
///
/// `retry_cap > 0` models reshape: the origin re-stems on embargo fire (up to
/// `STEMS − 1 = 1` alternates) instead of fluffing, so its forced fluff — and
/// thus the C3 term — is emitted only if it exhausts the cap. Reshape drives
/// `δ → 0` (§13.4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PrecisionIncrement {
    /// Spy fraction the measurement was taken at.
    pub spy_fraction: f64,
    /// `Precision(C1)` — stem channel alone.
    pub precision_c1: f64,
    /// `Precision(C1 + C3)` — stem OR forced-fluff.
    pub precision_c1_c3: f64,
    /// `δ` — the increment the embargo mechanism adds.
    pub delta: f64,
}

/// Measure [`PrecisionIncrement`] at spy fraction `f`, with an optional reshape
/// `retry_cap`.
///
/// # Panics
///
/// Panics if `trials` is zero or `spy_fraction` is outside `(0, 1)`.
#[must_use]
pub fn simulate_precision_increment<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    spy_fraction: f64,
    retry_cap: u32,
    trials: usize,
    rng: &mut R,
) -> PrecisionIncrement {
    assert!(trials > 0, "need at least one trial");
    assert!(
        spy_fraction > 0.0 && spy_fraction < 1.0,
        "spy fraction must be in (0, 1)"
    );
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;
    let is_spy = |rng: &mut R| (rng.next_u64() as u32) < spy_threshold;

    let mut c1_correct = 0_u64;
    let mut joint_correct = 0_u64;

    for _ in 0..trials {
        // Stem walk (RD-4): the origin (position 0) always stems; relays flip
        // the fluff coin from position 1.
        let mut deadlines: Vec<u64> = Vec::new();
        let mut t = 0_u64;
        loop {
            let d = embargo.deadline(t, rng);
            if !deadlines.is_empty() && bernoulli(rng, q, 100) {
                break;
            }
            deadlines.push(d);
            if deadlines.len() >= MAX_SIMULATED_HOPS {
                break;
            }
            t = t.saturating_add(hop_ms);
        }
        let natural_fluff = deadlines.len() as u64 * hop_ms;
        let disarm = natural_fluff.saturating_add(return_ms);

        // C1: the origin's successor (position 1) is a spy → it saw the tx from
        // the origin and names it correctly. Position 1 always exists (the
        // origin always has a stem successor). P = f.
        let c1 = is_spy(rng);
        if c1 {
            c1_correct += 1;
        }

        // C3: the origin's own embargo fires before disarm (a preemption). Under
        // reshape it re-stems up to `retry_cap` alternates and fluffs only if it
        // exhausts them — modelled by requiring `retry_cap + 1` independent fires
        // within the window (a renewal, as in `simulate_origin_exposure`), then
        // observed by a spy neighbour (independent, w.p. f).
        let origin_fluffs = {
            let mut elapsed = 0_u64;
            let mut fires = 0_u32;
            loop {
                let interval = embargo.deadline(0, rng);
                if elapsed.saturating_add(interval) >= disarm {
                    break;
                }
                elapsed = elapsed.saturating_add(interval);
                fires += 1;
                if fires > retry_cap {
                    break;
                }
            }
            fires > retry_cap
        };
        let c3_origin = origin_fluffs && is_spy(rng); // a spy neighbours the origin

        if c1 || c3_origin {
            joint_correct += 1;
        }
    }

    let n = trials as f64;
    let precision_c1 = c1_correct as f64 / n;
    let precision_c1_c3 = joint_correct as f64 / n;
    PrecisionIncrement {
        spy_fraction,
        precision_c1,
        precision_c1_c3,
        delta: precision_c1_c3 - precision_c1,
    }
}

/// Reshape's recovery-latency profile for a black-holed transaction — the one
/// place the "reshape strictly dominates fluff-on-expiry" claim can break.
///
/// **The performance cost of choosing privacy (§14).** Fluff-on-expiry recovers
/// a dropped tx in *one* embargo cycle (the embargo fires, the node diffuses
/// immediately). Reshape re-stems instead, so a dropped tx recovers in one cycle
/// when the alternate successor is honest, and in `retry_cap + 1` cycles in the
/// W3 case (every successor a black hole, then the fallback fluff). The retry cap
/// bounds it, so the worst-case recovery is `(retry_cap + 1)` embargo means. This
/// measures that the bound is a *cost* (a slower recovery) and not a *break* (the
/// tx never fails to propagate): the worst case must stay far under
/// `CRYPTONOTE_MEMPOOL_TX_LIVETIME` (3 days).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReshapeRecovery {
    /// Retry cap the profile was taken at.
    pub retry_cap: u32,
    /// Fluff-on-expiry recovery (one embargo cycle): p50 / p90 / p99, seconds.
    pub fluff_p50_s: f64,
    pub fluff_p90_s: f64,
    pub fluff_p99_s: f64,
    /// Reshape worst case (every successor black-holed → `cap+1` cycles then
    /// fallback fluff): p50 / p90 / p99, seconds.
    pub reshape_worst_p50_s: f64,
    pub reshape_worst_p90_s: f64,
    pub reshape_worst_p99_s: f64,
}

/// Measure [`ReshapeRecovery`] at a retry cap.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_reshape_recovery<R: RelayRng + ?Sized>(
    embargo: &EmbargoTimer,
    retry_cap: u32,
    trials: usize,
    rng: &mut R,
) -> ReshapeRecovery {
    assert!(trials > 0, "need at least one trial");
    // A dropped tx recovers when an embargo fires. Fluff = 1 fire; reshape
    // worst case = (retry_cap + 1) fires (each re-stem also dropped), then the
    // fallback fluff. Each fire is one embargo draw (memoryless).
    let mut one_cycle: Vec<u64> = Vec::with_capacity(trials);
    let mut worst: Vec<u64> = Vec::with_capacity(trials);
    for _ in 0..trials {
        let e1 = embargo.deadline(0, rng); // ms
        one_cycle.push(e1);
        let mut total = e1;
        for _ in 0..retry_cap {
            total = total.saturating_add(embargo.deadline(0, rng));
        }
        worst.push(total);
    }
    one_cycle.sort_unstable();
    worst.sort_unstable();
    let q = |v: &[u64], p: f64| -> f64 {
        let idx = (((v.len() as f64) * p) as usize).min(v.len() - 1);
        v[idx] as f64 / 1000.0
    };
    ReshapeRecovery {
        retry_cap,
        fluff_p50_s: q(&one_cycle, 0.50),
        fluff_p90_s: q(&one_cycle, 0.90),
        fluff_p99_s: q(&one_cycle, 0.99),
        reshape_worst_p50_s: q(&worst, 0.50),
        reshape_worst_p90_s: q(&worst, 0.90),
        reshape_worst_p99_s: q(&worst, 0.99),
    }
}

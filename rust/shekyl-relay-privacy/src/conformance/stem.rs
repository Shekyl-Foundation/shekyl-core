// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Goodness-of-fit grading / simulation is float math over sample counts.
//   Diagnostic-only and excluded from the default build.

use crate::params::DandelionParams;
use crate::rng::{bernoulli, RelayRng};
use crate::schedule::EmbargoTimer;

use super::util::MAX_SIMULATED_HOPS;

/// Per-trial record of one RD-4 stem walk: every armed position's absolute
/// embargo deadline, plus the natural-fluff and disarm times.
///
/// Shared by every stem instrument so RD-1/RD-4 fixes land once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StemTrace {
    /// Absolute embargo deadlines for positions `0..stem_hops` (origin = 0).
    /// The terminal fluffer does not contribute — it discards its embargo.
    pub deadlines: Vec<u64>,
    /// Monotonic time of the natural fluff (stem completion), in ms.
    pub natural_fluff_ms: u64,
    /// When each stem node's embargo is disarmed: natural fluff + return flood.
    pub disarm_ms: u64,
}

impl StemTrace {
    /// Number of stem hops (= armed positions = stem length under RD-4).
    #[must_use]
    pub fn stem_hops(&self) -> usize {
        self.deadlines.len()
    }

    /// True when some armed node's embargo fires before disarm.
    #[must_use]
    pub fn embargo_preempted(&self) -> bool {
        self.deadlines.iter().any(|&d| d < self.disarm_ms)
    }

    /// Earliest armed embargo deadline, or `u64::MAX` if none.
    #[must_use]
    pub fn earliest_embargo_ms(&self) -> u64 {
        self.deadlines.iter().copied().min().unwrap_or(u64::MAX)
    }
}

/// Walk a single RD-4 stem under `params` / `embargo`.
///
/// Origin (position 0) always stems. Relays flip the fluff coin. Each armed
/// node records its absolute embargo deadline; the terminal fluffer does not.
pub fn walk_stem<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    rng: &mut R,
) -> StemTrace {
    walk_stem_observing(params, embargo, rng, |_, _, _| {})
}

/// [`walk_stem`] with a per-position observer called *before* the position
/// arms its embargo, with `(position, absolute_time_ms, rng)`.
///
/// Used by instruments that inject spy / neighbour marks along the path.
pub fn walk_stem_observing<R, F>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    rng: &mut R,
    mut observe: F,
) -> StemTrace
where
    R: RelayRng + ?Sized,
    F: FnMut(usize, u64, &mut R),
{
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);

    let mut deadlines = Vec::new();
    let mut t = 0_u64;
    loop {
        let position = deadlines.len();
        observe(position, t, rng);
        let deadline = embargo.deadline(t, rng);
        // RD-4: origin always stems; fluff coin from the first relay onward.
        // A fluffing node discards its own embargo (not pushed).
        if position >= 1 && bernoulli(rng, q, 100) {
            break;
        }
        deadlines.push(deadline);
        if deadlines.len() >= MAX_SIMULATED_HOPS {
            break;
        }
        t = t.saturating_add(hop_ms);
    }

    let natural_fluff_ms = deadlines.len() as u64 * hop_ms;
    StemTrace {
        deadlines,
        natural_fluff_ms,
        disarm_ms: natural_fluff_ms.saturating_add(return_ms),
    }
}

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
/// Each trial is a [`walk_stem`]: the paper's RD-4/RD-1 model, measured rather
/// than assumed. See that helper for the arming / fluff / disarm rules.
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
    let mut outcomes = Vec::with_capacity(trials);
    for _ in 0..trials {
        let trace = walk_stem(params, embargo, rng);
        outcomes.push(Propagation {
            stem_hops: trace.stem_hops(),
            natural_fluff_ms: trace.natural_fluff_ms,
            earliest_embargo_ms: trace.earliest_embargo_ms(),
            embargo_preempted: trace.embargo_preempted(),
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
/// Bisects over the integer second. Re-seeds per probe so the search is
/// deterministic. See module docs in the design record for why measuring is
/// the only honest route past the closed form.
///
/// # Panics
///
/// Panics if `target` is not in `(0, 1)`, or if `trials` is zero.
#[must_use]
pub fn solve_embargo_secs_for_target(
    params: &DandelionParams,
    target: f64,
    family: crate::schedule::DelayFamily,
    trials: usize,
    seed: u64,
) -> Option<u32> {
    assert!(
        target > 0.0 && target < 1.0,
        "target must be a probability strictly inside (0, 1)"
    );
    assert!(trials > 0, "search needs at least one trial per probe");

    let measure = |secs: u32| -> f64 {
        let embargo = EmbargoTimer::new(secs, family);
        let mut rng = crate::rng::SplitMix64::new(seed);
        simulate_propagation(params, &embargo, trials, &mut rng).full_travel_rate
    };

    let mut hi = 1_u32;
    while measure(hi) < target {
        hi = hi.saturating_mul(2);
        if hi >= 1 << 20 {
            return None;
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

/// The preemption profile: **who** preempts, not just how often.
///
/// **Q-8's first-class instrument.** See design doc §6 / §12.
#[derive(Debug, Clone, PartialEq)]
pub struct PreemptionProfile {
    /// Trials run.
    pub trials: usize,
    /// Fraction of trials in which some stem node preempted.
    pub p_preempt: f64,
    /// `first[i]` = P(the first preempter is at separation `i` | preemption).
    pub first: Vec<f64>,
    /// `marginal[i]` = P(node at separation `i` fires before disarm), per trial.
    pub marginal: Vec<f64>,
}

impl PreemptionProfile {
    /// Expected leakage under a per-separation weight vector, as a fraction of
    /// the no-Dandelion baseline (`w[0]`).
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

    let mut first_counts: Vec<u64> = Vec::new();
    let mut marginal_counts: Vec<u64> = Vec::new();
    let mut preempted = 0_u64;

    for _ in 0..trials {
        let trace = walk_stem(params, embargo, rng);
        let disarm = trace.disarm_ms;

        if trace.deadlines.len() > marginal_counts.len() {
            marginal_counts.resize(trace.deadlines.len(), 0);
            first_counts.resize(trace.deadlines.len(), 0);
        }

        let mut earliest: Option<(u64, usize)> = None;
        for (i, deadline) in trace.deadlines.iter().enumerate() {
            if *deadline < disarm {
                marginal_counts[i] += 1;
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
#[derive(Debug, Clone, PartialEq)]
pub struct SightingSeparation {
    /// Trials in which at least one stem node was a spy (Δ observable).
    pub observed: usize,
    pub natural_p50_ms: u64,
    pub natural_p99_ms: u64,
    pub embargo_p01_ms: u64,
    pub embargo_p50_ms: u64,
    pub misclassification_rate: f64,
}

/// Measure [`SightingSeparation`] at a spy fraction `f`.
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
    let return_ms = u64::from(params.fluff_return_ms);
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;

    let mut natural: Vec<u64> = Vec::new();
    let mut embargo_gaps: Vec<u64> = Vec::new();

    for _ in 0..trials {
        let mut first_spy: Option<u64> = None;
        let trace = walk_stem_observing(params, embargo, rng, |_pos, t, rng| {
            if first_spy.is_none() && (rng.next_u64() as u32) < spy_threshold {
                first_spy = Some(t);
            }
        });

        let Some(sighting) = first_spy else {
            continue;
        };

        let earliest_embargo = trace
            .deadlines
            .iter()
            .copied()
            .filter(|d| *d < trace.disarm_ms)
            .min();

        let (fluff_time, is_embargo) = match earliest_embargo {
            Some(e) if e < trace.natural_fluff_ms => (e, true),
            _ => (trace.natural_fluff_ms, false),
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
            if deadlines.len() >= super::util::MAX_SIMULATED_HOPS {
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

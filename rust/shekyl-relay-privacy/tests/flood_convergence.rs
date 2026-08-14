// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The convergence criterion for first-passage readings.
//!
//! # What this is for
//!
//! `fluff_return_ms = 3250` was read off a single `(seed, trials)` pair —
//! `f7_directed.rs` takes `SplitMix64::new(0xF7_0000 + peers)` at 24 trials and
//! reports what comes back. That reading may well be right; the point is that
//! the *procedure* has no way to tell, because one draw carries no information
//! about the spread it was drawn from.
//!
//! `converged_fluff_return_mixed` supplies the missing half: re-run at
//! independent seeds, escalate until they agree to within the instrument's own
//! grid, and **refuse to report** if they never do. That fixes the class rather
//! than this instance — the next constant derived from this crate inherits the
//! check instead of repeating the omission.
//!
//! # What these tests do and do not assert
//!
//! They pin the criterion's *behaviour*, never a first-passage value. Asserting
//! the converged reading equals 3250 would defeat the purpose: the criterion
//! exists precisely so the re-derivation is free to land somewhere else.
//!
//! Every arm is deterministic. The simulation is a pure function of
//! `(seed, trials, params)` and `SplitMix64` is seeded explicitly, so a passing
//! run here is a passing run everywhere — these are fixed vectors, not samples.

use shekyl_relay_privacy::conformance::{
    converged_fluff_return_mixed, ConvergenceBudget, ConvergenceRefusal, FloodParams, FloodReach,
    FLOOD_TICK_MS,
};
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::SplitMix64;

/// The shipped derivation's inputs, so the criterion is exercised on the
/// measurement it is meant to govern rather than a convenient one.
/// `mean_quarter_secs = 20` and `Geometric` are `f7_directed.rs`'s.
const MEAN_QUARTER_SECS: u32 = 20;
const FAMILY: DelayFamily = DelayFamily::Geometric;
const SEEDS: [u64; 6] = [
    0xC0FF_EE01,
    0xC0FF_EE02,
    0xC0FF_EE03,
    0xC0FF_EE04,
    0xC0FF_EE05,
    0xC0FF_EE06,
];

fn shipped_topology() -> FloodParams {
    FloodParams {
        nodes: 512,
        peers: 12,
        reach: FloodReach::OutboundOnly,
    }
}

#[test]
fn the_shipped_topology_converges_and_reports_its_cost() {
    let flood = shipped_topology();
    let degrees = vec![flood.peers; flood.nodes];

    let converged = converged_fluff_return_mixed(
        flood,
        &degrees,
        MEAN_QUARTER_SECS,
        FAMILY,
        &SEEDS,
        ConvergenceBudget {
            start_trials: 32,
            max_trials: 1024,
            tolerance_ms: FLOOD_TICK_MS,
        },
        SplitMix64::new,
    )
    .expect("the shipped OutboundOnly@12 topology should converge inside 1024 trials");

    println!("\n  converged fluff-return p90");
    println!("  --------------------------");
    println!("  p90            {} ms", converged.p90_ms);
    println!("  trials/seed    {}", converged.trials_per_seed);
    println!("  spread         {} ms", converged.spread_ms);
    println!("  readings       {:?}", converged.readings_ms);
    println!("  shipped input  3250 ms (single seed, 24 trials — the thing being replaced)");

    assert!(
        converged.spread_ms <= FLOOD_TICK_MS,
        "a converged result must be within tolerance by construction"
    );
    assert_eq!(
        converged.readings_ms.len(),
        SEEDS.len(),
        "every seed must contribute a reading"
    );
    assert_eq!(
        converged.p90_ms,
        *converged.readings_ms.iter().max().unwrap(),
        "the reported reading is the max across seeds (the privacy-safe direction)"
    );
    assert!(
        converged.trials_per_seed >= 32,
        "escalation never goes below the starting trial count"
    );
}

/// Negative control for [`ConvergenceRefusal::Spread`].
///
/// A tolerance of zero demands the seeds agree *exactly*, which is below the
/// instrument's 250 ms grid and so is a demand it cannot satisfy by widening
/// the sample. With `max_trials == start_trials` the ladder gets one rung, so
/// the refusal is forced rather than waited for.
///
/// Without this arm the criterion could be a function that always returns
/// `Ok`, and the suite above would not notice.
#[test]
fn an_unsatisfiable_tolerance_is_refused_rather_than_reported() {
    let flood = shipped_topology();
    let degrees = vec![flood.peers; flood.nodes];

    let refusal = converged_fluff_return_mixed(
        flood,
        &degrees,
        MEAN_QUARTER_SECS,
        FAMILY,
        &SEEDS,
        ConvergenceBudget {
            start_trials: 8,
            max_trials: 8,
            tolerance_ms: 0,
        },
        SplitMix64::new,
    )
    .expect_err("a zero tolerance is sub-grid and must never produce a reading");

    println!("\n  {refusal}");

    match refusal {
        ConvergenceRefusal::Spread {
            trials_per_seed,
            spread_ms,
            tolerance_ms,
            ref readings_ms,
        } => {
            assert_eq!(trials_per_seed, 8, "the budget allowed exactly one rung");
            assert_eq!(tolerance_ms, 0);
            assert!(
                spread_ms > 0,
                "the seeds must actually disagree for this control to be meaningful — \
                 if they agreed exactly, this arm would pass vacuously"
            );
            assert_eq!(readings_ms.len(), SEEDS.len());
        }
        ConvergenceRefusal::Stranded { .. } => {
            panic!("degree 12 does not strand — this is the wrong refusal")
        }
    }
}

/// Negative control for [`ConvergenceRefusal::Stranded`], and for the decision
/// to keep it separate from `Spread`.
///
/// At out-degree 1 an `OutboundOnly` flood reaches a thin chain and strands the
/// rest, so p90 is `u64::MAX`. More trials cannot mend that — every trial
/// strands the same way — so escalating the budget would spend it against a
/// question the sample size does not govern. The refusal has to name the
/// topology.
#[test]
fn a_stranding_topology_is_refused_on_the_topology_not_the_budget() {
    let flood = FloodParams {
        nodes: 512,
        peers: 1,
        reach: FloodReach::OutboundOnly,
    };
    let degrees = vec![1_usize; flood.nodes];

    let refusal = converged_fluff_return_mixed(
        flood,
        &degrees,
        MEAN_QUARTER_SECS,
        FAMILY,
        &SEEDS,
        ConvergenceBudget {
            start_trials: 4,
            max_trials: 1024,
            tolerance_ms: FLOOD_TICK_MS,
        },
        SplitMix64::new,
    )
    .expect_err("an out-degree of 1 strands most of the network");

    println!("\n  {refusal}");

    match refusal {
        ConvergenceRefusal::Stranded {
            trials_per_seed,
            seeds_stranded,
            seeds,
        } => {
            assert_eq!(
                trials_per_seed, 4,
                "stranding is detected on the FIRST rung — the ladder must not be climbed \
                 against a condition trials cannot change"
            );
            assert_eq!(seeds, SEEDS.len());
            assert!(seeds_stranded > 0);
        }
        ConvergenceRefusal::Spread { .. } => {
            panic!(
                "a stranded p90 must not be reported as a spread — that would send the \
                    next reader to widen the budget instead of fixing the degrees"
            )
        }
    }
}

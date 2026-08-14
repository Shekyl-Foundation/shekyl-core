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
//! grid, and **refuse to report** if they never do.
//!
//! # What was and was not wrong with `f7_directed.rs`
//!
//! Its *comparison* is sound and stays as it is: both arms share a seed, so a
//! paired difference at one seed is a fair reading of the rule's effect, which
//! is all F-7 needed. What it cannot support is a **level** — "the p90 is 3250"
//! — because that is one draw with no spread attached, and a level is what got
//! consumed as a constant.
//!
//! So this does not retroactively condemn that test; it supplies the tool the
//! *derivation* needed. Nothing is routed through the criterion yet — it is
//! available, and the next constant taken as a level from this crate should
//! come through it.
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

/// Negative control for [`ConvergenceRefusal::Spread`], at the **default**
/// tolerance.
///
/// Eight trials is a trial count the seeds have not collapsed at — they span
/// three ticks there — and `max_trials == start_trials` gives the ladder one
/// rung, so the refusal is forced rather than waited for. Nothing here relies
/// on an exotic tolerance: the criterion as it ships refuses this reading.
///
/// Without this arm the criterion could be a function that always returns
/// `Ok`, and the suite above would not notice.
#[test]
fn a_spent_budget_is_refused_rather_than_reported() {
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
            tolerance_ms: FLOOD_TICK_MS,
        },
        SplitMix64::new,
    )
    .expect_err("eight trials has not collapsed the spread — it must not be reported");

    println!("\n  {refusal}");

    match refusal {
        ConvergenceRefusal::Spread {
            trials_per_seed,
            spread_ms,
            tolerance_ms,
            ref readings_ms,
        } => {
            assert_eq!(trials_per_seed, 8, "the budget allowed exactly one rung");
            assert_eq!(tolerance_ms, FLOOD_TICK_MS);
            assert!(
                spread_ms > FLOOD_TICK_MS,
                "the seeds must disagree by more than the tolerance for this control to \
                 be meaningful — if they were already within it, this arm would pass \
                 vacuously"
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

/// The direction result that decides whether 3500 ms is a placeholder or a
/// **floor** on `F′`.
///
/// The re-derivation was filed as blocked on a "churn-realistic" degree
/// distribution. That input was never measured, and this arm asks whether it
/// is needed at all.
///
/// Under `OutboundOnly` first passage is a minimum over directed paths, and
/// raising a node's out-degree only *adds* paths — so a graph whose degrees
/// are at or above the floor cannot flood more slowly than the uniform
/// floor graph, and heterogeneity above the floor can only lower the reading.
/// Below-floor nodes remove paths and can only raise it, which is the same
/// self-harm direction Q12-D9's check is justified on (§12.1) and the
/// condition §11.13 says a young network is in.
///
/// If both hold, uniform-at-the-floor is the **conservative** topology and
/// 3500 ms is a lower bound on `F′` — the missing distribution can move the
/// answer up, never down, so it is a refinement rather than a blocker.
///
/// Measured rather than argued, because the argument is exactly the kind that
/// sounds airtight and encodes a direction backwards.
#[test]
fn uniform_at_the_floor_is_the_conservative_topology() {
    let flood = shipped_topology();
    let budget = ConvergenceBudget {
        start_trials: 32,
        max_trials: 1024,
        tolerance_ms: FLOOD_TICK_MS,
    };

    let read = |degrees: &[usize], label: &str| -> u64 {
        let c = converged_fluff_return_mixed(
            flood,
            degrees,
            MEAN_QUARTER_SECS,
            FAMILY,
            &SEEDS,
            budget,
            SplitMix64::new,
        )
        .unwrap_or_else(|e| panic!("{label} did not converge: {e}"));
        println!(
            "  {label:34} p90 {:5} ms   ({} trials/seed, spread {})",
            c.p90_ms, c.trials_per_seed, c.spread_ms
        );
        c.p90_ms
    };

    println!("\n  degree distribution                  converged reading");
    println!("  -----------------------------------  ------------------");

    let uniform = read(&vec![12_usize; flood.nodes], "uniform at the floor (12)");

    // Every third node above the floor, the rest at it.
    let above: Vec<usize> = (0..flood.nodes)
        .map(|n| if n % 3 == 0 { 16 } else { 12 })
        .collect();
    let above = read(&above, "one third at 16, rest at 12");

    // Every third node below it — the young-network condition of §11.13.
    let below: Vec<usize> = (0..flood.nodes)
        .map(|n| if n % 3 == 0 { 8 } else { 12 })
        .collect();
    let below = read(&below, "one third at 8, rest at 12");

    println!("\n  shipped fluff_return_ms = 3250 ms; converged at the floor = {uniform} ms");

    assert!(
        above <= uniform,
        "heterogeneity ABOVE the floor must not raise the reading — extra out-edges \
         only add paths, and first passage is a min over paths. Got {above} vs {uniform}"
    );
    assert!(
        below >= uniform,
        "degrees BELOW the floor must not lower the reading — removing out-edges \
         removes paths. Got {below} vs {uniform}"
    );
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sustained timing: a convergence criterion, not an iteration count.
//!
//! §6.3.4 pins thermals as *"sustained, not burst — run to steady state before
//! measuring"*, because the A72 throttles and *"a burst measurement grades a
//! machine that does not exist after a minute"*. A fixed iteration count cannot
//! express that: it is either too few on a board that throttles late or wasted
//! minutes on one that never throttles.
//!
//! ## Why two independent windows, and not two running medians
//!
//! The first version compared consecutive **running** medians over the whole
//! sample. That cannot establish steady state, and fails in exactly the
//! direction that matters here: as the sample count grows each new observation
//! moves the running median less, so a workload whose duration **increases
//! every iteration** — a board throttling — eventually moves it by under the
//! tolerance and is marked converged. The criterion would have certified the
//! condition it exists to detect. Its own unit test only failed to expose this
//! because it used a 0.000001 % tolerance where grading uses 5 %.
//!
//! So convergence compares the median of the **last [`CONVERGENCE_WINDOW`]
//! samples** against the median of the [`CONVERGENCE_WINDOW`] before them —
//! two disjoint windows, each fully replaced as the run proceeds. A sustained
//! trend keeps the later window above the earlier one and never converges,
//! which is the behaviour the thermal protocol needs. The **whole
//! per-iteration series is reported** either way, so a reader can see the
//! throttle rather than taking the verdict on trust.

use serde::Serialize;
use std::time::{Duration, Instant};

/// Default convergence tolerance, in percent.
pub const DEFAULT_TOLERANCE_PCT: f64 = 5.0;
/// Samples in each of the two independent windows the convergence test
/// compares.
pub const CONVERGENCE_WINDOW: usize = 3;

/// Iterations before convergence is first tested — two full windows.
pub const MIN_ITERATIONS: usize = 2 * CONVERGENCE_WINDOW;
/// Hard stop on iteration count. A board that has not converged by here is
/// reported unconverged rather than measured forever — and `converged: false`
/// is what a grading reader keys on.
pub const MAX_ITERATIONS: usize = 60;

/// Seconds a series must run before convergence may be declared at all.
///
/// Window comparison alone is not enough: six samples of a fast workload can
/// agree inside the first few seconds and stop the loop **before the board has
/// had time to throttle** — which is precisely the burst measurement §5.2
/// rejects, arrived at through the steady-state test rather than around it. A
/// minute is the figure §6.3.4 uses when it says a burst measurement "grades a
/// machine that does not exist after a minute".
///
/// Only a floor on *time*: a series that is already slow (the worst-case replay
/// is ~74 s per iteration) clears it on its first sample and is unaffected.
pub const MIN_CONDITIONING_SECONDS: f64 = 60.0;

/// Hard stop on **wall time**, in seconds.
///
/// An iteration cap alone is not a bound. The worst-case replay is a
/// multi-minute operation on the rig, so `MAX_ITERATIONS` unconverged
/// iterations of it is *hours* — a harness that can run for an unbounded time
/// on the machine it exists to measure. The count and the clock are different
/// limits and both are needed: the count stops a fast-but-noisy workload, the
/// clock stops a slow one.
///
/// Reaching either reports `converged: false`; neither substitutes a different
/// statistic, because silently reporting one would hide the condition.
pub const MAX_WALL_SECONDS: f64 = 1_800.0;

/// Every iteration of one measurement, plus the summary statistics.
#[derive(Clone, Debug, Serialize)]
pub struct Series {
    /// Per-iteration seconds, in order. The throttle is visible here.
    pub iterations_s: Vec<f64>,
    /// Median of [`Series::iterations_s`].
    pub median_s: f64,
    /// 95th percentile, nearest-rank.
    pub p95_s: f64,
    /// Whether two consecutive running medians agreed within the tolerance.
    pub converged: bool,
    /// Why the loop stopped: `"converged"`, `"limits met, unconverged"` or
    /// `"wall-clock cap"`. A grading reader needs the *reason*, not only the
    /// `converged` flag — a series that ran its full budget without settling
    /// and one the wall clock cut short call for different responses.
    ///
    /// **`"iteration cap"` is deliberately not a value.** It was one until
    /// 2026-09-21, and it could not be true: the loop continues *past*
    /// `MAX_ITERATIONS` while the conditioning floor is unmet (that is the
    /// whole point of the two limits composing), so "the iteration cap
    /// stopped this run" is not a state this loop can reach. The string was
    /// the variable's initialiser and it rode the **normal** exit out, so an
    /// unconverged graded series reported itself as truncated by a cap when
    /// it had in fact met both limits and simply never settled — opposite
    /// remedies, which is exactly the distinction this field exists to draw.
    pub stopped_because: &'static str,
    /// The tolerance the convergence test used.
    pub tolerance_pct: f64,
    /// Warm-up iterations run and discarded before timing began.
    pub warmup_iterations: usize,
    /// Seconds the series had to run before convergence could be declared.
    pub min_conditioning_seconds: f64,
}

impl Series {
    /// The figure a grading run reads: the converged median.
    ///
    /// Unconverged series still return their median — the caller decides what
    /// to do about [`Series::converged`], because a harness that silently
    /// substituted a different statistic would hide the condition.
    #[must_use]
    pub fn graded_s(&self) -> f64 {
        self.median_s
    }
}

/// Run `f` to steady state, timing each call, under the default wall budget.
///
/// `warmup` calls are made and discarded first — the page cache, the allocator
/// and the branch predictors all settle, and none of that is the subject.
pub fn sustained<F>(warmup: usize, tolerance_pct: f64, f: F) -> Series
where
    F: FnMut(),
{
    sustained_within_conditioned(
        warmup,
        tolerance_pct,
        MAX_WALL_SECONDS,
        MIN_CONDITIONING_SECONDS,
        f,
    )
}

/// [`sustained`] with an explicit wall budget and the default conditioning
/// floor.
pub fn sustained_within<F>(warmup: usize, tolerance_pct: f64, max_wall_seconds: f64, f: F) -> Series
where
    F: FnMut(),
{
    sustained_within_conditioned(
        warmup,
        tolerance_pct,
        max_wall_seconds,
        MIN_CONDITIONING_SECONDS,
        f,
    )
}

/// [`sustained`] with an explicit wall budget.
///
/// The budget is a parameter rather than only a constant so the cap can be
/// *exercised* — a limit that no test can reach is a limit nobody has seen
/// work.
/// [`sustained`] with both floors explicit, so a test can reach either.
pub fn sustained_within_conditioned<F>(
    warmup: usize,
    tolerance_pct: f64,
    max_wall_seconds: f64,
    min_conditioning_seconds: f64,
    mut f: F,
) -> Series
where
    F: FnMut(),
{
    for _ in 0..warmup {
        f();
    }
    let mut samples: Vec<f64> = Vec::new();
    let mut converged = false;
    // Names the NORMAL exit — the guard below going false with both limits
    // met. Every other exit assigns over it before breaking.
    let mut stopped_because = "limits met, unconverged";
    let began = Instant::now();
    // The ITERATION cap must not preempt the CONDITIONING floor. A fast series
    // reaches 60 samples long before 60 seconds, and stopping there would mean
    // convergence could never be declared for it — the two limits would cancel
    // rather than compose. The caps exist to bound an UNCONVERGED run; the
    // floor exists to stop a converged verdict arriving too early. So the loop
    // continues while either is unmet, and the wall budget bounds both.
    //
    // There is therefore no "stopped at the iteration cap" exit to take: the
    // guard ends the loop only when BOTH limits are met, which is the
    // `"limits met, unconverged"` reason above. A break keyed on that same
    // condition used to sit in the body; it was the exact negation of this
    // guard, so it was reachable only if the clock crossed the floor between
    // the guard's read and its own, and it is deleted rather than kept as a
    // belt that cannot buckle.
    while samples.len() < MAX_ITERATIONS || duration_s(began.elapsed()) < min_conditioning_seconds {
        if duration_s(began.elapsed()) >= max_wall_seconds {
            stopped_because = "wall-clock cap";
            break;
        }
        let start = Instant::now();
        f();
        samples.push(duration_s(start.elapsed()));
        if samples.len() < MIN_ITERATIONS || duration_s(began.elapsed()) < min_conditioning_seconds
        {
            continue;
        }
        // Two DISJOINT windows: the most recent `CONVERGENCE_WINDOW` samples
        // against the `CONVERGENCE_WINDOW` before them. Each is fully replaced
        // as the run proceeds, so a sustained trend cannot be averaged away by
        // a growing denominator.
        let n = samples.len();
        let recent = median_of(&samples[n - CONVERGENCE_WINDOW..]);
        let prior = median_of(&samples[n - 2 * CONVERGENCE_WINDOW..n - CONVERGENCE_WINDOW]);
        // Relative change against the larger of the two, so the test is
        // symmetric: a 5 % rise and a 5 % fall are the same distance.
        let scale = prior.max(recent);
        if scale > 0.0 && (prior - recent).abs() / scale * 100.0 <= tolerance_pct {
            converged = true;
            stopped_because = "converged";
            break;
        }
    }
    Series {
        median_s: median_of(&samples),
        p95_s: percentile_of(&samples, 95.0),
        converged,
        stopped_because,
        tolerance_pct,
        warmup_iterations: warmup,
        min_conditioning_seconds,
        iterations_s: samples,
    }
}

/// Seconds as `f64`. One conversion site, so the units cannot drift between
/// the timer and the record.
#[must_use]
pub fn duration_s(d: Duration) -> f64 {
    d.as_secs_f64()
}

fn sorted(samples: &[f64]) -> Vec<f64> {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("timings are never NaN"));
    v
}

fn median_of(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let v = sorted(samples);
    let mid = v.len() / 2;
    if v.len().is_multiple_of(2) {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    }
}

fn percentile_of(samples: &[f64], pct: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let v = sorted(samples);
    // Nearest-rank: the smallest value at or above the requested percentile.
    let rank = (pct / 100.0 * v.len() as f64).ceil().max(1.0) as usize;
    v[rank.min(v.len()) - 1]
}

#[cfg(test)]
#[path = "timing_tests.rs"]
mod tests;

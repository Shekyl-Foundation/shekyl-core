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
//! So the loop runs until the running median stops moving — two consecutive
//! medians within [`Series::tolerance_pct`] — and the **whole per-iteration
//! series is reported**, so a reader can see the throttle happen rather than
//! taking the converged figure on trust.

use serde::Serialize;
use std::time::{Duration, Instant};

/// Default convergence tolerance, in percent.
pub const DEFAULT_TOLERANCE_PCT: f64 = 5.0;
/// Iterations before convergence is first tested. Below this a median is a
/// statement about two or three samples.
pub const MIN_ITERATIONS: usize = 5;
/// Hard stop on iteration count. A board that has not converged by here is
/// reported unconverged rather than measured forever — and `converged: false`
/// is what a grading reader keys on.
pub const MAX_ITERATIONS: usize = 60;

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
    /// Why the loop stopped: `"converged"`, `"iteration cap"` or
    /// `"wall-clock cap"`. A grading reader needs the *reason*, not only the
    /// `converged` flag — an iteration cap on a noisy fast workload and a
    /// wall-clock cap on a slow one call for different responses.
    pub stopped_because: &'static str,
    /// The tolerance the convergence test used.
    pub tolerance_pct: f64,
    /// Warm-up iterations run and discarded before timing began.
    pub warmup_iterations: usize,
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
    sustained_within(warmup, tolerance_pct, MAX_WALL_SECONDS, f)
}

/// [`sustained`] with an explicit wall budget.
///
/// The budget is a parameter rather than only a constant so the cap can be
/// *exercised* — a limit that no test can reach is a limit nobody has seen
/// work.
pub fn sustained_within<F>(
    warmup: usize,
    tolerance_pct: f64,
    max_wall_seconds: f64,
    mut f: F,
) -> Series
where
    F: FnMut(),
{
    for _ in 0..warmup {
        f();
    }
    let mut samples: Vec<f64> = Vec::new();
    let mut previous_median: Option<f64> = None;
    let mut converged = false;
    let mut stopped_because = "iteration cap";
    let began = Instant::now();
    while samples.len() < MAX_ITERATIONS {
        if duration_s(began.elapsed()) >= max_wall_seconds {
            stopped_because = "wall-clock cap";
            break;
        }
        let start = Instant::now();
        f();
        samples.push(duration_s(start.elapsed()));
        if samples.len() < MIN_ITERATIONS {
            continue;
        }
        let median = median_of(&samples);
        if let Some(prev) = previous_median {
            // Relative change against the larger of the two, so the test is
            // symmetric: a 5 % rise and a 5 % fall are the same distance.
            let scale = prev.max(median);
            if scale > 0.0 && (prev - median).abs() / scale * 100.0 <= tolerance_pct {
                converged = true;
                stopped_because = "converged";
                break;
            }
        }
        previous_median = Some(median);
    }
    Series {
        median_s: median_of(&samples),
        p95_s: percentile_of(&samples, 95.0),
        converged,
        stopped_because,
        tolerance_pct,
        warmup_iterations: warmup,
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

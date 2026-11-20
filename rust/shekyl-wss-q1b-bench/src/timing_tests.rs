// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::cell::Cell;

/// A clock the workload advances by exact amounts, so each test below states
/// the durations the loop sees rather than asking the scheduler for them
/// (see [`SeriesClock`]).
#[derive(Default)]
struct StepClock(Cell<Duration>);

impl StepClock {
    fn advance_s(&self, seconds: f64) {
        self.0.set(self.0.get() + Duration::from_secs_f64(seconds));
    }
}

impl SeriesClock for StepClock {
    fn now(&self) -> Reading {
        Reading::since_origin(self.0.get())
    }
}

/// The real-clock wiring check sleeps this long inside each sample.
const WIRING_SLEEP: Duration = Duration::from_millis(1);
/// Wall for that check. A few quiet sleeps fit under it, and a loaded runner
/// cannot spend the grading wall on a series that never settles.
const WIRING_WALL: Duration = Duration::from_millis(200);

fn assert_secs(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-12,
        "{actual} seconds, expected {expected}"
    );
}

/// `sustained_on` over a [`StepClock`] whose workload takes `sample_s(i)`
/// seconds on its `i`th call, warm-up calls included.
fn stepped(
    warmup: usize,
    tolerance_pct: f64,
    max_wall_seconds: f64,
    min_conditioning_seconds: f64,
    sample_s: impl Fn(u64) -> f64,
) -> Series {
    let clock = StepClock::default();
    let mut calls = 0u64;
    sustained_on(
        &clock,
        warmup,
        tolerance_pct,
        max_wall_seconds,
        min_conditioning_seconds,
        || {
            let i = calls;
            calls += 1;
            clock.advance_s(sample_s(i));
        },
    )
}

#[test]
fn a_steady_workload_converges_and_reports_every_iteration() {
    // 1 ms every sample, after two warm-up calls: the windows agree at the
    // first test past the 50 ms floor, the 50th sample.
    let series = stepped(2, DEFAULT_TOLERANCE_PCT, 30.0, 0.05, |_| 0.001);
    assert!(
        series.converged,
        "a steady workload must reach steady state (stopped_because = {})",
        series.stopped_because
    );
    assert_eq!(series.stopped_because, "converged");
    assert_eq!(series.iterations_s.len(), 50);
    assert_eq!(series.warmup_iterations, 2);
    assert_secs(series.median_s, 0.001);
    assert!(series.p95_s >= series.median_s);
}

#[test]
fn a_never_settling_workload_is_reported_unconverged_not_looped_forever() {
    // The throttling board's case: the harness must stop and SAY it did not
    // converge, rather than either spinning or quietly reporting a median that
    // never stabilised. At the GRADING tolerance: 5 ms × 1.06^i puts the two
    // windows' medians three steps, 19 %, apart on every sample, and sixty
    // samples sum to 2.7 s, under the 30 s wall.
    let series = stepped(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.05, |i| {
        0.005 * 1.06_f64.powi(i as i32)
    });
    assert!(
        !series.converged,
        "a monotonically slowing workload is not steady state (stopped_because = {})",
        series.stopped_because
    );
    // The sample cap is what must end this run: if the WALL cap ended it the
    // run was truncated and the length below is meaningless, so name that here
    // rather than letting it surface as a confusing count.
    assert_ne!(
        series.stopped_because, "wall-clock cap",
        "wall budget preempted the sample cap; this test no longer measures its subject"
    );
    assert_eq!(series.iterations_s.len(), MAX_ITERATIONS);
    // The NORMAL exit: the guard went false with both limits met, and the
    // series never settled (there is no separate "iteration cap" exit; see
    // `timing.rs`).
    assert_eq!(series.stopped_because, "limits met, unconverged");
}

#[test]
fn the_graded_figure_is_the_median() {
    // 1 ms, 5 ms, 2 ms. The windows first agree on the 8th sample, the
    // first at which 20 ms has passed: three 1s, two 2s and three 5s.
    // Median 2 ms, mean 2.75 ms, last sample 5 ms. A graded figure that
    // returned the mean or the last sample would miss the median.
    const LOW_S: f64 = 0.001;
    const HIGH_S: f64 = 0.005;
    const MID_S: f64 = 0.002;
    let series = stepped(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.02, |i| match i % 3 {
        0 => LOW_S,
        1 => HIGH_S,
        _ => MID_S,
    });
    assert_eq!(series.iterations_s.len(), 8);
    assert_eq!(series.graded_s(), series.median_s);
    assert_secs(series.median_s, MID_S);
    assert_secs(*series.iterations_s.last().expect("eight samples"), HIGH_S);
}

#[test]
fn the_wall_clock_cap_stops_a_loop_the_iteration_cap_would_not() {
    // An iteration cap alone is not a bound: on the rig the worst-case replay
    // is a multi-minute operation, so 60 unconverged iterations of it is hours.
    // A never-converging workload under a 50 ms budget must stop on the CLOCK:
    // samples of 2, 4, 6, ... ms reach 42 ms after the sixth, so the seventh
    // starts inside the budget and ends at 56 ms, and the next check stops the
    // loop at seven samples.
    let series = stepped(0, 0.000_001, 0.05, MIN_CONDITIONING_SECONDS, |i| {
        0.002 * (i + 1) as f64
    });
    assert!(!series.converged);
    assert_eq!(series.stopped_because, "wall-clock cap");
    assert_eq!(series.iterations_s.len(), 7);
}

#[test]
fn a_steadily_throttling_workload_never_converges_at_the_grading_tolerance() {
    // The defect the disjoint-window criterion exists to refuse, stated as its
    // own case: a running-median test marks this converged once the sample
    // count grows enough to damp each new observation, which certifies exactly
    // the condition §5.2 measures for. +6 % per sample is far below a running
    // median's damping after a dozen samples and far above 5 % between two
    // disjoint windows. The shipped floor and a 30 s wall: the run ends on the
    // wall, never on a verdict.
    let series = stepped(
        0,
        DEFAULT_TOLERANCE_PCT,
        30.0,
        MIN_CONDITIONING_SECONDS,
        |i| 0.008 * 1.06_f64.powi(i as i32),
    );
    assert!(
        !series.converged,
        "a monotonically slowing workload must not be called steady state; got {:?} after {} iters",
        series.stopped_because,
        series.iterations_s.len()
    );
    assert_eq!(series.stopped_because, "wall-clock cap");
}

#[test]
fn convergence_cannot_be_declared_inside_the_conditioning_floor() {
    // The burst case: a workload perfectly stable from its first sample still
    // must not be called steady state before the board has had time to
    // throttle. Six agreeing 50 ms samples would converge at 0.3 s; the 1 s
    // floor holds the verdict to the 20th sample, the first at which 1 s has
    // passed.
    let series = stepped(0, DEFAULT_TOLERANCE_PCT, 30.0, 1.0, |_| 0.05);
    assert!(
        series.converged,
        "a steady workload still converges eventually (stopped_because = {}, {} samples)",
        series.stopped_because,
        series.iterations_s.len()
    );
    assert_eq!(series.iterations_s.len(), 20);
    assert!(
        series.iterations_s.iter().sum::<f64>() >= 1.0 - 1e-9,
        "it must not converge before the conditioning floor"
    );
    assert_eq!(series.min_conditioning_seconds, 1.0);
}

#[test]
fn the_defaults_are_the_protocols_figures() {
    // The tests run with short floors so they stay tests; this is the one place
    // the SHIPPED figures are asserted, so a convenience default cannot quietly
    // become the protocol.
    assert_eq!(MIN_CONDITIONING_SECONDS, 60.0);
    assert_eq!(MAX_WALL_SECONDS, 1_800.0);
    assert_eq!(MIN_ITERATIONS, 2 * CONVERGENCE_WINDOW);
}

#[test]
fn a_fast_series_is_not_truncated_by_the_iteration_cap_before_conditioning() {
    // The two limits must compose, not cancel: a 1 ms workload reaches
    // MAX_ITERATIONS at 60 ms, long before a 250 ms floor, and stopping there
    // would mean convergence could never be declared for it at all. If the two
    // limits cancelled, the length would be exactly `MAX_ITERATIONS`.
    let series = stepped(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.25, |_| 0.001);
    assert!(
        series.iterations_s.len() > MAX_ITERATIONS,
        "it must keep sampling past the iteration cap until conditioning is met \
         (len = {}, stopped_because = {})",
        series.iterations_s.len(),
        series.stopped_because
    );
    assert!(series.converged);
    assert_eq!(series.iterations_s.len(), 250);
}

#[test]
fn a_clock_that_does_not_advance_ends_when_the_floor_is_zero() {
    // No conditioning floor: the sample cap is then the only bound, so a
    // clock that stays at the origin still ends. Zero-length samples have
    // no scale, so the windows cannot agree.
    let series = stepped(0, DEFAULT_TOLERANCE_PCT, MAX_WALL_SECONDS, 0.0, |_| 0.0);
    assert_eq!(series.iterations_s.len(), MAX_ITERATIONS);
    for sample in &series.iterations_s {
        assert_secs(*sample, 0.0);
    }
    assert!(!series.converged);
    assert_eq!(series.stopped_because, "limits met, unconverged");
}

#[test]
fn sustained_within_conditioned_reads_the_instant_clock() {
    // The tests above drive a StepClock. This one is the wiring
    // `sustained_within_conditioned` uses, which is what `sustained` and
    // `sustained_within` forward to. The floor is zero so a clock that does
    // not advance still ends at the sample cap, and the assertion can fail.
    // The wall is [`WIRING_WALL`], so a loaded runner cannot spend the
    // grading budget on sleeps that never settle. A sample under its own
    // sleep is the failure; whether the samples converge is the machine's
    // to decide (`spend_edge.rs`, §5.2).
    let series = sustained_within_conditioned(
        0,
        DEFAULT_TOLERANCE_PCT,
        duration_s(WIRING_WALL),
        0.0,
        || std::thread::sleep(WIRING_SLEEP),
    );
    assert!(
        !series.iterations_s.is_empty(),
        "the run recorded no sample"
    );
    let sleep_s = duration_s(WIRING_SLEEP);
    assert!(
        series.iterations_s.iter().all(|&sample| sample >= sleep_s),
        "a sample read under its own sleep: {:?}",
        series.iterations_s
    );
}

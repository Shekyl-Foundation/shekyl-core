// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::cell::Cell;

/// A clock the workload advances by exact amounts, so each test below states
/// the durations the loop sees rather than asking the scheduler for them
/// (see [`Clock`]).
#[derive(Default)]
struct StepClock(Cell<Duration>);

impl StepClock {
    fn advance_s(&self, seconds: f64) {
        self.0.set(self.0.get() + Duration::from_secs_f64(seconds));
    }
}

impl Clock for StepClock {
    fn now(&self) -> Duration {
        self.0.get()
    }
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
    let calls = Cell::new(0u64);
    sustained_on(
        &clock,
        warmup,
        tolerance_pct,
        max_wall_seconds,
        min_conditioning_seconds,
        || {
            let i = calls.get();
            calls.set(i + 1);
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
    assert!((series.median_s - 0.001).abs() < 1e-12);
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
    // Uneven samples, so the median, the mean and the last sample differ.
    let series = stepped(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.02, |i| {
        [0.001, 0.003, 0.002][(i % 3) as usize]
    });
    assert_eq!(series.graded_s(), series.median_s);
    assert!((series.median_s - 0.002).abs() < 1e-12);
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
    assert!(
        series.iterations_s.len() < MAX_ITERATIONS,
        "the clock must stop the loop before the count does"
    );
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
fn the_shipped_entry_points_read_the_monotonic_clock() {
    // The tests above drive a StepClock; this one is the wiring the binaries
    // use. It asserts only what no scheduler can break: a 1 ms sleep never
    // measures under 1 ms, and the run ends. Whether real samples converge is
    // the machine's to decide, and the binaries refuse an unconverged series
    // rather than publish it (`spend_edge.rs`, §5.2).
    let series = sustained_within_conditioned(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.02, || {
        std::thread::sleep(Duration::from_millis(1));
    });
    assert!(series.iterations_s.len() >= MIN_ITERATIONS);
    assert!(
        series.iterations_s.iter().all(|&s| s >= 0.001),
        "a sample read under its own sleep: {:?}",
        series.iterations_s
    );
}

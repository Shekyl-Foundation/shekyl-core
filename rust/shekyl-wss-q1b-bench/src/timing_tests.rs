// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::cell::Cell;

#[test]
fn a_steady_workload_converges_and_reports_every_iteration() {
    let series = sustained(2, DEFAULT_TOLERANCE_PCT, || {
        std::hint::black_box((0..200u64).sum::<u64>());
    });
    assert!(
        series.converged,
        "a steady workload must reach steady state"
    );
    assert!(series.iterations_s.len() >= MIN_ITERATIONS);
    assert_eq!(series.warmup_iterations, 2);
    assert!(series.median_s >= 0.0);
    assert!(series.p95_s >= series.median_s);
}

#[test]
fn a_never_settling_workload_is_reported_unconverged_not_looped_forever() {
    // The throttling board's case: the harness must stop and SAY it did not
    // converge, rather than either spinning or quietly reporting a median that
    // never stabilised.
    // At the GRADING tolerance, not a token one. The previous version used
    // 0.000001 %, which is the only reason the running-median criterion passed
    // it: at 5 % a growing running median settles and certifies a throttling
    // board as converged. Disjoint windows must refuse this at 5 %.
    let n = Cell::new(0u64);
    let series = sustained(0, DEFAULT_TOLERANCE_PCT, || {
        // Each call strictly longer than the last.
        let i = n.get();
        n.set(i + 1);
        std::thread::sleep(std::time::Duration::from_millis(2 * (i + 1)));
    });
    assert!(!series.converged);
    assert_eq!(series.iterations_s.len(), MAX_ITERATIONS);
    assert_eq!(series.stopped_because, "iteration cap");
}

#[test]
fn the_graded_figure_is_the_median() {
    let series = sustained(0, DEFAULT_TOLERANCE_PCT, || {
        std::hint::black_box(1u64);
    });
    assert_eq!(series.graded_s(), series.median_s);
}

#[test]
fn the_wall_clock_cap_stops_a_loop_the_iteration_cap_would_not() {
    // An iteration cap alone is not a bound: on the rig the worst-case replay
    // is a multi-minute operation, so 60 unconverged iterations of it is hours.
    // A never-converging workload under a tiny budget must stop on the CLOCK,
    // with fewer samples than the count would have allowed.
    // A sleep, not arithmetic: the optimizer can close-form a sum even behind
    // `black_box`, and a workload that finishes 60 iterations inside the budget
    // would hit the COUNT and leave the clock untested -- a test that passes
    // without exercising its subject.
    let n = Cell::new(0u64);
    let series = sustained_within(0, 0.000_001, 0.05, || {
        let i = n.get();
        n.set(i + 1);
        std::thread::sleep(std::time::Duration::from_millis(2 * (i + 1)));
    });
    assert!(!series.converged);
    assert_eq!(series.stopped_because, "wall-clock cap");
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
    // the condition §5.2 measures for.
    let n = Cell::new(0u64);
    let series = sustained_within(0, DEFAULT_TOLERANCE_PCT, 30.0, || {
        let i = n.get();
        n.set(i + 1);
        // +6% per iteration: far below a running median's damping after a
        // dozen samples, and far above 5% between two disjoint windows.
        let ms = 8.0_f64 * 1.06_f64.powi(i as i32);
        std::thread::sleep(std::time::Duration::from_micros((ms * 1000.0) as u64));
    });
    assert!(
        !series.converged,
        "a monotonically slowing workload must not be called steady state; got {:?} after {} iters",
        series.stopped_because,
        series.iterations_s.len()
    );
}

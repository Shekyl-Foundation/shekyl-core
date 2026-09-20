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
    let n = Cell::new(0u64);
    let series = sustained(0, 0.000_001, || {
        // Each call strictly longer than the last, so the running median never
        // settles within any meaningful tolerance.
        let i = n.get();
        n.set(i + 1);
        std::hint::black_box((0..(i * 2_000 + 1_000)).sum::<u64>());
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

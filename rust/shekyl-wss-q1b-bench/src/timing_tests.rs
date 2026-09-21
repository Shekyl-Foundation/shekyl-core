// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::cell::Cell;

#[test]
fn a_steady_workload_converges_and_reports_every_iteration() {
    // A short conditioning floor so the test is a test and not a minute of
    // waiting; `the_defaults_are_the_protocols_figures` pins the real one.
    // The workload SLEEPS rather than spinning, and that is load-bearing, not
    // taste. A microsecond CPU workload makes `Instant::elapsed` measure the
    // scheduler rather than the work: descheduled once, a sample is orders of
    // magnitude off, the disjoint medians swing past the 5 % tolerance, and a
    // test asserting `converged` fails for want of a quiet box. That is not
    // hypothetical — the sibling test below this one asserted convergence over
    // `(0..50).sum()` and failed on a stock CI runner (PR #812, 2026-09-21),
    // red on someone else's unrelated branch. A 1 ms sleep dominates ordinary
    // scheduling noise, so the quantity being compared is the workload, which
    // is what this test is about.
    let series = sustained_within_conditioned(2, DEFAULT_TOLERANCE_PCT, 30.0, 0.05, || {
        std::thread::sleep(std::time::Duration::from_millis(1));
    });
    assert!(
        series.converged,
        "a steady workload must reach steady state (stopped_because = {})",
        series.stopped_because
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
    let series = sustained_within_conditioned(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.05, || {
        // Each call strictly longer than the last.
        //
        // The 2 ms step is load-bearing and MUST NOT be shrunk for speed: this
        // test's signal is the *relative* gap between consecutive samples, and
        // under contention sleep overshoot adds a large near-constant term to
        // every sample, which swamps a small gap. Tried at 1 ms on 2026-09-21
        // and it made things worse — at load average 17.97 the slowing series
        // converged, i.e. the test's own premise failed. Two limits bound this
        // run in opposite directions and the step size sits between them: too
        // small and the slowdown stops being detectable, too large and
        // `MAX_ITERATIONS` of it approaches the 30 s wall budget.
        let i = n.get();
        n.set(i + 1);
        std::thread::sleep(std::time::Duration::from_millis(2 * (i + 1)));
    });
    assert!(
        !series.converged,
        "a monotonically slowing workload is not steady state (stopped_because = {})",
        series.stopped_because
    );
    // The sample cap is what must end this run — if the WALL cap ended it
    // instead, the run was truncated and the length below is meaningless, so
    // name that here rather than letting it surface as a confusing count.
    assert_ne!(
        series.stopped_because, "wall-clock cap",
        "wall budget preempted the sample cap; this test no longer measures its subject"
    );
    assert_eq!(series.iterations_s.len(), MAX_ITERATIONS);
    // The NORMAL exit: the guard went false with both limits met, and the
    // series never settled. This used to assert `"iteration cap"` and passed
    // — not because a cap stopped the loop (no such exit exists; see
    // `timing.rs`) but because that string was the variable's initialiser and
    // rode this very path out. The assertion documented the defect instead of
    // catching it.
    assert_eq!(series.stopped_because, "limits met, unconverged");
}

#[test]
fn the_graded_figure_is_the_median() {
    let series = sustained_within_conditioned(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.02, || {
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

#[test]
fn convergence_cannot_be_declared_inside_the_conditioning_floor() {
    // The burst case: a workload perfectly stable for its first samples still
    // must not be called steady state before the board has had time to
    // throttle. Six agreeing samples in under a second is exactly the
    // measurement §5.2 rejects, reached through the steady-state test rather
    // than around it.
    let started = std::time::Instant::now();
    let series = sustained_within_conditioned(0, DEFAULT_TOLERANCE_PCT, 30.0, 1.0, || {
        std::thread::sleep(std::time::Duration::from_millis(5));
    });
    assert!(
        series.converged,
        "a steady workload still converges eventually"
    );
    assert!(
        started.elapsed().as_secs_f64() >= 1.0,
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
    // The two limits must compose, not cancel: a microsecond workload reaches
    // MAX_ITERATIONS long before the conditioning floor, and stopping there
    // would mean convergence could never be declared for it at all.
    let series = sustained_within_conditioned(0, DEFAULT_TOLERANCE_PCT, 30.0, 0.25, || {
        std::hint::black_box((0..50u64).sum::<u64>());
    });
    // THE subject, and the sibling of the `== MAX_ITERATIONS` assertion in the
    // slowing-workload test above: there the conditioning floor was met long
    // before the cap, so the loop stops AT it; here the floor is still unmet at
    // the cap, so the loop must run PAST it. If the two limits cancelled, this
    // length would be exactly `MAX_ITERATIONS` — so `>` is what bites, and it
    // bites however loaded the box is.
    assert!(
        series.iterations_s.len() > MAX_ITERATIONS,
        "it must keep sampling past the iteration cap until conditioning is met \
         (len = {}, stopped_because = {})",
        series.iterations_s.len(),
        series.stopped_because
    );
    // Deliberately NOT `assert!(series.converged)`. Whether a microsecond
    // workload's disjoint medians settle within `DEFAULT_TOLERANCE_PCT` is a
    // property of the machine's scheduling, not of this loop: the guard exits
    // as soon as both limits are met, so convergence gets only the evaluations
    // after `elapsed` crosses the floor — stable on a quiet box, preemption
    // noise on a busy one, where `Instant::elapsed` around a microsecond
    // workload measures the descheduling rather than the work. That assertion
    // was asserting the box was quiet; it failed at load average 10.40 on a
    // shared machine (found by a concurrent workspace run, 2026-09-21).
    //
    // Refusing to converge under contention is the instrument WORKING — the
    // graded binaries refuse an unconverged series rather than publish its
    // median (`spend_edge.rs`, §5.2). So the outcome is the environment's to
    // decide and this test does not grade it.
}

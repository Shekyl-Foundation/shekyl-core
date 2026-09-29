// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `emit` is the one home three copies were consolidated into, and it had no
//! test. These pin the contract its doc states — **a write failure is an
//! error, never a warning** — because that is the property the consolidation
//! exists to hold and the one a fourth copy would drift away from.

use super::{emit, LoadControl};
use serde::Serialize;

#[derive(Serialize)]
struct Record {
    schema: u32,
    note: &'static str,
}

fn record() -> Record {
    Record {
        schema: 2,
        note: "a72",
    }
}

#[test]
fn a_path_receives_the_serialized_record() {
    let dir = std::env::temp_dir().join(format!("wss-q1b-emit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("record.json");
    let as_str = path.to_str().expect("utf8 path");

    emit(&record(), Some(as_str)).expect("a writable path must succeed");

    let written = std::fs::read_to_string(&path).expect("the artifact must exist");
    assert!(
        written.contains("\"schema\": 2") && written.contains("\"note\": \"a72\""),
        "the file must hold the record, not an empty or partial artifact: {written}"
    );
    drop(std::fs::remove_dir_all(&dir));
}

#[test]
fn an_unwritable_path_is_an_error_and_not_a_silent_success() {
    // The doc's central claim: "An explicitly requested artifact that silently
    // fails to appear leaves a measurement with no evidence behind it, which is
    // worse than no run." A directory that does not exist is the cheapest way
    // to make the write fail without depending on permissions, which vary by
    // runner and by root-ness.
    let missing = std::env::temp_dir()
        .join("wss-q1b-emit-no-such-dir")
        .join("nested")
        .join("record.json");
    let as_str = missing.to_str().expect("utf8 path");

    let err = emit(&record(), Some(as_str)).expect_err("a write that cannot land must be an error");
    assert!(
        err.contains("could not write"),
        "the error must name the failure so a run is not recorded as evidence-free: {err}"
    );
    assert!(!missing.exists(), "nothing should have been created");
}

#[test]
fn the_stdout_arm_reports_success_rather_than_assuming_it() {
    // The stdout arm used `println!`, which PANICS on an I/O failure rather
    // than returning one — so it broke the rule the path arm above keeps, and
    // a run piped into a closed reader aborted mid-measurement instead of
    // reporting a write that did not land. It is now an explicit stream write
    // whose result is propagated, so it has a value worth asserting at all.
    //
    // The broken-pipe path itself is deliberately NOT exercised here: closing
    // stdout in-process would take the test harness's own output with it. What
    // this pins is that the arm returns a `Result` reflecting the write, which
    // is what makes that failure reportable instead of fatal.
    emit(&record(), None).expect("writing the record to stdout must report success");
}

/// The bound must be able to reject, and the run that motivated it must be
/// the one it rejects. `+45.2 %` is not a hypothetical: it is a real
/// 2026-09-29 depth-4 control taken while a workspace test suite shared the
/// board, on a run that would otherwise have produced a record.
#[test]
fn a_busy_board_is_not_quiet_and_a_still_one_is() {
    let tol = 10.0;

    let busy = LoadControl::over(&[(45.2, true), (0.4, true)], tol);
    assert!(!busy.quiet, "a 45.2 % control split is not a quiet board");
    assert!((busy.max_divergence_pct - 45.2).abs() < 1e-9);

    // The control on the unmutated input: the same shape, quiet, or the
    // assertion above would pass for a reason other than the divergence.
    let still = LoadControl::over(&[(-0.8, true), (0.4, true)], tol);
    assert!(still.quiet, "the clean run's own controls must pass");
    assert!((still.max_divergence_pct - 0.8).abs() < 1e-9);

    // Sign must not decide it: the divergence is a magnitude.
    assert!(!LoadControl::over(&[(-45.2, true)], tol).quiet);

    // Both sides of the bound, so the threshold is shown to be the thing
    // being tested rather than a value nothing lands near.
    assert!(LoadControl::over(&[(9.99, true)], tol).quiet);
    assert!(!LoadControl::over(&[(10.01, true)], tol).quiet);

    // An unconverged control licenses nothing, whatever its divergence.
    assert!(!LoadControl::over(&[(0.1, false)], tol).quiet);

    // Rule 47: no control is not a quiet board, it is an unmeasured one.
    assert!(!LoadControl::over(&[], tol).quiet);
    assert_eq!(LoadControl::over(&[], tol).controls, 0);
}

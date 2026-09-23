// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `emit` is the one home three copies were consolidated into, and it had no
//! test. These pin the contract its doc states — **a write failure is an
//! error, never a warning** — because that is the property the consolidation
//! exists to hold and the one a fourth copy would drift away from.

use super::emit;
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

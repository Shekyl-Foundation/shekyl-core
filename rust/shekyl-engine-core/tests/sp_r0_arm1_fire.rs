// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-R0 arm #1 — the DQ-F logic-discharge **CI fire lane**.
//!
//! Integration test on purpose: the lib-under-test compiles **without**
//! `cfg(test)`, so `SpentRecordsDurablyPruned::for_test` /
//! `VerifiedBatch::for_test` do not exist in it (Guard 1 — no `for_test()` on
//! the path under test — holds structurally, not by review). The harness
//! drives the production scan/watch/prune/witness path end-to-end; this lane
//! asserts the GC **fired** (fire counters non-zero, records durably gone,
//! production-witness sweep refuses) — DQ-F's CI-asserted condition, not
//! test-existence.
//!
//! Status language (Guard 2): a green run here is **logic-discharge** only;
//! production-firing remains gated on the staker-activation round (#332).

use shekyl_engine_core::__test_helpers::run_arm1_fire;

#[tokio::test]
async fn arm1_gc_fires_on_the_production_path() {
    let report = run_arm1_fire().await.expect("fire harness runs");
    assert_eq!(
        report.cross_step_pruned, 1,
        "cross-step spend must prune exactly the one held record (watch-cache path)"
    );
    assert_eq!(
        report.in_step_pruned, 1,
        "in-step discover-then-spend must prune via the trailing pass"
    );
    assert_eq!(
        report.records_after_cross_step, 0,
        "no spent record survives the seal substrate (cross-step scenario)"
    );
    assert_eq!(
        report.records_after_in_step, 0,
        "no spent record survives the seal substrate (in-step scenario)"
    );
    assert!(
        report.sweep_refuses_after_prune,
        "the production-witness sweep must have nothing spent left to select"
    );
}

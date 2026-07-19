// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-R0 arm #3 — the DQ-F logic-discharge **CI fire lane**, the fixture
//! SA-DQ-3 co-designed with the activation round (an activation-induced
//! persist-then-no-broadcast crash, collected at the next production open).
//! Integration test on purpose: the lib-under-test compiles without
//! `cfg(test)`, so the evidence can only come from the production
//! verify/ingest/seal path (Guard 1, structural).
//!
//! Status language (Guard 2): a green run here is **logic-discharge**; the
//! production-discharge form (a crashed real `stake` RPC flow) rides the
//! regtest lane.

use shekyl_engine_core::__test_helpers::run_arm3_fire;

#[tokio::test(flavor = "multi_thread")]
async fn arm3_phantom_gc_fires_on_the_production_open_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let report = run_arm3_fire(tmp.path()).await.expect("fire harness runs");
    assert!(
        report.unscanned_slot_survived,
        "absence-unscanned must never GC (OutsideCovered keeps the slot)"
    );
    assert!(
        report.phantom_dropped,
        "confirmed-absent phantom slot must be collected at open"
    );
    assert!(
        report.reverted_to_non_staker,
        "an emptied bonded_slots reverts the wallet to a clean non-staker"
    );
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2g deliverable: per-hash latency benchmark against the v2
//! C reference, asserting Rust/C ratio ≤ 3.0× per Phase 0 §8 budget.
//! Requires 2g's differential harness binary; landed alongside 2g's
//! other harness infrastructure.
//!
//! Cadence: release-gate suite, not per-PR CI, per parent plan's
//! release-gate vs per-PR split.
//!
//! # Why this file exists at Phase 2c
//!
//! Per
//! [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §5.8 disposition #3 + §8 + §13 R3-minor-2: the per-hash latency
//! check is a Phase 2g forward-action, but the placeholder lands
//! here at Phase 2c so the deliverable name is grep-discoverable
//! from the canonical path that 2g's author will populate. The
//! `#[ignore]` keeps `cargo test` from running the unimplemented
//! body; the `unimplemented!()` produces a clear pointer to where
//! the real work lands if someone runs it explicitly with
//! `cargo test -- --ignored`.
//!
//! Structural code out-survives prose discipline per
//! [`21-reversion-clause-discipline.mdc`](../../../../.cursor/rules/21-reversion-clause-discipline.mdc);
//! the placeholder is the out-surviving form. Same shape as Phase
//! 2c's stub-NOP `dispatch_instruction` body-replacement, applied
//! to a different cross-phase hand-off (this one: the 2c → 2g
//! differential-harness deliverable).

#[test]
#[ignore = "Phase 2g deliverable; placeholder per 2c's F8 forward-action"]
fn per_hash_latency_ratio_within_budget() {
    unimplemented!(
        "Phase 2g lands this; see RANDOMX_V2_PHASE2C_PLAN.md §5.8 F8 \
         and §13 forward-path 2g inheritance"
    );
}

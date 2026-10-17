// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool decorator's negative control (DRS-E5 PR-b b1): a verdict
//! judged over [`PoolView`](shekyl_mempool::PoolView) cannot be connected.
//! The pool judges a transaction against the chain plus its own key images;
//! a `ChainValid` minted over that view is a statement about a chain the
//! store does not hold, and `connect` takes only a verdict branded with the
//! batch's own view (`ChainValid<'id, BatchView<'_, 'id>>`).
//!
//! `trybuild` compares stderr whole, so the cause of the failure is what is
//! asserted (`CHAIN_RULES_CRATE.md` §8.3: a `compile_fail` doctest cannot
//! say why), and `verdict_over_the_batch_view_connects.rs` is the positive
//! control — the same program over the batch's own view compiles.
//!
//! # Reading a snapshot mismatch
//!
//! - **The same `E0308`, reworded** — the toolchain moved (pinned in
//!   `rust-toolchain.toml`). Regenerate with `TRYBUILD=overwrite`.
//! - **A different error** — something else stopped the program compiling
//!   (the positive control fails too). Fix that; do not regenerate.
//! - **No error** — a pool verdict reached `connect`. That is a finding
//!   against the store's brand, not a snapshot to refresh.

#[test]
fn a_verdict_judged_over_the_pool_view_does_not_connect() {
    let t = trybuild::TestCases::new();
    t.pass("tests/trybuild/verdict_over_the_batch_view_connects.rs");
    t.compile_fail("tests/trybuild/verdict_over_the_pool_view_does_not_connect.rs");
}

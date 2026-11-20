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
//!
//! # Cadence
//!
//! `trybuild` builds the programs in a cargo project of its own, where the
//! dependency tree compiles again. These programs link `shekyl-chain-rules`
//! and reuse its harness's build when that ran first (two minutes on the CI
//! runner), and would pay the whole tree alone (about 19 minutes). Since
//! 2026-11-09 both tests are `#[ignore]`d and run every night, after the
//! chain-rules harness, by the `trybuild-ignored` lane
//! (`scripts/ci/ignored_set_trybuild.sh`); a pull request's Rust job only
//! checks that they are still here. `cargo test --test trybuild --
//! --ignored` runs them locally.

#[test]
#[ignore = "builds its programs over chain-rules' dependency tree, ~19 min cold; run nightly by trybuild-ignored"]
fn a_verdict_judged_over_the_pool_view_does_not_connect() {
    let t = trybuild::TestCases::new();
    t.pass("tests/trybuild/verdict_over_the_batch_view_connects.rs");
    t.compile_fail("tests/trybuild/verdict_over_the_pool_view_does_not_connect.rs");
}

/// S6 (the review of #1102): the block arrivals and the every-entry reads
/// are not the pool's public surface; `RelayView` is the one named reader.
#[test]
#[ignore = "builds its programs over chain-rules' dependency tree, ~19 min cold; run nightly by trybuild-ignored"]
fn a_block_arrival_and_an_unfiltered_read_are_not_public() {
    let t = trybuild::TestCases::new();
    t.pass("tests/trybuild/the_relay_view_reads_every_entry.rs");
    t.compile_fail("tests/trybuild/a_block_arrival_is_not_reachable.rs");
    t.compile_fail("tests/trybuild/an_unfiltered_read_is_the_relay_views.rs");
}

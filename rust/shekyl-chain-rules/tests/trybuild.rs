// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The brand gate on [`validate`](shekyl_chain_rules::validate): a verdict
//! carries its view's brand *and* type, so it connects under that view and
//! no other. A property the type system enforces has no runtime behaviour
//! to test; the test is the program that must not compile.
//!
//! These were two `compile_fail` doctests on `validate` until 2026-10-10.
//! A doctest's `compile_fail` verdict cannot say *why* the program failed,
//! and from 2026-09-29 — when `ChainView` grew the archival reads and the
//! doctests' stub views did not — both passed because their stubs no
//! longer implemented the trait (`E0046`), not because `connect` refused
//! the verdict. A green gate about the wrong subject. `trybuild` compares
//! stderr whole against a snapshot, so the failure's cause is the thing
//! asserted, and `verdict_connects_under_its_own_view.rs` is the positive
//! control that the shared stub (`stub_view.rs`) still implements the
//! trait at all.
//!
//! # Reading a snapshot mismatch
//!
//! - **`E0046` in the actual output** — the stub fell behind `ChainView`
//!   or `HeaderView`. Add the method to `stub_view.rs`; do not regenerate.
//! - **The same error, reworded** — the toolchain moved (it is pinned in
//!   `rust-toolchain.toml`, so this happens in the bump PR). Regenerate
//!   with `TRYBUILD=overwrite`.
//! - **A different error, or none** — the brand property itself moved.
//!   That is a finding against `validate`, not a snapshot to refresh.

#[test]
fn a_verdict_connects_under_the_view_it_was_judged_against_and_no_other() {
    let t = trybuild::TestCases::new();
    t.pass("tests/trybuild/verdict_connects_under_its_own_view.rs");
    t.compile_fail("tests/trybuild/verdict_does_not_escape_its_view.rs");
    t.compile_fail("tests/trybuild/unbranded_view_does_not_connect.rs");
}

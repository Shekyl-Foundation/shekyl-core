// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The lending types' negative controls (`RANDOMX_CACHE_ACTOR.md` §5.3): a
//! job cannot return its `Lent` or `Loan`, cannot store one where it
//! outlives the job, and cannot clone one. Each is what keeps a 256 MiB
//! cache from outliving the job that borrowed it, so the cap counts every
//! cache in the process.
//!
//! `trybuild` compares stderr whole, so the cause is asserted, not only the
//! failure; `a_job_that_hashes_compiles.rs` is the positive control.
//!
//! # Reading a snapshot mismatch
//!
//! - **The same error, reworded:** the toolchain moved (pinned in
//!   `rust-toolchain.toml`). Regenerate with `TRYBUILD=overwrite`.
//! - **A different error:** something else stopped the program compiling,
//!   and the positive control fails too. Fix that; do not regenerate.
//! - **No error:** a lent cache can leave its job. That is a finding
//!   against the lending types, not a snapshot to refresh.

#[test]
fn a_lent_cache_cannot_leave_its_job() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/trybuild/a_job_that_hashes_compiles.rs");
    cases.compile_fail("tests/trybuild/a_job_returns_its_lent.rs");
    cases.compile_fail("tests/trybuild/a_job_stores_its_loan.rs");
    cases.compile_fail("tests/trybuild/a_lent_is_cloned.rs");
}

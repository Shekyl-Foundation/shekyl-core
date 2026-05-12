// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to
//! `engine_trait_bench_key_account_public_address.rs`.
//!
//! `KeyEngine` is `pub(crate)` in `shekyl-engine-core`, so the trait
//! is not in scope from a bench-target compilation unit and cannot
//! be referenced via rustdoc intra-doc links here. References to
//! `KeyEngine` and `KeyEngine::account_public_address` render as
//! plain backticked code throughout this file by design.
//!
//! Same workload (a single `KeyEngine::account_public_address` call
//! against a freshly constructed [`LocalKeys`] fixture) measured via
//! Valgrind's Callgrind for deterministic instruction-count metrics.
//! This is the bench whose `instructions` value the CI gate
//! (`ci/benchmarks` workflow) uses for the pass/fail signal under the
//! `engine_trait_bench_*` threshold class (bidirectional ±10%
//! slowdown / ±25% speedup).
//!
//! Requires `cargo install iai-callgrind-runner` and a working
//! Valgrind install. See `docs/design/STAGE_0_HARNESS.md` §3 for the
//! existing harness substrate this bench plugs into.
//!
//! # Workload class
//!
//! **Trivial pure-read.** The method returns a borrow into a cached
//! [`AccountPublicAddress`] field on `LocalKeys` without any per-call
//! derivation, allocation, or arithmetic. The call chain is the
//! trait-dispatch ceremony (~10 instructions per
//! `engine_trait_bench_ledger_synced_height_iai.rs`'s expected
//! range) plus a single struct-field reference load. iai-callgrind's
//! deterministic instruction count is the load-bearing signal for
//! this workload class because criterion's `median_ns` reflects
//! optimizer amortization across the iteration loop (the §4.4 hoisting
//! rule applies here, unlike the LedgerEngine::balance state-walk
//! workload).
//!
//! # Expected post-fixture instructions
//!
//! Per `docs/design/STAGE_0_HARNESS.md` §4.4's static check
//! (component model): the post-fixture `instructions` count for this
//! bench is expected to be in the **low tens of instructions
//! (~10–30)** range — the trait-dispatch ceremony shared with
//! `engine_trait_bench_ledger_synced_height` plus the cached-field
//! load. Numbers above the upper bound (>100 instructions) suggest:
//!
//! 1. **Setup leakage** — the `#[bench::address(setup =
//!    build_local_keys_fixture, ...)]` attribute did not keep the
//!    fixture build (account derivation + ML-KEM keygen) outside the
//!    measured function body. Setup leakage manifests as billions of
//!    instructions for this workload class.
//! 2. **Teardown leakage (symmetry-rule violation)** — the bench
//!    function returns the fixture and `teardown =
//!    drop_local_keys_fixture` lifts `Drop` outside the measured
//!    region. Without that explicit teardown, the
//!    [`LocalKeys`]-zeroize teardown (`ZeroizeOnDrop` over the
//!    contained `AllKeysBlob`) would dominate the count.
//! 3. **Method gained per-call work** — e.g.,
//!    `KeyEngine::account_public_address` was refactored to derive
//!    on every call instead of returning a cached reference. Tighten
//!    the model with the additional component, refresh the expected
//!    range, and document the refinement in the PR description.
//!
//! # Boundary rule (`LocalKeys` fixture shape)
//!
//! The fixture shape `Box<LocalKeys>` is a substrate-forced
//! divergence from the unified `(Box<Engine<...>>, TempDir)` shape
//! the LedgerEngine bench uses. See the criterion sibling's docstring
//! for the full substrate rationale.
//!
//! Boundary-cost discipline is preserved: per §4.2, any fixture field
//! exceeding 64 bytes goes behind `Box<T>` so the bench-function
//! boundary moves only pointer-sized data, keeping iai-callgrind's
//! residual boundary cost at ~5–10 instructions instead of dominating
//! the measurement. `LocalKeys` is substantially larger than 64 bytes
//! (carries an `AllKeysBlob` plus state-shaped fields and a
//! subaddress-registry `RwLock`); `Box<LocalKeys>` moves only the
//! pointer.
//!
//! # Naming alignment
//!
//! The function name (`engine_trait_bench_key_account_public_address`)
//! is what `compare.py`'s `classify()` routes on for threshold-class
//! resolution. The file name's `_iai` suffix and the group name's
//! `_group` suffix are convention; the function name is the
//! load-bearing identifier. All three names share the
//! `engine_trait_bench_key_account_public_address` stem so PR
//! reviewers grepping for the workload find consistent surface
//! across the criterion / iai pair and the manifest row.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use shekyl_engine_core::__bench_internals::{engine_account_public_address_for_bench, LocalKeys};

mod common;

use common::engine_fixture::{build_local_keys_fixture, drop_local_keys_fixture};

#[library_benchmark]
#[bench::address(
    setup = build_local_keys_fixture,
    teardown = drop_local_keys_fixture
)]
fn engine_trait_bench_key_account_public_address(fixture: Box<LocalKeys>) -> Box<LocalKeys> {
    black_box(engine_account_public_address_for_bench(&fixture));
    fixture
}

library_benchmark_group!(
    name = engine_trait_bench_key_account_public_address_group;
    benchmarks = engine_trait_bench_key_account_public_address,
);

main!(library_benchmark_groups = engine_trait_bench_key_account_public_address_group);

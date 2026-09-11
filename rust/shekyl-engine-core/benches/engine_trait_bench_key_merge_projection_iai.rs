// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! gungraun companion to
//! `engine_trait_bench_key_merge_projection.rs`.
//!
//! Same workload (the §5.3 / §8.1 6-i construction-time view-secret
//! projection, `populate_engine_handle_fields`, over a batch of
//! `MERGE_BENCH_OUTPUT_COUNT` freshly-merged outputs) measured via
//! Valgrind's Callgrind for a deterministic instruction count. This is
//! the bench whose `instructions` value the CI gate uses for the
//! per-output projection cost under the `engine_trait_bench_*` threshold
//! class (bidirectional ±10% slowdown / ±25% speedup).
//!
//! Unlike the actor dispatch paths, the merge post-pass is synchronous
//! and runtime-free, so it is gungraun-friendly: no async scheduling, no
//! threads for Valgrind to serialize, a clean deterministic count.
//!
//! # Why Callgrind client requests, not the default toggle
//!
//! Gungraun's default collection starts when the `__gungraun_wrapper_mod`
//! symbol is *entered* (`--toggle-collect` + `--collect-at-start=no`). When
//! rustc inlines or ICF-folds that `#[inline(never)]` wrapper, the toggle
//! never fires and Callgrind reports exactly zero for every counter while the
//! run itself exits `Ok` — the capture guard's `instructions=0` rejection
//! (`docs/investigation/2026-05-09-bench-baseline-flake.md`). Because a folded
//! wrapper is a property of the emitted binary, the zero is **deterministic**
//! for a given source + toolchain: re-running the workflow cannot clear it.
//!
//! This cell hit exactly that on PR #607 (2026-09-04): it captured green on
//! head `5e56fefad`, and after the next head (`f90e9ea2d`) shifted engine-core
//! enough to tip the fold, it reported `instructions=0` on **all 3 in-run
//! attempts across two CI runs** (the original and a fresh rerun) while
//! measuring ~5.16M instructions locally under valgrind 3.24.0. Converted to
//! Callgrind client requests — position-based magic instructions inside the
//! measured region, immune to the wrapper fold — with setup left
//! uninstrumented via `--instr-atstart=no` + `EntryPoint::None`, the pattern
//! `key_dispatch_baseline_iai` and `ledger_iai` already carry. The reported
//! count moves by the handful of client-request instructions (far inside the
//! ±10% warn band); the post-merge `update-baseline` run absorbs it.
//!
//! # Workload class
//!
//! **Batch-bound, per-output crypto.** The count scales with
//! `MERGE_BENCH_OUTPUT_COUNT` (256): each output costs a `HashMap`
//! lookup + a `derive_output_handle` cSHAKE256 PRF + a ~1.1 KiB hybrid
//! ciphertext clone. The expected `instructions` count is large
//! (256 × per-output cost) and dominated by the cSHAKE256 work; it is
//! the load-bearing regression signal for the 6-i projection cost the
//! §8.1 6-ii-deferral decision is evidence-based against.
//!
//! # Boundary rule
//!
//! `Box<MergeProjectionBenchFixture>` keeps the bench-function boundary
//! at pointer width (§4.2); the fixture carries a `LedgerBlock` of 256
//! transfers plus a residue map (far above the 64-byte cutoff). The
//! function returns the fixture and `teardown =
//! drop_merge_projection_fixture` lifts the batch's `Drop` (256
//! transfers + 256 × 1.1 KiB ciphertexts) out of the measured region
//! (symmetry rule); without it, deallocation would distort the count.
//!
//! # Single measured invocation (idempotent-once)
//!
//! The projection only populates `None` fields, so it is one-shot per
//! fixture. gungraun builds a fresh fixture via `setup` and measures
//! exactly one `run_projection`, so the full batch's work is measured
//! once — matching the criterion sibling's `iter_batched` per-invocation
//! fresh-fixture shape.

use std::hint::black_box;

use gungraun::client_requests::callgrind as callgrind_cr;
use gungraun::{
    library_benchmark, library_benchmark_group, main, Callgrind, EntryPoint, LibraryBenchmarkConfig,
};
use shekyl_engine_core::__bench_internals::{
    build_merge_projection_fixture, drop_merge_projection_fixture, MergeProjectionBenchFixture,
};

#[library_benchmark]
#[bench::projection(
    setup = build_merge_projection_fixture,
    teardown = drop_merge_projection_fixture
)]
fn engine_trait_bench_key_merge_projection(
    mut fixture: Box<MergeProjectionBenchFixture>,
) -> Box<MergeProjectionBenchFixture> {
    // The projection and its `black_box` both sit INSIDE the measured region,
    // so the optimizer cannot sink the work past `stop_instrumentation`; the
    // fixture return stays outside (the `key_dispatch_baseline_iai` pattern).
    measure(|| {
        fixture.run_projection();
        black_box(fixture.populated_count())
    });
    fixture
}

/// Run `f` between Callgrind `start`/`stop_instrumentation` so the count is
/// the projection itself, via position-based client requests that survive
/// whatever the optimizer does to the default toggle wrapper (see the module
/// "Why Callgrind client requests" note). Mirrors
/// `engine_trait_bench_key_dispatch_baseline_iai`'s `measure`.
fn measure<T>(f: impl FnOnce() -> T) -> T {
    callgrind_cr::start_instrumentation();
    let out = f();
    callgrind_cr::stop_instrumentation();
    out
}

library_benchmark_group!(
    name = engine_trait_bench_key_merge_projection_group;
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::with_args(["--instr-atstart=no"])
            .entry_point(EntryPoint::None)
        );
    benchmarks = engine_trait_bench_key_merge_projection,
);

main!(library_benchmark_groups = engine_trait_bench_key_merge_projection_group);

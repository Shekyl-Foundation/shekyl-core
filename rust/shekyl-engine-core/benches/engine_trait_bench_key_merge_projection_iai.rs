// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to
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
//! and runtime-free, so it is iai-friendly: no async scheduling, no
//! threads for Valgrind to serialize, a clean deterministic count.
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
//! fixture. iai-callgrind builds a fresh fixture via `setup` and measures
//! exactly one `run_projection`, so the full batch's work is measured
//! once — matching the criterion sibling's `iter_batched` per-invocation
//! fresh-fixture shape.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
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
    fixture.run_projection();
    black_box(fixture.populated_count());
    fixture
}

library_benchmark_group!(
    name = engine_trait_bench_key_merge_projection_group;
    benchmarks = engine_trait_bench_key_merge_projection,
);

main!(library_benchmark_groups = engine_trait_bench_key_merge_projection_group);

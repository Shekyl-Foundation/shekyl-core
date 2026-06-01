// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! §5.3 **merge-path** benchmark (criterion / wall-clock): the 6-i
//! construction-time view-secret projection over a batch of freshly
//! merged outputs. See `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` §5.3
//! and §8.1.
//!
//! # What this measures (and what it is evidence for)
//!
//! `populate_engine_handle_fields` (`engine/merge.rs`) is the
//! synchronous post-pass `Engine::apply_scan_result` runs over every
//! newly-inserted output: per output it does a `HashMap` lookup
//! (detection residue → on-chain ciphertext), a `derive_output_handle`
//! (cSHAKE256 PRF over the view secret), and a hybrid-ciphertext clone
//! into `TransferDetails`. This bench drives that exact post-pass over a
//! synthetic batch of `MERGE_BENCH_OUTPUT_COUNT` unpopulated transfers.
//!
//! The per-output marginal cost is the evidence the §8.1 **6-ii deferral
//! decision** is weighed against: 6-i does this projection eagerly at
//! merge time; 6-ii would defer it to first spend. If the per-output
//! cost here is negligible against a refresh's other work, eager 6-i
//! stays and 6-ii remains deferred; a surprise here reopens §8.1.
//!
//! # iai sibling
//!
//! Unlike the actor dispatch paths, this post-pass is **synchronous and
//! runtime-free**, so it has a deterministic instruction count and a
//! paired iai-callgrind sibling
//! (`engine_trait_bench_key_merge_projection_iai.rs`). The pair restores
//! the criterion+iai discipline (`docs/design/STAGE_0_HARNESS.md`) that
//! the actor paths reason-deviate from.
//!
//! # Threshold class / naming
//!
//! `engine_trait_bench_key_merge_projection` routes (via the
//! `engine_trait_bench_` prefix in `compare.py`) into the bidirectional
//! `engine_trait_bench` class (±10% warn / ±25% fail). The frozen
//! baseline is captured at merge SHA (deferred → `PERFORMANCE_BASELINE.md`).
//!
//! # Measurement-region discipline
//!
//! The projection is **idempotent-once**: it only populates fields that
//! are `None`, so a second run over the same `LedgerBlock` does no work.
//! The bench therefore uses `iter_batched` with a fresh fixture per
//! measured invocation (`build_merge_projection_fixture` as the setup
//! closure), so every measured `run_projection` does the full
//! batch's work. Fixture build (256 transfers + residue map) is held
//! outside the measured region by `iter_batched`'s setup boundary.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use shekyl_engine_core::__bench_internals::build_merge_projection_fixture;

fn engine_trait_bench_key_merge_projection(c: &mut Criterion) {
    c.bench_function("engine_trait_bench_key_merge_projection", |b| {
        b.iter_batched(
            build_merge_projection_fixture,
            |mut fixture| {
                fixture.run_projection();
                black_box(fixture.populated_count())
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, engine_trait_bench_key_merge_projection);
criterion_main!(benches);

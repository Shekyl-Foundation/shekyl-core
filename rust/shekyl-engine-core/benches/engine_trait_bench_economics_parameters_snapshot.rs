// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Stage 1 PR 7 (EconomicsEngine) frozen-baseline criterion bench for
//! the `EconomicsEngine::parameters_snapshot` trait method.
//!
//! Companion to
//! `engine_trait_bench_economics_parameters_snapshot_iai.rs`. See
//! `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §3.8 and
//! `docs/PERFORMANCE_BASELINE.md`'s
//! `engine_trait_bench_economics_parameters_snapshot` section for the
//! harness integration this bench plugs into.
//!
//! `EconomicsEngine` is `pub(crate)` in `shekyl-engine-core`, so the
//! trait is not in scope from a bench-target compilation unit and
//! cannot be referenced via rustdoc intra-doc links here. References
//! to `EconomicsEngine` and `EconomicsEngine::parameters_snapshot`
//! render as plain backticked code throughout this file by design.
//!
//! # What this measures
//!
//! `engine.economics.parameters_snapshot()`, dispatched through the
//! `EconomicsEngine` trait surface on the engine's `economics` field.
//! Workload class: **pure compute with a digest**. Per §6.3 G5 the
//! snapshot is rebuilt fresh on every call (no process-wide cache) and
//! computes a Blake2b-256 `params_digest` over the fixed-width
//! parameter layout — the digest is the dominant per-call cost, so this
//! is *not* a trivial pure-read. The method reads nothing from
//! `ChainEconomicsSource`. The shim returns the snapshot's
//! `money_supply_atomic` (`u64`) so the bench consumes an observable
//! without widening the crate's public API with the `pub(crate)`
//! snapshot type.
//!
//! # Pair, threshold class, frozen baseline
//!
//! - Pair: this file (criterion / wall-clock) and
//!   `engine_trait_bench_economics_parameters_snapshot_iai.rs`
//!   (iai-callgrind / instructions). The CI gate (`ci/benchmarks`
//!   workflow) routes through iai-callgrind for the pass/fail signal;
//!   this file is the Tier-2 informational column.
//! - Threshold class: `engine_trait_bench_*` — bidirectional ±10%
//!   slowdown / ±25% speedup per `docs/MID_REWIRE_HARDENING.md` §3.3
//!   and `docs/design/STAGE_0_HARNESS.md` §4.3.
//! - Frozen baseline: captured at this PR's merge SHA per the
//!   `docs/design/STAGE_0_HARNESS.md` §4.5 per-bench frozen-baseline
//!   discipline. Transcription to `docs/PERFORMANCE_BASELINE.md`
//!   happens after CI workflow_dispatch captures the numbers under
//!   N=3 invariance.
//!
//! # Measurement-region discipline
//!
//! Per §4.2: the engine-construction work in [`build_engine_fixture`]
//! (`Engine::create` ceremony) is **setup**, held outside `b.iter`.
//! Only the `EconomicsEngine::parameters_snapshot` trait call is
//! measured.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shekyl_engine_core::__bench_internals::engine_economics_parameters_snapshot_for_bench;

mod common;

use common::engine_fixture::build_engine_fixture;

fn engine_trait_bench_economics_parameters_snapshot(c: &mut Criterion) {
    // Setup is outside `b.iter` — engine construction is excluded from
    // the measured region per §4.2 measurement-region discipline.
    let (engine, _tmp) = build_engine_fixture();

    c.bench_function("engine_trait_bench_economics_parameters_snapshot", |b| {
        b.iter(|| black_box(engine_economics_parameters_snapshot_for_bench(&engine)));
    });
}

criterion_group!(benches, engine_trait_bench_economics_parameters_snapshot);
criterion_main!(benches);

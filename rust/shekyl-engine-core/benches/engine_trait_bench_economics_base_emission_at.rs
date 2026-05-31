// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Stage 1 PR 7 (EconomicsEngine) frozen-baseline criterion bench for
//! the `EconomicsEngine::base_emission_at` trait method.
//!
//! Companion to `engine_trait_bench_economics_base_emission_at_iai.rs`.
//! See `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §3.8 / §5.2 B.6
//! and `docs/PERFORMANCE_BASELINE.md`'s
//! `engine_trait_bench_economics_base_emission_at` section for the
//! harness integration this bench plugs into.
//!
//! `EconomicsEngine` is `pub(crate)` in `shekyl-engine-core`, so the
//! trait is not in scope from a bench-target compilation unit and
//! cannot be referenced via rustdoc intra-doc links here. References
//! to `EconomicsEngine` and `EconomicsEngine::base_emission_at` render
//! as plain backticked code throughout this file by design.
//!
//! # What this measures
//!
//! `engine.economics.base_emission_at(ECONOMICS_BENCH_HEIGHT)`,
//! dispatched through the `EconomicsEngine` trait surface on the
//! engine's `economics` field. Workload class: **state-independent
//! compute, O(height)**. Under interpretation (A) the method walks
//! `projected_already_generated(height)` block-by-block from genesis
//! (`shekyl-economics::emission`), so per-call cost scales linearly
//! with the bench height — it is *not* a trivial pure-read, and
//! criterion's `median_ns` cleanly approximates per-call cost (the
//! §4.4 hoisting-rule amortization caveat applies to trivial reads,
//! not to this workload). The method reads nothing from
//! `ChainEconomicsSource`.
//!
//! Per §5.2 B.6 the naive O(height) projection is deliberate at V3.0;
//! if a hot consumer ever lands, the FOLLOWUPS checkpoint-table
//! disposition replaces the loop with an O(1) checkpoint lookup. The
//! frozen baseline pins to the naive-loop workload at the merge SHA.
//!
//! # Pair, threshold class, frozen baseline
//!
//! - Pair: this file (criterion / wall-clock) and
//!   `engine_trait_bench_economics_base_emission_at_iai.rs`
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
//! Only the `EconomicsEngine::base_emission_at` trait call is measured.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shekyl_engine_core::__bench_internals::engine_economics_base_emission_at_for_bench;

mod common;

use common::engine_fixture::{build_engine_fixture, ECONOMICS_BENCH_HEIGHT};

fn engine_trait_bench_economics_base_emission_at(c: &mut Criterion) {
    // Setup is outside `b.iter` — engine construction is excluded from
    // the measured region per §4.2 measurement-region discipline.
    let (engine, _tmp) = build_engine_fixture();

    c.bench_function("engine_trait_bench_economics_base_emission_at", |b| {
        b.iter(|| {
            black_box(engine_economics_base_emission_at_for_bench(
                &engine,
                black_box(ECONOMICS_BENCH_HEIGHT),
            ))
        });
    });
}

criterion_group!(benches, engine_trait_bench_economics_base_emission_at);
criterion_main!(benches);

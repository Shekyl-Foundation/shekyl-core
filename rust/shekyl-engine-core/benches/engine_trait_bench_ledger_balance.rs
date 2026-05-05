// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Stage 1 PR 2 frozen-baseline criterion bench for the
//! `LedgerEngine::balance` trait method on a state-populated
//! fixture.
//!
//! Companion to `engine_trait_bench_ledger_balance_iai.rs`. See
//! `docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md` §5 (commit 8) and
//! `docs/PERFORMANCE_BASELINE.md`'s
//! `engine_trait_bench_ledger_balance` section for the harness
//! integration this bench plugs into.
//!
//! `LedgerEngine` is `pub(crate)` in `shekyl-engine-core`, so the
//! type is not in scope from a bench-target compilation unit and
//! cannot be referenced via rustdoc intra-doc links here.
//! References to `LedgerEngine` and `LedgerEngine::balance` render
//! as plain backticked code throughout this file by design.
//!
//! # What this measures
//!
//! `engine.ledger.balance() -> BalanceSummary`, dispatched through
//! the `LedgerEngine` trait surface (commit 5 migrated `Engine`'s
//! production read paths to trait dispatch; this bench measures the
//! same call shape that production callers hit). On a fixture
//! pre-populated with [`BENCH_BALANCE_TRANSFER_COUNT`] = 1024
//! `TransferDetails` entries, `shekyl_scanner::BalanceSummary::compute`
//! walks the transfer slice once per call. Workload class:
//! **state-dependent compute** — per-call cost scales linearly with
//! the populated transfer count, so criterion's `median_ns` cleanly
//! approximates per-call cost (the §4.4 hoisting rule's amortization
//! caveat applies to trivial pure-reads, not to this workload).
//!
//! # Pair, threshold class, frozen baseline
//!
//! - Pair: this file (criterion / wall-clock) and
//!   `engine_trait_bench_ledger_balance_iai.rs` (iai-callgrind /
//!   instructions). The CI gate (`ci/benchmarks` workflow) routes
//!   through iai-callgrind for the pass/fail signal; this file is
//!   the Tier-2 informational column.
//! - Threshold class: `engine_trait_bench_*` — bidirectional ±10%
//!   slowdown / ±25% speedup per `docs/MID_REWIRE_HARDENING.md` §3.3
//!   and `docs/design/STAGE_0_HARNESS.md` §4.3.
//! - Frozen baseline: captured at this PR's merge SHA per the
//!   `docs/design/STAGE_0_HARNESS.md` §4.5 per-bench frozen-baseline
//!   discipline. The transcription to `docs/PERFORMANCE_BASELINE.md`
//!   happens in commit 9 after CI workflow_dispatch captures the
//!   numbers under N=3 invariance.
//!
//! # Measurement-region discipline
//!
//! Per §4.2: the engine-construction work in
//! [`build_engine_fixture_with_balance`] (`Engine::create` ceremony +
//! 1024-transfer state injection) is **setup**, held outside `b.iter`.
//! Only the `LedgerEngine::balance` trait call is measured.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shekyl_engine_core::__bench_internals::engine_balance_for_bench;

mod common;

use common::engine_fixture::{build_engine_fixture_with_balance, BENCH_BALANCE_TRANSFER_COUNT};

fn engine_trait_bench_ledger_balance(c: &mut Criterion) {
    // Setup is outside `b.iter` — engine construction + state
    // population are excluded from the measured region per §4.2
    // measurement-region discipline.
    let (engine, _tmp) = build_engine_fixture_with_balance(BENCH_BALANCE_TRANSFER_COUNT);

    c.bench_function("engine_trait_bench_ledger_balance", |b| {
        b.iter(|| black_box(engine_balance_for_bench(&engine)));
    });
}

criterion_group!(benches, engine_trait_bench_ledger_balance);
criterion_main!(benches);

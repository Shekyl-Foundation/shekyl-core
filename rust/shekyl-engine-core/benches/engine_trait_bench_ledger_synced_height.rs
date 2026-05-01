// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Stage 0 frozen-baseline criterion bench for the today-equivalent
//! call path of the future `LedgerEngine::synced_height` trait method.
//!
//! See `docs/design/STAGE_0_HARNESS.md` §4.1 (today-equivalent
//! enumeration) and §4.2 (Stage-0-frozen disposition for `synced_height`).
//!
//! # What this measures
//!
//! `Engine::<SoloSigner>::synced_height(&self) -> u64` — currently a
//! single field access through `self.ledger.ledger.height()`. State
//! independent: the workload does not scale with the wallet's transfer
//! count or block-history depth. The bench is the cheapest workload in
//! the `engine_trait_bench_*` family; its purpose is per-call dispatch
//! overhead, not algorithmic complexity.
//!
//! # Pair, threshold class, frozen baseline
//!
//! - Pair: this file (criterion / wall-clock) and
//!   `engine_trait_bench_ledger_synced_height_iai.rs` (iai-callgrind /
//!   instructions). The CI gate (`ci/benchmarks` workflow, extended in
//!   Stage 0 PR-2 commit 3) routes through iai-callgrind for the
//!   pass/fail signal; this file is the Tier-2 informational column.
//! - Threshold class: `engine_trait_bench_*` — bidirectional ±10%
//!   slowdown / ±25% speedup per `docs/MID_REWIRE_HARDENING.md` §3.3
//!   and `docs/design/STAGE_0_HARNESS.md` §4.3.
//! - Frozen baseline: captured at Stage 0 PR-2's merge SHA per §4.5.
//!   Cumulative-delta semantics: each Stage 1 PR's description cites
//!   this bench's delta against the frozen-baseline SHA, computed by
//!   re-running the bench at the PR's tip.
//!
//! # Measurement-region discipline
//!
//! Per §4.2: the engine-construction work in
//! [`common::engine_fixture::build_engine_fixture`] (Argon2id KDF,
//! ML-KEM keygen, envelope encryption, filesystem layout) is **setup**,
//! held outside `b.iter`. Only the [`Engine::synced_height`] call is
//! measured.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

mod common;

use common::engine_fixture::build_engine_fixture;

fn engine_trait_bench_ledger_synced_height(c: &mut Criterion) {
    // Setup is outside `b.iter` — engine construction is excluded from
    // the measured region per §4.2 measurement-region discipline.
    let (engine, _tmp) = build_engine_fixture();

    c.bench_function("engine_trait_bench_ledger_synced_height", |b| {
        b.iter(|| black_box(engine.synced_height()));
    });
}

criterion_group!(benches, engine_trait_bench_ledger_synced_height);
criterion_main!(benches);

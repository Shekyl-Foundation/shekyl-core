// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Stage 1 PR 3 close-out criterion bench for the
//! `KeyEngine::account_public_address` trait method on a freshly
//! constructed [`LocalKeys`] fixture.
//!
//! Companion to `engine_trait_bench_key_account_public_address_iai.rs`.
//! See `docs/design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md` §1.2 and
//! `docs/design/STAGE_0_HARNESS.md` §4.2 for the harness integration
//! this bench plugs into.
//!
//! `KeyEngine` is `pub(crate)` in `shekyl-engine-core`, so the trait
//! is not in scope from a bench-target compilation unit and cannot
//! be referenced via rustdoc intra-doc links here. References to
//! `KeyEngine` and `KeyEngine::account_public_address` render as
//! plain backticked code throughout this file by design.
//!
//! # What this measures
//!
//! `keys.account_public_address() -> &AccountPublicAddress`,
//! dispatched through the `KeyEngine` trait surface (M3a wired the
//! implementor; M3d completed the structural realignment). Workload
//! class: **trivial pure-read** — the method returns a borrow into
//! a cached `AccountPublicAddress` field on `LocalKeys` without
//! any per-call derivation work. The criterion `median_ns` is
//! expected to reflect optimizer amortization across `b.iter`'s
//! iteration loop; the iai-callgrind sibling is the load-bearing
//! signal for this pair (§4.4 amortization caveat for trivial
//! reads applies here, not to LedgerEngine::balance).
//!
//! # Pair, threshold class, frozen baseline
//!
//! - Pair: this file (criterion / wall-clock) and
//!   `engine_trait_bench_key_account_public_address_iai.rs`
//!   (iai-callgrind / instructions). The CI gate
//!   (`ci/benchmarks` workflow) routes through iai-callgrind for
//!   the pass/fail signal; this file is the Tier-2 informational
//!   column.
//! - Threshold class: `engine_trait_bench_*` — bidirectional ±10%
//!   slowdown / ±25% speedup per `docs/MID_REWIRE_HARDENING.md` §3.3
//!   and `docs/design/STAGE_0_HARNESS.md` §4.3. The function-name
//!   routing in `compare.py`'s `classify()` resolves this pair to
//!   the `engine_trait_bench_*` class on the
//!   `engine_trait_bench_key_account_public_address` stem.
//! - Frozen baseline: captured at this PR's merge SHA per the
//!   `docs/design/STAGE_0_HARNESS.md` §4.5 per-bench frozen-baseline
//!   discipline. Transcription to `docs/PERFORMANCE_BASELINE.md`
//!   happens after CI workflow_dispatch captures the numbers under
//!   N=3 invariance (deferred → captured at <merge SHA>).
//!
//! # Fixture-shape divergence from `engine_trait_bench_ledger_balance`
//!
//! The `LedgerEngine` bench uses `(Box<Engine<SoloSigner,
//! DaemonClient, LocalLedger>>, TempDir)`; this bench uses
//! `Box<LocalKeys>`. The divergence is forced by substrate, not
//! convenience:
//!
//! - `Engine<S, D, L>` holds `keys: AllKeysBlob` (the wallet key
//!   material) but does not yet hold the `KeyEngine`-implementing
//!   [`LocalKeys`] as a field — that orchestrator integration is
//!   PR-5 territory per
//!   `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` §2.1.1 (the Round 4a
//!   workflow-shape pivot).
//! - `LocalKeys` is purely in-memory (no `WalletFile`, no advisory
//!   lock, no wallet-state directory), so no `TempDir` guard is
//!   needed in the fixture tuple.
//!
//! Both points are documented at the fixture-builder site
//! ([`build_local_keys_fixture`]); the close-out PR's pre-flight
//! §1.2 captures the same divergence with the substrate-discipline
//! rationale.
//!
//! # Measurement-region discipline
//!
//! Per §4.2: the [`build_local_keys_fixture`] work
//! (`generate_account_from_raw_seed` KDF + ML-KEM keygen + cached
//! `AccountPublicAddress` construction) is **setup**, held outside
//! `b.iter`. Only the `KeyEngine::account_public_address` trait call
//! is measured.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shekyl_engine_core::__bench_internals::engine_account_public_address_for_bench;

mod common;

use common::engine_fixture::build_local_keys_fixture;

fn engine_trait_bench_key_account_public_address(c: &mut Criterion) {
    let keys = build_local_keys_fixture();

    c.bench_function("engine_trait_bench_key_account_public_address", |b| {
        b.iter(|| black_box(engine_account_public_address_for_bench(&keys)));
    });
}

criterion_group!(benches, engine_trait_bench_key_account_public_address);
criterion_main!(benches);

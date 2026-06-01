// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to the §5.3 **B9** composition baseline
//! (`engine_trait_bench_key_dispatch.rs`'s
//! `engine_trait_bench_key_dispatch_baseline_claim_mine`).
//!
//! See `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` §5.3. This sibling
//! measures **only** the deterministic crypto baseline
//! (`LocalKeys::try_claim_output` over a `Mine` output): X25519 view-tag
//! match + hybrid ML-KEM-768 decap + HKDF + key-image + handle insert.
//! There is deliberately **no** iai sibling for the actor `ask` paths —
//! they are cross-thread async round-trips whose Callgrind
//! instruction counts fold in nondeterministic runtime-scheduling
//! machinery (Valgrind serializes all threads onto one simulated core).
//! The actor paths are criterion-only by design; see the criterion
//! sibling's docstring for the reversion clause.
//!
//! # Why an actor-free fixture
//!
//! [`KeyBaselineBenchFixture`] holds just the `LocalKeys` and a prebuilt
//! `Mine` input — no `KeyEngineHandle`, no spawned `KeyActor` — so it
//! constructs without an ambient multi-thread runtime, and the Callgrind
//! run never simulates one. The single async call is driven by a leaked
//! **current-thread** runtime; `LocalKeys::try_claim_output` completes
//! synchronously inside its future (per `local_keys.rs`), so
//! `block_on`-of-an-immediately-`Ready`-future contributes only a small
//! constant, leaving the count dominated by the ML-KEM-768 decap.
//!
//! # Workload class
//!
//! **Crypto-bound, allocation-present.** Unlike the trivial pure-read
//! `account_public_address` bench, this path runs a full hybrid KEM
//! decapsulation and HKDF expansion plus a key-image scalar-mult, so the
//! expected `instructions` count is **large** (millions, dominated by
//! ML-KEM-768). iai-callgrind's determinism makes it the stable
//! regression signal for the crypto cost; the criterion sibling carries
//! the wall-clock ratio that B9's "within 5%" envelope is checked
//! against.
//!
//! # Threshold class / naming
//!
//! The function name `engine_trait_bench_key_dispatch_baseline_claim_mine`
//! is what `compare.py`'s `classify()` routes on — the
//! `engine_trait_bench_` prefix lands it in the bidirectional
//! `engine_trait_bench` class (±10% warn / ±25% fail). The file's `_iai`
//! suffix and the group's `_group` suffix are convention. The frozen
//! baseline is captured at merge SHA (deferred → `PERFORMANCE_BASELINE.md`).
//!
//! # Boundary rule
//!
//! `Box<KeyBaselineBenchFixture>` keeps the bench-function boundary at
//! pointer width (§4.2); the fixture carries a `LocalKeys` (well above
//! the 64-byte cutoff). `teardown = drop_key_baseline_fixture` lifts the
//! `LocalKeys` zeroize-on-drop out of the measured region (symmetry rule).

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use shekyl_engine_core::__bench_internals::{
    build_key_baseline_fixture, drop_key_baseline_fixture, KeyBaselineBenchFixture,
};

/// Leaked current-thread runtime that drives the single synchronously-
/// completing `claim_mine` future. Current-thread (not multi-thread) so
/// no worker threads exist for Valgrind to serialize; its `block_on`
/// overhead for a `Ready` future is a small constant.
fn baseline_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build current-thread tokio runtime for baseline iai bench")
    })
}

#[library_benchmark]
#[bench::claim_mine(
    setup = build_key_baseline_fixture,
    teardown = drop_key_baseline_fixture
)]
fn engine_trait_bench_key_dispatch_baseline_claim_mine(
    fixture: Box<KeyBaselineBenchFixture>,
) -> Box<KeyBaselineBenchFixture> {
    let rt = baseline_runtime();
    black_box(rt.block_on(async { fixture.claim_mine().await }));
    fixture
}

library_benchmark_group!(
    name = engine_trait_bench_key_dispatch_baseline_group;
    benchmarks = engine_trait_bench_key_dispatch_baseline_claim_mine,
);

main!(library_benchmark_groups = engine_trait_bench_key_dispatch_baseline_group);

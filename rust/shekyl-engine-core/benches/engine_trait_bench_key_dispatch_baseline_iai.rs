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
//! run never simulates one. The single async call is driven by a
//! **no-op-waker poll** (see `poll_ready` below), not a Tokio
//! `block_on`: `LocalKeys::try_claim_output` completes inside its first
//! poll (per `local_keys.rs`), so one `poll` returns `Ready` and the
//! count is exactly the ML-KEM-768 decap + HKDF + key-image work with no
//! runtime machinery folded in. A current-thread Tokio `block_on` was
//! tried first and rejected — under Callgrind it did not drive the body
//! to completion, collapsing the count to ≈4.8k handshake instructions
//! rather than the ≈15M decap.
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

use std::future::Future;
use std::hint::black_box;
use std::pin::pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use shekyl_engine_core::__bench_internals::{
    build_key_baseline_fixture, drop_key_baseline_fixture, KeyBaselineBenchFixture,
};

/// Drive a synchronously-completing future to its value with a no-op
/// waker — no Tokio runtime in the measured region.
///
/// `LocalKeys::try_claim_output` is `async` for Stage-4 trait-surface
/// flexibility but completes inside the first poll (per `local_keys.rs`).
/// A Tokio `block_on` would either (a) fold reactor/scheduler machinery
/// into the Callgrind count, or (b) — as observed for a current-thread
/// runtime — fail to drive the body to completion under Callgrind,
/// collapsing the measured count to the runtime-handshake instructions
/// only (≈4.8k) instead of the ML-KEM-768 decap (millions). Polling with
/// a no-op waker is the honest deterministic-crypto measurement: one
/// poll, asserted `Ready`, zero runtime noise.
fn poll_ready<F: Future>(fut: F) -> F::Output {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: the vtable's clone/wake/wake_by_ref/drop are all no-ops over
    // a null data pointer, so the waker is never dereferenced; it satisfies
    // the `RawWaker` contract trivially.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    match pin!(fut).poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => {
            panic!(
                "baseline iai bench future did not complete in one poll; \
                    LocalKeys::try_claim_output is expected to be synchronous"
            )
        }
    }
}

#[library_benchmark]
#[bench::claim_mine(
    setup = build_key_baseline_fixture,
    teardown = drop_key_baseline_fixture
)]
fn engine_trait_bench_key_dispatch_baseline_claim_mine(
    fixture: Box<KeyBaselineBenchFixture>,
) -> Box<KeyBaselineBenchFixture> {
    black_box(poll_ready(fixture.claim_mine()));
    fixture
}

library_benchmark_group!(
    name = engine_trait_bench_key_dispatch_baseline_group;
    benchmarks = engine_trait_bench_key_dispatch_baseline_claim_mine,
);

main!(library_benchmark_groups = engine_trait_bench_key_dispatch_baseline_group);

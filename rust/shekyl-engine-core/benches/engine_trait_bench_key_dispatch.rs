// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! §5.3 **B9 dispatch-overhead** benchmark (criterion / wall-clock).
//! See `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` §5.3.
//!
//! `KeyEngine` and `KeyEngineHandle` are `pub(crate)` in
//! `shekyl-engine-core`, so neither is in scope from a bench-target
//! compilation unit; the [`KeyDispatchBenchHarness`] (gated behind
//! `bench-internals`, re-exported through `__bench_internals`) is the
//! single surface this bench drives, and its measured methods return
//! `bool` so no `pub(crate)` type crosses the boundary.
//!
//! # What this measures (B9 = bench-vs-bench ratio, not an absolute gate)
//!
//! Three wall-clock numbers (§5.3):
//!
//! - `engine_trait_bench_key_dispatch_baseline_claim_mine` — direct
//!   `LocalKeys::try_claim_output` on a `Mine` output (X25519 view-tag +
//!   hybrid ML-KEM-768 decap + HKDF + key-image + handle insertion). The
//!   composition baseline.
//! - `engine_trait_bench_key_dispatch_actor_claim_mine` — the same
//!   output via `KeyEngineHandle::try_claim_output` (an `ask` round-trip
//!   through the mailbox). The **ratio actor/baseline is the B9 signal**;
//!   the DoD's "within 5%" is checked as `actor ≤ 1.05 × baseline`, with
//!   the messaging overhead expected lost in the ML-KEM-768 decap noise.
//! - `engine_trait_bench_key_dispatch_actor_claim_not_mine` — a
//!   `NotMine` output via the `ask` (X25519 pre-filter only, the cheap
//!   common case). This is where the 5% envelope is hardest to hold;
//!   §5.3 records the dispatch cost against the cheapest real op as
//!   evidence for (not a gate on) the §8.3 view-scan split.
//!
//! # No iai-callgrind sibling for the actor paths
//!
//! The `ask` is a cross-thread async round-trip; iai-callgrind runs
//! under Callgrind (Valgrind serializes threads onto a simulated single
//! core), so an `ask`'s instruction count folds in nondeterministic
//! runtime-scheduling machinery rather than the clean deterministic
//! signal iai exists for. The actor paths are criterion-only by design —
//! a reasoned, reversion-claused deviation from the criterion+iai
//! pairing discipline (`docs/design/STAGE_0_HARNESS.md`): reopen the iai
//! sibling if a deterministic async-dispatch measurement method lands.
//! Only the deterministic-crypto baseline gets an iai sibling
//! (`engine_trait_bench_key_dispatch_baseline_iai.rs`).
//!
//! # Threshold class / frozen baseline
//!
//! `compare.py`'s `classify()` routes on the `engine_trait_bench_`
//! prefix, so all three IDs land in the bidirectional `engine_trait_bench`
//! class (±10% warn / ±25% fail). The frozen baseline is captured at this
//! PR's merge SHA via CI `workflow_dispatch` (deferred → see
//! `docs/PERFORMANCE_BASELINE.md`).
//!
//! # Measurement-region discipline
//!
//! The harness build (two `AllKeysBlob` rederivations + ML-KEM keygen +
//! actor spawn + two synthetic outputs) is **setup**, held outside
//! `b.iter`. The runtime is leaked once for the bench binary so the
//! spawned `KeyActor` outlives the harness. Only the `try_claim_output`
//! calls are measured; `rt.block_on` drives the async surface inside the
//! iteration loop (its overhead is symmetric across the baseline and
//! actor paths, so it cancels in the ratio).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shekyl_engine_core::__bench_internals::KeyDispatchBenchHarness;

/// Process-wide multi-thread Tokio runtime, built once and intentionally
/// leaked for the bench binary's lifetime. The `KeyActor` the harness
/// spawns is an async task that must live on a runtime outlasting the
/// harness; a one-shot runtime would tear it down immediately. Same
/// shape `benches/common/engine_fixture.rs::bench_runtime` uses.
fn bench_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .expect("build multi-thread tokio runtime for dispatch bench")
    })
}

fn engine_trait_bench_key_dispatch(c: &mut Criterion) {
    let rt = bench_runtime();
    // Spawn the actor inside the runtime context (require-ambient, §4.2).
    let harness = rt.block_on(async { KeyDispatchBenchHarness::new() });

    c.bench_function("engine_trait_bench_key_dispatch_baseline_claim_mine", |b| {
        b.iter(|| rt.block_on(async { black_box(harness.baseline_claim_mine().await) }));
    });

    c.bench_function("engine_trait_bench_key_dispatch_actor_claim_mine", |b| {
        b.iter(|| rt.block_on(async { black_box(harness.actor_claim_mine().await) }));
    });

    c.bench_function(
        "engine_trait_bench_key_dispatch_actor_claim_not_mine",
        |b| {
            b.iter(|| rt.block_on(async { black_box(harness.actor_claim_not_mine().await) }));
        },
    );
}

criterion_group!(benches, engine_trait_bench_key_dispatch);
criterion_main!(benches);

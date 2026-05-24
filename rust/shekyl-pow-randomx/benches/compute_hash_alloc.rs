// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `compute_hash` per-call criterion bench (full pipeline under
//! stub-NOP dispatch) plus Phase 2F §6.3 Round 3 A/B harness.
//!
//! # Two harnesses live here
//!
//! 1. **Phase 2c baseline (`per_call`).** Original
//!    [`shekyl_pow_randomx::compute_hash`] median per
//!    [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//!    §5.8 + §8. Always runs.
//! 2. **Phase 2F A/B harness (`with_no_pool::per_call` +
//!    `with_pool::per_call`).** Round 3's cfg-gated A/B per
//!    [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
//!    §3.3 / §6.3 / §3.4. `with_no_pool` measures the production
//!    no-pool path against the same fixture the Phase 2c bench
//!    uses (so the A/B comparison is apples-to-apples).
//!    `with_pool` measures
//!    [`shekyl_pow_randomx::compute_hash_with_pool`] against a
//!    pre-allocated pool of capacity 4 (the test-default
//!    `binding_fanout + 1` per §3.5 R1-D5 Round 3 — see
//!    `BENCH_RESULTS.md` for the methodology). `with_pool` is
//!    cfg-gated: it only compiles when the bench is built with
//!    `cargo bench --bench compute_hash_alloc --features
//!    internal-pool-bench`.
//!
//! Phase 2c informational baseline per
//! [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §5.8 disposition #1 + §8. Measures the per-call cost of
//! `compute_hash(&prepared, &DATA)` with a pre-derived
//! [`PreparedCache`] shared across iterations (so the
//! [`PreparedCache::derive`] cost is amortized out of the per-call
//! measurement). The harness measures the **full `compute_hash`
//! pipeline**, not the `VmState` allocation skeleton in isolation —
//! the bench name's "alloc" suffix reflects the §5.8 plan-doc
//! framing (the planned ≤100 µs budget targeted the allocation
//! portion), not what the bench actually measures.
//!
//! [`PreparedCache`]: shekyl_pow_randomx::PreparedCache
//! [`PreparedCache::derive`]: shekyl_pow_randomx::PreparedCache::derive
//!
//! # Per-call cost composition
//!
//! Under the stub-NOP `dispatch_instruction` body, the per-call cost
//! is dominated by the per-chain hash-math pipeline plus the
//! inter-chain Blake2b chaining:
//!
//! - `VmState` allocation (2 MiB scratchpad + register file)
//!   — one-shot, sub-millisecond.
//! - `fillAes1Rx4` scratchpad seeding (1 round × 2 MiB / 64 B
//!   blocks) — per chain, 8 times.
//! - 8 × per-program init from entropy (`init_program`).
//! - 8 × 2048 stub-NOP iteration-loop bodies (sp_mix, register
//!   loads, AES f/e mix, dataset reads via `derive_item`'s
//!   superscalar program execution, scratchpad writes, register
//!   write-back — but no per-instruction work since dispatch is NOP).
//! - 7 × `feed_register_file_to_hasher` + Blake2b-512 for inter-
//!   chain `temp_hash` overwrites (Step 3 of `compute_hash`).
//! - `getFinalResult` (`hashAes1Rx4` over 2 MiB + Blake2b-256
//!   finalization).
//!
//! The dominant cost in this composition is the iteration-loop
//! bodies + `derive_item`'s SuperScalar execution + the
//! `hashAes1Rx4` final pass, **not** the one-shot allocation.
//!
//! # Status: informational, not PR-gating
//!
//! §5.8 originally framed this bench as an absolute-threshold PR
//! gate with **Median ≤ 100 µs**, with the budget binding the
//! `VmState` allocation portion specifically. The Phase 2c
//! empirical baseline on the reference machine (i9-11950H, Debian
//! 13) is **~296 ms median** per `BENCH_RESULTS.md` — the bench
//! measures the full pipeline (which the planned ≤100 µs budget
//! never bound), and the full-pipeline number is dominated by the
//! hash-math work above, not the one-shot allocation. The
//! disposition (R0-D12 in `RANDOMX_V2_PHASE2C_PLAN.md` §14) is to
//! record the empirical number, run this bench as **informational**
//! at Phase 2c, and either introduce an allocation-only sub-bench
//! (where the §8 ≤100 µs target stays applicable) or re-baseline
//! the budget against the full-pipeline shape this bench actually
//! measures. Phase 2d's plan doc is the natural decision point.
//! Until then, CI does not fail on this bench's output, and the
//! ≤100 µs claim should not be read as currently enforced.
//!
//! Phase 2d's real per-opcode dispatch will grow this bench's per-
//! call cost further by the per-instruction work (8 × 2048 = 16384
//! opcode executions per call), making the bench-split decision
//! more pressing.
//!
//! # Threshold enforcement mechanism (when the gate is re-enabled)
//!
//! Same as `cache_derive.rs`: §5.8's "PR fails if median > X"
//! framing applies once the R0-D12 reconciliation re-baselines the
//! budget against measured hardware classes (or splits this bench
//! into allocation-only vs. execution-only sub-benches). At Phase
//! 2c the CI threshold check is **informational** per §5.8 final
//! paragraph (the bench output is recorded but does not fail the
//! workflow).

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

/// 32-byte canonical bench seedhash bytes. Distinct from the
/// spec-vector tests' `CANONICAL_SEEDHASH_BYTES` to keep bench and
/// test reference state separate per the rationale in
/// `cache_derive.rs`.
const BENCH_SEEDHASH_BYTES: [u8; 32] = *b"shekyl-randomx-v2-bench-c_hash00";

/// 76-byte ASCII bench input. The actual byte content is irrelevant
/// to the measurement (compute_hash cost is input-length-dominated
/// only through the initial Blake2b-512 seed step, which is a fixed
/// few hundred nanoseconds against the dominant 2 MiB scratchpad
/// work); a stable label keeps the bench reproducible across runs.
const BENCH_DATA: &[u8] =
    b"shekyl-randomx-v2-phase2c-compute_hash-alloc-bench-canonical-input-padding";

/// Common sample-size pin for every per-call full-pipeline bench in
/// this file. §5.8's nominal sample-size is N=10000. Implementation-
/// PR-time observation (recorded in `BENCH_RESULTS.md`): the per-
/// call wall-clock cost of `compute_hash` under stub-NOP dispatch is
/// dominated by the iteration-loop overhead (8 chains × 2048 iters
/// × per-iteration AES f/e mix + scratchpad RW + dataset reads via
/// `derive_item`'s superscalar program execution) plus the final
/// `hashAes1Rx4` over 2 MiB plus Blake2b-256 finalization. That sums
/// to ~300 ms per call on the reference machine (i9-11950H per
/// `BENCH_RESULTS.md`), making 10000 samples take 30+ minutes wall-
/// clock per bench run — not tractable for the developer loop.
///
/// `sample_size = 100` keeps the bench measurement within criterion's
/// adaptive measurement-time budget (~1–2 minutes wall-clock per run)
/// while still producing a statistically meaningful median. Phase 2F
/// §6.3 Round 3's A/B benches use the same value so the no-pool
/// vs. pool comparison is apples-to-apples (same N, same prepared
/// cache, same data). The §5.8 budget reconciliation — the planned
/// ≤100 µs binds the allocation-only sub-bench (B-2 / B-3 in
/// `per_call_alloc.rs`), not this full-pipeline measurement — is
/// tracked at `RANDOMX_V2_PHASE2C_PLAN.md` §14 R0-D12 with reopening
/// criteria (re-baseline against measured hardware classes vs.
/// introduce an allocation-only sub-bench vs. defer to Phase 2g's
/// Rust-vs-C ratio). At Phase 2c / 2F this bench is informational,
/// not PR-gating.
const PER_CALL_SAMPLE_SIZE: usize = 100;

fn bench_compute_hash_alloc(c: &mut Criterion) {
    // Pre-derive the bundle outside the timed loop so the
    // `PreparedCache::derive` cost (~341 ms on the reference
    // machine per `BENCH_RESULTS.md`, dominated by the underlying
    // `Cache::derive` Argon2d fill) is paid once total, not per
    // iteration. Even with the bundle pre-derivation, this bench
    // measures the *full per-call pipeline* (VmState alloc +
    // scratchpad init + 8 chains × 2048-iter loop + 7 × Blake2b-512
    // inter-chain + final hashAes1Rx4 + Blake2b-256), not the
    // allocation skeleton in isolation.
    let prepared = PreparedCache::derive(Seedhash::from_bytes(BENCH_SEEDHASH_BYTES));

    let mut group = c.benchmark_group("compute_hash_alloc");
    group.sample_size(PER_CALL_SAMPLE_SIZE);
    group.bench_function("per_call", |b| {
        b.iter(|| {
            let hash = compute_hash(black_box(&prepared), black_box(BENCH_DATA));
            black_box(hash)
        });
    });
    group.finish();
}

/// Phase 2F §6.3 Round 3 `B-pool-off` bench: production no-pool
/// path under the cfg-gated A/B harness. Identical to
/// `bench_compute_hash_alloc` above in measurement target (both call
/// [`shekyl_pow_randomx::compute_hash`]); the bench exists separately
/// so the criterion ID `compute_hash_alloc::with_no_pool::per_call`
/// pairs with `compute_hash_alloc::with_pool::per_call` in the
/// `BENCH_RESULTS.md` A/B-delta table.
///
/// Always runs (no feature gate).
fn bench_compute_hash_with_no_pool(c: &mut Criterion) {
    let prepared = PreparedCache::derive(Seedhash::from_bytes(BENCH_SEEDHASH_BYTES));

    let mut group = c.benchmark_group("compute_hash_alloc");
    group.sample_size(PER_CALL_SAMPLE_SIZE);
    group.bench_function("with_no_pool::per_call", |b| {
        b.iter(|| {
            let hash = compute_hash(black_box(&prepared), black_box(BENCH_DATA));
            black_box(hash)
        });
    });
    group.finish();
}

/// Phase 2F §6.3 Round 3 `B-pool-on` bench: cfg-gated pool path
/// under the A/B harness. Pre-allocates a [`VmStatePool`] of capacity
/// 4 (the test-default per §3.5 R1-D5 Round 3 — Phase 3a's FFI shim
/// will pass an explicit capacity at production-construction time)
/// and runs `compute_hash_with_pool` against it. The pool persists
/// across criterion iterations so the second-and-subsequent calls
/// hit the recycled `VmState`, exposing the A/B savings against the
/// no-pool path's per-call `VmState::new` cost.
///
/// Cfg-gated to `feature = "internal-pool-bench"`. Build with
/// `cargo bench --bench compute_hash_alloc --features
/// internal-pool-bench` to enable; the production
/// `cargo bench --bench compute_hash_alloc` invocation skips the
/// bench entirely and the bench harness only registers
/// `with_no_pool::per_call` against the existing `per_call`.
///
/// [`VmStatePool`]: shekyl_pow_randomx::VmStatePool
#[cfg(feature = "internal-pool-bench")]
fn bench_compute_hash_with_pool(c: &mut Criterion) {
    use shekyl_pow_randomx::{compute_hash_with_pool, VmStatePool};

    let prepared = PreparedCache::derive(Seedhash::from_bytes(BENCH_SEEDHASH_BYTES));

    // Capacity 4 mirrors the §3.5 R1-D5 Round 3 test-default
    // (`m_max_prepare_blocks_threads + 1` − 1, where the daemon's
    // canonical default is 4 plus the +1 reserve gives 5 — but a
    // single-bench-thread harness only ever holds 1 lease at a
    // time, so any capacity ≥ 1 measures the steady-state pool-
    // hit cost. Capacity = 4 keeps the bench's pool shape in line
    // with the daemon's expected steady-state).
    let pool = VmStatePool::new(4);

    let mut group = c.benchmark_group("compute_hash_alloc");
    group.sample_size(PER_CALL_SAMPLE_SIZE);
    group.bench_function("with_pool::per_call", |b| {
        b.iter(|| {
            let hash = compute_hash_with_pool(
                black_box(&pool),
                black_box(&prepared),
                black_box(BENCH_DATA),
            );
            black_box(hash)
        });
    });
    group.finish();
}

#[cfg(feature = "internal-pool-bench")]
criterion_group!(
    benches,
    bench_compute_hash_alloc,
    bench_compute_hash_with_no_pool,
    bench_compute_hash_with_pool,
);

#[cfg(not(feature = "internal-pool-bench"))]
criterion_group!(
    benches,
    bench_compute_hash_alloc,
    bench_compute_hash_with_no_pool,
);

criterion_main!(benches);

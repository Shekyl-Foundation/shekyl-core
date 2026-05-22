// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `compute_hash` per-call criterion bench (allocation portion).
//!
//! Phase 2c PR-gate per
//! [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §5.8 disposition #1 + §8 BENCH_RESULTS.md baseline. Measures the
//! per-call cost of `compute_hash(&cache, &SEEDHASH, &DATA)` with a
//! pre-derived `Cache` shared across iterations (so the ~200 ms
//! `Cache::derive` cost is amortized over the 10000 iterations and
//! does not pollute the per-call measurement).
//!
//! # PR-gate budget (Phase 2c stub-NOP)
//!
//! **Median ≤ 100 µs** at Phase 2c, under the stub-NOP
//! `dispatch_instruction` body. The per-call cost is dominated by:
//!
//! - `VmState` allocation (2 MiB scratchpad + register file).
//! - Scratchpad zeroing (the `Box::new_zeroed_slice` call).
//! - `fillAes1Rx4` scratchpad seeding (1 round × 2 MiB / 64 B blocks).
//! - 8 × per-program init from entropy (`init_program`).
//! - 8 × 2048 stub-NOP iteration-loop bodies (sp_mix, register loads,
//!   AES f/e mix, dataset reads, scratchpad writes, register write-
//!   back — but no per-instruction work since dispatch is NOP).
//! - `getFinalResult` (hashAes1Rx4 over 2 MiB + Blake2b-256
//!   finalization).
//!
//! Phase 2d's real per-opcode dispatch will grow this bench's per-
//! call cost by the per-instruction work (8 × 2048 = 16384 opcode
//! executions per call). The 100 µs budget continues to bind the
//! *allocation* portion specifically; Phase 2d's plan doc may split
//! this bench into allocation-only vs. execution-only sub-benches if
//! precision becomes load-bearing (per §5.8 implementation-PR-time
//! decision clause).
//!
//! # Threshold enforcement mechanism
//!
//! Same as `cache_derive.rs`: §5.8's "PR fails if median > X" gate is
//! enforced by the PR author running `cargo bench -p shekyl-pow-
//! randomx --bench compute_hash_alloc` locally before opening the PR,
//! comparing the median against the 100 µs budget, and either
//! landing the result in `BENCH_RESULTS.md` (if green) or surfacing
//! the regression to the reviewer (if red). CI threshold check is
//! informational at Phase 2c per §5.8 final paragraph.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_pow_randomx::{compute_hash, Cache};

/// 32-byte canonical bench seedhash. Distinct from the spec-vector
/// tests' `CANONICAL_SEEDHASH` to keep bench and test reference
/// state separate per the rationale in `cache_derive.rs`.
const BENCH_SEEDHASH: [u8; 32] = *b"shekyl-randomx-v2-bench-c_hash00";

/// 76-byte ASCII bench input. The actual byte content is irrelevant
/// to the measurement (compute_hash cost is input-length-dominated
/// only through the initial Blake2b-512 seed step, which is a fixed
/// few hundred nanoseconds against the dominant 2 MiB scratchpad
/// work); a stable label keeps the bench reproducible across runs.
const BENCH_DATA: &[u8] =
    b"shekyl-randomx-v2-phase2c-compute_hash-alloc-bench-canonical-input-padding";

fn bench_compute_hash_alloc(c: &mut Criterion) {
    // Pre-derive cache outside the timed loop so the ~200 ms Argon2d
    // cost is paid once total, not per iteration. This is the whole
    // point of the "alloc" framing: measure compute_hash's *per-call*
    // cost (VmState alloc + iteration loop + final hash), not the
    // amortized cost-plus-cache-derivation.
    let cache = Cache::derive(&BENCH_SEEDHASH);

    let mut group = c.benchmark_group("compute_hash_alloc");
    // §5.8 specifies N=10000 iterations. Implementation-PR-time
    // observation (recorded in `BENCH_RESULTS.md`): the per-call
    // wall-clock cost of `compute_hash` under stub-NOP dispatch is
    // dominated by the iteration-loop overhead (8 chains × 2048
    // iters × per-iteration AES f/e mix + scratchpad RW + dataset
    // reads via `derive_item`'s superscalar program execution) plus
    // the final `hashAes1Rx4` over 2 MiB plus Blake2b-256 finalization.
    // That sums to ~hundreds of ms per call on this hardware class
    // (i9-11950H), making 10000 samples take 30+ minutes wall-clock
    // per bench run — not tractable for the developer loop §5.8's
    // disposition #1 names as the gate ("PR fails if median > 100 µs"
    // gate runs before PR open).
    //
    // The §5.8 "implementation-PR-time decision" clause authorizes the
    // sample-size choice. Pinning sample_size = 100 keeps the bench
    // measurement within criterion's adaptive measurement-time
    // budget (~1-2 minutes wall-clock per run) while still producing
    // a statistically meaningful median for the baseline. The §5.8
    // budget reconciliation (100 µs vs. measured per-call cost) is
    // surfaced in `BENCH_RESULTS.md` as a Phase 2c finding rather
    // than absorbed silently; the §5.8 budget shape ("budget binds
    // the VmState allocation portion specifically") may be revisited
    // in Phase 2d's plan doc as part of the bench-split decision
    // (allocation-only vs. execution-only sub-benches).
    group.sample_size(100);
    group.bench_function("per_call", |b| {
        b.iter(|| {
            let hash = compute_hash(
                black_box(&cache),
                black_box(&BENCH_SEEDHASH),
                black_box(BENCH_DATA),
            );
            black_box(hash)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_compute_hash_alloc);
criterion_main!(benches);

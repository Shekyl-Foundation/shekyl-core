// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Cache::derive` end-to-end criterion bench.
//!
//! Phase 2c PR-gate per
//! [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §5.8 disposition #1 + §8 BENCH_RESULTS.md baseline. Measures the
//! cost of a single `Cache::derive(&KEY)` call (Argon2d 256 MiB fill,
//! followed by eight `Blake2Generator`-seeded `generateSuperscalar`
//! programs) on a fixed 32-byte seedhash; sample size = 100 per §5.8
//! spec.
//!
//! # PR-gate budget
//!
//! **Median ≤ 200 ms.** Per §5.8: "PR fails if median > 200 ms."
//! Recorded in `BENCH_RESULTS.md` at PR-merge with the run conditions
//! (CPU, OS, kernel, libc, criterion version, wall-clock date) so
//! downstream phases (2d, 2f, 2g) compare against a known baseline.
//! Regression >10% triggers investigation but not auto-failure
//! (auto-failure is the absolute-threshold check above).
//!
//! # Threshold enforcement mechanism
//!
//! Per §5.8 final paragraph the CI threshold check is **informational
//! at this phase** (the bench output is recorded but does not fail
//! the workflow). The absolute-threshold gate is enforced by the PR
//! author running `cargo bench -p shekyl-pow-randomx --bench
//! cache_derive` locally before opening the PR, comparing the median
//! against the 200 ms budget, and either landing the result in
//! `BENCH_RESULTS.md` (if green) or surfacing the regression to the
//! reviewer (if red). The criterion runner is invoked with
//! `--measurement-time` long enough to converge to a stable median
//! on 256 MiB cache derivation, then the median printed to stdout by
//! criterion is the gate value.
//!
//! # Why this isn't a `#[test]`
//!
//! The natural alternative would be to put the threshold check in
//! `src/cache.rs#mod tests` so `cargo test` enforces it. Two
//! disqualifiers per §5.8 framing:
//!
//! 1. **Wall-clock determinism.** Tests are expected to be
//!    deterministic across CI runner classes. A 200 ms threshold on a
//!    busy runner can flake from background process contention,
//!    invalidating the test on substrate (runner load) rather than on
//!    code substance. Benches accept this noise because their job is
//!    measurement, not validation.
//! 2. **Sample-size economics.** 100 iterations × 200 ms = 20 s per
//!    `cargo test` invocation per test, which would dominate the
//!    debug-mode test runtime. Benches naturally accept that cost
//!    because the developer opts into them.
//!
//! The disposition therefore matches §5.8's "PR fails if median > X"
//! literal reading: enforcement is the developer's responsibility
//! pre-PR, the bench is the measurement instrument, BENCH_RESULTS.md
//! is the recorded baseline, and the reviewer's job is to confirm
//! the recorded numbers fit the budget.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_pow_randomx::Cache;

/// 32-byte canonical bench seedhash. Distinct from the spec-vector
/// tests' `CANONICAL_SEEDHASH` (sequential `0x01..=0x20`) to keep
/// benches and tests from accidentally sharing reference state; the
/// specific bytes are irrelevant to the measurement (Argon2d cost is
/// input-independent at fixed parameters), so a stable ASCII label
/// works as well as any other byte string.
const BENCH_SEEDHASH: [u8; 32] = *b"shekyl-randomx-v2-bench-Cache-00";

fn bench_cache_derive(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_derive");
    // §5.8 specifies N=100 iterations on a fixed seedhash. Criterion
    // chooses the actual sample size based on measurement-time + a
    // warm-up phase; pinning sample_size = 100 makes the reported
    // median directly correspond to the spec's prescribed sample
    // count rather than criterion's adaptive default (which would
    // pick 10 due to the per-iteration cost).
    group.sample_size(100);
    group.bench_function("derive", |b| {
        b.iter(|| {
            let cache = Cache::derive(black_box(&BENCH_SEEDHASH));
            // Force the result to be observable so the optimizer
            // cannot elide the derivation. `black_box` on the
            // resulting `Cache` participates in the per-iteration
            // measurement boundary.
            black_box(cache)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cache_derive);
criterion_main!(benches);

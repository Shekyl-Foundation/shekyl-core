// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PreparedCache::derive` end-to-end criterion bench.
//!
//! Phase 2c informational baseline per
//! [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §5.8 disposition #1 + §8. Measures the cost of a single
//! [`PreparedCache::derive(Seedhash)`][PreparedCache::derive] call
//! (the inner `Cache::derive` Argon2d 256 MiB fill, followed by
//! eight `Blake2Generator`-seeded `generateSuperscalar` programs,
//! plus the bundle assembly that copies the 32-byte seedhash) on
//! a fixed seedhash; sample size = 100 per §5.8 spec. The bundle
//! assembly is sub-microsecond and dominated by the Argon2d fill;
//! the bench's Phase 2c baseline is unchanged from the pre-Phase-2F
//! `Cache::derive` shape it replaces.
//!
//! [PreparedCache::derive]: shekyl_pow_randomx::PreparedCache::derive
//!
//! # Status: informational, not PR-gating
//!
//! §5.8 originally framed this bench as an absolute-threshold PR
//! gate with **Median ≤ 200 ms**. The Phase 2c empirical baseline
//! on the reference machine (i9-11950H, Debian 13) is **~341 ms
//! median** per `BENCH_RESULTS.md` — exceeding the planned budget.
//! Rather than retrofit a runner-class-specific budget at the §5.8
//! plan-doc layer, the disposition (R0-D12 in
//! `RANDOMX_V2_PHASE2C_PLAN.md` §14) is to record the empirical
//! number, run this bench as **informational** at Phase 2c, and
//! re-baseline the budget against measured hardware classes in
//! Phase 2d (or sooner if a sub-bench split materializes — see
//! R0-D12's reopening criteria). CI does not fail on this bench's
//! output at Phase 2c; the bench output is recorded in
//! `BENCH_RESULTS.md` so downstream phases (2d, 2f, 2g) compare
//! against a known baseline.
//!
//! # Threshold enforcement mechanism (when the gate is re-enabled)
//!
//! Per §5.8 final paragraph the CI threshold check is **informational
//! at this phase** (the bench output is recorded but does not fail
//! the workflow). The intended absolute-threshold gate (once the
//! R0-D12 reconciliation re-baselines the budget) is enforced by
//! the PR author running `cargo bench -p shekyl-pow-randomx --bench
//! cache_derive` locally before opening the PR, comparing the median
//! against the re-baselined budget, and either landing the result in
//! `BENCH_RESULTS.md` (if green) or surfacing the regression to the
//! reviewer (if red). At Phase 2c the second branch is the default
//! (the planned 200 ms budget is not met on the reference machine);
//! `BENCH_RESULTS.md` records the gap and the disposition.
//!
//! # Why this isn't a `#[test]`
//!
//! The natural alternative would be to put the threshold check in
//! `src/cache.rs#mod tests` so `cargo test` enforces it. Two
//! disqualifiers per §5.8 framing apply regardless of the eventual
//! re-baselined budget value:
//!
//! 1. **Wall-clock determinism.** Tests are expected to be
//!    deterministic across CI runner classes. A wall-clock threshold
//!    on a busy runner can flake from background-process contention,
//!    invalidating the test on substrate (runner load) rather than
//!    on code substance. Benches accept this noise because their
//!    job is measurement, not validation.
//! 2. **Sample-size economics.** 100 iterations × ~341 ms (current
//!    measured baseline) ≈ 34 s per `cargo test` invocation per
//!    test, which would dominate the debug-mode test runtime.
//!    Benches naturally accept that cost because the developer
//!    opts into them.
//!
//! The disposition therefore matches §5.8's framing: enforcement
//! (when re-enabled post-R0-D12 reconciliation) is the developer's
//! responsibility pre-PR; the bench is the measurement instrument;
//! `BENCH_RESULTS.md` is the recorded baseline; and the reviewer's
//! job is to confirm the recorded numbers fit the *currently-applicable*
//! budget (informational at Phase 2c).

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_pow_randomx::{PreparedCache, Seedhash};

/// 32-byte canonical bench seedhash bytes. Distinct from the
/// spec-vector tests' `CANONICAL_SEEDHASH_BYTES` (sequential
/// `0x01..=0x20`) to keep benches and tests from accidentally
/// sharing reference state; the specific bytes are irrelevant to
/// the measurement (Argon2d cost is input-independent at fixed
/// parameters), so a stable ASCII label works as well as any
/// other byte string.
const BENCH_SEEDHASH_BYTES: [u8; 32] = *b"shekyl-randomx-v2-bench-Cache-00";

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
            let prepared =
                PreparedCache::derive(black_box(Seedhash::from_bytes(BENCH_SEEDHASH_BYTES)));
            // Force the result to be observable so the optimizer
            // cannot elide the derivation. `black_box` on the
            // resulting `PreparedCache` participates in the
            // per-iteration measurement boundary.
            black_box(prepared)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cache_derive);
criterion_main!(benches);

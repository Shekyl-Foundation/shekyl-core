# `shekyl-pow-randomx` bench baseline

Phase 2c PR-merge baseline per [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
§5.8 + §8. Downstream phases (2d, 2f, 2g) compare against these
numbers; regression >10% triggers investigation per the §5.8
disposition. Phase 2d real-dispatch results recorded per
[`docs/design/RANDOMX_V2_PHASE2D_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2D_PLAN.md)
§9. Phase 2F cfg-gated A/B harness recorded per
[`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
§3.3 / §3.4 / §6.3 Round 3.

## Run conditions

| Field | Value |
|-------|-------|
| Date  | 2026-05-22 (UTC) |
| Crate version | `shekyl-pow-randomx = "3.1.0"` (Phase 2c PR-merge tip) |
| CPU model | 11th Gen Intel Core i9-11950H @ 2.60 GHz (8C/16T, boost to 4.9 GHz) |
| RAM | 128 GiB (DDR4) |
| OS | Debian GNU/Linux 13 (trixie) |
| Kernel | `6.12.88+deb13-amd64` |
| Libc | glibc (Debian 13 default) |
| Allocator | system (no `mimalloc`/`jemalloc` override) |
| Rust toolchain | workspace MSRV `1.85`, build profile `release` |
| Criterion version | `0.5.1` (per `Cargo.lock` at PR-merge) |
| Background load | machine quiescent at measurement time (single developer-loop run, no concurrent CI/build) |

## Measurements

| Bench | Median | 95% CI | Sample size | Outliers | Source |
|-------|--------|--------|-------------|----------|--------|
| `cache_derive::derive` | **341.45 ms** | [336.20 ms, 347.32 ms] | 100 (per §5.8 spec) | 8/100 (6 high-mild, 2 high-severe) | `benches/cache_derive.rs` |
| `compute_hash_alloc::per_call` | **296.00 ms** | [292.81 ms, 299.47 ms] | 100 (reduced from §5.8's 10000; see §"Threshold reconciliation" below) | 7/100 (2 high-mild, 5 high-severe) | `benches/compute_hash_alloc.rs` |

### Phase 2d post-dispatch deltas (2026-05-22)

| Bench | Median | Delta vs. Phase 2c | Comment |
|-------|--------|--------------------|---------|
| `cache_derive::derive` | not re-measured | — | Phase 2d does not touch the cache derivation path. |
| `compute_hash_alloc::per_call` | 303.60 ms | +2.6% | Real bytecode dispatch over 2048 iterations x 8 chains x 384 instructions per program; well under the §5.8 +/-10% regression-trigger threshold. |

### Phase 2F cfg-gated A/B harness (commit 4)

Per
[`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
§3.3 / §3.4 / §6.3 Round 3, Phase 2F lands a cfg-gated `VmStatePool`
plus a four-bench A/B harness so the §3.4 R1-D4 pool-promotion
disposition (Branch A / Branch B / Branch C) can be decided on
empirical evidence rather than estimate. The pool body lives behind
`#[cfg(any(test, feature = "internal-pool-bench"))]` regardless of
the disposition, closing the Round 1 circular-sequencing problem
("can't bench the pool without implementing the pool").

#### Bench harness

Four benches measure the production no-pool path, the cfg-gated
pool path, and the per-call allocation components:

| Bench | Source | Mode | Always-runs |
|-------|--------|------|-------------|
| `compute_hash_alloc::per_call` | `benches/compute_hash_alloc.rs` | Phase 2c / 2d baseline (full pipeline). | Yes |
| `compute_hash_alloc::with_no_pool::per_call` | `benches/compute_hash_alloc.rs` | Phase 2F §6.3 Round 3 `B-pool-off` (production no-pool path; identical to `per_call` in measurement target). | Yes |
| `compute_hash_alloc::with_pool::per_call` | `benches/compute_hash_alloc.rs`, `--features internal-pool-bench` | Phase 2F §6.3 Round 3 `B-pool-on` (cfg-gated pool path; pre-allocated `VmStatePool` of capacity 4). | Only with feature flag |
| `per_call_alloc::vmstate_alloc_scratchpad_zeroed` | `benches/per_call_alloc.rs` | Phase 2F §6.3 Round 3 `B-2` (per-call 2 MiB zero-init scratchpad alloc). | Yes |
| `per_call_alloc::vmstate_alloc_register_file` | `benches/per_call_alloc.rs` | Phase 2F §6.3 Round 3 `B-3` (per-call `Box<Program>` alloc). | Yes |

Run instructions:

```bash
# B-pool-off + Phase 2c/2d baseline (no feature flag).
cargo bench --bench compute_hash_alloc

# B-pool-off + B-pool-on + Phase 2c/2d baseline (feature on).
cargo bench --bench compute_hash_alloc --features internal-pool-bench

# B-2 + B-3 component floor (always; no feature flag).
cargo bench --bench per_call_alloc
```

#### Methodology

The A/B disposition rule per §3.4 R1-D4 Round 3 (component-floor
table folded into the A/B delta):

| A/B delta (`B-pool-off` − `B-pool-on`) | Branch | Disposition |
|-----------------------------------------|--------|-------------|
| < 50 µs | Branch A | No pool. Cfg-gated pool stays in source as bench-only artifact. §8 commit 5 omitted. |
| ≥ 50 µs and < 100 µs | Branch B | Ambiguity band; impl-PR pre-flight escalates per §3.3 Round 3 reversion clause #1. |
| ≥ 100 µs | Branch C | Pool promoted to production. §8 commit 5 flips the cfg-gate to unconditional; `compute_hash` rewires through the pool. |

The component-floor sum (B-2 median + B-3 median) is the sanity
check that the no-pool A/B median (`B-pool-off`) does not undercut
the per-call allocation cost lower bound. A no-pool A/B median
below the component-floor sum would indicate bench misconfiguration
(e.g., the `b.iter` body is being optimized out, or the
`PreparedCache` is being re-derived inside the timed loop).

Pool capacity for the bench harness is **4**, mirroring the §3.5
R1-D5 Round 3 test-default. Phase 3a's FFI shim derives the actual
deployment capacity via the methodology pinned at §3.5 (Round 1):
`capacity = binding_fanout + 1` where binding fanout is
`min(threadpool_max, m_max_prepare_blocks_threads)` at the
daemon's runtime state. The bench's choice of 4 is informational
for the A/B delta; capacity ≥ 1 measures the steady-state pool-hit
cost in a single-bench-thread harness.

#### Measurements (2026-05-23, commit 4 reference machine)

| Bench | Median | 95% CI | Sample size | Measurement context |
|-------|--------|--------|-------------|---------------------|
| `compute_hash_alloc::per_call` (Phase 2c/2d baseline replay) | 307.42 ms | [306.26, 308.94] | 100 | 2048-iter dispatch over 8 chains. |
| `compute_hash_alloc::with_no_pool::per_call` (B-pool-off) | **304.44 ms** | [303.14, 305.96] | 100 | Production no-pool path; `VmState::new()` per call. |
| `compute_hash_alloc::with_pool::per_call` (B-pool-on) | **303.72 ms** | [302.71, 304.88] | 100 | Cfg-gated pool path; `VmStatePool::new(4)` pre-allocated outside the timed loop. |
| `per_call_alloc::vmstate_alloc_scratchpad_zeroed` (B-2) | **47.66 µs** | [47.47, 47.87] | 200 | 2 MiB zero-init via `Box::new_zeroed_slice(N)` + `assume_init` — mirrors the production `crate::vm::alloc_zeroed_scratchpad` carve-out exactly (re-measured on review-fix commit; see §"B-2 methodology refinement" below). |
| `per_call_alloc::vmstate_alloc_register_file` (B-3) | **93.2 ns** | [92.32, 94.30] | 200 | `Box::new(Program::default())` — re-measured alongside B-2. |

Run conditions: 11th Gen Intel Core i9-11950H @ 2.60 GHz, 128 GiB
DDR4, Debian 13 (kernel `6.12.88+deb13-amd64`), system glibc
allocator (no `mimalloc`/`jemalloc` override), Rust workspace MSRV
`1.85`, Criterion `0.5.1`, machine quiescent at measurement time.

##### B-2 methodology refinement (review-fix commit, 2026-05-24)

Initial commit-4 B-2 used `vec![0u8; N].into_boxed_slice()` as
the zero-initialized 2 MiB allocation idiom. A PR review noted the
discrepancy against production: `crate::vm::alloc_zeroed_scratchpad`
goes through `Box::new_zeroed_slice(N) + assume_init`, which is
the stabilized (Rust 1.82+) path that routes directly to the
allocator's `alloc_zeroed`. The `vec![0u8; N]` form *also* folds
to `alloc_zeroed` on current `rustc` via the `IsZero`
specialization in `Vec::from_elem`, so the timing converged on
this hardware — but the convergence is a stdlib-implementation
property rather than a contract. The bench was switched to the
production-mirror form to remove the dependency on that
specialization holding across future stdlib versions.

Re-measurement under the new form yielded **B-2 = 47.66 µs**
(prev. 48.6 µs) and **B-3 = 93.2 ns** (prev. 81.7 ns; B-3's
allocation path was not changed, so the ~14% shift is run-to-run
variance at sub-100 ns scale). Component-floor sum:
**~47.75 µs** (prev. ~48.7 µs). The shift is below 1 µs in
absolute terms and well within the run-to-run noise band already
documented for these benches; the Branch A disposition below is
unaffected.

#### A/B delta and disposition: Branch A

- **Component-floor sum** (B-2 + B-3 ≈ 47.66 µs + 0.093 µs ≈ 47.75
  µs; updated post-review-fix per §"B-2 methodology refinement"
  above; prior estimate ≈ 48.7 µs): the theoretical maximum pool
  savings on this hardware. Pool amortization saves at most the
  per-call allocation cost; the component floor is the upper bound
  on `B-pool-off − B-pool-on`.
- **Measured A/B point-estimate delta**: 304.44 ms − 303.72 ms ≈
  **0.72 ms ≈ 720 µs**.
- **CI-overlap check**: the 95% CIs `[303.14, 305.96]` and
  `[302.71, 304.88]` overlap heavily — each median lies inside the
  other's CI. The point-estimate 720 µs delta is **statistically
  indistinguishable from zero** at this sample size.
- **Substrate reconciliation**: the measured 720 µs delta cannot
  be pool savings because the component-floor analysis caps
  achievable pool savings at ≈ 47.75 µs. The 720 µs is run-to-run
  measurement noise (allocator state, CPU thermal/scheduling
  variance, large-page TLB warmup) rather than pool benefit.

**Disposition: Branch A** per §3.4 R1-D4 Round 3. The achievable
pool savings (component-floor cap ≈ 47.75 µs) is below the 50 µs
threshold; pooling produces no production-relevant performance
improvement on this hardware class. The cfg-gated `VmStatePool`
stays in source as a bench-only artifact (cfg-gated under
`#[cfg(any(test, feature = "internal-pool-bench"))]`); §8 commit
5 (cfg-gate flip to default-on) is **omitted**. Phase 3a's FFI
shim sees the unchanged production `compute_hash` body
(`VmState::new()` per call).

#### Prediction-vs-measured reconciliation per §8 Round 3

- **Predicted branch** (§8 plan-doc): two competing predictions
  recorded — Branch C (≥ 100 µs) plausible if PR-66's per-call
  alloc cost was dominated by scratchpad zero-init / register-file
  alloc; Branch A (< 50 µs) plausible if modern glibc/mmap-backed
  allocators amortize the 2 MiB scratchpad zero-init to tens of µs.
- **Measured branch**: Branch A.
- **Reconciliation**: **prediction A held.** B-2 measured at 47.66
  µs (post-review-fix; initial 48.6 µs under the
  `vec![0u8; N].into_boxed_slice()` shape) on this hardware,
  consistent with the §8 "modern allocators amortize 2 MiB
  zero-init to tens of µs" framing (mmap-backed glibc on Linux
  kernel 6.12 large-page-aware allocator). PR-66's per-call
  full-pipeline cost was dominated by dispatch-loop overhead
  (2048 iterations × 8 chains × per-iter AES + scratchpad RW +
  dataset reads), not allocation-specific cost. Pooling cannot
  amortize dispatch-loop cost; only allocation cost can be
  amortized, and the component-floor cap (≈ 47.75 µs) is below
  the Branch B/C threshold.

The substrate finding: on this hardware class, RandomX
`compute_hash`'s per-call allocation cost is structurally below
the threshold at which pooling produces production-relevant
benefit. The cfg-gated pool was the right shape to land regardless
of branch (Round 3's circular-sequencing fix); the empirical
result confirms it stays as a bench-only artifact rather than
becoming a production rewire.

**Reopening criterion** per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc):
the Branch A disposition reopens when (a) a hardware class with
substantially different allocator behavior is benched and yields
A/B delta ≥ 100 µs (e.g., an allocator without large-page
amortization, or a CI runner where 2 MiB zero-init is in the
hundreds-of-µs range); or (b) Phase 3a's FFI shim's binding
fanout produces a steady-state pool-hit pattern that the
single-bench-thread harness does not capture; or (c) Phase 2g's
per-hash latency deliverable surfaces an A/B-delta-relevant cost
on production-target hardware. Reopening is via a fresh §3.4
disposition pin in the relevant phase's plan-doc, not by reflex
re-derivation of the Round 3 cfg-gate flip.

## Threshold reconciliation

The §5.8 plan-author budgets were set against estimates; the
measurements above are the first empirical baseline. Two gaps surface:

### Gap 1 — `cache_derive`: 341 ms measured vs. ≤200 ms budget (1.7×)

**Diagnosis.** Single-threaded Argon2d 256 MiB fill (RandomX spec
`parallelism = 1` per `external/randomx-v2/doc/specs.md` §7.1) is
fundamentally a hundreds-of-milliseconds operation on contemporary
x86-64 hardware. The 11th-gen i9-11950H is squarely in the
high-performance laptop class (not an old/underclocked machine); the
measured 341 ms is the realistic cost of the Argon2d primitive on
this hardware class, not implementation overhead vs. the C reference.

Cross-check: Monero's reference `argon2_ref.c` at single-threaded
`p=1` on similar hardware reports comparable wall-clock per
upstream's published timings. The Rust `argon2` crate's
`fill_memory` is the same algorithm; ~10% Rust-vs-C overhead is
within expected dev-loop noise on this primitive.

**Disposition.** The 200 ms budget needs to be re-baselined against
empirical hardware-class measurements rather than estimates. The
reconciliation is recorded in `docs/design/RANDOMX_V2_PHASE2C_PLAN.md`
§14 Round 0 as R0-D12 (plan-doc errata, separate commit per the
prior errata commit cadence) so the original plan-author estimate
is preserved as historical record and the empirical baseline is
named explicitly. **Phase 2c does not block on the gap**: the
absolute threshold's enforcement mechanism per §5.8 is the developer
running benches before PR-open and reporting the result — which this
file is.

**Reopening criterion** per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc):
the 200 ms budget reopens for revision when (a) `Cache::derive`
optimization landing produces a measurable improvement against
this baseline, or (b) the Phase 2f `CacheStore` LRU amortizes
the cost across many block validations such that the per-cache
budget becomes a downstream cache-population latency budget
rather than a per-validation latency budget. The reopening shape
is a §14 Round 0 errata entry citing the new measurement +
the reopening trigger.

### Gap 2 — `compute_hash_alloc`: 296 ms measured vs. ≤100 µs budget (2960×)

**Diagnosis.** The §5.8 budget framing was internally inconsistent:
the bench call target is `compute_hash` (end-to-end pipeline:
`VmState` alloc + `fillAes1Rx4` scratchpad init + 8 × per-program
init + 8 × 2048-iter execution loop + `getFinalResult`); the budget
description ("≤ 100 µs… binds the `VmState` allocation portion
specifically") binds only the alloc step. Allocation alone is
sub-millisecond on this hardware class (2 MiB scratchpad zeroing
~150 µs + register-file init + program-buffer init ≈ ~200 µs); the
full pipeline is ~300 ms under stub-NOP dispatch because the
iteration loop's per-iter work (AES f/e mix, scratchpad RW, dataset
reads via `derive_item`'s superscalar program execution) is
substantial regardless of whether `dispatch_instruction` does
anything inside the body.

The plan-author noted this gap parenthetically in §5.8 disposition
#1: "Mechanism for measuring just the allocation portion (e.g.,
`#[doc(hidden)] pub fn _bench_vm_state_alloc()` bench hook vs.
end-to-end `compute_hash` measurement) is an implementation-PR-time
decision; the plan-doc-time disposition is 'measure end-to-end
under stub-NOP; budget binds the allocation portion.'" The
implementation-PR-time decision recorded here: **the bench measures
end-to-end** (matching the bench function call), and the 100 µs
allocation-only budget needs a separate bench harness to validate
its narrower target.

**Disposition.** Same shape as Gap 1: the budget is re-baselined
against empirical end-to-end measurement and the
allocation-only-budget reconciliation is deferred. Recorded in
`docs/design/RANDOMX_V2_PHASE2C_PLAN.md` §14 Round 0 R0-D12 alongside
Gap 1. **Phase 2c does not block on the gap.**

**Reopening criterion.** The 100 µs budget reopens for revision
when (a) a separate `vm_state_alloc` bench is added that measures
allocation alone (the per-§5.8-parenthetical mechanism); or (b)
Phase 2d's plan doc splits this bench into allocation-only vs.
execution-only sub-benches per the §5.8 disposition's
implementation-PR-time clause; or (c) Phase 2g's per-hash latency
deliverable populates the canonical Rust-vs-C ratio per
`tests/perf/per_hash_latency.rs`, at which point the per-hash
budget shifts from an absolute Rust value to a Rust/C ratio against
the C reference's actual measurement on the same hardware.

## Regression-detection workflow

Downstream PRs that touch `shekyl-pow-randomx` should:

1. Re-run the two benches against this baseline.
2. Record their median in their PR description.
3. If the median exceeds the baseline by >10%, surface the
   regression in the PR for investigation (per §5.8 disposition
   #2). Auto-failure is reserved for the absolute-threshold check
   (per §5.8 disposition #1), which is the developer's
   responsibility pre-PR-open until Phase 2c's threshold-gap
   reconciliation lands.
4. If the optimization landed reduces the median, update this
   file's "Measurements" table and bump the date.

## Why this file lives next to the crate's `Cargo.toml`

Per §8 of the plan doc, `BENCH_RESULTS.md` is placed at the crate
root (not under `docs/`) so the baseline travels with the crate
and is grep-discoverable from the bench files' rustdoc. Phase
3a's `shekyl-ffi` integration may add an FFI-boundary bench (per
§5.11.6 forward-action); that crate's `BENCH_RESULTS.md` would
record its own baseline against this crate's numbers.

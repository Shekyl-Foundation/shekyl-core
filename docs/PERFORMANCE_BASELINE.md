# Performance baseline

This document holds the per-bench frozen performance baselines for
the Stage 1 trait-boundaries migration
([`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3 *interior-mutability measurement gate*).

The §3.3 gate is **binding before Stage 1 PRs land**: each Stage 1
PR's description cites the cumulative delta of each in-scope bench
against that bench's frozen baseline recorded in this document.
Reviewers cite this document during PR review per §3.3.1's
threshold-of-concern discipline (>10% requires PR-description
justification; >25% requires optimization before merge).

## Per-bench frozen-baseline framing

Per [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md)
§4.5 (per-bench frozen-baseline disposition):

- **Each bench has its own frozen-baseline SHA**, captured at the
  merge SHA of the PR that introduces the bench.
- **Frozen baselines are not re-measured** during Stage 1.
  Cumulative-delta computations diff against the frozen number;
  the frozen number does not move.
- **Per-bench cumulative deltas are independent.** The §3.3.1
  threshold-of-concern check (10% warn / 25% fail) applies
  per-bench, not summed across benches.
- **Two delta signals coexist.** The CI-gate delta against the
  rolling `bench-baseline/baseline.json` is a per-PR enforcement
  signal (what the workflow asserts). The frozen-baseline
  cumulative delta in this document is the §3.3.1
  cumulative-delta signal (what reviewers cite). Both are
  necessary; they answer different questions.

## Measurement gate vs informational metric

Per [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md)
§4.4 (two-anchor static check):

- **Gate metric: `iai-callgrind` instructions.** Hardware-independent
  (Valgrind's VEX IR), deterministic across runners (±0% variance
  on the reference runner). The §3.3.1 threshold-of-concern
  thresholds (10% warn / 25% fail) apply to this metric.
- **Informational metric: `criterion` median_ns.** Hardware-dependent
  (wall-clock on the runner), with workload-class qualification per
  §4.2's hoisting rule. Recorded for context but does not gate.
- **Hardware-dependent iai metrics** (`l1_hits`, `ll_hits`, `ram_hits`,
  `total_read_write`, `estimated_cycles`) are recorded for completeness
  but are not portable across runner hardware. Future per-trait PR
  captures may report different cache/cycle numbers without that
  being a regression — only the `instructions` count gates.

The hoisting rule applies asymmetrically by workload class:

- **Trivial pure-read** (e.g., `synced_height`): criterion's
  per-iteration time can be reduced below per-call cost by optimizer
  amortization across the `b.iter` loop. The criterion `median_ns`
  reflects the optimizer's success at amortizing the call across
  iterations, not per-call cost. iai-callgrind is immune (Valgrind
  cannot legally amortize across iterations).
- **State-dependent compute** (e.g., `balance` over N transfers):
  criterion's per-iteration time approximates per-call cost.
  Optimizer amortization does not apply meaningfully because each
  iteration measures meaningful work.

Each bench section records its workload-class assignment explicitly
(per §4.4's per-trait PR description checklist item 5).

## Scope of this document and forward-references

This document operationalizes the §3.3.1 single-threaded
instruction-count gate, which defends against per-call latency
regressions on hot-path engine trait methods. The broader
threat-model framing for the §3.3 measurement-gate apparatus —
naming the failure modes the gate apparatus collectively
defends, and motivating which anchors defend which modes — is
deferred to a subsequent preparatory PR (Stage 0 PR-D)
alongside the third-anchor (concurrent-throughput) bench
design. Concurrent-load benches and loom-style concurrency
correctness tests are not part of this document; they land in
Stage 0 PR-D and PR-D2 respectively, before Stage 1 PR 2
(LedgerEngine, the first substantive interior-mutability
surface). Until those PRs land, the discipline this document
encodes addresses one class of risk (per-call latency
regression); the broader risk surface is acknowledged here
only to make the scope boundary explicit.

## Hot paths under measurement

Per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3.1, the minimum hot paths:

| Trait | Method | Bench name | Frozen at |
|---|---|---|---|
| `LedgerEngine` | `synced_height` | `engine_trait_bench_ledger_synced_height` | Stage 0 PR-2 |
| `LedgerEngine` | `balance` | `engine_trait_bench_ledger_balance` | Stage 1 PR 2 |
| `EconomicsEngine` | `current_emission` | `engine_trait_bench_economics_current_emission` | Deferred to EconomicsEngine PR |
| `EconomicsEngine` | `parameters_snapshot` | `engine_trait_bench_economics_parameters_snapshot` | Deferred to EconomicsEngine PR |
| `KeyEngine` | `account_public_address` | `engine_trait_bench_key_account_public_address` | Deferred to KeyEngine PR |

Reviewers may identify additional hot paths during Stage 1 PR
review; new benches enter the harness per §4.6's harness-update
discipline.

## Bench: `engine_trait_bench_ledger_synced_height`

**Status:** Frozen at Stage 0 PR-2.

**Frozen-baseline source.**

| Field | Value |
|---|---|
| Introducing PR | Stage 0 PR-2 (`shekyl-engine-core` engine-trait benchmark harness) |
| Frozen at | `0276d210e7705a5d691e2d85bb9ad5fa340dd633` (PR-2 commit 4c, post-Q `Box<Engine<S>>` fixture; GHA run `25239954863`) |
| Date | 2026-05-02 |

**Workload class:** Trivial pure-read.

The bench measures `Engine::synced_height()` — a deref-chain field
read of a `u64` through the `LedgerState` chain — over a freshly
constructed `Engine<SoloSigner>` fixture. The call body is a
short field-access chain with no state-dependent compute; the
optimizer can hoist the call across criterion's iteration loop
(per §4.2 hoisting rule).

**iai-callgrind gate metric.**

| Metric | Value |
|---|---|
| `instructions` | `10` |

The §3.3.1 threshold-of-concern check (10% warn / 25% fail) applies
to this row only. The instruction count is portable across runner
hardware (Valgrind's VEX IR is hardware-independent) but **not**
portable across toolchain versions; see [Toolchain-bump
policy](#toolchain-bump-policy) for what happens when rustc /
valgrind / iai-callgrind-runner versions change during Stage 1.

**iai-callgrind hardware-dependent metrics (informational).**

These rows are recorded for completeness from the same capture but
do not gate. Different runner hardware reports different numbers;
the gate-metric `instructions` row above is the only iai value
that should be compared across captures or against the threshold.

| Metric | Value |
|---|---|
| `l1_hits` | `16` |
| `ll_hits` | `0` |
| `ram_hits` | `2` |
| `total_read_write` | `18` |
| `estimated_cycles` | `86` |

**criterion metrics (informational).**

| Metric | Value |
|---|---|
| `median_ns` | `0.6221` |
| `std_dev_ns` | `0.005864` |

*criterion median_ns reflects optimizer amortization (per §4.4
hoisting rule); per-call cost approximation: see iai instructions
× hardware-dependent ns-per-instruction. The criterion number does
not directly compare to iai's per-call cost for this workload class.*

**Capture environment:** see `env-0276d210` in
[Capture environments](#capture-environments).

**Cumulative-delta table.**

| PR | SHA | iai instructions | criterion median_ns | Δ vs frozen (iai) | Δ vs frozen (criterion) |
|---|---|---|---|---|---|
| Stage 0 PR-2 | `0276d210e` | `10` | `0.6221` | baseline | baseline |
| Stage 1 PR 1 | `6c6ecbd67` | `10` | `0.6224` | `0%` (no change) | `+0.05%` |
| Stage 1 PR 2 | `8efae3a40` | `49` | `5.5117` | `+390%` | `+786%` |

Stage 1 PR 2 (`LedgerEngine` extraction; `Engine<S, D, L: LedgerEngine
= LocalLedger>` parameterization with `LocalLedger` wrapping
`RwLock<LedgerState>` for interior mutability per §2.2) was N=3
invariance-verified per
[`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md) §4.4
dynamic check: GHA `workflow_dispatch` runs `25307774464`,
`25307777614`, and `25307781436` against PR-tip `8efae3a40` produced
byte-identical iai-callgrind output for `synced_height`
(`instructions=49`, `l1_hits=72`, `ll_hits=1`, `ram_hits=5`,
`total_read_write=78`, `estimated_cycles=252` — same across all three
runs to the digit). Toolchain matched env-`0276d210` row-for-row
(rustc 1.95.0 / valgrind 3.22.0 / iai-callgrind-runner v0.16.1), so
no new capture-environment block was added. CPU varied across the
three runs (runs `25307774464` and `25307777614` on AMD EPYC 7763,
matching the frozen baseline's CPU model; run `25307781436` on Intel
Xeon Platinum 8370C @ 2.80GHz) with no observed effect on the iai
gate metric — confirming Valgrind's hardware-independent VEX IR
once again. The criterion `median_ns` value cited above is from run
`25307774464` (matching-CPU; most directly comparable to the frozen
baseline); run `25307777614` measured `5.5123` (essentially identical)
and run `25307781436` measured `16.7389` (a 3x outlier on the
different CPU). The 3x criterion spread on the matching/non-matching
CPU pair is consistent with the §4.4 hoisting-rule caveat for
trivial pure-read workloads where criterion's number reflects
optimizer amortization rather than per-call cost.

The cumulative `Δ vs frozen (iai)` is `+390%`, exceeding the §3.3.1
25% fail threshold. **Disposition: §3.3.1 case (a) — intrinsic to
Stage 1's interior-mutability shape and will disappear at Stage 4.**
The +39-instruction delta is the `RwLock::read()` lock acquisition
introduced by `LocalLedger`'s interior-mutability shape. After PR 2,
the `synced_height` call path is `engine.synced_height()` →
`engine.ledger.synced_height()` → `<LocalLedger as
LedgerEngine>::synced_height()` → `LocalLedger::read()` →
`RwLock::read().expect(...)` → `WalletLedger.ledger.height()`. The
`RwLock::read()` uncontended fast path costs ~39 instructions
(loaded-acquire CAS on the lock state, guard construction, drop on
return); the original deref-chain field read is preserved underneath
at its prior 10-instruction cost. The §2.2 Round-3 disposition
adopted interior mutability deliberately — the producer task in
`run_refresh_task` relaxes from outer write-lock to read-lock per
§3.3, and the `apply_scan_result` async mutation runs against `&self`
without serializing readers, both of which are wins that pay for
the per-read lock cost under contention. Stage 4's Path B retires
the outer `RwLock<LedgerState>` in favor of `Arc`-published snapshots
for read paths (committed at the per-PR cost reviewed during the
trait-promotion PR per `V3_ENGINE_TRAIT_BOUNDARIES.md` §3.3.5),
returning `synced_height` to its 10-instruction deref-chain cost.
The +786% criterion `Δ vs frozen` is informational only and does not
gate per the §3.3.1 closing paragraph; the gate is the iai
instructions column.

Stage 1 PR 1 (`DaemonEngine` extraction; `Engine<S, D: DaemonEngine
= DaemonClient>` parameterization) was N=3 invariance-verified per
[`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md) §4.4
dynamic check: GHA `workflow_dispatch` runs `25256332992`,
`25256334848`, and `25256336611` against PR-tip `6c6ecbd67`
produced byte-identical iai-callgrind output for `synced_height`
(`instructions=10`, `l1_hits=16`, `ll_hits=0`, `ram_hits=2`,
`total_read_write=18`, `estimated_cycles=86` — matching env-`0276d210`
exactly). Toolchain matched env-`0276d210` row-for-row (rustc
1.95.0 / valgrind 3.22.0 / iai-callgrind-runner v0.16.1), so no
new capture-environment block was added. CPU varied across the
three runs (runs `25256332992` and `25256336611` on AMD EPYC 9V74;
run `25256334848` on AMD EPYC 7763, matching the frozen
baseline's CPU model) with no observed effect on the iai gate
metric — confirming Valgrind's hardware-independent VEX IR. The
criterion `median_ns` value cited above is from run `25256334848`
(same CPU as frozen baseline, so most directly comparable); the
two EPYC-9V74 runs measured `0.5453` and `0.7030` respectively,
a 30% spread that is consistent with the §4.4 hoisting-rule
caveat for trivial pure-read workloads where criterion's number
reflects optimizer amortization rather than per-call cost. The
cumulative `Δ vs frozen (iai)` is `0%`, well within the §3.3.1
10% warn threshold; the trait extraction monomorphizes the
`D: DaemonEngine` type parameter away on the `synced_height`
call path as expected.

Subsequent Stage 1 PRs append one row per merge, computed against
the frozen-baseline row. The §3.3.1 threshold-of-concern check
applies to the running `Δ vs frozen (iai)` column.

## Bench: `engine_trait_bench_ledger_balance`

**Status:** Frozen at Stage 1 PR 2.

**Frozen-baseline source.**

| Field | Value |
|---|---|
| Introducing PR | Stage 1 PR 2 (`LedgerEngine` trait extraction; `Engine<S, D, L: LedgerEngine = LocalLedger>` parameterization) |
| Frozen at | `8efae3a402b7a872ab5044ec4f69d2190fa34940` (PR-tip post-bench-row append; GHA runs `25307774464`, `25307777614`, `25307781436`) |
| Date | 2026-05-04 |

**Workload class:** State-dependent compute.

Per §4.6's per-bench deferred assignment, this bench is introduced
alongside the `LedgerEngine::balance` trait method's first measurable
surface on a state-populated fixture. The bench fixture builds the
engine through the production `Engine::create` lifecycle — the same
path `engine_trait_bench_ledger_synced_height`'s fixture uses
(`benches/common/engine_fixture.rs::build_engine_fixture`) — and then
injects 1024 `TransferDetails` entries into the engine's
`WalletLedger` directly via the `bench-internals`-gated
`LocalLedger::populate_for_bench` helper. The measured region
exercises `LedgerEngine::balance` (trait dispatch on
`engine.ledger.balance()`, post-commit-5 production call shape)
against the pre-populated state without running a full
producer/scanner ceremony. The per-iteration body walks the transfer
slice via `BalanceSummary::compute` and is non-hoistable, so
criterion's `median_ns` approximates per-call cost rather than
amortized cost (in contrast to `synced_height`'s trivial-pure-read
hoisting behavior).

**iai-callgrind gate metric.**

| Metric | Value |
|---|---|
| `instructions` | `20580` |

The §3.3.1 threshold-of-concern check (10% warn / 25% fail) applies
to this row only. The instruction count is portable across runner
hardware (Valgrind's VEX IR is hardware-independent) but **not**
portable across toolchain versions; see [Toolchain-bump
policy](#toolchain-bump-policy) for what happens when rustc /
valgrind / iai-callgrind-runner versions change during Stage 1.

**iai-callgrind hardware-dependent metrics (informational).**

These rows are recorded for completeness from the same capture but
do not gate. Different runner hardware reports different numbers;
the gate-metric `instructions` row above is the only iai value
that should be compared across captures or against the threshold.

| Metric | Value |
|---|---|
| `l1_hits` | `22408` |
| `ll_hits` | `3342` |
| `ram_hits` | `11` |
| `total_read_write` | `25761` |
| `estimated_cycles` | `39503` |

**criterion metrics (informational).**

| Metric | Value |
|---|---|
| `median_ns` | `2394.6` |
| `std_dev_ns` | `38.06` |

*criterion median_ns approximates per-call cost for this state-
dependent compute workload (the `BalanceSummary::compute` walk over
1024 transfers is non-hoistable). Per-call cost ratio to iai
instructions: `2394.6 ns / 20580 instr ≈ 0.116 ns/instr`, consistent
with a ~2.8 GHz host running ~1 IPC on a memory-walking workload —
no over-amortization signal.*

**Capture environment:** see `env-0276d210` in
[Capture environments](#capture-environments). Toolchain matches
env-`0276d210` row-for-row (rustc 1.95.0 / valgrind 3.22.0 /
iai-callgrind-runner v0.16.1, kernel `Linux 6.17.0-1010-azure`); no
new env block is added per the deduplication discipline. CPU varied
across the N=3 runs (runs `25307774464` and `25307777614` on AMD
EPYC 7763, matching env-`0276d210`; run `25307781436` on Intel Xeon
Platinum 8370C @ 2.80GHz) with no observed effect on the iai gate
metric.

**Cumulative-delta table.**

| PR | SHA | iai instructions | criterion median_ns | Δ vs frozen (iai) | Δ vs frozen (criterion) |
|---|---|---|---|---|---|
| Stage 1 PR 2 | `8efae3a40` | `20580` | `2394.6` | baseline | baseline |

Stage 1 PR 2 freezes this bench's baseline; subsequent Stage 1 PRs
append one row per merge, computed against the frozen-baseline row.
The §3.3.1 threshold-of-concern check applies to the running `Δ vs
frozen (iai)` column. N=3 invariance: all three runs produced
byte-identical iai-callgrind output for this bench
(`instructions=20580`, `l1_hits=22408`, `ll_hits=3342`,
`ram_hits=11`, `total_read_write=25761`, `estimated_cycles=39503`).
criterion `median_ns` for the table row is from run `25307774464`
(matching-CPU); the matching-CPU pair (`25307774464` / `25307777614`)
measured `2394.6` and `2418.3` ns respectively (a ~1% spread); run
`25307781436` on the Intel Xeon measured `1949.1` ns (a 19% lower
median, consistent with the different CPU's per-instruction cost
profile on a memory-walking workload). The state-populated workload
is markedly more stable than `synced_height`'s trivial pure-read
across CPUs because the per-call body's compute dominates the
optimizer-amortization noise floor.

## Bench: `engine_trait_bench_economics_current_emission`

**Status:** Deferred to EconomicsEngine PR.

This bench section is authored when the EconomicsEngine PR's
introducing commit lands; same template as
`engine_trait_bench_ledger_synced_height` above.

Per §4.6's per-bench deferred assignment, this bench is introduced
alongside the `EconomicsEngine::current_emission(height)` trait
method on a fixture appropriate to economics-layer state. Workload
class is determined when the bench is authored (likely
state-dependent compute given the `height` parameter dependency,
but pre-stated formally in the introducing PR's description per
§4.4's normative checklist item 5).

## Bench: `engine_trait_bench_economics_parameters_snapshot`

**Status:** Deferred to EconomicsEngine PR.

This bench section is authored when the EconomicsEngine PR's
introducing commit lands; same template as
`engine_trait_bench_ledger_synced_height` above.

Per §4.6's per-bench deferred assignment, this bench is introduced
alongside the `EconomicsEngine::parameters_snapshot()` trait method.
Expected workload class: trivial pure-read if the snapshot returns
the same value every iteration (criterion median_ns reflects
optimizer amortization); confirmed at authoring time per §4.4's
checklist item 5.

## Bench: `engine_trait_bench_key_account_public_address`

**Status:** Deferred to KeyEngine PR.

This bench section is authored when the KeyEngine PR's introducing
commit lands; same template as
`engine_trait_bench_ledger_synced_height` above.

Per §4.6's per-bench deferred assignment, this bench is introduced
alongside the `KeyEngine::account_public_address()` trait method on
a fixture appropriate to key-layer state. Expected workload class:
trivial pure-read (the address is stable across iterations);
confirmed at authoring time per §4.4's checklist item 5.

## Capture environments

Capture environments are deduplicated by introducing-PR merge SHA
(the `git_rev` field in the `shekyl_rust_v0.json` envelope's
`captured_on` block). Each environment block records the toolchain
and runner state that produced the benchmark numbers in bench
sections that cite it.

When two captures land at different SHAs but on identical runner
images (same kernel, rustc, valgrind, iai-callgrind-runner versions),
they get separate environment blocks keyed by their respective SHAs;
the toolchain rows happen to match. When a single SHA was captured
on two different runner images, the SHA-keyed block records the
canonical runner; cross-runner divergence (per §4.4's dynamic check)
is investigated rather than recorded as two parallel environments.

### `env-0276d210`

| Field | Value |
|---|---|
| `git_rev` | `0276d210e7705a5d691e2d85bb9ad5fa340dd633` |
| `git_dirty` | `clean` |
| `kernel` | `Linux 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar  6 22:00:57 UTC 2026 x86_64 GNU/Linux` |
| `cpu_model` | `AMD EPYC 7763 64-Core Processor` |
| `rustc_version` | `rustc 1.95.0 (59807616e 2026-04-14)` |
| `cargo_version` | `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` |
| `valgrind_version` | `valgrind-3.22.0` |
| `iai_callgrind_runner_version` | `v0.16.1` |

Source: GHA `ci/benchmarks` `workflow_dispatch` run `25239954863`
(`ubuntu-latest`), one of three N=3 invariance-verification captures
(runs `25239954863`, `25239956447`, `25239958016`) producing
byte-identical iai-callgrind output (±0% variance on `instructions`).
The full envelope is committed at
[`docs/benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json`](benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json).

## Threshold-of-concern disposition per §3.3.1

The §3.3.1 threshold-of-concern check applies per-bench to the
cumulative `Δ vs frozen (iai)` column.

- **Δ ≤ 10%**: cost is acceptable. No further action; PR proceeds
  to merge once other review concerns are addressed.
- **10% < Δ ≤ 25%**: cost is acceptable but requires explicit
  justification. The PR description names the source of the
  overhead (e.g., specific lock acquisition adding observed
  contention) and either argues that it's intrinsic to Stage 1's
  interior-mutability shape and will disappear at Stage 4 (when the
  outer `RwLock` retires per Path B), or names a specific Stage 1
  optimization deferred to a follow-up PR.
- **Δ > 25%**: cost is not acceptable as-is. The PR is sent back
  for optimization before merge. Candidate optimizations per
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3.5: narrowing critical sections; substituting
  `parking_lot::RwLock` for `std::sync::RwLock`; moving cached
  read-only values to `Arc`-published snapshots that bypass the
  lock entirely.

The check applies to **iai instructions**, not criterion `median_ns`.
criterion's number is informational and does not gate. For trivial
pure-read benches, criterion's median_ns may show a much larger
relative shift than iai instructions because optimizer amortization
changes non-linearly with code shape (e.g., adding a single
non-hoistable call inside a previously fully-hoisted bench can
multiply criterion's reported time without a corresponding
multiplication of iai instructions). The iai-instructions metric
remains the gate; criterion's number is consulted for context.

### Responsibility allocation across cumulative-delta breaches

The threshold-of-concern check applies to the **cumulative** `Δ vs
frozen (iai)` column, not to the per-PR delta. Two cases:

- **The PR's own per-PR delta exceeds the threshold.** The PR fails
  on its own merits: if a single PR's contribution is ≥10% the PR
  description owes the warn-tier justification; if ≥25% the PR is
  sent back for optimization. This is the standard case.
- **The PR's own per-PR delta is small but the cumulative breaches
  the threshold.** The PR is responsible for the breach regardless
  of its own contribution size. The rationale: Stage 1 has a
  per-bench cost budget, and that budget is the cumulative delta
  against the frozen baseline; the PR that breaches the budget owns
  the breach. *Worked example:* PRs 1–4 each add +9% per-PR delta;
  by PR 4 the cumulative is `(1.09)^4 − 1 ≈ +41%`, exceeding the
  fail threshold. PR 4 is sent back for optimization even though
  its own +9% looked typical against PRs 1–3, because PR 4 is the
  PR that pushed the cumulative past +25%.

The operational consequence: **authors of late-Stage-1 PRs verify
cumulative-delta headroom before measuring their own change**. If
the cumulative for a bench is at +22% and the PR's natural change
is expected to add +5%, the PR must either find +2% of optimization
elsewhere in scope, split into two PRs (with cumulative re-checked
after the first lands), or budget the work as a `parking_lot`-or-
`Arc`-snapshot optimization that brings cumulative back under
threshold before adding the trait-extraction delta. The threshold
is not a guideline that the PR author can argue around by pointing
to their own small contribution; it is a budget that the breaching
PR must close.

## Toolchain-bump policy

iai-callgrind's `instructions` count is portable across runner
*hardware* (Valgrind's VEX IR makes the measurement
hardware-independent for the measured code) but **not** portable
across *toolchain versions*. rustc codegen changes (including
LLVM-version-driven changes downstream of rustc) shift instruction
counts; valgrind/VEX-IR version changes can shift them; even a
patch-version iai-callgrind-runner bump can shift the per-call
wrapper-instrumentation overhead by a few instructions.

This means the cumulative `Δ vs frozen (iai)` column is only
meaningful when the toolchain at PR-current matches the toolchain
recorded in the bench's capture-environment block. If any of
`rustc_version`, `valgrind_version`, or `iai_callgrind_runner_version`
changes between the frozen baseline and PR-current, the cumulative
delta mixes Stage-1-attributable shifts with toolchain-attributable
shifts, and the threshold check stops measuring what §3.3.1 says it
measures.

**On toolchain bump during Stage 1, frozen baselines are
re-captured at the new toolchain.** Mechanics:

1. **Identify in-scope frozen baselines.** Every bench currently
   in `PERFORMANCE_BASELINE.md` whose status is "Frozen" (not
   "Deferred") is in scope. As of Stage 0 PR-2's merge,
   `engine_trait_bench_ledger_synced_height` is the only
   in-scope bench; later Stage 1 PRs add more.
2. **Re-capture at the introducing PR's tree state.** For each
   in-scope bench, check out the introducing-PR's merge SHA,
   build with the new toolchain, run the bench's `iai-callgrind`
   and `criterion` captures on the reference runner via the
   same `workflow_dispatch` path used for the original capture,
   and replace the bench section's gate-metric, hardware-
   dependent, and criterion rows with the new numbers.
3. **Update the capture-environment block.** The `env-<short-SHA>`
   block's toolchain rows update to the new versions; the
   `git_rev` row is unchanged (still points to the introducing
   PR's merge SHA — what was re-measured is the same source
   tree, with a different toolchain).
4. **Reset the cumulative-delta column.** Each in-scope bench's
   cumulative-delta table is truncated to the one row representing
   the re-captured introducing capture (delta = baseline).
   Subsequent Stage 1 PRs append rows from there. Cumulative-delta
   history before the rebaseline is preserved in git (`git log -p`
   of this document) but is no longer consulted by the threshold
   check.
5. **CHANGELOG entry.** The rebaseline commit gets its own
   `## [Unreleased] / ### Documentation` entry naming the bumped
   toolchain versions, the rebaselined benches, and the rationale
   (security patch, MSRV bump, dependency requirement, etc.). The
   commit is its own PR, not bundled with substantive Stage 1
   work.

The rebaseline commit is itself a "non-Stage-1 change" per §3.3.1
("the baseline is re-captured only if a non-Stage-1 change
materially shifts that bench's hot-path cost") and does not count
toward any bench's cumulative-delta column.

**What does not trigger a rebaseline.** Bumps to dependencies that
the bench's workload does not touch (e.g., `tokio`, `criterion`
itself when its harness changes don't shift `iai-callgrind`'s
measured instruction count, async runtime updates) are not
rebaseline triggers. The trigger is specifically codegen-affecting
toolchain changes (rustc/LLVM, valgrind/VEX IR, iai-callgrind-runner)
and only those. Reviewers presented with an ambiguous case (a
dependency bump that *might* affect codegen for the measured code)
re-run the affected bench's iai-callgrind capture: if the
instruction count is unchanged, no rebaseline is needed; if it
shifts, the bump is treated as a rebaseline trigger.

## Reviewer responsibility

Per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.3.1 (Round 4b — Item 14; refined in Stage 0 PR-B):

- The Stage 1 PR reviewer confirms that each in-scope bench's
  cumulative-delta row in this document is appended with the PR's
  iai-instructions and criterion-median_ns numbers, computed
  against the frozen baseline row.
- For deferred benches not yet introduced, the reviewer confirms
  the bench section is still in deferred state (no premature
  population).
- For the introducing PR of a deferred bench, the reviewer confirms
  the bench section is populated per the
  `engine_trait_bench_ledger_synced_height` template
  (frozen-baseline source, workload class, iai/criterion metrics,
  capture environment, cumulative-delta table with one row).
- The reviewer is the named owner of these checks; the PR author
  is not expected to re-measure unprompted.
- If the cumulative-delta tables for in-scope benches are not
  populated, the PR is not reviewable — measurement is the gate,
  not optional metadata.

## Cross-references

- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3 — interior-mutability measurement gate (governs this document).
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3.1 — Stage 1 outer-lock sequential consistency (the
  implementation surface measured against; per-bench frozen-baseline
  framing refined in Stage 0 PR-B).
- [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md)
  §4.4 — two-anchor static check (gate metric vs informational
  metric framing).
- [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md)
  §4.5 — per-bench frozen-baseline disposition (the operationalization
  this document implements).
- [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md)
  §4.6 — harness update discipline (per-bench deferred assignment
  for the four deferred benches).
- [`docs/benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json`](benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json)
  — the post-Q invariance-verified capture from Stage 0 PR-2 commit
  4c (GHA run 25239954863). Cited by Stage 0 PR-B's review-surface
  verification gate as the column-shape reference for this
  document's rewrite. Stage 0 PR-2 commit 5 will produce the actual
  frozen baseline against the merge SHA; that capture supersedes
  this one for transcription purposes but the c4c capture stays
  in-tree as the PR-B review-time reference (see
  [`docs/benchmarks/reference-captures/README.md`](benchmarks/reference-captures/README.md)).
- [`FOLLOWUPS.md`](FOLLOWUPS.md) §"V3.0" — performance baseline
  FOLLOWUPS row (close-condition: the four deferred-bench sections
  in this document are populated by their introducing per-trait
  PRs; the first Stage 1 PR review consumes the document).

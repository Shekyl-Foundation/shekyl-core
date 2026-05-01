# Stage 0 measurement harness — design

**Status.** Stage 0 PR-1 of the Stage 1 trait-extraction plan
(`docs/V3_ENGINE_TRAIT_BOUNDARIES.md` accepted at Round 5,
`e484d5041`, merged to `dev` at `40093ac7a`). This document is the
design contract that Stage 0 PR-2 implements.

The six decisions pinned below were named at category-level in the
trait spec and are pinned at implementation-level here. The Stage
0 PR-1 plan named them as the design surface; this document is
PR-1's deliverable.

---

## 1. Scope

The §3.3 *interior-mutability measurement gate* requires a
`criterion`-driven harness measuring read-path overhead on five
hot paths (named in §3.3.1) before any Stage 1 trait-extraction
PR lands. Stage 0 produces:

- A **frozen baseline** captured against the existing monolithic
  `Engine<S>` surface — what Stage 1 PRs measure their per-PR
  delta against.
- The **harness implementation** itself: bench files in
  `rust/shekyl-engine-core/benches/` and the wiring that lets the
  numbers reach reviewers during PR review.
- A **threshold sanity-check** confirming §3.3.1's 10% / 25%
  thresholds are coherent against measured run-to-run variance on
  the chosen runner.

This design doc pins how the harness is implemented; it does not
itself land any benches or numbers. PR-2 lands the implementation
against this design.

---

## 2. Relationship to `V3_ENGINE_TRAIT_BOUNDARIES.md` §3.3.1

This section consolidates the contract-vs-implementation
relationship between this design doc and the trait spec. It is
the single anchor reviewers should cite when asking "does this
design respect the spec?" or "does this design require a Round 6
spec amendment?"

### 2.1 Contract vs implementation

The trait-boundaries spec
([`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md))
is the **contract**. This design doc is the **implementation
governance** that names how the §3.3.1 measurement gate plugs
into the existing repository infrastructure. The contract pins:

- *What* is measured (read-path overhead on five hot paths
  named in §3.3.1).
- *Against what* (a frozen baseline of the existing monolithic
  `Engine<S>`).
- *To what tolerance* (the 10% justification threshold and the
  25% optimization threshold from §3.3.1).
- *In what document* (`docs/PERFORMANCE_BASELINE.md`).

The contract does **not** pin: which CI workflow runs the
measurement, which runner the workflow uses, which classification
class the bench-comparison script routes the entries through,
whether the baseline is frozen or rolling at the workflow level,
or whether iai-callgrind or criterion is the gate metric. Those
are implementation choices, and they live in this document.

If something in this document appears to amend the contract, the
contract wins and this document is wrong. The amendment vehicle
is Round 6 of the trait spec, not a design-doc revision. The
current design (six decisions in §4 below) does not amend the
contract — every decision is an implementation choice within the
contract's degrees of freedom.

### 2.2 The "§3.3" overload — two different gates

The phrase "the §3.3 gate" is overloaded across the project:

- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3 (the *trait spec §3.3*) — the *interior-mutability
  measurement gate*. Thresholds: **>10% requires PR-description
  justification; >25% requires optimization before merge.**
  Scope: read-path overhead from Stage 1 trait-extraction's
  interior locks, measured against the monolithic-`Engine<S>`
  baseline.
- [`MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §3.3
  (the *hardening §3.3*) — the *CI integration spec* for the
  existing benchmark gate. Thresholds: `crypto_bench_*` ±5%
  warn / ±15% fail (bidirectional); `hot_path_bench_*` +5%
  warn / +15% fail (slowdown-only).

These are two different gates measuring two different things,
both implemented through the same `ci/benchmarks` workflow. This
document treats them as orthogonal: the trait-spec gate adds a
**new** threshold class (`engine_trait_bench_*`, see §4.2) to
the existing harness rather than replacing the existing classes.
Naming below disambiguates by prefixing the spec name (e.g.
*trait-spec §3.3.1*, *hardening §3.3*).

### 2.3 Spec-as-source-of-truth for thresholds

The 10% / 25% threshold values come from trait spec §3.3.1
verbatim. They are not negotiated in this design doc; they are
**inherited**. The new bench class's routing entry in
`scripts/bench/compare.py` cites trait spec §3.3.1 as the
source-of-truth for the values. If trait spec §3.3.1 is ever
amended (Round 6 or later), `compare.py`'s routing entry is
updated to match and a single in-place comment cross-references
the spec amendment.

The corollary: this design doc does not "set the thresholds." It
**implements** them. Future spec amendments propagate to the
implementation through the same channel as any other spec change
— a follow-up commit that updates the citing site.

### 2.4 This document is the source-of-truth for Stage 0 PR-2's scope

The original Stage 1 plan named Stage 0 PR-2's scope at task-list
level: "criterion benches for the five §3.3.1 hot paths." The
plan was written before this design doc existed and assumed
Stage 0 was building from an empty CI substrate. The pre-drafting
gap-check (see PR description) surfaced the existing
`ci/benchmarks` harness; the design doc's Decision 4 (Option A
— extend the existing harness) shifts Stage 0 PR-2's scope to
include iai-callgrind benches alongside criterion, plus
workflow/script edits.

**The design doc is now the source of truth for Stage 0 PR-2's
scope.** §5 below ("What Stage 0 PR-2 implements") enumerates
the concrete handoff list; the original plan's task-list wording
is superseded by §5. PR-2 reviewers verify against §5; the
plan's pre-design wording is historical context, not a checklist.

### 2.5 Round 6 disposition for this PR

The pre-drafting gap-check considered whether the existing-harness
finding warrants a Round 6 spec amendment to §3.3.1. Disposition:
**no Round 6 amendment is needed.** The §3.3.1 contract is
correct; only the implementation choices changed. The design doc
captures everything; the framing tightening of §3.3.1
Component 1 (timing of when the harness lands shifts from "first
Stage 1 PR" to "Stage 0 PR-2") is a single-line in-place edit
that lands in Stage 0 PR-2's commit, not as a separate spec
amendment (per the plan's Push 4 disposition: "framing tightening
not Round 6").

---

## 3. Substrate that already exists

The repository already carries a per-PR benchmark gate. Stage 0's
design works *with* this substrate, not around it.

| Surface | Location | Role |
|---|---|---|
| Workflow | [`.github/workflows/benchmarks.yml`](../../.github/workflows/benchmarks.yml) (`name: ci/benchmarks`) | Per-PR gate + rolling baseline updater |
| Capture script | [`scripts/bench/capture_rust_baseline.sh`](../../scripts/bench/capture_rust_baseline.sh) | Runs criterion + iai-callgrind, writes `shekyl_rust_v0.json` envelope |
| Comparator | [`scripts/bench/compare.py`](../../scripts/bench/compare.py) | Routes each iai entry through the threshold table; emits a verdict per bench |
| Comment renderer | [`scripts/bench/post_comment.py`](../../scripts/bench/post_comment.py) | Upserts the marker-keyed PR comment |
| Baseline storage | Orphan branch `bench-baseline` (never merged) | Single `baseline.json` at tip; refreshed on every push to `dev` that touches a benched path |
| Schema | `shekyl_rust_v0` (criterion entries + iai-callgrind entries + host manifest) | Stable across reference-machine swaps; bumps require manifest update |
| Manifest | [`docs/benchmarks/shekyl_rust_v0.manifest.md`](../benchmarks/shekyl_rust_v0.manifest.md) | Prose specification of every measured operation |

The existing harness uses **iai-callgrind `instructions`** as the
gate-tier metric, explicitly because cloud-runner wall-clock is
too noisy for percentage-threshold gating. Criterion wall-clock is
captured into the same envelope and rendered as informational rows
in the PR comment, but does not gate.

The watched-path list does **not** currently include
`rust/shekyl-engine-core/**`. Adding it is part of Stage 0 PR-2's
implementation work.

---

## 4. Six decisions

The decisions that follow are pinned in the dependency order the
user-named drafting framework surfaced (Decision 6 frames the
measurement surface; the rest cascade). The reading order matches
the dependency order.

### 4.1 Decision 6 — Stage 0 ↔ Stage 4 forward-extension

**Decision.** Stage 0 measures **today's monolithic `Engine<S>`
surface** (inherent methods on `Engine<S>`). Stage 1 per-trait
PRs migrate each bench to call the **trait method** as part of
the per-trait extraction work. Stage 4 actor-backed implementations
inherit the same trait-surface benches with no harness code change;
the runtime cost shifts (mailbox round-trip + actor handler) but
the measured surface is invariant.

**Why this framing matters.** A naïve framing — "Stage 0 must
ship trait-surface-shaped benches from the start so they're
forward-compatible" — is not implementable, because the traits
don't exist yet at Stage 0. (The trait extractions *are* Stage 1.)
The honest framing is: forward-compatibility is a property of the
**migration path**, not of Stage 0's bench surface in isolation.
Stage 0's benches measure what exists now; Stage 1 PRs migrate
the call site as part of the same PR that introduces the trait;
Stage 4 inherits unchanged.

**Implementation hooks.** Each bench file's measured-surface
comment records what surface it currently calls (inherent method
on `Engine<S>` at Stage 0; trait method on `Engine<S, …>` after
the relevant Stage 1 PR). The migration is a one-line bench-code
change per per-trait PR; the fixture is unchanged.

**Cross-reference.** §10.2.2 *Stage 4 cost characterization*
inherits this harness as-is at Stage 4 cutover. Comparison
baseline at that point is Stage-1-final numbers (post-last-per-trait-PR),
not the Stage 0 frozen baseline.

### 4.2 Decision 1 — Benchmark selection

**Decision.** Five hot paths from §3.3.1, each shipping **two
benches** (criterion + iai-callgrind sibling) following the
existing `MID_REWIRE_HARDENING.md` §3.2 tool split. New
threshold-routing class introduced for these benches:
`engine_trait_bench_*`.

**Hot paths and bench filenames:**

| Hot path | Bench file (criterion) | Bench file (iai-callgrind) |
|---|---|---|
| `KeyEngine::account_public_address` | `benches/engine_trait_bench_key_account_public_address.rs` | `benches/engine_trait_bench_key_account_public_address_iai.rs` |
| `LedgerEngine::balance` | `benches/engine_trait_bench_ledger_balance.rs` | `benches/engine_trait_bench_ledger_balance_iai.rs` |
| `LedgerEngine::synced_height` | `benches/engine_trait_bench_ledger_synced_height.rs` | `benches/engine_trait_bench_ledger_synced_height_iai.rs` |
| `EconomicsEngine::current_emission` | `benches/engine_trait_bench_economics_current_emission.rs` | `benches/engine_trait_bench_economics_current_emission_iai.rs` |
| `EconomicsEngine::parameters_snapshot` | `benches/engine_trait_bench_economics_parameters_snapshot.rs` | `benches/engine_trait_bench_economics_parameters_snapshot_iai.rs` |

**Naming convention rationale.** The existing harness uses
`crypto_bench_*` (bidirectional) and `hot_path_bench_*`
(slowdown-only). The trait-spec measurement is **bidirectional**
(per `compare.py`'s pattern for `crypto_bench_*`): a +30% slowdown
is bad, and a -50% speed-up against the current monolithic engine
likely indicates the bench fixture broke or measured the wrong
work. A new prefix avoids redefining either of the two existing
classes' semantics.

**New threshold class:**

| Class | Warn | Fail | Direction |
|---|---|---|---|
| `engine_trait_bench_*` | ±10% | ±25% | **bidirectional** |

These are the trait-spec §3.3.1 thresholds verbatim, applied
bidirectionally for the same reason `crypto_bench_*` is
bidirectional.

**Surface measured at Stage 0:** `Engine<S>` inherent method.
**Surface measured after the relevant Stage 1 PR:** trait method
through `<Engine<S, …> as TraitName>` dispatch. The fixture is
identical across the migration; only the call site changes.

**Fixture shape.** Each bench constructs an `Engine<S>` with a
pre-populated state mimicking a typical wallet workload:

- 10 000-entry `transfers` vec (realistic for `LedgerEngine::balance`).
- Pre-derived `account_public_address` (single read, no derivation
  in the measured region).
- Mock daemon (no network I/O in the measured region; daemon RPC
  is not on these read paths anyway).
- No filesystem I/O in the measured region.

The fixture's exact layout lives in the Stage 0 PR-2 manifest
(see Decision 5 for manifest discipline).

**Stage 0 PR-1 scope guard.** This document does **not** pin the
fixture layout. PR-2 lands the fixture along with the bench files
and adds a manifest section for each bench naming the operation
list and fixture shape; reviewers gate PR-2's manifest separately
from this design.

### 4.3 Decision 2 — Baseline statistics

**Decision.** Two-tier metric, mirroring the existing harness:

- **Tier 1 (gate):** iai-callgrind `instructions`. Single
  deterministic value per bench; identical across runs on the
  same host (Valgrind does not introduce variance).
- **Tier 2 (informational):** criterion `median_ns` (printed in
  PR comment), with `mean_ns` and `std_dev_ns` carried for
  completeness in the JSON envelope. Not gated.

**Why median over mean for criterion.** The existing harness's
`compare.py` uses `median_ns` for criterion's informational
column because median is robust to outlier samples (background
GC pause, runner scheduling tick); mean is included alongside
for human triage when a regression appears.

**`PERFORMANCE_BASELINE.md` content.** The human-readable
baseline document carries:

- Per hot path: iai-callgrind `instructions` (single value),
  criterion `median_ns` and `mean_ns` (typical run on the
  reference runner).
- Host manifest: CPU model, kernel, rustc version, criterion
  version, iai-callgrind-runner version, valgrind version, build
  profile (`--release` with workspace defaults).
- Capture-time SHA on `dev`: the SHA at which the frozen baseline
  was measured.

**Sample size.** Criterion default (100 samples) — same as the
existing harness. iai-callgrind runs are single-shot per bench
(deterministic); no sample-size concept applies.

**Threshold disposition.** Per Tier 1 gate-metric choice:
percentage delta on `instructions` is the canonical signal for
the trait-spec §3.3.1 thresholds. The Tier 2 criterion `median_ns`
delta is a secondary check for cache-behavior-sensitive
regressions that the instruction count would not detect; it is
informational only and does not gate (matching the existing
harness's discipline).

### 4.4 Decision 3 — Environmental variance handling

**Decision.** **`ubuntu-latest` GHA runner** for the gate, same as
the existing harness. Determinism comes from iai-callgrind's
deterministic `instructions` metric, not from the runner. Cloud
runners' wall-clock variance is treated as expected for the Tier
2 informational column.

**Why this is sufficient.** The trait-spec §3.3.1 thresholds (10%,
25%) are calibrated to "typical criterion noise floor (1–3% under
good conditions)." On `ubuntu-latest` the criterion noise floor
is materially higher (5–15% common). Three options to reconcile:

1. **Use iai-callgrind for the gate** (selected). iai-callgrind's
   `instructions` is deterministic on shared runners; the 10% /
   25% thresholds are coherent against ±0% variance.
2. **Use a dedicated bench host.** Lower noise floor on criterion
   wall-clock; cost ~$30/mo cloud or zero on self-hosted with
   maintainer-approval gating. Tracked as a future Tier-2 upgrade
   in [`MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §6.1.
3. **Loosen the trait-spec thresholds** to absorb runner variance.
   Rejected: trait-spec §3.3.1 names the 10% / 25% values as the
   substantive threshold, not an artifact of measurement
   environment. Loosening to fit a noisy runner conflates "the
   change cost N%" with "the runner happened to vary by N%."

**Threshold sanity-check (Stage 0 PR-2 part 4).** Re-run
iai-callgrind across N runs on `ubuntu-latest`; expect ±0%
(Valgrind is deterministic). Re-run criterion across N runs;
record the wall-clock variance for the host manifest. The
sanity-check confirms the gate-metric is coherent against the
thresholds; it does not aim to prove criterion wall-clock is
precise (it isn't, on shared runners).

**If criterion variance is unexpectedly high on the gate-metric
benches.** PR-2 may surface a small framing tightening to
trait-spec §3.3.1 (single-line clarifying that criterion
wall-clock is informational and the 10%/25% thresholds apply to
the gate-metric). Per the plan's Push 4 disposition: this lands
as a standalone spec amendment in Stage 0 PR-2, *not* §8.2
co-landing with Stage 1 PR 1.

### 4.5 Decision 4 — CI integration

**Decision.** **Extend** the existing `ci/benchmarks` harness;
do not run a parallel harness. The trait-spec §3.3.1 hot paths
land as new entries in the existing capture/compare/comment
pipeline, gated through the new `engine_trait_bench_*` class.

**Concrete changes Stage 0 PR-2 makes:**

1. **Watched paths.** Add `rust/shekyl-engine-core/**` to the
   `paths:` list in
   [`.github/workflows/benchmarks.yml`](../../.github/workflows/benchmarks.yml)
   for both `pull_request` and `push` triggers. Without this, PRs
   touching `shekyl-engine-core` do not trigger the gate.
2. **Capture script.** Add five rows to the `BENCHES` array in
   [`scripts/bench/capture_rust_baseline.sh`](../../scripts/bench/capture_rust_baseline.sh)
   following the existing `crate:criterion-target:iai-callgrind-target`
   shape. Each new bench compiles to its own criterion +
   iai-callgrind sibling pair under the new naming convention.
3. **Compare classifier.** Add a third branch to the `classify()`
   function in
   [`scripts/bench/compare.py`](../../scripts/bench/compare.py)
   matching `engine_trait_bench_*`, with `verdict_for()` extended
   to apply the bidirectional ±10% warn / ±25% fail thresholds.
4. **PR-comment surface.** No change. The existing
   `post_comment.py` renders all entries from the report; new
   entries appear automatically.
5. **Manifest extension.** Add a new section to
   [`docs/benchmarks/shekyl_rust_v0.manifest.md`](../benchmarks/shekyl_rust_v0.manifest.md)
   for each of the five new benches, following the existing
   manifest section template (operation list, fixture shape, known
   gaps).

**Freeze-vs-rolling baseline reconciliation.** Trait-spec §3.3.1
requires a **frozen** baseline at Stage 0 PR-2's SHA, unchanged
through all Stage 1 PRs. The existing `bench-baseline` is
**rolling**, refreshed on every push to `dev`. Two readings of
"the per-PR delta" coexist:

- **CI-gate delta** (rolling): each PR's iai-callgrind delta
  against `bench-baseline/baseline.json` at the moment the gate
  runs. This is what the workflow enforces. As Stage 1 PRs land
  on `dev`, each subsequent PR's gate runs against the previous
  PR's post-merge state (the rolling baseline). The gate catches
  per-PR regressions but does not show cumulative delta across
  all Stage 1 PRs.
- **Cumulative-delta citation** (frozen): each Stage 1 PR's
  description cites both numbers — the CI-gate delta against the
  rolling baseline (gated; what the workflow says), and the
  cumulative delta against
  [`docs/PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md)'s
  Stage-0-frozen numbers (citation only; what reviewers consult
  for "did the trait extraction as a whole stay within budget").

Why both. The CI gate is the per-PR enforcement signal; it
catches a single PR introducing a >25% regression even if prior
PRs were fine. The frozen-baseline citation is the trait-spec
§3.3.1 cumulative-delta signal; it catches "each PR added 5%, the
last one tripped 25% over Stage 0 baseline" patterns. Both are
necessary; they answer different questions.

`PERFORMANCE_BASELINE.md`'s post-interior-lock table
(per-Stage-1-PR delta column) records the frozen-baseline delta
each PR introduces, computed against the Stage-0-frozen numbers.
Reviewers cite the table during Stage 1 PR review; the document
is the canonical source of cumulative delta.

**Why not lock the rolling baseline during Stage 1.** Plausible
alternative: suspend `update-baseline` for `shekyl-engine-core`
benches during Stage 1 (lock the baseline at Stage 0 PR-2's SHA
until the last per-trait PR lands; resume rolling refresh
after). Implementable via a path-filter on the `update-baseline`
job, but adds workflow complexity and creates a Stage-1-specific
exception in the otherwise-uniform rolling baseline. Both
readings of "per-PR delta" are useful to reviewers; the simpler
implementation (rolling baseline + frozen-baseline citation in
PERFORMANCE_BASELINE.md) preserves both signals.

**Existing-class alternative considered and rejected.** Routing
the new benches under the existing `hot_path_bench_*` class
(slowdown-only, +5% / +15%) would be simpler workflow-wise but
loses two properties trait-spec §3.3.1 requires: bidirectional
detection (a -50% speed-up flags a broken fixture, not a real
optimization, on engine read paths) and the looser 10% / 25%
thresholds (orchestration overhead is reasonably allowed more
runtime cost than a tight crypto inner loop). The new class is
necessary, not gratuitous.

### 4.6 Decision 5 — Harness update discipline

**Decision.** New benches enter the harness **as part of the PR
that introduces the new measured surface**. New crates enter the
watched paths **as part of the same PR**.

**Stage 1 per-trait PRs.** Each Stage 1 PR (DaemonEngine,
LedgerEngine, …) owns the migration of its benched methods from
the inherent-method call site to the trait-method call site. The
PR also owns the manifest update and any threshold-class
adjustment if needed for that trait's specific surface.

**Stage 2+ method additions.** When a future PR adds a new
hot-path method to an existing trait, that PR adds the bench
alongside the method. Reviewer responsibility: flag any new method
on `KeyEngine` / `LedgerEngine` / `EconomicsEngine` /
`DaemonEngine` / `RefreshEngine` / `PendingTxEngine` /
`PersistenceEngine` that does not have an accompanying bench, on
the same justification as the trait-spec §3.3.1 gate (read-path
overhead must be measured before merge).

**Stage 4 cutover.** The harness measures the trait surface,
which is invariant across Stage 1 ↔ Stage 4 (per spec §7
invariants). Bench code is unchanged at cutover; the comparison
baseline shifts from Stage-0-frozen to Stage-1-final-frozen for
§10.2.2 cost characterization (per Decision 6).

**V3.1 multisig (§10.3.1) and beyond.** New hot paths introduced
by V3.1+ work follow the same discipline: bench-with-method PR.
The trait-spec gate's category-level pinning (read-path
overhead) remains the contract; the specific bench list grows
through the existing manifest discipline.

**Schema bumps.** Per
[`docs/benchmarks/README.md`](../benchmarks/README.md), schema
bumps to `shekyl_rust_v0.json` are required when a bench's
operation list, fixture shape, or measurement boundary changes.
The trait-spec hot paths use the same schema; adding entries does
not require a schema bump (rows are additive). Migrating from
inherent-method to trait-method during a Stage 1 PR is a
**measurement-boundary change** (different surface, same fixture)
and requires a schema bump per the existing discipline. The
schema bump goes in the same Stage 1 PR that does the migration.

**Manifest stewardship.** The five new bench sections in
`shekyl_rust_v0.manifest.md` (added by Stage 0 PR-2) are owned by
the trait-extraction work for the duration of Stage 1. After
Stage 1 closes, ownership transfers to whoever maintains the
trait surface (default: the engine-core crate maintainers; not a
named role at V3.0).

---

## 5. What Stage 0 PR-2 implements

Concrete handoff list, in commit order. Each item is a checkbox
PR-2 reviewers verify against this design:

- [ ] Five criterion bench files under
      `rust/shekyl-engine-core/benches/engine_trait_bench_*.rs`
      (inherent-method call sites; today's monolithic surface).
- [ ] Five iai-callgrind sibling bench files under
      `rust/shekyl-engine-core/benches/engine_trait_bench_*_iai.rs`
      (same call sites, deterministic instruction counts).
- [ ] `[[bench]]` entries for each new bench in
      `rust/shekyl-engine-core/Cargo.toml` (`harness = false` per
      the existing convention).
- [ ] Five new sections in
      `docs/benchmarks/shekyl_rust_v0.manifest.md` documenting
      operation list, fixture shape, known gaps for each bench.
- [ ] `BENCHES` array extension in
      `scripts/bench/capture_rust_baseline.sh`.
- [ ] `classify()` + `verdict_for()` extension in
      `scripts/bench/compare.py` for the new
      `engine_trait_bench_*` class.
- [ ] `paths:` extension in `.github/workflows/benchmarks.yml`
      for `rust/shekyl-engine-core/**` (both `pull_request` and
      `push` triggers).
- [ ] Captured frozen baseline numbers landed in
      `docs/PERFORMANCE_BASELINE.md` at Stage 0 PR-2's SHA, with
      host manifest filled in.
- [ ] Single-line in-place tightening of trait-spec §3.3.1
      Component 1 placeholder to name Stage 0 PR-2's SHA and
      this design doc as the harness's design contract. This is
      contextual tightening (timing-of-when-harness-lands shifts
      from "first Stage 1 PR" to "Stage 0 PR-2"); the substantive
      §3.3.1 content is unchanged.
- [ ] Threshold sanity-check: re-run iai-callgrind N times across
      a fresh `ubuntu-latest` runner; record variance in the
      `PERFORMANCE_BASELINE.md` host manifest. Confirm
      iai-callgrind variance is ±0% (deterministic) and criterion
      wall-clock variance is documented. If criterion variance
      surfaces a §3.3.1 framing issue, ship the standalone
      tightening commit alongside PR-2 (per Push 4 disposition;
      not §8.2 co-landed with Stage 1 PR 1).

PR-2 does not modify trait-spec §3.3 substantive content; only
the in-place placeholder tightening at Component 1 is permitted,
and that's framing, not substance.

---

## 6. Cross-references

- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3 — the interior-mutability measurement gate this design
  implements.
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3.1 — the three-component gate (measurement, documentation,
  threshold).
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §10.2.1 — Stage 1 baseline (V3.0; this is the deferred-entry
  this design closes).
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §10.2.2 — Stage 4 cost characterization (inherits this harness).
- [`MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §3.2 —
  Rust scope, tool split (criterion + iai-callgrind), naming
  conventions.
- [`MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §3.3 —
  CI integration, threshold table, rolling baseline rules (the
  substrate this design extends).
- [`MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §6.1 —
  Tier-2 dedicated-runner upgrade (future; criterion as gated
  metric).
- [`docs/benchmarks/README.md`](../benchmarks/README.md) — the
  existing harness's user-facing reference.
- [`docs/benchmarks/shekyl_rust_v0.manifest.md`](../benchmarks/shekyl_rust_v0.manifest.md)
  — manifest format Stage 0 PR-2's new sections follow.
- [`docs/PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) —
  human-readable baseline document; PR-2 fills in numbers.
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 §"Stage 1
  performance baseline measurement" — the FOLLOWUPS row PR-2's
  baseline closes.

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

**`update-baseline` job behavior on PR-2's merge.** The
`update-baseline` job (gated on `push` to `dev`) runs against
PR-2's merge commit. Because PR-2 also lands the watched-path
addition for `rust/shekyl-engine-core/**`, the merge commit is
within scope; the job re-captures and absorbs the new
`engine_trait_bench_*` entries into `bench-baseline/baseline.json`.
Subsequent Stage 1 PR gates measure against this updated rolling
baseline; the §4.5 freeze-vs-rolling reconciliation depends on
this single absorption step.

---

## 4. Six decisions

The decisions that follow are pinned in the dependency order the
user-named drafting framework surfaced (Decision 6 frames the
measurement surface; the rest cascade). The reading order matches
the dependency order.

### 4.1 Decision 6 — Stage 0 ↔ Stage 4 forward-extension

**Decision.** Stage 0 measures **the today-equivalent call paths
through whatever surface exists at the baseline SHA** (typically
an `Engine<S>` accessor + inner-state method, e.g.,
`engine.ledger().compute_balance(...)`). The §3.3.1 trait-method
names (`KeyEngine::account_public_address`, `LedgerEngine::balance`,
etc.) are workload labels naming *which workloads to measure*,
not literal call-site requirements; the spec is silent on the
exact call-site shape at Stage 0 because the trait extraction is
Stage 1's substantive deliverable. Stage 1 per-trait PRs migrate
each bench's call site from the today-equivalent path to the
**trait-method path** as part of the per-trait extraction work.
Stage 4 actor-backed implementations inherit the same
trait-surface benches with no harness code change; the runtime
cost shifts (mailbox round-trip + actor handler) but the measured
surface is invariant.

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
comment records what surface it currently calls (the
today-equivalent call path at Stage 0, e.g.,
`engine.ledger().compute_balance(...)`; the trait method on
`Engine<S, …>` after the relevant Stage 1 PR, e.g.,
`<Engine<…> as LedgerEngine>::balance(&engine, ...)`). The Stage 1
migration reshapes the bench's call site from the today-equivalent
path to the trait-method path — typically a few lines: accessor
disappears, inner-state call becomes trait dispatch. The fixture
is unchanged; the measured work is unchanged.

**Note on the today-equivalent call path.** Of the five §3.3.1
hot paths, **two** have today-equivalent call paths at the Stage 0
baseline SHA:

- `LedgerEngine::synced_height`: `Engine<S>::synced_height()` at
  `engine/merge.rs:86`. Direct call.
- `LedgerEngine::balance`: `engine.ledger().balance(synced_height)`
  through `LedgerBlockExt::balance` in
  `shekyl-scanner/src/ledger_ext.rs:166`, which dispatches to
  `BalanceSummary::compute(transfers, height)`. Accessor +
  extension trait + state-layer compute.

The other three (`KeyEngine::account_public_address`,
`EconomicsEngine::current_emission`,
`EconomicsEngine::parameters_snapshot`) **have no today-equivalent
call path** because the workloads they label do not exist as
identifiable units in the V3.0 codebase: `account_public_address`
exists in C++ FFI (`shekyl-ffi/src/account_ffi.rs`) and as
docstring references but no Rust function derives a wallet's
primary account public address from key material as a single
operation; `current_emission`'s components live in
`shekyl-economics` (`calc_release_multiplier`,
`split_block_emission`, `apply_release_multiplier`,
`calc_effective_emission_share`) but no aggregating
"emission at height H" function exists; `parameters_snapshot`'s
`EconomicParams` struct exists but no snapshot-constructor
operation does. Per §4.2's per-bench frozen-baseline framing,
those three benches are **deferred** to their respective Stage 1
per-trait PRs (workload-doesn't-exist deferrals).

The two with today-equivalent paths (`balance`, `synced_height`)
are themselves split under §4.2's per-bench framing:
`synced_height` is the sole Stage-0-frozen bench (its workload
is state-size-insensitive and a fresh `Engine` from
`Engine::create` is a representative fixture); `balance` is
deferred to the **LedgerEngine PR** because its workload, while
existing today, requires a state-populated fixture (thousands of
`transfers`) and the only legitimate route to populate that
state is through `MockDaemon`-driven scan, which is introduced
by Stage 1 PR 1. See §4.2's "Why benches are deferred" for the
full disposition.

For the Stage-0-frozen bench (`synced_height`, where the
today-equivalent path exists and the fresh-engine fixture is
representative), two alternatives were considered and rejected:

- **Add thin shim `pub fn` methods to `Engine<S>` at Stage 0
  with the trait-method names**, replaced by trait impls at
  Stage 1. Rejected on two grounds. First, it introduces public
  methods on `Engine<S>` whose only Stage-0 caller is the bench
  file, violating `15-deletion-and-debt.mdc`'s
  "no-code-with-bench-as-only-caller" rule (the shims would
  exist for one Stage 1 PR's lifetime each, then be replaced by
  trait-impl methods of the same name). Second, it dilutes
  Stage 1's first-class trait-introduction framing —
  per-trait PRs would read as "rename a method and add a trait
  declaration around it" rather than "introduce the abstraction
  surface, the impl, the type-parameter discipline." Reviewers
  would see a smaller-than-real change.
- **Extract the trait at Stage 0 (move trait-definition work
  from Stage 1 PR 1 into Stage 0 PR-2).** Rejected on its face:
  Stage 0 is the harness, Stage 1 is the trait extractions;
  mixing the two defeats the two-stage structure.

The accepted approach for the Stage-0-frozen bench
(today-equivalent call path at Stage 0; trait dispatch at
Stage 1) produces a side-benefit: PR-2 discovers the
today-equivalent surface concretely as part of fixture authoring
(e.g., `engine.synced_height()` reads through to
`self.ledger.ledger.height()` per §4.1's enumeration), which is
information Stage 1's per-trait PRs would otherwise have to
surface from scratch. For the deferred four, the per-trait PR is
the moment the workload first exists as a measurable unit
through a representative fixture; the bench is authored together
with the trait method (or, for `balance`, together with the
state-populated fixture that `MockDaemon` from Stage 1 PR 1
makes possible). The disposition discussion (compose-inline vs
introduce-helper vs defer) for the deferred four lives in §4.2.

**Note on trait-method disambiguation.** Once a Stage 1 PR
introduces the trait, `Engine<S, …>` may carry both an inherent
method and a trait method with the same signature for the
trait's transitional period. Method-call syntax
(`engine.account_public_address(0, 0)`) resolves to the inherent
method when both exist, which would silently keep the bench on
the pre-migration surface. The migrating PR uses fully-qualified
trait dispatch (`<Engine<…> as KeyEngine>::account_public_address(&engine, 0, 0)`)
so the call site is unambiguous, and updates the bench file's
measured-surface comment to record which surface is in scope.
Reviewers verify the comment matches the actual call.

**Cross-reference.** §10.2.2 *Stage 4 cost characterization*
inherits this harness as-is at Stage 4 cutover. Comparison
baseline at that point is Stage-1-final numbers (post-last-per-trait-PR),
not the Stage 0 frozen baseline.

### 4.2 Decision 1 — Benchmark selection

**Decision.** Five hot paths from §3.3.1, each shipping **two
benches** (criterion + iai-callgrind sibling) following the
existing `MID_REWIRE_HARDENING.md` §3.2 tool split. New
threshold-routing class introduced for these benches:
`engine_trait_bench_*`. Per the per-bench frozen-baseline framing
below, **one** of the five pairs ships at Stage 0 PR-2 (the
sole Stage-0-frozen bench, `engine_trait_bench_ledger_synced_height`);
the other **four** ship at their respective Stage 1 per-trait PR
(per §4.6's per-bench deferred assignment). The
`engine_trait_bench_*` class definition and the threshold routing
apply to all five regardless of which PR introduces them; class
membership is the unifying contract.

**Hot paths, bench filenames, iai routing function names, and
Stage 0 disposition:**

| Hot path | Bench file (criterion) | Bench file (iai-callgrind) | iai `#[library_benchmark]` function | Stage 0 disposition |
|---|---|---|---|---|
| `KeyEngine::account_public_address` | `benches/engine_trait_bench_key_account_public_address.rs` | `benches/engine_trait_bench_key_account_public_address_iai.rs` | `engine_trait_bench_key_account_public_address` | Deferred to KeyEngine PR |
| `LedgerEngine::balance` | `benches/engine_trait_bench_ledger_balance.rs` | `benches/engine_trait_bench_ledger_balance_iai.rs` | `engine_trait_bench_ledger_balance` | Deferred to LedgerEngine PR |
| `LedgerEngine::synced_height` | `benches/engine_trait_bench_ledger_synced_height.rs` | `benches/engine_trait_bench_ledger_synced_height_iai.rs` | `engine_trait_bench_ledger_synced_height` | Stage-0-frozen |
| `EconomicsEngine::current_emission` | `benches/engine_trait_bench_economics_current_emission.rs` | `benches/engine_trait_bench_economics_current_emission_iai.rs` | `engine_trait_bench_economics_current_emission` | Deferred to EconomicsEngine PR |
| `EconomicsEngine::parameters_snapshot` | `benches/engine_trait_bench_economics_parameters_snapshot.rs` | `benches/engine_trait_bench_economics_parameters_snapshot_iai.rs` | `engine_trait_bench_economics_parameters_snapshot` | Deferred to EconomicsEngine PR |

Stage 0 PR-2 ships the sole Stage-0-frozen bench (two bench
files total: one criterion + one iai-callgrind sibling); the
four deferred benches enter the harness at their respective
Stage 1 per-trait PR (per §4.6's per-bench deferred assignment).

**Function-name routing discipline.** `compare.py`'s `classify()`
routes on the iai-callgrind `#[library_benchmark]` *function*
name, not the bench-target file name. Each new iai bench's
function must start with `engine_trait_bench_` — matching the
class name — or the entry lands in `unrouted` and the threshold
gate doesn't apply. The function name is what the existing
classes (`crypto_bench_*`, `hot_path_bench_*`) match against,
and the same convention extends to the new class without
infrastructure change. Reviewers verify the function name in
each new iai bench file matches the table above.

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

**Per-bench frozen baseline.** The trait-spec §3.3.1 frozen
baseline is **per-bench**, not uniform across all five hot paths.
**One rule applies to every bench**: each bench's
frozen-baseline SHA is the SHA at which the bench's measured
workload first exists as a measurable unit through a
representative fixture. There is no two-rule asymmetry between
"Stage-0-frozen" and "deferred" benches; the introducing PR is
whichever PR can first measure the workload honestly.

Concretely:

- **`engine_trait_bench_ledger_synced_height`**: frozen baseline
  captured at Stage 0 PR-2's merge SHA. The workload is a
  state-size-insensitive read (a single field access through
  the engine's public surface, per §4.1's today-equivalent call
  path) that a fresh `Engine<SoloSigner>` from `Engine::create`
  exercises at full representative cost. PR-2 captures the
  iai-callgrind `instructions` and criterion `median_ns` numbers
  and freezes them.
- **`engine_trait_bench_ledger_balance`**: frozen baseline
  captured at the **LedgerEngine PR's** merge SHA. The workload
  exists as a unit today (linear walk over `transfers`), but a
  representative measurement requires a state-populated fixture
  with thousands of `transfers`; that fixture in turn requires
  MockDaemon-driven scan infrastructure introduced by **Stage 1
  PR 1** (DaemonEngine, per §6.1 of the trait spec). The
  LedgerEngine PR introduces the bench alongside the
  `LedgerEngine::balance` trait method and freezes the baseline
  at that PR's merge SHA against a state-populated fixture.
- **`engine_trait_bench_key_account_public_address`**: frozen
  baseline captured at the **KeyEngine PR's** merge SHA. The
  workload first exists as a unit when the `KeyEngine` trait
  method is introduced; the per-trait PR introduces both.
- **`engine_trait_bench_economics_current_emission` and
  `engine_trait_bench_economics_parameters_snapshot`**: frozen
  baselines captured at the **EconomicsEngine PR's** merge SHA.
  Both workloads first exist as units when their `EconomicsEngine`
  trait methods are introduced; the per-trait PR introduces both
  trait methods and both benches together.

Stage 1 PR descriptions cite cumulative delta against each
bench's frozen-baseline SHA (per §4.5's per-bench-SHA
disposition); the temporal anchor shifts per-bench, but the
§3.3.1 cumulative-budget contract applies uniformly per bench.

**Surface measured at Stage 0** (Stage-0-frozen bench only):
today-equivalent call path for `synced_height` (direct `Engine<S>`
method, per §4.1).
**Surface measured after the relevant Stage 1 PR** (any bench in
scope at that PR): trait method through
`<Engine<S, …> as TraitName>` dispatch. The fixture is identical
across the migration; the call site reshapes (per §4.1's
*Implementation hooks*).

**Why benches are deferred.** Four of the five §3.3.1 hot paths
defer their bench introduction to a Stage 1 per-trait PR, for
two distinct reasons that resolve to the same disposition under
the **single rule** above ("frozen at the SHA where the
workload first exists as a measurable unit through a
representative fixture"):

- **Workload-doesn't-exist-as-a-unit deferrals**:
  `account_public_address`, `current_emission`,
  `parameters_snapshot`. Per §4.1's "Note on the today-equivalent
  call path", these three §3.3.1 hot paths are trait-method
  *labels* whose underlying composition is implicit at Stage 0
  (e.g., `current_emission` is computed by
  `next_block_subsidy(...)` against `EmissionParameters` derived
  from the current chain height; no `Engine<S>` method or
  inner-state helper exposes the composition as a unit). The
  workload first exists as a measurable unit when the per-trait
  PR introduces the trait method.
- **Workload-exists-but-fixture-requires-future-infrastructure
  deferral**: `balance`. The workload exists today
  (`engine.ledger().ledger.balance(synced_height)`, a linear walk
  over `transfers`), but a *representative* measurement requires
  a state-populated fixture with thousands of `transfers`. The
  only legitimate fixture-population route under the
  visibility-expansion principle (below) is driving the engine's
  production scan loop through a mock daemon; that infrastructure
  (`MockDaemon`, per §6.1 of the trait spec) is introduced by
  Stage 1 PR 1 (DaemonEngine) and not available at Stage 0 PR-2.
  Measuring `balance` against a fresh `Engine` fixture at PR-2
  would record a number that does not represent the workload the
  bench is named for; per the design's principle ("measurement
  that pretends to be more than it is corrupts the discipline
  depending on it"), this is rejected.

Three options to close the deferral gap were considered before
settling on deferral:

- **Compose the today-equivalent inline in the Stage 0 bench
  file.** The bench's setup composes the underlying functions
  into the workload; the measured region calls the composition.
  Rejected: the Stage 0 composition may not match what Stage 1's
  trait impl actually does. If they diverge, the cumulative-delta
  number against the Stage 0 baseline compares different
  workloads — a number that looks legitimate but isn't.
  Mitigation via "may re-baseline at Stage 1" weakens the §3.3.1
  frozen-baseline contract; the cumulative-delta semantics depend
  on the baseline being stable.
- **Introduce helper functions in inner-state crates at Stage 0**
  (e.g., `pub fn current_emission(...)` in `shekyl-economics`,
  `pub fn primary_account_address(...)` in the keys layer). The
  bench calls the helper; Stage 1's trait impl wraps it.
  Rejected on the same grounds as §4.1's shim alternative,
  displaced to a different crate. The
  "no-code-with-bench-as-only-caller" rule from
  `15-deletion-and-debt.mdc` is not Engine-specific. Worse on a
  subtler axis: at the inner-state layer, the helpers read as
  plausible APIs (someone might want `current_emission(height)`
  outside the trait context), which makes them harder to remove
  when Stage 1's trait-impl duplicates them. Inner-state crates
  accumulate near-duplicate API surface; nobody cleans up
  because "maybe someone uses it."
- **Defer to the introducing per-trait PR** (selected). The
  Stage 1 per-trait PR is the moment the workload first exists
  as a measurable unit through a representative fixture; that
  PR introduces both the trait method (where applicable) and the
  bench, with the bench's frozen baseline captured at the PR's
  merge SHA. The §3.3.1 spec's "at minimum" wording allows
  reviewer judgment to defer specific paths; this option uses
  that allowance, and is consistent with §4.6's general
  "bench-with-method PR" discipline applied to Stage 1's
  surface-introduction PRs.

The selected approach is honest about what Stage 0 measures
(the one hot path whose workload exists as a measurable unit
through a representative fresh-engine fixture; capture-when-real
for the four whose workload arrives later or whose fixture
requires future infrastructure) and preserves the §3.3.1
cumulative-delta semantics uniformly per bench (the temporal
anchor shifts; the contract shape is the same).

**Fixture shape per bench.** Each bench's fixture is sized to
the measurement intent of *that bench's* workload, not to a
single uniform "typical wallet workload" template. The
distinction is binding because §3.3.1's measurement-power
guarantee depends on the fixture exercising the work the bench
claims to measure.

- **`engine_trait_bench_ledger_synced_height` (Stage 0 PR-2).**
  State-size-insensitive workload (a single field access through
  the engine's public surface, per §4.1). The fixture is a fresh
  `Engine<SoloSigner>` constructed via the production lifecycle
  path (`EngineCreateParams` + `Engine::create`, per the
  fixture-construction approach below) with **no synthetic state
  population**. The measured cost is the real cost of the
  workload because the workload is genuinely
  state-size-insensitive; there is no scaling regression to
  detect because there is no scaling.
- **Each Stage 1 per-trait PR's bench(es).** Fixture sized
  appropriately for that workload's measurement intent, using
  whatever state-population infrastructure exists at that PR's
  tip (MockDaemon-driven scan from Stage 1 PR 1 onward, per §6.1
  of the trait spec). For state-size-scaling workloads
  (`balance`, on `transfers` of representative size — single
  digits of thousands of entries), the fixture exercises scale;
  scaling regressions are detectable. For state-size-insensitive
  workloads, the fixture is whatever minimal state the workload
  actually depends on.

The per-trait PR's manifest section documents its specific
fixture shape with derivation rationale (one or two sentences
naming the user-population shape the fixture represents).
Reviewers verify the rationale produces a workload representative
of the measurement intent of the bench.

**Stage 0 PR-1 scope guard.** This document does **not** pin
specific entry counts or fixture sizes for any bench. Pinning
numbers here would create synthetic precision the design cannot
justify (actual entry counts are an empirical question the
introducing PR answers during fixture derivation). However, the
manifest is required to make the derivation auditable:

- **Manifest requirement.** Each bench's manifest section
  documents specific entry counts, account counts, output counts,
  and block heights, **with derivation rationale** (one or two
  sentences naming the workload's measurement intent and the
  user-population shape the fixture represents — or, for
  state-size-insensitive benches, naming why no state population
  is required).
- **Reviewer gate.** Reviewers verify the manifest's derivation
  rationale produces a workload **representative of the bench's
  measurement intent**. For state-size-scaling workloads (e.g.,
  `balance`), this means a fixture sized to a typical user
  wallet at representative depth of use (single digits of
  thousands of `transfers`, derived per the introducing PR).
  For state-size-insensitive workloads (e.g., `synced_height`),
  this means an honest minimal fixture (a fresh `Engine` from
  `Engine::create`) and an explicit manifest note that the
  workload does not depend on populated state. The criterion is
  representativeness against the bench's measurement intent, not
  uniform numerical targets across all benches.
- **Why this matters.** Fixture shape is load-bearing for
  threshold sanity. iai-callgrind's `instructions` is largely
  insensitive to working-set size (cache misses don't add
  instructions), but criterion `median_ns` is highly sensitive
  to whether the fixture fits in L2/L3 cache. For
  state-size-scaling benches, a fixture chosen to "fit nicely"
  would understate real-world cost and a fixture chosen for
  "stress test" would overstate it. For state-size-insensitive
  benches, the cache-fit question doesn't arise because there is
  no scaling state.
- **Cross-bench surface distinction.** When a bench measures an
  engine-surface call that dispatches to an existing
  state-layer bench's measured operation (e.g.,
  `engine_trait_bench_ledger_balance` measures the engine
  surface whose underlying compute is also benched by
  `shekyl-engine-state`'s `hot_path_bench_balance_compute`),
  the manifest entry names both benches and explains the
  surface distinction. The engine-surface cost is gate-class
  `engine_trait_bench_*` (bidirectional ±10% / ±25%); the
  state-layer cost remains gate-class `hot_path_bench_*`
  (slowdown-only +5% / +15%). The two benches are not redundant
  — they measure different layers of the same logical
  operation — but reviewers should be able to find that
  distinction without reconstructing it.

The introducing PR (Stage 0 PR-2 for `synced_height`; the
relevant per-trait PR for each deferred bench) lands the bench's
fixture along with the bench files; reviewers gate the
manifest's representativeness rationale at that PR.

**Fixture construction approach (Path A).** Stage 0 PR-2's bench
constructs a real `Engine<SoloSigner>` instance via the
production lifecycle path — `Engine::create` with manually-built
`EngineCreateParams` — not through a synthetic `Engine` shim or a
`bench-internals`-exposed test constructor. The Engine instance
is built once per bench function (in iai-callgrind's
`#[benches::with_setup]` and outside criterion's `b.iter`
closure) and reused across measurement iterations. Setup cost
(~1–2 seconds per bench function, dominated by Argon2id KDF +
ML-KEM keygen) is excluded from the measured region.

The fixture lives in
`rust/shekyl-engine-core/benches/common/engine_fixture.rs`; each
bench file imports it via `mod common;`. Cargo treats
`benches/common/` as a shared-helper directory rather than a
bench target, so the helper does not appear in the workflow's
bench-target list and does not need a `[[bench]]` entry.

**Scope guard for `benches/common/`.** The shared module has
exactly one job: construct a real `Engine<SoloSigner>` via the
production lifecycle path and return it paired with a `TempDir`
guard for filesystem cleanup. Any other helper a future bench
needs lives in that bench's own file. Migration of a helper to
`common/` requires a documented two-caller justification (i.e.,
two separate bench files actually need it) and a comment naming
both call sites at the migration point. This is
`15-deletion-and-debt.mdc`'s "while we're here is the enemy"
applied to bench infrastructure: a `benches/common/` that
accumulates "general utilities" becomes its own audit surface
without the discipline.

**Why duplicate `EngineCreateParams::for_test_full`'s body.**
`shekyl-engine-core` has a `for_test_full(...)` helper at
`engine/lifecycle.rs` (`#[cfg(test)] pub(crate)`) that encodes
sensible defaults for FULL-capability `Engine<SoloSigner>`
construction with a known seed. The natural shortcut would be
exposing `for_test_full` to benches by widening its `cfg` to
`#[cfg(any(test, feature = "bench-internals"))] pub`. This is
rejected per the visibility-expansion principle below;
`benches/common/engine_fixture.rs` instead **duplicates the body
of `for_test_full`** rather than reusing it. The duplication is
intentional and documented in the fixture file's top-of-file
comment; reviewers verify the duplication's shape match against
the test helper during PR review (drift between the two would
surface as a bench-vs-test cost-profile discrepancy that the
threshold sanity-check or a per-trait PR's review would catch).

**Visibility-expansion principle.** Bench fixtures duplicate
test-helper logic locally (in `benches/common/`) rather than
widening test-helper visibility through `bench-internals`. The
duplication cost is small (one fixture file's worth of code per
crate touching benches); the surface-expansion cost is permanent
— every `#[cfg(any(test, feature = "bench-internals"))] pub`
declaration is a symbol that exists in any build with the
feature enabled, the `cfg` gate is a speed bump rather than a
wall, and the original `pub(crate)` visibility represents a
deliberate "safe-for-tests-only" judgement that side-channel
widening overrides without revisiting. **This principle applies
to all subsequent Stage 1 per-trait PR bench fixtures**: when a
bench fixture needs types or helpers from another crate, the
path is "duplicate the helper body in `benches/common/`" rather
than "expose the existing helper through `bench-internals`."
Future PRs cite this paragraph when faced with the same trade.

**Measurement region discipline.** The measurement region is the
trait-method-equivalent call only — for the Stage-0-frozen
bench, `engine.synced_height()` (per §4.1). Engine construction
(`EngineCreateParams` build, `Engine::create`, Argon2id KDF,
ML-KEM keygen, filesystem layout, advisory lock acquisition,
schema initialization) is **setup**, excluded from the measured
region by `#[benches::with_setup]` (iai-callgrind) and `b.iter`'s
closure scope (criterion). Three rules — each with its own
subsection below — govern harness-measurement subtleties beyond
the basic setup-exclusion above. They split along two axes:

- Two rules address **iai-callgrind contamination** — work
  counted that the bench author did not mean to count. The
  **symmetry rule** keeps fixture teardown out of the measured
  region; the **boundary rule** keeps fixture value-movement at
  the bench-function boundary pointer-sized so memcpy cost does
  not dominate.
- One rule addresses **criterion amortization** — work elided
  that the bench author *did* mean to count. The **hoisting
  rule** names criterion's iter-amortization model: trivial
  pure-read benches may produce per-iteration times below the
  per-call cost because the optimizer legally hoists the call
  out of `b.iter`'s inner loop.

The three rules share one predictive structure: each names a
relationship between what the bench source code looks like and
what the harness actually measures. Together they let §4.4's
two-anchor component model predict both numbers — iai
instructions and criterion median_ns — from the same workload
primitives, with the rules as the bridge terms. Reviewers verify
the boundaries in PR review:

- The `b.iter` closure body / iai-callgrind benchmark function
  body contains only the trait-method-equivalent expression
  wrapped in `black_box(...)`.
- The Engine and any pre-derived state live outside the measured
  region (in `b.iter`'s outer scope or iai-callgrind's
  `setup = ...` argument).
- The bench function's fixture parameter is the unified
  `(Box<Engine<S>>, TempDir)` shape (per the boundary rule
  below); the bench function returns the fixture rather than
  consuming it (per the symmetry rule below).
- The PR description pre-states the workload's amortizability
  class (per the hoisting rule below) so reviewers can verify
  criterion's reported median_ns is consistent with the
  pre-stated class.

The threshold sanity-check (§4.4) catches fixture leakage by
verifying the iai-callgrind `instructions` count is in the
expected range post-fixture: 20–40 instructions for
`synced_height`-class workloads (a few field accesses + one
method call, plus the unified-fixture-shape boundary cost);
proportional-to-N instructions for `balance`-class workloads
(linear walk over `transfers`) at the LedgerEngine PR.
Orders-of-magnitude-larger numbers — for example, millions of
instructions for `synced_height` — indicate either Engine
construction, fixture teardown, or fixture value-movement at
the boundary leaked into the measured region; the bench is
invalid pending fixture-shape investigation. See §4.4 for the
static check's three-cause resolution path.

**The symmetry rule (criterion-vs-iai-callgrind asymmetry).**
Setup and teardown are both excluded from the measured region;
measurement is the call only. This applies symmetrically to
fixture construction (already named above) and fixture
destruction. The two harnesses handle teardown differently,
which is the most common source of cross-harness divergence
on the same workload:

- **Criterion** amortizes drop cost implicitly. The fixture is
  built once outside `b.iter`; the closure body borrows it by
  reference; `Drop` runs at outer-function exit *after*
  `b.iter` returns; per-iteration time excludes drop because
  it's divided across millions of iterations and rounds to
  zero.
- **iai-callgrind** measures the full bench function body in
  a single shot. Any value moved into the bench function is
  dropped *inside* the measured region by default, and that
  drop is fully counted.

The asymmetry is structural — both harnesses are correct for
their measurement model — but it means the iai-callgrind side
needs explicit care to match what criterion does implicitly.
The mechanism is iai-callgrind's `teardown =` parameter, paired
with the `Box<Engine<S>>` indirection that the boundary rule
(below) requires:

```rust
fn drop_fixture(_f: (Box<Engine<SoloSigner>>, TempDir)) {}

#[library_benchmark]
#[bench::fresh_engine(setup = build_engine_fixture, teardown = drop_fixture)]
fn engine_trait_bench_ledger_synced_height(
    fixture: (Box<Engine<SoloSigner>>, TempDir),
) -> (Box<Engine<SoloSigner>>, TempDir) {
    let (engine, tmp) = fixture;
    let _ = black_box(engine.synced_height());
    (engine, tmp) // hand back to teardown
}
```

The bench function returns the fixture rather than consuming
it; iai-callgrind's `teardown` runs `drop_fixture` on the
returned value, and the actual `Drop` of `Engine` / `TempDir`
happens outside the measured region. The pattern is: **setup
builds; bench measures; bench returns the fixture; teardown
drops outside measurement.** The `Box<Engine<S>>` shape is
required by the boundary rule below; the symmetry rule and
the boundary rule together produce the unified fixture shape
`(Box<Engine<S>>, TempDir)` that both harnesses consume.

The diagnostic signal for a violation of this rule:
**order-of-magnitude divergence between the criterion and
iai-callgrind harnesses on the same workload.** If criterion
reports nanoseconds-per-iter consistent with a few cycles and
iai-callgrind reports tens-of-thousands of instructions, the
divergence is the fixture's `Drop` leaking into iai's
measurement. The order-of-magnitude check in §4.4 catches this
explicitly at the threshold-sanity-check step.

**This rule applies to all subsequent Stage 1 per-trait PR
benches.** Authors copy the template above and reviewers
verify the bench function returns its fixture (or returns a
value that doesn't drop expensively) before approving. The
shared `benches/common/engine_fixture.rs` provides a reusable
`drop_fixture` helper that the template above references.

**The boundary rule (iai-callgrind measures function-boundary
value movement).** iai-callgrind measures the *entire* bench
function body, including the memcpy that runs at function
entry (when arguments are passed by value) and at function
exit (when return values are returned by value). For small
fixtures this cost is negligible; for large fixtures it
dominates the measured number and obscures the call's actual
instruction count. The rule pairs with the symmetry rule:
where the symmetry rule excludes setup and teardown by moving
their *cost* outside the measured region, the boundary rule
keeps fixture *movement* outside the measured region by
ensuring what crosses the boundary is pointer-sized.

The mechanism: Valgrind models memcpy as a sequence of
instructions proportional to the bytes moved. At the
bench-function boundary, passing a value-typed fixture in
(and returning it out, per the symmetry rule's teardown
pattern) produces two memcpys whose instruction count scales
with the fixture's struct size. **`Engine<SoloSigner>` is
6,296 bytes at Stage 0 PR-2's HEAD** (load-bearing context
for fixture-shape decisions throughout Stage 1: every
per-trait PR's bench fixture inherits the same engine shape;
boundary cost would scale identically). Passing the engine
by value through the bench function produces ~600 instructions
of boundary cost — orders of magnitude larger than a
`synced_height`-class workload's actual ~5–10 instruction
cost.

**Resolution: pointer-sized indirection at the boundary.**
Wrap large fixture components in `Box<T>` so the
bench-function boundary moves only an 8-byte pointer (plus
any non-Box-wrapped siblings in the fixture tuple). The
fixture's type is `(Box<Engine<S>>, TempDir)`; total boundary
memcpy is `8 + sizeof::<TempDir>()` ≈ 32 bytes, well below
the modern x86-64 AVX-line-scale 64-byte heuristic (tighten
to 32 bytes if running on a runner with smaller vector units,
e.g. NEON/SSE-only hardware). The unified fixture shape
`(Box<Engine<S>>, TempDir)` is consumed transparently by both
harnesses:

- **iai-callgrind** receives the tuple by value through the
  bench function boundary at pointer cost (per the template
  in the symmetry rule above).
- **Criterion** captures `&fixture` by reference inside its
  `b.iter` closure; the closure body dereferences through
  the box (`engine.synced_height()` resolves through
  `Box`'s auto-deref) at zero pointer-chase cost beyond the
  one Valgrind already attributes to the call.

Criterion is not directly affected by the boundary rule
(closure capture by reference makes value-pass-at-boundary
moot for criterion's measurement model), but the unified
fixture shape means both harnesses share one
`build_engine_fixture` helper and one `drop_fixture` helper.

**Diagnostic signal for a violation of this rule:** the
order-of-magnitude check (§4.4) passes but the iai-callgrind
number sits in §4.4's "warning territory" (50–300 instructions
for `synced_height`-class workloads) without the workload
itself justifying that range. A reviewer who sees a number
in warning territory checks: was the fixture passed by value
across the bench-function boundary with any field exceeding
the 64-byte cutoff? If yes, the boundary rule applies; resolve
via `Box<T>` indirection.

**Fixture size matters: prefer `Box<T>` for large `T` at the
bench-function boundary.** Subsequent per-trait PRs follow
this template. The criterion for "large" is the 64-byte
heuristic at modern x86-64 AVX-line scale; any field of a
fixture tuple exceeding 64 bytes goes behind `Box`. Reviewers
verify each new bench's fixture-tuple total size against the
rule before approving.

**Stage 1 trait-extraction implications.** When `synced_height`
migrates from inherent method on `Engine<S>` to trait method
on `LedgerEngine`, the dispatched call receives `&self`
(`&Engine<S>`) by reference and the boundary cost is unchanged
— the trait-method dispatch doesn't move the engine across
the boundary. The boundary rule's relevance shifts from
"large fixture struct crosses the bench boundary" (current
concern) to "trait-method dispatch adds vtable indirection
inside the measured region" (Stage 1 concern, addressed by
§4.4's model-refinement path). The unified fixture shape
remains correct across the migration; the model's components
gain a vtable-indirection term.

**This rule applies to all subsequent Stage 1 per-trait PR
benches.** Authors copy the template above and reviewers
verify (a) the fixture tuple's total size, (b) the
Box-or-not declaration for any field exceeding 64 bytes,
and (c) the bench function's signature accepts and returns
the unified fixture shape. The shared
`benches/common/engine_fixture.rs` provides the
`build_engine_fixture` and `drop_fixture` helpers in the
canonical shape.

**The hoisting rule (criterion's iter-amortization model).**
Criterion's `b.iter` reports the **per-iteration time of the
inner loop**, which the optimizer may legally reduce below the
cost of a single call. For trivial pure-read benches (calls
that return a value from unchanging fixture state with no side
effects), the optimizer can hoist the call out of the loop —
common subexpression elimination, loop-invariant code motion —
leaving criterion's median_ns dominated by loop overhead rather
than call cost. This is **correct behavior**, documented by
`b.iter`'s contract: the harness reports per-iteration time of
the inner loop, which the compiler is permitted to optimize.

The two harnesses measure different things:

- **Criterion** runs the bench body inside an N-iteration loop
  to amortize timing overhead. The number is informative as
  "the optimizer can hoist this across N iterations"; it is
  *not* informative as "one call costs N picoseconds."
  `black_box` prevents the optimizer from eliminating the
  result entirely but does not prevent it from hoisting the
  call's *body* out of the loop.
- **iai-callgrind** invokes the bench function once per
  measurement and instruments at the assembly level. Valgrind
  counts every executed instruction; the optimizer cannot
  amortize *executed* instructions across measurements that do
  not loop. iai is amortization-immune by construction.

This is why iai is the Tier-1 gate metric and criterion is
Tier-2 informational: a future reader reconciling a criterion
median_ns of 622 ps with an iai instruction count of 10 (the
60 ps-per-instruction implication, ~16 GHz IPC, implausible)
should reach for the hoisting rule first — the two harnesses
are measuring different things, not the same thing with one of
them broken.

**Workload purity classes determine expected hoisting
behavior.** The per-trait PR author pre-states the workload's
class as part of §4.4's normative checklist:

- **Trivial pure-read class** (criterion is hoisted; per-iter
  time can be ≪ per-call cost). Examples: `synced_height`
  (returns a `u64` field through a chain of immutable
  references); `parameters_snapshot` (returns a value computed
  from fixture state that does not change between iterations
  on the same fixture). Criterion's median_ns is informative
  about amortization success, not call cost.
- **State-dependent compute class** (criterion is not hoisted;
  per-iter time ≈ per-call cost). Examples: `balance` (linear
  walk over `transfers` whose result depends on the fixture's
  populated state); `current_emission(height)` with `height`
  varying per-iteration via `b.iter_batched`. Criterion's
  median_ns is informative about call cost, converted to
  wall-clock time.

The classification is not always binary.
`current_emission(height)` with constant `height` is hoistable;
with varying `height` (via `b.iter_batched`) it is not. The
per-trait PR author chooses the criterion harness mode (`b.iter`
vs `b.iter_batched`) and pre-states the resulting class so
reviewers verify the actual capture matches.

**Diagnostic signal for a violation of this rule:** captured
criterion median_ns and iai-callgrind instructions disagree on
their workload-class implications. If criterion's number
suggests trivial-pure-read (per-iter time ≪ per-call cost
converted to time) but iai's instruction count suggests
state-dependent compute (proportional to N for some N implied
by the fixture), the harness mode is wrong: the author picked
`b.iter` for a class that wants `b.iter_batched`, or vice-versa.
Reviewers verify the harness-mode choice matches the workload's
actual amortizability.

**This rule applies to all subsequent Stage 1 per-trait PR
benches.** Authors copy the workload-class taxonomy when
drafting their PR description's pre-stated expectations;
reviewers verify the captured criterion behavior matches the
pre-stated class before approving. The §4.4 normative
checklist's "Pre-stated expected criterion behavior" item
operationalizes the verification.

**Why this distribution (gap-check meta-pattern).** Stage 0
PR-2's scope is the result of seven structural findings the
pre-drafting gap-check (Findings 1–4) and threshold
sanity-checks on successive captures (Findings 5–7) produced
before the baseline was transcribed:

1. **Finding 1** (resolved at the first design-doc tightening,
   §4.1): the §3.3.1 hot paths label trait-method surfaces that
   do not exist on `Engine<S>` today. Resolution: benches measure
   the **today-equivalent call path**; §4.1 enumerates each
   path's today equivalent. The cumulative-delta semantics
   anchor temporally (Stage 0 SHA → Stage-1-final SHA), not
   surface-shape-wise.
2. **Finding 2** (resolved at the second design-doc tightening,
   §4.2's per-bench frozen baseline): three of the five §3.3.1
   workloads do not exist as identifiable units anywhere in the
   V3.0 codebase. Resolution: those benches are deferred to
   their introducing per-trait PR; each bench's frozen-baseline
   SHA is the SHA where its workload first exists as a unit.
3. **Finding 3** (resolved here, §4.2's fixture-construction
   approach): no existing infrastructure constructs a real
   `Engine` for benches. Three options were considered (Path A:
   real Engine via `Engine::create` with a `benches/common/`
   shared helper; Path B: `bench-internals` constructor with
   cross-crate stubs; Path C: expose `EngineCreateParams::for_test_full`
   via `bench-internals`). Resolution: **Path A**, per the
   visibility-expansion principle above. Bench fixtures
   duplicate test-helper logic locally rather than widening
   test-helper visibility.
4. **Finding 4** (resolved here, §4.2's per-bench frozen
   baseline): `LedgerEngine::balance`'s representative
   measurement requires a state-populated fixture with thousands
   of `transfers`; the only legitimate route to populate that
   state is driving the production scan loop through a mock
   daemon, and that infrastructure (`MockDaemon`, per §6.1 of
   the trait spec) is introduced by Stage 1 PR 1 (DaemonEngine).
   Resolution: `balance` is deferred to the **LedgerEngine PR**
   (post-PR-1, with MockDaemon available); its frozen baseline
   is captured at the LedgerEngine PR's merge SHA against a
   state-populated fixture.
5. **Finding 5** (resolved here, §4.2's symmetry rule and
   §4.4's order-of-magnitude check): the first
   `workflow_dispatch` capture of
   `engine_trait_bench_ledger_synced_height` reported 60,033
   instructions where §4.4's component model predicted 20–40
   (a 1,500–3,000× divergence).
   Investigation traced the contamination to fixture `Drop`
   running inside iai-callgrind's measured region — a
   structural property of iai-callgrind's single-shot
   measurement model that doesn't amortize cleanup the way
   criterion's `b.iter` does. The criterion sibling reported
   0.62 ns/iter (consistent with a few cycles), confirming the
   actual `synced_height` call cost is on the expected order
   and that the divergence between the two harnesses is the
   diagnostic signal §4.2 names. Resolution: §4.2's "symmetry
   rule" — setup and teardown are both excluded from the
   measured region — operationalized through iai-callgrind's
   `teardown =` parameter, with a concrete template that
   subsequent per-trait PRs copy. The fix is **class-level**:
   every `engine_trait_bench_*` bench inherits the symmetry
   rule and the `drop_fixture` helper from
   `benches/common/engine_fixture.rs`, not just `synced_height`.
6. **Finding 6** (resolved here, §4.2's boundary rule and
   §4.4's warning-territory check): the second
   `workflow_dispatch` capture of
   `engine_trait_bench_ledger_synced_height` (after Finding 5's
   symmetry-rule fix landed) reported 637 instructions where
   §4.4's tightened expectation predicted 20–40. Investigation
   traced the contamination to memcpy at the bench-function
   boundary — passing the 6,296-byte `Engine<SoloSigner>`
   struct by value into and out of the bench function produced
   ~600 instructions of boundary cost. The criterion sibling
   reported a stable few-nanoseconds-per-iter, confirming the
   call's actual cost remained on the model's predicted order;
   iai-callgrind's measurement was capturing a structural
   property of value-pass-at-boundary that criterion's
   by-reference closure capture doesn't experience. Resolution:
   §4.2's "boundary rule" — pointer-sized indirection at the
   bench-function boundary, via `Box<T>` for large fixture
   components — operationalized through the unified fixture
   shape `(Box<Engine<S>>, TempDir)`. The fix is
   **class-level**: every `engine_trait_bench_*` bench inherits
   the boundary rule and the boxed-engine fixture shape from
   `benches/common/engine_fixture.rs`, not just `synced_height`.
7. **Finding 7** (resolved here, §4.2's hoisting rule and
   §4.4's two-anchor component model): the third
   `workflow_dispatch` capture of
   `engine_trait_bench_ledger_synced_height` (after Findings 5
   and 6's symmetry- and boundary-rule fixes landed) reported
   10 instructions, matching §4.4's component-model prediction
   at the lower bound. The criterion sibling reported 622 ps
   median per iteration, which implies ~16 GHz instructions per
   second at the iai-derived 10 instructions per call —
   implausible on the runner hardware. Investigation traced
   the disagreement to criterion's `b.iter` amortizing the
   trivial pure-read across N iterations: the optimizer hoists
   `synced_height`'s field-access chain out of the inner loop,
   leaving per-iteration time dominated by loop overhead
   rather than call cost. The disagreement is not a
   contamination but a structural property of criterion's
   measurement model — per `b.iter`'s contract, the optimizer
   is permitted to amortize work across iterations. Resolution:
   §4.2's "hoisting rule" — criterion's iter-amortization
   model is named explicitly, workload purity classes (trivial
   pure-read vs state-dependent compute) are pinned, and §4.4's
   component model becomes two-anchor (predicts both iai
   instructions and criterion median_ns from the same workload
   primitives, with hoisting amortization as the bridge term).
   The fix is **class-level**: every `engine_trait_bench_*`
   bench inherits the hoisting-rule classification, and the
   per-trait PR description checklist gains a fifth item
   ("Pre-stated expected criterion behavior") that forces each
   per-trait PR author to name the workload's amortizability
   class up front.

The seven findings share a structural feature: each is a case
of "the discipline named a measurement model; investigation
revealed a structural mechanism affecting that model; the
design had not named the mechanism, and the captured number
diverged from the predicted shape until the mechanism was
named." This is not a flaw in the discipline or the design
doc — the discipline's purpose is to name the property, the
design doc's purpose is to operationalize it, and both depend
on iterative verification against today's code (Findings 1–4)
and the harness's actual behavior (Findings 5–7). The
pre-drafting gap-check between PR-1 (design) and PR-2
(implementation) is the verification step where future-state
claims meet today's code; threshold sanity-checks at
successive `workflow_dispatch` captures (Findings 5–7) are
the verification steps where the design's claims meet the
harness's actual behavior — each capture's sanity-check
surfaces a structural property the design had not named, and
closing each by naming the property matures the substrate.
Findings 5, 6, and 7 were surfaced by *successive* captures
because each closure changed the shape of what the next
capture could measure: with `Drop` excluded (Finding 5
resolved), the previously-hidden boundary memcpy became the
dominant cost (Finding 6 surfaced); with both excluded
(Finding 6 resolved), the previously-hidden criterion-vs-iai
magnitude disagreement became visible (Finding 7 surfaced);
with all three named, both numbers sit at the model's
predicted order under the two-anchor component model.

**Pre-stated expectations are load-bearing.** Without §4.4's
explicit component-model expectation (20–40 for
`synced_height`-class workloads with the unified-fixture-shape
boundary cost; proportional-to-N for `balance`-class workloads),
60,033 instructions (Finding 5) and 637 instructions (Finding 6)
could each have been silently transcribed into
`PERFORMANCE_BASELINE.md` as the frozen baseline; the rolling
discipline would inherit the contamination and every per-trait
PR's cumulative-delta computation would be diffing against a
Drop-dominated or boundary-memcpy-dominated number. The
pre-stated expectation is what makes a divergence *meaningful*;
the number alone says nothing. Per §4.4's per-trait PR
description checklist, every new `engine_trait_bench_*` bench
pre-states an expected range (with component model) in its PR
description and the bench file's header comment.

**Resolutions are class-level, not one-off.** Findings 2–7
each surfaced through one specific bench (the workload-size
question for `balance`; the test-helper-visibility question
for the `synced_height` fixture; the workload-doesn't-exist
question for the three deferred benches; the
Drop-contamination question for the `synced_height` capture;
the boundary-memcpy question for the `synced_height`
re-capture; the criterion-iai-disagreement question for the
post-Box re-capture), but the resolution in each case is a
class-level rule that every bench in the family inherits.
This is deliberate: a one-off patch on the surfacing bench
would leave the next per-trait PR author rediscovering the
same problem. The symmetry rule (Finding 5), the boundary
rule (Finding 6), and the hoisting rule (Finding 7) all
apply to all `engine_trait_bench_*` benches, not just the
one whose capture surfaced them; the unified fixture shape
`(Box<Engine<S>>, TempDir)` operationalizes the symmetry and
boundary rules at the fixture layer, and §4.4's normative
checklist operationalizes the hoisting rule at the
PR-description layer, both for every per-trait PR's bench at
once.

The **single principle** that resolved all seven findings:
*a measurement that doesn't measure what it claims to measure
corrupts the discipline depending on it.* The principle is
verifiable: compare what the bench's name, the gate's
contract, and the predictive model claim it measures against
what the actual capture demonstrates it measures; the
discipline catches divergence. A baseline that re-baselines
isn't a baseline (Finding 2); a fixture that bypasses
production isn't a fixture (Finding 3); a number measured
against fresh-engine isn't a representative number for
state-dependent workloads (Finding 4); a measurement
dominated by Drop cost isn't a measurement of the call
(Finding 5); a measurement dominated by boundary memcpy
isn't a measurement of the call either (Finding 6); a
measurement amortized across iterations isn't a per-call
measurement (Finding 7). The design's scope is the result of
this principle applied uniformly: **benches measure their
workloads at the SHA where those workloads first exist as
measurable units through representative fixtures with
correctly-bounded measurement regions and explicitly-classified
amortization shape**, not earlier and not against synthetic
compositions, with neither construction, nor teardown, nor
boundary value-movement leaking into the iai measurement, and
with the criterion measurement's amortization shape pre-stated
so the cumulative-delta discipline knows what its baseline
represents.

Stage 0 PR-2 ships the harness substrate
(criterion + iai-callgrind discipline; new bench class; routing;
CI integration; `workflow_dispatch` enablement; the shared
`benches/common/` fixture) plus one populated bench
(`synced_height`) that validates the substrate end-to-end. Stage
1 per-trait PRs introduce their workloads alongside their bench
captures; the §3.3.1 cumulative-delta discipline scales across
the full Stage 1 surface.

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

**Threshold sanity-check (Stage 0 PR-2 part 4).** Two checks
required for a valid baseline; both run at the
`workflow_dispatch` capture. The order-of-magnitude check is
the **static** test (one number, one comparison) and runs
first because a number that fails it is invalid regardless of
how it varies; the determinism check is the **dynamic** test
(N numbers, equality comparison) and runs against the validated
shape.

**Static check: two-anchor expected-value comparison against
a component model.** Verify both captured numbers are
consistent with the predicted shape per §4.2's
measurement-region discipline: the iai-callgrind `instructions`
count's absolute range (the **iai anchor**), and criterion's
median_ns relative to iai's per-call cost (the **criterion
anchor**, with the relationship determined by the workload's
amortizability class per §4.2's hoisting rule). The expected
ranges are computed from a **component model** of the call's
actual cost plus the unified-fixture-shape boundary cost, not
a single order-of-magnitude estimate; with the symmetry rule,
boundary rule, and hoisting rule all in force, both anchors
are predictable to within a small constant.

**`synced_height`-class workloads (a few field accesses +
one method call) plus a unified-fixture bench-function
boundary:**

- **Expected (~20–40 instructions).** Component model: 4–6
  instructions for the call body (a chain of field accesses
  returning `u64`, with `black_box` on the result); 5–10 for
  the bench-function boundary memcpy (8-byte
  `Box<Engine<S>>` pointer plus `TempDir` plus alignment;
  passing the fixture tuple in and returning it out per the
  symmetry rule); a small overhead for setup/teardown wiring
  that iai-callgrind doesn't fully exclude. The 20–40 range
  bounds the model's components plus reasonable
  per-runner-architecture variance in instruction
  decomposition.
- **Warning territory (50–300 instructions).** Worth
  investigating before transcription. Three reviewer checks
  apply when a measurement lands here:
  1. **Did the fixture cross the bench-function boundary by
     value with any field exceeding 64 bytes?** (The 64-byte
     cutoff is a heuristic at modern x86-64 AVX-line scale;
     tighten to 32 bytes if running on a runner with smaller
     vector units, e.g. NEON/SSE-only hardware.) → likely
     boundary-rule violation; resolve via `Box<T>`
     indirection per §4.2's boundary rule.
  2. **Did fixture setup involve hardware-RNG instructions
     that leaked into the measured region?** → likely
     `RDRAND` leakage (cause 2 below); move RNG-touching
     code into setup, outside the measured region.
  3. **Is the called workload genuinely larger than the
     model assumed** (e.g., the trait method dispatches
     through a vtable that touches additional instructions
     of indirection beyond a direct field-access chain)?
     → tighten the model with the additional component;
     refresh the expected range; document the refinement
     in the PR description so subsequent per-trait PRs
     inherit the corrected model.
- **Invalid (>300 instructions).** The gap from prediction
  to measurement is too large for the number to represent
  the workload at the predicted shape. Investigation must
  close before transcription. The number does not enter
  `PERFORMANCE_BASELINE.md`.

**`balance`-class workloads (linear walk over `transfers`):**
Proportional to N where N is the number of `transfers` in
the fixture. The per-trait PR's design notes pre-state both
the expected per-element instruction cost and the fixture's
N; the static check verifies the captured count against
`N × per_element_cost + boundary_cost`. Same warning-territory
and invalid bands apply, scaled by N.

**Criterion anchor: per-iteration time relationship to iai
per-call cost.** Criterion's median_ns is predicted from iai's
instruction count via
`(instructions × per-instruction-time-on-runner) / amortization_factor`,
where `per-instruction-time-on-runner` is ~0.3–0.5 ns on
`ubuntu-latest` (typical x86-64 IPC under release-mode
optimization) and `amortization_factor` is set by the workload's
purity class (per §4.2's hoisting rule):

- **Trivial pure-read class** (synced_height,
  parameters_snapshot if returning a snapshot):
  amortization_factor can be ≫ 1. Criterion's median_ns may be
  ≪ iai's per-call time. *Example:* iai 10 instructions ×
  0.3–0.5 ns ≈ 3–5 ns per call; criterion reports 622 ps
  (0.6 ns), implying amortization_factor ≈ 5–8×. This is the
  expected shape for the class; a number close to iai-derived
  per-call time would be the *unexpected* shape and forces
  investigation.
- **State-dependent compute class** (balance,
  current_emission with varying input): amortization_factor ≈ 1.
  Criterion's median_ns should be ~iai-derived per-call time.
  A significantly lower number indicates the harness mode is
  wrong (the bench uses `b.iter` for a class that wants
  `b.iter_batched`).

The criterion anchor is verified **qualitatively** (right
relationship for the class), not quantitatively (exact
amortization_factor). Per-runner instruction-time variance
plus per-runner amortization-factor variance compound; setting
a tight criterion threshold against the iai number would
conflict with the runner-portability framing in §4.5
(criterion median_ns is recorded for completeness but is not
the gate metric and is not expected to be portable across
runner hardware).

**Four causes for static-check failures, in order of
likelihood:**

1. **Fixture teardown leaking into the measured region** —
   the bench function takes ownership of the fixture and
   `Drop` runs inside the measured region. Verify the bench
   function returns its fixture (or returns a value that
   doesn't drop expensively) and uses iai-callgrind's
   `teardown =` parameter for the actual cleanup. Per the
   symmetry rule in §4.2, setup and teardown are both
   excluded from the measured region.
2. **Hardware-RNG instruction leakage** — `RDRAND`-class
   instructions are modeled non-deterministically by
   Valgrind, which inflates the measured count and also
   defeats the determinism check below. None of the five
   §3.3.1 read paths should hit hardware RNG on the
   measured call; if the bench function does, the
   RNG-touching code lives in the fixture build and needs
   to move outside the measured region.
3. **Value-passing of large structs through the
   bench-function boundary** — iai-callgrind measures the
   memcpy at function entry and exit. A fixture tuple field
   exceeding the 64-byte cutoff that crosses the boundary by
   value adds boundary cost proportional to the bytes
   moved. Per the boundary rule in §4.2, large fixture
   components go behind `Box<T>` so the boundary moves only
   an 8-byte pointer.
4. **Criterion median_ns and iai instructions disagree on
   workload class** — criterion reports a per-iteration time
   suggesting trivial pure-read (≪ iai-derived per-call cost
   converted to time) but iai's instruction count suggests
   state-dependent compute (proportional to the fixture's N
   for a non-trivial N), or vice-versa. The bench's harness
   mode is inconsistent with the workload: `b.iter` is being
   used for a state-dependent compute class (so the
   optimizer-pressure that `b.iter_batched` would prevent
   leaks into the measurement), or `b.iter_batched` is being
   used for a trivial pure-read class (so per-iteration
   batching overhead obscures the actual amortization shape).
   Per the hoisting rule in §4.2, the per-trait PR author
   chooses the harness mode based on the workload's
   amortizability class and pre-states the resulting expected
   relationship; reviewers verify the actual capture matches.

**The model is a prediction, not a contract.** The 20–40
range is the design's prediction of the workload's actual
cost given the model components above. It is not a target
benches must hit; it is an expectation the discipline
validates or refines. A measurement that lands in the
expected range is a *necessary-but-not-sufficient* condition
for transcription — the discipline still requires the
determinism check (below) and the per-trait PR's structural
review against the substrate's accumulated rules. A
measurement that lands outside the range forces
investigation; investigation may refine the model (if the
workload is genuinely larger than predicted) or close a
contamination (if the workload is the predicted size and
the boundary or teardown is leaking). Pinning the model as
"prediction, not contract" prevents the fast-path acceptance
pattern where a measurement lands in the upper edge of the
expected range and ships without scrutiny; the model is a
sanity check, not a passing grade.

**Pre-stated expectations are load-bearing.** The static
check is **only meaningful with a pre-stated expectation**:
60,033 instructions on its own says nothing; 60,033
instructions against a pre-stated expectation of "20–40
per the synced_height-class model" is a 3,000× divergence
that forces investigation. Without the pre-stated
expectation, an invalid measurement transcribes silently
into `PERFORMANCE_BASELINE.md` and the discipline depending
on it inherits the contamination. The per-trait PR
description checklist (below) operationalizes this
obligation as a normative requirement.

**Per-trait PR description checklist (normative).** Every
Stage 1 per-trait PR introducing a new
`engine_trait_bench_*` bench must include the following five
items in its PR description; reviewers gate on all five. A
PR description missing any item is not reviewable until the
missing item is added.

1. **Pre-stated expected order-of-magnitude (or range) for
   iai-callgrind `instructions`.** Either a single number
   (e.g., "expected ~25 instructions") or a range (e.g.,
   "expected 20–40 per the synced_height-class model"),
   with the component model named. The pre-stated
   expectation is the anchor against which the static check
   applies; a bench whose design notes do not pre-state an
   expectation fails review on the missing anchor before a
   baseline is captured.
2. **Fixture tuple total size in bytes**, with explicit
   Box-or-not declaration for any field exceeding the
   64-byte cutoff. The total boundary cost (~5–10
   instructions for an all-pointer-sized tuple) is part of
   the model in item 1; a fixture whose fields cross the
   64-byte threshold without `Box<T>` indirection violates
   §4.2's boundary rule and must be revised before capture.
3. **Capture sequence.** N=3 `workflow_dispatch` runs on
   the PR's branch tip; iai-callgrind determinism asserted
   as ±0% across the runs (per §4.4's dynamic check). The
   PR description records the three numbers; the static
   check runs against any one of them (they're equal); the
   dynamic check runs against the trio.
4. **Known sources of contamination this PR's bench cannot
   hit.** Enumerate the inherited substrate rules
   (symmetry rule per §4.2; boundary rule per §4.2;
   hoisting rule per §4.2; per-bench frozen-baseline-SHA
   alignment per §4.2 / §4.5; visibility-expansion principle
   per §4.2; today-equivalent call path per §4.1) and assert
   non-violation for each. The PR description records the
   assertions; reviewers verify each assertion against the
   bench file's actual shape. This bullet is the load-bearing
   one — it forces each PR author to enumerate the
   substrate's accumulated state and confirm their bench is
   outside each rule's failure surface, producing a *positive
   verification* rather than absence-of-finding.
5. **Pre-stated expected criterion behavior.** Name the
   workload's amortizability class (trivial pure-read or
   state-dependent compute, per §4.2's hoisting rule) and
   pre-state criterion's expected median_ns relative to iai's
   per-call cost. Two example forms:
   - *"Trivial pure-read class: criterion median_ns expected
     ≪ iai-derived per-call time (estimate: amortization_factor
     of 5–10×, criterion median_ns < 1 ns for a synced_height-
     class workload)."*
   - *"State-dependent compute class: criterion median_ns
     expected ≈ iai-derived per-call time (estimate:
     amortization_factor ≈ 1, criterion median_ns ≈
     instructions × 0.3–0.5 ns)."*

   The pre-statement names the harness-mode choice (`b.iter`
   vs `b.iter_batched`) explicitly. Reviewers verify the
   captured criterion behavior matches the pre-stated class;
   a divergence forces investigation per §4.2's hoisting-rule
   diagnostic before transcription. This item is the
   criterion-side counterpart of item 1 (which pre-states
   the iai expectation); together they anchor §4.4's
   two-anchor static check at the PR-description layer.

The bench file's header comment mirrors items 1, 2, and 5
(the "Expected post-fixture instructions" + "Expected
criterion behavior" sections, per the convention established
by `engine_trait_bench_ledger_synced_height_iai.rs`). Items 3
and 4 live in the PR description only.

**Dynamic check: iai-callgrind determinism across N runs.**
Re-run iai-callgrind across N runs on `ubuntu-latest`.
**Confirm** variance is ±0% (Valgrind is deterministic for
typical code); do not assert it. Non-zero variance with the
static check passing typically points to hardware-RNG leakage
(cause 2 above) — the bench itself is shape-correct but the
fixture is touching `RDRAND`-class instructions during setup
that Valgrind models as non-deterministic. Re-run criterion
across N runs; record the wall-clock variance for the host
manifest. The dynamic check confirms the gate-metric is
coherent against the thresholds; it does not aim to prove
criterion wall-clock is precise (it isn't, on shared runners).

**Per-capture finding budget (substrate maturation, not
discipline failure).** The threshold sanity-check is *expected*
to surface findings — not because the discipline is broken,
but because the substrate has accumulated contamination layers
that successive captures peel off. Each finding closes one
layer; the substrate matures toward a steady state of zero
findings per capture. The trajectory is monotonic:
contamination layers don't regenerate once closed at
class-level (per the "Resolutions are class-level" principle
in §4.2).

Stage 0 PR-2's substrate-maturation cost paid up front: two
sanity-check captures surfaced two contamination layers
(Drop, then memcpy boundary), each closed at design-doc
level with class-wide rules that subsequent benches inherit.
Future per-trait PRs are expected to surface fewer findings
per capture as the substrate matures. **Both directions of
the signal are load-bearing**: a clean first capture
*late* in Stage 1 validates the substrate's maturation; a
clean first capture *now* would suggest the sanity-checks
are too weak to find what's there. If four deferred per-trait
PRs all produce clean first captures, that's news worth
investigating; if they each produce one or two findings that
close cleanly, that's the expected substrate-maturation
rhythm.

The discipline's failure mode under wrong framing would be:
"the gap-check produces N findings per capture; therefore the
gap-check is broken; therefore we should weaken the
sanity-checks or accept results without them." Each step is
wrong, but the wrongness compounds — and the resulting
steady state would be weakened sanity-checks that miss real
contamination. The right framing makes findings *and* their
absence carry information, and prevents the reasoning failure
under future "but we're surfacing too many findings" pressure.

**Gap-check shifts with PR scope.** The pre-drafting
gap-check's findings shift across PRs as the substrate
matures and as the surface under measurement changes:

- **Stage 0 PR-1 (design)** surfaced design→discipline gaps:
  did the design's framing match the discipline it was
  operationalizing? Findings were documentation-level and
  closed at design-doc-tightening rounds.
- **Stage 0 PR-2 (implementation)** surfaced
  design→implementation gaps (Findings 1–4) and
  design→harness-behavior gaps (Findings 5–6 — the symmetry
  rule and the boundary rule, respectively). Findings closed
  at design-doc level (rule additions) and propagated through
  implementation in the per-bench fix commits.
- **Stage 1 per-trait PRs** inherit the closed substrate.
  Their gap-checks surface trait-specific gaps:
  trait-method-dispatch overhead vs. the predicted model;
  fixture-state-population shape gaps (LedgerEngine PR's
  `balance` fixture); fixture-construction gaps for new
  trait surfaces (KeyEngine PR's account-address fixture).
  The substrate's accumulated rules apply by default; the
  per-trait PR's gap-check focuses on the trait's
  incremental surface.

Each PR's gap-check is bounded by what the substrate's
accumulated state has already named. Future per-trait PRs
are expected to surface different finding *shapes* than
Stage 0 PR-2's Findings 1–6; the per-capture-finding-budget
paragraph above quantifies the expected *number*, but the
*kind* of finding shifts with each PR's scope.

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

   **Stage 0 PR-2's own gate run on first introduction.** PR-2
   touches both watched paths and `scripts/bench/` (routing
   entries) and adds the bench files in the same commit, so the
   `pull_request` gate runs on PR-2 itself and encounters the new
   `engine_trait_bench_*` entries with no baseline counterpart.
   The existing `compare.py` (lines 165–255) routes such entries
   into the `added_in_pr` list, which is **informational**:
   `has_fail = (fail > 0) OR bool(missing_in_pr)`, so added
   entries do **not** trip the gate. This is also documented in
   [`docs/benchmarks/README.md`](../benchmarks/README.md):
   "An entry present in the PR but not the baseline is
   informational; the first merge to `dev` seeds it into the
   rolling baseline." On PR-2's merge to `dev`, the
   `update-baseline` job absorbs the new entries into
   `bench-baseline/baseline.json`. From the next Stage 1 PR
   onward, the gate runs against the seeded rolling baseline.

   No additional first-commit-with-placeholder-baselines step is
   required; the existing harness handles new-bench introduction
   correctly without it.
2. **Capture script.** Add **one** row to the `BENCHES` array in
   [`scripts/bench/capture_rust_baseline.sh`](../../scripts/bench/capture_rust_baseline.sh)
   for the Stage-0-frozen bench (`synced_height`), following the
   existing `crate:criterion-target:iai-callgrind-target` shape.
   The Stage-0-frozen bench compiles to its criterion +
   iai-callgrind sibling pair under the new naming convention.
   Each Stage 1 per-trait PR that introduces a deferred bench
   appends its own `BENCHES` row at that PR.
3. **Compare classifier.** Add a third branch to the `classify()`
   function in
   [`scripts/bench/compare.py`](../../scripts/bench/compare.py)
   matching `engine_trait_bench_*`, with `verdict_for()` extended
   to apply the bidirectional ±10% warn / ±25% fail thresholds.
   The classifier change covers all five benches by class
   membership; per-trait PRs introducing deferred benches do not
   need to touch the classifier.
4. **PR-comment surface.** No change. The existing
   `post_comment.py` renders all entries from the report; new
   entries appear automatically.
5. **Manifest extension.** Add a new section to
   [`docs/benchmarks/shekyl_rust_v0.manifest.md`](../benchmarks/shekyl_rust_v0.manifest.md)
   for the **Stage-0-frozen bench** (`synced_height`), following
   the existing manifest section template (operation list,
   fixture shape, known gaps). Add **four placeholder sections**
   for the deferred benches naming the target Stage 1 per-trait
   PR (per §4.6's per-bench deferred assignment); each per-trait
   PR replaces its placeholder section with the populated content
   when the deferred bench enters the harness.

**Freeze-vs-rolling baseline reconciliation.** Trait-spec §3.3.1
requires a **frozen** baseline, per-bench, captured at the SHA
where each bench's workload first exists as a measurable unit
through a representative fixture (per §4.2's per-bench
frozen-baseline framing — one rule, no two-rule asymmetry).
Stage 0 PR-2's merge SHA is the introducing SHA for
`engine_trait_bench_ledger_synced_height`; each Stage 1
per-trait PR's merge SHA is the introducing SHA for that PR's
bench(es) (per §4.6's per-bench deferred assignment). The
existing `bench-baseline` is **rolling**, refreshed on every
push to `dev`. Two readings of "the per-PR delta" coexist:

- **CI-gate delta** (rolling): each PR's iai-callgrind delta
  against `bench-baseline/baseline.json` at the moment the gate
  runs. This is what the workflow enforces. As Stage 1 PRs land
  on `dev`, each subsequent PR's gate runs against the previous
  PR's post-merge state (the rolling baseline). The gate catches
  per-PR regressions but does not show cumulative delta across
  all Stage 1 PRs.
- **Cumulative-delta citation** (frozen, per-bench): each Stage
  1 PR's description cites both numbers — the CI-gate delta
  against the rolling baseline (gated; what the workflow says),
  and the cumulative delta against
  [`docs/PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md)'s
  frozen numbers (citation only; what reviewers consult for "did
  the trait extraction as a whole stay within budget"). The
  §3.3.1 cumulative-delta contract ("no extraction adds more
  than 25% read-path overhead, cumulatively, across Stage 1")
  applies per-bench: for each bench, "cumulatively" sums the
  deltas across all Stage 1 PRs starting from **that bench's**
  introducing SHA. The temporal anchor shifts per-bench; the
  contract shape is uniform. Stage 1 PR descriptions list one
  cumulative-delta line per bench currently in scope at that PR,
  each citing the bench's specific frozen-baseline SHA.

Why both. The CI gate is the per-PR enforcement signal; it
catches a single PR introducing a >25% regression even if prior
PRs were fine. The frozen-baseline citation is the trait-spec
§3.3.1 cumulative-delta signal; it catches "each PR added 5%, the
last one tripped 25% over Stage 0 baseline" patterns. Both are
necessary; they answer different questions.

`PERFORMANCE_BASELINE.md`'s post-interior-lock table
(per-Stage-1-PR delta column) records the frozen-baseline delta
each PR introduces, computed against each bench's frozen numbers
at that bench's introducing-PR SHA (per the one-rule per-bench
disposition above). Reviewers cite the table during Stage 1 PR
review; the document is the canonical source of cumulative delta.

**Worked example (illustrative).** Suppose Stage 1 unfolds as
PR 1 = DaemonEngine, PR 2 = LedgerEngine, PR 3 = KeyEngine,
PR 4 = EconomicsEngine. The one-rule shape produces a uniform
"first measurement at the introducing PR; cumulative delta from
there" pattern for every bench:

- **`engine_trait_bench_ledger_synced_height`** (frozen at Stage
  0 PR-2's SHA). PR 1 cites cumulative delta against PR-2's SHA;
  PR 2 cites the running cumulative; PR 3 and PR 4 likewise.
  Stage 1 PR 3's description reads (illustratively): "CI-gate
  delta against rolling baseline: +4% (passes ±10% warn, ±25%
  fail). Cumulative delta against
  `engine_trait_bench_ledger_synced_height` frozen baseline at
  Stage 0 PR-2's SHA: +15% (between 10% warn and 25% fail
  thresholds; justification per trait-spec §3.3.1: combined
  trait-dispatch overhead is within budgeted total)."
- **`engine_trait_bench_ledger_balance`** (frozen at PR 2's SHA,
  per §4.6's per-bench deferred assignment — `balance` introduced
  alongside `LedgerEngine`'s trait method on a state-populated
  fixture using PR 1's MockDaemon infrastructure). PR 2's own
  description cites cumulative delta of zero by definition (the
  bench just got introduced). PR 3 re-runs the bench against the
  seeded rolling baseline and cites cumulative delta against
  PR 2's SHA — a non-zero number for the first time.
- **`engine_trait_bench_economics_current_emission` and
  `engine_trait_bench_economics_parameters_snapshot`** (frozen at
  PR 4's SHA — both introduced alongside their trait methods on
  a fixture appropriate to economics-layer state). PR 4's CI
  gate encounters the new entries with no baseline counterpart
  and routes them into `added_in_pr` (informational; non-gating
  per §4.5 item 1). PR 4's description cites cumulative delta of
  zero by definition. After PR 4 merges, `update-baseline` seeds
  the new entries; the next post-PR-4 Stage 1 PR cites cumulative
  delta against PR 4's SHA.

A representative Stage 1 PR's description carries one
cumulative-delta line per bench currently in scope at that PR,
each against its bench's specific frozen-baseline SHA. The
contract shape — "cumulative delta against the frozen baseline,
where 'cumulative' means summed across all Stage 1 PRs starting
from this bench's introducing SHA" — is identical for every
bench; only the temporal anchor differs.

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

**Per-bench deferred assignment.** Per §4.2's per-bench
frozen-baseline framing, four of the §3.3.1 hot paths defer
their bench introduction to a Stage 1 per-trait PR (three
because the workload doesn't exist as a unit at Stage 0, per
§4.1's "Note on the today-equivalent call path"; one because
representative measurement requires state-population
infrastructure introduced by Stage 1 PR 1, per §4.2's "Why
benches are deferred"). Explicit assignment:

- **LedgerEngine PR** introduces
  `engine_trait_bench_ledger_balance` (criterion + iai-callgrind
  sibling) along with the trait method on a state-populated
  fixture (using `MockDaemon`-driven scan from Stage 1 PR 1, per
  §6.1 of the trait spec, to populate `transfers` to a
  representative size). The bench's frozen baseline is captured
  at the LedgerEngine PR's merge SHA per §4.5's per-bench-SHA
  disposition.
- **KeyEngine PR** introduces
  `engine_trait_bench_key_account_public_address` (criterion +
  iai-callgrind sibling) along with the trait method. The bench's
  frozen baseline is captured at the KeyEngine PR's merge SHA.
- **EconomicsEngine PR** introduces both
  `engine_trait_bench_economics_current_emission` and
  `engine_trait_bench_economics_parameters_snapshot` (criterion +
  iai-callgrind sibling for each, four bench files total) along
  with the trait methods. Both benches' frozen baselines are
  captured at the EconomicsEngine PR's merge SHA.

The bench-with-method discipline (this section's general rule)
applies uniformly: the per-trait PR is the surface introduction
and carries the bench. Each per-trait PR's threshold sanity-check
(per §4.4 / §5) covers its newly-introduced bench(es) at the
PR's merge SHA, mirroring Stage 0 PR-2's sanity-check for the
Stage-0-frozen bench. Each per-trait PR's
`PERFORMANCE_BASELINE.md` update converts the placeholder rows
seeded by Stage 0 PR-2 (formatted as "deferred to: LedgerEngine
PR", "deferred to: KeyEngine PR", or "deferred to: EconomicsEngine
PR") into populated rows with the captured numbers and the PR's
merge SHA.

**Pre-drafting gap-check as workflow discipline.** Six
structural findings enumerated in §4.2's "Why this distribution"
were each surfaced by a verification step between the design
doc and the harness's actual behavior: the pre-drafting
gap-check between Stage 0 PR-1 (design) and Stage 0 PR-2
(implementation) surfaced Findings 1–4; threshold sanity-checks
on successive `workflow_dispatch` captures surfaced Findings
5–6. The design's operational claims were verified against
today's code before any commits were drafted, and against the
harness's measured behavior before any baseline was
transcribed. This pattern is not specific to Stage 0 PR-2; it
applies recursively to Stage 1 per-trait PRs and to V3.1+
spec/design-doc work:

- **Each Stage 1 per-trait PR** runs a pre-drafting gap-check
  against today's code (which now includes prior Stage 1 PRs'
  changes) before drafting its first commit, and applies the
  threshold sanity-check at each `workflow_dispatch` capture.
  Structural findings resolve at design-doc-tightening level
  (per the design-doc-first preparatory PR pattern below); code
  drafting begins against the cleaned-up plan.
- **V3.1+ spec/design-doc work** (V3.1 multisig per §10.3.1;
  V3.x archival; Phase 2b StakeEngine; future trait surfaces)
  inherits the same discipline. Spec rounds name the future-state
  surface; design-doc rounds verify each operational claim
  against today's code; pre-drafting gap-checks do the
  verification before commits; sanity-checks at first capture
  do the verification before transcription.

The cost is bounded (one investigation pass per design doc and
one sanity-check per capture, each producing a small finite
number of structural findings per the per-capture finding budget
in §4.4); the benefit is the same principle that anchored
Stage 0 PR-2 — *a measurement (or implementation) that pretends
to be more than it is corrupts the discipline depending on it*.
Future implementers inherit the discipline through this paragraph.

**Design-doc-first preparatory PRs (γ pattern).** When a
per-trait PR's pre-drafting gap-check or threshold sanity-check
surfaces a finding that requires a design-doc tightening, the
tightening lands in a **separate preparatory PR** (off `dev`,
design-doc only) before the per-trait PR's implementation
commits land. The implementation references the merged rule;
the design-doc rule exists independently and is testable in
isolation ("does the rule's framing hold up to scrutiny without
an implementation alongside?").

This pattern is policy-aligned with `06-branching.mdc`'s
"preparatory work lands on dev so subsequent work has a stable
base"; it operationalizes `05-system-thinking.mdc`'s
"specification first, code second." Stacking the design-doc
tightening as a commit *within* the per-trait PR (rather than
landing it as a separate preparatory PR) creates a temporal
entanglement where the implementation references a rule landing
simultaneously, weakening the rule's testability-in-isolation
property; the design-doc-first pattern breaks that entanglement.

Stage 0 PR-2's symmetry rule (Finding 5), boundary rule
(Finding 6), and hoisting rule (Finding 7) all followed this
pattern: each rule landed in a preparatory PR as a design-doc
tightening before PR-2's implementation referenced it. Three
preparatory PRs preceded PR-2's commit 5:

- **PR-A** codified the symmetry rule + boundary rule and the
  `Box<Engine<S>>` fixture pattern; closed Findings 5 and 6
  at design-doc level so PR-2's commit 4c could reference the
  merged rules.
- **PR-B** rewrote `PERFORMANCE_BASELINE.md` to match §4.5's
  per-bench frozen-baseline framing and amended
  `V3_ENGINE_TRAIT_BOUNDARIES.md` §3.3.1 Component 1 to
  correct wrong text (correction-of-existing-design, not new
  substantive content); operationalized Findings 1–4 for the
  document layer.
- **PR-C** codified the hoisting rule and §4.4's two-anchor
  component model; closed Finding 7 at design-doc level so
  PR-2's commit 5 could transcribe both numbers (iai
  instructions + criterion median_ns) into the post-PR-B
  baseline document with workload-class context.

Each preparatory PR closed a real finding the gap-checks
surfaced; the cumulative result is that PR-2's implementation
is straightforward application of merged rules rather than
parallel discovery and codification of new ones. Subsequent
per-trait PRs apply the same pattern when their own findings
surface — design-doc tightenings are not folded inline as
commits within the per-trait PR; they land as their own
preparatory PRs off `dev`. This precedent makes future
per-trait PRs simpler to scope: "our PR doesn't need to also
land design-doc tightenings inline; we surface, tighten in a
preparatory PR, then implement."

**Bundling exception for corrections-of-existing-design.** PR-B
demonstrates a narrow exception to the design-doc-first
discipline: when a preparatory PR's content is a correction of
text that's wrong as written (rather than introduction of new
substantive content), the correction can bundle with its
implementation rather than landing standalone. PR-B's §3.3.1
Component 1 amendment was a correction of factually-wrong text
fully determined by §4.5's already-merged per-bench framing; a
standalone Round-N micro-review would have produced no
information beyond "yes, it matches §4.5." The bundling cost
was small (~10 lines added to PR-B's review surface) and the
unbundling cost would have been a full review cycle for derived
content.

Future preparatory PRs can apply this exception **only** when
the content meets all three conditions, each tight enough to
prevent scope creep:

a. **Correction of existing wrong text, not new content.** The
   text being changed must already exist and be factually wrong
   as written. Adding a paragraph that introduces new framing,
   new rules, or new operationalization is *not* a correction
   — it is new substantive content, which warrants its own
   review cycle. The test: if the section being amended
   currently says nothing about the topic the amendment
   introduces, the amendment is new content.
b. **Fully derived from already-merged design content.** The
   correction's content must follow from design content that
   has already been through its own review cycle and merged.
   Corrections that re-interpret ambiguous design content —
   picking one of multiple defensible readings — are *not*
   derivations; they are substantive choices requiring their
   own review. The test: would two reviewers reading the
   merged design content arrive at the same correction
   independently? If yes, derivation; if no, substantive
   choice.
c. **Small enough that bundling cost is genuinely lower than
   a standalone review cycle.** PR-B's ~10-line amendment is
   the operative example. As a soft anchor, treat ~15 lines as
   the upper bound where bundling remains clearly cheaper than
   a standalone cycle; structural rewrites of 50+ lines almost
   always indicate that more is being changed than just text,
   even if the changed text was technically wrong as written.
   The threshold is judgment-bound, not numerical: a 20-line
   correction whose content is mechanical may still bundle; a
   12-line "correction" that re-frames a section may not.

**Corrections that do not meet all three conditions land as
standalone amendments before their implementation.** This
clause is the load-bearing one — it prevents the exception
from becoming the rule. The default discipline is
design-doc-first; the exception is narrow and conjunctive;
future authors who find their content failing any one of
(a)–(c) treat that failure as a signal to land standalone, not
a signal to argue the condition into compliance.

Amendments introducing new substantive content remain bound by
the design-doc-first discipline regardless of size or
derivation pattern.

**Stage 2+ method additions.** When a future PR adds a new
hot-path method to an existing trait, that PR adds the bench
alongside the method. Reviewer responsibility: flag any new
method on **the trait surfaces named in
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§3** (currently `KeyEngine`, `LedgerEngine`, `EconomicsEngine`,
`DaemonEngine`, `RefreshEngine`, `PendingTxEngine`,
`PersistenceEngine`; subject to refinement during Stage 1 if a
per-trait extraction surfaces a justified split or rename) that
does not have an accompanying bench, on the same justification
as the trait-spec §3.3.1 gate (read-path overhead must be
measured before merge). The spec is the source of truth for
the trait list; this design's enumeration is convenience for
current readers.

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

**Manifest stewardship.** The five `engine_trait_bench_*` sections
in `shekyl_rust_v0.manifest.md` are owned by the trait-extraction
work for the duration of Stage 1 — Stage 0 PR-2 seeds **one**
populated section (the Stage-0-frozen `synced_height` bench) and
**four** placeholder sections (the deferred benches: `balance`,
`account_public_address`, `current_emission`,
`parameters_snapshot`); each Stage 1 per-trait PR converts its
placeholder section(s) to populated content per the per-bench
deferred assignment above. After Stage 1 closes, ownership
transfers to whoever maintains the trait surface (default: the
engine-core crate maintainers; not a named role at V3.0).

---

## 5. What Stage 0 PR-2 implements

Concrete handoff list, in commit order. Each item is a checkbox
PR-2 reviewers verify against this design:

- [ ] **Shared bench fixture** at
      `rust/shekyl-engine-core/benches/common/engine_fixture.rs`
      constructing a real `Engine<SoloSigner>` via the production
      lifecycle path (`Engine::create` with manually-built
      `EngineCreateParams`, per §4.2's Path A pin). Returns the
      `Engine` paired with a `TempDir` guard for filesystem
      cleanup. Top-of-file comment names the visibility-expansion
      principle (per §4.2) and the duplication rationale
      (intentional duplication of
      `EngineCreateParams::for_test_full`'s body; the duplication
      is the cost of keeping the test surface bounded). Scope
      guard per §4.2: one job (build the Engine + `TempDir`
      guard); helpers migrate to `common/` only with explicit
      two-caller justification.
- [ ] **One** criterion bench file (the sole Stage-0-frozen
      bench, per §4.2's per-bench frozen-baseline framing) under
      `rust/shekyl-engine-core/benches/`:
      `engine_trait_bench_ledger_synced_height.rs`
      (today-equivalent call site per §4.1; imports the shared
      fixture via `mod common;`).
- [ ] **One** iai-callgrind sibling bench file under
      `rust/shekyl-engine-core/benches/`:
      `engine_trait_bench_ledger_synced_height_iai.rs`
      (same call site, deterministic instruction counts; imports
      the shared fixture via `mod common;`).
- [ ] `[[bench]]` entries for the Stage-0-frozen bench (two total
      entries: one criterion + one iai-callgrind) in
      `rust/shekyl-engine-core/Cargo.toml` (`harness = false` per
      the existing convention). The shared `common/` helper does
      **not** get a `[[bench]]` entry (Cargo treats it as a
      shared-helper directory, not a bench target).
- [ ] **One** new section in
      `docs/benchmarks/shekyl_rust_v0.manifest.md` documenting
      operation list, fixture shape, known gaps for the
      Stage-0-frozen bench (`synced_height`). **Four** placeholder
      sections marked as deferred with target Stage 1 per-trait
      PR named (per §4.6's per-bench deferred assignment):
      LedgerEngine PR for `balance`; KeyEngine PR for
      `account_public_address`; EconomicsEngine PR for
      `current_emission` and `parameters_snapshot`.
- [ ] `BENCHES` array extension in
      `scripts/bench/capture_rust_baseline.sh` for the
      Stage-0-frozen bench (one row covering the criterion +
      iai-callgrind sibling pair).
- [ ] `classify()` + `verdict_for()` extension in
      `scripts/bench/compare.py` for the new
      `engine_trait_bench_*` class. The class definition covers
      all five eventual benches by class membership; per-trait
      PRs introducing deferred benches do not need to touch the
      classifier.
- [ ] `paths:` extension in `.github/workflows/benchmarks.yml`
      for `rust/shekyl-engine-core/**` (both `pull_request` and
      `push` triggers).
- [ ] **Workflow-dispatch enablement on `capture-pr` job.** Add
      `|| github.event_name == 'workflow_dispatch'` to the
      `capture-pr` job's `if:` gate in
      [`.github/workflows/benchmarks.yml`](../../.github/workflows/benchmarks.yml).
      The trigger is already declared at the workflow level
      (`workflow_dispatch:`) but no job currently runs on
      dispatch; this enables the (iii) capture mechanism below.
- [ ] **Frozen baseline captured on the reference runner before
      review** (Stage-0-frozen bench only). PR-2 author triggers
      a one-shot `workflow_dispatch` against PR-2's branch (a
      fresh `ubuntu-latest` GHA runner per the §4.4 reference
      environment); downloads the `shekyl_rust_v0.json` artifact;
      transcribes the iai-callgrind `instructions` and criterion
      `median_ns` / `mean_ns` numbers for the **Stage-0-frozen
      bench** (`synced_height`) into
      `docs/PERFORMANCE_BASELINE.md` along with the host manifest
      and the SHA at which the capture ran; commits before
      opening PR-2 for review. **Four placeholder rows** in
      `PERFORMANCE_BASELINE.md` are seeded marking the deferred
      benches with their target per-trait PR named (per §4.6's
      per-bench deferred assignment); the rows convert from
      placeholder to populated when each per-trait PR captures
      its own frozen baseline at its merge SHA. The CI gate on
      PR-2 itself verifies the Stage-0-frozen number matches:
      iai-callgrind to deterministic tolerance (±0% modulo the
      §4.4 hardware-RNG exception), criterion to within the
      documented variance. Drift beyond tolerance is grounds for
      re-running the capture.
- [ ] Single-line in-place tightening of trait-spec §3.3.1
      Component 1 placeholder to name Stage 0 PR-2's SHA and
      this design doc as the harness's design contract. This is
      contextual tightening (timing-of-when-harness-lands shifts
      from "first Stage 1 PR" to "Stage 0 PR-2"); the substantive
      §3.3.1 content is unchanged.
- [ ] **Threshold sanity-check: iai-callgrind determinism**
      (Stage-0-frozen bench). Re-run iai-callgrind N times across
      a fresh `ubuntu-latest` runner for the Stage-0-frozen
      bench; confirm variance is ±0% and record the result in
      the `PERFORMANCE_BASELINE.md` host manifest. Non-zero
      variance triggers fixture-setup investigation per §4.4
      (most likely cause: hardware-RNG instruction leakage into
      the measured region). The deferred four benches'
      sanity-checks are carried out at their respective per-trait
      PRs per §4.6's per-bench deferred assignment.
  - **Static check: two-anchor expected-value comparison
    against the component model** (per §4.2's Measurement
    region discipline and §4.4's static check). Verify both
    anchors:
    1. **iai anchor.** Post-fixture iai-callgrind
       `instructions` are in the expected range: 20–40 for
       `synced_height`-class workloads (call body +
       unified-fixture-shape boundary cost); proportional-to-N
       for `balance`-class workloads at the LedgerEngine PR.
       Numbers in §4.4's warning territory (50–300) trigger
       the three reviewer checks (boundary rule violation,
       hardware-RNG leakage, model-refinement); numbers above
       the invalid threshold (>300) require investigation
       closure before transcription.
    2. **Criterion anchor.** Captured criterion median_ns
       relationship to iai's per-call cost is consistent with
       the workload's amortizability class (per §4.2's
       hoisting rule): trivial-pure-read class expects
       criterion ≪ iai-derived per-call time; state-dependent
       compute class expects criterion ≈ iai-derived per-call
       time. A class-disagreement (cause 4 in §4.4's four
       causes) indicates the harness mode is wrong for the
       workload and forces investigation closure before
       transcription.

    This sub-check runs at PR-2 for the Stage-0-frozen bench
    and at every per-trait PR introducing a deferred bench.
- [ ] **Threshold sanity-check: criterion variance documentation**
      (Stage-0-frozen bench). Re-run criterion N times across a
      fresh `ubuntu-latest` runner for the Stage-0-frozen bench;
      document the wall-clock variance (median, mean, std-dev)
      in the `PERFORMANCE_BASELINE.md` host manifest. Criterion
      is informational; the documentation is for reviewers
      comparing future per-PR criterion deltas against noise
      floor. Per the per-bench framing, each per-trait PR that
      introduces a deferred bench documents its own variance at
      that PR's merge SHA.
- [ ] **Conditional: standalone §3.3.1 tightening commit.** If
      the criterion variance documentation surfaces a §3.3.1
      framing issue (e.g., the spec's threshold framing reads
      ambiguously about whether 10%/25% applies to gate-metric
      or wall-clock), ship a **standalone** spec-amendment
      commit alongside PR-2 with the framing tightening — per
      Push 4 disposition, this is **never** §8.2 co-landed with
      Stage 1 PR 1. If criterion surfaces no framing issue,
      this checkbox is "N/A — no tightening needed" and the
      commit is omitted.

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

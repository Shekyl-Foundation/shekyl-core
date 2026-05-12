# Stage 1 PR 3 close-out — pre-flight investigation

**Status.** Pre-Phase-2 (pre-flight commit landing first; ready for
implementation once Rick disposes any open questions). This PR
captures M3-series (M3a–M3e) close-out residue surfaced by the
post-PR-#40 comprehensive audit, and tightens the V3.1 rules-queue
inputs while the empirical substrate is fresh. **Doc + bench-only**;
no schema changes, no consensus-touching code, no FFI surface
movement.

The PR is small mechanical work over well-anchored substrate — the
audit's findings, classifications, and dispositions are already in
hand. Pre-flight is correspondingly light.

**Branch.** `chore/stage-1-pr3-closeout` off `dev` at `a6c620d0a`
(the PR #40 merge commit closing the M-series).

**Cross-references.**

- **Audit transcript.** Comprehensive audit conducted post-PR-#40
  merge (2026-05-11) surfaced findings A1 / A2 / B1 / B2 with
  per-finding dispositions; Rick's disposition message authorized
  the single-PR / three-commit shape and added the new V3.1
  FOLLOWUP for the pre-flight-FOLLOWUP-scope discipline gap.
- **Closing-out target.** PR #40
  ([`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./STAGE_1_PR_3_M3E_PREFLIGHT.md))
  closed the M-series substrate work; this PR closes the M-series
  audit-surfaced residue.
- **Substrate framework.** `15-deletion-and-debt.mdc` trinary
  reading per `STAGE_1_PR_3_M3E_PREFLIGHT.md §11.1`. A1 + A2 +
  the L353-379 partial close are all mode-2 mechanical-residue;
  B1 + B2 + the new lemma entry are tightening of existing V3.1
  rules-queue FOLLOWUP entries.

---

## §1 Substrate audit invariants

### 1.1 — A1's complete enumeration of stage-1-PR docs needing past-tensing

Workspace-wide grep for `KeyEngine` references in design docs that
forward-frame KeyEngine PR / PR 3 as future work. **17 references
across 4 files** verified:

| File | Lines | Pattern |
| --- | --- | --- |
| `docs/PERFORMANCE_BASELINE.md` | L99, L399, L401, L406 | `Status: Deferred to KeyEngine PR.` (live header text) + 3 narrative refs |
| `docs/design/STAGE_0_HARNESS.md` | L349, L420, L1588, L1722, L1814, L1817, L1832-1834, L2082 | template-table "Deferred to KeyEngine PR" + narrative "KeyEngine PR introduces…" + worked-example "PR 3 = KeyEngine" |
| `docs/design/STAGE_1_PR_1_DAEMON_ENGINE.md` | L83, L198 | bench enumeration for KeyEngine (deferred) + future-tense expected-outcome ("PRs 3 onward") |
| `docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md` | L259, L298-299, L408 | "PRs 3 onward (the §8.1 chain — `KeyEngine`...)" + "PR 3 (`KeyEngine` per §8.1)" + "Stage 1 PR 4-ish per §8.1's `KeyEngine` / `LedgerEngine` / `DaemonEngine` chain" |

Past-tensing strategy per file: surgical update of the forward-tense
clauses to past-tense with `[KeyEngine PR landed at M3-series, 2026-05-11; see CHANGELOG]`
annotation. Template-table rows (`STAGE_0_HARNESS.md §3.3.1` and
`PERFORMANCE_BASELINE.md §3.3.1` — same table, replicated) update
the "Deferred to KeyEngine PR" cell to the post-merge SHA reference.
Worked-example sections (`STAGE_0_HARNESS.md §"Worked example"`)
preserve original framing as design-trajectory record (the example
is illustrating a hypothetical Stage 1 unfolding; past-tensing it
would falsify its illustrative shape).

### 1.2 — A2's template-source verification

`engine_trait_bench_ledger_balance.rs` (78 lines) and
`engine_trait_bench_ledger_balance_iai.rs` (128 lines) at
`rust/shekyl-engine-core/benches/` are the canonical template per
`STAGE_0_HARNESS.md §3.3.1`. Replication shape:

- **Criterion file (`engine_trait_bench_key_account_public_address.rs`).**
  Same harness shape (criterion_group / criterion_main); same
  `__bench_internals` re-export pattern (calls `engine_account_public_address_for_bench(&engine, 0, 0)`
  via a re-export to be added in `shekyl-engine-core::__bench_internals`);
  same `mod common;` fixture pattern. Workload class **trivial pure-read**
  per `PERFORMANCE_BASELINE.md §"Bench: engine_trait_bench_key_account_public_address"`
  (the address is stable across iterations; criterion `median_ns`
  reflects optimizer amortization).
- **iai-callgrind sibling file (`engine_trait_bench_key_account_public_address_iai.rs`).**
  Same `library_benchmark` / `library_benchmark_group` / `main!`
  shape; same `Box<Engine<SoloSigner, DaemonClient, LocalLedger>>`
  boundary-rule fixture per `STAGE_0_HARNESS.md §4.2`. Expected
  post-fixture instructions: **trivial pure-read range** (likely
  ~10-50 instructions per call after optimizer amortization, since
  `KeyEngine::account_public_address` returns a cached
  `&AccountPublicAddress` reference without per-call derivation).
- **`__bench_internals` re-export.** New
  `engine_account_public_address_for_bench(&LocalKeys) -> usize` helper
  in `shekyl-engine-core::__bench_internals` (returns the sum of both
  address-field byte-lengths to keep the trait-call observable without
  widening `AccountPublicAddress` to `pub`). The helper takes
  `&LocalKeys` rather than `&Engine<...>` because `KeyEngine::
  account_public_address` is a parameterless trait method on the
  implementor (`LocalKeys`), and the orchestrator does not yet hold
  `LocalKeys` as an `Engine` field — that orchestrator integration is
  PR-5 territory per `STAGE_1_PR_3_KEY_ENGINE.md` §2.1.1. KeyEngine is
  `pub(crate)`, so the bench compilation unit can't reach the trait
  method directly without a public shim.
- **`Cargo.toml` registration.** New `[[bench]]` entries for both
  files in `rust/shekyl-engine-core/Cargo.toml` matching the
  existing `engine_trait_bench_ledger_balance` registration pattern
  (likely `harness = false`).

### 1.3 — B1+B2+lemma exact-text additions to FOLLOWUPS

Three FOLLOWUP edits in commit 2 (no new top-level entries; one
new V3.1 entry alongside existing rules-queue items):

- **Extend L764 (§19 plan-vs-state-divergence).** Append a
  "Commit-history-level instance (PR #40)" sub-section with the
  six-actual-vs-four-planned divergence and the surgical-shape
  prescription (record divergence post-execution; preserve the
  planned framing as the operative review surface).
- **Extend L874 (rule-15 trinary).** Append an "Applied-disposition
  table (PR #40, two review-response cycles)" sub-section with the
  8-disposition table from the audit's Finding B2.
- **Add new V3.1 FOLLOWUP (after L969).** "Rules-queue: encode the
  pre-flight-FOLLOWUP-scope discipline" — the lemma A2 surfaced
  indirectly. Pre-flights should grep FOLLOWUPS for entries naming
  the current PR (by ID, trait, feature, or milestone) as their
  resolution point; otherwise the FOLLOWUP discipline is one-sided.
  Cite L353-379's KeyEngine slot as the precedent (M3a-M3e missed
  it; PR #40 audit caught it). Folds into the V3.1 rules-queue
  consolidation PR per L931-969.

### 1.4 — L353-379 partial-close annotation text

The L353-379 FOLLOWUP's close-condition is "the four deferred-bench
sections in `PERFORMANCE_BASELINE.md` are populated by their
introducing per-trait PRs." The KeyEngine slot was missed by every
M-series sub-PR; commit 3 satisfies it. **Annotation shape:**

> **Partial-close note (this PR).** KeyEngine slot
> (`engine_trait_bench_key_account_public_address`) satisfied at
> commit 3 of `chore/stage-1-pr3-closeout` (PR number filled in at
> PR-open time); see `PERFORMANCE_BASELINE.md §"Bench: engine_trait_bench_key_account_public_address"`.
> Remaining slots: `EconomicsEngine` (`current_emission` and
> `parameters_snapshot`) populates at the EconomicsEngine PR.
> `LedgerEngine` slot (`balance`) was satisfied at the LedgerEngine
> PR's merge (PR-2 of the Stage 1 sequence). Discipline binding
> remains live for the EconomicsEngine PR; close-condition fully met
> when its slot lands.

---

## §2 Dispositions

### D1 — A1's per-doc past-tensing surgery shape: surgical-edit vs comprehensive-pass

**Disposition: surgical-edit per file.** Same shape as M3e D1
(α). The 17 references concentrate at predictable patterns
("Deferred to KeyEngine PR", "PR 3 (`KeyEngine` per §8.1)",
"PRs 3 onward"); each is a one-line surgical past-tense edit with
the same `[KeyEngine PR landed at M3-series, 2026-05-11]` annotation
shape. Comprehensive past-tensing pass is unwarranted overhead.

### D2 — A1's worked-example handling: past-tense vs preserve-as-illustration

**Disposition: preserve as illustration.** `STAGE_0_HARNESS.md
§"Worked example"` (L1721-1834) is explicitly an illustrative
hypothetical ("Suppose Stage 1 unfolds as PR 1 = DaemonEngine,
PR 2 = LedgerEngine, PR 3 = KeyEngine, PR 4 = EconomicsEngine").
Past-tensing the example would falsify its illustrative shape;
the harness rule is template content for any future trait
extraction PR, not a record of what happened. Annotate the
worked-example header: `[Illustrative hypothetical preserved as
template; the actual Stage 1 unfolding matches this example through
PR 3, with PR 4 = EconomicsEngine still pending.]`

### D3 — A2's bench-introduction commit shape: minimal vs comprehensive

**Disposition: minimal commit (template-replicate + register +
populate `PERFORMANCE_BASELINE.md` section).** Per the harness
rule, the bench is **introduced alongside the trait method**; M3a
should have done this. The closing-out PR's commit shape mirrors
what M3a should have shipped: `__bench_internals` accessor +
criterion bench + iai sibling + Cargo.toml registration +
`PERFORMANCE_BASELINE.md` measurement transcription + L353-379
partial-close annotation. No new fixture work — the existing
`build_engine_fixture_with_balance` / `build_engine_fixture_with_default_balance`
fixtures cover the trivial-pure-read workload (the
`account_public_address(0, 0)` call is fixture-state-independent).

### D4 — Bench measurement-capture: local capture vs CI workflow_dispatch

**Disposition: CI workflow_dispatch.** Same shape as M3a's
LedgerEngine bench-measurement discipline per `STAGE_0_HARNESS.md
§4.5`. Local-machine numbers don't satisfy the per-bench
frozen-baseline rule (per-runner deterministic capture). Commit 3
introduces the bench files + Cargo.toml + the
`PERFORMANCE_BASELINE.md` section with `Status: pending CI capture
at this PR's merge SHA`; the actual measurement transcription
happens via a follow-up commit after `ci/benchmarks` workflow runs
on the merged PR.

---

## §3 Property delivery against three-timeframe framing

- **Now (V3 / current protocol).** Closes M-series audit residue;
  satisfies L353-379 FOLLOWUP's KeyEngine slot; tightens V3.1
  rules-queue inputs with empirical evidence from PR #40. Discipline
  integrity for the V3.0 release.
- **Mining era end (~30 years).** No effect; doc + bench work.
- **Post-quantum era (V4).** No effect; doc + bench work.

---

## §4 Commit decomposition

Three substantive commits + this preflight commit (commit 0). All
mode-2 mechanical work; no per-commit compile gate needed for
docs but commit 3 (bench introduction) does need to compile.

| # | Commit | Files touched | Rationale |
| --- | --- | --- | --- |
| 0 | `docs(chore-closeout): pre-flight investigation` | `docs/design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md` (this file) | Pre-flight locks scope before Phase 2 begins. |
| 1 | `docs(chore-closeout): A1 stage-1-PR docs past-tensing (M3-series closing-out residue)` | `docs/PERFORMANCE_BASELINE.md`, `docs/design/STAGE_0_HARNESS.md`, `docs/design/STAGE_1_PR_1_DAEMON_ENGINE.md`, `docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md` | Per D1: surgical past-tense + `[KeyEngine PR landed at M3-series]` annotation per the 17 enumerated references; per D2: preserve worked-example as illustration with header annotation. |
| 2 | `docs(chore-closeout): B1+B2 V3.1 rules-queue input sharpening + new pre-flight-FOLLOWUP-scope lemma entry` | `docs/FOLLOWUPS.md` | Per §1.3: extend L764 (§19) with commit-history-level instance; extend L874 (rule-15) with PR #40 applied-disposition table; add new V3.1 entry for pre-flight-FOLLOWUP-scope discipline. |
| 3 | `bench(shekyl-engine-core): introduce engine_trait_bench_key_account_public_address (criterion + iai)` | `rust/shekyl-engine-core/src/__bench_internals.rs` (accessor re-export), `rust/shekyl-engine-core/benches/engine_trait_bench_key_account_public_address.rs` (new), `rust/shekyl-engine-core/benches/engine_trait_bench_key_account_public_address_iai.rs` (new), `rust/shekyl-engine-core/Cargo.toml`, `docs/PERFORMANCE_BASELINE.md`, `docs/FOLLOWUPS.md` (L353-379 partial-close annotation) | Per D3: template-replicate the LedgerEngine bench shape; per D4: CI workflow_dispatch captures the measurement post-merge; the `PERFORMANCE_BASELINE.md` section transitions from "Deferred to KeyEngine PR" → "Pending CI capture at this PR's merge SHA" + L353-379 partial-close note. |

**Why three commits, not fewer or more.** Commit 1 is purely
cross-doc surgical-text edits; commit 2 is purely FOLLOWUPS
restructuring; commit 3 introduces compile-gated source. Each is
independently bisectable and reviewable. Folding any pair would
mix surfaces (docs sweep vs FOLLOWUPS edits vs Rust bench code) at
review time. Splitting commit 3 across criterion / iai / Cargo /
baseline / FOLLOWUP would optimize audit-trail granularity past
the bisection benefit (the bench introduction is one logical unit;
each piece is incomplete without the others).

---

## §5 Branching

- Branch: `chore/stage-1-pr3-closeout` off `dev` at `a6c620d0a`.
- Per `06-branching.mdc`: short-lived `chore/<description>` branch;
  ≤ 5 working days; lands on `dev` via PR.
- Each push requires explicit user authorization.
- Naming: `chore/` prefix per the rule (this is closing-out work,
  not a feature, not a fix; it's discipline-residue cleanup).

---

## §6 Success criteria

1. All 17 KeyEngine-as-future-work references identified in §1.1
   are past-tensed (or preserved-as-illustration per D2 for the
   worked example).
2. FOLLOWUPS L764 (§19) carries the commit-history-level
   fourth-precedent instance from PR #40.
3. FOLLOWUPS L874 (rule-15) carries the 8-disposition applied table
   from PR #40's two review-response cycles.
4. New V3.1 FOLLOWUP entry exists for the
   pre-flight-FOLLOWUP-scope discipline gap, with L353-379 cited as
   the surfacing precedent.
5. `engine_trait_bench_key_account_public_address` (criterion + iai
   sibling) exists at `rust/shekyl-engine-core/benches/`, registered
   in `Cargo.toml`, compiles against `cargo test -p shekyl-engine-core --benches`.
6. `PERFORMANCE_BASELINE.md §"Bench: engine_trait_bench_key_account_public_address"`
   carries `Status: Pending CI capture at this PR's merge SHA`
   (with the actual transcription happening as a follow-up after
   `ci/benchmarks` runs).
7. FOLLOWUPS L353-379 carries the KeyEngine-slot partial-close
   annotation per §1.4.
8. CI green at every commit (commit 3 introduces compilable bench
   code; commits 1/2 are doc-only).
9. CHANGELOG entry under `[Unreleased]` `### Changed` recording
   the close-out residue resolution and the V3.1 rules-queue
   tightening.
10. PR description includes the C1-C3 positive-verifications
    section per Rick's disposition (PR description, not
    `MIGRATION_AUDIT.md`).

---

## §7 Out of scope

- **Bench measurement transcription** — the `PERFORMANCE_BASELINE.md`
  section ships with `Status: Pending CI capture`; the actual
  numbers land as a follow-up commit after CI runs (per D4). This
  matches M3a's discipline.
- **EconomicsEngine bench introduction** — separate per-trait PR
  per §8.1 sequencing; not in this PR's scope.
- **The broader 34-occurrence broken-link surface in WALLET_REWRITE_PLAN.md**
  filed as V3.1 FOLLOWUP at L1447 in PR #40's review-response work.
  Stays deferred per its mode-3 classification.
- **FFI ABI declaration drift in `shekyl_ffi.h`** — covered by
  existing V3.2 FOLLOWUP at L2102. Stays deferred.

---

## §8 Open questions

None expected — the audit's dispositions answered the design
questions; this is mechanical execution. Surface any that emerge
during Phase 2 implementation as inline disposition decisions
recorded in the relevant commit messages.

---

## §9 C1-C3 positive-verifications recording shape

Per Rick's disposition: PR description carries a "Positive
verifications from PR #40 audit" section enumerating C1 / C2 / C3
with verification commands and results. **Not** added to
`MIGRATION_AUDIT.md` (avoids touching a doc that's already
settled; partial-close annotation propagation lives in FOLLOWUPS,
not MIGRATION_AUDIT.md). The PR description content drafted at
PR-open time captures:

- **C1** — Removed `TransferDetails`-fields sweep clean (residue
  in `shekyl-crypto-pq` engine-confined, in `wallet2.cpp` V3.2-
  scheduled, or in docstrings explicitly describing M3d removal).
- **C2** — Old KeyEngine method-name sweep clean (residue in
  preserved historical-record sections per M3e annotations, or
  false-positive matches in C++ wallet2's `sign_with_spend_key`
  enum / `derive_subaddress_public_key` removed method).
- **C3** — `.cursor/rules/*.mdc` stale-globs sweep clean (the
  `42-serialization-policy.mdc` realignment in M3e closed the
  one outstanding entry).

Each with the `rg` invocation that produced the result.

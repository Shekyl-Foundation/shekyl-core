# Stage 1 PR 4 — `RefreshEngine` extraction — design

**Status.** **DRAFT — Round 1 closed (2026-05-12).** Round 1's
load-bearing question (§5 producer redesign) settled to **α —
preserved current shape** per §5.4 below; Round 2+ residual
questions (R1 / R2 / R3) named in §5.4. The seed framing (Round 1
opening) is preserved below as the question-shape Round 1
evaluated against. This document was opened in parallel with the
M3c–M3e tail of Stage 1 PR 3 per the 2026-05-10 sequencing
decision recorded in
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§ tail-notes (the “co-locate the next-PR design draft with the
migration tail” disposition under Strategy B). PR 4 does not begin
implementation until M3e closes; this seed exists so the
producer-redesign discussion (§5 below) settles **before** PR 5
(`PendingTxEngine`) begins design rounds, since PR 5 depends on
the consumer-pattern decision that PR 4 makes — Round 1's
α-disposition is now the input PR 5's design rounds consume.

The seed is intentionally short on disposition and long on
question-naming. Subsequent revisions land each design round
inline (the precedent set by PR 3's
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md), which
grew round-by-round to its current 4 262 lines).

**Branch.** `feat/stage-1-pr4-refresh-engine-design` off `dev` at
`9e53c82fa` (post-PR-#36, post-PR-#34, post-PR-#35 once #35 lands).
The branch holds **doc-only** revisions until the design doc
reaches a state Phase 0 can amend
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.3 against, at which point the implementation branch
(`feat/stage-1-pr4-refresh-engine`) cuts off the post-Phase-0 dev
tip per the PR 2 / PR 3 precedent.

**Cross-references.**

- **Spec (binding).**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 (`RefreshEngine` trait surface, Round 2 reframing). The
  trait shape there is the contract this PR implements — the design
  doc operationalizes it; it does not re-litigate the surface.
- **Sequencing.**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §8.1 landing graph: PR 4 lands after `LedgerEngine` (PR 2,
  merged) and `DaemonEngine` (PR 1, merged) but in parallel with
  PR 5 (`PendingTxEngine`). The 2026-05-10 sequencing decision
  refines “in parallel” to **PR 4 design doc develops alongside
  M3c–M3e; PR 4 implementation lands first, then PR 5 design /
  implementation.**
- **Migration parallel.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3 (M3c–M3e) is the migration-tail context this seed is
  co-located with. PR 4 does not depend on M3c/M3d/M3e
  *behaviourally* — `RefreshEngine` extraction operates on the
  refresh state machine, not on the per-output secret derivation —
  but the discipline budget the migration tail consumes is the
  same one PR 4's design rounds will consume, so the parallel
  scheduling is a process choice, not a structural requirement.
- **Per-PR template.**
  [`STAGE_1_PR_1_DAEMON_ENGINE.md`](./STAGE_1_PR_1_DAEMON_ENGINE.md)
  and
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](./STAGE_1_PR_2_LEDGER_ENGINE.md)
  are the template — Phase 0 (doc-only spec amendments), Phase 1
  (implementation), §6 review checklist, §5 commit decomposition.
  PR 4 follows the same shape.

---

## §1 Mission posture

Per `00-mission.mdc`'s priority hierarchy, this PR is mostly
priority-3 work (system longevity through architectural cleanup):
extracting refresh state ownership from `Engine<S>` into a
dedicated trait so Stage 4's `kameo` actor model can swap the
implementor without touching call sites. It has a priority-1
(security) sub-component because the refresh path produces the
`ScanResult` that `Engine::apply_scan_result` merges, and the
`apply_scan_result` merge is the single audited mutation point for
scanner-derived state per `35-secure-memory.mdc` and the §3
threat-model citations in
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md).

The PR must preserve, by name:

- The `apply_scan_result_to_state` ⇒ `Engine::apply_scan_result`
  ⇒ `LedgerEngine::apply_scan_result` audited mutation chain.
  `RefreshEngine::produce_scan_result` is the **producer**; it
  must not bypass the merge gate.
- The four-checkpoint cancellation discipline pinned at
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 / §7. Checkpoints 1 (top-of-attempt) and 4 (pre-merge)
  belong to the orchestrator on `Engine<S>`; checkpoints 2
  (post-tip-fetch) and 3 (mid-scan, between blocks) belong to
  `RefreshEngine::produce_scan_result`. This split is part of the
  contract.
- The `RefreshError::ConcurrentMutation` retry loop semantics from
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs).
  The orchestrator owns the retry; the producer is one attempt.

Three timeframes:

- **Now.** Refresh today is an inherent method on `Engine<S>` that
  imports the producer logic by file inclusion. Extracting the
  trait makes the producer testable in isolation and unblocks
  Stage 4's actor model.
- **Mining era end (~30 years).** No effect — the refresh shape is
  consensus-independent.
- **PQC era (V4).** No effect — `RefreshEngine::produce_scan_result`
  consumes `RecoveredWalletOutput`, which already carries the
  hybrid ciphertext per M3b.

---

## §2 Scope

### §2.1 In-scope

1. **Trait extraction.** `RefreshEngine` per
   [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
   §2.3, with the Stage 1 surface unchanged from the spec.
2. **`LocalRefresh` implementor.** A struct wrapping the existing
   producer logic from
   [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
   (`run_refresh_task` and the four-checkpoint discipline within
   it). The implementor owns the producer-side scan-cursor state
   per §2.3's ownership clause.
3. **Engine generic parameter.** `Engine<S, D, L, R: RefreshEngine
   = LocalRefresh>` per the §2.3 generic-parameter pattern (Round
   3's “parameterize over `R`” disposition matching PR 1's `D`,
   PR 2's `L`).
4. **Orchestration migration.** `Engine::start_refresh` and
   `Engine::refresh` continue to live as inherent methods on
   `Engine<S>`, calling
   `self.refresh.produce_scan_result(...)` against the trait
   instead of the inline producer body.
5. **Cancellation-token plumbing.** No semantic change; the
   orchestrator-owned checkpoints (1 and 4) stay where they are,
   and the producer-owned checkpoints (2 and 3) move into the
   `LocalRefresh::produce_scan_result` body verbatim.

### §2.2 Out-of-scope

- **`PendingTxEngine` extraction (PR 5).** PR 5 depends on PR 4's
  consumer-pattern decision (§5) but is its own design doc and
  PR.
- **Reservation-tracker reorg semantics.** Touched in §5 under
  R3 (reorg-detection contract) but the reservation-tracker is
  `PendingTxEngine`-side state; PR 4 only specifies what
  `RefreshEngine` exposes about reorgs, not how the consumer
  responds.
- **Stage 4 actor migration.** `LocalRefresh` is the Stage 1
  in-process implementor. The Stage 4 `kameo`-actor implementor
  is a future PR; the trait surface is identical across both
  stages per `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.5's framing.
- **Producer-side parallelism.** A future scaling refinement may
  add per-block parallel fetches inside
  `LocalRefresh::produce_scan_result`. This PR keeps the existing
  serial scan; the trait surface accommodates either shape per
  §2.3's `Clone + Send + Sync + 'static` bound on `D`.

---

## §3 Pre-flight discipline checklist

Per `16-architectural-inheritance.mdc`'s “Continuous discipline as
inheritance prevention” framing, the per-trait extraction PRs
audit the trait surface against the threat model **before** Phase
0 spec amendments land. PR 3 surfaced the
`transfer_details`-equivalent migration finding via this check;
PR 4's check completes here.

### §3.1 What the trait delivers against the threat model

- **Audited mutation point preserved.** `RefreshEngine` is purely
  a producer; it returns `ScanResult` and observes none of the
  ledger's mutable state. The merge gate at
  `Engine::apply_scan_result` ⇒ `LedgerEngine::apply_scan_result`
  is unchanged. Threat-model property:
  `RefreshEngine::produce_scan_result` cannot bypass merge
  validation, by trait shape.
- **Cancellation discipline preserved.** §2.3 / §7 split is
  load-bearing; PR 4 codifies it but does not re-litigate it.
  Threat-model property: a cancelled refresh stops at one of the
  four documented checkpoints, not arbitrarily — reviewed in
  M3-tail's CI tests.
- **No new secret-touching surface.** `RefreshEngine` consumes
  `LedgerSnapshot` (cheap clone of public reorg-window
  descriptors) and a borrowed `&D: DaemonEngine`. It does not
  touch `KeyEngine`, does not derive secrets, does not hold
  output secrets. Per `30-cryptography.mdc` and
  `35-secure-memory.mdc`, the trait is below the secret-handling
  threshold; no `Zeroize` or constant-time concerns activate.

### §3.2 Architectural-inheritance audit

`engine/refresh.rs` is a Shekyl-greenfield module (it was rewritten
during the wallet rewrite per
[`STAGE_0_HARNESS.md`](./STAGE_0_HARNESS.md)); not inherited from
Monero/CryptoNote. The architectural-inheritance findings density
is low for this PR per the §16 density-expectation framing
(refresh state is a data-flow surface, not a cryptographic one).

**Audit result.** No migration findings expected; PR 4 is a
trait-extraction PR with no data-model restructuring. The
pre-flight expectation is a **confirmation, not a discovery** per
the §16 “discovery cadence” framing applied to PR 3's audit
results.

### §3.3 Discipline expectations passed forward

The “what does this trait deliver against the threat model?”
question per §16 is answered above (§3.1). The standard
per-trait pre-flight checklist:

- [x] Threat-model alignment (§3.1).
- [x] Architectural-inheritance audit (§3.2).
- [x] Producer-redesign decision (§5.4 — α, Round 1, 2026-05-12).
- [ ] Phase 0 spec amendments identified (§4 — α-scoped; Round 2
      resolves R3 then enumerates).
- [ ] Phase 1 commit decomposition (§6 — pending Round 4).

---

## §4 Phase 0 candidates (TBD)

Phase 0 doc-only spec amendments precede Phase 1 implementation
per the PR 2 / PR 3 precedent. Candidates surface as the design
rounds progress; this section is the holding place.

**Currently identified candidates (subject to revision).**

- **Phase 0a** — possible §2.3 surface refinements that surface
  during the §5 producer-redesign discussion. Likely empty if
  Strategy α (preserved current shape) is adopted; non-empty if
  Strategy β or γ is adopted (the trait surface itself shifts).
- **Phase 0b** — `RefreshOptions` / `RefreshProgress` shape
  audit. The current shapes
  ([`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs))
  are inherent types; PR 4 needs to decide whether they move to
  a `shekyl-engine-core::refresh` public module or stay
  crate-private. Spec amendment if public-side surface widens.
- **Phase 0c** — `RefreshError` shape against `LedgerEngine`'s
  `RefreshError`. The two are currently the same type per
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.5; PR 4 confirms the variant set covers all
  `RefreshEngine`-side failure modes (cancellation, daemon
  errors, scanner contract violations).

---

## §5 Open design question — producer redesign

This is the load-bearing open question per the 2026-05-10
sequencing decision. PR 5 (`PendingTxEngine`) depends on PR 4's
disposition.

### §5.1 The question

The current `engine/refresh.rs` implements a serial driver: the
orchestrator calls `produce_scan_result` once per attempt, the
producer fetches blocks serially from the daemon, scans them
sequentially, and returns one `ScanResult` per attempt. Three
strategies for evolving this shape, each with different
implications for `PendingTxEngine`'s consumer surface:

#### α — Preserved current shape

`RefreshEngine::produce_scan_result` returns one `ScanResult` per
call as today. `PendingTxEngine::build` queries the ledger
synchronously (post-merge) for current state.

- **Pros.** Minimal surface change; PR 4 lands as pure
  trait-extraction with no behavioural shift.
- **Cons.** Refreshes against a deep reorg window are O(window),
  not amortizable across attempts. `PendingTxEngine::build`
  cannot proceed during a long refresh — the orchestrator's
  refresh loop holds the synchronization point.

#### β — Internal batching

`RefreshEngine::produce_scan_result` continues to return one
`ScanResult` per attempt, but the *producer side* batches block
fetches internally (e.g., parallel fetch + sequential scan, or
sliding-window prefetch). `PendingTxEngine::build` is unchanged.

- **Pros.** Amortizes daemon round-trip latency without changing
  the trait surface.
- **Cons.** Producer-side complexity grows; the existing
  four-checkpoint discipline must extend to cover the parallel
  fetch (per-block fetch failures must not race with cancellation
  observation).

#### γ — Consumer-driven

`RefreshEngine::produce_scan_result` is replaced (or supplemented)
with a streaming surface — e.g., `produce_scan_results(...) ->
impl Stream<Item = ScanResult>` — and `PendingTxEngine::build` can
query refresh-progress state synchronously without blocking on a
full refresh attempt.

- **Pros.** `PendingTxEngine::build` proceeds during a long
  refresh against the most recently completed `ScanResult`;
  produces visible progress on the wallet UI.
- **Cons.** Largest surface change; introduces stream-cancellation
  semantics that the §2.3 four-checkpoint discipline does not
  cover. Stage 4 actor migration becomes more complex (per-stream-
  item back-pressure semantics).

### §5.2 Implications for PR 5

`PendingTxEngine::build` consumes refresh state. The three
strategies each project differently onto its trait surface:

- Under α: `build` blocks the refresh loop or fails with a
  `RefreshInProgress` error. PR 5 needs to specify which.
- Under β: same as α at the trait level; difference is only
  internal to `LocalRefresh`. PR 5's surface is unchanged.
- Under γ: `build` reads refresh-progress state synchronously.
  PR 5's surface needs a method or field on `PendingTxEngine` to
  query refresh progress.

**Decision deadline.** Before PR 5 design rounds begin. Per the
2026-05-10 sequencing, that is when M3e closes — currently
estimated ~2026-05-15 to 2026-05-20.

### §5.3 Recommendation track (post-Round-1)

Round 1 settled α (§5.4); the post-Round-1 schedule is therefore
narrower than the seed projected. The original four-round
sequencing assumed Round 1 would only *frame* the question; in
practice Round 1 converged on α directly, so Rounds 2–4 compress
to the residual questions R1 / R2 / R3 plus Phase-0 / Phase-1
mechanics.

- **Round 1 (closed, 2026-05-12).** Disposition α per §5.4. Four
  criteria evaluated: PR 4 extraction cleanliness; PR 5 two-phase
  build/submit/discard contract over reorg events; reservation-
  tracker reorg surfacing; Stage 4 actor compatibility. The
  validation-surface guard in
  [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)
  (named on `dev`; visible to PR 4 once the branch syncs)
  rejects bundling β/γ into PR 4 because they share the feature
  topic “refresh” without sharing PR 4's validation surface.
- **Round 2 (next).** Resolve **R2** (β internal-batching: V3.x
  FOLLOWUPS entry vs. §2.2 note) and **R3** (`RefreshOptions` /
  `RefreshProgress` public-module promotion, §4 Phase 0b);
  enumerate Phase 0 amendments now α has scoped them.
- **Round 3.** PR 5 interface contract review — settle **R1**
  (`PendingTxEngine::build` behaviour during a long refresh:
  `RefreshInProgress` error vs. block-until-merge vs.
  build-against-current-snapshot). PR 5's design rounds open
  with R1's disposition as input.
- **Round 4.** Phase 0 commit decomposition; §6 review checklist
  filled in; Phase 1 commit list pinned.

The convergence-in-Round-1 outcome is the discovery-cadence
framing in
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
working forward — α is the inheritance-clean answer because
`engine/refresh.rs` is itself a Shekyl-greenfield module (§3.2)
with no inherited architectural drift to migrate, so the trait
extraction has no structural reshape to absorb. Per the rule's
“PR 4 onward's audits are increasingly likely to be confirmations”
prediction, Round 1's confirmation-shape is the predicted
outcome, not a weak round.

The architectural-integrity-now disposition from
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
remains the operative governance: Round 3 evaluates whether PR 5
needs γ for **correctness** (not convenience). If R1's resolution
surfaces that the reservation tracker cannot deliver its
correctness property under α, the disposition reverts and PR 4
re-opens to γ at higher cost than landing γ in Round 1 would have
been. Round 1's α-disposition is therefore *provisionally
load-bearing* — the rounds budget Round 3 carries is the
re-evaluation gate.

### §5.4 Round 1 disposition — α (2026-05-12)

**Disposition: α — preserved current shape.**
`RefreshEngine::produce_scan_result` returns one `ScanResult` per
call exactly as
[`engine/refresh.rs:948`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
implements it today; the trait extraction is the §3.2-pattern
*moves not rewrites* — `LocalRefresh::produce_scan_result`
delegates to the existing producer body unchanged, and the
four-checkpoint cancellation discipline pinned in
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.3 / §7 is preserved verbatim. The orchestrator on `Engine<S>`
continues to own checkpoints 1 (top-of-attempt) and 4 (pre-merge);
`LocalRefresh::produce_scan_result` owns checkpoints 2
(post-tip-fetch) and 3 (mid-scan).

#### §5.4.1 Four-criteria rationale

**Criterion 1 — PR 4 extraction cleanliness.** α is trivial.
`produce_scan_result` already exists as a `pub(crate)` function
with the four-checkpoint discipline pinned; promoting it to a
trait method on `LocalRefresh` is the §3.2 *moves not rewrites*
pattern with zero behavioural shift. β requires extending the §7
checkpoint discipline to fork-join control flow (per-block fetch
failures must not race with cancellation observation); the
existing scalar control flow's cancellation invariants do not
generalize to a parallel-fetch surface without new design. γ is
the largest cost: new trait surface; new stream-cancellation
semantics that the §2.3 four-checkpoint discipline does not
cover.

**Criterion 2 — PR 5's two-phase build/submit/discard contract
over reorg events.** Under α, PR 5's `PendingTxEngine::build`
reads ledger state post-merge; the reservation tracker pins
reservations against the merged snapshot. Monotone snapshot
semantics: each reservation has a single, well-defined ledger
state it was allocated against. β preserves this property at the
trait level (β's amortization is internal to `LocalRefresh`).
Under γ, `build` reading mid-stream introduces a non-monotone
consumer surface — the reservation tracker would either replay
reservations on each stream item or reconcile partial-snapshot
pinning against the eventually-merged snapshot. γ's
correctness-preservation cost is the design discipline that
non-monotone snapshot semantics imposes on every consumer of
refresh state, not just the reservation tracker.

**Criterion 3 — Reservation-tracker reorg surfacing.** Under α,
reorgs surface through `ScanResult.reorg_rewind`
([`engine/refresh.rs:920–939`](../../rust/shekyl-engine-core/src/engine/refresh.rs))
merged via `LedgerEngine::apply_scan_result`; the reservation
tracker observes reorgs via post-merge ledger query and
fail-pending-on-reorg disposition. The `ConcurrentMutation` retry
loop already handles the second-reorg-during-scan case at the
orchestrator layer. β surfaces reorgs identically (trait surface
unchanged). Under γ, reorgs become per-stream events; the
reservation tracker reacts on each event rather than reading
post-merge state. The added event-channel surface and the
per-stream-event reactive logic are correctness-load-bearing
shapes that don't otherwise exist in PR 5's design surface.

**Criterion 4 — Stage 4 actor-migration compatibility.** α is a
literal class-c match per
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§3.4.4 / §4 async-story table — one `CancellationToken`, one
`Progress` channel, one reply. `kameo` wraps the trait method as
a request/reply actor with no stream-backpressure design needed.
β preserves the same single-reply shape. γ introduces a second
async story (stream consumer pattern) not in §4's table:
per-stream-item backpressure semantics, mailbox sizing, fan-out
to multiple downstream consumers. The §3.4.4 framework's class-c
pattern handles long-running operations via channel parameters,
but the stream-shape γ proposes is not the class-c pattern — it
is a separate async story PR 4 would need to land alongside the
trait extraction.

#### §5.4.2 Validation-surface separation (β / γ are not bundled)

β and γ share the feature topic "refresh" with the α producer-
redesign decision but do not share its validation surface. Per
[`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)
(named on `dev` 2026-05-10; the rule cites this PR 4 Round 1 as
its forward-looking worked example):

- **α/β/γ producer-redesign decision.** Validation surface: the
  consumer pattern's contract shape — what semantics consumers
  observe when they read refresh state.
- **β internal batching.** Validation surface: amortized
  round-trip latency under a sliding-window prefetch — a
  performance property, not a contract-shape property.
- **γ stream consumer surface.** Validation surface: stream-event
  back-pressure, per-event reactive logic, reservation-tracker
  re-pinning semantics — multiple correctness properties, each
  its own surface.

The α-disposition closes the producer-redesign decision. β and γ
remain on independent timelines (R2 and a hypothetical
follow-up PR respectively) with their own validation surfaces.

#### §5.4.3 Residual questions for Rounds 2+

- **R1 — `PendingTxEngine::build` behaviour during a long
  refresh.** Under α, the orchestrator's refresh loop holds the
  synchronization point; PR 5 must settle whether `build`
  returns a `RefreshInProgress` error, blocks until refresh
  completes, or builds against the current (potentially-stale)
  ledger snapshot. PR 5's design rounds settle this as the
  first item on its agenda. The α-disposition's
  *provisionally load-bearing* status (per §5.3) means R1's
  resolution can re-open α — if the reservation tracker's
  correctness property cannot hold under any of the three R1
  options, the rounds budget reverts to γ.
- **R2 — β internal-batching refinement.** Promote to a V3.x
  FOLLOWUPS entry, or leave as the §2.2 “future scaling
  refinement” note. The new V3.0 bandwidth FOLLOWUP entry (added
  in this commit) names α's bandwidth cost; whether β is the
  intended remediation or whether a different prune-shape
  refinement is preferable depends on the cold-sync profile
  measured in the V3.0 RC stabilization window. Round 2
  disposition.
- **R3 — `RefreshOptions` / `RefreshProgress` public-module
  promotion.** §4 Phase 0b candidate. Round 2 enumerates the
  public-side surface shift if the types move to a
  `shekyl-engine-core::refresh` public module; if they stay
  crate-private, Phase 0b is empty and §4 narrows to Phases 0a
  (likely empty under α) and 0c (`RefreshError` variant set
  audit).

### §5.5 Work-list — refresh-adjacent items and where they live

This table enumerates every refresh-adjacent work item PR 4's
design rounds reference, with its target version and the document
where its specification lives. The table satisfies
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)'s
"deferred without a named home is the failure mode" requirement
for PR 4's scope: every item has a named home.

| Item | Target | Where documented |
| --- | --- | --- |
| α/β/γ producer-redesign decision (Round 1 closed: α) | V3.0 | §5.4 (this doc) |
| Async-path-skip post-pass (P1 *latent*) | V3.0 | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 (recorded on `dev` 2026-05-10; entry titled “P1 (latent): refresh post-pass skipped on async path”) |
| Wallet-birthday plumbing into producer start-height (P2) | V3.0 | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 (recorded on `dev` 2026-05-10; entry titled “P2: wallet-birthday plumbing not wired into producer start-height”) |
| β internal-batching refinement | V3.x (R2) | §2.2 (out-of-scope note) + this table; promotion to FOLLOWUPS pending Round 2 R2 disposition |
| FMD (fuzzy message detection) — negative result for V3.0 | V4 research | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §4 |
| OMR (oblivious message retrieval) — negative result for V3.0 | V3.x research | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §5 |
| View-tag pre-filter (operational today) | already live | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §3 (cites [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) §3.1.1) |
| Refresh bandwidth tradeoff under α | V3.0 (RC stabilization) | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 (entry added in this commit) |
| Pruning-vocabulary disambiguation | reference | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §7 sidebar |
| `PendingTxEngine::build` behaviour during long refresh (R1) | V3.0 (PR 5 design rounds) | §5.4.3 R1; settled in PR 5 design doc once that branch opens |
| `RefreshOptions` / `RefreshProgress` public-module promotion (R3) | V3.0 (Round 2) | §5.4.3 R3; §4 Phase 0b candidate |

The table is designed to be read row-by-row as the decision-trail
artifact for each refresh-adjacent item; reviewers landing PR 4's
implementation phase can confirm each item's resolution against
its named home rather than re-deriving the decomposition.

---

## §6 Review checklist (TBD)

Filled in once §5 settles and Phase 0 / Phase 1 commit
decomposition is known. The shape mirrors PR 2's §6 (the
binding-check matrix against the spec, the test-substrate
preservation list, the call-site sweep audit).

---

## §7 Discipline budget

This seed counts as Round 1 of the design rounds. Subsequent
revisions land round-by-round inline (the PR 3 precedent).

**Estimate (subject to revision):** 3–4 rounds before Phase 0
spec amendments land; 1–2 rounds during Phase 0 review; Phase 1
implementation rounds depend on commit count.

The user's 2026-05-10 sequencing decision allocates the rounds
budget to the migration tail — M3c–M3e finish their landings
*before* PR 4's design rounds consume the human reviewer's
attention budget. PR 4's design discussion happens in writing
(this document) during the migration-tail window; live design
rounds resume after M3e closes.

---

## §8 What this document does not yet resolve

Round 1 closed the §5 producer-redesign disposition (α, §5.4).
The remaining fenceposts the round-by-round revisions fill in:

- §5.4.3 R1 (`PendingTxEngine::build` behaviour during long
  refresh) — settled by PR 5's design rounds; α is *provisionally
  load-bearing* until R1 resolves per §5.3's re-evaluation gate.
- §5.4.3 R2 (β internal-batching: V3.x FOLLOWUPS entry vs. §2.2
  note) — Round 2 disposition.
- §5.4.3 R3 (`RefreshOptions` / `RefreshProgress` public-module
  promotion) — Round 2 disposition; §4 Phase 0b candidate.
- §4 Phase 0 amendments — Round 2 enumerates now α has scoped
  them.
- §6 review checklist — depends on §4 and §6 commit decomposition.
- §7 commit decomposition for Phase 1 — Round 4.

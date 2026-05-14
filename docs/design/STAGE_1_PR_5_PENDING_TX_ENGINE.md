# Stage 1 PR 5 — `PendingTxEngine` extraction — design

**Status.** **Round 1 closed (2026-05-13); Round 2 in progress
— segments 2a (audit-readiness), 2b (R11 signing-actor split
reframe to (b); R14 reservation extensibility seam), 2c
(closure-rule and lens-applicability refinements paired with
R13 / R15 / R16 / R17 named with dispositions), 2d
(R2 + R12 co-disposition; Phase 0c truly collapses;
`SnapshotId` opacity closed as 16-byte content-addressed
digest), and 2e (R8 `ReservationTTLActor` composition closure;
`DiscardReason::TTLAutoDiscard` variant pin) landed
(2026-05-14).** This
document was opened as a seed immediately after Stage 1 PR 4's
design substrate landed on `dev` (merge commit `6de8335d5`,
PR #42). Round 1 closes here in one round — not deferred to
Round 2 — because the actor-mesh lens that PR 4 established in
its Round 2 reframe exhausts the wargaming surface of PR 5's
load-bearing first question. Shapes (2) and (3) fail criterion 5
(adversarial-daemon resistance) on **structural** grounds under
the actor framing, not contingent grounds; no fourth shape
survives the framing. See §5.0 (the reframe) and §5.5 (the
disposition).

**Round 2 segment 2a (2026-05-14) — audit-readiness.** The
post-R1-closure adversarial review surfaced a steelman attack
on §5.3 criterion 5: shapes (2)/(3) could be implemented via
stream subscription rather than synchronous query, avoiding the
"cross-actor liveness query" framing the criterion-5 prose
relied on. Segment 2a reframes the rejection ground from
"cross-actor liveness query" to **"contract dependency on
refresh quiescence at any point in the build/submit flow"** —
the load-bearing property is the contract dependency, not the
observation mechanism, and the daemon controls the underlying
signal regardless of which channel observes it. Threat-model
anchor strengthened to make the adversary-controlled-daemon
case the **expected deployment** (not a hardened edge case); §5.5
scorecard rationale clarified to distinguish criteria 4/5's
shared underlying mechanism from their distinct consequence axes
(implementation-creating-vulnerability vs. threat-model-
exercising-vulnerability). The R1 disposition still holds; the
strengthening sharpens the audit-blocking defense without
reopening the disposition. Lands ahead of the R-residual
dispositions per the audit-blocking sequencing decision so
audit-prep does not sequence behind R2 / R8 / R9 / R11 / R12.

**Round 2 segment 2b (2026-05-14) — R11 signing-actor split
reframe + R14 reservation extensibility seam.** Round 1 closed
R11 with a working disposition leaning (a) — `PendingTxActor`
holds spend material, "matches PR 4 R4's instance-scoped
pattern" — with shape (b) (separate `SigningActor`) deferred to
V3.x with the HW-wallet trigger. Segment 2b's adversarial review
identified the disposition as the **cost-benefit-defer-to-later
anti-pattern recurring in a residual** per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc):
the cost-asymmetry argument that justified PR 4 R4's tactical (a)
(Scanner already existed in C++ holding view + spend material;
restructuring Scanner was the deferral trigger) does **not**
apply to PR 5 R11, because PR 5 is opening the trait surface
and `LocalPendingTx` does not yet exist — the choice between
(a) and (b) is the same cost either way; we are designing one
or the other from scratch, not moving from one to the other.
R4-consistency cuts the other way: PR 4 R4's (a) explicitly
named (c) as the long-term shape with the HW-wallet trigger;
PR 5 R11 lands that long-term shape from the start. Segment 2b
closes R11 as **(b) — `LocalSigner` (Stage 1) / `SigningActor`
(Stage 4) is the sole holder of spend material; `LocalPendingTx`
/ `PendingTxActor` delegates via a narrow `Signer` trait /
mailbox surface**. HW-wallet integration in V3.x plugs into the
existing architecture as an alternative `Signer` impl
(substitution, not refactor); the V3.x FOLLOWUPS entry tracking
the (b) deferral is replaced by an entry tracking HW-wallet
integration. Segment 2b also lands **R14 — reservation
extensibility seam (`extensions: Vec<ReservationExtension>` with
`#[non_exhaustive]` enum)** as bounded-cost optionality
preservation against V3.x reservation-richness use cases
(coinjoin, atomic swap, time-locked, multi-stage, composable);
same pattern as the diagnostic-stream extensibility seams
PR 4 / PR 5 already established. The R1 disposition still
holds; segment 2b is residual-disposition work that applies the
PR 3 / PR 4 architectural-integrity-now discipline at the
R-residual level rather than at the load-bearing question.

**Round 2 segment 2c (2026-05-14) — closure-rule and
lens-applicability refinements + R13 / R15 / R16 / R17 named
with dispositions.** Segment 2c lands two project-wide
discipline refinements alongside four named-with-disposition
R-residuals. **§5.0.4 lens-applicability discipline**
establishes three structural conditions that govern when the
actor-mesh lens applies to a per-engine extraction (trait
surface mediates state-mutation across actors; adversarial
review surfaces a cross-actor liveness or quiescence
dependency; Stage 4 actor-migration target is non-trivial);
the lens compounds across PRs **whose structure admits it**,
not uniformly — per-engine PR pre-flights test applicability
rather than presume it. The Round 1 closure-review fourth-
shape adversarial test ((1)-build paired with (3)-submit
hybrid; rejected on criterion 5 because the contract
dependency on refresh quiescence moves from build-and-submit
to submit-only without dissolving) is recorded as the worked
example of "the contract dependency moves but doesn't
dissolve" under the lens. **§7 closure-rule strengthening**
pins "Round-N closes when the wargaming surface **known at
closure time** is genuinely exhausted; new shapes surfacing
in Round-N+1 reopen Round N rather than slipping past
closure" — the closure rule pins what was known at closure
time, not what could ever be known, and explicit reopening
is the discipline-correct response to new candidate shapes.
**R13 / R15 / R16 / R17 named with dispositions**: R13
(output selection algorithm) closes V3.0 ships wallet2-greedy
under `OutputSelector` trait seam; R15 (submission strategy
as composable actor) closes V3.0 ships
`SubmissionStrategyActor` seam with `DirectStrategy`
default; R16 (wallet-side fee estimation) closes V3.0 ships
daemon-recommendation-with-explicit-override under
`FeeEstimator` trait seam (with conditional V3.0 lift to (c)
if Phase 0 review confirms bounded `LedgerEngine`-accessor
cost); R17 (event-sourced recovery) closes V3.0 ships PR 4
§5.4.8 #1 carryover (drop-on-close) with diagnostic-stream
contract-pin refinement permitting wallet-internal
encrypted-persistence opt-in (V3.x). All four V3.x
deferrals get FOLLOWUPS entries with named V3.x triggers and
seam-design implications. The R1 disposition still holds;
segment 2c is discipline-strengthening + opportunity-surface
naming work that compounds project-wide design discipline
without reopening the load-bearing question.

**Round 2 segment 2d (2026-05-14) — R2 + R12 co-disposition;
Phase 0c truly collapses; `SnapshotId` opacity closed as
16-byte content-addressed digest.** Segment 2d closes the two
remaining `SnapshotId`-adjacent residuals against the actual
shape of the `LedgerSnapshot` substrate landed in PR 2.
**R12 closes as (a)** — content-derived `SnapshotId` from
existing `LedgerSnapshot` data. The substrate inspection
confirms `LedgerSnapshot` (per
[`rust/shekyl-engine-core/src/engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
ll. 147–166)
carries `synced_height: u64` and `reorg_blocks: ReorgBlocks`
— both deterministic by construction; sufficient for content-
addressed derivation without a `LedgerEngine` trait amendment.
Stage 1's `LocalPendingTx` derives `SnapshotId` from the
existing `LedgerEngine::snapshot()` trait method (returning
`LedgerSnapshot`); Stage 4's `PendingTxActor` receives
identical `SnapshotId` values via `LedgerDiagnostic::SnapshotMerged`
events emitted at merge time inside `LedgerEngine` using
the same digest function. **Phase 0c truly collapses** —
the §5.5 ground-1 "(pending R12)" qualifier is mechanically
softened, the §4 Phase 0c "(pending R12)" qualifier is
dropped, and ground 1 becomes closure-confirmed alongside
grounds 2 and 3. **R2 closes as opaque 16-byte content-
addressed digest**: `pub struct SnapshotId([u8; 16])`,
computed as a domain-separated hash over `LedgerSnapshot`'s
deterministic fields (specific hash primitive pinned at
Phase 0 review (segment 2g) per §3.1 PQC-discipline
alignment with the engine's hash selection). Determinism is
**required** by §5.0's submit-handler field-comparison
contract; the height-leak side-channel that a height-bearing
`SnapshotId` would carry into every reservation envelope and
actor message is closed by construction. **Projection-type
discipline preserved-as-pattern**: no V3.0 PR 5 call-site
introduces a cross-trust-boundary `SnapshotId` or
`SnapshotMerged` consumer, so the projection-type
implementation lands in the V3.x consumer-actor PR that
introduces the first cross-boundary consumer; the discipline
itself is documented per PR 4 §5.4.8 #4's recursive-trust-
boundary rule. **R16 conditional V3.0 lift evaluation
(segment 2c trigger)**: `LedgerBlock` (per
[`rust/shekyl-engine-state/src/ledger_block.rs`](../../rust/shekyl-engine-state/src/ledger_block.rs))
carries no per-block fee data today; lifting R16 (c) to V3.0
would require either a storage-layout amendment (persistence-
layer migration) or an unbounded historical-block walk per
estimator call. **Neither is bounded cost**, so R16's
conservative segment-2c default holds; R16 (c) lands in V3.x
behind a coordinated `LedgerEngine` + `FeeEstimator` PR. The
R1 disposition still holds; segment 2d is the segment-2c
follow-through (closure-rule operational discipline applied
to the conditional-V3.0-lift surface) plus the
`SnapshotId`-substrate co-disposition the §8 fenceposts
sequenced for this slot.

**Round 2 segment 2e (2026-05-14) — R8 `ReservationTTLActor`
composition closure; `DiscardReason::TTLAutoDiscard` variant
pin.** Round 1 already reframed R8 (reservation TTL / leak
prevention) as `ReservationTTLActor` consumer-actor
composition under the §5.0 actor-mesh framing — same shape as
PR 4's `PeerReputationActor` / `RecoveryActor` pattern.
Segment 2e closes R8 by pinning **all V3.0 deliverables**
explicitly so V3.x's `ReservationTTLActor` introduction is
additive-only — no V3.x trait revision, no V3.x enum revision,
no V3.x consumer-side breaking change. The V3.0 deliverables:
(1) `PendingTxDiagnostic::BuildSucceeded` emitted at the
`build`-success path in `LocalPendingTx::build` /
`PendingTxActor::handle_build` (Phase 1 call-site review
confirms); (2) `PendingTxDiagnostic::Discarded { reason:
SnapshotRotationAutoDiscard }` emitted at `submit`'s
snapshot-mismatch path (R5's lazy-discard semantics); (3)
`PendingTxDiagnostic::ReservationOutstanding` variant exists
in the `#[non_exhaustive]` enum (no V3.0 emitter;
`ReservationTTLActor` is the first V3.x emitter); (4) **new
in segment 2e:** `DiscardReason::TTLAutoDiscard` variant added
to the `#[non_exhaustive]` `DiscardReason` set so V3.x's
`ReservationTTLActor` can trigger `PendingTxActor` to emit
`Discarded { reason: TTLAutoDiscard }` without a V3.x enum
revision. R5 ↔ R8 coherence verified: R5's `SnapshotRotationAutoDiscard`
is the reactive cleanup path (cleanup-on-use); R8's
`TTLAutoDiscard` is the proactive complement (age-based
policy on never-used reservations). Both share the
`DiscardReason`/`Discarded` event infrastructure;
downstream consumers see a unified `Discarded` event stream
with discriminated reasons. The continuous-discipline
corollary of
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
applies: the V3.x consumer-actor PR does not get to revise
the V3.0 diagnostic-stream surface; segment 2e pins all V3.0
deliverables so V3.x is additive-only. **Hard mitigation
pins inherited verbatim from PR 4 §5.4.8** (restart-amnesia
per item 1; recursive trust boundary per item 4; bounded
mailbox per item 5) bind on the V3.x consumer-actor PR via
§5.0.3 — no PR 5 amendments needed; the contracts are
general. The existing
`ReservationTTLActor` FOLLOWUPS entry is amended with the
segment-2e `DiscardReason::TTLAutoDiscard` variant pin and
closure-status confirmation. The R1 disposition still holds;
segment 2e is residual-closure work that finalizes R8's
disposition for design purposes. Phase 1 call-site sweep
(Round 3 commit decomposition) confirms emission discipline
for V3.0 deliverables 1 and 2.

Subsequent revisions land each design round inline (the
precedent set by PR 3's
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) and
PR 4's
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md),
each of which grew round-by-round to its current shape). Round 2
disposes residuals R2 / R8 / R9 / R11 / R12 plus Phase 0
enumeration (R12 was added as a post-closure follow-up to §5.4 to
qualify §5.5 ground 1 — Stage 1's `current_snapshot` acquisition
mechanism is unspecified in Round 1's substrate; the disposition
does not depend on R12's outcome but the prose was sharpened
against the implicit overclaim); Round 3 does commit
decomposition. R3 / R5 / R10 dissolved by composition under §5.0
(see §5.4 for per-residual rationale).

**Branch.** `feat/stage-1-pr5-pending-tx-engine-design` off `dev`
at `6de8335d5` (PR-#42 merge — post-M3e, post-PR-#37 perf,
post-PR-#41 close-out, post-PR-4-design). The branch holds
**doc-only** revisions until the design doc reaches a state Phase 0
can amend
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.4 against, at which point the implementation branch
(`feat/stage-1-pr5-pending-tx-engine`) cuts off the post-Phase-0
`dev` tip per the PR 2 / PR 3 / PR 4 precedent.

**Cross-references.**

- **Spec (binding).**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.4 (`PendingTxEngine` trait surface, closed through Round 2
  Q9.8 / Q9.9 and Round 3 `&mut → &self` sweep). The trait shape
  there is the contract this PR implements — the design doc
  operationalizes it; it does not re-litigate the surface.
- **Prior round's bequest (settled in Round 1).**
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R1 carried forward
  **build-against-current-snapshot + snapshot-ID pinning** as
  PR 5 Round 1's working hypothesis. The reservation carries a
  `snapshot_id`; staleness detection runs at submit time. PR 5
  Round 1 confirms this shape on **structural grounds** under
  the §5.0 actor-mesh lens — not on the synchronous-CAS grounds
  the seed projected. Under the actor framing the
  serialization point is the actor's mailbox FIFO, not a
  compare-and-swap; the snapshot identity flows through the
  diagnostic-stream surface (`LedgerDiagnostic::SnapshotMerged`)
  rather than via a synchronous cross-trait `LedgerEngine`
  query. See §5.5 for the full Round 1 disposition.
- **Sequencing.**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §8.1 landing graph: PR 5 lands after `RefreshEngine` (PR 4,
  design landed; implementation pending PR 5's R1 disposition per
  PR 4 §5.3). The
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R1 framing: "PR 5's design rounds open with snapshot-ID
  pinning as the working hypothesis and look for a reason to
  reject it. If the rounds surface that the reservation tracker's
  correctness property cannot hold under α, PR 4 reverts to γ at
  higher cost than landing γ in Round 1 would have been."
- **Per-PR template.**
  [`STAGE_1_PR_1_DAEMON_ENGINE.md`](./STAGE_1_PR_1_DAEMON_ENGINE.md),
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](./STAGE_1_PR_2_LEDGER_ENGINE.md),
  and
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  are the template — Phase 0 (doc-only spec amendments), Phase 1
  (implementation), §6 review checklist, §7 commit decomposition.
  PR 5 follows the same shape.
- **PR 4 Round 3 dependency (resolved as confirmation, 2026-05-13).**
  PR 4 §5.3 explicitly deferred PR 4 Round 3 to PR 5's R1
  resolution: "Round 3 evaluates whether PR 5 needs γ for
  **correctness** (not convenience). If R1's resolution surfaces
  that the reservation tracker cannot deliver its correctness
  property under α, the disposition reverts and PR 4 re-opens to γ
  at higher cost than landing γ in Round 1 would have been.
  Round 1's α-disposition is therefore *provisionally
  load-bearing* — the rounds budget Round 3 carries is the
  re-evaluation gate."

  **Resolution.** PR 5 Round 1's disposition under the actor-mesh
  framing (§5.0, §5.5) confirms shape (1) — snapshot-ID pinning —
  with the reservation tracker holding **monotone semantics**
  under PR 4's α: the actor's mailbox FIFO is the serialization
  point; `LedgerDiagnostic::SnapshotMerged` events drive
  `PendingTxActor`'s `current_snapshot` field; staleness detection
  is a field comparison in the submit-message handler, not a
  cross-actor synchronous query. PR 4 Round 3 is therefore a
  **confirmation-shape round, not a re-evaluation round** —
  α holds and PR 4 advances directly to Round 4 (commit
  decomposition + Phase 1 commit list). The "provisionally
  load-bearing" qualifier on PR 4 §5.3's α is closed; PR 4 α is
  now confirmed.

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)'s
priority hierarchy, this PR is mostly priority-3 work (system
longevity through architectural cleanup): extracting reservation-
tracker and pending-transaction-state ownership from `Engine<S>`
into a dedicated trait so Stage 4's `kameo` actor model can swap
the implementor without touching call sites. It has a priority-1
(security) sub-component because the build / submit path
constructs and signs transactions, touching the spend secret in
the signing step; the reservation tracker's monotonicity is also
a consensus-adjacent invariant (double-spend prevention at the
wallet layer).

The PR must preserve, by name:

- The `build` ⇒ `submit` ⇒ `discard` two-phase state machine
  pinned in the *Pending-tx protocol* decision-log entry
  (2026-04-27) and operationalized in
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.4. `build` produces a `PendingTx` with a `ReservationId`;
  `submit` consumes the `ReservationId` and emits to the daemon;
  `discard` releases the reservation. The state machine is the
  contract; PR 5 codifies it but does not re-litigate it.
- The `SendError` (build-time validation) /
  `PendingTxError` (runtime invariants) error-vocabulary split
  per §2.4 Round 2 Q9.8. The two errors cover distinct domains;
  the snapshot-pinning extension this PR introduces (if R1
  closes at the working hypothesis) must land additively against
  one of these two, not as a new third type.
- The reservation tracker's actor-grouping with `PendingTxEngine`
  per §1.5's actor-identity test (§2.4 cites this directly). The
  tracker stays with `PendingTxEngine` rather than becoming its
  own actor; PR 5 must not introduce surface that suggests
  otherwise.

Three timeframes:

- **Now.** Transaction construction today lives as a path through
  `Engine::transfer` (and related methods) that imports
  reservation-tracker mutation by file inclusion. Extracting the
  trait makes the build/submit/discard lifecycle testable in
  isolation and unblocks Stage 4's actor model.
- **Mining era end (~30 years).** No effect — the build/submit/
  discard shape is consensus-independent at the wallet layer.
- **PQC era (V4).** No effect on the trait surface — `PendingTx`
  payloads carry whatever transaction bytes the consensus rules
  define, including the hybrid PQC signatures from genesis per
  `RCTTypeFcmpPlusPlusPqc`.

---

## §2 Scope

### §2.1 In-scope

1. **Trait extraction.** `PendingTxEngine` per
   [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
   §2.4, with the Stage 1 surface unchanged from the spec
   (`build` / `submit` / `discard` / `outstanding`).
2. **`LocalPendingTx` implementor.** A struct wrapping
   `Mutex<ReservationTracker>` for interior mutability per §2.4
   Round 3 disposition. The implementor owns the reservation-
   tracker state per §2.4's ownership clause.
3. **`Engine` generic parameter.** `Engine<S, D, L, R, P:
   PendingTxEngine = LocalPendingTx>` per the §2.4 generic-
   parameter pattern (Round 3's "parameterize over `P`" matching
   PR 1's `D`, PR 2's `L`, PR 4's `R`).
4. **Orchestration migration.** Existing transaction-construction
   call sites on `Engine<S>` migrate to call through the trait
   instead of inline reservation-tracker mutation.
5. **R1 disposition's required Phase 0 surface.** Whatever the
   §5 disposition is — snapshot-ID pinning, `RefreshInProgress`
   error, block-until-merge, or a different shape surfaced in
   rounds — its Phase 0 amendments to §2.4 (and possibly to §2.2
   `LedgerEngine::snapshot` to expose the snapshot identity) land
   in this PR's Phase 0.

### §2.2 Out-of-scope

- **V3.1 multisig methods (`inspect`, `adjust_fee`,
  `sign_partial`).** Per §2.4 Round 2 Q9.9, deferred to V3.1+;
  Stage 4's actor-shaped trait implementation can add them
  without re-opening the §2.4 surface.
- **PR 4 Round 3 (re-evaluation of α).** Triggered by PR 5's R1
  disposition per PR 4 §5.3, but executed in the PR 4
  re-evaluation pass after PR 5 lands its R1 disposition. PR 5
  surfaces the inputs PR 4 Round 3 consumes; PR 5 does not
  re-author PR 4's design rounds.
- **Stage 4 actor migration.** `LocalPendingTx` is the Stage 1
  in-process implementor. The Stage 4 `kameo`-actor implementor
  (`ActorRef<PendingTxActor>`) is a future PR; the trait surface
  is identical across both stages per
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §1.4 framing.
- **Reservation-tracker fee-market reactivity.** A future
  refinement may adapt the tracker to fee-market signals
  (e.g., re-quote held reservations against current fee
  estimates). This PR keeps the existing fee-at-build-time
  semantics; the trait surface accommodates either shape.
- **Cross-wallet reservation coordination (multi-device).** Out
  of scope for V3.0; the tracker is single-wallet, single-device.
  Multi-device coordination is a V3.x or post-V3 architectural
  question, not a PR 5 surface.

---

## §3 Pre-flight discipline checklist

Per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
"Continuous discipline as inheritance prevention" framing, the
per-trait extraction PRs audit the trait surface against the
threat model **before** Phase 0 spec amendments land. PR 3
surfaced the `transfer_details`-equivalent migration finding via
this check; PR 4's check completed as a confirmation; PR 5's
check completes here.

### §3.1 What the trait delivers against the threat model

- **Spend-secret locality.** `PendingTxEngine::submit` is the
  call site where the spend secret is consumed to sign the
  transaction. The trait must operationalize the secret-locality
  rule per
  [`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc):
  the spend secret enters `LocalPendingTx`'s signing path only at
  submit time, is consumed via a Zeroizing wrapper, and does not
  cross the trait surface in the trait's input/output types
  (i.e., neither `TxRequest`, `PendingTx`, nor `TxHash` carries
  the spend secret). The threat-model property: the spend secret
  is not reachable from anywhere the trait surface exposes.
- **Reservation-tracker monotonicity.** The tracker is the
  wallet's local double-spend defence. Reservations are
  monotonically created and either consumed (`submit`) or
  released (`discard`); no path mutates a reservation in place
  without going through the two-phase machine. Threat-model
  property: a reservation cannot be silently aliased to a
  different transaction.
- **Build/submit atomicity.** A successful `build` returns a
  `ReservationId` paired with the constructed `PendingTx` bytes;
  the subsequent `submit` consumes both atomically. If `submit`
  fails (e.g., daemon rejects, snapshot invalidated under R1's
  hypothesis), the reservation either auto-releases or requires
  explicit `discard`. The trait contract must pin this.
- **Audited mutation point preserved.** The reservation tracker
  is the audited mutation point for pending-transaction state.
  PR 5 does not introduce paths that mutate tracker state
  outside `build` / `submit` / `discard`. The trait shape
  enforces this by exposing exactly those three mutators (plus
  the read-only `outstanding`).

### §3.2 Architectural-inheritance audit

Transaction construction in
[`engine/`](../../rust/shekyl-engine-core/src/engine/) is largely
Shekyl-rewritten — the pre-Stage-0 transaction-construction path
was rewritten during the wallet rewrite per
[`STAGE_0_HARNESS.md`](./STAGE_0_HARNESS.md). However, the
following sub-paths warrant inheritance audit because they
intersect Monero-inherited concepts:

- **Decoy / ring selection.** PR 5's `build` consumes decoy
  candidates through the `LedgerEngine` (PR 2). Under FCMP++,
  decoy selection is replaced by full-chain membership proofs;
  the legacy `get_outs` / ring-construction code is removed per
  [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc).
  The audit checks that no Monero-era decoy logic survives in
  the build path.
- **Fee computation.** `build` queries fee estimates through
  `DaemonEngine::get_fee_estimates` (PR 1). The fee model is
  Shekyl-specific (`burn.rs` adaptive burn); the audit checks
  that no Monero-era flat-fee logic survives.
- **Two-phase build/submit/discard.** This pattern is itself
  Shekyl-specific (the *Pending-tx protocol* decision-log entry
  was authored 2026-04-27 against Shekyl's architecture, not
  inherited). No audit finding expected here.

**Audit result projection.** Confirmation-shape expected per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
"audits are increasingly likely to be confirmations" framing.
PR 5's substantive design surface is R1 (build behaviour during
long refresh), not architectural-inheritance migration. If the
audit surfaces unexpected findings during Round 2's call-site
sweep, the migration plan is scoped as a separate PR (per the
M3-tail precedent) and PR 5's design rounds extend.

### §3.3 Discipline expectations passed forward

The "what does this trait deliver against the threat model?"
question per §16 is answered above (§3.1). The standard
per-trait pre-flight checklist:

- [x] Threat-model alignment (§3.1).
- [x] Architectural-inheritance audit projection (§3.2).
- [ ] R1 disposition (§5 — pending design rounds).
- [ ] Phase 0 spec amendments identified (§4 — pending §5
      resolution).
- [ ] Phase 1 commit decomposition (§6 — pending §5 resolution).
- [ ] PR 4 Round 3 input bundle (§5.4 disposition + rationale
      packaged for PR 4 Round 3 consumption).

---

## §4 Phase 0 candidates (post-Round-1 enumeration)

Phase 0 doc-only spec amendments precede Phase 1 implementation
per the PR 2 / PR 3 / PR 4 precedent. Round 1's disposition
(§5.5 — shape (1) under the §5.0 actor-mesh framing) closes the
R1-dependence on these candidates; the surviving set is below.
Round 2 finalizes Phase 0 enumeration (binding type-signature
detail; cross-trait amendment review; review-checklist gate
for §6).

**Currently identified candidates (post-Round-1).**

- **Phase 0a — `SubmitError::SnapshotInvalidated` variant
  extension.** Add `SubmitError::SnapshotInvalidated {
  reservation_snapshot: SnapshotId, current_snapshot: SnapshotId }`
  to the §2.4 spec. Surface unchanged from the seed projection.
- **Phase 0b — `SnapshotId` public type.** New opaque
  identifier type `SnapshotId` lands in `shekyl-engine-core`
  (or as part of the §2.2 `LedgerEngine` surface). The type's
  shape — opaque content-addressed digest vs height-bearing —
  is the R2 disposition (recursive trust boundary applies
  per §5.4 R2; in-process consumers see full token,
  cross-boundary consumers see projection types).
- **Phase 0c — REMOVED at the trait surface under §5.0
  (R12 closed (a) in segment 2d; Phase 0c truly collapses).**
  The seed projected a cross-trait synchronous-query amendment
  to `LedgerEngine` (`current_snapshot_id() -> SnapshotId`) as
  a load-bearing amendment. Under the actor-mesh framing,
  snapshot identity flows through the diagnostic-stream
  surface as a `LedgerDiagnostic::SnapshotMerged` event
  (Phase 0g) for actor consumers; Stage 1's `LocalPendingTx`
  derives `SnapshotId` from `LedgerEngine::snapshot()` (the
  pre-existing trait method) per §5.4 R12 (a)'s segment-2d
  closure. **Net effect: the trait-surface load-bearing
  coupling the seed projected does not exist** — neither at
  V3.0 nor in any V3.x trajectory currently named. The
  additive event-surface amendment (Phase 0g) carries
  snapshot identity to actor consumers; the existing
  `LedgerEngine::snapshot()` carries it to Stage 1's
  synchronous trait-call consumer.
- **Phase 0d — `Reservation` struct extension.** The
  reservation record carries a `snapshot_id: SnapshotId` field.
  This is a `LocalPendingTx`-internal extension if `Reservation`
  is crate-private; a §2.4 surface amendment if `Reservation`
  is publicly exposed. Surface unchanged from the seed
  projection.
- **Phase 0e — reservation-lifecycle prose pin in §2.4.**
  Pin the build/submit/discard atomicity contract and the
  snapshot-invalidation disposition under §5.0:
  - `submit`'s staleness check is a **field comparison in the
    actor's message handler** (Stage 4) or under the trait's
    `&self` mutation discipline (Stage 1); not a CAS in the
    contract sense.
  - On staleness mismatch, `submit` emits
    `PendingTxDiagnostic::SubmitSnapshotInvalidated` and
    replies `SubmitError::SnapshotInvalidated`; the reservation
    auto-releases on this failure (lazy auto-discard policy
    per §5.4 R5); consumer rebuilds against the new snapshot.
  - Concurrent `build` / `submit` / `discard` semantics are
    delivered by the actor's mailbox FIFO (Stage 4) or by
    `&self` interior mutability under `Mutex<ReservationTracker>`
    (Stage 1). Both satisfy the trait contract; the
    "messages process serially per actor instance" property
    is the actor-system invariant per §5.4 R10's dissolution.
- **(NEW) Phase 0f — `PendingTxDiagnostic` enum +
  `DiagnosticSink` parameter on `LocalPendingTx`.** Parallel
  to PR 4's Phase 0e diagnostic-stream seam. Adds the
  `PendingTxDiagnostic` enum (definition in §5.0.2), the
  `DiscardReason` enum, and the `&dyn DiagnosticSink`
  parameter on `LocalPendingTx::new` (constructor-bound,
  matching PR 4's preference). Constructor-vs-per-method
  shape is jointly disposed with R11 in Round 2. The
  cross-cutting `DiagnosticSink` contracts from PR 4 §5.4.6
  / §5.4.7 R6 reframe / §5.4.8 (non-blocking emit, recursive
  trust boundary, restart-amnesia detection, panic safety,
  concurrent emit, emission/return coherence) bind to PR 5
  verbatim per §5.0.3.
- **(NEW) Phase 0g — `LedgerDiagnostic::SnapshotMerged`
  variant addition.** Cross-trait but **additive only**;
  lives entirely in the diagnostic-stream surface, not in
  `LedgerEngine`'s trait surface. Replaces Phase 0c. The
  `LedgerDiagnostic` enum (analogous to `RefreshDiagnostic`)
  is the parent surface; `SnapshotMerged { new: SnapshotId,
  prior: SnapshotId, height: BlockHeight }` is the variant
  PR 5 needs. Round 2 disposes whether PR 5 introduces the
  `LedgerDiagnostic` enum (no `LedgerEngine` consumer in
  Stage 1 yet) or whether `LedgerEngine` grows it on its
  own follow-up PR (PR 5 deferring the variant to a stub
  spec entry pending the consumer-introducing PR).

**Net Phase 0 change vs. seed projection.** One amendment
removed (0c — load-bearing cross-trait synchronous query); two
added (0f, 0g — additive diagnostic-stream surface). Surface
complexity stays roughly the same; the cross-trait coupling
moves from synchronous query (load-bearing surface) to event
emission (additive surface). Cleaner per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
— the load-bearing surface contraction is exactly the kind of
structural cleanup the rule's continuous-discipline corollary
predicts.

---

## §5 Round 1 — `PendingTxEngine::build` behaviour during long refresh

Round 1's load-bearing question — `build` behaviour during a
long refresh — closes here under the actor-mesh framing
(§5.0) at shape (1) (§5.5). The wargaming surface is exhausted
in one round per the §7 closure rule: shapes (2) and (3) fail
criterion 5 (adversarial-daemon resistance) on **structural**
grounds under the actor framing, not contingent grounds; no
fourth shape survives the framing. R3 / R5 / R10 dissolve by
composition under §5.0; R2 / R8 / R9 / R11 / R12 carry to Round 2.

### §5.0 Actor-mesh framing (Round 1 substrate)

PR 4's Round 2 reframe established a project-wide design lens:
the trait surface is the synchronous decision point that
consumers branch on; the rich semantic surface lives on the
diagnostic-stream seam (`DiagnosticSink` parameter; typed event
enum). The two channels carry different artifacts with
different consumers and different security properties. Per
PR 4
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.4.6 / §5.4.7 R6 reframe / §5.4.8, this isn't `RefreshEngine`-
specific — it's a project-wide lens that hadn't been named
yet when PR 4 opened.

PR 5 inherits the lens from Round 1. The cost-benefit-defer-to-later
anti-pattern PR 4 named (per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc))
has its cure now structurally available: apply the lens at
the load-bearing question, not after several rounds discovers
its absence. Subsequent per-trait extraction PRs
(`LedgerEngine` refinements, `DaemonEngine` extensions, V4
lattice-only work) inherit the lens the same way.

#### §5.0.1 What the framing changes for `PendingTxEngine`

The trait surface from
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.4 (`build` / `submit` / `discard` / `outstanding`) is binding
and identical across Stage 1 (`LocalPendingTx`) and Stage 4
(`ActorRef<PendingTxActor>`) — same property PR 4 §2.5 framed
for `RefreshEngine`. Implementation strategy diverges between
stages without trait revision:

```rust
// Stage 1: LocalPendingTx (in-process, &self, interior mutability)
struct LocalPendingTx<S: Signer> {
    inner: Mutex<ReservationTracker>,
    sink: Arc<dyn DiagnosticSink>,
    ledger: L,                 // for current_snapshot reads in Stage 1
    signer: Arc<S>,            // §5.4 R11 (b): sole holder of spend
                               // material; LocalPendingTx never holds
                               // spend_secret directly
}

// Stage 4: PendingTxActor (push-driven from diagnostic stream)
struct PendingTxActor {
    current_snapshot: SnapshotId,         // updated from
                                          // LedgerDiagnostic::SnapshotMerged
    reservations: HashMap<ReservationId, Reservation>,
    sink: Arc<dyn DiagnosticSink>,        // emits PendingTxDiagnostic
    signer: ActorRef<SigningActor>,       // §5.4 R11 (b): sole holder
                                          // of spend material; never
                                          // held by PendingTxActor
    // No mutex: mailbox FIFO is the serialization point.
}
```

The `Mutex<ReservationTracker>` from §2.4 Round 3 is a Stage 1
implementation detail — it satisfies the `&self` trait surface
under in-process call-graph semantics. The Stage 4 actor doesn't
need it because mailbox-FIFO is the serialization point.

The `signer` field is the §5.4 R11 (b) signing-actor-split
substrate (closed in segment 2b): spend material lives in a
single component (`LocalSigner` / `SigningActor`) whose sole job
is signing; `LocalPendingTx` / `PendingTxActor` constructs
transaction bytes and delegates signing via a narrow `Signer`
trait surface (Stage 1) / mailbox surface (Stage 4). HW-wallet
integration in V3.x is a `Signer`-impl substitution
(`HardwareSigner`) against the same boundary; no architectural
change.

#### §5.0.2 The diagnostic-stream seam for `PendingTxEngine`

Parallel to PR 4's `RefreshDiagnostic`, PR 5 defines its own
event surface. The seam shape is identical; the events differ:

```rust
#[non_exhaustive]
pub enum PendingTxDiagnostic {
    BuildSucceeded {
        reservation_id: ReservationId,
        snapshot_id: SnapshotId,
        outputs_count: u32,
    },
    BuildFailed { kind: BuildErrorKind },
    SubmitAttempted { reservation_id: ReservationId },
    SubmitSucceeded { reservation_id: ReservationId, tx_hash: TxHash },
    SubmitFailed { reservation_id: ReservationId, kind: SubmitErrorKind },
    SubmitSnapshotInvalidated {
        reservation_id: ReservationId,
        reservation_snapshot: SnapshotId,
        current_snapshot: SnapshotId,
    },
    Discarded { reservation_id: ReservationId, reason: DiscardReason },
    ReservationOutstanding {
        reservation_id: ReservationId,
        age: Duration,
    },
}

#[non_exhaustive]
pub enum DiscardReason {
    ConsumerExplicit,
    SnapshotRotationAutoDiscard,   // R5 lazy-discard variant
    DaemonRejectedTerminal,        // R9 disposition
    TTLAutoDiscard,                // R8 segment-2e variant (V3.x emitter:
                                   // ReservationTTLActor; no V3.0 emitter)
}
```

The trait surface adds a `&dyn DiagnosticSink` parameter to
`LocalPendingTx::new` (constructor-bound, matches PR 4's
preference per §3.1 spend-secret locality with R4-equivalent
reasoning) or per-method (per-call dispatch is also fine —
runtime-swap surface preserved either way). R11's segment-2b
closure (as (b) — separate `LocalSigner` / `SigningActor`)
makes the sink-binding question independent of the spend-
material disposition: `LocalPendingTx<S: Signer>` /
`PendingTxActor` is the sink-binding-host regardless of where
spend material lives. Segment 2f closes the constructor-vs-per-
method shape independently; the working disposition is
constructor-bound under PR 4 §3.4.5 / R4 (a) consistency.

#### §5.0.3 Cross-cutting `DiagnosticSink` contracts

The contract pins from PR 4 §5.4.6 / §5.4.7 R6 reframe / §5.4.8
bind here verbatim — they're general properties of any
`DiagnosticSink`-shaped seam in the codebase, not properties of
`RefreshDiagnostic` specifically:

- **Non-blocking `emit`.** `emit` MUST NOT block the calling
  task, even under concurrent emission from multiple tasks.
  Implementations use `try_send` semantics; on full or
  unavailable channel, drop silently. Implementations must
  remain non-blocking under concurrent emit; serializing
  internal synchronization that admits unbounded contention
  violates the contract.
- **Emission/return coherence.** `PendingTxEngine`
  implementations MUST emit at least one corresponding
  `PendingTxDiagnostic` event for every non-`Cancelled`
  error returned from `build` / `submit` / `discard`, **before**
  returning the error. Round 4 property test (the
  `AssertionSink` / `PanickingSink` pair PR 4 names) is the
  canonical reference for the coherence contract.
- **Recursive trust boundary.** Full-fidelity events flow only
  to actors whose **external surface** is itself within the
  trust boundary. The recursion matters: any in-process
  consumer that aggregates and republishes (metrics-export
  actor, debug UI with IPC channel, developer-mode log dump)
  inherits the trust-boundary obligation transitively.
  Cross-boundary consumers receive projection types only.
- **Restart-amnesia detection.** Stream-based reputation /
  pattern detectors must use coarse-window-based detection,
  not credit-history-based. Threat model resets on wallet
  restart per PR 4 §5.4.8 #1; consumer-actor PRs must design
  threshold logic against this constraint.
- **Producer panic-safety across `emit`.** Any panic
  propagating out of `emit` must result in a predictable
  `PendingTxEngine`-attempt failure with no leaked half-state
  and the cancellation token consistently in either
  fired-or-not state. Round 4 test deliverable; not a hard
  trait contract on consumer implementations.

**Generalization question (Round 2 disposition).**
PR 4's FOLLOWUPS named `docs/design/REFRESH_DIAGNOSTIC_STREAM.md`
as the spec doc. Now that the contracts are used by both PR 4
and PR 5, options are: (a) rename to `DIAGNOSTIC_STREAM.md`
(general); or (b) factor a parent
`DIAGNOSTIC_STREAM_CONTRACTS.md` that PR 4's and PR 5's
specific stream docs inherit from. Doc-only work; Round 2
disposition.

#### §5.0.4 Why the lens lands in Round 1, not Round 2

PR 4 took two rounds to arrive at the actor-mesh reframe
because the lens didn't yet exist as a named project-wide
design tool. PR 5 takes one round because the lens is now
available — applying it at the load-bearing question is the
architectural-integrity-now disposition per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
not a deferral candidate. The §7 closure rule ("Round-N
closes when the wargaming surface known at closure time is
exhausted") governs: the framing exhausts the surface in one
round, and delaying the disposition to Round 2 would be the
cost-benefit-defer-to-later anti-pattern the rule forecloses.

**Lens-applicability discipline (segment 2c).** The
actor-mesh lens compounds across PRs **whose structure
admits it**; future per-engine PRs test applicability rather
than presume it. Three structural conditions make the lens
applicable to a per-engine extraction:

1. **The trait surface mediates state-mutation across actors.**
   `RefreshEngine` (PR 4) and `PendingTxEngine` (PR 5) both
   mediate state mutation between an actor that produces
   data and an actor that consumes it; the lens reframes
   that mediation as message-passing-with-stream-side-effects
   rather than synchronous-call-with-shared-state. Engines
   whose trait surface is purely-functional (no actor mediation;
   e.g., a pure cryptographic primitive trait) do not admit
   the lens — synchronous call signatures are the right shape
   and the lens does not improve them.
2. **The trait carries a contract whose adversarial review
   surfaces a cross-actor liveness or quiescence dependency.**
   PR 5 R1's three structural grounds (Phase 0c collapses; the
   CAS isn't a CAS; adversarial-daemon resistance is structural)
   are all **lens-surfaced** properties — the synchronous
   framing's shapes (2)/(3) carry hidden cross-actor
   dependencies the lens makes visible. Engines whose
   adversarial review surfaces no cross-actor-dependency
   structural property do not benefit from the lens; the
   lens has nothing to surface that the synchronous framing
   doesn't already make visible.
3. **The Stage 4 actor-migration target is non-trivial.** The
   lens's primary payoff is forward-compatibility with the
   Stage 4 actor mesh. Engines whose Stage 4 shape is
   "co-located with another actor" or "no Stage 4 actor at
   all" derive less value from the lens; the lens may still
   be applicable but its payoff is bounded. The expected
   pattern: high-density lens applicability where Shekyl's
   threat-model surfaces concentrate (signing, refresh,
   ledger, daemon orchestration); low-density applicability
   where threat-model surfaces are sparse (config-loading,
   telemetry-emission, pure-utility).

**Test, don't presume.** Per-engine PR pre-flights ask:
"Does this trait surface satisfy conditions (1) / (2) / (3)?
If yes, the lens is the appropriate framing tool. If no,
the synchronous framing is correct." The discipline is
structural, not stylistic — the lens is a tool for engines
whose structure admits it, not a uniform house style.

**Closure-rule cross-reference.** Lens applicability and the
§7 closure rule co-govern when a per-engine PR Round 1 closes
on a disposition vs. defers. The lens **exhausts** the
wargaming surface for engines that admit it (PR 5 R1 is the
instance); the closure rule **lands** the disposition once
the surface is genuinely exhausted. For engines that don't
admit the lens, the closure rule still governs but the
exhaustion criterion is the synchronous framing's wargaming
surface, not the lens's. Round-1-closes-here is the discipline
the lens **enables** for engines that admit it; engines that
don't admit the lens still close Round 1 on adversarial review
of the synchronous framing's shapes, just over a different
wargaming surface.

**Fourth-shape adversarial test (Round 1 closure-review
record).** During Round 1's closure review, one hybrid shape
was tested as a candidate fourth: **(1)-build paired with
(3)-submit** — snapshot-ID pinning at build time, with
`submit` waiting for refresh quiescence before validating
staleness. The hybrid was rejected on criterion 5: the
contract dependency on refresh quiescence at the submit
step is the same fatal property that defeats shape (3) at
its own submit step. The hybrid's only difference from (3)
is moving the contract dependency from build-and-submit to
submit-only; it does not eliminate the dependency. A
hostile daemon stalling refresh during a `submit` call
delivers the same DoS surface as shape (3). The hybrid is
documented here so future per-engine PR pre-flights have a
worked example of what "the contract dependency moves but
doesn't dissolve" looks like under the lens. Shape (1)
under the actor mesh — `submit`'s field-comparison handler
runs against `current_snapshot` regardless of refresh
liveness — is the only shape that eliminates the dependency
at both build and submit.

The fourth-shape test exhausts the wargaming surface
known at Round 1 closure time. New shapes that surface in
Round 2 (or later rounds) reopen Round 1 rather than
slipping past closure — see §7 for the general statement.

### §5.1 The question (re-evaluated under §5.0)

When `PendingTxEngine::build` is invoked while a refresh attempt
is in flight (the steady-state poll case, or the cold-open multi-
minute case), what is the trait contract? Three candidate shapes,
each with different reservation-tracker semantics and different
UI consequences. The §5.0 actor-mesh lens surfaces three
**structural** grounds the synchronous framing did not, and on
those grounds shape (1) wins decisively rather than narrowly.

**Three structural grounds the actor-mesh lens surfaces.**

1. **The cross-trait synchronous query disappears.** Under the
   synchronous framing the seed first projected, `LedgerEngine`
   had to grow `current_snapshot_id() -> SnapshotId` so
   `PendingTxEngine::build` could read it inline. Under the
   actor framing, snapshot identity flows through the
   diagnostic-stream surface as a `LedgerDiagnostic::SnapshotMerged
   { new, prior, height }` event emitted at the merge gate's
   normal operation. `PendingTxActor` knows the current snapshot
   because it subscribed to the stream when it spawned, not
   because it can synchronously query `LedgerEngine`. Phase 0c
   collapses from *cross-trait synchronous query amendment*
   (load-bearing surface) to *additive event variant*
   (additive surface). See §4 Phase 0g for the resulting shape.
2. **The CAS isn't a CAS.** Under the actor mesh, `submit` is a
   mailbox message; the actor processes one message at a time;
   "check `reservation.snapshot_id` against `current_snapshot`"
   is a **field comparison in the message handler**, not a
   compare-and-swap. There is no concurrency to swap against —
   the actor is the serialization point. This eliminates an
   entire class of "what if a snapshot rotation happens between
   the CAS check and the consumption?" subtlety: between
   messages the actor is at rest; within a message handler no
   other state mutation happens. The synchronous-CAS framing
   from the seed's working hypothesis was implementation detail,
   not contract; the actor framing reduces the contract to "the
   message handler reads its own state."
3. **Adversarial-daemon resistance is structural, not just
   performance.** Under the actor mesh, `PendingTxActor` is
   decoupled from `RefreshActor`'s liveness by mailbox. A
   hostile daemon stalling refresh keeps `RefreshActor` busy
   in its `produce_scan_result` loop; `PendingTxActor`'s
   mailbox continues processing `build` / `submit` / `discard`
   messages against whatever the most-recently-merged snapshot
   is. There is no shared lock, no shared synchronous code
   path, no shared waiting-for-completion. Shapes (2) and (3)
   *require* `PendingTxActor` to query `RefreshActor`'s state,
   which is what creates the DoS surface; shape (1) under the
   actor mesh has no such query — `PendingTxActor` knows what
   it knows from the stream. Criterion 5 (§5.3) becomes
   load-bearing-by-construction, not contingent.

The shape comparison below applies these grounds to each
candidate.

#### (1) Build-against-current-snapshot + snapshot-ID pinning (Round 1 disposition)

`build` reads `current_snapshot` from `PendingTxActor`'s own
state (Stage 4: maintained from `LedgerDiagnostic::SnapshotMerged`
events; Stage 1: read from `LedgerEngine` through the trait,
internally — not as a contract on the trait surface) and
constructs the transaction against it. The resulting
`Reservation` carries a `snapshot_id`. `submit` validates
staleness via field comparison in the message handler:
succeed iff `current_snapshot == reservation.snapshot_id`;
else emit `PendingTxDiagnostic::SubmitSnapshotInvalidated`
and reply with `SubmitError::SnapshotInvalidated`.

- **Pros (UX).** UI shows "pending" without flashing; reservation
  tracker has monotone semantics (each reservation pinned to
  exactly one snapshot, never re-quoted); refresh and build
  proceed concurrently without serialization; consumer rebuilds
  cleanly on snapshot invalidation.
- **Pros (structural ground 1 — Phase 0c collapses).** No
  cross-trait synchronous query amendment to `LedgerEngine`;
  snapshot identity flows through the additive
  `LedgerDiagnostic::SnapshotMerged` event variant (Phase 0g).
  Surface complexity stays roughly the same as the seed
  projection but the cross-trait coupling moves from
  load-bearing-surface to additive-surface — auditable by
  reviewing the event variant set, not by re-litigating
  `LedgerEngine`'s API.
- **Pros (structural ground 2 — no CAS).** The submit-time
  staleness check is a field comparison in the actor's message
  handler, not a compare-and-swap. The actor is the
  serialization point; no concurrency exists to swap against
  between handler invocations. R3 / R10 dissolve as
  trait-surface contract questions (§5.4).
- **Pros (structural ground 3 — adversarial-daemon resistance
  is structural).** `PendingTxActor` is decoupled from
  `RefreshActor`'s liveness by mailbox FIFO. A hostile daemon
  stalling refresh cannot block the `build` / `submit` flow —
  there is no shared lock, no synchronous query, no
  waiting-for-refresh path. Adversarial daemon can force
  snapshot-rotation churn only by producing real chain reorgs
  (bounded by Shekyl's reorg-window depth); each consumer
  rebuild cycle is bounded latency, not unbounded. Criterion 5
  (§5.3) is satisfied by construction.
- **Cons.** New types: `SnapshotId`, `SubmitError::
  SnapshotInvalidated`, `PendingTxDiagnostic` enum. `SnapshotId`'s
  opacity is a Round 2 question (height-bearing token leaks
  block-height info into the actor envelope; opaque token
  requires the diagnostic-stream emitter to maintain a
  snapshot-ID derivation rule — see R2 in §5.4 for the
  recursive-trust-boundary refinement). The
  `LedgerDiagnostic::SnapshotMerged` event variant addition
  (Phase 0g) is cross-trait but additive only.

#### (2) `RefreshInProgress` error at build (rejected)

`build` returns `SendError::RefreshInProgress` if any refresh
attempt is in flight. The consumer waits for the refresh to
complete and retries.

- **Pros.** Minimal trait-surface change; no new types beyond a
  single `SendError` variant; reservation tracker is unchanged.
  Build only proceeds against a fully-merged ledger state.
- **Cons (UX).** Every steady-state poll racing with a user
  action flashes a transient UI error. The user retries;
  sometimes the retry races again. UI consequence under typical
  usage is poor — refresh polls happen every ~10–30 seconds,
  and any user action initiated during the poll window fails.
- **Cons (structural-ground-3 fatal — adversarial-daemon DoS by
  construction).** (2)'s contract makes the build/submit flow
  **dependent on refresh quiescence** — `build` cannot proceed
  while a refresh is in flight, so the contract requires
  observing refresh state somewhere. The standard
  implementation has `PendingTxActor` query `RefreshActor`'s
  state ("is a refresh attempt in flight?"); a stream-
  subscription steelman has it observe `RefreshDiagnostic`
  events instead (see §5.3 criterion 5). **Both deliver the
  same DoS:** an adversarial daemon controls refresh duration
  (RPC latency, response timing, withholding response
  completion); it can keep one refresh perpetually "in flight"
  via slow drip-feed responses, indefinitely blocking every
  user `submit` attempt with `SendError::RefreshInProgress`.
  Single-peer DoS of the entire transaction-submission flow —
  structural under the actor-mesh framing because the
  **contract dependency on refresh quiescence** is the attack
  surface, not any specific observation mechanism. Privacy
  wallets routinely connect to daemons under adversary control
  (Tor-routed daemons, hosted-wallet operators, mixed-trust
  deployments per
  [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md)); the
  build/submit flow must not depend on refresh quiescence for
  the wallet to remain usable in those threat models.
  **Rejected on criterion 5 (§5.3).**

#### (3) Block-until-merge at build (rejected)

`build` waits for the current refresh attempt to complete before
reading the snapshot. No error variant; just latency.

- **Pros.** No new types; no new error variants; UI shows a
  spinner without flashing.
- **Cons (UX).** Cold-open case: refresh attempt can take
  minutes; `build` hangs for the full duration. Serializes user
  input behind background work, which is the wrong default per
  PR 4 §5.4.4's three-call-mode constraint. Forecloses concurrent
  build-during-refresh entirely.
- **Cons (structural-ground-3 fatal — same DoS as (2)
  delivered as silent hang).** (3)'s contract has the same
  **dependency on refresh quiescence** as (2), realized as a
  wait rather than an error. The standard implementation has
  `PendingTxActor` await `RefreshActor`'s completion; a
  stream-subscription steelman has it await an
  `AttemptCompleted` event from `RefreshDiagnostic` (see §5.3
  criterion 5). Both stall identically: adversarial daemon
  keeps refresh "in flight" via drip-feed responses; `build`
  waits indefinitely regardless of which mechanism observes
  quiescence. Worse user experience than (2) (no error to act
  on, just a perpetual spinner) and identical structural DoS
  by construction — the **contract dependency on refresh
  quiescence** is the attack surface, not the await mechanism
  specifically. **Rejected on criterion 5 (§5.3).**

### §5.2 Implications for PR 4 (resolved as confirmation)

Under §5.0's actor-mesh framing, PR 5 Round 1 closes at
shape (1) on **structural grounds** — not on the contingent
"snapshot-ID pinning is one of three roughly-equivalent
options" grounds the seed projected. The implication for PR 4
follows directly:

- **PR 4 α confirms.** The reservation tracker has monotone
  semantics under α. `RefreshActor` produces one `ScanResult`
  per attempt (per α); `LedgerEngine`'s merge gate emits
  `LedgerDiagnostic::SnapshotMerged` on each merge;
  `PendingTxActor` updates `current_snapshot` from the stream;
  `submit`'s field-comparison handler catches stale reservations
  cleanly. No γ-style consumer-driven refresh-progress streaming
  is required.
- **PR 4 Round 3 is a confirmation-shape round, not a
  re-evaluation round.** PR 4 §5.3's "Round 3 evaluates whether
  PR 5 needs γ for **correctness**" gate closes at *no*. The
  `provisionally load-bearing` qualifier on PR 4 §5.3's α is
  withdrawn; PR 4 α is now confirmed. PR 4 Round 3 records the
  PR 5 R1 input bundle (this section + §5.5) and advances to
  Round 4 (commit decomposition + Phase 1 commit list).
- **No fourth-shape escape.** Under the actor-mesh framing the
  γ shape (consumer-driven refresh-progress streaming) is
  unnecessary: `PendingTxActor` already gets refresh-progress
  state push-driven from the diagnostic stream; the consumer-
  side query that γ was designed to support has no caller.
  Shapes (2) and (3) failed criterion 5 structurally; γ is
  not a fourth option to escape to but a redundant pattern
  the framing makes superfluous.

**Round 1 closure.** Round 1 closes here; Round 2 carries
residuals R2 / R8 / R9 / R11 / R12 plus Phase 0 enumeration.

### §5.3 Five-criteria rationale (PR 4 precedent + adversarial-daemon extension)

Round 1's disposition is evaluated against:

1. **PR 5 extraction cleanliness.** Does the chosen shape
   survive a §3.2 "moves not rewrites" pattern against the
   existing transaction-construction path? Specifically: does
   `LocalPendingTx::build` delegate to existing `Engine`-side
   code unchanged, or does it require new internal logic
   (snapshot-ID stamping, CAS at submit, etc.)?
2. **PR 4 α-disposition's `provisionally load-bearing` status.**
   Does the chosen shape let PR 4 confirm α (and proceed to
   Round 4), or does it force PR 4 to re-open to γ for
   correctness?
3. **Reservation-tracker reorg semantics.** Does the chosen
   shape give the tracker monotone semantics? Specifically: can
   a reservation be silently "rewound" by a merged reorg, or
   does the tracker's state-transition surface cover every
   possible reorg outcome with an explicit disposition (consume,
   release, error-at-submit)?
4. **Stage 4 actor-migration compatibility.** Does the chosen
   shape survive the `ActorRef<PendingTxActor>` migration
   without re-design? Specifically:
   - Can the build/submit/discard envelope cross the actor
     mailbox without leaking semantic content (e.g., does
     `SnapshotId` opacity hold across the mailbox)?
   - Does submit-time staleness detection translate cleanly to
     a mailbox message? Under the §5.0 framing this reduces to
     "the actor's own state-comparison in the message handler"
     rather than a CAS — the mailbox FIFO is the serialization
     point. (1) passes by construction; (2) and (3) fail
     because their **contract dependency on refresh quiescence**
     (criterion 5) creates a structural cross-actor coupling
     the actor mesh cannot serialize without re-introducing the
     DoS surface — regardless of which observation mechanism
     (synchronous query, stream-subscription bool, mailbox
     await) realizes the contract.
5. **Adversarial-daemon resistance (load-bearing-by-construction
   under §5.0).** Does the chosen shape survive a hostile
   daemon attempting to DoS the transaction-submission flow?
   Under the §5.0 actor-mesh framing this is **structural**, not
   contingent: the DoS surface is **contract dependency on
   refresh quiescence at any point in the build/submit flow**.
   Shapes (2) and (3) both build their contract on the property
   "no work proceeds while refresh is in flight" — (2) at the
   build stage as an explicit error; (3) at the build stage as
   a silent wait — and the daemon controls refresh duration.
   The *standard implementation* of either contract has
   `PendingTxActor` query `RefreshActor`'s state directly ("is a
   refresh in flight?" / "has the refresh completed?"); under
   hostile daemon control of refresh duration that query stalls
   indefinitely and the build/submit flow stalls with it.

   **Steelman defense — stream-subscription implementation.**
   A reviewer may steelman (2)/(3) by observing that
   `PendingTxActor` need not synchronously query `RefreshActor`
   — it can subscribe to PR 4's `RefreshDiagnostic` stream
   (`AttemptStarted` / `AttemptCompleted` events), maintain a
   `refresh_in_flight: bool` push-driven from those events, and
   gate `build` on the bool flipping false (for (3)) or return
   `RefreshInProgress` while true (for (2)). The steelman
   avoids the cross-actor query mechanism entirely. **It still
   fails criterion 5.** The daemon controls when
   `AttemptCompleted` fires (by controlling RPC response
   completion timing); the bool stays `true` indefinitely under
   drip-feed responses; the build (or submit, in any contract
   that gates on quiescence) stalls regardless of which
   mechanism observes quiescence. The load-bearing property is
   the **contract's dependency on refresh quiescence**, not the
   specific machinery that observes it. Synchronous query,
   push-driven bool from a diagnostic stream, mailbox await,
   polling at fixed intervals, or any other mechanism that
   delivers the "refresh has reached a quiescent state" signal
   carries the same daemon-controllable failure mode — because
   the daemon controls the underlying signal, not the
   observation channel.

   Shape (1) under the actor mesh has *no such dependency* in
   either build or submit. `PendingTxActor` knows the
   most-recently-merged snapshot identity from the diagnostic
   stream (`LedgerDiagnostic::SnapshotMerged`); the build/submit
   flow proceeds against whatever that identity is regardless
   of whether `RefreshActor` is currently making forward
   progress. Submit-time staleness is detected by field
   comparison in the actor's message handler (the §5.5 ground 2
   "the CAS isn't a CAS" property), not by waiting for refresh
   to declare itself quiescent. The decoupling is
   **contract-level**, not implementation-level — no shape (1)
   implementation, by any mechanism, depends on knowing whether
   refresh is in flight.

   **Threat-model anchor (explicit defense).** Shekyl treats the
   daemon as outside the wallet's trust boundary by **design
   choice**, not as a hardened edge case. The Tor/I2P-first
   deployment posture per
   [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) means
   wallets routinely connect to daemons under adversary control
   — anonymous-network exit operators, hosted-wallet
   deployments, mixed-trust environments where the daemon
   operator's identity and posture are unknown. The
   adversary-controlled-daemon case is the **expected
   deployment**, not an exception that the design tolerates.
   Designs that admit structural single-peer DoS of transaction
   submission are therefore rejected as **structurally
   incompatible with the project's primary deployment model** —
   the rejection is not "we can tolerate this in some
   deployments and harden against it in others"; it is "this
   contract shape contradicts the deployment model the design
   serves."

   Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §1
   (security and quantum resilience as preconditions), a shape
   that admits structural single-peer DoS of transaction
   submission is rejected even when its UX is good and its
   trait surface is minimal. This is the rejection ground that
   defeats (2) and (3) under the actor framing — the criterion
   is satisfied by construction by (1), and Round 1's wargaming
   has no fourth-shape escape route that doesn't reintroduce
   the contract dependency on refresh quiescence at some point
   in the build/submit flow.

### §5.4 Residuals (some dissolved by §5.0; rest deferred to Rounds 2+)

Several residuals dissolve by composition under the §5.0
actor-mesh framing — the same pattern as PR 4 §5.4.7 R5
(reorg-amplification → `ReorgAmplificationDetector` consumer
actor). The dissolution is principled, not optimistic: each
dissolved residual is a question the actor-mesh framing makes
**superfluous by construction**, not a question deferred to
later. The remaining residuals (R2 / R8 / R9 / R11 / R12) carry
to Round 2 with the dispositions framed below.

- **R2 — `SnapshotId` opacity and side-channel implications
  (closed in Round 2 segment 2d; Phase 0b detail).**
  Height-bearing `SnapshotId` (e.g., `pub struct SnapshotId(pub
  u64)` carrying block height) is simpler but leaks block-height
  info into every reservation and every actor envelope. Opaque
  `SnapshotId` (a content-addressed digest of `LedgerSnapshot`
  state) closes the height-leak side-channel and requires no
  `LedgerEngine`-side mapping (the digest is content-addressed
  so identity is equality on the digest, not lookup through a
  table).

  **Disposition (closed as opaque content-addressed digest).**
  V3.0 ships `SnapshotId` as a **16-byte content-addressed
  digest** computed from the deterministic fields of
  `LedgerSnapshot` (per §5.4 R12 (a)):

  ```rust
  pub struct SnapshotId([u8; 16]);

  impl From<&LedgerSnapshot> for SnapshotId {
      fn from(snapshot: &LedgerSnapshot) -> Self {
          // Domain-separated hash over deterministic fields.
          // Hash function aligned with PR 4 / PR 5
          // diagnostic-stream / engine-core hashing
          // discipline; truncated to 16 bytes (128-bit
          // collision resistance is sufficient for snapshot
          // identity given the bounded snapshot population
          // — one snapshot per refresh attempt).
          let digest = blake3::hash(&[
              SHEKYL_SNAPSHOT_ID_DOMAIN_SEP,
              &snapshot.synced_height.to_le_bytes(),
              snapshot.reorg_blocks.canonical_bytes(),
          ].concat());
          let mut id = [0u8; 16];
          id.copy_from_slice(&digest.as_bytes()[..16]);
          SnapshotId(id)
      }
  }
  ```

  The exact hash function (Blake3 vs. Keccak-256 vs. domain-
  separated SHA-3) is pinned at Phase 0 review (segment 2g)
  per §3.1 PQC-discipline alignment with the engine's hash
  selection; the segment-2d disposition is the **shape**
  (16-byte content-addressed digest), not the specific hash
  primitive. Truncation to 128 bits is sufficient because the
  snapshot population is bounded (one snapshot per refresh
  attempt; ≪ 2⁶⁴ over wallet lifetime).

  **Determinism is required by staleness detection.** Two
  reservations built against the same snapshot share the
  same `SnapshotId` (the digest is deterministic per
  snapshot). This is **required** by `submit`'s field-
  comparison handler under §5.0 (the snapshot identity must
  be deterministic for the comparison to detect staleness);
  it is also a side-channel for in-process consumers that
  aggregate reservations.

  **Side-channel posture.** Within trust boundary
  (orchestrator, in-process actors), `SnapshotId`-correlation
  across reservations is fine and even useful — the UI can
  batch-display reservations by snapshot for context, and
  the staleness-detection contract benefits from the
  determinism. Across trust boundary in the recursive sense
  per PR 4 §5.4.8 #4 (logs that get pasted, telemetry
  exports, debug UIs with off-host surfaces, any in-process
  consumer that aggregates and republishes), the deterministic
  identity leaks transaction-rate timing — observable as
  "user constructed N transactions during a single ~30s
  polling window."

  **Projection-type discipline (preserved-as-pattern; no V3.0
  named cross-boundary consumer).** The full `SnapshotId`
  flows only to in-process consumers whose external surface
  is itself within the trust boundary. **For cross-trust-
  boundary consumers, the prescribed pattern is projection
  types** — a per-reservation opaque random handle that
  internally maps to a `SnapshotId` for staleness detection,
  distinct per reservation even when the underlying snapshot
  is identical. The same recursive-trust-boundary discipline
  applies to `LedgerDiagnostic::SnapshotMerged { new, prior,
  height }`'s `height` field: in-process consumers see the
  full event, cross-boundary consumers see a projection that
  elides height. **No V3.0 PR 5 call-site introduces a
  cross-trust-boundary `SnapshotId` or `SnapshotMerged`
  consumer**, so the projection-type implementation is
  preserved-as-pattern (the discipline is documented; the
  code lands in the V3.x consumer-actor PR that introduces
  the first cross-boundary consumer). Phase 1 call-site
  sweep (Round 3) confirms no cross-boundary consumer is
  named at V3.0 ship time.

  **Why opaque-digest over height-bearing.** Per
  [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §2
  (privacy is the product), the height-bearing shape leaks
  block-height info through every reservation envelope and
  every actor message — a fingerprint surface that the
  opaque-digest shape closes by construction. The opaque-
  digest cost (one Blake3 call per snapshot merge; one
  comparison per `submit` handler invocation) is bounded;
  the height-bearing simplification is not worth the
  privacy cost.

  **Phase 0 implication (segment 2d).** §4 Phase 0b pins
  `SnapshotId` as `pub struct SnapshotId([u8; 16])` (opaque
  content-addressed digest); Phase 0g pins
  `LedgerDiagnostic::SnapshotMerged { new: SnapshotId,
  prior: SnapshotId, height: BlockHeight }` (the `height`
  field is in-trust-boundary-only data; cross-boundary
  consumers receive a projection via the V3.x consumer-
  actor PR that introduces them). Phase 0 review (segment
  2g) confirms the digest size, the hash primitive
  selection per §3.1 PQC alignment, and the projection-type
  pattern in the doc-only generalization of
  `DIAGNOSTIC_STREAM_CONTRACTS.md`.
- **R3 — Build-during-refresh-during-reorg interaction
  (dissolved by §5.0).** Under the actor mesh, mailbox FIFO
  orders these structurally. Sequence at `PendingTxActor`'s
  mailbox: `BuildMessage` arrives, handler runs against
  `current_snapshot = S_n`; during the handler,
  `LedgerDiagnostic::SnapshotMerged { new: S_{n+1}, prior: S_n,
  height: H+1 }` arrives at the actor's subscriber inbox and
  queues; handler completes, replies with `Reservation {
  snapshot_id: S_n }`; actor processes next message, updates
  `current_snapshot = S_{n+1}`; any subsequent `submit` for the
  build's `Reservation` field-comparison-fails against
  `S_n ≠ S_{n+1}`, replies `SubmitError::SnapshotInvalidated`,
  consumer rebuilds. There is no race; the answer is the FIFO
  order. **No Round 2 disposition required**; PR 5 Phase 0e
  prose pins this as the contract under §5.0.
- **R4 — Discard semantics under snapshot invalidation
  (Round 2 hygiene).** Under shape (1), the
  `SubmitError::SnapshotInvalidated` path auto-releases the
  reservation. Is auto-release the right behaviour, or should
  the consumer explicitly `discard`? The §5.0 framing renders
  this an actor-policy question (the `SnapshotMerged` handler's
  policy on outstanding-from-prior-snapshot reservations);
  default carries forward as lazy auto-discard at next submit.
  Round 2 hygiene; possible §4 Phase 0e prose pin.
- **R5 — Outstanding-reservations behavior on snapshot rotation
  (dissolved as trait-surface question; survives as policy
  question).** Under §5.0, this is `PendingTxActor`'s
  `SnapshotMerged` event handler — a policy decision **local to
  the actor**, not a trait-surface question. The three
  sub-options ((a) eager auto-discard on snapshot rotation;
  (b) lazy auto-discard at next submit per (1)'s
  field-comparison; (c) explicit consumer-driven discard)
  become implementation choices the actor makes; the trait
  contract just specifies that `outstanding()` reflects whichever
  policy is in effect.

  Round 2 disposes which policy ships in `LocalPendingTx`, **not
  what the trait surface requires**. Working default is
  lazy-discard (matches the field-comparison semantics);
  eager-discard is a future optimization if leak-pressure
  becomes measurable. R8's `ReservationTTLActor` provides the
  composition path for explicit-discard policy without trait
  revision.
- **R6 — `outstanding()` semantics under snapshot pinning
  (Round 2 hygiene).** Does `outstanding()` count reservations
  against the current snapshot only, or across all snapshots
  (including about-to-be-invalidated reservations from a prior
  snapshot)? Round 2 hygiene; depends on R5's policy
  disposition.
- **R7 — `Send + Sync + 'static` bound on `P` (Phase 0a
  candidate).** Stage 4 wraps `LocalPendingTx` in a `kameo`
  actor; the bound has to be on the `P` generic parameter.
- **R8 — Reservation TTL / leak prevention (closed in Round 2
  segment 2e as `ReservationTTLActor` consumer-actor
  composition; V3.0 ships the diagnostic-stream seam complete;
  V3.x lands the actor).** What happens to reservations that
  are neither submitted nor discarded? Under shape (1),
  staleness detection at submit invalidates reservations at
  snapshot rotation, but rotation only happens when refresh
  merges new state. A wallet that has finished refreshing and
  sits idle (user reviewing the constructed tx, considering
  whether to send) holds reservations indefinitely against the
  same snapshot. A consumer that crashes or has a bug between
  build and discard leaks the reservation outright. The
  threat-model property the tracker delivers (monotonicity,
  wallet-layer double-spend defence) interacts here: leaked
  reservations are output-locking the wallet against legitimate
  alternative uses.

  **Reframed disposition under §5.0.** A `ReservationTTLActor`
  subscribes to `PendingTxDiagnostic::BuildSucceeded` events,
  maintains in-memory per-reservation age tracking, emits
  `PendingTxDiagnostic::ReservationOutstanding { reservation_id,
  age }` warnings on stale reservations, signals
  `PendingTxActor` (via `AutoDiscardMessage { reservation_id }`
  mailbox message) to auto-discard if TTL policy permits. Same
  shape as PR 4's `PeerReputationActor` / `RecoveryActor`
  consumer-actor pattern. The trait surface stays minimal; the
  capability composes.

  **Disposition (closed in segment 2e).** Same architectural-
  integrity-now discipline as PR 4's consumer-actor pattern
  (`PeerReputationActor` / `RecoveryActor`): V3.0 lands the
  diagnostic-stream seam **complete with all variants needed
  by V3.x**; V3.x lands the consumer actor without any V3.x
  trait or enum revision. The pattern is described in PR 4
  §5.4.7 R6 reframe and binds verbatim here.

  **V3.0 deliverables (segment 2e closure).** PR 5 ships:

  1. **`PendingTxDiagnostic::BuildSucceeded { reservation_id,
     snapshot_id, outputs_count }`** — emitted at the
     `build`-success path in `LocalPendingTx::build` /
     `PendingTxActor::handle_build` immediately after the
     reservation is recorded in `ReservationTracker` /
     `reservations` HashMap and before the reply is sent. Phase
     1 call-site review (Round 3) confirms emission discipline.
  2. **`PendingTxDiagnostic::Discarded { reservation_id,
     reason: SnapshotRotationAutoDiscard }`** — emitted at
     `submit`'s snapshot-mismatch path (R5's lazy-discard
     semantics) when the field-comparison handler detects a
     stale reservation. The reservation auto-releases on this
     event; `submit` returns `SubmitError::SnapshotInvalidated`
     to the consumer.
  3. **`PendingTxDiagnostic::ReservationOutstanding {
     reservation_id, age }` variant exists in the
     `#[non_exhaustive]` enum** but is **not emitted in V3.0**
     — `ReservationTTLActor` is the only intended emitter, and
     it lands in V3.x. The variant existing pre-V3.0 means
     V3.x's `ReservationTTLActor` introduction does not require
     a `PendingTxDiagnostic` enum revision; per PR 4 §5.4.8 #6
     the consumer-side discipline ("treat unknown variants as
     `_ => ignore`") makes the emission-introduction additive.
  4. **`DiscardReason::TTLAutoDiscard` variant pin (segment 2e
     addition).** The current `#[non_exhaustive] enum
     DiscardReason` set (`ConsumerExplicit`,
     `SnapshotRotationAutoDiscard`, `DaemonRejectedTerminal`)
     does not name TTL-triggered discards. Segment 2e adds
     `TTLAutoDiscard` so V3.x's `ReservationTTLActor` can
     trigger `PendingTxActor` to emit `Discarded { reason:
     TTLAutoDiscard }` events without a V3.x `DiscardReason`
     enum revision. The variant exists pre-V3.0; no V3.0
     emitter; V3.x `ReservationTTLActor` is the first emitter.

  **Hard mitigation pins (binding on the V3.x consumer-actor
  PR per PR 4 §5.4.8).** Inherited verbatim via §5.0.3:

  - **Restart-amnesia per PR 4 §5.4.8 #1.** `ReservationTTLActor`
    state is in-memory only, scoped to the wallet session;
    drop on wallet close. No persistence beyond the wallet
    session. (Note: R17's segment-2c refinement permits
    user-controlled opt-in encrypted persistence for
    long-running deployments; the TTL actor's age-tracking
    state is a candidate for that persistence consumer when
    R17's V3.x implementation lands.)
  - **Recursive trust boundary per PR 4 §5.4.8 #4.**
    `ReservationOutstanding` warnings carry `reservation_id`
    and `age`; cross-boundary consumers receive projected
    events that elide `reservation_id` (or use opaque
    per-event handles per R2's projection-type discipline
    when the V3.x cross-boundary consumer-actor PR lands).
  - **Bounded mailbox per PR 4 §5.4.8 #5.** A consumer with
    per-reservation-age tracking unbounded against a
    reservation-spam scenario is itself an OOM surface;
    drop-oldest-on-overflow with aggregate age-band counts
    preserves the warning function at scale.

  **R5 ↔ R8 coherence (segment 2e verification).** R5's lazy
  auto-discard at submit time (`SnapshotRotationAutoDiscard`)
  is the **reactive** cleanup path — reservations against
  rotated snapshots get cleaned up when the consumer tries to
  use them. R8's `ReservationTTLActor` is the **proactive**
  complement — reservations that *never get used at all*
  (idle wallet; consumer crash; build-but-never-submit bug)
  get cleaned up by age-based policy. The two are
  architecturally distinct (R5 lives in `PendingTxActor`'s
  `submit` handler; R8 lives in a separate consumer actor)
  but use the same `DiscardReason`/`Discarded` event
  infrastructure. R5 emits `SnapshotRotationAutoDiscard`; R8
  emits (via `AutoDiscardMessage` round-trip to
  `PendingTxActor`) `TTLAutoDiscard`. Downstream consumers
  see a unified `Discarded` event stream with discriminated
  reasons.

  **Why architectural-integrity-now for V3.0 even though the
  actor lives in V3.x.** Per
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
  continuous-discipline corollary, the V3.x consumer-actor PR
  does not get to revise the V3.0 diagnostic-stream surface;
  the surface needs to be complete at V3.0 ship time.
  Segment 2e's closure pins **all V3.0 deliverables**
  (emission call sites for 1 and 2; variant existence for 3;
  variant addition for 4) so V3.x's `ReservationTTLActor`
  introduction is **additive only** — no trait revision, no
  enum revision, no consumer-side breaking change. Identical
  pattern to PR 4's `PeerReputationActor` consumer-actor
  shape.

  **V3.x trigger.** *When Stage 4 actor mesh stabilizes* —
  same trigger as PR 4's V3.x consumer-actor entries. The
  trigger gates land together because the consumer-actor
  pattern requires the actor-system runtime to land first
  (kameo wiring, mailbox infrastructure, supervisor tree).

  **FOLLOWUPS update.** Segment 2e amends the existing
  `ReservationTTLActor` FOLLOWUPS entry with the
  `DiscardReason::TTLAutoDiscard` variant pin (new V3.0
  deliverable per segment 2e closure) and confirms the
  segment-2e closure status. No new FOLLOWUPS entry is
  needed; the existing entry's Round 1 reframe already names
  the consumer-actor shape and the inherited contracts.
- **R9 — Daemon-side submit failure → reservation state
  (reframed as two-stage submit flow; Round 2).** R4 covers the
  staleness-fails case (snapshot-invalidated → auto-release →
  rebuild). It does **not** cover the staleness-passes-but-
  daemon-rejects case: `submit` consumed the reservation and the
  daemon returned `AlreadyInMempool` / `DoubleSpend` /
  `FeeTooLow` / `Malformed` / timeout.

  **Reframed flow under §5.0.** `PendingTxActor` receives
  `SubmitMessage`, performs the staleness field-comparison,
  sends `SubmitTxMessage` to `DaemonEngine` actor, awaits the
  reply (or uses ask-with-continuation pattern). The
  reservation state during the daemon round-trip is
  `submitted-pending-daemon-ack` — an intermediate state that
  must be explicit in the actor's state machine.

  Per-error-class semantics:
  - `AlreadyInMempool` — the tx is already known; treat as
    success and emit `PendingTxDiagnostic::SubmitSucceeded`
    (idempotent).
  - `DoubleSpend` — the outputs are genuinely gone; the
    tracker's "available" view is wrong and needs refresh;
    emit `Discarded { reason: DaemonRejectedTerminal }`.
  - `FeeTooLow` — the consumer may want to retry with higher
    fee; the outputs should be available again; emit
    `SubmitFailed { kind: FeeTooLow }` and **release the
    reservation** to the available pool.
  - `Malformed` — wallet-side bug or daemon-byzantine path;
    reservation releases but the bug surfaces diagnostically
    (`SubmitFailed { kind: Malformed }` plus producer-side
    `InternalInvariantViolation` if the malformation is
    wallet-attributable).
  - Timeout — genuinely ambiguous; the tx may or may not have
    landed. Conservative disposition: do not auto-retry; force
    operator to query before resubmitting; reservation stays in
    `submitted-pending-daemon-ack` state.

  **Round 2 disposition.** Three intermediate-state options:
  (a) block the `PendingTxActor` mailbox during daemon
  round-trip (simple, throughput-limiting);
  (b) **intermediate-state with self-continuation message
  (`SubmitCompleted { id, daemon_result }`) — preserves
  throughput, makes the intermediate state explicit, handles
  daemon timeouts cleanly;** working disposition.
  (c) one outstanding daemon-submit at a time with queue
  (compromise).
- **R10 — Concurrent build/submit/discard on the same
  reservation (dissolved by §5.0).** Under the actor mesh,
  mailbox FIFO is the contract. Two concurrent `submit(id)`
  messages from different consumers: first-acquired-mailbox-slot
  wins; the actor processes them serially; the second observes
  the consumed-reservation state and replies with the
  appropriate error. No mutex contention semantics to pin in
  the trait contract because there is no mutex — the actor is
  the serialization point. The contract pin reduces to
  "messages process serially per actor instance," which is the
  `kameo` / actor-system invariant, **not a `PendingTxEngine`
  trait property**. Stage 1's `LocalPendingTx` satisfies this
  by holding `Mutex<ReservationTracker>` under `&self`; the
  Stage 4 `PendingTxActor` satisfies it by mailbox FIFO. Both
  satisfy the trait contract; the trait contract needs no
  pinning because the actor-system invariant pins it
  transitively. **No Round 2 disposition required**; PR 5
  Phase 0e prose pins this under §5.0.
- **R11 — Signing-actor split (closed in Round 2 segment 2b as
  (b); HW-wallet integration in V3.x plugs into existing
  architecture).** §3.1 spend-secret-locality says the spend
  secret enters the signing path at submit time. Round 1's
  working disposition leaned (a) — `PendingTxActor` holds
  spend material, "matches PR 4 R4's instance-scoped pattern" —
  with shape (b) (separate `SigningActor`) deferred to V3.x with
  the HW-wallet trigger. Segment 2b's adversarial review
  identified the cost-asymmetry argument that justified PR 4 R4's
  tactical (a) does **not** apply to PR 5 R11; (b) is the
  architectural-integrity-now answer.

  **Disposition (closed as (b)).** `LocalPendingTx` /
  `PendingTxActor` does not hold spend material. Spend material
  lives in a separate `LocalSigner` (Stage 1) / `SigningActor`
  (Stage 4) construct that exposes a narrow signing surface:

  ```rust
  // Stage 1: LocalSigner is the sole holder of spend material
  trait Signer: Send + Sync {
      fn sign_tx(
          &self,
          tx: TransactionToSign,
      ) -> Result<SignedTransaction, SignerError>;
  }

  struct LocalSigner {
      spend_secret: Zeroizing<[u8; 32]>,
  }

  impl Signer for LocalSigner { /* signs with spend_secret */ }

  // LocalPendingTx delegates to the Signer; never holds spend material
  struct LocalPendingTx<S: Signer> {
      inner: Mutex<ReservationTracker>,
      sink: Arc<dyn DiagnosticSink>,
      ledger: L,
      signer: Arc<S>,            // sole holder of spend material
  }

  // Stage 4: SigningActor is a direct port of LocalSigner
  struct SigningActor {
      spend_secret: Zeroizing<[u8; 32]>,
  }

  struct PendingTxActor {
      current_snapshot: SnapshotId,
      reservations: HashMap<ReservationId, Reservation>,
      sink: Arc<dyn DiagnosticSink>,
      signer: ActorRef<SigningActor>, // sole holder of spend material
  }
  ```

  The `PendingTxEngine` trait surface does **not** change to
  accommodate this — the `Signer` is internal to the
  implementation, not part of the trait. Same property the
  existing `ledger: L` field has in §5.0.1.

  **The cost-asymmetry argument decomposed.** PR 4 R4 chose
  (a-instance-scoped) because Stage 1's spend-secret-flow
  architecture was already tied to (a)-equivalent: the existing
  `Scanner` held view + spend material, and moving to (c)
  required restructuring `Scanner` itself. The cost of
  restructuring was the deferral trigger. PR 5 is opening the
  trait surface; there is no existing `LocalPendingTx` structure
  to move from. The choice between (a) and (b) is the same cost
  either way; we are designing one or the other from scratch,
  not moving from one to the other. The "moves-not-rewrites"
  framing that justified PR 4 R4's (a) is upside-down for PR 5
  R11.

  **R4-consistency cuts the other way.** PR 4 R4's (a)
  disposition explicitly named (c) as the long-term shape with
  the HW-wallet trigger. Citing R4 as precedent for R11's (a)
  settlement compounds the deferral across both engines and
  makes the eventual V3.x migration more expensive (two engines
  need to migrate instead of one). The discipline-correct read:
  PR 4 R4 stays as it is (already landed under inheritance-
  pattern cost asymmetry); PR 5 R11 lands the architecturally-
  clean shape from the start because the inheritance-pattern
  cost asymmetry does not apply here.

  **HW wallets are core, not edge.** Per
  [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §1,
  security is precondition, not optimization. Hardware-backed
  secure-storage paths (trezor / ledger / YubiKey-class) are
  dominant for privacy-conscious users; foundation release-key
  signing already uses hardware-backed key storage. Designing
  the trait surface so spend material never enters
  `PendingTxActor` is the threat-model-correct shape; deferring
  it to V3.x treats the architecturally-cleaner shape as an
  optimization rather than the baseline.

  **Audit-surface narrowing.** Under (b), spend material lives
  in one actor whose sole job is signing. The audit question
  "where can the spend secret leak?" has one answer; the
  actor's surface is a small message vocabulary
  (`SignTx { tx_bytes, view } -> SignedTx`), one state field
  (`spend_secret`), one lifetime contract (lives with the
  wallet, zeroizes on lock). Under (a), spend material lives in
  `PendingTxActor` alongside reservation-tracker state, fee
  estimation, output selection, and daemon-submission
  orchestration — audit scope expands to cover all of it.
  (a) is not just less HW-wallet-ready; it is a larger audit
  surface for spend-material protection.

  **Stage 4 actor migration cost asymmetry.** Splitting an
  existing actor (the V3.x trajectory if (a) lands at Stage 1)
  is harder than designing actors split (the Stage 1 trajectory
  if (b) lands now): message types change, state ownership
  changes, downstream consumers of the original actor's events
  change. Doing this once in PR 5 design rounds is bounded;
  doing it as a post-Stage-4 migration is multi-engine refactor
  work with cross-actor implications.

  **HW-wallet integration in V3.x.** Plugs into the existing
  architecture as an alternative `Signer` implementation
  (`HardwareSigner` delegating to the device); no architectural
  change. PR 4 R4's V3.x deferred-(c) (split-producer/recoverer
  for view-tag matching vs. final hybrid-decap, per
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R4) benefits from PR 5 R11 (b)'s `SigningActor`
  infrastructure: the spend-key-isolated actor R4 (c) needs has
  a precedent and a target shape in PR 5's `SigningActor`; the
  V3.x R4-(c) migration becomes simpler.

  **FOLLOWUPS update.** The pre-segment-2b V3.x entry tracking
  the PR 5 R11 (b) deferral is replaced by a V3.x entry
  tracking HW-wallet integration as a `Signer`-impl
  substitution (no architectural change required at the
  trigger).

  **Round 1's (a)-leaning disposition was the cost-benefit-
  defer-to-later anti-pattern recurring in a residual.** Per
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
  §The "cost-benefit-defer-to-later" anti-pattern: when
  conventional cost-benefit analysis recommends incremental work
  and architectural-integrity analysis recommends structural
  work, the default disposition for security-load-bearing work
  is fix structurally now unless the cost is genuinely
  prohibitive. R11's reframe is a PR-5-internal instance of the
  discipline that PR 3 / PR 4 established at the load-bearing
  question; segment 2b applies it at the residual-disposition
  level so future per-engine PRs inherit the precedent that
  R-residual dispositions are subject to the same architectural-
  integrity-now discipline as load-bearing questions.
- **R12 — Stage 1 `current_snapshot` acquisition mechanism
  (closed in Round 2 segment 2d as (a) — content-derived
  `SnapshotId` from existing `LedgerSnapshot` data).** §5.0.1's
  `LocalPendingTx` sketch shows `ledger: L` "for
  `current_snapshot` reads in Stage 1." The §5.5 ground-1
  claim that "Phase 0c collapses" is true at the trait surface —
  the trait does not require `LedgerEngine::current_snapshot_id()`
  because actor consumers receive snapshot identity via
  `LedgerDiagnostic::SnapshotMerged` (Phase 0g). Round 1 left
  Stage 1's mechanism unspecified pending Round 2's
  inspection of the actual `LedgerSnapshot` shape.

  **Disposition (closed as (a)).** `LedgerSnapshot` —
  per [`rust/shekyl-engine-core/src/engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  ll. 147–166 — carries
  exactly the deterministic state R12 (a) needs:

  ```rust
  // LedgerSnapshot (pre-existing, PR 2 substrate)
  pub struct LedgerSnapshot {
      pub(crate) synced_height: u64,
      pub(crate) reorg_blocks: ReorgBlocks,
      // (ReorgBlocks: Vec<(u64, [u8; 32])>)
  }
  ```

  Both fields are deterministic given the ledger state at
  snapshot time; `LedgerSnapshot::from_ledger(&LedgerBlock)`
  is the existing constructor. Stage 1's `LocalPendingTx`
  acquires `current_snapshot` by:

  ```rust
  // Stage 1: LocalPendingTx::build (sketch)
  fn build(&self, intent: BuildIntent) -> Result<Reservation, BuildError> {
      let snapshot = self.ledger.snapshot();          // existing trait method
      let snapshot_id = SnapshotId::from(&snapshot);  // R2: opaque digest
      // ... construct reservation against snapshot, stamp snapshot_id
  }
  ```

  No new `LedgerEngine` trait surface; no cross-trait
  coupling beyond what `LedgerEngine::snapshot()` already
  provides. **Phase 0c truly collapses.**

  **Why (b) and (c) are rejected.** (b) (Stage 1 subscribes
  to the diagnostic stream) adds implementation-symmetry
  cost without architectural payoff — Stage 1's `&self`
  trait-call pattern reads `current_snapshot` synchronously
  through `LedgerEngine::snapshot()`; the stream-subscription
  pattern is the right shape for Stage 4 (where the actor
  is event-driven by construction) but not for Stage 1.
  (c) (`LedgerEngine` grows a `current_snapshot_id()`
  accessor) is unnecessary because `LedgerSnapshot`'s
  existing fields are sufficient for content-addressed
  derivation; adding the accessor would be a cross-trait
  amendment for a property that derives from already-
  available state.

  **Stage 4 alignment.** Stage 4's `PendingTxActor` maintains
  `current_snapshot: SnapshotId` in actor state, updated
  from `LedgerDiagnostic::SnapshotMerged { new, prior, height
  }` events. The Stage 4 `SnapshotId` is the **same digest
  function** applied at merge time inside `LedgerEngine`
  before emitting the event (so Stage 1 and Stage 4 produce
  identical `SnapshotId` values for identical `LedgerSnapshot`
  state). The digest function is documented in §5.4 R2 below.

  **§5.5 ground-1 prose softening.** The "pending R12"
  qualifier on ground 1 is dropped (§5.5 segment 2d
  edit); ground 1 is now closure-confirmed: Phase 0c
  collapses cleanly, R12 (a) is the chosen mechanism, no
  trait amendment.

  **§4 Phase 0c prose softening.** "(pending R12)" qualifier
  dropped (§4 segment 2d edit); Phase 0c is REMOVED at the
  trait surface — full stop.
- **R14 — `Reservation` extensibility seam (closed in Round 2
  segment 2b; near-zero cost; forecloses V3.x trait revision).**
  The current `Reservation` shape (reservation-id +
  snapshot-id + selected-outputs + tx-bytes) is the
  wallet2-flat-record shape carried forward. Under V3.x,
  reservations could be richer primitives:

  - Coinjoin coordination state (counterparty commitment,
    partial signatures).
  - Atomic-swap HTLC parameters.
  - Time-locked submission metadata.
  - Multi-stage state machines (waiting-for-counterparty →
    waiting-for-confirmation → confirmed).
  - Composable reservations (escrow patterns).

  None of these are V3.0 features. Adding an `extensions:
  Vec<ReservationExtension>` seam to `Reservation` now — with
  an empty initial variant set on `ReservationExtension`,
  marked `#[non_exhaustive]` — costs almost nothing and
  forecloses a V3.x trait revision. Future variants extend
  additively without breaking V3.0 wallets that don't
  understand them.

  ```rust
  pub struct Reservation {
      pub id: ReservationId,
      pub snapshot_id: SnapshotId,
      pub outputs: Vec<SelectedOutput>,
      pub tx_bytes: Vec<u8>,
      pub extensions: Vec<ReservationExtension>, // empty in V3.0
  }

  #[non_exhaustive]
  pub enum ReservationExtension {
      // V3.x variants land here (CoinjoinState, HtlcParams,
      // TimelockedSubmission, MultiStageState,
      // ComposedReservation). PR-5-side: none in V3.0.
  }
  ```

  **Same pattern as the diagnostic-stream extensibility seams.**
  `RefreshDiagnostic` (PR 4) and `PendingTxDiagnostic` (PR 5)
  are both `#[non_exhaustive]` — the V3.0 variant set is the
  shipping minimum; V3.x adds variants additively without
  breaking V3.0 consumers. R14 extends this discipline to
  `Reservation`'s value-data shape: V3.0 ships the minimum
  field set with the extensibility hook; V3.x consumer-actor
  PRs populate variants. Round 2 hygiene; small cost; large
  optionality preservation.

  **Phase 0 implication (segment 2b).** §4 Phase 0 enumeration
  pins the `Reservation` shape with the `extensions` field and
  the `#[non_exhaustive]` enum stub. The variant set is empty
  at V3.0; the variants land in V3.x consumer-actor PRs. Phase
  0 review (segment 2g) confirms the field-name discipline
  (`extensions: Vec<ReservationExtension>` matching the
  `RefreshDiagnostic` / `PendingTxDiagnostic` extensibility-
  pattern conventions) and the `#[non_exhaustive]`
  attribute placement.

  **R14 is name-only-architectural-integrity-now (R11's
  light-cost twin).** Where R11 reframe's (b) closure is
  load-bearing security work, R14's extensibility seam is
  optionality preservation that V3.0 should not pay deferred
  trait-revision cost to skip. The discipline-budget cost of
  segment 2b combining the two is bounded; the architectural-
  integrity-now payoff is asymmetric (R11 large; R14 small)
  but both lift in the same commit slot.
- **R13 — Output selection algorithm as a first-class privacy
  decision (named with disposition in Round 2 segment 2c;
  V3.0 ships wallet2-greedy under `OutputSelector` trait
  seam; V3.x lands alternatives).** `ReservationTracker`
  carries forward an output-selection algorithm wallet2
  designed under classical CryptoNote ring-signature
  semantics. Wallet-side output selection — which outputs
  to spend, in what order, against which change addresses —
  is a **first-class privacy decision** that survives FCMP++:
  full-chain membership replaces decoy-ring sampling, but
  output-set entropy (selection determinism, change-address
  reuse, selection-order-leak) is independent of ring
  semantics and remains a wallet-side privacy property.

  **Threat model.** Deterministic selection enables
  correlation between reservations against the same available
  set ("two reservations selecting the same outputs in the
  same order against the same available outputs reveal the
  same wallet"); subaddress-reuse-for-change creates linkable
  outputs ("reservations sharing a change address are likely
  the same wallet"); selection order leaks information about
  the wallet's internal output-list ordering ("ordering
  reveals scan-order, balance-rebalancing, or recent-output
  preference"). Per
  [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §2
  (privacy is the product), output-selection-algorithm
  weaknesses are not "performance optimizations deferred to
  V3.x" — they are wallet-layer privacy decisions whose
  trait-surface seam should be designed in at V3.0 even if
  the V3.0 default carries forward the wallet2 algorithm.

  **Options.**
  - (a) **Carry forward wallet2's algorithm** (greedy
    largest-fits-amount + subaddress preference). Inherits
    the deterministic-correlation / change-reuse / order-leak
    weaknesses; cheap; no V3.0 architectural cost beyond the
    seam.
  - (b) **Randomized selection with bounded variance**
    (Knuth-shuffle within size-constrained candidates).
    Defeats deterministic correlation; the bounded variance
    keeps fee predictability; modest implementation
    complexity.
  - (c) **Entropy-maximizing selection** (optimize for
    output-set ambiguity under FCMP++ semantics — output
    age, transaction-graph distance, ring-membership
    plausibility). V3.x research territory but
    architecturally fittable.

  **Disposition.** **V3.0 ships (a) — wallet2-greedy carryover —
  under an `OutputSelector` trait-parameter seam.** (b) and
  (c) land in V3.x consumer-actor PRs as alternative
  `OutputSelector` impls. The architectural-cost asymmetry
  per §5.0.4 lens-applicability discipline: designing the
  seam at V3.0 is near-zero cost; designing it post-V3.x
  requires migrating every `LocalPendingTx` /
  `PendingTxActor` construction site (the seam is on
  the engine type's parameterization, not on the trait
  surface itself). The seam is the architectural-integrity-
  now item; the algorithm choice is the V3.0-vs-V3.x decision.

  **Phase 0 implication.** `LocalPendingTx<S: Signer, O:
  OutputSelector>` (Stage 1) and `PendingTxActor`'s
  spawn-time-bound `output_selector: Arc<dyn OutputSelector>`
  (Stage 4) carry the seam. The `OutputSelector` trait
  surface mirrors the `Signer` trait shape per R11 (b) — a
  narrow trait method (`fn select_outputs(&self, candidates:
  &[OutputCandidate], target: Amount) -> SelectedOutputs`)
  with Stage 1 / Stage 4 implementations that share the
  trait. Phase 0 review (segment 2g) confirms the trait
  shape and the type-parameter / actor-field placement.

  **V3.x trigger.** Privacy-research outcomes (alternative
  selection algorithms validated under FCMP++ adversarial
  models); UX requirements (e.g., "privacy mode" toggles
  surfacing in the GUI); operational telemetry surfacing
  selection-correlation observable on-chain. None of these
  are V3.0 blockers; the seam preserves V3.0 shipping date
  while V3.x research advances.

  **FOLLOWUPS entry.** "Output selection algorithm
  alternatives under `OutputSelector` trait seam" target
  V3.x; cross-references this entry.
- **R15 — Submission strategy as a composable actor (named
  with disposition in Round 2 segment 2c; V3.0 ships
  `DirectStrategy` under `SubmissionStrategyActor` seam;
  V3.x lands privacy strategies).** Direct-to-daemon
  submission inherited from wallet2 leaves transaction-
  network-entry-point timing and routing as wallet-layer
  privacy weaknesses against traffic analysis. The wallet
  decides **when** to submit (immediately? randomized
  delay? Tor-circuit-aligned?), **through which transport**
  (current daemon connection? rotate circuit first?
  broadcast through multiple peers?), **in what order**
  (FIFO? randomized to defeat traffic analysis? batched
  with other wallets?) — wallet2 makes none of these
  choices; it submits when called, through the current
  connection, in call order.

  **Threat model.** Per
  [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) and
  the §5.3 threat-model anchor (adversary-controlled daemon
  is design-center), submission-time observability is a
  primary attribution surface: a network adversary observing
  transaction-entry-point timing can correlate wallet
  identity (via the daemon connection) with transaction
  identity (via the submitted tx). Wallet2's direct-to-
  daemon submission collapses the two correlations into a
  single observable event; privacy-enhancing strategies
  separate them.

  **Options.**
  - (a) **Direct-to-daemon submission** (wallet2 carryover).
    Submits when called, through the current connection,
    in call order. Cheapest; matches wallet2 behavior; the
    privacy weakness is the design-center.
  - (b) **Submission strategies as composable actors.**
    `PendingTxActor`'s submit message handler does not
    forward to `DaemonEngine` directly; it forwards to a
    `SubmissionStrategyActor` between them. The strategy
    actor applies whatever timing / routing / ordering
    discipline is configured.

  **Disposition.** **V3.0 ships (b)'s seam — the intermediate
  `SubmissionStrategyActor` slot in the submit path — with
  `DirectStrategy` as the default V3.0 strategy** (matches
  wallet2 behavior; no privacy regression at V3.0 ship time).
  V3.x consumer-actor PRs land privacy-enhancing strategies:
  - `JitteredSubmissionStrategy` — randomized delay within a
    configurable window; defeats single-event timing
    correlation.
  - `CircuitRotationStrategy` — request new Tor circuit
    before submission; separates submission-event identity
    from prior-connection identity.
  - `BroadcastStrategy` — submit through multiple peers
    simultaneously; defeats single-peer-eavesdrop attribution.
  - `BatchedStrategy` — coordinate submission timing with
    other Shekyl wallets through a coordination layer;
    defeats per-wallet timing correlation by reducing the
    population of submitters at any single timing window.

  **Phase 0 implication.** Submit path's actor topology
  pins the `SubmissionStrategyActor` slot:

  ```text
  PendingTxActor — submit msg → SubmissionStrategyActor
       │                           │
       │                           │ (apply strategy)
       │                           ▼
       │                       DaemonEngine actor
       │                           │
       │                           │ (broadcast)
       │                           ▼
       │                       (network)
  ```

  The trait surface does not grow; the composition surface
  does. `SubmissionStrategyActor` is itself an actor that
  consumes `PendingTxDiagnostic::SubmitAttempted` events and
  forwards `Submit` messages to `DaemonEngine`. Each V3.x
  strategy is a separate actor consuming the same diagnostic
  stream; configuration switches which strategy is bound at
  wallet startup. Same compositional pattern as PR 4's V3.x
  consumer actors (`PeerReputationActor`, `RecoveryActor`,
  etc.).

  **V3.x trigger.** Anonymity-network deployment maturity
  (e.g., Shekyl-native Tor / Lokinet / I2P integration
  validated against the threat model); coordination-layer
  research (BatchedStrategy requires multi-wallet
  coordination infrastructure that does not yet exist);
  user-configuration UX for strategy selection.

  **FOLLOWUPS entry.** "Submission-strategy actors under
  `SubmissionStrategyActor` seam (`JitteredSubmissionStrategy`,
  `CircuitRotationStrategy`, `BroadcastStrategy`,
  `BatchedStrategy`)" target V3.x; cross-references this
  entry.
- **R16 — Wallet-side fee estimation (named with disposition
  in Round 2 segment 2c; V3.0 ships daemon-recommendation-
  with-explicit-override under `FeeEstimator` trait seam;
  V3.x lands wallet-side estimator).** Wallet2 asks the
  daemon for fee estimates and uses them. This is a
  **fingerprint**: every wallet that takes the daemon's
  recommendation produces transactions with daemon-influenced
  fee values; a malicious daemon can identify "wallets
  following my recommendations" vs "wallets making
  independent decisions" by observing on-chain fee patterns.

  **Threat model.** Per the §5.3 threat-model anchor
  (adversary-controlled daemon is design-center), fee
  estimation is a wallet-side decision the daemon should
  not influence. A wallet-side fee estimator analyzing
  historical block fee distribution from `LedgerEngine`
  state directly decouples wallet fee from daemon
  recommendation; every wallet computes fees from the same
  chain-state inputs and produces statistically-
  indistinguishable outputs. Per
  [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §2
  (privacy is the product), fee-fingerprinting is a privacy
  weakness whose seam should be designed in at V3.0.

  **Options.**
  - (a) **Daemon-recommendation carryover** (wallet2). Cheap;
    inherits the fingerprint.
  - (b) **Daemon-recommendation with explicit override.**
    `build`'s fee parameter accepts either "daemon-recommended"
    (passed through) or an explicit fee value; the wallet
    UI / API can drive the override from any source. V3.0-
    feasible.
  - (c) **Wallet-side estimator analyzing historical block
    fee distribution from `LedgerEngine` state.** Decouples
    fee from daemon recommendation entirely; requires a
    `LedgerEngine` accessor for historical block fee
    distribution (small additive surface) plus the estimator
    itself. V3.x architectural cost is bounded but non-zero.

  **Disposition.** **V3.0 ships (b) — daemon-recommendation
  with explicit override — under a `FeeEstimator` trait-
  parameter seam.** The `FeeEstimator` trait abstracts over
  "where the fee comes from"; V3.0 default is
  `DaemonRecommendationEstimator` (asks the daemon, returns
  the value); the wallet UI / API can substitute an
  `ExplicitFeeEstimator` at construction time for explicit-
  fee workflows. (c) — `WalletSideEstimator` analyzing
  historical block fee distribution — lands in V3.x as an
  alternative `FeeEstimator` impl.

  **Why not (c) at V3.0?** The architectural cost is bounded
  but non-trivial: `LedgerEngine` needs a historical-block-
  fee-distribution accessor (small additive surface, plus
  storage cost for block-fee history if the snapshot doesn't
  already carry it); the estimator itself requires
  fee-distribution analysis logic (statistical methods,
  fee-band selection, time-window selection). Phase 0 review
  (segment 2d) bounds the cost.

  **Conditional V3.0 lift evaluation (segment 2d).**
  `LedgerBlock` (per
  [`rust/shekyl-engine-state/src/ledger_block.rs`](../../rust/shekyl-engine-state/src/ledger_block.rs))
  carries `block_version`, `transfers: Vec<TransferDetails>`,
  `tip: BlockchainTip`, `reorg_blocks: ReorgBlocks` —
  **no per-block fee data**. Adding a historical-block-fee
  accessor to `LedgerEngine` requires either (i) extending
  `LedgerBlock`'s persisted shape to carry fee-distribution
  summary per block (storage-layout amendment; persistence-
  layer migration; Phase 0 / Phase 1 spec amendment) or (ii)
  walking historical confirmed transactions per estimator
  call (CPU cost on every fee estimation; potentially
  unbounded depending on fee-window depth). Neither is
  bounded cost in the segment-2c sense. **R16 (c) does not
  lift to V3.0; the conservative segment-2c default holds.**
  V3.x lifts (c) when the storage-layout amendment is
  scoped under its own design pass and lands as a
  coordinated `LedgerEngine` + `FeeEstimator` PR. The
  FOLLOWUPS entry remains the V3.x trigger surface.

  **Phase 0 implication.** `LocalPendingTx<S: Signer, O:
  OutputSelector, F: FeeEstimator>` (Stage 1) gains the
  `FeeEstimator` parameter; `PendingTxActor`'s spawn-time-
  bound `fee_estimator: Arc<dyn FeeEstimator>` (Stage 4)
  carries the seam. The trait surface (`fn estimate_fee(&self,
  tx_size: usize, priority: FeePriority) -> Amount`) is
  narrow; V3.0 default impl is `DaemonRecommendationEstimator`;
  V3.x adds `WalletSideEstimator`. Phase 0 review (segment 2g)
  confirms the trait shape; segment 2d's R2 / R12 disposition
  may surface `LedgerEngine`-accessor amendments that R16
  (c) at V3.0 would benefit from.

  **V3.x trigger.** `LedgerEngine` historical-block-fee-
  distribution accessor cost confirmed bounded (Phase 0
  review or V3.x amendment); fee-estimation algorithm
  validated against on-chain fingerprint analysis;
  fee-band-selection UX validated. None of these are V3.0
  blockers; the seam preserves V3.0 shipping date while
  V3.x research advances.

  **FOLLOWUPS entry.** "Wallet-side fee estimator
  (`WalletSideEstimator`) under `FeeEstimator` trait seam"
  target V3.x; cross-references this entry. **Conditional
  V3.0 lift** noted: if Phase 0 review confirms bounded
  cost, R16 (c) lifts to V3.0.
- **R17 — Event-sourced recovery as user-controlled tradeoff
  (named with disposition in Round 2 segment 2c; V3.0
  default drop-on-close; V3.x optional encrypted persistence
  consumer; refines the diagnostic-stream restart-amnesia
  contract).** PR 4 §5.4.8 #1's restart-amnesia rule
  (in-memory only, drop on close) is a privacy default:
  applied to PR 5, `PendingTxDiagnostic` events do not
  persist; wallet crash mid-transaction loses reservation
  state entirely. For most use cases (steady-state wallet
  operation), this is correct. For a class of users
  (long-running mining wallets; institutional custody;
  multi-day transaction-construction workflows; foundation
  treasury operations) crash-recovery is a real concern;
  "lose all pending transactions on crash" is operationally
  unacceptable.

  **Threat model.** The restart-amnesia rule's privacy
  property is **diagnostic events do not leak across trust
  boundaries via persistence**; the rule was originally
  written against the threat that any persistence creates
  a leak surface (logs that get pasted, telemetry exports,
  debug UIs with off-host surfaces). The threat-model
  refinement: **persistence is a leak only when the
  persistence surface is outside the wallet's encrypted-state
  surface**. Persistence to a consumer entirely within the
  wallet's own encrypted-state surface (the wallet's own
  storage, encrypted under the wallet master key) is
  **not** a cross-trust-boundary leak per PR 4 §5.4.8 #4's
  recursive-trust-boundary discipline.

  **Options.**
  - (a) **Restart-amnesia default (PR 4 §5.4.8 #1
    carryover).** In-memory only, drop on close. Privacy-
    first; crash-recoverability lost.
  - (b) **Optional encrypted persistence opt-in.** Default
    off; user (or wallet UI) can enable encrypted persistence
    of `PendingTxDiagnostic` events for crash recovery via
    stream replay. The encryption key is the wallet master
    key; the persistence layer is the wallet's own storage;
    nothing leaks across trust boundaries.
  - (c) **Persistence-by-default with explicit opt-out.**
    Crash-recoverability-first; privacy-default reversed.
    Rejected: contradicts the privacy-as-product commitment
    per `00-mission.mdc` §2 — privacy is never a setting,
    let alone a default-off setting.

  **Disposition.** **V3.0 ships (a) — restart-amnesia default
  — preserving the privacy-first posture inherited from
  PR 4 §5.4.8 #1.** (b) — optional encrypted persistence
  consumer — lands in V3.x as an opt-in user-controlled
  tradeoff for the institutional / long-running use cases.
  (c) is rejected.

  **Diagnostic-stream contract refinement (segment 2c).**
  PR 4 §5.4.8 #1's contract pin updates from "in-memory only,
  drop on close" to:

  > **In-memory only by default; drop on close.** User-
  > controlled encrypted-persistence opt-in is permitted if
  > the persistence consumer's surface is entirely within
  > the wallet's own encrypted-state surface (no
  > cross-trust-boundary leak per §5.4.8 #4). The default
  > is privacy-first; the opt-in is the user's tradeoff.

  Cross-references PR 4 §5.4.8 #1 to mirror the contract
  refinement; the contract pin is updated to permit
  wallet-internal encrypted-persistence consumers without
  weakening the recursive-trust-boundary discipline. PR 4
  §5.4.8 #4 (recursive-trust-boundary discipline) is
  unchanged; this refinement narrows the persistence
  prohibition to cross-boundary persistence specifically,
  which §5.4.8 #4 already governs.

  **Phase 0 implication.** No V3.0 trait-surface change;
  the `PendingTxDiagnostic` stream's contract is
  refined-not-restructured. V3.x adds a
  `PersistenceConsumerActor` whose surface is the wallet's
  own encrypted storage; the `DiagnosticSink` registration
  surface already accepts arbitrary in-process consumers
  (per PR 4 §5.4.6 / §5.4.7 R6 reframe), so no architectural
  change is required at the V3.x trigger.

  **V3.x trigger.** Institutional / long-running deployment
  requirements (foundation treasury, multi-day tx workflows);
  wallet-storage encryption layer matures (wallet master
  key derivation surface, key-rotation discipline);
  user-configuration UX for persistence opt-in. None of
  these are V3.0 blockers; the contract refinement at V3.0
  preserves the V3.x option without committing to it.

  **FOLLOWUPS entry.** "Encrypted-persistence
  `PersistenceConsumerActor` for institutional / long-
  running wallet deployments" target V3.x; cross-references
  this entry and PR 4 §5.4.8 #1 contract refinement.

### §5.5 Round 1 disposition — shape (1), actor-mesh framing

**Disposition (2026-05-13).** Round 1 closes at **shape (1) —
build-against-current-snapshot + snapshot-ID pinning** — under
the §5.0 actor-mesh framing. The wargaming surface is
exhausted in this round per the §7 closure rule: shapes (2)
and (3) fail criterion 5 (§5.3) on **structural** grounds
rather than contingent grounds, and no fourth shape survives
the framing. The rounds budget for PR 5 compresses against
the seed's three-to-four-rounds projection: Round 2 disposes
the surviving residuals (R2 / R8 / R9 / R11 / R12) and enumerates
Phase 0 amendments; Round 3 does commit decomposition. Two
rounds saved against the original projection.

**Rationale (the three structural grounds, restated).** Under
the actor-mesh framing, shape (1) wins on:

1. **Phase 0c collapses at the trait surface (R12 closed (a)
   in segment 2d).** No cross-trait synchronous-query amendment
   to `LedgerEngine` is required by the trait contract; actor
   consumers receive snapshot identity through
   `LedgerDiagnostic::SnapshotMerged` events (additive surface,
   not load-bearing surface; Phase 0g) and Stage 1's
   `LocalPendingTx` derives `SnapshotId` from
   `LedgerEngine::snapshot()` (existing trait method; per §5.4
   R12 (a)'s segment-2d closure). The working hypothesis
   confirmed: `LedgerSnapshot` carries `synced_height +
   reorg_blocks` — sufficient deterministic state for content-
   addressed `SnapshotId` derivation per §5.4 R2's segment-2d
   closure (opaque 16-byte digest). **Phase 0c truly collapses;
   no qualifier remains.** Ground 1 is now closure-confirmed
   alongside grounds 2 and 3.
2. **The CAS isn't a CAS.** Submit-time staleness is a field
   comparison in the actor's message handler; the actor is the
   serialization point; mailbox FIFO orders concurrent calls.
   R3 / R10 dissolve; R5's trait-surface aspect dissolves.
3. **Adversarial-daemon resistance is structural.** The DoS
   surface in (2) and (3) is the **contract dependency on
   refresh quiescence at any point in the build/submit flow**,
   not the cross-actor query mechanism specifically. The
   standard implementation queries `RefreshActor` for liveness;
   the stream-subscription steelman observes
   `RefreshDiagnostic::AttemptCompleted` for the same signal;
   both deliver daemon-controllable stalls because the
   load-bearing property is the contract dependency, not the
   observation channel (the daemon controls the underlying
   signal, not the channel that observes it; see §5.3
   criterion 5 for the full steelman defense). Shape (1) under
   the actor mesh has no such dependency in either build or
   submit; `PendingTxActor` operates against the
   most-recently-merged snapshot regardless of refresh
   liveness. The decoupling is contract-level, not
   implementation-level.

**Five-criteria scorecard.**

| Criterion (§5.3)                              | (1) | (2) | (3) |
|-----------------------------------------------|-----|-----|-----|
| 1. PR 5 extraction cleanliness                | ✓   | ✓   | ✓   |
| 2. PR 4 α confirms                            | ✓   | ✓   | ✓   |
| 3. Reservation-tracker monotone semantics     | ✓   | ✓   | ✓   |
| 4. Stage 4 actor-migration compatibility      | ✓   | ✗   | ✗   |
| 5. Adversarial-daemon resistance (structural) | ✓   | ✗   | ✗   |

(2) and (3) fail criteria 4 and 5 on a **shared underlying
mechanism** — the contract dependency on refresh quiescence in
their build/submit flow — but score **distinct consequences**,
not double-counting:

- **Criterion 4 (implementation-feasibility / actor-migration
  compatibility)** is failed because the dependency creates a
  structural cross-actor coupling the actor mesh cannot
  serialize without re-introducing the DoS surface — regardless
  of which observation mechanism (synchronous query, stream
  subscription, mailbox await) realizes the contract. The
  property scored is "the implementation creates the
  vulnerability."
- **Criterion 5 (threat-model-survival / adversarial-daemon
  resistance)** is failed because the resulting DoS surface is
  exercised by Shekyl's primary deployment threat model — the
  adversary-controlled daemon per the §5.3 threat-model anchor.
  The property scored is "the threat model exercises the
  vulnerability."

The shared mechanism is one structural property; the criteria
evaluate distinct axes of consequence (implementation-creating-
vulnerability vs. threat-model-exercising-vulnerability). Both
✗s are correctly scored against (2) and (3); failing one
without the other would be possible only if the implementation
created a vulnerability the threat model didn't exercise, or the
threat model exercised a vulnerability the implementation didn't
create — neither holds here.

**What lands as Round 1 substrate (this commit).**

- §5.0 (actor-mesh framing as substrate; cross-cutting
  `DiagnosticSink` contracts inherited from PR 4 §5.4.6 /
  §5.4.7 R6 reframe / §5.4.8).
- §5.1 (three-shape comparison re-evaluated under §5.0; (1) wins
  decisively on structural grounds; (2)/(3) rejected on
  criterion 5).
- §5.2 (PR 4 implications: α confirmed; PR 4 Round 3 is a
  confirmation-shape round; "provisionally load-bearing"
  qualifier withdrawn).
- §5.3 (five criteria; criterion 5 is load-bearing-by-construction
  under §5.0).
- §5.4 (residuals: R3 / R5-trait-surface-aspect / R10 dissolved;
  R2 / R4 / R5-policy-aspect / R6 / R7 retained; R8 / R9
  reframed; R11 added; R12 added — Stage 1 `current_snapshot`
  acquisition mechanism, with three options enumerated; ground-1
  prose qualified by R12 pending Round 2 confirmation).
- §5.5 (this section; Round 1 disposition + scorecard).
- §4 Phase 0 candidates updated (§4 below): 0c removed at the
  trait surface (R12 closed (a) in segment 2d; Phase 0c truly
  collapses); 0f (`PendingTxDiagnostic` + `DiagnosticSink`
  parameter) and 0g (`LedgerDiagnostic::SnapshotMerged`
  variant) added.

**What Round 2 carries.** R2 (`SnapshotId` opacity / projection
types — closed in segment 2d as opaque 16-byte content-
addressed digest with projection-type discipline preserved-as-
pattern) and R12 (Stage 1 `current_snapshot` acquisition
mechanism — closed in segment 2d as (a) content-derived
`SnapshotId` from existing `LedgerSnapshot` data; Phase 0c
truly collapses); R8 (`ReservationTTLActor` composition closure
— closed in segment 2e; V3.0 ships diagnostic-stream seam
complete with `DiscardReason::TTLAutoDiscard` variant pin
added; V3.x lands `ReservationTTLActor` as consumer actor;
existing FOLLOWUPS entry amended with segment-2e closure-
status confirmation); R9 (two-stage submit flow +
intermediate state);
criterion-5 prose strengthening (contract-dependency-on-
refresh-quiescence framing — landed in segment 2a); R11
(signing-actor split — closed in segment 2b as (b); HW-wallet
integration in V3.x plugs into existing architecture); R14
(`Reservation` extensibility seam — closed in segment 2b);
R13 / R15 / R16 / R17 (output-selection / submission-strategy
/ fee-estimation / event-sourced-recovery — named with
V3.0-vs-V3.x dispositions in segment 2c; V3.0 ships seams +
privacy-default carryovers under `OutputSelector` /
`SubmissionStrategyActor` / `FeeEstimator` / refined
diagnostic-stream contract; V3.x lands alternative impls /
privacy strategies / wallet-side estimator / encrypted-
persistence consumer); R16 conditional V3.0 lift evaluated in
segment 2d — `LedgerBlock` does not carry per-block fee data
today; the V3.0 lift would require a storage-layout amendment,
**so R16 conservative V3.x default holds**; §5.0.4
lens-applicability discipline + §7 closure-rule strengthening
(landed in segment 2c); sink-binding decoupling (now
independent of R11 per segment-2b (b) closure; segment 2f);
plus Phase 0 enumeration and the cross-cutting
`DiagnosticSink` contract-doc generalization (§5.0.3).

**What Round 3 carries.** Commit decomposition + Phase 1
commit list (per the PR 1 / PR 2 / PR 3 / PR 4 precedent).

---

## §6 Review checklist (Round 2 task)

Filled in during Round 2 once Phase 0 enumeration completes.
The shape mirrors PR 4's §6: binding-check matrix against the
spec, test-substrate preservation list, call-site sweep audit,
PR 4 Round 3 input bundle (now resolved as confirmation per
§5.2; the bundle is this document plus PR 4's corresponding
follow-up commit recording the "α confirmed" disposition).

---

## §7 Discipline budget

Round 1 closes here (this commit) per the §5.5 disposition
under the §5.0 actor-mesh framing. Subsequent revisions land
round-by-round inline (the PR 3 / PR 4 precedent).

**Revised estimate post-Round-1 close.** Round 2 disposes
residuals (R2 / R8 / R9 / R11 / R12) and finalizes Phase 0
enumeration; Round 3 does commit decomposition + Phase 1
commit list. **Two rounds saved against the seed's
three-to-four projection** because the §5.0 reframe exhausts
the wargaming surface in one round.

The discipline-budget posture follows PR 4's: design rounds
happen in writing (this document) on the design feature branch;
the rounds budget is consumed by the user's review of the
written analysis between commits, not by live design sessions.
**This commit lands Round 1's disposition + the §5.0 reframe
as one cohesive unit** — they are inseparable substrate for
each other. Subsequent residual dispositions (R2 / R8 / R9 /
R11 / R12) land round-by-round in Round 2.

**Closure rule (strengthened in segment 2c).** Round-N closes
when the wargaming surface **known at closure time** is
genuinely exhausted, not on a schedule. The
"enumerate-now-dispose-Round-N+1" default exists for surfaces
broad enough that Round-N's review may not cover every
alternative; the default is not a mandate. If Round N's
wargaming closes with no surviving alternative under
adversarial review (the wargaming surface is genuinely
exhausted), landing the disposition in Round N is honest, not
premature. Delaying in that case is the
cost-benefit-defer-to-later anti-pattern per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc).

**New shapes surfacing in Round-N+1 reopen Round N.** A new
candidate shape that surfaces during Round-N+1's adversarial
review (or later) is not a closure-rule violation; it is a
signal that Round N's wargaming surface was incomplete.
Reopening Round N is the discipline-correct response —
re-evaluate the disposition against the expanded surface,
re-close if the new shape fails the criteria, otherwise
revisit. The closure rule pins **what was known at closure
time**, not **what could ever be known**; new shapes are
allowed to reopen but must reopen explicitly rather than
slipping past closure as quiet revisions.

**Lens-applicability cross-reference.** The closure rule's
"genuinely exhausted" criterion is satisfied differently
depending on whether the lens applies. For engines that
admit the actor-mesh lens (per §5.0.4 conditions 1 / 2 / 3),
Round 1 exhaustion is the lens's wargaming surface; for
engines that do not, Round 1 exhaustion is the synchronous
framing's wargaming surface. The closure rule governs both
cases; lens applicability shapes what "exhaustion" means in
each.

**Round 1 closure rule (applied to PR 5).** PR 5's R1 has
cascading effect on PR 4 Round 3 and the wargaming surface
is broader than PR 4 Round 1's (which converged at α because
architectural-inheritance discipline made α structurally
obvious). The §5.0 actor-mesh framing exhausts the
wargaming surface in this round on **three structural
grounds** (§5.1): the cross-trait synchronous query collapses
(Phase 0c → 0g); submit-time staleness is a field comparison,
not a CAS; adversarial-daemon resistance is structural by
construction. Shapes (2) and (3) fail criterion 5 (§5.3) by
construction under the framing.

**Round 1 fourth-shape closure-review test (segment 2c).**
During Round 1's closure review, one hybrid shape was
tested as a candidate fourth — (1)-build paired with
(3)-submit — and rejected on criterion 5 (§5.0.4 records
the worked test). The hybrid's contract dependency on
refresh quiescence moves from build-and-submit to
submit-only without dissolving; the rejection demonstrates
the wargaming surface was exhausted at closure time. No
fourth shape escape route exists under the framing that
doesn't reintroduce the contract dependency on refresh
quiescence at some point in the build/submit flow.

Per the closure rule (strengthened above), Round 1 closes
here. Delaying the disposition to Round 2 in spite of the
closed wargaming surface would be the cost-benefit-defer-to-
later anti-pattern; the closure rule forecloses that default.

---

## §8 Fenceposts — what subsequent rounds fill in

Round 1 closes the load-bearing question (§5.5). Remaining
work, by round:

**Round 2 — completed.**

- **Segment 2a — audit-readiness commit (items 3 / 4 / 5 from
  the post-R1-closure adversarial-review outcomes summary).**
  - **Item 4 (audit-blocking): §5.3 criterion 5 strengthening.**
    Reframed from "cross-actor liveness query" to **"contract
    dependency on refresh quiescence at any point in the
    build/submit flow"**; documents the stream-subscription
    steelman implementation of (2)/(3) and explains why it
    still fails (the daemon controls the underlying signal, not
    the channel that observes it; the load-bearing property is
    the contract dependency, not the observation mechanism).
    Lands ahead of the R-residual dispositions per the
    audit-blocking sequencing decision so audit-prep does not
    sequence behind R2 / R8 / R9 / R11 / R12.
  - **Item 5: §5.3 threat-model anchor explicit defense.**
    Adversary-controlled-daemon-as-design-center made explicit
    (not citation-only); references
    [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) plus
    the structural property "daemon outside the wallet's trust
    boundary by design choice"; rejection of single-peer-DoS
    contracts framed as "structurally incompatible with the
    project's primary deployment model" (not "tolerated in some
    deployments and hardened in others").
  - **Item 3: §5.5 scorecard rationale clarification.**
    One-line note expanded into structured prose explaining
    criteria 4 and 5 share underlying mechanism (contract
    dependency on refresh quiescence) but score distinct
    consequences (criterion 4 = implementation-creating-
    vulnerability; criterion 5 = threat-model-exercising-
    vulnerability). Closes the double-counting attack.
  - **Propagation: §5.1 (2)/(3) prose + §5.5 ground 3.**
    Updated to use the contract-dependency reframe consistently
    with §5.3's strengthened framing — the standard
    implementation and stream-subscription steelman share the
    same fatal property, and the prose says so explicitly.

- **Segment 2b — R11 signing-actor split reframe + R14
  reservation extensibility seam.**
  - **R11 reframe to (b) (architectural-integrity-now).** §5.4
    R11 prose replaced; closure on (b) as the Stage 1
    disposition (separate `LocalSigner` / `SigningActor`;
    `LocalPendingTx` / `PendingTxActor` never holds spend
    material). Cost-asymmetry argument decomposed (PR 4 R4's
    moves-not-rewrites cost asymmetry does not apply to PR 5
    R11 because `LocalPendingTx` is being designed fresh, not
    moved); R4-consistency reversal documented; HW-wallet-as-
    core-not-edge ground per `00-mission.mdc` §1; audit-surface
    narrowing; Stage 4 actor-migration cost asymmetry. §5.0.1
    sketches updated to add `signer: Arc<S>` (Stage 1) and
    `signer: ActorRef<SigningActor>` (Stage 4) fields plus
    explanatory prose.
  - **R14 reservation extensibility seam.** §5.4 R14 entry
    added; `Reservation` shape gains `extensions:
    Vec<ReservationExtension>` field; `ReservationExtension`
    enum is `#[non_exhaustive]` with empty V3.0 variant set;
    same pattern as `RefreshDiagnostic` / `PendingTxDiagnostic`
    extensibility seams. Forecloses V3.x trait revision when
    coinjoin / atomic-swap / time-locked / multi-stage /
    composable reservation variants land in V3.x consumer-
    actor PRs.
  - **FOLLOWUPS update.** V3.x `PendingTxEngine` (b)
    signing-actor-split deferral entry replaced with HW-wallet
    integration entry (`Signer`-impl substitution against the
    existing architecture; no architectural change required at
    the trigger).
  - **Discipline note (forward-template).** R11's reframe is
    the architectural-integrity-now discipline applied at the
    residual-disposition level — R-residual dispositions
    inherit the same architectural-integrity-now discipline
    that PR 3 / PR 4 established at the load-bearing question.
    Future per-engine PRs read PR 5's R11 reframe as substrate
    when R-residual dispositions surface the same anti-pattern.

- **Segment 2c — closure-rule and lens-applicability
  refinements paired with R13 / R15 / R16 / R17 named with
  dispositions.**
  - **§5.0.4 lens-applicability discipline.** Section
    expanded with structured "Lens-applicability discipline"
    subsection establishing three structural conditions
    that govern when the actor-mesh lens applies to a
    per-engine extraction (trait surface mediates state-
    mutation across actors; adversarial review surfaces a
    cross-actor liveness or quiescence dependency; Stage 4
    actor-migration target is non-trivial). Per-engine PR
    pre-flights test applicability rather than presume it.
    The lens compounds across PRs **whose structure admits
    it**, not uniformly. Closure-rule cross-reference and
    fourth-shape adversarial-test record (Round 1
    closure-review log: (1)-build paired with (3)-submit
    hybrid tested and rejected on criterion 5).
  - **§7 closure-rule strengthening.** Restructured into
    "Closure rule (strengthened)" + "Round 1 closure rule
    (applied to PR 5)". General rule pinned: Round-N closes
    when the wargaming surface **known at closure time** is
    genuinely exhausted; new shapes surfacing in Round-N+1
    reopen Round N rather than slipping past closure
    (the closure rule pins what was known, not what could
    ever be known). Lens-applicability cross-reference
    (closure rule's "exhausted" criterion is satisfied
    differently depending on whether the lens applies).
    Round 1 fourth-shape closure-review test recorded as
    instance of the strengthened rule.
  - **R13 — output selection algorithm.** §5.4 R13 entry
    added; threat model framed (deterministic correlation,
    change-reuse, order-leak independent of FCMP++ ring
    semantics); options enumerated; disposition closed as
    V3.0 ships wallet2-greedy under `OutputSelector`
    trait-parameter seam (`LocalPendingTx<S: Signer, O:
    OutputSelector>`); V3.x lands randomized / entropy-
    maximizing alternatives as alternative `OutputSelector`
    impls. Phase 0 implication: trait parameter on engine
    type; trait shape narrow (`fn select_outputs(...)
    -> SelectedOutputs`).
  - **R15 — submission strategy as a composable actor.**
    §5.4 R15 entry added; threat model framed
    (transaction-network-entry-point timing / routing as
    wallet-layer privacy weakness against
    `ANONYMITY_NETWORKS.md` adversary); options enumerated;
    disposition closed as V3.0 ships
    `SubmissionStrategyActor` seam with `DirectStrategy`
    default (matches wallet2 behavior, no V3.0 privacy
    regression); V3.x lands `JitteredSubmissionStrategy` /
    `CircuitRotationStrategy` / `BroadcastStrategy` /
    `BatchedStrategy`. Phase 0 implication: submit-path
    actor topology pins the intermediate-actor slot.
  - **R16 — wallet-side fee estimation.** §5.4 R16 entry
    added; threat model framed (daemon-recommendation
    on-chain fingerprint exploitable by malicious daemon
    per §5.3 threat-model anchor); options enumerated;
    disposition closed as V3.0 ships
    daemon-recommendation-with-explicit-override under
    `FeeEstimator` trait seam; V3.x lands
    `WalletSideEstimator` analyzing `LedgerEngine`
    historical block fee distribution. **Conditional V3.0
    lift** noted: if Phase 0 review (segment 2d) confirms
    bounded `LedgerEngine`-accessor cost, R16 (c) may lift
    to V3.0; segment-2c default is conservative.
  - **R17 — event-sourced recovery as user-controlled
    tradeoff.** §5.4 R17 entry added; threat model framed
    (PR 4 §5.4.8 #1 restart-amnesia rule's privacy
    property = persistence does not leak across trust
    boundaries; refinement narrows prohibition to
    cross-boundary persistence specifically); options
    enumerated; disposition closed as V3.0 ships PR 4
    §5.4.8 #1 carryover (drop-on-close); V3.x optionally
    lands encrypted-persistence consumer for institutional
    / long-running / multi-day workflows. Diagnostic-
    stream contract pin refined: in-memory-by-default
    plus permitted user-controlled encrypted-persistence
    opt-in for consumers entirely within wallet's own
    encrypted-state surface (no cross-trust-boundary leak
    per PR 4 §5.4.8 #4).
  - **CHANGELOG forward-template note.** Closure-rule
    "wargaming-surface-known-at-closure-time" qualifier and
    lens-applicability structural-conditions discipline
    flagged as V3.1 rules-queue inputs (consolidated
    forward-template content for the eventual rules-queue
    consolidation PR).

- **Segment 2d — R2 + R12 co-disposition; Phase 0c truly
  collapses; `SnapshotId` opacity closed as 16-byte
  content-addressed digest.**
  - **R12 closed as (a) — content-derived `SnapshotId` from
    existing `LedgerSnapshot` data.** Substrate inspection of
    `rust/shekyl-engine-core/src/engine/refresh.rs` ll. 147–166
    (linked from §5.4 R12) confirmed `LedgerSnapshot` carries
    `synced_height: u64` and `reorg_blocks: ReorgBlocks`
    (deterministic by construction; sufficient for
    content-addressed derivation). Stage 1's `LocalPendingTx`
    derives `SnapshotId` from `LedgerEngine::snapshot()`
    (existing trait method); Stage 4's `PendingTxActor` receives
    identical `SnapshotId` values via
    `LedgerDiagnostic::SnapshotMerged` events using the same
    digest function. No `LedgerEngine` trait amendment.
  - **R2 closed as opaque 16-byte content-addressed digest.**
    `pub struct SnapshotId([u8; 16])`; computed as a
    domain-separated hash over `LedgerSnapshot`'s
    deterministic fields. Specific hash primitive pinned at
    Phase 0 review (segment 2g) per §3.1 PQC-discipline
    alignment. Truncation to 128 bits sufficient given
    bounded snapshot population. Determinism required by
    §5.0's submit-handler field-comparison contract;
    height-leak side-channel closed by construction.
  - **§5.5 ground-1 prose softening.** "(pending R12)"
    qualifier on ground 1 dropped; ground 1 is now
    closure-confirmed (Phase 0c truly collapses; R12 (a)
    is the chosen mechanism; no trait amendment needed).
  - **§4 Phase 0c prose softening.** "(pending R12)"
    qualifier dropped; Phase 0c is REMOVED at the trait
    surface — full stop.
  - **Projection-type discipline preserved-as-pattern.**
    No V3.0 PR 5 call-site introduces a cross-trust-
    boundary `SnapshotId` or `SnapshotMerged` consumer;
    the projection-type implementation lands in the V3.x
    consumer-actor PR that introduces the first
    cross-boundary consumer (the discipline itself is
    documented per PR 4 §5.4.8 #4's recursive-trust-
    boundary rule).
  - **R16 conditional V3.0 lift evaluation.** `LedgerBlock`
    carries no per-block fee data today; lifting R16 (c) to
    V3.0 would require either a storage-layout amendment
    (persistence-layer migration) or an unbounded
    historical-block walk per estimator call — neither is
    bounded cost. **R16 (c) does not lift to V3.0**; the
    conservative segment-2c default holds; R16 (c) lands
    in V3.x behind a coordinated `LedgerEngine` +
    `FeeEstimator` PR. The R16 §5.4 entry is amended with
    the segment-2d evaluation outcome.

- **Segment 2e — R8 `ReservationTTLActor` composition closure;
  `DiscardReason::TTLAutoDiscard` variant pin.**
  - **R8 closed as `ReservationTTLActor` consumer-actor
    composition** following PR 4's `PeerReputationActor` /
    `RecoveryActor` pattern. V3.0 ships the diagnostic-stream
    seam complete; V3.x lands the actor with no V3.x trait /
    enum revision required (architectural-integrity-now per
    [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)).
  - **V3.0 deliverables (segment 2e closure).**
    `PendingTxDiagnostic::BuildSucceeded` emitted at the
    `build`-success path (Phase 1 call-site review confirms);
    `PendingTxDiagnostic::Discarded { reason:
    SnapshotRotationAutoDiscard }` emitted at `submit`'s
    snapshot-mismatch path (R5's lazy-discard semantics);
    `PendingTxDiagnostic::ReservationOutstanding` variant
    exists in the `#[non_exhaustive]` enum (no V3.0 emitter;
    V3.x `ReservationTTLActor` is the first emitter).
  - **New variant pin (segment 2e addition).**
    `DiscardReason::TTLAutoDiscard` added to the
    `#[non_exhaustive]` `DiscardReason` set so V3.x's
    `ReservationTTLActor` can trigger `PendingTxActor` to
    emit `Discarded { reason: TTLAutoDiscard }` events without
    a V3.x enum revision. No V3.0 emitter; V3.x
    `ReservationTTLActor` is the first emitter. Pinned in
    §5.0.2 enum sketch.
  - **R5 ↔ R8 coherence verified.** R5's
    `SnapshotRotationAutoDiscard` is the reactive cleanup
    path (cleanup-on-use); R8's `TTLAutoDiscard` is the
    proactive complement (age-based policy on never-used
    reservations). Both share the `DiscardReason`/`Discarded`
    event infrastructure; downstream consumers see a unified
    `Discarded` event stream with discriminated reasons.
  - **Hard mitigation pins inherited verbatim from PR 4
    §5.4.8** (restart-amnesia per #1; recursive trust boundary
    per #4; bounded mailbox per #5) bind on the V3.x
    consumer-actor PR via §5.0.3 — no PR 5 amendments needed.
  - **FOLLOWUPS amendment.** Existing `ReservationTTLActor`
    consumer-actor entry amended with the segment-2e
    `DiscardReason::TTLAutoDiscard` variant pin and
    closure-status confirmation. No new entry; the existing
    entry's Round 1 reframe already names the consumer-actor
    shape and the inherited contracts.

**Round 2 — pending.**

- **Segment 2f — R9 disposition + sink-binding decouple from
  R11.**
  - §5.4 R9 (two-stage submit flow; intermediate-state shape;
    per-error-class disposition; mailbox-ordering vs
    daemon-side authority for terminal-rejection visibility —
    Finding 2 from the prior adversarial pass).
  - §5.0.2 sink-binding decouple from R11 — constructor-bound
    under PR 4 §3.4.5 / R4 (a) consistency, independent of
    R11's spend-material disposition (closed as (b) in segment
    2b); Finding 4 from the prior adversarial pass. Note that
    R11's segment-2b closure leaves the sink-binding question
    independent because (b)'s `LocalPendingTx<S: Signer>` /
    `PendingTxActor` is the sink-binding-host regardless of
    whether spend material is held by `LocalPendingTx` or by
    `LocalSigner`.
- **Segment 2g — Round 2 close-out.**
  - §4 Phase 0 final enumeration (binding type-signature
    detail for 0a / 0b / 0d / 0e / 0f / 0g; cross-trait
    amendment review; final disposition of 0c per R12). The
    `Reservation` shape pins the segment-2b R14 `extensions`
    field and `#[non_exhaustive]` `ReservationExtension` enum
    stub. The `Signer` trait surface pins the segment-2b R11
    (b) signing-isolation discipline. The `OutputSelector` /
    `SubmissionStrategyActor` / `FeeEstimator` seam slots
    (segment-2c R13 / R15 / R16) are pinned at the trait /
    actor-topology level.
  - Cross-cutting `DiagnosticSink` contract-doc generalization
    (§5.0.3): rename `REFRESH_DIAGNOSTIC_STREAM.md` →
    `DIAGNOSTIC_STREAM.md` general, or factor parent
    `DIAGNOSTIC_STREAM_CONTRACTS.md` that PR 4 / PR 5 inherit
    from. Doc-only.
  - §6 review checklist (filled in once Phase 0 enumeration
    closes).

**Round 3.**

- §7 commit decomposition + Phase 1 commit list (per the PR 1
  / PR 2 / PR 3 / PR 4 precedent).

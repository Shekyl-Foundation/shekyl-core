# Stage 1 PR 5 — `PendingTxEngine` extraction — design

**Status.** **Round 1 closed (2026-05-13) — actor-mesh reframe +
shape (1) disposition.** This document was opened as a seed
immediately after Stage 1 PR 4's design substrate landed on
`dev` (merge commit `6de8335d5`, PR #42). Round 1 closes here
in one round — not deferred to Round 2 — because the
actor-mesh lens that PR 4 established in its Round 2 reframe
exhausts the wargaming surface of PR 5's load-bearing first
question. Shapes (2) and (3) fail criterion 5
(adversarial-daemon resistance) on **structural** grounds under
the actor framing, not contingent grounds; no fourth shape
survives the framing. See §5.0 (the reframe) and §5.5 (the
disposition).

Subsequent revisions land each design round inline (the
precedent set by PR 3's
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) and
PR 4's
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md),
each of which grew round-by-round to its current shape). Round 2
disposes residuals R2 / R8 / R9 / R11 plus Phase 0 enumeration;
Round 3 does commit decomposition. R3 / R5 / R10 dissolved by
composition under §5.0 (see §5.4 for per-residual rationale).

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
- **Phase 0c — REMOVED under §5.0.** The seed projected a
  cross-trait synchronous query amendment to `LedgerEngine`
  (`current_snapshot_id() -> SnapshotId`). Under the
  actor-mesh framing, snapshot identity flows through the
  diagnostic-stream surface as a `LedgerDiagnostic::SnapshotMerged`
  event (Phase 0g). The cross-trait synchronous query is
  unnecessary; the additive event-surface amendment replaces
  it. **Net effect: load-bearing surface coupling collapses
  to additive-only event-surface coupling.** Phase 0c is
  withdrawn.
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
composition under §5.0; R2 / R8 / R9 / R11 carry to Round 2.

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
struct LocalPendingTx {
    inner: Mutex<ReservationTracker>,
    sink: Arc<dyn DiagnosticSink>,
    ledger: L,                 // for current_snapshot reads in Stage 1
}

// Stage 4: PendingTxActor (push-driven from diagnostic stream)
struct PendingTxActor {
    current_snapshot: SnapshotId,         // updated from
                                          // LedgerDiagnostic::SnapshotMerged
    reservations: HashMap<ReservationId, Reservation>,
    sink: Arc<dyn DiagnosticSink>,        // emits PendingTxDiagnostic
    // No mutex: mailbox FIFO is the serialization point.
}
```

The `Mutex<ReservationTracker>` from §2.4 Round 3 is a Stage 1
implementation detail — it satisfies the `&self` trait surface
under in-process call-graph semantics. The Stage 4 actor doesn't
need it because mailbox-FIFO is the serialization point.

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
}
```

The trait surface adds a `&dyn DiagnosticSink` parameter to
`LocalPendingTx::new` (constructor-bound, matches PR 4's
preference per §3.1 spend-secret locality with R4-equivalent
reasoning) or per-method (per-call dispatch is also fine —
runtime-swap surface preserved either way). Round 2 disposes
the constructor-vs-per-method shape jointly with R11 (the
signing-actor split question).

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
not a deferral candidate. The §7 closure rule ("Round 1
closes when the wargaming surface is genuinely exhausted")
governs: the framing exhausts the surface in one round, and
delaying the disposition to Round 2 would be the
cost-benefit-defer-to-later anti-pattern the rule forecloses.

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
  construction).** Implementing `RefreshInProgress` requires
  `PendingTxActor` to query `RefreshActor`'s state ("is a
  refresh attempt in flight?"). That query is the DoS surface:
  an adversarial daemon controls refresh duration (RPC latency,
  response timing, withholding response completion); it can
  keep one refresh perpetually "in flight" via slow drip-feed
  responses, indefinitely blocking every user `submit` attempt
  with `SendError::RefreshInProgress`. Single-peer DoS of the
  entire transaction-submission flow — structural under the
  actor-mesh framing because the cross-actor query *is* the
  attack surface. Privacy wallets routinely connect to daemons
  under adversary control (Tor-routed daemons, hosted-wallet
  operators, mixed-trust deployments per
  [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md)); the
  build/submit flow must not serialize behind refresh
  quiescence for the wallet to remain usable in those threat
  models. **Rejected on criterion 5 (§5.3).**

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
  delivered as silent hang).** Implementing block-until-merge
  also requires `PendingTxActor` to depend on `RefreshActor`'s
  liveness (await its completion). The DoS surface is identical
  to (2): adversarial daemon keeps refresh "in flight" via
  drip-feed responses; `build` waits indefinitely. Worse user
  experience than (2) (no error to act on, just a perpetual
  spinner) and identical structural DoS by construction — the
  cross-actor liveness dependency is the attack surface.
  **Rejected on criterion 5 (§5.3).**

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
residuals R2 / R8 / R9 / R11 plus Phase 0 enumeration.

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
     because their `RefreshActor`-state query crosses an actor
     boundary that the mailbox cannot serialize without
     introducing the structural-ground-3 DoS surface.
5. **Adversarial-daemon resistance (load-bearing-by-construction
   under §5.0).** Does the chosen shape survive a hostile
   daemon attempting to DoS the transaction-submission flow?
   Under the §5.0 actor-mesh framing this is **structural**, not
   contingent: the DoS surface is the cross-actor liveness query
   itself. Shapes (2) and (3) *require*
   `PendingTxActor` to query `RefreshActor`'s state ("is a
   refresh in flight?" / "has the refresh completed?") to
   implement their respective contracts; under hostile daemon
   control of refresh duration, that query stalls indefinitely
   and the build/submit flow stalls with it. Shape (1) under
   the actor mesh has *no such query* — `PendingTxActor` knows
   what it knows from the diagnostic stream
   (`LedgerDiagnostic::SnapshotMerged`), and the build/submit
   flow proceeds against whatever the most-recently-merged
   snapshot is regardless of `RefreshActor`'s liveness.

   **Threat-model anchor.** Privacy wallets routinely connect
   to daemons under adversary control (Tor-routed daemons,
   hosted-wallet operators, mixed-trust deployments per
   [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md)); the
   build/submit flow must not serialize behind refresh
   quiescence for the wallet to remain usable in those threat
   models. Per
   [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §1
   (security and quantum resilience as preconditions), a shape
   that admits structural single-peer DoS of transaction
   submission is rejected even when its UX is good and its
   trait surface is minimal. This is the rejection ground that
   defeats (2) and (3) under the actor framing — the criterion
   is satisfied by construction by (1), and Round 1's wargaming
   has no fourth-shape escape route that doesn't reintroduce
   the cross-actor liveness query.

### §5.4 Residuals (some dissolved by §5.0; rest deferred to Rounds 2+)

Several residuals dissolve by composition under the §5.0
actor-mesh framing — the same pattern as PR 4 §5.4.7 R5
(reorg-amplification → `ReorgAmplificationDetector` consumer
actor). The dissolution is principled, not optimistic: each
dissolved residual is a question the actor-mesh framing makes
**superfluous by construction**, not a question deferred to
later. The remaining residuals (R2 / R8 / R9 / R11) carry to
Round 2 with the dispositions framed below.

- **R2 — `SnapshotId` opacity and side-channel implications
  (Round 2; Phase 0b candidate).** Height-bearing `SnapshotId`
  (e.g., `pub struct SnapshotId(pub u64)` carrying block height)
  is simpler but leaks block-height info into every reservation
  and every actor envelope. Opaque `SnapshotId` (e.g., a 16-byte
  digest of the snapshot's content) requires `LedgerEngine` to
  maintain an internal mapping but closes the height-leak
  side-channel.

  **Subtlety to pin in Round 2.** A content-addressed `SnapshotId`
  (hash of `LedgerSnapshot` state) is deterministic per snapshot
  by construction — two reservations built against the same
  snapshot share the same `SnapshotId`. This is *required* by
  staleness detection (the snapshot identity must be deterministic
  for the field comparison in §5.0's message handler to work)
  but it is itself a side-channel: any consumer of multiple
  reservations can correlate "these N reservations are pinned
  to the same snapshot," observable as "user constructed N
  transactions during a single ~30s polling window." Within
  trust boundary (orchestrator, in-process actors), this is
  fine and even useful (UI can batch-display reservations by
  snapshot for context). Across trust boundary in the recursive
  sense per PR 4 §5.4.8 #4 (logs that get pasted, telemetry
  exports, debug UIs with off-host surfaces, any in-process
  consumer that aggregates and republishes), it leaks
  transaction-rate timing.

  **Mitigation principle (carry forward from PR 4 §5.4.8 #4).**
  Full `SnapshotId` flows only to in-process consumers whose
  external surface is itself within the trust boundary; projection
  types (e.g., a per-reservation opaque random handle that
  internally maps to a `SnapshotId` for staleness detection,
  distinct per reservation even when the underlying snapshot is
  identical) cross the trust boundary for consumers that
  publish or persist. The same recursive-trust-boundary discipline
  applies to `LedgerDiagnostic::SnapshotMerged { new, prior,
  height }`'s `height` field; in-process consumers see the full
  event, cross-boundary consumers see a projection that elides
  height. Round 2 disposition lands the projection-type shape
  if any cross-boundary consumer is named in Phase 1's call-site
  sweep.
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
- **R8 — Reservation TTL / leak prevention (reframed as
  TTL-actor composition; Round 2 + V3.x FOLLOWUPS).** What
  happens to reservations that are neither submitted nor
  discarded? Under shape (1), staleness detection at submit
  invalidates reservations at snapshot rotation, but rotation
  only happens when refresh merges new state. A wallet that has
  finished refreshing and sits idle (user reviewing the
  constructed tx, considering whether to send) holds reservations
  indefinitely against the same snapshot. A consumer that
  crashes or has a bug between build and discard leaks the
  reservation outright. The threat-model property the tracker
  delivers (monotonicity, wallet-layer double-spend defence)
  interacts here: leaked reservations are output-locking the
  wallet against legitimate alternative uses.

  **Reframed disposition under §5.0.** A `ReservationTTLActor`
  subscribes to `PendingTxDiagnostic::BuildSucceeded` events,
  maintains in-memory per-reservation age tracking, emits
  `ReservationOutstanding { age }` warnings on stale
  reservations, signals `PendingTxActor` (via mailbox message)
  to auto-discard if policy permits. Same shape as PR 4's
  `PeerReputationActor` / `RecoveryActor` consumer-actor
  pattern. The trait surface stays minimal; the capability
  composes. Restart-amnesia constraint per PR 4 §5.4.8 #1
  binds: in-memory only, drop on wallet close.

  **Round 2 disposition for PR 5.** Trait-side: confirm that
  `PendingTxDiagnostic::ReservationOutstanding` and
  `Discarded { reason: SnapshotRotationAutoDiscard }` events
  are emitted from the right call sites. **V3.x FOLLOWUPS:**
  `ReservationTTLActor` consumer-actor entry, same shape as
  PR 4's V3.x consumer-actor entries.
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
- **R11 — Signing-actor split (new under §5.0; Round 2 + V3.x
  FOLLOWUPS).** §3.1 spend-secret-locality says the spend
  secret enters `LocalPendingTx`'s signing path at submit time.
  Under the actor mesh, two options:

  ```rust
  // (a) PendingTxActor holds spend material, like LocalRefresh
  //     under PR 4 R4
  struct PendingTxActor {
      spend_material: ScannerSecrets,  // bound at
                                       // LocalPendingTx::new
                                       // (R4-equivalent)
      // ...
  }

  // (b) Separate SigningActor; PendingTxActor delegates
  struct PendingTxActor {
      signing_actor: ActorRef<SigningActor>,
      // ...
  }
  struct SigningActor {
      spend_secret: Zeroizing<[u8; 32]>,
      // sole holder of spend material; replies to sign requests
  }
  ```

  (a) is consistent with PR 4 R4's instance-scoped pattern; the
  spend secret lives with the trait that uses it.

  (b) is the stricter threat-model shape: `PendingTxActor`
  never holds the spend secret; it constructs the transaction
  bytes, sends them to `SigningActor` for signing, receives
  signed bytes back. The signing surface is reduced to a single
  actor whose only job is signing — easier to audit, easier to
  isolate, easier to swap for HW-wallet integration in V3.x
  (which is exactly PR 4 R4's deferred-(c) trigger condition
  per
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R4).

  **Round 2 disposition for PR 5.** For Stage 1, (a) is the
  moves-not-rewrites path (the spend material crosses the
  trait boundary the same way it crosses today's `Engine<S>`
  boundary). For Stage 4+, (b) is the long-term shape and
  matches the trajectory R4 already pinned. **V3.x FOLLOWUPS:**
  `SigningActor` migration entry with the same HW-wallet-trigger
  language R4 used.

### §5.5 Round 1 disposition — shape (1), actor-mesh framing

**Disposition (2026-05-13).** Round 1 closes at **shape (1) —
build-against-current-snapshot + snapshot-ID pinning** — under
the §5.0 actor-mesh framing. The wargaming surface is
exhausted in this round per the §7 closure rule: shapes (2)
and (3) fail criterion 5 (§5.3) on **structural** grounds
rather than contingent grounds, and no fourth shape survives
the framing. The rounds budget for PR 5 compresses against
the seed's three-to-four-rounds projection: Round 2 disposes
the surviving residuals (R2 / R8 / R9 / R11) and enumerates
Phase 0 amendments; Round 3 does commit decomposition. Two
rounds saved against the original projection.

**Rationale (the three structural grounds, restated).** Under
the actor-mesh framing, shape (1) wins on:

1. **Phase 0c collapses.** No cross-trait synchronous query
   amendment to `LedgerEngine`; snapshot identity flows through
   `LedgerDiagnostic::SnapshotMerged` events (additive surface,
   not load-bearing surface). Phase 0g is the resulting
   amendment.
2. **The CAS isn't a CAS.** Submit-time staleness is a field
   comparison in the actor's message handler; the actor is the
   serialization point; mailbox FIFO orders concurrent calls.
   R3 / R10 dissolve; R5's trait-surface aspect dissolves.
3. **Adversarial-daemon resistance is structural.** The DoS
   surface in (2) and (3) is the cross-actor liveness query
   itself — `PendingTxActor` querying `RefreshActor` whether
   refresh is in flight or has completed. Shape (1) under the
   actor mesh has no such query. Hostile daemon control of
   refresh duration cannot block the build/submit flow because
   the build/submit flow does not depend on refresh
   termination.

**Five-criteria scorecard.**

| Criterion (§5.3)                              | (1) | (2) | (3) |
|-----------------------------------------------|-----|-----|-----|
| 1. PR 5 extraction cleanliness                | ✓   | ✓   | ✓   |
| 2. PR 4 α confirms                            | ✓   | ✓   | ✓   |
| 3. Reservation-tracker monotone semantics     | ✓   | ✓   | ✓   |
| 4. Stage 4 actor-migration compatibility      | ✓   | ✗   | ✗   |
| 5. Adversarial-daemon resistance (structural) | ✓   | ✗   | ✗   |

(2) and (3) fail criterion 4 because their `RefreshActor`-state
query introduces the structural-ground-3 DoS surface across the
actor boundary; criterion 5 is the same property re-evaluated
against the threat model.

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
  reframed; R11 added).
- §5.5 (this section; Round 1 disposition + scorecard).
- §4 Phase 0 candidates updated (§4 below): 0c removed; 0f
  (`PendingTxDiagnostic` + `DiagnosticSink` parameter) and 0g
  (`LedgerDiagnostic::SnapshotMerged` variant) added.

**What Round 2 carries.** R2 (`SnapshotId` opacity / projection
types), R8 (`ReservationTTLActor` composition + V3.x
FOLLOWUPS), R9 (two-stage submit flow + intermediate state),
R11 (signing-actor split for V3.x); plus Phase 0 enumeration
and the cross-cutting `DiagnosticSink` contract-doc
generalization (§5.0.3).

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
residuals (R2 / R8 / R9 / R11) and finalizes Phase 0
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
R11) land round-by-round in Round 2.

**Round 1 closure rule (applied).** Round 1 closes when the
wargaming surface is genuinely exhausted, not on a schedule.
The "enumerate-now-dispose-Round-2" default exists because
PR 5's R1 has cascading effect on PR 4 Round 3 and the
wargaming surface is broader than PR 4 Round 1's (which
converged at α because architectural-inheritance discipline
made α structurally obvious). The default is not a mandate:
if Round 1's wargaming closes with no surviving alternative
under adversarial review, landing the disposition in Round 1
is honest, not premature.

The §5.0 actor-mesh framing exhausts the wargaming surface
in this round on **three structural grounds** (§5.1): the
cross-trait synchronous query collapses (Phase 0c → 0g);
submit-time staleness is a field comparison, not a CAS;
adversarial-daemon resistance is structural by construction.
Shapes (2) and (3) fail criterion 5 (§5.3) by construction
under the framing; no fourth shape escape route exists that
doesn't reintroduce the cross-actor liveness query.
Per the §7 closure rule, Round 1 closes here.

Delaying the disposition to Round 2 in spite of the closed
wargaming surface would be the cost-benefit-defer-to-later
anti-pattern per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc);
the closure rule forecloses that default.

---

## §8 Fenceposts — what subsequent rounds fill in

Round 1 closes the load-bearing question (§5.5). Remaining
work, by round:

**Round 2.**

- §5.4 R2 (`SnapshotId` opacity / projection types disposition;
  Phase 0b detail).
- §5.4 R8 (`ReservationTTLActor` composition; V3.x FOLLOWUPS
  entry).
- §5.4 R9 (two-stage submit flow; intermediate-state shape;
  per-error-class disposition).
- §5.4 R11 (signing-actor split; V3.x FOLLOWUPS entry).
- §4 Phase 0 final enumeration (binding type-signature detail
  for 0a / 0b / 0d / 0e / 0f / 0g; cross-trait amendment
  review).
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

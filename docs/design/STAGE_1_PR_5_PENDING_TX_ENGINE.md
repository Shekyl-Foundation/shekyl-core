# Stage 1 PR 5 — `PendingTxEngine` extraction — design

**Status.** **DRAFT — initial seed (2026-05-13).** This document is
opened immediately after Stage 1 PR 4's design substrate lands on
`dev` (merge commit `6de8335d5`, PR #42). PR 5's load-bearing first
question — `PendingTxEngine::build` behaviour during a long refresh
— is the resolution gate that closes PR 4's **provisionally
load-bearing** α-disposition per
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.3 "Recommendation track (post-Round-2)" and §5.4.7 R1.

The seed is intentionally short on disposition and long on
question-naming. Subsequent revisions land each design round
inline (the precedent set by PR 3's
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) and
PR 4's
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md),
each of which grew round-by-round to its current shape).

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
- **Prior round's bequest.**
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R1 carries forward
  **build-against-current-snapshot + snapshot-ID pinning** as
  PR 5 Round 1's working hypothesis. The reservation tracker
  carries a `snapshot_id` with each reservation; the submit path
  becomes a CAS against `current_snapshot ==
  reservation.snapshot_id`, else returns
  `SubmitError::SnapshotInvalidated`. PR 5 opens with this as the
  hypothesis to attack, not as a settled disposition.
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
- **PR 4 Round 3 dependency.** PR 4 §5.3 explicitly defers
  PR 4 Round 3 to PR 5's R1 resolution: "Round 3 evaluates
  whether PR 5 needs γ for **correctness** (not convenience). If
  R1's resolution surfaces that the reservation tracker cannot
  deliver its correctness property under α, the disposition
  reverts and PR 4 re-opens to γ at higher cost than landing γ in
  Round 1 would have been. Round 1's α-disposition is therefore
  *provisionally load-bearing* — the rounds budget Round 3
  carries is the re-evaluation gate." **PR 5 Round 1 is therefore
  PR 4 Round 3's input.**

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

## §4 Phase 0 candidates (TBD)

Phase 0 doc-only spec amendments precede Phase 1 implementation
per the PR 2 / PR 3 / PR 4 precedent. Candidates surface as the
design rounds progress; this section is the holding place.

**Currently identified candidates (subject to revision).**

- **Phase 0a — `SubmitError` variant extension (R1-dependent).**
  Under the snapshot-ID-pinning working hypothesis, a new
  variant `SubmitError::SnapshotInvalidated { reservation_snapshot:
  SnapshotId, current_snapshot: SnapshotId }` lands additively.
  Under the `RefreshInProgress` alternative, the variant lands
  on `SendError` (build-time validation, not submit-time). Under
  block-until-merge, no variant addition needed. Phase 0a scope
  depends on §5 disposition.
- **Phase 0b — `SnapshotId` public type (R1-dependent).** Under
  the snapshot-ID-pinning working hypothesis, a new opaque
  identifier type `SnapshotId` lands in `shekyl-engine-core`
  (or as part of the §2.2 `LedgerEngine` surface). The type's
  shape — opaque token vs height-bearing — is a Round 2 question
  with actor-envelope and side-channel implications (see §5.4
  Sub-decision D candidate).
- **Phase 0c — `LedgerEngine::snapshot` surface extension
  (cross-trait, R1-dependent).** Under the snapshot-ID-pinning
  working hypothesis, `LedgerSnapshot` must expose a `SnapshotId`
  field (or `LedgerEngine` must expose `current_snapshot_id() ->
  SnapshotId`). This is a cross-trait Phase 0 — touches §2.2
  spec, not just §2.4. The amendment is additive per the §7
  invariants but lands in PR 5's Phase 0 (the originating PR).
- **Phase 0d — `Reservation` struct extension (R1-dependent).**
  Under the snapshot-ID-pinning working hypothesis, the
  reservation record carries a `snapshot_id: SnapshotId` field.
  This is a `LocalPendingTx`-internal extension if `Reservation`
  is crate-private; a §2.4 surface amendment if `Reservation` is
  publicly exposed.
- **Phase 0e — reservation-lifecycle prose pin in §2.4.** Pin
  the build/submit/discard atomicity contract and the
  snapshot-invalidation disposition (under R1's working
  hypothesis: the submit-time CAS returns
  `SubmitError::SnapshotInvalidated`; the reservation auto-
  releases on this failure; the consumer rebuilds against the
  new snapshot). Phase 0e is prose-only; the binding type
  signatures land in Phase 0a / 0b / 0c / 0d.

---

## §5 Open design question — `PendingTxEngine::build` behaviour during long refresh

This is the load-bearing open question per PR 4 §5.4.7 R1's
working hypothesis and PR 4 §5.3's "PR 5's R1 disposition is
PR 4 Round 3's input" framing.

### §5.1 The question

When `PendingTxEngine::build` is invoked while a refresh attempt
is in flight (the steady-state poll case, or the cold-open multi-
minute case), what is the trait contract? Three candidate shapes,
each with different reservation-tracker semantics and different
UI consequences:

#### (1) Build-against-current-snapshot + snapshot-ID pinning (working hypothesis)

`build` reads `current_snapshot` synchronously, constructs the
transaction against it, and the resulting `Reservation` carries a
`snapshot_id`. `submit` is a CAS: succeed iff `current_snapshot
== reservation.snapshot_id`; else return
`SubmitError::SnapshotInvalidated` and auto-release the
reservation.

- **Pros (UX).** UI shows "pending" without flashing; reservation
  tracker has monotone semantics (each reservation pinned to
  exactly one snapshot, never re-quoted); refresh and build can
  proceed concurrently without serialization; consumer rebuilds
  cleanly on snapshot invalidation.
- **Pros (adversarial-daemon robustness).** The build/submit
  flow is decoupled from refresh quiescence: `build` reads the
  most recent merged snapshot without requiring the current
  refresh attempt to complete, and `submit`'s CAS validates
  staleness without depending on refresh termination. An
  adversarial daemon can force snapshot-rotation churn by
  producing real chain reorgs, but that requires actual
  chain-rewrite cost (bounded by Shekyl's reorg-window depth);
  each consumer rebuild cycle is bounded latency, not unbounded.
  Unlike (2) and (3), no DoS pattern of "drip-feed refresh
  indefinitely" can block the submit flow.
- **Cons.** New types: `SnapshotId`, `SubmitError::
  SnapshotInvalidated`. Cross-trait Phase 0 amendment to §2.2 to
  expose snapshot identity from `LedgerEngine`. `SnapshotId`'s
  opacity is a Round 2 question (height-bearing token leaks
  block-height info into the actor envelope; opaque token
  requires `LedgerEngine` to maintain an internal snapshot-ID
  ↔ snapshot-state mapping).

#### (2) `RefreshInProgress` error at build

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
- **Cons (adversarial-daemon DoS).** An adversarial daemon
  controls refresh duration (RPC latency, response timing,
  withholding response completion). The daemon can keep one
  refresh perpetually "in flight" via slow drip-feed responses,
  indefinitely blocking every user `submit` attempt with
  `SendError::RefreshInProgress`. Single-peer DoS of the entire
  transaction-submission flow. This is structural, not a UX
  nicety: privacy wallets routinely connect to daemons under
  adversary control (Tor-routed daemons, hosted-wallet operators,
  mixed-trust deployments) and the build/submit flow must not
  serialize behind refresh quiescence for the wallet to remain
  usable in those threat models.

#### (3) Block-until-merge at build

`build` waits for the current refresh attempt to complete before
reading the snapshot. No error variant; just latency.

- **Pros.** No new types; no new error variants; UI shows a
  spinner without flashing.
- **Cons (UX).** Cold-open case: refresh attempt can take
  minutes; `build` hangs for the full duration. Serializes user
  input behind background work, which is the wrong default per
  PR 4 §5.4.4's three-call-mode constraint. Forecloses concurrent
  build-during-refresh entirely.
- **Cons (adversarial-daemon DoS).** The same DoS as (2),
  delivered as silent hang instead of error. An adversarial
  daemon keeps refresh "in flight" via drip-feed responses;
  `build` waits indefinitely. Worse user experience than (2)
  (no error to act on, just a perpetual spinner) and identical
  structural DoS — single hostile peer can prevent every user
  submit attempt indefinitely without producing any signal the
  consumer can branch on.

### §5.2 Implications for PR 4

PR 4 §5.3's framing: PR 4's α-disposition is *provisionally
load-bearing* until PR 5's R1 closes. If R1 closes at (1)
snapshot-ID pinning, the reservation tracker has monotone
semantics under α — refresh proceeds against the ledger
serially per α, build reads the most recent merged snapshot, the
CAS catches mid-refresh stale-snapshot cases. PR 4 confirms α
and proceeds to Round 4.

If R1 closes at (2) `RefreshInProgress`, the UI consequence is
poor but PR 4's α holds at the trait level — the reservation
tracker doesn't need new shape. PR 4 still confirms α; the UX
disposition is a separate question.

If R1 closes at (3) block-until-merge, PR 4's α holds but the
UX disposition is poor at cold open. PR 4 still confirms α.

If the rounds surface a fourth shape that requires consumer-
driven refresh-progress streaming (γ in PR 4's terms), PR 4 re-
opens to γ at higher cost than landing γ in Round 1 would have
been. The Round 1 review pass of PR 4 (§5.4.4 three-call-mode
analysis) projected that snapshot-ID pinning is the shape that
gives the reservation tracker monotone semantics without
requiring γ; PR 5's Round 1 task is to attack this projection.

**Decision deadline.** Before PR 5 design rounds reach Round 2.
Round 1 closes with a disposition; Rounds 2+ refine the chosen
shape's Phase 0 amendments.

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
   - Does the submit-time CAS (if R1 closes at shape (1))
     translate cleanly to a mailbox message, or does it require
     a synchronous reply that mailboxes serialize poorly?
5. **Adversarial-daemon resistance.** Does the chosen shape
   survive a hostile daemon attempting to DoS the
   transaction-submission flow? Specifically: can an adversary
   controlling daemon-side refresh timing (drip-feed responses,
   withheld completions, arbitrary RPC latency) block all user
   submits indefinitely, or is the build/submit flow decoupled
   from refresh quiescence? This is a structural property under
   the privacy-wallet threat model per
   [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) and the
   anonymity-network deployment topologies in
   [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md), not a UX
   nicety. The §5.1 analysis surfaces that (2) and (3) both fail
   this criterion identically (drip-feed-refresh → unbounded
   `RefreshInProgress` or unbounded wait); (1) passes by
   decoupling submit-time staleness detection from refresh
   termination. The criterion is named explicitly so Round 1's
   wargaming can attack (1)'s robustness claim rather than
   re-deriving the comparison from first principles.

### §5.4 Residuals (deferred to Rounds 2+)

The following residual questions surface from §5.1–§5.3 and
defer to subsequent rounds:

- **R2 — `SnapshotId` opacity and side-channel implications.**
  Height-bearing `SnapshotId` (e.g., `pub struct SnapshotId(pub
  u64)` carrying block height) is simpler but leaks block-height
  info into every reservation and every actor envelope. Opaque
  `SnapshotId` (e.g., a 16-byte digest of the snapshot's content)
  requires `LedgerEngine` to maintain an internal mapping but
  closes the height-leak side-channel.

  **Subtlety to pin in Round 2.** A content-addressed `SnapshotId`
  (hash of `LedgerSnapshot` state) is deterministic per snapshot
  by construction — two reservations built against the same
  snapshot share the same `SnapshotId`. This is *required* by
  the CAS (the snapshot identity must be deterministic for the
  comparison to work) but it is itself a side-channel: any
  consumer of multiple reservations can correlate "these N
  reservations are pinned to the same snapshot," which is
  observable as "user constructed N transactions during a single
  ~30s polling window." Within trust boundary (orchestrator,
  in-process actors), this is fine and even useful (UI can
  batch-display reservations by snapshot for context). Across
  trust boundary in the recursive sense per PR 4 §5.4.8 #4
  (logs that get pasted, telemetry exports, debug UIs with
  off-host surfaces, any in-process consumer that aggregates
  and republishes), it leaks transaction-rate timing.

  **Mitigation principle (carry forward from PR 4 §5.4.8 #4).**
  Full `SnapshotId` flows only to in-process consumers whose
  external surface is itself within the trust boundary; projection
  types (e.g., a per-reservation opaque random handle that
  internally maps to a `SnapshotId` for CAS, distinct per
  reservation even when the underlying snapshot is identical)
  cross the trust boundary for consumers that publish or persist.
  Round 2 disposition lands the projection-type shape if any
  cross-boundary consumer is named in Phase 1's call-site sweep.

  Phase 0b candidate.
- **R3 — Build-during-refresh-during-reorg interaction.** What
  happens if a reorg merges during `build`? Under (1), the
  build's CAS at submit catches this; under (2) and (3), the
  build either fails or waits. Round 2 detail.
- **R4 — Discard semantics under snapshot invalidation.** Under
  (1), the `SubmitError::SnapshotInvalidated` path auto-releases
  the reservation. Is auto-release the right behavior, or should
  the consumer explicitly `discard`? Round 2 hygiene.
- **R5 — Outstanding-reservations behavior on snapshot rotation.**
  When a new snapshot becomes current (refresh merges a
  `ScanResult`), what happens to outstanding reservations
  against the prior snapshot? Three sub-options: (a) eager
  auto-discard on snapshot rotation; (b) lazy auto-discard at
  next submit (per (1)); (c) explicit consumer-driven discard.
  Round 2 disposition.
- **R6 — `outstanding()` semantics under snapshot pinning.**
  Does `outstanding()` count reservations against the current
  snapshot only, or across all snapshots (including
  about-to-be-invalidated reservations from a prior snapshot)?
  Round 2 hygiene.
- **R7 — `Send + Sync + 'static` bound on `P`.** Stage 4 wraps
  `LocalPendingTx` in a `kameo` actor; the bound has to be on
  the `P` generic parameter. §4 Phase 0a candidate.
- **R8 — Reservation TTL / leak prevention.** What happens to
  reservations that are neither submitted nor discarded? Under
  shape (1), the CAS at submit invalidates reservations at
  snapshot rotation, but rotation only happens when refresh
  merges new state. A wallet that has finished refreshing and
  sits idle (user reviewing the constructed tx, considering
  whether to send) holds reservations indefinitely against the
  same snapshot. A consumer that crashes or has a bug between
  build and discard leaks the reservation outright. The
  threat-model property the tracker is supposed to deliver
  (monotonicity, wallet-layer double-spend defence) interacts
  here: leaked reservations are output-locking the wallet
  against legitimate alternative uses. Sub-options span (a) no
  TTL, documented discard discipline; (b) lazy TTL on
  output-reuse pressure (release oldest on collision); (c)
  explicit TTL with consumer-facing renewal. Each has different
  actor-envelope and persistence implications. Round 2
  disposition; possible §4 Phase 0d/0e amendment.
- **R9 — Daemon-side submit failure → reservation state.** R4
  covers the CAS-fails case (snapshot-invalidated → auto-release
  → rebuild). It does **not** cover the CAS-passes-but-
  daemon-rejects case: `submit` consumed the reservation and the
  daemon returned `AlreadyInMempool` / `DoubleSpend` / `FeeTooLow`
  / `Malformed` / timeout. Each has different downstream
  semantics:
  - `AlreadyInMempool` — the tx is already known; treat as
    success or duplicate?
  - `DoubleSpend` — the outputs are genuinely gone; the
    tracker's "available" view is wrong and needs refresh.
  - `FeeTooLow` — the consumer may want to retry with higher
    fee; the outputs should be available again.
  - `Malformed` — wallet-side bug or daemon-byzantine path;
    reservation should release but the bug should surface
    diagnostically.
  - Timeout — genuinely ambiguous; the tx may or may not have
    landed. Conservative disposition: do not auto-retry; force
    operator to query before resubmitting.

  Conservative working disposition is "on daemon rejection,
  refresh the tracker's view; consumer rebuilds if needed" but
  the trait contract should specify the per-error-class behavior
  rather than collapse to one disposition. Round 2.
- **R10 — Concurrent build/submit/discard on the same
  reservation.** `&self` everywhere (per §2.4 Round 3) means the
  trait can be called concurrently from multiple tasks.
  `Mutex<ReservationTracker>` handles the mutation serialization,
  but the contract surface needs explicit semantics for:
  - Two concurrent `submit(reservation_id)` calls — first wins,
    second errors with `PendingTxError::ReservationConsumed`
    (or equivalent).
  - Concurrent `submit` and `discard` on the same id —
    whichever acquires the mutex first wins; loser errors.
  - Concurrent `build` calls — independent, race on output
    selection mediated by the tracker; both succeed if disjoint
    outputs are available, second fails with insufficient-funds
    semantics if not.

  This is a contract pin, not a behavioural surprise — but the
  trait contract should specify so actor-model implementors
  and concurrent consumers share the same mental model.
  Round 2 hygiene; §4 Phase 0e candidate.

---

## §6 Review checklist (TBD)

Filled in once §5 settles and Phase 0 / Phase 1 commit
decomposition is known. The shape mirrors PR 4's §6 (the
binding-check matrix against the spec, the test-substrate
preservation list, the call-site sweep audit, the PR 4 Round 3
input bundle).

---

## §7 Discipline budget

This seed counts as Round 1 substrate of the design rounds.
Subsequent revisions land round-by-round inline (the PR 3 / PR 4
precedent).

**Estimate (subject to revision):** 2–4 rounds before Phase 0
spec amendments land; 1–2 rounds during Phase 0 review; Phase 1
implementation rounds depend on commit count.

The discipline-budget posture follows PR 4's: design rounds
happen in writing (this document) on the design feature branch;
the rounds budget is consumed by the user's review of the
written analysis between commits, not by live design sessions.
PR 5's R1 disposition lands as a separate commit after this
seed; subsequent residual dispositions (R2–R10) land round-by-
round.

**Round 1 closure rule.** Round 1 closes when the wargaming
surface is genuinely exhausted, not on a schedule. The
"enumerate-now-dispose-Round-2" default exists because PR 5's R1
has cascading effect on PR 4 Round 3 and the wargaming surface
is broader than PR 4 Round 1's (which converged at α because
architectural-inheritance discipline made α structurally
obvious). The default is not a mandate: if Round 1's wargaming
closes with no surviving alternative — if shapes (2) and (3)
both fail an explicit criterion and no fourth shape emerges
under adversarial review — landing the disposition in Round 1
is honest, not premature. PR 4 took one round because the
analysis closed there; PR 5 takes as many as the analysis
genuinely requires. The discipline is *settle when the
wargaming actually closes*, not *always take two rounds*.

---

## §8 What this seed does not yet resolve

- §5 R1 disposition (the load-bearing question; PR 4 Round 3
  input).
- §5.4 R2–R10 residuals (deferred to subsequent rounds).
- §4 Phase 0 amendments (depend on §5).
- §6 review checklist (depends on §5 and §4).
- §7 Phase 1 commit decomposition (depends on §5 / §4).

These are the fenceposts the round-by-round revisions fill in.

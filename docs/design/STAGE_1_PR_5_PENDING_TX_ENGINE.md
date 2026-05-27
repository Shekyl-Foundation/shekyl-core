# Stage 1 PR 5 — `PendingTxEngine` extraction — design

**Status.** **Round 1 closed (2026-05-13); Round 2 closed
(2026-05-14), segment 2h reopen-and-close (2026-05-26) for
actor-state-shape refinement, segment 2i reopen-and-close
(2026-05-27) for wider-ecosystem-lessons audit (G1–G8
substrate dispositions); Round 3 closed (2026-05-26) —
§7.X Phase 1 commit decomposition appended: eight commits
C0–C8 (with C2 / C4 / C5 sub-decomposed per `90-commits.mdc`
bisection discipline) load-bearing-ordered, every Phase
0a–0l binding-form mapped to a specific commit, every §6
review-checklist item mapped to a specific commit's test
deliverable, every existing pre-PR-5 substrate entry
inventoried with its diff scope. Segment 2h's §7.X delta
applied per §5.6.8 (commit list and load-bearing ordering
unchanged; within-commit content updated for the (γ) lean
actor-state-shape, the `SubmitError` / `SubmitErrorKind`
reshape into `TerminalErrorKind` + `AmbiguousErrorKind`,
the `PendingTxDiagnostic::SubmitFailed` removal +
`SubmitPendingResolution` addition, the
`DiscardReason::SnapshotRotationAutoDiscard` removal under
lazy R5, and the F1–F8 + P1–P9 dispositions); segment 2i's
§7.X delta applied per §5.6.12 (commit list and ordering
still unchanged; within-commit content updated for the G1
mempool-eviction substrate — `DiscardReason::MempoolEvicted`
variant, `tx_hash: TxHash` projection field on
`SubmitSucceeded` + `SubmitPendingResolution`,
`signal_mempool_evicted` narrow trait method with F2
ownership-boundary adjudication rationale, new Phase 0m
binding-form pin — and the G4 Stage 4 multi-step submit
shape pinned in §5.0.1 with deferred-reply substrate-
confirmation pin binding the Stage 4 actor-migration PR's
framework-selection pre-flight). The
`feat/stage-1-pr5-pending-tx-engine` short-lived branch
(per `06-branching.mdc` rule 2; ≤5 days, ≤10 commits)
cuts off the post-Round-3 dev tip; the PR opens against
`dev` after C8 lands locally with a passing CI run. —
all eight Round 2 segments landed: 2a (audit-readiness),
2b (R11 signing-actor split reframe to (b); R14 reservation
extensibility seam), 2c (closure-rule and lens-applicability
refinements paired with R13 / R15 / R16 / R17 named with
dispositions), 2d (R2 + R12 co-disposition; Phase 0c truly
collapses; `SnapshotId` opacity closed as 16-byte content-
addressed digest), 2e (R8 `ReservationTTLActor` composition
closure; `DiscardReason::TTLAutoDiscard` variant pin), 2f
(R9 two-stage submit-flow closure with daemon-side authority
for Finding 2 ambiguous outcomes; `SubmitError` +
`SubmitErrorKind` enum pins; sink-binding constructor-bound
closure for Finding 4), and 2g (Round 2 close-out: §4 Phase 0
binding-form enumeration including new Phase 0h `Signer` /
0i `OutputSelector` / 0j `FeeEstimator` / 0k
`SubmissionStrategyActor` topology slot; `SnapshotId` hash
primitive pinned as Keccak-256/128-bit truncation via
`shekyl-crypto-hash::cn_fast_hash` (revised from segment-2g's
prior `sha2`-based binding in the Copilot-fix follow-up for
dependency-discipline correctness — `sha2` at Cargo.toml line
115 is dev-deps-only, production at line 33 is `optional =
true`; `shekyl-crypto-hash` is unconditional in production
deps at line 28); §5.0.3 diagnostic-stream-doc
generalization closed as (a) rename to
`DIAGNOSTIC_STREAM.md`; §6 review checklist filled with all
binding-check / test-substrate / call-site-sweep items), and
2h (post-Round-3-readiness actor-state-shape refinement;
(γ) lean three-collection shape replacing the segment-2f
internal `ReservationState` enum; SubmitError /
SubmitErrorKind reshape into TerminalErrorKind +
AmbiguousErrorKind split; PendingTxDiagnostic::SubmitFailed
removal + SubmitPendingResolution addition; lazy R5
preservation with DiscardReason::SnapshotRotationAutoDiscard
removal at V3.0 and V3.x eager-discard FOLLOWUPS reopening
trigger; F1–F8 + P1–P9 dispositions; new Phase 0l
ReservationTTLConfig binding-form pin; §5.0.3 seventh
temporal- and distributional-projection contract pin;
§5.6.1–5.6.8 holds the substrate), and 2i (wider-ecosystem-
lessons audit post-segment-2h-close; G1 mempool-eviction
diagnostic-stream variant + tx_hash projection field + new
narrow `signal_mempool_evicted` trait method pinned with F2
ownership-boundary adjudication rationale per
`21-reversion-clause-discipline.mdc`; G2 long-range-reorg
of confirmed txs disposed as `LedgerDiagnostic`-domain
out-of-`PendingTxEngine`-scope with V3.0-accepted-UX
surface pin parallel to F8; G3 transaction-replacement
disposed as priority-hierarchy-rejected per
`00-mission.mdc` priority-ordering-not-magnitude framing
with sharpened reopening criteria (FCMP++ fingerprint-
unobservability cryptographic analysis OR R16 V3.x
WalletSideEstimator telemetry demonstrating fee-estimation
insufficiency at user-impact-significant rate that
re-classifies stuck-tx-recovery from priority-3 UX to
priority-1 security/integrity); G4 Stage 4 multi-step
submit shape (`submit_start` → `submit_signed` →
`submit_completed` self-continuation) + deferred-reply
substrate-confirmation pin binding the Stage 4 actor-
migration PR's framework-selection pre-flight; G5 output
maturity-filtering disposed as `LedgerEngine` trait-contract
domain forward-template; G6–G8 V3.x FOLLOWUPS; §5.6.9
discipline-citation matrix of seven what-the-wallet-
ecosystem-has-taught items; §5.6.10 / §5.6.11 hold the
G1–G8 substrate; new Phase 0m `signal_mempool_evicted`
trait-method binding-form pin; §4 Phase 0f reshape adds
the G1 enum/field amendments). Round 3 (commit
decomposition + Phase 1 commit list) closed 2026-05-26 —
see §7.X below for the eight-commit Phase 1 deliverable;
§5.6.8 records the segment-2h within-commit delta; §5.6.12
records the segment-2i delta-on-delta against §7.X.** This
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
**(Note: R17's "permitting wallet-internal encrypted-
persistence opt-in (V3.x)" framing is hardened by PR 4
Round 4 review pass F1 (2026-05-15) — see the carryover
note in the Round 4 review-pass-derived hardenings paragraph
below.)**

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

**Round 2 segment 2f (2026-05-14) — R9 two-stage submit-flow
closure with daemon-side authority for Finding 2 ambiguous
outcomes; `SubmitError` + `SubmitErrorKind` enum pins;
sink-binding constructor-bound closure for Finding 4.**
Segment 2f closes the last residual on the load-bearing
submit path and the constructor-vs-per-method sink-binding
question, leaving only Round 2 close-out work for segment 2g.
**R9 closure** pins the two-stage submit flow with explicit
internal `ReservationState` machine (`Active |
SubmitPendingDaemonAck | Resolved`) — trait-surface
unchanged; `outstanding()` counts `Active` +
`SubmitPendingDaemonAck`. Per-error-class disposition table
pins state-transition + diagnostic-event-sequence + trait-
return tuples for `Accepted` / `AlreadyInMempool` /
`DoubleSpend` / `FeeTooLow` / `Malformed` / `Timeout` /
`NetworkError` outcomes. **Finding 2 closes as (B) —
daemon-side authority for ambiguous outcomes**: on `Timeout`
or `DaemonUnavailable`, the reservation stays in
`SubmitPendingDaemonAck`; the wallet does not assume a
resolution it cannot verify; consumer-explicit `discard(id,
ConsumerExplicit)` is the resolution path; R8's
`ReservationTTLActor` (via per-state TTL configuration with
shorter TTL on `SubmitPendingDaemonAck` than on `Active`) is
the safety net for forgotten resolutions. (A) (actor-state
authority on timeout) is rejected because the phantom-spent-
output window violates the monotonicity property the tracker
delivers per §3.4.5; deferring the safety to the daemon's
`DoubleSpend` rejection is the same anti-pattern as
"consumer's checking does work the trait should be doing
structurally" identified in PR 4. (C) (bounded grace period)
is rejected for the same reason on a bounded window.
**`SubmitError` and `SubmitErrorKind` enums** pinned in
§5.0.2 (both `#[non_exhaustive]`): `SubmitError` =
`SnapshotInvalidated{ reservation_snapshot, current_snapshot }`
| `DaemonRejected{ kind: SubmitErrorKind }`;
`SubmitErrorKind` = `DoubleSpend | FeeTooLow | Malformed |
DaemonTimeout | DaemonUnavailable`. **Self-continuation
message pattern** pinned: `PendingTxActor` defers reply
until `SubmitCompleted` self-message arrives, preserving
mailbox throughput and making the intermediate state
explicit in the actor's state machine. **R5 ↔ R8 ↔ R9
coherence** verified: R5's reactive cleanup
(`SnapshotRotationAutoDiscard`), R8's proactive cleanup
(`TTLAutoDiscard`), and R9's daemon-authority cleanup
(`DaemonRejectedTerminal`) share the
`DiscardReason`/`Discarded` event infrastructure; downstream
consumers see a unified `Discarded` event stream with
discriminated reasons covering all three closure paths. **No
new `PendingTxDiagnostic` variants needed** — the existing
variant set (`SubmitAttempted`, `SubmitSucceeded`,
`SubmitFailed{kind}`, `Discarded{reason}`) is sufficient to
observe the full R9 state machine. **No new trait surface
methods needed** — `discard(id, ConsumerExplicit)` is
sufficient for consumer-explicit resolution of Finding-2
ambiguity cases; `resolve_pending(id, chain_observation)`
preserved as a V3.x ergonomic-API candidate.
**Sink-binding closure (Finding 4)**: §5.0.2.1 pins
constructor-bound `LocalPendingTx::new(..., sink: Arc<dyn
DiagnosticSink>, ...)` under PR 4 §3.4.5 / R4 (a)
consistency; R11's segment-2b closure as (b) makes the
sink-binding question independent of spend-material
disposition; the two close separately. Rationale: engine-
identity coupling (1-to-1 mapping load-bearing at the type
level), Stage 4 actor wiring alignment (spawn-time DI),
call-site cleanliness, runtime-swap surface preserved via
sink-side indirection. Existing `SubmitFailureAnalyzer`
FOLLOWUPS entry amended with segment-2f closure status; new
`TimeoutResolverActor` FOLLOWUPS entry added naming the V3.x
ergonomic-complement surface for Finding 2's daemon-side
authority disposition. The R1 disposition still holds;
segment 2f is residual-closure work that finalizes R9's
disposition and pins Finding 4 for design purposes. Phase 1
call-site sweep (Round 3 commit decomposition) confirms
emission discipline for all V3.0 deliverables. Only Round 2
close-out (segment 2g) remains.

**PR 4 Round 4 review pass — derived hardenings (2026-05-15).**
PR 4's pre-implementation adversarial review pass (full
writeup at PR 4 §5.4.9) produced two findings that bind to
PR 5 by carryover, applied here as substrate hardening
without reopening any PR 5 round. **F1 R17 hardening**:
the segment-2c R17 disposition's "wallet-internal
encrypted-persistence opt-in (V3.x)" framing is hardened
to a structural rejection at V3.0 with conditional
reopening per PR 4 §5.4.9 F1's six-attack-vector enumeration
(crypto code-path expansion, deserialization-on-startup,
metadata side-channel, cross-wallet correlation,
adversary-controlled DoS, forensic-artifact). Reopening
requires all of (a) demonstrated production use case from
real V3.0 deployments, (b) full threat-model review, (c)
explicit `AUDIT_SCOPE.md` amendment, (d) acknowledgment of
privacy-first default supremacy. The previously-planned
`PersistenceConsumerActor` V3.x FOLLOWUPS entry is
rewritten as a conditional-reopening bookmark with no
version target. See §5.4 R17's "Hardened disposition
(PR 4 Round 4 review pass F1 carryover)" subsection for
the full text. **F4 seventh contract pin**: the §5.0.3
cross-cutting `DiagnosticSink` contracts gain a
per-emitter FIFO ordering pin (per-emitter ordering
preserved; cross-emitter ordering undefined; consumer
actors derive cross-emitter ordering from explicit
causal-context fields like `SnapshotId`, not from
sink-observed arrival order). The pin binds symmetrically
across PR 4's `RefreshDiagnostic` and PR 5's
`PendingTxDiagnostic` streams. No PR 5 trait surface
change; both hardenings refine contract pins and
attack-surface dispositions without restructuring.

**PR 4 Round 4 review pass meta-review amendment — derived
hardening (2026-05-15).** PR 4's meta-review of its own
F1–F9 disposition substrate (full writeup at PR 4 §5.4.9
"Meta-review amendment — F11–F13") produced one finding
that binds to PR 5 by carryover: **F12 cross-emitter
ordering enforcement-gap amendment**. F4's seventh contract
pin is enforced procedurally; consumer-actor authors who
depend on cross-emitter arrival order produce code that
compiles cleanly, passes per-emitter FIFO tests, and
silently misbehaves under reordering at audit. F12 closes
the gap by binding consumer actors to derive cross-emitter
ordering from explicit causal-context fields carried inside
the events themselves (`SnapshotId`, `ReservationId` plus
version, `BlockHeight`); the V3.1+ FOLLOWUPS lint
(scope-extended from F5 to a unified
`diagnostic_consumer_discipline` lint) flags consumer-actor
code that branches on relative arrival timing of events
from distinct emitters without first constraining ordering
via a causal-context field. The §5.0.3 per-emitter FIFO
pin gains an "Enforcement-gap amendment (F12, 2026-05-15;
symmetric with PR 4 §5.4.6 amendment)" subsection naming
the binding discipline. F11 (per-transaction cancellation
safe-point pin) and F13 (`SuppressedRateLimit` field-shape
pin) do not bind to PR 5 by carryover — F11 targets PR 4's
per-block scan loop, which has no PR 5 analog (the `Signer`
trait per §5.4 R11 (b) does not iterate per-transaction
inside the synchronous trait surface); F13 targets PR 4's
`SuppressedRateLimit` variant, which is a `RefreshDiagnostic`
addition not mirrored in PR 5's `PendingTxDiagnostic`
taxonomy at this round. PR 5 may surface analogous pins at
its own pre-implementation review pass; tracking is
orthogonal. No PR 5 trait surface change; the hardening
refines the §5.0.3 contract pin without restructuring.

**Round 2 segment 2h (2026-05-26) — actor-state-shape
refinement (post-Round-3-readiness review).** Round 3
readiness review against the substrate landed through
segment 2g surfaced eight findings (F1–F8) and nine probes
(P1–P9). Three load-bearing classes clustered: (i)
**substrate-representation cost** — segment 2f's R9 closure
pinned an internal `ReservationState ∈ {Active,
SubmitPendingDaemonAck, Resolved}` enum carrying
representation that doesn't load-bear (F2's discard-during-pending-ack
and F7's per-state-TTL surface as state-machine-row questions
that dissolve under a leaner shape where the reservation's
collection-location encodes its lifecycle); (ii)
**submission-error reshape** — `PendingTxDiagnostic::SubmitFailed`
has no surviving emission site under P4's collection-moves
table, and unified `SubmitErrorKind` conflates terminal-vs-
ambiguous lifecycle consequences in a single type that
the collection-moves disposition makes legible only by
variant-set pattern-matching (type-correctness regression);
(iii) **lazy R5 vs eager R5 framing inconsistency** — P9
read as eager-discard but segment-2e's R5 closure pinned
lazy (stale reservations linger until consumer submits;
staleness detected at submit-time field comparison; rich
`SubmitError::SnapshotInvalidated` context). Segment 2h
reopens R5 / R8 / R9 per the §7 strengthened closure rule
and the
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
named-criteria reopening principle, and lands the **(γ)
three-collection lean state shape** —
`output_locks: HashMap<OutputId, ReservationId>` as single
source of truth for output ownership; `consumer_held:
HashMap<ReservationId, Instant>` for explicit consumer-held
membership and TTL aging; `in_flight: HashMap<ReservationId,
InFlightSubmit>` for explicit in-flight membership with
snapshot-id, creation, and submission timestamps; **no
`ReservationState` enum**. Lifecycle is encoded by
collection membership: in `output_locks` only → never
existed (gone); in `consumer_held` → consumer-held; in
`in_flight` → actor-owned during daemon round-trip; in
none → resolved (gone). The **SubmitError /
SubmitErrorKind reshape** splits `SubmitErrorKind` into
`TerminalErrorKind { DoubleSpend | FeeTooLow | Malformed }`
and `AmbiguousErrorKind { DaemonTimeout | DaemonUnavailable }`
(lifecycle distinction load-bearing at the type level);
removes `PendingTxDiagnostic::SubmitFailed` (no surviving
emission site under the P4 table); adds
`PendingTxDiagnostic::SubmitPendingResolution { rid,
kind: AmbiguousErrorKind }` for ambiguous-outcome
emission; adds `SubmitError::DaemonRejectedTerminal`,
`SubmitError::DaemonAmbiguous`,
`SubmitError::ReservationNotFound`,
`SubmitError::SubmitAlreadyPending`,
`PendingTxError::DiscardBlockedPendingDaemonAck`,
`PendingTxError::SubmitAlreadyPending`,
`PendingTxError::ReservationNotFound`,
`OutputSelectorError::ReturnedIndicesNotSubset`. **Lazy
R5 preserved** per segment-2e's original disposition;
snapshot rotation drives no automatic collection moves
at V3.0; consumer learns at submit-time via
`SubmitError::SnapshotInvalidated`;
`DiscardReason::SnapshotRotationAutoDiscard` drops at V3.0
with V3.x eager-discard FOLLOWUPS reopening trigger
(reopening criteria: telemetry-anchored performance need
+ selective-discard substrate refinement to
`HashMap<ReservationId, ConsumerHeldEntry { created_at,
snapshot_id }>`). **Per-finding dispositions** (full
substrate in §5.6.5): F1 Stage 1 / Stage 4
staleness-detection-property asymmetry pinned in §5.0 /
§5.0.1 / §5.0.2 prose (Stage 1 lock-based delivery is
exact; Stage 4 mailbox-FIFO delivery is best-effort per
the contract's "up to actor-local ledger view"
qualification; R9 daemon-side authority is the
consensus-correct ground); F2 ownership-boundary
disposition (consumer-initiated `discard` on `in_flight`
reservation → `PendingTxError::DiscardBlockedPendingDaemonAck`;
symmetric for re-submit via
`PendingTxError::SubmitAlreadyPending`); F3 §3.1
`Signer::Error` / `FeeEstimatorError` /
`OutputSelectorError` `Debug` / `Display` sensitive-material
discipline pin; F4 caller-side `OutputSelector` subset
re-verification + C5β binding test; F5 + F6 §5.0.3 seventh
temporal- and distributional-projection contract pin
(V3.0 ships field-projection only; temporal/distributional
disciplines deferred to `DIAGNOSTIC_STREAM.md` V3.x); F7
per-collection `ReservationTTLConfig { consumer_held,
in_flight }` V3.0 surface admitting V3.x
`ReservationTTLActor` per-collection aging policy (new
Phase 0l); F8 explicit V3.0 acceptance of
restart-during-`in_flight` consequence (V3.x
encrypted-persistence opt-in closes per existing R17
FOLLOWUPS scope). **Per-probe dispositions** (full
substrate in §5.6.6): P1 `outstanding() -> usize`
retained per §2.4 binding (no trait revision; §2.4
ownership-prose amendment is implementation-note
refinement only); P2
`PendingTxError::{DiscardBlockedPendingDaemonAck,
SubmitAlreadyPending, ReservationNotFound}` discriminated
taxonomy; P3 unified `ReservationNotFound` for
never-existed / already-resolved at the actor level
(diagnostic stream is the consumer-side reconstruction
surface for "was it ever there"); P4 collection-moves
table replaces enum-state-transitions table; P5
`InFlightSubmit { snapshot_id, created_at, submitted_at }`
admits either V3.x TTL aging policy (age-from-creation or
age-from-submission); P6 filter-then-select-then-subset-check
ordering pinned in §5.0.1; P7 actor handler-atomicity
(lock-claim + collection-insert + diagnostic-emit; no
`.await` between steps) pinned in §5.0.1 for Stage 1 and
Stage 4; P8 Stage 4 test-deliverable inheritance named in
§5.0.1 so Stage 4 actor-migration PR design rounds
inherit the obligation without re-derivation; P9 lazy R5
preservation (eager V3.x FOLLOWUPS with selective-discard
substrate trigger). **(c) FOLLOWUPS lean-shape rewrite**:
V3.x `discard_requested: bool` field on `InFlightSubmit`
reconciled at `SubmitCompleted` arrival; dual-emission
sub-note for `Rejected* ∧ discard_requested` cases
(audit/debug visibility design-rounds question);
strategy-actor threat-model regression note (V3.x
implementation MUST present the cancel-before-broadcast
and cancel-after-broadcast cases identically at the
consumer surface, OR the V3.x
`SubmissionStrategyActor`'s timing-obscurity property
is degraded). **Round 3 §7.X commit decomposition
stands** (commit list and load-bearing ordering
unchanged); within-commit content updated per §5.6.8 for
C0 / C2α / C2β / C2γ / C3 / C4α / C4β / C5β / C7 / C8.
The R1 disposition still holds; segment 2h is substrate
refinement that finalizes the actor-internal state shape
for design purposes ahead of Phase 1 implementation.

**Round 2 segment 2i (2026-05-27) — wider-ecosystem-lessons
audit (post-segment-2h substrate-completeness pass).**
Segment 2h polished the actor-state-shape question to a
high finish — internal-consistency-of-state-shape under
the (γ) lean three-collection substrate. The wider audit
question per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
("Internal consistency is necessary but not sufficient;
what the design delivers against the threat model is the
load-bearing question") is a different audit lens — what
does the wider transaction-handling ecosystem teach us
about what the engine needs to do that segment 2h didn't
name? Segment 2i is the substrate-completeness pass
against that lens. Eight gaps surface (G1–G8); five
require V3.0 substrate dispositions (G1–G5) and three
land as V3.x FOLLOWUPS (G6–G8). Two audit lenses, two
segments: segment 2h's commit `290ecb3c1` is the
state-shape substrate; segment 2i builds on it as the
ecosystem-lessons substrate; both stand together at
Round 2 close.

**G1 mempool-eviction substrate** — the existing
`SubmitPendingResolution` semantics assume the daemon
eventually delivers a verdict (Accepted /
TerminalErrorKind / AmbiguousErrorKind), but real-world
daemons silently drop txs from mempool when fee markets
fluctuate, mempool capacity refills, or peer-policy
filters trigger. Under the current segment-2h substrate
an evicted tx stays in `in_flight` until R8 TTL fires,
which could be hours, with `output_locks` held the entire
time and the consumer believing the tx is live. The V3.0
substrate gains: (i) `DiscardReason::MempoolEvicted` variant
pre-pinned per §4 Phase 0f reshape; (ii)
`PendingTxDiagnostic::SubmitSucceeded` and
`SubmitPendingResolution` gain a `tx_hash: TxHash`
projection field (the V3.x `MempoolMonitorActor`
consumer queries the daemon's mempool by tx hash and
can't reconstruct the hash from the actor-private
`InFlightSubmit`); (iii) a new narrow
`signal_mempool_evicted(rid) -> Result<(), PendingTxError>`
trait method on `PendingTxEngine` (new Phase 0m binding-
form pin) admitting the eviction signal back from the
consumer-observer. The narrow-vs-wide method-shape
question is adjudicated against F2's network-trust-
boundary discipline: mempool eviction is an *observation*
the consumer made that the actor couldn't, of a state
that's already terminal at the network level
(the tx is gone from the mempool; the daemon will never
Accept it); a wider `signal_external_terminal(rid, reason)`
shape would silently admit *decision-class* signals
(e.g., hypothetical `signal_user_force_cancel`) that F2's
discipline forbids. Per-method F2 adjudication preserves
the per-callsite grep-ability that the wider shape
forecloses; the rationale is recorded in §5.6.10 G1.
V3.x `MempoolMonitorActor` consumer-actor pattern
FOLLOWUPS'd.

**G2 long-range-reorg disposition** — a tx that
previously hit `SubmitSucceeded` and confirmed can get
reorged out at depth. The reservation is gone from
`PendingTxState` by then (P4 collection-moves dropped
the rid from `in_flight` at terminal resolution); the
outputs come back as unspent in `LedgerEngine`'s
candidate set on the surviving chain; the next build sees
them as available; no double-spend risk; the only rough
edge is the consumer-visible UI ("confirmed → unconfirmed →
re-confirmed") which is a `LedgerEngine` consumer-domain
concern. The proposed (c) disposition (PendingTxActor
emits a `TxReorgedOut` diagnostic) would require
retaining the rid → tx_hash mapping post-terminal
resolution, exactly the state-bloat the (γ) lean shape
was designed to forbid; (c) regresses (γ). The right
disposition is (a) reframed: G2 is `LedgerDiagnostic`-
domain, not `PendingTxDiagnostic`-domain. The V3.x
`LedgerDiagnostic::TxReorgedOut { tx_hash,
prior_block_height }` variant lands additively per
Phase 0g's deferred-to-consumer-PR pattern (parallel to
`SnapshotMerged`); V3.0 ships with the consensus-correct
behavior plus the V3.0-accepted UX-roughness surface pin
parallel to F8's restart-during-`in_flight` acceptance
(brief consumer-visible "confirmed → unconfirmed →
re-confirmed" indicator is V3.0-accepted; V3.x
`TxConfirmationTrackerActor` closes the UX gap). No
PendingTxEngine surface change at V3.0. Full substrate
in §5.6.10 G2.

**G3 transaction-replacement structural rejection** —
the design discipline question is whether to admit RBF /
CPFP-equivalent replacement of stuck txs. Replacement
creates a mempool-observer-visible linked-tx-pair
fingerprint (two replacement txs share a key image;
mempool observers see both sequentially before the second
gets rejected as double-spend; on-chain only one
persists). The fingerprint is *bounded* — transient,
mempool-only, only-fires-on-actual-replacement-invocation
— but it's a net-new privacy regression for a UX gain.
Per `00-mission.mdc` priority hierarchy as
*ordering-not-magnitude*: any priority-2 (privacy) cost
for any priority-3 (UX) benefit is rejected by the
ordering regardless of magnitude. Replacement is
structurally out-of-scope at V3.0; R14's
`ReservationExtension::Replacement` seam is **NOT
pre-pinned**. Per `21-reversion-clause-discipline.mdc`'s
named-criteria reopening principle, two substrate-
anchored triggers reopen the disposition: (i) FCMP++
cryptographic analysis demonstrating mempool-observer
fingerprint unobservability (e.g., proof-construction
randomization that prevents observers from linking key
images across mempool snapshots); (ii) R16 V3.x
`WalletSideEstimator` operational telemetry demonstrates
fee-estimation improvements are insufficient to prevent
stuck-tx scenarios at user-impact-significant rate —
which **re-classifies stuck-tx-recovery from priority-3
UX to priority-1 security/integrity** (users lose funds
to unrecoverable stuck txs), shifting the
priority-balance from priority-2-vs-priority-3 (privacy
wins) to priority-2-vs-priority-1 (security wins) under
the same ordering principle. The second trigger's
load-bearing piece is the priority-class promotion;
without it, the reopening criterion would be
"users complain at production scale," which is the
predictable-cost-of-the-priority-hierarchy disposition
that `00-mission.mdc` already rejects. Full disposition
in §5.6.10 G3; V3.x rejection-entry FOLLOWUPS'd with
named reopening criteria.

**G4 Stage 4 multi-step submit + deferred-reply
substrate-confirmation** — HW-wallet signing devices
routinely take 5–30 seconds for user confirmation; under
Stage 4, a single-step submit handler that calls
`Signer::sign` synchronously would block PendingTxActor's
mailbox FIFO for that duration, serializing multisig
coordination / batch operations / concurrent build flows
behind a single user tap. The structural disposition is
**multi-step submit at Stage 4**: `submit_start` handler
(atomic claim of `in_flight` via P7-atomic
consumer_held → in_flight collection-move; dispatch
signing request to `SigningActor` via `ActorRef`;
**defer reply**); `submit_signed` handler (self-message
from `SigningActor` with signed bytes; dispatch to
`DaemonEngine` with another deferred reply);
`submit_completed` handler (existing P4 table self-
message from `DaemonEngine` with collection-moves /
lock-release / emission and **the deferred reply
finally returned to the original caller**). P7's
handler-atomicity discipline holds within each handler
step; the submit operation as a whole is non-atomic by
design with the signing-latency window absorbed in the
gap between (1) and (2); PendingTxActor's mailbox
processes other messages (builds, discards on other
rids, snapshot-merged events) during the wait. The
V3.0 trait surface stays synchronous
(`Signer::sign(&self, ...) -> Result<...>` per
segment-2h Phase 0h); the multi-step shape is Stage-4-
internal and pinned in §5.0.1's Stage 4 prose. Stage 1
stays single-step (synchronous lock-based serialization
absorbs the latency cost; consumer blocks; correct
Stage 1 behavior).

The **deferred-reply substrate-confirmation pin** binds
the Stage 4 actor-migration PR's framework-selection
pre-flight: the multi-step submit shape requires the
Stage 4 actor framework to support deferred-reply
semantics (kameo's `Context::reply_later`-equivalent or
another framework's analogue — the actor accepts a
message, dispatches a self-continuation, defers the
reply, processes other mailbox messages, and replies on
a later self-message). Framework-selection pre-flight
MUST confirm substrate support before adopting kameo
or any alternative. If no candidate-set framework
supports deferred-reply, G4's disposition reopens at
the framework-selection altitude (trait-surface
revision to return a handle from `submit` and force
consumers to await it separately, OR framework-pattern
revision to spawn a per-submit ephemeral actor that
holds the reply context); the reopen lands at the
Stage 4 actor-migration PR's design-rounds altitude,
not retroactively against PR 5. Phase 1 wouldn't catch
this gap because PR 5 doesn't land Stage 4; the explicit
substrate-confirmation pin forecloses the Stage 4 PR's
design rounds discovering the framework gap and having
to redesign at a higher cost — the cost-benefit-defer-
to-later anti-pattern surfacing at the actor-framework-
selection altitude. Full pin in §5.6.10 G4 and §5.0.1
Stage 4 prose.

**G5 output-maturity-filtering forward-template** —
`LedgerEngine`'s candidate-fetch method returns
maturity-filtered outputs **by contract**:
`FCMP_REFERENCE_BLOCK_MIN_AGE` reorg-safety window;
coinbase-output unlock period; any V3.x staking-output
maturity. P6's filter-then-select-then-subset-check
ordering in `PendingTxActor`'s build flow handles
`output_locks` collision only; maturity is upstream.
Doc-level pin on `LedgerEngine`'s relevant method as a
forward-template item on the eventual `LedgerEngine`
trait extraction PR; segment 2i records the forward-
template explicitly so the eventual PR's design rounds
don't re-derive. Regression test posture: synthetic
immature output in the `LedgerEngine` impl's response
(rather than a `PendingTxActor`-side filter) is the
right test surface. Full disposition in §5.6.10 G5.

**§5.6.9 wallet-ecosystem-lessons discipline-citation
matrix.** Seven items recorded as a grep-able audit-trail
discipline: submit-time staleness detection over
optimistic-ignore-and-fail (R5 lazy); daemon-side
authority for ambiguous outcomes over local-optimistic
resolution (F2); ownership-boundary discipline over
state-machine-row enumeration ((γ) lean shape);
privacy-by-default fee estimation (R16); submission
strategy abstraction (R15); spend-material locality
(R11 Signer split); snapshot pinning over implicit-
"current state" assumption (R1, R2). Each entry pairs
the lesson with the wallet-ecosystem failure mode it
forecloses and the segment/closure that landed it.
Audit-attention surface for Phase 9 audit and post-V3.0
reviewers asking "why this substrate shape over the
obvious-from-other-coins shape?"

**G6 / G7 / G8 V3.x FOLLOWUPS.** G6 V3.x
`TxConfirmationTrackerActor` consumer-actor pattern
(post-`SubmitSucceeded` mempool-presence → confirmation-
count progression for wallet UI; shares
`SubmitSucceeded.tx_hash` substrate with G1). G7 V3.x
build-cancel ergonomic refinement (FCMP++ proof
generation can take seconds; consumer needs an abort
surface; V3.0 trait-surface synchronous `build() ->
Result<Reservation, ...>` shape doesn't foreclose
additive `build_with_handle()` or trait-extension
introduction at V3.x). G8 V3.x wallet-locked-during-
`in_flight` handling (wallet locks while in-flight
reservations exist; spend material clears from
`SigningActor` state on lock; in-flight reservations
whose daemon response arrives during the locked period
need a coordinated wallet-state-machine +
`PendingTxEngine` + `SigningActor` disposition).
FOLLOWUPS entries land in `docs/FOLLOWUPS.md` with
named reopening criteria and V3.x re-evaluation
shapes.

**§7.X commit-decomposition delta-on-delta (§5.6.12).**
The Round 3 eight-commit ordering (C0–C8) and segment-2h
sub-decomposition (C2α / C2β / C2γ / C4α / C4β / C5α /
C5β) survive segment 2i unchanged. Within-commit content
grows for C0 (Phase 0 doc-only scope grows ~10% by
segment 2i amendments, new Phase 0m); C2α (new
`DiscardReason::MempoolEvicted` variant, new
`signal_mempool_evicted` trait method on
`PendingTxEngine`, new `tx_hash: TxHash` fields on
`SubmitSucceeded` + `SubmitPendingResolution` variants);
C2β (`SubmitSuccessClass` discriminant projection grows
to include `tx_hash` projection-field); C3 (emission-
site for `MempoolEvicted` in the new
`signal_mempool_evicted` handler body); C5β
(`signal_mempool_evicted` handler body — F2 ownership-
boundary entry check; collection-moves dropping rid from
`in_flight`; lock release; `Discarded { rid,
MempoolEvicted }` emission); C7 (property test
covering `signal_mempool_evicted` ownership-boundary —
rid ∈ in_flight succeeds and drops; rid ∉ in_flight
returns `ReservationNotFound`; rid ∈ consumer_held
returns `ReservationNotFound` because consumer-held
reservations are not "in_flight" in the eviction-
relevant sense).

The R1 disposition still holds; segment 2i is substrate
refinement that completes the V3.0 substrate against the
wider transaction-handling ecosystem ahead of Phase 1
implementation. Segments 2h and 2i together close
Round 2's substrate work; Phase 1 begins on the C0 commit
landing.

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
- **Secret-locality discipline extends to delegate-trait error
  projections (segment 2h F3 pin).** Per
  [`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc),
  Phase 0h `Signer::Error` and (by extension) `FeeEstimatorError`
  / `OutputSelectorError` types carry `Debug + Display + Send +
  Sync + 'static` bounds. The `Debug` / `Display` projections
  routinely land in logs through standard tracing/log
  infrastructure; an HW-wallet `Signer` impl whose `Error`
  carries device-side attestation challenges, intermediate
  signing scalars, partial-signature material, or other
  Zeroize-required state would leak via the standard log
  surface. The trait bounds cannot syntactically enforce
  "no sensitive material in `Error` projections"; the
  discipline pin is documentary, binding `Signer` / `FeeEstimator`
  / `OutputSelector` impl authors and reviewers. **`Signer::Error`
  and its `Debug` / `Display` projections MUST NOT carry
  sensitive material** — spend-secret bytes, intermediate
  signing scalars, partial-signature material, HW-wallet
  device-side attestation challenges, or any intermediate
  state classified as Zeroize-required by §3.1's secret-locality
  taxonomy. Implementors structure their error types so
  `Debug` projects only the discriminant plus non-sensitive
  context; sensitive material returned by HW devices is
  consumed via `Zeroizing<…>` during Error construction,
  leaving the outward-facing Error free of secret material.
  The discipline transitively covers `FeeEstimatorError` and
  `OutputSelectorError` at reduced priority (these types
  don't normally hold spend material but the discipline pin
  is uniform across the secret-locality boundary). See §5.6.5
  F3 for the segment-2h substrate.

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
per-trait pre-flight checklist (status updated through
segment 2g):

- [x] Threat-model alignment (§3.1).
- [x] Architectural-inheritance audit projection (§3.2).
- [x] R1 disposition (§5 — closed in Round 1 as shape (1)
      build-against-current-snapshot + snapshot-ID pinning
      under the §5.0 actor-mesh framing; see §5.5).
- [x] Phase 0 spec amendments identified (§4 — closed in
      Round 2 segment 2g with binding-form type-signature
      detail for all candidates 0a–0k).
- [ ] Phase 1 commit decomposition (§6 — Round 3 task;
      §6 review checklist filled in segment 2g as substrate).
- [x] PR 4 Round 3 input bundle (resolved as confirmation
      per §5.2; the bundle is this document at segment-2g
      close-out plus PR 4's corresponding follow-up commit
      recording the "α confirmed" disposition).

---

## §4 Phase 0 candidates (post-Round-1 enumeration)

Phase 0 doc-only spec amendments precede Phase 1 implementation
per the PR 2 / PR 3 / PR 4 precedent. Round 1's disposition
(§5.5 — shape (1) under the §5.0 actor-mesh framing) closes the
R1-dependence on these candidates; the surviving set is below.
Round 2 segment 2g finalizes Phase 0 enumeration (binding
type-signature detail; cross-trait amendment review;
review-checklist gate for §6).

**Status (after Round 2 segments 2b–2g).** All Phase 0
candidates pin their type-signature shape. Phase 0c is removed.
Four additional candidates — Phase 0h (`Signer`), Phase 0i
(`OutputSelector`), Phase 0j (`FeeEstimator`), Phase 0k
(`SubmissionStrategyActor` topology slot) — land from
segment-2b / segment-2c residual closures. Phase 0 is closed for
design purposes; Phase 1 commit decomposition proceeds against
this enumeration in Round 3.

**Currently identified candidates (post-Round-1; finalized in
segment 2g).**

- **Phase 0a — `SubmitError` enum + `TerminalErrorKind` /
  `AmbiguousErrorKind` split enums + `PendingTxError`
  discriminated variants + `OutputSelectorError` subset-violation
  variant (binding form pinned in segment 2f; reshaped in
  segment 2h under the (γ) lean state shape + P4 collection-moves
  table + F2 / F4 / P2 / P3 dispositions; see §5.6.4 for the
  reshape rationale).** All `#[non_exhaustive]`. Binding
  signature:

  ```rust
  #[non_exhaustive]
  pub enum TerminalErrorKind {
      DoubleSpend,
      FeeTooLow,
      Malformed,
  }

  #[non_exhaustive]
  pub enum AmbiguousErrorKind {
      DaemonTimeout,
      DaemonUnavailable,
  }

  #[non_exhaustive]
  pub enum SubmitError {
      SnapshotInvalidated {
          reservation_snapshot: SnapshotId,
          current_snapshot: SnapshotId,
      },
      DaemonRejectedTerminal { kind: TerminalErrorKind },
      DaemonAmbiguous {
          kind: AmbiguousErrorKind,
          reservation_id: ReservationId,
      },
      ReservationNotFound { reservation_id: ReservationId },
      SubmitAlreadyPending { reservation_id: ReservationId },
  }

  #[non_exhaustive]
  pub enum PendingTxError {
      // ... build-side variants (BuildErrorKind family;
      // unchanged from segment 2g) ...
      DiscardBlockedPendingDaemonAck { reservation_id: ReservationId },
      SubmitAlreadyPending { reservation_id: ReservationId },
      ReservationNotFound { reservation_id: ReservationId },
  }

  #[non_exhaustive]
  pub enum OutputSelectorError {
      // ... existing variants ...
      ReturnedIndicesNotSubset { offending_index: OutputIndex },
  }
  ```

  Lives in `shekyl-engine-core::engine::pending_tx` (or the
  module that hosts the `PendingTxEngine` trait surface;
  Phase 1 review pins the precise location).

  **Type-correctness rationale (segment 2h).** The
  `TerminalErrorKind` / `AmbiguousErrorKind` split makes the
  lifecycle distinction (reservation gone vs. reservation
  still in `in_flight` per the P4 collection-moves table)
  load-bearing at the type level. Unified `SubmitErrorKind`
  conflated the two; consumer code matching the unified enum
  needed wildcard arms to handle lifecycle distinctions that
  the type system already knows about. The split exposes the
  distinction; consumers match on `SubmitError::DaemonRejectedTerminal`
  vs. `SubmitError::DaemonAmbiguous` and the type system
  enforces correct handling of each. The
  `PendingTxError::{DiscardBlockedPendingDaemonAck,
  SubmitAlreadyPending, ReservationNotFound}` taxonomy
  similarly makes the consumer-error class explicit (P2
  / P3 dispositions per §5.6.6). `OutputSelectorError::ReturnedIndicesNotSubset`
  satisfies the F4 caller-side subset re-verification contract
  (§5.6.5 F4).

- **Phase 0b — `SnapshotId` opaque type + hash primitive
  (binding form pinned in segment 2g per R2's segment-2d
  closure; revised in Copilot-fix follow-up for
  dependency-discipline correctness and security-rationale
  framing).** New opaque identifier type lands in
  `shekyl-engine-core` alongside the `LedgerEngine` surface
  it derives from. Binding signature:

  ```rust
  pub struct SnapshotId([u8; 16]);

  impl From<&LedgerSnapshot> for SnapshotId {
      fn from(snapshot: &LedgerSnapshot) -> Self { /* … */ }
  }
  ```

  **Hash primitive (segment-2g closure; revised in
  Copilot-fix follow-up).** Keccak-256 (original padding,
  `shekyl-crypto-hash::cn_fast_hash`) truncated to the first
  128 bits, with input domain-separated by a fixed prefix
  (e.g., `b"shekyl-snapshot-id-v1"`). Selection rationale:

  - **Dependency-discipline correctness
    (Copilot-fix follow-up).** `shekyl-crypto-hash` is an
    **unconditional** `[dependencies]` entry in
    `shekyl-engine-core` per
    [`rust/shekyl-engine-core/Cargo.toml`](../../rust/shekyl-engine-core/Cargo.toml)
    line 28; no feature flag, no `optional = true`, no
    dev-only gating. The Copilot-fix predecessor for this
    segment cited `sha2 = "0.10"` at line 115 as workspace-
    available, but line 115 is in `[dev-dependencies]`
    (test-only), and the production `sha2` at line 33 is
    `optional = true` (gated behind a feature flag).
    Switching the binding to `shekyl-crypto-hash::cn_fast_hash`
    satisfies the
    [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
    workspace-state reuse rule against the actual
    production-dependency graph rather than a misread of
    the Cargo.toml.
  - **Reuse of audit-scope primitive.** `cn_fast_hash` is
    Shekyl's consensus-critical `cn_fast_hash` primitive
    used throughout the codebase. Reusing it for
    `SnapshotId` derivation keeps the hash-primitive surface
    in `shekyl-engine-core` to a single audited
    construction.
  - **Bounded-population security framing
    (Copilot-fix follow-up; corrects prior collision-
    resistance / Grover-doubled-width framing).**
    `SnapshotId` is a **wallet-internal equality token over
    a bounded snapshot population**, not a consensus-bound
    or arbitrary-input hash. The relevant security property
    is **second-preimage resistance** (can an
    adversary-controlled daemon construct a `LedgerSnapshot`
    whose hash equals a target?), not collision resistance
    against arbitrary inputs. At 128-bit truncation:
    - **Classical second-preimage:** ~2¹²⁸ work (full output
      space).
    - **Quantum second-preimage (Grover):** ~2⁶⁴ work —
      large but bounded under aggressive quantum-adversary
      assumptions.
    - **Bounded-population safety:** the wallet observes
      ≪ 2⁴⁰ snapshots over its operational lifetime
      (one snapshot per refresh merge; ≈ one per ~30s
      during sync, ≈ one per ~2 min during normal
      operation; ≤ ~10⁷ snapshots over 100 years).
      Even framed as a generic collision primitive, the
      probabilistic-collision risk on uniformly-distributed
      128-bit outputs at this population is ~10⁻²⁵ —
      orders of magnitude below any practical security
      threshold.
    - **Impact bound under successful attack:** the wallet's
      submit-staleness check passes incorrectly against a
      daemon-injected snapshot replacement; the wallet
      submits a tx valid against the prior snapshot; the
      daemon could have rejected the tx anyway via
      `DoubleSpend` if the prior snapshot's outputs are now
      spent on-chain. No consensus violation; no wallet-
      state corruption that refresh cannot reconcile. The
      threat is bounded under the adversary-controlled-
      daemon design-center per §5.3.

    The prior segment-2g framing ("128-bit collision
    resistance gives ~2⁶⁴ classical work and ~2³² quantum
    work (Grover-doubled width)") applied Grover bounds
    to collision resistance, which is technically incorrect
    — Grover gives 2^(n/2) preimage attack work; collision
    on 128-bit truncated hashes is governed by birthday
    bound (~2⁶⁴ classical) and BHT (~2⁴³ quantum). The
    bounded-population framing avoids the misclassification
    by anchoring the security claim to the actual use case
    (equality-token comparison over a small finite
    population) rather than a generic
    cryptographic-collision-resistance threshold.
  - **Versioned prefix for V3.x migration.** Domain-
    separation via `b"shekyl-snapshot-id-v1"` forecloses
    hash collisions with other wallet-internal hashes over
    similar input shapes. The "v1" tag permits V3.x
    migration to a wider output (e.g., 256-bit) or a
    different hash family without a cross-stage rebuild
    (V3.0 wallets and V3.x wallets interoperate at the
    wire-format level; `SnapshotId` is a wallet-internal
    token that does not cross the wire).
  - **PQC alignment posture.** Keccak (the basis of SHA-3)
    is post-quantum-secure with the same Grover/BHT bounds
    as any hash function of comparable output width.
    Reusing `cn_fast_hash` does not introduce a new
    PQC-load-bearing primitive; the V3.x migration path is
    preserved via the version prefix.

  Recursive trust boundary applies per §5.4 R2: in-process
  consumers see the full 16-byte token; cross-boundary
  consumers receive projection types (the
  cross-boundary-projection implementation lands in the V3.x
  consumer-actor PR that introduces the first cross-boundary
  `SnapshotId` consumer; the discipline is documented per PR
  4 §5.4.8 #4's recursive-trust-boundary rule).

- **Phase 0c — REMOVED at the trait surface (R12 closed (a)
  in segment 2d; Phase 0c truly collapses; finalized in
  segment 2g).** The seed projected a cross-trait
  synchronous-query amendment to `LedgerEngine`
  (`current_snapshot_id() -> SnapshotId`) as a load-bearing
  amendment. Under the actor-mesh framing, snapshot identity
  flows through the diagnostic-stream surface as a
  `LedgerDiagnostic::SnapshotMerged` event (Phase 0g) for
  actor consumers; Stage 1's `LocalPendingTx` derives
  `SnapshotId` from `LedgerEngine::snapshot()` (the
  pre-existing trait method) per §5.4 R12 (a)'s segment-2d
  closure. **Net effect: the trait-surface load-bearing
  coupling the seed projected does not exist** — neither at
  V3.0 nor in any V3.x trajectory currently named. The
  additive event-surface amendment (Phase 0g) carries
  snapshot identity to actor consumers; the existing
  `LedgerEngine::snapshot()` carries it to Stage 1's
  synchronous trait-call consumer. **No Phase 1 commit
  decomposition entry for Phase 0c**; the slot is closed
  for design purposes.

- **Phase 0d — `Reservation` struct shape (binding form
  pinned in segment 2g; incorporates R14 extensibility
  seam from segment 2b).** Binding signature:

  ```rust
  pub struct Reservation {
      pub id: ReservationId,
      pub snapshot_id: SnapshotId,
      pub outputs: Vec<SelectedOutput>,
      pub tx_bytes: Vec<u8>,
      pub extensions: Vec<ReservationExtension>,
  }

  #[non_exhaustive]
  pub enum ReservationExtension {
      // Empty variant set in V3.0 per R14's segment-2b
      // closure. V3.x consumer-actor PRs add variants
      // (CoinjoinState, HtlcParams, TimelockedSubmission,
      // MultiStageState, ComposedReservation) additively
      // without a V3.0 trait revision.
  }
  ```

  **Field-name discipline** (segment-2g confirmation per
  segment-2b §5.4 R14): `extensions: Vec<ReservationExtension>`
  matches the `RefreshDiagnostic` / `PendingTxDiagnostic`
  extensibility-pattern conventions. **`#[non_exhaustive]`
  attribute placement** is on `ReservationExtension`
  (the variant-extending enum), not on `Reservation` itself
  (whose field set is fully exhaustive at V3.0; additions
  come through `extensions`'s variant set, not through
  field-adding edits). Lives in
  `shekyl-engine-core::engine::pending_tx` or a sibling
  module per Phase 1 location review.

- **Phase 0e — Reservation lifecycle prose in §2.4
  (binding form pinned in segment 2g; reshaped in segment 2h
  under the (γ) lean state shape — collection-moves replace
  enum-state-transitions; see §5.6.3).** Pin the
  build/submit/discard atomicity contract and the
  snapshot-invalidation + daemon-rejection dispositions
  under §5.0:

  - `submit`'s staleness check is a **field comparison in
    the actor's message handler** (Stage 4) or under the
    trait's `&self` mutation discipline (Stage 1); not a CAS
    in the contract sense. Stage 1 lock-based delivery is
    exact ("up to ledger truth"); Stage 4 mailbox-FIFO
    delivery is best-effort ("up to actor-local ledger
    view") per the segment-2h F1 staleness-detection
    asymmetry pin (§5.6.5 F1); R9 daemon-side authority is
    the consensus-correct ground.
  - On staleness mismatch, `submit` emits
    `PendingTxDiagnostic::SubmitSnapshotInvalidated` and
    replies `SubmitError::SnapshotInvalidated`. **Lazy R5
    disposition (segment-2h preservation):** the
    reservation does **not** auto-release on staleness
    mismatch; the consumer's `Reservation` value retains
    its `consumer_held` slot in the actor's tracker; the
    consumer is responsible for `discard(rid,
    ConsumerExplicit)` after receiving the error.
    Consumer's recourse: rebuild against the new snapshot
    (the rebuild's `discard` releases the stale
    reservation's `output_locks` cleanly). The R8 TTL
    safety-net handles consumer abandonment.
  - **(segment 2h reshape; replaces segment-2f addition)**
    On daemon round-trip completion, the **collection-moves
    table** per §5.4 R9 applies (§5.6.4 P4 table): for each
    `TerminalErrorKind` variant — drop from `in_flight`,
    release `output_locks` for the rid, emit `Discarded {
    rid, DaemonRejectedTerminal::* }`, return
    `Err(DaemonRejectedTerminal::*)`; for each
    `AmbiguousErrorKind` variant — retain in `in_flight`,
    retain `output_locks` for the rid (Finding-2 daemon-side
    authority), emit `SubmitPendingResolution { rid, kind }`,
    return `Err(DaemonAmbiguous { kind, rid })`. The actor
    does **not** carry a `ReservationState` enum — the
    reservation's `in_flight` / `consumer_held` /
    (none/gone) membership encodes the lifecycle. F2
    ownership-boundary: consumer-initiated `discard` on
    a reservation in `in_flight` returns
    `PendingTxError::DiscardBlockedPendingDaemonAck`;
    R8's V3.x `ReservationTTLActor` per-collection TTL
    safety-net fires on `in_flight[rid].submitted_at` (or
    `created_at`, per V3.x policy) for abandoned
    daemon-ambiguous reservations.
  - Concurrent `build` / `submit` / `discard` semantics are
    delivered by the actor's mailbox FIFO (Stage 4) or by
    `&self` interior mutability under
    `Mutex<ReservationTracker>` (Stage 1). Both satisfy
    the trait contract; the "messages process serially per
    actor instance" property is the actor-system invariant
    per §5.4 R10's dissolution. Per-handler atomicity (lock
    operations + collection-insert + diagnostic-emit all
    within a single handler invocation; no `.await` between
    mutation steps) is the segment-2h P7 discipline pin.

- **Phase 0f — `PendingTxDiagnostic` enum +
  constructor-bound `DiagnosticSink` parameter on
  `LocalPendingTx` (binding form pinned in segment 2g;
  reshaped in segment 2h under the (γ) lean state shape +
  P4 collection-moves table + lazy R5 preservation;
  segment 2i adds the G1 mempool-eviction variants +
  `tx_hash: TxHash` projection fields; see §5.6.4 for the
  segment-2h reshape rationale and §5.6.10 G1 for the
  segment-2i additions).** Parallel to PR 4's Phase 0e
  diagnostic-stream seam. Binding signature pinned in
  §5.0.2 (`PendingTxDiagnostic` variant set,
  `DiscardReason` variant set). Constructor-vs-per-method
  shape **closed as constructor-bound** in segment 2f per
  §5.0.2.1's five-point rationale (engine-identity coupling;
  Stage 4 actor wiring alignment; call-site cleanliness;
  runtime-swap surface preserved via sink-side indirection;
  no load-bearing reason for per-method override in
  production engines).

  **Segment-2h variant-set updates.** `PendingTxDiagnostic::SubmitFailed`
  REMOVED — no surviving emission site under the P4
  collection-moves table; terminal errors emit via
  `Discarded { rid, DaemonRejectedTerminal::* }`, ambiguous
  errors emit via the new `SubmitPendingResolution { rid,
  kind: AmbiguousErrorKind }`. `DiscardReason::SnapshotRotationAutoDiscard`
  REMOVED — segment-2h pins lazy R5; snapshot rotation
  drives no automatic collection moves at V3.0; consumer
  learns at submit-time via `SubmitError::SnapshotInvalidated`;
  V3.x eager-discard opt-in FOLLOWUPS (§5.6.7 P9 trigger)
  reintroduces the variant alongside selective-discard
  substrate. `DiscardReason::DaemonRejectedTerminal`
  ADDED with `{ kind: TerminalErrorKind }` payload.
  `PendingTxDiagnostic::SubmitPendingResolution { rid, kind:
  AmbiguousErrorKind }` ADDED.

  **Segment-2i variant-set updates.**
  `DiscardReason::MempoolEvicted` ADDED — variant for the
  G1 mempool-eviction terminal-resolution path; emitted by
  the new `signal_mempool_evicted` handler body (Phase 0m)
  on successful F2-adjudicated eviction signal.
  `PendingTxDiagnostic::SubmitSucceeded` gains a `tx_hash:
  TxHash` field projecting the just-submitted-and-accepted
  tx's hash; `PendingTxDiagnostic::SubmitPendingResolution`
  gains a `tx_hash: TxHash` field projecting the
  ambiguous-outcome tx's hash. Both projections are
  required by the V3.x `MempoolMonitorActor` consumer-actor
  pattern (the actor cannot reconstruct the tx hash from
  the actor-private `InFlightSubmit`; the diagnostic
  stream must project it). The V3.0 substrate pre-pins the
  projection; the V3.x consumer-actor PR consumes it
  additively without trait revision. Note `tx_hash` is
  *not* secret material — it appears on-chain by
  construction — so projection at the field-level
  recursive-trust-boundary discipline per PR 4 §5.4.8 #4
  is admissible without sensitive-material concerns.

  Cross-cutting `DiagnosticSink` contracts (non-blocking
  emit, emission/return coherence, recursive trust boundary,
  restart-amnesia detection, producer panic-safety,
  concurrent emit, and the segment-2h seventh
  temporal- and distributional-projection contract per
  §5.0.3 / §5.6.5 F5+F6) bind to PR 5 verbatim per §5.0.3.

- **Phase 0g — `LedgerDiagnostic::SnapshotMerged`
  variant addition (binding form pinned in segment 2g).**
  Cross-trait but **additive only**; lives entirely in
  the diagnostic-stream surface, not in `LedgerEngine`'s
  trait surface. Replaces Phase 0c. The `LedgerDiagnostic`
  enum (analogous to `RefreshDiagnostic`) is the parent
  surface; `SnapshotMerged { new: SnapshotId, prior:
  SnapshotId, height: BlockHeight }` is the variant PR 5
  needs.

  **Introduction-PR disposition (segment-2g closure).**
  PR 5 defers the `LedgerDiagnostic` enum introduction
  to a follow-up `LedgerEngine`-side PR. Rationale:

  - PR 5 has no V3.0 in-process consumer of
    `LedgerDiagnostic::SnapshotMerged` — Stage 1's
    `LocalPendingTx` derives `SnapshotId` synchronously
    from `LedgerEngine::snapshot()` (segment-2d R12 (a)
    closure); the event-stream consumer is Stage 4's
    `PendingTxActor`, which is not introduced in PR 5.
  - PR 5 introducing the `LedgerDiagnostic` enum
    speculatively (without a consumer) violates the
    [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)
    "code with no live caller" default-delete rule.
  - The natural introduction site is the V3.x
    consumer-actor PR that introduces the first
    `LedgerDiagnostic` consumer (likely Stage 4's
    `PendingTxActor` migration PR, or whichever
    consumer-actor lands first). The variant set is
    additive to PR 4's diagnostic-stream pattern and
    inherits the same `DiagnosticSink` contract bindings
    per §5.0.3.

  PR 5 records the variant **as a stub spec entry** in the
  follow-up PR's design doc (FOLLOWUPS entry); no Phase 1
  commit decomposition entry in PR 5 itself. This preserves
  the option without speculative introduction.

- **Phase 0h — `Signer` trait surface (binding form pinned
  in segment 2g per R11 (b) segment-2b closure).** Binding
  signature:

  ```rust
  pub trait Signer: Send + Sync {
      type Error: Debug + Display + Send + Sync + 'static;

      fn sign(
          &self,
          message: &[u8],
          // Additional Shekyl-specific signing inputs
          // pinned at Phase 1 (FCMP++ membership-proof
          // witness, hybrid-PQC signing context, etc.).
      ) -> Result<Signature, Self::Error>;
  }
  ```

  **Implementation locus.** `LocalSigner` is the V3.0
  software-key implementation; `HardwareSigner` is the V3.x
  HW-wallet implementation (per the FOLLOWUPS entry from
  segment 2b). The trait shape is narrow per the
  segment-2b discipline (sole purpose = signing; the
  spend-secret never escapes the `Signer` instance).
  Stage 1 consumption: `LocalPendingTx<S: Signer>` with
  `signer: Arc<S>` (constructor-bound). Stage 4
  consumption: `PendingTxActor` with `signer:
  ActorRef<SigningActor>` (spawn-time DI).

  **Phase 1 deferral.** The precise `sign()` method
  signature (additional Shekyl-specific witness inputs)
  is finalized at Phase 1 commit-decomposition review;
  the trait-existence and the spend-secret-locality
  contract are the segment-2g pin.

- **Phase 0i — `OutputSelector` trait surface (binding form
  pinned in segment 2g per R13 segment-2c closure).**
  Binding signature:

  ```rust
  pub trait OutputSelector: Send + Sync {
      fn select_outputs(
          &self,
          candidates: &[OutputCandidate],
          target: Amount,
      ) -> Result<SelectedOutputs, SelectionError>;
  }
  ```

  **Implementation locus.** `Wallet2GreedySelector` is the
  V3.0 default implementation (matches wallet2 carryover);
  V3.x alternative implementations
  (`RandomizedSelector`, `EntropyMaximizingSelector`)
  land per the FOLLOWUPS R13 entry. The trait shape is
  narrow (single method); selection-algorithm details are
  the impl's responsibility, not the trait surface's.
  Stage 1 consumption: `LocalPendingTx<S: Signer, O:
  OutputSelector>` with `output_selector: Arc<O>`
  (constructor-bound). Stage 4 consumption: `PendingTxActor`
  with `output_selector: Arc<dyn OutputSelector>` (spawn-time
  DI per segment-2c R13's actor-topology note).

- **Phase 0j — `FeeEstimator` trait surface (binding form
  pinned in segment 2g per R16 segment-2c closure +
  segment-2d V3.0-lift evaluation).** Binding signature:

  ```rust
  pub trait FeeEstimator: Send + Sync {
      fn estimate_fee(
          &self,
          tx_size: usize,
          priority: FeePriority,
      ) -> Result<Amount, FeeEstimationError>;
  }

  #[non_exhaustive]
  pub enum FeePriority {
      Low,
      Normal,
      High,
  }
  ```

  **Implementation locus.** `DaemonRecommendationEstimator`
  is the V3.0 default implementation (asks the daemon
  via `DaemonEngine::get_fee_estimates`); `ExplicitFeeEstimator`
  is a V3.0 alternative for wallet-UI / API explicit-fee
  workflows; `WalletSideEstimator` is the V3.x privacy-
  enhancing implementation analyzing `LedgerEngine`
  historical block-fee distribution (per segment-2d V3.0-
  lift evaluation, R16 (c) does not lift to V3.0; lands as
  a coordinated `LedgerEngine` + `FeeEstimator` PR in V3.x).
  Stage 1 consumption: `LocalPendingTx<S: Signer, O:
  OutputSelector, F: FeeEstimator>` with `fee_estimator:
  Arc<F>` (constructor-bound). Stage 4 consumption:
  `PendingTxActor` with `fee_estimator: Arc<dyn
  FeeEstimator>` (spawn-time DI).

- **Phase 0k — `SubmissionStrategyActor` topology slot
  (binding form pinned in segment 2g per R15 segment-2c
  closure).** **Not a trait surface amendment** —
  `SubmissionStrategyActor` is a Stage 4 actor-topology
  pin between `PendingTxActor` and `DaemonEngine`. Per
  segment-2c §5.4 R15:

  ```text
  PendingTxActor — submit msg → SubmissionStrategyActor
       │                           │ (apply strategy)
       │                           ▼
       │                       DaemonEngine actor
       │                           │ (broadcast)
       │                           ▼
       │                       (network)
  ```

  **V3.0 disposition.** Stage 1's `LocalPendingTx` calls
  `DaemonEngine::submit_tx()` directly with **no
  intermediate actor**; the `DirectStrategy` is implicit
  in the direct call. The actor-topology slot is reserved
  but unoccupied at V3.0; the trait surface does not
  grow. V3.x consumer-actor PRs land the
  `SubmissionStrategyActor` itself with the strategy
  taxonomy (`DirectStrategy`, `JitteredSubmissionStrategy`,
  `CircuitRotationStrategy`, `BroadcastStrategy`,
  `BatchedStrategy`) per the FOLLOWUPS R15 entry.

  **No Phase 1 commit decomposition entry for Phase 0k**;
  this is a forward-looking documentation pin rather than a
  V3.0 trait / type addition. The slot's existence is the
  Phase 0 deliverable; the actor's introduction is V3.x
  work.

- **Phase 0l — `ReservationTTLConfig` V3.0 surface (binding
  form pinned in segment 2h per F7 disposition; see §5.6.5
  F7).** Per-collection TTL configuration. Both fields default
  to `DEFAULT_RESERVATION_TTL`; the per-collection shape
  admits V3.x `ReservationTTLActor` per-collection aging
  policy without locking V3.x into uniform-TTL.
  `#[non_exhaustive]`. Binding signature:

  ```rust
  #[non_exhaustive]
  pub struct ReservationTTLConfig {
      pub consumer_held: Duration,
      pub in_flight: Duration,
  }

  impl Default for ReservationTTLConfig {
      fn default() -> Self {
          Self {
              consumer_held: DEFAULT_RESERVATION_TTL,
              in_flight: DEFAULT_RESERVATION_TTL,
          }
      }
      // Note: DEFAULT_RESERVATION_TTL value pinned in Phase 1
      // implementation; provisional 24h order-of-magnitude per
      // segment-2e R8 wargaming substrate.
  }
  ```

  Lives alongside `SubmitError` / `PendingTxError` in the
  `PendingTxEngine` module. **V3.0 consumer.** Constructor
  parameter on `LocalPendingTx::new(...)`; the engine's
  `outstanding()` / TTL-cleanup background scan reads
  `config.consumer_held` for `consumer_held[rid].created_at`
  aging and `config.in_flight` for either
  `in_flight[rid].created_at` or `in_flight[rid].submitted_at`
  aging (V3.x policy via `ReservationTTLActor`; V3.0 uses a
  uniform "age from creation" default for both collections,
  matching the V3.0 ergonomic-default disposition). **V3.x
  consumer.** `ReservationTTLActor` reads the same
  `ReservationTTLConfig` and applies per-collection aging
  policy (age-from-creation vs. age-from-submission) without
  trait revision.

- **Phase 0m — `PendingTxEngine::signal_mempool_evicted`
  trait method (binding form pinned in segment 2i per G1
  disposition; see §5.6.10 G1).** New narrow trait method
  admitting consumer-observed mempool eviction back to the
  actor. Lives on the `PendingTxEngine` trait alongside
  `build` / `submit` / `discard` / `outstanding`. Binding
  signature:

  ```rust
  /// Signal that a previously-submitted reservation's tx
  /// has been observed evicted from the daemon's mempool.
  ///
  /// **Threat-model framing (F2 ownership-boundary
  /// adjudication).** The actor owns the reservation
  /// during the in-flight window because the network is
  /// the trust boundary and the actor must hold the
  /// lock-release decision until the daemon resolves the
  /// outcome. Mempool eviction is an *observation* the
  /// consumer made that the actor couldn't make itself
  /// (the actor has no direct visibility into the
  /// daemon's mempool state); the observation is *of a
  /// state that's already terminal at the network level*
  /// (the tx is gone from the mempool; the daemon will
  /// never Accept it). The signal admits one specific
  /// observation under F2's discipline; it does NOT
  /// admit consumer-side terminal *decisions* (e.g., a
  /// hypothetical `signal_user_force_cancel` shape that
  /// F2 forbids).
  ///
  /// The narrow-vs-wide method-shape question is
  /// adjudicated here: each new "consumer signals
  /// terminal" candidate gets its own narrow method and
  /// its own F2 adjudication. A wider
  /// `signal_external_terminal(rid, reason)` shape would
  /// silently admit decision-class signals; the narrow
  /// shape preserves the per-method F2 adjudication
  /// grep-ability that the wider shape forecloses. See
  /// §5.6.10 G1 for the full F2 adjudication record.
  ///
  /// **Diagnostic emission.** On success, the engine
  /// emits `PendingTxDiagnostic::Discarded { rid,
  /// reason: DiscardReason::MempoolEvicted }` to the
  /// constructor-bound `DiagnosticSink`. Lock release and
  /// `in_flight` collection-move happen in the same
  /// handler step per P7's handler-atomicity discipline.
  ///
  /// **Errors.**
  /// - `PendingTxError::ReservationNotFound` if `rid` is
  ///   not in `in_flight` (either never existed,
  ///   already resolved, or is in `consumer_held` — the
  ///   eviction-relevant state requires `rid ∈ in_flight`).
  ///
  /// **Note: consumer-held reservations.** A `rid ∈
  /// consumer_held` returns `ReservationNotFound`, NOT a
  /// separate "wrong state" error, because (i) the
  /// eviction signal is meaningful only for in-flight
  /// reservations (consumer-held reservations were never
  /// submitted to the daemon, so they cannot be in the
  /// mempool, so they cannot be evicted); (ii) the
  /// consumer's submit-vs-evict race window is
  /// narrow-but-real (consumer submitted; daemon evicted
  /// before the success/timeout response landed; consumer
  /// then signals eviction; in the interim the actor's
  /// `submit_completed` handler may have already moved
  /// the rid out of `in_flight` per P4 — making the
  /// `signal_mempool_evicted` call's outcome a race
  /// against the actor's own state), where
  /// `ReservationNotFound` is the right disposition for
  /// "the rid is no longer in_flight, whatever the cause."
  fn signal_mempool_evicted(
      &self,
      rid: ReservationId,
  ) -> Result<(), PendingTxError>;
  ```

  Note `&self` (not `&mut self`) per `V3_ENGINE_TRAIT_BOUNDARIES.md`
  §2.4's Round 3 `&mut → &self` sweep — Stage 1 uses
  interior mutability (`Mutex<PendingTxState>`); Stage 4
  uses ActorRef-routing to the actor's mailbox FIFO.

  **V3.0 producer.** `MempoolMonitorActor` (V3.x; not
  pre-built at V3.0); pre-V3.x test fixtures hand-roll the
  call to exercise the trait method.

  **V3.x producer.** `MempoolMonitorActor` (FOLLOWUPS
  `MempoolMonitorActor` entry) subscribes to
  `PendingTxDiagnostic::SubmitSucceeded` and
  `SubmitPendingResolution` (both carry `tx_hash` per
  §4 Phase 0f reshape); periodically polls
  `DaemonEngine::query_mempool_presence(tx_hash)`; on
  observed eviction, calls
  `PendingTxEngine::signal_mempool_evicted(rid)`.

**Net Phase 0 change vs. seed projection (segment-2i final
summary).** One amendment removed (0c — load-bearing
cross-trait synchronous query); two diagnostic-stream
amendments added (0f, 0g — additive surface); five
trait-/topology-seam amendments added (0h `Signer`, 0i
`OutputSelector`, 0j `FeeEstimator`, 0k
`SubmissionStrategyActor` topology slot, 0l
`ReservationTTLConfig`); one trait-method amendment added
(0m `signal_mempool_evicted` per G1). Surface complexity
grows on the V3.0 trait-parameter side
(`LocalPendingTx<S, O, F>`), the constructor-parameter
side (`ReservationTTLConfig`), and the trait-surface
itself (one additional method) but contracts on the
cross-trait synchronous-coupling side (Phase 0c removed).
The structural trade is exactly the
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
continuous-discipline corollary: structural cleanup of
load-bearing surfaces at small additive cost on per-engine
type parameters and additive trait-method count; V3.x
consumer-actor PRs inherit the seams without trait
revision.

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

**Segment-2h (γ) lean state shape (see §5.6.2 for the
substrate, §5.6.3 for the collection-moves discipline).** The
actor / engine holds three collections and a snapshot; the
reservation's lifecycle is encoded by collection membership,
not by a `ReservationState` enum. Stage 1 and Stage 4 share
the same internal shape:

```rust
struct InFlightSubmit {
    snapshot_id: SnapshotId,
    created_at: Instant,    // preserved across consumer_held → in_flight
    submitted_at: Instant,  // when submit moved the rid into in_flight
    // V3.x: discard_requested: bool;  // see §5.6.7 (c) FOLLOWUPS entry
}

struct PendingTxState {
    current_snapshot: SnapshotId,
    output_locks: HashMap<OutputId, ReservationId>,
    consumer_held: HashMap<ReservationId, Instant>,   // explicit
                                                       // membership;
                                                       // tracks creation
    in_flight: HashMap<ReservationId, InFlightSubmit>,
}

// Stage 1: LocalPendingTx (in-process, &self, interior mutability)
struct LocalPendingTx<S: Signer, O: OutputSelector, F: FeeEstimator> {
    state: Mutex<PendingTxState>,
    sink: Arc<dyn DiagnosticSink>,
    ttl: ReservationTTLConfig,  // Phase 0l per-collection TTL
    ledger: L,                  // for current_snapshot reads at submit-time
                                // (Stage 1 lock-based; exact per F1 pin)
    signer: Arc<S>,             // §5.4 R11 (b): sole holder of spend
                                // material; LocalPendingTx never holds
                                // spend_secret directly
    output_selector: Arc<O>,    // Phase 0i
    fee_estimator: Arc<F>,      // Phase 0j
}

// Stage 4: PendingTxActor (push-driven from diagnostic stream)
struct PendingTxActor {
    state: PendingTxState,                // current_snapshot updated from
                                          // LedgerDiagnostic::SnapshotMerged
    sink: Arc<dyn DiagnosticSink>,        // emits PendingTxDiagnostic
    ttl: ReservationTTLConfig,            // Phase 0l per-collection TTL
    signer: ActorRef<SigningActor>,       // §5.4 R11 (b): sole holder
                                          // of spend material; never
                                          // held by PendingTxActor
    output_selector: Arc<dyn OutputSelector>,
    fee_estimator: Arc<dyn FeeEstimator>,
    // No mutex: mailbox FIFO is the serialization point.
}
```

The `Mutex<PendingTxState>` is a Stage 1 implementation detail
— it satisfies the `&self` trait surface under in-process
call-graph semantics. The Stage 4 actor doesn't need it because
mailbox-FIFO is the serialization point. **Handler-atomicity
discipline (segment-2h P7 pin).** Every message-handler that
mutates state must hold the lock (Stage 1) or run start-to-end
within a single mailbox-handler invocation (Stage 4) across
all of: lock claim/release on `output_locks` + collection
insert/remove on `consumer_held` / `in_flight` + sink emit. No
`.await` between mutation steps. Stage 1 satisfies this by
holding the `Mutex<PendingTxState>` guard across the
sequence; Stage 4 satisfies it by performing all mutations
synchronously within the handler before yielding to the
mailbox. **Staleness-detection asymmetry (segment-2h F1 pin).**
Stage 1's lock-based `current_snapshot` read is exact ("up to
ledger truth"); Stage 4's mailbox-FIFO `current_snapshot` read
is best-effort ("up to actor-local ledger view") because
`SnapshotMerged` and `submit` messages compete for FIFO
ordering. R9 daemon-side authority is the consensus-correct
ground in both cases. **Stage 4 test inheritance (segment-2h
P8 pin).** The Stage 1 test list (concurrent-build
serialization, etc.) is named in §6 review checklist; the
Stage 4 actor-migration PR inherits the test obligation —
the equivalent test under mailbox-FIFO serialization must
land in the Stage 4 PR's review checklist without being
re-derived from scratch.

The `signer` field is the §5.4 R11 (b) signing-actor-split
substrate (closed in segment 2b): spend material lives in a
single component (`LocalSigner` / `SigningActor`) whose sole job
is signing; `LocalPendingTx` / `PendingTxActor` constructs
transaction bytes and delegates signing via a narrow `Signer`
trait surface (Stage 1) / mailbox surface (Stage 4). HW-wallet
integration in V3.x is a `Signer`-impl substitution
(`HardwareSigner`) against the same boundary; no architectural
change.

**Stage 4 multi-step submit + deferred-reply substrate
(segment-2i G4 pin).** Under Stage 4, the `submit` trait
method's invocation routes through `ActorRef::ask`-equivalent
to `PendingTxActor`'s mailbox. The handler MUST decompose
into a three-step self-continuation pattern to preserve
mailbox-FIFO concurrency under HW-wallet signing latency
(5–30s for user confirmation, per G4 substrate). The
single-step shape would block the actor's main loop on the
signing round-trip, serializing multisig coordination /
batch operations / concurrent build flows behind a single
user tap. The multi-step shape:

1. **`submit_start` handler.** Receives the `Submit { rid,
   reservation }` message from the caller; performs P7-atomic
   `consumer_held → in_flight` collection move (lock claim
   already happened at `build`; the move just transfers
   metadata-ownership); dispatches the signing request to
   `SigningActor` via `ActorRef::tell` (fire-and-forget;
   `SigningActor` replies via self-message back to
   `PendingTxActor`); **defers the caller's reply** until
   step 3.

2. **`submit_signed` handler.** Self-message from
   `SigningActor` arrives carrying signed-tx bytes (or a
   signing error); the actor dispatches the submit to
   `DaemonEngine` via `ActorRef::tell`; **continues to
   defer the caller's reply** until step 3. (On signing
   error, the deferred reply resolves immediately with
   `SubmitError::SignerFailed`; the rid moves from
   `in_flight` back to either `consumer_held` or terminal
   depending on the signer-error's retry-class — pinned
   in Phase 1 against the `Signer::Error` taxonomy.)

3. **`submit_completed` handler.** Self-message from
   `DaemonEngine` arrives carrying the resolution
   (Accepted / TerminalErrorKind / AmbiguousErrorKind); the
   actor applies the P4 collection-moves table (drop from
   `in_flight`, drop matching `output_locks` entries for
   terminal outcomes; keep both for AmbiguousErrorKind per
   F2 daemon-side-authority) and the corresponding sink
   emission (`SubmitSucceeded` / `Discarded
   DaemonRejectedTerminal` / `SubmitPendingResolution`);
   **resolves the deferred caller reply** with the
   appropriate `Result<TxHash, SubmitError>`.

P7's handler-atomicity discipline holds within each handler
step. The submit operation as a whole is non-atomic by
design — the signing-latency window is absorbed in the gap
between (1) and (2); the daemon-round-trip window is
absorbed in the gap between (2) and (3); during both gaps,
`PendingTxActor`'s mailbox processes other messages
(`Build` on different inputs, `Discard` on other rids,
`SnapshotMerged` from `LedgerDiagnostic`, `Submit` on other
reservations entering their own multi-step sequences,
`signal_mempool_evicted` per Phase 0m).

**Deferred-reply substrate-confirmation pin
(segment-2i G4 pin; pre-flight obligation for the Stage 4
actor-migration PR).** The multi-step shape requires the
Stage 4 actor framework to support **deferred-reply
semantics**: a handler accepts a request-shaped message,
captures the reply-context, dispatches one or more
self-continuations, processes other mailbox messages
during the wait, and resolves the captured reply-context
on a later self-message arrival. The canonical
implementation in `kameo` is
`Context::reply_later() -> DelegatedReply` (or
equivalent); other Rust actor frameworks (`actix`,
`ractor`, `xtra`) have their own surface for the same
semantic.

The Stage 4 actor-migration PR's framework-selection
pre-flight MUST confirm substrate support before adopting
any framework. If no candidate-set framework supports
deferred-reply, G4's disposition reopens at the
framework-selection altitude with two named alternatives:
(a) trait-surface revision — `submit` returns a handle
(e.g., `Result<SubmitHandle, SubmitError>` where
`SubmitHandle: Future<Output = Result<TxHash,
SubmitError>>`) and consumers await it separately,
admitting trait-surface non-symmetry between Stage 1
(synchronous) and Stage 4 (handle-returning); (b)
framework-pattern revision — spawn an ephemeral per-submit
actor that holds the reply context and the three-step
state machine internally, leaving `PendingTxActor`'s main
mailbox responsive at the cost of additive actor
provisioning per submit. (b) is the actor-pattern-honest
fallback; (a) is the trait-surface-honest fallback. The
reopen lands at the Stage 4 actor-migration PR's
design-rounds altitude, NOT retroactively against PR 5;
PR 5's V3.0 trait surface stays synchronous
(`fn submit(&self, ...) -> Result<TxHash, SubmitError>`)
regardless.

**Why the pre-flight pin is load-bearing now.** Phase 1
implementation in PR 5 doesn't land Stage 4; the
framework-selection gap wouldn't surface in Phase 1
review. By naming the substrate-confirmation pin now, the
Stage 4 actor-migration PR's design rounds inherit the
obligation as a known pre-flight item rather than
discovering it mid-Phase-1 implementation and triggering
the cost-benefit-defer-to-later anti-pattern at the
framework-selection altitude. Per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
naming the load-bearing question at the design altitude
where the answer is cheap, not at the implementation
altitude where the answer is expensive.

**Stage 1 single-step submit retained.** Under Stage 1,
`LocalPendingTx::submit` runs synchronously within the
caller's thread holding the `Mutex<PendingTxState>` guard
for the lock-claim and collection-move steps; the
synchronous `Signer::sign` call (Phase 0h) and the
synchronous `DaemonEngine::submit` call happen with the
guard released between them (per P7's handler-atomicity
discipline — the mutation steps that touch state are
atomic; the async-flavored cross-component calls are
not). Stage 1's lock-based serialization absorbs the
signing-latency cost as caller-blocking — exactly the
desired behavior in the in-process single-thread CLI
case (which is the Stage 1 deployment target per the
PR-2 / PR-3 / PR-4 precedent).

#### §5.0.2 The diagnostic-stream seam for `PendingTxEngine`

Parallel to PR 4's `RefreshDiagnostic`, PR 5 defines its own
event surface. The seam shape is identical; the events differ:

```rust
// Segment-2h variant set (replaces segment-2g segment-2f baseline).
// See §5.6.4 for the reshape substrate.
// Segment-2i amendments: SubmitPendingResolution gains tx_hash
// projection; DiscardReason::MempoolEvicted variant added. See
// §5.6.10 G1 for the substrate rationale.

#[non_exhaustive]
pub enum PendingTxDiagnostic {
    BuildAttempted { request_summary: BuildRequestSummary },
    BuildSucceeded {
        reservation_id: ReservationId,
        snapshot_id: SnapshotId,
        outputs_count: u32,
    },
    BuildFailed { kind: BuildErrorKind },
    SubmitAttempted { reservation_id: ReservationId },
    // tx_hash: TxHash field is segment-2i-added per G1 — required
    // by the V3.x MempoolMonitorActor consumer to subscribe and
    // map daemon-mempool query results back to rids. Hash is
    // on-chain by construction (not secret material); field-level
    // projection is admissible at the recursive-trust-boundary
    // discipline per PR 4 §5.4.8 #4.
    SubmitSucceeded { reservation_id: ReservationId, tx_hash: TxHash },
    // SubmitPendingResolution: ambiguous daemon outcome; reservation
    // stays in in_flight; consumer learns at SubmitCompleted arrival
    // or via R8 TTL safety-net (segment-2h F2 / P4 disposition).
    // Segment-2i adds tx_hash projection per G1 — same rationale
    // as SubmitSucceeded; the V3.x MempoolMonitorActor needs to
    // observe ambiguous-outcome submissions too (DaemonTimeout
    // cases may resolve via the daemon's eventual response OR
    // via mempool-presence-disappears observation).
    SubmitPendingResolution {
        reservation_id: ReservationId,
        tx_hash: TxHash,
        kind: AmbiguousErrorKind,
    },
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
    // SubmitFailed REMOVED in segment 2h — no surviving emission site
    // under the P4 collection-moves table (terminal errors emit via
    // Discarded { DaemonRejectedTerminal { kind } }; ambiguous
    // errors emit via SubmitPendingResolution). The lifecycle-class
    // distinction is load-bearing on the emission side, parallel to
    // the type-correctness motivation for splitting SubmitErrorKind
    // on the error-return side.
}

#[non_exhaustive]
pub enum DiscardReason {
    ConsumerExplicit,
    DaemonRejectedTerminal { kind: TerminalErrorKind },  // R9 disposition
    TTLAutoDiscard,                // R8 segment-2e variant (V3.x emitter:
                                   // ReservationTTLActor; no V3.0 emitter)
    // MempoolEvicted: segment-2i-added per G1 — terminal-resolution
    // for reservations whose tx has been observed evicted from the
    // daemon's mempool. Emitted by the new
    // PendingTxEngine::signal_mempool_evicted handler (Phase 0m)
    // after F2-adjudicated entry check (rid must be in in_flight)
    // and collection-move + lock-release. V3.0 has no in-process
    // emitter (no MempoolMonitorActor at V3.0); V3.x consumer-
    // actor PR introduces the emitter per the FOLLOWUPS entry.
    // Pre-V3.x test fixtures hand-roll the call to exercise the
    // trait method + handler body.
    MempoolEvicted,
    // SnapshotRotationAutoDiscard REMOVED in segment 2h — lazy R5
    // preservation per §5.6.5 F5+F6 / §5.6.6 P9. Snapshot rotation
    // drives no automatic collection moves at V3.0; consumer learns
    // at submit-time via SubmitError::SnapshotInvalidated. V3.x
    // eager-discard opt-in (§5.6.7 P9 trigger) reintroduces the
    // variant alongside selective-discard substrate; the V3.x
    // emitter is the eager-discard handler keyed off SnapshotMerged.
}

// R9 segment-2h closure: SubmitError reshape + TerminalErrorKind /
// AmbiguousErrorKind split. Returned from `submit(reservation_id)`
// per the trait surface.

#[non_exhaustive]
pub enum TerminalErrorKind {
    DoubleSpend,   // R9: terminal; outputs genuinely gone
    FeeTooLow,     // R9: outputs released to pool; consumer rebuilds
    Malformed,     // R9: outputs released; bug surfaces diagnostically
}

#[non_exhaustive]
pub enum AmbiguousErrorKind {
    DaemonTimeout,      // R9 Finding 2: ambiguous; reservation stays
                        // in in_flight (daemon-side authority);
                        // consumer-explicit discard blocked per F2
                        // ownership-boundary; R8 TTL is the safety net
    DaemonUnavailable,  // R9 Finding 2: ambiguous; same disposition
                        // as DaemonTimeout
}

#[non_exhaustive]
pub enum SubmitError {
    // R5: pre-daemon staleness check failed (segment-2h lazy R5;
    // reservation does NOT auto-release; consumer must call
    // discard(rid, ConsumerExplicit) to release output_locks).
    SnapshotInvalidated {
        reservation_snapshot: SnapshotId,
        current_snapshot: SnapshotId,
    },
    // R9: daemon round-trip completed with a terminal error; rid
    // dropped from in_flight; output_locks released; consumer's
    // recourse is to rebuild against the current snapshot.
    DaemonRejectedTerminal { kind: TerminalErrorKind },
    // R9: daemon round-trip completed with an ambiguous error; rid
    // stays in in_flight; output_locks retained until consumer-
    // explicit discard (blocked per F2 ownership-boundary, so the
    // path is R8 TTL safety-net) or until daemon resolves.
    DaemonAmbiguous {
        kind: AmbiguousErrorKind,
        reservation_id: ReservationId,
    },
    // P3: rid not in consumer_held ∧ not in in_flight at submit
    // entry; never existed or already resolved.
    ReservationNotFound { reservation_id: ReservationId },
    // P2: rid found in in_flight at submit entry; second-submit
    // attempt on a reservation whose first submit is daemon-
    // pending.
    SubmitAlreadyPending { reservation_id: ReservationId },
}

// PendingTxError: build-side + non-submit-side error taxonomy.
// (Submit returns SubmitError; build / discard return
// PendingTxError.)

#[non_exhaustive]
pub enum PendingTxError {
    // ... build-side variants (BuildErrorKind family; unchanged from
    // segment 2g) ...
    // F2: consumer-initiated discard on a reservation in in_flight.
    DiscardBlockedPendingDaemonAck { reservation_id: ReservationId },
    // P2 mirror on the discard-side: rid in in_flight; discard
    // blocked.
    SubmitAlreadyPending { reservation_id: ReservationId },
    // P3: rid not in consumer_held ∧ not in in_flight at discard
    // entry; never existed or already resolved.
    ReservationNotFound { reservation_id: ReservationId },
}
```

**Concurrent-submit / discard-error handler shape (segment-2h
P2 / P3 cleanup; the prior P2 sketch placed an `unreachable!`
on `(false, true)`, which is the discard-success path, not
unreachable).** The submit-error-discriminating switch covers
three error cases, not four — the success path returns
`Ok(...)` before the switch runs:

```rust
// inside fn submit handler — error-discriminating switch
match (state.consumer_held.contains_key(&rid),
       state.in_flight.contains_key(&rid)) {
    (false, false) => SubmitError::ReservationNotFound { reservation_id: rid },
    (false, true)  => SubmitError::SubmitAlreadyPending { reservation_id: rid },
    (true,  true)  => unreachable!("invariant: rid is in at most one of \
                                    consumer_held / in_flight"),
    // (true, false) is the success path; consumer_held → in_flight
    // move runs before this switch is reached.
}

// inside fn discard handler — error-discriminating switch
match (state.consumer_held.contains_key(&rid),
       state.in_flight.contains_key(&rid)) {
    (false, false) => PendingTxError::ReservationNotFound { reservation_id: rid },
    (false, true)  => PendingTxError::DiscardBlockedPendingDaemonAck {
        reservation_id: rid,
    },
    (true,  true)  => unreachable!("invariant: rid is in at most one of \
                                    consumer_held / in_flight"),
    // (true, false) is the success path; consumer_held → (gone) +
    // output_locks release runs before this switch is reached.
}
```

##### §5.0.2.1 Sink-binding closure (segment 2f; Finding 4)

The trait surface adds an `Arc<dyn DiagnosticSink>` parameter
to `LocalPendingTx::new` — **constructor-bound, closed in
segment 2f**. The constructor-vs-per-method question is the
prior adversarial-review Finding 4 from
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)'s
post-R1-closure pass; R11's segment-2b closure (as (b) —
separate `LocalSigner` / `SigningActor`) makes the sink-binding
question independent of the spend-material disposition, so the
two close separately. Segment 2f closes the constructor-vs-per-
method shape as **constructor-bound** under PR 4
§3.4.5 / R4 (a) consistency.

**Why constructor-bound, not per-method.**

1. **Engine-identity coupling.** The sink is part of the
   engine instance's identity — one `LocalPendingTx` /
   `PendingTxActor` per wallet session, one
   `DiagnosticSink` consumer per engine. Constructor-binding
   makes this 1-to-1 mapping load-bearing at the type level;
   per-method dispatch admits arbitrary consumer plumbing
   that obscures the mapping.
2. **Stage 4 actor wiring alignment.** Stage 4's
   `PendingTxActor` is spawned with its `DiagnosticSink`
   consumer at spawn time (spawn-time DI); per-method
   dispatch in Stage 1 would create a Stage-1-vs-Stage-4
   shape mismatch that the actor-migration would have to
   bridge. Constructor-binding aligns the two stages by
   construction.
3. **Call-site cleanliness.** Per-method dispatch requires
   every consumer call site (`build`, `submit`, `discard`,
   `outstanding`) to thread the sink through; constructor-
   binding scopes the sink to the engine's internals where
   the emission discipline lives.
4. **Runtime-swap surface preserved.** Constructor-binding
   does not foreclose runtime sink swapping — consumers that
   need to swap sinks construct a new engine instance (or
   wrap the sink in a runtime-swappable indirection that the
   engine sees as a single `Arc<dyn DiagnosticSink>`). The
   per-method-dispatch argument relied on this concern; the
   indirection-at-the-sink shape covers it without admitting
   per-method coupling.
5. **No load-bearing reason for per-method override.** A
   per-method override pattern is the right shape when
   different call sites observe different consumer surfaces
   (e.g., a "build" debugger that doesn't see "submit"
   events) — but this is a debugging-tooling shape, not a
   production-engine shape. For production, one sink per
   engine instance is the load-bearing pattern; debugging
   tooling implements its own indirection.

**Disposition (closed in segment 2f).** Stage 1's
`LocalPendingTx::new` takes `sink: Arc<dyn DiagnosticSink>` as
a constructor parameter; the engine carries it as a field and
emits through it from internal call sites. R11's `signer:
Arc<S>` field and `sink: Arc<dyn DiagnosticSink>` field are
**both** constructor-bound; the two are independent. Stage 4's
`PendingTxActor` mirrors the shape at spawn time per the actor
DI pattern.

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
- **Per-emitter FIFO ordering (PR 4 Round 4 review pass F4,
  2026-05-15; F12 enforcement-gap amendment, 2026-05-15).**
  Events emitted by a single emitter (one
  `LocalRefresh` instance, one `LocalPendingTx` instance)
  arrive at the sink in emission order; cross-emitter
  ordering is undefined. Implementations satisfy the
  per-emitter half by construction (single-thread emission
  per engine instance plus FIFO queue or mailbox); the
  cross-emitter half is explicitly undefined so consumer
  actors do not rely on cross-emitter temporal context.
  Pinned here to bind PR 5's `PendingTxDiagnostic` stream
  symmetrically with PR 4's `RefreshDiagnostic` stream;
  see PR 4 §5.4.6 / §5.4.9 F4 for the full disposition
  reasoning. **Enforcement-gap amendment (F12, 2026-05-15;
  symmetric with PR 4 §5.4.6 amendment).** The cross-
  emitter-undefined half is procedurally enforced, not
  type-system enforced — a V3.x consumer-actor author
  who depends on cross-emitter arrival order writes code
  that compiles cleanly and passes per-emitter FIFO tests,
  then deadlocks or misbehaves under reordering at audit.
  The discipline that closes the gap: **consumer actors
  that need cross-emitter ordering MUST derive it from
  explicit causal-context fields carried inside the
  events themselves** — `SnapshotId` for ledger-rooted
  ordering (also load-bearing for PR 5's reservation-
  pinning per §5.0); `ReservationId` plus per-reservation
  monotone version counters for reservation-rooted
  ordering; `BlockHeight` for chain-rooted ordering. Sink-
  observed arrival order is *not* a causal-context source
  under the contract. The V3.x consumer-actor PR
  template's CI-lint deliverable (FOLLOWUPS F5 entry,
  scope-extended by F12) covers attempted cross-emitter-
  ordering reliance: the lint flags consumer-actor code
  that branches on the relative timing of events from
  distinct emitters without first constraining ordering
  via a causal-context field. See PR 4 §5.4.8 #4 V3.x
  forward-template item 4 for the lint's full scope.
- **Temporal- and distributional-projection discipline
  (segment 2h F5+F6 pin).** Field projection per
  PR 4 §5.4.8 #4 (recursive trust boundary) bounds *which
  fields* cross-boundary consumers observe, but doesn't
  bound *when events fire* or *what their long-run
  frequency distribution is*. Both surfaces fingerprint the
  producing wallet independently of any field elision:
  stable submit-attempted-to-submit-succeeded latencies are
  consumer-attributable broadcast-timing on the wallet side
  (complementing the V3.x `SubmissionStrategyActor`'s on-
  network jitter); long-run `DiscardReason` distributions
  fingerprint wallet behavior (frequent `TTLAutoDiscard` ⇒
  build-without-submit pattern possibly indicating multisig
  coordination; frequent `DaemonRejectedTerminal {
  DoubleSpend }` ⇒ decoy-resimulation pattern). **V3.0
  disposition.** The diagnostic surface ships **field-
  projection only** at V3.0; temporal smoothing (event
  coalescing, bucketed emission, strategy-aligned emission
  delays) and distributional smoothing (aggregated
  `Discarded` counts over windows, suppressing per-event
  emission for the noisy-distribution `DiscardReason`
  variants) are out of scope for V3.0. The disposition is
  named here so V3.0 reviewers do not mistake the omission
  for an oversight; the F5+F6 reopening criteria are
  documented in §5.6.5 F5+F6 and the V3.x
  `DIAGNOSTIC_STREAM.md` introduction PR inherits the
  temporal/distributional smoothing question as a design-
  rounds item.

**Generalization question (closed in Round 2 segment 2g
as (a) — rename to `DIAGNOSTIC_STREAM.md`).** PR 4's
FOLLOWUPS named `docs/design/REFRESH_DIAGNOSTIC_STREAM.md`
as the spec doc; the contracts are used by both PR 4 and
PR 5. Two options were evaluated:

- **(a) Rename to `DIAGNOSTIC_STREAM.md` (general).** Single
  doc; shared `DiagnosticSink` contracts live at the top;
  per-stream sections (`RefreshDiagnostic` from PR 4,
  `PendingTxDiagnostic` from PR 5, `LedgerDiagnostic`
  pending the Phase 0g consumer PR) document the variant
  taxonomy and emission-site discipline for each stream.
  V3.x consumer-actor design rounds extend the per-stream
  sections additively.
- **(b) Factor a parent `DIAGNOSTIC_STREAM_CONTRACTS.md`
  that per-stream docs inherit from.** Parent doc carries
  the shared contracts; per-stream docs reference the
  parent and document only the per-stream taxonomy.
  Stronger separation of concerns; more cross-references
  to maintain.

**Closes as (a)** — rename to `DIAGNOSTIC_STREAM.md`
(general). Rationale: the spec doc is a V3.x deferred
deliverable (no V3.0 PR introduces it; per the FOLLOWUPS
entry's "Trigger: when the first V3.x consumer actor enters
design rounds"). At V3.x introduction time, the contracts
shared between streams are already enumerated and modest in
volume (six bullets per §5.0.3); the per-stream taxonomies
are larger volume. A single doc with shared-then-per-stream
structure carries the substrate at lower cross-reference
cost than (b)'s parent-and-children factoring. The
factoring discipline can be applied retroactively if the
single doc grows beyond the threshold where a parent doc
adds clarity rather than friction; segment-2g closes the
question with (a) as the V3.x introduction shape.

**Segment-2g actions.**

- The FOLLOWUPS entry titled "Diagnostic-stream
  specification document
  (`docs/design/REFRESH_DIAGNOSTIC_STREAM.md`, V3.x)" is
  amended in segment-2g to rename the planned doc to
  `docs/design/DIAGNOSTIC_STREAM.md`. The doc itself does
  not yet exist; only the planned name changes.
- The trigger remains "when the first V3.x consumer actor
  enters design rounds"; the V3.x introduction PR creates
  the doc with shared-then-per-stream structure.

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
          // Domain-separated Keccak-256 over deterministic
          // fields, truncated to 16 bytes. The primitive
          // (`shekyl_crypto_hash::cn_fast_hash`) is the
          // engine-core's audited Keccak construction;
          // 128-bit truncation is sufficient because
          // `SnapshotId` is an equality token over a
          // bounded snapshot population (one snapshot per
          // refresh merge; ≪ 2⁴⁰ over wallet lifetime)
          // rather than a collision-resistance primitive
          // against arbitrary adversarial inputs.
          let mut buf = Vec::new();
          buf.extend_from_slice(SHEKYL_SNAPSHOT_ID_DOMAIN_SEP);
          buf.extend_from_slice(&snapshot.synced_height.to_le_bytes());
          buf.extend_from_slice(snapshot.reorg_blocks.canonical_bytes());
          let digest = shekyl_crypto_hash::cn_fast_hash(&buf);
          let mut id = [0u8; 16];
          id.copy_from_slice(&digest[..16]);
          SnapshotId(id)
      }
  }
  ```

  The hash primitive is pinned at Phase 0 review (segment 2g
  per §4 Phase 0b binding; revised in Copilot-fix follow-up
  for dependency-discipline correctness) as
  `shekyl_crypto_hash::cn_fast_hash` (Keccak-256, original
  padding) — `shekyl-crypto-hash` is an unconditional
  `[dependencies]` entry in `shekyl-engine-core` per
  [`rust/shekyl-engine-core/Cargo.toml`](../../rust/shekyl-engine-core/Cargo.toml)
  line 28; the segment-2d disposition is the **shape**
  (16-byte content-addressed digest), and segment-2g pins
  the **primitive** (Keccak-256 with 128-bit truncation).
  Truncation to 128 bits is sufficient because `SnapshotId`
  is a wallet-internal equality token over a bounded
  snapshot population — see §4 Phase 0b for the full
  bounded-population security framing.

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
  digest cost (one `cn_fast_hash` call per snapshot merge;
  one comparison per `submit` handler invocation) is
  bounded; the height-bearing simplification is not worth
  the privacy cost.

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
  `DIAGNOSTIC_STREAM.md` (segment-2g closure of the
  generalization question selected option (a) — rename
  `REFRESH_DIAGNOSTIC_STREAM.md` → `DIAGNOSTIC_STREAM.md`).
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
  (closed in Round 2 segment 2e as **lazy auto-discard**, with
  consumer-explicit discard required to release `output_locks`;
  reopen-and-close in Round 2 segment 2h preserves the lazy
  disposition under the (γ) lean state shape — see §5.6.5 F5+F6
  and §5.6.6 P9 for the preservation substrate).** Under
  §5.0, this is the `SnapshotMerged` event handler — a policy
  decision **local to the actor**, not a trait-surface
  question. The three sub-options ((a) eager auto-discard on
  snapshot rotation; (b) lazy auto-discard at next submit per
  (1)'s field-comparison; (c) explicit consumer-driven
  discard) become implementation choices the actor makes; the
  trait contract just specifies that `outstanding()` reflects
  whichever policy is in effect.

  **Segment 2h preservation (closes the segment-2h R5 reopen
  for lazy-vs-eager).** The original segment-2e closure as
  **lazy auto-discard** stands under the lean state shape:
  staleness is detected at submit-time field comparison and
  surfaced via `SubmitError::SnapshotInvalidated` (with rich
  `reservation_snapshot` / `current_snapshot` context); the
  consumer's `discard(rid, ConsumerExplicit)` releases the
  reservation's `output_locks` after they receive the error;
  R8 TTL is the safety-net for consumer abandonment. The
  P9 mechanism rewrite under (γ) preserves lazy semantics:
  the consumer-explicit discard's collection operations drop
  the rid from `consumer_held` and release the matching
  `output_locks` entries — no `ReservationState` field is
  set; collection-membership is the lifecycle encoding.
  `DiscardReason::SnapshotRotationAutoDiscard` is **removed**
  from the V3.0 surface (no V3.0 emitter under lazy); V3.x
  eager-discard opt-in (FOLLOWUPS §5.6.7 P9 trigger)
  reintroduces the variant alongside the selective-discard
  substrate (`ConsumerHeldEntry { created_at, snapshot_id }`
  expansion).

  **Lazy-vs-eager substrate (preserved from segment-2e wargaming).**
  Eager auto-discard releases `output_locks` proactively
  (faster availability for next build) but is hostile to
  consumer UX under fast snapshot rotation — on a sync-rate
  chain rotating snapshots every ~30s, a consumer who calls
  `build` and takes 60s to confirm submit loses their
  reservation mid-decision; their eventual submit returns
  `SubmitError::ReservationNotFound` (less context-rich than
  `SnapshotInvalidated`). Eager also requires the
  `consumer_held` entry to carry `snapshot_id` so the actor
  can filter "discard only entries built against prior
  snapshots" — otherwise eager becomes sweeping (discard
  everything on every `SnapshotMerged`, which is the
  operationally-hostile extreme). The V3.0 `consumer_held:
  HashMap<ReservationId, Instant>` shape doesn't admit
  selective eager discard; the V3.x eager-discard opt-in
  requires a substrate refinement to
  `HashMap<ReservationId, ConsumerHeldEntry { created_at,
  snapshot_id }>` per the FOLLOWUPS reopening criteria.
  Lazy holds `output_locks` longer (R8 TTL safety-net) but
  preserves consumer reservation lifetime across snapshot
  rotations; consumer gets rich error context when they
  eventually submit; cleanup-on-use semantics rather than
  cleanup-on-event. **Lazy is the V3.0 disposition;** eager
  V3.x opt-in is the named reopening clause.

  **Segment-2i scope-extension named-and-rejected (G2 long-range-
  reorg of confirmed txs).** R5 scope covers reservations *while
  they remain claims on output_locks* — `consumer_held` and
  `in_flight` membership. The G2 case is a tx that previously
  hit `SubmitSucceeded` and confirmed, then got reorged out at
  depth: by then the rid is gone from `consumer_held` /
  `in_flight` per P4 collection-moves; the outputs come back
  as unspent in `LedgerEngine`'s candidate set on the surviving
  chain; the next build sees them as available; no double-spend
  risk; the only rough edge is the consumer-visible UI
  ("confirmed → unconfirmed → re-confirmed"). The proposed (c)
  alternative — `PendingTxActor` emits a
  `PendingTxDiagnostic::TxReorgedOut { rid, tx_hash }`
  diagnostic — would require retaining the rid → tx_hash
  mapping past terminal resolution, exactly the state-bloat
  the (γ) lean shape was designed to forbid. **G2 is rejected
  as PendingTxEngine-domain** per the architectural-integrity-
  now disposition. The right disposition is **LedgerDiagnostic-
  domain**: the V3.x `LedgerDiagnostic::TxReorgedOut {
  tx_hash, prior_block_height }` variant lands additively per
  Phase 0g's deferred-to-consumer-PR pattern (parallel to
  `SnapshotMerged`); V3.0 ships with the consensus-correct
  behavior plus the V3.0-accepted UX-roughness surface pin
  parallel to F8's restart-during-`in_flight` acceptance.
  Full disposition in §5.6.10 G2; the
  `LedgerDiagnostic::TxReorgedOut` forward-template is
  FOLLOWUPS'd against the eventual `LedgerEngine`-side
  diagnostic-stream PR. **R5's V3.0 PendingTxEngine surface
  is unchanged by G2.**

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
  V3.x lands the actor; refined in Round 2 segment 2h via
  Phase 0l `ReservationTTLConfig` and the (γ) lean state shape
  — see §5.6.5 F7).** What happens to reservations that
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
  subscribes to **both reservation-creation events and
  reservation-terminal events** on the `PendingTxDiagnostic`
  stream, maintains in-memory per-reservation age tracking,
  emits `PendingTxDiagnostic::ReservationOutstanding {
  reservation_id, age }` warnings on stale reservations,
  signals `PendingTxActor` (via `AutoDiscardMessage {
  reservation_id }` mailbox message) to auto-discard if TTL
  policy permits. Same shape as PR 4's
  `PeerReputationActor` / `RecoveryActor` consumer-actor
  pattern. The trait surface stays minimal; the capability
  composes.

  **Subscription contract (segment-2e closure; refined in
  Copilot-fix follow-up).** The actor's diagnostic-stream
  subscription is **not** `BuildSucceeded`-only — that
  shape would leak closed reservations into the actor's
  in-memory map forever, producing stale
  `ReservationOutstanding` warnings on already-terminated
  reservations and spurious `AutoDiscardMessage` round-trips
  to `PendingTxActor`. The complete subscription contract:

  - **`PendingTxDiagnostic::BuildSucceeded { reservation_id,
    snapshot_id, outputs_count }`** — insert
    `{reservation_id → started_at: Instant::now()}` into
    the in-memory age-tracking map. Transition: "tracking
    started."
  - **`PendingTxDiagnostic::SubmitSucceeded { reservation_id,
    tx_hash }`** — remove `reservation_id` from the
    age-tracking map. Transition: "terminal — reservation
    consumed by submit."
  - **`PendingTxDiagnostic::Discarded { reservation_id,
    reason }`** — remove `reservation_id` from the
    age-tracking map regardless of `reason`. Under segment-2h
    the surviving `DiscardReason` variants are
    `ConsumerExplicit` (consumer called `discard`, including
    the explicit-discard-after-`SnapshotInvalidated` path R5
    requires under lazy semantics), `DaemonRejectedTerminal {
    kind: TerminalErrorKind }` (R9 terminal rejection per
    segment-2h's collection-moves table), and `TTLAutoDiscard`
    (the actor's own auto-discard fires; self-cleanup).
    `SnapshotRotationAutoDiscard` is removed under lazy R5;
    no V3.0 emitter. Transition: "terminal — reservation
    released."

  **What `SubmitPendingResolution` does *not* close (segment
  2h reshape).** Per the segment-2h collection-moves table
  (§5.6.4 P4), `SubmitPendingResolution { reservation_id,
  kind: AmbiguousErrorKind }` is emitted on daemon timeout /
  unavailable where the reservation stays in the actor's
  `in_flight` collection (Finding 2 daemon-side authority).
  The TTL actor **does not** remove the reservation from its
  tracking map on `SubmitPendingResolution`; the reservation
  is still output-locking and still ages. The terminal
  cleanup happens only on `SubmitSucceeded` or `Discarded`
  per the contract above. **Per-collection TTL pin
  (segment-2h F7 disposition; closes the prior "Optional
  V3.x refinement" with a binding V3.0 surface).** The
  V3.0 surface is the Phase 0l
  `ReservationTTLConfig { consumer_held: Duration, in_flight:
  Duration }` constructor parameter on `LocalPendingTx`.
  The two collections age on independent clocks; V3.x's
  `ReservationTTLActor` reads the config and applies per-
  collection aging policy without trait revision. Whether
  `in_flight` aging is age-from-`InFlightSubmit::created_at`
  or age-from-`InFlightSubmit::submitted_at` is a V3.x
  consumer-actor policy choice; the `InFlightSubmit` struct
  carries both fields per the segment-2h P5 disposition so
  either policy is admissible without struct revision.

  **Memory-bound property.** With the full subscription
  contract above, the actor's age-tracking map is bounded
  by the count of currently-outstanding reservations (i.e.,
  `PendingTxActor::outstanding()`'s return value), not by
  the cumulative count of all reservations the wallet has
  ever created. Per PR 4 §5.4.8 #5 (bounded mailbox)
  applied to the actor's internal state, the map is
  monotonically bounded by the wallet's actual reservation
  rate, with terminal events providing the cleanup signal.

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
  2. **`PendingTxDiagnostic::SubmitSnapshotInvalidated {
     reservation_id, reservation_snapshot, current_snapshot }`**
     — emitted at `submit`'s snapshot-mismatch path (R5's
     lazy-discard semantics; segment-2h preservation) when
     the field-comparison handler detects a stale reservation.
     Under segment-2h lazy R5, the reservation does **not**
     auto-release on this event; the consumer's explicit
     `discard(rid, ConsumerExplicit)` after receiving
     `SubmitError::SnapshotInvalidated` is what triggers the
     `Discarded { ConsumerExplicit }` emission that the TTL
     actor uses to drop the reservation from its tracking
     map. (The prior segment-2e V3.0 deliverable shape that
     emitted `Discarded { SnapshotRotationAutoDiscard }` at
     this site is dropped under segment-2h; V3.x eager-
     discard opt-in per §5.6.7 P9 reintroduces the variant.)
  3. **`PendingTxDiagnostic::ReservationOutstanding {
     reservation_id, age }` variant exists in the
     `#[non_exhaustive]` enum** but is **not emitted in V3.0**
     — `ReservationTTLActor` is the only intended emitter, and
     it lands in V3.x. The variant existing pre-V3.0 means
     V3.x's `ReservationTTLActor` introduction does not require
     a `PendingTxDiagnostic` enum revision; per PR 4 §5.4.8
     "Cross-cutting: variant ordering and serialization
     (forward-note)" the `#[non_exhaustive]` additive-evolution
     discipline makes the emission-introduction additive at the
     consumer side.
  4. **`DiscardReason::TTLAutoDiscard` variant pin (segment 2e
     addition; segment 2h preserves; the `DaemonRejectedTerminal`
     variant grows a `{ kind: TerminalErrorKind }` payload per
     §5.6.4).** The segment-2h `#[non_exhaustive] enum
     DiscardReason` set is `ConsumerExplicit`,
     `DaemonRejectedTerminal { kind: TerminalErrorKind }`, and
     `TTLAutoDiscard`. The segment-2e `SnapshotRotationAutoDiscard`
     variant is removed under lazy R5; V3.x eager-discard opt-in
     reintroduces it. V3.x's `ReservationTTLActor` can trigger
     `PendingTxActor` to emit `Discarded { reason:
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

  **R5 ↔ R8 coherence (segment 2e verification; segment 2h
  refinement).** R5's lazy disposition at submit time
  (`SubmitError::SnapshotInvalidated`) is the **diagnostic-
  emission point**; the consumer's `discard(rid,
  ConsumerExplicit)` after receiving the error is the
  **reactive cleanup path** — reservations against rotated
  snapshots get cleaned up when the consumer acknowledges
  the staleness explicitly. R8's `ReservationTTLActor` is
  the **proactive** complement — reservations that *never
  get used at all* (idle wallet; consumer crash; build-but-
  never-submit bug) get cleaned up by per-collection age-
  based policy via the Phase 0l `ReservationTTLConfig`. The
  two are architecturally distinct (R5 lives in
  `LocalPendingTx::submit` / `PendingTxActor`'s submit
  handler; R8 lives in a separate consumer actor) but use
  the same `DiscardReason`/`Discarded` event infrastructure.
  R5 emits `SubmitError::SnapshotInvalidated`; the consumer's
  follow-up `discard` emits `Discarded { ConsumerExplicit }`;
  R8 emits (via `AutoDiscardMessage` round-trip to
  `PendingTxActor`) `Discarded { TTLAutoDiscard }`.
  Downstream consumers see a unified `Discarded` event
  stream with discriminated reasons.

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
  (closed in Round 2 segment 2f as two-stage submit flow with
  intermediate `SubmitPendingDaemonAck` state; daemon-side
  authority disposition for ambiguous outcomes; per-error-class
  state-transition table pinned; reopen-and-close in Round 2
  segment 2h refines the disposition under the (γ) lean state
  shape — collection-moves table replaces the
  `ReservationState` state-transition table; the
  `TerminalErrorKind` / `AmbiguousErrorKind` split replaces
  the unified `SubmitErrorKind`; `PendingTxDiagnostic::SubmitFailed`
  is removed; `PendingTxDiagnostic::SubmitPendingResolution`
  is added. See §5.6.3 collection-moves discipline, §5.6.4
  reshape substrate, and §5.6.5 F1 / F2 dispositions.** R4 covers the
  staleness-fails case (snapshot-invalidated → auto-release →
  rebuild). It does **not** cover the staleness-passes-but-
  daemon-rejects case: `submit` consumed the reservation and the
  daemon returned `AlreadyInMempool` / `DoubleSpend` /
  `FeeTooLow` / `Malformed` / timeout / network-error.

  **Reframed flow under §5.0.** `PendingTxActor` receives
  `SubmitMessage`, performs the staleness field-comparison,
  sends `SubmitTxMessage` to `DaemonEngine` actor, awaits the
  reply via the **self-continuation pattern** (`PendingTxActor`
  emits a deferred `SubmitCompleted { id, daemon_result }`
  message to its own mailbox upon daemon reply; the original
  `SubmitMessage` reply is sent then). The reservation state
  during the daemon round-trip is `SubmitPendingDaemonAck` — an
  intermediate state that **must** be explicit in the actor's
  internal state machine (not the trait surface).

  **Three-state internal state machine (closed in segment 2f;
  dissolved in segment 2h under the (γ) lean state shape).**
  The segment-2f closure pinned an explicit internal enum:

  ```rust
  // SEGMENT-2H NOTE: the enum below is the segment-2f closure
  // shape, retained here for traceability. It is DISSOLVED by
  // segment 2h's collection-membership encoding (§5.6.2): the
  // reservation's location across `output_locks`,
  // `consumer_held`, and `in_flight` encodes the lifecycle.
  // No `ReservationState` enum exists in the V3.0 substrate.
  // The variants below map onto collection states as: Active ↔
  // {rid ∈ consumer_held}; SubmitPendingDaemonAck ↔
  // {rid ∈ in_flight}; Resolved ↔ {rid ∉ consumer_held ∧ rid ∉
  // in_flight}.
  enum ReservationState {
      Active,                    // build successful; submit not started
      SubmitPendingDaemonAck,    // submit started; awaiting daemon reply
      Resolved,                  // terminal: succeeded, discarded, or
                                 // released (entry is removed from the
                                 // tracker; the variant is named for
                                 // exposition only)
  }
  ```

  Trait surface unchanged: `outstanding()` counts reservations
  in `Active | SubmitPendingDaemonAck`; resolved reservations
  are removed from the tracker. The state machine is **invisible
  to consumers** except through observing
  `PendingTxDiagnostic::SubmitAttempted` (state entered
  `SubmitPendingDaemonAck`) and `SubmitSucceeded` / `SubmitFailed`
  / `SubmitSnapshotInvalidated` / `Discarded` (state exited to
  `Resolved`). The internal state is not enumerated through
  the trait surface because no consumer use case requires
  externally distinguishing `Active` from
  `SubmitPendingDaemonAck` — `outstanding()`'s aggregate count
  is the load-bearing query.

  **Per-error-class disposition (closed in segment 2f;
  reshaped in segment 2h to collection-moves + `Terminal` /
  `Ambiguous` split per §5.6.4 P4 table; see that section for
  the binding form. The segment-2f text below is retained for
  traceability and reads against the segment-2h collection-
  membership encoding in place of the dissolved
  `ReservationState` enum.).** All daemon responses map to a
  single trait-return + diagnostic-event-sequence + internal
  collection-move tuple. Each bullet below carries (1)
  **trait return**, (2) **diagnostic event sequence**, (3)
  **internal collection move** (segment-2h substitution for
  the segment-2f "state transition" terminology).

  - **`Accepted`** —
    `Ok(SubmitSuccess { tx_hash })`;
    `SubmitAttempted` → `SubmitSucceeded`;
    drop rid from `in_flight`; release matching
    `output_locks` entries.
  - **`AlreadyInMempool`** —
    `Ok(SubmitSuccess { tx_hash })` (idempotent);
    `SubmitAttempted` → `SubmitSucceeded`;
    drop rid from `in_flight`; release matching
    `output_locks` entries.
  - **`DoubleSpend`** —
    `Err(SubmitError::DaemonRejectedTerminal { kind:
    TerminalErrorKind::DoubleSpend })`;
    `SubmitAttempted` → `Discarded { kind:
    TerminalErrorKind::DoubleSpend }`;
    drop rid from `in_flight`; release matching
    `output_locks` entries (output-state subtlety below).
  - **`FeeTooLow`** —
    `Err(SubmitError::DaemonRejectedTerminal { kind:
    TerminalErrorKind::FeeTooLow })`;
    `SubmitAttempted` → `Discarded { kind:
    TerminalErrorKind::FeeTooLow }`;
    drop rid from `in_flight`; release matching
    `output_locks` entries (consumer rebuilds with higher
    fee).
  - **`Malformed`** —
    `Err(SubmitError::DaemonRejectedTerminal { kind:
    TerminalErrorKind::Malformed })`;
    `SubmitAttempted` → `Discarded { kind:
    TerminalErrorKind::Malformed }`
    (+ producer-side `InternalInvariantViolation` if the
    malformation is wallet-attributable);
    drop rid from `in_flight`; release matching
    `output_locks` entries (bug surfaces diagnostically;
    consumer should not auto-retry).
  - **`Timeout`** —
    `Err(SubmitError::DaemonAmbiguous { kind:
    AmbiguousErrorKind::DaemonTimeout, reservation_id })`;
    `SubmitAttempted` → `SubmitPendingResolution { kind:
    AmbiguousErrorKind::DaemonTimeout }`;
    **rid stays in `in_flight`**; `output_locks` retained
    (Finding 2 daemon-side authority).
  - **`Network error`** —
    `Err(SubmitError::DaemonAmbiguous { kind:
    AmbiguousErrorKind::DaemonUnavailable, reservation_id })`;
    `SubmitAttempted` → `SubmitPendingResolution { kind:
    AmbiguousErrorKind::DaemonUnavailable }`;
    **rid stays in `in_flight`**; `output_locks` retained
    (same daemon-side authority disposition as Timeout).

  **DoubleSpend output-state subtlety.** On `DoubleSpend`, the
  outputs are genuinely gone (spent on-chain in some other tx
  the wallet doesn't yet know about). The tracker discards the
  reservation, but the wallet's view of "available outputs" is
  stale until next refresh. Consumers must refresh before
  attempting to spend other outputs that overlap. V3.x
  consumer-actor (`SubmitFailureAnalyzer`) can auto-trigger
  `RefreshActor::request_refresh()` on `DoubleSpend`
  observation; for V3.0, consumer-explicit refresh is the
  disposition.

  **Finding 2 closure — daemon-side authority for ambiguous
  outcomes.** Timeout and `DaemonUnavailable` are the
  load-bearing ambiguity cases: the daemon may have accepted
  the tx (and the response was lost in transit) or rejected
  it (and the rejection was lost) — the wallet cannot
  determine ground truth from its own state. Three options
  were evaluated:

  - **(A) Actor-state authority on timeout.** Treat timeout as
    `Resolved` immediately; release outputs back to pool.
    **Risk:** phantom-spent-output window between timeout and
    next refresh — if the tx actually landed, the wallet's
    available pool says "outputs available" but they're
    on-chain; next consumer-side spend may wallet-double-spend
    (which the daemon will then reject as `DoubleSpend`).
    Refresh cleans up the state eventually, but the window is
    user-visible (UI may show an output as "spendable" then
    abruptly "spent").
  - **(B) Daemon-side authority.** Timeout keeps the
    reservation in `SubmitPendingDaemonAck`; outputs stay
    reserved; consumer (or V3.x `TimeoutResolverActor`)
    explicitly resolves after chain-state observation —
    the resolver consults the ledger to determine whether
    the timed-out tx landed on chain and then calls
    `discard(id, ConsumerExplicit)` (release on landing) or
    `discard(id, ConsumerExplicit)` after a grace period
    (release to retry on non-landing). The **exact
    chain-observation mechanism** (additive
    `LedgerDiagnostic` variant carrying tx-confirmation
    payloads, an additive `LedgerEngine` chain-query
    accessor, or a hybrid of both) is part of the V3.x
    consumer-actor PR's own design — Phase 0g's
    `LedgerDiagnostic::SnapshotMerged { new, prior, height }`
    variant deliberately carries no `tx_hash` and is
    insufficient on its own for this correlation. R8's
    `ReservationTTLActor` provides the safety net for
    forgotten resolutions: per-state TTL configuration permits
    shorter TTL on `SubmitPendingDaemonAck` than on `Active`
    (V3.x deliverable; segment-2e variant pin
    `DiscardReason::TTLAutoDiscard` covers this case).
  - **(C) Bounded grace period.** Timeout keeps reservation
    in `SubmitPendingDaemonAck` for N blocks (e.g., 20 blocks
    ≈ 40 minutes); after grace, auto-resolves to `Resolved`
    (release outputs). Phantom-spent window still exists during
    grace period; only the bound differs from (A).

  **Closes as (B) — daemon-side authority.** Rationale: the
  daemon is the wallet-external source of truth on chain
  state; the wallet's actor-state must not assume a resolution
  it cannot verify. The phantom-spent-output window of (A)/(C)
  is a wallet-side double-spend hazard that violates the
  threat-model property the tracker delivers
  (monotonicity; wallet-layer double-spend defence per
  §3.4.5). R8's TTL safety net handles forgotten resolutions
  (the failure mode where (B) would dominate (A)/(C) on
  operational hygiene). Consumer-explicit resolution preserves
  the wallet's authority to decide based on chain observation;
  the composition-side hook the V3.x `TimeoutResolverActor`
  consumes is the conjunction of (i) the
  `SubmitFailed { kind: DaemonTimeout | DaemonUnavailable }`
  event and (ii) a chain-observation mechanism for the
  timed-out `tx_hash` that the V3.x consumer-actor PR will
  design (additive `LedgerDiagnostic` variant carrying
  tx-confirmation payloads, additive `LedgerEngine`
  chain-query accessor, or both — `SnapshotMerged` carries
  `{new, prior, height}` only and is insufficient on its own
  for this correlation per Phase 0g binding).

  **Why (A) is not a `00-mission.mdc` priority-1 violation
  on its face.** The wallet-side double-spend hazard surfaces
  only when consumer behaves badly (spends from the same
  output pool without refreshing). The daemon's `DoubleSpend`
  rejection on the *second* attempt is the safety net.
  However, per
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
  threat-model anchoring discipline, "the daemon's safety net
  is doing work the wallet should be doing structurally" is
  the same anti-pattern as PR 4's "the consumer's checking
  is doing work the trait should be doing structurally."
  Choosing (B) closes the structural property the threat
  model needs; (A) would defer it to consumer behavior + a
  daemon-side check we can't guarantee under
  adversarial-daemon framing.

  **`SubmitError` + `TerminalErrorKind` / `AmbiguousErrorKind`
  enum pins (segment 2h reshape; replaces segment 2f's unified
  `SubmitErrorKind`).** Pinned in §5.0.2; all
  `#[non_exhaustive]` for future-additive variants. The split
  makes the lifecycle-class distinction (terminal: rid dropped;
  ambiguous: rid retained) load-bearing at the type level; see
  §5.6.4 for the substrate. The full binding signature lives in
  Phase 0a (§4) and §5.0.2; the schematic shape under R9 is:

  ```rust
  #[non_exhaustive]
  pub enum TerminalErrorKind { DoubleSpend, FeeTooLow, Malformed }

  #[non_exhaustive]
  pub enum AmbiguousErrorKind { DaemonTimeout, DaemonUnavailable }

  #[non_exhaustive]
  pub enum SubmitError {
      SnapshotInvalidated { … },
      DaemonRejectedTerminal { kind: TerminalErrorKind },
      DaemonAmbiguous { kind: AmbiguousErrorKind, reservation_id: ReservationId },
      ReservationNotFound { reservation_id: ReservationId },
      SubmitAlreadyPending { reservation_id: ReservationId },
  }
  ```

  **R5 ↔ R8 ↔ R9 coherence (segment 2f verification; segment
  2h refinement).** All three residuals share the
  `DiscardReason`/`Discarded` event infrastructure pinned in
  §5.0.2:

  - **R5 (lazy-discard diagnostic-emission)** — `submit`'s
    pre-daemon staleness check fails → `SubmitSnapshotInvalidated`
    diagnostic + `SubmitError::SnapshotInvalidated` return.
    Consumer's follow-up `discard(rid, ConsumerExplicit)`
    triggers `Discarded { reason: ConsumerExplicit }` and
    releases the reservation's `output_locks`. Wallet-internal
    authority (the wallet sees the snapshot rotated; no
    daemon round-trip needed; explicit consumer step required
    under lazy semantics per segment 2h §5.6.5 F5+F6 / §5.6.6
    P9).
  - **R8 (proactive cleanup-on-age)** — V3.x
    `ReservationTTLActor` observes per-collection age via the
    Phase 0l `ReservationTTLConfig { consumer_held, in_flight }`
    surface → sends `AutoDiscardMessage` → `PendingTxActor`
    emits `Discarded { reason: TTLAutoDiscard }`. Wallet-
    internal authority (the wallet sees age threshold
    exceeded). R8's per-collection TTL config covers
    Finding 2's safety net (independent age threshold on
    `in_flight` vs `consumer_held` per segment 2h F7).
  - **R9 (daemon-authority cleanup-on-rejection)** — daemon
    rejects definitively (terminal kinds) → `Discarded {
    reason: DaemonRejectedTerminal { kind: TerminalErrorKind } }`.
    Wallet defers to daemon authority for terminal-rejection
    visibility. For ambiguous kinds, no `Discarded` emission
    — `SubmitPendingResolution { rid, kind }` is emitted and
    the rid stays in `in_flight` (Finding 2 closure).

  Downstream consumers see a unified `Discarded` event stream
  with discriminated reasons covering R5's consumer-explicit
  path, R8's age-driven path, and R9's terminal-rejection path.

  **Why segment 2h adds `SubmitPendingResolution` (and
  removes `SubmitFailed`).** The segment-2f variant set
  conflated terminal and ambiguous lifecycles into a single
  `SubmitFailed { kind }` event; segment 2h's split routes
  terminal cases through `Discarded { DaemonRejectedTerminal
  { kind } }` (since the rid is actually leaving the
  tracker) and ambiguous cases through `SubmitPendingResolution
  { rid, kind }` (since the rid stays in `in_flight`).
  `SubmitFailed` is removed under segment 2h because the
  routing leaves no surviving emission site; the lifecycle-
  class distinction is now load-bearing on the emission side,
  parallel to the type-correctness motivation for splitting
  `SubmitErrorKind` on the error-return side. See §5.6.4 for
  the substrate.

  **No new trait surface methods needed in segment 2f.**
  `discard(id, ConsumerExplicit)` is sufficient for consumer-
  explicit resolution of Finding-2 ambiguity cases (Timeout /
  Unavailable). A `resolve_pending(id, chain_observation)`
  method would be a thin wrapper around `discard` with no
  new semantic; preserved as a V3.x ergonomic-API candidate
  if consumer telemetry surfaces the boilerplate.

  **V3.0 deliverables (segment 2f closure).** PR 5 ships:

  1. **`SubmitError` + `SubmitErrorKind` enums** in §5.0.2
     (both `#[non_exhaustive]`).
  2. **Per-error-class state-transition discipline** as
     pinned in the table above; emission discipline (Phase 1
     call-site review).
  3. **Self-continuation message pattern** for daemon
     round-trip (`PendingTxActor` defers reply until
     `SubmitCompleted` self-message arrives).
  4. **Daemon-side authority disposition** for Timeout /
     Unavailable: reservation stays in `SubmitPendingDaemonAck`;
     consumer-explicit `discard(id, ConsumerExplicit)` is the
     resolution path; R8's TTL is the safety net for
     forgotten resolutions.
  5. **`SubmitFailureAnalyzer`-readiness**: all events that
     V3.x's `SubmitFailureAnalyzer` consumes are emitted from
     the right call sites (Phase 1 confirms).

  **V3.x deferrals.** Existing `SubmitFailureAnalyzer`
  consumer-actor FOLLOWUPS entry is amended with segment-2f
  closure status; no new FOLLOWUPS entry needed (the analyzer
  shape is already pinned). `TimeoutResolverActor` (Finding 2
  ergonomic complement) is a V3.x consumer-actor candidate;
  segment 2f adds a brief FOLLOWUPS entry naming this
  surface.
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
  contract; reopen-and-close in Round 2 segment 2h amends
  the segment 2c F8 / restart-during-`in_flight` consequence
  pin under the (γ) lean state shape — see §5.6.5 F8).** PR 4
  §5.4.8 #1's restart-amnesia rule
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
  consumer — was originally noted as a V3.x "user-controlled
  tradeoff" candidate; **PR 4 Round 4 review pass F1
  (2026-05-15) hardens that disposition to a structural
  rejection at V3.0 with conditional reopening.** (c) is
  rejected.

  **Hardened disposition (PR 4 Round 4 review pass F1
  carryover, 2026-05-15).** Drop-on-close (in-memory only)
  is **structurally final at V3.0** for the
  `PendingTxDiagnostic` stream. The "V3.x optional
  encrypted-persistence consumer" framing — though
  defensible at PR 5 Round 2 segment-2c authoring time —
  understated the attack surface adding any persistence
  layer would create. The PR 4 review pass enumerated six
  attack vectors against an encrypted-persistence opt-in
  for diagnostic events (full enumeration at PR 4 §5.4.8 #1
  / §5.4.9 F1; abbreviated here): (1) crypto code-path
  expansion via persistence triggers (new code paths
  touching master-key material outside transaction signing,
  exercised under attacker-driven high-volume event
  emission to probe for nonce-reuse, weak-KDF, or
  IV-collision bugs); (2) deserialization-on-startup as
  exploit primitive (decrypt-and-replay during wallet open
  is a deserialization path before the wallet is fully
  verified; if any attacker-influenced field reaches the
  persisted artifact, the path becomes a startup-time exploit
  primitive); (3) metadata side-channel (file sizes, write
  timing, write patterns observable to filesystem-adjacent
  observers — multi-user systems, backup snapshots, swap
  files, `/proc` inspection — making the encrypted artifact
  a wallet-activity signal that exists only because we
  added persistence); (4) cross-wallet correlation
  amplification (statistically-correlatable persistence
  patterns across wallets exposed to the same daemon enable
  institutional-adversary backup-stealing or cloud-backup-
  compromise correlation that drop-on-close forecloses
  entirely); (5) persistence as adversary-controlled DoS
  (high-rate event emission → high write pressure → disk
  fills or wallet enters error state, neutralized by
  drop-on-close); (6) forensic-attack primitive against
  seized wallets (persistent diagnostic events on disk are
  exactly what forensic analysts want from a seized device;
  even encrypted, their existence is information about when
  the wallet was active, an artifact drop-on-close does not
  produce). The conventional "we'll evaluate it in V3.x"
  framing was a soft commitment that shaped reviewer and
  contributor expectations toward an opt-in shipping; the
  honest disposition is a hard rejection that walks the
  expectation back.

  **V3.x reopening criteria (symmetric with PR 4 §5.4.8 #1
  / §5.4.9 F1).** Reopening the encrypted-persistence
  question for `PendingTxDiagnostic` requires **all** of:
  (a) demonstrated production use case surfaced from real
  V3.0 deployments (not anticipated demand); (b) full
  threat-model review at the time of evaluation, including
  the metadata side-channel, cross-wallet correlation,
  deserialization-on-startup, and forensic-artifact attack
  vectors enumerated above; (c) explicit
  `AUDIT_SCOPE.md` amendment if adopted, with the
  persistence layer brought into audit scope; (d)
  acknowledgment that the privacy-first default discipline
  per `00-mission.mdc` §2 supersedes
  ergonomic-recovery considerations except in cases where
  (a)–(c) demonstrate the case. **No V3.x schedule entry;
  conditional reopening only.** The previous segment-2c
  refinement to the diagnostic-stream contract pin
  ("user-controlled encrypted-persistence opt-in is
  permitted if the persistence consumer's surface is
  entirely within the wallet's own encrypted-state
  surface") is **withdrawn**; PR 4 §5.4.8 #1's contract
  pin reverts to the structural drop-on-close rule.

  **Diagnostic-stream contract pin (post-F1 hardening).**
  PR 4 §5.4.8 #1's pin reads:

  > **In-memory only; drop on close.** Diagnostic events
  > (`RefreshDiagnostic`, `PendingTxDiagnostic`, and any
  > future stream) MUST NOT persist across wallet restart.
  > Persistence is structurally rejected at V3.0; reopening
  > requires the four-pronged criteria of PR 4 §5.4.9 F1.
  > The privacy-first default discipline supersedes
  > ergonomic-recovery considerations.

  **Phase 0 implication.** No V3.0 trait-surface change;
  the `PendingTxDiagnostic` stream's contract is
  hardened-not-restructured. The original segment-2c plan
  to ship a `PersistenceConsumerActor` in V3.x is
  withdrawn; if the four-pronged criteria are met later,
  the V3.x consumer-actor PR re-derives the actor shape
  under the threat-model review (b) requires.

  **V3.x trigger (revised).** None on the schedule. The
  conditional reopening is gated on demonstrated production
  use case (a) — not anticipated demand. The previous
  trigger language ("Institutional / long-running deployment
  requirements; wallet-storage encryption layer matures;
  user-configuration UX for persistence opt-in") is
  **withdrawn**; those are interesting *consequences* of a
  reopening but not *triggers* for one. The trigger is the
  use case; the consequences are downstream design work
  the reopening would carry.

  **FOLLOWUPS entry (revised).** The previously-planned
  "Encrypted-persistence `PersistenceConsumerActor` for
  institutional / long-running wallet deployments" V3.x
  entry is rewritten as a **conditional-reopening
  bookmark**, not a scheduled deliverable. The bookmark
  cross-references PR 4 §5.4.8 #1 / §5.4.9 F1 and PR 5
  §5.4 R17 (this entry) for the four-pronged criteria; it
  carries no version target and is closed automatically if
  V3.0 deployments do not surface the criterion-(a) use
  case within the V3.0 + V3.1 window.

  **Segment-2h F8 explicit-acceptance amendment.** Under the
  segment-2h (γ) lean state shape, a wallet restart that
  drops the actor's `in_flight` collection while a tx is
  live on-network produces a consumer-observable double-
  spend rejection on rebuild: the next refresh reconciles
  the confirmed tx (the wallet's output state catches up
  with chain state), but during the restart-to-refresh gap
  a consumer rebuild may re-select the same outputs and
  produce a `submit` whose daemon outcome is
  `DaemonRejectedTerminal { kind: TerminalErrorKind::DoubleSpend }`.
  The consequence is **explicitly accepted at V3.0** —
  drop-on-close is structurally final per the R17 hardened
  disposition above; the F8 surface is the named instance
  of that finality. **Mitigation surface:** the R17 V3.x
  conditional-reopening bookmark is the structural
  mitigation. The four-pronged criteria for reopening (per
  R17 above) do not change under F8 — F8 names a specific
  consequence of the V3.0 disposition rather than a new
  reopening trigger. The Phase 9 audit-readiness substrate
  documents F8 explicitly so reviewers do not mistake the
  surface for an oversight; see §5.6.5 F8 for the segment-2h
  pin.

- **R18 — Transaction replacement / fee-bump structural
  rejection (named with disposition in Round 2 segment 2i
  per G3; reopen-conditional on FCMP++ cryptographic
  analysis OR R16 V3.x telemetry-driven priority-class
  re-classification; see §5.6.10 G3 for the full
  substrate).** The design discipline question is whether
  to admit RBF / CPFP-equivalent replacement of stuck txs
  — `replace(rid, new_fee) → Reservation` constructing a
  new tx spending the same inputs at higher fee, atomically
  transitioning the `in_flight` entry to the replacement.
  The structural disposition is **rejection at V3.0**;
  R14's `ReservationExtension` seam is **NOT** pre-pinned
  with a `Replacement` variant.

  **Threat model.** Replacement creates a mempool-observer-
  visible linked-tx-pair fingerprint: two replacement txs
  share a key image; mempool observers see both sequentially
  before the second gets rejected as double-spend; on-chain
  only one persists. The fingerprint is **bounded** —
  transient, mempool-only, only-fires-on-actual-replacement-
  invocation — and may be further muted by FCMP++'s proof-
  construction characteristics, but it is net-new privacy
  surface that does not exist if replacement is not admitted.

  **Priority-ordering rationale (load-bearing).** Per
  [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)
  priority hierarchy as **ordering-not-magnitude-comparison**:
  any priority-2 (privacy) cost for any priority-3 (UX)
  benefit is rejected by the ordering regardless of the
  fingerprint cost's magnitude. The fingerprint being
  "bounded" or "mempool-only" or "transient" is not a
  mitigating factor under the ordering; only a priority-
  level shift (driven by substrate change) re-balances the
  decision. The rejection's defensibility comes from the
  priority-ordering principle, not from claiming the
  fingerprint is catastrophic.

  **Options.**
  - (a) **Structural rejection at V3.0.** No `replace` trait
    method; `ReservationExtension::Replacement` seam not
    pre-pinned; users with stuck txs wait for fee market
    relaxation or use the (V3.0-shipped) discard +
    rebuild-at-current-fee path, which produces a
    cancellable (because never-submitted-at-the-old-fee) new
    tx without the replacement fingerprint. **Privacy-first;
    stuck-tx-recovery worsens against truly-stuck txs.**
  - (b) **Admit `replace` at V3.0 with privacy mitigations.**
    R15's `SubmissionStrategyActor` mediates broadcast timing;
    R16's wallet-side fee estimation reduces the frequency
    with which replacement is needed. **Privacy regression
    accepted; UX-recoverability improved.** Rejected per the
    priority-ordering principle above.
  - (c) **Admit `replace` at V3.x with telemetry-driven
    re-evaluation.** Defer the design question to V3.x;
    re-evaluate against actual stuck-tx rates from V3.0
    deployments. The "we'll evaluate in V3.x" framing the R17
    F1 hardening already named as a soft-commitment anti-
    pattern. Rejected as cost-benefit-defer-to-later under
    [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc).

  **Disposition.** **V3.0 ships (a) — structural rejection
  with named conditional reopening criteria.**

  **V3.x reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
  named-criteria principle).** Reopening the replacement
  question requires **either**:

  1. **FCMP++ cryptographic fingerprint-unobservability
     analysis.** Demonstrate that under FCMP++'s proof-
     construction characteristics (per the FCMP++ spec /
     reference implementation), mempool observers cannot
     link key images across mempool snapshots — i.e., the
     replacement fingerprint is cryptographically muted
     rather than just bounded. This is the
     substrate-change-class trigger that re-anchors the
     priority-2-cost calculus: if the mempool-observer
     fingerprint isn't observable, the privacy cost is
     gone, and the priority-ordering allows priority-3 UX
     gain.

  2. **R16 V3.x `WalletSideEstimator` operational telemetry
     priority-class re-classification.** R16's V3.x
     telemetry demonstrates that fee-estimation improvements
     are insufficient to prevent stuck-tx scenarios at a
     user-impact-significant rate — re-classifying
     stuck-tx-recovery from priority-3 UX to priority-1
     security/integrity (users lose funds to unrecoverable
     stuck txs). The trigger's load-bearing piece is the
     **priority-class promotion**, not the user-impact rate
     itself. Without the promotion, the reopening criterion
     reduces to "users complain at production scale," which
     is the predictable-cost-of-the-priority-hierarchy
     disposition that `00-mission.mdc` already rejects. With
     the promotion, the priority-balance shifts from
     priority-2-vs-priority-3 (privacy wins) to
     priority-2-vs-priority-1 (security wins) under the
     same ordering principle.

  Either criterion is sufficient; the criteria are
  alternatives, not conjunctive. Both are substrate-anchored
  per the named-criteria principle; "users want this" is
  not.

  **Re-evaluation shape.** Reopening lands a fresh design
  round at the per-trait PR altitude (analogous to PR 5's
  Round 2 segment-2b R11 split or PR 4's Round 4 review
  pass), with the substrate-change evidence on the table
  before the round opens. The reopening evidence MUST
  include (i) the cryptographic-analysis citation or the
  telemetry-citation; (ii) a fresh threat-model review of
  the replacement fingerprint under the substrate change;
  (iii) an `AUDIT_SCOPE.md` amendment if the substrate
  change brings new surface into audit scope; (iv) a fresh
  `R14 ReservationExtension::Replacement` variant proposal
  with the field-set substrate the new round names.

  **Phase 0 implication.** No V3.0 trait-surface change;
  no `replace` method on `PendingTxEngine`; no
  `ReservationExtension::Replacement` pre-pin on R14's
  extensibility seam. The R14 seam (segment-2b closure)
  stands as the generic extensibility surface;
  replacement-specific variant addition is gated on the
  R18 reopening criteria.

  **FOLLOWUPS entry (segment-2i).** "Transaction replacement
  / fee-bump (RBF/CPFP-equivalent) structural rejection"
  V3.x conditional-reopening bookmark with the two named
  triggers above; lives alongside R17's persistence
  conditional-reopening bookmark in `docs/FOLLOWUPS.md`
  under a parallel structure. No V3.x schedule entry;
  conditional reopening only.

  **Relationship to R14, R15, R16.** R14 is the *extensibility
  seam* for reservation-payload richness (generic; any
  future variant can ride it). R18 is the *content
  decision* about whether the replacement-variant is added
  to that seam — and the answer is "not at V3.0; reopen on
  named criteria." R15's `SubmissionStrategyActor` would
  be a downstream consumer if R18 reopened (broadcast
  strategy for replacements differs from initial submissions
  because the linked-tx-pair fingerprint mitigations live
  there); R16's `WalletSideEstimator` is the V3.x
  telemetry-bearing component whose criterion-2 evidence
  could reopen R18. R18 is structurally independent of
  R14 / R15 / R16 at V3.0; the relationships activate only
  on reopening.

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

**What Round 2 carried (final inventory; closed
2026-05-14).** Seven segments landed across two days
(2026-05-13 → 2026-05-14), covering all named residuals and
the Phase 0 binding-form enumeration:

- **Segment 2a — audit-readiness.** Criterion-5 prose
  strengthening (contract-dependency-on-refresh-quiescence
  framing); §5.3 threat-model anchor explicit defense
  (adversary-controlled-daemon-as-design-center); §5.5
  scorecard rationale clarification (criteria 4 / 5
  distinct-consequences framing).
- **Segment 2b — R11 + R14 architectural-integrity-now.**
  R11 closed as (b) signing-actor split from Stage 1
  (`Signer` trait + `LocalSigner` + Stage 4
  `SigningActor`); R14 closed as `Reservation::extensions:
  Vec<ReservationExtension>` extensibility seam
  (`#[non_exhaustive]` empty V3.0 variant set). FOLLOWUPS
  R11 entry replaced with HW-wallet integration entry.
- **Segment 2c — closure-rule + lens-applicability +
  R13 / R15 / R16 / R17.** §5.0.4 lens-applicability
  discipline (three structural conditions); §7
  closure-rule strengthening (wargaming-surface-known-at-
  closure-time qualifier; new-shapes reopen Round N);
  R13 closed under `OutputSelector` trait seam (V3.0
  wallet2-greedy; V3.x alternatives); R15 closed under
  `SubmissionStrategyActor` topology slot (V3.0
  `DirectStrategy`; V3.x privacy strategies); R16 closed
  under `FeeEstimator` trait seam (V3.0
  daemon-recommendation-with-override; V3.x
  wallet-side estimator); R17 closed as drop-on-close
  V3.0 default with V3.x encrypted-persistence consumer
  option.
- **Segment 2d — R2 + R12 co-disposition.** R12 closed
  as (a) content-derived `SnapshotId` from existing
  `LedgerSnapshot` fields; R2 closed as opaque 16-byte
  content-addressed digest with projection-type
  discipline preserved-as-pattern; Phase 0c truly
  collapses; R16 conditional V3.0 lift evaluated and
  rejected (LedgerBlock carries no per-block fee data;
  conservative V3.x default holds).
- **Segment 2e — R8 + `DiscardReason::TTLAutoDiscard`.**
  R8 closed as `ReservationTTLActor` consumer-actor
  composition (V3.0 ships diagnostic-stream seam complete;
  V3.x lands actor); `DiscardReason::TTLAutoDiscard`
  variant added; R5 ↔ R8 coherence verified.
- **Segment 2f — R9 + Finding 2 + Finding 4.** R9 closed
  as two-stage submit flow with explicit internal
  `ReservationState` machine (`Active |
  SubmitPendingDaemonAck | Resolved`); Finding 2 closed
  as (B) daemon-side authority for ambiguous outcomes;
  Finding 4 closed as constructor-bound `DiagnosticSink`
  via §5.0.2.1; `SubmitError` + `SubmitErrorKind` enums
  pinned; R5 ↔ R8 ↔ R9 coherence verified; existing
  `SubmitFailureAnalyzer` FOLLOWUPS entry amended; new
  `TimeoutResolverActor` FOLLOWUPS entry added.
- **Segment 2g — Round 2 close-out.** §4 Phase 0
  binding-form enumeration finalized (Phase 0a–0g
  binding-pinned; new Phase 0h `Signer` / 0i
  `OutputSelector` / 0j `FeeEstimator` / 0k
  `SubmissionStrategyActor` topology slot from
  segment-2b / segment-2c closures); `SnapshotId` hash
  primitive pinned (Keccak-256/128-bit truncation via
  `shekyl-crypto-hash::cn_fast_hash` — unconditional
  workspace dep — with versioned domain-separation prefix;
  revised in Copilot-fix follow-up from segment-2g's prior
  `sha2`-based binding for dependency-discipline
  correctness); §5.0.3
  diagnostic-stream-doc generalization closed as (a)
  rename to `DIAGNOSTIC_STREAM.md` (FOLLOWUPS amended);
  §6 review checklist filled with binding-check /
  test-substrate / call-site-sweep enumerations.

**What Round 3 carries.** Commit decomposition + Phase 1
commit list (per the PR 1 / PR 2 / PR 3 / PR 4 precedent).
Substrate: this document at segment-2g close-out (Round 2
final form); §4 Phase 0 enumeration; §6 review checklist;
PR 4 Round 3 confirmation per §5.2.

---

## §5.6 Round 2 segment 2h — actor-state-shape refinement (post-Round-3-readiness review)

**Trigger.** Round 3 readiness review against the substrate
landed through segment 2g surfaced eight findings (F1–F8)
and nine probes (P1–P9) clustering into three load-bearing
classes:

1. **Substrate-representation cost.** Segment 2f's R9
   closure pinned an explicit internal `ReservationState ∈
   {Active, SubmitPendingDaemonAck, Resolved}` enum field
   on the `Reservation` record held inside the actor's
   `reservations: HashMap<ReservationId, Reservation>`
   tracker. Round 3 readiness review surfaced that **the
   state-enum is carrying representation that doesn't
   load-bear** — the per-record lifecycle stage is encoded
   redundantly in the enum field and in the actor's
   collection membership. F2 (consumer-initiated `discard`
   during `SubmitPendingDaemonAck`) and F7 (per-state TTL
   configurability) surfaced as state-machine-row questions
   that **dissolve under a leaner shape** where the
   reservation's location encodes its lifecycle stage.
2. **Submission-error reshape.** The R9 closure also pinned
   a unified `SubmitErrorKind = DoubleSpend | FeeTooLow |
   Malformed | DaemonTimeout | DaemonUnavailable` enum and a
   `PendingTxDiagnostic::SubmitFailed { kind: SubmitErrorKind
   }` diagnostic variant. P4's collection-moves table
   surfaced that **`SubmitFailed` has no surviving emission
   site** under the lean shape — terminal errors emit via
   `Discarded { reason: DaemonRejectedTerminal::* }`,
   ambiguous errors emit via a new `SubmitPendingResolution
   { rid, kind: AmbiguousErrorKind }`. The unified
   `SubmitErrorKind` also conflates **terminal-vs-ambiguous
   lifecycle consequences** in a single type, which the
   collection-moves disposition makes legible only by
   pattern-matching on the variant set — a type-correctness
   regression the split closes.
3. **Lazy R5 vs. eager R5 framing inconsistency.** P9
   surfaced that the segment-2g §5.0.2 prose around
   snapshot-rotation cleanup reads as eager-discard
   (`DiscardReason::SnapshotRotationAutoDiscard` variant
   suggests an emission site at `LedgerDiagnostic::SnapshotMerged`
   handling); segment-2e's R5 closure was explicitly
   **lazy** (stale reservations linger until consumer
   submits; staleness detection at submit-time field
   comparison; rich `SubmitError::SnapshotInvalidated`
   error context). The two readings disagree at substantive
   consequence — eager releases output_locks proactively but
   is hostile to consumer UX under fast snapshot rotation;
   lazy preserves reservation lifetime across rotations and
   delivers rich error context to the consumer. Lazy is the
   load-bearing disposition; segment 2h pins it explicitly
   and resolves the variant-without-emitter consequence.

The three classes are entangled — F2's framing, F7's
framing, P4's table, and the SnapshotRotationAutoDiscard
disposition all depend on which state-shape the actor uses
internally. Segment 2h closes the substrate refinement
holistically per the §7 strengthened closure rule and the
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
named-criteria reopening principle — **new shapes
surfacing in Round 3 readiness review reopen Round 2 rather
than slipping past closure**.

### §5.6.1 Sequencing — fold F1+F2+F7 into a single segment-2h reopen

Two dispositions were evaluated:

- **(A) Bundle into segment 2h.** F1's prose-tightening,
  F2's state-machine-row gap, and F7's per-state-TTL
  configurability surface together as a single segment-2h
  scope. F3/F5/F6/F8 ride along as Phase-1-binding-pin
  documentation discipline (no state-shape impact).
  Probes P1–P9 land as implementation-discipline pins
  inside §5.0 / §5.0.1 / §5.0.2 / §5.4 prose, with two
  probes (P4 and P9) carrying state-shape consequences
  that segment 2h's R5 / R8 / R9 reopens absorb.
- **(B) Open Round 3 directly; surface findings as
  Phase 1 review.** Lower upfront design cost; risk of
  finding a structural F2-shaped gap mid-Phase-1 and
  retreading. §7's strengthened closure rule reads
  toward (A) for F2 specifically — it's a
  state-transition the substrate doesn't cover, not
  closure-time-known wargaming residual.

**Disposition: (A).** F2's ownership-boundary framing
becomes load-bearing in the right way (ownership, not
state-machine bookkeeping); F7's per-state config collapses
to per-collection config under the lean shape with the same
V3.0-surface-for-V3.x-consumer discipline; shipping the
state-machine framing in C0 knowing we'd refine it later
is the cost-benefit-defer-to-later anti-pattern per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc).
The substrate refinement is the architectural-integrity-now
disposition; segment 2h lands it ahead of C0 implementation.

### §5.6.2 The (γ) three-collection lean state shape

The actor's internal state under segment 2h is bounded by
the three structures that load-bear for the safety
properties the threat model requires. Two intermediate
shapes were considered and rejected during segment 2h
substrate review:

- **(α) Minimum state with implicit consumer-held
  membership.**

  ```rust
  struct PendingTxState {
      current_snapshot: SnapshotId,
      output_locks: HashMap<OutputId, ReservationId>,
      created_at: HashMap<ReservationId, Instant>,   // TTL aging
      in_flight: HashMap<ReservationId, InFlightSubmit>,
  }
  ```

  Consumer-held membership is the set difference
  `created_at.keys() − in_flight.keys()`. Implicit;
  awkward to assert against.

- **(β) Symmetric with per-collection metadata carrying
  outputs.**

  ```rust
  struct ConsumerHeldEntry { outputs: BTreeSet<OutputId>, created_at: Instant }
  struct InFlightSubmit    { outputs: BTreeSet<OutputId>, snapshot_id: SnapshotId, submitted_at: Instant }

  struct PendingTxState {
      current_snapshot: SnapshotId,
      output_locks: HashMap<OutputId, ReservationId>,   // inverted index
      consumer_held: HashMap<ReservationId, ConsumerHeldEntry>,
      in_flight: HashMap<ReservationId, InFlightSubmit>,
  }
  ```

  Type-level symmetry; constant-time reverse-lookup for
  discard / terminal-resolution lock release. **Rejected
  on audit-surface grounds.** The duplication —
  `OutputId` lives in `output_locks` AND in
  `consumer_held[rid].outputs` (or `in_flight[rid].outputs`)
  — creates a runtime invariant ("the two views agree")
  that every mutation site must preserve. A refactor that
  updates one view but not the other produces lock-leak
  (claims unowned by any reservation) or false safety
  (metadata claims outputs the lock map doesn't enforce).
  The "grep-able union" property is a test-assertion
  convenience masquerading as audit value; the runtime
  safety property is "an output is reserved iff some
  active reservation claims it," which holds under any
  shape where `output_locks` is single source of truth.

- **(γ) (γ) — (α) with explicit consumer-held collection;
  no denormalization. The segment-2h pin.**

  ```rust
  struct InFlightSubmit {
      snapshot_id: SnapshotId,
      created_at: Instant,    // preserved across the consumer_held → in_flight move
      submitted_at: Instant,  // when submit moved the rid into in_flight
      // V3.x: discard_requested: bool;  // see §5.6.7 (c) FOLLOWUPS entry
  }

  struct PendingTxState {
      current_snapshot: SnapshotId,
      output_locks: HashMap<OutputId, ReservationId>,
      consumer_held: HashMap<ReservationId, Instant>,    // explicit membership; tracks creation
      in_flight: HashMap<ReservationId, InFlightSubmit>,
  }
  ```

**Why (γ).**

- **Symmetry argument met without denormalization.**
  Both per-reservation collections are
  `HashMap<ReservationId, T>` with `T` carrying a
  timestamp plus collection-specific extras. The
  parallel structure is at the type level; no
  duplicated state to keep in sync.
- **`output_locks` remains single source of truth.**
  The wallet-layer anti-double-spend invariant lives
  on `output_locks`: "an output is reserved iff
  `output_locks.contains_key(oid)`." No other view
  contradicts this; no invariant maintenance discipline
  required across two views.
- **Membership is explicit.** Under (α) the
  consumer-held set is computed; under (γ) the set is a
  collection the actor reads directly. Discard handlers
  can assert `consumer_held.contains_key(rid)` before
  scanning `output_locks`; the scan is guaranteed to
  find ≥ 1 entry rather than potentially-vacuous.
- **Discard is O(n) scan over `output_locks`.** Same as
  (α). At wallet scale (hundreds-to-low-thousands of
  locked outputs), nanoseconds; the actor's mailbox
  processing rate dominates by orders of magnitude.
- **Audit-assertion shape.** "For each `(output_id,
  reservation_id)` in `output_locks`, `reservation_id ∈
  consumer_held.keys() ∪ in_flight.keys()`." Checkable
  without state duplication; the assertion is the
  invariant the audit verifies, not state to maintain.

**Optional V3.x perf seam.** If wallet scale grows beyond
the point where the O(n) scan dominates handler latency
(unlikely under V3.0 wallet usage patterns; never observed
across PR 1 / PR 2 / PR 4 implementations), the actor can
add a maintained-by-actor inverse index `reservation_to_outputs:
HashMap<ReservationId, BTreeSet<OutputId>>` as a perf
optimization. The inverse index reintroduces (β)'s
denormalization but with explicit framing: perf seam,
audit verifies invariance against `output_locks`, single
mutation discipline (every `output_locks` mutation pairs
with a `reservation_to_outputs` mutation in the same
handler-atomicity scope per §5.6.6 P7). V3.0 does not
ship the inverse index; FOLLOWUPS entry per §5.6.7.

### §5.6.3 Collection-moves discipline (replaces enum-state-transitions)

The actor's state-mutating handlers under the (γ) shape:

- **`build(request)`** —
  1. Fetch raw candidate outputs from `LedgerEngine`.
  2. **Filter** against `output_locks.keys()` (only the
     actor sees `output_locks`; this is the
     P6-mandated filter-then-select discipline).
  3. Hand filtered candidates to `OutputSelector::select_outputs`.
  4. **Verify subset.** The returned `SelectedOutputs`
     indices MUST be in the filtered set passed to the
     selector (P-F4 caller-side subset re-verification;
     rejects with `OutputSelectorError::ReturnedIndicesNotSubset
     { offending_index }` if violated).
  5. Allocate a fresh `ReservationId`.
  6. **Atomically (P7):** insert `(oid, rid)` into
     `output_locks` for each selected output; insert
     `(rid, now)` into `consumer_held`; emit
     `BuildSucceeded { reservation_id, snapshot_id, ... }`;
     return the `Reservation` value to the caller.

- **`submit(reservation)`** — the consumer passes the
  full `Reservation` value back (containing
  `reservation_id`, `snapshot_id`, `outputs`,
  `tx_bytes`, and `extensions`).
  1. Match `(in_flight.contains_key(rid), consumer_held.contains_key(rid))`:
     - `(true, _)` → return `PendingTxError::SubmitAlreadyPending
       { reservation_id }`. The actor owns this reservation
       (in-flight to the daemon); the consumer's re-submit
       is a duplicate.
     - `(false, false)` → return `PendingTxError::ReservationNotFound
       { reservation_id }`. The reservation never existed
       or was already resolved; gone is gone (P3).
     - `(false, true)` → **success path; proceed.**
  2. **Staleness check (lazy R5 disposition).** Compare
     `reservation.snapshot_id` to `self.current_snapshot`.
     Mismatch → emit `PendingTxDiagnostic::SubmitSnapshotInvalidated
     { reservation_id, reservation_snapshot,
     current_snapshot }` and return `SubmitError::SnapshotInvalidated
     { reservation_snapshot, current_snapshot }`. **Do
     not** drop the reservation from `consumer_held`;
     consumer is responsible for `discard(rid)` after
     receiving the error. (See §5.6.5 F1 for the Stage 1
     vs. Stage 4 staleness-detection-property asymmetry
     pin.)
  3. **Move atomically (P7):**
     - Remove `rid` from `consumer_held` (capturing the
       `created_at` timestamp).
     - Insert into `in_flight[rid] = InFlightSubmit {
       snapshot_id: reservation.snapshot_id, created_at,
       submitted_at: now }`.
     - `output_locks` entries for `reservation.outputs`
       remain claimed (the reservation is still locked;
       only the lifecycle bucket changes).
     - Emit `SubmitAttempted { reservation_id }`.
  4. **Dispatch.** Hand `reservation.tx_bytes` to the
     `Signer` for signing (Stage 1: synchronous call;
     Stage 4: `signer: ActorRef<SigningActor>` message),
     then to `DaemonEngine::submit_tx` (Stage 1: direct
     call; Stage 4: through `SubmissionStrategyActor`
     per §5.4 R15 topology slot).
  5. **Reconcile** at daemon response per §5.6.4's P4
     collection-moves table.

- **`discard(reservation_id, reason)`** —
  1. Match `(in_flight.contains_key(rid), consumer_held.contains_key(rid))`:
     - `(true, _)` → return `PendingTxError::DiscardBlockedPendingDaemonAck
       { reservation_id }`. **F2 ownership-boundary
       disposition.** The actor owns the reservation
       (in-flight to the daemon; daemon has authority
       over its terminal state). The consumer's
       resolution surface for `in_flight` reservations
       is (i) wait for the daemon round-trip; (ii) the
       R8 TTL safety-net (V3.x `ReservationTTLActor`
       per §5.4 R8); (iii) restart and accept the F8
       surface (see §5.6.5 F8).
     - `(false, true)` → **success path.** Remove from
       `consumer_held`. **Atomically (P7):** for each
       `(oid, rid')` in `output_locks` where `rid' ==
       rid`, remove the entry. Emit `Discarded {
       reservation_id, reason }`.
     - `(false, false)` → return `PendingTxError::ReservationNotFound
       { reservation_id }`. Never existed or already
       resolved (P3).

- **`outstanding() -> usize`** — returns
  `consumer_held.len() + in_flight.len()`. The
  projection is count, not ID-enumeration; ID-enumeration
  is recoverable from diagnostic-stream subscription
  (`BuildSucceeded`, `Discarded`, `SubmitSucceeded`,
  `Discarded` events carry `ReservationId`). Pins §2.4
  binding (P1); §5.0.1 prose names the ID-via-diagnostic-stream
  pattern.

**Snapshot-rotation cascade (lazy R5; P9; segment-2e
preservation).** When `LedgerDiagnostic::SnapshotMerged
{ new, prior }` arrives in Stage 4 (Stage 1 reads
synchronously from `LedgerEngine::snapshot()` per
§5.4 R12 (a)):

1. Update `current_snapshot ← new`.
2. **No collection sweep.** Consumer-held entries
   linger in `consumer_held`; their `output_locks`
   entries remain claimed. The reservation is now
   stale-against-current-snapshot but the wallet does
   not proactively reclaim.
3. **Staleness is detected at submit time** per the
   `submit` flow above. The consumer's `Reservation`
   value carries `snapshot_id`; the submit handler
   compares against `self.current_snapshot`; mismatch
   surfaces as `SubmitError::SnapshotInvalidated` with
   rich `(reservation_snapshot, current_snapshot)`
   context the consumer can act on (rebuild against
   current snapshot or `discard`).
4. **`R8` TTL is the cleanup safety-net** for
   never-submitted stale reservations: aging fires on
   `consumer_held[rid]` (creation timestamp); emits
   `Discarded { reason: TTLAutoDiscard }`.

In-flight reservations are **not** swept by snapshot
rotation. The reservation is committed to the daemon
round-trip; the daemon's authority resolves whether the
tx survives the rotation (accept → on-chain; reject
`DoubleSpend` → terminal class moves the reservation
out of `in_flight` per the P4 table). The actor never
unilaterally discards an in-flight reservation; the
ownership boundary that motivates F2's disposition is
the same boundary that protects in-flight reservations
from automatic snapshot-rotation cleanup.

**Eager-discard alternative (P9 rejected at V3.0;
FOLLOWUPS V3.x trigger).** Eager-discard at SnapshotMerged
handling — proactive release of `output_locks` for
consumer-held stale reservations — was considered and
rejected at V3.0. Eager has two costs lazy avoids: (i)
hostile consumer UX under fast snapshot rotation (a
build that takes 60s to confirm submits against a
chain rotating every 30s loses its reservation
mid-decision; `ReservationNotFound` is less context-rich
than `SnapshotInvalidated`); (ii) selective discard
requires the actor to know each consumer-held
reservation's `snapshot_id`, which expands `consumer_held`'s
metadata beyond the (γ) shape's `Instant`-only timestamp
(`ConsumerHeldEntry { snapshot_id, created_at }`). The
V3.x eager-discard opt-in FOLLOWUPS entry (§5.6.7
P9 trigger) reintroduces the variant and substrate
when a V3.x performance-policy design rounds settles it.

### §5.6.4 SubmitError / SubmitErrorKind reshape

Segment 2h reshapes the segment-2g binding-form pins
under P4's collection-moves table.

**Type-correctness motivation.** Under P4 the actor's
reconciliation at daemon response is per-error-class:
terminal errors release output_locks and drop in_flight
(reservation gone); ambiguous errors retain output_locks
and in_flight (reservation pending daemon resolution).
The unified `SubmitErrorKind = DoubleSpend | FeeTooLow |
Malformed | DaemonTimeout | DaemonUnavailable` conflates
these two lifecycle classes in a single type; a consumer
matching `SubmitErrorKind` to decide "is my reservation
gone or pending?" must pattern-match on the variant set,
losing the lifecycle-class distinction at the type level.
Splitting `SubmitErrorKind` into `TerminalErrorKind` and
`AmbiguousErrorKind` makes the lifecycle distinction
load-bearing at the type system; consumer code matching
`TerminalErrorKind` knows by type that the reservation
is gone; consumer code matching `AmbiguousErrorKind`
knows the reservation is still in flight.

**Binding-form replacement (Phase 0a amendment).**

```rust
#[non_exhaustive]
pub enum TerminalErrorKind {
    DoubleSpend,
    FeeTooLow,
    Malformed,
}

#[non_exhaustive]
pub enum AmbiguousErrorKind {
    DaemonTimeout,
    DaemonUnavailable,
}

#[non_exhaustive]
pub enum SubmitError {
    SnapshotInvalidated {
        reservation_snapshot: SnapshotId,
        current_snapshot: SnapshotId,
    },
    DaemonRejectedTerminal { kind: TerminalErrorKind },
    DaemonAmbiguous { kind: AmbiguousErrorKind, reservation_id: ReservationId },
    ReservationNotFound { reservation_id: ReservationId },
    SubmitAlreadyPending { reservation_id: ReservationId },
}

#[non_exhaustive]
pub enum PendingTxError {
    // ... build-side variants (unchanged from segment 2g) ...
    DiscardBlockedPendingDaemonAck { reservation_id: ReservationId },
    SubmitAlreadyPending { reservation_id: ReservationId },
    ReservationNotFound { reservation_id: ReservationId },
}

#[non_exhaustive]
pub enum OutputSelectorError {
    // ... existing variants ...
    ReturnedIndicesNotSubset { offending_index: OutputIndex },
}
```

**Diagnostic-stream replacement (Phase 0f amendment).**

```rust
#[non_exhaustive]
pub enum PendingTxDiagnostic {
    BuildAttempted { request_summary: BuildRequestSummary },
    BuildSucceeded { reservation_id: ReservationId, snapshot_id: SnapshotId, outputs_count: u32 },
    BuildFailed { kind: BuildErrorKind },
    SubmitAttempted { reservation_id: ReservationId },
    SubmitSucceeded { reservation_id: ReservationId, tx_hash: TxHash },
    SubmitPendingResolution { reservation_id: ReservationId, kind: AmbiguousErrorKind },
    SubmitSnapshotInvalidated {
        reservation_id: ReservationId,
        reservation_snapshot: SnapshotId,
        current_snapshot: SnapshotId,
    },
    Discarded { reservation_id: ReservationId, reason: DiscardReason },
    ReservationOutstanding { reservation_id: ReservationId, age: Duration },
    // SubmitFailed REMOVED — no surviving emission site under the P4
    // collection-moves table; terminal errors emit via Discarded with
    // DaemonRejectedTerminal reason; ambiguous errors emit via
    // SubmitPendingResolution. The lifecycle-class distinction is
    // load-bearing on the emission side, parallel to the type-correctness
    // motivation for splitting SubmitErrorKind on the error-return side.
}

#[non_exhaustive]
pub enum DiscardReason {
    ConsumerExplicit,
    DaemonRejectedTerminal { kind: TerminalErrorKind },
    TTLAutoDiscard,
    // SnapshotRotationAutoDiscard REMOVED — segment-2h pins lazy R5;
    // snapshot rotation drives no automatic collection moves at V3.0;
    // consumer learns at submit-time via SubmitError::SnapshotInvalidated.
    // V3.x eager-discard opt-in (FOLLOWUPS §5.6.7 P9 trigger) reintroduces
    // the variant alongside selective-discard substrate.
}
```

**P4 collection-moves table.** For each `SubmitErrorKind`
the daemon returns at the round-trip completion:

| Outcome | `in_flight[rid]` move | `output_locks` for rid | Diagnostic emission | Trait return |
|---|---|---|---|---|
| `Accepted` | drop | release | `SubmitSucceeded { rid, tx_hash }` | `Ok(tx_hash)` |
| `TerminalErrorKind::DoubleSpend` | drop | release | `Discarded { rid, DaemonRejectedTerminal::DoubleSpend }` | `Err(DaemonRejectedTerminal::DoubleSpend)` |
| `TerminalErrorKind::FeeTooLow` | drop | release | `Discarded { rid, DaemonRejectedTerminal::FeeTooLow }` | `Err(DaemonRejectedTerminal::FeeTooLow)` |
| `TerminalErrorKind::Malformed` | drop | release | `Discarded { rid, DaemonRejectedTerminal::Malformed }` | `Err(DaemonRejectedTerminal::Malformed)` |
| `AmbiguousErrorKind::DaemonTimeout` | retain | retain | `SubmitPendingResolution { rid, DaemonTimeout }` | `Err(DaemonAmbiguous { DaemonTimeout, rid })` |
| `AmbiguousErrorKind::DaemonUnavailable` | retain | retain | `SubmitPendingResolution { rid, DaemonUnavailable }` | `Err(DaemonAmbiguous { DaemonUnavailable, rid })` |

The ambiguous cases preserve in-flight ownership per the
F2 ownership-boundary disposition; the terminal cases
release the locks because the daemon's authority has
resolved the reservation's lifecycle. The consumer
distinguishes the two classes by matching on `SubmitError::DaemonRejectedTerminal`
vs. `SubmitError::DaemonAmbiguous`; pattern matching
reaches the variant set without losing lifecycle context.

### §5.6.5 Per-finding dispositions

**F1 — Stage 1 / Stage 4 staleness-detection asymmetry
pin (prose tightening; §5.0 / §5.0.1 / §5.0.2).** Segment
2g's framing ("submit-time staleness is detected by field
comparison in the message handler; not a CAS in the
contract sense") is correct on the no-CAS-needed point
but overstates what mailbox-FIFO delivers under Stage 4.
The trait contract is "submit-time staleness is detected
up to actor-local ledger view"; the property the trait
**actually delivers** differs between stages:

- **Stage 1 (`LocalPendingTx`).** `Engine::submit_pending_tx`
  reads `self.ledger.snapshot()` synchronously at the
  orchestration-layer wrapper before calling
  `self.pending.submit(&snapshot, reservation)`. Submit-time
  staleness detection is **exact** because the snapshot
  is sourced from the same `&mut Engine`-locked
  `LedgerEngine` at the moment `submit` runs. The
  "field comparison" framing is sound under Stage 1 by
  virtue of lock-based serialization.

- **Stage 4 (`PendingTxActor`).** `current_snapshot` is
  push-driven from `LedgerDiagnostic::SnapshotMerged`
  events that compete with `Submit` messages in the
  same mailbox FIFO. If `Submit(reservation)` arrives
  ahead of `SnapshotMerged { new, prior }` in the
  mailbox, the field comparison reads the stale
  `current_snapshot` (which still equals the
  reservation's `snapshot_id`), the staleness check
  passes, and the stale tx ships to the daemon. The
  daemon's authority resolves: accept → outputs unspent
  on-chain; reject `DoubleSpend` → outputs spent. **No
  consensus violation; submit-time staleness detection
  is best-effort under actor mailbox ordering, not
  exact.** R9 daemon-side authority is the
  consensus-correct ground.

The trait surface invariance pin per §5.0.1 is unchanged
— the method signature is invariant Stage 1 ↔ Stage 4;
the staleness-detection property delivered by the
synchronous trait surface differs between stages but
**both stages satisfy the trait contract** ("up to
actor-local ledger view"). Stage 1 delivers the stronger
"up to ledger truth" property by virtue of synchronous
access. The pin closes the prose ambiguity without
reshaping the contract.

**F2 — ownership-boundary disposition (state-machine
gap closure; segment-2f R9 table reshape).** The
state-machine-row framing of segment-2f's R9 per-error-class
table didn't cover consumer-initiated transitions on
in-flight reservations. Under the lean shape, the
disposition is structurally cleaner — the actor owns
the reservation while it's in `in_flight`; the consumer
transferred ownership on `submit`; the only way out is
daemon resolution or TTL safety-net. The disposition
table reshape (§5.6.3 `discard` flow; §5.6.4 P4 table)
returns `PendingTxError::DiscardBlockedPendingDaemonAck
{ reservation_id }` for the F2 case and the symmetric
`PendingTxError::SubmitAlreadyPending { reservation_id
}` for the re-submit-during-in-flight case.

The consumer's resolution surface for in-flight
reservations is enumerated: (i) wait for the daemon
round-trip; (ii) the R8 TTL safety-net (V3.x
`ReservationTTLActor` per §5.4 R8, configured with
`in_flight` per-collection TTL per F7); (iii) restart
and accept the F8 surface.

**(c) ergonomic alternative considered; FOLLOWUPS V3.x
entry.** Two non-disposition shapes were enumerated:
(b) queue cancel-after-complete (consensus-dangerous —
consumer thinks cancelled, tx live on network, wallet
treats outputs as released, next build may re-spend);
(c) `discard_requested: bool` flag on `InFlightSubmit`,
reconciled at `SubmitCompleted` arrival. (c) is
consensus-honest about the surface ("discard during
daemon round-trip is a request, not a guarantee;
daemon authority resolves") but adds state-machine
complexity; V3.0 ships (a) with (c) as the FOLLOWUPS
V3.x ergonomic refinement (§5.6.7 (c) entry).

**F3 — `Signer::Error` / `FeeEstimatorError` /
`OutputSelectorError` formatter-trait discipline pin
(§3.1 documentation).** Phase 0h pins `type Error:
Debug + Display + Send + Sync + 'static`; Debug/Display
outputs routinely land in logs through standard
tracing/log infrastructure. An HW-wallet `Signer` impl
whose `Error` carries device-side attestation challenges,
intermediate signing state, or partial-signature
material leaks via standard log infrastructure. The
trait bounds can't syntactically enforce "no sensitive
material in Error projections"; a §3.1 documentation
pin names the discipline:

> **`Signer::Error` and its `Debug` / `Display`
> projections MUST NOT carry sensitive material** —
> spend-secret bytes, intermediate signing scalars,
> partial-signature material, HW-wallet device-side
> attestation challenges, or any intermediate state
> that downstream review would classify as
> Zeroize-required. Implementors structure their
> error types so `Debug` projects only the discriminant
> plus non-sensitive context; sensitive material
> returned by HW devices is wiped from the Error
> structure (via `Zeroizing<…>` wrapping that is then
> consumed during Error construction, leaving the
> outward-facing Error free of secret material).

The discipline transitively covers `FeeEstimatorError`
and `OutputSelectorError` at reduced priority (these
types don't normally hold spend material but the
discipline pin is uniform across the secret-locality
boundary).

**F4 — `OutputSelector` subset-verification caller-side
discipline (P-F4 binding test; C5β body amendment).**
Phase 0i's `fn select_outputs(&self, candidates:
&[OutputCandidate], target: Amount) -> Result<SelectedOutputs,
SelectionError>` has no syntactic constraint that
`SelectedOutputs ⊆ candidates`. A bug or malicious
`OutputSelector` impl returning outputs not in
`candidates` either fails downstream at tx construction
or silently corrupts (depending on what downstream
verifies).

**Caller-side discipline (lands in `LocalPendingTx::build`
body; C5β scope amendment).** Post-`select_outputs` call,
verify each returned index against the filtered
candidate set; reject with `OutputSelectorError::ReturnedIndicesNotSubset
{ offending_index }` if violated. The check is in the
caller's body, not the trait surface — the trait can't
syntactically enforce subset, but the caller's
verification is structural. C5β's test deliverable
inventory grows by `wallet_greedy_selector_returns_subset`
(regression for the default impl) and
`faulty_selector_returns_non_subset_rejected` (using a
`FaultyOutputSelector` test impl that returns an index
outside the candidate set).

**F5 + F6 — temporal- and distributional-projection
disciplines named in §5.0.3 (V3.x deferred).** The
recursive-trust-boundary contract per §5.0.3 (and PR 4
§5.4.8 #4) addresses **field-level projection**: what
each event reveals about wallet-internal state. It
doesn't address:

- **Temporal projection (F5).** `SubmitAttempted →
  SubmitSucceeded` firing at a stable wallet-internal
  delay before the daemon-side network broadcast is a
  wallet-attribution surface independent of any field
  elision. R15's `SubmissionStrategyActor` slot
  mitigates on-network timing (jitter, batched
  submission, circuit rotation) but not on-stream
  timing for cross-trust-boundary diagnostic consumers
  that observe the emission delay between
  `SubmitAttempted` and `SubmitSucceeded`.

- **Distributional projection (F6).** Distinct from F5
  but same category. Over wallet lifetime, the
  distribution of the `DiscardReason` variants
  fingerprints wallet behavior even with
  `reservation_id` elided (frequent `TTLAutoDiscard` =
  build-without-submit patterns possibly indicating
  multisig coordination; frequent `DaemonRejectedTerminal::DoubleSpend`
  = aggressive re-quote workflows; etc.).

**§5.0.3 amendment.** The contract list grows by a
seventh discipline:

> **Temporal and distributional projection
> (§5.0.3 amendment).** Field-level projection
> (§5.0.3 recursive-trust-boundary) addresses what
> each event reveals; **temporal-level projection**
> addresses what the timing of events between actors
> reveals; **distributional-level projection** addresses
> what the long-running shape of the event stream
> reveals. Cross-trust-boundary consumers MUST apply
> all three disciplines. **V3.0 ships field-projection
> only.** The V3.x consumer-actor PRs (the first PR
> introducing the first cross-trust-boundary
> diagnostic consumer) land the temporal- and
> distributional-projection disciplines as part of
> the consumer-actor's design rounds, settling the
> specific patterns (event coalescing, bucketed
> emission, strategy-aligned emission delay,
> variant-distribution rate-limiting, distributional-noise-injection)
> against the threat model of the specific consumer.
> `DIAGNOSTIC_STREAM.md` (V3.x; rename-from-`REFRESH_DIAGNOSTIC_STREAM.md`
> closed in segment 2g (a)) carries the patterns'
> spec content.

The §5.0.3 prose grows by a single new bullet under
the existing six-bullet contract list; FOLLOWUPS for
`DIAGNOSTIC_STREAM.md` is amended to include the
temporal/distributional discipline as scope (§5.6.7).

**F7 — per-collection `ReservationTTLConfig` V3.0
surface (Phase 0l addition; segment-2e R8 amendment).**
Under the lean shape, the two collections age on
distinct clocks: `consumer_held` ages from creation
timestamp (consumer-side decision delay; rebuilding
recommended after TTL); `in_flight` ages from
submission timestamp (daemon-side ambiguity; R8's V3.x
`ReservationTTLActor` is the safety-net consumer per
§5.4 R8). The V3.0 surface admits per-collection TTL
configuration; the V3.x `ReservationTTLActor` consumes
the per-collection config without requiring a V3.0
surface revision.

**New Phase 0l binding form.**

```rust
#[non_exhaustive]
pub struct ReservationTTLConfig {
    pub consumer_held: Duration,
    pub in_flight: Duration,
}

impl Default for ReservationTTLConfig {
    fn default() -> Self {
        Self {
            consumer_held: DEFAULT_RESERVATION_TTL,
            in_flight: DEFAULT_RESERVATION_TTL,
        }
    }
}
```

V3.0 carries no emitter (no V3.0 component ages
reservations against the config; the type is the V3.0
surface the V3.x `ReservationTTLActor` consumes).
V3.0 default is uniform across collections; V3.x
admits any per-collection aging policy without V3.0
surface revision. **Architectural-integrity-now
disposition:** if V3.0 ships `pub struct ReservationTTLConfig(Duration)`
(collapsed), V3.x inherits a uniform-TTL constraint
that V3.x's threat-model analysis is likely to relax,
requiring a V3.0-surface revision at V3.x landing
time. Per-collection surface from the start forecloses
the revision.

**F8 — restart-during-`in_flight` consequence
explicit V3.0 acceptance pin (§5.4 R17 prose
tightening).** Per PR 4 §5.4.8 #1 carryover (already
pinned in §5.4 R17), V3.0 drops in-memory reservation
state on close. A reservation in `in_flight` at
restart-time is gone from the tracker; the daemon-broadcast
tx may be live on the network. F8 makes the explicit
consequence load-bearing:

> **Restart-during-`in_flight` consequence (V3.0
> acceptance).** A reservation in `in_flight` at
> restart-time is gone from the tracker. Next-refresh
> reconciles the on-chain state if the daemon
> confirmed the tx before restart; during the
> reconciliation gap, a consumer rebuild may
> re-select the same outputs and produce a daemon
> `DoubleSpend` rejection on the rebuild's submit.
> **V3.0 accepts this surface explicitly** — the
> rebuild's `DoubleSpend` is consensus-correct (the
> outputs *are* spent on-chain by the prior tx); the
> consumer rebuilds against the post-reconciliation
> snapshot. **V3.x R17 encrypted-persistence opt-in
> closes the gap** for institutional / long-running /
> multi-day workflows that cannot tolerate the
> rebuild rejection; reopening criteria per §5.4 R17
> hardened disposition (PR 4 Round 4 review pass F1
> carryover).

### §5.6.6 Per-probe dispositions

**P1 — `outstanding() -> usize` retained per §2.4
binding.** V3_ENGINE_TRAIT_BOUNDARIES.md §2.4
binds the projection as count
(`fn outstanding(&self) -> usize`); segment 2h
preserves the binding without surface revision.
ID-enumeration semantics are recoverable from
diagnostic-stream subscription (`BuildSucceeded`,
`Discarded`, `SubmitSucceeded`, `Discarded` events
each carry `ReservationId`); committing the
synchronous trait surface to ID-enumeration would
expand the trait contract beyond what V3.0
substrate needs. §5.0.1 prose names the
ID-via-diagnostic-stream pattern explicitly so the
implementation discipline is visible to reviewers.

**§2.4 ownership-prose amendment.** The §2.4
ownership clause currently names the tracker shape
as `BTreeMap<ReservationId, Reservation>`. Segment
2h amends the ownership prose to name the (γ)
three-collection lean shape (`output_locks` +
`consumer_held` + `in_flight`); the §2.4 trait
surface (the rust block) is unchanged. The
amendment is an implementation-note refinement
that PR 5 lands without revisiting the §2.4 trait
binding.

**P2 — discriminated error taxonomy across re-submit
and consumer error cases.** Under (γ) the actor
distinguishes (consumer's reservation is in
`in_flight` → owner-boundary), (consumer's
reservation never existed or already resolved →
gone) at the handler level. The discriminated
taxonomy lands two new error variants beyond F2's
`DiscardBlockedPendingDaemonAck`:

- `PendingTxError::SubmitAlreadyPending { reservation_id }`
  — the re-submit case (consumer's `Reservation`
  was already moved to `in_flight` by a prior
  `submit` call); ownership-boundary parallel to
  F2's discard case.
- `PendingTxError::ReservationNotFound
  { reservation_id }` — never existed or already
  resolved; gone is gone (P3).

**P3 — unified `ReservationNotFound` for never-existed
/ already-resolved cases.** Distinguishing at the
actor level requires the actor to retain ghost
state (resolved-rid set; potentially unbounded
growth without TTL); V3.0 substrate doesn't need the
distinction. The diagnostic stream's emission
history (`BuildSucceeded` and `Discarded` events for
the rid) is the consumer-side reconstruction surface
for "was it ever there." Gone is gone at the actor
level; the diagnostic stream answers the
"was it ever there" question for consumers who need
it.

**P4 — collection-moves table replaces enum-state-transitions
table.** See §5.6.4 above for the table; segment-2f
R9's per-error-class state-transition table is
wholesale-replaced (not amended) under segment 2h.

**P5 — `InFlightSubmit { snapshot_id, created_at,
submitted_at }` admits either V3.x TTL aging policy.**
Per §5.6.3's `submit` flow, the consumer-held
creation timestamp is preserved across the
collection move; the submission timestamp is stamped
fresh. The V3.x `ReservationTTLActor` chooses its
aging clock per-collection: "age from creation"
reads `in_flight[rid].created_at`; "age from
submission" reads `in_flight[rid].submitted_at`;
neither V3.0 surface ages reservations against
either field. The V3.0 surface admits both policies.

**P6 — filter-then-select-then-subset-check ordering
pinned in §5.0.1.** The build handler's invariant
ordering:

1. Fetch raw candidates from `LedgerEngine`.
2. Filter against `output_locks.keys()` — only the
   actor sees `output_locks`; this filtering step
   is the wallet-layer anti-double-spend protection
   the OutputSelector cannot bypass.
3. Hand filtered candidates to `OutputSelector::select_outputs`.
4. F4 caller-side subset check: returned indices ⊆
   filtered candidates.

C5β implementation must follow this ordering. The
discipline pin lives in §5.0.1 prose. Bypassing
filter-and-relying-on-subset-check-after-fact is a
discipline violation; the actor's filtering step is
load-bearing for anti-double-spend even if the
selector is well-behaved, because output_locks may
have entries the selector never sees.

**P7 — actor handler-atomicity pin in §5.0.1.** The
build handler's steps (lock-claim + consumer_held
insert + diagnostic emit + return) and the submit
handler's steps (consumer_held remove + in_flight
insert + dispatch-initiate) and the discard
handler's steps (consumer_held remove + output_locks
removal + diagnostic emit) are atomic under both
Stage 1 (lock-based execution holding `Mutex<ReservationTracker>`)
and Stage 4 (mailbox-FIFO + standard actor-framework
handler-runs-to-completion semantics). No `.await`
between mutation steps; no opportunity for `discard
(id)` to interleave against a partial-state
reservation.

Standard actor frameworks (kameo, riker, actix) deliver
handler-atomicity by default — handlers run to
completion before the next message is processed —
but the discipline is named explicitly in §5.0.1 so
C5β's implementation doesn't accidentally introduce
an await between insert and emit, and so the Stage 4
actor-migration PR doesn't accidentally choose a
framework variant or configuration that breaks the
atomicity property.

**P8 — Stage 4 test-deliverable inheritance pin in
§5.0.1.** The C5β test list (Stage 1) lands the
atomicity properties for the in-process implementor
(`concurrent_build_serialized_by_engine_lock`,
`submit_moves_from_consumer_held_to_in_flight_atomically`,
`discard_atomic_against_output_locks_release`). The
Stage 4 actor-migration PR inherits the obligation
to land the Stage 4 equivalents against the kameo
actor harness: `concurrent_build_serialized_by_mailbox_fifo`,
`submit_dispatch_does_not_yield_between_collection_move_and_daemon_initiate`,
`discard_atomic_across_mailbox_under_concurrent_load`.

Naming the inheritance here in §5.0.1 forecloses
re-derivation in the Stage 4 actor-migration PR's
design rounds; the Stage 4 PR picks up the
obligation and confirms the actor framework's
handler-atomicity guarantee delivers it.

**P9 — lazy R5 preservation; eager R5 V3.x FOLLOWUPS
trigger.** Covered in §5.6.3 above. The V3.x
eager-discard opt-in FOLLOWUPS entry (§5.6.7 P9
trigger) tracks the reopening criteria.

### §5.6.7 V3.x FOLLOWUPS updates

**(c) ergonomic alternative (F2 V3.x trigger).** The
(c) `discard_requested: bool` shape implements the
cancel-after-complete intent under the lean state:

```rust
struct InFlightSubmit {
    snapshot_id: SnapshotId,
    created_at: Instant,
    submitted_at: Instant,
    discard_requested: bool,    // V3.x
}
```

V3.x `discard(rid)` on an `in_flight` reservation
sets `discard_requested = true` (instead of returning
`DiscardBlockedPendingDaemonAck`); reconciliation
at `SubmitCompleted` arrival:

- `Accepted ∧ discard_requested` → tx is live on
  network; consumer's discard intent is
  unenforceable. Outputs are spent on-chain; emit
  `SubmissionAcceptedDespiteDiscard { rid }` (new
  V3.x diagnostic) for consumer transparency.
  Standard `SubmitSucceeded` emission suppressed in
  favor of the override-class.
- `Accepted ∧ !discard_requested` → standard
  `SubmitSucceeded`.
- `TerminalErrorKind::* ∧ discard_requested` →
  treat as consumer's intent satisfied; emit
  `Discarded { rid, ConsumerExplicit }` (not
  `Discarded { DaemonRejectedTerminal::* }` — the
  daemon's rejection is moot to the consumer's
  intent). **Audit/debug-visibility sub-note:** the
  daemon's rejection reason is structurally hidden
  in this case; whether V3.x emits dual events
  (`Discarded { ConsumerExplicit }` + a separate
  `DaemonRejectionMooted { rid, kind:
  TerminalErrorKind }` diagnostic for audit visibility)
  is a V3.x design-rounds question.
- `TerminalErrorKind::* ∧ !discard_requested` →
  standard `Discarded { DaemonRejectedTerminal::* }`.

**Threat-model regression note (V3.x design-rounds
question).** V3.x's `SubmissionStrategyActor`
deliberately delays broadcast to obscure
wallet-network correlation. Under (c), a consumer's
discard arriving before strategy-actor-broadcast
could legitimately cancel; arriving after-broadcast
is unenforceable. Distinguishing these cases at the
consumer-visible API level (e.g., `Discarded {
ConsumerExplicit, broadcast_avoided: bool }`)
would create a timing side-channel that leaks the
strategy actor's broadcast timing back to the
consumer. **(c)'s V3.x implementation MUST present
the two cases identically at the consumer surface,
OR the strategy actor's timing-obscurity property
is degraded.** The design-rounds work to settle (c)
reopens the strategy-actor threat model.

**V3.x trigger.** "Telemetry surfaces consumer-impatience
patterns under (a) (`DiscardBlockedPendingDaemonAck`
errors observed in production at non-trivial frequency
across operational deployments)." Reopening lands in
a coordinated `PendingTxEngine` + `SubmissionStrategyActor`
+ `DIAGNOSTIC_STREAM.md` V3.x design-rounds pass.

**Temporal- and distributional-projection
disciplines (F5+F6 V3.x trigger).** The
`DIAGNOSTIC_STREAM.md` V3.x deferred deliverable
(rename-from-`REFRESH_DIAGNOSTIC_STREAM.md` per
segment-2g closure (a)) gains scope to cover
temporal-projection patterns (event coalescing,
bucketed emission, strategy-aligned emission delay,
projection-time noise injection) and
distributional-projection patterns (variant-distribution
rate-limiting, `DiscardReason` aggregation policy,
distributional-noise-injection). The doc is created
in the V3.x PR introducing the first cross-trust-boundary
diagnostic consumer; the doc's per-stream sections
inherit the temporal/distributional disciplines
alongside field-projection.

**V3.x trigger.** "First V3.x consumer-actor PR
enters design rounds that requires cross-trust-boundary
diagnostic-stream consumption." The doc-creation
work rides on the first-consumer PR; per-consumer
threat-model evaluation drives the specific
disciplines the doc captures.

**V3.x eager-discard-on-snapshot-merge opt-in (P9
trigger).** Reopening criteria:

- Performance telemetry from V3.0 production
  deployment surfaces a fast-snapshot-rotation
  workload where consumer rebuild rates against
  `SubmitError::SnapshotInvalidated` indicate the
  lazy-cleanup performance characteristics are
  load-bearing at scale.
- OR a V3.x performance policy design rounds names
  the lazy-vs-eager tradeoff as a reservation-policy
  configuration surface (similar to F7's per-collection
  TTL).
- AND the substrate refinement to support selective
  eager-discard (expand `consumer_held` to
  `HashMap<ReservationId, ConsumerHeldEntry { created_at,
  snapshot_id }>`) lands as part of the V3.x reopen.

Re-evaluation shape: a V3.x design-rounds pass
covering `R5` reservation-policy refinement; outcome
either lands eager-discard as an opt-in policy
(reintroducing `DiscardReason::SnapshotRotationAutoDiscard`
+ selective-discard substrate) or confirms lazy as
the only V3.x shape (consumer-policy-driven
abandonment via `discard(rid)` is the
alternative).

**F7 V3.x consumer (already FOLLOWUPS'd; segment 2h
amends).** The V3.x `ReservationTTLActor` FOLLOWUPS
entry per §5.4 R8 segment-2e closure is amended to
name the per-collection `ReservationTTLConfig`
consumption pattern. No new FOLLOWUPS entry;
existing entry's scope grows.

**F8 V3.x encrypted-persistence opt-in (already
FOLLOWUPS'd; segment 2h amends).** The V3.x
encrypted-persistence opt-in FOLLOWUPS entry per
§5.4 R17 hardened disposition (PR 4 Round 4 review
pass F1 carryover) is amended to name the
restart-during-`in_flight` consequence as the
specific surface this opt-in closes. No new
FOLLOWUPS entry; existing entry's scope grows.

**V3.x optional inverse-index seam (γ perf trigger).**
If V3.0 wallet usage telemetry surfaces wallet sizes
where O(n) `output_locks` scans dominate handler
latency (unlikely; V3.0 wallet scale per V3_ENGINE_TRAIT_BOUNDARIES.md
§2.4 implementation note bounds the scan), V3.x adds
a maintained-by-actor inverse index
`reservation_to_outputs: HashMap<ReservationId,
BTreeSet<OutputId>>` per §5.6.2's optional perf
seam. Reopening criteria: telemetry-anchored
demonstration of perf regression; the inverse index
is a perf optimization, not an audit shape change.
The maintained-invariant audit obligation is the
re-evaluation shape's compensating discipline.

### §5.6.8 Round 3 §7.X commit-decomposition delta

The §7.X eight-commit Phase 1 commit list (C0–C8)
load-bearing ordering and sub-decomposition (C2 / C4
/ C5) survive segment 2h unchanged. The delta is
within-commit content for six commits:

- **C0 (Phase 0 spec amendment; doc-only).** Scope
  grows to include all segment-2h amendments:
  - §3.1 F3 discipline pin (Signer::Error / FeeEstimatorError
    / OutputSelectorError sensitive-material discipline).
  - §4 Phase 0a reshape (TerminalErrorKind / AmbiguousErrorKind
    split; SubmitError variant set; PendingTxError variant set;
    OutputSelectorError variant addition).
  - §4 Phase 0e lifecycle prose rewrite under lean shape
    (lazy R5 disposition explicit; collection-moves not
    state-transitions).
  - §4 Phase 0f PendingTxDiagnostic reshape (SubmitFailed
    removed; SubmitPendingResolution added; DiscardReason
    variant set reduced under lazy R5).
  - §4 new Phase 0l (`ReservationTTLConfig { consumer_held,
    in_flight }`).
  - §5.0.1 actor-internal state sketch rewrite under (γ)
    lean shape; P6 / P7 / P8 prose pins.
  - §5.0.2 collection-moves table replaces enum-state-transitions
    table; SubmitError reshape; P4 ambiguous-vs-terminal
    framing.
  - §5.0.3 seventh contract pin (F5+F6 temporal- and
    distributional-projection discipline).
  - §5.4 R5 lazy disposition explicit under lean shape;
    SnapshotRotationAutoDiscard removal note + V3.x
    eager FOLLOWUPS pointer.
  - §5.4 R8 per-collection TTL config V3.0 surface pin.
  - §5.4 R9 wholesale rewrite (collection-moves table
    replaces enum-state-transitions table).
  - §5.4 R17 explicit V3.0 acceptance of
    restart-during-`in_flight` surface; V3.x
    encrypted-persistence opt-in closure pointer.

  Plus the corresponding `V3_ENGINE_TRAIT_BOUNDARIES.md`
  §2.4 ownership-prose amendment (tracker shape from
  `BTreeMap<ReservationId, Reservation>` to (γ) lean
  shape; trait surface unchanged) and
  `V3_WALLET_DECISION_LOG.md` entries.

  Net C0 size grows ~30%; still doc-only.

- **C1 (`SnapshotId` opaque type).** Unchanged from
  Round 3 §7.X.

- **C2α (error / discriminant enums; sub-commit
  α).** Scope changes:
  - **Removes:** `ReservationState` enum (no longer
    needed under (γ)); `SubmitErrorKind` unified enum
    (split into `TerminalErrorKind` + `AmbiguousErrorKind`).
  - **Adds:** `TerminalErrorKind`, `AmbiguousErrorKind`,
    `SubmitError::SnapshotInvalidated`,
    `SubmitError::DaemonRejectedTerminal { kind }`,
    `SubmitError::DaemonAmbiguous { kind, reservation_id }`,
    `SubmitError::ReservationNotFound { reservation_id }`,
    `SubmitError::SubmitAlreadyPending { reservation_id }`,
    `PendingTxError::DiscardBlockedPendingDaemonAck { reservation_id }`,
    `PendingTxError::SubmitAlreadyPending { reservation_id }`,
    `PendingTxError::ReservationNotFound { reservation_id }`,
    `OutputSelectorError::ReturnedIndicesNotSubset { offending_index }`.

- **C2β (discriminant projections; sub-commit β).**
  Scope follows C2α. The `BuildFailureClass`
  projection grows by `SelectorContractViolation`
  (mirrors `OutputSelectorError::ReturnedIndicesNotSubset`
  in the projection taxonomy).

- **C2γ (timestamps / config types; sub-commit γ).**
  Scope changes:
  - **Removes:** `Reservation::state` field (no longer
    needed under (γ)).
  - **Adds:** `ReservationTTLConfig { consumer_held,
    in_flight }` with `Default` impl yielding uniform
    `DEFAULT_RESERVATION_TTL`; `InFlightSubmit
    { snapshot_id, created_at, submitted_at }` as
    actor-private type.

- **C3 (`PendingTxDiagnostic` enum + emission
  infrastructure).** Scope changes:
  - **Removes:** `PendingTxDiagnostic::SubmitFailed`
    (no surviving emission site under P4 table).
  - **Adds:** `PendingTxDiagnostic::SubmitPendingResolution
    { reservation_id, kind: AmbiguousErrorKind }`.
  - **Updates:** `DiscardReason` variant set —
    `SnapshotRotationAutoDiscard` removed under lazy
    R5 (V3.x eager-discard opt-in FOLLOWUPS
    reintroduces); `DaemonRejectedTerminal` payload
    changes from no-payload to `{ kind: TerminalErrorKind }`.

- **C4 (`Signer` / `OutputSelector` / `FeeEstimator`
  trait surfaces + default impls).** Scope unchanged
  at the trait-surface level. C4α `Signer` trait
  documentation grows by the F3 sensitive-material
  discipline pin (doc-comments on `type Error`).
  C4β `OutputSelector` trait documentation grows by
  the F4 caller-side subset re-verification
  discipline pin (doc-comments on `select_outputs`
  naming the caller's responsibility).

- **C5β (`PendingTxEngine` trait-impl bodies;
  `LocalPendingTx` internals).** Bodies are
  wholesale-rewritten as collection-moves rather
  than enum-state-mutations:
  - `LocalPendingTx::build` body:
    1. Fetch raw candidates from `LedgerEngine`.
    2. Filter against `output_locks.keys()` (P6).
    3. Call `OutputSelector::select_outputs` on
       filtered candidates.
    4. Subset-verification check on returned indices
       (F4; rejects via
       `OutputSelectorError::ReturnedIndicesNotSubset`).
    5. Allocate fresh `ReservationId`.
    6. Atomically (P7): insert `output_locks` entries;
       insert `consumer_held[rid] = now`; emit
       `BuildSucceeded`; return `Reservation`.
  - `LocalPendingTx::submit` body:
    1. Match `(in_flight.contains_key, consumer_held.contains_key)`
       per §5.6.3 success/error dispatch.
    2. Staleness check vs `current_snapshot` (lazy R5).
    3. Atomic move (P7): `consumer_held → in_flight`
       with preserved `created_at` + fresh `submitted_at`.
    4. Dispatch to `Signer` and `DaemonEngine`.
    5. Reconcile per P4 table at daemon response.
  - `LocalPendingTx::discard` body:
    1. Match `(in_flight, consumer_held)` per
       §5.6.3 dispatch (F2 `DiscardBlockedPendingDaemonAck`
       for in_flight; `ReservationNotFound` for both-empty).
    2. Atomic (P7): remove from `consumer_held`;
       sweep `output_locks` for rid-matching entries;
       emit `Discarded { rid, reason }`.
  - `LocalPendingTx::outstanding` body: returns
    `consumer_held.len() + in_flight.len()`.

  Test deliverables grow:
  - `wallet_greedy_selector_returns_subset` (F4
    regression).
  - `faulty_selector_returns_non_subset_rejected`
    (F4 negative case via `FaultyOutputSelector`).
  - `discard_blocked_during_in_flight` (F2).
  - `submit_already_pending_during_in_flight` (P2).
  - `consumer_held_reservation_releases_locks_on_discard`.
  - `submit_moves_from_consumer_held_to_in_flight`.
  - `submit_completed_terminal_releases_locks` (one
    per `TerminalErrorKind` variant).
  - `submit_completed_ambiguous_retains_in_flight`
    (one per `AmbiguousErrorKind` variant).
  - `concurrent_build_serialized_by_engine_lock`
    (Stage 1 atomicity property).
  - `stage_1_submit_time_staleness_is_exact` (F1
    Stage 1 property).
  - `snapshot_rotation_does_not_sweep_consumer_held`
    (lazy R5).
  - `output_locks_invariant_across_handler_atomicity`
    (P7).

  **Stage 4 P8 inheritance pointer.** The Stage-1-side
  P7 / P8 atomicity tests above
  (`concurrent_build_serialized_by_engine_lock`,
  `submit_moves_from_consumer_held_to_in_flight`
  + collection-move sub-tests,
  `output_locks_invariant_across_handler_atomicity`)
  exercise the in-process `Arc<RwLock<Engine>>` lock
  serialization (Stage 1). The Stage 4 actor-migration
  PR inherits the obligation to land the actor-mailbox-
  serialization equivalents
  (`concurrent_build_serialized_by_mailbox_fifo`,
  `submit_dispatch_does_not_yield_between_collection_move_and_daemon_initiate`,
  `discard_atomic_across_mailbox_under_concurrent_load`)
  against the chosen actor framework (e.g., kameo's
  handler-atomicity guarantee) per the test-deliverable
  inheritance pin in §5.0.1 P8. The cross-reference is
  grep-able from §5.0.1 P8 → §5.6.8 C5β → the Stage 4
  actor-migration PR's design rounds, foreclosing
  re-derivation of the obligation in the Stage 4 PR's
  pre-flight investigation.

- **C6 (`Engine<S, D, L, R, P>` parameterization +
  orchestration-layer dispatch migration).** Scope
  unchanged from Round 3 §7.X. The dispatch wiring
  passes the consumer's `Reservation` value (already
  the trait surface).

- **C7 (`FaultInjecting<P: PendingTxEngine>` +
  property tests + R9 per-error-class coverage).**
  Scope changes:
  - **Removes:** Property tests asserting
    `ReservationState` transitions (no longer
    applicable under (γ)).
  - **Adds:** Property tests for collection
    invariants:
    - `output_locks_membership_iff_some_collection_claims`
      (every `(oid, rid)` in `output_locks` has
      `rid ∈ consumer_held ∪ in_flight`).
    - `consumer_held_and_in_flight_are_disjoint`
      (no rid in both at the same time).
    - `lock_claim_is_monotonic_until_terminal_resolution`
      (a rid's outputs claim doesn't change between
      build and terminal resolution; only the
      collection-membership changes).
  - **R9 per-error-class coverage** (P4 table):
    - `FaultInjecting` configured to yield each
      `TerminalErrorKind` and `AmbiguousErrorKind`
      variant; properties verify the table's
      collection-moves, lock-release, and emission
      claims.
  - **F2 ownership-boundary coverage:** Configure
    `FaultInjecting` to yield `AmbiguousErrorKind::DaemonTimeout`
    → reservation enters `in_flight`; consumer calls
    `discard(rid, ConsumerExplicit)` → assert
    `Err(DiscardBlockedPendingDaemonAck)` returned;
    fault-injector then yields
    `TerminalErrorKind::DoubleSpend` → consumer's
    subsequent `discard(rid)` returns
    `ReservationNotFound` (rid was already moved
    to "gone" by the daemon-resolved terminal class).

- **C8 (docs propagation + CHANGELOG).** FOLLOWUPS
  amendments inventory grows by:
  - F2 (c) V3.x ergonomic refinement candidate (new
    entry; includes the dual-emission sub-note and
    the strategy-actor threat-model regression
    note).
  - F5+F6 temporal- and distributional-projection
    disciplines in `DIAGNOSTIC_STREAM.md` V3.x
    deferred deliverable (existing
    `DIAGNOSTIC_STREAM.md` FOLLOWUPS entry scope
    grows).
  - F7 V3.x `ReservationTTLActor` per-collection
    consumer (existing R8 FOLLOWUPS entry scope
    grows).
  - F8 V3.x encrypted-persistence opt-in
    restart-during-`in_flight` closure (existing
    R17 FOLLOWUPS entry scope grows).
  - P9 V3.x eager-discard-on-snapshot-merge opt-in
    (new entry; includes selective-discard substrate
    trigger and reservation-policy design-rounds
    re-evaluation shape).
  - V3.x optional inverse-index seam (γ perf
    trigger; new entry; telemetry-anchored
    reopening criteria).

The §7.X commit decomposition's load-bearing
ordering is unchanged: C0 lands the doc-only
substrate; C1 lands `SnapshotId`; C2α/β/γ land the
type substrate that subsequent commits consume; C3
lands diagnostic infrastructure; C4α/β/γ land the
trait surfaces; C5α/β lands the aggregate; C6 lands
the orchestration migration; C7 lands the
property-test harness; C8 closes with documentation.

### §5.6.9 Wallet-ecosystem-lessons discipline-citation matrix

Segment 2i records the wallet-ecosystem lessons that the
PR 5 substrate is **getting right by construction** versus
the historical failure modes other cryptocurrency wallets
have absorbed. Each entry pairs the lesson with the
wallet-ecosystem failure mode it forecloses and the
segment/closure that landed the discipline. The matrix is
audit-attention surface for Phase 9 audit and post-V3.0
reviewers asking "why this substrate shape over the
obvious-from-other-coins shape?"

| # | Discipline | Failure mode foreclosed | Substrate / closure |
|---|------------|--------------------------|---------------------|
| 1 | **Submit-time staleness detection over optimistic ignore-and-fail.** Staleness is detected at submit-time field comparison; consumer receives rich `SubmitError::SnapshotInvalidated { reservation_snapshot, current_snapshot }` context; consumer-explicit `discard(rid, ConsumerExplicit)` releases the output locks. | Many wallets historically ignored snapshot drift and let the daemon reject; users saw cryptic errors with no recovery context. | R5 lazy-discard (segment-2e closure; segment-2h preservation). |
| 2 | **Daemon-side authority for ambiguous outcomes over local-optimistic resolution.** `AmbiguousErrorKind::{DaemonTimeout, DaemonUnavailable}` keeps the reservation in `in_flight` (output locks retained); consumer-explicit discard is blocked per F2; R8 TTL is the safety-net; the daemon eventually resolves. | Bitcoin / Ethereum wallets routinely show "sent" status on tx the daemon never acknowledged; user reports the tx as sent; on-chain it never lands; recovery is painful. | F2 ownership-boundary disposition (segment-2h closure). |
| 3 | **Ownership-boundary discipline over state-machine-row enumeration.** `PendingTxActor`'s internal state is **collection membership**, not an explicit `ReservationState` enum; `consumer_held` vs `in_flight` is the lifecycle encoding; F2 is "the consumer transferred ownership on submit; the only way out is daemon resolution or TTL" not "state X doesn't admit consumer-discard." | Most wallets bake explicit state machines that grow per-error-class rows over time, accumulating denormalization hazards and audit-surface bloat. | (γ) lean state shape (segment-2h closure). |
| 4 | **Privacy-by-default fee estimation.** `FeeEstimator` trait surface is wallet-side; daemon-recommended-fee paths are explicitly named as fingerprint surfaces; R16 V3.x `WalletSideEstimator` is the V3.x trajectory. | Many wallets use daemon-recommended fees by default, broadcasting "this wallet just asked for a fee estimate" timing/correlation signals to the daemon. | R16 disposition (segment-2c closure with segment-2d V3.0-lift evaluation). |
| 5 | **Submission strategy abstraction.** `SubmissionStrategyActor` topology slot pins broadcast timing / routing as wallet-layer privacy decisions, not engine-internal hardcoded behavior; V3.x consumer-actor patterns ride the slot additively. | Most wallets hardcode "send immediately on signing complete" which fingerprints the user's signing time. | R15 disposition (segment-2c closure). |
| 6 | **Spend-material locality.** `Signer` is a separate trait / `SigningActor` is a separate actor; `LocalPendingTx` / `PendingTxActor` never holds spend material; HW-wallet integration in V3.x is a `Signer`-impl substitution against the same boundary. | Many wallets keep keys in process-wide memory; key disclosure compromises everything; HW-wallet integration is awkward retrofit. | R11 (b) split (segment-2b closure). |
| 7 | **Snapshot pinning over implicit "current state" assumption.** `Reservation::snapshot_id` is the build-time pin; staleness checks compare it to the actor-local `current_snapshot` at submit-time; the actor explicitly admits "up to actor-local ledger view" qualification under Stage 4 per F1. | Many wallets implicitly assume "the chain state I saw 5 minutes ago is still current" leading to silent inconsistency under reorgs. | R1 + R2 dispositions (Round 1 / segment-2d closures). |

The matrix is grep-able from the segment-2i commit (audit
trail discipline per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
continuous-discipline-as-inheritance-prevention corollary).
New disciplines that pass the same lens land here as the
substrate extends; the matrix is the running tally rather
than a closed list.

### §5.6.10 G1–G5 V3.0 substrate dispositions

The five gaps requiring V3.0 substrate. Each entry names the
gap, cites the failure-mode it forecloses, and records the
disposition.

**G1 — Mempool eviction without daemon notification.**

*Gap.* Real-world daemons silently drop txs from mempool
under fee-market pressure, mempool-capacity refills, or
peer-policy filters. The daemon doesn't notify because from
its perspective the tx is simply not there anymore. Under
the segment-2h substrate, an evicted tx stays in `in_flight`
until R8 TTL fires — potentially hours, with output locks
held the entire time and the consumer believing the tx is
live. The R8 TTL safety-net is correct but late; consumer
observability is delayed.

*Disposition (V3.0 substrate).* Three pieces:

1. **`DiscardReason::MempoolEvicted` variant.** Pinned in
   §4 Phase 0f reshape. Terminal-resolution path for
   eviction-signal. V3.0 has no in-process emitter; V3.x
   `MempoolMonitorActor` consumer-actor is the emitter.
2. **`tx_hash: TxHash` projection field on
   `SubmitSucceeded` and `SubmitPendingResolution`.** Pinned
   in §4 Phase 0f reshape. The V3.x `MempoolMonitorActor`
   needs to query the daemon's mempool by tx hash; the
   `InFlightSubmit` actor-private state holds the hash but
   isn't accessible to the consumer-side actor; diagnostic-
   stream projection is the access path. Hash is on-chain
   by construction (not secret material); field-level
   projection is admissible at the recursive-trust-boundary
   discipline per PR 4 §5.4.8 #4.
3. **`PendingTxEngine::signal_mempool_evicted(rid)` trait
   method.** Pinned in §4 Phase 0m. The narrow-vs-wide
   method-shape question is adjudicated per F2's
   network-trust-boundary discipline:

   - **Narrow rationale (load-bearing).** Mempool eviction
     is an *observation* the consumer made that the actor
     couldn't make itself (the actor has no direct
     visibility into daemon-mempool state); the observation
     is *of a state that's already terminal at the network
     level* (the tx is gone from the mempool; the daemon
     will never Accept it). The signal admits one specific
     observation under F2's discipline.
   - **Wider shape rejected.** A wider
     `signal_external_terminal(rid, reason)` shape would
     silently admit *decision-class* signals (e.g., a
     hypothetical `signal_user_force_cancel` candidate)
     that F2 forbids. The narrow shape preserves the
     per-method F2 adjudication grep-ability that the
     wider shape forecloses. **Per
     [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
     named-criteria principle:** if a second observation-
     class consumer surfaces (e.g.,
     `signal_peer_dropped` from a hypothetical
     `PeerHealthMonitorActor`), the disposition is "add a
     second narrow method against F2 adjudication," not
     "regret the narrow shape." Two methods is still
     cleaner than the wide shape because the F2
     adjudication is grep-able per-method.
   - **Reopening criterion.** Any future "consumer signals
     terminal" candidate undergoes its own F2 adjudication.
     If three or more narrow methods accumulate AND all
     three pass F2 adjudication on identical grounds,
     consolidation into a wider shape is permitted — but
     the consolidation is a substrate-anchored decision,
     not a convenience anti-pattern.

*Failure mode foreclosed.* Bitcoin/Lightning ecosystem
wallets historically left users in "pending forever" UI
states for evicted txs because the wallet-side stack
trusted "daemon will tell us" semantics that the daemon
doesn't provide. The V3.0 substrate makes the consumer-
observer responsible (the wallet UI / mempool-monitor-
actor knows the daemon better than the engine does); the
F2 discipline ensures the signal is observation-class only.

**G2 — Long-range reorg of confirmed txs.**

*Gap.* A tx that previously hit `SubmitSucceeded` and
confirmed gets reorged out at depth. The reservation is
gone from `PendingTxState` by then (P4 collection-moves
dropped the rid from `in_flight` at terminal resolution);
the outputs come back as unspent in `LedgerEngine`'s
candidate set on the surviving chain; the next build sees
them as available; no double-spend risk; the only rough
edge is the consumer-visible UI ("confirmed →
unconfirmed → re-confirmed").

*Disposition (V3.0 substrate).* **Out-of-scope for
`PendingTxEngine`; `LedgerDiagnostic`-domain.** Three
alternatives evaluated:

- (a) **Out of scope; `LedgerEngine` handles.** ✅ Adopted.
  The reorg-detection runs in `RefreshEngine` /
  `LedgerEngine`; the V3.x consumer-actor PR introduces
  `LedgerDiagnostic::TxReorgedOut { tx_hash,
  prior_block_height }` additively per Phase 0g's
  deferred-to-consumer-PR pattern; the consumer-side UI
  layer subscribes to the variant and updates its
  tx-history view.
- (b) **`PendingTxActor` re-adds reorged-out tx to
  `in_flight` for re-submission.** Rejected. The actor
  would need to retain the rid → tx_hash mapping past
  terminal resolution; the (γ) lean shape was designed
  to forbid this exact bloat. Also, re-submission is a
  *consumer policy decision* (the user may not want to
  re-broadcast at the same fee), not an engine
  decision.
- (c) **`PendingTxActor` emits
  `PendingTxDiagnostic::TxReorgedOut { rid, tx_hash }`.**
  Rejected for the same (γ) state-bloat reason as (b) —
  emitting the diagnostic requires retaining the
  rid → tx_hash mapping past terminal resolution.

*V3.0-accepted-UX surface pin.* V3.0 ships with the
consensus-correct behavior plus the V3.0-accepted UX-
roughness pin parallel to F8's restart-during-`in_flight`
acceptance: the brief consumer-visible "confirmed →
unconfirmed → re-confirmed" indicator is V3.0-accepted;
V3.x `TxConfirmationTrackerActor` closes the UX gap
additively without `PendingTxEngine` trait revision.

*Failure mode foreclosed.* No `PendingTxEngine` state-bloat;
no rid-retention-past-terminal anti-pattern. The wallet-
ecosystem failure mode would be "track everything forever
just in case it reorgs" which is a memory-and-audit-surface
explosion.

**G3 — Transaction replacement / fee-bump structural
rejection.**

*Gap.* RBF / CPFP-equivalent semantics exist in other
ecosystems because real-world fee markets are volatile and
txs get stuck. Without replacement, the user's only recourse
on a truly-stuck tx is to wait or to perform out-of-band
operations that may violate wallet safety invariants.

*Disposition (V3.0 substrate).* **Structural rejection per
R18 closure (§5.4 R18).** Two reopening criteria named per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc):

1. **FCMP++ cryptographic fingerprint-unobservability
   analysis.** Demonstrates that mempool observers can't
   link key images across mempool snapshots; the replacement
   fingerprint is cryptographically muted; priority-2 cost
   dissolves.
2. **R16 V3.x `WalletSideEstimator` telemetry-driven
   priority-class re-classification.** Demonstrates that
   fee-estimation improvements are insufficient to prevent
   stuck-tx scenarios at user-impact-significant rate;
   stuck-tx-recovery promotes from priority-3 UX to
   priority-1 security/integrity (users lose funds to
   unrecoverable stuck txs).

The criteria are *alternatives*, not conjunctive; both are
substrate-anchored. **The load-bearing piece of criterion 2
is the priority-class promotion, not the user-impact rate
itself.** Without the promotion, the reopening criterion
reduces to "users complain at production scale," which
`00-mission.mdc` priority hierarchy already rejects.

*Phase 0 implication.* No V3.0 trait-surface change; no
`replace` method on `PendingTxEngine`; no
`ReservationExtension::Replacement` pre-pin on R14's
extensibility seam.

*Failure mode foreclosed.* Bitcoin-ecosystem RBF privacy
regression accepted by default; many wallets ship RBF
without explicit privacy-vs-UX trade-off review. The V3.0
substrate explicitly trades against the priority hierarchy
and names the reopening conditions.

**G4 — HW-wallet signing latency under Stage 4 actor.**

*Gap.* HW devices routinely take 5–30s for user
confirmation; under Stage 4, a single-step submit handler
that calls `Signer::sign` synchronously would block
`PendingTxActor`'s mailbox FIFO for that duration,
serializing multisig coordination / batch operations /
concurrent build flows behind a single user tap.

*Disposition (V3.0 substrate).* **Multi-step submit at
Stage 4** (`submit_start` → `submit_signed` →
`submit_completed` self-continuation per §5.0.1) +
**deferred-reply substrate-confirmation pin** binding the
Stage 4 actor-migration PR's framework-selection
pre-flight. Three pieces:

1. **Multi-step shape pinned in §5.0.1 Stage 4 prose.**
   Each handler step is P7-atomic; the submit operation as
   a whole is non-atomic by design; the signing-latency
   window is absorbed in the gap between (1) and (2);
   `PendingTxActor`'s mailbox processes other messages
   during the wait.
2. **Stage 1 stays single-step.** Synchronous lock-based
   serialization absorbs the signing-latency cost as
   caller-blocking — exactly the desired behavior in the
   in-process single-thread CLI case (which is the Stage 1
   deployment target per the PR-2 / PR-3 / PR-4 precedent).
3. **Deferred-reply substrate-confirmation pin.** The
   multi-step shape requires the Stage 4 actor framework to
   support **deferred-reply semantics** (the actor accepts a
   request, captures the reply-context, dispatches one or
   more self-continuations, processes other mailbox
   messages, and resolves the captured reply-context on a
   later self-message). The canonical implementation in
   `kameo` is `Context::reply_later() -> DelegatedReply`;
   other Rust actor frameworks have their own surface for
   the same semantic. **The Stage 4 actor-migration PR's
   framework-selection pre-flight MUST confirm substrate
   support before adopting any framework.**

*Reopening criterion.* If no candidate-set framework
supports deferred-reply, G4's disposition reopens at the
framework-selection altitude with two named alternatives:
(a) trait-surface revision — `submit` returns a handle and
consumers await it separately, admitting trait-surface
non-symmetry between Stage 1 and Stage 4; (b) framework-
pattern revision — spawn an ephemeral per-submit actor
that holds the reply context and the three-step state
machine internally. The reopen lands at the Stage 4 PR's
design-rounds altitude, NOT retroactively against PR 5;
PR 5's V3.0 trait surface stays synchronous regardless.

*Why the pre-flight pin is load-bearing now.* Phase 1
implementation in PR 5 doesn't land Stage 4; the
framework-selection gap wouldn't surface in Phase 1 review.
By naming the substrate-confirmation pin now, the Stage 4
actor-migration PR's design rounds inherit the obligation
as a known pre-flight item rather than discovering it
mid-Phase-1 implementation and triggering the cost-benefit-
defer-to-later anti-pattern at the framework-selection
altitude. Per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
naming the load-bearing question at the design altitude
where the answer is cheap, not at the implementation
altitude where the answer is expensive.

*Failure mode foreclosed.* HW-wallet integration retrofit
in many wallets ships with single-tap-blocks-everything
behavior; multisig coordination devolves to "wait your
turn" UX with no per-signer concurrency. The V3.0
substrate pre-pins the Stage 4 concurrency property
ahead of the framework choice.

**G5 — Output maturity filtering.**

*Gap.* `LedgerEngine`'s candidate-fetch method returns
outputs assigned to this wallet's keys. If the candidate set
includes immature outputs (within `FCMP_REFERENCE_BLOCK_MIN_AGE`
reorg-safety window; coinbase-output unlock period; any V3.x
staking-output maturity period), `OutputSelector` might
select them and fail at tx construction / get daemon-
rejected.

*Disposition (V3.0 substrate).* **`LedgerEngine` trait-
contract domain.** `LedgerEngine`'s candidate-fetch method
filters by maturity *by contract*; the V3.0 PR 5 substrate
does not duplicate maturity-filtering at the
`PendingTxActor` build flow. The right disposition is a
**forward-template** item on the eventual `LedgerEngine`
trait extraction PR's design rounds; segment 2i records
the forward-template explicitly so the eventual PR doesn't
re-derive from scratch.

*Why not `PendingTxActor`-side filter.* P6 (segment-2h
filter-then-select-then-subset-check) handles `output_locks`
collision filtering. Adding maturity filtering at the
`PendingTxActor` layer would duplicate the
`LedgerEngine`-side responsibility and create two
implementations to keep in sync; the contract-altitude
disposition keeps the responsibility upstream.

*Regression test posture.* Synthetic immature output in the
`LedgerEngine` impl's response (rather than a
`PendingTxActor`-side filter) is the right test surface;
PR 5's `LocalLedger` mock at C5β handles raw-output-set
filtering by construction (no immature outputs in the
fixtures); the maturity-filter regression lands in the
`LedgerEngine` extraction PR.

*FOLLOWUPS.* `LedgerEngine` trait-contract amendment for
maturity-filter forward-template (segment-2i amendment to
the LedgerEngine-related FOLLOWUPS area).

*Failure mode foreclosed.* Bitcoin / Monero wallets have
historically had subtle bugs where coinbase outputs got
selected before unlock, producing daemon-rejected
transactions and leaking "this wallet is mining" via the
attempted submission's failure mode. The V3.0 substrate
puts the responsibility at the contract altitude that owns
the maturity knowledge.

### §5.6.11 G6–G8 V3.x FOLLOWUPS dispositions

Three gaps disposed as V3.x FOLLOWUPS. Each entry names the
gap, the V3.x consumer-actor pattern (where applicable), and
the foreclosure-criteria pinning the V3.0 substrate against
the V3.x design surface.

**G6 — Tx-confirmation tracking handoff.**

*Gap.* After `SubmitSucceeded`, the tx is on-network but
not yet confirmed. Users want to see "pending in mempool" →
"1 conf" → "6 confs" → "finalized." `RefreshEngine` detects
on-chain confirmation; mempool presence is a separate
observation (the G1 substrate). The handoff between
`PendingTx`'s `SubmitSucceeded` and the wallet's
tx-history-view is currently undefined at the trait-surface
level.

*Disposition (V3.x FOLLOWUPS).* **V3.x
`TxConfirmationTrackerActor` consumer-actor pattern.** The
actor subscribes to `PendingTxDiagnostic::SubmitSucceeded`
(carries `tx_hash` per segment-2i Phase 0f reshape; shared
substrate with G1's `MempoolMonitorActor`) and
`LedgerDiagnostic::BlockObserved` / `RefreshDiagnostic::*`
(for confirmation-count progression); maintains a per-tx
confirmation-count state; emits a
`TxConfirmationDiagnostic` stream the wallet-UI consumes.

*V3.0 substrate dependencies.* (i) `SubmitSucceeded.tx_hash`
field (segment-2i Phase 0f). (ii) `LedgerEngine` /
`RefreshEngine` diagnostic-stream evolution (out-of-PR-5
scope; tracked separately in the eventual `LedgerEngine` /
`RefreshEngine` consumer-actor PR).

*Foreclosure-criteria pinning.* G6 does NOT require any
V3.0 PR 5 trait-surface change beyond what G1 already
provides. The V3.x consumer-actor PR's design rounds
inherit `tx_hash` projection without `PendingTxEngine`
trait revision.

*Failure mode foreclosed.* Wallets that hard-code
"confirmed after 6 blocks" with no observer-pattern produce
unresponsive UI under reorg; the consumer-actor pattern
admits per-deployment confirmation-policy.

**G7 — Cancel-build during construction.**

*Gap.* FCMP++ proof generation can take seconds; consumer
needs an abort surface during the build call. V3.0
synchronous `build() -> Result<Reservation, ...>` shape
doesn't admit abort.

*Disposition (V3.x FOLLOWUPS).* **V3.x build-cancel
ergonomic refinement.** The V3.0 trait shape doesn't
foreclose:

- An additive `build_with_handle() ->
  Result<BuildHandle, ...>` trait method at V3.x that
  returns an abortable handle.
- A trait-extension introduction at V3.x that admits
  abort-capability as a separate trait
  (`PendingTxEngineCancellable`).

Both additive paths preserve the V3.0 trait surface.

*Foreclosure-criteria pinning.* The V3.0 trait surface uses
`Result<Reservation, _>` (not `Future<Output = Result<...>>`
or `impl Future<Output = ...>`) — synchronous-return; the
V3.x additive paths don't require revising this shape.
**Crucial pin:** the V3.0 trait method MUST NOT change to
`async fn build(...)` or return a future without the V3.x
additive-path design surfacing first; an async-trait
migration is a downstream consequence of the abort surface,
not a precondition.

*Failure mode foreclosed.* Wallets that bake-in
"build can't be cancelled" produce unresponsive UI under
slow proof generation; users force-quit; partial state
persists. The V3.0 substrate leaves the door open
additively.

**G8 — Wallet-locked-during-`in_flight`.**

*Gap.* Wallet locks (user steps away) while `in_flight`
reservations exist; spend material clears from
`SigningActor` state on lock; in-flight reservations whose
daemon response arrives during the locked period need a
coordinated wallet-state-machine + `PendingTxEngine` +
`SigningActor` disposition.

*Disposition (V3.x FOLLOWUPS).* **V3.x wallet-state-machine
coordination.** Three sub-questions:

1. **What happens to `in_flight` reservations on lock?**
   Open at V3.x. Options: (a) actor mailbox drains
   `submit_completed` self-messages but defers the reply
   until unlock; (b) actor mailbox processes
   `submit_completed` and projects to a "deferred-
   notifications" queue the unlock-handler drains; (c)
   actor mailbox suspends processing entirely on lock.
2. **What happens to `consumer_held` reservations on
   lock?** Open at V3.x. The reservation payload includes
   the spend material's witness; the consumer is the wallet
   UI which is already in the locked state. Defer to V3.x
   wallet-state-machine PR.
3. **What happens to in-flight `SigningActor` requests
   when the device is unplugged / wallet locks during HW
   signing?** Open at V3.x. The G4 multi-step shape
   provides the timeout substrate; the V3.x consumer-actor
   PR's design rounds need to name the unlock policy.

*Foreclosure-criteria pinning.* The V3.0 trait surface
admits *all three* sub-question dispositions without
trait revision: (i) deferred replies are an actor-pattern
concern (G4 substrate); (ii) `consumer_held` state lives
in the engine, not in the wallet-state-machine; the
wallet-state-machine PR decides whether to clear it; (iii)
`SigningActor` state is `SigningActor`-internal; the
wallet-state-machine PR's design rounds coordinate.

*Failure mode foreclosed.* Wallets that don't coordinate
lock-during-signing produce "your tx may or may not have
been signed; we don't know" UX; key material may persist
in memory across the lock boundary because no component
owns the cleanup. The V3.0 substrate keeps the spend-
material locality (R11) and the multi-step submit (G4)
both intact under the lock boundary; the V3.x PR
coordinates the three components against the boundary.

### §5.6.12 §7.X commit-decomposition delta-on-delta

The Round 3 eight-commit ordering (C0–C8) and segment-2h
sub-decomposition (C2α / C2β / C2γ / C4α / C4β / C5α /
C5β) survive segment 2i unchanged. The delta-on-delta is
within-commit content for five commits:

- **C0 (Phase 0 spec amendment; doc-only).** Scope grows
  to include all segment-2i amendments:
  - **§4 Phase 0f reshape:** `DiscardReason::MempoolEvicted`
    variant; `tx_hash: TxHash` projection fields on
    `PendingTxDiagnostic::SubmitSucceeded` and
    `SubmitPendingResolution`.
  - **§4 new Phase 0m:** `PendingTxEngine::signal_mempool_evicted`
    trait method binding form with F2 ownership-boundary
    adjudication doc-comment.
  - **§5.0.1 Stage 4 prose extension:** multi-step submit
    pattern (`submit_start` → `submit_signed` →
    `submit_completed`); P7 handler-atomicity within each
    step; deferred-reply substrate-confirmation pin for
    Stage 4 framework-selection pre-flight.
  - **§5.0.2 enum-block updates:** `tx_hash` field added
    to `SubmitSucceeded` and `SubmitPendingResolution`;
    `MempoolEvicted` variant added to `DiscardReason`;
    segment-2i amendment annotations.
  - **§5.4 R5 scope-extension named-and-rejected for G2**
    (long-range-reorg of confirmed txs disposed as
    `LedgerDiagnostic`-domain).
  - **§5.4 new R18 closure:** transaction replacement /
    fee-bump structural rejection with priority-ordering
    rationale; two named reopening criteria.
  - **§5.6.9 wallet-ecosystem-lessons discipline-citation
    matrix** (seven items).
  - **§5.6.10 G1–G5 V3.0 substrate dispositions.**
  - **§5.6.11 G6–G8 V3.x FOLLOWUPS dispositions.**

  Plus the corresponding `V3_ENGINE_TRAIT_BOUNDARIES.md`
  §2.4 amendment (adding `signal_mempool_evicted` to the
  trait-method enumeration) and `V3_WALLET_DECISION_LOG.md`
  entries.

  Net C0 size grows another ~12% (cumulative segment-2h +
  segment-2i is ~42% over the original Round 3 baseline);
  still doc-only.

- **C2α (error / discriminant enums; sub-commit α).**
  Scope changes:
  - **Adds:** `DiscardReason::MempoolEvicted` variant;
    `tx_hash: TxHash` field on
    `PendingTxDiagnostic::SubmitSucceeded` and
    `PendingTxDiagnostic::SubmitPendingResolution`;
    `signal_mempool_evicted(rid) -> Result<(),
    PendingTxError>` trait-method declaration on
    `PendingTxEngine`.

- **C2β (discriminant projections; sub-commit β).**
  Scope changes:
  - **Adds:** `SubmitSuccessClass` discriminant projection
    grows to include `tx_hash` projection-field.

- **C3 (`PendingTxDiagnostic` enum + emission
  infrastructure).** Scope changes:
  - **Adds:** Emission infrastructure for `Discarded
    { rid, MempoolEvicted }` from the new
    `signal_mempool_evicted` handler.

- **C5β (`PendingTxEngine` trait-impl bodies;
  `LocalPendingTx` internals).** Scope changes:
  - **Adds:** `LocalPendingTx::signal_mempool_evicted`
    handler body:
    1. Acquire `Mutex<PendingTxState>` guard (P7-atomic
       window).
    2. Check rid ∈ in_flight; if not, drop guard and
       return `Err(PendingTxError::ReservationNotFound)`.
       (Consumer-held reservations also return
       `ReservationNotFound` per the trait doc-comment's
       Phase 0m note — eviction is meaningful only for
       in-flight reservations.)
    3. Remove rid from `in_flight`; sweep `output_locks`
       for rid-matching entries.
    4. Emit `PendingTxDiagnostic::Discarded { rid,
       reason: DiscardReason::MempoolEvicted }` via sink.
    5. Drop guard; return `Ok(())`.

  Test deliverables grow:
  - `signal_mempool_evicted_on_in_flight_succeeds`
    (G1 success path).
  - `signal_mempool_evicted_on_consumer_held_returns_not_found`
    (G1 F2 ownership-boundary entry check; consumer-held
    is not "in_flight" in the eviction-relevant sense).
  - `signal_mempool_evicted_on_never_existed_returns_not_found`
    (G1 negative case).
  - `signal_mempool_evicted_releases_output_locks`
    (G1 lock-release property).
  - `signal_mempool_evicted_emits_mempool_evicted_diagnostic`
    (G1 emission-coherence per §5.0.3).

- **C7 (`FaultInjecting<P: PendingTxEngine>` + property
  tests + R9 per-error-class coverage).** Scope changes:
  - **Adds:** Property test
    `signal_mempool_evicted_ownership_boundary` —
    `FaultInjecting` configured to yield
    `AmbiguousErrorKind::DaemonTimeout` (rid enters
    `in_flight`); consumer calls
    `signal_mempool_evicted(rid)` → assert
    `Ok(())` and `output_locks` released; subsequent
    consumer `discard(rid)` returns
    `Err(ReservationNotFound)` (rid was moved to "gone"
    by the eviction signal).

- **C8 (docs propagation + CHANGELOG).** FOLLOWUPS
  amendments inventory grows by:
  - G1 V3.x `MempoolMonitorActor` consumer-actor pattern
    (new entry; includes `tx_hash` projection rationale
    and F2 narrow-shape-adjudication rationale).
  - G2 `LedgerDiagnostic::TxReorgedOut` forward-template
    (amendment to existing `DIAGNOSTIC_STREAM.md`
    FOLLOWUPS entry scope).
  - G3 transaction-replacement / fee-bump V3.x
    conditional-reopening bookmark (new entry; includes
    the two named criteria and the relationship to R14
    / R15 / R16).
  - G5 `LedgerEngine` maturity-filter forward-template
    (amendment to existing `LedgerEngine` FOLLOWUPS
    entry scope).
  - G6 V3.x `TxConfirmationTrackerActor` consumer-actor
    pattern (new entry; cross-references G1's
    `tx_hash` substrate).
  - G7 V3.x build-cancel ergonomic refinement (new entry;
    includes the foreclosure-pin against async-trait
    migration without additive-path design surfacing
    first).
  - G8 V3.x wallet-locked-during-`in_flight` coordination
    (new entry; includes the three sub-question
    enumeration).

The §7.X commit decomposition's load-bearing ordering
survives segment 2i unchanged: C0 lands the doc-only
substrate; C1 lands `SnapshotId`; C2α/β/γ land the type
substrate (now including the G1 enum/field/method
additions); C3 lands diagnostic infrastructure (including
the `MempoolEvicted` emission path); C4α/β/γ land the
trait surfaces (unchanged); C5α/β lands the aggregate
(including the `signal_mempool_evicted` handler); C6
lands the orchestration migration (unchanged); C7 lands
the property-test harness (including the
ownership-boundary property); C8 closes with
documentation (including the segment-2i FOLLOWUPS
amendments).

---



Shape mirrors PR 4's §6. Round 2 closes here; Round 3 (commit
decomposition) consumes this checklist as the substrate
deliverable for Phase 1 commit decomposition.

**Binding-check matrix against the §2.4 spec (segment-2g
finalization).**

- [x] Trait surface methods (`build` / `submit` / `discard`
  / `outstanding`) — unchanged across Round 2 segments
  per §5.0.1's invariance pin. Trait-parameter additions
  (`S: Signer`, `O: OutputSelector`, `F: FeeEstimator`)
  affect the engine type, not the trait surface itself.
- [x] `SubmitError` + `SubmitErrorKind` enum surfaces — Phase
  0a binding form pinned in segment 2f; both
  `#[non_exhaustive]`; `SnapshotInvalidated` and
  `DaemonRejected { kind }` variants enumerated.
- [x] `SnapshotId` opaque type, Keccak-256/128-bit truncation
  via `shekyl-crypto-hash::cn_fast_hash`, domain-separation
  prefix — Phase 0b binding form pinned in segment 2g; hash
  primitive rationale recorded per dependency-discipline
  (`shekyl-crypto-hash` is unconditional `[dependencies]` in
  `shekyl-engine-core` per Cargo.toml line 28); security
  rationale framed as second-preimage resistance over bounded
  snapshot population (revised in Copilot-fix follow-up from
  prior collision-resistance / Grover-doubled-width framing).
- [x] `Reservation` struct shape with `extensions:
  Vec<ReservationExtension>` (R14 extensibility seam) —
  Phase 0d binding form pinned in segment 2g per
  segment-2b R14 closure; `ReservationExtension` enum
  is `#[non_exhaustive]` with empty V3.0 variant set.
- [x] Reservation-lifecycle prose with R5 / R9 / R10
  closure cross-references — Phase 0e binding form
  pinned in segment 2g.
- [x] `PendingTxDiagnostic` enum + constructor-bound
  `DiagnosticSink` parameter — Phase 0f binding form
  pinned in segment 2g per segment-2f §5.0.2.1
  sink-binding closure (Finding 4).
- [x] `LedgerDiagnostic::SnapshotMerged` variant —
  Phase 0g pinned as deferred-to-consumer-PR per
  segment-2g introduction-PR disposition.
- [x] `Signer` trait surface (R11 (b) segment-2b closure)
  — Phase 0h binding form pinned in segment 2g.
- [x] `OutputSelector` trait surface (R13 segment-2c
  closure) — Phase 0i binding form pinned in segment 2g.
- [x] `FeeEstimator` trait surface + `FeePriority` enum
  (R16 segment-2c closure with segment-2d V3.0-lift
  evaluation) — Phase 0j binding form pinned in
  segment 2g.
- [x] `SubmissionStrategyActor` topology slot (R15
  segment-2c closure) — Phase 0k pinned in segment 2g
  as actor-topology pin (V3.x introduction).
- [x] `DiscardReason` enum with `TTLAutoDiscard` variant
  (R8 segment-2e closure) — pinned in §5.0.2 enum
  sketch.

**Test-substrate preservation list (segment-2g enumeration).**

- [x] `LocalPendingTx::build` / `submit` / `discard` /
  `outstanding` unit-test coverage — Phase 1 confirms
  test surfaces match V3.0 trait-parameter additions
  (`S: Signer`, `O: OutputSelector`, `F: FeeEstimator`).
- [x] Property-test infrastructure for diagnostic-stream
  emission/return coherence — `AssertionSink` /
  `PanickingSink` pair per PR 4's canonical pattern;
  Phase 1 introduces the PR-5-side equivalents under
  §5.0.3 contract pins.
- [x] Stage 4 `PendingTxActor` migration test fixtures —
  not introduced in PR 5; deferred to Stage 4 actor-
  migration PR per §5.0.1 invariance pin.
- [x] R9 per-error-class disposition coverage — Phase 1
  confirms each daemon-response class
  (`Accepted` / `AlreadyInMempool` / `DoubleSpend` /
  `FeeTooLow` / `Malformed` / `Timeout` / `NetworkError`)
  has corresponding state-transition test coverage per
  segment-2f's per-error-class disposition table.
- [x] Finding-2 `SubmitPendingDaemonAck` daemon-side
  authority coverage — Phase 1 confirms test surfaces
  exercise the consumer-explicit-resolution path
  (timeout → `discard(id, ConsumerExplicit)`) and the
  R8 TTL safety-net path (timeout → TTL fires →
  `Discarded { reason: TTLAutoDiscard }`; deferred until
  V3.x `ReservationTTLActor` lands, per segment-2e).

**Call-site sweep audit (segment-2g enumeration; Phase 1
performs the sweep).**

- [x] `PendingTxDiagnostic::BuildSucceeded` emitted at
  `build`-success path in `LocalPendingTx::build` /
  `PendingTxActor::handle_build` (R8 segment-2e
  deliverable 1; Phase 1 confirms).
- [x] `PendingTxDiagnostic::Discarded { reason:
  SnapshotRotationAutoDiscard }` emitted at `submit`'s
  snapshot-mismatch path (R5 lazy-discard semantics;
  Phase 1 confirms).
- [x] `PendingTxDiagnostic::Discarded { reason:
  DaemonRejectedTerminal }` emitted on `DoubleSpend`
  daemon-rejection per R9 segment-2f per-error-class
  table (Phase 1 confirms).
- [x] `PendingTxDiagnostic::SubmitFailed { kind: ... }`
  emitted for all `SubmitErrorKind` variants per R9
  segment-2f per-error-class table (Phase 1 confirms).
- [x] `PendingTxDiagnostic::SubmitAttempted` emitted
  on submit-handler entry; `SubmitSucceeded` /
  `SubmitFailed` emitted on `SubmitCompleted`
  self-message arrival per R9 segment-2f self-
  continuation pattern (Phase 1 confirms).
- [x] No emission paths bypass the sink — every
  `&self` mutation event has an emit at the call
  site per §5.0.3 emission/return-coherence
  contract.

**PR 4 Round 3 input bundle (segment-2g final form).**
Resolved as confirmation per §5.2 — the bundle is **this
document** (PR 5 STAGE_1 design at segment-2g close-out)
plus PR 4's corresponding follow-up commit on its design
doc recording the "α confirmed" disposition. No further
PR-4-side design work is unblocked by PR 5 closing Round 2;
PR 4 Round 3 proceeds independently against the bundle.

**Round 3 readiness (segment-2g gate).** All §4 Phase 0
candidates are binding-pinned at the type-signature level
(0a–0k); §6 review checklist is filled; FOLLOWUPS amended
for the segment-2g `DIAGNOSTIC_STREAM.md` rename. Round 3
(commit decomposition + Phase 1 commit list) is ready to
proceed against the §4 enumeration. Round 3 produces the
Phase 1 commit-decomposition deliverable per the
PR 1 / PR 2 / PR 3 / PR 4 precedent.

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

- **Segment 2f — R9 two-stage submit-flow closure with
  daemon-side authority for Finding 2 ambiguous outcomes;
  `SubmitError` + `SubmitErrorKind` enum pins; sink-binding
  constructor-bound closure for Finding 4.**
  - **R9 closed as two-stage submit flow** with explicit
    internal `ReservationState` machine (`Active |
    SubmitPendingDaemonAck | Resolved`). Trait surface
    unchanged; `outstanding()` counts `Active +
    SubmitPendingDaemonAck` (both reserve outputs). The
    state machine is invisible to consumers except through
    the diagnostic stream's `SubmitAttempted` (state entered)
    and `SubmitSucceeded` / `SubmitFailed` /
    `SubmitSnapshotInvalidated` / `Discarded` (state exited).
  - **Self-continuation message pattern** pinned:
    `PendingTxActor` defers reply until `SubmitCompleted`
    self-message arrives, preserving mailbox throughput and
    making the intermediate state explicit in the actor's
    state machine without blocking concurrent message
    processing.
  - **Per-error-class disposition table** pins state-
    transition + diagnostic-event-sequence + trait-return
    tuples for all daemon-response classes (`Accepted`,
    `AlreadyInMempool`, `DoubleSpend`, `FeeTooLow`,
    `Malformed`, `Timeout`, `NetworkError`).
  - **Finding 2 closes as (B) — daemon-side authority for
    ambiguous outcomes.** On `Timeout` or `DaemonUnavailable`,
    reservation stays in `SubmitPendingDaemonAck`; the wallet
    does not assume a resolution it cannot verify; consumer-
    explicit `discard(id, ConsumerExplicit)` is the resolution
    path; R8's `ReservationTTLActor` (via per-state TTL
    configuration with shorter TTL on `SubmitPendingDaemonAck`)
    is the safety net for forgotten resolutions. (A)
    actor-state authority on timeout is rejected because the
    phantom-spent-output window violates the monotonicity
    property the tracker delivers per §3.4.5; deferring the
    safety to the daemon's `DoubleSpend` rejection is the same
    "consumer's checking does work the trait should be doing
    structurally" anti-pattern PR 4 named. (C) bounded grace
    period is rejected on the same grounds with bounded
    window.
  - **`SubmitError` + `SubmitErrorKind` enum pins** in §5.0.2
    (both `#[non_exhaustive]`). `SubmitError =
    SnapshotInvalidated{..} | DaemonRejected{kind:
    SubmitErrorKind}`; `SubmitErrorKind = DoubleSpend |
    FeeTooLow | Malformed | DaemonTimeout | DaemonUnavailable`.
  - **R5 ↔ R8 ↔ R9 coherence verified.** R5's reactive
    cleanup (`SnapshotRotationAutoDiscard`), R8's proactive
    cleanup (`TTLAutoDiscard`), and R9's daemon-authority
    cleanup (`DaemonRejectedTerminal`) share the
    `DiscardReason`/`Discarded` event infrastructure;
    downstream consumers see a unified `Discarded` event
    stream with discriminated reasons.
  - **No new `PendingTxDiagnostic` variants needed.** The
    existing variant set is sufficient for the R9 state
    machine; segment 2f adds enum variants only to
    `SubmitErrorKind`.
  - **No new trait surface methods needed.** `discard(id,
    ConsumerExplicit)` is sufficient for consumer-explicit
    resolution of Finding-2 ambiguity cases.
    `resolve_pending(id, chain_observation)` preserved as a
    V3.x ergonomic-API candidate if consumer telemetry
    surfaces the boilerplate.
  - **Sink-binding closure (Finding 4).** §5.0.2.1 pins
    `LocalPendingTx::new(..., sink: Arc<dyn DiagnosticSink>,
    ...)` as constructor-bound under PR 4 §3.4.5 / R4 (a)
    consistency. R11's segment-2b closure as (b) makes the
    sink-binding question independent of spend-material
    disposition; the two close separately. Rationale:
    engine-identity coupling (1-to-1 mapping load-bearing at
    the type level); Stage 4 actor wiring alignment
    (spawn-time DI); call-site cleanliness; runtime-swap
    surface preserved via sink-side indirection; no
    load-bearing reason for per-method override in
    production engines.
  - **FOLLOWUPS amendments.** Existing `SubmitFailureAnalyzer`
    consumer-actor entry amended with segment-2f closure
    status; new `TimeoutResolverActor` entry added naming the
    V3.x ergonomic-complement surface for Finding 2's
    daemon-side authority disposition. Cross-references the
    R8 `ReservationTTLActor` safety-net role.

- **Segment 2g — Round 2 close-out: §4 Phase 0 final
  enumeration; §5.0.3 diagnostic-stream-doc generalization
  closure; §6 review checklist filled.**
  - **§4 Phase 0 binding-form enumeration finalized.** All
    candidates pin their type-signature shape: Phase 0a
    (`SubmitError` + `SubmitErrorKind` per segment 2f);
    Phase 0b (`SnapshotId` opaque type + SHA-256/128-bit
    truncation + domain-separation prefix); Phase 0c
    (REMOVED at the trait surface per segment 2d's R12 (a)
    closure); Phase 0d (`Reservation` struct shape with
    R14 `extensions: Vec<ReservationExtension>`); Phase 0e
    (reservation-lifecycle prose with R5 / R9 / R10
    closure cross-references); Phase 0f
    (`PendingTxDiagnostic` enum + constructor-bound
    `DiagnosticSink` per segment-2f §5.0.2.1); Phase 0g
    (`LedgerDiagnostic::SnapshotMerged` deferred to
    consumer-PR per segment-2g introduction-PR
    disposition).
  - **New Phase 0 candidates from segment-2b / segment-2c
    closures.** Phase 0h (`Signer` trait surface per R11
    (b) segment-2b closure); Phase 0i (`OutputSelector`
    trait surface per R13 segment-2c closure); Phase 0j
    (`FeeEstimator` trait surface + `FeePriority` enum per
    R16 segment-2c closure with segment-2d V3.0-lift
    evaluation); Phase 0k (`SubmissionStrategyActor`
    topology slot per R15 segment-2c closure — V3.x
    introduction).
  - **`SnapshotId` hash primitive pinned (revised in
    Copilot-fix follow-up).** Keccak-256 via
    `shekyl-crypto-hash::cn_fast_hash` (original padding)
    truncated to the first 128 bits with input
    domain-separated by versioned prefix
    (`b"shekyl-snapshot-id-v1"`). `shekyl-crypto-hash` is
    an **unconditional** `[dependencies]` entry in
    `shekyl-engine-core` per Cargo.toml line 28, satisfying
    [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
    workspace-state reuse against the actual
    production-dependency graph. The prior segment-2g
    binding cited `sha2 = "0.10"` at Cargo.toml line 115
    as workspace-available, but line 115 is in
    `[dev-dependencies]` (test-only); the production
    `sha2` at line 33 is `optional = true`. The
    Copilot-fix follow-up switches the primitive to the
    consensus-audited `cn_fast_hash` already unconditional
    in production deps. Security rationale reframed from
    "128-bit collision resistance / Grover-doubled width
    on SHA-2" (technically incorrect — Grover applies to
    preimage, not collision; quantum collision is governed
    by BHT, ~2⁴³ for 128 bits) to **second-preimage
    resistance over bounded snapshot population** (wallet
    observes ≪ 2⁴⁰ snapshots over its operational
    lifetime; classical second-preimage ~2¹²⁸ work;
    quantum Grover second-preimage ~2⁶⁴ work; impact bound
    by adversary-controlled-daemon design-center per
    §5.3 — daemon-forged snapshot collision merely makes
    the wallet submit a tx valid against the prior
    snapshot, no consensus violation). Versioned prefix
    permits V3.x migration to a wider output or different
    hash family without cross-stage rebuild (the token
    does not cross the wire).
  - **§5.0.3 diagnostic-stream-doc generalization closure.**
    Option (a) — rename `REFRESH_DIAGNOSTIC_STREAM.md` →
    `DIAGNOSTIC_STREAM.md` (general). FOLLOWUPS entry
    amended; doc itself remains V3.x deferred (created at
    first consumer-actor PR introduction). Rationale:
    shared contracts (six bullets per §5.0.3) modest in
    volume relative to per-stream taxonomies; single doc
    with shared-then-per-stream structure lower
    cross-reference cost than parent-and-children
    factoring; factoring discipline applicable
    retroactively if growth justifies.
  - **§6 review checklist filled.** Binding-check matrix
    against the spec; test-substrate preservation list;
    call-site sweep audit; PR 4 Round 3 input bundle
    (resolved as confirmation per §5.2). All Phase 0
    candidates' binding-form pins recorded with segment-2g
    closure.
  - **Round 3 readiness gate.** All §4 Phase 0 candidates
    binding-pinned; §6 review checklist filled; FOLLOWUPS
    amended for the segment-2g rename. Round 3 (commit
    decomposition + Phase 1 commit list) ready to proceed.

**Round 3.**

- §7 commit decomposition + Phase 1 commit list (per the PR 1
  / PR 2 / PR 3 / PR 4 precedent). Substrate: this document at
  segment-2g close-out; §4 Phase 0 enumeration; §6 review
  checklist; PR 4 Round 3 confirmation per §5.2. Lands as
  §7.X below.

---

## §7.X Phase 1 commit decomposition (Round 3 deliverable)

**Implementer synthesis-banner (segment-2h / segment-2i deltas).**
The C0–C8 commit bodies below preserve the **Round-3-original
substrate** (segment-2g state at Round 3 closure) per the
[§7 closure-rule discipline](#round-3-closure-rule) — what
was known at closure time stays pinned; new substrate reopens
explicitly through the segment mechanism rather than rewriting
upstream history. Before executing each commit, **apply the
within-commit deltas recorded in [§5.6.8](#568-round-3-7x-commit-decomposition-delta)
(segment-2h refinements) and [§5.6.12](#5612-7x-commit-decomposition-delta-on-delta)
(segment-2i delta-on-delta)**. Commits affected: **C0, C2α, C2β,
C2γ, C3, C4α, C4β, C5α, C5β, C7, C8**. The deltas are
authoritative; the §7.X bodies below are audit-trail substrate
that the deltas refine.

Explicit deltas not visible in the §7.X bodies below (apply
during implementation):

- **C2β / C2γ — `ReservationState` enum removed; `Reservation::state`
  field removed.** §5.6.8 C2β / C2γ entries. The
  `{ Active | SubmitPendingDaemonAck | Resolved }` enum and the
  `state` field documented in §7.X's C2 bodies are
  segment-2g-shape artifacts that segment 2h dissolved into
  collection membership (the (γ) three-collection lean shape:
  `output_locks` + `consumer_held` + `in_flight`). State is
  implicit in collection membership; no enum.
- **C3 — `PendingTxDiagnostic` variant set re-shaped.** §5.6.8 C3
  + §5.6.12 C3 entries. Segment 2h removes
  `PendingTxDiagnostic::SubmitFailed` (no surviving emission
  site under the (γ) lean shape + the
  `SubmitErrorKind → TerminalErrorKind / AmbiguousErrorKind`
  split) and removes `DiscardReason::SnapshotRotationAutoDiscard`
  (lazy R5 — staleness detected at submit-time, not via eager
  sweep). Segment 2h adds `PendingTxDiagnostic::SubmitPendingResolution`.
  Segment 2i adds `DiscardReason::MempoolEvicted` and adds
  `tx_hash: TxHash` projection fields on `SubmitSucceeded` and
  `SubmitPendingResolution`.
- **C5α — `PendingTxEngine` trait receivers: `&mut self → &self`.**
  The C5α trait declaration body below (lines ~8297–8313) shows
  `&mut self` on `build` / `submit` / `discard`; the
  [V3_ENGINE_TRAIT_BOUNDARIES.md §2.4](V3_ENGINE_TRAIT_BOUNDARIES.md)
  Round 3 `&mut → &self` sweep moved all PR 5 trait surfaces
  to `&self` per §2.4's canonical trait spec. Implementer
  applies the sweep to C5α's declaration verbatim from §2.4;
  `LocalPendingTx` carries internal `Mutex<PendingTxState>`
  per the (γ) lean shape (P7 handler-atomicity per §5.0.1)
  to satisfy the interior-mutability surface. The
  `Engine`-side `Arc<RwLock<Engine>>` wrapper (cross-cutting
  lock 3) is unchanged; the trait-surface receiver is now
  `&self` for actor-substitution symmetry. The C5α trait
  declaration is the §2.4 canonical surface; §7.X C5α's
  body is the closure-time substrate.
- **C5α — `signal_mempool_evicted` trait method added.** Phase
  0m + §5.6.12 C5α entries. The C5α trait declaration grows
  a fourth signal-shaped method:
  `fn signal_mempool_evicted(&self, rid: ReservationId) ->
  Result<(), PendingTxError>`. Body lands in C5β per §5.6.12.
- **C5β — Implementation bodies follow the (γ) collection-moves
  shape, not enum-state-mutations.** §5.6.8 C5β + §5.6.12 C5β
  entries. The §7.X C5β bodies describe an enum-state-mutation
  shape (`Active → SubmitPendingDaemonAck → Resolved`
  transitions). Segment 2h replaced this with collection-move
  bodies (`consumer_held → in_flight`, `in_flight → gone`
  via removal + `output_locks` sweep) per the P4 collection-moves
  table. Segment 2i adds the `signal_mempool_evicted` body
  per the steps recorded in §5.6.12.
- **C0 — Phase 0 substrate growth.** §5.6.8 C0 + §5.6.12 C0
  entries. Phase 0a–0l from segment 2g plus Phase 0m
  (`signal_mempool_evicted` trait method declaration) from
  segment 2i.
- **C4α / C4β — Test substrate growth.** §5.6.8 C4α / C4β
  entries. Segment 2h's F4 subset-verification test
  (`faulty_selector_returns_non_subset_rejected`) and P-F4
  binding test land in C4α / C4β.
- **C7 — Property-test scope.** §5.6.8 C7 + §5.6.12 C7
  entries. Property tests remove `ReservationState`-transition
  assertions (no longer applicable under (γ)) and add
  collection-invariant properties; segment 2i adds the
  `signal_mempool_evicted_ownership_boundary` property.
- **C8 — FOLLOWUPS / CHANGELOG additions.** §5.6.8 C8 +
  §5.6.12 C8 entries. The FOLLOWUPS inventory grows with the
  G1–G8 entries (G1 `MempoolMonitorActor`, G3 transaction-
  replacement rejection, G6 `TxConfirmationTrackerActor`, G7
  cancel-build refinement, G8 wallet-locked-during-in_flight,
  G5 `LedgerEngine` maturity-filter forward-template, G2
  `LedgerDiagnostic::TxReorgedOut` amendment).

**Rationale (why preserve the §7.X bodies below at closure-time
substrate).** The §7 closure-rule discipline pins each round's
deliverable at the substrate-state that was known when the round
closed — substrate change reopens explicitly through the segment
mechanism rather than rewriting upstream history. The cost of
preserving the bodies-at-closure is the implementer-time
synthesis cost named in this banner; the benefit is that an
auditor reading the round in 18 months reconstructs the
round-by-round substrate evolution without forensic git
archaeology. The synthesis-banner is the cheap mitigation that
delivers both properties — closure-rule provenance is intact
*and* the implementation-time hazard is foreclosed.

---

Per the PR 1 / PR 2 / PR 3 / PR 4 precedent, Round 3 produces
the Phase 1 commit list as the substrate the implementation
branch (`feat/stage-1-pr5-pending-tx-engine`) cuts against. The
commits are **load-bearing-ordered** — each commit's preconditions
are the cumulative state of the prior commits; bisection isolates
each behaviour change to one commit boundary.

The commit list assumes the implementation branch cuts off the
post-Round-3 dev tip (post-PR-#60 [PR 4 RefreshEngine merge,
`fd6005e2a`]; post-PR-#79 [RandomX v2 c_oracle Flags merge,
`989610cac`]; the design branch's lifetime ends at Round 3
close). PR 5 implementation lands as **eight commits**; the PR
opens after C8 lands locally with a passing CI run.

### Pre-flight: existing substrate inventory

The existing `rust/shekyl-engine-core/src/engine/pending.rs`
(1036 lines, landed pre-PR-4) is the **source substrate** for
the trait extraction. PR 5 extracts and augments rather than
rewriting — per §3.2 architectural-inheritance audit and the
"moves not rewrites" pattern PR 3 / PR 4 established. The
inventory below names what is present today and what each
commit alters; reviewers cross-reference this table when
auditing each commit's diff scope.

**Types already in `engine/pending.rs` (pre-PR-5).**

- `ReservationId(u64)` — the monotone counter token; unchanged.
- `TxHash([u8; 32])` — opaque submit-result token; unchanged.
- `FeePriority { Economy | Standard | Priority | Custom(NonZeroU64) }` —
  caller-facing fee tier enum. Pre-PR-5 it is owned by `pending.rs`;
  PR 5 C4 *re-homes* it under the `FeeEstimator` trait surface
  (`Phase 0j`) so the trait's `estimate_fee(priority: FeePriority,
  ...) -> Result<u64, FeeEstimatorError>` signature is the canonical
  citation, with `pending.rs` re-exporting for backward source-text
  compatibility within the crate. No callers see a type change.
- `TxRecipient { address, amount_atomic_units }` — unchanged.
- `TxRequest { recipients, priority, from_subaddress }` — unchanged.
- `TxRecipientSummary { address, amount_atomic_units }` — unchanged.
- `Reservation { selected_transfer_indices, built_at_height,
  built_at_tip_hash, fee_atomic_units, recipients, priority }`
  (`pub(crate)`) — augmented in C2 with `snapshot_id: SnapshotId`
  (R12 (a) per §5.4) and `extensions: Vec<ReservationExtension>`
  (R14 per §5.4 / segment-2b) and `state: ReservationState`
  (R9 segment-2f). Existing fields retained.
- `PendingTx { id, built_at_height, built_at_tip_hash,
  fee_atomic_units, tx_bytes, recipients }` — augmented in C2
  with `snapshot_id: SnapshotId` (caller-visible token for
  symmetry with `Reservation`'s pinning; submit's
  field-comparison handler reads off the reservation, not the
  handle, per §5.0 — but the handle carries the same id so a
  caller can correlate diagnostic events without round-tripping
  through `outstanding()`).
- `build_pending_tx_in_state(...)` — free function; **extracted in
  C5 into `LocalPendingTx::build` method body** with the
  `SnapshotId`-pinning addition (per C2's augmented `Reservation`
  shape). No business logic changes; the function body becomes
  the method body verbatim with the snapshot-id stamping inserted
  at reservation insertion.
- `submit_pending_tx_in_state(...)` — free function; **extracted in
  C5 into `LocalPendingTx::submit` method body** with the
  snapshot-mismatch staleness check + state-machine transition
  (`Active → SubmitPendingDaemonAck → Resolved`) inserted per R9
  segment-2f. The existing tip-hash-comparison invariant
  (`PendingTxError::ChainStateChanged`) is preserved as a
  defense-in-depth check inside the `Active → ...` transition
  (the snapshot-id check is the load-bearing one; tip-hash
  comparison is a redundant cross-check that catches any
  derivation bug in `SnapshotId`).
- `discard_pending_tx_in_state(...)` — free function; **extracted
  in C5 into `LocalPendingTx::discard` method body**. The
  current signature returns `Result<(), PendingTxError>` on
  unknown id; the trait surface preserves that shape.
- `impl<S, D> Engine<S, D, LocalLedger> for build_pending_tx /
  submit_pending_tx / discard_pending_tx / outstanding_reservations`
  — Engine-side dispatch methods; **rewired in C6** to delegate
  through the `P: PendingTxEngine` generic parameter rather than
  reading `Engine`'s own `reservations` field directly. The
  `Engine` struct's `reservations: BTreeMap<ReservationId,
  Reservation>` and `next_reservation_id: u64` fields **migrate to
  `LocalPendingTx`'s interior state** in C5; `Engine` no longer
  owns them after C6.

**Types not present today (introduced in PR 5).**

- `SnapshotId([u8; 16])` opaque type (Phase 0b) — C2.
- `SubmitError`, `SubmitErrorKind` (Phase 0a) — C2.
- `DiscardReason { ConsumerExplicit | SnapshotRotationAutoDiscard
  | DaemonRejectedTerminal | TTLAutoDiscard }`
  (`#[non_exhaustive]`) — C2.
- `ReservationExtension` (`#[non_exhaustive]`, empty V3.0
  variant set; Phase 0d / R14) — C2.
- `ReservationState { Active | SubmitPendingDaemonAck | Resolved }`
  internal enum (R9 segment-2f) — C2.
- `PendingTxDiagnostic` enum (`#[non_exhaustive]`; Phase 0f) — C3.
- `Signer` trait (Phase 0h / R11 (b)) — C4.
- `LocalSigner` default impl of `Signer` over `AllKeysBlob` —
  C4.
- `OutputSelector` trait (Phase 0i / R13) — C4.
- `WalletGreedyOutputSelector` default impl (matches existing
  `build_pending_tx_in_state` selection logic verbatim) — C4.
- `FeeEstimator` trait (Phase 0j / R16) — C4.
- `DaemonFeeEstimator` default impl (Phase 1 stub returning
  `STUB_FEE_ATOMIC_UNITS`; V3.0 wire-up to `get_fee_estimates`
  is deferred to Phase 2a per the existing
  `STUB_FEE_ATOMIC_UNITS` docstring) — C4.
- `PendingTxEngine` trait (Phase 0a..0f composite) — C5.
- `LocalPendingTx<S, O, F>` aggregate impl of `PendingTxEngine` — C5.
- `FaultInjecting<P: PendingTxEngine>` test wrapper — C7.

**File-tree changes anticipated.**

- New file: `rust/shekyl-engine-core/src/engine/traits/pending_tx.rs`
  — trait definition (C5).
- New file: `rust/shekyl-engine-core/src/engine/local_pending_tx.rs`
  — `LocalPendingTx` aggregate (C5; mirrors
  `local_refresh.rs` / `local_ledger.rs` layout).
- New file: `rust/shekyl-engine-core/src/engine/fault_injecting_pending_tx.rs`
  — wrapper (C7; mirrors `fault_injecting_refresh.rs` /
  `fault_injecting_ledger.rs`).
- Existing file: `rust/shekyl-engine-core/src/engine/pending.rs`
  — augmented C2 (data-type fields); free functions removed in
  C5 (bodies migrated to `LocalPendingTx`); the file shrinks to
  hold only the wire-facing types (`ReservationId`, `TxHash`,
  `FeePriority`, `TxRecipient`, `TxRequest`, `TxRecipientSummary`,
  `PendingTx`) plus the new opaque types from C2.
- Existing file: `rust/shekyl-engine-core/src/engine/signer.rs`
  — augmented in C4 to add the new `Signer` trait + `LocalSigner`
  impl alongside the existing `EngineSignerKind` sealed-trait
  surface. The two are orthogonal: `EngineSignerKind` is the
  compile-time mode discriminator on `Engine<S>` (`SoloSigner` /
  multisig); `Signer` is the runtime spend-secret holder
  interface for `LocalPendingTx` per R11 (b).
- Existing file: `rust/shekyl-engine-core/src/engine/error.rs`
  — augmented in C2 with `SubmitError` / `SubmitErrorKind` /
  `FeeEstimatorError` / `OutputSelectorError` / `SignerError`
  variants. Existing `SendError` / `PendingTxError` retained;
  per §5.0.2 the trait surface returns `SendError` from `build`
  and `SubmitError` / `PendingTxError` from `submit` / `discard`
  per the segment-2f closure.
- Existing file: `rust/shekyl-engine-core/src/engine/diagnostics.rs`
  — augmented in C3 with `PendingTxDiagnostic` enum +
  emission-helper additions. `DiagnosticSink` trait is reused
  verbatim from PR 4 per §5.0.3 (no trait-shape change; the
  emit method already accepts `&dyn Debug` per PR 4's design).
- Existing file: `rust/shekyl-engine-core/src/engine/mod.rs`
  — augmented in C6 with the fifth type parameter on `Engine<S,
  D, L, R, P>`; orchestration-layer dispatch methods rewired to
  delegate through `P` rather than reading `engine.reservations`.
- Existing file: `rust/shekyl-engine-core/src/engine/lifecycle.rs`
  — augmented in C6 with the `replace_pending_tx` consume-and-
  rebuild constructor (mirrors PR 4's C7 `replace_refresh`
  refactor at `8f0fbf2bb` per PR 4 §7.X), gated
  `#[cfg(any(test, feature = "test-helpers"))]`.
- Existing file: `rust/shekyl-engine-core/src/engine/traits/mod.rs`
  — augmented in C5 with the `pub use traits::pending_tx::*;`
  re-export.
- Existing file: `rust/shekyl-engine-core/Cargo.toml` — the
  `test-helpers` feature already exists (PR 4 C6α landed it);
  no `Cargo.toml` change needed for C7. The `shekyl-crypto-hash`
  dependency is already unconditional in `[dependencies]`
  (line 28); C2 imports `cn_fast_hash` without a Cargo.toml
  change.

---

### Commit C0 — Phase 0 spec amendment (doc-only, prerequisite)

C0 lands the Phase 0 binding-form pins enumerated in §4 into
the cross-cutting design surface, so the implementation
commits (C1–C8) have a single authoritative spec citation per
trait surface, opaque type, and topology slot. No code change;
doc-only.

C0's scope:

- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  gains §2.5 `PendingTxEngine — Stage 1 surface` with the
  trait method signatures (`build` / `submit` / `discard` /
  `outstanding`), the four trait-parameter slots (`S: Signer`,
  `O: OutputSelector`, `F: FeeEstimator`, plus the
  diagnostic-stream sink-binding constructor parameter), the
  `SubmitError` / `SubmitErrorKind` / `DiscardReason` / `SnapshotId`
  / `ReservationExtension` / `PendingTxDiagnostic` enum
  enumerations, and the cross-reference back to this design
  doc's §4 enumeration.
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §1.x lifecycle status table gains the PR 5 row, marked
  `Round 3 closed; Phase 1 lands as commits C0–C8`. The
  cross-trait coupling row for `PendingTxEngine ↔ LedgerEngine`
  is noted as **additive-only** (Phase 0g
  `LedgerDiagnostic::SnapshotMerged` deferred to V3.x
  consumer-actor PR per segment-2g; no trait amendment in
  PR 5).
- [`docs/V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md)
  gains entries for each binding-form pin landed in Round 2's
  segments 2b–2g (R11 (b) signer split; R12 (a) content-derived
  `SnapshotId`; R2 16-byte truncation; R8 `TTLAutoDiscard`
  variant; R9 two-stage submit flow; R13 (b) `OutputSelector`
  trait seam; R15 (b) `SubmissionStrategyActor` topology slot;
  R16 (b) `FeeEstimator` trait seam; R17 (a) drop-on-close).
  Each entry cross-references the corresponding §5.4 R-residual
  section in this doc.
- [`docs/design/WALLET_REWRITE_PLAN.md`](./WALLET_REWRITE_PLAN.md)
  the Stage-1-PR-table row for "PR 5 — PendingTxEngine
  extraction" gains the design-doc cross-reference and the
  "Round 3 closed; ready for Phase 1" status note. (The plan's
  high-level phase enumeration is untouched.)
- This design doc (`STAGE_1_PR_5_PENDING_TX_ENGINE.md`) Status
  banner gains the **Round 3 closed; Phase 1 commits C0–C8
  enumerated below** marker before "Round 3 (commit
  decomposition + Phase 1 commit list) is the next forward
  step" line.

C0 is doc-only; CI gate: `cargo doc --no-deps` clean (no new
intra-doc-link warnings against `pending.rs` / `traits/`
referenced from the new §2.5 prose); the existing 170-test
suite is unchanged.

---

### Commit C1 — `SnapshotId` opaque type + `cn_fast_hash` derivation + domain-separation prefix

C1 lands the smallest type-level prerequisite: the opaque
16-byte `SnapshotId` token plus the domain-separated derivation
function over `LedgerSnapshot`'s deterministic fields. The
derivation is `pub(crate)` (Stage 1's `LocalPendingTx` calls
it; the trait surface never accepts a `SnapshotId` from a
caller — it is always engine-derived).

C1's scope:

- New module declaration in
  [`engine/mod.rs`](../../rust/shekyl-engine-core/src/engine/mod.rs)
  for the new file (if separate) or inline addition to
  [`engine/pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs)
  per the file-tree decision below.
- `pub struct SnapshotId([u8; 16])`. `#[derive(Clone, Copy,
  Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]`. Per
  `21-reversion-clause-discipline.mdc`'s rejection-with-reopening
  shape: `Clone + Copy + PartialEq + Eq` is required by the
  submit-handler field-comparison contract (§5.0 ground 2);
  `Hash + Ord` is required so consumers can use `SnapshotId` as
  a map key (V3.x consumer-actor PRs subscribing to
  `LedgerDiagnostic::SnapshotMerged` events will key indexes
  off it; the V3.0-time-cost is zero — the trait `Hash` and
  `Ord` impls are derived). Reopening criterion: none — the
  type's identity-as-bytes is structural to its purpose.
- `pub(crate) fn derive_snapshot_id(snapshot:
  &LedgerSnapshot) -> SnapshotId` in
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)'s
  `impl LedgerSnapshot` block (the function reads
  `pub(crate)` fields `synced_height` and `reorg_blocks`, so
  it must live in the same module the fields are declared
  in). Implementation:

  ```rust
  pub(crate) fn derive_snapshot_id(snapshot: &LedgerSnapshot) -> SnapshotId {
      let mut buf = Vec::with_capacity(
          b"shekyl-snapshot-id-v1".len()
              + 8
              + 8
              + snapshot.reorg_blocks.blocks.len() * (8 + 32),
      );
      buf.extend_from_slice(b"shekyl-snapshot-id-v1");
      buf.extend_from_slice(&snapshot.synced_height.to_le_bytes());
      buf.extend_from_slice(&(snapshot.reorg_blocks.blocks.len() as u64).to_le_bytes());
      for (height, hash) in &snapshot.reorg_blocks.blocks {
          buf.extend_from_slice(&height.to_le_bytes());
          buf.extend_from_slice(hash);
      }
      let digest = shekyl_crypto_hash::cn_fast_hash(&buf);
      let mut out = [0u8; 16];
      out.copy_from_slice(&digest.as_bytes()[..16]);
      SnapshotId(out)
  }
  ```

  Domain-separated by the versioned prefix per segment-2g
  rationale; length-prefixed `reorg_blocks` count
  forecloses extension/concatenation collisions against
  same-tip ledgers with different reorg-window depth (per
  the cryptographic discipline of canonical encoding).
- Unit tests at the bottom of `engine/refresh.rs`:
  - `derive_snapshot_id_deterministic` — same snapshot →
    same id; different snapshot (different height or
    different reorg-window contents) → different id.
  - `derive_snapshot_id_domain_separated` — synthetic
    snapshots with identical post-prefix bytes hash
    differently iff the prefix bytes differ (verifies the
    prefix is load-bearing in the derivation).
  - `derive_snapshot_id_length_prefix_separates_neighbours` —
    `reorg_blocks` of length 0 vs. length 1 vs. length 2
    over the same `synced_height` produce distinct ids;
    canonical-encoding regression test.

C1 is the smallest type-and-derivation commit; the existing
test suite still runs (the new type has no callers yet);
new tests in `engine/refresh.rs::tests` cover the derivation.

---

### Commit C2 — Error / discriminant enums + `Reservation` augmentation + `ReservationState` machine

C2 lands the Phase 0a / 0d / 0e / 0f-prerequisite type-level
additions in one bisection-coherent commit: the error enums,
the reservation extensibility seam, the snapshot-id pin on
existing `Reservation` / `PendingTx`, and the internal state
machine for R9's two-stage submit flow. No business-logic
change — these are data-shape additions whose consumers land
in subsequent commits.

C2 is decomposed into three sub-commits per bisection
discipline (per `90-commits.mdc`'s scope-per-commit rule and
PR 4's C5 / C5α / C5β precedent):

- **C2α — error enums (`SubmitError` + `SubmitErrorKind`;
  ancillary error enums for downstream traits).**

  Adds to
  [`engine/error.rs`](../../rust/shekyl-engine-core/src/engine/error.rs):

  ```rust
  #[derive(Debug)]
  #[non_exhaustive]
  pub enum SubmitError {
      SnapshotInvalidated {
          reservation_snapshot: SnapshotId,
          current_snapshot: SnapshotId,
      },
      DaemonRejected { kind: SubmitErrorKind },
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum SubmitErrorKind {
      DoubleSpend,
      FeeTooLow,
      Malformed,
      DaemonTimeout,
      DaemonUnavailable,
  }

  #[derive(Debug)]
  #[non_exhaustive]
  pub enum FeeEstimatorError {
      DaemonUnreachable,
      DaemonResponseInvalid { reason: &'static str },
  }

  #[derive(Debug)]
  #[non_exhaustive]
  pub enum OutputSelectorError {
      InsufficientFunds { needed: u64, available: u64 },
      NoEligibleOutputs,
  }

  #[derive(Debug)]
  #[non_exhaustive]
  pub enum SignerError {
      Unavailable,                                         // capability-bound
      RemoteFailure { reason: &'static str },              // HW-wallet trigger
  }
  ```

  All five enums `#[non_exhaustive]` per `21-reversion-clause-
  discipline.mdc`'s named-criteria pattern — the V3.0
  variant set is the audited surface, V3.x variants land
  additively without major-version breakage. Stage 4
  actor-migration may add `Cancelled` variants to
  `SignerError` / `FeeEstimatorError` / `OutputSelectorError`
  if the actor mailbox surfaces it; `#[non_exhaustive]`
  permits that addition without a trait-surface breaking
  change.

  Unit tests confirm `Debug` impls produce parseable output;
  no other test additions in C2α (the variants have no
  emission sites yet).

- **C2β — `DiscardReason` + `ReservationExtension` enums +
  `ReservationState` machine.**

  Adds to
  [`engine/pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs):

  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum DiscardReason {
      ConsumerExplicit,
      SnapshotRotationAutoDiscard,
      DaemonRejectedTerminal,
      TTLAutoDiscard,                 // V3.x emitter only
  }

  #[derive(Debug, Clone)]
  #[non_exhaustive]
  pub enum ReservationExtension {
      // V3.0 variant set: empty. V3.x adds coinjoin /
      // atomic-swap / time-locked / multi-stage / composable
      // variants without a trait revision.
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub(crate) enum ReservationState {
      Active,
      SubmitPendingDaemonAck,
      Resolved,
  }
  ```

  `ReservationState` is `pub(crate)` — invisible to
  consumers per §5.0.2 segment-2f pin (consumers observe
  state via diagnostic-stream events, not via trait
  surface).

- **C2γ — `Reservation` / `PendingTx` field augmentation.**

  Augments existing structs in `engine/pending.rs`:

  ```rust
  pub(crate) struct Reservation {
      // existing fields ...
      pub snapshot_id: SnapshotId,             // C1; pin per R12 (a)
      pub extensions: Vec<ReservationExtension>, // R14
      pub state: ReservationState,             // R9 segment-2f
  }

  pub struct PendingTx {
      // existing fields ...
      pub snapshot_id: SnapshotId,             // caller-visible for diagnostics
  }
  ```

  Stub construction sites in
  `build_pending_tx_in_state` populate the new fields with
  the to-be-implemented `derive_snapshot_id(&ledger_snapshot)`
  / `Vec::new()` / `ReservationState::Active`. The C2γ
  commit makes the field-augmentation visible without yet
  exercising the state-machine transitions (those land in
  C5's extracted method bodies).

  The `synced_height` / `reorg_blocks` reads needed for
  `derive_snapshot_id` require the `LedgerBlock` to expose
  a synthetic `LedgerSnapshot` view; the simplest path is to
  call `LedgerSnapshot::from_ledger(ledger)` at the
  build-pending-tx free function. The minor allocation
  (a `ReorgBlocks` clone, capped at
  `DEFAULT_REORG_BLOCKS_CAPACITY`) is bounded.

C2 (composite) leaves the test suite green: the augmented
data types have stub constructors at the existing free
functions; the existing assertion suite reads the existing
fields and the new fields are populated but unread (the
`Debug` derive provides a smoke-test surface; the existing
debug-format tests continue to match the augmented shape per
the standard `Debug` derive ordering). The CI gate is
`cargo fmt --all -- --check` clean + `cargo clippy
--all-targets -- -D warnings` clean + `cargo test --lib`
green.

---

### Commit C3 — `PendingTxDiagnostic` enum + diagnostics emission infrastructure

C3 lands the Phase 0f event enum and the emission-helper
infrastructure on the existing `DiagnosticSink` substrate
from PR 4. No production emission sites land yet — those
ride along with the C5 trait-impl extraction so the emission/
return coherence contract per §5.0.3 lands atomically with
the methods that emit.

C3's scope:

- Augments
  [`engine/diagnostics.rs`](../../rust/shekyl-engine-core/src/engine/diagnostics.rs)
  with the `PendingTxDiagnostic` enum:

  ```rust
  #[derive(Debug, Clone)]
  #[non_exhaustive]
  pub enum PendingTxDiagnostic {
      BuildSucceeded {
          reservation_id: ReservationId,
          snapshot_id: SnapshotId,
          fee_atomic_units: u64,
          recipient_count: usize,
      },
      BuildFailed {
          reason: BuildFailureClass,
      },
      SubmitAttempted {
          reservation_id: ReservationId,
          snapshot_id: SnapshotId,
      },
      SubmitSucceeded {
          reservation_id: ReservationId,
          tx_hash: TxHash,
      },
      SubmitFailed {
          reservation_id: ReservationId,
          kind: SubmitErrorKind,
      },
      SubmitSnapshotInvalidated {
          reservation_id: ReservationId,
          reservation_snapshot: SnapshotId,
          current_snapshot: SnapshotId,
      },
      Discarded {
          reservation_id: ReservationId,
          reason: DiscardReason,
      },
      ReservationOutstanding {       // V3.x ReservationTTLActor emitter
          reservation_id: ReservationId,
          age_secs: u64,
      },
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum BuildFailureClass {
      InvalidRecipient,
      InsufficientFunds,
      SignerUnavailable,
      LedgerNotReady,
  }
  ```

  `#[non_exhaustive]` on both per the extensibility pattern
  PR 4 / segment-2b established. `BuildFailureClass` is
  the projection-side discriminant for `BuildFailed`'s
  emission — sufficient for V3.0 consumer-actor template
  needs without leaking `SendError`'s `reason: &'static
  str` payloads across the recursive-trust-boundary per
  §5.0.3.
- Emission-helper additions: `pub(crate) fn
  emit_pending_tx_diagnostic(sink: &Arc<dyn DiagnosticSink>,
  event: PendingTxDiagnostic)` matches PR 4's
  `emit_refresh_diagnostic` shape. C3 lands the helper; C5
  wires its call sites in `LocalPendingTx`'s extracted
  method bodies.
- `AssertionSink` / `PanickingSink` from PR 4 C7 (`c9e65bbc6`)
  are already reused verbatim — no PR-5-specific sink
  variants needed. The existing `#[cfg(any(test, feature =
  "test-helpers"))]` gating covers both streams without
  modification.

C3 is doc + type addition; emission sites land in C5; no
test additions in C3 (the emission-coherence property tests
ride along with C7).

CI gate: `cargo fmt --check` + clippy clean + `cargo test
--lib` green (no functional change); `cargo doc --no-deps`
clean.

---

### Commit C4 — `Signer` / `OutputSelector` / `FeeEstimator` trait surfaces + default impls

C4 lands the three secondary-engine trait surfaces (Phase 0h
/ 0i / 0j per segment-2g) with their default V3.0 implementors
so the upcoming `PendingTxEngine` trait (C5) can dispatch
through them. The `Signer` trait is the load-bearing one (R11
(b) per segment-2b — `LocalPendingTx` never holds spend
material; `LocalSigner` is the sole holder; HW-wallet
integration in V3.x plugs in as an alternative `Signer` impl);
the `OutputSelector` / `FeeEstimator` traits are V3.0 narrow
seams whose default impls match wallet2-greedy / stub-fee
behavior verbatim, preserving the existing test surface.

C4 is decomposed into three sub-commits per bisection
discipline:

- **C4α — `Signer` trait + `LocalSigner` impl (R11 (b)).**

  Adds to
  [`engine/signer.rs`](../../rust/shekyl-engine-core/src/engine/signer.rs)
  alongside the existing `EngineSignerKind` sealed-trait
  surface:

  ```rust
  pub trait Signer: Send + Sync + 'static {
      type Error: Into<SignerError>;
      fn sign_transfer(
          &self,
          context: &TransferSigningContext,
      ) -> Result<SignedTransfer, Self::Error>;
  }

  pub struct LocalSigner {
      keys: Arc<AllKeysBlob>,
  }

  impl LocalSigner {
      pub(crate) fn new(keys: Arc<AllKeysBlob>) -> Self { Self { keys } }
  }

  impl Signer for LocalSigner {
      type Error = SignerError;
      fn sign_transfer(
          &self,
          context: &TransferSigningContext,
      ) -> Result<SignedTransfer, SignerError> {
          // Phase 1 stub: returns SignedTransfer with empty
          // body bytes (matches existing
          // build_pending_tx_in_state which sets
          // tx_bytes: Vec::new() per the existing
          // pending.rs:267 stub). Phase 2a wires
          // shekyl-tx-builder against `keys`.
          Ok(SignedTransfer::empty_phase1_stub(context))
      }
  }
  ```

  `TransferSigningContext` / `SignedTransfer` newtype shells
  ship as `pub(crate)` placeholders (Phase 2a fills them
  out). The signer's `Arc<AllKeysBlob>` is the sole holder
  of spend material in Stage 1 per R11 (b); Stage 4's
  `SigningActor` will hold the same `Arc` behind an
  `ActorRef` indirection (substitution-not-refactor at the
  V3.x migration).

  Tests cover:
  - `local_signer_holds_keys` — the `Arc<AllKeysBlob>`
    refcount discipline matches the design-time pin
    (one strong refcount per signer instance).
  - `local_signer_phase1_stub_succeeds` — the Phase 1 stub
    returns `Ok` for any well-formed context.

- **C4β — `OutputSelector` trait + `WalletGreedyOutputSelector`
  impl (R13).**

  New module `engine/output_selector.rs`:

  ```rust
  pub trait OutputSelector: Send + Sync + 'static {
      type Error: Into<OutputSelectorError>;
      fn select_outputs(
          &self,
          context: &OutputSelectionContext<'_>,
      ) -> Result<SelectedOutputs, Self::Error>;
  }

  pub struct OutputSelectionContext<'a> {
      pub ledger: &'a LedgerSnapshot,
      pub from_subaddress: Option<SubaddressIndex>,
      pub already_reserved: &'a BTreeSet<usize>,
      pub needed_amount: u64,
  }

  pub struct SelectedOutputs {
      pub indices: Vec<usize>,
      pub total_covered: u64,
  }

  pub struct WalletGreedyOutputSelector;

  impl OutputSelector for WalletGreedyOutputSelector {
      type Error = OutputSelectorError;
      fn select_outputs(
          &self,
          context: &OutputSelectionContext<'_>,
      ) -> Result<SelectedOutputs, OutputSelectorError> {
          // Body: extracted verbatim from
          // build_pending_tx_in_state lines 320–347
          // (the `candidates: Vec<(usize, u64)>`
          // construction + the largest-first selection
          // loop). No algorithmic change; only the
          // free-function-to-trait extraction.
          ...
      }
  }
  ```

  Tests cover:
  - `wallet_greedy_selects_largest_first` — regression
    test verifying the selection ordering matches the
    pre-PR-5 behavior byte-for-byte.
  - `wallet_greedy_insufficient_funds` — the
    `OutputSelectorError::InsufficientFunds` variant fires
    on under-coverage; the `needed` / `available` fields
    match the pre-PR-5 `SendError::InsufficientFunds`
    payload.
  - `wallet_greedy_no_eligible_outputs` — empty candidate
    set surfaces `NoEligibleOutputs` (new V3.0 surface;
    pre-PR-5 collapsed to `InsufficientFunds { needed: ...,
    available: 0 }`; the new surface is more precise but
    the orchestrator's `From<OutputSelectorError>` for
    `SendError` impl collapses it back to
    `InsufficientFunds { needed, available: 0 }` so the
    consumer-facing `SendError` surface is unchanged).

- **C4γ — `FeeEstimator` trait + `DaemonFeeEstimator` impl
  (R16).**

  New module `engine/fee_estimator.rs`:

  ```rust
  pub trait FeeEstimator: Send + Sync + 'static {
      type Error: Into<FeeEstimatorError>;
      fn estimate_fee(
          &self,
          priority: FeePriority,
          context: &FeeEstimationContext<'_>,
      ) -> Result<u64, Self::Error>;
  }

  pub struct FeeEstimationContext<'a> {
      pub ledger: &'a LedgerSnapshot,
      pub recipient_count: usize,
      pub input_count: usize,
  }

  pub struct DaemonFeeEstimator;

  impl FeeEstimator for DaemonFeeEstimator {
      type Error = FeeEstimatorError;
      fn estimate_fee(
          &self,
          _priority: FeePriority,
          _context: &FeeEstimationContext<'_>,
      ) -> Result<u64, FeeEstimatorError> {
          // Phase 1 stub: returns STUB_FEE_ATOMIC_UNITS
          // verbatim. Phase 2a wires daemon
          // get_fee_estimates against `_priority`.
          Ok(crate::engine::pending::STUB_FEE_ATOMIC_UNITS)
      }
  }
  ```

  The `FeePriority` enum migrates from `engine/pending.rs`
  to `engine/fee_estimator.rs` per the
  "trait-surface is the canonical citation" pin above;
  `engine/pending.rs` re-exports for backward source-text
  compatibility within the crate
  (`pub use crate::engine::fee_estimator::FeePriority;`).
  No external API breakage.

  Tests cover:
  - `daemon_fee_estimator_phase1_stub_returns_constant` —
    regression: any priority + context yields
    `STUB_FEE_ATOMIC_UNITS`.

C4 (composite) leaves the test suite green plus six new
tests across the three sub-commits. CI gate at each
sub-commit boundary: clippy + fmt + lib-tests pass; the
extracted helpers in C4β preserve byte-for-byte output
parity with the pre-PR-5 selection loop.

---

### Commit C5 — `PendingTxEngine` trait declaration + `LocalPendingTx` aggregate (extraction)

C5 is the **load-bearing extraction commit**: declares the
trait surface (Phase 0a..0f composite) and extracts the
free-function bodies from `engine/pending.rs` into the new
`LocalPendingTx` aggregate's trait impl. The trait surface
is method-shape-preserved per §5.0.1's invariance pin; the
extraction adds the snapshot-id pinning, the state-machine
transitions, the diagnostic emissions, and the dispatch
through C4's `Signer` / `OutputSelector` / `FeeEstimator`
traits.

C5 is decomposed into two sub-commits per bisection
discipline:

- **C5α — `PendingTxEngine` trait declaration +
  `LocalPendingTx` skeleton.**

  New file `engine/traits/pending_tx.rs`:

  ```rust
  pub trait PendingTxEngine: Send + Sync + 'static {
      type BuildError: Into<SendError>;
      type SubmitError: Into<SubmitError>;
      type DiscardError: Into<PendingTxError>;

      fn build(
          &mut self,
          ledger: &LedgerSnapshot,
          request: &TxRequest,
      ) -> Result<PendingTx, Self::BuildError>;

      fn submit(
          &mut self,
          ledger: &LedgerSnapshot,
          reservation_id: ReservationId,
      ) -> Result<TxHash, Self::SubmitError>;

      fn discard(
          &mut self,
          reservation_id: ReservationId,
          reason: DiscardReason,
      ) -> Result<(), Self::DiscardError>;

      fn outstanding(&self) -> usize;
  }
  ```

  Method signatures match §5.0.1's invariance pin; the
  `&mut self` receivers are explicit serialization points
  (`Engine`-wrapped under `Arc<RwLock<Engine>>` in the RPC
  binary per cross-cutting lock 3; Stage 4 actor-mailbox
  serialization preserves the same contract). The
  `ledger: &LedgerSnapshot` parameter is the
  `LedgerEngine::snapshot()`-returned view per R12 (a) — the
  engine reads the snapshot once per call from
  the caller-provided `LedgerEngine` and threads it through;
  this preserves the no-cross-trait-synchronous-query
  contract per §5.0 ground 1 (Stage 1 internally; Stage 4
  via `LedgerDiagnostic::SnapshotMerged`).

  New file `engine/local_pending_tx.rs`:

  ```rust
  pub struct LocalPendingTx<S: Signer, O: OutputSelector, F: FeeEstimator> {
      signer: Arc<S>,
      selector: O,
      estimator: F,
      sink: Arc<dyn DiagnosticSink>,
      reservations: BTreeMap<ReservationId, Reservation>,
      next_id: u64,
      network: Network,
  }

  impl<S: Signer, O: OutputSelector, F: FeeEstimator>
      LocalPendingTx<S, O, F>
  {
      pub fn new(
          signer: Arc<S>,
          selector: O,
          estimator: F,
          sink: Arc<dyn DiagnosticSink>,
          network: Network,
      ) -> Self {
          Self {
              signer,
              selector,
              estimator,
              sink,
              reservations: BTreeMap::new(),
              next_id: 0,
              network,
          }
      }
  }
  ```

  Per §5.0.2.1 segment-2f sink-binding closure: the
  `Arc<dyn DiagnosticSink>` is constructor-bound. Per R11
  (b) segment-2b: `signer: Arc<S>` is constructor-bound as
  well; `LocalPendingTx` holds an `Arc` to the signer but
  delegates all spend-secret access through the `Signer`
  trait — no direct field access to `AllKeysBlob`. The
  struct's `reservations` + `next_id` fields are the
  pre-PR-5 `Engine`-side fields, migrated here per the
  extraction.

  C5α's trait impl body for `PendingTxEngine` is **stub**:
  each method returns `unimplemented!("filled in C5β")`.
  The skeleton compiles green so C5β's diff is a body-fill
  rather than a structural change.

  Tests added: `local_pending_tx_new_constructs` smoke test
  only (struct field-set sanity); the trait-impl tests
  ride along with C5β.

- **C5β — `PendingTxEngine` trait-impl bodies (extraction
  with augmentation).**

  Fills out the three trait-method bodies in
  `engine/local_pending_tx.rs`:

  ```rust
  impl<S: Signer, O: OutputSelector, F: FeeEstimator>
      PendingTxEngine for LocalPendingTx<S, O, F>
  {
      type BuildError = SendError;
      type SubmitError = SubmitError;
      type DiscardError = PendingTxError;

      fn build(...) -> Result<PendingTx, SendError> {
          // Body extracted from
          // build_pending_tx_in_state(...) at
          // engine/pending.rs:285-385, with the following
          // augmentations:
          //   1. Output selection dispatches through
          //      self.selector.select_outputs(...) per C4β
          //      (replaces the inline candidate-construction
          //      and greedy-loop; same algorithm, trait-
          //      indirect).
          //   2. Fee resolution dispatches through
          //      self.estimator.estimate_fee(...) per C4γ
          //      (replaces the inline STUB_FEE_ATOMIC_UNITS
          //      constant).
          //   3. Signing dispatches through
          //      self.signer.sign_transfer(...) per C4α
          //      (Phase 1 stub: returns empty bytes;
          //      `tx_bytes: Vec::new()` per the existing
          //      pending.rs:267 stub semantics).
          //   4. The reservation gains
          //      snapshot_id: derive_snapshot_id(ledger) per
          //      C1+C2γ (R12 (a) pin).
          //   5. The reservation gains
          //      state: ReservationState::Active per C2β
          //      (R9 segment-2f initial state).
          //   6. The reservation gains
          //      extensions: Vec::new() per R14 (V3.0
          //      empty seam).
          //   7. PendingTxDiagnostic::BuildSucceeded is
          //      emitted via self.sink on the success path
          //      per §5.0.3 emission/return coherence (R8
          //      segment-2e deliverable 1).
          //   8. PendingTxDiagnostic::BuildFailed { reason }
          //      is emitted on each error path before
          //      returning Err(...) per §5.0.3 emission/
          //      return coherence; the BuildFailureClass
          //      projection is constructed at the emission
          //      site (InvalidRecipient / InsufficientFunds /
          //      SignerUnavailable / LedgerNotReady — the
          //      Class is the discriminant the consumer
          //      observes; the &'static str payload stays
          //      inside SendError and is not leaked across
          //      the recursive-trust-boundary per §5.0.3).
          ...
      }

      fn submit(...) -> Result<TxHash, SubmitError> {
          // Body extracted from
          // submit_pending_tx_in_state(...) at
          // engine/pending.rs:391-443, with the following
          // augmentations:
          //   1. Pre-daemon staleness check: compare
          //      reservation.snapshot_id against
          //      derive_snapshot_id(ledger). On mismatch:
          //      reservation removed; emit
          //      PendingTxDiagnostic::SubmitSnapshotInvalidated
          //      + PendingTxDiagnostic::Discarded
          //      { reason: SnapshotRotationAutoDiscard };
          //      return Err(SubmitError::SnapshotInvalidated
          //      { reservation_snapshot, current_snapshot })
          //      per R5 lazy-discard semantics.
          //   2. State transition Active → SubmitPendingDaemonAck
          //      pre-daemon-call (R9 segment-2f); emit
          //      PendingTxDiagnostic::SubmitAttempted.
          //   3. Daemon-call dispatch is a Phase 1 stub:
          //      returns Ok(TxHash) with id-encoded bytes
          //      (matches pre-PR-5 stub behavior in
          //      submit_pending_tx_in_state line 411-425).
          //      Phase 2a replaces with daemon broadcast.
          //   4. State transition SubmitPendingDaemonAck →
          //      Resolved on Ok path; emit
          //      PendingTxDiagnostic::SubmitSucceeded.
          //   5. Per R9 segment-2f Finding 2: the Phase 1
          //      stub has no Timeout / DaemonUnavailable
          //      path (always returns Ok); the per-error-
          //      class disposition table is exercised by
          //      C7's property tests injecting
          //      FaultInjecting<P>-queued failures, not by
          //      production code-path coverage in C5β.
          //   6. The existing tip-hash-comparison
          //      defense-in-depth check (PendingTxError::
          //      ChainStateChanged) is preserved as a
          //      redundant cross-check after the
          //      snapshot-id check.
          ...
      }

      fn discard(...) -> Result<(), PendingTxError> {
          // Body extracted from
          // discard_pending_tx_in_state(...) at
          // engine/pending.rs:444-465, with the following
          // augmentations:
          //   1. PendingTxDiagnostic::Discarded { reason }
          //      emitted on success path; `reason` is the
          //      caller-provided DiscardReason (typically
          //      ConsumerExplicit per Phase 1; V3.x
          //      ReservationTTLActor passes TTLAutoDiscard
          //      via the same surface).
          //   2. The existing UnknownHandle error variant
          //      is preserved verbatim (no diagnostic
          //      emission on the unknown-id path per
          //      §5.0.3 coherence: emission is for
          //      successful state changes; the error is
          //      caller-visible).
          ...
      }

      fn outstanding(&self) -> usize {
          // Counts Active + SubmitPendingDaemonAck per R9
          // segment-2f (both reserve outputs); excludes
          // Resolved (terminal). Pre-PR-5
          // outstanding_reservations on Engine counted
          // self.reservations.len() — the migration
          // changes the counted set per the R9 state-machine
          // refinement.
          self.reservations
              .values()
              .filter(|r| matches!(
                  r.state,
                  ReservationState::Active
                      | ReservationState::SubmitPendingDaemonAck,
              ))
              .count()
      }
  }
  ```

  The free functions
  `build_pending_tx_in_state` / `submit_pending_tx_in_state`
  / `discard_pending_tx_in_state` are **removed** in C5β;
  the existing in-state unit tests in `engine/pending.rs`'s
  `tests` module are migrated to drive
  `LocalPendingTx::build` / `submit` / `discard` directly
  (using `LocalSigner::new(Arc::new(AllKeysBlob::fixture()))`
  / `WalletGreedyOutputSelector` / `DaemonFeeEstimator`
  /`Arc::new(NoopSink)` from the test-helper
  re-exports). The pre-PR-5 test coverage is preserved
  byte-for-byte after the migration — the test bodies
  change only at the construction site, not at the
  assertion logic.

  Tests added or migrated:
  - All existing pre-PR-5 `tests` in `engine/pending.rs`
    migrate to call `LocalPendingTx::*` rather than the
    free functions. Migration is mechanical; no
    coverage loss.
  - New tests covering the augmentations:
    - `build_emits_build_succeeded_diagnostic` —
      AssertionSink records BuildSucceeded on success.
    - `build_emits_build_failed_on_each_error_class` —
      AssertionSink records the corresponding
      BuildFailureClass for each `SendError` variant.
    - `submit_emits_submit_snapshot_invalidated_on_stale` —
      reservation built against snapshot S1; ledger
      advanced to S2; submit returns
      SubmitError::SnapshotInvalidated with matching
      ids; AssertionSink records the matching event
      sequence (SubmitAttempted is *not* emitted because
      the snapshot check pre-empts entry into
      SubmitPendingDaemonAck per R5 + R9
      coherence).
    - `discard_emits_discarded_with_reason` —
      AssertionSink records the Discarded event with
      the caller-provided reason.
    - `outstanding_excludes_resolved_reservations` —
      after a successful submit, `outstanding()`
      decrements; after a snapshot-invalidated submit,
      `outstanding()` decrements (the reservation is
      auto-discarded per R5).

C5 is the **largest commit in the PR**. The diff is bounded
by the extraction scope: ~1000 lines of `engine/pending.rs`
shrink to ~300 lines (wire-facing types only); ~900 lines
of new `engine/local_pending_tx.rs` (struct + trait impl);
~70 lines of `engine/traits/pending_tx.rs` (trait surface).
Net code is roughly even with PR 4's C5's local_refresh.rs
expansion.

CI gate at C5 commit boundary: clippy + fmt + lib-tests
green; pre-PR-5 in-state tests all still pass (via
migration); new augmentation tests pass.

---

### Commit C6 — `Engine<S, D, L, R, P>` parameterization + orchestration-layer dispatch migration

C6 lands the fifth generic parameter on `Engine` and rewires
the orchestration-layer methods (`build_pending_tx` /
`submit_pending_tx` / `discard_pending_tx` /
`outstanding_reservations`) to dispatch through `P:
PendingTxEngine` rather than reading
`Engine`'s own `reservations` field directly. The
`Engine.reservations` / `Engine.next_reservation_id` fields
are **removed** in C6 — the state lives on the
`LocalPendingTx` aggregate now.

C6's scope:

- `Engine<S, D, L, R, P>` type signature updated in
  [`engine/mod.rs`](../../rust/shekyl-engine-core/src/engine/mod.rs)
  to add the fifth parameter. Default type
  `P = LocalPendingTx<LocalSigner,
  WalletGreedyOutputSelector, DaemonFeeEstimator>`
  preserves the existing concrete-typed shape for
  production callers (CLI / RPC binary), mirroring PR 4's
  C5 / C5α / C5β `R = LocalRefresh` precedent.
- Field migration: `Engine.reservations`,
  `Engine.next_reservation_id`, and the `_signer:
  PhantomData<S>` are restructured. The `signer` mode is
  still discriminated by the `S: EngineSignerKind`
  parameter; the runtime spend-secret holder is now the
  `pending: P` field's interior `Arc<Signer>` per C5's
  `LocalPendingTx` construction. The `_signer:
  PhantomData<S>` stays (it remains compile-time
  discriminator for capability surfaces); the
  `reservations` + `next_reservation_id` fields are
  removed.
- Orchestration-layer rewires in
  [`engine/pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs)
  (the `impl<S, D> Engine<S, D, LocalLedger>` block at
  line 466 in the pre-C6 file):

  ```rust
  impl<S, D, L, R, P> Engine<S, D, L, R, P>
  where
      S: EngineSignerKind,
      D: DaemonEngine,
      L: LedgerEngine,
      R: RefreshEngine,
      P: PendingTxEngine,
      P::BuildError: Into<SendError>,
      P::SubmitError: Into<SubmitError>,
      P::DiscardError: Into<PendingTxError>,
  {
      pub fn build_pending_tx(
          &mut self,
          request: &TxRequest,
      ) -> Result<PendingTx, SendError> {
          let snapshot = self.ledger.snapshot();
          self.pending.build(&snapshot, request)
              .map_err(Into::into)
      }

      pub fn submit_pending_tx(
          &mut self,
          id: ReservationId,
      ) -> Result<TxHash, SubmitError> {
          let snapshot = self.ledger.snapshot();
          self.pending.submit(&snapshot, id).map_err(Into::into)
      }

      pub fn discard_pending_tx(
          &mut self,
          id: ReservationId,
      ) -> Result<(), PendingTxError> {
          self.pending
              .discard(id, DiscardReason::ConsumerExplicit)
              .map_err(Into::into)
      }

      pub fn outstanding_reservations(&self) -> usize {
          self.pending.outstanding()
      }
  }
  ```

  Note: `Engine::discard_pending_tx`'s public surface
  drops the `reason` parameter; orchestration-layer
  callers always pass `ConsumerExplicit`. The internal
  trait `discard(id, reason)` retains the parameter for
  R8's V3.x `ReservationTTLActor` to call with
  `TTLAutoDiscard` and for the C5β snapshot-mismatch path
  that calls with `SnapshotRotationAutoDiscard` from
  inside `submit`. The orchestration layer is the
  caller-facing surface; the broader `DiscardReason` set
  is internal.
- Lifecycle constructors (`Engine::create`, `Engine::open_*`)
  updated to construct the default `LocalPendingTx` per
  the new field-set in
  [`engine/lifecycle.rs`](../../rust/shekyl-engine-core/src/engine/lifecycle.rs):

  ```rust
  pending: LocalPendingTx::new(
      Arc::new(LocalSigner::new(Arc::new(keys.clone()))),
      WalletGreedyOutputSelector,
      DaemonFeeEstimator,
      sink.clone(),
      network,
  ),
  ```

  The `sink` is the `Arc<dyn DiagnosticSink>` already
  threaded through the lifecycle constructor per PR 4.
  The `keys.clone()` creates the second `Arc<AllKeysBlob>`
  refcount handle; one stays on `Engine`'s `keys` field
  (for view-side derivations on refresh / scan), one
  flows into the signer. Both are `Arc`-strong references;
  drop discipline is unchanged.
- `replace_pending_tx` consume-and-rebuild constructor on
  `Engine` for the test-helpers surface:

  ```rust
  #[cfg(any(test, feature = "test-helpers"))]
  impl<S, D, L, R, P> Engine<S, D, L, R, P>
  where
      S: EngineSignerKind,
      D: DaemonEngine,
      L: LedgerEngine,
      R: RefreshEngine,
      P: PendingTxEngine,
  {
      pub fn replace_pending_tx<P2: PendingTxEngine>(
          self,
          pending: P2,
      ) -> Engine<S, D, L, R, P2> {
          Engine {
              file: self.file,
              keys: self.keys,
              ledger: self.ledger,
              indexes: self.indexes,
              prefs: self.prefs,
              daemon: self.daemon,
              network: self.network,
              capability: self.capability,
              refresh: self.refresh,
              pending,
              sink: self.sink,
              _signer: self._signer,
          }
      }
  }
  ```

  Mirrors PR 4's C7 `replace_refresh` constructor at
  `8f0fbf2bb` per §6 test-substrate preservation list.
- Call-site sweep in
  [`engine/test_support.rs`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
  to update `make_test_engine_with_blocks` / equivalents
  to construct the default `LocalPendingTx` per the new
  field-set. Mechanical; no test logic change.

C6 leaves the test suite green: orchestration-layer methods
preserve their public signatures (modulo the
`discard_pending_tx` reason-parameter drop noted above —
which has no callers outside the test suite per the
call-site sweep). Pre-PR-5 integration tests against
`Engine::build_pending_tx` etc. continue to pass through
the dispatch-through-`P` indirection.

CI gate: clippy + fmt + lib-tests pass; the public-API
surface of `Engine::build_pending_tx` etc. is preserved
verbatim modulo the documented `discard_pending_tx` reason
drop (which is documented in the CHANGELOG C8 commit per
the standard test-call-site narrowing pattern).

---

### Commit C7 — `FaultInjecting<P: PendingTxEngine>` wrapper + property tests + R9 per-error-class coverage

C7 lands the test substrate that exercises the
`PendingTxEngine` trait through the same no-Mock
composition-paradigm wrapper PR 4 §6 settled. The wrapper
follows F-Mock-1..F-Mock-8 / Two-Enum-Architecture pins
from PR 4 §6.1 / §6.1.1 verbatim — no new substrate
discipline.

C7's scope:

- New file
  `rust/shekyl-engine-core/src/engine/fault_injecting_pending_tx.rs`:

  ```rust
  #[cfg(any(test, feature = "test-helpers"))]
  pub struct FaultInjecting<P: PendingTxEngine> {
      inner: P,
      queued_build_failures: VecDeque<SendError>,
      queued_submit_failures: VecDeque<SubmitError>,
      queued_discard_failures: VecDeque<PendingTxError>,
  }

  impl<P: PendingTxEngine> FaultInjecting<P> {
      pub fn new(inner: P) -> Self { ... }
      pub fn queue_build_failure(&mut self, e: SendError) { ... }
      pub fn queue_submit_failure(&mut self, e: SubmitError) { ... }
      pub fn queue_discard_failure(&mut self, e: PendingTxError) { ... }
      pub fn queued_build_failures(&self) -> usize { ... }
      pub fn queued_submit_failures(&self) -> usize { ... }
      pub fn queued_discard_failures(&self) -> usize { ... }
  }

  impl<P: PendingTxEngine> Drop for FaultInjecting<P> {
      fn drop(&mut self) {
          debug_assert!(
              self.queued_build_failures.is_empty()
                  && self.queued_submit_failures.is_empty()
                  && self.queued_discard_failures.is_empty(),
              "FaultInjecting<P> dropped with un-consumed queued failures"
          );
      }
  }

  impl<P: PendingTxEngine> PendingTxEngine for FaultInjecting<P> {
      type BuildError = SendError;
      type SubmitError = SubmitError;
      type DiscardError = PendingTxError;

      fn build(...) -> Result<PendingTx, SendError> {
          if let Some(e) = self.queued_build_failures.pop_front() {
              return Err(e);
          }
          self.inner.build(ledger, request).map_err(Into::into)
      }
      // submit / discard mirror identically.

      fn outstanding(&self) -> usize { self.inner.outstanding() }
  }
  ```

  The wrapper carries three independent queues (one per
  fallible method) per the F-Mock-3-sharpening
  trait-reachable-vs-orchestrator-constructed variant
  pattern PR 4 settled. Each queue is FIFO; the
  per-method semantics match PR 4's
  `FaultInjecting<R: RefreshEngine>` (`fault_injecting_refresh.rs`)
  one-to-one.
- Property tests in
  `engine/fault_injecting_pending_tx.rs::tests`:
  - Wrapper smoke tests (Class 1 per PR 4 §6.1.1):
    empty-queue passthrough; single-injection-then-
    delegation; multi-injection FIFO; queue-drain-on-
    teardown; Drop-time `debug_assert!` panic
    verification.
  - Per-error-class disposition tests (Class 2 per §6
    test-substrate preservation list; segment-2f
    per-error-class table coverage):
    - `submit_double_spend_emits_terminal_discarded` —
      queue `SubmitErrorKind::DoubleSpend`; assert
      `submit` returns
      `SubmitError::DaemonRejected { kind: DoubleSpend }`;
      assert AssertionSink records
      `[SubmitAttempted, SubmitFailed { DoubleSpend },
      Discarded { DaemonRejectedTerminal }]` in order
      (the wrapper's injection drives the
      orchestrator-side state-machine through Active →
      SubmitPendingDaemonAck → Resolved).
    - `submit_fee_too_low_releases_outputs` — queue
      `SubmitErrorKind::FeeTooLow`; assert outputs
      return to the pool (`outstanding()` decrements;
      next `build` can select the same outputs);
      AssertionSink records `[SubmitAttempted,
      SubmitFailed { FeeTooLow }, Discarded
      { DaemonRejectedTerminal }]`.
    - `submit_malformed_releases_outputs` — same
      shape as FeeTooLow but with `Malformed`.
    - `submit_timeout_keeps_reservation_in_submit_pending` —
      queue `SubmitErrorKind::DaemonTimeout`; assert
      `outstanding()` still counts the reservation
      (Finding 2 disposition (B) — daemon-side
      authority); AssertionSink records
      `[SubmitAttempted, SubmitFailed { DaemonTimeout }]`
      with no `Discarded` event; consumer-explicit
      `discard(id, ConsumerExplicit)` resolves;
      AssertionSink then records `Discarded
      { ConsumerExplicit }`.
    - `submit_daemon_unavailable_same_as_timeout` —
      structurally identical to the timeout case.
  - Coherence property tests (mirrors PR 4's
    `produce_scan_result_emission_return_coherence` /
    `produce_scan_result_panicking_sink_unwind_safe`):
    - `pending_tx_build_emission_return_coherence` —
      every non-`Cancelled` error from `build` produces
      at least one matching `BuildFailed` event before
      the error returns.
    - `pending_tx_submit_emission_return_coherence` —
      every non-`SnapshotInvalidated` `SubmitError`
      produces at least one matching `SubmitFailed`
      event; `SnapshotInvalidated` produces
      `SubmitSnapshotInvalidated` + `Discarded
      { SnapshotRotationAutoDiscard }`.
    - `pending_tx_panicking_sink_unwind_safe` —
      `PanickingSink` injection during build / submit /
      discard panics the call; assert no
      `LocalPendingTx` interior-state corruption
      (reservation count unchanged; next-id counter
      unchanged from pre-panic; `outstanding()` agrees).
- Hybrid test in `engine/pending.rs::tests` (the
  orchestration-layer integration test, mirroring PR 4's
  `hybrid_refresh_engine_orchestrator_cancellation_retries`):
  - `hybrid_pending_tx_engine_orchestrator_snapshot_rotation` —
    exercises the build/submit cycle across a snapshot
    rotation:
    1. Construct `Engine<SoloSigner, TestDaemon,
       FaultInjecting<LocalLedger>, FaultInjecting<LocalRefresh>,
       FaultInjecting<LocalPendingTx<LocalSigner,
       WalletGreedyOutputSelector, DaemonFeeEstimator>>>`.
    2. Build pending-tx at snapshot S1; reservation
       carries `snapshot_id = derive_snapshot_id(S1)`.
    3. Inject a fresh ledger block via
       `LocalLedger::from_test_blocks` substrate;
       refresh-engine produces a ScanResult that
       advances to S2.
    4. Submit pending-tx; assert `SubmitError::
       SnapshotInvalidated { reservation_snapshot:
       S1_id, current_snapshot: S2_id }` returns.
    5. Assert AssertionSink recorded the expected
       event sequence including the `Discarded
       { SnapshotRotationAutoDiscard }`.
- `proptest` already in `[dev-dependencies]` per PR 4 C7;
  no Cargo.toml change.

C7 is the property-test commit; CI exercises the Wrapper
Class 1, Class 2, Coherence, Panic-safety, and Hybrid
classes. The PanickingSink unwind-safety is the load-bearing
LocalPendingTx-internal-state-zeroization deliverable per
§3.1 secret-locality / §35 secure-memory inheritance.

CI gate: clippy under both default-features and
`test-helpers`; fmt; `cargo test --features test-helpers --lib`
green; `cargo doc --features test-helpers --no-deps`
green.

---

### Commit C8 — Docs propagation + CHANGELOG

Final commit; doc-only.

C8's scope:

- This design doc
  (`STAGE_1_PR_5_PENDING_TX_ENGINE.md`) Status banner is
  updated marking Phase 1 as landed; §6 review checklist
  gains the per-commit landing-SHA cross-references
  (mirrors PR 4 C8 / §6 landing-SHA discipline).
- The `Commit Cn — Landed:` lines in this §7.X section
  (C0–C8 plus the per-sub-commit C2α/β/γ, C4α/β/γ,
  C5α/β) are filled in with the implementation
  branch's actual commit SHAs.
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.5 prose past-tenses the "Stage 1 surface" section to
  reflect the landed implementation; cross-references
  this PR's merge SHA for the implementation locator.
- [`docs/CHANGELOG.md`](../CHANGELOG.md) `[Unreleased]` /
  `Added` section gains the `PendingTxEngine` trait + the
  `PendingTxDiagnostic` enum + the `Signer` /
  `OutputSelector` / `FeeEstimator` trait surfaces with
  their default impls + the `SnapshotId` opaque type +
  the `SubmitError` / `SubmitErrorKind` / `DiscardReason`
  / `ReservationExtension` enums; `Changed` section gains
  the `Engine<S, D, L, R, P>` fifth-parameter entry, the
  `Engine::discard_pending_tx` `reason`-parameter drop
  note, the `Reservation` struct's three new fields
  (`snapshot_id`, `extensions`, `state`), and the
  `PendingTx` struct's `snapshot_id` field; `Internal`
  section notes the `engine/pending.rs` free-function-to-
  method extraction.
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) gains:
  - HW-wallet integration entry (Signer-impl substitution
    against the existing architecture; trigger:
    HW-wallet support is requested) — replaces the
    pre-segment-2b deferred "V3.x PendingTxEngine
    signer-actor split" entry per §8 Round-2 segment-2b
    FOLLOWUPS amendment.
  - `WalletSideEstimator` entry (R16 V3.x; trigger:
    `LedgerEngine` historical-block fee-data
    accessor lands).
  - `SubmissionStrategyActor` instantiation entry (R15;
    V3.x; trigger: first V3.x consumer-actor PR or
    user-controlled deployment-strategy demand).
  - `ReservationTTLActor` instantiation entry (R8; V3.x;
    trigger: forgotten-reservation telemetry surfaces
    realistic V3.x-time workload need) — entry already
    exists per segment-2e; C8 closes the status-line
    "design segment 2e closed; awaiting V3.x consumer
    PR".
  - `SubmitFailureAnalyzer` entry (R9 segment-2f
    closure; V3.x) — already exists per segment-2f;
    C8 closes the status-line as above.
  - `TimeoutResolverActor` entry (R9 Finding 2
    daemon-side authority complement; V3.x) — already
    exists per segment-2f; C8 closes the status-line.
- The `feat/stage-1-pr5-pending-tx-engine` branch's PR
  description references this §7.X commit list as the
  contract; CI green at every commit per the Phase 1
  bisection-discipline gate.

C8 is the docs / changelog commit; the PR opens with C8
as the tip.

---

### Round 3 closure rule

Per the §7 closure rule strengthened in segment-2c, Round 3
closes when the wargaming surface **known at closure time**
is genuinely exhausted. Round 3's wargaming surface is the
**commit-decomposition substrate** — eight commits with
load-bearing-ordered bisection discipline, each commit's
scope bounded by the §4 Phase 0 binding-form pins, §6
review checklist items, and the existing-substrate
inventory above. The exhaustion test: every Phase 0a–0k
binding form maps to a specific commit; every §6
review-checklist item maps to a specific commit's test
deliverable; every existing pre-PR-5 substrate entry maps
to a specific commit's diff scope.

No commit-decomposition shape known at closure time
remains unexplored. New shapes surfacing in Round 4 (or
later — the implementation phase's adversarial review
may surface them) reopen Round 3 per the strengthened
closure rule; Round 3 closes here.

---

### Round 4 (implementation; outside the design-doc scope)

Round 4 is the implementation phase — the
`feat/stage-1-pr5-pending-tx-engine` short-lived branch
cuts off the post-Round-3 dev tip and lands C0–C8 per
this §7.X commit list. Per `06-branching.mdc` rule 2 the
branch is short-lived (target: ≤5 working days; ≤10 commits
— eight commits per this list, comfortably under the
ceiling). Per `06-branching.mdc` default workflow rule 5
the branch does not push to remote without explicit user
authorization.

The PR opens against `dev` after C8 lands locally with a
passing CI run. The PR description cross-references this
§7.X commit list as the contract and includes the
per-commit landing-SHA table once filled in.

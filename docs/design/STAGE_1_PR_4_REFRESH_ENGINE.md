# Stage 1 PR 4 — `RefreshEngine` extraction — design

**Status.** **DRAFT — Round 1, Round 1 review pass, Round 2,
Round 2 reframe, Round 2 reframe follow-up (contract pins),
Round 2 close-out (Phase 0c `InternalInvariantViolation`
plus Phase 0e `DaemonOp` / `ProtocolErrorKind` seed enums,
2026-05-13), Round 3 confirmation (α confirmed by PR 5
Round 1's disposition under the actor-mesh framing,
2026-05-14), Round 4 (commit decomposition + Phase 1
commit list, 2026-05-14), Round 4 review pass
(adversarial review of the post-Round-4 substrate before
Phase 1 cuts; nine findings dispositioned, 2026-05-15),
Round 4 review pass meta-review amendment (review of the
F1–F9 disposition substrate; three additional findings
F11–F13 dispositioned without reopening Round 1–4, 2026-05-15),
and Round 4 review pass meta-review post-amendment sub-pins
(review of F11–F13 dispositions; three Phase-1-author-aware
sub-pins F11-S / F12-S / F13-S sharpening the dispositions
without reopening F1–F9 or Round 1–4; F13-S substantively
closes the `SuppressedRateLimit` emission-cadence covert
channel, 2026-05-15), and **Round 5 substrate-decision
amendment** (no-Mock substrate inheritance from PR 3 §2.1.2;
C6 plan rewritten from `MockRefresh` to
`FaultInjecting<R: RefreshEngine>`; retroactive Mock-X
cleanup of `MockLedger` extracted as `FaultInjecting<L:
LedgerEngine>` and `MockDaemon` renamed to `TestDaemon`
land in PR 4's C6 substrate scope per
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) scheduling, 2026-05-20)
closed.** Round 1's load-bearing question (§5 producer
redesign) settled to **α — preserved current shape** per
§5.4. The Round 1 review pass (2026-05-12)
corrected §3.1's materially-wrong "no secret-touching surface"
framing to master-secret isolation routed through R4, surfaced
four additional residual questions (R4 view-material flow, R5
mid-scan reorg-abort, R6 `RefreshError::ConcurrentMutation`
boundary, R7 `ScanResult` atomicity-under-cancellation) per
§5.4.3, and recorded the three call-mode invocation-overhead
constraint (§5.4.4), the four adversarial scenarios under α
(§5.4.5), and the trait-surface contract pins (§5.4.6). Round 2
(2026-05-12) settled R1 / R2 / R3 / R4 / R7 cleanly per §5.4.7;
R5 was deferred and R6 chose `MalformedScanResult { reason:
&'static str }`. **Round 2 reframe (2026-05-13) supersedes
Round 2's R5 and R6 dispositions** with the two-channel
actor-mesh shape: synchronous trait return `RefreshError`
becomes **unit-variant-only** (`Cancelled` / `Io` /
`MalformedScanResult`; no payload of any kind — *the Phase 0c
close-out amendment below + the pre-existing payload-bearing
variants refine this framing: only `Cancelled` is unit;
`Io(IoError)`, `MalformedScanResult { reason: &'static str }`,
and `InternalInvariantViolation { context: &'static str }` carry
bounded compile-time-fixed payloads, with the `&'static str`
constraint preserving the no-memory-amplifier-vector property per
§5.4.7 R6 closure. Of these payload-bearing variants, only
`Io` and `InternalInvariantViolation` are reachable from a
`RefreshEngine` impl's `Self::Error`; `MalformedScanResult` is
constructed exclusively by the merge layer (§4 Phase 0c;
§6.1 two-enum architecture pin). The "no payload" framing
was correct for the round's `RefreshEngine` impl-side error
convention; the orchestrator-side enum was payload-bearing
throughout, refined here by additive forward-pointer per the
coherence-pass meta-discipline*), and a parallel
**`RefreshDiagnostic` event stream emitted via `DiagnosticSink`**
fans out to specialized consumer actors with per-consumer trust
posture and sanitization rules. The reframe dissolves R5 by
composition (a `ReorgAmplificationDetector` actor consumes
`ReorgObserved` events and signals cancellation back to the
orchestrator) rather than extending §7's checkpoint discipline.
§5.4.8 honestly enumerates five new attack surfaces the
diagnostic-stream seam introduces (peer-reputation fingerprint;
PeerId stability under Tor/I2P; rotation-timing side-channel;
diagnostic-stream covert channel; mailbox-saturation DoS) and
names mitigations for each. **The α-disposition still holds;
R1 / R2 / R3 / R4 / R7 from Round 2 still hold; R5 retires by
composition; R6 reframes to the two-channel shape.** The seed
framing (Round 1 opening) is preserved below as the
question-shape Round 1 evaluated against.

The reframe is also the recurrence pattern named by
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
under "the cost-benefit-defer-to-later anti-pattern" working
against itself: Round 2's first pass landed
"defer R5 + bounded-`&'static str` for R6" — the conventional
cost-benefit-defer answer; the reframe is the
architectural-integrity-now answer that lays the diagnostic-stream
seam now (modest additional surface — one parameter, one enum,
one trait) and defers only the consumer implementations,
unlocking composable security policies, fail2ban-style
intra-session mitigation, pattern-based recovery, and natural
R5 resolution in V3.x without re-opening PR 4's trait surface.

The same-day follow-up pass (recorded in §5.4.6 / §5.4.7 R6 /
§5.4.8 amendments) pins **two load-bearing contracts** that
the V3.x consumer-actor PR would otherwise have to re-derive
from first principles: (1) `DiagnosticSink::emit` is
non-blocking (closes the producer-liveness hazard a hostile
or buggy consumer sink could otherwise introduce), and (2)
emission/return coherence (closes the silent-error and
phantom-error failure modes the unit-variant trait return
cannot rule out at the type-system level). The follow-up
also names restart-amnesia as a deliberate threat-model
consequence pinned forward to the consumer-actor PR's design
discipline (coarse-window detection, not credit-history-based),
broadens the §5.4.8 #4 trust-boundary framing to recursively
include in-process aggregator-republisher actors, and seeds
the Phase 0e `MalformedKind` initial variant set against the
existing daemon-attributable
[`MalformedScanResult { reason: &'static str }`](../../rust/shekyl-engine-core/src/engine/merge.rs)
call sites. The doc captures the kind of pins that get
caught at external-audit time if not pinned now —
"what happens if `emit` blocks?" and "what guarantees
correspondence between the synchronous error and the
diagnostic event?" are auditor questions the design answers
ahead of time rather than post-hoc.

A subsequent contract-pin refinement pass on the same day
closes three smaller remaining holes (recorded in §5.4.6
amendments and the `DiagnosticSink` docstring): (1) the
non-blocking pin is extended to **hold under concurrent
emission** (not merely per-call non-blocking), foreclosing
the `Mutex<VecDeque<_>>` class of implementation that
type-checks against the literal pin and re-introduces the
producer-liveness hazard at scale; (2) a
**producer-panic-safety** robustness property is named for
the producer side — `Scanner` zeroizes cleanly via `Drop`
across a panicking `emit`, cancellation-token state remains
well-defined, no half-state leaks — and the property is
made Round 4 testable via a `PanickingSink` variant
alongside the `AssertionSink` coherence test (deliberately
*not* pinned as a sink trait contract, which would push
unenforceable burden onto every sink author); (3) the
emission/return coherence prose names the property test as
**canonical reference** for coherence semantics per
[`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc),
making prose / test drift impossible without explicit
re-examination. None of these re-open the reframe; they
tighten its load-bearing contracts so the V3.x consumer-actor
PR has the constraints it needs to design against.

A Round 2 close-out pass on the same day resolves two items
the contract-pin refinements had flagged as "Round 4 vs
Round 2 hygiene" questions, both worth settling in Round 2
because of their downstream impact. **First, the Phase 0c
amendment**: the orchestrator-side `RefreshError` enum gains
`InternalInvariantViolation { context: &'static str }`,
resolving the §5.4.7 R6 "(a) extend `ConcurrentMutation` or
(b) introduce `InternalInvariantViolation`" cleanup pin at
the design layer rather than at Round 4 commit-decomposition.
The disposition is **(b)** because the retry-loop call sites
at
[`engine/refresh.rs:1672–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
and
[`:2055–2065`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
are state-machine invariant violations ("loop body itself is
broken"), not retry-budget exhaustion; conflating both into
`ConcurrentMutation` would route "wallet under sustained
merge contention" and "wallet hit an internal bug" through
the same variant, denying downstream consumers
(`PeerReputationActor`, telemetry, user-facing error surface)
the structural distinction they need to respond correctly.
`&'static str` is appropriate at the orchestrator-internal
site because the field carries compile-time-fixed developer
content, not attacker-influenced data — the memory-amplifier
and log-exfiltration vectors the producer-trait unit-variant
discipline closes do not apply here. The variant also bounds
future migrations: future "state machine reached a path
marked should-never-happen" findings route here, not into
`MalformedScanResult` or `ConcurrentMutation`. **Second, the
Phase 0e seed enums**: `DaemonOp` and `ProtocolErrorKind`
initial variant sets are seeded against the producer's
actual call-site surface, with two ground-truth audit
findings. `DaemonOp` narrows to two variants
(`GetHeight`, `GetScannableBlockByNumber`) per the
[`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
audit — the producer issues exactly these two daemon RPCs;
`GetFeeEstimates` / `SubmitTransaction` belong to
`PendingTxEngine`, not the refresh producer.
`ProtocolErrorKind` is **fresh-defined**, not a re-export of
upstream
[`shekyl_rpc::RpcError`](../../rust/shekyl-oxide/shekyl-oxide/rpc/src/lib.rs);
upstream `RpcError` carries `String` payloads in three of
its eight variants and is not a bounded re-export candidate,
so the producer must **classify upstream into a bounded
enum at the diagnostic-emission boundary** before emitting.
The `String` payload elision is the load-bearing
classification step per §5.4.7 R6's memory-amplifier
closure. Round 4 commit-decomposition re-audits the producer
call sites and confirms the seed (the audit may surface
additional reachable upstream variants the seed missed, or
paths the seed listed that aren't actually reachable; the
audit is authoritative).

A Round 3 confirmation pass (2026-05-14) closes the
*provisionally-load-bearing* qualifier on Round 1's
α-disposition. PR 5 Round 1's disposition under the
actor-mesh framing (per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.0 / §5.2 / §5.5) confirms shape (1) — *snapshot-ID
pinning* — with the reservation tracker holding **monotone
semantics** under PR 4's α: the actor's mailbox FIFO is the
serialization point, `LedgerDiagnostic::SnapshotMerged` events
drive `PendingTxActor`'s `current_snapshot` field, and
staleness detection is a field comparison in the
submit-message handler rather than a cross-actor synchronous
query. The re-evaluation gate is **not exercised**; α is
confirmed and PR 4 advances directly to Round 4 (commit
decomposition + Phase 1 commit list). Round 3's substantive
content is therefore a housekeeping pass: §3.1's threat-model
framing acknowledges PR 5 R11 (b)'s dual-holder context;
§5.3, §5.4.7 R1, §5.4.8 #1, and §8 record the closure and the
broadened diagnostic-stream contract scope; §8 / FOLLOWUPS R4
(c) entries cross-reference the PR 5 R11 (b) `Signer` trait
substrate that reduces the V3.x R4 (c) migration cost.

Round 4 (2026-05-14) closes the design rounds with the
commit-decomposition + Phase 1 commit list deliverable per
the PR 1 / PR 2 / PR 3 / PR 5 precedent. The §4 Phase 0
candidates (0a–0e, with 0d struck) finalize as
binding-pinned at the type-signature level; §6 review
checklist fills in against the `V3_ENGINE_TRAIT_BOUNDARIES.md`
§2.3 spec (binding-check matrix, test-substrate preservation
list, call-site sweep audit, Round 4 readiness gate); §7
extends with the Round-4 retrospective and the §7.X Phase 1
commit-list (eight commits, sequenced by load-bearing
ordering); §8 closes out the five "Remaining for Round 4"
items as Round-4-deliverable or Phase-1-confirms. Round 4 is
mechanical relative to Rounds 1–3 — no new design surface
opens; the deliverables are the substrate Phase 1 cuts
against. The implementation branch
(`feat/stage-1-pr4-refresh-engine`) cuts off the post-Round-4
dev tip and lands the §7.X commit list.

The **Round 4 review pass (2026-05-15)** is an adversarial
review of the post-Round-4 substrate before Phase 1
implementation cuts. Two reviewers exercised the
diagnostic-stream seam, the encrypted-persistence opt-in
language at §5.4.8 #1, and the resilience surface from an
attacker's perspective (hostile-daemon wargaming, restart
orchestration, covert-channel composition). The pass produced
**nine actionable findings**, all dispositioned and applied
inline as substrate hardening rather than reopening any
Round 1–4 question:
**F1** rewrites the R17 encrypted-persistence opt-in language
from "V3.x evaluates" to a hard rejection at V3.0 with
strict conditional reopening criteria (six attack vectors
named: crypto code-path expansion, deserialization-on-startup,
metadata side-channel, cross-wallet correlation, DoS,
forensic-artifact);
**F2** refines the §3.1 wallet-lock-latency property from
"single-block scan time, typically tens of ms" to
"per-transaction scan time, sub-block-bounded; millisecond-
scale even under adversarial daemon block crafting" and
extends §7's checkpoint discipline from four to **five**
checkpoints (adding an inner per-transaction cancellation
check inside the per-block scan loop);
**F3** pins `AssertionSink` and `PanickingSink` as
permanent CI regression coverage rather than one-shot
landing tests;
**F4** adds a **seventh contract pin** at §5.4.6
(per-emitter FIFO ordering preserved; cross-emitter ordering
undefined);
**F5** strengthens §5.4.8 #4's aggregator-republisher
recursive-leak framing with a V3.x forward-template
(per-consumer external-surface audit, projection-or-rejection,
future CI-lint enforcement);
**F6** adds a producer-side per-class emission rate budget
to §5.4.8 #5 (per-block ceilings per event class plus a
`SuppressedRateLimit` variant);
**F7** adds a new §5.4.8 #6 explicitly rejecting the
"encrypted cache for RPC recovery" V3.x candidate at V3.0
under the same conditional-reopening discipline as F1;
**F8** adds a new §5.4.8 #7 acknowledging emit-timing variance
as a microarchitectural side-channel residual with a Phase 1
implementation note for bounded-variance lock-free queues;
**F9** adds a §6 projection-type audit per event class with
explicit V3.0 per-class projections for `TracingDiagnosticSink`.
The full review-pass writeup with reviewer attribution,
attack-vector analysis, and disposition reasoning lives at
**§5.4.9**. The pass is recorded as a forward-template artifact
under [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
"discovery cadence" framing — a substrate harden ahead of
implementation cuts is cheaper than a post-implementation
re-design, and the review-pass shape is reusable for PR 5+'s
pre-implementation substrate review. The α-disposition still
holds; all Round 1–4 dispositions still hold; the review pass
hardens contract pins and attack-surface dispositions without
opening a new design question.

The **Round 5 substrate-decision amendment (2026-05-20)** lands
mid-Phase-1 between C5β (legacy producer scaffolding deletion)
and C6 (test substrate). The C6 plan as written through Round 4
("`MockRefresh` test substrate; mirrors `MockDaemon` / `MockLedger`
from PR 1 / PR 2") is **stale prose** from before the PR 3 §2.1.2
Mock-X rejection landed. Building `MockRefresh` would instantiate
exactly the parallel-implementation anti-pattern PR 3 §2.1.2
rejected as a category and compound the Mock-X debt that
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) already schedules to be
paid down "alongside Stage 1 PR 4 or PR 5." The amendment
disposition:

1. C6 replaces `MockRefresh` with the no-Mock substrate shape
 PR 3 settled on: production-only `LocalRefresh` (already
 landed at C4) plus a composable `FaultInjecting<R:
 RefreshEngine>` wrapper for failure injection. The wrapper
 composes against any current or future `R` implementor
 without per-impl parallel-Mock proliferation.
2. The FOLLOWUPS-scheduled retroactive Mock-X cleanup of
 `MockLedger` (extract `FaultInjecting<L: LedgerEngine>`
 from the existing wrapper body; add
 `LocalLedger::from_test_blocks(...)` constructor;
 rewire `test_support.rs` callers) lands in PR 4's C6
 substrate scope, not deferred to PR 5. Current
 `MockLedger` is structurally already a `FaultInjecting<
 LocalLedger>`-shaped wrapper around `apply_scan_result_to_state`
 (per [`engine/test_support.rs:773`](../../rust/shekyl-engine-core/src/engine/test_support.rs));
 the cleanup is mostly extraction-and-rename, not a
 re-implementation.
3. The FOLLOWUPS-scheduled `MockDaemon` → `TestDaemon` rename
 (lower priority per FOLLOWUPS line 617; structural shape is
 already correct, only the naming is wrong) lands alongside
 the `MockLedger` cleanup so PR 4 closes both FOLLOWUPS
 entries in one substrate-pass.

Per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
§"cost-benefit-defer-to-later anti-pattern", the
architectural-integrity-now disposition is the default for
security-load-bearing substrate work pre-genesis; the pre-genesis
discount per [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)
applies, and PR 4 is the FOLLOWUPS-named landing slot. The
amendment is **not** a round reopening — it does not revisit any
trait-surface contract pin, attack-surface disposition, or commit-
decomposition ordering decision; it replaces stale C6 substrate
prose with the binding no-Mock shape PR 3 §2.1.2 settled. The
α-disposition, the F1–F13 dispositions, and the C0–C5 / C7 / C8
commit prose are all unchanged.

The **Round 5 sub-pin extension (2026-05-20)** is a same-day
follow-up review that surfaces eight Mock-X-substrate findings
(F-Mock-1 through F-Mock-8) on the Round 5 amendment, runs an
amendment-layering coherence pass against the post-Round-5
substrate, and pins a paradigm-disambiguation locus (§6.1) the
existing prose has been operating against implicitly. The pass
lands four substantive sharpenings and four minor audit-trail
notes; none reopen any Round 1–4 disposition or the Round 5
amendment itself, but they refine the Round 5 C6 substrate so
the Phase 1 author implements against an explicit pin rather
than reverse-engineering it from tests. **Substantive (F-Mock-1
through F-Mock-4):** F-Mock-1 pins the cfg-gating symmetry across
all four C6 surfaces (Option (a): all gated `#[cfg(any(test,
feature = "test-helpers"))]`; C6α scope includes the
`[features]` `test-helpers = []` addition with the `bench-internals`
rationale-comment precedent); F-Mock-2 pins the
`FaultInjecting` queue contract (FIFO ordering;
`queued_failures()` drain inspector per the existing
[`MockLedger::queued_failures`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
precedent; `debug_assert!`-on-Drop for non-empty queue;
reentrance pops the head); F-Mock-3 + F-Mock-3-sharpening pin
the wrapper-API design (Option (i): `type Error = RefreshError`;
the queue holds `RefreshError` values directly) and the trait-
reachable-variant enumeration. Empirical resolution against
[`engine/error.rs:148–270`](../../rust/shekyl-engine-core/src/engine/error.rs),
[`engine/local_refresh.rs:347–384`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs),
[`engine/traits/ledger.rs:270–273`](../../rust/shekyl-engine-core/src/engine/traits/ledger.rs),
and [`engine/merge.rs:181–451`](../../rust/shekyl-engine-core/src/engine/merge.rs):
of `RefreshError`'s six variants, **three are reachable from a
`RefreshEngine` impl's `Self::Error`** (`Cancelled` unit, `Io(IoError)`
payload, `InternalInvariantViolation { context: &'static str }`
payload constructed at the `From` impl site), and **three are
orchestrator-constructed only** (`ConcurrentMutation { wallet, result }`
constructed at the merge gate; `AlreadyRunning` constructed at the
binary-layer single-flight; `MalformedScanResult { reason: &'static str }`
constructed in `apply_scan_result_to_state` when scan-result internal-
shape invariants fail). Under Option (i) the wrapper exposes the
full `RefreshError` surface uniformly across all `R`, with two test
classes named explicitly (Class 1: wrapper-based trait-surface tests;
Class 2: From-conversion tests against `LocalRefresh` directly per
the two-enum architecture pin in §6.1). The cause-vs-effect testing
pattern for orchestrator-constructed variants is documented in C6α
prose (drive causes through `FaultInjecting<LocalLedger>` for
`ConcurrentMutation`; through `FaultInjecting<LocalRefresh>` queuing
`RefreshError::InternalInvariantViolation` directly for the producer-
returned-then-orchestrator-propagated path; orchestrator-side
retry-budget-exhaustion `InternalInvariantViolation` construction is
exercised by Option (i)-injectable cause paths via the retry-loop
construction sites). The two-enum architecture itself
(`LocalRefreshError` `pub(crate)` + `RefreshError` `pub` + `From`
bridge constructing/discarding payloads at the boundary) is a
`RefreshEngine`-specific positive architectural pattern pinned in
§6.1 as a forward-template for future per-trait PRs;
`LedgerEngine::apply_scan_result` carries no analogous intermediate
because its trait signature speaks `RefreshError` directly; F-Mock-4 anchors the
"structurally-already-`FaultInjecting<LocalLedger>`" claim against
the current-source verification at
[`engine/test_support.rs:773–812`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
so future re-readers don't have to re-verify. **Minor (F-Mock-5
through F-Mock-8):** F-Mock-5 adds an explicit C6β migration
table for `MockLedger`'s public test surface
(`with_seed` / `with_seed_and_state` / `queue_concurrent_mutation`
/ `queued_failures`) to its new home in
`FaultInjecting<LocalLedger>` plus `LocalLedger::from_test_blocks`,
and corrects the "replaces `MockLedger::new(...)`" prose error
(the constructor is named `with_seed` / `with_seed_and_state`,
not `new`); F-Mock-6 adds the Phase 1 author commitment note
to C6γ's commit-message template; F-Mock-7 confirms the
`test-helpers` feature does not currently exist in
[`Cargo.toml`](../../rust/shekyl-engine-core/Cargo.toml) and
pins the introduction as part of C6α's scope; F-Mock-8
enumerates the C6α smoke-test property classes by name across
two test classes per the two-enum architecture pin in §6.1: Class 1
(wrapper-based, four sub-properties: empty-queue passthrough;
single-injection-then-delegation; multi-injection FIFO ordering;
queue-drain-on-teardown), and Class 2 (From-conversion tests against
`LocalRefresh` directly: each `LocalRefreshError` variant exercised
end-to-end against the corresponding `RefreshError` variant the
`From` impl produces — Class 2 lives in
[`local_refresh.rs`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)'s
existing tests module per the `local_refresh_error_maps_to_refresh_error`
precedent, sibling to the wrapper test surface, not a replacement).

The **amendment-layering coherence pass (2026-05-20)** runs
two lenses against the post-Round-5 substrate: (1)
layered-amendment forward-pointer gaps (sites where a later
amendment refined an earlier disposition without an inline
pointer back from the earlier site) and (2)
composition-paradigm-vs-actor-paradigm language conflation
(sites where the prose drifts between the two paradigms
without naming the seam). Lens 1 surfaces the pre-Phase-0c
forward-pointer gap as a **recurrence pattern** — the same
class of finding F-Mock-3 surfaced from one angle, present at
three sites (the Status banner's Round 2 reframe paragraph; §3.1's
two-channel error surface prose; §4 Phase 0c's inline comment).
All three sites carry the Round 2 reframe's "unit-variant-only;
no payload of any kind" framing which is correct for the
`RefreshEngine` impl's `Self::Error` (per the convention;
`LocalRefreshError` is unit-only by design) but reads as a flat
claim about the orchestrator-side `RefreshError` that the Phase 0c
amendment and pre-existing payload-bearing variants
(`Io(IoError)`, `MalformedScanResult { reason }`) later refined.
The lens records the **amendment-forward-pointer convention** as a
meta-discipline alongside `21-reversion-clause-discipline.mdc`'s
named-criteria principle: any future amendment that narrows or
refines an earlier round's contract lands its own forward-pointer
at the earlier site. The two disciplines are complementary —
reversion-clauses make rejection-dispositions readable across
substrate changes; forward-pointers make narrowing-amendments
readable across layered rounds. Both are about making layered
prose readable across time. Lens 2 finds no actionable
conflation — the doc is paradigm-honest (line 2747 explicitly
acknowledges "this applies in both the synchronous and actor-mesh
models"; §6 line 4589 honestly states "the α-disposition holds
under both the Round-1 synchronous framing and the Round-3
actor-mesh framing") — but lacks a single locus that defines
what each paradigm covers and where the seam sits. The new
§6.1 "Test-substrate paradigm pin" is that canonical locus.
The pass also lands a coordinated **V3.1 ledger-generator
FOLLOWUPS entry** (per the F-Mock-adjacent ledger-generator
question): PR 4 C6β's
`LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`
remains the V3.0 substrate (Need A — unit-test fixtures;
sufficient for `RefreshEngine` merge tests); the broader
`TestLedgerBuilder`-style coordinated test-infrastructure design
(Need B — valid FCMP++ transactions with valid PQC auth
signatures and valid curve-tree membership proofs, replacing the
deleted C++ chaingen harness for V3.x Rust unit tests on
tx-validation / tx-pool / staking invariants) is pinned as a
V3.1 substrate-design FOLLOWUPS entry to land BEFORE the first
daemon Rust port, with a structurally-valid-but-semantically-stubbed
middle-ground option flagged for the design conversation. The
amendment is **not** a round reopening — it pins what the existing
substrate already operates against; it does not revisit any
trait-surface contract pin, attack-surface disposition, or
commit-decomposition ordering decision. The α-disposition, the
F1–F13 dispositions, the Round 5 amendment, and the
C0–C5 / C7 / C8 commit prose remain unchanged; the C6
sub-decomposition (C6α / C6β / C6γ) gains the F-Mock dispositions
inline.

**Phase 1 landed (2026-05-20).** The §7.X commit list cuts
through against the post-Round-4 / post-Round-5 substrate as
specified; CI green at every commit per the Phase 1 bisection-
discipline gate. Landing SHAs on `feat/stage-1-pr4-refresh-engine`:
**C0** `322677261` (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.3 +
§7 amendment, doc-only) — landed on `dev` ahead of the branch
cut per Round 4's branching disposition; **C1** `d3edc1abb`
(`RefreshEngine` trait + `ViewMaterial` type); **C2**
`8fc207051` (`RefreshDiagnostic` + `DiagnosticSink` +
`NoopDiagnosticSink` + `TracingDiagnosticSink` + projection
plumbing + `SuppressedRateLimit` variant); **C3** `c45894ffe`
(`RefreshError::InternalInvariantViolation` variant addition,
bisectable from call-site migration); **C4** `ac100e1ab`
(`LocalRefresh` aggregate + `produce_scan_result` body + per-
output safe-point, with C4 prep at `e560d0c12` /
`365a2de7c` / `d385bd728`); **C5a** `553d70139`
(`Engine<S, D, L, R>` four-parameter type slot +
`ViewMaterial::try_from_keys` + `LocalRefresh` wired at
assemble); **C5b** `0dea3fd1e` (`RpcError` →
`ProtocolErrorKind` classifier + `DaemonProtocolError`
emission at the three retry-loop daemon-call sites);
**C5** `7140f726a` (orchestrator retry-loop migration to
trait dispatch on `R` + `InternalInvariantViolation` surfacing
at retry-loop construction sites); **C5β** `b6a1274de`
(legacy producer-scaffolding deletion in `engine/refresh.rs`
— `produce_scan_result` free function + `ProduceError` +
`ProgressEmitter` + duplicated helpers + constants;
orphaned tests ported / deleted against `LocalRefresh`);
**C6α** `e9310542a` (`FaultInjecting<R: RefreshEngine>`
wrapper + `test-helpers` Cargo feature +
`Engine::replace_refresh` test-only setter + Class 1 smoke
tests per F-Mock-8); **C6β** `e94526dec`
(`FaultInjecting<L: LedgerEngine>` extraction +
`LocalLedger::from_test_blocks(Vec<Block>)` constructor +
`MockLedger` retirement + hybrid retry test migration +
`ROLE_LEDGER` deletion); **C6γ** `b937906a6` (`MockDaemon`
→ `TestDaemon` rename across 99 call sites + active-doc
trajectory updates); **C7** `c9e65bbc6`
(`Engine::replace_refresh` consume-and-rebuild refactor +
`AssertionSink` + `PanickingSink` + `PanickingSinkTrigger` +
hybrid retry test
`hybrid_refresh_engine_orchestrator_cancellation_retries` +
producer-property-tests module with 5 parametric coherence
tests + 1 fuzzed proptest + 4 panic-safety tests + 1
classifier sanity test); **C8** *this commit*
(docs propagation + `CHANGELOG` + V3_ENGINE_TRAIT_BOUNDARIES
§2.3 past-tense + FOLLOWUPS Phase 0d-strike retirement
note). Round 5 substrate-decision amendment (`8484e669a`)
and Round 5 sub-pin extension (`29cb7e138`), plus the
F11-S audit-trail measurement evidence (`a4da2212a`), land
as design-doc commits on the implementation branch
alongside C5β / C6α and are not in the C0–C8 numbering.
Test-gate cumulative: 170 / 170 lib tests pass at C7;
`cargo fmt --all -- --check` clean; `cargo clippy -p
shekyl-engine-core --all-targets --features test-helpers --
-D warnings` clean; default-feature clippy clean; doc
warnings unchanged at 48 (zero new C7 warnings; baseline 49
pre-C7).

This document was opened in parallel with the
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
- The cancellation-checkpoint discipline pinned at
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 / §7. **Five checkpoints** (Round 4 review pass, 2026-05-15;
  promoted from four; see §5.4.9 F2): checkpoint 1 (top-of-attempt)
  and checkpoint 4 (pre-merge) belong to the orchestrator on
  `Engine<S>`; checkpoint 2 (post-tip-fetch), checkpoint 3
  (mid-scan, between blocks), and **checkpoint 5 (per-transaction,
  inside the per-block scan loop)** belong to
  `RefreshEngine::produce_scan_result`. **Checkpoint 5 fires at a
  pinned safe point** (Round 4 review pass amendment, 2026-05-15;
  see §5.4.9 F11): between consecutive per-transaction iterations
  of the scan loop, **before** the next transaction's view-tag
  / hybrid-decap / key-image derivation begins, **after** the
  prior iteration's `Zeroizing<…>`-wrapped per-output materials
  have left scope. Firing checkpoint 5 mid-derivation (between
  view-tag pre-filter and hybrid-decap, or between hybrid-decap
  and key-image) is forbidden — the partial-derivation state
  exposes secrets that the safe-point pin keeps off the unwound
  stack. The per-transaction checkpoint 5 bounds wallet-lock-
  latency content-independently under adversarial daemon block
  crafting; pre-Round-4-review-pass the discipline was four-
  checkpoint and the lock-latency bound was per-block (content-
  dependent). This split is part of the contract.
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
   (`run_refresh_task` and the five-checkpoint cancellation
   discipline within it; promoted from four by Round 4 review
   pass F2 — see §5.4.9 F2). The implementor owns the producer-
   side scan-cursor state per §2.3's ownership clause.
3. **Engine generic parameter.** `Engine<S, D, L, R: RefreshEngine
   = LocalRefresh>` per the §2.3 generic-parameter pattern (Round
   3's “parameterize over `R`” disposition matching PR 1's `D`,
   PR 2's `L`).
4. **Orchestration migration.** `Engine::start_refresh` and
   `Engine::refresh` continue to live as inherent methods on
   `Engine<S>`, calling
   `self.refresh.produce_scan_result(...)` against the trait
   instead of the inline producer body.
5. **Cancellation-token plumbing.** No semantic change at the
   trait surface from the §2.3 split; the orchestrator-owned
   checkpoints (1 and 4) stay where they are, and the producer-
   owned checkpoints (2, 3, and 5) move into the
   `LocalRefresh::produce_scan_result` body. Checkpoint 5 (the
   per-transaction inner cancellation check inside the per-block
   scan loop) is the new pin from Round 4 review pass F2 (see
   §5.4.9 F2); its emission semantics are otherwise identical to
   checkpoints 2 and 3 (poll cancellation token, return
   `RefreshError::Cancelled` if fired).

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
  **five** documented checkpoints, not arbitrarily — reviewed in
  M3-tail's CI tests. **Wallet-lock-latency property (Round 4
  review pass refinement; see §5.4.9 F2).** The lock-latency
  bound is **per-transaction scan time** (sub-block-bounded;
  millisecond-scale even under adversarial daemon block crafting),
  not per-block scan time. Checkpoint 5 (between transactions
  within a block; §7) bounds lock-latency content-independently:
  an adversarial daemon serving a maximally-hostile block
  (large block, high view-tag-match rate) cannot extend
  spend-secret residency-in-memory beyond the single-transaction
  scan window. The bound holds for typical and pathological
  blocks alike. The pre-Round-4-review-pass "tens of ms typical"
  framing (correct for typical blocks; broken under adversarial
  block crafting) is retired. **Checkpoint-5 safe-point pin
  (Round 4 review pass amendment, 2026-05-15; see §5.4.9 F11).**
  The "per-transaction scan window" the bound names is
  measured from one safe-point firing to the next — the check
  fires *between* per-transaction derivations, *after* the
  prior iteration's per-output secrets leave scope, *before*
  the next iteration loads its materials. The threat-model
  property the bound delivers therefore refines: not just
  "spend-secret residency capped at single-transaction scan
  time" but specifically "no per-output derived secret is
  resident on the stack at the moment cancellation is
  observed." Mid-derivation firing (between view-tag pre-filter
  and hybrid-decap; between hybrid-decap and key-image
  computation) would defeat this property and is forbidden by
  the safe-point pin.
- **Master-secret isolation (corrected per Round 1 review pass).**
  The seed's earlier framing ("does not touch `KeyEngine`, does
  not derive secrets, does not hold output secrets") was
  materially wrong — the existing producer
  ([`build_scanner_from_keys`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  at line 1254) consumes `&AllKeysBlob` and constructs a
  `Scanner` carrying both the **view secret** (for the X25519
  view-tag pre-filter and the hybrid-decap chain) and the
  **spend secret** (for key-image computation per output). The
  Scanner is per-attempt — built at the start of
  `run_refresh_task` and dropped at the end — but it observably
  holds spend material across the attempt's lifetime. The
  load-bearing threat-model property is therefore not "no
  secrets" but **master-secret isolation**: the producer's
  derivation of per-output material happens inside the
  attempt's stack frame and is dropped (with `Zeroize`) when the
  attempt ends; no per-output derived secrets cross the trait
  surface to the orchestrator. This matches the post-Round-3
  PR 3 handle-indirected workflow shape (per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md)
  §3.1.2): the trait's contract is "the orchestrator never
  observes derived per-output secrets."

  **R4 settled (Round 2, §5.4.7).** View-material flow lands as
  (a-instance-scoped): `LocalRefresh::new(view_material:
  ViewMaterial)` captures view-and-spend material at construction;
  the Scanner is held for `LocalRefresh`'s lifetime and zeroized
  on drop via the existing `ZeroizeOnDrop` chain. The master-
  secret-isolation property is now unconditional under the
  Round 2 disposition.

  **R4 (a) plus PR 5 R11 (b) — V3.0 dual-holder framing
  (Round 3 acknowledgment, 2026-05-14).** PR 5 Round 2
  segment 2b's R11 reframe lands `LocalSigner` /
  `SigningActor` as a separate spend-material holder (per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R11). V3.0 therefore has **two spend-material
  holders**: `LocalRefresh` / `Scanner` via PR 4 R4 (a)
  (justified by inheritance-asymmetry — `Scanner` pre-existed
  in C++ carrying view + spend material; the producer-side
  split-the-state migration would have lifted `Scanner`'s
  output shape and `ScanResult`'s wire shape inside this PR's
  scope), and `LocalSigner` via PR 5 R11 (b) (justified by
  architectural-integrity-now — `LocalSigner` is greenfield
  Rust with no inherited shape to absorb, so the split is the
  *cost-asymmetric* answer in the opposite direction).
  The two holders converge to one in V3.x: PR 4 R4 (c)
  (split-producer/recoverer) migrates the producer to hold
  **only view material** by emitting view-tag-matched
  candidates and delegating final hybrid-decap + key-image
  computation outside the producer; PR 5 R11 (b)'s `Signer`
  trait substrate is the target shape — `LocalSigner` /
  `SigningActor` becomes the sole holder once R4 (c) lifts.
  The §3.1 threat-model property (master-secret isolation:
  per-output derived secrets do not cross the trait surface
  to the orchestrator) holds for both holders independently
  in V3.0 — `LocalRefresh` zeroizes via `Scanner`'s
  `ZeroizeOnDrop` at attempt end; `LocalSigner` zeroizes via
  `Zeroizing<[u8; 32]>` on `spend_secret`. The V3.0
  two-holder state is named, tracked, and convergent; §5.4.7
  R4 and §8 / FOLLOWUPS R4 (c) record the migration target.

  **Per `30-cryptography.mdc` and `35-secure-memory.mdc`.** The
  Scanner's stack-frame materials (`view_scalar`, `x25519_sk`,
  `ml_kem_dk`, `spend_secret`) are already `Zeroizing<…>`-wrapped
  in the existing implementation (lines 1279–1292). Constant-time
  concerns activate inside the Scanner's hybrid decap and HKDF
  chain (per PR 3 §3.1.1), not at the trait surface; the trait
  surface does not expose timing-observable operations.
  Adversarial-input considerations against the constant-time
  framing are recorded in §5.4.5 below.

- **Two-channel error surface (Round 2 reframe; §5.4.7 R6,
  §5.4.8; orchestrator-side enum extended by Round 2 close-out
  / §4 Phase 0c; two-enum architecture pinned in §6.1).** PR 4
  separates the synchronous trait return from
  the actor-mesh diagnostic stream. The `RefreshEngine` impl's
  `Self::Error` is **unit-variant-only** by convention — no
  string, no evidence, no payload at the impl-side surface — so
  the attacker-influenced memory-amplifier vector (§5.4.5) is
  closed by construction at the producer-internal boundary. The
  orchestrator-side `RefreshError` enum (per §4 Phase 0c;
  §6 binding-check matrix) carries payload-bearing variants
  (`Io(IoError)`, `MalformedScanResult { reason: &'static str }`,
  `InternalInvariantViolation { context: &'static str }`) where
  the payload content is compile-time-fixed developer content,
  not attacker-influenced data. Of these payload-bearing variants,
  only `Io` and `InternalInvariantViolation` are reachable from a
  `RefreshEngine` impl's `Self::Error` via the `From` impl boundary;
  `MalformedScanResult` is constructed exclusively by the merge
  layer (`apply_scan_result_to_state` in `engine/merge.rs`) when
  scan-result internal-shape invariants fail, and the orchestrator-
  only variants (`ConcurrentMutation`, `AlreadyRunning`) are
  constructed at the merge-gate / binary-layer single-flight
  respectively. The orchestrator's branch table remains structural
  (cancel-propagate / retry-with-backoff / peer-rotation /
  invariant-violation-surface); the impl's `Self::Error` (e.g.,
  [`LocalRefreshError`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs),
  `pub(crate)`, unit-variant-only) maps to the orchestrator-side
  `RefreshError` via the `Self::Error: Into<RefreshError>` trait
  bound at the orchestrator boundary, where the orchestrator-side
  payload content is constructed at the `From` impl site. This
  is the **two-enum architecture** (`RefreshEngine`-specific;
  `LedgerEngine::apply_scan_result` returns `Result<(), RefreshError>`
  directly with no `Self::Error` indirection per
  [`engine/traits/ledger.rs:270–273`](../../rust/shekyl-engine-core/src/engine/traits/ledger.rs))
  pinned in §6.1 as a positive architectural pattern and
  forward-template for future per-trait PRs. The parallel `RefreshDiagnostic` event stream
  emitted via `DiagnosticSink` carries the rich structured
  information consumed by specialized actors (peer-reputation,
  recovery, telemetry, logger) with per-consumer trust posture
  and sanitization rules.

  **Threat-model property added by the diagnostic-stream seam.**
  Full-fidelity `RefreshDiagnostic` events stay **inside the
  wallet trust boundary** — in-process, inter-actor. Cross-
  process or network-bound consumers receive only **projection
  types** that have been explicitly sanitized at the boundary.
  This is the same principle as production/debug log separation,
  applied at the messaging layer; it is pinned in §5.4.6 as a
  trait contract so Stage 4's actor topology design cannot
  accidentally route full-fidelity events through a less-trusted
  actor (e.g., a remote UI process, a crash reporter with a
  network sink, or a tracing infrastructure with off-host
  storage). §5.4.8 enumerates the five attack surfaces this seam
  introduces and names mitigations for each.

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

- [x] Threat-model alignment (§3.1; corrected in Round 1 review
      pass — master-secret isolation framing, R4-resolved in
      Round 2 to (a-instance-scoped)).
- [x] Architectural-inheritance audit (§3.2).
- [x] Producer-redesign decision (§5.4 — α, Round 1, 2026-05-12).
- [x] Round 1 review pass (§5.4.3 R4–R7, §5.4.4 call modes,
      §5.4.5 adversarial scenarios, §5.4.6 contract pins,
      2026-05-12).
- [x] Round 2 dispositions (§5.4.7 — R2 / R3 / R4 / R5 / R6 / R7
      settled; R1 working hypothesis carried into PR 5,
      2026-05-12).
- [x] Round 2 reframe (§5.4.7 R5 / R6 / §5.4.8 — two-channel
      diagnostic-stream seam supersedes R5 "extend
      checkpoint 3" and R6 `MalformedScanResult { reason }`
      dispositions, 2026-05-13).
- [x] Round 2 reframe follow-up — contract pins (§5.4.6 /
      §5.4.7 R6 / §5.4.8 — `DiagnosticSink::emit`
      non-blocking + emission/return coherence + recursive
      trust-boundary + restart-amnesia detection
      discipline, 2026-05-13).
- [x] Round 2 reframe contract-pin refinements (§5.4.6 /
      `DiagnosticSink` docstring — concurrent-emit
      clarification + producer-panic-safety property +
      test-as-canonical-reference, 2026-05-13).
- [x] Round 2 close-out (§4 Phase 0c amendment —
      `InternalInvariantViolation { context: &'static str
      }`; §4 Phase 0e seeds — `DaemonOp` /
      `ProtocolErrorKind` initial variant sets against the
      call-site audit, 2026-05-13).
- [x] §5.5 work-list hygiene — P3
      (`apply_scan_result_to_state` `Vec<usize>`-discard at
      trait-impl call sites) row added against the dev-side
      FOLLOWUPS entry that landed via PR #37 (`0a0d46b38`,
      2026-05-10) during the design branch's pre-M3-tail
      window. Closes the work-list-vs-FOLLOWUPS audit
      delta before the design branch lands onto `dev`.
- [x] Phase 0 spec amendments identified (§4 — populated by
      Round 1 review pass; Round 2 finalized against the
      resolved residuals; Round 2 close-out extends Phase 0c
      and seeds Phase 0e enums).
- [ ] Phase 1 commit decomposition (§6 — pending Round 4;
      under (a-instance-scoped) the per-attempt scanner
      construction moves into `LocalRefresh::new` and the
      per-call setup cost drops, satisfying the §5.4.4
      invocation-overhead constraint by construction).

---

## §4 Phase 0 candidates (finalized at Round 4)

Phase 0 doc-only spec amendments precede Phase 1 implementation
per the PR 2 / PR 3 precedent. The list below is **binding-pinned
at Round 4** (2026-05-14); each candidate carries its
type-signature form and the round at which it stabilized.
Round 4's commit-decomposition pass (§7.X) lifts these as the
substrate Phase 1 cuts against.

**Phase 0 candidates (Round 1 review pass populated; Round 2
finalized the trait-surface entries; Round 2 close-out seeded
the variant sets; Round 4 binding-pin confirmed against the
call-site audit).**

- **Phase 0a — Trait-surface contract pins** in
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 / §7 prose:
  - `Send + Sync + 'static` bound on `R: RefreshEngine`
    (§5.4.6).
  - Progress-channel trust-boundary pin — consumers must be
    inside the wallet trust boundary (§5.4.6).
  - `ScanResult` atomicity-under-cancellation contract per R7
    — a `produce_scan_result` call returns either a `ScanResult`
    covering the full span it scanned, or
    `RefreshError::Cancelled`; no partial-span `ScanResult`.
    Confirmed against the existing implementation (cancel
    checks at
    [`engine/refresh.rs:980 / :1140 / :1186`](../../rust/shekyl-engine-core/src/engine/refresh.rs)).
  - `LedgerSnapshot` value-typed contract per §5.4.5 — confirmed
    against the type definition at
    [`engine/refresh.rs:147–156`](../../rust/shekyl-engine-core/src/engine/refresh.rs);
    cheap clone is honest because the type carries no shared
    state.
  - **`ViewMaterial` type definition** per §5.4.7 R4
    (a-instance-scoped): public `Zeroize + ZeroizeOnDrop` type
    carrying `{ spend_pub: EdwardsPoint, view_scalar:
    Zeroizing<Scalar>, x25519_sk: Zeroizing<[u8; 32]>,
    ml_kem_dk: Zeroizing<Vec<u8>>, spend_secret:
    Zeroizing<[u8; 32]> }`. Pinned at the trait surface so
    Stage 4 actor implementors and any future `RefreshEngine`
    impl share the constructor shape.

  Phase 0a was projected "likely empty under α" by the seed;
  the Round 1 review pass populated it; Round 2 finalized;
  Round 4 binding-pin **confirmed** against the call-site
  audit (§7.X commit C1 lands the Phase 0a spec amendment as
  one cohesive unit; the trait surface in §2.3 grows the
  `diagnostics` parameter and the per-attribute pins above
  in the same commit).
- **Phase 0b — `LocalRefresh::new(view_material: ViewMaterial)`
  constructor + flat-crate-root export.** Under §5.4.7 R4
  (a-instance-scoped), the constructor takes `ViewMaterial`;
  the existing `RefreshOptions` / `RefreshProgress` /
  `RefreshSummary` re-exports per
  [`lib.rs:25–30`](../../rust/shekyl-engine-core/src/lib.rs)
  cover the consumer surface — §5.4.7 R3 is a confirmation,
  not a promotion. `ViewMaterial` exports under the same flat
  convention.
- **Phase 0c — unit-variant `RefreshError` as trait error
  (Round 2 reframe) + `InternalInvariantViolation` on the
  orchestrator-side enum (Round 2 close-out, 2026-05-13).**
  Per §5.4.7 R6 reframe: trait-level `RefreshError` is
  **unit-variant-only** — `Cancelled` / `Io` /
  `MalformedScanResult` — with no payload of any kind. The
  synchronous trait return is the structural-branch signal;
  the rich diagnostic information moves to Phase 0e below.
  `Self::Error: Into<RefreshError>` in the trait surface;
  orchestrator's existing `RefreshError` enum is retained
  for backward compatibility and **extended with one new
  variant**:

  ```rust
  pub enum RefreshError {
      // Reachable from a `RefreshEngine` impl's `Self::Error` via
      // `Self::Error: Into<RefreshError>`. The impl's `Self::Error`
      // is unit-variant-only by convention (the Round 2 reframe's
      // "no payload at the impl-side surface" property — see
      // `LocalRefreshError`, `pub(crate)`, four unit variants).
      // Payload-bearing fields on these variants are constructed
      // at the `From<Self::Error>` impl site at the orchestrator
      // boundary, with the orchestrator supplying compile-time-
      // fixed `&'static str` content per the attacker-influenced-
      // data exclusion (§5.4.5 / §5.4.7 R6). Per §6.1 two-enum
      // architecture pin: this is the `RefreshEngine`-specific
      // shape; `LedgerEngine::apply_scan_result` speaks
      // `Result<(), RefreshError>` directly with no intermediate.
      Cancelled,                                       // unit
      Io(IoError),                                     // payload; from LocalRefreshError::{Io, Malformed}
      InternalInvariantViolation { context: &'static str }, // payload; from LocalRefreshError::Internal; also orchestrator-side construction at retry-loop sites
      // Orchestrator-merge-detected — not reachable from any
      // `RefreshEngine` impl's `Self::Error`; constructed
      // exclusively by `apply_scan_result_to_state` in
      // `engine/merge.rs` when scan-result internal-shape
      // invariants fail. `reason` is compile-time-fixed at the
      // construction site.
      MalformedScanResult { reason: &'static str },
      // Orchestrator-side merge / retry layer — never reached
      // from any trait impl; constructed by the orchestrator's
      // own control-flow (concurrent-mutation detection at merge;
      // binary-layer single-flight enforcement):
      ConcurrentMutation,
      AlreadyRunning,
  }
  ```

  **Why `InternalInvariantViolation` is its own variant, not
  an extension of `ConcurrentMutation`.** The two retry-loop
  call sites at
  [`engine/refresh.rs:1672–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  and
  [`:2055–2065`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  are **not** retry-budget exhaustion; the existing comments
  at those sites are explicit: *"falling through with `None`
  would mean the loop body itself is broken, which we
  surface as `MalformedScanResult` so audit reads a typed
  contract failure rather than silent retry exhaustion."*
  The unreached-invariant case is structurally distinct from
  the retry-budget-exhausted case (which is a legitimate
  `ConcurrentMutation` exhaustion, properly retryable at a
  higher level). Routing both through `ConcurrentMutation`
  would conflate "wallet is under sustained merge contention
  — back off and retry the user action" with "wallet hit
  an internal state-machine bug — please report and stop";
  downstream consumers (telemetry; future
  `PeerReputationActor`; future user-facing error surface)
  need different responses for the two cases. The variant
  separation is correctness-preserving, not stylistic.

  **Why `context: &'static str` is appropriate at this
  site.** The unit-variant discipline on the producer trait
  surface (Phase 0c trait-level `RefreshError`) was about
  closing the memory-amplifier and log-exfiltration vectors
  on attacker-influenced data per §5.4.7 R6. Neither vector
  applies to `InternalInvariantViolation::context`: the
  field is **compile-time-fixed developer content** at the
  orchestrator-internal call site — no daemon input flows
  in, no attacker-controllable string ever lands here. The
  `&'static str` preserves the existing developer-diagnostic
  content from the two current call sites (the comments
  cited above) as the migration target without information
  loss.

  **Future-proofing.** Any future orchestrator-internal
  "state machine reached a path the developer marked as
  'should never happen'" path routes here, not through
  `MalformedScanResult` or `ConcurrentMutation`. The
  variant exists categorically — the retry-loop-exhaustion
  sites are the immediate Round 4 migration target, but
  the variant bounds future migrations: future similar
  findings have a structurally-correct home rather than
  re-litigating where they belong.

  `ReorgTooDeep` stays as Ok-with-rewind merge-layer
  detection per the §1.5 actor-identity reasoning.
- **Phase 0d — retired (Round 2 reframe).** The Round 1-review-pass
  conditional candidate "checkpoint 3 extension for
  mid-scan reorg-abort" is **not landing in PR 4** and **not
  deferred as an open capability** — it retires by
  composition. R5 resolves via a `ReorgAmplificationDetector`
  actor consuming `RefreshDiagnostic::ReorgObserved` events
  (Phase 0e) and signalling cancellation back through the
  existing checkpoint-3 plumbing; the producer's checkpoint
  discipline does not grow. Phase 0d struck.
- **Phase 0e (new — Round 2 reframe) — `RefreshDiagnostic` +
  `DiagnosticSink` + `produce_scan_result` signature change.**
  Per §5.4.7 R6 reframe and §5.4.8 attack-surface
  enumeration:
  - `RefreshDiagnostic` enum (`#[non_exhaustive]`) with
    Stage 1 seed variants (`DaemonMalformed { kind:
    MalformedKind }`, `DaemonTimeout { op, elapsed }`,
    `DaemonProtocolError { kind }`, `ReorgObserved {
    fork_height, depth }`, `ScanProgress { height, candidates
    }`) and supporting bounded enums (`MalformedKind`,
    `DaemonOp`, `ProtocolErrorKind`); peer-attribution
    fields deferred until the future PR grows PR 1's
    `DaemonEngine` peer-aware surface.
  - `DiagnosticSink` trait (`Send + Sync + 'static`; one
    `emit(&self, event: RefreshDiagnostic)` method);
    trait-contract pin per §5.4.6 / §5.4.8 #4 (in-process
    only for full-fidelity; projection types cross trust
    boundaries).
  - `produce_scan_result` signature gains `diagnostics: &dyn
    DiagnosticSink` parameter (runtime-dispatch; per-call;
    locked now so Stage 4 does not re-rev the trait or widen
    `LocalRefresh::new`).
  - Stage 1 sink impls: `NoopDiagnosticSink` (drop everything)
    and `TracingDiagnosticSink` (route to `tracing::event!`);
    the production sink driving the actor mesh lands in
    V3.x's actor-mesh PR.
  - Flat-crate-root export under the existing
    `shekyl_engine_core` convention (R3 pattern).

  **Initial variant sets (Round 2 close-out seeding,
  2026-05-13; design-doc-completeness gain per the
  `#[non_exhaustive]` additive-growth discipline; Round 4
  commit-decomposition audit confirms).**

  `DaemonOp` — narrowed by the call-site audit. The producer
  issues exactly two daemon RPCs per
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs):
  `daemon.get_height()` (lines 1480 / 1958; tip fetch at
  top-of-attempt and post-tip-fetch fork detection) and
  `rpc.get_scannable_block_by_number(...)` (line 1190;
  per-block fetch of the scannable payload). No separate
  `GetBlocks` plural, no `GetTransactions`, no `GetOutputs`,
  no `GetChainHashes` — under FCMP++ with view-tag
  pre-filtering, the scannable-block RPC returns the full
  per-block payload the producer needs. Variants:

  ```rust
  #[non_exhaustive]
  pub enum DaemonOp {
      GetHeight,
      GetScannableBlockByNumber,
  }
  ```

  `GetFeeEstimates` and `SubmitTransaction` (the two
  `DaemonEngine`-extension methods on
  [`engine/traits/daemon.rs`](../../rust/shekyl-engine-core/src/engine/traits/daemon.rs))
  are **not** producer-issued and therefore not part of
  the refresh-producer's `DaemonOp` surface; they belong
  to PR 5's `PendingTxEngine`. If a future PR extends the
  diagnostic stream to cover `PendingTxEngine` ops, it
  either grows `DaemonOp` additively per `#[non_exhaustive]`
  or defines its own per-engine `DaemonOp` analogue.

  `ProtocolErrorKind` — fresh-define (not re-export), seeded
  against the call-site-reachable upstream
  [`shekyl_rpc::RpcError`](../../rust/shekyl-oxide/shekyl-oxide/rpc/src/lib.rs)
  subset. The upstream `RpcError` is a flat enum carrying
  `String` payloads in three of its eight variants
  (`InternalError(String)` / `ConnectionError(String)` /
  `InvalidNode(String)`), which makes it not a bounded
  re-export candidate — the producer must **classify
  upstream into a bounded enum at the diagnostic-emission
  boundary** before emitting. The classification responsibility
  lives on the producer, not on `DaemonEngine`. Variants
  (call-site-reachable for the refresh producer; the audit
  refines):

  ```rust
  #[non_exhaustive]
  pub enum ProtocolErrorKind {
      ConnectionError,       // RpcError::ConnectionError; transport failure
      InternalError,         // RpcError::InternalError; daemon-side failure (string payload elided)
      InvalidNode,           // RpcError::InvalidNode; daemon protocol violation
      InvalidTransaction,    // RpcError::InvalidTransaction; transaction within scannable block malformed
      PrunedTransaction,     // RpcError::PrunedTransaction; pruned transaction in scannable block (unsupported)
  }
  ```

  `RpcError::TransactionsNotFound` / `InvalidFee` /
  `InvalidPriority` are **not** reachable from refresh-issued
  RPCs (`get_height` / `get_scannable_block_by_number`);
  they surface on transaction-explicit-fetch / fee /
  priority paths owned by `PendingTxEngine`. If those paths
  ever produce `RefreshDiagnostic` events the variant set
  grows additively. The string-payload elision is the
  load-bearing classification step — `String` payloads must
  not flow into the diagnostic stream per §5.4.7 R6's
  memory-amplifier-vector closure.

  **Round 4 audit confirms.** Round 4 (2026-05-14) re-audited
  the producer's actual call sites against the Round-2 seed
  enumerations:

  - `DaemonOp` — **confirmed** as exactly two variants
    (`GetHeight`, `GetScannableBlockByNumber`). The audit at
    [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
    lines 1480 / 1958 (`get_height`) and line 1190
    (`get_scannable_block_by_number`) reproduces the seed
    exactly; no third producer-issued daemon RPC reachable
    from the refresh path.
  - `ProtocolErrorKind` — **confirmed** as five
    refresh-reachable variants (`ConnectionError`,
    `InternalError`, `InvalidNode`, `InvalidTransaction`,
    `PrunedTransaction`). The audit confirmed `RpcError::
    TransactionsNotFound` / `InvalidFee` / `InvalidPriority`
    are not reachable from `get_height` /
    `get_scannable_block_by_number`; they belong to PR 5's
    `PendingTxEngine` paths and grow `ProtocolErrorKind`
    additively per `#[non_exhaustive]` if PR 5 adopts the
    same diagnostic-stream substrate.

  The Round-4 audit is **authoritative**; the variant sets
  land in Phase 1 commit C2 (`RefreshDiagnostic` enum
  introduction) without further refinement. The
  `#[non_exhaustive]` discipline preserves additive
  growth without a binding-shape change.

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

### §5.3 Recommendation track (post-Round-2)

Round 1 settled α (§5.4); the Round 1 review pass surfaced R4–R7
plus the §5.4.4 / §5.4.5 / §5.4.6 substance; **Round 2 settled
all seven residuals (§5.4.7).** The remaining trajectory is now
narrower than the seed or Round 1 review pass projected: PR 5's
design rounds carry R1's working hypothesis (snapshot-ID pinning)
forward, and Round 4 is the only design round PR 4 needs before
Phase 0 lands.

- **Round 1 (closed, 2026-05-12).** Disposition α per §5.4. Four
  criteria evaluated: PR 4 extraction cleanliness; PR 5 two-phase
  build/submit/discard contract over reorg events; reservation-
  tracker reorg surfacing; Stage 4 actor compatibility. The
  validation-surface guard in
  [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)
  rejects bundling β/γ into PR 4 because they share the feature
  topic “refresh” without sharing PR 4's validation surface.
- **Round 1 review pass (closed, 2026-05-12).** Corrected §3.1's
  threat-model framing; surfaced R4 (load-bearing — view-material
  flow) / R5 (discipline-budget — mid-scan reorg-abort) / R6
  (hygiene — variant set) / R7 (load-bearing — atomicity); added
  §5.4.4 call modes, §5.4.5 adversarial scenarios, §5.4.6
  contract pins.
- **Round 2 (closed, 2026-05-12).** Settled R2 / R3 / R4 / R5 /
  R6 / R7 per §5.4.7. R1 carries forward to PR 5 with snapshot-ID
  pinning as the working hypothesis.
- **Round 3 (closed, 2026-05-14) — confirmation-shape.**
  PR 5 Round 1's disposition under the actor-mesh framing
  (per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0 / §5.2 / §5.5) confirms shape (1) — *snapshot-ID
  pinning*. The reservation tracker holds **monotone
  semantics** under PR 4's α: actor mailbox FIFO is the
  serialization point; `LedgerDiagnostic::SnapshotMerged`
  events drive `PendingTxActor`'s `current_snapshot` field;
  staleness detection is a field comparison in the
  submit-message handler. Shapes (2) and (3)
  (refresh-quiescence-and-reject; defer-build-until-refresh-
  quiescent) failed criterion 5 (adversarial-daemon
  resistance) on **structural** grounds under the framing —
  any contract dependency on refresh quiescence at any
  point in the build/submit flow is daemon-controllable —
  not contingent grounds; no fourth shape survived the
  framing. α's *provisionally-load-bearing* qualifier is
  therefore **closed**; the re-evaluation gate collapsed
  without firing. PR 4 advances directly to Round 4.
- **Round 4.** Phase 0 commit decomposition (against the
  Round 2-finalized §4 candidates); §6 review checklist filled in;
  Phase 1 commit list pinned. Sequencing under (a-instance-scoped)
  R4 is straightforward — `LocalRefresh::new(view_material:
  ViewMaterial)` is the new shape; Phase 1's first commit
  introduces the `ViewMaterial` type and the constructor; the
  per-attempt scanner build moves out of `run_refresh_task` and
  into `LocalRefresh`'s state.

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
was the operative governance for the re-evaluation gate:
Round 3 would have evaluated whether PR 5 needs γ for
**correctness** (not convenience), and the disposition
would have reverted if R1's resolution surfaced that the
reservation tracker could not deliver its correctness
property under α. **PR 5 Round 1's disposition under the
actor-mesh framing confirmed α** (per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.0 / §5.5): the reservation tracker's monotone semantics
hold; the field-comparison staleness check in the
submit-message handler delivers correctness without γ; the
structural-rejection of shapes (2) and (3) on criterion 5
closes the wargaming surface under the framing. Round 1's
α-disposition is therefore **confirmed, not provisional**,
and the re-evaluation gate collapsed without firing. The
discovery-cadence prediction in
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
("PR 4 onward's audits are increasingly likely to be
confirmations") holds at the Round 1 / Round 3 boundary on
the load-bearing question; the Round 2 reframe and PR 5
R11 (b)'s reframe are the two structural-density events
that surfaced inside this PR's design rounds (the
cost-benefit-defer-to-later anti-pattern surfacing once at
the load-bearing-question level, then again at the residual-
disposition level).

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
  ledger snapshot. PR 5's design rounds settle this as the first
  item on its agenda. **Working hypothesis (Round 1 review
  pass):** *build-against-current-snapshot with snapshot-ID
  pinning.* The reservation tracker carries a snapshot ID with
  each reservation; the submit path becomes a CAS — succeed iff
  `current_snapshot == reservation.snapshot_id`, else return a
  specific stale-snapshot error and the consumer rebuilds
  against the new snapshot. Of the three sub-options, this is
  the only shape that gives the reservation tracker monotone
  snapshot semantics and low-latency UI without serializing
  user input behind background work. `RefreshInProgress` flashes
  errors during normal steady-state polls; `block-until-merge`
  hangs the UI multi-minute on cold-open. PR 5's design rounds
  open with snapshot-ID pinning as the working hypothesis and
  look for a reason to reject it, not the other way around.
  The α-disposition's *provisionally load-bearing* status (per
  §5.3) was the re-evaluation gate — R1's resolution could
  have re-opened α if the reservation tracker's correctness
  property had not held under any sub-option. **PR 5 Round 1
  closed R1 under shape (1) (snapshot-ID pinning) under the
  actor-mesh framing** (per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0 / §5.2 / §5.5); the gate closed without firing and α
  is confirmed.
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
- **R4 — View-material flow to the producer (load-bearing).**
  §3.1's threat-model framing is conditional on R4. Three
  shapes:
  - **(a) Constructor-bound.**
    `LocalRefresh::new(view_descriptor: ViewMaterial)` —
    view-tag descriptor + view-decrypt capability (and key-image
    spend material if it stays in the producer per the current
    code) captured at `LocalRefresh` instantiation, not crossing
    the trait boundary per-call. Cleanest for Stage 4: the
    actor's mailbox shape carries no secrets. **Cost.** Ties
    `LocalRefresh`'s lifetime to wallet-unlock state — locking
    the wallet mid-refresh means the producer holds zeroizable
    material during a graceful-cancel window. The current
    `engine/refresh.rs` (lines 1421–1429) constructs the
    `Scanner` per attempt inside `run_refresh_task`, which is a
    sub-shape of (a) where the producer's keyed state is rebuilt
    each call rather than persisted across calls — Round 2
    enumerates whether (a-attempt-scoped) or (a-instance-scoped)
    is the PR 4 disposition.
  - **(b) Per-call.** View material crosses the trait boundary
    every call via `RefreshOptions`. Trivial today, hostile to
    actor migration: every mailbox message now carries secrets;
    `kameo`'s envelope crosses the trust boundary differently
    than a method call. **Disposition.** Argued against in
    Round 1 review pass per the Stage 4 envelope analysis;
    Round 2 confirms.
  - **(c) Split producer/recoverer.** Producer returns
    view-tag-matched candidates; the orchestrator (with
    `KeyEngine` access) does final hybrid-decap and key-image
    computation before `apply_scan_result`. Pushes work back to
    the orchestrator and changes `ScanResult` shape — non-trivial,
    but it is the only shape that makes §3.1's literal "no
    output secrets" claim true. **Cost.** `ScanResult`'s wire
    shape changes; the trait surface widens by one phase
    (recovery boundary). Round 2 evaluates whether the threat-
    model-cleanliness gain justifies the surface widening.

  R4 is the §4 Phase 0a/0b candidate that most directly affects
  the trait surface. Round 2 disposition; if (c) wins, Phase 1's
  commit decomposition includes the recovery-boundary shift.
- **R5 — Mid-scan reorg-abort at checkpoint 3.** Should
  checkpoint 3 (mid-scan, per §7) extend to detect daemon-tip
  reorgs during a scan attempt and abort the attempt early,
  rather than running to completion and failing at the merge
  gate? Adversarial daemon scenario per §5.4.5 below: under
  current §7 discipline, an adversarial daemon producing
  back-to-back reorgs sustains O(window) wasted scan work per
  reorg, indefinitely; checkpoint 3 catches cancellation but
  not reorg-during-scan. Mitigation cost: one daemon tip-poll
  per checkpoint-3 hit. Trade-off: extra daemon RPC cost per
  scan vs. hostile-daemon work amplification.
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 / §7 amendment if accepted. **Discipline-budget gate**:
  extending §7's checkpoint discipline has its own scope; R5 is
  a Round 2 disposition with potential to defer to V3.x if the
  Round 2 cost-benefit argues against landing it pre-genesis.
- **R6 — `RefreshError::ConcurrentMutation` boundary.**
  `ConcurrentMutation` is currently detected at merge time
  (post-checkpoint-4) by `LedgerEngine::apply_scan_result`, not
  inside the producer; the producer's error type is
  `ProduceError` (cancellation, daemon failure, scanner
  contract violation) and is translated by `run_refresh_task`
  into `RefreshError`. The trait surface should therefore not
  carry `ConcurrentMutation` on `RefreshEngine::produce_scan_result`'s
  error type — it is an orchestrator-internal translation of
  `LedgerEngine` errors. Round 2 (Phase 0c) confirms the variant
  set:
  - `Cancelled` — checkpoints 2 / 3 fired; orchestrator does
    not retry.
  - `DaemonError(D::Error)` — wrapped daemon failure;
    orchestrator may retry with backoff per peer-rotation
    policy (PR 1's `DaemonEngine` contract).
  - `ScannerContractViolation { kind, evidence }` — daemon
    returned malformed/inconsistent data; byzantine-daemon
    path (peer-ban candidate, not retry). The `evidence` field
    must be **bounded** — an attacker controls the daemon and
    a memory-amplifier shape is an attack vector (see §5.4.5).
  - `ReorgTooDeep { fork_height, max_rewind }` — beyond the
    snapshot's reorg window; requires wallet-side intervention
    (re-scan from earlier height, possibly user confirmation).
    Not retryable.
  - **Excluded.** `ConcurrentMutation` (orchestrator-internal,
    per above).

  Round 2 hygiene disposition; locks Phase 0c's variant audit
  to a single answer.
- **R7 — `ScanResult` atomicity-under-cancellation contract
  (load-bearing).** Trait contract pin: a `produce_scan_result`
  call returns either a `ScanResult` covering the **full** span
  it scanned, or `RefreshError::Cancelled`. **No partial-span
  `ScanResult`.** If the producer scanned blocks `[N, N+50)`
  and cancellation fires before completing block `N+50`, it
  returns `Cancelled`; the work for `[N, N+50)` is discarded;
  the orchestrator's retry-loop re-attempts from
  `snapshot.next_height`, not from a partial cursor.

  **Confirmed against the existing implementation.** The
  cancel checks at
  [`engine/refresh.rs:980`](../../rust/shekyl-engine-core/src/engine/refresh.rs),
  `:1140`, and `:1186` all return `Err(ProduceError::Cancelled)`
  immediately; partial accumulated state (`block_hashes`,
  `new_transfers`, `spent_key_images` for blocks already
  scanned) is discarded with the function frame. Atomicity is
  already a property of the existing producer; pinning it in
  the trait contract prevents a future `LocalRefresh` rewrite
  or Stage 4 actor implementor from drifting. **Adversarial
  note.** Without atomicity, an attacker who can trigger
  spurious cancellations (e.g., timer races at the orchestrator)
  could induce the merge gate to accept a stream of fragmented
  partial-snapshots. Atomicity is a correctness property, not
  hygiene. Round 2 prose update to
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 / §7; §4 Phase 0a candidate.

#### §5.4.4 Three call modes — invocation overhead constraint

The orchestrator calls `produce_scan_result` in three modes
with very different cost profiles. The trait must be cheap on
all three:

- **Cold open / restore.** First call after wallet load.
  Span: last-known-block to tip. On a freshly-restored wallet,
  this is the whole chain. For Shekyl V3-from-genesis this is
  not catastrophic for years, but `recover_from_seed` workflows
  hit it immediately. The trait needs `max_blocks`-style
  bounding (already present per
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  `RefreshOptions`) so the orchestrator can chunk this without
  holding a multi-minute attempt that blocks checkpoint 1.
- **Steady-state poll.** ~10–30 s cadence; span: 0–few blocks.
  Per-attempt overhead (snapshot clone, daemon `get_height`
  RPC, scanner construction, retry-loop fixed cost) dominates
  the work. Cancellation responsiveness here is "milliseconds"
  — if a user submits a tx during the poll window, checkpoint 1
  must fire fast. The orchestrator calls into the producer
  tens of thousands of times per wallet-day; per-call setup
  cost is paid every poll.
- **Post-submit confirmation.** Triggered by the
  `PendingTxEngine` workflow. Span: small; latency-sensitive —
  the UI is waiting for "1 confirmation" to flip. Under R1's
  `RefreshInProgress` sub-option, a steady-state poll racing
  with a submit causes a UI flash; under `block-until-merge`,
  the UI hangs briefly; under R1's working-hypothesis
  (snapshot-ID pinning), the UI shows pending and the next
  merge flips it cleanly. The post-submit-confirm path is the
  worst-UX case for the rejected R1 sub-options; this is one
  of the reasons the working hypothesis converges on
  snapshot-ID pinning.

**Constraint on Round 4 commit decomposition.** The §3.2
*moves not rewrites* posture is right partly because the
existing producer has already been tuned for this — but
Phase 1's commit decomposition must **explicitly not** introduce
per-call setup that the inherent method did not have. The R4
disposition is the load-bearing input here: option (c)
(split-producer/recoverer) widens the per-call surface; option
(a-attempt-scoped) preserves the current per-attempt setup
cost; option (a-instance-scoped) reduces per-call setup at the
cost of holding view material across the `LocalRefresh`'s
entire lifetime. Round 4 Phase 1 sequencing depends on R4.

**Round 2 reframe — `DiagnosticSink` per-call parameter is
cost-neutral.** The R6 reframe adds `diagnostics: &dyn
DiagnosticSink` to `produce_scan_result`'s signature. The
added per-call cost is one stack-pushed reference and one
vtable indirection per `sink.emit(event)` call site — both
negligible against the per-block scan envelope. In Stage 1
with `NoopDiagnosticSink`, the compiler can devirtualize and
elide the calls; in Stage 4 with the actor-mesh sink, the
per-event overhead is dominated by the `tokio::sync::mpsc`
send. **The invocation-overhead constraint above is
preserved under the reframe** — no per-call setup is added
beyond the parameter pass, and the steady-state poll mode's
~10K-calls/wallet-day envelope absorbs the parameter pass
trivially. Round 2 disposition R4 (a-instance-scoped) already
moves the per-attempt scanner construction out of the
per-call hot path; the reframe does not reintroduce it.

#### §5.4.5 Adversarial scenarios under α

Four scenarios where a malicious daemon — the most common
adversarial vector at this boundary, since the daemon is
outside the wallet's trust boundary — can stress the producer.
The α trait shape inherits these from the existing producer;
PR 4 makes the inheritance explicit so Stage 4's actor
implementor cannot drift away from the existing mitigations.

- **Reorg amplification.** Adversarial daemon produces a
  6-block reorg, wallet starts re-scan from fork height,
  daemon produces another reorg before scan completes. Under
  current §7 checkpoint discipline: checkpoint 3 catches
  cancellation but not reorg-during-scan. The producer runs
  to completion against the now-stale chain, returns a
  `ScanResult`, the merge gate detects mismatch, retries.
  Attacker can sustain O(window) wasted work per reorg,
  indefinitely. **Mitigation (Round 2 reframe — resolved by
  composition).** R5 retires here; a `ReorgAmplificationDetector`
  actor subscribing to `RefreshDiagnostic::ReorgObserved`
  events (Phase 0e) maintains windowed reorg counts and
  signals cancellation back through the existing
  `CancellationToken` checkpoint-3 plumbing. The producer's
  §7 checkpoint discipline does not grow; the detection logic
  lives in one actor. Implementation deferred to the V3.x
  actor-mesh PR; trait-surface seam lands in PR 4. See
  §5.4.7 R5 and §5.4.8 #1 (peer-reputation fingerprint), #3
  (rotation-timing side-channel) for related mitigations.
- **View-tag DoS.** View tags are limited entropy (8 bits in
  the X25519 view-tag pre-filter per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md)
  §3.1.1). Adversarial daemon crafts blocks with high
  false-positive view-tag rates — every output matches the
  view-tag, forcing trial-decrypt on each. CPU asymmetry:
  daemon's work to craft is O(1) per output, wallet's work to
  reject is O(decrypt). On real chains the view-tag rate is
  ~1/256; an attacker can amplify to 256/256 with crafted
  blocks. The producer's per-block compute is bounded by block
  size (and PR 1's daemon-side block-size limits are the
  outer envelope), but the bounding is loose — an attacker can
  saturate within those limits.

  **Disposition.** This is an implementation property of
  `LocalRefresh` / `Scanner`, not a trait-surface question.
  The Round 1 review pass explicitly notes that §3.1's
  "constant-time concerns activate inside the Scanner's hybrid
  decap and HKDF chain (per PR 3 §3.1.1), not at the trait
  surface" framing assumes non-adversarial input rates — the
  framing remains correct for the threat-model question (the
  hybrid decap is constant-time per output regardless of
  adversarial input), but the operational property "the
  producer's per-block compute is bounded under adversarial
  daemons" is a separate concern not delivered by the trait
  shape itself. **Round 2 reframe** opens a composition-side
  mitigation: high false-positive view-tag rates surface as a
  `RefreshDiagnostic` projection (rate of `ScanProgress`
  variants with high `candidates` per block); a future
  consumer actor (likely the `RecoveryActor` or a dedicated
  `ViewTagAnomalyDetector`) can apply threshold logic and
  signal cancellation, same shape as R5's resolution. PR 4
  pins the seam; the detector lands in V3.x.
- **Withholding / partial responses.** Daemon returns
  `tip = H` but withholds blocks `[H-k, H]`. Producer's
  behaviour depends on the daemon RPC — does it timeout,
  return empty, return error? Under the Round 2 reframe, the
  producer emits `RefreshDiagnostic::DaemonTimeout { op, elapsed }`
  or `RefreshDiagnostic::DaemonProtocolError { kind }` for
  consumer-side analysis; the synchronous trait return is
  `RefreshError::Io` (unit variant). PR 1's `DaemonEngine`
  trait specifies the RPC semantics; PR 4 inherits without
  re-litigating. Round 2 confirms PR 1's specification covers
  the withholding case; the diagnostic-stream variants give
  consumer actors the temporal context to distinguish
  "transient" from "byzantine."
- **Snapshot poisoning via `LedgerSnapshot`.** The producer
  reads `LedgerSnapshot` for reorg-window descriptors. If
  `LedgerSnapshot::clone` exposes any pointer-shared state,
  mutation by a parallel consumer could race. **Confirmed
  against the existing implementation.**
  [`engine/refresh.rs:147–156`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  defines `LedgerSnapshot { synced_height: u64, reorg_blocks:
  ReorgBlocks }` — a value type with no interior mutability;
  `ReorgBlocks` is itself value-typed. The "cheap clone" §3.1
  framing is honest: clones are deep in spirit because the
  type carries no shared state. Round 2 confirms the property
  holds under R4 (no R4 sub-option introduces shared state).
- **Memory-amplifier vector — closed by Round 2 reframe.**
  Round 1 review pass surfaced this as a concern under the
  proposed `ScannerContractViolation { kind, evidence }`
  variant: attacker-controlled `evidence` payload, even if
  bounded, is a memory-amplification surface. **The Round 2
  reframe closes the vector by construction:** the
  synchronous `RefreshError` is unit-variant-only (no
  payload, ever), and the `RefreshDiagnostic` stream's
  byzantine-daemon variant carries only a bounded enum
  (`MalformedKind`) with no attacker-controlled bytes. Stream
  consumers see typed-and-bounded events; the orchestrator's
  synchronous branch table sees variant tags. There is **no
  attacker-controlled-payload surface anywhere** in PR 4's
  trait or diagnostic-stream contract. §5.4.8 #5
  (mailbox-saturation DoS) addresses the related rate-control
  concern.

#### §5.4.6 Trait-surface contract pins (Phase 0a candidates)

The Round 1 review pass surfaces two trait-surface constraints
that do not need a residual letter (the disposition is not
"choose between options"; the constraint is a pin) but must
land in §4 Phase 0a's prose so Phase 1 has the bound to type-check
against and Stage 4 has the property to wrap around.

- **`Send + Sync + 'static` bound on `R`.**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 pins the bound on `D: DaemonEngine`; PR 4 pins it on
  `R: RefreshEngine` for symmetry. Stage 4's `kameo` actor
  wraps `LocalRefresh` as the actor body; the bound is the
  type-check predicate that lets the wrap compile. Listing it
  here rather than waiting for Stage 4 catches the common
  failure mode where a trait surface that "happens to be
  `Send + Sync + 'static` today" gains a non-`Send` method
  parameter before the actor wrap forces the issue.
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 amendment in Phase 0a.
- **Progress-channel trust-boundary pin (Round 1 review pass;
  generalized by Round 2 reframe).** The `RefreshProgress`
  channel surfaced in §2.3 carries `view_tag_matches_per_block`,
  `owned_candidates_observed`, and `current_height` (per the
  existing
  [`RefreshProgress`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  shape). In single-process Stage 1 wallets this is a non-issue;
  in Stage 4's actor model, the consumer of the `Progress`
  channel is a separate actor — possibly the UI actor. Progress
  messages correlate across time and reveal wallet activity
  rate.

  **Pin.** The trait contract states that `Progress` consumers
  **must** be inside the wallet trust boundary. Under the
  Round 2 reframe, the `RefreshProgress` watch channel becomes
  the UI-consumer projection of `RefreshDiagnostic::ScanProgress`;
  the pin generalizes to the broader diagnostic-stream
  trust-boundary pin below.
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 prose amendment in Phase 0a.
- **Diagnostic-stream trust-boundary pin (Round 2 reframe).**
  The `DiagnosticSink` contract surfaced in §5.4.7 R6 carries
  the full structured `RefreshDiagnostic` event stream —
  richer than `RefreshProgress` (`DaemonMalformed`,
  `DaemonTimeout`, `DaemonProtocolError`, `ReorgObserved`, and
  the variants that grow as the actor mesh's consumer
  patterns surface). Per §3.1 / §5.4.8 #4, sink implementations
  route full-fidelity events only to in-process consumers
  inside the wallet trust boundary; cross-process or network-
  bound consumers receive only **projection types** that have
  been explicitly sanitized at the boundary. The Progress-channel
  pin above is a specific case of this broader pin.

  **Pin.** The trait contract states that
  `DiagnosticSink::emit` consumers handling full-fidelity
  events **must** be inside the wallet trust boundary,
  **recursively** — see §5.4.8 #4 for the recursive framing
  that closes the in-process-aggregator-republisher hazard.
  PR 4 refuses to design the diagnostic-stream surface
  around the case where they are not. Stage 4's actor
  topology design must respect this; the trait-contract pin
  exists so Stage 4 cannot accidentally cross the boundary
  by routing `RefreshDiagnostic` events through a
  less-trusted actor (e.g., a remote crash reporter, a
  telemetry pipeline with network sinks, a tracing
  infrastructure with off-host storage, or an in-process
  actor that re-exports diagnostic state via a
  trust-boundary-crossing surface).
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 prose amendment in Phase 0a. Enforceable by review,
  not by the type system — Stage 4's review checklist
  includes the per-consumer trust-boundary audit.
- **`DiagnosticSink::emit` non-blocking pin (Round 2 reframe
  follow-up).** `DiagnosticSink::emit` **MUST NOT block** the
  calling task. Implementations use `try_send`-shaped
  semantics; on a full bounded channel, an unavailable
  consumer, or any other back-pressure condition, `emit`
  drops the event silently and returns promptly. The drop
  policy is the implementation's choice per §5.4.8 #5's
  taxonomy. **Rationale (pre-flight, per
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
  "what does this deliver against the threat model?").**
  Without the pin, a hostile or buggy consumer-actor sink
  implementation in V3.x can saturate its mailbox and pin
  the producer at the emission call. The producer holds the
  `Scanner`'s spend material across the pin, and the
  cancellation token at checkpoints 2 and 3 is not observed
  for the duration of the block. This compromises both the
  §5.4.4 invocation-overhead constraint and the §3.1
  wallet-lock-latency property — a blocked producer is a
  producer that cannot honor the four-checkpoint discipline.
  Pinning the non-blocking contract at the trait surface
  closes the hazard before any consumer-actor PR can
  introduce it. Phase 0e docstring amendment on the
  `DiagnosticSink` trait definition; binding on all V3.x
  consumer-actor sink implementations.

  **Concurrent-emit clarification (Round 2 reframe
  contract-pin refinements, 2026-05-13).** The
  `Send + Sync` bound on `DiagnosticSink` permits concurrent
  `emit` calls from multiple tasks. The non-blocking contract
  **holds under concurrent emission**, not merely per call.
  Serializing internal synchronization that admits unbounded
  contention — `Mutex<VecDeque<_>>`, `RwLock`-wrapped state,
  any shared mutable structure without bounded-wait
  guarantees — violates the contract even when each `emit`
  call returns "promptly" in isolation. Conforming
  implementations use lock-free queueing (e.g.,
  `crossbeam::queue::ArrayQueue`, `flume` non-blocking
  sends), atomic counters, or sharded mailboxes; not
  `Mutex<VecDeque<_>>`. **Rationale.** A per-call-only
  non-blocking property type-checks against the original
  pin and still re-introduces the producer-liveness hazard
  at scale: task A's `emit` blocks task B's `emit` because
  both contend on the sink's internal lock. This becomes
  load-bearing under any future producer-side parallelism
  shape (β-shape internal batching, a hypothetical multi-
  scanner architecture) or any Stage 4 actor-mesh topology
  where multiple `LocalRefresh` instances share a sink.
  Foreclosing the class now — at the contract surface,
  before any sink author has a chance to type-check around
  the literal-but-not-substantive interpretation — is the
  point. Phase 0e docstring amendment, same site as the
  base pin.
- **Emission/return coherence pin (Round 2 reframe
  follow-up).** `RefreshEngine` implementations **MUST**
  emit at least one corresponding `RefreshDiagnostic` event
  to the sink for every non-`Cancelled` `RefreshError`
  returned from `produce_scan_result`, **before** returning
  the error. The diagnostic event carries the structured
  information that the unit-variant error elides;
  consumer actors rely on this coherence to attribute
  synchronous errors to their detection context. **Failure
  modes the pin closes** (both fail open at the type-system
  level, both are silent without the pin):
  - **Silent error.** Implementation returns
    `Err(RefreshError::MalformedScanResult)` without
    emitting `RefreshDiagnostic::DaemonMalformed`.
    Orchestrator rotates peer per the structural branch
    table; reputation actor never learns what triggered
    the rotation; recovery actor sees no pattern;
    observability is blind. The unit-variant trait return
    is *only* useful to the orchestrator when it is paired
    with the structured event the diagnostic stream
    carries.
  - **Phantom error.** Implementation emits
    `DaemonMalformed` but returns `Ok(scan_result)`.
    Reputation actor decrements peer trust; orchestrator
    merges the scan result; the wallet treats a peer the
    reputation system considers untrustworthy as
    authoritative for the merge. The diagnostic event is
    *only* meaningful to consumer actors when it is paired
    with the synchronous outcome it attributes itself to.

  **Round 4 / Phase 1 candidate.** A property-test-shaped CI
  invariant wraps `LocalRefresh` with an `AssertionSink`
  that records every `emit` call; the test asserts coherence
  on fuzzed inputs — for each `produce_scan_result` call,
  any non-`Cancelled` `Err` return is preceded by at least
  one corresponding `RefreshDiagnostic` emission, and no
  `RefreshDiagnostic::DaemonMalformed` (or other
  error-class-attributed) event is followed by an `Ok`
  return. The property is enforceable by review and by the
  property test; the type system cannot enforce it
  directly. Phase 0a §2.3 prose pin; Phase 1 test design
  records the property-test invariant as a Round-4
  commit-decomposition deliverable.

  **Canonical-reference pin (Round 2 reframe contract-pin
  refinements, 2026-05-13).** When the `AssertionSink`
  coherence property test lands in Round 4, it becomes
  **executable documentation of what coherence means**. If
  a future implementer reads §5.4.6 prose and is uncertain
  about an edge case — e.g., "does a `ScanProgress`
  emission count toward coherence for a
  `MalformedScanResult` return?", or "do two distinct
  error-class events from the same scan span count as one
  emission or two?" — the test's behavior is the
  authoritative answer. Prose ambiguities are resolved
  against test behavior, not the other way around; if the
  test is wrong, the test is fixed and the prose follows,
  never the reverse. This is one of the validation
  surfaces for the coherence rule per
  [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc).
  Naming the property test as canonical reference makes
  drift between prose and test impossible without explicit
  re-examination — a future PR that lands prose changes
  to the coherence contract is required to re-examine the
  test (and a future PR that changes test behavior is
  required to re-examine the prose). Phase 0e docstring
  amendment on the `DiagnosticSink` trait definition,
  pointing to the test as the canonical reference for
  coherence semantics.

  **Permanent CI regression coverage pin (Round 4 review pass,
  2026-05-15; F3).** `AssertionSink` is **permanent CI
  regression coverage**, not a one-shot Phase 1 deliverable.
  Every PR touching any `RefreshEngine` implementation MUST
  continue to pass the `AssertionSink` property test. A test
  failure is a **contract violation**, not a "test failure to
  investigate" — the implementation either satisfies the
  coherence contract, or the design doc is updated with explicit
  re-pin language and the test follows. The discipline shifts
  the test's role from "tests we ship" to "the executable
  definition of the contract." Phase 1's CI configuration
  records the test as part of the standard `cargo test` pass for
  `shekyl-engine-core`; future PR-template language in
  [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc) for
  PRs touching `RefreshEngine` references this pin as a
  reviewer-checkpoint item. See §5.4.9 F3 for the adversarial
  rationale (silent-error-path detection by behavior-fingerprinting
  attacker) the pin closes long-term.
- **Producer-panic-safety property (Round 2 reframe
  contract-pin refinements, 2026-05-13). Not a sink
  contract pin — a producer-side robustness property and
  Round 4 test deliverable.** The non-blocking pin closes
  the producer-liveness hazard from a *blocking* `emit`.
  It does not close the adjacent hazard from a *panicking*
  `emit`. A buggy or third-party sink implementation that
  panics — null pointer dereference in a logger,
  allocator failure in a metrics consumer, panic-on-overflow
  in an aggregator, third-party `Drop` impl on a captured
  state object — propagates the unwind through the
  producer's call stack at the emission site. The
  producer's `Scanner` (holding spend material) is live
  across the `emit` call; an unwind during emission
  interacts with the `ZeroizeOnDrop` chain and the
  cancellation-checkpoint state machine in ways that
  depend on the exact unwind boundary.

  **Disposition: producer-side robustness, not sink
  contract.** Pinning "`emit` MUST NOT panic" as a hard
  trait contract is not enforceable at the type-system
  level and pushes development cost onto every sink
  implementer for limited gain. The load-bearing property
  is on the producer: **any panic propagating out of
  `emit` results in a predictable refresh-attempt failure
  with `Scanner` cleanly zeroized via `Drop`, no leaked
  half-state, and the cancellation token consistently in
  either fired-or-not state**. This is a testable
  property; the test is the contract.

  **Round 4 test deliverable.** The `AssertionSink`
  property test (per the coherence canonical-reference
  pin above) **must** include a `PanickingSink` variant
  that panics on configured event variants. The test
  asserts:
  - The producer's `Scanner` is dropped (visible to the
    test via a `Zeroize`-observer wrapper in the test
    harness — instrumented `Scanner` type or memory-witness
    counter), and the drop completes before the panic
    crosses the producer's frame.
  - No inconsistent producer state remains observable
    after the unwind (cancellation token is in a
    well-defined fired-or-not state; no half-emitted
    `RefreshDiagnostic` events; no half-written
    `ScanResult` buffers).
  - The panic propagates without corruption — `Drop`
    chain runs to completion; no double-panic from a
    `Drop` impl that itself panics on already-poisoned
    state.

  Round 4 commit-decomposition records the `PanickingSink`
  test alongside the `AssertionSink` coherence test as
  Phase 1 deliverables. This is robustness testing, not
  a contract pin; phrasing it here so the Round 4
  test-design pass has the property pre-specified rather
  than re-deriving it at test-authoring time.

  **Permanent CI regression coverage pin (Round 4 review pass,
  2026-05-15; F3).** `PanickingSink` is **permanent CI
  regression coverage**, parallel to the `AssertionSink` pin
  above. Every PR touching any `RefreshEngine` implementation
  MUST continue to pass the `PanickingSink` panic-safety
  property test. The producer-side robustness property is the
  contract; the test is its executable definition. See §5.4.9
  F3 for the rationale.
- **Per-emitter FIFO ordering pin (Round 4 review pass, 2026-05-15;
  F4).** `DiagnosticSink::emit` MUST preserve **per-emitter FIFO
  ordering**: events emitted by a single producer task arrive at
  any given consumer in the order they were emitted.
  **Cross-emitter ordering is undefined**: events emitted
  concurrently by different producer tasks may interleave
  arbitrarily; consumer actors MUST NOT rely on cross-emitter
  ordering for correctness. **Rationale (per §5.4.9 F4).** A
  peer-reputation actor that depends on event ordering
  ("`MalformedScanResult` observed before peer rotation") makes
  decisions on temporal context; if ordering is not pinned, an
  adversary-influenced reordering (concurrent-emit racing under
  specific timing windows) can shape consumer-actor conclusions.
  Per-emitter FIFO is naturally satisfied by single-emitter
  mailbox structures (`crossbeam::channel`, `flume`,
  `tokio::sync::mpsc`); the pin does not constrain implementation
  choice, only ordering semantics. Cross-emitter ordering is
  explicitly disclaimed because preserving it would require
  global serialization at the sink, contradicting the
  concurrent-emit pin and re-introducing the producer-liveness
  hazard. PR 5 §5.0.3 carries a parallel pin so the
  diagnostic-stream contract is symmetric across `RefreshDiagnostic`
  and `PendingTxDiagnostic`. Phase 0e docstring amendment on
  `DiagnosticSink::emit`, naming both halves explicitly so V3.x
  consumer-actor PRs cannot re-derive the contract inconsistently.
  **Enforcement gap and causal-context discipline (Round 4
  review pass amendment, 2026-05-15; F12).** The cross-emitter-
  undefined half is procedurally enforced, not type-system
  enforced — a V3.x consumer-actor author who depends on
  cross-emitter arrival order writes code that compiles cleanly
  and passes per-emitter FIFO tests, then deadlocks or
  misbehaves under reordering at audit. The discipline that
  closes the gap: **consumer actors that need cross-emitter
  ordering MUST derive it from explicit causal-context fields
  carried inside the events themselves** — `SnapshotId` for
  ledger-rooted ordering, `ReservationId` plus per-reservation
  monotone version counters for reservation-rooted ordering,
  `BlockHeight` for chain-rooted ordering. Sink-observed arrival
  order is *not* a causal-context source under the contract.
  The V3.x consumer-actor PR template's CI-lint deliverable
  (FOLLOWUPS F5 entry, scope-extended by F12) covers
  *attempted* cross-emitter-ordering reliance: the lint flags
  consumer-actor code that branches on the relative timing of
  events from distinct emitters without first constraining
  ordering via a causal-context field. See §5.4.8 #4's V3.x
  forward-template for the lint's full scope.

### §5.4.7 Round 2 dispositions — R2–R7 settled (2026-05-12)

Round 2 closes all seven residuals from §5.4.3 plus the §5.4.6
trait-contract pins. PR 4's design surface is now Phase-0-ready;
Round 4 carries the commit decomposition.

#### R1 — `PendingTxEngine::build` during long refresh

**Disposition.** Carry forward to PR 5's design rounds with
**build-against-current-snapshot + snapshot-ID pinning** as the
working hypothesis. Reservation tracker carries a snapshot ID
per reservation; submit path becomes a CAS against
`current_snapshot == reservation.snapshot_id`. **Closed in
PR 5 Round 1 (2026-05-14)** under the actor-mesh framing: the
mailbox FIFO is the serialization point,
`LedgerDiagnostic::SnapshotMerged` events drive the
`current_snapshot` field on `PendingTxActor`, and the
staleness check is a field comparison in the submit-message
handler. The α-disposition's *provisionally load-bearing*
status (per §5.3) is **closed**; α is confirmed and the
re-evaluation gate collapsed without firing. Cross-reference:
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.0 / §5.2 / §5.5.

PR 4 does not land R1 — it is a PR 5 surface. Naming the working
hypothesis here exists so PR 5's design opens with the
correctness-preserving shape rather than re-litigating the
three sub-options.

#### R2 — β internal-batching refinement

**Disposition.** Leave as the §2.2 "future scaling refinement"
note. Do **not** promote β to FOLLOWUPS yet.

**Rationale.** The V3.0 bandwidth FOLLOWUP entry already names
α's bandwidth cost; it does not prescribe β as the remediation.
V3.0 RC stabilization profiles cold-sync bandwidth empirically;
if the profile shows β is the right shape, promote then.
Promoting β prematurely overspecifies the remediation before
the cost-benefit is measured — alternatives include daemon-side
prefix-matching, view-tag pre-filter improvements, or wallet-side
prune-by-birthday — and "FOLLOWUPS without a named trigger
becomes a graveyard" per
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc).
The §2.2 note remains the named home.

#### R3 — `RefreshOptions` / `RefreshProgress` public-module promotion

**Disposition.** Confirmation, not discovery: the types are
**already crate-publicly re-exported** from `shekyl_engine_core`
([`lib.rs:25–30`](../../rust/shekyl-engine-core/src/lib.rs))
at the flat crate root, matching the `DaemonEngine` /
`LedgerEngine` convention. Stage 4's `kameo` actor implementor
imports them via `use shekyl_engine_core::{RefreshOptions,
RefreshProgress};` exactly as a Stage 1 caller does today.

**Phase 0b scope.** Confirmation that the existing exports
cover `RefreshEngine`'s consumer surface; no new module
promotion required. The R4 (a-instance-scoped) disposition
introduces a new `ViewMaterial` type whose export status lands
in Phase 0b: public-typed, `Zeroize + ZeroizeOnDrop`, exported
under the same flat-at-crate-root convention. No new
`shekyl_engine_core::refresh` namespace.

The §3.3 "discovery cadence" framing applied to PR 4 — Round 2's
confirmation-shape on R3 is the predicted outcome per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
"audits are increasingly likely to be confirmations as the
discipline's coverage extends." The pre-Stage-1 export
discipline already covers PR 4's needs.

#### R4 — view-material flow to the producer (load-bearing)

**Disposition.** **(a-instance-scoped).**
`LocalRefresh::new(view_material: ViewMaterial)` captures the
view-and-spend material at construction; the `Scanner` is built
once at `LocalRefresh::new` and held for the instance's
lifetime; per-attempt cost drops to `(snapshot.clone() +
daemon.get_height() + per-block fetch+scan)` — no per-attempt
scanner construction.

**`ViewMaterial` shape (Phase 0a).** A new public type in
`shekyl_engine_core` carrying:

```rust
pub struct ViewMaterial {
    pub spend_pub: EdwardsPoint,
    pub view_scalar: Zeroizing<Scalar>,
    pub x25519_sk: Zeroizing<[u8; 32]>,
    pub ml_kem_dk: Zeroizing<Vec<u8>>,
    pub spend_secret: Zeroizing<[u8; 32]>,
}
```

These are exactly the fields `build_scanner_from_keys`
([`engine/refresh.rs:1254`](../../rust/shekyl-engine-core/src/engine/refresh.rs))
extracts from `&AllKeysBlob` today. `ViewMaterial` is `Zeroize +
ZeroizeOnDrop` by construction (every field is already
`Zeroizing<…>` or a public point). The orchestrator's
`Engine<S>` constructs `ViewMaterial` from `AllKeysBlob` under
its existing key read-guard and passes it to
`LocalRefresh::new`.

**Wallet-lock semantics.** The wallet's lock state machine
already drops `LocalRefresh` on lock (the orchestrator owns
the handle); under (a-instance-scoped), drop runs the
`Zeroize` chain on `ViewMaterial`'s wrapped fields plus the
`Scanner`'s internal `ZeroizeOnDrop`. The "graceful-cancel
window" the user named is bounded by the cancellation+join
time of any in-flight refresh attempt — the same window
already exists today inside `run_refresh_task`'s scanner
ownership; (a-instance-scoped) makes it explicit at the type
level rather than wider.

**Stage 4 actor envelope.** `LocalRefresh`'s actor body holds
the keys; the actor's mailbox messages carry no secrets.
`kameo`'s envelope crosses the trust boundary cleanly:
`Tell { ProduceScanResult { snapshot, opts } } → Reply<…>`.

**(c) split-producer/recoverer deferred to V3.x.** The (c)
shape — producer emits view-tag-matched candidates; orchestrator
does final hybrid-decap + key-image computation — is the
threat-model-cleanest answer but requires changing `Scanner`'s
output shape and the `ScanResult` wire shape. **Trigger for
V3.x reconsideration:** *if HW-wallet-backed signing or a
post-V3 threat-model refinement requires producer-side
spend-key isolation*; in that case the (c) migration becomes
load-bearing and the existing FOLLOWUPS entry below tracks the
deferral.

**(b) per-call rejected.** Crosses the trait boundary every
call; hostile to actor migration per the Stage 4 envelope
analysis.

#### R5 — mid-scan reorg-abort: composition via `ReorgAmplificationDetector` (Round 2 reframe supersedes deferral)

**Disposition.** **Resolved by composition** under the
two-channel reframe (R6 below). R5 does **not** extend §7's
checkpoint discipline and does **not** defer to V3.x as an
open capability; it retires here, with the consumer
implementation deferred to the V3.x actor-mesh PR that wires
the diagnostic-stream consumers.

**The previous Round 2 disposition is superseded.** Round 2's
first pass (2026-05-12) read "defer R5 to V3.x; trigger:
hostile-daemon work-amplification measurable in V3.0 RC
stabilization or post-genesis production telemetry; if the
trigger fires, R5 extends checkpoint 3 with one tip-poll per
checkpoint-3 hit and §7's discipline grows accordingly." That
disposition is the cost-benefit-defer-to-later anti-pattern
per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) —
it weighed immediate cost (per-block RPC + §7 amendment)
against deferred benefit (capability gained only after
empirical telemetry shows the need) and chose deferral. The
reframe is the architectural-integrity-now answer: lay the
seam now, defer only the consumer implementation.

**How composition resolves R5.** Under the R6 two-channel
shape, the producer emits structured `ReorgObserved` events
to `DiagnosticSink` whenever `find_fork_point` detects a
fork during scanning. A `ReorgAmplificationDetector` actor
subscribes to the diagnostic stream, maintains a windowed
count of `ReorgObserved` events per peer (or per attempt, in
peer-less Stage 1), applies a threshold-based response
(rate-limit → cancel → peer-rotate via `PeerReputationActor`),
and signals cancellation back to the orchestrator via the
existing `CancellationToken` plumbing that checkpoint 3
already honors.

The producer's checkpoint 3 stays cancel-only — exactly its
current shape per
[`engine/refresh.rs:980 / :1140 / :1186`](../../rust/shekyl-engine-core/src/engine/refresh.rs).
No per-checkpoint-3 RPC. No §7 amendment. The capability is
added by composition of the actor mesh's consumers; the
producer's discipline budget does not grow.

**Why this is better than the deferred shape.**

1. **§7's discipline stays minimal.** Adding "checkpoint 3
   polls daemon tip" to the existing four-checkpoint
   discipline grows the contract every producer
   implementation must respect, every CI test must cover,
   and every audit must re-read. The composition shape
   keeps §7's discipline at four checkpoints and confines
   the reorg-detection logic to one actor.
2. **Future capability is unconditional, not trigger-gated.**
   The deferred shape required telemetry showing the need
   before R5 could land. The composition shape lands R5's
   *seam* now; whether to actually wire the
   `ReorgAmplificationDetector` actor in V3.0 vs V3.x is a
   separate decision that can be made on policy grounds
   (security default = wire it; pragmatism = wait for the
   actor-mesh PR), not on telemetry grounds.
3. **R5 generalizes.** The detector pattern (consume events,
   maintain state, signal cancellation) is reusable for
   other adversarial patterns — view-tag DoS (§5.4.5),
   withholding (§5.4.5), and any future class the actor
   mesh's diagnostic-stream pattern surfaces. The
   "extend checkpoint 3" shape generalized only to "extend
   checkpoint 3 again for the next pattern."

**FOLLOWUPS V3.x entry (consumer-side).** The
`ReorgAmplificationDetector` actor implementation, the
windowing and threshold policy, and the integration with
`PeerReputationActor` for peer rotation land in the V3.x
actor-mesh PR. **Trigger:** *when Stage 4 actor mesh
stabilizes;* no telemetry gate. The previous "extend
checkpoint 3" FOLLOWUPS entry from Round 2's first pass is
**withdrawn** and replaced in
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) by the
`ReorgAmplificationDetector` entry added in this commit.

#### R6 — `RefreshError` shape: two-channel actor-mesh seam (Round 2 reframe supersedes the `MalformedScanResult { reason }` disposition)

**Disposition.** **Two channels.** The synchronous trait
return and the actor-mesh diagnostic stream are different
artifacts with different consumers and different security
properties. PR 4 lands **both** channels — defining the
trait-level shape that supports composable security policies
without committing to the consumer implementations.

**The previous Round 2 disposition is superseded.** Round 2's
first pass (2026-05-12) kept `MalformedScanResult { reason:
&'static str }` and chose between bounded-`&'static str` vs.
the user-proposed `ScannerContractViolation { kind, evidence }`.
Both shapes assume a synchronous function-call graph where
the error is a single isolated event and the payload question
is "what does this caller branch on." In an actor-mesh fabric
the error is a stream event with temporal context, and the
same event routes to multiple consumers with different
security properties per consumer. **Neither
`MalformedScanResult { reason }` nor `ScannerContractViolation
{ kind, evidence }` is the right shape** — both are still
designed for the synchronous frame.

##### Channel 1 — synchronous trait return `RefreshError` (unit variants only)

```rust
/// Synchronous trait return.
///
/// What the orchestrator branches on, right now, in the
/// synchronous moment after `produce_scan_result` returns.
/// The branch table is structural — each variant maps to one
/// disposition; the response is structural ("rotate" / "retry"
/// / "cancel") rather than data-dependent.
///
/// **Unit variants only.** No string, no evidence, no payload
/// of any kind. Unit-variant-only is sufficient and the only
/// safe shape against the §5.4.5 memory-amplifier concern —
/// there is no attacker-controlled data anywhere on the
/// producer trait error surface.
pub enum RefreshError {
    /// Checkpoints 2 / 3 fired. Orchestrator propagates
    /// cancellation; does not retry.
    Cancelled,
    /// Daemon I/O failure. Orchestrator retries with backoff
    /// per the existing retry-policy contract.
    Io,
    /// Producer-side contract violation: scanner emitted a
    /// `ScanResult` whose shape disagrees with itself, or
    /// daemon returned malformed data that the scanner
    /// could not consume. Orchestrator does not retry —
    /// re-running against the same daemon produces the same
    /// violation — and signals to peer-rotation logic.
    MalformedScanResult,
}
```

The decision needs zero information beyond the variant tag
because the response is structural, not data-dependent. The
orchestrator's branch table is three rows; each row maps to
one disposition.

##### Channel 2 — diagnostic stream `RefreshDiagnostic` + `DiagnosticSink`

```rust
/// Actor-system diagnostic stream.
///
/// What fans out to specialized actors, each with its own
/// trust posture and its own sanitization rule. Full-fidelity
/// events stay in-process per the §3.1 / §5.4.6 trust-boundary
/// pin; persisted or exported projections are lossy by design.
///
/// Variants below are the Phase 0e seed set; the enum is
/// `#[non_exhaustive]` so the variant set can grow additively
/// as the actor-mesh consumers mature. Peer attribution
/// (a `PeerId` field per variant) is deferred to the future
/// PR that grows PR 1's `DaemonEngine` peer-aware surface;
/// Stage 1 emits variants without peer attribution.
#[non_exhaustive]
pub enum RefreshDiagnostic {
    /// Producer detected an inconsistency in daemon-returned
    /// data — typed for telemetry, not for orchestrator
    /// branching. `kind` enumerates distinguishable defect
    /// classes named at the call site (the previous
    /// `MalformedScanResult.reason: &'static str` content,
    /// now routed via the stream rather than the synchronous
    /// return).
    DaemonMalformed { kind: MalformedKind },
    /// Daemon RPC took longer than the producer's per-op
    /// budget. `op` names the RPC; `elapsed` is the observed
    /// time. Consumed by retry-policy and peer-reputation
    /// actors.
    DaemonTimeout { op: DaemonOp, elapsed: Duration },
    /// Daemon returned a response that violates the RPC
    /// protocol contract (e.g., field type mismatch, length
    /// constraints, version mismatch). Distinct from
    /// `DaemonMalformed`: this is RPC-layer; that is
    /// scan-content-layer.
    DaemonProtocolError { kind: ProtocolErrorKind },
    /// Producer's `find_fork_point` walked back from chain
    /// tip and detected a fork at `fork_height` with `depth`
    /// blocks rewound. The natural input for the
    /// `ReorgAmplificationDetector` actor per R5's composition
    /// resolution.
    ReorgObserved { fork_height: u64, depth: u32 },
    /// Per-block scan progress. Subsumes the existing
    /// `RefreshProgress` watch-channel content; the existing
    /// `RefreshProgress`-via-`tokio::sync::watch` stays as
    /// the UI-consumer projection of this stream variant
    /// (latest-value semantics, lossy-by-design), preserving
    /// the existing UI surface without rework. Stage 4's
    /// projector actor replaces direct watch-channel
    /// publication with stream-based emission.
    ScanProgress { height: u64, candidates: u32 },
}

/// Sink for `RefreshDiagnostic` events.
///
/// In Stage 1, the sink is a no-op or a simple tracing
/// emitter. In Stage 4, the sink is the entry point to the
/// actor mesh — a typed channel sender feeding specialized
/// consumer actors (peer-reputation, recovery, telemetry,
/// logger), each subscribing to the events it cares about
/// with its own per-consumer trust posture.
///
/// **Non-blocking contract (§5.4.6 pin).** `emit` **MUST NOT
/// block** the calling task. Implementations use
/// `try_send`-shaped semantics: on a full bounded channel,
/// an unavailable consumer, or any other back-pressure
/// condition, `emit` drops the event silently and returns
/// promptly. The drop policy per consumer is the
/// implementation's choice (per §5.4.8 #5's bounded-
/// mailbox-with-overflow-policy taxonomy: drop-oldest for
/// diagnostics consumers; aggregate-on-overflow for
/// reputation; event-sequence-aware drop for recovery), but
/// the producer-side guarantee is that the sink cannot
/// compromise producer liveness regardless of which
/// consumer is misbehaving. **Rationale.** A blocked `emit`
/// would pin the producer task at the emission call site
/// holding the `Scanner`'s spend material, and would block
/// observation of the cancellation token at checkpoints 2
/// and 3 — defeating both the §5.4.4 invocation-overhead
/// constraint and the §3.1 wallet-lock-latency property.
/// The non-blocking contract closes this hazard at the
/// trait surface so no consumer-actor implementation can
/// introduce it post-hoc.
///
/// **Non-blocking holds under concurrent emission.** `Send
/// + Sync` permits concurrent `emit` calls from multiple
/// tasks; implementations **MUST remain non-blocking under
/// concurrent emission**, not merely non-blocking per call.
/// Serializing internal synchronization that admits
/// unbounded contention — `Mutex<VecDeque<_>>`,
/// `RwLock`-wrapped state, any shared mutable structure
/// without bounded-wait guarantees — violates the contract
/// even when each `emit` call returns "promptly" in
/// isolation. In practice, conforming implementations use
/// lock-free queueing (e.g., `crossbeam::queue::ArrayQueue`,
/// `flume` non-blocking sends), atomic counters, or
/// sharded mailboxes. The clarification forecloses a class
/// of implementation that would type-check, satisfy the
/// per-call non-blocking property literally, and still
/// re-introduce the producer-liveness hazard at scale —
/// either under a future producer-side parallelism shape
/// or under Stage 4 actor-mesh topologies where multiple
/// `LocalRefresh` instances share a sink.
///
/// **Trust-boundary contract (§3.1, §5.4.6 pin).** Sink
/// implementations route full-fidelity events only to
/// in-process consumers inside the wallet trust boundary.
/// Cross-process or network-bound consumers — *including
/// in-process aggregator-republisher actors whose external
/// surface crosses the boundary*, per §5.4.8 #4 — receive
/// only projection types that have been explicitly
/// sanitized at the boundary. This is the production/debug-
/// log-separation principle applied at the messaging layer.
///
/// **Emission/return coherence contract (§5.4.6 pin).**
/// `RefreshEngine` implementations **MUST** emit at least
/// one corresponding `RefreshDiagnostic` event to the sink
/// for every non-`Cancelled` `RefreshError` returned from
/// `produce_scan_result`, *before* returning the error.
/// The diagnostic event carries the structured information
/// that the unit-variant error elides; consumer actors
/// rely on this coherence to attribute synchronous errors
/// to their detection context. See §5.4.7 R6 for the
/// silent-error and phantom-error failure modes this
/// closes.
///
/// **Canonical reference: the property test (§5.4.6 pin).**
/// The Round 4 `AssertionSink`-wrapped property test
/// (`tests/refresh_diagnostic_coherence.rs` or equivalent
/// crate-internal property-test module) is the
/// **authoritative reference** for the coherence semantics.
/// If a future implementer reads this prose and is
/// uncertain about an edge case — e.g., "does a
/// `ScanProgress` emission count toward coherence for a
/// `MalformedScanResult` return?" — the test's behavior
/// resolves the ambiguity. Prose changes that drift from
/// test behavior are rejected; if the test is wrong, the
/// test is fixed and the prose follows, never the
/// reverse. This is one of the validation surfaces for
/// the coherence rule per
/// [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc);
/// the test being authoritative makes prose / test drift
/// impossible without explicit re-examination.
    fn emit(&self, event: RefreshDiagnostic);
}
```

**Producer trait signature change.** `produce_scan_result`
adds a `diagnostics: &dyn DiagnosticSink` parameter (per-call;
runtime-dispatch). The choice of `dyn` rather than a generic
`S: DiagnosticSink` is deliberate: the sink is a runtime-swap
surface in Stage 4 (different sinks for different test
contexts, different log scopes, different actor topologies),
and one vtable indirection per call is cheap against the
per-call work envelope. **The signature is locked now** so
Stage 4's actor wiring does not have to widen
`LocalRefresh::new` or rev the trait.

##### What this shape unlocks (deferred consumers; PR 4 lands only the seam)

- **Fail2ban-style intra-session mitigation.** A
  `PeerReputationActor` subscribes to `RefreshDiagnostic`,
  maintains per-peer event history with decay, applies
  threshold-based graduated response (rate-limit → temp-ban
  → rotate). PR 1's `DaemonEngine` peer-rotation contract
  becomes the *output* of this actor rather than the
  orchestrator's primary decision logic. The orchestrator
  gets the unit-variant trait return for the synchronous
  moment; the rotation policy lives in the reputation actor
  and can grow without polluting the trait surface.
- **Pattern-based recovery.** A `RecoveryActor` watches for
  sequences like "`DaemonMalformed` at block H from peer A
  → re-request block H from peer B → cross-check with peer
  C." This is Byzantine-fault-tolerance-flavored recovery
  driven by the event stream's temporal structure, not by
  single error events. The recovery actor can require
  N-of-M agreement on contested data without any change to
  the producer.
- **R5 dissolved by composition** (per §5.4.7 R5 above).
- **R5 trigger becomes a natural projection.** What Round 2's
  first pass named as "telemetry counter to gate the V3.x
  decision" becomes a natural projection of the diagnostic
  stream rather than a separately-maintained counter — more
  granular, no trait-surface leakage.

The pattern: capability we'd otherwise spend on bespoke logic
at the producer becomes a property of the actor mesh's
composition.

##### Excluded from the synchronous trait error

- `ConcurrentMutation { wallet, result }` — orchestrator-
  internal; generated by `LedgerEngine::apply_scan_result`
  at the merge gate, translated by `run_refresh_task` into
  the orchestrator-side `RefreshError`. Producer never emits.
- `AlreadyRunning` — orchestrator-internal; refresh-handle
  racing concern, not a producer concern.
- `ReorgTooDeep { fork_height, max_rewind }` — kept as
  Ok-with-rewind merge-layer detection per
  [`find_fork_point`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  (lines 1148–1156); reorg-amplification detection moves to
  `ReorgAmplificationDetector` per R5's composition
  resolution above.

##### Phase 0c / 0e scope

- **Phase 0c — unit-variant `RefreshError`.** Three variants;
  no payload; `Self::Error: Into<RefreshError>` in the trait
  surface (orchestrator's existing `RefreshError` enum is
  *retained* — `Cancelled` / `Io(IoError)` /
  `MalformedScanResult { reason: &'static str }` /
  `ConcurrentMutation` / `AlreadyRunning` — and grows the
  trait-error→orchestrator-error conversion per the
  exclusion list above). The conversion drops payload at
  the trait boundary; the orchestrator's `RefreshError`
  reason content is for backward-compat synchronous-API
  callers and is constructed orchestrator-side from the
  variant tag plus orchestrator context, not from
  attacker-controlled trait payload.
- **Phase 0e (new) — `RefreshDiagnostic` enum + `DiagnosticSink`
  trait + `produce_scan_result` signature change.** Variant
  set per the Phase 0e seed above; `MalformedKind`,
  `DaemonOp`, `ProtocolErrorKind` are bounded enums (no
  attacker-controlled bytes). Stage 1's `LocalRefresh`
  emits a minimal subset of variants (`ScanProgress`,
  `DaemonMalformed`); the remaining variants land as the
  scan logic grows the corresponding observation points.
  A trivial `NoopDiagnosticSink` (drop everything) and a
  `TracingDiagnosticSink` (route to `tracing::event!`)
  satisfy Stage 1; the actor-mesh sink lands in V3.x.

  **`MalformedKind` initial variant set (Phase 0e seed).**
  The variants below cover the daemon-attributable
  `MalformedScanResult` call sites currently in
  [`engine/merge.rs`](../../rust/shekyl-engine-core/src/engine/merge.rs)
  (the merge-gate contract-violation checks) and
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  (the producer-side `find_fork_point` / scan-loop
  contract checks). Each variant corresponds to a current
  `reason: &'static str` cluster, so the unit-variant
  migration has a straightforward mapping:
  - `NonEmptyForEmptyRange` — `block_hashes` /
    `new_transfers` / `spent_key_images` non-empty for an
    empty `processed_height_range`.
  - `RangeLengthMismatch` — `processed_height_range`
    length exceeds `usize`, or `block_hashes` length
    disagrees with the range length.
  - `RangeMembershipViolation` — `block_hashes` /
    `new_transfers` / `spent_key_images` entry outside
    `processed_height_range`.
  - `DuplicateHeight` — `block_hashes` contains a
    duplicate height entry.
  - `MissingHeightEntry` — `block_hashes` missing an entry
    for a processed height.
  - `ResidualAfterApply` — `block_hashes` /
    `new_transfers` / `spent_key_images` left residual
    entries after the per-height apply loop (apply-loop
    invariant violation, daemon-attributable since the
    residual is produced by daemon data the apply loop
    consumed).

  **Non-daemon-attributable variants — Round 2 close-out
  resolved (2026-05-13).** The current
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  retry-loop call sites also use `MalformedScanResult {
  reason: "...retry loop exited without an observed
  ConcurrentMutation" }` (lines 1672–1680, 2055–2065) for
  an orchestrator-internal state-machine exhaustion
  failure that is **not** daemon-attributable. The
  existing comments at those sites are explicit:
  *"falling through with `None` would mean the loop body
  itself is broken, which we surface as
  `MalformedScanResult` so audit reads a typed contract
  failure rather than silent retry exhaustion."* This is
  a **state-machine invariant violation** — the
  "should-never-happen" path the loop took where neither
  the retry success nor the `ConcurrentMutation` signal it
  was retrying against was observed — not a retry-budget
  exhaustion (which is the legitimate
  `last_concurrent_mutation` case that exhausts cleanly
  through the orchestrator's `ConcurrentMutation` path).

  Under the Round 2 reframe these no longer fit
  `MalformedScanResult`'s "peer rotation decision needed"
  structural branch. **Round 2 close-out resolves the
  disposition: route through
  `RefreshError::InternalInvariantViolation { context:
  &'static str }`** (Phase 0c amendment, 2026-05-13). The
  alternative of extending `ConcurrentMutation` to carry
  the unreached-invariant case was rejected because it
  conflates two semantically distinct failure modes
  (retry-budget exhaustion vs. state-machine invariant
  violation) into one variant — downstream consumers
  (telemetry, future `PeerReputationActor`, future
  user-facing error surface) need different responses for
  the two cases (merge-contention back-off vs.
  wallet-bug report-and-stop). The variant separation is
  correctness-preserving routing, not stylistic
  decomposition. See Phase 0c (§4) for the full rationale.

  **Round 4 commit-decomposition migration target.** The
  two call sites at
  [`engine/refresh.rs:1678–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  and
  [`:2061–2064`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  migrate from `MalformedScanResult { reason: "..." }` to
  `InternalInvariantViolation { context: "..." }` with
  the existing reason strings becoming the `context`
  values. No structural ambiguity at the commit-author's
  desk; the disposition is resolved at the design layer.

  **`#[non_exhaustive]` discipline.** The `RefreshDiagnostic`,
  `MalformedKind`, `DaemonOp`, and `ProtocolErrorKind` enums
  are all `#[non_exhaustive]` so the V3.x consumer-actor PR
  can grow the variant set additively. The
  `ViewTagAnomalyDetector` is the immediate forward-driver:
  before the detector lands, the producer's per-block scan
  loop must grow a `ViewTagFalsePositive { observed_rate,
  expected_rate }` (or equivalent) variant — see the
  `ViewTagAnomalyDetector` FOLLOWUPS entry added in this
  commit for the explicit producer-side dependency.

Phase 1's commit decomposition (Round 4) sequences these
amendments: the unit-variant `RefreshError` and the
`DiagnosticSink` parameter on `produce_scan_result` land in
the same commit as a coupled signature change; the
`RefreshDiagnostic` enum's initial variant set lands
adjacent; the property-test invariants for the
emission/return coherence pin (per §5.4.6) and the
producer-panic-safety property (per §5.4.6) land as
Round-4 test-design deliverables — the coherence test
wraps `LocalRefresh` with an `AssertionSink` that records
every `emit` and asserts the structural emission/return
correspondence, and the panic-safety test wraps
`LocalRefresh` with a `PanickingSink` variant that panics
on configured event variants and asserts `Scanner`
zeroization, well-defined cancellation-token state, and
unwind-without-corruption (per §5.4.6's producer-panic-safety
pin); the consumer-side actors
(`PeerReputationActor`, `RecoveryActor`,
`ReorgAmplificationDetector`, `ViewTagAnomalyDetector`)
land in the V3.x actor-mesh PR per the FOLLOWUPS entries
added in this commit.

#### R7 — `ScanResult` atomicity-under-cancellation contract

**Disposition.** Pin the contract in
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.3 prose: *a `produce_scan_result` call returns either a
`ScanResult` covering the full span it scanned, or
`RefreshError::Cancelled`. No partial-span `ScanResult`.*

**Already true in the existing implementation** per the cancel
checks at
[`engine/refresh.rs:980 / :1140 / :1186`](../../rust/shekyl-engine-core/src/engine/refresh.rs);
the contract pin prevents future drift. Phase 0a prose
amendment.

#### Trait-surface contract pins (§5.4.6) — confirmed and extended by Round 2 reframe

- `Send + Sync + 'static` bound on `R: RefreshEngine` lands as
  Phase 0a §2.3 amendment.
- `Progress`-channel trust-boundary pin lands as Phase 0a §2.3
  prose; consumers must be inside the wallet trust boundary.
- **Diagnostic-stream trust-boundary pin (Round 2 reframe).**
  `DiagnosticSink` implementations route full-fidelity
  `RefreshDiagnostic` events only to in-process consumers
  inside the wallet trust boundary; cross-process or network-
  bound consumers receive only projection types explicitly
  sanitized at the boundary. Phase 0a §2.3 prose amendment.
  The Progress-channel pin above becomes a specific case of
  this broader pin (the `RefreshProgress` watch channel is
  the UI-consumer projection of `RefreshDiagnostic::ScanProgress`).

### §5.4.8 Diagnostic-stream attack surfaces (Round 2 reframe; honestly enumerated)

The R6 two-channel reframe introduces a new public surface —
`RefreshDiagnostic` events flowing through `DiagnosticSink` to
specialized consumer actors. This is **not free**; the
reframe lands here only because the additional surface is
**structural, not informational** — PR 4 defines a channel,
not a leak through it. The five attack surfaces below are
each named with a mitigation pinnable now (so Stage 4's actor
mesh has the constraints to design against) and a deferred
implementation (the consumer-actor PR).

#### 1. Peer reputation as fingerprint

**Threat.** A persistent peer-reputation database is a
deanonymization surface: "this wallet has interacted with
these daemons over time" leaks linkability across sessions
and is structurally adjacent to the privacy-first commitment
in [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) §2.

**Mitigation pin (binding on all V3.x consumer actors).** The
`PeerReputationActor`'s state is **in-memory only**, scoped
to the wallet session; drop on wallet close. **No persistence
beyond the wallet session.** A coarse-grained current-state-only
persistence ("daemon X banned until time T") is the most
that may persist, and only if a future review explicitly
justifies the relaxation — V3.x default is no persistence.

**Round 4 review pass — R17 hardening (2026-05-15; F1; replaces
the Round 3 acknowledgment).** The drop-on-close-by-default
rule pinned here is not refresh-specific. PR 5 Round 2
segment 2c closed R17 (*pending-tx event-sourced recovery*)
with the same default applied at the diagnostic-stream-contract
level. The Round 3 acknowledgment of this scope-broadening
admitted "per-stream wallet-internal encrypted-persistence
opt-in as a V3.x refinement," which the Round 4 review pass
identifies as a soft commitment with substantial unreviewed
attack surface (the cost-benefit-defer-to-later anti-pattern
applied to a feature commitment per §5.4.9 F1).

**Hardened disposition (binding on V3.0; Round 4 review pass,
2026-05-15).** **Drop-on-close is structurally final at V3.0
across all diagnostic streams in the engine mesh
(`RefreshDiagnostic`, `PendingTxDiagnostic`, `LedgerDiagnostic`,
and any future consumer-actor streams). Persistence of
diagnostic events is rejected.** The rejection covers in-process
encrypted persistence as much as any other shape — the
attack-surface analysis (per §5.4.9 F1's six vectors:
master-key code-path expansion, deserialization-on-startup,
metadata side-channel, cross-wallet correlation amplification,
adversary-controlled DoS, forensic-artifact primitive) does not
distinguish between cross-trust-boundary and within-trust-boundary
persistence — the surfaces materialize regardless of whether
the persisted bytes leave the wallet's encrypted-state surface.

**V3.x reopens this question only under all of:**

(a) **Demonstrated production use case from real deployments**,
    not anticipated demand. "We might want this someday" is
    not a use case; "this specific institutional deployment
    repeatedly hits this specific operational failure mode"
    is.
(b) **Full threat-model review at evaluation time**, including
    the six vectors named above, with each vector's mitigation
    explicitly designed and evaluated. The review's output is
    a design-doc round, not a feature-PR description.
(c) **Explicit `AUDIT_SCOPE.md` amendment** if adopted,
    bringing the persistence layer into audit scope. The
    persistence layer is then audited as a key-material-handling
    surface alongside transaction signing.
(d) **Explicit acknowledgment that the privacy-first default
    discipline supersedes ergonomic-recovery considerations**
    except where (a)–(c) demonstrate the case. The privacy-first
    posture is not negotiable on ergonomic grounds.

**No V3.x schedule entry; conditional reopening only.** The
distinction matters: a V3.x schedule entry shapes contributor
expectations toward "we'll ship this in V3.x"; a conditional
reopen shapes them toward "we won't ship this unless conditions
(a)–(d) are met." The former is a soft commitment; the latter
is a hard rejection with a path-to-reopen the feature only
earns by demonstrating need against the threat model.

See
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.4 R17 for the parallel hardening on the
`PendingTxDiagnostic` stream side; the two sections are
symmetric. The retired Round 3 acknowledgment language ("V3.x
refinement evaluated at the diagnostic-stream spec doc") is
preserved in the design-doc git history; the retired language
is not preserved inline because it carries the soft commitment
the hardening retires.

This conflicts with classical fail2ban's "remember bad actors
across sessions" disposition; the conflict is genuine, and
**privacy-first wins** per the priority hierarchy. Shekyl's
fail2ban is intra-session and resets on close.

**Restart-amnesia is deliberate (name the threat-model
consequence forward to the consumer-actor PR).** The
no-persistence-across-sessions stance is the correct
privacy posture, but the consequence — *the reputation
threat model resets on every wallet restart* — is itself
an attack surface. An adversary who can observe or trigger
wallet restarts (process kill, RPC-daemon restart in
hosted-wallet topologies, scheduled rotation in service
deployments, OOM-killer in resource-constrained
environments, user-initiated quit-and-restart cycles) can
**rate-limit hostile behavior to evade reputation
accumulation**. The evasion pattern is simple: behave well
for the first portion of the session; attack in the second
portion; restart; repeat. Cross-session reputation memory
would catch this; intra-session memory cannot.

**Mitigation pin for the consumer-actor PR design.** The
`PeerReputationActor`'s threshold logic **must** be designed
against this evasion pattern from the start. The pinned
design constraint:

- **Coarse-window-based detection**, not credit-history-based.
  The actor's threshold is driven by event-rate within
  bounded recent windows (per-minute, per-block-batch,
  per-bounded-rolling-window), not by accumulated trust
  credits or per-peer behavioral history. Coarse-window
  detection bounds the adversary's evasion benefit by the
  window size: an attacker who restarts every N minutes
  gets to mount attacks with a duty cycle of at most
  `attack_window / (good_window + attack_window + restart_overhead)`,
  and the per-restart cost (re-bootstrap connections,
  re-fetch state, re-trigger user attention if visible)
  bounds the realistic restart frequency.
- **No "trust accumulation" over time.** A peer that has
  behaved well for the entire session does not earn
  privileged status. The actor's response policy treats
  good and bad behavior symmetrically inside the
  detection window; long-running good behavior does not
  reduce the threshold sensitivity for incoming bad
  behavior. This forecloses the dual evasion pattern
  ("behave well long enough to earn trust, then attack").

The constraint binds at consumer-actor PR design review.
PR 4 pins it forward; the V3.x design rounds enumerate the
window parameters and threshold curves against the
restart-amnesia model as a load-bearing input.

#### 2. `PeerId` stability in mixed-anonymity contexts

**Threat.** Per
[`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md), daemon
connections over Tor/I2P intentionally lack stable peer
identifiers from the wallet's perspective. The `PeerId` field
in `RefreshDiagnostic`'s peer-attributing variants (when the
future-PR adds it) has different semantics depending on
transport: for direct connections, it is a network endpoint;
over Tor, a circuit-scoped opaque identifier; over I2P,
similar. The `PeerReputationActor`'s correctness depends on
what `PeerId` actually identifies — and the answer varies
per transport.

**Mitigation pin.** `PeerId` is a **transport-defined opaque
token**, not a stable identity. Reputation decay must be
aggressive enough that transport-rotated identifiers do not
persist as ghost-reputation; the decay constant is calibrated
to the transport's circuit-rotation cadence (Tor: ~10 min;
I2P: similar). The trait contract for `PeerId` (defined by
the future PR that grows PR 1's `DaemonEngine` peer-aware
surface) **must** include this opaque-token guarantee.
Stage 1's `RefreshDiagnostic` variants omit peer attribution
entirely; the variant set grows additively when `PeerId` lands.

#### 3. Peer rotation as side-channel

**Threat.** A daemon under adversary control can observe
whether the wallet rotated away from it by re-establishing
connections to peers it might also control. If rotation
timing reveals information ("rotated 50 ms after I sent
malformed block X"), the rotation behavior itself is
observable and gives the adversary a high-bandwidth covert
signal back from the wallet.

**Mitigation pin.** Rotation actions emitted by the
`PeerReputationActor` are **temporally decoupled** from
event-receipt times: jittered rotation, batched decisions,
and an actor-internal scheduler that decouples
event-observation-time from rotation-action-time. The jitter
parameters and batching window land in the consumer-actor
PR; the trait contract for the rotation signal must accept
delayed action without re-issuing on the same observation.

This applies in both the synchronous and actor-mesh models,
but the actor mesh makes it easier to implement properly —
the temporal decoupling is internal to the
`PeerReputationActor` and does not leak through the
producer's API.

#### 4. Diagnostic stream as covert channel

**Threat.** If any consumer of `RefreshDiagnostic` has a
network path (analytics, crash reporter, even tracing
infrastructure with remote sinks), the stream is a potential
exfiltration channel. Hostile telemetry consumers can
amplify wallet-state observations into a high-bandwidth
side channel — exactly the kind of property the §3.1
master-secret-isolation framing tries to prevent.

The obvious case is direct network egress. The subtler — and
more failure-prone in practice — case is the **in-process
aggregator-republisher**: a consumer actor that is in-process
by topology but whose *external surface* crosses the trust
boundary by publication. Examples that look in-process at
first glance:

- A metrics-export actor that collects counters in-process
  and exposes them via a Prometheus or OpenTelemetry HTTP
  endpoint.
- A debug-UI actor that reflects diagnostic state to a
  developer pane via an IPC channel (Unix socket, named
  pipe, local-only TCP).
- A logger actor that writes to a log file the user (or
  another process) reads, especially when the file is
  collected by remote logging infrastructure.
- A developer-mode flag that dumps diagnostic state to
  stdout / stderr / structured-event-collector outputs
  that route off-host in deployment.

Each of these is in-process at the message-passing layer
but trust-boundary-crossing at the publication layer.
Subscribing to the full-fidelity stream from inside the
process is not the safety property; what matters is what
the actor *does* with what it observes.

**Mitigation pin (trait contract, §5.4.6) — phrased
recursively.** Full-fidelity `RefreshDiagnostic` events flow
only to actors **whose external surface is itself inside the
wallet trust boundary, recursively**. An actor's external
surface includes every channel by which it republishes,
aggregates-and-exports, persists, or otherwise makes
observable to a different trust principal anything derived
from the events it consumes. If any such surface crosses
the trust boundary, the actor receives only **projection
types** that have been explicitly sanitized at the producer
or at a sanitization-actor boundary in front of it — counts
and aggregates, not events; opaque token IDs, not peer
identifiers; bounded enums, not free-form strings.

**The recursion matters operationally.** Adding a new
consumer actor in V3.x — or extending an existing actor's
external surface — creates the obligation to audit the
actor's complete external surface against this rule. The
audit is not a one-time check at PR 4 review time; it is a
continuous obligation that binds on every PR that touches
the consumer-actor topology. Stage 4's review checklist
includes the per-consumer recursive trust-boundary audit;
[`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)
is the procedural anchor for the audit cadence (the
audit-against-this-rule is one validation surface among the
rule's others).

The trait-contract pin is enforceable by review, not by the
type system; Stage 4's actor topology design must respect
it. Phase 0a §2.3 prose amendment pins the rule so future
implementations cannot accidentally cross it.

**Round 4 review pass — V3.x forward-template (2026-05-15;
F5).** The V3.0 mitigation is procedural (review checklist) and
**sufficient at V3.0 because no aggregator/republisher consumer
exists in V3.0** — the only consumers are `NoopDiagnosticSink`
and `TracingDiagnosticSink`, both project-controlled and
covered by F9's per-class projection-type audit. The recursive-
leak hazard surfaces only when V3.x adds aggregator-style
consumers (metrics-export actors with HTTP endpoints, debug-UI
actors with IPC, log-collection actors). The §5.4.9 F5
adversarial review identifies that procedural mitigation is
weaker than CI-enforced mitigation and that the discipline
should compound at the V3.x consumer-actor PR template level.

**V3.x forward-template requirements (binding on the first
aggregator/republisher consumer PR).**

1. **Per-consumer external-surface audit.** Each new
   consumer-actor PR enumerates the actor's complete external
   surface — every channel by which the actor can publish,
   aggregate-and-export, persist, or otherwise make
   observable to a different trust principal anything
   derived from the events it consumes. The enumeration is a
   PR-description deliverable; the review checklist verifies
   completeness against the actor's source code.
2. **Projection-or-rejection at every external-surface
   boundary.** For each external surface, the audit specifies
   either (i) the projection type and projection function
   sanitizing full-fidelity events to the surface's permitted
   shape, or (ii) the rejection — the actor explicitly does
   not export data derived from full-fidelity events on this
   surface.
3. **CI-lint enforcement (V3.x consumer-actor PR template
   target).** A lint or static analysis flags consumer-actor
   types implementing `DiagnosticSink` and also implementing
   `Write`, `serde::Serialize`, network export, or other
   trust-boundary-crossing surfaces, requiring an explicit
   `#[allow(diagnostic_external_surface)]` attribute with an
   inline rationale comment. The lint is a deliverable of the
   first aggregator/republisher consumer PR; subsequent PRs
   inherit it. See FOLLOWUPS for the V3.1+ entry naming the
   lint as the trigger.
4. **Cross-emitter ordering misuse coverage (Round 4 review
   pass amendment, 2026-05-15; F12 scope-extension of the
   F5 lint).** The same V3.x lint also covers consumer-actor
   code that branches on the relative arrival timing of
   events from distinct emitters without first constraining
   ordering via an explicit causal-context field
   (`SnapshotId`, `ReservationId` + version, `BlockHeight`,
   etc.). The diagnostic-stream contract pin (§5.4.6 7th pin
   per F4) declares cross-emitter ordering undefined; the
   lint catches code that depends on it anyway. Detection
   shape: pattern-match on consumer-actor event-handler
   bodies that compare timestamps or use sink-observed
   arrival order across events whose emitter identity
   differs (statically-determinable from the event-class
   taxonomy plus the consumer's subscription set). The lint
   flags such patterns and requires either (a) a causal-
   context field added to the relevant event class with a
   matching update to the consumer's ordering derivation, or
   (b) explicit `#[allow(diagnostic_cross_emitter_ordering)]`
   with an inline rationale comment naming why per-emitter-
   only ordering is sufficient at this site. The lint
   subsumes the F5 external-surface lint as a single
   `diagnostic_consumer_discipline` clippy-style check.

The V3.x forward-template strengthens the recursive-trust-
boundary discipline from procedural to CI-enforced at the
moment the discipline starts mattering operationally.
Pre-V3.x, the procedural mitigation suffices; post-V3.x, the
CI lint catches mistakes the review would otherwise miss.

#### 5. Mailbox saturation as DoS

**Threat.** Rich diagnostic events emitted at high rate (a
hostile daemon spamming malformed blocks; a chain with a
genuine surge in scan-relevant activity) could saturate an
actor's mailbox, with the usual back-pressure / drop / OOM
trichotomy. A hostile daemon controlling the
`RefreshDiagnostic` event rate can trigger OOM in the consumer
actors if the mailbox is unbounded.

**Mitigation pin.** Consumer mailboxes are **bounded** with
explicit overflow policies:

- **Diagnostics consumers** (telemetry, logger): drop-oldest-on-overflow.
  Losing forensic detail is acceptable; losing process liveness is not.
- **Reputation consumer** (`PeerReputationActor`):
  aggregate-on-overflow — preserve per-peer event counts,
  drop per-event detail. The threshold logic depends on
  counts, not individual events.
- **Recovery consumer** (`RecoveryActor`): event-sequence-aware
  drop policy; preserve enough temporal structure to detect
  pattern matches; drop redundant within-pattern events.

The bounded-mailbox property is a consumer-side contract,
not a producer-side one; the producer emits at its natural
rate, the sink dispatches to consumer mailboxes, each
consumer's mailbox enforces its own policy. The trait
contract for `DiagnosticSink` does **not** promise delivery;
it promises emission attempt. Phase 0e seed text records
this so consumers cannot assume lossless delivery.

**Round 4 review pass — producer-side per-class emission rate
budget (2026-05-15; F6).** The consumer-side bounded-mailbox-
with-overflow pin closes the OOM hazard but does **not** close
the saturation-attack on stateful consumers (per §5.4.9 F6
adversarial scenario): an attacker-controlled daemon flooding
malformed blocks at the producer's natural rate forces
stateful consumers (the `PeerReputationActor`'s overflow path,
specifically) into a state that prevents legitimate decisions
(e.g., "the reputation actor never sticks a peer-ban"). The
defense-in-depth answer is a **producer-side per-class
emission rate budget**, complementing the consumer-side
overflow policy.

**The producer-side pin (Round 4 review pass).** The
producer (`LocalRefresh::produce_scan_result`) MUST track a
per-event-class emission counter for each refresh attempt.
Each `RefreshDiagnostic` variant has a per-attempt-and-per-block
emission ceiling proportional to the natural per-block rate of
the variant:

- **`ScanProgress`** — at most one per block scanned (natural
  per-block rate; ceiling matches reality).
- **`DaemonMalformed`, `DaemonTimeout`, `DaemonProtocolError`,
  `ReorgObserved`** — at most one per block scanned per class
  (adversarial events; one-per-class-per-block bounds the
  attack surface without losing signal).
- **(Future variants)** — each variant pinned with a
  per-block ceiling at variant-introduction time.

**Suppression-notice variant (Phase 1 enum addition).** When
a per-class budget is exceeded, the producer emits a single
`RefreshDiagnostic::SuppressedRateLimit { class: <variant tag> }`
notice and stops emitting that class for the remainder of the
attempt. Consumer actors interpret the notice as "the producer
hit the rate limit on this class within this attempt" — adequate
signal for stateful decisions (the `PeerReputationActor` can
ban the peer based on the notice alone) without forcing the
consumer to process the full flood. The variant is added under
`#[non_exhaustive]` per §5.4.8 forward-note (additive variant
growth is supported by the trait contract).

**Field-shape pin (Round 4 review pass amendment, 2026-05-15;
F13).** The variant carries **only** `class: SuppressedClass`
where `SuppressedClass` is a small project-defined enum naming
the suppressed event class (`SuppressedClass::DaemonMalformed`,
`SuppressedClass::DaemonTimeout`, `SuppressedClass::DaemonProtocolError`,
`SuppressedClass::ReorgObserved`, `SuppressedClass::ScanProgress`).
The variant **MUST NOT** carry:

- A **count** of suppressed events (e.g., `count: u32`). The
  attacker who triggered the rate-limit learns from the count
  exactly how many of their flood events the budget swallowed,
  giving them a covert channel back from the producer's
  internal state. The reputation actor's stateful decision
  ("ban this peer") needs *that the limit was hit*, not *how
  many events were suppressed*; the count is signal-free for
  the consumer's correctness obligation and is signal-rich for
  the attacker's reconnaissance.
- A **timestamp** or **timing field** (`first_suppressed_at`,
  `window_elapsed`, etc.). Timing fields would carry the same
  attacker-reconnaissance shape as the count plus a side-
  channel into the producer's emission-loop scheduling.
- The **original event payload** that triggered suppression
  (e.g., `last_suppressed_event: RefreshDiagnostic`). This
  would defeat the projection-type discipline (per F9) by
  carrying full-fidelity event content past the rate-limit
  boundary that was meant to suppress it.

**What consumers infer from absence.** Consumer actors that
need a count derive it from *the absence of further events of
the suppressed class within the same attempt boundary*: the
attempt-end signal (the `produce_scan_result` future
completing, observable from the orchestrator side via
`ScanResult` or `RefreshError`) plus the `SuppressedRateLimit`
notice tells the consumer "between the notice and the attempt
end, no further events of that class were emitted by this
producer." For finer-grained rate-limit telemetry the
project would add a separate operator-only diagnostic surface
(metrics, not `DiagnosticSink`) with its own threat-model
disposition; the diagnostic stream is not that surface.

**Why a class enum and not a discriminant integer or string.**
A discriminant integer couples the projection contract to the
`RefreshDiagnostic` variant ordering (a new variant changes
older variants' discriminants under default Rust enum layout,
breaking consumer pattern-matches against the integer); a
string is a free-form attacker-influencable surface that
contradicts §5.4.8 #4's projection-type discipline. A
small project-defined `SuppressedClass` enum is stable across
`RefreshDiagnostic`'s additive variant growth (each new
adversarial-class variant gains a matching `SuppressedClass`
arm under `#[non_exhaustive]`) and is constructively
attacker-uninfluencable.

**Emission-cadence sub-pin (Round 4 review pass meta-review
post-amendment, 2026-05-15; F13 sub-pin).** The field-shape
pin closes the payload covert channel; the **emission-cadence
covert channel** is closed by a separate producer-internal
discipline. Without this sub-pin, an attacker triggers a flood
in class X, observes the resulting `SuppressedRateLimit
{ class: X }` notice, waits, triggers another flood, observes
a second notice, and reconstructs suppression frequency by
counting notice-arrival timestamps in their own emit-arrival
timeline. The class-only payload is signal-free; the
**emission cadence is the side-channel**. The discipline that
closes it: the producer emits **at most one
`SuppressedRateLimit { class: X }` event per class per
attempt**. Subsequent in-class suppressions within the same
attempt are absorbed silently — the producer's per-attempt
`emit_state` carries a per-class flag transitioning from
"emitting" to "suppressed (notice sent)" exactly once;
subsequent in-class emission attempts increment the per-class
counter (bounded by the per-block ceiling tracking) but do
not emit further notices. Consumer actors interpret the
notice as "this class had rate-limited activity at some point
in this attempt" — once per attempt per class, with class as
the only discriminant on payload *and* on cadence.

**Cross-attempt cadence is a separate layer-up question.** An
attacker who can force many attempts to run in close
succession (e.g., by triggering `RefreshError::ConcurrentMutation`
to drive orchestrator-side retries) observes one notice per
attempt per class, yielding *attempt-rate* as a residual
side-channel. This is bounded by the orchestrator's existing
retry-loop policy (per `engine/refresh.rs` retry semantics:
attempt count is capped, retry backoff is bounded), which
itself is sized against the threat model the
`ConcurrentMutation` retry was originally designed for.
Tightening the cross-attempt cadence further would require
producer state that survives across `produce_scan_result`
invocations — directly contradicting the per-attempt
producer-state-isolation property (the producer is
constructed fresh per attempt; per-attempt state is the
zeroization scope for the `ViewMaterial` and `Scanner`).
The cross-attempt threat is therefore deliberately
addressed at the orchestrator-side retry-loop layer, not
the producer-side notice cadence layer; pin recorded so
future audit cannot mistake the layer-up disposition for
an oversight.

**Implementation cost.** O(num\_event\_classes) `u32` counters
on the producer; one branch per emission. Producer-internal
property; does not change trait surface; lands in §7.X C4
commit body.

**Why producer-side, not consumer-side.** Consumer-side
overflow policies (drop-oldest, drop-newest, aggregate)
respond to events that have already been emitted by the
producer; the producer's emission cost (`emit` call, per-class
counter increment, bounded-channel send) is incurred regardless.
Producer-side rate-limiting bounds the producer's emission
cost as well, preserving the §5.4.4 invocation-overhead
property under adversarial daemon control. Defense in depth
because consumer-side policies vary by consumer; producer-side
rate-limiting establishes a ceiling all consumers can rely on.

#### 6. Encrypted cache for RPC recovery (V3.x candidate; structurally rejected at V3.0)

**Round 4 review pass surface (2026-05-15; F7).** A
hypothetical "encrypted RPC cache for recovery" — caching
RPC responses (tip height, scannable blocks, transaction
acceptance status) across wallet restarts to avoid re-fetching
from the daemon — has been raised as an adjacent feature to
the encrypted-persistence question (F1) but at a different
target. F1 covers diagnostic-event persistence; F7 covers
RPC-response persistence. The two are structurally adjacent
but distinct: F1's events flow through `DiagnosticSink`; F7's
data flows through `DaemonEngine` RPC paths.

**Threat-model adjacency to F1.** F7 inherits the same
attack-surface family as F1 (§5.4.9 F1 enumeration):
master-key code-path expansion (cache encryption requires
master-key derivation); deserialization-on-startup
(decrypt-and-replay on wallet open is a deserialization
path); metadata side-channel (cache write/read timing leaks
restart correlation); cross-wallet correlation amplification
(persisted RPC responses correlate across wallets exposed
to the same daemon); persistence as adversary-controlled DoS
(disk-fill, cache poisoning); forensic-attack primitive
(persistent on-disk artifact under encryption is still
information-bearing).

**Adversarial scenario (per §5.4.9 F7).** An attacker who
can trigger frequent wallet restarts (process kill, OOM,
hosted-wallet rotation, user quit/restart) drives the cache
write/read pattern under attacker-influenced conditions.
The cache becomes a persistent side-channel: an attacker
who forces a restart right after a high-value output is
scanned drives the next restart's cache write to leak
timing or content-hash signal correlating with the high-value
event. A weak nonce or single global key admits cache
poisoning across restarts; the wallet loads poisoned data
and either crashes or accepts a malformed `ScanResult`
that bypasses the merge gate.

**Hardened disposition (binding on V3.0; parallel to F1's
R17 hardening).** **V3.0 ships no encrypted RPC cache for
recovery; the feature is structurally rejected.** V3.0's
recovery path on restart is **re-fetch from the daemon**
(re-establishing peer connections, re-scanning from the
last-merged height, re-validating against on-chain state).
This is the privacy-first default; it is also the
attack-surface-minimal default.

**V3.x reopens this question only under all of:**

(a) **Demonstrated production use case from real deployments**
    — the operational failure mode the cache is intended to
    address must be observed in production, not anticipated.
(b) **Full threat-model review at evaluation time**, including
    the six vectors above plus RPC-cache-specific surfaces
    (cache invalidation on reorg; per-RPC-method nonce
    derivation; cache poisoning under attacker-controlled
    daemon).
(c) **Per-RPC-method nonce derivation, key rotation on
    password change, cache invalidation on reorg, and
    constant-time cache reads** are all design-doc-level
    pinned requirements before implementation. Half-mitigations
    (e.g., a single global key) are unacceptable.
(d) **Explicit `AUDIT_SCOPE.md` amendment** if adopted,
    bringing the RPC-cache layer into audit scope as a
    key-material-handling surface.

**No V3.x schedule entry; conditional reopening only.**
Same shape as F1; the rejection is structural at V3.0 and
the path-to-reopen is bounded by demonstrated need against
the threat model.

**Cross-reference.** F1's R17 hardening covers the
diagnostic-event persistence target; F7 covers the
RPC-response persistence target. Both rejections share the
attack-surface family; both V3.x reopening conditions are
parallel. The two together close the in-process-encrypted-
persistence question across the two adjacent surfaces with
consistent discipline.

#### 7. Emit-timing variance residual (acknowledged microarchitectural side-channel)

**Round 4 review pass surface (2026-05-15; F8).** Even with
lock-free queues, the exact moment `emit` returns can leak
whether the event was dropped or queued (cache-line
contention, branch-predictor side-channel, queue-internal
state-dependent latency). An attacker with nanosecond-resolution
timing observation on the producer can measure response-time
variance and infer event-class emission rate or hot-output
detection.

**Acknowledged-as-residual disposition.** The microarchitectural
side-channel is **real but disproportionate to V3.0's threat
model**:

- **Constant-time `emit` is hard.** Lock-free queues have
  variable latency by construction; bounding the variance
  requires either pre-allocating worst-case queue depth
  (memory cost; bounded by V3.x consumer-actor mailbox
  sizing decisions) or padding with timing-noise (bounded-
  variance loop adds non-trivial overhead and doesn't fully
  close the side-channel).
- **Realistic exposure analysis.** The producer-side `emit`
  timing variance contributes nanoseconds of jitter to the
  per-block scan time. Block-level scan time has natural
  variance much larger than this (per-block ML-KEM-768
  decapsulation cost dominates; network jitter on the
  daemon RPC path adds milliseconds). Whether the attacker
  can extract signal from the noise floor depends on the
  attacker's observation channel; for V3.0's primary
  deployment threat model (Tor/I2P-routed daemon
  connections), the network-jitter noise floor swamps the
  microarchitectural signal.
- **V3.x microarchitectural-side-channel hardening** is its
  own design surface — full mitigation requires constant-time
  `emit`, constant-time queue insertion, and likely
  scheduler isolation. None of this is V3.0-cheap; the
  cost-benefit at V3.0 lands on "acknowledge as residual."

**Phase 1 implementation note (§7.X C2).** The
`DiagnosticSink` implementations bundled with PR 4
(`NoopDiagnosticSink`, `TracingDiagnosticSink`) and any
Phase 1 internal queueing use a **bounded-variance lock-free
queue** (e.g., `crossbeam::queue::ArrayQueue` with
pre-allocated capacity) to bound worst-case `emit` variance
without claiming constant-time. This is best-effort
mitigation, not a hard property; the residual is named
explicitly so future microarchitectural-side-channel hardening
work can locate it.

**FOLLOWUPS entry.** Not added — the residual is bounded by
V3.0's threat-model anchor and the V3.x mitigation surface is
its own design topic. If V3.x microarchitectural-side-channel
work cuts, the FOLLOWUP is generated at that point.

#### Cross-cutting: actor-mesh emergent behaviour

The five surfaces above are individually mitigable; the
emergent-behaviour question — *do the mitigations compose
correctly when all five are active simultaneously* — is a
V3.x actor-mesh-PR review concern, not a PR 4 concern. PR 4
pins the constraints; the emergent-behaviour analysis is
deferred to the implementation PR with the constraints as
input. The
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
"audits-are-clean-so-compress" anti-pattern guards against
relaxing this discipline in the V3.x PR: the emergent-behaviour
audit must run even if each individual mitigation is
audit-clean.

#### Cross-cutting: variant ordering and serialization (forward-note)

Under the §5.4.6 / §5.4.8 #4 in-process trust-boundary pin,
the diagnostic stream is **not serialized** to any stable
external format. `RefreshDiagnostic` flows between actors as
in-process values; sanitized projections crossing the trust
boundary are typed differently and have their own
serialization-stability concerns. **Variant-ordering inside
the `RefreshDiagnostic` enum is therefore not load-bearing**
under PR 4's surface; the `#[non_exhaustive]` attribute
preserves future additive evolution without serialization
breakage. **No action required at PR 4.**

The forward-note is recorded only because the property
becomes load-bearing under one specific future PR shape:
**if a future PR ever wants to record diagnostic streams to
disk for test replay** (deterministic CI repro of
actor-mesh emergent-behaviour scenarios; cross-build
reproducibility of consumer-actor responses to recorded
adversarial inputs; debugging-tool snapshots), variant
order becomes part of the on-disk format and the additive-
evolution discipline acquires a backward-compatibility
constraint. That future PR re-reads this note and either
(a) freezes the variant ordering, (b) uses a stable
discriminant scheme (e.g., string-typed variant tags
serialized separately), or (c) recognizes that the on-disk
format is a separate type with its own evolution rules.
None of these are PR 4 work; the note exists so the future
PR has the constraint named ahead of time.

### §5.4.9 Round 4 review pass — adversarial review of the post-Round-4 substrate (2026-05-15)

Two reviewers ran adversarial reviews against the Round 4 close
substrate (the post-Round-4 design doc, before Phase 1 cuts).
Reviewer 1 focused on residual feature-commitment surfaces and
contract-pin tightening; Reviewer 2 focused on diagnostic-stream
attack surfaces and the encrypted-cache resilience adjacency.
Together they surfaced **nine actionable findings** (F1–F9) and
a tenth (F10) that collapsed into the first under shared
substrate. A subsequent **meta-review amendment (2026-05-15)
of the F1–F9 dispositions themselves** surfaced three additional
findings (F11–F13) targeting under-specifications introduced by
the F1–F9 disposition substrate rather than new attack vectors
against the pre-review-pass substrate. A further **post-
amendment review (2026-05-15) of the F11–F13 dispositions
themselves** surfaced three sub-pins (F11-S, F12-S, F13-S)
sharpening F11/F12/F13 with Phase-1-author-aware observations
that the disposition language admits but the discipline does
not — F13-S is the substantive one (closes the emission-cadence
covert channel the F13 field-shape pin left open). The combined
disposition total is **twelve actionable findings plus three
sub-pins** with thirteen recorded primary-attribution slots
(F10 collapsed) and three sub-pin attribution slots. This
section records each finding with reviewer attribution, attack
analysis, disposition reasoning, and a pointer to the inline
edit that landed the disposition; sub-pins are recorded after
the F11–F13 amendment block.

The review pass is a Round 4 deliverable, not a fresh round. It
captures the thought process behind each finding's disposition
so future readers (Phase 1 reviewers; auditors; future-PR
authors weighing similar trade-offs) can reconstruct why each
inline edit took the form it did rather than only what it says.

**Closure-rule cross-reference.** Per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§7's strengthened closure rule, the review pass is the
explicit reopening mechanism for any finding that surfaces
after a round closes — Round 4 reopens via the review pass,
disposes the findings inline, and re-closes. None of the
findings reopened a prior round (Round 1 / Round 2 / Round 2
reframe / Round 3 dispositions all hold); the dispositions
land at Round 4's substrate level (contract pins, attack-surface
enumerations, commit-list refinements).

**Meta-review amendment cross-reference.** The F11–F13 amendment
applies the same review-pass discipline to the F1–F9 substrate
that F1–F9 applied to the pre-review-pass substrate. The closure
rule's reopening mechanism is the explicit substrate; the
amendment does not constitute "Round 5" because none of F11–F13
reopens a Round 1–4 disposition (each targets an under-
specification *introduced by* an F1–F9 disposition, not a
substrate decision Rounds 1–4 settled). The amendment is
recorded inline at §5.4.9 below the F10 disposition; the
F1–F9 disposition rationale is unchanged.

#### F1 — R17 encrypted-persistence opt-in language hardening (Reviewer 1, expanded by Reviewer 2)

**Source.** Both reviewers converged on the same anti-pattern.
Reviewer 1 raised the diagnostic-event-persistence side directly
(R17's V3.x "wallet-internal encrypted-persistence opt-in"
language); Reviewer 2 raised the structurally adjacent
encrypted-cache-for-RPC-recovery side (different target, same
attack-surface family). F1 covers the diagnostic-event side; F7
covers the RPC-cache side with parallel framing.

**Reviewer 1's six attack vectors against the V3.x opt-in.**

1. **Crypto code-path expansion via persistence triggers.**
   Persisted events require encryption with a key derived from
   the wallet master key. New code-path touching master-key
   material outside transaction signing — exactly the surface
   that historically introduces nonce-reuse, weak-KDF-parameter,
   and IV-collision bugs. An adversary who can force high-volume
   event emission (hostile daemon producing many malformed
   blocks) drives this path under pathological conditions
   specifically to probe for these failures.
2. **Deserialization-on-startup as exploit primitive.**
   Encrypted-persistence-for-crash-recovery means decrypt-and-
   replay on wallet open. Replay is a deserialization path;
   deserialization paths from disk are notoriously fertile for
   vulnerabilities. Even with verified encryption, post-decrypt
   structured-event parsing is an attack surface — if attacker
   has any path to influence persisted content (the bug-class
   above plus an attacker-influenced event field), they have a
   deserialization-on-startup primitive that runs **before** the
   wallet is fully verified.
3. **Metadata side-channel.** "Encrypted" protects content but
   not metadata. File sizes, write timing, write patterns, IO
   syscall patterns are all observable to anyone with
   filesystem-adjacent access (multi-user systems, backup
   snapshots, swap files, `/proc` inspection). Write rate
   during refresh correlates with wallet activity; write
   patterns during transaction submission correlate with
   transaction construction. The encrypted-persistence file
   becomes a wallet-activity signal that exists **only because
   we added persistence**.
4. **Cross-wallet correlation amplification.** Two wallets
   running the same software, exposed to the same daemon,
   produce statistically-correlatable persistence patterns.
   An adversary with filesystem access to multiple wallets
   (institutional-adversary backup-stealing; multi-user system;
   cloud backup compromise) can correlate them across the
   persisted artifacts. Without persistence, this correlation
   surface doesn't exist.
5. **Persistence as adversary-controlled DoS.** Adversary
   causes high event volume → high write pressure → disk fills
   → wallet writes fail → wallet enters error state, or
   corrupts in specific ways that crash subsequent opens. The
   drop-on-close default neutralizes this entire class; the
   opt-in restores it.
6. **Forensic-attack primitive against seized wallets.**
   Persistent diagnostic events on disk are exactly what
   forensic analysts want from a seized device. Even if
   encrypted, their existence is information ("this wallet was
   active during these time windows"). The drop-on-close
   default produces no on-disk artifact; the opt-in produces
   one whose mere existence is informative.

**My analysis.** All six vectors are real and individually
load-bearing; A1 (master-key code-path expansion) is the
strongest because it directly creates new key-material handling
outside the audited transaction-signing path. A2
(deserialization-on-startup) is historically the most-exploited
class in this family (the Pickle, Marshalling, BSON-deserializer
bug catalogues span decades).

The current §5.4.8 #1 Round 3 acknowledgment paragraph reads as
a soft commitment to evaluate ("V3.x evaluates per-stream
wallet-internal encrypted-persistence opt-in"). This is the
*cost-benefit-defer-to-later* anti-pattern per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
applied to a feature commitment: deferring the disposition feels
safe ("we'll think about it later") but the deferral itself
isn't free — it shapes contributor and reviewer expectations
about what the project is going to ship. The
architectural-integrity-now disposition is to walk back the
soft commitment to a hard rejection with conditional-reopen
language: V3.0 ships drop-on-close as structurally final;
persistence of diagnostic events is rejected; V3.x reopens this
question only under explicit conditions that shift the burden
of proof onto the would-be feature.

**Disposition: accept.** Replace the §5.4.8 #1 Round 3
acknowledgment paragraph with the hard-rejection-plus-conditional-
reopen shape. The reopening conditions: (a) demonstrated
production use case from real deployments (not anticipated
demand); (b) full threat-model review at evaluation time
including all six vectors above; (c) explicit `AUDIT_SCOPE.md`
amendment if adopted; (d) acknowledgment that privacy-first
default supersedes ergonomic-recovery considerations except
where (a)–(c) are demonstrated. **No V3.x schedule entry**;
conditional reopening only.

Apply the same change symmetrically to PR 5 §5.4 R17 (the two
sections cross-reference each other; if one is hardened and the
other isn't, the asymmetry confuses readers and creates
plan-vs-state divergence per
[`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)
adjacent §19 pattern).

**Inline edits applied.**

- §5.4.8 #1 — Round 3 acknowledgment paragraph replaced with
  hard-rejection-plus-conditional-reopen language.
- PR 5 §5.4 R17 — disposition prose replaced with parallel
  hard-rejection language; the contract-refinement paragraph
  retired.
- PR 5 status banner — the "encrypted-persistence opt-in
  (V3.x)" language in the closure summary updated to reflect
  the hardening.

#### F2 — Lock-latency content-dependence + 5-checkpoint discipline (Reviewer 1)

**Adversarial scenario.** User locks wallet under perceived
threat (laptop seized, knock at door, sudden security event).
Pre-positioned hostile daemon serves a maximally-hostile block
(large block, high view-tag-match rate). Lock fires; cancellation
token sets; checkpoint 3 fires at block boundaries (between
blocks), not within a single block's scan loop. Spend secret
remains in memory for seconds while the current block's scan
loop completes. Memory dump (debugger, hibernation, process
inspection) during this window retrieves the spend secret.

**My analysis.** The §3.1 lock-latency property bound is
**content-dependent** under the current four-checkpoint
discipline. Concretely:

- The expensive operation in the per-block scan loop is the
  ML-KEM-768 hybrid decapsulation, triggered per
  view-tag-matched output (~100µs each on commodity hardware).
- A pathological block crafted by an adversarial daemon —
  maximum block size with maximum view-tag-match rate, possibly
  thousands of matches per block — extends single-block scan
  time to ~100ms or more.
- The §3.1 "tens of ms typical" bound holds for typical blocks
  but does **not** hold for adversarial blocks; the adversary
  controls the bound's content-dependence.

**Cost analysis for the mitigation.** Inner cancellation check
at per-transaction granularity adds one atomic load + branch
per transaction (~1–3 ns per check). For a typical block with
~50 transactions, ~50–150 ns added per block. For pathological
blocks with ~1000 transactions, ~1–3 µs added per block. This
is sub-microsecond per block and **negligible against the
per-transaction work cost** (microseconds to milliseconds per
transaction depending on view-tag-match count). The cost
argument for the inner check is structurally absent.

**Granularity choice: per-transaction vs per-output.** Per-output
granularity adds checks inside the inner-most decapsulation loop
(more overhead; harder to reason about timing-side-channel
implications). Per-transaction granularity is at a natural
boundary in the block-scan loop. The lock-latency upper bound
under per-transaction granularity is "max time to scan one
transaction's outputs" — milliseconds at most, even
pathologically (a transaction with 16 outputs, all view-tag-
matched, costs ~16 × 100µs = 1.6 ms). Per-transaction is the
right granularity.

**Atomicity-under-cancellation contract.** The current contract
(§7) says `produce_scan_result` returns either a full
`ScanResult` covering its scanned span or `RefreshError::
Cancelled`; no partial-span `ScanResult`. The inner check
preserves this — on cancellation, the producer discards
in-flight per-block partial state and returns `Cancelled`.
`Scanner`'s `ZeroizeOnDrop` chain handles the per-block
materials; `ViewMaterial`'s `ZeroizeOnDrop` handles the
attempt-scoped materials.

**Disposition: accept.** Add a fifth checkpoint at per-transaction
granularity inside checkpoint 3's per-block scan loop. The §7
four-checkpoint discipline becomes a five-checkpoint discipline:
checkpoint 3 (between blocks; existing) and checkpoint 5
(between transactions within a block; new) collectively bound
lock-latency to per-transaction scan time, content-independent
under adversarial daemon control.

The architectural-integrity-now disposition wins decisively
here: cost is sub-microsecond; benefit is content-independent
lock-latency bound under adversarial control; the "accept the
content-dependent bound with named justification" alternative
is the cost-benefit-defer-to-later anti-pattern with no
substantive cost to defer against.

**Inline edits applied.**

- §3.1 lock-latency property — refined from "single-block
  scan time, typically tens of ms" to "single-transaction scan
  time, sub-block-bounded; per-transaction worst case
  millisecond-scale even under adversarial daemon block
  crafting."
- §7 four-checkpoint discipline — promoted to five-checkpoint
  with the new checkpoint 5 (between transactions within a
  block) named and the rationale recorded.
- §6 binding-check matrix — updated to reflect the
  five-checkpoint contract.
- §7.X C4 commit description — updated to specify that the
  `produce_scan_result` body implements both the existing
  per-block checkpoint 3 and the new per-transaction
  checkpoint 5.

#### F3 — `AssertionSink` / `PanickingSink` as permanent CI regression coverage (Reviewer 1)

**The contract gap.** The current §5.4.6 framing reads as a
one-shot Round 4 / Phase 1 deliverable: "the property test lands
in Round 4." This is correct for Phase 1 timing but understates
the contract's status. Coherence is not a property the
implementation satisfies once at Phase 1 cut; it is a property
the implementation **must continue to satisfy** across all
future changes. The `AssertionSink` test is the canonical
reference for what coherence means; if a future implementer
breaks the test, the implementation is wrong, not the test.

**Adversarial relevance.** An implementation bug introduces a
silent-error path: returns `Err(MalformedScanResult)` without
emitting `RefreshDiagnostic::DaemonMalformed`. The bug is
invisible at the trait surface (return type matches; sink
emission is `&self`-side and the type system doesn't enforce
"emit-then-return" sequencing). Downstream consumers see fewer
events than the error rate implies. An adversary fingerprinting
wallet behavior by varying daemon responses can detect this
drift and target the silent path specifically — knowing the
wallet retries without alerting the reputation actor.

**My analysis.** The fix is a contract-clarification, not a
code change. Pinning `AssertionSink` and `PanickingSink` as
**permanent CI regression coverage** shifts their discipline
status from "tests we ship" to "tests that define the contract."
Practical implication: an implementation change that breaks
either test isn't "a test failure to investigate" — it's "a
contract violation that requires either fixing the
implementation or getting explicit re-pin from the design
doc." This is a meaningfully stronger discipline than ambient
test-passing.

The same reasoning applies to `PanickingSink`: the
producer-panic-safety property must continue to hold across
future changes; the test is the canonical reference for what
panic-safety means at the producer-side robustness layer.

**Disposition: accept.** Land a §5.4.6 prose addition pinning
both as **permanent CI regression coverage** binding on every
PR touching `RefreshEngine` implementations. The pin is a
prose-level change to the existing contract pin paragraphs.

**Inline edits applied.**

- §5.4.6 emission/return coherence pin — extended with
  "permanent CI regression coverage" framing; explicit
  statement that breaking the test is a contract violation,
  not a test-failure-to-investigate.
- §5.4.6 producer-panic-safety property — same extension
  applied to `PanickingSink`.

#### F4 — Per-emitter FIFO ordering as seventh contract pin (Reviewer 1)

**Contract gap.** The §5.0.3 / §5.4.6 contract pins enumerate
non-blocking, panic-safety, concurrent-emit, recursive
trust-boundary, restart-amnesia, and emission/return coherence
— six pins. They do **not** pin event ordering guarantees.

**Adversarial relevance.** A peer-reputation actor that depends
on event ordering ("`MalformedScanResult` observed before peer
rotation") makes decisions on temporal context. If the sink
doesn't preserve ordering, the reputation actor sees events in
reordered form; if the reordering is adversary-influenceable
(e.g., via concurrent emit racing under specific timing
windows), the attacker can shape what the reputation actor
concludes.

**My analysis.** The right pin is **per-emitter FIFO ordering
preserved; cross-emitter ordering is undefined; consumers
must not rely on cross-emitter ordering**. This is restrictive
enough to be implementable cheaply (a single-emitter mailbox
is naturally FIFO; the contract requires the sink not to
reorder events from a single emitter, but admits any
cross-emitter interleaving) and clear enough that downstream
consumer-actor PRs know what they can assume.

**Placement.** Reviewer 1 named §5.0.3 (PR 5's contract
section). The diagnostic-stream contract is project-wide; PR 4
§5.4.6 carries the same six pins for `RefreshDiagnostic`. The
seventh pin lands in **both** §5.0.3 and §5.4.6 to preserve
symmetry — the eventual `DIAGNOSTIC_STREAM.md` spec doc (V3.x)
will lift the contract to a single project-wide statement; for
V3.0, the per-engine-design-doc symmetry is the substitute.

**Disposition: accept.** Land the seventh contract pin in PR 4
§5.4.6 and PR 5 §5.0.3 with parallel wording.

**Inline edits applied.**

- PR 4 §5.4.6 — seventh contract pin added (per-emitter FIFO
  ordering preserved; cross-emitter ordering undefined).
- PR 5 §5.0.3 — same pin added with parallel wording.

#### F5 — Aggregator-republisher recursive-leak V3.x forward-template (Reviewer 2 A1)

**Reviewer 2's break.** An in-process aggregator-republisher
actor (metrics-export actor with Prometheus/OpenTelemetry HTTP
endpoint, debug-UI actor with IPC channel, logger actor writing
to a remote-collected log file) subscribes to the full stream,
aggregates, and republishes a sanitized projection over a
trust-boundary-crossing surface. The aggregator is in-process,
so it receives full events; the projection it republishes
crosses the boundary. Attacker reads the projection (or log
file) and reconstructs timing/rate information.

**My analysis.** The §5.4.8 #4 recursive-trust-boundary pin
already names this hazard. The substantive question is whether
the V3.0 mitigation is sufficient and what V3.x needs to add.

**For V3.0:** the only consumers are `NoopDiagnosticSink` and
`TracingDiagnosticSink`, both project-controlled. The
`TracingDiagnosticSink` routes to `tracing::event!`, which is a
trust-boundary-relevant surface — what it logs is the
projection. F9 (projection-type audit) covers this for V3.0.
**Aggregator/republisher consumers do not exist in V3.0**;
the recursive-leak hazard surfaces only when V3.x adds them.

**For V3.x:** procedural mitigation (Stage 4 review checklist,
per-PR audit) is what we have today. Reviewer 2 is right that
this is weaker than type-level or CI-level enforcement.

- **Type-level enforcement** is hard. Rust can't statically
  distinguish "this consumer exports to disk" from "this
  consumer keeps data in-process." A marker-trait approach
  (`InProcessOnly`) would constrain consumer types but the
  marker can be added by mistake; it's a *requires-discipline*
  type, not a *enforces-discipline* type.
- **CI-level enforcement** is plausible. A lint that flags
  consumer-actor types implementing `DiagnosticSink` and also
  implementing `Write` / network export, requiring an explicit
  `#[allow(...)]` with rationale. This is V3.x consumer-actor-PR
  template work — the lint lands when the first consumer-actor
  PR introduces an aggregator/republisher.

**Disposition: accept-as-FOLLOWUP.** Strengthen §5.4.8 #4 with
explicit V3.x forward-template language requiring per-consumer
external-surface audit; add a FOLLOWUP entry naming the V3.x
lint or static-analysis target (binding on the first
aggregator/republisher consumer PR).

**Inline edits applied.**

- §5.4.8 #4 — strengthened with V3.x forward-template (each
  new aggregator/republisher consumer must explicitly audit
  its external surface; V3.0 procedural mitigation is
  sufficient because no aggregator/republisher consumer
  exists in V3.0).
- FOLLOWUPS — V3.1+ entry: "Diagnostic-stream
  aggregator-republisher CI lint" with trigger "first
  consumer-actor PR introducing an aggregator or republisher."

#### F6 — Producer-side per-class emission rate budget (Reviewer 2 A2)

**Reviewer 2's break.** Attacker floods with crafted malformed
blocks that trigger `DaemonMalformed` + `ReorgObserved` at the
maximum producer rate (one per block, or one per scanned output
in pathological view-tag cases). Even with drop-oldest-on-overflow,
consumer actors must process the rate of events. If the bounded
mailbox is sized for "normal" traffic, the attacker forces the
reputation actor into "aggregate-on-overflow" continuously,
effectively resetting reputation every window and preventing
any peer-ban from sticking. Wallet stays connected to the
malicious peer.

**My analysis.** The mailbox-saturation pin at §5.4.8 #5
addresses bounded mailbox + overflow policy on the consumer
side. Reviewer 2 wants producer-side rate-limiting as well —
defense in depth.

**Refinement on the rate-limit shape.** Reviewer 2's specific
proposal ("≤ 1 event per block scanned") is too coarse:
`ScanProgress` is intentionally per-block (one progress update
per block scanned is the natural emission rate). The better
framing is **per-class per-block budget**: each event class has
a per-block emission ceiling; on overflow within a class, a
single suppression notice fires (e.g., `RefreshDiagnostic::
SuppressedRateLimit { class: DaemonOp::... }`) and the producer
stops emitting that class for the remainder of the attempt. The
reputation actor can then make a single decision based on "we
hit the rate limit on `DaemonMalformed` events" rather than
"we observed N/sec `DaemonMalformed` events" — which is
adequate signal for peer-ban with bounded actor cost.

**Implementation cost.** O(num\_event\_classes) counters on the
producer (single-digit number of classes; trivial). One branch
per emission. Producer-internal property; doesn't change trait
surface; lands in §7.X C4 commit body.

**Disposition: accept-with-refinement.** Land §5.4.8 #5
strengthening with per-block per-class emission budget on the
producer; pin as contract not just implementation choice; Phase 1
implements in C4. The suppression-notice variant lands as a
Phase 1 deliverable (it's a `RefreshDiagnostic` enum variant,
covered by `#[non_exhaustive]` additive growth).

**Inline edits applied.**

- §5.4.8 #5 — extended with producer-side per-class emission
  rate budget pin; suppression-notice variant named as a
  Phase 1 enum addition.
- §7.X C4 commit description — updated to specify producer-side
  per-class counter tracking and suppression-notice emission on
  budget exceeded.

#### F7 — Encrypted-cache-for-RPC-recovery V3.x rejection (Reviewer 2 A3)

**Reviewer 2's break.** A hypothetical "encrypted RPC cache for
recovery" feature (cache RPC responses across wallet restarts to
avoid re-fetching from the daemon) introduces structurally
adjacent attack surfaces to F1. Attacker triggers frequent
wallet restarts (process kill, OOM, hosted-wallet rotation,
user quit/restart). The encrypted cache becomes a persistent
side-channel: write/read timing leaks restart correlation; a
single global key or weak nonce admits cache poisoning;
per-restart cache writes leak which outputs the wallet cared
about.

**My analysis.** This is structurally adjacent to F1 but a
distinct target — RPC-response cache vs diagnostic-event
persistence. Same attack-surface family (deserialization,
key-derivation, side-channel, forensic artifact). The
hardening shape is the same: structural rejection at V3.0 +
conditional reopen under explicit conditions. The attack
vectors map closely (master-key code-path expansion;
deserialization-on-startup; metadata side-channel; cross-wallet
correlation; persistence as DoS; forensic primitive); the
target differs but the response should be the same.

**Disposition: accept-with-extension.** Land a new §5.4.8 #6
that names the encrypted-cache-for-RPC-recovery surface
explicitly with parallel hardening to F1 — V3.0 rejected;
V3.x reopens only under (a)–(d) conditions extended for the
RPC-cache target (per-RPC nonces, key rotation on password
change, cache invalidation on reorg, constant-time access).

The §5.4.8 numbering grows from five surfaces to seven (#1–#5
existing + #6 RPC cache + #7 emit-timing residual from F8).

**Inline edits applied.**

- §5.4.8 #6 (new) — encrypted-cache-for-RPC-recovery attack
  surface with structural V3.0 rejection + conditional reopen.

#### F8 — Emit-timing variance residual (Reviewer 2 A4)

**Reviewer 2's break.** Even with lock-free queues, the exact
moment `emit` returns can leak whether the event was dropped or
queued (cache-line contention, branch-predictor side-channel).
Attacker measures response-time variance from the producer to
infer claim rate or hot outputs.

**My analysis.** Real microarchitectural side-channel; real
constraint; disproportionate to V3.0 threat model.

- **Constant-time `emit` is hard.** Lock-free queues have
  variable latency by design; bounding the variance requires
  either pre-allocating worst-case queue depth (memory cost)
  or padding with timing-noise (bounded-variance loop). Both
  add complexity without closing the side-channel completely.
- **Realistic exposure.** Producer-side `emit` timing variance
  contributes nanoseconds of jitter to per-block scan time.
  Block-level scan time has natural variance much larger than
  this (per-block ML-KEM-768 decapsulation cost dominates).
  Whether the attacker can extract signal from the noise floor
  is the question; the realistic answer is "probably not at
  V3.0's primary deployment threat model" (Tor/I2P-routed
  daemon connections add network jitter that swamps
  microarchitectural timing).
- **V3.x microarchitectural-side-channel hardening** is its
  own design surface — full mitigation requires constant-time
  emit, constant-time queue insertion, and likely scheduler
  isolation. None of this is cheap; V3.0's cost-benefit lands
  on "acknowledge as residual."

**Disposition: acknowledge-as-residual.** Land a new §5.4.8 #7
that names the emit-timing variance residual; Phase 1 emit
implementation should use a bounded-variance lock-free queue
(e.g., `crossbeam::queue::ArrayQueue` with pre-allocated
capacity) to bound the worst-case variance without claiming
constant-time. The residual is named so future microarchitectural-
side-channel hardening work can locate it; not a V3.0 mitigation
target.

**Inline edits applied.**

- §5.4.8 #7 (new) — emit-timing variance residual
  acknowledgment; Phase 1 implementation note pinning
  bounded-variance lock-free queue.

#### F9 — Projection-type audit per event class (Reviewer 2 A5)

**Reviewer 2's gap.** §5.4.8 #4 requires sanitized projections
for cross-boundary consumers but doesn't pin what "sanitized"
means for each event class. Does `ScanProgress { height,
candidates }` leak block-height timing? Yes — `height` is a
direct correlation between wallet activity and on-chain
timing; `candidates` is a wallet-fingerprint signal (how many
view-tag matches per block, distinctive across wallets).

**My analysis.** This is V3.0-relevant because
`TracingDiagnosticSink` ships in V3.0 and routes to
`tracing::event!`. What `TracingDiagnosticSink` logs is the
projection; if it logs the full `RefreshDiagnostic` `Debug`
impl, it leaks every field. The default implementation needs to
explicitly choose what fields to log per event class — not
"emit `Debug`-formatted everything."

**Per-class projection candidates (Phase 1 starting points; the
full projection definition lands in V3.x's diagnostic-stream
spec doc).**

- `DaemonMalformed { kind: MalformedKind }` — log `kind`
  variant tag only; no per-occurrence detail.
- `DaemonTimeout { op: DaemonOp, elapsed: Duration }` — log
  `op` variant tag and bucketed `elapsed` (sub-100ms /
  100ms-1s / >1s); not raw duration.
- `DaemonProtocolError { kind: ProtocolErrorKind }` — log
  `kind` variant tag only; the bounded enum already excludes
  `String` payloads per §5.4.7 R6 closure.
- `ReorgObserved { fork_height: u64, depth: u32 }` — log
  bucketed `depth` (1 / 2-10 / >10); no `fork_height`
  (correlates with chain timing).
- `ScanProgress { height: u64, candidates: usize }` — log
  bucketed `candidates` (none / few / many) with rate-limited
  emission; no `height` (correlates with wallet activity rate).

**Disposition: accept.** Land an addition to §6 review checklist
requiring per-class projection definition; defer full projection
formalization to V3.x diagnostic-stream spec doc; for V3.0,
`TracingDiagnosticSink` implements the per-class projections
above as the V3.0 default. FOLLOWUP entry for the V3.x spec
doc work covering the formalization.

**Inline edits applied.**

- §6 review checklist — projection-type audit item added per
  event class.
- §7.X C2 commit description — `TracingDiagnosticSink`
  implementation must implement per-class projections (not
  `Debug`-formatted everything); explicit projection-per-class
  enumeration lifted into the C2 description.
- FOLLOWUPS — V3.x entry: "Diagnostic-stream projection-type
  formalization in `DIAGNOSTIC_STREAM.md`" with trigger
  "first V3.x cross-boundary consumer beyond
  `TracingDiagnosticSink`."

#### F10 — Keep in-memory-only default for V3.0 (Reviewer 2)

**Disposition: covered by F1.** Reviewer 2's recommendation to
"keep the in-memory-only default for reputation and diagnostics;
do not relax it in V3.0 even based on demand" is the same
disposition F1's R17 hardening lands. F1's "no V3.x schedule
entry; conditional reopening only" preserves the in-memory-only
default as structurally final at V3.0; F10 requires no separate
action.

---

#### Meta-review amendment — F11–F13 (2026-05-15)

The F1–F9 dispositions themselves were reviewed against the
same adversarial discipline that surfaced them. The meta-review
asked: "do the F1–F9 dispositions create new attack surface, or
do they leave new under-specifications that would surface at
Phase 1 commit-authoring as substrate decisions rather than
mechanical translations?" Three findings (F11–F13) emerged.
Each targets an under-specification *introduced by* an F1–F9
disposition; none reopens a Round 1–4 substrate decision.

The amendment lands in the same review-pass section because the
findings are structurally meta-review of F1–F9, not a separate
review pass against a substrate that doesn't yet exist (the
post-F1–F9 substrate is exactly what the meta-review reviewed).
The discipline-application shape is per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
"audits-are-clean-so-compress" anti-pattern: the F1–F9 review
pass produced clean dispositions; the temptation is to declare
victory and proceed; the discipline is to ask whether the
dispositions themselves carry the property they claim before
the implementation cuts against them. F11–F13 is the answer to
that question, recorded as it is rather than left for Phase 1
commit-authoring to discover under time pressure.

#### F11 — Per-transaction cancellation safe-point pin (meta-review of F2)

**The under-specification.** F2's five-checkpoint discipline
pins *that* a per-transaction cancellation check fires inside
the per-block scan loop body (per §3.1 §2.3 / §7 / §7.X C4
post-F2 edits). It does *not* pin *where* in the per-transaction
body the check fires. The implementation is free to place the
check at any point inside the per-transaction iteration —
between view-tag pre-filter and hybrid-decap; between hybrid-
decap and key-image computation; at the iteration's tail —
and all placements satisfy the literal text of the F2 pin.

**Adversarial relevance (the load-bearing one).** The four-
checkpoint-to-five-checkpoint promotion exists because §3.1's
wallet-lock-latency property needs the per-transaction-bounded
spend-secret residency to hold under adversarial daemon block
crafting (per F2 disposition rationale). If the check fires
*mid-derivation* — between view-tag pre-filter and hybrid-decap
when the X25519 ephemeral and `ml_kem_dk` are loaded but the
hybrid-shared-secret hasn't been derived; between hybrid-decap
and key-image when the per-output derived secrets are on the
stack but key-image hasn't computed — the cancellation observes
the producer with secret material on the unwound stack frame.
Stack unwinding runs `Drop` impls (so `Zeroizing<…>` fires),
but during the brief window between observation and `Drop`
completion a memory-disclosure adversary (concurrent process
on the same OS; Spectre-style speculative-read; coredump
triggered by the cancellation handler; kernel-side memory
introspection) sees secrets that the safe-point-pinned firing
keeps off the unwound stack entirely. F2's lock-latency
property *implicitly* assumed safe-point firing; the meta-
review surfaces the assumption and elevates it to a binding
pin.

**Disposition: accept; pin the safe point at "between
transactions, before next-tx secret load."** The check fires
at the top of the per-transaction iteration, *after* the prior
iteration's `Zeroizing<…>`-wrapped per-output materials have
been dropped at the iteration's scope exit, *before* the next
iteration's view-tag / hybrid-decap / key-image derivation
begins. Mid-derivation firing is forbidden by the contract,
and the C7 `AssertionSink` / coherence-pair test substrate
gains a safe-point fixture that constructs an adversarial
cancellation token firing during a synthesized per-transaction
iteration and asserts the producer's stack-effect-trace
contains no partial-derivation state at the observed
cancellation point.

**Inline edits applied.**

- §3.1 §2.3 cancellation-checkpoint paragraph — checkpoint 5
  safe-point pin added (between transactions, before next-tx
  secret load; mid-derivation firing forbidden).
- §3.1 "Cancellation discipline preserved" bullet — refined
  the "single-transaction scan window" framing to specify
  that the window is measured between safe-point firings and
  that no per-output derived secret is resident on the stack
  at the moment cancellation is observed.
- §7.X C4 commit description — extended the "Inner
  cancellation check" bullet with the binding safe-point
  firing site, the implementation shape (check as first
  statement inside the per-transaction loop body, with
  iteration-local material declared after the check), the
  C7 safe-point fixture deliverable, and the explicit
  prohibition on mid-derivation firing.

#### F12 — Cross-emitter ordering contract-gap (meta-review of F4)

**The under-specification.** F4's seventh contract pin (per-
emitter FIFO ordering preserved; cross-emitter ordering
undefined) is enforced procedurally, not at the type system.
A V3.x consumer-actor author writes code that:

```rust
match (peer_rotation_event, malformed_event) {
    (Some(rot), Some(mal)) if rot.observed_at < mal.observed_at => { ... }
    _ => { ... }
}
```

— compiles cleanly, passes per-emitter FIFO tests (each event
arrived in its emitter's order), and silently misbehaves under
reordering at audit. The pattern is `mal` and `rot` come from
distinct emitters (a `RefreshDiagnostic`-emitting refresh task
and a `LedgerDiagnostic`-emitting ledger task, say); F4 says
their relative arrival order is undefined; the consumer's
branch implicitly assumes it isn't.

**Adversarial relevance.** The same attack class F4 documented
(adversary-influenced reordering shaping consumer-actor
conclusions) reaches the consumer via a different shape: not
through the sink itself relaxing the FIFO contract, but
through the consumer-actor author depending on a contract that
F4 explicitly disclaimed. F4's V3.0 disposition (procedural
enforcement; no V3.x consumer-actor exists in V3.0) holds for
V3.0 because no aggregator/republisher consumer ships in V3.0
and `TracingDiagnosticSink` doesn't branch on cross-event
timing. The exposure is V3.x consumer-actor authors who
re-derive the contract from the prose and miss the cross-
emitter half.

**Disposition: accept; close the gap at the discipline level
and at the V3.x lint level.** Two-part disposition:

1. **Discipline-level close (V3.0 binding).** The §5.4.6
   seventh contract pin gains an "enforcement gap and causal-
   context discipline" amendment naming explicitly that
   consumer actors needing cross-emitter ordering MUST derive
   it from explicit causal-context fields carried inside the
   events themselves (`SnapshotId` for ledger-rooted ordering,
   `ReservationId` plus per-reservation monotone version
   counters for reservation-rooted ordering, `BlockHeight`
   for chain-rooted ordering). Sink-observed arrival order is
   *not* a causal-context source under the contract.
2. **CI-lint scope-extension (V3.1+).** The FOLLOWUPS F5 entry
   (V3.1+ consumer-actor PR aggregator-republisher CI lint)
   is scope-extended to cover cross-emitter ordering misuse
   as a sub-scope of the same `diagnostic_consumer_discipline`
   lint. Detection shape: pattern-match on consumer-actor
   event-handler bodies that compare timestamps or use sink-
   observed arrival order across events whose emitter
   identity differs (statically-determinable from the event-
   class taxonomy plus the consumer's subscription set).
   The lint flags such patterns and requires either a
   causal-context field added to the relevant event class or
   explicit `#[allow(diagnostic_cross_emitter_ordering)]`
   with an inline rationale comment.

**Why discipline-level close in V3.0 rather than CI-lint
in V3.0.** No V3.0 consumer hits the cross-emitter case; the
lint pays back when the second consumer enters design rounds.
The discipline-level close in V3.0 establishes the contract
clearly so the V3.1+ lint has clean text to pattern-match
against, and so PR-1 of the consumer-actor era doesn't have
to re-derive the contract from F4's pre-amendment text.

**Inline edits applied.**

- §5.4.6 seventh contract pin — extended with "enforcement
  gap and causal-context discipline" amendment naming the
  procedural-vs-type-system gap, the binding requirement to
  use causal-context fields for cross-emitter ordering, and
  the cross-reference to the V3.1+ lint.
- §5.4.8 #4 V3.x forward-template — added item 4
  "Cross-emitter ordering misuse coverage" to the lint
  requirements, with detection shape and `#[allow(...)]`
  attribute pattern.
- `docs/FOLLOWUPS.md` F5 entry — rewritten as the unified
  `diagnostic_consumer_discipline` lint covering both the
  F5 sub-scope (recursive trust-boundary) and the F12
  sub-scope (cross-emitter ordering misuse), with the F12
  rationale and detection shape recorded.
- PR 5 §5.0.3 (carryover edit) — adds the parallel
  enforcement-gap amendment so the symmetric pin in PR 5
  carries the same binding discipline.

#### F13 — `SuppressedRateLimit` field-shape pin (meta-review of F6)

**The under-specification.** F6's `SuppressedRateLimit` variant
addition pinned the variant exists and that the producer emits
it once-per-class-per-attempt when the per-class budget is
exceeded. It did not pin *what fields the variant carries*. The
implementation is free to add `count: u32`, `first_suppressed_at:
Instant`, `last_suppressed_event: Box<RefreshDiagnostic>`, or
any other field, and all field shapes satisfy the literal text
of the F6 pin.

**Adversarial relevance.** Each candidate field carries
attacker-relevant signal:

- A **count** of suppressed events tells the attacker who
  triggered the rate-limit *exactly how many of their flood
  events the budget swallowed* — a covert channel back from
  the producer's internal state. The reputation actor's
  stateful decision ("ban this peer") needs *that the limit
  was hit*, not *how many events were suppressed*; the count
  is signal-free for the consumer's correctness obligation
  and is signal-rich for the attacker's reconnaissance.
- A **timestamp** or **timing field** carries the same
  attacker-reconnaissance shape as the count plus a side-
  channel into the producer's emission-loop scheduling.
- The **original event payload** that triggered suppression
  defeats the projection-type discipline (per F9) by carrying
  full-fidelity event content past the rate-limit boundary
  that was meant to suppress it.

**Disposition: accept; pin the variant carries `class:
SuppressedClass` only, no count, no timing, no payload.**
`SuppressedClass` is a project-defined `#[non_exhaustive]`
enum at the same crate-root scope as `RefreshDiagnostic` with
arms one-per-rate-limited event class (`SuppressedClass::DaemonMalformed`,
`SuppressedClass::DaemonTimeout`, `SuppressedClass::DaemonProtocolError`,
`SuppressedClass::ReorgObserved`, `SuppressedClass::ScanProgress`).
Future per-class additions to `RefreshDiagnostic` add a
matching arm to `SuppressedClass` under both enums'
`#[non_exhaustive]` attribute.

Consumer actors that need a count derive it from *the absence
of further events of the suppressed class within the same
attempt boundary*: the attempt-end signal (the
`produce_scan_result` future completing, observable from the
orchestrator side via `ScanResult` or `RefreshError`) plus
the `SuppressedRateLimit` notice tells the consumer "between
the notice and the attempt end, no further events of that
class were emitted by this producer." For finer-grained
rate-limit telemetry the project would add a separate
operator-only diagnostic surface (metrics, not
`DiagnosticSink`) with its own threat-model disposition; the
diagnostic stream is not that surface.

**Why a class enum and not a discriminant integer or string.**
A discriminant integer couples the projection contract to the
`RefreshDiagnostic` variant ordering (a new variant changes
older variants' discriminants under default Rust enum layout,
breaking consumer pattern-matches against the integer); a
string is a free-form attacker-influenceable surface that
contradicts §5.4.8 #4's projection-type discipline. A small
project-defined `SuppressedClass` enum is stable across
`RefreshDiagnostic`'s additive variant growth and is
constructively attacker-uninfluenceable.

**Inline edits applied.**

- §5.4.8 #5 — added "Field-shape pin (Round 4 review pass
  amendment, 2026-05-15; F13)" subsection naming the binding
  field shape (`class: SuppressedClass` only), the explicit
  prohibition on count / timestamp / original-payload fields
  with the attacker-reconnaissance rationale per field, the
  consumer-side derivation for absence-of-further-events
  count inference, and the rationale for the class enum
  shape over discriminant integers or strings.
- §7.X C2 commit description — extended the
  `SuppressedRateLimit` variant description with the
  `SuppressedClass` enum addition (Phase 0e Phase 1 enum
  addition; project-defined `#[non_exhaustive]` enum at the
  same crate-root scope; arms one-per-rate-limited event
  class). Updated the flat-crate-root re-export list from
  eight items to nine to include `SuppressedClass`.

---

#### Post-amendment sub-pins — F11-S, F12-S, F13-S (2026-05-15)

A post-amendment review of the F11–F13 dispositions surfaced
three Phase-1-author-aware observations: F13's field-shape pin
left an emission-cadence covert channel; F11's per-transaction
safe-point granularity may not hold under hostile-output-count
transactions; F12's "unified lint" likely decomposes to two
related checks at the implementation level. Each is a sub-pin
on the corresponding F-finding — sharpening the disposition
without reopening it. None reopens a Round 1–4 substrate
decision; none reopens an F1–F9 disposition; each lands inline
at the disposition's existing site rather than as a new finding
number.

The substantive one is **F13-S**. F11-S and F12-S are smaller —
F11-S is an implementation-discipline note Phase 1 commit-author
applies against benchmarked cost; F12-S is a forward-template
clarification preventing a future "the lint isn't monolithic"
finding from invalidating a multi-check implementation that
delivers the unified discipline.

##### F13-S — `SuppressedRateLimit` emission-cadence sub-pin

**The covert channel F13 didn't close.** The field-shape pin
closes the payload covert channel (no count, no timestamp, no
payload). The **emission-cadence covert channel** is independent:
if the producer emits one `SuppressedRateLimit { class: X }` per
suppression-fire, the attacker reconstructs suppression frequency
by counting notice arrivals in their own emit-arrival timeline —
even though each notice payload carries no information. The
class-only payload is signal-free; the emission cadence is the
side-channel.

**The attack path (worked example).**

- T=0    : Attacker triggers 100 events in class X within 1s.
- T=0.1s : Producer rate-limits; 95 events suppressed; emits one
  `SuppressedRateLimit { class: X }`.
- T=0.5s : Attacker triggers 200 more events in class X.
- T=0.6s : Producer rate-limits; 195 suppressed; emits another
  `SuppressedRateLimit { class: X }` (under a per-block or
  per-suppression-fire emission cadence).

The attacker's two-notice arrival timeline reveals attack
spacing, suppression frequency, and (with calibration runs)
even per-block ceiling values — recovering exactly the
information the field-shape pin's prohibition on count was
designed to deny.

**Disposition: pin emission cadence at "at most one per class
per attempt."** The producer's per-attempt `emit_state` carries
a per-class `notice_emitted: bool` flag (cleared at attempt
start, never cleared mid-attempt). When per-block ceiling is
first exceeded for a class within an attempt — *and only if*
`notice_emitted` is false for that class — the producer emits
the notice and sets `notice_emitted = true`. Subsequent
in-class budget exceedances within the same attempt drop the
would-be event (per the per-block ceiling rule) but **do not
emit further notices**. The flag is the latch that closes the
emission-cadence covert channel.

**Cross-attempt cadence (acknowledged residual at orchestrator
layer).** An attacker forcing many attempts via
`ConcurrentMutation`-driven retries observes one notice per
attempt per class, yielding *attempt-rate* as a residual side-
channel. This is bounded at the orchestrator's existing
retry-loop policy layer (per `engine/refresh.rs` retry semantics:
attempt count is capped, retry backoff is bounded). Tightening
the cross-attempt cadence further would require producer state
that survives across `produce_scan_result` invocations,
contradicting the per-attempt producer-state-isolation
property (`ViewMaterial` and `Scanner` are zeroized at attempt
end). The cross-attempt threat is therefore deliberately
addressed at the orchestrator-side retry-loop layer, not the
producer-side notice cadence layer; pin recorded so future
audit cannot mistake the layer-up disposition for an oversight.

**Inline edits applied.**

- §5.4.8 #5 — appended "Emission-cadence sub-pin (Round 4
  review pass meta-review post-amendment, 2026-05-15; F13
  sub-pin)" subsection naming the at-most-one-per-class-per-
  attempt latch discipline and the cross-attempt layer-up
  disposition.
- §7.X C4 commit description — restructured the per-class
  emission rate budget bullet to enumerate the per-attempt
  state shape explicitly (per-class per-block `u32` counter
  for ceiling check + per-class `notice_emitted: bool`
  latch for cadence pin); pinned the "subsequent budget
  exceedances drop events but do not emit further notices"
  invariant; cross-referenced §5.4.8 #5's emission-cadence
  sub-pin for the cross-attempt-cadence layer-up
  disposition.

##### F11-S — Per-output safe-point escalation criterion

**The hostile-output-count gap.** F11's per-transaction
safe-point closes the mid-derivation residency window for
typical transactions (1–10 outputs; per-tx scan time well
under the §3.1 millisecond-scale lock-latency target). For
hostile transactions carrying many outputs (FCMP++ permits
some upper bound; the exact bound is a Phase-1-author
verification target against the protocol parameters), the
per-transaction safe-point still leaves an N-output-derivation
residency window for spend-derived secrets. If
`recover_outputs_in_tx`'s per-output cost grows linearly with
output count, a maximum-output-count hostile transaction
extends per-tx scan time proportionally — the §3.1 lock-
latency property's content-independence (which the five-
checkpoint discipline was designed to deliver) becomes
content-dependent again.

**Disposition: pin the escalation criterion, defer the
measurement to Phase 1 commit-author.** Phase 1 commit author
has the visibility to assess this against actual benchmarked
cost on reference hardware and against the protocol-parameter
upper bound on outputs per transaction. The criterion is
binding: if worst-case per-tx scan time under maximum-output-
count hostile transactions exceeds the §3.1 millisecond-scale
lock-latency target, the safe-point escalates to per-output
granularity (check fires between consecutive per-output decap
iterations within the per-tx loop, with the same safe-point
semantics — after prior per-output material drops; before next
per-output material loads). Per-output granularity imposes
~1–3 ns × num_outputs per-tx cost (negligible against the
per-output decap cost itself). The §3.1 lock-latency
property's content-independence holds under either granularity
*provided the criterion is satisfied*.

**Why defer rather than escalate by default.** Per-output
granularity has a real readability cost (the inner check
sits inside two nested loops rather than one), and the
typical-case per-tx scan time is well under the lock-latency
target — the typical-case escalation is unnecessary. Phase 1
commit-author makes the call against benchmarked cost; the
choice is recorded in the C4 commit message and bisectable
against the C4 commit boundary. **Measurement evidence
landed.** The Phase 1 author's reference measurement (Linux
i9-11950H, `performance` governor, bench harness commit
`46c64760d`, 2026-05-20) lives durably at §7.Y. Worst-case
per-tx scan time at `N = MAX_OUTPUTS = 16` measures
12.95 ms cold p99 — exceeding the §3.1 millisecond-scale
target by ~13× — so the criterion is met and C4 lands the
per-output safe-point granularity.

**Inline edits applied.**

- §7.X C4 commit description — added "Per-output escalation
  criterion (F11 sub-pin amendment, 2026-05-15)" bullet
  enumerating the verification deliverable (FCMP++
  per-tx output upper bound; benchmarked
  `recover_outputs_in_tx` per-output cost), the binding
  disposition criterion (escalate to per-output if worst-case
  per-tx scan time exceeds §3.1 lock-latency target), and
  the audit-trail discipline (Phase 1 commit message
  records measurement and chosen granularity).

##### F12-S — `diagnostic_consumer_discipline` lint conceptual unification

**The implementation-strategy clarification.** F12's
unification of the F5 sub-scope (recursive trust-boundary;
sanitized-projection-required for cross-boundary consumers)
and the F12 sub-scope (cross-emitter ordering forbidden
without explicit causal-context derivation) is at the
contract level — one named discipline,
`diagnostic_consumer_discipline`, two related properties.
The implementation strategy follows each property's nature:
F5 is a type-level property (likely realized as a compile-
time trait-bound or `clippy` lint over consumer constructors);
F12 is a code-pattern property (likely realized as an AST-
level pattern-match over event-handler bodies comparing
timestamps or arrival order across distinct emitters). These
probably end up as two related checks under one configuration
namespace rather than one literal lint pass.

**Disposition: pin the conceptual-not-monolithic clarification
in the FOLLOWUPS entry.** The unification is at the contract
level (one named discipline, two related properties); the
implementation strategy follows the property's nature (one
type-level check + one AST-level check is a valid factoring
that delivers the unified contract). Pinned here so a future
"the lint doesn't exist as a single pass" finding cannot
retroactively invalidate a multi-check implementation.

**Why pin this now rather than at V3.1+ implementation time.**
The V3.1+ consumer-actor PR's lint-author needs the contract-
level intent clear at the moment they cut the implementation,
not after they've spent design rounds defending a multi-check
factoring against "the FOLLOWUPS entry says lint." Forecloses
the recurrence pattern named in
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
where a procedural-discipline pin gets read as an
implementation-architecture pin and forces the implementer
to re-litigate the factoring.

**Inline edits applied.**

- `docs/FOLLOWUPS.md` `diagnostic_consumer_discipline` lint
  entry — added "The lint is conceptual, not necessarily
  monolithic (Stage 1 PR 4 Round 4 review pass meta-review
  post-amendment, 2026-05-15; F12 sub-pin)" paragraph naming
  the contract-level vs implementation-level distinction
  and the two-checks-under-one-namespace factoring as a
  valid satisfaction of the unified discipline.

#### Considered and not elevated

Reviewer 1's "considered-and-not-elevated" list (view-tag-timing
side-channel; ConcurrentMutation retry-loop amplification;
PeerId stability under forced transport rotation; mailbox
saturation overflow-policy details; reorg-replay resource
exhaustion; supply-chain compromise of V3.x consumer actors;
memory dump while running; SnapshotId 128-bit truncation
collision) is validated as correctly classified — each item is
either Monero-family-inherited (AUDIT_SCOPE.md territory),
already-pinned in §5.4.8 #2 / #5, V3.x consumer-actor-PR
territory, platform-deployment territory, or a PR 5 disposition
that holds for its use case. None require Round 4 review-pass
disposition; Phase 1 inherits them in their current form.

#### Round 4 review pass closure

**F1–F9 close (initial review pass, 2026-05-15).** Nine
actionable findings, nine dispositions, all inline edits
applied to §3.1, §5.4.6, §5.4.8 (#1, #4, #5; new #6 / #7), §6,
§7, §7.X (C2 / C4 commit descriptions), and the parallel PR 5
sections (§5.0.3, §5.4 R17, status banner). FOLLOWUPS records
the V3.1+ entries for consumer-actor-PR aggregator-republisher
lint (F5) and diagnostic-stream projection-type formalization
(F9). CHANGELOG records the review pass under `[Unreleased]` /
`Changed`.

**F11–F13 close (meta-review amendment, 2026-05-15).** Three
additional findings on the F1–F9 disposition substrate, three
dispositions, all inline edits applied to §3.1 §2.3
cancellation-checkpoint paragraph, §3.1 "Cancellation
discipline preserved" bullet, §5.4.6 seventh contract pin
(F4 enforcement-gap amendment), §5.4.8 #4 V3.x forward-template
(item 4 cross-emitter sub-scope), §5.4.8 #5 (field-shape pin
subsection), §7.X C2 (SuppressedClass enum addition; nine-item
re-export list), §7.X C4 (safe-point firing site; C7 fixture
deliverable). FOLLOWUPS F5 entry rewritten as the unified
`diagnostic_consumer_discipline` lint covering both F5 and F12
sub-scopes. PR 5 §5.0.3 carryover edit lands the parallel F12
enforcement-gap amendment. CHANGELOG `[Unreleased]` / `Changed`
gains a meta-review amendment entry distinct from the F1–F9
close.

**F11-S / F12-S / F13-S close (post-amendment sub-pins,
2026-05-15).** Three Phase-1-author-aware sub-pins on the
F11–F13 dispositions, three sub-dispositions, all inline edits
applied to §5.4.8 #5 (F13-S emission-cadence sub-pin), §7.X C4
(F11-S per-output escalation criterion bullet; F13-S per-class
state shape and notice-emitted latch invariant), and FOLLOWUPS
`diagnostic_consumer_discipline` lint entry (F12-S
conceptual-not-monolithic clarification). F13-S is the
substantive sub-pin (closes the emission-cadence covert channel
the F13 field-shape pin left open); F11-S is an implementation-
discipline note Phase 1 commit-author applies against
benchmarked cost; F12-S is a forward-template clarification
preventing a future "the lint isn't monolithic" finding from
invalidating a multi-check implementation. CHANGELOG
`[Unreleased]` / `Changed` extends the meta-review amendment
entry with the three sub-pins.

**Round 4 closure rule (re-applied).** The review pass, the
meta-review amendment, and the post-amendment sub-pins are all
explicit reopening mechanisms the closure rule (PR 5 §7)
admits. None of F1–F13 nor F11-S–F13-S reopened a prior round
(Round 1 / 2 / 2 reframe / 3 dispositions all hold); F1–F9
dispositions land at Round 4's substrate level (contract pins,
attack-surface enumerations, commit-list refinements); F11–F13
dispositions land at the F1–F9 substrate level (under-
specification closures introduced by the F1–F9 disposition
shapes); F11-S–F13-S sub-pins land at the F11–F13 substrate
level (sharpening the dispositions without reopening them).
The recursive structure (review pass → meta-review →
post-amendment) is the closure rule's reopening mechanism
operating at each level; each level closes the wargaming
surface known at its own closure time and reopens explicitly
when a new shape surfaces. Round 4 re-closes here; the
implementation branch (`feat/stage-1-pr4-refresh-engine`)
cuts off the post-sub-pin dev tip per the §6 Round 4 readiness
gate (which the review-pass, meta-review, and post-amendment
dispositions re-confirm in their final state).

**Forward-template — review-pass discipline.** The Round 4
review pass is itself a forward-template artifact: per-engine
PR pre-flights for Phase 1 cuts of subsequent engines (PR 5,
the eventual `MempoolEngine` / `WalletEngine` extractions)
should ask "does the Round 4 substrate need a review pass
before Phase 1 cuts?" The review pass's value compounds with
the lens-applicability discipline (PR 5 §5.0.4) and the closure
rule (PR 5 §7) — together they form the discipline cluster
that makes per-engine PRs robust against late-surfacing
adversarial findings without re-opening rounds gratuitously.

---

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
| Trait-impl `apply_scan_result` `Vec<usize>`-discard (P3) | V3.0 (closed by Round 3 / Round 4 trait-surface enumeration) | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 (recorded on `dev` 2026-05-10 via PR #37 commit `0a0d46b38`; entry titled “P3: `apply_scan_result_to_state` allocates `Vec<usize>` even for trait-impl callers that discard it”). PR #37 reshaped the merge pipeline so `LedgerIndexes::ingest_block`, `process_scanned_outputs`, and `apply_scan_result_to_state` carry insertion-index ranges (`Range<usize>` and `Vec<usize>`); the two trait-impl call sites (`LocalLedger::apply_scan_result`, `EngineFixture::apply_scan_result`) currently discard the `Vec` to preserve `LedgerEngine::apply_scan_result`'s unit-result trait signature. PR 4's trait-surface enumeration (Round 3 / Round 4) decides between two shapes that both close P3: (a) `LedgerEngine::apply_scan_result` grows to surface the insertion-range carryout, in which case the `Vec` is consumed and the optimization is dead code; (b) `RefreshEngine` owns the merge post-pass directly and `LedgerEngine::apply_scan_result` is removed, in which case the discard sites disappear with the trait method. Under α (Round 1) plus the (a-instance-scoped) view-material disposition (Round 2 R4), both shapes remain candidates — the choice falls out of Round 3's trait-surface enumeration against the post-M3e tree |
| β internal-batching refinement | **closed (Round 2)** — kept as §2.2 future-scaling note; **not** promoted to FOLLOWUPS yet (avoids "FOLLOWUPS without a named trigger" graveyard per [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)); revisit if V3.0 RC stabilization bandwidth profiling identifies β as the remediation over alternatives (daemon-side prefix-matching, view-tag pre-filter improvements, wallet-side prune-by-birthday) | §2.2 (out-of-scope note) + §5.4.7 R2 |
| FMD (fuzzy message detection) — negative result for V3.0 | V4 research | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §4 |
| OMR (oblivious message retrieval) — negative result for V3.0 | V3.x research | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §5 |
| View-tag pre-filter (operational today) | already live | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §3 (cites [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) §3.1.1) |
| Refresh bandwidth tradeoff under α | V3.0 (RC stabilization) | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 (entry added in this commit) |
| Pruning-vocabulary disambiguation | reference | [`REFRESH_DESIGN_LANDSCAPE.md`](./REFRESH_DESIGN_LANDSCAPE.md) §7 sidebar |
| `PendingTxEngine::build` behaviour during long refresh (R1) | V3.0 (PR 5 design rounds) | §5.4.7 R1; carried into PR 5 with **build-against-current-snapshot + snapshot-ID pinning** as the working hypothesis |
| `RefreshOptions` / `RefreshProgress` public-module promotion (R3) | **closed (Round 2)** | §5.4.7 R3 — confirmation: types already publicly re-exported at flat crate root; no module promotion |
| View-material flow to the producer (R4) | **closed (Round 2)** | §5.4.7 R4 — disposition **(a-instance-scoped)**: `LocalRefresh::new(view_material: ViewMaterial)`; `ViewMaterial` type lands in Phase 0a |
| Mid-scan reorg-abort at checkpoint 3 (R5) | **retired by composition (Round 2 reframe)** | §5.4.7 R5 (reframe) — resolved by `ReorgAmplificationDetector` actor consuming `RefreshDiagnostic::ReorgObserved` events; producer's §7 checkpoint discipline does not grow; consumer-actor implementation deferred to V3.x actor-mesh PR. Supersedes Round 2's first-pass "defer + extend checkpoint 3" disposition |
| `RefreshError` shape (R6) | **reframed (Round 2 reframe) + close-out (2026-05-13)** | §5.4.7 R6 (reframe) — two-channel: unit-variant trait `RefreshError` (`Cancelled` / `Io` / `MalformedScanResult`; no payload) + `RefreshDiagnostic` event stream + `DiagnosticSink` trait. Orchestrator-side enum extends with `InternalInvariantViolation { context: &'static str }` per the Round 2 close-out (Phase 0c amendment) — separates state-machine invariant violation from retry-budget exhaustion (vs. conflating into `ConcurrentMutation`). Supersedes Round 2's first-pass `MalformedScanResult { reason: &'static str }` disposition; closes the memory-amplifier vector by construction; Round 4 cleanup target resolved at the design layer |
| `RefreshDiagnostic` + `DiagnosticSink` (Round 2 reframe; Phase 0e) | V3.0 (Phase 0e) | §5.4.7 R6 (reframe), §4 Phase 0e — enum + trait + `produce_scan_result` signature change; Stage 1 sinks: `NoopDiagnosticSink`, `TracingDiagnosticSink` |
| `DaemonOp` + `ProtocolErrorKind` initial variant sets (Round 2 close-out seeding, 2026-05-13) | V3.0 (Phase 0e seed; Round 4 audit confirms) | §4 Phase 0e — `DaemonOp` narrowed to `{ GetHeight, GetScannableBlockByNumber }` by call-site audit against `engine/refresh.rs` (producer issues exactly these two RPCs); `ProtocolErrorKind` fresh-defined (not a re-export — upstream `shekyl_rpc::RpcError` carries `String` payloads in 3/8 variants and is not bounded) and seeded against call-site-reachable upstream subset: `{ ConnectionError, InternalError, InvalidNode, InvalidTransaction, PrunedTransaction }`. `String` payload elision is the load-bearing producer-side classification step (per §5.4.7 R6 memory-amplifier closure). Round 4 commit-decomposition audit is authoritative |
| Diagnostic-stream attack surfaces (peer-reputation fingerprint; PeerId stability under Tor/I2P; rotation-timing side-channel; covert-channel; mailbox saturation) | V3.0 trait pin + V3.x consumer-side enforcement | §5.4.8 (Round 2 reframe) — mitigation pins land in Phase 0a / Phase 0e prose; consumer-side enforcement (in-memory-only reputation, jittered rotation, projection-only cross-boundary consumers, bounded mailboxes) lands in V3.x actor-mesh PR |
| `ReorgAmplificationDetector` consumer actor | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: when Stage 4 actor mesh stabilizes |
| `PeerReputationActor` consumer actor (fail2ban-style intra-session) | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: when Stage 4 actor mesh stabilizes; per §5.4.8 #1 mitigation pin (in-memory only, drop on wallet close) |
| `RecoveryActor` consumer actor (pattern-based recovery / Byzantine-fault-tolerance) | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: when Stage 4 actor mesh stabilizes |
| `RefreshDiagnostic` peer-attribution variant extension (gated by PR 1 `DaemonEngine` peer-aware surface) | V3.x | Stage 1 emits peer-less variants; the `RefreshDiagnostic` enum's `#[non_exhaustive]` attribute lets PR 1's peer-aware DaemonEngine surface land with additive variant additions per §5.4.8 #2 |
| `ScanResult` atomicity-under-cancellation contract (R7) | **closed (Round 2)** | §5.4.7 R7 — already true in `engine/refresh.rs`; pinned in §2.3 prose (Phase 0a) |
| Three call modes (cold open / steady-state / post-submit) — invocation-overhead constraint | V3.0 (Round 4 commit decomposition) | §5.4.4 — under (a-instance-scoped) the per-attempt scanner construction moves into `LocalRefresh::new`, satisfying the constraint by construction |
| Adversarial daemon scenarios under α (reorg amplification, view-tag DoS, withholding, snapshot poisoning, evidence amplifier) | mostly closed (Round 2); reorg amplification deferred via R5 | §5.4.5; mitigations: R5 (V3.x deferral), R6 keeps `&'static str` evidence (strictly bounded), Phase 0a `LedgerSnapshot` value-typed confirmation |
| Trait-surface contract pins (`Send + Sync + 'static` on `R`; Progress-channel trust boundary) | **closed (Round 2)** | §5.4.6; both pinned as Phase 0a prose amendments |
| `DiagnosticSink::emit` non-blocking + concurrent-emit clarification + emission/return coherence + canonical-reference-to-test (contract pins) | **closed (Round 2 reframe + contract-pin refinements)** | §5.4.6 / §5.4.7 R6; pinned in trait docstring and §5.4.6 prose; concurrent-emit clarification forecloses `Mutex<VecDeque<_>>`-class implementations; canonical-reference pin makes the Round 4 `AssertionSink` property test authoritative for coherence semantics per [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc) |
| Producer-panic-safety property (Round 4 `PanickingSink` test deliverable) | V3.0 (Round 4 / Phase 1 test design) | §5.4.6 (producer-side property; **not** a sink trait contract — pinning "MUST NOT panic" on `emit` is unenforceable and pushes burden onto sink authors for limited gain). Test wraps `LocalRefresh` with a `PanickingSink` variant; asserts `Scanner` zeroizes via `Drop`, cancellation token in well-defined fired-or-not state, unwind without corruption |
| (c) split-producer/recoverer view-material shape (R4 deferral) | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: HW-wallet-backed signing or post-V3 threat-model refinement requires producer-side spend-key isolation |
| `ViewMaterial` type definition (R4 — Phase 0a) | V3.0 (Round 4 / Phase 0a) | §5.4.7 R4 — public type in `shekyl_engine_core` carrying spend-pub + view-scalar + x25519-sk + ml-kem-dk + spend-secret; `Zeroize + ZeroizeOnDrop` |

The table is designed to be read row-by-row as the decision-trail
artifact for each refresh-adjacent item; reviewers landing PR 4's
implementation phase can confirm each item's resolution against
its named home rather than re-deriving the decomposition.

---

## §6 Review checklist (filled in Round 4)

Shape mirrors PR 5's §6 (binding-check matrix against the
`V3_ENGINE_TRAIT_BOUNDARIES.md` §2.3 spec, test-substrate
preservation list, call-site sweep audit, Round 4 readiness
gate). Round 4 closes here; Phase 1 implementation consumes
this checklist as the substrate deliverable for the §7.X
commit list.

**Binding-check matrix against the §2.3 spec (Round 4
finalization).**

- [x] Trait surface methods (`produce_scan_result`) —
  unchanged across Round 2 / Round 4 per §5.4.6's
  emission/return-coherence pin. The Phase 0a Round-2
  reframe added `diagnostics: &dyn DiagnosticSink` as a
  trait-method parameter (not a trait-level associated type
  or generic), so the trait method count stays at one and
  the Stage 4 actor topology inherits the parameter
  verbatim.
- [x] `Self::Error: Into<RefreshError>` trait-error
  bound — Phase 0c binding form pinned in Round 2 reframe
  (`RefreshError` is unit-variant-only at the trait surface;
  payload-bearing variants stay on the orchestrator-side
  enum). Round 4 audit confirms no payload-bearing trait
  return paths reachable from the Stage 1 producer body.
- [x] `RefreshError` enum surface (orchestrator-side) —
  Phase 0c binding form pinned in Round 2 close-out;
  `InternalInvariantViolation { context: &'static str }`
  variant added; the two retry-loop call sites
  ([`engine/refresh.rs:1672–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  and [`:2055–2065`](../../rust/shekyl-engine-core/src/engine/refresh.rs))
  migrate from `MalformedScanResult` in Phase 1 commit C5.
- [x] `ViewMaterial` type — Phase 0a binding form pinned
  in Round 2 (public `Zeroize + ZeroizeOnDrop` type carrying
  `{ spend_pub, view_scalar, x25519_sk, ml_kem_dk,
  spend_secret }`). Stage 4 actor implementors and any
  future `RefreshEngine` impl share the constructor shape.
- [x] `LocalRefresh::new(view_material: ViewMaterial)`
  constructor — Phase 0b binding form pinned in Round 2
  under §5.4.7 R4 (a-instance-scoped); flat-crate-root
  export under the existing
  [`lib.rs:25–30`](../../rust/shekyl-engine-core/src/lib.rs)
  re-export convention; `ViewMaterial` re-exports adjacent.
- [x] `RefreshDiagnostic` enum — Phase 0e binding form
  pinned in Round 2 reframe with the Round-4 audit
  refining the variant set (`DaemonOp` two-variant
  confirmed; `ProtocolErrorKind` five-variant
  refresh-reachable subset confirmed); `#[non_exhaustive]`
  on every enum to preserve additive growth without a
  binding-shape change.
- [x] `DiagnosticSink` trait — Phase 0e binding form
  pinned in Round 2 reframe follow-up (`Send + Sync +
  'static`; one `emit(&self, event: RefreshDiagnostic)`
  method); the §5.4.6 / §5.4.8 #4 in-process-only
  trust-boundary contract pin lands as part of the trait
  rustdoc.
- [x] `produce_scan_result` signature — `diagnostics:
  &dyn DiagnosticSink` parameter Phase 0e binding form;
  runtime-dispatch; per-call (no `LocalRefresh::new`
  widening); locked at Round 2 so Stage 4 does not re-rev
  the trait surface.
- [x] Stage 1 sink impls (`NoopDiagnosticSink`,
  `TracingDiagnosticSink`) — flat-crate-root export under
  the §5.4.7 R3 pattern; the production sink driving the
  actor mesh is V3.x's actor-mesh PR.
- [x] Contract pins (`Send + Sync + 'static` bound on
  `R: RefreshEngine`; progress-channel trust-boundary;
  `ScanResult` atomicity-under-cancellation; `LedgerSnapshot`
  value-typed) — all confirmed against current source per
  §4 Phase 0a. **Round 4 review pass (2026-05-15; F2)**
  promotes the cancel-checkpoint discipline from four to
  **five** to bound lock-latency content-independently under
  adversarial daemon block crafting. The four existing
  checkpoints at
  [`engine/refresh.rs:980 / :1140 / :1186`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  remain (checkpoints 1, 2, 3, 4); the new **checkpoint 5**
  (between transactions within a per-block scan loop) lands
  in Phase 1 commit C4 inside `LocalRefresh::produce_scan_result`.
  See §7 for the discipline statement.
- [x] Contract pins (Round 4 review pass additions, F3 + F4)
  — `AssertionSink` / `PanickingSink` pinned as **permanent
  CI regression coverage** per §5.4.6; **per-emitter FIFO
  ordering** pinned as the seventh `DiagnosticSink::emit`
  contract (per-emitter FIFO preserved; cross-emitter ordering
  undefined). Both pin Phase 0e docstring amendments on
  `DiagnosticSink::emit`; both confirmed in Round 4 review
  pass §5.4.9.
- [x] Contract pins (Round 4 review pass additions, F1, F6,
  F7) — drop-on-close persistence-rejection (F1) hardened at
  §5.4.8 #1; producer-side per-class emission rate budget (F6)
  added at §5.4.8 #5; encrypted-cache-for-RPC-recovery
  structural rejection (F7) added at §5.4.8 #6. All three
  confirmed in Round 4 review pass §5.4.9.
- [x] §5.0 actor-mesh framing inheritance — PR 4 produces
  the substrate (the producer trait surface, the diagnostic
  sink, the cancellation checkpoint split) that PR 5 Round 1
  consumed. PR 4's α-disposition holds under both the
  Round-1 synchronous framing and the Round-3 actor-mesh
  framing (the framing recasts but does not change the
  disposition; per Round 3 status banner).

**Test-substrate discipline — no-Mock substrate inheritance from
PR 3 §2.1.2 (Round 5 amendment, 2026-05-20).**

PR 4's test substrate is binding-pinned against the no-Mock
substrate pattern PR 3 §2.1.2 settled. PR 3 rejected the Mock-X
pattern as a category — not as a per-trait disposition — naming
five failure modes the pattern instantiates regardless of which
trait it's applied to:

1. **Adds attack surface.** Test-only types in production code;
 visibility-constraint dependencies; build-config edge cases
 that test paths exercise but production paths don't.
2. **Conflates test-controlled inputs to real implementations
 with test substitute implementations.** Different operational
 shapes that share the same `MockX` naming. A real
 implementation seeded with deterministic test inputs is
 structurally different from a fake of an implementation, and
 naming them both `MockX` hides the distinction.
3. **Inherits a Monero pattern that has produced real bugs in
 the inherited codebase.**
4. **Doesn't compose with future implementors** (HSM-backed,
 hardware-key, future remote-refresh implementors) — each
 implementor would need its own Mock variant, and tests
 verifying against fake semantics rather than real semantics
 multiply with the implementor count.
5. **Encourages tests to verify against fake semantics rather
 than real semantics.** The test suite's coverage claim
 degrades: "tested" means "tested against the Mock," not
 "tested against the production implementation."

The binding no-Mock substrate shape for PR 4:

- **Production-only `LocalRefresh`** for the success path
 (landed at C4). Tests that need the production producer
 body consume `LocalRefresh` directly; the
 [`engine/local_refresh.rs`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)
 `tests` module exercises real `Scanner`, real `TestDaemon`
 chain serving (`MockDaemon` pre-C6γ rename), real
 `apply_scan_result_to_state` merge body.
- **Composable `FaultInjecting<R: RefreshEngine>` wrapper**
 for failure injection. Defined once, composes against any
 `R` implementor (`FaultInjecting<LocalRefresh>` for V3.0;
 `FaultInjecting<FutureRemoteRefresh>` for later impls
 without re-writing the wrapper). The wrapper holds a
 `pub(crate)` failure queue; tests inject
 `RefreshError::Cancelled` / `RefreshError::Io` /
 `RefreshError::InternalInvariantViolation` via
 `queue_failure(...)` and run the engine against the wrapper.
- **Composable `FaultInjecting<L: LedgerEngine>` wrapper**
 for failure injection at the merge boundary (extracted
 from the current `MockLedger`'s `concurrent_mutation_queue`
 body per the FOLLOWUPS retroactive cleanup; current
 `MockLedger` is structurally already this wrapper).
 `LocalLedger::from_test_blocks(...)` constructor replaces
 the parallel-implementation `MockLedger::new(...)` test
 surface.
- **`TestDaemon` (rename of `MockDaemon`)** for the
 alternative-real-implementation case (per FOLLOWUPS line
 614). `TestDaemon`'s structural shape is already correct
 — real `DaemonClient` requires network connectivity, so
 the test substitute is a legitimate alternative real
 implementation serving canned / cached test responses
 without network. The `Mock` naming was the bug; the
 rename signals "alternative real implementation for tests"
 rather than "fake of an implementation."

The substrate decision is auditable against PR 3 §2.1.2's named
criteria, not against precedent. Future per-trait PRs (PR 5+)
inherit the same discipline via the PR 3 §2.1.5 four-pattern
pre-flight checklist; PR 4's substrate work is the first
post-PR-3 application of the discipline and the first retroactive
cleanup of pre-discipline `MockX` types under the
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
continuous-discipline framing.

### §6.1 Test-substrate paradigm pin (Round 5 sub-pin extension, 2026-05-20)

The C6 test-substrate is **composition-paradigm by design**.
`FaultInjecting<R: RefreshEngine>` is a wrapper type implementing
the same trait as its inner `R`, delegating with optional injection
at the trait boundary — canonical Decorator pattern / static
composition via generics, with no actor machinery, no message
passing, no mailboxes, no supervision.
`LocalLedger::from_test_blocks` is a constructor; the resulting
`LocalLedger` composes into wrappers via static generics.
`Engine::replace_refresh` is a pure type-system mechanism
(`&mut self` exclusive borrow, swap the inner `R` field). The
test-substrate stays composition-paradigm even when the
production substrate migrates to the Stage 4 `kameo`-based actor
mesh — the failure-injection seam is at the trait boundary,
which is the stable interface across both paradigms.

The seam between paradigms in PR 4 substrate:

- **Composition-paradigm surfaces.** The
  `RefreshEngine` / `LedgerEngine` / `KeyEngine` /
  `DaemonEngine` traits; the `Engine<S, D, L, R>`
  parameterized struct; the `FaultInjecting<R>` /
  `FaultInjecting<L>` wrappers; the
  `LocalLedger::from_test_blocks` constructor; the
  `Engine::replace_refresh` setter; the trait-dispatch path
  from the orchestrator into `R::produce_scan_result`.
- **Actor-paradigm surfaces.** The `RefreshDiagnostic`
  event stream emitted via `DiagnosticSink`; the
  `ReorgAmplificationDetector` / `PeerReputationActor` /
  `RecoveryActor` consumer actors (V3.x per §5.4.7 R5
  reframe / §5.4.8 #1 / §5.4.8 attack-surface dispositions);
  the Stage 4 `kameo`-based actor mesh wrapping the engines
  (planned, not yet landed — per §1.4 return-value discipline
  and §2.2 out-of-scope note).
- **Paradigm-coherent design property.** The composition
  trait surfaces are designed to admit Stage 4 actor wrapping
  without re-rev (per §1.4 return-value discipline). The trait
  surface stays stable; Stage 4 wraps each implementor in a
  `kameo` actor with a message-passing surface that delegates
  through the same trait method signatures. The
  composition-paradigm test substrate
  (`FaultInjecting<R>` / `LocalLedger::from_test_blocks`)
  keeps testing the trait boundary even after Stage 4 migration
  — actor-paradigm tests are a different scope (mailbox tests,
  supervision tests, message-ordering tests) that do not replace
  the trait-boundary tests.

**Why composition-paradigm for the test substrate specifically.**
The test substrate exists to verify trait-surface contract
behavior. The trait surface is stable across the composition →
actor migration; the actor surface is Stage-4-specific. Building
test substrate against the actor surface would mean building
substrate against a future contract that does not yet exist;
building against the trait surface means substrate that survives
both V3.0 (composition production) and Stage 4 (actor production)
without re-design.

**The four substantive F-Mock findings under the paradigm lens.**

- **F-Mock-1 (cfg-gating symmetry).** Composition-paradigm. The
  symmetry resolution (Option (a): all four C6 surfaces gated
  `#[cfg(any(test, feature = "test-helpers"))]`) is correct
  because the composition primitives (`FaultInjecting<R>` +
  `LocalLedger::from_test_blocks`) compose for external test
  consumers as a coherent test-helpers API surface.
- **F-Mock-2 (queue contract).** Composition-paradigm. FIFO
  ordering, drain inspection, `debug_assert!`-on-Drop, reentrance
  behavior — all properties of a synchronous wrapper type with
  internal queue state. The queue is **wrapper-internal state
  visible only through the wrapper's API**, not an actor mailbox.
  If this were actor-paradigm the queue would be the actor's
  mailbox and the contract would be about message ordering
  through the mailbox; the wrapper-on-trait disposition is
  structurally different and pinned here so the Stage 4
  migration author does not translate it incorrectly.
- **F-Mock-3 / F-Mock-3-sharpening (wrapper-API design +
  variant disambiguation).** Composition-paradigm. The wrapper-
  API choice is **Option (i)**: `type Error = RefreshError`;
  the queue holds `RefreshError` values directly, uniform across
  all `R` (the wrapper is R-agnostic at the injection surface;
  tests do not need to know which `R::Error` shape the
  underlying producer carries). Cross-wrapper symmetry justifies
  the choice: `FaultInjecting<L: LedgerEngine>` must queue
  `RefreshError` by trait necessity
  ([`engine/traits/ledger.rs:270–273`](../../rust/shekyl-engine-core/src/engine/traits/ledger.rs)
  — `apply_scan_result` returns `Result<(), RefreshError>` with
  no `Self::Error` indirection), so `FaultInjecting<R>` queuing
  `RefreshError` matches.

  **Trait-reachable vs. orchestrator-constructed variants
  (empirical per `engine/error.rs`, `engine/merge.rs`, and
  `engine/local_refresh.rs`).** Of the six `RefreshError`
  variants, three are reachable from a `RefreshEngine` impl's
  `Self::Error` (via `Self::Error: Into<RefreshError>`):
  `Cancelled` (unit), `Io(IoError)` (payload), and
  `InternalInvariantViolation { context: &'static str }`
  (payload, with `context` constructed at the `From` impl site).
  Three are orchestrator-constructed only:
  `MalformedScanResult { reason }` (constructed exclusively by
  the merge layer in
  [`engine/merge.rs:315–451`](../../rust/shekyl-engine-core/src/engine/merge.rs)
  when scan-result internal-shape invariants fail),
  `ConcurrentMutation { wallet, result }` (constructed at the
  merge gate), and `AlreadyRunning` (constructed at the
  binary-layer single-flight).

  **Direct injection vs. cause injection.** Under Option (i),
  `FaultInjecting<R>` can inject any `RefreshError` variant
  directly into the orchestrator-side surface. For
  trait-reachable variants this exercises the same code paths
  the production From conversion would reach; for
  orchestrator-constructed variants it lets tests exercise the
  orchestrator's handling logic without requiring the cause
  (e.g., test "orchestrator handles `MalformedScanResult` from
  the producer trait surface correctly" even though no V3.0
  `RefreshEngine` impl actually returns it — the wrapper bypass
  is a deliberate test affordance). For `InternalInvariantViolation`
  specifically, both paths are legitimate test classes:
  **direct injection** via `FaultInjecting<R>` exercises the
  producer-returned-then-orchestrator-propagated path
  (verifying the orchestrator propagates without retry);
  **cause injection** via the existing retry-loop construction
  sites in `engine/refresh.rs` exercises the orchestrator-side
  construction path (where the orchestrator's own control-flow
  reaches an unreachable branch). Cause injection for
  `ConcurrentMutation` happens through
  `FaultInjecting<LocalLedger>::queue_concurrent_mutation` per
  the F-Mock-2 wrapper API. The two patterns are siblings, not
  alternatives, and both translate cleanly to Stage 4
  actor-paradigm tests (drive causes through one actor's
  mailbox; observe effects from another) so the test
  substrate's discipline transfers without re-design.
- **F-Mock-4 (verification gate).** Paradigm-independent.
  Verified at the composition level against current source at
  [`engine/test_support.rs:773–812`](../../rust/shekyl-engine-core/src/engine/test_support.rs):
  `MockLedger::apply_scan_result` (line 792) pops from
  `concurrent_mutation_queue` (line 794) and otherwise delegates
  to the canonical `apply_scan_result_to_state` (line 810). The
  structural shape is already
  `FaultInjecting<LocalLedger>`-shaped; C6β extraction is
  mostly extraction-and-rename per Round 5 amendment.

#### §6.1.1 Two-enum architecture (RefreshEngine-specific positive pattern)

The `RefreshEngine` trait carries a deliberate two-enum
architecture that the C6 substrate inherits and tests against,
worth pinning explicitly as a positive architectural reference:

- **Producer-internal `LocalRefreshError`** —
  [`engine/local_refresh.rs:347`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs),
  `pub(crate)`, **unit-variant-only** by convention, four variants
  (`Cancelled`, `Io`, `Malformed`, `Internal`). The producer
  carries no payload material at its `Self::Error` boundary;
  internal context that distinguishes "the daemon failed" from
  "the scanner saw a malformed block" lives in the producer's
  body and gets diagnostic-stream emitted (`DaemonProtocolError`,
  `DaemonMalformed`) before the return; the `Self::Error` itself
  is structural-branch-signal-only.
- **Orchestrator-facing `RefreshError`** —
  [`engine/error.rs:148`](../../rust/shekyl-engine-core/src/engine/error.rs),
  `pub`, payload-bearing throughout (only `Cancelled` and
  `AlreadyRunning` are unit). Of the six variants, three are
  reachable from a `RefreshEngine` impl's `Self::Error` per
  §6.1's F-Mock-3 paragraph (`Cancelled`, `Io(IoError)`,
  `InternalInvariantViolation { context: &'static str }`);
  three are constructed by the orchestrator (`MalformedScanResult`
  by merge; `ConcurrentMutation` by merge gate; `AlreadyRunning`
  by binary-layer single-flight).
- **From impl boundary** —
  [`engine/local_refresh.rs:368–384`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs).
  Payload information is constructed or discarded at this
  boundary, not in the producer's body. `LocalRefreshError::Io`
  maps to `RefreshError::Io(IoError::Daemon { detail: "..." })`
  with the `detail` field a compile-time-fixed `String` literal;
  `LocalRefreshError::Malformed` maps to
  `RefreshError::Io(IoError::Scanner { detail: "..." })` with the
  same property; `LocalRefreshError::Internal` maps to
  `RefreshError::InternalInvariantViolation { context: "..." }`
  with `context` compile-time-fixed at the conversion site.
  The orchestrator-side payload guarantees (no attacker-influenced
  data; no memory-amplifier vector per §5.4.5 / §5.4.7 R6) are
  enforced at the type-system level at the conversion boundary,
  not by convention at each producer return site.

**Why this is a positive pattern.** The architectural cleanness
that the two-enum split delivers — payload guarantees enforced
by the type system at the conversion boundary, not by convention
at every producer return site — makes the trait surface auditable
in a way single-enum architectures cannot match. A reviewer
auditing the orchestrator's `RefreshError` handling reads one
enum with bounded compile-time-fixed payloads; a reviewer auditing
the producer's error vocabulary reads one enum with no payload
discipline to enforce. Both reviewer surfaces are minimal and the
discipline at the boundary is explicit.

**Forward-template for per-trait PRs.** Future per-trait PRs
(PR 5 `PendingTxEngine`, PR 6 `KeyEngine` per the
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
sequencing) adopt this shape when applicable: producer-internal
error enums are `pub(crate)` and unit-variant-only; trait-surface
error enums are `pub` and may carry payloads constrained to
compile-time-fixed types; `From` impls bridge them and construct
payloads at the boundary. The shape is not load-bearing for traits
whose canonical method signatures return `Result<_, OrchestratorError>`
directly (per the `LedgerEngine` precedent); it is load-bearing
for traits whose canonical method signatures return
`Result<_, Self::Error>` with `Self::Error: Into<OrchestratorError>`.
Per-trait PR pre-flight checks include "does this trait have an
impl-side `Self::Error` indirection, and if so, is the producer-
internal enum unit-variant-only?" as a substrate-application check
alongside the four-pattern no-Mock pre-flight per
PR 3 §2.1.5.

**Test-substrate implications.** Two test classes follow from the
two-enum architecture, both load-bearing for C6α's smoke-test
coverage (per F-Mock-8 sub-finding):

- **Class 1 — wrapper-based trait-surface tests.** Tests use
  `FaultInjecting<R: RefreshEngine>` to inject `RefreshError`
  values directly (per F-Mock-3 Option (i) wrapper design) and
  verify the orchestrator handles each variant correctly. This
  class lives in C6α's smoke-test surface against the wrapper
  itself plus the trait-dispatched `Engine` integration tests.
- **Class 2 — From-conversion tests against `LocalRefresh`.**
  Tests drive `LocalRefresh` directly via the `pub(crate)`
  producer-internal surface to produce each `LocalRefreshError`
  variant, then verify the `From<LocalRefreshError>` impl produces
  the correct `RefreshError` variant. This class lives in
  [`local_refresh.rs`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)'s
  existing tests module per the
  [`local_refresh_error_maps_to_refresh_error`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)
  test precedent — sibling to the wrapper test surface, not a
  replacement, because the wrapper bypasses the From conversion
  by injecting `RefreshError` directly at its trait boundary.

The C6 substrate as drafted handles Class 1 well via the
wrapper; Class 2 lives in `local_refresh.rs`'s test module and
is named here explicitly so the test-coverage story is complete
across both surfaces.

**Test-substrate preservation list (Round 4 enumeration; Round 5
substrate amendment, 2026-05-20; Round 5 sub-pin extension F-Mock
sharpening, 2026-05-20).**

- [x] `LocalRefresh::produce_scan_result` unit-test
  coverage — Phase 1 confirms test surfaces match the
  §2.3 trait-method signature additions
  (`diagnostics: &dyn DiagnosticSink` parameter);
  existing producer-body tests at
  [`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  port to the trait-dispatch shape with `NoopDiagnosticSink`
  as the default test sink.
- [x] **`FaultInjecting<R: RefreshEngine>` test substrate
  (Round 5 amendment; replaces the prior `MockRefresh` plan;
  Round 5 sub-pin extension F-Mock-3-sharpening).** Phase 1
  commit C6α introduces; `Engine::replace_refresh`
  test-only setter on `Engine<S, D, L, R>` gated behind
  `#[cfg(any(test, feature = "test-helpers"))]`. Per F-Mock-3
  Option (i) wrapper design (see §6.1 F-Mock-3 paragraph;
  §6.1.1 two-enum architecture pin) the wrapper carries
  `type Error = RefreshError` and queues `RefreshError` values
  directly, uniform across all `R`. Cross-wrapper symmetry with
  `FaultInjecting<L: LedgerEngine>` (which queues `RefreshError`
  by trait necessity per
  [`engine/traits/ledger.rs:270–273`](../../rust/shekyl-engine-core/src/engine/traits/ledger.rs))
  justifies the choice. The wrapper composes around `LocalRefresh`
  (the production producer body lives in
  [`engine/local_refresh.rs`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)),
  not as a parallel implementation. Class 1 wrapper-based tests
  inject `RefreshError` values directly into the orchestrator
  surface; Class 2 From-conversion tests live in
  `local_refresh.rs`'s existing tests module and exercise
  `LocalRefresh` directly against its `pub(crate)` producer
  surface per the
  [`local_refresh_error_maps_to_refresh_error`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)
  test precedent (per §6.1.1 Test-substrate implications). Per
  PR 3 §2.1.2's five-failure-mode rejection of the Mock-X
  pattern; see the no-Mock substrate inheritance discipline
  above for the binding rationale and §6.1 for the paradigm pin.
- [x] **`FaultInjecting<L: LedgerEngine>` test substrate +
  `LocalLedger::from_test_blocks(...)` constructor (Round 5
  amendment; retroactive Mock-X cleanup of `MockLedger` per
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)'s `MockLedger`
  cleanup entry; Round 5 sub-pin extension F-Mock-4 +
  F-Mock-5).**
  Phase 1 commit C6β introduces; extracts the existing
  `MockLedger::queue_concurrent_mutation` body — verified
  against current source at
  [`engine/test_support.rs:773–812`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
  (`impl LedgerEngine for MockLedger`):
  `apply_scan_result` (line 792) pops from
  `concurrent_mutation_queue` (line 794); on empty-queue,
  delegates to the canonical `apply_scan_result_to_state`
  (line 810); the structural shape is already
  `FaultInjecting<LocalLedger>`-shaped per F-Mock-4 — into
  the composable wrapper at
  `rust/shekyl-engine-core/src/engine/fault_injecting_ledger.rs`,
  same `#[cfg(any(test, feature = "test-helpers"))]` gating
  as `FaultInjecting<R: RefreshEngine>` per F-Mock-1 symmetry.
  Adds `LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`
  (deterministic test-block fixtures, gated
  `#[cfg(any(test, feature = "test-helpers"))]` per F-Mock-1
  symmetry). C6β migration table maps `MockLedger`'s four
  public-test-affordance methods to their post-migration homes:

  | `MockLedger` method (current) | Post-C6β home |
  | --- | --- |
  | `with_seed(seed: [u8; 32]) -> Self` ([`test_support.rs:695`](../../rust/shekyl-engine-core/src/engine/test_support.rs)) | `LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self` constructs against a deterministic block vector. Callers that previously used `with_seed` to seed an empty-chain test build `Vec::new()`; callers seeding a chain pass the existing block vector |
  | `with_seed_and_state(seed: [u8; 32], blocks: Vec<ScannableBlock>) -> Self` ([`test_support.rs:707`](../../rust/shekyl-engine-core/src/engine/test_support.rs)) | `LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self` — the `seed` field was used for `WalletLedger` cosmetic state and is not load-bearing for `LedgerEngine` merge tests; callers migrate to passing the chain only |
  | `queue_concurrent_mutation(&self)` ([`test_support.rs:733`](../../rust/shekyl-engine-core/src/engine/test_support.rs)) | `FaultInjecting<LocalLedger>::queue_concurrent_mutation()` (preserves the method name; identical semantics) |
  | `queued_failures(&self) -> usize` ([`test_support.rs:745`](../../rust/shekyl-engine-core/src/engine/test_support.rs)) | `FaultInjecting<LocalLedger>::queued_failures() -> usize` (the wrapper's queue-drain inspector — `MockLedger`'s existing implementation is the F-Mock-2 queue-contract precedent the wrapper formalizes) |

  Rewires `test_support.rs` callers and all per-test
  instantiations. The cleanup is mostly extraction-and-rename
  — current `MockLedger` already runs the canonical
  `apply_scan_result_to_state` merge body, so the structural
  shape is already the wrapper-not-parallel-implementation
  shape per PR 3 §2.1.2 (verified against current source per
  F-Mock-4). C6β closes the FOLLOWUPS entry; per F-Mock-7 the
  `test-helpers` feature is introduced as part of C6α's
  scope so the gating composes at C6β.
- [x] **`TestDaemon` rename of `MockDaemon` (Round 5
  amendment; retroactive Mock-X cleanup per
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)'s `MockDaemon`
  cleanup entry; Round 5 sub-pin extension F-Mock-6).**
  Phase 1 commit C6γ introduces; mechanical rename of the
  `MockDaemon` type and all callers in
  [`engine/test_support.rs`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
  and tests. The structural shape is unchanged — `MockDaemon`
  is already an alternative real implementation that serves
  canned / cached test responses without network connectivity;
  the rename signals that shape correctly. **Phase 1 author
  commit-message-template addition (F-Mock-6).** The C6γ
  commit message enumerates the test affordances `MockDaemon`
  carries that survive the rename unchanged
  (`with_seed` / `with_seed_and_chain` / `push_block` /
  `replace_chain_from` / `set_daemon_height` /
  `set_height_error_for_next_n_calls` /
  `inject_block_fetch_failure` / `set_block_returns_malformed`
  / `chain_len` / `set_fee_estimates` /
  `inject_submit_failure` / `inject_fee_failure` /
  `submitted_count` per
  [`engine/test_support.rs:318–490`](../../rust/shekyl-engine-core/src/engine/test_support.rs)),
  documenting the semantic shift "fake of an implementation" →
  "alternative real implementation for tests" at the
  doc-trail level so the rename's intent is preserved in
  the commit-message archive. C6γ closes the FOLLOWUPS entry.
- [x] `AssertionSink` (test substrate; coherence property
  test) — Phase 1 commit C7 introduces per §5.4.6 emission/
  return-coherence canonical-reference pin. The sink
  records every `emit` call in-order; the property test
  asserts `produce_scan_result`'s return discriminant
  matches the recorded sink stream's terminal event class.
  Coherence-test authority pinned per §5.4.6: prose / test
  drift on the coherence contract resolves against the
  test, not against the prose.
- [x] `PanickingSink` (test substrate; producer-panic-safety
  test) — Phase 1 commit C7 introduces per §5.4.6
  producer-panic-safety pin. The sink panics on `emit`;
  the property test verifies producer-side robustness:
  `Scanner` zeroization completes, cancellation-token
  consistency holds, the panic unwinds to the call boundary
  without corrupting `LocalRefresh` interior state.
- [x] Stage 4 `RefreshActor` migration test fixtures —
  not introduced in PR 4; deferred to Stage 4 actor-
  migration PR per §1.4 return-value discipline. PR 4's
  trait surface admits the Stage 4 actor without re-rev.
- [x] Hybrid retry test (mirrors PR 2's
  `hybrid_apply_scan_result_retries_on_concurrent_mutation`)
  — Phase 1 commit C7 introduces a `RefreshEngine`-side
  hybrid that exercises the producer/orchestrator
  cancellation-checkpoint split (checkpoints 2/3 in the
  trait body; checkpoints 1/4 in the orchestrator) and the
  retry-loop's `ConcurrentMutation` retry path against
  `FaultInjecting<LocalLedger>`-injected mutations
  (Round 5 amendment; replaces the prior
  `MockRefresh`-injected reference). The engine instance
  under test is `Engine<SoloSigner, TestDaemon,
  FaultInjecting<LocalLedger>, FaultInjecting<LocalRefresh>>`
  — all production implementors, all failure injection via
  composable wrappers, no parallel-implementation Mocks.

**Call-site sweep audit (Round 4 enumeration; Phase 1
performs the migration).**

- [x] `RefreshDiagnostic::DaemonMalformed` emission point
  — at the producer's malformed-block detection sites in
  `LocalRefresh::produce_scan_result`'s body; current
  C++ / Rust scanning loop locations need confirmation
  during Phase 1 migration. Round 4 audit identifies
  the `MalformedKind` variants as a Round-1-finalization
  candidate (the Round 2 close-out seeded the `DaemonOp`
  and `ProtocolErrorKind` variant sets but left
  `MalformedKind` as Phase-1-confirmed).
- [x] `RefreshDiagnostic::DaemonTimeout` emission point
  — at the daemon-RPC-timeout detection sites; the
  `op: DaemonOp` field is one of the two confirmed
  variants (`GetHeight`, `GetScannableBlockByNumber`);
  `elapsed: Duration` carries the per-RPC timeout
  observation.
- [x] `RefreshDiagnostic::DaemonProtocolError` emission
  point — at the producer's `RpcError`-classification
  boundary inside `LocalRefresh::produce_scan_result`.
  Phase 1 commit C6 implements the classification (the
  `String` payload is **not** propagated; the bounded
  `ProtocolErrorKind` enum is constructed from the
  `RpcError` variant tag alone, per §5.4.7 R6
  memory-amplifier-vector closure).
- [x] `RefreshDiagnostic::ReorgObserved` emission point
  — at the post-tip-fetch fork-detection site (the
  `fork_height: u64`, `depth: u32` fields are derived
  from the existing fork-detection invariants); the
  `ReorgAmplificationDetector` consumer (V3.x; per
  §5.4.7 R5 reframe disposition) consumes these events.
- [x] `RefreshDiagnostic::ScanProgress` emission point
  — at the per-block scan-progress observation site
  (the `height: u64`, `candidates: usize` fields are
  derived from the existing `Scanner` per-block output);
  drives any future `WalletProgress`-style consumer (R6
  reframe diagnostic-stream spec doc territory).
- [x] No emission paths bypass the sink — every
  producer-side observable event has an emit at the
  call site per §5.4.6 emission/return-coherence
  contract; `AssertionSink`-driven property test (Phase 1
  commit C8) is the canonical reference for the
  contract.
- [x] Retry-loop-exhaustion sites
  ([`engine/refresh.rs:1672–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  and [`:2055–2065`](../../rust/shekyl-engine-core/src/engine/refresh.rs))
  — migrate from `MalformedScanResult { reason: "..." }`
  to `InternalInvariantViolation { context: "..." }` per
  Round 2 close-out Phase 0c amendment; the existing reason
  strings become the `context` values directly. Phase 1
  commit C5 lands the migration.

**PR 5 input bundle (Round 4 final form; resolved as
confirmation per Round 3 §8 fenceposts).** PR 5 Round 1's
disposition under the actor-mesh framing (per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.0 / §5.2 / §5.5) consumed PR 4's α as a confirmed input;
PR 4 Round 4 produces no further design-doc revisions for
PR 5's consumption. The Phase 1 implementation work below
lands the substrate PR 5's eventual Phase 1 cuts against
(the `RefreshDiagnostic` enum's contract is the template
PR 5's `PendingTxDiagnostic` follows; the `DiagnosticSink`
trait is the substrate PR 5's per-engine sink composes into
the diagnostic-stream spec doc per §5.4.7 R6 reframe and
PR 5 R17 closure).

**Projection-type audit per event class (Round 4 review pass,
2026-05-15; F9).** Every cross-boundary `RefreshDiagnostic`
consumer MUST define an explicit projection type per event
class, sanitized for the consumer's external surface. The
audit is binding on V3.0 because `TracingDiagnosticSink` ships
as a V3.0 cross-boundary consumer (routes to `tracing::event!`,
which is a trust-boundary-relevant logging surface). Default
`Debug`-formatted emission is **not acceptable** — `Debug`
leaks every field including those whose presence in
cross-boundary logs is a wallet-fingerprint or
on-chain-correlation signal.

**V3.0 per-class projections (Phase 1 commit C2 deliverables).**
`TracingDiagnosticSink` implements the following per-class
projections in its `emit` method; the projections are documented
inline next to each variant's definition.

- [x] **`DaemonMalformed { kind }`** — log `kind` variant
  tag only.
- [x] **`DaemonTimeout { op, elapsed }`** — log `op` variant
  tag and bucketed `elapsed` (`<100ms` / `100ms-1s` / `>1s`);
  not the raw duration.
- [x] **`DaemonProtocolError { kind }`** — log `kind`
  variant tag only (the bounded enum already excludes
  `String` payloads per §5.4.7 R6 closure).
- [x] **`ReorgObserved { fork_height, depth }`** — log
  bucketed `depth` (`1` / `2-10` / `>10`); **not**
  `fork_height` (correlates with chain timing).
- [x] **`ScanProgress { height, candidates }`** — log
  bucketed `candidates` (`none` / `few` / `many`); **not**
  `height` (correlates with wallet activity rate);
  rate-limited per §5.4.8 #5 producer-side budget.
- [x] **`SuppressedRateLimit { class }`** — log `class`
  variant tag only (the variant exists to signal
  rate-limited suppression; logging it requires no
  sanitization).

**FOLLOWUP for V3.x diagnostic-stream spec doc.** The
formalization of per-class projection types lifts to the
`docs/design/DIAGNOSTIC_STREAM.md` spec doc when it cuts
(per PR 5 §5.0.3 segment-2g closure). V3.x cross-boundary
consumers beyond `TracingDiagnosticSink` (analytics actors,
metrics-export actors) inherit the spec doc's per-class
projection definitions; the V3.0 `TracingDiagnosticSink`
implementations seed the spec doc's content.

**Round 4 readiness gate (Phase 1 cut authorization).** All
§4 Phase 0 candidates are binding-pinned at the type-signature
level (0a–0e, with 0d struck); §6 review checklist is filled
(this section); §7.X Phase 1 commit list is sequenced (eight
commits, load-bearing-ordered); §8 fenceposts close the
five "Remaining for Round 4" items; **Round 4 review pass
(§5.4.9) closed with nine findings dispositioned and inline
edits applied**. The implementation branch
(`feat/stage-1-pr4-refresh-engine`) cuts off the
post-Round-4-review-pass dev tip; no further Round-N design
rounds open unless the Phase 1 commit-authoring surfaces a
structural finding (the Phase 0 binding-pin discipline plus
the review-pass discipline together prevent that; the Round 4
audit confirms the pre-condition; the review pass extends the
substrate to cover the late-surfacing adversarial findings).
Phase 1 implementation is authorized to proceed against this
checklist as the binding substrate.

---

## §7 Discipline budget

This seed counts as Round 1 of the design rounds. Subsequent
revisions land round-by-round inline (the PR 3 precedent).

**Original estimate (Round 1 seed):** 3–4 rounds before Phase 0
spec amendments land; 1–2 rounds during Phase 0 review; Phase 1
implementation rounds depend on commit count.

**Round trajectory at Round 4 close (2026-05-14) and Round 4
review pass close (2026-05-15).** Seven rounds elapsed: Round 1,
the Round 1 review pass, Round 2, the Round 2 reframe and
follow-up and close-out, Round 3 confirmation, Round 4 commit
decomposition, and the Round 4 review pass. The seed's
"3–4 rounds" estimate held to within one round on the Phase 0
surface plus two adversarial review passes (Round 1 review
pass and Round 4 review pass). The Round 2 reframe expanded
scope by introducing the diagnostic-stream substrate (Phase 0e),
which is the round most adjacent to the seed's slack. Round 3
was a confirmation pass triggered by PR 5 Round 1's actor-mesh-
framing closure (the *provisionally-load-bearing* qualifier on
Round 1's α-disposition collapsed without firing the
re-evaluation gate); Round 4 is the mechanical
commit-decomposition round per the PR 1 / PR 2 / PR 3 / PR 5
precedent; **Round 4 review pass (2026-05-15) is the
adversarial review of the post-Round-4 substrate before Phase 1
cuts** (per §5.4.9: nine findings dispositioned with inline
edits applied across §3.1, §5.4.6, §5.4.8 #1 / #4 / #5 plus new
§5.4.8 #6 / #7, §6, §7, §7.X, and the parallel PR 5 sections).

The review pass shape is itself a forward-template artifact:
per-engine PR pre-flights for subsequent engines (PR 5's
Phase 1 cut, eventual `MempoolEngine` / `WalletEngine`
extractions) should ask "does the Round-N substrate need a
review pass before Phase 1 cuts?" The review pass's value
compounds with the lens-applicability discipline (PR 5 §5.0.4)
and the closure rule (PR 5 §7) — together they form the
discipline cluster that makes per-engine PRs robust against
late-surfacing adversarial findings without re-opening rounds
gratuitously.

The user's 2026-05-10 sequencing decision allocates the rounds
budget to the migration tail — M3c–M3e finish their landings
*before* PR 4's design rounds consume the human reviewer's
attention budget. PR 4's design discussion happens in writing
(this document) during the migration-tail window; live design
rounds resume after M3e closes. The closure rule (per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§7) applies symmetrically: each round closes when the wargaming
surface known at closure time is genuinely exhausted; new shapes
surfacing later reopen the corresponding round explicitly. PR 4's
Round 1 → Round 3 trajectory (the *provisionally-load-bearing*
qualifier closing in Round 3 rather than reopening Round 1) is
the closure rule's working — the qualifier was the explicit
reopening mechanism, exercised by PR 5 Round 1's confirmation
disposition.

---

## §7.X Phase 1 commit decomposition (Round 4 deliverable)

Per the PR 1 / PR 2 / PR 3 / PR 5 precedent, Round 4 produces
the Phase 1 commit list as the substrate the implementation
branch (`feat/stage-1-pr4-refresh-engine`) cuts against. The
commits are **load-bearing-ordered** — each commit's preconditions
are the cumulative state of the prior commits; bisection
isolates each behaviour change to one commit boundary.

The commit list assumes the implementation branch cuts off the
post-Round-4 dev tip (post-PR-#36, post-PR-#34, post-PR-#35,
post-PR-#43; the design branch's lifetime ends at Round 4
close). PR 4 implementation lands as **eight commits**; the
PR opens after C8 lands locally with a passing CI run.

**Commit C0 — Phase 0 spec amendment (doc-only, prerequisite).**

Updates [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.3 to land the Phase 0a binding-pinned trait surface:

- `produce_scan_result` signature gains
  `diagnostics: &dyn DiagnosticSink` parameter.
- `Self::Error: Into<RefreshError>` trait-error bound named
  with the unit-variant trait-surface discipline (Phase 0c).
- `Send + Sync + 'static` bound on `R: RefreshEngine` pinned
  in §2.3 prose per §5.4.6.
- `LedgerSnapshot` value-typed contract pin per §5.4.5.
- `ScanResult` atomicity-under-cancellation contract per R7.
- `ViewMaterial` type pin (§5.4.7 R4 a-instance-scoped)
  documented in §2.3's adjacent-types prose.

C0 is **doc-only**; no Rust code changes; CI runs the
markdownlint gate but no compile gate. C0 lands on a
short-lived branch off `dev` and merges before C1 begins to
land the implementation surface against the amended spec.
C0's commit message references this design doc's §4 Phase 0a
binding-pinned form as the substrate.

**Landed: `322677261`** on `dev` (2026-05-15;
`docs: amend §2.3 RefreshEngine + sweep §7 four→five
checkpoints`).

**Commit C1 — `RefreshEngine` trait declaration + `ViewMaterial`
type.**

Introduces the Phase 0a trait surface and the Phase 0a
`ViewMaterial` type:

- `pub(crate) trait RefreshEngine` in
  `rust/shekyl-engine-core/src/engine/traits/refresh.rs` with
  the §2.3 surface (one async method, five-checkpoint
  cancellation discipline per §7 (promoted from four by
  Round 4 review pass F2 — see §5.4.9 F2),
  `Self::Error: Into<RefreshError>` bound;
  `&dyn DiagnosticSink` parameter).
- `pub struct ViewMaterial` in
  `rust/shekyl-engine-core/src/engine/view_material.rs` with
  `Zeroize + ZeroizeOnDrop` derived; the five fields
  (`spend_pub: EdwardsPoint`, `view_scalar: Zeroizing<Scalar>`,
  `x25519_sk: Zeroizing<[u8; 32]>`,
  `ml_kem_dk: Zeroizing<Vec<u8>>`,
  `spend_secret: Zeroizing<[u8; 32]>`); module-level rustdoc
  cross-references this design doc §3.1 for the threat-model
  framing.
- `traits/mod.rs` re-exports `RefreshEngine`; `lib.rs`
  re-exports `ViewMaterial` flat at the crate root per the
  R3 pattern.

C1 introduces no implementing aggregate yet; the trait sits
unconsumed until C4 wires it into `Engine`. CI compiles the
new trait against the existing crate but does not exercise
it.

**Landed: `d3edc1abb`** (`refresh: introduce RefreshEngine
trait + ViewMaterial type (PR 4 C1)`).

**Commit C2 — `RefreshDiagnostic` enum + `DiagnosticSink`
trait + Stage 1 sink impls.**

Lands the Phase 0e diagnostic-stream substrate:

- `pub enum RefreshDiagnostic` in
  `rust/shekyl-engine-core/src/engine/diagnostics.rs` with
  the Round-4-audit-confirmed variant set (`DaemonMalformed`,
  `DaemonTimeout`, `DaemonProtocolError`, `ReorgObserved`,
  `ScanProgress`); the supporting bounded enums (`MalformedKind`,
  `DaemonOp`, `ProtocolErrorKind`); all `#[non_exhaustive]`.
- `pub trait DiagnosticSink` adjacent to the enum with
  `Send + Sync + 'static` bound and one `emit(&self, event:
  RefreshDiagnostic)` method; the §5.4.6 / §5.4.8 #4
  in-process-only trust-boundary contract pin in trait
  rustdoc.
- `pub struct NoopDiagnosticSink` and
  `pub struct TracingDiagnosticSink` (Stage 1 sink impls);
  `TracingDiagnosticSink` routes to `tracing::event!` at
  `Level::INFO` per the §5.4.7 R6 reframe disposition.
- Flat-crate-root re-exports of all nine public items
  (`RefreshDiagnostic`, `DiagnosticSink`, `MalformedKind`,
  `DaemonOp`, `ProtocolErrorKind`, `SuppressedClass`,
  `NoopDiagnosticSink`, `TracingDiagnosticSink`, plus the
  `SuppressedRateLimit` variant on `RefreshDiagnostic` itself).
- **Per-class projections in `TracingDiagnosticSink::emit`
  (Round 4 review pass, 2026-05-15; F9).**
  `TracingDiagnosticSink` does **not** route the full
  `RefreshDiagnostic` `Debug` impl to `tracing::event!`; it
  routes the per-class projections enumerated in §6's
  projection-type-audit subsection (variant tag only for
  `DaemonMalformed` / `DaemonProtocolError` /
  `SuppressedRateLimit`; bucketed `elapsed` for
  `DaemonTimeout`; bucketed `depth` for `ReorgObserved`;
  bucketed `candidates` for `ScanProgress` with `height`
  elided). The projection per variant is documented inline
  next to the variant's `emit` arm.
- **`SuppressedRateLimit { class: SuppressedClass }` variant
  added to `RefreshDiagnostic` (Round 4 review pass,
  2026-05-15; F6; field-shape pinned by F13 amendment,
  2026-05-15).** The producer emits this variant once per
  attempt per event class when the per-class emission budget
  is exceeded (per §5.4.8 #5); consumers interpret it as
  "the producer hit the rate limit on this class" and make
  stateful decisions accordingly. **`SuppressedClass`
  enum (Phase 0e Phase 1 enum addition).** Project-defined
  `#[non_exhaustive]` enum at the same crate-root scope as
  `RefreshDiagnostic` with arms one-per-rate-limited event
  class (`SuppressedClass::DaemonMalformed`,
  `SuppressedClass::DaemonTimeout`,
  `SuppressedClass::DaemonProtocolError`,
  `SuppressedClass::ReorgObserved`,
  `SuppressedClass::ScanProgress`). The variant carries
  *only* `class: SuppressedClass` — no count, no timing
  field, no original-event payload — per §5.4.8 #5's F13
  field-shape pin (preventing the suppressed-event count
  from becoming an attacker covert channel back from the
  producer's internal state). Future per-class additions
  to `RefreshDiagnostic` add a matching arm to
  `SuppressedClass` under both enums' `#[non_exhaustive]`
  attribute.

C2 introduces no production consumers yet; the substrate
sits ready for C4 to wire `produce_scan_result` against it.

**Landed: `8fc207051`** (`refresh: populate RefreshDiagnostic
+ DiagnosticSink + Stage 1 sinks (PR 4 C2)`).

**Commit C3 — `RefreshError::InternalInvariantViolation`
variant addition.**

Lands the Phase 0c orchestrator-side variant addition:

- `RefreshError::InternalInvariantViolation { context:
  &'static str }` added to the enum at
  `rust/shekyl-engine-core/src/engine/refresh.rs` (or the
  `RefreshError` definition site).
- Variant is introduced **without call-site migration** —
  C5 lands the migration. C3 keeps the change minimal so
  the variant addition is bisectable independently of the
  call-site migration.
- Doc-comment on the variant cross-references this design
  doc §4 Phase 0c "Why `InternalInvariantViolation` is its
  own variant" prose for the rationale.

CI compiles the enum; existing `RefreshError`-matching code
needs `_ => ...` arms or explicit `InternalInvariantViolation`
arms. The match-arm exhaustiveness pass is part of C3's
mechanical scope.

**Landed: `c45894ffe`** (`refresh: add
RefreshError::InternalInvariantViolation variant (PR 4 C3)`).

**Commit C4 — `LocalRefresh` aggregate + `produce_scan_result`
implementation.**

Introduces the `RefreshEngine`-implementing aggregate:

- `pub struct LocalRefresh` in
  `rust/shekyl-engine-core/src/engine/local_refresh.rs` with
  `view_material: ViewMaterial` field (and any
  scanner-construction state lifted out of `run_refresh_task`
  per §5.4.7 R4 a-instance-scoped).
- `LocalRefresh::new(view_material: ViewMaterial)`
  constructor (Phase 0b binding form).
- `impl RefreshEngine for LocalRefresh` with
  `produce_scan_result`'s body implementing the §2.3
  contract: cancel-checkpoints 2/3/5 inside the body
  (checkpoints 1/4 stay on the orchestrator; **checkpoint 5
  is the per-transaction inner check** added by Round 4
  review pass §5.4.9 F2); scanner construction from
  `view_material`; per-block scan loop; `RefreshDiagnostic`
  events emitted at the audited call sites enumerated in
  §6's call-site sweep.
- **Inner cancellation check (Round 4 review pass, 2026-05-15;
  F2; safe-point pin from F11 amendment, 2026-05-15;
  per-output escalation criterion from F11 sub-pin
  amendment, 2026-05-15).** The
  per-block scan loop body adds a per-transaction cancellation
  check (`token.is_cancelled()` → return `RefreshError::Cancelled`
  on hit). **Safe-point firing site (binding).** The check fires
  at the top of the per-transaction scan-loop iteration, **after**
  the prior iteration's `Zeroizing<…>`-wrapped per-output
  materials have been dropped at the iteration's scope exit, and
  **before** the next transaction's view-tag / hybrid-decap /
  key-image derivation begins. Implementation shape: place the
  check as the first statement inside the per-transaction loop
  body, with the iteration-local per-output material declared
  *after* the check (so the prior iteration's drops have
  completed by the time the check observes the token). Mid-
  derivation firing (between view-tag pre-filter and hybrid-decap
  call; between hybrid-decap and key-image computation) is
  forbidden by the §3.1 / §2.3 cancellation-checkpoint contract;
  C7's `AssertionSink` / coherence-pair test substrate gains
  a safe-point fixture (per §6 Test-substrate-preservation
  list) that constructs an adversarial cancellation token
  firing during a synthesized per-transaction iteration and
  asserts the producer's stack-effect-trace contains no
  partial-derivation state at the observed cancellation point.
  On hit the producer discards in-flight per-block partial
  state; `Scanner`'s `ZeroizeOnDrop` chain handles the
  per-block materials. Cost: ~1–3 ns per transaction;
  preserves §3.1 sub-block lock-latency property under
  adversarial daemon block crafting.
- **Per-output escalation criterion (F11 sub-pin amendment,
  2026-05-15).** The per-transaction safe-point granularity
  is sufficient *if* per-transaction `recover_outputs_in_tx`
  cost is bounded sub-millisecond independent of per-output
  count. Phase 1 commit author MUST verify this against the
  actual benchmarked cost: enumerate the FCMP++ per-tx
  output upper bound (against
  [`shekyl-protocol-spec`](../../docs/) protocol parameters
  for the maximum legal output count per transaction at
  current consensus height), measure
  `recover_outputs_in_tx`'s per-output marginal cost on the
  Phase 1 author's reference hardware, and compute the
  worst-case per-tx scan time under maximum-output-count
  hostile transactions. **Disposition criterion (binding):**
  if worst-case per-tx scan time exceeds the §3.1 sub-block
  lock-latency target (millisecond-scale under adversarial
  daemon block crafting), the safe-point granularity
  **escalates to per-output** — the inner check fires
  between consecutive per-output decap iterations within
  the per-tx loop, with the same safe-point semantics
  (after prior per-output material drops; before next
  per-output material loads). Per-output-granularity
  imposes ~1–3 ns × num_outputs per-tx cost (negligible
  against the per-output decap cost itself). The §3.1
  lock-latency property's content-independence holds
  under either granularity provided the criterion is
  satisfied. Phase 1 commit-message records the
  measurement and the chosen granularity per the
  audit-trail discipline (durable measurement evidence
  lives at §7.Y; C4 commit-message summarizes and cites
  by section); the choice is bisectable against the C4
  commit boundary.
- **Producer-side per-class emission rate budget (Round 4
  review pass, 2026-05-15; F6; emission-cadence pin from
  F13 sub-pin amendment, 2026-05-15).**
  `LocalRefresh::produce_scan_result` tracks per-attempt
  per-class emission state (`O(num_event_classes)` entries on
  `LocalRefresh::emit_state`, per-attempt scratch, reset at
  attempt start). Each entry carries (a) a `u32` per-class
  per-block emission counter (cleared at block boundary) for
  the per-block ceiling check, and (b) a per-class
  `notice_emitted: bool` flag (cleared at attempt start, never
  cleared mid-attempt) for the per-attempt
  emission-cadence pin. **Per-block ceiling check.** On each
  emission attempt, the per-block counter is incremented; when
  the per-block ceiling (one-per-class-per-block for adversarial
  event classes; one-per-block for `ScanProgress`) is exceeded,
  the would-be event is dropped (no payload emitted).
  **Per-attempt notice emission (F13 sub-pin).** When the
  per-block ceiling is first exceeded for a class within an
  attempt — *and only if* `notice_emitted` is false for that
  class — the producer emits a single
  `SuppressedRateLimit { class: SuppressedClass::<C> }`
  notice and sets `notice_emitted = true` for that class.
  Subsequent in-class budget exceedances within the same
  attempt drop the would-be event (per the per-block ceiling
  rule) but **do not emit further notices** — the
  `notice_emitted` flag is the latch that closes the
  emission-cadence covert channel. Cross-attempt cadence
  (an attacker forcing many attempts via
  `ConcurrentMutation`-driven retries) is bounded at the
  orchestrator's existing retry-loop policy layer per
  §5.4.8 #5's emission-cadence-sub-pin "cross-attempt
  cadence is a separate layer-up question" framing; no
  producer-side state survives across attempts (the
  zeroization scope for `ViewMaterial` and `Scanner`
  forecloses producer-side cross-attempt state).
- The migration of the existing `run_refresh_task`
  producer-body content into `LocalRefresh::produce_scan_result`
  preserves the **five-cancellation-checkpoint discipline**
  (per the Round 4 review-pass-promoted contract); the
  behavioural changes are the `&dyn DiagnosticSink`
  parameter routing observable events, the per-transaction
  inner check, and the per-class emission counter tracking.

C4 introduces no `Engine`-side parameterization; the new
aggregate sits in the crate but unconsumed until C5.

**Landed: `ac100e1ab`** (`refresh: add LocalRefresh aggregate
with per-output safe-point (PR 4 C4)`); C4 prep:
**`e560d0c12`** (`refresh: add MalformedKind::ExcessiveOutputs
variant (PR 4 C4 prep)`); **`365a2de7c`** (`scanner: add
Scanner::scan_with_cancel per-output safe-point API (PR 4 C4
prep)`); **`d385bd728`** (`scanner: enforce MAX_OUTPUTS bound
at scan_transaction entry (PR 4 F11-S prep)`).

**Commit C5 — `Engine` parameterization + retry-loop call-site
migration + `RpcError` classification.**

Wires the trait into `Engine` and lands the two adjacent
migrations:

- `Engine<S, D: DaemonEngine = DaemonClient, L: LedgerEngine =
  LocalLedger, R: RefreshEngine = LocalRefresh>` adds the
  fourth type parameter; `OpenedEngine<S, D, L, R>` mirrors.
- `Engine::start_refresh` and `run_refresh_task` dispatch
  through the `R: RefreshEngine` parameter rather than the
  inlined producer body; the orchestrator-side checkpoint
  observation (checkpoints 1/4) and the retry loop stay on
  `Engine<S, D, L, R>`.
- Retry-loop-exhaustion call-site migration at
  [`engine/refresh.rs:1672–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  and [`:2055–2065`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  — `RefreshError::MalformedScanResult { reason: "..." }`
  becomes `RefreshError::InternalInvariantViolation { context:
  "..." }` with the existing reason strings as the `context`
  values. Both sites become `&'static str` literals.
- Producer-side `RpcError` classification at the
  `RefreshDiagnostic::DaemonProtocolError`-emission boundary
  inside `LocalRefresh::produce_scan_result`: `RpcError`
  variant tag → `ProtocolErrorKind` enum tag (no `String`
  payload propagated); the five Round-4-audit-confirmed
  variants map per §4 Phase 0e's `ProtocolErrorKind` table.

C5 is the load-bearing trait-dispatch commit; existing
`Engine`-driven refresh paths execute against the trait surface
after C5 lands.

**Landed:** **C5a** `553d70139` (`refresh: parameterize Engine
with R: RefreshEngine type slot (PR 4 C5a)`); **C5b**
`0dea3fd1e` (`refresh: classify RpcError as ProtocolErrorKind
diagnostics (PR 4 C5b)`); **C5** `7140f726a` (`refresh: cut
Engine retry loop over to RefreshEngine dispatch (PR 4 C5)`);
**C5β** `b6a1274de` (`refresh: delete legacy producer
scaffolding in refresh.rs (PR 4 C5β)`). The C5β cleanup
deletes the pre-trait `produce_scan_result` free function +
`ProduceError` + `ProgressEmitter` + duplicated helpers +
constants from `engine/refresh.rs`; the bisection-discipline
gates run green between the C5 trait-dispatch cutover and the
C5β scaffolding removal.

**Commit C6 — `FaultInjecting<R: RefreshEngine>` test substrate
+ retroactive Mock-X cleanup of `MockLedger` and `MockDaemon`
(Round 5 substrate amendment, 2026-05-20).**

The prior Round-4 plan was `MockRefresh` mirroring `MockDaemon` /
`MockLedger`. The Round 5 amendment (Status banner above; §6
no-Mock substrate inheritance discipline) replaces it with the
binding no-Mock substrate shape PR 3 §2.1.2 settled and lands
the FOLLOWUPS-scheduled retroactive cleanups of `MockLedger`
and `MockDaemon` in the same substrate-pass. The amendment
disposition (architectural-integrity-now per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc))
prevents PR 4 from compounding Mock-X debt and closes two
FOLLOWUPS entries
([`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) lines 578–620).

C6 is decomposed into three sub-commits per bisection discipline
(per the `90-commits.mdc` scope-per-commit rule and the PR 4
precedent set by C5 / C5a / C5b / C5β):

- **C6α — `FaultInjecting<R: RefreshEngine>` wrapper +
  `test-helpers` feature introduction (Round 5 sub-pin
  extension F-Mock-1 / F-Mock-2 / F-Mock-3-sharpening /
  F-Mock-7 / F-Mock-8).**

  **Wrapper definition (F-Mock-3 Option (i)).** Introduces the
  composable wrapper at
  `rust/shekyl-engine-core/src/engine/fault_injecting_refresh.rs`
  (gated `#[cfg(any(test, feature = "test-helpers"))]` per
  F-Mock-1 symmetry).
  `impl<R: RefreshEngine> RefreshEngine for FaultInjecting<R>`
  with **`type Error = RefreshError`** (per §6.1 F-Mock-3 +
  §6.1.1 two-enum architecture pin: the wrapper exposes the
  orchestrator-side `RefreshError` surface uniformly across
  all `R`, R-agnostic; cross-wrapper symmetry with
  `FaultInjecting<L: LedgerEngine>` whose trait signature
  forces the same shape per
  [`engine/traits/ledger.rs:270–273`](../../rust/shekyl-engine-core/src/engine/traits/ledger.rs)).
  The queue holds `RefreshError` values directly.
  `produce_scan_result` pops the head injection if non-empty
  (returns the queued `RefreshError` without invoking the
  inner producer; the wrapper's
  `Self::Error: Into<RefreshError>` bound is the identity at
  the orchestrator boundary) or delegates to
  `self.inner.produce_scan_result(...)` and forwards the
  result, with the inner producer's `R::Error` converted to
  `RefreshError` via the `Into` bound at the wrapper's return
  site (so the wrapper sees `RefreshError` on both injection
  and delegation paths, uniformly). `Engine::replace_refresh(
  &mut self, refresh: R)` test-only setter on `Engine<S, D, L, R>`
  gated behind the same feature.

  **F-Mock-3-sharpening (trait-reachable vs.
  orchestrator-constructed variants; cause-vs-effect testing
  pattern).** Of the six `RefreshError` variants per
  [`engine/error.rs:148–270`](../../rust/shekyl-engine-core/src/engine/error.rs),
  three are reachable from a `RefreshEngine` impl's
  `Self::Error` via the `From` conversion: `Cancelled` (unit),
  `Io(IoError)` (payload), and `InternalInvariantViolation
  { context: &'static str }` (payload constructed at the From
  impl site per
  [`engine/local_refresh.rs:368–384`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)).
  Three are orchestrator-constructed only:
  `MalformedScanResult { reason }` (constructed exclusively by
  the merge layer in
  [`engine/merge.rs:315–451`](../../rust/shekyl-engine-core/src/engine/merge.rs)),
  `ConcurrentMutation { wallet, result }` (constructed at the
  merge gate), `AlreadyRunning` (constructed at binary-layer
  single-flight). Under Option (i) **direct injection** the
  wrapper can inject any of the six variants directly into the
  orchestrator surface; for trait-reachable variants this
  exercises the same code path the production From conversion
  would reach; for orchestrator-constructed variants direct
  injection is a deliberate test affordance (test "orchestrator
  handles `MalformedScanResult` from the producer trait surface
  correctly" even though no V3.0 `RefreshEngine` impl actually
  returns it). For `InternalInvariantViolation` both direct
  injection (testing producer-returned-then-orchestrator-
  propagated path) and **cause injection** (driving causes
  through `FaultInjecting<LocalLedger>::queue_concurrent_mutation`
  per F-Mock-2 to exhaust the retry budget at the orchestrator-
  side construction sites in `engine/refresh.rs`) are legitimate
  test classes; both are exercised. For `ConcurrentMutation`
  cause injection through `FaultInjecting<LocalLedger>` is the
  primary path (exercises the merge-gate construction site);
  direct injection through `FaultInjecting<R>` exercises the
  orchestrator's handling of an orchestrator-already-detected
  ConcurrentMutation arriving at the producer surface
  (deliberate test affordance, not a production-reachable path
  on `R`). The pattern is "drive causes through one trait
  wrapper, observe effects on the orchestrator surface" — see
  §6.1 paradigm pin for why this shape translates cleanly to
  Stage 4 actor-paradigm tests.

  **F-Mock-2 queue contract (composition-paradigm; see §6.1
  paradigm pin).** The queue is **wrapper-internal state
  visible only through the wrapper's API**, not an actor
  mailbox; the queue type is `RefreshError` per the Option (i)
  wrapper API above. Contract:

  - **FIFO ordering.** Injections are popped head-first;
    if the test injects
    `[RefreshError::Cancelled, RefreshError::Io(IoError::Daemon {..})]`
    in that order, the next two calls return `Cancelled`
    then `Io(IoError::Daemon{..})`. The ordering pin
    forecloses property tests that assert per-call
    return-discriminant ordering from failing unhelpfully
    against a LIFO or unordered implementation.
  - **Drain inspector.** The wrapper exposes
    `queued_failures(&self) -> usize` per the existing
    [`MockLedger::queued_failures`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
    precedent (per F-Mock-2 the existing API is the canonical
    shape). Tests verify queue-drain by asserting
    `wrapper.queued_failures() == 0` at teardown, closing
    the false-positive class where a test injects a failure,
    runs the engine, asserts the engine handled correctly,
    and never notices the injection path was not exercised.
  - **`debug_assert!` on Drop for non-empty queue.** If a
    test leaves the wrapper without draining, the wrapper's
    `Drop` impl fires `debug_assert!(self.queue.is_empty(),
    "FaultInjecting dropped with N queued failures
    un-consumed; tests must drain via queued_failures()")` —
    panic-on-leftover in test/debug builds; silent in
    release (release builds should not have the wrapper
    compiled in regardless, per the F-Mock-1 cfg-gating).
  - **Reentrance.** If a test injects a failure and the
    producer's body internally re-enters via some path that
    calls back into `RefreshEngine`, the second call also
    pops from the queue per the "pop head if non-empty"
    semantics. The V3.0 `LocalRefresh` has no such
    reentrance pattern; the pin is for forward-compatibility
    with Stage 4 actor-mesh implementors that may carry
    different reentrance behaviour.

  **F-Mock-7 `test-helpers` feature introduction.** C6α's
  scope includes adding `test-helpers = []` to
  [`rust/shekyl-engine-core/Cargo.toml`](../../rust/shekyl-engine-core/Cargo.toml)'s
  `[features]` section, with a rationale comment matching the
  existing `bench-internals` precedent (lines 223–227):

  ```toml
  # Internal feature: re-exports otherwise-`pub(crate)`
  # failure-injection wrappers (FaultInjecting<R: RefreshEngine>,
  # FaultInjecting<L: LedgerEngine>, Engine::replace_refresh,
  # LocalLedger::from_test_blocks) for downstream integration
  # test crates that need composition-paradigm failure injection
  # at the trait boundary. Not part of the public API; consumers
  # must not depend on this feature in production builds.
  test-helpers = []
  ```

  Per F-Mock-1 symmetry the feature gates all four C6
  test-helper surfaces uniformly. Pre-genesis no downstream
  test-helpers consumer crate exists yet; the feature is
  declared so the gating composes correctly when one emerges
  (the gating is the load-bearing property, not the
  external-API polish).

  **F-Mock-8 smoke-test property classes (two test classes
  per §6.1.1 two-enum architecture pin).** C6α's smoke-test
  surface covers **two classes** corresponding to the two-enum
  architecture; both are load-bearing for the test-coverage
  story to be complete.

  **Class 1 — wrapper-based trait-surface tests** (live in the
  new `fault_injecting_refresh.rs` test module). Four
  sub-properties:

  1. **Empty-queue passthrough.** Wrapper with empty queue
     delegates to inner producer; no injection consumed.
  2. **Single-injection-then-delegation.** Queue one
     `RefreshError`; first call returns the injection; second
     call delegates to inner producer.
  3. **Multi-injection FIFO ordering.** Queue `[A, B]`;
     first call returns `A`; second call returns `B`;
     third call delegates to inner producer.
  4. **Queue-drain-on-teardown.** Queue two failures; consume
     one; assert `queued_failures() == 1`; drain via a second
     consume; assert `queued_failures() == 0`. (The Drop-time
     `debug_assert!` is a separate test that constructs a
     wrapper, queues a failure, and lets it drop;
     `#[should_panic]` verifies the assert fires.)

  **Class 2 — From-conversion tests against `LocalRefresh`**
  (live in [`local_refresh.rs`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)'s
  existing tests module per the
  [`local_refresh_error_maps_to_refresh_error`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)
  precedent). Each `LocalRefreshError` variant exercised
  end-to-end against the corresponding `RefreshError` variant
  the `From` impl produces; the existing test already covers
  the four-variant matrix and C6α scope confirms its presence
  rather than adding new content (Phase 1 author confirms the
  test compiles after the wrapper introduction and gates;
  no migration needed because `LocalRefreshError` and its
  `From` impl are unchanged by C6α). This class is **sibling
  to Class 1, not a replacement** — the wrapper bypasses the
  From conversion by injecting `RefreshError` directly under
  Option (i), so wrapper tests do not exercise the From impl;
  Class 2 is what verifies the From impl behavior.

  CI gate: existing test suite against the trait-dispatched
  `Engine` plus Class 1 wrapper smoke tests plus Class 2
  From-conversion test (already in place; confirmed-only).
- **C6β — `FaultInjecting<L: LedgerEngine>` extraction +
  `LocalLedger::from_test_blocks(...)` constructor
  (closes [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) lines 578–604).**
  Extracts the existing `MockLedger::queue_concurrent_mutation`
  body ([`engine/test_support.rs:773`](../../rust/shekyl-engine-core/src/engine/test_support.rs))
  into the new wrapper at
  `rust/shekyl-engine-core/src/engine/fault_injecting_ledger.rs`
  (same `#[cfg(...)]` gating). Adds
  `LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`
  (deterministic test-block fixtures, gated by `#[cfg(test)]`)
  replacing `MockLedger::new(...)`. Rewires
  `engine/test_support.rs` callers and all per-test instantiations.
  Per §6 no-Mock substrate inheritance discipline: current
  `MockLedger` is structurally already a `FaultInjecting<
  LocalLedger>`-shaped wrapper (its merge path delegates to the
  canonical `apply_scan_result_to_state`); the cleanup is
  mostly extraction-and-rename, not a re-implementation.
- **C6γ — `MockDaemon` → `TestDaemon` rename
  (closes [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) lines 606–620).**
  Mechanical rename of the `MockDaemon` type and all callers in
  [`engine/test_support.rs`](../../rust/shekyl-engine-core/src/engine/test_support.rs)
  and tests. The structural shape is unchanged — `MockDaemon`
  is already an alternative real implementation that serves
  canned / cached test responses without network connectivity;
  the rename signals that shape correctly per PR 3 §2.1.2.
  Bundled with C6α/C6β because PR 4's substrate-pass is the
  FOLLOWUPS-named landing slot for both cleanups.

C6 (composite) is the test-substrate commit; the existing test
suite runs against the trait-dispatched `Engine` after C6
lands, with all failure injection routed through the composable
`FaultInjecting<...>` wrappers and no parallel-implementation
Mocks remaining in the engine-core crate.

**Landed:** **C6α** `e9310542a` (`refresh: C6α
FaultInjecting<R: RefreshEngine> wrapper + test-helpers`);
**C6β** `e94526dec` (`refresh: C6β FaultInjecting<L:
LedgerEngine> + LocalLedger::from_test_blocks + MockLedger
retirement`); **C6γ** `b937906a6` (`refresh: C6γ MockDaemon
→ TestDaemon rename`). Round 5 substrate-decision amendment
`8484e669a` (`refresh: Round 5 substrate-decision amendment
(no-Mock C6 plan)`) and Round 5 sub-pin extension
`29cb7e138` (`refresh: Round 5 sub-pin extension (F-Mock-1..8
+ two-enum architecture)`) precede C6α as design-doc commits
on the implementation branch; they are not part of the C6
implementation numbering but record the binding substrate
C6α/β/γ implement against.

**Re-iterated no-Mock rationale (per PR 3 §2.1.2 and §6 above):**
the prior `MockRefresh` plan would have re-instantiated the
parallel-implementation anti-pattern PR 3 rejected as a category.
Building it would (1) add attack surface via test-only types in
production code; (2) conflate test-controlled inputs to real
implementations with substitute implementations under the same
`MockX` naming; (3) carry forward an inherited-Monero pattern
that has produced real bugs in the inherited codebase; (4)
foreclose composition with future `RefreshEngine` implementors
(each implementor would need its own Mock variant); (5) encourage
tests to verify against fake producer semantics rather than
real `LocalRefresh` semantics, degrading the test suite's
coverage claim. The no-Mock substrate shape avoids all five
failure modes by construction: tests exercise the real
`LocalRefresh` producer body through the `FaultInjecting<...>`
wrapper, with deterministic failure injection at the trait
boundary rather than as a parallel implementation of the trait.

**Commit C7 — Hybrid retry test + property tests
(`AssertionSink` / `PanickingSink`).**

Lands the §6 Test-substrate-preservation deliverables:

- Hybrid test
  `hybrid_refresh_engine_orchestrator_cancellation_retries`
  — exercises the producer-trait/orchestrator
  cancellation-checkpoint split (checkpoints 2/3 in the
  trait body; checkpoints 1/4 in the orchestrator) and the
  retry-loop's `ConcurrentMutation` retry path against
  `FaultInjecting<LocalLedger>`-injected mutations
  (Round 5 amendment; replaces the prior `MockRefresh`-injected
  reference per the no-Mock substrate inheritance discipline).
  Mirrors PR 2's
  `hybrid_apply_scan_result_retries_on_concurrent_mutation`
  shape.
- `pub struct AssertionSink` (test-only) implementing
  `DiagnosticSink` by recording `emit` calls in-order; the
  property test
  `produce_scan_result_emission_return_coherence` asserts
  the trait return discriminant matches the recorded sink
  stream's terminal event class. Coherence-test authority
  per §5.4.6.
- `pub struct PanickingSink` (test-only) implementing
  `DiagnosticSink` by panicking on `emit`; the property
  test `produce_scan_result_panicking_sink_unwind_safe`
  verifies producer-side robustness: `Scanner` zeroization
  completes (the field's `ZeroizeOnDrop` impl fires on
  unwind), cancellation-token consistency holds, the panic
  unwinds without corrupting `LocalRefresh` interior state.

C7 is the property-test commit; the hybrid test is
end-to-end against `Engine<SoloSigner, TestDaemon,
FaultInjecting<LocalLedger>, FaultInjecting<LocalRefresh>>`
(Round 5 amendment; production implementors with failure
injection via composable wrappers, per the no-Mock substrate
inheritance discipline). CI exercises both classes.

**Landed: `c9e65bbc6`** (`refresh: C7 hybrid retry test +
AssertionSink/PanickingSink property tests`). Concrete C7
deliverables landed (the C7 design above is the binding
substrate; the implementation widens within the binding
contract): `Engine::replace_refresh` refactored from
`&mut self` setter to consume-and-rebuild constructor so the
`R` type parameter can change to `FaultInjecting<LocalRefresh>`
(mirrors the existing `replace_daemon` / `replace_ledger`
shape per
[`engine/lifecycle.rs`](../../rust/shekyl-engine-core/src/engine/lifecycle.rs));
`AssertionSink` + `PanickingSink` + `PanickingSinkTrigger`
land at
[`engine/diagnostics.rs`](../../rust/shekyl-engine-core/src/engine/diagnostics.rs)
gated `#[cfg(any(test, feature = "test-helpers"))]` per the
F-Mock-1 cfg-symmetry pin; `proptest = "1"` added as a
`dev-dependency` for the producer-property-tests module at
[`engine/local_refresh.rs`](../../rust/shekyl-engine-core/src/engine/local_refresh.rs)
(5 parametric coherence tests + 1 fuzzed proptest +
4 panic-safety tests + 1 classifier sanity test); the
hybrid retry test
`hybrid_refresh_engine_orchestrator_cancellation_retries` at
[`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
exercises the producer-trait/orchestrator cancellation-
checkpoint split end-to-end against
`Engine<SoloSigner, TestDaemon, FaultInjecting<LocalLedger>,
FaultInjecting<LocalRefresh>>`. Tests pass 170/170 under
`cargo test --features test-helpers --lib`; `cargo fmt --all
-- --check` + `cargo clippy --all-targets --features
test-helpers -- -D warnings` + default-feature clippy +
`cargo doc --features test-helpers --no-deps` all green
(no new doc warnings; pre-existing intra-doc-link warnings
to private items are baseline and unrelated to C7 changes).

**Commit C8 — Docs propagation + CHANGELOG.**

Final commit; doc-only:

- This design doc (`STAGE_1_PR_4_REFRESH_ENGINE.md`) gains
  a top-of-doc Status banner update marking Phase 1 as
  landed; §6's checklist gains the per-commit landing-SHA
  cross-references.
- [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 prose past-tenses the "Stage 1 surface" section to
  reflect the landed implementation; cross-references this
  PR's merge SHA for the implementation locator.
- [`docs/CHANGELOG.md`](../CHANGELOG.md) `[Unreleased]` /
  `Added` section gains the `RefreshEngine` trait + the
  `RefreshDiagnostic` enum (including the
  `SuppressedRateLimit` variant added by Round 4 review pass
  F6) + the `DiagnosticSink` trait entries (with the
  per-emitter FIFO ordering pin per F4); `Changed` section
  gains the `Engine` parameterization fourth-parameter entry
  and the `RefreshError::InternalInvariantViolation` variant
  addition.
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) gains Phase 0d-strike
  retirement note (the conditional candidate retired by
  composition per §5.4.7 R5 reframe; not deferred — struck);
  the §5.4.7 R5 / R6 / R4 (c) deferrals stay open per
  Round 3's prior amendments. **Round 4 review pass V3.1+
  entries** also referenced: the consumer-actor-PR
  aggregator-republisher CI lint (F5) and the diagnostic-stream
  spec doc per-class projection-type formalization (F9).
  **Round 5 substrate amendment closures (2026-05-20):** the
  two retroactive Mock-X cleanup entries (`MockLedger` →
  `FaultInjecting<LocalLedger>` + `LocalLedger::from_test_blocks`
  at FOLLOWUPS lines 578–604; `MockDaemon` → `TestDaemon` rename
  at lines 606–620) are closed by PR 4 C6α/C6β/C6γ; the
  FOLLOWUPS entries are marked closed with the PR 4 merge SHA
  as the closure anchor.
- The `feat/stage-1-pr4-refresh-engine` branch's PR
  description references this §7.X commit list as the
  contract; CI green at every commit per the Phase 1
  bisection-discipline gate.

C8 is the docs / changelog commit; the PR opens with C8 as
the tip.

**Landed: this commit** (`refresh: C8 docs propagation +
CHANGELOG`). C8's scope as executed: the Status-banner
"Phase 1 landed" closure paragraph above (line-anchored
just before "This document was opened in parallel with…");
the per-`Commit Cn` `Landed:` lines in this §7.X section
(C0–C7, plus C5/C5β decomposition and C6α/β/γ); the
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.3 past-tense reframe with implementation-locator
SHAs; the [`CHANGELOG`](../CHANGELOG.md) `[Unreleased]`
extension covering C7 under the existing PR 4 entry plus
the C8-mandated `### Added` entries for the `RefreshEngine`
trait + `RefreshDiagnostic` enum (with `SuppressedRateLimit`
variant) + `DiagnosticSink` trait (with per-emitter FIFO
pin); the `### Changed` entries for `Engine<S, D, L, R>`
four-parameter wiring and `RefreshError::InternalInvariantViolation`
variant addition; and the [`FOLLOWUPS`](../FOLLOWUPS.md)
Phase 0d-strike retirement note (the conditional candidate
retired by composition per §5.4.7 R5 reframe; **struck**, not
deferred — the §5.4.7 R5 / R6 / R4 (c) V3.x consumer-actor
deferrals remain open per Round 3's prior amendments and
the existing FOLLOWUPS entries). PR 4 §7.X commits C0–C8
are now landed; the PR is ready to open against `dev`.

**Phase 1 readiness checklist (gates the C0 cut).** The
following are pre-conditions for the implementation branch to
cut off the post-Round-4 dev tip:

- [x] §4 Phase 0 candidates binding-pinned at type-signature
  level (Round 4 close confirms).
- [x] §6 review checklist filled (this Round 4 commit).
- [x] §7.X commit decomposition sequenced and load-bearing-
  ordered (this section).
- [x] §8 fenceposts close the five "Remaining for Round 4"
  items (Round 4 close).
- [x] No outstanding adversarial-review residual that
  reopens any Round (PR 5 Round 1's confirmation closed
  Round 3's *provisionally-load-bearing* qualifier; no
  subsequent reopening triggers identified).

**Phase 1 invocation-overhead gate (§5.4.4 cross-reference).**
The trait-method dispatch through `&dyn DiagnosticSink` plus
the per-call `diagnostics` parameter pass adds bounded
per-attempt overhead (one `Box<dyn ...>`-sized indirection
per `emit` call). The §5.4.4 invocation-overhead constraint
is satisfied by construction: no per-call setup cost beyond
the parameter passes; no per-block dispatch overhead beyond
the existing per-block scan loop's iteration count.

---

## §7.Y Phase 1 F11-S audit-trail measurement (2026-05-20)

The Round 4 review-pass §5.4.9 F11-S post-amendment sub-pin
pinned the per-output safe-point escalation criterion as a
binding Phase 1 commit-author deliverable: if worst-case per-tx
`recover_outputs_in_tx` scan time under maximum-output-count
hostile transactions exceeds the §3.1 sub-block lock-latency
target, the safe-point granularity escalates from per-transaction
(per §7.X C4 "Inner cancellation check") to per-output (per §7.X
C4 "Per-output escalation criterion"). The §7.X C4 commit message
records the chosen granularity and summarizes the measurement;
**this section holds the durable evidence so the C4 commit body
can cite by section rather than embedding multi-page benchmark
output**. The FOLLOWUPS V3.0 entry "F11-S Windows-midrange-PC
measurement revisit at stressnet" ([`docs/FOLLOWUPS.md`](../FOLLOWUPS.md))
references this section as the substrate the Phase 7.7
re-measurement is compared against.

This section is **append-only**: re-measurements at FOLLOWUPS-
triggered substrate changes (Windows-midrange-PC re-measurement
at Phase 7.7; future re-measurements at hardware-floor shifts)
land as new sub-sections (§7.Y.11, §7.Y.12, …) preserving the
historical audit trail.

### §7.Y.1 Disposition

**Chosen granularity: per-output safe-point.** Worst-case per-tx
scan time under `N = MAX_OUTPUTS = 16` hostile transactions measures
**12.95 ms p99 cold-cache** on the Phase 1 author's reference
hardware (§7.Y.2), exceeding the §3.1 millisecond-scale lock-latency
target by ~13×. The F11-S sub-pin's binding criterion is met
unambiguously; per-output granularity is mandatory at C4.

**Strict 2× safety margin breach acknowledged and deferred.**
Per-output marginal cost measures **819 µs cold p99**
(regression-derived) / **809 µs cold p99** (direct quotient at
N=16) — within the §3.1 raw 1 ms target (0.82×) but exceeding the
strict 500 µs microbench-to-production decision-line by 1.64×.
The Phase 7.7 stressnet re-measurement on the designated Windows-
midrange PC (per FOLLOWUPS) is the load-bearing audit-trail floor
that confirms (per-output granularity remains sub-millisecond on
commodity Windows hardware) or escalates (per-output cost exceeds
§3.1 target ⇒ further optimization or safe-point granularity
revision) the disposition.

### §7.Y.2 Environment

| Item | Value |
|---|---|
| Hardware | 11th Gen Intel Core i9-11950H @ 2.60 GHz base / 5.00 GHz turbo (8C/16T, Tiger Lake-H) |
| OS | Linux 6.12.88-1 Debian 13, x86_64 |
| Toolchain | rustc 1.95.0, cargo 1.95.0, release profile |
| CPU governor | `performance` (all 16 logical cores) |
| CPU pinning | `taskset -c 4` (single logical core, physical core 4) |
| Power source | AC (BAT0 = Full) |
| Load avg at bench start | 0.36 / 0.36 / 0.52 (1m / 5m / 15m) |
| Frequency at bench start (core 4) | 4.35 GHz |
| valgrind | 3.24.0 |
| iai-callgrind-runner | 0.16.1 |
| Bench harness commit | `46c64760d` (PR 4 F11-S prep #2) |
| Measurement date | 2026-05-20 |

### §7.Y.3 Harness

The bench harness lives at three sites, all gated to dev/bench
builds:

- [`rust/shekyl-scanner/src/bench_fixtures.rs`](../../rust/shekyl-scanner/src/bench_fixtures.rs)
  (gated behind the `test-utils` feature) — `BenchWalletKeys`,
  `make_bench_wallet`, `build_worst_case_scannable_block`,
  `build_typical_case_scannable_block`, plus sanity-check tests
  that assert the worst-case fixture actually exercises the
  view-tag-matching slow path and the typical-case fixture
  actually exits via the view-tag mismatch fast path.
- [`rust/shekyl-scanner/benches/scan_transaction.rs`](../../rust/shekyl-scanner/benches/scan_transaction.rs)
  (criterion) — two benchmark groups
  (`worst_case_all_view_tags_match` [F11-S binding, identified
  in code via the `F11S_BINDING_GROUP` constant] and
  `typical_case_view_tag_filtered` [contextual]), each sweeping
  N ∈ {1, 4, 8, 16} outputs with both warm-cache and cold-cache
  variants. Warm-cache uses criterion's `iter_batched_ref`;
  cold-cache uses `iter_batched` with `BatchSize::PerIteration`
  (fresh `(Scanner, ScannableBlock)` constructed per iteration
  outside the measured region — setup-induced L1/L2 thrashing
  is part of what "cold" means here).
- [`rust/shekyl-scanner/benches/scan_transaction_iai.rs`](../../rust/shekyl-scanner/benches/scan_transaction_iai.rs)
  (iai-callgrind companion) — deterministic instruction-count
  cross-check on the same two groups at the same N sweep.

The harness measures `Scanner::scan(block)` (the public API),
accepting minimal block-orchestration overhead in exchange for
public-API consistency with the production refresh-engine call
path.

### §7.Y.4 Wall-clock measurement (criterion, performance governor)

Per-tx total scan time, all N values (100 samples per cell):

| Group | Cache | N | p50 (µs) | p99 (µs) | max (µs) | min (µs) |
|---|---|---|---:|---:|---:|---:|
| worst_case | warm | 1 | 724 | 820 | 1063 | 710 |
| worst_case | warm | 4 | 2927 | 2974 | 2991 | 2910 |
| worst_case | warm | 8 | 5877 | 6024 | 6483 | 5843 |
| worst_case | warm | 16 | 11672 | 11895 | 12215 | 11600 |
| worst_case | cold | 1 | 721 | 771 | 1014 | 714 |
| worst_case | cold | 4 | 2941 | 2994 | 3001 | 2923 |
| worst_case | cold | 8 | 5901 | 6382 | 6382 | 5844 |
| **worst_case** | **cold** | **16** | **11754** | **12983** | **14273** | **11642** |
| typical_case | warm | 1 | 93 | 95 | 96 | 92 |
| typical_case | warm | 4 | 365 | 395 | 397 | 360 |
| typical_case | warm | 8 | 789 | 1360 | 1525 | 730 |
| typical_case | warm | 16 | 1510 | 2541 | 2542 | 1460 |
| typical_case | cold | 1 | 97 | 117 | 130 | 95 |
| typical_case | cold | 4 | 386 | 432 | 449 | 374 |
| typical_case | cold | 8 | 743 | 777 | 780 | 732 |
| typical_case | cold | 16 | 1500 | 1768 | 1852 | 1465 |

**F11-S binding row in bold**: `worst_case / cold-cache /
N = MAX_OUTPUTS = 16`.

Linear regression across N (`time = F + N × P`, cold-cache p99):

| Group | Per-tx fixed F (µs) | Per-output marginal P (µs) | Worst @ N=16 (µs) |
|---|---:|---:|---:|
| worst_case (p50) | -2 | 735 | 11764 |
| **worst_case (p99)** | **-157** | **819** | **12951** |
| worst_case (max) | -329 | 896 | 14009 |
| typical_case (p99) | -23 | 110 | 1734 |

The slightly negative intercept at p99 reflects per-iteration
setup outliers at low N (N=1 cold p99 = 771 µs vs regression-
predicted 662 µs; +109 µs residual); the high-N points are
clean (N=16 cold p99 residual = +32 µs, <0.3% of measurement).
**The directly-measured N=16 cold p99 (12.95 ms) is the
load-bearing number**; the regression-derived per-output cost
(819 µs) is the secondary derivation and is anchored against
the deterministic iai-callgrind per-output instruction count
(§7.Y.5).

### §7.Y.5 iai-callgrind cross-check (deterministic; governor-independent)

iai-callgrind instruments under valgrind to count executed
instructions exactly, decoupling the measurement from CPU
frequency, scheduling jitter, and cache state. Instruction
counts per `Scanner::scan` call:

| Group | N=1 | N=4 | N=8 | N=16 |
|---|---:|---:|---:|---:|
| worst_case (insn) | 13,597,126 | 54,308,095 | 108,578,773 | 217,160,656 |
| typical_case (insn) | 1,695,591 | 6,698,615 | 13,375,638 | 28,122,608 |

Linear regression:

| Group | Per-tx fixed (insn) | Per-output marginal (insn) | Residual @ N=16 |
|---|---:|---:|---:|
| worst_case | +22,429 | 13,570,860 | +4,471 (0.002%) |
| typical_case | -324,444 | 1,765,180 | +204,167 (0.7%) |

Worst-case is linear to within **0.005% at N=16** — the per-output
cost is genuinely flat (no per-tx amortizable overhead is being
missed). Typical-case has a slightly looser fit due to ~16% per-tx
fixed overhead (`Scanner` setup amortizes faster relative to the
smaller per-output cost), but residuals remain under 1.5% at every
N.

**Cache locality (worst case).** RAM hits scale by **+15.7 per
added output** (N=1: 585 RAM hits; N=16: 821). The per-output
cost is dominated by L1-resident crypto code (ML-KEM-768 decap +
Curve25519 commitment verify + HKDF derivations), not memory
bandwidth. **This property bounds portability across systems** —
the FOLLOWUPS Windows-midrange re-measurement at Phase 7.7
should track the i9-11950H result modulo single-thread frequency
differences only.

### §7.Y.6 Cross-method agreement

| Source | Slow-path-to-fast-path ratio |
|---|---:|
| Wall-clock (cold p99) | **7.46×** |
| Instruction count (iai-callgrind) | **7.69×** |
| **Agreement** | **within 3.1%** |

The 3.1% wall-clock-vs-instruction agreement is strong evidence
the measurement isn't being confounded by noise or cache
pathology, and that the slow-path / fast-path cost ratio is a
real architectural property of `scan_output_recover`'s
X25519-precedes-view-tag-derivation ordering (§7.Y.7).

### §7.Y.7 Methodology sanity check — Shekyl-corrected expected ratio range

The F11-S sub-pin's audit-trail-template framing presumed an
expected slow-path-to-fast-path ratio of ~100-500×, anchored on
Monero's wire-byte view-tag ordering where the fast-path is
dominated by a 50-200 ns wire compare *before* any DH work. The
measured ratio of 6.58× (powersave first-pass) / 7.46×
(performance second-pass) trips that framing's "ratio is wildly
off ⇒ measurement-methodology smell" rule on its face — but the
discrepancy is **architectural, not methodological**.

**Shekyl's `scan_output_recover` ordering** (see the bench
harness's sanity-check tests
`worst_case_first_output_returns_full_recovery` and
`typical_case_first_output_exits_via_view_tag_mismatch`, which
assert the typical-case error literally carries the `"X25519 view
tag mismatch"` text): each per-output flow is **X25519 ECDH →
HKDF-derive view tag from SS → wire-compare derived vs on-chain →
branch**. The wire-compare-derived-vs-on-chain step is still
~50-200 ns, but X25519 ECDH + HKDF (~95-105 µs) is **always paid**
on every output regardless of view-tag outcome. The typical-case
cost is therefore X25519-ECDH-bound, not wire-compare-bound.

**Shekyl-corrected expected ranges:**

| Quantity | Expected (Shekyl ordering) | Measured |
|---|---:|---:|
| Fast-path floor (X25519 ECDH + HKDF) | 80-150 µs/output | **105 µs** |
| Slow-path (fast-path + ML-KEM-768 decap + commit/amount verify) | 600-900 µs/output | **690-819 µs** |
| Slow-path-to-fast-path ratio | 5-10× | **7.46×** |

All three figures land in-range; the sanity-check passes. The
audit-trail template's 100-500× range derived from Monero's
wire-byte view-tag ordering — not Shekyl's derive-on-scan
ordering — and is re-anchored at the Shekyl-corrected **5-10×**
range for future re-measurements (the FOLLOWUPS Phase 7.7
re-measurement's expected-range column should cite the 5-10×
figure with this section as the anchor).

### §7.Y.8 Powersave → performance delta (governor sensitivity)

The Phase 1 author's first-pass measurement used the system's
default `powersave` CPU governor; a second pass under
`performance` governor (all 16 logical cores) confirms the
load-bearing N=16 result is governor-insensitive:

| N | Powersave cold p99 (µs) | Performance cold p99 (µs) | Δ |
|---:|---:|---:|---:|
| 1 | 1308 | 771 | -41% |
| 4 | 5161 | 2994 | -42% |
| 8 | 6131 | 6382 | +4% |
| **16** | **12319** | **12983** | **+5%** |

`powersave` significantly inflates the low-N samples (the
powersave-to-turbo frequency ramp dominates the short
per-iteration measurement window), but the high-N samples are
already turbo-saturated by the time of measurement. The +5%
drift at N=16 cold p99 reflects that `performance` amplifies
background-interference outliers visible against a less-noisy
steady state; the **median** at N=16 actually improved from
11963 → 11754 µs (-1.7%), confirming the central tendency is
consistent.

For audit-trail purposes the `performance`-governor p99
(12.95 ms) is the conservative binding; the `powersave`
first-pass remains valid as a corroborating data point.

### §7.Y.9 Forward bindings (reversion-clause discipline)

Per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc),
the §7.Y.1 disposition records the substrate-anchored
re-evaluation criterion explicitly:

- **Substrate (now).** Phase 1 author's reference hardware
  (Intel i9-11950H, Linux + AC, `performance` governor),
  bench harness commit `46c64760d`, dev-tip
  `recover_outputs_in_tx` implementation.
- **Re-evaluation criterion (named substrate change).** A
  measurement on the designated Windows midrange PC at Phase 7.7
  stressnet against the same bench harness, OR a measurement
  on different hardware after a substantive
  `recover_outputs_in_tx` implementation change (e.g., ML-KEM-768
  decap crate upgrade with substantially-different per-output
  cost), OR a `MAX_OUTPUTS` bound change (currently 16; FCMP++
  consensus-binding).
- **Re-evaluation shape.** Append a new sub-section §7.Y.N to
  this section with the re-measurement's environment, table, and
  disposition; if the disposition changes (granularity escalates
  from per-output, or de-escalates back to per-tx), the FOLLOWUPS
  entry's escalation-PR shape (per
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "F11-S Windows-midrange-PC
  measurement revisit at stressnet (V3.0)") applies.

**Cross-references.**
- §5.4.9 F11-S sub-pin disposition (the criterion this section
  satisfies).
- §7.X C4 "Per-output escalation criterion" bullet (the commit
  decomposition that lands the per-output safe-point against this
  section's measurement).
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "F11-S Windows-midrange-PC
  measurement revisit at stressnet (V3.0)" entry (the close-condition
  that triggers re-measurement).
- [`rust/shekyl-scanner/src/scan.rs`](../../rust/shekyl-scanner/src/scan.rs)
  `MAX_OUTPUTS = 16` (the consensus-binding upper bound the
  measurement's N sweep is anchored against).

### §7.Y.10 Re-measurement protocol

When the FOLLOWUPS Phase 7.7 entry triggers, the re-measurement
follows this protocol:

1. Recompile the `46c64760d` bench harness on the target
   platform against the dev tip at re-measurement time
   (confirming behavioural compatibility with the bench-harness
   API; if the harness has drifted post-`46c64760d`, capture the
   harness's then-current commit SHA in the re-measurement's
   §7.Y.2-equivalent environment table).
2. Capture the §7.Y.2 environment table for the target platform.
3. Run `cargo bench -p shekyl-scanner --bench scan_transaction`
   under the target platform's equivalent of `performance`
   governor + single-core pin; capture per-N per-cache
   p50/p99/max tables.
4. Run `cargo bench -p shekyl-scanner --bench scan_transaction_iai`
   for the deterministic instruction-count cross-check; expect
   approximately-identical instruction counts (governor- and
   platform-independent modulo libc / crypto-crate ISA-feature
   variation) and confirm linearity holds.
5. Compute the cold-cache p99 N=16 worst-case per-tx scan time
   and the per-output marginal cost.
6. Compare against the §3.1 1 ms target and the strict 500 µs
   decision-line; document the disposition in a new §7.Y.*
   sub-section appended to this section, naming the re-measurement
   date and target platform.
7. If the disposition changes (per-output granularity escalates
   to per-N-output batching, or to per-instruction safe-point, or
   the cost falls below the strict decision-line obviating the
   2× margin caveat), the FOLLOWUPS entry's escalation-PR shape
   applies.

---

## §8 What this document does not yet resolve

Round 1 closed the §5 producer-redesign disposition (α, §5.4).
The Round 1 review pass (2026-05-12) corrected §3.1 and surfaced
R4–R7 plus the §5.4.4 call-mode constraint, the §5.4.5 adversarial
scenarios, and the §5.4.6 trait-surface contract pins. Round 2
(2026-05-12) settled R1 / R2 / R3 / R4 / R7 cleanly. **Round 2
reframe (2026-05-13) supersedes Round 2's R5 and R6 dispositions**
with the two-channel actor-mesh shape (§5.4.7 R5 reframe, R6
reframe, §5.4.8 attack surfaces). The Round 2 reframe follow-up
(2026-05-13) pinned the `DiagnosticSink` contract pins
(non-blocking, emission/return coherence, recursive
trust-boundary, restart-amnesia); the contract-pin
refinements (2026-05-13) added
concurrent-emit, producer-panic-safety, and test-as-canonical-
reference. **Round 2 close-out (2026-05-13)** extends Phase 0c
with `InternalInvariantViolation { context: &'static str }` and
seeds Phase 0e's `DaemonOp` / `ProtocolErrorKind` initial variant
sets against the call-site audit. **Round 3 (2026-05-14)** closes
the *provisionally-load-bearing* qualifier on Round 1's
α-disposition triggered by PR 5 Round 1's actor-mesh-framing
confirmation. **Round 4 (2026-05-14)** finalizes §4 Phase 0
binding-pinned forms, fills §6 review checklist, and extends
§7 with the §7.X Phase 1 commit decomposition. All
PR-4-internal design rounds are closed.

**Carried into PR 5 and closed in PR 5 Round 1.**

- §5.4.7 R1 (`PendingTxEngine::build` behaviour during long
  refresh) — **closed in PR 5 Round 1 (2026-05-14)** as
  *build-against-current-snapshot + snapshot-ID pinning*
  under the actor-mesh framing (per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0 / §5.2 / §5.5). The α-disposition's
  *provisionally-load-bearing* qualifier is closed; α is
  confirmed and the re-evaluation gate collapsed without
  firing. Round 3 (this section) records the confirmation;
  PR 4 advances directly to Round 4.

**Deferred to V3.x FOLLOWUPS (named homes in
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)).**

- §5.4.7 R5 (reframe) — `ReorgAmplificationDetector` consumer
  actor; trigger: when Stage 4 actor mesh stabilizes. **The
  previous "extend checkpoint 3" deferral is withdrawn and
  replaced** with the composition disposition.
- §5.4.7 R6 (reframe) — `PeerReputationActor`, `RecoveryActor`,
  and a possible `ViewTagAnomalyDetector` consumer actor; the
  diagnostic-stream spec doc capturing the contract for future
  consumers; all triggered by Stage 4 actor mesh stabilization.
- §5.4.7 R4 (c) split-producer/recoverer — V3.x trigger:
  HW-wallet-backed signing or post-V3 threat-model refinement
  requires producer-side spend-key isolation. **Round 3
  acknowledgment (2026-05-14):** PR 5 Round 2 segment 2b's
  R11 (b) reframe landed the `Signer` trait infrastructure
  (`LocalSigner` Stage 1 / `SigningActor` Stage 4) as a sole
  spend-material holder, per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R11. The V3.x R4 (c) migration becomes *"Scanner
  stops holding spend material; delegates key-image
  generation to the existing `Signer` trait"* rather than
  designing the split from scratch — the spend-key-isolated
  actor target shape already exists in the codebase. See
  the FOLLOWUPS R4 (c) entry for the updated migration cost.

**Closed in Round 4 (2026-05-14).** All five "Remaining for
Round 4" items from prior round states are now closed; below
records the closure form per item.

- **§6 review checklist — closed.** Filled in this Round 4
  commit per the PR 5 §6 shape (binding-check matrix against
  `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.3, test-substrate
  preservation list, call-site sweep audit, Round 4
  readiness gate). All bracketed checklist items carry
  binding-pinned form.
- **§7 commit decomposition for Phase 1 — closed.** Lifted
  into a new §7.X subsection in this Round 4 commit; the
  eight-commit Phase 1 list (C0 spec amendment + C1–C8
  implementation) is sequenced load-bearing-ordered. The
  C4 `LocalRefresh` aggregate carries the §5.4.7 R4
  (a-instance-scoped) `ViewMaterial` + constructor + the
  per-attempt scanner-build move; C2 lands the coupled
  Phase 0e `RefreshDiagnostic` + `DiagnosticSink`
  substrate; C5 lands the coupled Phase 0c trait-surface
  change with `Engine` parameterization. The §5.4.4
  invocation-overhead constraint is satisfied by
  construction per the §7.X Phase 1 invocation-overhead
  gate.
- **§7 test-design pass — closed.** `AssertionSink`
  (coherence) and `PanickingSink` (panic-safety) land in
  Phase 1 commit C7 per the §6 test-substrate preservation
  list; the coherence test is canonical-reference per
  §5.4.6 emission/return-coherence pin; the panic-safety
  test verifies `Scanner` zeroization completion,
  cancellation-token consistency, and unwind-without-
  corruption per §5.4.6 producer-panic-safety pin.
- **§7 retry-loop-exhaustion call-site migration — closed.**
  Phase 1 commit C5 lands the migration of the two call sites
  at [`engine/refresh.rs:1672–1680`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  and [`:2055–2065`](../../rust/shekyl-engine-core/src/engine/refresh.rs)
  from `MalformedScanResult { reason: "..." }` to
  `InternalInvariantViolation { context: "..." }` per the
  Round 2 close-out Phase 0c amendment. The existing reason
  strings transcribe directly to the `context` `&'static str`
  values; no structural ambiguity at the commit-author's desk.
- **§7 producer-side classification of upstream
  `shekyl_rpc::RpcError` into `ProtocolErrorKind` — closed.**
  Phase 1 commit C5 lands the classification at the
  `RefreshDiagnostic::DaemonProtocolError`-emission boundary
  inside `LocalRefresh::produce_scan_result`. The Round 4
  audit (per §4 Phase 0e "Round 4 audit confirms" subsection)
  confirms the five-variant `ProtocolErrorKind` set
  (`ConnectionError`, `InternalError`, `InvalidNode`,
  `InvalidTransaction`, `PrunedTransaction`) is exhaustive
  for the refresh producer's call surface; `String` payloads
  do not propagate into the diagnostic stream per §5.4.7 R6
  memory-amplifier-vector closure.

All Round 4 deliverables are closed in this commit; the
implementation branch (`feat/stage-1-pr4-refresh-engine`) is
authorized to cut off the post-Round-4 dev tip per the §6
Round 4 readiness gate. No further design rounds open
unless Phase 1 commit-authoring surfaces a structural
finding (the Phase 0 binding-pin discipline is designed to
prevent that; the closure rule per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§7 governs reopening if it does).

**Closed in Round 4 review pass (2026-05-15).** A
pre-implementation adversarial review of the post-Round-4
substrate (full writeup at §5.4.9) produced **nine
actionable findings** — all dispositioned and applied
inline as substrate hardening rather than reopening any
Round 1–4 question. The findings cluster across three
threat-model surfaces: **feature-soft-commitment hardening**
(F1 R17 encrypted-persistence opt-in rewrite to hard
rejection with conditional reopening; F7 new §5.4.8 #6
"encrypted cache for RPC recovery" V3.x candidate
structurally rejected at V3.0 under symmetric criteria),
**checkpoint-discipline tightening** (F2 §3.1 lock-latency
property refined to per-transaction sub-block bound; §7
checkpoint discipline extended from four to **five**
checkpoints with the per-transaction inner cancellation
check), and **diagnostic-stream contract pinning** (F3
`AssertionSink` / `PanickingSink` pinned as permanent CI
regression coverage; F4 seventh contract pin
"per-emitter FIFO ordering preserved; cross-emitter ordering
undefined"; F5 §5.4.8 #4 V3.x forward-template for
aggregator-republisher recursive-leak mitigation; F6
producer-side per-class emission rate budget at §5.4.8 #5
plus the `SuppressedRateLimit` variant; F8 emit-timing
microarchitectural side-channel residual at §5.4.8 #7;
F9 §6 projection-type audit per event class with explicit
V3.0 per-class projections for `TracingDiagnosticSink`).
The α-disposition still holds; all Round 1–4 dispositions
still hold; the review pass hardens contract pins and
attack-surface dispositions. The §7.X commit decomposition
absorbs the substrate hardening: C2 carries the
`SuppressedRateLimit` variant + per-class projections + 7th
contract pin; C4 carries the per-transaction inner
cancellation check + producer-side per-class emission rate
budget enforcement; C7 carries `AssertionSink` /
`PanickingSink` as permanent CI fixtures rather than
landing-only tests; C8 carries the `CHANGELOG` entry
documenting the contract pins. New V3.1+ FOLLOWUPS entries
queue the F5 consumer-actor-PR aggregator-republisher
CI-lint enforcement and the F9 diagnostic-stream
spec-doc projection-type formalization. The implementation
branch authorization holds; the review pass shapes Phase 1's
substrate without reopening it.

**Closed in Round 4 review pass meta-review amendment
(2026-05-15).** A second-pass adversarial review of the
F1–F9 disposition substrate itself (full writeup at §5.4.9
"Meta-review amendment — F11–F13") produced **three
additional actionable findings** — F11 (per-transaction
cancellation safe-point pin: meta-review of F2), F12
(cross-emitter ordering contract-gap: meta-review of F4),
and F13 (`SuppressedRateLimit` field-shape pin: meta-review
of F6). Each targets an under-specification *introduced by*
an F1–F9 disposition rather than a substrate decision Rounds
1–4 settled; none reopens a Round 1–4 disposition; the
F1–F9 dispositions remain unchanged. **F11** pins the
per-transaction inner cancellation check fires *between*
transactions, *after* the prior iteration's per-output
materials have left scope, *before* the next transaction's
secret derivation begins (forbidding mid-derivation firing
that would defeat F2's lock-latency property). **F12** closes
the cross-emitter ordering enforcement gap at the discipline
level (V3.0: consumer actors deriving cross-emitter ordering
from causal-context fields) and at the lint level (V3.1+:
extending the FOLLOWUPS F5 lint to a unified
`diagnostic_consumer_discipline` lint covering both
recursive-trust-boundary and cross-emitter-ordering misuse
sub-scopes). **F13** pins `SuppressedRateLimit { class:
SuppressedClass }` carries class only — no count, no
timestamp, no original-event payload — preventing the
suppressed-event count from becoming an attacker covert
channel back from the producer's internal state. The §7.X
commit decomposition absorbs the meta-review hardening: C2
adds the `SuppressedClass` enum (project-defined
`#[non_exhaustive]`; nine-item flat-crate-root re-export
list); C4 extends the inner cancellation check description
with the binding safe-point firing site and the C7 fixture
deliverable; C7 gains the safe-point-firing assertion
fixture for `AssertionSink` / coherence-pair tests. The
FOLLOWUPS F5 entry is rewritten as the unified
`diagnostic_consumer_discipline` lint covering both F5 and
F12 sub-scopes. PR 5 §5.0.3 carries a parallel F12
enforcement-gap amendment so the symmetric pin in PR 5
carries the same binding discipline. The implementation
branch authorization continues to hold; the meta-review
amendment shapes Phase 1's substrate without reopening it
or extending its scope.

**Closed in Round 4 review pass meta-review post-amendment
sub-pins (2026-05-15).** A third-pass review of the F11–F13
dispositions themselves (full writeup at §5.4.9
"Post-amendment sub-pins — F11-S, F12-S, F13-S") produced
**three Phase-1-author-aware sub-pins** — F11-S (per-output
safe-point escalation criterion), F12-S
(`diagnostic_consumer_discipline` lint conceptual
unification), F13-S (`SuppressedRateLimit` emission-cadence
sub-pin). Each sharpens the corresponding F-finding's
disposition without reopening it; none reopens a Round 1–4
disposition; none reopens an F1–F13 disposition. **F13-S is
the substantive sub-pin**: F13's field-shape pin (carries
class only) closed the payload covert channel but left the
emission-cadence covert channel open — if the producer
emits one notice per suppression-fire, an attacker
reconstructs suppression frequency by counting notice
arrivals in their own emit-arrival timeline regardless of
payload shape. F13-S pins emission cadence at "at most one
`SuppressedRateLimit { class }` per class per attempt" via
a per-class `notice_emitted: bool` latch on the producer's
per-attempt `emit_state`; cross-attempt cadence is bounded
at the orchestrator's existing retry-loop policy layer
(producer-side cross-attempt state is foreclosed by the
zeroization scope for `ViewMaterial` and `Scanner`). **F11-S**
pins the per-output safe-point escalation criterion: Phase 1
commit-author verifies `recover_outputs_in_tx`'s benchmarked
per-output cost on reference hardware against the FCMP++
protocol-parameter upper bound on outputs per transaction; if
worst-case per-tx scan time exceeds the §3.1 lock-latency
target, the safe-point escalates to per-output granularity
(check between consecutive per-output decap iterations).
The C4 commit message records the measurement and the chosen
granularity, bisectable against the C4 commit boundary.
**F12-S** pins the conceptual-not-monolithic clarification
in the FOLLOWUPS `diagnostic_consumer_discipline` lint
entry: the unification is at the contract level (one named
discipline, two related properties); the implementation
strategy follows each property's nature (F5 sub-scope as a
type-level check + F12 sub-scope as an AST-level pattern
check is a valid factoring delivering the unified contract).
The §7.X commit decomposition absorbs the post-amendment
hardening: C4 carries the F11-S verification deliverable
and the F13-S `notice_emitted: bool` latch invariant; the
FOLLOWUPS entry carries the F12-S clarification. The
recursive structure (review pass → meta-review → post-
amendment) is the closure rule's reopening mechanism
operating at each level of the substrate hierarchy. The
implementation-branch authorization continues to hold; the
sub-pins shape Phase 1's substrate (in particular, C4's
commit-message audit-trail deliverable for the F11-S
benchmark measurement) without reopening it or extending
its scope.

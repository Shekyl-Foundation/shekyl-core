# Stage 1 PR 4 — `RefreshEngine` extraction — design

**Status.** **DRAFT — Round 1, Round 1 review pass, Round 2,
and Round 2 reframe closed (2026-05-13).** Round 1's load-bearing
question (§5 producer redesign) settled to **α — preserved
current shape** per §5.4. The Round 1 review pass (2026-05-12)
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
`MalformedScanResult`; no payload of any kind), and a parallel
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
R5 resolution in V3.x without re-opening PR 4's trait surface. This document was opened in parallel with the
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
  §5.4.8).** PR 4 separates the synchronous trait return from
  the actor-mesh diagnostic stream. The synchronous return
  (`RefreshError`) is **unit-variant-only** — no string, no
  evidence, no payload — so the orchestrator's branch table is
  structural (cancel-propagate / retry-with-backoff / peer-
  rotation) and the §5.4.5 memory-amplifier vector is closed
  by construction. The parallel `RefreshDiagnostic` event stream
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
- [x] Phase 0 spec amendments identified (§4 — populated by
      Round 1 review pass; Round 2 finalized against the
      resolved residuals).
- [ ] Phase 1 commit decomposition (§6 — pending Round 4;
      under (a-instance-scoped) the per-attempt scanner
      construction moves into `LocalRefresh::new` and the
      per-call setup cost drops, satisfying the §5.4.4
      invocation-overhead constraint by construction).

---

## §4 Phase 0 candidates (TBD)

Phase 0 doc-only spec amendments precede Phase 1 implementation
per the PR 2 / PR 3 precedent. Candidates surface as the design
rounds progress; this section is the holding place.

**Currently identified candidates (subject to revision; the
Round 1 review pass populated this list against the seed's
"likely empty under α" framing).**

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
  the Round 1 review pass populated it; Round 2 finalized.
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
  (Round 2 reframe).** Per §5.4.7 R6 reframe: trait-level
  `RefreshError` is **unit-variant-only** — `Cancelled` /
  `Io` / `MalformedScanResult` — with no payload of any kind.
  The synchronous trait return is the structural-branch
  signal; the rich diagnostic information moves to Phase 0e
  below. `Self::Error: Into<RefreshError>` in the trait
  surface; orchestrator's existing `RefreshError` enum is
  retained for backward compatibility (it adds
  `ConcurrentMutation`, `AlreadyRunning` at the merge layer,
  and carries `&'static str` reason content on its
  `MalformedScanResult` variant constructed orchestrator-side
  from the unit-variant trait tag plus orchestrator context —
  no attacker-controlled trait payload). `ReorgTooDeep` stays
  as Ok-with-rewind merge-layer detection per the §1.5
  actor-identity reasoning.
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
- **Round 3 (deferred to PR 5).** R1 lands in PR 5's design
  rounds; PR 4 does not need a separate Round 3. The α-disposition
  remains *provisionally load-bearing* per the original Round 1
  framing — if PR 5's R1 resolution requires γ for correctness,
  PR 4 re-opens; otherwise PR 4 advances directly to Round 4.
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
  §5.3) means R1's resolution can re-open α — if the
  reservation tracker's correctness property cannot hold under
  any sub-option, the rounds budget reverts to γ — but
  snapshot-ID pinning makes that revert unlikely.
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
  events **must** be inside the wallet trust boundary. PR 4
  refuses to design the diagnostic-stream surface around the
  case where they are not. Stage 4's actor topology design
  must respect this; the trait-contract pin exists so Stage 4
  cannot accidentally cross the boundary by routing
  `RefreshDiagnostic` events through a less-trusted actor
  (e.g., a remote crash reporter, a telemetry pipeline with
  network sinks, or a tracing infrastructure with off-host
  storage).
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 prose amendment in Phase 0a. Enforceable by review,
  not by the type system — Stage 4's review checklist
  includes the per-consumer trust-boundary audit.

### §5.4.7 Round 2 dispositions — R2–R7 settled (2026-05-12)

Round 2 closes all seven residuals from §5.4.3 plus the §5.4.6
trait-contract pins. PR 4's design surface is now Phase-0-ready;
Round 4 carries the commit decomposition.

#### R1 — `PendingTxEngine::build` during long refresh

**Disposition.** Carry forward to PR 5's design rounds with
**build-against-current-snapshot + snapshot-ID pinning** as the
working hypothesis. Reservation tracker carries a snapshot ID
per reservation; submit path becomes a CAS against
`current_snapshot == reservation.snapshot_id`. PR 5 opens with
this hypothesis and looks for a reason to reject it; the
α-disposition's *provisionally load-bearing* status (per §5.3)
remains the re-evaluation gate.

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
/// **Trust-boundary contract (§3.1, §5.4.6 pin).** Sink
/// implementations route full-fidelity events only to
/// in-process consumers inside the wallet trust boundary.
/// Cross-process or network-bound consumers receive only
/// projection types that have been explicitly sanitized at
/// the boundary. This is the production/debug-log-separation
/// principle applied at the messaging layer.
pub trait DiagnosticSink: Send + Sync + 'static {
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

Phase 1's commit decomposition (Round 4) sequences these
amendments: the unit-variant `RefreshError` and the
`DiagnosticSink` parameter on `produce_scan_result` land in
the same commit as a coupled signature change; the
`RefreshDiagnostic` enum's initial variant set lands
adjacent; the consumer-side actors (`PeerReputationActor`,
`RecoveryActor`, `ReorgAmplificationDetector`) land in the
V3.x actor-mesh PR per the FOLLOWUPS entries added in this
commit.

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

This conflicts with classical fail2ban's "remember bad actors
across sessions" disposition; the conflict is genuine, and
**privacy-first wins** per the priority hierarchy. Shekyl's
fail2ban is intra-session and resets on close.

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
side channel — exactly the kind of property the §3.1 master-
secret-isolation framing tries to prevent.

**Mitigation pin (trait contract, §5.4.6).** Full-fidelity
`RefreshDiagnostic` events flow only to **in-process** actors
inside the wallet trust boundary. Cross-process or network-
bound consumers receive only **projection types** that have
been explicitly sanitized at the boundary — counts and
aggregates, not events. This is the same principle as
production/debug log separation, enforced at the messaging
layer rather than the logging layer.

The trait-contract pin is enforceable by review (consumer
actors are reviewed against this rule) but not by the type
system; Stage 4's actor topology design must respect it.
Phase 0a §2.3 prose amendment pins the rule so future
implementations cannot accidentally cross it.

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
| `PendingTxEngine::build` behaviour during long refresh (R1) | V3.0 (PR 5 design rounds) | §5.4.7 R1; carried into PR 5 with **build-against-current-snapshot + snapshot-ID pinning** as the working hypothesis |
| `RefreshOptions` / `RefreshProgress` public-module promotion (R3) | **closed (Round 2)** | §5.4.7 R3 — confirmation: types already publicly re-exported at flat crate root; no module promotion |
| View-material flow to the producer (R4) | **closed (Round 2)** | §5.4.7 R4 — disposition **(a-instance-scoped)**: `LocalRefresh::new(view_material: ViewMaterial)`; `ViewMaterial` type lands in Phase 0a |
| Mid-scan reorg-abort at checkpoint 3 (R5) | **retired by composition (Round 2 reframe)** | §5.4.7 R5 (reframe) — resolved by `ReorgAmplificationDetector` actor consuming `RefreshDiagnostic::ReorgObserved` events; producer's §7 checkpoint discipline does not grow; consumer-actor implementation deferred to V3.x actor-mesh PR. Supersedes Round 2's first-pass "defer + extend checkpoint 3" disposition |
| `RefreshError` shape (R6) | **reframed (Round 2 reframe)** | §5.4.7 R6 (reframe) — two-channel: unit-variant `RefreshError` (`Cancelled` / `Io` / `MalformedScanResult`; no payload) + `RefreshDiagnostic` event stream + `DiagnosticSink` trait. Supersedes Round 2's first-pass `MalformedScanResult { reason: &'static str }` disposition; closes the memory-amplifier vector by construction |
| `RefreshDiagnostic` + `DiagnosticSink` (Round 2 reframe; Phase 0e) | V3.0 (Phase 0e) | §5.4.7 R6 (reframe), §4 Phase 0e — enum + trait + `produce_scan_result` signature change; Stage 1 sinks: `NoopDiagnosticSink`, `TracingDiagnosticSink` |
| Diagnostic-stream attack surfaces (peer-reputation fingerprint; PeerId stability under Tor/I2P; rotation-timing side-channel; covert-channel; mailbox saturation) | V3.0 trait pin + V3.x consumer-side enforcement | §5.4.8 (Round 2 reframe) — mitigation pins land in Phase 0a / Phase 0e prose; consumer-side enforcement (in-memory-only reputation, jittered rotation, projection-only cross-boundary consumers, bounded mailboxes) lands in V3.x actor-mesh PR |
| `ReorgAmplificationDetector` consumer actor | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: when Stage 4 actor mesh stabilizes |
| `PeerReputationActor` consumer actor (fail2ban-style intra-session) | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: when Stage 4 actor mesh stabilizes; per §5.4.8 #1 mitigation pin (in-memory only, drop on wallet close) |
| `RecoveryActor` consumer actor (pattern-based recovery / Byzantine-fault-tolerance) | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: when Stage 4 actor mesh stabilizes |
| `RefreshDiagnostic` peer-attribution variant extension (gated by PR 1 `DaemonEngine` peer-aware surface) | V3.x | Stage 1 emits peer-less variants; the `RefreshDiagnostic` enum's `#[non_exhaustive]` attribute lets PR 1's peer-aware DaemonEngine surface land with additive variant additions per §5.4.8 #2 |
| `ScanResult` atomicity-under-cancellation contract (R7) | **closed (Round 2)** | §5.4.7 R7 — already true in `engine/refresh.rs`; pinned in §2.3 prose (Phase 0a) |
| Three call modes (cold open / steady-state / post-submit) — invocation-overhead constraint | V3.0 (Round 4 commit decomposition) | §5.4.4 — under (a-instance-scoped) the per-attempt scanner construction moves into `LocalRefresh::new`, satisfying the constraint by construction |
| Adversarial daemon scenarios under α (reorg amplification, view-tag DoS, withholding, snapshot poisoning, evidence amplifier) | mostly closed (Round 2); reorg amplification deferred via R5 | §5.4.5; mitigations: R5 (V3.x deferral), R6 keeps `&'static str` evidence (strictly bounded), Phase 0a `LedgerSnapshot` value-typed confirmation |
| Trait-surface contract pins (`Send + Sync + 'static` on `R`; Progress-channel trust boundary) | **closed (Round 2)** | §5.4.6; both pinned as Phase 0a prose amendments |
| (c) split-producer/recoverer view-material shape (R4 deferral) | V3.x | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.x entry added in this commit; trigger: HW-wallet-backed signing or post-V3 threat-model refinement requires producer-side spend-key isolation |
| `ViewMaterial` type definition (R4 — Phase 0a) | V3.0 (Round 4 / Phase 0a) | §5.4.7 R4 — public type in `shekyl_engine_core` carrying spend-pub + view-scalar + x25519-sk + ml-kem-dk + spend-secret; `Zeroize + ZeroizeOnDrop` |

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
The Round 1 review pass (2026-05-12) corrected §3.1 and surfaced
R4–R7 plus the §5.4.4 call-mode constraint, the §5.4.5 adversarial
scenarios, and the §5.4.6 trait-surface contract pins. Round 2
(2026-05-12) settled R1 / R2 / R3 / R4 / R7 cleanly. **Round 2
reframe (2026-05-13) supersedes Round 2's R5 and R6 dispositions**
with the two-channel actor-mesh shape (§5.4.7 R5 reframe, R6
reframe, §5.4.8 attack surfaces). Only Round 4 remains as
PR-4-internal work.

**Carried into PR 5.**

- §5.4.7 R1 (`PendingTxEngine::build` behaviour during long
  refresh) — PR 5's design rounds open with
  *build-against-current-snapshot + snapshot-ID pinning* as the
  working hypothesis. The α-disposition remains *provisionally
  load-bearing*; if PR 5's R1 resolution requires γ for
  correctness, PR 4 re-opens.

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
  requires producer-side spend-key isolation.

**Remaining for Round 4.**

- §6 review checklist — fills in once Phase 0 commit
  decomposition is known.
- §7 commit decomposition for Phase 1 — under §5.4.7 R4
  (a-instance-scoped) the first commit introduces `ViewMaterial`
  and the constructor; the per-attempt scanner build moves out
  of `run_refresh_task` and into `LocalRefresh`'s state. The
  Round 2 reframe adds two coupled signature changes (Phase 0c
  unit-variant `RefreshError`; Phase 0e `DiagnosticSink`
  parameter on `produce_scan_result`) that land in the same
  commit as a coupled trait-surface change; the `RefreshDiagnostic`
  enum's initial variant set lands adjacent. The §5.4.4
  invocation-overhead constraint is satisfied by construction
  (no per-call setup added beyond the parameter passes).

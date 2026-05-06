# Stage 1 PR 3 — `KeyEngine` extraction — design

**Status.** Round 1 (in-flight). Stage 1 PR 3 of the seven-trait
extraction chain pinned in
[`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§8.1, named explicitly as PR 3 in
[`docs/design/STAGE_0_HARNESS.md:1722`](STAGE_0_HARNESS.md) and
[`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md)
§2.2 ("PR 3 (`KeyEngine` per §8.1)").

This document is the durable in-repo design contract for PR 3's spec
amendments and substantive implementation. It mirrors
[`STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md)'s
structure but is keyed to a substantially larger pre-flight drift
surface than PR 2's: PR 2 surfaced 3 amendments across pre-flight
+ commit-time + post-merge; PR 3's pre-flight pass surfaces 5
amendments at the design-doc stage, with 2 of them §7-non-compliant
(re-opening the spec for a new round). The drift count is not a
defect — it is the discipline working as designed against a trait
whose §2.1 surface predates the workspace's hybrid-cryptography
framework solidification (see §2.1 below).

## Round trajectory

- **Round 1 (this commit).** Pre-flight gap-check captures all 5
  drift bundles below; substantive design choices pinned per the
  user's Decision-1-through-Decision-5 reasoning recorded in §3;
  trait-surface diff for the post-amendment §2.1 shape staged in
  §4; sequencing for preparatory amendment PRs and the optional
  preparatory code PR (`AllKeysBlob` `ZeroizeOnDrop` migration)
  staged in §5.
- **Round 2+ (forthcoming).** Reviewer challenges to the trait
  surface diff and the per-bundle dispositions; the negative-space
  anchor for `KeyEngineError` (§3.2) is the most likely site for
  Round 2 surfacing. Per
  [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)'s
  4–6-rounds-before-implementation rule for crypto-critical trait
  migrations, PR 3 cannot cut a feat branch until at least Round 2's
  acceptance signal lands.

The long-form draft history will live ephemerally in
`.cursor/plans/stage_1_pr_3_plan_*.plan.md`; this document is the
durable equivalent.

---

## 1. Scope

### 1.1 Phases 0–0d — spec amendments (doc-only, prerequisite)

Five amendment bundles to
[`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.1, each landing as a single-commit PR against `dev` per
PR 2's amendment-shape precedent (PRs #22, #23, #25). Two of the
five (Phases 0 and 0b) are non-additive and re-open §2.1 for a new
round per §8.2's closing clause; three (Phases 0c, 0d, 0e) are
additive and absorb under §8.2's two-commit form.

| Phase | Subject | Shape | §7 status |
|---|---|---|---|
| 0 | Workflow-shape pivot (primitive-shape `view_ecdh` / `hybrid_decapsulate` / `sign_with_spend` replaced by workflow-shape `try_claim_output` / `sign_transaction`; hybrid-framework reconciliation absorbed) | Doc-only spec amendment | **Re-opens §7** |
| 0b | `KeyError` / `KeyEngineError` split | Doc-only spec amendment | **Re-opens §7** |
| 0c | Workflow-internal types + message shapes for cross-boundary travel (Sub-bundle A: `pub(crate)` impl-internals — `SignDomain`, `AccountPublicAddress`; Sub-bundle B: trait-surface message shapes — `OutputDetectionInput`, `OutputClaimResult`, `OutputClaim`, `TxToSign`, `TxSignatures`, `SubaddressPurpose`, `SubaddressFor`, `RecipientSubaddress`, `SubaddressKeyPair`, `ViewTag`) | Doc-only spec amendment | Additive |
| 0d | `pub(crate)` visibility + `Send + Sync + 'static` super-bound + Q9.3 disposition correction | Doc-only spec amendment | Additive |
| 0e (optional, code) | `AllKeysBlob` migrated to `#[derive(Zeroize, ZeroizeOnDrop)]` | Code PR in `shekyl-crypto-pq` | Out of §2.1 scope (precondition correction) |

**Phase 0c sub-bundle structure.** Sub-bundle A (workflow-internal types) lives behind the trait surface as `pub(crate)` impl-internals — `SignDomain` is no longer a trait-level concept; it cryptographically separates HKDF contexts inside `LocalKeys`'s impl. Sub-bundle B (message shapes) is the actor-message granularity at which `KeyEngine` exposes work; each shape is a structured non-secret bundle that crosses the trait boundary in place of the primitive-shape signatures the pre-amendment §2.1 named. Stub-quality shapes land in commit 1 of this design-doc round; concrete field sets land in commit 2 (and accept Round-3+ refinement against PR 5's `PendingTxEngine` constraints).

§3 below names each bundle's substantive content. §5 names the
sequencing.

### 1.2 Phase 1 — implementation

Phase 1 lands the post-Phase-0d §2.1 trait surface and
parameterizes `Engine<S, D, L>` over a fourth type parameter
`K: KeyEngine`:

- **Trait surface.** `pub(crate) trait KeyEngine: Send + Sync +
  'static` with four methods (post-amendment shape in §4);
  declared in `rust/shekyl-engine-core/src/engine/traits/key.rs`,
  re-exported from `traits/mod.rs`.
- **Implementing aggregate.** `pub struct LocalKeys { keys:
  AllKeysBlob }` (or similar; precise wrapper shape pinned at
  commit time per PR 2's degrees-of-freedom precedent). Held as
  `keys: LocalKeys` on `Engine`'s state. `LocalKeys` exposes
  `from_seed(seed: &WalletSeed) -> Result<Self, KeyError>` for
  the production wallet-create path and a `#[cfg(test)]
  from_test_seed(test_label: &str) -> Self` constructor for
  authentic-crypto test fixtures (per §6.4's no-Mock test-substrate
  pattern).
- **`Engine` parameterization.** `Engine<S, D: DaemonEngine =
  DaemonClient, L: LedgerEngine = LocalLedger, K: KeyEngine =
  LocalKeys>` extends PR 2's three-parameter shape.
  `OpenedEngine<S, D, L, K>` carries the same parameterization.
- **`async fn` for workflow ops.** `try_claim_output` and
  `sign_transaction` are `async fn` per Q9.1 (Stage-4-actor
  compatibility); the sync-shape methods (`account_public_address`,
  `derive_subaddress`) stay sync.
- **Test substrate.** **No `MockKeys` type.** Production-only
  `LocalKeys` with `from_test_seed` covers authentic-crypto tests;
  a composable `FaultInjecting<K: KeyEngine>` wrapper (`#[cfg(test)]`-
  gated) covers failure-injection tests by composition rather than
  by parallel implementation. See §6.4 for the broader Mock-X
  rejection rationale and §2.1's forward-template addendum for the
  pattern's generalization to PR 4–7 and the retroactive-cleanup
  scheduling for PR 1's `MockDaemon` / PR 2's `MockLedger`.
- **Hybrid test.** One end-to-end test exercising one §5.2 property
  PRs 1–2's hybrid tests have not yet covered (per PR 2's
  forward-template — §6.4 below names the candidate property).

This design doc does not pin every method body. PR 3 has degrees
of freedom on internal structure; those decisions land at commit
time and surface in code review.

---

## 2. Pre-flight discipline pattern — what PR 3 contributes to the
template

PR 2's
[design doc §2.2](STAGE_1_PR_2_LEDGER_ENGINE.md) framed pre-flight
as "one of several discovery points" and budgeted 1–3 spec drifts
per per-trait PR. PR 3 surfaces 5 drifts at pre-flight alone; this
section names what PR 3 contributes to the forward-discipline
pattern that PR 2 established.

### 2.1 Hybrid-framework drift is a class, not a coincidence

PR 3's biggest drift bundle (Phase 0 — hybrid-framework
reconciliation) is structurally the same shape as PR 2's Phase 0c
(`transfers()` removal for `!Clone` discipline), but generalized
to a different rule:

- **PR 2 Phase 0c:** the workspace's `!Clone` security discipline
  (TransferDetails) made a trait signature unsatisfiable. The
  disposition was to align the trait with the discipline, not to
  break the discipline to satisfy the trait.
- **PR 3 Phase 0:** the workspace's hybrid-by-default cryptography
  discipline ([`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc)'s
  "Hybrid post-quantum is the default") made `sign_with_spend →
  Ed25519Signature` and `ml_kem_decapsulate(MlKemEncapsulation) →
  MlKemSharedSecret` rule-violating. The disposition is to align
  the trait with the discipline, not to expose classical-only
  primitives at the trait surface.

Both are instances of a general pattern: **§2.X surfaces written
before a workspace-discipline anchor solidified will accumulate
drift against that anchor that pre-flight surfaces only when the
trait extraction begins.** PR 4–7 authors should expect drift of
this class against any rule whose enforcement tightened between
the spec's Round 1 (October 2026) and the per-trait PR's pre-flight.

The named candidates worth pre-flight-checking explicitly for
PR 4+:

- `30-cryptography.mdc` "domain separators on every hash" rule —
  any trait method consuming hashed material should expose the
  domain separator at the trait surface, not bury it in the impl.
- `30-cryptography.mdc` "wide-reduce, not modular reduction" rule
  — any trait method returning derived scalars should specify the
  reduction width.
- `35-secure-memory.mdc` "structural memwipe" rule — any trait
  method returning secret-bearing types must expose them through
  `Zeroizing<T>` or a struct with `#[derive(Zeroize, ZeroizeOnDrop)]`,
  not raw byte arrays.

PR 3's Phase 0 amendment block is explicit that the rewrite
reconciles §2.1 with the post-hybrid-framework reality, not just
"two signature drifts." This framing is the contribution PR 3
makes to the forward-template: future readers asking "why did §2.1
get a non-additive rewrite" find the answer in the amendment block,
not in commit-message archaeology.

#### 2.1.1 Workflow-shape vs. primitive-shape trait surfaces

PR 3's Round 2 review surfaced a second class of drift: §2.1's
original `KeyEngine` named primitive-shape methods (`view_ecdh`,
`hybrid_decapsulate`, `sign_with_spend`) that exposed cryptographic
intermediates at the trait boundary. The pivot to workflow-shape
methods (`try_claim_output`, `sign_transaction`) is itself a
generalizable pattern worth pinning for PR 4–7:

> **Trait surfaces designed against actor-message granularity
> rather than primitive-operation granularity reduce cross-boundary
> leakage and compose better with Stage 4's actor abstraction.**

The structural property: actor-grain trait surfaces produce
structured non-secret outputs and keep cryptographic intermediates
(raw shared secrets, HKDF intermediates, per-domain HKDF context)
confined to the implementor's stack frame. Primitive-grain trait
surfaces force the orchestrator's address space to hold those
intermediates across the trait boundary, which is exactly the
property `35-secure-memory.mdc`'s zeroize-discipline is fighting.
Stage 4's actor abstraction (`Arc<dyn KeyEngine>` across a
message-passing channel) makes the cost concrete: every primitive-
grain method becomes a separate channel send/receive carrying a
secret-bearing message; every workflow-grain method bundles the
primitive sequence into one round-trip carrying only structured
non-secret outputs.

The pattern's evidence sites for PR 4–7:

- `PendingTxEngine` (PR 5): "build a transaction" should be a
  workflow method bundling output selection + change derivation +
  per-input signing context preparation, not separate primitive
  methods. Primitives should live inside the impl, not at the
  trait surface.
- `RefreshEngine` (PR 6 or wherever scanner orchestration lands):
  "scan a block range" should be a workflow method bundling
  output detection + key-image derivation + balance update; the
  scanner's two-step view-tag pre-filter / hybrid decap pattern
  is implementation orchestration hidden behind the workflow
  boundary.
- `MultisigEngine` (Stage 2): "produce a partial signature" is a
  workflow method; "compute partial Schnorr challenge" is an
  impl-internal primitive.

The contribution PR 3 makes to PR 4–7's pre-flight discipline is
naming this lens explicitly. Pre-flight checklists should ask
"does this trait method expose a primitive or a workflow?" and
"would Stage 4's actor abstraction force secret-bearing messages
across the channel boundary?" — primitive answers signal the same
class of drift PR 3's pre-flight surfaced.

#### 2.1.2 The Mock-X pattern is wrong as a category

PR 3's L3.3 review surfaced a third class of drift: the `MockKeys`
type the Round 1 draft proposed (and the inherited `MockLedger` /
`MockDaemon` types from PR 2 / PR 1) instantiate a Mock-X pattern
that's wrong as a category, not just in any individual case. The
pattern's failure modes:

- **Adds attack surface.** Test-only types in production code;
  visibility-constraint dependencies; build-config edge cases that
  test paths exercise but production paths don't.
- **Conflates test-controlled inputs to real implementations with
  test substitute implementations.** Different operational shapes
  that get the same naming. A real implementation seeded with
  deterministic test inputs is structurally different from a fake
  of an implementation, and naming them both `MockX` hides the
  distinction.
- **Inherits a Monero pattern that has produced real bugs in the
  inherited codebase.**
- **Doesn't compose with future implementors** (HSM-backed,
  hardware-key) — each implementor would need its own Mock variant,
  and tests verifying against fake semantics rather than real
  semantics multiply with the implementor count.
- **Encourages tests to verify against fake semantics rather than
  real semantics.** The test suite's coverage claim degrades:
  "tested" means "tested against the Mock," not "tested against
  the production implementation."

PR 3 lands the no-Mock pattern at the per-trait PR cut-point. The
replacement: **production-only `LocalKeys`** with a `from_seed`
constructor for production and a `#[cfg(test)] from_test_seed`
constructor for test fixtures (deterministic, publicly-known seed;
the `#[cfg(test)]` visibility constraint structurally enforces
"production code MUST NEVER call this constructor"); plus a
**composable `FaultInjecting<K: KeyEngine>` wrapper** for
failure-injection tests, which composes with any `K: KeyEngine`
implementor (`FaultInjecting<LocalKeys>` for fault tests against
authentic crypto; `FaultInjecting<HsmBackedKeys>` for future HSM
impls). No parallel implementation. Production code paths are the
only paths exercised; the only test-specific elements are the
deterministic seed (input) and the wrapper (failure injection on
top of the real impl). See §6.4 for the per-PR substrate
disposition.

The retroactive cleanup of PR 1's `MockDaemon` and PR 2's
`MockLedger` is **not** worth retroactive churn within those
already-merged PRs; instead it lands alongside their own
trait-extraction work in PR 4 or PR 5. The cases are structurally
different:

- **`MockLedger` → `LocalLedger::from_test_blocks(...)` +
  `FaultInjecting<LocalLedger>`.** The parallel-implementation
  pattern is wrong-by-shape; clear-cut deletion.
- **`MockDaemon` → `TestDaemon` rename.** The structural shape is
  fine — real `DaemonClient` requires network connectivity, so the
  test-substitute is a legitimate alternative real implementation
  that serves canned/cached test responses without network. The
  "Mock" naming is the bug; it inherits the conflation that the
  broader Mock-X rejection identifies. The fix is a rename to
  `TestDaemon` (signaling "alternative real implementation for
  tests" rather than "fake of an implementation") with the same
  shape.

The scheduling is concrete, not aspirational: see
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) entries (added in this
spec round) carrying explicit V3.0-baseline targets per
`15-deletion-and-debt.mdc`'s "no graveyard" rule.

### 2.2 Cumulative §5.2 hybrid-test coverage so far

Per PR 2 §2.3's forward-looking framing, each per-trait PR's
hybrid test exercises one §5.2 property predecessors have not yet
covered. The cumulative state going into PR 3:

| PR | §5.2 property exercised |
|---|---|
| PR 1 (`DaemonEngine`) | Happy-path producer/consumer plumbing under failure-injection-free conditions |
| PR 2 (`LedgerEngine`) | Retry-contract failure path with explicit failure injection via `MockLedger` |
| **PR 3 (`KeyEngine`)** | Layered-call error preservation when a runtime key-op error propagates through `Engine<S>`'s wallet-level methods. |

§6.4 records the rationale for selecting layered-call error
preservation over the alternative cancel-class candidate that
appeared in earlier Round-1 drafts. The cancel-class candidate is
**not** preserved here as a forward-looking row for a future
per-trait PR — if a subsequent per-trait PR's pre-flight surfaces
a concrete observable-residual story justifying it, that PR's
design doc introduces the candidate then. Anti-pattern of
preserving "speculative future may exercise" rows in the cumulative
table (rejected for the same reason as PR 2's `BalanceSummary →
Balance` rename deferral row).

### 2.3 This document is the source-of-truth for PR 3's scope

Mirrors PR 2 §2.4. Per
[`.cursor/rules/91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc),
the plan file
(`.cursor/plans/stage_1_pr_3_plan_*.plan.md`) is the long-form
draft history; this document is the durable in-repo equivalent.
PR-3 reviewers verify against §6 below; the plan's pre-design
wording is historical context, not a checklist.

---

## 3. The five amendment bundles

Each subsection records the user's substantive reasoning verbatim
where the reasoning carries the disposition; the prose around it
is editorial framing for the design-doc audience.

### 3.1 Phase 0 — workflow-shape pivot (hybrid-framework reconciliation absorbed) (§7-non-compliant, primary)

**Drift.** §2.1 names `sign_with_spend → Ed25519Signature` and
`ml_kem_decapsulate(MlKemEncapsulation) → MlKemSharedSecret`,
along with `view_ecdh → SharedSecret`. Two intersecting drifts:
(a) the named return types violate
[`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc)'s
"hybrid post-quantum is the default" rule (classical-only return
types are V4 deletion debt today); and (b) all four methods are
**primitive-shape** — they expose cryptographic intermediates
(raw shared secrets, individual signatures over individual
messages) at the trait boundary, which forces the orchestrator's
address space to hold secret-bearing intermediates across that
boundary in violation of the property §2.1.1 names. Round 1 of
this design doc treated drift (a) as the primary concern;
Round 2 surfaced (b) as the deeper concern, of which (a) is a
symptom.

**Disposition.** **(i) Pivot to workflow-shape.** The amendment
removes `view_ecdh`, `hybrid_decapsulate`, and `sign_with_spend`
from the trait surface entirely; introduces `try_claim_output`
(workflow bundling X25519 view-tag pre-filter + hybrid decap +
HKDF chain + key-image computation) and `sign_transaction`
(workflow bundling per-input signing context preparation +
hybrid signature production + FCMP++ witness generation) in
their place; absorbs the hybrid-framework reconciliation as a
consequence of the larger pivot (the classical types
`Ed25519Signature`, `EdwardsPoint`, `MlKemEncapsulation`,
`MlKemSharedSecret` cease to appear at the trait surface; the
hybrid types `HybridSignature`, `HybridCiphertext`, `SharedSecret`
also cease to appear at the trait surface — they all live inside
the workflow methods' impls). The post-amendment trait surface
exposes only structured non-secret message shapes
(`OutputDetectionInput`, `OutputClaimResult`, `TxToSign`,
`TxSignatures`, etc.); see §3.3 Sub-bundle B and §4 for the
post-amendment trait surface.

**Reasoning (recorded verbatim).**

> 1. **Rule-compliance is a hard constraint, not a preference.**
>    `30-cryptography.mdc` "hybrid is the default" is workspace-
>    policy at the rule level, the same way `00-mission.mdc`
>    priority 1 is mission-level. Trait surfaces that violate
>    workspace policy are wrong by precondition. The spec's
>    classical-primitive language is a stale artifact of pre-hybrid
>    drafting; the workspace has moved past it; the trait must
>    move past it too.
>
>    This is structurally the same shape as Phase 0c's discipline:
>    when the workspace's security discipline (`Clone`-discipline
>    for `TransferDetails`) made a trait signature unsatisfiable,
>    the disposition was to align the trait with the discipline,
>    not to break the discipline to satisfy the trait. Same
>    argument applies here: when the workspace's security
>    discipline (hybrid-by-default) makes a classical-only trait
>    signature wrong, the disposition is to align the trait with
>    the discipline, not to expose classical-only primitives at
>    the trait surface.
>
> 2. **Workspace-alignment is operationally necessary, not
>    aesthetic.** The implementing types (`HybridSignature`,
>    `HybridCiphertext`) already exist; they're what the codebase
>    actually uses; the C++ FFI shim, the wallet2 layer, the
>    eventual Rust JSON-RPC server all pass these hybrid types. A
>    trait that returns `Ed25519Signature` would force every
>    caller to either decompose the workspace's hybrid types into
>    their classical halves (losing the hybrid invariant) or wrap
>    them back into a hybrid construct after the trait call
>    (adding a useless round-trip).
>
>    (ii) "spec stays classical, impl is hybrid internally"
>    doesn't actually exist as a sustainable shape. The trait
>    would either lie about what it produces (returning a typed
>    `Ed25519Signature` that's actually been hybrid-augmented
>    somewhere) or split the return into "what the trait promises"
>    vs "what the impl additionally produces" — both options
>    destroy the trait's contract integrity.
>
>    (iii) "two separate methods" is rejected for the right
>    reason: it composes badly. Hybrid-as-one-call is the
>    workspace's actual ergonomic shape; a trait that decomposes
>    into classical and PQC halves is a regression on the
>    ergonomic property the workspace's hybrid types specifically
>    deliver.
>
> 3. **The amendment block needs to acknowledge this isn't just
>    signature drift; it's framework drift.** §2.1 was written
>    before the workspace's hybrid framework solidified into
>    types. The amendment isn't "fix two signatures"; it's
>    "reconcile §2.1 with the post-hybrid-framework reality." The
>    amendment should be explicit about this so future readers
>    understand why the change feels structural rather than
>    mechanical.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection).**

> §2.1 was authored when the cryptographic abstractions were
> named in classical-primitive terms (`Ed25519Signature`,
> `ml_kem_decapsulate`); the workspace has since solidified
> hybrid-primitive types
> ([`shekyl-crypto-pq::signature::HybridSignature`](../../rust/shekyl-crypto-pq/src/signature.rs),
> [`shekyl-crypto-pq::kem::HybridCiphertext`](../../rust/shekyl-crypto-pq/src/kem.rs))
> per [`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc).
> Round 2 of the spec amendment pivots further: the trait surface
> moves from primitive-shape (individual signatures, individual
> shared secrets) to workflow-shape (`try_claim_output`,
> `sign_transaction`), keeping all cryptographic intermediates —
> including the hybrid types themselves — confined to the
> implementor's stack frame. The hybrid-framework reconciliation
> is absorbed into the workflow pivot rather than landing as an
> independent rewrite. The trait's signatures change shape; the
> underlying capability ("derive output secrets for an incoming
> output"; "produce all signatures for a transaction") is
> unchanged.

**Note on the verbatim reasoning above.** The reasoning bullets
are recorded as written when the disposition was "rewrite the
trait surface from classical primitives to hybrid primitives."
Round 2's pivot to workflow-shape supersedes the disposition
without invalidating the reasoning — the hybrid-by-default rule
still binds (the workflow methods produce hybrid signatures and
consume hybrid ciphertexts internally), the workspace-alignment
argument still holds (hybrid types live inside the impl), and the
"two separate methods" rejection still holds (the workflow shape
is a structurally tighter version of the same composition
property). The amendment block above is the post-pivot framing;
the reasoning is the pre-pivot context that fed it.

### 3.1.1 Scanner two-step pattern is implementation orchestration hidden behind the workflow boundary

The Round 1 draft of this subsection asked whether `view_ecdh` and
`hybrid_decapsulate` are redundant at the trait surface and
concluded that both should stay because they serve structurally
different ends in the scanner's output-detection flow. Round 2's
review surfaced a deeper structural answer: **neither belongs at
the trait surface at all.** The scanner's two-step output-detection
pattern is implementation orchestration, not trait-shape; pushing
it behind a workflow boundary (`try_claim_output`) is the
post-pivot disposition.

**The scanner's two-step output-detection pattern (impl-internal).**
The actual scanner code in
[`shekyl-crypto-pq::output::scan_output`](../../rust/shekyl-crypto-pq/src/output.rs)
(lines 297–317) reveals the structural shape:

- **Step 1 (X25519 view-tag pre-filter).** Classical X25519 ECDH
  against the X25519 ephemeral from `HybridCiphertext.x25519`.
  Produces a 32-byte raw shared secret. Used as input to view-tag
  derivation, which serves as a cheap pre-filter: most outputs
  aren't yours, view-tag mismatches reject them without doing the
  expensive PQC half.
- **Step 2 (full hybrid decap).** Full hybrid KEM decap against
  the entire `HybridCiphertext`. Produces a 64-byte hybrid shared
  secret. Only runs for outputs that passed the step-1 view-tag
  check. Feeds the HKDF chain that derives output-secret material
  and the per-output key image.

In the post-amendment trait surface, this entire pattern lives
**inside** `LocalKeys::try_claim_output`'s impl. The X25519 raw
shared secret, the 64-byte hybrid shared secret, and the HKDF
intermediate keying material exist only transiently in the
implementation's stack frame; they are zeroized on drop per the
workspace's `Zeroize` / `ZeroizeOnDrop` discipline; nothing crosses
the trait boundary except the structured non-secret
`OutputClaimResult` (Mine with structured claim, or NotMine).

**Why the workflow boundary is the right shape (recorded
verbatim).**

> 1. **Primitives don't cross actor boundaries.** Stage 4's actor
>    abstraction (`Arc<dyn KeyEngine>` across a message-passing
>    channel) makes the cost concrete: every primitive-grain
>    method becomes a separate channel send/receive carrying a
>    secret-bearing message; every workflow-grain method bundles
>    the primitive sequence into one round-trip carrying only
>    structured non-secret outputs. A primitive-shape `view_ecdh
>    -> X25519SharedSecret` forces the orchestrator's address
>    space to hold a 32-byte raw shared secret across the trait
>    boundary; the workflow shape keeps it confined to the
>    `KeyEngine` impl's stack frame.
>
> 2. **The two-step pattern is a performance optimization, not a
>    trait contract.** Most outputs aren't yours, so do the cheap
>    X25519 pre-filter first. This is impl-internal orchestration
>    logic; the key engine should expose the workflow ("try to
>    claim this output"), not the orchestration ("do X25519 ECDH;
>    check view tag; if matches do full hybrid decap; ..."). A
>    future implementor (HSM-backed, hardware-key) whose
>    performance characteristics make the two-step optimization
>    unnecessary or counterproductive can adopt a different
>    orchestration internally without changing the trait
>    contract.
>
> 3. **The X25519 + ML-KEM types still exist; they just don't
>    cross the trait surface.** `HybridCiphertext`, `SharedSecret`,
>    `HybridSignature`, the X25519 raw 32-byte ECDH output —
>    these all still live in `shekyl-crypto-pq` and are consumed
>    inside `try_claim_output`'s impl. The structural change is
>    "what the trait exposes," not "what types exist." Reviewers
>    reading Phase 1's implementation code in PR 3 should expect
>    to see all four types referenced.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection, alongside §3.1's
hybrid-framework reconciliation prose).**

> The pre-amendment §2.1 named `view_ecdh` and `ml_kem_decapsulate`
> as parallel primitive-shape operations on the classical and PQC
> halves. The post-amendment §2.1 names `try_claim_output` (the
> workflow that bundles X25519 view-tag pre-filter + hybrid decap
> + HKDF chain + key-image computation behind a single trait
> boundary) and removes `view_ecdh` / `hybrid_decapsulate` from
> the trait surface entirely. The hybrid-framework reconciliation
> from §3.1 is absorbed into this larger pivot: the trait surface
> no longer exposes primitives at all, so the question "should
> `sign_with_spend` return `Ed25519Signature` or `HybridSignature`?"
> dissolves — `sign_with_spend` is no longer at the trait surface;
> `sign_transaction` (workflow shape) replaces it; the
> `HybridSignature` type lives inside the impl. The trait surface
> changes shape; the underlying capability ("derive output secrets
> for an incoming output"; "produce all signatures for a
> transaction") is unchanged.

### 3.2 Phase 0b — `KeyError` / `KeyEngineError` split (§7-non-compliant)

**Drift.** Existing `KeyError`
([`engine/error.rs:362`](../../rust/shekyl-engine-core/src/engine/error.rs))
covers wallet-open / derivation only: `PublicBytesMismatch`,
`UnsupportedDerivationPair`, `Primitive`. The §2.1 trait surface
has runtime ops (signing, ECDH, decap, subaddress derivation)
whose error paths cannot map into existing `KeyError`. The trait's
`type Error: Into<KeyError>` bound is mis-scoped at the spec level.

**Disposition.** **(ii) Split.** `KeyError` keeps its current
variants and its current scope (wallet-open / derivation,
unchanged). A new `KeyEngineError` carries runtime-op variants;
the trait bound becomes `type Error: Into<KeyEngineError>`. The
two error types live side-by-side; cross-trait runtime errors
arising from coordination with other engines (e.g., concurrent key
rotation invalidating an in-progress signing attempt) accumulate
on a future cross-trait error type when concrete triggers
materialize.

**Reasoning (recorded verbatim).**

> 1. **The `LedgerEngine` precedent is load-bearing.** PR 2
>    settled `LedgerError` (the trait's error type) as separate
>    from `RefreshError` (the cross-trait runtime error), with
>    Q9.5 anchoring why: cross-trait concerns belong on cross-trait
>    error types, not bundled into per-trait error types where
>    they hide structural concerns.
>
>    The same argument applies here. `KeyError` (existing) covers
>    wallet-open / derivation — those are key lifecycle concerns.
>    Runtime operations (signing, decapsulation) have different
>    failure modes (signature attempt failed, ciphertext malformed,
>    key unavailable, hybrid component mismatch). Bundling them
>    into one growing `KeyError` collapses a structural distinction
>    the workspace already maintains for `LedgerError` /
>    `RefreshError`.
>
> 2. **Audit-grep anchor matters here specifically.**
>    Cryptographic error types are exactly where reviewers want
>    to grep: "show me all the places where signing can fail; show
>    me all the places where decapsulation can produce errors;
>    show me all the places where key access can fail." Different
>    concerns, different greps. One `KeyError` enum makes those
>    greps return the same hits regardless of which concern the
>    reviewer is investigating.
>
>    (iii) "drop the bound" loses this anchor entirely; trait
>    reviewers can't see the error contract from the trait
>    declaration. Rejected for the right reason.
>
> 3. **The migration cost is bounded.** Existing `KeyError` keeps
>    its current variants (`PublicBytesMismatch`,
>    `UnsupportedDerivationPair`, `Primitive`) and its current
>    scope (wallet-open / derivation). New `KeyEngineError`
>    introduces with empty/minimal-viable starter shape per the
>    same pattern as PR 2's `LedgerError` introduction. Per Q9.5's
>    negative-space framing applied to `KeyEngine`: cross-trait
>    concerns (operations that fail because another engine
>    produced bad input, e.g., a ledger snapshot that's stale by
>    the time the signing attempt completes) go on a cross-trait
>    error type, not on `KeyEngineError`.
>
>    Worth pinning the cross-trait error candidate explicitly in
>    the amendment: are there cross-trait runtime errors for
>    signing/decapsulation that warrant a `RefreshError`-shaped
>    sibling? My read is probably not at PR 3 cut-point — the
>    obvious candidate (concurrent key rotation invalidating an
>    in-progress signing attempt) doesn't yet have a concrete
>    trigger because key rotation isn't part of Stage 1's scope.
>    But worth being explicit that the negative-space anchor
>    exists for `KeyEngineError`'s eventual variants.

**Starter shape for `KeyEngineError` (Round 1 proposal).**

```rust
/// Failures during runtime KeyEngine operations (signing,
/// hybrid decapsulation, ECDH, subaddress derivation). Distinct
/// from [`KeyError`], which scopes wallet-open / derivation
/// failures. Cross-trait coordination failures (e.g., concurrent
/// key rotation invalidating an in-progress signing attempt) do
/// not appear here per Q9.5's negative-space framing — they
/// accumulate on a future cross-trait error type when concrete
/// triggers materialize.
#[derive(Debug, thiserror::Error)]
pub enum KeyEngineError {
    /// Phase-2a-specific runtime variants land here when the
    /// implementor surfaces them. Empty starter shape mirrors PR
    /// 2's `LedgerError` introduction.
}
```

The empty starter shape is intentional. Variants accrete from the
implementor's actual failure modes during Phase 1, not speculatively
in the spec round.

### 3.3 Phase 0c — workflow-internal types + message shapes for cross-boundary travel

**Drift.** Round 1's pre-flight surfaced 5 spec-named types that
needed shape decisions or workspace-rename. Round 2's pivot to
workflow-shape (§3.1) restructures Phase 0c into two sub-bundles:

- **Sub-bundle A — workflow-internal types** (`pub(crate)`
  impl-internals; do not cross the trait surface).
- **Sub-bundle B — message shapes for cross-boundary travel**
  (the structured non-secret types that replace the
  primitive-shape signatures the pre-amendment §2.1 named).

**Disposition.** Define both sub-bundles. Sub-bundle A's types
are consumed inside `LocalKeys`'s impl; Sub-bundle B's types are
the trait surface's parameters and return types.

#### Sub-bundle A — workflow-internal types

| Type | Shape | Source / rationale |
|---|---|---|
| `SignDomain` | `pub(crate) #[non_exhaustive] enum SignDomain { OutputSecretDerivation, TransactionSignature, FcmpPlusPlusWitness, MlKemChallenge }` | No longer a trait-level concept; lives inside `LocalKeys`'s impl. The cryptographic enforcement (preventing cross-domain signature reuse via per-domain HKDF chains) is unchanged from Round 1's framing — each impl-internal call site asserts the domain it's signing in, and the impl's `assert_sign_domain` (or equivalent) machinery rejects mismatches. The audit-grep argument shifts: reviewers grep for "internal HKDF-context derivation sites" rather than "trait-surface call sites." Stage 4 adds multisig witness / partial signature variants additively per Q9.2's `#[non_exhaustive]` disposition. |
| `AccountPublicAddress` | `pub struct AccountPublicAddress { pub pqc_public_key: [u8; PQC_PUBLIC_KEY_BYTES], pub classical_address_bytes: [u8; CLASSICAL_ADDRESS_BYTES] }` | Mirror `AllKeysBlob`'s public side. Returned by `account_public_address` (the one trait method that hands out a borrowed reference rather than an owned message — addresses are stable for the wallet's lifetime, so a `&AccountPublicAddress` is honest). The 1216-byte ML-KEM PK + 65-byte classical address bytes shape is consistent with what ML-KEM-768 + the existing classical-address representation produces. |

> **Note on removed rows.** `X25519SharedSecret` (the net-new
> Round 1 newtype for the 32-byte raw X25519 ECDH output),
> `HybridSignature`, `SharedSecret`, and `HybridCiphertext` are
> still consumed inside `LocalKeys`'s `try_claim_output` and
> `sign_transaction` implementations (the X25519 raw 32-byte SS
> feeds the view-tag pre-filter; the 64-byte hybrid SS feeds the
> HKDF chain that produces output-secret material;
> `HybridSignature` is what `sign_transaction` produces per-input
> internally; `HybridCiphertext` is consumed by the hybrid decap
> step). The Sub-bundle A row removal reflects that **these
> types no longer appear at the trait surface** — they're
> workflow internals, not boundary-crossing types. Reviewers
> reading Phase 1's implementation code in PR 3 should expect to
> see all four types referenced; their continued existence in
> `shekyl-crypto-pq` is necessary, not vestigial. The structural
> change is "what the trait exposes," not "what types exist."
> The Round 1 net-new `X25519SharedSecret` newtype is no longer
> needed — without a trait surface for `view_ecdh`, the 32-byte
> raw shared secret never crosses an API boundary that warrants
> a typed wrapper; it lives as a `[u8; 32]` (or `Zeroizing<[u8;
> 32]>`) on the impl's stack frame.

#### Sub-bundle B — message shapes for cross-boundary travel

The workflow-shape trait surface needs structured non-secret
parameter and return types for `try_claim_output`,
`sign_transaction`, and `derive_subaddress`. **Stub rows here for
commit 1 of this design-doc round; concrete field sets land in
commit 2.** Each row's "shape" cell carries enough information
for reviewers to confirm the pivot direction without committing
to every field-level decision:

| Type | Shape (stub for commit 1; pinned in commit 2) | Source / rationale |
|---|---|---|
| `OutputDetectionInput` | Bundles `HybridCiphertext` + `ViewTag` + `output_index` (and possibly block-context fields) for `try_claim_output`'s input | Single message struct so `try_claim_output`'s impl receives all source-correct fields together; constructor-enforced source correctness (see commit 2's `from_block_output(&LedgerBlock, u64) -> Option<Self>` shape). |
| `OutputClaimResult` | `#[non_exhaustive] enum OutputClaimResult { Mine(OutputClaim), NotMine }` | Workflow output; structured non-secret. The `Mine` variant carries the `OutputClaim` payload; `NotMine` carries no data (most outputs are NotMine in real scanning). |
| `OutputClaim` | Structured non-secret claim data: per-output spend secret material derivative, key image, amount-blinding-factor, decrypted amount (and any additional FCMP++-scanner fields) | The structured non-secret payload from a successful output detection. Secret intermediates (raw shared secrets, HKDF intermediates) are confined to `try_claim_output`'s stack frame; the claim type carries only what downstream balance / spend-tx-construction code needs. |
| `TxToSign` | Bundles per-input signing context, per-output context, and any FCMP++ context the signing pass needs | Single message struct so `sign_transaction`'s impl receives all signing inputs together; the type's exact shape depends on FCMP++ context details and is pinned in commit 2 (with deferral to PR 5's `PendingTxEngine` design doc for the per-input context details). |
| `TxSignatures` | Per-input signature bundle returned by `sign_transaction` | Structured non-secret payload of the signing pass. Carries hybrid signatures per-input, FCMP++ witnesses, and any other signature-class output the signing produced. |
| `SubaddressPurpose` | `#[non_exhaustive] enum SubaddressPurpose { Recipient, Audit }` | Purpose-decomposed subaddress derivation per L2.2's design pivot. New purposes accrete additively in V3.x (e.g., `PqcRecipient` for hybrid-augmented subaddresses); the `#[non_exhaustive]` annotation gives existing call sites a compile-time signal when new variants land. |
| `SubaddressFor` | `#[non_exhaustive] enum SubaddressFor { Recipient(RecipientSubaddress), Audit(SubaddressKeyPair) }` | Discriminated union over `SubaddressPurpose`. New variants accrete in lockstep with `SubaddressPurpose`. |
| `RecipientSubaddress` | `{ encoded: Address, kem_pk: HybridKemPublicKey }` | The recipient-context payload: encoded address (Bech32m for Shekyl) + KEM public key for senders to encapsulate against. Used by payment-URI / QR-code generation paths. |
| `SubaddressKeyPair` | `{ spend_pk: [u8; 32], view_pk: [u8; 32] }` | The audit-context payload: canonical key pairs for backup/inspection. Used by export paths. PQC-augmented subaddresses are a V3.x extension that lands as an additional `SubaddressFor::PqcRecipient` variant carrying its own message shape. |
| `ViewTag` | Newtype wrapping `[u8; N]` for the view-tag bytes | Carries the view tag from a hybrid ciphertext into `OutputDetectionInput`'s constructor. Stub size pinned in commit 2 against the FCMP++ output-format. |

**Reuse notes.** `HybridPublicKey` and `HybridKemPublicKey` exist
in the workspace
([`shekyl-crypto-pq::signature::HybridPublicKey`](../../rust/shekyl-crypto-pq/src/signature.rs)
for Ed25519+ML-DSA-65 signing,
[`shekyl-crypto-pq::kem::HybridKemPublicKey`](../../rust/shekyl-crypto-pq/src/kem.rs)
for X25519+ML-KEM-768 KEM); `HybridKemPublicKey` is reused inside
`RecipientSubaddress`. Neither type appears as a direct trait-method
parameter or return — they cross the trait boundary only as fields
inside Sub-bundle B message shapes. Reviewers asking "why doesn't
the trait surface name primitives?" find the answer in §3.1.1's
workflow-orchestration framing.

`Address` (the encoded-address type used by `RecipientSubaddress`)
and `KeyImage` (used by `OutputClaim`) are existing or to-be-added
workspace types; commit 2 pins their provenance (workspace path or
new Phase 0c row).

### 3.4 Phase 0d — bundled small fixes (visibility + super-bound + Q9.3)

**Drift.** Three small, additive amendments bundled into one PR
because each is too small to warrant its own:

1. **Visibility.** §2.1 writes `pub trait KeyEngine`; PR 2's
   Phase 0c amendment landed `LedgerEngine` as `pub(crate)`. Per
   Decision 4 (the user's reasoning recorded below), KeyEngine
   ships as `pub(crate)` for V3.0 with promotion to `pub` deferred
   to V3.2 alongside `LedgerEngine` and `DaemonEngine`.
2. **`Send + Sync + 'static` super-bound.** `LedgerEngine` and
   `DaemonEngine` both pin it for Stage-4-actor compat;
   `KeyEngine` as written has no super-bound. The super-bound is
   what makes `KeyEngine` usable across `Arc<dyn KeyEngine>`
   boundaries in Stage 4's actor abstraction; its absence in §2.1
   is a Round-1-spec drafting oversight that subsequent per-trait
   extractions (`LedgerEngine`, `DaemonEngine`) corrected. The
   amendment adds the super-bound consistent with the per-trait
   template; the property it encodes — Stage 4 actor-compatibility
   at the trait surface — is **substantive, not editorial**. If
   Round 2 challenges Phase 0d on the super-bound, the substantive
   framing holds; an "editorial drift" framing wouldn't have.
3. **Q9.3 `ZeroizeOnDrop` disposition.** Q9.3 cites
   `AllKeysBlob: ZeroizeOnDrop`. Per Decision 3, the disposition
   is fixed by **(i) migrating `AllKeysBlob` to
   `#[derive(Zeroize, ZeroizeOnDrop)]`** (the optional Phase 0e
   code PR) — making the spec's claim true rather than rewriting
   the spec to describe the workaround. Phase 0d's spec change is
   a one-line cross-reference update from "implementor's manual
   `Drop`" back to "implementor's `ZeroizeOnDrop` derive" once
   Phase 0e lands.

**Reasoning for visibility (recorded verbatim).**

> 1. **The `LedgerEngine` precedent is load-bearing.** Same
>    argument as Decision 2 — the discipline has settled "trait
>    surfaces start `pub(crate)` and promote when external
>    consumers materialize." Deviation requires explicit
>    justification; KeyEngine doesn't have it (no concrete
>    external consumer at PR 3 cut-point).
>
> 2. **Tightening is harder than relaxing.** This is the
>    operational asymmetry. If KeyEngine ships `pub` and someone
>    outside the crate writes an HSM-backed implementor, then
>    later we discover a trait-surface bug (e.g., a method
>    signature that's semantically wrong; an error variant we
>    want to reorganize), tightening means breaking external
>    consumers. If KeyEngine ships `pub(crate)` and we discover
>    the same bug, the fix is internal-only.
>
>    The asymmetry compounds when multiple traits are involved.
>    Each per-trait extraction that ships `pub` adds external
>    commitment surface; each that ships `pub(crate)` keeps the
>    option open. By Stage 4 cutover, the cumulative surface
>    decision shapes whether the actor abstraction can ship
>    cleanly or has to navigate around external commitments made
>    speculatively in Stage 1.
>
> 3. **The "HSM/hardware-key consumers must be in-crate or rely
>    on `Engine<S>` facade" cost is real but bounded.** No Stage 1
>    work depends on external HSM consumers; the V3.2 promotion
>    timeline is reasonable; the `Engine` facade provides an
>    interim integration point that doesn't require the trait
>    itself to be `pub`.
>
> Worth being explicit in the amendment: V3.2's trait visibility
> promotion is one of several Stage 4 concerns being deferred
> consistently across per-trait PRs. KeyEngine, LedgerEngine,
> DaemonEngine all ship `pub(crate)`; the unified promotion
> happens at V3.2 when the actor abstraction surfaces concrete
> external consumers.

### 3.5 Phase 0e (optional, code) — `AllKeysBlob` `ZeroizeOnDrop` migration

**Drift.** §2.1's Q9.3 disposition cites `AllKeysBlob:
ZeroizeOnDrop` as a precondition for the "no `wipe()` method
needed" design. The actual struct
([`shekyl-crypto-pq/src/account.rs:484–499`](../../rust/shekyl-crypto-pq/src/account.rs))
implements **manual `Drop`** with field-by-field `.zeroize()`, no
`#[derive(ZeroizeOnDrop)]`, no `impl ZeroizeOnDrop`. The Q9.3
design rationale rests on a trait bound that does not hold.

**Disposition (per Decision 3).** **(i) Migrate `AllKeysBlob` to
`#[derive(Zeroize, ZeroizeOnDrop)]`.** Small code PR in
`shekyl-crypto-pq`; deletes the manual `Drop` impl. The spec
assertion becomes true; the migration aligns code with rule.

**Reasoning (recorded verbatim).**

> 1. **The rule preference is explicit and the structural
>    conditions hold.**
>    [`35-secure-memory.mdc:23-25`](../../.cursor/rules/35-secure-memory.mdc)
>    names `#[derive(ZeroizeOnDrop)]` as preferred when all fields
>    implement `Zeroize`. Every field of `AllKeysBlob` is
>    `[u8; N]`; arrays of `u8` implement `Zeroize`; the
>    structural condition holds. The manual `Drop` impl is doing
>    what `derive(ZeroizeOnDrop)` would do automatically, but
>    with more surface area for getting it wrong (forgetting a
>    field; ordering mistakes if any field had non-trivial drop
>    semantics; reviewer auditing a manual implementation versus
>    a derive macro).
>
>    Manual `Drop` for Zeroize-correct types is exactly the
>    pattern the rule discourages. The migration aligns code
>    with rule.
>
> 2. **The spec assertion becomes true.** Q9.3 currently cites
>    `AllKeysBlob: ZeroizeOnDrop` as a precondition. Today, it's
>    not literally true — the type behaves as `ZeroizeOnDrop`
>    because the manual `Drop` zeroizes, but the trait isn't
>    implemented. (ii) "rewrite Q9.3 to cite manual `Drop`"
>    documents the lie rather than fixing it. The choice between
>    "make the spec true" and "rewrite the spec to describe the
>    workaround" should default to the former unless the
>    workaround has substantive justification — and there's no
>    such justification here. The manual `Drop` is just
>    historical drift.
>
> 3. **The PR cost is genuinely bounded.** Per pre-flight, this
>    is a small code PR in `shekyl-crypto-pq` — delete manual
>    `Drop`, add `#[derive(Zeroize, ZeroizeOnDrop)]`. The diff is
>    probably 5-10 lines. The verification is "the same
>    zeroization behavior, derived rather than hand-written;
>    existing tests around `AllKeysBlob`'s drop semantics still
>    pass."

**Sequencing.** Per the user's "(a)" lean, Phase 0e lands as a
**separate small chore PR before PR 3 cuts**. Mirrors the
Phase 0/0b/0c pattern: small focused PR, single concern, lands
cleanly, PR 3 cuts off post-merge dev tip with the precondition
true. Bundling code cleanup with trait extraction conflates two
concerns; reviewers asking "is the trait extraction correct?"
should not also have to verify the Zeroize migration didn't break
anything.

This adds another preparatory PR to PR 3's count. The trajectory
cost is real — but the discipline has consistently produced this
trade across Stage 1, and PR 3's substrate-quality benefit is the
same as PR 2's.

---

## 4. Post-amendment §2.1 trait surface

The trait surface §2.1 declares after Phases 0–0d land:

```rust
/// Engine-side view of wallet key material (§2.1).
///
/// Owns `AllKeysBlob` privately; no other actor sees raw key
/// material. Per §1.3's inlining-for-audit rationale, every key
/// operation should inline into one audited compilation unit.
/// The trait surface is workflow-shape: it exposes actor-message
/// granularity operations (`try_claim_output`, `sign_transaction`)
/// rather than primitive-grain operations (raw ECDH, raw decap,
/// per-message signing). Cryptographic intermediates — including
/// hybrid types from `shekyl-crypto-pq` — never cross the trait
/// boundary; they live transiently inside the implementor's stack
/// frame, zeroized on drop. See §3.1.1 for the structural rationale.
pub(crate) trait KeyEngine: Send + Sync + 'static {
    type Error: Into<KeyEngineError>;

    /// Account-level public address material. Cheap; does not
    /// touch secrets. Stable for the wallet's lifetime — the only
    /// trait method returning a borrowed reference (`&AccountPublicAddress`)
    /// rather than an owned message, because address material is
    /// not bound to any per-call context. See §7 for the
    /// account-address-stability assumption (today's classical-Monero
    /// behavior; PQC schemes with key-rotation properties may
    /// re-open this in V3.x).
    fn account_public_address(&self) -> &AccountPublicAddress;

    /// Derive a subaddress for a specific purpose.
    ///
    /// The `purpose` argument selects the `SubaddressFor` variant
    /// returned: `SubaddressPurpose::Recipient` produces an encoded
    /// address + KEM public key for senders to encapsulate against
    /// (used by payment-URI / QR-code generation paths);
    /// `SubaddressPurpose::Audit` produces canonical key pairs for
    /// backup / inspection (used by export paths). Both enums are
    /// `#[non_exhaustive]`; new purposes accrete additively in
    /// V3.x (e.g., `PqcRecipient` for hybrid-augmented subaddresses)
    /// per Q9.2 / §8.2.
    ///
    /// The classical spend/view subaddress derivation has no
    /// concrete failure mode at today's surface (the classical
    /// path's only failure modes are RNG-failure-class events,
    /// essentially impossible during pure derivation from existing
    /// key material). The `Result<...>` shape is reserved for the
    /// V3.x PQC-augmented subaddress extension, where the hybrid
    /// derivation path can fail with non-negligible probability
    /// in ways the classical path cannot (e.g., ML-KEM keypair
    /// derivation has a defined failure surface). Trait stability
    /// across the V3.x extension is the rationale for the `Result`
    /// shape now.
    fn derive_subaddress(
        &self,
        idx: SubaddressIndex,
        purpose: SubaddressPurpose,
    ) -> Result<SubaddressFor, Self::Error>;

    /// Workflow: try to claim an on-chain output for this wallet.
    ///
    /// Bundles X25519 view-tag pre-filter + hybrid decap + HKDF
    /// chain + key-image computation behind a single trait
    /// boundary. Returns a structured non-secret claim
    /// (`OutputClaimResult::Mine(OutputClaim)`) on a successful
    /// detection, or `OutputClaimResult::NotMine` for outputs that
    /// don't claim. Most outputs are `NotMine` in real scanning;
    /// the X25519 pre-filter rejects them cheaply.
    ///
    /// **Cryptographic intermediates never cross the trait
    /// boundary.** The X25519 raw shared secret (32 bytes), the
    /// 64-byte hybrid shared secret, and HKDF intermediate keying
    /// material exist only transiently inside this method's stack
    /// frame and are zeroized on drop per the workspace's
    /// `Zeroize` / `ZeroizeOnDrop` discipline.
    async fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> Result<OutputClaimResult, Self::Error>;

    /// Workflow: sign a fully-prepared transaction.
    ///
    /// The `TxToSign` parameter bundles all per-input signing
    /// context (signing key derivation paths, FCMP++ context, any
    /// per-input message bytes). The implementor handles per-input
    /// hybrid signature production, FCMP++ witness generation, and
    /// any other signature-class work the transaction requires.
    /// Returns `TxSignatures` carrying the structured non-secret
    /// signature bundle.
    ///
    /// **Cross-domain signature reuse is prevented cryptographically
    /// inside the impl** via per-domain HKDF chains (the impl's
    /// `SignDomain` enumeration); not at the trait surface, because
    /// `SignDomain` is no longer a trait-level concept (see §3.3
    /// Sub-bundle A).
    async fn sign_transaction(
        &self,
        tx: &TxToSign,
    ) -> Result<TxSignatures, Self::Error>;
}
```

### What `KeyEngine` deliberately does not expose, and why

Reviewers familiar with the Round 1 draft of this trait may notice
several capabilities they expected to find at the trait surface
that are deliberately absent. Each absence has a specific
rationale; surfacing the rationale here keeps the structural
choice legible against future "shouldn't `KeyEngine` also expose
X?" review questions.

- **Hybrid encapsulation against external recipient public keys.**
  The sender's `KeyEngine` does not mediate hybrid encapsulation;
  `HybridX25519MlKem::encapsulate` is a free function in
  `shekyl-crypto-pq` consumed at transaction-build time outside
  the `KeyEngine` boundary. A `KeyEngine::encapsulate(...)` method
  would expose nothing the free function doesn't already expose
  and would conflate "operations that touch the wallet's secret
  keys" with "operations that don't" at the same trait. (L1.1)
- **Signature verification.** Verification needs only public
  material; not a `KeyEngine` concern. Lives in
  `shekyl-crypto-pq::signature::HybridEd25519MlDsa::verify` (free
  function) or in the verification call sites themselves.
  Including verification at the trait surface would invite a
  generic-signing-oracle abuse pattern that the workflow shape
  specifically prevents. (L1.3)
- **Wallet creation seed-derivation.** Runs once before the
  `KeyEngine` exists. `LocalKeys::from_seed(seed: &WalletSeed) ->
  Result<Self, KeyError>` is the wallet-create path's
  responsibility (and `LocalKeys::from_test_seed(test_label: &str)`
  is the `#[cfg(test)]` analog for fixtures); the trait method
  surface assumes a fully-derived blob already exists. The
  wallet-open / derivation error type stays as the existing
  `KeyError` (per §3.2's split); it does not leak into
  `KeyEngineError`. (L1.5)
- **Secret intermediates never cross the trait boundary.** The
  X25519 raw shared secret (32 bytes), the 64-byte hybrid shared
  secret, and HKDF intermediate keying material exist only
  transiently inside `try_claim_output`'s and `sign_transaction`'s
  stack frames. They are zeroized on drop per the workspace's
  `Zeroize` / `ZeroizeOnDrop` discipline
  ([`35-secure-memory.mdc`](../../.cursor/rules/35-secure-memory.mdc)).
  The orchestrator's address space sees only the structured
  non-secret outputs (`OutputClaimResult`'s `OutputClaim`,
  `TxSignatures`); secret intermediates are not exposed, not
  borrowed across `await` points to non-`KeyEngine` callers, and
  not returned. **This is the load-bearing security property that
  workflow-shape trait surfaces deliver and primitive-shape
  surfaces (e.g., a hypothetical `view_ecdh -> X25519SharedSecret`)
  violate.** A primitive-shape trait would force the orchestrator's
  address space to hold a secret across the trait boundary; the
  workflow-shape trait keeps the secret confined to the
  `KeyEngine` impl's stack frame. The "Round 3 reviewer asks
  'what's the security difference between primitive-shape and
  workflow-shape?'" question is answered here, in the doc, not
  derived during review.

### Notable changes vs. the pre-amendment shape

- **`pub(crate)` not `pub`** (Phase 0d).
- **`: Send + Sync + 'static` super-bound** (Phase 0d).
- **`type Error: Into<KeyEngineError>`** instead of
  `Into<KeyError>` (Phase 0b).
- **Workflow-shape methods replace primitive-shape methods**
  (Phase 0). `view_ecdh`, `hybrid_decapsulate`, and
  `sign_with_spend` are removed; `try_claim_output` and
  `sign_transaction` are added. The hybrid-framework
  reconciliation is absorbed into the workflow pivot — the
  classical types (`Ed25519Signature`, `EdwardsPoint`,
  `MlKemEncapsulation`, `MlKemSharedSecret`) and the hybrid types
  (`HybridSignature`, `HybridCiphertext`, `SharedSecret`) all
  cease to appear at the trait surface; they live inside the
  workflow methods' impls. See §3.1.1 for the structural
  rationale.
- **`derive_subaddress` replaces `derive_subaddress_public`**
  (Phase 0). Purpose-decomposed via `SubaddressPurpose` /
  `SubaddressFor` per L2.2's design pivot; allows additive
  V3.x extensions (e.g., PQC-augmented subaddresses) without
  re-opening the trait.
- **Message-shape parameters and returns** replace primitive
  parameters and returns: `OutputDetectionInput`,
  `OutputClaimResult`, `TxToSign`, `TxSignatures`,
  `SubaddressPurpose`, `SubaddressFor` — all defined per Phase 0c
  Sub-bundle B.
- **`SignDomain` is no longer a trait-level concept** (Phase 0c
  Sub-bundle A). Cross-domain signature reuse is prevented
  cryptographically inside the impl via per-domain HKDF chains;
  the trait surface no longer exposes `SignDomain`.

The Q9.1 / Q9.2 / Q9.3 dispositions retain their stated
conclusions; Q9.3's underlying precondition becomes literally true
once Phase 0e lands.

---

## 5. Sequencing

### 5.1 Spec-amendment PR sequence

Five preparatory PRs; landing order:

| PR | Subject | Type | Why this order |
|---|---|---|---|
| 0e | `AllKeysBlob` `ZeroizeOnDrop` migration | Code (`shekyl-crypto-pq`) | Lands first so Q9.3's precondition holds when Phase 0d's spec amendment cross-references it. |
| 0 | Hybrid-framework reconciliation (sign/decap rewrite + Ed25519/EdwardsPoint removal) | Doc-only spec | Largest scope; lands second so subsequent additive amendments build against post-Phase-0 §2.1. |
| 0b | `KeyError` / `KeyEngineError` split | Doc-only spec | Second-largest; lands after Phase 0 because Phase 0's hybrid-rewrite changes some method signatures whose error variants `KeyEngineError` will eventually carry. |
| 0c | Missing-type definitions (`AccountPublicAddress`, `SignDomain`, `SubaddressPublic`, hybrid renames) | Doc-only spec | Lands after Phases 0 + 0b because the type definitions reference the post-amendment trait surface. |
| 0d | Visibility + super-bound + Q9.3 cross-reference | Doc-only spec | Bundled small fixes; lands last among the preparatory PRs so the fully-shaped surface is committed before PR 3 cuts. |

Five PRs is more than PR 2's three. The trajectory is consistent
with PR 2's discipline: each PR is single-concern, doc-only (or
single-file code change in 0e's case), independently reviewable,
and bisectable. The author commits to landing them on `dev` over
~5 working days; PR 3's feat branch cuts off the post-Phase-0d
dev tip.

**Phase 0e ↔ Phase 0d coupled-pair landing (disposition α).**
Phase 0e (the `AllKeysBlob` `ZeroizeOnDrop` migration code PR)
lands first; Phase 0d's spec amendment (which cross-references the
post-migration state via Q9.3) lands immediately after. **The
half-state where the spec's Q9.3 cross-reference language doesn't
yet match the post-migration code is bounded to hours, not days.**
This matches PR 2's Phase 0/0b precedent (small bounded amendments
landing in tight sequence). Disposition (α) is preferred over (β)
documenting the half-state and (γ) inverting spec-and-code
authority; (γ) was rejected because it has the spec asserting a
property that is not yet literally true at the moment the
amendment lands, which inverts the discipline of "spec describes
the code" into "spec promises the code will become."

**Operational fallback.** If Phase 0d's review introduces a delay
(CI lag, reviewer availability, additional review pass), the
responsibility falls to the PR author to update Phase 0e's PR
description retroactively to name the transient half-state
explicitly and point at the pending Phase 0d PR for closure. The
fallback is the author's action — not an automatic property of
the system — and should be documented in the post-merge
realignment subsection of this design doc if it triggers.

### 5.2 PR 3 feat branch

Cuts off `dev` after Phase 0d lands. Mirrors PR 2's
`feat/stage-1-ledger-engine` shape; commit count budget (subject
to Round 2 refinement):

1. Trait declaration in `engine/traits/key.rs`.
2. `LocalKeys` implementing aggregate, with both `from_seed`
   (production) and `#[cfg(test)] from_test_seed` (test fixture)
   constructors.
3. Sub-bundle B message types (`OutputDetectionInput`,
   `OutputClaimResult`, `OutputClaim`, `TxToSign`, `TxSignatures`,
   `SubaddressPurpose`, `SubaddressFor`, `RecipientSubaddress`,
   `SubaddressKeyPair`, `ViewTag`); pinned shapes from commit 2 of
   this design-doc round.
4. `Engine<S, D, L, K>` parameterization.
5. Migrate consumers from `engine.keys` direct field access to
   `K: KeyEngine` trait dispatch.
6. `FaultInjecting<K: KeyEngine>` test wrapper in `test_support`
   (or wherever the test substrate accumulates); `#[cfg(test)]`-
   gated. **No `MockKeys`** (per §6.4 / §2.1.2).
7. Hybrid test exercising one §5.2 property predecessors haven't
   covered (selection per §6.4 — (a) layered-call error
   preservation, exercised via `FaultInjecting<LocalKeys>`).
8. Benchmark harness for `KeyEngine` hot-path methods (selection
   per §6.5; `account_public_address` plus the `try_claim_output`
   bench split queued for commit 2 of this design-doc round).
9. Docs propagation (this design doc's realignment + CHANGELOG
   entry + `V3_ENGINE_TRAIT_BOUNDARIES.md` post-PR-3 cross-anchor
   updates).

The synchronous wrappers question (PR 2's `Engine::refresh` /
`refresh_with` `LocalLedger`-specialized impl block) does not
apply to PR 3 — `KeyEngine`'s sync methods stay sync; its async
workflow methods are async — there are no `LocalKeys`-specialized
synchronous entry points to retain.

---

## 6. What PR 3 implements (scope)

### 6.1 Trait declaration

Per §4 above. `pub(crate) trait KeyEngine: Send + Sync + 'static`
with five methods. Declared in
`rust/shekyl-engine-core/src/engine/traits/key.rs`; re-exported from
`traits/mod.rs`; consumed via `K: KeyEngine` bound.

### 6.2 Implementing aggregate

`pub struct LocalKeys` wrapping `AllKeysBlob` (precise wrapper
shape pinned at commit time per PR 2's degrees-of-freedom
precedent). Held as `keys: LocalKeys` on `Engine`. The `pub`
visibility (vs. `pub(crate)`) is a default-type-parameter
constraint (Rust requires `pub` defaults for `pub` generic
parameters); `LocalKeys`'s public surface is intentionally minimal
— the trait `KeyEngine` itself stays `pub(crate)` per Phase 0d.

### 6.3 `Engine` parameterization

`Engine<S, D = DaemonClient, L = LocalLedger, K = LocalKeys>`.
`OpenedEngine<S, D, L, K>` carries the same parameterization. The
non-test consumer-facing surface continues to name `Engine<S>` /
`OpenedEngine<S>` exactly as before via the cumulative default
arguments — same property PR 1 and PR 2 preserved.

### 6.4 Hybrid test + test-substrate disposition

PR 3 exercises **(a) layered-call error preservation** — a runtime
key-op error injected through a `FaultInjecting<LocalKeys>` wrapper
propagates through `Engine<S>`'s wallet-level workflow methods
(`try_claim_output`, `sign_transaction`) with the error variant
intact and the layered-call structure preserved.

**Rationale (recorded verbatim).**

> `&self` async drops local state when the future drops; nothing
> residual that the next call observes; the cancel-class
> implication is speculative until a concrete observable-residual
> story exists. (a) layered-call error preservation has concrete
> behavior at PR 3 cut-point; the "`PendingTxEngine` has more
> cross-trait paths" argument doesn't preclude PR 3 exercising
> its single cross-trait path; `PendingTxEngine` PR can exercise
> its more complex paths additionally.

The earlier Round-1 draft leaned toward cancel-class verification
on the framing that `KeyEngine`'s `sign_with_spend` was the first
per-trait PR where dropping a future before completion has
observable trait-shape implications. That framing assumed
cancel-class verification has observable trait-shape implications
specific to `KeyEngine`, but two questions undermine the
assumption: (1) what residual state could a dropped workflow
future leave that the next call could observe? `KeyEngine` is
`&self` async; the future captures `&self` and any local state.
If the future is dropped mid-await, the local state is dropped
too; `&self` is unchanged from the caller's perspective. (2) If
there is residual state in some future implementation (e.g.,
HKDF context state; intermediate scalar arithmetic state in a
hardware-key implementation), is the test exercising current
`LocalKeys` behavior or future-implementor behavior? If the
latter, the test is exercising a property that isn't yet
observable. Layered-call error preservation has concrete
observable behavior at PR 3 cut-point; cancel-class verification
doesn't, and is deferred to a future per-trait PR whose pre-flight
surfaces a concrete observable-residual story. The Round 2 pivot
to workflow-shape methods does not change this disposition — the
cancel-class observability question is about `&self` async
semantics regardless of whether the methods are primitive- or
workflow-shape; the workflow shape if anything makes the question
less observable (more impl-internal state to drop, none of it
visible to the orchestrator).

**Test substrate (no `MockKeys` type).** Round 2's L3.3 review
rejected the Mock-X pattern as a category (see §2.1.2). PR 3
lands the no-Mock pattern at the per-trait PR cut-point; the
substrate has two pieces:

- **Production-only `LocalKeys` with two seed-derivation paths.**
  `pub fn from_seed(seed: &WalletSeed) -> Result<Self, KeyError>`
  for the production wallet-create path; `#[cfg(test)] pub
  fn from_test_seed(test_label: &str) -> Self` for test fixtures.
  The test seed is publicly known (the `test_label` argument
  feeds a deterministic derivation); any wallet derived from a
  test seed has publicly-derivable secret keys, which is
  acceptable in test scope and unacceptable in production scope.
  The `#[cfg(test)]` visibility constraint structurally enforces
  "production code MUST NEVER call this constructor" — the
  symbol does not exist in non-test compilation. Different tests
  needing distinct keys use distinct `test_label`s (e.g.,
  `"shekyl-test-keys-default"`, `"shekyl-test-keys-alt-1"`).
- **Composable `FaultInjecting<K: KeyEngine>` wrapper for
  failure-injection tests.** Lives in a `test_support` module
  (or wherever the test substrate accumulates); `#[cfg(test)]`-
  gated. Wraps any `K: KeyEngine` impl, preserves the inner
  impl's behavior by default, and queues `KeyEngineError`
  variants via `queue_fault(KeyEngineError)` for tests to inject
  failures at specific call sites. Composable: `FaultInjecting<LocalKeys>`
  for fault tests against authentic crypto; `FaultInjecting<HsmBackedKeys>`
  for future HSM impls; the wrapper composes with any `K: KeyEngine`
  implementor without per-implementor work.

**Why no `MockKeys`.** The Round 1 draft proposed `MockKeys` +
`replace_keys` mirroring PR 2's `MockLedger` + `replace_ledger`
pattern. The Round 2 review rejected that for the broader Mock-X
reasons named in §2.1.2: parallel implementations conflate
test-controlled inputs with substitute implementations, add attack
surface, don't compose with future implementors, and encourage
tests to verify against fake semantics. `LocalKeys::from_test_seed`
provides authentic-crypto fixtures; `FaultInjecting<LocalKeys>`
provides composable failure-injection. Together they cover what
`MockKeys` was for, without the structural failure modes.

**Retroactive cleanup.** PR 1's `MockDaemon` (rename to
`TestDaemon`) and PR 2's `MockLedger` (replace with
`LocalLedger::from_test_blocks` + `FaultInjecting<LocalLedger>`)
land in PR 4 or PR 5 alongside their own trait-extraction work —
not as retroactive churn within those already-merged PRs, but
also not deferred indefinitely. See
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) for the explicit V3.0-baseline
schedule; see §2.1.2 for the rationale distinguishing the two
cases (`MockLedger` is a parallel-implementation pattern that is
wrong-by-shape; `MockDaemon` is structurally fine and only
badly-named because real `DaemonClient` requires network).

### 6.5 Benchmark harness

Mirrors PR 2's `engine_trait_bench_ledger_balance` /
`engine_trait_bench_ledger_synced_height` pair, reframed against
the workflow-shape trait surface:

- `engine_trait_bench_key_account_public_address` — sync,
  infallible-read hot path; `LedgerEngine`'s `synced_height` is
  the structural analog. The cheapest method on the trait;
  measures trait-dispatch overhead with no cryptographic work.
- `engine_trait_bench_key_try_claim_output` — async workflow
  hot path; **the highest-leverage benchmark on the entire
  trait** because the scanner's per-output cost dominates
  wallet-refresh time. Most wallet operations spend most of
  their wall-clock time inside this method (or its impl-internal
  X25519 view-tag pre-filter, which rejects most outputs cheaply).
  Commit 1 lists this as a single bench placeholder; **commit 2
  splits it into two benches** measuring structurally distinct
  workloads (see "Bench refinements queued for commit 2" below).
- `engine_trait_bench_key_sign_transaction` — async workflow
  hot path for the spend path; potentially deferred to Phase-2a
  if hybrid-signature setup cost dwarfs the trait-dispatch
  overhead measurement, or if the bench fixture (a complete
  `TxToSign` with FCMP++ context) is structurally too heavy to
  set up at PR 3 cut-point.

The frozen baselines and cumulative-delta documentation pattern
established in PR 2's `docs/PERFORMANCE_BASELINE.md` extend to
PR 3; the post-PR-3 row count grows by 2–4 (one for
`account_public_address`; two for the `try_claim_output` split
once commit 2 lands; optionally one for `sign_transaction`).

**Bench refinements queued for commit 2.** Two refinements from
Round-2 review must land alongside commit 2's message-shape
detailed design:

- **X25519 ephemeral reuse vs double-compute.** The X25519
  ephemeral (`HybridCiphertext.x25519`) is public on-chain data;
  both the view-tag pre-filter (impl-internal step 1) and the
  full hybrid decap (impl-internal step 2) need an ECDH against
  it. Question: does `LocalKeys`'s `try_claim_output` impl
  compute X25519 ECDH twice (once for view-tag check, once as
  part of hybrid decap), or is the pre-filter result reused as
  input to the full decap? `try_claim_output`'s measured cost
  depends on the answer. Not a trait-surface concern (impl
  detail), but commit 2's bench commentary will pin the assumed
  shape so the benchmark numbers are interpretable, and so the
  implementer doesn't accidentally double-compute when the
  pre-filter result is already in scope. If the implementation
  discovers reuse is structurally impossible (e.g., the hybrid
  decap's X25519 ECDH is bundled with ML-KEM operations in a
  way that doesn't expose the intermediate), the bench commentary
  updates accordingly.
- **NotMine vs Mine bench split (option (c)).**
  `engine_trait_bench_key_try_claim_output` measures structurally
  distinct workloads depending on whether the test input is a
  Mine output (X25519 pre-filter accepts; full hybrid decap
  runs; HKDF chain runs; key image computes) or a NotMine output
  (X25519 pre-filter rejects; full hybrid decap doesn't run).
  Combined into one bench, the measurement's meaning depends on
  the test data's Mine:NotMine ratio — uninformative. The
  disposition is **(c) separate benches**:
  `engine_trait_bench_key_try_claim_output_not_mine` (the
  dominant case in real scanning — most outputs aren't yours)
  and `engine_trait_bench_key_try_claim_output_mine`
  (rare-but-expensive). Each measures a structurally distinct
  workload; both are needed to characterize scanner cost.
  Fixture setup is non-trivial (a `LocalKeys::from_test_seed`
  wallet plus a test block carrying one Mine output and N
  NotMine outputs, where NotMine outputs target distinct test
  wallets so their view-tag pre-filter rejects); commit 2 pins
  the fixture-shape requirement alongside the bench-target list.

### 6.6 Docs propagation

Mirrors PR 2's commit 9. Updates:

- `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.1 (the post-amendment
  shape committed; the in-flight subsections from Phases 0–0d
  consolidated; cross-anchors to other §2.X subsections updated).
- This design doc (post-implementation realignment subsection
  if the post-merge §2.1 surface differs from §4 above).
- `docs/CHANGELOG.md` (a new bullet under the unreleased
  Stage-1-trait-extraction section).
- `docs/FOLLOWUPS.md` — refined V3.x entries for:
  - The `AllKeysBlob: Clone` audit-or-delete decision
    (§7 below).
  - The unified V3.2 visibility-promotion bundle for `KeyEngine`,
    `LedgerEngine`, `DaemonEngine`.
  - **The retroactive Mock-X cleanup** of PR 1's `MockDaemon`
    (rename to `TestDaemon`) and PR 2's `MockLedger` (replace
    with `LocalLedger::from_test_blocks` +
    `FaultInjecting<LocalLedger>`). Per §2.1.2 / §6.4 / §7.9; both
    target V3.0 baseline alongside PR 4 or PR 5's trait-extraction
    work.
  - Any Round-2+ deferred items.

---

## 7. Open questions (Round 2+)

### 7.1 §5.2 property selection for the hybrid test

**Closed for PR 3.** §6.4 selected (a) layered-call error
preservation in commit 85f90994e; the Round 2 workflow-shape
pivot does not change the disposition (the cancel-class
observability question is about `&self` async semantics
regardless of method shape; if anything the workflow shape makes
cancel-class less observable). The cancel-class candidate is
not preserved as a forward-looking row for a future per-trait
PR — if a subsequent per-trait PR's pre-flight surfaces a
concrete observable-residual story, that PR's design doc
introduces it then.

### 7.2 `KeyEngineError` starter shape

Empty per §3.2 and PR 2's `LedgerError` precedent. Round 2
reviewer may surface concrete variants worth seeding once Phase 1
implementation surfaces the workflow methods' actual failure
modes (e.g., `OutputDetectionInputMalformed`,
`HybridDecapsulationFailed`, `SignatureProductionFailed`).
Variants land at implementation time, not speculatively in the
spec round.

### 7.3 `LocalKeys` wrapper shape

Several viable shapes (`LocalKeys(AllKeysBlob)` newtype;
`LocalKeys { keys: AllKeysBlob }` struct; `LocalKeys(Box<AllKeysBlob>)`
boxed; etc.). Pinned at commit time per PR 2's degrees-of-freedom
precedent. The `mlock` discipline noted in
[`35-secure-memory.mdc:55–60`](../../.cursor/rules/35-secure-memory.mdc)
makes `Box<AllKeysBlob>` an interesting candidate (lives on heap,
amenable to `mlock` on a single allocation). The constructor
surface is fixed: `LocalKeys::from_seed(seed: &WalletSeed) ->
Result<Self, KeyError>` for production; `#[cfg(test)]
LocalKeys::from_test_seed(test_label: &str) -> Self` for
fixtures (per §6.4's no-Mock test-substrate pattern).

### 7.4 Cross-trait error type

Per §3.2's negative-space framing, the cross-trait runtime error
candidate (concurrent key rotation invalidating an in-progress
signing attempt) doesn't have a concrete trigger at PR 3 cut-point.
If Round 2 surfaces a concrete trigger, the design doc adds a
Phase-0f for the cross-trait error type.

### 7.6 Multisig surface — additive vs. separate trait

Does the multisig surface accrete onto `KeyEngine` additively
(per §8.2's additive-amendment discipline), or get its own
`MultisigKeyEngine` trait that composes alongside `KeyEngine`?
PQC-multisig is a Stage 2 concern per
[`docs/design/PQC_MULTISIG.md`](PQC_MULTISIG.md); the PR 3 trait
does not expose any multisig surface today. The disposition is
**open**; arguments on each side:

- **Additive on `KeyEngine`:** keeps the actor abstraction (one
  `Arc<dyn KeyEngine>` per wallet) simple; multisig partial
  signatures are the same kind of capability as full-signing
  (produce signature material on a message), differing in
  per-message context rather than in trait-level surface.
- **Separate `MultisigKeyEngine`:** the multisig protocol's
  per-signer-per-round state has structurally different
  ownership and lifecycle properties (round numbers, partial
  signature accumulation, threshold checks) than `KeyEngine`'s
  per-call independence. A separate trait keeps the per-call
  contract clean and hides the per-round state.

Round 2+ may surface a preferred disposition; PR 3 ships without
multisig surface either way. (L1.4)

### 7.7 V3.x full-PQC trait churn acknowledgement

The current trait is **hybrid-transitional**. A future
full-PQC-only world re-opens §2.1 again per §8.2's closing
clause:

- `try_claim_output`'s impl-internal scanner pattern restructures
  (no classical X25519 pre-filter; the view-tag pre-filter
  becomes an ML-KEM-derived check).
- `HybridSignature` (impl-internal) becomes `MlDsa65Signature`.
- `HybridCiphertext` (impl-internal) becomes `MlKem768Ciphertext`.
- `HybridKemPublicKey` (a field of `RecipientSubaddress`) becomes
  `MlKem768PublicKey`.

**The workflow-shape pivot makes this churn substantially
smaller than it would be on a primitive-shape trait.** Message-
shape internals change (e.g., `RecipientSubaddress` swaps
`HybridKemPublicKey` for `MlKem768PublicKey`); the workflow
boundary stays. The `try_claim_output` and `sign_transaction`
signatures don't change; only the message shapes' fields churn,
and `#[non_exhaustive]` annotations on the `SubaddressPurpose` /
`SubaddressFor` enums absorb the additive variants.

This dissolves the L4.1 / L4.2 / L4.3 naming concerns from the
Round 1 review (the classical-rooted names are gone from the
trait surface); only the hybrid-rooted names inside Sub-bundle B
need V3.x churn. (L2.1, L2.3)

### 7.8 Account-address stability assumption

`account_public_address` returns `&AccountPublicAddress` with a
"stable for wallet lifetime" doc-comment. **This is a classical-
Monero assumption, not a structural necessity.** PQC schemes with
key-rotation properties (e.g., forward-secure signature schemes)
might not have a stable account-address concept in the same form.

The disposition for V3.0 / V3.x: keep the assumption explicit
and acknowledge it as an assumption rather than a property. If
a future PQC-augmented account-address scheme breaks the
stability property, the trait method either (a) returns an owned
`AccountPublicAddress` instead of a borrow (so the impl can
recompute per call), or (b) gains a parameter that selects which
generation of the rotating key to return. Either change is
non-breaking on the workflow methods (`try_claim_output`,
`sign_transaction`) and only changes `account_public_address`'s
signature.

The lens this surfaced under: (L4.2). The acknowledgement here
is not a forward-looking commitment to a particular V3.x shape;
it's a record that the PR 3 trait's classical-Monero-shaped
account-address contract is one of several places where V3.x
PQC evolution may surface trait churn.

### 7.9 Test-substrate disposition — Mock-X pattern broader rejection

§2.1.2 names the broader rejection of Mock-X parallel
implementations; §6.4 lands the per-PR-3 substrate (no
`MockKeys`; production-only `LocalKeys::from_test_seed` +
composable `FaultInjecting<K: KeyEngine>` wrapper).

The disposition has implications that propagate to PR 4–7's
per-trait-PR template content:

- **PR 4 / PR 5 substrate work** lands `MockLedger` →
  `LocalLedger::from_test_blocks` + `FaultInjecting<LocalLedger>`
  and `MockDaemon` → `TestDaemon` rename alongside their own
  trait-extraction work. See
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) for the explicit
  V3.0-baseline schedule.
- **PR 6 / PR 7 trait extractions** start without a `MockX`
  proposal at all; the no-Mock pattern is the default substrate
  shape. The pre-flight checklist for those PRs should include
  "what does the test substrate look like?" with the expected
  answer being `LocalX::from_test_*` constructors plus
  `FaultInjecting<X>` composability, not "introduce `MockX` +
  `replace_x` analog of PR 2."

(L3.3)

### 7.5 `AllKeysBlob: Clone` derive — audit or delete

`AllKeysBlob` derives `Clone`
([`shekyl-crypto-pq/src/account.rs:436`](../../rust/shekyl-crypto-pq/src/account.rs)).
Holds spend/view secret keys; `Clone` multiplies wipe surface.
Per
[`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc) and
[`35-secure-memory.mdc:26-28`](../../.cursor/rules/35-secure-memory.mdc),
`Clone` on a secret-bearing struct requires explicit, documented
justification.

**Disposition.** Add a V3.x `docs/FOLLOWUPS.md` entry framed as an
audit task with two outcomes (per the user's refined framing):

> **`AllKeysBlob: Clone` derive (`shekyl-crypto-pq/src/account.rs:436`).**
> Holds spend/view secret keys; `Clone` multiplies wipe surface.
> Per `30-cryptography.mdc` and `35-secure-memory.mdc:26–28`,
> audit whether the `Clone` has a documented justification (e.g.,
> explicit need for a duplicate during a multi-step protocol that
> can't be served by a borrow). If no justification surfaces, the
> derive should be removed and call sites that depend on it
> migrated to borrows or to explicit-`Zeroize`-aware copy patterns.
> Target: V3.x.

This converts "deletion candidate" into "audit task with two
outcomes" — either documented justification surfaces (`Clone`
stays with explicit reasoning) or no justification surfaces
(`Clone` gets removed). Future audit work has clear branching
disposition rather than just "investigate."

The audit is **not** a PR 3 blocker. PR 3's trait surface uses
`&self` exclusively and does not require `AllKeysBlob: Clone`.

---

## 8. References

- Spec: [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.1 (current) → §4 (post-amendment).
- Sibling PR design docs:
  [`STAGE_0_HARNESS.md`](STAGE_0_HARNESS.md),
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md).
- Cryptography rules:
  [`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc),
  [`35-secure-memory.mdc`](../../.cursor/rules/35-secure-memory.mdc).
- Stage 1 / Stage 2 lifecycle:
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (V3.0 baseline + V3.x
  cutover entries).
- Decision log:
  `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 — Engine
  architecture: actor model with staged migration*.

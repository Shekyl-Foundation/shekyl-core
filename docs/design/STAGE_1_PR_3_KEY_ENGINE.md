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
`sign_transaction`, and `derive_subaddress`. Concrete shapes
pinned below; doc-comment prose is normative for the Phase 0c
amendment block. Round 3+ may refine field details against PR 5
(`PendingTxEngine`) consumer constraints.

##### `OutputDetectionInput`

```rust
/// Input to `KeyEngine::try_claim_output`.
///
/// Bundles the per-output detection context the scanner extracts
/// from a single on-chain output: the hybrid ciphertext (carrying
/// the X25519 ephemeral and ML-KEM ciphertext), the view tag (for
/// the cheap pre-filter), and the output's index within its
/// containing block (used for HKDF context binding).
///
/// Constructed via `from_block_output(&LedgerBlock, u64)` (the
/// scanner's natural source-of-truth path) or `from_components`
/// (for fixture / replay paths where the source is reconstructed
/// from primitives).
pub struct OutputDetectionInput {
    /// The hybrid ciphertext (X25519 ephemeral + ML-KEM ciphertext).
    /// Public on-chain data.
    ciphertext: HybridCiphertext,
    /// The view tag, used by `try_claim_output`'s impl for the
    /// X25519 pre-filter check.
    view_tag: ViewTag,
    /// The output's index within its containing block, used for
    /// HKDF context binding inside `try_claim_output`'s impl.
    output_index: u64,
}

impl OutputDetectionInput {
    /// Construct from a ledger block + output index.
    ///
    /// **Coupling note.** This constructor is intentionally
    /// coupled to `LedgerBlock`'s field shape because that is
    /// where the source-correctness invariants live: the X25519
    /// ephemeral, the hybrid ciphertext, and the view tag are
    /// co-located in the on-chain output and must be sourced
    /// together to remain consistent. If `LedgerBlock` changes —
    /// e.g., FCMP++ scanner work refactors block structure, or
    /// PR 4–7 surface changes ripple back to ledger types — this
    /// constructor is one of the constraint sites that updates
    /// with it. This coupling is **expected and documented, not
    /// surprise**; the alternative (a `from_components(ciphertext,
    /// view_tag, output_index)`-only construction surface) would
    /// distribute source-correctness responsibility back to the
    /// caller, which the workflow-shape pivot specifically
    /// prevents.
    pub(crate) fn from_block_output(
        block: &LedgerBlock,
        output_index: u64,
    ) -> Option<Self>;

    /// Construct from already-extracted components.
    ///
    /// For fixture / replay paths where the source is being
    /// reconstructed from primitives. **Production scanner code
    /// should use `from_block_output` instead** — this constructor
    /// is exposed because tests need to build inputs against
    /// known-good components without going through full block
    /// construction.
    #[cfg(test)]
    pub(crate) fn from_components(
        ciphertext: HybridCiphertext,
        view_tag: ViewTag,
        output_index: u64,
    ) -> Self;
}
```

##### `ViewTag`

```rust
/// View tag bytes from a hybrid ciphertext.
///
/// Newtype around `[u8; N]` where `N` is pinned against the
/// FCMP++ output format. The view-tag size is a property of the
/// scanner's pre-filter design; the type's purpose at the
/// `KeyEngine` boundary is to type-distinguish view-tag bytes
/// from arbitrary 1-byte (or N-byte) fields in the surrounding
/// types.
pub struct ViewTag(pub(crate) [u8; VIEW_TAG_BYTES]);
```

`VIEW_TAG_BYTES` is a workspace-level constant (FCMP++ output
format pins the value); the `[u8; N]` shape rather than a typed
hash output is intentional — view tags are short
publicly-comparable bytestrings, not opaque hashes that need
verification machinery.

##### `OutputClaimResult` and `OutputClaim`

```rust
/// Result of a `KeyEngine::try_claim_output` call.
///
/// Mine carries the structured non-secret claim payload; NotMine
/// carries no data. Most outputs are NotMine in real scanning;
/// the X25519 pre-filter rejects them cheaply inside
/// `try_claim_output`'s impl.
#[non_exhaustive]
pub enum OutputClaimResult {
    Mine(OutputClaim),
    NotMine,
}

/// Structured non-secret claim payload from a successful output
/// detection.
///
/// **Cryptographic intermediates** (the X25519 raw 32-byte
/// shared secret, the 64-byte hybrid shared secret, HKDF
/// intermediate keying material) are **not** carried by this
/// type — they are zeroized in-place inside `try_claim_output`'s
/// stack frame. The fields below are the structured non-secret
/// payload downstream balance / spend-tx-construction code
/// needs.
pub struct OutputClaim {
    /// The output's per-output secret-key material derivative
    /// (used by spend-construction to produce the per-input
    /// signing key for this output). Wrapped in `Zeroizing<...>`
    /// because while the value is the *key* the wallet uses to
    /// spend, it is bound to the per-output context (output
    /// index + transaction context) rather than the wallet's
    /// long-term spend secret. Rotation / churn across outputs
    /// is what makes this distinct from the long-term
    /// `AllKeysBlob` material.
    pub output_secret_key: Zeroizing<[u8; 32]>,
    /// The output's key image. Public; used by both wallet-side
    /// double-spend tracking and consensus-side double-spend
    /// detection.
    pub key_image: KeyImage,
    /// The amount-blinding factor (Pedersen-commitment blinder).
    /// Used by spend-construction to balance commitments across
    /// the transaction. Not strictly secret (the receiver can
    /// recompute it from the shared secret), but treated with
    /// `Zeroizing` discipline to match the surrounding type's
    /// security posture.
    pub amount_blinding_factor: Zeroizing<[u8; 32]>,
    /// The decrypted output amount (atomic units).
    ///
    /// Open question for Round 3: should `OutputClaim` carry the
    /// already-decrypted amount, or only the
    /// `amount_blinding_factor` and let downstream code recompute
    /// the amount? Decrypting at `try_claim_output` time is the
    /// natural single-pass shape (the impl already has the shared
    /// secret in scope); requiring downstream re-decryption forces
    /// the secret-derivation path to run twice. Pinned here as
    /// "decrypt at claim time, return the value" pending Round 3
    /// pushback.
    pub amount_atomic_units: u64,
}
```

##### `TxToSign` and `TxSignatures`

```rust
/// Input to `KeyEngine::sign_transaction`.
///
/// Bundles all per-input signing context, per-output context,
/// and FCMP++ context the signing pass needs. **The exact field
/// shape depends on FCMP++ context details and is finalized in
/// PR 5 (`PendingTxEngine`)** alongside that trait's
/// transaction-build workflow; the shape pinned below is
/// PR-3-side stub adequate for trait extraction but not for
/// actual transaction construction.
///
/// Consumers: PR 5's transaction-build workflow constructs a
/// `TxToSign` and passes it to `sign_transaction` as the final
/// step before broadcast.
pub struct TxToSign {
    /// Per-input signing context. Each entry carries the input's
    /// FCMP++ membership-proof context, the per-input signing
    /// message bytes, and any per-input HKDF binding context.
    /// The exact shape is pinned in PR 5.
    pub inputs: Vec<TxInputSigningContext>,
    /// Per-output context (commitment, amount-blinding factor,
    /// destination subaddress kem_pk). Used by the signing pass
    /// to bind output commitments into the per-input signature
    /// challenges.
    pub outputs: Vec<TxOutputContext>,
    /// FCMP++ transaction-level context (reference block, anchor
    /// data, etc). Pinned in PR 5.
    pub fcmp_plus_plus_context: FcmpPlusPlusContext,
}

/// Output of `KeyEngine::sign_transaction`.
///
/// Carries hybrid signatures per-input, FCMP++ witnesses, and
/// any other signature-class output the signing pass produces.
/// All fields are public (signatures are public by definition);
/// no `Zeroizing` discipline applies.
pub struct TxSignatures {
    /// Per-input hybrid signature bundle.
    pub per_input: Vec<TxInputSignature>,
    /// FCMP++ membership-proof witnesses, one per input.
    pub fcmp_plus_plus_witnesses: Vec<FcmpPlusPlusWitness>,
}
```

> **Open questions for Round 3 / PR 5 hand-off.** The shapes
> `TxInputSigningContext`, `TxOutputContext`, `FcmpPlusPlusContext`,
> `TxInputSignature`, and `FcmpPlusPlusWitness` are referenced
> here as forward declarations. PR 5 (`PendingTxEngine`) is the
> design doc that pins them. PR 3's spec amendment block will
> name them as "shape pinned in PR 5"; PR 3's implementation work
> uses minimal stub shapes adequate for trait extraction. The
> workflow boundary stays stable across PR 5's pinning — only the
> message-shape internals change.

##### `SubaddressPurpose` and `SubaddressFor`

```rust
/// Purpose argument to `KeyEngine::derive_subaddress`.
///
/// Selects which `SubaddressFor` variant the trait method
/// returns. New purposes accrete additively in V3.x (e.g.,
/// `PqcRecipient` for hybrid-augmented subaddresses); the
/// `#[non_exhaustive]` annotation gives existing call sites a
/// compile-time signal when new variants land.
#[non_exhaustive]
pub enum SubaddressPurpose {
    /// Recipient context: encoded address + KEM public key for
    /// senders to encapsulate against. Used by payment-URI /
    /// QR-code generation paths.
    Recipient,
    /// Audit context: canonical spend / view public-key pair.
    /// Used by export / backup / inspection paths.
    Audit,
}

/// Discriminated return type from `KeyEngine::derive_subaddress`.
///
/// Each variant pairs with a `SubaddressPurpose` variant; the
/// `#[non_exhaustive]` annotation accretes additively with
/// `SubaddressPurpose`.
#[non_exhaustive]
pub enum SubaddressFor {
    Recipient(RecipientSubaddress),
    Audit(SubaddressKeyPair),
}
```

##### `RecipientSubaddress` and `SubaddressKeyPair`

```rust
/// Recipient-context subaddress payload.
///
/// Returned by `derive_subaddress(idx, SubaddressPurpose::Recipient)`.
/// Carries everything a sender needs to encapsulate to this
/// subaddress: the encoded address (for display / UI / parsing
/// at recipient input) and the KEM public key (for hybrid
/// encapsulation at transaction-build time).
pub struct RecipientSubaddress {
    /// Encoded address. Whether this is a parsed structured
    /// `Address` or a `String` representation is an open question
    /// (see "open questions" below); pinned here as `Address`
    /// (parsed structured) so the type system catches encoding
    /// errors at compile time.
    pub encoded: Address,
    /// The hybrid KEM public key (X25519+ML-KEM-768) the sender
    /// encapsulates against. Public; not zeroized.
    pub kem_pk: HybridKemPublicKey,
}

/// Audit-context subaddress payload.
///
/// Returned by `derive_subaddress(idx, SubaddressPurpose::Audit)`.
/// Carries the canonical classical spend / view public-key pair
/// for the subaddress index; used by export / backup paths.
///
/// **Today's classical-only shape.** Per `30-cryptography.mdc`'s
/// hybrid-by-default rule, a future V3.x shape may extend the
/// audit payload with the hybrid KEM PK (mirroring
/// `RecipientSubaddress.kem_pk`). The extension lands as an
/// additional field on `SubaddressKeyPair` (or as a new variant
/// on `SubaddressFor` + `SubaddressPurpose`) when designed.
pub struct SubaddressKeyPair {
    pub spend_pk: [u8; 32],
    pub view_pk: [u8; 32],
}
```

##### Open questions for Round 3 / commit 3+

The shapes above pin enough structure to confirm the workflow-
shape direction at Round 2 review. Several field-level questions
remain open and will be pinned in Round 3 or in PR 3's
implementation work:

- **`TxInputSigningContext` and `TxOutputContext` shapes.** Pinned
  in PR 5's design doc, not PR 3's. The forward-declaration shape
  in `TxToSign` is adequate for PR 3's trait extraction; PR 5's
  consumer-constraint analysis pins the field-level details.
- **`FcmpPlusPlusContext` shape.** Same; pinned in PR 5.
- **`Address` type provenance.** Whether the workspace already
  carries a parsed structured `Address` type (likely in
  `shekyl-wallet-core` or similar), or whether PR 3 / commit 3+
  needs to introduce one as an additional Phase 0c row. If the
  workspace has it, cite the path; if not, add the Phase 0c row.
- **`KeyImage` type provenance.** Same as `Address`. The
  workspace likely has a `KeyImage` newtype somewhere; cite the
  path or add the Phase 0c row.
- **`OutputClaim::amount_atomic_units` decryption-at-claim-time
  vs decrypt-on-demand.** Pinned here as "decrypt at claim time,
  return the value"; reviewers may push back on the security-
  surface argument (the decrypted amount is shaped like a
  trait-surface secret-bearing field even though it isn't a
  secret).
- **`RecipientSubaddress::encoded` parsed vs string.** Pinned here
  as parsed structured `Address`; reviewers may prefer a
  `String` representation if the structural typing imposes
  parsing overhead at unwanted points.

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
    /// returned: `SubaddressPurpose::Recipient` returns
    /// `SubaddressFor::Recipient(RecipientSubaddress { encoded,
    /// kem_pk })` (encoded address + hybrid KEM public key for
    /// senders to encapsulate against; used by payment-URI /
    /// QR-code generation paths); `SubaddressPurpose::Audit`
    /// returns `SubaddressFor::Audit(SubaddressKeyPair { spend_pk,
    /// view_pk })` (canonical classical spend / view PK pair; used
    /// by export / backup / inspection paths). Both enums are
    /// `#[non_exhaustive]`; new purposes accrete additively in
    /// V3.x (e.g., `PqcRecipient` for hybrid-augmented subaddresses
    /// extending the audit payload with the hybrid KEM PK) per
    /// Q9.2 / §8.2.
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
    /// boundary. The `OutputDetectionInput` carries the per-output
    /// detection context (hybrid ciphertext, view tag, output
    /// index) sourced via `OutputDetectionInput::from_block_output`
    /// at the scanner call site. Returns
    /// `OutputClaimResult::Mine(OutputClaim)` on a successful
    /// detection, carrying the per-output secret-key derivative,
    /// key image, amount-blinding factor, and decrypted amount;
    /// or `OutputClaimResult::NotMine` for outputs that don't
    /// claim. Most outputs are `NotMine` in real scanning; the
    /// X25519 pre-filter rejects them cheaply.
    ///
    /// **Cryptographic intermediates never cross the trait
    /// boundary.** The X25519 raw shared secret (32 bytes), the
    /// 64-byte hybrid shared secret, and HKDF intermediate keying
    /// material exist only transiently inside this method's stack
    /// frame and are zeroized on drop per the workspace's
    /// `Zeroize` / `ZeroizeOnDrop` discipline. The `OutputClaim`'s
    /// secret-bearing fields (`output_secret_key`,
    /// `amount_blinding_factor`) are wrapped in `Zeroizing<...>`;
    /// the orchestrator owns the zeroize-on-drop discipline once
    /// the claim crosses the boundary.
    async fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> Result<OutputClaimResult, Self::Error>;

    /// Workflow: sign a fully-prepared transaction.
    ///
    /// The `TxToSign` parameter bundles all per-input signing
    /// context (`Vec<TxInputSigningContext>`), per-output context
    /// (`Vec<TxOutputContext>`), and FCMP++ transaction-level
    /// context (`FcmpPlusPlusContext`). The exact field shapes
    /// for the per-input / per-output / per-tx context types are
    /// pinned in PR 5 (`PendingTxEngine`) alongside that trait's
    /// transaction-build workflow; PR 3 carries forward
    /// declarations adequate for trait extraction. The implementor
    /// handles per-input hybrid signature production, FCMP++
    /// witness generation, and any other signature-class work the
    /// transaction requires. Returns `TxSignatures` carrying the
    /// `Vec<TxInputSignature>` and `Vec<FcmpPlusPlusWitness>`
    /// bundle.
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
(`try_claim_output(&OutputDetectionInput)`,
`sign_transaction(&TxToSign)`) with the error variant intact, the
`OutputClaimResult` / `TxSignatures` return types not produced
(the error short-circuits before construction), and the
layered-call structure preserved across the wallet-level method's
internal trait dispatch.

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
  No fixture beyond a `LocalKeys::from_test_seed` instance.
- `engine_trait_bench_key_try_claim_output_not_mine` — async
  workflow path for the **dominant scanning case**: an output
  whose X25519 view-tag pre-filter rejects. Measures the
  X25519 ECDH + view-tag derivation + tag-comparison + early-
  return path, which is what runs ~99%+ of the time during a
  full wallet rescan. The highest-leverage benchmark on the
  trait for total-wall-clock-time terms.
- `engine_trait_bench_key_try_claim_output_mine` — async
  workflow path for the **rare-but-expensive** case: an output
  whose pre-filter accepts and triggers the full hybrid decap
  + HKDF chain + key-image computation. Measures the full
  output-detection-and-claim cost. Less time-dominant than the
  NotMine path in aggregate scanning but worth a separate bench
  because the workloads are structurally distinct (combining
  them into one bench produces a number whose meaning depends
  on the test data's Mine:NotMine ratio — uninformative).
- `engine_trait_bench_key_sign_transaction` — async workflow
  hot path for the spend path; potentially deferred to Phase-2a
  if hybrid-signature setup cost dwarfs the trait-dispatch
  overhead measurement, or if the bench fixture (a complete
  `TxToSign` with FCMP++ context) is structurally too heavy to
  set up at PR 3 cut-point. The fixture-construction work
  shares substrate with PR 5 (`PendingTxEngine`) and may land
  there instead.

The frozen baselines and cumulative-delta documentation pattern
established in PR 2's `docs/PERFORMANCE_BASELINE.md` extend to
PR 3; the post-PR-3 row count grows by 3–4 (one for
`account_public_address`, two for the `try_claim_output` split,
optionally one for `sign_transaction`).

**Bench fixture shape.** `try_claim_output_not_mine` and
`try_claim_output_mine` need different fixture inputs:

- **`_not_mine` fixture.** A `LocalKeys::from_test_seed("a")`
  wallet under test, plus a single `OutputDetectionInput`
  constructed via `from_components(...)` carrying a hybrid
  ciphertext and view tag derived from a *different* test wallet
  (`from_test_seed("b")`)'s spend / view secret. The view-tag
  pre-filter rejects; the bench measures the rejection path's
  cost.
- **`_mine` fixture.** A `LocalKeys::from_test_seed("a")` wallet
  under test, plus a single `OutputDetectionInput` constructed
  from a hybrid ciphertext / view tag derived against the same
  test wallet's KEM public key. The pre-filter accepts; the
  bench measures the full hybrid-decap + HKDF + key-image path.

Both fixtures are deterministic and reproducible across runs.
The construction surface is `OutputDetectionInput::from_components`
(the `#[cfg(test)]`-gated alternative to `from_block_output`,
introduced specifically for fixture-construction without going
through full block construction).

**X25519 ephemeral reuse vs double-compute (impl-internal note
for bench-cost interpretability).** The X25519 ephemeral
(`HybridCiphertext.x25519`) is public on-chain data; both the
view-tag pre-filter (impl-internal step 1) and the full hybrid
decap (impl-internal step 2) need an ECDH against it. The bench
commentary assumes the pre-filter's ECDH result is **reused** as
input to the full hybrid decap rather than recomputed: the impl
holds a `Zeroizing<[u8; 32]>` X25519 SS scratch local across the
view-tag check and the hybrid decap entry point, eliminating the
~50 µs X25519 round trip that a naive double-compute would add
to the Mine path. If implementation surfaces a structural reason
the reuse is impossible (e.g., the hybrid decap's X25519 ECDH is
internally bundled with ML-KEM operations in a way that doesn't
expose the intermediate scalar), the `_mine` bench's measured
cost rises by the X25519 round-trip cost; the bench commentary
updates with the actual disposition once Phase 1 lands.

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

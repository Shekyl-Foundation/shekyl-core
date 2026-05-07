# Stage 1 PR 3 — `KeyEngine` extraction — design

**Status.** Round 4 closed; M3a pre-flight pending. Stage 1 PR 3 of the seven-trait
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
+ commit-time + post-merge; PR 3's pre-flight pass surfaced 5
amendments at the design-doc stage (Round 1), Round 2 surfaced a
substantive workflow-shape pivot, and Round 3 surfaced a handle-
indirected contract pivot completing the workflow-shape pivot's
"no secrets cross the trait boundary" property. The accumulating
drift count is not a defect — it is the discipline working as
designed against a trait whose pre-Round-1 §2.1 surface predates
the workspace's hybrid-cryptography framework solidification (see
§2.1 below) and whose security-claim-vs-message-shape mismatch
required adversarial review to surface.

## Round trajectory

- **Round 1 (commit `24a936e4f`).** Pre-flight gap-check captured
  5 drift bundles; substantive design choices pinned per the user's
  Decision-1-through-Decision-5 reasoning recorded in §3;
  trait-surface diff for the post-amendment §2.1 shape staged in
  §4; sequencing for preparatory amendment PRs and the optional
  preparatory code PR (`AllKeysBlob` `ZeroizeOnDrop` migration)
  staged in §5. Round 1 review pass landed as commit `85f90994e`.
- **Round 2 (commits `1c20fb7ee`, `3e3cb292c`).** Substantive
  workflow-shape pivot replacing primitive-shape methods
  (`view_ecdh`, `hybrid_decapsulate`, `sign_with_spend`) with
  workflow-shape methods (`try_claim_output`, `sign_transaction`).
  Concrete message-shape definitions pinned for Sub-bundle B
  (`OutputDetectionInput`, `OutputClaimResult`, `OutputClaim`,
  `TxToSign`, `TxSignatures`, `SubaddressPurpose`, `SubaddressFor`,
  `RecipientSubaddress`, `SubaddressKeyPair`, `ViewTag`).
  Purpose-decomposed subaddress derivation. No-Mock test substrate
  pattern (§2.1.2). Trust-class A/B classification deferred.
- **Round 3 (substantive content complete; commits 3a,
  3a-review-pass, 3b, 3c, 3d, 3e landed).** Adversarial
  wargaming pass surfaced 12 findings clustered into 7
  threat patterns (4 generalizing to PR 4–7's pre-flight
  checklist; 3 KeyEngine-specific). Round-3 dispositions
  landed across five sequential commits (3a–3e):
  - **3a (commit `8553ae297`).** Handle-indirected workflow
    contract per A1's α disposition; `OutputClaim` reshape;
    seven-bullet "deliberately does not expose" subsection;
    Round-4 candidates pinned (A6, A7, handle persistence,
    concurrency-quality).
  - **3a review pass (commit `32057219f`).** Capability-vs-
    material honesty for active attacker (bullet 4); softer
    framing of trait-surface scope vs implementor-internal
    discipline (bullet 5); §7.11 option-space expanded to four
    candidates (split (2) into 2a / 2b); §6.4 orphan-absence
    verification mechanism deferred to commit 3d.
  - **3b (commit `b020a33cc`).** A2 → β disposition: per-
    subaddress `kem_pk` derivation specification. New §3.1.3
    walks the priority-hierarchy decomposition showing β is
    rule-forced (α decomposes into (P1) X25519-only / (P2)
    wallet-level ML-KEM PK in encoding / (P3) out-of-band PK
    delivery, each violating a priority-hierarchy rule). §3.3
    Sub-bundle A pins `SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT =
    b"shekyl/subaddr-mlkem-keygen-v1"` and the
    `derive_subaddress_kem_keypair` primitive. Sub-bundle B
    `RecipientSubaddress` doc-comment refresh (E1) makes the
    dual-derivation contract explicit; `SubaddressKeyPair`
    tightened to note V3.x audit-payload extension composes
    with the same primitive. §4 `derive_subaddress`
    doc-comment names the per-call cost regime (~50 µs
    dominated by ML-KEM-768 KeyGen).
  - **3c (this commit).** Pattern-2 spec-silent junctions
    cluster (Sub-bundle E). New §3.1.4 frames the threat-pattern
    shape ("load-bearing cryptographic junctions whose
    specification lives in implementation lore rather than at
    the spec level") and lands the Pattern-2 generalization
    checklist for PR 4–7 pre-flight. Four findings closed:
    **A3** — per-output HKDF derivation pinned by reference to
    the canonical `shekyl-crypto-pq::derivation` registry
    (`HKDF_SALT_OUTPUT_DERIVE`,
    `HKDF_SALT_VIEW_TAG_X25519`, `SALT_KEM_DERIVE_V1`,
    per-secret labels), with the "tx_context_hash" wargaming
    framing reframed as overspecified (per-output uniqueness
    is delivered by `combined_ss` being per-output-unique by
    construction). **A4** — `VIEW_TAG_BYTES = 1` pinned at the
    spec level, matching `derive_view_tag_x25519`'s `u8`
    return type and the existing `SharedKey::view_tag` shape.
    **A5 → ζ** — method-to-domain binding via `SignsInDomain`
    marker trait + per-domain unit-struct markers
    (`SignTransactionDomain`, `OutputSecretDerivationDomain`,
    `FcmpPlusPlusWitnessDomain`, `MlKemChallengeDomain`) plus
    the generic `derive_signing_key<D: SignsInDomain>`
    primitive; cross-domain reuse becomes a compile-time-
    inspectable action rather than a copy-paste accident. **D1**
    — `sign_transaction` validation contract pinned with
    impl-side responsibilities (handle resolution, per-input
    signature production, FCMP++ witness production) and
    caller-side preconditions (amount accounting, fee
    correctness, address validity, structural well-formedness)
    explicit. §3.3 Sub-bundle A grows by five rows
    (`VIEW_TAG_BYTES`, `OUTPUT_DERIVE_HKDF_REGISTRY` reference,
    `SignsInDomain` trait, four per-domain markers,
    `derive_signing_key` primitive); §3.3 Sub-bundle B's
    `ViewTag` doc updates the `VIEW_TAG_BYTES` pin language;
    §4's `try_claim_output` doc-comment adds the A3 derivation
    reference; §4's `sign_transaction` doc-comment adds the D1
    validation contract and inlines the A5 → ζ disposition.
  - **3d (this commit).** Pattern-3 / Pattern-4 cluster
    (Sub-bundle F). New §3.1.5 frames the cluster's
    threat-pattern shape (Pattern 3: test substrate
    visibility leakage; Pattern 4: external-implementor
    trust + visibility discipline). Three findings closed:
    **B1** — three-layer discipline for test-only constructors
    and inspection accessors (`#[cfg(test)]` cfg-gate +
    `pub(crate)` visibility + CI gate); applies to
    `LocalKeys::from_test_seed` and the new
    `LocalKeys::handle_table_size` accessor; pinned in §6.6.
    **B2** — handle-storage hygiene replaces the pre-A1
    lifetime-of-secret-material framing post-A1's
    handle-indirection; three hygiene properties (orphan
    absence, entry deletion on consumption, bounded growth)
    anchored against the workflow-internal `HandleTable`;
    pinned in §6.7. **Attack 4.2** — per-message-type
    visibility table with explicit rationale for the
    Sub-bundle B types; Trust-class B classification confirms
    the `pub` visibilities; new "Visibility discipline for
    Sub-bundle B message types" subsection lands in §3.3.
    §6.4's deferred orphan-absence verification mechanism is
    pinned to option (i) — the test-inspection accessor under
    the three-layer discipline — closing the Round-4
    prerequisite for the post-A1 hygiene tests. The Pattern-3
    and Pattern-4 generalization checklists are forward-
    template content for PR 4–7's pre-flight discipline (per
    §3.1.5).
  - **3e (this commit).** Residual + forward-template
    content (Sub-bundle G). New §3.1.6 frames the Pattern-6
    replay/idempotency cluster and lands the KeyEngine
    method-by-method contract table (per-method idempotency,
    side-effect, and retry-safety columns for
    `account_public_address`, `derive_subaddress`,
    `try_claim_output`, `sign_transaction`). The Pattern-5
    cross-call-state pattern is acknowledged as adjacent but
    distinct; KeyEngine's specific Pattern-5 disposition stays
    in §7.13 as Round-4 work. **§2.1.3** lifts the Trust-class
    A/B classification from a Stage-4 promotion-time debate to
    a per-trait PR design-doc decision: PR 1 = B; PR 2 = B;
    PR 3 = A; PR 4–7 classify at design time. **§2.1.4** lands
    the Pattern-7 economic-incentive emergence cross-reference
    rule: per-trait PRs that surface resource-asymmetry
    concerns escalate to project-level economic-design review
    via FOLLOWUPS / `docs/DESIGN_CONCEPTS.md` rather than
    embedding the analysis in the trait scope. **§2.1.5**
    consolidates the four-pattern checklist for PR 4–7
    pre-flight (Pattern 2 spec-silent junctions; Pattern 3
    test substrate visibility; Pattern 4 visibility / external-
    implementor trust; Pattern 6 replay/idempotency contract);
    Pattern 1 (workflow-shape) is upstream and Pattern 5
    (cross-call state) is downstream-deferred; Pattern 7 is
    the escalation rule from §2.1.4. **§2.1.6** lands the
    trajectory meta-note on accumulated adversarial intuition
    as forward-template content; PR 4–7's pre-flight is
    bootstrapped with the patterns rather than starting from
    scratch, and per-trait PR rounds budgets are likely to be
    smaller because the substrate is more substantial.
    **§7.9** (Mock-X disposition) marked closed for PR 3
    with cross-references to §2.1.5's Pattern-3 forward-
    template; **§7.14** added as a closure cross-reference
    for the Pattern-6 disposition table. §1.1 Phase 0c prose
    grew Sub-bundle G mention. Round trajectory updated to
    mark Round 3 substantive content complete.
- **Round 4 (closed).** Round 4 produced the migration-planning
  artifact set rather than closing the handle-model emergent
  surface that Round 3 deferred. Specifically: the
  architectural-inheritance discipline anchor
  ([`.cursor/rules/16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)),
  the workspace surface audit
  ([`docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md`](STAGE_1_PR_3_MIGRATION_AUDIT.md)),
  and the operational migration plan
  ([`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](STAGE_1_PR_3_MIGRATION_PLAN.md))
  for the 5-PR M3a–M3e sequence the audit's findings shape,
  plus a continuity-of-discipline coda in §3.1.2 framing the
  migration as the same discipline already operative in
  `rust/shekyl-oxide/` applied retroactively to wallet-side state
  inherited from `wallet2.h::struct transfer_details`.

  **What Round 4 deliberately deferred.** The handle-model
  emergent attack surface that Round 3 surfaced as deferral
  candidates remains open: A6 (handle-table memory-pressure /
  §7.10), A7 (handle unforgeability / §7.12), handle persistence
  across wallet restart (§7.11 four-option-space), and Pattern-5
  cluster (handle-table concurrency quality / §7.13 with explicit
  timing-channel analysis). Closing those is M3a-pre-flight work
  per the migration plan §3.1, not Round-4 work — separating the
  "what we're migrating and how" planning concern from the "what
  the new shape's open questions resolve to" implementation
  concern keeps each PR's review surface bounded.

- **M3a pre-flight (forthcoming).** Per the migration plan, M3a's
  pre-flight investigation closes §7.10–§7.13 dispositions
  (concurrent-access shape; handle-derivation formula and its
  coupling to §7.11's persistence disposition; memory-pressure
  bound). The migration plan §3.1 currently defers these to
  M3a pre-flight rather than over-specifying them; M3a's PR will
  amend the migration plan to cite the closures. Per
  [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)'s
  4–6-rounds-before-implementation rule for crypto-critical
  trait migrations, M3a does not cut a feat branch until the
  pre-flight closes the deferred questions; the substrate
  Round 3 produced (the four-pattern checklist; the Trust-class
  A/B classification; the Pattern-7 escalation rule) is
  forward-template content for PR 4–7 regardless of how the
  handle-model emergent surface resolves.

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
| 0c | Workflow-internal types + message shapes for cross-boundary travel (Sub-bundle A: `pub(crate)` impl-internals — `SignDomain`, `AccountPublicAddress`, `HandleTable`, `SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT`, `derive_subaddress_kem_keypair` primitive, `VIEW_TAG_BYTES`, `OUTPUT_DERIVE_HKDF_REGISTRY` reference, `SignsInDomain` marker trait + per-domain markers (`SignTransactionDomain`, `OutputSecretDerivationDomain`, `FcmpPlusPlusWitnessDomain`, `MlKemChallengeDomain`), `derive_signing_key<D: SignsInDomain>` primitive; Sub-bundle B: trait-surface message shapes — `OutputDetectionInput`, `OutputHandle`, `OutputClaimResult`, `OutputClaim`, `TxToSign`, `TxSignatures`, `SubaddressPurpose`, `SubaddressFor`, `RecipientSubaddress`, `SubaddressKeyPair`, `ViewTag`; Sub-bundle C: handle-indirected workflow contract — `OutputHandle` is opaque to the orchestrator with inner shape pinned in Round 4; Sub-bundle D: per-subaddress `kem_pk` derivation — `RecipientSubaddress.kem_pk` derives deterministically from view secret + subaddress index per §3.1.3, β disposition rule-forced by `00-mission.mdc`'s priority hierarchy; Sub-bundle E: Pattern-2 spec-silent junctions — A3 per-output HKDF derivation reference, A4 `VIEW_TAG_BYTES = 1` pin, A5 → ζ marker-trait domain-binding, D1 `sign_transaction` validation contract, all per §3.1.4) | Doc-only spec amendment | Additive |
| 0d | `pub(crate)` visibility + `Send + Sync + 'static` super-bound + Q9.3 disposition correction | Doc-only spec amendment | Additive |
| 0e (optional, code) | `AllKeysBlob` migrated to `#[derive(Zeroize, ZeroizeOnDrop)]` | Code PR in `shekyl-crypto-pq` | Out of §2.1 scope (precondition correction) |

**Phase 0c sub-bundle structure.** Sub-bundle A (workflow-internal types) lives behind the trait surface as `pub(crate)` impl-internals — `SignDomain` is no longer a trait-level concept; it cryptographically separates HKDF contexts inside `LocalKeys`'s impl. `HandleTable` (added in Round-3 commit 3a) is the workflow-internal state mapping `OutputHandle` → per-output secret material; concurrent-access shape pinned in Round 4. `SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT` and the `derive_subaddress_kem_keypair` primitive (added in Round-3 commit 3b) pin the per-subaddress deterministic ML-KEM-768 keygen path that `derive_subaddress(_, Recipient)` consumes. Sub-bundle B (message shapes) is the actor-message granularity at which `KeyEngine` exposes work; each shape is a structured non-secret bundle that crosses the trait boundary in place of the primitive-shape signatures the pre-amendment §2.1 named. Sub-bundle C (handle-indirected workflow contract) is the post-Round-3 disposition: per-output spending material does not cross the trait boundary; the orchestrator receives an opaque `OutputHandle` and references it in subsequent `sign_transaction` calls. Sub-bundle D (per-subaddress `kem_pk` derivation, added in Round-3 commit 3b per §3.1.3) pins the rule-forced disposition that `RecipientSubaddress.kem_pk` derives deterministically from view secret + subaddress index — α (drop per-subaddress `kem_pk`) decomposes into three sub-options each violating a priority-hierarchy rule, leaving β as the only admissible disposition. Sub-bundle E (Pattern-2 spec-silent junctions, added in Round-3 commit 3c per §3.1.4) closes four load-bearing cryptographic junctions whose specification previously lived in implementation lore: A3 pins the per-output HKDF derivation by reference to the canonical `shekyl-crypto-pq::derivation` registry; A4 pins `VIEW_TAG_BYTES = 1` at the spec level; A5 → ζ pins method-to-domain binding via the `SignsInDomain` marker trait + associated const for compile-time cross-domain-reuse prevention; D1 pins the `sign_transaction` validation contract, separating impl-side responsibilities (handle resolution, per-input signature production, FCMP++ witness production) from caller-side preconditions (amount accounting, fee correctness, address validity, structural well-formedness). Sub-bundle F (Pattern-3 / Pattern-4 test-substrate + visibility discipline, added in Round-3 commit 3d per §3.1.5) lands three dispositions: B1 — three-layer discipline (`#[cfg(test)]` cfg-gate + `pub(crate)` visibility + CI gate) for test-only constructors and inspection accessors (§6.6); B2 — handle-storage hygiene replaces the pre-A1 lifetime-of-secret-material framing, with three test properties (orphan absence, entry deletion on consumption, bounded growth) anchored against the workflow-internal `HandleTable` (§6.7); Attack 4.2 — per-message-type visibility table with explicit rationale for Sub-bundle B types and Trust-class B classification (§3.3 "Visibility discipline for Sub-bundle B message types" subsection). §6.4's orphan-absence verification mechanism (deferred from the 3a review pass) is pinned to option (i) — the `handle_table_size` test-inspection accessor under the three-layer discipline. Sub-bundle G (Pattern-6 replay/idempotency cluster + forward-template content, added in Round-3 commit 3e per §3.1.6) lands the KeyEngine method-by-method replay/idempotency contract table (`account_public_address` and `derive_subaddress` pure-read / pure-derivation; `try_claim_output` workflow-level idempotent with handle-table insertion side effect; `sign_transaction` handle-consuming with deliberate replay rejection at the trait surface), plus the four-pattern forward-template content for PR 4–7 pre-flight (§2.1.5), the Trust-class A/B classification (§2.1.3), the Pattern-7 economic-incentive emergence cross-reference rule (§2.1.4), and the trajectory meta-note on accumulated adversarial intuition (§2.1.6). Stub-quality shapes landed in commit 1 of this design-doc round; concrete field sets landed in commit 2; the handle-indirected reshape lands in Round-3 commit 3a; the per-subaddress `kem_pk` derivation specification lands in Round-3 commit 3b; the spec-silent-junctions cluster lands in Round-3 commit 3c; the test-substrate + visibility discipline cluster lands in Round-3 commit 3d; the replay/idempotency cluster + forward-template content lands in Round-3 commit 3e (concluding Round 3 substantive content; further refinement accepts at Round 4+ against the handle-table internal disposition).

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

#### 2.1.3 Trust-class A/B classification across per-trait PRs

Per-trait PRs handle either **secret material directly**
(long-term keys, per-output secrets, signing material —
Trust-class A) or **public state only** (block heights,
transaction hashes, public addresses, opaque references like
`OutputHandle` — Trust-class B). The classification has
visibility-promotion implications: Trust-class A traits stay
`pub(crate)` until external-implementor trust models are
concrete (the V3.2 visibility-promotion bundle at the
earliest); Trust-class B traits may ship `pub` from V3.0 with
the standard external-implementor caveats.

Round 3 lifts the classification from a Stage-4 promotion-time
debate to a per-trait PR design-doc decision. The per-trait
PR design doc names the trust class at the design stage and
records the rationale; the V3.2 visibility-promotion bundle
becomes a ratification exercise rather than a debate.

| Per-trait PR | Trust class | Trait-level visibility (V3.0) | Rationale |
|---|---|---|---|
| PR 1 (`DaemonEngine`) | **B** | `pub(crate)` per Stage-1 default | Handles public on-chain queries; no secret material. May promote at V3.2 alongside `KeyEngine` and `LedgerEngine` per the unified bundle. |
| PR 2 (`LedgerEngine`) | **B** | `pub(crate)` per Stage-1 default | Handles ledger snapshots, balance summaries, height queries; no secret material directly. Wallet-state values pass through but are public-derivable from the trait's inputs. |
| PR 3 (`KeyEngine`) | **A** | `pub(crate)` per Stage-1 default | Handles long-term wallet keys (`AllKeysBlob`), per-output spending material (in `HandleTable`), signature production. The handle-indirected workflow shape (§3.1.2) keeps secret material confined to the engine's address space, but the engine itself is Trust-class A. The `pub(crate)` visibility prevents external implementors from materializing before the trust-model framework is concrete. |
| PR 4 (forthcoming) | (TBD at design time) | `pub(crate)` per Stage-1 default | Per-PR design doc names. |
| PR 5 (`PendingTxEngine`, forthcoming) | (TBD at design time) | `pub(crate)` per Stage-1 default | Per-PR design doc names. |
| PR 6 / PR 7 (forthcoming) | (TBD at design time) | `pub(crate)` per Stage-1 default | Per-PR design doc names. |

**Forward-template instruction.** Each PR 4–7 design doc
includes a one-line classification: "Trust class: A (handles
long-term secret material) [or B (handles public state only)].
V3.2 promotion implications: [...]." The classification is
named at the same time the trait's primary purpose is named,
not at promotion time. Where a trait's classification is
ambiguous (e.g., Trust-class B for the trait's primary methods,
Trust-class A for an additive method that handles secrets), the
default disposition is **classify as A**: the unified V3.2
promotion bundle handles the visibility decision, not the
per-method decisions.

**V3.2 visibility-promotion bundle.** Per [§7.7](#77-v3x-fullpqc-trait-churn-acknowledgement)
and the existing follow-up entries, the V3.2 bundle promotes
Trust-class B traits to `pub` (or per the per-PR rationale)
based on materialized external-consumer trust models. Trust-
class A traits remain `pub(crate)` until external-implementor
trust models are themselves concrete (a separate Stage-4
question; the lifecycle is "make the actor abstraction work
across `Arc<dyn KeyEngine>` boundaries first; expose to
external implementors only when the abstraction is hardened").

#### 2.1.4 Pattern-7 economic-incentive emergence — cross-reference rule

A trait surface that introduces resource asymmetry (some
operations cheap, others expensive; some operations bounded,
others unbounded; some operations free, others rate-limited)
creates an attack vector orthogonal to the trait's primary
correctness contract: **adversaries who can drive the wallet
into the expensive-operation regime asymmetrically cost the
defender**. KeyEngine's A6 finding (handle-table memory-
pressure, §7.10) is an instance — an adversary who can inject
many crafted outputs that pass the X25519 pre-filter forces
the `HandleTable` to grow without bound, asymmetrically
costing the defender's memory.

> **Pattern 7 — Economic-incentive emergence.** A trait method
> whose cost differs significantly across input regimes creates
> an asymmetric-cost lever. Adversaries who can shape the
> input distribution can shape the cost imposed on the
> defender. The pattern is not a per-trait correctness
> finding — the trait's primary contract is unaffected; the
> impact is at the project-level economic-design layer (the
> defender's resource budget under adversarial workload).

**Cross-reference rule for per-trait PRs.** When a per-trait
PR's pre-flight surfaces a resource-asymmetry concern, the
per-trait PR **does not** embed the project-level economic-
design analysis in the trait scope. Instead, the per-trait PR:

1. Records the asymmetry as a finding at the per-trait
   design-doc level (e.g., §7.10 for KeyEngine's A6), with
   Round-4 candidate dispositions named.
2. Opens a coordination ticket against the project-level
   `docs/DESIGN_CONCEPTS.md` economic-design section (or the
   equivalent project-level doc) referencing the per-trait
   finding.
3. Per-trait PR ships with the Round-4 disposition placeholder;
   project-level analysis lands at the project-level pace.

The discipline keeps per-trait PR review surfaces bounded and
aligns the analysis location with the analysis level. Per-
trait PR reviewers verify "the asymmetry is named and
escalated"; project-level reviewers verify "the asymmetry's
economic-design implications are dispositioned."

**KeyEngine A6 cross-reference.** A6 (handle-table memory-
pressure) is named at §7.10 with Round-4 candidate
dispositions (hard size cap with eviction; backpressure /
orchestrator-cooperative pruning; persistence-bounded growth).
The cross-reference to project-level economic-design lives in
the FOLLOWUPS entry seeded by this commit; the project-level
analysis lands when the V3.x economic-design framework is
written.

#### 2.1.5 Four-pattern checklist for PR 4–7 pre-flight

Round 3's adversarial pass produced four threat patterns whose
shape generalizes beyond KeyEngine. Each pattern is a class of
finding the per-trait PR pre-flight catches systematically
rather than relying on adversarial review to surface them
case-by-case. PR 4–7 inherit the checklist as forward-template
content; the per-trait PR design doc records the disposition
for each pattern at the design stage.

**Checklist (apply to every per-trait PR's pre-flight):**

1. **Pattern 2 — Spec-silent load-bearing junctions.**
   Read the trait's doc-comments. List every load-bearing
   cryptographic operation named. For each, ask:
   (a) "If a future maintainer rebuilt this from the spec
   alone, would they bind the same context into the
   primitive?" and
   (b) "If a cross-version verifier consumed the spec alone,
   would they reject outputs the impl rejects?"
   If either answer is no, the junction is spec-silent and
   worth pinning at the per-trait PR design-doc level. See
   §3.1.4 for the pattern's full framing and KeyEngine's
   instances (A3 per-output HKDF derivation, A4
   `VIEW_TAG_BYTES` pin, A5 → ζ method-to-domain marker
   trait, D1 `sign_transaction` validation contract).
2. **Pattern 3 — Test substrate visibility leakage.**
   For each test-only addition to a production type
   (constructors, inspection accessors, fault-injection
   wrappers), apply the three-layer discipline:
   `#[cfg(test)]` cfg-gate (Layer 1) + `pub(crate)` or
   tighter visibility (Layer 2) + CI gate (Layer 3). The
   default when in doubt is **trait-surface-observable, not
   test-only-observable**; the test-only addition is a
   fallback when the trait-surface alternative would weaken
   the trait's contract. See §3.1.5 for the pattern's full
   framing and §6.6 for KeyEngine's instances.
3. **Pattern 4 — External-implementor trust + visibility
   discipline.** For each message type that crosses the
   trait boundary, pin the type-level and per-field
   visibility with explicit rationale at the per-trait PR
   design-doc level. The default visibility is the
   **tightest that satisfies the trait's contract**;
   widening to `pub` requires naming the consumer that
   needs the wider visibility. The trait-level visibility
   couples to the Trust-class A/B classification (§2.1.3);
   message types are typically Trust-class B (the opaque-
   reference pattern keeps secret material confined to
   workflow internals). See §3.1.5 for the pattern's full
   framing and §3.3 Sub-bundle B's visibility-discipline
   subsection for KeyEngine's instances.
4. **Pattern 6 — Replay / idempotency contract.**
   For each trait method, pin the (i) idempotency contract,
   (ii) side-effect contract, and (iii) retry safety in a
   per-method table at the per-trait PR design-doc level.
   The default disposition for new trait methods is
   **explicit contract specification**; spec-silent on this
   axis is a finding the pre-flight catches. See §3.1.6 for
   the pattern's full framing and KeyEngine's instances
   (`account_public_address`, `derive_subaddress`,
   `try_claim_output`, `sign_transaction`).

**Pattern 1 (workflow-shape vs. primitive-shape) and Pattern
5 (cross-call state) cross-references.** Pattern 1 is
fundamental and pre-dates the Round-3 cluster — every per-
trait PR's pre-flight should already validate against it per
§2.1.1's framing. Pattern 5 (cross-call state correlation as
side-channel) is per-trait-PR-conditional: per-trait PRs
whose methods are stateless dispose of it trivially; per-trait
PRs whose methods carry concurrent-access state (KeyEngine's
`HandleTable`; potentially future per-trait-PR concurrent-
access shapes) defer to Round-4 disposition with explicit
timing-channel analysis. Neither is part of the four-pattern
pre-flight checklist (Pattern 1 is upstream; Pattern 5 is
downstream); both are acknowledged as adjacent.

**Pattern 7 (economic-incentive emergence) cross-reference.**
Pattern 7 is the escalation rule (§2.1.4) rather than a
pre-flight checklist item. Per-trait PRs that surface
resource-asymmetry concerns escalate to project-level
economic-design review; the per-trait PR design doc records
the finding and the cross-reference, not the analysis.

**Format for per-trait PR design docs.** Each PR 4–7 design
doc includes a "Pattern checklist" subsection (or equivalent;
the placement is per-PR judgment) with the four checks above
applied. The expected output is one of: "no finding for this
pattern" (with one-sentence rationale); "finding pinned at §X
disposition Y" (with cross-reference to where the disposition
lives in the design doc); "finding deferred to Round-N" (with
cross-reference to the §7-equivalent open-question entry).
The discipline is **systematic**: every pattern is checked,
every check produces an output, no pattern is silently
skipped.

#### 2.1.6 Trajectory note — accumulated adversarial intuition as forward-template

Round 1's adversarial pass against the pre-amendment §2.1
surface produced 12 findings clustered into 7 threat patterns.
Round 3's dispositions across commits 3a–3e closed the
findings, but the more durable contribution is **the patterns
themselves**: Patterns 2, 3, 4, 6 are now forward-template
content (§2.1.5) rather than ad-hoc adversarial-pass output.
PR 4–7's pre-flight does not need to rederive them; the
pre-flight applies the checklist and produces dispositions
systematically.

This is what the substrate-quality investment buys at the
trait-extraction layer. The first per-trait PR (PR 1) had no
pattern-shaped pre-flight content; the second per-trait PR
(PR 2) inherited PR 1's commit-9 docs propagation precedent
plus the Phase 0/0b/0c amendment cadence; the third per-trait
PR (PR 3) inherited PR 2's amendment-shape precedent plus the
no-Mock test substrate framing plus the four-pattern Round-3
discipline.

Each per-trait PR's substrate-quality contribution compounds.
By PR 7's pre-flight, the discipline includes:

- The amendment-shape precedent (PR 1).
- The commit-9 docs propagation precedent (PR 2).
- The no-Mock test substrate pattern (PR 2 / PR 3).
- The four-pattern checklist (PR 3, this commit).
- The Trust-class A/B classification (PR 3, §2.1.3).
- The Pattern-7 escalation rule (PR 3, §2.1.4).
- The amendment-block provenance discipline (PR 3, §2.1's
  spec-clarification subsection lifecycle).
- Whatever PR 4 / PR 5 / PR 6 / PR 7's own pre-flight passes
  surface as new pattern-shaped content.

The cost of each per-trait PR's pre-flight investment is
front-loaded; the benefit accrues to every subsequent
per-trait PR. By Stage-4 cutover, the cumulative discipline
shapes whether the actor abstraction can ship cleanly or has
to navigate around inadequately-pre-flighted per-trait
extractions; the Round-3 discipline is part of the cumulative
investment.

**Round-budget implication for PR 4–7.** Per-trait PRs that
inherit the four-pattern checklist as forward-template content
should require **fewer rounds** before implementation than
PR 3 did. PR 3 ran Rounds 1–3 with substantive design-doc
revisions in each; PR 4 / PR 5's pre-flight produces
pattern-shaped findings against the inherited checklist
methodically rather than discovering them adversarially. The
4–6-rounds-before-implementation rule from
[`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
remains the discipline; the rounds are likely to be shorter
because the substrate is more substantial.

This trajectory note is itself the forward-template content:
PR 4–7's design docs cite §2.1.6 as the "what does
substrate-quality investment compound to?" anchor, and PR 4–7's
own trajectory notes record what new substrate the per-trait
PR contributed to the cumulative pile.

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

### 3.1.2 Handle-indirected workflow shape — completing the workflow-shape pivot

Round 3's adversarial pass surfaced a property gap that the
Round-2 workflow-shape pivot did not fully close. §3.1's pivot
established that **cryptographic primitives** never cross the
trait surface — raw shared secrets, HKDF intermediates, and the
hybrid types themselves stay confined to `LocalKeys`'s stack
frame. But the Round-2 `OutputClaim` shape carried
`output_secret_key: Zeroizing<[u8; 32]>` and
`amount_blinding_factor: Zeroizing<[u8; 32]>` as `pub` fields,
which meant the orchestrator's address space held **per-output
derived secrets** across the (potentially months-long) interval
between claim and spend. The "no secrets cross" claim was
**quantitatively true** (high-cardinality intermediates absorbed)
but **qualitatively false** (per-output derived secrets crossed
anyway).

`Zeroizing<...>` is wipe-on-drop, not wipe-on-read: any consumer
that observes the bytes during the value's lifetime can copy
them. Long lifetimes (storage in `transfer_details`, persistence
to disk via wallet encryption layer, sharing across Stage-4
actor channels) multiply the surface area. The Round-2 shape
relied on the orchestrator inheriting a Zeroize discipline that
flowed from the trait method's stack through every downstream
consumer; one break in that chain (a misbehaving log, an
unencrypted persistence path, an over-eager debug print) leaks
the secret.

**Disposition (per Round 3's A1 → α):** the trait-surface
contract ships **handle-indirected**. `try_claim_output`'s impl
inserts the per-output spending material into a workflow-internal
`HandleTable` (Sub-bundle A) and returns an opaque `OutputHandle`
(Sub-bundle B) to the orchestrator. The orchestrator's
`OutputClaim` carries the handle alongside non-secret on-chain
metadata (`key_image`, `amount_atomic_units`); the spending
secrets stay confined to the engine's address space. Spending
later: the orchestrator passes the handle into `sign_transaction`
via `TxToSign.inputs[i].handle`; the impl resolves the handle
internally, signs using the per-output secret, and returns
`TxSignatures` carrying no secret material.

**The structural property the table delivers** is the same
property session tokens deliver vs. session keys: a leaked handle
is meaningless without the engine's internal mapping. Handle-only
disclosure does not compromise the underlying spending secret.
The orchestrator's persistence, debug-print paths, log paths, and
Stage-4 actor-channel boundaries can all carry handles without
inheriting the wipe-on-drop discipline that secret bytes would
impose. The "no secrets cross the trait boundary" claim becomes
**literal**, not quantitative.

**Trajectory cost.** The handle-indirected pivot adds workflow-
internal state to `LocalKeys` (the table is held behind interior
mutability for the `&self` async trait surface). Several emergent
attack vectors and design questions surface that the Round-3
disposition explicitly defers to Round 4:

- **A6 — handle-table memory-pressure attack.** Unbounded growth
  under adversarial scanning load. Eviction discipline (LRU,
  orchestrator-pinning, persistence-aware aging) is Round 4 work.
- **A7 — handle-collision / handle-forgery.** Predictable handle
  IDs invite cross-context misuse. Unforgeability disposition
  (counter vs UUID vs cryptographic random ID) is Round 4 work.
- **Handle persistence across wallet restart.** Three option-space
  candidates (ephemeral + restart-rescan; persisted handle →
  ciphertext mapping; deterministic handle from ciphertext);
  Round-3 lean is "ephemeral + restart-rescan for V3.0 with
  performance optimization deferred to V3.x." Round 4 ratifies.
- **Concurrency-quality / cross-call state correlation.** The
  table's interior mutability shape (sharded `RwLock`, lock-free
  hashmap, fair-queued single-writer) determines side-channel
  observability. Pattern-5 cluster work, Round 4 disposition.

These are pinned in §7. The Round-3 cut-point lands the trait-
surface contract — opaque-handle-bearing — and exposes the table-
internal questions to Round 4's adversarial pass against the
handle model itself. This is the rounds-budget compounding the
discipline anticipates: each round's structural disposition
surfaces new questions that the next round resolves.

**Amendment-block framing (handle-indirection completion).**

> The Round-2 workflow-shape pivot established that primitives
> do not cross the trait surface. Round 3's adversarial pass
> identified a residual: per-output derived secrets
> (`output_secret_key`, `amount_blinding_factor`) crossed the
> boundary as `Zeroizing<...>`-wrapped fields in `OutputClaim`,
> imposing a long-lifetime wipe-discipline on every downstream
> consumer that the trait could not enforce. The post-Round-3
> §2.1 ships a handle-indirected contract: `try_claim_output`
> returns an opaque `OutputHandle` rather than secret bytes;
> `sign_transaction` resolves handles internally; per-output
> secrets stay confined to `LocalKeys`'s workflow-internal
> `HandleTable`. The "no secrets cross the trait boundary"
> property becomes literal. The trait surface's signatures
> change (`OutputClaim`'s field set; `TxInputSigningContext`'s
> handle reference); the underlying capability is unchanged.

#### Continuity-of-discipline framing

The handle-indirected workflow shape isn't novel discipline — it
applies a discipline already operative elsewhere in the codebase to
wallet-side state. `rust/shekyl-oxide/` is the artifact of Shekyl's
discipline applied to upstream proof-system code: legacy proofs
removed; FCMP++ and PQC primitives added; `#![deny(unsafe_code)]`
across the vendored crates; `RELEASE-BLOCKER` items tracked per
`SHEKYL_READINESS.md`. Wallet-side state was not vendored; it was
ported from C++ `wallet2.h::struct transfer_details` directly into
`shekyl-core`'s Rust without the same discipline pass. The
secret-bearing fields on `TransferDetails`
(`combined_shared_secret`, `ho`, `y`, `z`, `k_amount`) are the
residue of that direct port.

The architectural-inheritance disposition
(`16-architectural-inheritance.mdc` §"The inherited-architecture
rule") asks: where inherited architecture contradicts a Shekyl-
specific commitment (here, `36-secret-locality.mdc`'s "engine owns
secrets"), migrate. The handle-indirected workflow shape is that
migration. The discipline being applied is the same discipline
already operative in the vendored proof-system surfaces, applied
retroactively to the part of the codebase where it hadn't been
applied yet.

This framing matters because it clarifies what the migration is
*not*: it is not a novel security investment; it is not a
speculative engineering project; it is not adding discipline that
the rest of the codebase doesn't already operate under. It is
continuity-of-discipline. Forward, per-trait PRs 4–7 should expect
similar continuity-of-discipline opportunities wherever wallet-side
state ported from C++ benefits from the discipline already operative
in vendored proof-system surfaces.

### 3.1.3 Per-subaddress `kem_pk` derivation is rule-forced, not stylistic

Round 3's adversarial pass (A2) probed whether `RecipientSubaddress`
must carry a per-subaddress `kem_pk: HybridKemPublicKey` for
V3.0, or whether the trait could ship without per-subaddress ML-KEM
material at the V3.0 cut-point and accrete it as a V3.x
extension. The Round-3 disposition is **per-subaddress `kem_pk`
in V3.0**, dispositioned **β** in the A2 option-space. The
disposition is **rule-forced by `00-mission.mdc`'s priority
hierarchy**, not stylistic — α (drop per-subaddress `kem_pk` for
V3.0) decomposes into three sub-options each violating a
priority-hierarchy rule.

**The α decomposition.** Where would the sender obtain the
ML-KEM public key to encapsulate against, if `RecipientSubaddress`
did not carry one?

- **(P1) X25519-only encryption.** Drop ML-KEM encapsulation
  entirely and encrypt outputs against the X25519 component
  alone. **Violates `00-mission.mdc` priority 1** (security and
  quantum resilience are preconditions). No PQC in the
  encryption path means no quantum resilience for received
  outputs. The hybrid-by-default rule
  ([`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc))
  is itself an instance of priority 1 at the rule level.
  Rejected unconditionally.
- **(P2) Wallet-level ML-KEM PK in the encoded subaddress.**
  Each subaddress encoding embeds the wallet-level (root) ML-KEM
  PK in addition to the per-subaddress X25519 component. Senders
  encapsulate against the wallet-level ML-KEM PK; the receiver
  decapsulates with the wallet-level ML-KEM SK and routes the
  result via the per-subaddress X25519 derivation. **Violates
  priority 2** (privacy is the product; never weaken privacy to
  add a feature of any kind other than security): two
  subaddress encodings from the same wallet share their
  ML-KEM PK component byte-for-byte; an observer who has two
  subaddress encodings can compare them directly and learn
  "same wallet" without observing any on-chain activity. This
  is direct subaddress-encoding linkability — not a
  ciphertext-correlation degradation, not an
  observation-window-bound privacy leak, but a literal byte
  comparison that any party in possession of two encodings
  performs trivially. Subaddress unlinkability is the
  privacy-class property the receiver designs around;
  collapsing it for a deferral convenience is rejected.
- **(P3) Out-of-band ML-KEM PK delivery.** The encoded
  subaddress carries only the X25519 component and a wallet
  identifier; the sender obtains the ML-KEM PK out-of-band
  (lookup service, pinned-key directory, manual exchange).
  **Breaks the self-contained-address UX**: payment URIs / QR
  codes are no longer fully addressable; the sender cannot
  send without an additional resolution step; the wallet-pair
  introduces a coordination dependency that the entire
  subaddress design specifically eliminates. Not viable for
  V3.0; not viable in V3.x either, because re-introducing
  out-of-band coordination contradicts the privacy property
  the self-contained-address provides (third-party PK
  resolvers observe sender intent before the transaction
  exists).

There is no fourth option. α decomposes into (P1) ∨ (P2) ∨ (P3),
and each sub-option violates a priority-hierarchy rule. **β is
the only admissible disposition**: per-subaddress `kem_pk`
derives deterministically from view secret + index, lives in
`RecipientSubaddress` as a precomputed value the sender
extracts, and is regenerated by the recipient on demand from
the same inputs.

**Disposition (β specification).** `RecipientSubaddress.kem_pk`
is a `HybridKemPublicKey` carrying both the X25519 and ML-KEM-768
public-key components per-subaddress index:

- **X25519 component.** Derives per-index from the view secret
  per the existing classical-Monero subaddress derivation
  machinery (the same path that produces the classical
  spend / view subaddress key pair). No new primitive needed;
  the derivation is already in the workspace.
- **ML-KEM-768 component.** Derives via deterministic ML-KEM-768
  keygen, where the keygen RNG is replaced by an HKDF-derived
  byte stream:

  ```text
  rng_bytes = HKDF-Expand(
      prk = HKDF-Extract(
          salt = "", // salt-less; HKDF-Extract reduces to a
                     // single PRF call against view_secret
          ikm  = view_secret_bytes,
      ),
      info = "shekyl/subaddr-mlkem-keygen-v1"
              || subaddress_index_le_bytes,
      L    = ML_KEM_768_KEYGEN_RNG_BYTES,
  )
  (mlkem_pk_i, mlkem_sk_i) = ML-KEM-768.KeyGen(rng_bytes)
  ```

  The HKDF context string `"shekyl/subaddr-mlkem-keygen-v1"`
  domain-separates the kem-keygen path from any other HKDF
  consumer of the view secret (per
  [`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc)'s
  domain-separator rule). The `-v1` suffix reserves a versioning
  axis if a future hard fork ever needs to migrate the
  derivation while preserving wallet-level continuity.
  `subaddress_index_le_bytes` is the canonical encoding the rest
  of the subaddress derivation uses, so two subaddress consumers
  on the same view secret + index always produce the same
  keypair.

**Sender-vs-recipient asymmetry.**

- **Sender side**: zero per-encapsulation cost — `kem_pk` is a
  precomputed field of `RecipientSubaddress`; the sender extracts
  it and feeds it into the existing `HybridX25519MlKem::encapsulate`
  path. The HKDF + ML-KEM-keygen work happens once at
  subaddress-creation / address-display time on the recipient's
  side.
- **Recipient side**: ~50 µs per derivation (dominated by
  ML-KEM-768 KeyGen, not HKDF; HKDF is a small constant). Called
  rarely — once per subaddress index, cacheable in a
  subaddress-derivation cache if the same index is hit
  repeatedly during a scan window. Across a wallet's full
  subaddress space, the cost is bounded by the number of
  subaddress indices the wallet has actually created, not the
  total scan workload.
- **Encoding overhead**: ~1216 bytes per encoded address (the
  ML-KEM-768 PK is 1184 bytes plus a small framing overhead).
  Relative to the existing classical-encoding bloat of
  hybrid-typed addresses, the additive cost is small; the
  encoding's self-contained-address property is preserved.

**Rationale framing (recorded for the V3.x-churn audit anchor).**
β is explicitly **rule-forced**, not "the best stylistic option
considered." Future readers tracing "why does V3.0 ship
per-subaddress ML-KEM derivation rather than wallet-level?" find
the priority-hierarchy decomposition above as the binding
argument. If a future hard fork reaches a state where one of
(P1) / (P2) / (P3) is admissible (e.g., a future ciphertext-
correlation-resistant ML-KEM variant that defangs the (P2)
linkability concern, or a fully-PQC encryption primitive that
defangs (P1)'s classical-only failure), the disposition can be
re-opened — but only against a concrete change to the
priority-hierarchy-rule landscape, not as a stylistic
re-litigation. The `-v1` suffix in the HKDF context string is
the versioning anchor for any such future migration.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection alongside §3.1's
hybrid-framework reconciliation prose and §3.1.2's handle-
indirection completion prose).**

> The Round-3 commit 3b lands the per-subaddress `kem_pk`
> derivation specification: `RecipientSubaddress.kem_pk` is a
> `HybridKemPublicKey` whose X25519 component derives per-index
> via classical-Monero subaddress derivation and whose
> ML-KEM-768 component derives via deterministic ML-KEM-768
> keygen seeded by `HKDF-Expand(view_secret, "shekyl/
> subaddr-mlkem-keygen-v1" || subaddress_index_le_bytes)`. The
> disposition is rule-forced by `00-mission.mdc`'s priority
> hierarchy: dropping per-subaddress `kem_pk` would either
> break the PQC commitment (P1, violating priority 1) or break
> subaddress unlinkability (P2, violating priority 2) or break
> the self-contained-address UX (P3, not viable). β is the only
> admissible disposition; the recipient regenerates per-subaddress
> ML-KEM keypairs on demand from view secret + index; senders
> extract precomputed `kem_pk` from `RecipientSubaddress`.

### 3.1.4 Pattern-2 spec-silent junctions cluster

Round 3's adversarial pass surfaced four findings that share a
structural shape: **load-bearing cryptographic junctions whose
specification lives in implementation lore rather than at the
spec level**. Each finding names a junction the implementation
already handles correctly today but whose spec-level pin is
missing or ambiguous. The cluster's threat-pattern shape:

> **Pattern 2 — Spec-silent load-bearing junctions.** When a
> trait's contract describes _what_ the impl produces but not
> _how_ the impl binds context into the production, an
> adversary's probe target shifts from "find a primitive that
> leaks" to "find a junction the spec doesn't pin and nudge the
> impl into binding the wrong context." Future maintainers
> rebuilding the impl from the spec alone may rebuild the
> binding differently than the original; cross-version
> verifiers reading the spec alone may accept an output the
> original would reject.

The four findings landed by commit 3c:

- **A3 — per-output HKDF context binding.** The spec names
  `try_claim_output` as performing "HKDF chain" but does not
  pin which HKDF labels, salts, and per-output index-binding
  bytes the chain uses. Disposition: pin the canonical
  derivation reference (`shekyl-crypto-pq::derivation`'s
  `derive_output_secrets` and `derive_view_tag_x25519` salt
  / label registry) at the spec level; explain the per-output
  uniqueness argument (uniqueness comes from `combined_ss`
  being per-output-unique, not from an explicit
  transaction-context hash; the wargaming pass's
  "tx_context_hash" framing was overspecified — the actual
  binding is via unique-per-output `combined_ss`).
- **A4 — `VIEW_TAG_BYTES` width.** The spec names a
  `ViewTag(pub(crate) [u8; VIEW_TAG_BYTES])` newtype but does
  not pin the constant's value. Disposition: pin
  `VIEW_TAG_BYTES = 1` (matching the existing `u8` shape in
  `shekyl-crypto-pq::derivation::derive_view_tag_x25519`'s
  return type and `shekyl-scanner::shared_key::SharedKey::view_tag`'s
  field); the 1-byte width is consistent with classical Monero's
  view-tag width and bounds the false-positive rate the
  pre-filter trades for the pre-filter's cheap-path benefit.
- **A5 → ζ — Method-to-domain binding via marker trait.**
  Cross-domain signature reuse prevention via per-domain HKDF
  chains (the impl's `SignDomain` enumeration) is currently
  enforced by convention — each call site asserts the domain
  it's signing in, and a future maintainer copying a
  `sign_transaction` body to add `sign_governance_proposal`
  could reuse the same domain by accident. Disposition: ζ
  (marker trait + associated const). A `SignsInDomain` trait
  with an associated `const DOMAIN: SignDomain` plus per-domain
  unit-struct markers (`SignTransactionDomain`,
  `OutputSecretDerivationDomain`, etc.) bound to the
  `derive_signing_key<D: SignsInDomain>` primitive. Reusing a
  domain becomes a deliberate inspection-visible action;
  introducing a new domain requires deliberately introducing a
  new marker. Compile-time enforcement of a load-bearing
  security property at minimal cost.
- **D1 — `sign_transaction` validation contract.** The
  `sign_transaction` doc-comment names the workflow but does
  not specify which validations are the impl's responsibility
  versus the orchestrator's. Disposition: pin the validation
  boundary explicitly. The impl validates: handle resolution
  succeeds; per-input signature can be produced (per-output
  secret recoverable); FCMP++ witness can be produced. The
  impl does **not** validate amount accounting (orchestrator's
  responsibility, established at `TxToSign` construction time),
  fee calculation (orchestrator), or recipient-address validity
  (already validated at `TxToSign` construction). The
  validation boundary defines which `KeyEngineError` variants
  surface from `sign_transaction` versus which conditions are
  caller-side preconditions. See §4 for the doc-comment
  amendment.

**Pattern-2 generalization for PR 4–7.** Per-trait PRs land
spec-silent junctions whenever the trait's contract describes
_capability_ ("produce a signature") without pinning _binding_
("what context binds into the signature challenge?"). PR 4–7
authors should run a spec-silent-junction sweep at pre-flight:

1. Read the trait's doc-comments. List every load-bearing
   cryptographic operation named.
2. For each, ask: "if a future maintainer rebuilt this from the
   spec alone, would they bind the same context into the
   primitive?" If no, the junction is spec-silent and worth
   pinning.
3. For each, ask: "if a cross-version verifier consumed the
   spec alone, would they reject outputs the impl rejects?"
   If no, the junction is spec-silent.
4. Pin junctions at the per-trait PR design-doc stage; do not
   defer to implementation.

The four landings above are an instance of this checklist
applied retrospectively. PR 4–7's pre-flight should produce the
checklist eagerly rather than waiting for adversarial review to
surface findings.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection).**

> The Round-3 commit 3c lands four spec-silent junction
> dispositions: A3 — per-output HKDF derivation pinned to the
> canonical `shekyl-crypto-pq::derivation` reference; A4 —
> `VIEW_TAG_BYTES = 1` pinned at the spec level; A5 → ζ —
> method-to-domain binding via `SignsInDomain` marker trait +
> associated const for compile-time cross-domain-reuse
> prevention; D1 — `sign_transaction` validation contract
> pinned with the impl-side / orchestrator-side validation
> boundary explicit. None of these change the trait's
> capability surface; all close junctions whose specification
> currently lives in implementation lore rather than at the
> spec level. The Pattern-2 generalization checklist (above)
> is the contribution PR 3 makes to PR 4–7's pre-flight
> discipline.

### 3.1.5 Pattern-3 (test substrate) + Pattern-4 (visibility) cluster

Round 3's adversarial pass surfaced three findings that share a
structural shape: **trait-surface and impl-internal disciplines
that the type system cannot enforce alone, and that the spec
must pin so future maintainers and reviewers share the same
mental model**. The cluster spans two threat-pattern axes:

> **Pattern 3 — Test substrate visibility leakage.** Test-only
> constructors and inspection accessors that exist on
> production types must be structurally inaccessible from
> production code paths. A test-only constructor that compiles
> in production (because the gate is convention rather than
> structure) is a class of finding the type system can prevent
> by construction; the cost is a small discipline on every
> test-only addition.
>
> **Pattern 4 — External-implementor trust model and visibility
> discipline.** The trait surface defines what implementors must
> publicly support; it does not define implementor-internal
> discipline (per the §3.1.2 / §4 "deliberately does not
> expose" bullet 5 honesty). Where the spec's visibility
> decisions cannot be enforced by the type system alone (for
> example, a `pub` struct that should not be constructed
> outside the crate), the spec must pin the rationale so
> reviewers see the discipline rather than infer it from
> grep-output.

The three findings landed by commit 3d:

- **B1 — Three-layer discipline for test-only constructors and
  inspection accessors.** Layer 1 — `#[cfg(test)]` gating
  ensures the symbol does not exist in non-test compilation.
  Layer 2 — `pub(crate)` (or tighter) visibility ensures even
  in test compilation the symbol is reachable only from the
  same crate's test code, not from downstream test crates that
  depend on the production surface. Layer 3 — a CI gate (a
  small `xtask` or shell-grep step in the existing CI workflow)
  asserts the symbol does not appear in non-`cfg(test)`
  reachable code; this is the residual defense against a
  future maintainer accidentally widening the gate. The three
  layers are independent: if one fails, the next catches; if
  two fail, the third catches. The discipline applies to
  `LocalKeys::from_test_seed`, `LocalKeys::handle_table_size`
  (introduced for B2 / §6.4), and any future test-only
  constructor or accessor that lands on a production type.
- **B2 — Handle-storage hygiene replaces lifetime-of-secret-
  material framing.** The pre-Round-3 framing said tests verify
  wipe-on-drop of secret bytes that crossed the trait boundary
  (e.g., `OutputClaim`'s `output_secret_key`). After A1's
  handle-indirection pivot, no secrets cross the boundary;
  there is nothing for the orchestrator's wipe discipline to
  protect. The test discipline shifts: instead of verifying
  secret-material wipe-on-drop at the boundary, tests verify
  **handle-storage hygiene** — orphan absence (no entry
  present without a successful claim), entry deletion on
  consumption (a successful `sign_transaction` removes the
  consumed handle's entry), bounded growth (repeated
  `try_claim_output` calls don't accumulate stale entries).
  The hygiene properties are the post-A1 analog of the
  wipe-on-drop properties; both target the question "does the
  engine retain state it shouldn't?" but the answer relocates
  from boundary-crossing types to the workflow-internal
  `HandleTable`.
- **Attack 4.2 — Message-type visibility discipline.** Each
  Sub-bundle B message type's visibility (`pub`, `pub(crate)`,
  `pub(super)`, plus per-field visibility) is a deliberate
  decision with rationale. The Round-3 finding: pin each
  decision and its rationale at the spec level, so reviewers
  reading the visibility table see the discipline rather than
  needing to reconstruct it from the production code. All
  Sub-bundle B types are **Trust-class B** (handle public
  state only — the handle itself is opaque, but the surrounding
  message types carry public on-chain metadata, addresses, or
  references); no message type is Trust-class A (handles
  long-term secret material directly). The visibility table
  lands in §3.3 Sub-bundle B's new "Visibility discipline"
  subsection.

**Pattern-3 generalization for PR 4–7.** Per-trait PRs land
test-only constructors and inspection accessors whenever a
production type needs deterministic test fixtures or
correctness-property verification beyond what the trait surface
exposes. The three-layer discipline is the forward-template
content PR 4–7 inherit:

1. Identify every test-only addition to a production type.
2. Apply Layer 1 (`#[cfg(test)]`), Layer 2 (`pub(crate)`),
   Layer 3 (CI gate).
3. Document the addition in the per-trait PR's design doc with
   the rationale for needing a test-only addition rather than
   refactoring to expose the property at the trait surface.
4. The default answer when in doubt is "this should be
   trait-surface-observable, not test-only-observable"; the
   test-only addition is a fallback when trait-surface
   observability would weaken the trait's contract.

**Pattern-4 generalization for PR 4–7.** Per-trait PRs cross a
crate boundary (the trait is `pub(crate)` until V3.2 promotion
per §3.4, and the message types are `pub` because they
participate in the actor abstraction at Stage 4). Each
visibility decision has rationale; the per-trait PR design doc
lists the message types with `pub` / `pub(crate)` / `pub(super)`
visibilities and per-field visibilities, with explicit rationale
for each. The default visibility is the **tightest** that
satisfies the trait's contract; widening to `pub` requires
naming the consumer that needs the wider visibility.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection).**

> The Round-3 commit 3d lands three Pattern-3 / Pattern-4
> dispositions: B1 — three-layer discipline (`#[cfg(test)]` +
> `pub(crate)` + CI gate) for test-only constructors and
> inspection accessors; B2 — handle-storage hygiene replacing
> lifetime-of-secret-material framing post-A1; Attack 4.2 —
> per-message-type visibility table with explicit rationale
> for Sub-bundle B types. §6.4's orphan-absence verification
> mechanism (deferred from the 3a review pass) is pinned to
> option (i) — the `handle_table_size` test-inspection
> accessor under the three-layer discipline — closing the
> Round-4 prerequisite for the post-A1 hygiene tests. The
> Pattern-3 and Pattern-4 generalization checklists (above)
> are the contributions PR 3 makes to PR 4–7's pre-flight
> discipline.

### 3.1.6 Pattern-6 (replay/idempotency) cluster

Round 3's adversarial pass surfaced a pattern that the
pre-Round-3 spec did not pin: **for each trait method, what is
the contract under repeated invocation with the same input?**
The contract has structural consequences for the orchestrator
(retry behavior on transient failure; deduplication of
in-flight requests at higher layers; persistence-layer
interactions if the method's effects must be journaled), and a
future maintainer rebuilding the impl from the spec alone may
rebuild the contract differently than the original.

> **Pattern 6 — Replay / idempotency contract.** A trait
> method's behavior on repeated invocation with the same input
> is part of the trait's contract; spec-silent on this axis
> means the behavior is implementation-defined and may drift
> across impls or across time. The contract dimensions to pin
> are: (i) does the method have observable side effects that
> persist across calls? (ii) is repeated invocation safe
> (idempotent), error-producing (replay-rejecting), or
> undefined? (iii) does the orchestrator's retry pattern
> interact with the method's failure modes (e.g., a successful
> operation that returns a network error before the response
> arrives)? Workflow-shape methods like `try_claim_output` and
> `sign_transaction` have different replay contracts than each
> other; the difference must be pinned at the spec.

**KeyEngine method-by-method dispositions.**

| Method | Idempotency contract | Side-effect contract | Retry safety |
|---|---|---|---|
| `account_public_address` | Pure read; idempotent by construction. | None. | Trivially safe to retry. |
| `derive_subaddress` | Pure derivation; idempotent — same `(SubaddressIndex, SubaddressPurpose)` returns the same `SubaddressFor`. | None — no `HandleTable` mutation; no persistent state change. | Trivially safe to retry. The ML-KEM-768 KeyGen step (per §3.1.3 / §3.3 Sub-bundle A `derive_subaddress_kem_keypair`) is deterministic; the cost (~50 µs / call) makes orchestrator-level caching attractive but does not change the contract. |
| `try_claim_output` | **Idempotent at the workflow level.** Calling `try_claim_output(input)` twice with the same `OutputDetectionInput` returns equivalent `OutputClaimResult`s; the second call observes the existing handle-table entry and returns the same `OutputHandle` (or returns `NotMine` deterministically). The exact insertion-policy question — "subsequent calls are pure no-ops" vs. "subsequent calls return the existing handle" — is pinned at impl time and tested per §6.7's bounded-growth property. | Inserts a new entry into `HandleTable` on first successful detection; subsequent calls observe the existing entry without modifying it. | Safe to retry on transient errors; the orchestrator can replay an interrupted scan against the same block range without producing duplicate handles. Exception: a `KeyEngineError` returned by a partial-failure path should not leave an orphan entry per §6.7's orphan-absence property. |
| `sign_transaction` | **Handle-consuming, not idempotent.** A successful `sign_transaction` removes consumed handles from the `HandleTable` (per §6.7's entry-deletion property). A second call against the same `TxToSign` fails with a handle-resolution error because the consumed handles are no longer present. **This is deliberate replay rejection at the trait surface:** double-spend prevention is a structural property of the method, not a discipline imposed at a higher layer. | Removes consumed handles from `HandleTable`; produces signature material that is subsequently broadcast as part of the signed transaction. | Retry semantics are caller-driven: the orchestrator must distinguish "transaction broadcast succeeded but acknowledgment lost" (no retry — the consumed handles are gone; rebuilding the transaction with replacement inputs is necessary) from "signing failed before any persistent state change" (retry against the original `TxToSign` with the original handles is admissible). The `KeyEngineError` taxonomy (§3.2 / §7.2) surfaces variants whose distinction supports this caller-driven discrimination. |

**Cross-cutting: `FaultInjecting<LocalKeys>` and replay.** The
fault-injection wrapper preserves the underlying impl's
idempotency contract — a fault injected before the impl runs
leaves no handle-table state change; a fault injected after the
impl runs but before the wrapper returns the result leaves the
impl's state change in place (orphan entry). The orphan-absence
test (§6.4) exercises the second case under `try_claim_output`;
the wrapper's contract for `sign_transaction` faults requires
either pinning the fault-injection point relative to the impl's
table-mutation (so the test can distinguish "fault before
mutation" from "fault after mutation") or accepting that some
fault-injected scenarios produce orphaned consumed-handle state
that the orchestrator must reconcile. The exact wrapper contract
is pinned at PR 3 implementation time.

**Pattern-5 cross-reference.** Pattern 5 (cross-call state
correlation as side-channel) and Pattern 6 (replay/idempotency)
are structurally adjacent — both concern the trait method's
behavior across multiple invocations — but address different
adversary models. Pattern 5 addresses **timing-channel
observability** of state changes; Pattern 6 addresses
**functional-contract** behavior under repeated invocation.
KeyEngine's Pattern-5 disposition is Round-4-deferred (§7.13);
Pattern-6 dispositions land in this commit (3e). Per-trait PRs
that surface concurrent-access sensitivity should pin both
patterns; per-trait PRs whose methods are stateless can dispose
of Pattern 6 trivially and defer Pattern 5 if no concurrent-
access shape is on the trait surface.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection).**

> The Round-3 commit 3e lands the Pattern-6 replay/idempotency
> dispositions for KeyEngine's four trait methods, plus the
> forward-template content (§2.1.3 Trust-class A/B
> classification; §2.1.4 Pattern-7 economic-incentive
> cross-reference rule; §2.1.5 four-pattern checklist for PR
> 4–7 pre-flight; §2.1.6 trajectory meta-note on accumulated
> adversarial intuition). The per-method contract table is the
> format PR 4–7 inherit for their own pre-flight discipline.
> Pattern 5 (cross-call state) is acknowledged as adjacent but
> distinct; KeyEngine's specific Pattern-5 disposition stays in
> §7.13 as Round-4 work.

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
| `HandleTable` | `pub(crate) struct HandleTable { /* concurrent-access shape pinned in Round 4 */ }` | Workflow-internal state owned by `LocalKeys`. Maps `OutputHandle` → per-output secret material (`output_secret_key`, `amount_blinding_factor`) for outputs the wallet has claimed but not yet spent. Lives behind interior mutability (the `KeyEngine` trait is `&self` async; concurrent `try_claim_output` calls insert; `sign_transaction` looks up). The exact concurrent-access shape (sharded `RwLock`, lock-free hashmap, fair-queued single-writer, etc.) is **Round 4 work**; the shape selection couples to A6 (memory-pressure attack surface) and the Round-3 Pattern-5 cluster (cross-call state correlation as side-channel). The trait surface is unchanged regardless of inner shape. |
| `SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT` | `pub(crate) const SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT: &[u8] = b"shekyl/subaddr-mlkem-keygen-v1";` | HKDF-Expand info-string prefix for the per-subaddress ML-KEM-768 keygen path (per §3.1.3). The `-v1` suffix is the versioning axis: a future hard fork that migrates the derivation (e.g., V4 lattice-only swap from ML-KEM-768 to a successor primitive) bumps the suffix and lives alongside the v1 path until the migration completes. The constant is `pub(crate)` because it's consumed inside `derive_subaddress`'s impl (and the symmetric recipient-side spend path that resolves an output against the same per-index ML-KEM secret); no trait-surface caller observes it. Consumed in conjunction with `subaddress_index_le_bytes` to form the full HKDF info string per the §3.1.3 byte-layout. |
| `derive_subaddress_kem_keypair` (workflow-internal primitive) | `pub(crate) fn derive_subaddress_kem_keypair(view_secret: &ViewSecret, idx: SubaddressIndex) -> (HybridKemPublicKey, ZeroizingMlKemSecretKey)` (or signature pinned at impl time) | Deterministic per-subaddress ML-KEM-768 keypair derivation per §3.1.3. Workflow-internal; lives in `shekyl-crypto-pq` (or, if cleaner, in a `LocalKeys`-private module that re-exports the underlying ML-KEM-768 KeyGen against an HKDF-seeded byte stream). Consumed by `derive_subaddress(_, SubaddressPurpose::Recipient)` to populate `RecipientSubaddress.kem_pk` (returning the public component) and by `try_claim_output`'s impl to recover the per-subaddress ML-KEM SK during hybrid decap (re-deriving the keypair from view secret + the candidate index). The `ZeroizingMlKemSecretKey` return wrap (or equivalent) is per `35-secure-memory.mdc`'s structural-memwipe rule for SK material. The exact return-tuple shape, name, and module location are pinned at PR 3 implementation time; the §3.1.3 spec pins the inputs, the byte-layout of the HKDF info string, and the output-keypair determinism. |
| `VIEW_TAG_BYTES` (A4 disposition) | `pub(crate) const VIEW_TAG_BYTES: usize = 1;` | Width of the on-wire view tag (`ViewTag(pub(crate) [u8; VIEW_TAG_BYTES])` per §3.3 Sub-bundle B). Pinned at `1` to match `shekyl-crypto-pq::derivation::derive_view_tag_x25519`'s `u8` return type and `shekyl-scanner::shared_key::SharedKey::view_tag`'s field shape. The 1-byte width is consistent with classical Monero's view-tag width; it bounds the false-positive rate of the X25519-only pre-filter to 2⁻⁸ per output, which is the chosen trade-off between filter selectivity and on-wire bloat. The constant is `pub(crate)` because it's consumed inside `try_claim_output`'s pre-filter machinery; no trait-surface caller observes it directly (the `ViewTag` newtype hides the width). Pinning the value at the spec level closes the A4 spec-silent junction (Round 3 §3.1.4 finding) so cross-version verifiers and future maintainers reading the spec alone share the same width as the impl. The `-v1` framing for view-tag derivation lives at the salt level (`HKDF_SALT_VIEW_TAG_X25519 = b"shekyl-view-tag-x25519-v1"`), not at the constant; a future migration that widens the tag would bump the salt suffix and the `VIEW_TAG_BYTES` value together as a coupled spec amendment. |
| `OUTPUT_DERIVE_HKDF_REGISTRY` (A3 reference, not a Rust item) | The canonical HKDF salt + label registry living in `shekyl-crypto-pq::derivation`: `HKDF_SALT_OUTPUT_DERIVE = b"shekyl-output-derive-v1"`, `HKDF_SALT_VIEW_TAG_X25519 = b"shekyl-view-tag-x25519-v1"`, `SALT_KEM_DERIVE_V1 = b"shekyl-output-kem-v1"`; per-secret labels `shekyl-output-x`, `shekyl-output-y`, `shekyl-output-mask`, `shekyl-output-amount-key`, `shekyl-output-view-tag-combined`, `shekyl-output-amount-tag`, `shekyl-pqc-output`, `shekyl-pqc-ed25519`, `shekyl-view-tag-x25519`. | Per-output HKDF chain that `try_claim_output`'s impl uses to derive output-spending secrets, view-tag-combined cross-check, amount key, ML-DSA seed, and Ed25519-PQC seed. The spec's pre-Round-3 framing said "HKDF chain" without pinning the binding; A3's disposition (Round 3 §3.1.4) is to **reference the canonical registry** rather than restate it here. The single source of truth is `shekyl-crypto-pq::derivation` (alongside `tools/reference/derive_output_secrets.py` and the locked `docs/test_vectors/PQC_OUTPUT_SECRETS.json`); `KeyEngine`'s impl consumes those constants directly. **Per-output uniqueness argument:** the wargaming pass framed the concern as "cross-output replay needs explicit `tx_context_hash` binding"; this was overspecified. The actual binding is via `combined_ss = X25519(eph_sk, view_pk) ‖ ML-KEM-Decap(kem_sk, ct)` which is per-output-unique by construction (each output has a unique X25519 ephemeral and unique ML-KEM ciphertext). The `output_index_le64` byte-suffix on every label provides intra-tx separation; the per-output `combined_ss` provides cross-tx and cross-output separation. No `tx_context_hash` is required; the registry's existing salt + label + index-suffix layout already binds the full context. **Future-proofing:** a future hard fork that bundles a tx-level context (e.g., binding the FCMP++ root hash into the per-output derivation) would be a coupled `-v2` salt + label migration (the `-v1` suffixes are the versioning axis) and lives alongside the v1 path until the migration completes. The trait surface absorbs the migration through the impl; the trait's contract is unchanged. |
| `SignsInDomain` (A5 → ζ) | `pub(crate) trait SignsInDomain { const DOMAIN: SignDomain; }` | Marker trait pinning the cryptographic domain a workflow-internal signing operation operates in. Implemented by per-domain unit-struct markers (`SignTransactionDomain`, `OutputSecretDerivationDomain`, `FcmpPlusPlusWitnessDomain`, `MlKemChallengeDomain`); each marker's `impl SignsInDomain` sets `const DOMAIN` to the matching `SignDomain` variant. Consumed by the workflow-internal `derive_signing_key<D: SignsInDomain>` primitive (and by future per-domain HKDF-context-derivation sites) — the type parameter forces the call site to name the domain, and the impl's HKDF context derivation reads `D::DOMAIN` to drive per-domain salt selection. Cross-domain reuse becomes a deliberate inspection-visible action: a future maintainer copying `sign_transaction`'s body to add `sign_governance_proposal` must change the type parameter to a new marker (introducing `SignGovernanceDomain` against the existing `SignDomain` enum), or reuse `SignTransactionDomain` against a non-transaction-signing call (an inspection-visible mismatch a reviewer flags). Compile-time enforcement of a load-bearing security property at minimal cost (~10–15 LOC for the trait + four markers); the discipline transfers from convention (every call site asserts) to type system (rustc enforces). The trait + markers are `pub(crate)` because no trait-surface caller observes them; they live entirely behind `LocalKeys`'s impl boundary. The `#[non_exhaustive]` on `SignDomain` (existing) keeps the enum extensible; new domains added per Q9.2's additive-amendment discipline land alongside their per-domain marker structs. |
| `SignTransactionDomain` / `OutputSecretDerivationDomain` / `FcmpPlusPlusWitnessDomain` / `MlKemChallengeDomain` (A5 → ζ markers) | `pub(crate) struct SignTransactionDomain;` (and three siblings) with `impl SignsInDomain for SignTransactionDomain { const DOMAIN: SignDomain = SignDomain::TransactionSignature; }` (and three siblings, each binding to its matching `SignDomain` variant) | The four per-domain markers, one per `SignDomain` variant. Unit structs with no runtime cost; the `const DOMAIN` is monomorphized at compile time. Each call site that consumes `derive_signing_key<D: SignsInDomain>(...)` instantiates with the appropriate marker, naming the domain at the call site rather than passing it as a runtime argument. Stage 4's multisig variants (multisig witness, partial signature, etc.) add new `SignDomain` variants and corresponding new markers additively, per Q9.2's `#[non_exhaustive]` disposition. PR 4–7 trait extractions that introduce new signing workflows (e.g., a `PendingTxEngine`-internal partial-signature path) follow the same pattern: a new `SignDomain` variant, a new marker, the new workflow's impl uses the marker. |
| `derive_signing_key` (workflow-internal primitive) | `pub(crate) fn derive_signing_key<D: SignsInDomain>(keys: &AllKeysBlob, msg_context: &[u8], /* additional inputs pinned at impl time */) -> SigningKeyMaterial` (signature pinned at impl time) | Generic over `D: SignsInDomain`. Reads `D::DOMAIN` to select the per-domain HKDF salt (or label, or context byte-string — the exact mapping is pinned at impl time per the existing per-domain HKDF-context discipline). Returns the signing material (or signature output, depending on whether the primitive splits into "derive key" + "sign with key" or fuses them — pinned at impl time). The **load-bearing property** is that the type parameter `D` is the **only** way to select a domain: there is no runtime `domain: SignDomain` argument; there is no default; there is no fallback. A call site must name the marker; the marker pins the domain. Future maintainers extending the primitive's signature add additional inputs (e.g., the FCMP++ witness root hash); the domain-selection axis is fixed by the type parameter and cannot drift. |

#### Why a workflow-internal handle table — the handle-indirected workflow shape

The Round-2 workflow-shape pivot (§3.1) established that **primitives** never cross the trait surface — raw shared secrets, HKDF intermediates, and the hybrid types themselves stay confined to `LocalKeys`'s stack frame. Round 3's adversarial pass surfaced that **derived secrets** still crossed: the original Round-2 `OutputClaim` shape carried `output_secret_key: Zeroizing<[u8; 32]>` and `amount_blinding_factor: Zeroizing<[u8; 32]>` as `pub` fields, which meant the orchestrator's address space held per-output spending secrets across the (potentially months-long) interval between claim and spend. The "secret intermediates never cross" claim was quantitatively true (high-cardinality intermediates absorbed) but qualitatively false (per-output derived secrets crossed anyway).

The handle-indirected disposition completes the workflow-shape pivot's promise. `try_claim_output`'s impl inserts the per-output secret material into the workflow-internal `HandleTable` and returns an opaque `OutputHandle` to the orchestrator. The orchestrator's `OutputClaim` carries the handle alongside non-secret metadata (`key_image`, `amount_atomic_units`); the orchestrator never observes the secrets themselves. Spending later: the orchestrator passes the handle into `sign_transaction` via `TxToSign`'s inputs; the impl resolves the handle internally, signs using the per-output secret, and returns `TxSignatures` carrying no secret material. End-to-end, **no secret crosses the trait boundary** — neither intermediates nor derived secrets.

The structural property the table delivers: a leaked `OutputHandle` is meaningless without `LocalKeys`'s table (the same property session tokens deliver vs. session keys). Handle-only disclosure does not compromise the underlying spending secret. The orchestrator's persistence layer, debug-print paths, and Stage-4 actor-channel boundaries can all carry handles without inheriting the wipe-on-drop discipline that secret bytes would impose.

The cost is internal-to-`KeyEngine` complexity: a handle table to manage, a concurrent-access shape to choose, a lifecycle to define, a persistence story to pin. These concerns are deliberately scoped as Round 4 work (see §7); the Round-3 disposition lands the trait-surface contract — opaque-handle-bearing — and surfaces the table-internal questions as Round-4 candidates.

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

`VIEW_TAG_BYTES = 1` (pinned in §3.3 Sub-bundle A's
`VIEW_TAG_BYTES` row, A4 disposition Round 3 §3.1.4). The
1-byte width matches `shekyl-crypto-pq::derivation::derive_view_tag_x25519`'s
`u8` return type and `shekyl-scanner::shared_key::SharedKey::view_tag`'s
field shape; consistent with classical Monero's view-tag width;
bounds the X25519-only pre-filter false-positive rate to 2⁻⁸
per output. The `[u8; N]` shape rather than a typed hash output
is intentional — view tags are short publicly-comparable
bytestrings, not opaque hashes that need verification machinery.
A future migration that widens the tag would bump
`VIEW_TAG_BYTES` and the underlying HKDF salt suffix
(`HKDF_SALT_VIEW_TAG_X25519`'s `-v1`) together as a coupled
spec amendment; the `ViewTag` newtype absorbs the width change
behind its constructor.

##### `OutputHandle`

```rust
/// Opaque reference to a per-output spending capability held
/// inside `LocalKeys`'s workflow-internal `HandleTable`.
///
/// **Carries no secret material itself.** A leaked `OutputHandle`
/// is meaningless without the originating engine's table; an
/// attacker who observes a handle (via memory disclosure, debug
/// print, or unencrypted persistence) cannot derive the
/// underlying spending secret without the engine's internal
/// mapping.
///
/// The orchestrator stores `OutputHandle` against per-output
/// metadata (`key_image`, `amount_atomic_units`) inside whatever
/// long-lived structure tracks claimed-but-unspent outputs
/// (`transfer_details`, the wallet ledger). At spend time, the
/// handle is referenced inside `TxToSign.inputs[i].handle`;
/// `sign_transaction`'s impl resolves the handle internally to
/// recover the per-output secret material and produce the
/// signature.
///
/// **Inner shape (Round 4).** Whether the handle is a counter,
/// a UUID, a 16-byte random ID, or a cryptographic commitment
/// is pinned in Round 4 against the unforgeability requirement
/// (per A7) and the persistence model selected (per the
/// handle-persistence option-space, §7). The type stays opaque
/// to the trait surface regardless of inner shape; downstream
/// callers treat it as `Hash + Eq + Clone` only.
pub struct OutputHandle(/* opaque inner shape; pinned in Round 4 */);
```

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
/// **No fields are secret-bearing.** The per-output spending
/// secrets (the secret-key derivative, the amount-blinding
/// factor, and any HKDF-derived intermediate material) live
/// inside `LocalKeys`'s workflow-internal `HandleTable` keyed
/// by `handle`; they are not exposed to the orchestrator. The
/// only fields below are public on-chain data (`key_image`)
/// and balance-display data (`amount_atomic_units`); neither
/// imposes a `Zeroize` discipline on the receiver.
pub struct OutputClaim {
    /// Opaque reference to the per-output spending capability.
    /// Stored by the orchestrator against the claimed output's
    /// long-lived record; passed back into `sign_transaction`
    /// via `TxToSign.inputs[i].handle` at spend time. Carries
    /// no secret material; safe to log, persist, or transmit
    /// across non-`KeyEngine` boundaries (subject to the
    /// privacy concern that the handle's *existence* leaks
    /// "this output belongs to this wallet" — observers should
    /// not see handles for outputs they don't already know
    /// belong to the wallet).
    pub handle: OutputHandle,
    /// The output's key image. Public on-chain after spend; used
    /// by wallet-side double-spend tracking and consensus-side
    /// double-spend detection.
    pub key_image: KeyImage,
    /// The decrypted output amount (atomic units). Non-secret;
    /// the orchestrator displays it as part of the wallet's
    /// balance presentation and uses it to drive transaction-
    /// build amount accounting.
    ///
    /// Decrypted at `try_claim_output` time (the impl already
    /// has the shared secret in scope); requiring downstream
    /// re-decryption would force the secret-derivation path to
    /// run twice. The decrypted-at-claim-time disposition is
    /// stable post-handle-pivot — the shared secret remains
    /// confined to the impl's stack frame either way; only the
    /// resulting `u64` crosses the boundary.
    pub amount_atomic_units: u64,
}
```

> **Round-3 deletion note.** The Round-2 `OutputClaim` shape
> carried `output_secret_key: Zeroizing<[u8; 32]>` and
> `amount_blinding_factor: Zeroizing<[u8; 32]>` as `pub` fields.
> Both are deleted by the handle-indirected pivot. The
> spending-secret material lives behind `handle` inside
> `LocalKeys`'s `HandleTable`; the amount-blinding factor lives
> there too (the impl regenerates it at sign time from the
> per-output shared secret accessible via the handle, or stores
> it in the table alongside the secret-key derivative — the
> exact internal layout is impl freedom). The orchestrator's
> address space no longer holds either secret.

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
    /// Per-input signing context. Each entry carries an
    /// `OutputHandle` referencing the per-output spending
    /// capability (resolved by `sign_transaction`'s impl
    /// internally to the per-output secret material), plus the
    /// input's FCMP++ membership-proof context, per-input
    /// signing message bytes, and per-input HKDF binding
    /// context. The exact shape — including the precise
    /// placement of the handle inside `TxInputSigningContext`
    /// — is pinned in PR 5; PR 3 forward-declares the type
    /// with the constraint that one of its fields is `handle:
    /// OutputHandle`.
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
    /// The hybrid KEM public key (X25519 + ML-KEM-768) the sender
    /// encapsulates against. Public; not zeroized.
    ///
    /// **Per-subaddress derivation (§3.1.3 / §3.3 Sub-bundle A).**
    /// Both components are bound to `(view_secret,
    /// subaddress_index)`:
    ///
    /// - **X25519 component.** Derives per-index from the view
    ///   secret per the existing classical-Monero subaddress
    ///   derivation machinery — the same path that produces
    ///   `SubaddressKeyPair { spend_pk, view_pk }` under the
    ///   `Audit` purpose. No new primitive needed.
    /// - **ML-KEM-768 component.** Derives via deterministic
    ///   ML-KEM-768 keygen seeded by `HKDF-Expand(view_secret,
    ///   SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT ||
    ///   subaddress_index_le_bytes)`. The HKDF context string is
    ///   pinned in §3.3 Sub-bundle A
    ///   (`SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT =
    ///   b"shekyl/subaddr-mlkem-keygen-v1"`); the `-v1` suffix
    ///   reserves a versioning axis for future migration.
    ///
    /// **Sender vs. recipient asymmetry.** The sender extracts
    /// the precomputed `kem_pk` from `RecipientSubaddress` and
    /// feeds it into `HybridX25519MlKem::encapsulate` — zero
    /// per-encapsulation derivation cost. The recipient
    /// regenerates the per-subaddress ML-KEM keypair on demand
    /// from `(view_secret, subaddress_index)` (~50 µs per
    /// derivation, dominated by ML-KEM-768 KeyGen rather than
    /// HKDF, called rarely; cacheable in a subaddress-derivation
    /// cache if hot).
    ///
    /// **Why per-subaddress and not wallet-level.** Carrying a
    /// wallet-level ML-KEM PK in the encoded subaddress would
    /// make any two encodings from the same wallet trivially
    /// linkable via direct byte comparison of the embedded PK.
    /// Per-subaddress derivation is rule-forced by
    /// `00-mission.mdc`'s priority hierarchy; see §3.1.3 for the
    /// full priority-hierarchy decomposition (P1 X25519-only
    /// breaks PQC; P2 wallet-level PK breaks subaddress
    /// unlinkability; P3 out-of-band delivery breaks the
    /// self-contained-address UX).
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
/// `RecipientSubaddress.kem_pk`). The extension composes
/// cleanly with the deterministic per-subaddress ML-KEM-768
/// derivation now landing in §3.1.3 / §3.3 Sub-bundle A: the
/// audit-extended payload would surface the same `kem_pk:
/// HybridKemPublicKey` produced by the same
/// `derive_subaddress_kem_keypair(view_secret, idx)` primitive
/// — no separate keygen path needed; the audit purpose just
/// publishes more of the per-subaddress derived material than
/// the recipient purpose does. The extension lands as an
/// additional field on `SubaddressKeyPair` (or, if the audit
/// payload's V3.x shape diverges further, as a new variant on
/// `SubaddressFor` + `SubaddressPurpose`) when designed; the
/// `#[non_exhaustive]` annotation on the enums absorbs the
/// additive variant without breaking existing call sites.
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

#### Visibility discipline for Sub-bundle B message types (Attack 4.2 disposition)

Each Sub-bundle B message type has a deliberate visibility
shape — both the type-level visibility (`pub`, `pub(crate)`,
`pub(super)`) and the per-field visibility. Round 3's
adversarial pass surfaced that these decisions, while
internally coherent, were not pinned at the spec level with
rationale; reviewers had to reconstruct the discipline from
the production code rather than read it from the design doc.
The Attack 4.2 disposition pins each decision and its
rationale here.

**Trust class.** All Sub-bundle B message types are
**Trust-class B** (handle public state only). No message type
is Trust-class A (handles long-term secret material directly):
`OutputHandle` is opaque (the inner shape's secret material
lives in `LocalKeys`'s `HandleTable`, not in the handle); all
other message types carry public on-chain metadata, addresses,
or references. The Trust-class B classification is what
permits the `pub` visibilities below; a Trust-class A type
would default to `pub(crate)` until external-implementor
trust models are concrete (§7.7).

**Default discipline.** The default visibility is the
**tightest that satisfies the trait's contract**; widening
to `pub` requires naming the consumer that needs the wider
visibility. Per-field visibility defaults tighter than the
type-level visibility — fields are `pub` only when the
orchestrator's contract requires field access; otherwise
`pub(crate)` (so the impl constructs them) and constructors
expose the safe construction surface.

| Type | Type-level visibility | Per-field visibility | Rationale |
|---|---|---|---|
| `OutputDetectionInput` | `pub` | private (`ciphertext`, `view_tag`, `output_index`) | Crosses the trait boundary as a `&Self` parameter on `try_claim_output`; orchestrator constructs via `from_block_output(&LedgerBlock, u64) -> Option<Self>` (the source-correctness path) or `from_components(...)` (the fixture / replay path). Field privacy enforces that all construction goes through one of the two named constructors; arbitrary byte-soup construction (which would defeat the source-correctness invariant per §3.3 Sub-bundle B's coupling note) is impossible. Constructor visibility is `pub(crate)` for `from_block_output` (only the scanner / impl crate needs it) and `pub` for `from_components` (test fixtures and replay paths cross crate boundaries; not security-load-bearing because the caller is responsible for source correctness in those scopes). |
| `OutputHandle` | `pub` | private (inner shape opaque, pinned in Round 4) | Opaque reference type. Crosses the trait boundary in `OutputClaim` and in `TxInputSigningContext`. Field privacy is structural: an `OutputHandle` is meaningful **only** to the `LocalKeys` that issued it (the `HandleTable` keys against the inner shape); orchestrator code can store, persist, and reference handles but cannot inspect them. The opacity is the load-bearing security property the handle-indirected workflow shape delivers (§3.1.2). Future implementors (HSM-backed, hardware-key) inherit the opacity by adopting the trait surface. The `pub` type-level visibility is needed because the message types referencing `OutputHandle` (themselves `pub`) are crate-boundary-crossing; tightening to `pub(crate)` would constrain the trait surface to a single crate. |
| `OutputClaimResult` | `pub` | `pub` variants (`NotMine`, `Mine(OutputClaim)`) | Returned by `try_claim_output`. The orchestrator pattern-matches on the variant; that requires `pub` at the variant level. The discriminant carries no secret material (NotMine vs Mine is on-chain-public information after the orchestrator has the X25519 ephemeral and view tag). `#[non_exhaustive]` per Q9.2's additive-amendment discipline. |
| `OutputClaim` | `pub` | `pub` (`handle: OutputHandle`, `key_image: KeyImage`, `amount_atomic_units: u64`) | Returned inside `OutputClaimResult::Mine`. All three fields are public-state: `handle` is opaque per the row above; `key_image` is on-chain-public after the eventual spend; `amount_atomic_units` is wallet-state but not consensus-secret (the orchestrator's wallet view exposes balances anyway). Field visibility is `pub` because orchestrator code consumes all three: `handle` for later `sign_transaction` calls; `key_image` for double-spend tracking; `amount_atomic_units` for balance computation. |
| `TxToSign` | `pub` | `pub` (per-field shapes pinned at PR 5 implementation time) | Crosses as a `&Self` parameter on `sign_transaction`. Constructed by the orchestrator (or `PendingTxEngine` per PR 5) at transaction-build time; consumed by `KeyEngine` at signing time. All fields are public structural data plus opaque `OutputHandle` references; no secret material. |
| `TxSignatures` | `pub` | `pub` (per-field shapes pinned at PR 5 implementation time) | Returned by `sign_transaction`. All fields are signature-class data (publicly verifiable; no `Zeroize` discipline applies). |
| `SubaddressPurpose` | `pub` | `#[non_exhaustive]`; `pub` variants (`Recipient`, `Audit`, future variants) | Crosses as a parameter on `derive_subaddress`. Variants are a stable enumeration the orchestrator names at the call site. `#[non_exhaustive]` per Q9.2. |
| `SubaddressFor` | `pub` | `#[non_exhaustive]`; `pub` variants (`Recipient(RecipientSubaddress)`, `Audit(SubaddressKeyPair)`, future variants) | Returned by `derive_subaddress`. Variants are pattern-matched by the orchestrator; `pub` at the variant level is needed. The inner-type visibilities apply per row below. |
| `RecipientSubaddress` | `pub` | `pub` (`encoded: Address`, `kem_pk: HybridKemPublicKey`) | Sender-facing payment-URI / QR-code shape. Both fields are public: `encoded` is the address string the recipient publishes; `kem_pk` is the per-subaddress hybrid KEM public key the sender encapsulates against (per §3.1.3's β disposition). No secret material. |
| `SubaddressKeyPair` | `pub` | `pub` (`spend_pk: [u8; 32]`, `view_pk: [u8; 32]`) | Audit / backup shape. Both fields are public-key bytes. The "key pair" naming is a Monero-inherited convention referring to the spend / view distinction at the public-key level, not to a secret-key pair. No secret material; backup-context code that exports subaddress structure consumes these. |
| `ViewTag` | `pub` | `pub(crate) [u8; VIEW_TAG_BYTES]` (single tuple field) | Type wraps a 1-byte view-tag value (per §3.3 Sub-bundle A's `VIEW_TAG_BYTES` row, A4 disposition). Type-level `pub` because it appears in `OutputDetectionInput`'s field set (which is `pub` at the type level, private at the field level — `ViewTag` reaches the trait surface only via `OutputDetectionInput::from_*` constructors). Field-level `pub(crate)` because only the scanner / impl crate constructs a `ViewTag` from raw bytes; orchestrator code that manipulates `ViewTag` values reads through trait-bounded APIs (or doesn't manipulate the inner bytes at all). The width-pinning in §3.3 Sub-bundle A absorbs future migrations behind the newtype. |

**Pattern-4 generalization for PR 4–7.** Per-trait PRs that
introduce message types document each type's visibility
decision and rationale at the design-doc level. The format
above (a table with type / type-level visibility / per-field
visibility / rationale columns) is the forward-template; PR
4–7 inherit it. The Trust-class A/B classification (§3.1.5)
gates the default visibility — Trust-class A types start
`pub(crate)` until external-implementor trust models are
concrete; Trust-class B types may ship `pub` from V3.0 with
the standard external-implementor caveats. The `KeyEngine`
trait itself is currently `pub(crate)` per §3.4 Decision 4
(trait-level visibility distinct from message-type
visibility); the V3.2 promotion bundle reconciles both.

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
    /// **Recipient purpose — derivation cost.** The X25519
    /// component of `kem_pk` derives via the existing
    /// classical-Monero subaddress-derivation machinery (cheap;
    /// scalar arithmetic). The ML-KEM-768 component derives via
    /// deterministic keygen seeded by `HKDF-Expand(view_secret,
    /// SUBADDR_MLKEM_KEYGEN_HKDF_CONTEXT ||
    /// subaddress_index_le_bytes)` — see §3.1.3 / §3.3 Sub-bundle A
    /// for the byte-layout. Total cost is dominated by ML-KEM-768
    /// KeyGen (~50 µs on commodity hardware as of V3.0; HKDF is
    /// a small constant on top), so per-call cost is bounded by
    /// the ML-KEM keygen cost regardless of HKDF overhead. The
    /// method is called rarely in normal wallet operation
    /// (subaddress-creation, address-display, payment-URI
    /// generation); implementations may cache resolved
    /// subaddresses by `(idx, purpose)` if a caller's workload
    /// hits the same index repeatedly. **Audit purpose** has the
    /// same X25519-derivation cost as Recipient and skips the
    /// ML-KEM-keygen path entirely.
    ///
    /// **Why per-subaddress ML-KEM-768 derivation rather than
    /// wallet-level.** Rule-forced by `00-mission.mdc`'s priority
    /// hierarchy — embedding a wallet-level ML-KEM PK in encoded
    /// subaddresses would make any two encodings trivially
    /// linkable via direct byte comparison. See §3.1.3 for the
    /// full priority-hierarchy decomposition.
    ///
    /// The classical spend/view subaddress derivation has no
    /// concrete failure mode at today's surface (the classical
    /// path's only failure modes are RNG-failure-class events,
    /// essentially impossible during pure derivation from existing
    /// key material). The deterministic ML-KEM-768 keygen path
    /// has a defined failure surface (rejection-sampling internal
    /// to ML-KEM-768 KeyGen, vanishing probability in practice
    /// against any single index, but well-defined as a possibility
    /// at the spec level); trait stability across the V3.x
    /// PQC-augmented audit-payload extension is also part of the
    /// rationale for the `Result` shape now.
    fn derive_subaddress(
        &self,
        idx: SubaddressIndex,
        purpose: SubaddressPurpose,
    ) -> Result<SubaddressFor, Self::Error>;

    /// Workflow: try to claim an on-chain output for this wallet.
    ///
    /// Bundles X25519 view-tag pre-filter + hybrid decap + HKDF
    /// chain + key-image computation + handle-table insertion
    /// behind a single trait boundary. The `OutputDetectionInput`
    /// carries the per-output detection context (hybrid
    /// ciphertext, view tag, output index) sourced via
    /// `OutputDetectionInput::from_block_output` at the scanner
    /// call site.
    ///
    /// On a successful detection, the impl inserts the per-output
    /// spending material (secret-key derivative, amount-blinding
    /// factor, any HKDF-derived intermediates needed for spend
    /// construction) into `LocalKeys`'s workflow-internal
    /// `HandleTable` and returns
    /// `OutputClaimResult::Mine(OutputClaim { handle, key_image,
    /// amount_atomic_units })` — the orchestrator receives the
    /// opaque handle plus public metadata; the spending secrets
    /// stay confined to the engine's address space. On a rejected
    /// detection (X25519 pre-filter mismatch, or post-decap
    /// validity check failure), returns
    /// `OutputClaimResult::NotMine`. Most outputs are `NotMine`
    /// in real scanning; the X25519 pre-filter rejects them
    /// cheaply without entering the handle-table insertion path.
    ///
    /// **No secret material crosses the trait boundary.** The
    /// X25519 raw shared secret (32 bytes), the 64-byte hybrid
    /// shared secret, HKDF intermediate keying material, the
    /// per-output secret-key derivative, and the amount-blinding
    /// factor all stay inside this method's stack frame or
    /// inside `LocalKeys`'s `HandleTable`; none cross the trait
    /// boundary. The `OutputClaim` returned to the orchestrator
    /// carries only an opaque `handle: OutputHandle` reference
    /// plus non-secret on-chain metadata (`key_image`,
    /// `amount_atomic_units`). This is the load-bearing security
    /// property the handle-indirected workflow shape delivers;
    /// see §3.1.1 / §3.3 / §4-deliberately-does-not-expose for
    /// the structural argument.
    ///
    /// **HKDF derivation reference (A3 disposition, Round 3 §3.1.4).**
    /// The per-output HKDF chain consumes the canonical salt + label
    /// registry pinned in `shekyl-crypto-pq::derivation`:
    /// `HKDF_SALT_OUTPUT_DERIVE = b"shekyl-output-derive-v1"` for the
    /// post-decap output-secret derivation;
    /// `HKDF_SALT_VIEW_TAG_X25519 = b"shekyl-view-tag-x25519-v1"` for
    /// the X25519-only pre-filter tag; per-secret labels
    /// `shekyl-output-x`, `shekyl-output-y`, `shekyl-output-mask`,
    /// `shekyl-output-amount-key`,
    /// `shekyl-output-view-tag-combined`,
    /// `shekyl-output-amount-tag`, `shekyl-pqc-output`,
    /// `shekyl-pqc-ed25519`, each suffixed with `output_index_le64`.
    /// Per-output uniqueness is delivered by `combined_ss = X25519(eph_sk,
    /// view_pk) ‖ ML-KEM-Decap(kem_sk, ct)` being per-output-unique by
    /// construction (each output has a unique X25519 ephemeral and unique
    /// ML-KEM ciphertext); the `output_index_le64` byte-suffix provides
    /// intra-tx separation. No explicit `tx_context_hash` binding is
    /// required at this layer. The single source of truth is
    /// `shekyl-crypto-pq::derivation` (alongside
    /// `tools/reference/derive_output_secrets.py` and the locked
    /// `docs/test_vectors/PQC_OUTPUT_SECRETS.json`); the trait surface
    /// references the registry rather than restating it. See §3.3
    /// Sub-bundle A's `OUTPUT_DERIVE_HKDF_REGISTRY` row.
    async fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> Result<OutputClaimResult, Self::Error>;

    /// Workflow: sign a fully-prepared transaction.
    ///
    /// The `TxToSign` parameter bundles all per-input signing
    /// context (`Vec<TxInputSigningContext>`), per-output context
    /// (`Vec<TxOutputContext>`), and FCMP++ transaction-level
    /// context (`FcmpPlusPlusContext`). Each
    /// `TxInputSigningContext` references its per-output spending
    /// capability via `handle: OutputHandle` (the opaque reference
    /// returned by an earlier `try_claim_output` call); the
    /// implementor resolves the handle internally against
    /// `LocalKeys`'s `HandleTable` to recover the per-output
    /// secret-key derivative and amount-blinding factor needed
    /// to produce the per-input signature. The exact field shapes
    /// for the per-input / per-output / per-tx context types are
    /// pinned in PR 5 (`PendingTxEngine`) alongside that trait's
    /// transaction-build workflow; PR 3 carries forward
    /// declarations adequate for trait extraction with the
    /// constraint that `TxInputSigningContext` carries an
    /// `OutputHandle`. Returns `TxSignatures` carrying the
    /// `Vec<TxInputSignature>` and `Vec<FcmpPlusPlusWitness>`
    /// bundle; all returned material is signature-class
    /// (publicly verifiable; no `Zeroize` discipline applies).
    ///
    /// **Handle resolution failure modes** (Round-4 follow-on:
    /// concrete `KeyEngineError` variants land at implementation
    /// time): handle not present in table (caller bug or
    /// post-eviction reference); handle from a different engine
    /// instance (cross-engine reference); handle present but the
    /// underlying output has already been consumed by an
    /// earlier `sign_transaction` call (replay rejection per
    /// the per-method replay-behavior contract — see §7's
    /// Pattern-6 cluster).
    ///
    /// **Validation contract (D1 disposition, Round 3 §3.1.4).**
    /// The impl validates: (i) handle resolution succeeds for every
    /// `TxInputSigningContext.handle` in `tx.inputs`; (ii) the
    /// per-input signature can be produced from the resolved
    /// per-output secret material (the cryptographic primitives
    /// don't fail mid-signing on well-formed inputs, but
    /// resource-class faults — exhausted entropy, missing PQC
    /// backend, etc. — surface here); (iii) the FCMP++ witness can
    /// be produced from the resolved spending material against
    /// `tx.fcmp_context`. The impl does **not** validate: amount
    /// accounting (sum of input amounts == sum of output amounts +
    /// fee — orchestrator's responsibility, established at
    /// `TxToSign` construction time per PR 5's `PendingTxEngine`
    /// contract); fee calculation (orchestrator); recipient-address
    /// validity (already validated at the address-decoding boundary
    /// before `TxToSign` was constructed); transaction structural
    /// well-formedness beyond what the type system enforces
    /// (orchestrator). This boundary is load-bearing: it pins
    /// which `KeyEngineError` variants surface from this method
    /// (handle-resolution-class + signing-resource-class) versus
    /// which conditions are **caller-side preconditions** that
    /// must hold before invocation (amount accounting, fee
    /// correctness, address validity, structural well-formedness).
    /// A future maintainer adding a validation responsibility to
    /// this method must justify why the validation belongs
    /// inside the engine boundary rather than at the orchestrator
    /// layer; the default is the orchestrator. See §3.1.4 for the
    /// Pattern-2 spec-silent-junctions framing this contract closes.
    ///
    /// **Cross-domain signature reuse is prevented cryptographically
    /// inside the impl** via per-domain HKDF chains plus
    /// **compile-time type-system enforcement** (A5 → ζ
    /// disposition, Round 3 §3.1.4). The `SignDomain` enumeration
    /// (§3.3 Sub-bundle A) is no longer a trait-level concept; the
    /// binding from workflow method to `SignDomain` variant is
    /// pinned via the `SignsInDomain` marker trait (§3.3 Sub-bundle
    /// A) plus per-domain unit-struct markers
    /// (`SignTransactionDomain`, `OutputSecretDerivationDomain`,
    /// `FcmpPlusPlusWitnessDomain`, `MlKemChallengeDomain`). The
    /// impl's call sites consume the workflow-internal
    /// `derive_signing_key::<SignTransactionDomain>(...)` (and
    /// per-domain siblings) — the type parameter is the only way
    /// to select a domain; there is no runtime `domain: SignDomain`
    /// argument. A future maintainer copying this method's body
    /// to add a new signing workflow must change the marker (or
    /// introduce a new one) — cross-domain reuse becomes a
    /// deliberate inspection-visible action, not a copy-paste
    /// accident. The discipline transfers from convention (every
    /// call site asserts) to type system (rustc enforces).
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

- **(1) Hybrid encapsulation against external recipient public
  keys.** The sender's `KeyEngine` does not mediate hybrid
  encapsulation; `HybridX25519MlKem::encapsulate` is a free
  function in `shekyl-crypto-pq` consumed at transaction-build
  time outside the `KeyEngine` boundary. A
  `KeyEngine::encapsulate(...)` method would expose nothing the
  free function doesn't already expose and would conflate
  "operations that touch the wallet's secret keys" with
  "operations that don't" at the same trait. (L1.1)
- **(2) Signature verification.** Verification needs only public
  material; not a `KeyEngine` concern. Lives in
  `shekyl-crypto-pq::signature::HybridEd25519MlDsa::verify` (free
  function) or in the verification call sites themselves.
  Including verification at the trait surface would invite a
  generic-signing-oracle abuse pattern that the workflow shape
  specifically prevents. (L1.3)
- **(3) Wallet creation seed-derivation.** Runs once before the
  `KeyEngine` exists. `LocalKeys::from_seed(seed: &WalletSeed) ->
  Result<Self, KeyError>` is the wallet-create path's
  responsibility (and `LocalKeys::from_test_seed(test_label: &str)`
  is the `#[cfg(test)]` analog for fixtures); the trait method
  surface assumes a fully-derived blob already exists. The
  wallet-open / derivation error type stays as the existing
  `KeyError` (per §3.2's split); it does not leak into
  `KeyEngineError`. (L1.5)
- **(4) Secret material in any form across the trait boundary.**
  The handle-indirected workflow shape makes this property
  literal, not quantitative. Three classes of secret stay inside
  the `KeyEngine` impl:
  - **Long-term key material** (`AllKeysBlob`'s spend / view
    secrets, the wallet-level ML-KEM secret) — owned exclusively
    by `LocalKeys`; never crosses the boundary at all.
  - **Per-output derived secrets** (the per-output secret-key
    derivative, the amount-blinding factor) — held inside
    `LocalKeys`'s workflow-internal `HandleTable`, keyed by
    `OutputHandle`; the orchestrator sees only the opaque
    handle. Spend-time access is mediated by `sign_transaction`
    resolving the handle internally and never returning the
    underlying secret bytes.
  - **Cryptographic intermediates** (the X25519 raw 32-byte
    shared secret, the 64-byte hybrid shared secret, HKDF
    intermediate keying material) — exist only transiently in
    the workflow methods' stack frames; zeroized on drop per
    the workspace's `Zeroize` / `ZeroizeOnDrop` discipline
    ([`35-secure-memory.mdc`](../../.cursor/rules/35-secure-memory.mdc)).
  The orchestrator's address space sees only structured non-
  secret outputs (`OutputClaim`'s `handle` + `key_image` +
  `amount_atomic_units`; `TxSignatures`'s public signature
  bundle).

  **What handle disclosure leaks** is the wallet's
  received-output enumeration over the disclosure window
  (a privacy concern; see §7's Pattern-7 cluster). For a
  long-lived wallet, that enumeration combined with the
  orchestrator's other state (transaction history, address
  book, balance presentation) produces a substantial privacy
  fingerprint — the leak is not a single fact ("this output
  belongs to this wallet") but the cumulative set of
  detected-output observations across whatever time window the
  handles are held. This is unavoidable for orchestrator-side
  state; the handle model does not eliminate the privacy
  surface, only the spending-secret surface.

  **What handle disclosure does not leak** is the underlying
  spending secret — a leaked handle is meaningless to a
  **passive** attacker without `LocalKeys`'s table (memory
  scraping, log leakage, persistence-to-disk-without-engine-
  access). An **active** attacker who has compromised the
  orchestrator and can submit messages to `LocalKeys` can use
  leaked handles to obtain signatures via `sign_transaction`,
  gaining the spending capability without the spending material;
  this is the inherent capability-vs-material trade-off for
  handle-based designs and is the same property session tokens
  have. Defense against active orchestrator compromise is at
  the orchestrator's integrity boundary, not at the trait
  surface; Stage 4's actor isolation is the structural defense
  once it lands. The "leaked handle is meaningless" claim is
  correct for passive disclosure and weaker for active
  orchestrator compromise.

  **This is the load-bearing security property the handle-
  indirected workflow shape delivers and primitive-shape
  surfaces (e.g., a hypothetical `view_ecdh ->
  X25519SharedSecret`) or Round-2-shape returns (e.g., the
  deleted `OutputClaim.output_secret_key: Zeroizing<[u8; 32]>`
  field) violate.** Primitive-shape and Round-2-shape surfaces
  leak the spending material to passive attackers, which the
  handle model closes; closing the active-orchestrator-compromise
  surface is Stage 4's actor-isolation work, not PR 3's. The
  "Round 3 reviewer asks 'what's the security difference between
  primitive-shape and workflow-shape?'" question is answered
  here, in the doc, not derived during review.
- **(5) Direct access to long-term key material at the trait
  surface.** No `get_view_secret(...)`, no `get_spend_secret(...)`,
  no byte-level view of `AllKeysBlob`. The workflow-shape
  boundary depends structurally on **no trait method exposing
  long-term key material directly** — once long-term key
  material is reachable through the trait, the orchestrator can
  orchestrate its own primitives outside the impl and the
  boundary collapses.

  The trait surface is **silent on what implementors do outside
  the trait methods**. An HSM-backed or hardware-key implementor
  that respects the trait surface but additionally exposes raw
  key bytes via a side-channel (debug interface, structured
  logging, configuration export, telemetry path) is not
  constrained by the trait — the trait can only define what the
  implementor must publicly support, not what the implementor
  must not do beyond the trait. External-implementor trust is a
  separate property whose disposition lives with §3.4 / Phase 0d's
  `pub(crate)` visibility decision and the V3.2 promotion-bundle
  commitment that defers external-implementor trust until the
  actor abstraction surfaces concrete external consumers. The
  trait surface enforces what the trait surface can enforce; the
  rest is policy at the implementor-trust boundary.
- **(6) Key rotation, revocation, derivation-reset.** V3.0 does
  not support these. Wallet-key rotation is handled by wallet
  re-creation (rebuild from new seed; manually transfer
  balances). Stage-4 / V4 reviewers asking "what's the migration
  story when a wallet's classical half is compromised?" find the
  answer here: there is no in-engine rotation surface; the
  recovery path is operational, not cryptographic. Future
  rotation-as-runtime-operation is V4-territory pending the
  lattice-only transition; if it lands, it does so as a new
  workflow method, not as a primitive on the existing surface.
- **(7) View-only / spend-only mode runtime distinction.**
  Handled at construction: `LocalKeys::from_view_only_seed(...)`
  returns a `KeyEngine` whose `sign_transaction` returns
  `Err(KeyEngineError::SpendKeyUnavailable)` while
  `try_claim_output` and `account_public_address` /
  `derive_subaddress(_, Audit)` work normally. The trait does
  not expose a runtime mode flag or separate trait-method
  variants; the construction-time discrimination is sufficient,
  and the runtime error path lives in `KeyEngineError` rather
  than in trait-shape. (Auditing nodes, exchange listeners,
  multi-party-hosted view nodes consume this construction path;
  the trait's contract is identical regardless of mode.)

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
   `OutputHandle`, `OutputClaimResult`, `OutputClaim`, `TxToSign`,
   `TxSignatures`, `SubaddressPurpose`, `SubaddressFor`,
   `RecipientSubaddress`, `SubaddressKeyPair`, `ViewTag`); pinned
   shapes from commit 2 + Round-3 commit 3a of this design-doc
   round.
4. **`HandleTable` workflow-internal state inside `LocalKeys`.**
   Per Round 3's handle-indirected pivot (§3.1.2). Concurrent-
   access shape, eviction policy, persistence story, handle-ID
   unforgeability shape — all Round-4 dispositions. PR 3
   implementation lands the simplest viable shape (per §7.11's
   Round-3 lean: ephemeral handles + restart-rescan;
   sharded-`RwLock` table; counter-with-engine-ID handles) and
   updates against Round-4 outcomes if the dispositions change
   before the feat branch cuts.
5. `try_claim_output` impl: X25519 view-tag pre-filter + hybrid
   decap + HKDF chain + key-image computation + handle-table
   insertion; returns handle-bearing `OutputClaim`.
6. `sign_transaction` impl: per-input handle resolution against
   the table + per-domain HKDF derivation (per Round-3 A5
   disposition: marker trait + associated const, lands in commit
   3c of this design-doc round) + hybrid signature production +
   FCMP++ witness generation.
7. `Engine<S, D, L, K>` parameterization.
8. Migrate consumers from `engine.keys` direct field access to
   `K: KeyEngine` trait dispatch.
9. `FaultInjecting<K: KeyEngine>` test wrapper in `test_support`
   (or wherever the test substrate accumulates); `#[cfg(test)]`-
   gated (visibility discipline per Round-3 commit 3d). **No
   `MockKeys`** (per §6.4 / §2.1.2).
10. Hybrid test exercising one §5.2 property predecessors haven't
    covered (selection per §6.4 — (a) layered-call error
    preservation, exercised via `FaultInjecting<LocalKeys>` against
    handle-bearing message shapes).
11. Benchmark harness for `KeyEngine` hot-path methods (selection
    per §6.5; `account_public_address` plus the `try_claim_output`
    Mine/NotMine split plus optional handle-resolution and
    sign-transaction-full benches per Round 4's table-shape
    disposition).
12. Docs propagation (this design doc's realignment + CHANGELOG
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
(`try_claim_output(&OutputDetectionInput) -> OutputClaimResult`,
`sign_transaction(&TxToSign) -> TxSignatures`) with the error
variant intact, the `OutputClaimResult` / `TxSignatures` return
types not produced (the error short-circuits before construction),
and the layered-call structure preserved across the wallet-level
method's internal trait dispatch.

Under the handle-indirected workflow contract, the test exercises
two specific error-propagation paths:

- **`try_claim_output` failure** — `FaultInjecting<LocalKeys>`
  injects a `KeyEngineError` variant before the real impl
  reaches the handle-table insertion path; the wallet-level
  method observes the error without producing an `OutputHandle`
  in any return value. The substantive correctness property
  the test checks — that **no orphan entry persists in the
  handle table after the failed call** — is pinned in
  commit 3d's B1 disposition to **option (i)**: a
  `#[cfg(test)] pub(crate) fn handle_table_size(&self) ->
  usize` (or equivalent) test-inspection accessor on
  `LocalKeys`. The accessor is protected by the three-layer
  discipline (§6.6 B1 disposition — `#[cfg(test)]` cfg-gate +
  `pub(crate)` visibility + CI gate). Rationale for picking
  (i) over the rejected (ii) "indirect observation" claim:
  orphan-absence is a substantive correctness property of the
  handle-storage hygiene contract (§3.1.5 B2 / §6.7). The (ii)
  weaker claim ("subsequent `sign_transaction` calls fail to
  resolve handles that should have been issued") cannot
  distinguish "no orphan present" from "orphan present but
  never referenced"; a slow-leak failure mode (a subset of
  failure paths leave orphans, eventually exhausting memory)
  passes (ii) but fails (i). The test-only inspection surface
  is bounded — one accessor, three-layer-protected, with a
  named consumer (the §6.4 fault-injection tests and the
  §6.7 B2 handle-storage hygiene tests) — and the
  forward-template discipline (§3.1.5 Pattern-3) is explicit
  about when test-only additions are admissible.

  The PR 3 hybrid test asserts both the trait-surface-observable
  property (no `OutputHandle` returned in any `OutputClaim`
  because the failed call returns `Err(...)`, not `Ok(...
  ::Mine(...))`) and the orphan-absence property (the
  table size before and after the failed call is unchanged,
  asserted via `handle_table_size`).
- **`sign_transaction` failure with handle resolution** — the
  test seeds the handle table via a successful prior
  `try_claim_output` call, then injects a `KeyEngineError`
  variant on the subsequent `sign_transaction` call. The test
  verifies that the handle remains valid post-failure
  (signature failure does not consume the handle; the
  orchestrator can retry) and that the layered-call error path
  preserves the variant intact. The "handle remains valid"
  property is trait-surface-observable: a follow-up
  `sign_transaction` call against the same handle without the
  fault injected succeeds, demonstrating the handle was not
  consumed by the failed call.

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
  + HKDF chain + key-image computation + handle-table insertion.
  Measures the full output-detection-and-claim cost including
  the workflow-internal handle-table insertion. Less time-
  dominant than the NotMine path in aggregate scanning but
  worth a separate bench because the workloads are structurally
  distinct (combining them into one bench produces a number
  whose meaning depends on the test data's Mine:NotMine ratio
  — uninformative; reviewers familiar with criterion's
  parameterized bench shape may ask why not parameterize over
  the ratio — the answer is that the workloads have different
  cost regimes that warrant per-regime measurement, with system-
  level wallet-refresh modeling deferred to higher-level benches
  in PR 4 or PR 5).
- `engine_trait_bench_key_sign_transaction_resolve_handle` —
  amortized handle-table lookup cost for `sign_transaction`'s
  per-input handle resolution. Round-4 candidate; the actual
  cost depends on the handle-table's concurrent-access shape
  (sharded `RwLock` vs lock-free hashmap vs fair-queued) which
  is itself Round 4 work. The bench may land alongside Round 4's
  table-shape disposition rather than at PR 3 cut-point if the
  shape isn't pinned by then.
- `engine_trait_bench_key_sign_transaction_full` — async
  workflow hot path for the spend path: handle resolution +
  per-input hybrid signature production + FCMP++ witness
  generation. Potentially deferred to Phase-2a if hybrid-
  signature setup cost dwarfs the trait-dispatch overhead
  measurement, or if the bench fixture (a complete `TxToSign`
  with FCMP++ context) is structurally too heavy to set up at
  PR 3 cut-point. The fixture-construction work shares substrate
  with PR 5 (`PendingTxEngine`) and may land there instead.

The frozen baselines and cumulative-delta documentation pattern
established in PR 2's `docs/PERFORMANCE_BASELINE.md` extend to
PR 3; the post-PR-3 row count grows by 3–5 (one for
`account_public_address`, two for the `try_claim_output` split,
optionally one for `sign_transaction_resolve_handle` once Round 4
pins the table-shape, optionally one for `sign_transaction_full`).

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

### 6.6 Three-layer discipline for test-only additions (B1 disposition)

Test-only constructors and inspection accessors that exist on
production types must be **structurally inaccessible from
production code paths**. The discipline applies to
`LocalKeys::from_test_seed` (already named in §6.4),
`LocalKeys::handle_table_size` (introduced for §6.4 + §6.7),
and any future test-only addition to a production type.

**Layer 1 — `#[cfg(test)]` cfg-gate.** The symbol is gated on
`cfg(test)` so it does not exist in non-test compilation. This
is the strongest of the three layers: the symbol is literally
absent from the production binary's symbol table and cannot be
called even via dynamic-dispatch tricks. The gate is structural,
not conventional; rustc enforces it.

```rust
impl LocalKeys {
    /// Production constructor.
    pub fn from_seed(seed: &WalletSeed) -> Result<Self, KeyError> {
        // ...
    }

    /// Test-only constructor; deterministic seed derivation.
    /// The `test_label` argument feeds a deterministic
    /// derivation; any wallet derived from a test seed has
    /// publicly-derivable secret keys, which is acceptable in
    /// test scope and unacceptable in production scope.
    #[cfg(test)]
    pub(crate) fn from_test_seed(test_label: &str) -> Self {
        // ...
    }

    /// Test-only handle-table size accessor for orphan-absence
    /// and bounded-growth assertions in §6.4 / §6.7.
    #[cfg(test)]
    pub(crate) fn handle_table_size(&self) -> usize {
        // ...
    }
}
```

**Layer 2 — `pub(crate)` (or tighter) visibility.** Even in
test compilation, the symbol is reachable only from the same
crate's test code. A downstream test crate that depends on the
production crate cannot reach the symbol; this prevents the
test-only addition from accreting a downstream-test consumer
that constrains future evolution. `pub(crate)` is the typical
choice; `pub(super)` or unrestricted private (no `pub` modifier)
applies where tighter visibility is admissible.

**Layer 3 — CI gate.** A small CI step (an `xtask`, a
shell-grep on the build artifacts, or a `cargo-deny`-style
custom lint) asserts that test-only symbols do not appear in
non-`cfg(test)` reachable code. The exact mechanism is pinned
at PR 3 implementation time; the structural property is **the
gate exists, fails the build on violation, and runs on every
push to `dev`**. The gate is the residual defense against a
future maintainer accidentally widening Layer 1 (deleting the
`#[cfg(test)]`) or Layer 2 (widening `pub(crate)` to `pub`)
without noticing the consequence.

**Three layers, independent.** The discipline's strength is
that the layers are independent: if Layer 1 fails (the cfg-gate
is removed by accident or rebase mishap), Layer 2 still
prevents downstream-test reachability; if Layers 1 + 2 both
fail, Layer 3's CI gate catches the regression before merge.
Defense-in-depth at the code-review boundary; the cost is one
CI step plus a one-line cfg-gate per addition.

**Forward-template content for PR 4–7.** The discipline applies
to any per-trait PR that lands a test-only addition on a
production type. Per-trait PRs that don't need test-only
additions (the trait surface alone supports the test
correctness properties) skip the discipline; per-trait PRs
that do need them inherit the three-layer pattern. The default
when in doubt is **trait-surface-observable, not test-only-
observable**; the test-only addition is a fallback when the
trait-surface alternative would weaken the trait's contract
(see §3.1.5 Pattern-3).

### 6.7 Handle-storage hygiene (B2 disposition)

Pre-Round-3 framing said tests verify wipe-on-drop of secret
bytes that crossed the trait boundary (e.g., `OutputClaim`'s
`output_secret_key` field). Post-A1 (handle-indirected
workflow), no secrets cross the boundary; the orchestrator's
wipe discipline has nothing to protect. The test discipline
shifts to **handle-storage hygiene** — the post-A1 analog of
the pre-A1 wipe-on-drop discipline; both target the question
"does the engine retain state it shouldn't?" but the answer
relocates from boundary-crossing types to the workflow-internal
`HandleTable`.

**Three hygiene properties tested.**

1. **Orphan absence.** A failed `try_claim_output` call leaves
   the handle table size unchanged. Tested via
   `FaultInjecting<LocalKeys>` injecting a `KeyEngineError`
   variant before the impl reaches the handle-table insertion
   path; the test asserts `handle_table_size()` before == after.
   See §6.4 for the full test scenario.
2. **Entry deletion on consumption.** A successful
   `sign_transaction` call against a `TxToSign` whose inputs
   reference handles `H1`, `H2`, ..., `Hn` reduces the handle
   table size by `n`. Tested via setup
   (`try_claim_output` for `n` distinct outputs, asserting
   `handle_table_size() == n`), execution
   (`sign_transaction(&tx)` succeeds), and verification
   (`handle_table_size() == 0` post-call). Round 4's handle-
   persistence option-space disposition (§7.11) may refine this
   property — if persisted handles are retained across spend
   for audit purposes, the post-call size may not be zero
   immediately and the test refines accordingly.
3. **Bounded growth.** Repeated `try_claim_output` calls for
   the same output (idempotency) do not accumulate duplicate
   entries. Tested via repeated calls with identical input;
   the test asserts the table size grows by 1 (first call
   inserts, subsequent calls observe the existing entry) or by
   0 (subsequent calls are pure no-ops). The exact disposition
   (insert-once-then-no-op vs. error-on-duplicate) is a
   §7's Pattern-6 cluster (replay/idempotency) item; the test
   adapts to the chosen disposition.

**Test-substrate dependencies.** All three hygiene tests
require `handle_table_size()` (§6.6 B1 disposition, three-layer
protected). They also require `FaultInjecting<LocalKeys>` for
property (1). They do not require a `MockKeys` substitute; the
production `LocalKeys` impl runs authentic crypto, and the
test inputs are deterministic-seed-derived per §6.4.

**Trait-surface-observable vs. inspection-required.** The three
properties split:

- **Property (2)** is partially trait-surface-observable: a
  successful `sign_transaction` followed by a second
  `sign_transaction` against the same handles fails (the
  handles were consumed by the first call). The test-surface
  version of (2) catches "handles aren't consumed" failures
  but not "handles are consumed but the table grows" failures
  (e.g., a buggy impl that adds a "spent" entry instead of
  deleting); the inspection-required version
  (`handle_table_size`) catches both.
- **Properties (1) and (3)** are not trait-surface-observable
  in any meaningful way and require the inspection accessor.

The default discipline (§3.1.5 Pattern-3) is "trait-surface-
observable when possible"; for the handle-storage hygiene
properties, that default fails — the inspection accessor is
the load-bearing discipline, and the three-layer protection
(§6.6) is the structural defense against the test-only surface
leaking to production.

### 6.8 Docs propagation

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

**Closed for PR 3.** §2.1.2 names the broader rejection of
Mock-X parallel implementations; §6.4 lands the per-PR-3
substrate (no `MockKeys`; production-only
`LocalKeys::from_test_seed` + composable
`FaultInjecting<K: KeyEngine>` wrapper); §6.6 (commit 3d) pins
the three-layer discipline that protects the test-only
constructors and accessors; §2.1.5 (commit 3e) elevates the
no-Mock substrate shape to forward-template content for PR 4–7.

The cross-references for the surviving forward-looking work:

- **PR 4 / PR 5 substrate work** lands `MockLedger` →
  `LocalLedger::from_test_blocks` + `FaultInjecting<LocalLedger>`
  and `MockDaemon` → `TestDaemon` rename alongside their own
  trait-extraction work; see
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) for the explicit
  V3.0-baseline schedule.
- **PR 6 / PR 7 trait extractions** apply §2.1.5's four-pattern
  pre-flight checklist (Pattern 3 catches Mock-X regressions);
  the no-Mock pattern is the default substrate shape with no
  per-PR debate needed.

(L3.3)

### 7.10 Handle-table memory-pressure attack (A6)

**Round-4 disposition required.** A6 from Round 3's adversarial
pass. An adversary who can make the wallet scan a large block
range (broadcasting many crafted outputs that pass the X25519
pre-filter, or otherwise inflating the Mine-output count) can
force the workflow-internal `HandleTable` to grow without bound
between successful claims and eventual spends. Long-lived wallets
with infrequent spends accumulate handles indefinitely.

**Round-4 candidate dispositions:**

- **Hard size cap with eviction.** The table grows up to a
  configured cap; insertions past the cap evict according to a
  documented policy (LRU; orchestrator-pinned-vs-unpinned;
  persistence-aware aging). Eviction-policy choice itself is a
  Round-4 design question; the orchestrator's interaction with
  evicted handles (silent re-claim via re-scan? error variant?)
  affects the trait surface's `KeyEngineError` enumeration.
- **Backpressure / orchestrator-cooperative pruning.** The
  trait surface gains a method (`release_handle(OutputHandle)`
  or similar) that the orchestrator calls when an output is
  permanently spent or a wallet is closed. The table stays
  bounded by orchestrator discipline rather than internal
  policy.
- **Persistence-bounded growth.** If handle persistence ships
  as the disk-mapping option (per §7.11 below), the table's
  growth is bounded by available disk rather than memory.
  Memory-pressure becomes a non-issue at the cost of disk
  pressure and persistence-layer security discipline.

The disposition couples to §7.11 (handle persistence). Round 4
selects.

### 7.11 Handle persistence across wallet restart

**Round-4 disposition required.** Four option-space candidates
surfaced in Round 3 synthesis (option (2) splits into 2a / 2b
with structurally different trade-offs); PR 3's Round-3 lean is
**(1)** for V3.0 with explicit deferral of (2b) to V3.x as the
performance optimization when restart cost matters.

- **(1) Ephemeral handles, restart-rescan.** Wallet startup
  re-runs `try_claim_output` against persisted ciphertexts;
  rebuilds handle table from scratch. Operationally heavy at
  startup (linear in claim count: ~1 s for 10K outputs at
  ~100 µs/decap) but conceptually simple. No persistence-layer
  security boundary to get wrong. Cross-restart consistency is
  trivial because the table is rebuilt from scratch.
- **(2a) Persisted handle → ciphertext-pointer; secrets
  re-derived on demand.** Persists the handle table's index
  shape (handle → on-chain-ciphertext locator) but not the
  secret material; on resolution, the impl reads the locator,
  fetches the ciphertext, and re-runs decap to recover the
  secret. Restart skips the rescan but pays a per-spend
  decap cost; effectively (3) with a redirect step. Limited
  benefit over (3) given the doubled decap path is the same in
  both; the redirect adds storage complexity without
  proportionate benefit. Worth naming as a discrete option so
  Round 4 can reject it explicitly rather than leave it ambient.
- **(2b) Persisted handle → encrypted-secret-storage.**
  Persists the handle table with the per-output secrets
  encrypted under a key derived from the wallet password (or
  whatever wallet-encryption discipline lives in the
  persistence layer); on restart, after the user provides the
  password, decrypt the persisted secrets and load them into
  the in-memory table. **Cheap restart after password unlock
  with no re-scan and no doubled decap cost** — the
  optimization (1) and (3) both lack. Cost: persistence-layer
  complexity (encryption discipline; key-derivation
  consistency; on-disk format versioning); the table itself
  becomes a persistence-secret subject to the wallet-encryption
  invariants; cross-restart consistency requires wallet-
  encryption-key derivation to be deterministic across
  sessions. Most complex of the four options; delivers the
  strongest restart-cost property.
- **(3) Handle is deterministic from ciphertext.** `handle =
  HKDF(view_secret, "shekyl/output-handle-v1", ciphertext_hash)`.
  Stateless: no table; lookup at spend time = re-decap. Pays
  the decap cost twice (claim + spend) but the V3.0
  implementation is structurally cleanest. Memory-pressure
  attack (A6) is dissolved.

Round-3 lean: **(1)**. Reasoning: simplest correctness story
for V3.0; the ~1 s startup cost is acceptable for desktop and
server wallets; mobile wallets typically have fewer outputs and
constrained CPU but the bound stays operationally manageable.
**(2a)** introduces persistence-layer complexity without a
proportionate benefit over (3); probably rejected at Round 4.
**(2b)** delivers cheap restart but requires committing to
persistence-layer security discipline that PR 4–7 work has to
consume correctly — premature commitment for V3.0 but the
natural V3.x optimization when wallets accumulate enough
outputs that (1)'s startup cost matters. **(3)** is
structurally cleanest but doubles the per-output detection
cost, and the bench impact is direct (`_mine` bench absorbs the
decap-twice cost). Round 4 ratifies the Round-3 lean or
amends.

### 7.12 Handle unforgeability (A7)

**Round-4 disposition required.** A7 from Round 3's adversarial
pass. If handles are predictable (e.g., monotonic counter), an
attacker who can inject controlled outputs into the wallet's
scan stream might predict assigned handle IDs and reference them
in unrelated contexts (cross-engine references, cross-session
replay, etc.).

**Round-4 candidate dispositions:**

- **Counter-based handles** (8 bytes, monotonic per engine
  instance). Cheap; predictable; vulnerable to A7 unless the
  trait contract enforces "handle was issued by this engine
  instance" at resolution time (e.g., engine-instance ID bound
  into the handle).
- **UUID-based handles** (16 bytes; v4 random). Unpredictable;
  collision-resistant under birthday bound; standard library
  support. Probably the V3.0-proportional choice.
- **Cryptographic handles** (16 bytes from a CSPRNG, or HKDF-
  derived from view secret + per-handle nonce). Unforgeable
  under standard cryptographic assumptions; closes A7
  completely. Cost is similar to UUID at the storage-and-
  comparison level; the unforgeability property is structurally
  stronger.

Round-4 selects. The choice couples to §7.11's persistence
disposition: under (1), handle uniqueness only needs to hold per
session, so counter-with-engine-ID is sufficient. Under (2)/(3),
handles persist across sessions or are deterministic from
ciphertext, which constrains the choice differently.

### 7.13 Handle-table concurrency quality (Pattern-5 cluster)

**Round-4 disposition required.** Per Round 3 Pattern-5 cluster
(cross-call state correlation as side-channel). The handle
table's concurrent-access shape is interior mutability behind
the `&self` async trait surface. Side-channel observers can
infer table state changes by measuring response-time variance
(insertion vs no-op), lock-contention patterns, and cache-miss
patterns under concurrent load.

**Round-4 candidate dispositions:**

- **Sharded `RwLock<HashMap<...>>`.** Bounded contention; standard
  pattern; observable contention under sustained adversarial
  load.
- **Lock-free hashmap.** Higher complexity; lower contention
  observability; depends on a vetted dependency
  (`dashmap`, `crossbeam`, etc.).
- **Fair-queued single-writer.** Eliminates contention timing
  channels at the cost of per-call queue overhead. Useful if
  the hot-path is read-dominated (lookups during
  `sign_transaction`) with rare writes (insertions during
  `try_claim_output`).

Round-4 selects, with explicit timing-channel analysis under
concurrent-load benchmarks. The selection feeds the
`engine_trait_bench_key_sign_transaction_resolve_handle` bench's
expected cost regime.

### 7.14 Pattern-6 replay/idempotency contract (KeyEngine)

**Closed for PR 3.** §3.1.6 (commit 3e) lands the per-method
replay/idempotency contract table for KeyEngine's four trait
methods. Summary cross-reference for Round-4+ readers:

- `account_public_address` and `derive_subaddress`: pure
  reads / pure derivations; idempotent; no side effects;
  trivially safe to retry.
- `try_claim_output`: idempotent at the workflow level
  (subsequent calls observe the existing handle-table entry);
  inserts into `HandleTable` on first successful detection;
  safe to retry on transient errors (orphan absence per §6.7
  property (1)).
- `sign_transaction`: handle-consuming, **not** idempotent;
  replay is rejected at the trait surface via handle-resolution
  failure (consumed handles are gone from the table). Caller-
  driven retry semantics: distinguish "broadcast succeeded but
  acknowledgment lost" (no retry; rebuild with replacement
  inputs) from "signing failed before any state change" (retry
  admissible).

The `FaultInjecting<LocalKeys>` wrapper's interaction with the
contract — particularly the fault-injection point relative to
the impl's table-mutation — is pinned at PR 3 implementation
time. Round-4+ refines the wrapper's exact contract once the
implementation surface is concrete.

This entry is a closure cross-reference rather than an open
question; preserved here per `15-deletion-and-debt.mdc`'s
"items get a target version or get closed" rule. Listed under
§7 because the underlying property (replay/idempotency
contract) is a structural concern that Round-4+ readers
auditing the trait surface will look for here.

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

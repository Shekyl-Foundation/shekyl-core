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
| 0 | Hybrid-framework reconciliation (renames + signature changes) | Doc-only spec amendment | **Re-opens §7** |
| 0b | `KeyError` / `KeyEngineError` split | Doc-only spec amendment | **Re-opens §7** |
| 0c | Missing-type definitions (`AccountPublicAddress`, `SignDomain`, `SubaddressPublic`; spec renames for hybrid types) | Doc-only spec amendment | Additive |
| 0d | `pub(crate)` visibility + `Send + Sync + 'static` super-bound + Q9.3 disposition correction | Doc-only spec amendment | Additive |
| 0e (optional, code) | `AllKeysBlob` migrated to `#[derive(Zeroize, ZeroizeOnDrop)]` | Code PR in `shekyl-crypto-pq` | Out of §2.1 scope (precondition correction) |

§3 below names each bundle's substantive content. §5 names the
sequencing.

### 1.2 Phase 1 — implementation

Phase 1 lands the post-Phase-0d §2.1 trait surface and
parameterizes `Engine<S, D, L>` over a fourth type parameter
`K: KeyEngine`:

- **Trait surface.** `pub(crate) trait KeyEngine: Send + Sync +
  'static` with five methods (post-amendment shape in §4);
  declared in `rust/shekyl-engine-core/src/engine/traits/key.rs`,
  re-exported from `traits/mod.rs`.
- **Implementing aggregate.** `pub struct LocalKeys { keys:
  AllKeysBlob }` (or similar; precise wrapper shape pinned at
  commit time per PR 2's degrees-of-freedom precedent). Held as
  `keys: LocalKeys` on `Engine`'s state.
- **`Engine` parameterization.** `Engine<S, D: DaemonEngine =
  DaemonClient, L: LedgerEngine = LocalLedger, K: KeyEngine =
  LocalKeys>` extends PR 2's three-parameter shape.
  `OpenedEngine<S, D, L, K>` carries the same parameterization.
- **`async fn` for runtime ops.** `sign_with_spend`, `view_ecdh`,
  `hybrid_decapsulate` are `async fn` per Q9.1 (Stage-4-actor
  compatibility); pure-derivation methods stay sync.
- **Test substrate.** `MockKeys` + `replace_keys` mirror
  `MockLedger` + `replace_ledger` from PR 2. `MockKeys` queues
  `KeyEngineError` variants for failure injection.
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

### 3.1 Phase 0 — hybrid-framework reconciliation (§7-non-compliant, primary)

**Drift.** §2.1 names `sign_with_spend → Ed25519Signature` and
`ml_kem_decapsulate(MlKemEncapsulation) → MlKemSharedSecret`. Both
violate
[`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc)'s
"hybrid post-quantum is the default" rule: every classical
primitive ships alongside its lattice counterpart, and the
classical-only operation is V4 deletion debt today. The workspace
already has the hybrid-shaped types
(`shekyl-crypto-pq::signature::HybridSignature`, the
`HybridEd25519MlDsa` `SignatureScheme`, `HybridX25519MlKem` `Kem`,
`HybridCiphertext`, `SharedSecret(pub [u8; 64])`); the trait
surface should expose those, not their classical halves.

**Disposition.** **(i) Rewrite §2.1's surface to hybrid.** The
amendment changes `sign_with_spend → HybridSignature` and
`hybrid_decapsulate(HybridCiphertext) → SharedSecret`; the
classical types (`Ed25519Signature`, `EdwardsPoint`,
`MlKemEncapsulation`, `MlKemSharedSecret`) cease to appear at the
trait surface as a consequence.

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

> §2.1 was authored when the cryptographic abstractions were named
> in classical-primitive terms (`Ed25519Signature`,
> `ml_kem_decapsulate`); the workspace has since solidified
> hybrid-primitive types (`HybridSignature`, `HybridCiphertext`)
> per [`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc).
> This amendment reconciles §2.1 with the post-hybrid-framework
> reality. The trait's signatures change shape; the underlying
> capability ("produce a signature on this message") is unchanged.

### 3.1.1 Structural distinction: `view_ecdh` and `hybrid_decapsulate` are not redundant

A naive read of the post-amendment §2.1 surface might ask: "if
both `view_ecdh` and `hybrid_decapsulate` are part of the hybrid
output-decryption flow, isn't one of them redundant after the
hybrid-framework reconciliation?" The answer — and the reason both
methods stay at the trait surface — is structural. The pre-amendment
spec was naming two operations with one signature; that conflation
is itself the drift Phase 0 surfaces.

**The scanner's two-step output-detection pattern.** The actual
scanner code in
[`shekyl-crypto-pq::output::scan_output`](../../rust/shekyl-crypto-pq/src/output.rs)
(lines 297–317) reveals the structural shape:

- **Step 1 (`view_ecdh` analog).** Classical X25519 ECDH against
  the X25519 ephemeral from `HybridCiphertext.x25519`. Produces a
  32-byte raw shared secret. Used as input to view-tag derivation,
  which serves as a cheap pre-filter: most outputs aren't yours,
  view-tag mismatches reject them without doing the expensive PQC
  half.
- **Step 2 (`hybrid_decapsulate`).** Full hybrid KEM decap against
  the entire `HybridCiphertext`. Produces a 64-byte hybrid shared
  secret. Only runs for outputs that passed the step-1 view-tag
  check.

**Why both stay at the trait surface (recorded verbatim).**

> 1. **The two operations have different security-discipline
>    implications.** Step 1's 32-byte raw X25519 SS is not the
>    kind of secret that flows into long-term derivation; it's an
>    ephemeral computation feeding into a tag check. Step 2's
>    64-byte hybrid SS is a substantive secret that derives output
>    keys downstream. Type-distinguishing them at the trait surface
>    (different return types — `X25519SharedSecret` vs.
>    `SharedSecret`) signals the security-discipline distinction.
>    Collapsing them into one composite operation hides the
>    distinction from reviewers who'd otherwise see different types
>    and ask different questions.
>
> 2. **The trait surface should expose the operations, not the
>    orchestration.** The scanner's two-step pattern is a
>    performance optimization — most outputs aren't yours, so do
>    the cheap check first. That's scanner orchestration logic,
>    not key-engine internal logic. The key engine should expose
>    the primitives; the scanner composes them. A single
>    `scan_output_secrets(...)` method that returns both would
>    make the key engine responsible for the orchestration; future
>    implementors (HSM-backed, hardware-key) would have to
>    replicate the orchestration internally even if their
>    performance characteristics make the two-step optimization
>    unnecessary or counterproductive.
>
> 3. **"Lift `view_ecdh` out of the trait" doesn't actually work**
>    because the X25519 view secret is itself a secret the key
>    engine owns. The scanner can't do the X25519 pre-filter
>    "directly" without access to the view secret, which is
>    exactly what `KeyEngine` is supposed to encapsulate. The
>    view-tag pre-filter has to go through the key engine; the
>    question is just what shape the method takes.

**Amendment-block framing (to land in §2.1's "Stage 1 PR 3
spec-clarification" provenance subsection, alongside §3.1's hybrid
reconciliation prose).**

> The pre-amendment §2.1 named `view_ecdh` and `ml_kem_decapsulate`
> as parallel operations on the classical and PQC halves. The
> post-amendment §2.1 names `view_ecdh` (classical X25519 ECDH
> producing 32-byte raw shared secret, used as input to the
> view-tag pre-filter) and `hybrid_decapsulate` (full hybrid KEM
> decap producing 64-byte hybrid shared secret, used for full
> output-secret derivation). These are not redundant operations
> after the hybrid-framework reconciliation — they serve
> structurally different ends in the scanner's two-step
> output-detection pattern. The view-tag pre-filter rejects most
> outputs cheaply against the 32-byte raw SS; only outputs passing
> the tag check trigger the full hybrid decap.

**Round-2-confirm: `view_ecdh` parameter shape.** This draft uses
`eph_x25519: &[u8; 32]` rather than the prior round's
`tx_pub: &HybridPublicKey` text. The prior round's phrasing
carried a classical-Monero-model assumption that the X25519
component for ECDH lives in a signing-side public key. In the
hybrid framework, the X25519 ephemeral lives in
`HybridCiphertext.x25519` (the per-tx ephemeral packaged in the
KEM ciphertext, structurally analogous to classical
`tx_pub_key = r*G` in tx_extra); it has no relationship to a
signing key. The scanner's `scan_output` at lines 297–317 confirms
this — the X25519 ephemeral is sourced from `kem_ct_x25519`, not
from a signing public key. **Round 2 reviewer to confirm the
parameter shape;** if the alternative shape
`ciphertext: &HybridCiphertext` (pass the whole ciphertext, access
`.x25519` internally) is preferred for trait-surface consistency
with `hybrid_decapsulate`, the amendment lands that instead. The
narrower `&[u8; 32]` is preferred here because the trait method's
contract is "do X25519 ECDH against this ephemeral"; passing the
whole ciphertext when only one field is used misleads reviewers
about what the method depends on.

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

### 3.3 Phase 0c — missing-type definitions

**Drift.** §2.1's trait surface references 5 types that do not
exist in the workspace: `AccountPublicAddress`, `SignDomain`,
`SubaddressPublic`, `MlKemEncapsulation`, `MlKemSharedSecret`.
The latter two are spec-side names for already-existing workspace
types (`HybridCiphertext` and `SharedSecret`); the former three
need shape decisions.

**Disposition (per Decision 5).** Define the three missing types;
rename the spec to use the existing two.

| Type | Shape | Source / rationale |
|---|---|---|
| `AccountPublicAddress` | `pub struct AccountPublicAddress { pub pqc_public_key: [u8; PQC_PUBLIC_KEY_BYTES], pub classical_address_bytes: [u8; CLASSICAL_ADDRESS_BYTES] }` | Mirror `AllKeysBlob`'s public side. Keeps the type-pairing legible (private blob has a public counterpart with the same field structure); uses concrete sizes that match existing conventions; the 1216-byte ML-KEM PK + 65-byte classical address bytes shape is consistent with what ML-KEM-768 + the existing classical-address representation produces. |
| `SignDomain` | `#[non_exhaustive] pub enum SignDomain { OutputSecretDerivation, TransactionSignature, FcmpPlusPlusWitness, MlKemChallenge }` | Per Q9.2's `#[non_exhaustive]` disposition. Variants cover the substantive cases. **Binding-parameter framing:** `SignDomain` is what prevents cross-domain signature reuse — each call site asserts the domain it's signing in, and the trait verifies (via an internal `assert_sign_domain` mechanism) that the call's domain matches the key's authorized domains. Stage 4 adds multisig witness / partial signature variants additively without re-opening the trait per Q9.2. |
| `SubaddressPublic` | `pub struct SubaddressPublic { pub spend_pk: [u8; 32], pub view_pk: [u8; 32] }` | Standard Monero subaddress public-key pair; today's shape because subaddresses derive from the classical spend/view keys via standard Monero machinery. **PQC-augmented subaddresses are V3.x.** Worth being explicit in the amendment: PR 3's `SubaddressPublic` reflects the post-PR-3 implementation reality (classical-derived subaddresses); the PQC-augmented subaddress shape is a V3.x design open question and lands as an additive `SubaddressPublic` extension when designed. |
| `MlKemEncapsulation` (spec name) | Reuse existing `shekyl-crypto-pq::kem::HybridCiphertext` | Spec was inventing a name for a type that already exists. Rename in the amendment. |
| `MlKemSharedSecret` (spec name) | Reuse existing `shekyl-crypto-pq::kem::SharedSecret` (64-byte hybrid combined secret) | Same. The 64-byte hybrid shared secret is what `HybridX25519MlKem::decapsulate` produces. Used as the post-decap return type for `hybrid_decapsulate`. |
| `HybridSignature` (existing, cite) | Reuse existing `shekyl-crypto-pq::signature::HybridSignature` | The post-Phase-0 return type for `sign_with_spend`. Already exists in the workspace; the amendment cites the existing path rather than re-introducing a name. |
| `X25519SharedSecret` (**net-new**) | `pub struct X25519SharedSecret(pub [u8; 32])` with `#[derive(Zeroize, ZeroizeOnDrop)]` | Confirmed via grep that no existing 32-byte raw-ECDH-output newtype exists in `shekyl-crypto-pq::kem` (the workspace currently uses raw `MontgomeryPoint` and accesses `.0` for `[u8; 32]` inline at scanner call sites). Introduced to type the 32-byte raw X25519 shared secret returned by `view_ecdh`'s step-1 view-tag pre-filter; structurally distinct from `SharedSecret([u8; 64])` (full hybrid combined secret used by `hybrid_decapsulate`). The newtype carries its security-discipline anchor in its type — reviewers seeing two distinct return types at the trait surface ask different questions about each per §3.1.1's structural-distinction framing. |

**Reuse note — `HybridPublicKey` and `HybridKemPublicKey`.** Both
types exist in the workspace
([`shekyl-crypto-pq::signature::HybridPublicKey`](../../rust/shekyl-crypto-pq/src/signature.rs)
for Ed25519+ML-DSA-65 signing,
[`shekyl-crypto-pq::kem::HybridKemPublicKey`](../../rust/shekyl-crypto-pq/src/kem.rs)
for X25519+ML-KEM-768 KEM). **Neither appears in the post-amendment
§2.1 trait surface.** `HybridSignature` is the trait-surface return
type for `sign_with_spend`; `HybridCiphertext` is the parameter
for `hybrid_decapsulate`; `view_ecdh` takes `&[u8; 32]` (the X25519
ephemeral component sourced from `HybridCiphertext.x25519` at the
call site, not a hybrid public key). Reviewers asking "why doesn't
the trait surface name `HybridPublicKey` or `HybridKemPublicKey`?"
find the answer in §3.1.1's structural-distinction subsection
above.

The cascading consequence of Phase 0's hybrid rewrite is that
`Ed25519Signature` and `EdwardsPoint` references vanish from the
trait surface (Phase 0 uses `HybridSignature` and the hybrid
encapsulation type instead). The amendment block records this as
a Phase-0-consequence, not a separate decision.

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
pub(crate) trait KeyEngine: Send + Sync + 'static {
    type Error: Into<KeyEngineError>;

    /// Public address material for this engine's account. Cheap;
    /// does not touch secrets. Stable for the wallet's lifetime.
    fn account_public_address(&self) -> &AccountPublicAddress;

    /// Hybrid-sign an Ed25519+ML-DSA-65 challenge with the spend
    /// secret. The `domain` argument selects the HKDF context
    /// (output-secret derivation, transaction signature, FCMP++
    /// witness, ML-KEM challenge) so this trait cannot be coerced
    /// into a generic signing oracle. Returns the workspace's
    /// hybrid signature type, not the classical Ed25519 half.
    async fn sign_with_spend(
        &self,
        domain: SignDomain,
        message: &[u8],
    ) -> Result<HybridSignature, Self::Error>;

    /// ECDH against the X25519 ephemeral from a hybrid ciphertext.
    /// Caller passes `HybridCiphertext.x25519`; the trait is
    /// structurally accepting `&[u8; 32]` because step-1 view-tag
    /// pre-filtering doesn't need the ML-KEM half. Returns the
    /// 32-byte raw shared secret used as input to view-tag
    /// derivation. For full output-secret derivation, see
    /// [`KeyEngine::hybrid_decapsulate`]. The parameter is not a
    /// generic "any 32 bytes" — it is specifically the X25519
    /// component sourced from a hybrid ciphertext at the call site;
    /// passing arbitrary 32 bytes (e.g., from outside the scanner's
    /// source-correct extraction) would produce a meaningless
    /// shared secret. See §3.1.1 for the structural rationale that
    /// keeps `view_ecdh` and `hybrid_decapsulate` as distinct
    /// trait-surface methods rather than collapsing them.
    async fn view_ecdh(
        &self,
        eph_x25519: &[u8; 32],
    ) -> Result<X25519SharedSecret, Self::Error>;

    /// Hybrid X25519+ML-KEM-768 decapsulate against an incoming
    /// output's hybrid encapsulation. Returns the 64-byte hybrid
    /// shared secret only; the decap key itself does not leave
    /// the implementor.
    async fn hybrid_decapsulate(
        &self,
        ciphertext: &HybridCiphertext,
    ) -> Result<SharedSecret, Self::Error>;

    /// Derive a subaddress public-key pair. At today's surface
    /// this is pure derivation: reads the view secret, produces
    /// only public material, and the classical spend/view
    /// subaddress derivation has no concrete failure mode (the
    /// classical path's only failure modes are RNG-failure-class
    /// events, essentially impossible during pure derivation from
    /// existing key material). The `Result<...>` shape is reserved
    /// for the V3.x PQC-augmented subaddress extension, where the
    /// hybrid derivation path can fail with non-negligible
    /// probability in ways the classical path cannot (e.g.,
    /// ML-KEM keypair derivation has a defined failure surface).
    /// Trait stability across the V3.x extension is the rationale
    /// for the `Result` shape now.
    fn derive_subaddress_public(
        &self,
        index: SubaddressIndex,
    ) -> Result<SubaddressPublic, Self::Error>;
}
```

Notable changes vs. the pre-amendment shape:

- **`pub(crate)` not `pub`** (Phase 0d).
- **`: Send + Sync + 'static` super-bound** (Phase 0d).
- **`type Error: Into<KeyEngineError>`** instead of `Into<KeyError>` (Phase 0b).
- **`HybridSignature`** instead of `Ed25519Signature` (Phase 0).
- **`view_ecdh` takes `&[u8; 32]`** (the X25519 ephemeral sourced
  from `HybridCiphertext.x25519` at the call site) instead of
  `&EdwardsPoint` (Phase 0); returns the new 32-byte
  `X25519SharedSecret` newtype rather than the 64-byte
  `SharedSecret`. See §3.1.1 for the structural distinction
  rationale (the pre-amendment spec named two operations with one
  return type; that conflation is itself the drift).
- **`hybrid_decapsulate(HybridCiphertext)`** instead of
  `ml_kem_decapsulate(MlKemEncapsulation)` (Phase 0); returns the
  64-byte hybrid `SharedSecret`.
- **Two distinct shared-secret return types** at the trait
  surface: `X25519SharedSecret` (32-byte, from `view_ecdh`'s
  step-1 pre-filter) and `SharedSecret` (64-byte hybrid combined
  secret, from `hybrid_decapsulate`'s step-2 full decap). The
  type distinction signals the security-discipline distinction
  per §3.1.1.
- **`AccountPublicAddress`** is concretely shaped (Phase 0c).
- **`SubaddressPublic`** is concretely shaped (Phase 0c).
- **`SignDomain`** is concretely enumerated (Phase 0c).

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
2. `LocalKeys` implementing aggregate.
3. `Engine<S, D, L, K>` parameterization.
4. Migrate consumers from `engine.keys` direct field access to
   `K: KeyEngine` trait dispatch.
5. `MockKeys` test substrate + `replace_keys` `#[cfg(test)]`
   helper.
6. Hybrid test exercising one §5.2 property predecessors haven't
   covered (selection per §6.4).
7. Benchmark harness for one `KeyEngine` hot-path method
   (selection per §6.5).
8. Docs propagation (this design doc's realignment + CHANGELOG
   entry + `V3_ENGINE_TRAIT_BOUNDARIES.md` post-PR-3 cross-anchor
   updates).

The synchronous wrappers question (PR 2's `Engine::refresh` /
`refresh_with` `LocalLedger`-specialized impl block) does not
apply to PR 3 — `KeyEngine`'s sync methods stay sync; its async
methods are async — there are no `LocalKeys`-specialized synchronous
entry points to retain.

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

### 6.4 Hybrid test (one §5.2 property)

PR 3 exercises **(a) layered-call error preservation** — a runtime
key-op error injected through `MockKeys` propagates through
`Engine<S>`'s wallet-level methods with the error variant intact
and the layered-call structure preserved.

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
on the framing that `KeyEngine`'s `sign_with_spend` is the first
per-trait PR where dropping a future before completion has
observable trait-shape implications. That framing assumed
cancel-class verification has observable trait-shape implications
specific to `KeyEngine`, but two questions undermine the
assumption: (1) what residual state could a dropped
`sign_with_spend` future leave that the next call could observe?
`KeyEngine` is `&self` async; the future captures `&self` and any
local state. If the future is dropped mid-await, the local state
is dropped too; `&self` is unchanged from the caller's perspective.
(2) If there is residual state in some future implementation
(e.g., HKDF context state; intermediate scalar arithmetic state in
a hardware-key implementation), is the test exercising current
`LocalKeys` behavior or future-implementor behavior? If the latter,
the test is exercising a property that isn't yet observable.
Layered-call error preservation has concrete observable behavior
at PR 3 cut-point; cancel-class verification doesn't, and is
deferred to a future per-trait PR whose pre-flight surfaces a
concrete observable-residual story.

### 6.5 Benchmark harness

Mirrors PR 2's `engine_trait_bench_ledger_balance` /
`engine_trait_bench_ledger_synced_height` pair:

- `engine_trait_bench_key_account_public_address` — sync,
  infallible-read hot path; `LedgerEngine`'s `synced_height` is
  the structural analog.
- `engine_trait_bench_key_sign_with_spend` (async hot path) —
  potentially deferred to Phase-2a if hybrid-signature setup cost
  dwarfs the trait-dispatch overhead measurement.

The frozen baselines and cumulative-delta documentation pattern
established in PR 2's `docs/PERFORMANCE_BASELINE.md` extend to
PR 3; the post-PR-3 row count grows by 1–2.

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
  - Any Round-2+ deferred items.

---

## 7. Open questions (Round 2+)

### 7.1 §5.2 property selection for the hybrid test

§6.4 above leans (b); Round 2 reviewer challenges welcome.

### 7.2 `KeyEngineError` starter shape

Empty per §3.2 and PR 2's `LedgerError` precedent. Round 2
reviewer may surface concrete variants worth seeding.

### 7.3 `LocalKeys` wrapper shape

Several viable shapes (`LocalKeys(AllKeysBlob)` newtype;
`LocalKeys { keys: AllKeysBlob }` struct; `LocalKeys(Box<AllKeysBlob>)`
boxed; etc.). Pinned at commit time per PR 2's degrees-of-freedom
precedent. The `mlock` discipline noted in
[`35-secure-memory.mdc:55–60`](../../.cursor/rules/35-secure-memory.mdc)
makes `Box<AllKeysBlob>` an interesting candidate (lives on heap,
amenable to `mlock` on a single allocation).

### 7.4 Cross-trait error type

Per §3.2's negative-space framing, the cross-trait runtime error
candidate (concurrent key rotation invalidating an in-progress
signing attempt) doesn't have a concrete trigger at PR 3 cut-point.
If Round 2 surfaces a concrete trigger, the design doc adds a
Phase-0f for the cross-trait error type.

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

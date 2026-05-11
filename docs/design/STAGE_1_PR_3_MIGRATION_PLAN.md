# Stage 1 PR 3 — Migration Plan

**Status.** Operational plan for the Stage 1 PR 3 architectural-inheritance
migration (M3a–M3e). Companion document to
`STAGE_1_PR_3_KEY_ENGINE.md` (design rationale) and
`STAGE_1_PR_3_MIGRATION_AUDIT.md` (workspace surface audit).
**Scope.** Operational details — per-PR scope, dependencies, schema
state at each PR boundary, success criteria, sequencing, and freeze
semantics. Architectural rationale lives in `STAGE_1_PR_3_KEY_ENGINE.md`;
substantive findings live in `STAGE_1_PR_3_MIGRATION_AUDIT.md`. This
document does not re-litigate either; it sequences their consequences.
**Anchored by.** `.cursor/rules/16-architectural-inheritance.mdc` (the
discipline rule that produced this migration).

---

## Label disambiguation

This document and the audit (`STAGE_1_PR_3_MIGRATION_AUDIT.md`) refer to
the migration's five PRs as **M3a, M3b, M3c, M3d, M3e** (the "M" prefix
denotes migration). The forward-looking PRs themselves will land on
`dev` from short-lived feature branches when drafting begins.

This naming avoids a collision with the design-document Round 3 commit
sub-series (commits `3a`–`3e` on the
`chore/spec-stage-1-pr3-keyengine-round` branch, which produced
`STAGE_1_PR_3_KEY_ENGINE.md` Round 3). Those sub-commits are landed
history on the design-doc branch; the M-labels denote forward-looking
migration PRs. Future references should use `M3a`/`M3b`/… for the
migration PRs and `Round 3 commit 3a`/`Round 3 commit 3b`/… (or the
commit SHA) when referring to the design-doc commits.

The broader project-level identifier "PR 3" (the `KeyEngine` per-trait
extraction effort, of which this migration is a component) is unchanged
and refers to the umbrella work covered by `STAGE_1_PR_3_KEY_ENGINE.md`.

---

## 🔒 FREEZE NOTICE

> **`dev` branch is frozen for non-migration work for the duration of
> M3a–M3e.** Per `06-branching.mdc` discipline against long-lived
> feature branches, the migration sequences as short-lived PRs landing
> on `dev` directly, but each PR's review and merge expects a stable
> base. Non-migration commits to `dev` during the freeze window
> introduce dev-drift across an open multi-PR series and risk
> rebase/conflict cascades.
>
> **What is gated.** New features, refactors, dependency bumps, and
> documentation updates outside the migration plan's scope.
>
> **What is exempt.** Critical security fixes, CI infrastructure
> repairs, and explicitly-coordinated work that the migration plan
> annotates as compatible.
>
> **Freeze duration.** Two estimates, with contingency:
>
> - **Best-case: 5–7 working days.** Assumes each PR lands without
>   review-cycle blockers, no pre-flight findings expand scope, and
>   the M3b source-switch surfaces no unexpected refactor concerns.
>   This is the floor of the discipline ceiling in `06-branching.mdc`'s
>   short-lived-branch target, not a likely outcome.
> - **Realistic: 8–12 working days.** Assumes one PR surfaces an
>   unexpected concern during pre-flight or review (a not-uncommon
>   experience across Stage 1 — PR 2's review cycle ran multiple
>   weeks). Sized for the migration to absorb one substantive blocker
>   without invalidating the freeze.
>
> **Per-PR contingency.** If any single PR is blocked beyond
> 5 working days from open to merge, the migration plan re-evaluates
> at that PR's blocker boundary: pause and assess (drop the freeze,
> let other work proceed while the blocker is resolved) versus
> continue (extend the freeze with a documented justification). The
> default disposition at the threshold is pause-and-assess; continuing
> requires explicit rationale captured in the assessment note.
>
> Updated as PRs land. Headline duration in this notice tracks the
> realistic estimate; the best-case is recorded for reference.
>
> **Lift condition.** M3d merges (the property-activating PR);
> M3e is doc-only and can land in parallel with the freeze lift.

---

## §1 Scope summary

### §1.0 Framing: continuity of discipline

This migration extends a discipline already operative elsewhere in
the codebase rather than introducing a new one. `rust/shekyl-oxide/`
is the artifact of Shekyl's discipline applied to upstream
proof-system code: legacy proof types (MLSAG, Borromean, CLSAG)
removed; FCMP++ and PQC primitives added; `#![deny(unsafe_code)]`
enforced across the vendored crates; release blockers tracked per
`SHEKYL_READINESS.md`. The vendored subset is deliberately scoped
(proof primitives, transaction wire format, RPC shim); wallet-side
state is not vendored.

The wallet-side state in `shekyl-core` was ported from C++
`wallet2.h::struct transfer_details` without the same discipline pass.
`TransferDetails`'s secret-bearing fields are the residue of that
direct port. This migration applies the discipline already operative
in `shekyl-oxide` to wallet-side state — the same architectural-inheritance
disposition (`16-architectural-inheritance.mdc`) the
`shekyl-oxide` rebuild applied to upstream proof-system code,
applied retroactively to the part of the codebase where it hadn't
been applied yet.

This framing matters for two reasons. (1) It rules out the "we are
fixing inherited code in isolation" misreading: the migration is a
continuity-of-discipline operation, not novel surface work. (2) It
sets a forward expectation: per-trait PRs 4–7 will likely surface
similar continuity-of-discipline opportunities, where wallet-side
state ported from C++ benefits from the same discipline already
operative in vendored proof-system surfaces. The architectural-inheritance
check during pre-flight investigations should ask
"is this the C++-port residue or the discipline-already-applied
shape?" and apply the rule accordingly.

### §1.1 In scope

- Introduction of the `KeyEngine` trait and the `LocalKeys` bridge
  implementation (M3a).
- Reroute of the scanner's secret-emit path from
  `TransferDetails` write to `KeyEngine::try_claim_output` (M3b).
- Bridge-implementation secret-source switch from
  `TransferDetails` legacy fields to the deterministic handle path
  (re-derive spend material from `(view_secret, source_ciphertext)`
  per design doc §7.12); legacy fields retained as transitional
  fallback (M3b). Adds `source_ciphertext` and `output_handle` to
  the `TransferDetails` schema at M3b so the primary path is
  functional from M3b.
- Additive end-to-end test caller validating
  `KeyEngine::sign_transaction` produces byte-identical output to
  the legacy direct-secret path (M3c).
- Removal of legacy secret-bearing fields from `TransferDetails`;
  removal of bridge-impl fallback (M3d).
- Documentation realignment across `STAGE_1_PR_3_KEY_ENGINE.md`,
  `STAGE_1_PR_3_MIGRATION_AUDIT.md`, `CHANGELOG.md`, and
  `docs/FOLLOWUPS.md` (M3e).

### §1.2 Out of scope

- Migration of any wallet2-bridged code path. All such paths are
  enumerated in `STAGE_1_PR_3_MIGRATION_AUDIT.md` §3 as deletion
  targets at the wallet RPC server cutover (separate workstream;
  V3.2 per `15-deletion-and-debt.mdc` and `docs/FOLLOWUPS.md` §V3.1).
- Migration of the C++ `wallet2::transfer_details` consumers. Tracked
  separately in `docs/FOLLOWUPS.md` §V3.0 line 755; superseded by the
  wallet RPC cutover.
- Stage 2 `KeyEngine` actor migration (V3.1+). Tracked in
  `docs/FOLLOWUPS.md` §V3.1 line 259; depends on this migration's
  property delivery being settled.
- v31 multisig migration. Audit §4 confirmed structural alignment;
  no concurrent migration required.

---

## §2 Excluded sites

| # | Site | Class | Deletion vehicle | Tracked in |
|---|---|---|---|---|
| 1 | `rust/shekyl-ffi/src/lib.rs:3127, 3305, 3331` | wallet2 FFI export (signing) | Wallet RPC server cutover (V3.2) | `FOLLOWUPS.md` §V3.0 line 755; §V3.1 wallet_rpc_server entries |
| 2 | `rust/shekyl-engine-rpc/src/engine.rs:388–479` (`transfer_native`, `native-sign` feature) | wallet2-bridged transitional Rust path | Wallet RPC server cutover (V3.2) | Same as #1 |
| 3 | `src/wallet/wallet2*` (C++ secret handling) | Out-of-`shekyl-core` scope | Wallet RPC server cutover (V3.2) | `FOLLOWUPS.md` §V3.0 line 755 |

The migration is not blocked by the cutover and the cutover removes
paths the migration deliberately does not touch. The two workstreams
are independent and complementary.

The `transfer_native` exclusion (row 2) is per the architectural-inheritance
rule's "inherited code with a deletion target doesn't get
migrated; it gets deleted" disposition (`16-architectural-inheritance.mdc`
§"When to migrate vs. when to keep"). Migrating `transfer_native`
would mean migrating a path whose only forward state is deletion.

---

## §3 Per-PR specifications

### §3.1 M3a — trait + bridge impl + engine-internal SpendInput

**Title.** `feat(engine): introduce KeyEngine trait and LocalKeys bridge impl`

**Pre-flight investigation (closed; M3a feat branch cleared to
cut).** M3a pre-flight closed the four open dispositions Round 4
deliberately deferred — the handle-model emergent attack surface
that Round 3 surfaced. Resolutions:

- **§7.11 (handle persistence across wallet restart) = option (3)
  deterministic from ciphertext.** Handle is
  `cSHAKE256(view_secret || tx_hash || output_index_le_bytes(8))`
  with customization `"shekyl/output-handle-v1"`, 16-byte output.
  Round-3 lean toward (1) ephemeral amended; the four-question
  coupled cluster (§7.10 / §7.12 / §7.13) collapses from this one
  disposition per the structural-reduction analysis in
  `STAGE_1_PR_3_KEY_ENGINE.md` §7.11. (2a) rejected; (2b)
  deferred to V3.x as performance-optimization candidate.
- **§7.12 (handle unforgeability / A7) = cSHAKE256-based
  deterministic derivation.** A7 closes by construction:
  cSHAKE256 with `view_secret` in the input phase is a PRF in
  `view_secret` (standard assumption); cross-engine references
  and predicted-handle injection attacks are foreclosed.
  Implementation crate: `sha3 = "0.10"` (already a workspace dep
  via `shekyl-crypto-pq`) with the `zeroize` feature flag
  enabled, giving `Sha3State` wipe-on-drop discipline structurally
  per `35-secure-memory.mdc`. `tiny-keccak` rejected on
  memory-wipe grounds (private `KeccakState`; no `Zeroize` impl;
  no public reset path). See design doc §7.12 for full closure.
- **§7.10 (handle-table memory-pressure / A6) = dissolved by
  §7.11=(3).** No table; no growth target; no eviction policy;
  no `release_handle` trait method; no `KeyEngineError` variant
  for evicted-handle resolution.
- **§7.13 (handle-table concurrency quality / Pattern-5 cluster)
  = dissolved by §7.11=(3).** No shared mutable state; pure
  per-call sponge-state mutation only; no concurrent-access
  shape to choose; no contention-timing side channel.

The closures land as a single commit on `dev` (parent of M3a's
feat branch). Per
[`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)'s
4–6-rounds-before-implementation rule for crypto-critical trait
migrations, the pre-flight investigation discharges the
round-budget work the migration plan deliberately separates from
Round-4 planning artifacts so each PR's review surface stays
bounded. M3a is now cleared to cut its feat branch.

**Scope.**

- Define `KeyEngine` trait in `shekyl-engine-core/src/engine/traits/key.rs`
  per `STAGE_1_PR_3_KEY_ENGINE.md` Round 3 surface — the four
  workflow-shaped methods `account_public_address`,
  `derive_subaddress`, `try_claim_output`, and `sign_transaction`
  (per the design doc's §6 trait-surface IDL and the supporting
  message shapes in §0c Sub-bundle B).
- Implement `LocalKeys` (production-only, `from_seed` /
  `#[cfg(test)] from_test_seed` constructors per the no-Mock pattern
  from `KEY_ENGINE.md` §2.1.2).
- Implement engine-internal `SpendInput` construction inside
  `LocalKeys::sign_transaction`. Bridge sources secrets from
  `TransferDetails`'s existing secret-bearing fields (transitional;
  M3b switches the source via the deterministic-handle pathway).
- **No `HandleTable` data structure.** Per `STAGE_1_PR_3_KEY_ENGINE.md`
  §7.11=(3) and §7.13's dissolution, the engine holds no
  handle-table state; `try_claim_output` returns the deterministic
  handle directly, and `sign_transaction` re-derives spending
  material from `(view_secret, source_ciphertext)` at the
  input-resolution step. No concurrent-access primitive, no
  eviction policy, no `release_handle` method, no
  `HandleNotFound` `KeyEngineError` variant.
- Introduce `OutputHandle` newtype (`[u8; 16]` wrapper) and
  `derive_output_handle` pure function per
  `STAGE_1_PR_3_KEY_ENGINE.md` §7.12: cSHAKE256 over
  `view_secret || tx_hash || output_index_le_bytes(8)` with
  customization `"shekyl/output-handle-v1"`, 16-byte output.
  Crate: `sha3 = "0.10"` with the `zeroize` feature flag enabled
  on the `shekyl-crypto-pq` import; the customization string is a
  named constant (`OUTPUT_HANDLE_CUSTOMIZATION` or
  `OUTPUT_HANDLE_DOMAIN_SEP`) per the SP 800-185 vocabulary
  matching note in design doc §7.12.
- **No memory-pressure bound required.** Per
  `STAGE_1_PR_3_KEY_ENGINE.md` §7.10's dissolution, A6's attack
  surface (cross-call accumulation in an unbounded handle table)
  has no target; per-call decap state remains stack-frame
  bounded and wiped per `35-secure-memory.mdc`'s
  structural-memwipe rule.
- v31 multisig pre-flight verification: confirm the audit's §4
  structural-alignment finding still holds at HEAD; produce a
  one-line confirmation comment in the PR description.
- Initial test substrate: unit tests for `LocalKeys::from_test_seed`
  determinism; `derive_output_handle` known-answer tests
  (cross-language reproducible vectors covering several
  `(view_secret, tx_hash, output_index)` triples);
  cross-input-divergence tests (different `view_secret` /
  `tx_hash` / `output_index` produce distinct handles);
  customization-bump versioning test (`v1` vs. hypothetical `v2`
  customization strings produce distinct handles for the same
  other-inputs); view-secret wipe-on-drop smoke test confirming
  the `Sha3State` `Zeroize` feature is wired correctly at the
  workspace dep level.

**Files touched (estimated).**

- New: `rust/shekyl-engine-core/src/engine/traits/key.rs` (~300 lines).
- New: `rust/shekyl-engine-core/src/engine/local_keys.rs` (~400 lines
  including impl + tests; no handle-table management).
- New: `rust/shekyl-engine-core/src/engine/handle.rs` (~80 lines:
  `OutputHandle` newtype + `derive_output_handle` pure function +
  customization-string constant).
- Edit: `rust/shekyl-engine-core/src/engine/mod.rs` (re-exports).
- Edit: `rust/shekyl-crypto-pq/Cargo.toml` (enable `zeroize`
  feature flag on the `sha3` direct dep so `Sha3State`'s
  `Zeroize + ZeroizeOnDrop` impls are available downstream).
- New: `rust/shekyl-engine-core/tests/key_engine_unit.rs` (~150
  lines).

**Dependencies.** None (foundation PR).

**Schema state at PR boundary.** `TransferDetails` unchanged. Bridge
impl reads secrets from `TransferDetails`'s existing fields.

**Property delivery.** None directly. M3a is the architectural
foundation against which the "secrets confined to engine" property
activates at M3d. Specifically, M3a establishes:

- The `KeyEngine` trait surface that the property eventually
  attaches to (the boundary across which secrets do not flow once
  the property is live).
- The deterministic `OutputHandle` derivation (`derive_output_handle`
  per design doc §7.12) — the stateless shape that replaces a
  cached handle table by re-decapping at spend time. The runtime
  state the property eventually attaches to is the
  engine-internal long-term key material; no per-output cache.
- The production-only discipline (no Mock-X; bridge impl is real
  code reading real secrets from existing fields) that the
  property's implementation respects.
- The test substrate (`derive_output_handle` known-answer
  reproducibility, view-secret wipe-on-drop, byte-identical
  signing) against which M3b/M3c/M3d validate the property's
  behavior.

The property does not activate until M3d removes the
`TransferDetails` secret fields. M3a is what makes that activation
possible.

**Success criteria.**

- Workspace compiles; existing tests green.
- `LocalKeys` production-only (`#[cfg(not(test))]` paths exclude any
  test-only constructor).
- `derive_output_handle` known-answer tests pass against
  cross-language-reproducible vectors (the same
  `(view_secret, tx_hash, output_index)` triple produces the
  documented 16-byte output across implementations).
- View-secret wipe-on-drop wired correctly at the workspace dep
  level: `sha3 = "0.10"` is configured with the `zeroize` feature
  on `shekyl-crypto-pq`'s direct dep so downstream `Sha3State`
  use inherits `Zeroize + ZeroizeOnDrop`. A smoke test confirms
  the feature is active (a compilation check that
  `Sha3State: Zeroize` is satisfied; not a re-implementation of
  the test that lives in `sha3`'s own test suite).
- v31 multisig pre-flight comment in PR description.
- No public API change to existing crates outside
  `shekyl-engine-core`.

**Estimated review surface.** ~900 lines added; zero deleted; ~6
files edited including re-exports and the `Cargo.toml` feature
flip.

#### Landing notes (M3a closed)

M3a landed on `feat/stage-1-pr3-m3a` as six commits and diverged
from the estimate above in three structural ways. Each divergence
is recorded against the discipline that drove it.

**Sub-commit breakdown.**

1. *`crypto-pq: enable sha3 zeroize feature for cSHAKE256 wipe-on-drop`*
   — direct-dep `Cargo.toml` change wiring `Sha3State`'s `Zeroize`
   impl into the `shekyl-crypto-pq` build graph. Pre-cursor for
   sub-commit 2.
2. *`crypto-pq: add OutputHandle and ViewSecret newtypes (cSHAKE256, §7.12)`*
   — `OutputHandle` newtype, `ViewSecret` newtype (`#[repr(transparent)]`,
   FFI-layout-stable with `shekyl_ffi::ShekylAllKeysBlob.view_sk`),
   `derive_output_handle` cSHAKE256 derivation per §7.12 with locked
   reference vectors.
3. *`engine: introduce KeyEngine trait surface and KeyImage newtype (M3a §4)`*
   — `KeyEngine` trait surface in `shekyl-engine-core/src/engine/traits/key.rs`,
   supporting message types (`AccountPublicAddress`, `OutputDetectionInput`,
   `OutputClaim`, `OutputClaimResult`, `SubaddressFor`, `SubaddressPurpose`,
   `SubaddressKeyPair`, `RecipientSubaddress`, `TxInputSigningContext`,
   `SourceSecretsBundle`, `TxToSign`/`TxOutputContext`/
   `FcmpPlusPlusContext`, `TxSignatures`, `TxInputSignature`,
   `FcmpPlusPlusWitness`, `ViewTag`), `KeyEngineError` (empty
   `#[non_exhaustive]` starter shape), and the `KeyImage` newtype
   in `shekyl-crypto-pq::key_image`.
4. *`crypto-pq: relocate subaddress derivation from shekyl-scanner (M3a §6.4)`*
   — classical Edwards-curve subaddress derivation (`subaddress_derivation_scalar`,
   `subaddress_keys`) relocated from `shekyl-scanner` to
   `shekyl-crypto-pq::subaddress`; `SubaddressIndex::to_canonical_bytes`
   accessor and `PRIMARY` constant added; `ViewPair::subaddress_keys`
   converted to a thin call-through.
5. *`engine: implement LocalKeys (M3a §4.1, KeyEngine in-process actor)`*
   — `LocalKeys` struct (private `AllKeysBlob`, cached
   `AccountPublicAddress`, pre-computed `DerivedScalars`, `RwLock`-guarded
   subaddress registry); production constructor `from_keys_blob`
   and `#[cfg(test)] from_test_seed`; real implementations of
   `account_public_address`, `derive_subaddress(_, Audit)`, and
   `try_claim_output`; named-infrastructure-gap stubs for
   `derive_subaddress(_, Recipient)` and `sign_transaction` with
   their `KeyEngineError` variants
   (`RecipientSubaddressKemKeygenNotImplemented`,
   `SignTransactionTraitSurfaceIncomplete`); 11 unit / integration
   tests including end-to-end claim paths driven by
   `construct_output`.
6. *`docs: M3a landing realignment (PR-3 Commit 5)`* — this commit.

**Divergence 1 — `OutputHandle` placement.** Plan estimate said
new `rust/shekyl-engine-core/src/engine/handle.rs` (~80 lines).
Actual: `OutputHandle` and `derive_output_handle` live in
`rust/shekyl-crypto-pq/src/handle.rs`. The placement decision was
driven by `.cursor/rules/18-type-placement.mdc`'s
transform-vs-state classification: `OutputHandle` is
**transform-shaped** (defined by `derive_output_handle`'s
function), and the rule places transform-shaped types with their
defining function rather than with any state-shaped consumer that
happens to store them. The engine-side import is a one-line
re-export rather than the original placement.

**Divergence 2 — `KeyImage` newtype + classical Edwards-curve
subaddress relocation.** Plan estimate did not separately enumerate
`KeyImage` or the subaddress-derivation relocation. Both surfaced
during M3a as discipline-grounded additions:

- `KeyImage` was upgraded from a raw `[u8; 32]` to a typed newtype
  in `shekyl-crypto-pq::key_image` per the "type each thing when
  it surfaces" disposition (sub-commit 3). The newtype carries the
  privacy-correlation discipline mirroring `OutputHandle`'s
  (truncated `Debug`, no `Display`, no `Zeroize`).
- Classical Edwards-curve subaddress derivation
  (`subaddress_derivation_scalar`, `subaddress_keys`) was relocated
  from `shekyl-scanner::view_pair` to
  `shekyl-crypto-pq::subaddress` (sub-commit 4) per the
  path-stateless discipline (extension to the stateless-actor
  framing): paths from trait surface to cryptographic primitive
  must be stateless end-to-end, not just at their endpoints. The
  module is structured to also house future
  `derive_subaddress_kem_keypair` (per-subaddress hybrid X25519 +
  ML-KEM-768 keygen, §6.4) when its infrastructure lands.

**Divergence 3 — `sign_transaction` is stubbed with named gap.**
Plan estimate said `sign_transaction` would bridge through to
`shekyl_tx_builder::sign_transaction` via `SourceSecretsBundle`-
populated `SpendInput`s. Actual: `LocalKeys::sign_transaction`
returns `KeyEngineError::SignTransactionTraitSurfaceIncomplete`.
The gap: `TxToSign`'s `outputs: Vec<TxOutputContext>` and
`fcmp_plus_plus_context: FcmpPlusPlusContext` are PR-5-pinned
forward-declared as empty stubs (per the design doc's "TxToSign's
exact field shape is finalized in PR 5" framing), so the bridge
cannot reach `shekyl_tx_builder::sign_transaction`'s public-data
inputs (`output_key`, `commitment`, `amount`, `h_pqc`,
tree-branch context). The bridge lands when PR 5 (`PendingTxEngine`)
finalizes `TxToSign`'s shape; the `KeyEngineError` variant's
doc-comment names the gap and the landing target. Test substrate
exercises the stub-validation path (`sign_transaction` returns the
named-gap error).

**Files actually touched (M3a sub-commits 1–5; sub-commit 6 is
this docs commit).**

- New: `rust/shekyl-crypto-pq/src/handle.rs` (~210 lines —
  `OutputHandle` newtype, `derive_output_handle`, locked reference
  vectors).
- New: `rust/shekyl-crypto-pq/src/keys.rs` (`ViewSecret` newtype).
- New: `rust/shekyl-crypto-pq/src/key_image.rs` (`KeyImage` newtype).
- New: `rust/shekyl-crypto-pq/src/subaddress.rs` (~210 lines —
  relocated derivation primitives + module-level discipline doc).
- New: `rust/shekyl-engine-core/src/engine/local_keys.rs` (~720
  lines — `LocalKeys` struct, `KeyEngine` impl, 11 tests).
- Edit: `rust/shekyl-engine-core/src/engine/traits/key.rs` (~700
  lines — full trait surface + supporting message shapes).
- Edit: `rust/shekyl-engine-core/src/engine/error.rs` —
  `KeyEngineError` extension with two named-gap variants.
- Edit: `rust/shekyl-engine-core/src/engine/mod.rs` —
  `local_keys` module exposure.
- Edit: `rust/shekyl-engine-state/src/subaddress.rs` —
  `to_canonical_bytes` accessor + `PRIMARY` constant.
- Edit: `rust/shekyl-scanner/src/view_pair.rs` — methods converted
  to thin call-throughs over the relocated primitives.
- Edit: `rust/shekyl-crypto-pq/Cargo.toml` — `sha3` zeroize feature
  + `shekyl-primitives` direct dep for relocated derivation.
- Edit: `rust/shekyl-crypto-pq/src/lib.rs` — `subaddress`,
  `handle`, `keys`, `key_image` module exposure.

The total review surface is ~2.2× the planned ~900 lines, driven
mostly by the discipline-grounded additions in Divergence 2 and
the comprehensive test substrate for `LocalKeys` (11 tests, each
exercising the real-impl methods end-to-end via
`construct_output`-produced inputs rather than synthetic
fixtures).

**Deferred to between M3a and M3b.** Per the in-flight
disposition, the typed-wrapper migration for the remaining
`AllKeysBlob` fields (`spend_sk` → `SpendSecret`,
`view_pk` → `ViewPublicKey`, `spend_pk` → `SpendPublicKey`, plus
sweeping existing raw `[u8; 32]` `KeyImage` sites to the newtype)
lands as a separate short-lived branch off `dev` before M3b
cuts.

---

### §3.2 M3b — scanner reroute + bridge source switch

**Title.** `feat(engine): reroute scanner secrets via KeyEngine deterministic handle`

**Scope.**

- Edit `rust/shekyl-scanner/src/ledger_ext.rs:125–129` (the
  audit's load-bearing single-site change): scanner emits
  `OutputClaim` to `KeyEngine::try_claim_output` instead of
  populating `TransferDetails`'s secret-bearing fields directly.
- Engine returns `OutputHandle` (deterministic per design doc
  §7.12) to the orchestrator; orchestrator persists the handle
  and the `source_ciphertext` (the on-chain hybrid ciphertext the
  scanner detected) on `TransferDetails`. Both fields are added
  to the schema at this PR so the bridge impl's primary path is
  functional from M3b; the legacy secret-bearing fields remain
  populated transitionally to keep the bridge-impl fallback live.
- Switch `LocalKeys::sign_transaction`'s primary secret source
  from `TransferDetails`'s legacy secret fields to the
  deterministic handle path: re-derive spend material from
  `(view_secret, source_ciphertext)` at the input-resolution
  step. `TransferDetails` legacy fields remain as transitional
  fallback (selected by feature-detection, not feature flag — if
  `source_ciphertext` is present, re-derive from it; else fall
  through to the legacy fields).
- Test fixtures in `rust/shekyl-scanner/src/tests.rs:77, 855, 1037`
  rewrite to exercise the engine-mediated flow.
- Add byte-identical-derivation property test: for the same input
  ciphertext + tx context, deterministic-handle-path-resolved
  secrets (re-decap from `source_ciphertext`) must equal
  legacy-`TransferDetails`-resolved secrets bit-for-bit. This is
  the audit's cross-PR safety property; failure indicates a bug
  in either path.

**Files touched (estimated).**

- Edit: `rust/shekyl-scanner/src/ledger_ext.rs` (~30 lines net).
- Edit: `rust/shekyl-scanner/src/tests.rs` (~150 lines net).
- Edit: `rust/shekyl-engine-core/src/engine/local_keys.rs` (~80 lines
  net for source-switch + fallback logic).
- New: `rust/shekyl-engine-core/tests/byte_identical_derivation.rs`
  (~100 lines).

**Dependencies.** M3a (trait + bridge impl + `derive_output_handle`).

**Schema state at PR boundary.** `TransferDetails` carries both
the legacy secret-bearing fields (still populated) and the new
`source_ciphertext` + `output_handle` fields. Two parallel
secret-recovery sources exist transitionally; the bridge impl's
primary path uses the new fields, the fallback uses the legacy
ones.

**Property delivery.** Partial. The engine has a functional
deterministic-handle path; the orchestrator's legacy
secret-bearing copies remain. Property "secrets confined to
engine" not yet active (orchestrator-side copies remain).

**Success criteria.**

- Workspace compiles; all existing tests green.
- Byte-identical-derivation property test passes (re-decap path
  produces secrets bit-identical to legacy-field path).
- `OutputHandle` and `source_ciphertext` populated for every
  output the scanner ingests.
- Bridge impl exercises deterministic-handle primary path on at
  least one end-to-end test; fallback path covered by an explicit
  fallback test (e.g., a `TransferDetails` with legacy fields
  populated but `source_ciphertext = None`).

**Estimated review surface.** ~360 lines net; one production write
site moved; one new property test.

#### §3.2.1 Pre-flight reconciliation (added 2026-05-08)

Pre-flight investigation per
[`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./STAGE_1_PR_3_M3B_PREFLIGHT.md)
surfaced three substantive refinements to §3.2's estimate that
land at Phase 2 entry. Recording here as the canonical reference
for reviewers reading commit messages and the M3b PR description.

**Refinement 1 — Two-layer derivation-primitive split (D1).** §3.2
named the re-decap derivation primitive without specifying its
shape. Applying `18-type-placement.mdc` during pre-flight produced
a two-layer split:

- **Layer 1 (transform-shaped):**
  `shekyl_crypto_pq::output::recover_combined_ss(view_x25519_sk,
  view_ed_sk, ml_kem_dk, source_ciphertext) -> SharedSecret`. Pure,
  sync, no engine context. Lives in `shekyl-crypto-pq` because it
  is defined by what it computes.
- **Layer 2 (state-shaped):**
  `LocalKeys::derive_source_secrets_bundle(source_ciphertext,
  output_index, subaddress_idx) -> Result<SourceSecretsBundle,
  KeyEngineError>`. Composes Layer 1's output with the engine-owned
  `b` (spend secret) and `m_i` (subaddress derivation scalar).
  Lives in `shekyl-engine-core::engine::local_keys` because it is
  defined by who owns the result.

**Refinement 2 — Scanner reroute lives at the orchestrator layer
(§3 of pre-flight doc).** §3.2's "scanner emits `OutputClaim` to
`KeyEngine::try_claim_output`" framing is operationally infeasible
inside `shekyl-scanner::process_scanned_outputs` because:

- `shekyl-scanner` does not depend on `shekyl-engine-core`
  (dependency direction is engine-core → scanner via
  `LedgerIndexesExt`).
- `KeyEngine` is `pub(crate)` to `shekyl-engine-core` per the M3a
  Round 4a visibility decision.
- `process_scanned_outputs` is sync and called from ~30 sites;
  forcing it `async` would cascade into every test/bench fixture.

**Disposition.** The reroute lives at the orchestrator layer in
`shekyl-engine-core::engine::merge`. A new async sibling helper
(`populate_engine_handle_fields`) runs after the existing sync
`apply_scan_result_to_state` body and populates
`td.source_ciphertext` / `td.output_handle` via
`KeyEngine::try_claim_output`. The sync/async split is a
**permanent intentional pattern**, not transitional drift; both
have legitimate consumers (the sync substrate serves the
bookkeeping pipeline; the async sibling layers engine integration).

**Refinement 3 — Test-fixture estimate revision (§4 of pre-flight
doc).** §3.2 estimated ~150 lines of test fixture rewrites in
`shekyl-scanner/src/tests.rs`. Pre-flight investigation revealed
that legacy fields stay populated transitionally and the engine
post-pass is exercised via real `LocalKeys` integration tests
(`engine-core/tests/byte_identical_derivation.rs`), not via the
synthetic `wrap_recovered`/`mock_output` fixtures. Revised
estimate: ~10–20 lines.

**Total estimate revision.**

| Source | Net lines |
|---|---|
| Plan §3.2 estimate | ~360 |
| Pre-flight estimate | ~500–550 |
| Delta | +140–190 |
| Drivers | D1 two-layer split (+~60); engine post-pass scaffolding (+~80–100); schema-derive plumbing in `shekyl-crypto-pq` (+~10) |
| Offsets | Test-fixture estimate revision (−~130–140) |
| Net delta | +70–130 |
| Cumulative-diff guardrail | 600 net lines |
| Margin | ~50–100 lines |

**The plan estimate of ~360 was grounded in framing-level estimates
from design rounds that did not include the two-layer split or the
engine post-pass shape specifics. The pre-flight investigation
worked as intended in surfacing these specifics before drafting.**
The 600-line ceiling holds; the realistic estimate of 500–550 is
well within scope.

#### Landing notes (M3b closed)

M3b landed on `feat/stage-1-pr3-m3b` as ten commits (one of which
was a mechanical rustfmt fix between substantive commits) cut off
`dev` at `647f82d59`. Three structural divergences from the
pre-flight (§3.2.1) estimate are recorded against the discipline
that drove each.

**Sub-commit breakdown.**

1. *`crypto-pq: extract recover_combined_ss re-decap primitive (M3b D1 Layer 1)`*
   — extracts the X25519 + ML-KEM-768 + HKDF-SHA-512 re-decap chain
   from `scan_output_recover`'s prefix into a public `pub fn
   recover_combined_ss(view_x25519_sk, ml_kem_dk, kem_ct_x25519,
   kem_ct_ml_kem) -> Result<SharedSecret, CryptoError>`. Refactors
   `scan_output_recover` to call the new fn for compositional
   clarity (the inline X25519 ECDH is preserved so view-tag
   pre-filter still short-circuits before the more expensive ML-KEM
   decap). New `tests/recover_combined_ss.rs` (~196 lines, 5 tests)
   pins Layer-1 byte-identity at the primitive boundary.
2. *`crypto-pq: derive Schema + transparent serde on OutputHandle and HybridCiphertext (M3b D3 α)`*
   — `postcard-schema` direct dep added to `shekyl-crypto-pq` for
   Disposition Q1's α path. `Schema` derive on `HybridCiphertext`,
   `Schema` + transparent `Serialize`/`Deserialize` on `OutputHandle`.
   Enables the schema additions in commit 4. Pin matches the
   existing `shekyl-engine-state` direct-dep pin per
   `17-dependency-discipline.mdc`.
3. *`engine-core: add SourceCiphertextDecapsulationFailed to KeyEngineError (M3b D6)`*
   — the named-failure-mode variant for re-decap rejection.
   Pre-flight defaulted to "unit variant"; landed shape is
   `SourceCiphertextDecapsulationFailed(#[from] CryptoError)` so
   audit logs see whether the rejection was at the X25519 (low-order
   point), the ML-KEM-768 (decap failure), or the input-shape
   (invalid key material) layer. The `#[from]` is load-bearing for
   the re-decap call site's `?` operator in commit 6.
4. *`engine-state: extend TransferDetails with source_ciphertext + output_handle`*
   — `TransferDetails` schema extension (D3); both fields are
   `Option<…>` to keep the bridge-impl fallback live during the
   transitional window per §3.2's "feature-detection, not
   feature-flag" framing. `Zeroize` impl skips the new fields
   (public on-chain residue + deterministic handle, not secret).
   `LEDGER_BLOCK_VERSION` + `WALLET_LEDGER_FORMAT_VERSION` bumped
   2 → 3; both schema snapshots regenerated. `TransferDetails`
   initializers updated across 11 sites in `shekyl-engine-state`
   (benches, invariants, ledger_indexes), `shekyl-engine-core`
   (benches), and `shekyl-scanner` (`ledger_ext.rs::from_wallet_output`).
5. *`engine-core: swap TxInputSigningContext source_secrets for ciphertext`*
   — `TxInputSigningContext` field swap (D2): drops
   `source_secrets: SourceSecretsBundle` (the by-value secret
   carrier that contradicted the engine-confined-secrets property)
   in favor of `source_ciphertext: HybridCiphertext` + `output_index:
   u64`. `Debug` impl simplified; redaction tests updated. `LocalKeys`
   consumers in `try_claim_output` are unaffected (use `OutputDetectionInput`,
   not `TxInputSigningContext`); `sign_transaction`'s stub body
   unaffected.
6. *`engine-core: derive_source_secrets_bundle on LocalKeys (M3b D1 Layer 2)`*
   — Layer 2 of the D1 split: `pub(crate) fn
   derive_source_secrets_bundle(&self, source_ciphertext: &HybridCiphertext,
   output_index: u64, subaddress_idx: SubaddressIndex) ->
   Result<SourceSecretsBundle, KeyEngineError>` composes Layer 1's
   `recover_combined_ss` with `derive_output_secrets` and the
   engine-owned `b` (spend secret) and `m_i` (subaddress derivation
   scalar). Two smoke tests; the comprehensive byte-identical
   property test lands at commit 8.
7. *`scanner: preserve OutputDetectionInput residue on RecoveredWalletOutput`*
   (was C9 in pre-flight; reordered to land before C7) — the
   pre-flight estimated this as "may be no-op" but inspection
   revealed `RecoveredWalletOutput` was discarding the
   `source_ciphertext`, `view_tag`, `enc_amount`, and `amount_tag`
   on-chain residue at construction time. Without this commit, the
   engine post-pass at commit 8 has no `HybridCiphertext` to use
   for the handle derivation. Reordered to land first per
   bisection-friendliness; the engine post-pass commit then
   compiles against the populated residue without a forward
   reference.
8. *`engine-core: orchestrator-side handle population post-pass (M3b §3 reroute)`*
   — the actual scanner-reroute equivalent (Q2's δ disposition).
   `Engine::apply_scan_result` becomes `collect → merge → populate`
   inside one `LocalLedger` write guard: `collect_detection_residue`
   builds a `HashMap<(tx_hash, internal_output_index),
   HybridCiphertext>` from the `ScanResult`'s new transfers;
   `apply_scan_result_to_state` performs the existing sync
   bookkeeping merge; `populate_engine_handle_fields` walks the
   freshly-merged `TransferDetails` and binds each to its
   `source_ciphertext` + deterministic `output_handle` from the
   residue map. Atomic against external readers — concurrent reads
   either see pre-merge or post-population, never an intermediate
   state. Idempotent. Four unit tests in `engine::merge::tests`
   (positive, selectivity, idempotency, empty-residue).
9. *`engine-core: rustfmt merge.rs after C7b residue tests landed`*
   — mechanical fmt-only fix to `merge.rs:979,1083` that escaped
   commit 8's package-wide format pass. The chained
   `.as_ref().expect(...)` reformatted across multiple lines once
   the surrounding expression depth crossed `rustfmt`'s line-break
   threshold. Standalone per `15-deletion-and-debt.mdc`'s
   scope-per-commit discipline.
10. *`engine-core: byte-identical-derivation property test (M3b D5)`*
    — two unit tests in `local_keys.rs::tests`: (a)
    `derive_source_secrets_bundle_byte_identical_against_legacy_chain`
    exercises 24 derivations (8 distinct (output_index, tx_hash)
    pairs × 3 subaddress indices — PRIMARY, idx=1, idx=42) asserting
    field-by-field byte-identity against a hand-rolled bundle from
    `scan_output_recover`'s `RecoveredOutput`; (b)
    `derive_source_secrets_bundle_diverges_across_distinct_seeds`
    exercises cross-seed isolation, with the test docstring pinning
    that ML-KEM-768 implicit rejection (FIPS 203) means a wrong-wallet
    decap *succeeds* with a junk bundle rather than refusing — the
    isolation property is "junk bundle differs byte-for-byte," not
    "function refuses."

(Sub-commit 11 is this docs commit.)

**Divergence 1 — Test placement.** Pre-flight (§D5 / §5 commit
table line 8) named the test file
`rust/shekyl-engine-core/tests/byte_identical_derivation.rs`
(integration test). Actual placement: two unit tests inside
`rust/shekyl-engine-core/src/engine/local_keys.rs`'s `mod tests`.
The deviation is driven by the M3a Round 4a `pub(crate)` lock on
`LocalKeys`, `SourceSecretsBundle`, and `KeyEngineError`. Integration
tests run as external crates and cannot reach `pub(crate)` items;
expanding visibility — or adding a `__test_internals` re-export
module — for one test contradicts the visibility lock and inflates
the public API surface for no proportional benefit. Located
alongside the C6 smoke tests, the property is identical regardless
of file placement. The deviation is recorded inline in the test
docstring so a future maintainer can re-locate to `tests/` if the
visibility lock relaxes (e.g. at the V3.2 wallet-RPC cutover when
`KeyEngine` widens to `pub`); tracked in `docs/FOLLOWUPS.md` § V3.2
as "M3b property-test re-location."

**Divergence 2 — C7→C7a/C7b commit reorder.** Pre-flight estimated
C9 (`scanner: process_scanned_outputs preserves OutputDetectionInput
residue`) as "~0–10 lines, may be no-op." Actual: C9 was load-bearing
for C7's engine post-pass — `RecoveredWalletOutput` was discarding
the `source_ciphertext` / `view_tag` / `enc_amount` / `amount_tag`
on-chain residue at construction time. Reordered C9 to land as C7a
(scanner residue plumbing, ~73-line delta in `shekyl-scanner/src/scan.rs`)
before the renamed C7b (orchestrator post-pass), preserving
bisection-friendliness — every commit leaves the workspace
`cargo check`-green and each commit's body matches its subject.
The reorder is honest about the layering: the engine post-pass
needs structured input, and the scanner is the only producer.

**Divergence 3 — Engine post-pass placement; sync helper, async-ready
surface.** Pre-flight Q2's δ disposition framed
`populate_engine_handle_fields` as "async sibling helper" assuming
`self.keys.try_claim_output(...)` flows through `KeyEngine`. That
requires wiring `LocalKeys` onto `Engine`, which `from_keys_blob`'s
own dead-code marker pins to M3c+. Rather than scope-creep that
wiring into M3b, M3b derived the handle directly via the public
`derive_output_handle` primitive (mathematically equivalent — same
`(view_secret, tx_hash, output_index)` cSHAKE256 binding — and the
view secret is already on `Engine.keys: AllKeysBlob`). The helper
stays sync; the async signature flips when M3c+ wires `LocalKeys`.
The `# Synchronous body, async-ready surface` doc-comment on
`populate_engine_handle_fields` pins the trajectory so a future
maintainer doesn't re-litigate it. M3b's architectural property
(every output the scanner ingests has a deterministic handle on its
`TransferDetails`) is delivered without the audit's "engine sole
authority on handles" framing — that property activates at M3d per
§3.4 below.

**Files actually touched.**

- New: `rust/shekyl-crypto-pq/tests/recover_combined_ss.rs` (~196
  lines).
- Edit: `rust/shekyl-crypto-pq/Cargo.toml` (+`postcard-schema`
  direct dep).
- Edit: `rust/shekyl-crypto-pq/src/output.rs` (+`recover_combined_ss`,
  refactored `scan_output_recover` body).
- Edit: `rust/shekyl-crypto-pq/src/handle.rs` (`Schema` + transparent
  serde derives on `OutputHandle`).
- Edit: `rust/shekyl-crypto-pq/src/kem.rs` (`Schema` derive on
  `HybridCiphertext`).
- Edit: `rust/shekyl-engine-core/src/engine/error.rs`
  (+`SourceCiphertextDecapsulationFailed(#[from] CryptoError)`).
- Edit: `rust/shekyl-engine-core/src/engine/local_keys.rs`
  (+`derive_source_secrets_bundle` + 4 tests including the byte-
  identical property test).
- Edit: `rust/shekyl-engine-core/src/engine/merge.rs` (+engine
  post-pass: `collect_detection_residue`,
  `populate_engine_handle_fields`, 4 tests).
- Edit: `rust/shekyl-engine-core/src/engine/traits/key.rs`
  (`TxInputSigningContext` field swap).
- Edit: `rust/shekyl-engine-state/src/transfer.rs` (+`source_ciphertext`,
  `output_handle` `Option<…>` fields; schema; Zeroize-skip on new
  non-secret fields).
- Edit: `rust/shekyl-engine-state/src/ledger_block.rs`
  (`LEDGER_BLOCK_VERSION` 2→3).
- Edit: `rust/shekyl-engine-state/src/wallet_ledger.rs`
  (`WALLET_LEDGER_FORMAT_VERSION` 2→3).
- Edit: `rust/shekyl-engine-state/schemas/{ledger_block,wallet_ledger}.snap`
  (regenerated; ~+498 lines combined — generated artifacts).
- Edit: `rust/shekyl-scanner/src/scan.rs`
  (+4 residue fields on `RecoveredWalletOutput` + accessors).
- Edit: `rust/shekyl-scanner/src/tests.rs` (3 fixtures updated for
  the new fields).
- Edit: `rust/shekyl-scanner/src/ledger_ext.rs` (+`source_ciphertext:
  None`, `output_handle: None` initialization).
- Edit: ~9 sites across `shekyl-engine-state` and `shekyl-engine-core`
  benches / invariants / ledger_indexes for `TransferDetails`
  initializer updates.

**Net diff stat.** ~+2109 / −147 across 27 files, ~+1962 net. Of
which ~+498 is the regenerated schema snapshots (load-bearing
generated artifacts; a manual write of the same content would still
land identically). Net code lines: ~+1465 — over the pre-flight's
500–550 estimate and over the original 600-line guardrail. The
overage drivers:

- Comprehensive doc-comments on `populate_engine_handle_fields`,
  `derive_source_secrets_bundle`, the byte-identical property test,
  and the C7b commit's design rationale (~+200 lines of doc-comments
  total — the source-of-truth pinning that prevents re-litigation
  per `16-architectural-inheritance.mdc` §"Continuous discipline as
  inheritance prevention").
- Engine post-pass test substrate (4 unit tests, ~+200 lines) that
  was sized as ~60–100 lines in the pre-flight.
- Byte-identical property test substrate (260 lines vs the
  pre-flight's ~120-line estimate) due to the 24-derivation sweep
  and the cross-seed isolation test (the second test was not in
  the pre-flight estimate).

The overage is honest expansion of the test substrate and the
in-source design-rationale documentation; not a scope expansion of
the production code paths. The pre-flight's `~50–100 lines margin`
framing fell on the wrong side; future per-PR estimates should
budget more generously for in-source discipline-pinning
doc-comments at architectural-inheritance-load-bearing surfaces.

**Property delivery.** Partial (per §3.2 "Property delivery").
Engine cache populated for every output the scanner ingests; both
`TransferDetails.source_ciphertext` and `TransferDetails.output_handle`
are populated post-merge. The legacy secret-bearing fields remain
populated transitionally to keep the bridge-impl fallback live;
"secrets confined to engine" is not yet active. M3d removes the
legacy fields and the orchestrator-side copies they hold.

**Discipline-application notes.** Two recurrence-pattern instances
worth recording for the V3.x post-mortem:

- **Sync/async architectural-integrity-now.** The engine post-pass
  could have been wrapped in `async fn` from M3b to anticipate
  M3c+'s `KeyEngine::try_claim_output` integration. Per
  `16-architectural-inheritance.mdc` §"The cost-benefit-defer-to-later
  anti-pattern," the architectural-integrity-now disposition for
  M3b was: keep the helper sync because the cryptographic primitive
  (`derive_output_handle`) is sync, and let the `async` upgrade
  happen at M3c+ when the integration shape forces it. The
  alternative — wrap in `async` now for "future-proofing" — would
  cascade `.await` chains through `Engine::apply_scan_result`'s
  callers without delivering any property M3b ships. The
  doc-comment on `populate_engine_handle_fields` captures the
  trajectory.
- **Test-fixture honesty.** The pre-flight's ~10–20 lines for
  test-fixture rewrites was approximately correct (3 fixtures
  updated for the new `RecoveredWalletOutput` fields, ~21 lines).
  But the pre-flight underestimated the new test-substrate
  required to exercise the engine post-pass (4 unit tests in
  `merge.rs`) and the byte-identical property (2 unit tests in
  `local_keys.rs`). Test substrate scales with the property
  surface, not with the call-site count.

---

### §3.3 M3c — additive test caller

> **§3.3-rides-with-M3c exception to `91-documentation-after-plans.mdc`.**
> The §3.3 revision documenting M3c's actual disposition (Option C:
> bypass the stubbed `KeyEngine::sign_transaction` and directly call
> `tx_builder::sign_transaction` with engine-derived
> `SourceSecretsBundle`s) **lands in the M3c PR itself**, not in
> M3e's documentation closeout. The general rule
> (`.cursor/rules/91-documentation-after-plans.mdc`) is that
> documentation updates follow plan execution; this specific case is
> the exception, because the §3.3 revision **is the rationale the
> M3c PR review depends on**. Without the revision in the same PR,
> each reviewer independently re-derives "why isn't this what the
> plan said," and the migration's discipline budget pays for the
> re-derivation N times. Pinning the exception here in the plan
> rather than relying on M3c's PR description ensures the M3c PR
> doesn't accidentally ship without the §3.3 revision (per the
> 2026-05-10 user direction).

**Title.** `test(engine): exercise KeyEngine::sign_transaction end-to-end`

**Scope.**

- Add a Rust integration test in `rust/shekyl-engine-core/tests/`
  (suggested name: `key_engine_sign_e2e.rs`) that:
  1. Constructs a synthetic transaction prefix using existing
     `tx-builder` test vectors.
  2. Populates a `LocalKeys` instance with handles for the inputs.
  3. Calls `KeyEngine::sign_transaction(tx_prefix_hash, &handles, ...)`.
  4. Verifies the resulting `SignedProofs` against the existing
     `tx_builder::sign_transaction` test-vector outputs (byte-identical
     signatures, commitments, proofs).
- This validates the handle→secret resolution path produces output
  indistinguishable from the legacy direct-secret path. It is the
  property-test that the audit-bounded migration relies on.

**Files touched (estimated).**

- New: `rust/shekyl-engine-core/tests/key_engine_sign_e2e.rs`
  (~250 lines).
- Possibly edit: `rust/shekyl-tx-builder/src/tests.rs` to expose
  shared test-vector fixtures via `#[cfg(test)] pub` if not already
  accessible from the engine-core tests. (Cross-crate test fixture
  visibility — flag if friction.)

**Dependencies.** M3a (trait + bridge). Independent of M3b in
scope (test constructs the deterministic handle directly via
`derive_output_handle` against a synthetic fixture, not via the
scanner reroute), so M3c can merge in parallel with M3b.

**Schema state at PR boundary.** Unchanged from incoming.

**Property delivery.** Validation milestone. Not a property delivery,
but the precondition for trusting M3d's removal of fallback paths.

**Success criteria.**

- Test passes against ≥3 existing `tx-builder` test vectors.
- Test produces byte-identical `SignedProofs` to the legacy path.
- Test runs in <1 s (engine-internal construction is not a
  performance regression).

**Estimated review surface.** ~250 lines added; minimal
cross-crate friction.

#### §3.3.1 Post-implementation cross-reference (Option C disposition)

The §3.3 wording above predates two structural facts that surfaced
during M3a/M3b execution and one runtime/coverage discovery that
surfaced during M3c implementation. The disposition is recorded in
[`STAGE_1_PR_3_M3C_PREFLIGHT.md`](./STAGE_1_PR_3_M3C_PREFLIGHT.md);
this section names the deltas so a reader of §3.3 reaches the
authoritative implementation-side wording in one hop.

**Structural deltas (pre-flight §1, §2).**

- **Trait method is a non-functional stub.**
  `KeyEngine::sign_transaction` returns
  `KeyEngineError::SignTransactionTraitSurfaceIncomplete`
  unconditionally because `TxToSign`'s `outputs` and
  `fcmp_plus_plus_context` are PR-5-pinned forward-declared stubs
  (see §3.1 Divergence 3). M3c cannot exercise the trait method
  end-to-end; the bridge to `tx_builder::sign_transaction` lands in
  PR 5. The pre-flight's Option C disposition pins the property
  M3c was designed to validate at the surface where it is reachable
  today — direct call from engine-derived bundles to
  `tx_builder::sign_transaction` — bypassing the trait stub.
- **`pub(crate)` lock forces unit-test placement.** The `tests/`
  integration-test placement in §3.3 is unreachable: `KeyEngine`,
  `LocalKeys`, and `SourceSecretsBundle` are all `pub(crate)` per
  the M3a Round 4a discipline lock. The test lands inline in
  `rust/shekyl-engine-core/src/engine/local_keys.rs::tests` as a
  peer to M3b D5's bundle-byte-identity test. Re-location to
  `tests/` is co-located with M3b D5's re-location at the
  "`KeyEngine` widens to `pub`" trigger (see `docs/FOLLOWUPS.md`).
- **Sign is non-deterministic.** `tx_builder::sign_transaction`
  calls `OsRng` internally for BP+ pseudo-output blindings, the
  BP+ proof, and the FCMP++ proof. The §3.3 success-criterion line
  "*Test produces byte-identical `SignedProofs` to the legacy
  path*" is unreachable at this surface. The pre-flight refines
  the property to deterministic-component byte-identity plus
  verifier-acceptance for the randomized components.

**Runtime/coverage delta (pre-flight §2.1.1, Trim-1 disposition).**

- **SpendInput byte-equality + sign-once supersedes parallel sign.**
  Implementation surfaced that `SpendInput` byte-equality at the
  input layer is strictly stronger than `commitments` /
  `enc_amounts` byte-equality at the signer-output layer (the
  latter follows from the former by signer determinism; the former
  additionally guards against `SpendInput` field drift irrelevant
  to commitments / enc_amounts but relevant to signature behavior
  or future field additions). Substituting the parallel sign call
  for input-layer byte-equality + sign-once on the engine path
  halves the test runtime (32s → 17s debug; 12s → 7s release).
  The named coverage gap (workspace sole-coverage of
  `tx_builder::sign_transaction` end-to-end success goes from 2× to
  1×) is accepted given M3d removes the legacy bundle-derivation
  chain entirely. Pre-flight §2.1.1 records the discovery and
  names it as a forward template: implementation may strengthen
  pre-flight properties post-implementation; weakening requires
  explicit revisit of the original disposition.

**Updated dispositions.**

- *Test name.* `engine_derived_bundle_signs_through_tx_builder_end_to_end`
  (peer to M3b D5 in `local_keys.rs::tests`).
- *Fixture sweep.* 9 fixtures (3 input counts × 3 subaddress
  indices) — orthogonal coverage of n_in pseudo-output-blinding and
  subaddress-derivation axes plus their cross-axis interaction.
- *Success criteria.* (a) `Ok(SignedProofs)`; (b) engine `SpendInput`
  byte-identical field-by-field to a hand-composed legacy
  `SpendInput`; (c) BP+ verifies via
  `Bulletproof::read_plus` + `Bulletproof::verify`; FCMP++ verifies
  via `shekyl_fcmp::proof::verify`; `reference_block` and
  `tree_depth` echo unchanged.
- *Review surface.* ~700 LOC including inline cryptographic
  tree-fixture construction (replicating the recipe from
  `shekyl-fcmp::proof::tests::prove_verify_roundtrip`), not the
  ~250 LOC originally estimated.

The validation property M3d depends on (the precondition for
removing the legacy bundle-derivation fallback) is unchanged in
substance: M3b D5 + M3c-via-C together pin the full cryptographic-
derivation chain end-to-end, with the engine path now load-bearing
for `tx_builder::sign_transaction`'s sole successful end-to-end
coverage in the workspace.

---

### §3.4 M3d — schema cleanup; property activates

**Title.** `feat(engine): remove TransferDetails secret fields; secrets confined to engine`

**Scope.**

- Remove from `rust/shekyl-engine-state/src/transfer.rs:86–98` the
  five legacy secret-bearing fields:
  - `combined_shared_secret: Option<Zeroizing<[u8; 64]>>`
  - `ho: Option<Zeroizing<[u8; 32]>>`
  - `y: Option<Zeroizing<[u8; 32]>>`
  - `z: Option<Zeroizing<[u8; 32]>>`
  - `k_amount: Option<Zeroizing<[u8; 32]>>`
- (`source_ciphertext` and `output_handle` were added to the
  schema at M3b; M3d removes the legacy fields they superseded.)
- Update `Zeroize` / `Drop` impls; update postcard schema; update
  serde helpers.
- Remove the bridge impl's legacy-`TransferDetails`-fallback path
  in `LocalKeys::sign_transaction`. Post-M3d, the deterministic
  handle path (re-derive from `(view_secret, source_ciphertext)`)
  is the only secret source.
- Rewrite test/bench fixtures per audit §2.4 (10 sites).
- Update the scanner's `TransferDetailsExt::populate_*` helpers in
  `ledger_ext.rs` to drop the legacy-field writes (the write site
  moved to engine in M3b; the helper now populates
  `source_ciphertext` and `output_handle` only).

**Files touched (estimated).**

- Edit: `rust/shekyl-engine-state/src/transfer.rs` (schema; ~80 lines
  net).
- Edit: `rust/shekyl-engine-state/src/ledger_block.rs` (test rewrite;
  ~40 lines net).
- Edit: `rust/shekyl-engine-state/src/ledger_indexes.rs` (test rewrite;
  ~5 lines net).
- Edit: `rust/shekyl-engine-state/src/invariants.rs` (test rewrite;
  ~5 lines net).
- Edit: `rust/shekyl-engine-core/benches/common/engine_fixture.rs`
  (~5 lines net).
- Edit: `rust/shekyl-engine-core/benches/refresh_snapshot.rs` (~5 lines).
- Edit: `rust/shekyl-engine-state/benches/{ledger,ledger_iai,balance,balance_iai}.rs`
  (transparent; ~5 lines each).
- Edit: `rust/shekyl-scanner/src/balance.rs` (test rewrite; ~5 lines).
- Edit: `rust/shekyl-scanner/src/ledger_ext.rs` (helper rewrite;
  ~30 lines net).
- Edit: `rust/shekyl-engine-core/src/engine/local_keys.rs` (remove
  fallback; ~50 lines deleted).

**Dependencies.** M3a, M3b, M3c. M3c is a hard dependency: removing
the fallback without the byte-identical-derivation property test
having validated the engine path is unsafe.

**Schema state at PR boundary.** `TransferDetails` carries
`source_ciphertext` + `output_handle` only; the five legacy
secret-bearing fields are removed. Bridge impl exclusively uses
the deterministic handle path: re-derive spend material from
`(view_secret, source_ciphertext)` per design doc §7.12.

**Property delivery.** **"Secrets confined to engine" activates.**
Orchestrator-side `TransferDetails` no longer carries derived
per-output secrets. Engine compromise still discloses long-term key
material via `AllKeysBlob`; orchestrator compromise no longer
discloses output-secret material (capability disclosure unchanged
per Round 3 §7.10/§7.11 framing).

**Success criteria.**

- Workspace compiles; all tests green; all benches run.
- `transfer.rs:322–340` (postcard roundtrip test) rewritten and passes
  for the new schema.
- The byte-identical-derivation property test from M3b continues to
  pass (now exercising only the handle path, since fallback is gone).
- `git grep -E 'combined_shared_secret|\\.ho\\b|\\.k_amount'` returns
  zero hits in `rust/` excluding `shekyl-crypto-pq` (which owns the
  derivation primitives) and `shekyl-proofs` (which uses derived
  fields by their ProofSecrets type, distinct from TransferDetails).

**Estimated review surface.** ~225 lines net (mostly deletes with
small additions for the new fields). The largest single per-file
change is the bridge impl's fallback removal (~50 lines).

---

### §3.5 M3e — documentation realignment

**Title.** `docs: STAGE_1_PR_3 — post-migration realignment`

**Scope.**

- Update `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` to reflect
  post-migration architecture as the operative design (Round 3's
  handle-indirected workflow becomes the sole architecture; pre-migration
  framing moves to a "history" section or is deleted).
- Update `docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md` snapshot
  reference to the post-M3d HEAD.
- Update `docs/CHANGELOG.md` per `91-documentation-after-plans.mdc`
  with one entry per merged PR (M3a, M3b, M3c, M3d).
- Update `docs/FOLLOWUPS.md`:
  - Close: any open V3.0 entries that reference the pre-migration
    architecture (review §V3.0 entries cross-referencing
    `KEY_ENGINE.md` for staleness).
  - Update: §V3.1 line 259 (`Stage 2 — KeyEngine migration to actor`)
    cross-reference to use the post-migration trait surface.
  - Add (if not already present): "PR 3 architectural-inheritance
    migration complete" close-record per the FOLLOWUPS audit-trail
    convention.
- Update `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` if it references the
  pre-migration `KeyEngine` shape.

**Files touched (estimated).**

- Edit: `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` (substantial; large
  doc).
- Edit: `docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md` (small; snapshot
  ref).
- Edit: `docs/CHANGELOG.md` (one section per PR).
- Edit: `docs/FOLLOWUPS.md` (close + update entries).
- Edit: `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` (cross-reference update).

**Dependencies.** M3d (post-migration architecture must be the
operative one before docs realign to it).

**Schema state at PR boundary.** Unchanged from M3d.

**Property delivery.** None (doc-only).

**Success criteria.**

- All documentation is internally consistent against the post-migration
  architecture.
- No reference to removed `TransferDetails` fields exists outside
  git history.
- `CHANGELOG.md` has a complete record of the migration's user-visible
  effects (zero, since RPC contract is migration-transparent
  per audit §2.5; the CHANGELOG entries note this explicitly).

**Estimated review surface.** Doc-only; depends on `KEY_ENGINE.md`'s
post-migration update size. M3e can land same-day or next-day
after M3d; freeze lifts at M3d's merge.

---

## §4 Cross-PR concerns

### §4.1 Property delivery timeline

| PR | Property state |
|---|---|
| M3a | Substrate. No property delivered. |
| M3b | Engine cache populated. Property partial: orchestrator copy still present. |
| M3c | Validation milestone. No property change. |
| M3d | **"Secrets confined to engine" activates.** |
| M3e | None (doc-only). |

The "secrets confined to engine" property activates at M3d's
merge. Earlier framing in design rounds anchored this to M3a;
the audit and the 5-PR collapse moved it to M3d, which is honest
about when the orchestrator's `TransferDetails` actually stops
carrying derived secrets.

### §4.2 Bridge impl secret-source evolution

| PR | Primary source | Fallback | Both populated? |
|---|---|---|---|
| M3a | legacy `TransferDetails` fields | — | n/a (only legacy fields exist) |
| M3b | re-derive from `(view_secret, source_ciphertext)` | legacy `TransferDetails` fields | Yes (transitional) |
| M3c | (unchanged from M3b) | (unchanged) | Yes |
| M3d | re-derive from `(view_secret, source_ciphertext)` | — | No (legacy fields removed) |

The fallback at M3b is feature-detected, not feature-flagged: if
`source_ciphertext` is present on the `TransferDetails`, the
bridge re-derives spend material from it; if not (legacy
fixture), the bridge falls through to the legacy fields. This
means the fallback does not require any explicit "switch" at M3d
— just the removal of the legacy fields the fallback would have
read.

### §4.3 Schema state at each PR boundary

| PR | `TransferDetails` carries |
|---|---|
| Pre-M3a | 5 secret-bearing fields (legacy) |
| M3a | (unchanged) |
| M3b | 5 legacy secret-bearing fields (still populated; transitional fallback) **plus** `source_ciphertext: HybridCiphertext` and `output_handle: OutputHandle` (new; primary path source) |
| M3c | (unchanged) |
| M3d | `source_ciphertext` + `output_handle` (only). 5 legacy fields removed. |
| M3e | (unchanged) |

### §4.4 Test substrate evolution

- **M3a.** New unit tests for `LocalKeys` (including
  `from_test_seed` determinism) and `derive_output_handle`
  (known-answer vectors, cross-input divergence,
  customization-bump versioning, `Sha3State` `Zeroize` feature
  wiring). Existing scanner / engine-state tests untouched.
- **M3b.** Scanner test fixtures rewrite to engine-mediated flow.
  New byte-identical-derivation property test.
- **M3c.** New end-to-end engine signing test against `tx-builder`
  vectors.
- **M3d.** `engine-state` test fixtures rewrite for new schema (10
  sites). Byte-identical-derivation test simplifies (no fallback
  branch).
- **M3e.** No test changes (doc-only).

### §4.5 PR sequencing & parallelism

```
M3a (foundation)
 ├─→ M3b (scanner reroute + source switch)
 │    └─→ M3d (schema cleanup; property activates) ──→ M3e (docs)
 └─→ M3c (additive test caller)              ──→ M3d
```

M3b and M3c can merge in parallel. Both depend on M3a; both
are prerequisites for M3d. M3e depends on M3d only.

The honest critical path is `M3a → M3b → M3d → M3e` (4 PRs serial); 3c
can land any time between M3a and M3d without blocking the path.

---

## §5 Operational concerns

### §5.1 `dev` branch freeze

See top-of-document FREEZE NOTICE. Restated for completeness:

- **Window.** M3a opens → M3d merges. (M3e is exempt; doc-only.)
- **Estimated duration.**
  - Best-case: 5–7 working days. Floor of the
    `06-branching.mdc` short-lived-branch ceiling, conditional on
    no PR surfacing an unexpected blocker.
  - Realistic: 8–12 working days. Sized to absorb one substantive
    blocker (review-cycle questions, pre-flight scope expansion, or
    refactor surprises during M3b's source-switch) without
    invalidating the freeze. Stage 1 PR 2 ran multiple weeks; the
    realistic estimate reflects that experience.
  - Headline tracking: this section and the FREEZE NOTICE track
    the realistic estimate. Best-case is recorded for reference and
    used to evaluate progress, not as the planning baseline.
- **Per-PR contingency.** If any single PR is blocked beyond
  5 working days from open to merge, re-evaluate at that boundary:
  pause-and-assess (drop the freeze; allow `dev` to proceed while the
  blocker is resolved) is the default; continuing requires explicit
  rationale recorded in the assessment note. The pause-and-assess
  default reflects that a blocked migration PR holding up `dev` has
  worse compounding cost than a temporary freeze lift.
- **Lift condition.** M3d merges to `dev`.
- **Exemptions.** Critical security fixes; CI infrastructure repairs.
- **Authoring discipline.** Per `06-branching.mdc`, no contributor
  pushes to `dev` during the freeze without explicit migration-plan-compatible
  coordination. Each PR opens against `dev` HEAD at the
  time of opening; no rebase-onto-`dev` cycles needed if the freeze
  holds.

### §5.2 Coordination with wallet RPC server cutover (V3.2)

The wallet RPC server cutover is a separate workstream (V3.2 per
`docs/FOLLOWUPS.md` §V3.0 line 755, §V3.1 wallet_rpc_server entries).
This migration plan does not block on it, and it does not block on
this migration plan.

The cutover will:
- Remove the FFI signing paths (`shekyl-ffi/src/lib.rs:3127, 3305, 3331`).
- Remove the `transfer_native` path (`engine-rpc/src/engine.rs:388–479`)
  and the `native-sign` feature.
- Introduce production callers of `KeyEngine::sign_transaction` to
  replace what the wallet2 paths did.

If the cutover begins before M3d merges, the cutover work plans
against the post-migration `KeyEngine` API (the trait surface stable
at M3a's merge). If the cutover begins after M3d, the
"removed paths" set is unambiguous.

**No cross-workstream changes are required by either side during the
freeze window.**

### §5.3 v31 multisig pre-flight

Audit §4 confirmed structural alignment; expected outcome is "no
concurrent migration required." M3a includes a pre-flight
verification step:

- Re-inspect `rust/shekyl-engine-core/src/multisig/` at M3a HEAD.
- Confirm public types still carry public material only.
- Confirm per-signer secret state still resides in session-scoped
  containers.
- Confirm message-passing surfaces still carry public material only.

If the inspection finds drift, M3a's description records the
finding and the migration plan adds a small concurrent-migration
sub-PR (sequenced before M3d). Expected outcome: no drift.

### §5.4 `docs/FOLLOWUPS.md` entries

This migration plan implies the following `FOLLOWUPS.md` updates,
landing in M3e:

**Add (V3.0 close-records, audit trail):**
- "PR 3 architectural-inheritance migration complete (M3a–M3e
  per `STAGE_1_PR_3_MIGRATION_PLAN.md`)."
- "TransferDetails secret-bearing fields removed; secrets confined
  to engine via deterministic handle derivation (cSHAKE256;
  re-derive from `(view_secret, source_ciphertext)` per design
  doc §7.12) (M3d)."

**Update:**
- §V3.1 line 259 (`Stage 2 — KeyEngine migration to actor`):
  cross-reference the post-migration trait surface; note that the
  Stage 2 actor migration builds on the now-stable `KeyEngine` API.
- §V3.0 line 755 (transfer_details C++ migration): cross-reference
  to this migration's `TransferDetails` schema as the now-stable
  Rust target.

**Close (if present):**
- Any V3.0 entry that references the pre-migration `TransferDetails`
  schema as the open question (the schema is settled at M3d).

M3a and M3b do not edit `FOLLOWUPS.md`; the entries land at
M3e with the rest of the documentation realignment.

---

## §6 Open questions / explicit deferrals

1. **Cross-crate test-fixture visibility for M3c.** M3c needs
   access to `tx-builder`'s test vectors from `engine-core` tests.
   If `pub(crate)` visibility prevents this, M3c either (a) moves
   the vectors to a shared `dev-dependencies` test-utility crate, or
   (b) duplicates a small fixture into `engine-core`'s test tree.
   Decision deferred to M3c's draft phase; either resolution is
   acceptable.

2. **~~`HandleTable` size bound.~~** Closed at M3a pre-flight:
   dissolved by design doc §7.11=(3). The engine holds no
   handle-table state; no size bound, eviction policy, or shard
   layout exists to set. Preserved here as a closure cross-reference
   per `15-deletion-and-debt.mdc`'s "items get a target version
   or get closed" rule.

3. **Byte-identical-derivation test scope (M3b property).** The
   test compares re-derive-from-`source_ciphertext` output against
   legacy-`TransferDetails`-fields output for the same input
   ciphertext + tx context; both paths are deterministic by
   construction (cSHAKE256 derivation + ML-KEM-768 decap on the
   primary path; direct field reads on the fallback path), so the
   property test is deterministic without further qualification.
   No deferral needed.

4. **M3c → cutover handoff documentation.** M3c's test caller
   is the canonical example of how the post-cutover production
   caller will look. M3e's docs should anchor this with a "the
   wallet RPC cutover replaces the wallet2-bridged paths with a
   production caller of the same shape as `key_engine_sign_e2e.rs`"
   note. Light touch; not a deferral, just an explicit documentation
   item.

5. **Audit re-run trigger.** Per `MIGRATION_AUDIT.md` §7.4, the
   audit re-runs as M3a pre-flight if `dev` has advanced beyond
   `ffcaa62e9` when M3a opens. The freeze (§5.1) is the structural
   mitigation; the re-run is the residual fallback. Re-run takes
   <30 minutes per audit's documented methodology.

---

## §7 Audit citations

This plan's substantive findings derive from
`STAGE_1_PR_3_MIGRATION_AUDIT.md`. The audit-cited claims are:

- "Production SpendInput construction outside FFI/native-sign: zero"
  → audit §1, §5.
- "Production TransferDetails secret-field read sites: zero" →
  audit §2.3, §5.
- "Single production write site at `ledger_ext.rs:125–129`" →
  audit §2.2, §5.
- "Non-wallet2-bridged `tx_builder::sign_transaction` callers: zero"
  → audit §3, §5.
- "v31 multisig structurally aligned" → audit §4.
- "5-PR sequence collapse rationale" → audit §1 implication-for-PR-3a,
  audit §6.

If the audit's findings change (e.g., a runtime path the static
audit missed surfaces during M3a's CI), the migration plan's
scope tables reopen for revision before the affected PR drafts.

---

## §8 Document trajectory

This document is operational; its lifetime is the migration's
duration. Per `15-deletion-and-debt.mdc`:

- **Active phase.** M3a–M3e in flight. Document is the source of
  truth on per-PR scope and sequencing.
- **Post-migration.** M3e closes the migration. This document
  is retained as historical record (the migration's audit trail)
  alongside `STAGE_1_PR_3_KEY_ENGINE.md` (now the operative design
  doc) and `STAGE_1_PR_3_MIGRATION_AUDIT.md` (now the historical
  audit snapshot).
- **Long-term.** When the wallet RPC cutover lands and removes the
  excluded sites enumerated in §2, this document's §2 row count
  drops to zero. Document remains as the precedent for the
  architectural-inheritance discipline's first application.

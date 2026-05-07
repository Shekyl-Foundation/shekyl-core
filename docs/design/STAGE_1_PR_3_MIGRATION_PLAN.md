# Stage 1 PR 3 — Migration Plan

**Status.** Operational plan for the Stage 1 PR 3 architectural-
inheritance migration (PRs 3a–3e). Companion document to
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

## 🔒 FREEZE NOTICE

> **`dev` branch is frozen for non-migration work for the duration of
> PRs 3a–3e.** Per `06-branching.mdc` discipline against long-lived
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
> **Freeze duration.** Best estimate per audit §6.6: PRs 3a–3d land
> within 5 working days. PR 3e (docs) lands the same day or next.
> Total freeze: ~5–7 working days. Updated as PRs land.
>
> **Lift condition.** PR 3d merges (the property-activating PR);
> PR 3e is doc-only and can land in parallel with the freeze lift.

---

## §1 Scope summary

### §1.1 In scope

- Introduction of the `KeyEngine` trait and the `LocalKeys` bridge
  implementation (PR 3a).
- Reroute of the scanner's secret-emit path from
  `TransferDetails` write to `KeyEngine::try_claim_output` (PR 3b).
- Bridge-implementation secret-source switch from `TransferDetails`
  fields to `HandleTable` lookups, with `TransferDetails` retained as
  transitional fallback (PR 3b).
- Additive end-to-end test caller validating `KeyEngine::sign_transaction`
  produces byte-identical output to the legacy direct-secret path
  (PR 3c).
- Removal of secret-bearing fields from `TransferDetails`; addition of
  `source_ciphertext` and `output_handle`; removal of bridge-impl
  fallback (PR 3d).
- Documentation realignment across `STAGE_1_PR_3_KEY_ENGINE.md`,
  `STAGE_1_PR_3_MIGRATION_AUDIT.md`, `CHANGELOG.md`, and
  `docs/FOLLOWUPS.md` (PR 3e).

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

The `transfer_native` exclusion (row 2) is per the architectural-
inheritance rule's "inherited code with a deletion target doesn't get
migrated; it gets deleted" disposition (`16-architectural-inheritance.mdc`
§"When to migrate vs. when to keep"). Migrating `transfer_native`
would mean migrating a path whose only forward state is deletion.

---

## §3 Per-PR specifications

### §3.1 PR 3a — trait + bridge impl + engine-internal SpendInput

**Title.** `feat(engine): introduce KeyEngine trait and LocalKeys bridge impl`

**Scope.**

- Define `KeyEngine` trait in `shekyl-engine-core/src/engine/traits/key.rs`
  per `STAGE_1_PR_3_KEY_ENGINE.md` Round 3 surface
  (workflow-shaped methods including `try_claim_output`,
  `sign_transaction`, `sign_pqc_auth`, `address_for_subaddress`).
- Implement `LocalKeys` (production-only, `from_seed` /
  `#[cfg(test)] from_test_seed` constructors per the no-Mock pattern
  from `KEY_ENGINE.md` §2.1.2).
- Implement engine-internal `SpendInput` construction inside
  `LocalKeys::sign_transaction`. Bridge sources secrets from
  `TransferDetails`'s existing secret-bearing fields (transitional;
  PR 3b switches the source).
- Introduce `HandleTable` (16-shard `std::sync::RwLock` cache;
  FIFO eviction) per Round 3 §3.1.6. Empty at PR 3a; populated at
  PR 3b.
- Introduce `OutputHandle` deterministic-derivation
  (`HMAC(view_secret, canonical(tx_hash || output_index))[..16]`) per
  Round 3 §7.12.
- v31 multisig pre-flight verification: confirm the audit's §4
  structural-alignment finding still holds at HEAD; produce a one-
  line confirmation comment in the PR description.
- Initial test substrate: unit tests for `LocalKeys::from_test_seed`
  determinism, handle-table sharding, handle deterministic derivation.

**Files touched (estimated).**

- New: `rust/shekyl-engine-core/src/engine/traits/key.rs` (~300 lines).
- New: `rust/shekyl-engine-core/src/engine/local_keys.rs` (~600 lines
  including impl + handle table + tests).
- New: `rust/shekyl-engine-core/src/engine/handle.rs` (~150 lines).
- Edit: `rust/shekyl-engine-core/src/engine/mod.rs` (re-exports).
- New: `rust/shekyl-engine-core/tests/key_engine_unit.rs` (~200 lines).

**Dependencies.** None (foundation PR).

**Schema state at PR boundary.** `TransferDetails` unchanged. Bridge
impl reads secrets from `TransferDetails`'s existing fields.

**Property delivery.** None. Substrate.

**Success criteria.**

- Workspace compiles; existing tests green.
- `LocalKeys` production-only (`#[cfg(not(test))]` paths exclude any
  test-only constructor).
- Handle-table sharding test exercises ≥2 shards under contention.
- v31 multisig pre-flight comment in PR description.
- No public API change to existing crates outside `shekyl-engine-core`.

**Estimated review surface.** ~1300 lines added; zero deleted; ~5
files edited including re-exports.

---

### §3.2 PR 3b — scanner reroute + bridge source switch

**Title.** `feat(engine): reroute scanner secrets via KeyEngine handle table`

**Scope.**

- Edit `rust/shekyl-scanner/src/ledger_ext.rs:125–129` (the
  audit's load-bearing single-site change): scanner emits
  `OutputClaim` to `KeyEngine::try_claim_output` instead of
  populating `TransferDetails`'s secret-bearing fields directly.
- Engine populates `HandleTable` from the claim; orchestrator
  receives `OutputHandle` and `source_ciphertext` to persist on
  `TransferDetails`. (The schema additions land in PR 3d; for PR 3b,
  the secret-bearing fields remain populated as before to keep the
  bridge-impl fallback live.)
- Switch `LocalKeys::sign_transaction`'s primary secret source from
  `TransferDetails`'s secret fields to `HandleTable` lookups, with
  `TransferDetails` as transitional fallback (selected by feature-
  detection, not feature flag — if the handle resolves, use it; else
  fall through to `TransferDetails`).
- Test fixtures in `rust/shekyl-scanner/src/tests.rs:77, 855, 1037`
  rewrite to exercise the engine-mediated flow.
- Add byte-identical-derivation property test: for the same input
  ciphertext + tx context, `HandleTable`-resolved secrets must equal
  `TransferDetails`-resolved secrets bit-for-bit. This is the audit's
  cross-PR safety property; failure indicates a bug in either path.

**Files touched (estimated).**

- Edit: `rust/shekyl-scanner/src/ledger_ext.rs` (~30 lines net).
- Edit: `rust/shekyl-scanner/src/tests.rs` (~150 lines net).
- Edit: `rust/shekyl-engine-core/src/engine/local_keys.rs` (~80 lines
  net for source-switch + fallback logic).
- New: `rust/shekyl-engine-core/tests/byte_identical_derivation.rs`
  (~100 lines).

**Dependencies.** PR 3a (trait + bridge impl + handle table).

**Schema state at PR boundary.** `TransferDetails` carries both old
secret-bearing fields (still populated) and is referenced by
`OutputHandle` in the handle table. Two parallel sources exist
transitionally.

**Property delivery.** Partial. Engine cache populated; orchestrator
copy still present. Property "secrets confined to engine" not yet
active (orchestrator-side copies remain).

**Success criteria.**

- Workspace compiles; all existing tests green.
- Byte-identical-derivation property test passes.
- `OutputHandle` populated for every output the scanner ingests.
- Bridge impl exercises `HandleTable` primary path on at least one
  end-to-end test; fallback path covered by an explicit fallback test.

**Estimated review surface.** ~360 lines net; one production write
site moved; one new property test.

---

### §3.3 PR 3c — additive test caller

**Title.** `test(engine): exercise KeyEngine::sign_transaction end-to-end`

**Scope.**

- Add a Rust integration test in `rust/shekyl-engine-core/tests/`
  (suggested name: `key_engine_sign_e2e.rs`) that:
  1. Constructs a synthetic transaction prefix using existing
     `tx-builder` test vectors.
  2. Populates a `LocalKeys` instance with handles for the inputs.
  3. Calls `KeyEngine::sign_transaction(tx_prefix_hash, &handles, ...)`.
  4. Verifies the resulting `SignedProofs` against the existing
     `tx_builder::sign_transaction` test-vector outputs (byte-
     identical signatures, commitments, proofs).
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

**Dependencies.** PR 3a (trait + bridge). Independent of PR 3b in
scope (test populates `HandleTable` directly via fixture, not via
scanner reroute), so PR 3c can merge in parallel with PR 3b.

**Schema state at PR boundary.** Unchanged from incoming.

**Property delivery.** Validation milestone. Not a property delivery,
but the precondition for trusting PR 3d's removal of fallback paths.

**Success criteria.**

- Test passes against ≥3 existing `tx-builder` test vectors.
- Test produces byte-identical `SignedProofs` to the legacy path.
- Test runs in <1 s (engine-internal construction is not a
  performance regression).

**Estimated review surface.** ~250 lines added; minimal
cross-crate friction.

---

### §3.4 PR 3d — schema cleanup; property activates

**Title.** `feat(engine): remove TransferDetails secret fields; secrets confined to engine`

**Scope.**

- Remove from `rust/shekyl-engine-state/src/transfer.rs:86–98` the
  five secret-bearing fields:
  - `combined_shared_secret: Option<Zeroizing<[u8; 64]>>`
  - `ho: Option<Zeroizing<[u8; 32]>>`
  - `y: Option<Zeroizing<[u8; 32]>>`
  - `z: Option<Zeroizing<[u8; 32]>>`
  - `k_amount: Option<Zeroizing<[u8; 32]>>`
- Add to the same struct:
  - `source_ciphertext: HybridCiphertext`
  - `output_handle: OutputHandle`
- Update `Zeroize` / `Drop` impls; update postcard schema; update
  serde helpers.
- Remove the bridge impl's `TransferDetails`-fallback path in
  `LocalKeys::sign_transaction`. Post-PR 3d, handles are the only
  secret source.
- Rewrite test/bench fixtures per audit §2.4 (10 sites).
- Update the scanner's `TransferDetailsExt::populate_*` helpers
  in `ledger_ext.rs` to write the new fields instead of the removed
  ones (the write site moved to engine in PR 3b; the helper now
  populates `source_ciphertext` and `output_handle` only).

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

**Dependencies.** PR 3a, 3b, 3c. PR 3c is a hard dependency: removing
the fallback without the byte-identical-derivation property test
having validated the engine path is unsafe.

**Schema state at PR boundary.** `TransferDetails` carries
`source_ciphertext` + `output_handle` instead of the five secret-
bearing fields. Bridge impl exclusively uses `HandleTable`.

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
- The byte-identical-derivation property test from PR 3b continues to
  pass (now exercising only the handle path, since fallback is gone).
- `git grep -E 'combined_shared_secret|\\.ho\\b|\\.k_amount'` returns
  zero hits in `rust/` excluding `shekyl-crypto-pq` (which owns the
  derivation primitives) and `shekyl-proofs` (which uses derived
  fields by their ProofSecrets type, distinct from TransferDetails).

**Estimated review surface.** ~225 lines net (mostly deletes with
small additions for the new fields). The largest single per-file
change is the bridge impl's fallback removal (~50 lines).

---

### §3.5 PR 3e — documentation realignment

**Title.** `docs: STAGE_1_PR_3 — post-migration realignment`

**Scope.**

- Update `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` to reflect
  post-migration architecture as the operative design (Round 3's
  handle-indirected workflow becomes the sole architecture; pre-
  migration framing moves to a "history" section or is deleted).
- Update `docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md` snapshot
  reference to the post-3d HEAD.
- Update `docs/CHANGELOG.md` per `91-documentation-after-plans.mdc`
  with one entry per merged PR (3a, 3b, 3c, 3d).
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

**Dependencies.** PR 3d (post-migration architecture must be the
operative one before docs realign to it).

**Schema state at PR boundary.** Unchanged from PR 3d.

**Property delivery.** None (doc-only).

**Success criteria.**

- All documentation is internally consistent against the post-
  migration architecture.
- No reference to removed `TransferDetails` fields exists outside
  git history.
- `CHANGELOG.md` has a complete record of the migration's user-
  visible effects (zero, since RPC contract is migration-transparent
  per audit §2.5; the CHANGELOG entries note this explicitly).

**Estimated review surface.** Doc-only; depends on `KEY_ENGINE.md`'s
post-migration update size. PR 3e can land same-day or next-day
after PR 3d; freeze lifts at PR 3d's merge.

---

## §4 Cross-PR concerns

### §4.1 Property delivery timeline

| PR | Property state |
|---|---|
| 3a | Substrate. No property delivered. |
| 3b | Engine cache populated. Property partial: orchestrator copy still present. |
| 3c | Validation milestone. No property change. |
| 3d | **"Secrets confined to engine" activates.** |
| 3e | None (doc-only). |

The "secrets confined to engine" property activates at PR 3d's
merge. Earlier framing in design rounds anchored this to PR 3a;
the audit and the 5-PR collapse moved it to PR 3d, which is honest
about when the orchestrator's `TransferDetails` actually stops
carrying derived secrets.

### §4.2 Bridge impl secret-source evolution

| PR | Primary source | Fallback | Both populated? |
|---|---|---|---|
| 3a | `TransferDetails` fields | — | n/a (only `TransferDetails` exists) |
| 3b | `HandleTable` | `TransferDetails` fields | Yes (transitional) |
| 3c | (unchanged from 3b) | (unchanged) | Yes |
| 3d | `HandleTable` | — | No (`TransferDetails` fields removed) |

The fallback at PR 3b is feature-detected, not feature-flagged: if
the handle resolves, use it; if not, fall through. This means the
fallback does not require any explicit "switch" at PR 3d — just the
removal of the source the fallback would have read.

### §4.3 Schema state at each PR boundary

| PR | `TransferDetails` carries |
|---|---|
| Pre-3a | 5 secret-bearing fields (legacy) |
| 3a | (unchanged) |
| 3b | 5 secret-bearing fields (legacy, still populated; transitional fallback live) |
| 3c | (unchanged) |
| 3d | `source_ciphertext` + `output_handle` (only). 5 legacy fields removed. |
| 3e | (unchanged) |

### §4.4 Test substrate evolution

- **PR 3a.** New unit tests for `LocalKeys`, handle table, handle
  derivation. Existing scanner / engine-state tests untouched.
- **PR 3b.** Scanner test fixtures rewrite to engine-mediated flow.
  New byte-identical-derivation property test.
- **PR 3c.** New end-to-end engine signing test against `tx-builder`
  vectors.
- **PR 3d.** `engine-state` test fixtures rewrite for new schema (10
  sites). Byte-identical-derivation test simplifies (no fallback
  branch).
- **PR 3e.** No test changes (doc-only).

### §4.5 PR sequencing & parallelism

```
3a (foundation)
 ├─→ 3b (scanner reroute + source switch)
 │    └─→ 3d (schema cleanup; property activates) ──→ 3e (docs)
 └─→ 3c (additive test caller)              ──→ 3d
```

PR 3b and PR 3c can merge in parallel. Both depend on PR 3a; both
are prerequisites for PR 3d. PR 3e depends on PR 3d only.

The honest critical path is `3a → 3b → 3d → 3e` (4 PRs serial); 3c
can land any time between 3a and 3d without blocking the path.

---

## §5 Operational concerns

### §5.1 `dev` branch freeze

See top-of-document FREEZE NOTICE. Restated for completeness:

- **Window.** PR 3a opens → PR 3d merges. (PR 3e is exempt; doc-only.)
- **Estimated duration.** 5–7 working days per audit §6.
- **Lift condition.** PR 3d merges to `dev`.
- **Exemptions.** Critical security fixes; CI infrastructure repairs.
- **Authoring discipline.** Per `06-branching.mdc`, no contributor
  pushes to `dev` during the freeze without explicit migration-plan-
  compatible coordination. Each PR opens against `dev` HEAD at the
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

If the cutover begins before PR 3d merges, the cutover work plans
against the post-migration `KeyEngine` API (the trait surface stable
at PR 3a's merge). If the cutover begins after PR 3d, the
"removed paths" set is unambiguous.

**No cross-workstream changes are required by either side during the
freeze window.**

### §5.3 v31 multisig pre-flight

Audit §4 confirmed structural alignment; expected outcome is "no
concurrent migration required." PR 3a includes a pre-flight
verification step:

- Re-inspect `rust/shekyl-engine-core/src/multisig/` at PR 3a HEAD.
- Confirm public types still carry public material only.
- Confirm per-signer secret state still resides in session-scoped
  containers.
- Confirm message-passing surfaces still carry public material only.

If the inspection finds drift, PR 3a's description records the
finding and the migration plan adds a small concurrent-migration
sub-PR (sequenced before PR 3d). Expected outcome: no drift.

### §5.4 `docs/FOLLOWUPS.md` entries

This migration plan implies the following `FOLLOWUPS.md` updates,
landing in PR 3e:

**Add (V3.0 close-records, audit trail):**
- "PR 3 architectural-inheritance migration complete (PRs 3a–3e
  per `STAGE_1_PR_3_MIGRATION_PLAN.md`)."
- "TransferDetails secret-bearing fields removed; secrets confined
  to engine via HandleTable (PR 3d)."

**Update:**
- §V3.1 line 259 (`Stage 2 — KeyEngine migration to actor`):
  cross-reference the post-migration trait surface; note that the
  Stage 2 actor migration builds on the now-stable `KeyEngine` API.
- §V3.0 line 755 (transfer_details C++ migration): cross-reference
  to this migration's `TransferDetails` schema as the now-stable
  Rust target.

**Close (if present):**
- Any V3.0 entry that references the pre-migration `TransferDetails`
  schema as the open question (the schema is settled at PR 3d).

PR 3a and PR 3b do not edit `FOLLOWUPS.md`; the entries land at
PR 3e with the rest of the documentation realignment.

---

## §6 Open questions / explicit deferrals

1. **Cross-crate test-fixture visibility for PR 3c.** PR 3c needs
   access to `tx-builder`'s test vectors from `engine-core` tests.
   If `pub(crate)` visibility prevents this, PR 3c either (a) moves
   the vectors to a shared `dev-dependencies` test-utility crate, or
   (b) duplicates a small fixture into `engine-core`'s test tree.
   Decision deferred to PR 3c's draft phase; either resolution is
   acceptable.

2. **`HandleTable` size bound.** Round 3 §7.10 framed this as a
   capacity-bounded FIFO eviction policy. The exact bound is not
   set by this plan; PR 3a draws a default (suggested: 4096 handles
   per shard × 16 shards = 65k handles, ample for typical wallets)
   and the migration-plan-final review can revisit. Bound changes
   are non-breaking post-3a (cache-internal).

3. **Byte-identical-derivation test scope (PR 3b property).** The
   test must be deterministic across shards (the `HandleTable`'s
   shard assignment is content-addressed by handle, so deterministic).
   If a future change introduces non-determinism (e.g., parallel
   eviction), the property test catches it. No deferral needed.

4. **PR 3c → cutover handoff documentation.** PR 3c's test caller
   is the canonical example of how the post-cutover production
   caller will look. PR 3e's docs should anchor this with a "the
   wallet RPC cutover replaces the wallet2-bridged paths with a
   production caller of the same shape as `key_engine_sign_e2e.rs`"
   note. Light touch; not a deferral, just an explicit documentation
   item.

5. **Audit re-run trigger.** Per `MIGRATION_AUDIT.md` §7.4, the
   audit re-runs as PR 3a pre-flight if `dev` has advanced beyond
   `ffcaa62e9` when PR 3a opens. The freeze (§5.1) is the structural
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
audit missed surfaces during PR 3a's CI), the migration plan's
scope tables reopen for revision before the affected PR drafts.

---

## §8 Document trajectory

This document is operational; its lifetime is the migration's
duration. Per `15-deletion-and-debt.mdc`:

- **Active phase.** PRs 3a–3e in flight. Document is the source of
  truth on per-PR scope and sequencing.
- **Post-migration.** PR 3e closes the migration. This document
  is retained as historical record (the migration's audit trail)
  alongside `STAGE_1_PR_3_KEY_ENGINE.md` (now the operative design
  doc) and `STAGE_1_PR_3_MIGRATION_AUDIT.md` (now the historical
  audit snapshot).
- **Long-term.** When the wallet RPC cutover lands and removes the
  excluded sites enumerated in §2, this document's §2 row count
  drops to zero. Document remains as the precedent for the
  architectural-inheritance discipline's first application.

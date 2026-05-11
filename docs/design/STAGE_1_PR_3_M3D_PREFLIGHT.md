# Stage 1 PR 3 — M3d pre-flight investigation

**Status.** Read-only investigation. No code changes proposed yet.
This document re-anchors M3d against its actual structural state on
`dev` post-M3c (PR #38 merged at `e6efaf5b5`), surfaces one named
divergence between the
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§3.4 wording and what is implementable today, and disposes the
remaining open design questions before Phase 2 begins.

**Branch.** `feat/stage-1-pr3-m3d` off `dev` at `e6efaf5b5` (post
M3c/PR #38 merge). Pre-flight commits land here before
implementation begins.

**Cross-references.**

- **Migration plan.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.4 (M3d — schema cleanup; property activates) is the binding
  scope statement. §4.1 names M3d as the property-activating PR
  ("Secrets confined to engine"). §4.2 / §4.3 record the
  bridge-impl secret-source evolution and per-PR schema state.
- **Audit.**
  [`STAGE_1_PR_3_MIGRATION_AUDIT.md`](./STAGE_1_PR_3_MIGRATION_AUDIT.md)
  §2.1 enumerates the five legacy fields scheduled for removal;
  §2.2 names the single production write site; §2.3 confirms zero
  production read sites; §2.4 enumerates the ten test/bench
  fixture sites to clean up; §2.5 confirms RPC-transparent
  migration.
- **M3b landing notes.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.2 ("Landing notes (M3b closed)") records the M3b
  divergences. Sub-commit 8 (`populate_engine_handle_fields`) is
  the post-pass M3d depends on; sub-commit 4 added the
  `source_ciphertext + output_handle` schema fields that M3d
  promotes to the only secret-source path.
- **M3c landing notes.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.3.1 records the M3c-via-C disposition and the Trim-1
  property-strengthening at the `SpendInput` layer. M3c's named
  coverage gap (legacy `sign_transaction` end-to-end execution)
  is bounded by M3d's lifetime since M3d is the next-but-one
  legacy-removal PR in the sequence.
- **Property-delivery framing.**
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md)
  §3.3 / §7.10–§7.13 define the engine-confined-secrets property
  M3d activates. §7.12 specifies the cSHAKE256 handle derivation
  that the post-M3d signing path resolves against
  `(view_secret, source_ciphertext)`.

---

## §1 Audit invariants — re-verification on `dev` tip `e6efaf5b5`

| # | Invariant | Audit citation | Verification command | Result |
|---|---|---|---|---|
| 1 | Five legacy secret-bearing fields still present on `TransferDetails` | AUDIT §2.1 | `rg -n 'pub (combined_shared_secret\|ho\|y\|z\|k_amount):' rust/shekyl-engine-state/src/transfer.rs` | ✅ Lines `91, 94, 97, 100, 103`. Schema mirror (`TransferDetailsSchema`) carries the same five at lines `245–249`. M3d removes both groups. |
| 2 | Single production write site at `ledger_ext.rs:148–152` | AUDIT §2.2 | `rg -n 'td\.(combined_shared_secret\|ho\|y\|z\|k_amount)\s*=' rust/` | ✅ Only `rust/shekyl-scanner/src/ledger_ext.rs:148–152` (five writes) outside the `transfer.rs::tests` schema round-trip fixture at lines `381–385`. **One production write site, line shift +24 from the audit's pinned 124–129 (post-M3b ledger-ext rework).** |
| 3 | Zero production read sites of legacy fields | AUDIT §2.3 | `rg -n '\.(combined_shared_secret\|k_amount)' rust/ --type rust` filtered against `shekyl-crypto-pq` (owns derivation primitives), test/bench files, and the schema mirror | ✅ Outside `shekyl-crypto-pq`'s `OutputSecrets` / `ProofSecrets` types (distinct from `TransferDetails`) and outside test/bench fixtures, **no production code reads `td.combined_shared_secret`, `td.ho`, `td.k_amount` (or `td.y` / `td.z`)**. Removing the fields affects no production read site. |
| 4 | `populate_engine_handle_fields` populates `source_ciphertext + output_handle` for every newly-inserted transfer | M3b sub-commit 8 | Read `rust/shekyl-engine-core/src/engine/merge.rs:546–605` | ✅ M3b post-pass is in place; every transfer inserted by `apply_scan_result_to_state` is bound to its on-chain `source_ciphertext` and the deterministic `OutputHandle` (cSHAKE256 over `view_secret \|\| tx_hash \|\| output_index`). Idempotent; partial-population respected. Four unit tests at `merge.rs:1077–1300` pin the contract. The post-pass is the precondition that makes M3d's legacy-field removal safe. |
| 5 | `LocalKeys::sign_transaction` is the PR-5-pinned named-gap stub (no fallback to remove) | M3a Round 4a + M3c landing notes | Read `rust/shekyl-engine-core/src/engine/local_keys.rs:531–543` | ⚠ **Divergence vs plan §3.4 wording** (see §2 D1 below). The bridge impl is a stub returning `KeyEngineError::SignTransactionTraitSurfaceIncomplete`; it has never read legacy `TransferDetails` fields. Plan §3.4's "Remove the bridge impl's legacy-`TransferDetails`-fallback path" bullet is therefore vacuous against the current state. |
| 6 | `LEDGER_BLOCK_VERSION` and `WALLET_LEDGER_FORMAT_VERSION` are both at `3` post-M3b | M3b sub-commit 4 | `rg -n 'pub const LEDGER_BLOCK_VERSION\|pub const WALLET_LEDGER_FORMAT_VERSION' rust/shekyl-engine-state/src/` | ✅ `LEDGER_BLOCK_VERSION = 3` (`ledger_block.rs:81`); `WALLET_LEDGER_FORMAT_VERSION = 3` (`wallet_ledger.rs:78`). M3d bumps both 3 → 4. |
| 7 | v31 multisig structurally aligned (no `TransferDetails` references in `multisig/`) | AUDIT §4 | `rg 'TransferDetails\|combined_shared_secret\|k_amount' rust/shekyl-engine-core/src/multisig/` | ✅ No matches across `multisig/{dkg,group,mod,signing,tests}.rs` and `multisig/v31/`. **No drift; M3d changes do not interact with multisig.** |

**Invariants 1, 2, 3, 4, 6, 7 hold; invariant 5 reveals a plan-vs-state divergence disposed in §2 D1.** No re-triage required; M3d can proceed.

---

## §2 Disposition D1–D5

### D1 — Plan §3.4 "remove bridge-impl fallback" wording vs. current bridge-impl state

**Decision.** Acknowledge the plan-vs-state divergence in the M3d landing notes; do not write any "remove fallback" code in `LocalKeys::sign_transaction`. The bridge impl remains the PR-5-pinned named-gap stub at the M3d boundary; M3d's scope is exclusively the schema / write-site / fixture / version / snapshot work.

**Discipline grounding.**

- Per `16-architectural-inheritance.mdc` "what does this deliver against the threat model?" framing: plan §3.4's "remove fallback" bullet was written under the assumption that the bridge impl in `LocalKeys::sign_transaction` would, at the M3d boundary, contain a feature-detected branch reading legacy `TransferDetails` fields when `source_ciphertext.is_none()`. That branch was never written, because the trait method's body remained PR-5-pinned (`TxToSign.outputs` and `.fcmp_plus_plus_context` are forward-declared empty stubs per design doc Round 3 §3.3 Divergence 3).
- Per `15-deletion-and-debt.mdc` "default: delete": code that doesn't exist doesn't need deleting. The plan's wording reflects a pre-M3a design assumption (bridge impl exists at M3a boundary); the M3a Round 4a `pub(crate)` visibility lock and the PR-5-pinned `TxToSign` shape combined to defer the bridge impl past M3d. Plan §3.4 carries the residue of the earlier assumption.
- Per `16-architectural-inheritance.mdc` "pre-flight literal vs underlying property" (cited in M3c pre-flight §2.1.1 Trim-1 disposition): the plan's literal wording is the means; the underlying property is the end. The underlying property at M3d is "secrets confined to engine" (per plan §4.1 / §4.2 M3d row). That property is delivered by the schema/write-site removal alone; the fallback-removal bullet was a means under a different bridge-impl assumption.

**M3c parallel.** M3c's pre-flight similarly disposed of plan §3.3's "byte-identical `SignedProofs`" wording against the actual `OsRng`-driven `tx_builder::sign_transaction` (M3c pre-flight §2.1 Option C). Both divergences share the same root cause: the migration plan was written before the M3a Round 4a workflow-shape pivot (per `STAGE_1_PR_3_KEY_ENGINE.md` §2.1.1), which deferred the bridge impl. M3d's disposition is the M3c-pattern applied a second time: name the divergence; deliver the underlying property; record the divergence in the landing notes for `MIGRATION_PLAN.md` §3.4.

**Rejected alternatives.**

- **(a) Write the bridge impl in M3d to give the "remove fallback" bullet something to remove.** Rejected: pulls PR-5 scope (the `TxToSign` shape finalization) into M3d, multiplying the review surface and breaking the per-PR scope discipline established at M3a Round 4a. M3d is schema cleanup; PR-5 is signing-trait completion.
- **(b) Defer M3d until PR-5 lands, then run the original plan §3.4 wording verbatim.** Rejected on `16-architectural-inheritance.mdc` pre-genesis-discount grounds: the orchestrator-side `TransferDetails` carrying derived per-output secrets is the architectural-inheritance finding M3d resolves. Deferring it past PR-5 would mean shipping V3.0 with the legacy secret-bearing schema for a longer window than necessary, contradicting the priority-1 (security) commitment in `00-mission.mdc`. The structural fix is bounded pre-genesis; deferral compounds cost.
- **(c) Re-author plan §3.4 in this pre-flight, leaving the migration plan's wording authoritative.** Rejected: the plan's per-PR sections are read by future maintainers as the binding scope. Silent deviation between plan and execution is a discipline failure. The pre-flight surfaces the divergence; M3d's landing-notes commit updates the plan with the corrected wording, the same pattern M3b sub-commit 11 and M3c commit 3 followed.

### D2 — Version-constant bump policy: bump both, or bump conditionally

**Decision.** Bump both `LEDGER_BLOCK_VERSION` (3 → 4) and `WALLET_LEDGER_FORMAT_VERSION` (3 → 4) unconditionally. Both `.snap` schema snapshots are regenerated; the per-block version drift check (`ledger_block.rs:230, 627–632`) and the wallet-format drift check (`wallet_ledger.rs:166`) both refuse pre-M3d state.

**Rationale.**

- Per `15-deletion-and-debt.mdc` pre-V3-launch: `rm -rf ~/.shekyl` is the only migration path. There is no on-disk state to migrate; version bumps exist as a CI-blocking drift detector (per `schema_snapshot.rs:27–28` cross-reference convention), not as a runtime migration boundary.
- Per the `wallet_ledger.rs:67` docstring ("Each per-block bump (`LEDGER_BLOCK_VERSION`, ...) implies a `WALLET_LEDGER_FORMAT_VERSION` bump"): the convention is that any per-block-schema change (including field removals) propagates to the aggregator version. M3d removes 5 fields from `TransferDetails`, which is held inside `LedgerBlock`; both versions move in lockstep.
- The bump is monotonic; no version-downgrade path is supported (per `06-branching.mdc` append-only discipline applied to schema versions).

**Rejected alternatives.**

- **(a) Bump `LEDGER_BLOCK_VERSION` only.** Rejected: `wallet_ledger.snap` will diff (the wallet-ledger schema embeds the ledger-block schema by reference). The `WALLET_LEDGER_FORMAT_VERSION` bump is the only way to keep the version-vs-snapshot pairing honest.
- **(b) Skip both bumps and rely on snapshot regeneration alone.** Rejected: the version constants are the source of truth for the snapshot-drift CI check (`schema_snapshot.rs:27–28`). A snapshot regeneration without a version bump would silently shift the canonical on-disk shape under a version constant that hasn't moved, defeating the drift detector.

### D3 — Fixture-rewrite shape across the ten test/bench sites

**Decision.** Mechanical deletion of the five-field initializer block at each site. New `TransferDetails` initializers omit the five fields entirely (Rust's struct-init syntax requires every field to be named; M3d's field removal forces the deletion, no opt-in needed).

**Sites enumerated** (matching audit §2.4):

| # | File:Line | Class | Disposition |
|---|---|---|---|
| 1 | `rust/shekyl-engine-state/src/transfer.rs:381–385` (`postcard_roundtrip_with_secrets`) | Test | Test rename + body rewrite (asserts the new `source_ciphertext + output_handle` round-trip; legacy-field round-trip property is gone with the fields). |
| 2 | `rust/shekyl-engine-state/src/transfer.rs:353–357` (`sample()` test helper) | Test | Remove the five `None` initializers; init `source_ciphertext: None, output_handle: None` (already present). |
| 3 | `rust/shekyl-engine-state/src/ledger_block.rs:444–448` + `486–532` | Test (`#[cfg(test)]`) | Remove the five-field init at `444–448`; rewrite the assertion block at `486–532` to assert the new field set. Hits: 5 init + 2 read assertions. |
| 4 | `rust/shekyl-engine-state/src/ledger_indexes.rs:539–543` | Test | Remove the five-field init block. |
| 5 | `rust/shekyl-engine-state/src/invariants.rs:424` (and surrounding 5-line init block) | Test | Remove the five-field init block. |
| 6 | `rust/shekyl-engine-state/benches/ledger.rs` | Bench | Migration-transparent (`None`-only init); remove the five lines. |
| 7 | `rust/shekyl-engine-state/benches/ledger_iai.rs` | Bench | Migration-transparent; remove the five lines. |
| 8 | `rust/shekyl-engine-state/benches/balance.rs` | Bench | Migration-transparent; remove the five lines. |
| 9 | `rust/shekyl-engine-state/benches/balance_iai.rs` | Bench | Migration-transparent; remove the five lines. |
| 10 | `rust/shekyl-engine-core/benches/common/engine_fixture.rs:486` (and surrounding 5-line block) | Bench | Substantive: the fixture currently uses non-`None` init (`Zeroizing::new([lo.wrapping_add(1); 64])`, etc.) for `combined_shared_secret` and the other four fields. Remove the five-field init block; init `source_ciphertext: Some(synthetic_ciphertext)` + `output_handle: Some(derive_output_handle(...))` per the M3b post-pass shape so benches still exercise the populated handle path. |
| 11 | `rust/shekyl-engine-core/benches/refresh_snapshot.rs:75` (and surrounding 5-line block) | Bench | Same shape as site 10; remove + repopulate with handle-pathway fixtures. |
| 12 | `rust/shekyl-scanner/src/balance.rs:98` (and surrounding 5-line block) | Test | Migration-transparent (`None`-only init); remove the five lines. |
| 13 | `rust/shekyl-scanner/src/ledger_ext.rs:148–152` | Production write site | The five `td.<field> = Some(Zeroizing::new(...))` lines deleted. This is the §2.2 single production write site. |

(Audit §2.4 enumerates these as a single "10 sites" line; the table above expands to 13 entries because two `transfer.rs` test-fixture sub-sites and the production write site are separated. Total file count touched is the same.)

**Rationale.** Per `60-no-monero-legacy.mdc` "prefer outright removal over commenting out" and `15-deletion-and-debt.mdc` "default: delete": each fixture site is a deletion target, not a transitional rewrite. The two benchmark sites (10, 11) need the small additive change to populate the M3b handle-pathway fields so the bench fixture continues to exercise the production-shape `TransferDetails`; this is mechanical, not a design decision.

**Rejected alternatives.**

- **(a) Migrate fixtures by setting the five fields to `None` everywhere, then delete the fields in a follow-up PR.** Rejected: contradicts `15-deletion-and-debt.mdc` ("migration code is a permanent attack surface for a one-time problem"). Pre-V3 launch, the cost is bounded; the rule's preferred shape is single-PR removal.

### D4 — Zeroize-allowlist + schema-snapshot maintenance

**Decision.** Single-commit removal of the five `.zeroize-allowlist` entries (`rust/shekyl-engine-state/.zeroize-allowlist:115–119`) co-located with the schema-field removal in `transfer.rs`. Both `.snap` schema snapshots (`rust/shekyl-engine-state/schemas/ledger_block.snap` and `wallet_ledger.snap`) regenerated as part of the same commit; the `check_zeroize.sh` CI script and the snapshot-drift CI both refuse stale state.

**Rationale.**

- The allowlist's own header docstring (lines 24–28): "If you are **removing** a field whose entry appears below, also remove the allowlist line in the same commit. A stale entry is a CI-blocking error — it would silently permit a future field with the same normalized declaration to bypass the zeroize check." M3d removes the five fields; the five allowlist entries go in the same commit by rule.
- Schema snapshots are regenerated by running the existing snapshot test (`cargo test -p shekyl-engine-state --test snapshot_*` or the in-crate snapshot test, per `schema_snapshot.rs` convention) with `INSTA_UPDATE=auto` and committing the regenerated `.snap` files. The regeneration is mechanical; the snapshot-drift check (run in CI without `INSTA_UPDATE`) gates the commit.

**Co-location discipline.** Per `90-commits.mdc` "scope per commit" and `15-deletion-and-debt.mdc` "small, scope-respecting commits": the `transfer.rs` schema-field removal + `Zeroize`-impl edit + `.zeroize-allowlist` removal + both `.snap` regeneration land in **one commit** because they are a single load-bearing change (the schema cleanup). Splitting would produce intermediate states that fail CI's drift checks.

### D5 — Property-test continuity at M3d

**Decision.** The M3b D5 byte-identical-derivation property test (`derive_source_secrets_bundle_byte_identical_against_legacy_chain` at `local_keys.rs::tests`, ~line 1150) and the M3c-via-C end-to-end test (`engine_derived_bundle_signs_through_tx_builder_end_to_end`, ~line 1380) **both continue to pass at M3d with no rewrite needed**.

**Why both pass unchanged:**

- M3b D5 reads the legacy chain via `scan_output_recover` + hand-composed `(ho + b + m_i)` — none of those derivations touch `TransferDetails`. The test reconstructs the "legacy" bundle from `recovered.ho`, `recovered.y`, `recovered.z`, `recovered.combined_ss`, etc., where `recovered: RecoveredOutput` is the `shekyl-crypto-pq` return value, not the `TransferDetails` schema. Removing the `TransferDetails` legacy fields does not affect `RecoveredOutput`'s shape (per the audit §2.3 "zero production reads" finding: the `TransferDetails` fields were write-only).
- M3c-via-C derives both bundles (engine + legacy) the same way, also bypassing `TransferDetails`. The legacy chain in M3c reuses the M3b D5 derivation pattern.
- The fallback branch the migration plan §4.2 row "M3c (unchanged from M3b)" referred to was the *bridge-impl* fallback (the one inside `LocalKeys::sign_transaction`'s body); since that body remains a stub, neither test ever exercised it. M3d's removal of the legacy `TransferDetails` fields therefore leaves both tests' fallback-vs-handle-path coverage shape unchanged.

**Coverage gap (named, accepted).**

- M3c's accepted coverage gap (legacy `sign_transaction` end-to-end execution; per M3c pre-flight §2.1.1 Trim-1 disposition) closes at M3d's merge by construction — there is no legacy path to execute end-to-end after the legacy `TransferDetails` fields are gone. The gap was bounded by M3d's lifetime; M3d's lifetime is now.
- No new coverage gap is opened by M3d. The byte-identical-derivation property remains pinned by M3b D5; the cryptographic-chain end-to-end property remains pinned by M3c-via-C.

**Rejected alternative.**

- **Rewrite both tests to drop the "legacy chain" comparison.** Rejected on `00-mission.mdc` priority-1 grounds: the legacy chain in both tests is the *hand-composed reference implementation*, not a transitional path. Removing it would forfeit the byte-identical-against-known-reference property that pins regression detection against future engine-derivation drift. The reference implementation lives in test code, not in production; M3d doesn't touch it.

---

## §3 Scope

### §3.1 In scope (M3d)

The thirteen file-edits enumerated in §2 D3, plus the schema/version/snapshot/allowlist work in D2/D4. Estimated review surface: ~225 lines net (per plan §3.4), dominated by deletions. Two benchmark sites (D3 entries 10, 11) carry small additive changes for handle-pathway fixture population.

### §3.2 Out of scope (M3d → deferred to M3e or later PRs)

- **`LocalKeys::sign_transaction` bridge impl body.** Remains PR-5-pinned named-gap stub (per D1). PR-5 is the trait-surface completion PR; M3d does not touch it.
- **Test-relocation for M3b D5 + M3c-via-C.** Bundled in the `FOLLOWUPS.md` "Stage 1 PR 3 engine-property test re-location" entry, triggered by the `KeyEngine::pub(crate)` → `pub` widening (post-M3e or later).
- **Documentation realignment.** M3e's scope (`KEY_ENGINE.md` post-migration update, audit snapshot refresh, CHANGELOG entries per PR, FOLLOWUPS close-records). M3d's CHANGELOG entry is part of M3d; the broader doc sweep is M3e.
- **Wallet-RPC server cutover.** Separate planning track (per audit §3.1 / FOLLOWUPS §V3.1 line 259). Not affected by M3d.

### §3.3 Property delivery at M3d's merge

- **"Secrets confined to engine" activates** (per plan §4.1 / §4.2 M3d row).
  - **Before M3d:** `TransferDetails` carries `combined_shared_secret`, `ho`, `y`, `z`, `k_amount` (5 secret-bearing `Option<Zeroizing<…>>` fields) populated by the scanner write site. Orchestrator compromise discloses output-secret material.
  - **After M3d:** `TransferDetails` carries only `source_ciphertext` (public on-chain residue) and `output_handle` (publicly-derivable from view material). Spend material is re-derived from `(view_secret, source_ciphertext)` at signing time per design doc §7.12. Orchestrator compromise does *not* disclose output-secret material; engine compromise still discloses long-term key material via `AllKeysBlob` (unchanged per Round 3 §7.10–§7.11).
- **Engine-confined-secrets property is the V3.0-binding security property** delivered by the Stage 1 PR 3 architectural-inheritance migration. M3d activating it is the structural close-out of the migration.

### §3.4 Property delivery against the three-timeframe framing (`05-system-thinking.mdc`)

- **Now (V3.0):** Delivers the engine-confined-secrets property in V3.0 from genesis. Orchestrator compromise no longer discloses output-secret material; this is the property the architectural-inheritance migration was designed to deliver.
- **Mining era end (~30 years):** No interaction. The schema cleanup is orthogonal to the block-reward / fee-market trajectory.
- **Post-quantum era (V4):** No interaction with V4's lattice-only transition. The `source_ciphertext` retains its hybrid X25519 + ML-KEM-768 shape for V3.x; V4's lattice-only schema is a separate migration. M3d does not pre-bind any V3-specific assumption that would block V4's schema redesign.

---

## §4 Commit decomposition

Estimated five commits, mechanically derived from the audit §2.4 / plan §3.4 site enumeration.

| # | Commit | Files | Substance | Lines net |
|---|---|---|---|---|
| 1 | `engine-state: remove legacy secret-bearing fields from TransferDetails` | `transfer.rs`, `.zeroize-allowlist`, both `.snap` | Schema deletion (5 fields + schema mirror + Zeroize impl + 5 allowlist entries + 2 snapshot regenerations). Includes `LEDGER_BLOCK_VERSION` + `WALLET_LEDGER_FORMAT_VERSION` bumps (3 → 4) in the same commit because the snapshot regeneration depends on the version bump being concurrent. | ~-80 |
| 2 | `scanner: drop legacy-field writes from ledger_ext::from_wallet_output` | `rust/shekyl-scanner/src/ledger_ext.rs` | Production write site removal (D3 entry 13). Five `td.<field> = Some(Zeroizing::new(...))` lines deleted. | ~-5 |
| 3 | `engine-state: rewrite test fixtures for post-M3d schema` | `transfer.rs::tests`, `ledger_block.rs`, `ledger_indexes.rs`, `invariants.rs`, four `benches/*.rs` | D3 entries 1, 2, 3, 4, 5, 6, 7, 8, 9 + 12 (the "migration-transparent" + "rewrite for new schema" sites in `shekyl-engine-state`). Per-file scope respected. | ~-40 |
| 4 | `engine-core: rewrite bench fixtures for post-M3d handle pathway` | `benches/common/engine_fixture.rs`, `benches/refresh_snapshot.rs` | D3 entries 10, 11. Substantive: remove the five-field init blocks; init `source_ciphertext` + `output_handle` per the M3b post-pass shape so benches still exercise the populated handle path. | ~+15 |
| 5 | `docs(stage-1-pr3-m3d): plan §3.4 cross-ref + CHANGELOG + FOLLOWUPS` | `STAGE_1_PR_3_MIGRATION_PLAN.md`, `STAGE_1_PR_3_M3D_PREFLIGHT.md`, `CHANGELOG.md`, `FOLLOWUPS.md` | Landing-notes cross-reference paragraph in plan §3.4 naming the D1 divergence (bridge impl stays a stub past M3d); pre-flight EXECUTED marker per M3b/M3c precedent; CHANGELOG entry for M3d (`### Removed` + `### Changed`); FOLLOWUPS update closing the architectural-inheritance migration entry. | ~+60 |

Five-commit estimate; the migration plan's §3.4 wording presupposed six (the original "remove fallback" commit folds into the docs commit since there is no code to remove). Per `90-commits.mdc` "scope per commit": each commit is bisection-friendly; CI is green at every commit boundary.

---

## §5 Branching

- **Branch:** `feat/stage-1-pr3-m3d` off `dev` at `e6efaf5b5`.
- **Pre-flight commit:** lands on this branch before implementation begins; surfaced for review before Phase 2.
- **Push policy:** per `06-branching.mdc` rule 4, no push to `dev` or to the remote feature branch without explicit user authorization for that specific push.
- **Estimated branch lifetime:** 3–5 working days. Within the `06-branching.mdc` short-lived-branch ceiling.

---

## §6 Success criteria

The M3d PR is review-merge-ready when:

- [ ] `cargo build --workspace --all-targets` succeeds on the `feat/stage-1-pr3-m3d` HEAD.
- [ ] `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean.
- [ ] `cargo test --workspace` is green (all 145+ tests in `shekyl-engine-core`, all `shekyl-engine-state` tests including postcard round-trip, all scanner tests, all bench compile checks).
- [ ] M3b D5 byte-identical-derivation property test (`derive_source_secrets_bundle_byte_identical_against_legacy_chain`) continues to pass unchanged.
- [ ] M3c-via-C end-to-end test (`engine_derived_bundle_signs_through_tx_builder_end_to_end`) continues to pass unchanged.
- [ ] `git grep -E 'combined_shared_secret|\.ho\b|\.k_amount'` returns zero hits in `rust/` excluding `shekyl-crypto-pq` (which owns the derivation primitives at its `OutputSecrets` / `ProofSecrets` types, distinct from `TransferDetails`) and excluding `shekyl-fcmp` / `shekyl-oxide` / FFI surfaces (which use these field names on their own types).
- [ ] `LEDGER_BLOCK_VERSION = 4`, `WALLET_LEDGER_FORMAT_VERSION = 4`; both `.snap` schema snapshots regenerated and committed.
- [ ] `.zeroize-allowlist` no longer contains the five legacy-field entries (lines 115–119 pre-M3d).
- [ ] CHANGELOG entry under `[Unreleased]` describes the engine-confined-secrets property activation; FOLLOWUPS architectural-inheritance migration entry is closed with a pointer to this PR.

---

## §7 Out-of-scope reminders

- M3d does **not** touch `LocalKeys::sign_transaction`'s body. PR-5 territory.
- M3d does **not** widen `KeyEngine::pub(crate)` to `pub`. The M3b D5 + M3c-via-C test-relocation bundled in `FOLLOWUPS.md` is deferred until the visibility widens; that widening is post-M3e or later.
- M3d does **not** edit `shekyl-crypto-pq`'s `OutputSecrets`, `ProofSecrets`, or any of the field names that happen to collide (`ho`, `y`, `z`, `k_amount`, `combined_shared_secret`). Those types are upstream-of-`TransferDetails` derivations; the field-name collision is intentional (the same labels appear at both layers because they identify the same HKDF outputs).
- M3d does **not** modify the wallet-RPC server, the FFI surfaces, or any wallet2-bridged signing path. Those are separate cutover tracks per audit §3.1.

---

## §8 Open questions for user disposition

None. All structural questions are disposed in §2 D1–D5 above. M3d is the cleanest of the five PRs in the migration: a mechanical schema cleanup that activates the migration's headline property. Phase 2 (implementation) can begin once this pre-flight is reviewed and Phase 1 is committed.

---

## §9 Phase-2 implementation order

1. **Commit 1** (`engine-state: remove legacy secret-bearing fields from TransferDetails`) lands first because every other commit depends on the schema being in its post-M3d shape. Snapshot regeneration is part of this commit; CI gates the regeneration on the same boundary.
2. **Commit 2** (`scanner: drop legacy-field writes`) — landed after Commit 1 so the scanner compiles against the post-M3d schema. Mechanical.
3. **Commit 3** (`engine-state: rewrite test fixtures`) — the engine-state-resident tests + benches. Landed before the engine-core bench commit because the bench fixtures depend on the engine-state types being in their post-M3d shape.
4. **Commit 4** (`engine-core: rewrite bench fixtures`) — the substantive bench rewrite (handle-pathway init). Lands last in the code-bearing sequence.
5. **Commit 5** (`docs(stage-1-pr3-m3d): plan + CHANGELOG + FOLLOWUPS + pre-flight EXECUTED marker`) — the documentation commit per `91-documentation-after-plans.mdc`. Lands last; surfaces the M3d landing notes for plan §3.4.

Per-commit gate: `cargo build && cargo test && cargo clippy -- -D warnings && cargo fmt --check` at every boundary. M3c-style `--push` only after user-explicit authorization per `06-branching.mdc` rule 4.

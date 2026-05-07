# Stage 1 PR 3 — Migration Audit

**Status.** Audit artifact, precursor to `STAGE_1_PR_3_MIGRATION_PLAN.md`.
**Scope.** Workspace audit of the surface affected by the Stage 1 PR 3
architectural-inheritance migration (PRs 3a–3f) per
`STAGE_1_PR_3_KEY_ENGINE.md` and `.cursor/rules/16-architectural-inheritance.mdc`.
**Methodology.** Static `rg`/`grep` over `rust/`, cross-checked against
function signatures and feature gates. Test-only and bench-only sites are
labelled but not excluded; they migrate alongside production code per
their respective PR targets.
**Snapshot.** Workspace state at `chore/spec-stage-1-pr3-keyengine-round`
HEAD = `ffcaa62e9` (commit landing `16-architectural-inheritance.mdc`).

The audit's headline finding: **the migration surface is markedly smaller
than the per-PR scope tables in earlier rounds estimated**, and **PR 3d
is additive rather than migrational** — there is no current
non-wallet2-bridged orchestrator path to `tx_builder::sign_transaction`
to migrate.

---

## §1 SpendInput construction sites

`shekyl_tx_builder::SpendInput` is the input record consumed by
`tx_builder::sign_transaction`. The handle-indirected migration moves
construction inside `KeyEngine::sign_transaction`; this table enumerates
every construction site so PR 3c's scope is bounded.

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| FFI-export wrapper | `rust/shekyl-ffi/src/lib.rs:3305` | Production, FFI-bridged | **Excluded** — legacy, deletion target at wallet RPC cutover | — |
| Engine-RPC `transfer_native` deserialization | `rust/shekyl-engine-rpc/src/engine.rs:427` | Production, `native-sign` feature, wallet2-bridged | **Excluded** — legacy, deletion target at wallet RPC cutover | — |
| Test fixture (small) | `rust/shekyl-tx-builder/src/tests.rs:28` | Test-only (pure-function library) | Keep — exercises `tx-builder` directly, not the engine path | — |
| Test fixture (depth) | `rust/shekyl-tx-builder/src/tests.rs:269` | Test-only (pure-function library) | Keep — exercises `tx-builder` directly | — |
| Type definition | `rust/shekyl-tx-builder/src/types.rs:231` | Library type | Keep, ungate from `Deserialize` (PR 3c makes engine-internal); fields stable | 3c |

**Production SpendInput construction outside FFI/`native-sign`: zero sites.**

The two FFI-bridged construction sites are deletion targets per the
"inherited code with a deletion target doesn't get migrated; it gets
deleted" disposition (`16-architectural-inheritance.mdc` §"When to
migrate vs. when to keep"). The wallet-RPC-server cutover removes them.

`tx-builder`'s test fixtures construct `SpendInput` directly because
`tx-builder` is a pure-function library that the engine wraps. PR 3c
keeps the library tests intact; engine-side tests construct via the
engine wrapper. This isolates the pure-function surface from the
secret-flow architecture migration cleanly.

**Implication for PR 3c.** The PR is not a migration of construction
call sites. It is the introduction of `KeyEngine::sign_transaction`
that wraps `tx_builder::sign_transaction` and constructs `SpendInput`
internally from handle-resolved secrets. The library API of `tx-builder`
remains stable; the only library-side change is that `SpendInput` becomes
engine-internal in practice (the public type stays for the legacy/test
paths until the wallet RPC cutover).

---

## §2 TransferDetails secret-field surface

The handle-indirected migration moves derived per-output secrets out of
`TransferDetails` and into the engine's handle table, with `TransferDetails`
holding `source_ciphertext` + `output_handle` post-PR 3e.

### §2.1 Schema

| Field | File:Line | Class |
|---|---|---|
| `combined_shared_secret: Option<Zeroizing<[u8; 64]>>` | `rust/shekyl-engine-state/src/transfer.rs:86` | Removed in PR 3e |
| `ho: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:89` | Removed in PR 3e |
| `y: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:92` | Removed in PR 3e |
| `z: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:95` | Removed in PR 3e |
| `k_amount: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:98` | Removed in PR 3e |

PR 3e adds `source_ciphertext: HybridCiphertext` and
`output_handle: OutputHandle` in their place (final field set per
`STAGE_1_PR_3_KEY_ENGINE.md` Round 3 schema).

### §2.2 Production write sites

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| Scanner output ingestion | `rust/shekyl-scanner/src/ledger_ext.rs:125–129` | Production | Reroute: scanner emits `OutputClaim` to `KeyEngine::try_claim_output`; engine populates handle table; orchestrator persists `TransferDetails` with `source_ciphertext + output_handle` only | 3b |

**Production write sites of secret fields: exactly one.** The migration's
data-flow rerouting happens at this single point.

### §2.3 Production read sites of secret fields

**None.** Outside `rust/shekyl-engine-state/src/transfer.rs` (the schema
itself) and `rust/shekyl-scanner/src/ledger_ext.rs:125–129` (the write
site), no production code reads the `combined_shared_secret`, `ho`, `y`,
`z`, or `k_amount` fields of `TransferDetails`. The orchestrator
persists them but does not consume them; signing flows through wallet2
which carries its own copies.

This is the audit's strongest finding for migration-cost bounding: **the
secret-bearing fields on `TransferDetails` are write-only from
production code's perspective.** Removing them in PR 3e affects no
production read site. The compile-time fallout is confined to:

- The schema (`transfer.rs`) — PR 3e edits.
- The write site (`ledger_ext.rs`) — PR 3b reroutes.
- Test/bench fixtures (see §2.4) — PR 3e cleans up.

### §2.4 Test- and bench-only secret-field touches

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| Schema roundtrip test | `rust/shekyl-engine-state/src/transfer.rs:322–340` | Test | Rewrite for new schema | 3e |
| Scanner test fixtures | `rust/shekyl-scanner/src/tests.rs:77, 855, 1037` | Test | Rewrite for new flow | 3b |
| Scanner staging struct | `rust/shekyl-scanner/src/scan.rs:52, 106, 341` | Production (engine-internal post-3b) | Stays internal to scanner→engine path | 3b |
| Ledger-block test | `rust/shekyl-engine-state/src/ledger_block.rs:425, 486–511` | Test (`#[cfg(test)]`) | Rewrite for new schema | 3e |
| Ledger-indexes test | `rust/shekyl-engine-state/src/ledger_indexes.rs:523` | Test | Rewrite for new schema | 3e |
| Invariants test | `rust/shekyl-engine-state/src/invariants.rs:424` | Test | Rewrite for new schema | 3e |
| Engine-core bench fixture | `rust/shekyl-engine-core/benches/common/engine_fixture.rs:484` | Bench | Rewrite for new schema | 3e |
| Refresh-snapshot bench | `rust/shekyl-engine-core/benches/refresh_snapshot.rs:73` | Bench | Rewrite for new schema | 3e |
| Ledger benches | `rust/shekyl-engine-state/benches/{ledger,ledger_iai,balance,balance_iai}.rs` (init `None` only) | Bench | Migration-transparent (default-init pattern; `Option` removal cascades) | 3e |
| Scanner balance test | `rust/shekyl-scanner/src/balance.rs:98` (init `None` only) | Test | Migration-transparent | 3e |

The non-test write sites in `scan.rs` are the scanner's own staging
struct (`ScannedOutput` or equivalent), separate from `TransferDetails`.
Post-PR 3b it remains the scanner's internal carrier between recovery
and engine handoff. Its lifetime ends at the engine boundary; it is
not persisted.

### §2.5 RPC contract

Verified via `transfer_to_json` audit (Round 3 of design rounds): the
RPC layer exposes `tx_hash`, `internal_output_index`, `global_output_index`,
`block_height`, `key`, `commitment`, `subaddress`, `payment_id`, `spent`,
`spent_height`, `key_image`, staking metadata, and `eligible_height`.
**No secret-bearing field is exposed.** Migration is RPC-transparent;
no version bump; no client coordination required.

---

## §3 `tx_builder::sign_transaction` callers

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| FFI signing path A | `rust/shekyl-ffi/src/lib.rs:3127` | Production, FFI export | **Excluded** — legacy, deletion target at wallet RPC cutover | — |
| FFI signing path B | `rust/shekyl-ffi/src/lib.rs:3331` | Production, FFI export | **Excluded** — legacy, deletion target at wallet RPC cutover | — |
| Engine-RPC `transfer_native` | `rust/shekyl-engine-rpc/src/engine.rs:455` | Production, `native-sign` feature, wallet2-bridged | **Excluded** — legacy, deletion target at wallet RPC cutover | — |

**Non-wallet2-bridged orchestrator callers of `tx_builder::sign_transaction`:
zero.** All current callers cross the wallet2 FFI in either direction.

### §3.1 Implication for PR 3d

PR 3d as previously framed ("orchestrator signing pipeline migration")
overstated its scope. There is no orchestrator signing pipeline
independent of wallet2 to migrate. PR 3d's actual content is:

1. Introduce `KeyEngine::sign_transaction(tx_prefix_hash, &[OutputHandle], ...)`
   that resolves handles internally and calls `tx_builder::sign_transaction`.
2. Wire it from a (new) non-wallet2 orchestrator caller — likely the
   first crate that produces a transaction without going through wallet2.
3. The wallet RPC server cutover (separate planning track) eventually
   replaces the wallet2-bridged callers with this new path.

**This reframes PR 3d as additive, not migrational.** The scope and
risk profile drop significantly. The migration plan should reflect this.

The pre-cutover orchestrator (today's `shekyl-engine-rpc` + wallet2)
continues to use the legacy path until the RPC server cutover; that
cutover is not in PR 3a–3f scope.

---

## §4 v31 multisig — verification check

Verified via inspection of `rust/shekyl-engine-core/src/multisig/`:

- Public data types (`TrackedIntent`, `ProverOutput`, etc.) carry public
  material only.
- Per-signer secret state lives in session-scoped containers, not in
  shared types.
- Message-passing surfaces (round-1 / round-2 transcripts) carry public
  commitments and proof bytes, not secrets.

This is structurally analogous to the post-migration `KeyEngine` pattern:
public types for orchestration, secret state confined to engine-internal
session containers. **No concurrent migration required.** v31 is an
instance of the post-CryptoNote design discipline applied during initial
design, per `16-architectural-inheritance.mdc` §"Density expectations".

A pre-flight verification step at PR 3a confirms the structure has not
drifted between this audit's snapshot and the merge of 3a; expected
outcome unchanged.

---

## §5 Audit totals

| Quantity | Count |
|---|---|
| Production SpendInput construction sites (all) | 2 |
| Production SpendInput construction sites (non-FFI, non-`native-sign`) | **0** |
| Production `TransferDetails` secret-field write sites | 1 |
| Production `TransferDetails` secret-field read sites | **0** |
| `tx_builder::sign_transaction` callers (all) | 3 |
| `tx_builder::sign_transaction` callers (non-wallet2-bridged) | **0** |
| Test/bench fixtures touching secret fields | 12 |
| Excluded-from-migration sites (FFI / `native-sign`, deletion targets) | 5 |

The "excluded sites" line is the operative one for migration sequencing:
**five out of five production secret-flow sites that aren't the scanner
write site are FFI-bridged legacy with named deletion targets.** The
migration's load-bearing single-site change is `ledger_ext.rs:125–129`.

---

## §6 Implications for the migration plan

1. **PR 3b scope is pinpoint.** Single-site reroute at
   `shekyl-scanner/src/ledger_ext.rs:125–129` plus the scanner's
   `ScannedOutput`-to-engine handoff. Test fixtures in `scanner/tests.rs`
   move with it.

2. **PR 3c scope is library-API-additive.** `KeyEngine::sign_transaction`
   wraps `tx_builder::sign_transaction`. No call-site migration in
   `tx-builder`. Test fixtures in `tx-builder/src/tests.rs` stay.

3. **PR 3d scope is reframed: additive, not migrational.** No existing
   non-wallet2 orchestrator path to migrate. PR 3d introduces the path
   and exercises it from a new caller.

4. **PR 3e scope is schema cleanup + test rewrite.** Five field removals
   on `TransferDetails`, two field additions, and the test/bench fixture
   rewrites enumerated in §2.4. No production read-site fallout.

5. **PR 3f scope is documentation-only** (design-doc realignment plus
   `CHANGELOG.md` per `91-documentation-after-plans.mdc`).

6. **`dev` branch freeze duration.** PR 3a–3e are short; with the audit
   confirming bounded scope, freeze duration estimates from earlier
   rounds (multi-week) should be revisited. Best estimate now: 3a–3e
   land within the 5-working-day target of `06-branching.mdc`'s
   short-lived-branch discipline if sequenced without cross-PR
   coordination overhead.

7. **Forward-template content for PR 4–7.** "Audit secret-field
   write/read symmetry before assuming migration cost" is a reusable
   pre-flight check. The fact that `TransferDetails`' secret fields
   were write-only from production's perspective is not coincidence —
   it's a property the `36-secret-locality.mdc` discipline enforces and
   the audit confirms. Future per-trait PR pre-flights should run the
   same audit early.

---

## §7 Audit limitations

1. **Static-only.** The audit does not exercise runtime paths. A
   feature flag combination not visible to `rg` could enable a code
   path the audit missed. Mitigation: PR 3a CI runs the full test
   matrix including `native-sign` and FFI test suites; any missed
   call site surfaces as a compile or test failure.

2. **C++ side not audited.** The C++ `wallet2` and FFI consumer code is
   in scope of the wallet RPC server cutover, not this migration.
   The audit's exclusion-from-migration findings are gated on the
   premise that the FFI path remains until the cutover removes it
   wholesale; if that premise changes, the audit must be re-run.

3. **No quantitative comparison to `monero-oxide`.** The audit assumes
   the architectural-inheritance findings are Shekyl-specific (i.e. the
   structural drift exists in Shekyl because Shekyl's threat model
   differs, not because the upstream has the same drift). A spot-check
   against `monero-oxide`'s `transfer_details` confirms the secret-
   carrying pattern is inherited; the structural-drift framing per
   `16-architectural-inheritance.mdc` §"The inherited-architecture rule"
   stands.

4. **Snapshot stability.** Audit holds against
   `chore/spec-stage-1-pr3-keyengine-round` HEAD `ffcaa62e9`. If `dev`
   advances before PR 3a opens, the audit re-runs as part of PR 3a's
   pre-flight. The freeze on `dev` (per migration plan) is the
   structural mitigation; this section is the residual fallback.

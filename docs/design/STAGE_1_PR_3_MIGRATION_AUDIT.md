# Stage 1 PR 3 — Migration Audit

**Status.** Audit artifact, precursor to `STAGE_1_PR_3_MIGRATION_PLAN.md`.
**Scope.** Workspace audit of the surface affected by the Stage 1 PR 3
architectural-inheritance migration (M3a–M3e per the 5-PR sequence
adopted in the migration plan; an earlier 6-PR shape collapsed once
the audit confirmed no separate `SpendInput`-construction-migration PR
was needed) per `STAGE_1_PR_3_KEY_ENGINE.md` and
`.cursor/rules/16-architectural-inheritance.mdc`.
**Methodology.** Static `rg`/`grep` over `rust/`, cross-checked against
function signatures and feature gates. Test-only and bench-only sites are
labelled but not excluded; they migrate alongside production code per
their respective PR targets.
**Snapshot.** Workspace state at `chore/spec-stage-1-pr3-keyengine-round`
HEAD = `ffcaa62e9` (commit landing `16-architectural-inheritance.mdc`).

The audit's headline finding: **the migration surface is markedly smaller
than the per-PR scope tables in earlier rounds estimated**, and **the
additive caller PR (M3c) is not a migration of an existing path** — there
is no current non-wallet2-bridged orchestrator path to
`tx_builder::sign_transaction` to migrate.

---

## §1 SpendInput construction sites

`shekyl_tx_builder::SpendInput` is the input record consumed by
`tx_builder::sign_transaction`. The handle-indirected migration places
`SpendInput` construction inside `KeyEngine::sign_transaction` from
M3a's bridge impl onward; this table enumerates every existing
construction site so the construction surface is bounded.

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| FFI-export wrapper | `rust/shekyl-ffi/src/lib.rs:3305` | Production, FFI-bridged | **Excluded** — legacy, deletion target at wallet RPC cutover | — |
| Engine-RPC `transfer_native` deserialization | `rust/shekyl-engine-rpc/src/engine.rs:427` | Production, `native-sign` feature, wallet2-bridged | **Excluded** — legacy, deletion target at wallet RPC cutover | — |
| Test fixture (small) | `rust/shekyl-tx-builder/src/tests.rs:28` | Test-only (pure-function library) | Keep — exercises `tx-builder` directly, not the engine path | — |
| Test fixture (depth) | `rust/shekyl-tx-builder/src/tests.rs:269` | Test-only (pure-function library) | Keep — exercises `tx-builder` directly | — |
| Type definition | `rust/shekyl-tx-builder/src/types.rs:231` | Library type | Keep public; type stays in `tx-builder` for legacy/test paths until wallet RPC cutover | — |

**Production SpendInput construction outside FFI/`native-sign`: zero sites.**

The two FFI-bridged construction sites are deletion targets per the
"inherited code with a deletion target doesn't get migrated; it gets
deleted" disposition (`16-architectural-inheritance.mdc` §"When to
migrate vs. when to keep"). The wallet-RPC-server cutover removes them.

`tx-builder`'s test fixtures construct `SpendInput` directly because
`tx-builder` is a pure-function library that the engine wraps. The
migration keeps the library tests intact; engine-side tests construct
via the engine wrapper. This isolates the pure-function surface from
the secret-flow architecture migration cleanly.

**Implication for M3a.** The bridge impl introduced in M3a
constructs `SpendInput` engine-internally from the start, sourcing
secrets from `TransferDetails`'s existing secret-bearing fields
(transitional). M3b switches the source to `HandleTable` (with
`TransferDetails` fallback); M3d removes the fallback when the
fields go away. There is no separate "move construction into the
engine" PR — the construction is engine-internal from inception, and
the audit confirms there are no extant non-deletion-target sites to
move from. (This is the collapse that took the migration sequence from
six PRs to five.)

---

## §2 TransferDetails secret-field surface

The handle-indirected migration moves derived per-output secrets out of
`TransferDetails` and into the engine's handle table, with `TransferDetails`
holding `source_ciphertext` + `output_handle` post-M3d.

### §2.1 Schema

| Field | File:Line | Class |
|---|---|---|
| `combined_shared_secret: Option<Zeroizing<[u8; 64]>>` | `rust/shekyl-engine-state/src/transfer.rs:86` | Removed in M3d |
| `ho: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:89` | Removed in M3d |
| `y: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:92` | Removed in M3d |
| `z: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:95` | Removed in M3d |
| `k_amount: Option<Zeroizing<[u8; 32]>>` | `rust/shekyl-engine-state/src/transfer.rs:98` | Removed in M3d |

M3d adds `source_ciphertext: HybridCiphertext` and
`output_handle: OutputHandle` in their place (final field set per
`STAGE_1_PR_3_KEY_ENGINE.md` Round 3 schema).

### §2.2 Production write sites

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| Scanner output ingestion | `rust/shekyl-scanner/src/ledger_ext.rs:125–129` | Production | Reroute: scanner emits `OutputClaim` to `KeyEngine::try_claim_output`; engine populates handle table; orchestrator persists `TransferDetails` with `source_ciphertext + output_handle` only | M3b |

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
production code's perspective.** Removing them in M3d affects no
production read site. The compile-time fallout is confined to:

- The schema (`transfer.rs`) — M3d edits.
- The write site (`ledger_ext.rs`) — M3b reroutes.
- Test/bench fixtures (see §2.4) — M3d cleans up.

### §2.4 Test- and bench-only secret-field touches

| Site | File:Line | Class | Disposition | PR |
|---|---|---|---|---|
| Schema roundtrip test | `rust/shekyl-engine-state/src/transfer.rs:322–340` | Test | Rewrite for new schema | M3d |
| Scanner test fixtures | `rust/shekyl-scanner/src/tests.rs:77, 855, 1037` | Test | Rewrite for new flow | M3b |
| Scanner staging struct | `rust/shekyl-scanner/src/scan.rs:52, 106, 341` | Production (engine-internal post-M3b) | Stays internal to scanner→engine path | M3b |
| Ledger-block test | `rust/shekyl-engine-state/src/ledger_block.rs:425, 486–511` | Test (`#[cfg(test)]`) | Rewrite for new schema | M3d |
| Ledger-indexes test | `rust/shekyl-engine-state/src/ledger_indexes.rs:523` | Test | Rewrite for new schema | M3d |
| Invariants test | `rust/shekyl-engine-state/src/invariants.rs:424` | Test | Rewrite for new schema | M3d |
| Engine-core bench fixture | `rust/shekyl-engine-core/benches/common/engine_fixture.rs:484` | Bench | Rewrite for new schema | M3d |
| Refresh-snapshot bench | `rust/shekyl-engine-core/benches/refresh_snapshot.rs:73` | Bench | Rewrite for new schema | M3d |
| Ledger benches | `rust/shekyl-engine-state/benches/{ledger,ledger_iai,balance,balance_iai}.rs` (init `None` only) | Bench | Migration-transparent (default-init pattern; `Option` removal cascades) | M3d |
| Scanner balance test | `rust/shekyl-scanner/src/balance.rs:98` (init `None` only) | Test | Migration-transparent | M3d |

The non-test write sites in `scan.rs` are the scanner's own staging
struct (`ScannedOutput` or equivalent), separate from `TransferDetails`.
Post-M3b it remains the scanner's internal carrier between recovery
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

### §3.1 Implication for M3c

M3c as previously framed ("orchestrator signing pipeline migration",
under the prior 6-PR sequence's M3d label) overstated its scope.
There is no orchestrator signing pipeline independent of wallet2 to
migrate. M3c's actual content is:

1. Introduce a new caller (test path in `shekyl-engine-core/tests/`)
   that exercises `KeyEngine::sign_transaction(&[OutputHandle], ...)`
   end-to-end against the existing `tx-builder` test vectors.
2. Validate the handle→secret resolution path produces byte-identical
   output to the legacy direct-secret path.
3. The wallet RPC server cutover (separate planning track) eventually
   replaces the wallet2-bridged callers with a production caller of
   the same API.

**This reframes M3c as additive, not migrational.** The scope and
risk profile drop significantly.

The pre-cutover orchestrator (today's `shekyl-engine-rpc` + wallet2)
continues to use the legacy path until the RPC server cutover; that
cutover is not in M3a–M3e scope.

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

A pre-flight verification step at M3a confirms the structure has not
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

The 5-PR sequence (M3a/M3b/M3c/M3d/M3e) collapsed an earlier 6-PR shape
once this audit confirmed there is no separate "move `SpendInput`
construction" migration to do. The implications below are written
against the 5-PR sequence; the migration plan doc carries the scope
tables.

1. **M3a scope absorbs engine-internal `SpendInput` construction.**
   The bridge impl constructs `SpendInput` from inception, sourcing
   secrets from `TransferDetails`'s existing secret-bearing fields.
   No call-site migration; pure-function `tx-builder` library tests
   remain intact.

2. **M3b scope is pinpoint.** Single-site reroute at
   `shekyl-scanner/src/ledger_ext.rs:125–129` plus the scanner's
   `ScannedOutput`-to-engine handoff and the bridge impl secret-source
   switch (with `TransferDetails` fallback). Test fixtures in
   `scanner/tests.rs` move with it.

3. **M3c scope is additive, not migrational.** No existing
   non-wallet2 orchestrator path to migrate. M3c introduces a test
   caller exercising end-to-end against the new API; production
   callers land during the wallet RPC cutover.

4. **M3d scope is schema cleanup + test rewrite.** Five field
   removals on `TransferDetails`, two field additions, removal of the
   bridge impl's transitional fallback, and the test/bench fixture
   rewrites enumerated in §2.4. No production read-site fallout.
   **"Secrets confined to engine" property activates here.**

5. **M3e scope is documentation-only** (design-doc realignment plus
   `CHANGELOG.md` per `91-documentation-after-plans.mdc`).

6. **`dev` branch freeze duration.** M3a–M3d are individually
   short, and the audit's bounded-scope finding rules out the
   multi-week estimates from earlier design rounds. The migration
   plan §5.1 carries the operational framing; for reference, the
   audit's estimates feeding it are:
   - **Best-case: 5–7 working days.** M3a–M3d land within the
     `06-branching.mdc` short-lived-branch target, conditional on
     no PR surfacing an unexpected blocker during pre-flight or
     review.
   - **Realistic: 8–12 working days.** Absorbs one substantive
     blocker. Stage 1 PR 2's multi-week review cycle is the
     baseline experience this estimate reflects.
   The 5-working-day target of `06-branching.mdc` is a discipline
   ceiling per individual PR, not a likely aggregate timeline for a
   multi-PR sequence. Treating it as the headline freeze duration
   compresses what's realistic; the migration plan's framing avoids
   that compression.

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
   path the audit missed. Mitigation: M3a CI runs the full test
   matrix including `native-sign` and FFI test suites; any missed
   call site surfaces as a compile or test failure.

2. **C++ side not audited.** The C++ `wallet2` and FFI consumer code is
   in scope of the wallet RPC server cutover, not this migration.
   The audit's exclusion-from-migration findings are gated on the
   premise that the FFI path remains until the cutover removes it
   wholesale; if that premise changes, the audit must be re-run.

3. **Provenance of the secret-carrying pattern: the C++ `wallet2`
   struct, with no Rust intermediary in the workspace.** An earlier
   audit draft asserted that a "spot-check against `monero-oxide`'s
   `transfer_details`" showed an alternative Rust pattern available
   to the workspace as precedent. That framing is incorrect and is
   retracted.

   What the workspace actually contains:

   - **`rust/shekyl-oxide/`** vendors a specific subset of upstream
     `monero-oxide` — proof-system primitives (`fcmps`, `bulletproofs`,
     `helioselene`, `divisors`, `generalized-bulletproofs`,
     `fcmp/fcmp++`), transaction wire format (`primitives`,
     top-level `shekyl-oxide`), I/O and generator helpers, and the
     RPC shim (`rpc`, `rpc/simple-request`). Wallet-side state
     is **not** vendored. The `shekyl-oxide/wallet/` subtree exists
     only in the standalone upstream clone outside `shekyl-core` and
     is not part of Shekyl's compiled workspace.
   - The C++ `src/wallet/wallet2.h:327–453` defines
     `struct transfer_details` carrying `m_mask` (Pedersen commitment
     mask), `m_y` (HKDF-derived T-component scalar), `m_k_amount`
     (HKDF-derived amount key), and `m_combined_shared_secret` (KEM
     combined secret). This shape was ported to Shekyl's Rust
     `engine-state` crate directly, with no Rust intermediary.

   The provenance of `TransferDetails`'s secret-carrying shape is
   the C++ struct in `wallet2.h`, ported into Rust within
   `shekyl-core` itself. There is no workspace-internal Rust
   precedent the port could have followed; the inheritance is
   single-step from C++.

   The architectural-inheritance rule's primary application stands:
   `TransferDetails` carries derived per-output secrets that
   contradict `36-secret-locality.mdc`'s "engine owns secrets"
   discipline; the migration is the rule's primary statement applied
   to that inheritance. The case does not depend on a Rust-side
   precedent — the C++ structural-drift evidence is sufficient.

   The continuity-of-discipline observation worth pinning is
   different from the previous draft's precedent claim: `shekyl-oxide`
   itself is the artifact of Shekyl's discipline applied to upstream
   proof-system code (legacy proof types removed; FCMP++ and PQC
   added; `#![deny(unsafe_code)]` enforced; `RELEASE-BLOCKER` items
   tracked per `SHEKYL_READINESS.md`). The `TransferDetails`
   migration extends that same discipline — already operative in the
   vendored proof-system surfaces — to wallet-side state inherited
   from `wallet2.h`. The migration is continuity-of-discipline
   across the codebase, not novel-discipline-introduction.

4. **Snapshot stability.** Audit holds against
   `chore/spec-stage-1-pr3-keyengine-round` HEAD `ffcaa62e9`. If `dev`
   advances before M3a opens, the audit re-runs as part of M3a's
   pre-flight. The freeze on `dev` (per migration plan) is the
   structural mitigation; this section is the residual fallback.

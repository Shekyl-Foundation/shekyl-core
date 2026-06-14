# CT-5 — engine wiring: production CurveTreeClient into the 2A signer (design — Round 1, OPEN)

**Status:** Round 1 open (2026-06-13). Substrate audit complete and
source-pinned (§3). No code yet — this doc is the frozen contract and
threat-model frame the implementation cuts against, per
`05-system-thinking.mdc` (spec first, code second). Design rounds run to
closure before any production commit.

**Parent design:** [`CURVE_TREE_CLIENT.md`](./CURVE_TREE_CLIENT.md) §9 CT-5 row:
"Wire into 2A signer behind the §3.5 contract (replaces synthetic vectors); 2A
§3.7.6 terminology correction (§5.4)." The terminology correction already
landed (parent §5.4 "Landed (Round-1 cross-edit)"); CT-5 confirms it, it is not
new work (§7).

**Sibling designs consumed:** [`PHASE_2A_SEND_PATH.md`](./PHASE_2A_SEND_PATH.md)
(the signer this wires into — F1/F2 vessel, §3.6 `ProofStale`, §3.7.5 C2 gate,
§3.7.6 C3 path precondition), and the landed CT-1–CT-4 client surface
([`CT3_ROUND1_CLOSEOUT.md`](./CT3_ROUND1_CLOSEOUT.md),
[`CT4_ROUND1_CLOSEOUT.md`](./CT4_ROUND1_CLOSEOUT.md)).

**Process discipline:** this plan-doc cites `26-sub-pr-design-discipline.mdc`
(multi-round per-trait PR; crosses the FFI-adjacent signer boundary and the
consensus-coupled reference-block selection). The substrate audit (§3) follows
**A2** (audit-against-actual-code, pinned `path:line` citations read at the dev
tip, not summarized); sub-PR boundaries follow **A1** (function-body
replacement) and **A4** (reversion-clause for boundary moves); findings route
per **A5**. The threat-model pass (§5) is the **A3** late-round addendum.

**Timeframes (`05-system-thinking.mdc`):** addresses **Now** (V3.0 pre-genesis:
the production send path stops using synthetic membership vectors and proves
against the real wallet-reconstructed curve-tree root). Mining-era end and the
V4 lattice transition are unaffected — CT-5 is orchestration over the CT-1–CT-4
client and the 2A signer, adding no consensus rule and no new crypto primitive.

---

## 1. Scope and definition of done

### In scope

1. **Client ownership and lifecycle.** The `Engine` owns a production
   `CurveTreeClient` (CT-1–CT-3), opened against an on-disk `LeafStore` beside
   the wallet files, resumed on open, dropped on close.
2. **Forward ingest.** The refresh producer feeds every scanned block into
   `CurveTreeClient::ingest_block` at consecutive height, keeping the tree's
   `sync_tip` in lockstep with the ledger tip it already advances.
3. **Reorg rollback + poison recovery.** When refresh detects a fork, the tree
   rolls back to the fork height alongside the ledger rewind, and the
   `ClientError::Poisoned` drop-and-reopen contract is honored.
4. **Real path assembly.** The 2A signer's synthetic `TreeContext` / membership
   vectors (`signing_assembly` + `sign_bridge` + `synthetic_tree`) are replaced
   by `CurveTreeClient::assemble_path` per spend input, mapped onto the existing
   `TxInputSigningContext` / `SpendInput` shapes (the §3.5 adapter is a field
   copy).
5. **Reference-block selection.** The reference block is chosen at
   `tip − REF_ANCHOR_AGE` via `reference::select_reference_height`, the
   reference-height block hash + header `curve_tree_root` are bound into a
   `ReferenceBlock`, and the C2 spendability gate (`eligible_height ≤
   reference_height`) is enforced at selection time.
6. **Proactive rebuild horizon (the interim `ProofStale` guard).** Pending
   transactions track their reference height; `reference::should_reanchor`
   drives a pre-emptive rebuild before a proof ages past the daemon acceptance
   window (parent §5.2; 2A §3.6 reactive backstop stays deferred to Phase 6).

### Out of scope

- The C++ `get_curve_tree_leaves` bulk-leaf RPC and any daemon change (parent §6
  / §9 C++ row; block-derived forward sync is the confirmed CT-3 default, so the
  RPC is not on the CT-5 path).
- Reactive `ProofStale` *detection* — needs a daemon-side stale-root signal,
  deferred to Phase 6 with a `SHEKYLD_PREREQUISITE` (2A §3.6 reversion clause).
  CT-5 lands only the proactive horizon guard.
- Store-backed / pruned-tree path assembly (`assemble` reads the in-memory entry
  vec today; CT-3 F5 disposition). CT-5 consumes the in-memory path; the
  pruned-store path is its own follow-up.
- `ArchivalEngine` serve/market, Tor/I2P routing (parent §7.6 / §8 #11).
- Multisig (v31) send — CT-5 wires the single-signer 2A path; multisig spend
  reuses the same assembled path but is a separate signer surface.

### DoD (proposed — confirmed/adjusted at round closure)

- A built-and-submitted transaction in the `TestDaemon` harness proves against a
  **real reconstructed root**: the tree the refresh loop ingested produces the
  `tree_root` the proof is bound to, and `assemble_path`'s C3 precondition
  (`c1_layers.len() + c2_layers.len() + 1 == tree_depth`) holds — replacing the
  `synthetic_tree_root_from_leaf_chunk` placeholder.
- Refresh + reorg KAT: ingest N blocks, fork at `k`, and the post-rollback tree
  root at every reference height equals the CT-2 oracle (reuse the
  `ct2_tier_a.json` `reorg_deep` fixture through the engine path, not the
  client-only path).
- The C2 gate rejects an output whose `eligible_height > reference_height` with
  a clean `OutputNotYetSpendable { eligible_height, reference_block_height,
  wait_blocks }` (2A §3.7.5 point 3), not an opaque assembly miss.
- The structural no-secrets test extends over the engine's client ownership: the
  `CurveTreeClient` and `AssembledPath` carry no secret-bearing field (parent
  §4.1/§4.2; the secrets are added only in `sign_bridge` → `SpendInput`).
- `cargo fmt` / `clippy -D warnings` / `cargo test` clean across
  `shekyl-engine-core` and `shekyl-curve-tree`.

---

## 2. The contract CT-5 consumes (landed CT-1–CT-4)

CT-5 adds **no** new client API. Everything below is landed and KAT-gated; CT-5
is the first production caller. The contract surfaces (parent §3.5):

| Surface | Signature | CT-5 use |
|---------|-----------|----------|
| `CurveTreeClient::open(path)` | resume from on-disk `LeafStore` | open at wallet open |
| `ingest_block(&mut self, BlockLeaves<'_>) -> Result<(), ClientError>` | consecutive-height forward sync | per block in refresh |
| `rollback_to_fork(&mut self, BlockHeight) -> Result<(), ClientError>` | truncate + rebuild; sets/clears `poisoned` | on reorg |
| `assemble_path(&self, &OutputIdentity, &ReferenceBlock) -> Result<AssembledPath, ClientError>` | gated on §3.3 root match | per spend input |
| `reference::select_reference_height(tip) -> Option<u64>` | `tip − REF_ANCHOR_AGE`; `None` pre-maturity | reference selection |
| `reference::should_reanchor(tip_now, ref_h) -> bool` | reached `REBUILD_AT` (or ref above tip) | proactive rebuild |
| `reference::proof_submittable` / `proof_expired` / `reference_block_age` | acceptance-window predicates | horizon guard |

The data carried (parent §3.5):

- `AssembledPath { leaf_chunk: Vec<ChunkLeaf>, c1_layers: Vec<Vec<[u8;32]>>,
  c2_layers: Vec<Vec<[u8;32]>>, tree: TreeContext }`.
- `ChunkLeaf { output_key, key_image_gen, commitment, h_pqc }` — four `[u8;32]`,
  **field-identical** to `shekyl_tx_builder::LeafEntry`.
- `TreeContext { reference_block, tree_root, tree_depth }` — field-identical to
  `shekyl_tx_builder::TreeContext`.
- `OutputIdentity { output_key, commitment }` — what the client matches on (§4.3).
- `ReferenceBlock { height, curve_tree_root, block_hash }` — the caller's
  consensus anchor (CT-3↔CT-4 hardening); `block_hash` is echoed into
  `TreeContext::reference_block`, `curve_tree_root` is the header-committed root
  the proof binds to, and `tree_depth` is *derived* during assembly.

**The single invariant CT-5 must uphold (C1, parent §3.5 / 2A §3.7.1):** every
input of one transaction calls `assemble_path` with the **same** `ReferenceBlock`
— one tree snapshot per tx, never per-input. The 2A vessel already makes this
structurally unrepresentable (`FcmpPlusPlusContext { tree }` is tx-level); CT-5
must not reintroduce a per-input root.

---

## 3. Integration substrate (A2 — audit-against-actual-code)

All citations read at the `dev` tip (merge of PR #136, `49a07ad2b`).
`shekyl-engine-core` has **zero** dependency on `shekyl-curve-tree` today; CT-5
adds the dependency and the call sites below.

### 3.1 Client ownership and lifecycle

The engine has no `CurveTreeClient` field. The orchestrator composes file, keys,
ledger, daemon, refresh, pending-tx (`engine/mod.rs:6–24`). The ledger snapshot
that refresh advances and the signer reads is reached via
`self.ledger.with_ledger_block(...)` (`local_pending_tx.rs:613, 656, 775`).

**Decision (R1-Q1, open):** where the client lives, how it is opened, and the
single-writer discipline `ingest_block`/`rollback_to_fork` require
(`&mut self`). Candidates:

- **(a)** A field on `Engine`, opened in the engine constructor against a path
  derived from the wallet dir, behind the same interior-mutability the ledger
  uses so refresh (writer) and pending-tx (reader) share it.
- **(b)** A sub-state owned by the refresh engine (the only writer), with the
  signer reading an immutable assembled path handed across the
  superset/projection boundary (2A §3.7.9) rather than holding the client.

Pull toward **(b)**: refresh is the sole `&mut` user (ingest + rollback); the
signer only needs `&self` `assemble_path`. The client's single-writer/
single-reader shape (CT-1 redb single write txn) matches refresh-writes /
signer-reads cleanly. R1-Q1 resolves the exact ownership cell and the open path.

### 3.2 Forward ingest (the refresh producer)

The per-block loop is `LocalRefresh::produce_scan_result`
(`local_refresh.rs:531–538` signature; `while h < end` loop `:620–812`). Each
iteration: `fetch_block_with_retry` → reorg check → record `block_hash` + key
images → `scanner.scan_with_cancel` → append transfers → `h += 1`. The result
`ScanResult { processed_height_range, parent_hash, block_hashes, new_transfers,
spent_key_images, stake_events, reorg_rewind }` is then merged by
`Engine::apply_scan_result` (`merge.rs:196–246`), per-height at `merge.rs:440–464`.

`ingest_block` (`client.rs:474–484`) is **consecutive-height**: it computes
`expected = last_ingested + 1` and returns `NonConsecutiveBlockHeight` otherwise.
Its input is `BlockLeaves { height, txs: &[TxLeafInputs] }` where
`TxLeafInputs { is_miner, leaf_hash_blob, outputs: &[RawOutput] }` and
`RawOutput { output_key, commitment, target }` (`client.rs:66–97`).

**Decision (R1-Q2, open):** ingest *site* and *ordering* relative to the ledger
merge.

- The producer has a `ScannableBlock` in hand after `fetch_block_with_retry`;
  decoding it to `BlockLeaves` there is natural, but the producer holds `&self`
  and runs before the merge that advances the canonical tip.
- The merge (`apply_scan_result_to_state`) is the height-ordered, `&mut`,
  post-validation point where the ledger tip actually advances — the natural
  place to advance the tree tip in lockstep so the two never diverge across a
  cancelled/failed refresh.

Pull toward **ingest in the merge loop** (`merge.rs:440–464`), driven from the
`block_hashes` + per-height transfer data the merge already iterates: it keeps
tree-tip and ledger-tip atomic w.r.t. the same `&mut` state transition and
inherits the merge's height ordering. The producer would carry the *raw leaf
inputs* (decoded `BlockLeaves` data) forward on `ScanResult` rather than
ingesting mid-scan. R1-Q2 resolves site + what `ScanResult` must carry. This is
the **A1 frozen-contract** question: what new field(s) `ScanResult` grows.

**Decision (R1-Q3, open):** the `ScannableBlock → BlockLeaves` decode — which
outputs become leaves (coinbase vs non-coinbase maturity, `is_miner`,
`leaf_hash_blob` provenance) must match the CT-2 drain-order replication exactly
(parent §6 / CT2_DRAIN_ORDER.md). The decode adapter is the highest
inheritance-risk surface (it reproduces consensus leaf-insertion order); it gets
a dedicated KAT against the CT-2 oracle.

### 3.3 Reorg rollback + poison recovery

Refresh detects a fork by parent-hash mismatch (`local_refresh.rs:634–673`),
emits `ReorgRewind { fork_height }`, and the merge calls
`LedgerIndexes::handle_reorg(ledger, rewind.fork_height)` (`merge.rs:337–338`;
`ledger_indexes.rs:306–343` drops transfers ≥ fork, rewinds tip, rebuilds
indexes, `staker_pool.handle_reorg`). The tree is **not** rewound today.

`CurveTreeClient::rollback_to_fork` (`client.rs:426–445`) truncates the store,
sets `poisoned = true`, rebuilds in-memory, clears `poisoned` on success. If it
fails between truncate and rebuild the client stays `Poisoned`; the recovery
contract is **drop the client and `open()` again** (`client.rs:169–177`).

**Decision (R1-Q4, open):** CT-5 calls `rollback_to_fork(fork_height)` in the
same `handle_reorg` transition (`merge.rs:337`), *before or after* the ledger
rewind, and on `Err(ClientError::Poisoned)` (or any rollback error) drops and
reopens the client, then re-syncs forward from the fork. Open sub-points:

1. Ordering vs the ledger rewind (tree and ledger must agree on the post-fork
   tip; if one rewinds and the other doesn't, the next `ingest_block` either
   `NonConsecutiveBlockHeight`-errors or silently diverges).
2. Whether drop-and-reopen is automatic (engine self-heals) or surfaced as a
   refresh error the caller retries. Pull toward **automatic reopen** — a poison
   is a transient persistence hiccup, not a user-actionable fault, and refresh
   already retries blocks.
3. The poison reaction must not lose the ledger's reorg progress; it re-runs the
   same forward sync the ledger does.

### 3.4 Real path assembly (replacing the synthetic vectors)

The synthetic surface, all to be replaced:

- `local_pending_tx.rs:657` — `let tree_depth = 1u8;` (hardcoded placeholder).
- `local_pending_tx.rs:775–784` — `assemble_tx_to_sign(.., tip_hash,
  tree_depth, ..)` passes the **synced tip hash** (`tip_hash =
  block_hash_at(synced)`, `:615`) as the `reference_block`. **Confirmed bug:**
  the reference block is the tip, not `tip − REF_ANCHOR_AGE`; the C1 snapshot is
  anchored at the wrong height. CT-5 fixes this (§3.5).
- `signing_assembly.rs:47–51, 88–115` — `synthetic_tree_context(...)` and
  per-input `enrich_input_tree(vec![leaf_entry], tree_depth)` fabricate the path;
  `synthetic_h_pqc_bytes` / `key_image_gen_bytes` fabricate leaf fields.
- `sign_bridge.rs:301–320` — re-runs `enrich_input_tree` and overwrites
  `tree_root` via `synthetic_tree_root_from_leaf_chunk`.
- `engine/synthetic_tree.rs` — `placeholder_selene_sibling`,
  `placeholder_helios_sibling`, `synthetic_h_pqc_bytes`,
  `synthetic_tree_context`, `enrich_input_tree`, `synthetic_tree_root_from_leaf_chunk`.

The adapter is a field copy (parent §3.5, confirmed): `ChunkLeaf` ≡
`tx_builder::LeafEntry` (4×32), `curve_tree::TreeContext` ≡
`tx_builder::TreeContext` (3 fields). Per spend input:
`OutputIdentity { output_key, commitment }` (from the selected
`TransferDetails`) + the one tx-level `ReferenceBlock` → `assemble_path` →
copy `leaf_chunk` / `c1_layers` / `c2_layers` into `TxInputSigningContext`
(`traits/key.rs:305–332`); the tx-level `TreeContext` populates
`FcmpPlusPlusContext { tree }` (`:556–559`). Secrets are still added only in
`sign_bridge` → `SpendInput` (`tx-builder/types.rs:232–271`), so the
secret-locality boundary is unchanged.

**Decision (R1-Q5, open):** the `synthetic_tree` module's disposition.
Per `60-no-monero-legacy.mdc` / `15-deletion-and-debt.mdc` it is pre-genesis
scaffolding with no users — **deleted, not gated**, once `assemble_path` is the
producer. Tests that depend on synthetic vectors migrate to the real client over
the CT-2 fixture (the `TestDaemon` harness fakes the daemon, not the tree, so
its proof-validity tests gain real coverage). R1-Q5 confirms the deletion set
and the test migration, applying the A4 reversion clause (the module reopens
only if a non-daemon test surface genuinely needs synthetic vectors — none
identified).

### 3.5 Reference-block selection + proactive horizon

No engine code consumes `reference::*` today (confirmed: the predicates appear
only in `shekyl-curve-tree` and design docs). The engine *does* embed
`FCMP_REFERENCE_BLOCK_MIN_AGE` / `MAX_AGE` via `build.rs` for multisig intent
validation (`multisig/v31/intent.rs`) — same JSON source, so the constants are
already in the build; CT-5 reuses the `reference.rs` predicates rather than
re-deriving.

At build time (`local_pending_tx.rs` build path) CT-5:

1. computes `reference_height = select_reference_height(synced)`; `None` →
   clean "wallet too young to spend" error (pre-maturity window);
2. binds `ReferenceBlock { height: reference_height, curve_tree_root:
   <header root at reference_height>, block_hash: block_hash_at(reference_height) }`
   — the reference-height block hash and its header-committed root, **not** the
   tip;
3. enforces the C2 gate at selection (2A §3.7.5): outputs with
   `eligible_height > reference_height` are not selected, surfaced as
   `OutputNotYetSpendable`;
4. records `reference_height` on the pending tx so `should_reanchor(tip_now,
   reference_height)` can drive a pre-emptive rebuild before submit (the interim
   `ProofStale` guard; 2A §3.6).

**Decision (R1-Q6, open):** the source of the **header `curve_tree_root` at the
reference height**. The ledger records `block_hash_at(h)` (`local_pending_tx.rs:615`);
does it record the per-height `curve_tree_root` the proof must bind to, or is
that fetched/derived? The client reconstructs roots but stores no header roots
(parent §3.3 — root is *verified* against the header, the caller supplies it).
R1-Q6 pins where the engine reads the header `curve_tree_root` at an arbitrary
past height. This is the load-bearing data-availability question for §3.5; if
the ledger does not retain per-height curve-tree roots, CT-5 grows that
retention (small, append-only) or sources it from the synced header.

---

## 4. Round-1 open questions (agenda)

Consolidated from §3. Each resolves to a pinned disposition before closure.

| ID | Question | Pull (provisional) |
|----|----------|--------------------|
| **R1-Q1** | Where the `CurveTreeClient` lives + open path + single-writer cell (§3.1) | refresh-owned writer, signer reads `&self` |
| **R1-Q2** | Ingest site (producer vs merge) + what `ScanResult` carries (§3.2) | ingest in the merge loop; carry decoded leaf inputs on `ScanResult` |
| **R1-Q3** | `ScannableBlock → BlockLeaves` decode = consensus drain order (§3.2) | dedicated KAT vs CT-2 oracle; reuse CT2_DRAIN_ORDER |
| **R1-Q4** | Reorg ordering + automatic poison drop-and-reopen (§3.3) | rollback in `handle_reorg` transition; auto-reopen |
| **R1-Q5** | `synthetic_tree` deletion set + test migration (§3.4) | delete (no users); migrate tests to real client + CT-2 fixture |
| **R1-Q6** | Source of header `curve_tree_root` at reference height (§3.5) | from synced header; grow ledger retention only if absent |

**R1-Q6 is the gating question** — if the engine cannot supply the header
`curve_tree_root` at an arbitrary reference height, the assembled proof cannot be
bound, and the answer reshapes ledger retention. It is resolved first.

---

## 5. Threat-model frame (A3 — late-round addendum, opened early)

CT-5 is orchestration (no new crypto, no new consensus rule), so the §3.7.x
security boundaries are inherited, not re-litigated. The objectives below are
the active-defense pass; each routes to (a) in-scope absorption, (b) discipline
note, or (c) named forward-action.

1. **Wrong-root / stale-snapshot spend (O1).** A built proof anchored at the
   wrong height or a stale root. *Defense:* C1 single-`ReferenceBlock`-per-tx
   (§2), C2 selection gate, C3 path precondition, proactive `should_reanchor`.
   *Disposition (a):* the §3.5 reference-selection fix is the direct remedy for
   the confirmed tip-as-reference bug.
2. **Tree/ledger tip divergence across reorg (O2).** Ledger rewinds, tree does
   not (or vice versa), so the next ingest diverges silently. *Defense:*
   R1-Q4 atomic rollback in the same `handle_reorg` transition;
   `NonConsecutiveBlockHeight` is a loud failure, not silent drift. *Disposition
   (a).*
3. **Poison left unhandled (O3).** A failed rollback leaves a `Poisoned` client
   that then serves stale paths. *Defense:* `ensure_live()` fail-closes every
   client method; R1-Q4 drop-and-reopen. *Disposition (a):* the poison contract
   is machine-enforced; CT-5 must exercise the reopen path in a KAT.
4. **Secret leak via the new ownership (O4).** The engine now holds a tree
   client on the orchestrator side. *Defense:* the client is public-data-only
   (parent §4.1/§4.2 structural no-secrets test); `AssembledPath` carries no
   secret; secrets enter only in `sign_bridge → SpendInput`. *Disposition (a):*
   extend the no-secrets structural test over the engine's client field
   (architectural-inheritance §, `16-architectural-inheritance.mdc` — orchestrator
   must not become a secret holder).
5. **Lying-daemon DoS via leaf inputs (O5).** A malicious daemon feeds bad
   leaves; the reconstructed root won't match the header. *Defense:* parent §3.3
   root-vs-header verify (DoS only, never a witness leak); `assemble_path` is
   gated on the root match. *Disposition (b):* discipline note — CT-5 must not
   weaken the gate by assembling before the root is verified.
6. **Resource exhaustion on reorg storm (O6).** Repeated deep rollbacks +
   re-sync. *Disposition (c):* forward-action — bounded only by the existing
   refresh retry/cancel budget; no new bound in CT-5, recorded for the refresh
   resilience review.

---

## 6. Sub-PR decomposition (A1 — function-body replacement; provisional)

Boundaries are provisional until R1-Q1/Q2/Q6 close (they decide field shapes).
Each sub-PR lands ≤ the `06-branching.mdc` 5-day / 10-commit envelope; none is a
consensus-atomic cutover (`07-consensus-atomic-cutovers.mdc` not invoked — the
synthetic→real swap is flag-decomposable behind the assembler boundary).

- **CT-5a — client lifecycle + ingest (no signer change).** Add the
  `shekyl-curve-tree` dependency, the ownership cell (R1-Q1), open/resume on
  engine open, the `ScannableBlock → BlockLeaves` decode (R1-Q3 KAT), and ingest
  in the chosen site (R1-Q2). Reorg rollback + poison reopen (R1-Q4). The signer
  still uses synthetic vectors. DoD: refresh + reorg KAT root-matches the CT-2
  oracle through the engine path.
- **CT-5b — reference selection + header-root availability (R1-Q6).** Wire
  `select_reference_height`, the C2 gate, and the header `curve_tree_root`
  source. Lands the `ReferenceBlock` construction the signer will consume; the
  signer still builds synthetic paths but against the *real* reference
  selection. DoD: C2 `OutputNotYetSpendable` KAT.
- **CT-5c — assembler cutover + `synthetic_tree` deletion (R1-Q5).** Replace
  `signing_assembly`/`sign_bridge` synthetic vectors with `assemble_path`; delete
  `synthetic_tree`; migrate tests. DoD: real-root proof builds + submits in the
  `TestDaemon` harness; C3 precondition holds.
- **CT-5d — proactive horizon guard + closeout.** `should_reanchor` rebuild loop
  for pending txs; parent §9 CT-5 row → closed; `CT5_ROUND1_CLOSEOUT.md`;
  FOLLOWUPS/CHANGELOG. DoD: horizon KAT; docs resync (`91-documentation-after-plans.mdc`).

---

## 7. Documentation cross-edits

- **Parent §5.4 terminology correction — already landed.** The "two ages, not
  one" cross-edit to 2A §3.7.1/§3.7.5/error-table/§9 landed in CT-4 Round 1
  (parent §5.4 "Landed (Round-1 cross-edit)"). The §9 CT-5 row's reference to it
  is stale; CT-5d corrects the row to note it is confirmed, not pending. **No new
  2A edit is required** — verified: 2A §3.7.5 already reads `reference_height =
  tip − REF_ANCHOR_AGE` with the explicit "two ages must not be conflated"
  caveat.
- **`CURVE_TREE_CLIENT.md` §9 CT-5 row** → "Round 1 closed" with the landed
  modules/symbols at closeout (CT-5d).
- **`PHASE_2A_SEND_PATH.md`** — the F1/F2 synthetic-vector notes get a back-ref
  to CT-5 as the production replacement; §3.6 `ProofStale` interim-guard note
  cross-links the landed `should_reanchor` wiring.
- **`CHANGELOG.md`** — per sub-PR.

---

## 8. Review checklist (pre-implementation)

- [ ] §1 scope + DoD agreed (real-root proof in `TestDaemon`; reorg KAT vs CT-2
  oracle; C2 clean error; no-secrets test over engine client).
- [ ] §2 contract confirmed — CT-5 adds **no** new client API; C1
  one-`ReferenceBlock`-per-tx upheld.
- [ ] R1-Q1 client ownership + open path + single-writer cell.
- [ ] R1-Q2 ingest site + `ScanResult` field growth (A1 frozen contract).
- [ ] R1-Q3 `BlockLeaves` decode = CT-2 drain order (dedicated KAT).
- [ ] R1-Q4 reorg ordering + automatic poison drop-and-reopen.
- [ ] R1-Q5 `synthetic_tree` deletion set + test migration (A4 reversion clause).
- [ ] R1-Q6 **(gating)** header `curve_tree_root` source at reference height.
- [ ] §3.4 confirmed bug fixed: reference block = `tip − REF_ANCHOR_AGE`, not the
  tip (`local_pending_tx.rs:781`); `tree_depth` derived, not `1u8` (`:657`).
- [ ] §5 threat objectives O1–O6 each routed (a)/(b)/(c).
- [ ] §6 sub-PR boundaries confirmed after R1-Q1/Q2/Q6 close.
- [ ] §7 parent §9 row + 2A back-refs; §5.4 confirmed-not-pending.


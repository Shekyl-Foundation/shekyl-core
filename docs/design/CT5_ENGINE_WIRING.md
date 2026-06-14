# CT-5 — engine wiring: production CurveTreeClient into the 2A signer (design — Round 1, OPEN)

**Status:** Round 2 dispositions resolved (2026-06-14). Round 1 closed
R1-Q1–R1-Q6 (§4); Round 2 applied three standing architectural principles
(below) and revised R1-Q1 (→ actor) and R1-Q6 (→ derive-not-hold). No code yet —
this doc is the frozen contract and threat-model frame the implementation cuts
against, per `05-system-thinking.mdc` (spec first, code second). A closure-review
round (and the A3 threat pass against §5) precedes any production commit.

**Standing principles this design is held to** (operator directive, 2026-06-14;
they govern every CT-5 disposition):

1. **Rust-first, push the FFI boundary.** This is the Rust wallet rewrite; the
   C++ surface goes away at Stage 5. New logic is Rust — including daemon-side
   work when a CT-5 change touches the daemon (route through a `shekyl_*` FFI
   entry point, keep C++ a marshaling shim) per `20-rust-vs-cpp-policy.mdc`.
2. **`shekyl-oxide` is ours to rewrite** (except vendored crypto primitives).
   Extending its block types for Shekyl consensus (§3.6, pre-0) is normal work,
   not fork-fighting.
3. **Maximize the actor pattern; derive over hold.** Public state lives behind a
   `kameo` actor with a `Clone` handle (mirror `KeyActor`); the engine holds the
   handle, not the state. Prefer re-deriving a value from owned state over
   persisting it.

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
- The structural no-secrets test extends over the `CurveTreeHandle` message
  surface: the `CurveTreeActor` messages, `CurveTreeClient`, and `AssembledPath`
  carry no secret-bearing field (parent §4.1/§4.2; the secrets are added only in
  `sign_bridge` → `SpendInput`).
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

**Decision (R1-Q1, RESOLVED Round 2 — `CurveTreeActor` + `CurveTreeHandle`).**
Draft history: Round-1 first leaned "refresh-owned writer" (corrected by the
lock-free-producer model — `mod.rs:525–528`), then "plain `Engine` field under
the shared RwLock." Round 2 applies the actor principle and lands on the
`KeyActor` shape (`key_actor.rs`):

- A **`CurveTreeActor`** (`kameo`) owns the `CurveTreeClient` privately; its
  single-threaded message loop serializes writes (matching redb's single-writer
  txn). Fail-stop on panic (`on_panic → ControlFlow::Break`) collapses every
  handle call to a terminal error — the same shape as the client's `Poisoned`
  contract, so R1-Q4 reopen = actor respawn.
- `Engine` holds a `Clone` **`CurveTreeHandle`** (not the client), exactly as it
  holds `KeyEngineHandle` in place of an `AllKeysBlob` field.
- Writers send `Ingest` / `Rollback`; the signer sends `AssemblePath` (read).
  "Sole writer" becomes **sole ingest-sender** (the merge); the signer is
  read-only over the handle.

**Consistency without a shared lock (the Round-2 change from the field design).**
The merge does `handle.ingest(leaves@H).await` and **commits the ledger to `H`
only on ack**; on ingest failure the ledger does not advance and the refresh
attempt aborts/retries. Cross-divergence is still caught by the height invariant
(`NonConsecutiveBlockHeight` → loud, never silent) and healed by respawn + resync
(R1-Q4). This is derive>hold at the consistency layer: the tree *derives* its
agreement with the ledger from the height check rather than a lock *holding* the
two tips lockstep. The `ask().await` runs under the engine's `tokio::sync::RwLock`
write guard — legal and precedented (the merge post-pass already `ask`s the key
actor under the guard; `key_actor.rs` §"Integration"), and brief (local redb
work, no network).

**Counterpoint recorded (why this is a preference, not a forced move).**
`KeyActor`'s load-bearing justification is secret isolation; the curve tree is
**public data** (parent §4.1/§4.2 no-secrets test), so the actor here does not
buy a secret-containment property — it buys fail-stop, single-writer, and
message-discipline consistency with the rest of the engine. Adopted per the
standing actor principle; the cost is the two-phase ingest-ack-before-commit
ordering above.

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

**Decision (R1-Q2, RESOLVED — merge drives the actor ingest; `ScanResult` grows
a transit leaf set + header root).** The merge (`apply_scan_result_to_state`,
`merge.rs:440–464`) sends `handle.ingest(...)` and commits the ledger on ack
(R1-Q1). The producer decodes what it already parses and carries it forward on
`ScanResult` as **transit** data (not persisted state — consistent with
derive>hold):

- The **full per-block leaf set** (all on-chain outputs, not just owned).
  `ScanResult` today carries `block_hashes` + `new_transfers`, but
  `new_transfers` is **wallet-owned only** (`scan.rs:101`); the tree contains
  every output, so the producer materializes all of them where the
  `ScannableBlock` is in hand.
- The **per-block header `curve_tree_root`** (from pre-0's parser, 32 B/height),
  consumed by the merge's §3.3 ingest-time verify (R1-Q6) and then discarded.

This is the **A1 frozen-contract** decision — the two new `ScanResult` fields are
frozen here; both are transit-only (dropped after merge), so no persistence /
schema impact.

Rejected alternative: producer sends leaves straight to the tree actor,
bypassing the merge. It avoids growing `ScanResult` but decouples tree-ingest
from the ledger commit, so the ingest-ack-before-commit ordering (R1-Q1) can no
longer gate the ledger advance — reintroducing O2. Rejected on correctness.

**Decision (R1-Q3, RESOLVED — dedicated decode KAT vs the CT-2 oracle).** The
`ScannableBlock → BlockLeaves` decode (which outputs become leaves; coinbase vs
non-coinbase maturity, `is_miner`, `leaf_hash_blob` provenance) must match the
CT-2 drain-order replication exactly (parent §6 / `CT2_DRAIN_ORDER.md`). This is
the highest inheritance-risk surface (it reproduces consensus leaf-insertion
order), so it gets a dedicated KAT (A2 audit-against-actual-code) asserting the
engine-path decode reproduces the `ct2_tier_a.json` oracle leaf stream. Lands in
CT-5a (§6).

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

**Decision (R1-Q4, RESOLVED — rollback in `handle_reorg`, automatic
drop-and-reopen).** CT-5 calls `rollback_to_fork(fork_height)` inside the same
`handle_reorg` transition (`merge.rs:337`), under the write guard, atomic with
`LedgerIndexes::handle_reorg`, so tree and ledger agree on the post-fork tip (if
they didn't, the next `ingest_block` would `NonConsecutiveBlockHeight`-error —
the desired fail-closed behavior, not silent divergence). On
`Err(ClientError::Poisoned)` (or any rollback error, or a fail-stopped actor) the
engine **automatically respawns** the `CurveTreeActor` (drop + reopen the client
in a fresh task) and re-runs the same forward sync the ledger does: a poison is a
transient persistence hiccup, not a user-actionable fault, and refresh already
retries. Respawn is the actor-shape form of drop-and-reopen (R1-Q1); the path is
exercised by a KAT (O3, §5).

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

**Decision (R1-Q5, RESOLVED — delete `synthetic_tree`, migrate tests).**
Per `60-no-monero-legacy.mdc` / `15-deletion-and-debt.mdc` it is pre-genesis
scaffolding with no users — **deleted, not gated**, once `assemble_path` is the
producer (CT-5c). Tests that depend on synthetic vectors migrate to the real
client over the CT-2 fixture (the `TestDaemon` harness fakes the daemon, not the
tree, so its proof-validity tests gain real coverage). A4 reversion clause: the
module reopens only if a non-daemon test surface genuinely needs synthetic
vectors — none identified.

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

**Decision (R1-Q6, RESOLVED — wire §3.3 fully; header-parser prerequisite).**
The initial draft framed this as "without the header root the proof cannot be
bound." **That was wrong.** `assemble_path` reconstructs the root from leaves,
and CT-2 proved that reconstruction equals the consensus root at every height
(`recon_kat.rs` on `ct2_tier_a.json`), so the wallet *can* bind a proof to its
**own reconstructed** root and the daemon will accept it. What the header root
actually buys is the **§3.3 integrity defense**: `assemble_path` is "gated on
the §3.3 root match," comparing its reconstruction against the caller-supplied
`ReferenceBlock.curve_tree_root`. Supply the *self-reconstructed* root and that
gate is a **tautology**; supply the *header* root and it catches a lying/buggy
daemon, turning a silent submit-time failure into a **detected DoS** (parent
§3.3; threat O5, §5).

Per `00-mission.mdc` priority-1 (security is a precondition), CT-5 wires §3.3
**fully**, not the tautological gate. That requires a real source of the
header-committed `curve_tree_root` — and the substrate audit found there is
**none today** (§3.6). The fix is a prerequisite PR (§6, CT-5 pre-0) that teaches
the Rust block parser the consensus field.

**Derive, don't hold (Round 2).** The header root is *not* retained per height —
no `42-serialization-policy.mdc` schema bump. Instead:

- **Verify at ingest (transient).** Each ingested block carries its header root
  (pre-0); the merge reconstructs the new root and compares — loud DoS on
  mismatch. This is *continuous* §3.3 (every block), strictly stronger than a
  point-in-time send check, and the header root is held only for the duration of
  the comparison, then dropped.
- **Re-derive at send.** The reference-height root is reconstructed from the
  already-held tree (the drain-cutoff reconstruction `assemble_path` performs as
  of `reference.height`). Because §3.3 was enforced at ingest, the wallet's
  reconstruction at `H_ref` equals consensus, so the proof binds and the daemon
  accepts it. The `ReferenceBlock.curve_tree_root` the signer supplies is this
  re-derived value; `assemble_path`'s internal gate is then a defense-in-depth
  consistency check, not the primary §3.3 defense (which lives at ingest).

The only held state is the tree itself, which genuinely cannot be re-derived
per-send at scale (the entire point of CT-1/CT-2/CT-3 persistence) — so holding
it is the justified exception to derive>hold, and the cheaply-derivable header
root is not held.

### 3.6 The header-`curve_tree_root` availability gap (prerequisite finding)

The consensus C++ `block_header` serializes `curve_tree_root` after `nonce`
(`src/cryptonote_basic/cryptonote_basic.h:723`, inside `BEGIN_SERIALIZE` /
`END_SERIALIZE` at `:735`). The **Rust** `shekyl-oxide` `BlockHeader` does **not**
carry or parse it: `BlockHeader::read` reads `{hardfork_version,
hardfork_signal, timestamp, previous, nonce}` and stops
(`rust/shekyl-oxide/shekyl-oxide/src/block.rs:43–68`); the field is absent from
`Block`, `ScannableBlock`, and the RPC types. `curve_tree_root` appears nowhere
in `shekyl-engine-state` / `shekyl-engine-core`.

Two consequences:

1. **CT-5's §3.3 wiring is blocked** until the Rust header carries the root.
2. **Latent correctness concern (flag, confirm in pre-0):** a 5-field Rust
   parser reading a 6-field consensus header would **mis-align** on real Shekyl
   blocks (it would read the 32-byte `curve_tree_root` as the start of the miner
   transaction). The Rust block path works in tests today only because they feed
   synthetic / Monero-format blocks without the field. This suggests the parser
   fix is needed for the Rust block deserializer to be correct against real
   consensus blocks at all — **independent of CT-5** — which is why it lands as a
   prerequisite PR, not folded into CT-5a (R1-Q6 sequencing decision).

**Disposition:** **CT-5 pre-0** (prerequisite PR, §6) extends `shekyl-oxide`
`BlockHeader` to parse/serialize `curve_tree_root` gated on `hardfork_version`,
with a round-trip + cross-check KAT against a real consensus header. Reopening
/ scope note (A4): if pre-0 surfaces that the field is conditionally present
(e.g. only from a given hard fork), the gate is `hardfork_version`-keyed per
`60-no-monero-legacy.mdc` (Shekyl min HF is 1; the field is present from
genesis, so no dead pre-genesis branch).

---

## 4. Round-1 open questions (agenda)

Consolidated from §3. All six resolved 2026-06-14 (§3); two corrected the
initial pull (struck through).

| ID | Question | Resolution |
|----|----------|------------|
| **R1-Q1** | Where the `CurveTreeClient` lives + single-writer cell (§3.1) | ~~refresh-owned~~ → ~~`Engine` field under the RwLock~~ → **`CurveTreeActor` + `Clone` `CurveTreeHandle`** (Round 2, mirror `KeyActor`); merge is sole ingest-sender; consistency via ingest-ack-before-ledger-commit |
| **R1-Q2** | Ingest site + what `ScanResult` carries (§3.2) | **merge drives `handle.ingest`**, commits ledger on ack; `ScanResult` grows **two transit fields** — full per-block leaf set + per-block header root (both dropped after merge) — A1 frozen |
| **R1-Q3** | `ScannableBlock → BlockLeaves` decode = consensus drain order (§3.2) | **dedicated KAT vs the `ct2_tier_a.json` oracle** (A2); lands CT-5a |
| **R1-Q4** | Reorg ordering + poison handling (§3.3) | **rollback in `handle_reorg`** under the same guard, atomic with the ledger rewind; **automatic** drop-and-reopen |
| **R1-Q5** | `synthetic_tree` disposition (§3.4) | **delete** (no users); migrate tests to the real client + CT-2 fixture; lands CT-5c |
| **R1-Q6** | Source of header `curve_tree_root` (§3.5) | ~~from synced header~~ → ~~retain per-height (schema bump)~~ → **derive>hold (Round 2): verify at ingest, re-derive at send, no schema bump**; pre-0 parser PR still required so ingest can read the header root |

**R1-Q6 was the gating question, and the gate moved.** The proof can bind to
the wallet's self-reconstructed root (CT-2 equality), so binding is *not*
blocked — but the §3.3 lying-daemon defense requires the header root, which the
Rust parser does not carry today (§3.6). Resolving it surfaced a prerequisite
PR (CT-5 pre-0) that is arguably needed for the Rust block deserializer to be
correct against real consensus blocks at all.

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
   ingest-ack-before-ledger-commit (R1-Q1) gates the ledger advance on tree
   success; R1-Q4 rollback in the same `handle_reorg` transition;
   `NonConsecutiveBlockHeight` is a loud failure, not silent drift. *Disposition
   (a).*
3. **Poison left unhandled (O3).** A failed rollback (or fail-stopped actor)
   leaves a dead handle that then serves stale paths. *Defense:* `ensure_live()`
   fail-closes every client method, and a fail-stopped `CurveTreeActor` collapses
   every handle call to a terminal error; R1-Q4 respawn. *Disposition (a):* the
   poison/fail-stop contract is machine-enforced; CT-5 must exercise the respawn
   path in a KAT.
4. **Secret leak via the new ownership (O4).** The engine now holds a tree
   handle. *Defense:* the client is public-data-only (parent §4.1/§4.2 structural
   no-secrets test); `AssembledPath` and every `CurveTreeActor` message carry no
   secret; secrets enter only in `sign_bridge → SpendInput`. The actor boundary
   *reinforces* this: like `KeyActor`, no `&`-state escapes the task, but unlike
   `KeyActor` the contained state is public, so the boundary is consistency- not
   secrecy-load-bearing (§3.1 counterpoint). *Disposition (a):* extend the
   no-secrets structural test over the handle's message types
   (`16-architectural-inheritance.mdc` — orchestrator must not become a secret
   holder).
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

Boundaries are firm now that R1-Q1/Q2/Q6 are resolved (they decided the field
shapes). Each sub-PR lands ≤ the `06-branching.mdc` 5-day / 10-commit envelope;
none is a consensus-atomic cutover (`07-consensus-atomic-cutovers.mdc` not
invoked — the synthetic→real swap is flag-decomposable behind the assembler
boundary).

- **CT-5 pre-0 — `shekyl-oxide` block-header parser (prerequisite, R1-Q6 / §3.6).**
  Extend `BlockHeader` (`rust/shekyl-oxide/shekyl-oxide/src/block.rs`) to
  parse/serialize `curve_tree_root` after `nonce`, matching the consensus
  serialization (`src/cryptonote_basic/cryptonote_basic.h:723/735`), gated on
  `hardfork_version`. Thread it through `Block` / `ScannableBlock` so the refresh
  path can read it. DoD: header round-trip KAT + a cross-check that a real
  consensus-serialized header deserializes with the field intact (confirms the
  latent mis-alignment in §3.6 #2 is closed). This lands **before** CT-5a; it is
  not folded in, because the parser correctness is independent of the engine
  wiring.
- **CT-5a — actor lifecycle + ingest (no signer change).** Add the
  `shekyl-curve-tree` dependency, the **`CurveTreeActor` + `CurveTreeHandle`**
  (R1-Q1, mirror `KeyActor`), spawn on engine open with the `Engine` holding the
  handle, the `ScannableBlock → BlockLeaves` decode (R1-Q3 KAT), and the
  merge-driven `handle.ingest` with ingest-ack-before-ledger-commit (R1-Q2).
  Reorg rollback + actor respawn (R1-Q4). The signer still uses synthetic
  vectors. DoD: refresh + reorg KAT root-matches the CT-2 oracle through the
  engine path; respawn KAT (O3).
- **CT-5b — reference selection + §3.3 verify (R1-Q6, derive>hold).** Wire
  `select_reference_height`, the C2 gate, the **§3.3 ingest-time verify**
  (reconstructed root == pre-0 header root → loud DoS on mismatch), and the
  **send-time re-derivation** of the reference-height root from the actor (no
  retention, no schema bump). Lands the `ReferenceBlock` construction (height +
  re-derived root + block hash from the ledger reorg window) the signer will
  consume; the signer still builds synthetic paths but against the *real*
  reference selection. DoD: C2 `OutputNotYetSpendable` KAT + a §3.3
  mismatch-rejection KAT (O5).
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
  oracle; C2 clean error; no-secrets test over the `CurveTreeHandle` surface).
- [ ] §2 contract confirmed — CT-5 adds **no** new client API; C1
  one-`ReferenceBlock`-per-tx upheld.
- [x] R1-Q1 client ownership — **resolved (Round 2):** `CurveTreeActor` +
  `CurveTreeHandle`; merge sole ingest-sender; ingest-ack-before-commit (§3.1).
- [x] R1-Q2 ingest site + `ScanResult` growth — **resolved:** merge-driven actor
  ingest, two transit fields (leaf set + header root), A1 frozen (§3.2).
- [x] R1-Q3 `BlockLeaves` decode = CT-2 drain order — **resolved:** dedicated
  KAT vs the oracle (§3.2).
- [x] R1-Q4 reorg ordering + poison handling — **resolved:** rollback in
  `handle_reorg`, automatic reopen (§3.3).
- [x] R1-Q5 `synthetic_tree` disposition — **resolved:** delete + migrate tests
  (§3.4).
- [x] R1-Q6 header `curve_tree_root` source — **resolved (Round 2):** derive>hold
  — verify at ingest, re-derive at send, no schema bump; pre-0 parser PR still
  required (§3.5/§3.6).
- [ ] §3.4 confirmed bug fixed: reference block = `tip − REF_ANCHOR_AGE`, not the
  tip (`local_pending_tx.rs:781`); `tree_depth` derived, not `1u8` (`:657`).
- [ ] §5 threat objectives O1–O6 each routed (a)/(b)/(c).
- [x] §6 sub-PR boundaries firm (R1-Q1/Q2/Q6 resolved); pre-0 prerequisite added.
- [ ] §7 parent §9 row + 2A back-refs; §5.4 confirmed-not-pending.
- [ ] **Closure-review round** + A3 threat pass against §5 before first commit.


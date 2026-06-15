# CT-5 — engine wiring: production CurveTreeClient into the 2A signer (design — Round 2, review integrated)

**Status:** Closure round complete (2026-06-14). Round 1 closed R1-Q1–R1-Q6
(§4); Round 2 applied three standing architectural principles (below), revised
R1-Q1 (→ actor) and R1-Q6 (→ derive-not-hold), and absorbed the Round-2 review
(E1–E9, §9). **The closure round finished the three gating findings: E1
(read-path snapshot atomicity — upgraded to a type/message-shape guarantee via
the batch `AssembleTx` message, §3.7 T3), E2 (under-guard `await` — promoted to
an enforceable two-clause structural invariant), and E5 (reorg-orphans-reference
— `REF_ANCHOR_AGE=6` confirmed production, trigger added to CT-5d). §3.7 adds the
type-enforced contracts (T1–T3) that make the §3.4 / E1 bug classes
unrepresentable rather than discipline-avoided.** This doc is now the frozen contract and threat-model frame the
implementation cuts against, per `05-system-thinking.mdc` (spec first, code
second). **The A3 threat pass is complete on both faces — internal (§5, O1–O6)
and external/graveyard (§5.1, X1–X7). The weight-bearing external finding (X3)
resolved, after running its two load-bearing verifications down against the code,
to a wallet-side *resolution ambiguity* — NOT a consensus gap: V1 confirms `O` is
one-time-address-derived (`output.rs:8–28`) so a payer cannot target `O.x` (the
adversarial precondition is cryptographically unreachable), and — after V3 confirmed
the index→gindex binding is locally constructible at the match site (`assemble.rs:89`
carries `e.gindex`; scanner `global_output_index` is the same `next_output_seq`
numbering, `ledger_ext.rs:74`/`scan.rs:562`/`recon.rs:122–148`) — the fix resolves
owned outputs by `gindex`, the tree's actual unique key, in CT-5c. This makes the
collision case *structurally impossible* (deleted from the threat model, not bounded);
`(O, C, h_pqc)` is the recorded-but-not-taken fallback. A consensus output-key-uniqueness
rule is explicitly rejected as a privacy regression, and the threat model records why.
X1 folded into O1
(anchor-age is a fingerprinting oracle); X2/X4/X6/X7 confirmed; X5 run down to a
bounded CT-5c `eligible_height` fix (coinbase flows through `from_wallet_output`
with the flat `+10`; align via the ignored `additional_timelock`). The §3.4 bugs
are confirmed against live code — all pre-implementation checklist items are
closed. CT-5 pre-0 may begin.**

**Post-closure pin (Round 3, 2026-06-15) — R1-Q2 ingest-feed amendment (§3.2.1).**
A CT-5a-implementation substrate finding falsifies the §3.2 / CT-3 R1-Q1
premise that *"the refresh loop already delivers every block; CT-5 connects
it."* It does not: the refresh producer is **birthday-floored and
`synced_height + 1`-based** (`local_refresh.rs:589`), so its block range is
governed by owned-output economics, while the curve tree's range is governed by
anonymity-set completeness (a global tree **from genesis**, `client.rs:476`,
CT3_SYNC.md:112). These are different ranges and always will be. Per
`21-reversion-clause-discipline.mdc` this is a post-closure pin, **not** a
reopening of Round 1: the merge-driven per-block ingest *mechanism* (R1-Q2)
stands; what is amended is the *feed* that drives it — it must be a
genesis-anchored tree-leaf feed independent of the floor. §3.2.1 records the
finding, the cost-asymmetry measurement that selects the resolution, the CT-3
R1-Q1 reopening it triggers, and the Round-3 design questions for the feed
shape. **Round 3 closed (2026-06-15): R3-Q1–R3-Q6 resolved — fork three, a
genesis-anchored tree feed, and a two-cursor merge that splits display
(detection, tree-independent) from spend (tree-verified). CT-5a commit 4 may
land against the §3.2.1 contract; the only remaining gate is the Tier-B
non-coinbase fixture for the floored-sibling DoD KAT.**

**Decisions frozen (irreversible once implemented — the load-bearing choices, so
the closure reviewer and CT-5c implementer find them at the top, not derived from
the finding logs §9):**

1. **`CurveTreeClient` lives behind a `kameo` actor**, on the redb single-writer
   argument (not "standing principle"); engine holds a `Clone` handle. Reversion
   target: `RwLock<CurveTreeClient>`. — §3.1 (E0).
2. **Derive > hold for the root:** bind to the self-reconstructed root; the header
   `curve_tree_root` *defends at ingest*, it is not held as truth. — §3.6 / R1-Q6.
3. **pre-0 is a prerequisite, not CT-5 proper:** add `curve_tree_root` to the Rust
   `BlockHeader` (read/write/hash). E3 verified **(a)** — this *establishes*
   block-header/hash correctness for the first time (no real block has ever
   deserialized through the Rust path); also fixes `ReferenceBlock.block_hash`. — §3.6 / §6.
4. **X3 resolves owned outputs by `gindex`** (the tree's unique key), making the
   collision case structurally impossible (deleted, not bounded). No consensus
   output-key index (privacy regression). Wallet-conformance requirement (X3 × X1).
   — §5.1 / §7.
5. **Batch `AssembleTx` message:** all N inputs assemble in one handler under one
   snapshot — mid-assembly-reorg split is type-unrepresentable. — §3.7 T3 / §3.1.
6. **`REF_ANCHOR_AGE` is consensus-uniform** across wallet implementations (privacy
   fingerprint, not just reorg-safety); never a config knob. — §5 O1 / X1.

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

**Why the actor, stated correctly (Round-2 review, E0).** The load-bearing
reason is **not** the standing principle and **not** secret isolation (the tree
is public data — parent §4.1/§4.2 no-secrets test — so unlike `KeyActor` the
actor buys no secret-containment here). It is **redb's single-writer transaction
model**: `CurveTreeClient` wraps a redb store that permits exactly one write
transaction at a time, and `ingest_block` / `rollback_to_fork` are `&mut self`.
*Something* must serialize those writes; the actor's message loop is the natural
serializer for a resource that is already single-writer at the storage layer.
This argument holds even without the standing principle, which is why it is the
honest justification. Fail-stop-on-panic then yields the `Poisoned` contract for
free as actor-death.

**A4 reversion target.** If E1/E2 (below) resolve badly in the closure round,
the fallback is **not** "plain `Engine` field" — it is `RwLock<CurveTreeClient>`
with the writer side funneled through the merge, which preserves the same
single-writer discipline without the cross-actor read latency. Recorded so the
actor decision has an explicit escape hatch; not expected to be needed.

**E1 (CLOSED, closure round) — the read path crosses the actor boundary.**
`assemble_path` is `&self`, but behind the actor the signer sends an
`AssemblePath` message and awaits a reply. Two consequences, the second
load-bearing and now a frozen-contract requirement:

- *Latency / write-serialization.* A send with N inputs is N `AssemblePath`
  messages, each queued behind any in-flight `Ingest` from the refresh loop;
  refresh can delay assembly, and N inputs serialize through one mailbox.
  Invisible at Tier-A scale, but to be acknowledged. redb supports **concurrent
  read txns alongside the single writer**, so the actor *could* serve
  `AssemblePath` as a concurrent read rather than through the write loop — but
  only if structured for it; "single-threaded loop serializes writes" as written
  does not. Closure round decides whether reads are spawned concurrently.
- *C1 read-side mirror (the load-bearing half) — resolved by message shape, not
  discipline (see §3.7).* C1 (one `ReferenceBlock` per tx) is structurally upheld
  because all inputs share one `ReferenceBlock` **value** — but if a tx's N
  per-input assembly calls interleave with an `Ingest`+`Rollback` (reorg
  mid-assembly), inputs `1..k` assemble against the pre-rollback tree and
  `k+1..N` against the post-rollback tree: same `ReferenceBlock`, different
  underlying tree state. Equal `ReferenceBlock` does not save you if the tree
  moved under the reads. **Frozen-contract requirement (CT-5c): the read API is a
  single batch message** —
  `AssembleTx { reference: ReferenceBlock, inputs: Vec<AssembleInput> } ->
  Vec<AssembledPath>`, where each `AssembleInput` carries the **`gindex` resolution
  key** (the owned output's `global_output_index`, the tree's unique key per X3 §5.1)
  and retains the `OutputIdentity` for a post-resolution consistency assertion
  (resolved leaf's `(O, C, h_pqc)` must equal the expected identity, else
  gindex/store corruption → error — defense-in-depth, not the resolution path) —
  so the actor assembles **all N inputs inside one handler
  invocation, under one snapshot**, and the handler runs to completion before any
  `Ingest`/`Rollback` can interleave. There is no per-input message to interleave,
  so the mid-assembly-reorg split is **structurally unrepresentable**, not merely
  discipline-avoided. The `Vec` is bounded by `FCMP_MAX_INPUTS_PER_TX = 8`. (A
  lifetime-guard session type — `TxAssembler<'a>` owning a redb read-txn — was
  rejected: the read-txn lifetime cannot cross the actor message channel; the
  batch message is the actor-native encoding of the same atomicity. §3.7.)
  *Latency note:* the batch is still serialized against the write loop; redb's
  concurrent-read support means the actor *could* serve `AssembleTx` off a
  concurrent read txn rather than the write loop — a perf option, orthogonal to
  the correctness the batch shape already guarantees; closure decides.

**E2 (CLOSED, closure round) — `ask().await` under the engine write guard:
verified, and the invariant promoted to enforceable form.** Holding a
`tokio::sync::RwLock` write guard across an `.await` that round-trips to another
actor is the classic async-deadlock shape if the awaited actor ever (directly or
transitively) wants that same engine lock — deadlocking only under the triggering
interleaving, passing every test until production. The substrate confirms the
property today (`KeyActor`'s struct holds only `local: LocalKeys`, no engine
reference — `key_actor.rs`), **but "happens not to hold a reference today" is a
fact about current code that a future "let the actor read engine config for X"
change silently breaks.** The durable form is a *structural constraint*, pinned
with the same review status as the no-secrets test:

> **Two-clause lock-ordering invariant (CT-5a structural rule).**
> 1. The `CurveTreeActor` struct owns **only the store handle** and holds **no
>    `Engine` / `EngineHandle` / engine-lock reference** of any kind. A field
>    addition that reaches back for engine state fails review **on this rule** —
>    not on someone re-deriving the deadlock analysis.
> 2. Respawn-on-poison (R1-Q4) runs **engine-side, after the failed `ask`
>    returns** — never inside a handler awaited under the guard. The one path
>    that might want engine state to re-open does not run under the lock.

Corollary: *the curve-tree actor never acquires the engine lock; the engine may
hold its lock across a curve-tree `ask`.* CT-5a lands clause 1 as a structural
review item (the same enforceable shape as `no_secrets`), not a one-time build
confirmation.

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

> **Amended by §3.2.1 (Round-3 post-closure pin, 2026-06-15).** The mechanism
> below (merge drives `handle.ingest`, commit-on-ack) stands. The clause "the
> producer decodes what it already parses and carries it forward" is the part
> amended: the *owned-output* producer is birthday-floored, so it cannot be the
> tree's leaf source for `0..birthday`. The tree gets a separate
> genesis-anchored feed; see §3.2.1.

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

**Recorded cost (E4) — this is not a free transit field.** Materializing *all*
outputs per block (not just wallet-owned) is a per-block allocation proportional
to total chain output count, on the **refresh hot path**, where today the
producer only materializes owned transfers. At mainnet block sizes this is the
difference between scan-for-mine (small) and buffer-every-output (large) on every
block. It is **O(outputs-per-block), released per block** — a throughput /
allocation cost, **not** a leak or an unbounded buffer. It is necessary if the
tree ingests via the merge, and it is named here as the **price of the
ingest-ack-before-commit ordering** so a future profiling finding inherits a
recorded disposition rather than re-litigating it.

Rejected alternative: producer sends leaves straight to the tree actor,
bypassing the merge. It avoids this buffering but decouples tree-ingest from the
ledger commit, so the ingest-ack-before-commit ordering (R1-Q1) can no longer
gate the ledger advance — reintroducing O2. Rejected on correctness; the
buffering above is the named price of that correctness.

**Decision (R1-Q3, RESOLVED — dedicated decode KAT vs the CT-2 oracle).** The
`ScannableBlock → BlockLeaves` decode (which outputs become leaves; coinbase vs
non-coinbase maturity, `is_miner`, `leaf_hash_blob` provenance) must match the
CT-2 drain-order replication exactly (parent §6 / `CT2_DRAIN_ORDER.md`). This is
the highest inheritance-risk surface (it reproduces consensus leaf-insertion
order), so it gets a dedicated KAT (A2 audit-against-actual-code) asserting the
engine-path decode reproduces the `ct2_tier_a.json` oracle leaf stream. Lands in
CT-5a (§6).

### 3.2.1 Post-closure pin (Round 3) — the tree feed is genesis-anchored, not producer-driven

**Status: RESOLVED (Round-3 design round closed 2026-06-15).** Recorded
2026-06-15 from a CT-5a-implementation substrate finding. Per
`21-reversion-clause-discipline.mdc` this is a post-closure pin on a
substrate falsification, not a reopening of the closed Round-1 disposition:
the R1-Q2 *mechanism* (merge drives `handle.ingest`, commit-on-ack, §3.2)
stands unchanged; what is amended is the *feed* that drives it.

**The finding.** §3.2 and CT-3 R1-Q1 both rest on the premise that the
wallet's refresh loop delivers every block from genesis, so wiring the tree to
the merge is "free." The premise is false. Two facts about the producer:

- **`synced_height + 1` start.** `produce_scan_result` begins at
  `original_start = synced_height + 1` (`local_refresh.rs:589`), not at
  `BlockHeight(0)`. The genesis-off-by-one case.
- **Birthday floor.** A floored wallet deliberately does **not** scan
  `0..birthday` — by design, there is nothing of its own there. The larger
  case, and load-bearing: removing/lowering the floor re-introduces the exact
  full-genesis owned-output scan cost the floor exists to avoid.

The tree client requires the opposite: strictly consecutive heights **from
genesis** (`expected = 0` when fresh, `client.rs:476`; CT3_SYNC.md:112 S3).
The producer's range is governed by **owned-output economics**; the tree's
range is governed by **anonymity-set completeness**. These are different
ranges and always will be — there is no birthday shortcut to a *global*
anonymity set, by construction. Genesis-off-by-one and the birthday gap are
two instances of one mismatch; a genesis-seed step fixes only the first and
leaves floored wallets with a tree missing `0..birthday`, i.e. **silent
corrupt membership for every output below the floor**. This is the
`16-architectural-inheritance.mdc` shape: the merge-drives-ingest trait
surface is right, but "the producer's blocks are the tree's blocks" is the
inherited-from-Monero falsehood (Monero's wallet has no genesis-anchored
global structure to maintain).

**The resolution: fork three — separate the feeds.** The owned-output scanner
keeps its birthday floor. The tree gets its own genesis-to-tip leaf feed that
ignores both `synced_height + 1` and the floor. They share block fetches where
ranges overlap (`birthday..tip` fetched once, feeding both consumers); the
tree additionally pulls `0..birthday`. There is no special "genesis seed"
step — there is a genesis-anchored tree feed of which height 0 is simply the
first block.

**Why fork three and not "un-defer the bulk-leaf RPC" — the cost-asymmetry
measurement.** The hinge is the per-output cost of feeding the tree
(leaf-extract) vs. feeding the owned-output scanner (trial-decrypt), measured
against live code:

- **Leaf extraction** (`curve_tree_decode.rs`): per output, a byte-copy of
  `output_key`/`commitment`, a commitment-index lookup, and a `target`
  classification. **Zero elliptic-curve ops, zero KEM, zero per-output
  hashing.**
- **Owned-output trial-decrypt** (`scan.rs` `scan_transaction`): per output,
  an Ed25519 point decompression (`output.key.decompress()`) **plus a hybrid
  KEM decapsulation** — X25519 ECDH **and** ML-KEM-768 lattice decapsulation
  (`scan_output_recover_with_ml_kem_dk`, `shared_key.rs`), then further hashing
  on a match. **Two-to-three orders of magnitude more per output.**

So leaf extraction is cheap relative to trial-decrypt. Genesis-to-tip
leaf-extraction for the tree is therefore *not* equivalent to an unfloored
scan: the floor's saving is the expensive trial-decrypt below birthday, which
fork three preserves. The bulk-leaf RPC (deferred in CT-3 R1-Q1) would make
even the *block fetch* cheap, but it is not required for correctness — fork
three is correct today with block-derived extraction. The bulk RPC becomes a
fetch-cost optimization, not a correctness prerequisite.

**Rejected (recorded so it is not re-proposed): segment-root partial tree.**
Holding only the `R_k` segment-root commitments for `0..birthday` and full
leaves only above it. The cost measurement kills it: its sole justification was
avoiding sub-birthday work, but that work is now measured as *cheap*
(extraction, not scan), so the shortcut saves the cheap axis while adding the
genuinely hard thing — a store-backed path-assembly that serves scattered
sub-birthday siblings on demand, which is unbuilt (F5) and carries the
targeted-fetch ownership-oracle risk. It trades cheap, correct, simple
genesis-to-tip extraction for an expensive, unbuilt, privacy-fraught partial
structure: a worse design dressed as an optimization.

**CT-3 R1-Q1 reopening (narrowed).** CT-3 R1-Q1 deferred the bulk-leaf RPC on
the reasoning that "forward sync is block-derived and the wallet gets every
block from the refresh loop anyway." That reasoning assumed genesis-anchored
block delivery, which the birthday floor falsifies for any wallet flooring
above genesis: such a wallet must run a **separate genesis-to-tip block fetch
for the tree**, which the deferral's cost model did not account for. The
reversion clause's spirit ("forward-sync data-source decision rested on a
producer behavior that doesn't hold") is triggered. **Disposition:** the
reopening resolves to *"the tree gets its own full-range block feed"* (fork
three), **not** *"un-defer the bulk RPC"* — the cost asymmetry above shows
block-derived extraction is cheap enough that the bulk RPC stays deferred as a
fetch-cost optimization with its original reversion clause intact. Recorded
against CT-3 R1-Q1 so the deferral's premise correction is auditable from
both docs.

The falsified premise was false in a *bounded* way — false on the **fetch**
axis (a floored wallet does not get `0..birthday` blocks from the refresh
loop), true on the **extraction** axis (extraction stays cheap). The narrowed
reopening trigger names the axis it fires on so it is measurable, not vague:
**the fetch cost becomes load-bearing when genesis-to-tip block download for
the tree dominates fresh-wallet sync wall-time to the point where bulk-leaf
fetch would materially cut it** — leaves are a fraction of block bytes (no
`tx_extra` beyond the `0x07` tag, no signatures, no range proofs). That is a
bandwidth/wall-time measurement against a real chain length, so it is a
**post-genesis observation** (cannot be decided pre-genesis) — the trigger is
"measured on fresh-wallet sync wall-time, post-genesis."

**F5 coupling (one scaling axis, two deferred items).** Path assembly reads
the **in-memory leaf vec**: `assemble_path` runs
`build_layers(assemble_leaf_stream(&self.entries, …))` (`assemble.rs:84–85`)
— the store-backed `root_at` is only the integrity gate (`assemble.rs:71–75`),
the branches come from `entries`. So the genesis-anchored feed makes the
in-memory `entries` vec **genesis-to-tip-sized** (it is what the feed fills).
F5's deferral (store-backed assembly; R1-Q6 V3.0 whole-tree-in-memory
disposition) is therefore *coupled* to this feed: F5's firing condition is
"in-memory tree exceeds budget," which is the **same post-genesis-measurement
class** as the bulk-RPC trigger above — both are functions of **chain length**,
both correctly wait for the same field data. Recording the coupling here so the
two deferrals are seen as one scaling axis, not two independent "revisit if
slow"s.

**Round-3 design questions — RESOLVED (2026-06-15).** The four open questions
collapse around one reframe: **R3-Q2 is not "where does the feed start" (we know:
0); it is "display-completeness and spend-completeness are different
requirements."** Detection (owned-output trial-decapsulation) does not need the
tree; the tree is only for the membership proof at spend time. So the backfill
blocks *spendability*, not *display* — "received, pending sync" is an honest,
correct wallet state, and conflating display with spend is the same error shape
as conflating the producer's range with the tree's range. The two source
confirmations that gate the reframe both came back affirming it (below). Each
question's disposition:

- **R3-Q1 — feed driver shape (RESOLVED).** Single block fetch, two consumers:
  the tree-leaf extractor and the owned-output scanner. Where ranges overlap
  (`birthday..tip`) a block is fetched once and read by both. The tree
  consumer *additionally* pulls `0..birthday` alone — a tree-only fetch, and
  the fetch cost the CT-3 R1-Q1 reversion trigger watches. No second source
  for genesis (the genesis-feed-source confirmation below). Whether the
  driver is a second output on `produce_scan_result` or a second coordinated
  loop is an implementation choice bounded by the fetch-once constraint; it
  does not change the contract.
- **R3-Q2 — display/spend decoupling (RESOLVED, the load-bearing reframe).**
  Ack-before-commit (R1-Q1, O2) binds the **synced/spendable** height — the
  ledger tip must not advance past the tree-verified height — **not** the
  detection surface. The merge therefore tracks **two cursors**: a
  *detection* cursor (how far the scanner has looked; surfaces detected
  transfers as pending-incoming, tree-independent) and a *tree-verified /
  spendable* cursor (gated by ingest-ack, governs `synced_height` and
  spendability). For a fresh floored wallet there are **no ledger commits in
  `0..birthday`** (no owned outputs there), so ack-before-commit does not bind
  in that range — the `0..birthday` backfill runs with no commit to gate.
  From `birthday+1` the tree and ledger move in lockstep under ack-before-commit;
  because tree ingest is strictly consecutive from 0, the first lockstep
  commit at `birthday+1` cannot land until the `0..birthday` backfill
  completes — so the backfill is a blocking prefix on the **first
  spendable/synced advance**, but **not** on detection display.
  **Requirement for commit 4:** the merge must surface `new_transfers` as
  pending-incoming **independent of** the tree-gated synced-height advance.
  Today a transfer becomes user-visible only at merge-commit; gating that
  commit on tree-ingest without the split would wire the first-run *display*
  cliff back in by accident. The invariant is preserved — the spendable tip
  still never outruns the tree — only the honest "pending, scanning" surface
  moves ahead. This is a real merge-shape decision (two cursors), not a free
  property.
- **R3-Q3 — `synced_height` for the tree (RESOLVED, confirmed in code).** The
  tree has its own last-ingested cursor `ingested_tip_height: Option<BlockHeight>`
  (`client.rs:205`), `None` when fresh; `ingest_block` computes
  `expected = ingested_tip_height + 1` (or `BlockHeight(0)` when `None`,
  `client.rs:476–478`). It is structurally decoupled from the wallet's
  `synced_height`. The merge computes the tree's next expected height from
  this cursor, not `synced_height`.
- **R3-Q4 — already-synced wallet adopting the tree (RESOLVED).** A wallet
  that synced owned outputs *before* the tree existed (or after a tree-store
  wipe) has `synced_height ≫ 0` but a fresh tree; the tree feed backfills
  `0..synced_height` independent of the owned-output cursor. This is the
  **cleanest instance of the R3-Q2 reframe**: detection is *entirely* done
  (balances already shown), so nothing is gated on display — only spendability
  waits on the backfill. Same display/spend split, with display fully on the
  "done" side.
- **R3-Q5 — DoD (RESOLVED, KATs pinned).** The load-bearing KAT nothing else
  exercises: a **floored wallet** (tree genesis-to-tip, owned birthday-to-tip)
  spending a `birthday+1` output whose membership path includes a
  **sub-birthday sibling** — fails if the tree was not truly backfilled to
  genesis (sibling missing → wrong path → invalid proof). This is exactly the
  shape no existing fixture covers (the CT-2 oracle is coinbase-only and
  unfloored), so it **inherits the Tier-B non-coinbase fixture gate** (same as
  the CT-5a reorg KAT; part of what Tier-B-ungated-by-CT-5c buys). Plus a
  reorg-into-backfill KAT (R3-Q6): backfill frontier above a fork, reorg,
  assert **resume-from-cursor not resume-from-counter**.
- **R3-Q6 — reorg during backfill (NEW, RESOLVED).** A wallet mid-backfill
  (tree ingested `0..k`) when a reorg fires: the reorg is within the shallow
  near-tip reorg window, so while the backfill frontier `k` is below the
  window the reorg is below nothing the backfill touches and `0..k` is stable.
  The one edge: `k` has climbed into the window (`k > fork_height`), so
  `rollback_to_fork` truncates part of what the backfill just ingested and the
  backfill must resume from `fork_height + 1`. That is ordinary
  rollback-then-resume **iff the backfill driver reads its resume point from
  `ingested_tip_height` after the rollback, never from a driver-local
  counter** — `rollback_to_fork` rebuilds and writes that cursor
  (`client.rs:443`), so cursor-driven resume is correct by construction and a
  counter-driven driver is the silent-gap hazard. **Constraint pinned: the
  backfill driver is cursor-driven, not counter-driven.**

**Source confirmations gating the reframe (both came back affirming):**

1. **Detection is tree-independent.** `shekyl-scanner` has **no
   `shekyl-curve-tree` dependency** (`Cargo.toml`); the only `curve_tree` token
   in `scan.rs` is `curve_tree_root: [0u8; 32]` in a *test* `BlockHeader`
   (`scan.rs:1313`). The production detection path is pure trial-decapsulation
   against wallet keys — zero tree consultation. So display can decouple from
   spend, and the decoupling is correct.
2. **Cursor-driven resume substrate.** `rollback_to_fork` rebuilds from the
   store and writes `self.ingested_tip_height = rebuilt.ingested_tip_height`
   (`client.rs:443`); `ingest_block` derives `expected` from it
   (`client.rs:476`). The cursor is the authoritative resume point and rollback
   updates it. (No backfill driver exists yet — this makes cursor-driven the
   *only correct* shape for R3-Q1/Q6, a design constraint, not an existing-code
   confirmation.)

**Genesis-feed source (RESOLVED, confirmed in code) — no genesis special
case.** The genesis block's leaves flow through the *same* decode path as every
other block: `curve_tree_decode.rs` has no `genesis` / `height == 0` /
chain-params branch (grep-clean), and the client's `ingest_block` expects
`BlockHeight(0)` when fresh by construction (`client.rs:476`). So the genesis
feed is "fetch block 0, run the same decode, ingest at `BlockHeight(0)`,"
identical to every height — there is no hand-built genesis leaf set and no
second source of truth. The "genesis seed step" from earlier rounds fully
dissolves: there is no special genesis step, only a feed that *starts* at 0
(ignoring the floor and `synced_height + 1`). The answer keeps genesis as
`chain[0]` fetched the same way as any block — if it ever routes around the
daemon for genesis, that reintroduces the two-sources-of-truth hazard and is
rejected.

**Round 3 closed (2026-06-15).** R3-Q1–R3-Q6 resolved above; the §3.2 mechanism
is now **fed** (genesis-anchored, two-cursor display/spend split). CT-5a commit
4 may land against this contract. The only external gate remaining is the
Tier-B non-coinbase fixture for the floored-sibling DoD KAT (R3-Q5), shared
with the CT-5a reorg KAT.

#### 3.2.1.1 Commit-4 envelope and constraints (Decisions 1–4, 2026-06-15)

With the design resolved, four implementation decisions fix what commit 4
carries and what it explicitly does not.

**D1 — the two-cursor split is its own commit, *not* commit 4 (envelope
decision).** Today `apply_scan_result_to_state` **fuses** detection and commit:
`new_transfers` are appended and `synced_height` (`ledger.height()`) advances in
one call (`merge.rs:215`, `:271–337`). The split (detection-height advances on
trial-decap success, independent of the tree; spendable/synced-height advances
only under ack-before-commit) is **real merge surgery** plus a new
pending-incoming surface — a *presentation/spendability-semantics* validation
surface distinct from commit 4's *correctness* surface (O2: the spendable tip
never outruns the tree). Per `19-validation-surface-discipline.mdc` and
`90-commits.mdc` scope discipline they separate:

- **Commit 4 (correctness):** wire the genesis-anchored feed + the
  merge-driven `handle.ingest` so the **spendable/synced cursor** advances only
  on ingest-ack (O2 preserved). Single-surfaced — `new_transfers` still appear
  only when the gated `synced_height` advances, i.e. the first-run **cliff is
  present** in interim builds.
- **Commit 4b (display decoupling):** surface `new_transfers` as
  pending-incoming **independent of** the tree-gated synced-height advance
  (received-shows-immediately, spend-lags-backfill). UX-shaped, independently
  testable.

The interim cliff is acceptable **pre-genesis** (no users; per the
`16-architectural-inheritance.mdc` user-protection-defaults-in-user-absent-contexts
framing) and 4b lands before any release. Splitting keeps commit 4 the
auditable correctness unit — a reviewer checking "does the spendable tip stay
gated on the tree" does not wade through presentation changes. (The prior
turn's closing sentence read as pre-deciding "build the split in commit 4"; the
preceding analysis argued split-out and handed the envelope call here — this is
that call: **split out**.)

**D2 — counter-driven resume forbidden by construction, not by discipline.**
The backfill driver MUST read its resume point from `ingested_tip_height` every
iteration; it MUST NOT hold a driver-local fetch-frontier field. Enforcement is
the T1–T3 unrepresentable-not-forbidden move: the driver type has **no
frontier field**, so the resume point is a cursor read (a `CurveTreeHandle`
cursor-query message → the actor's `ingested_tip_height`), not stored state.
Counter-drift after a reorg into the backfilled range is then *unrepresentable*
rather than merely prohibited. Implied handle surface: a cursor-read `ask` on
`CurveTreeHandle` (none exists yet; commit 4 adds it).

**D3 — adopting-wallet spendability during backfill: acceptable, and must be
surfaced.** A wallet that synced owned outputs before the tree existed (or after
a tree-store wipe) backfills `0..synced_height`; during that backfill, outputs
that were spendable yesterday are **temporarily unspendable** (the tree cannot
build a membership path until rebuilt). This is correctness-correct and honest,
but a UX-surprising regression, so it is **not silent**: the wallet surfaces
"rebuilding membership data — spending temporarily unavailable" (a
`82-failure-mode-ux.mdc` first-class failure surface), it does not silently
reject spends. The surfacing rides with the display-decoupling commit (4b), not
the correctness commit (4).

**D3 — landed (4b-1 + 4b-2).** The spend-side gate landed in commit 4b-1:
`LocalPendingTx::build` caps the spendable set at `min(synced_height,
tree_cursor)` and surfaces the lag as `SendError::SpendUnavailableRebuilding`
(→ `BuildErrorKind::RebuildingMembershipData`) rather than a misleading
`InsufficientFunds`. The display side landed in commit 4b-2: `RefreshProgress`
gains `pending_incoming_count` / `pending_incoming_atomic_units` (the
per-attempt detected-output summary, decoupled from spendability) and
`rebuilding_membership` (the ledger-ahead-of-tree predicate,
`refresh::membership_rebuilding`). The orchestrator emits the summary on the
pre-merge `Merging` frame — reading the tree cursor *before* the ingest
pre-pass, so a long adopting backfill surfaces "rebuilding membership data" for
its whole duration — and on the terminal success frame with
`rebuilding_membership: false` (the pre-pass acked the range under
ack-before-commit, so the tree is caught up). The `rebuilding == true` and
non-zero pending-incoming-amount KATs are Tier-B-gated to CT-5c (divergent
adopting state / non-coinbase fixture); 4b-2 lands the pure-predicate KAT and
the forward-from-genesis wiring smoke test.

**D4 — R3-Q5 KATs inherit the Tier-B gate; name the green-positive hazard in
commit 4's DoD.** Commit 4 lands with the **reorg-into-backfill KAT** (R3-Q6:
resume-from-cursor) which *is* coinbase-fixture-expressible (it tests cursor
resume, not non-coinbase siblings). The **floored-wallet sub-birthday-sibling
completeness KAT** (R3-Q5) needs the Tier-B non-coinbase fixture and is
**proven at CT-5c, not here**. Commit 4's DoD says this explicitly — *"backfill
correctness for non-coinbase sub-birthday siblings is Tier-B-gated, proven at
CT-5c, not at commit 4"* — so a green commit 4 (coinbase fixtures) is **not**
mistaken for a proven backfill. This is the CT-3c
green-positive-for-broken-thing lesson one level up: the merge wiring's green
status must not imply membership-completeness is tested; it is not until the
fixture exists.

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

**Disposition (E3 — standalone correctness fix, surfaced by CT-5).** **CT-5
pre-0** (prerequisite PR, §6) extends `shekyl-oxide` `BlockHeader` to
parse/serialize `curve_tree_root` gated on `hardfork_version`, with a round-trip
+ cross-check KAT against a real consensus header. This is **not** a CT-5 detail
— it is a block-deserializer correctness bug that CT-5 happened to find, the same
shape as keeping a schema-version stamp independent of its triggering PR. It
lands and is verified **in its own right**: if CT-5 slips for an unrelated
reason, the parser fix does not slip with it, and the closeout records it as
"block-deserializer correctness fix, surfaced by CT-5."

**Verify at pre-0 which of two states holds** (changes nothing about the fix,
but records the bug's true severity):

- **(a) not-yet-exercised:** no real Shekyl block has ever been deserialized by
  the Rust path (plausible pre-genesis). Then pre-0 is "needed for correctness
  at all," exactly as framed.
- **(b) compensating offset:** something downstream absorbs the 32 extra bytes
  that the audit did not surface. Then the fix interacts with that offset and
  pre-0 must remove it too.

State which one was found in the pre-0 PR. Reopening / scope note (A4): if pre-0
surfaces that the field is conditionally present (e.g. only from a given hard
fork), the gate is `hardfork_version`-keyed per `60-no-monero-legacy.mdc` (Shekyl
min HF is 1; the field is present from genesis, so no dead pre-genesis branch).

**Landed (CT-5 pre-0, `fix/block-header-curve-tree-root`).** State found: **(a)
not-yet-exercised** — confirmed at source (no compensating offset; the five-field
`serialize_pow_hash` could not match consensus). `BlockHeader` now reads/writes
`curve_tree_root` after `nonce` **unconditionally** (the scope-note's "field is
present from genesis" leg → no `hardfork_version` gate, which would be a dead
pre-genesis branch per `60-no-monero-legacy.mdc`). `ScannableBlock`/`Block`
expose it through the public `block.header` path (no new field needed). KATs:
header round-trip, consensus field-layout cross-check (six-field byte order vs
the C++ `BEGIN_SERIALIZE`), and a full-block round-trip proving the miner tx no
longer mis-aligns. Establishes header/block deserialization correctness for the
first time and corrects `Block::hash()` / `ReferenceBlock.block_hash`.

### 3.7 Type-enforced contracts (make the §3.4 / E1 bug classes unrepresentable)

`20-rust-vs-cpp-policy.mdc` #2: a cryptographic contract is enforced by the type
system at every use site, not by documentation. The §3.4 bugs and the E1
read-atomicity hazard are all expressible **only because the current API permits
them**; the cutover removes the permission. No *new* type vocabulary is added —
`ReferenceBlock`, `BlockHeight` / `Gindex`, and `AssembledPath` already exist; the
move is to make them the **only representable path**. This is a deletion-and-shape
discipline, not a type-zoo expansion (`15-deletion-and-debt.mdc`).

**T1 — `ReferenceBlock` is the only assembly input; delete the raw `[u8;32]`
reference parameter (CT-5c).** The tip-as-reference bug (§3.4) exists because
`assemble_tx_to_sign(.., reference_block: [u8;32], ..)` collapsed a three-field
concept (height + curve-tree root + block hash) to one 32-byte field, so a *tip
hash* and a *reference-block hash* shared a type and the confusion compiled.
`ReferenceBlock { height, curve_tree_root, block_hash }` already carries the three
together; consuming it (and **deleting** the raw `[u8;32]` param, not bypassing
it — `60-no-monero-legacy.mdc`) makes "pass a lone tip hash" a type error: you
cannot satisfy a value that demands a height and a root as well. The three-field
shape *is* the barrier.

**T2 — derive `tree_depth` from `AssembledPath`; delete the free `tree_depth: u8`
parameter (CT-5c).** The `1u8` placeholder (§3.4) is possible only because depth
is a caller-supplied scalar. `AssembledPath.tree.tree_depth` already carries the
real depth from `assemble_path`; the signer reads it from the path, and the free
parameter is removed. "Derive over hold" applied to a single scalar — no place to
hardcode means no placeholder.

**T3 — batch the tx's assembly into one message; the actor handler is the
snapshot (CT-5c). Upgrades E1 from discipline to type/message shape.** The read
API is `AssembleTx { reference: ReferenceBlock, inputs: Vec<AssembleInput> } ->
Vec<AssembledPath>`, not N separate `AssemblePath` calls, and each `AssembleInput`
carries the `gindex` resolution key (X3, §5.1) plus the `OutputIdentity` for the
post-resolution consistency assertion. The actor assembles all
N inputs in **one handler invocation under one snapshot**; the handler runs to
completion before any `Ingest`/`Rollback` interleaves, so the mid-assembly-reorg
split (E1) is **structurally unrepresentable**. One `ReferenceBlock` in the
message also makes C1's per-tx value-equality the only expressible shape. Bounded
by `FCMP_MAX_INPUTS_PER_TX = 8`. *Rejected alternative:* a lifetime-guard session
type `TxAssembler<'a>` owning the redb read-txn — the read-txn lifetime cannot
cross the actor message channel, so the guard cannot span the N reads; the batch
message is the actor-native encoding of the same atomicity. (If the A4 reversion
to `RwLock<CurveTreeClient>` is ever taken, the lifetime guard *does* become
available and is the better shape there — recorded so the reversion carries its
own type story.)

**Explicitly NOT type-preventable (honesty boundary — do not fake a type here):**

- **O3 respawn-bound** — a retry counter + escalation; "the disk is permanently
  corrupt" is not a representable value. Runtime budget (§5 O3-sub).
- **E5 reorg-fork-crossing** — `reference_height ≥ fork_height ⇒ reanchor` is a
  comparison against a reorg *event*, not a value invariant. Logic (§5 O1-sub /
  CT-5d).
- **O5 lying-daemon gate** — already a *store* invariant (single-writer actor +
  ingest-verify ⇒ the store holds only verified state, so `assemble` reads
  verified state by construction). A per-call typestate would be redundant with
  the store invariant — adding one is the speculative-extensibility failure
  `21-reversion-clause-discipline.mdc` warns against.

T1/T2 land as deletions in CT-5c; T3 reshapes the CT-5c actor read API and is the
E1 closure (§3.1). The cross-seam `BlockHeight` adoption (E7, CT-5a) is the same
class as T1 — a newtype displacing a raw `u64` at a confusion-prone boundary.

---

## 4. Round-1 open questions (agenda)

Consolidated from §3. All six resolved 2026-06-14 (§3); two corrected the
initial pull (struck through).

| ID | Question | Resolution |
|----|----------|------------|
| **R1-Q1** | Where the `CurveTreeClient` lives + single-writer cell (§3.1) | ~~refresh-owned~~ → ~~`Engine` field under the RwLock~~ → **`CurveTreeActor` + `Clone` `CurveTreeHandle`** (Round 2, mirror `KeyActor`); merge is sole ingest-sender; consistency via ingest-ack-before-ledger-commit |
| **R1-Q2** | Ingest site + what `ScanResult` carries (§3.2) | **merge drives `handle.ingest`**, commits ledger on ack; `ScanResult` grows **two transit fields** — full per-block leaf set + per-block header root (both dropped after merge) — A1 frozen. **Feed amended by §3.2.1 (Round 3): genesis-anchored, not the floored producer** |
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

## 5. Threat-model frame (A3 — pass complete 2026-06-14)

CT-5 is orchestration (no new crypto, no new consensus rule), so the §3.7.x
security boundaries are inherited, not re-litigated. The objectives below are
the active-defense pass; each routes to (a) in-scope absorption, (b) discipline
note, or (c) named forward-action. **The A3 pass surfaced three sub-findings —
O1-sub (E1 read-snapshot makes C1 sufficient), O3-sub (respawn must be bounded
or a corrupt store livelocks), and the O5 boundary (consistent-liar caught at
consensus, never a leak) — each recorded inline.** No objective inverted to a
blocker; the security property (no witness leak; lying-daemon degrades to DoS
only) holds across all six.

1. **Wrong-root / stale-snapshot spend (O1).** A built proof anchored at the
   wrong height or a stale root. *Defense:* C1 single-`ReferenceBlock`-per-tx
   (§2), **plus the E1 read-snapshot atomicity that makes C1 sufficient** — C1's
   equal-`ReferenceBlock`-*value* across N inputs does **not** prevent a wrong-root
   spend on its own, because a reorg interleaving N per-input assembly reads would
   assemble different inputs against different tree states under one
   `ReferenceBlock` value (A3 finding: C1 value-equality is necessary, not
   sufficient). The batch `AssembleTx` message (E1, §3.1 / §3.7 T3) is the half
   that closes it — all N assemble in one handler under one snapshot, so the
   interleaving is structurally unrepresentable. C2 selection gate, C3 path
   precondition, and proactive `should_reanchor` complete the defense.
   *Disposition (a):* the §3.5 reference-selection fix is the direct remedy for
   the confirmed tip-as-reference bug; E1's snapshot is the structural backstop.
   - **O1-sub (E5) — reorg replaces the reference block while the tip stays above
     it.** `should_reanchor` (`reference.rs:189`) catches two cases: age ≥
     `REBUILD_AT` (=50), and reference *above* the tip (age `None`, a reorg that
     rewound past it). It does **not** catch a reorg whose fork height is ≤ the
     reference height but whose new chain still extends above it: the reference
     block is orphaned, yet age is `Some(< 50)`, so the age predicate stays quiet.
     A reorg deeper than `REF_ANCHOR_AGE` (=6) is exactly this shape.
     **Constant confirmed production, not placeholder:**
     `FCMP_REFERENCE_BLOCK_MIN_AGE = 5` (`config/consensus_constants.json:4`),
     `REF_ANCHOR_AGE = MIN_AGE + 1 = 6` (`reference.rs:83`). It is deliberately
     shallow: maturity is enforced by *deferred tree insertion* (coinbase 60,
     regular 10, staked max(lock,10) — `FCMP_PLUS_PLUS.md:434`), so `MIN_AGE`
     carries **only** a reorg safety margin, and 5 blocks is the consensus
     design's "sufficient for the referenced tree state to be stable."
     **Frequency, framed correctly:** that same premise bounds E5 — the design
     *assumes* reorgs deeper than ~5 blocks are rare; if they were common,
     `MIN_AGE=5` would be a **consensus** safety problem upstream of E5, not a
     refresh-cost one. So the E5 trigger is **rare but bursty**: when a deep reorg
     does fire it orphans *every* in-flight proof at once (all anchor at
     `tip − 6`), so the cost concentrates as `pending_txs × N`-assemblies in one
     burst — this is where E5 couples with E6c (N round-trips per re-anchor),
     analyzed separately but joined by the shallow anchor. Absent the guard it
     degrades to **submit-time daemon rejection** (DoS, never a witness leak —
     O5 posture). *Defense (engine-side, CT-5d):* the reanchor trigger composes
     `should_reanchor(tip, ref_height)` **with** a reorg-fork-crossing check —
     any pending tx whose `reference_height ≥ handle_reorg.fork_height` is forced
     to re-anchor regardless of age. Only the engine knows the fork height
     (`reference.rs` sees only tip + reference), so this is CT-5's responsibility,
     not the curve-tree crate's. **KAT (raised priority):** pending tx at
     `reference_height`, reorg of depth 7–10 crossing it, assert re-anchor fires
     — not an edge case, the normal deep-reorg-with-pending-tx interaction. The
     `REF_ANCHOR_AGE` value carries its own reversion clause (`reference.rs:80`):
     it moves only on a `MIN_AGE` consensus change or an observed deep-reorg-rate
     change, not by preference. *Disposition (a).*
   - **O1-priv (X1) — `REF_ANCHOR_AGE` is a wallet-fingerprinting oracle, not
     only an E5 cost lever (external pass, Monero decoy-timing lesson).** FCMP++
     full-chain membership removes the decoy-selection deanonymization class
     structurally (no ring, no decoy distribution to fingerprint), but the
     *successor* risk survives: the reference-block choice is a wallet-side
     timing signal. Every Shekyl wallet anchors at `tip − REF_ANCHOR_AGE`; two
     wallets spending at the same tip anchor at the same height, which is the
     privacy-preserving outcome **only while the anchor age is uniform across all
     wallet implementations**. A divergent anchor age (a config knob, or a second
     implementation choosing a different value) makes the reference height a
     wallet-software fingerprint the way decoy-algorithm version once fingerprinted
     Monero wallets. The E5 reversion clause already pins `REF_ANCHOR_AGE` to the
     consensus `MIN_AGE` and forbids "by preference" changes; X1 sharpens *why*:
     the constraint is **consensus-uniformity**, not merely stability — if a
     second Shekyl wallet ever ships, its anchor age is a **consensus-conformance
     requirement, not a config option**, because a per-wallet anchor age is a
     deanonymization oracle (`00-mission.mdc` priority-2: privacy is never a
     setting). *Disposition (b):* discipline note — `REF_ANCHOR_AGE` is never
     surfaced as user/wallet configuration; any future wallet implementation
     treats it as consensus-derived. No CT-5 code change (the single Shekyl-oxide
     implementation already derives it from `MIN_AGE`); recorded so the constraint
     is privacy-load-bearing, not just reorg-safety-load-bearing.
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
   - **O3-sub (A3 finding) — respawn must be bounded, or a deterministically
     corrupt store livelocks.** R1-Q4 frames respawn as "a poison is a transient
     persistence hiccup; refresh already retries." That holds for a transient
     fault (a truncate-without-rebuild crash that a reopen repairs). It does
     **not** hold for a genuinely corrupt redb file (disk failure): reopen → poison
     → respawn → reopen, an unbounded loop that no test surfaces because tests use
     clean stores. *Defense:* respawn is **bounded by the existing refresh
     retry/cancel budget** (couples with O6) — a respawn count exceeding the budget
     escalates the persistence error to a **surfaced fault** rather than looping
     silently; at that point the poison is no longer transient and is
     user-actionable (re-sync from a clean store). CT-5d's respawn KAT (O3) must
     include the bounded-retry-then-surface path, not only the happy respawn.
     *Disposition (a) for the bound; (c) for the escalation wiring, recorded for
     the refresh-resilience review with O6.*
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
   - **O5 boundary (A3 finding) — the ingest verify catches an *inconsistent*
     liar; a *consistent* liar is caught at consensus, and neither leaks the
     witness.** The header root the §3.3 verify compares against comes from the
     same daemon that supplied the leaves (the Rust parser reads it from the
     daemon's block header — §3.6). So the ingest-time verify only catches a
     daemon that lies about leaves but *not* about the header (an inconsistent
     liar); a daemon that supplies bad leaves *and* a matching bad header root
     passes ingest. That is **not** a hole, because the proof built against the
     liar's view is rejected by honest nodes at submit (its `referenceBlock` root
     is non-canonical) — still DoS, never a leak. The witness-no-leak property is
     independent of leaf honesty entirely: spend secrets come from the wallet's
     own keys, never the daemon's leaves, and FCMP++ zero-knowledge means a
     malformed membership path yields an *invalid* proof, not a *leaky* one. The
     ingest verify is defense-in-depth (fail-fast on the common inconsistent
     liar); consensus rejection is the backstop for the consistent liar.
     *Disposition (b) holds — the gate ordering is the discipline; the security
     property does not rest on the ingest verify alone.*
6. **Resource exhaustion on reorg storm (O6).** Repeated deep rollbacks +
   re-sync. *Disposition (c):* forward-action — bounded only by the existing
   refresh retry/cancel budget; no new bound in CT-5, recorded for the refresh
   resilience review. *A3 cross-references:* this is the budget the O3-sub bound
   draws on (respawn shares the retry envelope), and the E4 per-block full-leaf-set
   allocation (§3.2) is the per-block re-ingest cost under a storm — both are
   O(work-per-block), released per block, and the resilience review owns the
   aggregate bound.

### 5.1 External threat pass (X1–X7 — privacy-coin failure graveyard, complete 2026-06-14)

The A3 pass (O1–O6) reasons from CT-5's own surfaces. This pass reasons from the
graveyard — how *other* privacy coins and sync wallets were actually exploited —
and maps each class to whether CT-5 is exposed. The weight-bearing finding (X3)
resolved — after running its two load-bearing verifications down against the code
— to a **wallet-side resolution ambiguity, not a consensus gap**, with an
adversarial precondition that is cryptographically unreachable; X1 sharpened an
existing defense (folded into O1-priv above); the rest confirm inherited
properties. None inverts a disposition.

- **X3 (Zcash malformed-proof-input class — THE weight-bearing one) — a wallet
  *resolution-ambiguity* finding, NOT a consensus gap. The fix resolves owned
  outputs by `gindex`, the tree's actual unique key (V3-confirmed locally
  constructible), making the collision case *structurally impossible* — deleted
  from the threat model, not bounded; `(O, C, h_pqc)` is the recorded fallback. A
  consensus output-key-uniqueness rule is explicitly rejected as a privacy
  regression.** `assemble_path` (`assemble.rs:90–97`) resolves an `OutputIdentity`
  to a position by **first-match** `.position(|e| e.identity.output_key ==
  id.output_key && e.identity.commitment == id.commitment)` — keyed on `(O, C)`
  only, *not* `h_pqc`, *not* `gindex`. The whole blast radius is: two leaves at
  different gindexes sharing both `O.x` and `C.x`, and the wallet picks the
  lower-gindex one. The tree is sound (`gindex` is the total unique key,
  `DuplicateGindex` = store corruption, `client.rs:361`); the ambiguity is purely
  that the *wallet's resolution key is weaker than the tree's unique key*.

  **Why NOT a consensus rule (privacy > security > correctness — the priority
  order points away from consensus).** The reflex to close X3 by making
  `output_key` unique at consensus is the move that has bitten other coins, and it
  is wrong here at every level of the hierarchy:
  - *Privacy (decisive).* A consensus output-key-uniqueness rule forces every
    validator to maintain and consult a **global index of every output key ever
    seen**, and forces block construction to prove non-membership in it. On a
    transparent chain that is free; on a *privacy* chain it is exactly the kind of
    chain-wide, cross-output linkable structure FCMP++ exists to keep from being
    load-bearing. Monero deliberately does **not** enforce global output-key
    uniqueness for this reason — it tolerates key reuse and handles the
    consequences in the wallet, because the alternative is a canonical linkability
    surface. Solving a narrow wallet bug by adding a chain-wide privacy-adjacent
    index is disqualified under `00-mission.mdc` priority-2 alone.
  - *Security (the rule wouldn't even close it).* The dangerous case is not two
    *honest* outputs colliding by chance (negligible at 32-byte key space) — it is
    an *adversary* paying you, crafting an output that collides with one of your
    existing `(O.x, C.x)`. **Verified unreachable (V1, load-bearing):** `O` is a
    one-time address, `O = ho*G + B + y*T` (`output.rs:14/28`), where `ho` and `y`
    come from `derive_output_secrets(combined_ss, output_index)` and `combined_ss =
    combine(x25519_ss, ml_kem_ss)` is the hybrid-KEM shared secret from
    `HybridKEM.Encap(recipient_pk)` (`output.rs:8–28`). `B` (recipient spend key)
    is fixed and `ho`/`y` are hash outputs over a KEM-derived secret — so a payer
    cannot drive `O.x` to a chosen target without grinding a
    hash-composed-with-scalar-mult preimage (a ~32-byte match), and `O` always
    lands in *your* key space, not an arbitrary one. The adversarial-collision
    precondition is therefore cryptographically hard, which **downgrades X3 from
    "adversarial wrong-leaf assembly" to "negligible honest collision"** — a class
    that does not warrant a consensus rule. (If the derivation *did* let a sender
    target `O.x`, that would be a derivation finding far upstream of X3, and a
    consensus rule still wouldn't be the fix — the derivation would.)
  - *Correctness (where the fix belongs).* The bug is simply that the resolution
    key is weaker than the tree's unique key. Fix it wallet-side, on data the
    wallet already holds.

  **Disposition (a) — resolve owned outputs by `gindex`, the tree's actual unique
  key, in CT-5c; no consensus surface. The collision case is *deleted*, not
  bounded.** The two candidate fixes are **not** two points on one quality axis —
  they close different properties: `(O, C, h_pqc)` makes collision *cryptographically
  negligible*; `gindex` makes it *structurally impossible*. After V1 the
  `(O, C, h_pqc)` residual defends only against simultaneous honest collision in
  three hash-derived 32-byte fields — a probability so far below every other
  failure in the system that the defense is decorative, and it forces the threat
  model to *carry the collision-negligibility argument forever*. The `gindex`
  resolution lets the model **delete** the collision case instead — the same
  "make the bad state unrepresentable, don't defend against it" discipline as the
  T1–T3 type contracts and the E1 batch message. So the ordering is inverted from
  "minimal vs preferred": **`gindex` is *the* fix; `(O, C, h_pqc)` is the fallback,
  gated on a single binding-derivability check — which the verification below shows
  *holds*, so the fallback is recorded but not taken.**

  **Why `gindex` is the correct fix, not merely the stronger one.** The
  `(O, C)` content-match was always solving a problem the wallet does not have for
  its *own* outputs. The §4.3 content-match exists to avoid *querying the daemon
  for position* (the privacy property: never ask the daemon "where is my output").
  But for an owned output the wallet is matching its own output in **downloaded
  data**, not querying anyone, and it already holds the global index from its own
  scan (`TransferDetails.global_output_index`, `transfer.rs:90`). First-match on a
  weak content key is a *vestige* of treating owned-output resolution as if it were
  locating an arbitrary output — which it is not.

  **V3 (hinge verification) — the index→gindex binding IS locally constructible at
  `assemble.rs:92`, confirmed at source, no daemon query:**
  - The `drained` stream at the match site is `Vec<LeafEntry>`, each carrying
    `e.gindex` (`assemble.rs:89`, `LeafEntry.gindex` `types.rs:141`). Tree position
    `P` = index in `drained`, so "global index `G` sits at tree position `P`" is
    `drained.position(|e| e.gindex == G)` — entirely local.
  - The numbering matches, **resting on the no-legacy genesis invariant**: the
    scanner sets `global_output_index = output.index_on_blockchain()`
    (`ledger_ext.rs:74`), accumulated as a coinbase-first per-tx base plus the
    intra-tx index `o` (`scan.rs:562`, base advanced at `scan.rs:735–738`,
    miner-tx-first at `scan.rs:672–678`); the curve-tree `gindex` is the **same**
    `next_output_seq` counter (`types.rs:116`, mirrors `blockchain_db.cpp:360`),
    locally recomputed coinbase-first over every output (`recon.rs:144–148`). They
    agree because **every Shekyl tx is V2** (`RCTTypeFcmpPlusPlusPqc` minimum, no V1
    — `60-no-monero-legacy.mdc`): the scanner advances its base only for
    `Transaction::V2` (`scan.rs:735`, a Monero-legacy guard that is vacuously
    always-true under FCMP++), and the curve-tree counts every output
    unconditionally, so "count every V2 output" = "count every output." Were a V1
    tx ever admissible, the scanner would skip its outputs while the tree counted
    them and the two numberings would diverge — so the binding's soundness is the
    genesis no-V1 invariant, not an unconditional property of the two counters.
    (The `output_index_for_first_ringct_output` name and the `V2` guard are
    Monero-legacy residue — a rule-60 dead-naming / vacuous-guard cleanup
    candidate, FOLLOWUPS, not CT-5 scope; flagged so the inherited naming isn't
    mistaken for a live RingCT/V1 distinction.)
  - On any consensus-valid chain `gindex` is **dense-equals-daemon** (every
    consensus output is leaf-eligible and commitment-bearing — `client.rs:278–296`);
    the sparse-gindex degradation is confined to consensus-unreachable outputs,
    which never produce a `drained` leaf and which the wallet never owns — so it
    does not touch the owned-output resolution path.
  - The owned output is always a leaf (the wallet can only own tagged/staked,
    i.e. leaf-eligible, outputs), so its gindex is present in `drained` and the
    match resolves exactly.

  **The fix (CT-5c):** thread the owned input's `global_output_index` into the
  assembly input (it rides the batch `AssembleTx` message alongside the
  `ReferenceBlock`, aligning with T1/T3 — the engine has it per input from
  `TransferDetails`), and resolve `leaf_pos = drained.position(|e| e.gindex ==
  Gindex(G))`. Keyed on the tree's actual unique key, the resolution is **total**:
  there is no collision case. The `(O, C)`/`(O, C, h_pqc)` content-match is deleted
  from the owned-output path.
  - **Reorg-safety (inherits X2).** `gindex`/`next_output_seq` can renumber across
    a reorg, but the wallet resolves by its own `TransferDetails.global_output_index`,
    which is rewound/rescanned inside the **same `handle_reorg` atomic** as the tree
    rollback (X2, `merge.rs:337/595–602`) — so the resolution key moves with the
    tree, never lagging it. Spendable outputs are ≥`SPENDABLE_AGE` deep and below
    the shallow reference anchor; a reorg deep enough to renumber one triggers the
    CT-5d re-anchor + rescan (E5), which re-resolves against the rebuilt index.
  - **Test obligation collapses:** the total fix has **no collision case to test**
    — the KAT is "resolves to the correct `gindex`," full stop. (The probabilistic
    fallback would have required a `(O, C)`-collision-with-distinct-`h_pqc` KAT
    *and* a standing negligibility argument; the total fix deletes both.)
  - **`(O, C, h_pqc)` fallback (not taken):** would apply only if V3 had shown the
    index→gindex binding required a daemon query or a structure the client does not
    hold — which it does not. Recorded so the fallback's gate is explicit;
    `h_pqc` is on `OutputIdentity` (`types.rs:55`) and in hand if ever needed.
  - **Failure floor (retained backstop, either fix):** even if a collision somehow
    occurred, it degrades to DoS, never theft — the key image is `I = Hp(O)`
    (`assemble.rs:110`), a function of `O` alone, so a wrong pick cannot yield a
    spendable proof for an output the wallet doesn't control; the ledger already
    runs a burning-bug-drop under the reorg-atomic merge guard (`merge.rs:597`); a
    wrong leaf yields an *invalid* proof, never a *leaky* one (O5 / FCMP++ ZK).
    This is the constant-time-failure instinct applied to resolution: the floor
    holds regardless of which resolution fix lands.
  - **Reopening clause (A4):** revisit **only** if the one-time-address derivation
    is found to let a sender target an existing `O.x` — a derivation finding
    upstream of X3, not a content-match one, and the consensus question would still
    resolve against an output-key index. **Cited at the §4.3 content-match
    contract** (CURVE_TREE_CLIENT.md): owned-output resolution is keyed on the
    tree's `gindex`-uniqueness (total), resting on the V1 derivation (sender cannot
    target `O.x`) and the V3 local index→gindex binding — and the threat model
    records **why the chain does *not* need an output-key index** (a privacy
    regression), so the next proposal to add one has the disposition on file.

- **X2 (reorg double-spend-against-self class) — CONFIRMED: selection state
  rebuilds inside the same reorg-atomic transition, not lazily.** The failure
  class (chain view rewinds, spendable-set rebuild deferred, tx in the window
  selects a phantom output) does not apply: `apply_scan_result_to_state`
  (`merge.rs:329–339`) runs the whole merge under one `self.ledger.write()` guard
  (`merge.rs:209`) and calls `indexes.handle_reorg(ledger, fork_height)` **before**
  any per-height additive event. `LedgerIndexes` owns the selection state
  (`staker_pool` + transfer indices), so the spendable-set rebuild is *inside* the
  same atomic; the `merge.rs:595–602` comment confirms inserted indices are
  "post-burning-bug-drop and post-reorg-rewind by construction … same write guard."
  The third leg (E5 pending-tx reference re-anchor) closes the remaining surface.
  *Disposition (a):* no change; the engine reorg KAT (§6, E6a) asserts pending-table
  equality post-reorg, which exercises exactly this atomicity.

- **X4 (timing side-channel on ingest class) — CONFIRMED: ingest cost is constant
  w.r.t. ownership; the full-leaf-set buffer is privacy-neutral.** The "wallet does
  more work on blocks containing its outputs" leak does not apply: `collect_block_leaves`
  (`recon.rs:136–163`) iterates **every** output and calls `try_build_leaf` with no
  ownership check — the tree ingests every consensus output identically whether owned
  or not. The per-block ingest work is a function of outputs-per-block, **not** of
  which outputs are the wallet's, so a local observer cannot infer owned-output
  positions from ingest timing. *Disposition (b):* discipline note — the
  constant-time-w.r.t.-ownership property of the ingest path is what makes the E4
  full-leaf-set buffer privacy-neutral (the crypto-path constant-time discipline,
  lifted to ingest); CT-5 must not introduce an owned-output fast-path in ingest.

- **X5 (maturity off-by-one / two-sources-of-truth class) — CONFIRMED single source;
  coinbase grep run down to a CT-5c *code change*, not a confirmation.** `eligible_height`
  is the single field both balance display (`balance.rs:61`, `current_height >=
  td.eligible_height`) and the C2 selection gate read — selection does **not** re-derive
  maturity, it reads the stored field (the CT-2/CT-3 "single enforcer" property holds).
  **But** the scanner sets `eligible_height = block_height + SPENDABLE_AGE` with
  `SPENDABLE_AGE = 10` **unconditionally** (`ledger_ext.rs:111`, `transfer.rs:25`), while
  the curve-tree `maturity_height` is **type-specific** — coinbase `60`, regular `10`,
  staked `max(lock, 10)` (`recon.rs:82–85`, `COINBASE_LOCK_WINDOW = 60`). For regular
  outputs (the common case) `10 == 10`, no divergence. For **coinbase**, selection would
  mark an output spendable at `+10` while the tree inserts it at `+60`.

  **The coinbase grep (run down at the V1/V3 bar, resolving the disposition's open
  fork): coinbase *does* flow through `from_wallet_output` with the flat `+10` — so X5
  is a CT-5c code change, not a confirmation.** `from_wallet_output`
  (`ledger_ext.rs:61–116`) has **no coinbase/miner branch**: it sets `eligible_height =
  block_height + SPENDABLE_AGE` for every owned output and accounts for staking
  separately (`stake_lock_until`, `:67`). Miner-ness is **not** a `WalletOutput` field
  (`output.rs:208–214` — `absolute_id`, `relative_id`, `data`, `metadata`, `staking`);
  the coinbase lock instead rides `WalletOutput::additional_timelock()`
  (`output.rs:248`, "Additional timelock beyond the default 10-block lock window"),
  which `from_wallet_output` currently **ignores**. So the divergence is real *and the
  fix is constructible at this exact site* from data the scanner already holds:
  `eligible_height = max(block_height + SPENDABLE_AGE, timelock_height(additional_timelock),
  stake_lock_until)` — the latest of the default window, the explicit/coinbase timelock,
  and any stake lock. (This also subsumes any non-coinbase explicit timelock, which is
  ignored today by the same omission; coinbase `+60` is the concrete instance.) The
  precondition for the hazard to bite is a **mining wallet owning its own coinbase**
  (coinbase outputs are scannable to the miner's address, inherited from CryptoNote);
  for non-mining wallets there is nothing to own and the divergence is inert.

  *Backstop (why this is sizing, not safety):* the divergence is **backstopped** —
  `assemble_path` returns `ClientError::OutputNotDrained` (`assemble.rs:95`) if the leaf
  is not yet drained at the reference height, so a too-optimistic coinbase
  `eligible_height` degrades to a **clean assembly error (DoS floor), not a wrong
  proof.** The grep settles the PR scope: CT-5c **aligns `from_wallet_output`'s
  `eligible_height` to incorporate `additional_timelock`** (a bounded edit at one site),
  removing the OutputNotDrained-as-stuck-funds UX. **KAT:** coinbase output owned by a
  mining wallet, tx attempt at reference between `+10` and `+60`; assert the output is
  **gated at selection** (post-fix `eligible_height = +60`), and — pre-fix safety
  invariant — that an over-optimistic `eligible_height` yields clean OutputNotDrained,
  never a malformed path.

- **X6 (supply-chain / dependency-substitution class) — discipline note.** CT-5
  adds a `shekyl-curve-tree` dependency edge to `shekyl-engine-core` and (if the
  actor is `kameo`) puts a new framework dependency adjacent to the signer — the
  Ledger Connect-Kit lesson is that the wallet's most-trusted component (the signing
  path) is the highest-value supply-chain target. *Disposition (b):* new dependency
  edges (`shekyl-curve-tree`, and `kameo`/`redb` to the extent newly introduced to
  this crate) are **exact-pinned** in the workspace `Cargo.toml`
  (`= "x.y.z"` posture, matching the `fips203 = "=0.4.3"` precedent), and the CT-5a
  PR's dependency-discipline review (`17-dependency-discipline.mdc`) explicitly covers
  the new edge — version, feature flags, and audit posture verified at source, not
  from training-data recall.

- **X7 (RPC/daemon trust-boundary confusion class) — leaf-set blob size must be
  bounded by the consensus block-size limit before buffering.** O5 covers the lying
  daemon for leaf *content*; the Electrum lesson is broader — every daemon-sourced
  field the wallet trusts without bound is a surface, including ones that seem
  innocuous. CT-5 newly buffers the **full per-block leaf set** (E4), daemon-controlled
  in *size*; an enormous leaf blob is a memory-exhaustion DoS if the materialization
  trusts the blob length. *Disposition (a) — assert the bound at pre-0/CT-5a:* the
  leaf-set materialization inherits the consensus block-size limit rather than
  trusting the daemon's blob length — "the daemon wouldn't send something that large"
  is exactly the assumption Electrum servers exploited. The fetch path's block-size
  validation must gate **before** the E4 buffer allocation; CT-5a's DoD asserts the
  buffer size is bounded by the consensus block-size constant, not by the received
  length.

- **X1 (Monero decoy-timing deanonymization class)** — folded into **O1-priv**
  above (`REF_ANCHOR_AGE` consensus-uniformity as a wallet-fingerprinting defense,
  not only an E5 cost lever).

**External pass net:** X3 resolves to a **wallet-side resolution ambiguity, not a
consensus gap** — its adversarial precondition is cryptographically unreachable
(V1: `O` is one-time-address-derived, a payer cannot target `O.x`), so the residual
is negligible honest collision. V3 then confirmed the index→gindex binding is
locally constructible at the match site (the `drained` leaf stream carries
`e.gindex`, and the scanner's `global_output_index` is the same `next_output_seq`
numbering), so the fix **resolves owned outputs by `gindex`** — the tree's actual
unique key — making the collision case *structurally impossible* (deleted from the
threat model, not bounded). `(O, C, h_pqc)` is the recorded fallback, gated on a
binding-derivability check that V3 shows holds, so it is not taken. A consensus
output-key-uniqueness rule is
**explicitly rejected** — it is a privacy regression (a chain-wide output-key
index, the linkability surface FCMP++/Monero deliberately avoid), and it wouldn't
even close the threat. The threat model now records *why* the chain doesn't need
that index. X2/X4 confirm clean; X5 confirms single-source
with a coinbase alignment to land in CT-5c; X6/X7 are a pin-discipline note and a
buffer-bound assertion. The threat model has now looked at the graveyard as well as
at itself.

---

## 6. Sub-PR decomposition (A1 — function-body replacement; provisional)

Boundaries are firm now that R1-Q1/Q2/Q6 are resolved (they decided the field
shapes). Each sub-PR lands ≤ the `06-branching.mdc` 5-day / 10-commit envelope;
none is a consensus-atomic cutover (`07-consensus-atomic-cutovers.mdc` not
invoked — the synthetic→real swap is flag-decomposable behind the assembler
boundary).

- **CT-5 pre-0 — `shekyl-oxide` block-header parser (prerequisite, R1-Q6 / §3.6).
  DONE (`fix/block-header-curve-tree-root`).** Extended `BlockHeader`
  (`rust/shekyl-oxide/shekyl-oxide/src/block.rs`) to parse/serialize
  `curve_tree_root` after `nonce`, matching the consensus serialization
  (`src/cryptonote_basic/cryptonote_basic.h:723/735`). **Implemented unconditional,
  not `hardfork_version`-gated:** the C++ `BEGIN_SERIALIZE` block carries no version
  guard and the field is present from genesis (Shekyl min HF 1), so a gate would be
  a dead pre-genesis branch (`60-no-monero-legacy.mdc`) — the §3.6 scope-note's
  "present from genesis" leg. Threading is automatic: `ScannableBlock.block.header`
  is the public read path, no new `Block`/`ScannableBlock` field. DoD met: header
  round-trip KAT + consensus field-layout cross-check + full-block round-trip
  proving the §3.6 #2 mis-alignment is closed (`src/tests/block.rs`). Lands
  **before** CT-5a, not folded in, because the parser correctness is independent of
  the engine wiring.
- **CT-5a — actor lifecycle + ingest (no signer change).** Add the
  `shekyl-curve-tree` dependency (**exact-pinned; the CT-5a dependency-discipline
  review covers this edge and any new `kameo`/`redb` edge — X6**), the
  **`CurveTreeActor` + `CurveTreeHandle`**
  (R1-Q1, mirror `KeyActor`), spawn on engine open with the `Engine` holding the
  handle, the `ScannableBlock → BlockLeaves` decode (R1-Q3 KAT), and the
  merge-driven `handle.ingest` with ingest-ack-before-ledger-commit (R1-Q2).
  **§3.2.1 (Round 3, closed 2026-06-15) governs the feed: genesis-anchored, not
  the birthday-floored producer. Per §3.2.1.1 (Decisions 1–4) the work splits:
  commit 4 wires the genesis-anchored feed + merge-driven ingest so the
  spendable/synced cursor advances only on ingest-ack (O2 correctness;
  single-surfaced — interim cliff present, acceptable pre-genesis); the
  detection/display two-cursor decoupling (received-shows-immediately) is
  commit 4b, before any release. The backfill driver is cursor-driven by
  construction — no frontier field, resume read from `ingested_tip_height` each
  iteration (D2). Adopting-wallet temporary-unspendability during a
  `0..synced_height` rebuild is surfaced, not silent (D3, with 4b). Commit 4's
  DoD lands the reorg-into-backfill resume-from-cursor KAT (coinbase-expressible)
  and explicitly names that non-coinbase sub-birthday-sibling backfill
  correctness is Tier-B-gated, proven at CT-5c, not at commit 4 (D4) — a green
  commit 4 is not a proven backfill.**
  **The per-block leaf-set materialization (E4) bounds its buffer by the consensus
  block-size limit *before* allocation, not by the daemon's received blob length
  (X7); DoD asserts the bound.**
  Reorg rollback + actor respawn (R1-Q4). Engine call sites carry `BlockHeight`
  across the actor message boundary (not unwrapped to `u64`), **closing the
  CT-3a P5 cross-seam item** (`FOLLOWUPS.md` "Carry `BlockHeight`/`Gindex`
  typing across the client → engine seam"). The signer still uses synthetic
  vectors. **(E6b note for reviewers:** CT-5a carries the per-block header-root
  transit field on `ScanResult` but does **not** consume it — the §3.3 verify is
  CT-5b — so for one PR the field is write-but-not-read. This is the frozen
  contract, not dead code; do not "helpfully" remove it.) DoD: refresh + reorg
  KAT root-matches the CT-2 oracle through the engine path **and asserts
  pending-table equality post-reorg, not only root equality** (the CT-3c
  green-positive-for-broken-migration lesson; a coinbase-only fixture cannot
  exercise class-(b) pending migration, so this DoD **inherits the Tier-B
  non-coinbase fixture dependency** — E6a); respawn KAT (O3).
- **CT-5b — reference selection + §3.3 verify (R1-Q6, derive>hold).** Wire
  `select_reference_height`, the C2 gate, the **§3.3 ingest-time verify**
  (reconstructed root == pre-0 header root → loud DoS on mismatch), and the
  **send-time re-derivation** of the reference-height root from the actor (no
  retention, no schema bump). Lands the `ReferenceBlock` construction (height +
  re-derived root + block hash from the ledger reorg window) the signer will
  consume; the signer still builds synthetic paths but against the *real*
  reference selection. DoD: C2 `OutputNotYetSpendable` KAT + a §3.3
  mismatch-rejection KAT (O5).
- **CT-5c — assembler cutover + `synthetic_tree` deletion + type-enforced contracts
  (R1-Q5, §3.7).** Replace `signing_assembly`/`sign_bridge` synthetic vectors with
  the batch `AssembleTx` message (T3); delete `synthetic_tree`; **delete the raw
  `reference_block: [u8;32]` param** (T1 — `assemble_tx_to_sign` consumes
  `ReferenceBlock`) and **delete the free `tree_depth: u8` param** (T2 — depth
  derived from `AssembledPath.tree`); migrate tests. The §3.7 deletions are the
  E1 closure and the §3.4 bug-class barriers, landed as type changes not
  discipline notes. **Resolve owned outputs by `gindex`, the tree's unique key
  (X3) — thread the owned input's `global_output_index` (`TransferDetails`,
  `transfer.rs:90`) into the batch `AssembleTx` message (T1/T3-aligned) and match
  `drained.position(|e| e.gindex == Gindex(G))` (`assemble.rs:89–94`); delete the
  `(O, C)` content-match on the owned path.** Total resolution, collision case
  *deleted* (V3-confirmed locally constructible — `drained` carries `e.gindex`,
  scanner `global_output_index` is the same `next_output_seq` numbering). No
  consensus change — X3 is a wallet resolution ambiguity, not a consensus gap, and
  its adversarial precondition is unreachable (V1); `(O, C, h_pqc)` is the recorded
  fallback (not taken). **Align `from_wallet_output`'s `eligible_height` to incorporate
  `additional_timelock` (X5 — confirmed code change, not a confirmation).** Coinbase
  flows through `from_wallet_output` (`ledger_ext.rs:61–116`) with the flat `+10`, but
  the tree matures it at `+60` and the coinbase lock rides
  `WalletOutput::additional_timelock()` (`output.rs:248`), ignored today; set
  `eligible_height = max(block_height + SPENDABLE_AGE, timelock_height(additional_timelock),
  stake_lock_until)` so selection and tree-insertion agree. Bounded one-site edit;
  `OutputNotDrained` backstops it DoS-never-theft.
  DoD: real-root proof builds + submits in the `TestDaemon`
  harness; C3 precondition holds; the raw-`[u8;32]`-reference and free-`tree_depth`
  call paths no longer exist (grep-clean); **X3 KAT (owned output resolves to the
  correct `gindex` — no collision case to test); X5 KAT
  (coinbase tx attempt at reference between `+10` and `+60` → no wrong-leaf
  assembly).**
- **CT-5d — proactive horizon guard + closeout.** `should_reanchor` rebuild loop
  for pending txs, composed with the **reorg-fork-crossing trigger** (O1-sub /
  E5: re-anchor any pending tx whose `reference_height ≥ fork_height`, regardless
  of age). Note the cost (E6c): each re-anchor re-assembles the pending tx's N
  inputs → N more actor round-trips per re-anchor (E1). Closeout obligations:
  parent §9 CT-5 row → closed; **`recon_tier_b.rs` un-ignored** — CT-5c landing
  is the trigger that ungates the five Tier-B `#[ignore]` tests, the Stage-2
  closer (`FOLLOWUPS.md` "CT-2 Tier B reconstruct-root KATs"); **close the CT-5
  poison drop-and-reopen FOLLOWUPS item** (absorbed by R1-Q4 respawn — the
  reaction is now done, so the item closes rather than carries); add the new
  FOLLOWUPS row **"unify multisig intent reference-age validation onto
  `reference.rs` predicates post-CT-5"** (E8). `CT5_ROUND1_CLOSEOUT.md`;
  FOLLOWUPS/CHANGELOG. DoD: horizon KAT + reorg-fork-crossing re-anchor KAT; docs
  resync (`91-documentation-after-plans.mdc`).

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
- **`CURVE_TREE_CLIENT.md` §4.3 content-match contract (X3, CT-5c)** → record that
  owned-output resolution is keyed on `gindex` (the tree's unique key), resting on
  the V1 derivation (a payer cannot target `O.x`) and the V3 local index→gindex
  binding (which itself rests on the no-V1 genesis invariant, §5.1); and record
  **why the chain does not need an output-key index** (privacy regression), so the
  next proposal to add one finds the disposition on file. **Also record the
  wallet-conformance corollary (X3 × X1):** owned-output resolution **by `gindex`
  is a wallet-conformance requirement, not a single-implementation choice** — like
  `REF_ANCHOR_AGE` consensus-uniformity (X1), a divergent resolution is a
  correctness/fingerprinting hazard. A second wallet implementation that kept an
  `(O, C)` content-match would diverge in the (negligible-but-nonzero) collision
  case, and — load-bearing — would have to independently encode the **no-V1 genesis
  invariant** the `index→gindex` binding rests on (V3); the `gindex` resolution makes
  that invariant the *only* thing a second implementation must honor, rather than a
  re-derivation of the content-match's collision reasoning.
- **Rule-60 `ringct`/`V2` naming residue — FOLLOWUPS V3.0 (landed 2026-06-14).**
  The public field `ScannableBlock.output_index_for_first_ringct_output`
  (`shekyl-oxide` `rpc/src/lib.rs:80`) and the `matches!(tx, Transaction::V2)`
  index-advance guard (`scan.rs:735`) are Monero-legacy naming / a vacuously-
  always-true guard under FCMP++ (no V1 txs). Not CT-5 scope and not a correctness
  bug (the §5.1 V3 binding rests on the no-V1 genesis invariant either way). Placed
  in the **V3.0 pre-genesis queue** (not CT-5d) because `ScannableBlock` is a public
  RPC type — the rename is free pre-genesis, breaking post-genesis. The FOLLOWUPS
  entry also records the four-version disambiguation (era `V3` ≠ tx-format `2` ≠
  hardfork `1` ≠ proof `FcmpPlusPlusPqc`) so the "is `V2` a protocol bug?" question
  is answered on file.
- **`PHASE_2A_SEND_PATH.md`** — the F1/F2 synthetic-vector notes get a back-ref
  to CT-5 as the production replacement; §3.6 `ProofStale` interim-guard note
  cross-links the landed `should_reanchor` wiring.
- **Multisig reference-age unification (E8) — FOLLOWUPS row, not CT-5 scope.**
  `multisig/v31/intent.rs` already embeds `FCMP_REFERENCE_BLOCK_MIN_AGE` /
  `FCMP_REFERENCE_BLOCK_MAX_AGE` for intent validation (`:56–61`, `:310/:320`).
  Once CT-5 establishes the canonical single-signer reference-selection + C2-gate
  flow in `reference.rs`, multisig's intent validation should route through the
  same predicates rather than its own constant embedding — else two
  reference-selection implementations drift (the hazard `21-reversion-clause-discipline.mdc`
  guards). Not CT-5 scope; recorded as the FOLLOWUPS row CT-5d adds.
- **`CHANGELOG.md`** — per sub-PR.

---

## 8. Review checklist (pre-implementation)

- [x] §1 scope + DoD agreed (real-root proof in `TestDaemon`; reorg KAT vs CT-2
  oracle; C2 clean error; no-secrets test over the `CurveTreeHandle` surface).
- [x] §2 contract confirmed — CT-5 adds **no** new client API; C1
  one-`ReferenceBlock`-per-tx upheld.
- [x] R1-Q1 client ownership — **resolved (Round 2):** `CurveTreeActor` +
  `CurveTreeHandle`; merge sole ingest-sender; ingest-ack-before-commit (§3.1).
- [x] R1-Q2 ingest site + `ScanResult` growth — **resolved:** merge-driven actor
  ingest, two transit fields (leaf set + header root), A1 frozen (§3.2).
  **Mechanism stands; feed amended by §3.2.1 (Round-3 post-closure pin) — the
  tree feed is genesis-anchored, not the birthday-floored producer.**
- [x] R1-Q3 `BlockLeaves` decode = CT-2 drain order — **resolved:** dedicated
  KAT vs the oracle (§3.2).
- [x] R1-Q4 reorg ordering + poison handling — **resolved:** rollback in
  `handle_reorg`, automatic reopen (§3.3).
- [x] R1-Q5 `synthetic_tree` disposition — **resolved:** delete + migrate tests
  (§3.4).
- [x] R1-Q6 header `curve_tree_root` source — **resolved (Round 2):** derive>hold
  — verify at ingest, re-derive at send, no schema bump; pre-0 parser PR still
  required (§3.5/§3.6).
- [x] §3.4 bug **confirmed against live code (A2)**: `tip_hash =
  block_hash_at(synced)` (`local_pending_tx.rs:615`) is passed as the
  `reference_block` 5th arg of `assemble_tx_to_sign` (`:781`; signature
  `signing_assembly.rs:34`) and propagated into `TreeContext` via
  `synthetic_tree_context` (`:51`) — reference is the tip, not `tip −
  REF_ANCHOR_AGE`. `tree_depth = 1u8` hardcoded (`:657`). CT-5 §3.5 / §3.4 fix
  both; line citations verified accurate.
- [x] §5 threat objectives O1–O6 each routed (a)/(b)/(c) — **A3 pass complete**;
  three sub-findings (O1-sub, O3-sub, O5 boundary) recorded inline; no blocker.
- [x] **§5.1 external threat pass (X1–X7) complete** — graveyard mapped; **X3
  run down (the weight-bearing one) with its two load-bearing verifications:
  V1 — `O` is one-time-address-derived (`output.rs:8–28`, `O = ho*G + B + y*T`,
  `ho`/`y` from the hybrid-KEM secret), so a payer cannot target `O.x`
  (adversarial precondition cryptographically unreachable); V2 — `h_pqc`
  (`types.rs:55`) and `TransferDetails.global_output_index` (`transfer.rs:90`) are
  both in hand at the match site. X3 is a wallet *resolution ambiguity*, NOT a
  consensus gap; V3 confirmed the index→gindex binding is locally constructible,
  so the fix resolves owned outputs by `gindex` (the tree's unique key) in CT-5c —
  collision *structurally impossible* (deleted, not bounded), `(O, C, h_pqc)` the
  recorded fallback; a consensus output-key index is rejected as a privacy
  regression.** X1 folded into O1-priv; X2/X4
  confirmed clean; X5 single-source + coinbase align (CT-5c); X6 pin-discipline;
  X7 leaf-blob bound (CT-5a). No disposition inverted.
- [x] §6 sub-PR boundaries firm (R1-Q1/Q2/Q6 resolved); pre-0 prerequisite added.
- [x] §7 parent §9 row + 2A back-refs; §5.4 confirmed-not-pending; **X3 adds
  `CURVE_TREE_CLIENT.md` §4.3 gindex-resolution citation (CT-5c) and the rule-60
  `first_ringct`/`V2`-guard FOLLOWUPS row (CT-5d)**.
- [x] **E1 (closed, upgraded)** — tx-scoped read-snapshot atomicity vs C1:
  resolved by the batch `AssembleTx` message (§3.7 T3) — all N inputs assemble in
  one handler under one snapshot, mid-assembly-reorg split unrepresentable;
  concurrent-read remains a CT-5c perf option (§3.1).
- [x] **§3.7 type-enforced contracts** — T1 (`ReferenceBlock`-only, delete raw
  `[u8;32]`), T2 (derive `tree_depth`, delete free param), T3 (batch
  `AssembleTx`); not-type-preventable list recorded (O3/E5/O5). Land in CT-5c.
- [x] **E2 (closed)** — two-clause structural lock-ordering invariant pinned
  with no-secrets-test review status; substrate-confirmed (`KeyActor` holds no
  engine ref); respawn is engine-side (§3.1).
- [x] **E5 (closed)** — `REF_ANCHOR_AGE=6` confirmed production (deferred-insertion
  maturity, reorg-safety-margin rationale); CT-5d composes the reorg-fork-crossing
  re-anchor trigger; depth-7–10 KAT specified (§5 O1-sub).
- [x] **Closure-review round complete** (E1/E2/E5 finished); **A3 internal threat
  pass complete** (O1–O6, three sub-findings); **A3 external threat pass complete**
  (§5.1, X1–X7, one real gap X3 closing to a CT-5c match tightening); **§3.4 bug
  confirmed against live code**. All pre-implementation checklist items are now
  closed — CT-5 pre-0 may begin.

---

## 9. Round-2 review findings (E1–E9) — disposition log

External review of the Round-2 doc, integrated 2026-06-14. Each finding's full
treatment is in the cited section; this is the audit index.

| ID | Finding | Disposition | Lands |
|----|---------|-------------|-------|
| **E0** | Actor justification was "standing principle"; real reason is redb single-writer | Justification corrected; A4 reversion target named (`RwLock<CurveTreeClient>`) | §3.1 |
| **E1** | `assemble_path` crosses the actor boundary; C1 read-side not closed | **CLOSED + upgraded to type/message shape (T3)** — batch `AssembleTx` message assembles all N inputs in one handler under one snapshot; mid-assembly-reorg split structurally unrepresentable | §3.1, §3.7, §8 |
| **E2** | `ask().await` under the engine write guard asserted, not verified | **CLOSED** — promoted to enforceable two-clause structural invariant (actor holds no engine ref; respawn engine-side), no-secrets-test review status | §3.1, §8 |
| **E3** | §3.6 mis-alignment is a standalone block-deserializer bug | **CLOSED — (a) verified at source.** C++ header is 6-field (`curve_tree_root` last, `cryptonote_basic.h:723/735`); Rust reads 5 (`block.rs:60–68`), so `Block::read` mis-aligns at the miner tx and **fails loudly** on any real block (root's first byte parsed as tx-version → `version != 2` reject, `block.rs:212–215`) — it has never been fed one (tests use synthetic 5-field blocks). **No compensating offset:** the only hash special-case is the unrelated inherited `202612` Monero test-vector remap (`block.rs:201`), and `serialize_pow_hash` (`block.rs:170–184`) hashes the 5-field header so the Rust block hash *cannot* match consensus for a real block. pre-0 therefore **establishes** correctness for the first time — its KAT is a genuine new guarantee (6-field round-trip + Rust block hash == consensus incl. `curve_tree_root`), **not** a proof-of-inertness against a compensation. Also fixes `ReferenceBlock.block_hash` correctness, which X3/CT-5 depend on. | §3.6, §6 |
| **E4** | Full leaf set is a real refresh-path cost, not free transit | Cost named (O(outputs/block), released per block) as the price of ingest-ack-before-commit | §3.2 |
| **E5** | Reorg can orphan the reference block while tip stays above it; `should_reanchor` (age) misses it | **CLOSED** — `REF_ANCHOR_AGE=6` confirmed production (rare-but-bursty, couples with E6c); CT-5d reorg-fork-crossing trigger + depth-7–10 KAT | §5 O1, §6 |
| **E6a** | Reorg KAT must assert pending-table equality (CT-3c lesson); inherits Tier-B fixture | CT-5a DoD updated | §6 |
| **E6b** | `ScanResult` header-root field is write-but-not-read in CT-5a | Reviewer note added so it is not removed | §6 |
| **E6c** | Re-anchor = N more actor round-trips per pending tx | Cost noted | §6 |
| **E7** | FOLLOWUPS reconciliation: poison closes, `BlockHeight` seam closes, Tier B ungated | CT-5a closes the `BlockHeight` seam; CT-5d closes poison + ungates Tier B | §6 |
| **E8** | Multisig already embeds the reference-age constants — drift hazard | FOLLOWUPS row (CT-5d): unify multisig intent onto `reference.rs` predicates | §7 |
| **E9** | Title stale ("Round 1, OPEN") | Retitled "Round 2, review integrated"; closure gate kept | header |

### External threat pass (X1–X7) — disposition log

Graveyard-mapped pass, integrated 2026-06-14. X3 is the only real gap and closes
to a wallet-side `gindex` resolution — the tree's actual unique key — making the
collision case structurally impossible (deleted, not bounded), not a consensus
citation (the honest correction).

| ID | Class (incident) | Exposed? | Disposition | Lands |
|----|------------------|----------|-------------|-------|
| **X1** | Monero decoy-timing deanonymization | Successor risk: anchor-age fingerprint | `REF_ANCHOR_AGE` is **consensus-uniform** across implementations (privacy, not just reorg-safety); never a config knob | §5 O1-priv |
| **X2** | Reorg double-spend-against-self (Electrum-class) | No | **Confirmed** — selection state (`LedgerIndexes`) rebuilt inside the same `handle_reorg` atomic under one write guard (`merge.rs:337/595–602`), not lazily | §5.1 |
| **X3** | Zcash malformed-proof-input / wrong-leaf | **Wallet resolution ambiguity, not a consensus gap; adversarial precondition unreachable (V1)** | **Resolve owned outputs by `gindex` — the tree's unique key — in CT-5c: collision *structurally impossible* (deleted, not bounded). V3-confirmed locally constructible: `drained` carries `e.gindex` (`assemble.rs:89`/`types.rs:141`) and scanner `global_output_index` is the same `next_output_seq` numbering (`ledger_ext.rs:74`/`scan.rs:562`/`recon.rs:122–148`). `(O, C, h_pqc)` recorded fallback (not taken). KAT = "resolves to correct gindex" (no collision case). Consensus output-key index REJECTED (privacy regression). V1: `O` one-time-address-derived (`output.rs:8–28`)** | §5.1, §6 |
| **X4** | Ingest timing side-channel (owned vs not) | No | **Confirmed** — `collect_block_leaves` ingests every output identically (no ownership check, `recon.rs:136–163`); constant-w.r.t.-ownership makes the E4 buffer privacy-neutral | §5.1 |
| **X5** | Maturity off-by-one / two-sources spendability | Common path no; coinbase is a **code change** | **Single source confirmed** (`eligible_height` read by both balance + C2). **Coinbase grep resolves to a CT-5c *code change*, not a confirmation:** `from_wallet_output` (`ledger_ext.rs:61–116`) sets `eligible_height = block_height + SPENDABLE_AGE` (flat +10) for *every* output — no coinbase branch — while the tree matures coinbase at +60. Miner-ness is not a `WalletOutput` field, but the coinbase lock rides `additional_timelock()` (`output.rs:248`), currently **ignored** at this site. Fix (constructible here): `eligible_height = max(block_height + SPENDABLE_AGE, timelock_height(additional_timelock), stake_lock_until)`. Precondition = mining wallets owning coinbase; `OutputNotDrained` (DoS floor) backstops it DoS-never-theft regardless | §5.1, §6 |
| **X6** | Supply-chain / dependency substitution (Ledger Connect-Kit) | Discipline | New edges (`shekyl-curve-tree`, `kameo`/`redb`) **exact-pinned**; CT-5a dependency-discipline review covers the edge | §5.1, §6 |
| **X7** | RPC/daemon trust-boundary (Electrum malicious-server) | **Yes (DoS)** | Leaf-set buffer bounded by **consensus block-size limit before allocation**, not by daemon blob length; CT-5a DoD asserts it | §5.1, §6 |


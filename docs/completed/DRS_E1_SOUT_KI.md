# DRS-E1 S-OUT-KI — outputs and key images: increment plan and Round-0 pre-flight

**Status:** CLOSED-as-record — **archived 2026-09-19 by S-TX's pre-flight PR** ([`DRS_E1_STX.md`](../design/DRS_E1_STX.md) §2.5), the reader §10 was waiting for; owns no open residue (SOK-10 CLOSED by deletion in PR #784, [`SOK_10_PATH_POSITION_RESOLUTION.md`](SOK_10_PATH_POSITION_RESOLUTION.md)). Increment LANDED 2026-09-18 (the §7 commits 1–3 are
code: `store/read.rs` K1/K2/O1/O2, `store/at_index.rs`, layout v6 in
`schema.rs` / `codec/chain.rs` / `codec/undo.rs` / `store/connect.rs`; Q3's
deletion is PR #782). It stayed in `design/` until S-TX's pre-flight had read it
(archive-or-contract per index §8), which it now has. History: **Round 0 (pre-flight)
executed 2026-09-18** at `dev` = `d89f99791` (the tree that merged PR #772,
S-CHAIN-R). **Round 1 RULED 2026-09-18** (maintainer, on PR #779; §9, each
ruling line-local): Q1 **A**, Q2 default, Q4 `OutTx`; **Q3 overridden to B**
— the histogram RPC and its CLI command are deleted now, on privacy grounds,
as their own PR. (The code gate on PR #777 — RTN-7 retyped `store/connect.rs`
and `store/chain_reads.rs`, which §7 commits 1, 2 and 4 edit — **lifted
2026-09-18: #777 merged**, and this document was re-based and re-verified on
that tree, `51d7f2416`; every code anchor re-read.) Implements *from*
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) §3.5/§7 (the S-OUT-KI row:
extraction order **4**, "consensus-critical (double-spend admission) and
needs chain reads for height context, so it follows S-CHAIN-R"), §7.6 (parity
first, the ported partition is transitional, **byte parity was never a
constraint — the comparator projects logical content**), and §11.1(f) (every
value is a named shape); from
[`DRS_E1_SCHAIN_R.md`](DRS_E1_SCHAIN_R.md) (the read handle,
`ReadSnapshot`, and its fault policy — this surface is more reads on it;
SCR-11 routes E2's key-image scan here); from
[`CONSENSUS_STORE_RECONCILIATION.md`](../design/CONSENSUS_STORE_RECONCILIATION.md)
CEN-L1 / CEN-I7 (the two halves of key-image uniqueness, ruled C2-R8 Q6) and
CEN-L6 (amount-0 indexing is **arm C — unspecified**, routed to **R8b-2** and
open); and from [`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md) G11 and the
rules crate's own statement of it (`rust/shekyl-chain-rules/src/view.rs:30`,
"absence is a case, not a `None`" — adopted here for every by-index read;
the class is stated once, with its instances, in
[`CURVE_TREE_STORE_SHAPES.md`](../design/CURVE_TREE_STORE_SHAPES.md) §3.1). Nothing in this document re-opens any of them; §3.4 and SOK-1 *ask*
one of them (R8b-2's neighbour, the physical shape of `output_amounts`)
because this surface is its first reader and cannot be built at LMDB's
complexity on the ported shape.

**Why a separate document.** The S-OUT-KI row is one table line naming seven
`BlockchainDB` methods (histogram **DELETED 2026-09-18**, PR #782; it is not
a ghost name on the DRS §3.5 map). Of the seven, **four** become reads here, one
dissolves into the snapshot handle's own shape (SOK-3), and **two are not
ported** — one has no caller at all, one has no production route (a unit
test is its only caller). The four reads are: **K1** membership
(`has_key_image`, with `has_key_images` folded into it), **K2** the
key-image scan (`for_all_key_images`, the digest's), **O1** the stored
output record (`get_output_key`, from `output_amounts`) and **O2** the
output's origin (`get_output_tx_and_index`, from `output_txs`) — two
independent lookups over one dense index, not one record (§3.2). The
increment's content is the mapping, the absence semantics for a dense index
(§3.3), and one finding that is not a read at all: the shape in which
S-CHAIN-W wrote `output_amounts` makes this surface's point read a scan
(SOK-1, §3.4). Rule 26's pre-flight pass is the instrument; this is the same
shape as `DRS_E1_SCHAIN_R.md` and stays in `docs/design/` while the
increment is open.

**Identifier family.** Findings and questions here are **SOK-n**, registered
in [`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2 by this document's
PR (prefix `SOK` checked distinct against the registry with
`check_index_prefix_uniqueness.py`: `SOK` ≠ `SCR`, `SCW`, `SO-`). One series,
numbered in order of surfacing; a question and the finding that raised it
share a number.

---

## 1. Preconditions, as found at the pin

| Precondition | State at `d89f99791` |
| --- | --- |
| S-CHAIN-R landed (`ReadSnapshot`, the fault policy, `AtHeight` on by-height reads) | **landed** (PR #772, merged 2026-09-17): `rust/shekyl-chain-store/src/store/read.rs`, `chain_reads.rs`. Reads never arm the halt; SI-7 is `InvariantViolated`, plain (`read.rs:25`–`:30`). |
| §11.1(f) value shapes on every table this surface reads | **landed** (PR #772): `spent_keys: LmdbHashKey → Present` (`schema.rs:364`), `output_txs: u64 → Coded<OutTx>` (`:356`), `tx_outputs: u64 → Coded<TxOutputIndices>` (`:353`). **Except one:** `output_amounts` is `MultimapTableDefinition<u64, U64PrefixBytes>` (`:359`) — a *key* type carrying `OutKey` bytes as multimap members, not a value shape. §11.1(f) has no multimap arm; this surface's shape ruling (SOK-1) closes that gap as a side effect. |
| The writes this surface reads | **landed** (PR #757, S-CHAIN-W): `connect` records every vout into `output_txs` (dense `output_id`), `output_amounts` (per-amount `amount_index`, SI-9), `tx_outputs` (`connect.rs:554`–`:622`) and every key image into `spent_keys` (SI-1, `:480`). |
| The validator's half of key-image uniqueness | **landed** (the trait PR #753, E6 increment 1; the `BatchView` impl PR #757, S-CHAIN-W): `ChainView::has_key_image` (`rust/shekyl-chain-rules/src/view.rs:161`), implemented on `BatchView` over `spent_keys` (`rust/shekyl-chain-store/src/store/view.rs:151`–`:161`). CEN-I7 (chain-wide, validator) and CEN-L1 (intra-block, validator) are both on the register; `spent_keys` set-ness is SI-1, a belt, never a verdict (CSR `:171`). |
| The consumer that routed a read here | E2's digest reader: SCR-11 routed the `spent_keys` scan to S-OUT-KI. Digest v0's key-image input is order-insensitive — "`spent_keys` is `n_spent` concatenated 32-byte key images **in any order**" (`rust/shekyl-ffi/src/chain_digest_ffi.rs:29`–`:30`). The C++ oracle feeds it from `for_all_key_images` (`src/blockchain_db/lmdb/logical_state_digest.cpp:73`). |
| The amount-0 indexing question | **open**: R8b-2 (`CONSENSUS_C2_R8_STORE_PLACEMENT.md` §12, archived) — *is amount-0 indexing a consensus-visible fact or a storage index choice?* S-CHAIN-W ported the keying **verbatim** under it (SCW-8) and recorded that as a knowingly-reproduced shape with R8b-2 as its reopener. §3.4 here does not rule R8b-2; it separates the *physical* table shape (this surface's) from the *exposure* question (R8b-2's). |
| In flight, and why it matters | PR #777 (RTN-7, the wire crate's hash surface) edits `store/connect.rs`, `store/chain_reads.rs`, the connect fixtures and tests. §7's code commits wait for it; this document does not touch code. **Substrate re-check 2026-09-18 at `eee838d4d`** (#774, #775, #776 landed after the pin): no code under `rust/` or `src/` changed — every `:line` anchor above holds at `git diff d89f99791..eee838d4d --stat`, docs only. #774 (PDM-Q rulings, the S-PRUNE skeleton) touches this surface's tables in one way, recorded in §3.3. |

---

## 2. Scope

### 2.1 In

Four reads on `ReadSnapshot`, one layout correction the reads require, and
the deletions the correction makes dead.

**A. Key images (K1, K2).** `has_key_image(&KeyImage) -> Result<bool, StoreError>`
— `spent_keys` membership on the committed snapshot, **one body** shared
with `BatchView`'s `ChainView::has_key_image` (the `chain_reads` pattern,
SCR-13: same classification, different fault arm). `key_images()` — an
iterator over every recorded key image, for E2's digest and nothing else
named yet; yields in `LmdbHashKey` order because that is the table's order,
and no consumer may depend on it (the digest does not).

**B. Outputs (O1, O2).** `output(GlobalOutputIndex) -> Result<AtIndex<RecordedOutput>, StoreError>`
— the stored record: one-time pubkey, commitment, recording height, unlock
time. `output_origin(GlobalOutputIndex) -> Result<AtIndex<OutTx>, StoreError>`
— which transaction and which vout produced it (`OutTx` as it exists, SOK-Q4). `AtIndex<T>` is the dense
index's absence type (§3.3).

**C. `output_amounts` becomes a keyed table (SOK-1, SOK-Q1 default).**
`TableDefinition<(u64, u64), Coded<OutKey>>` keyed `(amount, amount_index)`,
replacing the multimap; `OutKey` drops the `amount_index` field its key now
carries; **`SCHEMA_VERSION 5 → 6`**, one layout commit. Same logical content
as LMDB's `DUPSORT` table — the pair `(amount, amount_index) → record` — in
the shape redb can seek in. `next_output_slot` mints the `(bucket, output_id)`
slot or refuses: both ends of the table must carry the bucket's amount
before `len` is trusted as the bucket's cardinality, and the next index
must equal `output_id` (SOK-Q2 / SOK-2). A hole compensated by a
foreign-bucket row would otherwise sum to the right length. `check_redb_schema_key_types.py` parses the tuple
key and accepts a `compare_uint64` `DUPSORT` table as either `u64` (a
zerokval collapse) or `(u64, u64)` (a genuine `DUPSORT` as a key); its
multimap value rule is gone with the multimap. The gate asserts ordering,
and a tuple key orders `amount` numerically then `amount_index` numerically,
which is `MDB_INTEGERKEY` then `compare_uint64`.

**D. Deletions the correction leaves dead (rule 15), in the same commit as C.**
`U64PrefixBytes` (`lmdb_order/u64_prefix.rs`, one consumer) and its
`Restorable` (`store/undo.rs:93`); `OutKey::amount_index_of`
(`codec/chain.rs:240`); `UndoEntry::MultiInserted` (`codec/undo.rs:88`), the
`SetTable` that constructs it (`store/set.rs`, re-exported at
`store/mod.rs:112`), `WriteBatch::open_multimap_table` (`write.rs:361`) that
returns it, `impl UndoTarget for MultimapTableDefinition` (`store/undo.rs:275`)
and `ReadSnapshot::open_multimap_table` — after C the catalogue has **no
multimap**, so none of it has a caller. They go together because they do not
compile apart (§7 commit 2). **Added, same commit:** `impl Restorable for
(u64, u64)` — the tuple key needs one to pass `open_insert_table`'s
`K: Key + Restorable` bound (`write.rs:291`–`:293`).

**E. Docs:** this document; DRS §7 S-OUT-KI row; §7.6's "`output_amounts`
keyed verbatim with R8b-2 open" gets its dated UPDATE; `STORE_INVARIANT_REGISTER.md`
SI-9 cell; `LMDB_SCHEMA.md`'s redb-mapping note if it names the multimap;
`DRS_E1_SCHAIN_R.md` archived (§2.4); index rows; CHANGELOG one line.

### 2.2 Out (named, so it is not scope shed by omission)

- **Ruling R8b-2.** Whether `amount_index` is a consensus-visible fact is a
  spec question routed to R8b (CEN-L6, C2-R8 Q6). SOK-Q1's default keeps the
  `amount` dimension in the key *because* R8b-2 is open; arm B (§9) collapses
  it and is available only once R8b-2 is ruled. The Rust read API takes a
  `GlobalOutputIndex` and reads bucket `0` (§3.4) — that is the C++'s own
  posture (`db_lmdb.cpp:3746`–`:3747` throws on `amount != 0`), not a ruling.
- **`for_all_outputs`** (both overloads) — ported as nothing (SOK-4).
- **`get_output_distribution`** — ported as nothing (SOK-5; extends SCR-2).
- **`get_output_histogram`** — **DELETED 2026-09-18** by PR #782 (SOK-6;
  SOK-Q3 ruled B), not by this increment. The S-OUT-KI vocabulary is seven
  methods from there. The name does **not** stay on the DRS §3.5 row:
  unlike SCW-2/SCR-2, the C++ method is gone from `blockchain.cpp`, so the
  map must drop it or `check_drs_c_surface_map.py` is a lie.
- **The pool's half of double-spend detection** (`tx_memory_pool::have_tx_keyimg_as_spent`,
  `src/cryptonote_core/tx_pool.cpp:1711`) — S-POOL's. K1 is the chain half
  only; the RPC that unions them (`is_key_image_spent`,
  `src/rpc/rpc_facts_ffi.cpp:915`) is a cutover-time consumer.
- **`get_tx_unlock_time`, `get_tx_block_height`** — S-TX's, even though the
  histogram's `unlocked` walk called them; the histogram is **DELETED**.
- **Any daemon wiring.** The daemon serves LMDB at this pin; the path
  builder's `read_output_oc` callback (`curve_tree_path.cpp:67` at `8494f2a27` —
  deleted 2026-09-18 with the RPC, `SOK-10` Q7 → A) and the two key-image
  RPC/verdict readers switch to `ReadSnapshot` at cutover, not here.
- **S-TX, S-CURVE**: the next surfaces in DRS §7's order. Named so a read
  this increment finds convenient (a tx blob, a leaf) is not smuggled in.

### 2.3 What DRS-E2 gets from this increment

The second of the three digest-v0 inputs (SCR-11): every block hash in
height order came with S-CHAIN-R (`block_infos`), the curve-tree root is
S-CURVE's, and the key-image set is K2. After this increment E2's redb-side
`logical_state_digest_v0` is one read away from complete. E2's per-table
comparator also gets its first projection of an LMDB `DUPSORT` table onto a
keyed redb table (§3.4) — the case DRS §7.6 said the comparator "was always
going to" handle, now with a concrete instance.

### 2.4 What this pre-flight closes

`DRS_E1_SCHAIN_R.md` §10 held itself in `docs/design/` "until S-OUT-KI's
pre-flight has read it". It has been read (§1, §3.1, §3.3 build on it). It
owns no open residue — FL-R3-STORE's consumer half is a `FOLLOWUPS.md` row,
the reads are code, its docs are landed — so it is a finished plan and
archives to `docs/completed/` in this PR (index §8, own commit, inbound
links rewritten). The S-CHAIN-W precedent: archived by the S-CHAIN-R PR.

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the reads live

On `ReadSnapshot`, beside S-CHAIN-R's nine (`store/read.rs`), with the
shared-body pattern S-CHAIN-R set: a read whose classification `BatchView`
also needs lives once in `chain_reads.rs` and is projected twice (the
snapshot returns SI-7 plain; the batch poisons). K1 is exactly that case —
`BatchView::has_key_image` exists (`view.rs:151`) and becomes the second
caller of one body. O1/O2 have no batch-side caller at HEAD (the validator
does not look outputs up by index — FCMP++ has no ring members to fetch)
and live on the snapshot only; they move to `chain_reads` the day a rule
wants them, not before (rule 21: no pre-provisioned second arm).

### 3.2 The mapping — 7 live methods + 1 DELETED, 4 reads

| C++ (`BlockchainDB`) | Live callers at HEAD | Rust read | Notes |
| --- | --- | --- | --- |
| `has_key_image` | `Blockchain::have_tx_keyimg_as_spent` (`blockchain.cpp:254`) ← CEN-I7's per-input check (`:3366`, `:3502`, `:3526`, `:3555`), the pool's chain half (`tx_pool.cpp:1711`), the submit verdict (`daemon_submit_ffi.cpp:126`); the block-level double-spend visitor (`blockchain.cpp:3097`) | **K1** `has_key_image(&KeyImage) -> Result<bool>` | Shared body with `BatchView` (SCR-13 shape). The C++ warns in prose that this read takes no lock and must not be paired with another (`blockchain.cpp:250`–`:253`); the snapshot is the lock. |
| `has_key_images` | `have_tx_keyimges_as_spent` (`:3380`) ← `is_key_image_spent` RPC (`rpc_facts_ffi.cpp:915`) | **dissolves into K1** (SOK-3) | The batch form exists to hold one `rtxn` across N keys (`db_lmdb.cpp:3851`–`:3869`). A `ReadSnapshot` *is* one transaction; N calls to K1 on it are the batch. |
| `for_all_key_images` | the digest oracle (`logical_state_digest.cpp:73`) | **K2** `key_images() -> impl Iterator<Item = Result<KeyImage, StoreError>>` | Order is the table's (`LmdbHashKey`); the one consumer is order-insensitive. |
| `get_output_key` (single, `db_lmdb.cpp:3728`; batch `:4460`) | `Blockchain::get_output_key` (`blockchain.cpp:2616`) — **no caller**; the path builder reads the DB directly, `db.get_output_key(0, pos)` (`curve_tree_path.cpp:67`; SOK-10); `BlockchainLMDB::prune_tx_data`'s stripe walk (`db_lmdb.cpp:10189`, reached from `Blockchain::{prune_blockchain, update_blockchain_pruning}` `:6221`, `:6232`) — **dies with the stripe engine** (`PDM-Q7`, S-PRUNE), so it is a current caller with no redb successor; `blockchain_utilities` (LMDB tools, die with LMDB) | **O1** `output(GlobalOutputIndex) -> Result<AtIndex<RecordedOutput>>` | `RecordedOutput { pubkey: OneTimePubkey, commitment: CommitmentBytes, height: BlockHeight, unlock_time: Timelock }` — `OutKey` minus the ids. The batch form (`allow_partial`) dissolves like SOK-3: the caller loops on one snapshot and stops at the first `BeyondCount`. |
| `get_output_tx_and_index` (amount-specific: single `:3778`, batch `:4506`, both composing `output_amounts[(amount, index)].output_id` → `output_txs`) and `get_output_tx_and_index_from_global` (`:3755`, reading `output_txs[output_id]` directly — **not** in the S-OUT-KI vocabulary, `blockchain.cpp` never calls it; the LMDB body's own helper) | `get_output_key_mask_unlocked` (`blockchain.cpp:2623`–`:2631`) — **no caller**; the histogram's `unlocked` walk (deleted with it, SOK-Q3) — not ported | **O2** `output_origin(GlobalOutputIndex) -> Result<AtIndex<OutTx>>` | **Index domain, stated so the implementation cannot pick the wrong one (PR #779 review):** O2 takes a *global* index and is the `_from_global` read — `output_txs[output_id]`, one lookup. It is **not** the amount-specific composition; that path (`(0, i)` → `OutKey.output_id` → `output_txs`) equals the direct read only by SOK-2's belt, and a read that depends on a belt to be right is the wrong read. `OutTx { tx_hash: TxHash, local_index: OutputIndexInTx }` as it exists (`codec/chain.rs:187`–`:192`; SOK-Q4). Kept although its `blockchain.cpp` callers are dead: E2's comparator projects `output_txs` through it, and O1(i).`output_id` vs O2(i) is how SOK-2's belt is checked from the read side. |
| `for_all_outputs` ×2 (`:4028`, `:4063`) | **none** — `Blockchain::for_all_outputs` (`blockchain.cpp:7029`, `:7034`) has no caller in `src/` or `tests/` | **not ported** (SOK-4) | Zero consumers at HEAD; the row keeps the names. |
| `get_output_distribution` (`:4542`) | `Blockchain::get_output_distribution` (`blockchain.cpp:2633`) ← `core::get_output_distribution` ← `RpcHandler::get_output_distribution` (`src/rpc/rpc_handler.cpp:29`) — **no RPC route**: `core_rpc_server.cpp` has no `on_get_output_distribution`; the only caller is `tests/unit_tests/output_distribution.cpp:92` | **not ported** (SOK-5) | SCR-2 found the `amount == 0` arm's helper dead; this confirms the whole method is. Its `m_nettype != FAKECHAIN` branch (`blockchain.cpp:2636`) — a rule-71 divergence — dies with it. |
| `get_output_histogram` | **DELETED 2026-09-18** by PR #782 (SOK-Q3 B) — was a live RPC + `shekyld` CLI `output_histogram` + store chain; `CORE_RPC_VERSION` 3.33; the name is refused in RK-8 so it is not re-minted (rule 23). Not in the DRS §3.5 vocabulary (7 methods). The regtest `get_output_histogram_stays_unrouted` pins `Method not found` on both listeners. | **not ported** (SOK-6) | Monero decoy-selection tooling: per-amount output counts with `unlocked` / `recent_cutoff` walks. FCMP++ selects no decoys (rule 60; census U-7). |

### 3.3 Absence, faults, and what a read may not do

S-CHAIN-R's policy (`read.rs:16`–`:35`) holds unchanged: every decode is
SI-7, a read never arms the halt, by-hash reads return `Option`. This surface
adds one absence shape.

**By-index reads return `AtIndex<T>`, not `Option`.** Output ids are dense
(SI-9: `output_id` is `output_txs`'s entry count at write time), so the only
absence a snapshot can report is *at or beyond the count* — the same
structure as heights above the tip. `AtIndex<T> { Recorded(T), BeyondCount }`,
matched exhaustively, no `Option` conversion, no `?` — `AtHeight`'s
discipline (`CHAIN_RULES_CRATE.md` G11) at a second dense index. **Bound
first:** the count (`output_txs.len()`, the primary `output_id` is dense in)
is read before any row, so a stray row at or beyond it is never served as
`Recorded` (#783 review). A row missing *below* the count is not absence:
it is SI-9's hole, `InvariantViolated(IdNotFresh)` — the count and the keys
disagree — as a `block_info` hole below the tip is SI-7. And a row whose
record carries an `output_id` other than its slot's index is the same SI-9:
O1 validates the join where it decodes, because a raw or corrupt file can
hold what `connect` refuses to write, and serving it would hand out the
wrong output under a global index.
`CURVE_TREE_STORE_SHAPES.md` §3.1 is the class statement; this is its
fourth application, and the counter-rule there applies too — `has_key_image`
returns `bool`, because "not spent" is a value inside the type's range with
no arm that differs.

**The dense model and S-PRUNE (checked against #774).** `PDM-Q1` grades
`output_txs` / `output_amounts` **CACHE** — a pure function of the retained
base, rebuilt by replay (`ARCHIVAL_PRUNED_DAEMON_MODE.md` §9.2) — and
`spent_keys` **KEEP-C**, never prunable at any depth. `PDM-Q2`'s discard
predicate removes a shard's *prunable regions and `pqc_auths`* and nothing
else; no ruling discards a CACHE row, and the class definition says a CACHE
discard "is a performance choice, never scarcity" that no one has chosen.
So at this pin a row missing below the count is corruption, as stated. **If
a later S-PRUNE ruling elects to discard CACHE rows below `W`**, that
discard is shard-atomic by Q2's shape and `BeyondCount` is not its word:
the absence would need its own arm (`Discarded`, say), decided by that
ruling, not by this surface guessing — reopen there; falsify by
`DRS_E1_SPRUNE.md` naming `output_amounts` or `output_txs` in a discard
set.

**Key-image membership is exact, never approximate.** K1 reads the table;
no bloom filter, no cache, no "probably". The C++ has none either; stated so
nobody adds one for the pool's benefit on this side of the boundary.

### 3.4 `output_amounts` — the shape this surface cannot be built on (SOK-1)

S-CHAIN-W wrote `output_amounts` as `MultimapTableDefinition<u64, U64PrefixBytes>`
(`schema.rs:359`): key `amount`, members the `OutKey` bytes ordered by their
`amount_index` prefix (`lmdb_order/u64_prefix.rs`). That is LMDB's `DUPSORT`
table reproduced member-for-member, chosen under SCW-8 as parity-first with
R8b-2 open. It was the right choice for a **writer**: `connect` only appends
at the high end and needs an O(1) end-peek (`connect.rs:584`–`:598`), which a
multimap gives it.

This surface is the table's first **reader**, and it reads by index:
`get_output_key(amount, index)` is `mdb_cursor_get(…, MDB_GET_BOTH)`
(`db_lmdb.cpp:3738`) — a B-tree seek to one member among the duplicates,
O(log n). redb has no equivalent. `ReadOnlyMultimapTable::get(key)` returns
`MultimapValue`, a forward/backward **iterator** over every member under the
key (redb 4.1.0, `src/multimap_table.rs`: `get` at line 1558, the `Iterator`
and `DoubleEndedIterator` impls at 846 and 865 — verified at source in the
registry, rule 17); there is no seek into a key's value set. On the ported shape, O1
for output *i* is a scan of `i` members of the amount-0 bucket — **every
output on the chain** lives in that bucket — and the path builder calls it
once per leaf it needs (`curve_tree_path.cpp:67`). LMDB's O(log n) point read
would become O(n) at cutover. That is not a performance preference; it is
the surface being unimplementable at the complexity the C++ has.

**The correction (SOK-Q1 default, arm A).** The pair LMDB keys by is
`(amount, amount_index)`; redb keys by tuples natively (redb 4.1.0,
`src/tuple_types.rs`, the `Key for (T0, …, Tn)` impl at line 263 —
lexicographic over the components' own orders). So:

```rust
pub const OUTPUT_AMOUNTS: TableDefinition<(u64, u64), Coded<OutKey>> =
    TableDefinition::new("output_amounts");
```

- **Same logical content.** Every LMDB `(amount ⇉ member)` is one
  `(amount, amount_index) → OutKey` row. E2's comparator projects both to
  the same pairs — DRS §7.6 says in so many words that the comparator
  compares "logical content through per-table projections" and that
  `schema.rs` "already diverges structurally from LMDB" on the zerokval
  tables; this is the same move on the one `DUPSORT` table that had not yet
  made it.
- **Same ordering.** `u64` then `u64`, numeric: `MDB_INTEGERKEY` on `amount`,
  `compare_uint64` on `amount_index`. `check_redb_schema_key_types.py`
  extends its `DUPSORT` rule to accept the tuple form and its key regex to
  parse a tuple (`[^,]+?` cannot; the value regex had the same widening in
  PR #772).
- **O(log n) point reads and range scans**: `get(&(0, i))`; a bucket is
  `range((a, 0)..=(a, u64::MAX))`; `next_amount_index` is that range's
  `next_back()` plus one.
- **§11.1(f) closes.** The table's value becomes `Coded<OutKey>` like every
  other; `U64PrefixBytes` — a `Key` type standing in for a value shape — is
  deleted, and the catalogue has no multimap, so the journal's
  `MultiInserted` arm and the multimap `UndoTarget` go with it (§2.1 D).
- **`OutKey` drops `amount_index`.** The key carries it; a field that
  duplicates its own key is the accretion `CURVE_TREE_STORE_SHAPES.md`
  CTS-2 names. `output_id` stays in the value — it is the join to
  `output_txs`, not the key.
- **R8b-2 is untouched, and the amount dimension is carried, not chosen.**
  Arm A records the same facts LMDB does, including the amount dimension;
  whether `amount_index` is *exposed* as a consensus fact is exactly as open
  after this as before. What changes is that the question can now be
  answered by a projection, not by a table rewrite. Said plainly for the
  next reader, who will find a two-part key whose first component is always
  `0`: that is **not a design** — it is parity with R8b-2 open, carried
  until R8b-2 is ruled on a consensus reason of its own (Q1's ruling).

**What the Rust read exposes.** `output(idx)` reads `(0, idx)`. Shekyl has
one bucket: every coinbase and emission vout is stored under `0` with its
ct-base commitment and every other vout under its own amount, which CEN-H14
makes `0` (`connect.rs:62`–`:66`); the C++ refuses any other amount
(`db_lmdb.cpp:3746`–`:3747`). The API does not take an `amount` because there
is nothing a caller could pass but `0` — and *not* because R8b-2 is
prejudged: if R8b-2 rules the dimension consensus-visible, the read grows a
parameter and the table needs no change (rule 21 reopening: R8b-2 ruled).

**The two counters that coincide, and the third that does not (SOK-2,
SOK-10 — corrected on PR #779 review).** With one bucket, two dense
counters are equal for every output: `output_id` (`output_txs`' count) and
`amount_index` under `0` (the bucket's count). `CT2_DRAIN_ORDER.md` §"What
'global index' the wallet sees" already records the equality as the fact
the wallet relies on; nothing in the store asserts it — it is true by
construction of two separate `last + 1` counters that advance together. The
increment adds the belt: after every `connect`, the amount-0 bucket's last
index equals `output_txs`' last id (SI-9 restated, SOK-Q2).

The curve-tree **leaf position is not a third member of that equality.**
`OutputIndex` is not `TreePosition`: leaves drain in `(maturity, gindex)`
order, coinbase leaves defer sixty blocks, and the LMDB store keeps
`output_to_leaf` / `leaf_to_output` for exactly that reason
(`CT2_DRAIN_ORDER.md:85`; `blockchain_db.h:2670`, `get_leaf_output_index`).
The first draft of this section asserted the three-way equality and
proposed a test for it; the review refuted the premise at source, and
reading the call chain found the defect the wrong premise had been
covering: the path builder's `read_output_oc` callback passes a **tree
position** straight to `get_output_key(0, pos)` (`curve_tree_path.cpp:67`;
`fcmp/src/rpc_path.rs:85`–`:89` (at `8494f2a27`; deleted since) calls `output_oc(pos)` with the
same `pos` it hands `leaf(pos)`), never resolving it through
`get_leaf_output_index`. The pre-extraction C++ did the same
(`get_output_key(0, i)`, commit `f2df035e7`), so the Rust assembler
inherited the contract. For any chunk whose leaf order differs from gindex
order, `chunk_outputs` carries the wrong `(O, I, C)` for those leaves, the
prover rebuilds the wrong siblings (`proof.rs:377`–`:385`), and the proof
**fails verification** — fail-closed, so not a soundness hole, but a live
liveness defect that no current test reaches (a coinbase-only chain drains
in gindex order). **This is SOK-10, and it is not this surface's to fix**
(rule 22: named, routed, disclosed): the fix is Rust, in the assembler's
contract — `PathStore` resolves position → `GlobalOutputIndex` (a
`leaf_to_output` read, S-CURVE's on redb; `get_leaf_output_index` on LMDB
today) before `output_oc` — owned by the path-FFI lane (PDM-Q-F9's).
`FOLLOWUPS.md` row with the falsifier: a chain in which a normal-tx output
drains before an earlier coinbase's leaf, asserting `chunk_outputs[j]` is
the output whose leaf sits at position `j`. What this surface owes it is
already in the design: O1 takes a `GlobalOutputIndex`, so a caller cannot
hand it a position without a named conversion, which is the shape that
makes SOK-10 unrepresentable once the resolver exists.

**UPDATE 2026-09-18 — SOK-10 closed by deletion, not by fix (`SOK-Q7` → A,
RULED by the maintainer; [`SOK_10_PATH_POSITION_RESOLUTION.md`](../completed/SOK_10_PATH_POSITION_RESOLUTION.md)).**
The path-FFI lane found the endpoint spend-revealing under a binding ruling
(`PHASE_2A_SEND_PATH.md` §3.0.1), consumer-less on every repo, and wrong on
every chain carrying a transaction (coinbase `+60` vs tx `+10` inverts the
orders in the first block with a transaction). `rpc_path.rs`,
`curve_tree_path.cpp` and `get_curve_tree_path` are deleted (RPC 3.34). No
resolver is built. Consequence for this surface: SOK-7's "the Rust read is
shaped for the live consumer" has lost that consumer (`curve_tree_path.cpp:67`
no longer exists); O1's pubkey-and-commitment shape is still the record's
logical content, but its stated reason is gone — this lane decides whether
the row's note is re-grounded. Disclosed here by the path-FFI lane (rule 94 §6).

### 3.5 Types this increment adds to the store crate

- `AtIndex<T>` — dense-index absence (§3.3). `#[must_use]`, exhaustive, no
  `Option`/`?` conversion; the `compile_fail` doctests `AtHeight` carries
  (`view.rs:50`–`:57`), duplicated for the second type rather than
  generalised (rule 21: two instances is not yet a pattern worth an
  abstraction; the third caller generalises).
- `RecordedOutput` — `OutKey` projected without its join key (§3.2), the
  join **validated** against the slot where the record is decoded so the
  projection can leave it out honestly. Not `Canonical`: a read projection,
  never stored. Lives in `store/output_reads.rs`, the output tables' shared
  read body (the sibling of `chain_reads.rs`).
- `OutputSlot` — the `output_amounts` key as a type: bucket (an
  `AtomicUnits`) and dense position (an `AmountIndex`), with
  `CONFIDENTIAL_AMOUNT`, `confidential(GlobalOutputIndex)`, `key()`,
  `from_key()`, `bucket()` (the bound that keeps the tuple order here;
  not the SI-9 end-peek), fields private so the tuple is assembled in
  one place and the one-bucket premise is code (`ids.rs`).
- O2 returns `OutTx` as it exists — no `OutputOrigin` twin (SOK-Q4, ruled).

### 3.6 What this surface inherits, and for how long

The tables §4 lists are Monero's partition; DRS §7.6 makes that transitional
and names what is pinned (consensus-visible encodings) and what is not (the
layout). This increment reproduces the partition's *logical* content and
corrects one *physical* shape the partition cannot serve (§3.4) — inside
§7.6's own statement that byte parity was never the constraint. Anything it
reproduces knowingly is in §6.1.

---

## 4. The read set, table by table

| Table | Key → value (after §3.4) | Read | Absence | Written by |
| --- | --- | --- | --- | --- |
| `spent_keys` | `LmdbHashKey → Present` | K1 membership; K2 scan | none — a set | `connect` (SI-1) |
| `output_amounts` | `(u64, u64) → Coded<OutKey>` | O1 `get(OutputSlot::confidential(i).key())`, bound first against `output_txs.len()` | `BeyondCount` for `i ≥ count`, no row read; a hole below `count` is SI-9; a record whose `output_id ≠ i` is SI-9 (join validated) | `connect` (SI-9) |
| `output_txs` | `u64 → Coded<OutTx>` | O2 `get(output_id)`, bound first against `len()` | `BeyondCount` for `output_id ≥ len`, no row read; a hole below `len` is SI-9 | `connect` (SI-9) |
| `tx_outputs` | `u64 → Coded<TxOutputIndices>` | **not read here** — S-TX's `get_tx_amount_output_indices` | — | `connect` |

---

## 5. Store invariants this increment builds or restates

- **SI-1** (`spent_keys` is a set) — read side: K1 is membership on the
  table SI-1 guards; nothing to add.
- **SI-9** (dense ids) — restated for a unique-key `output_amounts`
  (SOK-Q2): duplicates are unrepresentable by the key; density per bucket is
  `last + 1 == count`, where `count` is exact for the whole table when one
  bucket exists — and a *second* bucket appearing at `connect` is itself the
  belt firing: `connect` stores every miner and emission vout under `0`
  regardless of its loud amount (`connect.rs:584`–`:598`; CEN-H14 *permits*
  those), so a second bucket can only mean a **non-miner, non-emission** vout
  with a non-zero amount reached the store — the case CEN-H14 forbids — and
  the validator admitted it (`StoreInvariantViolated`, never a verdict; the
  validator has the bug). The SOK-2 coincidence (`output_id ==
  amount_index` under `0`) joins the row; the leaf position does not (SOK-10).
- **SI-7** — every decode strict, unchanged.

---

## 6. Round-0 findings

| # | Finding (at `d89f99791`) | Disposition |
| --- | --- | --- |
| **SOK-1** | `output_amounts` is a redb multimap whose only lookup is a full iteration of the key's members (redb 4.1.0 has no seek within `MultimapValue`); `get_output_key`'s `MDB_GET_BOTH` seek has no O(log n) equivalent on it. First reader finds the writer's shape unservable. | Keyed tuple table, `SCHEMA_VERSION 5 → 6` (§3.4, SOK-Q1). |
| **SOK-2** | Two dense counters coincide by construction and nothing asserts it: `output_id` and amount-0 `amount_index` (`CT2_DRAIN_ORDER.md` records the equality as the wallet's assumption). *Corrected on #779 review:* the first draft counted the leaf position as a third; it is not (SOK-10). | Belt on SI-9 (§3.4, SOK-Q2). |
| **SOK-10** | **(PR #779 review; defect, not this surface's.)** The path builder's `read_output_oc` passes a **tree position** to `get_output_key(0, pos)` (`curve_tree_path.cpp:67`; `rpc_path.rs:85`–`:89`) without `get_leaf_output_index`; leaf order ≠ gindex order (`CT2_DRAIN_ORDER.md:85`), so a reordered chunk yields wrong `chunk_outputs`, wrong rebuilt siblings, a proof that fails verification. Inherited from the pre-extraction C++ (`f2df035e7`). Fail-closed; no current test reaches it. | **CLOSED 2026-09-18 by deletion** (`SOK-Q7` → A, path-FFI lane): the endpoint and its assembler are removed (RPC 3.34) — spend-revealing (`PHASE_2A` §3.0.1), consumer-less, wrong on every real chain. FOLLOWUPS row removed. O1's `GlobalOutputIndex` parameter still makes the confusion unrepresentable at the store. Record: [`SOK_10_PATH_POSITION_RESOLUTION.md`](../completed/SOK_10_PATH_POSITION_RESOLUTION.md). |
| **SOK-3** | `has_key_images` and the batch `get_output_key` / `get_output_tx_and_index` exist to hold one LMDB `rtxn` across N lookups. `ReadSnapshot` is that transaction. | Dissolve into K1 / O1 / O2 on one snapshot; no batch API. |
| **SOK-4** | `Blockchain::for_all_outputs` (two overloads) has no caller in `src/` or `tests/`. | Not ported. |
| **SOK-5** | `get_output_distribution` has no RPC route (`core_rpc_server.cpp` has no handler; `RpcHandler::get_output_distribution` is reached only from `tests/unit_tests/output_distribution.cpp:92`). Extends SCR-2 from "the `amount == 0` helper is dead" to "the method is". Carries a rule-71 nettype branch (`blockchain.cpp:2636`). | Not ported; branch dies with it. |
| **SOK-6** | **DELETED 2026-09-18.** At `d89f99791` `get_output_histogram` was a live RPC serving Monero decoy selection; census U-7 flagged it 2026-07 as a deletion candidate under RT-9's precedent. Two in-tree clients at that pin: the `shekyld` CLI command `output_histogram` (`rpc_command_executor.cpp:1204`–`:1226`) — the same decoy tooling, one layer up — and a regtest whose assertion was that the restricted listener refuses it. | Not ported; **SOK-Q3 RULED B — LANDED**: the RPC, its CLI command and the callerless store chain deleted by PR #782 (privacy grounds — a disclosure surface with no consumer); `CORE_RPC_VERSION` 3.33; the regtest pins `Method not found` on both listeners. |
| **SOK-7** | `Blockchain::get_output_key` and `get_output_key_mask_unlocked` (`blockchain.cpp:2616`–`:2631`) have no callers; the live consumer of the underlying DB read bypasses `Blockchain` (`curve_tree_path.cpp:67`). | Note only — C++ dies at cutover; the Rust read is shaped for the live consumer (O1 returns pubkey **and** commitment). |
| **SOK-8** | `output_amounts` is the one table §11.1(f) left without a value shape: `U64PrefixBytes` is a `Key` type carrying `OutKey` bytes. | Closed by SOK-1 (`Coded<OutKey>`). |
| **SOK-9** | `has_key_images` initialises its result to `true` (`db_lmdb.cpp:3856`) before overwriting every element — harmless, but the fail-open default is the shape §3.1 of the curve-tree plan names. | Dissolved with SOK-3; noted so it is not re-created. |

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

| Reproduced | Where | Ratified state | Why reproduced now |
| --- | --- | --- | --- |
| **The `amount` dimension of `output_amounts`.** Every output on a valid chain is under `0`; the key still carries `amount`. | `schema.rs` `OUTPUT_AMOUNTS` key `(u64, u64)`; SCW-8's inline note on `OutKey` | R8b-2 open: the ratified state is *unspecified*. Arm A records what LMDB records so the comparator projects 1:1; arm B (drop the dimension) is available the day R8b-2 rules it a storage choice. | A shape cannot drop a dimension whose consensus-visibility is an open spec question; the port carries it and names the reopener. |

SOK-1 is **corrected-at-port**, not reproduced: the C++ behaviour (O(log n)
seek) and the Rust behaviour (O(log n) `get`) are the same; only the ported
intermediate (O(n) scan) was wrong, and it never ships.

---

## 7. Commit sequence (rule 90; one PR, ≤ 5 commits, cut from `dev` after this document merges; the #777 gate has lifted)

1. `store: ReadSnapshot::has_key_image + key_images — spent_keys membership shared with BatchView` — K1, K2; the shared body moves to `chain_reads.rs` (SCR-13 shape); tests: membership on a connected chain, the scan equals the connected set, the snapshot sees one state across a concurrent connect. No layout change.
2. `store: layout v6 — output_amounts is a keyed (amount, amount_index) table; the multimap machinery goes with it; SCHEMA_VERSION 5 → 6` — **the one layout commit, and it is one unit** (PR #779 review, round 3): the multimap's deletions cannot follow in a later commit because they do not compile apart. `UndoEntry::MultiInserted` is constructed by `SetTable` (`store/set.rs:68`), which `WriteBatch::open_multimap_table` returns (`write.rs:364`) and `store/mod.rs:112` re-exports; deleting the variant (a codec change, so it rides the bump) deletes its constructor, its opener, the multimap `UndoTarget` (`undo.rs:275`), `U64PrefixBytes` and its `Restorable` (`undo.rs:93`), and `ReadSnapshot::open_multimap_table` — in this commit. In the same commit: `impl Restorable for (u64, u64)` (well-formed iff 16 bytes) — `open_insert_table` requires `K: Key + Restorable` (`write.rs:291`–`:293`) and no tuple has one today, so without it `connect`'s write does not compile; `schema.rs`, `OutKey` minus its prefix, `connect`'s output write and `next_amount_index` as the bucket's last key plus one behind a checked single-bucket premise (first and last keys carry the bucket's amount — as landed after #783 review; the plan had said a bare `range(..).next_back()`), SI-9 restated (SOK-Q2), `check_redb_schema_key_types.py`'s tuple rule, snapshots re-pinned, the `SCHEMA_VERSION` history entry; and every test the shape names (§8's list) rewritten against the keyed table — no assertion weakened, each names what it now pins. The one opener caller that is **not** an `OUTPUT_AMOUNTS` site, `store_tests.rs:449`–`:453` (the `properties` `IMPOSTOR` multimap, the only leg proving the typed-properties refusal is **by name, not by type**), is kept as a keyed impostor (`TableDefinition<&str, &[u8]>::new("properties")` through `open_insert_table`). `rg 'MultimapTableDefinition|SetTable|U64PrefixBytes|open_multimap_table' rust/shekyl-chain-store/src` returning nothing is the commit's exit check.
3. `store: ReadSnapshot::output / output_origin — AtIndex, RecordedOutput` — O1, O2, `AtIndex<T>` with its `compile_fail` doctests, the SOK-2 two-counter test, `BeyondCount` at the count and SI-9 on a planted hole.
4. `store: DRS §7 row, SI-9 cell, §7.6 UPDATE, index, CHANGELOG` — §10.
5. (`docs`, if not folded into 4) `DAEMON_RPC_KV_CUTOVER.md` row for `get_output_histogram` per SOK-Q3's ruling.

Commit 2 is the one a reviewer reads line by line — a layout change and
the deletions it forces, reviewable as one because they are one; 1 and 3
are reads in the S-CHAIN-R shape.

---

## 8. Denominator — what must stay green, what must be extended

- `cargo test -p shekyl-chain-store` — S-CHAIN-W's connect/pop/undo tests are the writer-side denominator for commit 2; every literal that names `output_amounts`' shape (`connect_tests.rs:210`, `:334`, `:554`, `:597`; `undo_tests.rs:52`, `:135`, `:190`, `:244`, `:255`) changes with it and is listed here so the diff is checked against a list, not discovered. Commit 2's opener deletion has one more caller, the `IMPOSTOR` leg at `store_tests.rs:452` — re-shaped to a keyed impostor, not removed (commit 2). `rg 'MultimapTableDefinition|SetTable|U64PrefixBytes|open_multimap_table' rust/shekyl-chain-store/src` returning anything after commit 2 is the check; `SetTable`'s own tests (`store/set.rs`, if any beside `undo_tests`) go with it.
- `scripts/ci/check_redb_schema_key_types.py` — **extended** (tuple key parse; the INTEGERKEY + `compare_uint64` dupsort rule decided by the table's `mdb_cursor_put` key argument: zerokval puts → exactly `u64`, a real key with `MDB_APPENDDUP` → exactly `(u64, u64)`, #783 review round 2); its `--selftest` gains the tuple parse, the three put shapes and the unclassified case; its floor moves 30 → 29 because the one multimap value rule retired with the multimap (the table fires one key constraint where it fired a key and a member rule).
- `check_redb_schema_coverage.py` (bijection) — unchanged; the table keeps its name.
- The codec snapshot gate — `OutKey` and `UndoLog` fixtures change; the bump in commit 2 is what §11.1(b) demands.
- `check_drs_c_surface_map.py` — the S-OUT-KI row names the seven remaining methods (histogram deleted, not a ghost name).
- **Extended:** K1/K2 tests (commit 1); the SOK-2 two-counter test, `BeyondCount`, planted-hole SI-9, `AtIndex` `compile_fail` (commit 4); a `range`-based bucket read asserting O(log n) *shape* (a `get`, not an iteration — pinned by the code, not timed).
- Docs gates: links, code citations, claims, index prefix/table shape, banners, landed-row stamps, surface map.

---

## 9. Round-1 questions — RULED 2026-09-18 (maintainer, PR #779; each row carries its ruling)

| Q | Question | Default → **Ruling** | Why it is a question |
| --- | --- | --- | --- |
| **SOK-Q1** | What shape does `output_amounts` take? **A** — keyed `(amount, amount_index) → Coded<OutKey>`; **B** — collapse into one `outputs: u64 → Coded<Output>` keyed by `output_id` (merging `OutTx` + `OutKey`, dropping the amount dimension — `output_id == amount_index` under one bucket, SOK-2; the leaf position is **not** part of that key and stays a separate `leaf_to_output` mapping, SOK-10); **C** — keep the multimap and accept O(n) point reads. | **A — RULED 2026-09-18.** The maintainer's reason is sharper than the default's: B answers a *storage layout* question by ruling a *consensus spec* question. R8b-2 — whether amount-0 indexing of loud coinbase and emission amounts is consensus-visible or a storage index choice — should be ruled when someone has a **consensus** reason to rule it, on its merits, not because a table would be tidier without the dimension; ruling the spec to fit the table is the same move rejected on the `properties` heading demotion (edit the document to fit the parser). A records the facts LMDB records and costs one deferred layout bump if B ever wins — free pre-genesis. **The amount dimension is carried, not chosen** (§3.4): a two-part key whose first component is always `0` is parity with R8b-2 open, not a design. | C is rejected on SOK-1 (the surface's live consumer does a point read per leaf). B is the designed shape and the one this store would have if drawn fresh — but it drops a dimension whose consensus-visibility is R8b-2's open question; the store increment cannot rule a spec question. A carries the dimension at zero cost to the reader (`get(&(0, i))`), closes §11.1(f), and leaves B a pure layout change under §7.6's reopening the day R8b-2 rules. **If the maintainer rules R8b-2 now** ("storage index choice"), B is the default instead and this row records both rulings. **D — wait for a redb multimap cursor — REJECTED 2026-09-18, researched at source so it is not re-researched:** redb 4.2.0 (2026-08-17) added `Cursor` / `CursorMut` behind `experimental_cursor` — on `Table` only, for bulk sorted insertion, "unstable and may change incompatibly, or be removed, in any release" (its CHANGELOG). redb 4.3.0 (2026-09-14) added `ReadableMultimapTable::{lower_bound, upper_bound}` behind `experimental-api-5`, returning a `MultimapCursor` that is a **stub**: its own doc comment says the type "only reserves the constructors' signatures" and navigation "will be added behind `experimental_cursor`"; the position field is `#[allow(dead_code)]` (upstream PR #1347 — reserving the redb-5 trait surface). The bound is `Bound<K>`, a seek over the *key* tree; no released or reserved signature seeks to a `(key, value)`. The engine can find a value inside a key's collection in O(log n) internally (`remove(key, value)` does), but does not expose it. No milestone, no open issue tracks a value-level seek; the 4.3.0 tarball's CHANGELOG already carries an undated `5.0.0` section. So D has no falsifiable wait, would rest a per-leaf read on an unstable flag of an unreleased major, and even if it landed would buy back only what A already has with stable tuple keys. **Reopen** if redb exposes a stable value-level multimap seek — falsify by `rg -e 'fn lower_bound' -e 'fn seek' -e 'fn get_value' src/multimap_table.rs` in the pinned version showing a `(K, V)` bound — and even then A stays the shape; the reopening would only retire the "redb cannot" half of SOK-1's wording. |
| **SOK-Q2** | How is SI-9 stated for a unique-key `output_amounts`? | **Default — RULED 2026-09-18.** Per bucket: `last_index + 1 == next`; whole-table `len() == last + 1` as the density check, valid because one bucket exists; a second bucket at `connect` **is** a breach (CEN-H14's store-side belt). Plus SOK-2: amount-0 `last == output_txs.last` — two counters, not three (SOK-10). *Stating the premise is what makes the belt honest, and the belt is **self-guarding**: if a second bucket ever appears, `table.len() == last + 1` fails rather than passing, because per-bucket indices are dense from zero. **UPDATE 2026-09-18 (#783 review): not by itself** — a hole in the bucket compensated by a foreign-bucket row (`(0,0), (0,2), (7,x)`) sums to the right length; the landed belt therefore *checks* the premise (first and last keys carry the bucket's amount) before trusting the length. **UPDATE 2026-09-18 (code-quality pass):** that belt is `next_output_slot` — it mints the `(bucket, output_id)` slot or refuses, so SOK-2 is the same check, not a filter on a bare index (`connect.rs`). Routing that failure to `StoreInvariantViolated` rather than a verdict is C2-R8's taxonomy — CEN-H14 is the validator's rule, so the belt firing means the validator has a hole.* | The multimap belt needed an end-peek for a compensating hole+duplicate (PR #757 review); unique keys make the duplicate unrepresentable, so the belt simplifies — but only if the single-bucket premise is stated as the premise it is, not assumed. |
| **SOK-Q3** | `get_output_histogram`: not ported (SOK-6) — and the C++ RPC, with the `shekyld` CLI command `output_histogram` that fronts it? **A** — both die at cutover with the LMDB path (the countermand's RECORD-AND-SPECIFY default, SCR-2's precedent); **B** — deleted now (rule 60: decoy-selection tooling; U-7 already recommends it). | Default was **A**. **RULED 2026-09-18: B — on privacy grounds, not tidiness** (`00-mission.mdc` #2). The request takes `amounts`, `min_count`, `max_count`, `unlocked`, `recent_cutoff` (`src/rpc/core_rpc_server_commands_defs.h:1142`–`:1154`); the handler is live (`core_rpc_server.cpp:1160`) and fronted by a CLI command registered at `src/daemon/command_server.cpp:258`. On a chain with rings that is decoy-selection support; on a chain without them it is a **statistical disclosure surface with no consumer** — per-amount output counts over operator-chosen unlock and recency windows is close to precisely what a chain analyst would ask for, queryable by anyone who can reach the RPC. "Dies at cutover" is a schedule, not a mitigation: the C++ daemon runs testnet until then, and testnet is where analysis tooling gets built and validated; two months of U-7 unacted is the argument *for* closing it. Scope: route, handler, wire struct, CLI command, and the store chain they leave callerless — a deletion, so rule 20 does not bite; **its own PR** under rule 15, not a commit in this increment. **RK-8's row stops listing it as served the moment this ruling lands** (this PR), so the affordance cannot survive by being invisible at review time; the deletion PR marks it deleted. Falsify by `rg on_get_output_histogram src/` returning anything after that PR merges. | B is a C++ deletion PR, the class the countermand routes to cutover — which is why it was not the default; the maintainer's override weighs the disclosure surface above the schedule, and the scope is three sites plus the callerless chain. |
| **SOK-Q4** | Is `OutputOrigin` a new name or `OutTx` re-exported? | **`OutTx`, re-exported — RULED 2026-09-18.** One type, one name; O2 returns it. | A second name for a field-identical struct is the identity-DTO hop CTS-5 and the GUI's rule 27 name. Only a semantic remap earns a second shape; there is none. |

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md` §7 S-OUT-KI row: landed stamp, "7 methods → 4 reads (K1, K2, O1, O2); `has_key_images` + batch forms dissolve (SOK-3); two not ported (SOK-4/5); histogram DELETED (SOK-6)"; §7.6's "`output_amounts` keyed verbatim with R8b-2 open" gets `UPDATE`: keyed tuple table at v6, same logical content, R8b-2 still open, arm B named.
- `STORE_INVARIANT_REGISTER.md` SI-9: the unique-key restatement and the SOK-2 leg.
- `FOLLOWUPS.md`: the SOK-10 row (this PR) — owner the path-FFI lane, falsifier named.
- `LMDB_SCHEMA.md` if it carries the redb mapping for `output_amounts`: multimap → keyed tuple.
- `DAEMON_RPC_KV_CUTOVER.md`: RK-8's `get_output_histogram` struck as REJECTED **on this PR** (Q3's ruling); the deletion PR marks it deleted and closes census U-7.
- `IMPLEMENTATION_INDEX.md`: `SOK-` row (this PR); `DRS-*` row UPDATE; §7 document rows — this document (this PR), `DRS_E1_SCHAIN_R.md` → completed (this PR).
- `docs/CHANGELOG.md`: one Unreleased line under "Daemon chain store" at the increment (layout v6; four reads).
- This document: banner flips to *landed* at the increment PR; archive-or-contract per index §8 when S-TX's pre-flight has read it.

---

## 11. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-18 | **PR #783 code-quality pass.** `TableShape` deleted (one-variant enum, rule 21 — the snapshot writes `map<…>` as a word; a second shape re-mints it with its table; no next surface adds a multimap). `OutputSlot::bucket` **kept**: it is the bound constructor so the tuple's field order is written once (`§3.4`'s bucket range), not the SI-9 end-peek (that read is table-wide first/last so a foreign row is visible). Fields private. `next_output_slot` mints the `(bucket, output_id)` slot or refuses, so SOK-2 is a named check not a `.filter`. Tests: S-OUT-KI snapshot cases live in `output_read_tests.rs` (sibling of `output_reads.rs`); SI-9 plant-then-connect belts share one helper so `connect_tests.rs` stays under 1k. SI-9 register no longer calls the length check self-guarding. Copilot rounds 1–2 already taken; Bugbot did not run (usage limit). |
| 2026-09-18 | **PR #783 review round 2 (Copilot: 4 open; 4 taken, 0 refuted).** The one code finding was the key-type gate: accepting both `u64` and `(u64, u64)` for every INTEGERKEY + `compare_uint64` dupsort table let `output_amounts` lose its amount component, or `block_info` gain a spurious one, unnoticed. The flags cannot tell those two apart (they are identical), so the gate now reads the fact that does — how the C++ *writes* each table, the key argument of its `mdb_cursor_put` calls: every put keyed by `zerokval` is a collapse (exactly `u64`); a real key with `MDB_APPENDDUP` is a genuine multi-member DUPSORT (exactly the tuple); a real key without it admits both (the key's order is what is consensus-visible); an `MDB_CURRENT` in-place update is not a keying fact and is left out of the fold; a uint64-dupsort table with no parsed put is a gate failure, not an unconstrained table (rule 47). No table-name set. Both negative cases observed red. Docs: DRS §3.6.4's write-path bullets no longer name `SetTable` / a multimap journal verb; §7 commit 2's `range(..).next_back()` and §8's floor of 30 brought to what landed; the index header's verification line moved with the unified stamp. |
| 2026-09-18 | **PR #783 review round 1 (Copilot: 4 open + 6 suppressed; 10 taken, 0 refuted).** Two were real. (1) The reads looked the row up *before* classifying the index against the count, so a stray `(0, i)` at or beyond `output_txs.len()` would have been served as `Recorded` — the reads now classify first (`AtHeight`'s discipline) and never read past the count. (2) The SI-9 belt at `connect` was not self-guarding as SOK-Q2's ruling said: a hole compensated by a foreign-bucket row sums to the right length; `next_amount_index` now checks the premise (first and last keys carry the bucket's amount) before trusting `len()`. Also taken: O1 validates the record's `output_id` against its slot (a raw file can hold what `connect` refuses; the doc had promised a check the projection could not perform); the output reads moved to their own body, `store/output_reads.rs`, the sibling of `chain_reads.rs`, and the `(amount, amount_index)` tuple became a type, `OutputSlot` (`ids.rs`), assembled in one place; §2.1 B / §3.5 / §4 brought to the ruled `OutTx` and the keyed table; DRS §3.6.4's stale `cfg(test)` opener sentence and §7.6's `v5` lead corrected; the index row's pre-landing clause removed. Three tests added: the compensated hole, the disagreeing join, the stray row beyond the count. `cargo test -p shekyl-chain-store` 254 + 10. |
| 2026-09-18 | **Increment landed** — §7 commits 1–3 as sequenced (commit 4 is this docs commit; commit 5's RK-8 row was written by #782). What landed differs from the plan in two places worth naming: `next_amount_index` on the keyed table is `last + 1 == len` with the single-bucket premise stated at the site (no end-peek is needed once duplicates are unrepresentable), and SOK-2's belt is enforced at `connect` as `amount_index == output_id` rather than checked only by a test — the write refuses the divergence. `AtIndex<T>` lives in its own module with `compile_fail` doctests. `check_redb_schema_key_types.py` had silently dropped the tuple-keyed definition (its key regex could not cross the inner comma) and only its constraint floor noticed — fixed with a parse selftest, the dual-form INTEGERKEY+uint64-dupsort rule, and the floor moved 30 → 29 with the reason beside it. `cargo test -p shekyl-chain-store` 251 + 10 doctests. |
| 2026-09-18 | **Round 1 RULED (maintainer, on PR #779).** Q1 **A** — with the sharper reason: B would rule a consensus spec question (R8b-2) to settle a storage layout, the tail wagging the dog; the amount dimension is *carried, not chosen*, said in those words in §3.4. Q2 default, with the self-guarding property named (a second bucket fails `len() == last + 1`, never passes). Q4 `OutTx`. **Q3 overridden to B**: `get_output_histogram` and its CLI command are a statistical disclosure surface with no consumer on a ringless chain; "dies at cutover" is a schedule, not a mitigation, and testnet is where analysis tooling gets built — deleted now, own PR, and RK-8 stops listing it as served on this PR. Implementation may start once this document merges. |
| 2026-09-18 | **PR #779 review round 3 (Copilot: 4 open + 4 suppressed; 8 taken, 0 refuted) — and the #777 gate lifted.** Re-based onto `51d7f2416` (#777 RTN-7 and #780 landed **code**); every code anchor re-read — only the five `undo_tests.rs` lines moved (+2); stamp moved with the checks actually re-run (242 + 8; census 6/151, held 2, 153, 126/153; policy 0/9; `tables.snap` 51; `SCHEMA_VERSION 5`). Two findings reshaped the commit sequence: the tuple key needs `impl Restorable for (u64, u64)` to pass `open_insert_table`'s bound (`write.rs:291`–`:293`), and `MultiInserted` cannot outlive its constructor — `SetTable` (`set.rs:68`) is returned by `open_multimap_table` and re-exported at `store/mod.rs:112` — so the layout change and the multimap deletions are **one commit** (6 → 5). O2's index domain pinned: the `_from_global` read (`output_txs[output_id]`), never the amount-specific composition that is right only by SOK-2's belt. `prune_tx_data`'s `get_output_key` (`db_lmdb.cpp:10282`) joins the census: a current caller that dies with the stripe engine (PDM-Q7). CEN-H14 wording corrected — miner/emission loud amounts are stored under `0` and permitted; a second bucket means a non-miner, non-emission vout escaped. Census records updated in-line (`CONSENSUS_RULE_CENSUS.md` §5.2 ×2: `get_output_key_mask_unlocked` has zero callers; `CONSENSUS_RULE_CENSUS_1.md` U-7: `get_output_distribution` has no route). Archived S-CHAIN-R doc's §10 archive bullet put in the past tense. PR title/description updated to SOK-1…SOK-10. |
| 2026-09-18 | **PR #779 review round 2 (Copilot: 4 open + 1 suppressed; 5 taken, 0 refuted).** Commit 3's opener deletion has a non-`OUTPUT_AMOUNTS` caller — the `properties` `IMPOSTOR` multimap leg at `store_tests.rs:449`–`:453`, the only test of the by-name half of the typed-properties refusal — kept as a keyed impostor, named in §7 and §8; Q1 arm B no longer carries the refuted `== leaf` equality; Q3's default is stated as the future doc action it is (RK-8 still lists the route); the index `SOK-` row and `DRS-*` cell synchronised to two counters and SOK-10; the archived S-CHAIN-R doc's lifecycle sentence put in the past tense. Rebased onto `cb6b72b47` (#778); the two lanes' stamp moves to `eee838d4d` merged into one stamp crediting both. |
| 2026-09-18 | **PR #779 review (Copilot: 4 open + 11 suppressed; 15 taken, 0 refuted).** The one that changed the plan was suppressed: the leaf position is **not** a third member of SOK-2's equality — `OutputIndex ≠ TreePosition`, leaves drain in `(maturity, gindex)` order — and reading the call chain behind the wrong premise found **SOK-10**: the path builder passes a tree position to `get_output_key(0, pos)` unresolved (`curve_tree_path.cpp:67`, `rpc_path.rs:85`–`:89`), inherited from the pre-extraction C++; a reordered chunk fails proof verification. Routed to the path-FFI lane with a `FOLLOWUPS.md` row and falsifier; O1's `GlobalOutputIndex` parameter is the store's half. Also taken: the `output_histogram` CLI command joins SOK-6/Q3's caller set; O2 returns `OutTx` as it exists (`local_index`); the `BeyondCount` boundary stated as `≥ count`; preamble reworded (K2 named, two lookups not one record, no-caller vs no-route, the SOK-1 sentence); the redb falsifier without a pipe; `#760` = plan PR, `#772` = increment in the two chain-rules docs; the archived S-CHAIN-R doc's two live instructions marked done; CTS's two name-mentions linked to `completed/`; index stamp moved to `eee838d4d` with its checks re-run. |
| 2026-09-18 | **Substrate re-check at `eee838d4d`** (#774 PDM-Q second ruling pass + S-PRUNE skeleton, #775 two-store record, #776 curve-tree plan — all docs-only; no `rust/` or `src/` change, anchors hold). One interaction found and recorded in §3.3: `PDM-Q1` grades this surface's output tables CACHE and `spent_keys` KEEP-C; `PDM-Q2`'s predicate discards only the GOOD region, so the dense-index absence model stands, with the reopener named if a CACHE discard is ever ruled. `CURVE_TREE_STORE_SHAPES.md` landed (#776) and is now linked. Nothing in this plan is re-addressed. |
| 2026-09-18 | **SOK-Q1 arm D (wait for a redb multimap cursor) researched at source and REJECTED**, with the falsifier in the row: 4.2.0's `experimental_cursor` is `Table`-only and self-declared removable; 4.3.0's `MultimapCursor` is a constructor-only stub seeking the key tree, no `(K, V)` bound anywhere; no milestone or issue tracks a value-level seek. Recorded so the next reader of SOK-1 does not re-research it. |
| 2026-09-18 | **Round 0 executed at `d89f99791`.** Nine findings, four questions with defaults. The finding that shapes the increment is not a read: `output_amounts`' ported multimap has no seek (verified in redb 4.1.0 at source), so the surface's point read is O(n) on it — corrected as a keyed `(amount, amount_index)` table under DRS §7.6's own statement that the comparator projects logical content, with R8b-2 left exactly as open as it was (SOK-1, SOK-Q1). Three of eight methods are not ported (no callers / decoy tooling); the batch forms dissolve into the snapshot. `DRS_E1_SCHAIN_R.md` read and archived by this PR (§2.4). Code commits wait on PR #777. |

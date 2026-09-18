# DRS-E1 S-OUT-KI — outputs and key images: increment plan and Round-0 pre-flight

**Status:** OPEN — **Round 0 (pre-flight) executed 2026-09-18** at `dev` =
`d89f99791` (the tree that merged PR #772, S-CHAIN-R). Round-1 questions (§9)
are **proposed with defaults, not ruled**; the increment (§7) does not start
until they are, and its code commits do not start until PR #777 (RTN-7) has
merged — it retypes `store/connect.rs` and `store/chain_reads.rs`, which §7
commits 1, 2 and 4 edit. Implements *from*
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §3.5/§7 (the S-OUT-KI row:
extraction order **4**, "consensus-critical (double-spend admission) and
needs chain reads for height context, so it follows S-CHAIN-R"), §7.6 (parity
first, the ported partition is transitional, **byte parity was never a
constraint — the comparator projects logical content**), and §11.1(f) (every
value is a named shape); from
[`DRS_E1_SCHAIN_R.md`](../completed/DRS_E1_SCHAIN_R.md) (the read handle,
`ReadSnapshot`, and its fault policy — this surface is more reads on it;
SCR-11 routes E2's key-image scan here); from
[`CONSENSUS_STORE_RECONCILIATION.md`](CONSENSUS_STORE_RECONCILIATION.md)
CEN-L1 / CEN-I7 (the two halves of key-image uniqueness, ruled C2-R8 Q6) and
CEN-L6 (amount-0 indexing is **arm C — unspecified**, routed to **R8b-2** and
open); and from [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) G11 and the
rules crate's own statement of it (`rust/shekyl-chain-rules/src/view.rs:30`,
"absence is a case, not a `None`" — adopted here for every by-index read;
the class is stated once, with its instances, in `CURVE_TREE_STORE_SHAPES.md`
§3.1, PR #776, linked when it lands). Nothing in this document re-opens any of them; §3.4 and SOK-1 *ask*
one of them (R8b-2's neighbour, the physical shape of `output_amounts`)
because this surface is its first reader and cannot be built at LMDB's
complexity on the ported shape.

**Why a separate document.** The S-OUT-KI row is one table line naming eight
`BlockchainDB` methods. Of the eight, **four** become reads here, one
dissolves into the snapshot handle's own shape (SOK-3), and **three are not
ported** — two have no caller at HEAD and one is Monero decoy-selection
tooling the census already flagged (U-7). The four are not four functions:
the two key-image tests are one membership read, the two output lookups
are one record read projected two ways, so they land as **four** Rust reads
(§3.2). The increment's content is the mapping, the absence semantics for a
dense index (§3.3), and one finding that is not a read at all: the shape
S-CHAIN-W wrote `output_amounts` in makes this surface's point read a scan
(SOK-1, §3.4). Rule 26's pre-flight pass is the instrument; this is the same
shape as `DRS_E1_SCHAIN_R.md` and stays in `docs/design/` while the
increment is open.

**Identifier family.** Findings and questions here are **SOK-n**, registered
in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by this document's
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
| In flight, and why it matters | PR #777 (RTN-7, the wire crate's hash surface) edits `store/connect.rs`, `store/chain_reads.rs`, the connect fixtures and tests. §7's code commits wait for it; this document does not touch code. PR #776 (curve-tree store plan) is docs-only and disjoint. |

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
time. `output_origin(GlobalOutputIndex) -> Result<AtIndex<OutputOrigin>, StoreError>`
— which transaction and which vout produced it. `AtIndex<T>` is the dense
index's absence type (§3.3).

**C. `output_amounts` becomes a keyed table (SOK-1, SOK-Q1 default).**
`TableDefinition<(u64, u64), Coded<OutKey>>` keyed `(amount, amount_index)`,
replacing the multimap; `OutKey` drops the `amount_index` field its key now
carries; **`SCHEMA_VERSION 5 → 6`**, one layout commit. Same logical content
as LMDB's `DUPSORT` table — the pair `(amount, amount_index) → record` — in
the shape redb can seek in. The `next_amount_index` end-peek becomes a
`range(..).next_back()`; SI-9's density belt is restated for a unique-key
table (SOK-Q2). `check_redb_schema_key_types.py` learns that a
`compare_uint64` `DUPSORT` table is reproduced by a `(K, u64)` tuple key as
well as by a `U64PrefixBytes` multimap value — the gate asserts ordering,
and a tuple key orders `amount` numerically then `amount_index` numerically,
which is `MDB_INTEGERKEY` then `compare_uint64`.

**D. Deletions the correction leaves dead (rule 15).** `U64PrefixBytes`
(`lmdb_order/u64_prefix.rs`, one consumer); `OutKey::amount_index_of`
(`codec/chain.rs:240`); `UndoEntry::MultiInserted` (`codec/undo.rs:88`) and
`impl UndoTarget for MultimapTableDefinition` (`store/undo.rs:275`) — after C
the catalogue has **no multimap**, so the journal's multimap arm has nothing
to replay; `WriteBatch::open_multimap_table` and the multimap
`ReadSnapshot::open_multimap_table`. The `UndoEntry` variant removal is a
codec change and rides the same bump as C.

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
- **`get_output_histogram`** — ported as nothing (SOK-6; SOK-Q3 names the
  RPC's fate). The three stay on the DRS §3.5 row so
  `check_drs_c_surface_map.py`'s count holds (the SCW-2 / SCR-2 precedent).
- **The pool's half of double-spend detection** (`tx_memory_pool::have_tx_keyimg_as_spent`,
  `src/cryptonote_core/tx_pool.cpp:1711`) — S-POOL's. K1 is the chain half
  only; the RPC that unions them (`is_key_image_spent`,
  `src/rpc/rpc_facts_ffi.cpp:915`) is a cutover-time consumer.
- **`get_tx_unlock_time`, `get_tx_block_height`** — S-TX's, even though the
  histogram's `unlocked` walk called them; the histogram is not ported.
- **Any daemon wiring.** The daemon serves LMDB at this pin; the path
  builder's `read_output_oc` callback (`src/cryptonote_core/curve_tree_path.cpp:67`)
  and the two key-image RPC/verdict readers switch to `ReadSnapshot` at
  cutover, not here.
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

### 3.2 The mapping — 8 methods, 4 reads

| C++ (`BlockchainDB`) | Live callers at HEAD | Rust read | Notes |
| --- | --- | --- | --- |
| `has_key_image` | `Blockchain::have_tx_keyimg_as_spent` (`blockchain.cpp:254`) ← CEN-I7's per-input check (`:3366`, `:3502`, `:3526`, `:3555`), the pool's chain half (`tx_pool.cpp:1711`), the submit verdict (`daemon_submit_ffi.cpp:126`); the block-level double-spend visitor (`blockchain.cpp:3097`) | **K1** `has_key_image(&KeyImage) -> Result<bool>` | Shared body with `BatchView` (SCR-13 shape). The C++ warns in prose that this read takes no lock and must not be paired with another (`blockchain.cpp:250`–`:253`); the snapshot is the lock. |
| `has_key_images` | `have_tx_keyimges_as_spent` (`:3380`) ← `is_key_image_spent` RPC (`rpc_facts_ffi.cpp:915`) | **dissolves into K1** (SOK-3) | The batch form exists to hold one `rtxn` across N keys (`db_lmdb.cpp:3851`–`:3869`). A `ReadSnapshot` *is* one transaction; N calls to K1 on it are the batch. |
| `for_all_key_images` | the digest oracle (`logical_state_digest.cpp:73`) | **K2** `key_images() -> impl Iterator<Item = Result<KeyImage, StoreError>>` | Order is the table's (`LmdbHashKey`); the one consumer is order-insensitive. |
| `get_output_key` (single, `db_lmdb.cpp:3728`; batch `:4460`) | `Blockchain::get_output_key` (`blockchain.cpp:2616`) — **no caller**; the path builder reads the DB directly, `db.get_output_key(0, pos)` (`curve_tree_path.cpp:67`); `blockchain_utilities` (LMDB tools, die with LMDB) | **O1** `output(GlobalOutputIndex) -> Result<AtIndex<RecordedOutput>>` | `RecordedOutput { pubkey: OneTimePubkey, commitment: CommitmentBytes, height: BlockHeight, unlock_time: Timelock }` — `OutKey` minus the ids. The batch form (`allow_partial`) dissolves like SOK-3: the caller loops on one snapshot and stops at the first `BeyondCount`. |
| `get_output_tx_and_index` (single `:3778`; batch `:4506`) | `get_output_key_mask_unlocked` (`blockchain.cpp:2623`–`:2631`) — **no caller**; the histogram's `unlocked` walk (`db_lmdb.cpp:4603`) — not ported | **O2** `output_origin(GlobalOutputIndex) -> Result<AtIndex<OutputOrigin>>` | `OutputOrigin { tx_hash: TxHash, index_in_tx: OutputIndexInTx }` = `OutTx` (`output_txs[output_id]`). Kept although its C++ callers are dead: E2's comparator projects `output_txs` through it, and it is the read that makes SOK-2's coincidence checkable. |
| `for_all_outputs` ×2 (`:4028`, `:4063`) | **none** — `Blockchain::for_all_outputs` (`blockchain.cpp:7029`, `:7034`) has no caller in `src/` or `tests/` | **not ported** (SOK-4) | Zero consumers at HEAD; the row keeps the names. |
| `get_output_distribution` (`:4635`) | `Blockchain::get_output_distribution` (`blockchain.cpp:2633`) ← `core::get_output_distribution` ← `RpcHandler::get_output_distribution` (`src/rpc/rpc_handler.cpp:29`) — **no RPC route**: `core_rpc_server.cpp` has no `on_get_output_distribution`; the only caller is `tests/unit_tests/output_distribution.cpp:92` | **not ported** (SOK-5) | SCR-2 found the `amount == 0` arm's helper dead; this confirms the whole method is. Its `m_nettype != FAKECHAIN` branch (`blockchain.cpp:2636`) — a rule-71 divergence — dies with it. |
| `get_output_histogram` (`:4542`) | `on_get_output_histogram` (`src/rpc/core_rpc_server.cpp:1160`; routed `core_rpc_ffi.cpp:273`) — a **live RPC** whose only in-tree client is a regtest asserting the restricted listener *refuses* it (`rust/shekyl-engine-core/src/engine/regtest_e2e.rs:4090`) | **not ported** (SOK-6; SOK-Q3) | Monero decoy-selection tooling: per-amount output counts with `unlocked` / `recent_cutoff` walks. FCMP++ selects no decoys (rule 60; census U-7, `CONSENSUS_RULE_CENSUS_1.md:233`). |

### 3.3 Absence, faults, and what a read may not do

S-CHAIN-R's policy (`read.rs:16`–`:35`) holds unchanged: every decode is
SI-7, a read never arms the halt, by-hash reads return `Option`. This surface
adds one absence shape.

**By-index reads return `AtIndex<T>`, not `Option`.** Output ids are dense
(SI-9: `output_id` is `output_txs`'s entry count at write time), so the only
absence a snapshot can report is *at or beyond the count* — the same
structure as heights above the tip. `AtIndex<T> { Recorded(T), BeyondCount }`,
matched exhaustively, no `Option` conversion, no `?` — `AtHeight`'s
discipline (`CHAIN_RULES_CRATE.md` G11) at a second dense index. A row
missing *below* the count is not absence: it is SI-9's hole, reported as
`InvariantViolated`, exactly as a `block_info` hole below the tip is SI-7.
`CURVE_TREE_STORE_SHAPES.md` §3.1 is the class statement; this is its
fourth application, and the counter-rule there applies too — `has_key_image`
returns `bool`, because "not spent" is a value inside the type's range with
no arm that differs.

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
- **R8b-2 is untouched.** Arm A records the same facts LMDB does, including
  the amount dimension; whether `amount_index` is *exposed* as a consensus
  fact is exactly as open after this as before. What changes is that the
  question can now be answered by a projection, not by a table rewrite.

**What the Rust read exposes.** `output(idx)` reads `(0, idx)`. Shekyl has
one bucket: every coinbase and emission vout is stored under `0` with its
ct-base commitment and every other vout under its own amount, which CEN-H14
makes `0` (`connect.rs:62`–`:66`); the C++ refuses any other amount
(`db_lmdb.cpp:3746`–`:3747`). The API does not take an `amount` because there
is nothing a caller could pass but `0` — and *not* because R8b-2 is
prejudged: if R8b-2 rules the dimension consensus-visible, the read grows a
parameter and the table needs no change (rule 21 reopening: R8b-2 ruled).

**The three counters that coincide (SOK-2).** With one bucket, three dense
counters are equal for every output: `output_id` (`output_txs`' count),
`amount_index` under `0` (the bucket's count), and the curve-tree leaf
position the path builder passes as `pos` to `get_output_key(0, pos)`. The
path builder's correctness rests on the third equalling the first two, and
nothing at HEAD asserts it — it is true by construction of three separate
`last + 1` counters that happen to advance together. The increment adds the
belt: after every `connect`, the amount-0 bucket's last index equals
`output_txs`' last id (SI-9 restated, SOK-Q2), and a test pins that O1 and
O2 at index *i* describe the same output the leaf at *i* commits to. S-CURVE
inherits the third leg when it lands its leaf reads.

### 3.5 Types this increment adds to the store crate

- `AtIndex<T>` — dense-index absence (§3.3). `#[must_use]`, exhaustive, no
  `Option`/`?` conversion; the `compile_fail` doctests `AtHeight` carries
  (`view.rs:50`–`:57`), duplicated for the second type rather than
  generalised (rule 21: two instances is not yet a pattern worth an
  abstraction; the third caller generalises).
- `RecordedOutput` — `OutKey` projected without its ids (§3.2). Not
  `Canonical`: a read projection, never stored.
- `OutputOrigin` — `OutTx` re-exported under the name the read surface
  uses, or `OutTx` itself if a second name buys nothing (SOK-Q4).

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
| `output_amounts` | `(u64, u64) → Coded<OutKey>` | O1 `get(&(0, i))` | `BeyondCount` at/after the bucket's last; a hole below is SI-9 | `connect` (SI-9) |
| `output_txs` | `u64 → Coded<OutTx>` | O2 `get(output_id)` | `BeyondCount` at/after `len`; a hole below is SI-9 | `connect` (SI-9) |
| `tx_outputs` | `u64 → Coded<TxOutputIndices>` | **not read here** — S-TX's `get_tx_amount_output_indices` | — | `connect` |

---

## 5. Store invariants this increment builds or restates

- **SI-1** (`spent_keys` is a set) — read side: K1 is membership on the
  table SI-1 guards; nothing to add.
- **SI-9** (dense ids) — restated for a unique-key `output_amounts`
  (SOK-Q2): duplicates are unrepresentable by the key; density per bucket is
  `last + 1 == count`, where `count` is exact for the whole table when one
  bucket exists — and a *second* bucket appearing at `connect` is itself the
  belt firing, because a non-zero amount on a connected vout is what CEN-H14
  forbids and the validator admitted it (`StoreInvariantViolated`, never a
  verdict; the validator has the bug). The SOK-2 coincidence (`output_id ==
  amount_index` under `0`) joins the row.
- **SI-7** — every decode strict, unchanged.

---

## 6. Round-0 findings

| # | Finding (at `d89f99791`) | Disposition |
| --- | --- | --- |
| **SOK-1** | `output_amounts` is a redb multimap whose only lookup is a full iteration of the key's members (redb 4.1.0 has no seek within `MultimapValue`); `get_output_key`'s `MDB_GET_BOTH` seek has no O(log n) equivalent on it. First reader finds the writer's shape unservable. | Keyed tuple table, `SCHEMA_VERSION 5 → 6` (§3.4, SOK-Q1). |
| **SOK-2** | Three dense counters coincide by construction and nothing asserts it: `output_id`, amount-0 `amount_index`, leaf position (`curve_tree_path.cpp:67` passes a leaf position as an amount-0 index). | Belt on SI-9 + a test (§3.4, SOK-Q2). |
| **SOK-3** | `has_key_images` and the batch `get_output_key` / `get_output_tx_and_index` exist to hold one LMDB `rtxn` across N lookups. `ReadSnapshot` is that transaction. | Dissolve into K1 / O1 / O2 on one snapshot; no batch API. |
| **SOK-4** | `Blockchain::for_all_outputs` (two overloads) has no caller in `src/` or `tests/`. | Not ported. |
| **SOK-5** | `get_output_distribution` has no RPC route (`core_rpc_server.cpp` has no handler; `RpcHandler::get_output_distribution` is reached only from `tests/unit_tests/output_distribution.cpp:92`). Extends SCR-2 from "the `amount == 0` helper is dead" to "the method is". Carries a rule-71 nettype branch (`blockchain.cpp:2636`). | Not ported; branch dies with it. |
| **SOK-6** | `get_output_histogram` is a live RPC serving Monero decoy selection; census U-7 flagged it 2026-07 as a deletion candidate under RT-9's precedent. Its one in-tree client tests that the restricted listener refuses it. | Not ported; the RPC's fate is SOK-Q3. |
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

## 7. Commit sequence (rule 90; one PR, ≤ 6 commits, cut from `dev` after this document merges **and PR #777 has merged**)

1. `store: ReadSnapshot::has_key_image + key_images — spent_keys membership shared with BatchView` — K1, K2; the shared body moves to `chain_reads.rs` (SCR-13 shape); tests: membership on a connected chain, the scan equals the connected set, the snapshot sees one state across a concurrent connect. No layout change.
2. `store: layout v6 — output_amounts is a keyed (amount, amount_index) table; OutKey drops its prefix; MultiInserted retired; SCHEMA_VERSION 5 → 6` — **the one layout commit**: `schema.rs`, `OutKey`, `UndoEntry`, `connect`'s output write and `next_amount_index`, SI-9 restated (SOK-Q2), `check_redb_schema_key_types.py`'s tuple rule, snapshots re-pinned, the `SCHEMA_VERSION` history entry.
3. `store: delete the multimap machinery — U64PrefixBytes, UndoTarget for MultimapTableDefinition, open_multimap_table` — pure deletion; `undo_tests` that used `OUTPUT_AMOUNTS` as their multimap example are rewritten against the keyed table (no assertion weakened — each names what it now pins).
4. `store: ReadSnapshot::output / output_origin — AtIndex, RecordedOutput` — O1, O2, `AtIndex<T>` with its `compile_fail` doctests, the SOK-2 coincidence test, `BeyondCount` at the count and SI-9 on a planted hole.
5. `store: DRS §7 row, SI-9 cell, §7.6 UPDATE, index, CHANGELOG` — §10.
6. (`docs`, if not folded into 5) `DAEMON_RPC_KV_CUTOVER.md` row for `get_output_histogram` per SOK-Q3's ruling.

Commit 2 is the one a reviewer reads line by line; 3 is a deletion diff; 1
and 4 are reads in the S-CHAIN-R shape.

---

## 8. Denominator — what must stay green, what must be extended

- `cargo test -p shekyl-chain-store` — S-CHAIN-W's connect/pop/undo tests are the writer-side denominator for commit 2; every literal that names `output_amounts`' shape (`connect_tests.rs:210`, `:334`, `:554`, `:597`; `undo_tests.rs:50`, `:133`, `:188`, `:242`, `:253`) changes with it and is listed here so the diff is checked against a list, not discovered.
- `scripts/ci/check_redb_schema_key_types.py` — **extended** (tuple key parse; `DUPSORT compare_uint64 → (K, u64)` accepted); its `--selftest` gains the tuple case; its floor of 30 constraints holds (the table is still constrained, differently).
- `check_redb_schema_coverage.py` (bijection) — unchanged; the table keeps its name.
- The codec snapshot gate — `OutKey` and `UndoLog` fixtures change; the bump in commit 2 is what §11.1(b) demands.
- `check_drs_c_surface_map.py` — the S-OUT-KI row keeps all eight names.
- **Extended:** K1/K2 tests (commit 1); the SOK-2 coincidence test, `BeyondCount`, planted-hole SI-9, `AtIndex` `compile_fail` (commit 4); a `range`-based bucket read asserting O(log n) *shape* (a `get`, not an iteration — pinned by the code, not timed).
- Docs gates: links, code citations, claims, index prefix/table shape, banners, landed-row stamps, surface map.

---

## 9. Round-1 questions (proposed; each ruling to be written line-local)

| Q | Question | Default | Why it is a question |
| --- | --- | --- | --- |
| **SOK-Q1** | What shape does `output_amounts` take? **A** — keyed `(amount, amount_index) → Coded<OutKey>`; **B** — collapse into one `outputs: u64 → Coded<Output>` (merging `OutTx` + `OutKey`, dropping the amount dimension; `output_id == amount_index == leaf` by construction); **C** — keep the multimap and accept O(n) point reads. | **A.** | C is rejected on SOK-1 (the surface's live consumer does a point read per leaf). B is the designed shape and the one this store would have if drawn fresh — but it drops a dimension whose consensus-visibility is R8b-2's open question; the store increment cannot rule a spec question. A carries the dimension at zero cost to the reader (`get(&(0, i))`), closes §11.1(f), and leaves B a pure layout change under §7.6's reopening the day R8b-2 rules. **If the maintainer rules R8b-2 now** ("storage index choice"), B is the default instead and this row records both rulings. |
| **SOK-Q2** | How is SI-9 stated for a unique-key `output_amounts`? | Per bucket: `last_index + 1 == next`; whole-table `len() == last + 1` as the density check, valid because one bucket exists; a second bucket at `connect` **is** a breach (CEN-H14's store-side belt). Plus SOK-2: amount-0 `last == output_txs.last`. | The multimap belt needed an end-peek for a compensating hole+duplicate (PR #757 review); unique keys make the duplicate unrepresentable, so the belt simplifies — but only if the single-bucket premise is stated as the premise it is, not assumed. |
| **SOK-Q3** | `get_output_histogram`: not ported (SOK-6) — and the C++ RPC? **A** — dies at cutover with the LMDB path (the countermand's RECORD-AND-SPECIFY default, SCR-2's precedent); **B** — deleted now (rule 60: decoy-selection tooling; U-7 already recommends it). | **A**, recorded in `DAEMON_RPC_KV_CUTOVER.md` as *not carried*, falsify by `rg on_get_output_histogram src/` after cutover. | B is a C++ deletion PR, the class the countermand routes to cutover; but U-7 is a 2026-07 finding nobody has acted on, and a live RPC that advertises ring-selection data on a chain with no rings is an affordance (RT-9). If the maintainer prefers B it is its own PR, not a commit here. |
| **SOK-Q4** | Is `OutputOrigin` a new name or `OutTx` re-exported? | **`OutTx`, re-exported** — one type, one name; O2 returns it. | A second name for a field-identical struct is the identity-DTO hop CTS-5 and the GUI's rule 27 name. Only a semantic remap earns a second shape; there is none. |

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md` §7 S-OUT-KI row: landed stamp, "8 methods → 4 reads (K1, K2, O1, O2); `has_key_images` + batch forms dissolve (SOK-3); three not ported (SOK-4/5/6)"; §7.6's "`output_amounts` keyed verbatim with R8b-2 open" gets `UPDATE`: keyed tuple table at v6, same logical content, R8b-2 still open, arm B named.
- `STORE_INVARIANT_REGISTER.md` SI-9: the unique-key restatement and the SOK-2 leg.
- `LMDB_SCHEMA.md` if it carries the redb mapping for `output_amounts`: multimap → keyed tuple.
- `DAEMON_RPC_KV_CUTOVER.md`: `get_output_histogram` per SOK-Q3.
- `IMPLEMENTATION_INDEX.md`: `SOK-` row (this PR); `DRS-*` row UPDATE; §7 document rows — this document (this PR), `DRS_E1_SCHAIN_R.md` → completed (this PR).
- `docs/CHANGELOG.md`: one Unreleased line under "Daemon chain store" at the increment (layout v6; four reads).
- This document: banner flips to *landed* at the increment PR; archive-or-contract per index §8 when S-TX's pre-flight has read it.

---

## 11. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-18 | **Round 0 executed at `d89f99791`.** Nine findings, four questions with defaults. The finding that shapes the increment is not a read: `output_amounts`' ported multimap has no seek (verified in redb 4.1.0 at source), so the surface's point read is O(n) on it — corrected as a keyed `(amount, amount_index)` table under DRS §7.6's own statement that the comparator projects logical content, with R8b-2 left exactly as open as it was (SOK-1, SOK-Q1). Three of eight methods are not ported (no callers / decoy tooling); the batch forms dissolve into the snapshot. `DRS_E1_SCHAIN_R.md` read and archived by this PR (§2.4). Code commits wait on PR #777. |

# DRS-E1 S-CHAIN-R — the committed-chain read surface: increment plan and Round-0 pre-flight

**Status:** OPEN — **Round 0 (pre-flight) executed 2026-09-16** at `dev`
`3560b80c2` (the tree that merged PR #757, S-CHAIN-W); **round-1 rulings
taken 2026-09-16 on every §9 question** (each entry carries its ruling
line-local; Q4 overturned its own default — §3.6). §3 is the contract as
ruled; §7 the commit sequence, which may start once this document merges.
The review also minted [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)
**§7.6** (the ported partition is transitional; parity first, repair after,
in Rust; the comparator gates cutover and `ratified / enforced` gates
release) — a property of the whole E-series, recorded there and pointed to
from §3.8 here. Implements *from*
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §3.6.2 (halt visibility on
the tip), §3.5/§7 (the S-CHAIN-R row: extraction order **3**, "reads the
tables S-CHAIN-W writes") and DRS-D12 (replay-that-validates is the only
pre-cutover writer — this increment writes nothing on the connect path
except what §3.6 names); from
[`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md) (the codecs and tables this
surface decodes, landed PR #757); and from
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) G11 (absence is matched,
never propagated — the `AtHeight<T>` discipline, adopted here for every
by-height read). Nothing in this document re-opens any of them.

**Why a separate document.** The S-CHAIN-R row in DRS §7 is one table line
naming 23 `BlockchainDB` methods. Twenty-two of them read five tables, and
the port is not 22 functions: seven of the methods are one `block_info`
decode with a different field projected, three are one hash lookup, three
more are one blob read. The increment's content is the **mapping** — which
Rust read each C++ method becomes, what each returns when the height is
above the tip or the row is missing, and which C++ sentinels do not
survive — plus the two per-block fold fields FL-R3-STORE routes to this
surface. Rule 26's pre-flight pass is the instrument; this is the same shape
as [`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md) and stays in `docs/design/`
while the increment is open.

**Identifier family.** Findings and questions here are **SCR-n**, registered
in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by this document's
PR (prefix `SCR` checked distinct against the registry with
`check_index_prefix_uniqueness.py`: `SCR` ≠ `SCW`, `SCE`, `CSR`). One series,
numbered in order of surfacing; a question and the finding that raised it
share a number.

---

## 1. Preconditions, as found at the pin

| Precondition (DRS §7 S-CHAIN-R row) | State at `3560b80c2` | Evidence |
| --- | --- | --- |
| S-CHAIN-W landed — the tables this surface reads have a Rust writer and canonical codecs | **landed** (PR #757, merged 2026-09-16) | `rust/shekyl-chain-store/src/store/connect.rs` writes `blocks`, `block_heights`, `block_info`, `hf_versions`, `block_burn`, `total_burned`; `codec/chain.rs` `BlockInfo` (88 B), `codec/property.rs` `TotalBurnedCell` |
| A read handle exists | **exists, untyped** — `ChainStore::begin_read` → `ReadSnapshot` with generic `open_table` / `open_multimap_table` / `get_property` only | `store/read.rs`; zero callers outside the crate's own tests (`rg begin_read rust --glob '!rust/shekyl-chain-store/**'` → none) |
| The write-side `ChainView` projection (the one reader the store already has) | **landed** (PR #757) — `BatchView::{has_key_image, block_at, root_at}` over the batch's own transaction; a private `tip()` and `cell()` | `store/view.rs` (module docs name a `ReadSnapshot`-backed view as "a later, separate implementor" — it is **not** this increment, §2.2) |
| The halt the tip must carry | **types landed, producer wired store-side** — `ConnectState` / `StoreInvariantRow` in `shekyl-rpc-types::chain`; `ChainStore::connect_state()` on the handle; `get_info` not wired, `CORE_RPC_VERSION` unchanged | `rust/shekyl-rpc-types/src/chain.rs`; `store/mod.rs` `connect_state`; DRS §7 S-CHAIN-W row "types only at this pin" |
| DRS-E2 has no subject yet | E2's replay needs a committed-chain reader to compare against LMDB; the row's own rationale for order 3 | DRS §7: "Split across increments, the two halves of one table's contract move separately and a digest mismatch cannot be localised to either" |

**No hard dependency on an unmerged PR.** Every input is on `dev`. The
increment branch cuts from `dev` after this document's PR merges — not
stacked on it (the S-CHAIN-W rule, §1 there).

---

## 2. Scope

### 2.1 In

- The 23 `BlockchainDB` methods of the DRS §7 S-CHAIN-R row, as **reads on
  `ReadSnapshot`** over the five tables S-CHAIN-W writes — `block_info`,
  `blocks`, `block_heights`, `block_burn`, `properties.total_burned` — with
  the 23 → 9 mapping of §3.2 (one Rust read per *distinct* table access, not
  one per C++ name).
- The by-height absence discipline: every by-height read returns
  `AtHeight<T>` (G11), classified against the tip exactly as `BatchView`
  does; a hole below the tip is SI-7, returned to the caller and **not**
  armed as a halt (DRS §3.6.2: reads do not own the writer's state).
- The tip as one read: `RecordedTip { height, hash, connect }` — the
  store-side value the daemon projects to `shekyl-rpc-types::chain::ChainTip`
  at cutover (§3.4, SCR-12).
- Range reads for the two windowed callers (`get_block_weights`,
  `get_long_term_block_weights`) and the one range iterator
  (`for_blocks_range`), as iterators over `block_info` / `blocks` (§3.5).
- **FL-R3-STORE** — the two per-block fold fields
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) routes to "the S-CHAIN-R surface":
  `cumulative_tx_count(h)` and `long_term_effective_median(h)`. They are
  **connect writes** with a read here; the write half is a one-phase
  S-CHAIN-W amendment carried by this increment because the read is the
  requirement (§3.6, SCR-10; shape **ruled** Q4 — two more `BlockInfo`
  fields, 88 → 104 B).
- One shared read body for the two transactions: `BatchView::block_at` and
  `ReadSnapshot::block(h)` decode and verify the same row the same way
  (§3.3, SCR-13) — the row's own reason for landing readers as one increment.

### 2.2 Out (named, so it is not scope shed by omission)

- **A `ChainView` impl for `ReadSnapshot`.** `view.rs` names it as "a later,
  separate implementor" for RPC-side re-validation and DRS-E5's `PoolView`
  decorator; it carries no batch brand by design. It is E5's, and nothing
  here pre-provisions it (SCR-16).
- **`get_info` / any daemon wiring.** The daemon serves LMDB at this pin;
  the `ChainTip.connect` field's producer and the `CORE_RPC_VERSION` bump
  land at cutover (DRS §7 S-CHAIN-W row). This increment ships the
  store-side value only.
- **The digest reader for redb** (`logical_state_digest_v0` over a
  `ReadSnapshot`). It needs a `spent_keys` scan — S-OUT-KI's
  `for_all_key_images` — and belongs to E2's first commit as a
  store-internal fold, not to this surface (SCR-11).
- **`get_block_cumulative_rct_outputs`** — ported as nothing: its only
  consumer chain is dead at HEAD (SCR-2). The method stays on the row so
  `check_drs_c_surface_map.py`'s count holds (the SCW-2 precedent).
- **`get_settlement_epoch_blocks_pin`** — already a read on the handle
  (`ChainStore::settlement_epoch_blocks()`, SCW-2); nothing new (SCR-6).
- **`hf_versions[h]` reads.** `get_hard_fork_version` is not in
  `blockchain.cpp`'s vocabulary (the `HardFork` class reads the DB
  directly), so it is in no DRS §3.5 surface; R4 owns what replaces the
  incremental window (DRS-W15). Not here.
- The C++ deletions this pre-flight makes eligible (SCR-2's dead chain).
  The countermand's RECORD-AND-SPECIFY default and rule 20 keep this a Rust
  increment; the C++ dies at cutover with the rest of the LMDB path.
- S-OUT-KI, S-TX, S-CURVE: the next surfaces in DRS §7's order. Named so
  that a read this increment finds convenient (an output lookup, a tx blob)
  is not smuggled in.

### 2.3 What DRS-E2 gets from this increment

E2's replay connects blocks through S-CHAIN-W and compares committed state
against LMDB. Before this increment the only committed-chain reads are the
generic `open_table` (bytes, no codec) and `BatchView` (inside a live batch).
After it, the comparison's chain half — heights, hashes, headers, every
`block_info` field, burns — is a typed read over a `ReadSnapshot`, taken
**after** commit, which is what DRS §6.3 ("checkpoint verification =
post-commit reopen reads") requires the harness to use.

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the reads live

On `ReadSnapshot` (`store/read.rs`), which already exists and is the only
read handle (`ChainStore::begin_read`). Two consequences of putting them
there rather than on a new type:

- A snapshot is one redb read transaction: every read in a sequence sees one
  committed state, so `tip()` followed by `block_info(tip.height)` cannot
  straddle a connect. The C++ has exactly this hazard and warns about it in
  prose (`src/cryptonote_core/blockchain.cpp:2735`–`:2738`: "no getheight +
  gethash(height-1)"). Here it is the handle's shape.
- `ReadSnapshot` currently carries `PhantomData<&'store ChainStore>`. This
  increment makes that a real `&'store ChainStore` so `tip()` can read the
  writer's halt (§3.4). Same lifetime, one field, no API change for
  existing callers.

The generic `open_table` / `open_multimap_table` narrow to `pub(crate)` in
this increment's last commit, once every table S-CHAIN-R reads has a typed
read (SCR-9 / Q3 — **ruled**, plain encapsulation): a raw handle on the
read side is the mirror of the raw `properties` handle the write side
already refuses (`PropertiesAreTyped`).

### 3.2 The mapping — 23 methods, 9 reads

Every C++ line is at `3560b80c2`. "Above tip" is the `AtHeight::AboveTip`
arm; "hole" is a row missing at or below the tip, which is SI-7
(`CellCorrupt { fault: Absent }`) — returned, never a value (§3.3).

| # | Rust read on `ReadSnapshot` | Returns | C++ methods it replaces (`src/blockchain_db/lmdb/db_lmdb.cpp` unless noted) | Table |
| --- | --- | --- | --- | --- |
| R1 | `tip()` | `Result<Option<RecordedTip>, StoreError>` — `None` for an empty chain; `RecordedTip { height, hash, connect }` | `height()` (`:3209`, = entry count = tip + 1 under SI-2), `top_block_hash(&h)` (`:3179`), `get_top_block_timestamp()` (`:2900`, via R3 at the tip), `get_top_block()` (`:3194`, via R6 at the tip) | `block_info` (last key) |
| R2 | `height_of(&BlockHash)` | `Result<Option<BlockHeight>, StoreError>` | `block_exists(h, &height)` (`:2720`), `get_block_height(h)` (`:2759`) | `block_heights` |
| R3 | `block_info(BlockHeight)` | `Result<AtHeight<BlockInfo>, StoreError>` — after Q4, the 104-byte record carrying `cumulative_tx_count` and `long_term_effective_median` too (§3.6) | `get_block_timestamp` (`:2815`), `get_block_weight` (`:2915`), `get_block_cumulative_difficulty` (`:3002`), `get_block_already_generated_coins` (`:3082`), `get_block_long_term_weight` (`:3105`), `get_block_hash_from_height` (`:3128`); `get_block_difficulty` (`:3027`) is **not a store read** — `shekyl-chain-rules` owns `difficulty_at` over two recorded cumulative values (Q1, **ruled**) | `block_info` |
| R4 | `block_infos(Range<BlockHeight>)` | iterator of `Result<(BlockHeight, BlockInfo), StoreError>`, clamped to `..=tip` | `get_block_weights(start, count)` (`:2992`), `get_long_term_block_weights(start, count)` (`:2997`) — both are `get_block_info_64bit_fields` (`:2938`) with an offset; the caller projects the field | `block_info` |
| R5 | `block_blob(BlockHeight)` | `Result<AtHeight<RawBlockBytes>, StoreError>` — the recorded bytes, **not** verified against `block_info.hash`, in a type no consensus path can consume without an explicit, greppable decode (Q2, **ruled**: a distinct return type, not a distinct name — §3.3) | `get_block_blob_from_height` (`:2789`); `get_block_blob(hash)` = R2 then R5 | `blocks` |
| R6 | `block(BlockHeight)` | `Result<AtHeight<RecordedBlockBody>, StoreError>` — `{ hash, block: shekyl_wire::Block }`, parsed and verified to hash to `block_info[h].hash` | `get_block_from_height` (`src/blockchain_db/blockchain_db.cpp:976`), `get_block(hash)` (`:986`) = R2 then R6 | `blocks` + `block_info` |
| R7 | `blocks(Range<BlockHeight>)` | iterator of `Result<(BlockHeight, RecordedBlockBody), StoreError>`, clamped to `..=tip` | `for_blocks_range(h1, h2, f)` (`:3905`) — the C++ re-hashes each blob (`:3931`–`:3933`); R7 reads the recorded identity and verifies the blob against it (SCR-7) | `blocks` + `block_info` |
| R8 | `block_burn(BlockHeight)` | `Result<AtHeight<u64>, StoreError>` — an absent row at or below the tip is **`Recorded(0)`**, the writer's own convention (S-CHAIN-W phase 8 writes no row for a zero burn) | `get_block_burn` (`:4890`) | `block_burn` |
| R9 | `total_burned()` | `Result<u64, StoreError>` — absent cell is `0` (nothing has burned; `connect` reads it the same way) | `get_total_burned` (`:5079`) | `properties` (`TotalBurnedCell`) |
| — | *(already a read)* `ChainStore::settlement_epoch_blocks()` | `SettlementEpochBlocks` | `get_settlement_epoch_blocks_pin` (`:5042`) — SCW-2 / SCR-6 | header cell |
| — | *(not ported)* | — | `get_block_cumulative_rct_outputs` (`:2838`) — SCR-2 | — |

Twenty-three names; nine reads plus one existing accessor plus one
not-ported. The count on the DRS §7 row stays 23 (the surface-map gate
derives it from `blockchain.cpp`, not from this table).

### 3.3 Absence, faults, and what a read may not do

- **By-height reads return `AtHeight<T>`** (the rules crate's type, already
  a dependency of this crate through `BatchView`). `AboveTip` only above the
  dense tip; a missing `block_info` or `blocks` row at or below it is SI-7
  `CellCorrupt { key, fault: Absent }`. This is `BatchView::block_at`'s
  classification, verbatim (`store/view.rs` module docs), and the reason is
  the same: a hole that reads as "not yet" is the LMDB
  `curve_tree_roots[0]` defect in a new coat.
- **By-hash reads return `Option`.** `height_of` is not a by-height lookup;
  G11's rule is about heights, where absence has two meanings. A hash the
  chain does not contain has one.
- **Every decode is SI-7.** `BlockInfo::decode`, `Block::from_bytes`, the
  `u64` codecs — an undecodable row is `CellCorrupt { fault: Undecodable }`.
  The C++ reads `block_info` by `reinterpret_cast` and `total_burned` by an
  unchecked 8-byte `memcpy` (`:5097`; `get_block_burn` at `:4906`–`:4909`
  *does* check) — SCR-5. The Rust side is uniformly strict.
- **A read never arms the halt.** DRS §3.6.2 rules it: the halt is the
  writer's state; a read that hits SI-7 returns the error and the writer
  arms it the next time it touches the cell. `ReadSnapshot` has no
  `Poison`; the SI-7 it returns is a plain `StoreError::InvariantViolated`.
  This is the one behavioural difference from `BatchView`, and it is the
  batch's poison arm, not the classification, that differs (SCR-13).
- **The block body is verified where it is decoded.** R6/R7 parse the blob
  and refuse (SI-7, `blocks` undecodable) when it does not hash to
  `block_info[h].hash` — `BatchView::block_at`'s check, in the shared body.
  R5 hands out bytes for the sync path and does not hash them (Q2).
- **Unverified bytes are a type, not a name (Q2, ruled).** `RawBlockBytes`
  is a newtype over the recorded blob with no `Deref<[u8]>`, no `AsRef`, and
  no `From` into `Block` or `RecordedBlockBody`; its only outward path is
  `into_wire_bytes(self) -> Vec<u8>` for the relay/sync writer, and its only
  path into a parsed block is R6 (which re-reads and verifies) — never a
  method on the newtype. Two readers that differ only by name are a
  plausible review miss (a consensus caller reaching for the cheap one); a
  return type that cannot occupy a consensus position is the `ChainValid`
  move — make the unsafe-for-this-purpose thing unrepresentable there,
  not merely differently named. `rg RawBlockBytes` is the audit.
- **`difficulty(h)` is not a read here (Q1, ruled), and the reason
  generalises.** Per-block difficulty is a consensus computation;
  cumulative difficulty is the stored quantity. C2-R8 bans the store from
  computing consensus-visible values, and this is the first time that ban
  constrains the **read** surface — R8 was argued entirely around writes.
  Nor is it "the caller's": that is how one `checked_sub`, with one `h = 0`
  arm and one missing-row arm, gets written three times slightly
  differently. `shekyl-chain-rules` owns `difficulty_at` — one
  implementation in the crate whose job is consensus arithmetic, landing
  with E6 slice 2 (4.D), reading `cumulative_difficulty` off the view's
  `RecordedBlock` once that field grows (`CHAIN_RULES_CRATE.md` §13). The
  store exposes the recorded value (R3) and nothing derived from it.

### 3.4 The tip, and the halt it carries

```rust
pub struct RecordedTip {
    pub height: BlockHeight,
    pub hash: BlockHash,
    /// `ChainStore::connect_state()` read *after* the snapshot was taken.
    pub connect: ConnectState,
}
```

`ConnectState` is the store's own (`store/halt.rs`), not the wire enum; the
daemon projects `StoreInvariant::row()` into `StoreInvariantRow` at the
`get_info` producer (DRS §3.6.2, "one expression at the writer that mints the
halt"). Carrying it on the store-side tip is SCR-12 / Q5: the §3.6.2 hazard
is a reader that returns a stale tip without saying so, and a `tip()` that
cannot omit the field is cheaper than a test in the adapter that remembers
to read two things.

Ordering is sound because the halt is monotonic: a snapshot taken before a
halt latched shows a tip the failed write did not move (the refusing
transaction rolled back), and `connect` read after `begin_read` is either
`Live` (true of the snapshot) or `Halted { at_height ≥ tip }` (also true —
the write that halted would have been at `tip + 1`).

`None` for an empty chain replaces three C++ sentinels — `null_hash`,
timestamp `0`, and a default-constructed `block` — and one underflow:
`top_block_hash(&h)` writes `*block_height = m_height − 1` at `:3185`
**before** the `if (m_height != 0)` guard at `:3186`, so an empty chain
hands back `UINT64_MAX` beside `null_hash` — two sentinels, neither
distinguishable from data (SCR-4, both anchors verified at review).

**`Option` stays `Option` (ruled).** Do not upgrade it to a bespoke absence
type for symmetry with `AtHeight`. A custom absence type earns its keep when
the default value lies *inside* the valid range of the type — `[0u8; 32]` is
a valid `curve_tree_roots` encoding, which is the whole CEN-I12 defect —
and here it does not: there is no "zero tip" that reads as data. `None` is
already unrepresentable as a tip. Someone will propose the enum for
consistency; it would buy nothing.

### 3.5 Ranges

`block_infos(range)` and `blocks(range)` take a half-open `Range<BlockHeight>`
and yield rows in ascending height, stopping at the tip: the C++
`get_block_info_64bit_fields` clamps with `height < h && count--`
(`:2955`) and returns fewer rows than asked without saying so; here the
caller counts what it got, which is the same information stated once. A
range that starts above the tip yields nothing (not an error: the C++ does
the same). `for_blocks_range`'s early-stop closure becomes the caller's
`take_while` / `?` — an iterator is the shape that lets the sync path stop
without a callback. The two callers that motivate ranges: the
`CRYPTONOTE_REWARD_BLOCKS_WINDOW` median (`blockchain.cpp:1581`) and the
100 000-block long-term median seed (`:1624`; `relay_floor_ring.cpp:194`).
Decoding 88 bytes instead of reading 8 per row is not measurable at those
sizes and buys one codec path.

### 3.6 FL-R3-STORE — the per-block fold fields (S-CHAIN-W amendment A1)

[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) FL-R3-STORE owes this surface two
O(1) per-height reads, each with a consensus bit-identity gate:

| Field | What it is | Who computes it | Read | Write |
| --- | --- | --- | --- | --- |
| `cumulative_tx_count(h)` | `Σ_{i ≤ h} \|tx_hashes(i)\|` — non-coinbase transactions through `h` (`FEE_LADDER_DERIVATION.md` §10.12.2) | **the store**: a count of what it records, the `rct_outputs` precedent (`BlockInfo` docs: "a storage count the store does maintain"); `checked_add` under SI-8 | `AtHeight<u64>` | `connect`, from `valid.block().transaction_hashes.len()` and the parent's value |
| `long_term_effective_median(h)` | the 100 000-block long-term weight median the daemon overwrites each block and cannot step backwards (FL-R23 amendment) | **not the store** — it is a consensus computation (C2-R8 Q4); it arrives as a `ConnectFacts` field with `Origin`, `DeletedBy` = CEN-G6 / CEN-G6b (slice 7), exactly like `long_term_weight` | `AtHeight<u64>` | `connect`, passed through |

Both are connect writes, so both need a row per block that the undo log
reverses — which the journaling verbs give any table for free.

**Shape — Q4 RULED 2026-09-16, overturning the default.** The default
proposed a Rust-only `block_fold` table on the ground that `BlockInfo` is
"the LMDB struct minus the key" and its 88 bytes are what E2 diffs. That
ground does not exist: zerokval is an LMDB `DUPSORT` workaround that
`schema.rs` already collapses, so the redb schema *already* diverges
structurally from LMDB on those tables and the comparator was always going
to compare logical content through per-table projections. Byte parity was
imported from a document that describes Monero's storage, not one that
specifies ours (DRS §7.6 states the actual constraint once: consensus-visible
bytes — hash preimages and the digest fold input — and nothing else). So
the choice is decided **on the codec**: both fields are fixed-width `u64`,
the same shape as every other `BlockInfo` field → **widen the record, 88 →
104 B**, one read, no second table, no permanent `RUST_ONLY_TABLES` entry.
A separate table is the right answer for anything variable or optional,
because bolting variability onto a fixed-width record is where codecs get
ugly; neither field is. Transitional legibility of the E2 projection is
worth something during E2 and nothing after, so it does not decide a
permanent structure. `codec/chain.rs`'s module docs lose the "LMDB struct
minus the key" framing in the same commit (rule 91: a doc that argues from
a constraint that does not exist will be quoted). Rule-42 layout change
either way: `SCHEMA_VERSION 2 → 3`, snapshot tests move. The paired-bump
gate firing in the second increment running is the gate doing its job
under rebuild-never-migrate.

**The counter goes up, and that is not regression.** `ConnectFacts`
gains a seventh field with `Origin::PassedThrough`, so
`ConnectFacts::passed_through().count()` rises by one when this lands. That
number is **the set of facts the store does not derive** — it grows as
facts are discovered and shrinks as E6 lands the rows that derive them
(`DeletedBy`). It is not a progress bar, and an increase is not a
regression; a reader who takes it as one will file the finding this
sentence pre-empts. The same sentence is written on the method's doc
comment in `store/connect.rs` by this PR, because that is where the next
reader meets the number.

The gate the requirement names (rule 47, §10.12.2): on a regtest chain with
empty blocks, a pop and a reorg, `cum(h) − cum(h−1) == |tx_hashes(h)|` at
**every** height, and the derived window equals the blob walk's at every
height. The store test is the first half (against its own `blocks` rows,
through pop and re-connect); the second half is the consumer's when
`get_tx_volume_window` moves. The walk it retires is
`blockchain.cpp:1917` (`get_tx_volume_window`) and the stepped median at
`relay_floor_ring.cpp:181`–`:200`; neither is touched here (rule 20 —
their deletion is the cutover's).

### 3.7 Types this increment adds to the store crate

| Item | Where | Why |
| --- | --- | --- |
| `RecordedTip { height, hash, connect }` | `store/read.rs` | R1 (§3.4) |
| `RecordedBlockBody { hash, block }` | `store/read.rs` | R6/R7 — the identity is `block_info`'s and the body is verified against it; a bare `Block` would let a caller re-hash and disagree |
| `BlockInfo::{cumulative_tx_count, long_term_effective_median}` — two `u64` fields, record 88 → 104 B; `FIXED_WIDTH = Some(104)` | `codec/chain.rs` | §3.6 (Q4 ruled) |
| `RawBlockBytes` — newtype over the recorded blob; `into_wire_bytes` only; no `Deref`/`AsRef`/`From<_> for Block` | `store/read.rs` | R5 (Q2 ruled) |
| `ConnectFacts::long_term_effective_median: Fact<u64>` (+ its `DeletedBy` row; `DELETED_BY` becomes `[_; 7]`, `PassedThroughFacts` positions widen by one — a layout change to that cell's encoding) | `store/connect.rs`, `codec/evidence.rs` | §3.6 |
| `chain_reads` (private): `tip_of`, `cell`, `block_body` generic over `redb::ReadableTable` | `store/chain_reads.rs` | one body for `BatchView` and `ReadSnapshot` (SCR-13) |

No new `StoreError` variant, no new `SI-` row (§5).

### 3.8 What this surface inherits, and for how long

The tables §4 lists are Monero's partition in a different engine. That is
the parity-first choice, and it is **transitional**: DRS §7.6 (minted at
this document's review) records that the ported partition is reopened
after cutover with the consensus-visible encodings named as the part that
is not, that every deviation reproduced during the port is repaired
afterwards in Rust only, and that the comparator gates cutover while
`ratified / enforced` gates release. This increment reproduces the read
semantics the row names (§3.5's clamp, §3.3's absent-burn-is-zero) and
corrects only what parity cannot see (SCR-4's sentinels, SCR-5's unchecked
read — read-side shapes the comparator never observes). Anything it
reproduces knowingly is listed in §6.1 in the form §7.6 item 1 requires.

---

## 4. The read set, table by table

| Table | Key → value (codec) | Reads here | Written by | Absence semantics |
| --- | --- | --- | --- | --- |
| `block_info` | `u64 → BlockInfo` (88 B → **104 B** after §3.6: `+ cumulative_tx_count, long_term_effective_median`) | R1 (last key), R3, R4, R6/R7 (identity), `cumulative_tx_count`, `long_term_effective_median` | `connect` phase 6 (the two new fields: amendment A1, journaled with the row) | dense `0..=tip` (SI-2): hole = SI-7 |
| `blocks` | `u64 → &[u8]` (wire `Block`) | R5, R6, R7 | `connect` phase 6 | dense `0..=tip`: hole = SI-7; body must hash to `block_info[h].hash` |
| `block_heights` | `LmdbHashKey → u64` | R2 | `connect` phase 6 | absent = not this chain's block (`None`) |
| `block_burn` | `u64 → u64` | R8 | `connect` phase 8, **only if** `h > 0 && burned > 0` | absent at or below tip = `0` (writer convention; `blockchain.cpp:6148`) |
| `properties["total_burned"]` | `TotalBurnedCell: u64` | R9 | `connect` phase 8 (`checked_add`, SI-8) | absent = `0` (nothing has burned yet) |

`curve_tree_roots` is read by `BatchView::root_at` and will be by E2's
digest; it is **not** on this surface's row (S-CURVE owns the tree's reads),
and this increment adds no snapshot read for it.

---

## 5. Store invariants this increment builds

None new. The register's rows are enforced at the write; this increment is
reads. What it *uses*:

- **SI-7** on every decoded row and cell, returned as
  `StoreError::InvariantViolated(CellCorrupt { .. })`, never as a value and
  never as `AboveTip`.
- **SI-2**'s density as the classifier for `AboveTip` vs hole (§3.3).
- **SI-8** for `cumulative_tx_count`'s `checked_add` at the write (§3.6) —
  the existing row, one more accumulator under it; the register's SI-8 cell
  gains the field name in the same PR.

The register's `Status` cells do not move.

---

## 6. Round-0 findings

Each finding names its substrate and its disposition. Dispositions marked
**→ §9** are questions for round 1; the rest are taken into §3 / §7.

| Id | Finding | Evidence (`3560b80c2`) | Disposition |
| --- | --- | --- | --- |
| **SCR-1** | Seven of the 23 methods are one `block_info` decode with a different field projected (timestamp, weight, cumulative difficulty, coins, long-term weight, hash — plus difficulty as a subtraction). Porting them one-to-one would be seven readers of one 88-byte row. | `db_lmdb.cpp:2815`, `:2915`, `:3002`, `:3027`, `:3082`, `:3105`, `:3128` — each is `RCURSOR(block_info)` + `MDB_GET_BOTH` + one field | One read `block_info(h) -> AtHeight<BlockInfo>` (R3); callers project. The 23 → 9 table in §3.2 is the increment's shape. |
| **SCR-2** | `get_block_cumulative_rct_outputs` has exactly one caller, `Blockchain::get_output_distribution` (`blockchain.cpp:2661`–`:2663`; anchor verified at review); that function's only caller is `core::get_output_distribution` (`cryptonote_core.cpp:1198`), which **nothing calls**: the daemon RPC asserts `/get_output_distribution.bin` is *not* served (`rust/shekyl-daemon-rpc/src/server.rs:727`, `:881`) and `rpc_handler.cpp:29`'s helper has no caller. The method is the ring-decoy distribution rule 60 deleted from the wallet. | `rg get_output_distribution src rust` — no live producer | **Not ported.** The name stays on the DRS §7 row so the surface-map gate's 23 holds (SCW-2 precedent: a row entry can be marked not-a-read without leaving the vocabulary). S-OUT-KI's `get_output_distribution` is dead by the same chain — noted for that lane. The C++ is not deleted here (rule 20, countermand). **Q6 RULED:** no FOLLOWUPS row — the surface row is the finding's home; a queue row would outlive its subject when the C++ goes. |
| **SCR-3** | `get_block_difficulty(h)` is `cum(h) − cum(h−1)` (`db_lmdb.cpp:3027`–`:3040`): arithmetic over two recorded values, in the store. C2-R8 Q4 is about the store *deriving* consensus-visible values at the write; a read-side subtraction is not that, but it is arithmetic the store would own and could get wrong (a corrupt row with `cum(h) < cum(h−1)` underflows `u128`). | one caller, `Blockchain::block_difficulty` (`blockchain.cpp:2741`), already an unlocked read-only wrapper | **Q1 RULED:** no store method — C2-R8 constraining a read for the first time (§3.3). Refined: not "the caller's" either; `shekyl-chain-rules` owns `difficulty_at` (E6 slice 2), one implementation. |
| **SCR-4** | Empty-chain sentinels: `top_block_hash` returns `null_hash` and writes `*block_height = m_height − 1` before the `m_height != 0` check (`:3185`, `:3191`) — `u64::MAX` beside a null hash; `get_top_block_timestamp` returns `0` (`:2907`); `get_top_block` returns a default-constructed `block` (`:3204`). | `:3185` (the write) precedes `:3186` (the guard) — both anchors verified at review | `tip()` returns `Option<RecordedTip>`; there is no sentinel and no field an empty chain can populate. Callers that today compare against `null_hash` (`blockchain.cpp:1168`, `:6641`) match on `None` at cutover. **Ruled: `Option` is not upgraded** — a bespoke absence type earns its keep only when the default lies inside the type's valid range (§3.4). |
| **SCR-5** | `get_total_burned` `memcpy`s 8 bytes from the cell without checking `mv_size` (`:5097`); `get_block_burn` two hundred lines earlier does check (`:4906`–`:4909`) and names the height in its error. Same value type, two disciplines. | as cited | Both go through the `u64` `Canonical` codec (fixed 8): a short or long cell is SI-7 on either read. Recorded as a divergence the C++ cannot exhibit on its own writes (it always writes 8), visible only on a corrupted file — the read is stricter, never looser. |
| **SCR-6** | `get_settlement_epoch_blocks_pin` (`:5042`) returns `0` when absent; its one caller (`blockchain.cpp:515`) is the open-time compare against the session's schedule. SCW-2 already re-homed the *pin* as the `settlement_epoch_blocks` header cell checked at every open with a typed refusal. | `ChainStore::settlement_epoch_blocks()` (`store/mod.rs:287`); `header::verify` | Already a read; nothing added. The `0`-when-absent arm does not survive: an absent pin is `StoreInvariant::CellCorrupt` at open, not a store that reports epoch `0`. |
| **SCR-7** | `for_blocks_range` parses each blob and **recomputes** its hash (`:3931`–`:3933`) rather than reading `block_info`'s. `BatchView::block_at` (S-CHAIN-W) reads the recorded identity and verifies the blob hashes to it. Two readers of one table with two notions of the block's identity is the drift this row exists to prevent. | `store/view.rs` `block_at`; `db_lmdb.cpp:3905`–`:3945` | R6/R7 use the recorded identity and verify the blob against it, in the shared body (SCR-13). A blob that hashes to something else is SI-7 on `blocks`, the same outcome `BatchView` gives a rule. |
| **SCR-8** | The block-sync path hands out raw blobs without parsing (`blockchain.cpp:2505`, `:2769` → `get_block_blob_from_height`). Verifying every blob against `block_info.hash` on that path is one hash per served block that the C++ does not pay, and the receiving peer validates the block anyway. | as cited | **Q2 RULED:** R5 returns the recorded bytes unverified — as **`RawBlockBytes`**, a distinct type no consensus path can consume without an explicit decode (§3.3), not merely a distinct method name; R6/R7 verify. Re-verifying to forward bytes is waste; a consensus caller reaching for the cheap one by name is the review miss the type forecloses. |
| **SCR-9** | `ReadSnapshot::open_table` / `open_multimap_table` are `pub` and generic over any `TableDefinition`: after this increment every S-CHAIN-R table has a typed read, and the raw handle lets a caller bypass the codec and the SI-7 classification. The write side already refuses the equivalent (`StoreCannot::PropertiesAreTyped`, no raw `properties` handle). Zero external callers today. | `store/read.rs:45`, `:63`; `rg` for callers | **Q3 RULED:** narrow to `pub(crate)` in this increment's last commit (the tests that use it are in-crate). Reopener: a surface whose tables have no typed read yet (S-OUT-KI, S-TX) lands its own reads rather than re-widening this. |
| **SCR-10** | FL-R3-STORE routes two per-block fields to this surface and names the falsifier `rg cumulative_tx_count rust/shekyl-chain-store`. Both are **writes** on the connect path S-CHAIN-W just landed; the read is trivial once the row exists. One of them (`cumulative_tx_count`) is a count of what the store records (the `rct_outputs` precedent); the other (`long_term_effective_median`) is a rolling median — a consensus computation the store must not perform (C2-R8 Q4) and therefore a passed-through `ConnectFacts` field. | `docs/FOLLOWUPS.md` FL-R3-STORE; `FEE_LADDER_DERIVATION.md` §10.12.2; `codec/chain.rs` `rct_outputs` doc; `store/connect.rs` `ConnectFacts` | In scope as **S-CHAIN-W amendment A1** carried here (§3.6): the FOLLOWUPS routing is explicit, and rule 22 lands scoped work where it is scoped. **Q4 RULED against the default:** widen `BlockInfo` (88 → 104 B) — decided on the codec (both fields fixed-width), the "LMDB struct" ground withdrawn (§3.6, DRS §7.6). **Consequence named:** `passed_through().count()` rises by one; not a regression (§3.6). |
| **SCR-11** | E2's redb-side digest v0 needs three reads: every block hash in height order (this surface, R4), every spent key image (`spent_keys` scan — S-OUT-KI's `for_all_key_images`), and the live curve root (S-CURVE's `get_curve_tree_root` in LMDB; in redb equal to `curve_tree_roots[tip + 1]` by SI-4). The LMDB reader is `logical_state_digest.cpp:60`–`:86`. A digest reader that waits for three surfaces' public reads delays E2 by two increments for a fold that reads tables directly. | as cited; `rust/shekyl-chain-store/src/digest_v0.rs` takes slices | **Q7 RULED:** `ReadSnapshot::digest_v0()` is a store-internal fold landing in **E2's first commit**, reading `block_info`, `spent_keys` and `curve_tree_roots` directly (the accumulator module's contract, not a surface method). Not this increment — it is E2's instrument, and landing it here would be a callee with no caller (rule 22). |
| **SCR-12** | `ReadSnapshot` holds `PhantomData<&'store ChainStore>` — it cannot reach `connect_state()`. DRS §3.6.2's hazard is a reader that returns a stale tip after a halt without saying so, and its ruling puts the halt "on the tip itself, not in a log line". A store-side `tip()` that omits it leaves the adapter to remember two reads. | `store/read.rs:27`–`:30`; DRS §3.6.2 | **Q5 RULED:** `ReadSnapshot` holds `&'store ChainStore`; `RecordedTip` carries `connect` (§3.4) — the halt where a wallet actually reads it, which was §3.6.2's point. Ordering argument in §3.4. |
| **SCR-13** | `BatchView` has private `tip()` / `cell()` / `absent_below_tip()` / `blocks_invalid()` helpers over `self.batch.txn()`; `ReadSnapshot` would need the same over `self.txn`. redb's `ReadableTable` is the trait both transaction types' tables implement. Two copies of the decode-verify-classify body is exactly "the two halves of one table's contract moving separately". | `store/view.rs:97`–`:153` | One private `chain_reads` module generic over `impl ReadableTable`, returning the raw classification (`Ok(None)` for hole, `Err(CodecError)` for undecodable, hash mismatch as a typed enum); `BatchView` wraps each outcome in `self.poison().arm(..)`, `ReadSnapshot` in `StoreError::from(..)`. The **only** difference between the two implementors is the poison arm, and it is at the wrap, not in the body. |
| **SCR-14** | `height()` in the C++ vocabulary is `blocks`' entry count (`mdb_stat`, `:3220`) and 54 call sites in `blockchain.cpp` use it as "tip + 1". Under SI-2 the two agree; a store that offered both a count and a tip would let them disagree on a corrupt file and let a caller pick the one that looks right. `ChainTipFactsFfi.chain_height` is documented as "top block height + 1" (`rust/shekyl-daemon-rpc/src/ffi.rs:339`). | as cited | One read, `tip()`; no count method. "Chain height" is the adapter's `tip.height + 1` (or `0`), computed where the wire field is filled. A count read reopens only if a caller needs the count of a table SI-2 does **not** make dense — none on this surface. |
| **SCR-15** | `get_block_weights(start, count)` silently returns fewer than `count` when the window runs past the tip (`get_block_info_64bit_fields`, `:2955`: `height < h && count--`); `Blockchain::get_last_n_blocks_weights` pre-clamps `start_offset` (`blockchain.cpp:1580`) so it never observes the short return, and the long-term-median seed passes `min(N, oldest)` (`relay_floor_ring.cpp:192`) for the same reason. | as cited | `block_infos(range)` clamps to `..=tip` and yields what exists; the callers' pre-clamps become redundant and the length is the caller's to read. Stated so that a port does not add a "count must fit" refusal the C++ never had, nor drop the clamp. |
| **SCR-16** | `view.rs` names a `ReadSnapshot`-backed `ChainView` for RPC-side re-validation and E5's `PoolView` as "a later, separate implementor". With typed reads landing on `ReadSnapshot` the impl is a few lines, and the temptation to add it "while here" is real. | `store/view.rs:19`–`:22`; `CHAIN_RULES_CRATE.md` §13 (`PoolView` — DRS-E5) | **Out**, named in §2.2. It carries no brand, so it cannot mint a `ChainValid` that `connect` accepts; its consumer (pool admission) does not exist yet; adding it is pre-provisioning (rule 21). E5 adds it with its `PoolView`. |

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

The form §7.6 requires: each knowingly-reproduced deviation with its
ratified state, so the repair phase's one query finds it here.

| Reproduced | Where | Ratified state ("what correct looks like") | Why reproduced now |
| --- | --- | --- | --- |
| **None.** | — | — | Every C++ read-side irregularity this pre-flight found is corrected in the port rather than carried: SCR-4's two empty-chain sentinels → `Option<RecordedTip>`; SCR-5's unchecked `memcpy` → SI-7 on the `u64` codec; SCR-7's re-hash-instead-of-record → recorded identity verified. These are **read-side shapes the comparator never observes** (the diff compares committed content), so correcting them costs parity nothing — the test that distinguishes "correct now" from "reproduce, repair later" is whether the comparator would see the difference. §3.5's clamp and §3.3's absent-burn-is-zero are *behaviours*, not deviations: they are the writer's own conventions, read back. |

The S-CHAIN-W-side items that **are** reproduced knowingly — `output_amounts`
keyed verbatim under R8b-2 (SCW-8), `bi_cum_rct` per-block under the dead
v4 arm (CEN-L15) — belong to that increment's record and to the query, not
to this table.

---

## 7. Commit sequence (rule 90; one PR, ≤ 8 commits, cut from `dev` after this document merges)

1. `store: chain_reads — one decode/verify/classify body for BatchView and ReadSnapshot` — the private generic module; `BatchView` rewired onto it (SCR-13, SCR-7); no behaviour change; `view_tests.rs` green unchanged.
2. `store: ReadSnapshot::{tip, height_of, block_info, block_infos}` — R1–R4; `RecordedTip` with `connect` (Q5); `ReadSnapshot` holds `&'store ChainStore`; tests: empty chain → `None`; tip after `connect`; `AboveTip` above it; a deleted `block_info` row below it → SI-7 **without** halting the writer (`connect_state()` stays `Live` — the read-side half of §3.6.2, pinned).
3. `store: ReadSnapshot::{block_blob, block, blocks}` — R5–R7; `RecordedBlockBody`; `RawBlockBytes` (Q2 — a `compile_fail` doctest pins that it does not deref to `[u8]` and does not convert into `Block`); tests: body hashes to identity; a rewritten blob → SI-7 on `block`/`blocks`, bytes still returned by `block_blob`; range clamps at the tip.
4. `store: ReadSnapshot::{block_burn, total_burned}` — R8–R9; tests: zero-burn block reads `Recorded(0)` with no row; genesis burn reads `0`; the cell after two burns is their sum (against `connect`'s `checked_add`).
5. `store: BlockInfo carries cumulative_tx_count and long_term_effective_median (FL-R3-STORE; S-CHAIN-W amendment A1)` — `BlockInfo` 88 → 104 B (Q4), `codec/chain.rs` module docs re-grounded (no "LMDB struct minus the key"), `ConnectFacts` field + `DeletedBy` row + `passed_through()` doc sentence, `connect` writes both fields (the count as `checked_add` under SI-8 from the parent's row), the two reads, `SCHEMA_VERSION 2 → 3`, snapshot moves; the §3.6 gate test (empty blocks, pop, re-connect; `cum(h) − cum(h−1) == |tx_hashes(h)|` at every height).
6. `store: narrow ReadSnapshot::open_table to pub(crate)` (Q3) — the in-crate tests keep it; no external caller.
7. `docs: S-CHAIN-R landed — DRS §7 row, §3.6.3 pointers, register SI-8 cell, FOLLOWUPS FL-R3-STORE, index, CHANGELOG; archive DRS_E1_SCHAIN_W.md` (§10).

Every question is ruled; all seven commits may start once this document
merges. Each commit builds, `fmt`/`clippy` clean, tests green (rule 26 B5).

---

## 8. Denominator — what must stay green, what must be extended

**Unchanged and green throughout:** `cargo test -p shekyl-chain-store`
(201 tests at `3560b80c2`); `check_redb_schema_bijection.py` (no table is
added — Q4 widened a record instead — so the map is untouched);
`check_redb_schema_key_types.py`; `check_store_invariant_register.py` (no
`StoreInvariant` variant is added or removed); `check_store_error_conversion_ban.py`;
`check_chain_rules_no_store.sh` (this crate depends on the rules crate,
never the reverse); `check_drs_c_surface_map.py` (the row's method list and
count 23 are untouched); `check_lmdb_schema_coverage.py`.

**Extended:** the codec snapshot tests move with `SCHEMA_VERSION 3`
(commit 5) — a `.snap` diff in the same commit, reviewed as a layout
change; the paired-bump gate fires and is satisfied by the same commit;
the property catalogue is unchanged (no new cell).

**New:** the read-side tests listed per commit in §7; the FL-R3 gate test.
Every test that asserts a `StoreError` asserts the **variant** (`CellCorrupt
{ key: "blocks", .. }`), never `is_err()`.

---

## 9. Round-1 questions — RULED 2026-09-16 (each ruling line-local)

| Q | Question | Ruling | The record |
| --- | --- | --- | --- |
| **Q1** (SCR-3) | Does the store offer `difficulty(h)`? | **RULED 2026-09-16 — default approved, refined.** No store read; **and not "the caller's" either** — `shekyl-chain-rules` owns `difficulty_at`, landing with E6 slice 2 (4.D). | The reason generalises and is stated in §3.3: per-block difficulty is a consensus computation, cumulative difficulty the stored quantity; C2-R8 bans the store from computing consensus-visible values, and this is the first time the ban constrains the **read** surface (R8 was argued around writes). Leaving it to "the caller" is how one `checked_sub` with one `h = 0` arm gets written three times slightly differently. One implementation, in the crate whose job is consensus arithmetic. |
| **Q2** (SCR-8) | Does `block_blob(h)` verify the bytes against `block_info[h].hash`? | **RULED 2026-09-16 — default approved, with a distinct return type rather than a distinct name.** `RawBlockBytes` (§3.3, §3.7). | An unverified reader is correct for the relay path — re-verifying to forward bytes is waste. The hazard is `block_blob` and `block` differing only by name; a consensus caller reaching for the cheap one is a plausible review miss. The `ChainValid` move: make the unsafe-for-this-purpose thing unrepresentable in that position. |
| **Q3** (SCR-9) | Narrow `ReadSnapshot::open_table` / `open_multimap_table` to `pub(crate)`? | **RULED 2026-09-16 — default approved** (commit 6). | Plain encapsulation; zero external callers at the pin; later surfaces land their own typed reads. |
| **Q4** (SCR-10) | Shape of the FL-R3 fields: a Rust-only `block_fold` table, or two more `BlockInfo` fields? | **RULED 2026-09-16 — default OVERTURNED: widen `BlockInfo`, 88 → 104 B.** | The default's ground — `BlockInfo` is "the LMDB struct minus the key" and its bytes are what E2 diffs — imported a constraint that does not exist: zerokval is already collapsed in `schema.rs`, so the redb schema already diverges structurally and the comparator compares logical content through projections; layout was never the constraint (DRS §7.6 states the real one once — consensus-visible bytes). Decide on the codec: both fields are fixed-width, so widen the record — one read, no second table, no permanent lead-table entry. A separate table is for anything variable or optional. Transitional legibility of the projection decides nothing permanent. `SCHEMA_VERSION 2 → 3` is fine under rebuild-never-migrate; the paired-bump gate firing is the gate working. |
| **Q5** (SCR-12) | Does the store-side `RecordedTip` carry `connect: ConnectState`? | **RULED 2026-09-16 — default approved.** | Puts the halt where a wallet actually reads it, which was §3.6.2's point. |
| **Q6** (SCR-2) | Does the dead `get_output_distribution` chain get a FOLLOWUPS deletion row? | **RULED 2026-09-16 — default approved: no row.** | The surface row is the right home; a FOLLOWUPS row would outlive its subject when the C++ goes. |
| **Q7** (SCR-11) | Where does the redb-side digest v0 reader land? | **RULED 2026-09-16 — default approved: E2's first commit.** | The reader has no subject until E2. |

**Also ruled at the same review, outside the numbered questions:** SCR-4's
`Option<RecordedTip>` is not upgraded to a bespoke absence type (§3.4);
SCR-10's `passed_through()` increase is named as not-a-regression beside the
counter (§3.6, `store/connect.rs`); and DRS **§7.6** was minted — the
transitional partition, the encoding constraint stated once, parity-then-
repair in Rust with the comparator gating cutover and `ratified / enforced`
gating release (§3.8 points at it).

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md`: banner (E1 increment 4 landed); §7 S-CHAIN-R row (LANDED; `get_block_cumulative_rct_outputs` marked not-ported per SCR-2, `get_settlement_epoch_blocks_pin` marked already-a-read per SCR-6, count kept 23); §3.6.3 implementation pointers (the read handle); decision-log row.
- `STORE_INVARIANT_REGISTER.md`: SI-8 cell gains `cumulative_tx_count` (commit 5). No status moves.
- `docs/FOLLOWUPS.md` FL-R3-STORE: **removed** when commit 5 lands (its falsifier returns) — the consumer-side migration (`get_tx_volume_window`, the ring's cold path) is the cutover's and is named in the DRS §7 row, not re-queued.
- `LMDB_SCHEMA.md` / `LMDB_WRITE_ATOMICITY_AUDIT.md`: no change (no LMDB table changes; the widened `BlockInfo` is the redb record — `LMDB_SCHEMA.md`'s `block_info` row describes LMDB's 96 bytes and stays true of LMDB).
- `codec/chain.rs` module docs: the "LMDB struct minus the key" framing goes (commit 5); the record is described by what its bytes hold and which are consensus-visible (none of `BlockInfo`'s — the block hash is a preimage-derived identity *stored* here, not *defined* here).
- `IMPLEMENTATION_INDEX.md`: `SCR` family and §7 doc row (this PR); the `DRS-*` row `UPDATE` for the increment is the increment PR's (rule 94 §4).
- `docs/CHANGELOG.md`: one Unreleased line at landing (`SCHEMA_VERSION` 2 → 3 is a rebuild; the reads are a crate API).
- **Archive:** [`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md) `git mv` to `docs/completed/` in the increment's commit 7 — its stated archive condition is "S-CHAIN-R has consumed the codecs", and commit 4 does. Its index §7 row moves with it.
- This document: banner flips to *landed* at the increment PR; archive-or-contract per index §8 when S-OUT-KI's pre-flight has read it (the next surface's pre-flight is the reader this document exists for).

---

## 11. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-16 | Round 0 executed at `dev` `3560b80c2` (post-#757). Sixteen findings (SCR-1…SCR-16); seven routed to round 1 as Q1–Q7 with defaults; the rest dispositioned into §3 and §7. Contract §3 **proposed, not ruled**. FL-R3-STORE taken into scope as S-CHAIN-W amendment A1 on FOLLOWUPS' explicit routing (rule 22). |
| 2026-09-16 | **Round-1 rulings (maintainer, same day; PR #760 remote review).** Both SCR-2 and SCR-4 anchors verified at source. Q1 approved and refined — no store `difficulty(h)`, **and** not the caller's: `shekyl-chain-rules` owns `difficulty_at`; the row states that C2-R8 constrains a read for the first time. Q2 approved as a distinct **type** (`RawBlockBytes`), not a distinct name. Q3/Q5/Q6/Q7 approved as defaulted. **Q4 overturned:** widen `BlockInfo` 88 → 104 B — the default argued from byte parity with the LMDB struct, and byte parity was never a constraint (zerokval already collapsed; the comparator projects); decide on the codec, both fields fixed-width. SCR-4: `Option` stays `Option`. SCR-10: `passed_through()` rises by one and is not a regression — written beside the counter. **DRS §7.6 minted** from this review: the ported partition is transitional; consensus-visible bytes are the only pinned encodings; parity first, repair after, in Rust only (CEN-I12's argument resolved); one repair backlog sharing a denominator with bucket-4; the comparator gates cutover, `ratified / enforced` gates release. Contract §3 is now **as ruled**; §7 may start once this document merges. |

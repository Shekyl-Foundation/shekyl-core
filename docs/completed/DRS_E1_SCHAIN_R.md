# DRS-E1 S-CHAIN-R — the committed-chain read surface: increment plan and Round-0 pre-flight

**Status:** CLOSED-as-record — **archived 2026-09-18 by S-OUT-KI's pre-flight PR** ([`DRS_E1_SOUT_KI.md`](DRS_E1_SOUT_KI.md) §2.4), the reader §10 was waiting for. Increment LANDED (PR #772, 2026-09-17): the §3 contract is code (`rust/shekyl-chain-store/src/store/{read,chain_reads}.rs`), the three amendments and §11.1(f)'s value shapes are the layout (`SCHEMA_VERSION 2 → 5`), `DRS_E1_SCHAIN_W.md` is archived; nothing here is still proposed and this document owns no open residue (FL-R3-STORE's consumer half is a `FOLLOWUPS.md` row). Do not implement from this file. History: **Round 0 (pre-flight) executed 2026-09-16** at `dev`
`3560b80c2` (the tree that merged PR #757, S-CHAIN-W); **round-1 rulings
taken 2026-09-16 on every §9 question** (each entry carries its ruling
line-local; Q4 overturned its own default — §3.6). §3 is the contract as
ruled; §7 the commit sequence, which may start once this document merges
(it did — PR #772; every §7 commit is on `dev`).
The review also minted [`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md)
**§7.6** (the ported partition is transitional; parity first, repair after,
in Rust; the comparator gates cutover and `ratified / enforced` gates
release) — a property of the whole E-series, recorded there and pointed to
from §3.8 here. Implements *from*
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) §3.6.2 (halt visibility on
the tip), §3.5/§7 (the S-CHAIN-R row: extraction order **3**, "reads the
tables S-CHAIN-W writes") and DRS-D12 (replay-that-validates is the only
pre-cutover writer — this increment writes nothing on the connect path
except what §3.6 names); from
[`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md) (the codecs and tables this
surface decodes, landed PR #757); and from
[`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md) G11 (absence is matched,
never propagated — the `AtHeight<T>` discipline, adopted here for every
by-height read). Nothing in this document re-opens any of them.

**Why a separate document.** The S-CHAIN-R row in DRS §7 is one table line
naming 23 `BlockchainDB` methods. Of the 23 names, **21** become reads here,
one is already an accessor on the handle (the epoch pin, SCW-2) and one is
not ported (its consumer is dead, SCR-2) — and the 21 are not 21 functions:
seven of them are one `block_info` decode with a different field projected,
two are one hash lookup, three more are one blob read, so they land as
**nine** Rust reads (§3.2). The increment's content is the **mapping** — which
Rust read each C++ method becomes, what each returns when the height is
above the tip or the row is missing, and which C++ sentinels do not
survive — plus the two per-block fold fields FL-R3-STORE routes to this
surface. Rule 26's pre-flight pass is the instrument; this is the same shape
as [`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md); it stayed in `docs/design/`
while the increment was open and moved here when S-OUT-KI's pre-flight had
read it (PR #779).

**Identifier family.** Findings and questions here are **SCR-n**, registered
in [`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2 by this document's
PR (prefix `SCR` checked distinct against the registry with
`check_index_prefix_uniqueness.py`: `SCR` ≠ `SCW`, `SCE`, `CSR`). One series,
numbered in order of surfacing; a question and the finding that raised it
share a number.

---

## 1. Preconditions, as found at the pin

| Precondition (DRS §7 S-CHAIN-R row) | State at `3560b80c2` | Evidence |
| --- | --- | --- |
| S-CHAIN-W landed — the tables this surface reads have a Rust writer and canonical codecs | **landed** (PR #757, merged 2026-09-16 10:53 UTC; its rulings and commits are dated 2026-09-15, which is what the DRS §7 row's earlier `LANDED 2026-09-15` stamp recorded — corrected to the merge date in this PR) | `rust/shekyl-chain-store/src/store/connect.rs` writes `blocks`, `block_heights`, `block_info`, `hf_versions`, `block_burn`, `total_burned`; `codec/chain.rs` `BlockInfo` (88 B), `codec/property.rs` `TotalBurnedCell` |
| A read handle exists | **exists, untyped** — `ChainStore::begin_read` → `ReadSnapshot` with generic `open_table` / `open_multimap_table` / `get_property` only | `store/read.rs`; zero callers outside the crate's own tests (`rg begin_read rust --glob '!rust/shekyl-chain-store/**'` → none) |
| The write-side `ChainView` projection (the one reader the store already has) | **landed** (PR #757) — `BatchView::{has_key_image, block_at, root_at}` over the batch's own transaction; a private `tip()` and `cell()` | `store/view.rs` (module docs name a `ReadSnapshot`-backed view as "a later, separate implementor" — it is **not** this increment, §2.2) |
| The halt the tip must carry | **types landed, producer wired store-side** — `ConnectState` / `StoreInvariantRow` in `shekyl-rpc-types::chain`; `ChainStore::connect_state()` on the handle; `get_info` not wired, `CORE_RPC_VERSION` unchanged | `rust/shekyl-rpc-types/src/chain.rs`; `store/mod.rs` `connect_state`; DRS §7 S-CHAIN-W row "types only at this pin" |
| DRS-E2 has no subject yet | E2's replay needs a committed-chain reader to compare against LMDB; the row's own rationale for order 3 | DRS §7: "Split across increments, the two halves of one table's contract move separately and a digest mismatch cannot be localised to either" |
| **E6 slice 1 (concurrent lane, PR #761)** — `ChainView::tip() -> Option<Tip { height, hash }>` with `BatchView`'s private `tip()` becoming the trait impl | **pre-flight OPEN, Q1 (`Option<Tip>`) RULED 2026-09-16**; its commit 1 edits `store/view.rs:97`–`:108`, the same lines S-CHAIN-R's commit 1 (`chain_reads`, SCR-13) factors | `CHAIN_RULES_SLICE_1.md` (PR #761, not yet on `dev` — named, not linked) §2, §7; its §10 names "the S-CHAIN-R driver's use of `Tip`" as read *by this document*, not the reverse — so the composition in §3.4 is this document's to state |

**One ordering dependency on a concurrent PR — agreed between the lanes
2026-09-16 (PR #760 / #761 comments).** The increment branch cuts from
`dev` after this document's PR merges (the S-CHAIN-W rule, §1 there). E6
slice 1's commit 1 and this increment's commit 1 both touch
`BatchView::tip()`. **Order: this increment's `chain_reads` lands first;**
slice 1's `ChainView::tip()` impl for `BatchView` then reads through
`chain_reads::tip_of` — one read body, written so that `BatchView::tip()`
→ `Some(Tip { height, hash })` and `ReadSnapshot::tip()` →
`TipState { recorded, connect }` are two projections of one read. So
that slice 1 is not waiting on seven commits, **commit 1 ships as its own
PR** the day this document merges: a private module and a rewire with no
behaviour change is exactly the small, bisectable unit rule 06 prefers,
and it is the only commit the other lane depends on. Slice 1 keeps
`ChainView::tip()` at exactly three implementors (`BatchView`, `MockChain`,
`FaultingView`); SCR-16 keeps `ReadSnapshot` off the trait.

**A second upstream dependency, ruled 2026-09-16 (DRS §7.7, from
`PDM-Q-F26`) — SATISFIED 2026-09-17 on E6's PR #768.** Commit 2's layout
carries the `txs_pqc_auth_hash` row (amendment A3), written from
`TxIdentity.pqc_auth_hash: Option<PqcAuthHash>`. Both halves it needed are
on `dev` once #768 merges, and both came from the one PR: the rules-crate
field (fed by `Transaction::txid_parts()`, one construction for the txid
and its two store-row digests) and the wire half — `pqc_auth_hash() ->
Option<PqcAuthHash>`, `prunable_hash() -> PrunableHash`, and the
two-supplied entry `hash_with_supplied_components(pqc_auth:
Option<PqcAuthHash>, prunable: PrunableHash)`, arity read off the supplied
`Option` after the prefix predicate, with `hash()` and
`hash_with_supplied_prunable` as its special cases over one mixer
(`transaction/txid.rs`), KAT'd against the pinned oracle txid on a full
body and on a skeleton. §7.7 had assigned the wire half to this lane as
its own small PR; it landed with item 1 instead, because the KAT for one
is the KAT for the other. **This lane owes no wire PR.** A PQC-only
supplied method would not have done: a band-1 skeleton (F28) holds neither
`pqc_auths` nor the prunable region, so the arity cannot be read off a
body that is not there. Commit 2 now waits on nothing outside this
increment. The row is not added with a locally computed hash: the
identity comes from the one `validate`, or the store derives a
consensus-visible value (C2-R8 Q4).

**The dependency runs the other way too, and the order is settled
(maintainer OK 2026-09-16 13:31 on #761).** `TipState` composes
`shekyl_chain_rules::Tip`, which does not exist until E6 lands it. E6
therefore ships `Tip` + `ChainView::tip()` + its three impls as **its own
small PR cut the day `chain_reads` merges** (Q1-only dependency; touches
`view.rs` once, through `chain_reads::tip_of`). The full order:
**#760 → `chain_reads` PR (this increment's commit 1) → E6 `tip()` PR →
this increment's PR (commits 2–7) ∥ E6 slice-1 rules PR.** This increment
does **not** define a local `(height, hash)` pair type to start early —
one definition of the tip in the workspace is the point, and a stopgap
type is the same-shape duplicate rule 18 exists to stop. `Tip`'s shape is
frozen for composition: `#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip { pub height: BlockHeight, pub hash: BlockHash }`,
re-exported at the crate root; no `Default` (G11), no `Hash`/`Ord` (no
caller). `TipState` derives the same five and needs nothing more.

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
- The tip as one read: `TipState { recorded: Option<Tip>, connect }` — the
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
- `ReadSnapshot` carried `PhantomData<&'store ChainStore>` at the pin. This
  increment made it a real `&'store ChainStore` (commit 3) so `tip()` can read the
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
| R1 | `tip()` | `Result<TipState, StoreError>` — `TipState { recorded: Option<Tip>, connect: ConnectState }`: the recorded tip is `None` for an empty chain, and `connect` is carried **outside** the `Option` so a writer halted while connecting genesis is representable (§3.4) | `height()` (`:3209`, = entry count = tip + 1 under SI-2), `top_block_hash(&h)` (`:3179`), `get_top_block_timestamp()` (`:2900`, via R3 at the tip), `get_top_block()` (`:3194`, via R6 at the tip) | `block_info` (last key) |
| R2 | `height_of(&BlockHash)` | `Result<Option<BlockHeight>, StoreError>` | `block_exists(h, &height)` (`:2720`), `get_block_height(h)` (`:2759`) | `block_heights` |
| R3 | `block_info(BlockHeight)` | `Result<AtHeight<BlockInfo>, StoreError>` — after Q4, the 104-byte record carrying `cumulative_tx_count` and `long_term_effective_median` too (§3.6) | `get_block_timestamp` (`:2815`), `get_block_weight` (`:2915`), `get_block_cumulative_difficulty` (`:3002`), `get_block_already_generated_coins` (`:3082`), `get_block_long_term_weight` (`:3105`), `get_block_hash_from_height` (`:3128`); `get_block_difficulty` (`:3027`) is **not a store read** — `shekyl-chain-rules` owns `difficulty_at` over two recorded cumulative values (Q1, **ruled**) | `block_info` |
| R4 | `block_infos(Range<BlockHeight>)` | `Result<AtHeight<impl Iterator<Item = Result<(BlockHeight, BlockInfo), StoreError>>>, StoreError>` — `AboveTip` when `range.start > tip` (the whole range is absent), otherwise the rows `start..min(end, tip + 1)` in ascending height (§3.5) | `get_block_weights(start, count)` (`:2992`), `get_long_term_block_weights(start, count)` (`:2997`) — both are `get_block_info_64bit_fields` (`:2938`) with an offset; the caller projects the field | `block_info` |
| R5 | `block_blob(BlockHeight)` | `Result<AtHeight<RawBlockBytes>, StoreError>` — the recorded bytes, **not** verified against `block_info.hash`, in a type no consensus path can consume without an explicit, greppable decode (Q2, **ruled**: a distinct return type, not a distinct name — §3.3) | `get_block_blob_from_height` (`:2789`). (`get_block_blob(hash)` at `:2751` is **not** one of the row's 23 — it is outside `blockchain.cpp`'s vocabulary and appears here only because `get_block(hash)` routes through it; it is R2 then R5 and adds nothing to the count) | `blocks` |
| R6 | `block(BlockHeight)` | `Result<AtHeight<RecordedBlockBody>, StoreError>` — `{ hash, block: shekyl_wire::Block }`, parsed and verified to hash to `block_info[h].hash` | `get_block_from_height` (`src/blockchain_db/blockchain_db.cpp:976`), `get_block(hash)` (`:986`) = R2 then R6 | `blocks` + `block_info` |
| R7 | `blocks(Range<BlockHeight>)` | same shape as R4 over `RecordedBlockBody` — **half-open**; `for_blocks_range`'s `h2` is **inclusive** (`:3945`–`:3946` calls `f` for `h2` and then stops), so its caller's `start..=start + count − 1` (`cryptonote_core.cpp:918`–`:920`) is `start..start + count` here; the conversion is stated so a port does not drop the last block (SCR-20) | `for_blocks_range(h1, h2, f)` (`:3905`) — the C++ re-hashes each blob (`:3931`–`:3933`); R7 reads the recorded identity and verifies the blob against it (SCR-7) | `blocks` + `block_info` |
| R8 | `block_burn(BlockHeight)` | `Result<AtHeight<u64>, StoreError>` — an absent **row** at or below the tip is **`Recorded(0)`**, the writer's own convention (S-CHAIN-W phase 8 writes no row for a zero burn); an absent **table** is not a value (§3.3 — the table exists from the seal, amendment A2) | `get_block_burn` (`:4890`) | `block_burn` |
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
  **Genesis is a case that function must write, pinned here beside Q1:**
  the C++ subtracts zero at `h = 0` (`db_lmdb.cpp:3035`–`:3039`, the `if
  (height != 0)` guard), so `difficulty_at(0) = cum(0)`; a port that reads
  `h − 1` unguarded underflows the height, and one that reads `AtHeight`
  at `h − 1` turns genesis into `AboveTip`. Neither is a store concern —
  R3 answers `block_info(0)` — but the arm is the rules crate's to write
  and its fixture's to pin (`cen_d*_difficulty_at_genesis_is_cumulative`).
- **A missing table is corruption, never a value (S-CHAIN-W amendment
  A2).** At the pin a fresh file sealed only `properties` (`store/mod.rs`
  `create_sealed` → `header::seal`) and every chain table was created lazily by
  the first `connect`'s `open_insert_table`, and `ReadSnapshot::open_table`
  on an absent table is `EngineError::Table(TableDoesNotExist)`. So on an
  empty store R1/R2/R3 would fail with an engine error rather than answer
  `None`, and `block_burn` would not exist at all on a chain that has never
  burned (SCR-17). Two ways to close it: normalise `TableDoesNotExist` to
  "empty" in every read, or **create the chain table set in the seal
  transaction**. The second is taken. The store's table set is its declared
  layout (`SCHEMA_VERSION`, the bijection gate's subject), not a function of
  what history has happened to write; a read that treats "no table" as "no
  rows" makes absence a value again — the exact class (CEN-I12) this
  document exists to keep out of the read side. So `header::seal` opens
  every S-CHAIN-W table (§4's five plus the rest of the connect write set
  and `undo_log`) in the first transaction, and a declared table missing
  from a sealed file is **SI-7** (`CellCorrupt { key: <table>, fault:
  Absent }` — the register's SI-7 cell gains "or a declared table", §5) at
  the read that meets it and at `verify` on open. Archival-family tables are
  **not** sealed: a stubbed `ApplyPolicy` must not create them
  (`StoreCannot::FamilyStubbed`), and they are E4's. `undo_log` is sealed so
  `pop` on an empty chain stays `StoreCannot::ChainEmpty`, not an engine
  error.

### 3.4 The tip, and the halt it carries

```rust
pub struct TipState {
    /// The last recorded block — `shekyl_chain_rules::Tip { height, hash }`,
    /// the one definition of "the tip" in the workspace, minted by E6
    /// slice 1 (PR #761, `CHAIN_RULES_SLICE_1.md` §2) for
    /// `ChainView::tip()`. `None`: nothing recorded.
    pub recorded: Option<Tip>,
    /// `ChainStore::connect_state()` read *after* the snapshot was taken.
    /// Outside the `Option`: a writer halted while connecting **genesis**
    /// has no recorded tip and a halt to report (SCR-18).
    pub connect: ConnectState,
}
```

`TipState` **composes** the rules crate's `Tip` rather than repeating its
two fields: E6 slice 1 mints `Tip { height, hash }` as the trait's return
(`Option<Tip>`, the same `Option` shape for the same SCR-4 reason — that
document says so at its §2), the store already depends on the rules crate,
and a second `(height, hash)` pair type would be the kind of same-shape
duplicate rule 18 exists to stop. `TipState` is the envelope for a
different reader (RPC/wallet): the recorded tip plus the writer's state.
This is the one place S-CHAIN-R's read surface names a rules-crate type
beyond `AtHeight`, and it names it for the same reason.

**Why `connect` sits outside the `Option` (SCR-18).** `connect` notes the
connecting height *before* any belt runs, including height 0
(`store/connect.rs:287`–`:305`), so a genesis connect that hits SI-4
(a `curve_tree_roots[1]` row already present) or SI-8 halts the writer at
`at_height = 0` with nothing recorded. An `Option<{ tip, connect }>` cannot
say so — `None` would read as "empty, live", the silently-wrong tip §3.6.2
exists to prevent. The envelope always carries the writer's state; only the
recorded block is optional. The empty-but-halted case is a pinned test
(§7 commit 3).

`ConnectState` is the store's own (`store/halt.rs`), not the wire enum; the
daemon projects `StoreInvariant::row()` into `StoreInvariantRow` at the
`get_info` producer (DRS §3.6.2, "one expression at the writer that mints the
halt"). Carrying it on the store-side tip is SCR-12 / Q5: the §3.6.2 hazard
is a reader that returns a stale tip without saying so, and a `tip()` that
cannot omit the field is cheaper than a test in the adapter that remembers
to read two things.

What the pairing guarantees, stated exactly (corrected on PR #772 review —
the first draft claimed `at_height ≥ tip`, which a reorg falsifies): the
halt is monotonic and a refused write moves nothing, so a snapshot taken
before a halt latched shows a tip no halting write produced, and `connect`
read after `begin_read` is the writer's **current** state — `Halted` means
halted now. It is not snapshot-consistent: another batch can pop below this
snapshot's tip and then halt at the lower current height, so `at_height`
may be below `recorded.height`. Callers read `connect` as "is the writer
halted", never as an ordering against the tip.

`None` for an empty chain replaces three C++ sentinels — `null_hash`,
timestamp `0`, and a default-constructed `block` — and one underflow:
`top_block_hash(&h)` writes `*block_height = m_height − 1` at `:3185`
**before** the `if (m_height != 0)` guard at `:3186`, so an empty chain
hands back `UINT64_MAX` beside `null_hash` — two sentinels, neither
distinguishable from data (SCR-4, both anchors verified at review).

**`Option` stays `Option` (ruled).** Do not upgrade `recorded` to a bespoke
absence type for symmetry with `AtHeight`. A custom absence type earns its
keep when the default value lies *inside* the valid range of the type —
`[0u8; 32]` is a valid `curve_tree_roots` encoding, which is the whole
CEN-I12 defect — and here it does not: there is no "zero tip" that reads as
data. `None` is already unrepresentable as a tip. Someone will propose the
enum for consistency; it would buy nothing. (SCR-18 does not reopen this:
it moves a field *out* of the `Option`, it does not replace the `Option`.)

### 3.5 Ranges

`block_infos(range)` and `blocks(range)` take a **half-open**
`Range<BlockHeight>` and return `AtHeight<impl Iterator>`: `AboveTip` when
`range.start > tip` (the whole range is absent — matched, per G11, not
propagated as an empty iterator), otherwise the rows `start..min(end, tip +
1)` in ascending height. The two C++ shapes this replaces disagree with each
other, and the Rust picks one and says so (SCR-15):

- `get_block_info_64bit_fields` **throws** `DB_ERROR` when `start_height >=
  height()` (`:2946`–`:2948`) and otherwise clamps with `height < h &&
  count--` (`:2955`), returning fewer rows than asked without saying so.
  Its callers pre-clamp so neither arm is observed (`blockchain.cpp:1580`,
  `relay_floor_ring.cpp:192`).
- `for_blocks_range` with `h1` above the tip positions the cursor with
  `MDB_SET` (`:3921`), gets `MDB_NOTFOUND`, breaks (`:3930`–`:3931`), and
  returns `true` having called nothing — an empty result, no error.

Here the start-above-tip case is the typed `AboveTip` arm on both reads
(closer to the throw than to the silent empty, but a value the caller must
match rather than an exception), and an in-range end past the tip clamps.
The caller counts what it got, which is the same information the C++
clamp carried, stated once.

**Inclusive vs half-open (SCR-20).** `for_blocks_range(h1, h2, f)` is
**inclusive of `h2`**: the loop calls `f` for `h2` and only then breaks
(`:3945`–`:3946`), and its one caller passes `end = start + count − 1`
(`cryptonote_core.cpp:918`–`:920`). `blocks(range)` is half-open, so that
caller's range is `start..start + count`. A direct port that keeps the
caller's `− 1` drops the last block; commit 4's test asserts the last height
of the range is yielded. `for_blocks_range`'s early-stop closure becomes the
caller's `take_while` / `?` — an iterator is the shape that lets the sync
path stop without a callback. The two callers that motivate ranges: the
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
| `long_term_effective_median(h)` | the 100 000-block long-term weight median the daemon overwrites each block and cannot step backwards (FL-R23 amendment). **Indexing rule, pinned (SCR-19):** the value **in force for block `h`** — the median over the long-term weights of the recorded blocks *below* `h` (window `N`), i.e. the operand block `h` was validated and fee-floored against, **before** its own weight enters the window. That is the ring's `rm` at iteration `h` (`relay_floor_ring.cpp:196`–`:200`: insert `h − 1`'s weight, then take the median for `h`) and `Blockchain::get_long_term_block_weight_median` as `add_block`'s caller sees it. At genesis the window is empty and the value is the floor constant the ring uses (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`, `:199`). Not the post-insert recompute at the new `db_height` — that value is block `h + 1`'s and is stored at `h + 1`. | **not the store** — it is a consensus computation (C2-R8 Q4); it arrives as a `ConnectFacts` field with `Origin`, `DeletedBy` = CEN-G6 / CEN-G6b (slice 7), exactly like `long_term_weight` | `AtHeight<u64>` | `connect`, passed through |

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
minus the key" framing in the same commit (commit 2b, the amendments' layout commit) (rule 91: a doc that argues from
a constraint that does not exist will be quoted). Rule-42 layout change
either way: a `SCHEMA_VERSION` bump (3 → 4 — §7 commit 2b; 2 → 3 is commit 2a's value shapes), snapshot tests move. The paired-bump
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

The gates (rule 47; §10.12.2 names the first), on a regtest chain with
empty blocks, a pop and a reorg:

- **`cumulative_tx_count`:** `cum(0) == |tx_hashes(0)|` and, for every
  `h > 0`, `cum(h) − cum(h−1) == |tx_hashes(h)|` — the genesis case stated
  separately because `cum(−1)` is not a value; then the derived window
  equals the blob walk's at every height. The store test is the first half
  (against its own `blocks` rows, through pop and re-connect); the second
  half is the consumer's when `get_tx_volume_window` moves.
- **`long_term_effective_median`:** a fixture handing a **distinct** value
  per block through `ConnectFacts` asserts `block_info[h]` reads back
  exactly the value handed for `h` (not `h − 1`, not `h + 1` — the SCR-19
  indexing rule as a test), and that a pop of `h + 1` followed by a
  re-connect with a different value restores and then replaces it (the
  journal reverses the row). The store cannot test the value's *derivation*
  — it is passed through — so the bit-identity gate against the ring's
  stepped median (`relay_floor_ring.cpp:196`–`:200`) is **assigned to the
  consumer increment** that retires that code at cutover, and named there
  as owed, not left implicit here.

The walk it retires is
`blockchain.cpp:1917` (`get_tx_volume_window`) and the stepped median at
`relay_floor_ring.cpp:181`–`:200`; neither is touched here (rule 20 —
their deletion is the cutover's).

### 3.7 Types this increment adds to the store crate

| Item | Where | Why |
| --- | --- | --- |
| `TipState { recorded: Option<shekyl_chain_rules::Tip>, connect: ConnectState }` | `store/read.rs` | R1 (§3.4); composes E6 slice 1's `Tip` (PR #761); `connect` outside the `Option` (SCR-18) |
| **Amendment A2:** `header::seal` opens every table with a writer in the seal transaction; `header::verify` refuses a sealed file missing one (SI-7, the table named as the cell). **LANDED commit 2b (PR #772):** the set is **derived**, not listed — every table whose value shape is not `Unshaped` (§11.1(f); `Restorable::SEALED`, `UndoTarget::{create, exists}` over the catalogue) — so "archival-family tables excluded" is a consequence of their having no writer, and a table joins the seal by the same edit that gives it one. Gates: `amendments_tests::the_seal_creates_every_table_with_a_writer_and_no_unshaped_one` (18 sealed + 33 `Unshaped` = 51) and `a_sealed_file_missing_a_sealed_table_is_refused_as_si7` | `store/header.rs`, `store/undo.rs` | §3.3 (SCR-17) |
| **Amendment A3:** `txs_pqc_auth_hash: u64 → Coded<PqcAuthHash>` (§11.1(f); the identity type, not a `Hash32` — a value carries no LMDB ordering) — the txid's **third component**, `keccak256(varint(count) ‖ auths)` exactly as `Transaction::hash()` computes it (**not** `keccak256` of the raw `txs_pqc_auths` segment, which has no count prefix and verifies nothing the chain signed), written by `connect` beside `txs_prunable_hash` from `TxIdentity.pqc_auth_hash: Option<_>`, under F26's **three-leg** invariant: (1) row present ⇔ txid 4-part — permanent, written at connect, **never deleted** by any prune; (2) segment present ⇒ row present — a body the store cannot verify is the violation; (3) row present ∧ segment absent ⇔ *discarded* — the steady state of every 4-part tx below `W`, **not a fault** (a first draft here wrote a three-way equivalence, which would have made every pruned tx an invariant violation; corrected on PR #766 review against the merged F26); Rust-only until an LMDB twin exists (`RUST_ONLY_TABLES`, SCW-11 — the **second** entry, so `schema.rs`'s "first — and so far only" and DRS §7.6's "50 tables, 49 mirrors plus one" are rewritten in the same commit); journaled; SI-9-fresh under `tx_id`; sealed by A2 | `schema.rs`, `store/connect.rs` | `PDM-Q-F26` (PR #765) is the finding; DRS **§7.7** the landing plan: `PDM-Q6`'s second occupant is archival subject only if its hash is a persisted per-tx row, and the store had committed the identity to the first occupant alone. **Depended on** `TxIdentity.pqc_auth_hash` + `shekyl_types::PqcAuthHash` and the wire crate's **two-supplied** txid form (F28: a band-1 skeleton holds neither component, so the arity must come from the supplied third component) — **both landed on E6's PR #768** (§1), so commit 2b waited on nothing outside this increment. **LANDED commit 2b (PR #772):** the row is written by `record_tx` when `identity.pqc_auth_hash` is `Some`; leg 2 is `validate`'s (the identity is derived beside the body, CEN-B6); the gate is `amendments_tests::txs_pqc_auth_hash_has_a_row_iff_the_txid_is_4_part_and_it_is_the_identitys` — one row for the 4-part spend, none for either coinbase or the 3-part spend, the value is the identity's, and a pop removes it |
| `RecordedBlockBody { hash, block }` | `store/read.rs` | R6/R7 — the identity is `block_info`'s and the body is verified against it; a bare `Block` would let a caller re-hash and disagree |
| `BlockInfo::{cumulative_tx_count, long_term_effective_median}` — two `u64` fields, record 88 → 104 B; `FIXED_WIDTH = Some(104)`. **LANDED commit 2b (PR #772)** — `cumulative_tx_count` from the decoded tip row's value plus `transactions().len()` under SI-8; the median stored at the height it is in force for. Gates: `amendments_tests::cumulative_tx_count_is_the_running_total_through_pop_and_reconnect`, `long_term_effective_median_is_stored_at_the_height_it_is_in_force_for` (the SCR-19 rule as a test: `h`, not `h ± 1`, through pop and re-connect). The `u64` fields are typed by #771's newtype pass when it lands (`RAW_TYPE_NEWTYPE_MIGRATION.md`), not here | `codec/chain.rs` | §3.6 (Q4 ruled) |
| `RawBlockBytes` — newtype over the recorded blob; `into_wire_bytes` only; no `Deref`/`AsRef`/`From<_> for Block` | `store/read.rs` | R5 (Q2 ruled) |
| `ConnectFacts::long_term_effective_median: Fact<u64>` (+ its `DeletedBy` row — CEN-G6 / CEN-G6b, slice 7, beside `long_term_weight`; `DELETED_BY` becomes `[_; 7]`; the `PassedThroughFacts` bit is **appended** so the six existing positions keep theirs — still a layout change to that cell's encoding, on the 3 → 4 bump). **LANDED commit 2b (PR #772)**; `passed_through().count()` rose from six to seven, as §3.6 said it would | `store/connect.rs`, `codec/evidence.rs` | §3.6 |
| `chain_reads` (private): `tip_of`, `cell`, `block_body` generic over `redb::ReadableTable` | `store/chain_reads.rs` | one body for `BatchView` and `ReadSnapshot` (SCR-13) |

No new `SI-` row (§5). **Two `StoreCannot` variants, added on PR #772 review (2026-09-17), not in the pre-flight:** `RowWidth { table, expected, actual }` — the fallible insertion boundary for fixed-width value shapes, refusing where redb's `LeafBuilder::append` would assert (§11.1(f)); `LayoutForeign { expected }` — a file whose `properties` table type is not this layout's, refused before the version cell can be read (§11.1(a)'s "older refuses too", one step earlier). Both are refusals of a caller or a foreign file, not invariants.

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
| `block_heights` | `LmdbHashKey → u64` | R2 | `connect` phase 6 | absent **row** = not this chain's block (`None`); the table exists from the seal (A2) |
| `block_burn` | `u64 → u64` | R8 | `connect` phase 8, **only if** `h > 0 && burned > 0` | absent **row** at or below tip = `0` (writer convention; `blockchain.cpp:6148`); the table exists from the seal (A2) even on a chain that has never burned |
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
  never as `AboveTip`. **Wording extension, same row:** a declared chain
  table missing from a sealed file is SI-7 too (`CellCorrupt { key:
  <table>, fault: Absent }`) — A2 makes the table set part of what the seal
  vouches for, so its absence is the "missing sealed cell" the row already
  names, at table granularity. The register's SI-7 cell gains "or a
  declared table" in commit 2 (the layout commit); no new row, no status move.
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
| **SCR-4** | Empty-chain sentinels: `top_block_hash` returns `null_hash` and writes `*block_height = m_height − 1` before the `m_height != 0` check (`:3185`, `:3191`) — `u64::MAX` beside a null hash; `get_top_block_timestamp` returns `0` (`:2907`); `get_top_block` returns a default-constructed `block` (`:3204`). | `:3185` (the write) precedes `:3186` (the guard) — both anchors verified at review | `tip()` returns `TipState` with `recorded: Option<Tip>`; there is no sentinel and no field an empty chain can populate. Callers that today compare against `null_hash` (`blockchain.cpp:1168`, `:6641`) match on `None` at cutover. **Ruled: `Option` is not upgraded** — a bespoke absence type earns its keep only when the default lies inside the type's valid range (§3.4). |
| **SCR-5** | `get_total_burned` `memcpy`s 8 bytes from the cell without checking `mv_size` (`:5097`); `get_block_burn` two hundred lines earlier does check (`:4906`–`:4909`) and names the height in its error. Same value type, two disciplines. | as cited | Both go through the `u64` `Canonical` codec (fixed 8): a short or long cell is SI-7 on either read. Recorded as a divergence the C++ cannot exhibit on its own writes (it always writes 8), visible only on a corrupted file — the read is stricter, never looser. |
| **SCR-6** | `get_settlement_epoch_blocks_pin` (`:5042`) returns `0` when absent; its one caller (`blockchain.cpp:515`) is the open-time compare against the session's schedule. SCW-2 already re-homed the *pin* as the `settlement_epoch_blocks` header cell checked at every open with a typed refusal. | `ChainStore::settlement_epoch_blocks()` (`store/mod.rs:287`); `header::verify` | Already a read; nothing added. The `0`-when-absent arm does not survive: an absent pin is `StoreInvariant::CellCorrupt` at open, not a store that reports epoch `0`. |
| **SCR-7** | `for_blocks_range` parses each blob and **recomputes** its hash (`:3931`–`:3933`) rather than reading `block_info`'s. `BatchView::block_at` (S-CHAIN-W) reads the recorded identity and verifies the blob hashes to it. Two readers of one table with two notions of the block's identity is the drift this row exists to prevent. | `store/view.rs` `block_at`; `db_lmdb.cpp:3905`–`:3945` | R6/R7 use the recorded identity and verify the blob against it, in the shared body (SCR-13). A blob that hashes to something else is SI-7 on `blocks`, the same outcome `BatchView` gives a rule. |
| **SCR-8** | The block-sync path hands out raw blobs without parsing (`blockchain.cpp:2505`, `:2769` → `get_block_blob_from_height`). Verifying every blob against `block_info.hash` on that path is one hash per served block that the C++ does not pay, and the receiving peer validates the block anyway. | as cited | **Q2 RULED:** R5 returns the recorded bytes unverified — as **`RawBlockBytes`**, a distinct type no consensus path can consume without an explicit decode (§3.3), not merely a distinct method name; R6/R7 verify. Re-verifying to forward bytes is waste; a consensus caller reaching for the cheap one by name is the review miss the type forecloses. |
| **SCR-9** | `ReadSnapshot::open_table` / `open_multimap_table` are `pub` and generic over any `TableDefinition`: after this increment every S-CHAIN-R table has a typed read, and the raw handle lets a caller bypass the codec and the SI-7 classification. The write side already refuses the equivalent (`StoreCannot::PropertiesAreTyped`, no raw `properties` handle). Zero external callers today. | `store/read.rs:45`, `:63`; `rg` for callers | **Q3 RULED:** narrow to `pub(crate)` in commit 6 (the tests that use it are in-crate). Reopener: a surface whose tables have no typed read yet (S-OUT-KI, S-TX) lands its own reads rather than re-widening this. |
| **SCR-10** | FL-R3-STORE routes two per-block fields to this surface and names the falsifier `rg cumulative_tx_count rust/shekyl-chain-store`. Both are **writes** on the connect path S-CHAIN-W just landed; the read is trivial once the row exists. One of them (`cumulative_tx_count`) is a count of what the store records (the `rct_outputs` precedent); the other (`long_term_effective_median`) is a rolling median — a consensus computation the store must not perform (C2-R8 Q4) and therefore a passed-through `ConnectFacts` field. | `docs/FOLLOWUPS.md` FL-R3-STORE; `FEE_LADDER_DERIVATION.md` §10.12.2; `codec/chain.rs` `rct_outputs` doc; `store/connect.rs` `ConnectFacts` | In scope as **S-CHAIN-W amendment A1** carried here (§3.6): the FOLLOWUPS routing is explicit, and rule 22 lands scoped work where it is scoped. **Q4 RULED against the default:** widen `BlockInfo` (88 → 104 B) — decided on the codec (both fields fixed-width), the "LMDB struct" ground withdrawn (§3.6, DRS §7.6). **Consequence named:** `passed_through().count()` rises by one; not a regression (§3.6). |
| **SCR-11** | E2's redb-side digest v0 needs three reads: every block hash in height order (this surface, R4), every spent key image (`spent_keys` scan — S-OUT-KI's `for_all_key_images`), and the live curve root (S-CURVE's `get_curve_tree_root` in LMDB; in redb equal to `curve_tree_roots[tip + 1]` by SI-4). The LMDB reader is `logical_state_digest.cpp:60`–`:86`. A digest reader that waits for three surfaces' public reads delays E2 by two increments for a fold that reads tables directly. | as cited; `rust/shekyl-chain-store/src/digest_v0.rs` takes slices | **Q7 RULED:** `ReadSnapshot::digest_v0()` is a store-internal fold landing in **E2's first commit**, reading `block_info`, `spent_keys` and `curve_tree_roots` directly (the accumulator module's contract, not a surface method). Not this increment — it is E2's instrument, and landing it here would be a callee with no caller (rule 22). |
| **SCR-12** | `ReadSnapshot` holds `PhantomData<&'store ChainStore>` — it cannot reach `connect_state()`. DRS §3.6.2's hazard is a reader that returns a stale tip after a halt without saying so, and its ruling puts the halt "on the tip itself, not in a log line". A store-side `tip()` that omits it leaves the adapter to remember two reads. | `store/read.rs:27`–`:30`; DRS §3.6.2 | **Q5 RULED:** `ReadSnapshot` holds `&'store ChainStore`; the tip envelope (`TipState`) carries `connect` (§3.4) — the halt where a wallet actually reads it, which was §3.6.2's point. Ordering argument in §3.4. |
| **SCR-13** | `BatchView` has private `tip()` / `cell()` / `absent_below_tip()` / `blocks_invalid()` helpers over `self.batch.txn()`; `ReadSnapshot` would need the same over `self.txn`. redb's `ReadableTable` is the trait both transaction types' tables implement. Two copies of the decode-verify-classify body is exactly "the two halves of one table's contract moving separately". | `store/view.rs:97`–`:153` | One private `chain_reads` module generic over `impl ReadableTable`, returning the raw classification (`Ok(None)` for hole, `Err(CodecError)` for undecodable, hash mismatch as a typed enum); `BatchView` wraps each outcome in `self.poison().arm(..)`, `ReadSnapshot` in `StoreError::from(..)`. The **only** difference between the two implementors is the poison arm, and it is at the wrap, not in the body. |
| **SCR-14** | `height()` in the C++ vocabulary is `blocks`' entry count (`mdb_stat`, `:3220`) and 54 call sites in `blockchain.cpp` use it as "tip + 1". Under SI-2 the two agree; a store that offered both a count and a tip would let them disagree on a corrupt file and let a caller pick the one that looks right. `ChainTipFactsFfi.chain_height` is documented as "top block height + 1" (`rust/shekyl-daemon-rpc/src/ffi.rs:339`). | as cited | One read, `tip()`; no count method. "Chain height" is the adapter's `tip.height + 1` (or `0`), computed where the wire field is filled. A count read reopens only if a caller needs the count of a table SI-2 does **not** make dense — none on this surface. |
| **SCR-15** | `get_block_weights(start, count)` silently returns fewer than `count` when the window runs past the tip (`get_block_info_64bit_fields`, `:2955`: `height < h && count--`); `Blockchain::get_last_n_blocks_weights` pre-clamps `start_offset` (`blockchain.cpp:1580`) so it never observes the short return, and the long-term-median seed passes `min(N, oldest)` (`relay_floor_ring.cpp:192`) for the same reason. | as cited; and it **throws** `DB_ERROR` when `start_height >= height()` (`:2946`–`:2948`), where `for_blocks_range` returns an empty result (`:3921`, `:3930`–`:3931`) — the two C++ range readers disagree on start-above-tip | `block_infos(range)` / `blocks(range)` return `AtHeight<impl Iterator>`: `AboveTip` when the start is above the tip (one typed arm for both, replacing a throw and a silent empty), otherwise clamped to `..=tip` with the length the caller's to read (§3.5). The first draft of this row said the C++ "does the same" for an above-tip start; it does not for `get_block_info_64bit_fields` — corrected on PR #760 review. |
| **SCR-16** | `view.rs` names a `ReadSnapshot`-backed `ChainView` for RPC-side re-validation and E5's `PoolView` as "a later, separate implementor". With typed reads landing on `ReadSnapshot` the impl is a few lines, and the temptation to add it "while here" is real. | `store/view.rs:19`–`:22`; `CHAIN_RULES_CRATE.md` §13 (`PoolView` — DRS-E5) | **Out**, named in §2.2. It carries no brand, so it cannot mint a `ChainValid` that `connect` accepts; its consumer (pool admission) does not exist yet; adding it is pre-provisioning (rule 21). E5 adds it with its `PoolView`. |
| **SCR-17** | A fresh file seals only `properties`; every chain table is created lazily by the first `connect`'s `open_insert_table`, and `ReadSnapshot::open_table` on an absent table is `EngineError::Table(TableDoesNotExist)`. R1/R2/R3 on an empty store would fail with an engine error, not answer `None`; `block_burn` would not exist on a chain that has never burned. *(PR #760 review, three suppressed findings — all valid.)* | `store/mod.rs` `create_sealed` → `header::seal` (five `put`s, no tables); `store/write.rs:291`–`:303`; `store/read.rs:45`–`:56` | **S-CHAIN-W amendment A2** (§3.3): the seal creates the chain table set; a declared table missing from a sealed file is SI-7. Chosen over normalising `TableDoesNotExist` to "empty" in each read, which would make absence a value again. Archival tables excluded (`FamilyStubbed`). |
| **SCR-18** | `connect` notes the connecting height before its belts, including height 0 (`store/connect.rs:287`–`:305`), so a writer can be halted at `at_height = 0` with nothing recorded. An `Option<{ tip, connect }>` tip reads that store as "empty, live" — the stale-tip hazard §3.6.2 names. *(PR #760 review, suppressed — valid.)* | as cited; `store/halt.rs` | `TipState { recorded: Option<Tip>, connect: ConnectState }` — `connect` outside the `Option` (§3.4). Does not reopen SCR-4: the `Option` stays; a field moves out of it. Test: empty-but-halted (commit 3). |
| **SCR-19** | `long_term_effective_median(h)` had no indexing rule: the C++ computes the median used *for* block `h` before `add_block` and recomputes after the insert at the new height; a `block_info[h]` replay could be off by one. *(PR #760 review, suppressed — valid.)* | `relay_floor_ring.cpp:196`–`:200`; `blockchain.cpp:1624` | Pinned in §3.6: the value **in force for `h`** (median over blocks below `h`; floor constant at genesis), never the post-insert value. Distinct-value fixture + pop/re-connect test in commit 2; derivation bit-identity assigned to the consumer increment. |
| **SCR-20** | `for_blocks_range(h1, h2, f)` is inclusive of `h2` (`:3945`–`:3946`) and its caller passes `start + count − 1` (`cryptonote_core.cpp:918`–`:920`); `blocks(range)` is half-open. A direct port keeping the `− 1` drops the last block. *(PR #760 review — valid.)* | as cited | Conversion stated in §3.2/§3.5; commit 4's test asserts the range's last height is yielded. |

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

The form §7.6 requires: each knowingly-reproduced deviation with its
ratified state, so the repair phase's one query finds it here.

| Reproduced | Where | Ratified state ("what correct looks like") | Why reproduced now |
| --- | --- | --- | --- |
| **None.** | — | — | Every C++ read-side irregularity this pre-flight found is corrected in the port rather than carried: SCR-4's two empty-chain sentinels → `TipState { recorded: None, .. }`; SCR-5's unchecked `memcpy` → SI-7 on the `u64` codec; SCR-7's re-hash-instead-of-record → recorded identity verified. These are **read-side shapes the comparator never observes** (the diff compares committed content), so correcting them costs parity nothing — the test that distinguishes "correct now" from "reproduce, repair later" is whether the comparator would see the difference. §3.5's clamp and §3.3's absent-burn-is-zero are *behaviours*, not deviations: they are the writer's own conventions, read back. |

The S-CHAIN-W-side items that **are** reproduced knowingly — `output_amounts`
keyed verbatim under R8b-2 (SCW-8), `bi_cum_rct` per-block under the dead
v4 arm (CEN-L15) — belong to that increment's record and to the query, not
to this table.

**A distinction the query must keep.** DRS §7.6 names "a surface plan's
finding list" as one of the four homes, with SCR-4's `UINT64_MAX` as the
example. SCR-4 is a *C++* deviation this port **corrects** (`Option`), not
one it reproduces; it is in the finding list because that is where a
pre-flight records what it found, not because it is backlog. The query's
subject is *reproduced* deviations (E6 slice 1's F2 — two undocumented
parse bounds, carried as-is — is the shape: reproduced / why / correct),
so a finding-list entry enters it only when it says `reproduced`, and the
form for a corrected one is stated here so the two are not confused:
**corrected-at-port**, with the C++ behaviour and the Rust behaviour both
named (SCR-4, SCR-5, SCR-7 above). The repair phase inherits none of
those; the comparator never saw them.

---

## 7. Commit sequence (rule 90; one PR, ≤ 8 commits, cut from `dev` after this document merges)

1. `store: chain_reads — one decode/verify/classify body for BatchView and ReadSnapshot` — the private generic module (`tip_of`, `cell`, `block_body`); `BatchView` rewired onto it including its private `tip()` (SCR-13, SCR-7); no behaviour change; `view_tests.rs` green unchanged. **Ships as its own PR first** (§1) — E6 slice 1's `BatchView: ChainView::tip()` impl reads through `tip_of`.
2a. `store: value shapes — Coded<V> / Blob<K> / Unshaped; SCHEMA_VERSION 2 → 3` — DRS §11.1(f), ruled 2026-09-17 while the `tip()` PR (#768) awaited CI: every table's value type is a named shape (`codec::shape`), the key-types gate's value regex admits a generic `V`, 4 codecs gain fixtures (`block_height`, `rule_set_id`, `prunable_hash`, `block_burn`), `tables.snap` moves on its value column only, no row fixture moves. **Depends on nothing in flight** — cut from `dev` at #770 — which is why it is its own commit ahead of 2b rather than folded in: a layout commit that waits on `Tip` would have parked a ruling that was ready. Consequence disclosed: the increment pays **two** bumps (2 → 3 here, 3 → 4 in 2b), not the one §7 first promised; the alternative was to hold a finished, gated commit uncommitted until #768 merged (rule 90, *no batch and bisect*). Tests: `view_tests::a_wrong_width_row_cannot_reach_a_coded_table` (the engine holds a `Coded` table's width — the scenario the PR #764 review's undecodable-tip test planted is now unrepresentable, and the test says so) and `a_corrupt_row_read_through_the_view_is_si7_and_poisons_the_batch` re-planted on a `blocks` blob, the surface where a corrupt row still exists.
2b. `store: layout v4 — seal the chain table set (A2); BlockInfo carries cumulative_tx_count and long_term_effective_median (A1); txs_pqc_auth_hash row (A3) with TxIdentity.pqc_auth_hash + shekyl_types::PqcAuthHash (§7.7 item 1, this lane's since #768 scoped it out by name); SCHEMA_VERSION 3 → 4` — **the layout commit for the three amendments, before any read depends on any of the three changes (rule 42: a change to what an on-disk file may look like is paired with its version bump in the same commit).** Three amendments land together because they are one layout — A3 (DRS §7.7: the `txs_pqc_auth_hash` row from `TxIdentity.pqc_auth_hash`, `RUST_ONLY_TABLES` entry, journaled, SI-9-fresh; its rules-crate and wire-crate halves land before this commit, §1) beside: `header::seal` opens every S-CHAIN-W table and `header::verify` refuses a sealed file missing one (SI-7; register SI-7 cell wording); `BlockInfo` 88 → 104 B (Q4) with `codec/chain.rs` module docs re-grounded (no "LMDB struct minus the key"); `ConnectFacts::long_term_effective_median` + `DeletedBy` row + the `passed_through()` doc sentence; `connect` writes both fields (the count as `checked_add` under SI-8 from the parent's row; genesis `cum(0) = |tx_hashes(0)|`); snapshot moves; the paired-bump gate fires and is satisfied here. **A `SCHEMA_VERSION = 2` file is refused as `SchemaVersionMismatch` from this commit on** — never classified SI-7 for lacking tables it was allowed not to have. Gates: `cum(0)` and every `h > 0` difference through pop and re-connect; the distinct-value median fixture with pop/re-connect (SCR-19); a dropped `block_heights` table on a v3 file → SI-7 at `verify`.
3. `store: ReadSnapshot::{tip, height_of, block_info, block_infos}` — R1–R4; `TipState { recorded, connect }` (Q5, SCR-18); `ReadSnapshot` holds `&'store ChainStore`; tests: empty chain → `recorded: None, connect: Live` **on a fresh file** (the table exists from commit 2, so no engine error); **empty-but-halted** — plant `curve_tree_roots[1]` before connecting genesis so SI-4 fires at height 0, then `tip()` is `recorded: None, connect: Halted { at_height: 0, .. }`; tip after `connect`; `AboveTip` above it; a start above the tip → `AboveTip` from `block_infos`; a deleted `block_info` row below it → SI-7 **without** halting the writer (`connect_state()` stays `Live` — the read-side half of §3.6.2, pinned).
4. `store: ReadSnapshot::{block_blob, block, blocks}` — R5–R7; `RecordedBlockBody`; `RawBlockBytes` (Q2 — a `compile_fail` doctest pins that it does not deref to `[u8]` and does not convert into `Block`); tests: body hashes to identity; a rewritten blob → SI-7 on `block`/`blocks`, bytes still returned by `block_blob`; range clamps at the tip; **the last height of a half-open range is yielded** (`start..start + count` yields `count` rows — SCR-20).
5. `store: ReadSnapshot::{block_burn, total_burned, cumulative_tx_count, long_term_effective_median}` — R8–R9 and the two fold reads over the fields commit 2 wrote; tests: zero-burn block reads `Recorded(0)` with no row **on a chain that has never burned** (the table exists from the seal); genesis burn reads `0`; the cell after two burns is their sum (against `connect`'s `checked_add`); the fold reads return exactly what commit 2's fixtures wrote.
6. `store: narrow ReadSnapshot::open_table to pub(crate)` (Q3) — the in-crate tests keep it; no external caller.
7. `docs: S-CHAIN-R landed — DRS §7 row, §3.6.3 pointers, register SI-8 cell, FOLLOWUPS FL-R3-STORE store half, index, CHANGELOG; archive DRS_E1_SCHAIN_W.md` (§10).

Every question is ruled. Commit 1 shipped as its own PR (#764). Commit 2a
cut from `dev` at #770 with no in-flight dependency; commits 2b–7 wait on
E6's `tip()` PR (#768 — commit 3 imports `Tip`) and on this lane's wire PR
(§1). Each commit builds, `fmt`/`clippy` clean, tests
green (rule 26 B5).

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
(commit 2, the one layout commit) — a `.snap` diff in the same commit, reviewed as a layout
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
| **Q4** (SCR-10) | Shape of the FL-R3 fields: a Rust-only `block_fold` table, or two more `BlockInfo` fields? | **RULED 2026-09-16 — default OVERTURNED: widen `BlockInfo`, 88 → 104 B.** | The default's ground — `BlockInfo` is "the LMDB struct minus the key" and its bytes are what E2 diffs — imported a constraint that does not exist: zerokval is already collapsed in `schema.rs`, so the redb schema already diverges structurally and the comparator compares logical content through projections; layout was never the constraint (DRS §7.6 states the real one once — consensus-visible bytes). Decide on the codec: both fields are fixed-width, so widen the record — one read, no second table, no permanent lead-table entry. A separate table is for anything variable or optional. Transitional legibility of the projection decides nothing permanent. a `SCHEMA_VERSION` bump (3 → 4, commit 2b) is fine under rebuild-never-migrate; the paired-bump gate firing is the gate working. |
| **Q5** (SCR-12) | Does the store-side tip carry `connect: ConnectState`? | **RULED 2026-09-16 — default approved.** | Puts the halt where a wallet actually reads it, which was §3.6.2's point. |
| **Q6** (SCR-2) | Does the dead `get_output_distribution` chain get a FOLLOWUPS deletion row? | **RULED 2026-09-16 — default approved: no row.** | The surface row is the right home; a FOLLOWUPS row would outlive its subject when the C++ goes. |
| **Q7** (SCR-11) | Where does the redb-side digest v0 reader land? | **RULED 2026-09-16 — default approved: E2's first commit.** | The reader has no subject until E2. |

**Also ruled at the same review, outside the numbered questions:** SCR-4's
`Option<Tip>` inside `TipState` is not upgraded to a bespoke absence type (§3.4);
SCR-10's `passed_through()` increase is named as not-a-regression beside the
counter (§3.6, `store/connect.rs`); and DRS **§7.6** was minted — the
transitional partition, the encoding constraint stated once, parity-then-
repair in Rust with the comparator gating cutover and `ratified / enforced`
gating release (§3.8 points at it).

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md`: banner (E1 increment 4 landed); §7 S-CHAIN-R row (LANDED; `get_block_cumulative_rct_outputs` marked not-ported per SCR-2, `get_settlement_epoch_blocks_pin` marked already-a-read per SCR-6, count kept 23); §3.6.3 implementation pointers (the read handle); decision-log row.
- `STORE_INVARIANT_REGISTER.md`: SI-8 cell gains `cumulative_tx_count`, SI-7 cell gains "or a declared table", SI-9's side-table list gains `txs_pqc_auth_hash` (commit 2). No status moves.
- **Two sentences A3 makes stale, rewritten in commit 2:** `rust/shekyl-chain-store/src/schema.rs` module docs — "`undo_log` is the first — and so far only — table with no X-macro twin" (now two); `DAEMON_REDB_STORE.md` §7.6 — "the gated catalogue declares **50** tables, the 49 LMDB mirrors plus Rust-only `undo_log`, of which **46** are E1's write target" (51 and two Rust-only; the write target is re-derived from the connect write set at that commit, not restated from memory — `txs_pqc_auth_hash` is written by `connect`, so it enters the target).
- `ARCHIVAL_PRUNED_DAEMON_MODE.md` `PDM-Q6` item 2, its §7 Q6 row, and FOLLOWUPS F26: rewritten in this PR. #773 landed first and those three said the row was still owed; this increment is the row (DRS §7.7 item 3). Same present-tense claim flipped on the PDM banner, SF sub-PR 2, DRS §7.7 item 3 / E2 precondition / DRS-* index, and `CHAIN_RULES_CRATE.md`.
- `docs/FOLLOWUPS.md` FL-R3-STORE: the row has **two halves with two falsifiers**, and only the store half closes here. Commit 2 makes `rg cumulative_tx_count rust/shekyl-chain-store` and `rg long_term_effective_median rust/shekyl-chain-store` return, which closes the *store* half; the *consumer* half — `get_tx_volume_window`'s 720-block blob walk (`blockchain.cpp:1917`) and `rebuild_relay_floor_ring`'s stepped median (`relay_floor_ring.cpp:181`–`:200`) reading the two fields instead, and the derivation bit-identity gate (§3.6) — is live work that stays in the queue with its own falsifier (`rg 'get_block_from_height\(h\)\.tx_hashes' src/cryptonote_core` and `rg rolling_median_t src/cryptonote_core/relay_floor_ring.cpp` returning nothing), carrier: the cutover increment that wires the Rust daemon's reward/fee path onto S-CHAIN-R. Commit 7 rewrites the row to the consumer half only; it is not removed.
- `LMDB_SCHEMA.md` / `LMDB_WRITE_ATOMICITY_AUDIT.md`: no change (no LMDB table changes; the widened `BlockInfo` is the redb record — `LMDB_SCHEMA.md`'s `block_info` row describes LMDB's 96 bytes and stays true of LMDB).
- `codec/chain.rs` module docs: the "LMDB struct minus the key" framing goes (commit 2); the record is described by what its bytes hold and which are consensus-visible (none of `BlockInfo`'s — the block hash is a preimage-derived identity *stored* here, not *defined* here).
- `IMPLEMENTATION_INDEX.md`: `SCR` family and §7 doc row (this PR); the `DRS-*` row `UPDATE` for the increment is the increment PR's (rule 94 §4).
- `docs/CHANGELOG.md`: one Unreleased line at landing (`SCHEMA_VERSION` 2 → 5 across commits 2a/2b and the review's `Present` shape is a rebuild; the reads are a crate API).
- **Archive — DONE (PR #772, 2026-09-17; the file is beside this one in `docs/completed/`):** [`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md) became **eligible** when commit 5 landed (its stated archive condition, "S-CHAIN-R has consumed the codecs", was met once every S-CHAIN-W codec had a snapshot read) and was **`git mv`'d** to `docs/completed/` in commit 7, the increment's documentation commit — same PR, two commits apart. Its index §7 row moves with it in commit 7.
- This document: banner flips to *landed* at the increment PR; archive-or-contract per index §8 when S-OUT-KI's pre-flight has read it — **DONE 2026-09-18: archived by PR #779** (`DRS_E1_SOUT_KI.md` §2.4) (the next surface's pre-flight is the reader this document exists for).

---

## 11. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-17 | **#773 landed first; this PR is §7.7 item 3.** Q6 item 2 / the §7 Q6 row / FOLLOWUPS F26 said the `txs_pqc_auth_hash` row was still owed. Those three, plus the same present-tense claim on the PDM banner, SF sub-PR 2, DRS §7.7 item 3 / E2 precondition / DRS-* index, and `CHAIN_RULES_CRATE.md`, rewritten line-local. §10's "named here, not edited from this lane" is superseded. |
| 2026-09-18 | **PR #772 review (structural + Copilot round 3).** Range reads collapsed to one `range_at`; height classification is one `class_of`; `chain_reads::block_body` returns `BlockHash` (the domain identity, not `Hash32`); `connect_chain` lives in `connect_fixtures`; `pop` tests read the tip through R1. Value-shape taxonomy completed: `spent_keys` is `Present` (`SCHEMA_VERSION` 4 → 5; zero stored bytes, `TypeName` moved). Insertion boundary is `Restorable::well_formed`, not width alone — a forged variable-width `Encoded<UndoLog>` is `StoreCannot::RowIllFormed` (Copilot: `check_width` was a no-op when `FIXED_WIDTH` is `None`). Schema comments: archived `DRS_E1_SCHAIN_W.md` path; `txs_pqc_auth_hash` is never deleted *by a prune*, and `pop` reverses the journaled insert. |
| 2026-09-17 | **A3's two upstream dependencies landed together on E6's PR #768** (DRS §7.7 items 1–2): `TxIdentity::pqc_auth_hash: Option<PqcAuthHash>` and, in the wire crate, `Transaction::pqc_auth_hash() -> Option<PqcAuthHash>`, `prunable_hash() -> PrunableHash` and `hash_with_supplied_components(Option<PqcAuthHash>, PrunableHash)` — typed as §7.7 wrote them (`shekyl-wire` now depends on `shekyl-types`). **This lane's "own small wire PR" is not owed.** Commit 2 waits on nothing but itself: the row's input is on the identity `connect` is handed, and the KAT the row binds to is `pruned_tx_hash_parity`'s skeleton reconstruction against the pinned oracle txid. |
| 2026-09-16 | Round 0 executed at `dev` `3560b80c2` (post-#757). Sixteen findings (SCR-1…SCR-16); seven routed to round 1 as Q1–Q7 with defaults; the rest dispositioned into §3 and §7. Contract §3 **proposed, not ruled**. FL-R3-STORE taken into scope as S-CHAIN-W amendment A1 on FOLLOWUPS' explicit routing (rule 22). |
| 2026-09-17 | **PR #772 review (Copilot, two rounds: 9 open + 6 suppressed; 15 findings, 15 taken) and the #771 rebase.** Substantive: (1) `Value::from_bytes` is public, so "Encoded is constructible only from `V::encode`" was not a guarantee — the fixed-width soundness argument now rests on `store::keyed::check_width`, a fallible insertion boundary on every table handle (`StoreCannot::RowWidth`), and the leaking `catch_unwind` test became a plain `Result` test; (2) `header::verify` checked the seal set before the version, so a v3 file would have read as SI-7 corruption instead of a version mismatch — version first; and a pre-§11.1(f) file cannot open `properties` at all (its type name moved), which is now `StoreCannot::LayoutForeign` rather than an engine error; (3) `UndoTarget::undo` ran `well_formed` only on `prior`, so an `Inserted` entry naming an `Unshaped` table reached the uninhabited `from_bytes` — refused on `SEALED` first; (4) the `TipState` ordering claim `at_height ≥ tip` is false across a pop; `connect` is documented as current writer state with no ordering. Docs: the `TypeName` is `shekyl::Coded<name>` not `V::NAME`; `Unshaped` is catalogued and replay-refused but **not** seal-created (four sites said otherwise); `shape.rs` still said redb "checks nothing" (it asserts); stale 88s and a stale test pointer; SI-9's side-table column. Rebase onto #771: `CurveRoot` → `CurveTreeRoot`, `BlockBurn` → `Coded<AtomicUnits>` (the newtype now exists, so §11.1(f)'s rule applies — and `total_burned`'s cell and R8/R9 take `AtomicUnits` with it), `long_term_effective_median: LongTermWeight`; folded into the commits they belong to. |
| 2026-09-17 | **Commit 2b landed on PR #772 — layout v4, `SCHEMA_VERSION 3 → 4`: A1, A2, A3.** Cut after #768 merged; the sweep found E6 had landed §7.7 items 1–2 there (`TxIdentity::pqc_auth_hash`, `PqcAuthHash`, `TxidParts` with the two-supplied form), so the wire PR this lane owed is not owed and 2b waited on nothing. A2's set is derived from §11.1(f)'s shapes (`Restorable::SEALED`: every non-`Unshaped` table) rather than kept as a list — 18 sealed, 33 `Unshaped`, 51 catalogued — so 2a paid for 2b. A1 feeds the running total from the tip row `connect` already decodes in phase 1. A3 is `Coded<PqcAuthHash>`, ordinal 50, the second `RUST_ONLY_TABLES` entry; `schema.rs`'s "first — and so far only" and DRS §7.6's 50/46 rewritten (51; 48 target; 18 live writers). Six gates in `store/amendments_tests.rs`, all named in §3.7. Tests that asserted `open_table(X).is_err()` for a never-written table now assert *exists and empty* — the A2 property, not a weakening. #771 (in flight) types the `BlockInfo` fields; the two new ones are `u64` here and take their newtypes when it lands. |
| 2026-09-17 | **Value shapes ruled (DRS §11.1(f)) and landed as commit 2a, `SCHEMA_VERSION 2 → 3`.** Keys were typed for ordering from the first increment; values were `&[u8]` by inheritance, so two tables of one `(u64, &[u8])` shape were indistinguishable to the engine and every increment ahead would have decided the value side locally — the §7.7 lesson in another table. Ruled while #768 awaited CI, cut from `dev` at #770 with no in-flight dependency, so committed rather than held (rule 90); the increment now pays two bumps, disclosed in §7. Three review corrections taken at source before landing: `fixed_width` is a leaf-page layout change, not metadata, and is reported deliberately (the codec already swore to the width; redb *asserts* it — a panic that poisons the lock — so a boundary that keeps wrong-width bytes from the engine is what makes it sound — first written as the `Encoded`-only constructor; corrected on PR #772 review to the `check_width` insertion boundary, since `Value::from_bytes` is public); the redb `TypeName` guard covers table confusion only, codec confusion is closed by `Encoded<V>`/`Coded<V>` with `cell` inferring `V` from the definition; `Canonical` will move to a shared crate with the curve-tree PR but (b)'s bump rule stays with the digest. One property change recorded: a fixed-width `Coded` row whose codec checks only width cannot be undecodable in a file the engine accepted — the PR #764 review's undecodable-tip scenario is unrepresentable, and its test now pins the refusal instead. |
| 2026-09-16 | **PR #766 review (Copilot, 7 findings; all valid, all taken) against the *merged* F26/F28.** A3's invariant corrected from a three-way equivalence to F26's three legs — row ⇔ 4-part (never deleted), segment ⇒ row, row ∧ no segment = *discarded* — the draft would have made every pruned tx an SI violation. The wire dependency is a **two-supplied** txid form (F28: a skeleton holds neither component; arity from the supplied third, not from `pqc_auths.is_empty()`), not a PQC-only method. `PqcAuthHash` in `shekyl-types` named as E6's on the `Tip` PR. `get_pruned_transaction_weight` is a retained-metadata precedent, not a stored-digest one — `hash_with_supplied_prunable` is the only such precedent, item 2 its second application. §10 gains the two sentences A3 makes stale (`schema.rs` "first — and so far only"; DRS §7.6's 50/46). Rebased onto `dev` post-#765; §15 rows kept in F26-then-plan order. |
| 2026-09-16 | **Amendment A3 added to the layout commit (DRS §7.7; the finding is `PDM-Q-F26`, PR #765).** `TxIdentity` committed the per-tx identity to `PDM-Q6`'s first occupant alone; the `txs_pqc_auth_hash` row — the txid's third component over `varint(count) ‖ auths`, sparse, `Option` on the identity — rides commit 2 so the bump is paid once. Commit 2 gains a second upstream dependency beside `Tip`: the rules-crate field (E6's `Tip` PR) and the wire-crate `pqc_auth_hash` / `hash_with_supplied_pqc_auth` (this lane's own small PR). |
| 2026-09-16 | **PR #760 Copilot review, round 2 at `23c19a441` — 7 findings, every one re-verified at source; 7 taken, 0 refuted.** (1) Commit sequence re-cut so **commit 2 is the one layout commit with the one `SCHEMA_VERSION 2 → 3` bump** — A2 (seal the table set) and A1 (`BlockInfo` 104 B) together, before any read depends on either; the draft had A2's `verify` classifying a table-less v2 file as SI-7 while the version stayed 2 until commit 5, against rule 42's same-commit bump and the `SchemaVersionMismatch`-not-`CellCorrupt` contract for incompatible layouts. (2) FL-R3-STORE is **two halves**: the store half closes at commit 2; the consumer half (`get_tx_volume_window`'s walk, the ring's stepped median, the derivation gate) stays queued with its own falsifiers and the cutover as carrier — removing the row at commit 2 would have dropped live work. (3) The repair-backlog FOLLOWUPS row cut to a one-liner (rule 95). (4) DRS §7.6: the release gate is **`ratified == enforced` AND the backlog query at zero** — the ratio is computed from consensus buckets only (`check_chain_rules_coverage.py:303`–`:309`) and cannot see store-invariant or schema-shape deviations; §8.1 item aligned. (5) DRS §7.6's "every deviation is reproduced" scoped to **comparator-visible** deviations, with comparator-invisible read-side corrections (SCR-4/5/7) allowed and named — the absolute rule contradicted §6.1. (6) "46 tables" → the gated catalogue's **50** (49 mirrors + `undo_log`), 46 being E1's write target after the three exclusions. (7) PR #760's description updated to the ruled state. |
| 2026-09-16 | **PR #760 Copilot review, round 1 at `be4ae99b1` — 15 findings (4 inline + 11 suppressed), every one re-verified at source; 15 taken, 0 refuted.** Two were contract holes, not wording: a fresh file has no chain tables (SCR-17 → **S-CHAIN-W amendment A2**, the seal creates the table set; chosen over normalising a missing table to "empty", which makes absence a value), and a writer halted at genesis was unrepresentable by `Option<RecordedTip>` (SCR-18 → `TipState { recorded: Option<Tip>, connect }`, the halt outside the `Option`). Two were semantics left unpinned: the median's height indexing (SCR-19 — the value in force *for* `h`, floor constant at genesis) and `for_blocks_range`'s inclusive `h2` against the half-open `Range` (SCR-20). One was a false claim about the C++ (`get_block_info_64bit_fields` **throws** on start ≥ height; the row said "does the same" — corrected, and both range reads now return `AtHeight<impl Iterator>` with a typed `AboveTip` arm). The rest: `difficulty_at(0)` genesis arm pinned beside Q1; `cum(0)` stated separately in the gate; a median fixture added and the derivation gate assigned to the consumer; 23 → 21 + 1 + 1 accounting made exact; `get_block_blob(hash)` marked outside the row; archive eligible-at-4 / moved-at-7; S-CHAIN-W merge date 2026-09-16 (DRS banner and §7 row corrected from `2026-09-15`); DRS S-CHAIN-R row no longer claims a live `get_info` field. |
| 2026-09-16 | **Cross-lane check against E6 slice 1 (PR #761, same day).** Consistent: `Option` for the tip on both sides for the same SCR-4 reason; `difficulty_at` owned by the rules crate; the parity-then-repair ruling read the same way. Taken from that lane: the store-side tip **composes** its `Tip` (§3.4); the `view.rs:97`–`:108` overlap is a rebase (§1). Corrected in DRS §7.6 from that lane's landed-text check: parity evidence requires `implemented == enforced`, not `ratified == enforced` — the second figure was printed and gated nothing, the gate is new; bucket-4 consensus figure 27 at the pin, not 34. **Resolved the same hour by the E6 lane** (`789f5b0f5` on #761): its DRS edits withdrawn, `CHAIN_RULES_SLICE_1.md` §9 and `CHAIN_RULES_CRATE.md` §6.3 point at §7.6 as the one home; `view.rs` order agreed — this increment's `chain_reads` lands first, as its own PR, then slice 1's `tip()` impl reads through it. |
| 2026-09-16 | **Round-1 rulings (maintainer, same day; PR #760 remote review).** Both SCR-2 and SCR-4 anchors verified at source. Q1 approved and refined — no store `difficulty(h)`, **and** not the caller's: `shekyl-chain-rules` owns `difficulty_at`; the row states that C2-R8 constrains a read for the first time. Q2 approved as a distinct **type** (`RawBlockBytes`), not a distinct name. Q3/Q5/Q6/Q7 approved as defaulted. **Q4 overturned:** widen `BlockInfo` 88 → 104 B — the default argued from byte parity with the LMDB struct, and byte parity was never a constraint (zerokval already collapsed; the comparator projects); decide on the codec, both fields fixed-width. SCR-4: `Option` stays `Option`. SCR-10: `passed_through()` rises by one and is not a regression — written beside the counter. **DRS §7.6 minted** from this review: the ported partition is transitional; consensus-visible bytes are the only pinned encodings; parity first, repair after, in Rust only (CEN-I12's argument resolved); one repair backlog sharing a denominator with bucket-4; the comparator gates cutover, `ratified / enforced` gates release. Contract §3 is now **as ruled**; §7 may start once this document merges. |

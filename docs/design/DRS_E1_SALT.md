# DRS-E1 S-ALT — the alternative-chain store: increment plan and Round-0 pre-flight

**Status:** LANDED — **implemented 2026-09-25** on the S-ALT increment PR,
stacked on the pre-flight (#856): three commits (§7 as executed; layout
**12 → 13**; `codec/alt.rs` `AltBlock`, `store/alt.rs` AL1–AL3 on the
batch, `store/alt_reads.rs` AL4–AL7 on the snapshot and the batch,
`AltCannot` under `StoreCannot`; `archival_alt_attestation_witness` folded
into `alt_blocks`, `schema::FOLDED_INTO` and the bijection gate's fourth
direction with its selftest; the digest-boundary test). As-built deviations
in §11 (2026-09-25, "as built"): ops named by family on the shared handle,
AL7 returns a `Vec`, `AltCannot` has two arms with the third refusal at
construction, and SAL-2's key-types claim corrected (the floor moved 25 → 24).
This file stays in `design/` as the E1/E5 boundary statement (§0, §2.2,
§2.3, SAL-13, SAL-14) until E5's plan owns it.
**Round 0 executed 2026-09-24** at `dev` @ `9532b58f5`
(the merge of PR #851, S-POOL). **Round 1 RULED 2026-09-25** (maintainer, on
PR #856; §9, each row line-local): **all six defaults approved; Q3's reason
replaced** — refusal because removing what is not held is a caller-contract
violation (L14's insert-versus-upsert ruling applied to a remove), not
because the C++ throws; **Q1's cross-check written into the row**, Q5's
performance ground made explicit. Two findings added on the rulings:
**SAL-14** (`rollback_blockchain_switching` is deleted, not ported — its
absence is the evidence SAL-1's atomicity landed) and **SAL-15** (the folded
witness's §7.1.1 KAT obligation transfers to `alt_blocks`, and the
"declared, not enforced" exclusion boundary can now be enforced by one
test). The increment was cut and landed the same day (§7). Implements *from*
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §5 (the S-ALT row: extraction
order **9**, the last ordered surface — "alt-chain storage depends on both
chain surfaces being settled; its reorg path is the one place both are
exercised together"), §11.2 (`alt_blocks` and
`archival_alt_attestation_witness` are *not chain state*: replay cannot
produce them, every digest excludes them) and the S-POOL row's inheritance
for this surface (census by *table*, not by the `Blockchain::` corridor —
[`DRS_E1_SPOOL.md`](DRS_E1_SPOOL.md) §2.2, SPL-15); from
[`DRS_E1_SARCH.md`](DRS_E1_SARCH.md) `SAR-Q5` (RULED: the alt-attestation
witness pair lands **here**, as an alt-block attribute, not as an archival
read); from [`CONSENSUS_STORE_RECONCILIATION.md`](CONSENSUS_STORE_RECONCILIATION.md)
CEN-K3 ("belt survives the engine change only if re-specified" — this is the
re-specification) and the §4.K slice's six walks; and from
[`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) §3 CW-2 (the hash-keyed
witness is *owned by the alt-block table* and never outlives its block).
Process per `26-sub-pr-design-discipline.mdc`; identifier families **`SAL-`**
(findings) and **`SAL-Q`** (round questions) registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by the PR that adds
this file (rule 94 §1; `check_index_prefix_uniqueness.py` branch (a): the
two parse to `SAL` and `SAL-Q`, distinct, clear of the 99 registered —
`SAR-` is a different prefix by the gate's grammar, checked rather than
judged by appearance).

**The question S-POOL left for this increment, answered first (rule 22).**
S-POOL moved the pool to its own file and wrote, of `alt_blocks` and the
witness table: *"E5 S-ALT's, not asked here; recorded so the two answers
are given by the increments that own the tables and can be checked against
each other"* (`SPL-Q2`'s reopening criterion). This document's answer is
**the other one — the consensus file, the same `WriteBatch`** — and §6
SAL-1 / SAL-10 state why the two answers differ: the pool is never inside
a chain transaction and holds privacy-bearing relay state; the alt store's
**admission and reorg writes** — `add_alt_block`, the witness, `remove_alt_block`
— run inside one (the C++ already does so — the witness write dereferences
the live batch's `m_write_txn`), it holds public data, and the one place it
matters — the switch — is the place atomicity is the property. The one
write that is *not* inside a chain transaction is `drop_alt_blocks`, which
opens its own (SAL-9) at init and reset; it is the wipe, not the reorg, and
AL3 puts it in the caller's batch. (Narrowed on review, Copilot PR #856:
the first draft said "only ever".)
Same rule, opposite facts, opposite answer (`SAL-Q1`).

**Two lanes, stated once.** *E1 S-ALT* (this document) is the **store**: the
alt-block record's type and codec, the seven typed operations on the
consensus file, and what those operations refuse. *E5* is the **reorg**:
`handle_alternative_block`'s admission ladder (CEN-K1…K10, all
CHECKED-CONFORMANT, none of them storage), `build_alt_chain`, fork choice
(`shekyl_difficulty_fork_choice`), the switch and its demotion, the
`--keep-alt-blocks` policy. E1 mints what E5 writes into and reads from.
Nothing in the C++ alt path moves in this increment: `blockchain.cpp` stays
the live reorg over LMDB until the cutover, as every other C++ consumer of
every other E1 surface has.

---

## 1. Preconditions, as found at the pin

| Precondition | State at `9532b58f5` |
|---|---|
| S-TXN … S-POOL (E1 increments 1–9) | landed (#740, #749, #757, #772, #783, #800, #815, #844, #851) |
| `WriteBatch<'store, 'id>` with `connect` / `pop` callable repeatedly on one batch ("a reorg pops several", `store/pop.rs:59`); `ChainStore::write(\|batch\| …)` commits on `Ok`, aborts on `Err` (`store/mod.rs:445`) | landed (E1 increments 2.5, 3) — **the switch can be one transaction** (SAL-1) |
| `ReadSnapshot` typed reads; `chain_reads::{cell, absent, undecodable}`; SI-7 (`StoreInvariant::CellCorrupt`) | landed (S-CHAIN-R onward) |
| `CumulativeDifficulty` as one little-endian `u128` in the chain codec (`codec/chain.rs:112–127`) | landed — the alt record reuses it (SAL-5) |
| `BlockHeight`, `BlockWeight`, `BlockHash` in `shekyl-types`; `AtomicUnits` in `shekyl-units` | landed |
| A `Coded<V>` record carrying variable-length bytes (`BondRecord.hybrid_pubkey: Vec<u8>`, `codec/archival.rs:305`) | landed — the precedent for one row carrying block bytes beside the record (`SAL-Q2`) |
| `alt_blocks`, `archival_alt_attestation_witness` in the redb schema | landed, **both `Unshaped`, in the consensus file** (`schema.rs:384`, `:423`; `tables.snap` #13, #21); `accumulator/class.rs:108`, `:110` grade both `Excluded` |
| `check_redb_schema_bijection.py` — X-macro ↔ `schema.rs`, plus `RUST_ONLY_TABLES` (Rust has a table LMDB never had) and `MIRRORED_ELSEWHERE` (LMDB's twin lives in another file) | landed — has **no** "folded into another table's record" direction (SAL-2) |
| `SCHEMA_VERSION = 12` (`codec/schema_version.rs:132`) | landed — this increment bumps to **13** (two `Unshaped` → one shaped, one table folded; rule 42) |
| `SAR-Q5` — the witness pair is S-ALT's | **RULED 2026-09-23** (`DRS_E1_SARCH.md` §9) |
| E5 (pool / alt / prune) | **not started**; named in the DRS graph (§7, `E4 --> E5`); no plan document yet |

The stated dependency is E1 increments 2.5 and 3 (the batch that can pop and
connect more than once) and the codec vocabulary, and nothing from a later
surface. **Unblocked.**

---

## 2. Scope

### 2.1 In — the census, method by method

Method: every reader and writer of `alt_blocks` and
`archival_alt_attestation_witness` in `db_lmdb.cpp`, then every caller of
each — the S-POOL method, not the `Blockchain::` corridor alone. Nine
methods on the two tables; six are the §5 row's, three are the witness
pair's (two in S-ARCH's row by count, ruled here by `SAR-Q5`) plus the
remover that no `Blockchain::` method reaches.

| # | C++ method (LMDB impl) | Table(s) | Callers at the pin (`blockchain.cpp` unless noted) | Rust op |
|---|---|---|---|---|
| 1 | `add_alt_block(blkid, data, blob)` (`blockchain_db.h:1844`; `db_lmdb.cpp:4292`) — one value `alt_block_data_t ‖ blob`, `MDB_NODUPDATA`; `MDB_KEYEXIST` throws "Attempting to add alternate block that's already in the db" | `alt_blocks` | `handle_alternative_block` `:2359`, immediately after the caller's own `CHECK_AND_ASSERT_MES(!get_alt_block(id))` at `:2352` (CEN-K3's two belts) | **AL1** `insert` — the one belt, typed (`AltCannot::AlreadyHeld`) |
| 2 | `get_alt_block(blkid, *data, *blob)` (`:1855`; `:4314`) — `false` on `MDB_NOTFOUND`; throws "Record size is less than expected" | `alt_blocks` | `get_block_by_hash` `:937` (orphan flag; needs blob); `build_alt_chain` `:2023`, `:2036` (the parent walk; needs both); `handle_alternative_block` `:2117` (`prev_data.height`, `.already_generated_coins` read at `:2130`, `:2157`; blob `NULL`), `:2352` (dup belt; both `NULL`); `have_block_unlocked` `:3004` (both `NULL`) | **AL4** `alt_block` (record + bytes + witness) for the three that read; **AL5** `contains` for the two that only ask |
| 3 | `remove_alt_block(blkid)` (`:1862`; `:4342`) — **throws** on `MDB_NOTFOUND` ("Error locating alternate block"); then `remove_archival_alt_attestation_witness` | both | `switch_to_alternative_blockchain` `:1207`, `:1214` (the failed-switch path), `:1246` (every promoted alt after the switch) | **AL2** `remove` (`AltCannot::NotHeld`) |
| 4 | `get_alt_block_count()` (`:1867`; `:4362`) — `mdb_stat` entries | `alt_blocks` | `get_alternative_blocks` `:2582`, `get_alternative_blocks_count` `:2603` (RPC `get_info.alt_blocks_count`, `core_rpc_server.cpp:214`), `get_alternative_chains` `:6740` | **AL6** `len` |
| 5 | `drop_alt_blocks()` (`:1872`; `:4383`) — `mdb_drop` both tables in **its own** `TXN_PREFIX(0)` transaction | both | `reset_and_set_genesis_block` `:791` (before the `db_wtxn_guard` at `:794` — a two-transaction reset, SAL-9); `core::init` `cryptonote_core.cpp:653` when `!keep_alt_blocks` | **AL3** `drop_all` |
| 6 | `for_all_alt_blocks(f, include_blob)` (`:1979`; `:2322`) — cursor walk, `include_blob` selects whether the callback sees the bytes | `alt_blocks` | `get_alternative_blocks` `:2583` (RPC `get_alt_blocks_hashes`, `core_rpc_server.cpp:307`), `get_alternative_chains` `:6741` (RPC `get_alternate_chains`, `:1186`) — **both** pass `include_blob = true` and parse the block | **AL7** `entries` (the flag dissolves, SAL-11) |
| 7 | `store_archival_alt_attestation_witness(blkid, witness)` (`:2696`; `:9130`) — `mdb_put` flags `0` (an upsert) on the live `*m_write_txn` | witness | `handle_alternative_block` `:2368`, right after #1, `if (!connect.attestation_witness.empty())` — "Empty stores no row"; **the only writer** (`:2362` comment) | folded into **AL1**: `AltBlock.attestation_witness: Option<…>` |
| 8 | `get_archival_alt_attestation_witness(blkid)` (`:2704`; `:9142`) — **empty when absent** | witness | `switch_to_alternative_blockchain` `:1192` (the promoted block's witness, handed to `handle_block_to_main_chain` so `add_block` re-writes the height-keyed row — CEN-K5b) | folded into **AL4** |
| 9 | `remove_archival_alt_attestation_witness(blkid)` (`:2712`; `:9160`) — tolerant of a missing key | witness | **none in `blockchain.cpp`** — reached only from inside #3 (`:4359`) and #5 (`:4394`) | dissolves: one row has one lifetime |

Nine methods, seven operations. `get_alt_block`'s two shapes (record-only,
membership-only) are two operations because their costs differ by a block
blob on the p2p `have_block` path (SAL-12); `for_all`'s flag has one value
at both callers; the witness has no operation of its own because it has no
lifetime of its own (CW-2, made structural).

### 2.2 Out (named, so it is not scope shed by omission)

- **The admission ladder and the reorg** — `handle_alternative_block`
  (`:2079`), `build_alt_chain` (`:2018`), `switch_to_alternative_blockchain`
  (`:1134`), `rollback_blockchain_switching` (`:1080`), fork choice, the
  alt-window difficulty (`shekyl-difficulty::alt_window`). **E5's**, every
  line. CEN-K1…K10 are all CHECKED-CONFORMANT against the C2-R1 spec and
  none of them is a storage rule; this increment changes no verdict.
- **`--keep-alt-blocks`** (`cryptonote_core.cpp:186`, `:653`) — the policy
  that calls AL3 at init. E5 / the daemon's.
- **The height-keyed witness** `archival_attestation_witness` — main-chain
  owned (CW-2's first clause), read by S-ARCH A-read #15, written by
  `add_block` / `pop_block`: **E4's write half**. This increment stores the
  *hash-keyed* twin as an attribute and hands it back at promotion; the
  height-keyed re-write is `connect`'s business.
- **`alt_block_data_t`'s bookkeeping values** — `height`,
  `cumulative_difficulty`, `already_generated_coins`, the block's weight —
  are **computed by E5** (`:2130`, `:2157`, `:2311–2346`, `shekyl-difficulty`,
  `shekyl_advance_already_generated`). The store types and holds them; it
  computes none (C2-R8: the store computes nothing consensus-visible).
- **Parsing the block** — both enumerators parse
  (`parse_and_validate_block_from_blob`, `:2590`, `:6749`) and `MERROR`-skip
  a bad blob. The store hands bytes (S-CHAIN-R's `RawBlockBytes` discipline);
  what a consumer does with an unparsable alt block is its business.
- **Any change to the consensus file's digest families** — both tables are
  `Excluded` today and stay so (§11.2); this increment moves no family.
- **`ChainView`** — alt data is **never** projected onto the validator's
  view (SAL-7).

### 2.3 What E5 gets from this increment

- A typed `AltBlock` and seven operations on the store it already has —
  the batch for the reorg, the snapshot for the RPCs — with the refusals
  the C++ throws as strings (`AltCannot`).
- **The atomic switch** (SAL-1): pop to the split, connect the alt chain,
  demote the disconnected blocks, remove the promoted alts — one
  `ChainStore::write` closure. A failure anywhere aborts everything the
  **store** did; the store never shows a half-switched chain, so the
  rollback's *store* compensation has no Rust counterpart. E5 inherits the
  *sequence* (read the tip before popping it — SAL-13), not the
  compensation — **and the non-store side effects the C++ rollback also
  undid** (Copilot, PR #856): `pop_block_from_blockchain` re-adds the popped
  block's transactions to the pool and steps the hard-fork tracker
  (`:711`, `:738`), promotion takes transactions out of the pool, and both
  invalidate the block-template cache (`:753`). Those are not in the store's
  transaction. They need no compensation **if they run after the closure
  commits**: chain-first, pool-second is already the ruled order
  (`SPL-Q5`), so E5 applies the pool returns and the cache invalidation from
  the closure's `Ok`, and an abort has applied nothing to compensate. The
  hard-fork state is `hf_versions`, a store table, inside the transaction.
  A crash between the commit and the pool's apply is the case the pool's
  reconcile-at-open already owns (`SPL-Q5`, new E5 work).
- **A deletion, not a port** (SAL-14): `rollback_blockchain_switching`
  (`:1080`) exists only to compensate for writes the C++ committed
  separately. At cutover it is deleted; E5's plan carries the row and its
  falsifier (`git grep rollback_blockchain_switching src/` → 0 after the
  cutover PR).
- CW-2's lifetime clause for free: the witness cannot outlive its alt block
  because it is a field of it.

### 2.4 What the consensus store gets

`alt_blocks` shaped (`[u8; 32] → Coded<AltBlock>`), the witness table
**folded** into that record and evicted from the catalogue (`tables.snap`
47 → 46, `Unshaped` 20 → 18), the bijection gate's fourth direction
(`FOLDED_INTO`, SAL-2), layout 12 → 13 — and the **exclusion test** the
audit named as this class's open item (SAL-15): a write to `alt_blocks`
must not move any digest, the `txpool` exclusion test's shape, now
covering the witness too because the witness is in that row.

### 2.5 What DRS-E2 gets

Nothing to replay and nothing to compare. §11.2 already excludes both tables
from every digest; the C++ drops alt blocks at every init unless
`--keep-alt-blocks` (SAL-8), so the redb store starts with an empty alt
table at cutover and no LMDB → redb carry of alt entries exists (rule 15:
pre-genesis, and the C++ default already discards them).

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the store lives

The **consensus file**, on the existing handles: writes as methods of
`WriteBatch<'store, 'id>` in `rust/shekyl-chain-store/src/store/alt.rs`
(the `connect.rs` / `pop.rs` shape — one file per write surface), reads as
methods of `ReadSnapshot` in `store/alt_reads.rs` (the `archival_reads.rs`
shape), the record in `codec/alt.rs`. **Not** a second file (`SAL-Q1`).

### 3.2 The mapping — nine methods, seven operations

| Op | Signature | Replaces | Semantics |
|---|---|---|---|
| **AL1** | `insert_alt_block(&self, id: &BlockHash, block: &AltBlock) -> Result<(), StoreError>` on `WriteBatch` (*ruled as* `insert`; the shared handle carries the family in the name — §11 as built) | #1, #7 | One row. An existing key is `AltCannot::AlreadyHeld` — CEN-K3's belt, typed; the caller's pre-read at `:2352` is redundant inside a batch (SAL-4). Empty block bytes are `AltCannot::EmptyBlock`. The witness rides in the record as `Option` — `None` is the C++ "empty stores no row". |
| **AL2** | `remove_alt_block(&self, id: &BlockHash) -> Result<(), StoreError>` (*ruled as* `remove`) | #3, #9 | One row; an absent key is `AltCannot::NotHeld` — the C++ throws here and its three callers remove blocks they just enumerated, so absence is a logic fault worth surfacing, not an idempotent no-op (`SAL-Q3`). The witness leaves with the row. |
| **AL3** | `drop_alt_blocks(&self) -> Result<u64, StoreError>` (*ruled as* `drop_all`) | #5 | Every row, in the caller's batch; returns how many. The C++ opened its own transaction for this and ran it *outside* the reset's guard (SAL-9). |
| **AL4** | `alt_block(&self, id: &BlockHash) -> Result<Option<AltBlock>, StoreError>` on `ReadSnapshot` **and** on `WriteBatch` (the batch itself, not `BatchView` — alt data is never a `ChainView` fact, SAL-7) | #2 (three callers), #8 | The record, the block bytes and the witness. `None` is "not an alt block". An undecodable row is SI-7. |
| **AL5** | `has_alt_block(&self, id: &BlockHash) -> Result<bool, StoreError>` (*ruled as* `contains`) | #2 (two callers) | Membership without decoding or copying a block — `have_block_unlocked` asks this for every hash a peer announces (SAL-12). |
| **AL6** | `alt_block_count(&self) -> Result<u64, StoreError>` (*ruled as* `len`) | #4 | The table's length. |
| **AL7** | `alt_blocks(&self) -> Result<Vec<AltEntry>, StoreError>`, `AltEntry { id: BlockHash, block: AltBlock }` (*ruled as* an iterator; a `Vec` as built — one body serves a `ReadOnlyTable` and a write `Table`, the table is small by construction, SAL-8) | #6 | Key order. Both callers want the bytes; there is no bytes-less enumeration to offer (SAL-11). |

Reads on `ReadSnapshot`; the reorg reads AL4/AL5 through the batch's own
view so a switch decides against what it is about to change. Writes inside
`ChainStore::write(|batch| …)` — the same closure that commits `connect`
and `pop`; **no separate handle, no separate transaction** (`SAL-Q1`).

### 3.3 Absence, faults, and what an operation may not do — the S-TX discriminator applied

- **"Not an alt block" is a case.** #2's `bool` + out-params is `Option`.
- **"No witness" is a case, not an empty string.** #8 returns `blobdata{}`
  for absent; `Option` (the S-ARCH discipline for the same sentinel on the
  height-keyed twin).
- **"Weight unknown" is a case, not zero.** `handle_alternative_block` sets
  `block_cumulative_weight = 0` when a transaction cannot be found
  (`:2345`, "we can't determine the block weight") and persists it
  (`:2355`). `Option<BlockWeight>`; `None` is the sentinel (`SAL-Q4`).
- **Remove-absent is a refusal, not a throw and not a no-op.** `AltCannot::NotHeld`.
- **Add-existing is a refusal.** `AltCannot::AlreadyHeld` — the one belt
  CEN-K3 asked to survive.
- **"Record size is less than expected" / "alt_blocks record is too small"**
  (`:4331`, `:2345` in `db_lmdb.cpp`) are SI-7 (`CellCorrupt`), named by
  the read that found them.
- **Two `u64` halves are one `u128`.** `cumulative_difficulty_low/high` are
  split by hand at `:2356–2357` and reassembled at `:2031–2032` and
  `:6753–6754`; the record holds `CumulativeDifficulty`, encoded as the
  chain codec already encodes it (SAL-5).
- **What an operation may not do:** decide whether a block is an alt block
  (admission), walk a chain, choose a fork, compute a difficulty, weight or
  coin total, parse a block, or drop alt blocks on its own initiative.

### 3.4 Types this increment adds — and where they live

| Type | Shape | Home (default) | Why |
|---|---|---|---|
| `AltBlock` | `{ height: BlockHeight, block_weight: Option<BlockWeight>, cumulative_difficulty: CumulativeDifficulty, coins_generated: AtomicUnits, block: Vec<u8> /* BlockBody bytes, opaque */, attestation_witness: Option<Vec<u8>> }` | `shekyl-chain-store::codec::alt` | `alt_block_data_t` re-specified: the u128 as one field, the weight's zero sentinel as `None`, the misnamed `cumulative_weight` (it is the block's own weight, `:2313–2340`) named for what it holds, the block bytes and the CW-2 witness beside the record so the pairing invariants S-POOL had to *enforce* (SI-16) are here *unrepresentable* (`SAL-Q2`). Constructed through `checked()`, which applies **the shared validation, not an emptiness check** (sharpened on review, Copilot PR #856): the block bytes must satisfy `BlockBody::well_formed` — the `blocks` table's own rule, which parses — and a present witness must satisfy `AttestationWitnessBytes::well_formed` — the height-keyed twin's own rule, which refuses empty and over-bound; a zero weight is refused; the codec refuses the same three at decode (SI-14's shape). **The parse boundary is explicit:** the record does not hand out raw bytes — `AltBlock::block()` returns a parsed `Block` (every C++ consumer parses: `:937`, `:2023`, `:2590`, `:6749`; a row that decodes *is* a block), and the untyped `Vec<u8>` is a storage detail behind a private field, never a surface. And the key is not trusted: **AL1 verifies `id == block.hash()`** (`AltCannot::IdentityMismatch`), the same belt class as `chain_reads::block_body` verifying a blob against `block_info.hash` — verification of a caller-supplied identity, not computation of a consensus value (C2-R8). The witness accessor stays `Option<&[u8]>` for parity with the height-keyed read (S-ARCH #15 returns `Option<Vec<u8>>`); a typed witness wrapper is a change to that family's whole surface and is E4's. |
| `AltCannot` | **as built:** `{ AlreadyHeld, NotHeld, IdentityMismatch }` — `IdentityMismatch` refuses an AL1 whose key is not the hash of the block it stores (Copilot, PR #856; the C++ trusted the caller at `:2359`) — (*ruled as* `{ AlreadyHeld, NotHeld, EmptyBlock }` — `EmptyBlock` is unreachable at the store: the record cannot be built without a block, so the refusal is `AltBlockError::BlockMalformed` at `AltBlock::checked`, beside `WitnessMalformed` and `ZeroWeight`) | `shekyl-chain-store::store::error`, as `StoreCannot::Alt(AltCannot)`; `AltBlockError` in `codec::alt` | The store's decisions, not faults — `PoolCannot`'s shape. `AlreadyHeld` is CEN-K3's belt; `NotHeld` is the C++ throw at `:4354`, typed. |
| `FOLDED_INTO: &[(&str, &str, &str)]` | `(lmdb_name, host_table, reason)` | `schema.rs`, beside `MIRRORED_ELSEWHERE` | The bijection gate's fourth direction: an X-macro table whose bytes now live as a **field of another table's record**. Rule-47 self-assertion as the other two: an entry naming a table not in the X-macro is red; an entry whose host is not a `TableDefinition` in `schema.rs` is red; an entry whose LMDB name *is* still defined in `schema.rs` is red (SAL-2). |

No new vocabulary in `shekyl-types`: every scalar the record needs exists.

### 3.5 What this surface inherits, and for how long

- **From S-CHAIN-W:** the batch, the closure, the poison, the journal — and
  the rule that a write surface is one file (`connect.rs`, `pop.rs`,
  `alt.rs`). Alt writes are journaled like any other so the writer halt
  covers them; they are `Excluded` from every accumulator so no digest
  moves.
- **From S-ARCH:** absence carried by `Option`, not a sentinel; a record
  re-specified rather than ported; the read file per surface.
- **From S-POOL:** the census method; `checked()` construction with the
  codec refusing what construction refuses; refusals as an enum under
  `StoreCannot`; the schema gate learns a direction rather than an
  allowlist.
- **From the C++, for as long as the C++ runs:** nothing. The C++ alt path
  keeps writing LMDB until the cutover; the redb alt table is empty until
  E5's first `handle_alternative_block` writes it.

---

## 4. The store set, table by table

| Table | At v12 | After this increment (v13) | Op |
|---|---|---|---|
| `alt_blocks` | `LmdbHashKey → Unshaped` (#13) | `LmdbHashKey → Coded<AltBlock>` — the key type **stays** `LmdbHashKey`: the LMDB table is `compare_hash32`, the key-types gate maps that comparator to `LmdbHashKey`, and `BlockHash` converts at the API boundary (`alt_reads::key`). *Corrected on review (Copilot, PR #856): the first draft wrote `[u8; 32]`, the pool file's deliberate exception, which would have failed the gate or silently changed key order.* | AL1–AL7 |
| `archival_alt_attestation_witness` | `LmdbHashKey → Unshaped` (#21) | **folded** — no definition in `schema.rs`; named in `FOLDED_INTO` with `alt_blocks` as the host (SAL-2) | — |

`SCHEMA_VERSION` 12 → 13 (rule 42; `tables.snap` loses exactly one row and
re-types one; the pinned-ordinals test records the shift for every ordinal
after #21). `accumulator/class.rs` keeps its two rows — the class table is
the LMDB inventory (S-POOL as-built deviation (2)); a `FOLDED_INTO` entry is
required to be classed, as a `MIRRORED_ELSEWHERE` entry is.

---

## 5. Store invariants this increment builds or restates

None new. The two pairings the C++ maintained by convention — a witness row
never without its alt block (CW-2, `:4359`, `:4394`, `:9129`), an alt
record never without its bytes (`:4330`) — are one row here and cannot be
observed apart. CEN-K3's belt is re-specified as `AltCannot::AlreadyHeld`;
the census row's state stays CHECKED-CONFORMANT with its anchor moved from
`mdb_cursor_put(…, MDB_NODUPDATA)` to the typed refusal when the increment
lands (§10).

---

## 6. Round-0 findings

- **SAL-1 — the switch is not atomic in C++, and the Rust store can make it
  so.** `switch_to_alternative_blockchain` (`:1134`) pops to the split,
  promotes each alt block through the 4-arg `handle_block_to_main_chain`
  (`:1193`), and on any failure calls `rollback_blockchain_switching`
  (`:1204`) to pop the promoted blocks and re-add the disconnected ones —
  compensation for a sequence of separately committed writes (CEN-K5's
  own evidence). `WriteBatch::pop` "may be called repeatedly on one batch
  (a reorg pops several)" (`store/pop.rs:59`) and `connect` is a method on
  the same batch, so the whole switch — pops, connects, AL1 for each
  demoted block, AL2 for each promoted one — is one closure that commits
  or aborts as a unit. The store never shows a half-switched chain and E5
  writes no rollback. This is the reason the alt table belongs in the
  consensus file (`SAL-Q1`), and the reason the S-ALT row is last in the
  order: it is the one surface that exercises S-CHAIN-W's two writers
  together.
- **SAL-2 — the schema gates have no "folded" direction.**
  `check_redb_schema_bijection.py` knows three surfaces plus two
  exceptions: `RUST_ONLY_TABLES` (Rust has it, LMDB never did) and
  `MIRRORED_ELSEWHERE` (LMDB has it, Rust's twin is in another file). An
  LMDB table whose bytes become a *field of another table's record* is
  neither; evicting `archival_alt_attestation_witness` turns the gate red
  for the right reason with the wrong message, as SPL-2 did. The increment
  adds `FOLDED_INTO` with the same three self-assertions (§3.4) rather
  than widening `MIRRORED_ELSEWHERE`'s meaning — a twin table and a host
  field are different claims and the gate should say which it checked.
  ~~`check_redb_schema_key_types.py` carries no constraint on either table
  (both are `compare_hash32`, the default), so its floor of 25 does not
  move.~~ **CORRECTED as built (2026-09-25):** `compare_hash32` is *not*
  the gate's default — it is the constraint that maps a table to
  `LmdbHashKey` (`expected_key_types`), and both tables fired it. Folding
  the witness table removes one constraint: **floor 25 → 24**, re-derived
  by counting; `alt_blocks` keeps `LmdbHashKey` and still fires. The
  pre-flight read the gate's comment, not its code — the rule-16 corollary,
  caught by the gate itself on the increment.
- **SAL-3 — the surface has one consumer and it *is* `blockchain.cpp`.**
  Every production caller of the nine methods is in `blockchain.cpp`
  (twelve sites, eight functions) or `cryptonote_core.cpp:653`; the two RPC
  routes (`get_alt_blocks_hashes`, `get_alternate_chains`) and
  `get_info.alt_blocks_count` reach the store through `Blockchain::`
  forwards. Unlike S-POOL, the §5 row's method count (6) is the census's
  count for the corridor; the three witness methods are S-ARCH's #15–#17
  by the surface map's count and this increment's by `SAR-Q5`'s ruling —
  the map's S-ALT Methods cell stays at **6** at landing (the SPL-15
  lesson, applied before rather than after the gate fires).
- **SAL-4 — CEN-K3's two belts collapse to one, and the survivor is the
  store's.** The add path asserts `!get_alt_block(id)` (`:2352`) and then
  `add_alt_block` refuses `MDB_KEYEXIST` (`:4307`). Inside a redb write
  transaction the read and the insert cannot interleave with another
  writer, so the caller's pre-read is a belt against nothing; the typed
  `AltCannot::AlreadyHeld` is the specification CEN-K3's row asked for and
  E5's caller branches on it rather than on a prior read. The register row
  keeps its state and gains the anchor.
- **SAL-5 — a `u128` stored as two `u64` by hand, three times.**
  `alt_block_data_t` carries `cumulative_difficulty_low/high`; the split is
  written at `:2356–2357` and the reassembly `(hi << 64) + lo` appears at
  `:2031–2032` and `:6753–6754`. The chain codec already encodes
  `CumulativeDifficulty` as one little-endian `u128` (`codec/chain.rs:112`,
  `bi_diff_lo` then `bi_diff_hi`); the alt record uses the same field and
  the same bytes. One codec, no hand arithmetic at any reader.
- **SAL-6 — the witness has no lifetime of its own, so it has no operation
  of its own.** Written once, beside `add_alt_block`, by one site (`:2368`,
  "This is the ONLY writer of that table"); read once, at promotion
  (`:1192`); removed only by the alt block's own removers (`:4359`, `:4394`);
  `remove_archival_alt_attestation_witness` has no `Blockchain::` caller at
  all. Every clause of CW-2's ownership rule is a statement that the witness
  is an attribute — `SAR-Q5` said so — and an attribute is a field. The
  `mdb_put` with flags `0` (an upsert the single writer never exercises as
  one) and "empty stores no row" become `Option<…>` on the record.
- **SAL-7 — alt data never reaches `ChainView`.** CEN-A4 is *held-by-cxx*
  because "alt-store membership is not a recorded-chain fact"; CEN-K8's
  reader enumeration finds no consensus-bearing reader of the alt
  bookkeeping. The validator's view is projected from the chain; AL4–AL7
  live on `ReadSnapshot` and the batch's view, and no `ChainView` accessor
  is minted. A rule that wanted to know whether a hash is an alt block
  would be a rule about the store's contents, which C2-R8 forbids.
- **SAL-8 — the cutover starts empty.** `core::init` drops every alt block
  unless `--keep-alt-blocks` (`cryptonote_core.cpp:653`), so the C++'s own
  default is that alt state does not survive a restart; DRS-E2's replay
  produces none (§11.2); no migration path is owed and none is written.
- **SAL-9 — `drop_alt_blocks` runs in its own transaction, outside the
  reset's.** `TXN_PREFIX(0)` at `:4388` opens (or joins) a write
  transaction; `reset_and_set_genesis_block` calls it at `:791`, *before*
  the `db_wtxn_guard` at `:794` that wraps the genesis write — so a reset is
  two commits and a crash between them leaves a reset chain with its alt
  blocks intact (harmless, since init drops them, but a shape). AL3 is a
  batch operation; a Rust reset composes it into the one closure.
- **SAL-10 — alt writes are already chain-batch writes in the C++.**
  `add_new_block` opens the batch (`batch_start`, `:6175`) before
  `handle_alternative_block` runs, and
  `store_archival_alt_attestation_witness` dereferences `*m_write_txn`
  unguarded (`db_lmdb.cpp:9137`) — it would fault outside a batch. The
  "which file" question is answered by the transaction the C++ already
  uses for admission and reorg: those alt writes have never had a
  transaction of their own — the one that has, `drop_alt_blocks`'s
  `TXN_PREFIX(0)` (SAL-9), is the wipe at init/reset, not a reorg write,
  and AL3 folds it into the caller's batch. The pool's
  separate file was ruled on privacy and on the pool never being inside a
  chain write (`SPL-Q2`); both grounds are absent here. The two answers are
  checked against each other, as `SPL-Q2` asked: same rule, opposite facts.
- **SAL-11 — a flag with one value and a field with the wrong name.**
  `for_all_alt_blocks(f, include_blob)` is called twice, both with `true`
  (`:2583`, `:6741`), and both callbacks fail on `!blob`; the parameter
  dissolves into AL7. `alt_block_data_t::cumulative_weight` receives
  `bei.block_cumulative_weight` (`:2355`), which is the **block's own**
  weight — the miner tx plus each transaction (`:2313`, `:2322`, `:2340`) —
  not a cumulative anything; the record names it `block_weight`.
- **SAL-12 — `get_alt_block` is two reads wearing one signature.** Three
  callers need the record (`:937`, `:2023`/`:2036`, `:2117` — the last for
  `prev_data.height` and `.already_generated_coins`); two ask only whether
  the row exists (`:2352`, `:3004`), and one of those is `have_block`, the
  test run for every block hash a peer announces. AL5 `contains` answers
  without decoding or copying a block; AL4 answers with the block. The C++
  pays the copy either way (`memcpy` of the record; the blob only on
  request), which is what the `NULL` out-params were for.
- **SAL-13 — demotion needs the tip read before the pop, and `Popped` does
  not carry it.** `switch_to_alternative_blockchain` reads each block it
  pops (`pop_block_from_blockchain` returns the block, `:679`) and its
  height-keyed witness (`:1170`, S-ARCH #15) so it can re-add them as alt
  blocks with witnesses (`:1233`). `WriteBatch::pop` returns
  `Popped { height, reversed }` (`store/pop.rs:49`) — undo-log replay, not
  the block. E5's demotion sequence is therefore: read the tip's bytes,
  cumulative difficulty, coins and weight and the witness through the
  batch's view, `pop()`, AL1. Stated here so the E5 plan inherits the order
  rather than discovering `Popped`'s shape.
- **SAL-14 — `rollback_blockchain_switching` is a deletion, not a port**
  *(added on the rulings, 2026-09-25)*. The function (`:1080`, called at
  `:1204`) pops the blocks the failed switch promoted and re-adds the ones
  it disconnected — it exists *only* because the C++ commits the switch's
  writes separately (SAL-1). Under one `ChainStore::write` closure there is
  no half-switched **store** state to compensate for, so the function has no
  Rust counterpart and is deleted at the cutover rather than moved. **Its
  absence is the evidence that the atomicity landed**: a Rust reorg that
  needed a rollback would be a reorg that was not one transaction. **What
  the deletion does not cover, stated so E5 does not inherit a gap**
  (Copilot, PR #856): the C++ function also re-adds the failed promotion's
  transactions to the pool and re-pops hard-fork and cache state — effects
  outside the store's transaction. Their owner is an **ordering rule**, not
  a rollback: pool and cache effects are applied from the closure's `Ok`
  (chain-first, pool-second — `SPL-Q5`'s contract), so an aborted switch has
  applied nothing non-store. The row belongs to E5's plan with both halves
  and the falsifier (`git grep rollback_blockchain_switching src/` → 0 after
  the cutover); this document names it so the E5 plan inherits a deletion
  plus an ordering rule, not a translation task.
- **SAL-15 — the folded witness's §7.1.1 obligation moves with it, and the
  fold lets the "declared, not enforced" boundary be enforced** *(added on
  the rulings, 2026-09-25; checked against `DAEMON_REDB_STORE.md` §7.1.1
  and `LMDB_WRITE_ATOMICITY_AUDIT.md` §"non-canonical")*. **The archival
  bar's count does not move.** §7.1.1 bars the *apply/revert* path — the
  archival journal families E4 writes — until a digest family or a
  replacement KAT forces them; `archival_alt_attestation_witness` was never
  in that set. The audit classes it **non-canonical (4)** with `alt_blocks`
  and the pool pair ("the alt witness is archival as well as alt; it is
  classed here because the domain argument is the one that holds today, and
  it inherits §7.1.1's KAT obligation when S-ARCH ports"), Digest v0
  `excluded` / accumulator `excluded`, and the digest freeze excludes the
  non-chain class "for all future digests". **What the fold changes is the
  route the obligation takes**: the KAT that must force the witness path —
  stored at admission (AL1), read at promotion (AL4), re-written
  height-keyed by `connect` (E4's write half) — now exercises `alt_blocks`
  rows, not a table of its own, so when the archival apply KAT is written
  (E4) its alt leg is AL1 → AL4 → the height-keyed row, and the S-ARCH #16 /
  #17 rows point here. **What the fold makes possible**: the audit's open
  item for this class is that `alt_blocks` and the witness "have no
  equivalent test, so for them the boundary is *declared, not enforced*" —
  two tables, no exclusion test. One row means one test: a write through
  AL1 (with a witness) must move no digest, the `txpool` exclusion test's
  shape. The increment writes it (§7 commit 2) and closes the item.
  **Enforcement was not the fold's purpose.** The row was chosen for
  `SAL-Q2`'s reasons — one logical thing, pairings unrepresentable — and the
  test exists because the boundary *became testable*, not because someone
  set out to close an audit row; a reader who finds the test later should
  read it that way. **What travels to E4, as one item, not two:** (a) the
  witness's non-canonical classification is a **dated conditional** — it
  holds "because the domain argument is the one that holds today" and
  *expires* when S-ARCH's apply path ports, at which point the §7.1.1 KAT
  obligation is live; and (b) the route that obligation is exercised
  through is **AL1 → AL4 → the height-keyed row**, not a table of its own.
  Carried together (§10) so E4 does not inherit a table that looks settled
  and a route nobody described.

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None. No K row is DIVERGENT; the register's §4.K slice is CHECKED-CONFORMANT
end to end, and this increment's typed refusals reproduce the C++'s two
throws (add-existing, remove-absent) as refusals with the same polarity.
Nothing that was accepted becomes refused, or the reverse.

---

## 7. Commit sequence (rule 90; one PR, ≤ 3 commits, cut from `dev` after §9 is RULED)

1. **`chain-store: AltBlock record and the shaped alt_blocks table (S-ALT)`** —
   `codec/alt.rs` (`AltBlock`, `checked()`, `Canonical`, snapshot
   registration `alt_block.snap`), `schema.rs` (`ALT_BLOCKS` shaped;
   `ARCHIVAL_ALT_ATTESTATION_WITNESS` evicted; `FOLDED_INTO`),
   `SCHEMA_VERSION` 13, `tables.snap`, the pinned-ordinals test,
   `check_redb_schema_bijection.py`'s fourth direction with its selftest
   refusals. One commit because the record's snapshot and the table's
   catalogue share `codec::snapshot_tests` (S-POOL as-built (1)).
2. **`chain-store: AL1–AL7 on the batch and the snapshot (S-ALT)`** —
   `store/alt.rs`, `store/alt_reads.rs`, `AltCannot` under `StoreCannot`,
   tests: each op and refusal, the atomic switch shape (pop, connect, AL1,
   AL2 in one closure; an `Err` aborts all four), AL4/AL5 on the batch's
   view, SI-7 on a corrupt row, `entries` with both callers' folds; the
   **alt exclusion test** — an AL1 with a witness moves no digest (SAL-15).
3. **`docs: S-ALT landed (DRS-E1 increment 10)`** — §10.

---

## 8. Denominator — what must stay green, what must be extended

| Gate / suite | Now | After |
|---|---|---|
| `check_redb_schema_bijection.py` | 47 ↔ 45 + 2 ↔ 47 | **as built:** 47 censused ↔ 44 here + 2 mirrored + 1 folded ↔ 47 classes; 46 definitions; selftest 4 clean shapes / 19 refusals (five `FOLDED_INTO` refusals plus the absent-const parse refusal) |
| `check_redb_schema_key_types.py` | floor 25 | **25 → 24 as built** — the folded table's `compare_hash32` constraint left with it (SAL-2, corrected) |
| `check_drs_c_surface_map.py` | 95 ↔ 95 across 10 surfaces | unchanged — the S-ALT Methods cell stays 6; witness methods stay in S-ARCH's cell (SAL-3) |
| rule-42 snapshot gate | `SCHEMA_VERSION = 12` | 13; `tables.snap` −1 row, one re-typed; `alt_block.snap` new |
| `check_store_invariant_register.py` | 16 rows / 14 ↔ 14 | unchanged (no new SI) |
| digest exclusion tests (`accumulator`) | `txpool` pair only — alt boundary "declared, not enforced" | + the `alt_blocks` exclusion test (SAL-15) |
| `check_conformance_coverage.py`, `check_consensus_invariants.sh` | 126 / 2 / 5 over 133 rows | unchanged (no verdict moves; CEN-K3's anchor text updates) |
| `cargo test -p shekyl-chain-store` | 332 + 14 | **342 + 14 as built** (four codec tests, five store tests including the switch and the digest boundary, one schema test) |

---

## 9. Round-1 questions — RULED 2026-09-25 (maintainer, on PR #856; each row line-local)

| Q | Question | Default | Reason |
|---|---|---|---|
| **SAL-Q1** | Do the alt tables stay in the **consensus file** (same `Database`, same `WriteBatch`), or move to a second file as the pool did — or into the pool file? | **RULED: consensus file — approved, with the method written into the row.** The answer was reached by checking S-POOL's grounds *against this surface* — privacy-bearing state (absent: alt blocks are public), never inside a chain write (absent: SAL-10), discardable wholesale (satisfied by AL3) — which is why the two files differ *for a reason* rather than by whoever asked first; `SPL-Q2`'s reopening criterion is what sent the question here, and this row is its discharge. | SAL-1: the switch is the one place atomicity with `connect`/`pop` is the property, and it is only expressible in one transaction. SAL-10: the C++ already writes alt rows inside the chain batch. The pool's grounds (`SPL-Q2`: privacy-bearing state; never inside a chain write; discardable wholesale) are absent, absent, and satisfied by AL3. "Not chain state" (§11.2) is a *digest* statement, honoured by `Excluded`, not a file statement. The pool file is wrong for the same reason a second file is: a switch would then span two databases with no transaction across them. |
| **SAL-Q2** | One row per alt block — record, block bytes and witness in one `Coded<AltBlock>` — or the LMDB shape, three tables (`alt_meta`, `alt_block`, `alt_witness`) with an SI-16-style pairing invariant? | **RULED: one row — approved.** Three tables would reproduce LMDB's split for no reason; the record is one logical thing and the split was storage mechanics. | Every reader that wants the record's bytes wants the block too, or wants only membership (SAL-12, served by AL5 without a decode). The pairings become unrepresentable rather than enforced; CW-2's lifetime clause is a field's lifetime. Alt blocks are few (a table dropped at every init) so the copy cost of one row is not a consideration. Precedent for bytes inside a `Coded` record: `BondRecord` (`codec/archival.rs:305`). Reopens if E5 shows a hot record-only read — a walk that needs `height`/`coins_generated` per step without the block — in which case `alt_record` splits the row *by op*, not by table. |
| **SAL-Q3** | `remove` of an absent key: typed refusal (`AltCannot::NotHeld`, the C++ throw at `:4354`) or idempotent success (the pool's P3 choice)? | **RULED: refusal — approved, reason REPLACED.** | *Ruled reason:* removing what is not held is a **caller-contract violation**, and `AltCannot::NotHeld` makes the caller state what it expected — L14's insert-versus-upsert ruling applied to a remove. Had the C++ returned silently the answer would still be refusal. *The posed reason* ("the C++ throws; polarity reproduced") was the transcription reflex and happened to reach the right answer; kept here only as the record of what was posed. The consequence stands: an absent key means the switch's own bookkeeping is wrong, and surfacing it aborts SAL-1's closure. |
| **SAL-Q4** | `block_weight: Option<BlockWeight>` with `None` for the C++ zero sentinel, or `BlockWeight` with zero carried? | **RULED: `Option` — approved by the discriminator, not by pattern.** `0` is an impossible weight (every block has a coinbase), so the sentinel is unambiguous; and `None` carries a distinct, caller-actionable meaning — *not yet validated far enough to have a weight* — which is exactly what a cumulative-weight comparison must not consume silently. | `:2345` writes `0` for "cannot determine"; a block with a miner tx never weighs zero, so the sentinel is unambiguous and the type says what the zero meant. The consumer (`get_alternate_chains`'s `block_weight` field; the alt window's weight inputs if any) decides what to do with `None` — the rule's business, not the store's (S-ARCH discipline). |
| **SAL-Q5** | Keep AL5 `contains` as a separate op, or fold it into AL4 (`alt_block(h)?.is_some()`)? | **RULED: keep — approved, on performance, stated so.** `have_block` per announced hash is a hot path, and a full record read (decode plus a block-blob copy) to answer a membership question is real waste. **Performance is the legitimate reason for a separate read here**; the op is not an accidental duplicate of AL4 and its doc comment says why it exists. | `have_block_unlocked` (`:3004`) runs per announced hash; a membership test that decodes and copies a block for a `bool` is the wrong shape on a p2p path. `contains` is a `get` whose guard is dropped undecoded. |
| **SAL-Q6** | `FOLDED_INTO` as a fourth gate direction (own array, own three refusals), or widen `MIRRORED_ELSEWHERE`'s twin cell to mean "table or host"? | **RULED: own direction — approved.** Widening `MIRRORED_ELSEWHERE` would make one vocabulary term mean two relationships — the defect `RELAY_STATE_REFERENCE_SHAPES.md` is about, arriving in a gate's vocabulary. | A twin *table* is checked by opening its definition in the named file; a host *field* is checked by the host table's definition existing here and the LMDB name's definition not. Different checks, different failure messages; one array that means two things is the allowlist-by-name the gate was built to avoid (SPL-2). |

---

## 10. Documentation owed by the increment (rule 91) — discharged 2026-09-25 (commit 3)

- `DAEMON_REDB_STORE.md` §5 S-ALT row → LANDED (6 → 7 mapping; the witness
  pair's disposition; Methods cell **6**, unchanged — SAL-3); §11.2's table
  list (the witness table folded); the DRS-E1 increment list.
- `CONSENSUS_STORE_RECONCILIATION.md` CEN-K3 row: anchor →
  `AltCannot::AlreadyHeld` (state unchanged).
- `ARCHIVAL_CREDIT_WIRE.md` §3 CW-2: the hash-keyed witness is a field of
  the alt record in the redb store; the ownership rule is structural.
- `LMDB_SCHEMA.md` (or its successor): `archival_alt_attestation_witness`
  marked folded in redb.
- `DRS_E1_SARCH.md` §2.1 rows #16, #17: "landed with S-ALT as
  `AltBlock.attestation_witness`".
- `IMPLEMENTATION_INDEX.md`: `SAL-` rows LANDED with the verify grep; the
  §4 code-anchors paragraph.
- `LMDB_WRITE_ATOMICITY_AUDIT.md` §"non-canonical": the class's open item
  (alt boundary declared, not enforced) closed by the `alt_blocks` exclusion
  test; the witness's §7.1.1 KAT obligation now routed through `alt_blocks`
  (SAL-15) — a dated note; the inventory rows are the audit's pin.
- **Carried to E5's plan when it is written:** SAL-14's deletion row for
  `rollback_blockchain_switching` with its falsifier, and SAL-13's demotion
  sequence.
- **Carried to E4's plan (the archival write half) as one item:** the
  witness's non-canonical classification is a dated conditional that
  expires when the apply path ports (§7.1.1's KAT obligation goes live),
  **and** the route the KAT exercises is AL1 → AL4 → the height-keyed row
  (SAL-15). Neither half alone: the first without the second is a table
  that looks settled; the second without the first is a route with no
  reason to run it.
- `CHANGELOG.md`: one Unreleased line if the layout bump is judged
  user-visible (a store re-create at 12 → 13 is, pre-genesis, `rm -rf`).
- This file: `Status` → LANDED with the as-built row in §11.

---

## 11. Decision log

| Date | Entry |
|---|---|
| 2026-09-25 | **Copilot round on PR #856 — four findings, all validated at source, all applied.** **(1)** SAL-1 / SAL-14 overstated what one `ChainStore::write` closure covers: the store rows, not the pool re-adds, the hard-fork step or the cache invalidation `pop_block_from_blockchain` and promotion also perform (`:711`, `:738`, `:753`) and the C++ rollback also undid. The deletion stands for the store half; the non-store half's owner is an **ordering rule** — apply pool and cache effects from the closure's `Ok` (chain-first, pool-second, `SPL-Q5`) — written into §2.3 and SAL-14 so E5 inherits a deletion *plus* an ordering rule. **(2)** §4 wrote the shaped key as `[u8; 32]`; the table is `compare_hash32` and the key-types gate maps that to `LmdbHashKey` — corrected; `BlockHash` converts at the API boundary. **(3)** §3.4's `AltBlock` row described `checked()` as an emptiness check over untyped bytes; sharpened to the shared validation (`BlockBody::well_formed`, `AttestationWitnessBytes::well_formed`), an explicit parse boundary (`block()` returns a parsed `Block`; no raw-bytes surface), and a new AL1 belt `AltCannot::IdentityMismatch` — the key must hash the block. **(4)** §0 and SAL-10 said the alt store is "only ever" written inside a chain transaction; `drop_alt_blocks` opens its own (SAL-9) — narrowed to the admission and reorg writes. |
| 2026-09-25 | **As built — the increment (three commits stacked on #856), with its deviations from the ruled plan disclosed (rule 22).** **(1) Names carry the family.** The ops live on the `WriteBatch` / `ReadSnapshot` that `connect`, `pop` and every other surface share, so `insert` / `remove` / `drop_all` / `contains` / `len` / `entries` became `insert_alt_block` / `remove_alt_block` / `drop_alt_blocks` / `has_alt_block` / `alt_block_count` / `alt_blocks` — a bare `insert` on a shared handle names nothing. **(2) AL7 returns `Vec<AltEntry>`**, not an iterator: one body serves the snapshot's `ReadOnlyTable` and the batch's write `Table`, and the table is small by construction (SAL-8). **(3) `AltCannot { AlreadyHeld, NotHeld }`** — the ruled `EmptyBlock` is unreachable at the store because `AltBlock` has private fields and one constructor, `checked(facts, block, witness)`, which refuses block bytes that do not parse (`BlockBody::well_formed`, the `blocks` table's rule), a present-but-malformed witness (`AttestationWitnessBytes::well_formed`, the height-keyed twin's rule) and a zero weight; decode refuses the same three, so a row that decodes is a row `checked` would have built. **(4) SAL-2's key-types claim was wrong** and the gate said so: both tables fired the `compare_hash32 → LmdbHashKey` constraint, so the fold moves the floor 25 → 24 (the row above corrected in-line). **(5) Alt writes bypass the journaling handles on purpose.** `InsertTable::insert` treats a present key as an `SI-` row and poisons the batch; a present alt key is a refusal, not an invariant. And alt rows must never enter a pop journal (a pop must not delete a block demoted in the same batch), which the batch's own sequence guarantees — the recording is live only inside `connect` — and a `debug_assert` states. **(6) `ArchivalFamily::AltAttestationWitness` stays.** The family list is pinned against the LMDB X-macro, where the table still exists for the C++; in this store a policy that stubs that family has nothing to skip — the witness travels in the alt row, which is not an archival write. E4's plan inherits that note with SAL-15's carry. **What the tests hold** (§7 as executed): 4 codec tests (round trips, every refusal at `checked` and at decode against hand-forged bytes), 5 store tests (the ops and both readers seeing the batch's own writes; both refusals non-fatal; SI-7 on a corrupt row — the snapshot arms nothing, the batch poisons and refuses to commit; **the switch as one transaction** — pop, demote, connect, remove in one closure, then the same closure failing at its last step with the pop, the insert and the remove all not landed; **the digest boundary** — an alt block with a witness moves `logical_state_digest_v0` by nothing, and neither does its removal), 1 schema test (`folded_tables_are_absent_here_and_their_host_is_defined`); the bijection selftest gains five `FOLDED_INTO` refusals and the parse refusal. |
| 2026-09-25 | **Round 1 RULED** (maintainer, PR #856). All six defaults approved. **Q1** with the method in the row: the answer was reached by checking S-POOL's grounds against this surface, which is why the two files differ for a reason. **Q3's reason replaced**: refusal because removing what is not held is a caller-contract violation (L14's insert-vs-upsert applied to a remove), not because the C++ throws — the posed reason was the transcription reflex. **Q4** earns `Option` by the discriminator (`None` = not yet validated far enough to have a weight). **Q5** keeps `contains` on performance, stated explicitly. **Q6** own direction: one vocabulary term must not mean two relationships. **Two findings added:** SAL-14 (`rollback_blockchain_switching` is deleted, not ported; its absence is the evidence SAL-1 landed — row and falsifier carried to E5's plan) and SAL-15 (the fold moves the witness's §7.1.1 KAT obligation onto `alt_blocks` without moving the archival bar's count, and lets the audit's "declared, not enforced" alt boundary be enforced by one exclusion test — written in commit 2). **The increment may be cut.** |
| 2026-09-24 | **Round 0 executed** at `9532b58f5`. Thirteen findings (SAL-1 … SAL-13); six questions posed with defaults (SAL-Q1 … Q6). Nine methods on two tables map to seven operations; the witness pair (`SAR-Q5`) becomes a field; the alt tables stay in the consensus file for the reason the pool's left it — the switch is one transaction or it is not a switch. |

# DRS-E1 S-POOL — the transaction pool's store: increment plan and Round-0 pre-flight

**Status:** LANDED — **implemented 2026-09-24** on the S-POOL increment PR,
stacked on the pre-flight (#849) and cut at `f099d70df` (three commits, §7
as executed; layout **11 → 12**; `shekyl-chain-store::pool::PoolStore`, the
pool's own file with P1–P7 and SI-16 built; `txpool_meta` / `txpool_blob`
evicted from the consensus catalogue and §5.1's falsifier closed;
`PoolRecord` along §92.4's seams; `RelayMethod` / `NetZone` in
`shekyl_types::relay`; the bijection gate's third direction). As-built
deviations from the ruled plan are in §11 (2026-09-24, "as built"): the
commits re-cut two-plus-one, the class table's two rows kept, one layout
number for the crate's two files, `PoolCannot::PhaseWithoutOrigin`, the
responsibility as `Option`, and the census row's method for S-ALT.
**Round 0 executed 2026-09-24** at `dev` @ `a1159f1a2`;
**Round 1 RULED 2026-09-24** (maintainer, on PR #849; §9, each row
line-local): **Q1, Q2, Q3, Q4, Q5, Q7, Q8 approved, four with their reason
written into the row; Q6's default CORRECTED** — the codec refuses every
unrecognised relay state and `fluff` is never reachable by fall-through;
refusing `None` was a guard on a value nothing can write. The maintainer's
verification of SPL-4 surfaced that the tree already documents the
fall-through — as an aside inside a comment about `relayable`
(`blockchain_db.h:126–130`) — and it is now its own finding, **SPL-14**,
because `SPL-Q3` is the moment it is fixed or reproduced. **Copilot's
review round (same day) added SPL-15** — a ninth DB method the §5 row
never counted, reached past `Blockchain::` by the network path's membership
test — and sharpened four rows (§11). **Round 1 AMENDED the same day from
the Dandelion++ arc (maintainer; SPL-16, SPL-17, SPL-18):** the pool file's
write API is the chain store's closure shape and explicitly *not* a
caller-held batch with an aborting `Drop` (`LockedTXN`'s abort-on-drop is
the mechanism of the known relay-timestamp bug, not a property to carry);
the record's relay fields duplicate nothing the Zone holds (confirmed field
by field — the Zone refuses per-transaction state by its own doc), so Q7
stands; and the record's relay fields follow §92.4's decomposition —
`Origin` / `RelayPhase` / `Responsibility` — rather than a field-for-field
`RelayMethod`, which re-bundles what that round unbundled (**`SPL-Q9` RULED
2026-09-24: the decomposition**, with `Responsibility` a separate field —
not nested, because the two have different lifetimes — and `Arrived` +
`Armed` refused at decode and at write). **The increment may now be cut
from `dev` (§7).** This file stays in `design/` as the E1/E5 boundary statement
(§0, §2.2, §2.3) until E5's plan owns it. Implements *from*
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §5 (the S-POOL row:
extraction order **8**, "no consensus state and no dependency on the chain
surfaces … privacy-sensitive (Dandelion++)"), **§5.1** (the DRS-0 slice-C
pick, `ba4b3c73a`: *"the pool does not live in the consensus store file"* —
a separate store file that may be discarded wholesale; **falsifier: any pool
table in the consensus store's `TableDefinition` set**), §11.2 (the pool is
*not chain state*: replay cannot produce it, every digest excludes it) and
§7.5 (the nine 4.M policy rows arrive through **E5's `AdmissionPolicy`**,
never as `RuleSet`); from [`DRS_E1_SARCH.md`](DRS_E1_SARCH.md) (the E1 shape
this increment repeats: shapes minted for a writer that is another
increment's, absence carried by the type, vocabulary in `shekyl-types`, a
record re-specified rather than ported); and from
[`LMDB_WRITE_ATOMICITY_AUDIT.md`](../LMDB_WRITE_ATOMICITY_AUDIT.md) §4
(fourteen `LockedTXN` constructions, thirteen commits; wart **DRS-W2**, the
commit that cannot fail loudly). Process per `26-sub-pr-design-discipline.mdc`;
identifier families **`SPL-`** (findings) and **`SPL-Q`** (round questions)
registered in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by the
PR that adds this file (rule 94 §1; `check_index_prefix_uniqueness.py`
branch (a): the two parse to distinct prefixes — `SPL-`, `SPL-Q` — and clear
the 97 registered; `SP-` and `SP-T` are different prefixes by the gate's own
grammar, checked rather than judged by appearance).

**The pick that is already falsified, re-read rather than inherited (rule 22).**
§5.1's row says *"depends on the slice-B schema map; if one file is ruled
instead, the fallback pick is wipe-on-open"*. Slice B mapped LMDB's
inventory 1:1 into `schema.rs`, so at this pin `TXPOOL_META` and
`TXPOOL_BLOB` sit in the consensus store's `TableDefinition` set
(`rust/shekyl-chain-store/src/schema.rs:350`, `:353`, both `Unshaped`) — the
row's own falsifier, firing since 2026-09-12, unnoticed because nothing reads
a falsifier. Neither pick was ever *chosen* against the map; the pool tables
simply arrived with everything else. This document is the re-read: the
separate file is the ruled disposition, this increment builds it, and the
eviction of the two tables from the consensus store is its first
consequence (SPL-1).

**Two lanes, stated once.** *E1 S-POOL* (this document) is the **store**:
the pool file, the record's type and codec, the seven typed operations the
pool performs on its store, and the store invariant those operations keep.
*E5* is the **pool**: admission (`AdmissionPolicy`, the nine 4.M rows,
`PoolView` decorating `ChainView`), the relay state machine, eviction, the
block-template selection and every in-memory index. E1 mints what E5 writes
into and reads from; E5 does not get to choose a second shape for the same
byte (the S-CURVE contract). Nothing in the C++ pool moves in this
increment: `tx_memory_pool` stays the live pool over LMDB until the cutover,
as every other C++ consumer of every other E1 surface has.

---

## 1. Preconditions, as found at the pin

| Precondition | State at `a1159f1a2` |
|---|---|
| S-TXN … S-ARCH read half (E1 increments 1–8) | landed (#740, #749, #757, #772, #783, #800, #815, #844) |
| `WriteBatch<'id>` (the commit-consuming write API, B3), `StoreError::class()`, `StoreInvariant`, `InsertTable`/`UpsertTable` | landed (E1 increment 2.5, 2026-09-15) — the shape DRS-W2's wart is closed by, available to a second file |
| `Canonical` codec vocabulary (`shekyl-store-codec`), `Coded<V>`, `Blob<K>`, `Present`, `Unshaped`, the rule-42 snapshot gate | landed; `SCHEMA_VERSION = 11` (`codec/schema_version.rs:116`, S-ARCH's bump) — this increment bumps to **12** (the eviction) |
| `header::seal` / `header::verify` — a sealed file refuses to open without its shaped tables (SI-7, SCR-17) | landed — the pattern the pool file's own header repeats |
| `txpool_meta`, `txpool_blob` in the redb schema | landed, **`Unshaped`, in the consensus file** (`schema.rs:350`, `:353`; `tables.snap` #13, #14) — §5.1's falsifier, firing (SPL-1) |
| `accumulator/class.rs` grades both `Excluded` (`:160–161`); `digest_v0` excludes txpool (`digest_v0.rs:24`); §11.2 "not chain state" | landed — this increment moves no digest family (SPL-12) |
| `RelayMethod` (five variants, byte-pinned to `cryptonote::relay_method`) and `NetZone` (four, pinned to `epee::net_utils::zone`) | exist in `shekyl-relay` (`zone_route.rs:67`, `:104`), FFI-mirrored by value and `const` assert — not in `shekyl-types`, and the daemon store cannot depend on `shekyl-relay` (SPL-6, `SPL-Q6`) |
| `check_redb_schema_bijection.py` — every X-macro table has exactly one `TableDefinition` in `schema.rs`; `RUST_ONLY_TABLES` is the one exception direction | landed — has **no** "mirrored in another file" direction (SPL-2) |
| `check_redb_schema_key_types.py` — 49 definitions / 27 constraints, `txpool_meta hash key` among them (`:327`) | landed — the constraint follows the table when it moves (SPL-2) |
| §5.1 pick: separate pool file | **RULED 2026-09-12** (`ba4b3c73a`), unbuilt; this is its increment |
| E5 (pool / alt / prune; `AdmissionPolicy`) | **not started**; named in the DRS graph (§7, `E4 --> E5`) and table 3's 4.M row ("slice 10 with E5"); no plan document yet |

The stated dependency is E1 increment 2.5's write API and the codec
vocabulary, and nothing from a later surface. **Unblocked**, and the only E1
surface whose writer is not a chain event: the pool writes on p2p arrival,
on relay ticks, on block connect (`take_tx`) and on pop (`add_tx` of the
block's transactions), all through the pool's own lock.

---

## 2. Scope

### 2.1 In — the census, method by method

Eight methods on the §5 row (`blockchain_db.h`; declaration line in the
table) **plus a ninth the row's census missed** (#9, SPL-15 — reached
through `m_blockchain.get_db()`, past `Blockchain::`, which is what the §5
partition enumerated). **Every one of the eight is a `Blockchain::`
pass-through** (`blockchain.cpp:6610–6652`: eight one-line forwards to
`m_db`, no logic), and **every production caller is `tx_memory_pool`**
(`tx_pool.cpp`, 31 call sites in 28 functions, enumerated by `rg` at the
pin and mapped to their enclosing function by script). `blockchain.cpp` is a corridor, not a consumer (SPL-3). **Class**
is what the *pool* does at the site: *admit* (`add_tx`, `insert_attested_tx`),
*relay* (the relay state machine: `get_relayable_transactions`,
`set_relayed`, `on_stem_propagated`), *evict* (`prune`,
`remove_stuck_transactions`), *take* (block connect / pop: `take_tx`,
`get_complement`), *template* (`fill_block_template`,
`get_block_template_backlog`), *serve* (RPC and the engine facts:
`get_transactions*`, `get_pool_for_rpc`, `get_transaction_info`,
`get_transaction_stats`, `get_transaction_backlog`, `print_pool`),
*index* (the key-image conflict map: `insert_key_images`,
`check_for_key_images`, `have_tx_keyimg_as_spent`), *init* (`init`,
`validate`).

| # | Method (`blockchain_db.h`) | Table(s) | Pool callers (enclosing function; class) | Rust op |
|---|---|---|---|---|
| 1 | `add_txpool_tx(txid, blob, meta)` (`:1765`; `db_lmdb.cpp:2054`) — puts **both** rows with `MDB_NODUPDATA`, throws on an existing key | `txpool_meta`, `txpool_blob` | `add_tx` `:348` (kept-by-block arm), `:508` (after a `remove_txpool_tx` at `:507` — the upgrade path is remove-then-add, i.e. an **upsert**); `insert_attested_tx` `:644` | **P1** `insert(TxHash, PoolRecord, &[u8]) -> Result<(), PoolCannot>` — refuses an existing key (the C++ throw, typed); the `add_tx` upgrade's remove+add is **P3 then P1** in one batch, as today |
| 2 | `update_txpool_tx(txid, meta)` (`:1773`; `:2080`) — delete-then-put of the meta row only; throws if absent | `txpool_meta` | `get_relayable_transactions` `:1229` (stem next-attempt time); `on_stem_propagated` `:1260` (`observed_circulating`); `set_relayed` `:1304` (class upgrade, `relayed`, the embargo draw); `mark_double_spend` `:2002`; `fill_block_template` `:2188` (readiness cache, written only when the record changed — `memcmp` at `:2181`); `validate` `:2286` | **P2** `update(TxHash, PoolRecord) -> Result<(), PoolCannot>` — refuses an absent key; meta only, the blob is immutable for the entry's life |
| 3 | `remove_txpool_tx(txid)` (`:1790`; `:2177`) — deletes both rows, **idempotent** (absent is not an error) | both | `add_tx` `:507`; `prune` `:754`; `take_tx` `:902`; `remove_stuck_transactions` `:1120`; `init` `:2409` (unparseable blob) | **P3** `remove(&TxHash) -> Result<(), StoreError>` — idempotent, both rows |
| 4 | `get_txpool_tx_meta(txid, out) -> bool` (`:1800`; `:2207`) | `txpool_meta` | `add_tx` `:375` (`existing_tx`); `prune` `:728`; `take_tx` `:865`; `get_transaction_info` `:931`; `on_stem_propagated` `:1250`; `set_relayed` `:1288`; `get_block_template_backlog` `:1411`; `mark_double_spend` `:1990`; `fill_block_template` `:2083` | **P4** `record(&TxHash) -> Result<Option<PoolRecord>, StoreError>` |
| 5 | `get_txpool_tx_blob(txid, out, category) -> bool` (`:1811`, throwing overload `:1820`; `:2228`, `:2265`) — reads the meta row first when `category != all` and answers `false` for a non-matching class | `txpool_blob` (+ `txpool_meta` under a filter) | `prune` `:745`; `take_tx` `:873`; `get_transaction_info` `:941`; `get_complement` `:1015` (**`broadcasted`**); `remove_stuck_transactions` `:1110`; `get_relayable_transactions` `:1207`; `get_block_template_backlog` `:1415`; `get_transaction` `:1665` (caller's category); `fill_block_template` `:2162` — eight of nine pass `all` | **P5** `blob(&TxHash) -> Result<Option<Vec<u8>>, StoreError>` — **no category parameter**: the filter is `record(h)?.filter(\|r\| r.method.matches(cat))` at the caller (SPL-3); one call site (`get_complement`) composes it |
| 6 | `get_txpool_tx_count(category) -> u64` (`:1778`; `:2106`) — `mdb_stat` for `all`, a **full meta scan** for any other category | `txpool_meta` | `get_relayable_transactions` `:1152`; `get_transactions_count` `:1328`; `get_transactions` `:1336`; `get_transaction_hashes` `:1356`; `get_transaction_backlog` `:1370`; `get_transaction_stats` `:1451`; `get_transactions_and_spent_keys_info` `:1536`; `get_pool_for_rpc` `:1593–1594` — all as `reserve()` hints or an RPC count, most with `include_sensitive ? all : broadcasted` | **P6** `len() -> Result<u64, StoreError>` (the `all` count, O(1)); a per-class count is `entries().filter().count()` at the caller — the C++ already scans for it |
| 7 | `txpool_tx_matches_category(txid, category) -> bool` (`:1830`; **`blockchain_db.cpp:1885`**, non-virtual: `get_txpool_tx_meta` then `meta.matches`; `false` on absent *and* on a DB error, with an `MERROR`) | `txpool_meta` | `insert_key_images` `:800`; `get_transactions_and_spent_keys_info` `:1578`; `get_pool_for_rpc` `:1627`; `check_for_key_images` `:1651`; `have_tx_keyimg_as_spent` `:1721` — all `broadcasted` but one | **none** — dissolves into **P4** + `RelayMethod::matches(category)` (SPL-3); the "absent ⇒ false" and "error ⇒ false" collapse the C++ made is not carried (§3.3) |
| 8 | `for_all_txpool_txes(f, include_blob, category) -> bool` (`:1887`; `:2273`) — meta scan in key order, optional blob join (throws if a meta row has no blob — the pairing invariant, enforced at read), class filter, early exit on `f == false` | both | `get_complement` `:1005`; `remove_stuck_transactions` `:1054`; `get_relayable_transactions` `:1153` (`relayable`, no blob); `get_transactions` `:1337`; `get_transaction_hashes` `:1357`; `get_transaction_backlog` `:1371`; `get_block_template_backlog` `:1386`; `get_transaction_stats` `:1454`; `get_transactions_and_spent_keys_info` `:1539`; `get_pool_for_rpc` `:1595`; `print_pool` `:2023`; `validate` `:2253`; `init` `:2380` (two passes, blobs, `all`) | **P7** `entries(&self) -> impl Iterator<Item = Result<PoolEntry, StoreError>>` with `PoolEntry { txid, record }` and `PoolEntry::blob(&self)` a second read on demand — class filter and early exit are the iterator's consumer's; the pairing invariant is **SI-16** (§5) |

| 9 | `txpool_has_tx(txid, category) -> bool` (`:1783`; `db_lmdb.cpp:2151`) — meta lookup, then `matches` unless `all`; **not on the §5 row** and **not a `Blockchain::` forward**: `tx_memory_pool::have_tx` reaches it through `m_blockchain.get_db()` (`tx_pool.cpp:1689–1694`) | `txpool_meta` | `have_tx` `:1693` — whose callers are `core::handle_incoming_tx` `cryptonote_core.cpp:999` (`broadcasted`, CEN-M1's idempotent-accept), `core::pool_has_tx` `:1512` (`all` — the protocol's "do I hold these bytes", `cryptonote_protocol_handler.inl:634`, and `levin_notify`'s `i_core_events::pool_has_tx`), and the alt-block supplement path `blockchain.cpp:2287`, `:2318` (`broadcasted`) | **none** — dissolves into **P4** + `matches` (`all` → `record(h)?.is_some()`); *the* membership read a cutover following the §5 row alone would have omitted (SPL-15; Copilot, PR #849) |

#7 is the `BlockchainDB` non-virtual over #4; #9 is its `BlockchainLMDB`
virtual twin with its own callers. Both dissolve the same way.

### 2.2 Out (named, so it is not scope shed by omission)

- **The pool.** `tx_memory_pool` entire — admission (`add_tx`,
  `insert_attested_tx`; the nine 4.M rows CEN-M1 … M11 minus M8's field),
  the relay state machine (`set_relayed`, `get_relayable_transactions`,
  `on_stem_propagated`; `relay_method`'s monotone upgrade and the `local`
  origin pin, `tx_pool.cpp:389–458`), eviction (`remove_stuck_transactions`,
  `prune`, `m_txpool_max_weight`), block-template selection and the
  fee/receive-time order, the key-image conflict map (`m_spent_key_images`),
  the parsed-tx cache, `m_cookie`, `m_next_check`. **E5.** This increment
  mints the store E5's pool writes into; it does not decide when a pool
  writes or what class a transaction is in.
- **`relay_category` and `matches_category`** (`blockchain_db.h:114–168`,
  `blockchain_db.cpp:51–96`) — the classifier is pool policy, not storage.
  The store persists the **method**; the *category* a method matches is a
  function the consumer applies (`RelayMethod::matches`, where the enum
  lives — `SPL-Q6`). The three-way table with its nested exhaustive
  `switch` and its "fail closed for an out-of-domain category" property
  travels with the enum.
- **The in-memory indices** — rebuilt from the store at `init`
  (`tx_pool.cpp:2362–2425`, SPL-9). The store offers enumeration (P7) and
  nothing index-shaped; a fee-ordered secondary table would be a second
  source of truth for a derived order.
- **`LockedTXN`** (the pool's transactional wrapper; audit §4, FOLLOWUPS
  "`tx_pool` / `blockchain_db` LMDB transactional wrapper — typed
  commit-or-abort") — the C++ wrapper stays with the C++ pool, and **none
  of its semantics travel** (SPL-16): not the batch-nesting (lost with the
  second file, SPL-7) and not the abort-on-drop (the mechanism of the
  relay-timestamp bug). Its Rust successor is `PoolStore::write(|batch| …)`,
  the chain store's closure shape, in which forgetting to commit is
  unrepresentable (SPL-11); the FOLLOWUPS row is about the C++ and is not
  closed here.
- **The consensus-store schema's alt tables** (`alt_blocks`,
  `archival_alt_attestation_witness`) — §11.2 groups them with the pool as
  "not chain state", and they raise the same *which file* question. **E5
  S-ALT's**, not asked here; recorded so the two answers are given by the
  increments that own the tables and can be checked against each other
  (`SPL-Q2`'s reopening criterion names it).
- **The DRS-BENCH residue measurement** (§5.1 row 1, "file growth over
  multi-year small commits") — the pool file is the surface that makes the
  measurement *possible* to scope (pool churn is the small-commit workload);
  the measurement is BENCH's.

### 2.3 What E5 gets from this increment

A pool store it did not have to design: **one file**, opened and sealed by
its own header; **two tables** typed (`pool_meta[TxHash] → Coded<PoolRecord>`,
`pool_blob[TxHash] → Blob<PoolTxBytes>`); **seven operations** (P1–P7) whose
absence and refusal cases are the type's; **one invariant** (SI-16) the
operations keep and the enumeration checks; a `PoolRecord` whose relay
class, timing and verification cache are typed rather than bit-decoded; and
the contract that the pool file commits **after** the chain file on a block
connect and reconciles at open (SPL-7, `SPL-Q5`). E5 writes what these
operations write and reads what they read; the admission policy, the relay
clock and the indices are its own.

### 2.4 What the consensus store gets

Two tables fewer and a closed falsifier. Layout **11 → 12**: `txpool_meta`
and `txpool_blob` leave `schema.rs`, `tables.snap` goes 49 → 47 and
`Unshaped` 22 → 20; `accumulator/class.rs` loses two `Excluded` rows (the
class table describes the consensus file); the bijection and key-type gates
learn the direction "mirrored in another file" (SPL-2). §11.2's *not chain
state* group loses its first two members to a **boundary** — the sentence
the section already wrote for it: *"slice C's §5.1 pick moves the pool out
of the consensus store file entirely, which makes this a boundary rather
than an exception."*

### 2.5 What DRS-E2 gets

Nothing to compare, by construction: the pool is not chain state, no digest
reaches it (`digest_v0.rs:24`, §11.2), and there is no LMDB pool to replay
from — the pool file's first writer is E5's pool, not a replay. E2's
`pipeline_tests` and `digest_read_tests` are unchanged in outcome (SPL-12);
they are the belt that proves it.

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the store lives

`rust/shekyl-chain-store/src/pool/` (`SPL-Q2`, default): a module with its
own `Database` handle (`PoolStore::create(path)` / `open(path)`), its own
header cell and version, its own two tables and `PoolCannot` refusals,
sharing the crate's `Canonical` vocabulary, `Blob`/`Coded` wrappers, the
commit-consuming batch shape and the CI gates that already read this crate.
**Not** a table set in `ChainStore`: the two files never share a
transaction, and the type system says so by giving them different handles.
The alternative — a sibling crate `shekyl-pool-store` — is `SPL-Q2`.

### 3.2 The mapping — nine methods, seven operations

| Op | Signature | Replaces | Semantics |
|---|---|---|---|
| **P1** | `insert(&mut self, txid: TxHash, record: PoolRecord, blob: &[u8]) -> Result<(), PoolCannot>` on the write batch | #1 | Both rows in one write; an existing key is `PoolCannot::AlreadyHeld` (the C++ `MDB_KEYEXIST` throw, "Attempting to add txpool tx metadata that's already in the db", typed and non-fatal — the pool decides whether to upsert by removing first, as `add_tx` does at `:507–508`). An empty blob is `PoolCannot::EmptyBlob` (a pool entry is a transaction; Copilot, PR #849 — the refusal now has a representable result). |
| **P2** | `update(&mut self, txid: &TxHash, record: PoolRecord) -> Result<(), PoolCannot>` | #2 | Meta row only; an absent key is `PoolCannot::NotHeld` (the C++ "Error finding txpool tx meta to update" throw). The blob is immutable for the entry's life — the C++ has no blob update and `add_tx`'s upgrade path removes the entry to change it. |
| **P3** | `remove(&mut self, txid: &TxHash) -> Result<(), StoreError>` | #3 | Both rows; idempotent (the C++ ignores `MDB_NOTFOUND` on each). |
| **P4** | `record(&self, txid: &TxHash) -> Result<Option<PoolRecord>, StoreError>` | #4, and #7's meta read | `None` is "not in the pool" — the state every caller branches on (`existing_tx`, `have_tx`). An undecodable row is SI-7. |
| **P5** | `blob(&self, txid: &TxHash) -> Result<Option<Vec<u8>>, StoreError>` | #5 | The bytes, unparsed (the store does not parse a transaction — S-CHAIN-R's `RawBlockBytes` discipline). `None` is "not in the pool". No category parameter (SPL-3). |
| **P6** | `len(&self) -> Result<u64, StoreError>` | #6 (`all`) | The table's length. A per-class count is the caller's fold over P7. |
| **P7** | `entries(&self) -> impl Iterator<Item = Result<PoolEntry, StoreError>>`, `PoolEntry { txid: TxHash, record: PoolRecord }`, `PoolEntry::blob(&self, snapshot) -> Result<Vec<u8>, StoreError>` | #8 | Key order (natural, SPL-8). The blob is a second read the consumer asks for — six of the thirteen `for_all` callers pass `include_blob = false`. A meta row whose blob is missing is **SI-16**, named by the read that found it, not the `DB_ERROR` string the C++ throws. |

Reads (P4–P7) are on a read snapshot of the pool file; writes (P1–P3) inside
`PoolStore::write(|batch| …)` — **the closure shape the chain store already
has** (`store/mod.rs:445–470`: the store constructs the batch, runs the
closure, and `complete(outcome)` commits on `Ok` and aborts on `Err`; an
unwind aborts). The caller never holds the batch across a return, so
*forgetting to commit* is unrepresentable (B3) — which is the property
`LockedTXN` lacked (SPL-16). **Explicitly not** a caller-held `PoolBatch`
with `commit(self)`: that shape's `Drop` aborts silently on any early return,
which is `LockedTXN`'s abort-on-drop in a new language — the mechanism of
the known Dandelion++ bug — and was this section's first draft (corrected
2026-09-24, §11). DRS-W2 (`LockedTXN::commit` swallowing `batch_stop`'s
exception) is closed the same way: the store's `complete` returns the
commit's `Result` (SPL-11).

### 3.3 Absence, faults, and what an operation may not do — the S-TX discriminator applied

- **"Not in the pool" is a case.** P4/P5 return `Option`; the C++ `bool` +
  out-param is the same shape less the type.
- **"Not matching the category" is not the store's absence.** #5 and #7
  answer `false` for a held entry whose class does not match — the same
  `false` as "not held". Two facts, one bit; the pool's `have_tx(h, broadcasted)`
  semantics rely on the collapse (a `local` entry "is not in the pool" for a
  peer's purposes — §92's carve-out, `tx_pool.cpp:445–447`). Typed apart:
  `record(h)` says held-or-not, `record.method.matches(cat)` says
  visible-or-not; the pool composes the bit it wants and the reason is
  legible at the site.
- **"Error ⇒ false" is not carried.** `txpool_tx_matches_category` returns
  `false` on a DB exception with an `MERROR` (`blockchain_db.cpp:1885–1900`);
  its five callers cannot tell a missing entry from a broken store. `Result`.
- **Two sentinels and one overload in the timing fields** (SPL-5) — typed.
- **An unknown relay-bit state decodes to `fluff`** — *broadcasted*, the
  leaking direction (`blockchain_db.cpp:132–165`, `default: // error case`;
  SPL-14). A `PoolRecord` that does not decode is SI-7; **nothing decodes to
  public**: `RelayMethod`'s decoder is exhaustive over its five pinned bytes
  with no default arm, and `Fluff` is reached only by its own discriminant
  (`SPL-Q3`, `SPL-Q6` as RULED).
- **What an operation may not do:** classify (apply `relay_category`),
  order by fee, parse a transaction, decide eviction, or hold an index.

### 3.4 Types this increment adds — and where they live

| Type | Shape | Home (default) | Why |
|---|---|---|---|
| `RelayMethod` | `{ None, Local, Stem, Fluff, Block }`, `repr(u8)` byte-pinned to `cryptonote::relay_method`; **decoder exhaustive over the five bytes, no default arm, unknown ⇒ error** (RULED, `SPL-Q6`). **AMENDED 2026-09-24 (SPL-18):** the **FFI seam's word** — an arrival class handed in, a routing plan handed out — **not a field of `PoolRecord`**; the record persists `Origin` + `RelayPhase` and the seam converts `(origin, phase) → RelayMethod` where C++ still asks in that vocabulary | **moves to `shekyl-types`** from `shekyl-relay` (`SPL-Q6`); `shekyl-relay` re-exports; `matches(RelayCategory)` is defined on `(Origin, RelayPhase)` and the byte enum gets the derived form | Rule 18 (`SCU-Q2`, `SAR-Q2`): a word two crates need lives below both. The store cannot depend on `shekyl-relay`; a second `RelayClass` enum in the store is a conversion layer between two spellings of one fact. The decoder's shape is SPL-14's fix: `Fluff` is reached only by its own discriminant, never by fall-through; `None` is a legal, unreachable, non-relayable state and is **not** specially refused — a guard on it protects nothing. |
| `RelayCategory` | `{ Broadcasted, Relayable, All }` | with `RelayMethod` | The classifier's other operand; `RelayMethod::matches` is the C++ `matches_category` table, exhaustive on both sides. |
| `NetZone` | `{ Invalid, Public, I2p, Tor }`, `repr(u8)` pinned to `epee::net_utils::zone` | **moves to `shekyl-types`** (`SPL-Q6`) | Same ground; the record's `origin_zone`. |
| `PoolRecord` | `weight: u64`, `fee: AtomicUnits`, `receive_time: UnixSeconds`, **`origin: Origin`, `phase: RelayPhase`, `responsibility: Responsibility`** (the §92 decomposition, `SPL-Q9` — *as first written:* `relay: RelayClock`, `method: RelayMethod`, `observed_circulating: bool`, `origin_zone: NetZone`, superseded by SPL-18), `relayed: bool`, `double_spend_seen: bool`, `readiness: Readiness { max_used: Option<(BlockHeight, BlockHash)>, last_failed: Option<(BlockHeight, BlockHash)> }`, `fcmp_cache: Option<FcmpVerificationHash>` | `shekyl-chain-store::pool::record` (`Canonical`, `NAME = "pool_record"`) | The 192-byte packed `txpool_tx_meta_t` (`blockchain_db.h:218–348`, `LMDB_SCHEMA.md:1054–1078`) re-specified: **same semantics, not byte-compatible** (`SPL-Q3`, the `SAR-Q3` ruling's form). The five relay bits become the enum; two sentinels and an overload become `RelayClock`; the `fcmp_verified` bit and its hash become one `Option`; `pruned`, `do_not_relay` and `padding[44]` are not carried (SPL-6). The store's only reader is the store, so the record is the store's (the `BondRecord` as-built precedent, `DRS_E1_SARCH.md` §3.4). |
| `Origin` | `enum { Originated, Arrived { zone: NetZone } }` — **permanent**: written by P1, and P2 refuses a record whose origin differs from the stored one (`PoolCannot::OriginChanged`) | with `PoolRecord` (`SPL-Q9`) | §92.4's first clause, *provenance is permanent*, as a field that cannot be upgraded past because nothing upgrades it. Subsumes `is_local` and `origin_zone` (the C++ already writes `zone::invalid` for an originated entry; `Arrived { Invalid }` is the "origin unknown" arm for a pre-field record and stays representable). |
| `RelayPhase` | `enum { Held { last_attempt: Option<UnixSeconds> }, Stem { next_attempt: UnixSeconds }, Fluff { last_relayed: Option<UnixSeconds> }, Block { last_relayed: Option<UnixSeconds> } }` — each phase carries the clock word that phase means; `upgrade(origin, next)` is the ratchet **and the pin**: `Arrived` walks `Stem → Fluff → Block`; `Originated` walks `Held → Block` only (yields to proof of work, refuses a peer's `Stem`/`Fluff`) | with `PoolRecord` (`SPL-Q9`) | The ratchet's domain, with §92.4's pin as a transition rule that names its reason (`origin`) instead of a `relay_method::local` special case in `add_tx :456–458`. **Subsumes `RelayClock`** (SPL-5): `u64::MAX` is `Held { None }` / the absence of a clock, a stem deadline is `Stem { next_attempt }`, a past relay is `Fluff`/`Block { last_relayed }`, and the attested-local admission is `Held { Some(receive_time) }` — the overload dissolves because no single field means three things. `matches(Broadcasted) ⇔ Fluff \| Block`; `Relayable` is every phase (there is no `None`); `All`. The decoder has no default arm (SPL-14). |
| `Responsibility` | `enum { Armed, Disarmed }` — **a separate field, deliberately not nested inside `Origin::Originated`**, and legal only with it: `Arrived` + `Armed` is **refused at decode** (SI-7) **and at write** (`PoolCannot::ResponsibilityWithoutOrigin`), the way the relay discriminant refuses an unknown byte | with `PoolRecord` (`SPL-Q9` RULED) | §92.4's second clause and §92.5c item 1's third: re-broadcast responsibility ends when F-10's predicate fires; `on_stem_propagated` writes `Disarmed`. The C++ `observed_circulating` bit, given the only entry class it is defined for. **Why not nested, written here so nobody nests it later:** `Origin` is permanent and refused-on-change; `Responsibility` transitions `Armed → Disarmed`. Nesting the second inside the first makes the permanent field mutable and P2's `OriginChanged` refusal unenforceable. Two lifetimes, two fields; the unrepresentability nesting would buy is bought instead by the refusal. |
| ~~`RelayClock`~~ | ~~`enum { NotYet, NextAttemptAt(UnixSeconds), LastRelayedAt(UnixSeconds) }`~~ — **SUPERSEDED 2026-09-24 by `RelayPhase`'s per-phase clock words (SPL-18, `SPL-Q9`)**; the analysis in this row stands as the reason each phase carries its own | ~~with `PoolRecord`~~ | `last_relayed_time`'s three meanings (SPL-5): `u64::MAX` at admission ("never relayed", `tx_pool.cpp:470–473`); for a `stem` entry the **next attempt / embargo deadline** (`set_relayed :1297`, `get_relayable_transactions :1227`); otherwise the last relay time. Which arm is legal for which method is a `PoolRecord` construction check, not a decode-time guess. **Two admission rules, both explicit** (Copilot, PR #849): a *received* entry is admitted `NotYet` — its dispatch always follows and `set_relayed` overwrites it (`add_tx :470`); an *attested-local* entry (`insert_attested_tx`, `tx_pool.cpp:575–589`) is admitted **`LastRelayedAt(receive_time)`**, because its relay is fire-and-forget and the periodic loop is its stated fallback — and the C++ `u64::MAX` sentinel makes that fallback **permanently ineligible** (`now - max()` underflows, `get_relay_delay` returns a huge delay; the comment at `:580–585` says so). `NotYet` therefore means *dispatch pending, not eligible for the periodic fallback*, and E5's loop reads it as such — never as a timestamp. |
| `UnixSeconds` | `u64` newtype (wall-clock seconds) | `shekyl-types` | `receive_time` and the relay clock are **wall-clock**, not block time; `Timestamp` (a block header's field) is the wrong word for them and the two must not be addable. |
| `FcmpVerificationHash` | `[u8; 32]` (`hash32!`) | `shekyl-types` | CEN-M8's cache key: `H(proof ‖ referenceBlock ‖ key images)` (`tx_pool.cpp:495`). `fcmp_verified ⇔ Some` (SPL-10). |
| `PoolTxBytes` | `BlobKind`, `NAME = "pool_tx"` | `shekyl-chain-store::pool` | The raw transaction; empty refused. |
| `PoolCannot` | `{ AlreadyHeld, NotHeld, EmptyBlob, OriginChanged, ResponsibilityWithoutOrigin }` | `shekyl-chain-store::pool` | P1/P2's typed refusals — the pool's decisions, not faults (`StoreCannot`'s shape). `EmptyBlob` added on review (Copilot, PR #849): P1's row required the refusal and the enum did not carry it. `OriginChanged` (P2 handed a record whose `origin` differs from the stored one) and `ResponsibilityWithoutOrigin` (`Arrived` + `Armed`) are `SPL-Q9`'s two write-side refusals; the same two conditions are SI-7 at decode. |
| `PoolStore`, `PoolSnapshot<'_>`, `PoolBatch<'_>` | the handle, the read snapshot, the write batch **handed only to a `PoolStore::write` closure** (`#[must_use]`, never returned to a caller) | `shekyl-chain-store::pool` | One file, one writer (§3.6's process model, applied to a second file). The batch's shape is SPL-16's: the store decides commit or abort at the closure's exit; no code path holds a batch it could drop. |

### 3.5 What this surface inherits, and for how long

- **The two-table split** (meta beside blob) — **inherited**, on its merits:
  the meta row is rewritten on every relay tick, readiness probe and class
  upgrade (six `update_txpool_tx` sites) while the blob is written once;
  under redb's copy-on-write a single row would copy the transaction bytes
  on every relay-clock tick. Same two tables, typed, with the pairing made an
  invariant (SI-16) rather than a `DB_ERROR` string.
- **`compare_hash32` key order** — **not inherited** (SPL-8): the pool file
  has no LMDB twin to stay in step with, and no `for_all` caller depends on
  iteration order. `TxHash`'s natural byte order (`SCU-Q3`: remove the thing
  that needs pinning).
- **The 192-byte record layout** — **not inherited** (`SPL-Q3`). Nothing
  hashes, relays or migrates the persisted record: the C++ pool over LMDB
  runs to the cutover and is then gone with its file. The re-specification
  is free to choose its encoding and drops the dead fields.
- **`relay_method`'s byte values** — **inherited as the wire contract they
  already are** (`cryptonote_protocol/enums.h:39`, `zone_route.rs:46–50`'s
  `const` pins): the enum keeps `None = 0 … Block = 4` because the FFI seam
  is pinned to them. What the *store* does with `None` is `SPL-Q6`.
- **Persistence across restart** — **inherited as the default, its policy
  named as a question** (`SPL-Q7`): the C++ pool reloads every entry at
  `init` and resumes each relay clock where it stopped, including a stem
  entry's embargo deadline and a `local` origin's re-broadcast schedule.
  §5.1 made residue "a policy question rather than an engine-reclamation
  question" by moving the file; the policy — which entries a restarted node
  should still hold, and what the file's on-disk lifetime is — belongs to
  the relay-privacy lane, and this increment records the question where
  that lane will read it.

---

## 4. The store set, table by table

| Table | At v11 | After this increment (v12 of the consensus file; v1 of the pool file) | Op |
|---|---|---|---|
| `txpool_meta` (consensus file) | `LmdbHashKey → Unshaped` | **evicted** — no definition in `schema.rs`; named in the bijection gate's "mirrored elsewhere" map with the pool file as the twin (SPL-2) | — |
| `txpool_blob` (consensus file) | `LmdbHashKey → Unshaped` | **evicted**, likewise | — |
| `pool_meta` (pool file) | — | `[u8; 32]` (`TxHash`) → `Coded<PoolRecord>` | P1, P2, P3, P4, P6, P7 |
| `pool_blob` (pool file) | — | `[u8; 32]` → `Blob<PoolTxBytes>` | P1, P3, P5, P7 |
| pool file header | — | the pool file's own version cell (`SPL-Q8`) and creation seal | open/create |

Consensus-file layout `SCHEMA_VERSION` 11 → 12 (rule 42; `tables.snap`
moves by exactly the two evicted rows). The pool file's snapshot is
registered beside it (`SPL-Q8`).

---

## 5. Store invariants this increment builds or restates

| Row | Statement | Armed where |
|---|---|---|
| **SI-16** | **A pool entry is one entry.** `pool_meta[h]` exists ⇔ `pool_blob[h]` exists — P1 writes both, P3 deletes both, P2 touches only the meta row, and no other writer exists. The C++ enforces the meta ⇒ blob half at `for_all_txpool_txes` (`db_lmdb.cpp:2304`, `DB_ERROR("Failed to find txpool tx blob to match metadata")`) and never checks the other. Observed by P7's `blob()` (meta without blob) and by P1 (blob without meta would be a key P1 finds in one table and not the other). | P1, P7 |

The row lands in `STORE_INVARIANT_REGISTER.md` with the increment's commit 2
(`SPL-Q2` decides whether the register's gate reads a second `enum` or the
pool file's invariant joins `StoreInvariant`). No invariant is stated over
the record's fields (a `stem` entry with `LastRelayedAt`, a `Block` entry
with an embargo): those are `PoolRecord` **construction** checks and the
codec refuses what they would observe, SI-14's shape.

---

## 6. Round-0 findings

- **SPL-1 — §5.1's falsifier is firing at the pin, and has been since the
  pick.** *"Falsifier: any pool table in the consensus store's
  `TableDefinition` set"* (`DAEMON_REDB_STORE.md:1120`) — `TXPOOL_META` and
  `TXPOOL_BLOB` are in `schema.rs` (`:350`, `:353`), `Unshaped`, seeded by
  DRS-0 slice B's 1:1 map of the LMDB inventory. The row made itself
  conditional on that map ("depends on the slice-B schema map") and the map
  landed without choosing. Not a defect in any code: an unbuilt pick whose
  falsifier had no reader. The increment closes it (§2.4).
- **SPL-2 — the schema gates are single-file.** `check_redb_schema_bijection.py`
  asserts every `SHEKYL_LMDB_TABLES` entry has exactly one `TableDefinition`
  in `schema.rs`, with `RUST_ONLY_TABLES` as the one sanctioned exception
  (Rust has a table LMDB never had). The opposite exception — LMDB has a
  table whose redb twin lives in **another file** — does not exist, so
  evicting the pool tables turns the gate red for the right reason with the
  wrong message. `check_redb_schema_key_types.py` carries `txpool_meta hash
  key` (`:327`) as an LMDB-side constraint on a definition that will not be
  there, and `accumulator/class.rs` (`:160–161`) grades two tables the
  consensus file no longer holds. The increment adds the direction —
  `MIRRORED_ELSEWHERE: &[(&str, &str /* file */, &str /* reason */)]` in
  `schema.rs`, read by the bijection gate, with the same rule-47 self-assertion
  `RUST_ONLY_TABLES` has (an entry naming a table not in the X-macro is red;
  an entry with no pool-file definition is red) — rather than an allowlist
  by name.
- **SPL-3 — the surface has one consumer and it is not `blockchain.cpp`.**
  Eight `Blockchain::` methods, eight one-line forwards (`blockchain.cpp:6610–6652`);
  every production caller is `tx_memory_pool` (31 sites, 28 functions, §2.1).
  Three of the nine are pure compositions of the others: #7 is #4 +
  `matches` (`blockchain_db.cpp:1885`), #9 is the same composition one
  layer down (SPL-15), and #5's category parameter is #4 + `matches`
  bolted onto a blob read. Nine methods → **seven operations**,
  none of which classifies (§3.3).
- **SPL-4 — the relay class is four bits, five encoder patterns, and a
  decoder whose error arm is "public".** `set_relay_method` writes one of
  five patterns over four class bits (`kept_by_block`, `do_not_relay`,
  `is_local`, `dandelionpp_stem` — one set, or all four clear = `fluff`);
  `get_relay_method` sums the four and returns `fluff` for
  `default: // error case` (`blockchain_db.cpp:132–165`). Both functions'
  comments explain why a *new* class must not encode as all-clear ("would
  read back BROADCASTED … published it rather than failing") — the
  encoder's hazard, stated; the decoder's identical hazard on a *corrupt*
  record, not. A sum type cannot have an unknown state; an undecodable row
  is SI-7. And the independent fifth bit `set_relay_method` also resets,
  `observed_circulating`, is kept out of the sum by comment
  (`blockchain_db.cpp:145–149`: "must not shift a `local` entry's decoded
  method") — a `bool` beside an `enum` cannot shift it. (Wording fixed on
  review — Copilot, PR #849: the first draft said "five bits" and counted
  the all-clear state as a fifth, which made the cross-check ambiguous.)
- **SPL-5 — two sentinels and one overload in the timing fields.**
  `last_relayed_time` is `u64::MAX` at admission (`tx_pool.cpp:470`: "never
  relayed"); for a `stem` entry it is the **next** attempt time — the
  embargo deadline drawn at `set_relayed` (`:1297`) and re-drawn when it
  passes (`:1227`) — and for every other class the **last** relay time. Its
  own declaration says so (`blockchain_db.h:227`: "If Dandelion++ stem,
  randomized embargo time. Otherwise, last relayed timestamp"). One `u64`
  that is a future instant, a past instant or "none" depending on a bit
  elsewhere in the record is `RelayClock` (§3.4). `receive_time` is the
  second wall-clock field and needs its own word (`UnixSeconds`): the
  store's other timestamps are block-header time, and nothing should be
  able to subtract one from the other. **A fourth case, missed at Round 0
  and added on review** (Copilot, PR #849): `insert_attested_tx` admits
  with `last_relayed_time = receive_time`, not the sentinel
  (`tx_pool.cpp:575–589`), precisely because the sentinel arithmetic makes
  the periodic fallback skip the entry forever — the sentinel is a bug
  waiting at every consumer that subtracts from it, and `RelayClock`'s
  construction rule (§3.4) is where the two admission paths are told
  apart.
- **SPL-6 — three fields are dead by ruling or by deletion, and the
  record's shared words are in the wrong crate.** `do_not_relay` /
  `relay_method::none` is unreachable — *"`none` means received via RPC with
  `do_not_relay` set, and Shekyl has no such RPC"* (`blockchain_db.h:123`);
  `pruned` is unreachable — a pool entry is pruned only if admitted from a
  pruned blob, and the one path that produced pruned blobs for the pool,
  `--sync-pruned-blocks`, was deleted 2026-09-21 under `PDM-Q5`
  (`DRS_E1_SPRUNE.md` §13); `padding[44]` is the C struct's. Not carried
  (rule 60 / rule 15). `RelayMethod` and `NetZone` exist in `shekyl-relay`
  with FFI byte pins (`zone_route.rs:46–56`) — the store needs the same
  words and cannot take `shekyl-relay` (a relay scheduler with an async
  driver) as a dependency; rule 18 says they move down (`SPL-Q6`).
- **SPL-7 — a separate file loses an atomicity the C++ has, and §5.1 already
  paid for it.** *(Which `LockedTXN` property this row is about, stated
  because the other one is the known bug — SPL-16,
  [`RELAY_STATE_REFERENCE_SHAPES.md`](RELAY_STATE_REFERENCE_SHAPES.md) §1:
  the batch-**nesting**, lost and accepted here; **not** the abort-on-drop,
  which is refused.)* Today the pool's `LockedTXN` nests under an active block
  batch (audit §4: "writes piggyback on the outer transaction"), so
  `take_tx`'s removal of a mined transaction commits **with** the block, and
  a pop's re-`add_tx` commits with the pop. Two files, two commits: a crash
  between them leaves either a mined transaction still in the pool (the
  chain committed first) or a pool entry lost (the pool committed first).
  The second is the loss §5.1 accepted when it ruled the file discardable
  wholesale; the first is a pool entry whose key images are spent on chain,
  which the C++ pool detects **lazily** (`double_spend_seen` on a later
  conflicting arrival, `is_transaction_ready_to_go` at template time,
  lifetime eviction) — and **not at restart**: `init` rebuilds
  `m_spent_key_images` from the pool's own rows and removes unparseable
  blobs, and never reads the chain's `spent_keys` (`tx_pool.cpp:2362–2398`;
  Copilot, PR #849, correcting this row's first draft, which said every
  restart re-checks). So the reconciliation is **new work E5 owns**, not
  inherited behaviour: at open, and after every connect that lands
  without the pool's commit, E5 removes or marks every pool entry whose
  key images are spent on chain **before** it is offered to a template,
  a relay pass or `have_tx`. The contract this increment states for E5:
  **chain commit first, pool commit second, and the pool reconciles
  against the chain at open** — no cross-file transaction is offered,
  because none can be made (`SPL-Q5`).
- **SPL-8 — no caller depends on key order.** All thirteen `for_all_txpool_txes`
  sites (§2.1 #8) either collect into an unordered structure, count, or
  select by their own criterion; the block template walks the in-memory
  fee/receive-time index, not the table. The `compare_hash32` order the
  redb schema carries as `LmdbHashKey` exists to keep the *consensus* file
  in LMDB's order for the digest oracle; the pool file has no oracle and no
  twin. Natural order (`SCU-Q3`).
- **SPL-9 — the store is the pool's state of record; the pool's memory is a
  cache.** `init` (`tx_pool.cpp:2362–2425`) clears every in-memory
  structure and rebuilds it from a full two-pass enumeration — non-kept
  entries first, then `kept_by_block`, "to avoid rejection due to key image
  collision" — inserting key images, the fee/receive-time order and the
  weight total, and removing entries whose blob does not parse. So E5's
  pool is reconstructible from P7 alone, and P7 is the only enumeration the
  store needs to offer; the two-pass order is the consumer's (it reads the
  class from the record). A secondary index in the store would be a second
  source of truth for a derived order.
- **SPL-10 — a consensus row's mechanism is a pool-store field.** CEN-M8
  (`C`, bucket 1, `spec`): the pool stores `H(proof ‖ referenceBlock ‖ key
  images)` and block connect skips only the proof re-verify while the hash
  matches (`tx_pool.cpp:485–494`, `blockchain.cpp:4592–4625`). The field is
  `fcmp_verification_hash` + `fcmp_verified`; a `null_hash` with the bit
  clear is "no cache" (`:500–501`). `Option<FcmpVerificationHash>` — the
  bit is the `Some`. The row's consumer gate is E6's / the connect path's
  (FOLLOWUPS `:109` names the unwired regression test); the field's shape is
  this increment's.
- **SPL-11 — DRS-W2 closes for the pool file by construction.**
  `LockedTXN::commit` swallows `batch_stop`'s exception (audit §4; "commit
  failures are silent to callers"). The pool file's write API is the chain
  store's closure shape (§3.2): `complete(outcome)` returns the commit's
  `Result` to the caller of `write`, so a failed commit is an error at the
  site that asked for the write. *(First draft, corrected 2026-09-24: "the
  batch's `commit(self)` is the only exit that keeps the writes, and a
  dropped batch aborts" — the second half of that sentence is the defect
  SPL-16 names, and the first half is what makes it reachable.)* Recorded
  so the wart row can name where it closed.
- **SPL-12 — E2 is untouched, and the reason is a boundary, not an
  exclusion.** `digest_v0` excludes txpool (`:24`); §11.2 lists the pair
  under *not chain state* and says the pick "makes this a boundary rather
  than an exception". After the eviction the consensus file has no pool
  table for a digest to exclude. `pipeline_tests` / `digest_read_tests`
  unchanged in outcome.
- **SPL-13 — the pool's write rate is the residue.** Six `update_txpool_tx`
  sites, one per relay tick per relayable entry (`get_relayable_transactions`
  every ~2 min rewrites every stem entry whose deadline passed), one per
  readiness probe in `fill_block_template`, one per class upgrade. In the
  consensus file these rewrites are the copy-on-write churn §5.1 called
  "relay-timing residue that outlives the tx" in the *consensus* file's free
  pages. In a separate file they are the pool file's own growth, which is
  §5.1 row 1's BENCH measurement (small commits over time) with a subject.
  Recorded for BENCH; not this increment's to measure.
- **SPL-14 — a zeroed or unreadable relay state resolves to the
  broadcast-to-everyone phase, and the tree documents it as an aside.**
  (Maintainer, verifying SPL-4 on PR #849, 2026-09-24.) `blockchain_db.h:126–130`,
  inside the justification for keeping `relay_category::relayable`: *"a
  zeroed record decodes to `fluff`, NOT `none` (`get_relay_method` falls
  through state 0 to the `fluff` return)"*. Written by someone who noticed
  it while reasoning about a different question, and recorded nowhere as a
  finding. What it says: under Dandelion++ a stem-phase transaction must
  not be fluffed — that is the entire mechanism — and a decode that falls
  through to `fluff` means a record whose relay bits are zeroed or
  corrupted is relayed to anyone who asks while it should still be
  stemming. **Origin disclosure caused by a parse default**, on a chain
  whose second commitment is privacy. It gets its own row because
  `SPL-Q3` is the moment it is fixed or reproduced, and because it
  corrects `SPL-Q6`'s default: refusing `None` guarded a state nothing can
  write (the same comment: reaching `none` needs a `do_not_relay` writer
  Shekyl does not have) while leaving the state that *does* occur — 0
  falling to `fluff` — unguarded. The fix is the decoder's shape: no
  default arm, an error on any unrecognised discriminant, `Fluff` reachable
  only by its own byte. Absence-as-a-case, applied to a relay state whose
  "value" is a privacy decision. **Precedent in the same subsystem** —
  follow it rather than the principle: `shekyl-relay-privacy/src/stem_map/mod.rs:9–13`
  removed `boost::uuids::nil_uuid()` because the C++ used one sentinel in
  three roles and every caller had to know which; each became an `Option`
  in a distinct position ([`RELAY_STATE_REFERENCE_SHAPES.md`](RELAY_STATE_REFERENCE_SHAPES.md)
  §4). **Scenario for the relay-privacy lane**
  (`SPL-Q7`): a persisted stem-phase entry whose embargo deadline passed
  during downtime — SPL-5's `RelayClock` and this finding meeting in one
  record; the wrong default on either leaks.
- **SPL-15 — the §5 row's census missed a method, because it counted
  `Blockchain::` forwards and one pool read bypasses `Blockchain::`.**
  (Copilot, PR #849.) `tx_memory_pool::have_tx` calls
  `m_blockchain.get_db().txpool_has_tx(id, category)` directly
  (`tx_pool.cpp:1689–1694`); its callers are `core::handle_incoming_tx`
  (CEN-M1's idempotent accept), `core::pool_has_tx` (the protocol's and
  `levin_notify`'s membership test) and the alt-block supplement path
  (`blockchain.cpp:2287`, `:2318`). Round 0 read the §5 row's eight names
  and `rg`'d those; the ninth is reached by a different spelling. A
  cutover following the row alone would have omitted the one membership
  read the network path depends on. Mapped as #9 (§2.1): P4 + `matches`.
  **Method for the remaining surfaces:** census by *table* (every reader
  of `txpool_meta` / `txpool_blob` in `db_lmdb.cpp`, then every caller of
  each), not by the `Blockchain::` corridor — the corridor is one route,
  not the set. S-ALT's pre-flight inherits this.
- **SPL-16 — `LockedTXN` had two properties, and only one of them is worth
  a sentence in a Rust store; the other is the mechanism of the known bug.**
  (Maintainer, from the Dandelion++ arc, 2026-09-24.) The nesting — a
  `LockedTXN` under an active block batch piggybacks on the block's
  transaction — is what gave `take_tx` atomicity with connect; SPL-7 names
  that as lost and accepted. The **abort-on-drop default** — a `LockedTXN`
  that goes out of scope without `lock.commit()` rolls its writes back
  silently — is how `get_relayable_transactions` lost **every** Dandelion++
  stem/forward timestamp update on every invocation until the missing commit
  was added (origin-disclosure class, inherited from Monero; the fix is at
  `tx_pool.cpp:1232` and the atomicity audit re-verified it intact,
  `LMDB_WRITE_ATOMICITY_AUDIT.md:88`). The two are separable and this
  document now says which it preserves: **neither as a mechanism**. The
  nesting is gone because the files are separate; the abort-on-drop is gone
  because the pool file's write API is the chain store's closure shape
  (§3.2), in which no caller ever holds a batch it could drop — a caller-held
  batch with `commit(self)` and an aborting `Drop`, which this document's
  first draft proposed, is the same defect in a new language: one early
  `return Ok(())` and the relay clock is silently un-written again. "We kept
  `LockedTXN`'s semantics" is exactly how the second half comes back; the
  store keeps none of them and states the property it wants instead:
  *forgetting to commit is unrepresentable.*
- **SPL-17 — the Zone owns routing; the pool owns every per-transaction
  relay fact, by the Zone's own ruling — so the record duplicates nothing.**
  (Maintainer's question, 2026-09-24: for each relay field, does
  `shekyl-relay-privacy` / `shekyl-relay` already hold the authoritative
  value?) Field by field, at source:
  `RelayZone` (`shekyl-relay`, `zone/mod.rs:305–329`) holds per-**connection**
  and per-**epoch** state — `StemMap`, `FluffScheduler`, the epoch clock,
  `DandelionParams`, `FluffReach` — and returns a *plan* (`STEM` /
  `FLUFF_EPOCH` / `NO_ROUTE`) per call through
  `shekyl_relay_zone_plan_relay_with_refresh`; it holds **no per-transaction
  class**, and its own doc refuses to: *"retaining a per-transaction outcome
  for a consumer to poll would put a second copy of a fact the txpool
  already owns beside the txpool, with no invalidation tied to the pool
  entry's own lifetime"* (`zone/mod.rs:594–597`). `EmbargoTimer`
  (`shekyl-relay-privacy`, `schedule.rs:420`) owns the **distribution**; the
  pool stamps and holds the **deadline** (`tx_pool.cpp:1298`, via
  `shekyl_dandelionpp_embargo_draw_seconds`). `StemWatch` (`stem_watch.rs:194–206`)
  holds a *transient* per-transaction `Pending { successor, source, deadline }`
  — a **different** deadline, the observation window that judges the
  successor — whose verdict leaves the watch and lands in the pool's
  `observed_circulating` through `on_stem_propagated` (§92.5c item 1: *"the
  verdict now leaves `seen` itself, the last point that still holds a
  hash"*). `origin_zone`, `receive_time`, `relayed`, the readiness cache and
  the class bits have no Rust twin at all. The test the maintainer gave for
  each field — *if this value disagreed with the Zone's, which one would be
  right?* — has no Zone-side value to name for any of them
  ([`RELAY_STATE_REFERENCE_SHAPES.md`](RELAY_STATE_REFERENCE_SHAPES.md) §2).
  **Answer:** every relay field is *evidence*, not policy state; the pool
  record is the *sole persistent home* of these facts, not a second copy;
  `SPL-Q7`'s persist-whole stands on that ground and only on it. **Forward
  to E5:** the store's readers do not branch on these fields; the relay
  loop that does (`tx_pool.cpp` deciding re-relay from `last_relayed_time`)
  is the Zone's job in the Rust design, taking the record as input. **What it adds to Q7's scenario:**
  `StemWatch.pending` does not survive a restart, so a persisted
  *originated* entry whose observation was in flight restarts with its
  re-broadcast responsibility armed and no watch that can disarm it until
  the transaction is re-observed — the second leg of the downtime scenario
  handed to the relay-privacy lane.
- **SPL-18 — §92.4 unbundled `Local` into three facts with three lifetimes,
  and a field-for-field `RelayMethod` re-bundles them.** (Maintainer,
  2026-09-24.) The ruling: *"`Local` is two facts with different lifetimes —
  provenance, which is permanent, and re-broadcast responsibility, which
  should end when the transaction is observed circulating"* — with the
  disarm resolved by F-10's predicate (§92.5c item 1) as the third clause.
  The C++ carries all three as one `relay_method::local` value plus the
  `observed_circulating` bit plus the origin-pin logic in `add_tx`
  (`:456–458`), and its ratchet **destroys provenance on a `Block` arrival**
  (`set_relay_method(block)` clears `is_local`) — intended for the
  *behaviour* (§92.4: "past that point the pin's sign flips") but it takes
  the *fact* with it. `PoolRecord.method: RelayMethod` as §3.4 first wrote
  it would persist exactly that collapse: provenance and phase in one
  field, the pin re-implemented as a transition rule over an enum that
  cannot say why. The record's relay fields are re-shaped along §92's
  seams — `SPL-Q9` — and the byte enum stays what it is: the **FFI seam's
  word** for an arrival class or a routing plan (transform-shaped, rule 18),
  not the record's state. `relay_category::legacy`, recorded in §93.4 as
  having no referent in a pre-genesis coin and deleted from the C++
  2026-08-24, is **not** minted in `RelayCategory` (three members) — checked
  against that arc's stale-premise list before `SPL-Q6` mints anything.
  SPL-14 is untouched and sharper: the crate that owns fluff *scheduling*
  is not the one decoding the byte that says *fluff*.

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None. The pool has no digest, no conformance row and no LMDB twin to
reproduce against; §7.6's "parity first" phase does not reach it. The one
behaviour this increment deliberately does **not** reproduce is SPL-4 /
SPL-14's decode-to-`fluff` on a zeroed or unknown bit state, which is a
corruption path with a privacy consequence, not a conformance state.

---

## 7. Commit sequence (rule 90; one PR, ≤ 4 commits, cut from `dev` after §9 is RULED)

1. **Vocabulary.** `RelayMethod`, `RelayCategory` (with `matches`), `NetZone`
   to `shekyl-types` per `SPL-Q6`, `shekyl-relay` re-exporting (its `const`
   byte pins stay where the FFI seam is); `UnixSeconds`,
   `FcmpVerificationHash` minted; `PoolRecord` with **`Origin` /
   `RelayPhase` / `Responsibility`** per `SPL-Q9` (as ruled) and their
   `Canonical` codec and construction checks (`Held` only for `Originated`,
   `Stem` only for `Arrived`, `Responsibility` only for `Originated`;
   `RelayPhase::upgrade(origin, next)` is the ratchet and the pin), the seam
   conversion `(Origin, RelayPhase) → RelayMethod` with `matches` pinned
   against the C++ table exhaustively; **`Arrived` + `Armed` refused at
   decode and at write, `OriginChanged` refused at P2** (`SPL-Q9` as RULED);
   `RelayMethod`'s decoder with no default arm (`SPL-Q6` as RULED);
   tests: round trip at every arm, each refusal, **every byte outside the
   five pinned discriminants is an error and no byte reaches `Fluff` but
   3** (SPL-14), the C++ bit-pattern table transcribed as a
   **semantic** cross-check — for each of the five `set_relay_method`
   patterns over the four class bits, with `observed_circulating` varied
   independently, and the **four** `last_relayed_time` cases (the sentinel,
   the attested-local `receive_time`, a stem deadline, a past relay), the `PoolRecord` the
   record-shaped C++ struct means (a table in the test, not a byte codec —
   there is no v7-style corpus to capture because the encoding is
   `memcpy` of a C struct and nothing is meant to survive it).
2. **The file.** `pool/` module: `PoolStore::create/open` with header and
   version (`SPL-Q8`), `pool_meta` / `pool_blob`, P1–P7, `PoolCannot`,
   **SI-16** in the register; **the eviction**: `TXPOOL_META` / `TXPOOL_BLOB`
   leave `schema.rs`, `SCHEMA_VERSION` 11 → 12, `tables.snap` regenerated,
   `MIRRORED_ELSEWHERE` added and the bijection / key-type gates taught the
   direction (SPL-2), `accumulator/class.rs` and `amendments_tests`' count
   moved; tests: create → open → every op on the empty file, P1 twice
   (`AlreadyHeld`), P2 on a stranger (`NotHeld`), P3 twice, P7 over planted
   entries with and without blobs, the SI-16 fault named, the version
   mismatch arm per `SPL-Q8`, and the durability setting per `SPL-Q4`
   asserted on the opened `Database`.
3. **Docs** (rule 91): §5 row flip in `DAEMON_REDB_STORE.md`, §5.1's row
   gains its closing date, §11.2's group loses the pair to the boundary,
   index rows, `STORE_INVARIANT_REGISTER.md`, `LMDB_SCHEMA.md`'s two
   sections gain a "redb twin: the pool file" line, this file's status,
   CHANGELOG.

No fold commit: the surface has no computation.

---

## 8. Denominator — what must stay green, what must be extended

- `check_chain_rules_no_store.sh` — unchanged (the rules crate reaches no
  store; the pool file is a store).
- Rule-42 schema snapshot: **must move**, by exactly the two evicted rows +
  version in `tables.snap`, plus the pool file's own snapshot (`SPL-Q8`);
  arming last verified in the failing direction 2026-09-23
  (`DRS_E1_SARCH.md` §8) — re-check at this bump the same way
  (`gh run list --workflow schema-snapshot.yml --status failure`).
- `check_redb_schema_bijection.py` — **must be extended** (SPL-2): the
  `MIRRORED_ELSEWHERE` direction, with its own self-assertions and
  `--selftest` cases. 49/49 becomes 47 in `schema.rs` + 2 mirrored.
- `check_redb_schema_key_types.py` — 47 definitions / 26 constraints
  (`txpool_meta hash key` retires with the definition it constrained; the
  pool file's key is not LMDB's order and is out of the gate's domain by
  construction — the gate reads `schema.rs`).
- `check_store_invariant_register.py` — SI-16 `built`; whether the anchor is
  a `StoreInvariant` variant or a `PoolInvariant` one the gate learns to
  read is `SPL-Q2`'s.
- `check_conformance_coverage.py`, `check_chain_rules_coverage.py` — no
  register row touched, no `CenRow` moved (CEN-M8's field changes shape,
  not its rule).
- `check_lmdb_schema_coverage.py`, `check_archival_forcing_cells.py` — the
  LMDB side is untouched (no C++ changes); recorded so a red there is
  someone else's.
- E2's `pipeline_tests` and `digest_read_tests` — unchanged in outcome
  (SPL-12).
- `cargo test -p shekyl-relay` — unchanged in count after the re-export
  (commit 1 moves definitions, not tests); its FFI `const` pins keep
  compiling against the moved enum.

---

## 9. Round-1 questions — RULED 2026-09-24 (maintainer, on PR #849; each row line-local); AMENDED the same day from the Dandelion++ arc (Q6 re-shaped, Q7 confirmed at source, Q9 posed and RULED)

| Q | Question | Ruling | Why |
|---|---|---|---|
| **SPL-Q1** | Does E1 build the pool **store** now — file, handle, P1–P7, SI-16, tests — with E5 as its named consumer, or only the record shapes and the eviction, leaving the handle to E5's first commit? | **RULED: approved — build it.** *(posed default: Build it.)* | `SCU-Q4`'s precedent (the leaf walk landed with E3 named) and `SAR`'s (six shapes minted for E4's writers). The ops are seven functions; what they buy is a **contract E5 writes against** with tests already pinning the absence and refusal cases, and the eviction alone would leave `PoolRecord` with no table to be the value of. STAGED per rule 23 with E5 named in `DAEMON_REDB_STORE.md` §7's graph and table 3's 4.M row; the reopening criterion is E5's pre-flight finding the ops' shape wrong, at which point they are E5's to reshape — cheaper than E5 designing them from the C++ with the C++ gone. Rule 23 staging with E5 named; shapes-plus-eviction leaves a surface half-built with no consumer for either half. |
| **SPL-Q2** | Where does the pool store live: a `pool/` module in `shekyl-chain-store` with its own `Database` (sharing codec, batch shape, gates), or a sibling crate `shekyl-pool-store`? | **RULED: approved — the module.** *(posed default: The module.)* | One store crate, two files: the codec vocabulary, `Blob`/`Coded`, the commit-consuming batch, the header/seal pattern, the register gate and the schema gates all already read this crate, and a second crate would re-plumb each. The crate's name says *chain* and the pool is not chain state — a naming cost, paid knowingly. **Reopens** (rule 21) if E5 S-ALT's answer to the same question for `alt_blocks` (§2.2) is a separate file *and* E5's pool crate wants the pool store without the chain store's dependency graph; then both non-chain files move to one `shekyl-node-store` crate together, not one at a time. §5.1 ruled the pool out of the consensus store *file*, not out of the crate; a module with its own file satisfies it, and a sibling crate adds an edge for nothing. Reopening jointly with S-ALT's file question is right — they are one question about how many files the store owns. |
| **SPL-Q3** | Is `PoolRecord` a re-specified `Canonical` — same semantics, dead fields dropped, the five bits an enum, the timing overload a sum type (§3.4) — or a byte-for-byte port of the 192-byte struct? | **RULED: approved — re-specified, and it is where SPL-14 lands.** Bits → enum is right; the requirement is that the enum has **no default arm** and the decoder returns an **error** on an unknown discriminant rather than a value. *(posed default: Re-specified.)* | `SAR-Q3`'s ruling applies with less resistance than it had there: nothing hashes, relays or migrates the persisted pool record, the C++ pool's LMDB dies at the cutover with its file, and the struct's encoding is `memcpy` with 44 bytes of padding. The semantic cross-check is a transcribed table (§7 commit 1), not a corpus. Absence-as-a-case, applied to a relay state where the "value" is a privacy decision. |
| **SPL-Q4** | Does the pool file take DRS-D9's durability (full fsync per commit, "no security-vs-speed tradeoff") or a weaker setting, given §5.1 ruled the file discardable and its loss mode benign? | **RULED: approved — D9.** *(posed default: D9. One durability policy (§11.1 (d)'s reasoning: one file, one writer, one policy — applied per file).)* | "Discardable" is about what the file may be *made* to lose, not about accepting a torn one. A weaker setting would be picked on a cost nobody has measured; SPL-13 names the measurement and BENCH owns it. **Reopens** on a BENCH result showing pool-file fsync on the relay path is the binding cost on relay latency — not on a preference for speed. |
| **SPL-Q5** | Two files, two commits on a block connect (SPL-7). Does the store offer anything toward the lost atomicity — a "reconcile at open" op that drops entries whose key images are spent — or is the ordering rule (chain first, pool second) and the reconciliation entirely E5's? | **RULED: approved — entirely E5's; the store states the order. The reason, in the row:** chain-first is the *recoverable* ordering. A crash between the two commits leaves a transaction in a block and still in the pool, which reconciliation removes; pool-first would remove it from the pool before it was in a block, losing it. Same outcome either way on a clean run; only one of them is safe on a dirty one. *(posed default: Entirely E5's; the store states the rule and offers no op.)* **Sharpened on review** (Copilot, PR #849): the reconciliation is *new* E5 work, not inherited — the C++ `init` never reads the chain's `spent_keys` (SPL-7 corrected) — so the contract names it as an obligation with a falsifier: a pool entry whose key image is spent on chain, offered to a template or a relay pass after open. | Which pool entries a connected block invalidates is admission's knowledge (the key-image set, CEN-M6/M7's domain), not the store's; a store-side reconcile would need the chain file's spent-key table, which is the cross-file read this design exists to avoid. The rule is written here (§2.3) and in the `PoolStore` docs, and E5 inherits it as a precondition — the `SAR-Q6` "record it here, decide it there" shape. |
| **SPL-Q6** | `RelayMethod` / `NetZone` move to `shekyl-types` (rule 18, `SCU-Q2`'s general form) with `shekyl-relay` re-exporting — and does the persisted record admit `RelayMethod::None`? | **RULED: default CORRECTED — move; the codec refuses every unrecognised state, and `fluff` is never reachable by fall-through. Refusing `None` is a guard on the wrong value.** Per `blockchain_db.h:126–130` `none` is unreachable — nothing writes it, and reaching it needs a `do_not_relay` writer Shekyl does not have — so the posed default guarded a state that cannot occur while leaving the one that does (state 0 falling to `fluff`, SPL-14) unguarded. *(posed default: Move; refuse `None` at the codec.)* | One definition, both crates; a store-side `RelayClass` beside `shekyl-relay`'s `RelayMethod` is two spellings of one fact (the `SAR-Q2` lesson). `None` stays in the enum because the FFI byte contract pins it (`enums.h:39`, the `const` asserts), but no writer exists for it (SPL-6) and a persisted variant nothing writes is pre-provisioning (rule 23): `PoolRecord`'s codec refuses it on encode and decode, the way `Holdings::shard_set` refuses a duplicate. **Reopens** if an RPC that sets `do_not_relay` is ever specified — the refusal is one arm to delete. The fix is the decoder's shape (no default arm, error on an unknown discriminant, `Fluff` only by its own byte); `None` stays a legal, unreachable, non-relayable member of the shared enum and is not specially refused. **AMENDED 2026-09-24 (SPL-18, maintainer's arc review):** the move stands and the decoder rule stands, but the byte enum is the **seam's** word, not the record's — `PoolRecord` persists `Origin` + `RelayPhase` (`SPL-Q9`), so `None` is not a question the record can ask: it is neither an origin nor a phase. Rule 18's transform/state split is why the seam conversion `(origin, phase) → RelayMethod` is not `SAR-Q2`'s two-spellings hazard: they are not one fact. |
| **SPL-Q7** | §5.1 made residue "a policy question". Which entries survive a restart, and what is the pool file's on-disk lifetime — persist the whole record and resume every relay clock (the C++ behaviour), or wipe some class of entry (stem embargoes? `local` origins?) at open? Whose question is it? | **RULED: approved — persist whole; the relay-privacy lane owns the policy — for the same reason S-ARCH's `Option` survived.** Persisting the whole record is what makes that lane's decision *possible*: drop the state and timing at write time and "should a restarted node re-stem, fluff, or discard an embargoed transaction?" becomes unaskable, because the information needed to answer it was destroyed by the store. Record here, decide there. **Pulled forward into the hand-off as a scenario, not two field descriptions:** a persisted stem-phase entry whose embargo deadline passed during downtime — SPL-5's `RelayClock` and SPL-14's decode meeting in one record, the case where the wrong default leaks. *(posed default: Record it here, decide it there — default persist-whole; the relay-privacy lane owns the policy.)* **CONFIRMED AT SOURCE 2026-09-24 (SPL-17):** the maintainer asked, field by field, whether `shekyl-relay-privacy` / `shekyl-relay` already hold the authoritative value — they hold none of them, by the Zone's own refusal to keep a per-transaction outcome (`zone/mod.rs:594–597`); the pool record is the sole persistent home, so persist-whole duplicates nothing. The scenario gains its second leg: `StemWatch.pending` does not survive a restart, so an originated entry mid-observation restarts armed with nothing that can disarm it until re-observed. | The store must persist whatever policy is chosen, and persisting the whole record is the superset; a store that wiped a class at open would be deciding relay privacy. The question is real — a `local` entry's `origin_zone` + `receive_time` on disk is evidence this node originated a transaction, and a stem entry's embargo resuming after a reboot is either continuity or a timing fingerprint — and it has an owner with a document (`DAEMON_RELAY_PRIVACY.md`, whose §92 already governs the `local` class's lifecycle). Forward-action named there by this PR's docs commit; the store's `open` gains a hook only if that lane rules one. |
| **SPL-Q8** | Does the pool file carry its own version cell with **mismatch ⇒ recreate** (no migrator, no refusal — the file is discardable), and is its snapshot registered under the rule-42 gate as a second file? | **RULED: approved — yes to both.** Own version cell with wipe-and-recreate is consistent with the file being discardable, which is what §5.1 already paid for. **The check that authorizes the wipe, named on review** (Copilot, PR #849 — the consensus store refuses a mismatch in both directions and keeps the file, `store/mod.rs:77–87`, `:278–282`; an automatic delete needs a stated precondition): the pool file is recreated **only** when it opens as a redb database *and* carries this store's own header seal with a `PoolStore` version cell whose value differs — i.e. it is recognisably a Shekyl pool file at another layout. A path that is not a redb file, a redb file without the seal, or a sealed file whose header does not decode is **refused, never deleted** — a wrong `--data-dir`, a foreign file or a tampered one is an operator's to look at, not the store's to erase. The wipe is one log line naming the old and new versions, and the store's tests construct all three refusals. *(posed default: Yes to both.)* | Rule 42's discipline is "a persisted-block wire change ⇒ a version bump, CI-enforced"; the pool file is persisted state and its record is a codec, so the snapshot belongs under the gate. What differs is the *response* to a mismatch: the consensus file refuses to open (SI-7, rebuild from the corpus); the pool file has no corpus and §5.1 says it may be discarded wholesale, so a mismatch is a wipe-and-recreate with one log line — the fallback pick §5.1 named ("wipe-on-open"), used where it is actually correct. `rm -rf ~/.shekyl` is the pre-genesis migration path anyway (rule 15). |
| **SPL-Q9** | *(posed 2026-09-24, post-ruling — SPL-18.)* Do the record's relay fields follow §92.4's decomposition — `origin: Origin` (permanent; P2 refuses a change), `phase: RelayPhase` (the ratchet, with the pin as a transition rule over `origin`; each phase carrying its own clock word), `responsibility: Responsibility` (F-10's disarm, `Originated` only) — with the FFI byte enum kept as the seam's word and derived at the seam; or does the record persist `method: RelayMethod` + `RelayClock` + `observed_circulating` + `origin_zone` field-for-field as §3.4 first wrote it? | **RULED 2026-09-24: the decomposition** (maintainer: "better than the shape I sketched"). `Origin { Originated, Arrived { zone } }` with `PoolCannot::OriginChanged` is stronger than an `originated_here: bool` — it carries the arrival zone and makes permanence *enforced* rather than asserted. `RelayPhase`'s per-variant timing is the best part: the three meanings `last_relayed_time` carried are three fields that cannot be confused, and the phase already determines which applies, so no second discriminant — better placement than the sum type SPL-5 first asked for. **One refinement, and one reason not to take the obvious one:** `Arrived` + `Armed` is representable and would mean an arrived transaction believes it owes a broadcast; nesting `Responsibility` inside `Origin::Originated { … }` would make it unrepresentable — **but don't**: `Origin` is permanent and refused-on-change while `Responsibility` transitions `Armed → Disarmed`, so nesting makes the permanent field mutable and P2's refusal unenforceable. The two have different lifetimes; separate fields are right, and that sentence lives in the `Responsibility` row so nobody "improves" it by nesting. The invariant is **enforced, not documented**: `Arrived` + `Armed` is refused at decode (SI-7) and at write (`PoolCannot::ResponsibilityWithoutOrigin`), the way the relay discriminant refuses an unknown byte. *(posed default: the decomposition)* | A faithful port re-bundles what the design spent a round unbundling: `relay_method::local` is provenance + responsibility + a routing class in one value, the ratchet destroys the provenance on `Block`, and the pin lives in `add_tx` as a special case over an enum that cannot carry its reason. Three fields with three lifetimes make the pin a *typed transition* (`Originated` never walks to `Stem`/`Fluff`; it yields to `Block`), make the disarm's domain a construction fact (`Responsibility` exists only for `Originated`), and dissolve SPL-5's overload — each phase's clock is that phase's field. The record's only reader is E5's pool, so the shape is free (no hash, no wire, no migration; `SPL-Q3`). Cost: the seam conversion `(origin, phase) → RelayMethod` for the C++ that still speaks the byte, and the `matches` table re-derived over `(Origin, RelayPhase)` — pinned by a test against the C++ table, exhaustive on both sides. **Reopens** if E5's admission finds a pool state the three fields cannot express — the falsifier is a `RelayMethod` value with no `(Origin, RelayPhase)` preimage. |

---

## 10. Documentation owed by the increment (rule 91) — discharged 2026-09-24 (commit 3)

- `DAEMON_REDB_STORE.md` §5: S-POOL row → LANDED with the mapping; §5.1's
  first row gains "built 2026-xx-xx (S-POOL); falsifier closed"; §11.2's
  *not chain state* group loses `txpool_meta` / `txpool_blob` with the
  sentence that the pick is now a boundary; §7's graph and table 3's 4.M
  row name E5 as the pool store's consumer.
- `IMPLEMENTATION_INDEX.md`: `SPL-` / `SPL-Q` rows lead with status; this
  document's row; the verification stamp.
- `STORE_INVARIANT_REGISTER.md`: SI-16.
- `LMDB_SCHEMA.md` §`txpool_meta`, §`txpool_blob`: a line naming the redb
  twin's file (the LMDB tables themselves are unchanged until the cutover).
- `LMDB_WRITE_ATOMICITY_AUDIT.md` §4 / §9 (DRS-W2): the wart names where it
  closed for the pool file (SPL-11).
- `DAEMON_RELAY_PRIVACY.md`: `SPL-Q7`'s forward-action, at the section that
  owns the `local` class's lifecycle. *(§92.4 gained a pointer to
  [`RELAY_STATE_REFERENCE_SHAPES.md`](RELAY_STATE_REFERENCE_SHAPES.md) §3,
  the pool-side consequence, on the pre-flight PR — 2026-09-24.)*
- [`RELAY_STATE_REFERENCE_SHAPES.md`](RELAY_STATE_REFERENCE_SHAPES.md) —
  **landed 2026-09-24 on the pre-flight PR:** the five shapes (`LockedTXN`,
  relay-state ownership, `Local`'s three properties, SPL-14's decoder, the
  peerlist → outbound → stem-map chain) with the ruling each comes from and
  what drift looks like; the home for three rulings that lived only in chat
  and comments.
- `18-type-placement.mdc`: no change — the rule covers `SPL-Q6` (`SCU-Q2`'s
  general form); this document cites it.
- CHANGELOG: one entry (the pool file; layout 12 with the eviction; the
  pool record's Rust type; `RelayMethod` / `NetZone` in `shekyl-types`).

---

## 11. Decision log

| Date | Entry |
|---|---|
| 2026-09-24 | **As built — the increment (three commits on the S-POOL PR), with its deviations from the ruled plan disclosed (rule 22).** **(1) Commits re-cut.** §7's "vocabulary" and "the file" are one commit: the record's snapshot registration and the file's catalogue share `codec::snapshot_tests`, so a commit that registered `PoolRecord` without the file could not build; the eviction and the gates are the second commit, the docs the third. **(2) The class table keeps its rows.** §2.4 said `accumulator/class.rs` loses `txpool_meta` / `txpool_blob`; it does not — the bijection gate's own words make that table *the LMDB inventory*, and the LMDB tables still exist. `MIRRORED_ELSEWHERE` entries are required to be classed. **(3) One layout number for two files** (`SPL-Q8` as built). The pool file seals the crate's `SCHEMA_VERSION` in its own `pool_header` cell rather than a `POOL_SCHEMA_VERSION` of its own: the rule-42 gate is per crate directory (`schemas/*.snap` ⇒ `SCHEMA_VERSION`), and splitting it is a CI change with no present need — a pool wire change bumps the crate's number and recreates the chain store too, which pre-genesis is `rm -rf` either way. Reopens when a pool-only wire change is wanted without a chain rebuild. The *response* to a mismatch is the ruling's: recreate, with the precondition (`PoolOpen::Recreated { from }`; `StoreCannot::PoolFileForeign` for everything else, the file kept). **(4) `PoolCannot::PhaseWithoutOrigin`** joins the five named in §3.4: `Held` on an `Arrived` entry and `Stem` on an `Originated` one are cross-field rules too, and a write-side refusal needs a name; `ResponsibilityWithoutOrigin` covers both directions of that pair (a responsibility on `Arrived`, none on `Originated`). **(5) `responsibility: Option<Responsibility>`**, `Some` iff `Originated` — the separate field the ruling asked for, with absence for `Arrived` spelled as `None` rather than a third variant. **(6) `matches` is on `RelayMethod`**, and `PoolRecord::matches` derives through `relay_method()`, rather than a second table over `(Origin, RelayPhase)`: one table, transcribed once, pinned once. **(7) `PoolStore::create` returns `(PoolStore, PoolOpen)`** so the recreate is the caller's one log line without the store taking a logging dependency. **What the tests hold** (§7 as executed): 3 in `shekyl-types` (the 256-byte decoder sweep), 8 codec tests (every arm, every refusal at `checked()` and at decode, the 256-byte phase-tag sweep with `Fluff` reached once, the C++ bit-pattern table — 30 rows, the two sentinel-stem rows having no meaning), 9 pool-file tests (create/open/recreate, each op and refusal, an `Err` aborting the batch, enumeration with the consumer's class fold, SI-16 both ways, SI-7, and the header's one recreation and three refusals with the refused files kept byte for byte). |
| 2026-09-24 | **`SPL-Q9` RULED — the decomposition** (maintainer, PR #849). `Origin` with `OriginChanged` enforces permanence rather than asserting it; `RelayPhase`'s per-variant timing dissolves SPL-5 with no second discriminant. `Responsibility` stays a **separate field** — nesting it inside `Origin::Originated` would make `Arrived` + `Armed` unrepresentable but would also make the permanent field mutable and P2's refusal unenforceable; different lifetimes, different fields — and the invariant is enforced instead: `Arrived` + `Armed` refused at decode (SI-7) and at write (`PoolCannot::ResponsibilityWithoutOrigin`). Same PR, same day: `--add-peer` closed against the review's draft and for the ratified brief in `RELAY_STATE_REFERENCE_SHAPES.md` §5 (white means "I dialled this and it answered"; an operator assertion is not a dial — one container, two meanings), the borrowed-citation-with-self-as-lender failure recorded; the unruled re-validation figure removed entirely. **The increment may be cut.** |
| 2026-09-24 | **Round 1 AMENDED from the Dandelion++ arc** (maintainer, PR #849; post-ruling substrate per rule 21 — a completeness amendment, not a new round). Three findings minted: **SPL-16** — `LockedTXN`'s two properties separated, the nesting lost-and-accepted (SPL-7) and the abort-on-drop (the mechanism of the `get_relayable_transactions` bug, fixed at `tx_pool.cpp:1232`, audit `:88`) explicitly not carried; §3.2's first draft — a caller-held `PoolBatch` with `commit(self)` and an aborting `Drop` — was that defect in Rust and is replaced by the chain store's `write(\|batch\| …)` closure shape. **SPL-17** — field by field, the Zone holds no per-transaction relay fact (its own doc refuses to, `zone/mod.rs:594–597`); `EmbargoTimer` owns the distribution, the pool the deadline; `StemWatch.pending` is transient and its verdict lands in the pool — the record is the sole persistent home, `SPL-Q7` confirmed, and the downtime scenario gains a second leg (a mid-observation originated entry restarts armed with nothing to disarm it). **SPL-18** — §92.4 unbundled `Local` into provenance (permanent), responsibility (disarmed by F-10) and class; a field-for-field `RelayMethod` re-bundles them and the ratchet destroys provenance on `Block`; **`SPL-Q9` posed** with the decomposition (`Origin` / `RelayPhase` / `Responsibility`, the byte enum kept as the seam's word) as default, `RelayClock` superseded by per-phase clock words; `SPL-Q6` amended accordingly (`None` is neither an origin nor a phase); `relay_category::legacy` confirmed not minted (§93.4). SPL-14 untouched and sharper. *(`SPL-Q9` ruled the same day — the row above.)* |
| 2026-09-24 | **Copilot round on PR #849 — six findings, all validated at source, all applied.** SPL-15 minted (a ninth DB method, `txpool_has_tx`, reached past `Blockchain::` by `have_tx` — the network path's membership read; census method corrected for S-ALT); `PoolCannot::EmptyBlob` (P1's refusal had no representable result); `RelayClock`'s two admission rules (attested-local admits `LastRelayedAt(receive_time)`, not the sentinel — the sentinel makes the fallback permanently ineligible); SPL-7 / `SPL-Q5` corrected — the C++ `init` never reads the chain's `spent_keys`, so reconciliation is new E5 work with a falsifier, not inherited behaviour; `SPL-Q8` gains the check that authorizes the wipe (only a sealed pool file at another version; everything else refused); SPL-4's "five bits" → four class bits, five encoder patterns, one independent bit. |
| 2026-09-24 | **Round 1 RULED** (maintainer, PR #849). Q1, Q2, Q4, Q8 approved; Q3 approved with the requirement stated (no default arm; an error, never a value, on an unknown discriminant); Q5 approved with the reason written into the row (chain-first is the recoverable ordering — only one order is safe on a dirty run); Q7 approved for the reason S-ARCH's `Option` survived (persist-whole is what makes the relay-privacy lane's decision askable), with the concrete scenario pulled forward — a persisted stem-phase entry whose embargo passed during downtime. **Q6's default corrected:** the maintainer's verification of SPL-4 found the fall-through already documented as an aside (`blockchain_db.h:126–130`, inside the case for keeping `relayable`) and recorded nowhere as a finding; it is now **SPL-14** — origin disclosure caused by a parse default — and the codec's guard moves from `None` (unreachable; nothing writes it) to *every unrecognised state*, with `Fluff` reachable only by its own byte. Fourteen findings; the increment may be cut. |
| 2026-09-24 | **Round 0 executed** at `a1159f1a2`. Thirteen findings (SPL-1 … SPL-13); eight questions posed with defaults (SPL-Q1 … Q8). The surface's eight methods are eight pass-throughs with one consumer (`tx_memory_pool`) and map to seven store operations, none of which classifies; the substrate fact that sizes the increment is SPL-1 — the §5.1 pick (separate pool file) is ruled, unbuilt, and its falsifier has been firing since the schema map landed — so the increment is a **new file** and an **eviction**, not a re-typing in place. The record is re-specified (five relay bits → `RelayMethod`; `u64::MAX` / next-attempt / last-relayed → `RelayClock`; `fcmp_verified` + hash → `Option`; `pruned`, `do_not_relay`, `padding` dropped). The C++ pool moves nothing. |

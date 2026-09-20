# DRS-E1 S-TX — transaction blob and existence: increment plan and Round-0 pre-flight

**Status:** OPEN — **increment LANDED 2026-09-19** (the §3 contract is code: `store/tx_reads.rs`, `store/read.rs` T1–T6, `store/tx_read_tests.rs`, the STX-9 gate `check_store_unlock_time_projection.py`; no layout change). Stays in `design/` until S-CURVE's pre-flight has read it (archive-or-contract per index §8 then). History: **Round 0 (pre-flight) executed 2026-09-19** at `dev` =
`8b48f574c` (the tree that merged PR #783, S-OUT-KI); re-based through `6c41bf820`
(#784 … #790; the increment cut from `fbc92287a`). **Round 1 RULED 2026-09-19** (maintainer,
on PR #786; §9, each ruling line-local): **Q1 B** (`Option`, the counter-rule's
worked case), **Q2 A**, **Q4 A** with a coupling to Q3; **Q3 re-ruled the
same day: the walk lands on completeness grounds** (a range read is part of
what makes a keyed dense table a table, not a feature rule 22 can withhold),
and the question to E2 becomes the **row shape**, non-blocking (§9; the DRS
lane-coordination log). **No public read type under `store/` has an `unlock_time` field** (STX-9
as restated on round 3, with its gate; the one existing offender is
S-OUT-KI's `RecordedOutput`, removed by this increment's commit 1).
**Round 3 (PR #786 review, 2026-09-19):** T1 returns `TxLocation`, not the
stored row; T6 is the walk `tx_indices` can actually give at v6 — its own
key order, its own projection — and **#788 answered the E2 question**: E2's
redb-side reads are `block_info` hashes, `key_images` and the root into
`digest_v0`; it projects no tx table, so `TxHeader` and its join are not
built. (Implementation started when this document merged, #786, and landed the same day.) Implements *from* [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)
§3.5/§7 (the S-TX row: extraction order **5**, "tx blob and existence reads,
dependent on chain-R for height context; no writer of its own — the daemon
writes txs only through `add_block`"), §7.6 (parity first; the ported
partition is transitional; the comparator projects logical content) and
§7.7 (the hash-row / segment invariant); from
[`DRS_E1_SCHAIN_R.md`](../completed/DRS_E1_SCHAIN_R.md) (the read handle and
its fault policy — this surface is more reads on `ReadSnapshot`, and its
"Option stays Option" counter-rule is applied, not overridden, in §3.3); from
[`DRS_E1_SOUT_KI.md`](../completed/DRS_E1_SOUT_KI.md) §2.2 (which handed
`get_tx_unlock_time` and `get_tx_block_height` to this surface, and whose
`AtIndex<T>` is reused for the one dense-id read here); and from
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) **`PDM-Q6`
item 1** (the prunable region *is* the archival good) and **`PDM-Q7`** (the
stripe engine is deleted) — the two rulings whose interaction §2.3 states,
because a reader who has only heard of the second will draw the wrong
conclusion about this surface's three prunable reads. Process per
`26-sub-pr-design-discipline.mdc`; identifier family **`STX-`** registered
in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by the PR that
adds this file (rule 94 §1).

**Steering, 2026-09-19 (maintainer, on the S-OUT-KI closeout):** three
corrections that shape this round, recorded before it begins so they are
the round's premises rather than its discoveries.

1. **The unblocking claim rests on S-CHAIN-R (#772), which is in `dev`.**
   PR #784 (SOK-10, the path-assembler deletion) is **not** in `dev` at this
   pin and is not a dependency of this surface. SOK-10's C++ deletion stays
   outstanding; it does not gate S-TX, and **no daemon is built until the
   redb conversion is complete**, so an outstanding C++ deletion in another
   lane is not a build problem for this one.
2. **The prune-shaped methods cannot be "not ported," and the reason is the
   opposite of the one a reader would infer from `PDM-Q7`.** §2.3.
3. **`get_tx_unlock_time` and `for_all_transactions` get a full caller
   census before any disposition** — the shape #782 just closed (a served
   surface with no consumer) is the shape to check for, and "four callers"
   that are three offline tools and one daemon path is a different port
   than four daemon paths. §2.1 carries both censuses with their
   split.

---

## 0. What this document is

The plan and pre-flight for **DRS-E1 increment 6**: the S-TX read surface
on `ReadSnapshot`. Nine `BlockchainDB` methods in DRS §7's row, plus one
re-homed here by S-OUT-KI (`get_tx_block_height`), become a small number of
typed reads over the tables `connect` already writes. There is no writer:
S-CHAIN-W writes every transaction table at `connect` (`tx_indices`,
`txs_pruned`, `txs_prunable`, `txs_prunable_hash`, `txs_pqc_auths`,
`txs_pqc_auth_hash`, `tx_outputs`), and this increment reads them.

Two things make this surface more than "S-OUT-KI again with hashes":

- **Three absence shapes on one surface, each earned — and one of them is
  `Option`.** A lookup by transaction hash is sparse — absence is ordinary
  and carries no instruction beyond *not here*, so it is the counter-rule's
  case and stays `Option` (Q1 B). A lookup by `tx_id` is dense — a hole is
  SI-9. A lookup of the *prunable region* of a recorded transaction has a
  third state that is neither: **discarded**, the store state
  `DAEMON_REDB_STORE.md` §7.7 leg (iii) defines (hash row present ∧ segment
  absent), which is not corruption and not "not here" — it is *this node
  does not hold the good*, and the caller's next action (answer from the
  hash, or fetch from an archiver) is different from both. §3.3 states the
  discriminator; it is the same one `CURVE_TREE_STORE_SHAPES.md` §3.1 and
  `CHAIN_RULES_CRATE.md` G11 state, applied three ways rather than copied.
- **The prunable-region reads are the archival good's read path.** §2.3.

---

## 1. Preconditions, as found at the pin

| Precondition | State at `8b48f574c` |
|---|---|
| S-TXN lifecycle (increment 1) | landed (PR #740, 2026-09-13) |
| Canonical codecs, rule-42 gate, `schema_version` seal (increment 2) | landed (PR #749, 2026-09-15) |
| S-CHAIN-W (increment 3): `connect` writes every tx table | landed (PR #757, merged 2026-09-16) |
| S-CHAIN-R (increment 4): `ReadSnapshot`, `AtHeight`, the fault policy, `chain_reads.rs` | landed (PR #772, merged 2026-09-17) |
| S-OUT-KI (increment 5): `AtIndex<T>`, `output_reads.rs`, layout v6 | landed (PR #783, merged 2026-09-19) |
| §7.7 legs (i)–(iii): hash row permanent; segment ⇒ hash row; hash row ∧ segment absent ⇔ discarded | landed (F26 / A3, #772). Leg (iv), the `u32` length rows, is **A4, owed** to S-CHAIN-W by `PDM-Q-F32` — **not** a precondition here (§2.2) |
| `PDM-Q6` item 1 (the good) and `PDM-Q7` (stripe engine deleted) | RULED 2026-09-17 / 2026-09-18 |
| PR #784 (SOK-10) | **not in `dev`**; not a dependency (steering item 1) |

The stated dependency is S-CHAIN-R alone: the tx reads need height context
(`TxIndex.height` is a `BlockHeight` the tip classifies) and nothing else
from a later surface. The lane is unblocked on that ground.

---

## 2. Scope

### 2.1 In — the census, method by method

Callers are counted **outside the DB layer** (`src/blockchain_db/**`
excluded), read at `8b48f574c`, and split three ways: **daemon** (the live
node, `blockchain.cpp` / `cryptonote_core.cpp` / protocol), **FFI seam**
(`rpc_facts_ffi.cpp` / `daemon_submit_ffi.cpp` — reads that already cross
into `shekyl-daemon-rpc` today), and **tools**
(`src/blockchain_utilities/*`, offline, die with the C++ store).

| Method | Daemon callers | FFI-seam callers | Tool callers | Disposition |
|---|---|---|---|---|
| `tx_exists` | `have_tx` (`blockchain.cpp:244`), `handle_alternative_block` (`:2295`), `get_tx_outputs_gindexs` (`:3155`, `:3171`), `handle_block_to_main_chain` (`:5681`) | — | — | **T1** `tx_location(&TxHash)`: the existence answer *is* the index row, projected to `TxLocation` |
| `get_tx_count` | `Blockchain::get_tx_count` (`:3064`) → `get_total_transactions` → `get_info.tx_count` (`core_rpc_server.cpp:213`) | — | — | **T2** `tx_count()` |
| `get_tx_blob` | `get_blocks` (`:2800`), `get_transactions` (`:2901`) | via `bc.get_transactions` (`rpc_facts_ffi.cpp:1056`) | — | **T3 + T4** composed: the full blob is `pruned ‖ pqc_auths ‖ prunable` (STX-8); no third read |
| `get_pruned_tx_blob` | `handle_alternative_block` (`:2338`), `get_blocks` (`:2792`), `get_transactions` (`:2901`) | `rpc_facts_ffi.cpp:747` (`shekyl_rpc_tx_entry.pruned`) | `blockchain_ancestry`, `blockchain_depth`, `blockchain_stats` | **T3** `tx_record(&TxHash)` — the permanent half |
| `get_prunable_tx_blob` | `get_blocks` (`:2819`) | `rpc_facts_ffi.cpp:781` (`shekyl_rpc_tx_entry.prunable`) | `blockchain_stats` | **T4** `tx_prunable(TxStorageId) -> AtIndex<Prunable>` — the good (§2.3) |
| `get_prunable_tx_hash` | `get_blocks` (`:2829`) | `rpc_facts_ffi.cpp:771` (`shekyl_rpc_tx_entry.prunable_hash`) | — | carried on **T3**'s record (a permanent hash row, §7.7 leg (i)) |
| `get_tx_unlock_time` | `get_output_key_mask_unlocked` (`:2630`) **only** — and S-OUT-KI's census (SOK-7, `CONSENSUS_RULE_CENSUS.md` UPDATE 2026-09-18) found *that* method callerless | — | — | **transitively callerless** (STX-1). Not ported by default; **STX-Q2** |
| `get_tx_amount_output_indices` | `get_tx_outputs_gindexs` (`:3160`, `:3176`) → `core::get_tx_outputs_gindexs` (`cryptonote_core.cpp:1203`) | `rpc_facts_ffi.cpp:617`, `:794` (`/get_o_indexes.bin`, `get_transactions` facts) | — | **T5** `tx_output_indices(TxStorageId) -> AtIndex<TxOutputIndices>` — the one dense-id read |
| `for_all_transactions` | `Blockchain::for_all_transactions` (`:7019`) is a wrapper with **no daemon caller** | — | `blockchain_usage.cpp:187` | **not ported as a callback**; a range read lands only for a named consumer (**STX-Q3**) |
| `get_tx_block_height` (re-homed here by S-OUT-KI §2.2) | — | `rpc_facts_ffi.cpp:785` (`block_height`), `daemon_submit_ffi.cpp:405` (`in_chain_height`) | `blockchain_usage.cpp:190` | carried on **T3**'s record: `TxIndex.height` |

**The split, stated.** Of the ten, the tool-only callers are one method's
(`for_all_transactions`); every other method has a daemon or FFI-seam
caller, and **four of them already cross the FFI into Rust**
(`get_pruned_tx_blob`, `get_prunable_tx_blob`, `get_prunable_tx_hash`,
`get_tx_block_height` — all in `shekyl_rpc_transactions`, `rpc_facts_ffi.cpp:735–790`,
feeding `shekyl-daemon-rpc`'s `get_transactions`; and `get_tx_block_height`
again in the submit path's `SubmitFactsFfi.in_chain_height`). The C++
callers switch to `ReadSnapshot` at cutover, not here (§2.2); the reads
exist so that they can.

### 2.2 Out (named, so it is not scope shed by omission)

- **The prune itself** — the discard, its predicate, the journal horizon,
  the `u32` length rows (S-CHAIN-W amendment **A4**, owed by `PDM-Q-F32`).
  That is S-PRUNE's ([`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md), a skeleton at
  this pin). This surface **reads** the state S-PRUNE will produce
  (§7.7 leg (iii)) and adds nothing S-PRUNE's first increment would have to
  move. T4's `Discarded` arm is well-defined today on legs (i)–(iii) alone:
  it does not read the length rows and does not distinguish *discarded*
  from *never held* — "body-absent is one state" (S-PRUNE §5).
- **`txs_prunable_tip`** (`u64 → Unshaped`, LMDB's prune-worker cursor
  table). No read here; it is the stripe engine's and dies with `PDM-Q7`
  (STX-4). It stays in the catalogue until DRS-E* deletes it with the C++.
- **Any daemon wiring** and any C++ deletion. `get_blocks`,
  `handle_alternative_block`, `get_transactions`, the two FFI seams switch
  readers at cutover; C++ methods die at DRS-E* under `PDM-Q-S0` (S-PRUNE
  §13's pattern). Nothing in `src/` changes in this increment.
- **S-CURVE** (DRS §7 order 6), the next surface. Named so a leaf read this
  increment finds convenient is not smuggled in.
- **Alt-block transactions** (`handle_alternative_block`'s pruned-blob read
  is against the *main* chain's table, for a tx an alt block references;
  the alt-block store itself is S-ALT).

### 2.3 The prunable region is the good — stated once, here

A reader arriving from `PDM-Q7` ("the stripe engine is deleted") will infer
that `get_prunable_tx_blob` and `get_prunable_tx_hash` are stripe residue
and may be dropped with it. **That inference is wrong, and the rest of PDM
depends on its being wrong.** `PDM-Q6` item 1 ruled that the archival
subject — the thing the archival market is built to sell — *is* each
transaction's prunable region (`CtSigPrunable`, `src/fcmp/ct_types.h:298`):
the unit of possession is one transaction's `CtSigPrunable` bytes, the unit
of verification is its `txs_prunable_hash`, which every node retains
forever. What `PDM-Q7` deleted is the *mechanism* by which Monero decided
which stripe of that region a node kept; what `PDM-Q6` made load-bearing
is *access to the region itself* — for the archiver that serves it, the
verifier that binds it to the hash, and the node that fetches it back.

So the disposition for the three prune-shaped methods is the opposite of
"not ported": **they are the archival good's read path**, and `PDM` made
them more load-bearing, not less. Concretely:

- `get_prunable_tx_hash` → the **verification unit**, carried on T3's
  record as a permanent row (§7.7 leg (i)). It is read unconditionally
  today at `rpc_facts_ffi.cpp:771`, with a `MERROR` if absent; under the
  typed read a record without its hash row is **SI-7**, not a log line
  (STX-6).
- `get_prunable_tx_blob` → the **possession unit**, T4, with the
  three-state answer §3.3 defines. Its `Discarded` arm is the state an
  archiver's *serve* path and a pruned node's *fetch* path both branch on.
- `get_pruned_tx_blob` → the permanent half, T3, which every node holds
  at every horizon.

Conflating "the stripe mechanism is dead" with "prunable-region access is
dead" would delete the access path for the thing the market sells. The
next lane to read this plan inherits *this* paragraph, not "not ported."

### 2.4 What DRS-E2 gets from this increment

The comparator's projection of the tx tables: T1/T3/T4 give it a
by-hash read of everything the LMDB `get_*_tx_blob` family returns, T5 the
`tx_outputs` row, and **T6** the bounded walk over `tx_indices` in its own
key order. **What E2 actually reads, per #788 §3.1:** none of these — its
redb-side digest is `block_info` hashes + `key_images` + the root. S-TX's
reads exist for the cutover-time C++ callers and the FFI seam (§2.1); E2
gets them as a by-product, not as their reason.

### 2.5 What this pre-flight closes

- The S-OUT-KI hand-offs (`get_tx_unlock_time`, `get_tx_block_height`) are
  dispositioned (§2.1), which is the event that archives
  `DRS_E1_SOUT_KI.md` (its §10; done by this PR).
- The `PDM-Q6`/`PDM-Q7` interaction on this surface is stated (§2.3).

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the reads live

`ReadSnapshot` methods in `store/read.rs`, thin over a shared body in
**`store/tx_reads.rs`** — the third sibling of `chain_reads.rs` and
`output_reads.rs`, so that a reader that later needs a tx read from
`BatchView` (E2's comparator, or a validator rule) gets the same body.
Faults classify through `ReadFault` as the other two bodies do.

### 3.2 The mapping — 10 methods, 5 point reads and one bounded walk

| Read | Signature (proposed) | Replaces |
|---|---|---|
| **T1** | `tx_location(&TxHash) -> Result<Option<TxLocation>, StoreError>` | `tx_exists` (both overloads); the index row *is* existence, and callers that then want the id (`get_tx_outputs_gindexs`) have it. Returns **`TxLocation { id, height }`**, not the stored `TxIndex` (round 3): the stored row carries `unlock_time`. **This is not the identity-DTO hop SOK-Q4 / STX-Q4 refused** — those rejected a second struct that *renames* an identical shape; `TxLocation` deliberately *drops* a field, which is the opposite operation and the whole reason it exists. Said here so rule 27 applied correctly does not reach the wrong conclusion. |
| **T2** | `tx_count() -> Result<u64, StoreError>` | `get_tx_count` (`txs_pruned.len()`, the dense primary) |
| **T3** | `tx_record(&TxHash) -> Result<Option<TxRecord>, StoreError>` | `get_pruned_tx_blob`, `get_prunable_tx_hash`, `get_tx_block_height`, and the pruned half of `get_tx_blob` |
| **T4** | `tx_prunable(TxStorageId) -> Result<AtIndex<Prunable>, StoreError>` | `get_prunable_tx_blob`, and the prunable half of `get_tx_blob`. `AtIndex` because `TxStorageId` is a dense id with a public `from_raw` (round 4): the bound is checked first, as T5 does |
| **T5** | `tx_output_indices(TxStorageId) -> Result<AtIndex<TxOutputIndices>, StoreError>` | `get_tx_amount_output_indices` |

`get_tx_unlock_time` is not in the table (Q2 A, not ported). `for_all_transactions`'
successor is **T6** `tx_locations(range: Range<TxHash>) -> impl Iterator<Item = Result<(TxHash, TxLocation), StoreError>>`
— a **bounded** walk over **`tx_indices` in its own key order** (hash order,
`LmdbHashKey`), yielding the table's projection and nothing joined to it.
`Range<TxHash>`, half-open with both endpoints present — S-CHAIN-R's clamped
shape — **not** `impl RangeBounds` (round 4): `RangeBounds` admits `..`,
`start..` and `..end`, so a signature stated as bounded would have let a
caller request the full-chain scan the word was there to exclude. The type
is the bound; there is nothing to test for rejection because the unbounded
call does not compile.
It lands in commit 3 on **completeness** grounds (Q3 as re-ruled): a range
read over a keyed table is part of what makes the table a table — `keyed.rs`
ships a generic `range`, `read.rs` has `range_at`, S-CHAIN-R landed
half-open clamped ranges — and S-TX would otherwise be the one surface
walkable in principle and not in practice.

**Why this shape and not the round-2 one** (round 3, two corrections):

- *Hash order, not id order.* Round 2 drafted an id-ordered header walk
  over `txs_pruned`. At layout v6 that is not implementable: `txs_pruned` is
  `u64 → Blob` (`schema.rs:311`), `height` lives in `tx_indices` keyed by
  hash (`schema.rs:329`), and nothing maps `tx_id → hash` — the walk would
  have needed a reverse index (a layout change) or a full scan per range,
  and its "opens no blob table" test could not have held. Hash order is what
  LMDB's `for_all_transactions` actually walks (it cursors `tx_indices`),
  and it is `tx_indices`' own projection. **A reverse index is rejected
  now, reopened if** a consumer names an id-ordered walk of `txs_pruned` —
  ruled then with its `SCHEMA_VERSION` bump, never smuggled in.
- *No `TxHeader`, no join.* Round 2 had T6 join each row by id to the two
  permanent hash rows to yield a `TxHeader` for E2's per-table comparator.
  **#788 (DRS-E2's pre-flight, Round 0 ruled) answered the question before
  E2 had to:** E2's redb-side reads are `block_info` hashes, `key_images`
  (S-OUT-KI K2, which exists *for* this) and the live root, assembled into
  `digest_v0` (#788 §3.1, RD-F5); E2 **projects no tx table**. So the join
  has no consumer and is not built: a walk that joins is 2N random point
  reads against one sequential scan — fine for a comparator, wrong for
  anything else — and building it speculatively is how `tx_headers` would
  become the walk the next lane reaches for. A caller that wants hash rows
  for a walked row has T3. **Reopen criterion (rule 21), stated as one
  question because its two halves are coupled:** a later E2 increment that
  projects tx tables per row names, *together*, the row it needs and the
  order it needs it in — id order keys the row on id and needs the reverse
  index above; hash order keys it on hash and grows this walk a join. The
  `comparator-parity` cfg mechanism (§3.4) is the decided shape for
  `unlock_time` if that row ever needs the column.

T4 takes a **`TxStorageId`, not a hash** — deliberately: a caller reaches
the prunable region *through* a record (T3 hands it the id), so the by-hash
`None` does not recur at T4. **But the argument type does not carry
"already resolved"** (round 4 correction): `TxStorageId` is publicly
re-exported with a public `from_raw(u64)` (`ids.rs`, `lib.rs`), so any
caller can pass an absent or out-of-range id, and a contract that read such
an id as SI-7 corruption would be classifying ordinary invalid input as a
store fault. So T4 returns **`AtIndex<Prunable>`** and applies the dense-id
discipline T5 already does: bound first against `txs_pruned.len()` — at or
beyond the count is `BeyondCount`, no row read; below it the region is
`Retained` or `Discarded`; below it with no `txs_prunable_hash` row is SI-7.
The two-state answer is the *inner* type, reached only once the bound has
admitted the id. (A minted opaque handle would have been the alternative;
it was not taken because `from_raw` is legitimately public for the codec
layer, and a second id type for one read is the identity hop.)
`get_tx_blob`'s callers compose T3 then T4 and concatenate in the wire's
segment order (STX-8); no third read exists for the composition, because
the composition is one line and a third read would be the identity-DTO hop
SOK-Q4 refused.

### 3.3 Absence, faults, and what a read may not do — three shapes, one discriminator (Q1 RULED B)

`CHAIN_RULES_CRATE.md` G11 / `CURVE_TREE_STORE_SHAPES.md` §3.1: **absence
earns a type when its case carries caller-actionable semantics**, and
S-CHAIN-R's counter-rule: **`Option` stays `Option`** when it does not.
This surface has three lookups and they land on three different sides of
that line; the pattern is now easy to cargo-cult, so each is justified:

- **By hash (T1, T3) — `Option<T>`. This is the counter-rule's worked
  case, recorded as such (Q1 RULED B, 2026-09-19).** Hashes are sparse. A
  miss is ordinary and instructs nothing beyond *not here* (`have_tx`
  returns false; `get_transactions` adds to `missed_txs`); there is no
  second absence the caller must tell apart, so there is nothing for an
  arm to name. The round's proposed alternative — a named
  `AtHash { Recorded, NotRecorded }` "for family coherence" with T4 — was
  refuted by this section's own text: T4 is **two** arms, neither of which
  is *not recorded*, and the state the coherence argument leaned on
  (`Discarded` for an id with no hash row) is the one this section forbids
  as SI-7, "never a third arm." With that removed the discriminator decides
  alone, and it says `Option`. **Why this is written down rather than
  just done:** the absence pattern is now easy to cargo-cult — `AtHeight`,
  `AtIndex`, `SegmentAvailability`, `Prunable` all in the tree — and a
  documented instance of *here it does not apply* is what stops the next
  reader from minting a fourth absence type for a sparse key.
- **By dense id (T4, T5) — `AtIndex<T>`, reused.** `tx_id` is dense (SI-9: `txs_pruned`' entry count at write time). At or beyond the count is `BeyondCount`; a hole below it is **SI-9**; bound first, then the row — exactly `output_reads`' discipline, and the same type, because the index domain is the same kind of thing.
  **Then the primary, before any side table** (PR #800 review round 1): the count proves an id *should* exist, only `txs_pruned[id]` proves it *does*,
  and a side row present at an id whose primary is missing is the count lying — SI-9 — not a recorded transaction. One admission step
  (`tx_reads::admit`) does both, so T4 and T5 cannot disagree on what "recorded at `id`" means; S-OUT-KI's O1 had the same gap against
  `output_txs` and takes the same step in the same commit.
- **The prunable region (T4) — `AtIndex<Prunable>`, with
  `Prunable { Retained(bytes), Discarded }` inside.** The outer `AtIndex`
  is the dense-id bound (round 4: `TxStorageId::from_raw` is public, so an
  out-of-range id is `BeyondCount`, not corruption). Given an id below the
  count, the region is either held or it is not, and *not
  held* is a **defined store state** (§7.7 leg (iii): hash row present ∧
  segment absent ⇔ discarded — below `W`, or never held; one state, one
  meaning). It is not corruption (the writer never wrote it, or the prune
  removed it under its contract) and it is not "not here" (the transaction
  is recorded; its hash is answerable). The caller's action differs from
  both: serve the hash and let the client fetch the bytes from an archiver,
  or, on an archiver, refuse to serve. That is the case that earns the
  arm. **What T4 may not do:** return `Discarded` for an id with no
  `txs_prunable_hash` row — that is the segment-without-hash-row or
  record-without-hash-row shape §7.7 leg (ii)/(i) forbids, and it is
  **SI-7** (`CellCorrupt { key: "txs_prunable_hash", fault: Absent }`),
  never a third arm.

Faults, uniformly: a row that must exist and does not is the invariant
whose leg says so (SI-9 for a dense hole, SI-7 for a missing permanent
row); a row that does not decode is SI-7 `Undecodable`; engine errors pass
through. **A read never arms the halt** (DRS §3.6.2, read-side half).

### 3.4 Types this increment adds to the store crate

- No by-hash absence type (Q1 B): T1 and T3 return `Option`. The
  `TxHash`/`TxStorageId` parameter types already keep a sparse lookup and
  a dense one from being confused at a call site.
- `TxLocation` — T1's answer and T6's item: `id: TxStorageId`,
  `height: BlockHeight`. The stored `TxIndex` projected **without
  `unlock_time`**; existence plus where. A read projection, not
  `Canonical`. Not the identity-DTO hop (§3.2 T1: it drops a field, the
  opposite of renaming one).
- `TxHeader` — **not built** (round 3; #788 shows E2 projects no tx table).
  Recorded so the shape is not re-derived if §3.2's reopen criterion fires:
  `TxLocation` joined by id to `prunable_hash` and `pqc_auth_hash`,
  **without the blobs**, and **without `unlock_time`** (STX-9: a field with
  no live consumer does not get a second reason to exist by being designed
  into a projection E2 will then depend on). **The one exception, with its
  mechanism decided now and dormant until that criterion fires:** if a
  later E2 row needs the column for completeness of a parity diff against
  LMDB's `txindex`, it enters that row **behind a cfg feature the
  comparator owns** — `#[cfg(feature = "comparator-parity")] pub unlock_time: Timelock`,
  the feature declared in `shekyl-chain-store`'s `Cargo.toml` and enabled by
  the comparator crate alone. A *"transitional — dies with the comparator"*
  marker would state an expiry with nothing that fires at it (the field
  would sit, and the marker would become a comment explaining why a field
  outlived its reason). The feature makes the expiry a **consequence of the
  event**: retiring the comparator deletes the feature, and the field cannot
  compile without it — the same move as `held_by_cxx` expiring when its
  cited test file is gone. **The one link that construction still rested
  on — noticing that the feature is declared with no enabler left — is a
  gate, not a remembered grep:** `scripts/ci/check_test_only_features.py`
  (already reading `cargo metadata`) gained a `CONSUMER_OWNED` limb whose
  row `("shekyl-chain-store", "comparator-parity") → (<comparator crate>,
  why)` lands in the same commit as the feature. It goes red when the
  enabler is no longer a workspace member (self-expiry, with the delete
  instruction), when a second crate enables the feature (a second consumer
  quietly depending on code that dies with the first), when no crate
  enables it, or when the owner's own feature table does; `--selftest`
  pins all four on synthetic metadata so the limb asserts its subject while
  the registry is still empty (rule 47). And because those checks are keyed
  by the row, the same gate makes the registries **exhaustive** for
  `shekyl-chain-store`: every feature the crate declares must be categorized
  (test-only, consumer-owned or permanent) or the gate is red — landed while
  the crate declares no features, the one moment that costs nothing. What
  the gate cannot see, named in its docstring: whether anything is still
  *guarded* by the feature; whoever deletes the last `cfg`'d item deletes
  the feature and the row with it. A genuinely different shape from `TxRecord`, not the same
  shape renamed (Q4's coupling): a full-chain comparator pass over an
  eager record would materialise every pruned blob in sequence.
- `TxRecord` — a read projection, not `Canonical`: `id: TxStorageId`,
  `height: BlockHeight`, `pruned: Bytes` (the `TxPrunedSegment` blob), `pqc_auths: Option<Bytes>`
  (present ⇔ the txid is 4-part, §7.7), `prunable_hash: PrunableHash`,
  `pqc_auth_hash: Option<PqcAuthHash>` (A3). **No `unlock_time`** (STX-9;
  `TxIndex` keeps storing it — the layout does not move — but no read
  projects it until U-2 rules the field). `pruned` is read eagerly
  with the record (Q4 A): every T3 caller wants the bytes, and `have_tx`
  has T1. The one consumer that wants the header without the blob is the
  walk, and it gets its own item type (`TxLocation`; `TxHeader` if the
  §3.2 criterion ever fires), not a lazy flag on this one.
- `Prunable` — the two-arm enum above, with the bytes as the
  `TxPrunableSegment` blob.
- No new key type: `tx_indices` is `LmdbHashKey`-keyed (`Hash32`), and
  `TxHash` converts at the edge as `KeyImage` does for `spent_keys`.

### 3.5 What this surface inherits, and for how long

- **`TxIndex.unlock_time`** is stored because LMDB's `txindex` stored it,
  and the field's fate is **already owned elsewhere**: census **U-2**
  (`CONSENSUS_RULE_CENSUS_1.md` — "the highest-value item in the census …
  needs a ruling, not a port") and the reconciliation's **§6 finding 2**,
  the *unlock_time triple-divergence* (consensus-legal CEN-H16,
  relay-illegal CEN-M5, semantically inert CEN-L12, no single owner). This
  surface does not rule it and does not pre-empt it. What it does (STX-9):
  keeps writing the field (no layout move) and holds an invariant stated
  **narrowly enough to check** (round 3 — the round-2 wording "exposes no
  read of it" was ambiguous between *decodes a row containing it* and
  *returns it*, and that ambiguity is what let T1 return the stored
  `TxIndex`): **no public read type under `store/` has an `unlock_time`
  field.** Reads still decode `TxIndex` and `OutKey` rows — the field is in
  their bytes — but no type they hand out carries it. Enforced, not
  asserted: a grep-shaped CI gate (`rg -n 'pub unlock_time'
  rust/shekyl-chain-store/src/store/` must be empty; the stored codec rows
  under `codec/` are exempt by construction) lands with commit 1. **Running
  it today is red on one line:** S-OUT-KI's `RecordedOutput.unlock_time`
  (`store/output_reads.rs:72`), a projection with no consumer outside the
  crate (SOK-7: the path builder wants pubkey and commitment) — the exact
  shape this invariant forbids, landed one increment earlier by the same
  lane. Commit 1 removes that field with its test literals; the gate is
  green from the commit it lands in. The C++ method that read the tx field
  dies with the C++ store (Q2 A). Falsifier for anyone tempted to add a
  projection back:
  `rg -n 'unlock_time' rust/shekyl-chain-rules/src` non-empty *outside the
  test harness* ⇒ a rule reads it and the read is minted for that rule, by
  name.
- **`txs_prunable_tip`** — inherited, unread, dies with `PDM-Q7` (STX-4).

---

## 4. The read set, table by table

| Table | Key → value (at v6) | Read here | Absence | Writer |
|---|---|---|---|---|
| `tx_indices` | `LmdbHashKey → Coded<TxIndex>` | T1, T3 `get(hash)`; T6 `range` in key (hash) order | `None` — sparse (Q1 B); no read returns the stored row whole (T1/T6 → `TxLocation`) | `connect` (SI-3) |
| `txs_pruned` | `u64 → Blob<TxPrunedSegment>` | T2 `len()`; T3 `get(id)` after T1 | below the count and absent: **SI-9**; T3 never asks beyond it (the id came from a record) | `connect` (SI-9) |
| `txs_prunable` | `u64 → Blob<TxPrunableSegment>` | T4 `get(id)`, bound first against `txs_pruned.len()` | `BeyondCount` at or beyond the count (no row read); below it, absent with hash row present: **`Discarded`** (§7.7 (iii)) | `connect`; removed by S-PRUNE's discard |
| `txs_prunable_hash` | `u64 → Coded<PrunableHash>` | T3 `get(id)`; T4 checks presence before `Discarded` | absent for a recorded id: **SI-7** (permanent row, leg (i)) | `connect`, never deleted |
| `txs_pqc_auths` | `u64 → Blob<TxPqcAuthsSegment>` | T3 `get(id)` | absent ⇔ 3-part txid (no `txs_pqc_auth_hash` row); absent *with* a hash row: **SI-7** (leg (ii), pairwise) | `connect`; S-PRUNE (`pqc_auths` enter the good, `PDM-Q6` item 2) |
| `txs_pqc_auth_hash` | `u64 → Coded<PqcAuthHash>` | T3 `get(id)` | absent ⇔ 3-part txid | `connect`, never deleted |
| `tx_outputs` | `u64 → Coded<TxOutputIndices>` | T5 `get(id)`, bound first against `txs_pruned.len()` | `BeyondCount` / **SI-9** hole | `connect` (SI-9) |
| `txs_prunable_tip` | `u64 → Unshaped` | **not read** | — | stripe engine; dies with `PDM-Q7` |

The dense count authority is **`txs_pruned.len()`** — the primary `tx_id`
is dense in — the same "one table is the authority, the others are checked
against it" that `output_reads` uses with `output_txs`.

---

## 5. Store invariants this increment builds or restates

None new. Restated at the read site: **SI-3** (`tx_indices` keys are
fresh — a by-hash read has at most one row by construction), **SI-9**
(`tx_id` dense — T5's `BeyondCount` boundary and hole), and **§7.7 legs
(i)–(iii)** (T3's SI-7 on a missing hash row; T4's `Discarded` is leg (iii)
read back). Leg (iv) is A4's and not read here.

---

## 6. Round-0 findings

| # | Finding | Disposition |
|---|---|---|
| **STX-1** | `get_tx_unlock_time` is **transitively callerless**: its only caller outside the DB layer is `Blockchain::get_output_key_mask_unlocked` (`blockchain.cpp:2623`–`2630`), which S-OUT-KI's census found has no caller of its own (SOK-7; `CONSENSUS_RULE_CENSUS.md` UPDATE 2026-09-18). Under FCMP++ maturity is height + miner flag; the per-tx unlock time is stored (`TxIndex.unlock_time`) and read by nothing live. | Not ported by default. **STX-Q2** decides whether the C++ pair (method + dead caller) is deleted now, #782's shape, or dies with the C++ store at DRS-E*. Field fate: FOLLOWUPS row with falsifier (§3.5). |
| **STX-2** | The three prune-shaped methods are **the archival good's read path** (`PDM-Q6` item 1) and **already cross the FFI into Rust** (`rpc_facts_ffi.cpp:747`, `:771`, `:781` → `shekyl_rpc_tx_entry` → `shekyl-daemon-rpc` `get_transactions`). "Not ported" would break the Rust RPC layer that consumes them today and delete the access path for what the market sells. | Ported as T3/T4 with the three-state prunable answer. §2.3 is the standing statement. |
| **STX-3** | `for_all_transactions`' callers split **one tool + one wrapper with no daemon caller**: `blockchain_usage.cpp:187` and `Blockchain::for_all_transactions` (`:7019`), the latter reached by nothing in `src/` or `rust/`. | Not ported as a callback. Its successor is the bounded range read T6 over `tx_indices` in key order, which lands on completeness grounds (STX-Q3 as re-ruled; STX-10 on why rule 22 does not withhold it) with **no named consumer** — #788 shows E2 projects no tx table, so none is claimed. |
| **STX-4** | `txs_prunable_tip` (`u64 → Unshaped`) is the stripe worker's cursor table: written by `prune_worker`, read by nothing this surface replaces, and `PDM-Q7` deleted the engine. | Not read. Stays in the catalogue (renumbering is a layout bump) until DRS-E* deletes it with the C++; named here so the deletion is scheduled, not discovered. |
| **STX-5** | `get_tx_block_height` (re-homed here by S-OUT-KI §2.2) has two FFI-seam callers (`rpc_facts_ffi.cpp:785`, `daemon_submit_ffi.cpp:405`) and one tool; its answer is `TxIndex.height`. | Carried on T3's record; no separate read. |
| **STX-6** | `shekyl_rpc_transactions` reads the prunable **hash** unconditionally and `MERROR`s when a recorded transaction has none (`rpc_facts_ffi.cpp:771`–`776`, with the comment above it naming why: the hash is what lets a client bind a pruned body). That is §7.7 leg (i) enforced by a log line. | Under T3 a record without its hash row is **SI-7** `CellCorrupt { "txs_prunable_hash", Absent }` — a fault the caller cannot ignore, not a message it can. |
| **STX-7** | Three absence shapes on one surface (§3.3). The risk after S-OUT-KI is that `AtIndex` gets copied onto a sparse key because it is the newest shape in the tree. | §3.3 states the discriminator per read, and — Q1 RULED B — records the sparse lookup as the counter-rule's **worked case**: `Option`, with the refuted coherence argument kept in the text so the next reader sees why a fourth absence type was not minted. |
| **STX-9** | `TxIndex.unlock_time` (STX-1: transitively callerless) was drafted into both projections "because `TxIndex` stores it" — the mechanism by which a dead field acquires a second reason to exist, on a row E2 would then depend on. Its fate is owned by census U-2 / CSR §6 finding 2, not by this surface. | **Invariant, restated on round 3 so it is checkable: no public read type under `store/` has an `unlock_time` field** (§3.5), with a grep-shaped gate landing in commit 1 — red today on S-OUT-KI's `RecordedOutput.unlock_time`, removed by the same commit. If a later E2 row needs the column for a parity diff, it enters **behind the comparator-owned cfg feature `comparator-parity`** — retiring the comparator deletes the feature and the field cannot compile without it; the expiry is a consequence of the event, not a marker, and `check_test_only_features.py`'s `CONSUMER_OWNED` limb is what fires if the feature is ever left declared without its consumer (§3.4). |
| **STX-10** | Q3's first default (withhold the walk, rule 22) applied rule 22 to the wrong category. Rule 22 forbids a *feature* with no caller; a range read over a keyed, dense table is part of what makes the table a table, and the store already treats it so (`keyed.rs` generic `range`, `read.rs` `range_at`, S-CHAIN-R's clamped ranges). The three cases that do withhold an iterator — order as unpublished implementation detail (`tx_id` order is ruled and dense, SI-9); unbounded hot-path O(n) (argues for a *bounded* range, not omission); enumeration as a gated capability (an RPC concern, not an internal store API) — none apply. | T6 lands on completeness grounds (§3.2); Q3 to E2 is a shape question. Recorded so the next surface does not re-derive it. |
| **STX-8** | `get_tx_blob` is `pruned ‖ pqc_auths ‖ prunable` (`db_lmdb.cpp:3363`–`3366`: `assign` the pruned segment, `append` the `pqc_auths` segment where present, `append` the prunable one — the same three segments `connect` splits at write). No LMDB read returns the composition *and* a discard state, so `get_transactions(pruned = false)` on a pruned node fails the whole lookup where T3 → T4 answers `Recorded` + `Discarded`. | The composition is the caller's one line over T3 and T4; the new state is what the cutover-time caller needs and the C++ could not express. |

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None found. The LMDB reads are one-row lookups whose logical content the
tables reproduce; the only behavioural difference is STX-8, and it is an
*addition* (a state the C++ collapsed into failure), not a deviation.

---

## 7. Commit sequence (rule 90; one PR, ≤ 4 commits, cut from `dev` after this document merges)

**As landed (2026-09-19, cut from `fbc92287a`), three commits, not four — a
disclosed deviation, not a shed:** the STX-9 gate and the `RecordedOutput`
field removal went **first** as their own commit (independently green, and
the reason the invariant is checkable before the reads that rely on it);
then **T1–T6 in one commit** — the read body is one module
(`tx_reads.rs`) and one test file, and splitting six functions of one
module across three commits would have been the after-the-fact bisection
rule 90 forbids, not the unit-of-work planning it asks for; then the docs.
The sequence below is the plan as ruled; what changed is only the grouping.

1. `store: ReadSnapshot::tx_location / tx_count / tx_record — T1, T2, T3 on tx_reads.rs; the unlock_time projection gate` — also **removes `RecordedOutput.unlock_time`** (S-OUT-KI O1, consumer-less, §3.5) and lands the grep-shaped gate that no public read type under `store/` carries the field, red on that line until this commit — the shared body, `TxRecord`, SI-7 on a missing hash row (STX-6); tests: recorded / not recorded on one snapshot, a record with its hash row removed is SI-7, a 3-part txid has no `pqc_auths`, snapshot isolation across a concurrent connect.
2. `store: ReadSnapshot::tx_prunable / tx_output_indices — T4 (AtIndex<Prunable>), T5 (AtIndex)` — both bound-first against `txs_pruned.len()` (`BeyondCount` at the count for a forged or stale id, no row read); `Prunable` with `Discarded` planted by removing the segment under a present hash row; T5 bound first, `BeyondCount` at the count, SI-9 on a hole; T3 → T4 composition test against `get_tx_blob`'s concatenation.
3. `store: ReadSnapshot::tx_locations — T6, the bounded walk over tx_indices` — `(TxHash, TxLocation)` in the table's key order with S-CHAIN-R's half-open clamping; tests that the walk and T1 agree row-for-row over the range, that the order is the key order, and that the body opens exactly one table (no blob table, no join); no consumer is named (#788: E2 projects no tx table) and the doc comment carries §3.2's reopen criterion.
4. `docs: S-TX landed — DRS §7 row, index, plan banner, CHANGELOG` — §10.

No layout change: `SCHEMA_VERSION` is untouched by this increment (it was 6 when this plan was written and 7 at the cut — DRS-E6 slice 2 moved it between; the increment's own delta is zero bytes of layout); the codec snapshot gate is
unchanged (no codec added — `TxRecord` and `Prunable` are projections).

---

## 8. Denominator — what must stay green, what must be extended

- `cargo test -p shekyl-chain-store` — S-CHAIN-W's connect/pop tests are the
  writer-side denominator; nothing here changes a write.
- `check_redb_schema_key_types.py`, `check_redb_schema_bijection.py` —
  unchanged (no table added, renamed or retyped).
- `check_store_invariant_register.py` — unchanged; §5 adds no row.
- `check_engine_decomposition.sh` — unchanged.
- `check_doc_claims.py` / `check_doc_code_citations.py` — every `file:line`
  above is a claim; the pre-flight PR runs both.

---

## 9. Round-1 questions — RULED 2026-09-19 (maintainer, PR #786; Q3 asked of E2, each row line-local)

| # | Question | Default and reasoning |
|---|---|---|
| **STX-Q1** | By-hash absence (T1, T3): **A** — named `AtHash<T> { Recorded, NotRecorded }`; **B** — `Option<T>` per S-CHAIN-R's counter-rule. | **B — RULED 2026-09-19.** A's only argument (family coherence with a three-arm T4 whose first arm is *not recorded*) did not survive §3.3 itself: T4 is two arms, neither *not recorded*, and the state the argument leaned on is the one §3.3 forbids as SI-7. With it removed the discriminator decides alone — a hash miss instructs nothing — and §3.3 now records the sparse lookup as the counter-rule's **worked case**, which is worth more than a fourth absence type because the pattern is now easy to cargo-cult. *(Proposed default was A.)* |
| **STX-Q2** | `get_tx_unlock_time` (STX-1, transitively callerless): **A** — not ported; the C++ method and its dead caller die with the C++ store at DRS-E* (`PDM-Q-S0`); **B** — delete both now, #782's shape, own PR. | **A — RULED 2026-09-19.** Unlike #782 this is not a served surface — `get_output_key_mask_unlocked` has no RPC route and no caller — so there is no disclosure to close and no schedule to distrust; and no daemon is built until the redb conversion completes (steering item 1), so the deletion's timing buys nothing before then. The field's fate is census U-2's, and no S-TX projection carries it (STX-9, §3.5). Reopen to B if a route to `get_output_key_mask_unlocked` is found. |
| **STX-Q3** | `for_all_transactions` (STX-3): **A** — not ported; **B** — **T6** `tx_locations(range)`, a bounded walk over `tx_indices` in its key order yielding `(TxHash, TxLocation)` — the table's own projection, no join (round 3; a `TxHeader` join and an id-ordered walk are §3.2's coupled reopen criterion). | **B — RULED 2026-09-19, on completeness grounds; the question to E2 is the row shape, and it does not block the cut.** The morning's first ruling had made this a yes/no for E2; the maintainer re-ruled it the same day because the first default had applied rule 22 to the wrong category (STX-10): rule 22 withholds a *feature* nobody asked for, and a range read over a keyed, dense table is part of what makes the table a table — the store already ships `keyed.rs`' generic `range`, `read.rs`' `range_at` and S-CHAIN-R's clamped ranges, so S-TX would be the one surface walkable in principle and not in practice. None of the three cases that do withhold an iterator apply (order is ruled and dense; unboundedness argues for a *bounded* range, which T6 is; gating is an RPC concern). **The question to E2 was answered by #788 before E2 had to answer it** (round 3): DRS-E2's pre-flight rules the redb-side reads as `block_info` hashes + `key_images` + the root into `digest_v0` (#788 §3.1, RD-F5) — E2 projects no tx table, so there is no row shape to correct and no consumer to name. T6 is therefore the table's own projection (`tx_locations`), not a joined `TxHeader`; the join, the id-ordered alternative and the reverse index are one coupled reopen criterion (§3.2: a later E2 increment names row and order *together*, because id order keys on id and needs the reverse index while hash order grows this walk a join). `unlock_time` is in no projection (STX-9 as restated); if a reopened row ever needs it, it arrives behind the comparator-owned `comparator-parity` cfg feature (§3.4), decided before the ask. *(Proposed default was A; first ruling was "ask E2, blocking".)* |
| **STX-Q4** | T3's `pruned` bytes: **A** — eager (the record carries the blob); **B** — a separate `tx_pruned(TxStorageId)` read, T3 carrying only the index and hash rows. | **A — RULED 2026-09-19, with a coupling to Q3.** For the **point read** eager is right: every T3 caller in §2.1 wants the bytes (`get_pruned_tx_blob`, `get_transactions`, the FFI seam); the one caller that wants existence alone (`have_tx`) has T1; B would be SOK-Q4's identity hop one read later. **The walk (T6, Q3 B) does not reuse `TxRecord`:** a pass over every transaction with an eager record materialises every pruned blob in sequence — fine for a point read, expensive for a bounded scan — so T6 yields `(TxHash, TxLocation)`, blob-free (round 3 dropped the `TxHeader` join once #788 showed it had no consumer; §3.2). That is *not* the DTO hop, because the two reads have genuinely different shapes rather than one shape renamed. §3.4 carries both types. |

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md` §7 S-TX row → LANDED with the read list; §3.6.4
  gains the tx reads; §7.7 gains the read-side statement of legs (i)–(iii)
  (T3's SI-7, T4's `Discarded`).
- `IMPLEMENTATION_INDEX.md`: `STX-` row (this PR registers it), the
  `DRS-*` lead cell, the document row; stamp moves with the increment.
- `CHANGELOG.md` Unreleased / Daemon chain store: one entry (API-visible
  reads; no layout change).
- This document: banner flips to *landed* at the increment PR;
  archive-or-contract per index §8 when S-CURVE's pre-flight has read it.
- No new FOLLOWUPS row for `TxIndex.unlock_time`: its fate is census U-2's
  and the reconciliation's §6 finding 2, already open; this surface's
  line-local note there says S-TX projects the field nowhere and that
  S-OUT-KI's `RecordedOutput.unlock_time` — the one Rust projection —
  is removed by this increment's commit 1 (corrected on round 3; the
  round-2 note had claimed no projection existed).
- The DRS lane-coordination log: the E2 ask closed as answered by #788,
  with the reopen criterion pointing at §3.2 (done by this PR).

---

## 11. Decision log

| Date | Entry |
|---|---|
| 2026-09-19 | **PR #800 review round 1 (Copilot: 3 open; 3 taken, 0 refuted).** Two were one defect in the bound-first discipline: after the count admitted an id, T4 read the hash row and T5 read `tx_outputs` without checking that the **primary** `txs_pruned[id]` existed — so a hole in the primary below the count, with side rows still present, was served as a recorded transaction instead of SI-9. Fixed structurally: one admission step, `tx_reads::admit` (bound, then primary), used by both by-id reads; S-OUT-KI's O1 had the same gap against `output_txs` and takes the same check in the same commit (same class, same file family, disclosed here rather than deferred). Both new tests observed red without the checks. The third: `RecordedOutput`'s doc still described LMDB's `output_data_t` *with* `unlock_time`; corrected. |
| 2026-09-19 | **Increment landed** (cut from `dev` `fbc92287a`, the day the plan merged). Three commits (§7's disclosed regrouping): the STX-9 gate + `RecordedOutput.unlock_time` removal; T1–T6 on `store/tx_reads.rs` with `read.rs` delegating; this docs commit. What landed matches §3 as ruled through round 4, with three implementation facts worth naming: (1) `SegmentBytes<K: BlobKind>` is one newtype per segment through the marker the table is already typed by — `RawBlockBytes`' discipline (no slice view, `into_wire_bytes` the one way out) plus a `compile_fail` that a pruned segment cannot be handed where a prunable one is expected; `Clone`/`PartialEq`/`Eq` are hand-written so the zero-sized marker owes no bounds. (2) T6 lives on `ReadSnapshot` directly rather than in the shared body: the trait's borrowed table cannot outlive the function, and the snapshot's owned table gives the `'static` range; the projection `TxIndex → TxLocation` and the key helper are the body's, so the field is dropped in one place. (3) The pqc pair is checked pairwise (leg ii), naming whichever table is the one missing. `TxIndex` has no non-canonical same-width encoding, so the "undecodable row" arm of T6 is exercised by type, not by a planted row. T2's doc names #799's shard predicate as the consumer standing on the dense count. `cargo test -p shekyl-chain-store` 270 + 13 doctests; clippy `-D warnings`; every store gate green, the new one observed red on the pre-change tree at `output_reads.rs:72`. |
| 2026-09-19 | **PR #786 review round 4 (Copilot: 10 open; 10 taken, 0 refuted).** Contract: T4 returns `AtIndex<Prunable>` — `TxStorageId` has a public `from_raw`, so "the argument type carries already-resolved" was not true and an out-of-range id must be `BeyondCount`, not SI-7 (§3.2, §3.3); T6 takes `Range<TxHash>`, not `impl RangeBounds` — the type is the bound, the unbounded call does not compile (§3.2); two stale `TxHeader` mentions (Q4's row, the index) brought to `tx_locations`. Gate (`check_test_only_features.py`): **feature forwarding** (`x = ["owner/feat"]` in a consumer's own feature table) now counts as an enablement in all three limbs — it had let a forwarded second consumer past the sole-enabler check and hidden cross-crate features from the trigger; counting it raised the grandfathered set from twelve to fifteen and exposed a second normal-edge path for `shekyl-crypto-pq/test-utils` (via `shekyl-p-serve`'s `test-signer`, F-7 §4); the grandfather list now records each crate's **exact hit set** (feature, consumer, kind) so a new feature or enabler on a listed crate is red and a vanished hit is red until deleted (owner-keyed exemption would have covered both silently); selftest 6 + 4 + 10. Rule 95: the F-7 audit the FOLLOWUPS row had grown into moves to its own record, `F7_TEST_ONLY_FFI_EXPORTS.md`; both rows are one sentence, a link and a target (F-7's original row had no `Target:` — fixed). The PR's description stops saying "docs only": it ships a gate and the workflow runs it. |
| 2026-09-19 | **PR #786 review round 3 (Copilot: 2 open; 2 taken, 0 refuted), the maintainer's three refinements, and #788's answer.** Two contract errors caught before the cut: (1) T1 returned the stored `TxIndex`, which carries `unlock_time` — STX-9's claim was false through the front door; T1 now returns `TxLocation { id, height }`, written up as *not* the identity-DTO hop (it drops a field, the opposite of renaming one) so rule 27 applied correctly does not reach the wrong conclusion. (2) T6 as an id-ordered header walk over `txs_pruned` was not implementable at v6 — `height` lives in `tx_indices` keyed by hash and nothing maps `tx_id → hash`; T6 is now `tx_locations` over `tx_indices` in its own key order, the reverse index rejected-now-reopen-if. STX-9's invariant restated narrowly enough to check — *no public read type under `store/` has an `unlock_time` field* — with a grep-shaped gate in commit 1; running it today is red on S-OUT-KI's `RecordedOutput.unlock_time` (`output_reads.rs:72`), landed by this lane one increment ago with no consumer, which commit 1 removes; the U-2 UPDATE that said "projects it on no read" was therefore false and is corrected. The E2 ask's two halves (row shape, order) are coupled and are now one reopen criterion — and **#788 answered it**: E2's redb-side reads are `block_info` hashes + `key_images` + root into `digest_v0`; it projects no tx table, so the `TxHeader` join (2N random reads against one scan; fine for a comparator, wrong for anything else) is not built and no consumer is named. Also this round: `dev` drift brought `shekyl-chain-rules/harness` (E6 slice 2 F11), the first cross-crate feature declared after the fourth limb landed; the limb fired in CI as designed, and the crate joined `GOVERNED_OWNERS` with `harness` as a `TEST_ONLY` row — its own manifest's sentence, as a gate. |
| 2026-09-19 | **Q3 RE-RULED the same morning (maintainer, on PR #786): the walk lands; the ask to E2 is the row shape and is non-blocking.** The first ruling ("ask E2 yes/no, do not cut until answered") stood on rule 22, and rule 22 had been applied to the wrong category — it forbids a callee with no caller, a *feature*; a range read over a keyed dense table is part of what makes the table a table, and the store already treats it so (`keyed.rs` `range`, `read.rs` `range_at`, S-CHAIN-R's clamped ranges, SOK-Q1's `range(..).next_back()`). The three legitimate grounds for withholding an iterator — unpublished order, unbounded hot path, gated enumeration — were checked and none apply (STX-10). Q4's coupling is now the only live design constraint: headers on the walk, blob on the point read, two shapes because the reads differ. **And `unlock_time` leaves both projections** (STX-9): STX-1 found it transitively callerless, its fate is owned by census U-2 / CSR §6 finding 2, and putting it in the walk's row would be how a dead field acquires a second reason to exist on a row E2 then depends on. Offered row: `TxHeader { id, height, prunable_hash, pqc_auth_hash }`. **Follow-up the same morning:** the exception's expiry gets a mechanism — a transitional field behind a *marker* would outlive the comparator and sit, the marker becoming a comment about why; behind a **comparator-owned cfg feature** (`comparator-parity`) it cannot compile once the comparator retires and deletes the feature. Decided before E2 answers, so the field arrives with its expiry built in whatever the answer prompts. **Then the last manual link went structural too:** the "declared with no enabler ⇒ delete" falsifier moved from a documented `rg` into `check_test_only_features.py` as a `CONSUMER_OWNED` limb (self-expiry when the enabler leaves the workspace; sole-enabler; no-enabler; owner-side), with a `--selftest` on synthetic metadata so the limb has a subject while its registry is empty. The same escalation as `compile_fail` → `cargo tree` and holder-grep → rejection-test: the shape was right, the gate is what makes it true. |
| 2026-09-19 | **Round 1 RULED (maintainer, on PR #786).** Q1 **B** — the proposed A rested on coherence with a three-arm T4 whose first arm is *not recorded*; §3.3 defines T4 as two arms and forbids the third as SI-7, so the argument refuted itself and the discriminator alone decides: `Option`, recorded in §3.3 as the counter-rule's worked case (the documented *here it does not apply* being what stops the pattern being cargo-culted). Q2 **A** — transitively callerless, no route, no served surface, no daemon built before the conversion completes; the reopening criterion is checkable, which is what separates it from a deferral. Q3 **asked of E2 this round, not defaulted** — E2's comparator is the per-table diff (DRS §7.6), and a tx walk is close to a structural requirement of it; defaulting to A would land the iterator as a retrofit against a frozen read set. Put to the E2 lane in the coordination log; B lands in commit 3 with E2 named if yes. Q4 **A** with the coupling written into both rows: eager for the point read; if Q3 is B the walk yields `TxHeader` without the blob — a different shape, not the DTO hop. Re-based on `090f2e8f2` (#784: SOK-10 closed by deletion; the archived S-OUT-KI banner and the index SOK row say so). |
| 2026-09-19 | **Round 0 executed at `8b48f574c`.** Eight findings, four questions with defaults. Steering recorded as premises: #784 is not in `dev` and is not a dependency (S-CHAIN-R is, and is in); the prune-shaped methods are the archival good's read path per `PDM-Q6`, not `PDM-Q7` residue — stated in §2.3 so the next lane inherits the right conclusion; `get_tx_unlock_time` and `for_all_transactions` censused before disposition (STX-1: transitively callerless; STX-3: one tool + one callerless wrapper). Three absence shapes on one surface, each justified against the discriminator rather than copied (§3.3, STX-7). `DRS_E1_SOUT_KI.md` archived by this PR (its §10 condition — this pre-flight has read it — is met). |

# LMDB Write Atomicity Audit

**Date:** 2026-09-05 (DRS-P0b; supersedes the April 2026 audit in place);
§9's register extended 2026-09-08 by **DRS-P0c** (rows DRS-W12 through DRS-W15);
DRS-W12 and DRS-W15 regraded 2026-09-09; §11 digest ledger added
2026-09-11 by **DRS-P0e**; §12 accumulator class freeze and §10's
`Accumulator class` column added 2026-09-12 by **DRS-0 slice A**
**Pin:** five, and each row states which it was verified against. **P0b rows
(DRS-W1 through DRS-W11) and §§0–8, §10: `dev` `2dba46537`. P0c rows
(DRS-W12 through DRS-W15) as first written: `dev` `14aa42074`. The 2026-09-09
regrade evidence in the DRS-W12 and DRS-W15 subsections — the `hardfork.cpp`
and `blockchain.cpp` call-graph and window-length citations: `dev`
`3497b8a78`. P0e's §11 ledger and §10's `Digest v0` column — the
digest walker's accessor mapping and the per-table divergence test: `dev`
`eb1b60198`. DRS-0 slice A's §12 and §10's `Accumulator class` column —
the delete-path falsifier run, the `compare_hash32` characterisation and
DRS-W16: `dev` `ba4b3c73a`.** Line citations are *records-was*
against the pin they name, not against `HEAD`; they are expected to drift
and must not be "corrected" to a later tree. Two eras are safe only while
both are declared — an undeclared second era is what put three citations on
code they did not describe (fixed 2026-09-08, and the reason this line now
names shas per row-set rather than one).
**Scope:** every `BlockchainLMDB` write path at the pin: block connect, block
pop, the transaction pool, alt blocks, the three prunes, and the store
lifecycle (`open()`, `reset()`, `migrate()`). One coverage row per `SHEKYL_LMDB_TABLES` entry. Counts here
are **gate-checked, not free-standing**: where a figure is stated (§10's
row count) the schema-coverage gate compares it against the macro's
length in the same run that checks the rows both ways, so a drifted
literal fails CI rather than misleading a reader. Derived figures that
no gate can check are written as descriptions rather than numbers.
**Goal:** confirm each logical mutation is fully contained in a single LMDB
transaction with no partial-commit risk — and record, for the redb store's
specification, every convention this layer keeps only in code (DRS-P0b
transcriptions A-2 / A-4 / A-6, and the §6.6 read-after-write edge set).

<!-- claim-audit: series DRS-W -->
<!-- claim-audit: series R -->
<!-- claim-audit: range DRS-W -->
<!-- claim-audit: sections -->
<!-- claim-audit: numbered -->
<!-- claim-audit: counts -->
<!-- claim-audit: citations -->

Findings are **recorded, never fixed here** (P0c RECORD-AND-SPECIFY,
countermand 2026-09-01): a defect in this layer becomes a wart row for the
Rust store unless it is S-graded, which stops the lane and goes to Rick.
This pass found **no S-graded defect**; the findings register is §9.

---

## 0. Provenance — what happened to the April 2026 audit

The previous audit in this file (born `a17ccd0c81`, 2026-04-07; 183 lines)
was graded **STALE** in `DAEMON_REDB_STORE.md`'s oracles table: *PASS over a
superseded write set*. P0b's grounding measured how superseded, by set
difference against the April tree (era-calibrated: at that pin, table names
were `const char* const LMDB_*` constants in `db_lmdb.cpp`, not the X-macro
— and its 51 raw `lmdb_db_open` hits close only as 1 definition + 34
symbol-keyed production opens over **29 tables** + 5 migration re-opens + 16
*quoted-literal* opens of Monero-lineage legacy names in since-deleted
`migrate_*` code; production opens were symbol-keyed while migration opens
were quoted, so a single extraction over the raw hits silently mixes live
tables with dead migration code):

- **April 29 → Round-2 pin 46**: +19 tables (14 `archival_*`, `block_burn`,
  `block_pending_additions`, `curve_tree_roots`, `leaf_to_output`,
  `output_to_leaf`), −2 (`staker_accrual`, `staker_claims`, deleted with the
  claim-era wire). **Round-2 → this pin: +3** (both attestation-witness
  tables, `archival_settlement`), −0. Both directions of each delta measured.
- **22 of the 49 declared tables post-date the April audit** (declared,
  not live: DRS-W5 and §10 record that a writable `open()` deletes
  `hf_starting_heights`, so the running store holds 48) and had zero
  atomicity coverage until this rewrite. The April PASS was doing work it
  was never entitled to do: a verdict over a store that is now half tables
  it never saw, while several of its covered subjects are dead. A seal is
  not coverage.

Per-subject disposition of the April sections (records-was; the old verdicts
were true of their tree):

| April subject | Disposition at this pin |
| --- | --- |
| Block connect / block pop core | Covered then; **re-audited below** — the paths have since grown the archival journal hooks, the witness store, and the epoch-close/prune machinery |
| Staking-Specific Write Paths (accrual, claim pool restore, `txin_stake_claim`) | **Dead** — deleted with the claim-era wire; `txin_stake_claim` and `staker_pool_balance` have zero occurrences in `src/` |
| `get_relayable_transactions` missing-commit fix (Dandelion++ timestamps) | **Alive, fix intact** — the function stands at `tx_pool.cpp:1130` and `lock.commit()` at `:1224` precedes the `m_next_check` update; stem *selection* moved to Rust (`shekyl-relay-privacy`), the txpool bookkeeping and its transaction discipline stayed C++ |
| `pop_block_from_blockchain` staker-accrual `db_wtxn_guard` fix | **The claim-era write died; the guard survives, load-bearing for a successor** — `db_wtxn_guard` at `blockchain.cpp:896` now wraps the post-pop **burn-total reversal** (`get_block_burn` → `set_total_burned`), preserving exactly the defensive shape the April fix added; see §3 and DRS-W6 |
| `hf_versions` not cleaned on pop | **Alive, unchanged — re-verified by the write-site census**: the table's only writers are `set_hard_fork_version` and `drop_hard_fork_info`; no pop-side remove exists among the 135 enumerated sites. Settled 2026-09-08 as **DRS-W15** (see §9) |
| FCMP++ curve tree (grow/trim/pending) | Covered then; re-audited below — the family has since gained `curve_tree_roots`, both output↔leaf maps, `block_pending_additions`, and the segment-freeze hook |
| `LockedTXN` nesting + silent-commit-failure notes | Still accurate; restated in §4 with a re-enumerated site census |

---

## 1. Transaction mechanisms at the pin

The April frame still holds, with two additions (the last two rows):

| Mechanism | Scope | When |
| --- | --- | --- |
| **Batch** (`m_write_batch_txn` via `batch_start`/`batch_stop`) | Groups multiple blocks into one LMDB txn | Block ingestion from P2P and sync |
| **Block write guard** (`block_wtxn_start`/`block_wtxn_stop`) | Single write txn, or no-op when batch active | Genesis init, standalone pop, tests |
| **`TXN_BLOCK_PREFIX`** (defined `db_lmdb.cpp:2049`) | Joins active batch/write txn, or opens its own | Sole remaining user: `set_hard_fork_version` (`:4697`) |
| **`db_wtxn_guard`** | No-op under an active batch, else own txn | Defensive wrapping of standalone write callers |
| **`LockedTXN`** (txpool) | Batch join with commit/abort; §4 | Txpool mutations — and one deliberate read-snapshot user, §4 |
| **`prune_tx_data`'s txn swap** (`:10144`) | Begins its **own** write txn and RAII-swaps it into `m_write_txn` (`write_txn_restorer`), restoring the saved pointer on exit | The standalone tx-data prune only — a mechanism the April audit predates |

When a batch is active, everything below that says "the block's transaction"
means the batch transaction: all writes for all blocks in the batch commit
or abort together at `batch_stop`.

## 2. Block connect (`BlockchainDB::add_block`, `blockchain_db.cpp:435`)

Ordering at the pin (the funnel every connected block traverses):

1. `add_transaction` for the miner tx and each block tx — tx data, indices,
   outputs, spent keys, **and the per-vin archival journal writes** (bond
   record mutations with their unbond/rebond/holdings-update pre-image
   journals, emission-claim journal, serve-credit bits) ride tx-connect.
2. The FCMP++ curve-tree block, in this order — the sequence is
   load-bearing, so it is transcribed as the code has it rather than
   summarised:
   1. **`drain_pending_tree_leaves`** (`:625`) — matured leaves only, each
      entry auto-journalled for `pop_block`, writing the output↔leaf
      mappings as tree positions are assigned;
   2. **`collect_outputs`** for the miner tx then each tx (`:629`–`:631`),
      which is what writes *this* block's `pending_tree_leaves` and
      `block_pending_additions` rows (`:617`–`:618`);
   3. **`grow_curve_tree`** (`:635`), gated on a nonzero new-output count;
   4. the **segment-freeze connect hook** at `prev_height + 1`, after grow
      so a segment completed at this height is countable by an epoch close
      at the same height.

   **Draining before collecting is the deferral**: a block's own outputs
   enter the pending table *after* that block's drain has run, so they
   cannot reach the tree in the block that created them. The maturity
   comparison and the ordering enforce the same rule, and a port that
   keeps only the comparison would admit an output a block early. The
   in-code invariant (`:491`) covers all four steps: *pending, drain,
   output↔leaf maps, `block_pending_additions`, and `curve_tree_*` tables
   MUST be mutated within the same `m_write_txn` as the block add — any
   partial commit here is a consensus split.*
3. Attestation witness store, keyed `archival_attestation_witness_key(prev_height)`.
4. `BlockchainLMDB::add_block` — block blob, `block_info`, `block_heights`.
5. **`m_hardfork->add(blk, prev_height)`** (`blockchain_db.cpp:683`) —
   immediately after the block row and before the accrual. It is a state
   transition, not bookkeeping: `HardFork::add` calls
   `db.set_hard_fork_version(height, …)` (`hardfork.cpp:141`), which writes
   `hf_versions` through `TXN_BLOCK_PREFIX` and so joins this block's
   transaction (§1). A port that loses this step loses the fork-version row
   for the height it belongs to.
6. The budget-accrual row at `prev_height` (F-B1a: written inside this
   funnel, before the hooks, not by `blockchain.cpp` after the fact).
7. `process_archival_slash_at_height(prev_height + 1)`.
8. `process_archival_epoch_close_at_height(prev_height + 1)` — which, at an
   epoch boundary, also runs the archival retention prune (§5a) in the same
   transaction.

Every step writes through `*m_write_txn` / `m_wcursors` under the block's
transaction; `set_hard_fork_version` joins it via `TXN_BLOCK_PREFIX`. No
`mdb_txn_commit` occurs mid-block, and an exception raised **inside** the
funnel leaves the transaction uncommitted: `handle_block_to_main_chain`
wraps `m_db->add_block` in a try whose two catches set
`m_batch_success = false` (`blockchain.cpp:6423`, `:6432`), and
`cleanup_handle_incoming_blocks` reads that flag to choose `batch_abort()`
over `batch_stop()` (`:6821`).

**Two writes run after that try block, and the flag does not cover them.**
The connect-side burn pair — `add_block_burn`, then the `total_burned`
increment (`:6425`–`:6437`) — is core-layer and post-funnel, the mirror of
the pop-side pair in §3. Between them sits a real partial-commit window: if
`add_block_burn` succeeds and the `get_total_burned`/`set_total_burned`
pair then throws (any LMDB-level write failure — a full map, a disk error),
the exception unwinds to `add_new_block`'s outer
`catch (const std::exception&)`, which sets `bvc.m_verifivation_failed` and
returns **without touching `m_batch_success`**. The flag is still true, so
`cleanup_handle_incoming_blocks` calls `batch_stop()` and **commits the
block, its transactions, and the `block_burn` row while the aggregate they
belong to is not updated** (**DRS-W9**).

That is a partial commit of one logical unit, so this section does not
claim an unconditional PASS — and the correction reaches further than this
section: the surviving `total_burned` is too **low**, the direction §9's
DRS-W7 graded unreachable. It is reachable, by this path.

**Verdict: PASS for the funnel** — `BlockchainDB::add_block` is one
transaction per block (or per batch), including every archival journal
write and the boundary-epoch prune, and an in-funnel failure aborts the
batch. **The post-funnel burn pair is DRS-W9**, and it converges with
DRS-W6 on a single specification: the burn bookkeeping is core-layer on
*both* sides, so neither the connect increment nor the pop reversal
inherits the funnel's failure semantics. In the Rust store both belong
**inside** the funnel, where the block's transaction and its failure
handling already are.

## 3. Block pop (`BlockchainDB::pop_block`, `blockchain_db.cpp:717`)

One funnel, one write transaction (`block_wtxn` unless a batch is active),
entered only above the prune-watermark floor (C2-R1b-Q1c: the floor comes
from the prune's own persisted receipt, never the tip). The revert sequence
mirrors connect in reverse; its height conventions and ordering constraints
are the A-2/A-4 transcriptions (§7, §8). All removals — journal-driven
curve-tree trim included — ride the same transaction; the witness row is
dropped rather than parked (a hash-keyed parked row would be unreachable to
the height-keyed prune and leak; reorg survival is explicit via the
read-before-pop handoff to `handle_alternative_block`).

A note the two misclassifications of this pass earned (D++ and the row
below): a two-valued provenance column — dead or alive — cannot express a
subject that was **replaced in place**. The guard here outlived its
original write and wraps a successor; the D++ fix outlived its lane and
kept its C++ tenancy. Both times the category set, not the provenance,
was what was wrong.

Two burn writes live **outside** the funnel, at the core layer: the post-pop
**burn-total reversal** and the `block_burn` row removal
(`Blockchain::pop_block_from_blockchain`, `blockchain.cpp:896`–`:905`),
which read `block_burn` for the popped height, lower the `total_burned`
properties scalar, and drop the row — under `db_wtxn_guard`, the guard the
April fix introduced for the (now dead) staker-accrual reversal and which
this successor write inherited. That placement has **two** consequences,
and the second is the sharper one:

- **A batchless core-path caller pops in two transactions.** Under a batch
  the guard is a no-op and the reversal joins the pop's transaction;
  standalone it is a second transaction after the pop's commit.
- **A caller that pops through the DB funnel skips both writes entirely**,
  because neither lives in `BlockchainDB::pop_block`. This is not
  hypothetical: `blockchain_import --pop-blocks` calls
  `get_db().pop_block(...)` directly, and says why in its own comment —
  *"pop_block_from_blockchain() is private, so call directly through db"*
  (`blockchain_import.cpp:92`–`:119`, driven from `:779`–`:785`). Since the
  connect-side increment is also core-layer
  (`handle_block_to_main_chain`, `:6436`), a database whose blocks were
  added through the verifying path and popped through that tool keeps a
  `total_burned` that counts burns the chain no longer contains, plus a
  `block_burn` row for a height that no longer exists. Deterministically,
  on a normal run of a shipped utility — no crash required.

Both are **DRS-W6**. The grade is unchanged and still rests on the
five-site consumer census (§9): the scalar is read by an RPC readout and by
two slash guards that abort on arithmetic violation, and an *inflated*
value satisfies both guards with headroom, so nothing halts and no
consensus arithmetic consumes it. What changes is reachability — this is a
live path, not a crash window — and the stale `block_burn` row is
self-healing only if that height is re-added, since connect overwrites it.

**Verdict: PASS for the funnel itself** — `BlockchainDB::pop_block` is one
transaction and the pop-side invariant comment (`:863`) states the same
consensus-split consequence as connect's. The burn pair's placement outside
it is DRS-W6, and the specification it implies for the Rust store is plain:
**derived-total reversal belongs in the pop funnel**, so that popping
through the store cannot silently mean something different from popping
through the node.

## 4. Transaction pool (`tx_pool.cpp`)

Re-enumerated at the pin: **14 `LockedTXN` constructions, 13
`lock.commit()` sites.** The sole non-committing construction is
`get_transaction_info` (`:913`) — a `const`, read-only path where the
`LockedTXN` provides a consistent snapshot and the destructor's abort
discards no writes. **That imbalance is the deliberate baseline**: any
future construction without a commit on some path is exactly the April
defect class (`get_relayable_transactions`, fixed then, fix verified intact
at `:1224`), so re-run this census — constructions vs commits, then walk
the odd ones out — whenever the file changes shape.

April's still-true notes, restated: `LockedTXN` nests by no-op'ing under an
active batch (writes piggyback on the outer transaction), and
`LockedTXN::commit` swallows `batch_stop` exceptions — commit failures are
silent to callers. The latter is **wart row DRS-W2** (§9) for the Rust store:
a store API where commit cannot fail silently.

**Verdict: PASS**, one baseline recorded, one wart carried.

## 5. Alt blocks and the detached witness table

`add_alt_block` / `remove_alt_block` operate on `*m_write_txn` cursors and
require the caller's transaction (callers: `handle_alternative_block` under
the incoming-blocks batch; `switch_to_alternative_blockchain`'s removal
loop, same batch).

`drop_alt_blocks` (`:4821`) is a **separate self-transactional path**, not
a rider on anyone else's: it opens `TXN_PREFIX(0)`, which joins an active
batch when there is one and otherwise begins and commits its own
transaction, and empties both `alt_blocks` and
`archival_alt_attestation_witness` (`mdb_drop(…, del=0)`). It is not part
of `reset()`'s transaction — `Blockchain::reset_and_set_genesis_block`
calls `m_db->reset()` first, which commits, and *then*
`m_db->drop_alt_blocks()` (`blockchain.cpp:923`–`:924`) — and it has a
second live caller at core init, dropping alt blocks on startup unless
`keep_alt_blocks` is set and the DB is writable
(`cryptonote_core.cpp:655`). Each call is atomic in itself; the two
tables are emptied in one transaction, so the witness table cannot
survive the alt blocks it belongs to. The
`archival_alt_attestation_witness` table is written beside the alt block
that owns it and its rows cannot outlive that block (one table, one owner —
the alt-block lifecycle, not the height prune, bounds it).

**Verdict: PASS.**

## 5a. Retention prunes — three paths, three shapes

**Archival retention prune** (`prune_archival_epochs_before`, `:7704`):
runs *inside* the epoch-close connect hook, under the block's transaction.
The watermark receipt is written **before** the deletions, same
transaction: commit lands floor and destruction together, abort lands
neither; no pop path reverts the receipt, so the floor never retreats
(the pop funnel's entry gate reads it). Seven families pruned; the
`archival_budget` walk early-breaks on the BE-ordered key where the others
scan-and-delete — an idiom difference, not a semantic one.

**Tx-data prune** (`prune_tx_data`, `:10144`): **also checkpointed**, and
its checkpoints are the better-designed of the two. Its `while` loop takes
at most 256 heights per pass, each under a fresh transaction that is
RAII-swapped into `m_write_txn` for that pass (§1's last mechanism), and
each pass commits its deletions **together with its own resumption
anchor** — `write_tx_prune_next_block_height(wtxn, h)` rides the same
transaction as the work it describes (`:10179`–`:10200`, `:10283`–`:10288`).
So the crash window here leaves earlier batches committed, exactly as the
stripe prune does, but the persisted next-height means the resumed run
neither repeats nor skips: the anchor cannot disagree with the data,
because they commit or abort together. (An anchor written in a *separate*
transaction from its work is the shape this one avoids — compare the
receipt-before-destruction ordering in the archival prune above, which
achieves the same property the other way round.) v11 retention semantics:
the depth pass keeps `txs_prunable_hash` and `txs_pqc_auths` — the
pruned-txid operands — when it drops the prunable body.

**Stripe prune** (`prune_worker`, `:2320`): the one write path in this
store that is **deliberately multi-transaction**. It opens its own
transaction, and every 4096 deletions it *commits and reopens* — re-opening
each cursor, and in the tx-indices arm re-anchoring that cursor with
`MDB_GET_BOTH` (`:2447`–`:2463`, `:2552`–`:2577`). A crash mid-run
therefore leaves the store **partially pruned**, with the committed
checkpoints kept.

That is a valid state rather than a corrupt one, and the reasons are worth
stating because they are exactly the reasons the block funnel cannot be
written this way:

- the **pruning seed is persisted in the first transaction**, before any
  deletion (`:2365`), so a resumed run derives the same stripe and prunes
  the same set — the work is deterministic across the interruption;
- deletion here is **monotonic** — a dropped prunable body stays dropped,
  and re-running the pass simply continues; there is no reversal to get
  half-applied;
- pruning is **local storage policy, not consensus state**. A partially
  pruned node is a node that holds more data than it eventually will,
  which no rule reads.

Contrast with connect and pop (§2/§3), where a partial commit is a
consensus split: there the multi-transaction shape is forbidden, here it is
the design.

**Verdict: PASS** on all three — **one atomic, two deliberately
checkpointed**, each checkpointed one with a resumable, consensus-neutral
failure window and a persisted anchor that commits with its own work. Only
the archival retention prune is a single transaction, and only because it
rides the block's. The receipt-before-destruction edge is R-2 in the RAW
set (§6); the depth prune's anchor-with-batch is R-6.

## 5b. Store lifecycle — `open()`, `reset()`, `migrate()`

`open()` (`:1537`) is a write path, and the audit's completeness claim
owes it a verdict. One transaction (`mdb_txn_begin` at `:1651`, read-only
flagged when the store is) does all of it: `lmdb_db_open(… MDB_CREATE)`
for every name in the macro list — creating a missing named DB is itself
a write to the unnamed main DB — plus the unconditional
`mdb_drop(m_hf_starting_heights, 1)` on any writable open (DRS-W5) and,
on an empty store, the `properties` version seed. It has **three exits**,
and they do not agree about what a failed open leaves behind:

- **newer DB than the binary** (`db_version > VERSION`) — `txn.abort()`,
  return: nothing is written, which is right;
- **empty or current DB** — seed the version if absent, `txn.commit()` at
  the end: one transaction, all or nothing;
- **older DB** (`db_version < VERSION`) — **`txn.commit()` *first*, then
  `migrate(db_version)`** (`:1819`-ff). Since `migrate()` refuses loudly
  pre-genesis (below), the open fails — but the table creations and the
  `hf_starting_heights` drop are **already committed**. A refusing open
  mutates the store's structure before refusing (**DRS-W10**).

The consequence today is small, because the refusal's own remedy is to
delete the datadir and resync, so nothing survives to be inconsistent.
It is recorded because the shape does not survive contact with a store
that *can* migrate: an open that fails should leave the store as it found
it.

**Verdict: PASS on atomicity** — every exit is a single transaction,
committed or aborted as a whole; DRS-W10 is about *which* exit commits,
not about a partial one.


`reset()` (`:1911`): wipes by **enumerating** the environment's named
tables (main-DB keys are table names) and dropping every one not in the
keep predicate — `is_chain_reset_keep_table` (`:404`) keeps exactly
`txpool_meta` and `txpool_blob` (mempool lifecycle is `tx_memory_pool`'s;
reset has never touched it) — then re-seeds only the version row, in one
transaction. The 2026-08-07 finding recorded in FOLLOWUPS (*"drops an
INCOMPLETE table set — 29 of 48 tables not dropped"*) described the
hand-written drop list this enumeration **replaced the same day**
(`190fd73a65`); the row was never closed and is closed by this PR. A
hand-written drop list cannot go stale again — there isn't one.

`migrate()` (`:10295`): **zero writes** — pre-genesis posture, refuse
loudly and direct to resync; the Monero-era `migrate_0_1..5_6` ladder
(whose quoted-literal opens dominated the April file's raw hit count) is
deleted.

**Verdict: PASS** (`reset()`); `migrate()` is a non-write path by design,
and `open()` carries DRS-W10 above.

## 5c. Standalone write paths outside any block

Seven writers run under neither a block funnel nor a prune — four
production paths, one nettype-fenced RPC injector, and two test-support
seams — and the coverage matrix routes to this section:

**`set_settlement_epoch_blocks_pin`** (`:5013`): an init-time write from
`Blockchain::init` (`blockchain.cpp:652`), guarded by `is_read_only()` so an
unpinned read-only datadir stays unpinned rather than crashing on the put.
It manages its own short transaction — begin, one `mdb_put` into
`properties`, explicit `commit()` — because it runs before any block-add
transaction exists. A single-put transaction has nothing to be partial
about. **Verdict: PASS.**

**`correct_block_cumulative_difficulties`** (`:3034`): brackets its own
`block_wtxn_start()`/`block_wtxn_stop()` and rewrites `block_info` rows
in-place (`MDB_CURRENT`) across a height range. Atomicity holds — nothing
commits until `block_wtxn_stop()`, so an exception anywhere in the loop
leaves the whole correction unapplied rather than half-applied. Two
observations belong on the record:

- **the exception paths are asymmetric, and the second one poisons the
  store.** The size-mismatch guard aborts explicitly
  (`block_wtxn_abort()`) before throwing; the loop's own throws
  (`BLOCK_DNE` on a missing row, `DB_ERROR` on the put) do not — and
  there is no stack owner to clean up after them. `block_wtxn_start()`
  **heap-allocates** the transaction into the member pointer
  (`m_write_txn = new mdb_txn_safe()`, `:4311`); only
  `block_wtxn_stop()` and `block_wtxn_abort()` delete it and clear the
  member (`:4344`, `:4361`). A throw between them bypasses both, so the
  `mdb_txn_safe` is never destroyed, the LMDB write transaction stays
  **live**, and `m_write_txn` stays non-null — which makes the *next*
  `block_wtxn_start()` throw `DB_ERROR_TXN_START` (*"Attempted to start
  new write txn when write txn already exists"*, `:4307`). So the
  failure is not "a transaction left open until unwind"; it is a
  poisoned writer that fails every subsequent block write until the
  process restarts (**DRS-W8**). Still no partial commit — nothing
  commits — but the two failure modes leave the store in materially
  different states;
- **it has no production caller.** The symbol resolves only to the
  interface declaration, the `testdb` stub, and this definition — the same
  unwired shape the census recorded for `set_archival_settlement`
  (CEN-L8). An unwired writer's atomicity is a claim about code nobody
  runs, which is worth knowing before the Rust store reproduces it.

**`drop_hard_fork_info`** (`:4675`): intended to delete **both** hard-fork
tables under one `TXN_PREFIX(0)`. It cannot, and the reason is DRS-W5
reaching further than the table count. LMDB's `del=1` does not only delete
the database — it **closes the handle**: the header says so ("delete it
from the environment and close the DB handle",
`liblmdb/lmdb.h:1216`–`:1225`) and the implementation marks the slot
`DB_STALE` and calls `mdb_dbi_close` (`mdb.c:10970`–`:10973`). Every
writable `open()` already does exactly that to `m_hf_starting_heights`
(`:1779`), so by the time this function runs, its first argument is a
handle LMDB has closed. The first `mdb_drop` therefore fails and the
function throws (`:4683`) **before reaching the `hf_versions` drop**:
`blockchain_import --drop-hard-fork` (`blockchain_import.cpp:788`–`:793`)
cannot do the thing it exists to do (**DRS-W11**).

The transaction property still holds — nothing half-applies, because
nothing applies — but the earlier reading of this path ("both drops share
one transaction, so the pair cannot half-apply") was resting on a handle
that was already closed, which is a verdict about code that cannot run
rather than about atomicity.

One consequence is worth recording as spec-derived rather than observed:
LMDB documents that a closed handle's slot may be **reused** by a later
`mdb_dbi_open`, so a stale member handle can come to name a different
table. Nothing in this tree demonstrates that path — `drop_hard_fork_info`
throws first, and it is the only other user of the member — but "a member
handle that outlives its database" is the shape, and the Rust store's rule
follows from it: deleting a table consumes its handle, so a stale one is
unrepresentable rather than merely unused.

**Verdict: FAILS in the shipped tool**, recorded as DRS-W11; atomicity
itself is not the defect.

**`set_archival_settlement`** (`:7410`): writes one `archival_settlement`
row through the **caller's** transaction — it does not open one. It
guards the precondition first (`if (!m_write_txn) throw` — one of A-6's
22 bare `std::runtime_error` sites, §9/DRS-W1), then folds the row and
`mdb_put`s it, throwing `DB_ERROR` if the put fails. Nothing commits
here, so a failure leaves the caller's transaction to decide: under the
block funnel (§2) that means the batch aborts and the row never lands.
**Verdict: PASS**, inherited from whichever transaction the caller
holds — which is the whole content of the verdict, and the reason the
unwired status matters: **it has no production caller**
(`set_archival_settlement` is CEN-L8's census question — the row's spec
names a writer that nothing invokes, and SO-D7 puts that writer in the
slash pass rather than at epoch close). An unwired writer's atomicity is
a claim about code nobody runs, exactly as with
`correct_block_cumulative_difficulties` above; both are recorded so the
Rust store ports a *decision* rather than a dormant path.

**`Blockchain::regtest_inject_archival_serve_credit`** (`blockchain.cpp:5238`):
a live RPC-reachable writer — `on_inject_archival_serve_credit`
(`core_rpc_server.cpp:1078`) drives it — that sets one
`archival_serve_credit` bit outside connect, pop and prune. It opens its
own `db_wtxn_guard` (a no-op under a batch, its own transaction
otherwise) around a single `set_archival_serve_credit_bit`, so it is
atomic by construction, and it is **nettype-fenced**: the first thing it
does is refuse unless `m_nettype == FAKECHAIN` (`:5242`), which is
rule 71's shape — the divergence is named, loud, and confined to the
test network rather than branching consensus behaviour. **Verdict: PASS.**

**Two test-support writers** complete the write-path census and are named
here so "every write path" is a claim rather than a hope:
`put_archival_shard_segment_raw_for_corruption_test` (`:7963`) and
`remove_curve_tree_layer_chunk_for_corruption_test` (`:7994`). Both write
through the caller's `*m_write_txn` behind the standard guard, so their
atomicity is the caller's like any other write here, and both exist for a
stated reason: the production writers funnel through `encode()` and can
only ever leave the store consistent, so the malformed-row and
inconsistent-layer cases are **unreachable without a bypass** — and a
consensus rule that refuses corrupt rows cannot be tested against a store
that cannot hold one. Their callers are unit tests only
(`archival_substrate_lmdb.cpp`, `archival_segment_freeze.cpp`).

Worth one line for the port rather than a finding: they are ordinary
public methods, compiled into the production binary and documented
"test-support only; no production caller" by comment alone. That is a
convention, not a boundary. The Rust store should put such seams behind
a `#[cfg(test)]` or a capability type, so the compiler enforces what the
comment currently asserts — the same instinct as gating an unsound
surface with a type rather than a docstring.

**Verdict for §5c: PASS** (each path atomic in itself), with DRS-W8
recorded, its unwired status flagged for the census, and the
tool-reachability of `drop_hard_fork_info` noted beside §3's.

## 6. Read-after-write dependency set (RAW edges, DRS §6.6)

The §6.6 seeds re-verified, one dead, and the live set enumerated:

| # | Edge | Where | Why it must hold |
| --- | --- | --- | --- |
| R-1 | `drain_pending_tree_leaves` → `grow_curve_tree` | connect step 2 | grow consumes the drained leaf set produced earlier in the same txn; splitting them plants leaves twice or never |
| R-2 | watermark receipt → the seven `delete_*` walks | `prune_archival_epochs_before` | the pop floor must never postdate the destruction it defends against |
| R-3 | budget-accrual rows (earlier blocks) → epoch-close range-sum | `process_archival_epoch_close_at_height` | cross-**block** reads: the close of epoch E sums accrual rows written by E's whole span; the retention window dominates the reorg window and the pop floor (R-2) defends the remainder |
| R-4 | slash-journal restore → holdings-update restore | pop funnel | shared fields (`bonded_total`, `held_shard_ids`, `shard_add_epochs`); §8's partial order |
| R-5 | witness read → pop → alt-store handoff | reorg (`switch_to_alternative_blockchain`) | the reorg reads the witness *before* popping and stores it beside the alt block; pop itself deletes the row |
| R-6 | depth-prune batch deletions → `tx_prune_next_block` anchor | `prune_tx_data` | the resumption anchor commits in the same transaction as the batch it describes, so a crash cannot leave the anchor disagreeing with the data (§5a) |
| — | ~~multi-claim pool balance~~ | — | **dead seed** — the §6.6 text predates the claim-era deletion; `txin_stake_claim` has zero occurrences at the pin |

Journals were expected to add more; R-2/R-3/R-4 are those additions.

### Digest v0 read set (P0d)

Unnumbered on purpose: this document's `§6.6` citations are DRS
§6.6 (cross-document). A dotted local heading would make the
sections-leg treat those four as dangling internals.

P0b left the rest of the RAW enumeration — full read-set tracing per
write path — to P0d, "where the reads become the digest's inputs."
Those inputs, for digest v0, are the three families below, read
under **one** LMDB snapshot (`block_rtxn_start` around the walker so
nested `TXN_PREFIX_RDONLY` reuse it). A write path that mutates one
of them and does not change the digest is a coverage hole; a write
path that mutates something else and *does* change the digest is a
v0-scope leak (the txpool exclusion test guards the leak direction).

Archival journals are a **named exclusion** (`DAEMON_REDB_STORE.md`
§7.1.1). They are not digest-v0 reads. Do not extract S-ARCH, and do
not implement archival apply in `shekyl-chain-store`, until those
journals are in the digest or carry a replacement KAT.

| Family | Digest read | Write paths that must move the digest | Notes |
| --- | --- | --- | --- |
| Core chain | `get_block_hash_from_height(h)` for `h ∈ [0, height)` — the hash is `block_info.bi_hash`, not the `blocks` blob | `add_block`, `remove_block` | height-ordered sequence, not a set |
| `spent_keys` | `for_all_key_images` | `add_spent_key`, `remove_spent_key` | set-shaped; XOR accumulator; LMDB dup-sort order is not load-bearing |
| Curve root | `get_curve_tree_root` (`curve_tree_meta` `"root"`; empty → Selene `hash_init`) | `grow_curve_tree`, `trim_curve_tree` | `curve_tree_roots` (per-height history) is P0e, not v0 |

The R-1…R-6 edges above remain the connect/pop partial-order
constraints. They are not digest inputs: several of them are
archival-journal RAW edges, which v0 deliberately does not hash.

## 7. Transcription A-2 — height base per journal (transcribed, not invented)

Connect fires the slash and epoch-close hooks at `prev_height + 1` — the
chain height *after* the block. The tx-connect journals key on the block's
*index* `N = prev_height`. Pop therefore reverts at **two bases** (with
`removed_block_height` = the pre-remove chain height):

| Journal / hook | Base on pop | Writer's base on connect |
| --- | --- | --- |
| `archival_slash_log` / `archival_slash_applied` revert | `removed_block_height` | hook at `prev_height + 1` |
| `archival_epoch_close_log` revert (+ boundary prune floor) | `removed_block_height` | hook at `prev_height + 1` |
| `archival_emission_claim_log` revert | `removed_block_height − 1` | tx-connect at block index `N` |
| `archival_bond_unbond_log` revert | `removed_block_height − 1` | tx-connect at `N` |
| `archival_bond_holdings_update_log` revert | `removed_block_height − 1` | tx-connect at `N` |
| `archival_bond_rebond_log` revert | `removed_block_height − 1` | tx-connect at `N` |
| `archival_budget_accrual` remove | `removed_block_height − 1` | funnel step 6 at `prev_height` |
| attestation witness remove | `removed_block_height` | store at key `prev_height` (`archival_attestation_witness_key` adds the +1) |
| segment-freeze revert | height-free (row count) | hook at `prev_height + 1` |

**Why two bases — the in-code rationale, verbatim** (F-B5b,
`blockchain_db.cpp:757`-ff): *"the slash/close hooks key on the chain
height AFTER the block (connect fires them at prev_height + 1), which
equals removed_block_height here. The claim journal keys on the block's
INDEX N = removed_block_height − 1, because the connect arm must journal at
the same operand verify's claim-age bound used (pin (b): both read height()
before the block row exists). **Convert, don't unify — moving the journal
to N + 1 would shift the connect-side settled-epoch operand off verify's at
every epoch boundary.**"* A reader who sees only "two bases" will file it
as a defect and normalize them; the sentence above is why that
normalization is the defect. The Rust store keeps both conventions or
re-derives verify's operand with them — it does not unify.

## 8. Transcription A-4 — pop revert partial order

From the load-bearing-order comments in the pop funnel (`:748`–`:798`),
as journal × fields × must-run-after × reason:

Bases are written as **expressions, not as offsets from `N`**: §7 defines
`N` as the block *index* (`= removed_block_height − 1`), so an `N`-relative
label here is one shift away from transcribing the wrong key — which is
exactly what it had done until this row was corrected. The hook base is
`removed_block_height` (`= N + 1`); the tx-connect journals key at
`removed_block_height − 1` (`= N`).

| Revert | Fields restored | Must run AFTER | Reason (from the comments) |
| --- | --- | --- | --- |
| slashes (hook base, `removed_block_height`) | `bonded_total`, `held_shard_ids`, `shard_add_epochs`, `bad_intervals` appends | — (first) | within a block, txs connect before the slash hook; pop mirrors in reverse |
| epoch close (hook base, `removed_block_height`) | epoch/budget close state | slashes | connect order mirror |
| emission claims (index base, `removed_block_height − 1`) | claimed set, `first_paying_emission_height` | slashes + close | claims connect at tx-connect, before the hooks; **fields disjoint** from the slash revert's, so this one *could* compose either way — the order is the mirror, kept |
| unbonds (index base, `removed_block_height − 1`) | `bonded_total`, holdings, interval log | slashes | defensive belt; a violation surfaces as `MISSING_CLEAN_CLOSE`, loud |
| holdings updates (index base, `removed_block_height − 1`) | `bonded_total`, `held_shard_ids`, `shard_add_epochs` | slashes | **ORDER IS LOAD-BEARING**: the slash journal restores the very same fields; reverting in the wrong order makes the exactly-one-FLOOR delta check see `FLOOR ± slashed_amount` and abort the pop with `NotSingleShardDelta` |
| rebonds (index base, `removed_block_height − 1`) | holdings/balance, closed interval | slashes | both journals touch `bad_intervals`; the slash revert strips its appended intervals before the rebond revert re-opens the journaled closed one |
| segment freezes (count) | frozen-segment counter | epoch-close revert | `:903`: counted against post-close state |

Inserting a new journal that touches `bonded_total`/`held_shard_ids`/
`bad_intervals` **between** any of these breaks the delta checks by
construction — the table above is the constraint surface the Rust store's
pop must reproduce or re-derive.

## 9. Transcription A-6, and the findings register

**A-6 — `m_write_txn` assertion census** (all sites in `db_lmdb.cpp`):
129 sites **dereference** `*m_write_txn`; 24 sites guard with
`if (!m_write_txn) throw …`; 15 are lifecycle
assignments (batch/guard machinery and the §1 prune swap). The 24 guards
split into **two exception families**: 2 throw `DB_ERROR_TXN_START`
(inherited paths) and 22 throw bare `std::runtime_error("FATAL: …")`
(the archival/curve-tree generation). A `std::runtime_error` sails past
every `catch (DB_ERROR&)` recovery surface, so the same precondition
violation has two different crash behaviors depending on which table
tripped it.

**What this census is, and is not.** The three numbers are a *lexical*
count over `db_lmdb.cpp`; they are not a safety classification. An
unknown subset of the 129 dereferences is **dominated by a caller's
guard** — `process_archival_slash_at_height` is the worked example: it
checks `!m_write_txn` at `:5930` and its comment names the helpers it is
guarding for (*"every mutating helper below … dereferences
`*m_write_txn`. Fail"* fast here). Counting those helpers' dereferences
as unguarded would double-count exactly the paths the guard exists to
protect. **The dominance analysis is not done here** — it needs the call
graph, which was P0c's instrument, not this pass's — so the figure is
reported as what it is: the total dereference census, and an upper bound
on the unguarded set. *(P0c **declined** it on 2026-09-08 and the upper
bound is now the final recorded figure — see the closure note under the
register below. This sentence is kept as written because it records why
the figure was left as a bound; it is no longer a live deferral.)*

| # | Finding | Grade | Disposition |
| --- | --- | --- | --- |
| DRS-W1 | Guard exception split: 22× `std::runtime_error` vs 2× `DB_ERROR_TXN_START` for the identical `!m_write_txn` precondition | wart (no unsound state; inconsistent failure surface) | RECORD-AND-SPECIFY: the Rust store has **one** typed precondition error; no C++ harmonization |
| DRS-W2 | `LockedTXN::commit` swallows `batch_stop` exceptions — silent commit failure (April note, still true) | wart | RECORD-AND-SPECIFY: Rust store commit is `Result`, callers must consume it |
| DRS-W3 | 129 dereferences of `*m_write_txn` in `db_lmdb.cpp` with no guard **at the dereference site**; an unknown subset is dominated by a caller's guard (worked example: `process_archival_slash_at_height`, `:5930`), so 129 is the total census and an **upper bound** on the unguarded set, not a count of latent null dereferences | wart (latent; **bound, not measured** — P0c declined the dominance analysis; the upper bound is the recorded figure) | RECORD-AND-SPECIFY: the Rust store's write handle is possession-typed, which makes the precondition unrepresentable and the whole census moot — that is why the exact figure is not worth computing in C++ |
| DRS-W4 | `txs` has **zero write and zero read sites** — the handle's only occurrence in `db_lmdb.cpp` is its `open()` (`:1662`); every live tx write goes to the pruned/prunable split. Verified wide across `src/` and `tests/` (the tests' `m_txs` is a test-local vector, not the handle) | wart (inherited-dead surface; no unsound state) | RECORD-AND-SPECIFY: the Rust store does not port the table. Deleting it here is a C++ **and** schema-version change, owned by the census/DRS lane, not by a docs pass |
| DRS-W5 | `hf_starting_heights` is `mdb_drop(…, del=1)`-deleted at every writable `open()` (`:1779`) and never re-created, so the **declared** table set (49) and the **runtime** set (48) differ permanently — and the coverage gate cannot see the class, since both sides of its comparisons derive from the same macro (§10) | wart (structural divergence between register and runtime; no unsound state) | RECORD-AND-SPECIFY, and routed to census **R4**, which owns the hardfork machinery. A runtime census is out of this pass's scope by design |
| DRS-W6 | The post-pop burn pair (`total_burned` reversal + `block_burn` row removal, `blockchain.cpp:896`–`:905`) sits at the **core layer, outside `BlockchainDB::pop_block`**. Two consequences: a batchless core-path caller pops in two transactions; and a caller popping through the DB funnel skips both writes entirely — **live today** via `blockchain_import --pop-blocks`, which calls `get_db().pop_block(...)` directly and documents why (§3). A database added through the verifying path and popped by that tool keeps burns the chain no longer contains | wart (**latent bookkeeping, live reachability** — graded on the complete five-site consumer census: RPC readout, connect add, pop reversal, and the two slash guards — an *inflated* value satisfies the underflow guard more easily but **reduces** the overflow guard's headroom, so the earlier reading ("satisfies both with headroom") was wrong in direction; the grade survives on magnitude instead, since that guard fires only within `slashed_amount` of `UINT64_MAX`, astronomically far from any burn total in atomic units. DRS-W6's own tool path can repeat, so the inflation is unbounded in principle: popping through the DB and re-adding increments the aggregate again each cycle. No emission, supply, or validation arithmetic consumes the scalar — `shekyl-economics-sim/src/record.rs:143` refuses the `already_generated − total_burned` derivation on the record, and the conservation helper is KAT-only with synthetic operands. **Grade expires with its ground**: any consensus consumer of the scalar re-grades this at that consumer's design round) | RECORD-AND-SPECIFY: **derived-total reversal belongs in the pop funnel** in the Rust store, so popping through the store cannot mean something different from popping through the node |
| DRS-W7 | **Four** sites, four semantics for the same scalar's impossible value: the connect increment **wraps** (`blockchain.cpp:6436` — unchecked `uint64_t +=`, no guard at all), the pop reversal **clamps** to floor (`:902`), the slash add **throws** `FATAL` on overflow (`db_lmdb.cpp:6050`), the slash revert **throws** `FATAL` on underflow (`:6362`). The census read "three sites, three semantics" until review found the unchecked connect add — the one site with no opinion at all about an impossible value | wart (**reachable — regraded**: DRS-W9 produces the too-LOW scalar the `:6362` underflow tests, and DRS-W6's tool path the too-HIGH one. The disagreement is live, and the fourth site is the sharpest part of it: three sites decided what an impossible total means and the fourth never asked) | RECORD-AND-SPECIFY: the Rust store gets **one** ruled semantic for an impossible derived total, applied at every site including the increment — checked arithmetic, not `+=`. The ruling belongs to the economics lane |
| DRS-W8 | `correct_block_cumulative_difficulties` (`:3034`) aborts explicitly on its size-mismatch guard but not on its loop throws — and there is no stack owner to unwind them: `block_wtxn_start` heap-allocates into `m_write_txn` (`:4311`) and only stop/abort delete and clear it (`:4344`, `:4361`). A loop throw therefore leaves the LMDB write transaction **live** and the member non-null, so the next `block_wtxn_start()` throws `DB_ERROR_TXN_START` and every subsequent block write fails until the process restarts. It also has **no production caller** (§5c) | wart (no partial commit — nothing commits — but a **poisoned writer**, not merely an open transaction; unwired today) | RECORD-AND-SPECIFY: one unwinding path in the Rust store, and a write handle whose lifetime is owned by the scope that opened it rather than by a raw member pointer |
| DRS-W9 | The connect-side burn pair (`add_block_burn` + `total_burned` increment, `blockchain.cpp:6425`–`:6437`) runs **after** the try whose catches set `m_batch_success = false`. A throw between the two unwinds to `add_new_block`'s outer catch, which sets only `bvc`, so `cleanup_handle_incoming_blocks` still calls `batch_stop()`: the block, its txs and the `block_burn` row commit **without** the aggregate — a partial commit of one logical unit, and the production entry for a too-LOW `total_burned` that DRS-W7 lacked | wart (**the most severe of this set, and still not S-graded**: no consensus arithmetic reads the scalar and no fund-safety consequence follows, and the window needs an LMDB-level write failure — but it can leave a node whose next slash revert trips the `:6362` FATAL underflow, a local halt, and it falsified a PASS this audit had published) | RECORD-AND-SPECIFY, converging with DRS-W6: the burn bookkeeping is core-layer on **both** connect and pop, so neither side inherits the funnel's failure semantics. In the Rust store both belong **inside** the funnel. **The oracle does not catch this (P0e, 2026-09-11):** `total_burned` lives in `properties` (`set_total_burned` writes `m_properties`), and `properties` is **uncovered** by digest v0 (§11) — the digest reads only `blocks`' row count, `block_info.bi_hash`, `spent_keys` and `curve_tree_meta`'s root. A store that suffered this partial commit is **indistinguishable from a healthy one** under the v0 digest, so nothing here may be read as "a regression check would find it" |
| DRS-W10 | `open()`'s older-DB exit **commits before it refuses**: `txn.commit()` runs, then `migrate()` throws (`:1819`-ff), so the table creations and the `hf_starting_heights` drop persist on a store the binary just declined to open (§5b) | wart (no partial transaction and no unsound state — the refusal's remedy is delete-and-resync, so nothing survives to be inconsistent; recorded because the shape does not survive a store that *can* migrate) | RECORD-AND-SPECIFY: in the Rust store, an open that fails leaves the store as it found it — structural changes commit only on the path that succeeds |
| DRS-W11 | `drop_hard_fork_info` (`:4675`) reuses `m_hf_starting_heights`, a handle every writable `open()` has already **closed** — LMDB's `del=1` deletes the database *and* closes the handle (`lmdb.h:1216`–`:1225`; `mdb.c:10970`–`:10973`). The first `mdb_drop` fails and the function throws before reaching the `hf_versions` drop, so the shipped `blockchain_import --drop-hard-fork` cannot do its job. Spec-derived consequence, not observed here: a closed handle's slot may be reused, so a stale member handle can come to name a different table (§5c) | wart (**loud, not silent** — the tool throws `DB_ERROR` rather than dropping the wrong thing, and it is the only other user of the member; graded on that, not on the aliasing path, which nothing in this tree reaches) | RECORD-AND-SPECIFY: in the Rust store, deleting a table **consumes** its handle, so a stale handle is unrepresentable rather than merely unused. Whether `--drop-hard-fork` should work at all is the census/R4 question, not this pass's |
| — | Dead schema-doc row: `properties` key `staker_pool_balance` + both accessors, zero occurrences in `src/` | doc defect | fixed in this PR (`LMDB_SCHEMA.md` row and the Staking-section pointer) |
| DRS-W12 | Fifteen archival apply/revert hooks on `BlockchainDB` have empty `{}` bodies, so a subclass that forgets one inherits a silent no-op | wart (latent: production 15/15; exposure is test doubles — evidence below) | RECORD-AND-SPECIFY: no default bodies on consensus hooks in the Rust store. C++ `= 0` patch **withdrawn**, not deferred |
| DRS-W13 | Curve-tree pop reconstructs `TreePosition` as `leaf_count - drained_count + j` because the drain journal never recorded it | wart (latent, correct today by invariant — evidence below) | RECORD-AND-SPECIFY: journal the assigned position; pop reads it back |
| DRS-W14 | Unbounded probe loops walk archival journal rows until first miss, so the reader holds the writer's density invariant | wart (no unsound state today — evidence below) | RECORD-AND-SPECIFY: range-scan the key prefix; gap-tolerance is a property of the query |
| DRS-W15 | `hf_versions` rows above the new tip are not deleted on pop, and **one** site reads them (`hardfork.cpp:300`, the file's only above-tip read) | wart (**regraded 2026-09-09**: the read-back is load-bearing *only for the incremental vote window*, and that window is discarded by two of four pop callers and wrong for the other two. It diverges from the authoritative rebuild on two axes — **contents**, masked by the inert table, and **length**, one entry per pop below `window_size` and observable today. No consensus effect: `threshold` is 0) | RECORD-AND-SPECIFY. Forbidden: DIVERGE-by-delete — **conditional**: the obligation survives into Rust only if R4 keeps an incremental window. Drop it and the clause retires, leaving `hf_versions` deletable on pop |
| DRS-W16 | `remove_block` deletes from `m_cur_blocks` **without positioning it** (`db_lmdb.cpp:1053`), while positioning its two sibling cursors explicitly in the same function. The `mdb_cursor_get(…, MDB_SET)` that positioned it was **removed** by inherited commit `22c0fae47b`, whose subject ("db: store cumulative rct output distribution in the db for speed") is unrelated to block removal. It is correct today only because its **sole** caller reads the top block through the **same** write-cursor member one call earlier (`blockchain_db.cpp:743`), a coupling `remove_block` neither states nor can check | wart (**latent, not reachable in this tree** — one caller, no interleaved `blocks` read. A `blocks` read inserted in that window, or a second caller, makes the delete remove whatever row the cursor last landed on, and `mdb_cursor_del` at a valid-but-wrong position **succeeds**: a torn logical unit, not a crash, since `block_info` and `block_heights` are positioned explicitly) | RECORD-AND-SPECIFY: in the Rust store a delete names its key, so there is no ambient cursor position for a future edit to strand. Restoring the dropped `MDB_SET` is the cheap C++ guard and is **not** taken here |

**P0c — what these four rows are, and the pin they were read at.** Rows
DRS-W12 through DRS-W15 are the **wart register** the P0c envelope calls for,
verified against `dev` `14aa42074` (P0b's rows stay at `2dba46537`; see the
header). Three come from the 2026-07-27 substrate findings whose "Plan
effect" column scheduled C++ patches — A-1, A-3 and A-5 in
[`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md)’s substrate-findings table; the fourth is
the `hf_versions` row (R2-1) carried in this table since April. **The
countermand of 2026-09-01 inverted all four to RECORD-AND-SPECIFY.** No C++
is written, and none is owed: these rows close when the Rust store implements
its half, not when someone patches the substrate. Evidence for each row is
the subsection below, not the table cell.

**Two figures inherited from the substrate findings were re-counted rather
than copied.** A-1's "fourteen (plus segment-freeze process)" is right —
fifteen hooks, all with empty `{}` bodies. A-3's expression is quoted in
the tree verbatim. A-5's probe loops were located at three call sites, not
assumed from the finding's prose.

**The 129-dereference dominance analysis is declined, and this closes it.**
§9's A-6 census above reports 129 `*m_write_txn` dereferences as an *upper
bound* on the unguarded set and deferred the dominance analysis to "the call
graph, which is P0c's instrument". P0c declines it, on DRS-W3's own
reasoning: the Rust store's write handle is possession-typed, so the
precondition those 129 sites could violate is unrepresentable rather than
merely unviolated, and an exact count of C++ sites is a measurement of a
question the rewrite deletes. The upper bound stands as the recorded
figure. This is a **closed** deferral, not a carried one — there is no
blocker, and nothing downstream waits on the number.

No finding is S-graded — re-checked **as of P0c (2026-09-08)** over the
fifteen rows then in the register, including the four added there (DRS-W12
was the candidate: 15/15 production overrides put it at latent). Nothing
there blocks DRS-0, and nothing there adds C++. **DRS-W16 was added
2026-09-12 and is graded in its own subsection**; this sentence is P0c's
record and is not restated to cover it.

### DRS-W12 — empty archival apply/revert bodies

**Fifteen** archival apply/revert hooks — fourteen plus
`process_archival_segment_freezes_at_height` — are declared on `BlockchainDB`
and defined out-of-line with empty `{}` bodies
(`src/blockchain_db/blockchain_db.cpp:1725`–`:1810`), so a subclass that
forgets one inherits a silent no-op. The contrast is deliberate and one file
away: `get_archival_last_slash_epoch` (`:1799`) returns `UINT64_MAX` with a
comment saying the sentinel "fails the release verify closed rather than
open" — the same base class chooses fail-closed for a getter and
silent-success for fifteen mutators.

`BlockchainLMDB` overrides **15/15**, so no production hook is a no-op today.
The exposure is the test doubles, and it is **latent** —
measured at `14aa42074`: `BaseTestDB` (`src/blockchain_db/testdb.h:44`)
overrides **0 of 15**, so every double built on it inherits fifteen silent
no-ops. Of the two that exercise archival paths,
`ArchivalBondPostIntegrationDB`
(`tests/unit_tests/archival_bond_post_integration.cpp:100`) overrides
**none**, and `EmissionConnectDB`
(`tests/unit_tests/archival_emission_connect.cpp:84`) overrides **exactly
one** — `apply_archival_emission_claim`, the hook it means to observe — and
inherits the other fourteen.

**Latent, and the distinction is the point.** What is measured is the
*capability*: such a double can only see the call it already thought to
look for, and any other hook the path under test invoked would be
indistinguishable from one never called. What is **not** established — and
what an earlier revision of this row asserted by writing "realized, not
hypothetical" — is that any test today is actually blinded. None is: the
archival apply/revert semantics are covered against the real
`BlockchainLMDB` in `tests/unit_tests/archival_substrate_lmdb.cpp`, every
`BaseTestDB`-derived double that calls `add_block` overrides it (so it
never reaches `BlockchainDB`'s dispatch), and `EmissionConnectDB`'s
emission fixtures only trigger the one hook it does override. The `{}`
bodies did not hide a defect; they removed the compiler's ability to notice
if one ever arrived. Recorded this way because inferring the consequence
from the capability is the error this register has now made twice — the
other is DRS-W15's superseded "load-bearing, therefore Rust must keep the
rows".

The C++ fix originally scheduled here (`= 0` plus explicit `BaseTestDB`
stubs) is **withdrawn** under the 2026-09-01 countermand; it is not deferred,
and there is no blocker to name, because the row is closed by the rewrite
rather than by the patch. Rust: no default methods on consensus hooks —
"forgot to implement" is a compile error, not a passing test.

### DRS-W13 — `TreePosition` reconstructed on pop

The curve-tree pop reconstructs each drained leaf's `TreePosition`
arithmetically — `TreePosition tree_pos{leaf_count - drained_count + j}`
(`src/blockchain_db/blockchain_db.cpp:887`) — because the drain journal never
recorded it: `drain_entry_t` (`src/blockchain_db/blockchain_db.h:2512`)
carries `maturity`, `output` and the 128-byte `leaf`, and no position. The
forward path *has* the value and drops it, assigning
`tree_pos{tree_leaf_base + count}` at `src/blockchain_db/lmdb/db_lmdb.cpp:8678`
and journalling without it.

Latent, **correct today by invariant**: drain-to-tip plus contiguous leaves
makes the arithmetic agree with what the drain assigned; it is not
guesswork. Recorded because correctness rests on an invariant held in two
functions rather than on the journal, which is the same species as the slash
pre-image reconstruction bugs. Like W6/W9 the reconstruction sits at the
**core layer**, in `BlockchainDB::pop_block`, not in the backend.

Rust: journal the position the drain assigned and have pop read it back. A
reversal must not recompute what the forward path already knew — zero
reconstruction for pending keys.

### DRS-W14 — dense-seq probe loops

Unbounded probe loops walk archival journal rows until first miss —
`for (uint32_t seq = 0; ; ++seq)` at `src/blockchain_db/lmdb/db_lmdb.cpp:5443`
and `:6286`, and the same shape with the counter declared above the loop at
`:5411` — so the **reader** encodes an invariant the **writer** holds: that
`seq` is dense with no gaps. Nothing enforces it; the writer's `seq++`
(`:6062`) is the only reason the slash-log path is dense (the template
journals keep density by `archival_journal_next_seq` + put, the third site).

No unsound state today — the writers are dense — but the invariant is
unwritten and split across sites, so a future gap truncates a journal read
silently rather than failing.

Rust: range-scan the key prefix rather than probing a counter, which makes
gap-tolerance a property of the query instead of an assumption about the
writer. Applies to the epoch-marker seq on the same footing.

### DRS-W15 — `hf_versions` read-back on pop

`hf_versions` rows above the new tip are **not deleted on pop**, and exactly
one site reads them: `db.get_hard_fork_version(height)` at
`src/cryptonote_basic/hardfork.cpp:300`, inside `HardFork::on_block_popped`
(`:286`–`:309`). It is the file's **only** above-tip read — the other three
reads are at or below the tip (`:214` in `reorganize_from_block_height` at
the new tip block, `:266` in `rescan_from_block_height` at
`db.height() - 1`, `:357` the public accessor). **The whole redb obligation
descends from that one line**, so the row's grade has to be about it and not
about the table in general.

**What the read-back is worth, per caller.** `pop_block_from_blockchain`
(`src/cryptonote_core/blockchain.cpp:814`) is the only caller of
`on_block_popped`, always with a literal `1` (`:846`), so the loop runs once
and the multi-block arm is dead. It has four callers of its own:

| pop caller | authoritative rebuild after? | incremental result |
| --- | --- | --- |
| `switch_to_alternative_blockchain` (`:1308`) | yes — `:1385` | **discarded** |
| `rollback_blockchain_switching` (`:1237`) | yes — `:1242` | **discarded** |
| `pop_blocks` (`:782`, operator/RPC batch) | **no** | retained, and wrong |
| `handle_block_to_main_chain` unwind (`:6599`) | **no** | retained, and wrong |

**No caller both relies on the incremental result and gets a correct one.**
The two paths where hardfork state actually matters are reorgs, and both
recompute the window from scratch microseconds later; the two that keep it
keep a wrong answer. That is inheritance from upstream, not a design.

**Two independent divergences from the authoritative rebuild**, and only one
of them is masked:

1. **Contents — masked today.** `on_block_popped` pops the newest *vote*
   off the back (`versions.pop_back()`, correct) and pushes
   `get_hard_fork_version(h)` onto the **oldest** end for the block just
   popped. Wrong block, wrong end, wrong quantity: `add()` stores
   `heights[current_fork_index].version` via `set_hard_fork_version` but
   pushes `get_effective_version(voting_version)` into the deque
   (front-oldest / back-newest: eviction `pop_front` at `:149`, append `push_back` at `:153`) — the asymmetry CEN-B3
   records. The block that *should* re-enter the window never does. This is
   invisible under the shipped table: `get_effective_version` clamps to
   `heights.back().version` (`:102`–`:104`) and `do_check` requires
   `voting_version >= heights[current_fork_index].version` (`:112`), and
   with a single `{1, 1, 0, …}` entry both bounds are `1`, so every accepted
   block contributes `1`. Observing it needs a **synthetic multi-version
   fixture**, as `tests/unit_tests/hardfork.cpp`'s reorganize tests build.
2. **Length — not masked, observable now.** `on_block_popped` is
   size-preserving (one `pop_back`, one `push_front`, net zero).
   `reorganize_from_block_height` is not: `rescan_height` (`:213`) plus the
   fill loop (`:218`) produce exactly `min(height + 1, window_size)`
   entries. Below `window_size` the incremental window is therefore **one
   entry too long per pop**, and `last_versions` miscounts with it.
   `DEFAULT_WINDOW_SIZE` is `10080` (`hardfork.h:51`), so every pre-genesis
   chain and every plausible fixture sits under it. Because no rebuild
   follows `pop_blocks` or the `:6599` unwind, *k* consecutive pops leave
   the deque *k* entries too long relative to the remaining chain,
   re-converging only once the chain passes `10080` and `add()`'s
   eviction clamps it.

**No consensus effect today**: `heights[0].threshold` is `0`, so
`get_voted_fork_index`'s `accumulated_votes >= threshold` is vacuous. The
state divergence is real and present regardless.

The unsigned-underflow shape in the loop bound
(`height >= new_chain_height` with `--height`) is **guarded, not open** —
`pop_block_from_blockchain` asserts `m_db->height() > 1` at `:825`, so
`new_chain_height` is never `0`. Checked rather than recorded as a finding.

**Class:** RECORD-AND-SPECIFY. **Forbidden: DIVERGE-by-delete — but the
clause is conditional, and this is the regrade.** The earlier wording
("load-bearing, not residue … deleting them on pop breaks reorg") had it
backwards: on the reorg callers a delete breaks nothing, because the
rebuild reads block data rather than the table. The rows are load-bearing
**only for the incremental window**, and the incremental window is
redundant on two callers and incorrect on the other two. So the honest
statement is not "the rows are read, therefore Rust must keep them" — it is
that **the read-back obligation survives into Rust only if R4 keeps an
incremental window at all.** If R4 drops it in favour of the shape already
in the tree, the Forbidden clause **retires** and `hf_versions` becomes
deletable-on-pop, which is the schema one would design from scratch.

**The shape that fits is already here.** Callers 1 and 2 do it by hand: pop
in a loop, rebuild once at the end. The window is a derived cache of the
last *N* votes, so the correct primitive is **invalidate-on-pop, rebuild
once when the pop sequence ends** — O(window) per batch instead of O(1)×*k*
plus a wrong answer. Note why the obvious patch is wrong: calling the
rebuild *from* `on_block_popped` would make `pop_blocks(k)` perform *k*
rebuilds of up to `10080` block reads each. `pop_blocks` and the `:6599`
unwind simply never got the treatment the reorg paths did.

**What is undetermined** is not whether the two paths differ — they do, and
the length axis is measurable today without a fixture. It is the *intended*
semantics: the July round's class was "decide correct semantics" and
nothing has decided it. This row does not upgrade the divergence to a
defect, because "wrong" presumes the rescan is the intended reference, and
that is R4's to rule.

The A3 narrow exception does not fire — on the register's current state, not
on a correctness finding. FIX-IN-CPP survives the countermand only where a
defect blocks the C++ from serving as an interim oracle for a *ratified,
conformance-checked* row. No such row covers post-reorg hardfork
reconstruction: CEN-B3 is the only census row over this machinery and it is
**bucket 4** — no ratified spec to check against — held there deliberately
for the R4 round. With nothing ratified, there is nothing for the defect to
block, so the exception has no subject. **It re-runs if R4 ratifies such a
row.** The April **Forbidden** clause is the binding constraint **while
R4 keeps an incremental window**: classifying this **DIVERGE**, having
the Rust store delete the row, and asserting the delete in a KAT would
ship a hardfork-state regression on the two callers that retain that
window. It does **not** ship a reorg regression — both reorg callers
rebuild from block data. If R4 drops the incremental window, the clause
retires.

**Citation warning for anyone quoting CEN-B3 here.** The census cites the
reorg rebuild at `blockchain.cpp:1494` against *its own* pin (`8ba1aae3d`).
That address is records-was there and must not be copied onto this pin: at
this pin `:1494` is an unrelated alt-window plan loop, and the call is
`m_hardfork->reorganize_from_chain_height(split_height)` at `:1385`. A
borrowed citation inherits the lender's pin.

The question routed to census R4 — which already owns this machinery
(DRS-W5, DRS-W11, CEN-B3) — is therefore **one question, not two**, and it
is prior to both of the ones this row carried before: *does the Rust store
keep an incremental vote window at all?* Everything else follows from it.
Keep one, and the intended semantics must be decided (the July "correct
semantics" question) and the tip-above read-back specified with it. Drop it
in favour of invalidate-and-rebuild-once, and there is no above-tip read,
no Forbidden clause, and `hf_versions` is deletable on pop. Vacuousness
today is exactly what makes that decision cheap to take **now** rather than
after the table stops being inert.

The envelope's "FIX or REPLICATE" disjunction is answered by not fixing in
C++ and not diverging by delete *while the question is open*; it is **not**
a commitment to match the reconstruction algorithm, which this row now
records as divergent from the authoritative rebuild on two axes.

### DRS-W16 — `remove_block` deletes from an unpositioned `blocks` cursor

Found 2026-09-12 during DRS-0 slice A's delete-path falsifier run (§12),
verified against `dev` `ba4b3c73a`.

`remove_block` positions two of its three write cursors explicitly before
deleting through them — `m_cur_block_info` by `MDB_GET_BOTH` on the height,
then `m_cur_block_heights` by `MDB_GET_BOTH` on the `bi_hash` read back from
that row. It then calls `mdb_cursor_del(m_cur_blocks, 0)` (`:1053`) with **no
positioning call on `m_cur_blocks` anywhere in the function**.
`CURSOR(blocks)` (`:433`) only opens the cursor if the member is null; it
does not position it.

**The positioning call existed and was removed.** `git log -S` on the exact
expression returns two commits, and the later one deleted it:

```
-  if ((result = mdb_cursor_get(m_cur_blocks, &k, NULL, MDB_SET)))
-      throw1(DB_ERROR(lmdb_error("Failed to locate block for removal: ", result).c_str()));
   if ((result = mdb_cursor_del(m_cur_blocks, 0)))
```

The commit is `22c0fae47b`, subject *"db: store cumulative rct output
distribution in the db for speed"* — inherited, and on its face unrelated to
block removal. A removal that rides along in a commit about something else,
leaving two sibling cursors positioned and the third not, is the signature
of an omission rather than a decision.

**Why it nevertheless works today — the mechanism, found rather than
assumed.** An unpositioned `mdb_cursor_del` returns `EINVAL`, so a pop
*should* throw on the first call; pops do not. The resolution is an
**implicit position coupling across two functions**.
`BlockchainDB::pop_block` calls `blk = get_top_block()`
(`blockchain_db.cpp:743`) immediately before the pop sequence.
`get_top_block` reaches `get_block_blob_from_height`, which does
`mdb_cursor_get(m_cur_blocks, &key, …, MDB_SET)` (`:2789`) — and `RCURSOR`
(`:440`) opens into `m_cursors`, which **is** `&m_wcursors` inside a write
transaction. It is therefore the *same* `m_cur_blocks` member, left
positioned at `height() - 1` — exactly the row `remove_block` then
deletes. Nothing between the two touches the `blocks` table
(`blockchain_db.cpp:743`–`:805`), and `pop_block` is `remove_block`'s
**sole caller** (`:805`; the only other declarations are the pure virtual
and `testdb.h`'s empty override).

**So the grade is latent, not unresolved, and the hazard is precise.**
`remove_block` is correct today by a property of its caller that
`remove_block` does not state and cannot check. Two changes break it, both
silent:

- any `blocks` read inserted between `get_top_block()` and `remove_block()`
  in that window — it repositions the shared cursor, and the delete then
  removes **whatever row the cursor last landed on**; and
- any second caller of `remove_block` that does not read the top block
  first — it deletes at a stale position, or throws `EINVAL` if the cursor
  is fresh.

The first is the dangerous one: `mdb_cursor_del` at a *valid but wrong*
position succeeds. There is no loud failure — the wrong block row is
removed while `block_info` and `block_heights`, which **are** positioned
explicitly, remove the right ones. That is a torn logical unit, not a
crash.

**Routing.** Standing RECORD-AND-SPECIFY default; the A3 narrow exception
does not fire, because no ratified, conformance-checked row depends on the
C++ serving as an interim oracle here. **Not S-graded:** the defect is not
reachable in this tree — one caller, no interleaved `blocks` read — so
this is a latent fragility, not a live fault. In the Rust store a delete
names its key and there is no ambient cursor position for a future edit to
strand, which is the specification this row closes on. If the C++ is to
live any length of time, the cheap guard is to restore the `MDB_SET` the
inherited commit dropped; that is a C++ change and therefore not taken
here.

## 10. Coverage matrix — every table, its writers, its audited path

One row per `SHEKYL_LMDB_TABLES` entry (gate-pinned bijection; the row
count is the macro's length by construction). "Path §" points at the
section above whose verdict covers the table's writers. **`Digest v0`**
states what digest v0 sees of that table — one of `v0`, `v0-partial`,
`excluded` or `uncovered`, defined in §11 and gate-enforced one-per-table
by the P0e leg. A state token is **not** a coverage claim: 24 of the 49 read
`uncovered`. **`Accumulator class`** states what the frozen design commits
to — one of `set-shaped`, `append-mostly`, `small`, `derived` or `excluded`,
defined in §12 and gate-enforced one-per-table by the slice-A leg. **The two
columns are different axes and neither is a proxy for the other** — they
disagree on the count §12 states and the gate derives, because the archival
journals are v0-`excluded` and carry a real accumulator class. A class token
is **not** a soundness claim — see §12's stated limitation.

**49 rows** (the stated figure is gate-checked against the macro's
length, like the P0a registry's). **A stated property of this matrix, not
a footnote on one row:** it covers the 49 **declared** tables — the
X-macro is a register of declarations, not a census of what exists at
runtime — and DRS-W5 proves the two populations differ: `hf_starting_heights`
is dropped (`del=1`) at every writable `open()`, so the running store
holds one table fewer than the register says. The coverage gate
**structurally cannot observe this class**, because both sides of every
comparison it makes derive from the same macro. Recorded here for census
R4 (which owns the hardfork machinery) to rule on; building a runtime
census is out of this pass's scope by design:

**Two writers are cross-cutting, and are stated here once rather than
repeated down the column** — a universal fact copied into every row is a
copy per row that can drift, and the per-row "Writers" column earns its
keep by naming what *distinguishes* one table from another. They apply to
every row of the table that follows:

- **`open()` (§5b) creates every missing declared table** —
  `lmdb_db_open(… MDB_CREATE)` per name in the macro list, which is a
  write to the unnamed main DB — then **drops `hf_starting_heights`**
  (`del=1`, DRS-W5) and seeds the `properties` version row on an empty
  database, all in one transaction. So §5b is in every row's writer set.
- **`reset()` (§5b) writes every table it enumerates**, which is every
  named table *present in the environment* except the keep set
  (`txpool_meta`, `txpool_blob`) — `mdb_drop(…, del=0)` per name, one
  transaction. It is therefore in every row's writer set except three,
  and the third is the declared/runtime distinction biting again: the
  two keep-set rows say *reset-kept*, and **`hf_starting_heights` is not
  there to enumerate** — `open()` deleted the database before `reset()`
  could see the name. A rule that said "every table except the keep set"
  would contradict DRS-W5 one line after stating it.

| Table | Writers at the pin | Path § | Digest v0 | Accumulator class |
| --- | --- | --- | --- | --- |
| `alt_blocks` | `add_alt_block` / `remove_alt_block`; `drop_alt_blocks` (emptied) | §5 | excluded | excluded |
| `archival_alt_attestation_witness` | `store/remove_archival_alt_attestation_witness`; `drop_alt_blocks` | §5 | excluded | excluded |
| `archival_attestation_witness` | `store/remove_…_at_height`; `delete_…_before_height` (prune) | §2/§3/§5a | excluded | small |
| `archival_bond` | `put_archival_bond_value` / `remove_archival_bond_record` | §2/§3 | excluded | set-shaped |
| `archival_bond_holdings_update_log` | journal helpers | §2/§3/§7/§8 | excluded | append-mostly |
| `archival_bond_rebond_log` | journal helpers | §2/§3/§7/§8 | excluded | append-mostly |
| `archival_bond_unbond_log` | journal helpers (`archival_journal_put/delete`, param dbi) | §2/§3/§7/§8 | excluded | append-mostly |
| `archival_budget` | epoch-close put; `delete_archival_budget_for_epoch` — the **pop-side** revert (`revert_archival_epoch_close_at_height`, `:8536`); `delete_archival_budget_before_epoch` — the retention prune | §2/§3/§5a | excluded | small |
| `archival_budget_accrual` | `add/remove_archival_budget_accrual`; `delete_…_before_height` | §2/§3/§5a | excluded | small |
| `archival_emission_claim_log` | journal helpers | §2/§3/§7/§8 | excluded | append-mostly |
| `archival_epoch_close_log` | `process/revert_archival_epoch_close_at_height` | §2/§3 | excluded | append-mostly |
| `archival_r_market` | epoch-close put; `delete_archival_r_market_for_epoch` — **pop-side** revert (`:8528`); `delete_archival_r_market_before_epoch` — retention prune | §2/§3/§5a | excluded | small |
| `archival_serve_credit` | `set/remove_archival_serve_credit_bit`; `delete_archival_serve_credit_before_epoch` (retention prune); FAKECHAIN-fenced RPC injector `regtest_inject_archival_serve_credit` (§5c) | §2/§3/§5a/§5c | excluded | small |
| `archival_settlement` | `set_archival_settlement` — caller's txn, unwired (CEN-L8); `delete_archival_settlement_for_epoch` — **pop-side**, from `revert_archival_slashes_at_height` (`:6423`), not a prune; `delete_archival_settlement_before_epoch` — retention prune | §3/§5a/§5c | excluded | small |
| `archival_shard_segment` | `put_archival_shard_segment`; `revert_archival_segment_freezes`; corruption-test put (§5c) | §2/§3/§5c | excluded | set-shaped |
| `archival_sigma_work` | epoch-close put; `delete_archival_sigma_work_for_epoch` — **pop-side** revert (`:8529`); `delete_archival_sigma_work_before_epoch` — retention prune | §2/§3/§5a | excluded | small |
| `archival_slash_applied` | `set/remove_archival_slash_applied` | §2/§3 | excluded | set-shaped |
| `archival_slash_log` | `append_archival_slash_log`; `revert_archival_slashes_at_height` | §2/§3 | excluded | append-mostly |
| `block_burn` | `add_block_burn` / `remove_block_burn` | §2/§3 | uncovered | set-shaped |
| `block_heights` | `add_block` / `remove_block` | §2/§3 | uncovered | set-shaped |
| `block_info` | `add_block` / `remove_block`; `correct_block_cumulative_difficulties` (own `block_wtxn`) | §2/§3/§5c | v0-partial | append-mostly |
| `block_pending_additions` | `add_block_pending_addition`; `remove_block_pending_additions` | §2/§3 | uncovered | set-shaped |
| `blocks` | `add_block` / `remove_block` (`m_wcursors`) | §2/§3 | v0-partial | append-mostly |
| `curve_tree_checkpoints` | `save_curve_tree_checkpoint`; `prune_curve_tree_intermediate_layers` | §2/§3 | uncovered | derived |
| `curve_tree_layers` | `grow/trim_curve_tree`; `prune_curve_tree_intermediate_layers`; corruption-test del (§5c) | §2/§3/§5c | uncovered | derived |
| `curve_tree_leaves` | `grow_curve_tree` / `trim_curve_tree` | §2/§3 | uncovered | append-mostly |
| `curve_tree_meta` | `grow/trim_curve_tree` | §2/§3 | v0-partial | small |
| `curve_tree_roots` | `store/remove_curve_tree_root_at_height` | §2/§3 | uncovered | set-shaped |
| `hf_starting_heights` | **deleted at every non-read-only `open()`** (`mdb_drop` del=1, `:1779`); `drop_hard_fork_info`; finding DRS-W5 | §5b/§5c | uncovered | excluded |
| `hf_versions` | `set_hard_fork_version` (`TXN_BLOCK_PREFIX`); `drop_hard_fork_info`; not cleaned on pop (P0c wart) | §2/§5c | uncovered | small |
| `leaf_to_output` | `add/remove_output_leaf_mapping` | §2/§3 | uncovered | set-shaped |
| `output_amounts` | `add_output` / `remove_output` | §2/§3 | uncovered | set-shaped |
| `output_metadata` | `store_output_metadata` — sole caller is inside `prune_tx_data` (`db_lmdb.cpp:10229`), so this table is written by the **depth prune**, not by connect | §5a | uncovered | excluded |
| `output_to_leaf` | `add/remove_output_leaf_mapping` | §2/§3 | uncovered | set-shaped |
| `output_txs` | `add_output` / `remove_output` | §2/§3 | uncovered | set-shaped |
| `pending_tree_drain` | `add_pending_tree_drain_entry`; `remove_pending_tree_drain_entries` | §2/§3 | uncovered | set-shaped |
| `pending_tree_leaves` | `add/remove_pending_tree_leaf`; `drain_pending_tree_leaves` | §2/§3 | uncovered | set-shaped |
| `properties` | `open()` version seed; `set_total_bonded_atomic` / `set_total_burned` (incl. the post-pop burn reversal, `blockchain.cpp:896` — §3/DRS-W6); `set_archival_last_slash_epoch` — written on **both** paths, by `process_archival_slash_at_height` on connect (`:6248`) and `revert_archival_slashes_at_height` on pop (`:6429`, `:6431`); prune receipts — `note_archival_prune_watermark_epoch` and `set_archival_frozen_shard_count_on_write_txn`, plus `pruning_seed` written by `prune_worker` (`:2365`) and `tx_prune_next_block` by `write_tx_prune_next_block_height` (`:10283`), both §5a; `set_settlement_epoch_blocks_pin` (own txn) | §2/§3/§5a/§5b/§5c | uncovered | small |
| `spent_keys` | `add_spent_key` / `remove_spent_key` | §2/§3 | v0 | set-shaped |
| `tx_indices` | `add_transaction_data` / `remove_transaction_data` | §2/§3 | uncovered | set-shaped |
| `tx_outputs` | `add_tx_amount_output_indices` / `remove_transaction_data` | §2/§3 | uncovered | append-mostly |
| `txpool_blob` | `add/remove_txpool_tx` (`LockedTXN`); reset-kept | §4/§5b | excluded | excluded |
| `txpool_meta` | `add/update/remove_txpool_tx` (`LockedTXN`); reset-kept | §4/§5b | excluded | excluded |
| `txs` | **none** — opened (`:1662`), never written or read through its handle; finding DRS-W4 | §9 | excluded | excluded |
| `txs_pqc_auths` | `add_transaction_data` / `remove_transaction_data` (v11: kept by the depth prune) | §2/§3/§5a | uncovered | append-mostly |
| `txs_prunable` | `add/remove_transaction_data`; `prune_worker`, `prune_tx_data` (own txns) | §2/§3/§5a | uncovered | excluded |
| `txs_prunable_hash` | `add/remove_transaction_data` (v11: kept by the depth prune) | §2/§3/§5a | uncovered | append-mostly |
| `txs_prunable_tip` | `add/remove_transaction_data`; `prune_worker` | §2/§3/§5a | uncovered | excluded |
| `txs_pruned` | `add_transaction_data` / `remove_transaction_data` | §2/§3 | uncovered | append-mostly |

Enumeration ground: 135 write call sites across 81 functions (79
`BlockchainLMDB::` methods + the two anonymous-namespace journal template
helpers, which take the `MDB_dbi` as a parameter — the three
non-member-handle write sites are those two plus `reset()`'s per-name local
dbi). `txs` is the one macro table with no write site (DRS-W4), and
`hf_starting_heights` is deleted at every writable `open()` (DRS-W5) — both in
§9's register.

---

*The April 2026 text this file replaces is preserved in git history at
`a17ccd0c81` (`git show a17ccd0c81:docs/LMDB_WRITE_ATOMICITY_AUDIT.md`);
its verdicts are records-was — true of a 29-table store with claim-era
staking and a live Monero migration ladder, none of which exist at this
pin.*

## 11. Digest v0 coverage ledger (P0e)

**This section states what digest v0 sees. It does not claim the store is
covered** — three of its four states say the opposite, and the count below is
the measured size of the gap P0d named when it scoped v0 as a *minimum*.

**Every one of the 49 declared tables carries exactly one state token in
§10's `Digest v0` column**, and the schema-coverage gate's P0e leg enforces
that — one token per table, drawn from the four below, no blanks. The leg
asserts **statehood, not coverage**: a tree where all 49 read `uncovered`
passes it. What the leg prevents is a table entering or leaving the digest
with nobody writing it down.

**The test applied to every row, and the only one applied:** *would a
divergence in this table move a digest-v0 input?* Digest v0 reads exactly
four things (`logical_state_digest.cpp:41`) — the row **count** of `blocks`
via `mdb_stat`, `block_info.bi_hash` for every height, the whole
`spent_keys` set, and `curve_tree_meta`'s `"root"`. A table's role, its
importance, or the fact that it is indexed off something digested are **not**
answers to that question. "Derived from a digested primary" was rejected as a
class for exactly this reason: the digest hashes `bi_hash`, not the
`block_info` row, so an index keyed on a field the digest never reads can
diverge freely.

| State | Count | Meaning |
| --- | --- | --- |
| `v0` | **1** | Fully hashed. Any divergence moves the digest |
| `v0-partial` | **3** | One field or one property is hashed; the rest of the table is not |
| `excluded` | **21** | Outside the oracle's stated domain, or dead |
| `uncovered` | **24** | In domain, consensus-bearing, and invisible to the digest |

**`v0` and `v0-partial` — what is actually hashed.**

`spent_keys` is the only table hashed whole. The other three are partial, and
the partiality is easy to misread:

- **`blocks` — row count only.** `height()` takes `mdb_stat(m_blocks)` and
  uses `ms_entries`. The block *blobs* are never read by the digest. A blob
  corrupted at height *h* with `block_info.bi_hash` intact does not move it.
  The Digest-v0 read-set table in §6 says the hash is "`block_info.bi_hash`,
  not the `blocks` blob", which is true of the *hash* and has been read as
  meaning `blocks` is out of the digest entirely. Its cardinality is in.
- **`block_info` — `bi_hash` only.** The row also carries `bi_height`,
  `bi_timestamp`, `bi_coins`, `bi_weight`, `bi_diff` and `bi_cum_rct`. Block
  **difficulty and weight are consensus inputs** and the digest does not see
  them.
- **`curve_tree_meta` — the `"root"` property only.** Other keys in the table
  are not read.

**A joint property of `blocks` and `block_info`, not a note on either.** The
digest's **length** comes from one table and its **content** from another:
`n_blocks` is `mdb_stat(m_blocks).ms_entries`, and the values hashed are
`block_info.bi_hash` for `h ∈ [0, n_blocks)`. **Nothing in the walker asserts
the two tables agree in cardinality**, and the two directions of disagreement
do not behave alike:

- `block_info` **shorter** than `blocks` — `get_block_hash_from_height`
  raises `BLOCK_DNE` and the digest **fails loudly**. Safe direction.
- `block_info` **longer** than `blocks` — the loop stops at the smaller
  `n_blocks` and the trailing heights are **silently dropped** from the
  hash. A `block_info` row above the `blocks` count is invisible.

So `blocks` being `v0-partial` is not only "the blob is not read": its row
count is the digest's *bound*, and an under-count silently shortens the
digest's domain rather than failing. Recorded as a coverage finding over the
pair; widening the digest to hash the cardinalities against each other is
**E1**'s.

**`excluded` — outside the oracle's domain, or dead.**

Digest v0 is a **main-chain-state oracle by construction**, so non-canonical
state is outside its *domain* rather than missing from its *coverage*. That
is the whole justification, and it is a domain claim, not a safety claim.

- **Non-canonical (4):** `txpool_meta`, `txpool_blob`, `alt_blocks`,
  `archival_alt_attestation_witness`. **Only the txpool pair has the boundary
  enforced** — §6's exclusion test guards the leak direction (a write there
  must *not* move the digest). `alt_blocks` and the alt witness have no
  equivalent test, so for them the boundary is *declared, not enforced*. That
  is this class's open item. The alt witness is archival as well as alt; it
  is classed here because the domain argument is the one that holds today,
  and it inherits §7.1.1's KAT obligation when S-ARCH ports.
- **Archival journal families (16):** the `DAEMON_REDB_STORE.md` §7.1.1 named
  exclusion. **The replacement KAT that rule requires does not exist yet.**
  §7.1.1 forbids extracting S-ARCH or implementing archival apply in
  `shekyl-chain-store` until these are digested *or* carry that KAT, so the
  obligation is live and unmet — recorded here as the exclusion's open item
  rather than treated as discharged by being written down.
- **Dead (1):** `txs` — zero read sites and zero write sites (DRS-W4).
  Nothing can diverge in a table nothing touches.

**`uncovered` — in domain, and the digest cannot see it.**

Twenty-four tables hold main-chain state that no digest-v0 input depends on.
Four are worth naming individually because a reader would otherwise assume
the oracle covers them:

- **`properties` — and this one has a consumer in this document.** It holds
  the schema version, the prune-watermark receipt, and **`total_burned`**
  (`set_total_burned` writes `m_properties`). The burn aggregate is the
  subject of three wart rows, and **DRS-W9 describes a partial commit that
  leaves it wrong**: the block, its txs and the `block_burn` row commit
  without the aggregate. **Digest v0 cannot distinguish a store that suffered
  that failure from one that did not.** W9's disposition carries this
  cross-reference.
- **`curve_tree_roots` — per-height roots, read by consensus.** Written on
  connect (`blockchain_db.cpp:658`), removed on pop (`:874`), and read as the
  FCMP membership-proof reference root at `blockchain.cpp:3898`, `:4047` and
  `:4309`. The digest hashes only the *current* root, so a historical root
  diverging at a height the tree has since moved past is invisible. §6 said
  this table "is P0e, not v0"; this is that disposition — **uncovered**, not
  excluded.
- **Stored transaction bodies (`txs_pruned`, `txs_prunable`,
  `txs_prunable_hash`, `txs_prunable_tip`).** The digest hashes block
  *identities*, never stored tx content. This is the largest single hole by
  volume. Do not read DRS-W4's "dead" verdict onto these — W4 is about `txs`
  alone; these four are live.
- **`hf_versions` and `hf_starting_heights`.** Uncovered like the rest, with
  a caveat that is *not* a coverage state: their retention semantics are
  pending census R4 (DRS-W5, DRS-W11, DRS-W15). `hf_starting_heights` is
  additionally `mdb_drop`'d at every writable `open()` (DRS-W5), so it has no
  runtime rows to diverge — its uncoveredness is vacuous at runtime rather
  than latent.

The remaining eighteen — the output set (`output_txs`, `output_amounts`,
`output_metadata`, `tx_outputs`), the tx and block indices (`tx_indices`,
`block_heights`), the curve-tree working state (`curve_tree_leaves`,
`curve_tree_layers`, `curve_tree_checkpoints`, `leaf_to_output`,
`output_to_leaf`, `pending_tree_leaves`, `pending_tree_drain`,
`block_pending_additions`), `txs_pqc_auths`, `block_burn` and the two
hardfork tables above — fail the divergence test for the same reason: no
digest-v0 input reads them.

**These are findings, not decisions.** Widening the digest is **DRS-E1**'s,
not P0e's: v0's read set is P0d's and pinned, and changing it moves the
oracle. P0e's job was to measure the gap and make it impossible to lose.


---

## 12. Accumulator class freeze (DRS-0 slice A, R2-6)

**This section states what the frozen design commits to for each table. It
is a different axis from §11.** §11's `Digest v0` state says what the
*minimum oracle reads today*; this section's `Accumulator class` says what
the *design commits to*. By construction **they disagree on **16** rows** —
a count the gate derives from the two columns rather than trusting this
sentence: the archival journals are v0-`excluded`, and
`DAEMON_REDB_STORE.md` §6.2 names "archival journals" under **Small**. A v0
exclusion is therefore **not** an accumulator exclusion, and §7.1.1 agrees —
it requires those journals in digest coverage *before* S-ARCH extraction,
which is only possible if the freeze gives them a class. **Do not read
either column as a proxy for the other.**

**Every one of the 49 declared tables carries exactly one class token in
§10's `Accumulator class` column**, drawn from the five below, gate-enforced
one-per-table. As with the P0e leg, **the leg asserts classhood, not
soundness** — a tree where all 49 read `excluded` passes it. See the stated
limitation at the end of this section, which is not a footnote.

### The five tokens

| Token | Mechanism | Pop behaviour |
| --- | --- | --- |
| `set-shaped` | Order-independent incremental accumulator (XOR / additive field hash) over per-element **canonical encodings**; update on insert, reverse on delete | **Pop-symmetric by construction** — *conditional on the per-table falsifier below* |
| `append-mostly` | Running chained hash `H_n = h(H_{n-1} ‖ x_n)` | **Pop-symmetric by checkpoint, NOT by construction** — see finding 1 |
| `small` | Full-domain digest every block | Trivially pop-symmetric (stateless recompute) |
| `derived` | Recompute from a **named source** through an **independently specified** derivation at declared checkpoint heights, and compare | Trivially pop-symmetric (stateless recompute) |
| `excluded` | Not folded, with a **named reason** from the three below | n/a |

**`excluded` is never bare.** Each excluded row's reason is one of:

- **non-chain** — pool and alt surface (`txpool_meta`, `txpool_blob`,
  `alt_blocks`, `archival_alt_attestation_witness`). Two honest nodes at the
  same height legitimately differ here. **This is a stronger commitment than
  v0's**: v0 excluded them for scope, the freeze excludes them for *all
  future digests*.
- **node-local** — content a node's own pruning policy legitimately varies
  (`txs_prunable`, `txs_prunable_tip`, `output_metadata`). Two honest nodes
  with different prune seeds hold different bytes. **Each such row names its
  surrogate**: `txs_prunable_hash` is digested (`append-mostly`) and *is* the
  integrity cover for `txs_prunable`'s content. The schema already separates
  the hash from the blob for exactly this reason.
- **dead** — declared but not live: `txs` (never written, DRS-W4) and
  `hf_starting_heights` (dropped at every writable `open()`, DRS-W5).
  Excluded because the domain is empty, not because divergence is tolerable.

### What the fold consumes (binds DRS-0 slice B's codecs)

The accumulator folds a **canonical encoding of the decoded logical value**,
never the storage bytes. This is forced, not stylistic: digest v0 is
deliberately layout-independent, and that property is what lets the C++ LMDB
implementation and the Rust redb implementation produce the *same* digest —
the entire basis of **DRS-E2**. A fold over storage bytes would make that
differential oracle impossible by construction, since LMDB stores
Monero-lineage structs and redb will store redb-native ones.

The cheapest correct design is therefore **one encoding per table serving
both roles** — the redb value codec *is* the canonical encoding, so the fold
is free on the redb side and the C++ side reaches the same function through
FFI by passing logical values, exactly the shape
`logical_state_digest.cpp:41` already has. Consequences that bind slice B:
no map iteration order, no varint with multiple valid encodings of one
value, no padding slack, no platform-dependent integer width, no float.
**A late encoding change is consensus-visible, not a refactor.**

**That last sentence is a design commitment with no mechanical enforcement
behind it today, and is recorded as such rather than left to imply one.**
Rule 42 (persisted-wire change ⇒ version-constant bump, CI-enforced) is
scoped by globs to the wallet crates; `rust/shekyl-chain-store` is outside
them. So at the moment this freeze lands, the codec stability it depends on
is a convention, not a gate. DRS-0 slice C's §11.1 states the matching rule
from the store side (a value-codec change bumps the store's
`schema_version`) and has the same gap. Extending rule 42's globs to cover
the chain-store crate is the mechanism that would close it; that is a
rules change, and it is escalated rather than assumed here.

**§6.3 independence, made checkable per value type:** *can the canonical
encoding be computed from the logical value alone, with no cursor, no txn,
no height counter and no previously-stored row?* If not, it is
writer-coupled and fails §6.3.

### The per-table falsifier for `set-shaped`

Set-shaped reversibility requires the element's canonical encoding be
**bit-identical at insert and delete**, or the XOR does not cancel. That is
a property of the *table*, not of the class, so it is established per row
rather than asserted class-wide.

**The falsifier run for this freeze, and its result:** for each of the
fifteen `set-shaped` tables, does the delete path have the stored element
**in hand**, or does it delete by key with the value never read? **The
answer is not uniform, and an earlier draft of this section said it was.**
Ten paths read the element back; five delete by key alone:

| Delete has the element | Mechanism |
| --- | --- |
| `spent_keys` | `remove_spent_key` — `MDB_GET_BOTH`; the element *is* the key image |
| `block_heights` | `remove_block` — element derived from the `mdb_block_info` read back |
| `tx_indices` | `remove_transaction_data` — whole `txindex` via `MDB_GET_BOTH` |
| `output_txs`, `output_amounts` | `remove_output` — stored `pre_rct_outkey` read back |
| `output_to_leaf`, `leaf_to_output` | `remove_output_leaf_mapping` — `mdb_get` then verify-before-delete |
| `block_pending_additions`, `pending_tree_drain` | range cursor walks holding `&v` |
| `archival_shard_segment` | `revert_archival_segment_freezes` — cursor walk holding `&v` |

| Delete by key ALONE — element never read | Call |
| --- | --- |
| `archival_bond` | `remove_archival_bond_record` — `mdb_del(txn, dbi, &k, nullptr)` |
| `archival_slash_applied` | `remove_archival_slash_applied` — same shape |
| `block_burn` | `remove_block_burn` — same shape |
| `curve_tree_roots` | `remove_curve_tree_root_at_height` — same shape |
| `pending_tree_leaves` | `remove_pending_tree_leaf` — same shape |

**This does not move any class**, because a `set-shaped` accumulator is
still reversible on those five — redb can always read before it deletes.
What it moves is the **obligation**: for those five the Rust store must
perform a read the C++ does not, and a port that transliterates
`mdb_del(…, nullptr)` into a bare redb `remove` desynchronizes the
accumulator silently. That is a specific instruction to DRS-0 slice B and
DRS-E1, and it only exists because the run was per-table.

**The general design rule, which holds for all fifteen: fold the value read
from the store, never the caller's argument.**
`remove_output_leaf_mapping` is why it is phrased that way — DRS-W13
records that the caller *reconstructs* `TreePosition` arithmetically
because the drain journal never recorded it, and the store defends itself
by reading the stored value back and throwing on mismatch. A fold over the
caller's argument would inherit W13's reconstruction; a fold over the
stored bytes does not. `output_to_leaf` and `leaf_to_output` are therefore
`set-shaped` **and** carry W13 as a live constraint on the Rust
implementation.

**Blind upsert is the second reversibility obligation, and four
`set-shaped` tables have one.** `put_archival_bond_value`,
`set_archival_slash_applied`, `add_block_burn` and
`store_curve_tree_root_at_height` all call `mdb_put(…, 0)` — flags `0`,
so an existing row is **overwritten without being read**. An XOR
accumulator over those tables must fold the old value *out* before folding
the new value *in*, which again requires a read the C++ does not perform.
An earlier draft of this section named `txpool_meta`'s `update_txpool_tx`
as "the live example" of an update path and noted it was `excluded`,
implying no `set-shaped` table had one. Four do, and they are the same
simple key→value tables that delete by key above.

### Comparator coupling — the seven `compare_hash32` tables

`BlockchainLMDB::compare_hash32` (`db_lmdb.cpp:236`) is **not**
lexicographic: it walks eight `uint32_t` words from word 7 down to word 0,
which on a little-endian host orders a 32-byte hash as a little-endian
256-bit integer — ascending lexicographic over the **reversed** byte string,
which is *not* descending lexicographic over the forward one. It governs
**key** order on `txpool_meta`, `txpool_blob`, `alt_blocks`,
`archival_alt_attestation_witness` and **duplicate** order on `spent_keys`,
`block_heights`, `tx_indices` (`db_lmdb.cpp:1759`–`:1774`). Full
characterisation belongs to the §6.4 divergence register, not here.

**It does not reach any fold under this freeze** — the three duplicate-order
tables are all `set-shaped` (order-independent), and the four key-order
tables are all `excluded`. **That is an accident of this assignment, not a
structural guarantee**, so it is recorded as a standing constraint: *if any
of these seven is ever regraded into an order-dependent class, the
comparator becomes digest-relevant and this row must be revisited.*

### Findings — three things the freeze establishes that §6.2 does not say

1. **`append-mostly` is not pop-symmetric by construction.** §6.2 grants
   that property to `set-shaped` only, and correctly: a running chained hash
   `H_n = h(H_{n-1} ‖ x_n)` cannot be reversed one step without retaining
   `H_{n-1}`. §6.2 leaves this unsaid, so a reader infers the property
   class-wide. **`blocks`, `block_info` and the `txs_*` family are
   pop-symmetric by checkpoint**, via the reopen-and-reconcile mechanism —
   not by construction.

2. **§6.2's fourth row is a cross-cutting mechanism, not a table class.**
   "Torn-commit / durability visibility — reopen + full-domain
   reconciliation at declared checkpoint heights" is a property of the
   *verification schedule*, not of any table: no table is "the torn-commit
   table". It applies to the two *incremental* classes (`set-shaped`,
   `append-mostly`) as the thing that bounds their drift. The five tokens
   above are per-table; checkpoint reconciliation is orthogonal to all five.

3. **"Archival journals → Small" is sound only for the pruned ones.** Small
   means a full-domain digest every block is cheap, which is a claim about a
   *bounded* domain. Seven archival tables carry a retention prune
   (`archival_attestation_witness`, `archival_budget`,
   `archival_budget_accrual`, `archival_r_market`, `archival_serve_credit`,
   `archival_settlement`, `archival_sigma_work`) and are bounded by it —
   **the prune is what makes Small viable, and without it the class is
   unbounded**. The six genuinely append-only journals
   (`archival_slash_log`, `archival_epoch_close_log`,
   `archival_emission_claim_log`, `archival_bond_unbond_log`,
   `archival_bond_holdings_update_log`, `archival_bond_rebond_log`) have no
   prune and are graded `append-mostly`, not `small`. Three further archival
   tables (`archival_bond`, `archival_slash_applied`,
   `archival_shard_segment`) are live keyed state, not journals, and are
   `set-shaped`.

### `derived` — why the class is legitimate and not merely convenient

`curve_tree_layers` and `curve_tree_checkpoints` are both functions of the
leaves, so an independent accumulator over them would assert their storage
is ground truth when it is not.

**Their named source is `curve_tree_leaves` for both, and for
`curve_tree_checkpoints` that is a correction rather than a restatement.**
`save_curve_tree_checkpoint` builds a row by *copying* `root`, `depth` and
`leaf_count` out of `curve_tree_meta`. Verifying a checkpoint against
`curve_tree_meta` would therefore compare a copy with its original: it
detects a bad copy and is blind to a bad tree, which is the degenerate case
the discriminator below exists to reject. The verification must recompute
from the **leaves**.

**Reconstructibility is a recovery property, not a digest exemption.**
DRS-D10 says non-block-corpus tables are rebuildable by replaying local
blocks; that tells you a detected problem is repairable, and says nothing
about detection. A derived table can be *stored wrong* — torn commit, writer
bug, a pop that reconstructs instead of reading back — and noticing is the
digest's job. Exempting derived tables because "we can always rebuild them"
builds a system that can repair a corruption it cannot see.

What reconstructibility buys is a **different mechanism**, not the absence
of one: recompute and compare, which checks the *derivation* rather than
only the storage. **That is only true if the verifier's derivation is
independent of the writer's** — otherwise both sides inherit the same
derivation bug and the comparison passes on identical wrong rows.
Canonicalizing independently does not fix this; it canonicalizes two copies
of the same error. Lifting the derivation into one shared pure function does
not fix it either; it makes the common mode tidier.

**The discriminator, checkable at assignment time:** *can the derived
table's contents be stated as a function of its named source without
reference to the writer's code?* If yes, `derived` is sound — verifier and
writer are two implementations of one spec. If the only definition of the
rows is "whatever `apply_block` wrote", the class degrades to a storage
check wearing a derivation check's label, and the table belongs in
`set-shaped` or `append-mostly` until someone writes the independent spec.
Both current `derived` rows pass: DRS-D3b makes `shekyl-fcmp` /
`shekyl-wire` the single source for leaf codecs, tree-position maps and hash
arithmetic, and forbids the daemon's grow/trim/drain from reimplementing any
of it — so the layer above a set of leaves is a stated pure function owned
by a different crate than the writer path.

**Why `curve_tree_roots` is `set-shaped` and not `derived`,** though it too
is a function of the leaves: consensus reads it directly
(`blockchain.cpp:3898`, `:4047`, `:4309`), so a wrong stored root is
*consumed* rather than merely stored. Folding the stored bytes catches that
divergence at the point it can do harm; recomputation is additional
assurance, not a substitute. `curve_tree_checkpoints` has no consensus
reader, so recomputation at checkpoint heights is sufficient for it. The
distinction is **consensus-read versus internal**, and it is stated here
because the next table assigned to either class will be argued by analogy.

**A `derived` row with no nameable source is a finding against D10's
universal wording, not a table-level exception.**

### Stated limitation of the gate — read before quoting any figure

**Pop symmetry is a design property the gate cannot check.** The class leg
asserts that every table carries exactly one of five tokens. It cannot
assert that a `set-shaped` assignment is actually reversible, that an
`append-mostly` table really has a checkpoint, or that a `derived` row's
source is independently specified.

This is demonstrated, not merely asserted: the negative control for this leg
marks `curve_tree_layers` — a table whose contents the pop path recomputes —
as `set-shaped`, and confirms **the gate stays GREEN**. So **"49/49
classified" means every table carries one of five tokens and nothing more.**
It is a statement on the *classhood* axis. The reversibility evidence lives
in the falsifier run above, per row, and in no exit code.

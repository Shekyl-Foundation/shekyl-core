# LMDB Write Atomicity Audit

**Date:** 2026-09-05 (DRS-P0b; supersedes the April 2026 audit in place)
**Pin:** `dev` `2dba46537` — every claim below was verified against this tree
**Scope:** every `BlockchainLMDB` write path at the pin: block connect, block
pop, the transaction pool, alt blocks, the two retention prunes, `reset()`,
and `migrate()`. One coverage row per `SHEKYL_LMDB_TABLES` entry — the count
is derived from the macro wherever it is used, never restated as a literal
(the schema-coverage gate pins the matrix to the macro in both directions).
**Goal:** confirm each logical mutation is fully contained in a single LMDB
transaction with no partial-commit risk — and record, for the redb store's
specification, every convention this layer keeps only in code (DRS-P0b
transcriptions A-2 / A-4 / A-6, and the §6.6 read-after-write edge set).

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
  tables, `archival_settlement`), −0. Both direction of each delta measured.
- **22 of the 49 live tables post-date the April audit** and had zero
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
| `hf_versions` not cleaned on pop | **Alive, unchanged — re-verified by the write-site census**: the table's only writers are `set_hard_fork_version` and `drop_hard_fork_info`; no pop-side remove exists among the 135 enumerated sites. Carried as the P0c wart row (`hf_versions` FIX-or-REPLICATE) |
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
2. The FCMP++ curve-tree block: `block_pending_additions` journal, the
   drain (auto-journaled per entry for `pop_block`), `grow_curve_tree`,
   then the segment-freeze connect hook at `prev_height + 1`. The in-code
   invariant (`:491`): *pending, drain, output↔leaf maps,
   `block_pending_additions`, and `curve_tree_*` tables MUST be mutated
   within the same `m_write_txn` as the block add — any partial commit here
   is a consensus split.*
3. Attestation witness store, keyed `archival_attestation_witness_key(prev_height)`.
4. `BlockchainLMDB::add_block` — block blob, `block_info`, `block_heights`.
5. The budget-accrual row at `prev_height` (F-B1a: written inside this
   funnel, before the hooks, not by `blockchain.cpp` after the fact).
6. `process_archival_slash_at_height(prev_height + 1)`.
7. `process_archival_epoch_close_at_height(prev_height + 1)` — which, at an
   epoch boundary, also runs the archival retention prune (§5a) in the same
   transaction.

Every step writes through `*m_write_txn` / `m_wcursors` under the block's
transaction; `set_hard_fork_version` joins it via `TXN_BLOCK_PREFIX`. No
`mdb_txn_commit` occurs mid-block; exceptions leave the transaction
uncommitted and `cleanup_handle_incoming_blocks` aborts the batch.

**Verdict: PASS** — one transaction per block (or per batch), including all
archival journal writes and the boundary-epoch prune.

## 3. Block pop (`BlockchainDB::pop_block`, `blockchain_db.cpp:695`)

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
  (`handle_block_to_main_chain`, `:6455`), a database whose blocks were
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
transaction and the pop-side invariant comment (`:841`) states the same
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

## 5b. `reset()` and `migrate()`

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

**Verdict: PASS** (`reset()`); `migrate()` is a non-write path by design.

## 5c. Standalone write paths outside any block

Two writers run under neither a block funnel nor a prune, and the coverage
matrix routes to this section:

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

- **the exception paths are asymmetric.** The size-mismatch guard aborts
  explicitly (`block_wtxn_abort()`) before throwing; the loop's own throws
  (`BLOCK_DNE` on a missing row, `DB_ERROR` on the put) do not, so they
  leave the write transaction open until the owning `mdb_txn_safe` unwinds
  it. No partial commit either way — but the two failure modes leave the
  writer in different states (**DRS-W8**);
- **it has no production caller.** The symbol resolves only to the
  interface declaration, the `testdb` stub, and this definition — the same
  unwired shape the census recorded for `set_archival_settlement`
  (CEN-L8). An unwired writer's atomicity is a claim about code nobody
  runs, which is worth knowing before the Rust store reproduces it.

**Verdict: PASS** (atomic by construction), with DRS-W8 recorded and the
unwired status flagged for the census.

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
| `archival_budget_accrual` remove | `removed_block_height − 1` | funnel step 5 at `prev_height` |
| attestation witness remove | `removed_block_height` | store at key `prev_height` (`archival_attestation_witness_key` adds the +1) |
| segment-freeze revert | height-free (row count) | hook at `prev_height + 1` |

**Why two bases — the in-code rationale, verbatim** (F-B5b,
`blockchain_db.cpp:735`-ff): *"the slash/close hooks key on the chain
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

From the load-bearing-order comments in the pop funnel (`:726`–`:790`),
as journal × fields × must-run-after × reason:

| Revert | Fields restored | Must run AFTER | Reason (from the comments) |
| --- | --- | --- | --- |
| slashes (`N` base) | `bonded_total`, `held_shard_ids`, `shard_add_epochs`, `bad_intervals` appends | — (first) | within a block, txs connect before the slash hook; pop mirrors in reverse |
| epoch close (`N` base) | epoch/budget close state | slashes | connect order mirror |
| emission claims (`N−1`) | claimed set, `first_paying_emission_height` | slashes + close | claims connect at tx-connect, before the hooks; **fields disjoint** from the slash revert's, so this one *could* compose either way — the order is the mirror, kept |
| unbonds (`N−1`) | `bonded_total`, holdings, interval log | slashes | defensive belt; a violation surfaces as `MISSING_CLEAN_CLOSE`, loud |
| holdings updates (`N−1`) | `bonded_total`, `held_shard_ids`, `shard_add_epochs` | slashes | **ORDER IS LOAD-BEARING**: the slash journal restores the very same fields; reverting in the wrong order makes the exactly-one-FLOOR delta check see `FLOOR ± slashed_amount` and abort the pop with `NotSingleShardDelta` |
| rebonds (`N−1`) | holdings/balance, closed interval | slashes | both journals touch `bad_intervals`; the slash revert strips its appended intervals before the rebond revert re-opens the journaled closed one |
| segment freezes (count) | frozen-segment counter | epoch-close revert | `:875`: counted against post-close state |

Inserting a new journal that touches `bonded_total`/`held_shard_ids`/
`bad_intervals` **between** any of these breaks the delta checks by
construction — the table above is the constraint surface the Rust store's
pop must reproduce or re-derive.

## 9. Transcription A-6, and the findings register

**A-6 — `m_write_txn` assertion census** (all sites in `db_lmdb.cpp`):
129 dereferences ride a caller-provided transaction with no local guard;
24 sites guard with `if (!m_write_txn) throw …`; 15 are lifecycle
assignments (batch/guard machinery and the §1 prune swap). The 24 guards
split into **two exception families**: 2 throw `DB_ERROR_TXN_START`
(inherited paths) and 22 throw bare `std::runtime_error("FATAL: …")`
(the archival/curve-tree generation). A `std::runtime_error` sails past
every `catch (DB_ERROR&)` recovery surface, so the same precondition
violation has two different crash behaviors depending on which table
tripped it.

| # | Finding | Grade | Disposition |
| --- | --- | --- | --- |
| DRS-W1 | Guard exception split: 22× `std::runtime_error` vs 2× `DB_ERROR_TXN_START` for the identical `!m_write_txn` precondition | wart (no unsound state; inconsistent failure surface) | RECORD-AND-SPECIFY: the Rust store has **one** typed precondition error; no C++ harmonization |
| DRS-W2 | `LockedTXN::commit` swallows `batch_stop` exceptions — silent commit failure (April note, still true) | wart | RECORD-AND-SPECIFY: Rust store commit is `Result`, callers must consume it |
| DRS-W3 | 129 unguarded `*m_write_txn` dereferences (null deref if a caller path ever arrives guardless — none found at the pin) | wart (latent) | RECORD-AND-SPECIFY: the Rust store's write handle is possession-typed; the precondition becomes unrepresentable |
| DRS-W4 | `txs` has **zero write and zero read sites** — the handle's only occurrence in `db_lmdb.cpp` is its `open()` (`:1662`); every live tx write goes to the pruned/prunable split. Verified wide across `src/` and `tests/` (the tests' `m_txs` is a test-local vector, not the handle) | wart (inherited-dead surface; no unsound state) | RECORD-AND-SPECIFY: the Rust store does not port the table. Deleting it here is a C++ **and** schema-version change, owned by the census/DRS lane, not by a docs pass |
| DRS-W5 | `hf_starting_heights` is `mdb_drop(…, del=1)`-deleted at every writable `open()` (`:1778`) and never re-created, so the **declared** table set (49) and the **runtime** set (48) differ permanently — and the coverage gate cannot see the class, since both sides of its comparisons derive from the same macro (§10) | wart (structural divergence between register and runtime; no unsound state) | RECORD-AND-SPECIFY, and routed to census **R4**, which owns the hardfork machinery. A runtime census is out of this pass's scope by design |
| DRS-W6 | The post-pop burn pair (`total_burned` reversal + `block_burn` row removal, `blockchain.cpp:896`–`:905`) sits at the **core layer, outside `BlockchainDB::pop_block`**. Two consequences: a batchless core-path caller pops in two transactions; and a caller popping through the DB funnel skips both writes entirely — **live today** via `blockchain_import --pop-blocks`, which calls `get_db().pop_block(...)` directly and documents why (§3). A database added through the verifying path and popped by that tool keeps burns the chain no longer contains | wart (**latent bookkeeping, live reachability** — graded on the complete five-site consumer census: RPC readout, connect add, pop reversal, and the two slash guards, both of which an *inflated* value satisfies with headroom; no emission, supply, or validation arithmetic consumes it — `shekyl-economics-sim/src/record.rs:143` refuses the `already_generated − total_burned` derivation on the record, and the conservation helper is KAT-only with synthetic operands. **Grade expires with its ground**: any consensus consumer of the scalar re-grades this at that consumer's design round) | RECORD-AND-SPECIFY: **derived-total reversal belongs in the pop funnel** in the Rust store, so popping through the store cannot mean something different from popping through the node |
| DRS-W7 | Three sites, three semantics for the same scalar's impossible value: the pop reversal **clamps** to floor (`blockchain.cpp:902`), the slash revert **throws** `FATAL` on underflow (`db_lmdb.cpp:6362`), the slash add **throws** `FATAL` on overflow (`:6050`) — the paths disagree about what an impossible `total_burned` means, so the node's behavior under a (today unreachable) divergence depends on which path meets it first: silent floor vs halt | wart (unreachable at the pin — see DRS-W6's reachability argument — but the disagreement is a standing trap for whichever future change arms it) | RECORD-AND-SPECIFY: the Rust store has **one** ruled semantic for an impossible derived total — and the ruling itself belongs to the economics lane, not the store |
| DRS-W8 | `correct_block_cumulative_difficulties` (`:3034`) aborts explicitly on its size-mismatch guard but not on its loop throws, so the same function leaves the write transaction in two different states depending on which failure fires — and it has **no production caller** (§5c) | wart (atomicity holds either way; unwired) | RECORD-AND-SPECIFY: one unwinding path in the Rust store. The unwired status is a census datum, the `set_archival_settlement`/CEN-L8 shape |
| — | `hf_versions` not cleaned on pop | carried | P0c wart row (owned there since April; not re-opened here) |
| — | Dead schema-doc row: `properties` key `staker_pool_balance` + both accessors, zero occurrences in `src/` | doc defect | fixed in this PR (`LMDB_SCHEMA.md` row and the Staking-section pointer) |

No finding is S-graded; nothing here blocks DRS-0, and nothing here adds
C++.

## 10. Coverage matrix — every table, its writers, its audited path

One row per `SHEKYL_LMDB_TABLES` entry (gate-pinned bijection; the row
count is the macro's length by construction). "Path §" points at the
section above whose verdict covers the table's writers.

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

| Table | Writers at the pin | Path § |
| --- | --- | --- |
| `alt_blocks` | `add_alt_block` / `remove_alt_block`; `drop_alt_blocks` (emptied) | §5 |
| `archival_alt_attestation_witness` | `store/remove_archival_alt_attestation_witness`; `drop_alt_blocks` | §5 |
| `archival_attestation_witness` | `store/remove_…_at_height`; `delete_…_before_height` (prune) | §2/§3/§5a |
| `archival_bond` | `put_archival_bond_value` / `remove_archival_bond_record` | §2/§3 |
| `archival_bond_holdings_update_log` | journal helpers | §2/§3/§7/§8 |
| `archival_bond_rebond_log` | journal helpers | §2/§3/§7/§8 |
| `archival_bond_unbond_log` | journal helpers (`archival_journal_put/delete`, param dbi) | §2/§3/§7/§8 |
| `archival_budget` | epoch close put; `delete_…_for/before_epoch` | §2/§5a |
| `archival_budget_accrual` | `add/remove_archival_budget_accrual`; `delete_…_before_height` | §2/§3/§5a |
| `archival_emission_claim_log` | journal helpers | §2/§3/§7/§8 |
| `archival_epoch_close_log` | `process/revert_archival_epoch_close_at_height` | §2/§3 |
| `archival_r_market` | epoch close put; `delete_…_for/before_epoch` | §2/§5a |
| `archival_serve_credit` | `set/remove_archival_serve_credit_bit`; `delete_…_before_epoch` (prune) | §2/§3/§5a |
| `archival_settlement` | `set_archival_settlement` (production caller = census question CEN-L8); `delete_…_for/before_epoch` | §5a/§9 |
| `archival_shard_segment` | `put_archival_shard_segment`; `revert_archival_segment_freezes`; corruption-test put | §2/§3 |
| `archival_sigma_work` | epoch close put; `delete_…_for/before_epoch` | §2/§5a |
| `archival_slash_applied` | `set/remove_archival_slash_applied` | §2/§3 |
| `archival_slash_log` | `append_archival_slash_log`; `revert_archival_slashes_at_height` | §2/§3 |
| `block_burn` | `add_block_burn` / `remove_block_burn` | §2/§3 |
| `block_heights` | `add_block` / `remove_block` | §2/§3 |
| `block_info` | `add_block` / `remove_block`; `correct_block_cumulative_difficulties` (own `block_wtxn`) | §2/§3/§5c |
| `block_pending_additions` | `add_block_pending_addition`; `remove_block_pending_additions` | §2/§3 |
| `blocks` | `add_block` / `remove_block` (`m_wcursors`) | §2/§3 |
| `curve_tree_checkpoints` | `save_curve_tree_checkpoint`; `prune_curve_tree_intermediate_layers` | §2/§3 |
| `curve_tree_layers` | `grow/trim_curve_tree`; `prune_curve_tree_intermediate_layers`; corruption-test del | §2/§3 |
| `curve_tree_leaves` | `grow_curve_tree` / `trim_curve_tree` | §2/§3 |
| `curve_tree_meta` | `grow/trim_curve_tree` | §2/§3 |
| `curve_tree_roots` | `store/remove_curve_tree_root_at_height` | §2/§3 |
| `hf_starting_heights` | **deleted at every non-read-only `open()`** (`mdb_drop` del=1, `:1778`); `drop_hard_fork_info`; finding DRS-W5 | §9 |
| `hf_versions` | `set_hard_fork_version` (`TXN_BLOCK_PREFIX`); `drop_hard_fork_info`; not cleaned on pop (P0c wart) | §2 |
| `leaf_to_output` | `add/remove_output_leaf_mapping` | §2/§3 |
| `output_amounts` | `add_output` / `remove_output` | §2/§3 |
| `output_metadata` | `store_output_metadata` | §2 |
| `output_to_leaf` | `add/remove_output_leaf_mapping` | §2/§3 |
| `output_txs` | `add_output` / `remove_output` | §2/§3 |
| `pending_tree_drain` | `add_pending_tree_drain_entry`; `remove_pending_tree_drain_entries` | §2/§3 |
| `pending_tree_leaves` | `add/remove_pending_tree_leaf`; `drain_pending_tree_leaves` | §2/§3 |
| `properties` | `open()` version seed; `set_total_bonded_atomic` / `set_total_burned` (incl. the post-pop burn reversal, `blockchain.cpp:896` — §3/DRS-W6); prune receipts (`note_archival_prune_watermark_epoch`, frozen-shard count, `pruning_seed`, `tx_prune_next_block`); `set_settlement_epoch_blocks_pin` (own txn) | §2/§5a/§5b/§5c |
| `spent_keys` | `add_spent_key` / `remove_spent_key` | §2/§3 |
| `tx_indices` | `add_transaction_data` / `remove_transaction_data` | §2/§3 |
| `tx_outputs` | `add_tx_amount_output_indices` / `remove_transaction_data` | §2/§3 |
| `txpool_blob` | `add/remove_txpool_tx` (`LockedTXN`); reset-kept | §4/§5b |
| `txpool_meta` | `add/update/remove_txpool_tx` (`LockedTXN`); reset-kept | §4/§5b |
| `txs` | **none** — opened (`:1662`), never written or read through its handle; finding DRS-W4 | §9 |
| `txs_pqc_auths` | `add_transaction_data` / `remove_transaction_data` (v11: kept by the depth prune) | §2/§3/§5a |
| `txs_prunable` | `add/remove_transaction_data`; `prune_worker`, `prune_tx_data` (own txns) | §2/§3/§5a |
| `txs_prunable_hash` | `add/remove_transaction_data` (v11: kept by the depth prune) | §2/§3/§5a |
| `txs_prunable_tip` | `add/remove_transaction_data`; `prune_worker` | §2/§3/§5a |
| `txs_pruned` | `add_transaction_data` / `remove_transaction_data` | §2/§3 |

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

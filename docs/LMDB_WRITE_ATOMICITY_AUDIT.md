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
| `pop_block_from_blockchain` staker-accrual `db_wtxn_guard` fix | **The claim-era write died; the guard survives, load-bearing for a successor** — `db_wtxn_guard` at `blockchain.cpp:896` now wraps the post-pop **burn-total reversal** (`get_block_burn` → `set_total_burned`), preserving exactly the defensive shape the April fix added; see §3 and W-6 |
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

One write lives **outside** the funnel: the core-level post-pop
**burn-total reversal** (`Blockchain::pop_block_from_blockchain`,
`blockchain.cpp:896`) reads `block_burn` for the popped height and lowers
the `total_burned` properties scalar, under `db_wtxn_guard` — the guard
the April fix introduced for the (now dead) staker-accrual reversal,
inherited by this successor write. Under a batch the guard is a no-op and
the reversal joins the pop's transaction; **standalone, it is a second
transaction after the pop's commit** — the same latent two-txn window the
April audit graded low for the accrual (production callers hold a batch),
carried forward as **W-6**: the Rust store's pop is one transaction,
derived-total reversals included.

**Verdict: PASS** (production callers batched; the standalone two-txn
window is W-6, latent) — and the pop-side invariant comment (`:841`)
states the same consensus-split consequence as connect's.

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
silent to callers. The latter is **wart row W-2** (§9) for the Rust store:
a store API where commit cannot fail silently.

**Verdict: PASS**, one baseline recorded, one wart carried.

## 5. Alt blocks and the detached witness table

`add_alt_block` / `remove_alt_block` operate on `*m_write_txn` cursors and
require the caller's transaction (callers: `handle_alternative_block` under
the incoming-blocks batch; `switch_to_alternative_blockchain`'s removal
loop, same batch; `drop_alt_blocks` via `reset()`'s own transaction). The
`archival_alt_attestation_witness` table is written beside the alt block
that owns it and its rows cannot outlive that block (one table, one owner —
the alt-block lifecycle, not the height prune, bounds it).

**Verdict: PASS.**

## 5a. Retention prunes — two paths, two shapes

**Archival retention prune** (`prune_archival_epochs_before`, `:7704`):
runs *inside* the epoch-close connect hook, under the block's transaction.
The watermark receipt is written **before** the deletions, same
transaction: commit lands floor and destruction together, abort lands
neither; no pop path reverts the receipt, so the floor never retreats
(the pop funnel's entry gate reads it). Seven families pruned; the
`archival_budget` walk early-breaks on the BE-ordered key where the others
scan-and-delete — an idiom difference, not a semantic one.

**Tx-data prune** (`prune_tx_data`, `:10144`): a standalone write path with
its **own** transaction, RAII-swapped into `m_write_txn` for the duration
(§1's last mechanism). v11 retention semantics: the depth pass keeps
`txs_prunable_hash` and `txs_pqc_auths` — the pruned-txid operands — when
it drops the prunable body.

**Verdict: PASS** on both; the receipt-before-destruction edge is R-2 in
the RAW set (§6).

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

## 6. Read-after-write dependency set (RAW edges, DRS §6.6)

The §6.6 seeds re-verified, one dead, and the live set enumerated:

| # | Edge | Where | Why it must hold |
| --- | --- | --- | --- |
| R-1 | `drain_pending_tree_leaves` → `grow_curve_tree` | connect step 2 | grow consumes the drained leaf set produced earlier in the same txn; splitting them plants leaves twice or never |
| R-2 | watermark receipt → the seven `delete_*` walks | `prune_archival_epochs_before` | the pop floor must never postdate the destruction it defends against |
| R-3 | budget-accrual rows (earlier blocks) → epoch-close range-sum | `process_archival_epoch_close_at_height` | cross-**block** reads: the close of epoch E sums accrual rows written by E's whole span; the retention window dominates the reorg window and the pop floor (R-2) defends the remainder |
| R-4 | slash-journal restore → holdings-update restore | pop funnel | shared fields (`bonded_total`, `held_shard_ids`, `shard_add_epochs`); §8's partial order |
| R-5 | witness read → pop → alt-store handoff | reorg (`switch_to_alternative_blockchain`) | the reorg reads the witness *before* popping and stores it beside the alt block; pop itself deletes the row |
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
| W-1 | Guard exception split: 22× `std::runtime_error` vs 2× `DB_ERROR_TXN_START` for the identical `!m_write_txn` precondition | wart (no unsound state; inconsistent failure surface) | RECORD-AND-SPECIFY: the Rust store has **one** typed precondition error; no C++ harmonization |
| W-2 | `LockedTXN::commit` swallows `batch_stop` exceptions — silent commit failure (April note, still true) | wart | RECORD-AND-SPECIFY: Rust store commit is `Result`, callers must consume it |
| W-3 | 129 unguarded `*m_write_txn` dereferences (null deref if a caller path ever arrives guardless — none found at the pin) | wart (latent) | RECORD-AND-SPECIFY: the Rust store's write handle is possession-typed; the precondition becomes unrepresentable |
| W-6 | Post-pop burn-total reversal (`blockchain.cpp:896`) is outside the pop funnel: one logical pop = two transactions for any standalone (batchless) caller — the April staker-guard finding's shape, inherited by the successor write | wart (latent; production callers hold a batch) | RECORD-AND-SPECIFY: the Rust store's pop is one transaction, derived-total reversals included |
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
runtime — and W-5 proves the two populations differ: `hf_starting_heights`
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
| `hf_starting_heights` | **deleted at every non-read-only `open()`** (`mdb_drop` del=1, `:1778`); `drop_hard_fork_info`; finding W-5 | §9 |
| `hf_versions` | `set_hard_fork_version` (`TXN_BLOCK_PREFIX`); `drop_hard_fork_info`; not cleaned on pop (P0c wart) | §2 |
| `leaf_to_output` | `add/remove_output_leaf_mapping` | §2/§3 |
| `output_amounts` | `add_output` / `remove_output` | §2/§3 |
| `output_metadata` | `store_output_metadata` | §2 |
| `output_to_leaf` | `add/remove_output_leaf_mapping` | §2/§3 |
| `output_txs` | `add_output` / `remove_output` | §2/§3 |
| `pending_tree_drain` | `add_pending_tree_drain_entry`; `remove_pending_tree_drain_entries` | §2/§3 |
| `pending_tree_leaves` | `add/remove_pending_tree_leaf`; `drain_pending_tree_leaves` | §2/§3 |
| `properties` | `open()` version seed; `set_total_bonded_atomic` / `set_total_burned` (incl. the post-pop burn reversal, `blockchain.cpp:896` — §3/W-6); prune receipts (`note_archival_prune_watermark_epoch`, frozen-shard count, `pruning_seed`, `tx_prune_next_block`); `set_settlement_epoch_blocks_pin` (own txn) | §2/§5a/§5b/§5c |
| `spent_keys` | `add_spent_key` / `remove_spent_key` | §2/§3 |
| `tx_indices` | `add_transaction_data` / `remove_transaction_data` | §2/§3 |
| `tx_outputs` | `add_tx_amount_output_indices` / `remove_transaction_data` | §2/§3 |
| `txpool_blob` | `add/remove_txpool_tx` (`LockedTXN`); reset-kept | §4/§5b |
| `txpool_meta` | `add/update/remove_txpool_tx` (`LockedTXN`); reset-kept | §4/§5b |
| `txs` | **none** — opened (`:1662`), never written or read through its handle; finding W-4 | §9 |
| `txs_pqc_auths` | `add_transaction_data` / `remove_transaction_data` (v11: kept by the depth prune) | §2/§3/§5a |
| `txs_prunable` | `add/remove_transaction_data`; `prune_worker`, `prune_tx_data` (own txns) | §2/§3/§5a |
| `txs_prunable_hash` | `add/remove_transaction_data` (v11: kept by the depth prune) | §2/§3/§5a |
| `txs_prunable_tip` | `add/remove_transaction_data`; `prune_worker` | §2/§3/§5a |
| `txs_pruned` | `add_transaction_data` / `remove_transaction_data` | §2/§3 |

Enumeration ground: 135 write call sites across 81 functions (79
`BlockchainLMDB::` methods + the two anonymous-namespace journal template
helpers, which take the `MDB_dbi` as a parameter — the three
non-member-handle write sites are those two plus `reset()`'s per-name local
dbi). `txs` is the one macro table with no write site (W-4), and
`hf_starting_heights` is deleted at every writable `open()` (W-5) — both in
§9's register.

---

*The April 2026 text this file replaces is preserved in git history at
`a17ccd0c81` (`git show a17ccd0c81:docs/LMDB_WRITE_ATOMICITY_AUDIT.md`);
its verdicts are records-was — true of a 29-table store with claim-era
staking and a live Monero migration ladder, none of which exist at this
pin.*

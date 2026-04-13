# LMDB Write Atomicity Audit

**Date:** April 2026
**Scope:** Every `BlockchainLMDB` write path reachable from block connect, block pop, tx pool mutations, alt blocks, and staking accrual/pool management.
**Goal:** Confirm that each logical mutation is fully contained in a single LMDB transaction with no partial-commit risk.

## Background

All LMDB writes go through one of three transaction mechanisms:

| Mechanism | Scope | When |
|---|---|---|
| **Batch** (`m_write_batch_txn` via `batch_start`/`batch_stop`) | Groups multiple blocks into one LMDB txn | Normal block ingestion from P2P and sync |
| **Block write guard** (`block_wtxn_start`/`block_wtxn_stop`) | Single write txn, or no-op when batch active | Genesis init, standalone pop, tests |
| **`TXN_BLOCK_PREFIX` macro** | Joins active batch/write txn, or opens its own | Auxiliary writes (`set_hard_fork_version`, properties) |

When a batch is active, `block_wtxn_start`/`stop` become no-ops (they only assert thread ownership). All `mdb_put`/`mdb_cursor_put` calls in the same batch share one LMDB transaction until `batch_stop` commits.

## Block Connect (`add_block`)

### Transaction coverage

All writes for a block connect are issued under one LMDB transaction:

| Write set | LMDB functions | Same txn? |
|---|---|---|
| Block header, block_info, block_heights | `mdb_cursor_put` via `m_wcursors` | Yes |
| Tx indices, txs_pruned, txs_pqc_auths, txs_prunable, etc. | `mdb_cursor_put` via `m_wcursors` | Yes |
| Output amounts, output_txs, tx_outputs | `mdb_cursor_put` via `m_wcursors` | Yes |
| Spent keys | `mdb_cursor_put` via `m_wcursors` | Yes |
| Hard fork version (`set_hard_fork_version`) | `mdb_put` via `TXN_BLOCK_PREFIX` | Yes (joins batch) |
| Pending tree leaves + drain journal | `mdb_put`/`mdb_del` on `*m_write_txn` | Yes |
| Curve tree leaves, layers, meta, checkpoints | `mdb_put` on `*m_write_txn` | Yes |
| Staker accrual record | `mdb_put` on `*m_write_txn` | Yes |
| Staker pool balance, total burned (properties) | `mdb_put` on `*m_write_txn` | Yes |

### Ordering within `BlockchainDB::add_block`

1. `add_transaction` for miner tx and each block tx (spent keys, tx data, outputs, indices)
2. FCMP++ pending/drain/grow + checkpoints (if `>= HF_VERSION_FCMP_PLUS_PLUS_PQC`)
3. `BlockchainLMDB::add_block` (block blobs, block_info, block_heights)
4. `HardFork::add` → `set_hard_fork_version`
5. Staking accrual, pool balance, burn updates (in `handle_block_to_main_chain`, post-`add_block`)

### Early return analysis

No `mdb_txn_commit` is called mid-block. Exceptions (`DB_ERROR`, `KEY_IMAGE_EXISTS`) leave the LMDB transaction uncommitted. The caller's `cleanup_handle_incoming_blocks` sets `m_batch_success = false` and aborts on failure. **No partial-commit risk.**

### Verdict: PASS

---

## Block Pop (`pop_block` / `pop_block_from_blockchain`)

### LMDB-level pop (`BlockchainLMDB::pop_block`)

Wraps `BlockchainDB::pop_block` in `block_wtxn_start`/`block_wtxn_stop` with a catch-all `block_wtxn_abort`. Within this scope:

| Write set | Same txn? |
|---|---|
| Block removal (blocks, block_info, block_heights) | Yes |
| Tx removal (tx_indices, txs_pruned, txs_prunable, etc.) | Yes |
| Output removal (output_amounts, output_txs) | Yes |
| Spent key removal | Yes |
| Claim pool balance restore (`set_staker_pool_balance` for `txin_stake_claim` inputs) | Yes |
| Curve tree trim + pending tree restore | Yes |

### Core-level pop (`Blockchain::pop_block_from_blockchain`)

After `m_db->pop_block` returns, the core reverses staker accrual records, pool balance, and burn totals. These writes must run under an active write transaction.

**Finding (fixed):** The staker accrual reversal (lines 690-708 in `blockchain.cpp`) previously ran without its own write transaction guard. All production callers (`pop_blocks`, `switch_to_alternative_blockchain`, `rollback_blockchain_switching`) have a batch active, so this was **not an active bug**, but was a latent risk if any future caller invoked `pop_block_from_blockchain` without a batch.

**Fix applied:** Wrapped the staker accrual reversal block in `db_wtxn_guard`, which is a no-op when a batch is already active but starts/commits its own write txn otherwise.

### `pop_blocks` (multi-block rewind)

Wraps all pops in `batch_start`/`batch_stop`. All `pop_block_from_blockchain` calls, txpool `add_tx` re-insertions, and staker accrual reversals share one LMDB transaction.

### Known issue: hf_versions not cleaned on pop

The code comment at line 653-655 notes that popping a block does not remove the corresponding `hf_versions` LMDB entry. `HardFork::on_block_popped` only adjusts in-memory state. This is a **logical inconsistency** (the LMDB table has one extra entry relative to the chain tip), not a data corruption risk — `hf_versions` is overwritten on re-add.

### Verdict: PASS (with fix applied for defensive guard)

---

## Transaction Pool

### Properly atomic paths

| Function | Mechanism | Verdict |
|---|---|---|
| `add_tx` | `LockedTXN` → `lock.commit()` | PASS |
| `take_tx` | `LockedTXN` → `lock.commit()` | PASS |
| `set_relayed` | `LockedTXN` → `lock.commit()` (line 934) | PASS |
| `remove_stuck_transactions` | `LockedTXN` → `lock.commit()` | PASS |
| `fill_block_template` | `LockedTXN` → `lock.commit()` | PASS |
| `validate` | `LockedTXN` → `lock.commit()` | PASS |

### Bug found and fixed: `get_relayable_transactions`

**Before fix:** The function created a `LockedTXN` at line 821 and called `m_blockchain.update_txpool_tx()` for Dandelion++ stem/forward timestamp updates, but returned **without calling `lock.commit()`**. The destructor called `abort()`, silently rolling back all timestamp updates on every invocation.

**Impact:** Dandelion++ stem/forward transaction relay timestamps were never persisted. Transactions in these states could be re-relayed prematurely or with stale timing data. This affected privacy (Dandelion++ timing resistance) but not consensus or fund safety.

**Fix applied:** Added `lock.commit()` before `m_next_check` assignment.

### `LockedTXN` nesting behavior

When a batch is already active (e.g., during block processing), `LockedTXN::batch_start()` returns `false`, and the inner `commit()`/`abort()` are no-ops. All writes piggyback on the outer batch. This is correct behavior but worth noting for future developers.

### `LockedTXN::commit` exception handling

`commit()` catches and logs exceptions from `batch_stop` but does not propagate them. Callers cannot distinguish a successful commit from a failed one without additional checks. This is a **design trade-off** (avoids double-throw in destructors) but means commit failures are silent.

### Verdict: PASS (with fix applied)

---

## Alt Blocks

### `add_alt_block` / `remove_alt_block`

Both use `CURSOR(alt_blocks)` which operates on `*m_write_txn`. They do not start their own transactions — they require an active write txn from the caller.

### Call paths

| Caller | Batch active? | Safe? |
|---|---|---|
| `handle_alternative_block` (via `add_new_block`) | Yes (from `prepare_handle_incoming_blocks`) | Yes |
| `switch_to_alternative_blockchain` (remove loop) | Yes (same batch context) | Yes |
| `drop_alt_blocks` (via `reset`) | Uses `db_wtxn_guard` | Yes |

### Verdict: PASS

---

## Staking-Specific Write Paths

### Block connect (accrual + pool + burn)

Covered under "Block Connect" above. All writes are in the same batch transaction.

### Block pop (accrual reversal)

Covered under "Block Pop" above. Now protected by `db_wtxn_guard`.

### Claim processing (`add_transaction` / `remove_transaction`)

Claim pool balance decrements (`set_staker_pool_balance`) in `add_transaction_data` and increments in `remove_transaction` both use `*m_write_txn` and are in the same transaction as the block they belong to.

**Note:** Multiple claim transactions in the same block each individually validate against the pool balance, then decrement sequentially. A warning log was previously added to flag cases where a claim amount exceeds the pool balance (indicating potential inter-tx over-claim). The sequential validation within one LMDB transaction ensures consistency.

### Verdict: PASS

---

## FCMP++ Curve Tree

### grow_curve_tree / trim_curve_tree

Both use `*m_write_txn` directly for leaves, layers, and meta updates. Checkpoint saves and intermediate layer prunes are in the same transaction.

### Pending tree lifecycle

`add_pending_tree_leaf`, `drain_pending_tree_leaves`, and drain journal entries all use `*m_write_txn`. The drain-then-grow sequence in `BlockchainDB::add_block` is atomic within the block's transaction.

### Verdict: PASS

---

## Summary of Fixes

| Issue | Severity | Status |
|---|---|---|
| `get_relayable_transactions` missing `lock.commit()` | Medium (privacy/Dandelion++) | **Fixed** |
| `pop_block_from_blockchain` staker accrual writes without defensive write txn guard | Low (latent risk, all current callers safe) | **Fixed** |
| `hf_versions` LMDB entry not removed on pop | Low (cosmetic, overwritten on re-add) | Known, not fixed (pre-existing) |

## Overall Assessment

The LMDB write layer is well-designed. The batch mechanism (`m_write_batch_txn`) provides strong atomicity guarantees for block processing, and `TXN_BLOCK_PREFIX` correctly joins existing transactions. The two issues found were a missing commit in a txpool helper and a missing defensive guard for a post-pop write path — neither caused data corruption in production paths. All FCMP++ curve tree operations and staking writes are properly scoped within their parent transactions.

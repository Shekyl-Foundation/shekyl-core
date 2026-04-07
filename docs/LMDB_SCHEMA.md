# LMDB Schema Reference

**Last updated:** April 2026
**DB version:** 6 (after migration `migrate_5_6`)
**Source:** `src/blockchain_db/lmdb/db_lmdb.cpp`, `src/blockchain_db/lmdb/db_lmdb.h`, `src/blockchain_db/blockchain_db.h`

## Conventions

### Byte order

All integer fields are stored in **native host byte order** (little-endian on x86-64 and ARM64). There is no explicit byte-order conversion in any write or read path. This means the LMDB files are architecture-dependent.

### Integer keys

Sub-databases opened with `MDB_INTEGERKEY` use 8-byte `uint64_t` keys. LMDB's built-in integer comparator orders them numerically.

### Zerokval pattern

Several `DUPSORT` tables use a **dummy primary key** of 8 zero bytes (`zerokval`). The real identifier is embedded in the fixed-size **duplicate value** and sorted by a custom `mdb_set_dupsort` comparator. This pattern enables efficient ordered iteration over the "real" key while using LMDB's dup-sort B-tree.

### Hash comparator

`compare_hash32` interprets a 32-byte `crypto::hash` as 8 consecutive `uint32_t` words in memory order and compares them lexicographically.

### String comparator

`compare_string` uses `strncmp` on the shorter length, breaking ties by length.

---

## Core Chain

### `blocks`

| Property | Value |
|---|---|
| LMDB name | `"blocks"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` block height (8 bytes) |
| Value | Serialized `block` blob (cryptonote binary archive). Variable length. |
| Comparators | None (LMDB default integer key ordering) |
| Writers | `add_block` (append with `MDB_APPEND`), `remove_block` (delete last) |
| Readers | `get_block_blob`, `get_block_blob_from_height` |
| Introduced | Genesis (DB v0) |

### `block_heights`

Maps block hash → height. Uses the zerokval pattern.

| Property | Value |
|---|---|
| LMDB name | `"block_heights"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Primary key | `zerokval` (8 zero bytes) |
| Value (dup) | `blk_height` struct, 40 bytes: |

```
Offset  Size  Field
0       32    crypto::hash bh_hash
32       8    uint64_t bh_height
```

| Property | Value |
|---|---|
| Dup sort | `compare_hash32` (sorts by `bh_hash`) |
| Writers | `add_block`, `remove_block` |
| Readers | `get_block_height`, `block_exists` |
| Introduced | Genesis (DB v0, migrated in v1) |

### `block_info`

Block metadata for fast lookups without deserializing the full block blob.

| Property | Value |
|---|---|
| LMDB name | `"block_info"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Primary key | `zerokval` (8 zero bytes) |
| Value (dup) | `mdb_block_info_4` struct, 96 bytes: |

```
Offset  Size  Field
0        8    uint64_t bi_height
8        8    uint64_t bi_timestamp
16       8    uint64_t bi_coins (already generated coins)
24       8    uint64_t bi_weight (block weight)
32       8    uint64_t bi_diff_lo (cumulative difficulty, low 64 bits)
40       8    uint64_t bi_diff_hi (cumulative difficulty, high 64 bits)
48      32    crypto::hash bi_hash
80       8    uint64_t bi_cum_rct (cumulative RCT output count)
88       8    uint64_t bi_long_term_block_weight
```

| Property | Value |
|---|---|
| Dup sort | `compare_uint64` (sorts by `bi_height`) |
| Writers | `add_block`, `remove_block` |
| Readers | `get_block_info`, `get_block_cumulative_difficulty`, `get_block_already_generated_coins`, etc. |
| Introduced | Genesis (DB v0, migrated through v2→v3→v4→v5 for struct growth) |

---

## Transactions

### `txs_pruned`

Unprunable prefix of serialized transactions.

| Property | Value |
|---|---|
| LMDB name | `"txs_pruned"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` tx_id (internal sequential ID, 8 bytes) |
| Value | First `pruned1_sz` bytes of the raw tx blob (unprunable prefix, up to PQC auth offset if applicable). Variable length. |
| Writers | `add_transaction_data`, `remove_transaction_data` |
| Readers | `get_pruned_tx_blob`, `get_pruned_tx_blobs_from` |
| Introduced | Genesis (DB v0) |

### `txs_pqc_auths`

PQC authentication data for v3+ transactions (second unprunable segment, between the classical prefix and the prunable suffix).

| Property | Value |
|---|---|
| LMDB name | `"txs_pqc_auths"` |
| Flags | `MDB_INTEGERKEY` |
| Key comparator | `compare_uint64` |
| Key | `uint64_t` tx_id (8 bytes) |
| Value | Byte slice `[pqc_auths_offset, unprunable_size)` from the tx blob. Variable length. Only present for non-coinbase transactions with `tx.version >= 3`. |
| Writers | `add_transaction_data` (conditional), `remove_transaction_data` |
| Readers | `get_pruned_tx_blob` (concatenates with txs_pruned) |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC (DB v6, `migrate_5_6`) |

### `txs_prunable`

Prunable suffix of serialized transactions (ring signatures, FCMP++ proofs, range proofs).

| Property | Value |
|---|---|
| LMDB name | `"txs_prunable"` |
| Flags | `MDB_INTEGERKEY` |
| Key comparator | `compare_uint64` |
| Key | `uint64_t` tx_id (8 bytes) |
| Value | Bytes from `unprunable_size` to end of tx blob. Variable length. |
| Writers | `add_transaction_data`, `remove_transaction_data` |
| Readers | `get_prunable_tx_blob`, `get_prunable_tx_hash` |
| Introduced | Genesis (DB v0) |

### `txs_prunable_hash`

Hash of the prunable section, kept for verification when the prunable data itself is discarded.

| Property | Value |
|---|---|
| LMDB name | `"txs_prunable_hash"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Key | `uint64_t` tx_id (8 bytes) |
| Value (dup) | `crypto::hash` (32 bytes) |
| Dup sort | `compare_uint64` (first 8 bytes of hash treated as uint64) |
| Writers | `add_transaction_data` (for tx version > 1), `remove_transaction_data` |
| Introduced | Genesis (DB v0) |

### `txs_prunable_tip`

Tracks which transactions are at the pruning frontier. Not opened in read-only mode.

| Property | Value |
|---|---|
| LMDB name | `"txs_prunable_tip"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Key | `uint64_t` tx_id (8 bytes) |
| Value (dup) | `uint64_t` block height at insertion (8 bytes) |
| Dup sort | `compare_uint64` |
| Writers | `add_transaction_data` (when pruning seed != 0), `remove_transaction_data` |
| Note | Only present when blockchain pruning is active. |
| Introduced | Genesis (DB v0) |

### `txs` (legacy)

| Property | Value |
|---|---|
| LMDB name | `"txs"` |
| Flags | `MDB_INTEGERKEY` |
| Note | Opened for DB version/migration compatibility. Current transaction data lives in `txs_pruned` / `txs_pqc_auths` / `txs_prunable`. Not used for normal writes in DB v6+. |

---

## Transaction Indices

### `tx_indices`

Maps transaction hash → internal tx_id, unlock_time, and block_id. Uses the zerokval pattern.

| Property | Value |
|---|---|
| LMDB name | `"tx_indices"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Primary key | `zerokval` (8 zero bytes) |
| Value (dup) | `txindex` struct, 56 bytes (`#pragma pack(1)`): |

```
Offset  Size  Field
0       32    crypto::hash key (tx hash)
32       8    uint64_t tx_id
40       8    uint64_t unlock_time
48       8    uint64_t block_id (height)
```

| Property | Value |
|---|---|
| Dup sort | `compare_hash32` (sorts by tx hash) |
| Writers | `add_transaction_data`, `remove_transaction_data` |
| Readers | `get_tx_data`, `tx_exists`, `get_tx_block_height` |
| Introduced | Genesis (DB v0) |

### `tx_outputs`

Maps tx_id → per-output amount-specific indices.

| Property | Value |
|---|---|
| LMDB name | `"tx_outputs"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` tx_id (8 bytes) |
| Value | Dense array of `uint64_t`, one per output in the transaction. Each is the amount-specific output index. Size = `num_outputs * 8`. |
| Writers | `add_tx_amount_output_indices`, `remove_transaction_data` |
| Readers | `get_tx_amount_output_indices` |
| Introduced | Genesis (DB v0, rebuilt in v1 migration) |

---

## Outputs

### `output_txs`

Maps global output index → (tx_hash, local_index). Uses the zerokval pattern.

| Property | Value |
|---|---|
| LMDB name | `"output_txs"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Primary key | `zerokval` (8 zero bytes) |
| Value (dup) | `outtx` struct, 48 bytes: |

```
Offset  Size  Field
0        8    uint64_t output_id (global output index)
8       32    crypto::hash tx_hash
40       8    uint64_t local_index (vout position within tx)
```

| Property | Value |
|---|---|
| Dup sort | `compare_uint64` (sorts by `output_id`) |
| Writers | `add_output`, `remove_output` |
| Readers | `get_output_tx_and_index_from_global`, `get_output_tx_and_index` |
| Introduced | Genesis (DB v0, rebuilt in v1 migration) |

### `output_amounts`

Maps (amount, amount_index) → output public key, unlock_time, height, and commitment.

| Property | Value |
|---|---|
| LMDB name | `"output_amounts"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Key | `uint64_t` amount (0 for RCT outputs, 8 bytes) |
| Value (dup) | Either `outkey` (96 bytes, for RCT/amount=0) or `pre_rct_outkey` (64 bytes, for non-zero amounts): |

**`outkey` (RCT, amount = 0), 96 bytes:**

```
Offset  Size  Field
0        8    uint64_t amount_index
8        8    uint64_t output_id (global)
16      32    crypto::public_key pubkey
48       8    uint64_t unlock_time
56       8    uint64_t height
64      32    rct::key commitment
```

**`pre_rct_outkey` (non-RCT, amount > 0), 64 bytes:**

```
Offset  Size  Field
0        8    uint64_t amount_index
8        8    uint64_t output_id (global)
16      32    crypto::public_key pubkey
48       8    uint64_t unlock_time
56       8    uint64_t height
```

| Property | Value |
|---|---|
| Dup sort | `compare_uint64` (sorts by `amount_index`) |
| Writers | `add_output`, `remove_output` |
| Readers | `get_output_key`, `get_output_data`, `for_all_outputs` |
| Note | Shekyl uses only RCT outputs (amount = 0), so all entries use the `outkey` layout. The `pre_rct_outkey` layout is retained for migration compatibility. |
| Introduced | Genesis (DB v0, rebuilt in v1 migration) |

### `output_metadata`

Pruning-safe output metadata, retained after transaction pruning.

| Property | Value |
|---|---|
| LMDB name | `"output_metadata"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` global output index (8 bytes) |
| Value | `output_pruning_metadata_t`, 88 bytes (`#pragma pack(1)`): |

```
Offset  Size  Field
0       32    crypto::public_key pubkey
32      32    rct::key commitment
64       8    uint64_t unlock_time
72       8    uint64_t height
80       1    uint8_t pruned (1 if parent tx prunable data removed)
81       7    uint8_t padding[7]
```

| Property | Value |
|---|---|
| Writers | `add_output` (when pruning enabled), `prune_tx_data` |
| Readers | `get_output_metadata` |
| Introduced | DB v6 |

---

## Spent Keys

### `spent_keys`

Set of all consumed key images. Uses the zerokval pattern.

| Property | Value |
|---|---|
| LMDB name | `"spent_keys"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Primary key | `zerokval` (8 zero bytes) |
| Value (dup) | `crypto::key_image` (32 bytes) |
| Dup sort | `compare_hash32` |
| Writers | `add_spent_key`, `remove_spent_key` |
| Readers | `has_key_image` |
| Introduced | Genesis (DB v0, rebuilt in v1 migration) |

---

## Staking

### `staker_accrual`

Per-block staking emission and fee pool records.

| Property | Value |
|---|---|
| LMDB name | `"staker_accrual"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` block height (8 bytes) |
| Value | `staker_accrual_record`, 32 bytes: |

```
Offset  Size  Field
0        8    uint64_t staker_emission
8        8    uint64_t staker_fee_pool
16       8    uint64_t total_weighted_stake
24       8    uint64_t actually_destroyed
```

| Property | Value |
|---|---|
| Writers | `add_staker_accrual` (block connect), `remove_staker_accrual` (block pop) |
| Readers | `get_staker_accrual` (claim validation, reward estimation) |
| Notes | `total_weighted_stake` is the sum of `shekyl_stake_weight(amount, tier)` for all active staked outputs at that height, excluding outputs past `lock_until`. When `total_weighted_stake == 0`, `actually_destroyed` records the staker inflow that was burned. |
| Introduced | HF1 (Shekyl genesis) |

### `staker_claims`

Per-staked-output watermark tracking the last claimed height.

| Property | Value |
|---|---|
| LMDB name | `"staker_claims"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` global output index of the staked output (8 bytes) |
| Value | `uint64_t` last_claimed_height (8 bytes) |
| Writers | `set_staker_claim_watermark` (after successful claim tx), `remove_staker_claim_watermark` (on staked output removal/pop) |
| Readers | `get_staker_claim_watermark` (claim validation: `from_height` must equal watermark) |
| Introduced | HF1 (Shekyl genesis) |

### `properties` — Staking keys

The `properties` table (see below) stores these staking-related entries:

| Key string | Value type | Description |
|---|---|---|
| `staker_pool_balance` | `uint64_t` (8 bytes) | Running balance of the staker reward pool. Incremented by emission + fee pool inflow per block (when stakers exist), decremented by successful claims. |
| `total_burned` | `uint64_t` (8 bytes) | Cumulative amount of SHEKYL destroyed (zero-staker burns + explicit burns). |

---

## FCMP++ Curve Tree

### `curve_tree_leaves`

Full-chain membership proof tree leaf nodes.

| Property | Value |
|---|---|
| LMDB name | `"curve_tree_leaves"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` global output index (0-based leaf order, 8 bytes) |
| Value | 128 bytes — 4 × 32-byte curve scalars forming the leaf tuple |
| Writers | `grow_curve_tree`, `trim_curve_tree` |
| Readers | `get_curve_tree_leaf`, leaf iteration for proof generation |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

### `curve_tree_layers`

Internal hash nodes of the curve tree, organized by layer and chunk.

| Property | Value |
|---|---|
| LMDB name | `"curve_tree_layers"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` composite: `(uint64_t(layer_index) << 56) \| chunk_index`. High 8 bits = layer, low 56 bits = chunk. |
| Value | 32 bytes — layer chunk hash |
| Writers | `grow_curve_tree`, `trim_curve_tree`, `prune_curve_tree_intermediate_layers` |
| Readers | `get_curve_tree_layer_chunk`, layer iteration |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

### `curve_tree_meta`

Small key-value store for tree state metadata.

| Property | Value |
|---|---|
| LMDB name | `"curve_tree_meta"` |
| Flags | None (plain) |
| Entries: | |

| Key (string) | Value | Size |
|---|---|---|
| `"root"` | Tree root hash | 32 bytes |
| `"leaf_count"` | `uint64_t` total leaves | 8 bytes |
| `"depth"` | `uint8_t` tree depth | 1 byte |

| Property | Value |
|---|---|
| Writers | `grow_curve_tree`, `trim_curve_tree` |
| Readers | `get_curve_tree_root`, `get_curve_tree_leaf_count`, `get_curve_tree_depth` |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

### `curve_tree_checkpoints`

Periodic snapshots of the tree state for efficient rollback.

| Property | Value |
|---|---|
| LMDB name | `"curve_tree_checkpoints"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` block height (8 bytes) |
| Value | 41 bytes: |

```
Offset  Size  Field
0       32    root hash
32       1    uint8_t depth
33       8    uint64_t leaf_count
```

| Property | Value |
|---|---|
| Writers | `save_curve_tree_checkpoint` (every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` blocks) |
| Readers | `get_curve_tree_checkpoint` (for rollback), `prune_curve_tree_intermediate_layers` |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

### `pending_tree_leaves`

Outputs that have been created but not yet matured into the curve tree.

| Property | Value |
|---|---|
| LMDB name | `"pending_tree_leaves"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Key | `uint64_t` maturity height (8 bytes) |
| Value (dup) | 128 bytes — leaf tuple data (same format as `curve_tree_leaves`) |
| Dup sort | LMDB default byte-order for dup data |
| Writers | `add_pending_tree_leaf` (block connect), removed by `drain_pending_tree_leaves` |
| Readers | `drain_pending_tree_leaves` (at maturity height) |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

### `pending_tree_drain`

Journal of leaves that were drained from `pending_tree_leaves` into the curve tree. Used for rollback: if a block is popped, these entries are restored to `pending_tree_leaves`.

| Property | Value |
|---|---|
| LMDB name | `"pending_tree_drain"` |
| Flags | `MDB_INTEGERKEY \| MDB_DUPSORT \| MDB_DUPFIXED` |
| Key | `uint64_t` block height where drain occurred (8 bytes) |
| Value (dup) | 136 bytes: |

```
Offset  Size  Field
0        8    uint64_t maturity_height (original pending key)
8      128    leaf tuple data
```

| Property | Value |
|---|---|
| Dup sort | LMDB default byte-order for dup data |
| Writers | `drain_pending_tree_leaves` (records what was drained) |
| Readers | `BlockchainDB::pop_block` (restores entries on rollback) |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

---

## Hard Fork Tracking

### `hf_versions`

Per-height hard fork version.

| Property | Value |
|---|---|
| LMDB name | `"hf_versions"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` height (8 bytes) |
| Value | `uint8_t` hard fork version (1 byte) |
| Writers | `set_hard_fork_version` (via `TXN_BLOCK_PREFIX`, joins active batch) |
| Readers | `get_hard_fork_version` |
| Note | Entries are not removed on block pop (known issue; see `LMDB_WRITE_ATOMICITY_AUDIT.md`). Overwritten on re-add. |
| Introduced | Genesis (DB v0) |

### `hf_starting_heights`

Scratch table used during initialization. Dropped after use.

| Property | Value |
|---|---|
| LMDB name | `"hf_starting_heights"` |
| Flags | `MDB_CREATE` |
| Note | Opened only in write mode; immediately dropped with `mdb_drop(..., 1)`. Not persisted. |

---

## Transaction Pool

### `txpool_meta`

Per-transaction metadata for the memory pool.

| Property | Value |
|---|---|
| LMDB name | `"txpool_meta"` |
| Flags | None special |
| Key comparator | `compare_hash32` |
| Key | `crypto::hash` txid (32 bytes) |
| Value | `txpool_tx_meta_t`, 192 bytes: |

```
Offset  Size  Field
0       32    crypto::hash max_used_block_id
32      32    crypto::hash last_failed_id
64       8    uint64_t weight
72       8    uint64_t fee
80       8    uint64_t max_used_block_height
88       8    uint64_t last_failed_height
96       8    uint64_t receive_time
104      8    uint64_t last_relayed_time
112      1    uint8_t kept_by_block
113      1    uint8_t relayed
114      1    uint8_t do_not_relay
115      1    bitfield: double_spend_seen:1, pruned:1, is_local:1,
               dandelionpp_stem:1, is_forwarding:1, fcmp_verified:1, bf_padding:2
116     32    crypto::hash fcmp_verification_hash
148     44    uint8_t padding[44]
```

| Property | Value |
|---|---|
| Writers | `add_txpool_tx`, `update_txpool_tx`, `remove_txpool_tx` |
| Readers | `get_txpool_tx_meta`, `for_all_txpool_txes` |
| Introduced | Genesis |

### `txpool_blob`

Raw transaction blobs in the memory pool.

| Property | Value |
|---|---|
| LMDB name | `"txpool_blob"` |
| Flags | None special |
| Key comparator | `compare_hash32` |
| Key | `crypto::hash` txid (32 bytes) |
| Value | Raw transaction blob. Variable length. |
| Writers | `add_txpool_tx`, `remove_txpool_tx` |
| Readers | `get_txpool_tx_blob`, `for_all_txpool_txes` |
| Introduced | Genesis |

---

## Alt Blocks

### `alt_blocks`

Alternative (orphan) block storage for reorg candidates.

| Property | Value |
|---|---|
| LMDB name | `"alt_blocks"` |
| Flags | None special |
| Key comparator | `compare_hash32` |
| Key | `crypto::hash` block id (32 bytes) |
| Value | `alt_block_data_t` (40 bytes) concatenated with block `blobdata`. Variable total length: |

```
Offset  Size  Field
0        8    uint64_t height
8        8    uint64_t cumulative_weight
16       8    uint64_t cumulative_difficulty_low
24       8    uint64_t cumulative_difficulty_high
32       8    uint64_t already_generated_coins
40       *    block blob (variable)
```

| Property | Value |
|---|---|
| Writers | `add_alt_block`, `remove_alt_block`, `drop_alt_blocks` |
| Readers | `get_alt_block`, `for_all_alt_blocks` |
| Introduced | Genesis |

---

## Properties

### `properties`

General key-value store for database-level metadata.

| Property | Value |
|---|---|
| LMDB name | `"properties"` |
| Flags | None special |
| Key comparator | `compare_string` |
| Key | ASCII string (variable length, some NUL-terminated, some not) |

**Known entries:**

| Key | Value type | Description |
|---|---|---|
| `"version"` (NUL-terminated) | `uint32_t` | Database schema version (currently 6) |
| `"pruning_seed"` (NUL-terminated) | `uint32_t` | Blockchain pruning seed |
| `"tx_prune_next_block"` (NUL-terminated) | `uint64_t` | Next block height for tx pruning |
| `"last_pruned_tx_data_height"` (NUL-terminated) | `uint64_t` | Height of last pruned tx data |
| `"staker_pool_balance"` (no NUL) | `uint64_t` | Running staker reward pool balance |
| `"total_burned"` (no NUL) | `uint64_t` | Cumulative destroyed SHEKYL |

| Property | Value |
|---|---|
| Writers | Various — `set_staker_pool_balance`, `set_total_burned`, migration code, pruning code |
| Readers | Various — `get_staker_pool_balance`, `get_total_burned`, `get_blockchain_pruning_seed`, etc. |
| Introduced | Genesis (DB v0) |

---

## Summary Table

| # | LMDB name | Key type | Value type | Size | Flags |
|---|---|---|---|---|---|
| 1 | `blocks` | `uint64_t` height | block blob | var | `INTEGERKEY` |
| 2 | `block_heights` | zerokval | `blk_height` | 40 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 3 | `block_info` | zerokval | `mdb_block_info_4` | 96 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 4 | `txs_pruned` | `uint64_t` tx_id | tx prefix blob | var | `INTEGERKEY` |
| 5 | `txs_pqc_auths` | `uint64_t` tx_id | PQC auth blob | var | `INTEGERKEY` |
| 6 | `txs_prunable` | `uint64_t` tx_id | prunable blob | var | `INTEGERKEY` |
| 7 | `txs_prunable_hash` | `uint64_t` tx_id | `crypto::hash` | 32 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 8 | `txs_prunable_tip` | `uint64_t` tx_id | `uint64_t` height | 8 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 9 | `tx_indices` | zerokval | `txindex` | 56 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 10 | `tx_outputs` | `uint64_t` tx_id | `uint64_t[]` indices | var | `INTEGERKEY` |
| 11 | `output_txs` | zerokval | `outtx` | 48 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 12 | `output_amounts` | `uint64_t` amount | `outkey`/`pre_rct_outkey` | 96/64 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 13 | `output_metadata` | `uint64_t` global_idx | `output_pruning_metadata_t` | 88 | `INTEGERKEY` |
| 14 | `spent_keys` | zerokval | `crypto::key_image` | 32 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 15 | `staker_accrual` | `uint64_t` height | `staker_accrual_record` | 32 | `INTEGERKEY` |
| 16 | `staker_claims` | `uint64_t` output_idx | `uint64_t` height | 8 | `INTEGERKEY` |
| 17 | `curve_tree_leaves` | `uint64_t` output_idx | leaf tuple | 128 | `INTEGERKEY` |
| 18 | `curve_tree_layers` | `uint64_t` composite | chunk hash | 32 | `INTEGERKEY` |
| 19 | `curve_tree_meta` | string | varies | varies | — |
| 20 | `curve_tree_checkpoints` | `uint64_t` height | snapshot | 41 | `INTEGERKEY` |
| 21 | `pending_tree_leaves` | `uint64_t` maturity | leaf tuple | 128 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 22 | `pending_tree_drain` | `uint64_t` height | maturity+leaf | 136 | `INTEGERKEY\|DUPSORT\|DUPFIXED` |
| 23 | `hf_versions` | `uint64_t` height | `uint8_t` version | 1 | `INTEGERKEY` |
| 24 | `txpool_meta` | `crypto::hash` txid | `txpool_tx_meta_t` | 192 | — |
| 25 | `txpool_blob` | `crypto::hash` txid | tx blob | var | — |
| 26 | `alt_blocks` | `crypto::hash` blkid | meta + blob | var | — |
| 27 | `properties` | string | varies | varies | — |
| 28 | `txs` (legacy) | `uint64_t` tx_id | — | — | `INTEGERKEY` |

Total: **28 sub-databases** (27 active + 1 legacy migration stub).

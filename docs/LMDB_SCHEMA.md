# LMDB Schema Reference

**Last updated:** August 2026
**DB version:** 10 (schema v10: serve-credit key widened 48 → 56 B — `BE(block_height)` appended, one row per challenge (PC-D4) — with the additive `archival_settlement` table riding the boundary; v9: block header gains `attestation_root` (+32 B block blob), witness tables ride; v8: persisted pop-symmetric frozen-shard counter; v7: composite-key pending/drain tables, output↔leaf mapping)
**Source:** `src/blockchain_db/lmdb/db_lmdb.cpp`, `src/blockchain_db/lmdb/db_lmdb.h`, `src/blockchain_db/blockchain_db.h`, `src/blockchain_db/shekyl_types.h`

## Conventions

### Byte order

All integer fields are stored in **native host byte order** (little-endian on x86-64 and ARM64). There is no explicit byte-order conversion in any write or read path. This means the LMDB files are architecture-dependent.

### Integer keys

Sub-databases opened with `MDB_INTEGERKEY` use 8-byte `uint64_t` keys in **native-endian** layout. LMDB's built-in integer comparator orders them numerically.

### Big-endian composite keys (Shekyl curve-tree state)

Shekyl-specific curve-tree tables (`pending_tree_leaves`, `pending_tree_drain`, `block_pending_additions`) use 16-byte composite keys encoded as `BE(field_1) || BE(field_2)` in big-endian byte order. LMDB's default byte-wise comparator then yields canonical `(field_1, field_2)` sort order without custom comparators. These tables do **NOT** use `MDB_INTEGERKEY` (which expects native-endian single integers) or `MDB_DUPSORT`. The typed key/value encoders in `src/blockchain_db/shekyl_types.h` encapsulate the byte layout.

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

### `block_burn`

Per-height destroyed-amount record (the adaptive fee burn's destroyed
share), so `pop_block` can roll `total_burned` back without recomputing the
block's burn.

| Property | Value |
|---|---|
| LMDB name | `"block_burn"` |
| Flags | `MDB_INTEGERKEY \| MDB_CREATE` |
| Key | `uint64_t` block height (8 bytes, native-endian) |
| Value | `uint64_t` burned amount (8 bytes, native-endian) |
| Writers | `add_block_burn` (`handle_block_to_main_chain`, only when the amount is nonzero — absent height reads as 0), `remove_block_burn` (`pop_block_from_blockchain`) |
| Readers | `get_block_burn` (`MDB_NOTFOUND` reads as 0) |

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

Prunable suffix of serialized transactions (`CtSigPrunable`: Bulletproof+ range proofs, pseudo-outs, and the opaque FCMP++ membership-proof blob).

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
64      32    ct::key commitment
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
32      32    ct::key commitment
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

The claim-era `staker_accrual` / `staker_claims` tables were **deleted with
the claim-era C++ wire** (PR-4 retirement); staker inflow now persists
through `archival_budget_accrual` → `archival_budget` (below). The coverage
gate refuses a section for a table that is no longer in the live list.

### `archival_serve_credit`

Affirmative serve-credit pass per `(P_id, shard_id, settlement_epoch, block)`
— **per CHALLENGE, not per pair-epoch** (`PC-D4`). A pair-epoch holds up to
`CHALLENGES_PER_PAIR_PER_EPOCH` rows, one per block that challenged it, and
consensus counts passes by **enumerating** them: no field anywhere carries a
tally (`PC-D1`/`PC-D5`).

| Property | Value |
|---|---|
| LMDB name | `"archival_serve_credit"` |
| Flags | `MDB_CREATE` (composite key; no `INTEGERKEY`) |
| Key | `P_id[32] \|\| BE(shard_id) \|\| BE(settlement_epoch) \|\| BE(block_height)` (**56 bytes**) |
| Value | `uint8_t` `0x01` (presence flag; key existence is the authoritative bit) |
| Writers | `set_archival_serve_credit_bit` (on archival vin block connect, at the block's INDEX), `remove_archival_serve_credit_bit` (reorg `pop_block`, at the same index) |
| Readers | `has_archival_serve_credit_bit` (the EXACT per-challenge question), `archival_serve_credit_pass_count` (the pair-epoch enumeration; the prefix scan every "did this pair serve at all" caller wants) |
| Encoder | `shekyl::db::ArchivalServeCreditKey` in `blockchain_db/shekyl_types.h` |
| Introduced | HF1 (Shekyl genesis; gate-2 §10 step 3) |

**Field order is load-bearing.** `BE(block_height)` is **appended**, so offsets
0..47 are exactly the pair-epoch layout: the epoch stays at offset 40, which is
what lets `delete_archival_serve_credit_before_epoch` and the cursor scans keep
working by construction rather than by re-audit. The 48-byte prefix is
`shekyl::db::ArchivalPairEpochKey`, which is a **different type** for the tables
that are per-pair-epoch by design (`archival_slash_applied`,
`archival_settlement`) — see `ARCHIVAL_PER_CHALLENGE_RECORD.md` §5.2.

### `archival_settlement`

Three-valued settlement verdict per `(P_id, shard_id, settlement_epoch)`
(`SO-D1`/`SO-D2`). **One row per pair with `issued >= 1`** — a pair the urn
never reached is recorded by its ABSENCE, which is what makes *absent ⇒ never
issued* a theorem about the writer rather than an inference. `issued = 0` is
refused at the boundary (`SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_ZERO`), on both
the write and the read.

| Property | Value |
|---|---|
| LMDB name | `"archival_settlement"` |
| Flags | `MDB_CREATE` (composite key; no `INTEGERKEY`) |
| Key | `P_id[32] \|\| BE(shard_id) \|\| BE(settlement_epoch)` (48 bytes) |
| Value | `outcome \|\| passes \|\| issued` (3 bytes) — `0x01` Served, `0x02` Missed, `0x03` NonObservation; `0x00` is deliberately not a live tag |
| Writers | `set_archival_settlement` — **not wired to production yet** (`SO-D8`); when it lands it runs inside the slash scheduler's per-epoch pass (`SO-D7`), not at a separate epoch-close event |
| Readers | `get_archival_settlement` |
| Revert | `delete_archival_settlement_for_epoch` (reorg crossing a fold — the row is a memoised derivation over final chain state, so it is DELETED and recomputed rather than journalled) |
| Prune | `delete_archival_settlement_before_epoch`, from `prune_archival_epochs_before` |
| Encoder | key `shekyl::db::ArchivalPairEpochKey`; **value encoded in Rust only** |
| Introduced | HF1 (Shekyl genesis) |

**C++ never composes the value.** Rust folds `(passes, issued)` and emits the
three bytes (`shekyl_archival_settlement_row`), so a row whose outcome
contradicts its counts is not a state this side can express. The FFI writes
nothing on any refusal, so a caller that ignored the return code still cannot
store a fabricated settlement. The 3-byte length is a fixed-size FFI contract
agreed at compile time on both sides (`SHEKYL_ARCHIVAL_SETTLEMENT_ROW_BYTES`,
rule 40).

**Keyed by `ArchivalPairEpochKey`, not `ArchivalServeCreditKey`.** `SO-D2`
ruled the two byte-identical so one key could probe both tables; `PC-D4` then
widened the serve-credit key to 56 B while this table stayed per-pair-epoch, so
the shared-key rationale is **retired rather than broken** — the tables answer
at different granularities, evidence per challenge and verdict per pair-epoch
(`ARCHIVAL_PER_CHALLENGE_RECORD.md` §5.2).

**Not merged with `archival_serve_credit`.** This table records a NEGATIVE
(Missed), while every consumer of the serve-credit ledger reads key-presence as
"pay this pair" — so a Missed cell there would corrupt vin-dedup and emission at
once (`SO-D4.3`).

### `archival_bond`

Gate-4 `ArchivalBondRecord` substrate for serve-credit and emission reads
(`ARCHIVAL_CONSENSUS_STATE.md` §3.4). Written on JoinMarket bond-post connect
(gate-4 §3.4.1).

| Property | Value |
|---|---|
| LMDB name | `"archival_bond"` |
| Flags | `MDB_CREATE` |
| Key | `P_id[32]` (`P_canonical_id`) |
| Value | versioned `ArchivalBondValue` blob (v4 only at genesis: hybrid pubkey, **`bond_spend_pk`** (GF-1 debit authorizer, gate-4 §4.1), `E_join`, `bonded_total_atomic`, `holdings_kind`, shard set or CompleteTree sentinel, bad intervals, claimed settlement epochs, `first_paying_emission_height`; v1–v3 decode rejected) |
| Writers | `put_archival_bond_record` (join/re-bond connect), `remove_archival_bond_record` (reorg) |
| Readers | `get_archival_bond_hybrid_pubkey`, `archival_bond_join_epoch`, `archival_bond_good_through`, `archival_bond_holds_shard` |
| Encoder | `shekyl::db::ArchivalBondValue` in `blockchain_db/shekyl_types.h` |
| Introduced | HF1 (gate-4 substrate; gate-2 §5.3 steps 2–3 reads) |

v4 layout (`REWARD_EMISSION_LEG.md` §6.2/§6.3, pinned 2026-06-11; `bond_spend_pk`
amended in per `ARCHIVAL_BOND_GATE4.md` §4.1, 2026-06-16 — committed at JoinMarket,
immutable, and bound into the bond-post sig-preimage (gate-4 §3.4.1), so the
persisted record must carry it. Pre-genesis amendment: no migration, reset
data-dir per the v4 posture; the field is in the genesis v4, not a v5 bump):

```text
u8  version (= 4)
u16 BE pubkey_len ‖ pubkey bytes              (≤ 2048)   // P_pubkey (account identity)
u16 BE bond_spend_pk_len ‖ bond_spend_pk      (≤ 2048)   // GF-1 debit authorizer (gate-4 §4.1); committed at JoinMarket, immutable
u64 BE join_settlement_epoch
u64 BE bonded_total_atomic
u8  holdings_kind (0 = shard set, 1 = CompleteTree)
u32 BE holdings_count ‖ u64 BE shard ids      (≤ 4096)
u32 BE bad_interval_count ‖ (u64 BE start, u64 BE end_exclusive) pairs (≤ 256)
u32 BE claimed_count ‖ u64 BE claimed epochs  (≤ 32 = W + 6, strictly
                                               increasing, span ≤ W)
u64 BE first_paying_emission_height
```

`first_paying_emission_height` sentinel `0` = unset; unreachable as a real
value because no emission can pay before the first settlement epoch closes at
height `SETTLEMENT_EPOCH_BLOCKS` (10_000). Claimed-set mutation semantics
(windowed dedup `check_and_set`, prune below `current − W`) are consensus
rules and live in Rust only (`shekyl-archival-retention::claimed_epochs`); the
codec stores and validates the at-rest shape. The cap and span bounds derive
from `max_claim_age_w` in `config/consensus_constants.json`
(`SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W`).

### `archival_r_market`

Serve-credit-weighted `R_market(shard, E)` snapshot at epoch close (`ARCHIVAL_CONSENSUS_STATE.md` §3.3).

| Property | Value |
|---|---|
| LMDB name | `"archival_r_market"` |
| Flags | `MDB_CREATE` |
| Key | `BE(shard_id) \|\| BE(settlement_epoch)` (16 bytes) |
| Value | `BE(u64)` count |
| Writers | `process_archival_epoch_close_at_height` |
| Readers | `get_archival_r_market` |
| Reorg | `revert_archival_epoch_close_at_height` deletes epoch materialization |

### `archival_sigma_work`

Per-epoch `Σwork(E)` milli accumulator (`ARCHIVAL_CONSENSUS_STATE.md` §3.5).

| Property | Value |
|---|---|
| LMDB name | `"archival_sigma_work"` |
| Flags | `MDB_CREATE` |
| Key | `BE(settlement_epoch)` (8 bytes) |
| Value | `BE(u64)` sigma milli |
| Writers | `process_archival_epoch_close_at_height` |
| Readers | `get_archival_sigma_work_milli` |
| Prune | `prune_archival_epochs_before` when `E < tip − W` |

### `archival_budget_accrual`

Per-height staker-inflow accrual row (`ARCHIVAL_BUDGET_SCHEDULE.md` §3.1),
summed once per epoch into the frozen `archival_budget` close row.

| Property | Value |
|---|---|
| LMDB name | `"archival_budget_accrual"` |
| Flags | `MDB_CREATE` |
| Key | `BE(block_height)` (8 bytes; `shekyl::db::ArchivalBudgetAccrualKey`, an alias of `ArchivalEpochCloseLogKey`) |
| Value | `BE(u64)` staker-inflow amount (atomic units) |
| Writers | `add_archival_budget_accrual` (from `BlockchainDB::add_block`, keyed at `prev_height`), `remove_archival_budget_accrual` (`pop_block`) |
| Readers | `get_archival_budget_accrual` (`MDB_NOTFOUND` reads as 0), the close's bounded range-sum in `process_archival_epoch_close_at_height` |
| Prune | `prune_archival_epochs_before` via `delete_archival_budget_accrual_before_height` at the retained epoch's open height |

**Burn-record idiom:** the row is persisted only when the amount is nonzero —
absent height reads as 0, and the pop removes the height row. BE keys make
cursor order numeric order, which the close's range-sum over
`[E·SEB, (E+1)·SEB)` and the prune walk depend on. Revert is asymmetric to
the budget row's: accrual rows revert with their own block's pop, so a
pop-and-re-close re-sums the retained rows plus the re-connecting block's
fresh row and reproduces the budget byte-identically (§3.2, KAT B3). The sum
aborts on u64 wrap rather than minting
(`FATAL: archival budget accrual sum overflow on close`).

### `archival_budget`

Frozen `budget(E)` close row (`ARCHIVAL_BUDGET_SCHEDULE.md` §3.2): the
bounded range-sum of the accrual rows over `[E·SEB, (E+1)·SEB)`, written in
the same txn as the sigma row so budget and denominator freeze in the same
close event (the M1 same-snapshot pin).

| Property | Value |
|---|---|
| LMDB name | `"archival_budget"` |
| Flags | `MDB_CREATE` |
| Key | `BE(settlement_epoch)` (8 bytes; `shekyl::db::ArchivalBudgetKey`, an alias of `ArchivalSigmaWorkKey`) |
| Value | `BE(u64)` budget (atomic units) |
| Writers | `process_archival_epoch_close_at_height` (put), `revert_archival_epoch_close_at_height` via `delete_archival_budget_for_epoch` |
| Readers | `get_archival_budget` (`MDB_NOTFOUND` laundered to 0), `has_archival_budget_row` (LMDB-class-only existence probe), `gather_archival_emission_window_snapshots` |
| Prune | `prune_archival_epochs_before` via `delete_archival_budget_before_epoch` |

**Written unconditionally, including zero:** a present-and-zero row is a
closed zero-budget epoch (§5, structurally non-claimable), distinguishable
from never-closed-or-pruned (`MDB_NOTFOUND` → gather failure, reject) — the
distinction `has_archival_budget_row` exists to make. The verify-side gather
reads the stored value and never re-sums the accrual rows (§3.3).

### `archival_epoch_close_log`

Journal: block heights that finalized an epoch (pop revert).

| Property | Value |
|---|---|
| LMDB name | `"archival_epoch_close_log"` |
| Key | `BE(block_height)` |
| Value | `BE(settlement_epoch)` finalized at close |

### `archival_shard_segment`

Frozen segment metadata per `shard_id` (gate-2 §9;
`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`; `CURVE_TREE_CLIENT.md` §7.2).

Rows are written by the segment-freeze connect hook at the block whose
same-txn `grow_curve_tree` first crosses a `SEGMENT_LEAF_COUNT` (25 992)
boundary: `freeze_height` = that block's height (first-crossing rule, O-2
per-branch monotone), `R_k` = the layer-2 chunk hash the grow computed
(MMR-final). The pop hook deletes rows whose segment un-completes after the
same-txn `trim_curve_tree` (O-3 pop-symmetry: re-applying the block rewrites
a bit-identical row). Writer/deleter one-site and the cursor accounting are
CI-enforced (`scripts/ci/check_segment_freeze_sites.sh` — renamed from
`check_reward_gate_predicate_sites.sh` at the M1 gate's retirement, PR #346; the
writer/deleter one-site and counting-read invariants survived the split intact).

The row count is mirrored by the persisted `"archival_frozen_shard_count"`
counter in `properties` (V8; `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §4.4):
+1 on put (`MDB_NOOVERWRITE` — rows are CREATE-only), −1 per row deleted on
revert, same write transaction. `count_frozen_shards_at_close` reads the
counter in O(1) and frontier-checks the `MDB_LAST` row (decode + boundary);
the O(N) walk survives only as the differential test oracle
`count_frozen_shard_rows_by_walk_for_test`.

| Property | Value |
|---|---|
| LMDB name | `"archival_shard_segment"` |
| Flags | `MDB_CREATE` |
| Key | `BE(shard_id)` (8 bytes) |
| Value | `ArchivalShardSegmentValue` — `freeze_height`, `segment_leaf_count`, `R_k[32]` |
| Writers | `process_archival_segment_freezes_at_height` → `put_archival_shard_segment` (sole production caller) |
| Readers | `get_archival_shard_segment_at_height`, `count_frozen_shards_at_close` (M1 gate operand) |
| Reorg | `revert_archival_segment_freezes` (reverse walk deleting rows above the post-trim frontier) |
| Introduced | HF1 (gate-2 verifier step 6) |

The former `archival_shard_leaf` table (Selene leaf-layer scalar chunks per
challenged index) is **deleted** (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`
§6.2): it was a derived copy of `m_curve_tree_leaves`, and the serve-credit
challenge path now derives the global chunk bounds via
`shekyl_archival_challenge_leaf_chunk_bounds` and reads the 38-leaf chunk
from the curve tree directly.

### `archival_slash_applied`

Slash idempotency per `(P_id, shard_id, settlement_epoch)` (gate-4 §4.2).

| Property | Value |
|---|---|
| LMDB name | `"archival_slash_applied"` |
| Flags | `MDB_CREATE` |
| Key | `ArchivalPairEpochKey`: `P_id[32] \|\| BE(shard_id) \|\| BE(settlement_epoch)` (48 bytes; the serve-credit key's pair-epoch prefix, not its 56-byte shape) |
| Value | `uint8_t` `0x01` presence flag |
| Writers | `set_archival_slash_applied` (slash scheduler), `remove_archival_slash_applied` (reorg) |
| Readers | `has_archival_slash_applied` |
| Encoder | `shekyl::db::ArchivalPairEpochKey` (per-pair-epoch by design, like `archival_settlement`) |
| Introduced | HF1 (gate-2 §10 step 4) |

### `archival_slash_log`

Per-block revert journal for slash connect / `pop_block` (gate-2 §8).

| Property | Value |
|---|---|
| LMDB name | `"archival_slash_log"` |
| Flags | `MDB_CREATE` |
| Key | `BE(block_height) \|\| BE(seq)` (12 bytes) |
| Value | versioned `ArchivalSlashRevertValue` blob, or epoch-marker sentinel at `seq = 0xFFFFFFFF` |
| Writers | `append_archival_slash_log`, deleted on slash revert |
| Readers | `revert_archival_slashes_at_height` |
| Introduced | HF1 (gate-2 §10 step 4) |

### The four pre-image journals

`archival_emission_claim_log`, `archival_bond_unbond_log`,
`archival_bond_holdings_update_log`, and `archival_bond_rebond_log` share
the slash log's row layout and the height-keyed journal scaffold in
`db_lmdb.cpp` (`archival_journal_{next_seq,put,read,delete}`): key
`BE(block_height) ‖ BE(seq)` (12 bytes; each key type is an alias of
`ArchivalSlashLogKey`), seq dense from 0 per height, read-to-first-gap on
pop, restore in reverse connect order, then delete `[0, count)`. All four
key on the **block INDEX** `N = removed_block_height − 1` (F-B5b "convert,
don't unify"), unlike the slash/close hooks, which take the post-block
height. None uses the slash log's `0xFFFFFFFF` epoch-marker sentinel — that
is the slash log's bespoke loop only. Pop ordering is **load-bearing** and
documented at `BlockchainDB::pop_block`: every journal restore runs after
the slash revert (the slash journal restores overlapping record fields;
reordering trips the reverts' delta guards).

### `archival_emission_claim_log`

Per-block journal for the emission-claim dedup revert on `pop_block`
(`REWARD_EMISSION_E3_GATING_ROUND.md` §6.3, WS-2 §6.2). The connect
mutation is insert + window prune whose floor keys on the tip settled epoch
(non-monotonic under reorg), so an insert-only journal cannot restore
prune-evicted entries — a floor-lowering pop would leave an already-claimed
epoch absent: the double-mint. The row therefore carries the FULL
pre-mutation claimed set.

| Property | Value |
|---|---|
| LMDB name | `"archival_emission_claim_log"` |
| Flags | `MDB_CREATE` |
| Key | `BE(block_height) \|\| BE(seq)` (12 bytes) |
| Value | `ArchivalEmissionClaimRevertValue` v1, variable: `version[1] \|\| p_id[32] \|\| BE(pre_first_paying_emission_height)[8] \|\| BE32(count) \|\| BE(pre_claimed_epochs[])` (45 + 8·count bytes; epochs strictly increasing, enforced on encode and decode) |
| Writers | `apply_archival_emission_claim` (append; pre-image captured before the mutation), the revert's clear |
| Readers | `revert_archival_emission_claims_at_height` |

### `archival_bond_unbond_log`

Per-block journal for the Unbond connect's record pre-image
(`ARCHIVAL_BOND_GATE4.md` §3.5 connect step 1 / §5 pop twin). The vin
carries the POST-connect state (§3.5 debit-path pin), so the pre-release
holdings and interval log are not reconstructible at pop without this row;
it carries exactly the three fields the connect mutates (`bonded_total`,
holdings, `bad_intervals` — disjoint from the emission-claim journal's
fields, so the two reverts compose in any order).

| Property | Value |
|---|---|
| LMDB name | `"archival_bond_unbond_log"` |
| Flags | `MDB_CREATE` |
| Key | `BE(block_height) \|\| BE(seq)` (12 bytes) |
| Value | `ArchivalBondUnbondRevertValue` v2, variable: `version[1] \|\| p_id[32] \|\| BE(pre_bonded_total)[8] \|\| pre_holdings_kind[1] \|\| BE32(shard_count) \|\| BE(pre_shard_ids[]) \|\| BE(pre_shard_add_epochs[]) \|\| BE32(interval_count) \|\| pre_bad_intervals[]` (50 + 16·shards + 16·intervals bytes; `pre_bonded_total == 0` refused on encode AND decode) |
| Writers | `apply_archival_unbond` (append), the revert's clear |
| Readers | `revert_archival_unbonds_at_height` (reverse-order restore through the Rust pop fold) |

### `archival_bond_holdings_update_log`

Per-block journal for the HoldingsUpdate connect's record pre-image
(`ARCHIVAL_BOND_GATE4.md` §4.4, the add/drop grace-tail path). A
HoldingsUpdate stays `Bonded` (no Exited transition, no clean
interval-close), so it cannot share the Unbond journal or pop path; its
connect mutates a strict subset of Unbond's fields, and the pre-image here
is smaller than the Unbond value by exactly the two never-mutated fields
(`holdings_kind`, `bad_intervals`) — an honest minimal journal, not the
Unbond superset reused.

| Property | Value |
|---|---|
| LMDB name | `"archival_bond_holdings_update_log"` |
| Flags | `MDB_CREATE` |
| Key | `BE(block_height) \|\| BE(seq)` (12 bytes) |
| Value | `ArchivalBondHoldingsUpdateRevertValue` v1, variable: `version[1] \|\| p_id[32] \|\| BE(pre_bonded_total)[8] \|\| BE32(shard_count) \|\| BE(pre_shard_ids[]) \|\| BE(pre_shard_add_epochs[])` (45 + 16·shards bytes; zero `pre_bonded_total` refused both ways) |
| Writers | `apply_archival_holdings_update_add` / `_drop` via the single-sourced `apply_archival_bond_record_update` scaffold and `put_archival_holdings_update_journal`, the revert's clear |
| Readers | `revert_archival_holdings_updates_at_height` |

### `archival_bond_rebond_log`

Per-block journal for the Rebond connect's record pre-image
(`ARCHIVAL_BOND_GATE4.md` §3.4; P2B-9 reinstatement). Rebond is the one
bond-post kind that mutates an EXISTING interval in place (`end_exclusive`:
MAX → `E_rebond + 1`), so alongside the holdings pre-image the row carries
the closed interval's index + start; the pop re-opens exactly that entry to
MAX, with a belt that the start must match and the entry must currently be
closed (`FATAL: archival rebond revert interval desync` otherwise).

| Property | Value |
|---|---|
| LMDB name | `"archival_bond_rebond_log"` |
| Flags | `MDB_CREATE` |
| Key | `BE(block_height) \|\| BE(seq)` (12 bytes) |
| Value | `ArchivalBondRebondRevertValue` v1, variable: `version[1] \|\| p_id[32] \|\| BE(pre_bonded_total)[8] \|\| BE32(closed_interval_index) \|\| BE(closed_interval_start)[8] \|\| BE32(shard_count) \|\| BE(pre_shard_ids[]) \|\| BE(pre_shard_add_epochs[])` (57 + 16·shards bytes; `pre_bonded_total == 0` is LEGAL — a terminal-slash reinstatement starts from a zero-balance record) |
| Writers | `apply_archival_rebond` via the shared bond-record scaffold, the revert's clear |
| Readers | `revert_archival_rebonds_at_height` |

### `archival_attestation_witness`

Credit-wire attestation witness (`ARCHIVAL_CREDIT_WIRE.md` §3.2/§4,
transport B2): the per-block `r` + pass-signature admission witness —
prunable, opaque at this layer (decode/verify live in Rust), never in the
block blob. The mined commitment is the block header's `attestation_root`.

| Property | Value |
|---|---|
| LMDB name | `"archival_attestation_witness"` |
| Flags | `MDB_INTEGERKEY \| MDB_CREATE` |
| Key | `uint64_t` (8 bytes, native-endian): the POST-add chain height — `archival_attestation_witness_key(block_index) = block_index + 1` (mirrors `store_curve_tree_root_at_height`); every site goes through the helper so the +1 cannot drift |
| Value | variable-length opaque witness blob (`r ‖ pass signatures`); an empty witness writes NO row, absent reads as empty |
| Writers | `store_archival_attestation_witness_at_height` (`add_block`, same write txn), `remove_archival_attestation_witness_at_height` (`pop_block`) |
| Readers | `get_archival_attestation_witness_at_height` — single chain-layer read site is `Blockchain::get_block_attestation_witness` (CW-2: every outgoing `block_complete_entry` fills from here) |
| Prune | `prune_archival_epochs_before` via `delete_archival_attestation_witness_before_height` |
| Introduced | rides the v9 boundary (additive, no bump) |

### `archival_alt_attestation_witness`

Reorg-survival counterpart: the same opaque bytes, keyed by **block hash**
— alt blocks are not height-canonical.

| Property | Value |
|---|---|
| LMDB name | `"archival_alt_attestation_witness"` |
| Flags | `MDB_CREATE` |
| Key | `crypto::hash` block id (32 bytes) |
| Value | variable-length opaque witness blob (same content as the height-keyed table); empty writes no row |
| Comparators | `compare_hash32` (set at open) |
| Writers | `store_archival_alt_attestation_witness` (`handle_alternative_block`, beside `add_alt_block`, same txn), `remove_archival_alt_attestation_witness` (from `remove_alt_block`), `drop_alt_blocks` |
| Readers | `get_archival_alt_attestation_witness` (reorg promotion in `switch_to_alternative_blockchain`) |
| Introduced | rides the v9 boundary (additive, no bump) |

**One table, one owner.** Rows are owned by the alt block: written beside
`add_alt_block`, removed by `remove_alt_block` / `drop_alt_blocks` /
`reset()` — a row cannot outlive (or survive without) its alt block. The
height-keyed retention prune structurally cannot see this table (hash
keys), which is exactly why the lifetime is tied to the alt block instead:
a row parked here by a pop would otherwise leak for the life of the
database. A block moving between main and alt carries its witness
explicitly through `block_connect_supplement`.

### `properties` — Staking keys

The `properties` table (see below) stores these staking-related entries:

| Key string | Value type | Description |
|---|---|---|
| `staker_pool_balance` | `uint64_t` (8 bytes) | Running balance of the staker reward pool. Incremented by emission + fee pool inflow per block (when stakers exist), decremented by successful claims. |
| `total_bonded_atomic` | `uint64_t` (8 bytes) | Global audit scalar: sum of per-`P` `bonded_total_atomic` (gate-4 §4.5). Credited on JoinMarket `bond_credit`; debited on Unbond/slash connect paths. |
| `total_burned` | `uint64_t` (8 bytes) | Cumulative amount of SHEKYL destroyed (zero-staker burns + explicit burns). |

---

## FCMP++ Curve Tree

### `curve_tree_leaves`

Full-chain membership proof tree leaf nodes.

| Property | Value |
|---|---|
| LMDB name | `"curve_tree_leaves"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` tree position (0-based, dense, monotonic; assigned during drain, 8 bytes). **Not** the global output index — use `output_to_leaf` for the mapping. |
| Value | 128 bytes — 4 × 32-byte curve scalars forming the leaf tuple |
| Writers | `grow_curve_tree`, `trim_curve_tree` |
| Readers | `get_curve_tree_leaf_by_tree_position`, `get_curve_tree_leaf_by_output_index` (double lookup via `output_to_leaf`), leaf iteration for proof generation |
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

### `curve_tree_roots`

Per-block curve-tree root hash for fast lookup without deserializing checkpoints.

| Property | Value |
|---|---|
| LMDB name | `"curve_tree_roots"` |
| Flags | `MDB_INTEGERKEY` |
| Key | `uint64_t` block height (8 bytes) |
| Value | 32-byte root hash |
| Writers | `set_curve_tree_root_at_height` (block connect), deleted on `pop_block` |
| Readers | `get_curve_tree_root_at_height` |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC |

### `pending_tree_leaves`

Outputs that have been created but not yet matured into the curve tree. Composite key enforces canonical `(maturity, output_index)` drain order.

| Property | Value |
|---|---|
| LMDB name | `"pending_tree_leaves"` |
| Flags | `MDB_CREATE` only — **no** `MDB_DUPSORT`, **no** `MDB_INTEGERKEY` |
| Key | 16 bytes: `BE(maturity_height) \|\| BE(global_output_index)` — see `PendingLeafKey` in `shekyl_types.h` |
| Value | 128 bytes — leaf tuple data (same format as `curve_tree_leaves`) |
| Writers | `add_pending_tree_leaf` (block connect), removed by `drain_pending_tree_leaves` |
| Readers | `drain_pending_tree_leaves` (cursor scan up to current height) |
| Notes | LMDB's default byte-compare yields canonical `(maturity, output_index)` order. No `DUPSORT` anywhere in curve-tree state — this was changed in DB v7 to fix a consensus-critical bug where `DUPSORT` on leaf bytes caused non-deterministic drain order for outputs sharing the same maturity height. |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC (schema v7) |

### `pending_tree_drain`

Journal of leaves that were drained from `pending_tree_leaves` into the curve tree. Used for rollback: if a block is popped, these entries are restored to `pending_tree_leaves`. Contains everything needed for exact reversal without consulting other tables.

| Property | Value |
|---|---|
| LMDB name | `"pending_tree_drain"` |
| Flags | `MDB_CREATE` only — **no** `MDB_DUPSORT`, **no** `MDB_INTEGERKEY` |
| Key | 16 bytes: `BE(block_height) \|\| BE(global_output_index)` — see `DrainKey` in `shekyl_types.h` |
| Value | 136 bytes — see `DrainValue` in `shekyl_types.h`: |

```
Offset  Size  Field
0        8    BE(maturity_height) — original pending key, needed for re-insertion
8      128    leaf tuple data
```

| Property | Value |
|---|---|
| Writers | `drain_pending_tree_leaves` (records what was drained) |
| Readers | `BlockchainDB::pop_block` (restores entries on rollback) |
| Notes | `pop_block` range-scans by `DrainKey::prefix(block_height)` to find all entries for the popped block, then restores each to `pending_tree_leaves` and removes the output→leaf mapping. |
| Introduced | HF_VERSION_FCMP_PLUS_PLUS_PQC (schema v7) |

### `block_pending_additions`

Journal recording which outputs were added to `pending_tree_leaves` by each block. Enables `pop_block` to remove the exact pending entries without reconstructing output IDs from the post-pop state.

| Property | Value |
|---|---|
| LMDB name | `"block_pending_additions"` |
| Flags | `MDB_CREATE` only — **no** `MDB_DUPSORT`, **no** `MDB_INTEGERKEY` |
| Key | 16 bytes: `BE(block_height) \|\| BE(global_output_index)` — see `BlockPendingKey` in `shekyl_types.h` |
| Value | 8 bytes: `BE(maturity_height)` — see `BlockPendingValue` in `shekyl_types.h` |

| Property | Value |
|---|---|
| Writers | `add_block_pending_addition` (during `collect_outputs` in `add_block`) |
| Readers | `get_block_pending_additions` (consumed by `pop_block`) |
| Notes | One entry per output added to pending. `pop_block` range-scans by `BlockPendingKey::prefix(block_height)`, then deletes each listed entry from `pending_tree_leaves` by primary key `PendingLeafKey(maturity, output_index)`. |
| Introduced | DB v7 |

### `output_to_leaf`

Bidirectional mapping: global output index → tree position. Written during drain when a tree position is assigned. Enables `get_curve_tree_leaf_by_output_index` (double lookup).

| Property | Value |
|---|---|
| LMDB name | `"output_to_leaf"` |
| Flags | `MDB_INTEGERKEY \| MDB_CREATE` |
| Key | `uint64_t` global output index (native-endian, 8 bytes) |
| Value | `uint64_t` tree position (native-endian, 8 bytes) |
| Writers | `add_output_leaf_mapping` (during drain), `remove_output_leaf_mapping` (during `pop_block`) |
| Readers | `get_output_leaf_index`, `get_curve_tree_leaf_by_output_index` |
| Notes | Cannot be pruned beyond the reorg window. Checkpoint snapshots must include this table's state (or its content hash). |
| Introduced | DB v7 |

### `leaf_to_output`

Bidirectional mapping: tree position → global output index. Inverse of `output_to_leaf`.

| Property | Value |
|---|---|
| LMDB name | `"leaf_to_output"` |
| Flags | `MDB_INTEGERKEY \| MDB_CREATE` |
| Key | `uint64_t` tree position (native-endian, 8 bytes) |
| Value | `uint64_t` global output index (native-endian, 8 bytes) |
| Writers | `add_output_leaf_mapping` (during drain), `remove_output_leaf_mapping` (during `pop_block`) |
| Readers | `get_leaf_output_index` |
| Notes | Same lifecycle as `output_to_leaf`. Both tables are exact inverses — a debug invariant asserts `size(output_to_leaf) == size(leaf_to_output) == leaf_count` after every block. |
| Introduced | DB v7 |

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
               dandelionpp_stem:1, bf_padding:1 (reserved; was is_forwarding),
               fcmp_verified:1, origin_zone:2
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
| `"version"` (NUL-terminated) | `uint32_t` | Database schema version — tracks `#define VERSION` in `db_lmdb.cpp` (the header of this document names the current value; a third copy here just drifts) |
| `"pruning_seed"` (NUL-terminated) | `uint32_t` | Blockchain pruning seed |
| `"tx_prune_next_block"` (NUL-terminated) | `uint64_t` | Next block height for tx pruning |
| `"last_pruned_tx_data_height"` (NUL-terminated) | `uint64_t` | Height of last pruned tx data |
| `"staker_pool_balance"` (no NUL) | `uint64_t` | Running staker reward pool balance |
| `"total_bonded_atomic"` (no NUL) | `uint64_t` | Global bonded collateral audit scalar (gate-4 §4.5) |
| `"total_burned"` (no NUL) | `uint64_t` | Cumulative destroyed SHEKYL |
| `"archival_frozen_shard_count"` (no NUL) | `uint64_t` | Pop-symmetric `archival_shard_segment` row counter — the M1 gate operand's O(1) backing store (V8; `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §4.4). +1 in `put_archival_shard_segment`, −1 per deleted row in `revert_archival_segment_freezes`; mutation surface CI-pinned |

| Property | Value |
|---|---|
| Writers | Various — `set_staker_pool_balance`, `set_total_bonded_atomic`, `set_total_burned`, migration code, pruning code |
| Readers | Various — `get_staker_pool_balance`, `get_total_bonded_atomic`, `get_total_burned`, `get_blockchain_pruning_seed`, etc. |
| Introduced | Genesis (DB v0) |

---

## Sub-database total

Total: **49 sub-databases**. The single source of truth is the
`SHEKYL_LMDB_TABLES` X-macro list in `db_lmdb.cpp`; its derived
`kLmdbTableCount` is what `mdb_env_set_maxdbs` receives (`SO-D4`,
`ARCHIVAL_SETTLEMENT_WRITER.md`), so the count is exact by construction with
**no headroom** — a margin would silently absorb a table opened outside the
list. (`archival_shard_leaf` was deleted pre-genesis by the segment-freeze
pipeline and is not in the list.) The coverage gate
(`scripts/ci/check_lmdb_schema_coverage.py`) holds this document to that
list: every table must have a section here, and the total above must match.

### Schema v6 → v7 migration (breaking)

DB v7 is **not** backward compatible with v6. Nodes with v6 data must resync from genesis. The schema change:
- `pending_tree_leaves`: changed from `MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED` (key=maturity, dup=leaf) to composite 16-byte key `BE(maturity) || BE(output_index)` with `MDB_CREATE` only.
- `pending_tree_drain`: same restructuring (key was block_height with DUPSORT, now composite key).
- Three new tables: `block_pending_additions`, `output_to_leaf`, `leaf_to_output`.
- `maxdbs` increased from 32 to 36; gate-2/gate-4 archival substrate later required **42**, and the hand-maintained ceiling grew with each table until `SO-D4` replaced it with the derived `kLmdbTableCount` (see the sub-database total above — the ceiling is now exact by construction, not a number anyone edits).
- Typed key/value encoders added in `src/blockchain_db/shekyl_types.h`.

### Schema v7 → v8 (breaking, no migration path)

DB v8 adds the persisted `"archival_frozen_shard_count"` counter to
`properties` (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §4.4). A pre-v8 database
has `archival_shard_segment` rows the counter does not account for, so
`BlockchainLMDB::migrate` **refuses any pre-v8 database loudly** and directs
the operator to delete the data directory and resync. Pre-genesis, no
in-Shekyl migration code is justified (`15-deletion-and-debt.mdc`).

### Schema v8 → v9 (breaking, no migration path)

DB v9: the block header gains `attestation_root` (`ARCHIVAL_CREDIT_WIRE.md`
§3), so the persisted block blob in `blocks` grows 32 bytes; a pre-v9 blob
has no `attestation_root` and the v9 parser cannot read it. Delete and
resync. The block's boost serializer enforces the same boundary via
`BOOST_CLASS_VERSION(cryptonote::block, 1)`: a pre-v9 archive is refused
loudly, not misparsed. **Within v9 (no bump):** the additive
`archival_attestation_witness` / `archival_alt_attestation_witness` tables
ride the boundary — a new empty table on an existing env asserts no
incompatibility.

### Schema v9 → v10 (breaking, no migration path)

DB v10: the `archival_serve_credit` key widens 48 → 56 B (`PC-D4`:
`BE(block_height)` appended — one row per challenge). A v9 datadir has
48-byte rows, and v10 code fails against them in the worst split of ways:
point and prefix reads **silently miss** every old row (a 56-byte probe never
equals a 48-byte key), while the full-scan `mv_size` guards throw FATAL — a
node would first misjudge dedup and emission quietly and only crash on the
next scan. Delete and resync. This bump is the LMDB-schema guard, **not**
rule 42's persisted-block version, which correctly does not fire (no block
blob byte moves). **Within v10 (no bump):** the additive
`archival_settlement` table rides the boundary as the witness tables rode
v9.

`BlockchainLMDB::migrate` refuses any pre-`VERSION` database with a message
that tracks the constant, so each bump extends the refusal automatically.

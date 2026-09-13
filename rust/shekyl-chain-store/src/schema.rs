// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The redb schema map over the censused LMDB inventory (DRS-0 slice B).
//!
//! One `TableDefinition` per LMDB table, **derived from the X-macro
//! `SHEKYL_LMDB_TABLES` (`src/blockchain_db/lmdb/db_lmdb.cpp:317`) and nothing
//! else**. The denominator is counted from that macro; the bijection is gated
//! by `scripts/ci/check_redb_schema_bijection.py`. Key/value types that
//! reproduce LMDB order are gated by `scripts/ci/check_redb_schema_key_types.py`.
//! Slice A's per-table accumulator classes pin to the same X-macro; a name
//! that exists in only one of the two modules is a merge defect, not a
//! third list to maintain here.
//!
//! Walking `BlockchainDB`'s virtual interface would miss tables. The
//! settlement pair exists only on `BlockchainLMDB` (SO-D8), so a schema built
//! from the abstract interface silently ships without a write path LMDB has.
//!
//! # Mapping rules, derived from LMDB open flags and comparators
//!
//! | LMDB | redb |
//! |---|---|
//! | `MDB_INTEGERKEY` | `u64` key (redb orders `u64` numerically) |
//! | `MDB_DUPSORT` | multimap, **or** a zerokval collapse (below) |
//! | `MDB_DUPFIXED` | storage hint only; no semantic effect |
//! | `compare_uint64` | `u64` ordering — numeric, same as `MDB_INTEGERKEY` |
//! | `compare_string` | `&str` — byte-lexicographic with a length tiebreak |
//! | `compare_hash32` | [`LmdbHashKey`] — **not** [`Hash32`], see that type |
//! | no flags, no comparator | `&[u8]` — byte-lexicographic |
//!
//! Default-flag tables that store `BE(x)` 8-byte keys are correctly mapped as
//! either `u64` or `&[u8]`: big-endian bytes compared lexicographically *are*
//! numeric order. The type gate leaves those unconstrained.
//!
//! # The zerokval collapse (a deliberate divergence, §6.4)
//!
//! Five tables — `block_heights`, `block_info`, `output_txs`, `spent_keys`,
//! `tx_indices` — store a **dummy 8-zero-byte key** and put the real
//! identifier in a fixed-size duplicate value, ordered by a custom dupsort
//! comparator. That exists to exploit LMDB's dup-sort B-tree; redb has no
//! DUPSORT, so the workaround has no purpose and the real identifier becomes
//! the redb **key**.
//!
//! This **preserves ordering rather than changing it**: the comparator moves
//! from duplicate-position to key-position and compares the same bytes the
//! same way. It is recorded as a divergence because the shape differs, not
//! because the semantics do.
//!
//! # Value types
//!
//! Where the LMDB value is an opaque serialized blob the redb value is
//! `&[u8]`. These are **storage** types; per DRS-0 slice A the accumulator
//! folds a canonical encoding of the *decoded logical value*, never storage
//! bytes. Hash *values* (not keys) are [`Hash32`]: the 32-byte stored form,
//! which cannot be used as a table key. Write-pattern obligations (read
//! before delete on set-shaped tables) are DRS-E1; they live in
//! `LMDB_WRITE_ATOMICITY_AUDIT.md` §12, not as a list here.

use redb::{MultimapTableDefinition, TableDefinition};

use crate::lmdb_order::{Hash32, LmdbHashKey, U64PrefixBytes};

/// `blocks` — INTEGERKEY; height → block blob.
pub const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

/// `block_heights` — zerokval collapse: dup hash (`compare_hash32`) becomes the key.
pub const BLOCK_HEIGHTS: TableDefinition<LmdbHashKey, u64> = TableDefinition::new("block_heights");

/// `block_info` — zerokval collapse: dup height (`compare_uint64`) becomes the key.
pub const BLOCK_INFO: TableDefinition<u64, &[u8]> = TableDefinition::new("block_info");

/// `txs` — INTEGERKEY. Dead (DRS-W4): no runtime rows.
pub const TXS: TableDefinition<u64, &[u8]> = TableDefinition::new("txs");

/// `txs_pruned` — INTEGERKEY; tx_id → pruned blob.
pub const TXS_PRUNED: TableDefinition<u64, &[u8]> = TableDefinition::new("txs_pruned");

/// `txs_pqc_auths` — INTEGERKEY + `compare_uint64` (numeric, same as INTEGERKEY).
pub const TXS_PQC_AUTHS: TableDefinition<u64, &[u8]> = TableDefinition::new("txs_pqc_auths");

/// `txs_prunable` — INTEGERKEY. Node-local; excluded from the accumulator.
pub const TXS_PRUNABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("txs_prunable");

/// `txs_prunable_hash` — INTEGERKEY; 1:1 hash value (not a key, so [`Hash32`]).
pub const TXS_PRUNABLE_HASH: TableDefinition<u64, Hash32> =
    TableDefinition::new("txs_prunable_hash");

/// `txs_prunable_tip` — INTEGERKEY; 1:1 height value. Node-local.
pub const TXS_PRUNABLE_TIP: TableDefinition<u64, u64> = TableDefinition::new("txs_prunable_tip");

/// `tx_indices` — zerokval collapse: dup tx hash (`compare_hash32`) becomes the key.
pub const TX_INDICES: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("tx_indices");

/// `tx_outputs` — INTEGERKEY; tx_id → output indices.
pub const TX_OUTPUTS: TableDefinition<u64, &[u8]> = TableDefinition::new("tx_outputs");

/// `output_txs` — zerokval collapse: dup output id (`compare_uint64`) becomes the key.
pub const OUTPUT_TXS: TableDefinition<u64, &[u8]> = TableDefinition::new("output_txs");

/// `output_amounts` — true multimap; dups order by little-endian `amount_index` prefix.
pub const OUTPUT_AMOUNTS: MultimapTableDefinition<u64, U64PrefixBytes> =
    MultimapTableDefinition::new("output_amounts");

/// `spent_keys` — zerokval collapse: dup key image (`compare_hash32`) becomes the key.
pub const SPENT_KEYS: TableDefinition<LmdbHashKey, ()> = TableDefinition::new("spent_keys");

/// `txpool_meta` — key order `compare_hash32`.
pub const TXPOOL_META: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("txpool_meta");

/// `txpool_blob` — key order `compare_hash32`.
pub const TXPOOL_BLOB: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("txpool_blob");

/// `alt_blocks` — key order `compare_hash32`.
pub const ALT_BLOCKS: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("alt_blocks");

/// `hf_starting_heights` — default flags. Dead (DRS-W5): no runtime rows.
pub const HF_STARTING_HEIGHTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("hf_starting_heights");

/// `hf_versions` — INTEGERKEY; height → hf version.
pub const HF_VERSIONS: TableDefinition<u64, u8> = TableDefinition::new("hf_versions");

/// `properties` — `compare_string` == byte-lex + length tiebreak == `&str` order.
pub const PROPERTIES: TableDefinition<&str, &[u8]> = TableDefinition::new("properties");

/// `block_burn` — INTEGERKEY.
pub const BLOCK_BURN: TableDefinition<u64, u64> = TableDefinition::new("block_burn");

/// `archival_serve_credit` — default flags; composite `P_id||shard||epoch||BE(height)`.
pub const ARCHIVAL_SERVE_CREDIT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_serve_credit");

/// `archival_settlement` — default flags. Not on the abstract interface (SO-D8).
pub const ARCHIVAL_SETTLEMENT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_settlement");

/// `archival_attestation_witness` — INTEGERKEY.
pub const ARCHIVAL_ATTESTATION_WITNESS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_attestation_witness");

/// `archival_alt_attestation_witness` — key order `compare_hash32`.
pub const ARCHIVAL_ALT_ATTESTATION_WITNESS: TableDefinition<LmdbHashKey, &[u8]> =
    TableDefinition::new("archival_alt_attestation_witness");

/// `archival_bond` — default flags.
pub const ARCHIVAL_BOND: TableDefinition<&[u8], &[u8]> = TableDefinition::new("archival_bond");

/// `archival_shard_segment` — default flags, `BE(x)` keys (u64 preserves numeric order).
pub const ARCHIVAL_SHARD_SEGMENT: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_shard_segment");

/// `archival_slash_applied` — default flags.
pub const ARCHIVAL_SLASH_APPLIED: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_slash_applied");

/// `archival_slash_log` — default flags.
pub const ARCHIVAL_SLASH_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_slash_log");

/// `archival_emission_claim_log` — default flags.
pub const ARCHIVAL_EMISSION_CLAIM_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_emission_claim_log");

/// `archival_bond_unbond_log` — default flags.
pub const ARCHIVAL_BOND_UNBOND_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_bond_unbond_log");

/// `archival_bond_holdings_update_log` — default flags.
pub const ARCHIVAL_BOND_HOLDINGS_UPDATE_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_bond_holdings_update_log");

/// `archival_bond_rebond_log` — default flags.
pub const ARCHIVAL_BOND_REBOND_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_bond_rebond_log");

/// `archival_r_market` — default flags.
pub const ARCHIVAL_R_MARKET: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_r_market");

/// `archival_sigma_work` — default flags, `BE(x)` keys (u64 preserves numeric order).
pub const ARCHIVAL_SIGMA_WORK: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_sigma_work");

/// `archival_epoch_close_log` — default flags, `BE(x)` keys (u64 preserves numeric order).
pub const ARCHIVAL_EPOCH_CLOSE_LOG: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_epoch_close_log");

/// `archival_budget_accrual` — default flags, `BE(x)` keys (u64 preserves numeric order).
pub const ARCHIVAL_BUDGET_ACCRUAL: TableDefinition<u64, u64> =
    TableDefinition::new("archival_budget_accrual");

/// `archival_budget` — default flags, `BE(x)` keys (u64 preserves numeric order).
pub const ARCHIVAL_BUDGET: TableDefinition<u64, &[u8]> = TableDefinition::new("archival_budget");

/// `pending_tree_leaves` — default flags; composite BE keys.
pub const PENDING_TREE_LEAVES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("pending_tree_leaves");

/// `pending_tree_drain` — default flags; composite BE keys.
pub const PENDING_TREE_DRAIN: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("pending_tree_drain");

/// `block_pending_additions` — default flags; composite BE keys.
pub const BLOCK_PENDING_ADDITIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("block_pending_additions");

/// `output_to_leaf` — INTEGERKEY.
pub const OUTPUT_TO_LEAF: TableDefinition<u64, &[u8]> = TableDefinition::new("output_to_leaf");

/// `leaf_to_output` — INTEGERKEY.
pub const LEAF_TO_OUTPUT: TableDefinition<u64, &[u8]> = TableDefinition::new("leaf_to_output");

/// `curve_tree_leaves` — INTEGERKEY.
pub const CURVE_TREE_LEAVES: TableDefinition<u64, &[u8]> =
    TableDefinition::new("curve_tree_leaves");

/// `curve_tree_layers` — INTEGERKEY. Derived: recomputed from leaves, not folded.
pub const CURVE_TREE_LAYERS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("curve_tree_layers");

/// `curve_tree_meta` — default flags.
pub const CURVE_TREE_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("curve_tree_meta");

/// `curve_tree_checkpoints` — INTEGERKEY. Derived: recomputed, not folded.
pub const CURVE_TREE_CHECKPOINTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("curve_tree_checkpoints");

/// `curve_tree_roots` — INTEGERKEY.
pub const CURVE_TREE_ROOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("curve_tree_roots");

/// `output_metadata` — INTEGERKEY. Node-local; excluded from the accumulator.
pub const OUTPUT_METADATA: TableDefinition<u64, &[u8]> = TableDefinition::new("output_metadata");

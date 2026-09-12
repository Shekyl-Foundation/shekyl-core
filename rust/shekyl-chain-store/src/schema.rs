// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The redb schema map over the censused LMDB inventory (DRS-0 slice B).
//!
//! One `TableDefinition` per LMDB table, **derived from the X-macro
//! `SHEKYL_LMDB_TABLES` (`src/blockchain_db/lmdb/db_lmdb.cpp:317`) and nothing
//! else**. The denominator is **49**, counted from that macro; the bijection is
//! gated by `scripts/ci/check_redb_schema_bijection.py`.
//!
//! # Why the X-macro is the only admissible source
//!
//! Walking `BlockchainDB`'s virtual interface would miss tables. The
//! settlement pair (`set_archival_settlement` / `get_archival_settlement`)
//! occurs zero times in `blockchain_db.h` and `testdb.h` and five times in
//! `db_lmdb.h`: it exists only on `BlockchainLMDB`, so a schema built from the
//! abstract interface silently ships without a write path LMDB has (SO-D8).
//!
//! This was not hypothetical when the map was written. A first draft of this
//! table, written from familiarity with the archival subsystem rather than
//! from the macro, contained **52** entries: it invented
//! `archival_claimed_epochs`, `archival_prune_watermark`,
//! `archival_reward_paid` and `archival_bond_value` — all real *concepts*, none
//! of them tables (the watermark is a `properties` key; claimed epochs live
//! inside the bond record) — and omitted the real `output_metadata`. The
//! bijection gate is what caught it.
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
//! | `compare_hash32` | [`LmdbHashKey`] — **not** `[u8; 32]`, see that type |
//! | no flags, no comparator | `&[u8]` — byte-lexicographic |
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
//! bytes — that is what lets LMDB and redb produce the same digest and is the
//! basis of DRS-E2. Slice A's acceptance question governs any encoding that
//! lands here: *can it be computed from the logical value alone, with no
//! cursor, txn, height counter or previously-stored row?*
//!
//! # Write patterns that constrain the engine (DRS-E1, not this module)
//!
//! **A bare redb `remove` or `insert` on a set-shaped table desynchronizes the
//! accumulator**: the old value must be read and folded out first.
//!
//! The obligation is stated structurally rather than as a list of tables,
//! because the list is the part that drifts. The fifteen set-shaped tables
//! split cleanly:
//!
//! - **Five are DUPSORT / cursor-managed** — `spent_keys`, `block_heights`,
//!   `tx_indices`, `output_txs`, `output_amounts` — written with
//!   `mdb_cursor_put` and deleted with `mdb_cursor_del` after an
//!   `MDB_GET_BOTH` that positions on the row. **None blind-upserts.**
//! - **Ten are simple key→value**, written with `mdb_put`. **All ten
//!   blind-upsert**, so every one needs a read-modify-write hook.
//!
//! So the tables whose storage *shape* changes most under redb (the five,
//! which lose DUPSORT and gain composite keys) are exactly the ones whose
//! accumulator hook is simplest, and vice versa.
//!
//! This module therefore treats **all fifteen** as read-before-delete rather
//! than tracking which currently need it. A table that gains a blind `put`
//! later needs the hook without anyone remembering to update a list.
//!
//! One case shows why a lexical scan cannot substitute for reading the call
//! site: `remove_output_leaf_mapping` deletes from **two** tables four lines
//! apart. It reads and verifies `output_to_leaf`'s value before deleting it,
//! and deletes `leaf_to_output` at a derived key with its value never read.
//! Both are `mdb_del(..., nullptr)`; only one is delete-by-key-alone.

use redb::{MultimapTableDefinition, TableDefinition};

use crate::hash_order::LmdbHashKey;

/// `blocks` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `append-mostly`.
///
/// height -> block blob.
pub const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

/// `block_heights` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_hash32`, accumulator class `set-shaped`.
///
/// ZEROKVAL COLLAPSE: dup value (block hash, compare_hash32) becomes the key.
pub const BLOCK_HEIGHTS: TableDefinition<LmdbHashKey, u64> = TableDefinition::new("block_heights");

/// `block_info` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_uint64`, accumulator class `append-mostly`.
///
/// ZEROKVAL COLLAPSE: dup value (height, compare_uint64) becomes the key.
pub const BLOCK_INFO: TableDefinition<u64, &[u8]> = TableDefinition::new("block_info");

/// `txs` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `excluded`.
///
/// DEAD (DRS-W4): no runtime rows.
pub const TXS: TableDefinition<u64, &[u8]> = TableDefinition::new("txs");

/// `txs_pruned` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `append-mostly`.
///
/// tx_id -> pruned blob.
pub const TXS_PRUNED: TableDefinition<u64, &[u8]> = TableDefinition::new("txs_pruned");

/// `txs_pqc_auths` — LMDB flags `INTEGERKEY`, comparator `compare:compare_uint64`, accumulator class `append-mostly`.
///
/// key order pinned by compare_uint64 (numeric), same as INTEGERKEY.
pub const TXS_PQC_AUTHS: TableDefinition<u64, &[u8]> = TableDefinition::new("txs_pqc_auths");

/// `txs_prunable` — LMDB flags `INTEGERKEY`, comparator `compare:compare_uint64`, accumulator class `excluded`.
///
/// node-local: prune seed differs between honest nodes.
pub const TXS_PRUNABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("txs_prunable");

/// `txs_prunable_hash` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_uint64`, accumulator class `append-mostly`.
///
/// integrity cover for txs_prunable's content.
pub const TXS_PRUNABLE_HASH: TableDefinition<u64, LmdbHashKey> =
    TableDefinition::new("txs_prunable_hash");

/// `txs_prunable_tip` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_uint64`, accumulator class `excluded`.
///
/// node-local.
pub const TXS_PRUNABLE_TIP: TableDefinition<u64, u64> = TableDefinition::new("txs_prunable_tip");

/// `tx_indices` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_hash32`, accumulator class `set-shaped`.
///
/// ZEROKVAL COLLAPSE: dup value (tx hash, compare_hash32) becomes the key.
pub const TX_INDICES: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("tx_indices");

/// `tx_outputs` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `append-mostly`.
///
/// tx_id -> output indices.
pub const TX_OUTPUTS: TableDefinition<u64, &[u8]> = TableDefinition::new("tx_outputs");

/// `output_txs` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_uint64`, accumulator class `set-shaped`.
///
/// ZEROKVAL COLLAPSE: dup value (output id, compare_uint64) becomes the key.
pub const OUTPUT_TXS: TableDefinition<u64, &[u8]> = TableDefinition::new("output_txs");

/// `output_amounts` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_uint64`, accumulator class `set-shaped`.
///
/// amount -> many outputs; dup order compare_uint64 (numeric).
pub const OUTPUT_AMOUNTS: MultimapTableDefinition<u64, &[u8]> =
    MultimapTableDefinition::new("output_amounts");

/// `spent_keys` — LMDB flags `INTEGERKEY+DUPSORT+DUPFIXED`, comparator `dupsort:compare_hash32`, accumulator class `set-shaped`.
///
/// ZEROKVAL COLLAPSE: dup value (key image, compare_hash32) becomes the key; membership only.
pub const SPENT_KEYS: TableDefinition<LmdbHashKey, ()> = TableDefinition::new("spent_keys");

/// `txpool_meta` — LMDB flags `default`, comparator `compare:compare_hash32`, accumulator class `excluded`.
///
/// key order compare_hash32.
pub const TXPOOL_META: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("txpool_meta");

/// `txpool_blob` — LMDB flags `default`, comparator `compare:compare_hash32`, accumulator class `excluded`.
///
/// key order compare_hash32.
pub const TXPOOL_BLOB: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("txpool_blob");

/// `alt_blocks` — LMDB flags `default`, comparator `compare:compare_hash32`, accumulator class `excluded`.
///
/// key order compare_hash32.
pub const ALT_BLOCKS: TableDefinition<LmdbHashKey, &[u8]> = TableDefinition::new("alt_blocks");

/// `hf_starting_heights` — LMDB flags `default`, comparator `-`, accumulator class `excluded`.
///
/// DEAD (DRS-W5): no runtime rows.
pub const HF_STARTING_HEIGHTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("hf_starting_heights");

/// `hf_versions` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `small`.
///
/// height -> hf version.
pub const HF_VERSIONS: TableDefinition<u64, u8> = TableDefinition::new("hf_versions");

/// `properties` — LMDB flags `default`, comparator `compare:compare_string`, accumulator class `small`.
///
/// compare_string == byte-lex + length tiebreak == &str order; holds the schema-version cell.
pub const PROPERTIES: TableDefinition<&str, &[u8]> = TableDefinition::new("properties");

/// `block_burn` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert + delete-by-key: read-modify-write.
pub const BLOCK_BURN: TableDefinition<u64, u64> = TableDefinition::new("block_burn");

/// `archival_serve_credit` — LMDB flags `default`, comparator `-`, accumulator class `small`.
///
/// composite P_id||shard||epoch||BE(height).
pub const ARCHIVAL_SERVE_CREDIT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_serve_credit");

/// `archival_settlement` — LMDB flags `default`, comparator `-`, accumulator class `small`.
///
/// NOT on the abstract interface (SO-D8); map from the X-macro, not a BlockchainDB walk.
pub const ARCHIVAL_SETTLEMENT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_settlement");

/// `archival_attestation_witness` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `small`.
pub const ARCHIVAL_ATTESTATION_WITNESS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_attestation_witness");

/// `archival_alt_attestation_witness` — LMDB flags `default`, comparator `compare:compare_hash32`, accumulator class `excluded`.
///
/// key order compare_hash32.
pub const ARCHIVAL_ALT_ATTESTATION_WITNESS: TableDefinition<LmdbHashKey, &[u8]> =
    TableDefinition::new("archival_alt_attestation_witness");

/// `archival_bond` — LMDB flags `default`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert + delete-by-key: read-modify-write.
pub const ARCHIVAL_BOND: TableDefinition<&[u8], &[u8]> = TableDefinition::new("archival_bond");

/// `archival_shard_segment` — LMDB flags `default`, comparator `-`, accumulator class `set-shaped`.
///
/// TWO write sites, different overwrite semantics (:7972 blind, :8592 NOOVERWRITE).
pub const ARCHIVAL_SHARD_SEGMENT: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_shard_segment");

/// `archival_slash_applied` — LMDB flags `default`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert + delete-by-key: read-modify-write.
pub const ARCHIVAL_SLASH_APPLIED: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_slash_applied");

/// `archival_slash_log` — LMDB flags `default`, comparator `-`, accumulator class `append-mostly`.
pub const ARCHIVAL_SLASH_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_slash_log");

/// `archival_emission_claim_log` — LMDB flags `default`, comparator `-`, accumulator class `append-mostly`.
pub const ARCHIVAL_EMISSION_CLAIM_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_emission_claim_log");

/// `archival_bond_unbond_log` — LMDB flags `default`, comparator `-`, accumulator class `append-mostly`.
pub const ARCHIVAL_BOND_UNBOND_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_bond_unbond_log");

/// `archival_bond_holdings_update_log` — LMDB flags `default`, comparator `-`, accumulator class `append-mostly`.
pub const ARCHIVAL_BOND_HOLDINGS_UPDATE_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_bond_holdings_update_log");

/// `archival_bond_rebond_log` — LMDB flags `default`, comparator `-`, accumulator class `append-mostly`.
pub const ARCHIVAL_BOND_REBOND_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_bond_rebond_log");

/// `archival_r_market` — LMDB flags `default`, comparator `-`, accumulator class `small`.
pub const ARCHIVAL_R_MARKET: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("archival_r_market");

/// `archival_sigma_work` — LMDB flags `default`, comparator `-`, accumulator class `small`.
pub const ARCHIVAL_SIGMA_WORK: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_sigma_work");

/// `archival_epoch_close_log` — LMDB flags `default`, comparator `-`, accumulator class `append-mostly`.
pub const ARCHIVAL_EPOCH_CLOSE_LOG: TableDefinition<u64, &[u8]> =
    TableDefinition::new("archival_epoch_close_log");

/// `archival_budget_accrual` — LMDB flags `default`, comparator `-`, accumulator class `small`.
pub const ARCHIVAL_BUDGET_ACCRUAL: TableDefinition<u64, u64> =
    TableDefinition::new("archival_budget_accrual");

/// `archival_budget` — LMDB flags `default`, comparator `-`, accumulator class `small`.
pub const ARCHIVAL_BUDGET: TableDefinition<u64, &[u8]> = TableDefinition::new("archival_budget");

/// `pending_tree_leaves` — LMDB flags `default`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert + delete-by-key: read-modify-write.
pub const PENDING_TREE_LEAVES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("pending_tree_leaves");

/// `pending_tree_drain` — LMDB flags `default`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert.
pub const PENDING_TREE_DRAIN: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("pending_tree_drain");

/// `block_pending_additions` — LMDB flags `default`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert.
pub const BLOCK_PENDING_ADDITIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("block_pending_additions");

/// `output_to_leaf` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `set-shaped`.
///
/// Blind upsert. NOT delete-by-key: `remove_output_leaf_mapping` reads the
/// value and verifies it against `tree_pos` before deleting. W13 reversibility
/// falsifier fails today.
pub const OUTPUT_TO_LEAF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("output_to_leaf");

/// `leaf_to_output` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert + delete-by-key; W13 reversibility falsifier fails today.
pub const LEAF_TO_OUTPUT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("leaf_to_output");

/// `curve_tree_leaves` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `append-mostly`.
pub const CURVE_TREE_LEAVES: TableDefinition<u64, &[u8]> =
    TableDefinition::new("curve_tree_leaves");

/// `curve_tree_layers` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `derived`.
///
/// DERIVED: recomputed from leaves, not folded.
pub const CURVE_TREE_LAYERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("curve_tree_layers");

/// `curve_tree_meta` — LMDB flags `default`, comparator `-`, accumulator class `small`.
pub const CURVE_TREE_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("curve_tree_meta");

/// `curve_tree_checkpoints` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `derived`.
///
/// DERIVED: recomputed, not folded.
pub const CURVE_TREE_CHECKPOINTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("curve_tree_checkpoints");

/// `curve_tree_roots` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `set-shaped`.
///
/// blind upsert + delete-by-key: read-modify-write.
pub const CURVE_TREE_ROOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("curve_tree_roots");

/// `output_metadata` — LMDB flags `INTEGERKEY`, comparator `-`, accumulator class `excluded`.
///
/// node-local: honest nodes differ; excluded from the accumulator.
pub const OUTPUT_METADATA: TableDefinition<u64, &[u8]> = TableDefinition::new("output_metadata");

/// Every table name in this module, for the bijection gate and for engine
/// bring-up. **This list is the module's own claim about its contents** — the
/// gate compares it against the X-macro in both directions, so an entry added
/// here without a `TableDefinition`, or a definition added without an entry,
/// fails rather than drifts.
pub const ALL_TABLE_NAMES: [&str; 49] = [
    "blocks",
    "block_heights",
    "block_info",
    "txs",
    "txs_pruned",
    "txs_pqc_auths",
    "txs_prunable",
    "txs_prunable_hash",
    "txs_prunable_tip",
    "tx_indices",
    "tx_outputs",
    "output_txs",
    "output_amounts",
    "spent_keys",
    "txpool_meta",
    "txpool_blob",
    "alt_blocks",
    "hf_starting_heights",
    "hf_versions",
    "properties",
    "block_burn",
    "archival_serve_credit",
    "archival_settlement",
    "archival_attestation_witness",
    "archival_alt_attestation_witness",
    "archival_bond",
    "archival_shard_segment",
    "archival_slash_applied",
    "archival_slash_log",
    "archival_emission_claim_log",
    "archival_bond_unbond_log",
    "archival_bond_holdings_update_log",
    "archival_bond_rebond_log",
    "archival_r_market",
    "archival_sigma_work",
    "archival_epoch_close_log",
    "archival_budget_accrual",
    "archival_budget",
    "pending_tree_leaves",
    "pending_tree_drain",
    "block_pending_additions",
    "output_to_leaf",
    "leaf_to_output",
    "curve_tree_leaves",
    "curve_tree_layers",
    "curve_tree_meta",
    "curve_tree_checkpoints",
    "curve_tree_roots",
    "output_metadata",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_list_has_no_duplicates_and_is_the_censused_size() {
        let mut sorted = ALL_TABLE_NAMES.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            before,
            "duplicate table name in ALL_TABLE_NAMES"
        );
        assert_eq!(
            before, 49,
            "the censused denominator is 49 (SHEKYL_LMDB_TABLES)"
        );
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store-wide layout version (`DAEMON_REDB_STORE.md` §11.1(a)).
//!
//! One constant for the whole store, not one per table: §11.1(b) makes
//! *any* stored-byte change a bump — a table added, removed or re-keyed,
//! or a value codec moved — and there is no migration ladder to make
//! finer granularity useful. **Newer refuses; older refuses too**; the
//! answer to a mismatch is a rebuild from the block corpus (§11), never a
//! migrator.
//!
//! This is the constant the schema-snapshot workflow pairs every
//! `rust/shekyl-chain-store/schemas/*.snap` against. A `.snap` that moves
//! without the declaration line below moving in the same PR fails CI.

use super::{Canonical, CodecError};

/// The layout this binary reads and writes.
///
/// **Bump when any stored byte changes** (§11.1(b)). History:
///
/// - `1` — DRS-E1 increment 2: the `properties` header cells
///   (`schema_version`, `apply_policy`) and the scalar codecs.
/// - `2` — DRS-E1 increment 3 (S-CHAIN-W): the `undo_log` table (first
///   Rust-only table; `TableOrdinal` 49) and its `UndoLog` row codec
///   (commit 1); the connect write set's value codecs — `BlockInfo`,
///   `TxIndex`, `OutTx`, `OutKey`, `TxOutputIndices`, `CurveTreeRoot` — pinned
///   to the LMDB layouts minus the collapsed key (commit 2). Ordinals are
///   now load-bearing, so any later reorder **or removal** in the `tables!`
///   list is also a bump.
/// - `3` — DRS-E1 increment 4 (S-CHAIN-R) layout commit, first half: the
///   value side is typed (§11.1(f), `codec::shape`). Every table's value is
///   `Coded<V>` / `Blob<K>` / `Unshaped`; each value `TypeName` in the
///   catalogue moved, and every fixed-width codec table now declares its
///   width to the engine (a leaf-page layout change from `&[u8]`, which is
///   variable-width). No codec's **bytes** moved — the row fixtures are
///   unchanged — so the digest is unchanged; the file format is not.
/// - `4` — DRS-E1 increment 4 (S-CHAIN-R) layout commit, second half — the
///   three S-CHAIN-W amendments (`DRS_E1_SCHAIN_R.md` §3.7): **A1**
///   `BlockInfo` grows `cumulative_tx_count` and
///   `long_term_effective_median` (88 → 104 B; FL-R3-STORE, Q4) and
///   `ConnectFacts` a seventh passed-through fact, so `PassedThroughFacts`
///   gains a bit; **A2** the seal creates every table with a writer (SCR-17);
///   **A3** `txs_pqc_auth_hash` (`TableOrdinal` 50, the second Rust-only
///   table; `PDM-Q-F26`). Row fixtures move for `block_info` and
///   `passed_through_facts`; the catalogue gains a row.
/// - `5` — `spent_keys` value is [`Present`](super::Present) (`shekyl::Present`),
///   not redb's `()`. Completes §11.1(f): every map value is a named shape.
///   Zero stored bytes change; the `TypeName` is a layout change.
/// - `6` — DRS-E1 increment 5 (S-OUT-KI) layout commit (`DRS_E1_SOUT_KI.md`
///   §3.4, SOK-1 / SOK-Q1 arm A): `output_amounts` is a keyed
///   `(amount, amount_index) → Coded<OutKey>` table, not a multimap — redb
///   has no seek within a key's members, so the ported multimap's point read
///   walked the whole amount-0 bucket; the tuple key is LMDB's `DUPSORT`
///   pair as a key, same logical content, same order, O(log n). `OutKey`
///   drops the `amount_index` prefix its key now carries (96 → 88 B). The
///   catalogue has no multimap left, so the journal's `MultiInserted` (tag
///   2) is retired and the tag RESERVED; `U64PrefixBytes`, `SetTable` and the
///   multimap `UndoTarget` are deleted. Row fixtures move for `out_key` and
///   `undo_log`; the catalogue row for `output_amounts` moves.
/// - `7` — DRS-E6 slice 2 (`CHAIN_RULES_SLICE_2.md` §4.3, Q5), the first
///   passed-through fact deleted by the row that derives it:
///   `cumulative_difficulty` leaves `ConnectFacts` (the validator derives it,
///   CEN-D4, and `connect` reads it off the verdict), so `FACT_FIELDS` loses
///   its name and `PassedThroughFacts` its accepted vocabulary shrinks
///   7 → 6. Zero bytes of any table change; the `passed_through_facts` cell's
///   fixtures move.
/// - `8` — the `Rebond` → `Reinstate` rename: the table
///   `archival_bond_rebond_log` becomes `archival_bond_reinstate_log`.
///   **Zero stored bytes change, and no codec, fixture or digest input
///   moves** — the catalogue row is renamed and nothing else. It is a layout
///   bump for the same reason `5` was: a table's *name* is part of the
///   layout, because an old binary looks it up by that name at `open_table`
///   and does not find it. The wire is untouched (the `Reinstate` bond-post
///   kind keeps discriminant `1`, and the FFI error-code values are
///   unchanged); this bump is about the store's file, not the chain's bytes.
/// - `9` — DRS-E1 S-CURVE (`DRS_E1_SCURVE.md` §4): three curve-tree tables
///   leave `Unshaped`. `curve_tree_leaves` → `Coded<tree_leaf>` (128 bytes,
///   the C++ row as-is); `curve_tree_layers` re-keys from the packed
///   `(layer << 56) | chunk` `u64` to the tuple `(u8, u64)` (`SCU-Q3`) with
///   `Coded<layer_hash>` values; `curve_tree_meta` collapses three
///   string-keyed cells into **one** `Coded<curve_tree_state>` row under the
///   unit key (`SCU-Q1`), written `EMPTY` by the seal. Leaf and hash bytes
///   are unchanged; the layer key and the meta row are new layouts. Four
///   codec fixtures are born; the digest's root family (`curve_tree_roots`)
///   does not move.
/// - `10` — two tables leave the catalogue with the C++ tx-data prune
///   (`PDM-Q7`'s stripe engine went first, on #821; this is the rest):
///   `txs_prunable_tip` (#8, the engine's tip index, write-never) and
///   `output_metadata` (#48, the C++ prune's post-discard scan cache, whose
///   read chain was dead two levels deep). **Zero stored bytes of any
///   surviving table change**, but every ordinal after #8 shifts by one and
///   `undo_log` by two — and the pop journal persists ordinals, so a v9
///   journal names the wrong tables under v10. Layout bump; pre-genesis
///   delete-and-resync. The uniform discard that replaces both is S-PRUNE
///   (`DRS_E1_SPRUNE.md`), which will mint what it needs against the tx
///   unit rather than inherit either row. LMDB moved `14 → 15` in the same
///   PR (the X-macro is the bijection's other half).
/// - `11` — DRS-E1 S-ARCH (`DRS_E1_SARCH.md` §4): six archival tables
///   leave `Unshaped`. `archival_bond` → `[u8; 32] → Coded<BondRecord>` (the
///   persisted bond record's first Rust type, re-specified from
///   `ArchivalBondValue` v7 — same semantics, its own encoding, `SAR-Q3`);
///   `archival_serve_credit` → the tuple `(persona, shard, epoch, height)`
///   → `Present` (the 56-byte pack becomes a component-wise key);
///   `archival_r_market` → `(u64, u64) → Coded<RMarket>`;
///   `archival_sigma_work` → `Coded<SigmaWorkMilli>`; `archival_budget` →
///   `Coded<AtomicUnits>`; `archival_attestation_witness` →
///   `Blob<AttestationWitnessBytes>`; and `properties` gains the
///   `archival_last_slash_epoch` cell. Five codec fixtures are born
///   (`bond_record`, `r_market`, `sigma_work_milli`, `settlement_epoch`,
///   `shard_id`). The digest's families do not move (§7.1.1 excludes
///   `archival_*`); the layout does.
/// - `12` — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §4): **the pool leaves the
///   consensus file.** `txpool_meta` and `txpool_blob` are evicted from
///   this catalogue (`DAEMON_REDB_STORE.md` §5.1's pick, built) — which
///   moves every later table's ordinal by two, so a v11 pop journal names
///   the wrong tables under v12 — and the pool file is born: its own
///   `redb::Database` (`crate::pool`), three tables (`pool_meta` →
///   `[u8; 32] → Coded<PoolRecord>`, `pool_blob` → `Blob<PoolTxBytes>`, its
///   `pool_header`), one layout number for the crate's two files
///   (`SPL-Q8` as built: the pool file seals this constant in its own
///   header cell and is **recreated**, not refused, at another value).
///   `pool_record` is the persisted `txpool_tx_meta_t` re-specified as
///   `RelayState` — the phase enum is chosen by provenance, so an
///   originated entry is `Held` or `Block` and an arrival is `Stem`,
///   `Fluff` or `Block`; two fixtures are born (`pool_record`,
///   `pool_tables`). No digest family
///   moves: the pool was never in one (§11.2).
/// - `13` — DRS-E1 S-ALT (`DRS_E1_SALT.md` §4): **the alt-chain store
///   stays in this file and takes its shape.** `alt_blocks` →
///   `LmdbHashKey → Coded<AltBlock>` — the C++ `alt_block_data_t ‖ blob`
///   re-specified as one record: the `u128` as one field, the weight's
///   zero sentinel as `None`, the block bytes and the reorg-survival
///   attestation witness as fields (`SAL-Q2`). One fixture is born
///   (`alt_block`). `archival_alt_attestation_witness` is **folded** into
///   that record and leaves this catalogue (`FOLDED_INTO`, SAL-2) — every
///   later table's ordinal moves by one. No digest family moves: the alt
///   surface is `Excluded` (§11.2), and a write to it moving no digest is
///   now a test rather than a declaration (SAL-15).
/// - `14` — DRS-E1 S-PRUNE (`DRS_E1_SPRUNE.md`): **the retention prune.**
///   `properties` gains the `undo_log_floor` cell — the lowest height whose
///   `undo_log` row the boundary batch kept, written monotone as rows below
///   `tip − retention` are retired, read by `pop` to tell *pruned below*
///   from *lost*. No table moves; the body discard stores nothing (its set
///   is named by the epoch). `txs_pqc_auths` re-grades `AppendMostly →
///   Excluded` in the accumulator matrix: this surface deletes its rows,
///   and the permanent `txs_pqc_auth_hash` row is the append-mostly one.
/// - `15` — DRS-E3 (`DRS_E3_CURVE_WRITER.md` §3.7, commit 1): **the
///   curve-tree writer's tables.** Four X-macro tables are **not ported**
///   (`NOT_PORTED`, the bijection gate's fifth direction): the pending set
///   is a view of the block index (maturity is `f(height, is_miner)`), two
///   were the C++'s pop journals (the `undo_log` is ours), and the
///   checkpoint row is a view of the meta row — every later table's ordinal
///   moves. `output_to_leaf` / `leaf_to_output` take types
///   (`TreePosition` / `GlobalOutputIndex`, the drain-order bijection,
///   SI-17). `curve_tree_leaf_counts` is born, Rust-only: the count at each
///   height, keyed as the roots are (`CTW-Q4`). No digest family moves.
///   The same increment (commit 5) deletes `root_after` from `ConnectFacts`
///   — `validate` derives it, `connect` records the verdict's — so
///   `FACT_FIELDS` loses its name and the `passed_through_facts` vocabulary
///   shrinks 6 → 5 under this one bump (the `7` mechanism, second instance).
/// - `16` — E6 slice 7 commit 5 (`CHAIN_RULES_SLICE_7.md` §5 row 5):
///   **four passed-through facts become the verdict's.** `validate` derives
///   the two block-weight medians (CEN-G6/G6b), the block's weight and
///   long-term weight, the paid reward and the advanced accumulator
///   (CEN-F14b, G12); `connect` records `ValidatedBlock::{weights,
///   emission}`. `weight`, `long_term_weight`, `long_term_effective_median`
///   and `coins_generated` leave `ConnectFacts` and `FACT_FIELDS`, so the
///   `passed_through_facts` vocabulary shrinks 5 → 1 (`burned` remains for
///   wave B) — the `7` mechanism, third instance. No table moves; no digest
///   family moves: the cells hold the same columns, now written from the
///   verdict.
/// - `17` — E6 slice 7 wave B (`CHAIN_RULES_SLICE_7.md` §5 row 9): **the
///   last passed-through fact becomes the verdict's, and the cell goes.**
///   `validate` derives the fee split (CEN-F17 / G11) and `connect` records
///   `ValidatedBlock::emission`'s burn; `burned` leaves `ConnectFacts`,
///   which leaves with it — `Fact`, `Origin`, `FACT_FIELDS` and
///   `PassedThroughFacts` are deleted rather than kept as a permanent
///   `Derived` (rule 15). The `passed_through_facts` **property cell is no
///   longer written or read**: the catalogue loses a row and the seal
///   writes one cell fewer, which is the layout change (a `16` file has a
///   cell this binary does not know; the seal refuses it — rebuild, never
///   migrate). No table moves; no digest family moves.
/// - `18` — the `SHT-Q2` build (`ARCHIVAL_SHARD_T_DERIVATION.md` §8.6,
///   RULED 2026-09-29): **shards are cut by archival length.**
///   `txs_archival_len` is born, Rust-only, appended at ordinal 43: each
///   transaction's `|prunable| + |pqc_auths|`, sparse (present ⇔ `> 0`),
///   never pruned. `block_info` widens 104 → 112 bytes with
///   `cumulative_archival_len`, the running total every shard boundary is
///   read off (`⌊C / W⌋`), widened under S-CHAIN-R's Q4 ruling. The prune
///   stores nothing new: `D(E)` is still named by the epoch. Digest v0 reads
///   `block_info` by `bi_hash` alone, and the new table is outside the
///   digest domain, so no digest family moves.
/// - `19` — DRS-E4 commit 1 (`DRS_E4_ARCHIVAL_WRITER.md` §3.3, §3.4, §6):
///   **the archival write surface's tables decided.** Seven X-macro tables
///   leave as `NOT_PORTED` — five C++ pop journals and the epoch-close log
///   (the undo log holds their pre-images), the per-height accrual rows (a
///   view), the retired freeze registry — and the ordinals of every later
///   table shift (`txs_archival_len` 43 → 37), which is the layout change:
///   an undo row written under `18` names targets by ordinal.
///   `archival_slash_log` and `archival_slash_applied` gain their types
///   (`(u64, u32) → slash_log_entry`, `([u8; 32], u64, u64) → Present`);
///   `archival_budget_accruing` is born Rust-only. No digest family moves
///   yet (`digest_v1` is commit 6's).
/// - `20` — DRS-E4 commit 5 (`DRS_E4_ARCHIVAL_WRITER.md` §3.2 phase 9,
///   §3.5, `ARW-Q3`): **the undo log gains a third entry kind.** The
///   epoch close deletes `archival_budget_accruing[E]` in the transaction
///   that writes `archival_budget[E]`, and the store's first journaling
///   delete records `Removed { table, key, prior }` under **tag 4**
///   (`codec/undo.rs`); a `19` file's undo rows decode under `20`, but a
///   `20` row with a tag-4 entry is a corrupt cell to `19`'s decoder and
///   the pop it would drive must not be attempted. No table or digest
///   family moves.
/// - `21` — the txid binds the archival length (`SHT-Q2`,
///   `GENESIS_TX_WIRE_FORMAT.md` §11). **Content, not layout:** no table,
///   codec or fixture moves, but the bytes a connect stores for the same
///   chain do — `tx_indices` is keyed by the txid and every block body lists
///   its transactions by it, and every non-coinbase txid changed. A store
///   written under `20` or earlier names its spends by ids this binary does
///   not compute, and would halt at its first skeleton rebuild as
///   corruption; the bump refuses it at open with the true reason. LMDB
///   took `VERSION` 15 → 16 with the same change, for the same reason.
/// - `22` — the settlement writer's tables (`ARCHIVAL_SETTLEMENT_WRITER.md`
///   §14, `SO-D10`). `archival_settlement` leaves `Unshaped` for
///   `([u8; 32], u64, u64) → settlement_row` and is sealed from here on;
///   `archival_issued_draw` (`(u64, [u8; 32], u64, u64, u32) →
///   issued_draw`) and `archival_issued_digest` (`u64 → issued_digest`) are
///   born Rust-only, appended at ordinals 38 and 39 so no existing ordinal
///   moves. A `21` file lacks all three, and `header::verify` would refuse
///   it as a sealed file missing a table (SI-7); the bump refuses it at
///   open with the true reason. No snapshot family moves: none of the
///   three has a C++ counterpart to compare.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(22);

/// A layout version as stored in the `schema_version` cell.
///
/// A newtype rather than a bare `u64` so a height or a count cannot be
/// handed to the version check by mistake, and so the cell has its own
/// snapshot under its own name. Per rule 42's *envelope vs payload*
/// distinction this is the **payload/layout** version: it is what the
/// store's bytes are laid out under, and there is no envelope version
/// because redb owns the file container (§11.1(c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion(u64);

impl SchemaVersion {
    /// Wrap a raw version number.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// The raw number, for diagnostics.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "schema v{}", self.0)
    }
}

impl Canonical for SchemaVersion {
    const NAME: &'static str = "schema_version";
    const FIXED_WIDTH: Option<usize> = <u64 as Canonical>::FIXED_WIDTH;

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_version_is_pinned_and_encodes_as_u64_le() {
        // Moves with every layout bump, on purpose: the history list above
        // this constant is the record, and this line is what makes a bump
        // without a history entry visible in review.
        assert_eq!(SCHEMA_VERSION, SchemaVersion::new(22));
        assert_eq!(SCHEMA_VERSION.encode(), [22, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            SchemaVersion::decode(&[22, 0, 0, 0, 0, 0, 0, 0]),
            Ok(SCHEMA_VERSION)
        );
    }

    #[test]
    fn a_length_error_names_the_version_codec() {
        assert_eq!(
            SchemaVersion::decode(&[1, 0]),
            Err(CodecError::Length {
                codec: "schema_version",
                expected: 8,
                actual: 2
            })
        );
    }

    #[test]
    fn display_says_what_kind_of_version_it_is() {
        assert_eq!(SchemaVersion::new(7).to_string(), "schema v7");
    }
}

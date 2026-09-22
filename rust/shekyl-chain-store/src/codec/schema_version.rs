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
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(9);

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
        assert_eq!(SCHEMA_VERSION, SchemaVersion::new(9));
        assert_eq!(SCHEMA_VERSION.encode(), [9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            SchemaVersion::decode(&[9, 0, 0, 0, 0, 0, 0, 0]),
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

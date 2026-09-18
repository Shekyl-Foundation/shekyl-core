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
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(2);

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
        assert_eq!(SCHEMA_VERSION, SchemaVersion::new(2));
        assert_eq!(SCHEMA_VERSION.encode(), [2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            SchemaVersion::decode(&[2, 0, 0, 0, 0, 0, 0, 0]),
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

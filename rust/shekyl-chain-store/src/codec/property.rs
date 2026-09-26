// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed cells of the `properties` table.
//!
//! `properties` is one `&str → &[u8]` table holding values of **different
//! types and different jurisdictions**: engine bookkeeping (`version`,
//! `pruning_seed`) sits next to chain state (`total_burned`,
//! `total_bonded_atomic`). LMDB's schema does not tell them apart and the
//! C++ reads each cell by string at every call site. Here a cell is a
//! **type**: its key, its value codec and its scope are declared once, and
//! a read or write of that cell is a generic over the type rather than a
//! string that might be misspelled at one site.
//!
//! # Scope is the digest's fold domain
//!
//! `LMDB_WRITE_ATOMICITY_AUDIT.md` §12 classes `properties` as *small*
//! (full-domain digest every block). That class cannot mean "every cell":
//! `apply_policy` differs between a parity run and a sufficiency run over
//! identical chain state, and `schema_version` is layout, not state. The
//! `properties` fold is therefore defined as **every
//! [`ChainState`] cell and nothing else**, and the scope lives on the cell
//! type so the fold cannot pick the domain up by string.
//!
//! # Scope is also the write permission
//!
//! Scope is an associated **type**, not only a constant, so a bound can
//! name it: [`WriteBatch::upsert_property`](crate::store::WriteBatch::upsert_property)
//! accepts `C: PropertyCell<Scope = ChainState>` and nothing else. The
//! two [`EngineLocal`] header cells are therefore unwritable through the
//! public surface by construction — the store's own seal and commit paths
//! are their only writers — and the raw `properties` table is refused on
//! the write side altogether so this cannot be routed around by string.
//!
//! # The cell set is closed
//!
//! A permission carried on the cell type is only as strong as the set of
//! cell types. If any crate could implement [`PropertyCell`], it could
//! declare a marker with `KEY = "schema_version"` and `Scope = ChainState`
//! and the bound above would admit it: the seal would be overwritable by
//! anyone who typed the string. So the trait is **sealed** — its private
//! supertrait can only be implemented in this module — and every cell is
//! minted by `property_cells!` here, which also records it in
//! [`PROPERTY_CELLS`]. A cell is therefore part of the store's *layout*: it is
//! declared in this crate, it is enumerable (the digest fold reads its
//! domain from the same list), and its key cannot collide with another
//! cell's without a test in this module failing.

use shekyl_types::{BlockHeight, SettlementEpoch};
use shekyl_units::AtomicUnits;

use crate::family_set::FamilySet;

use super::{
    BlobKind, Canonical, CoverageGaps, PassedThroughFacts, SchemaVersion, SettlementEpochBlocks,
};

/// The value shape of the `properties` table (`shape` module docs).
///
/// `properties` is the one table whose codec is chosen **per key**: each
/// [`PropertyCell`] names its own `Value: Canonical`, and the store decodes
/// a cell under the codec its key selects (`store/header.rs`). No single
/// `Coded<V>` can name that, so the table is a [`Blob`](super::Blob) of
/// this kind, and `well_formed` checks what can be checked without the
/// key: nothing. The per-cell strictness lives where the key is.
#[derive(Debug)]
pub struct PropertyCellBytes;

impl BlobKind for PropertyCellBytes {
    const NAME: &'static str = "property_cell";
}

/// Whose state a `properties` cell is, as a value (for the digest fold).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellScope {
    /// Consensus-visible chain state. In the `properties` digest domain;
    /// identical across every correct store of the same chain.
    ChainState,
    /// This store's own bookkeeping. **Out** of the digest domain; may
    /// legitimately differ between two stores of the same chain.
    EngineLocal,
}

impl CellScope {
    /// Stable token for the property-catalogue snapshot. Changing a
    /// spelling here without moving `properties.snap` is a gate failure.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChainState => "chain_state",
            Self::EngineLocal => "engine_local",
        }
    }
}

/// A cell scope, as a type (for bounds). Sealed: exactly two exist.
pub trait Scope: sealed::Sealed {
    /// This scope as a value.
    const SCOPE: CellScope;
}

/// Type-level [`CellScope::ChainState`]. The only scope
/// [`WriteBatch::upsert_property`](crate::store::WriteBatch::upsert_property) accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainState;

/// Type-level [`CellScope::EngineLocal`]. Written only by the store itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineLocal;

impl Scope for ChainState {
    const SCOPE: CellScope = CellScope::ChainState;
}

impl Scope for EngineLocal {
    const SCOPE: CellScope = CellScope::EngineLocal;
}

/// The seal on [`Scope`] and [`PropertyCell`]: implementable only here.
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ChainState {}
    impl Sealed for super::EngineLocal {}
}

/// One cell of the `properties` table, as a type.
///
/// Implemented on a zero-sized marker per cell; the marker is the only
/// thing a caller names. **Sealed**: cells are declared by
/// `property_cells!` in this module and nowhere else (module docs, *The
/// cell set is closed*). A foreign marker cannot borrow a header cell's
/// key to reach it through the chain-state write bound:
///
/// ```compile_fail,E0277
/// use shekyl_chain_store::codec::{ChainState, PropertyCell, SchemaVersion};
///
/// struct Impostor;
///
/// impl PropertyCell for Impostor {
///     const KEY: &'static str = "schema_version";
///     type Scope = ChainState;
///     type Value = SchemaVersion;
/// }
/// ```
pub trait PropertyCell: sealed::Sealed {
    /// The key, ASCII, stored **without** NUL terminator or length prefix
    /// (§11.1(a) pins the byte form because `properties` orders by string
    /// comparison, so the bytes are load-bearing for the port).
    const KEY: &'static str;
    /// Whether the cell is in the digest's fold domain — and, through the
    /// bound on `upsert_property`, whether callers may write it.
    type Scope: Scope;
    /// The cell's value codec.
    type Value: Canonical;

    /// [`Self::Scope`] as a value.
    const SCOPE: CellScope = <Self::Scope as Scope>::SCOPE;
}

/// One `properties` cell as the store's layout records it.
///
/// Emitted by `property_cells!` as [`PROPERTY_CELLS`]. The property-catalogue
/// snapshot pins every field: renaming a key, moving a scope, or changing
/// the value codec is a layout change even when no codec fixture's bytes
/// move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyCellSpec {
    /// [`PropertyCell::KEY`].
    pub key: &'static str,
    /// Digest-domain membership and write permission.
    pub scope: CellScope,
    /// [`Canonical::NAME`] of [`PropertyCell::Value`].
    pub value: &'static str,
}

/// Declares the closed set of `properties` cells.
///
/// Each entry mints the marker type, its [`PropertyCell`] impl and its
/// seal, and adds one [`PropertyCellSpec`] row to [`PROPERTY_CELLS`] — so
/// the list a reader or the digest fold consults and the set of types the
/// compiler admits are one declaration, not two that can drift.
macro_rules! property_cells {
    (
        $(
            $(#[$attr:meta])*
            $name:ident { key: $key:literal, scope: $scope:ident, value: $value:ty }
        ),+ $(,)?
    ) => {
        $(
            $(#[$attr])*
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct $name;

            impl sealed::Sealed for $name {}

            impl PropertyCell for $name {
                const KEY: &'static str = $key;
                type Scope = $scope;
                type Value = $value;
            }
        )+

        /// Every cell of the `properties` table, in declaration order.
        /// **This is the store's cell set**: a key not here is not a cell
        /// this binary reads or writes, and the [`ChainState`] rows are
        /// exactly the `properties` digest domain.
        pub const PROPERTY_CELLS: &[PropertyCellSpec] = &[
            $(PropertyCellSpec {
                key: $key,
                scope: <$scope as Scope>::SCOPE,
                value: <$value as Canonical>::NAME,
            }),+
        ];
    };
}

property_cells! {
    /// `schema_version` — the layout this store was written under (§11.1(a)).
    ///
    /// Engine-local: two stores of the same chain at different layout
    /// versions hold the same state, and one refuses to open under the
    /// other's binary.
    SchemaVersionCell { key: "schema_version", scope: EngineLocal, value: SchemaVersion },

    /// `apply_policy` — the archival families whose applies **some
    /// committed batch skipped**, over the whole life of this file.
    ///
    /// The value is a union that only grows: a stubbed session widens it in
    /// the same transaction as the rows it wrote, and nothing narrows it,
    /// so a file that ever took a stubbed commit says so forever.
    /// Engine-local by necessity — a sufficiency run and a parity run over
    /// the same chain must digest identically, or the sufficiency red could
    /// not be attributed to the skipped apply.
    ApplyPolicyCell { key: "apply_policy", scope: EngineLocal, value: FamilySet },

    /// `settlement_epoch_blocks` — the archival settlement schedule this
    /// file was built under (S-CHAIN-W SCW-2; the C++ pin's key, verbatim).
    ///
    /// Sealed at create from the session's value, compared at every open,
    /// refused on mismatch ([`StoreCannot::SettlementEpochMismatch`]):
    /// epoch-derived rows are only meaningful under the schedule that
    /// wrote them. Engine-local: two correct stores of one chain hold the
    /// same chain state whatever schedule label each carries, and a
    /// mismatch is a refusal to open, never a digest difference.
    ///
    /// [`StoreCannot::SettlementEpochMismatch`]: crate::store::StoreCannot::SettlementEpochMismatch
    SettlementEpochBlocksCell {
        key: "settlement_epoch_blocks",
        scope: EngineLocal,
        value: SettlementEpochBlocks
    },

    /// `rule_coverage_gaps` — census rows some committed `connect` was
    /// handed a verdict for without the row having been evaluated
    /// (C2-R8 §9.4, S-CHAIN-W §3.8). The second component of the file's
    /// [`Provenance`](crate::provenance::Provenance): widened in the
    /// committing batch's own transaction, never narrowed. Engine-local —
    /// two correct stores of one chain validated by validators of
    /// different completeness hold the same chain state and different
    /// evidence.
    CoverageGapsCell { key: "rule_coverage_gaps", scope: EngineLocal, value: CoverageGaps },

    /// `passed_through_facts` — `ConnectFacts` fields some committed
    /// `connect` recorded as passed through rather than derived (SCW-1).
    /// The third provenance component; same discipline as the second.
    /// `block_info`'s diff rows are not parity evidence while this is
    /// non-empty, and it names which E6 rows make them so.
    PassedThroughFactsCell {
        key: "passed_through_facts",
        scope: EngineLocal,
        value: PassedThroughFacts
    },

    /// `total_burned` — the chain's destroyed-fee fold (C++
    /// `set_total_burned`; `LMDB_SCHEMA.md` `properties`).
    ///
    /// Chain state, and therefore in the `properties` digest domain and
    /// writable through `upsert_property`. Written by `connect` as
    /// `checked_add` of the block's burned amount (register row SI-8 — an
    /// overflow is fatal, never a saturate); `pop` restores the journaled
    /// pre-image, so there is no subtract and no pop-side saturation.
    TotalBurnedCell { key: "total_burned", scope: ChainState, value: AtomicUnits },

    /// `undo_log_floor` — the lowest height whose `undo_log` row the
    /// retention prune has kept (DRS-E1 S-PRUNE, `DRS_E1_SPRUNE.md` §3, §7;
    /// S-CHAIN-W §5.4's "persists the floor it establishes").
    ///
    /// Written by the boundary batch as it retires rows below
    /// `tip − retention`, monotone (never lowered). `pop` reads it to tell
    /// *pruned below* (a capability limit,
    /// [`StoreCannot::PopBelowFloor`](crate::store::StoreCannot::PopBelowFloor))
    /// from *lost* (a journal that does not describe its tables, SI-6).
    /// **Absent means nothing has been retired** — the floor is genesis, `1`.
    /// Engine-local: two correct stores of one chain under different
    /// retention parameters hold the same chain state and different floors;
    /// this is not the body discard's frontier (which is named by the epoch
    /// and stored nowhere, §4) but the undo journal's own retention mark.
    UndoLogFloorCell { key: "undo_log_floor", scope: EngineLocal, value: BlockHeight },

    /// `archival_last_slash_epoch` — the slash scheduler's monotone settled
    /// watermark: every settlement epoch `<=` the value has been scanned at
    /// its slash deadline (DRS-E1 S-ARCH A9; the C++ key, verbatim).
    ///
    /// **Absent means no epoch settled yet** — the C++ spelled that as a
    /// `u64::MAX` sentinel (`db_lmdb.cpp`, `get_archival_last_slash_epoch`);
    /// here the read is `Option<SettlementEpoch>` and no sentinel is stored.
    /// Chain-state: the bond-post admission and the emission claim source
    /// read it as a consensus fact. E4's slash writer is its one writer; the
    /// cell is absent in every store until then, so the digest domain gains
    /// a key and no bytes (DRS-E2's archival coverage arrives with E4,
    /// `DRS_E1_SARCH.md` SAR-11).
    ArchivalLastSlashEpochCell {
        key: "archival_last_slash_epoch",
        scope: ChainState,
        value: SettlementEpoch
    },
}

/// A chain-state cell that exists only in this crate's tests, so the typed
/// write surface can be exercised before any production chain-state cell
/// lands (`total_burned`, … arrive with the surfaces that write them).
///
/// Deliberately **outside** `property_cells!` and therefore outside
/// [`PROPERTY_CELLS`]: it is a test fixture, not part of the store's layout.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeCell;

#[cfg(test)]
impl sealed::Sealed for ProbeCell {}

#[cfg(test)]
impl PropertyCell for ProbeCell {
    const KEY: &'static str = "__e1_probe_cell";
    type Scope = ChainState;
    type Value = u64;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn the_schema_version_key_bytes_are_the_pinned_fourteen() {
        // §11.1(a): ASCII `schema_version`, 14 bytes, no NUL, no length
        // prefix. The exact bytes are load-bearing because `properties`
        // orders by string comparison.
        assert_eq!(
            SchemaVersionCell::KEY.as_bytes(),
            [0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e]
        );
        assert_eq!(SchemaVersionCell::KEY.len(), 14);
    }

    #[test]
    fn header_cells_are_engine_local_and_never_in_the_digest_domain() {
        // A store written under a stubbed policy must digest identically to
        // one written under Full, or the sufficiency control's red could
        // not be attributed to the skipped apply. Layout is not state.
        assert_eq!(SchemaVersionCell::SCOPE, CellScope::EngineLocal);
        assert_eq!(ApplyPolicyCell::SCOPE, CellScope::EngineLocal);
        assert_eq!(<ChainState as Scope>::SCOPE, CellScope::ChainState);
        assert_eq!(CellScope::ChainState.as_str(), "chain_state");
        assert_eq!(CellScope::EngineLocal.as_str(), "engine_local");
    }

    #[test]
    fn the_registry_lists_every_declared_cell_with_its_scope() {
        // The macro writes both the impl and the row; this holds them equal
        // for the two cells that exist, and is the shape every later cell
        // is checked by.
        assert_eq!(
            PROPERTY_CELLS,
            &[
                PropertyCellSpec {
                    key: SchemaVersionCell::KEY,
                    scope: SchemaVersionCell::SCOPE,
                    value: SchemaVersion::NAME,
                },
                PropertyCellSpec {
                    key: ApplyPolicyCell::KEY,
                    scope: ApplyPolicyCell::SCOPE,
                    value: FamilySet::NAME,
                },
                PropertyCellSpec {
                    key: SettlementEpochBlocksCell::KEY,
                    scope: SettlementEpochBlocksCell::SCOPE,
                    value: SettlementEpochBlocks::NAME,
                },
                PropertyCellSpec {
                    key: CoverageGapsCell::KEY,
                    scope: CoverageGapsCell::SCOPE,
                    value: CoverageGaps::NAME,
                },
                PropertyCellSpec {
                    key: PassedThroughFactsCell::KEY,
                    scope: PassedThroughFactsCell::SCOPE,
                    value: PassedThroughFacts::NAME,
                },
                PropertyCellSpec {
                    key: TotalBurnedCell::KEY,
                    scope: TotalBurnedCell::SCOPE,
                    value: AtomicUnits::NAME,
                },
                PropertyCellSpec {
                    key: UndoLogFloorCell::KEY,
                    scope: UndoLogFloorCell::SCOPE,
                    value: BlockHeight::NAME,
                },
                PropertyCellSpec {
                    key: ArchivalLastSlashEpochCell::KEY,
                    scope: ArchivalLastSlashEpochCell::SCOPE,
                    value: SettlementEpoch::NAME,
                },
            ]
        );
        // The two chain-state cells are the digest-domain members.
        assert_eq!(TotalBurnedCell::SCOPE, CellScope::ChainState);
        assert_eq!(ArchivalLastSlashEpochCell::SCOPE, CellScope::ChainState);
        // The C++ store's key, byte for byte (S-ARCH A9).
        assert_eq!(ArchivalLastSlashEpochCell::KEY, "archival_last_slash_epoch");
        assert_eq!(SettlementEpochBlocksCell::SCOPE, CellScope::EngineLocal);
        // The pin's key is the C++ store's key, byte for byte.
        assert_eq!(SettlementEpochBlocksCell::KEY, "settlement_epoch_blocks");
    }

    #[test]
    fn cell_keys_are_plain_lowercase_ascii_and_distinct() {
        let mut seen = BTreeSet::new();
        for cell in PROPERTY_CELLS {
            assert!(!cell.key.is_empty() && !cell.key.contains('\0'), "{cell:?}");
            assert!(
                cell.key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{:?}: `properties` orders by string comparison; keep keys to [a-z_]",
                cell.key
            );
            assert!(
                seen.insert(cell.key),
                "duplicate `properties` key {:?}",
                cell.key
            );
        }
        // The test-only probe must not shadow a real cell either.
        assert!(
            !seen.contains(ProbeCell::KEY),
            "ProbeCell::KEY collides with a declared cell"
        );
    }
}

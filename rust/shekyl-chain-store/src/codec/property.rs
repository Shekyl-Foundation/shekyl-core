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
//! name it: [`WriteBatch::put_property`](crate::store::WriteBatch::put_property)
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

use crate::family_set::FamilySet;

use super::{Canonical, SchemaVersion};

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

/// A cell scope, as a type (for bounds). Sealed: exactly two exist.
pub trait Scope: sealed::Sealed {
    /// This scope as a value.
    const SCOPE: CellScope;
}

/// Type-level [`CellScope::ChainState`]. The only scope
/// [`WriteBatch::put_property`](crate::store::WriteBatch::put_property) accepts.
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
    /// bound on `put_property`, whether callers may write it.
    type Scope: Scope;
    /// The cell's value codec.
    type Value: Canonical;

    /// [`Self::Scope`] as a value.
    const SCOPE: CellScope = <Self::Scope as Scope>::SCOPE;
}

/// Declares the closed set of `properties` cells.
///
/// Each entry mints the marker type, its [`PropertyCell`] impl and its
/// seal, and adds one `(KEY, CellScope)` row to [`PROPERTY_CELLS`] — so the list a
/// reader or the digest fold consults and the set of types the compiler
/// admits are one declaration, not two that can drift.
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

        /// Every cell of the `properties` table, as `(KEY, scope)`, in
        /// declaration order. **This is the store's cell set**: a key not
        /// here is not a cell this binary reads or writes, and the
        /// [`ChainState`] rows are exactly the `properties` digest domain.
        pub const PROPERTY_CELLS: &[(&str, CellScope)] = &[$(($key, <$scope as Scope>::SCOPE)),+];
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
    }

    #[test]
    fn the_registry_lists_every_declared_cell_with_its_scope() {
        // The macro writes both the impl and the row; this holds them equal
        // for the two cells that exist, and is the shape every later cell
        // is checked by.
        assert_eq!(
            PROPERTY_CELLS,
            &[
                (SchemaVersionCell::KEY, SchemaVersionCell::SCOPE),
                (ApplyPolicyCell::KEY, ApplyPolicyCell::SCOPE),
            ]
        );
    }

    #[test]
    fn cell_keys_are_plain_lowercase_ascii_and_distinct() {
        let mut seen = BTreeSet::new();
        for (key, _) in PROPERTY_CELLS {
            assert!(!key.is_empty() && !key.contains('\0'), "{key:?}");
            assert!(
                key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{key:?}: `properties` orders by string comparison; keep keys to [a-z_]"
            );
            assert!(seen.insert(*key), "duplicate `properties` key {key:?}");
        }
        // The test-only probe must not shadow a real cell either.
        assert!(
            !seen.contains(ProbeCell::KEY),
            "ProbeCell::KEY collides with a declared cell"
        );
    }
}

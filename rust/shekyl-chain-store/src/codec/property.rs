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

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ChainState {}
    impl Sealed for super::EngineLocal {}
}

/// One cell of the `properties` table, as a type.
///
/// Implemented on a zero-sized marker per cell; the marker is the only
/// thing a caller names.
pub trait PropertyCell {
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

/// `schema_version` — the layout this store was written under (§11.1(a)).
///
/// Engine-local: two stores of the same chain at different layout versions
/// hold the same state, and one refuses to open under the other's binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaVersionCell;

impl PropertyCell for SchemaVersionCell {
    const KEY: &'static str = "schema_version";
    type Scope = EngineLocal;
    type Value = SchemaVersion;
}

/// `apply_policy` — the archival families whose applies **some committed
/// batch skipped**, over the whole life of this file.
///
/// The value is a union that only grows: a stubbed session widens it in
/// the same transaction as the rows it wrote, and nothing narrows it, so a
/// file that ever took a stubbed commit says so forever. Engine-local by
/// necessity — a sufficiency run and a parity run over the same chain must
/// digest identically, or the sufficiency red could not be attributed to
/// the skipped apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyPolicyCell;

impl PropertyCell for ApplyPolicyCell {
    const KEY: &'static str = "apply_policy";
    type Scope = EngineLocal;
    type Value = FamilySet;
}

#[cfg(test)]
mod tests {
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
    fn header_keys_are_plain_ascii_and_distinct() {
        for key in [SchemaVersionCell::KEY, ApplyPolicyCell::KEY] {
            assert!(key.is_ascii() && !key.contains('\0'), "{key:?}");
            assert!(
                key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{key:?}"
            );
        }
        assert_ne!(SchemaVersionCell::KEY, ApplyPolicyCell::KEY);
    }
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Subaddress index type.
//!
//! Shekyl's subaddress index space is **flat**: a single `u32`. There is no
//! `(account, address)` two-level hierarchy as in wallet2 — see
//! `docs/V3_WALLET_DECISION_LOG.md` entry "Subaddress hierarchy: flat, no
//! account level". The primary address is `SubaddressIndex(0)`; user-derived
//! subaddresses run `1..u32::MAX`. The `0` value is **not** reserved on this
//! type — primary and derived addresses both come from the same derivation
//! function (see `shekyl_scanner::view_pair::ViewPair::subaddress_derivation`)
//! to avoid a special-case code path. Callers that want to test "this is the
//! primary address" use `idx.get() == 0`.
//!
//! ## Wire shape
//!
//! On disk and on the wire, `SubaddressIndex` serializes as a bare `u32`
//! (postcard varint, JSON integer). The previous two-field struct
//! `{account, address}` is gone; pre-genesis there is no migration path.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// A subaddress index identifying a derived address within a wallet.
///
/// Flat namespace: a single `u32`. The primary address is the index `0`;
/// user-derived subaddresses run `1..u32::MAX`. `Ord` is the natural `u32`
/// order, used to key [`BTreeMap`](std::collections::BTreeMap) entries in
/// [`BookkeepingBlock`](crate::bookkeeping_block::BookkeepingBlock) so
/// postcard serialization is byte-stable across runs.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    Zeroize,
    postcard_schema::Schema,
)]
pub struct SubaddressIndex(u32);

impl SubaddressIndex {
    /// The primary-address index. Equivalent to `SubaddressIndex(0)` and
    /// `SubaddressIndex::default()`; named for clarity at call sites.
    pub const PRIMARY: Self = SubaddressIndex(0);

    /// Construct a [`SubaddressIndex`] from a raw `u32`. All values are
    /// valid — there is no reserved index. Pair with [`Self::PRIMARY`] when
    /// expressing the primary address.
    pub const fn new(index: u32) -> Self {
        SubaddressIndex(index)
    }

    /// The underlying `u32` value.
    pub const fn get(&self) -> u32 {
        self.0
    }

    /// Whether this is the primary-address index. Convenience over
    /// `idx.get() == 0`.
    pub const fn is_primary(&self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for SubaddressIndex {
    fn from(value: u32) -> Self {
        SubaddressIndex(value)
    }
}

impl From<SubaddressIndex> for u32 {
    fn from(value: SubaddressIndex) -> Self {
        value.0
    }
}

// Serialize as a bare u32 — the wire shape is the integer, not a struct.
// Using the auto-derived `Serialize` would wrap the value in a one-tuple
// container which postcard can encode, but JSON consumers expect the bare
// integer. Hand-rolled impls keep the two encodings identical.
impl Serialize for SubaddressIndex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for SubaddressIndex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        u32::deserialize(d).map(SubaddressIndex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json_primary() {
        let idx = SubaddressIndex::PRIMARY;
        let s = serde_json::to_string(&idx).unwrap();
        assert_eq!(s, "0");
        let back: SubaddressIndex = serde_json::from_str(&s).unwrap();
        assert_eq!(idx, back);
        assert!(back.is_primary());
    }

    #[test]
    fn roundtrip_json_derived() {
        let idx = SubaddressIndex::new(42);
        let s = serde_json::to_string(&idx).unwrap();
        assert_eq!(s, "42");
        let back: SubaddressIndex = serde_json::from_str(&s).unwrap();
        assert_eq!(idx, back);
        assert!(!back.is_primary());
    }

    #[test]
    fn ord_is_natural_u32_order() {
        let a = SubaddressIndex::new(1);
        let b = SubaddressIndex::new(2);
        let c = SubaddressIndex::new(u32::MAX);
        assert!(a < b);
        assert!(b < c);
        assert!(SubaddressIndex::PRIMARY < a);
    }

    #[test]
    fn from_into_u32() {
        let idx: SubaddressIndex = 7u32.into();
        assert_eq!(idx.get(), 7);
        let raw: u32 = idx.into();
        assert_eq!(raw, 7);
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A set of [`ArchivalFamily`], as a bit per family.
//!
//! The one set type both [`ApplyPolicy`](crate::apply_policy::ApplyPolicy)
//! (the families *this session* skips) and
//! [`Provenance`](crate::provenance::Provenance) (the families *some
//! committed session ever* skipped) are made of. It is `Copy`, `const`
//! -constructible, and has a four-byte canonical encoding so the
//! provenance cell is a fixed-width row rather than a list.

use crate::apply_policy::ArchivalFamily;
use crate::codec::{exact, Canonical, CodecError};

// One bit per family. Adding the thirty-third family is a layout change
// (a wider cell) and therefore a `SCHEMA_VERSION` bump, which this makes
// impossible to do by accident.
const _: () = assert!(
    ArchivalFamily::ALL.len() <= u32::BITS as usize,
    "FamilySet is a u32 bitset; widen it (and bump SCHEMA_VERSION) before adding a 33rd family"
);

/// The bits that name a family. Everything above is not an encoding.
const VALID_BITS: u32 = if ArchivalFamily::ALL.len() == u32::BITS as usize {
    u32::MAX
} else {
    (1_u32 << ArchivalFamily::ALL.len()) - 1
};

/// A set of archival families.
///
/// Bit `i` is [`ArchivalFamily::ALL`]`[i]` — macro order, the same order
/// `check_lmdb_schema_coverage.py` pins against the X-macro — so the
/// encoding is fixed by the family list and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FamilySet(u32);

impl FamilySet {
    /// No families.
    pub const EMPTY: Self = Self(0);

    /// Every family.
    pub const ALL: Self = Self(VALID_BITS);

    /// The set of the given families. Duplicates collapse.
    #[must_use]
    pub const fn of(families: &[ArchivalFamily]) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < families.len() {
            set = set.with(families[i]);
            i += 1;
        }
        set
    }

    /// This set plus `family`.
    #[must_use]
    pub const fn with(self, family: ArchivalFamily) -> Self {
        Self(self.0 | family.bit())
    }

    /// Every family in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `family` is in the set.
    #[must_use]
    pub const fn contains(self, family: ArchivalFamily) -> bool {
        self.0 & family.bit() != 0
    }

    /// Whether the set has no families.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// How many families are in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The families in the set, in macro order.
    pub fn iter(self) -> impl Iterator<Item = ArchivalFamily> {
        ArchivalFamily::ALL
            .into_iter()
            .filter(move |f| self.contains(*f))
    }

    /// The set whose bits these are, if every set bit names a family.
    pub(crate) const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !VALID_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
}

impl ArchivalFamily {
    /// This family's bit in a [`FamilySet`].
    const fn bit(self) -> u32 {
        // A fieldless enum's discriminant is its position in the macro.
        1_u32 << (self as u32)
    }
}

impl core::fmt::Debug for FamilySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// Comma-joined table names in macro order; empty set renders empty.
impl core::fmt::Display for FamilySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for family in self.iter() {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            f.write_str(family.table())?;
        }
        Ok(())
    }
}

impl Canonical for FamilySet {
    const NAME: &'static str = "family_set";
    const FIXED_WIDTH: Option<usize> = Some(4);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let bits = u32::from_le_bytes(exact::<4>(Self::NAME, bytes)?);
        Self::from_bits(bits).ok_or(CodecError::Invalid {
            codec: Self::NAME,
            reason: "a set bit names no archival family",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_follow_macro_order_exactly() {
        for (i, family) in ArchivalFamily::ALL.into_iter().enumerate() {
            assert_eq!(family.bit(), 1 << i, "{family:?}");
            let one = FamilySet::of(&[family]);
            assert_eq!(one.len(), 1);
            assert!(one.contains(family));
            assert_eq!(one.iter().collect::<Vec<_>>(), [family]);
        }
        assert_eq!(FamilySet::ALL.len(), ArchivalFamily::ALL.len());
        assert_eq!(
            FamilySet::ALL.iter().collect::<Vec<_>>(),
            ArchivalFamily::ALL
        );
    }

    #[test]
    fn duplicates_collapse_and_union_is_or() {
        let a = FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::Bond]);
        assert_eq!(a.len(), 1);
        let b = FamilySet::of(&[ArchivalFamily::SlashLog]);
        let u = a.union(b);
        assert_eq!(
            u,
            FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog])
        );
        assert_eq!(u.union(a), u, "union with a subset is identity");
        assert!(FamilySet::EMPTY.is_empty() && !u.is_empty());
        assert_eq!(FamilySet::default(), FamilySet::EMPTY);
    }

    #[test]
    fn encodes_as_four_le_bytes_and_refuses_unknown_bits() {
        let set = FamilySet::of(&[ArchivalFamily::ALL[0], ArchivalFamily::ALL[9]]);
        assert_eq!(set.encode(), [0b0000_0001, 0b0000_0010, 0, 0]);
        assert_eq!(FamilySet::decode(&set.encode()), Ok(set));
        assert_eq!(FamilySet::decode(&[0; 4]), Ok(FamilySet::EMPTY));
        // Bit 31 names no family (17 families at this pin). A lenient
        // decode would silently drop it; the cell would then read as
        // "fewer families stubbed" than the writer recorded.
        assert!(matches!(
            FamilySet::decode(&[0, 0, 0, 0x80]),
            Err(CodecError::Invalid {
                codec: "family_set",
                ..
            })
        ));
        assert!(matches!(
            FamilySet::decode(&[0; 3]),
            Err(CodecError::Length {
                codec: "family_set",
                expected: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn display_is_table_names_in_macro_order() {
        let set = FamilySet::of(&[ArchivalFamily::SlashLog, ArchivalFamily::Bond]);
        assert_eq!(set.to_string(), "archival_bond,archival_slash_log");
        assert_eq!(FamilySet::EMPTY.to_string(), "");
        assert_eq!(format!("{set:?}"), "{Bond, SlashLog}");
    }
}

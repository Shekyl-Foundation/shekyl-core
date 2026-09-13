// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Multimap values ordered by a little-endian `u64` prefix.
//!
//! `output_amounts` stores 96-byte `outkey` / 64-byte `pre_rct_outkey`
//! duplicates whose first eight bytes are the `amount_index`, and sorts them
//! with `compare_uint64` (`db_lmdb.cpp:228`), which compares **only** that
//! prefix. redb's `&[u8]` would order the whole value byte-lexicographically,
//! which on a little-endian host is not the amount-index sequence.
//!
//! # The one deliberate difference from the C++
//!
//! `compare_uint64` returns `Equal` for two values sharing a prefix — it never
//! looks past byte 8. redb requires a **total order** on multimap values, and
//! two distinct values comparing equal would be treated as one. This type
//! therefore tie-breaks on the remaining bytes.
//!
//! That cannot change behaviour on reachable data: `amount_index` is unique
//! per amount, so no two live duplicates share a prefix. The tie-break orders
//! a case LMDB would have collapsed, rather than reordering one it ranks.
//!
//! # Endianness
//!
//! The C++ `compare_uint64` memcpy's eight bytes into a host `uint64_t`.
//! This type is **little-endian-explicit**, matching the reading every
//! machine the project supports produces, and does not inherit the host's
//! byte order.

use std::cmp::Ordering;

use redb::{Key, TypeName, Value};

/// Byte values ordered by a **little-endian `u64` prefix**, then by the
/// remaining bytes.
#[derive(Debug)]
pub struct U64PrefixBytes;

impl Value for U64PrefixBytes {
    type SelfType<'a> = &'a [u8];
    type AsBytes<'a> = &'a [u8];

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> &'a [u8]
    where
        Self: 'a,
    {
        data
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a [u8]
    where
        Self: 'b,
    {
        value
    }

    fn type_name() -> TypeName {
        TypeName::new("shekyl::U64PrefixBytes")
    }
}

impl Key for U64PrefixBytes {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        match (data1.first_chunk::<8>(), data2.first_chunk::<8>()) {
            (Some(a), Some(b)) => u64::from_le_bytes(*a)
                .cmp(&u64::from_le_bytes(*b))
                .then_with(|| data1.cmp(data2)),
            _ => data1.cmp(data2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `U64PrefixBytes` ordering is the little-endian u64 prefix, not
    /// whole-value bytes — and the two differ on little-endian, which is
    /// the point.
    #[test]
    fn u64_prefix_beats_byte_order_and_stays_total() {
        // Little-endian prefixes 1 and 256. Numerically 1 < 256. Byte-lex
        // compares byte 0 first, where 1 > 0, so it ranks them the OTHER way
        // — which is the divergence this type exists to remove.
        let mut lo = [0u8; 16];
        lo[0] = 1; // LE prefix = 1
        let mut hi = [0u8; 16];
        hi[1] = 1; // LE prefix = 256
        assert_eq!(U64PrefixBytes::compare(&lo, &hi), Ordering::Less);
        assert_eq!(
            lo.as_slice().cmp(hi.as_slice()),
            Ordering::Greater,
            "byte order must disagree here, or the test proves nothing"
        );
        let mut a = [0u8; 16];
        a[7] = 1; // prefix = 2^56
        let mut b = [0u8; 16];
        b[0] = 2; // prefix = 2
        assert_eq!(U64PrefixBytes::compare(&a, &b), Ordering::Greater);
        assert_eq!(
            a.as_slice().cmp(b.as_slice()),
            Ordering::Less,
            "byte order disagrees"
        );

        // Equal prefixes still order totally, so redb never sees two distinct
        // multimap values compare Equal (which LMDB's compare_uint64 would).
        let mut p = [7u8; 16];
        let mut q = [7u8; 16];
        p[15] = 1;
        q[15] = 2;
        assert_eq!(U64PrefixBytes::compare(&p, &q), Ordering::Less);
        assert_ne!(U64PrefixBytes::compare(&p, &q), Ordering::Equal);
    }
}

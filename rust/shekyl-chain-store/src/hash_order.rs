// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The LMDB hash ordering, carried into redb.
//!
//! Seven LMDB tables order 32-byte hashes with `BlockchainLMDB::compare_hash32`
//! (`src/blockchain_db/lmdb/db_lmdb.cpp:236`), and **it is not the ordering a
//! reimplementation reaches for**. The loop is
//!
//! ```text
//! for (int n = 7; n >= 0; n--) { if (va[n] == vb[n]) continue; return va[n] < vb[n] ? -1 : 1; }
//! ```
//!
//! — eight native `uint32_t` loads compared from word **7 down to 0**. On a
//! little-endian host that makes byte 31 the most significant and byte 0 the
//! least: the 32 bytes are ordered as a **little-endian 256-bit integer**,
//! equivalently **ascending lexicographic over the reversed byte string**.
//!
//! # Why this type exists rather than a `[u8; 32]`
//!
//! redb's `[u8; N]` compares with `memcmp` — byte 0 first. That is the exact
//! opposite end of the hash, so a table keyed on a bare array range-scans a
//! different set than its LMDB twin. The failure is invisible: point lookups
//! all agree, only ordered reads diverge.
//!
//! `docs/LMDB_SCHEMA.md` described the C++ as "memory order … lexicographic",
//! which is byte 0 first — i.e. the doc agreed with redb's default and both
//! disagreed with the code. Corrected in the same PR that added this type.
//!
//! # The mistake this type is shaped to prevent
//!
//! `Reverse<[u8; 32]>` is **wrong**, and wrong in a way that survives testing.
//! Descending-lexicographic flips the *result* of comparing byte 0 first; the
//! real ordering flips *which byte is compared* first. Measured over 4 000
//! random pairs against a transcription of the C++: reversed-byte agrees
//! 4000/4000, descending-lexicographic disagrees **2010/4000**. A wrong
//! implementation is wrong on about half of all pairs — not cleanly inverted,
//! so a smoke test passes. [`LmdbHashKey::compare`] is pinned against that
//! transcription in this module's tests.
//!
//! # Endianness (`DAEMON_REDB_STORE.md` §6.4, record-and-specify)
//!
//! The C++ ordering is host-dependent **by construction**: on a big-endian
//! host the same source compares bytes 28,29,30,31,24,…,0,1,2,3 — a
//! word-shuffled hybrid that is neither lexicographic nor reversed. There is
//! no host on which that function is lexicographic. This type is
//! **endianness-explicit**: it defines the little-endian reading, which is the
//! one every machine the project supports produces, and does not inherit the
//! host's byte order.

use std::cmp::Ordering;

use redb::{Key, TypeName, Value};

/// A 32-byte hash keyed in **LMDB `compare_hash32` order** — ascending
/// lexicographic over the reversed byte string (byte 31 most significant).
///
/// Stored bytes are the hash in its natural order; only the *ordering*
/// differs, so the on-disk value is directly comparable with LMDB's and no
/// re-encoding happens on read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LmdbHashKey(pub [u8; 32]);

impl LmdbHashKey {
    /// The ordering `compare_hash32` implements, over raw bytes.
    ///
    /// Byte 31 is most significant; ties walk down to byte 0. Kept separate
    /// from the `Key` impl so tests can exercise it directly against a
    /// transcription of the C++.
    #[must_use]
    pub fn order(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
        a.iter().rev().cmp(b.iter().rev())
    }
}

impl Value for LmdbHashKey {
    type SelfType<'a> = LmdbHashKey;
    type AsBytes<'a> = [u8; 32];

    fn fixed_width() -> Option<usize> {
        Some(32)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> LmdbHashKey
    where
        Self: 'a,
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(data);
        LmdbHashKey(out)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> [u8; 32]
    where
        Self: 'b,
    {
        value.0
    }

    fn type_name() -> TypeName {
        // Distinct from `[u8;32]` on purpose: redb keys the on-disk type by
        // this name, so a table that silently swapped to the default ordering
        // would be a different type rather than a quiet behaviour change.
        TypeName::new("shekyl::LmdbHashKey")
    }
}

impl Key for LmdbHashKey {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        data1.iter().rev().cmp(data2.iter().rev())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A direct transcription of `BlockchainLMDB::compare_hash32` — eight
    /// native `uint32_t` loads, words 7 down to 0. The oracle this type is
    /// checked against; it is deliberately written from the C++ shape rather
    /// than from `LmdbHashKey`'s, so agreement is evidence rather than a
    /// tautology.
    fn cpp_compare_hash32(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
        for n in (0..8).rev() {
            let va = u32::from_le_bytes(a[n * 4..n * 4 + 4].try_into().unwrap());
            let vb = u32::from_le_bytes(b[n * 4..n * 4 + 4].try_into().unwrap());
            if va != vb {
                return va.cmp(&vb);
            }
        }
        Ordering::Equal
    }

    /// Deterministic pseudo-random pairs — no dev-dependency on `rand` for a
    /// test whose whole job is reproducibility.
    fn pairs(n: usize) -> Vec<([u8; 32], [u8; 32])> {
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            let mut out = [0u8; 32];
            for b in &mut out {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                // Explicit byte extraction: a `as u8` cast here is a
                // truncation clippy is right to refuse.
                *b = s.to_le_bytes()[3];
            }
            out
        };
        (0..n).map(|_| (next(), next())).collect()
    }

    #[test]
    fn matches_the_cpp_comparator_on_every_pair() {
        for (a, b) in pairs(4000) {
            assert_eq!(
                LmdbHashKey::compare(&a, &b),
                cpp_compare_hash32(&a, &b),
                "disagreed on {a:02x?} vs {b:02x?}"
            );
        }
    }

    /// The negative control. Without this the test above could pass against a
    /// comparator that is merely *some* total order; this pins that the
    /// ordering is genuinely different from the two plausible wrong ones, so
    /// a regression to either is caught.
    #[test]
    fn the_two_plausible_wrong_orderings_disagree_a_lot() {
        let ps = pairs(4000);
        let lexicographic = ps
            .iter()
            .filter(|(a, b)| LmdbHashKey::compare(a, b) != a.cmp(b))
            .count();
        let descending = ps
            .iter()
            .filter(|(a, b)| LmdbHashKey::compare(a, b) != b.cmp(a))
            .count();
        // redb's default `[u8; 32]` ordering, and `Reverse<[u8; 32]>`.
        assert!(
            lexicographic > 1500,
            "byte-lexicographic should differ on ~half; got {lexicographic}/4000"
        );
        assert!(
            descending > 1500,
            "descending-lex should differ on ~half; got {descending}/4000"
        );
    }

    #[test]
    fn byte_31_outranks_byte_0() {
        let mut lsb_end = [0u8; 32];
        lsb_end[0] = 1;
        let mut msb_end = [0u8; 32];
        msb_end[31] = 1;
        // The documented worked example: LMDB says A < B, memcmp says A > B.
        assert_eq!(LmdbHashKey::compare(&lsb_end, &msb_end), Ordering::Less);
        assert_eq!(lsb_end.cmp(&msb_end), Ordering::Greater);
    }

    #[test]
    fn round_trips_through_the_value_impl() {
        let h = pairs(1)[0].0;
        let encoded = <LmdbHashKey as Value>::as_bytes(&LmdbHashKey(h));
        assert_eq!(encoded, h, "as_bytes must not re-order the stored form");
        assert_eq!(<LmdbHashKey as Value>::from_bytes(&encoded), LmdbHashKey(h));
    }
}

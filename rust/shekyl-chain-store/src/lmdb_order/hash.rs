// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 32-byte hashes: stored form, and the LMDB `compare_hash32` key order.
//!
//! Seven LMDB tables order 32-byte hashes with `BlockchainLMDB::compare_hash32`
//! (`src/blockchain_db/lmdb/db_lmdb.cpp:236`). The loop is
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
//! redb's `[u8; N]` compares with `memcmp` — byte 0 first. That is the
//! opposite end of the hash, so a table keyed on a bare array range-scans a
//! different set than its LMDB twin. Point lookups all agree; only ordered
//! reads diverge.
//!
//! `Reverse<[u8; 32]>` is **wrong**, and wrong in a way that survives testing.
//! Descending-lexicographic flips the *result* of comparing byte 0 first; the
//! real ordering flips *which byte is compared* first. Measured over 4 000
//! random pairs against a transcription of the C++: reversed-byte agrees
//! 4000/4000, descending-lexicographic disagrees **2010/4000**.
//!
//! # Endianness (`DAEMON_REDB_STORE.md` §6.4, record-and-specify)
//!
//! The C++ ordering is host-dependent **by construction**: on a big-endian
//! host the same source compares bytes 28,29,30,31,24,…,0,1,2,3 — a
//! word-shuffled hybrid that is neither lexicographic nor reversed. There is
//! no host on which that function is lexicographic. [`LmdbHashKey`] is
//! **endianness-explicit**: it defines the little-endian reading, which is the
//! one every machine the project supports produces, and does not inherit the
//! host's byte order.

use std::cmp::Ordering;

use redb::{Key, TypeName, Value};

/// A 32-byte hash in its natural stored form.
///
/// Implements [`Value`] so it can sit in a table as a *value* (e.g.
/// `txs_prunable_hash`). Does **not** implement [`Key`]: byte-lexicographic
/// order on a hash is the order [`LmdbHashKey`] exists to reject, and making
/// that unrepresentable as a table key is the point. Convert with
/// [`LmdbHashKey::from`] when the hash is the key.
///
/// `Ord` is byte-lexicographic (memcmp). That is the stored-byte order, not
/// LMDB's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// Wrap raw bytes. An *edge* constructor.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Unwrap to the raw bytes. An *edge* accessor.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Hash32> for [u8; 32] {
    fn from(hash: Hash32) -> Self {
        hash.0
    }
}

impl AsRef<[u8; 32]> for Hash32 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Value for Hash32 {
    type SelfType<'a> = Hash32;
    type AsBytes<'a> = [u8; 32];

    fn fixed_width() -> Option<usize> {
        Some(32)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Hash32
    where
        Self: 'a,
    {
        Hash32(
            data.try_into()
                .expect("Hash32 is 32 bytes (redb fixed_width)"),
        )
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> [u8; 32]
    where
        Self: 'b,
    {
        value.0
    }

    fn type_name() -> TypeName {
        TypeName::new("shekyl::Hash32")
    }
}

/// A [`Hash32`] keyed in **LMDB `compare_hash32` order** — ascending
/// lexicographic over the reversed byte string (byte 31 most significant).
///
/// Stored bytes are the hash in its natural order; only the *ordering*
/// differs, so the on-disk value is directly comparable with LMDB's and no
/// re-encoding happens on read or write.
///
/// `Ord` / `PartialOrd` are implemented, not derived. A derive would order
/// by the inner bytes — byte 0 first — which is the ordering this type
/// exists to reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct LmdbHashKey(Hash32);

impl LmdbHashKey {
    /// Wrap a stored hash as a `compare_hash32`-ordered key.
    #[must_use]
    pub const fn from_hash(hash: Hash32) -> Self {
        Self(hash)
    }

    /// Wrap raw bytes as a `compare_hash32`-ordered key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash32::from_bytes(bytes))
    }

    /// The stored hash, without the key order.
    #[must_use]
    pub const fn to_hash(self) -> Hash32 {
        self.0
    }

    /// Unwrap to the raw bytes. An *edge* accessor.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// The ordering `compare_hash32` implements, over raw bytes.
    ///
    /// Byte 31 is most significant; ties walk down to byte 0. Shared by
    /// [`Ord`] and [`Key::compare`].
    #[must_use]
    pub fn order(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
        a.iter().rev().cmp(b.iter().rev())
    }
}

impl From<Hash32> for LmdbHashKey {
    fn from(hash: Hash32) -> Self {
        Self::from_hash(hash)
    }
}

impl From<LmdbHashKey> for Hash32 {
    fn from(key: LmdbHashKey) -> Self {
        key.0
    }
}

impl From<[u8; 32]> for LmdbHashKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<LmdbHashKey> for [u8; 32] {
    fn from(key: LmdbHashKey) -> Self {
        key.to_bytes()
    }
}

impl AsRef<[u8; 32]> for LmdbHashKey {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for LmdbHashKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Ord for LmdbHashKey {
    fn cmp(&self, other: &Self) -> Ordering {
        Self::order(self.as_bytes(), other.as_bytes())
    }
}

impl PartialOrd for LmdbHashKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
        LmdbHashKey(Hash32::from_bytes(
            data.try_into()
                .expect("LmdbHashKey is 32 bytes (redb fixed_width)"),
        ))
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> [u8; 32]
    where
        Self: 'b,
    {
        value.to_bytes()
    }

    fn type_name() -> TypeName {
        // Distinct from `Hash32` and from `[u8;32]` on purpose: redb keys
        // the on-disk type by this name, so a table that silently swapped
        // to the default ordering would be a different type rather than a
        // quiet behaviour change.
        TypeName::new("shekyl::LmdbHashKey")
    }
}

impl Key for LmdbHashKey {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        let a: &[u8; 32] = data1
            .try_into()
            .expect("LmdbHashKey is 32 bytes (redb fixed_width)");
        let b: &[u8; 32] = data2
            .try_into()
            .expect("LmdbHashKey is 32 bytes (redb fixed_width)");
        Self::order(a, b)
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
            let want = cpp_compare_hash32(&a, &b);
            assert_eq!(
                LmdbHashKey::order(&a, &b),
                want,
                "order disagreed on {a:02x?} vs {b:02x?}"
            );
            assert_eq!(
                LmdbHashKey::compare(&a, &b),
                want,
                "Key::compare disagreed on {a:02x?} vs {b:02x?}"
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
            .filter(|(a, b)| LmdbHashKey::order(a, b) != a.cmp(b))
            .count();
        let descending = ps
            .iter()
            .filter(|(a, b)| LmdbHashKey::order(a, b) != b.cmp(a))
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
        assert_eq!(LmdbHashKey::order(&lsb_end, &msb_end), Ordering::Less);
        assert_eq!(lsb_end.cmp(&msb_end), Ordering::Greater);
        // Hash32's Ord is the stored-byte (memcmp) order; LmdbHashKey's is not.
        assert_eq!(
            Hash32::from_bytes(lsb_end).cmp(&Hash32::from_bytes(msb_end)),
            Ordering::Greater
        );
        assert_eq!(
            LmdbHashKey::from_bytes(lsb_end).cmp(&LmdbHashKey::from_bytes(msb_end)),
            Ordering::Less
        );
    }

    #[test]
    fn round_trips_through_the_value_impls_without_reordering() {
        let h = pairs(1)[0].0;
        let stored = Hash32::from_bytes(h);
        let encoded = <Hash32 as Value>::as_bytes(&stored);
        assert_eq!(encoded, h, "as_bytes must not re-order the stored form");
        assert_eq!(<Hash32 as Value>::from_bytes(&encoded), stored);

        let key = LmdbHashKey::from_hash(stored);
        let key_encoded = <LmdbHashKey as Value>::as_bytes(&key);
        assert_eq!(key_encoded, h, "key as_bytes is the same stored form");
        assert_eq!(<LmdbHashKey as Value>::from_bytes(&key_encoded), key);
        assert_eq!(Hash32::from(key).to_bytes(), h);
    }
}

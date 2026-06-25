// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PoW-target predicate: does a hash satisfy a difficulty?
//!
//! Direct port of the inherited C++ `check_hash` family
//! (`src/cryptonote_basic/difficulty.cpp`), collapsed into the single
//! mathematical predicate the contract always was. The C++ split into
//! `check_hash_64` / `check_hash_128` existed purely as a speed
//! optimization for the common case `difficulty <= u64::MAX`; both
//! paths compute the identical boolean, proven over the boundary +
//! fuzz corpus committed in `tests/check_hash_vectors.rs`. There is
//! exactly one path here.
//!
//! # Contract
//!
//! The 32-byte `hash` is interpreted as a 256-bit **little-endian**
//! integer (`u64::from_le_bytes` per 8-byte word — the portable
//! equivalent of the C++ `swap64le((const uint64_t*)&hash)[i]` on the
//! daemon's little-endian targets). The hash passes iff
//!
//! ```text
//! hash * difficulty < 2^256
//! ```
//!
//! i.e. the (at most 384-bit) product fits without overflow into the
//! least-significant 256 bits. `difficulty == 0` always passes (the
//! product is `0 < 2^256`); this matches the C++ `check_hash_64`
//! result for `difficulty == 0` and is the documented genesis/escape
//! behaviour, not an error.
//!
//! # Arithmetic
//!
//! No bigint dependency (crate is `#![no_std]`, `#![deny(unsafe_code)]`,
//! zero external deps). The 256-bit hash is four `u64` limbs; the
//! product with a 128-bit difficulty is at most `256 + 128 = 384` bits
//! = six `u64` limbs. The schoolbook limb multiply uses `u128`
//! intermediates (each `limb * difficulty` is at most
//! `(2^64-1) * (2^128-1) < 2^192`, which does not fit `u128`, so the
//! difficulty itself is split into two `u64` halves and accumulated).
//! The predicate is: the two most-significant limbs (`words[4]`,
//! `words[5]`, i.e. bits 256..384) are both zero.

/// Low 64 bits of `v`, as a lossless limb extraction (no truncating
/// `as` cast — the crate avoids `as` narrowing; see `lwma1.rs`).
#[inline]
fn low64(v: u128) -> u64 {
    let bytes = v.to_le_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// High 64 bits of `v` (bits 64..128), as a lossless limb extraction.
#[inline]
fn high64(v: u128) -> u64 {
    let bytes = v.to_le_bytes();
    u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ])
}

/// Returns `true` iff `hash` (read little-endian) satisfies `difficulty`.
///
/// Equivalent to the inherited `cryptonote::check_hash`: passes iff
/// `(hash as 256-bit LE integer) * difficulty < 2^256`. Pure,
/// panic-free, and total over every `(hash, difficulty)`. A
/// `difficulty` of `0` always passes (see module docs).
#[must_use]
pub fn check_hash(hash: &[u8; 32], difficulty: u128) -> bool {
    // Hash as four little-endian u64 limbs (limb 0 = least significant).
    let h = [
        u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]),
        u64::from_le_bytes([
            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
        ]),
        u64::from_le_bytes([
            hash[16], hash[17], hash[18], hash[19], hash[20], hash[21], hash[22], hash[23],
        ]),
        u64::from_le_bytes([
            hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31],
        ]),
    ];

    // Split the 128-bit difficulty into two 64-bit halves so each
    // partial product `u64 * u64` fits in a `u128` with room for carries.
    // `low64` / `high64` are lossless limb extractions written without
    // truncating casts (the crate avoids `as` narrowing; see lwma1.rs).
    let d_lo = low64(difficulty);
    let d_hi = high64(difficulty);

    // Schoolbook multiply: product = h (4 limbs) * d (2 limbs) -> 6 limbs.
    // words[k] accumulates the k-th output limb. The high limbs
    // words[4] and words[5] hold bits 256..384; the predicate is that
    // both are zero (no overflow past 2^256).
    let mut words = [0u64; 6];

    for (i, &h_limb) in h.iter().enumerate() {
        // Pass over difficulty's two limbs.
        let mut carry: u64 = 0;
        for (j, &d_limb) in [d_lo, d_hi].iter().enumerate() {
            let k = i + j;
            // h_limb * d_limb fits in u128; add the current word and the
            // running carry (each < 2^64), so the sum is < 2^128.
            let prod =
                u128::from(h_limb) * u128::from(d_limb) + u128::from(words[k]) + u128::from(carry);
            words[k] = low64(prod);
            carry = high64(prod);
        }
        // Propagate the final carry into the next-higher limb (i + 2).
        // i ranges 0..=3 and j ends at 1, so i + 2 <= 5 — always in bounds.
        words[i + 2] = words[i + 2].wrapping_add(carry);
    }

    // Pass iff bits 256..384 are zero (product < 2^256).
    words[4] == 0 && words[5] == 0
}

#[cfg(test)]
mod tests {
    use super::check_hash;

    fn h_from_le_words(w: [u64; 4]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in w.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn difficulty_zero_always_passes() {
        assert!(check_hash(&[0u8; 32], 0));
        assert!(check_hash(&[0xffu8; 32], 0));
        assert!(check_hash(&h_from_le_words([1, 2, 3, 4]), 0));
    }

    #[test]
    fn all_zero_hash_passes_any_difficulty() {
        assert!(check_hash(&[0u8; 32], 1));
        assert!(check_hash(&[0u8; 32], u128::MAX));
    }

    #[test]
    fn hash_one_difficulty_one_passes() {
        // 1 * 1 = 1 < 2^256.
        assert!(check_hash(&h_from_le_words([1, 0, 0, 0]), 1));
    }

    #[test]
    fn all_ones_hash_overflows_for_difficulty_two() {
        // (2^256 - 1) * 2 = 2^257 - 2 >= 2^256, must fail.
        assert!(!check_hash(&[0xffu8; 32], 2));
        // ... but passes for difficulty 1 (2^256 - 1 < 2^256).
        assert!(check_hash(&[0xffu8; 32], 1));
    }

    #[test]
    fn top_limb_set_fails_large_difficulty() {
        // hash = 2^192 (top limb = 1). With difficulty 2^64 the product
        // is 2^256, which is NOT < 2^256 -> fail.
        let hash = h_from_le_words([0, 0, 0, 1]);
        assert!(!check_hash(&hash, 1u128 << 64));
        // difficulty (2^64 - 1): product = 2^192 * (2^64 - 1) < 2^256 -> pass.
        assert!(check_hash(&hash, (1u128 << 64) - 1));
    }

    #[test]
    fn threshold_exact_boundary() {
        // hash = 2^255 (top bit of the 256-bit LE integer set),
        // difficulty 2 -> product = 2^256 -> fail.
        let mut hash = [0u8; 32];
        hash[31] = 0x80; // top bit of the 256-bit LE integer
        assert!(!check_hash(&hash, 2));
        // difficulty 1 -> 2^255 < 2^256 -> pass.
        assert!(check_hash(&hash, 1));
    }
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Differential gate for the ported PoW predicate
//! [`shekyl_difficulty::check_hash`].
//!
//! Consensus equivalence is *proven*, not assumed. This file pins the
//! Rust port against two independent oracles:
//!
//! 1. **`corpus`** — a locked vector set captured from the inherited
//!    C++ `cryptonote::check_hash` (`src/cryptonote_basic/difficulty.cpp`)
//!    via the differential oracle generator. The generator additionally
//!    verified that the C++ `check_hash_64` and `check_hash_128` paths
//!    agree on every `difficulty <= u64::MAX` input across 200k random
//!    samples plus the boundary corpus, so the unified Rust path is a
//!    faithful collapse of both. The corpus deliberately covers the
//!    `_64`/`_128` seam: difficulty in `{0, 1, u64::MAX-1, u64::MAX,
//!    u64::MAX+1, u128::MAX}`, threshold-exact / off-by-one hashes, and
//!    all-zero / all-ones / top-word-only hashes.
//!
//! 2. **`golden_formula`** / **`independent_reference`** — `proptest`
//!    fuzz against the closed-form predicate from the inherited
//!    `tests/hash-target.cpp` (uniform-byte hashes:
//!    `pass == (b == 0 || difficulty <= 255 / b)`) and against a
//!    256-bit reference multiply written independently of the SUT's
//!    limb code (it widens through `u128` differently and compares
//!    against `2^256`).

#[path = "check_hash_data/corpus.rs"]
mod check_hash_corpus;

use check_hash_corpus::CHECK_HASH_VECTORS;
use shekyl_difficulty::check_hash;

/// The locked C++-captured corpus must match bit-for-bit.
#[test]
fn matches_cpp_oracle_corpus() {
    for (idx, (hash, difficulty, expected)) in CHECK_HASH_VECTORS.iter().enumerate() {
        let got = check_hash(hash, *difficulty);
        assert_eq!(
            got, *expected,
            "corpus vector #{idx}: hash={hash:02x?} difficulty={difficulty} \
             expected={expected} got={got}",
        );
    }
}

/// Sanity: the corpus actually exercises both accept and reject and
/// straddles the `u64::MAX` difficulty seam.
#[test]
fn corpus_is_nontrivial() {
    let passes = CHECK_HASH_VECTORS.iter().filter(|(_, _, p)| *p).count();
    let fails = CHECK_HASH_VECTORS.len() - passes;
    assert!(passes > 0 && fails > 0, "corpus must contain both outcomes");
    let above_u64 = CHECK_HASH_VECTORS
        .iter()
        .filter(|(_, d, _)| *d > u128::from(u64::MAX))
        .count();
    let at_or_below = CHECK_HASH_VECTORS.len() - above_u64;
    assert!(
        above_u64 > 0 && at_or_below > 0,
        "corpus must straddle the u64::MAX difficulty seam (_64 vs _128 paths)",
    );
}

/// Independent 256-bit reference: read the hash as a little-endian
/// integer, multiply by `difficulty`, and test `< 2^256`. Implemented
/// with a different limb schedule than the SUT (accumulate per
/// difficulty-half across the whole hash, then add) so a shared bug is
/// unlikely to cancel.
fn reference_check_hash(hash: &[u8; 32], difficulty: u128) -> bool {
    // 6 output limbs (384 bits). Build hash limbs.
    let mut h = [0u64; 4];
    for (i, limb) in h.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(bytes);
    }
    // Lossless 64-bit limb extraction without truncating `as` casts.
    let lo64 = |v: u128| -> u64 {
        let b = v.to_le_bytes();
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    };
    let hi64 = |v: u128| -> u64 {
        let b = v.to_le_bytes();
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])
    };
    let d = [lo64(difficulty), hi64(difficulty)];

    let mut words = [0u64; 6];
    // Iterate difficulty-major (the SUT iterates hash-major).
    for (j, &dj) in d.iter().enumerate() {
        let mut carry = 0u128;
        for (i, &hi) in h.iter().enumerate() {
            let k = i + j;
            let acc = u128::from(hi) * u128::from(dj) + u128::from(words[k]) + carry;
            words[k] = lo64(acc);
            carry = u128::from(hi64(acc));
        }
        // The final carry is output limb 4 + j (j in {0,1} -> index 4 or 5),
        // and it is zero at this point on both passes: j=0 writes words[4]
        // before the j=1 inner loop reaches it, and j=1 writes words[5],
        // which nothing else touches. So the carry lands exactly — a plain
        // assignment, a distinct limb schedule from the SUT, same 384-bit
        // product.
        words[4 + j] = lo64(carry);
    }
    words[4] == 0 && words[5] == 0
}

#[test]
fn agrees_with_independent_reference_on_corpus() {
    for (hash, difficulty, _) in &CHECK_HASH_VECTORS {
        assert_eq!(
            check_hash(hash, *difficulty),
            reference_check_hash(hash, *difficulty),
            "reference disagreement: hash={hash:02x?} difficulty={difficulty}",
        );
    }
}

proptest::proptest! {
    /// Fuzz against the independent 256-bit reference over arbitrary
    /// hashes and difficulties (covers both sides of the seam).
    #[test]
    fn fuzz_matches_independent_reference(
        hash in proptest::array::uniform32(proptest::num::u8::ANY),
        difficulty in proptest::num::u128::ANY,
    ) {
        proptest::prop_assert_eq!(
            check_hash(&hash, difficulty),
            reference_check_hash(&hash, difficulty)
        );
    }

    /// Fuzz against the inherited `hash-target.cpp` golden formula:
    /// for a uniform-byte hash (every byte == `b`), the predicate is
    /// `b == 0 || difficulty <= 255 / b`. The uniform-byte hash equals
    /// `b * (2^256 - 1) / 255`, so `hash * difficulty < 2^256` reduces
    /// exactly to that closed form.
    #[test]
    fn fuzz_matches_golden_uniform_byte_formula(
        b in proptest::num::u8::ANY,
        // hash-target.cpp drives difficulty >= 1; difficulty 0 always
        // passes and is covered by the corpus and the unit tests.
        difficulty in 1u128..=u128::MAX,
    ) {
        let hash = [b; 32];
        // pass iff b == 0 or difficulty <= 255 / b (hash-target.cpp).
        let golden = if b == 0 {
            true
        } else {
            difficulty <= u128::from(255u8 / b)
        };
        proptest::prop_assert_eq!(check_hash(&hash, difficulty), golden);
    }
}

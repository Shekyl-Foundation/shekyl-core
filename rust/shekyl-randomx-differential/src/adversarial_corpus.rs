// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Adversarial seedhash + u128-edge-case data corpus
//! (§5.1.6 + R1-D5 + R1-D6 + §3.18 R6-D2).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §3 R1-D5 close, the
//! adversarial corpus complements the §5.1.5 random corpus by
//! exercising rare-path inputs that random sampling almost never
//! hits: high-frequency rare opcode classes (CFROUND, FDIV_M, Cache-
//! miss, CBRANCH), combined-heavy seedhashes, and u128 edge-case
//! data (div-by-zero, signed-div overflow, shift-by-width, u128
//! truncation high-bit). Per R1-D5 the seedhashes are *grinded*
//! (each chosen by frequency-counting opcode classes in the AES4R-
//! of-scratchpad-derived program for that seedhash) and committed as
//! hex bytes; per R1-D6 the u128 edge-case data values are
//! hand-derived from spec analysis and committed as hex bytes.
//!
//! ## C5a scope (§3.18 R6-D2)
//!
//! This module is the **scaffolded-empty** form per §3.18 R6-D2's
//! C5a/C5b split:
//!
//! - C5a (this commit) ships the nine per-class arrays with the
//!   structurally-correct shape (`&[ [u8; 32] ]` for seedhash
//!   classes; `&[ Vec<u8> ]` materialized at module-load time for
//!   data classes) but **empty**. T10
//!   (`adversarial_corpus_hash_pin`) asserts SHA-256 of the
//!   empty-scaffold contents at C5a.
//! - C5b refills each array against grinded bytes (R1-D5 grinding
//!   tool + R1-D6 hand-derivation) and refreshes T10's SHA-256 pin.
//!
//! The class names below are pinned at C5a to anchor the §5.7
//! surface contract; C5b adds the grinding-tool surface via a
//! plan-doc amendment per §3.18 R6-D2 + R5-D2's substrate-amendment-
//! then-code precedent.
//!
//! ## Class taxonomy
//!
//! Five seedhash classes (R1-D5 grinding categories) and four data
//! classes (R1-D6 u128 edge-case derivations):
//!
//! | Class | Anchor | Selection criterion |
//! |---|---|---|
//! | `CFROUND_SEEDHASHES` | R1-D5 | ≥40% of program instructions decode to CFROUND |
//! | `FDIV_M_SEEDHASHES` | R1-D5 | ≥40% of program instructions decode to FDIV_M |
//! | `CACHE_MISS_SEEDHASHES` | R1-D5 | ≥40% of memory-touching instructions miss the scratchpad |
//! | `CBRANCH_SEEDHASHES` | R1-D5 | ≥40% of program instructions decode to CBRANCH |
//! | `COMBINED_HEAVY_SEEDHASHES` | R1-D5 | ≥60% of program instructions decode to ≥2 of CFROUND/FDIV_M/CBRANCH |
//! | `DIV_BY_ZERO_DATA` | R1-D6 | Data that forces zero u128 divisor in IADD_M / ISUB_M path |
//! | `SIGNED_DIV_OVERFLOW_DATA` | R1-D6 | Data that forces `i128::MIN / -1` signed-overflow path |
//! | `SHIFT_BY_WIDTH_DATA` | R1-D6 | Data that forces shift-by-≥-bit-width truncation path |
//! | `U128_TRUNC_HIGH_DATA` | R1-D6 | Data that forces high-bit truncation in u128 ops |
//!
//! The class names are stable; the per-class arrays grow with
//! C5b's grinding output without changing the surface contract.

use sha2::{Digest, Sha256};
use shekyl_pow_randomx::Seedhash;

/// Grinded seedhashes targeting ≥40% CFROUND opcode density.
///
/// Per §3.18 R6-D2 C5a scope, the array is intentionally empty;
/// C5b fills it from the grinding tool's output. The class name
/// is committed at C5a so the §5.7 drift-prevention boundary
/// recognizes the surface.
pub const CFROUND_SEEDHASHES: &[[u8; 32]] = &[];

/// Grinded seedhashes targeting ≥40% FDIV_M opcode density.
pub const FDIV_M_SEEDHASHES: &[[u8; 32]] = &[];

/// Grinded seedhashes targeting ≥40% scratchpad-cache-miss
/// behaviour on memory-touching instructions.
pub const CACHE_MISS_SEEDHASHES: &[[u8; 32]] = &[];

/// Grinded seedhashes targeting ≥40% CBRANCH opcode density.
pub const CBRANCH_SEEDHASHES: &[[u8; 32]] = &[];

/// Grinded seedhashes targeting ≥60% combined CFROUND + FDIV_M +
/// CBRANCH opcode density.
pub const COMBINED_HEAVY_SEEDHASHES: &[[u8; 32]] = &[];

/// Hand-derived data values driving the zero-divisor path of
/// IADD_M / ISUB_M u128 arithmetic.
pub const DIV_BY_ZERO_DATA: &[&[u8]] = &[];

/// Hand-derived data values driving the `i128::MIN / -1`
/// signed-division-overflow path.
pub const SIGNED_DIV_OVERFLOW_DATA: &[&[u8]] = &[];

/// Hand-derived data values driving shift-by-≥-bit-width
/// truncation on u128 shifts.
pub const SHIFT_BY_WIDTH_DATA: &[&[u8]] = &[];

/// Hand-derived data values driving high-bit truncation on u128
/// arithmetic.
pub const U128_TRUNC_HIGH_DATA: &[&[u8]] = &[];

/// SHA-256 pin of the per-class arrays' canonical serialization,
/// per §3.18 R6-D2.
///
/// At C5a the pin asserts the SHA-256 of the empty-scaffold
/// contents; at C5b the pin **refreshes** against the grinded
/// bytes and the refresh is cited in C5b's commit message per
/// §8.1 C5b. The constant is `pub` so T10 can re-derive the
/// SHA-256 at runtime via [`compute_adversarial_corpus_hash`] and
/// assert equality.
///
/// Per R1-D5 the SHA-256 covers a canonical byte serialization of
/// the per-class contents in declaration order. See
/// [`compute_adversarial_corpus_hash`] for the serialization
/// shape.
pub const ADVERSARIAL_CORPUS_SHA256: [u8; 32] = [
    0x6d, 0xb6, 0x5f, 0xd5, 0x9f, 0xd3, 0x56, 0xf6, 0x72, 0x91, 0x40, 0x57, 0x1b, 0x5b, 0xcd, 0x6b,
    0xb3, 0xb8, 0x34, 0x92, 0xa1, 0x6e, 0x1b, 0xf0, 0xa3, 0x88, 0x44, 0x42, 0xfc, 0x3c, 0x8a, 0x0e,
];

/// Total number of seedhashes across all R1-D5 classes.
///
/// At C5a this is `0`; at C5b it equals the grinded count
/// (~25–50 per R1-D5 F3 budget). Exposed for documentation and
/// for the structural-stub T16 (canonical_outputs) sizing check.
pub const ADVERSARIAL_SEEDHASH_COUNT: usize = CFROUND_SEEDHASHES.len()
    + FDIV_M_SEEDHASHES.len()
    + CACHE_MISS_SEEDHASHES.len()
    + CBRANCH_SEEDHASHES.len()
    + COMBINED_HEAVY_SEEDHASHES.len();

/// Total number of data values across all R1-D6 classes.
///
/// At C5a this is `0`; at C5b it equals the hand-derived count.
pub const ADVERSARIAL_DATA_COUNT: usize = DIV_BY_ZERO_DATA.len()
    + SIGNED_DIV_OVERFLOW_DATA.len()
    + SHIFT_BY_WIDTH_DATA.len()
    + U128_TRUNC_HIGH_DATA.len();

/// Iterate every adversarial seedhash with its class label.
///
/// Class labels are stable (the strings are committed-named); they
/// surface in T11 failure-output diagnostics when an adversarial-
/// corpus byte-equality mismatch is reported so the reviewer can
/// classify the failure without re-deriving the class from the
/// seedhash bytes.
pub fn iter_adversarial_seedhashes() -> impl Iterator<Item = (&'static str, Seedhash)> {
    let classes: [(&'static str, &'static [[u8; 32]]); 5] = [
        ("CFROUND", CFROUND_SEEDHASHES),
        ("FDIV_M", FDIV_M_SEEDHASHES),
        ("CACHE_MISS", CACHE_MISS_SEEDHASHES),
        ("CBRANCH", CBRANCH_SEEDHASHES),
        ("COMBINED_HEAVY", COMBINED_HEAVY_SEEDHASHES),
    ];
    classes.into_iter().flat_map(|(label, slice)| {
        slice
            .iter()
            .map(move |bytes| (label, Seedhash::from_bytes(*bytes)))
    })
}

/// Iterate every adversarial data value with its class label.
pub fn iter_adversarial_data() -> impl Iterator<Item = (&'static str, &'static [u8])> {
    let classes: [(&'static str, &'static [&'static [u8]]); 4] = [
        ("DIV_BY_ZERO", DIV_BY_ZERO_DATA),
        ("SIGNED_DIV_OVERFLOW", SIGNED_DIV_OVERFLOW_DATA),
        ("SHIFT_BY_WIDTH", SHIFT_BY_WIDTH_DATA),
        ("U128_TRUNC_HIGH", U128_TRUNC_HIGH_DATA),
    ];
    classes
        .into_iter()
        .flat_map(|(label, slice)| slice.iter().map(move |bytes| (label, *bytes)))
}

/// Compute the canonical SHA-256 over the adversarial corpus
/// contents in declaration order.
///
/// Serialization shape (T10-pinned per §3.18 R6-D2):
///
/// 1. For each seedhash class (CFROUND, FDIV_M, CACHE_MISS,
///    CBRANCH, COMBINED_HEAVY), write the class's count as a
///    `u32` little-endian, then each seedhash's 32 bytes.
/// 2. For each data class (DIV_BY_ZERO, SIGNED_DIV_OVERFLOW,
///    SHIFT_BY_WIDTH, U128_TRUNC_HIGH), write the class's count
///    as a `u32` little-endian, then for each data value its
///    length as `u32` little-endian followed by its bytes.
///
/// The declaration-order traversal pins the serialization so the
/// SHA-256 is stable across rebuilds at the same committed
/// contents; reordering the class declarations or arrays
/// invalidates the pin (caught by T10).
pub fn compute_adversarial_corpus_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    let seedhash_classes: [&[[u8; 32]]; 5] = [
        CFROUND_SEEDHASHES,
        FDIV_M_SEEDHASHES,
        CACHE_MISS_SEEDHASHES,
        CBRANCH_SEEDHASHES,
        COMBINED_HEAVY_SEEDHASHES,
    ];
    for class in seedhash_classes {
        hasher.update(class_len_u32(class.len()).to_le_bytes());
        for bytes in class {
            hasher.update(bytes);
        }
    }
    let data_classes: [&[&[u8]]; 4] = [
        DIV_BY_ZERO_DATA,
        SIGNED_DIV_OVERFLOW_DATA,
        SHIFT_BY_WIDTH_DATA,
        U128_TRUNC_HIGH_DATA,
    ];
    for class in data_classes {
        hasher.update(class_len_u32(class.len()).to_le_bytes());
        for data in class {
            hasher.update(class_len_u32(data.len()).to_le_bytes());
            hasher.update(data);
        }
    }
    hasher.finalize().into()
}

/// Encode a class / data length as a `u32` for the
/// [`compute_adversarial_corpus_hash`] canonical serialization.
///
/// Each adversarial class is bounded by R1-D5 F3's budget (~50 seedhashes
/// per class; ~10 data values per class) — far below `u32::MAX`. The
/// per-data-value length is bounded by the C reference's input size
/// limit (well below 4 GiB). Using `u32::try_from` here panics loudly if
/// a future grinding-tool revision tries to feed a class exceeding
/// `u32::MAX` entries, rather than silently truncating via an `as` cast.
fn class_len_u32(len: usize) -> u32 {
    u32::try_from(len)
        .expect("adversarial-corpus class/data length must fit u32 per R1-D5 F3 + R1-D6 budget")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T10 — adversarial-corpus drift-detection SHA-256 pin
    /// (§3.18 R6-D2).
    ///
    /// Asserts that the runtime-computed SHA-256 of the committed
    /// per-class arrays equals [`ADVERSARIAL_CORPUS_SHA256`]. At
    /// C5a the pin is computed against the empty-scaffold contents;
    /// at C5b the pin refreshes against the grinded bytes and the
    /// commit message cites "T10 SHA-256 pin refresh against grinded
    /// bytes per §3.18 R6-D2."
    ///
    /// Failure mode: drift between the committed arrays and the pin
    /// — almost always either a code-review-time mistake (an array
    /// edited without refreshing the pin) or an attacker-style T-A2
    /// corpus tamper (a malicious diff that swaps adversarial bytes
    /// without refreshing the pin). Per the §4.5 T-A2 disposition,
    /// the T10 pin is the leg-3-catch-of-tamper surface.
    #[test]
    fn adversarial_corpus_hash_pin() {
        let computed = compute_adversarial_corpus_hash();
        let pin = ADVERSARIAL_CORPUS_SHA256;
        assert_eq!(
            computed, pin,
            "adversarial corpus SHA-256 drift: committed pin = {pin:?}, \
             runtime-derived = {computed:?}. Either the per-class arrays \
             changed without refreshing the pin (R1-D5/D6 + §3.18 \
             R6-D2 discipline) or the canonical serialization in \
             compute_adversarial_corpus_hash drifted from the pin's \
             generation"
        );
    }

    /// C5a structural invariant: the scaffolded module ships every
    /// class but every class is empty.
    ///
    /// Per §3.18 R6-D2 C5a scope, the per-class arrays are pinned
    /// empty at C5a and refilled at C5b. The test catches a
    /// mistaken partial-fill at C5a that would shift T10's pin
    /// computation away from the empty-scaffold reference.
    #[test]
    fn c5a_scaffold_is_empty() {
        assert_eq!(
            ADVERSARIAL_SEEDHASH_COUNT, 0,
            "C5a seedhash scaffold not empty"
        );
        assert_eq!(ADVERSARIAL_DATA_COUNT, 0, "C5a data scaffold not empty");
    }

    /// Class-label round trip via the iterator surfaces. At C5a
    /// the iterators yield zero pairs; the test verifies the
    /// iteration shape (no panics, well-formed labels) so the
    /// C5b grinding-tool consumer has a stable surface to count
    /// against.
    #[test]
    fn class_iterators_yield_well_formed_labels() {
        let seedhash_labels: Vec<&str> = iter_adversarial_seedhashes()
            .map(|(label, _)| label)
            .collect();
        let data_labels: Vec<&str> = iter_adversarial_data().map(|(label, _)| label).collect();
        for label in &seedhash_labels {
            assert!(
                [
                    "CFROUND",
                    "FDIV_M",
                    "CACHE_MISS",
                    "CBRANCH",
                    "COMBINED_HEAVY"
                ]
                .contains(label),
                "unknown seedhash class label {label}"
            );
        }
        for label in &data_labels {
            assert!(
                [
                    "DIV_BY_ZERO",
                    "SIGNED_DIV_OVERFLOW",
                    "SHIFT_BY_WIDTH",
                    "U128_TRUNC_HIGH"
                ]
                .contains(label),
                "unknown data class label {label}"
            );
        }
    }
}

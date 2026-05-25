// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic ChaCha20-seeded random corpus generator
//! (§5.1.5 + R1-D4 + §3.18 R6-D1).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §3 R1-D4 close, the
//! random `(seedhash, data)` corpus is derived from a fixed 32-byte
//! `ChaCha20Rng` seed so a CI byte-equality failure is reproducible
//! from a local `cargo` invocation at the same fork pin. Per §3.18
//! R6-D1 substrate-correction, the 32-byte seed is the SHA-256 of a
//! named source string (the original "padded to 32 bytes" close was
//! a literal-arithmetic slip — the source string is 37 ASCII bytes,
//! which does not fit a `[u8; 32]`).
//!
//! ## Corpus shape
//!
//! Per R1-D4 §F2:
//!
//! - Per-PR cadence: 16 seedhashes × 8 data values = 128 pairs.
//! - Nightly cadence: 32 seedhashes × 32 data values = 1024 pairs.
//!
//! Sizing is selected via the §5.1.1 CLI flags
//! `--random-corpus-seedhashes=<N>` (default 32) and
//! `--random-corpus-data-per-seedhash=<M>` (default 32) per R4-D6.
//!
//! Per R1-D4's data-length distribution pin: each data value is
//! drawn from a block-template-shaped bimodal distribution — 50%
//! header-shaped (`Uniform(64, 200)`) and 50% larger
//! block-template-shaped (`Uniform(200, 600 * 1024)`). The
//! distribution mirrors realistic `compute_hash` inputs, catching
//! divergences in the common-input path before the §5.1.6
//! adversarial corpus catches rare-path divergences.
//!
//! ## C5a scope (§3.18 R6-D2)
//!
//! This module is fully implemented at C5a; the random corpus
//! exercises the byte-equality and canonical-output assertions
//! that anchor the R1-D14 cache-equivalence precondition + the
//! per-`(seedhash, data)` byte-equality test. The §5.1.6 adversarial
//! corpus arrives structurally scaffolded at C5a and is filled
//! against grinded bytes at C5b per §3.18 R6-D2.

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use shekyl_pow_randomx::Seedhash;

/// Source string from which [`RANDOM_CORPUS_SEED_V1`] is derived
/// per §3.18 R6-D1.
///
/// The `-v1` suffix anchors the R1-D4 reversion clause: a future
/// R1-D4 reopen toward a different distribution lands as
/// `RANDOM_CORPUS_SEED_V2_SOURCE` + `RANDOM_CORPUS_SEED_V2` in new
/// constants, leaving v1 intact for historical reproduction.
pub const RANDOM_CORPUS_SEED_V1_SOURCE: &str = "shekyl-randomx-differential-corpus-v1";

/// 32-byte `ChaCha20Rng` seed for the random corpus, per R1-D4.
///
/// Per §3.18 R6-D1, this equals
/// `SHA-256(RANDOM_CORPUS_SEED_V1_SOURCE)`; the
/// [`tests::seed_v1_matches_source_sha256`] unit test re-derives the
/// SHA-256 at runtime and asserts equality, catching any drift
/// between the source string and the committed bytes. The runtime
/// recompute is deliberate — a hard-coded hex pin would pass even
/// if the constant and the source-string comment drifted apart.
pub const RANDOM_CORPUS_SEED_V1: [u8; 32] = [
    0xeb, 0x09, 0xeb, 0x8c, 0xe6, 0xc5, 0xfe, 0xb6, 0xb5, 0xda, 0x25, 0xb4, 0x57, 0xde, 0x85, 0x15,
    0xea, 0xf6, 0xa0, 0x93, 0x30, 0x0d, 0x6e, 0xbf, 0xb9, 0xeb, 0xe2, 0xc6, 0xe5, 0x48, 0x61, 0x65,
];

/// Header-shaped data length lower bound (inclusive), per R1-D4.
///
/// Stored as `u32` because [`sample_uniform_u32`] operates on u32
/// ranges; both header-shaped and block-template-shaped bounds fit
/// comfortably below `u32::MAX`. The widening to `usize` happens at
/// the call site via `usize::from`, which is infallible on the
/// project's supported (≥32-bit) targets.
const DATA_LEN_HEADER_MIN: u32 = 64;
/// Header-shaped data length upper bound (exclusive), per R1-D4.
const DATA_LEN_HEADER_MAX: u32 = 200;
/// Block-template-shaped data length upper bound (exclusive), per
/// R1-D4 (named against `parent §6 line 234`'s 2 MiB ceiling without
/// grinding against the ceiling itself).
const DATA_LEN_BLOCK_TEMPLATE_MAX: u32 = 600 * 1024;

/// Per-PR-cadence default sizing per R1-D4 §F2.
pub const PER_PR_SEEDHASH_COUNT: usize = 16;
/// Per-PR-cadence default sizing per R1-D4 §F2.
pub const PER_PR_DATA_PER_SEEDHASH: usize = 8;

/// Nightly-cadence default sizing per R1-D4 §F2.
pub const NIGHTLY_SEEDHASH_COUNT: usize = 32;
/// Nightly-cadence default sizing per R1-D4 §F2.
pub const NIGHTLY_DATA_PER_SEEDHASH: usize = 32;

/// One `(seedhash, data)` pair in the random corpus.
///
/// `data` is owned (`Vec<u8>`) because the bimodal distribution
/// yields lengths from 64 B up to ~600 KiB; a fixed-size buffer
/// would over-allocate the 128-pair per-PR corpus by ~75 MiB.
#[derive(Debug, Clone)]
pub struct RandomCorpusPair {
    pub seedhash: Seedhash,
    pub data: Vec<u8>,
}

/// Deterministic random corpus generator (§5.1.5 + R1-D4).
///
/// The seed-to-corpus mapping is byte-stable across (a) re-invocations
/// at the same `(seedhash_count, data_per_seedhash)` sizing — T9 asserts
/// this property — and (b) hardware platforms — `ChaCha20Rng` is a
/// software-defined stream cipher and produces identical bytes
/// regardless of CPU. The corpus shape `(seedhash_count,
/// data_per_seedhash)` is **not** a discriminator for byte-stability
/// within a single sizing — re-running with a different sizing yields
/// a different corpus, by construction.
///
/// Failure-reproduction discipline (R1-D4 §F2): given a `(seedhash,
/// data, …)` failure surfaced in a CI byte-equality run, a local
/// reviewer reproduces the corpus with the matching CLI flags and
/// re-runs the harness; the pair indexed at the same `(i, j)` is
/// guaranteed byte-identical.
pub fn generate_random_corpus(
    seedhash_count: usize,
    data_per_seedhash: usize,
) -> Vec<RandomCorpusPair> {
    let mut rng = ChaCha20Rng::from_seed(RANDOM_CORPUS_SEED_V1);
    let mut pairs = Vec::with_capacity(seedhash_count * data_per_seedhash);
    for _ in 0..seedhash_count {
        let mut seedhash_bytes = [0u8; 32];
        rng.fill_bytes(&mut seedhash_bytes);
        let seedhash = Seedhash::from_bytes(seedhash_bytes);
        for _ in 0..data_per_seedhash {
            // `usize::try_from(u32)` is infallible on ≥32-bit targets,
            // which covers every supported Shekyl build target. Using
            // `try_from` over an `as` cast keeps the lossy-cast clippy
            // lint quiet without an `#[allow]`.
            let len = usize::try_from(next_data_length(&mut rng))
                .expect("u32 data length fits usize on supported targets");
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);
            pairs.push(RandomCorpusPair { seedhash, data });
        }
    }
    pairs
}

/// Draw a single data length from the R1-D4 block-template-shaped
/// bimodal distribution: 50% header-shaped (`Uniform(64, 200)`),
/// 50% larger block-template-shaped (`Uniform(200, 600 KiB)`).
///
/// The bimodality is implemented with one bit of `ChaCha20Rng`
/// output (the low bit of a u32) for the mode selection followed by
/// a uniform draw within the selected range. The single-bit
/// selection is byte-stable across invocations at the same RNG
/// state (T9 anchor).
///
/// Returns a `u32` because both R1-D4 ranges fit comfortably below
/// `u32::MAX` (the upper bound is `DATA_LEN_BLOCK_TEMPLATE_MAX =
/// 600 * 1024`). The widening to `usize` happens at the call site
/// via `usize::try_from`, which is infallible on every supported
/// Shekyl target (≥32-bit).
fn next_data_length(rng: &mut ChaCha20Rng) -> u32 {
    let mode_bit = rng.next_u32() & 1;
    if mode_bit == 0 {
        sample_uniform_u32(rng, DATA_LEN_HEADER_MIN, DATA_LEN_HEADER_MAX)
    } else {
        sample_uniform_u32(rng, DATA_LEN_HEADER_MAX, DATA_LEN_BLOCK_TEMPLATE_MAX)
    }
}

/// Sample a `u32` from `[lo, hi)` using rejection sampling on
/// `ChaCha20Rng::next_u32` output.
///
/// Why rejection sampling rather than `rng.gen_range`: the workspace
/// dep is `rand_chacha = { workspace = true }` without the `rand`
/// front-door crate (per §5.1.15 + R4-D1; `rand` is not a workspace
/// dep), so `Rng::gen_range` isn't in scope. Rejection sampling
/// produces a byte-stable, bias-free draw using only
/// `RngCore::next_u32` — the surface `rand_chacha` exposes directly.
///
/// The range `(lo, hi)` must satisfy `hi > lo`. Both current R1-D4
/// call sites (`(64, 200)` and `(200, 600 KiB)`) fit `u32`; a future
/// R1-D4 reopen that widens the upper bound past `u32::MAX` will
/// introduce a `sample_uniform_u64` sibling rather than restoring a
/// dual-branch shape — keeping the byte sequence stable for any
/// committed canonicals against the current sizing.
fn sample_uniform_u32(rng: &mut ChaCha20Rng, lo: u32, hi: u32) -> u32 {
    assert!(hi > lo, "sample_uniform_u32: hi must exceed lo");
    let bound = hi - lo;
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let v = rng.next_u32();
        if v < zone {
            return lo + (v % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// T9 (a) — seed-source SHA-256 derivation (§3.18 R6-D1).
    ///
    /// Re-derives `RANDOM_CORPUS_SEED_V1` at runtime by hashing
    /// `RANDOM_CORPUS_SEED_V1_SOURCE` and asserts equality with the
    /// committed constant. The runtime recompute (rather than a
    /// hard-coded hex pin) catches comment-vs-bytes drift if a future
    /// `_V2` revision lands the constant and the comment-cited source
    /// drift apart.
    #[test]
    fn seed_v1_matches_source_sha256() {
        let computed: [u8; 32] = Sha256::digest(RANDOM_CORPUS_SEED_V1_SOURCE.as_bytes()).into();
        assert_eq!(
            computed, RANDOM_CORPUS_SEED_V1,
            "RANDOM_CORPUS_SEED_V1 must equal SHA-256 of \
             RANDOM_CORPUS_SEED_V1_SOURCE; drift indicates the \
             constant and the named source disagree per \
             RANDOMX_V2_PHASE2G_PLAN.md §3.18 R6-D1 discipline"
        );
    }

    /// T9 (b) — corpus determinism across re-invocations (§3 R1-D4).
    ///
    /// Two independent invocations at the same `(seedhash_count,
    /// data_per_seedhash)` sizing yield byte-identical corpora. The
    /// property is anchored by `ChaCha20Rng` being a software-defined
    /// stream cipher that produces identical bytes from identical
    /// seed input regardless of platform.
    #[test]
    fn random_corpus_seed_determinism() {
        let corpus_a = generate_random_corpus(4, 3);
        let corpus_b = generate_random_corpus(4, 3);
        assert_eq!(corpus_a.len(), corpus_b.len());
        assert_eq!(corpus_a.len(), 12);
        for (i, (a, b)) in corpus_a.iter().zip(corpus_b.iter()).enumerate() {
            assert_eq!(
                a.seedhash.as_bytes(),
                b.seedhash.as_bytes(),
                "pair {i} seedhash drift"
            );
            assert_eq!(a.data, b.data, "pair {i} data drift");
        }
    }

    /// Shape invariant: every data length falls within the
    /// R1-D4 bimodal distribution's union range
    /// `[DATA_LEN_HEADER_MIN, DATA_LEN_BLOCK_TEMPLATE_MAX)`.
    #[test]
    fn random_corpus_data_lengths_in_distribution_range() {
        let corpus = generate_random_corpus(8, 4);
        let lo = DATA_LEN_HEADER_MIN as usize;
        let hi = DATA_LEN_BLOCK_TEMPLATE_MAX as usize;
        for pair in &corpus {
            let len = pair.data.len();
            assert!(len >= lo, "data length {len} below header-min {lo}");
            assert!(
                len < hi,
                "data length {len} at or above block-template-max {hi}"
            );
        }
    }

    /// Per-PR / nightly default sizing is reachable via the public
    /// generator surface. Documents the F2-pinned cadence sizing as
    /// load-bearing for §5.5.1 + §5.5.2 budget calculation.
    #[test]
    fn cadence_sizing_constants_compose() {
        assert_eq!(PER_PR_SEEDHASH_COUNT * PER_PR_DATA_PER_SEEDHASH, 128);
        assert_eq!(NIGHTLY_SEEDHASH_COUNT * NIGHTLY_DATA_PER_SEEDHASH, 1024);
    }
}

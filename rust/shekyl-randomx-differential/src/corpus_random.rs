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

/// `(canonical_index, RandomCorpusPair)` for each pair in the
/// correctness-mode subset of the always-nightly random corpus
/// (§3.18 R6-D4).
///
/// Per R6-D4, the canonical pin (`CANONICAL_RANDOM_HASHES` +
/// `CANONICAL_CACHE_SHAS`) is committed at nightly sizing
/// `(NIGHTLY_SEEDHASH_COUNT, NIGHTLY_DATA_PER_SEEDHASH) = (32, 32)`
/// and indexed by corpus position. To preserve the canonical
/// mapping at per-PR cadence (16 × 8 = 128 pairs), the harness
/// **must** advance the underlying `ChaCha20Rng` through the full
/// nightly stream so the *i*-th seedhash and the *j*-th data value
/// land on the same RNG bytes that produced the canonical entry
/// at flat index `i * NIGHTLY_DATA_PER_SEEDHASH + j`. Selecting a
/// `(requested_seedhashes, requested_data_per_seedhash)` subset is
/// therefore a *2D filter* over the nightly stream, not a contiguous
/// prefix.
///
/// The returned `usize` is the pair's flat index in the nightly
/// corpus, i.e., the index into [`crate::canonical_outputs::
/// CANONICAL_RANDOM_HASHES`]. The seedhash's nightly index (for
/// [`crate::canonical_outputs::CANONICAL_CACHE_SHAS`]) is
/// `canonical_index / NIGHTLY_DATA_PER_SEEDHASH`.
///
/// # Panics
///
/// Panics if either `requested_seedhashes` or
/// `requested_data_per_seedhash` exceeds the corresponding
/// `NIGHTLY_*` constant; the caller (mode_correctness) clamps the
/// CLI-supplied sizing against the nightly bounds before calling.
///
/// # Cost
///
/// The function advances the RNG through every nightly pair (1024
/// ChaCha20 draws + data-length-shaped byte fills) regardless of
/// the requested subset. Skipped pairs are dropped immediately
/// without storage, so the heap cost is bounded by the *requested*
/// subset, not the nightly corpus. The RNG-advance cost (~1024
/// data draws, mean ~150 KiB each) dominates a 1×1 smoke test;
/// per-PR (16 × 8) and nightly (32 × 32) runs amortize the
/// generation against the per-pair byte-equality work.
pub fn generate_correctness_subset(
    requested_seedhashes: usize,
    requested_data_per_seedhash: usize,
) -> Vec<(usize, RandomCorpusPair)> {
    assert!(
        requested_seedhashes <= NIGHTLY_SEEDHASH_COUNT,
        "requested_seedhashes={requested_seedhashes} > NIGHTLY_SEEDHASH_COUNT={NIGHTLY_SEEDHASH_COUNT}"
    );
    assert!(
        requested_data_per_seedhash <= NIGHTLY_DATA_PER_SEEDHASH,
        "requested_data_per_seedhash={requested_data_per_seedhash} > NIGHTLY_DATA_PER_SEEDHASH={NIGHTLY_DATA_PER_SEEDHASH}"
    );
    let mut rng = ChaCha20Rng::from_seed(RANDOM_CORPUS_SEED_V1);
    let mut subset = Vec::with_capacity(requested_seedhashes * requested_data_per_seedhash);
    for i in 0..NIGHTLY_SEEDHASH_COUNT {
        let mut seedhash_bytes = [0u8; 32];
        rng.fill_bytes(&mut seedhash_bytes);
        let seedhash = Seedhash::from_bytes(seedhash_bytes);
        for j in 0..NIGHTLY_DATA_PER_SEEDHASH {
            let len = usize::try_from(next_data_length(&mut rng))
                .expect("u32 data length fits usize on supported targets");
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);
            if i < requested_seedhashes && j < requested_data_per_seedhash {
                let canonical_index = i * NIGHTLY_DATA_PER_SEEDHASH + j;
                subset.push((canonical_index, RandomCorpusPair { seedhash, data }));
            }
        }
    }
    subset
}

/// `(seedhash, data_values)` for the §5.1.12 latency-mode draw
/// (§5.1.12 + R1-D7 §F2 + the §3.15.2 "single seedhash, N data
/// samples" disposition).
///
/// Per R1-D7's methodology pin ("single fixed seedhash + 1024 fixed
/// deterministic data values per R1-D4's ChaCha20Rng-seeded shape"),
/// the latency mode pins the seedhash to the **first nightly
/// seedhash** (byte-identical to `generate_random_corpus(1,
/// 1)[0].seedhash` and to `generate_correctness_subset(1, 1)[0].1
/// .seedhash` — anchoring it to the same first-of-the-corpus
/// position so the BENCH_RESULTS.md / failure-output reader can
/// cross-reference latency runs with correctness runs at the same
/// canonical position) and draws `samples` data values from the same
/// [`RANDOM_CORPUS_SEED_V1`]-seeded `ChaCha20Rng` stream after the
/// single seedhash draw — i.e., the latency mode is a **single-
/// seedhash sub-sample of the R1-D4 data stream**, not a separate
/// domain-separated stream.
///
/// ## Byte stability
///
/// `(seedhash, data_values[0..samples])` is byte-stable across
/// platforms and re-invocations at the same `samples` value. The
/// first 32 entries of `data_values` are byte-identical to the
/// nightly random corpus's 32 data values for seedhash 0; entries
/// 32..N continue the same stream that *would have been*
/// seedhash-1+ data in the random corpus had this draw interleaved
/// new seedhashes. The latency mode pins to seedhash 0 — no further
/// seedhash draws — so the data stream past index 31 diverges from
/// the random corpus's emission order. The divergence is by design:
/// the latency mode is a single-seedhash mode and does not need
/// per-seedhash byte alignment with the random corpus past the
/// first 32 data values.
///
/// ## Cost
///
/// Draws `1 + samples` `next_data_length` invocations from a fresh
/// [`ChaCha20Rng`]. Total cost is bounded by the `samples * mean
/// data length` byte fills — at `samples = 1024` and a mean ~150
/// KiB the corpus pays ~150 MiB of `fill_bytes` work, dwarfed by
/// the per-iteration `compute_hash` work that latency mode is
/// measuring.
pub fn generate_latency_data(samples: usize) -> (Seedhash, Vec<Vec<u8>>) {
    let mut rng = ChaCha20Rng::from_seed(RANDOM_CORPUS_SEED_V1);
    let mut seedhash_bytes = [0u8; 32];
    rng.fill_bytes(&mut seedhash_bytes);
    let seedhash = Seedhash::from_bytes(seedhash_bytes);
    let mut data_values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let len = usize::try_from(next_data_length(&mut rng))
            .expect("u32 data length fits usize on supported targets");
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        data_values.push(data);
    }
    (seedhash, data_values)
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

    /// `generate_correctness_subset(requested_S, requested_M)` returns
    /// the *same* `(seedhash, data)` bytes for each `(i, j)` pair as
    /// `generate_random_corpus(NIGHTLY_S, NIGHTLY_M)[i * NIGHTLY_M + j]`.
    ///
    /// This is the load-bearing property for the §3.18 R6-D4
    /// canonical pin: the per-PR subset's pair at canonical index
    /// `i * NIGHTLY_DATA_PER_SEEDHASH + j` indexes into the
    /// committed `CANONICAL_RANDOM_HASHES` at the same position,
    /// because the underlying RNG bytes are byte-identical between
    /// the full nightly generator and the subset filter. Asserts
    /// the property across a small 4 × 3 subset of the full
    /// (32, 32) nightly draw.
    #[test]
    fn correctness_subset_aligns_with_nightly_indexing() {
        let nightly = generate_random_corpus(NIGHTLY_SEEDHASH_COUNT, NIGHTLY_DATA_PER_SEEDHASH);
        let subset = generate_correctness_subset(4, 3);
        assert_eq!(subset.len(), 12);
        for (idx, pair) in &subset {
            let nightly_pair = &nightly[*idx];
            assert_eq!(
                pair.seedhash.as_bytes(),
                nightly_pair.seedhash.as_bytes(),
                "canonical_index {idx} seedhash drift"
            );
            assert_eq!(
                pair.data, nightly_pair.data,
                "canonical_index {idx} data drift"
            );
        }
    }

    /// The subset emission order is row-major over `(i, j)`: pairs
    /// from seedhash *i* arrive contiguously, followed by seedhash
    /// *i+1*'s pairs. The canonical-index sequence is the strictly-
    /// increasing 2D filter
    /// `[i * NIGHTLY_M + j for i in 0..req_S for j in 0..req_M]`.
    #[test]
    fn correctness_subset_canonical_index_sequence() {
        let subset = generate_correctness_subset(3, 2);
        let indices: Vec<usize> = subset.iter().map(|(idx, _)| *idx).collect();
        let expected: Vec<usize> = (0..3)
            .flat_map(|i| (0..2).map(move |j| i * NIGHTLY_DATA_PER_SEEDHASH + j))
            .collect();
        assert_eq!(indices, expected);
    }

    /// A `(1, 1)` subset — the §8.1 C7 row's smoke-test sizing —
    /// returns a single pair at canonical index 0 that matches
    /// `generate_random_corpus(1, 1)[0]`. Pins the smoke-test path
    /// against the always-nightly indexing.
    #[test]
    fn correctness_subset_smoke_test_single_pair() {
        let subset = generate_correctness_subset(1, 1);
        assert_eq!(subset.len(), 1);
        let (canonical_idx, pair) = &subset[0];
        assert_eq!(*canonical_idx, 0);
        // The seedhash bytes come from the first 32 bytes of the
        // ChaCha20 stream; verify against `generate_random_corpus(1, 1)`
        // which uses the same seed.
        let direct = generate_random_corpus(1, 1);
        assert_eq!(direct.len(), 1);
        assert_eq!(pair.seedhash.as_bytes(), direct[0].seedhash.as_bytes());
        // The data lengths might differ because `(1, 1)` ends the
        // RNG draw after one data value, while `generate_correctness_subset(1, 1)`
        // continues advancing through the full nightly stream — the
        // data length of the *first* draw is identical, though.
        assert_eq!(pair.data, direct[0].data);
    }

    /// `generate_latency_data` is byte-stable across re-invocations
    /// at the same `samples` value. The seedhash equals the first
    /// nightly seedhash from `generate_random_corpus(1, 1)`. The
    /// first 32 data values are byte-identical to the nightly random
    /// corpus's data values for seedhash 0 (per the
    /// "single-seedhash sub-sample of the R1-D4 data stream" rustdoc).
    #[test]
    fn latency_data_byte_stability_and_first_32_match() {
        let (sh_a, d_a) = generate_latency_data(64);
        let (sh_b, d_b) = generate_latency_data(64);
        assert_eq!(sh_a.as_bytes(), sh_b.as_bytes());
        assert_eq!(d_a.len(), 64);
        assert_eq!(d_b.len(), 64);
        for i in 0..64 {
            assert_eq!(d_a[i], d_b[i], "data pair {i} drift between invocations");
        }
        // Cross-check the first 32 data values against the nightly
        // random corpus's seedhash-0 row.
        let nightly = generate_random_corpus(1, NIGHTLY_DATA_PER_SEEDHASH);
        assert_eq!(nightly.len(), NIGHTLY_DATA_PER_SEEDHASH);
        assert_eq!(sh_a.as_bytes(), nightly[0].seedhash.as_bytes());
        for i in 0..NIGHTLY_DATA_PER_SEEDHASH {
            assert_eq!(
                d_a[i], nightly[i].data,
                "latency data[{i}] should match nightly seedhash-0 data[{i}]"
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

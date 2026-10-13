// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RNG seam and the unbiased integer uniform draw.
//!
//! One trait with one method keeps this crate dependency-free. The same draw
//! code serves the daemon's CSPRNG in production, a seeded `SplitMix64` in
//! the measurement harness, and the frozen golden vector. The trait is the
//! same shape as `shekyl-standoff`'s `GapRng`: one method, integer draws,
//! no dependency. The goodness-of-fit grade stays with the distribution it
//! grades (`shekyl-relay-privacy`'s `conformance` feature, and
//! `shekyl-standoff`'s).
//!
//! # Why its own crate
//!
//! The relay scheduler, the peerlist, the dialer and the FFI's CSPRNG all
//! draw through [`RelayRng`]. It lived in `shekyl-relay-privacy`, so each of
//! them depended on the relay-timing crate for one trait. No crate below all
//! of them could hold it, so it has a crate of its own with no dependencies.
//!
//! # `SplitMix64` does not exist in a production build
//!
//! The seeded reference generator is not a CSPRNG. It lives in `splitmix`
//! and compiles only under `cfg(any(test, feature = "splitmix"))`. The
//! `splitmix` feature is enabled from `[dev-dependencies]` edges only
//! (`scripts/ci/check_test_only_features.py`). A production draw from it is
//! a compile error, not a review finding. The name is the generator's, so
//! it is not confused with the `conformance` feature those other crates use
//! for their float grader.
//!
//! # Why not `rand`
//!
//! The inherited C++ reaches `std::uniform_int_distribution` and
//! `std::poisson_distribution` through `crypto::random_device`
//! (`src/crypto/crypto.h`, `src/crypto/duration.h`). Both distributions are
//! **implementation-defined**: libstdc++ and libc++ emit different sequences
//! from identical entropy. `shekyl-relay-privacy`'s crate docs and
//! `poisson.rs` record why that rules out a cross-language golden vector for
//! the inherited timers. Taking a dependency on `rand`/`rand_distr` would
//! re-create that problem one layer up — the sequence would then be pinned
//! to a crate version rather than a stdlib. The draws here are written out,
//! so the distribution is the reviewable artifact.

#![deny(unsafe_code)]

/// Minimal RNG abstraction the daemon's draws are generic over.
///
/// Production supplies a CSPRNG; the measurement harness and golden vector
/// supply a seeded `SplitMix64`. A single method is deliberate: it is the
/// smallest surface that keeps the crate dependency-free, and every draw
/// generic over it is built from it.
pub trait RelayRng {
    /// Next uniformly-distributed 64-bit word.
    fn next_u64(&mut self) -> u64;
}

#[cfg(any(test, feature = "splitmix"))]
mod splitmix;

/// Seeded reference generator. Absent unless this crate is built for tests
/// or with the `splitmix` feature.
#[cfg(any(test, feature = "splitmix"))]
pub use splitmix::SplitMix64;

impl<R: RelayRng + ?Sized> RelayRng for &mut R {
    fn next_u64(&mut self) -> u64 {
        (**self).next_u64()
    }
}

/// Draw a uniformly-distributed integer in the inclusive range `[0, max]`,
/// free of modulo bias.
///
/// The naive `next_u64() % (max + 1)` over-weights the low residues whenever
/// `max + 1` does not divide `2^64`. That bias is privacy-load-bearing here
/// exactly as it is in the funding-seam draw: a skewed epoch or flush offset
/// is a fingerprint. The incomplete top bucket is rejected so every value in
/// `[0, max]` is equiprobable.
///
/// Pure integer arithmetic, so the result is deterministic and identical on
/// every architecture.
pub fn bounded_uniform<R: RelayRng + ?Sized>(rng: &mut R, max: u64) -> u64 {
    if max == u64::MAX {
        // Full range: every draw is already uniform over [0, u64::MAX].
        return rng.next_u64();
    }
    let range = max + 1; // number of outcomes in [0, max], >= 1

    // `2^64 mod range`, computed without overflowing u64. `u64::MAX % range`
    // is `(2^64 - 1) mod range`; adding 1 gives `2^64 mod range`, except when
    // that lands on `range` itself (range divides 2^64 evenly), which folds
    // to 0.
    let rem = {
        let r = (u64::MAX % range) + 1;
        if r == range {
            0
        } else {
            r
        }
    };

    // Accept the largest range-aligned prefix `[0, 2^64 - rem)`; reject the
    // top `rem` values so the accepted region is an exact multiple of `range`.
    loop {
        let x = rng.next_u64();
        if rem == 0 || x <= u64::MAX - rem {
            return x % range;
        }
    }
}

/// Draw a fair Bernoulli trial that succeeds with probability
/// `numerator / denominator`.
///
/// The inherited fluff coin is `crypto::rand_idx(100) < 20`
/// (`levin_notify.cpp:709`) — a uniform draw over `[0, 99]` compared against a
/// threshold. That shape is reproduced here exactly, but over the unbiased
/// sampler above rather than `std::uniform_int_distribution`.
///
/// # Panics
///
/// Panics if `denominator` is zero — a zero-denominator probability has no
/// meaning and every caller passes a compile-time constant.
pub fn bernoulli<R: RelayRng + ?Sized>(rng: &mut R, numerator: u64, denominator: u64) -> bool {
    assert!(denominator > 0, "bernoulli denominator must be non-zero");
    bounded_uniform(rng, denominator - 1) < numerator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_uniform_respects_its_bound() {
        let mut rng = SplitMix64::new(7);
        for max in [0_u64, 1, 2, 99, 1_000, u64::MAX] {
            for _ in 0..256 {
                assert!(bounded_uniform(&mut rng, max) <= max);
            }
        }
    }

    #[test]
    fn bounded_uniform_zero_max_is_constant() {
        let mut rng = SplitMix64::new(11);
        for _ in 0..64 {
            assert_eq!(bounded_uniform(&mut rng, 0), 0);
        }
    }

    #[test]
    fn bernoulli_matches_its_stated_rate_coarsely() {
        // Coarse smoke check only. The chi-square grade lives in
        // `shekyl-relay-privacy`'s conformance suite. 20/100 over 20k trials
        // sits far inside these bounds.
        let mut rng = SplitMix64::new(2026);
        let hits = (0..20_000).filter(|_| bernoulli(&mut rng, 20, 100)).count();
        assert!(
            (3_600..4_400).contains(&hits),
            "fluff coin rate out of coarse band: {hits}/20000"
        );
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn bernoulli_rejects_zero_denominator() {
        let mut rng = SplitMix64::new(1);
        let _ = bernoulli(&mut rng, 0, 0);
    }
}

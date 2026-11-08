// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sim's one deterministic generator.
//!
//! SplitMix64 over a `u64` state, with no `rand` dependency
//! (`17-dependency-discipline.mdc`). Every mode replays from its seed, so
//! the stream is load-bearing: the five-seed L11/L13 pins hold its bits.
//! Nothing the chain computes is drawn from it. The economics sim's
//! `rng.rs` is the same body; the two crates do not share a dependency
//! for it.
//!
//! This module replaces four copies that were one function: `model::Rng`
//! and the `SplitMix64` structs of `standoff.rs`, `clustering.rs` and
//! `cover.rs` (EUP-3 check half, Appendix B N5/R20).

/// `2^64 / φ`. SplitMix64 adds this to its state on every draw.
pub(crate) const GOLDEN_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;
/// Stafford mix multipliers. The shifts 30, 27, 31 are part of that mix.
const STAFFORD_MIX_1: u64 = 0xBF58_476D_1CE4_E5B9;
const STAFFORD_MIX_2: u64 = 0x94D0_49BB_1331_11EB;

/// SplitMix64 over a `u64` state.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GOLDEN_INCREMENT);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(STAFFORD_MIX_1);
        z = (z ^ (z >> 27)).wrapping_mul(STAFFORD_MIX_2);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)` from the top 53 bits.
    pub(crate) fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform integer in `[0, n)`; `0` when `n` is `0`.
    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// In-place Fisher–Yates shuffle.
    pub(crate) fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.below(i + 1);
            slice.swap(i, j);
        }
    }

    /// Standard normal by Box–Muller; one of the pair is used.
    pub(crate) fn gaussian(&mut self) -> f64 {
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Poisson draw: Knuth for a mean up to 30, a normal approximation
    /// above it, where `exp(-λ)` underflows and Knuth's loop is slow.
    pub(crate) fn poisson(&mut self, mean: f64) -> u64 {
        if mean <= 0.0 {
            return 0;
        }
        if mean > 30.0 {
            let v = mean + mean.sqrt() * self.gaussian();
            return v.round().max(0.0) as u64;
        }
        let l = (-mean).exp();
        let mut k = 0u64;
        let mut p = 1.0;
        loop {
            k += 1;
            p *= self.unit();
            if p <= l {
                return k - 1;
            }
        }
    }

    /// Geometric draw with the given **mean** (failures before the first
    /// success): `P(j) = (1−p)^j · p`, `mean = (1−p)/p`, so
    /// `p = 1/(mean+1)`. Inverse CDF: `j = ⌊ln(U) / ln(1−p)⌋`. Heavy right
    /// tail, so `CV ≈ 1`.
    pub(crate) fn geometric(&mut self, mean: f64) -> u64 {
        if mean <= 0.0 {
            return 0;
        }
        let p = 1.0 / (mean + 1.0);
        let denom = (1.0 - p).ln();
        if denom == 0.0 {
            return 0;
        }
        let u = self.unit().max(1e-12);
        (u.ln() / denom).floor().max(0.0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream is SplitMix64's published one: seed 0 gives
    /// `0xE220A8397B1DCDAF` first (Vigna's reference implementation).
    #[test]
    fn seed_zero_matches_the_reference_stream() {
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    }
}

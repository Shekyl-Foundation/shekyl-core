// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sim's deterministic generators.
//!
//! Two generators, two pinned streams, no `rand` crate. [`SplitMix64`] is
//! what the secret-draw evidence draws when a block is never built: a
//! dropout, a reveal lag, a seed, a hash. [`PoissonTrace`] is the
//! xorshift64* stream the fee instruments share for Poisson traffic.
//! Nothing the chain computes is drawn from either. A production CSPRNG
//! lives with the code that needs one.

/// Low half of `2^64 / φ`. Spreads a small run index off the all-zero
/// state. It is not the generator's per-draw increment.
const SEED_SPREAD: u64 = 0x9E37_79B9;

/// `2^64 / φ`. SplitMix64 adds this to its state on every draw.
const GOLDEN_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;

/// Stafford mix multipliers. The shifts 30, 27, 31 are part of that mix.
const STAFFORD_MIX_1: u64 = 0xBF58_476D_1CE4_E5B9;
const STAFFORD_MIX_2: u64 = 0x94D0_49BB_1331_11EB;

/// Vigna's xorshift64* multiplier. The shifts 12, 25, 27 are the triple.
const XORSHIFT64_STAR_MUL: u64 = 0x2545_F491_4F6C_DD1D;

/// Seed both fee instruments use, so a dwell trace and a floor trace are
/// the same block sequence.
pub(crate) const POISSON_TRACE_SEED: u64 = 0x5EED_F1FE_ED1E_5EED;

/// Knuth's product underflows past a mean near 745 and would silently cap
/// samples. The assert fires before that.
const POISSON_MEAN_LIMIT: f64 = 700.0;

/// SplitMix64 over a `u64` state. The secret-draw stream.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    /// The generator for run `seed`. Seeds are small integers; the multiply
    /// spreads them and the `+ 1` keeps seed 0 off the all-zero state.
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(seed.wrapping_mul(SEED_SPREAD).wrapping_add(1))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GOLDEN_INCREMENT);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(STAFFORD_MIX_1);
        z = (z ^ (z >> 27)).wrapping_mul(STAFFORD_MIX_2);
        z ^ (z >> 31)
    }

    /// 32 bytes, one [`Self::below`]`(256)` each.
    ///
    /// The secret-draw figures are pinned to this packing: one uniform byte
    /// per draw. Filling the array from raw `u64` words would be a different
    /// stream.
    pub(crate) fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for byte in &mut out {
            *byte = u8::try_from(self.below(256)).expect("below 256 fits a byte");
        }
        out
    }

    /// Uniform draw in `[0, n)` by rejection (no modulo bias).
    /// `n` must be nonzero — an empty range has no uniform draw.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "uniform draw from an empty range");
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next();
            if v < zone {
                return v % n;
            }
        }
    }
}

/// xorshift64* for the fee instruments' Poisson traffic.
pub(crate) struct PoissonTrace(u64);

impl PoissonTrace {
    /// The shared fee-instrument stream.
    pub(crate) fn trace() -> Self {
        Self(POISSON_TRACE_SEED)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(XORSHIFT64_STAR_MUL)
    }

    #[allow(clippy::cast_precision_loss)]
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Knuth Poisson sampler. Exact for the registered means (≤ 500).
    pub(crate) fn poisson(&mut self, mean: f64) -> u64 {
        assert!(
            mean < POISSON_MEAN_LIMIT,
            "Knuth sampler underflows near mean 745"
        );
        if mean <= 0.0 {
            return 0;
        }
        let l = (-mean).exp();
        let mut k = 0u64;
        let mut p = 1.0;
        loop {
            p *= self.unit();
            if p <= l {
                return k;
            }
            k += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both streams are pinned functions of their seeds. The values were
    /// computed from the generator definitions, not copied out of a run.
    #[test]
    fn the_streams_are_pinned() {
        let mut rng = SplitMix64::seeded(1);
        let draws: Vec<u64> = (0..5).map(|_| rng.below(1000)).collect();
        assert_eq!(draws, [191, 661, 971, 330, 55]);

        let mut rng = SplitMix64::seeded(7);
        assert_eq!(
            rng.bytes32(),
            [
                0x48, 0xa1, 0x61, 0xe5, 0x85, 0x5c, 0x33, 0x17, 0xfd, 0x09, 0xd2, 0x8f, 0x41, 0x56,
                0x93, 0x16, 0xe2, 0x21, 0x06, 0x4a, 0xdd, 0xd7, 0xd7, 0xc0, 0x2e, 0x12, 0x08, 0x8b,
                0x7d, 0x39, 0x13, 0x17,
            ]
        );

        let mut trace = PoissonTrace::trace();
        let samples: Vec<u64> = (0..5).map(|_| trace.poisson(50.0)).collect();
        assert_eq!(samples, [54, 48, 54, 50, 48]);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn an_empty_range_has_no_draw() {
        let _ = SplitMix64::seeded(1).below(0);
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sim's deterministic generators.
//!
//! Two generators, three pinned uses, no `rand` crate. [`SplitMix64`] is
//! what the secret-draw evidence draws when a block is never built: a
//! dropout, a reveal lag, a seed, a hash. It also draws the honest count a
//! block is offered when a fold's traffic varies ([`honest_count`]), keyed
//! on the block's height. [`PoissonTrace`] is the xorshift64* stream the
//! fee instruments share for Poisson traffic. Nothing the chain computes is
//! drawn from either. A production CSPRNG lives with the code that needs
//! one.

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

/// Seed of the fee-floor slew traces, fixed so every scenario and every run
/// sees the same block sequence.
pub(crate) const POISSON_TRACE_SEED: u64 = 0x5EED_F1FE_ED1E_5EED;

/// Spreads a [`HONEST_SEEDS`] member into the honest counts' key
/// ([`honest_count`]).
const HONEST_COUNT_SEED: u64 = 0x4F4E_E57C_0A11_7E57;

/// The declared seeds of variable traffic (§5.34): each figure on it is read
/// at all three, and the narration pins carry the first, the canonical one.
pub(crate) const HONEST_SEEDS: [u64; 3] = [1, 2, 3];

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

/// The honest transactions offered to the block at `height` under seed
/// `seed` when traffic is variable (`ECONOMICS_SIM_PRODUCTION_REBASE.md`
/// §5.34): geometric with mean `mean`.
///
/// Poisson arrivals at rate λ over an exponential block interval of mean
/// τ arrive as a geometric count of mean λτ, so this is production's
/// arrival count with the interval left implicit. It is drawn in integers,
/// as the number of draws `below(mean + 1)` that come up nonzero before
/// one comes up zero, each nonzero with probability `mean / (mean + 1)`.
/// No floating point, so a pin made on one host holds on every host. The
/// generator is seeded from the seed and the height alone, so two folds
/// over the same heights draw the same counts whatever else they do, and
/// in any order.
pub(crate) fn honest_count(seed: u64, height: u64, mean: u64) -> u64 {
    let key = SplitMix64::seeded(HONEST_COUNT_SEED ^ seed).next();
    let mut rng = SplitMix64::seeded(key ^ height);
    let mut count = 0;
    while rng.below(mean + 1) != 0 {
        count += 1;
    }
    count
}

/// The lower-middle median of [`honest_count`]'s distribution at mean
/// `mean`, in closed form: the least `k` with `1 − q^(k+1) ≥ 1/2`, where
/// `q = mean / (mean + 1)` (§5.34, the restated baseline).
///
/// `q^(k+1)` is a running product, not a rounded logarithm: at mean 50 the
/// answer, 35, sits on `P(count ≤ 34)` = 0.499 97, three parts in 10^5
/// under one half, against a product's error near 10^-14.
pub(crate) fn geometric_median(mean: u64) -> u64 {
    let q = mean as f64 / (mean + 1) as f64;
    let (mut k, mut tail) = (0, q);
    while tail > 0.5 {
        k += 1;
        tail *= q;
    }
    k
}

/// xorshift64* for the fee-floor slew traces' Poisson traffic.
pub(crate) struct PoissonTrace(u64);

impl PoissonTrace {
    /// The slew traces' fixed stream.
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

    /// The honest count is a function of the height and the mean alone,
    /// and geometric: over many heights at mean 50 its mean is 50, and the
    /// share of blocks offered at most `k` is `1 − (50/51)^(k+1)` (`k` = 0:
    /// one block in 51; 34: just under half; 68: about three in four).
    #[test]
    fn the_honest_count_is_geometric_and_keyed_on_the_height() {
        assert_eq!(honest_count(1, 17, 50), honest_count(1, 17, 50));
        assert_eq!(honest_count(1, 17, 0), 0, "a mean of zero offers nothing");
        assert!(
            (0..64).any(|h| honest_count(1, h, 50) != honest_count(2, h, 50)),
            "each seed draws its own traffic"
        );
        let blocks = 200_000u64;
        let counts: Vec<u64> = (0..blocks).map(|h| honest_count(1, h, 50)).collect();
        let mean = counts.iter().sum::<u64>() as f64 / blocks as f64;
        assert!((mean - 50.0).abs() < 0.5, "mean {mean}");
        for k in [0u64, 34, 68] {
            let at_most = counts.iter().filter(|&&c| c <= k).count() as f64 / blocks as f64;
            let expected = 1.0 - (50.0f64 / 51.0).powi(i32::try_from(k + 1).expect("small"));
            assert!(
                (at_most - expected).abs() < 0.004,
                "P(count <= {k}) = {at_most}, geometric {expected}"
            );
        }
    }

    /// The restated baseline's derivation (§5.34): at mean 50 the median is
    /// 35, with `P(count ≤ 34)` just under one half and `P(count ≤ 35)`
    /// over it; the median of a geometric count is near `ln 2` of its mean.
    #[test]
    fn the_geometric_median_at_the_baseline_is_35() {
        let at_most = |k: i32| 1.0 - (50.0f64 / 51.0).powi(k + 1);
        assert!((at_most(34) - 0.49997).abs() < 0.000_005, "{}", at_most(34));
        assert!((at_most(35) - 0.50978).abs() < 0.000_005, "{}", at_most(35));
        assert_eq!(geometric_median(50), 35);
        assert_eq!(geometric_median(0), 0);
        assert_eq!(geometric_median(1), 0, "P(0) = 1/2 at mean 1");
        for mean in [10u64, 50, 200, 1000] {
            let k = geometric_median(mean);
            let q = mean as f64 / (mean + 1) as f64;
            assert!(1.0 - q.powi(i32::try_from(k + 1).unwrap()) >= 0.5);
            assert!(k == 0 || 1.0 - q.powi(i32::try_from(k).unwrap()) < 0.5);
        }
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn an_empty_range_has_no_draw() {
        let _ = SplitMix64::seeded(1).below(0);
    }
}

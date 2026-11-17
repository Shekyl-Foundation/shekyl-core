// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sim's deterministic generators.
//!
//! Two generators, three pinned uses, no `rand` crate. [`SplitMix64`] is
//! what the secret-draw evidence draws when a block is never built: a
//! dropout, a reveal lag, a seed, a hash. It also draws standard traffic:
//! each block's interval ([`block_interval`]) and each fee rung's arrivals
//! over it ([`rung_arrivals`]), keyed on the seed and the block's height.
//! [`PoissonTrace`] is the xorshift64* stream the fee instruments share for
//! Poisson traffic. Nothing the chain computes is drawn from either. A
//! production CSPRNG lives with the code that needs one.

use crate::rung_mix::FeePriority;

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

/// Spreads a [`HONEST_SEEDS`] member into standard traffic's key
/// ([`block_interval`], [`rung_arrivals`]).
const HONEST_TRAFFIC_SEED: u64 = 0x4F4E_E57C_0A11_7E57;

/// The declared seeds of standard traffic (§5.34, §5.35): each figure on it
/// is read at all three on demand, and the narration pins carry the first,
/// the canonical one.
pub(crate) const HONEST_SEEDS: [u64; 3] = [1, 2, 3];

/// Knuth's product underflows past a mean near 745 and would silently cap
/// samples. The assert fires before that.
const POISSON_MEAN_LIMIT: f64 = 700.0;

/// The largest mean one Knuth draw of standard traffic takes, under
/// [`POISSON_MEAN_LIMIT`]. A larger mean is split into equal chunks no
/// larger, each drawn and the draws summed: a sum of Poissons is Poisson,
/// so the draw stays exact at any demand (§5.35).
pub(crate) const POISSON_CHUNK_MEAN: f64 = 500.0;

/// The lane of a block's honest stream its interval draws from. Each fee
/// rung draws from its own lane after it ([`rung_lane`]).
const INTERVAL_LANE: u64 = 0;

/// SplitMix64 over a `u64` state. The secret-draw stream.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    /// The generator for run `seed`. Seeds are small integers; the multiply
    /// spreads them and the `+ 1` keeps seed 0 off the all-zero state.
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(seed.wrapping_mul(SEED_SPREAD).wrapping_add(1))
    }

    /// A uniform draw in `[0, 1)`: the top 53 bits of one word.
    #[allow(clippy::cast_precision_loss)]
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
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

/// One block's stream of standard traffic: lane `lane` of the block at
/// `height` under seed `seed`. A function of those three alone, so two
/// folds over the same heights draw the same traffic whatever else they
/// do, and in any order (a stuffed fold and its counterfactual, the threads
/// of a parallel map).
fn honest_stream(seed: u64, height: u64, lane: u64) -> SplitMix64 {
    let key = SplitMix64::seeded(HONEST_TRAFFIC_SEED ^ seed).next();
    let block = SplitMix64::seeded(key ^ height).next();
    SplitMix64::seeded(block ^ lane)
}

/// A fee rung's lane in a block's honest stream: one after the interval's
/// per rung, in [`FeePriority::ALL`]'s order.
const fn rung_lane(rung: FeePriority) -> u64 {
    INTERVAL_LANE
        + match rung {
            FeePriority::Economy => 1,
            FeePriority::Standard => 2,
            FeePriority::High => 3,
        }
}

/// The interval before the block at `height` under seed `seed`, in units
/// of the target spacing (`daa_target_seconds`): exponential with mean 1
/// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.35). Production's blocks come
/// as a Poisson process, so the time to the next one is memoryless.
///
/// Drawn by inversion, `−ln U` with `U` in `(0, 1]`, on `libm`'s `log`: the
/// same bits on every host.
pub(crate) fn block_interval(seed: u64, height: u64) -> f64 {
    let u = 1.0 - honest_stream(seed, height, INTERVAL_LANE).unit();
    -libm::log(u)
}

/// The transactions of rung `rung` that arrive before the block at
/// `height` under seed `seed`, when `mean` arrive on average over that
/// block's interval: Poisson with mean `mean` (§5.35). The caller passes
/// the rung's demand per target spacing times [`block_interval`].
///
/// A mean above [`POISSON_CHUNK_MEAN`] is drawn as equal chunks no larger,
/// summed. `libm`'s `exp` keeps the bits the same on every host.
pub(crate) fn rung_arrivals(seed: u64, height: u64, rung: FeePriority, mean: f64) -> u64 {
    if mean <= 0.0 {
        return 0;
    }
    let mut rng = honest_stream(seed, height, rung_lane(rung));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let chunks = (mean / POISSON_CHUNK_MEAN).ceil() as u64;
    #[allow(clippy::cast_precision_loss)]
    let chunk = mean / chunks as f64;
    (0..chunks)
        .map(|_| knuth_poisson(chunk, libm::exp, || rng.unit()))
        .sum()
}

/// Knuth's Poisson sampler at mean `mean`, from uniform draws in `[0, 1)`:
/// the count of draws whose running product stays above `e^−mean`, less
/// one. `exp` is the caller's, so each stream keeps its own pinned bits.
fn knuth_poisson(mean: f64, exp: impl Fn(f64) -> f64, mut unit: impl FnMut() -> f64) -> u64 {
    assert!(
        mean < POISSON_MEAN_LIMIT,
        "Knuth sampler underflows near mean 745"
    );
    if mean <= 0.0 {
        return 0;
    }
    let l = exp(-mean);
    let mut k = 0u64;
    let mut p = 1.0;
    loop {
        p *= unit();
        if p <= l {
            return k;
        }
        k += 1;
    }
}

/// The lower-middle median of standard traffic's per-block count at mean
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
        knuth_poisson(mean, f64::exp, || self.unit())
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

    /// Standard traffic's streams are pinned functions of the seed, the
    /// height and the lane. The values were computed from the definitions
    /// by an independent implementation, not copied out of a run: the
    /// interval to 1e-12 (its `log` is another library's), the counts
    /// exactly.
    #[test]
    fn the_standard_traffic_streams_are_pinned() {
        let intervals = [
            2.011_485_580_880_604_5,
            0.511_078_171_179_896_3,
            0.433_338_939_715_999_4,
            0.063_176_278_325_379_17,
        ];
        for (height, expected) in (0u64..).zip(intervals) {
            let got = block_interval(1, height);
            assert!((got - expected).abs() < 1e-12, "height {height}: {got}");
        }
        let standard: Vec<u64> = (0..6)
            .map(|h| rung_arrivals(1, h, FeePriority::Standard, 40.0))
            .collect();
        assert_eq!(standard, [35, 35, 62, 41, 44, 40]);
        let chunked: Vec<u64> = (0..3)
            .map(|h| rung_arrivals(1, h, FeePriority::High, 1_900.0))
            .collect();
        assert_eq!(chunked, [1_890, 1_896, 1_881], "four chunks of 475, summed");
    }

    /// The draw is keyed (the same block draws the same traffic, each seed
    /// and each rung its own), and a mean of zero offers nothing.
    #[test]
    fn standard_traffic_is_keyed_on_the_seed_the_height_and_the_rung() {
        assert_eq!(
            block_interval(1, 17).to_bits(),
            block_interval(1, 17).to_bits()
        );
        let at = |seed, h, rung| rung_arrivals(seed, h, rung, 50.0);
        assert_eq!(
            at(1, 17, FeePriority::Standard),
            at(1, 17, FeePriority::Standard)
        );
        assert_eq!(rung_arrivals(1, 17, FeePriority::Standard, 0.0), 0);
        assert!((0..64).any(|h| at(1, h, FeePriority::Standard) != at(2, h, FeePriority::Standard)));
        assert!((0..64).any(|h| at(1, h, FeePriority::Standard) != at(1, h, FeePriority::Economy)));
    }

    /// STD-1 (§5.35): the rungs' arrivals over one interval sum to the
    /// geometric count of §5.34. At a mean of 50 split 15/80/5, over
    /// 100 000 heights at each declared seed: the mean is within 1 % of
    /// 50, the median is 34 or 35 (the restated baseline's derivation),
    /// the interval's mean is within 1 % of the target spacing, and at
    /// seed 1 the share of blocks offered at most `k` follows
    /// `1 − (50/51)^(k+1)`.
    #[test]
    fn the_rungs_sum_to_the_geometric_count() {
        const BLOCKS: u64 = 100_000;
        let shares = [
            (FeePriority::Economy, 7.5),
            (FeePriority::Standard, 40.0),
            (FeePriority::High, 2.5),
        ];
        for seed in HONEST_SEEDS {
            let mut interval_sum = 0.0;
            let mut counts: Vec<u64> = (0..BLOCKS)
                .map(|h| {
                    let interval = block_interval(seed, h);
                    interval_sum += interval;
                    shares
                        .iter()
                        .map(|&(rung, demand)| rung_arrivals(seed, h, rung, demand * interval))
                        .sum()
                })
                .collect();
            let mean = counts.iter().sum::<u64>() as f64 / BLOCKS as f64;
            assert!((mean - 50.0).abs() < 0.5, "seed {seed}: mean {mean}");
            let interval_mean = interval_sum / BLOCKS as f64;
            assert!(
                (interval_mean - 1.0).abs() < 0.01,
                "seed {seed}: interval {interval_mean}"
            );
            if seed == HONEST_SEEDS[0] {
                for k in [0u64, 34, 68] {
                    let at_most = counts.iter().filter(|&&c| c <= k).count() as f64 / BLOCKS as f64;
                    let expected =
                        1.0 - (50.0f64 / 51.0).powi(i32::try_from(k + 1).expect("small"));
                    assert!(
                        (at_most - expected).abs() < 0.005,
                        "P(count <= {k}) = {at_most}, geometric {expected}"
                    );
                }
            }
            counts.sort_unstable();
            let median = counts[usize::try_from(BLOCKS / 2 - 1).expect("small")];
            assert!(
                median == 34 || median == geometric_median(50),
                "seed {seed}: median {median}"
            );
        }
    }

    /// STD-1's chunked draw: a mean past Knuth's limit (the growth
    /// scenario's year 20 is about 1 900 a block) draws in chunks and stays
    /// exact, mean within 1 %; a mean at the chunk itself takes one draw.
    #[test]
    fn a_mean_past_the_limit_draws_in_chunks() {
        for mean in [POISSON_CHUNK_MEAN, POISSON_CHUNK_MEAN + 1.0, 1_900.0] {
            let blocks = 20_000u64;
            let total: u64 = (0..blocks)
                .map(|h| rung_arrivals(2, h, FeePriority::Standard, mean))
                .sum();
            let got = total as f64 / blocks as f64;
            assert!((got - mean).abs() < mean * 0.01, "mean {mean}: {got}");
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

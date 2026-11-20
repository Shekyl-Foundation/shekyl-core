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

/// The mean from which standard traffic's count is drawn by Hörmann's
/// transformed rejection ([`ptrs_poisson`]) instead of Knuth's product
/// ([`knuth_poisson`]). Knuth's costs one uniform draw per arrival, so it
/// cannot follow the growth schedule's demand (two million a block by its
/// sixtieth year); the rejection's cost does not grow with the mean.
/// Hörmann states his method for means of 10 and above (§5.35).
pub(crate) const PTRS_MEAN: f64 = 10.0;

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
/// A mean under [`PTRS_MEAN`] is drawn by Knuth's product, a larger one by
/// transformed rejection; both are exact. `libm`'s `exp` and `log` keep
/// the bits the same on every host.
pub(crate) fn rung_arrivals(seed: u64, height: u64, rung: FeePriority, mean: f64) -> u64 {
    if mean <= 0.0 {
        return 0;
    }
    let mut rng = honest_stream(seed, height, rung_lane(rung));
    if mean < PTRS_MEAN {
        knuth_poisson(mean, libm::exp, || rng.unit())
    } else {
        ptrs_poisson(mean, || rng.unit())
    }
}

/// Poisson at mean `mean` (at least [`PTRS_MEAN`]) by W. Hörmann's
/// transformed rejection with squeeze, PTRS ("The transformed rejection
/// method for generating Poisson random variables", Insurance: Mathematics
/// and Economics 12, 39–45, 1993), with his constants, in the order numpy's
/// `random_poisson_ptrs` evaluates them. A trial takes two uniform draws,
/// and a count takes 1.13 to 1.33 trials on average over the means from
/// 10 to 1 900. The squeeze ends about half the counts at a mean of 10 and
/// most of them at large means; the rest compare against the exact
/// log-probability, so the count is exactly Poisson. Every logarithm
/// is `libm`'s; `sqrt`, `floor` and `abs` are exact in IEEE arithmetic.
fn ptrs_poisson(mean: f64, mut unit: impl FnMut() -> f64) -> u64 {
    assert!(
        mean >= PTRS_MEAN,
        "PTRS is stated for means of 10 and above"
    );
    let root = mean.sqrt();
    let log_mean = libm::log(mean);
    let b = 0.931 + 2.53 * root;
    let a = -0.059 + 0.02483 * b;
    let inv_alpha = 1.1239 + 1.1328 / (b - 3.4);
    let v_r = 0.9277 - 3.6224 / (b - 2.0);
    loop {
        let u = unit() - 0.5;
        let v = unit();
        let us = 0.5 - u.abs();
        let k = ((2.0 * a / us + b) * u + mean + 0.43).floor();
        // A negative candidate is rejected before it is ever returned; the
        // squeeze cannot produce one at these means (its least `k` at mean
        // 10 is 4), and the cast below asserts it.
        if us >= 0.07 && v <= v_r {
            return count(k);
        }
        if k < 0.0 || (us < 0.013 && v > us) {
            continue;
        }
        if libm::log(v) + libm::log(inv_alpha) - libm::log(a / (us * us) + b)
            <= -mean + k * log_mean - ln_factorial(count(k))
        {
            return count(k);
        }
    }
}

/// A sampler's candidate as a count: a whole, non-negative `f64` below
/// 2^53, so the conversion is exact.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn count(k: f64) -> u64 {
    assert!(
        (0.0..9_007_199_254_740_992.0).contains(&k),
        "a Poisson count is a non-negative whole number: {k}"
    );
    k as u64
}

/// The Stirling-series coefficients of `ln Γ`, from S. Zhang and J. Jin,
/// "Computation of Special Functions" (Wiley, 1996), as numpy's
/// `random_loggam` carries them.
const LOG_GAMMA_SERIES: [f64; 10] = [
    8.333_333_333_333_333e-2,
    -2.777_777_777_777_778e-3,
    7.936_507_936_507_937e-4,
    -5.952_380_952_380_952e-4,
    8.417_508_417_508_418e-4,
    -1.917_526_917_526_918e-3,
    6.410_256_410_256_41e-3,
    -2.955_065_359_477_124e-2,
    1.796_443_723_688_307e-1,
    -1.392_432_216_905_90,
];

/// `ln(2π)`.
const LN_TWO_PI: f64 = 1.837_877_066_409_345_3;

/// The least argument the series is evaluated at; a smaller one is reached
/// by stepping down from here.
const LOG_GAMMA_SERIES_FROM: u64 = 7;

/// `ln k!`, as `ln Γ(k + 1)` by Zhang and Jin's series in numpy's order:
/// at `k + 1` when that is at least [`LOG_GAMMA_SERIES_FROM`], else at
/// [`LOG_GAMMA_SERIES_FROM`] and then down to `k + 1`, one `ln` a step. The
/// argument is a whole count, so the series' argument is a whole number
/// exactly; every `ln` is `libm`'s, so the bits are the same on every host.
#[allow(clippy::cast_precision_loss)]
fn ln_factorial(k: u64) -> f64 {
    if k <= 1 {
        return 0.0;
    }
    let x = k + 1;
    let steps = LOG_GAMMA_SERIES_FROM.saturating_sub(x);
    let mut x0 = (x + steps) as f64;
    let x2 = (1.0 / x0) * (1.0 / x0);
    let mut series = LOG_GAMMA_SERIES[9];
    for coefficient in LOG_GAMMA_SERIES[..9].iter().rev() {
        series *= x2;
        series += coefficient;
    }
    let mut gl = series / x0 + 0.5 * LN_TWO_PI + (x0 - 0.5) * libm::log(x0) - x0;
    for _ in 0..steps {
        gl -= libm::log(x0 - 1.0);
        x0 -= 1.0;
    }
    gl
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
        let at = |rung, mean, blocks: u64| -> Vec<u64> {
            (0..blocks)
                .map(|h| rung_arrivals(1, h, rung, mean))
                .collect()
        };
        let standard = FeePriority::Standard;
        assert_eq!(at(standard, 4.0, 6), [5, 0, 7, 3, 3, 1], "Knuth");
        assert_eq!(at(standard, 9.99, 6), [12, 4, 19, 10, 13, 8], "Knuth");
        assert_eq!(at(standard, 10.0, 6), [8, 12, 10, 9, 9, 10], "PTRS");
        assert_eq!(at(standard, 40.0, 6), [36, 28, 40, 37, 39, 40]);
        assert_eq!(at(FeePriority::High, 1_900.0, 3), [1_863, 1_849, 1_858]);
        assert_eq!(
            at(standard, 2_347_813.0, 3),
            [2_346_888, 2_344_864, 2_347_803],
            "the growth schedule's sixtieth year"
        );
    }

    /// The series against `ln k!` summed term by term, on both sides of
    /// [`LOG_GAMMA_SERIES_FROM`] and far past it.
    #[test]
    fn the_series_is_ln_factorial() {
        for k in [0u64, 1, 2, 3, 5, 6, 7, 9, 99, 10_000] {
            #[allow(clippy::cast_precision_loss)]
            let summed = (2..=k).map(|i| (i as f64).ln()).sum::<f64>();
            let got = ln_factorial(k);
            assert!(
                (got - summed).abs() <= 1e-12 * summed.max(1.0),
                "k {k}: {got} against {summed}"
            );
        }
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

    /// The draw is Poisson in shape, not only in mean, on both sides of
    /// [`PTRS_MEAN`]: over 200 000 heights at seed 2, every count's share
    /// is within five standard errors of the Poisson probability (plus
    /// 10^-4 for the far tail), and the variance is within 2 % of the mean.
    /// A wrong constant in the rejection's squeeze would bend the shape
    /// while the mean held.
    #[test]
    fn the_draw_is_poisson_on_both_sides_of_the_cutover() {
        const BLOCKS: u64 = 200_000;
        for mean in [9.99, PTRS_MEAN, 12.0, 40.0] {
            let draws: Vec<u64> = (0..BLOCKS)
                .map(|h| rung_arrivals(2, h, FeePriority::Standard, mean))
                .collect();
            let n = BLOCKS as f64;
            let average = draws.iter().sum::<u64>() as f64 / n;
            let variance = draws
                .iter()
                .map(|&d| (d as f64 - average).powi(2))
                .sum::<f64>()
                / n;
            assert!(
                (average - mean).abs() < mean * 0.01,
                "mean {mean}: {average}"
            );
            assert!(
                (variance - mean).abs() < mean * 0.02,
                "mean {mean}: var {variance}"
            );
            let top = draws.iter().copied().max().expect("draws");
            let mut probability = (-mean).exp();
            for k in 0..=top {
                if k > 0 {
                    probability *= mean / k as f64;
                }
                let share = draws.iter().filter(|&&d| d == k).count() as f64 / n;
                let error = (probability * (1.0 - probability) / n).sqrt();
                assert!(
                    (share - probability).abs() <= 5.0 * error + 1e-4,
                    "mean {mean}, count {k}: share {share}, Poisson {probability}"
                );
            }
        }
    }

    /// The rejection's cost does not grow with the mean: from the
    /// cutover to the growth schedule's sixtieth year (2.35 million a
    /// block), a count takes under three uniform draws on average, and the
    /// mean of the counts is within five standard errors of its target.
    #[test]
    fn the_rejection_costs_the_same_at_any_mean() {
        const COUNTS: u64 = 10_000;
        for mean in [PTRS_MEAN, 1_900.0, 2_347_813.0] {
            let mut rng = SplitMix64::seeded(5);
            let mut draws = 0u64;
            let total: u64 = (0..COUNTS)
                .map(|_| {
                    ptrs_poisson(mean, || {
                        draws += 1;
                        rng.unit()
                    })
                })
                .sum();
            let per_count = draws as f64 / COUNTS as f64;
            assert!(per_count < 3.0, "mean {mean}: {per_count} draws a count");
            let average = total as f64 / COUNTS as f64;
            let error = (mean / COUNTS as f64).sqrt();
            assert!(
                (average - mean).abs() < 5.0 * error,
                "mean {mean}: {average}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "non-negative whole number")]
    fn a_negative_candidate_is_never_a_count() {
        let _ = count(-1.0);
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

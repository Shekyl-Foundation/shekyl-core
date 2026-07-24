// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Geometric draws — the discrete memoryless delay, and the distribution the
//! Dandelion++ embargo derivation actually assumes.
//!
//! # Why this module exists
//!
//! The inherited daemon draws its stem embargo from
//! `crypto::random_poisson_seconds` (`tx_pool.cpp:1031`). The formula that
//! produced its constant —
//!
//! ```text
//! Tbase = (-k * (k - 1) * hop) / (2 * ln(1 - ep))
//! ```
//!
//! — is the Dandelion++ paper's appendix B.5 result, and the `ln(1 - ep)` term
//! is the giveaway: that shape comes from an **exponential** survival
//! function. The derivation models each node arming a memoryless timer and
//! asks how likely it is that none of `k` of them fires early.
//!
//! A Poisson is not that distribution. Poisson(λ) has standard deviation
//! `√λ`, so at λ = 39 the coefficient of variation is about 0.16 — draws
//! cluster tightly around the mean. An exponential with the same mean has a
//! coefficient of variation of 1.0. Feeding a Poisson into a formula derived
//! for an exponential does not produce the `ep` that was asked for, and the
//! error does not go in a safe direction in every regime (see
//! `tests/propagation_measurement.rs`).
//!
//! The geometric distribution is the exact discrete analogue of the
//! exponential — it is the only discrete distribution that is memoryless — and
//! the inherited timer already works in whole seconds, so nothing is lost by
//! discretizing. This module provides it with the same frozen integer
//! inverse-CDF construction [`crate::poisson`] uses.
//!
//! # Determinism
//!
//! Weights are `w_k = (1 - p)^k`, built by the recurrence
//! `w_0 = 1, w_k = w_{k-1} * (1 - p)`. Multiplication only — no `exp`, no
//! `pow`, no `ln` — so the table is bit-identical on every platform for the
//! same reason the Poisson table is.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Confined to table construction; the draw path is integer-only.

use crate::rng::RelayRng;

/// Relative-weight cutoff for truncating the geometric tail.
///
/// Looser than the Poisson table's `2^-70` because the geometric tail decays
/// far more slowly: holding the same cutoff would need a table an order of
/// magnitude longer. At `2^-40` the truncated mass is below one part in
/// `1.1e12`, immaterial for a relay timer.
const TAIL_CUTOFF: f64 = 1.0 / 1_099_511_627_776.0; // 2^-40

/// Hard bound on table length so construction terminates for any input.
///
/// At `2^-40` the table runs to roughly `27.7 * mean` entries, so this
/// supports means up to about 4,700 ticks — 1,175 s at the quarter-second tick
/// [`crate::schedule::EmbargoTimer`] uses, well past anything the parameter
/// sweep reaches. Worst-case allocation is 1 MiB, which is fine for a table
/// built once per timer.
const MAX_SUPPORT: usize = 131_072;

/// A geometric distribution as a frozen integer inverse-CDF, counting
/// failures before the first success.
///
/// The unit is a **tick**, not a second. The caller chooses the tick size, and
/// that choice matters more than it looks: see
/// [`crate::schedule::EmbargoTimer::geometric_with_tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeometricTable {
    thresholds: Vec<u64>,
    mean: u32,
    truncated: bool,
}

impl GeometricTable {
    /// Build the table for a given mean, in ticks.
    ///
    /// The success probability is `p = 1 / (mean + 1)`, which gives
    /// `E[X] = (1 - p) / p = mean`.
    ///
    /// # Panics
    ///
    /// Panics if `mean` is zero — a zero-mean memoryless delay is the constant
    /// `0`, which silently disables whatever it is delaying.
    #[must_use]
    pub fn new(mean: u32) -> Self {
        assert!(mean > 0, "geometric mean must be non-zero");
        let p = 1.0 / (f64::from(mean) + 1.0);
        let q = 1.0 - p;

        let mut weights: Vec<f64> = Vec::with_capacity(1024);
        let mut w = 1.0_f64;
        let mut truncated = true;
        weights.push(w);
        for _ in 1..MAX_SUPPORT {
            w *= q;
            weights.push(w);
            // The geometric is monotonically decreasing, so the first weight
            // under the cutoff is the tail — no shoulder to skip past.
            if w < TAIL_CUTOFF {
                truncated = false;
                break;
            }
        }

        let total: f64 = weights.iter().sum();
        let scale = 18_446_744_073_709_551_616.0_f64; // 2^64

        let mut thresholds = Vec::with_capacity(weights.len());
        let mut cumulative = 0.0_f64;
        for w in &weights {
            cumulative += *w;
            let scaled = (cumulative / total) * scale;
            let t = if scaled >= scale {
                u64::MAX
            } else {
                scaled as u64
            };
            thresholds.push(t);
        }
        if let Some(last) = thresholds.last_mut() {
            *last = u64::MAX;
        }

        Self {
            thresholds,
            mean,
            truncated,
        }
    }

    /// True if construction hit [`MAX_SUPPORT`] before the tail fell below the
    /// cutoff, so the upper tail is clipped more aggressively than intended.
    ///
    /// Exposed rather than silently tolerated: a clipped tail is a *shortened*
    /// embargo, which biases exactly the measurement this crate exists to
    /// make. `tests/propagation_measurement.rs` asserts it never fires.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Draw one geometric-distributed count. Pure integer.
    pub fn draw<R: RelayRng + ?Sized>(&self, rng: &mut R) -> u64 {
        let u = rng.next_u64();
        let k = self.thresholds.partition_point(|&t| t <= u);
        (k.min(self.thresholds.len() - 1)) as u64
    }

    /// The mean this table was built for.
    #[must_use]
    pub const fn mean(&self) -> u32 {
        self.mean
    }

    /// Largest count the table can produce.
    #[must_use]
    pub fn max_support(&self) -> u64 {
        (self.thresholds.len() - 1) as u64
    }

    /// Exact probability mass the table assigns to `k`, as a fraction of
    /// `2^64` — the quantized mass the draw actually realizes.
    #[must_use]
    pub fn quantized_mass(&self, k: u64) -> u64 {
        let Ok(idx) = usize::try_from(k) else {
            return 0;
        };
        if idx >= self.thresholds.len() {
            return 0;
        }
        let hi = self.thresholds[idx];
        let lo = if idx == 0 {
            0
        } else {
            self.thresholds[idx - 1]
        };
        hi.saturating_sub(lo)
    }

    /// Per-outcome quantized masses, indexed by `k`.
    #[must_use]
    pub fn masses(&self) -> Vec<u64> {
        (0..=self.max_support())
            .map(|k| self.quantized_mass(k))
            .collect()
    }

    /// FNV-1a fingerprint over the threshold table, for golden-vector pinning.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325_u64;
        for t in &self.thresholds {
            for b in t.to_le_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SplitMix64;

    #[test]
    fn thresholds_are_monotonic_and_total() {
        for mean in [1_u32, 5, 17, 39, 316] {
            let t = GeometricTable::new(mean);
            assert!(t.thresholds.windows(2).all(|w| w[0] <= w[1]));
            assert_eq!(*t.thresholds.last().unwrap(), u64::MAX);
        }
    }

    #[test]
    fn sample_mean_tracks_the_parameter() {
        for mean in [5_u32, 17, 39] {
            let t = GeometricTable::new(mean);
            let mut rng = SplitMix64::new(u64::from(mean) * 13 + 5);
            let n = 200_000_u64;
            let sum: u64 = (0..n).map(|_| t.draw(&mut rng)).sum();
            let observed = sum as f64 / n as f64;
            let expected = f64::from(mean);
            // Geometric variance is m(m+1); standard error of the mean is
            // sqrt(m(m+1)/n). Five sigma.
            let tol = 5.0 * (expected * (expected + 1.0) / n as f64).sqrt();
            assert!(
                (observed - expected).abs() < tol,
                "mean={mean}: observed {observed}, tolerance {tol}"
            );
        }
    }

    #[test]
    fn spread_is_far_wider_than_poisson_at_the_same_mean() {
        // This is the finding the module exists for, asserted rather than
        // claimed: a geometric has CV ~ 1, a Poisson at the same mean has
        // CV ~ 1/sqrt(mean).
        use crate::poisson::PoissonTable;
        let mean = 39_u32;
        let g = GeometricTable::new(mean);
        let p = PoissonTable::new(mean);
        let mut rng = SplitMix64::new(99);

        let n = 100_000;
        let gs: Vec<f64> = (0..n).map(|_| g.draw(&mut rng) as f64).collect();
        let ps: Vec<f64> = (0..n).map(|_| p.draw(&mut rng) as f64).collect();

        let sd = |v: &[f64]| {
            let m = v.iter().sum::<f64>() / v.len() as f64;
            (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
        };
        let g_cv = sd(&gs) / (gs.iter().sum::<f64>() / f64::from(n));
        let p_cv = sd(&ps) / (ps.iter().sum::<f64>() / f64::from(n));

        assert!(
            (0.9..1.1).contains(&g_cv),
            "geometric CV should be ~1, got {g_cv}"
        );
        assert!(
            (0.12..0.20).contains(&p_cv),
            "Poisson CV at mean 39 should be ~0.16, got {p_cv}"
        );
        assert!(
            g_cv > p_cv * 4.0,
            "geometric should be several times more dispersed: {g_cv} vs {p_cv}"
        );
    }

    #[test]
    fn memorylessness_holds_approximately() {
        // P(X >= a + b | X >= a) ~ P(X >= b). This is the property the
        // Dandelion++ derivation relies on and the Poisson does not have.
        let t = GeometricTable::new(20);
        let mut rng = SplitMix64::new(1234);
        let n = 400_000;
        let samples: Vec<u64> = (0..n).map(|_| t.draw(&mut rng)).collect();

        let ge = |v: u64| samples.iter().filter(|s| **s >= v).count() as f64 / f64::from(n);
        let conditional = ge(30) / ge(10);
        let unconditional = ge(20);
        assert!(
            (conditional - unconditional).abs() < 0.02,
            "memorylessness violated: P(>=30|>=10)={conditional}, P(>=20)={unconditional}"
        );
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_mean_is_rejected() {
        let table = GeometricTable::new(0);
        assert_eq!(table.mean(), 0, "unreachable: construction panics above");
    }
}

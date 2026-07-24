// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Poisson draws by frozen integer inverse-CDF, replacing
//! `std::poisson_distribution`.
//!
//! The inherited daemon draws its fluff-flush and stem-embargo delays from
//! `crypto::random_poisson_duration` (`src/crypto/duration.h`), a thin wrapper
//! over `std::poisson_distribution`. That distribution is
//! **implementation-defined**: the standard fixes the *distribution*, not the
//! *algorithm*, so libstdc++ and libc++ emit different sequences from
//! identical entropy. Three consequences follow, and they shaped this module:
//!
//! 1. No cross-language golden vector for the inherited timer is possible.
//!    A port cannot be validated by differential replay the way the consensus
//!    port is; only a *statistical* grade is available.
//! 2. Two Shekyl nodes built against different standard libraries already draw
//!    from different sequences today. That is harmless for a timing draw (it
//!    is node-local policy, not consensus) but it means "the C++ behaviour" is
//!    not a single well-defined thing to reproduce.
//! 3. The distribution is not a reviewable artifact anywhere in the C++ tree —
//!    it is whatever the toolchain shipped.
//!
//! This module makes it one. A [`PoissonTable`] is an inverse-CDF over `u64`:
//! the per-`k` cumulative mass is computed once as a table of thresholds, and
//! **every draw after that is pure integer** — one RNG word and a binary
//! search. The table is the distribution, and it can be printed, diffed, and
//! asserted on.
//!
//! # Cross-architecture determinism
//!
//! Table construction uses `f64`, but deliberately uses **no transcendental
//! function**: the weights are built by the recurrence `w_0 = 1`,
//! `w_k = w_{k-1} * λ / k`, and normalized by their own sum. Only `+`, `*`,
//! and `/` are involved, all of which IEEE-754 pins exactly. There is no
//! `exp()` and no `pow()`, so no libm variation can enter. The resulting table
//! is bit-identical on every platform, which is what makes the fingerprint
//! assertion in `tests/golden_vector.rs` a real gate rather than an x86 note.
//!
//! # Float honesty
//!
//! Unlike `shekyl-standoff`, this crate does **not** claim a float-free
//! default build. It does not need to: the consumer is the daemon's relay
//! timer, and relay timing is node-local policy that no consensus rule reads
//! (nodes running different delays do not fork). The property that is actually
//! load-bearing here — a reviewable, reproducible distribution — is delivered
//! by the no-transcendental recurrence above, not by banning floats. Draw-time
//! is integer regardless.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Table construction widens small integer counts to `f64` and narrows the
//   normalized cumulative mass back to a `u64` threshold. Both are confined to
//   `PoissonTable::new`; the draw path below is integer-only.

use crate::rng::RelayRng;

/// Relative-weight cutoff for truncating the upper tail of the table.
///
/// Terms below `2^-70` of the modal weight contribute less than one part in
/// `2^64` of the total mass, i.e. less than the quantization of a single `u64`
/// threshold. Truncating there is exact at the resolution the table can
/// represent at all.
const TAIL_CUTOFF: f64 = 1.0 / 1_180_591_620_717_411_303_424.0; // 2^-70

/// Hard bound on table length, so construction terminates for any input.
/// λ values in this crate are at most 39; the cap is three orders of magnitude
/// above anything reachable and exists only to make the loop total.
const MAX_SUPPORT: usize = 4096;

/// A Poisson distribution as a frozen integer inverse-CDF.
///
/// `thresholds[k]` is `floor(CDF(k) * 2^64)`, with the final entry forced to
/// `u64::MAX` so the top outcome absorbs the quantization remainder and every
/// RNG word maps to some `k`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoissonTable {
    thresholds: Vec<u64>,
}

impl PoissonTable {
    /// Build the inverse-CDF table for mean `lambda`.
    ///
    /// `lambda` is the distribution mean in whatever unit the caller is
    /// counting — this type is unit-agnostic on purpose, because the inherited
    /// code draws the fluff delay in quarter-seconds and the embargo in whole
    /// seconds from the same primitive. [`crate::schedule`] applies the units.
    ///
    /// # Panics
    ///
    /// Panics if `lambda` is zero. A zero-mean Poisson is the constant `0`,
    /// which is never a meaningful relay delay, and silently accepting it
    /// would turn a misconfiguration into a *disabled* jitter — exactly the
    /// failure this crate exists to make impossible to ship unnoticed.
    #[must_use]
    pub fn new(lambda: u32) -> Self {
        assert!(lambda > 0, "Poisson lambda must be non-zero");
        let lam = f64::from(lambda);

        // Unnormalized weights w_k = λ^k / k! by recurrence. No `exp`, no
        // `pow` — see the module docs on cross-architecture determinism.
        let mut weights: Vec<f64> = Vec::with_capacity(64);
        let mut w = 1.0_f64; // w_0
        let mut peak = w;
        weights.push(w);
        for k in 1..MAX_SUPPORT {
            w = w * lam / (k as f64);
            weights.push(w);
            if w > peak {
                peak = w;
            }
            // Only start testing the tail past the mode, or the rising
            // shoulder (which is genuinely tiny for large λ) would truncate
            // the distribution at k = 1.
            if f64::from(u32::try_from(k).unwrap_or(u32::MAX)) > lam && w < peak * TAIL_CUTOFF {
                break;
            }
        }

        let total: f64 = weights.iter().sum();
        let scale = 18_446_744_073_709_551_616.0_f64; // 2^64

        let mut thresholds = Vec::with_capacity(weights.len());
        let mut cumulative = 0.0_f64;
        for w in &weights {
            cumulative += *w;
            let frac = cumulative / total;
            let scaled = frac * scale;
            // `frac` can reach exactly 1.0 on the final term, and `1.0 * 2^64`
            // is one past `u64::MAX`. Saturate rather than wrap.
            let t = if scaled >= scale {
                u64::MAX
            } else {
                scaled as u64
            };
            thresholds.push(t);
        }
        // Force the final entry so the draw is total over all `u64` inputs.
        if let Some(last) = thresholds.last_mut() {
            *last = u64::MAX;
        }

        Self { thresholds }
    }

    /// Draw one Poisson-distributed count. Pure integer: one RNG word and a
    /// binary search over the frozen thresholds.
    pub fn draw<R: RelayRng + ?Sized>(&self, rng: &mut R) -> u64 {
        let u = rng.next_u64();
        // Number of thresholds at or below `u` is the outcome `k`; the final
        // threshold is `u64::MAX`, so clamp to keep `k` inside the support.
        let k = self.thresholds.partition_point(|&t| t <= u);
        let last = self.thresholds.len() - 1;
        k.min(last) as u64
    }

    /// Largest count the table can produce.
    #[must_use]
    pub fn max_support(&self) -> u64 {
        (self.thresholds.len() - 1) as u64
    }

    /// Exact probability mass the table assigns to `k`, as a fraction of
    /// `2^64`. This is the *quantized* mass the draw actually realizes, not
    /// the ideal Poisson mass — asserting on this is asserting on shipped
    /// behaviour.
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

    /// FNV-1a fingerprint over the threshold table.
    ///
    /// The golden vector freezes this instead of 100+ lines of hex: any change
    /// to λ, to the recurrence, or to the truncation rule moves it loudly,
    /// while the table itself stays derived-in-code and reviewable.
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
        for lambda in [1_u32, 10, 20, 39, 100] {
            let t = PoissonTable::new(lambda);
            assert!(
                t.thresholds.windows(2).all(|w| w[0] <= w[1]),
                "λ={lambda}: thresholds not monotonic"
            );
            assert_eq!(
                *t.thresholds.last().unwrap(),
                u64::MAX,
                "λ={lambda}: table does not cover the full u64 domain"
            );
        }
    }

    #[test]
    fn support_brackets_the_mean() {
        for lambda in [1_u32, 10, 20, 39] {
            let t = PoissonTable::new(lambda);
            assert!(
                t.max_support() > u64::from(lambda),
                "λ={lambda}: support truncated at or below the mean"
            );
        }
    }

    #[test]
    fn sample_mean_tracks_lambda() {
        // Coarse check that the table is actually Poisson-shaped; the strict
        // grade is the chi-square in `conformance`.
        for lambda in [10_u32, 20, 39] {
            let t = PoissonTable::new(lambda);
            let mut rng = SplitMix64::new(u64::from(lambda) * 7 + 1);
            let n = 100_000;
            let sum: u64 = (0..n).map(|_| t.draw(&mut rng)).sum();
            let mean = sum as f64 / f64::from(n);
            let lam = f64::from(lambda);
            // Standard error of the mean is sqrt(λ/n); 5 sigma is generous.
            let tol = 5.0 * (lam / f64::from(n)).sqrt();
            assert!(
                (mean - lam).abs() < tol,
                "λ={lambda}: sample mean {mean} outside {tol} of λ"
            );
        }
    }

    #[test]
    fn quantized_mass_sums_to_the_full_domain() {
        let t = PoissonTable::new(20);
        let total: u128 = (0..=t.max_support())
            .map(|k| u128::from(t.quantized_mass(k)))
            .sum();
        assert_eq!(total, u128::from(u64::MAX));
    }

    #[test]
    fn table_is_reproducible() {
        assert_eq!(PoissonTable::new(39), PoissonTable::new(39));
        assert_ne!(
            PoissonTable::new(39).fingerprint(),
            PoissonTable::new(20).fingerprint()
        );
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_lambda_is_rejected() {
        let table = PoissonTable::new(0);
        assert_eq!(
            table.max_support(),
            0,
            "unreachable: construction panics above"
        );
    }
}

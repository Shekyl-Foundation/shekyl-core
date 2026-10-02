// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The witness-miss reading of a size ladder, and the ceiling it puts on the
//! shard length — the analysis `ARCHIVAL_SHARD_T_DERIVATION.md` §10.1 fixes.
//!
//! A fetch **misses** when it does not return the whole object within
//! [`DEADLINE`]: any outcome but success, or a success slower than the
//! deadline. The failure window ships against a per-attempt miss of
//! [`TARGET_MISS_PER_CENT`], so that is the rate a shard length has to stay
//! under.
//!
//! Three readings, in the order §10.1 lists them:
//!
//! 1. **The decision at one size, with no model** ([`decide`]): the miss
//!    rate's 95 % Wilson interval against the target.
//! 2. **The ceiling as a number** ([`fit`]): `t₇₀ = t_fixed + bytes / v` over
//!    the ladder, where `t₇₀` is the time by which 70 % of *all* attempts had
//!    completed, a miss counted as never completing. The model is rejected on
//!    §4.1a's thresholds, and is not fitted at all when a size's `t₇₀` is
//!    infinite.
//! 3. **Fixed against size-driven misses** ([`SizeReading`]): circuit
//!    failures apart from transfer failures. Only the second kind shrinks
//!    with the object.
//!
//! Everything reads the same [`Observation`]s through the same percentile
//! rule as the rest of the crate ([`crate::measure`]), so a number here and a
//! number from `pd-f2-diff` cannot come from two definitions.

use std::time::Duration;

use crate::measure::{nearest_rank, FailureKind, Observation};

/// The single-attempt deadline a witness read has (`U1a`).
pub const DEADLINE: Duration = Duration::from_secs(120);

/// The per-attempt read failure the failure window's floor targets were
/// calibrated on (`shekyl-economics-sim`, `mn_feasibility::default_sources`),
/// in per cent.
pub const TARGET_MISS_PER_CENT: u8 = 30;

/// The percentile of all attempts that has to complete inside the deadline
/// for the miss rate to stay at the target: its complement.
pub const GOVERNING_PERCENTILE: u8 = 100 - TARGET_MISS_PER_CENT;

/// The 5 % overshoot of the heaviest shard over `W` at `W = 3,000,000 B`
/// (§9.3): the ceiling is judged at `W + overshoot`, so it comes off the
/// fitted maximum.
pub const OVERSHOOT_BYTES: u32 = 149_400;

/// §4.1a's linearity threshold: the model is rejected when an interior
/// point's `t₇₀` lies further than this share **of its own value** from the
/// line through the ladder's two ends. Per cent.
pub const LINEARITY_TOLERANCE_PER_CENT: u8 = 15;

/// The two-sided 95 % normal quantile the Wilson interval is built on.
const Z_95: f64 = 1.959_963_984_540_054;

/// A count as a float. Counts here are observations in one arm of one run —
/// thousands — so the saturation is unreachable and exists only to make the
/// conversion total.
fn as_f64(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

/// One object size's attempts, classed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SizeReading {
    /// The object's length.
    pub bytes: u32,
    /// Attempts.
    pub n: usize,
    /// No exchange happened: the circuit or rendezvous was never there. A
    /// smaller object does not help these.
    pub circuit: usize,
    /// The exchange started and did not deliver in time: a timeout, a body
    /// cut short, or a success slower than [`DEADLINE`]. These shrink with
    /// the object.
    pub transfer: usize,
    /// A completed exchange the client refused. That is the apparatus, not
    /// the path; any count here voids the reading rather than informing it.
    pub refused: usize,
    /// The time by which [`GOVERNING_PERCENTILE`] per cent of all attempts had
    /// completed, or `None` when more than the target missed — the
    /// percentile is then a miss, which never completes.
    pub t_governing: Option<Duration>,
}

impl SizeReading {
    /// Class one size's observations.
    #[must_use]
    pub fn of(bytes: u32, observations: &[Observation]) -> Self {
        let mut circuit = 0;
        let mut transfer = 0;
        let mut refused = 0;
        // A miss sorts after every completion, so the percentile below reads
        // it as "never".
        let mut completion: Vec<Duration> = Vec::with_capacity(observations.len());
        for observation in observations {
            let missed = match observation.failure {
                Some(FailureKind::Circuit) => {
                    circuit += 1;
                    true
                }
                Some(FailureKind::Timeout | FailureKind::Truncated) => {
                    transfer += 1;
                    true
                }
                Some(FailureKind::Refused) => {
                    refused += 1;
                    true
                }
                None if observation.elapsed > DEADLINE => {
                    transfer += 1;
                    true
                }
                None => false,
            };
            completion.push(if missed {
                Duration::MAX
            } else {
                observation.elapsed
            });
        }
        completion.sort_unstable();
        let t_governing =
            nearest_rank(&completion, GOVERNING_PERCENTILE).filter(|t| *t != Duration::MAX);
        Self {
            bytes,
            n: observations.len(),
            circuit,
            transfer,
            refused,
            t_governing,
        }
    }

    /// Attempts that missed, of any kind.
    #[must_use]
    pub fn misses(&self) -> usize {
        self.circuit + self.transfer + self.refused
    }

    /// The miss rate, `0.0` for an empty reading.
    #[must_use]
    pub fn miss_rate(&self) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        as_f64(self.misses()) / as_f64(self.n)
    }

    /// The miss rate's 95 % Wilson interval; `None` for an empty reading.
    #[must_use]
    pub fn miss_interval(&self) -> Option<(f64, f64)> {
        wilson_95(self.misses(), self.n)
    }
}

/// The 95 % Wilson score interval of `k` in `n`; `None` when `n` is zero.
#[must_use]
pub fn wilson_95(k: usize, n: usize) -> Option<(f64, f64)> {
    if n == 0 {
        return None;
    }
    let n_f = as_f64(n);
    let p = as_f64(k) / n_f;
    let z2 = Z_95 * Z_95;
    let denom = 1.0 + z2 / n_f;
    let centre = (p + z2 / (2.0 * n_f)) / denom;
    let half = Z_95 * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt() / denom;
    Some((centre - half, centre + half))
}

/// §10.1 item 1: what one size's miss interval says about the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The whole interval is at or under the target: the length stands.
    Stands,
    /// The whole interval is over the target: the ceiling binds.
    Binds,
    /// The interval straddles the target: nothing is re-pinned.
    Inconclusive,
    /// No attempts, or a refused exchange among them: the apparatus did not
    /// produce a reading to decide on.
    NoReading,
}

/// Read one size's miss interval against [`TARGET_MISS_PER_CENT`].
#[must_use]
pub fn decide(reading: &SizeReading) -> Decision {
    let Some((low, high)) = reading.miss_interval() else {
        return Decision::NoReading;
    };
    if reading.refused > 0 {
        return Decision::NoReading;
    }
    let target = f64::from(TARGET_MISS_PER_CENT) / 100.0;
    if high <= target {
        Decision::Stands
    } else if low > target {
        Decision::Binds
    } else {
        Decision::Inconclusive
    }
}

/// Why a fitted model is not used.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rejection {
    /// The fitted fixed time is negative.
    NegativeFixedTime,
    /// The fitted rate is zero or negative: time does not grow with size.
    NoPositiveRate,
    /// An interior point lies off the line through the ladder's ends by this
    /// many per cent of its own value, past [`LINEARITY_TOLERANCE_PER_CENT`].
    NotLinear { off_per_cent: f64 },
}

/// §10.1 item 2: `t₇₀ = t_fixed + bytes / v` over the ladder.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fit {
    /// Fewer than three sizes, or two of the same size: no line to judge.
    TooFewSizes,
    /// A size missed more than the target, so its `t₇₀` is infinite. Item 1
    /// has then already answered and no model is fitted.
    Unbounded { bytes: u32 },
    /// The model fits and is rejected on §4.1a's thresholds: the transport
    /// does not decompose this way.
    Rejected {
        t_fixed_s: f64,
        bytes_per_s: f64,
        why: Rejection,
    },
    /// The model, and the largest shard length whose heaviest shard still
    /// completes inside the deadline at the governing percentile.
    Kept {
        t_fixed_s: f64,
        bytes_per_s: f64,
        /// The interior point's distance from the line through the ends, per
        /// cent of its own value.
        off_per_cent: f64,
        /// `v · (deadline − t_fixed) − overshoot`.
        w_max_bytes: f64,
        /// Whether `w_max_bytes` lies past the largest size measured, where
        /// it is an extrapolation and not a reading.
        extrapolated: bool,
    },
}

/// Fit the ladder. `readings` in any order; sorted by size here.
#[must_use]
pub fn fit(readings: &[SizeReading]) -> Fit {
    let mut by_size: Vec<&SizeReading> = readings.iter().collect();
    by_size.sort_unstable_by_key(|r| r.bytes);
    by_size.dedup_by_key(|r| r.bytes);
    if by_size.len() < 3 {
        return Fit::TooFewSizes;
    }
    let mut points: Vec<(f64, f64)> = Vec::with_capacity(by_size.len());
    for reading in &by_size {
        let Some(t) = reading.t_governing else {
            return Fit::Unbounded {
                bytes: reading.bytes,
            };
        };
        points.push((f64::from(reading.bytes), t.as_secs_f64()));
    }

    // Least squares of t on bytes.
    let count = as_f64(points.len());
    let mean_x = points.iter().map(|(x, _)| x).sum::<f64>() / count;
    let mean_y = points.iter().map(|(_, y)| y).sum::<f64>() / count;
    let sxx: f64 = points.iter().map(|(x, _)| (x - mean_x).powi(2)).sum();
    let sxy: f64 = points
        .iter()
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum();
    let slope = sxy / sxx;
    let t_fixed_s = mean_y - slope * mean_x;
    if slope <= 0.0 {
        return Fit::Rejected {
            t_fixed_s,
            bytes_per_s: 0.0,
            why: Rejection::NoPositiveRate,
        };
    }
    let bytes_per_s = 1.0 / slope;
    if t_fixed_s < 0.0 {
        return Fit::Rejected {
            t_fixed_s,
            bytes_per_s,
            why: Rejection::NegativeFixedTime,
        };
    }

    // Linearity: every interior point against the line through the two ends.
    let (x_low, y_low) = points[0];
    let (x_high, y_high) = points[points.len() - 1];
    let off_per_cent = points[1..points.len() - 1]
        .iter()
        .map(|(x, y)| {
            let on_line = y_low + (y_high - y_low) * (x - x_low) / (x_high - x_low);
            100.0 * (y - on_line).abs() / y
        })
        .fold(0.0_f64, f64::max);
    if off_per_cent > f64::from(LINEARITY_TOLERANCE_PER_CENT) {
        return Fit::Rejected {
            t_fixed_s,
            bytes_per_s,
            why: Rejection::NotLinear { off_per_cent },
        };
    }

    let w_max_bytes =
        bytes_per_s * (DEADLINE.as_secs_f64() - t_fixed_s) - f64::from(OVERSHOOT_BYTES);
    Fit::Kept {
        t_fixed_s,
        bytes_per_s,
        off_per_cent,
        w_max_bytes,
        extrapolated: w_max_bytes > x_high,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(secs: u64) -> Observation {
        Observation::success(Duration::from_secs(secs))
    }

    fn missed(kind: FailureKind) -> Observation {
        Observation::failure(Duration::from_secs(1), kind)
    }

    /// `n` attempts at one size, `misses` of them circuit failures, the rest
    /// completing in `secs`.
    fn reading(bytes: u32, n: usize, misses: usize, secs: u64) -> SizeReading {
        let mut observations: Vec<Observation> = (0..n - misses).map(|_| ok(secs)).collect();
        observations.extend((0..misses).map(|_| missed(FailureKind::Circuit)));
        SizeReading::of(bytes, &observations)
    }

    /// The interval is the textbook Wilson score interval, to four places,
    /// on the count the first governing reading produced.
    #[test]
    fn the_wilson_interval_matches_a_worked_value() {
        let (low, high) = wilson_95(13, 319).expect("non-empty");
        assert!((low - 0.0240).abs() < 5e-5, "low {low}");
        assert!((high - 0.0685).abs() < 5e-5, "high {high}");
        assert_eq!(wilson_95(0, 0), None);
        // Zero of n still has a non-degenerate upper bound.
        let (zero_low, zero_high) = wilson_95(0, 100).expect("non-empty");
        assert!(zero_low.abs() < 1e-12 && zero_high > 0.03 && zero_high < 0.04);
    }

    /// Each outcome lands in its class, and a success past the deadline is a
    /// transfer miss, not a completion.
    #[test]
    fn outcomes_are_classed_and_a_late_success_is_a_miss() {
        let observations = [
            ok(10),
            ok(120),
            ok(121),
            missed(FailureKind::Circuit),
            missed(FailureKind::Timeout),
            missed(FailureKind::Truncated),
            missed(FailureKind::Refused),
        ];
        let reading = SizeReading::of(1, &observations);
        assert_eq!(reading.n, 7);
        assert_eq!(reading.circuit, 1);
        assert_eq!(
            reading.transfer, 3,
            "timeout, truncated, and the 121 s success"
        );
        assert_eq!(reading.refused, 1);
        assert_eq!(reading.misses(), 5);
        assert_eq!(decide(&reading), Decision::NoReading, "a refusal voids it");
    }

    /// The governing percentile counts misses as never completing: at exactly
    /// the target's share of misses it is the slowest completion, and one
    /// more miss makes it infinite.
    #[test]
    fn the_governing_percentile_counts_a_miss_as_never() {
        // 10 attempts, 3 misses: rank ceil(70 * 10 / 100) = 7 is the last
        // of the seven completions.
        let mut observations: Vec<Observation> = (1..=7).map(ok).collect();
        observations.extend((0..3).map(|_| missed(FailureKind::Circuit)));
        assert_eq!(
            SizeReading::of(1, &observations).t_governing,
            Some(Duration::from_secs(7))
        );
        // 4 misses: rank 7 is a miss.
        let mut observations: Vec<Observation> = (1..=6).map(ok).collect();
        observations.extend((0..4).map(|_| missed(FailureKind::Timeout)));
        assert_eq!(SizeReading::of(1, &observations).t_governing, None);
    }

    /// The three verdicts, each from an interval on its own side of 0.30.
    #[test]
    fn the_decision_reads_the_interval_against_the_target() {
        assert_eq!(decide(&reading(1, 300, 12, 10)), Decision::Stands);
        assert_eq!(decide(&reading(1, 300, 150, 10)), Decision::Binds);
        // 90 of 300 is exactly 0.30: the interval straddles it.
        assert_eq!(decide(&reading(1, 300, 90, 10)), Decision::Inconclusive);
        assert_eq!(decide(&SizeReading::of(1, &[])), Decision::NoReading);
    }

    /// Points on an exact line give that line back, and the ceiling is
    /// `v · (120 − t_fixed) − overshoot`.
    #[test]
    fn an_exact_line_is_recovered_with_its_ceiling() {
        // t = 5 s + bytes / 250,000 B/s.
        let readings = [
            reading(1_000_000, 100, 0, 9),
            reading(2_000_000, 100, 0, 13),
            reading(4_000_000, 100, 0, 21),
        ];
        let Fit::Kept {
            t_fixed_s,
            bytes_per_s,
            off_per_cent,
            w_max_bytes,
            extrapolated,
        } = fit(&readings)
        else {
            panic!("an exact line is kept: {:?}", fit(&readings));
        };
        assert!((t_fixed_s - 5.0).abs() < 1e-9);
        assert!((bytes_per_s - 250_000.0).abs() < 1e-3);
        assert!(off_per_cent < 1e-9);
        assert!((w_max_bytes - (250_000.0 * 115.0 - 149_400.0)).abs() < 1e-3);
        assert!(extrapolated, "28.6 MB is past the 4 MB largest size");
    }

    /// The governing arm of the 2026-10-01 ladder reads as
    /// `ARCHIVAL_SHARD_T_DERIVATION.md` §10.5 records it. The numbers in that
    /// section were printed by this code from this file; a change to the
    /// percentile rule, the miss definition or the fit moves them, and this
    /// is where that shows.
    #[test]
    fn the_recorded_ladder_reads_as_the_record_says() {
        let file =
            include_str!("../../../docs/benchmarks/w2_ladder_interleaved_pow_on_20261001.tsv");
        let mut sizes: std::collections::BTreeMap<u32, Vec<Observation>> =
            std::collections::BTreeMap::new();
        for line in file
            .lines()
            .filter(|l| *l != crate::measure::ROW_HEADER && !l.is_empty())
        {
            let (arm, observation) = crate::measure::parse_row(line).expect("a row");
            let bytes = arm.strip_prefix("soak@").expect("a soak arm");
            sizes
                .entry(bytes.parse().expect("an object size"))
                .or_default()
                .push(observation);
        }
        let readings: Vec<SizeReading> = sizes
            .iter()
            .map(|(bytes, observations)| SizeReading::of(*bytes, observations))
            .collect();

        // (bytes, n, circuit, transfer), smallest object first.
        let classed: Vec<(u32, usize, usize, usize)> = readings
            .iter()
            .map(|r| (r.bytes, r.n, r.circuit, r.transfer))
            .collect();
        assert_eq!(
            classed,
            [
                (831_744, 318, 2, 2),
                (1_663_488, 318, 4, 5),
                (3_326_976, 319, 2, 11),
            ]
        );
        assert!(readings.iter().all(|r| r.refused == 0));

        let largest = readings.last().expect("three sizes");
        let (low, high) = largest.miss_interval().expect("non-empty");
        assert!((low - 0.0240).abs() < 5e-5 && (high - 0.0685).abs() < 5e-5);
        assert_eq!(decide(largest), Decision::Stands);

        let Fit::Kept {
            t_fixed_s,
            bytes_per_s,
            off_per_cent,
            w_max_bytes,
            extrapolated,
        } = fit(&readings)
        else {
            panic!("the model is kept: {:?}", fit(&readings));
        };
        assert!((t_fixed_s - 5.899).abs() < 5e-4, "t_fixed {t_fixed_s}");
        assert!((bytes_per_s - 400_358.0).abs() < 0.5, "v {bytes_per_s}");
        assert!((off_per_cent - 6.1).abs() < 0.05, "off {off_per_cent}");
        assert!(
            (w_max_bytes - 45_532_062.0).abs() < 0.5,
            "W_max {w_max_bytes}"
        );
        assert!(extrapolated);
    }

    /// Each rejection, and the two cases where no model is fitted.
    #[test]
    fn the_model_is_rejected_on_the_pre_registered_thresholds() {
        // The middle point 25 % of its own value above the line.
        let bent = [
            reading(1_000_000, 100, 0, 10),
            reading(2_000_000, 100, 0, 20),
            reading(3_000_000, 100, 0, 20),
        ];
        assert!(matches!(
            fit(&bent),
            Fit::Rejected {
                why: Rejection::NotLinear { off_per_cent },
                ..
            } if (off_per_cent - 25.0).abs() < 1e-9
        ));
        // Time falls with size.
        let falling = [
            reading(1_000_000, 100, 0, 30),
            reading(2_000_000, 100, 0, 20),
            reading(3_000_000, 100, 0, 10),
        ];
        assert!(matches!(
            fit(&falling),
            Fit::Rejected {
                why: Rejection::NoPositiveRate,
                ..
            }
        ));
        // A line that crosses zero time above zero bytes.
        let steep = [
            reading(1_000_000, 100, 0, 1),
            reading(2_000_000, 100, 0, 11),
            reading(3_000_000, 100, 0, 21),
        ];
        assert!(matches!(
            fit(&steep),
            Fit::Rejected {
                why: Rejection::NegativeFixedTime,
                ..
            }
        ));
        // More than the target missed at one size.
        let unbounded = [
            reading(1_000_000, 100, 0, 10),
            reading(2_000_000, 100, 31, 20),
            reading(3_000_000, 100, 0, 30),
        ];
        assert_eq!(fit(&unbounded), Fit::Unbounded { bytes: 2_000_000 });
        assert_eq!(fit(&unbounded[..2]), Fit::TooFewSizes);
    }
}

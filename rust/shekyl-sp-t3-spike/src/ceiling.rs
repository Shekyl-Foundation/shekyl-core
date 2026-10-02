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
//! An arm with no attempts, or with an exchange the client **refused**, is
//! the apparatus and not the path. It is a [`Void`], not a reading: there is
//! no [`SizeReading`] of it for the decision or the fit to be handed.
//!
//! Everything reads the same [`Observation`]s through the same percentile
//! rule as the rest of the crate ([`crate::measure`]), so a number here and a
//! number from `pd-f2-diff` cannot come from two definitions.

use std::collections::BTreeMap;
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

/// The heaviest shard at the provisional shard length: `W` plus its
/// overshoot. The object a witness's read is sized against.
pub const HEAVIEST_SHARD_BYTES: u32 = 3_149_400;
const _: () = assert!(
    HEAVIEST_SHARD_BYTES as u64 == shekyl_types::SHARD_LENGTH.to_raw() + OVERSHOOT_BYTES as u64
);

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

/// Why a size's observations are not a reading.
///
/// Both are the apparatus, not the path, so neither is a miss rate to judge
/// or a point to fit: a [`SizeReading`] of either cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Void {
    /// No attempts were made at this size.
    NoAttempts,
    /// A completed exchange the client refused — the identical 404, a
    /// malformed envelope, a countersignature that does not verify. None of
    /// that is Tor's doing, so its presence says the rig was wrong while it
    /// measured, and every other row of the arm with it.
    Refused {
        /// Refused exchanges.
        refused: usize,
        /// Of this many attempts.
        attempts: usize,
    },
}

impl std::fmt::Display for Void {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAttempts => f.write_str("no attempts"),
            Self::Refused { refused, attempts } => write!(
                f,
                "{refused} of {attempts} exchanges were refused by the client: the apparatus, not the path"
            ),
        }
    }
}

impl std::error::Error for Void {}

/// One object size's attempts, classed.
///
/// Built only by [`Self::of`], which refuses a [`Void`] arm: a value of this
/// type has at least one attempt and no refused exchange, so nothing that
/// takes one has to ask.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SizeReading {
    bytes: u32,
    n: usize,
    circuit: usize,
    transfer: usize,
    t_governing: Option<Duration>,
}

impl SizeReading {
    /// Class one size's observations.
    ///
    /// # Errors
    ///
    /// [`Void`] when there are no observations, or when any of them is a
    /// refused exchange.
    pub fn of(bytes: u32, observations: &[Observation]) -> Result<Self, Void> {
        if observations.is_empty() {
            return Err(Void::NoAttempts);
        }
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
        if refused > 0 {
            return Err(Void::Refused {
                refused,
                attempts: observations.len(),
            });
        }
        completion.sort_unstable();
        let t_governing =
            nearest_rank(&completion, GOVERNING_PERCENTILE).filter(|t| *t != Duration::MAX);
        Ok(Self {
            bytes,
            n: observations.len(),
            circuit,
            transfer,
            t_governing,
        })
    }

    /// The object's length.
    #[must_use]
    pub fn bytes(&self) -> u32 {
        self.bytes
    }

    /// Attempts; never zero.
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.n
    }

    /// No exchange happened: the circuit or rendezvous was never there. A
    /// smaller object does not help these.
    #[must_use]
    pub fn circuit_misses(&self) -> usize {
        self.circuit
    }

    /// The exchange started and did not deliver in time: a timeout, a body
    /// cut short, or a success slower than [`DEADLINE`]. These shrink with
    /// the object.
    #[must_use]
    pub fn transfer_misses(&self) -> usize {
        self.transfer
    }

    /// The time by which [`GOVERNING_PERCENTILE`] per cent of all attempts had
    /// completed, or `None` when more than the target missed — the
    /// percentile is then a miss, which never completes.
    #[must_use]
    pub fn t_governing(&self) -> Option<Duration> {
        self.t_governing
    }

    /// Attempts that missed, of either kind.
    #[must_use]
    pub fn misses(&self) -> usize {
        self.circuit + self.transfer
    }

    /// The miss rate.
    #[must_use]
    pub fn miss_rate(&self) -> f64 {
        as_f64(self.misses()) / as_f64(self.n)
    }

    /// The miss rate's 95 % Wilson interval.
    #[must_use]
    pub fn miss_interval(&self) -> (f64, f64) {
        wilson(self.misses(), self.n)
    }
}

/// The 95 % Wilson score interval of `k` in `n`; `None` when `n` is zero.
#[must_use]
pub fn wilson_95(k: usize, n: usize) -> Option<(f64, f64)> {
    (n > 0).then(|| wilson(k, n))
}

/// [`wilson_95`] for a non-zero `n`.
fn wilson(k: usize, n: usize) -> (f64, f64) {
    let n_f = as_f64(n);
    let p = as_f64(k) / n_f;
    let z2 = Z_95 * Z_95;
    let denom = 1.0 + z2 / n_f;
    let centre = (p + z2 / (2.0 * n_f)) / denom;
    let half = Z_95 * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt() / denom;
    (centre - half, centre + half)
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
}

/// Read one size's miss interval against [`TARGET_MISS_PER_CENT`].
#[must_use]
pub fn decide(reading: &SizeReading) -> Decision {
    let (low, high) = reading.miss_interval();
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

/// `t = t_fixed + bytes / v`, fitted over a size ladder and kept on §4.1a's
/// thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Line {
    /// The time that does not depend on the object's size, in seconds.
    pub t_fixed_s: f64,
    /// The rate the rest is paid at.
    pub bytes_per_s: f64,
    /// The furthest interior point's distance from the line through the
    /// ladder's ends, per cent of its own value.
    pub off_per_cent: f64,
}

impl Line {
    /// The fitted time for an object of `bytes`, in seconds.
    #[must_use]
    pub fn at(&self, bytes: u32) -> f64 {
        self.t_fixed_s + f64::from(bytes) / self.bytes_per_s
    }
}

/// Why a ladder gives no [`Line`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoLine {
    /// Fewer than three distinct sizes: no line to judge.
    TooFewSizes,
    /// The model fits and is rejected on §4.1a's thresholds: the transport
    /// does not decompose this way.
    Rejected {
        t_fixed_s: f64,
        bytes_per_s: f64,
        why: Rejection,
    },
}

/// Least squares of time on size, judged on §4.1a's thresholds. `points` in
/// any order; sorted by size here, and a repeated size counts once.
///
/// # Errors
///
/// [`NoLine`] when there are fewer than three sizes or the model is rejected.
pub fn line_through(points: &[(u32, Duration)]) -> Result<Line, NoLine> {
    let mut by_size: Vec<(u32, Duration)> = points.to_vec();
    by_size.sort_unstable_by_key(|(bytes, _)| *bytes);
    by_size.dedup_by_key(|(bytes, _)| *bytes);
    if by_size.len() < 3 {
        return Err(NoLine::TooFewSizes);
    }
    let points: Vec<(f64, f64)> = by_size
        .iter()
        .map(|(bytes, t)| (f64::from(*bytes), t.as_secs_f64()))
        .collect();

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
        return Err(NoLine::Rejected {
            t_fixed_s,
            bytes_per_s: 0.0,
            why: Rejection::NoPositiveRate,
        });
    }
    let bytes_per_s = 1.0 / slope;
    if t_fixed_s < 0.0 {
        return Err(NoLine::Rejected {
            t_fixed_s,
            bytes_per_s,
            why: Rejection::NegativeFixedTime,
        });
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
        return Err(NoLine::Rejected {
            t_fixed_s,
            bytes_per_s,
            why: Rejection::NotLinear { off_per_cent },
        });
    }
    Ok(Line {
        t_fixed_s,
        bytes_per_s,
        off_per_cent,
    })
}

/// §10.1 item 2: the governing percentile's line over the ladder, and the
/// ceiling it puts on the shard length.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fit {
    /// A size missed more than the target, so its `t₇₀` is infinite. Item 1
    /// has then already answered and no model is fitted.
    Unbounded { bytes: u32 },
    /// No line: too few sizes, or the model rejected.
    NoLine(NoLine),
    /// The model, and the largest shard length whose heaviest shard still
    /// completes inside the deadline at the governing percentile.
    Kept {
        line: Line,
        /// `v · (deadline − t_fixed) − overshoot`.
        w_max_bytes: f64,
        /// Whether `w_max_bytes` lies past the largest size measured, where
        /// it is an extrapolation and not a reading.
        extrapolated: bool,
    },
}

/// Fit the governing percentile over the ladder.
#[must_use]
pub fn fit(readings: &[SizeReading]) -> Fit {
    let mut points: Vec<(u32, Duration)> = Vec::with_capacity(readings.len());
    for reading in readings {
        let Some(t) = reading.t_governing else {
            return Fit::Unbounded {
                bytes: reading.bytes,
            };
        };
        points.push((reading.bytes, t));
    }
    let line = match line_through(&points) {
        Ok(line) => line,
        Err(no_line) => return Fit::NoLine(no_line),
    };
    let largest = points.iter().map(|(bytes, _)| *bytes).max().unwrap_or(0);
    let w_max_bytes =
        line.bytes_per_s * (DEADLINE.as_secs_f64() - line.t_fixed_s) - f64::from(OVERSHOOT_BYTES);
    Fit::Kept {
        line,
        w_max_bytes,
        extrapolated: w_max_bytes > f64::from(largest),
    }
}

/// §4.1a's per-percentile fit: the `p`th percentile of each size's
/// **completions** (every success, however slow — the crate's percentile
/// rule, [`crate::measure::summarize`]), as a line over the ladder.
///
/// # Errors
///
/// [`NoLine`] when fewer than three sizes have a completion, or the model is
/// rejected.
pub fn completion_line(sizes: &[(u32, &[Observation])], p: u8) -> Result<Line, NoLine> {
    let points: Vec<(u32, Duration)> = sizes
        .iter()
        .filter_map(|(bytes, observations)| {
            let mut completions: Vec<Duration> = observations
                .iter()
                .filter(|o| o.is_success())
                .map(|o| o.elapsed)
                .collect();
            completions.sort_unstable();
            nearest_rank(&completions, p).map(|t| (*bytes, t))
        })
        .collect();
    line_through(&points)
}

/// The part of `L`'s four blocks allotted to fetch-plus-retry: two blocks
/// (`ARCHIVAL_SHARD_FETCH.md`, `SF-D8`, "`L = 4` — why, and how it moves").
pub const FETCH_SPAN: Duration = Duration::from_secs(240);

/// `L`'s upper falsifier: fetch-plus-retry past six minutes means the retry
/// budget is too generous, and `L` must not grow to absorb it (same ruling).
pub const RETRY_CEILING: Duration = Duration::from_secs(360);

/// A read of one attempt and, while attempts miss, up to some number of
/// retries.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetriedRead {
    /// The share of reads in which every attempt missed, **if attempts were
    /// independent draws**. On a bad day they are not — circuit failures
    /// cluster inside a window — so this is a floor on the failure share,
    /// and nothing is calibrated on it.
    pub failure_rate: f64,
    /// The `p`th percentile of the reads that completed, from the first
    /// attempt's start; `None` when none did.
    pub completed_by: Option<Duration>,
}

fn as_u128(count: usize) -> u128 {
    u128::try_from(count).unwrap_or(u128::MAX)
}

/// What a witness's read looks like when a missed attempt is retried up to
/// `retries` times, on the attempts actually observed.
///
/// Exact, not sampled: every ordered `(retries + 1)`-tuple of observed
/// attempts is one read, each attempt drawn independently of the others. The
/// read is its first attempt that completes inside [`DEADLINE`], and takes
/// that attempt's time plus what the misses before it cost. A miss costs what
/// it took, capped at the deadline — a witness gives up there. If every
/// attempt misses, the read fails.
///
/// The tuples are counted, not listed: the misses before a completion
/// contribute only their total, so the totals are tallied once per count of
/// misses and each is paired with the completions.
///
/// `None` for no observations, or for more tuples than a `u128` counts.
#[must_use]
pub fn read_with_retries(observations: &[Observation], retries: u32, p: u8) -> Option<RetriedRead> {
    if observations.is_empty() {
        return None;
    }
    let completed = |o: &Observation| o.is_success() && o.elapsed <= DEADLINE;
    let mut completions: Vec<Duration> = observations
        .iter()
        .filter(|o| completed(o))
        .map(|o| o.elapsed)
        .collect();
    completions.sort_unstable();
    let spent_on_misses: Vec<Duration> = observations
        .iter()
        .filter(|o| !completed(o))
        .map(|o| o.elapsed.min(DEADLINE))
        .collect();
    let n = as_u128(observations.len());
    let attempts = retries.checked_add(1)?;
    n.checked_pow(attempts)?;

    // For each count of misses before the completion: every total those
    // misses can have cost with the number of ordered tuples that cost it,
    // and the weight of the attempts the read never took. One read per
    // untaken draw keeps every tuple the same weight.
    let mut layers: Vec<(Vec<(Duration, u128)>, u128)> = Vec::new();
    let mut spent: BTreeMap<Duration, u128> = BTreeMap::from([(Duration::ZERO, 1)]);
    for misses_first in 0..=retries {
        let untaken = n.pow(retries - misses_first);
        layers.push((spent.iter().map(|(t, w)| (*t, *w)).collect(), untaken));
        if misses_first < retries {
            let mut next: BTreeMap<Duration, u128> = BTreeMap::new();
            for (total, tuples) in &spent {
                for miss in &spent_on_misses {
                    *next.entry(*total + *miss).or_insert(0) += tuples;
                }
            }
            spent = next;
        }
    }
    let completed_by = |t: Duration| -> u128 {
        layers
            .iter()
            .map(|(spent, untaken)| {
                // Totals rise, so the first one past `t` ends the walk.
                spent
                    .iter()
                    .map_while(|(total, tuples)| {
                        let left = t.checked_sub(*total)?;
                        let done = completions.partition_point(|c| *c <= left);
                        Some(tuples * untaken * as_u128(done))
                    })
                    .sum::<u128>()
            })
            .sum()
    };

    // The crate's nearest rank, over counted reads: the smallest time by
    // which `ceil(p * reads / 100)` of the completed reads had completed. It
    // is an observed total, because the count only rises at one.
    let longest = longest_read(retries);
    let all_completed = completed_by(longest);
    let rank = (u128::from(p) * all_completed)
        .div_ceil(100)
        .clamp(1, all_completed.max(1));
    let nearest = (all_completed > 0).then(|| {
        let (mut low, mut high) = (0_u64, u64::try_from(longest.as_nanos()).unwrap_or(u64::MAX));
        while low < high {
            let middle = low + (high - low) / 2;
            if completed_by(Duration::from_nanos(middle)) >= rank {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        Duration::from_nanos(low)
    });
    let miss_share = as_f64(spent_on_misses.len()) / as_f64(observations.len());
    Some(RetriedRead {
        failure_rate: miss_share.powi(i32::try_from(attempts).unwrap_or(i32::MAX)),
        completed_by: nearest,
    })
}

/// The longest a read of one attempt and `retries` retries can take: every
/// attempt running to [`DEADLINE`]. No day's weather moves it, and neither
/// does a `P` that stalls each attempt on purpose.
#[must_use]
pub fn longest_read(retries: u32) -> Duration {
    DEADLINE.saturating_mul(retries.saturating_add(1))
}

/// `SF-D6`'s retry budget, read on one day's attempts at one size: the
/// largest retry count that satisfies both of
///
/// - the retried read completes inside [`FETCH_SPAN`] at p99 on those
///   attempts, and
/// - no read can run past [`RETRY_CEILING`] ([`longest_read`]).
///
/// The first is the measurement's. It does not bound the count by itself:
/// once fewer than 1 % of reads reach another attempt, more retries stop
/// moving the p99. The second is what bounds it, and it is arithmetic on the
/// deadline — so the budget cannot trip `L`'s upper falsifier on any day.
///
/// `None` when the observations give no retried read, or none completes.
#[must_use]
pub fn retry_budget(observations: &[Observation]) -> Option<u32> {
    let mut budget = None;
    for retries in 0.. {
        if longest_read(retries) > RETRY_CEILING {
            break;
        }
        match read_with_retries(observations, retries, 99)?.completed_by {
            Some(p99) if p99 <= FETCH_SPAN => budget = Some(retries),
            _ => break,
        }
    }
    budget
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
        SizeReading::of(bytes, &observations).expect("attempts, none refused")
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
        ];
        let reading = SizeReading::of(1, &observations).expect("a reading");
        assert_eq!(reading.n, 6);
        assert_eq!(reading.circuit, 1);
        assert_eq!(
            reading.transfer, 3,
            "timeout, truncated, and the 121 s success"
        );
        assert_eq!(reading.misses(), 4);
    }

    /// A void arm is not a reading: no attempts, or one refused exchange
    /// among any number of good ones. Nothing downstream can then judge it or
    /// fit it, because there is no value to hand over.
    #[test]
    fn a_void_arm_cannot_become_a_reading() {
        assert_eq!(SizeReading::of(1, &[]), Err(Void::NoAttempts));

        let mut observations: Vec<Observation> = (0..99).map(|_| ok(10)).collect();
        observations.push(missed(FailureKind::Refused));
        assert_eq!(
            SizeReading::of(1, &observations),
            Err(Void::Refused {
                refused: 1,
                attempts: 100
            })
        );
        // The same arm without the refusal is an ordinary reading, so it is
        // the refusal and nothing else that voided it.
        observations.pop();
        assert!(SizeReading::of(1, &observations).is_ok());
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
            SizeReading::of(1, &observations)
                .expect("a reading")
                .t_governing,
            Some(Duration::from_secs(7))
        );
        // 4 misses: rank 7 is a miss.
        let mut observations: Vec<Observation> = (1..=6).map(ok).collect();
        observations.extend((0..4).map(|_| missed(FailureKind::Timeout)));
        assert_eq!(
            SizeReading::of(1, &observations)
                .expect("a reading")
                .t_governing,
            None
        );
    }

    /// The three verdicts, each from an interval on its own side of 0.30.
    #[test]
    fn the_decision_reads_the_interval_against_the_target() {
        assert_eq!(decide(&reading(1, 300, 12, 10)), Decision::Stands);
        assert_eq!(decide(&reading(1, 300, 150, 10)), Decision::Binds);
        // 90 of 300 is exactly 0.30: the interval straddles it.
        assert_eq!(decide(&reading(1, 300, 90, 10)), Decision::Inconclusive);
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
            line,
            w_max_bytes,
            extrapolated,
        } = fit(&readings)
        else {
            panic!("an exact line is kept: {:?}", fit(&readings));
        };
        assert!((line.t_fixed_s - 5.0).abs() < 1e-9);
        assert!((line.bytes_per_s - 250_000.0).abs() < 1e-3);
        assert!(line.off_per_cent < 1e-9);
        assert!(
            (line.at(3_000_000) - 17.0).abs() < 1e-9,
            "5 s + 3 MB / 250 kB/s"
        );
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
            .map(|(bytes, observations)| {
                SizeReading::of(*bytes, observations).expect("no void arm in the record")
            })
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

        let largest = readings.last().expect("three sizes");
        let (low, high) = largest.miss_interval();
        assert!((low - 0.0240).abs() < 5e-5 && (high - 0.0685).abs() < 5e-5);
        assert_eq!(decide(largest), Decision::Stands);

        let Fit::Kept {
            line,
            w_max_bytes,
            extrapolated,
        } = fit(&readings)
        else {
            panic!("the model is kept: {:?}", fit(&readings));
        };
        assert!((line.t_fixed_s - 5.899).abs() < 5e-4, "{line:?}");
        assert!((line.bytes_per_s - 400_358.0).abs() < 0.5, "{line:?}");
        assert!((line.off_per_cent - 6.1).abs() < 0.05, "{line:?}");
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
            Fit::NoLine(NoLine::Rejected {
                why: Rejection::NotLinear { off_per_cent },
                ..
            }) if (off_per_cent - 25.0).abs() < 1e-9
        ));
        // Time falls with size.
        let falling = [
            reading(1_000_000, 100, 0, 30),
            reading(2_000_000, 100, 0, 20),
            reading(3_000_000, 100, 0, 10),
        ];
        assert!(matches!(
            fit(&falling),
            Fit::NoLine(NoLine::Rejected {
                why: Rejection::NoPositiveRate,
                ..
            })
        ));
        // A line that crosses zero time above zero bytes.
        let steep = [
            reading(1_000_000, 100, 0, 1),
            reading(2_000_000, 100, 0, 11),
            reading(3_000_000, 100, 0, 21),
        ];
        assert!(matches!(
            fit(&steep),
            Fit::NoLine(NoLine::Rejected {
                why: Rejection::NegativeFixedTime,
                ..
            })
        ));
        // More than the target missed at one size.
        let unbounded = [
            reading(1_000_000, 100, 0, 10),
            reading(2_000_000, 100, 31, 20),
            reading(3_000_000, 100, 0, 30),
        ];
        assert_eq!(fit(&unbounded), Fit::Unbounded { bytes: 2_000_000 });
        // Two sizes are not a ladder, whatever they read.
        assert_eq!(fit(&bent[..2]), Fit::NoLine(NoLine::TooFewSizes));
    }

    /// §4.1a's per-percentile fit reads completions only, by the crate's
    /// percentile rule, and gives the line they lie on.
    #[test]
    fn a_completion_percentile_is_fitted_over_the_ladder() {
        // Every completion at a size takes the same time, on
        // t = 5 s + bytes / 250,000 B/s; misses are not completions.
        let at = |secs: u64| -> Vec<Observation> {
            let mut observations: Vec<Observation> = (0..9).map(|_| ok(secs)).collect();
            observations.push(missed(FailureKind::Circuit));
            observations
        };
        let (small, middle, large) = (at(9), at(13), at(21));
        let sizes: [(u32, &[Observation]); 3] = [
            (1_000_000, &small),
            (2_000_000, &middle),
            (4_000_000, &large),
        ];
        let line = completion_line(&sizes, 99).expect("an exact line");
        assert!((line.t_fixed_s - 5.0).abs() < 1e-9 && (line.bytes_per_s - 250_000.0).abs() < 1e-3);
        assert_eq!(completion_line(&sizes[..2], 99), Err(NoLine::TooFewSizes));
    }

    /// One attempt and one retry, exact over every ordered pair: four
    /// attempts, two completing in 10 s and 20 s, one failing after 30 s and
    /// one "succeeding" at 200 s, which is a miss that cost the full deadline.
    #[test]
    fn a_retried_read_is_every_ordered_pair_of_attempts() {
        let observations = [
            ok(10),
            ok(20),
            Observation::failure(Duration::from_secs(30), FailureKind::Circuit),
            ok(200),
        ];
        // 16 pairs. First completes: 8 reads (10 x4, 20 x4). First misses and
        // the retry completes: 30+10, 30+20, 120+10, 120+20. Both miss: 4.
        let read = read_with_retries(&observations, 1, 100).expect("observations");
        assert!((read.failure_rate - 0.25).abs() < 1e-12);
        assert_eq!(read.completed_by, Some(Duration::from_secs(140)));
        // Median of the twelve completed reads: the sixth, a first-attempt 20.
        assert_eq!(
            read_with_retries(&observations, 1, 50)
                .expect("observations")
                .completed_by,
            Some(Duration::from_secs(20))
        );
        assert_eq!(read_with_retries(&[], 1, 50), None);
    }

    /// The counted read is the listed one. Every ordered tuple of attempts
    /// is walked here, one read each, and the percentile taken by the crate's
    /// rule over the list — for no retry, one, two and three, at every
    /// percentile, on attempts whose miss costs and completions all differ.
    #[test]
    fn a_counted_read_equals_the_read_listed_tuple_by_tuple() {
        let observations = [
            ok(7),
            ok(31),
            ok(64),
            ok(119),
            ok(121), // a success past the deadline: a miss costing 120
            Observation::failure(Duration::from_secs(13), FailureKind::Circuit),
            Observation::failure(Duration::from_secs(58), FailureKind::Truncated),
        ];
        let n = observations.len();
        for retries in 0..=3_u32 {
            let attempts = retries as usize + 1;
            let mut listed: Vec<Duration> = Vec::new();
            let mut failed = 0_usize;
            for tuple in 0..n.pow(retries + 1) {
                let mut spent = Duration::ZERO;
                let mut done = None;
                let mut rest = tuple;
                for _ in 0..attempts {
                    let o = &observations[rest % n];
                    rest /= n;
                    if o.is_success() && o.elapsed <= DEADLINE {
                        done = Some(spent + o.elapsed);
                        break;
                    }
                    spent += o.elapsed.min(DEADLINE);
                }
                match done {
                    Some(t) => listed.push(t),
                    None => failed += 1,
                }
            }
            listed.sort_unstable();
            for p in 0..=100_u8 {
                let read = read_with_retries(&observations, retries, p).expect("observations");
                assert_eq!(
                    read.completed_by,
                    nearest_rank(&listed, p),
                    "{retries} retries, p{p}"
                );
                let share = as_f64(failed) / as_f64(n.pow(retries + 1));
                assert!((read.failure_rate - share).abs() < 1e-12);
            }
        }
    }

    /// The budget is the larger of the counts the span admits, and never
    /// more than the ceiling admits whatever the day was like.
    #[test]
    fn the_retry_budget_is_bounded_by_the_ceiling_and_by_the_day() {
        // A clean day: every count fits the span, so the ceiling decides.
        // Three attempts of 120 s are six minutes; four are eight.
        assert_eq!(longest_read(2), RETRY_CEILING);
        assert!(longest_read(3) > RETRY_CEILING);
        let clean: Vec<Observation> = (0..20).map(|_| ok(10)).collect();
        assert_eq!(retry_budget(&clean), Some(2));

        // A day on which nine attempts in ten run to the deadline: a second
        // retry's p99 is past the span (120 + 120 + 100), a first's is not
        // (120 + 100), so the day decides.
        let mut bad: Vec<Observation> = vec![ok(100)];
        bad.extend((0..9).map(|_| ok(500)));
        let two = read_with_retries(&bad, 2, 99).expect("observations");
        assert_eq!(two.completed_by, Some(Duration::from_secs(340)));
        assert_eq!(retry_budget(&bad), Some(1));

        // Nothing completes: there is no read to budget for.
        let dead: Vec<Observation> = (0..5).map(|_| missed(FailureKind::Circuit)).collect();
        assert_eq!(retry_budget(&dead), None);
        assert_eq!(retry_budget(&[]), None);
    }

    /// The worse of the two PoW-off days reads as
    /// `ARCHIVAL_SHARD_T_DERIVATION.md` §10.6 records it for `L`: the
    /// per-byte span at the governing percentile and at the p99 of
    /// completions, and the read of one attempt and one retry.
    #[test]
    fn the_worse_day_reads_as_the_record_says_for_the_span() {
        let file = include_str!("../../../docs/benchmarks/w2_ladder_soak_pow_off_20260930.tsv");
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
            .map(|(bytes, observations)| {
                SizeReading::of(*bytes, observations).expect("no void arm in the record")
            })
            .collect();
        let largest = readings.last().expect("three sizes");
        assert_eq!((largest.attempts(), largest.misses()), (489, 98));
        assert_eq!(decide(largest), Decision::Stands);

        let Fit::Kept { line, .. } = fit(&readings) else {
            panic!("the model is kept: {:?}", fit(&readings));
        };
        assert!((line.t_fixed_s - 12.092).abs() < 5e-4, "{line:?}");
        assert!((line.bytes_per_s - 71_606.0).abs() < 0.5, "{line:?}");
        assert!((line.at(HEAVIEST_SHARD_BYTES) - 56.1).abs() < 0.05);

        let ladder: Vec<(u32, &[Observation])> = sizes
            .iter()
            .map(|(bytes, observations)| (*bytes, observations.as_slice()))
            .collect();
        let tail = completion_line(&ladder, 99).expect("the p99 line is kept");
        assert!((tail.t_fixed_s - 54.937).abs() < 5e-4, "{tail:?}");
        assert!((tail.bytes_per_s - 47_851.0).abs() < 0.5, "{tail:?}");
        assert!((tail.at(HEAVIEST_SHARD_BYTES) - 120.8).abs() < 0.05);

        let (_, at_largest) = ladder.last().expect("three sizes");
        let read = read_with_retries(at_largest, 1, 99).expect("observations");
        assert!((read.failure_rate - 0.0402).abs() < 5e-5, "{read:?}");
        let p99 = read.completed_by.expect("reads completed").as_secs_f64();
        assert!((p99 - 149.7).abs() < 0.05, "p99 {p99}");
        // Over two minutes and under six: neither arm of `L`'s falsifier.
        assert!(p99 > 120.0 && p99 < 360.0);

        // §10.7, `SF-D6`'s budget: a second retry completes inside the two
        // blocks at p99, and so would a third — the day does not bound the
        // count. The ceiling does, at two.
        let p99_at = |retries: u32| {
            read_with_retries(at_largest, retries, 99)
                .expect("observations")
                .completed_by
                .expect("reads completed")
                .as_secs_f64()
        };
        assert!((p99_at(2) - 190.4).abs() < 0.05, "{}", p99_at(2));
        assert!((p99_at(3) - 202.9).abs() < 0.05, "{}", p99_at(3));
        assert!(p99_at(3) < FETCH_SPAN.as_secs_f64());
        assert_eq!(retry_budget(at_largest), Some(2));
    }
}

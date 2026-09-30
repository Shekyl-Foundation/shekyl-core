// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two runs of one arm, compared — the PoW diff `ARCHIVAL_SHARD_T_DERIVATION.md`
//! §4.1a pre-registers.
//!
//! A difference between two runs is only a finding if it is larger than what
//! resampling the same runs produces. Each judged statistic's difference
//! (treatment − baseline) gets a bootstrap interval, and the interval is read
//! against an **equivalence margin fixed before the data**:
//!
//! | Interval | Verdict |
//! | --- | --- |
//! | entirely inside `±margin` | [`Verdict::Immaterial`] — any difference is smaller than the margin |
//! | entirely outside `±margin`, on one side | [`Verdict::Material`] |
//! | anything else | [`Verdict::Inconclusive`] — the runs cannot tell |
//!
//! A **control** comparison — two runs that differ in nothing but the day
//! they ran — can void a verdict: a statistic the control already finds
//! [`Verdict::Material`] moves with the day alone, so the same statistic's
//! treatment verdict is [`Verdict::Void`]. A control can void; it cannot
//! validate, because a quiet control on few observations is weak evidence
//! that the day did not matter.
//!
//! `p99` is reported and never judged: at the soak's ~470 observations per
//! object it rests on ~5 tail observations, and a bootstrap interval over five
//! values is not a statement about the tail.
//!
//! Everything here reads the same [`Observation`]s through the same
//! percentile rule ([`crate::measure`]) for both runs, so a difference can
//! only come from the observations.

use std::time::Duration;

use crate::measure::{nearest_rank, Observation};

/// Bootstrap resamples per judged statistic.
pub const RESAMPLES: usize = 2_000;

/// The seed every comparison's resampling starts from: the diff is a pure
/// function of its two files, so a re-run prints the same intervals.
const SEED: u64 = 0x5348_4B59_4C57_3250; // "SHKYLW2P"

/// The interval's two-sided coverage, per mille: the 2.5th and 97.5th
/// percentiles of the resampled differences.
const INTERVAL_TAIL_PER_MILLE: usize = 25;

/// Per mille of a whole.
const PER_MILLE: usize = 1_000;

/// The equivalence margin on the completion rate, in absolute terms: three
/// percentage points.
pub const COMPLETION_MARGIN: f64 = 0.03;

/// The equivalence margin on a latency percentile, as a fraction of the
/// baseline's value: ten per cent.
pub const LATENCY_MARGIN_FRACTION: f64 = 0.10;

/// A statistic the comparison judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statistic {
    /// Fetches that delivered a shard, over all attempts.
    Completion,
    /// Median success latency, in seconds.
    P50,
    /// 90th-percentile success latency, in seconds.
    P90,
}

impl Statistic {
    /// Every judged statistic, in report order.
    pub const JUDGED: [Self; 3] = [Self::Completion, Self::P50, Self::P90];

    /// The report's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::P50 => "p50 (s)",
            Self::P90 => "p90 (s)",
        }
    }

    /// Its value on an arm; `None` for a percentile of an arm with no
    /// successes, or for an empty arm.
    #[must_use]
    pub fn value(self, observations: &[Observation]) -> Option<f64> {
        match self {
            Self::Completion => completion(observations),
            Self::P50 => success_percentile(observations, 50),
            Self::P90 => success_percentile(observations, 90),
        }
    }

    /// The pre-registered margin around `baseline`.
    #[must_use]
    pub fn margin(self, baseline: f64) -> f64 {
        match self {
            Self::Completion => COMPLETION_MARGIN,
            Self::P50 | Self::P90 => baseline.abs() * LATENCY_MARGIN_FRACTION,
        }
    }
}

/// What an interval says about a difference (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The whole interval lies beyond the margin, on one side.
    Material,
    /// The whole interval lies inside the margin.
    Immaterial,
    /// The interval straddles a margin edge.
    Inconclusive,
    /// The control comparison found the same statistic material: the day
    /// alone moves it, so this comparison cannot attribute it.
    Void,
}

impl Verdict {
    /// Read an interval `[lo, hi]` of differences against `±margin`.
    #[must_use]
    pub fn of(interval: (f64, f64), margin: f64) -> Self {
        let (lo, hi) = interval;
        if lo >= -margin && hi <= margin {
            Self::Immaterial
        } else if lo > margin || hi < -margin {
            Self::Material
        } else {
            Self::Inconclusive
        }
    }

    /// This verdict, voided when the control found the statistic material.
    #[must_use]
    pub fn under_control(self, control: Option<Self>) -> Self {
        match control {
            Some(Self::Material) => Self::Void,
            _ => self,
        }
    }
}

/// One statistic, judged across two runs of one arm.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Judged {
    /// Which statistic.
    pub statistic: Statistic,
    /// Its value on the baseline run.
    pub baseline: f64,
    /// Its value on the treatment run.
    pub treatment: f64,
    /// The bootstrap interval of `treatment − baseline`.
    pub interval: (f64, f64),
    /// The interval read against the margin.
    pub verdict: Verdict,
}

impl Judged {
    /// `treatment − baseline`.
    #[must_use]
    pub fn delta(&self) -> f64 {
        self.treatment - self.baseline
    }
}

/// Judge `statistic` across `baseline` and `treatment`. `None` when the
/// statistic is undefined on either run, or on too many resamples to give an
/// interval (a percentile of resamples with no successes).
#[must_use]
pub fn judge(
    baseline: &[Observation],
    treatment: &[Observation],
    statistic: Statistic,
) -> Option<Judged> {
    let base = statistic.value(baseline)?;
    let treat = statistic.value(treatment)?;
    let interval = bootstrap_interval(baseline, treatment, statistic)?;
    Some(Judged {
        statistic,
        baseline: base,
        treatment: treat,
        interval,
        verdict: Verdict::of(interval, statistic.margin(base)),
    })
}

/// The `[2.5 %, 97.5 %]` interval of `treatment − baseline` over
/// [`RESAMPLES`] resamples of each run, with replacement. `None` unless the
/// statistic is defined on every resample.
fn bootstrap_interval(
    baseline: &[Observation],
    treatment: &[Observation],
    statistic: Statistic,
) -> Option<(f64, f64)> {
    let mut rng = SplitMix64(SEED ^ statistic as u64);
    let mut deltas = Vec::with_capacity(RESAMPLES);
    let mut base_draw = Vec::with_capacity(baseline.len());
    let mut treat_draw = Vec::with_capacity(treatment.len());
    for _ in 0..RESAMPLES {
        rng.resample(baseline, &mut base_draw);
        rng.resample(treatment, &mut treat_draw);
        let delta = statistic.value(&treat_draw)? - statistic.value(&base_draw)?;
        deltas.push(delta);
    }
    deltas.sort_by(f64::total_cmp);
    Some((
        at_per_mille(&deltas, INTERVAL_TAIL_PER_MILLE),
        at_per_mille(&deltas, PER_MILLE - INTERVAL_TAIL_PER_MILLE),
    ))
}

/// The value `per_mille / 1000` of the way through a sorted, non-empty
/// sample.
fn at_per_mille(sorted: &[f64], per_mille: usize) -> f64 {
    sorted[(sorted.len() - 1) * per_mille / PER_MILLE]
}

fn completion(observations: &[Observation]) -> Option<f64> {
    if observations.is_empty() {
        return None;
    }
    let successes = observations.iter().filter(|o| o.is_success()).count();
    Some(count_f64(successes) / count_f64(observations.len()))
}

fn success_percentile(observations: &[Observation], p: u8) -> Option<f64> {
    let mut successes: Vec<Duration> = observations
        .iter()
        .filter(|o| o.is_success())
        .map(|o| o.elapsed)
        .collect();
    successes.sort_unstable();
    nearest_rank(&successes, p).map(|d| d.as_secs_f64())
}

/// A count as `f64`. Counts here are observations in one run, far below
/// `2^52`, so the conversion is exact.
fn count_f64(n: usize) -> f64 {
    u32::try_from(n).map_or(f64::from(u32::MAX), f64::from)
}

/// SplitMix64 — a small, seedable generator, enough to resample with: the
/// comparison needs reproducibility, not cryptographic quality.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// An index below `n` (`n > 0`). The modulo bias is below `n / 2^64`.
    fn below(&mut self, n: usize) -> usize {
        let n64 = u64::try_from(n).unwrap_or(u64::MAX);
        usize::try_from(self.next() % n64).unwrap_or(0)
    }

    /// Fill `into` with `from.len()` draws from `from`, with replacement.
    fn resample(&mut self, from: &[Observation], into: &mut Vec<Observation>) {
        into.clear();
        for _ in 0..from.len() {
            into.push(from[self.below(from.len())]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measure::FailureKind;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    /// `n` successes spread evenly over `[lo, lo + span)` ms, plus `fail`
    /// circuit failures.
    fn arm(n: u64, lo: u64, span: u64, fail: u64) -> Vec<Observation> {
        let mut out: Vec<Observation> = (0..n)
            .map(|i| Observation::success(ms(lo + i * span / n)))
            .collect();
        out.extend((0..fail).map(|_| Observation::failure(ms(60_000), FailureKind::Circuit)));
        out
    }

    #[test]
    fn the_verdict_reads_the_interval_against_the_margin() {
        assert_eq!(Verdict::of((-0.5, 0.5), 1.0), Verdict::Immaterial);
        assert_eq!(Verdict::of((1.5, 3.0), 1.0), Verdict::Material);
        assert_eq!(Verdict::of((-3.0, -1.5), 1.0), Verdict::Material);
        assert_eq!(Verdict::of((0.5, 1.5), 1.0), Verdict::Inconclusive);
        assert_eq!(Verdict::of((-2.0, 2.0), 1.0), Verdict::Inconclusive);
    }

    #[test]
    fn a_material_control_voids_and_nothing_else_does() {
        for v in [
            Verdict::Material,
            Verdict::Immaterial,
            Verdict::Inconclusive,
        ] {
            assert_eq!(v.under_control(Some(Verdict::Material)), Verdict::Void);
            assert_eq!(v.under_control(Some(Verdict::Immaterial)), v);
            assert_eq!(v.under_control(Some(Verdict::Inconclusive)), v);
            assert_eq!(v.under_control(None), v);
        }
    }

    /// The same run on both sides has a zero difference and is never
    /// material. At the soak's size its interval can still reach a margin
    /// edge — resampling noise is about that wide at ~470 observations —
    /// so only a larger sample is required to read immaterial.
    #[test]
    fn the_same_run_twice_is_never_material_and_immaterial_when_large() {
        let soak_sized = arm(470, 8_000, 40_000, 40);
        let large = arm(3_000, 8_000, 40_000, 250);
        for statistic in Statistic::JUDGED {
            let judged = judge(&soak_sized, &soak_sized, statistic).expect("defined");
            assert!(judged.delta().abs() < f64::EPSILON, "{statistic:?}");
            assert_ne!(judged.verdict, Verdict::Material, "{statistic:?}");
            let judged = judge(&large, &large, statistic).expect("defined");
            assert_eq!(judged.verdict, Verdict::Immaterial, "{statistic:?}");
        }
    }

    #[test]
    fn a_doubled_latency_is_material_and_a_small_shift_is_not() {
        let base = arm(470, 8_000, 40_000, 40);
        let slow = arm(470, 16_000, 80_000, 40);
        for statistic in [Statistic::P50, Statistic::P90] {
            let judged = judge(&base, &slow, statistic).expect("defined");
            assert_eq!(judged.verdict, Verdict::Material, "{statistic:?}");
            assert!(judged.delta() > 0.0);
        }
        let nudged = arm(470, 8_100, 40_000, 40);
        let p50 = judge(&base, &nudged, Statistic::P50).expect("defined");
        assert_eq!(p50.verdict, Verdict::Immaterial, "one per cent of a p50");
    }

    #[test]
    fn a_completion_drop_past_the_margin_is_material() {
        let base = arm(470, 8_000, 40_000, 30);
        let lossy = arm(400, 8_000, 40_000, 100);
        let judged = judge(&base, &lossy, Statistic::Completion).expect("defined");
        assert_eq!(judged.verdict, Verdict::Material);
        assert!(judged.delta() < -COMPLETION_MARGIN);
    }

    #[test]
    fn the_intervals_are_reproducible() {
        let base = arm(200, 8_000, 40_000, 20);
        let treat = arm(200, 9_000, 42_000, 25);
        let first = judge(&base, &treat, Statistic::P90);
        assert_eq!(first, judge(&base, &treat, Statistic::P90));
    }

    #[test]
    fn a_run_with_no_successes_has_no_latency_verdict() {
        let dead = arm(0, 0, 1, 10);
        let live = arm(100, 8_000, 40_000, 0);
        assert!(judge(&live, &dead, Statistic::P50).is_none());
        assert!(judge(&live, &dead, Statistic::Completion).is_some());
    }
}

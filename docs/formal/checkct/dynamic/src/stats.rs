// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! dudect's statistic: Welch's t between the two classes' batch timings, on
//! the full sample and on the sample with its slowest tail removed (the
//! tail is where interrupts live). A constant-time operation stays under
//! the threshold however many samples are taken; a leaking one grows past
//! it with the square root of the sample, so a borderline `t` is settled by
//! growing the sample, never by re-running at the same size.

use core::fmt;

/// dudect's decision threshold on `|t|`.
pub const DUDECT_T_THRESHOLD: f64 = 4.5;

/// The share of each class's slowest samples dropped before the second t,
/// in percent (dudect crops the tail).
pub const TAIL_CROP_PERCENT: u32 = 1;

/// The share of each class's samples the cropped t keeps.
const TAIL_KEEP_SHARE: f64 = 1.0 - TAIL_CROP_PERCENT as f64 / 100.0;

/// Welch's t divides each class's variance by `n - 1`.
const WELCH_MIN_PER_CLASS: usize = 2;

/// The smallest sample per class that still leaves Welch's minimum after
/// the crop; any fewer would print a verdict computed from a NaN.
pub const MIN_SAMPLES_PER_CLASS: usize = 3;

/// How many of `n` samples the cropped t keeps.
const fn kept_after_crop(n: usize) -> usize {
    (n as f64 * TAIL_KEEP_SHARE) as usize
}

// The floor above is the least sample that survives the crop, not a guess.
const _: () = assert!(
    kept_after_crop(MIN_SAMPLES_PER_CLASS) >= WELCH_MIN_PER_CLASS
        && kept_after_crop(MIN_SAMPLES_PER_CLASS - 1) < WELCH_MIN_PER_CLASS
);

/// The two classes compared.
pub struct Comparison {
    pub t_full: f64,
    pub t_cropped: f64,
    pub mean_fixed: f64,
    pub mean_random: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Either t is past the threshold.
    ClassDifference,
    /// Both t are under it: no difference observed (never "constant time").
    NoDifferenceSeen,
    /// A class had no variance, so t is undefined.
    Undetermined,
}

impl Comparison {
    pub fn of(fixed: &[f64], random: &[f64]) -> Self {
        Comparison {
            t_full: welch_t(fixed, random),
            t_cropped: welch_t(&crop_tail(fixed), &crop_tail(random)),
            mean_fixed: mean(fixed),
            mean_random: mean(random),
        }
    }

    pub fn verdict(&self) -> Verdict {
        let past = |t: f64| t.abs() > DUDECT_T_THRESHOLD;
        if self.t_full.is_nan() || self.t_cropped.is_nan() {
            Verdict::Undetermined
        } else if past(self.t_full) || past(self.t_cropped) {
            Verdict::ClassDifference
        } else {
            Verdict::NoDifferenceSeen
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::ClassDifference => "CLASS DIFFERENCE",
            Verdict::NoDifferenceSeen => "no difference seen",
            Verdict::Undetermined => "undetermined (a class has no variance)",
        })
    }
}

fn mean(x: &[f64]) -> f64 {
    x.iter().sum::<f64>() / x.len() as f64
}

fn variance(x: &[f64], mean: f64) -> f64 {
    x.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / (x.len() as f64 - 1.0)
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let (mean_a, mean_b) = (mean(a), mean(b));
    let (var_a, var_b) = (variance(a, mean_a), variance(b, mean_b));
    (mean_a - mean_b) / (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt()
}

/// The sample without its slowest `TAIL_CROP_PERCENT`.
fn crop_tail(x: &[f64]) -> Vec<f64> {
    let mut sorted = x.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted.truncate(kept_after_crop(sorted.len()));
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ramp(n: usize, offset: f64) -> Vec<f64> {
        (0..n).map(|i| offset + (i % 10) as f64).collect()
    }

    #[test]
    fn equal_samples_show_no_difference() {
        let c = Comparison::of(&ramp(1000, 100.0), &ramp(1000, 100.0));
        assert_eq!(c.verdict(), Verdict::NoDifferenceSeen);
    }

    #[test]
    fn a_shifted_sample_crosses_the_threshold() {
        let c = Comparison::of(&ramp(1000, 100.0), &ramp(1000, 101.0));
        assert!(c.t_full < -DUDECT_T_THRESHOLD);
        assert_eq!(c.verdict(), Verdict::ClassDifference);
    }

    #[test]
    fn the_crop_removes_only_the_slow_tail() {
        let mut x = vec![1.0; 99];
        x.push(1e9);
        assert_eq!(crop_tail(&x), vec![1.0; 99]);
    }

    #[test]
    fn no_variance_is_undetermined_not_clear() {
        let flat = vec![5.0; MIN_SAMPLES_PER_CLASS];
        assert_eq!(
            Comparison::of(&flat, &flat).verdict(),
            Verdict::Undetermined
        );
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Goodness-of-fit grading / simulation is float math over sample counts.
//   Diagnostic-only and excluded from the default build.

use crate::params::DandelionParams;
use crate::rng::{bernoulli, RelayRng};
use crate::schedule::EmbargoTimer;

use super::stem::walk_stem;
use super::util::MAX_SIMULATED_HOPS;

/// Origin exposure to a whole-prefix supernode — reshape lever.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OriginExposure {
    pub retry_cap: u32,
    pub exposure_rate: f64,
}

/// Measure [`OriginExposure`] at a reshape `retry_cap`.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_origin_exposure<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    retry_cap: u32,
    trials: usize,
    rng: &mut R,
) -> OriginExposure {
    assert!(trials > 0, "need at least one trial");
    let hop_ms = u64::from(params.time_between_hop_ms);
    let q = u64::from(params.fluff_probability_pct);
    let return_ms = u64::from(params.fluff_return_ms);

    let mut exposed = 0_u64;
    for _ in 0..trials {
        // Stem length h (RD-4): geometric on {1,2,…}.
        let mut h = 1_u64;
        while !bernoulli(rng, q, 100) {
            h += 1;
            if h >= MAX_SIMULATED_HOPS as u64 {
                break;
            }
        }
        let window = h.saturating_mul(hop_ms).saturating_add(return_ms);

        let mut elapsed = 0_u64;
        let mut fires = 0_u32;
        loop {
            let interval = embargo.deadline(0, rng);
            if elapsed.saturating_add(interval) >= window {
                break;
            }
            elapsed = elapsed.saturating_add(interval);
            fires += 1;
            if fires > retry_cap {
                break;
            }
        }
        if fires > retry_cap {
            exposed += 1;
        }
    }

    OriginExposure {
        retry_cap,
        exposure_rate: exposed as f64 / trials as f64,
    }
}

/// The δ increment-form adopt-criterion (§13), measured end-to-end.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PrecisionIncrement {
    pub spy_fraction: f64,
    pub precision_c1: f64,
    pub precision_c1_c3: f64,
    pub delta: f64,
}

/// Measure [`PrecisionIncrement`] at spy fraction `f`, with optional reshape
/// `retry_cap`.
///
/// # Panics
///
/// Panics if `trials` is zero or `spy_fraction` is outside `(0, 1)`.
#[must_use]
pub fn simulate_precision_increment<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    spy_fraction: f64,
    retry_cap: u32,
    trials: usize,
    rng: &mut R,
) -> PrecisionIncrement {
    assert!(trials > 0, "need at least one trial");
    assert!(
        spy_fraction > 0.0 && spy_fraction < 1.0,
        "spy fraction must be in (0, 1)"
    );
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;
    let is_spy = |rng: &mut R| (rng.next_u64() as u32) < spy_threshold;

    let mut c1_correct = 0_u64;
    let mut joint_correct = 0_u64;

    for _ in 0..trials {
        let trace = walk_stem(params, embargo, rng);
        let disarm = trace.disarm_ms;

        let c1 = is_spy(rng);
        if c1 {
            c1_correct += 1;
        }

        let origin_fluffs = {
            let mut elapsed = 0_u64;
            let mut fires = 0_u32;
            loop {
                let interval = embargo.deadline(0, rng);
                if elapsed.saturating_add(interval) >= disarm {
                    break;
                }
                elapsed = elapsed.saturating_add(interval);
                fires += 1;
                if fires > retry_cap {
                    break;
                }
            }
            fires > retry_cap
        };
        let c3_origin = origin_fluffs && is_spy(rng);

        if c1 || c3_origin {
            joint_correct += 1;
        }
    }

    let n = trials as f64;
    let precision_c1 = c1_correct as f64 / n;
    let precision_c1_c3 = joint_correct as f64 / n;
    PrecisionIncrement {
        spy_fraction,
        precision_c1,
        precision_c1_c3,
        delta: precision_c1_c3 - precision_c1,
    }
}

/// Reshape's recovery-latency profile for a black-holed transaction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReshapeRecovery {
    pub retry_cap: u32,
    pub fluff_p50_s: f64,
    pub fluff_p90_s: f64,
    pub fluff_p99_s: f64,
    pub reshape_worst_p50_s: f64,
    pub reshape_worst_p90_s: f64,
    pub reshape_worst_p99_s: f64,
}

/// Measure [`ReshapeRecovery`] at a retry cap.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_reshape_recovery<R: RelayRng + ?Sized>(
    embargo: &EmbargoTimer,
    retry_cap: u32,
    trials: usize,
    rng: &mut R,
) -> ReshapeRecovery {
    assert!(trials > 0, "need at least one trial");
    let mut one_cycle: Vec<u64> = Vec::with_capacity(trials);
    let mut worst: Vec<u64> = Vec::with_capacity(trials);
    for _ in 0..trials {
        let e1 = embargo.deadline(0, rng);
        one_cycle.push(e1);
        let mut total = e1;
        for _ in 0..retry_cap {
            total = total.saturating_add(embargo.deadline(0, rng));
        }
        worst.push(total);
    }
    one_cycle.sort_unstable();
    worst.sort_unstable();
    let q = |v: &[u64], p: f64| -> f64 {
        let idx = (((v.len() as f64) * p) as usize).min(v.len() - 1);
        v[idx] as f64 / 1000.0
    };
    ReshapeRecovery {
        retry_cap,
        fluff_p50_s: q(&one_cycle, 0.50),
        fluff_p90_s: q(&one_cycle, 0.90),
        fluff_p99_s: q(&one_cycle, 0.99),
        reshape_worst_p50_s: q(&worst, 0.50),
        reshape_worst_p90_s: q(&worst, 0.90),
        reshape_worst_p99_s: q(&worst, 0.99),
    }
}

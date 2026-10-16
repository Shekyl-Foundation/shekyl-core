// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The secret per-block draw's analytic side, and the count rule's two
//! callers (ESR-11's record).
//!
//! ESR-11 (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.13 to
//! §5.15) simulated one settlement epoch of the serve-credit design: each
//! block's producer draws pairs from a seed only it knows, and a draw is
//! *issued* only when that seed is revealed. That loop is deleted
//! (2026-10-15, §5.22): ESR-13 ([`crate::secret_draw_production`]) runs the
//! same epoch under `Timing::esr11()`, on the same production rule and
//! selection, and the two agreed within seed noise on every cell. §5.14
//! reports that loop's run.
//!
//! What stays here, and ESR-13 calls:
//!
//! - **The count rule's callers.** [`count_at`] and [`capped_at`]: the
//!   shortfall net of what is in flight, and `draw_count` / `draw_target`
//!   of `shekyl-archival-retention` at the horizon, with no copy of the
//!   cap.
//! - **The evidence set's shape.** [`EVIDENCE_PAIRS`],
//!   [`EVIDENCE_DROPOUT_PERMILLE`], [`SEEDS`], and the bar
//!   ([`SHORT_BAR_PERMILLE`] at [`BAR_DROPOUT_PERMILLE`]).
//! - **The `(m, n)` re-check**, analytically: the read itself is not
//!   simulated; pass and miss enter through [`window_check`], the retry
//!   mixture ([`retry_row`]) and the clearing figures, rendered by
//!   [`render_window_figures`].

use serde::Serialize;

use shekyl_archival_retention::{
    draw_count, draw_horizon, draw_target, CHALLENGE_RESPONSE_BLOCKS, FAILURE_WINDOW_M,
    FAILURE_WINDOW_N, SETTLEMENT_EPOCH_BLOCKS,
};

use crate::mn_feasibility::{
    default_sources, false_slash_bound, max_holder_exposure, FeasibilityTargets, BOND_LIFE_EPOCHS,
};

/// Draws counted per pair at settlement, and the count a pair must reach to
/// be observed at all: the daemon's constant, in the width this module's
/// per-pair counts use.
pub const COUNTED_DRAWS: u8 = 3;
const _: () = assert!(COUNTED_DRAWS as usize == shekyl_types::archival::COUNTED_DRAWS);

/// The bar, in per-mille of pairs short of [`COUNTED_DRAWS`] at 10 %
/// dropout. PROVISIONAL (the brief's ruling 6); graded on the maximum over
/// seeds.
pub const SHORT_BAR_PERMILLE: f64 = 30.0;

/// The dropout the bar is stated at, in per-mille of blocks.
pub const BAR_DROPOUT_PERMILLE: u32 = 100;

/// The count rule's two inputs that the run derives: `u`, the visible
/// shortfall less what is in flight and never below zero, and the horizon.
/// Production's functions take `u`, not the raw shortfall.
fn rule_inputs(shortfall: u64, in_flight: u64, h: u64) -> (u64, u64) {
    (
        shortfall.saturating_sub(in_flight),
        draw_horizon(h, SETTLEMENT_EPOCH_BLOCKS, CHALLENGE_RESPONSE_BLOCKS),
    )
}

/// `count(h)` and the carry it leaves, from production's rule.
#[must_use]
pub fn count_at(pairs: u32, shortfall: u64, in_flight: u64, h: u64, carry: u32) -> (u64, u32) {
    let (u, horizon) = rule_inputs(shortfall, in_flight, h);
    draw_count(u64::from(pairs), u, horizon, SETTLEMENT_EPOCH_BLOCKS, carry)
        .expect("the epoch length and the horizon are both nonzero")
}

/// Whether the cap bound at these inputs: production's answer
/// ([`draw_target`]), which is `D·H + SEB·u > 9·D·H`. A target that lands
/// exactly on the cap is not capped. The sim keeps no copy of the cap.
#[must_use]
pub fn capped_at(pairs: u32, shortfall: u64, in_flight: u64, h: u64) -> bool {
    let (u, horizon) = rule_inputs(shortfall, in_flight, h);
    draw_target(u64::from(pairs), u, horizon, SETTLEMENT_EPOCH_BLOCKS)
        .expect("the epoch length and the horizon are both nonzero")
        .capped
}

/// Seeds per cell (§5.13).
pub const SEEDS: u64 = 8;

/// The `(m, n)` re-check at one observation rate (§5.13).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct WindowCheck {
    /// Per-read failure probability, from the feasibility module's sources.
    pub read_failure: f64,
    /// Probability an observed epoch settles Missed for an honest pair:
    /// fewer than 2 of the 3 counted reads passed.
    pub miss_given_observation: f64,
    /// Union bound on a false slash over the bond's life at production
    /// `(m, n)`, for one pair.
    pub false_slash_bound: f64,
    /// The same bound for an archiver holding the maximum number of shards.
    /// The feasibility module's budget is set on this axis, per archiver.
    pub false_slash_max_holder: f64,
    /// Whether the per-archiver exposure is inside the module's provisional
    /// budget.
    pub clears_floor: bool,
    /// Share of epochs that are observations: `1 − short`.
    pub observation_rate: f64,
    /// Epochs a pair that never serves takes to reach `m` misses.
    pub epochs_to_m_misses: f64,
}

/// Probability that fewer than 2 of 3 independent reads pass, at per-read
/// failure `x`.
#[must_use]
pub fn missed_two_of_three(x: f64) -> f64 {
    let x = x.clamp(0.0, 1.0);
    3.0 * x * x * (1.0 - x) + x * x * x
}

/// Re-check the production window at a short share, in per-mille.
#[must_use]
pub fn window_check(short_permille: f64) -> WindowCheck {
    let sources = default_sources();
    let read_failure = sources
        .p_attempt
        .clamp(0.0, 1.0)
        .powi(sources.attempts as i32);
    let q = missed_two_of_three(read_failure);
    let observation_rate = 1.0 - short_permille / 1000.0;
    let per_pair = false_slash_bound(FAILURE_WINDOW_M, FAILURE_WINDOW_N, q, BOND_LIFE_EPOCHS);
    let max_holder = max_holder_exposure(per_pair);
    WindowCheck {
        read_failure,
        miss_given_observation: q,
        false_slash_bound: per_pair,
        false_slash_max_holder: max_holder,
        clears_floor: max_holder <= FeasibilityTargets::operative_defaults().false_slash_target,
        observation_rate,
        epochs_to_m_misses: f64::from(FAILURE_WINDOW_M) / observation_rate,
    }
}

/// Reads the witness makes of one draw before abandoning it, spread across
/// `W₂`. Each is a whole read by the fetch caller's own rule, including its
/// stall retries inside one window, which the calibration does not credit.
pub const RETRY_ATTEMPTS: u32 = 3;

/// The correlations the retry table is printed at, from the calibration
/// (every failure common to all tries) to independent tries.
pub const RETRY_CORRELATIONS: [f64; 6] = [1.0, 0.5, 0.25, 0.10, 0.05, 0.0];

/// Probability a read fails after `attempts` tries, when a share
/// `correlation` of single-try failures is common to every try of that read
/// and the rest are independent.
///
/// `p · (ρ + (1 − ρ) · p^(a−1))`. At `ρ = 1` it is `p`, the feasibility
/// module's calibration, which credits one attempt. At `ρ = 0` it is `p^a`.
/// `ρ` is a parameter of this model, not a quantity a run observes: a
/// measurement observes the read failure itself (see
/// [`clearing_read_failure`]), and `ρ` is inferred from it.
#[must_use]
pub fn correlated_read_failure(p_attempt: f64, attempts: u32, correlation: f64) -> f64 {
    let p = p_attempt.clamp(0.0, 1.0);
    let rho = correlation.clamp(0.0, 1.0);
    let independent_rest = p.powi(attempts.saturating_sub(1) as i32);
    p * (rho + (1.0 - rho) * independent_rest)
}

/// The production window at one retry correlation.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RetryRow {
    pub attempts: u32,
    pub correlation: f64,
    pub read_failure: f64,
    pub miss_given_observation: f64,
    pub false_slash_bound: f64,
    pub false_slash_max_holder: f64,
    pub clears_floor: bool,
}

/// The production window with [`RETRY_ATTEMPTS`] tries per read at one
/// correlation, judged on the per-archiver axis.
#[must_use]
pub fn retry_row(correlation: f64) -> RetryRow {
    let read_failure =
        correlated_read_failure(default_sources().p_attempt, RETRY_ATTEMPTS, correlation);
    let q = missed_two_of_three(read_failure);
    let per_pair = false_slash_bound(FAILURE_WINDOW_M, FAILURE_WINDOW_N, q, BOND_LIFE_EPOCHS);
    let max_holder = max_holder_exposure(per_pair);
    RetryRow {
        attempts: RETRY_ATTEMPTS,
        correlation,
        read_failure,
        miss_given_observation: q,
        false_slash_bound: per_pair,
        false_slash_max_holder: max_holder,
        clears_floor: max_holder <= FeasibilityTargets::operative_defaults().false_slash_target,
    }
}

/// The window's verdict at a read failure `x`, whatever produced it.
fn clears_at_read_failure(x: f64) -> bool {
    let q = missed_two_of_three(x);
    let per_pair = false_slash_bound(FAILURE_WINDOW_M, FAILURE_WINDOW_N, q, BOND_LIFE_EPOCHS);
    max_holder_exposure(per_pair) <= FeasibilityTargets::operative_defaults().false_slash_target
}

/// The largest probability of a draw going unread, after every try, at
/// which the production window clears the per-archiver budget.
///
/// This is the boundary in the quantity a measurement reports directly, and
/// it assumes no model of how tries correlate. The exposure rises with the
/// read failure, so it is found by bisection.
#[must_use]
pub fn clearing_read_failure() -> f64 {
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..60 {
        let mid = 0.5 * (lo + hi);
        if clears_at_read_failure(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// The largest correlation at which the production window clears the
/// per-archiver budget with [`RETRY_ATTEMPTS`] tries, or `None` if it does
/// not clear even with independent tries. The exposure rises with the
/// correlation, so the boundary is found by bisection.
#[must_use]
pub fn clearing_correlation() -> Option<f64> {
    if !retry_row(0.0).clears_floor {
        return None;
    }
    if retry_row(1.0).clears_floor {
        return Some(1.0);
    }
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..60 {
        let mid = 0.5 * (lo + hi);
        if retry_row(mid).clears_floor {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(lo)
}

/// The pair counts the evidence set runs at: a genesis set of 4,096 pairs,
/// and maturity.
pub const EVIDENCE_PAIRS: [u32; 2] = [4_096, 324_000];

/// The dropouts the evidence set runs at, in per-mille.
pub const EVIDENCE_DROPOUT_PERMILLE: [u32; 3] = [0, 100, 300];

/// Render the `(m, n)` re-check, the retry mixture and the clearing figures
/// into `out`. No run reaches them: the function takes none.
///
/// # Errors
///
/// The sink's.
pub fn render_window_figures(out: &mut impl std::fmt::Write) -> std::fmt::Result {
    let w = window_check(0.0);
    writeln!(
        out,
        "(m, n) = ({FAILURE_WINDOW_M}, {FAILURE_WINDOW_N}): read failure x = {:.2}, \
         missed-observation q = 3x^2(1-x) + x^3 = {:.4}; the false-slash bound does not depend \
         on the observation rate",
        w.read_failure, w.miss_given_observation
    )?;
    writeln!(
        out,
        "false slash over the bond's life: {:.2e} per pair; {:.3} for an archiver at the maximum \
         holdings, against a per-archiver budget of {:.0e}: {}",
        w.false_slash_bound,
        w.false_slash_max_holder,
        FeasibilityTargets::operative_defaults().false_slash_target,
        if w.clears_floor { "clears" } else { "EXCEEDS" }
    )?;
    writeln!(
        out,
        "retries: {RETRY_ATTEMPTS} tries per read at per-try failure {:.2}; rho = share of failures \
         common to every try (1 = the calibration, one attempt credited)",
        w.read_failure
    )?;
    writeln!(
        out,
        "{:>6} {:>10} {:>10} {:>12} {:>14} {:>8}",
        "rho", "read fail", "q", "per pair", "per archiver", "budget"
    )?;
    for rho in RETRY_CORRELATIONS {
        let r = retry_row(rho);
        writeln!(
            out,
            "{:>6.2} {:>10.4} {:>10.5} {:>12.2e} {:>14.2e} {:>8}",
            r.correlation,
            r.read_failure,
            r.miss_given_observation,
            r.false_slash_bound,
            r.false_slash_max_holder,
            if r.clears_floor { "clears" } else { "EXCEEDS" }
        )?;
    }
    let x_star = clearing_read_failure();
    writeln!(
        out,
        "the window clears the per-archiver budget when a draw goes unread after every try with \
         probability <= {x_star:.4}; at per-try failure {:.2} that is: the later tries all fail, \
         given the first did, with probability <= {:.4}",
        w.read_failure,
        x_star / w.read_failure
    )?;
    match clearing_correlation() {
        Some(rho) => writeln!(
            out,
            "in the mixture model that is rho <= {rho:.4}; none of the three is measured"
        )?,
        None => writeln!(
            out,
            "the window does not clear the per-archiver budget even with independent tries"
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: u32 = 4_096;

    /// The cap flag is production's own answer at the run's inputs. It
    /// does not take the block's carry: that carry can add a draw, and the
    /// added draw is not the cap.
    #[test]
    fn the_cap_flag_is_productions() {
        assert!(
            !capped_at(D, 0, 0, 0),
            "an empty shortfall is under the cap"
        );
        assert!(capped_at(D, u64::MAX, 0, 0));
    }

    #[test]
    fn the_missed_observation_rate_is_the_two_of_three_tail() {
        assert!((missed_two_of_three(0.30) - 0.216).abs() < 1e-12);
        assert!(missed_two_of_three(0.0).abs() < 1e-12);
        assert!((missed_two_of_three(1.0) - 1.0).abs() < 1e-12);
        let w = window_check(25.0);
        assert!((w.observation_rate - 0.975).abs() < 1e-12);
        assert!(
            (w.epochs_to_m_misses - f64::from(FAILURE_WINDOW_M) / 0.975).abs() < 1e-9,
            "a non-serving pair needs m observed epochs"
        );
        // The bound is priced at one observation per epoch, so it is the
        // same at every observation rate.
        assert!((w.false_slash_bound - window_check(0.0).false_slash_bound).abs() < f64::EPSILON);
    }

    #[test]
    fn a_fully_correlated_retry_is_one_attempt_and_an_independent_one_is_a_power() {
        let p = default_sources().p_attempt;
        // Every failure common to all tries: retries buy nothing, and the
        // row is the calibration's.
        assert!((correlated_read_failure(p, RETRY_ATTEMPTS, 1.0) - p).abs() < 1e-15);
        let calibrated = window_check(0.0);
        let row = retry_row(1.0);
        assert!((row.false_slash_bound - calibrated.false_slash_bound).abs() < 1e-18);
        assert_eq!(row.clears_floor, calibrated.clears_floor);
        // No failure common: three tries fail together at p cubed.
        assert!((correlated_read_failure(p, 3, 0.0) - p * p * p).abs() < 1e-15);
        assert!((correlated_read_failure(0.30, 3, 0.0) - 0.027).abs() < 1e-12);
        // One try is one try at any correlation.
        assert!((correlated_read_failure(p, 1, 0.0) - p).abs() < 1e-15);
        assert!((correlated_read_failure(p, 1, 0.4) - p).abs() < 1e-15);
        // Halfway is the mixture, not the midpoint of the exponents.
        assert!((correlated_read_failure(0.30, 3, 0.5) - 0.30 * (0.5 + 0.5 * 0.09)).abs() < 1e-12);
    }

    #[test]
    fn exposure_rises_with_the_correlation_and_the_boundary_separates_the_verdicts() {
        let mut last = -1.0_f64;
        for rho in [0.0, 0.05, 0.10, 0.25, 0.5, 1.0] {
            let r = retry_row(rho);
            assert!(
                r.false_slash_max_holder >= last,
                "exposure fell at rho = {rho}"
            );
            last = r.false_slash_max_holder;
        }
        // Where the boundary falls depends on the window and the read
        // failure, which are provisional. What holds for any of them: the
        // reported correlation clears, and none above it does.
        match clearing_correlation() {
            None => assert!(!retry_row(0.0).clears_floor),
            Some(rho) => {
                assert!(retry_row(rho).clears_floor);
                if rho < 1.0 {
                    assert!(!retry_row((rho + 1e-6).min(1.0)).clears_floor);
                }
            }
        }
    }

    #[test]
    fn the_boundary_is_one_read_failure_however_it_is_reached() {
        // The window reads only the probability that a draw goes unread. The
        // mixture's boundary and the model-free one are the same point.
        let x = clearing_read_failure();
        assert!(clears_at_read_failure(x));
        assert!(!clears_at_read_failure(x + 1e-9));
        let p = default_sources().p_attempt;
        if let Some(rho) = clearing_correlation().filter(|rho| *rho < 1.0) {
            assert!((correlated_read_failure(p, RETRY_ATTEMPTS, rho) - x).abs() < 1e-9);
            // What a run observes is the conditional rate, which is not rho:
            // it is rho plus the independent remainder.
            let conditional = x / p;
            assert!((conditional - (rho + (1.0 - rho) * p * p)).abs() < 1e-9);
            assert!(conditional > rho);
        }
        // Independent tries still fail together sometimes.
        assert!((correlated_read_failure(p, 3, 0.0) / p - p * p).abs() < 1e-15);
    }

    #[test]
    fn the_window_is_judged_per_archiver_not_per_pair() {
        let w = window_check(0.0);
        // The budget is per archiver. An archiver at the maximum holdings is
        // exposed on every pair it holds, so its exposure is above one
        // pair's and is what the verdict compares.
        assert!(w.false_slash_max_holder > w.false_slash_bound);
        // Just past the clearing boundary one pair's bound is still inside
        // the budget and the archiver's exposure is not. A verdict read on
        // the per-pair figure would clear there; this one does not. The
        // point is found from the window, so it moves with a re-pin instead
        // of pinning today's outcome.
        let budget = FeasibilityTargets::operative_defaults().false_slash_target;
        let x = clearing_read_failure() + 1e-6;
        let per_pair = false_slash_bound(
            FAILURE_WINDOW_M,
            FAILURE_WINDOW_N,
            missed_two_of_three(x),
            BOND_LIFE_EPOCHS,
        );
        assert!(per_pair <= budget);
        assert!(max_holder_exposure(per_pair) > budget);
        assert!(!clears_at_read_failure(x));
    }
}

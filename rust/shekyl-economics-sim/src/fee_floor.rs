// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! §11 of `docs/design/FEE_LADDER_DERIVATION.md` — the relay floor follows
//! `C`. The confirmation set for FL-E1…FL-E4, pre-registered in §11.5
//! before this file was first run.
//!
//! What is measured. Under FL-R20 the relay floor is the raw economy rate
//! `F(h) = R·C(h)·w_ref/M²` — unquantized, unrounded — and the wallet pays
//! exactly the served rung (FL-R22: no pad, no draw). Under FL-R23 a
//! transaction is admitted at height `h′` iff
//!
//! ```text
//! fee/byte ≥ min{ F(h′−k) : 0 ≤ k ≤ G }        (lookback-min, G = LOOKBACK_G)
//! ```
//!
//! with `h′` the RECEIVING node's tip, so a quote taken at `h` is admitted
//! by identity at every node whose tip is in `[h, h+G]`. What the lookback
//! COSTS is the grace it extends: admission may sit below the current floor
//! by `F(h′)/min_k F(h′−k) − 1`, which is exactly the floor's worst rise
//! over `G` blocks. So the whole question is the per-block slew of `C`, and
//! this module measures it two ways:
//!
//! - **`slew`** — `C` along Poisson-driven volume traces (stationary,
//!   720-block ramps, and INSTANTANEOUS steps, the worst case a linear ramp
//!   cannot show), on the operand production computes: each block's whole
//!   transaction count enters the fold's [`VolumeWindow`] and `C` is priced
//!   at the exact window ratio (FL-R24, the operand the validator reads).
//!   Reported: the worst rise and fall over 1–3 blocks, and the lookback's
//!   grace (`grace_bp_max`, `grace_bp_mean`) for each `G` in
//!   [`LOOKBACK_SWEEP`] (FL-E2, FL-E3, FL-E4).
//! - **`feedback`** — FL-C7's fee↔volume loop iterated through the served
//!   map (paid standard fee `4·F`), so the round can say whether putting
//!   the floor in the loop changes the convergence §4.5 recorded on raw
//!   `C` (FL-E1). Demand crosses from float to whole transactions once, at
//!   the scenario boundary ([`whole_transactions`], DQ-2G).
//!
//! §1.9 discipline: `C` comes from the owners through
//! [`fee_ladder::correction_factor_ratio`]. The floor formula's owner is
//! `shekyl_economics::relay_fee_floor`, and the daemon's
//! `get_current_fee_per_byte` calls it.
//!
//! [`floor_rate`] is NOT simply replaced by it, and the reason is the
//! instrument's subject rather than inertia: the owner returns atomic
//! units per byte, floored at 1, which at large `M` is a single digit —
//! so per-block RATIOS taken on it would be dominated by integer
//! truncation and would report quantization as slew. This function keeps
//! `SCALE` in the numerator and stays in `u128` precisely to measure
//! below that floor. What the sweep owes is a CROSS-CHECK that the two
//! agree once truncated (`the_floor_is_the_owners_at_scale_resolution`),
//! not a substitution.

use core::fmt::Write as _;

use serde::Serialize;
use shekyl_economics::params::TX_VOLUME_WINDOW;
use shekyl_economics::{
    base_block_reward, EconomicParams, TxVolume, BLOCKS_PER_YEAR, RELAY_FLOOR_LOOKBACK,
    RELAY_FLOOR_REFERENCE_TX_WEIGHT,
};

use crate::fee_bar::CONVERGED_AMPLITUDE_BP;
use crate::fee_ladder::{
    advance_traced_state, age_state, correction_factor_ratio, AgeState, FULL_REWARD_ZONE,
};
use crate::rng::PoissonTrace;
use crate::volume_window::VolumeWindow;

const VOLUME_WINDOW: u64 = TX_VOLUME_WINDOW;

/// FL-R23's lookback depth as re-derived at review A-1: the hot-session gap
/// (0–2 blocks) + the network height spread at relay (2) + one block of
/// slack. The identity the predicate delivers is per receiving node — a
/// quote at `h` is admitted by identity at every node whose tip is in
/// `[h, h+G]`.
pub const LOOKBACK_G: usize = RELAY_FLOOR_LOOKBACK;
/// FL-E4's sweep: the first draft's `G` = 3, the re-derived 5, and the
/// point between, so the grace curve — not the derivation alone — is on
/// record.
pub const LOOKBACK_SWEEP: [usize; 3] = [3, 4, 5];

/// Gaps, in blocks, over which the rise and fall of `F` are scored — the
/// span the lookback covers.
pub const GAPS: [usize; 3] = [1, 2, 3];

/// Lookback grace over each `G` in [`LOOKBACK_SWEEP`]: `(max, mean)` of
/// `F(t)/min_{k≤G} F(t−k) − 1` in basis points, ceiling ratio.
fn grace_sweep(floors: &[u128]) -> ([u64; 3], [u64; 3]) {
    let mut maxes = [0u64; 3];
    let mut means = [0u64; 3];
    for (i, &g) in LOOKBACK_SWEEP.iter().enumerate() {
        let (mut mx, mut sum, mut n) = (0u64, 0u128, 0u64);
        for t in g..floors.len() {
            let lo = floors[t - g..=t]
                .iter()
                .copied()
                .min()
                .expect("non-empty lookback");
            let bp = ((floors[t] * 10_000).div_ceil(lo.max(1)) - 10_000) as u64;
            mx = mx.max(bp);
            sum += u128::from(bp);
            n += 1;
        }
        maxes[i] = mx;
        means[i] = (sum / u128::from(n.max(1))) as u64;
    }
    (maxes, means)
}

/// The relay floor at `SCALE` resolution: `R·w_ref·C/M²` before the owner's
/// division by `SCALE` and its rounding to a whole atomic unit per byte,
/// with `M` floored at the penalty-free zone as the shipped floor does. A
/// declared instrument precision (§4 of the rebase document): the slew
/// this module measures is finer than a unit per byte. The pin
/// `the_floor_is_the_owners_at_scale_resolution` holds it to
/// [`shekyl_economics::relay_fee_floor`].
fn floor_rate(base_reward: u64, median: u64, c_scaled: u64) -> u128 {
    let m = u128::from(median.max(FULL_REWARD_ZONE));
    u128::from(base_reward) * u128::from(RELAY_FLOOR_REFERENCE_TX_WEIGHT) * u128::from(c_scaled)
        / (m * m)
}

/// `C` at the fold's window operand.
fn c_at(volume: TxVolume, ag: u64, height: u64, params: &EconomicParams) -> u64 {
    correction_factor_ratio(volume, ag, height, params).c_scaled
}

/// Volume traces for the slew set: `(label, mean_start, mean_end, step)`.
/// `step = true` switches the mean instantaneously at [`STEP_AT`]; `false`
/// ramps it linearly over one window. `v = 40` is
/// the low rail's edge, where `M_r` first unclamps; `v = 500` is the
/// sweep's top.
pub const SLEW_SCENARIOS: &[(&str, f64, f64, bool)] = &[
    ("stationary-v40", 40.0, 40.0, false),
    ("stationary-v50", 50.0, 50.0, false),
    ("stationary-v500", 500.0, 500.0, false),
    ("ramp-v50-to-v500", 50.0, 500.0, false),
    ("ramp-v500-to-v50", 500.0, 50.0, false),
    ("step-v40-to-v500", 40.0, 500.0, true),
    ("step-v50-to-v500", 50.0, 500.0, true),
    ("step-v500-to-v50", 500.0, 50.0, true),
];
const STEP_AT: u64 = 2_000;
const SLEW_BLOCKS: u64 = 20_000;

#[derive(Serialize, Clone)]
pub struct SlewResult {
    pub scenario: &'static str,
    pub age_years: u64,
    /// `max_t F(t+k)/F(t) − 1` for `k ∈ GAPS`, basis points (rise), ceiling
    /// ratio so a rise is never understated.
    pub rise_bp_max: [i64; 3],
    /// `min_t F(t+k)/F(t) − 1` for `k ∈ GAPS`, basis points (fall).
    pub fall_bp_max: [i64; 3],
    /// FL-R23's grace, `F(t)/min_{k≤G} F(t−k) − 1` in basis points — the
    /// most an admitted transaction may sit below the current floor, and
    /// the mean over the trace — for each `G` in [`LOOKBACK_SWEEP`]
    /// (FL-E4).
    pub grace_bp_max: [u64; 3],
    pub grace_bp_mean: [u64; 3],
    pub blocks_measured: u64,
    /// Blocks on which `C` changed at all.
    pub c_changes: u64,
    pub c_min: u64,
    pub c_max: u64,
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
fn slew_scenario(
    scenario: &'static str,
    mean_start: f64,
    mean_end: f64,
    step: bool,
    st: AgeState,
    params: &EconomicParams,
) -> SlewResult {
    // `PoissonTrace::trace` is a fixed stream, so every slew scenario sees
    // the same block sequence.
    let mut rng = PoissonTrace::trace();
    // The window production reads (CEN-F20), warmed with one full W.
    let mut window = VolumeWindow::default();
    for _ in 0..VOLUME_WINDOW {
        window.push(rng.poisson(mean_start));
    }
    let mut ag = st.ag;
    let mut floors: Vec<u128> = Vec::with_capacity(SLEW_BLOCKS as usize);
    let (mut c_min, mut c_max, mut c_changes) = (u64::MAX, 0u64, 0u64);
    let mut last_c: Option<u64> = None;
    for t in 0..SLEW_BLOCKS {
        // The block at `t` is priced at the window of the blocks before it,
        // then its own transactions join the fold.
        let volume = window.operand();
        let height = st.height + t;
        let base = base_block_reward(ag, params).expect("base along trace");
        let c = c_at(volume, ag, height, params);
        floors.push(floor_rate(base, FULL_REWARD_ZONE, c));
        c_min = c_min.min(c);
        c_max = c_max.max(c);
        if last_c.is_some_and(|p| p != c) {
            c_changes += 1;
        }
        last_c = Some(c);
        ag = advance_traced_state(ag, volume, params);

        let mean = if step {
            if t < STEP_AT {
                mean_start
            } else {
                mean_end
            }
        } else if (mean_end - mean_start).abs() < f64::EPSILON {
            mean_start
        } else {
            mean_start + (mean_end - mean_start) * (t as f64 / VOLUME_WINDOW as f64).min(1.0)
        };
        window.push(rng.poisson(mean));
    }

    let mut rise = [i64::MIN; 3];
    let mut fall = [i64::MAX; 3];
    let n = floors.len() - GAPS[GAPS.len() - 1];
    for t in 0..n {
        for (i, &k) in GAPS.iter().enumerate() {
            let bp = (floors[t + k] * 10_000).div_ceil(floors[t].max(1)) as i64 - 10_000;
            rise[i] = rise[i].max(bp);
            fall[i] = fall[i].min(bp);
        }
    }
    let (grace_max, grace_mean) = grace_sweep(&floors);
    SlewResult {
        scenario,
        age_years: st.height / BLOCKS_PER_YEAR,
        rise_bp_max: rise,
        fall_bp_max: fall,
        grace_bp_max: grace_max,
        grace_bp_mean: grace_mean,
        blocks_measured: n as u64,
        c_changes,
        c_min,
        c_max,
    }
}

#[derive(Serialize, Clone)]
pub struct FloorFeedbackResult {
    pub age_years: u64,
    pub median: u64,
    pub elasticity_milli: u64,
    pub demand_scale: u64,
    pub start_volume: u64,
    /// Paid-fee range over the 3 000-block tail and its amplitude.
    pub fee_tail_min: u128,
    pub fee_tail_max: u128,
    pub tail_amplitude_bp: u64,
    pub tail_transitions: u64,
    pub converged: bool,
    /// FL-R23 along the deterministic trace: the lookback grace, max and
    /// mean in basis points, per `G` in [`LOOKBACK_SWEEP`].
    pub grace_bp_max: [u64; 3],
    pub grace_bp_mean: [u64; 3],
}

/// The scenario layer's demand, a float, crossing into the chain's
/// integers: whole transactions for one block, rounded to nearest. The one
/// boundary in the two fee instruments' feedback loops (DQ-2G), named as
/// the integer-seams gate's one exception.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn whole_transactions(demand: f64) -> u64 {
    demand.max(0.0).round() as u64
}

/// FL-C7's loop under the FL-R20 served map. Deterministic demand
/// `D·(fee/f_ref)^−ε` through the real 720-block window, read as the
/// validator reads it ([`VolumeWindow`]); `f_ref` is the paid fee at the
/// trace's start state.
#[allow(clippy::cast_precision_loss)]
fn floor_feedback_scenario(
    eps_milli: u64,
    demand_scale: u64,
    start_volume: u64,
    st: AgeState,
    median: u64,
    params: &EconomicParams,
) -> FloorFeedbackResult {
    let paid_at = |volume: TxVolume, ag: u64, height: u64| -> (u128, u128) {
        let base = base_block_reward(ag, params).expect("base along trace");
        let c = c_at(volume, ag, height, params);
        let f = floor_rate(base, median, c);
        // Standard rung = 4·F, paid exactly (FL-R22).
        (4 * f, f)
    };
    // The window production reads (CEN-F20), warmed with one full W of the
    // start volume, so the trace's first operand is `start_volume · W`
    // over W blocks.
    let mut window = VolumeWindow::default();
    for _ in 0..VOLUME_WINDOW {
        window.push(start_volume);
    }
    let warm = window.operand();
    assert_eq!(
        warm,
        TxVolume::window(start_volume * VOLUME_WINDOW, VOLUME_WINDOW),
        "the warmed window is one full W"
    );
    let f_ref = paid_at(warm, st.ag, st.height).0;

    let eps = eps_milli as f64 / 1000.0;
    let blocks: u64 = 30_000;
    let tail: u64 = 3_000;
    let mut floors: Vec<u128> = Vec::with_capacity(blocks as usize);
    let (mut fee_min, mut fee_max) = (u128::MAX, 0u128);
    let mut tail_transitions = 0u64;
    let mut last_tail_fee: Option<u128> = None;
    let mut ag = st.ag;
    for t in 0..blocks {
        let volume = window.operand();
        let (fee, f) = paid_at(volume, ag, st.height + t);
        floors.push(f);
        ag = advance_traced_state(ag, volume, params);
        let demand = (demand_scale as f64) * (fee as f64 / f_ref.max(1) as f64).powf(-eps);
        window.push(whole_transactions(demand));
        if t >= blocks - tail {
            fee_min = fee_min.min(fee);
            fee_max = fee_max.max(fee);
            if last_tail_fee.is_some_and(|p| p != fee) {
                tail_transitions += 1;
            }
            last_tail_fee = Some(fee);
        }
    }
    let (grace_max, grace_mean) = grace_sweep(&floors);
    let amplitude_bp = (fee_max * 10_000 / fee_min.max(1) - 10_000) as u64;
    FloorFeedbackResult {
        age_years: st.height / BLOCKS_PER_YEAR,
        median,
        elasticity_milli: eps_milli,
        demand_scale,
        start_volume,
        fee_tail_min: fee_min,
        fee_tail_max: fee_max,
        tail_amplitude_bp: amplitude_bp,
        tail_transitions,
        converged: amplitude_bp <= CONVERGED_AMPLITUDE_BP,
        grace_bp_max: grace_max,
        grace_bp_mean: grace_mean,
    }
}

#[derive(Serialize)]
pub struct FeeFloorReport {
    pub lookback_g: usize,
    pub lookback_sweep: [usize; 3],
    pub converged_amplitude_bp: u64,
    pub slew: Vec<SlewResult>,
    pub feedback: Vec<FloorFeedbackResult>,
}

/// Run the §11 set: the §1.8 age grid × [`SLEW_SCENARIOS`], and FL-C7's
/// grid (medians, ε, demand scales, displaced starts).
pub fn report() -> FeeFloorReport {
    let params = EconomicParams::default();
    let zone = FULL_REWARD_ZONE;
    // The §1.8 age grid prices FL-E1's feedback cells. The slew traces run
    // on to the saturation plateau: from about year 80 the burn sits at its
    // cap and `C` at its structural maximum, so the roll-ups' worst case is
    // the chain's and not the grid's edge (`ECONOMICS_SIM_PHASE0.md` §P0.1).
    let feedback_ages: [u64; 5] = [0, 1, 4, 12, 30];
    let slew_ages: [u64; 7] = [0, 1, 4, 12, 30, 60, 80];
    let states: Vec<AgeState> = feedback_ages
        .iter()
        .map(|&a| age_state(a, &params))
        .collect();
    let slew_states: Vec<AgeState> = slew_ages.iter().map(|&a| age_state(a, &params)).collect();

    let mut slew = Vec::new();
    for &st in &slew_states {
        for &(label, m0, m1, step) in SLEW_SCENARIOS {
            slew.push(slew_scenario(label, m0, m1, step, st, &params));
        }
    }

    let mut feedback = Vec::new();
    for &st in &states {
        for &median in &[zone, 3 * zone, 10 * zone, 50 * zone] {
            for eps in [0u64, 500, 1000, 2000, 3000] {
                for demand_scale in [50u64, 100, 400] {
                    feedback.push(floor_feedback_scenario(
                        eps,
                        demand_scale,
                        demand_scale,
                        st,
                        median,
                        &params,
                    ));
                    // A displaced start probes convergence back to the
                    // fixed point, not just persistence at it.
                    feedback.push(floor_feedback_scenario(
                        eps,
                        demand_scale,
                        8 * demand_scale.min(1_250),
                        st,
                        median,
                        &params,
                    ));
                }
            }
        }
    }
    FeeFloorReport {
        lookback_g: LOOKBACK_G,
        lookback_sweep: LOOKBACK_SWEEP,
        converged_amplitude_bp: CONVERGED_AMPLITUDE_BP,
        slew,
        feedback,
    }
}

pub fn render_summary(r: &FeeFloorReport, out: &mut String) {
    let _ = writeln!(
        out,
        "fee-floor: lookback_g={} lookback_sweep={:?} gaps={:?} converged_amplitude_bp={}",
        r.lookback_g, r.lookback_sweep, GAPS, r.converged_amplitude_bp
    );
    for s in &r.slew {
        let _ = writeln!(
            out,
            "fee-floor: slew {} age={} rise_bp_max={:?} fall_bp_max={:?} grace_bp_max[G=3,4,5]={:?} grace_bp_mean[G=3,4,5]={:?} blocks={} c_changes={} c_range=[{},{}]",
            s.scenario,
            s.age_years,
            s.rise_bp_max,
            s.fall_bp_max,
            s.grace_bp_max,
            s.grace_bp_mean,
            s.blocks_measured,
            s.c_changes,
            s.c_min,
            s.c_max
        );
    }
    // FL-E2 / FL-E3 / FL-E4 roll-up.
    {
        let cells = &r.slew;
        let worst_rise1 = cells.iter().map(|s| s.rise_bp_max[0]).max().unwrap_or(0);
        let worst_grace: [u64; 3] =
            core::array::from_fn(|i| cells.iter().map(|s| s.grace_bp_max[i]).max().unwrap_or(0));
        let mean_grace: [u64; 3] = core::array::from_fn(|i| {
            if cells.is_empty() {
                0
            } else {
                cells.iter().map(|s| s.grace_bp_mean[i]).sum::<u64>() / cells.len() as u64
            }
        });
        let stationary_mean: [u64; 3] = core::array::from_fn(|i| {
            cells
                .iter()
                .filter(|s| s.scenario.starts_with("stationary"))
                .map(|s| s.grace_bp_mean[i])
                .max()
                .unwrap_or(0)
        });
        let _ = writeln!(
            out,
            "fee-floor: FL-E2/E3/E4 cells={} worst_1block_rise_bp={} grace_bp_max[G=3,4,5]={:?} grace_bp_mean_of_means[G=3,4,5]={:?} stationary_grace_bp_mean_max[G=3,4,5]={:?}",
            cells.len(),
            worst_rise1,
            worst_grace,
            mean_grace,
            stationary_mean
        );
    }
    // FL-E1: the feedback grid.
    {
        let cells = &r.feedback;
        let not_converged = cells.iter().filter(|f| !f.converged).count();
        let worst_amp = cells.iter().map(|f| f.tail_amplitude_bp).max().unwrap_or(0);
        let worst_grace: [u64; 3] =
            core::array::from_fn(|i| cells.iter().map(|f| f.grace_bp_max[i]).max().unwrap_or(0));
        let _ = writeln!(
            out,
            "fee-floor: FL-E1 cells={} not_converged={} worst_tail_amplitude_bp={} grace_bp_max[G=3,4,5]={:?}",
            cells.len(),
            not_converged,
            worst_amp,
            worst_grace
        );
        for f in cells.iter().filter(|f| !f.converged) {
            let _ = writeln!(
                out,
                "fee-floor: FL-E1 NOT-CONVERGED age={} M={} eps={} D={} start={} tail_amplitude_bp={} tail_transitions={} fee_tail=[{},{}]",
                f.age_years,
                f.median,
                f.elasticity_milli,
                f.demand_scale,
                f.start_volume,
                f.tail_amplitude_bp,
                f.tail_transitions,
                f.fee_tail_min,
                f.fee_tail_max
            );
        }
    }
}

pub fn render_json(r: &FeeFloorReport) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::params::SCALE;
    use shekyl_economics::{
        corrected_fee_ladder, EconomicParams, FeeCorrection, RELAY_FLOOR_REFERENCE_TX_WEIGHT,
    };

    /// The instrument's floor is the owner's before rounding: divided by
    /// `SCALE` it is `relay_fee_floor` exactly, and the Standard rung it
    /// pays (`4·F`) is the owner's ladder's own multiple of that floor.
    #[test]
    fn the_floor_is_the_owners_at_scale_resolution() {
        let params = EconomicParams::default();
        for base in [1_000_000_000u64, 584_930_000_000, 2_048_000_000_000] {
            for median in [FULL_REWARD_ZONE, 764_000, 3 * FULL_REWARD_ZONE] {
                for c in [680_000u64, 1_000_000, 1_474_300, 12_920_000] {
                    let at_scale = floor_rate(base, median, c);
                    let ladder = corrected_fee_ladder(
                        base,
                        median,
                        RELAY_FLOOR_REFERENCE_TX_WEIGHT,
                        FeeCorrection::from_scaled(c),
                        &params,
                    );
                    let owned = u128::from(ladder.economy);
                    assert_eq!(
                        (at_scale / u128::from(SCALE)).max(1),
                        owned,
                        "base {base} median {median} C {c}"
                    );
                    assert_eq!(u128::from(ladder.standard), 4 * owned, "Standard is 4F");
                }
            }
        }
    }

    /// The one float-to-integer boundary rounds to the nearest whole
    /// transaction and never goes negative.
    #[test]
    fn demand_crosses_to_whole_transactions_once() {
        assert_eq!(whole_transactions(49.4), 49);
        assert_eq!(whole_transactions(49.5), 50);
        assert_eq!(whole_transactions(-3.0), 0);
        assert_eq!(whole_transactions(0.0), 0);
    }

    /// FL-E1 on the exact window, held by no test until Phase 0
    /// (`ECONOMICS_SIM_PHASE0.md` §P0.1): 600 cells on the §1.8 age grid,
    /// four of them not converged under the 50 bp bar, all at age 12 with
    /// `eps` = 3, `D` = 400 and the displaced start, worst tail amplitude
    /// 87 bp. The fee-floor report is this crate's instrument, not a fold.
    #[test]
    fn fl_e1_has_four_unconverged_cells_at_age_twelve_and_a_worst_of_87_bp() {
        let report = report();
        assert_eq!(report.feedback.len(), 600);
        let unconverged: Vec<_> = report.feedback.iter().filter(|f| !f.converged).collect();
        assert_eq!(unconverged.len(), 4);
        for cell in &unconverged {
            assert_eq!(cell.age_years, 12);
            assert_eq!(cell.elasticity_milli, 3_000);
            assert_eq!(cell.demand_scale, 400);
            assert_eq!(cell.tail_amplitude_bp, 87);
        }
        let worst = report.feedback.iter().map(|f| f.tail_amplitude_bp).max();
        assert_eq!(worst, Some(87));
    }
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee ladder production serves, measured over the registered state grid.
//!
//! Production multiplies three rungs by raw `C` (`corrected_fee_ladder`,
//! FL-R20). This instrument reports that ladder, how long a posted rung
//! holds under Poisson traffic, and whether the fee-volume loop settles.
//! The legacy column is the ArticMine 2021 transliteration, rounded to two
//! significant digits: the pre-FL-R20 comparison, so the gap between that
//! ladder and the served one is a measured output.
//!
//! Dwell and feedback run the served ladder. A new question is a new row
//! in the scenario tables. The snap, the band, the dwell floor and the
//! grid were deleted with FL-R21; they reopen when a production caller
//! needs one.
//!
//! Economics quantities come from `shekyl-economics` or from
//! build-generated params. Two exceptions, marked where they are defined:
//! the ArticMine transliteration, and `REF_TX_WEIGHT` (the same pinned
//! copy `fee_policy.rs` carries).
//!
//! This module renders. `main.rs --fee-ladder` writes.

use core::fmt::Write as _;
use std::collections::{BTreeSet, VecDeque};

use serde::Serialize;
use shekyl_economics::params::{SCALE, TX_VOLUME_WINDOW};
use shekyl_economics::{
    advance_already_generated, base_block_reward, block_reward_with_penalty, calc_burn_pct,
    calc_release_multiplier, corrected_fee_ladder, effective_emission, emission_share_at,
    fee_correction, paid_block_reward, projected_already_generated, relay_fee_floor,
    round_money_up_2, tail_subsidy_per_block, EconomicParams, FeeCorrection, FeeLadder, TxVolume,
    BLOCKS_PER_YEAR, RELAY_ADMISSION_SLACK_BP,
};

use crate::rng::PoissonTrace;

/// Penalty-free zone. [`shekyl_economics::FULL_REWARD_ZONE`], generated from
/// `config/consensus_constants.json`.
pub(crate) const FULL_REWARD_ZONE: u64 = shekyl_economics::FULL_REWARD_ZONE;

/// `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT` (`src/cryptonote_config.h`).
/// No single Rust owner exists; `fee_policy.rs` carries the same pin.
pub(crate) const REF_TX_WEIGHT: u64 = 3_000;

/// Rolling transaction-volume window (`SHEKYL_TX_VOLUME_WINDOW`): one day
/// at the 120 s target. Build-generated, so a window change cannot leave
/// this instrument measuring a span the chain no longer uses.
const VOLUME_WINDOW: usize = TX_VOLUME_WINDOW as usize;
const _: () = assert!(
    TX_VOLUME_WINDOW <= usize::MAX as u64,
    "TX_VOLUME_WINDOW does not fit this target's usize"
);

/// [`FeeLadder::as_slots`] order: economy, standard, priority.
const ECONOMY_RUNG: usize = 0;
const STANDARD_RUNG: usize = 1;
const PRIORITY_RUNG: usize = 2;

/// Served-ladder arity, taken from the production owner.
const SERVED_SLOTS: usize = FeeLadder::SATURATED.as_slots().len();
const _: () = assert!(
    ECONOMY_RUNG < SERVED_SLOTS && STANDARD_RUNG < SERVED_SLOTS && PRIORITY_RUNG < SERVED_SLOTS
);

/// Registered chain ages, in years. Supply on the projected trajectory is
/// a function of age, so these are the reachable states.
const TRACE_AGES: [u64; 5] = [0, 1, 4, 12, 30];

/// Supply ratios on the correction surface, in tenths of the asymptote.
/// `5` is half. The projected trajectory is folded in separately, because
/// these three points exclude genesis.
const SUPPLY_TENTHS: [u64; 3] = [1, 5, 9];
const SUPPLY_TENTH_DENOMINATOR: u64 = 10;

/// Per-block volume samples on the correction surface.
const SURFACE_VOLUMES: [u64; 6] = [0, 5, 50, 100, 200, 500];

/// Long-term median as a multiple of the penalty-free zone. The served
/// ladder is a function of this median alone.
const MEDIAN_ZONE_FACTORS: [u64; 4] = [1, 3, 10, 50];

/// Demand elasticity in thousandths (`0` is inelastic, `3000` is `ε = 3`).
const ELASTICITY_MILLI: [u64; 5] = [0, 500, 1_000, 2_000, 3_000];

/// Fixed points of the demand curve, in transactions per block. These
/// scales sit off a pow2 boundary; the boundary probe left with the snap.
const DEMAND_SCALES: [u64; 3] = [50, 100, 400];

/// A displaced start is this many times the demand scale. At every
/// registered scale the product is the start the convergence probe used.
const DISPLACED_START_FACTOR: u64 = 8;

/// Blocks in one dwell trace.
const DWELL_TRACE_BLOCKS: u64 = 20_000;

/// Blocks in one feedback trace, and the tail the settlement test reads.
const FEEDBACK_TRACE_BLOCKS: u64 = 30_000;
const FEEDBACK_TAIL_BLOCKS: u64 = 3_000;

// ---------------------------------------------------------------------------
// Correction factor
// ---------------------------------------------------------------------------

/// The correction factor and its components at one state.
#[derive(Serialize, Clone, Copy)]
pub struct Correction {
    pub release_multiplier: u64,
    pub burn_pct: u64,
    pub emission_share_sigma: u64,
    /// `C = (1−σ)·M_r/(1−b)`, fixed-point [`SCALE`].
    pub c_scaled: u64,
}

/// One evaluated point of the correction surface.
#[derive(Serialize, Clone, Copy)]
pub struct CorrectionPoint {
    pub age_years: u64,
    pub height: u64,
    pub supply_ratio_millionths: u64,
    pub reachable: bool,
    pub tx_volume_avg: u64,
    #[serde(flatten)]
    pub correction: Correction,
}

/// `C` at a per-block volume. Inputs come from the canonical crate.
fn correction_factor(v: u64, circulating: u64, height: u64, params: &EconomicParams) -> Correction {
    correction_factor_ratio(TxVolume::per_block(v), circulating, height, params)
}

/// [`correction_factor`] with the volume given as the [`TxVolume`] the
/// owners take. `window(sum, 720)` is the 720-block mean at rational
/// resolution; `per_block` is the integer-truncated operand.
pub(crate) fn correction_factor_ratio(
    volume: TxVolume,
    circulating: u64,
    height: u64,
    params: &EconomicParams,
) -> Correction {
    let baseline = params.tx_volume_baseline;
    let m_r = calc_release_multiplier(volume, baseline, params.release_min, params.release_max);
    let b = calc_burn_pct(
        volume,
        baseline,
        circulating,
        params.emission_curve_asymptote,
        params.burn_base_rate,
        params.burn_cap,
    );
    let sigma = emission_share_at(height);
    let c = fee_correction(volume, sigma, b, params);
    Correction {
        release_multiplier: m_r,
        burn_pct: b,
        emission_share_sigma: sigma,
        c_scaled: c.as_scaled(),
    }
}

// ---------------------------------------------------------------------------
// Legacy transliteration and the served ladder
// ---------------------------------------------------------------------------

/// Unrounded four-rung ladder. Exact integer transliteration of the
/// five-argument `get_dynamic_base_fee_estimate_2021_scaling`, including
/// its folded-division order. The comparison column reproduces that
/// function; it does not idealize it.
///
/// The five-argument form does not clamp its medians. The production
/// wrapper guarantees `Mlw ≥ zone` and `Mnw ≥ Mlw` before the call. The
/// asserts keep a grid row below the zone from printing fees that wrapper
/// cannot emit, and from dividing by zero in `Fh`.
fn articmine_ladder_raw(base_reward: u64, mnw: u64, mlw: u64) -> [u64; 4] {
    assert!(mlw >= FULL_REWARD_ZONE, "wrapper guarantees Mlw >= zone");
    assert!(mnw >= mlw, "wrapper guarantees Mnw >= Mlw");
    let mfw = mnw.min(mlw);
    let fl = base_reward * REF_TX_WEIGHT / (mfw * mfw);
    let fn_ = 4 * base_reward * REF_TX_WEIGHT / (mfw * mfw);
    let fm = 16 * base_reward * REF_TX_WEIGHT / (FULL_REWARD_ZONE * mfw);
    let fh = (4 * fm).max(4 * fm * mfw / (32 * REF_TX_WEIGHT * mnw / FULL_REWARD_ZONE));
    [fl, fn_, fm, fh]
}

/// The legacy ladder on the three priced rungs.
///
/// `articmine_ladder_raw` returns four. Its medium slot has no served
/// counterpart, so the comparison drops it and rounds the three that remain.
fn rounded(raw: [u64; 4]) -> [u64; SERVED_SLOTS] {
    [
        round_money_up_2(raw[0]),
        round_money_up_2(raw[1]),
        round_money_up_2(raw[3]),
    ]
}

/// The served ladder, from `corrected_fee_ladder`. `C` sits in the
/// numerator and the division happens once.
fn served_ladder(
    base_reward: u64,
    median: u64,
    c: u64,
    params: &EconomicParams,
) -> [u64; SERVED_SLOTS] {
    corrected_fee_ladder(
        base_reward,
        median,
        REF_TX_WEIGHT,
        FeeCorrection::from_scaled(c),
        params,
    )
    .as_slots()
}

/// The relay floor, from `relay_fee_floor`.
fn relay_floor(base_reward: u64, median: u64, c: u64, params: &EconomicParams) -> u64 {
    relay_fee_floor(
        base_reward,
        median,
        REF_TX_WEIGHT,
        FeeCorrection::from_scaled(c),
        params,
    )
}

/// Standard-rung fee the feedback loop treats as the price. At least 1,
/// so a zero rung cannot divide the demand curve.
fn standard_fee(v_avg: u64, ag: u64, height: u64, median: u64, params: &EconomicParams) -> u64 {
    let base = base_block_reward(ag, params).expect("base along trace");
    let c = correction_factor(v_avg, ag, height, params).c_scaled;
    served_ladder(base, median, c, params)[STANDARD_RUNG].max(1)
}

// ---------------------------------------------------------------------------
// Spacing of the served ladder
// ---------------------------------------------------------------------------

/// Spacing of the served three-tier ladder at one long-term median.
#[derive(Serialize)]
pub struct XServedRow {
    /// Long-term effective median the ladder is priced against.
    pub median: u64,
    /// `C` in force, in [`SCALE`] units. `x` moves with `C`.
    pub c_scaled: u64,
    /// `x_i = f_i·M/R` per rung, in millionths: the expansion of the
    /// median that rung funds on an average-cost basis.
    pub x_millionths: [u64; SERVED_SLOTS],
    /// Adjacent-rung ratios ×1000: standard/economy, then priority/standard.
    pub adjacent_ratio_milli: [u64; SERVED_SLOTS - 1],
}

fn x_served_row(
    base_reward: u64,
    median: u64,
    c_scaled: u64,
    params: &EconomicParams,
) -> XServedRow {
    let f = served_ladder(base_reward, median, c_scaled, params);
    let m = median.max(FULL_REWARD_ZONE);
    let x = f.map(|fi| {
        u64::try_from(u128::from(fi) * u128::from(m) * u128::from(SCALE) / u128::from(base_reward))
            .expect("x fits u64")
    });
    let ratio = |hi: u64, lo: u64| -> u64 {
        if lo == 0 {
            0
        } else {
            u64::try_from(u128::from(hi) * 1000 / u128::from(lo)).expect("ratio fits u64")
        }
    };
    XServedRow {
        median: m,
        c_scaled,
        x_millionths: x,
        adjacent_ratio_milli: [
            ratio(f[STANDARD_RUNG], f[ECONOMY_RUNG]),
            ratio(f[PRIORITY_RUNG], f[STANDARD_RUNG]),
        ],
    }
}

// ---------------------------------------------------------------------------
// Per-age chain state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct AgeState {
    pub(crate) height: u64,
    pub(crate) ag: u64,
    pub(crate) base_reward: u64,
}

pub(crate) fn age_state(age_years: u64, params: &EconomicParams) -> AgeState {
    let height = age_years * BLOCKS_PER_YEAR;
    let ag = projected_already_generated(height, params).expect("projected ag");
    let base_reward = base_block_reward(ag, params).expect("base reward");
    AgeState {
        height,
        ag,
        base_reward,
    }
}

// ---------------------------------------------------------------------------
// Rung tables at representative states
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RungTable {
    pub label: &'static str,
    pub age_years: u64,
    pub supply_ratio_millionths: u64,
    pub tx_volume_avg: u64,
    pub median: u64,
    pub base_reward_unmodulated: u64,
    pub c_scaled: u64,
    /// Pre-FL-R20 ArticMine ladder on the three priced rungs.
    pub legacy: [u64; SERVED_SLOTS],
    /// Served ladder at raw `C`.
    pub served: [u64; SERVED_SLOTS],
    /// Relay acceptance bound at this state, per byte. FL-R23 sets the
    /// slack to zero, so the bound is the floor.
    pub relay_floor_accept: u64,
    /// The served economy rung sits below the relay accept bound (FL-C6).
    pub served_below_relay: bool,
}

fn supply_ratio_millionths(ag: u64, params: &EconomicParams) -> u64 {
    u64::try_from(u128::from(ag) * u128::from(SCALE) / u128::from(params.emission_curve_asymptote))
        .expect("ratio fits")
}

fn rung_table(
    label: &'static str,
    age_years: u64,
    v: u64,
    median: u64,
    st: AgeState,
    params: &EconomicParams,
) -> RungTable {
    let corr = correction_factor(v, st.ag, st.height, params);
    let legacy = rounded(articmine_ladder_raw(st.base_reward, median, median));
    let served = served_ladder(st.base_reward, median, corr.c_scaled, params);
    let floor = relay_floor(st.base_reward, median, corr.c_scaled, params);
    debug_assert_eq!(
        RELAY_ADMISSION_SLACK_BP, 0,
        "accept == floor assumes zero slack"
    );
    RungTable {
        label,
        age_years,
        supply_ratio_millionths: supply_ratio_millionths(st.ag, params),
        tx_volume_avg: v,
        median,
        base_reward_unmodulated: st.base_reward,
        c_scaled: corr.c_scaled,
        legacy,
        served,
        relay_floor_accept: floor,
        served_below_relay: served[ECONOMY_RUNG] < floor,
    }
}

// ---------------------------------------------------------------------------
// Dwell: how long a posted rung value persists
// ---------------------------------------------------------------------------

/// Registered dwell scenarios: `(label, mean_start, mean_end, median)`.
///
/// Stationary rows cover the volume grid. The two ramps are both
/// directions of the registered 50↔200 crossing, so a ramp is measured
/// on the way down as well as on the way up.
const DWELL_SCENARIOS: &[(&str, f64, f64, u64)] = &[
    ("stationary-v0", 0.0, 0.0, FULL_REWARD_ZONE),
    ("stationary-v5", 5.0, 5.0, FULL_REWARD_ZONE),
    ("stationary-v50", 50.0, 50.0, FULL_REWARD_ZONE),
    ("stationary-v100", 100.0, 100.0, FULL_REWARD_ZONE),
    ("stationary-v200", 200.0, 200.0, FULL_REWARD_ZONE),
    ("stationary-v500", 500.0, 500.0, FULL_REWARD_ZONE),
    (
        "stationary-v50-m10z",
        50.0,
        50.0,
        MEDIAN_ZONE_FACTORS[2] * FULL_REWARD_ZONE,
    ),
    ("ramp-v50-to-v200", 50.0, 200.0, FULL_REWARD_ZONE),
    ("ramp-v200-to-v50", 200.0, 50.0, FULL_REWARD_ZONE),
];

/// One block of traced chain state: the shipped paid emission at the
/// windowed volume, added through the asymptote.
pub(crate) fn advance_traced_state(ag: u64, v_avg: u64, params: &EconomicParams) -> u64 {
    let paid = effective_emission(ag, TxVolume::per_block(v_avg), params)
        .expect("paid emission along trace");
    advance_already_generated(ag, paid)
}

/// Per-rung run lengths over a dwell trace.
struct RungRuns<const N: usize> {
    runs: [Vec<(u64, u64)>; N],
    values: [BTreeSet<u64>; N],
    current: [u64; N],
    run_len: [u64; N],
    run_start: [u64; N],
}

struct RungStats<const N: usize> {
    median_dwell: [u64; N],
    distinct: [u64; N],
    changes: [u64; N],
    min_ramp: [Option<u64>; N],
}

impl<const N: usize> RungRuns<N> {
    fn new() -> Self {
        Self {
            runs: std::array::from_fn(|_| Vec::new()),
            values: std::array::from_fn(|_| BTreeSet::new()),
            current: [0; N],
            run_len: [0; N],
            run_start: [0; N],
        }
    }

    fn observe(&mut self, t: u64, fees: [u64; N]) {
        for (i, fee) in fees.into_iter().enumerate() {
            self.values[i].insert(fee);
            if fee == self.current[i] {
                self.run_len[i] += 1;
            } else {
                if self.run_len[i] > 0 {
                    self.runs[i].push((self.run_start[i], self.run_len[i]));
                }
                self.current[i] = fee;
                self.run_len[i] = 1;
                self.run_start[i] = t;
            }
        }
    }

    fn finish(mut self, is_ramp: bool, ramp_len: u64) -> RungStats<N> {
        for ((runs, start), len) in self.runs.iter_mut().zip(self.run_start).zip(self.run_len) {
            runs.push((start, len));
        }
        let mut stats = RungStats {
            median_dwell: [0; N],
            distinct: [0; N],
            changes: [0; N],
            min_ramp: [None; N],
        };
        for (i, runs) in self.runs.iter().enumerate() {
            let mut lens: Vec<u64> = runs.iter().map(|&(_, l)| l).collect();
            lens.sort_unstable();
            stats.median_dwell[i] = lens[lens.len() / 2];
            stats.distinct[i] = u64::try_from(self.values[i].len()).expect("distinct count fits");
            stats.changes[i] = u64::try_from(runs.len() - 1).expect("change count fits");
            if is_ramp {
                stats.min_ramp[i] = runs
                    .iter()
                    .filter(|&&(start, _)| start > 0 && start < ramp_len)
                    .map(|&(_, l)| l)
                    .min();
            }
        }
        stats
    }
}

#[derive(Serialize)]
pub struct DwellResult {
    pub scenario: &'static str,
    pub is_ramp: bool,
    pub age_years: u64,
    pub blocks_measured: u64,
    pub median_dwell: [u64; SERVED_SLOTS],
    pub distinct_posted_values: [u64; SERVED_SLOTS],
    pub value_changes: [u64; SERVED_SLOTS],
    /// Shortest run that started inside the ramp window. `None` on a
    /// stationary scenario, and on a rung the ramp never moved.
    pub min_dwell_started_in_ramp: [Option<u64>; SERVED_SLOTS],
}

#[allow(clippy::cast_precision_loss)]
fn dwell_scenario(
    scenario: &'static str,
    mean_start: f64,
    mean_end: f64,
    median: u64,
    st: AgeState,
    params: &EconomicParams,
) -> DwellResult {
    // Supply, σ and the reward move with the trace. A rung change caused
    // by that drift is part of the measurement.
    let blocks = DWELL_TRACE_BLOCKS;
    let ramp_len = u64::try_from(VOLUME_WINDOW).expect("window fits u64");
    let mut rng = PoissonTrace::trace();
    let mut window: VecDeque<u64> = VecDeque::new();
    let mut sum: u64 = 0;
    for _ in 0..VOLUME_WINDOW {
        let n = rng.poisson(mean_start);
        sum += n;
        window.push_back(n);
    }

    let mut ag = st.ag;
    let mut rungs = RungRuns::<SERVED_SLOTS>::new();
    for t in 0..blocks {
        let frac = if (mean_end - mean_start).abs() < f64::EPSILON {
            0.0
        } else {
            (t as f64 / ramp_len as f64).min(1.0)
        };
        let mean = mean_start + (mean_end - mean_start) * frac;
        let n = rng.poisson(mean);
        sum += n;
        window.push_back(n);
        sum -= window.pop_front().expect("window warm");
        let v_avg = sum / ramp_len;

        let height = st.height + t;
        let base = base_block_reward(ag, params).expect("base along trace");
        let c_raw = correction_factor(v_avg, ag, height, params).c_scaled;
        let fees = served_ladder(base, median, c_raw, params);
        ag = advance_traced_state(ag, v_avg, params);
        rungs.observe(t, fees);
    }

    let is_ramp = (mean_end - mean_start).abs() >= f64::EPSILON;
    let stats = rungs.finish(is_ramp, ramp_len);
    DwellResult {
        scenario,
        is_ramp,
        age_years: st.height / BLOCKS_PER_YEAR,
        blocks_measured: blocks,
        median_dwell: stats.median_dwell,
        distinct_posted_values: stats.distinct,
        value_changes: stats.changes,
        min_dwell_started_in_ramp: stats.min_ramp,
    }
}

// ---------------------------------------------------------------------------
// Feedback: the fee↔volume loop on the served ladder
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeedbackResult {
    pub age_years: u64,
    pub median: u64,
    pub elasticity_milli: u64,
    /// Fixed point of `v = D·(f/f_D)^(−ε)`.
    pub demand_scale: u64,
    pub start_volume: u64,
    /// Distinct standard-rung fees over the tail. `1` has settled.
    pub distinct_fees_tail: u64,
    /// Value changes over the tail. One change tracks emission drift.
    /// Two or more is a cycle.
    pub tail_transitions: u64,
    pub v_avg_tail_min: u64,
    pub v_avg_tail_max: u64,
    pub fee_tail_min: u64,
    pub fee_tail_max: u64,
}

/// Two or more standard-rung changes in the tail.
fn is_oscillating(fb: &FeedbackResult) -> bool {
    fb.tail_transitions >= 2
}

/// One feedback cell. The reference fee is the standard rung at the
/// demand scale, taken at the trace's start, so the demand curve stays
/// put while the loop's fee moves.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn feedback_scenario(
    eps_milli: u64,
    demand_scale: u64,
    start_volume: u64,
    st: AgeState,
    median: u64,
    params: &EconomicParams,
) -> FeedbackResult {
    let f_ref = standard_fee(demand_scale, st.ag, st.height, median, params);
    let eps = eps_milli as f64 / 1000.0;
    let mut window: VecDeque<f64> = VecDeque::with_capacity(VOLUME_WINDOW);
    let mut sum = 0.0f64;
    for _ in 0..VOLUME_WINDOW {
        sum += start_volume as f64;
        window.push_back(start_volume as f64);
    }

    let mut fee_min = u64::MAX;
    let mut fee_max = 0u64;
    let mut v_min = u64::MAX;
    let mut v_max = 0u64;
    let mut tail_fees = BTreeSet::new();
    let mut tail_transitions = 0u64;
    let mut last_tail_fee: Option<u64> = None;
    let mut ag = st.ag;
    let tail_from = FEEDBACK_TRACE_BLOCKS - FEEDBACK_TAIL_BLOCKS;
    for t in 0..FEEDBACK_TRACE_BLOCKS {
        let v_avg = (sum / VOLUME_WINDOW as f64).max(0.0) as u64;
        let fee = standard_fee(v_avg, ag, st.height + t, median, params);
        ag = advance_traced_state(ag, v_avg, params);
        // The demand model has no saturation cap. `M_r` rails at its
        // maximum, so the fee stays finite. The cast saturates.
        let demand = (demand_scale as f64) * (fee as f64 / f_ref as f64).powf(-eps);
        let demand = demand.max(0.0);
        sum += demand;
        window.push_back(demand);
        sum -= window.pop_front().expect("window warm");
        if t >= tail_from {
            fee_min = fee_min.min(fee);
            fee_max = fee_max.max(fee);
            v_min = v_min.min(v_avg);
            v_max = v_max.max(v_avg);
            tail_fees.insert(fee);
            if let Some(prev_fee) = last_tail_fee {
                if fee != prev_fee {
                    tail_transitions += 1;
                }
            }
            last_tail_fee = Some(fee);
        }
    }

    FeedbackResult {
        age_years: st.height / BLOCKS_PER_YEAR,
        median,
        elasticity_milli: eps_milli,
        demand_scale,
        start_volume,
        distinct_fees_tail: u64::try_from(tail_fees.len()).expect("tail cardinality fits"),
        tail_transitions,
        v_avg_tail_min: v_min,
        v_avg_tail_max: v_max,
        fee_tail_min: fee_min,
        fee_tail_max: fee_max,
    }
}

// ---------------------------------------------------------------------------
// Degenerate pins (FL-C8) and the tier-share reduction (FL-C9)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DegeneratePins {
    /// `b` reaches its cap on-grid: `(v = 500, ratio = 0.9)` → `burn_cap`.
    pub burn_at_cap: u64,
    /// `M_r` at `v = 0` and at twice the baseline.
    pub release_at_zero: u64,
    pub release_at_double_baseline: u64,
    /// Tail subsidy per block, and the supply headroom at tail entry.
    /// `tail_era_blocks` is `2^esf`: the tail-rate blocks the headroom to
    /// the asymptote covers. The tail is perpetual.
    pub tail_subsidy_per_block: u64,
    pub headroom_at_tail_entry: u64,
    pub tail_era_blocks: u64,
    /// At `already_generated == emission_curve_asymptote`: the estimate
    /// path's pre-penalty curve value, and the paid quantity validation
    /// settles on.
    pub estimate_reward_at_exhaustion: u64,
    pub validation_reward_at_exhaustion: u64,
    /// Tail-emission reward at `weight = 1.5·zone`: `TAIL·(1 − x²) = TAIL·¾`.
    pub penalty_at_tail_x_half: u64,
    /// Legacy ladder at the estimate reward and at the validation reward,
    /// both at the zone. These are the pre-FL-R20 comparison, computed at
    /// the two rewards FL-V1 separates.
    pub legacy_ladder_at_estimate_reward: [u64; SERVED_SLOTS],
    pub legacy_ladder_at_validation_reward: [u64; SERVED_SLOTS],
    /// Served relay floor at `C = 1`, on the validation reward.
    pub relay_floor_at_exhaustion: u64,
}

fn degenerate_pins(params: &EconomicParams) -> DegeneratePins {
    let ratio_09 = params.emission_curve_asymptote / SUPPLY_TENTH_DENOMINATOR * 9;
    let esf = params.emission_speed_factor_per_block;
    let tail = tail_subsidy_per_block(params).expect("tail subsidy");
    let s = params.emission_curve_asymptote;
    let est_reward = base_block_reward(s, params).expect("base at exhaustion");
    let val_reward = paid_block_reward(
        FULL_REWARD_ZONE,
        FULL_REWARD_ZONE,
        s,
        TxVolume::per_block(params.tx_volume_baseline),
        params,
    )
    .expect("paid reward at the asymptote is total");
    DegeneratePins {
        burn_at_cap: calc_burn_pct(
            TxVolume::per_block(500),
            params.tx_volume_baseline,
            ratio_09,
            s,
            params.burn_base_rate,
            params.burn_cap,
        ),
        release_at_zero: calc_release_multiplier(
            TxVolume::ZERO,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        ),
        release_at_double_baseline: calc_release_multiplier(
            TxVolume::per_block(2 * params.tx_volume_baseline),
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        ),
        tail_subsidy_per_block: tail,
        headroom_at_tail_entry: tail << esf,
        tail_era_blocks: 1 << esf,
        estimate_reward_at_exhaustion: est_reward,
        validation_reward_at_exhaustion: val_reward,
        penalty_at_tail_x_half: block_reward_with_penalty(
            FULL_REWARD_ZONE,
            FULL_REWARD_ZONE + FULL_REWARD_ZONE / 2,
            s,
            params,
        )
        .expect("tail-reward penalty pin"),
        legacy_ladder_at_estimate_reward: rounded(articmine_ladder_raw(
            est_reward,
            FULL_REWARD_ZONE,
            FULL_REWARD_ZONE,
        )),
        legacy_ladder_at_validation_reward: rounded(articmine_ladder_raw(
            val_reward.max(1),
            FULL_REWARD_ZONE,
            FULL_REWARD_ZONE,
        )),
        relay_floor_at_exhaustion: relay_floor(val_reward, FULL_REWARD_ZONE, SCALE, params),
    }
}

/// How far one public fee rung shrinks an anchored observer's candidate set.
///
/// FCMP++ puts no linkage on the wire. The attack acquires an anchor
/// off-chain and filters the height window by every public field. The
/// rung contributes `1/usage_share` on that one transaction, once.
/// Surprisal is `log2` of the same factor. The single state-computed rate
/// contributes ×1.
#[derive(Serialize)]
pub struct AnchoredReduction {
    pub traffic_model: &'static str,
    /// Tier shares ×1000, in economy / standard / priority order.
    pub shares_milli: [u64; 3],
    /// `1/share` ×1000, per rung.
    pub reduction_factor_milli: [u64; 3],
    /// `log2(reduction)` ×1000, per rung.
    pub rung_surprisal_milli: [u64; 3],
    /// `H(rung)` ×1000.
    pub ladder_bits_per_tx_milli: u64,
    /// The single rate's reduction ×1000. `1000` is ×1.
    pub single_rate_reduction_milli: u64,
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn anchored_reduction(traffic_model: &'static str, shares_milli: [u64; 3]) -> AnchoredReduction {
    let mut h = 0.0f64;
    let mut surprisal = [0u64; 3];
    let mut reduction = [0u64; 3];
    for (i, &m) in shares_milli.iter().enumerate() {
        let p = m as f64 / 1000.0;
        if p > 0.0 {
            let s_bits = -p.log2();
            h += p * s_bits;
            surprisal[i] = (s_bits * 1000.0).round() as u64;
            reduction[i] = (1000.0 / p).round() as u64;
        }
    }
    AnchoredReduction {
        traffic_model,
        shares_milli,
        reduction_factor_milli: reduction,
        rung_surprisal_milli: surprisal,
        ladder_bits_per_tx_milli: (h * 1000.0).round() as u64,
        single_rate_reduction_milli: 1000,
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeeLadderReport {
    c_surface: Vec<CorrectionPoint>,
    c_reachable_min: u64,
    c_reachable_max: u64,
    x_served: Vec<XServedRow>,
    rung_tables: Vec<RungTable>,
    dwell: Vec<DwellResult>,
    feedback: Vec<FeedbackResult>,
    degenerate: DegeneratePins,
    fee_signal_bits: Vec<AnchoredReduction>,
}

fn supply_millionths(tenth: u64) -> u64 {
    SCALE * tenth / SUPPLY_TENTH_DENOMINATOR
}

/// Run the instrument.
pub fn report() -> FeeLadderReport {
    let params = EconomicParams::default();
    let zone = FULL_REWARD_ZONE;

    let states: Vec<(u64, AgeState)> = TRACE_AGES
        .iter()
        .map(|&age| (age, age_state(age, &params)))
        .collect();
    let state_of = |age: u64| -> AgeState {
        states
            .iter()
            .find(|&&(a, _)| a == age)
            .expect("age in grid")
            .1
    };

    let mut c_surface = Vec::new();
    let (mut c_min, mut c_max) = (u64::MAX, 0u64);
    for &(age, st) in &states {
        let proj_ratio = u128::from(supply_ratio_millionths(st.ag, &params));
        for &tenth in &SUPPLY_TENTHS {
            let ratio = supply_millionths(tenth);
            let lo = proj_ratio * u128::from(params.release_min) / u128::from(SCALE);
            let hi = (proj_ratio * u128::from(params.release_max) / u128::from(SCALE))
                .min(u128::from(SCALE));
            let reachable = u128::from(ratio) >= lo && u128::from(ratio) <= hi;
            let circ = u64::try_from(
                u128::from(params.emission_curve_asymptote) * u128::from(ratio) / u128::from(SCALE),
            )
            .expect("circ fits");
            for &v in &SURFACE_VOLUMES {
                let correction = correction_factor(v, circ, st.height, &params);
                if reachable {
                    c_min = c_min.min(correction.c_scaled);
                    c_max = c_max.max(correction.c_scaled);
                }
                c_surface.push(CorrectionPoint {
                    age_years: age,
                    height: st.height,
                    supply_ratio_millionths: ratio,
                    reachable,
                    tx_volume_avg: v,
                    correction,
                });
            }
        }
    }
    // The tenth grid excludes genesis. The projected trajectory includes it.
    for &(_, st) in &states {
        for &v in &SURFACE_VOLUMES {
            let c = correction_factor(v, st.ag, st.height, &params).c_scaled;
            c_min = c_min.min(c);
            c_max = c_max.max(c);
        }
    }

    let genesis = state_of(0);
    let c_baseline = correction_factor(
        params.tx_volume_baseline,
        genesis.ag,
        genesis.height,
        &params,
    )
    .c_scaled;
    let x_served = MEDIAN_ZONE_FACTORS
        .iter()
        .map(|&factor| x_served_row(genesis.base_reward, factor * zone, c_baseline, &params))
        .collect();

    let rung_tables = vec![
        rung_table("genesis-quiet", 0, 0, zone, genesis, &params),
        rung_table("genesis-baseline", 0, 50, zone, genesis, &params),
        rung_table("young-congested", 1, 200, zone, state_of(1), &params),
        rung_table("mature-quiet", 12, 5, zone, state_of(12), &params),
        rung_table("mature-congested", 12, 200, 3 * zone, state_of(12), &params),
        rung_table(
            "old-congested-wide",
            30,
            500,
            10 * zone,
            state_of(30),
            &params,
        ),
    ];

    let mut dwell = Vec::new();
    for &(_, st) in &states {
        for &(label, mean_start, mean_end, median) in DWELL_SCENARIOS {
            dwell.push(dwell_scenario(
                label, mean_start, mean_end, median, st, &params,
            ));
        }
    }

    let mut feedback = Vec::new();
    for &(_, st) in &states {
        for &factor in &MEDIAN_ZONE_FACTORS {
            let median = factor * zone;
            for &eps in &ELASTICITY_MILLI {
                for &demand_scale in &DEMAND_SCALES {
                    for start in [demand_scale, DISPLACED_START_FACTOR * demand_scale] {
                        feedback.push(feedback_scenario(
                            eps,
                            demand_scale,
                            start,
                            st,
                            median,
                            &params,
                        ));
                    }
                }
            }
        }
    }

    // Shares are economy / standard / priority. The defaulted model puts
    // the 80% majority on standard. Equal thirds do not divide 1000, so
    // 33/33/33 is 334 + 333 + 333.
    let fee_signal = vec![
        anchored_reduction("registered 50/40/10", [500, 400, 100]),
        anchored_reduction("sensitivity 70/25/5", [700, 250, 50]),
        anchored_reduction("sensitivity 33/33/33", [334, 333, 333]),
        anchored_reduction("defaulted 15/80/5", [150, 800, 50]),
    ];

    FeeLadderReport {
        c_surface,
        c_reachable_min: c_min,
        c_reachable_max: c_max,
        x_served,
        rung_tables,
        dwell,
        feedback,
        degenerate: degenerate_pins(&params),
        fee_signal_bits: fee_signal,
    }
}

/// Render the human summary into `out`. The binary writes it to stderr.
#[allow(clippy::cast_precision_loss)]
pub fn render_summary(r: &FeeLadderReport, out: &mut String) {
    let f = |scaled: u64| scaled as f64 / SCALE as f64;
    let c_lo = f(r.c_reachable_min);
    let c_hi = f(r.c_reachable_max);
    let _ = writeln!(
        out,
        "fee-ladder: C over reachable states = [{c_lo:.3}, {c_hi:.3}]"
    );
    for t in &r.rung_tables {
        let c = f(t.c_scaled);
        let _ = writeln!(
            out,
            "fee-ladder: {label} C={c:.3} legacy={legacy:?} served={served:?} floor_accept={floor} served_below_relay={below}",
            label = t.label,
            legacy = t.legacy,
            served = t.served,
            floor = t.relay_floor_accept,
            below = t.served_below_relay,
        );
    }
    let _ = writeln!(out, "fee-ladder: dwell grid = {} runs", r.dwell.len());
    for d in &r.dwell {
        let repeats = d.value_changes[STANDARD_RUNG] >= 2;
        let reference = d.scenario.starts_with("stationary-v50");
        if reference || repeats {
            let _ = writeln!(
                out,
                "fee-ladder: dwell {scenario} age={age} median={median:?} distinct={distinct:?} changes={changes:?} min_ramp={min_ramp:?}",
                scenario = d.scenario,
                age = d.age_years,
                median = d.median_dwell,
                distinct = d.distinct_posted_values,
                changes = d.value_changes,
                min_ramp = d.min_dwell_started_in_ramp,
            );
        }
    }
    let secular = r
        .feedback
        .iter()
        .filter(|fb| fb.distinct_fees_tail > 1 && fb.tail_transitions <= 1)
        .count();
    let oscillating: Vec<_> = r.feedback.iter().filter(|fb| is_oscillating(fb)).collect();
    let _ = writeln!(
        out,
        "fee-ladder: feedback grid = {} cells; {secular} secular single crossings; {} oscillating",
        r.feedback.len(),
        oscillating.len()
    );
    for fb in oscillating {
        let _ = writeln!(
            out,
            "fee-ladder: feedback age={} M={} eps={} D={} start={} distinct_tail={} transitions={} v_tail=[{},{}] fee_tail=[{},{}]",
            fb.age_years,
            fb.median,
            fb.elasticity_milli,
            fb.demand_scale,
            fb.start_volume,
            fb.distinct_fees_tail,
            fb.tail_transitions,
            fb.v_avg_tail_min,
            fb.v_avg_tail_max,
            fb.fee_tail_min,
            fb.fee_tail_max
        );
    }
    for fs in &r.fee_signal_bits {
        let _ = writeln!(
            out,
            "fee-ladder: c9 [{}] reduction_x1000={:?} surprisal={:?} ladder_bits/tx={} single_rate_reduction=x1.0",
            fs.traffic_model,
            fs.reduction_factor_milli,
            fs.rung_surprisal_milli,
            fs.ladder_bits_per_tx_milli
        );
    }
    let _ = writeln!(
        out,
        "fee-ladder: degenerate tail_era_blocks={} est_reward_at_exhaustion={} val_reward_at_exhaustion={} penalty_at_tail_x_half={}",
        r.degenerate.tail_era_blocks,
        r.degenerate.estimate_reward_at_exhaustion,
        r.degenerate.validation_reward_at_exhaustion,
        r.degenerate.penalty_at_tail_x_half
    );
}

/// Machine-readable report. The binary writes it to stdout.
pub fn render_json(r: &FeeLadderReport) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prints the served-ladder spacing table.
    ///
    /// ```text
    /// cargo test -p shekyl-economics-sim served_ladder_spacing_table -- --nocapture
    /// ```
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn served_ladder_spacing_table() {
        let params = EconomicParams::default();
        let zone = FULL_REWARD_ZONE;
        let genesis = age_state(0, &params);
        let c = correction_factor(
            params.tx_volume_baseline,
            genesis.ag,
            genesis.height,
            &params,
        )
        .c_scaled;
        println!(
            "C_scaled = {c} (genesis, baseline volume {})",
            params.tx_volume_baseline
        );
        println!("base_reward = {}", genesis.base_reward);
        println!("median | x(economy) x(standard) x(priority) | std/eco pri/std");
        for &factor in &MEDIAN_ZONE_FACTORS {
            let row = x_served_row(genesis.base_reward, factor * zone, c, &params);
            let x = row.x_millionths;
            let r = row.adjacent_ratio_milli;
            println!(
                "{:>9} | {:>9.3}% {:>10.3}% {:>10.3}% | {:>6.2}x {:>6.2}x",
                row.median,
                x[ECONOMY_RUNG] as f64 / 10_000.0,
                x[STANDARD_RUNG] as f64 / 10_000.0,
                x[PRIORITY_RUNG] as f64 / 10_000.0,
                r[0] as f64 / 1000.0,
                r[1] as f64 / 1000.0,
            );
        }
    }

    #[test]
    fn rung_runs_tracks_one_change_per_slot() {
        let mut rungs = RungRuns::<SERVED_SLOTS>::new();
        rungs.observe(0, [10, 20, 40]);
        rungs.observe(1, [10, 20, 40]);
        rungs.observe(2, [10, 20, 80]);
        let stats = rungs.finish(false, 0);
        assert_eq!(SERVED_SLOTS, 3);
        assert_eq!(stats.distinct, [1, 1, 2]);
        assert_eq!(stats.changes, [0, 0, 1]);
        assert_eq!(stats.min_ramp, [None, None, None]);
    }

    /// The legacy column reproduces the pre-FL-R20 four-rung oracle in
    /// `tests/unit_tests/scaling_2021.cpp` (`wallet_fee_estimate`, 10 SKL).
    /// The pin covers all four rungs. [`rounded`] drops the medium one
    /// for the comparison table; this test does not.
    #[test]
    fn transliteration_matches_cpp_kat() {
        let coin: u64 = crate::burden::COIN;
        let legacy =
            |r: u64, mnw: u64, mlw: u64| articmine_ladder_raw(r, mnw, mlw).map(round_money_up_2);
        assert_eq!(
            legacy(10 * coin, 300_000, 300_000),
            [340, 1400, 5400, 67_000]
        );
        assert_eq!(
            legacy(10 * coin, 15_000_000, 300_000),
            [340, 1400, 5400, 22_000]
        );
        assert_eq!(
            legacy(10 * coin, 1_500_000, 1_500_000),
            [13, 53, 1100, 14_000]
        );
    }

    /// Genesis priority on the legacy column is 6_900_000: `2·R₀/Zm` at
    /// the design's `R₀` of 1 024 SKL, rounded up to two significant digits.
    #[test]
    fn genesis_fh_of_the_legacy_transliteration() {
        let params = EconomicParams::default();
        let base = base_block_reward(0, &params).expect("genesis base");
        let fees = rounded(articmine_ladder_raw(base, 300_000, 300_000));
        assert_eq!(fees[PRIORITY_RUNG], 6_900_000);
    }

    /// The served ladder is `corrected_fee_ladder`. At 10 SKL, a 1.5 MB
    /// median and `C = 16` the economy rung is 213.
    #[test]
    fn served_ladder_is_the_owners_arithmetic() {
        let coin: u64 = crate::burden::COIN;
        let params = EconomicParams::default();
        // The legacy transliteration truncates the rung, then the column
        // rounds it. That column is the pre-FL-R20 comparison.
        let raw = articmine_ladder_raw(10 * coin, 1_500_000, 1_500_000);
        assert_eq!(raw[ECONOMY_RUNG], 13);

        let served = served_ladder(10 * coin, 1_500_000, 16 * SCALE, &params);
        assert_eq!(served[ECONOMY_RUNG], 213);
        assert_eq!(
            served,
            corrected_fee_ladder(
                10 * coin,
                1_500_000,
                REF_TX_WEIGHT,
                FeeCorrection::from_scaled(16 * SCALE),
                &params,
            )
            .as_slots()
        );
    }
}

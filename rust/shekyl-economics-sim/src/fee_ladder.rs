// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee ladder production serves, measured over the registered state grid.
//!
//! Production multiplies three rungs by raw `C` (`corrected_fee_ladder`,
//! FL-R20). This instrument reports that ladder over the correction
//! surface and at representative states, and whether the fee-volume loop
//! settles (FL-C7).
//!
//! The instrument measures the design as built, on the operands production
//! computes: every trace pushes each block's whole transaction count into
//! the fold's [`VolumeWindow`], and `C` and the paid emission are priced at
//! the [`TxVolume`] the validator reads (CEN-F20; FL-R24's exact window).
//! Demand crosses from the scenario layer's float to whole transactions
//! once, at the scenario boundary ([`whole_transactions`], DQ-2G).
//!
//! The feedback loop runs the served ladder. A new question is a new row
//! in the scenario tables. How far the floor moves per block is
//! `fee_floor.rs`'s, in basis points (FL-E2).
//!
//! Economics quantities come from `shekyl-economics` or from
//! build-generated params. The reference weight is
//! [`shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT`].
//!
//! This module renders. `main.rs --fee-ladder` writes.

use core::fmt::Write as _;
use std::collections::BTreeSet;

use serde::Serialize;
use shekyl_economics::params::{SCALE, TX_VOLUME_WINDOW};
use shekyl_economics::{
    advance_already_generated, base_block_reward, block_reward_with_penalty, calc_burn_pct,
    calc_release_multiplier, corrected_fee_ladder, correction_factors_at, effective_emission,
    emission_share_at, paid_block_reward, projected_already_generated, relay_fee_floor,
    tail_subsidy_per_block, CirculatingSupply, EconomicParams, FeeCorrection, FeeLadder, TxVolume,
    BLOCKS_PER_YEAR, RELAY_ADMISSION_SLACK_BP, RELAY_FLOOR_REFERENCE_TX_WEIGHT,
};
use shekyl_units::AtomicUnits;

use crate::fee_bar::CONVERGED_AMPLITUDE_BP;
use crate::fee_floor::whole_transactions;
use crate::fee_signal::{registered_models, AnchoredReduction};
use crate::volume_window::VolumeWindow;

/// Penalty-free zone. [`shekyl_economics::FULL_REWARD_ZONE`], generated from
/// `config/consensus_constants.json`.
pub(crate) const FULL_REWARD_ZONE: u64 = shekyl_economics::FULL_REWARD_ZONE;

/// Rolling transaction-volume window (`SHEKYL_TX_VOLUME_WINDOW`): one day
/// at the 120 s target. Build-generated, so a window change cannot leave
/// this instrument measuring a span the chain no longer uses.
const VOLUME_WINDOW: u64 = TX_VOLUME_WINDOW;

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

/// Fixed points of the demand curve, in transactions per block.
const DEMAND_SCALES: [u64; 3] = [50, 100, 400];

/// A displaced start is this many times the demand scale. At every
/// registered scale the product is the start the convergence probe used.
const DISPLACED_START_FACTOR: u64 = 8;

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

/// `C` at a per-block volume: the surface grid's whole-number points.
fn correction_factor(
    v: u64,
    parent_coins: u64,
    height: u64,
    params: &EconomicParams,
) -> Correction {
    correction_factor_ratio(TxVolume::per_block(v), parent_coins, height, params)
}

/// Supply a trace can name. Traces advance gross `already_generated` and
/// keep no burn ledger, so the burned total is zero — written here, at
/// the owner's derive, rather than by pricing `b` on the gross coins.
fn traced_supply(parent_coins: u64) -> CirculatingSupply {
    CirculatingSupply::derive(AtomicUnits::from_raw(parent_coins), AtomicUnits::ZERO)
        .expect("a trace with no burn ledger burns nothing")
}

/// [`correction_factor`] with the volume given as the [`TxVolume`] the
/// owners take — the fold's window operand on a trace.
///
/// `parent_coins` is the trace's gross accumulator. [`traced_supply`]
/// turns it into the circulating supply the composition prices.
pub(crate) fn correction_factor_ratio(
    volume: TxVolume,
    parent_coins: u64,
    height: u64,
    params: &EconomicParams,
) -> Correction {
    let factors = correction_factors_at(height, traced_supply(parent_coins), volume, params);
    Correction {
        release_multiplier: factors.release_multiplier,
        burn_pct: factors.burn_pct,
        emission_share_sigma: factors.emission_share,
        c_scaled: factors.correction.as_scaled(),
    }
}

// ---------------------------------------------------------------------------
// The served ladder
// ---------------------------------------------------------------------------

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
        RELAY_FLOOR_REFERENCE_TX_WEIGHT,
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
        RELAY_FLOOR_REFERENCE_TX_WEIGHT,
        FeeCorrection::from_scaled(c),
        params,
    )
}

/// Standard-rung fee the feedback loop treats as the price, at the fold's
/// window operand. At least 1, so a zero rung cannot divide the demand
/// curve.
fn standard_fee(
    volume: TxVolume,
    ag: u64,
    height: u64,
    median: u64,
    params: &EconomicParams,
) -> u64 {
    let base = base_block_reward(ag, params).expect("base along trace");
    let c = correction_factor_ratio(volume, ag, height, params).c_scaled;
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
    state_at_height(age_years * BLOCKS_PER_YEAR, params)
}

/// The projected trajectory's state at one height. [`age_state`] is this at
/// a whole year. The reachable extremes also read it at block 1, where the
/// staker share starts, and at the first height where the share has decayed
/// to zero: `C` is lowest at the one and highest at the other, and a sample
/// on whole years sees neither (`ECONOMICS_SIM_PHASE0.md` §P0.1).
pub(crate) fn state_at_height(height: u64, params: &EconomicParams) -> AgeState {
    let ag = projected_already_generated(height, params).expect("projected ag");
    let base_reward = base_block_reward(ag, params).expect("base reward");
    AgeState {
        height,
        ag,
        base_reward,
    }
}

/// The first whole-year height at which production's staker share is zero.
/// The share decays by a tenth a year and its fixed-point value truncates to
/// nothing; the owner is asked year by year rather than the year assumed.
fn sigma_floor_height() -> u64 {
    (0..)
        .map(|years| 1 + years * BLOCKS_PER_YEAR)
        .find(|&height| emission_share_at(height) == 0)
        .expect("the staker share decays to zero")
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
        served,
        relay_floor_accept: floor,
        served_below_relay: served[ECONOMY_RUNG] < floor,
    }
}

// ---------------------------------------------------------------------------
// Traced chain state
// ---------------------------------------------------------------------------

/// One block of traced chain state: the shipped paid emission at the
/// validator's window operand, added through the asymptote.
pub(crate) fn advance_traced_state(ag: u64, volume: TxVolume, params: &EconomicParams) -> u64 {
    let paid = effective_emission(ag, volume, params).expect("paid emission along trace");
    advance_already_generated(ag, paid)
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
    /// Value changes over the tail.
    pub tail_transitions: u64,
    /// The window operand's whole-block mean over the tail: `Σ tx / W`.
    pub v_avg_tail_min: u64,
    pub v_avg_tail_max: u64,
    pub fee_tail_min: u64,
    pub fee_tail_max: u64,
    /// `fee_tail_max / fee_tail_min − 1`, basis points: FL-C7's reading,
    /// scored against [`CONVERGED_AMPLITUDE_BP`].
    pub tail_amplitude_bp: u64,
    /// The cell's reading against the bar ([`settlement`]).
    pub settled: Settlement,
}

/// How a feedback cell's tail reads against FL-E1's pre-registered bar.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// Tail amplitude at or under [`CONVERGED_AMPLITUDE_BP`].
    Converged,
    /// Above the bar, and the tail toggles between two standard-rung
    /// values exactly one served-floor unit apart: the served rate's
    /// whole-atomic-unit resolution acting as an output quantizer where `F`
    /// is small, not loop instability (FL-V12,
    /// `FEE_LADDER_DERIVATION.md` §2). The same loop converges at
    /// `fee_floor.rs`'s finer resolution.
    ResolutionCell,
    /// Above the bar in any other shape: an oscillation this instrument
    /// does not explain.
    Oscillating,
}

/// Standard-rung atomic units one atomic unit of the served floor moves,
/// read off the production ladder (`standard = 4F`) rather than restated.
fn standard_units_per_floor_unit(params: &EconomicParams) -> u64 {
    let ladder = corrected_fee_ladder(
        10 * shekyl_units::ATOMIC_UNITS_PER_SKL,
        FULL_REWARD_ZONE,
        RELAY_FLOOR_REFERENCE_TX_WEIGHT,
        FeeCorrection::UNITY,
        params,
    );
    assert_eq!(
        ladder.standard % ladder.economy,
        0,
        "the standard rung is a whole multiple of the floor"
    );
    ladder.standard / ladder.economy
}

/// FL-C7's reading of one cell's tail against FL-E1's bar: its amplitude,
/// how many distinct standard-rung fees it held and their range, and the
/// rung units one served-floor unit is.
fn settlement(
    tail_amplitude_bp: u64,
    distinct_fees_tail: u64,
    fee_tail: (u64, u64),
    floor_unit: u64,
) -> Settlement {
    if tail_amplitude_bp <= CONVERGED_AMPLITUDE_BP {
        Settlement::Converged
    } else if distinct_fees_tail == 2 && fee_tail.1 - fee_tail.0 == floor_unit {
        Settlement::ResolutionCell
    } else {
        Settlement::Oscillating
    }
}

/// One feedback cell. The reference fee is the standard rung at the
/// demand scale, taken at the trace's start, so the demand curve stays
/// put while the loop's fee moves.
#[allow(clippy::cast_precision_loss)]
fn feedback_scenario(
    eps_milli: u64,
    demand_scale: u64,
    start_volume: u64,
    st: AgeState,
    median: u64,
    floor_unit: u64,
    params: &EconomicParams,
) -> FeedbackResult {
    let f_ref = standard_fee(
        TxVolume::per_block(demand_scale),
        st.ag,
        st.height,
        median,
        params,
    );
    let eps = eps_milli as f64 / 1000.0;
    let mut window = VolumeWindow::default();
    for _ in 0..VOLUME_WINDOW {
        window.push(start_volume);
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
        let volume = window.operand();
        let fee = standard_fee(volume, ag, st.height + t, median, params);
        ag = advance_traced_state(ag, volume, params);
        // The demand model has no saturation cap. `M_r` rails at its
        // maximum, so the fee stays finite. The one float-to-integer
        // boundary: the next block's whole transactions.
        let demand = (demand_scale as f64) * (fee as f64 / f_ref as f64).powf(-eps);
        window.push(whole_transactions(demand));
        if t >= tail_from {
            fee_min = fee_min.min(fee);
            fee_max = fee_max.max(fee);
            let v_avg = volume.tx_count_sum() / volume.blocks().max(1);
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

    let distinct_fees_tail = u64::try_from(tail_fees.len()).expect("tail cardinality fits");
    let tail_amplitude_bp =
        u64::try_from(u128::from(fee_max) * 10_000 / u128::from(fee_min.max(1)) - 10_000)
            .expect("amplitude fits u64");
    FeedbackResult {
        age_years: st.height / BLOCKS_PER_YEAR,
        median,
        elasticity_milli: eps_milli,
        demand_scale,
        start_volume,
        distinct_fees_tail,
        tail_transitions,
        v_avg_tail_min: v_min,
        v_avg_tail_max: v_max,
        fee_tail_min: fee_min,
        fee_tail_max: fee_max,
        tail_amplitude_bp,
        settled: settlement(
            tail_amplitude_bp,
            distinct_fees_tail,
            (fee_min, fee_max),
            floor_unit,
        ),
    }
}

// ---------------------------------------------------------------------------
// Degenerate pins (FL-C8)
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
        relay_floor_at_exhaustion: relay_floor(val_reward, FULL_REWARD_ZONE, SCALE, params),
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
    feedback: Vec<FeedbackResult>,
    converged_amplitude_bp: u64,
    standard_units_per_floor_unit: u64,
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
            let parent_coins = u64::try_from(
                u128::from(params.emission_curve_asymptote) * u128::from(ratio) / u128::from(SCALE),
            )
            .expect("parent coins fit");
            for &v in &SURFACE_VOLUMES {
                let correction = correction_factor(v, parent_coins, st.height, &params);
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
    // The tenth grid excludes genesis. The projected trajectory includes it,
    // and the two heights the year grid misses: block 1, where the staker
    // share is at its start and `C` at its low end, and the first height
    // where the share is zero and `C` at its structural maximum.
    let boundaries = [
        state_at_height(1, &params),
        state_at_height(sigma_floor_height(), &params),
    ];
    for st in states.iter().map(|(_, st)| *st).chain(boundaries) {
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

    let floor_unit = standard_units_per_floor_unit(&params);
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
                            floor_unit,
                            &params,
                        ));
                    }
                }
            }
        }
    }

    FeeLadderReport {
        c_surface,
        c_reachable_min: c_min,
        c_reachable_max: c_max,
        x_served,
        rung_tables,
        feedback,
        converged_amplitude_bp: CONVERGED_AMPLITUDE_BP,
        standard_units_per_floor_unit: floor_unit,
        degenerate: degenerate_pins(&params),
        fee_signal_bits: registered_models(),
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
            "fee-ladder: {label} C={c:.3} served={served:?} floor_accept={floor} served_below_relay={below}",
            label = t.label,
            served = t.served,
            floor = t.relay_floor_accept,
            below = t.served_below_relay,
        );
    }
    let count = |want: Settlement| r.feedback.iter().filter(|fb| fb.settled == want).count();
    let worst_amplitude = r
        .feedback
        .iter()
        .map(|fb| fb.tail_amplitude_bp)
        .max()
        .unwrap_or(0);
    let _ = writeln!(
        out,
        "fee-ladder: feedback grid = {} cells; converged_amplitude_bp={}; worst_tail_amplitude_bp={worst_amplitude}; {} converged; {} FL-V12 resolution cells (the tail toggles one served-floor unit, {} standard-rung units: the served rate's whole-unit resolution, not loop instability); {} oscillating",
        r.feedback.len(),
        r.converged_amplitude_bp,
        count(Settlement::Converged),
        count(Settlement::ResolutionCell),
        r.standard_units_per_floor_unit,
        count(Settlement::Oscillating)
    );
    for fb in r
        .feedback
        .iter()
        .filter(|fb| fb.settled != Settlement::Converged)
    {
        let label = match fb.settled {
            Settlement::ResolutionCell => "FL-V12-resolution",
            _ => "OSCILLATING",
        };
        let _ = writeln!(
            out,
            "fee-ladder: feedback {label} age={} M={} eps={} D={} start={} distinct_tail={} transitions={} tail_amplitude_bp={} v_tail=[{},{}] fee_tail=[{},{}]",
            fb.age_years,
            fb.median,
            fb.elasticity_milli,
            fb.demand_scale,
            fb.start_volume,
            fb.distinct_fees_tail,
            fb.tail_transitions,
            fb.tail_amplitude_bp,
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
        "fee-ladder: degenerate tail_era_blocks={} est_reward_at_exhaustion={} val_reward_at_exhaustion={} penalty_at_tail_x_half={} relay_floor_at_exhaustion={}",
        r.degenerate.tail_era_blocks,
        r.degenerate.estimate_reward_at_exhaustion,
        r.degenerate.validation_reward_at_exhaustion,
        r.degenerate.penalty_at_tail_x_half,
        r.degenerate.relay_floor_at_exhaustion
    );
}

/// Machine-readable report. The binary writes it to stdout.
pub fn render_json(r: &FeeLadderReport) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT;

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

    /// The served ladder is `corrected_fee_ladder`. At 10 SKL, a 1.5 MB
    /// median and `C = 16` the economy rung is 213.
    #[test]
    fn served_ladder_is_the_owners_arithmetic() {
        let coin: u64 = crate::burden::COIN;
        let params = EconomicParams::default();
        let served = served_ladder(10 * coin, 1_500_000, 16 * SCALE, &params);
        assert_eq!(served[ECONOMY_RUNG], 213);
        assert_eq!(
            served,
            corrected_fee_ladder(
                10 * coin,
                1_500_000,
                RELAY_FLOOR_REFERENCE_TX_WEIGHT,
                FeeCorrection::from_scaled(16 * SCALE),
                &params,
            )
            .as_slots()
        );
    }

    /// The traced emission advances on the validator's window operand: a
    /// window whose mean is fractional pays what `effective_emission` pays
    /// at that exact ratio, not at its truncated whole-block mean (FL-R24).
    #[test]
    fn the_trace_advances_on_the_exact_window_operand() {
        let params = EconomicParams::default();
        let st = age_state(4, &params);
        let exact = TxVolume::window(40 * VOLUME_WINDOW + VOLUME_WINDOW / 2, VOLUME_WINDOW);
        let truncated = TxVolume::per_block(40);
        let on_exact = advance_traced_state(st.ag, exact, &params);
        let on_truncated = advance_traced_state(st.ag, truncated, &params);
        assert!(
            on_exact > on_truncated,
            "a 40.5 mean must pay more than the 40 the truncated operand paid"
        );
        assert_eq!(
            on_exact - st.ag,
            effective_emission(st.ag, exact, &params).expect("priced"),
            "one owner prices the trace's emission"
        );
    }

    /// FL-C7's reading is the FL-E1 bar: at or under
    /// `CONVERGED_AMPLITUDE_BP` a cell has settled; above it, a tail that
    /// toggles one served-floor unit is an FL-V12 resolution cell, and any
    /// other shape oscillates.
    #[test]
    fn settlement_is_scored_on_the_shared_bar_and_the_floor_unit() {
        let params = EconomicParams::default();
        let unit = standard_units_per_floor_unit(&params);
        assert_eq!(unit, 4, "standard is 4F");
        // At and just over the bar, on a large rung.
        assert_eq!(
            settlement(CONVERGED_AMPLITUDE_BP, 2, (10_000, 10_050), unit),
            Settlement::Converged
        );
        // 48 ↔ 52: one floor unit on a two-digit rung, 833 bp.
        assert_eq!(
            settlement(833, 2, (48, 52), unit),
            Settlement::ResolutionCell
        );
        // Two rung values two floor units apart, or three values: not one
        // unit of resolution, so the instrument does not explain it.
        assert_eq!(
            settlement(1_666, 2, (48, 56), unit),
            Settlement::Oscillating
        );
        assert_eq!(settlement(833, 3, (48, 52), unit), Settlement::Oscillating);
        assert_eq!(
            settlement(CONVERGED_AMPLITUDE_BP + 1, 2, (10_000, 10_051), unit),
            Settlement::Oscillating
        );
    }
}

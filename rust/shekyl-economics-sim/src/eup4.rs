// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! EUP-4 prep 2: the criteria's instruments
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.32, EI-1…EI-7).
//!
//! Each instrument measures one criterion of the umbrella's §4 table, or a
//! stress ESR-10 left open, and prints the measure: never a verdict against
//! the criterion, which is ratified apart from the number it grades.
//!
//! Rows 2, 3 and Capacity read one set of runs: both `w_ref` arms × the
//! production fee at ×1 all-Standard and the flat control × every scenario,
//! to the onset horizon ([`SharedRuns`]). Each run is ESR-10's fold
//! ([`a1_year_aggs_probed`]) with a [`YearReader`] asked at every block; the
//! reader takes what it prints and changes nothing, so a run's aggregates
//! are the ones every other mode folds. Row 5 and Stuffing are in
//! [`crate::window_stuffer`]; the two stresses are here, each on its own
//! runs.

use std::fmt;

use serde::Serialize;
use shekyl_economics::{
    calc_release_multiplier, effective_emission, neutral_height_reaching,
    params::{BLOCK_WEIGHT_LONG_TERM_WINDOW, TX_VOLUME_WINDOW},
    tail_subsidy_per_block,
};

use crate::burden::COIN;
use crate::engine::{emitted_at_start, ScenarioConfig, SimParams, VolumeSchedule};
use crate::esr10::{arms, economy_served, every_scenario, scenario_named, Arm};
use crate::fee_model::{FeeModel, StandardMultiplier};
use crate::growth_gate::{cell_gate, year_label};
use crate::onset::{
    at_horizon, binding_onsets, fmt_onset, legs_at_flat_onset, BLOCK_SPACE_YEARS,
    ONSET_HORIZON_YEARS,
};
use crate::rung_mix::RungMix;
use crate::scenarios::BASELINE_STEADY_STATE;
use crate::stage2::{a1_year_aggs_probed, A1YearAgg, BlockSeen, FoldProbe, NoProbe};

/// The fee arms the shared runs fold: what the chain charges by default,
/// and the control the archival tables were measured on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeeArm {
    Production,
    FlatControl,
}

impl FeeArm {
    pub(crate) const ALL: [Self; 2] = [Self::Production, Self::FlatControl];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Production => "production x1",
            Self::FlatControl => "flat control",
        }
    }

    fn fee(self) -> FeeModel {
        match self {
            Self::Production => FeeModel::PRODUCTION_DEFAULT,
            Self::FlatControl => SimParams::section_12_14_control().fee,
        }
    }
}

/// `params` with `fee`'s arm.
fn with_fee(params: &SimParams, fee: FeeModel) -> SimParams {
    let mut run = params.clone();
    run.fee = fee;
    run
}

pub(crate) fn skl(atomic: u128) -> f64 {
    atomic as f64 / COIN as f64
}

/// `M_r` at a block a fold priced, in production's fixed point: the
/// release multiplier the block's emission was composed with.
pub(crate) fn release_multiplier_at(seen: &BlockSeen<'_, '_>, params: &SimParams) -> u64 {
    let economic = params.economic();
    calc_release_multiplier(
        seen.priced.volume,
        economic.tx_volume_baseline,
        economic.release_min,
        economic.release_max,
    )
}

/// One year of a run, as rows 2 and 3 read it.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct YearRead {
    pub(crate) year: u64,
    /// The year's `PaidEmission::owed`: the miner leg of the emission and
    /// the miner's fee income, as production composes them.
    pub(crate) miner_owed_atomic: u128,
    /// Of that, the fee income (`BurnSplit::miner_fee_income`).
    pub(crate) miner_fee_atomic: u128,
    /// Blocks whose effective emission is the tail subsidy.
    pub(crate) tail_blocks: u64,
    pub(crate) tail_owed_atomic: u128,
    pub(crate) tail_fee_atomic: u128,
    /// Coins generated through the year's last block.
    pub(crate) generated_atomic: u128,
}

/// The block at which a run first holds a fraction of the asymptote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum Crossing {
    /// Already held when the fold starts.
    BeforeTheFold,
    /// First held through this chain height (blocks from genesis).
    AtHeight(u64),
    /// Not held by the horizon.
    NotReached,
}

/// Rows 2 and 3's reader: asked at every block of a run.
pub(crate) struct YearReader<'p> {
    params: &'p SimParams,
    tail: u64,
    genesis_offset: u64,
    thresholds: [u128; 2],
    crossings: [Crossing; 2],
    year: YearRead,
    pub(crate) years: Vec<YearRead>,
}

impl<'p> YearReader<'p> {
    pub(crate) fn new(params: &'p SimParams, config: &ScenarioConfig) -> Self {
        let economic = params.economic();
        let asymptote = u128::from(economic.emission_curve_asymptote);
        let thresholds = [asymptote / 2, asymptote / 5 * 4];
        let start = emitted_at_start(
            economic.emission_curve_asymptote,
            config.initial_emitted_ppm,
        );
        Self {
            params,
            tail: tail_subsidy_per_block(economic).expect("the tail subsidy is in its domain"),
            genesis_offset: config.genesis_height_offset,
            thresholds,
            crossings: thresholds.map(|t| {
                if start >= t {
                    Crossing::BeforeTheFold
                } else {
                    Crossing::NotReached
                }
            }),
            year: YearRead::default(),
            years: Vec::new(),
        }
    }

    /// The 50 % and 80 % crossings.
    pub(crate) fn crossings(&self) -> [Crossing; 2] {
        self.crossings
    }
}

impl FoldProbe for YearReader<'_> {
    fn seen(&mut self, seen: &BlockSeen<'_, '_>) {
        let economic = self.params.economic();
        let paid = &seen.priced.paid;
        let owed = u128::from(paid.owed.to_raw());
        let fee = u128::from(paid.fee_burn.miner_fee_income);
        self.year.miner_owed_atomic += owed;
        self.year.miner_fee_atomic += fee;
        let effective = effective_emission(
            seen.priced.fee_point.already_generated,
            seen.priced.volume,
            economic,
        )
        .expect("the fold priced this block's emission");
        if effective == self.tail {
            self.year.tail_blocks += 1;
            self.year.tail_owed_atomic += owed;
            self.year.tail_fee_atomic += fee;
        }
        for (threshold, crossing) in self.thresholds.iter().zip(self.crossings.iter_mut()) {
            if *crossing == Crossing::NotReached && seen.already_generated >= *threshold {
                *crossing = Crossing::AtHeight(self.genesis_offset + seen.block + 1);
            }
        }
        let blocks_per_year = self.params.blocks_per_year();
        if (seen.block + 1).is_multiple_of(blocks_per_year) {
            self.year.year = (seen.block + 1) / blocks_per_year;
            self.year.generated_atomic = seen.already_generated;
            self.years.push(core::mem::take(&mut self.year));
        }
    }
}

/// One `(arm, fee arm, scenario)` of the shared runs.
pub(crate) struct SharedRun {
    pub(crate) arm: &'static str,
    pub(crate) fee: FeeArm,
    pub(crate) scenario: String,
    pub(crate) aggs: Vec<A1YearAgg>,
    pub(crate) years: Vec<YearRead>,
    pub(crate) crossings: [Crossing; 2],
}

/// Rows 2, 3 and Capacity's runs, folded once.
pub(crate) struct SharedRuns {
    pub(crate) runs: Vec<SharedRun>,
    pub(crate) blocks_per_year: u64,
    /// The neutral trajectory's 50 % and 80 % heights.
    pub(crate) neutral: [u64; 2],
}

impl SharedRuns {
    /// Fold `arms` × `fees` × `scenarios`, each to the onset horizon.
    pub(crate) fn fold(
        base: &SimParams,
        arms: &[Arm],
        fees: &[FeeArm],
        scenarios: &[String],
        years: u64,
    ) -> Self {
        let jobs: Vec<(&Arm, FeeArm, &str)> = arms
            .iter()
            .flat_map(|arm| {
                fees.iter().flat_map(move |&fee| {
                    scenarios.iter().map(move |name| (arm, fee, name.as_str()))
                })
            })
            .collect();
        let runs = crate::parallel::map(&jobs, |&(arm, fee, scenario)| {
            let params = with_fee(&arm.params, fee.fee());
            let config = to_years(scenario_named(&params, scenario), years);
            let mut reader = YearReader::new(&params, &config);
            let aggs = a1_year_aggs_probed(&params, &config, &mut reader);
            SharedRun {
                arm: arm.which.name(),
                fee,
                scenario: config.name.clone(),
                crossings: reader.crossings(),
                years: reader.years,
                aggs,
            }
        });
        let economic = base.economic();
        let asymptote = economic.emission_curve_asymptote;
        let neutral = [asymptote / 2, asymptote / 5 * 4].map(|target| {
            neutral_height_reaching(target, economic).expect("the neutral trajectory reaches it")
        });
        Self {
            runs,
            blocks_per_year: base.blocks_per_year(),
            neutral,
        }
    }

    fn cells(&self) -> Vec<(&'static str, FeeArm)> {
        let mut cells: Vec<(&'static str, FeeArm)> = Vec::new();
        for run in &self.runs {
            if !cells.contains(&(run.arm, run.fee)) {
                cells.push((run.arm, run.fee));
            }
        }
        cells
    }

    fn of_cell(&self, arm: &'static str, fee: FeeArm) -> impl Iterator<Item = &SharedRun> {
        self.runs
            .iter()
            .filter(move |run| run.arm == arm && run.fee == fee)
    }
}

/// `config` folded to `years`: [`ONSET_HORIZON_YEARS`] for a report, fewer
/// for the reach probe.
fn to_years(mut config: ScenarioConfig, years: u64) -> ScenarioConfig {
    config = at_horizon(config);
    config.sim_years = years;
    config
}

/// A block count as years, to two places.
fn years_of(height: u64, blocks_per_year: u64) -> f64 {
    height as f64 / blocks_per_year as f64
}

// ---------------------------------------------------------------- row 2

/// EI-1's summary row: one run's miner income by year.
#[derive(Debug, Clone, Serialize)]
pub struct MinerIncomeRow {
    arm: &'static str,
    fee: &'static str,
    scenario: String,
    /// Per year: the mean `owed` per block and its fee part, SKL.
    owed_per_block_skl: Vec<f64>,
    fee_per_block_skl: Vec<f64>,
    /// The fee part of `owed` over the tail era's blocks; `None` when no
    /// block of the run is in the tail era.
    tail_era_fee_share: Option<f64>,
}

fn per_block(atomic: u128, blocks: u64) -> f64 {
    skl(atomic) / blocks as f64
}

/// A run's miner income at the sampled years, as EI-1 prints it.
fn sampled_income(years: &[YearRead], bpy: u64) -> String {
    let mut line = String::new();
    for year in BLOCK_SPACE_YEARS {
        if let Some(y) = years.iter().find(|y| y.year == year) {
            let owed = per_block(y.miner_owed_atomic, bpy);
            let share = if y.miner_owed_atomic == 0 {
                0.0
            } else {
                100.0 * y.miner_fee_atomic as f64 / y.miner_owed_atomic as f64
            };
            line.push_str(&format!(" y{year} {owed:.2} ({share:.1}%)"));
        }
    }
    line
}

/// EI-1 (row 2): miner income per block by year, and the tail era's fee
/// share.
pub(crate) fn write_miner_income(
    out: &mut impl fmt::Write,
    shared: &SharedRuns,
) -> Result<Vec<MinerIncomeRow>, fmt::Error> {
    let bpy = shared.blocks_per_year;
    writeln!(
        out,
        "\nEI-1 — ROW 2, MINER INCOME. Per block, by year: production's PaidEmission::owed (the miner\n\
         leg of the emission and the miner's fee income) in SKL, and in brackets the fee part's share\n\
         of it. Then the tail era's fee share: the fee part over owed in the blocks whose effective\n\
         emission is the tail subsidy."
    )?;
    let mut rows = Vec::new();
    for (arm, fee) in shared.cells() {
        writeln!(out, "== {arm} | {}", fee.name())?;
        for run in shared.of_cell(arm, fee) {
            let figures = sampled_income(&run.years, bpy);
            writeln!(
                out,
                "  {:<22}{figures}",
                crate::stage2::trunc(&run.scenario, 22)
            )?;
            if run.scenario != BASELINE_STEADY_STATE
                && shared
                    .of_cell(arm, fee)
                    .find(|r| r.scenario == BASELINE_STEADY_STATE)
                    .is_some_and(|baseline| sampled_income(&baseline.years, bpy) == figures)
            {
                writeln!(
                    out,
                    "      the same as {BASELINE_STEADY_STATE} at every sampled year: the scenario runs, and \
                     its blocks carry what the baseline's do"
                )?;
            }
            let (tail_blocks, tail_owed, tail_fee) =
                run.years.iter().fold((0u64, 0u128, 0u128), |t, y| {
                    (
                        t.0 + y.tail_blocks,
                        t.1 + y.tail_owed_atomic,
                        t.2 + y.tail_fee_atomic,
                    )
                });
            let tail_share =
                (tail_blocks > 0 && tail_owed > 0).then(|| tail_fee as f64 / tail_owed as f64);
            match tail_share {
                Some(share) => writeln!(
                    out,
                    "      tail era: {tail_blocks} blocks, fee share {:.2}%",
                    100.0 * share
                )?,
                None => writeln!(
                    out,
                    "      tail era: not reached by y{}",
                    run.years.last().map_or(0, |y| y.year)
                )?,
            }
            rows.push(MinerIncomeRow {
                arm,
                fee: fee.name(),
                scenario: run.scenario.clone(),
                owed_per_block_skl: run
                    .years
                    .iter()
                    .map(|y| per_block(y.miner_owed_atomic, bpy))
                    .collect(),
                fee_per_block_skl: run
                    .years
                    .iter()
                    .map(|y| per_block(y.miner_fee_atomic, bpy))
                    .collect(),
                tail_era_fee_share: tail_share,
            });
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------- row 3

/// EI-2's summary row: one run's crossings and their distances.
#[derive(Debug, Clone, Serialize)]
pub struct PredictabilityRow {
    arm: &'static str,
    fee: &'static str,
    scenario: String,
    half: Crossing,
    eighty: Crossing,
    /// The crossing's distance from the neutral trajectory's, in years;
    /// `None` when there is no crossing inside the fold.
    half_distance_years: Option<f64>,
    eighty_distance_years: Option<f64>,
    /// The emitted fraction at each year's end.
    emitted_fraction: Vec<f64>,
}

fn crossing_text(crossing: Crossing, neutral: u64, bpy: u64) -> (String, Option<f64>) {
    match crossing {
        Crossing::BeforeTheFold => ("before the fold".to_string(), None),
        Crossing::NotReached => ("not reached".to_string(), None),
        Crossing::AtHeight(height) => {
            let distance = years_of(height, bpy) - years_of(neutral, bpy);
            (
                format!("y{:.2} ({distance:+.2})", years_of(height, bpy)),
                Some(distance),
            )
        }
    }
}

/// EI-2 (row 3): the emitted fraction by year, and the 50 % and 80 %
/// crossings against the neutral trajectory's.
pub(crate) fn write_predictability(
    out: &mut impl fmt::Write,
    shared: &SharedRuns,
    asymptote: u64,
) -> Result<Vec<PredictabilityRow>, fmt::Error> {
    let bpy = shared.blocks_per_year;
    writeln!(
        out,
        "\nEI-2 — ROW 3, PREDICTABILITY. The year each run first holds 50 % and 80 % of the asymptote,\n\
         and in brackets its distance in years from the neutral trajectory's, which production's\n\
         neutral_height_reaching gives: 50 % at block {} (y{:.2}), 80 % at block {} (y{:.2}).\n\
         Then the emitted fraction at the sampled years.",
        shared.neutral[0],
        years_of(shared.neutral[0], bpy),
        shared.neutral[1],
        years_of(shared.neutral[1], bpy),
    )?;
    let mut rows = Vec::new();
    for (arm, fee) in shared.cells() {
        writeln!(out, "== {arm} | {}", fee.name())?;
        for run in shared.of_cell(arm, fee) {
            let (half, half_d) = crossing_text(run.crossings[0], shared.neutral[0], bpy);
            let (eighty, eighty_d) = crossing_text(run.crossings[1], shared.neutral[1], bpy);
            let fractions: Vec<f64> = run
                .years
                .iter()
                .map(|y| y.generated_atomic as f64 / asymptote as f64)
                .collect();
            let sampled: Vec<String> = BLOCK_SPACE_YEARS
                .iter()
                .filter_map(|&year| {
                    fractions
                        .get(usize::try_from(year).ok()?.checked_sub(1)?)
                        .map(|f| format!("y{year} {:.1}%", 100.0 * f))
                })
                .collect();
            writeln!(
                out,
                "  {:<22} 50% {half}; 80% {eighty}\n      emitted {}",
                crate::stage2::trunc(&run.scenario, 22),
                sampled.join(" ")
            )?;
            rows.push(PredictabilityRow {
                arm,
                fee: fee.name(),
                scenario: run.scenario.clone(),
                half: run.crossings[0],
                eighty: run.crossings[1],
                half_distance_years: half_d,
                eighty_distance_years: eighty_d,
                emitted_fraction: fractions,
            });
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------- capacity

/// EI-4's summary row.
#[derive(Debug, Clone, Serialize)]
pub struct CapacityRow {
    arm: &'static str,
    fee: &'static str,
    /// The first year whose blocks carry the baseline's demand within one
    /// transaction; `None` when none does by the horizon.
    carries_from_year: Option<u64>,
}

/// The baseline's demand a block, which Capacity counts against.
fn baseline_demand(params: &SimParams) -> u64 {
    params.economic().tx_volume_baseline
}

/// EI-4 (Capacity): the first year each arm carries the baseline's demand.
pub(crate) fn write_capacity(
    out: &mut impl fmt::Write,
    shared: &SharedRuns,
    base: &SimParams,
) -> Result<Vec<CapacityRow>, fmt::Error> {
    let demand = baseline_demand(base);
    let bpy = shared.blocks_per_year;
    writeln!(
        out,
        "\nEI-4 — CAPACITY. On the baseline scenario, the first year whose blocks carry its {demand} a block\n\
         within one transaction, per arm."
    )?;
    let mut rows = Vec::new();
    for (arm, fee) in shared.cells() {
        let Some(run) = shared
            .of_cell(arm, fee)
            .find(|run| run.scenario == BASELINE_STEADY_STATE)
        else {
            continue;
        };
        let year = run
            .aggs
            .iter()
            .find(|a| a.carried_txs() + u128::from(bpy) >= u128::from(demand) * u128::from(bpy))
            .map(|a| a.year);
        writeln!(
            out,
            "  {arm:<11} {:<14} carries {demand} from {}",
            fee.name(),
            year.map_or_else(
                || format!("never by y{ONSET_HORIZON_YEARS}"),
                |y| format!("y{y}")
            ),
        )?;
        rows.push(CapacityRow {
            arm,
            fee: fee.name(),
            carries_from_year: year,
        });
    }
    Ok(rows)
}

// ---------------------------------------------------------------- EI-6

/// The Priority cells EI-6 runs: Priority at 5 %, 2.5 %, 1 % and 0, the
/// share it gives up moved to Standard, and the elastic arm at 5 %.
pub(crate) const PRIORITY_CELLS: [RungMix; 5] = [
    RungMix::DEFAULTED,
    RungMix::defaulted_with_priority(25),
    RungMix::defaulted_with_priority(10),
    RungMix::ZERO_PRIORITY,
    RungMix::DEFAULTED.priority_elastic(),
];

/// EI-6's summary row.
#[derive(Debug, Clone, Serialize)]
pub struct PriorityRow {
    arm: &'static str,
    mix: String,
    scenario: String,
    onset_flat: crate::onset::Onset,
    onset_best: crate::onset::Onset,
    /// A1's fee leg at the flat-25 onset (or the horizon), SKL a year, and
    /// its share of the budget.
    fee_leg_skl_per_year: Option<f64>,
    fee_leg_pct: Option<f64>,
    /// Miner income per block by year, SKL.
    owed_per_block_skl: Vec<f64>,
}

/// EI-6: Priority's demand share, fixed and elastic, on both arms over
/// `scenarios`.
pub(crate) fn write_priority_elasticity(
    out: &mut impl fmt::Write,
    arms: &[Arm],
    cells: &[RungMix],
    scenarios: &[String],
    years: u64,
) -> Result<Vec<PriorityRow>, fmt::Error> {
    writeln!(
        out,
        "\nEI-6 — PRIORITY ELASTICITY. The 15/80/5 mix with Priority's share at 5, 2.5, 1 and 0 %, the\n\
         share it gives up moved to Standard, and an elastic arm (a declared behaviour): Priority keeps\n\
         5 % x min(1, P0/P), P its fee and P0 its fee at the fold's first block, unit elasticity.\n\
         Per cell: A1's onset (flat-25, best), its fee leg at the flat-25 onset, and miner income\n\
         per block at the sampled years (SKL)."
    )?;
    let jobs: Vec<(&Arm, RungMix, &str)> = arms
        .iter()
        .flat_map(|arm| {
            cells
                .iter()
                .flat_map(move |&mix| scenarios.iter().map(move |name| (arm, mix, name.as_str())))
        })
        .collect();
    let folded = crate::parallel::map(&jobs, |&(arm, mix, scenario)| {
        let params = with_fee(
            &arm.params,
            FeeModel::Production {
                multiplier: StandardMultiplier::UNIT,
                mix,
            },
        );
        let config = to_years(scenario_named(&params, scenario), years);
        let mut reader = YearReader::new(&params, &config);
        let aggs = a1_year_aggs_probed(&params, &config, &mut reader);
        let onsets = binding_onsets(&aggs, &params);
        let legs = legs_at_flat_onset(&aggs, onsets.flat, &params);
        (onsets, legs, reader.years, params.blocks_per_year())
    });
    let mut rows = Vec::new();
    let mut last_cell = None;
    for (&(arm, mix, scenario), (onsets, legs, years, bpy)) in jobs.iter().zip(folded) {
        if last_cell != Some((arm.which.name(), mix)) {
            writeln!(out, "== {} | {mix} x1.000", arm.which.name())?;
            last_cell = Some((arm.which.name(), mix));
        }
        let legs_text = legs.as_ref().map_or("-".to_string(), |l| {
            format!(
                "fee leg {:.1} SKL/yr ({:.1}%) at y{}",
                skl(l.fee_atomic),
                l.fee_pct(),
                l.year
            )
        });
        let income: Vec<String> = BLOCK_SPACE_YEARS
            .iter()
            .filter_map(|&year| {
                years
                    .iter()
                    .find(|y| y.year == year)
                    .map(|y| format!("y{year} {:.2}", per_block(y.miner_owed_atomic, bpy)))
            })
            .collect();
        writeln!(
            out,
            "  {:<22} onset flat-25 {}, best {}; {legs_text}\n      owed {}",
            crate::stage2::trunc(scenario, 22),
            fmt_onset(onsets.flat),
            fmt_onset(onsets.best),
            income.join(" ")
        )?;
        rows.push(PriorityRow {
            arm: arm.which.name(),
            mix: mix.to_string(),
            scenario: scenario.to_string(),
            onset_flat: onsets.flat,
            onset_best: onsets.best,
            fee_leg_skl_per_year: legs.as_ref().map(|l| skl(l.fee_atomic)),
            fee_leg_pct: legs.as_ref().map(crate::onset::Legs::fee_pct),
            owed_per_block_skl: years
                .iter()
                .map(|y| per_block(y.miner_owed_atomic, bpy))
                .collect(),
        });
    }
    Ok(rows)
}

// ---------------------------------------------------------------- EI-7

/// One perturbation EI-7 runs: a demand blip of `factor_milli` thousandths
/// of the baseline's demand for `blocks` blocks, from the start of `year`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Blip {
    pub(crate) year: u64,
    pub(crate) factor_milli: u64,
    pub(crate) blocks: u64,
}

/// The blips at one length: a doubling at the ratchet year −2…+2 (the
/// inherited 15/80/5 baseline grows in year 19, §5.29.1), and ×1.5 and ×3
/// at the ratchet year.
const fn blips_of(blocks: u64) -> [Blip; 7] {
    const fn blip(year: u64, factor_milli: u64, blocks: u64) -> Blip {
        Blip {
            year,
            factor_milli,
            blocks,
        }
    }
    [
        blip(17, 2_000, blocks),
        blip(18, 2_000, blocks),
        blip(19, 2_000, blocks),
        blip(20, 2_000, blocks),
        blip(21, 2_000, blocks),
        blip(19, 1_500, blocks),
        blip(19, 3_000, blocks),
    ]
}

/// The registered blips last one volume window (§5.32). The long-term
/// median is a median over [`BLOCK_WEIGHT_LONG_TERM_WINDOW`] blocks, which
/// a window's blip cannot move; the blips of half that window were added
/// after the registered run showed it, so the question is asked of a blip
/// that can reach the median.
pub(crate) const REGISTERED_BLIPS: [Blip; 7] = blips_of(TX_VOLUME_WINDOW);
pub(crate) const LONG_BLIPS: [Blip; 7] = blips_of(BLOCK_WEIGHT_LONG_TERM_WINDOW / 2);

/// The demand the stuffing attack offers above the baseline (`scenarios.rs`:
/// five times it), and for how long.
const STUFFING_FACTOR_MILLI: u64 = 5_000;
const STUFFING_BLOCKS: u64 = 21_600;

/// Blips added on review, after the registered run: at the ratchet year, a
/// doubling for longer than half the long-term window (which a median can
/// answer), a halving, and the stuffing attack's demand, for its 21 600
/// blocks and for a long-term window, then stopped.
pub(crate) const REVIEW_BLIPS: [Blip; 6] = [
    Blip {
        year: 19,
        factor_milli: 2_000,
        blocks: BLOCK_WEIGHT_LONG_TERM_WINDOW * 3 / 5,
    },
    Blip {
        year: 19,
        factor_milli: 2_000,
        blocks: BLOCK_WEIGHT_LONG_TERM_WINDOW,
    },
    Blip {
        year: 19,
        factor_milli: 2_000,
        blocks: 2 * BLOCK_WEIGHT_LONG_TERM_WINDOW,
    },
    Blip {
        year: 19,
        factor_milli: 500,
        blocks: BLOCK_WEIGHT_LONG_TERM_WINDOW,
    },
    Blip {
        year: 19,
        factor_milli: STUFFING_FACTOR_MILLI,
        blocks: STUFFING_BLOCKS,
    },
    Blip {
        year: 19,
        factor_milli: STUFFING_FACTOR_MILLI,
        blocks: BLOCK_WEIGHT_LONG_TERM_WINDOW,
    },
];

/// No blip, then the registered blips, the half-window ones, and the
/// review's.
pub(crate) fn every_blip() -> Vec<Option<Blip>> {
    core::iter::once(None)
        .chain(REGISTERED_BLIPS.into_iter().map(Some))
        .chain(LONG_BLIPS.into_iter().map(Some))
        .chain(REVIEW_BLIPS.into_iter().map(Some))
        .collect()
}

/// The baseline scenario with `blip` on its schedule: a declared traffic
/// schedule (§4's exogenous schedules), the baseline's own outside it.
pub(crate) fn blipped(params: &SimParams, blip: Option<Blip>) -> ScenarioConfig {
    let mut config = scenario_named(params, BASELINE_STEADY_STATE);
    if let Some(blip) = blip {
        let demand = baseline_demand(params);
        let length = blip.blocks;
        let start = (blip.year - 1) * params.blocks_per_year();
        let blipped = demand * blip.factor_milli / 1_000;
        config.volume = VolumeSchedule {
            get_volume: Box::new(move |block, _bpy| {
                if block >= start && block < start + length {
                    blipped
                } else {
                    demand
                }
            }),
        };
    }
    config
}

/// EI-7's summary row.
#[derive(Debug, Clone, Serialize)]
pub struct MedianPathRow {
    blip: String,
    growth_year: Option<u64>,
    long_term_median_y30: Option<u64>,
    long_term_median_y60: Option<u64>,
    economy_served: Option<f64>,
}

fn blip_label(blip: Option<Blip>) -> String {
    blip.map_or_else(
        || "none".to_string(),
        |b| {
            format!(
                "x{:.1} at y{} for {}",
                b.factor_milli as f64 / 1_000.0,
                b.year,
                b.blocks
            )
        },
    )
}

/// EI-7: where the long-term median rests after the ratchet, under demand
/// blips around it, on the inherited arm's 15/80/5 baseline.
pub(crate) fn write_median_path(
    out: &mut impl fmt::Write,
    base: &SimParams,
    blips: &[Option<Blip>],
    years: u64,
) -> Result<Vec<MedianPathRow>, fmt::Error> {
    let params = with_fee(
        base,
        FeeModel::Production {
            multiplier: StandardMultiplier::UNIT,
            mix: RungMix::DEFAULTED,
        },
    );
    writeln!(
        out,
        "\nEI-7 — MEDIAN PATH-DEPENDENCE. The inherited arm's 15/80/5 baseline with a demand blip, the\n\
         demand multiplied for a number of blocks from the start of a year. Registered: one volume\n\
         window ({TX_VOLUME_WINDOW}). Added after the registered run: half the long-term window ({}), the\n\
         longest blip that cannot move a median over {BLOCK_WEIGHT_LONG_TERM_WINDOW} blocks; then, on review, doublings of\n\
         {}, {} and {} blocks, a halving, and the stuffing attack's x5 for {STUFFING_BLOCKS} blocks and for\n\
         {}, each then stopped. Per run: the year blocks grow, the long-term median at y30 and\n\
         y{ONSET_HORIZON_YEARS} (KB), and Economy carried over Economy demanded over the run.",
        BLOCK_WEIGHT_LONG_TERM_WINDOW / 2,
        BLOCK_WEIGHT_LONG_TERM_WINDOW * 3 / 5,
        BLOCK_WEIGHT_LONG_TERM_WINDOW,
        2 * BLOCK_WEIGHT_LONG_TERM_WINDOW,
        BLOCK_WEIGHT_LONG_TERM_WINDOW,
    )?;
    let folded = crate::parallel::map(blips, |&blip| {
        let config = to_years(blipped(&params, blip), years);
        a1_year_aggs_probed(&params, &config, &mut NoProbe)
    });
    let mut rows = Vec::new();
    for (&blip, aggs) in blips.iter().zip(folded) {
        let gate = cell_gate(&params, &aggs, StandardMultiplier::UNIT);
        let median = |year: u64| {
            aggs.iter()
                .find(|a| a.year == year)
                .map(|a| a.long_term_median)
        };
        let served = economy_served(&aggs);
        writeln!(
            out,
            "  blip {:<24} blocks grow {:<6} median y30 {:>5} y{ONSET_HORIZON_YEARS} {:>5}; Economy served {}",
            blip_label(blip),
            year_label(gate.growth),
            median(30).map_or("-".to_string(), |m| format!("{}K", m / 1_000)),
            median(ONSET_HORIZON_YEARS).map_or("-".to_string(), |m| format!("{}K", m / 1_000)),
            served.map_or("-".to_string(), |s| format!("{:.1}%", 100.0 * s)),
        )?;
        rows.push(MedianPathRow {
            blip: blip_label(blip),
            growth_year: gate.growth,
            long_term_median_y30: median(30),
            long_term_median_y60: median(ONSET_HORIZON_YEARS),
            economy_served: served,
        });
    }
    Ok(rows)
}

/// Both `w_ref` arms.
pub(crate) fn both_arms(base: &SimParams) -> Vec<Arm> {
    arms(base).into_iter().collect()
}

/// Every scenario's name.
pub(crate) fn all_scenario_names(base: &SimParams) -> Vec<String> {
    every_scenario(base)
}

// ---------------------------------------------------------------- the modes

/// One instrument, run alone by its mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instrument {
    MinerIncome,
    Predictability,
    DemandResponse,
    Capacity,
    StuffingEnvelope,
    PriorityElasticity,
    MedianPath,
}

impl Instrument {
    pub const ALL: [Self; 7] = [
        Self::MinerIncome,
        Self::Predictability,
        Self::DemandResponse,
        Self::Capacity,
        Self::StuffingEnvelope,
        Self::PriorityElasticity,
        Self::MedianPath,
    ];

    /// The instrument's mode.
    #[must_use]
    pub const fn flag(self) -> &'static str {
        match self {
            Self::MinerIncome => "--miner-income",
            Self::Predictability => "--predictability",
            Self::DemandResponse => "--demand-response",
            Self::Capacity => "--capacity",
            Self::StuffingEnvelope => "--stuffing-envelope",
            Self::PriorityElasticity => "--priority-elasticity",
            Self::MedianPath => "--median-path",
        }
    }
}

/// What a run prints as JSON: each instrument it ran.
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    miner_income: Option<Vec<MinerIncomeRow>>,
    predictability: Option<Vec<PredictabilityRow>>,
    step_response: Option<Vec<crate::window_stuffer::StepRow>>,
    window_edge_stuffer: Option<Vec<crate::window_stuffer::StufferRow>>,
    every_miner_stuffs: Option<Vec<crate::window_stuffer::AllMinersRow>>,
    capacity: Option<Vec<CapacityRow>>,
    stuffing: Option<Vec<crate::window_stuffer::StuffingRow>>,
    priority_elasticity: Option<Vec<PriorityRow>>,
    median_path: Option<Vec<MedianPathRow>>,
}

/// The scenarios EI-5's envelope rows read ([`crate::miner_stuffer::ROWS`]).
fn envelope_scenarios() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (scenario, _, _) in crate::miner_stuffer::ROWS {
        if !names.iter().any(|n| n == scenario) {
            names.push(scenario.to_string());
        }
    }
    names
}

/// How much of `--eup4` a run folds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every scenario: `--eup4`, and the on-demand pin.
    Full,
    /// The nightly lane's pin: the shared runs on the baseline and the
    /// stuffing attack, and the stuffer's campaigns from year 5 alone.
    #[cfg(test)]
    Nightly,
}

impl Scope {
    /// The years a report folds to.
    const fn years(self) -> u64 {
        match self {
            Self::Full => ONSET_HORIZON_YEARS,
            #[cfg(test)]
            Self::Nightly => ONSET_HORIZON_YEARS,
        }
    }
}

/// The scenarios the nightly scope's shared runs fold.
#[cfg(test)]
const NIGHTLY_SCENARIOS: [&str; 2] = [BASELINE_STEADY_STATE, crate::scenarios::STUFFING_ATTACK];

/// Run `instrument`, or every instrument for `None` (`--eup4`). Under
/// `--eup4` EI-6 folds the baseline alone; its mode folds every scenario.
///
/// # Errors
///
/// The sink's.
pub fn run(
    out: &mut impl fmt::Write,
    base: &SimParams,
    instrument: Option<Instrument>,
) -> Result<Summary, fmt::Error> {
    run_scoped(out, base, instrument, Scope::Full)
}

/// [`run`] at `scope`.
///
/// # Errors
///
/// The sink's.
pub fn run_scoped(
    out: &mut impl fmt::Write,
    base: &SimParams,
    instrument: Option<Instrument>,
    scope: Scope,
) -> Result<Summary, fmt::Error> {
    let runs = |i: Instrument| instrument.is_none_or(|only| only == i);
    let arms = both_arms(base);
    let every = match scope {
        Scope::Full => all_scenario_names(base),
        #[cfg(test)]
        Scope::Nightly => NIGHTLY_SCENARIOS.map(String::from).to_vec(),
    };
    let years = scope.years();
    let mut summary = Summary::default();
    let shared_needed = runs(Instrument::MinerIncome)
        || runs(Instrument::Predictability)
        || runs(Instrument::Capacity)
        || runs(Instrument::StuffingEnvelope);
    let shared = shared_needed.then(|| match instrument {
        Some(Instrument::StuffingEnvelope) => SharedRuns::fold(
            base,
            &arms,
            &[FeeArm::Production],
            &envelope_scenarios(),
            years,
        ),
        Some(Instrument::Capacity) => SharedRuns::fold(
            base,
            &arms,
            &FeeArm::ALL,
            &[BASELINE_STEADY_STATE.to_string()],
            years,
        ),
        _ => SharedRuns::fold(base, &arms, &FeeArm::ALL, &every, years),
    });
    writeln!(
        out,
        "EUP-4 PREP 2 — THE CRITERIA'S INSTRUMENTS (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.32).\n\
         Measures only: no line grades a criterion. Arms: inherited (the run's w_ref and zone) and\n\
         re-derived (the declared pair, ESR-10)."
    )?;
    if let Some(shared) = &shared {
        if runs(Instrument::MinerIncome) {
            summary.miner_income = Some(write_miner_income(out, shared)?);
        }
        if runs(Instrument::Predictability) {
            summary.predictability = Some(write_predictability(
                out,
                shared,
                base.economic().emission_curve_asymptote,
            )?);
        }
        if runs(Instrument::Capacity) {
            summary.capacity = Some(write_capacity(out, shared, base)?);
        }
    }
    let stuffer =
        (runs(Instrument::DemandResponse) || runs(Instrument::StuffingEnvelope)).then(|| {
            use crate::window_stuffer::{CAMPAIGN_START_YEARS, STUFFER_SHARES_PCT};
            let (starts, shares): (&[u64], &[u64]) = match scope {
                Scope::Full => (&CAMPAIGN_START_YEARS, &STUFFER_SHARES_PCT),
                #[cfg(test)]
                Scope::Nightly => (&CAMPAIGN_START_YEARS[..1], &STUFFER_SHARES_PCT),
            };
            crate::window_stuffer::stuffer_rows(&arms, starts, shares)
        });
    if runs(Instrument::DemandResponse) {
        summary.step_response = Some(crate::window_stuffer::write_step_response(out, &arms)?);
        if let Some(rows) = &stuffer {
            crate::window_stuffer::write_stuffer(out, rows)?;
            summary.window_edge_stuffer = Some(rows.clone());
        }
        let starts: &[u64] = match scope {
            Scope::Full => &crate::window_stuffer::CAMPAIGN_START_YEARS,
            #[cfg(test)]
            Scope::Nightly => &crate::window_stuffer::CAMPAIGN_START_YEARS[..1],
        };
        let every_miner = crate::window_stuffer::all_miners_rows(&arms, starts);
        crate::window_stuffer::write_all_miners(out, &every_miner)?;
        summary.every_miner_stuffs = Some(every_miner);
    }
    if runs(Instrument::StuffingEnvelope) {
        if let (Some(shared), Some(rows)) = (&shared, &stuffer) {
            summary.stuffing = Some(crate::window_stuffer::write_stuffing_floors(
                out, shared, &arms, rows,
            )?);
        }
    }
    if runs(Instrument::PriorityElasticity) {
        let scenarios = if instrument.is_none() {
            vec![BASELINE_STEADY_STATE.to_string()]
        } else {
            every.clone()
        };
        let cells: &[RungMix] = match scope {
            Scope::Full => &PRIORITY_CELLS,
            #[cfg(test)]
            Scope::Nightly => &PRIORITY_CELLS,
        };
        summary.priority_elasticity = Some(write_priority_elasticity(
            out, &arms, cells, &scenarios, years,
        )?);
    }
    if runs(Instrument::MedianPath) {
        let blips = match scope {
            Scope::Full => every_blip(),
            #[cfg(test)]
            Scope::Nightly => every_blip(),
        };
        summary.median_path = Some(write_median_path(out, base, &blips, years)?);
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_fixture::{self, regenerate, Output};
    use crate::stage2::a1_year_aggs;

    fn path(scope: Scope) -> &'static str {
        match scope {
            Scope::Full => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/eup4_narration.txt"
            ),
            Scope::Nightly => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/eup4_narration_nightly.txt"
            ),
        }
    }

    fn narration(scope: Scope) -> String {
        let mut narration = String::new();
        run_scoped(&mut narration, &SimParams::default(), None, scope)
            .expect("String sink is infallible");
        narration
    }

    /// The whole `--eup4` report against its committed copy. Reviewed as
    /// output, never trusted as an oracle for the line it was regenerated
    /// to match. Ignored by default and run on demand, not nightly: about
    /// 4 300 fold-years, about 18 minutes on 16 threads. The committed
    /// fixture is generated and checked on Linux x86-64.
    #[test]
    #[ignore = "full --eup4 report, about 4 300 fold-years — on demand, not nightly; run with --release --ignored; fixture generated and checked on Linux x86-64"]
    fn eup4_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches(
            "--eup4 narration",
            path(Scope::Full),
            &narration(Scope::Full),
        );
    }

    /// The nightly scope against its committed copy ([`Scope::Nightly`]).
    #[test]
    #[ignore = "--eup4's nightly scope — run with --release --ignored; nightly economics-sim-ignored; fixture generated and checked on Linux x86-64"]
    fn eup4_nightly_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches(
            "--eup4 nightly narration",
            path(Scope::Nightly),
            &narration(Scope::Nightly),
        );
    }

    /// Regenerate both committed narrations, armed (rule 50). Ignored by
    /// default; run with `SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD
    /// <rationale>" cargo test --release -p shekyl-economics-sim -- --ignored
    /// regen_eup4_narration_fixtures`, the date naming the
    /// `ECONOMICS_SIM_PRODUCTION_REBASE.md` entry that records what moved.
    #[test]
    #[ignore = "armed regeneration helper; writes the committed fixtures; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_eup4_narration_fixtures() {
        regenerate(
            "the --eup4 narrations",
            &[
                Output {
                    path: path(Scope::Full),
                    build: || narration(Scope::Full),
                },
                Output {
                    path: path(Scope::Nightly),
                    build: || narration(Scope::Nightly),
                },
            ],
        );
    }

    fn two_years(params: &SimParams) -> ScenarioConfig {
        let mut config = scenario_named(params, BASELINE_STEADY_STATE);
        config.sim_years = 2;
        config
    }

    /// The readers change nothing: a fold a reader is asked at is the fold
    /// every other mode folds, aggregate for aggregate.
    #[test]
    fn a_probed_fold_is_the_plain_fold() {
        let params = SimParams::default();
        let config = two_years(&params);
        let mut reader = YearReader::new(&params, &config);
        let probed = a1_year_aggs_probed(&params, &config, &mut reader);
        let plain = a1_year_aggs(&params, &config);
        assert_eq!(
            serde_json::to_string(&probed).expect("serialises"),
            serde_json::to_string(&plain).expect("serialises"),
        );
        assert_eq!(reader.years.len(), 2, "one read a year");
        for (read, agg) in reader.years.iter().zip(&plain) {
            assert_eq!(read.year, agg.year);
            assert!(read.miner_fee_atomic <= read.miner_owed_atomic);
            assert_eq!(read.tail_blocks, 0, "the tail is decades away");
        }
    }

    /// A scenario that starts past a fraction has crossed it before the
    /// fold; one that has not reached it by its horizon has not.
    #[test]
    fn a_crossing_is_read_from_the_fold_start() {
        let params = SimParams::default();
        let late = scenario_named(&params, crate::scenarios::LATE_CHAIN_TAIL);
        let reader = YearReader::new(&params, &late);
        assert_eq!(reader.crossings(), [Crossing::BeforeTheFold; 2]);
        let config = two_years(&params);
        let mut reader = YearReader::new(&params, &config);
        a1_year_aggs_probed(&params, &config, &mut reader);
        assert_eq!(reader.crossings(), [Crossing::NotReached; 2]);
    }

    /// EI-7's blip is the baseline's demand times its factor for one volume
    /// window from its year's first block, and the baseline's elsewhere.
    #[test]
    fn a_blip_lasts_one_volume_window() {
        let params = SimParams::default();
        let bpy = params.blocks_per_year();
        let demand = params.economic().tx_volume_baseline;
        let config = blipped(
            &params,
            Some(Blip {
                year: 3,
                factor_milli: 1_500,
                blocks: TX_VOLUME_WINDOW,
            }),
        );
        let at = |block: u64| (config.volume.get_volume)(block, bpy);
        let start = 2 * bpy;
        assert_eq!(at(start - 1), demand);
        assert_eq!(at(start), demand * 3 / 2);
        assert_eq!(at(start + TX_VOLUME_WINDOW - 1), demand * 3 / 2);
        assert_eq!(at(start + TX_VOLUME_WINDOW), demand);
        let plain = blipped(&params, None);
        assert_eq!((plain.volume.get_volume)(start, bpy), demand);
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! ESR-10: the fee multiplier and the rung mix, on both `w_ref` arms
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.29;
//! `docs/design/ESR10_PREDICTIONS.md`).
//!
//! Every cell is the production run but for its named alternatives: the
//! Standard multiplier, the rung mix, and the arm. The inherited arm is the
//! run's own `w_ref` and zone. The re-derived arm is two overrides on it,
//! derived by [`rederived_pair`] and never typed: declared, until the
//! owners' ruling on `w_ref` and the zone replaces it (EUP-5 G).
//!
//! The run is computed, then printed. Each `(arm, cell, scenario)` folds to
//! the onset horizon on its own core, and every reading the narration takes
//! of it (the growth gate, A1's onsets, the year-1 Standard fee) is taken
//! there, once ([`ScenarioRun`]). The narration's four sections print from
//! those runs in a fixed order, so it is the same whatever the thread
//! count.

use std::fmt;

use serde::Serialize;
use shekyl_economics::{projected_already_generated, ClosedShardCount};

use crate::baseline::Override;
use crate::burden::{ordinary_tx_weight, COIN};
use crate::calibration::tree_depth_for_leaves;
use crate::chain_cursor::{ChainCursor, ChainStep};
use crate::engine::ScenarioConfig;
use crate::engine::{emitted_at_start, SimParams};
use crate::escalation::flat_25;
use crate::fee_model::{FeeModel, OrdinaryTx, StandardMultiplier, MILLI};
use crate::growth_gate::{cell_gate, m_star, year_label, CellGate};
use crate::onset::{
    age_quantile, at_horizon, binding_onsets, fmt_onset, BindingOnsets, Onset, BLOCK_SPACE_YEARS,
    ONSET_HORIZON_YEARS,
};
use crate::rung_mix::{Rung, RungMix};
use crate::scenarios::{all_scenarios, BASELINE_STEADY_STATE};
use crate::stage2::{a1_shipped_budget_atomic, a1_year_aggs, kilobytes, trunc, A1YearAgg};

/// The inherited ratio of the zone to the reference weight, kept by the
/// re-derived arm and declared as inherited (`ESR10_PREDICTIONS.md` §0.3).
const ZONE_OVER_W_REF: u64 = 100;

/// Passes the re-derived pair may take to settle. The weight moves only
/// through the fee's varint, so two passes settle it; more is a defect.
const PAIR_PASSES: u32 = 8;

/// The year-1 fee ceiling, in basis points of the year-1 mean block reward:
/// 0.05 % (umbrella §4, Usability, ratified 2026-11-06).
const CEILING_BASIS_POINTS: u64 = 5;

/// Basis points in one.
const BASIS_POINTS: u64 = 10_000;

/// The Standard multipliers the brief sweeps on the all-Standard mix, beside
/// `m*` (P2), which the run derives.
const SWEPT_MULTIPLIERS: [StandardMultiplier; 5] = [
    StandardMultiplier::UNIT,
    StandardMultiplier::from_milli(1_250),
    StandardMultiplier::from_milli(1_500),
    StandardMultiplier::from_milli(2_000),
    StandardMultiplier::from_milli(3_000),
];

/// The rung mixes the brief registers, each at the unit multiplier.
const REGISTERED_MIXES: [RungMix; 2] = [RungMix::DEFAULTED, RungMix::ZERO_PRIORITY];

/// The year a scenario's closed shards are sampled at beside the horizon
/// (R5's operand).
const SHARD_SAMPLE_YEAR: u64 = 10;

/// The year-1 Standard fee ceiling, atomic units: 0.05 % of the mean block
/// reward over the first year on the shipped design curve
/// ([`projected_already_generated`] over its blocks). Ratified as a number,
/// so it is read on the shipped baseline, whatever a run overrides.
#[must_use]
pub(crate) fn year_one_fee_ceiling() -> u64 {
    let shipped = SimParams::default();
    let blocks = shipped.blocks_per_year();
    let generated = projected_already_generated(blocks, shipped.economic())
        .expect("the first year's projection is in the emission's domain");
    u64::try_from(
        u128::from(generated) * u128::from(CEILING_BASIS_POINTS)
            / (u128::from(blocks) * u128::from(BASIS_POINTS)),
    )
    .expect("a fee fits")
}

/// The scenario called `name` under `params`.
fn scenario_named(params: &SimParams, name: &str) -> ScenarioConfig {
    all_scenarios(params)
        .into_iter()
        .find(|config| config.name == name)
        .expect("a stage-2 scenario's name")
}

/// Every stage-2 scenario's name, in [`all_scenarios`]' order: what a full
/// run folds.
pub(crate) fn every_scenario(params: &SimParams) -> Vec<String> {
    all_scenarios(params)
        .into_iter()
        .map(|config| config.name)
        .collect()
}

/// The re-derived `w_ref′` and `zone′`, and what they were derived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RederivedPair {
    /// The ordinary 1-in/2-out weight at genesis depth, at its own fee.
    pub(crate) w_ref: u64,
    /// `ZONE_OVER_W_REF × w_ref`.
    pub(crate) zone: u64,
    /// The curve-tree depth the weight is taken at.
    pub(crate) depth: u8,
    /// The Standard fee the fold prices at its first block under the pair.
    pub(crate) fee_atomic: u64,
    /// Passes until the weight repeated.
    pub(crate) passes: u32,
}

impl RederivedPair {
    /// The two overrides that make the arm.
    pub(crate) fn overrides(self) -> Vec<Override> {
        pair_overrides(self.w_ref)
    }
}

fn pair_overrides(w_ref: u64) -> Vec<Override> {
    [
        format!("relay.ref_tx_weight={w_ref}"),
        format!("economic.full_reward_zone={}", ZONE_OVER_W_REF * w_ref),
    ]
    .iter()
    .map(|text| Override::parse(text).expect("well-formed"))
    .collect()
}

/// The Standard transaction the baseline scenario's first block is built
/// with under `params`.
fn genesis_standard_tx(params: &SimParams) -> OrdinaryTx {
    let config = scenario_named(params, BASELINE_STEADY_STATE);
    let economic = params.economic();
    ChainCursor::default()
        .price(
            ChainStep {
                chain_height: config.genesis_height_offset,
                demand: 0,
                leaves: 0,
                already_generated: emitted_at_start(
                    economic.emission_curve_asymptote,
                    config.initial_emitted_ppm,
                ),
                total_burned: 0,
                closed_shards: ClosedShardCount::ZERO,
            },
            params,
            economic,
        )
        .tx
}

/// `w_ref′` and `zone′` for `base`: the ordinary transaction's weight at
/// genesis depth, at the Standard fee the fold prices its first block at
/// under the pair itself. The fee's varint is in the weight and the fee
/// reads the pair, so the weight is iterated from the zero-fee weight until
/// it repeats.
///
/// # Panics
///
/// When the weight does not settle in [`PAIR_PASSES`], or the pair fails a
/// validator.
#[must_use]
pub(crate) fn rederived_pair(base: &SimParams) -> RederivedPair {
    let depth = tree_depth_for_leaves(0);
    let mut w_ref = ordinary_tx_weight(0, 0);
    for passes in 1..=PAIR_PASSES {
        let arm = base
            .with_more(pair_overrides(w_ref))
            .expect("the re-derived pair passes the validators");
        let tx = genesis_standard_tx(&arm);
        if tx.weight == w_ref {
            return RederivedPair {
                w_ref,
                zone: ZONE_OVER_W_REF * w_ref,
                depth,
                fee_atomic: tx.fee_atomic,
                passes,
            };
        }
        w_ref = tx.weight;
    }
    panic!("the re-derived weight did not settle in {PAIR_PASSES} passes")
}

/// Which `w_ref` and zone an arm runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WRefArm {
    /// The run's own.
    Inherited,
    /// The declared re-derived pair.
    Rederived(RederivedPair),
}

impl WRefArm {
    /// The arm's name in the narration and the summary.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Inherited => "inherited",
            Self::Rederived(_) => "re-derived",
        }
    }
}

/// One of the two constant arms, and the run parameters it makes.
pub(crate) struct Arm {
    pub(crate) which: WRefArm,
    pub(crate) params: SimParams,
}

impl Arm {
    /// `base` itself.
    pub(crate) fn inherited(base: &SimParams) -> Self {
        Self {
            which: WRefArm::Inherited,
            params: base.clone(),
        }
    }
}

/// The inherited arm (`base` itself) and the re-derived one.
pub(crate) fn arms(base: &SimParams) -> [Arm; 2] {
    let pair = rederived_pair(base);
    [
        Arm::inherited(base),
        Arm {
            which: WRefArm::Rederived(pair),
            params: base
                .with_more(pair.overrides())
                .expect("the re-derived pair passes the validators"),
        },
    ]
}

/// One fee cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cell {
    /// A swept Standard multiplier, all Standard.
    Swept(StandardMultiplier),
    /// `m*`, all Standard (P2).
    MStar(StandardMultiplier),
    /// A registered rung mix at the unit multiplier.
    Mixed(RungMix),
}

impl Cell {
    /// The cell's Standard multiplier.
    pub(crate) const fn multiplier(self) -> StandardMultiplier {
        match self {
            Self::Swept(multiplier) | Self::MStar(multiplier) => multiplier,
            Self::Mixed(_) => StandardMultiplier::UNIT,
        }
    }

    /// The cell's fee arm.
    pub(crate) const fn fee(self) -> FeeModel {
        FeeModel::Production {
            multiplier: self.multiplier(),
            mix: match self {
                Self::Swept(_) | Self::MStar(_) => RungMix::ALL_STANDARD,
                Self::Mixed(mix) => mix,
            },
        }
    }

    /// `x1.000 all-Standard`, `x1.352 all-Standard (m*)`, `15/80/5 x1.000`.
    pub(crate) fn label(self) -> String {
        match self {
            Self::Swept(multiplier) => format!("{multiplier} all-Standard"),
            Self::MStar(multiplier) => format!("{multiplier} all-Standard (m*)"),
            Self::Mixed(mix) => format!("{mix} {}", StandardMultiplier::UNIT),
        }
    }
}

/// The cells: the swept multipliers with `m*`, when one exists, in its place
/// among them, then the registered mixes.
pub(crate) fn cells(m_star: Option<StandardMultiplier>) -> Vec<Cell> {
    let mut multiplied: Vec<Cell> = SWEPT_MULTIPLIERS.into_iter().map(Cell::Swept).collect();
    if let Some(m_star) = m_star {
        let at = multiplied.partition_point(|cell| cell.multiplier() <= m_star);
        multiplied.insert(at, Cell::MStar(m_star));
    }
    multiplied
        .into_iter()
        .chain(REGISTERED_MIXES.map(Cell::Mixed))
        .collect()
}

/// `m*` from the inherited arm's year 1 on the baseline scenario: one
/// year of the unit cell's fold. `None` when no multiplier reaches `θ`
/// there ([`m_star`]).
pub(crate) fn m_star_from(base: &SimParams) -> Option<StandardMultiplier> {
    let mut config = scenario_named(base, BASELINE_STEADY_STATE);
    config.sim_years = 1;
    let year_one = a1_year_aggs(base, &config);
    m_star(base, year_one.first().expect("one year folded"))
}

/// One scenario folded in one cell, and every reading the narration takes
/// of it, taken once.
struct ScenarioRun {
    scenario: String,
    aggs: Vec<A1YearAgg>,
    gate: CellGate,
    onsets: BindingOnsets,
    /// [`year_one_standard_fee`] of `aggs`.
    year_one_fee: Option<u64>,
}

impl ScenarioRun {
    fn fold(params: &SimParams, cell: Cell, scenario: &str) -> Self {
        let config = at_horizon(scenario_named(params, scenario));
        let aggs = a1_year_aggs(params, &config);
        Self {
            gate: cell_gate(params, &aggs, cell.multiplier()),
            onsets: binding_onsets(&aggs, params),
            year_one_fee: year_one_standard_fee(&aggs),
            scenario: config.name,
            aggs,
        }
    }
}

/// One cell on one arm: the parameters it runs and each scenario's run.
struct CellRun<'a> {
    arm: &'a Arm,
    cell: Cell,
    params: SimParams,
    scenarios: Vec<ScenarioRun>,
}

/// `arm`'s parameters with `cell`'s fee arm.
fn cell_params(arm: &Arm, cell: Cell) -> SimParams {
    let mut params = arm.params.clone();
    params.fee = cell.fee();
    params
}

/// Every `(arm, cell)` over `scenarios`, arm by arm, cell by cell.
fn fold_every_cell<'a>(arms: &'a [Arm], cells: &[Cell], scenarios: &[String]) -> Vec<CellRun<'a>> {
    let mut runs: Vec<CellRun<'a>> = arms
        .iter()
        .flat_map(|arm| {
            cells.iter().map(move |&cell| CellRun {
                arm,
                cell,
                params: cell_params(arm, cell),
                scenarios: Vec::with_capacity(scenarios.len()),
            })
        })
        .collect();
    let jobs: Vec<(usize, &str)> = (0..runs.len())
        .flat_map(|run| scenarios.iter().map(move |name| (run, name.as_str())))
        .collect();
    let folded = crate::parallel::map(&jobs, |&(run, scenario)| {
        ScenarioRun::fold(&runs[run].params, runs[run].cell, scenario)
    });
    for (&(run, _), scenario) in jobs.iter().zip(folded) {
        runs[run].scenarios.push(scenario);
    }
    runs
}

/// One row of the summary EUP-5 reads, written to stdout as JSON.
#[derive(Debug, Clone, Serialize)]
pub struct SummaryRow {
    arm: &'static str,
    cell: String,
    scenario: String,
    /// The year blocks first grow past the constrained ceiling.
    growth_year: Option<u64>,
    /// The first year whose last block leaves nothing waiting.
    queue_empties_year: Option<u64>,
    /// Economy carried over Economy demanded over the horizon; `None` when
    /// the cell sends Economy nothing.
    economy_served: Option<f64>,
    /// A1's onset under the shipped flat-25 budget, and whether a later
    /// year clears again.
    onset_flat: Onset,
    /// A1's onset under the best band candidate.
    onset_best: Onset,
    /// The Standard fees carried in year 1 over the Standard transactions
    /// carried, atomic units.
    year_one_standard_fee_atomic: Option<u64>,
    /// That fee over the ratified ceiling.
    ratio_to_ceiling: Option<f64>,
}

impl SummaryRow {
    fn of(cell: &CellRun<'_>, run: &ScenarioRun, ceiling: u64) -> Self {
        Self {
            arm: cell.arm.which.name(),
            cell: cell.cell.label(),
            scenario: run.scenario.clone(),
            growth_year: run.gate.growth,
            queue_empties_year: queue_empties(&run.aggs),
            economy_served: economy_served(&run.aggs),
            onset_flat: run.onsets.flat,
            onset_best: run.onsets.best,
            year_one_standard_fee_atomic: run.year_one_fee,
            ratio_to_ceiling: run.year_one_fee.map(|fee| ratio(fee, ceiling)),
        }
    }
}

fn skl(atomic: u128) -> f64 {
    atomic as f64 / COIN as f64
}

fn ratio(fee: u64, ceiling: u64) -> f64 {
    fee as f64 / ceiling as f64
}

/// The Standard fees carried in year 1 over the Standard transactions
/// carried, atomic units.
fn year_one_standard_fee(aggs: &[A1YearAgg]) -> Option<u64> {
    let year = &aggs.first()?.rungs[Rung::Standard];
    (year.carried_txs > 0)
        .then(|| u64::try_from(year.fees_atomic / year.carried_txs).expect("one fee fits"))
}

/// Economy carried over Economy demanded, over every year.
fn economy_served(aggs: &[A1YearAgg]) -> Option<f64> {
    let (carried, demand) = aggs.iter().fold((0u128, 0u128), |(c, d), a| {
        let economy = &a.rungs[Rung::Economy];
        (c + economy.carried_txs, d + economy.demand_txs)
    });
    (demand > 0).then(|| carried as f64 / demand as f64)
}

fn queue_empties(aggs: &[A1YearAgg]) -> Option<u64> {
    aggs.iter()
        .find(|a| a.waiting_at_year_end == 0)
        .map(|a| a.year)
}

fn option_year(year: Option<u64>) -> String {
    year.map_or_else(|| "never".to_string(), |y| format!("y{y}"))
}

/// `E/S/P` of `f`, each to `width` and `places`.
fn per_rung(width: usize, places: usize, f: impl Fn(Rung) -> f64) -> String {
    Rung::ALL
        .map(|rung| format!("{:>width$.places$}", f(rung)))
        .join("/")
}

/// The `--esr10` narration over `scenarios`: both arms, every cell. Returns
/// the summary rows.
///
/// # Errors
///
/// The sink's.
pub fn run_esr10(
    out: &mut impl fmt::Write,
    base: &SimParams,
    scenarios: &[String],
) -> Result<Vec<SummaryRow>, fmt::Error> {
    narrate(out, base, &arms(base), &cells(m_star_from(base)), scenarios)
}

/// The scenarios the reach probe folds: the nightly pair with boom-bust and
/// the late-chain tail. Measured 2026-11-08: the release multiplier's
/// ceiling, the burn cap, the surge factor and the tail subsidy move the
/// 15/80/5 cell only in those two (and in sustained growth and
/// high-history, which add nothing these two do not show).
#[cfg(test)]
pub(crate) const REACH_SCENARIOS: [&str; 4] = [
    BASELINE_STEADY_STATE,
    crate::scenarios::STUFFING_ATTACK,
    crate::scenarios::BOOM_BUST_CYCLE,
    crate::scenarios::LATE_CHAIN_TAIL,
];

/// The reach probe `--esr10`'s reader list is measured on
/// (`baseline::tests::every_declared_reader_moves_its_report`): the
/// inherited arm's 15/80/5 cell on [`REACH_SCENARIOS`], printed as
/// `--esr10` prints it. The cell prices all three rungs with every field the
/// other cells read, and its lines are lines of the narration, so a field
/// that moves the probe moves the report.
#[cfg(test)]
pub(crate) fn run_reach_probe(out: &mut impl fmt::Write, base: &SimParams) -> fmt::Result {
    narrate(
        out,
        base,
        &[Arm::inherited(base)],
        &[Cell::Mixed(RungMix::DEFAULTED)],
        &REACH_SCENARIOS.map(String::from),
    )
    .map(|_| ())
}

/// The narration over `arms` × `cells`, each folding `scenarios`.
fn narrate(
    out: &mut impl fmt::Write,
    base: &SimParams,
    arms: &[Arm],
    cells: &[Cell],
    scenarios: &[String],
) -> Result<Vec<SummaryRow>, fmt::Error> {
    let ceiling = year_one_fee_ceiling();
    let runs = fold_every_cell(arms, cells, scenarios);
    let every = every_scenario(base).as_slice() == scenarios;
    write_header(out, arms, cells, scenarios, every, ceiling)?;
    write_headline(out, &runs, ceiling)?;
    let rows: Vec<SummaryRow> = runs
        .iter()
        .flat_map(|cell| {
            cell.scenarios
                .iter()
                .map(move |run| SummaryRow::of(cell, run, ceiling))
        })
        .collect();
    write_summary(out, &rows)?;
    write_cells(out, &runs, ceiling, base.blocks_per_year())?;
    Ok(rows)
}

/// The title, the arms, the cells, the ceiling and how to read the tables.
fn write_header(
    out: &mut impl fmt::Write,
    arms: &[Arm],
    cells: &[Cell],
    scenarios: &[String],
    every: bool,
    ceiling: u64,
) -> fmt::Result {
    writeln!(
        out,
        "ESR-10 — the fee multiplier and the rung mix, on both w_ref arms\n\
         (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.29; ESR10_PREDICTIONS.md). Every cell is production but for\n\
         its named alternatives; {SCOPE} folds to {ONSET_HORIZON_YEARS} y.",
        SCOPE = if every {
            "every scenario".to_string()
        } else {
            format!("{} only,", scenarios.join(", "))
        },
    )?;
    writeln!(out, "ARMS:")?;
    for arm in arms {
        let name = arm.which.name();
        match arm.which {
            WRefArm::Inherited => writeln!(
                out,
                "  {name:<11} w_ref {} B, zone {} B: the run's own.",
                arm.params.relay().ref_tx_weight,
                arm.params.economic().full_reward_zone,
            )?,
            WRefArm::Rederived(pair) => writeln!(
                out,
                "  {name:<11} declared; the owners' ruling replaces it (EUP-5 G). w_ref' = {} B, the ordinary\n\
                 \x20             1in/2out weight at genesis tree depth {} at its own genesis Standard fee {:.4} SKL\n\
                 \x20             (a fixed point: {} pass(es) from the zero-fee weight); zone' = {ZONE_OVER_W_REF} x w_ref' = {} B,\n\
                 \x20             the inherited ratio. --set {}",
                pair.w_ref,
                pair.depth,
                skl(u128::from(pair.fee_atomic)),
                pair.passes,
                pair.zone,
                pair.overrides()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" --set "),
            )?,
        }
    }
    let m_star = if cells.iter().any(|cell| matches!(cell, Cell::MStar(_))) {
        "m* = ceil(1000 theta(y1)/rho(y1))"
    } else {
        "m* none: no multiplier reaches theta(y1)"
    };
    writeln!(
        out,
        "CELLS: {}.\n\
         \x20 {m_star} on the inherited arm's year 1. Mixes are Economy/Standard/Priority\n\
         \x20 percent; demand splits by largest remainder on the cumulative target, and one block's arrivals are\n\
         \x20 admitted Priority, Standard, Economy: a declared order, which can move the pool (§5.29).",
        cells.iter().map(|c| c.label()).collect::<Vec<_>>().join(", "),
    )?;
    writeln!(
        out,
        "CEILING (umbrella §4, ratified 2026-11-06): the year-1 Standard fee <= 0.05% of the year-1 mean block\n\
         \x20 reward on the design curve = {ceiling} atomic ({:.4} SKL). The year-1 Standard fee is the Standard\n\
         \x20 fees carried in year 1 over the Standard transactions carried.",
        skl(u128::from(ceiling)),
    )?;
    writeln!(
        out,
        "READING: grows = the year carried first passes the constrained ceiling by more than one tx/block;\n\
         \x20 empties = the first year whose last block leaves nothing waiting; Econ served = Economy carried /\n\
         \x20 demanded over {ONSET_HORIZON_YEARS} y; onset = A1-T's first sustained year under 1 at 10% (flat-25, best).",
    )
}

/// The headline: each cell's year-1 Standard fee on the baseline against
/// the ceiling, and its range over every scenario folded.
fn write_headline(out: &mut impl fmt::Write, runs: &[CellRun<'_>], ceiling: u64) -> fmt::Result {
    writeln!(
        out,
        "\nYEAR-1 STANDARD FEE against the ceiling: the baseline's, and the range of x ceiling over every scenario."
    )?;
    writeln!(
        out,
        "  {:<11} {:<26} {:>12} {:>8}   range x ceil",
        "arm", "cell", "baseline SKL", "x ceil"
    )?;
    for cell in runs {
        let baseline = cell
            .scenarios
            .iter()
            .find(|run| run.scenario == BASELINE_STEADY_STATE)
            .and_then(|run| run.year_one_fee);
        let (low, high) = cell
            .scenarios
            .iter()
            .filter_map(|run| run.year_one_fee)
            .fold((f64::INFINITY, 0.0f64), |(lo, hi), fee| {
                (lo.min(ratio(fee, ceiling)), hi.max(ratio(fee, ceiling)))
            });
        writeln!(
            out,
            "  {:<11} {:<26} {:>12} {:>8}   {:.2}-{:.2}",
            cell.arm.which.name(),
            cell.cell.label(),
            baseline.map_or("-".to_string(), |f| format!("{:.4}", skl(u128::from(f)))),
            baseline.map_or("-".to_string(), |f| format!("{:.2}", ratio(f, ceiling))),
            low,
            high,
        )?;
    }
    Ok(())
}

/// The summary EUP-5 reads, one row per cell and scenario.
fn write_summary(out: &mut impl fmt::Write, rows: &[SummaryRow]) -> fmt::Result {
    writeln!(out, "\nSUMMARY, every cell and scenario.")?;
    writeln!(
        out,
        "  {:<11} {:<26} {:<20} {:>6} {:>7} {:>11} {:>7} {:>7} {:>10} {:>7}",
        "arm",
        "cell",
        "scenario",
        "grows",
        "empties",
        "Econ served",
        "onset",
        "best",
        "y1 Std SKL",
        "x ceil"
    )?;
    for row in rows {
        writeln!(
            out,
            "  {:<11} {:<26} {:<20} {:>6} {:>7} {:>11} {:>7} {:>7} {:>10} {:>7}",
            row.arm,
            row.cell,
            trunc(&row.scenario, 20),
            year_label(row.growth_year),
            option_year(row.queue_empties_year),
            row.economy_served
                .map_or("-".to_string(), |f| format!("{:.1}%", 100.0 * f)),
            fmt_onset(row.onset_flat),
            fmt_onset(row.onset_best),
            row.year_one_standard_fee_atomic
                .map_or("-".to_string(), |f| format!("{:.4}", skl(u128::from(f)))),
            row.ratio_to_ceiling
                .map_or("-".to_string(), |r| format!("{r:.2}")),
        )?;
    }
    Ok(())
}

/// Each cell in full: per scenario its head lines, then its sampled years.
fn write_cells(
    out: &mut impl fmt::Write,
    runs: &[CellRun<'_>],
    ceiling: u64,
    blocks_per_year: u64,
) -> fmt::Result {
    let sample_years = BLOCK_SPACE_YEARS.map(|y| y.to_string()).join("/");
    writeln!(
        out,
        "\nPER CELL, at y{sample_years}. Per block, Economy/Standard/Priority: carried; dropped as refused, evicted\n\
         (CEN-M10) and expired (reference out of CEN-I11's window); age at inclusion in blocks, median/p95 per\n\
         rung ('-' when none listed); fees (SKL); Priority's share of the block's fees. Then the long-term median\n\
         at year end (KB) and the paid block reward, miner and staker, per block (SKL)."
    )?;
    for cell in runs {
        writeln!(
            out,
            "\n== {} | {}",
            cell.arm.which.name(),
            cell.cell.label()
        )?;
        for run in &cell.scenarios {
            write_scenario(out, &cell.params, cell.cell, run, ceiling)?;
            for year in run
                .aggs
                .iter()
                .filter(|a| BLOCK_SPACE_YEARS.contains(&a.year))
            {
                write_year(out, year, blocks_per_year)?;
            }
        }
    }
    Ok(())
}

/// One scenario's head lines in a cell: the gate, A1's legs at onset, and
/// the year-1 Standard fee against the ceiling.
fn write_scenario(
    out: &mut impl fmt::Write,
    params: &SimParams,
    cell: Cell,
    run: &ScenarioRun,
    ceiling: u64,
) -> fmt::Result {
    let gate = &run.gate;
    let multiplier = cell.multiplier().milli() as f64 / MILLI as f64;
    writeln!(
        out,
        "  {}: rho(y1) {:.3}, theta(y1) {:.3}; m*rho >= theta from {}; blocks grow {}{}",
        run.scenario,
        gate.rho_y1,
        gate.theta_y1,
        year_label(gate.crossing),
        year_label(gate.growth),
        gate.rho_at_growth.map_or(String::new(), |rho| format!(
            ", rho there {rho:.3} (m*rho {:.3})",
            multiplier * rho
        )),
    )?;
    let (at, which) = match run
        .onsets
        .flat
        .year
        .and_then(|y| run.aggs.iter().find(|a| a.year == y))
    {
        Some(a) => (Some(a), "at the flat-25 onset"),
        None => (run.aggs.last(), "no flat-25 onset; at the horizon"),
    };
    if let Some(a) = at {
        let budget = a1_shipped_budget_atomic(a, &flat_25(params));
        let fee_leg = budget - a.emission_leg_atomic;
        writeln!(
            out,
            "    A1 @10%: onset flat-25 {}, best {}; legs {which} (y{}): emission {:.1}, fee {:.1} SKL/yr ({:.1}% fee)",
            fmt_onset(run.onsets.flat),
            fmt_onset(run.onsets.best),
            a.year,
            skl(a.emission_leg_atomic),
            skl(fee_leg),
            if budget == 0 {
                0.0
            } else {
                100.0 * fee_leg as f64 / budget as f64
            },
        )?;
    }
    let shards = |year: u64| {
        run.aggs
            .iter()
            .find(|a| a.year == year)
            .map_or("-".to_string(), |a| a.n.to_string())
    };
    let fee = run
        .year_one_fee
        .map_or("no Standard carried".to_string(), |fee| {
            format!(
                "{:.4} SKL = {:.2}x the ceiling",
                skl(u128::from(fee)),
                ratio(fee, ceiling)
            )
        });
    writeln!(
        out,
        "    y1 Standard fee {fee}; closed shards y{SHARD_SAMPLE_YEAR} {}, y{ONSET_HORIZON_YEARS} {}",
        shards(SHARD_SAMPLE_YEAR),
        shards(ONSET_HORIZON_YEARS),
    )
}

/// One sampled year of a scenario in a cell, per block.
fn write_year(out: &mut impl fmt::Write, year: &A1YearAgg, blocks_per_year: u64) -> fmt::Result {
    let per_block = |txs: u128| txs as f64 / blocks_per_year as f64;
    let rungs = &year.rungs;
    let fees = rungs.sum(|rung| rung.fees_atomic);
    writeln!(
        out,
        "     {:>3} {} | {} | {} | {} | {} | {} | {:>5} | {:>6.0}K {:>8.2}",
        format!("y{}", year.year),
        per_rung(5, 1, |r| per_block(rungs[r].carried_txs)),
        per_rung(5, 1, |r| per_block(rungs[r].refused_txs)),
        per_rung(5, 1, |r| per_block(rungs[r].evicted_txs)),
        per_rung(5, 1, |r| per_block(rungs[r].expired_txs)),
        Rung::ALL
            .map(|r| format!(
                "{:>2}/{:>2}",
                age_quantile(&year.rung_ages[r], 50),
                age_quantile(&year.rung_ages[r], 95)
            ))
            .join(" "),
        per_rung(8, 3, |r| skl(rungs[r].fees_atomic) / blocks_per_year as f64),
        if fees == 0 {
            "-".to_string()
        } else {
            format!(
                "{:.1}%",
                100.0 * rungs[Rung::Priority].fees_atomic as f64 / fees as f64
            )
        },
        kilobytes(year.long_term_median),
        skl(year.total_emission_atomic) / blocks_per_year as f64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::Baseline;
    use crate::committed_fixture::{self, regenerate, Output};
    use crate::scenarios::STUFFING_ATTACK;

    /// The ceiling as ratified: 0.05 % of the design curve's year-1 mean
    /// block reward, 992.58 SKL (umbrella §4).
    #[test]
    fn the_year_one_ceiling_is_the_ratified_number() {
        assert_eq!(year_one_fee_ceiling(), 496_289_839);
    }

    /// The re-derived pair is the ordinary weight at genesis depth at its
    /// own genesis fee, and the zone is a hundred of it. Pins the
    /// derivation, not the numbers (the `bond_duration` precedent): the
    /// numbers are printed.
    #[test]
    fn the_rederived_pair_is_the_genesis_weight_at_its_own_fee() {
        let base = SimParams::default();
        let pair = rederived_pair(&base);
        println!(
            "w_ref' = {} B, zone' = {} B, at depth {} and fee {} atomic, {} pass(es)",
            pair.w_ref, pair.zone, pair.depth, pair.fee_atomic, pair.passes
        );
        assert_eq!(pair.depth, tree_depth_for_leaves(0));
        assert_eq!(pair.zone, ZONE_OVER_W_REF * pair.w_ref);
        assert_eq!(
            ordinary_tx_weight(0, pair.fee_atomic),
            pair.w_ref,
            "the weight at the pair's own fee"
        );
        let arm = base.with_more(pair.overrides()).expect("in band");
        assert_eq!(
            genesis_standard_tx(&arm),
            OrdinaryTx {
                fee_atomic: pair.fee_atomic,
                weight: pair.w_ref
            },
            "a fixed point: pricing under the pair returns the pair"
        );
    }

    /// The two arms' parameter sets differ in exactly `w_ref` and the zone.
    #[test]
    fn the_arms_differ_in_exactly_the_two_fields() {
        let [inherited, rederived] = arms(&SimParams::default());
        let fields = |b: &Baseline| {
            [
                (
                    "economic",
                    serde_json::to_value(&b.economic).expect("serializes"),
                ),
                ("relay", serde_json::to_value(b.relay).expect("serializes")),
                (
                    "archival",
                    serde_json::to_value(b.archival).expect("serializes"),
                ),
            ]
        };
        let mut differ = Vec::new();
        for ((set, a), (_, b)) in fields(inherited.params.baseline())
            .into_iter()
            .zip(fields(rederived.params.baseline()))
        {
            let (a, b) = (
                a.as_object().expect("an object").clone(),
                b.as_object().expect("an object").clone(),
            );
            for (key, value) in &a {
                if b.get(key) != Some(value) {
                    differ.push(format!("{set}.{key}"));
                }
            }
        }
        differ.sort();
        assert_eq!(
            differ,
            vec!["economic.full_reward_zone", "relay.ref_tx_weight"]
        );
        assert_eq!(inherited.params.fee, rederived.params.fee);
    }

    /// `m*` from the inherited arm's year 1 sits in the registered band,
    /// 1.30–1.40 (`ESR10_PREDICTIONS.md` P2, amended 2026-11-08).
    #[test]
    fn m_star_is_in_the_registered_band() {
        let m_star = m_star_from(&SimParams::default()).expect("year 1 prices an m*");
        assert!(
            (StandardMultiplier::from_milli(1_300)..=StandardMultiplier::from_milli(1_400))
                .contains(&m_star),
            "m* = {m_star}"
        );
    }

    #[test]
    fn the_cells_are_the_briefs_in_order() {
        let labels: Vec<String> = cells(Some(StandardMultiplier::from_milli(1_352)))
            .iter()
            .map(|c| c.label())
            .collect();
        assert_eq!(
            labels,
            [
                "x1.000 all-Standard",
                "x1.250 all-Standard",
                "x1.352 all-Standard (m*)",
                "x1.500 all-Standard",
                "x2.000 all-Standard",
                "x3.000 all-Standard",
                "15/80/5 x1.000",
                "15/85/0 x1.000",
            ]
        );
        assert_eq!(
            Cell::Swept(StandardMultiplier::UNIT).fee(),
            FeeModel::PRODUCTION_DEFAULT
        );
    }

    /// A zero release multiplier leaves no fee correction, so `ρ(y1)` is
    /// zero and no multiplier reaches `θ(y1)`: the sweep runs without an
    /// `m*` cell instead of dividing by zero, and its header says so.
    #[test]
    fn without_a_release_no_multiplier_is_m_star() {
        let base = SimParams::default()
            .with_more(
                ["economic.release_min=0", "economic.release_max=0"]
                    .map(|text| Override::parse(text).expect("well-formed"))
                    .to_vec(),
            )
            .expect("a zero release passes the validators");
        let m_star = m_star_from(&base);
        assert_eq!(m_star, None);
        let swept = cells(m_star);
        assert!(!swept.iter().any(|cell| matches!(cell, Cell::MStar(_))));
        assert_eq!(
            swept.len(),
            SWEPT_MULTIPLIERS.len() + REGISTERED_MIXES.len()
        );
        let mut header = String::new();
        write_header(&mut header, &arms(&base), &swept, &[], false, 0).expect("a String sink");
        assert!(
            header.contains("m* none: no multiplier reaches theta(y1)"),
            "{header}"
        );
    }

    /// The summary carries A1's onsets whole: a recovering onset keeps its
    /// flag in the JSON as it keeps its `*` in the narration.
    #[test]
    fn a_summary_row_keeps_the_onsets_recovery() {
        let onset = Onset {
            year: Some(26),
            recovers: true,
        };
        let row = SummaryRow {
            arm: "inherited",
            cell: Cell::Swept(StandardMultiplier::UNIT).label(),
            scenario: crate::scenarios::BOOM_BUST_CYCLE.to_string(),
            growth_year: Some(15),
            queue_empties_year: Some(2),
            economy_served: None,
            onset_flat: onset,
            onset_best: onset,
            year_one_standard_fee_atomic: None,
            ratio_to_ceiling: None,
        };
        let json = serde_json::to_value(&row).expect("serializes");
        assert_eq!(
            json["onset_flat"],
            serde_json::json!({"year": 26, "recovers": true})
        );
    }

    /// The narrations committed beside the crate: the registered run, and
    /// the nightly lane's scope of it.
    #[derive(Clone, Copy)]
    enum Committed {
        /// Every scenario: the registered run, on demand.
        Full,
        /// The baseline and the stuffing attack, both arms, every cell:
        /// what the nightly lane runs (`nightly.yml`,
        /// `economics-sim-ignored`), because the full set does not fit its
        /// budget beside the lane's other tests.
        Nightly,
    }

    impl Committed {
        fn scenarios(self) -> Vec<String> {
            match self {
                Self::Full => every_scenario(&SimParams::default()),
                Self::Nightly => [BASELINE_STEADY_STATE, STUFFING_ATTACK]
                    .map(String::from)
                    .to_vec(),
            }
        }

        fn path(self) -> &'static str {
            match self {
                Self::Full => concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/esr10_narration.txt"
                ),
                Self::Nightly => concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/esr10_narration_nightly.txt"
                ),
            }
        }

        fn narration(self) -> String {
            let mut narration = String::new();
            run_esr10(&mut narration, &SimParams::default(), &self.scenarios())
                .expect("String sink is infallible");
            narration
        }

        fn assert_matches(self) {
            committed_fixture::assert_matches("--esr10 narration", self.path(), &self.narration());
        }
    }

    /// The whole `--esr10` report against the committed copy: both arms,
    /// every cell, every scenario to 60 years. Reviewed as output, never
    /// trusted as an oracle for the line it was regenerated to match.
    ///
    /// Ignored by default and run on demand, not nightly: 144 folds of 60
    /// years, about 85 CPU-minutes. Run with `cargo test --release -p
    /// shekyl-economics-sim -- --ignored
    /// esr10_narration_matches_the_committed_fixture`. The committed fixture
    /// is generated and checked on Linux x86-64.
    #[test]
    #[ignore = "full --esr10 report, 144 folds of 60 years — on demand, not nightly; run with --release --ignored; fixture generated and checked on Linux x86-64"]
    fn esr10_narration_matches_the_committed_fixture() {
        Committed::Full.assert_matches();
    }

    /// The nightly scope against its committed copy: both arms, every cell,
    /// the baseline and the stuffing attack.
    #[test]
    #[ignore = "--esr10 on the baseline and the stuffing attack, 32 folds of 60 years — run with --release --ignored; nightly economics-sim-ignored; fixture generated and checked on Linux x86-64"]
    fn esr10_nightly_narration_matches_the_committed_fixture() {
        Committed::Nightly.assert_matches();
    }

    /// Regenerate both committed narrations, armed (rule 50). Ignored by
    /// default; run with `SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD
    /// <rationale>" cargo test --release -p shekyl-economics-sim -- --ignored
    /// regen_esr10_narration_fixtures`, the date naming the
    /// `ECONOMICS_SIM_PRODUCTION_REBASE.md` entry that records what moved.
    #[test]
    #[ignore = "armed regeneration helper; writes the committed fixtures; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_esr10_narration_fixtures() {
        regenerate(
            "the --esr10 narrations",
            &[
                Output {
                    path: Committed::Full.path(),
                    build: || Committed::Full.narration(),
                },
                Output {
                    path: Committed::Nightly.path(),
                    build: || Committed::Nightly.narration(),
                },
            ],
        );
    }
}

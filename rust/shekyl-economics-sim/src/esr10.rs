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
//! Each cell folds every stage-2 scenario to the onset horizon. The folds run
//! in parallel; the narration is printed in a fixed order, so it is the same
//! whatever the thread count.

use std::fmt;
use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::Serialize;
use shekyl_economics::{projected_already_generated, ClosedShardCount};

use crate::baseline::Override;
use crate::burden::{ordinary_tx_weight, COIN};
use crate::calibration::tree_depth_for_leaves;
use crate::chain_cursor::{ChainCursor, ChainStep};
use crate::engine::{emitted_at_start, SimParams};
use crate::escalation::flat_25;
use crate::fee_model::{FeeModel, OrdinaryTx};
use crate::growth_gate::{cell_gate, m_star_milli, year_label, CellGate};
use crate::onset::{age_quantile, at_horizon, binding_onsets, fmt_onset, BLOCK_SPACE_YEARS};
use crate::rung_mix::{Rung, RungMix};
use crate::scenarios::{all_scenarios, BASELINE_STEADY_STATE};
use crate::stage2::{a1_shipped_budget_atomic, a1_year_aggs, trunc, A1YearAgg};

/// Thousandths in one.
const MILLI: u64 = 1_000;

/// The inherited ratio of the zone to the reference weight, kept by the
/// re-derived arm and declared as inherited (`ESR10_PREDICTIONS.md` §0.3).
const ZONE_OVER_W_REF: u64 = 100;

/// Passes the re-derived pair may take to settle. The weight moves only
/// through the fee's varint, so two passes settle it; more is a defect.
const PAIR_PASSES: u32 = 8;

/// The year-1 fee ceiling's share of the year-1 mean block reward: 0.05 %
/// (umbrella §4, Usability, ratified 2026-11-06).
const CEILING_PARTS: u64 = 5;
const CEILING_OF: u64 = 10_000;

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
        u128::from(generated) * u128::from(CEILING_PARTS)
            / (u128::from(blocks) * u128::from(CEILING_OF)),
    )
    .expect("a fee fits")
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
    let config = all_scenarios(params)
        .into_iter()
        .find(|c| c.name == BASELINE_STEADY_STATE)
        .expect("the stage-2 set has a baseline");
    let economic = params.economic();
    let mut cursor = ChainCursor::default();
    cursor
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

/// One of the two constant arms.
pub(crate) struct Arm {
    pub(crate) name: &'static str,
    pub(crate) params: SimParams,
    /// The re-derived pair; `None` on the inherited arm.
    pub(crate) pair: Option<RederivedPair>,
}

/// The inherited arm (`base` itself) and the re-derived one.
pub(crate) fn arms(base: &SimParams) -> [Arm; 2] {
    let pair = rederived_pair(base);
    [
        Arm {
            name: "inherited",
            params: base.clone(),
            pair: None,
        },
        Arm {
            name: "re-derived",
            params: base
                .with_more(pair.overrides())
                .expect("the re-derived pair passes the validators"),
            pair: Some(pair),
        },
    ]
}

/// One fee cell: a Standard multiplier and a rung mix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cell {
    pub(crate) multiplier_milli: u64,
    pub(crate) mix: RungMix,
    /// Whether this is the `m*` cell.
    m_star: bool,
}

impl Cell {
    const fn standard(multiplier_milli: u64) -> Self {
        Self {
            multiplier_milli,
            mix: RungMix::ALL_STANDARD,
            m_star: false,
        }
    }

    const fn mixed(mix: RungMix) -> Self {
        Self {
            multiplier_milli: MILLI,
            mix,
            m_star: false,
        }
    }

    /// The cell's fee arm.
    pub(crate) const fn fee(self) -> FeeModel {
        FeeModel::Production {
            multiplier_milli: self.multiplier_milli,
            mix: self.mix,
        }
    }

    /// `x1.000 all-Standard`, `x1.352 all-Standard (m*)`, `15/80/5 x1.000`.
    pub(crate) fn label(self) -> String {
        let multiplier = format!(
            "x{}.{:03}",
            self.multiplier_milli / MILLI,
            self.multiplier_milli % MILLI
        );
        if self.mix == RungMix::ALL_STANDARD {
            let star = if self.m_star { " (m*)" } else { "" };
            format!("{multiplier} all-Standard{star}")
        } else {
            format!("{} {multiplier}", self.mix)
        }
    }
}

/// The cells, in the order the brief names them, with `m*` in thousandths.
pub(crate) fn cells(m_star_milli: u64) -> [Cell; 8] {
    [
        Cell::standard(1_000),
        Cell::standard(1_250),
        Cell {
            m_star: true,
            ..Cell::standard(m_star_milli)
        },
        Cell::standard(1_500),
        Cell::standard(2_000),
        Cell::standard(3_000),
        Cell::mixed(RungMix::DEFAULTED),
        Cell::mixed(RungMix::ZERO_PRIORITY),
    ]
}

/// `m*` from the inherited arm's year 1 on the baseline scenario: one
/// year of the `x1.000` cell's fold.
pub(crate) fn m_star_from(base: &SimParams) -> u64 {
    let mut config = all_scenarios(base)
        .into_iter()
        .find(|c| c.name == BASELINE_STEADY_STATE)
        .expect("the stage-2 set has a baseline");
    config.sim_years = 1;
    let year_one = a1_year_aggs(base, &config);
    m_star_milli(base, year_one.first().expect("one year folded"))
}

/// One cell's fold of one scenario.
pub(crate) struct CellFold {
    pub(crate) scenario: String,
    pub(crate) aggs: Vec<A1YearAgg>,
}

/// Run `job` over `0..count` on every core; the results come back in index
/// order.
fn in_parallel<T: Send>(count: usize, job: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<T>>> = (0..count).map(|_| Mutex::new(None)).collect();
    let threads = std::thread::available_parallelism()
        .map_or(4, NonZero::get)
        .min(count.max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= count {
                    break;
                }
                let result = job(index);
                *slots[index].lock().expect("a slot is written once") = Some(result);
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .expect("a slot is written once")
                .expect("every job ran")
        })
        .collect()
}

/// The scenarios a narration folds: every stage-2 scenario, or the two the
/// nightly lane runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every stage-2 scenario: the registered run, on demand.
    Full,
    /// The baseline and the stuffing attack: what the nightly lane runs
    /// (`nightly.yml`, `economics-sim-ignored`), because the full set does
    /// not fit its budget beside the lane's other tests.
    // Run by the nightly's tests only: the binary has no library target, so
    // a variant only a test builds is dead in the bin (the `cartel.rs`
    // precedent).
    #[cfg_attr(not(test), allow(dead_code))]
    Nightly,
    /// The nightly scope with boom-bust and the late-chain tail: the reach
    /// probe's ([`run_reach_probe`]). Measured 2026-11-08: the release
    /// multiplier's ceiling, the burn cap, the surge factor and the tail
    /// subsidy move the 15/80/5 cell only in those two scenarios (and in
    /// sustained growth and high-history, which add nothing these two do
    /// not show).
    #[cfg(test)]
    Reach,
}

/// The stuffing attack's name in the stage-2 set.
const STUFFING_ATTACK: &str = "stuffing_attack";

impl Scope {
    /// The names of the scenarios this scope folds; `None` for every one.
    fn names(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Full => None,
            Self::Nightly => Some(&[BASELINE_STEADY_STATE, STUFFING_ATTACK]),
            #[cfg(test)]
            Self::Reach => Some(&[
                BASELINE_STEADY_STATE,
                STUFFING_ATTACK,
                "boom_bust_cycle",
                "late_chain_tail",
            ]),
        }
    }

    /// The indexes into [`all_scenarios`] this scope folds.
    fn scenarios(self, params: &SimParams) -> Vec<usize> {
        all_scenarios(params)
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                self.names()
                    .is_none_or(|names| names.contains(&c.name.as_str()))
            })
            .map(|(index, _)| index)
            .collect()
    }
}

/// Every `(arm, cell)`'s fold of each scenario in `scope`:
/// `[arm][cell][scenario]`.
fn fold_every_cell(arms: &[Arm], cells: &[Cell], scope: Scope) -> Vec<Vec<Vec<CellFold>>> {
    let picked = scope.scenarios(&arms[0].params);
    let scenarios = picked.len();
    let per_arm = cells.len() * scenarios;
    let mut flat = in_parallel(arms.len() * per_arm, |job| {
        let arm = &arms[job / per_arm];
        let cell = cells[(job % per_arm) / scenarios];
        let mut params = arm.params.clone();
        params.fee = cell.fee();
        let config = at_horizon(
            all_scenarios(&params)
                .into_iter()
                .nth(picked[job % scenarios])
                .expect("the scenario index is in range"),
        );
        CellFold {
            scenario: config.name.clone(),
            aggs: a1_year_aggs(&params, &config),
        }
    })
    .into_iter();
    arms.iter()
        .map(|_| {
            cells
                .iter()
                .map(|_| flat.by_ref().take(scenarios).collect())
                .collect()
        })
        .collect()
}

/// One row of the summary EUP-5 reads.
#[derive(Debug, Clone, Serialize)]
pub struct SummaryRow {
    pub arm: String,
    pub cell: String,
    pub scenario: String,
    /// The year blocks first grow past the constrained ceiling.
    pub growth_year: Option<u64>,
    /// The first year whose last block leaves nothing waiting.
    pub queue_empties_year: Option<u64>,
    /// Economy carried over Economy demanded over the horizon; `None` when
    /// the cell sends Economy nothing.
    pub economy_served: Option<f64>,
    pub onset_flat: Option<u64>,
    pub onset_best: Option<u64>,
    /// The Standard fees carried in year 1 over the Standard transactions
    /// carried, atomic units.
    pub year_one_standard_fee_atomic: Option<u64>,
    /// That fee over the ratified ceiling.
    pub ratio_to_ceiling: Option<f64>,
}

fn skl(atomic: u128) -> f64 {
    atomic as f64 / COIN as f64
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

/// The `--esr10` narration over `scope`: both arms, every cell. Returns the
/// summary rows.
///
/// # Errors
///
/// The sink's.
pub fn run_esr10(
    out: &mut impl fmt::Write,
    base: &SimParams,
    scope: Scope,
) -> Result<Vec<SummaryRow>, fmt::Error> {
    let cells = cells(m_star_from(base));
    narrate(out, base, &arms(base), &cells, scope)
}

/// The reach probe `--esr10`'s reader list is measured on
/// (`baseline::tests::every_declared_reader_moves_its_report`): the
/// inherited arm's 15/80/5 cell on [`Scope::Reach`]'s scenarios, printed as
/// `--esr10` prints it. The cell prices all three rungs with every field the
/// other cells read, and its lines are lines of the narration, so a field
/// that moves the probe moves the report.
#[cfg(test)]
pub(crate) fn run_reach_probe(out: &mut impl fmt::Write, base: &SimParams) -> fmt::Result {
    let inherited = Arm {
        name: "inherited",
        params: base.clone(),
        pair: None,
    };
    narrate(
        out,
        base,
        &[inherited],
        &[Cell::mixed(RungMix::DEFAULTED)],
        Scope::Reach,
    )
    .map(|_| ())
}

/// The narration over `arms` × `cells`, each folding `scope`'s scenarios.
fn narrate(
    out: &mut impl fmt::Write,
    base: &SimParams,
    arms: &[Arm],
    cells: &[Cell],
    scope: Scope,
) -> Result<Vec<SummaryRow>, fmt::Error> {
    let ceiling = year_one_fee_ceiling();
    let folds = fold_every_cell(arms, cells, scope);
    let bpy = base.blocks_per_year();
    let per_block = |txs: u128| txs as f64 / bpy as f64;

    writeln!(
        out,
        "ESR-10 — the fee multiplier and the rung mix, on both w_ref arms\n\
         (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.29; ESR10_PREDICTIONS.md). Every cell is production but for\n\
         its named alternatives; {SCOPE} folds to {H} y.",
        SCOPE = match scope.names() {
            None => "every scenario".to_string(),
            Some(names) => format!("{} only,", names.join(", ")),
        },
        H = crate::onset::ONSET_HORIZON_YEARS,
    )?;
    writeln!(out, "ARMS:")?;
    for arm in arms {
        let relay = arm.params.relay();
        let zone = arm.params.economic().full_reward_zone;
        match arm.pair {
            None => writeln!(
                out,
                "  {:<11} w_ref {} B, zone {zone} B: the run's own.",
                arm.name, relay.ref_tx_weight,
            )?,
            Some(pair) => writeln!(
                out,
                "  {:<11} declared; the owners' ruling replaces it (EUP-5 G). w_ref' = {} B, the ordinary\n\
                 \x20             1in/2out weight at genesis tree depth {} at its own genesis Standard fee {:.4} SKL\n\
                 \x20             (a fixed point: {} pass(es) from the zero-fee weight); zone' = {ZONE_OVER_W_REF} x w_ref' = {} B,\n\
                 \x20             the inherited ratio. --set {}",
                arm.name,
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
    writeln!(
        out,
        "CELLS: {}.\n\
         \x20 m* = ceil(1000 theta(y1)/rho(y1)) on the inherited arm's year 1. Mixes are Economy/Standard/Priority\n\
         \x20 percent; demand splits by largest remainder on the cumulative target, and one block's arrivals are\n\
         \x20 admitted Priority, Standard, Economy (a drop's label, not the pool; §5.29).",
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
         \x20 demanded over {H} y; onset = A1-T's first sustained year under 1 at 10% (flat-25, best).",
        H = crate::onset::ONSET_HORIZON_YEARS,
    )?;

    // The headline: the year-1 Standard fee against the ceiling.
    writeln!(
        out,
        "\nYEAR-1 STANDARD FEE against the ceiling: the baseline's, and the range of x ceiling over every scenario."
    )?;
    writeln!(
        out,
        "  {:<11} {:<26} {:>12} {:>8}   range x ceil",
        "arm", "cell", "baseline SKL", "x ceil"
    )?;
    let ratio = |fee: u64| fee as f64 / ceiling as f64;
    for (arm, by_cell) in arms.iter().zip(&folds) {
        for (cell, by_scenario) in cells.iter().zip(by_cell) {
            let fees: Vec<u64> = by_scenario
                .iter()
                .filter_map(|f| year_one_standard_fee(&f.aggs))
                .collect();
            let baseline = by_scenario
                .iter()
                .find(|f| f.scenario == BASELINE_STEADY_STATE)
                .and_then(|f| year_one_standard_fee(&f.aggs));
            let (low, high) = fees.iter().fold((f64::INFINITY, 0.0f64), |(lo, hi), &f| {
                (lo.min(ratio(f)), hi.max(ratio(f)))
            });
            writeln!(
                out,
                "  {:<11} {:<26} {:>12} {:>8}   {:.2}-{:.2}",
                arm.name,
                cell.label(),
                baseline.map_or("-".to_string(), |f| format!("{:.4}", skl(u128::from(f)))),
                baseline.map_or("-".to_string(), |f| format!("{:.2}", ratio(f))),
                low,
                high,
            )?;
        }
    }

    // The summary EUP-5 reads.
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
    let mut rows = Vec::new();
    for (arm, by_cell) in arms.iter().zip(&folds) {
        for (cell, by_scenario) in cells.iter().zip(by_cell) {
            let mut params = arm.params.clone();
            params.fee = cell.fee();
            for fold in by_scenario {
                let gate = cell_gate(&params, &fold.aggs, cell.multiplier_milli);
                let onsets = binding_onsets(&fold.aggs, &params);
                let fee = year_one_standard_fee(&fold.aggs);
                let row = SummaryRow {
                    arm: arm.name.to_string(),
                    cell: cell.label(),
                    scenario: fold.scenario.clone(),
                    growth_year: gate.growth,
                    queue_empties_year: queue_empties(&fold.aggs),
                    economy_served: economy_served(&fold.aggs),
                    onset_flat: onsets.flat.year,
                    onset_best: onsets.best.year,
                    year_one_standard_fee_atomic: fee,
                    ratio_to_ceiling: fee.map(ratio),
                };
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
                    fmt_onset(onsets.flat),
                    fmt_onset(onsets.best),
                    fee.map_or("-".to_string(), |f| format!("{:.4}", skl(u128::from(f)))),
                    row.ratio_to_ceiling
                        .map_or("-".to_string(), |r| format!("{r:.2}")),
                )?;
                rows.push(row);
            }
        }
    }

    // Each cell in full.
    let sample_years = BLOCK_SPACE_YEARS.map(|y| y.to_string()).join("/");
    writeln!(
        out,
        "\nPER CELL, at y{sample_years}. Per block, Economy/Standard/Priority: carried; dropped as refused, evicted\n\
         (CEN-M10) and expired (reference out of CEN-I11's window); age at inclusion in blocks, median/p95 per\n\
         rung ('-' when none listed); fees (SKL); Priority's share of the block's fees. Then the long-term median\n\
         at year end (KB) and the paid block reward, miner and staker, per block (SKL)."
    )?;
    for (arm, by_cell) in arms.iter().zip(&folds) {
        for (cell, by_scenario) in cells.iter().zip(by_cell) {
            let mut params = arm.params.clone();
            params.fee = cell.fee();
            writeln!(out, "\n== {} | {}", arm.name, cell.label())?;
            for fold in by_scenario {
                let gate = cell_gate(&params, &fold.aggs, cell.multiplier_milli);
                write_scenario(out, &params, cell, fold, &gate, ceiling)?;
                for a in fold
                    .aggs
                    .iter()
                    .filter(|a| BLOCK_SPACE_YEARS.contains(&a.year))
                {
                    let fees = a.rungs.iter().map(|r| r.fees_atomic).sum::<u128>();
                    writeln!(
                        out,
                        "     {:>3} {} | {} | {} | {} | {} | {} | {:>5} | {:>6.0}K {:>8.2}",
                        format!("y{}", a.year),
                        per_rung(5, 1, |r| per_block(a.rungs[r].carried_txs)),
                        per_rung(5, 1, |r| per_block(a.rungs[r].refused_txs)),
                        per_rung(5, 1, |r| per_block(a.rungs[r].evicted_txs)),
                        per_rung(5, 1, |r| per_block(a.rungs[r].expired_txs)),
                        Rung::ALL
                            .map(|r| format!(
                                "{:>2}/{:>2}",
                                age_quantile(&a.rungs[r].inclusion_ages, 50),
                                age_quantile(&a.rungs[r].inclusion_ages, 95)
                            ))
                            .join(" "),
                        per_rung(8, 3, |r| skl(a.rungs[r].fees_atomic) / bpy as f64),
                        if fees == 0 {
                            "-".to_string()
                        } else {
                            format!(
                                "{:.1}%",
                                100.0 * a.rungs[Rung::Priority].fees_atomic as f64 / fees as f64
                            )
                        },
                        a.long_term_median as f64 / 1_000.0,
                        skl(a.total_emission_atomic) / bpy as f64,
                    )?;
                }
            }
        }
    }
    Ok(rows)
}

/// One scenario's head lines in a cell: the gate, A1's legs at onset, and
/// the year-1 Standard fee against the ceiling.
fn write_scenario(
    out: &mut impl fmt::Write,
    params: &SimParams,
    cell: &Cell,
    fold: &CellFold,
    gate: &CellGate,
    ceiling: u64,
) -> fmt::Result {
    let m = cell.multiplier_milli as f64 / MILLI as f64;
    writeln!(
        out,
        "  {}: rho(y1) {:.3}, theta(y1) {:.3}; m*rho >= theta from {}; blocks grow {}{}",
        fold.scenario,
        gate.rho_y1,
        gate.theta_y1,
        year_label(gate.crossing),
        year_label(gate.growth),
        gate.rho_at_growth.map_or(String::new(), |rho| format!(
            ", rho there {rho:.3} (m*rho {:.3})",
            m * rho
        )),
    )?;
    let onsets = binding_onsets(&fold.aggs, params);
    let flat = flat_25(params);
    let (at, which) = match onsets
        .flat
        .year
        .and_then(|y| fold.aggs.iter().find(|a| a.year == y))
    {
        Some(a) => (Some(a), "at the flat-25 onset"),
        None => (fold.aggs.last(), "no flat-25 onset; at the horizon"),
    };
    if let Some(a) = at {
        let budget = a1_shipped_budget_atomic(a, &flat);
        let fee_leg = budget - a.emission_leg_atomic;
        writeln!(
            out,
            "    A1 @10%: onset flat-25 {}, best {}; legs {which} (y{}): emission {:.1}, fee {:.1} SKL/yr ({:.1}% fee)",
            fmt_onset(onsets.flat),
            fmt_onset(onsets.best),
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
        fold.aggs
            .iter()
            .find(|a| a.year == year)
            .map_or("-".to_string(), |a| a.n.to_string())
    };
    let fee = year_one_standard_fee(&fold.aggs).map_or("no Standard carried".to_string(), |fee| {
        format!(
            "{:.4} SKL = {:.2}x the ceiling",
            skl(u128::from(fee)),
            fee as f64 / ceiling as f64
        )
    });
    writeln!(
        out,
        "    y1 Standard fee {fee}; closed shards y10 {}, y60 {}",
        shards(10),
        shards(crate::onset::ONSET_HORIZON_YEARS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::Baseline;

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
    /// 1.30–1.40 (`ESR10_PREDICTIONS.md` P2, amended 2026-11-08), and is the
    /// least multiplier at which `m*·ρ(y1) ≥ θ(y1)`.
    #[test]
    fn m_star_is_in_the_registered_band() {
        let m_star = m_star_from(&SimParams::default());
        assert!((1_300..=1_400).contains(&m_star), "m* = {m_star}");
    }

    /// Each committed scope's narration. The reach probe is compared with
    /// itself under an override, never with a committed copy.
    fn fixture(scope: Scope) -> &'static str {
        match scope {
            Scope::Reach => unreachable!("the reach probe has no committed narration"),
            Scope::Full => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/esr10_narration.txt"
            ),
            Scope::Nightly => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/esr10_narration_nightly.txt"
            ),
        }
    }

    fn esr10_narration(scope: Scope) -> String {
        let mut narration = String::new();
        run_esr10(&mut narration, &SimParams::default(), scope).expect("String sink is infallible");
        narration
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
        assert_narration_matches(Scope::Full);
    }

    /// The nightly scope against its committed copy: both arms, every cell,
    /// the baseline and the stuffing attack.
    #[test]
    #[ignore = "--esr10 on the baseline and the stuffing attack, 32 folds of 60 years — run with --release --ignored; nightly economics-sim-ignored; fixture generated and checked on Linux x86-64"]
    fn esr10_nightly_narration_matches_the_committed_fixture() {
        assert_narration_matches(Scope::Nightly);
    }

    fn assert_narration_matches(scope: Scope) {
        let path = fixture(scope);
        let committed = std::fs::read_to_string(path).expect("read committed narration");
        let current = esr10_narration(scope);
        if committed != current {
            let first = committed
                .lines()
                .zip(current.lines())
                .position(|(a, b)| a != b)
                .map_or_else(
                    || committed.lines().count().min(current.lines().count()) + 1,
                    |i| i + 1,
                );
            panic!(
                "--esr10 narration drifted from {path}; first differing line {first} ({} \
                 committed lines, {} current). Regenerate with SHEKYL_REGEN_FIXTURES=1 and \
                 read the diff.",
                committed.lines().count(),
                current.lines().count(),
            );
        }
    }

    /// Regenerate both committed narrations. Ignored by default; run with
    /// `SHEKYL_REGEN_FIXTURES=1 cargo test --release -p shekyl-economics-sim
    /// -- --ignored regen_esr10_narration_fixtures`.
    #[test]
    #[ignore = "regeneration helper; writes the committed fixtures"]
    fn regen_esr10_narration_fixtures() {
        assert_eq!(
            std::env::var("SHEKYL_REGEN_FIXTURES").as_deref(),
            Ok("1"),
            "set SHEKYL_REGEN_FIXTURES=1 to regenerate"
        );
        for scope in [Scope::Full, Scope::Nightly] {
            std::fs::write(fixture(scope), esr10_narration(scope)).expect("write narration");
        }
    }

    #[test]
    fn the_cells_are_the_briefs_in_order() {
        let labels: Vec<String> = cells(1_352).iter().map(|c| c.label()).collect();
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
        assert_eq!(cells(1_352)[0].fee(), FeeModel::PRODUCTION_DEFAULT);
    }
}

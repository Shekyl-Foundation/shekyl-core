// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The growth under standard traffic, traced
//! (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.36, GRW-1…GRW-6).
//!
//! The baseline scenario folds to [`TRACE_YEARS`] at the canonical seed, on
//! standard traffic and on `steady`, in the inherited zone and the
//! re-derived one. A probe reads every block the fold prices; nothing here
//! changes a fold. Period by period it prints the medians, where the
//! effective median sits against its surge ceiling, why each fill ended, the
//! bodies listed past the penalty-free weight with their fees, the penalty
//! and the surplus, and the pool.

use std::collections::BTreeMap;
use std::fmt::{self, Write};

use crate::block_space::FillStop;
use crate::engine::SimParams;
use crate::esr10::{arms, scenario_named, Arm};
use crate::eup4::skl;
use crate::honest_step::lower_median;
use crate::rung_mix::RungTraffic;
use crate::scenarios::BASELINE_STEADY_STATE;
use crate::stage2::{a1_year_aggs_probed, kilobytes, BlockSeen, FoldProbe};

/// The fold's horizon: two decades past the inherited baseline's crossing
/// (y19), so the rest the growth reaches is read for as long as it lasts.
pub(crate) const TRACE_YEARS: u64 = 40;

/// The years read by quarter: the one before the crossing through the
/// climb. Earlier years are one period; later ones are read by year.
const QUARTER_YEARS: core::ops::RangeInclusive<u64> = 18..=23;

/// Quarters in a year.
const QUARTERS: u64 = 4;

/// The period a block falls in, by its one-based year.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeriodKey {
    /// Every year before [`QUARTER_YEARS`].
    Before,
    /// A quarter (one to four) of a year in [`QUARTER_YEARS`].
    Quarter(u64, u64),
    /// A year after [`QUARTER_YEARS`].
    Year(u64),
}

impl PeriodKey {
    fn of(block: u64, blocks_per_year: u64) -> Self {
        let year = block / blocks_per_year + 1;
        if year < *QUARTER_YEARS.start() {
            Self::Before
        } else if QUARTER_YEARS.contains(&year) {
            Self::Quarter(
                year,
                (block % blocks_per_year) * QUARTERS / blocks_per_year + 1,
            )
        } else {
            Self::Year(year)
        }
    }

    fn label(self) -> String {
        match self {
            Self::Before => format!("y1-y{}", QUARTER_YEARS.start() - 1),
            Self::Quarter(year, quarter) => format!("y{year} q{quarter}"),
            Self::Year(year) => format!("y{year}"),
        }
    }
}

/// One period's reading, summed over its blocks.
#[derive(Debug, Clone)]
struct Period {
    key: PeriodKey,
    blocks: u64,
    /// The long-term effective median the period's last block was judged
    /// under.
    ltem: u64,
    effective_sum: u128,
    /// Blocks judged under an effective median at its surge ceiling,
    /// `S · LTEM`.
    at_ceiling: u64,
    /// Blocks heavier than the effective median they were judged under.
    past_effective: u64,
    drained: u64,
    penalty_stops: u64,
    limit_stops: u64,
    past_bodies: u64,
    past_fees: u128,
    penalty: u128,
    /// Each block's past-free fees less its penalty, summed.
    surplus: u128,
    fees: u128,
    /// The paid (penalised) reward each block minted, summed.
    emitted: u128,
    /// The Standard rung's ordinary body at each block, its weight and its
    /// fee, summed.
    body_weight_sum: u128,
    body_fee_sum: u128,
    waiting_sum: u128,
    /// Expired, evicted and refused.
    dropped: u64,
    /// Transactions each block carried, value to count.
    carried: BTreeMap<u64, u64>,
}

impl Period {
    fn new(key: PeriodKey) -> Self {
        Self {
            key,
            blocks: 0,
            ltem: 0,
            effective_sum: 0,
            at_ceiling: 0,
            past_effective: 0,
            drained: 0,
            penalty_stops: 0,
            limit_stops: 0,
            past_bodies: 0,
            past_fees: 0,
            penalty: 0,
            surplus: 0,
            fees: 0,
            emitted: 0,
            body_weight_sum: 0,
            body_fee_sum: 0,
            waiting_sum: 0,
            dropped: 0,
            carried: BTreeMap::new(),
        }
    }

    fn add(&mut self, seen: &BlockSeen<'_, '_>, surge_factor: u64) {
        let priced = seen.priced;
        let filled = &priced.filled;
        let ltem = priced.medians.long_term_effective_median.to_raw();
        let effective = priced.medians.effective_median.to_raw();
        self.blocks += 1;
        self.ltem = ltem;
        self.effective_sum += u128::from(effective);
        self.at_ceiling += u64::from(effective >= ltem.saturating_mul(surge_factor));
        self.past_effective += u64::from(filled.block_weight > effective);
        match filled.stop {
            FillStop::Drained => self.drained += 1,
            FillStop::Penalty => self.penalty_stops += 1,
            FillStop::Limit => self.limit_stops += 1,
        }
        self.past_bodies += filled.past_free.bodies;
        self.past_fees += u128::from(filled.past_free.fees_atomic);
        self.penalty += u128::from(filled.past_free.penalty_atomic);
        self.surplus += u128::from(filled.past_free.surplus_atomic());
        self.fees += u128::from(filled.fees_atomic());
        self.emitted += u128::from(priced.paid_reward());
        self.body_weight_sum += u128::from(priced.tx.weight);
        self.body_fee_sum += u128::from(priced.tx.fee_atomic);
        self.waiting_sum += u128::from(filled.waiting);
        self.dropped += filled
            .rungs
            .sum(|rung: &RungTraffic<u64>| rung.expired_txs + rung.evicted_txs + rung.refused_txs);
        *self.carried.entry(filled.carried_txs()).or_insert(0) += 1;
    }
}

/// The probe: every block into its period.
struct GrowthProbe {
    blocks_per_year: u64,
    surge_factor: u64,
    periods: Vec<Period>,
}

impl FoldProbe for GrowthProbe {
    fn seen(&mut self, seen: &BlockSeen<'_, '_>) {
        let key = PeriodKey::of(seen.block, self.blocks_per_year);
        if self.periods.last().is_none_or(|period| period.key != key) {
            self.periods.push(Period::new(key));
        }
        let period = self.periods.last_mut().expect("pushed above");
        period.add(seen, self.surge_factor);
    }
}

/// One traced run: a zone on a traffic.
struct Run {
    zone: &'static str,
    traffic: &'static str,
    params: SimParams,
}

/// The four runs: each zone of [`arms`] on standard traffic, then on
/// `steady`.
fn runs(base: &SimParams) -> Vec<Run> {
    let [inherited, rederived] = arms(base);
    let mut out = Vec::new();
    for Arm { which, params } in [inherited, rederived] {
        out.push(Run {
            zone: which.name(),
            traffic: "standard",
            params: params.clone(),
        });
        out.push(Run {
            zone: which.name(),
            traffic: "steady",
            params: params.on_steady(),
        });
    }
    out
}

/// The baseline scenario, to [`TRACE_YEARS`].
fn fold(params: &SimParams) -> Vec<Period> {
    let mut config = scenario_named(params, BASELINE_STEADY_STATE);
    config.sim_years = TRACE_YEARS;
    let mut probe = GrowthProbe {
        blocks_per_year: params.blocks_per_year(),
        surge_factor: params.economic().block_weight_surge_factor,
        periods: Vec::new(),
    };
    a1_year_aggs_probed(params, &config, &mut probe);
    probe.periods
}

/// The `--growth-trace` report: the four runs folded on every core, then
/// printed in order.
///
/// # Errors
///
/// Only `out`'s.
pub(crate) fn run(out: &mut impl Write, base: &SimParams) -> fmt::Result {
    let runs = runs(base);
    let folded = crate::parallel::map(&runs, |run| fold(&run.params));
    writeln!(
        out,
        "GROWTH UNDER STANDARD TRAFFIC, TRACED (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.36, GRW-1..GRW-6).\n\
         Measures only. The baseline scenario to y{TRACE_YEARS}, production's fee, seed 1, in the inherited\n\
         and the re-derived zone, on standard traffic and on steady. Per period: the long-term effective\n\
         median at its last block (LTEM, KB) and the mean effective median (eff, KB); the share of blocks\n\
         judged with the effective median at its surge ceiling (S x LTEM) and the share heavier than it;\n\
         why each fill ended, as shares (drained: every offered body listed; penalty: a body's fee under\n\
         the penalty it adds; limit: the block's limit); the bodies listed past the penalty-free weight per\n\
         block; per year, the penalty those bodies cost, their fees, and the surplus (fees less penalty),\n\
         in SKL, and the penalty as a share of every listed fee; the pool's waiting count per block and its\n\
         drops (expired, evicted, refused) per block; the median count carried; the reward the blocks\n\
         minted per year (SKL) and the penalty as a share of it; every listed fee per block (SKL); the\n\
         Standard rung's ordinary body, its mean weight (KB) and its mean fee (SKL)."
    )?;
    for (run, periods) in runs.iter().zip(&folded) {
        writeln!(out)?;
        writeln!(out, "== {} zone | {} traffic", run.zone, run.traffic)?;
        writeln!(
            out,
            "  {:<8} {:>7} {:>7} {:>5} {:>6} {:>21} {:>6} {:>10} {:>10} {:>10} {:>7} {:>8} {:>7} {:>5} {:>12} {:>8} {:>9} {:>7} {:>8}",
            "period",
            "LTEM",
            "eff",
            "at S%",
            "past%",
            "drained/penalty/limit",
            "past/b",
            "pen SKL/y",
            "fees SKL/y",
            "surp SKL/y",
            "pen/fee",
            "waiting",
            "drop/b",
            "carr",
            "emit SKL/y",
            "pen/emit",
            "fee/b SKL",
            "body KB",
            "body fee"
        )?;
        let blocks_per_year = run.params.blocks_per_year();
        for period in periods {
            row(out, period, blocks_per_year)?;
        }
    }
    Ok(())
}

/// One period's line.
#[allow(clippy::cast_precision_loss)]
fn row(out: &mut impl Write, period: &Period, blocks_per_year: u64) -> fmt::Result {
    let blocks = period.blocks.max(1);
    let share = |n: u64| 100.0 * n as f64 / blocks as f64;
    let per_block = |n: u128| n as f64 / blocks as f64;
    let per_year = |atomic: u128| skl(atomic) * blocks_per_year as f64 / blocks as f64;
    let effective = u64::try_from(period.effective_sum / u128::from(blocks))
        .expect("a mean of u64 weights fits u64");
    let penalty_of_fees = if period.fees == 0 {
        0.0
    } else {
        100.0 * period.penalty as f64 / period.fees as f64
    };
    let penalty_of_emitted = if period.emitted == 0 {
        0.0
    } else {
        100.0 * period.penalty as f64 / period.emitted as f64
    };
    let body_weight = u64::try_from(period.body_weight_sum / u128::from(blocks))
        .expect("a mean of u64 weights fits u64");
    writeln!(
        out,
        "  {:<8} {:>7.0} {:>7.0} {:>5.1} {:>6.1} {:>6.1}/{:>6.1}/{:>6.1} {:>6.2} {:>10.2} {:>10.2} {:>10.2} {:>6.3}% {:>8.1} {:>7.2} {:>5} {:>12.0} {:>7.4}% {:>9.3} {:>7.2} {:>8.4}",
        period.key.label(),
        kilobytes(period.ltem),
        kilobytes(effective),
        share(period.at_ceiling),
        share(period.past_effective),
        share(period.drained),
        share(period.penalty_stops),
        share(period.limit_stops),
        per_block(u128::from(period.past_bodies)),
        per_year(period.penalty),
        per_year(period.past_fees),
        per_year(period.surplus),
        penalty_of_fees,
        per_block(period.waiting_sum),
        per_block(u128::from(period.dropped)),
        lower_median(&period.carried, period.blocks),
        per_year(period.emitted),
        penalty_of_emitted,
        skl(period.fees) / blocks as f64,
        kilobytes(body_weight),
        skl(period.body_fee_sum) / blocks as f64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_fixture::{self, regenerate, Output};

    /// The trace's committed narration.
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/growth_trace_narration.txt"
    );

    fn narration() -> String {
        let mut out = String::new();
        run(&mut out, &SimParams::default()).expect("String sink is infallible");
        out
    }

    /// Each block falls in one period: the years before the climb in one,
    /// the climb by quarter, the rest by year.
    #[test]
    fn a_block_falls_in_its_period() {
        let year = 1_000;
        assert_eq!(PeriodKey::of(0, year), PeriodKey::Before);
        assert_eq!(PeriodKey::of(17 * year - 1, year), PeriodKey::Before);
        assert_eq!(PeriodKey::of(17 * year, year), PeriodKey::Quarter(18, 1));
        assert_eq!(
            PeriodKey::of(17 * year + 249, year),
            PeriodKey::Quarter(18, 1)
        );
        assert_eq!(
            PeriodKey::of(17 * year + 250, year),
            PeriodKey::Quarter(18, 2)
        );
        assert_eq!(
            PeriodKey::of(23 * year - 1, year),
            PeriodKey::Quarter(23, 4)
        );
        assert_eq!(PeriodKey::of(23 * year, year), PeriodKey::Year(24));
        assert_eq!(PeriodKey::Before.label(), "y1-y17");
        assert_eq!(PeriodKey::Quarter(19, 3).label(), "y19 q3");
        assert_eq!(PeriodKey::Year(40).label(), "y40");
    }

    /// The four runs are the two zones, each on standard traffic and on
    /// `steady`.
    #[test]
    fn the_runs_are_each_zone_on_each_traffic() {
        let base = SimParams::default();
        let names: Vec<(&str, &str, bool)> = runs(&base)
            .iter()
            .map(|run| {
                (
                    run.zone,
                    run.traffic,
                    run.params.traffic.report_line().is_some(),
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                ("inherited", "standard", true),
                ("inherited", "steady", false),
                ("re-derived", "standard", true),
                ("re-derived", "steady", false),
            ]
        );
    }

    /// The whole report against its committed copy.
    #[test]
    #[ignore = "--growth-trace, four 40-year folds — on demand, not nightly; run with --release --ignored; fixture generated and checked on Linux x86-64"]
    fn growth_trace_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches("--growth-trace narration", FIXTURE, &narration());
    }

    /// Armed: rewrites the committed narration under a cited decision.
    #[test]
    #[ignore = "armed regeneration helper; writes the committed fixture; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_growth_trace_narration_fixture() {
        regenerate(
            "the --growth-trace narration",
            &[Output {
                path: FIXTURE,
                build: narration,
            }],
        );
    }
}

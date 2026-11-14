// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Row 5 and Stuffing's instruments
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.32, EI-3 and EI-5):
//! the step response of `M_r` and the burn, the window-edge stuffer, and
//! the ESR-7 envelope in floors per byte.
//!
//! The window-edge stuffer is ESR-7's miner run for a window. A miner with
//! a declared hashrate share mines every `round(100 / share)`-th block and
//! lists bodies of its own there, after the pool's, as many as fit under
//! the penalty-free weight, so it takes no penalty
//! (`block_space::OwnBodies`). Unlike the envelope's one block, its bodies
//! enter the medians and the volume window, which is how it moves `M_r`.
//! Its gain is read against the same fold with no stuffing: the change in
//! `owed` on its own blocks, less the fees it paid.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;
use shekyl_economics::params::{SCALE, TX_VOLUME_WINDOW};
use shekyl_types::SHARD_LENGTH;

use crate::chain_cursor::OwnFee;
use crate::engine::{ScenarioConfig, SimParams, VolumeSchedule};
use crate::esr10::{scenario_named, Arm};
use crate::eup4::{release_multiplier_at, SharedRuns};
use crate::miner_stuffer::{envelope_at, ROWS};
use crate::scenarios::{BASELINE_STEADY_STATE, BOOM_BUST_CYCLE, STUFFING_ATTACK};
use crate::stage2::{a1_year_aggs_probed, BlockSeen, FoldProbe};

/// Blocks a trace starts before its edge, and runs after it.
const TRACE_BEFORE: u64 = 120;
const TRACE_AFTER: u64 = 3 * TX_VOLUME_WINDOW;
/// Blocks between printed trace samples.
const TRACE_STRIDE: u64 = 120;

/// The step schedule's name: 50 a block, 200 through year 2, 50 again.
pub(crate) const STEP: &str = "step_50_200_50";

/// The step schedule, a declared traffic schedule (§4's exogenous
/// schedules): the baseline's demand, four times it through year 2, and
/// the baseline's again.
pub(crate) fn step_scenario(params: &SimParams) -> ScenarioConfig {
    let mut config = scenario_named(params, BASELINE_STEADY_STATE);
    let demand = params.economic().tx_volume_baseline;
    config.name = STEP.into();
    config.description = "50 a block, 200 through year 2, then 50 again".into();
    config.sim_years = 4;
    config.volume = VolumeSchedule {
        get_volume: Box::new(move |block, blocks_per_year| {
            if block / blocks_per_year == 1 {
                demand * 4
            } else {
                demand
            }
        }),
    };
    config
}

/// One schedule the step response folds, and the blocks its demand steps
/// at.
struct Stepped {
    config: ScenarioConfig,
    edges: Vec<u64>,
}

fn stepped(params: &SimParams) -> Vec<Stepped> {
    let bpy = params.blocks_per_year();
    let mut boom_bust = scenario_named(params, BOOM_BUST_CYCLE);
    boom_bust.sim_years = 3;
    let mut stuffing = scenario_named(params, STUFFING_ATTACK);
    stuffing.sim_years = 1;
    vec![
        Stepped {
            config: step_scenario(params),
            edges: vec![bpy, 2 * bpy],
        },
        Stepped {
            config: boom_bust,
            edges: vec![bpy, 2 * bpy],
        },
        Stepped {
            config: stuffing,
            // The attack's last block is 21 599 (`scenarios.rs`).
            edges: vec![21_600],
        },
    ]
}

/// `M_r` and the burn rate at each block of a fold inside any edge's
/// trace.
struct TraceProbe<'p> {
    params: &'p SimParams,
    ranges: Vec<(u64, u64)>,
    samples: BTreeMap<u64, (u64, u64)>,
}

impl FoldProbe for TraceProbe<'_> {
    fn seen(&mut self, seen: &BlockSeen<'_, '_>) {
        if self
            .ranges
            .iter()
            .any(|&(from, to)| seen.block >= from && seen.block < to)
        {
            self.samples.insert(
                seen.block,
                (
                    release_multiplier_at(seen, self.params),
                    seen.priced.burn_pct,
                ),
            );
        }
    }
}

/// Blocks from `edge` until a series first covers 95 % of its move from
/// the block before the edge to the trace's last block. `None` when it
/// does not move.
fn settles(
    samples: &BTreeMap<u64, (u64, u64)>,
    edge: u64,
    pick: impl Fn((u64, u64)) -> u64,
) -> Option<u64> {
    let old = i128::from(pick(*samples.get(&(edge - 1))?));
    let new = i128::from(pick(*samples.get(&(edge + TRACE_AFTER - 1))?));
    let span = new - old;
    if span == 0 {
        return None;
    }
    (0..TRACE_AFTER).find(|&t| {
        samples
            .get(&(edge + t))
            .is_some_and(|&s| 20 * (i128::from(pick(s)) - old) * span.signum() >= 19 * span.abs())
    })
}

fn scaled(value: u64) -> f64 {
    value as f64 / SCALE as f64
}

/// EI-3's step-response summary row.
#[derive(Debug, Clone, Serialize)]
pub struct StepRow {
    arm: &'static str,
    scenario: String,
    edge_block: u64,
    m_r_before: f64,
    m_r_after: f64,
    m_r_settles_blocks: Option<u64>,
    burn_before_pct: f64,
    burn_after_pct: f64,
    burn_settles_blocks: Option<u64>,
}

/// EI-3 (row 5): `M_r` and the burn rate across each step in demand.
pub(crate) fn write_step_response(
    out: &mut impl fmt::Write,
    arms: &[Arm],
) -> Result<Vec<StepRow>, fmt::Error> {
    writeln!(
        out,
        "\nEI-3 — ROW 5, THE STEP RESPONSE. Production x1. Across each step in demand, M_r and the burn\n\
         rate every {TRACE_STRIDE} blocks from {TRACE_BEFORE} before the edge to {TRACE_AFTER} after it, and the blocks each takes\n\
         to cover 95 % of its move (from the block before the edge to the trace's last block). The\n\
         step schedule ({STEP}) is declared; boom-bust and the stuffing attack are run beside it."
    )?;
    let jobs: Vec<(&Arm, usize)> = arms
        .iter()
        .flat_map(|arm| (0..stepped(&arm.params).len()).map(move |i| (arm, i)))
        .collect();
    let folded = crate::parallel::map(&jobs, |&(arm, i)| {
        let schedule = stepped(&arm.params).swap_remove(i);
        let mut probe = TraceProbe {
            params: &arm.params,
            ranges: schedule
                .edges
                .iter()
                .map(|&edge| (edge - TRACE_BEFORE, edge + TRACE_AFTER))
                .collect(),
            samples: BTreeMap::new(),
        };
        a1_year_aggs_probed(&arm.params, &schedule.config, &mut probe);
        (schedule.config.name, schedule.edges, probe.samples)
    });
    let mut rows = Vec::new();
    for (&(arm, _), (scenario, edges, samples)) in jobs.iter().zip(folded) {
        for edge in edges {
            let before = samples[&(edge - 1)];
            let after = samples[&(edge + TRACE_AFTER - 1)];
            let m_r = settles(&samples, edge, |s| s.0);
            let burn = settles(&samples, edge, |s| s.1);
            let blocks =
                |b: Option<u64>| b.map_or("no move".to_string(), |b| format!("{b} blocks"));
            writeln!(
                out,
                "== {} | {scenario} | edge at block {edge}: M_r {:.3} -> {:.3}, 95 % in {}; burn {:.2}% -> {:.2}%, 95 % in {}",
                arm.which.name(),
                scaled(before.0),
                scaled(after.0),
                blocks(m_r),
                100.0 * scaled(before.1),
                100.0 * scaled(after.1),
                blocks(burn),
            )?;
            let mut line = String::from("     ");
            let mut t = 0;
            while t < TRACE_BEFORE + TRACE_AFTER {
                let block = edge - TRACE_BEFORE + t;
                if let Some(&(m, b)) = samples.get(&block) {
                    line.push_str(&format!(
                        " {:+}:{:.3}/{:.2}%",
                        i128::from(block) - i128::from(edge),
                        scaled(m),
                        100.0 * scaled(b)
                    ));
                }
                t += TRACE_STRIDE;
                if t % (5 * TRACE_STRIDE) == 0 {
                    writeln!(out, "{line}")?;
                    line = String::from("     ");
                }
            }
            if line.trim().is_empty() {
                // Every sample is printed.
            } else {
                writeln!(out, "{line}")?;
            }
            rows.push(StepRow {
                arm: arm.which.name(),
                scenario: scenario.clone(),
                edge_block: edge,
                m_r_before: scaled(before.0),
                m_r_after: scaled(after.0),
                m_r_settles_blocks: m_r,
                burn_before_pct: 100.0 * scaled(before.1),
                burn_after_pct: 100.0 * scaled(after.1),
                burn_settles_blocks: burn,
            });
        }
    }
    Ok(rows)
}

// ------------------------------------------------------- the window-edge stuffer

/// The stuffer's hashrate shares, percent: 20 % is the stuffing attack's.
pub(crate) const STUFFER_SHARES_PCT: [u64; 3] = [10, 20, 33];
/// The years a campaign starts in: the inherited arm's constrained era,
/// and after its ratchet.
pub(crate) const CAMPAIGN_START_YEARS: [u64; 2] = [5, 30];
/// A campaign's length, blocks: one volume window.
const CAMPAIGN_BLOCKS: u64 = TX_VOLUME_WINDOW;
/// The blocks a campaign is measured over: itself, and two windows after.
const MEASURED_BLOCKS: u64 = 3 * TX_VOLUME_WINDOW;

/// When the stuffer lists its bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Timing {
    /// In every own block of the campaign.
    Uniform,
    /// The same number of bodies, packed into the campaign's first own
    /// blocks: each one enters the window as early as it can.
    Edge,
}

impl Timing {
    const fn name(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::Edge => "edge",
        }
    }
}

const fn fee_name(fee: OwnFee) -> &'static str {
    match fee {
        OwnFee::None => "unenforced",
        OwnFee::RelayFloor => "enforced",
    }
}

/// One campaign, or the same blocks with no stuffing (`fee` `None`).
#[derive(Debug, Clone, Copy)]
struct Campaign {
    every: u64,
    start: u64,
    fee: Option<OwnFee>,
    timing: Timing,
    /// Bodies an edge campaign lists in all: its uniform twin's.
    budget: Option<u64>,
}

/// What a campaign's fold reads: `M_r` over the measured blocks, and the
/// stuffer's own blocks.
struct StufferProbe<'p> {
    params: &'p SimParams,
    campaign: Campaign,
    m_r: Vec<u64>,
    own_owed: u128,
    own_fees: u128,
    listed: u64,
    floor_rate: Option<u64>,
}

impl StufferProbe<'_> {
    fn measured(&self, block: u64) -> bool {
        block >= self.campaign.start && block < self.campaign.start + MEASURED_BLOCKS
    }

    fn own(&self, block: u64) -> bool {
        self.measured(block) && (block - self.campaign.start).is_multiple_of(self.campaign.every)
    }
}

impl FoldProbe for StufferProbe<'_> {
    fn own_bodies(&mut self, block: u64) -> Option<OwnFee> {
        let fee = self.campaign.fee?;
        if !self.own(block) {
            return None;
        }
        let listing = match self.campaign.timing {
            Timing::Uniform => block < self.campaign.start + CAMPAIGN_BLOCKS,
            Timing::Edge => self.listed < self.campaign.budget.unwrap_or(0),
        };
        listing.then_some(fee)
    }

    fn seen(&mut self, seen: &BlockSeen<'_, '_>) {
        if !self.measured(seen.block) {
            return;
        }
        if seen.block == self.campaign.start {
            self.floor_rate = Some(
                self.params
                    .fee
                    .admission_rate(&seen.priced.fee_point)
                    .atomic(),
            );
        }
        self.m_r.push(release_multiplier_at(seen, self.params));
        if self.own(seen.block) {
            self.own_owed += u128::from(seen.priced.paid.owed.to_raw());
            self.own_fees += u128::from(seen.priced.filled.own.fees_atomic);
            self.listed += seen.priced.filled.own.txs;
        }
    }
}

/// One campaign folded, or its counterfactual.
struct Folded {
    m_r: Vec<u64>,
    own_owed: u128,
    own_fees: u128,
    listed: u64,
    floor_rate: u64,
    archival_bytes: u64,
}

fn fold_campaign(params: &SimParams, start_year: u64, campaign: Campaign) -> Folded {
    let mut config = scenario_named(params, BASELINE_STEADY_STATE);
    config.sim_years = start_year;
    let mut probe = StufferProbe {
        params,
        campaign,
        m_r: Vec::new(),
        own_owed: 0,
        own_fees: 0,
        listed: 0,
        floor_rate: None,
    };
    let aggs = a1_year_aggs_probed(params, &config, &mut probe);
    Folded {
        m_r: probe.m_r,
        own_owed: probe.own_owed,
        own_fees: probe.own_fees,
        listed: probe.listed,
        floor_rate: probe
            .floor_rate
            .expect("the campaign's first block is measured"),
        archival_bytes: aggs.last().map_or(0, |a| a.cumulative_archival_bytes),
    }
}

/// The longest run of `M_r > 1.0` in `m_r`, and `M_r`'s mean over it.
fn longest_run_above_one(m_r: &[u64]) -> (u64, Option<f64>) {
    let (mut best, mut best_sum, mut run, mut sum) = (0u64, 0u128, 0u64, 0u128);
    for &m in m_r {
        if m > SCALE {
            run += 1;
            sum += u128::from(m);
            if run > best {
                best = run;
                best_sum = sum;
            }
        } else {
            run = 0;
            sum = 0;
        }
    }
    let mean = (best > 0).then(|| best_sum as f64 / best as f64 / SCALE as f64);
    (best, mean)
}

/// One campaign's reading (EI-3, and EI-5's member).
#[derive(Debug, Clone, Serialize)]
pub struct StufferRow {
    arm: &'static str,
    start_year: u64,
    share_pct: u64,
    fee: &'static str,
    timing: &'static str,
    bodies: u64,
    longest_run_blocks: u64,
    mean_m_r_over_run: Option<f64>,
    /// The fees it paid, in floors: one floor is the relay floor's fee for
    /// one reference transaction at the campaign's first block.
    gross_cost_floors: f64,
    /// Its payout less its fees, against no stuffing, SKL.
    net_gain_skl: f64,
    /// Archival bytes it added.
    archival_bytes: u64,
    /// Its net cost per archival byte over the relay floor's rate, in
    /// floors a byte; negative where it gains. `None` when it added none.
    net_cost_floors_per_byte: Option<f64>,
}

/// Every campaign on `arms` from each of `start_years`, at each of `shares`. The counterfactuals and the uniform campaigns
/// fold first, together; then each edge campaign, at its uniform twin's
/// bodies.
pub(crate) fn stuffer_rows(arms: &[Arm], start_years: &[u64], shares: &[u64]) -> Vec<StufferRow> {
    let every = |share: u64| (100 + share / 2) / share;
    let start = |a: usize, year: u64| (year - 1) * arms[a].params.blocks_per_year();
    let mut cells: Vec<(usize, u64, u64, OwnFee)> = Vec::new();
    let mut bases: Vec<(usize, u64, u64)> = Vec::new();
    for a in 0..arms.len() {
        for &year in start_years {
            for &share in shares {
                bases.push((a, year, share));
                for fee in [OwnFee::None, OwnFee::RelayFloor] {
                    cells.push((a, year, share, fee));
                }
            }
        }
    }
    // Phase one: each campaign uniform, and each share's blocks with no
    // stuffing at the same stride.
    let first: Vec<(usize, u64, u64, Option<OwnFee>)> = bases
        .iter()
        .map(|&(a, year, share)| (a, year, share, None))
        .chain(
            cells
                .iter()
                .map(|&(a, year, share, fee)| (a, year, share, Some(fee))),
        )
        .collect();
    let mut folded = crate::parallel::map(&first, |&(a, year, share, fee)| {
        fold_campaign(
            &arms[a].params,
            year,
            Campaign {
                every: every(share),
                start: start(a, year),
                fee,
                timing: Timing::Uniform,
                budget: None,
            },
        )
    });
    let uniform = folded.split_off(bases.len());
    let base_of = |a: usize, year: u64, share: u64| {
        let i = bases
            .iter()
            .position(|&key| key == (a, year, share))
            .expect("every cell has its counterfactual");
        &folded[i]
    };
    // Phase two: each campaign at the edge, with its uniform twin's bodies.
    let edge = crate::parallel::map(
        &cells.iter().zip(&uniform).collect::<Vec<_>>(),
        |&(&(a, year, share, fee), twin)| {
            fold_campaign(
                &arms[a].params,
                year,
                Campaign {
                    every: every(share),
                    start: start(a, year),
                    fee: Some(fee),
                    timing: Timing::Edge,
                    budget: Some(twin.listed),
                },
            )
        },
    );
    let mut rows = Vec::new();
    for ((&(a, year, share, fee), uniform), edge) in cells.iter().zip(&uniform).zip(&edge) {
        let base = base_of(a, year, share);
        for (timing, run) in [(Timing::Uniform, uniform), (Timing::Edge, edge)] {
            rows.push(reading(&arms[a], year, share, fee, timing, run, base));
        }
    }
    rows
}

fn reading(
    arm: &Arm,
    start_year: u64,
    share_pct: u64,
    fee: OwnFee,
    timing: Timing,
    folded: &Folded,
    base: &Folded,
) -> StufferRow {
    let (longest, mean) = longest_run_above_one(&folded.m_r);
    let floor_fee = u128::from(folded.floor_rate) * u128::from(arm.params.relay().ref_tx_weight);
    let gain = i128::try_from(folded.own_owed).expect("a window's payout fits")
        - i128::try_from(base.own_owed).expect("a window's payout fits")
        - i128::try_from(folded.own_fees).expect("a window's fees fit");
    let bytes = folded.archival_bytes.saturating_sub(base.archival_bytes);
    StufferRow {
        arm: arm.which.name(),
        start_year,
        share_pct,
        fee: fee_name(fee),
        timing: timing.name(),
        bodies: folded.listed,
        longest_run_blocks: longest,
        mean_m_r_over_run: mean,
        gross_cost_floors: if floor_fee == 0 {
            0.0
        } else {
            folded.own_fees as f64 / floor_fee as f64
        },
        net_gain_skl: gain as f64 / crate::burden::COIN as f64,
        archival_bytes: bytes,
        net_cost_floors_per_byte: (bytes > 0 && folded.floor_rate > 0)
            .then(|| -(gain as f64) / bytes as f64 / folded.floor_rate as f64),
    }
}

/// EI-3's stuffer: every campaign.
pub(crate) fn write_stuffer(out: &mut impl fmt::Write, rows: &[StufferRow]) -> fmt::Result {
    writeln!(
        out,
        "\nEI-3 — ROW 5, THE WINDOW-EDGE STUFFER. On the baseline, a miner with a hashrate share mines\n\
         every round(100/share)-th block and lists bodies of its own there after the pool's, as many\n\
         as fit under the penalty-free weight, for one window ({CAMPAIGN_BLOCKS} blocks) from the start of a\n\
         year: unenforced (no fee) or enforced (the relay floor), uniform (every own block) or edge (the\n\
         same bodies in the first own blocks). Measured over {MEASURED_BLOCKS} blocks from the start: the longest run of\n\
         M_r > 1.0 and M_r's mean over it; the fees paid in floors (one floor = the relay floor's fee\n\
         for one reference transaction at the start); the net gain against no stuffing (its payout\n\
         change less its fees, SKL)."
    )?;
    writeln!(
        out,
        "  {:<11} {:>3} {:>5} {:<10} {:<7} {:>7} {:>6} {:>7} {:>12} {:>14}",
        "arm",
        "y",
        "share",
        "fee",
        "timing",
        "bodies",
        "run",
        "mean",
        "cost floors",
        "net gain SKL"
    )?;
    for r in rows {
        writeln!(
            out,
            "  {:<11} {:>3} {:>4}% {:<10} {:<7} {:>7} {:>6} {:>7} {:>12.1} {:>14.2}",
            r.arm,
            r.start_year,
            r.share_pct,
            r.fee,
            r.timing,
            r.bodies,
            r.longest_run_blocks,
            r.mean_m_r_over_run
                .map_or("-".to_string(), |m| format!("{m:.4}")),
            r.gross_cost_floors,
            r.net_gain_skl,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------- EI-5

/// EI-5's summary row: one envelope row on one arm.
#[derive(Debug, Clone, Serialize)]
pub struct StuffingRow {
    arm: &'static str,
    scenario: &'static str,
    year: u64,
    era: &'static str,
    floor_atomic_per_byte: u64,
    today_floors_per_byte: f64,
    enforced_floors_per_byte: f64,
}

/// EI-5 (Stuffing): the ESR-7 envelope's minimum per archival byte over
/// the relay floor's rate, at ESR-7's rows, and the window-edge stuffer as
/// a further member.
pub(crate) fn write_stuffing_floors(
    out: &mut impl fmt::Write,
    shared: &SharedRuns,
    arms: &[Arm],
    stuffer: &[StufferRow],
) -> Result<Vec<StuffingRow>, fmt::Error> {
    let shard = SHARD_LENGTH.to_raw();
    writeln!(
        out,
        "\nEI-5 — STUFFING. The ESR-7 envelope's minimum on each chain (today; and with the floor\n\
         enforced on a block's own bodies) per archival byte, over the relay floor's rate at the same\n\
         block, in floors per byte, at ESR-7's rows; production x1. Then the window-edge stuffer as a\n\
         member: its net cost per archival byte it added, over the floor at its start (negative where\n\
         it gains), at the 20 % share."
    )?;
    let mut rows = Vec::new();
    for arm in arms {
        writeln!(out, "== {}", arm.which.name())?;
        for (scenario, year, era) in ROWS {
            let Some(run) = shared.runs.iter().find(|run| {
                run.arm == arm.which.name()
                    && run.fee == crate::eup4::FeeArm::Production
                    && run.scenario == scenario
            }) else {
                continue;
            };
            let Some(agg) = run.aggs.iter().find(|a| a.year == year) else {
                continue;
            };
            let envelope = envelope_at(&agg.last_block, &arm.params);
            let floor = envelope.floor.atomic();
            let per_byte = |atomic: u128| atomic as f64 / shard as f64 / floor as f64;
            let row = StuffingRow {
                arm: arm.which.name(),
                scenario,
                year,
                era,
                floor_atomic_per_byte: floor,
                today_floors_per_byte: per_byte(envelope.today_atomic()),
                enforced_floors_per_byte: per_byte(envelope.after_fix_atomic()),
            };
            writeln!(
                out,
                "  {:<22} y{year:<3} {era:<11} floor {floor} atomic/B: today {:.3}, enforced {:.3} floors/B",
                crate::stage2::trunc(scenario, 22),
                row.today_floors_per_byte,
                row.enforced_floors_per_byte,
            )?;
            rows.push(row);
        }
        for r in stuffer.iter().filter(|r| {
            r.arm == arm.which.name() && r.share_pct == 20 && r.timing == Timing::Uniform.name()
        }) {
            writeln!(
                out,
                "  window-edge stuffer    y{:<3} {:<11} {} archival bytes: {} floors/B",
                r.start_year,
                r.fee,
                r.archival_bytes,
                r.net_cost_floors_per_byte
                    .map_or("- (listed nothing)".to_string(), |c| format!("{c:.3}")),
            )?;
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest run counts only `M_r` strictly above 1.0, and its mean is
    /// over that run alone.
    #[test]
    fn the_longest_run_is_strictly_above_one() {
        let one = SCALE;
        let m_r = [
            one,
            one + 10,
            one + 30,
            one,
            one + 20,
            one + 20,
            one + 20,
            one,
        ];
        let (run, mean) = longest_run_above_one(&m_r);
        assert_eq!(run, 3);
        let mean = mean.expect("a run");
        assert!((mean - (one + 20) as f64 / one as f64).abs() < 1e-12);
        assert_eq!(longest_run_above_one(&[one; 4]), (0, None));
    }

    /// 95 % of a move is read from the block before the edge to the trace's
    /// last block, in either direction; a flat series has no move.
    #[test]
    fn a_series_settles_at_ninety_five_percent_of_its_move() {
        let edge = 1_000;
        let mut rising = BTreeMap::new();
        let mut flat = BTreeMap::new();
        rising.insert(edge - 1, (0, 100));
        flat.insert(edge - 1, (5, 5));
        for t in 0..TRACE_AFTER {
            let v = (t * 100 / 400).min(100);
            rising.insert(edge + t, (v, 100 - v));
            flat.insert(edge + t, (5, 5));
        }
        assert_eq!(settles(&rising, edge, |s| s.0), Some(380));
        assert_eq!(
            settles(&rising, edge, |s| s.1),
            Some(380),
            "falling the same"
        );
        assert_eq!(settles(&flat, edge, |s| s.0), None);
    }
}

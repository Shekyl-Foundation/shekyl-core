// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! EI-3's step response (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.32):
//! `M_r` and the burn across each declared step in demand.
//!
//! The trace is the blocks around an edge. Its settle time is the first
//! block that covers 95 % of the move from the block before the edge to
//! the trace's last block. The honest chain's window-mean reading is
//! [`crate::honest_step`], not this trace.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;
use shekyl_economics::params::TX_VOLUME_WINDOW;

use crate::engine::{ScenarioConfig, SimParams, VolumeSchedule};
use crate::esr10::{scenario_named, Arm};
use crate::eup4::release_multiplier_at;
use crate::scenarios::{
    BASELINE_STEADY_STATE, BOOM_BUST_CYCLE, STUFFING_ATTACK, STUFFING_ATTACK_BLOCKS,
};
use crate::stage2::{a1_year_aggs_probed, BlockSeen, FoldProbe};
use crate::window_stuffer::{scaled, years_through};

/// Blocks a trace starts before its edge, and runs after it.
const TRACE_BEFORE: u64 = 120;
pub(crate) const TRACE_AFTER: u64 = 3 * TX_VOLUME_WINDOW;

/// The first block of `edge`'s trace: [`TRACE_BEFORE`] blocks before it,
/// or the fold's first block where the edge is nearer than that.
fn trace_start(edge: u64) -> u64 {
    edge.saturating_sub(TRACE_BEFORE)
}

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

/// One schedule the step response folds, and the blocks its demand steps at.
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
    [
        (step_scenario(params), vec![bpy, 2 * bpy]),
        (boom_bust, vec![bpy, 2 * bpy]),
        // The attack's demand steps down at its last block's successor.
        (stuffing, vec![STUFFING_ATTACK_BLOCKS]),
    ]
    .into_iter()
    .map(|(mut config, edges)| {
        let last = edges.iter().max().expect("a schedule steps");
        config.sim_years = config.sim_years.max(years_through(last + TRACE_AFTER, bpy));
        Stepped { config, edges }
    })
    .collect()
}

/// `M_r` and the burn rate at each block of a fold inside any edge's trace.
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
pub(crate) fn settles(
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
                .map(|&edge| (trace_start(edge), edge + TRACE_AFTER))
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
            while trace_start(edge) + t < edge + TRACE_AFTER {
                let block = trace_start(edge) + t;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A day a block: 365 blocks a year, fewer than a trace, which is
    /// counted in blocks.
    fn day_blocks() -> SimParams {
        SimParams::with_overrides(vec![crate::baseline::Override::parse(
            "economic.daa_target_seconds=86400",
        )
        .expect("well-formed")])
        .expect("a day a block passes the validators")
    }

    /// Each schedule folds through its last edge's trace, whatever a
    /// year's blocks: the step response reads a sample at every traced block.
    #[test]
    fn every_schedule_folds_through_its_last_trace() {
        let params = day_blocks();
        let bpy = params.blocks_per_year();
        assert_eq!(bpy, 365);
        for schedule in stepped(&params) {
            let last = schedule.edges.iter().max().expect("a schedule steps");
            assert!(
                schedule.config.sim_years * bpy >= last + TRACE_AFTER,
                "{} ends before its trace",
                schedule.config.name
            );
        }
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

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stage-2 archival burden/escalation arms
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12).
//!
//! **Checkpoint 1 — the burden trajectory** (the A1 burden-growth side). This
//! module grows to hold the six §12.2 arms (A1 clearance … A6 swing); it starts
//! with the physical burden over time, since every arm weighs something against
//! it. The funding side is `budget.rs` (already landed); the clearance
//! comparison (A1) and the wargame arms (A4/A5) land in later checkpoints.
//!
//! Output convention matches the rest of the binary: machine JSON to stdout,
//! the human-readable table to stderr.

use serde::Serialize;
use std::io::Write;

use crate::burden::{
    burden_cost_fiat_per_year, frozen_shards, KryderRate, BASE_STORAGE_FIAT_PER_BYTE_YEAR,
    OUTPUTS_PER_TX_NORMAL,
};
use crate::engine::{ScenarioConfig, SimParams};
use crate::scenarios::all_scenarios;

/// One sampled year of a scenario's burden trajectory. Storage cost is reported
/// across the full DQ-2B Kryder band at the base price; the `SKL/fiat`
/// conversion is an arm concern (the burden is fiat-denominated here).
#[derive(Debug, Clone, Serialize)]
pub struct BurdenYearRow {
    pub year: u64,
    /// Cumulative outputs (leaves) at the end of this year.
    pub cumulative_outputs: u64,
    /// `frozen_segment_count` — the D2 operand `n`.
    pub frozen_shards: u64,
    /// Whole-corpus annual burden cost (fiat), 0%/yr Kryder — the **binding**
    /// clearance case.
    pub burden_fiat_stall: f64,
    /// … 10%/yr Kryder.
    pub burden_fiat_slowdown: f64,
    /// … 25%/yr Kryder.
    pub burden_fiat_historical: f64,
}

/// A scenario's burden trajectory over its simulated years.
#[derive(Debug, Clone, Serialize)]
pub struct BurdenTrajectory {
    pub scenario: String,
    pub description: String,
    pub sim_years: u64,
    /// Final `n` (shards are monotone, so this is the max).
    pub final_frozen_shards: u64,
    pub years: Vec<BurdenYearRow>,
}

/// Simulate a scenario's honest burden: accumulate outputs
/// (`tx_volume · OUTPUTS_PER_TX_NORMAL`), sample `frozen_shards` and the
/// Kryder-band burden cost at each year boundary.
///
/// The Kryder decline runs over **elapsed years** (the base scenarios start at
/// genesis, `genesis_height_offset == 0`); scenario 9's pre-existing history is
/// handled where it lands.
#[must_use]
pub fn burden_trajectory(params: &SimParams, config: &ScenarioConfig) -> BurdenTrajectory {
    let total_blocks = params.blocks_per_year * config.sim_years;
    // Accumulate in f64 so a fractional outputs-per-tx never rounds per block;
    // floor to u64 only at the freeze-rule boundary.
    let mut cumulative_outputs: f64 = 0.0;
    let mut years: Vec<BurdenYearRow> = Vec::with_capacity(config.sim_years as usize);

    for block in 0..total_blocks {
        let txs = (config.volume.get_volume)(block, params.blocks_per_year);
        cumulative_outputs += txs as f64 * OUTPUTS_PER_TX_NORMAL;

        if (block + 1) % params.blocks_per_year == 0 {
            let year = (block + 1) / params.blocks_per_year; // 1-indexed
            let shards = frozen_shards(cumulative_outputs as u64);
            let year_f = year as f64;
            years.push(BurdenYearRow {
                year,
                cumulative_outputs: cumulative_outputs as u64,
                frozen_shards: shards,
                burden_fiat_stall: burden_cost_fiat_per_year(
                    shards,
                    year_f,
                    BASE_STORAGE_FIAT_PER_BYTE_YEAR,
                    KryderRate::Stall,
                ),
                burden_fiat_slowdown: burden_cost_fiat_per_year(
                    shards,
                    year_f,
                    BASE_STORAGE_FIAT_PER_BYTE_YEAR,
                    KryderRate::Slowdown,
                ),
                burden_fiat_historical: burden_cost_fiat_per_year(
                    shards,
                    year_f,
                    BASE_STORAGE_FIAT_PER_BYTE_YEAR,
                    KryderRate::Historical,
                ),
            });
        }
    }

    let final_frozen_shards = years.last().map_or(0, |y| y.frozen_shards);
    BurdenTrajectory {
        scenario: config.name.clone(),
        description: config.description.clone(),
        sim_years: config.sim_years,
        final_frozen_shards,
        years,
    }
}

/// `--stage2` entry: the burden trajectory across the scenario set. JSON to
/// stdout, a human-readable summary to stderr.
pub fn run_stage2(params: &SimParams) {
    eprintln!(
        "Stage-2 archival burden trajectory (§12.1 checkpoint 1)\n\
         outputs = tx_volume x {OUTPUTS_PER_TX_NORMAL:.0} (1in/2out normal traffic); \
         n = frozen_segment_count(cumulative outputs)\n\
         burden = n x {SHARD:.2} MB x storage($/B/yr, Kryder); \
         base = {BASE:.0e} $/B/yr; funding + clearance (A1) land next\n",
        SHARD = crate::burden::SHARD_BYTES / 1.0e6,
        BASE = BASE_STORAGE_FIAT_PER_BYTE_YEAR,
    );
    eprintln!("Kryder band swept (DQ-2B):");
    for k in KryderRate::BAND {
        eprintln!("  - {}", k.label());
    }
    eprintln!();
    eprintln!(
        "{:<22} {:>6} {:>14} {:>10} {:>16}",
        "scenario", "years", "final_outputs", "final_n", "final_burden$/yr@0%"
    );

    let mut trajectories: Vec<BurdenTrajectory> = Vec::new();
    for config in all_scenarios(params) {
        let traj = burden_trajectory(params, &config);
        let final_burden = traj.years.last().map_or(0.0, |y| y.burden_fiat_stall);
        let final_outputs = traj.years.last().map_or(0, |y| y.cumulative_outputs);
        eprintln!(
            "{:<22} {:>6} {:>14} {:>10} {:>16.2}",
            traj.scenario, traj.sim_years, final_outputs, traj.final_frozen_shards, final_burden,
        );
        trajectories.push(traj);
    }

    eprintln!(
        "\nReading: `final_n` is the D2 operand at horizon; `final_burden` is the\n\
         whole-corpus annual storage cost under the BINDING 0%/yr Kryder case.\n\
         Absolute $ is conditional on the base-price + SKL/fiat bands (N-1); the\n\
         robust signal is the burden *trajectory* vs the funding decay (A1, next)."
    );

    let json = serde_json::to_string_pretty(&trajectories).expect("JSON serialization failed");
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes()).expect("write failed");
    stdout.write_all(b"\n").expect("write failed");
    eprintln!("\nStage-2 burden trajectory complete. Per-year JSON written to stdout.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trajectory_shards_are_monotone_and_final_is_max() {
        let params = SimParams::default();
        for config in all_scenarios(&params) {
            let traj = burden_trajectory(&params, &config);
            let mut prev = 0u64;
            for row in &traj.years {
                assert!(
                    row.frozen_shards >= prev,
                    "shards must be monotone in {}: {} < {}",
                    traj.scenario,
                    row.frozen_shards,
                    prev
                );
                prev = row.frozen_shards;
            }
            assert_eq!(traj.final_frozen_shards, prev);
        }
    }

    #[test]
    fn stall_burden_is_the_binding_worst_case() {
        let params = SimParams::default();
        // At every sampled year, the 0%/yr band is >= the declining bands.
        for config in all_scenarios(&params) {
            for row in burden_trajectory(&params, &config).years {
                assert!(row.burden_fiat_stall >= row.burden_fiat_slowdown);
                assert!(row.burden_fiat_slowdown >= row.burden_fiat_historical);
            }
        }
    }
}

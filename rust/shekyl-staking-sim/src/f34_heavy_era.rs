// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **`--f34-heavy-era`** — the heavy-era-ages-into-deep arm, run exactly as
//! `STAKER_ARCHIVAL_SIM.md` §L19a pre-registers it (committed `cd1f87651`, amended
//! `7f5119f49`, both before this code existed).
//!
//! The question: does a heavy era, aged into the **deep** band with its bytes intact,
//! breach coverage when **total bytes are held fixed**? It is the one arm that could
//! force a byte operand into channel 1 (`PDM-Q6` item 5's **(g)**).
//!
//! **The method, as registered — this module implements it and chooses nothing:**
//!
//! - **Demand matching normalizes sizes** (`World::renormalize_sizes`, every epoch),
//!   so capacity, carry and the L10 fetch lag all see fixed total bytes. The realized
//!   mean must read 1.000 or the run is not evidence.
//! - **Paired, `N = 8` seeds** (common random numbers): each arm and its dynamic,
//!   demand-matched control run on the same seed, and the delta is formed **per seed**.
//! - **Per seed, the worst-band delta is the worst of the differences** —
//!   `max over cells of (arm − control)`, cell by cell, over cells occupied in both —
//!   never `max(arm) − max(control)`.
//! - **BREACH ⇔ `min over seeds` of that delta `> X = 0.05`.**
//! - **Both bases**, marginal (`storage_scale` 1.0) and covered (1.3).
//! - **The subject must be in frame**: every arm run must show deep heavies
//!   (`InFrame::deep_heavy > 0`), and for `Burst` they must be the majority of the
//!   heavies. A run that fails this is **void**, and a verdict with a void run in it
//!   is not reported as one.
//! - The `storage_scale`-scaled variant is **diagnostic and ungraded**, same pairing.

use crate::metrics::{BandedVerdict, GRADING_AGE_BANDS, GRADING_COST_BANDS};
use crate::model::EraShape;
use crate::scenarios::{baseline, run_sim, ScenarioResult, SimConfig};

/// `N`, fixed by §L19a item 2 before the first run.
pub const SEEDS: u64 = 8;
/// `X`, fixed by §L19a item 2 before the first run.
pub const BREACH_X: f64 = 0.05;
/// The first seed — the baseline's own, so seed 0 of every pair is the default run.
const SEED0: u64 = 0x5EED_1234;
/// The dynamic window the arm lives in (§L19 arm, unchanged).
const EPOCH_AGING: f64 = 0.02;

/// Per-seed worst-band delta: `max over cells occupied in both of (arm − control)`.
/// `None` if no cell is occupied in both, which would make the seed void.
pub fn cellwise_worst_delta(arm: &BandedVerdict, ctl: &BandedVerdict) -> Option<f64> {
    let mut worst: Option<f64> = None;
    for a in 0..GRADING_AGE_BANDS {
        for c in 0..GRADING_COST_BANDS {
            if arm.cell_n[a][c] == 0 || ctl.cell_n[a][c] == 0 {
                continue;
            }
            let d = arm.cells[a][c] - ctl.cells[a][c];
            worst = Some(worst.map_or(d, |w: f64| w.max(d)));
        }
    }
    worst
}

fn dynamic_cfg(name: String, base_scale: f64, seed: u64) -> SimConfig {
    let mut c = baseline();
    c.name = name;
    c.axis = "f34_l19a".into();
    c.storage_scale = base_scale;
    c.dynamic = true;
    c.epoch_aging = EPOCH_AGING;
    c.seed = seed;
    c
}

fn arm_cfg(shape: EraShape, spread: f64, base_scale: f64, seed: u64, matched: bool) -> SimConfig {
    let mut c = dynamic_cfg(format!("arm_{shape:?}_s{spread:.0}"), base_scale, seed);
    c.era_shape = shape;
    c.size_spread = spread;
    c.demand_match = matched;
    c
}

/// Whether an arm run shows its subject (§L19a item 4).
fn in_frame(shape: EraShape, r: &ScenarioResult) -> bool {
    let f = r.in_frame;
    match shape {
        EraShape::Burst => f.deep_heavy > 0 && f.deep_heavy * 2 > f.heavy,
        _ => f.deep_heavy > 0,
    }
}

#[derive(serde::Serialize)]
struct SeedRow {
    seed: u64,
    delta: Option<f64>,
    worst_band: (usize, usize),
    margin_arm: i64,
    margin_ctl: i64,
    size_mean: f64,
    deep_heavy: usize,
    heavy: usize,
    in_frame: bool,
    /// The diagnostic `storage_scale`-scaled variant's delta for the same seed.
    diag_delta: Option<f64>,
    diag_unmatched_mean: f64,
}

#[derive(serde::Serialize)]
struct ArmReport {
    base: &'static str,
    shape: String,
    spread: f64,
    seeds: Vec<SeedRow>,
    min_delta: Option<f64>,
    void_runs: usize,
    mean_off_one: usize,
    verdict: &'static str,
    diag_min_delta: Option<f64>,
}

pub fn print_f34_heavy_era_report() {
    let bases: [(&'static str, f64); 2] = [("marginal", 1.0), ("covered", 1.3)];
    let arms = [
        (EraShape::Plateau, 4.0),
        (EraShape::Plateau, 10.0),
        (EraShape::Burst, 4.0),
        (EraShape::Burst, 10.0),
    ];
    let mut reports = Vec::new();

    for (base, scale) in bases {
        // One control per (base, seed): composition off, so matched and unmatched are
        // the same run, and it serves every arm on that base.
        let controls: Vec<ScenarioResult> = (0..SEEDS)
            .map(|i| {
                let mut c = dynamic_cfg(format!("ctl_{base}"), scale, SEED0 + i);
                c.demand_match = true;
                run_sim(&c)
            })
            .collect();

        for (shape, spread) in arms {
            let mut rows = Vec::new();
            for i in 0..SEEDS {
                let seed = SEED0 + i;
                let ctl = &controls[i as usize];
                let arm = run_sim(&arm_cfg(shape, spread, scale, seed, true));
                let delta = cellwise_worst_delta(&arm.banded, &ctl.banded);
                let frame = in_frame(shape, &arm);

                // Diagnostic, ungraded: hold bytes fixed on the CAPACITY leg only, by
                // scaling the budget by this seed's unmatched realized mean.
                let unmatched = run_sim(&arm_cfg(shape, spread, scale, seed, false));
                let mut scaled = arm_cfg(shape, spread, scale * unmatched.size_mean, seed, false);
                scaled.name = format!("{}_scaled", scaled.name);
                let diag = run_sim(&scaled);
                let diag_delta = cellwise_worst_delta(&diag.banded, &ctl.banded);

                rows.push(SeedRow {
                    seed,
                    delta,
                    worst_band: arm.banded.worst_band,
                    margin_arm: arm.banded.worst_margin,
                    margin_ctl: ctl.banded.worst_margin,
                    size_mean: arm.size_mean,
                    deep_heavy: arm.in_frame.deep_heavy,
                    heavy: arm.in_frame.heavy,
                    in_frame: frame,
                    diag_delta,
                    diag_unmatched_mean: unmatched.size_mean,
                });
            }
            let void_runs = rows
                .iter()
                .filter(|r| !r.in_frame || r.delta.is_none())
                .count();
            let mean_off_one = rows
                .iter()
                .filter(|r| (r.size_mean - 1.0).abs() > 1e-9)
                .count();
            let min_delta = rows
                .iter()
                .filter_map(|r| r.delta)
                .fold(None, |m: Option<f64>, d| Some(m.map_or(d, |m| m.min(d))));
            let diag_min_delta = rows
                .iter()
                .filter_map(|r| r.diag_delta)
                .fold(None, |m: Option<f64>, d| Some(m.map_or(d, |m| m.min(d))));
            // A verdict with a void run or a mean off 1.000 is not a verdict.
            let verdict = if void_runs > 0 {
                "VOID (subject not in frame)"
            } else if mean_off_one > 0 {
                "VOID (demand not matched)"
            } else if min_delta.is_some_and(|d| d > BREACH_X) {
                "BREACH"
            } else {
                "clear"
            };
            reports.push(ArmReport {
                base,
                shape: format!("{shape:?}"),
                spread,
                seeds: rows,
                min_delta,
                void_runs,
                mean_off_one,
                verdict,
                diag_min_delta,
            });
        }
    }

    match serde_json::to_string_pretty(&reports) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing f34 report: {e}"),
    }
    eprintln!("F34 heavy-era arm (§L19a): N = {SEEDS} paired seeds, BREACH iff min over seeds of max-over-cells (arm − control) > {BREACH_X}");
    eprintln!("base      shape      S |  minDelta   diagMin | void mOff |  deepHeavy | VERDICT");
    for r in &reports {
        let dh: Vec<String> = r
            .seeds
            .iter()
            .map(|s| format!("{}/{}", s.deep_heavy, s.heavy))
            .collect();
        eprintln!(
            "{:<9} {:<8} {:>3.0} | {:>9} {:>9} | {:>4} {:>4} | {:>10} | {}",
            r.base,
            r.shape,
            r.spread,
            r.min_delta.map_or("-".into(), |d| format!("{d:+.3}")),
            r.diag_min_delta.map_or("-".into(), |d| format!("{d:+.3}")),
            r.void_runs,
            r.mean_off_one,
            dh.first().cloned().unwrap_or_default(),
            r.verdict
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_with(cells: [[f64; 3]; 3], n: usize) -> BandedVerdict {
        BandedVerdict {
            worst_frac_under: 0.0,
            worst_margin: 0,
            worst_band: (0, 0),
            worst_band_n: 0,
            cells,
            cell_n: [[n; 3]; 3],
        }
    }

    /// The pre-registered delta is the worst of the DIFFERENCES, not the difference of
    /// the worsts. Here the control's worst cell is elsewhere: difference-of-worsts
    /// would read 0.5 − 0.6 = −0.1 (clear); cell-wise reads 0.5 − 0.0 = +0.5 in the
    /// cell where the arm actually degraded.
    #[test]
    fn the_delta_is_cell_wise_not_a_difference_of_worsts() {
        let mut arm = [[0.0; 3]; 3];
        arm[2][2] = 0.5;
        let mut ctl = [[0.0; 3]; 3];
        ctl[0][0] = 0.6;
        let d = cellwise_worst_delta(&verdict_with(arm, 10), &verdict_with(ctl, 10)).unwrap();
        assert!((d - 0.5).abs() < 1e-12, "cell-wise delta {d}");
    }

    /// A cell empty in either run contributes nothing; all empty ⇒ no delta (void).
    #[test]
    fn empty_cells_contribute_no_delta() {
        assert!(cellwise_worst_delta(
            &verdict_with([[1.0; 3]; 3], 0),
            &verdict_with([[0.0; 3]; 3], 5)
        )
        .is_none());
    }
}

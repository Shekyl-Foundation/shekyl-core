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

/// The lever values a run is taken at. `age_weight` defaults to the baseline's.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Levers {
    /// Headroom.
    pub storage_scale: f64,
    /// The deep-history premium.
    pub age_weight: f64,
    /// The per-unit carry cost of storage (§L19e).
    pub storage_unit_cost: f64,
}

impl Levers {
    /// The covered baseline's levers at a given headroom.
    fn at_scale(storage_scale: f64) -> Self {
        let b = baseline();
        Self {
            storage_scale,
            age_weight: b.age_weight,
            storage_unit_cost: b.storage_unit_cost,
        }
    }
}

fn dynamic_cfg(name: String, lv: Levers, seed: u64) -> SimConfig {
    let mut c = baseline();
    c.name = name;
    c.axis = "f34_l19a".into();
    c.storage_scale = lv.storage_scale;
    c.age_weight = lv.age_weight;
    c.storage_unit_cost = lv.storage_unit_cost;
    c.dynamic = true;
    c.epoch_aging = EPOCH_AGING;
    c.seed = seed;
    c
}

fn arm_cfg(shape: EraShape, spread: f64, lv: Levers, seed: u64, matched: bool) -> SimConfig {
    let mut c = dynamic_cfg(format!("arm_{shape:?}_s{spread:.0}"), lv, seed);
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
pub struct SeedRow {
    pub seed: u64,
    pub delta: Option<f64>,
    pub worst_band: (usize, usize),
    pub margin_arm: i64,
    pub margin_ctl: i64,
    pub size_mean: f64,
    pub deep_heavy: usize,
    pub heavy: usize,
    pub in_frame: bool,
    /// Absolute worst-band `frac_under` of the arm and of its control — reported so a
    /// delta between two saturated (or two collapsed) runs is visible as such.
    pub arm_worst: f64,
    pub ctl_worst: f64,
    /// Shards in the arm's worst cell, and the control's own worst cell — the control
    /// can fail somewhere the arm does not, which the cell-wise delta nets out.
    pub arm_worst_band_n: usize,
    pub ctl_worst_band: (usize, usize),
    /// The diagnostic `storage_scale`-scaled variant's delta for the same seed.
    pub diag_delta: Option<f64>,
    pub diag_unmatched_mean: f64,
}

#[derive(serde::Serialize)]
pub struct ArmReport {
    pub base: &'static str,
    pub shape: String,
    pub spread: f64,
    pub seeds: Vec<SeedRow>,
    pub min_delta: Option<f64>,
    pub void_runs: usize,
    pub mean_off_one: usize,
    pub verdict: &'static str,
    pub diag_min_delta: Option<f64>,
}

/// One lever point graded as L19a registers it: `N` paired seeds, each arm against
/// the control at the **same lever values** (so a lever that moves the flat control is
/// credited only with its effect on the heavy era), cell-wise delta, demand matching,
/// in-frame check. `diagnostic` adds L19a's ungraded `storage_scale` variant.
fn grade_point(
    shape: EraShape,
    spread: f64,
    lv: Levers,
    diagnostic: bool,
) -> (Vec<SeedRow>, Grade) {
    let mut rows = Vec::new();
    for i in 0..SEEDS {
        let seed = SEED0 + i;
        let mut cc = dynamic_cfg("ctl".into(), lv, seed);
        cc.demand_match = true;
        let ctl = run_sim(&cc);
        let arm = run_sim(&arm_cfg(shape, spread, lv, seed, true));
        let delta = cellwise_worst_delta(&arm.banded, &ctl.banded);
        let (diag_delta, diag_unmatched_mean) = if diagnostic {
            let unmatched = run_sim(&arm_cfg(shape, spread, lv, seed, false));
            let scaled_lv = Levers {
                storage_scale: lv.storage_scale * unmatched.size_mean,
                ..lv
            };
            let diag = run_sim(&arm_cfg(shape, spread, scaled_lv, seed, false));
            (
                cellwise_worst_delta(&diag.banded, &ctl.banded),
                unmatched.size_mean,
            )
        } else {
            (None, f64::NAN)
        };
        rows.push(SeedRow {
            seed,
            delta,
            worst_band: arm.banded.worst_band,
            margin_arm: arm.banded.worst_margin,
            margin_ctl: ctl.banded.worst_margin,
            size_mean: arm.size_mean,
            deep_heavy: arm.in_frame.deep_heavy,
            heavy: arm.in_frame.heavy,
            in_frame: in_frame(shape, &arm),
            arm_worst: arm.banded.worst_frac_under,
            ctl_worst: ctl.banded.worst_frac_under,
            arm_worst_band_n: arm.banded.worst_band_n,
            ctl_worst_band: ctl.banded.worst_band,
            diag_delta,
            diag_unmatched_mean,
        });
    }
    let g = Grade::of(&rows);
    (rows, g)
}

/// The registered verdict over one point's seeds.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Grade {
    pub min_delta: Option<f64>,
    pub median_delta: Option<f64>,
    pub max_delta: Option<f64>,
    /// Seeds whose delta exceeds `BREACH_X`. The registered BREACH needs all `SEEDS`; its
    /// complement, "clear", needs only one seed at or under the bar — so a clear is read
    /// with this count beside it, never alone.
    pub seeds_over_x: usize,
    pub void_runs: usize,
    pub mean_off_one: usize,
    pub verdict: &'static str,
    /// The worst cell on the most seeds, and on how many.
    pub modal_worst_band: (usize, usize),
    pub modal_worst_band_seeds: usize,
    /// Median across seeds of the arm's and of the control's **absolute** worst-cell
    /// `frac_under`. The verdict reads only the delta; these show when a delta is taken
    /// between two runs that have both collapsed (or a control that has), where a
    /// `frac_under` bounded at 1 caps the delta and it stops reading the arm.
    pub median_arm_worst: f64,
    pub median_ctl_worst: f64,
}

impl Grade {
    fn of(rows: &[SeedRow]) -> Self {
        let void_runs = rows
            .iter()
            .filter(|r| !r.in_frame || r.delta.is_none())
            .count();
        let mean_off_one = rows
            .iter()
            .filter(|r| (r.size_mean - 1.0).abs() > 1e-9)
            .count();
        let mut ds: Vec<f64> = rows.iter().filter_map(|r| r.delta).collect();
        ds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let min_delta = ds.first().copied();
        let max_delta = ds.last().copied();
        let seeds_over_x = ds.iter().filter(|&&d| d > BREACH_X).count();
        let median_delta = if ds.is_empty() {
            None
        } else {
            Some(ds[ds.len() / 2])
        };
        let mut counts = [[0usize; GRADING_COST_BANDS]; GRADING_AGE_BANDS];
        for r in rows {
            counts[r.worst_band.0][r.worst_band.1] += 1;
        }
        let mut modal = ((0, 0), 0);
        for (a, row) in counts.iter().enumerate() {
            for (c, &n) in row.iter().enumerate() {
                if n > modal.1 {
                    modal = ((a, c), n);
                }
            }
        }
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
        Self {
            min_delta,
            median_delta,
            max_delta,
            seeds_over_x,
            void_runs,
            mean_off_one,
            verdict,
            modal_worst_band: modal.0,
            modal_worst_band_seeds: modal.1,
            median_arm_worst: median(rows.iter().map(|r| r.arm_worst)),
            median_ctl_worst: median(rows.iter().map(|r| r.ctl_worst)),
        }
    }
}

/// **`--f34-heavy-era`** — §L19a's graded arms on both bases, with the diagnostic
/// `storage_scale` variant. Rendered by `main.rs`.
pub fn heavy_era_report() -> Vec<ArmReport> {
    let bases: [(&'static str, f64); 2] = [("marginal", 1.0), ("covered", 1.3)];
    let arms = [
        (EraShape::Plateau, 4.0),
        (EraShape::Plateau, 10.0),
        (EraShape::Burst, 4.0),
        (EraShape::Burst, 10.0),
    ];
    let mut reports = Vec::new();

    for (base, scale) in bases {
        for (shape, spread) in arms {
            let lv = Levers::at_scale(scale);
            let (rows, g) = grade_point(shape, spread, lv, true);
            let diag_min_delta = rows
                .iter()
                .filter_map(|r| r.diag_delta)
                .fold(None, |m: Option<f64>, d| Some(m.map_or(d, |m| m.min(d))));
            reports.push(ArmReport {
                base,
                shape: format!("{shape:?}"),
                spread,
                seeds: rows,
                min_delta: g.min_delta,
                void_runs: g.void_runs,
                mean_off_one: g.mean_off_one,
                verdict: g.verdict,
                diag_min_delta,
            });
        }
    }
    reports
}

/// `STAKER_ARCHIVAL_SIM.md` §L19c's headroom ladder, fixed before the run. `1.32` and
/// `1.34` round to exactly `1.30`'s whole-slot capacities and are omitted.
pub const HEADROOM_LADDER: [f64; 8] = [1.30, 1.36, 1.40, 1.45, 1.50, 1.60, 1.75, 2.00];
/// §L19c's `age_weight` ladder, fixed before the run (`2.0` is the baseline).
pub const AGE_WEIGHT_LADDER: [f64; 7] = [0.0, 1.0, 2.0, 3.0, 4.0, 6.0, 8.0];

#[derive(serde::Serialize)]
pub struct LeverRow {
    pub lever: &'static str,
    pub spread: f64,
    pub levers: Levers,
    /// Whole storage slots for a storage-rich / capital-rich actor at this point.
    pub slots: (usize, usize),
    pub grade: Grade,
    pub seeds: Vec<SeedRow>,
}

pub fn slots(scale: f64) -> (usize, usize) {
    let b = baseline();
    (
        ((b.storage_rich_storage as f64 * scale).round() as usize).max(1),
        ((b.capital_rich_storage as f64 * scale).round() as usize).max(1),
    )
}

/// **`--f34-levers`** — `STAKER_ARCHIVAL_SIM.md` §L19c on covered Burst: headroom and
/// `age_weight`, one at a time from the covered baseline, then the corner. `r_target`
/// is the grading bar and is not swept.
pub fn lever_report() -> Vec<LeverRow> {
    const COVERED: f64 = 1.30;
    let mut rows = Vec::new();
    for spread in [4.0, 10.0] {
        for &sc in &HEADROOM_LADDER {
            let lv = Levers::at_scale(sc);
            let (seeds, g) = grade_point(EraShape::Burst, spread, lv, false);
            rows.push(LeverRow {
                lever: "headroom",
                spread,
                levers: lv,
                slots: slots(sc),
                grade: g,
                seeds,
            });
        }
        for &aw in &AGE_WEIGHT_LADDER {
            let lv = Levers {
                age_weight: aw,
                ..Levers::at_scale(COVERED)
            };
            let (seeds, g) = grade_point(EraShape::Burst, spread, lv, false);
            rows.push(LeverRow {
                lever: "age_weight",
                spread,
                levers: lv,
                slots: slots(COVERED),
                grade: g,
                seeds,
            });
        }
        let lv = Levers {
            age_weight: AGE_WEIGHT_LADDER[AGE_WEIGHT_LADDER.len() - 1],
            ..Levers::at_scale(HEADROOM_LADDER[HEADROOM_LADDER.len() - 1])
        };
        let (seeds, g) = grade_point(EraShape::Burst, spread, lv, false);
        rows.push(LeverRow {
            lever: "corner",
            spread,
            levers: lv,
            slots: slots(lv.storage_scale),
            grade: g,
            seeds,
        });
    }
    rows
}

/// One `storage_unit_cost` point of §L19e.
#[derive(serde::Serialize)]
pub struct UnitCostRow {
    pub spread: f64,
    pub storage_unit_cost: f64,
    pub grade: Grade,
    pub seeds: Vec<SeedRow>,
}

/// `STAKER_ARCHIVAL_SIM.md` §L19e's `storage_unit_cost` ladder, fixed before the run
/// (`0.03` is the baseline).
pub const UNIT_COST_LADDER: [f64; 6] = [0.0, 0.01, 0.03, 0.06, 0.10, 0.20];

/// **`--f34-unit-cost`** — §L19e (item 7): the carry signal separated from the capacity
/// leg on the L19d subject. `0.0` removes the size-scaled carry term but not the
/// size-scaled L10 fetch lag — inert here because `fetch_latency_per_unit` is `0.0` at
/// baseline — so that point is capacity + (inert) fetch.
pub fn unit_cost_report() -> Vec<UnitCostRow> {
    let mut rows = Vec::new();
    for spread in [4.0, 10.0] {
        for &uc in &UNIT_COST_LADDER {
            let lv = Levers {
                storage_unit_cost: uc,
                ..Levers::at_scale(1.30)
            };
            let (seeds, g) = grade_point(EraShape::Burst, spread, lv, false);
            rows.push(UnitCostRow {
                spread,
                storage_unit_cost: uc,
                grade: g,
                seeds,
            });
        }
    }
    rows
}

fn median(xs: impl Iterator<Item = f64>) -> f64 {
    let mut v: Vec<f64> = xs.collect();
    v.sort_by(f64::total_cmp);
    v.get(v.len() / 2).copied().unwrap_or(f64::NAN)
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

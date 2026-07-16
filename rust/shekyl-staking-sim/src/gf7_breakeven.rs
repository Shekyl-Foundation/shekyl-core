//! GF-7 effective-cover breakeven sweep — the fifth WI-4 §13.5 conditional's
//! monitoring threshold (`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §13.5;
//! `ARCHIVAL_FIREWALL_GATE6.md` §12.8).
//!
//! # What this is — and what it is not
//!
//! The WI-4 gate verdict (`r = 1.86 < 2` at `N = 10`) was computed at
//! **nominal** cover: `RunConfig { n: 10 }` seeds the full honest-traffic
//! strength, and Gate-6 §11 qualifier (iv) names the measured set an upper
//! bound. The *effective* post-isolation cover is an economics quantity
//! (Gate-6 §11.8 method note 3) — unmeasurable pre-genesis. That makes the
//! gate's central number conditional on a cover level nobody can validate
//! before real value is at risk.
//!
//! This sweep derives the one thing about that conditional that **is**
//! derivable today: the breakeven — at what cover level does the model's own
//! `r` reach the committed bound? It is a sensitivity sweep over the existing
//! harness at the gate-relevant posture (`SynthParams::posture()`), a property
//! of the **model**, not of the world: mechanism-class under method note 3,
//! no testnet, no economics input.
//!
//! It is **not a gate**. The gate (`r < 2` at target cover) passed and is not
//! re-litigated here. Gate-side, a breakeven bar would be overreach — it would
//! gate on a whole-system end state the protocol does not control.
//! Aspiration-side, it converts the fifth conditional from "unfalsifiable,
//! carry an assumption" into "cover ≥ threshold, monitored against a named
//! number" — a real reopen criterion. The post-genesis monitoring plan reads
//! its threshold from this sweep.
//!
//! # Reading the direction honestly — two anchors, one finding
//!
//! `r = P(link) · N` renormalizes by the degraded baseline: it asks "how many
//! times blind guessing," not "how exposed." Both anchors are derived and
//! reported, because they answer different questions:
//!
//! - **Ratio-anchored** (`worst-arm r < 2` at each swept `N`): does the
//!   *mechanism's relative leak* worsen as cover thins? The 2026-07-16
//!   evidence run answers no — worst-arm `r` is flat (≈1.7–1.86) across
//!   `N ∈ [2, 16]`; `P(link)` scales ≈ `1.8/N`. The mechanism property the
//!   gate certified is scale-invariant in-model: there is **no ratio
//!   breakeven in range**. That is the reassuring half.
//! - **Absolute-anchored** (`worst-arm P(link) ≤ RATIO_BOUND / 10 = 0.2`,
//!   the exposure the nominal verdict certified): does the *realized
//!   exposure* stay at what the gate said? Flat `r` forces
//!   `P ≈ 1.86/N`, so the exposure bar is crossed at `N* ≈ 1.86/0.2 ≈ 9.3` —
//!   the evidence run straddles it exactly (worst `P = 0.203` at `N = 9`,
//!   `0.177` at `N = 10`). The certified exposure has **no measurable cover
//!   slack**: any real-world shortfall below nominal cover puts the realized
//!   exposure above what the verdict certified. That is the load-bearing
//!   half, and it is the direct corollary of the gate's ~7% margin — with
//!   flat `r ≈ 1.86`, the exposure breakeven *must* sit at
//!   `N* = 10 · (1.86/2) ≈ 9.3`.
//!
//! The fifth conditional's monitoring threshold is the **absolute** anchor:
//! the ratio anchor cannot see thin-cover harm (it renormalizes it away),
//! and a low-`N` row clearing `r < 2` is not "passing" in any sense the
//! aspiration cares about.
//!
//! # Scope
//!
//! The sweep grades the block-time correlator arms only. The §19 leg-(b)
//! wall-clock arm is not a function of `N` (it grades a sub-block
//! sweep-phase channel per pair) and is out of scope here; its verdict input
//! to the gate is unchanged.

use serde::Serialize;

use crate::gf7_timeline::{grade, ArmResult, SynthParams, RATIO_BOUND};
use crate::standoff::SplitMix64;

/// Positive-control pass floor (same bar as the measurement round §5).
const POSITIVE_CONTROL_MIN: f64 = 0.80;

/// Negative-control tolerance (same bar as the measurement round §5).
const NEGATIVE_CONTROL_TOL: f64 = 0.05;

/// The swept cover levels. `10` is the nominal gate point (the `1.86` row);
/// the sweep brackets it both ways so the direction of `r(N)` is measured,
/// never assumed — the ratio's small-`N` cap means degradation may express as
/// rising absolute linkage rather than rising ratio.
const COVER_LEVELS: [usize; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16];

/// One cover level's graded result at the gate posture.
#[derive(Serialize)]
pub struct BreakevenRow {
    pub n: usize,
    pub baseline: f64,
    /// Per-`n` validity controls (the measurement round's §5 pair, re-run at
    /// this cover level — a controls-failed row counts for nothing).
    pub controls_valid: bool,
    pub blind: ArmResult,
    pub modeled_s3: ArmResult,
    pub lr_stress: ArmResult,
    /// Worst graded arm's ratio (the number the gate verdict quotes).
    pub worst_ratio: f64,
    /// Worst graded arm's absolute linkage probability — reported beside the
    /// ratio because the ratio is capped at `n` and thin cover expresses
    /// harm in the absolute number first.
    pub worst_p_link: f64,
    pub clears_bound: bool,
}

/// The full breakeven report.
#[derive(Serialize)]
pub struct BreakevenReport {
    pub ratio_bound: f64,
    pub trials: u32,
    /// The nominal gate point (`n = 10`) restated from this run, for
    /// continuity with the WI-4 verdict row.
    pub nominal_n: usize,
    /// The absolute linkage bar the nominal verdict certified:
    /// `RATIO_BOUND / nominal_n` (= `P(link) < 0.2` at `N = 10`). The
    /// absolute-anchored threshold below holds effective cover to *this*
    /// exposure, not to the ratio.
    pub absolute_bar: f64,
    pub rows: Vec<BreakevenRow>,
    /// Cover levels (valid rows only) where the worst arm breaches the
    /// ratio bound.
    pub failing_n: Vec<usize>,
    /// Ratio-anchored threshold: the smallest valid cover level at which the
    /// worst arm still clears `r < RATIO_BOUND`; `None` if every valid row
    /// fails. If the ratio surface is flat (the 2026-07-16 evidence run:
    /// worst-arm `r ≈ 1.7–1.86` at every swept `N`), this lands at the
    /// bottom of the sweep and is **not** the number to monitor — the ratio
    /// cannot see thin-cover harm below its `r ≤ N` cap.
    pub ratio_threshold_n: Option<usize>,
    /// Absolute-anchored threshold — the fifth conditional's monitoring
    /// number: the smallest valid cover level whose worst-arm `P(link)`
    /// stays at or under `absolute_bar`, i.e. the cover level below which
    /// the realized exposure exceeds what the nominal verdict certified.
    pub absolute_threshold_n: Option<usize>,
    /// Worst-arm absolute `P(link)` at the absolute threshold, stated
    /// beside it so the threshold is never quoted without its exposure.
    pub absolute_threshold_worst_p_link: Option<f64>,
}

/// Run the two validity controls at cover level `n` (measurement round §5,
/// re-run per swept point: a correlator that cannot link the un-jittered
/// coupling or manufactures linkage from independence at *this* `n` grades
/// nothing at this `n`).
fn controls_valid_at(n: usize, trials: u32, rng: &mut SplitMix64) -> bool {
    let baseline = 1.0 / n as f64;

    let pos = SynthParams {
        window: 0,
        ..SynthParams::posture()
    };
    let (_, pos_s3, _) = grade(&pos, n, trials, rng);

    let neg = SynthParams {
        independent_bond: true,
        ..SynthParams::posture()
    };
    let (_, neg_s3, _) = grade(&neg, n, trials, rng);

    pos_s3 >= POSITIVE_CONTROL_MIN && (neg_s3 - baseline).abs() < NEGATIVE_CONTROL_TOL
}

fn run_breakeven(trials: u32, seed: u64) -> BreakevenReport {
    let mut rng = SplitMix64(seed);
    let posture = SynthParams::posture();

    let rows: Vec<BreakevenRow> = COVER_LEVELS
        .iter()
        .map(|&n| {
            let controls_valid = controls_valid_at(n, trials, &mut rng);
            let (blind, s3, lr) = grade(&posture, n, trials, &mut rng);
            let (blind, s3, lr) = (
                ArmResult::new(blind, n),
                ArmResult::new(s3, n),
                ArmResult::new(lr, n),
            );
            let worst = [&blind, &s3, &lr]
                .into_iter()
                .max_by(|a, b| a.ratio.total_cmp(&b.ratio))
                .expect("three arms");
            let (worst_ratio, worst_p_link) = (worst.ratio, worst.p_link);
            BreakevenRow {
                n,
                baseline: 1.0 / n as f64,
                controls_valid,
                blind,
                modeled_s3: s3,
                lr_stress: lr,
                worst_ratio,
                worst_p_link,
                clears_bound: worst_ratio < RATIO_BOUND,
            }
        })
        .collect();

    let failing_n: Vec<usize> = rows
        .iter()
        .filter(|r| r.controls_valid && !r.clears_bound)
        .map(|r| r.n)
        .collect();

    let ratio_threshold = rows
        .iter()
        .filter(|r| r.controls_valid && r.clears_bound)
        .min_by_key(|r| r.n);

    let nominal_n = 10usize;
    let absolute_bar = RATIO_BOUND / nominal_n as f64;
    let absolute_threshold = rows
        .iter()
        .filter(|r| r.controls_valid && r.worst_p_link <= absolute_bar)
        .min_by_key(|r| r.n);

    BreakevenReport {
        ratio_bound: RATIO_BOUND,
        trials,
        nominal_n,
        absolute_bar,
        ratio_threshold_n: ratio_threshold.map(|r| r.n),
        absolute_threshold_n: absolute_threshold.map(|r| r.n),
        absolute_threshold_worst_p_link: absolute_threshold.map(|r| r.worst_p_link),
        rows,
        failing_n,
    }
}

/// Binary entry: the full breakeven sweep (evidence config — same trial count
/// as the measurement round's evidence run).
pub fn run_full_report() -> BreakevenReport {
    run_breakeven(1_000, 0x6F7_B3EA_4E00_0001)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sweep's structural invariants on a small config: every row grades
    /// all three arms at its own `n`, the nominal point is present, and the
    /// threshold (when it exists) is a valid clearing row's `n`.
    #[test]
    fn breakeven_report_is_well_formed() {
        let report = run_breakeven(60, 0x51DE_BE01);
        assert_eq!(report.rows.len(), COVER_LEVELS.len());
        assert!(report.rows.iter().any(|r| r.n == report.nominal_n));
        for row in &report.rows {
            assert!((row.baseline - 1.0 / row.n as f64).abs() < 1e-12);
            // r = P·N is capped at N by construction.
            assert!(row.worst_ratio <= row.n as f64 + 1e-9);
            assert!(row.worst_ratio >= row.worst_p_link - 1e-9);
        }
        assert!((report.absolute_bar - RATIO_BOUND / report.nominal_n as f64).abs() < 1e-12);
        if let Some(t) = report.ratio_threshold_n {
            let row = report
                .rows
                .iter()
                .find(|r| r.n == t)
                .expect("threshold row");
            assert!(row.controls_valid && row.clears_bound);
            assert!(!report.failing_n.contains(&t));
        }
        if let Some(t) = report.absolute_threshold_n {
            let row = report
                .rows
                .iter()
                .find(|r| r.n == t)
                .expect("threshold row");
            assert!(row.controls_valid && row.worst_p_link <= report.absolute_bar);
        }
    }
}

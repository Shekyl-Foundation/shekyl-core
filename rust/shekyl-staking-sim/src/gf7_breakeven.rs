//! GF-7 effective-cover sensitivity sweep — the fifth WI-4 §13.5 conditional's
//! measured shape (`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §13.5;
//! `ARCHIVAL_FIREWALL_GATE6.md` §12.8).
//!
//! # What this is — and what it is not
//!
//! The WI-4 gate verdict (`r = 1.86 < 2` at `N = 10`) was computed at
//! **nominal** cover: `RunConfig { n: 10 }` seeds the full honest-traffic
//! strength, and Gate-6 §11 qualifier (iv) names the measured set an upper
//! bound. The *effective* post-isolation cover is an economics quantity
//! (Gate-6 §11.8 method note 3) — unmeasurable pre-genesis.
//!
//! This sweep derives the one thing about that conditional that **is**
//! derivable today: how the model's own `r` and `P(link)` move as the cover
//! level varies. It is a sensitivity sweep over the existing harness at the
//! gate-relevant posture (`SynthParams::posture()`), a property of the
//! **model**, not of the world: mechanism-class under method note 3, no
//! testnet, no economics input. It is **not a gate**: the gate (`r < 2` at
//! target cover) passed and is not re-litigated here.
//!
//! # The finding: `r < 2` is structurally blind to cover
//!
//! `r = P(link) · N` renormalizes by the degraded baseline: it asks "how many
//! times blind guessing," not "how exposed." The 2026-07-16 evidence run
//! shows worst-arm `r` staying within ≈1.46–1.83 across `N ∈ [2, 16]`,
//! clearing the bound at every row and never trending toward the bar as
//! cover thins, with `P(link)` scaling ≈ `1.8/N` — the LR scorer's hit
//! probability and the `1/N` blind baseline shrink together, so the ratio
//! renormalizes thin-cover harm away **by construction** (`r ≤ N` caps it,
//! compressing the smallest rows as the hit probability saturates; at
//! `N = 2` the worst arm links 72.9% of the time and still "clears"). Two
//! consequences:
//!
//! - **Cover was never gated.** Not "gated on an optimistic assumption" —
//!   never gated at all. The gate's ~7% margin (`1.86` vs `2`) is margin on
//!   the mechanism's *fixed relative leak*, which cover shortfall cannot
//!   consume. This corrects the pre-sweep framing ("the true `r` is ≥ 1.86,
//!   unknown"): `r` does not degrade as cover thins; it structurally cannot.
//!   It is also why the §12.8 misfiling was possible — no gate-side number
//!   ever watched cover.
//! - **There is no discovered breakeven.** The exposure figure
//!   `RATIO_BOUND / N_nominal = 0.2` is the ratio bar *evaluated at nominal
//!   cover* — back-derived arithmetic, never an a-priori commitment (`r < 2`
//!   was committed on its merits; `P(link) < 0.2` fell out of the division).
//!   Under flat `r`, worst-arm `P(link)` meets it at
//!   `N = N_nominal · (r / bound) ≈ 9.3` **by identity**: "keep cover at the
//!   level we assumed, because below it you are below what we assumed."
//!   The report states that identity for the record; it does **not** pin
//!   `0.2` as a bound, and no monitoring threshold is minted from it —
//!   committing an absolute bar backwards from the number it would need to
//!   certify is the move this track has refused four times.
//!
//! # Where the aspiration's number actually lives
//!
//! Per-event `P(link)` is not the aspiration's quantity in any case: the
//! `P`↔principal binding is observed repeatedly, and intersection collapses
//! geometrically (F-D4 §13.3 / F-W5), so no finite per-event anchor bounds
//! lifetime exposure. The aspiration's quantity is whole-life fused
//! exposure, and its instrument is the S-2 ledger (Gate-6 R5, unbuilt) —
//! not any per-event number this sweep can produce.
//!
//! # Scope
//!
//! The sweep grades the block-time correlator arms only. The §19 leg-(b)
//! wall-clock arm is not a function of `N` (it grades a sub-block
//! sweep-phase channel per pair) and is out of scope here; its verdict input
//! to the gate is unchanged.

use serde::Serialize;

use crate::gf7_timeline::{grade, ArmResult, SynthParams, NOMINAL_COVER_N, RATIO_BOUND};
use crate::standoff::SplitMix64;

/// Positive-control pass floor (same bar as the measurement round §5).
const POSITIVE_CONTROL_MIN: f64 = 0.80;

/// Negative-control tolerance (same bar as the measurement round §5).
const NEGATIVE_CONTROL_TOL: f64 = 0.05;

/// The swept cover levels. `NOMINAL_COVER_N` (10) is the nominal gate point
/// (the `1.86` row) and must appear in the sweep — `run_breakeven` asserts it,
/// since the parity identity and the WI-4 continuity claim both anchor there.
/// The sweep brackets it both ways so the direction of `r(N)` is measured,
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
    /// The nominal gate point (`NOMINAL_COVER_N`, shared with the measurement
    /// round's `RunConfig`) restated from this run, for continuity with the
    /// WI-4 verdict row.
    pub nominal_n: usize,
    /// The ratio bar evaluated at nominal cover: `RATIO_BOUND / nominal_n`
    /// (= `0.2` at `N = 10`). **Back-derived arithmetic, not a committed
    /// bound** — `r < 2` was committed a-priori on its merits; this number
    /// fell out of the division and is reported only so the parity identity
    /// below is legible. Never quote it as an a-priori exposure bar.
    pub nominal_exposure_identity: f64,
    pub rows: Vec<BreakevenRow>,
    /// Cover levels (valid rows only) where the worst arm breaches the
    /// ratio bound.
    pub failing_n: Vec<usize>,
    /// Ratio-anchored breakeven: the smallest valid cover level at which the
    /// worst arm still clears `r < RATIO_BOUND`; `None` if every valid row
    /// fails. The 2026-07-16 evidence run lands this at the bottom of the
    /// sweep (worst-arm `r` clears at every swept `N`, never trending toward
    /// the bar): the relative leak is scale-invariant in-model, so **no
    /// ratio breakeven exists in range** and the ratio cannot see thin-cover
    /// harm below its `r ≤ N` cap. That scale invariance is the sweep's
    /// finding.
    pub ratio_threshold_n: Option<usize>,
    /// Nominal-exposure parity point; `None` if every valid row realizes
    /// more than the nominal-cover exposure. One field, not two parallel
    /// `Option`s, so "`n` present without its exposure" is unrepresentable.
    pub nominal_parity: Option<ParityPoint>,
}

/// The smallest valid cover level whose worst-arm `P(link)` stays at or
/// under `nominal_exposure_identity`, with that realized exposure beside it
/// so the identity is never quoted without it. Under flat `r` this sits at
/// `nominal_n · (r / RATIO_BOUND)` **by identity** — it restates the
/// nominal-cover assumption ("below it you are below what we assumed") and
/// carries no independent content. It is **not** a monitoring threshold;
/// the aspiration's quantity is lifetime exposure (F-D4 §13.3 / F-W5),
/// instrumented by the S-2 ledger.
#[derive(Serialize)]
pub struct ParityPoint {
    pub n: usize,
    pub worst_p_link: f64,
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

/// SplitMix64's own seeding increment (the golden-ratio constant). Deriving
/// each row's seed as `base + n · γ` is a seeder jump to an independent
/// stream — rows are decoupled, so editing `COVER_LEVELS` never perturbs the
/// other rows' numbers (which the docs quote).
const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

fn run_breakeven(trials: u32, seed: u64) -> BreakevenReport {
    assert!(
        COVER_LEVELS.contains(&NOMINAL_COVER_N),
        "COVER_LEVELS must include the nominal gate point (NOMINAL_COVER_N = \
         {NOMINAL_COVER_N}) — the parity identity and the WI-4 continuity claim anchor there",
    );
    let posture = SynthParams::posture();

    let rows: Vec<BreakevenRow> = COVER_LEVELS
        .iter()
        .map(|&n| {
            let mut rng = SplitMix64(seed.wrapping_add((n as u64).wrapping_mul(SPLITMIX_GAMMA)));
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

    let nominal_exposure_identity = RATIO_BOUND / NOMINAL_COVER_N as f64;
    let nominal_parity = rows
        .iter()
        .filter(|r| r.controls_valid && r.worst_p_link <= nominal_exposure_identity)
        .min_by_key(|r| r.n);

    BreakevenReport {
        ratio_bound: RATIO_BOUND,
        trials,
        nominal_n: NOMINAL_COVER_N,
        nominal_exposure_identity,
        ratio_threshold_n: ratio_threshold.map(|r| r.n),
        nominal_parity: nominal_parity.map(|r| ParityPoint {
            n: r.n,
            worst_p_link: r.worst_p_link,
        }),
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
        assert!(
            (report.nominal_exposure_identity - RATIO_BOUND / report.nominal_n as f64).abs()
                < 1e-12
        );
        if let Some(t) = report.ratio_threshold_n {
            let row = report
                .rows
                .iter()
                .find(|r| r.n == t)
                .expect("threshold row");
            assert!(row.controls_valid && row.clears_bound);
            assert!(!report.failing_n.contains(&t));
        }
        if let Some(p) = &report.nominal_parity {
            let row = report.rows.iter().find(|r| r.n == p.n).expect("parity row");
            assert!(row.controls_valid && row.worst_p_link <= report.nominal_exposure_identity);
            assert!((row.worst_p_link - p.worst_p_link).abs() < 1e-12);
        }
    }
}

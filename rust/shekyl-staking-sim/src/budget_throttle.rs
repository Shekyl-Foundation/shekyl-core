// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
//! F-B1c-c2 disposition-(b) coverage cross-check (Part 2 of the reopen
//! evidence; Part 1 is `shekyl-economics-sim --fb1c-c2`).
//!
//! **The reopen question** (`REWARD_EMISSION_E3_GATING_ROUND.md` §9.9,
//! `docs/FOLLOWUPS.md` V3.0 pre-genesis queue). Disposition (a) makes the
//! archival budget's emission leg *release-modulated*, so `budget(E)` throttles
//! with tx volume; disposition (b) would insulate it. Part 1 measured the
//! **budget swing**: the (a)-vs-(b) delta is the release multiplier applied to
//! the emission share of the block reward, clamped to
//! `[release_min, release_max]` — so the worst-case throttle is the floored
//! `release_min` on the *emission leg only*. Part 2 asks the second half: does
//! that throttle **cross a coverage knee** in the
//! `budget → APR → marginal entry → archiver count → deep coverage` transfer
//! curve (L11 Finding 3 / L13 fee-era knee)?
//!
//! **The emis_frac weighting is the crux.** The release multiplier modulates
//! only the *emission* leg; the *fee* leg (`staker_pool_amount`) is
//! disposition-neutral. So at an operating point where the emission leg is a
//! fraction `emis_frac` of the total budget, the *effective* budget multiplier
//! (a)-vs-(b) is
//!
//! ```text
//! m_eff = 1 − emis_frac · (1 − release_min)          // release_min = 0.8
//! ```
//!
//! A naive "run the sweep at 0.8× vs 1.0×" would be **wrong** — it would apply
//! the throttle to the whole purse, including the fee leg the throttle cannot
//! touch. Part 1 supplies the per-regime `emis_frac`:
//!
//! - **mining-era low-volume window:** the emission leg is ~100 % of budget
//!   (`emis_frac ≈ 1.0`) — but the absolute purse is the early bootstrap
//!   subsidy, orders of magnitude above the co-location-saturated ceiling
//!   (L11: `b200 ≡ b400`), so 0.8× of a saturated purse stays saturated.
//! - **fee-era late tail:** the emission leg has decayed to ~1 % of budget
//!   (`emis_frac ≈ 0.012`), so even the worst 0.8× throttle moves the
//!   (knee-adjacent) purse by ~0.24 % — nowhere near the ~20 % drop the L13
//!   knee needs (`budget 100 → 80`).
//!
//! **The safety is regime separation, not a harmless throttle.** The
//! `mining_lean_stress` row is the deliberate counterfactual: a *full* 0.8×
//! throttle applied at the lean operating point (budget 100) — a combination
//! that does **not** occur (mining is saturated, not lean) — *does* cross the
//! knee. That row is reported for honesty but excluded from the verdict: it
//! shows the throttle is safe only because the deep-throttle regime and the
//! knee-adjacent regime never coincide.
//!
//! This module computes the evidence on the L11 lean cold-fill transfer
//! (`l11_bud_*` template, ρ=0.02) at each regime's (a) and (b) *effective*
//! budgets, seed-averaged, plus a context sweep that locates the knee. The
//! report rendering lives in `main.rs` (`print_budget_throttle_report`), per
//! the compute-in-module / print-in-binary split the other sim modes follow.

use serde::Serialize;
use shekyl_economics::params::{EconomicParams, SCALE};

use crate::scenarios::{build_scenarios, run_sim, SimConfig};

/// Worst-case release-multiplier throttle floor, sourced from the same
/// build-generated view of `config/economics_params.json` the consensus model
/// uses (`EconomicParams::default().release_min`, fixed-point over [`SCALE`]) —
/// not a local re-assertion, so a config change cannot silently drift this
/// report's math. Pinned 800_000 ⇒ 0.8×: the deepest a sustained low-volume
/// window can throttle the emission leg.
#[allow(clippy::cast_precision_loss)]
pub fn release_min_floor() -> f64 {
    EconomicParams::default().release_min as f64 / SCALE as f64
}

/// Coverage feasibility bar: `covered = deep_frac_under_target < 0.05`
/// (the sim's stated sub-claim threshold, `main.rs` summary header).
pub const COVERED_BAR: f64 = 0.05;

/// Material-degradation bar: (a) is materially worse than (b) at the same
/// operating point if its mean cDeepU exceeds (b)'s by more than this. One
/// coverage-bar's worth of extra deep under-target is the "material" threshold.
pub const MATERIAL_DELTA: f64 = 0.05;

/// Seed sweep. Near the coverage knee the participation servo sits at a discrete
/// breakeven — a marginal budget change can flip whether the marginal archiver
/// seats, producing a chaotic single-seed jump in bondA/coverage. Reading the
/// mean over a seed sweep (the doc's own `hu_cushion` pattern) smooths the
/// lattice noise so a small (a)-vs-(b) budget delta is not swamped by it.
pub const SEEDS: [u64; 8] = [
    0x5EED_1234,
    0x5EED_2222,
    0x5EED_9999,
    0x5EED_0001,
    0x5EED_ABCD,
    0x5EED_BEEF,
    0x5EED_5555,
    0x5EED_7A7A,
];

/// Operating points: (regime, base budget in sim units, emission leg's share of
/// budget from Part 1, real-operating-point?). `emis_frac` ≈ 1.0 in the
/// mining-era low-volume window (emission leg ~all of budget), ≈ 0.012 in the
/// fee-era late tail (emission share decayed). The mining-era absolute purse is
/// far above the co-location ceiling, so it reads at the saturated `base = 200`;
/// the lean-stress row is the deliberately conservative counterfactual — the
/// mining purse pretended as thin as the fee-era lean attractor, so the *full*
/// throttle lands at the leanest possible operating point. `real = false`
/// excludes it from the verdict (the regime does not occur).
pub const POINTS_SPEC: [(&str, f64, f64, bool); 3] = [
    ("fee_era_lean", 100.0, 0.012, true),
    ("mining_saturated", 200.0, 1.0, true),
    ("mining_lean_stress", 100.0, 1.0, false),
];

/// Context transfer-curve budgets: spans the L11/L13 window (broken 50 →
/// funded 100 → saturated 200) including the L13 knee bracket (80, 86).
pub const TRANSFER_BUDGETS: [f64; 6] = [50.0, 80.0, 86.0, 100.0, 160.0, 200.0];

/// Seed-averaged coverage read at one budget.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetRead {
    pub budget: f64,
    /// Mean bonded-archiver count (bondA) over the seed sweep.
    pub bonda_mean: f64,
    /// Mean windowed committed deep under-target (cDeepU) — the coverage read.
    pub cdeepu_mean: f64,
    /// Worst-seed cDeepU (the pessimistic read).
    pub cdeepu_max: f64,
    /// Mean oldest-band oscillation (oUmx).
    pub oumx_mean: f64,
}

/// One (a)-vs-(b) operating point: effective budgets, seed-averaged coverage on
/// each side, and the material-degradation verdict.
#[derive(Debug, Clone, Serialize)]
pub struct ThrottlePoint {
    pub regime: String,
    /// Emission leg's share of budget at this regime (from Part 1).
    pub emis_frac: f64,
    /// The regime's operating budget in sim units before the throttle.
    pub base_budget: f64,
    /// `1 − emis_frac·(1−release_min)` — the effective (a)-vs-(b) multiplier.
    pub m_eff: f64,
    /// Seed-averaged coverage under (a) (throttled) and (b) (unthrottled).
    pub read_a: BudgetRead,
    pub read_b: BudgetRead,
    /// `cdeepu_a_mean − cdeepu_b_mean` — how much worse (a)'s coverage is.
    pub coverage_delta: f64,
    /// A genuine operating point the chain actually occupies. `false` for the
    /// `mining_lean_stress` counterfactual, which is excluded from the verdict.
    pub real_operating_point: bool,
    /// (a) materially worse than (b) at a real operating point.
    pub material_starvation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BudgetThrottleReport {
    pub points: Vec<ThrottlePoint>,
    pub transfer_curve: Vec<BudgetRead>,
    /// The load-bearing verdict: does the throttle materially starve coverage at
    /// any *real* operating point? `false` ⇒ swing tolerable ⇒ disposition (a)
    /// stands.
    pub any_material_starvation: bool,
}

/// The L11 lean cold-fill transfer template (endogenous participation, ρ=0.02,
/// cold start): the exact config behind L11 Finding 3's budget→coverage table,
/// reused drift-free rather than replicated.
pub fn transfer_template() -> SimConfig {
    build_scenarios()
        .into_iter()
        .find(|c| c.axis == "participation_transfer" && c.name == "l11_bud_b100")
        .expect("l11_bud_b100 template present in build_scenarios()")
}

/// Seed-averaged read of the transfer curve at one budget.
#[allow(clippy::cast_precision_loss)]
pub fn read_budget(template: &SimConfig, label: &str, budget: f64) -> BudgetRead {
    let mut bonda = 0.0;
    let mut cdeepu_sum = 0.0;
    let mut cdeepu_max = 0.0_f64;
    let mut oumx = 0.0;
    for (i, seed) in SEEDS.iter().enumerate() {
        let mut c = template.clone();
        c.name = format!("{label}_s{i}");
        c.budget = budget;
        c.seed = *seed;
        let r = run_sim(&c);
        bonda += r.bonded_active;
        cdeepu_sum += r.committed_deep_under;
        cdeepu_max = cdeepu_max.max(r.committed_deep_under);
        oumx += r.oldest_under_max;
    }
    let n = SEEDS.len() as f64;
    BudgetRead {
        budget,
        bonda_mean: bonda / n,
        cdeepu_mean: cdeepu_sum / n,
        cdeepu_max,
        oumx_mean: oumx / n,
    }
}

/// Evaluate one `POINTS_SPEC` operating point: run (a) at the
/// emis_frac-weighted effective budget and (b) at the unthrottled base, both
/// seed-averaged, and grade the delta.
pub fn evaluate_point(
    template: &SimConfig,
    regime: &str,
    base: f64,
    emis_frac: f64,
    real: bool,
) -> ThrottlePoint {
    let m_eff = 1.0 - emis_frac * (1.0 - release_min_floor());
    let read_a = read_budget(template, &format!("bt_{regime}_a"), base * m_eff);
    let read_b = read_budget(template, &format!("bt_{regime}_b"), base);
    let coverage_delta = read_a.cdeepu_mean - read_b.cdeepu_mean;
    let material_starvation = real && coverage_delta > MATERIAL_DELTA;
    ThrottlePoint {
        regime: regime.to_string(),
        emis_frac,
        base_budget: base,
        m_eff,
        read_a,
        read_b,
        coverage_delta,
        real_operating_point: real,
        material_starvation,
    }
}

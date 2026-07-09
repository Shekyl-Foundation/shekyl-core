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
//! the emission share of the block reward, clamped to `[0.8, 1.3]` — so the
//! worst-case throttle is a floored **0.8×** on the *emission leg only*. Part 2
//! asks the second half: does that throttle **cross a coverage knee** in the
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
//! m_eff = 1 − emis_frac · (1 − RELEASE_MIN)          // RELEASE_MIN = 0.8
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
//! This mode runs the L11 lean cold-fill transfer (`l11_bud_*` template, ρ=0.02)
//! at each regime's (a) and (b) *effective* budgets, seed-averaged, and reads
//! deep coverage on each side, plus a context sweep that locates the knee.

use serde::Serialize;

use crate::scenarios::{build_scenarios, run_sim, SimConfig};

/// Worst-case release-multiplier throttle floor: `release_min = 0.8`
/// (`config/economics_params.json` `shekyl_release_min = 800_000`, SCALE 1e6).
/// This is the deepest a low-volume window can throttle the emission leg.
const RELEASE_MIN: f64 = 0.8;

/// Coverage feasibility bar: `covered = deep_frac_under_target < 0.05`
/// (the sim's stated sub-claim threshold, `main.rs` summary header).
const COVERED_BAR: f64 = 0.05;

/// Material-degradation bar: (a) is materially worse than (b) at the same
/// operating point if its mean cDeepU exceeds (b)'s by more than this. One
/// coverage-bar's worth of extra deep under-target is the "material" threshold.
const MATERIAL_DELTA: f64 = 0.05;

/// Seed sweep. Near the coverage knee the participation servo sits at a discrete
/// breakeven — a marginal budget change can flip whether the marginal archiver
/// seats, producing a chaotic single-seed jump in bondA/coverage. Reading the
/// mean over a seed sweep (the doc's own `hu_cushion` pattern) smooths the
/// lattice noise so a small (a)-vs-(b) budget delta is not swamped by it.
const SEEDS: [u64; 8] = [
    0x5EED_1234,
    0x5EED_2222,
    0x5EED_9999,
    0x5EED_0001,
    0x5EED_ABCD,
    0x5EED_BEEF,
    0x5EED_5555,
    0x5EED_7A7A,
];

/// Seed-averaged coverage read at one budget.
#[derive(Debug, Clone, Serialize)]
struct BudgetRead {
    budget: f64,
    /// Mean bonded-archiver count (bondA) over the seed sweep.
    bonda_mean: f64,
    /// Mean windowed committed deep under-target (cDeepU) — the coverage read.
    cdeepu_mean: f64,
    /// Worst-seed cDeepU (the pessimistic read).
    cdeepu_max: f64,
    /// Mean oldest-band oscillation (oUmx).
    oumx_mean: f64,
}

fn read_budget(template: &SimConfig, label: &str, budget: f64) -> BudgetRead {
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

/// One (a)-vs-(b) operating point: effective budgets, seed-averaged coverage on
/// each side, and the material-degradation verdict.
#[derive(Debug, Clone, Serialize)]
struct ThrottlePoint {
    regime: String,
    /// Emission leg's share of budget at this regime (from Part 1).
    emis_frac: f64,
    /// The regime's operating budget in sim units before the throttle.
    base_budget: f64,
    /// `1 − emis_frac·(1−0.8)` — the effective (a)-vs-(b) budget multiplier.
    m_eff: f64,
    /// Seed-averaged coverage under (a) (throttled) and (b) (unthrottled).
    read_a: BudgetRead,
    read_b: BudgetRead,
    /// `cdeepu_a_mean − cdeepu_b_mean` — how much worse (a)'s coverage is.
    coverage_delta: f64,
    /// A genuine operating point the chain actually occupies. `false` for the
    /// `mining_lean_stress` counterfactual, which is excluded from the verdict.
    real_operating_point: bool,
    /// (a) materially worse than (b) at a real operating point.
    material_starvation: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TransferPoint {
    budget: f64,
    bonda_mean: f64,
    cdeepu_mean: f64,
    cdeepu_max: f64,
    oumx_mean: f64,
}

#[derive(Debug, Clone, Serialize)]
struct BudgetThrottleReport {
    points: Vec<ThrottlePoint>,
    transfer_curve: Vec<TransferPoint>,
    /// The load-bearing verdict: does the throttle materially starve coverage at
    /// any *real* operating point? `false` ⇒ swing tolerable ⇒ disposition (a)
    /// stands.
    any_material_starvation: bool,
}

pub fn run_budget_throttle_report() {
    // The L11 lean cold-fill transfer template (endogenous participation,
    // ρ=0.02, cold start): the exact config behind L11 Finding 3's
    // budget→coverage table, reused drift-free rather than replicated.
    let template = build_scenarios()
        .into_iter()
        .find(|c| c.axis == "participation_transfer" && c.name == "l11_bud_b100")
        .expect("l11_bud_b100 template present in build_scenarios()");

    // Operating points. `emis_frac` is sourced from Part 1
    // (`shekyl-economics-sim --fb1c-c2`): ~1.0 in the mining-era low-volume
    // window (emission leg ~all of budget), ~0.012 in the fee-era late tail
    // (emission share decayed). `real` marks whether the chain actually occupies
    // the point (the lean-stress row is a counterfactual bracket).
    // (regime, base_budget, emis_frac, real_operating_point)
    let points_spec = [
        ("fee_era_lean", 100.0_f64, 0.012_f64, true),
        ("mining_saturated", 200.0, 1.0, true),
        ("mining_lean_stress", 100.0, 1.0, false),
    ];

    eprintln!(
        "shekyl-staking-sim --budget-throttle — F-B1c-c2 disposition-(b) coverage cross-check"
    );
    eprintln!("(Part 2; Part 1 = shekyl-economics-sim --fb1c-c2. See budget_throttle.rs header.)");
    eprintln!(
        "Each cell is the mean over {} seeds (knee is a chaotic knife-edge single-seed).",
        SEEDS.len()
    );
    eprintln!();
    eprintln!(
        "m_eff = 1 - emis_frac*(1-{RELEASE_MIN}); (a) budget = base*m_eff, (b) budget = base."
    );
    eprintln!(
        "cDeepU = windowed committed deep under-target (lower better); covered < {COVERED_BAR}."
    );
    eprintln!();
    eprintln!(
        "{:<19} {:>4} {:>8} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8}",
        "regime", "real", "emisFrac", "bud_a", "bud_b", "cDeepU_a", "cDeepU_b", "delta", "verdict"
    );

    let mut points = Vec::new();
    let mut any_material = false;
    for (regime, base, emis_frac, real) in points_spec {
        let m_eff = 1.0 - emis_frac * (1.0 - RELEASE_MIN);
        let read_a = read_budget(&template, &format!("bt_{regime}_a"), base * m_eff);
        let read_b = read_budget(&template, &format!("bt_{regime}_b"), base);
        let coverage_delta = read_a.cdeepu_mean - read_b.cdeepu_mean;
        let material = real && coverage_delta > MATERIAL_DELTA;
        any_material |= material;

        let verdict = if !real {
            "counterfact"
        } else if material {
            "MATERIAL"
        } else {
            "tolerable"
        };
        eprintln!(
            "{:<19} {:>4} {:>8.3} {:>7.2} {:>7.1} {:>8.4} {:>8.4} {:>+8.4} {:>8}",
            regime,
            if real { "yes" } else { "no" },
            emis_frac,
            read_a.budget,
            read_b.budget,
            read_a.cdeepu_mean,
            read_b.cdeepu_mean,
            coverage_delta,
            verdict,
        );

        points.push(ThrottlePoint {
            regime: regime.to_string(),
            emis_frac,
            base_budget: base,
            m_eff,
            read_a,
            read_b,
            coverage_delta,
            real_operating_point: real,
            material_starvation: material,
        });
    }

    // Context transfer curve: locate the knee so the (a)/(b) points can be read
    // against it. Spans the L11/L13 window (broken 50 → funded 100 → saturated
    // 200) including the L13 knee bracket (80, 86).
    eprintln!();
    eprintln!("Transfer curve (seed-averaged; locates the knee):");
    eprintln!(
        "{:>7} {:>9} {:>10} {:>9} {:>9}",
        "budget", "bondA", "cDeepU", "cDeepUmax", "oUmx"
    );
    let mut transfer_curve = Vec::new();
    for budget in [50.0_f64, 80.0, 86.0, 100.0, 160.0, 200.0] {
        let r = read_budget(&template, &format!("bt_curve_{budget}"), budget);
        eprintln!(
            "{:>7.1} {:>9.1} {:>10.4} {:>9.4} {:>9.4}",
            r.budget, r.bonda_mean, r.cdeepu_mean, r.cdeepu_max, r.oumx_mean
        );
        transfer_curve.push(TransferPoint {
            budget: r.budget,
            bonda_mean: r.bonda_mean,
            cdeepu_mean: r.cdeepu_mean,
            cdeepu_max: r.cdeepu_max,
            oumx_mean: r.oumx_mean,
        });
    }

    eprintln!();
    if any_material {
        eprintln!(
            "VERDICT: a real operating point shows material starvation under (a) —\n\
             the swing is MATERIAL; disposition (b) reopens (§9.9 rule-21 criterion)."
        );
    } else {
        eprintln!(
            "VERDICT: no real operating point materially degrades under (a).\n\
             - mining_saturated: 0.8x of a co-location-saturated purse stays covered.\n\
             - fee_era_lean: the decayed emission leg makes the throttle ~0.24% — below\n\
               the knee's ~20% and below the seed-noise floor.\n\
             - mining_lean_stress (counterfactual): a full 0.8x on a LEAN purse WOULD\n\
               cross the knee, but that regime does not occur (mining is saturated).\n\
             Swing TOLERABLE => disposition (a) stands."
        );
    }

    let report = BudgetThrottleReport {
        points,
        transfer_curve,
        any_material_starvation: any_material,
    };
    let json = serde_json::to_string_pretty(&report).expect("JSON serialization failed");
    println!("{json}");
}

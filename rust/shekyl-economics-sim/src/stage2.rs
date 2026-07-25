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

use shekyl_economics::{
    base_block_reward,
    burn::{calc_burn_pct, compute_burn_split},
    calc_effective_emission_share, calc_release_multiplier,
    params::{mul_scale, EconomicParams, SCALE},
    release::apply_release_multiplier,
    split_block_emission,
};

use crate::burden::{
    bond_opp_cost_skl, burden_cost_fiat_per_year, frozen_shards, KryderRate,
    BASE_STORAGE_FIAT_PER_BYTE_YEAR, OPP_COST_RATE_BAND, OUTPUTS_PER_TX_NORMAL, REPLICAS_PER_SHARD,
    SKL_FIAT_PRICE_BAND,
};
use crate::calibration::{
    leaf_stuffer_cost_per_shard_atomic, rucknium_shards_equivalent, stuffer_tx_fee_atomic,
    tree_depth_for_leaves, RUCKNIUM_DURATION_DAYS, RUCKNIUM_SPAM_BYTES_GB, RUCKNIUM_SPAM_FEES_XMR,
};
use crate::engine::{ScenarioConfig, SimParams};
use crate::escalation::{family, flat_25, EscalationCurve};
use crate::scenarios::all_scenarios;
use shekyl_archival_retention::SEGMENT_LEAF_COUNT;

/// Atomic units per SKL (mirrors `engine.rs`).
const COIN: f64 = 1_000_000_000.0;

/// Ramp years excluded from the A1 clearance verdict: the first two years, where
/// the corpus is tiny and any share trivially "clears". Clearance is judged on
/// the sustained trajectory.
const A1_RAMP_YEARS: u64 = 2;

/// `frozen_segment_count` sample points for the escalation-candidate preview,
/// spanning the [`crate::escalation::KNEE_BAND`].
const ESCALATION_PREVIEW_N: [u64; 5] = [0, 5_000, 25_000, 100_000, 250_000];

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

/// One year's funding + burden inputs for A1, computed once per scenario on the
/// **flat-ledger** trajectory (shipped 25% split), independent of the escalation
/// candidate. The candidate is applied downstream only to the fee leg
/// (`mul_scale(whole_burn_atomic, share_milli(n))`); the second-order ledger feedback from
/// redistributing the burn (`actually_destroyed` shifts `circulating`, nudging
/// future `burn_pct`/emission) is deliberately not modeled here — it is small
/// against the first-order clearance question, and a full-feedback refinement
/// can follow if a verdict sits on the margin.
#[derive(Debug, Clone, Serialize)]
pub struct A1YearAgg {
    pub year: u64,
    /// `frozen_segment_count` at year end (the D2 operand `n`).
    pub n: u64,
    /// Staker emission leg accrued over the year, **atomic units** (integer —
    /// the DQ-2G algorithm zone; SKL/f64 conversion is deferred to the reported
    /// clearance ratio). Sum of the production `split_block_emission` staker leg.
    pub emission_leg_atomic: u64,
    /// Whole fee burn over the year (pre-share), **atomic units**. The fee leg
    /// is `mul_scale(this, share_milli(n))` — the same integer op production runs
    /// (`compute_burn_split`), never an f64 `× share_fraction`.
    pub whole_burn_atomic: u64,
}

/// Accumulate the per-year A1 inputs over a scenario's blocks (one flat-ledger
/// pass). Mirrors `budget.rs`'s per-block economics.
#[must_use]
pub fn a1_year_aggs(params: &SimParams, config: &ScenarioConfig) -> Vec<A1YearAgg> {
    let economic = EconomicParams {
        release_min: params.release_min,
        release_max: params.release_max,
        tx_volume_baseline: params.tx_volume_baseline,
        burn_base_rate: params.burn_base_rate,
        burn_cap: params.burn_cap,
        staker_pool_share: params.staker_pool_share,
        money_supply: params.money_supply,
        emission_speed_factor_per_minute: params.emission_speed_factor_per_minute,
        final_subsidy_per_minute: params.final_subsidy_per_minute,
        daa_target_seconds: EconomicParams::default().daa_target_seconds,
    };
    let total_blocks = params.blocks_per_year * config.sim_years;
    let money_supply = u128::from(params.money_supply);
    let mut already_generated: u128 =
        (config.initial_emitted_fraction * params.money_supply as f64) as u128;
    let mut total_burned: u128 = 0;
    let mut cumulative_outputs: f64 = 0.0;
    // Integer atomic accumulators (DQ-2G: the budget quantities never touch f64).
    let mut year_emission_atomic: u128 = 0;
    let mut year_burn_atomic: u128 = 0;
    let mut aggs = Vec::with_capacity(config.sim_years as usize);

    for block in 0..total_blocks {
        let abs_height = block + config.genesis_height_offset;
        let base_reward = base_block_reward(
            already_generated.min(u128::from(u64::MAX)) as u64,
            &economic,
        )
        .unwrap_or(0);
        let tx_volume = (config.volume.get_volume)(block, params.blocks_per_year);
        cumulative_outputs += tx_volume as f64 * OUTPUTS_PER_TX_NORMAL;

        let mult = calc_release_multiplier(
            tx_volume,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        );
        let remaining = money_supply.saturating_sub(already_generated);
        let remaining_u64 = remaining.min(u128::from(u64::MAX)) as u64;
        let effective = apply_release_multiplier(base_reward, mult).min(remaining_u64);

        let emission_share = calc_effective_emission_share(
            abs_height,
            0,
            params.staker_emission_share,
            params.staker_emission_decay,
            params.blocks_per_year,
        );
        let (_miner, staker_emission) = split_block_emission(effective, emission_share);

        let circulating = (already_generated as u64).saturating_sub(total_burned as u64);
        let burn_pct = calc_burn_pct(
            tx_volume,
            params.tx_volume_baseline,
            circulating,
            params.money_supply,
            params.burn_base_rate,
            params.burn_cap,
        );
        let total_fees = (u128::from(tx_volume) * u128::from(config.fee_per_tx))
            .min(u128::from(u64::MAX)) as u64;
        // share = SCALE → the whole burn (pre-split); the candidate re-splits it.
        let whole_burn = compute_burn_split(total_fees, burn_pct, SCALE).staker_pool_amount;
        // Flat-ledger advance: destroy at the shipped 25% split.
        let flat = compute_burn_split(total_fees, burn_pct, params.staker_pool_share);

        year_emission_atomic += u128::from(staker_emission);
        year_burn_atomic += u128::from(whole_burn);
        already_generated = (already_generated + u128::from(effective)).min(money_supply);
        total_burned += u128::from(flat.actually_destroyed);

        if (block + 1) % params.blocks_per_year == 0 {
            let year = (block + 1) / params.blocks_per_year;
            aggs.push(A1YearAgg {
                year,
                n: frozen_shards(cumulative_outputs as u64),
                emission_leg_atomic: year_emission_atomic.min(u128::from(u64::MAX)) as u64,
                whole_burn_atomic: year_burn_atomic.min(u128::from(u64::MAX)) as u64,
            });
            year_emission_atomic = 0;
            year_burn_atomic = 0;
        }
    }
    aggs
}

/// The **minimum** clearance ratio `budget_skl / burden_skl` across the
/// sustained years (past the ramp) for a candidate, at a given opportunity-cost
/// rate. `≥ 1` ⇒ the candidate keeps the staker whole every sustained year.
///
/// **Algorithm zone is integer** (DQ-2G): `budget_atomic = emission_leg +
/// mul_scale(whole_burn, share_milli(n))` — the escalation share is applied by
/// the SAME `mul_scale` production runs (`compute_burn_split`), never an f64
/// `× share_fraction`. Burden (F-G) is the integer locked-bond opportunity cost
/// (principal atomic; the exogenous rate is the single float boundary) plus the
/// minor fiat storage term. f64 appears **only** in the returned ratio (report)
/// and at the two named exogenous boundaries (rate, `SKL/fiat` price). The
/// dominant term is price-independent (SKL vs SKL).
#[must_use]
pub fn a1_min_clearance_ratio(
    aggs: &[A1YearAgg],
    candidate: &EscalationCurve,
    opp_cost_rate: f64,
    fiat_per_skl: f64,
    kryder: KryderRate,
) -> f64 {
    aggs.iter()
        .filter(|a| a.year > A1_RAMP_YEARS && a.n > 0)
        .map(|a| {
            // Integer share application — production's exact op, not f64.
            let share_milli = candidate.share(a.n);
            let fee_leg_atomic = mul_scale(a.whole_burn_atomic, share_milli);
            let budget_atomic = u128::from(a.emission_leg_atomic) + u128::from(fee_leg_atomic);
            let budget_skl = budget_atomic as f64 / COIN; // report/comparison boundary

            let opp_cost_skl = bond_opp_cost_skl(a.n, opp_cost_rate);
            let storage_fiat = burden_cost_fiat_per_year(
                a.n * REPLICAS_PER_SHARD,
                a.year as f64,
                BASE_STORAGE_FIAT_PER_BYTE_YEAR,
                kryder,
            );
            let burden_skl = opp_cost_skl + storage_fiat / fiat_per_skl;
            if burden_skl <= 0.0 {
                f64::INFINITY
            } else {
                budget_skl / burden_skl
            }
        })
        .fold(f64::INFINITY, f64::min)
}

/// A1 clearance for one candidate (or the flat baseline): the min clearance
/// ratio at each opportunity-cost-rate-band member, at the binding 0%/yr Kryder
/// and mid price for the minor storage term (F-G; the dominant term is
/// price-independent).
#[derive(Debug, Clone, Serialize)]
pub struct A1CandidateResult {
    /// `None` for the flat-25 status-quo baseline.
    pub asymptote_pct: Option<f64>,
    pub knee_shards: Option<u64>,
    /// Min `budget/burden` ratio across sustained years, per opportunity-cost
    /// rate (`≥ 1` clears). Parallel to [`OPP_COST_RATE_BAND`]; the last member
    /// (10%) is the binding case.
    pub min_ratio_by_rate: Vec<f64>,
}

/// A1 clearance for one scenario.
#[derive(Debug, Clone, Serialize)]
pub struct A1ScenarioResult {
    pub scenario: String,
    pub final_n: u64,
    pub flat25: A1CandidateResult,
    pub candidates: Vec<A1CandidateResult>,
}

fn a1_candidate_result(
    aggs: &[A1YearAgg],
    curve: &EscalationCurve,
    is_flat: bool,
) -> A1CandidateResult {
    // Mid price ($0.10) for the minor storage term; the binding bond-opp-cost
    // term is price-independent, so this choice barely moves the verdict (F-G).
    let mid_price = SKL_FIAT_PRICE_BAND[1];
    let min_ratio_by_rate = OPP_COST_RATE_BAND
        .iter()
        .map(|&rate| a1_min_clearance_ratio(aggs, curve, rate, mid_price, KryderRate::Stall))
        .collect();
    A1CandidateResult {
        asymptote_pct: if is_flat {
            None
        } else {
            Some(curve.asymptote as f64 / 10_000.0)
        },
        knee_shards: if is_flat {
            None
        } else {
            Some(curve.knee_shards)
        },
        min_ratio_by_rate,
    }
}

/// A1 — burden clearance (§12.2, reshaped by F-G). For each scenario, the min
/// `budget/burden` ratio of the flat-25 baseline and every candidate, across the
/// opportunity-cost-rate band. `budget = emission_leg + fee_burn·share(n)`;
/// `burden = locked-bond opportunity cost (binding) + minor storage`. Prints a
/// stderr table, returns the data.
fn a1_clearance_report(params: &SimParams) -> Vec<A1ScenarioResult> {
    eprintln!(
        "\nA1 — burden clearance (§12.2, F-G): min budget / (bond-opp-cost + storage) ratio.\n\
         budget = emission_leg + fee_burn x share(n) [SKL]; binding burden = bond_floor 0.75 x R{R} x n x rate.\n\
         >=1.0 keeps the staker whole every sustained year. Columns = opp-cost rate {RATES:?} (10% binding).\n\
         Storage is a minor add-on (F-G: ~100x smaller); the binding term is PRICE-INDEPENDENT (SKL vs SKL).",
        R = REPLICAS_PER_SHARD,
        RATES = OPP_COST_RATE_BAND,
    );
    eprintln!(
        "{:<20} {:>12}   {:>24}   {:>24}",
        "scenario", "best-cand", "flat-25 ratio @rate", "best-cand ratio @rate"
    );

    let mut results = Vec::new();
    for config in all_scenarios(params) {
        let aggs = a1_year_aggs(params, &config);
        let final_n = aggs.last().map_or(0, |a| a.n);
        let flat25 = a1_candidate_result(&aggs, &flat_25(), true);
        let candidates: Vec<A1CandidateResult> = family()
            .iter()
            .map(|c| a1_candidate_result(&aggs, c, false))
            .collect();

        // Headline: the flat baseline and the strongest candidate (max min-ratio
        // at the BINDING 10% rate); the JSON carries all nine.
        let binding = OPP_COST_RATE_BAND.len() - 1; // 10% index
        let best = candidates
            .iter()
            .max_by(|a, b| {
                a.min_ratio_by_rate[binding]
                    .partial_cmp(&b.min_ratio_by_rate[binding])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
            .unwrap_or_else(|| flat25.clone());
        eprintln!(
            "{:<20} {:>12}   {:>7.2} {:>7.2} {:>7.2}   {:>7.2} {:>7.2} {:>7.2}",
            trunc(&config.name, 20),
            best.asymptote_pct
                .map(|a| format!("{a:.0}%/{}", best.knee_shards.unwrap_or(0)))
                .unwrap_or_default(),
            flat25.min_ratio_by_rate[0],
            flat25.min_ratio_by_rate[1],
            flat25.min_ratio_by_rate[2],
            best.min_ratio_by_rate[0],
            best.min_ratio_by_rate[1],
            best.min_ratio_by_rate[2],
        );

        results.push(A1ScenarioResult {
            scenario: config.name.clone(),
            final_n,
            flat25,
            candidates,
        });
    }
    eprintln!(
        "  -> rate cols each = {:?} (10% binding, last). The D2 case is where the\n\
         best candidate clears (>=1.0) at 10% while flat-25 does NOT — escalation\n\
         earning its keep. A4/A5 then drop any winner that fails W9/W10.",
        OPP_COST_RATE_BAND
    );
    results
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

/// Preview the §6.1 escalation candidate family (DQ-2D): the staker-share `%`
/// each `(asymptote, knee)` candidate produces across a span of
/// `frozen_segment_count`. Shows the shapes A1 will measure for clearance; the
/// flat 25% status quo is the first column's `n = 0` value (all candidates floor
/// there).
fn print_escalation_family() {
    eprintln!(
        "\nEscalation candidate family (§6.1 / DQ-2D) — staker share % vs n = frozen shards:\n\
         (floor 25% at n=0, saturates to asymptote at the knee; all asymptotes < 100%)"
    );
    eprint!("{:>8} {:>7}", "asympt%", "knee");
    for n in ESCALATION_PREVIEW_N {
        eprint!("  n={n:>7}");
    }
    eprintln!();
    // Status-quo baseline: the frozen 25% share every candidate is measured
    // against in A1 (does escalation clear where the flat share does not?).
    eprint!("{:>8} {:>7}", "FLAT", "-");
    for n in ESCALATION_PREVIEW_N {
        eprint!("  {:>9.1}", flat_25().share_fraction(n) * 100.0);
    }
    eprintln!();
    for c in family() {
        eprint!(
            "{:>8.0} {:>7}",
            c.asymptote as f64 / 10_000.0,
            c.knee_shards
        );
        for n in ESCALATION_PREVIEW_N {
            eprint!("  {:>9.1}", c.share_fraction(n) * 100.0);
        }
        eprintln!();
    }
    eprintln!(
        "  -> Stage 2 sweeps all {} candidates; A1 keeps those that clear the\n\
         burden under 0%/yr Kryder, A4/A5 drop those that fail W9/W10; Stage 3\n\
         freezes the survivor's number.",
        family().len()
    );
}

/// A4 (W9) **cost side** — the leaf-stuffer's cost to inflate `n` by one shard,
/// across chain depth (§12.2, DQ-2C). The *revenue* side and the ROI < 1 gate
/// land next (cp4b); this establishes the price of a stuffed shard, single-
/// sourced through the production weight predictor (`calibration.rs`), and the
/// Monero-replication row (the March-2024 anchor as shards' worth of leaves).
///
/// `n` is sampled as **frozen shards**; the curve-tree depth (hence FCMP proof
/// cost) rides the total leaf count `n · SEGMENT_LEAF_COUNT`, so the cost RISES
/// with chain size — cheapest early (the binding direction, §11.3).
fn print_stuffer_cost_curve() {
    let rep = rucknium_shards_equivalent();
    eprintln!(
        "\nA4 (W9) leaf-stuffer cost — 1-in/{OUT}-out, min weight-fee @ {FPB} atomic/byte:\n\
         Monero-replication anchor (DQ-2C): the March-2024 spam bought ~{GB:.2} GB / {DAYS} days\n\
         for ~{XMR:.1} XMR — that output volume is only ~{REP} Shekyl shards' worth of leaves.\n\
         Shape is max-leaves-per-fee geometry, NOT decoy poisoning (FCMP++ has no rings).",
        OUT = crate::calibration::STUFFER_OUTPUTS_PER_TX,
        FPB = crate::calibration::FEE_PER_BYTE_ATOMIC,
        GB = RUCKNIUM_SPAM_BYTES_GB,
        DAYS = RUCKNIUM_DURATION_DAYS,
        XMR = RUCKNIUM_SPAM_FEES_XMR,
        REP = rep,
    );
    eprintln!(
        "{:<14} {:>10} {:>16} {:>18}",
        "chain n(shards)", "tree_depth", "fee/tx (SKL)", "cost/shard (SKL)"
    );
    for n_shards in ESCALATION_PREVIEW_N {
        // n=0 has no tree; sample the first shard so the depth/cost are defined.
        let n_shards = n_shards.max(1);
        let chain_leaves = n_shards.saturating_mul(SEGMENT_LEAF_COUNT);
        let depth = tree_depth_for_leaves(chain_leaves);
        let fee_tx_skl = stuffer_tx_fee_atomic(depth) as f64 / COIN;
        let cost_shard_skl = leaf_stuffer_cost_per_shard_atomic(chain_leaves) as f64 / COIN;
        eprintln!("{n_shards:<14} {depth:>10} {fee_tx_skl:>16.6} {cost_shard_skl:>18.4}",);
    }
    eprintln!(
        "  -> cost/shard rises with chain depth (deeper tree = larger FCMP proof).\n\
         cp4b weighs this against the escalation Delta-pool a stuffing staker captures\n\
         (ROI < 1 gate): a survivor of A1 must ALSO price the stuffer out here."
    );
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

    print_escalation_family();
    print_stuffer_cost_curve();
    let a1 = a1_clearance_report(params);

    let report = Stage2Report {
        burden_trajectories: trajectories,
        a1_clearance: a1,
    };
    let json = serde_json::to_string_pretty(&report).expect("JSON serialization failed");
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes()).expect("write failed");
    stdout.write_all(b"\n").expect("write failed");
    eprintln!("\nStage-2 (burden trajectory + escalation family + A1 clearance) complete.");
}

/// The combined `--stage2` JSON payload (grows as arms land).
#[derive(Debug, Clone, Serialize)]
pub struct Stage2Report {
    pub burden_trajectories: Vec<BurdenTrajectory>,
    pub a1_clearance: Vec<A1ScenarioResult>,
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
    fn a1_aggs_positive_and_emission_decays() {
        let params = SimParams::default();
        let cfg = &all_scenarios(&params)[0]; // baseline
        let aggs = a1_year_aggs(&params, cfg);
        assert!(!aggs.is_empty());
        for a in &aggs {
            assert!(a.emission_leg_atomic > 0, "emission leg positive");
            assert!(a.whole_burn_atomic > 0, "fee burn positive");
        }
        // Emission decays ×0.90/yr, so the last year's leg is below the first's.
        assert!(aggs.last().unwrap().emission_leg_atomic < aggs[0].emission_leg_atomic);
    }

    #[test]
    fn a1_escalation_never_below_flat() {
        // share(n) >= FLOOR (25%) always, so any candidate's fee leg — and thus
        // its clearance ratio — is >= the flat-25 baseline's, at any price.
        let params = SimParams::default();
        for cfg in all_scenarios(&params) {
            let aggs = a1_year_aggs(&params, &cfg);
            // Binding 10% opp-cost rate, mid price.
            let flat_ratio =
                a1_min_clearance_ratio(&aggs, &flat_25(), 0.10, 0.10, KryderRate::Stall);
            for c in family() {
                let r = a1_min_clearance_ratio(&aggs, &c, 0.10, 0.10, KryderRate::Stall);
                assert!(
                    r >= flat_ratio - 1e-6,
                    "escalation ratio {r} < flat {flat_ratio} in {}",
                    cfg.name
                );
            }
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

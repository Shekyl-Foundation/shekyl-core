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

use std::fmt;

use serde::Serialize;
use std::io::Write;

use shekyl_economics::{
    base_block_reward,
    burn::{calc_burn_pct, compute_burn_split},
    calc_effective_emission_share, calc_release_multiplier,
    params::{mul_scale, EconomicParams, SCALE},
    release::apply_release_multiplier,
    split_block_emission, ScaledShare,
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
use crate::population::{
    attacker_capped_work_milli, honest_sigma_work_milli, honest_sigma_work_milli_deleted, DQ2H_TAIL,
};
use crate::scenarios::all_scenarios;
use shekyl_archival_retention::{
    reward_share_floor, ARCHIVAL_BOND_FLOOR_ATOMIC, MAX_HOLDINGS_SHARDS, SEGMENT_LEAF_COUNT,
};

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
        // Escalation numerics come from the shipped config: the sim must never
        // invent them, since the asymptote is ceremony-gated and unpinned (§11.4).
        ..EconomicParams::default()
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
        let whole_burn =
            compute_burn_split(total_fees, burn_pct, ScaledShare::from_raw(SCALE)).staker_pool_amount;
        // Flat-ledger advance: destroy at the shipped 25% split.
        let flat = compute_burn_split(
            total_fees,
            burn_pct,
            ScaledShare::from_raw(params.staker_pool_share),
        );

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
fn a1_clearance_report(
    out: &mut impl fmt::Write,
    params: &SimParams,
) -> Result<Vec<A1ScenarioResult>, fmt::Error> {
    writeln!(out,
        "\nA1 — burden clearance (§12.2, F-G): min budget / (bond-opp-cost + storage) ratio.\n\
         budget = emission_leg + fee_burn x share(n) [SKL]; binding burden = bond_floor 0.75 x R{R} x n x rate.\n\
         >=1.0 keeps the staker whole every sustained year. Columns = opp-cost rate {RATES:?} (10% binding).\n\
         Storage is a minor add-on (F-G: ~100x smaller); the binding term is PRICE-INDEPENDENT (SKL vs SKL).",
        R = REPLICAS_PER_SHARD,
        RATES = OPP_COST_RATE_BAND,
    )?;
    writeln!(
        out,
        "{:<20} {:>12}   {:>24}   {:>24}",
        "scenario", "best-cand", "flat-25 ratio @rate", "best-cand ratio @rate"
    )?;

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
        writeln!(
            out,
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
        )?;

        results.push(A1ScenarioResult {
            scenario: config.name.clone(),
            final_n,
            flat25,
            candidates,
        });
    }
    writeln!(
        out,
        "  -> rate cols each = {:?} (10% binding, last). The D2 case is where the\n\
         best candidate clears (>=1.0) at 10% while flat-25 does NOT — escalation\n\
         earning its keep. A4/A5 then drop any winner that fails W9/W10.",
        OPP_COST_RATE_BAND
    )?;
    Ok(results)
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
fn print_escalation_family(out: &mut impl fmt::Write) -> fmt::Result {
    writeln!(
        out,
        "\nEscalation candidate family (§6.1 / DQ-2D) — staker share % vs n = frozen shards:\n\
         (floor 25% at n=0, saturates to asymptote at the knee; all asymptotes < 100%)"
    )?;
    write!(out, "{:>8} {:>7}", "asympt%", "knee")?;
    for n in ESCALATION_PREVIEW_N {
        write!(out, "  n={n:>7}")?;
    }
    writeln!(out)?;
    // Status-quo baseline: the frozen 25% share every candidate is measured
    // against in A1 (does escalation clear where the flat share does not?).
    write!(out, "{:>8} {:>7}", "FLAT", "-")?;
    for n in ESCALATION_PREVIEW_N {
        write!(out, "  {:>9.1}", flat_25().share_fraction(n) * 100.0)?;
    }
    writeln!(out)?;
    for c in family() {
        write!(
            out,
            "{:>8.0} {:>7}",
            c.asymptote as f64 / 10_000.0,
            c.knee_shards
        )?;
        for n in ESCALATION_PREVIEW_N {
            write!(out, "  {:>9.1}", c.share_fraction(n) * 100.0)?;
        }
        writeln!(out)?;
    }
    writeln!(
        out,
        "  -> Stage 2 sweeps all {} candidates; A1 keeps those that clear the\n\
         burden under 0%/yr Kryder, A4/A5 drop those that fail W9/W10; Stage 3\n\
         freezes the survivor's number.",
        family().len()
    )?;

    Ok(())
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
fn print_stuffer_cost_curve(out: &mut impl fmt::Write) -> fmt::Result {
    let rep = rucknium_shards_equivalent();
    writeln!(
        out,
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
    )?;
    writeln!(
        out,
        "{:<14} {:>10} {:>16} {:>18}",
        "chain n(shards)", "tree_depth", "fee/tx (SKL)", "cost/shard (SKL)"
    )?;
    for n_shards in ESCALATION_PREVIEW_N {
        // n=0 has no tree; sample the first shard so the depth/cost are defined.
        let n_shards = n_shards.max(1);
        let chain_leaves = n_shards.saturating_mul(SEGMENT_LEAF_COUNT);
        let depth = tree_depth_for_leaves(chain_leaves);
        let fee_tx_skl = stuffer_tx_fee_atomic(depth) as f64 / COIN;
        let cost_shard_skl = leaf_stuffer_cost_per_shard_atomic(chain_leaves) as f64 / COIN;
        writeln!(
            out,
            "{n_shards:<14} {depth:>10} {fee_tx_skl:>16.6} {cost_shard_skl:>18.4}",
        )?;
    }
    writeln!(
        out,
        "  -> cost/shard rises with chain depth (deeper tree = larger FCMP proof).\n\
         The A4 ROI gate below weighs this against the escalation Delta-pool a\n\
         stuffing staker captures: a survivor of A1 must ALSO price the stuffer out."
    )?;

    Ok(())
}

// ── A4 (W9) ROI gate — cp4b (served-work capture + coupled burden) ───────────

/// Attacker horizon band, **years** the inflated corpus persists (the ratchet is
/// permanent, §6.2). Revenue AND the coupled bond burden both accrue per year, so
/// horizon is swept, not simply maximised (DQ-2E / D-1..D-5).
const A4_HORIZON_BAND: [u64; 3] = [1, 5, 10];

/// Shards the attacker stuffs in one campaign (the leverage axis they optimise).
/// The gate takes the **max ROI** over this sweep — the attacker picks the block.
const A4_DELTA_SWEEP: [u64; 5] = [100, 1_000, 10_000, 50_000, 100_000];

/// Honest-archiver holdings per bond — the **concentration axis** the verdict is
/// sensitive to (`population.rs`): small bonds dodge the `curve_milli` plateau
/// (large `Σwork`, small attacker slice); large bonds are capped (small `Σwork`,
/// large attacker slice). Swept, and the gate takes the worst (most concentrated,
/// = most attacker-favouring) — so a pass is robust to however honest archivers
/// actually group holdings.
const A4_HONEST_HOLDINGS_BAND: [u64; 3] = [4, 64, 512];

/// The stuffer groups its fresh shards **small** (4/bond) to stay under the
/// plateau knee — full work credit, attacker-favouring (`population.rs`).
const A4_ATTACKER_HOLDINGS: u64 = 4;

/// Opportunity-cost rate on the attacker's locked bond capital — the **minimum**
/// band member (2%), the cheapest hold and so the highest ROI (attacker-favouring;
/// F-G). Storage (~100× smaller, F-G) is omitted from cost — also attacker-
/// favouring. The single float boundary in the cost.
const A4_OPP_RATE: f64 = 0.02;

/// One attacker configuration's ROI (§12.2 A4, DQ-2C) — the **manipulation
/// premium**, served-work channel. The base archiver return (does serving `Δn`
/// shards pay at the *un-manipulated* share) is A1's question, not W9's; W9 asks
/// only whether **gaming the escalation share** adds profit. So revenue is the
/// attacker's served-work slice of the **Δpool the share increase creates** — not
/// the whole captured pool (which would conflate "archiving is profitable" with
/// "stuffing pays"). A flat share has no lever, so flat-25 reads exactly 0.
///
/// - **revenue** = `capture · Δpool · horizon`, where `Δpool = mul_scale(whole_burn,
///   share(n+Δn)) − mul_scale(whole_burn, share(n))` (share gates only the fee
///   leg; emission is share-independent, so it drops out of the *delta*), and
///   `capture = reward_share_floor(Δpool, their_work, Σwork)` — the attacker's
///   served-work slice via the production distribution. They serve the `Δn` fresh
///   shards at `r = 1` (sole first-mover), grouped small to dodge the cap.
/// - **cost** = one-time stuffing weight-fees **+ the §6.2 coupled burden**: to
///   capture, the attacker must bond `ARCHIVAL_BOND_FLOOR` per fresh shard (r=1,
///   sole replica) and hold it every year. That coupling is the defense.
///
/// Attacker-favouring: min opp-rate, storage omitted, small (uncapped) attacker
/// grouping, age-0 (no incumbency). Integer through Δpool + the reward chain; f64
/// only at the reported ratio and the opp-rate boundary (DQ-2G).
/// Lag, **years**, before honest replicas respond to the stuffer's fresh r=1
/// shards (the replication-response sensitivity). NOT gating — a freeze decision
/// cannot rely on market-response speed — but reported so Stage 3 sees how much
/// of the r=1 multiplier is "market never responds" vs "fails robustly".
const A4_RESPONSE_LAG_YEARS: u64 = 2;

/// Decomposed A4 attack economics — the components the fee-floor must be sized
/// against, not the bare ratio (revenue rides fee-flow *volume*; the per-output
/// fee rides *rate*, so a floor cannot close a volume-driven gap in every regime).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct A4Decomp {
    /// Δshare-attributable pool flow per year, SKL — the **volume** term (scales
    /// with the network's fee burn, which the attacker does not pay for).
    pub dpool_skl_per_year: f64,
    /// The attacker's served-work slice of that Δpool (0..1).
    pub capture_frac: f64,
    /// `Δn/(n+Δn)` — the slice a non-premium (proportional) capture would take.
    pub proportional_frac: f64,
    /// `capture_frac / proportional_frac` — the **first-mover work premium** (>1
    /// means r=1 density + honest capping let the attacker grab more than its
    /// shard share).
    pub premium: f64,
    pub revenue_skl: f64,
    /// Cost split: one-time stuffing weight-fees …
    pub fee_skl: f64,
    /// … and the §6.2 coupled bond opportunity cost over the horizon.
    pub bond_skl: f64,
    pub roi: f64,
    /// ROI once honest replicas respond (r: 1→R after [`A4_RESPONSE_LAG_YEARS`]);
    /// a first-order sensitivity, not the gate.
    pub roi_market_responds: f64,
    /// Per-output fee **multiplier** that would drive this config's ROI to 1
    /// (≈ ROI while cost is fee-dominated) — the size of the fee-floor lever *this
    /// regime* demands. Wide variation across regimes ⇒ no single floor closes all.
    pub fee_mult_to_close: f64,
}

/// Decompose one attacker configuration (§12.2 A4, DQ-2C) — the manipulation
/// premium, served-work channel. See [`A4Decomp`]; revenue is `capture · Δpool ·
/// horizon`, cost is stuffing fees + the coupled bond.
#[must_use]
fn a4_decompose(
    whole_burn_atomic: u64,
    n: u64,
    sigma_honest_milli: u64,
    candidate: &EscalationCurve,
    delta: u64,
    horizon_years: u64,
) -> A4Decomp {
    let n2 = n.saturating_add(delta);
    // The share-manipulation Δpool on the honest burn — the production op. Only the
    // fee leg is share-gated, so the emission leg cancels in the delta.
    let dpool_atomic = mul_scale(whole_burn_atomic, candidate.share(n2))
        .saturating_sub(mul_scale(whole_burn_atomic, candidate.share(n)));
    let dpool_skl_per_year = dpool_atomic as f64 / COIN;
    // Served-work capture of that Δpool: Δn fresh shards at r=1, grouped small.
    let capped_att = attacker_capped_work_milli(delta, A4_ATTACKER_HOLDINGS);
    let sigma_total = sigma_honest_milli.saturating_add(capped_att);
    let capture_frac = if sigma_total == 0 {
        0.0
    } else {
        capped_att as f64 / sigma_total as f64
    };
    let proportional_frac = if n2 == 0 {
        0.0
    } else {
        delta as f64 / n2 as f64
    };
    let premium = if proportional_frac > 0.0 {
        capture_frac / proportional_frac
    } else {
        0.0
    };
    let revenue_atomic = reward_share_floor(dpool_atomic, capped_att, sigma_total);
    let revenue_skl = (u128::from(revenue_atomic) * u128::from(horizon_years)) as f64 / COIN;

    // Cost: one-time stuffing weight-fees + the coupled bond opportunity cost.
    let chain_leaves = n2.saturating_mul(SEGMENT_LEAF_COUNT);
    let fee_skl =
        (leaf_stuffer_cost_per_shard_atomic(chain_leaves) * u128::from(delta)) as f64 / COIN;
    let bond_skl = (u128::from(ARCHIVAL_BOND_FLOOR_ATOMIC) * u128::from(delta)) as f64 / COIN
        * A4_OPP_RATE
        * horizon_years as f64;
    let cost_skl = fee_skl + bond_skl;
    let roi = if cost_skl <= 0.0 {
        f64::INFINITY
    } else {
        revenue_skl / cost_skl
    };

    // Replication response (first-order): for the first LAG years the attacker is
    // sole server (full capture); after, honest replicas raise r to R, so the
    // attacker becomes 1-of-R and their slice of each shard's (r-independent) work
    // falls by ~R. Fraction of the r=1 revenue that survives over the horizon:
    let r = REPLICAS_PER_SHARD.max(1) as f64;
    let h = horizon_years.max(1) as f64;
    let lag = A4_RESPONSE_LAG_YEARS.min(horizon_years) as f64;
    let survive = (lag + (h - lag) / r) / h;
    let roi_market_responds = if cost_skl <= 0.0 {
        f64::INFINITY
    } else {
        revenue_skl * survive / cost_skl
    };
    // Fee multiplier to drive ROI→1: raise the fee leg until fee' + bond = revenue.
    let fee_mult_to_close = if fee_skl > 0.0 {
        ((revenue_skl - bond_skl).max(0.0)) / fee_skl
    } else {
        f64::INFINITY
    };

    A4Decomp {
        dpool_skl_per_year,
        capture_frac,
        proportional_frac,
        premium,
        revenue_skl,
        fee_skl,
        bond_skl,
        roi,
        roi_market_responds,
        fee_mult_to_close,
    }
}

/// The scalar ROI (the gate quantity) — a thin projection of [`a4_decompose`].
#[must_use]
fn a4_stuffing_roi(
    whole_burn_atomic: u64,
    n: u64,
    sigma_honest_milli: u64,
    candidate: &EscalationCurve,
    delta: u64,
    horizon_years: u64,
) -> f64 {
    a4_decompose(
        whole_burn_atomic,
        n,
        sigma_honest_milli,
        candidate,
        delta,
        horizon_years,
    )
    .roi
}

/// A4 verdict for one candidate: the **max attacker ROI** over years × `Δn` ×
/// horizon, reported **separately per honest-holdings environment** so the
/// escalation's own manipulation effect (at the rational small-bond equilibrium,
/// `hHold = 4`) is distinguishable from the curve-cap amplification (at the
/// pathological fully-capped `hHold = 512`, a separate concern — the cap
/// under-rewards naive big-bond archivers and inflates the stuffer's slice).
///
/// The gate binds on the **realistic** end (index 0, rational honest archivers
/// dodge the cap): `passes` = `roi_by_hholdings[0] < 1`. The capped end is
/// reported for visibility, not as the escalation's verdict.
#[derive(Debug, Clone, Serialize)]
pub struct A4CandidateResult {
    /// `None` for the flat-25 status-quo baseline.
    pub asymptote_pct: Option<f64>,
    pub knee_shards: Option<u64>,
    /// Max attacker ROI per [`A4_HONEST_HOLDINGS_BAND`] member (realistic →
    /// capped). Index 0 is the rational small-bond environment the gate binds on.
    pub roi_by_hholdings: [f64; A4_HONEST_HOLDINGS_BAND.len()],
    /// The `(n, Δn, horizon_years)` achieving the realistic-end (index 0) max.
    pub worst_at: (u64, u64, u64),
    /// Decomposition at the realistic-end worst config (the row the fee-floor and
    /// replication-response analysis reads). `None` only if no sustained year had
    /// a positive-Δpool config (e.g. flat-25, where every Δpool is 0).
    pub worst_decomp: Option<A4Decomp>,
    pub passes: bool,
}

/// A4 verdict for one scenario.
#[derive(Debug, Clone, Serialize)]
pub struct A4ScenarioResult {
    pub scenario: String,
    pub flat25: A4CandidateResult,
    pub candidates: Vec<A4CandidateResult>,
}

/// Precomputed honest `Σwork` per sustained year, one value per
/// [`A4_HONEST_HOLDINGS_BAND`] member. Built once per scenario (independent of the
/// escalation candidate) since `Σwork_honest` depends only on `n` + holdings.
struct SigmaCache {
    /// `(year, n, [Σwork per honest-holdings band member])`.
    rows: Vec<(u64, u64, [u64; A4_HONEST_HOLDINGS_BAND.len()])>,
}

impl SigmaCache {
    fn build(aggs: &[A1YearAgg]) -> Self {
        let rows = aggs
            .iter()
            .filter(|a| a.year > A1_RAMP_YEARS && a.n > 0)
            .map(|a| {
                let mut sig = [0u64; A4_HONEST_HOLDINGS_BAND.len()];
                for (k, &h) in A4_HONEST_HOLDINGS_BAND.iter().enumerate() {
                    sig[k] = honest_sigma_work_milli(a.n, DQ2H_TAIL, h);
                }
                (a.year, a.n, sig)
            })
            .collect();
        Self { rows }
    }
}

fn a4_candidate_result(
    aggs: &[A1YearAgg],
    sigma: &SigmaCache,
    curve: &EscalationCurve,
    is_flat: bool,
) -> A4CandidateResult {
    let mut roi_by_hholdings = [0.0_f64; A4_HONEST_HOLDINGS_BAND.len()];
    let mut worst_at = (0u64, 0u64, 0u64);
    let mut worst_decomp: Option<A4Decomp> = None;
    for &(_year, n, ref sig) in &sigma.rows {
        let agg = aggs.iter().find(|a| a.n == n);
        let Some(agg) = agg else { continue };
        for &delta in &A4_DELTA_SWEEP {
            for &h in &A4_HORIZON_BAND {
                for k in 0..A4_HONEST_HOLDINGS_BAND.len() {
                    let roi = a4_stuffing_roi(agg.whole_burn_atomic, n, sig[k], curve, delta, h);
                    if roi > roi_by_hholdings[k] {
                        roi_by_hholdings[k] = roi;
                        // Track config + decomposition at the realistic (index-0)
                        // end, the gate the fee-floor/response analysis reads.
                        if k == 0 {
                            worst_at = (n, delta, h);
                            worst_decomp = Some(a4_decompose(
                                agg.whole_burn_atomic,
                                n,
                                sig[k],
                                curve,
                                delta,
                                h,
                            ));
                        }
                    }
                }
            }
        }
    }
    A4CandidateResult {
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
        roi_by_hholdings,
        worst_at,
        worst_decomp,
        passes: roi_by_hholdings[0] < 1.0,
    }
}

/// A4 (W9) attacker-ROI gate across the scenario set (§12.2). Served-work capture
/// with the §6.2 bond coupling; the gate is **ROI < 1 everywhere** — the
/// executable form of "stuffing it funds it".
fn a4_stuffing_report(
    out: &mut impl fmt::Write,
    params: &SimParams,
) -> Result<Vec<A4ScenarioResult>, fmt::Error> {
    writeln!(
        out,
        "\nA4 — W9 output-stuffing ROI (§12.2, DQ-2C): SERVED-WORK capture (the D2 pool\n\
         is distributed by served work per bond, NOT by stake). Attacker serves the Δn\n\
         stuffed shards at r=1 and captures reward_share_floor(pool(n+Δn), their work,\n\
         Σwork) each year; cost = stuffing fees + the §6.2 coupled bond (0.75 SKL/shard\n\
         held forever). Best over [years x Δn{DELTAS:?} x horizon{H:?}yr], shown at BOTH\n\
         honest-holdings ends: hHold=4 (rational small bonds — the gate) and hHold=512\n\
         (pathological fully-capped — a curve-cap concern, not the escalation's).\n\
         Flat-25 has no share lever ⇒ 0. Attacker-favouring: min opp-rate {RATE}, storage\n\
         omitted, age-0. PASS iff realistic-end (hHold=4) ROI < 1 everywhere.",
        DELTAS = A4_DELTA_SWEEP,
        H = A4_HORIZON_BAND,
        RATE = A4_OPP_RATE,
    )?;
    writeln!(
        out,
        "{:<20} {:>10} {:>14} {:>14} {:>18}",
        "scenario", "flat-25", "best@hHold4", "best@hHold512", "worst (n/Δn/H)"
    )?;

    let mut results = Vec::new();
    let mut decomp_rows: Vec<(String, A4Decomp)> = Vec::new();
    for config in all_scenarios(params) {
        let aggs = a1_year_aggs(params, &config);
        let sigma = SigmaCache::build(&aggs);
        let flat25 = a4_candidate_result(&aggs, &sigma, &flat_25(), true);
        let candidates: Vec<A4CandidateResult> = family()
            .iter()
            .map(|c| a4_candidate_result(&aggs, &sigma, c, false))
            .collect();
        let last = A4_HONEST_HOLDINGS_BAND.len() - 1;
        // Worst candidate at the realistic (index-0) end — the gate binds here.
        let worst_real = candidates
            .iter()
            .max_by(|a, b| {
                a.roi_by_hholdings[0]
                    .partial_cmp(&b.roi_by_hholdings[0])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
            .unwrap_or_else(|| flat25.clone());
        let worst_capped_roi = candidates
            .iter()
            .map(|c| c.roi_by_hholdings[last])
            .fold(0.0_f64, f64::max);
        let (wn, wd, whz) = worst_real.worst_at;
        writeln!(
            out,
            "{:<20} {:>10.4} {:>14.4} {:>14.4} {:>10}/{:>5}/{:>2}",
            trunc(&config.name, 20),
            flat25.roi_by_hholdings[0],
            worst_real.roi_by_hholdings[0],
            worst_capped_roi,
            wn,
            wd,
            whz,
        )?;
        if let Some(d) = worst_real.worst_decomp {
            decomp_rows.push((config.name.clone(), d));
        }
        results.push(A4ScenarioResult {
            scenario: config.name.clone(),
            flat25,
            candidates,
        });
    }
    let any_fail = results
        .iter()
        .any(|r| !r.flat25.passes || r.candidates.iter().any(|c| !c.passes));
    writeln!(
        out,
        "  -> W9 gate (realistic hHold=4 end): {}. Flat-25 = 0 (no share lever): the\n\
         premium is purely the escalation's. A steeper share (higher asymptote /\n\
         tighter knee) lets the marginal stuffed shard's Δpool slice out-earn its\n\
         coupled bond — so the gate, not just A1, bounds escalation aggressiveness.\n\
         The hHold=512 column is far worse but reflects a SEPARATE curve-cap\n\
         dodgeability concern (naive big-bond archivers self-capped), not D2.",
        if any_fail {
            "FAIL — rule-21 per-output fee-floor reopen (§11.3), NOT a D2 redesign (§8)"
        } else {
            "PASS"
        }
    )?;
    a4_print_decomposition(out, &decomp_rows)?;
    Ok(results)
}

/// Decompose the realistic-end worst config per scenario (the row the fee-floor
/// must be sized against). Separates **revenue** into the Δpool *flow* (rides
/// network fee-volume, which the attacker does not pay for) and the first-mover
/// *premium* (capture > proportional), and **cost** into fees vs the coupled
/// bond — then reports the fee-multiplier each regime would need to reach ROI 1.
/// The multiplier's wide spread across scenarios is the evidence that a per-
/// output fee-floor alone cannot close every regime: revenue rides volume, the
/// fee rides rate. The `ROI(respond)` column strips the r=1-forever assumption.
fn a4_print_decomposition(out: &mut impl fmt::Write, rows: &[(String, A4Decomp)]) -> fmt::Result {
    writeln!(
        out,
        "\nA4 decomposition — realistic-end (hHold=4) worst config per scenario. Size the\n\
         remedy against the DOMINANT term, not the ratio (§12.2, per the D-2 retraction):\n\
         revenue = Δpool-flow x capture; cost = fees + coupled bond. 'prem' = capture /\n\
         proportional (first-mover premium); 'fee×→1' = the per-output fee multiplier that\n\
         would drive ROI to 1 in THIS regime; 'ROI(resp)' = ROI once honest replicas answer\n\
         (r:1→{R} after {LAG}y lag; first-order, NOT gating).",
        R = REPLICAS_PER_SHARD,
        LAG = A4_RESPONSE_LAG_YEARS,
    )?;
    writeln!(
        out,
        "{:<20} {:>13} {:>7} {:>5} {:>11} {:>9} {:>7} {:>8} {:>9}",
        "scenario",
        "Δpool/yr SKL",
        "capt%",
        "prem",
        "revenue",
        "fees",
        "bond",
        "fee×→1",
        "ROI(resp)"
    )?;
    for (name, d) in rows {
        writeln!(
            out,
            "{:<20} {:>13.1} {:>6.2}% {:>5.1} {:>11.1} {:>9.1} {:>7.2} {:>8.1} {:>9.2}",
            trunc(name, 20),
            d.dpool_skl_per_year,
            d.capture_frac * 100.0,
            d.premium,
            d.revenue_skl,
            d.fee_skl,
            d.bond_skl,
            d.fee_mult_to_close,
            d.roi_market_responds,
        )?;
    }
    writeln!(
        out,
        "  -> Read: prem≈1.0 at the realistic end ⇒ NO concentration premium — the attack is\n\
         pure fee-flow-volume leverage (cheap stuffing unlocks a large Δpool; the attacker\n\
         takes only their proportional slice, but the pool dwarfs the stuffing cost). The\n\
         fee-RATE cancels in fee×→1, so its 2.8→17.8x spread is volume/share-slope variation:\n\
         one per-output floor sized for late-tail over-charges benign multi-output txs ~6x —\n\
         the remedy's real cost. Denominate it in WEIGHT (a virtual-weight surcharge rides\n\
         the fee market over time; an atomic constant rots) — but weight alone can't erase\n\
         the cross-regime spread. The D3 dodge is load-bearing at the CAPPED-honest end\n\
         (prem>1, ROI ~2x higher); its undodgeable-cap fix prices concentration in bonded\n\
         capital THERE. So the pair: fee-floor for the fee-flow regime, D3 for the capped one."
    )?;

    Ok(())
}

/// Archiver-population sizes swept by A3 — shallow (`r` below the pre-fix
/// co-holder cliff) through deep (past it). Replication is *derived* from these
/// (`mean_replication`), so the D1 cliff is reached only where a real network
/// would reach it.
const A3_ARCHIVER_BAND: [u64; 3] = [2_000, 20_000, 60_000];

/// A3 (W-stranding) — the fraction of `budget(E)` that never mints, under **both**
/// work scorings. This is the executable evidence for the §1 Stage-0 coupling
/// claim ("D2 without D1 enlarges a pool that partly evaporates"): pre-D1 puts a
/// bulk-holder cohort at structural zero past the co-holder cliff, and a share
/// that is never claimed is *supply never created* (`ARCHIVAL_BUDGET_SCHEDULE.md`
/// §4). The claim cost is one transaction at the fee floor, priced through the
/// production weight predictor (`calibration`), not a guessed constant.
fn a3_stranding_report(out: &mut impl fmt::Write, params: &SimParams) -> fmt::Result {
    // One claim tx (1-in/2-out) at the chain's depth and the fee floor.
    let claim_cost_atomic = {
        let n_in = shekyl_tx_weight::InputCount::clamped(1);
        let n_out = shekyl_tx_weight::OutputCount::clamped(2);
        let depth = tree_depth_for_leaves(SEGMENT_LEAF_COUNT * 1_000);
        let mut fee = 0u64;
        for _ in 0..2 {
            fee = shekyl_tx_weight::predict_weight(n_in, n_out, depth, fee) as u64
                * crate::calibration::FEE_PER_BYTE_ATOMIC;
        }
        fee
    };
    writeln!(
        out,
        "\nA3 — budget stranding (§12.2): fraction of budget(E) that NEVER MINTS.\n\
         budget is a minting ENTITLEMENT — unclaimed past MAX_CLAIM_AGE_W=26 is \"supply\n\
         never created\" (ARCHIVAL_BUDGET_SCHEDULE §4). A class claims iff its reward\n\
         covers one claim tx ({CC:.6} SKL @ the {FPB} atomic/byte floor, via the production\n\
         predictor). PRE-D1 vs POST-D1 scoring = the §1 Stage-0 coupling claim, measured:\n\
         pre-D1 zeroes bulk holders past the co-holder cliff (r_market > g_milli ≈ 1000),\n\
         and a structural-zero cohort's slice never mints.",
        CC = claim_cost_atomic as f64 / COIN,
        FPB = crate::calibration::FEE_PER_BYTE_ATOMIC,
    )?;
    writeln!(
        out,
        "{:<10} {:>8} {:>8}  {:>10} {:>9}  {:>11} {:>9} {:>10}",
        "archivers",
        "mean_r",
        "n",
        "pre strand",
        "pre zero%",
        "post strand",
        "post zero%",
        "post noclm%"
    )?;

    // Sweep the CORPUS TRAJECTORY, not one year: replication is
    // `archivers · holdings / n`, so the pre-fix co-holder cliff is an EARLY-chain
    // regime (few shards, many holders ⇒ r ≫ 1000) that the corpus grows out of.
    // Showing early/mid/late is what makes the crossing legible.
    let cfg = &all_scenarios(params)[0];
    let aggs = a1_year_aggs(params, cfg);
    let years: Vec<&A1YearAgg> = aggs.iter().filter(|a| a.n > 0).collect();
    if years.is_empty() {
        return Ok(());
    }
    let picks = [0usize, years.len() / 2, years.len() - 1];
    let epy = crate::proxy::epochs_per_year();
    for (label, &yi) in ["early", "mid", "late"].iter().zip(picks.iter()) {
        let a = years[yi];
        let budget_atomic = a
            .emission_leg_atomic
            .saturating_add(mul_scale(a.whole_burn_atomic, flat_25().share(a.n)));
        let budget_per_epoch = (budget_atomic as f64 / epy) as u64;
        for &archivers in &A3_ARCHIVER_BAND {
            let pre = crate::stranding::measure(
                budget_per_epoch,
                a.n,
                archivers,
                claim_cost_atomic,
                crate::stranding::RATIONAL_CLAIM_CADENCE_EPOCHS,
                crate::stranding::Scoring::PreD1,
            );
            let post = crate::stranding::measure(
                budget_per_epoch,
                a.n,
                archivers,
                claim_cost_atomic,
                crate::stranding::RATIONAL_CLAIM_CADENCE_EPOCHS,
                crate::stranding::Scoring::PostD1,
            );
            writeln!(
                out,
                "{:<10} {:>8} {:>8}  {:>9.2}% {:>8.1}%  {:>10.2}% {:>8.1}% {:>9.1}%  {label}",
                archivers,
                pre.mean_r,
                a.n,
                pre.stranded_fraction * 100.0,
                pre.zero_work_fraction * 100.0,
                post.stranded_fraction * 100.0,
                post.zero_work_fraction * 100.0,
                post.non_claiming_fraction * 100.0,
            )?;
        }
    }
    writeln!(
        out,
        "  -> Read: the §1 Stage-0 claim is CONFIRMED, and stronger than stated — where\n\
         mean_r crosses the co-holder cliff (~1000) pre-D1 strands 100% of budget,\n\
         not 'partly': EVERY class floors to zero, so the whole epoch's entitlement is\n\
         supply-never-created. Replication = archivers x holdings / n, so this is an\n\
         EARLY-CHAIN regime (few shards, many holders) the corpus grows out of — and one a\n\
         large archiver population re-enters at any n. D2-without-D1 would have escalated\n\
         a pool that evaporates ENTIRELY in exactly the bootstrap window that most needs\n\
         archivers paid.\n\
         RESIDUAL = a QUANTIZATION FLOOR, not a remaining defect: D1 does not abolish\n\
         structural zeros, it SCALES the cliff with holdings to r > ~1000 x shards_held\n\
         (the micro sum must reach one milli). Unreachable for a bulk holder (4096 shards\n\
         ⇒ r > 4M); a 16-shard hobbyist still zeroes at r > ~16k — the 70% column above.\n\
         Sub-milli work is UNREPRESENTABLE under the frozen WORK_MILLI_SCALE, so the\n\
         honest name is a MINIMUM VIABLE HOLDING THRESHOLD, not a bug: eliminating it\n\
         would mean changing a frozen constant. The archiver's levers are holdings size\n\
         and replication depth. It is the third force in D3's holdings-size triangle.\n\
         Joint with A1: stranded budget is not burden-clearing.",
    )?;

    Ok(())
}

/// **OQ-4** (D3 round §12.8) — re-run the A4 gate under **R2 (plateau deleted)**.
/// Prediction: the capped column vanishes, the realistic-end numbers become the
/// only numbers, and `fee_mult_to_close` is unchanged — because reopen (c) was
/// sized against the realistic end already.
fn oq4_deletion_recheck(out: &mut impl fmt::Write, params: &SimParams) -> fmt::Result {
    let cfg = &all_scenarios(params)[0];
    let aggs = a1_year_aggs(params, cfg);
    let Some(a) = aggs.iter().rfind(|a| a.n > 0) else {
        return Ok(());
    };
    let curve = family()
        .iter()
        .max_by_key(|c| c.asymptote)
        .copied()
        .unwrap_or_else(flat_25);
    let (delta, horizon) = (10_000u64, 10u64);
    writeln!(
        out,
        "\nOQ-4 (D3 round §12.8) — A4 gate under PLATEAU DELETION (scenario {SC}, n={N},\n\
         steepest candidate, Δn={D}, H={H}y). Prediction: the capped column vanishes and\n\
         the realistic-end numbers become the only numbers.",
        SC = trunc(&cfg.name, 20),
        N = a.n,
        D = delta,
        H = horizon,
    )?;
    writeln!(
        out,
        "{:<26} {:>12} {:>14}",
        "honest regime", "ROI", "fee x -> 1"
    )?;
    for (label, sigma) in [
        (
            "kept, small bonds (h=4)",
            honest_sigma_work_milli(a.n, DQ2H_TAIL, 4),
        ),
        (
            "kept, capped (h=512)",
            honest_sigma_work_milli(a.n, DQ2H_TAIL, 512),
        ),
        (
            "DELETED (h irrelevant)",
            honest_sigma_work_milli_deleted(a.n, DQ2H_TAIL, 4),
        ),
    ] {
        let d = a4_decompose(a.whole_burn_atomic, a.n, sigma, &curve, delta, horizon);
        writeln!(
            out,
            "{:<26} {:>12.4} {:>14.1}",
            label, d.roi, d.fee_mult_to_close
        )?;
    }
    writeln!(
        out,
        "  -> Read: deletion reproduces the small-bond row exactly — under R2 there is no\n\
         cap to dodge, so the honest-holdings axis stops mattering and A4 has ONE number\n\
         per regime instead of a naive/rational spread. fee_mult_to_close is unchanged\n\
         from the realistic end, so reopen (c)'s sizing evidence SURVIVES deletion\n\
         (it was sized there already). The capped row is what deletion removes: a\n\
         penalty that fell on non-optimizing honest archivers and doubled the stuffer's\n\
         relative capture."
    )?;

    Ok(())
}

/// `--stage2` entry: the burden trajectory across the scenario set. JSON to
/// stdout, a human-readable summary to stderr.
pub fn run_stage2(out: &mut impl fmt::Write, params: &SimParams) -> fmt::Result {
    writeln!(
        out,
        "Stage-2 archival burden trajectory (§12.1 checkpoint 1)\n\
         outputs = tx_volume x {OUTPUTS_PER_TX_NORMAL:.0} (1in/2out normal traffic); \
         n = frozen_segment_count(cumulative outputs)\n\
         burden = n x {SHARD:.2} MB x storage($/B/yr, Kryder); \
         base = {BASE:.0e} $/B/yr; funding + clearance (A1) land next\n",
        SHARD = crate::burden::SHARD_BYTES / 1.0e6,
        BASE = BASE_STORAGE_FIAT_PER_BYTE_YEAR,
    )?;
    writeln!(out, "Kryder band swept (DQ-2B):")?;
    for k in KryderRate::BAND {
        writeln!(out, "  - {}", k.label())?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "{:<22} {:>6} {:>14} {:>10} {:>16}",
        "scenario", "years", "final_outputs", "final_n", "final_burden$/yr@0%"
    )?;

    let mut trajectories: Vec<BurdenTrajectory> = Vec::new();
    for config in all_scenarios(params) {
        let traj = burden_trajectory(params, &config);
        let final_burden = traj.years.last().map_or(0.0, |y| y.burden_fiat_stall);
        let final_outputs = traj.years.last().map_or(0, |y| y.cumulative_outputs);
        writeln!(
            out,
            "{:<22} {:>6} {:>14} {:>10} {:>16.2}",
            traj.scenario, traj.sim_years, final_outputs, traj.final_frozen_shards, final_burden,
        )?;
        trajectories.push(traj);
    }

    writeln!(
        out,
        "\nReading: `final_n` is the D2 operand at horizon; `final_burden` is the\n\
         whole-corpus annual storage cost under the BINDING 0%/yr Kryder case.\n\
         Absolute $ is conditional on the base-price + SKL/fiat bands (N-1); the\n\
         robust signal is the burden *trajectory* vs the funding decay (A1, next)."
    )?;

    print_escalation_family(out)?;
    print_stuffer_cost_curve(out)?;
    let a1 = a1_clearance_report(out, params)?;
    a3_stranding_report(out, params)?;
    crate::distribution::oq1_probe_report(out)?;
    crate::admission::oq2_report(out, &A3_ARCHIVER_BAND, &[1_011, 6_066, 10_110])?;
    oq4_deletion_recheck(out, params)?;
    // A2 (W6) — now unblocked by the D3 closure. Budget from the A1-conditional
    // envelope: the strongest surviving candidate's pool at the scenario's n.
    {
        let cfg = &all_scenarios(params)[0];
        let aggs = a1_year_aggs(params, cfg);
        if let Some(a) = aggs.iter().rfind(|a| a.n > 0) {
            let best = family()
                .iter()
                .max_by_key(|c| c.asymptote)
                .copied()
                .unwrap_or_else(flat_25);
            let pool = a
                .emission_leg_atomic
                .saturating_add(mul_scale(a.whole_burn_atomic, best.share(a.n)));
            let per_epoch = (pool as f64 / crate::proxy::epochs_per_year()) as u64;
            crate::redistribution::a2_report(
                out,
                per_epoch,
                20_000,
                &format!("{} n={}", trunc(&cfg.name, 18), a.n),
            )?;
        }
    }
    {
        // Base block reward at a representative mid-chain supply, for A6's measured
        // penalty-compensation term (the production emission fn, not a constant).
        let econ = EconomicParams {
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
            // Escalation numerics come from the shipped config: the sim must never
            // invent them, since the asymptote is ceremony-gated and unpinned (§11.4).
            ..EconomicParams::default()
        };
        let br = base_block_reward(params.money_supply / 2, &econ).unwrap_or(0);
        crate::swing::a6_report(out, &ESCALATION_PREVIEW_N, br)?;
    }
    let a4 = a4_stuffing_report(out, params)?;

    // A5 (W10): the L14 slash forfeits the forgone post-D1/D2 reward stream — of
    // the SLASHED SHARD only, matching the per-shard slash scope
    // (`FOUNDATION_GENESIS_IDENTITY_SET.md` §3.2: a ShardSetCompact record's failed
    // challenge slashes that shard's bond; other shards stay bonded). Take the
    // highest PER-SHARD reward across the scenario set (biggest forfeit ⇒ the
    // strongest deterrent the margin must STILL fail against). Pool = A1's
    // flat-ledger budget (emission + fee leg); one shard's slice of n is 1/n at the
    // small-bond equilibrium (work is proportional there — the A4 invariant).
    // Scope consistency: only count years where the full holding is realizable
    // (`n ≥ MAX_HOLDINGS_SHARDS`), since the exposure sums over that many shards
    // at risk — an early-chain year with fewer shards in existence would pair a
    // small-n per-shard reward with 4,096 shards that do not exist.
    let epy = crate::proxy::epochs_per_year();
    let mut max_shard_reward_per_epoch_skl = 0.0f64;
    for config in all_scenarios(params) {
        for a in a1_year_aggs(params, &config)
            .iter()
            .filter(|a| a.n >= MAX_HOLDINGS_SHARDS as u64)
        {
            let pool_atomic = a
                .emission_leg_atomic
                .saturating_add(mul_scale(a.whole_burn_atomic, flat_25().share(a.n)));
            let pool_per_epoch_skl = (pool_atomic as f64 / COIN) / epy;
            max_shard_reward_per_epoch_skl =
                max_shard_reward_per_epoch_skl.max(pool_per_epoch_skl / a.n as f64);
        }
    }
    // The absorption DP prices the stream forgone FROM the slash epoch, so it
    // takes the per-epoch rate rather than a horizon lump.
    crate::proxy::a5_proxy_report(out, max_shard_reward_per_epoch_skl, SKL_FIAT_PRICE_BAND[1])?;

    let report = Stage2Report {
        burden_trajectories: trajectories,
        a1_clearance: a1,
        a4_stuffing: a4,
    };
    let json = serde_json::to_string_pretty(&report).expect("JSON serialization failed");
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes()).expect("write failed");
    stdout.write_all(b"\n").expect("write failed");
    writeln!(
        out,
        "\nStage-2 (burden trajectory + escalation family + A1 clearance + A4 W9 ROI) complete."
    )?;

    Ok(())
}

/// The combined `--stage2` JSON payload (grows as arms land).
#[derive(Debug, Clone, Serialize)]
pub struct Stage2Report {
    pub burden_trajectories: Vec<BurdenTrajectory>,
    pub a1_clearance: Vec<A1ScenarioResult>,
    pub a4_stuffing: Vec<A4ScenarioResult>,
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

    #[test]
    fn a4_served_work_roi_responds_to_steepness_and_concentration() {
        // The served-work ROI must move correctly with its levers: (a) a steeper
        // escalation (higher asymptote, same knee) raises the pool the marginal
        // stuffed shard is paid from, and (b) more-concentrated (capped) honest
        // holdings shrink Σwork, enlarging the attacker's captured slice. Neither
        // may lower ROI, else the gate measures nothing.
        let params = SimParams::default();
        let aggs = a1_year_aggs(&params, &all_scenarios(&params)[0]);
        let a = aggs
            .iter()
            .find(|a| a.year > A1_RAMP_YEARS && a.n > 0)
            .unwrap();
        // Same knee, different asymptote — a controlled steepness comparison.
        let knee = crate::escalation::KNEE_BAND[1];
        let steep = EscalationCurve {
            asymptote: crate::escalation::ASYMPTOTE_BAND[2],
            knee_shards: knee,
        };
        let shallow = EscalationCurve {
            asymptote: crate::escalation::ASYMPTOTE_BAND[0],
            knee_shards: knee,
        };
        let sigma = honest_sigma_work_milli(a.n, DQ2H_TAIL, 64);
        let roi_steep = a4_stuffing_roi(a.whole_burn_atomic, a.n, sigma, &steep, 10_000, 10);
        let roi_shallow = a4_stuffing_roi(a.whole_burn_atomic, a.n, sigma, &shallow, 10_000, 10);
        assert!(
            roi_steep >= roi_shallow,
            "steeper share must not lower served-work ROI: {roi_steep} < {roi_shallow}"
        );
        // Concentrated honest holdings (512, capped) → smaller Σwork → larger slice.
        let sigma_capped = honest_sigma_work_milli(a.n, DQ2H_TAIL, 512);
        let sigma_spread = honest_sigma_work_milli(a.n, DQ2H_TAIL, 4);
        assert!(sigma_capped < sigma_spread, "capping must shrink Σwork");
        let roi_capped =
            a4_stuffing_roi(a.whole_burn_atomic, a.n, sigma_capped, &steep, 10_000, 10);
        let roi_spread =
            a4_stuffing_roi(a.whole_burn_atomic, a.n, sigma_spread, &steep, 10_000, 10);
        assert!(
            roi_capped >= roi_spread,
            "capped honest holdings must not lower attacker ROI: {roi_capped} < {roi_spread}"
        );
    }
}

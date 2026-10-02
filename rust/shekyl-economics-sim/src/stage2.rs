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
    calc_effective_emission_share, effective_emission,
    params::{EconomicParams, SCALE},
    split_block_emission, ScaledShare, TxVolume,
};

use crate::burden::{
    bond_opp_cost_skl, burden_cost_fiat_per_year, closed_shards, normal_tx_archival_bytes,
    KryderRate, BASE_STORAGE_FIAT_PER_BYTE_YEAR, OPP_COST_RATE_BAND, OUTPUTS_PER_TX_NORMAL,
    REPLICAS_PER_SHARD, SHARD_BYTES, SKL_FIAT_PRICE_BAND,
};
use crate::calibration::{
    rucknium_shards_equivalent, stuffer_campaign, stuffer_cost_per_shard_atomic, stuffer_shape,
    stuffer_txs_per_shard, sustained_stuffer_cost_per_shard_atomic, tree_depth_for_leaves,
    RUCKNIUM_DURATION_DAYS, RUCKNIUM_SPAM_BYTES_GB, RUCKNIUM_SPAM_FEES_XMR,
};
use crate::engine::{ScenarioConfig, SimParams};
use crate::escalation::{family, flat_25, EscalationCurve, KNEE_ARCHIVAL_LEN_BYTES, KNEE_BAND};
use crate::fee_model::FeePoint;
use crate::population::{
    attacker_capped_work_milli, honest_sigma_work_milli, honest_sigma_work_milli_deleted, DQ2H_TAIL,
};
use crate::scenarios::all_scenarios;
use shekyl_archival_retention::{
    reward_share_floor, ARCHIVAL_BOND_FLOOR_ATOMIC, MAX_HOLDINGS_SHARDS,
};

/// Atomic units per SKL (mirrors `engine.rs`).
const COIN: f64 = 1_000_000_000.0;

/// Ramp years excluded from the A1 clearance verdict: the first two years, where
/// the corpus is tiny and any share trivially "clears". Clearance is judged on
/// the sustained trajectory.
const A1_RAMP_YEARS: u64 = 2;

/// Closed-shard sample points for the escalation-candidate preview, spanning
/// the [`KNEE_BAND`] — derived from it, so the preview follows a re-derivation.
const ESCALATION_PREVIEW_N: [u64; 5] = [
    0,
    KNEE_BAND[0] / 5,
    KNEE_BAND[0],
    KNEE_BAND[1],
    KNEE_BAND[2],
];

/// The honest chain's leaf count at the top of the knee band — the "deep"
/// end of every shallow..deep range the reports quote.
fn deep_chain_leaves() -> u64 {
    crate::burden::honest_leaves_at_closed_shards(KNEE_BAND[2])
}

/// One sampled year of a scenario's burden trajectory. Storage cost is reported
/// across the full DQ-2B Kryder band at the base price; the `SKL/fiat`
/// conversion is an arm concern (the burden is fiat-denominated here).
#[derive(Debug, Clone, Serialize)]
pub struct BurdenYearRow {
    pub year: u64,
    /// Cumulative outputs (leaves) at the end of this year — drives the
    /// curve-tree depth, and so each transaction's archival length.
    pub cumulative_outputs: u64,
    /// Cumulative archival length at the end of this year (bytes) — what the
    /// partition folds.
    pub cumulative_archival_bytes: u64,
    /// Closed shards — the D2 operand `n` (`shard_of` of the bytes above).
    pub closed_shards: u64,
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
    pub final_closed_shards: u64,
    pub years: Vec<BurdenYearRow>,
}

/// The honest fold, one block: `txs` normal-shape transactions add
/// `txs · OUTPUTS_PER_TX_NORMAL` leaves and `txs · archival_len(depth)` bytes,
/// where the depth is the curve tree's at the block's start. The two
/// accumulators are what `shard_of` and `tree_depth_for_leaves` consume.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HonestFold {
    /// f64 so a fractional outputs-per-tx never rounds per block; floored to
    /// u64 only where a consumer needs an integer.
    cumulative_outputs: f64,
    cumulative_archival_bytes: u64,
}

impl HonestFold {
    pub(crate) fn add_block(&mut self, txs: u64) {
        let per_tx = normal_tx_archival_bytes(self.cumulative_outputs as u64);
        self.cumulative_archival_bytes = self
            .cumulative_archival_bytes
            .saturating_add(txs.saturating_mul(per_tx));
        self.cumulative_outputs += txs as f64 * OUTPUTS_PER_TX_NORMAL;
    }

    /// Outputs in the curve tree at this point of the fold — what sets the
    /// proof size, and so an ordinary transaction's weight and fee.
    pub(crate) fn leaves(&self) -> u64 {
        self.cumulative_outputs as u64
    }

    /// The D2 operand at this point of the fold — the partition, not a
    /// re-derivation.
    fn closed_shards(&self) -> u64 {
        closed_shards(self.cumulative_archival_bytes)
    }
}

/// Simulate a scenario's honest burden: fold outputs and archival bytes
/// ([`HonestFold`]), sample `closed_shards` and the Kryder-band burden cost at
/// each year boundary.
///
/// The Kryder decline runs over **elapsed years** (the base scenarios start at
/// genesis, `genesis_height_offset == 0`); scenario 9's pre-existing history is
/// handled where it lands.
#[must_use]
pub fn burden_trajectory(params: &SimParams, config: &ScenarioConfig) -> BurdenTrajectory {
    let total_blocks = params.blocks_per_year * config.sim_years;
    let mut fold = HonestFold::default();
    let mut years: Vec<BurdenYearRow> = Vec::with_capacity(config.sim_years as usize);

    for block in 0..total_blocks {
        let txs = (config.volume.get_volume)(block, params.blocks_per_year);
        fold.add_block(txs);

        if (block + 1) % params.blocks_per_year == 0 {
            let year = (block + 1) / params.blocks_per_year; // 1-indexed
            let shards = fold.closed_shards();
            let year_f = year as f64;
            years.push(BurdenYearRow {
                year,
                cumulative_outputs: fold.cumulative_outputs as u64,
                cumulative_archival_bytes: fold.cumulative_archival_bytes,
                closed_shards: shards,
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

    let final_closed_shards = years.last().map_or(0, |y| y.closed_shards);
    BurdenTrajectory {
        scenario: config.name.clone(),
        description: config.description.clone(),
        sim_years: config.sim_years,
        final_closed_shards,
        years,
    }
}

/// One year's funding + burden inputs for A1, computed once per scenario on the
/// **flat-ledger** trajectory (shipped 25% split), independent of the escalation
/// candidate. The candidate is applied downstream only to the fee leg
/// (`year_share_atomic(whole_burn_atomic, share_milli(n))`); the second-order ledger feedback from
/// redistributing the burn (`actually_destroyed` shifts `circulating`, nudging
/// future `burn_pct`/emission) is deliberately not modeled here — it is small
/// against the first-order clearance question, and a full-feedback refinement
/// can follow if a verdict sits on the margin.
#[derive(Debug, Clone, Serialize)]
pub struct A1YearAgg {
    pub year: u64,
    /// Closed shards at year end (the D2 operand `n`).
    pub n: u64,
    /// Cumulative outputs (leaves) at year end — the curve-tree depth any
    /// transaction priced in this year is proved at (A3's claim, A4's stuffer).
    pub cumulative_outputs: u64,
    /// Staker emission leg accrued over the year, **atomic units** (integer —
    /// the DQ-2G algorithm zone; SKL/f64 conversion is deferred to the reported
    /// clearance ratio). Sum of the production `split_block_emission` staker leg.
    ///
    /// The four annual sums are `u128`, not the chain's `u64`: a *year* of
    /// fees is not a chain quantity, and under the growth schedule run to 60 y
    /// (`onset.rs`) it passes `u64::MAX` from ≈ year 52. A `u64` here would
    /// have to clip, and a clipped aggregate fails silently — it stays
    /// valid-looking while the ratio it feeds goes wrong.
    pub emission_leg_atomic: u128,
    /// Whole fee burn over the year (pre-share), **atomic units**. The fee leg
    /// is [`year_share_atomic`]`(this, share_milli(n))` — production's
    /// `mul_scale` floor on the year aggregate, never an f64 `× share_fraction`.
    pub whole_burn_atomic: u128,
    /// All fees paid over the year (pre-burn), **atomic units**: the ceiling of
    /// every share-of-fees lever, miner income included. `whole_burn` is the
    /// `burn_pct` fraction of this; the `√V` damper in `calc_burn_pct` is the
    /// gap between the two (`onset.rs`).
    pub whole_fees_atomic: u128,
    /// All block emission over the year (miner + staker, pre-split), **atomic
    /// units** — the operand a non-decaying staker floor would be a share of
    /// (`onset.rs`). `emission_leg` is the shipped decaying split of this.
    pub total_emission_atomic: u128,
}

/// A fixed-point `SCALE` share of a **year aggregate**: `floor(pool × share /
/// SCALE)`, the same floor production's `mul_scale` takes per block
/// (`compute_burn_split`), on the `u128` the year sums to. This exists only
/// because `mul_scale` is `u64 → u64` and a year of fees is not (see
/// [`A1YearAgg`]); for any `pool ≤ u64::MAX` it equals `mul_scale` exactly
/// (pinned in `year_share_matches_mul_scale_in_u64_range`). Every share of a
/// year aggregate goes through here — the sim never writes `× share` itself.
#[must_use]
pub fn year_share_atomic(pool_atomic: u128, share_milli: u64) -> u128 {
    pool_atomic * u128::from(share_milli) / u128::from(SCALE)
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
        emission_curve_asymptote: params.emission_curve_asymptote,
        emission_speed_factor_per_minute: params.emission_speed_factor_per_minute,
        final_subsidy_per_minute: params.final_subsidy_per_minute,
        daa_target_seconds: EconomicParams::default().daa_target_seconds,
        // Escalation numerics come from the shipped config: the sim must never
        // invent them, since the asymptote is ceremony-gated and unpinned (§11.4).
        ..EconomicParams::default()
    };
    let total_blocks = params.blocks_per_year * config.sim_years;
    let mut already_generated: u128 =
        (config.initial_emitted_fraction * params.emission_curve_asymptote as f64) as u128;
    let mut total_burned: u128 = 0;
    let mut fold = HonestFold::default();
    // Integer atomic accumulators (DQ-2G: the budget quantities never touch f64).
    let mut year_emission_atomic: u128 = 0;
    let mut year_burn_atomic: u128 = 0;
    let mut year_fees_atomic: u128 = 0;
    let mut year_total_emission_atomic: u128 = 0;
    let mut aggs = Vec::with_capacity(config.sim_years as usize);

    for block in 0..total_blocks {
        let abs_height = block + config.genesis_height_offset;
        let ag = already_generated.min(u128::from(u64::MAX)) as u64;
        let tx_volume = (config.volume.get_volume)(block, params.blocks_per_year);
        fold.add_block(tx_volume);

        let effective =
            effective_emission(ag, TxVolume::per_block(tx_volume), &economic).unwrap_or(0);

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
            TxVolume::per_block(tx_volume),
            params.tx_volume_baseline,
            circulating,
            params.emission_curve_asymptote,
            params.burn_base_rate,
            params.burn_cap,
        );
        let fee_per_tx = config.fee.per_tx_atomic(&FeePoint {
            already_generated: ag,
            volume: TxVolume::per_block(tx_volume),
            sigma_scaled: emission_share,
            burn_pct_scaled: burn_pct,
            chain_leaves: fold.leaves(),
            params: &economic,
        });
        let total_fees =
            (u128::from(tx_volume) * u128::from(fee_per_tx)).min(u128::from(u64::MAX)) as u64;
        // share = SCALE → the whole burn (pre-split); the candidate re-splits it.
        let whole_burn = compute_burn_split(total_fees, burn_pct, ScaledShare::from_raw(SCALE))
            .staker_pool_amount;
        // Flat-ledger advance: destroy at the shipped 25% split.
        let flat = compute_burn_split(
            total_fees,
            burn_pct,
            ScaledShare::from_raw(params.staker_pool_share),
        );

        year_emission_atomic += u128::from(staker_emission);
        year_burn_atomic += u128::from(whole_burn);
        year_fees_atomic += u128::from(total_fees);
        year_total_emission_atomic += u128::from(effective);
        already_generated += u128::from(effective);
        total_burned += u128::from(flat.actually_destroyed);

        if (block + 1) % params.blocks_per_year == 0 {
            let year = (block + 1) / params.blocks_per_year;
            aggs.push(A1YearAgg {
                year,
                n: fold.closed_shards(),
                cumulative_outputs: fold.cumulative_outputs as u64,
                emission_leg_atomic: year_emission_atomic,
                whole_burn_atomic: year_burn_atomic,
                whole_fees_atomic: year_fees_atomic,
                total_emission_atomic: year_total_emission_atomic,
            });
            year_emission_atomic = 0;
            year_burn_atomic = 0;
            year_fees_atomic = 0;
            year_total_emission_atomic = 0;
        }
    }
    aggs
}

/// The **minimum** clearance ratio `budget_skl / burden_skl` across the
/// sustained years (past the ramp) for a candidate, at a given opportunity-cost
/// rate. `≥ 1` ⇒ the candidate keeps the staker whole every sustained year.
///
/// **Algorithm zone is integer** (DQ-2G): `budget_atomic = emission_leg +
/// year_share_atomic(whole_burn, share_milli(n))` — the escalation share is
/// the floor production's `mul_scale` takes (`compute_burn_split`), never an
/// f64 `× share_fraction`. Burden (F-G) is the integer locked-bond opportunity cost
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
    a1_sustained_years(aggs)
        .map(|a| {
            a1_year_clearance_ratio(
                a,
                a1_shipped_budget_atomic(a, candidate),
                opp_cost_rate,
                fiat_per_skl,
                kryder,
            )
        })
        .fold(f64::INFINITY, f64::min)
}

/// The years A1 judges: past the ramp, with a non-empty corpus.
pub fn a1_sustained_years(aggs: &[A1YearAgg]) -> impl Iterator<Item = &A1YearAgg> {
    aggs.iter().filter(|a| a.year > A1_RAMP_YEARS && a.n > 0)
}

/// The shipped budget for one year under a candidate, **atomic**: the decaying
/// staker emission leg plus the candidate's share of the fee **burn** — the
/// escalation share taken with production's floor ([`year_share_atomic`]),
/// never an f64 `× share_fraction`. The one home for the shipped budget: A1,
/// A2, A3 and `onset.rs`'s shipped lever all call it; `onset.rs` builds the
/// alternative budgets (share of fees, a tail floor) beside it.
#[must_use]
pub fn a1_shipped_budget_atomic(a: &A1YearAgg, candidate: &EscalationCurve) -> u128 {
    a.emission_leg_atomic + year_share_atomic(a.whole_burn_atomic, candidate.share(a.n))
}

/// One year's clearance ratio `budget_skl / burden_skl` for an already-formed
/// budget. Burden (F-G) is the integer locked-bond opportunity cost (principal
/// atomic; the exogenous rate is the single float boundary) plus the minor fiat
/// storage term; f64 appears only in the returned ratio and at the two named
/// exogenous boundaries (rate, `SKL/fiat` price). The one home for the ratio:
/// the A1 min and the per-year onset table both fold over it.
#[must_use]
pub fn a1_year_clearance_ratio(
    a: &A1YearAgg,
    budget_atomic: u128,
    opp_cost_rate: f64,
    fiat_per_skl: f64,
    kryder: KryderRate,
) -> f64 {
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
    /// The replica count the budget would sustain at each rate — the
    /// un-binarised form of the ratio. Both burden terms are linear in
    /// [`REPLICAS_PER_SHARD`] (`locked_bond_atomic` and the storage term), so
    /// `ratio(R) = ratio(R_0) · R_0 / R` exactly and this is
    /// `REPLICAS_PER_SHARD · min_ratio`. `R = 6` is a leaf-era replication
    /// constant carried as an input; the ceremony reads "clears at R = 2"
    /// here rather than a binary fail at that constant.
    pub replicas_sustained_by_rate: Vec<f64>,
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
    let min_ratio_by_rate: Vec<f64> = OPP_COST_RATE_BAND
        .iter()
        .map(|&rate| a1_min_clearance_ratio(aggs, curve, rate, mid_price, KryderRate::Stall))
        .collect();
    let replicas_sustained_by_rate = min_ratio_by_rate
        .iter()
        .map(|r| r * REPLICAS_PER_SHARD as f64)
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
        replicas_sustained_by_rate,
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
         Storage is a minor add-on (F-G: ~100x smaller); the binding term is PRICE-INDEPENDENT (SKL vs SKL).\n\
         Knee band {BAND:?} closed shards; the shipped middle is {KNEE_TB:.2} TB of archival at W = {W} B/shard.",
        R = REPLICAS_PER_SHARD,
        RATES = OPP_COST_RATE_BAND,
        BAND = KNEE_BAND,
        KNEE_TB = KNEE_ARCHIVAL_LEN_BYTES as f64 / 1e12,
        W = shekyl_types::SHARD_LENGTH.to_raw(),
    )?;
    writeln!(
        out,
        "{:<20} {:>12}   {:>24}   {:>24}   {:>17}",
        "scenario", "best-cand", "flat-25 ratio @rate", "best-cand ratio @rate", "R sustained @10%"
    )?;
    writeln!(
        out,
        "{:<20} {:>12}   {:>24}   {:>24}   {:>8} {:>8}",
        "", "", "", "", "flat", "best"
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
            "{:<20} {:>12}   {:>7.2} {:>7.2} {:>7.2}   {:>7.2} {:>7.2} {:>7.2}   {:>8.2} {:>8.2}",
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
            flat25.replicas_sustained_by_rate[binding],
            best.replicas_sustained_by_rate[binding],
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
         earning its keep. A4/A5 then drop any winner that fails W9/W10.\n\
         'R sustained' = R{R} x ratio: the replica count the budget would carry at\n\
         10% (both burden terms are linear in R), so a fail reads as a number.\n\
         The 10%/yr binding rate is EXOGENOUS: SKL bonded for decades in a settled\n\
         chain at ~{tx} tx/block is where that assumption is strongest and least\n\
         grounded; the band is kept, the choice of binding member is the owner's.",
        OPP_COST_RATE_BAND,
        R = REPLICAS_PER_SHARD,
        tx = crate::scenarios::SCENARIO_9_TAIL_TX_PER_BLOCK,
    )?;
    // Verdict, computed: which scenarios no candidate clears at the binding
    // rate, and which are the D2 case proper (best clears, flat does not).
    let binding = OPP_COST_RATE_BAND.len() - 1;
    let uncleared: Vec<&str> = results
        .iter()
        .filter(|r| {
            r.candidates
                .iter()
                .all(|c| c.min_ratio_by_rate[binding] < 1.0)
        })
        .map(|r| r.scenario.as_str())
        .collect();
    let d2_case: Vec<&str> = results
        .iter()
        .filter(|r| {
            r.flat25.min_ratio_by_rate[binding] < 1.0
                && r.candidates
                    .iter()
                    .any(|c| c.min_ratio_by_rate[binding] >= 1.0)
        })
        .map(|r| r.scenario.as_str())
        .collect();
    writeln!(
        out,
        "  -> VERDICT @10%: D2 case (best clears, flat does not): {d2}; cleared by NO\n\
         candidate in the band: {un}. Byte-keyed, n counts ~10 KB of archival per\n\
         transaction, not one 128-B leaf per output, so the §6.2 coupled bond per unit\n\
         of traffic is ~40x the leaf-era figure — a scenario the leaf-era sweep cleared\n\
         can fail here on the bond term alone, with no change to the escalation.",
        d2 = if d2_case.is_empty() {
            "none".to_string()
        } else {
            d2_case.join(", ")
        },
        un = if uncleared.is_empty() {
            "none".to_string()
        } else {
            uncleared.join(", ")
        },
    )?;
    if d2_case.is_empty() {
        writeln!(
            out,
            "  -> NO DISCRIMINATING SCENARIO AT THIS HORIZON: across the whole set, every\n\
             scenario either clears flat or clears for no candidate — within its own\n\
             sim_years the escalation does no work the flat share does not. That is a\n\
             statement about the horizon, not the lever: A1-T below runs the same\n\
             scenarios to 60 y, where the staker emission leg has decayed under the bond\n\
             burden and the region (flat fails, best clears) opens at the low rates\n\
             (ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md §12.13–§12.14)."
        )?;
    }
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
/// each `(asymptote, knee)` candidate produces across a span of closed-shard
/// counts. Shows the shapes A1 will measure for clearance; the flat 25% status
/// quo is the first column's `n = 0` value (all candidates floor there).
fn print_escalation_family(out: &mut impl fmt::Write) -> fmt::Result {
    writeln!(
        out,
        "\nEscalation candidate family (§6.1 / DQ-2D) — staker share % vs n = closed shards:\n\
         (floor 25% at n=0, saturates to asymptote at the knee; all asymptotes < 100%)"
    )?;
    write!(out, "{:>8} {:>9}", "asympt%", "knee")?;
    for n in ESCALATION_PREVIEW_N {
        write!(out, "  n={n:>9}")?;
    }
    writeln!(out)?;
    // Status-quo baseline: the flat 25% share every candidate is measured
    // against in A1 (does escalation clear where the flat share does not?).
    write!(out, "{:>8} {:>9}", "FLAT", "-")?;
    for n in ESCALATION_PREVIEW_N {
        write!(out, "  {:>11.1}", flat_25().share_fraction(n) * 100.0)?;
    }
    writeln!(out)?;
    for c in family() {
        write!(
            out,
            "{:>8.0} {:>9}",
            c.asymptote as f64 / 10_000.0,
            c.knee_shards
        )?;
        for n in ESCALATION_PREVIEW_N {
            write!(out, "  {:>11.1}", c.share_fraction(n) * 100.0)?;
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

/// A4 (W9) **cost side** — the stuffer's cost to close one more shard (`W`
/// archival bytes), across chain depth (§12.2, DQ-2C). The *revenue* side and
/// the ROI < 1 gate follow; this establishes the price of a stuffed shard,
/// single-sourced through the production weight + archival-length predictors
/// (`calibration.rs`), and the Monero-replication row (the March-2024 anchor
/// as shards' worth of bytes).
///
/// `n` is sampled as **closed shards**; the curve-tree depth (hence FCMP proof
/// size) rides the honest chain's leaf count at `n`. Byte-keyed, the proof is
/// archival good the stuffer is *buying*, so depth moves only the
/// archival/weight ratio, and only by a few percent (measured 2026-10-01:
/// one-shot +1.3 %, sustained −2.6 %, depth 1 → 6). The leaf era's "cheapest
/// early" was a lever; here it is noise. The binding figure is the minimum
/// over the sampled depths, which this table makes visible.
fn print_stuffer_cost_curve(out: &mut impl fmt::Write) -> fmt::Result {
    let rep = rucknium_shards_equivalent();
    let shape0 = stuffer_shape(tree_depth_for_leaves(1));
    writeln!(
        out,
        "\nA4 (W9) stuffer cost — max-archival-bytes-per-fee shape ({SHAPE}, searched over every\n\
         builder-legal shape), min weight-fee @ {FPB} atomic/byte, W = {W:.1} MB/shard:\n\
         Monero-replication anchor (DQ-2C): the March-2024 spam bought ~{GB:.2} GB / {DAYS} days\n\
         for ~{XMR:.1} XMR — that byte volume is ~{REP} Shekyl shards' worth of archival good.\n\
         Shape is max-archival-per-fee geometry (inputs carry the PQC auth + FCMP share the\n\
         operand counts; outputs carry unprunable prefix it does not), NOT decoy poisoning\n\
         (FCMP++ has no rings). 'sustained' prices the cheapest output-conserving\n\
         producer/consumer cycle — what a campaign that must mint its own inputs pays.",
        SHAPE = shape0.label(),
        FPB = crate::calibration::FEE_PER_BYTE_ATOMIC,
        W = SHARD_BYTES / 1.0e6,
        GB = RUCKNIUM_SPAM_BYTES_GB,
        DAYS = RUCKNIUM_DURATION_DAYS,
        XMR = RUCKNIUM_SPAM_FEES_XMR,
        REP = rep,
    )?;
    writeln!(
        out,
        "{:<15} {:>5} {:>12} {:>14} {:>9} {:>18} {:>20}",
        "chain n(shards)",
        "depth",
        "shape",
        "fee/tx (SKL)",
        "tx/shard",
        "cost/shard (SKL)",
        "sustained (SKL)"
    )?;
    for n_shards in ESCALATION_PREVIEW_N {
        // n=0 has no tree; sample the first shard so the depth/cost are defined.
        let n_shards = n_shards.max(1);
        let chain_leaves = crate::burden::honest_leaves_at_closed_shards(n_shards);
        let depth = tree_depth_for_leaves(chain_leaves);
        let shape = stuffer_shape(depth);
        let fee_tx_skl = shape.tx_fee_atomic(depth) as f64 / COIN;
        let txs = stuffer_txs_per_shard(depth);
        let cost_shard_skl = stuffer_cost_per_shard_atomic(chain_leaves) as f64 / COIN;
        let sustained_skl = sustained_stuffer_cost_per_shard_atomic(chain_leaves) as f64 / COIN;
        writeln!(
            out,
            "{n_shards:<15} {depth:>5} {:>12} {fee_tx_skl:>14.6} {txs:>9} {cost_shard_skl:>18.4} {sustained_skl:>20.4}",
            shape.label(),
        )?;
    }
    writeln!(
        out,
        "  -> cost/shard is depth-FLAT to within a few percent (the FCMP proof grows with\n\
         depth, but it is archival good the stuffer is buying, so only the archival/weight\n\
         ratio moves): one-shot drifts UP ~1%, sustained DOWN ~3%. The leaf era's\n\
         'cheapest early' is gone with its unit. The A4 ROI gate below weighs the one-shot\n\
         (binding, attacker-favouring) cost against the escalation Delta-pool a stuffing\n\
         staker captures: a survivor of A1 must ALSO price the stuffer out."
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
    whole_burn_atomic: u128,
    n: u64,
    sigma_honest_milli: u64,
    candidate: &EscalationCurve,
    delta: u64,
    horizon_years: u64,
) -> A4Decomp {
    let n2 = n.saturating_add(delta);
    // The share-manipulation Δpool on the honest burn — production's floor on
    // the year aggregate. Only the fee leg is share-gated, so the emission leg
    // cancels in the delta. `reward_share_floor` is the production per-epoch
    // op and takes the chain's `u64`; a year's Δpool fits it in every A4 run
    // (A4 runs at the scenarios' own horizons), and the conversion is loud
    // rather than clipping if a schedule ever moves that.
    let dpool_atomic = year_share_atomic(whole_burn_atomic, candidate.share(n2))
        .saturating_sub(year_share_atomic(whole_burn_atomic, candidate.share(n)));
    let dpool_atomic = u64::try_from(dpool_atomic)
        .expect("a year's share-manipulation Δpool fits the chain's u64 budget operand");
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
    // The stuffer is priced against the tree the honest chain has at `n`,
    // each transaction at the depth the tree has when it is built — the
    // campaign's own outputs can carry it across a layer boundary, and the
    // integrator prices the two sides at their own depths. One-shot cost —
    // the binding figure — with the transaction count rounded once.
    let fee_skl = stuffer_campaign(crate::burden::honest_leaves_at_closed_shards(n), delta)
        .cost_atomic as f64
        / COIN;
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
    whole_burn_atomic: u128,
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
    let (mult_lo, mult_hi) = rows
        .iter()
        .map(|(_, d)| d.fee_mult_to_close)
        .filter(|m| m.is_finite())
        .fold((f64::INFINITY, 0.0_f64), |(lo, hi), m| {
            (lo.min(m), hi.max(m))
        });
    writeln!(
        out,
        "  -> Read: prem≈1.0 at the realistic end ⇒ NO concentration premium — the attack is\n\
         pure fee-flow-volume leverage (cheap stuffing unlocks a large Δpool; the attacker\n\
         takes only their proportional slice, but the pool dwarfs the stuffing cost). The\n\
         fee-RATE cancels in fee×→1, so its {mult_lo:.1}→{mult_hi:.1}x spread is volume/share-slope\n\
         variation: one fee-floor sized for the worst regime over-charges benign traffic\n\
         ~{OVER:.0}x in the mildest — the remedy's real cost. Denominate it in WEIGHT (a\n\
         virtual-weight surcharge rides the fee market over time; an atomic constant rots)\n\
         — but weight alone can't erase the cross-regime spread. The D3 dodge is load-bearing\n\
         at the CAPPED-honest end (prem>1, ROI several x higher); its undodgeable-cap fix\n\
         prices concentration in bonded capital THERE. So the pair: fee-floor for the\n\
         fee-flow regime, D3 for the capped one.",
        OVER = mult_hi / mult_lo,
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
    // One claim tx (the normal 1-in/2-out shape) at the fee floor, priced at
    // the curve-tree depth of the year it is claimed in (the proof grows with
    // the chain, so the claim gets dearer late).
    let claim_cost_atomic = |chain_leaves: u64| -> u64 {
        let (n_in, n_out) = crate::burden::normal_tx_shape();
        crate::calibration::Shape { n_in, n_out }.tx_fee_atomic(tree_depth_for_leaves(chain_leaves))
    };
    writeln!(
        out,
        "\nA3 — budget stranding (§12.2): fraction of budget(E) that NEVER MINTS.\n\
         budget is a minting ENTITLEMENT — unclaimed past MAX_CLAIM_AGE_W=26 is \"supply\n\
         never created\" (ARCHIVAL_BUDGET_SCHEDULE §4). A class claims iff its reward\n\
         covers one claim tx ({CC0:.6}..{CC1:.6} SKL early..late @ the {FPB} atomic/byte\n\
         floor, via the production predictor at each year's tree depth). PRE-D1 vs\n\
         POST-D1 scoring = the §1 Stage-0 coupling claim, measured: pre-D1 zeroes bulk\n\
         holders past the co-holder cliff (r_market > g_milli ≈ 1000), and a\n\
         structural-zero cohort's slice never mints.",
        CC0 = claim_cost_atomic(1) as f64 / COIN,
        CC1 = claim_cost_atomic(deep_chain_leaves()) as f64 / COIN,
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
        let budget_atomic = a1_shipped_budget_atomic(a, &flat_25());
        let budget_per_epoch = (budget_atomic as f64 / epy) as u64;
        let claim_cost = claim_cost_atomic(a.cumulative_outputs);
        for &archivers in &A3_ARCHIVER_BAND {
            let pre = crate::stranding::measure(
                budget_per_epoch,
                a.n,
                archivers,
                claim_cost,
                crate::stranding::RATIONAL_CLAIM_CADENCE_EPOCHS,
                crate::stranding::Scoring::PreD1,
            );
            let post = crate::stranding::measure(
                budget_per_epoch,
                a.n,
                archivers,
                claim_cost,
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

/// Per-shard post-D1/D2 reward per epoch across the scenario family.
///
/// Pool = A1's flat-ledger budget (emission + fee leg); one shard's slice is
/// `1/n` at the small-bond equilibrium (work is proportional there — the A4
/// invariant). Scope: only years where the full holding is realizable
/// (`n ≥ MAX_HOLDINGS_SHARDS`), since A5 exposure sums over that many shards —
/// an early-chain year with fewer shards would pair a small-n per-shard reward
/// with 4 096 shards that do not exist.
///
/// Operand direction differs by arm:
/// - **A5** takes [`Self::max_per_epoch_skl`] (larger forfeit ⇒ stronger
///   deterrent ⇒ conservative).
/// - **TJ-4 / TJ-7** take median + max (larger flow ⇒ more profitable attack ⇒
///   max is alarm-raising; median is the representative cell).
#[derive(Debug, Clone, Copy)]
struct ShardRewardOperands {
    median_per_epoch_skl: f64,
    max_per_epoch_skl: f64,
}

fn shard_reward_operands(params: &SimParams) -> ShardRewardOperands {
    let epy = crate::proxy::epochs_per_year();
    let mut rewards: Vec<f64> = Vec::new();
    let mut max_per_epoch_skl = 0.0_f64;
    for config in all_scenarios(params) {
        for a in a1_year_aggs(params, &config)
            .iter()
            .filter(|a| a.n >= MAX_HOLDINGS_SHARDS as u64)
        {
            let pool_atomic = a1_shipped_budget_atomic(a, &flat_25());
            let pool_per_epoch_skl = (pool_atomic as f64 / COIN) / epy;
            let per_shard = pool_per_epoch_skl / a.n as f64;
            rewards.push(per_shard);
            max_per_epoch_skl = max_per_epoch_skl.max(per_shard);
        }
    }
    rewards.sort_by(|a, b| a.partial_cmp(b).expect("finite rewards"));
    let median_per_epoch_skl = statistical_median(&rewards);
    ShardRewardOperands {
        median_per_epoch_skl,
        max_per_epoch_skl,
    }
}

/// Statistical median of a sorted non-empty slice: middle element for odd
/// length, mean of the two central elements for even. Empty → 0 (no qualifying
/// cells — A5/TJ arms then report a zero operand rather than panicking).
fn statistical_median(sorted: &[f64]) -> f64 {
    match sorted.len() {
        0 => 0.0,
        n if n % 2 == 1 => sorted[n / 2],
        n => 0.5 * (sorted[n / 2 - 1] + sorted[n / 2]),
    }
}

/// A trajectory's `n` at its first, middle and last sampled year — the
/// early / mid / late corpus the OQ-2 admission probe is run against.
#[must_use]
fn oq2_corpus_samples(traj: &BurdenTrajectory) -> [u64; 3] {
    let n_at = |i: usize| traj.years.get(i).map_or(0, |y| y.closed_shards);
    let last = traj.years.len().saturating_sub(1);
    [n_at(0), n_at(last / 2), n_at(last)]
}

/// `--stage2` entry: the burden trajectory across the scenario set. JSON to
/// stdout, a human-readable summary to stderr.
pub fn run_stage2(out: &mut impl fmt::Write, params: &SimParams) -> fmt::Result {
    // The arm first: every fee-dependent figure below is a figure under it.
    writeln!(out, "{}", params.fee.label())?;
    if params.fee.flat_per_tx_atomic().is_none() {
        // The arms' prose was written when every run charged the flat fee,
        // and some of it states results. A table is computed; a paragraph
        // is not.
        writeln!(
            out,
            "The paragraphs below were written against the flat control fee. Where one states a\n\
             result, the table beside it governs."
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Stage-2 archival burden trajectory (§12.1 checkpoint 1)\n\
         outputs = tx_volume x {OUTPUTS_PER_TX_NORMAL:.0} (1in/2out normal traffic, drives tree depth); \
         archival bytes = Σ tx_volume x archival_len(1in/2out @ depth) ({AB0}..{AB1} B/tx shallow..deep);\n\
         n = shard_of(cumulative archival bytes), W = {SHARD:.1} MB/shard (SHT-Q2)\n\
         burden = n x W x storage($/B/yr, Kryder); \
         base = {BASE:.0e} $/B/yr; funding + clearance (A1) land next\n",
        AB0 = normal_tx_archival_bytes(1),
        AB1 = normal_tx_archival_bytes(deep_chain_leaves()),
        SHARD = SHARD_BYTES / 1.0e6,
        BASE = BASE_STORAGE_FIAT_PER_BYTE_YEAR,
    )?;
    writeln!(out, "Kryder band swept (DQ-2B):")?;
    for k in KryderRate::BAND {
        writeln!(out, "  - {}", k.label())?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "{:<22} {:>6} {:>14} {:>14} {:>10} {:>16}",
        "scenario", "years", "final_outputs", "final_GB", "final_n", "final_burden$/yr@0%"
    )?;

    let mut trajectories: Vec<BurdenTrajectory> = Vec::new();
    for config in all_scenarios(params) {
        let traj = burden_trajectory(params, &config);
        let final_burden = traj.years.last().map_or(0.0, |y| y.burden_fiat_stall);
        let final_outputs = traj.years.last().map_or(0, |y| y.cumulative_outputs);
        let final_gb = traj
            .years
            .last()
            .map_or(0.0, |y| y.cumulative_archival_bytes as f64 / 1.0e9);
        writeln!(
            out,
            "{:<22} {:>6} {:>14} {:>14.2} {:>10} {:>16.2}",
            traj.scenario,
            traj.sim_years,
            final_outputs,
            final_gb,
            traj.final_closed_shards,
            final_burden,
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
    // A1-T / A1-L (§12.14): A1's min hides when the failure arrives; the onset
    // table and the lever table fold the same per-year ratio.
    let a1_onset = crate::onset::onset_report(out, params)?;
    let a1_levers = crate::onset::lever_report(out, params)?;
    a3_stranding_report(out, params)?;
    crate::distribution::oq1_probe_report(out)?;
    // OQ-2's corpus samples are the baseline trajectory's early / mid / late
    // `n` — read off the fold, not literals, so a re-keyed unit cannot leave a
    // stale band behind.
    let oq2_n = oq2_corpus_samples(&trajectories[0]);
    crate::admission::oq2_report(out, &A3_ARCHIVER_BAND, &oq2_n)?;
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
            let pool = a1_shipped_budget_atomic(a, &best);
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
            emission_curve_asymptote: params.emission_curve_asymptote,
            emission_speed_factor_per_minute: params.emission_speed_factor_per_minute,
            final_subsidy_per_minute: params.final_subsidy_per_minute,
            daa_target_seconds: EconomicParams::default().daa_target_seconds,
            // Escalation numerics come from the shipped config: the sim must never
            // invent them, since the asymptote is ceremony-gated and unpinned (§11.4).
            ..EconomicParams::default()
        };
        let br = base_block_reward(params.emission_curve_asymptote / 2, &econ).unwrap_or(0);
        crate::swing::a6_report(out, &ESCALATION_PREVIEW_N, br)?;
    }
    let a4 = a4_stuffing_report(out, params)?;

    // A5 / TJ-4 / TJ-7 share one per-shard post-D1/D2 reward operand family
    // (see [`shard_reward_operands`]). A5 takes the MAX (stronger forfeit ⇒
    // conservative deterrent); TJ-4/TJ-7 take MEDIAN + MAX (larger flow is
    // alarm-raising for the attacker).
    let rewards = shard_reward_operands(params);
    // The absorption DP prices the stream forgone FROM the slash epoch, so it
    // takes the per-epoch rate rather than a horizon lump.
    crate::proxy::a5_proxy_report(out, rewards.max_per_epoch_skl, SKL_FIAT_PRICE_BAND[1])?;
    crate::proxy::tj_shard_payload_report(out, rewards.max_per_epoch_skl, SKL_FIAT_PRICE_BAND[1])?;
    crate::cartel::tj_inequalities_report(
        out,
        rewards.median_per_epoch_skl,
        rewards.max_per_epoch_skl,
    )?;

    // (m, n) feasibility — policy defaults live in the arm
    // (`default_sources`, `FeasibilityTargets::operative_defaults`).
    crate::mn_feasibility::mn_feasibility_report(
        out,
        &crate::mn_feasibility::default_sources(),
        crate::mn_feasibility::BOND_LIFE_EPOCHS,
        &crate::mn_feasibility::FeasibilityTargets::operative_defaults(),
    )?;

    let report = Stage2Report {
        burden_trajectories: trajectories,
        a1_clearance: a1,
        a1_onset,
        a1_levers,
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
    pub a1_onset: Vec<crate::onset::OnsetScenarioResult>,
    pub a1_levers: Vec<crate::onset::LeverResult>,
    pub a4_stuffing: Vec<A4ScenarioResult>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::params::mul_scale;

    #[test]
    fn trajectory_shards_are_monotone_and_final_is_max() {
        let params = SimParams::default();
        for config in all_scenarios(&params) {
            let traj = burden_trajectory(&params, &config);
            let mut prev = 0u64;
            for row in &traj.years {
                assert!(
                    row.closed_shards >= prev,
                    "shards must be monotone in {}: {} < {}",
                    traj.scenario,
                    row.closed_shards,
                    prev
                );
                // The row's `n` IS the partition of the row's bytes — no second
                // derivation can drift between the two columns.
                assert_eq!(
                    row.closed_shards,
                    closed_shards(row.cumulative_archival_bytes)
                );
                prev = row.closed_shards;
            }
            assert_eq!(traj.final_closed_shards, prev);
        }
    }

    #[test]
    fn knee_band_brackets_the_sweep_trajectories() {
        // KNEE_BAND is re-derived in the byte-keyed unit from the sweep itself
        // (escalation.rs): low ≈ the baseline trajectory's n at ~10 y, high ≈
        // the sustained-growth trajectory's final n, middle = their geometric
        // mean. A trajectory change that moved either anchor by more than a
        // factor of two fails here, so the band cannot silently go stale.
        let params = SimParams::default();
        let scenarios = all_scenarios(&params);
        let baseline = burden_trajectory(&params, &scenarios[0]);
        let at_10y = baseline
            .years
            .iter()
            .find(|y| y.year == 10)
            .map_or(baseline.final_closed_shards, |y| y.closed_shards);
        let max_final = scenarios
            .iter()
            .map(|c| burden_trajectory(&params, c).final_closed_shards)
            .max()
            .unwrap();
        let within_2x = |band: u64, anchor: u64| band * 2 >= anchor && band <= anchor * 2;
        assert!(
            within_2x(KNEE_BAND[0], at_10y),
            "low {} vs baseline@10y {at_10y}",
            KNEE_BAND[0]
        );
        assert!(
            within_2x(KNEE_BAND[2], max_final),
            "high {} vs max final {max_final}",
            KNEE_BAND[2]
        );
        let geo = ((KNEE_BAND[0] as f64) * (KNEE_BAND[2] as f64)).sqrt() as u64;
        assert!(
            within_2x(KNEE_BAND[1], geo),
            "middle {} vs geometric mean {geo}",
            KNEE_BAND[1]
        );
        assert!(KNEE_BAND[0] < KNEE_BAND[1] && KNEE_BAND[1] < KNEE_BAND[2]);
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
    fn year_share_matches_mul_scale_in_u64_range() {
        // The year-aggregate share is production's `mul_scale` floor widened,
        // not a second rounding rule: wherever both are defined they agree
        // bit-for-bit, including at the u64 ceiling.
        for pool in [
            0u64,
            1,
            999_999,
            1_000_000,
            1_000_001,
            3,
            u64::MAX / 7,
            u64::MAX,
        ] {
            for share in [0u64, 1, 250_000, 333_333, 999_999, SCALE] {
                assert_eq!(
                    year_share_atomic(u128::from(pool), share),
                    u128::from(mul_scale(pool, share)),
                    "pool {pool} share {share}"
                );
            }
        }
        // And past it, the floor continues rather than clipping.
        let pool = u128::from(u64::MAX) * 3;
        assert_eq!(year_share_atomic(pool, SCALE / 2), pool / 2);
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

    /// A fee arm of the `--stage2` report and the file that pins it.
    struct PinnedArm {
        params: fn() -> SimParams,
        fixture: &'static str,
    }

    /// `--stage2`: the production fee arm, which is the default run.
    const PRODUCTION_ARM: PinnedArm = PinnedArm {
        params: SimParams::default,
        fixture: concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stage2_narration.txt"
        ),
    };

    /// `--stage2 --control-flat-fee`: the flat fee the §12.13–§12.14 tables
    /// were measured on.
    const FLAT_CONTROL_ARM: PinnedArm = PinnedArm {
        params: SimParams::section_12_14_control,
        fixture: concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stage2_narration_flat_control.txt"
        ),
    };

    fn stage2_narration(arm: &PinnedArm) -> String {
        let mut narration = String::new();
        run_stage2(&mut narration, &(arm.params)()).expect("String sink is infallible");
        narration
    }

    /// The whole `--stage2` report against the committed copy
    /// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §2). The re-base changes one
    /// operand of the fold per commit; this is what says which lines of the
    /// report that commit moved, and that it moved no others. A commit that
    /// means to move a line regenerates the fixture and the diff is its
    /// evidence — so the fixture is reviewed as output, never trusted as an
    /// oracle for the line it was regenerated to match.
    ///
    /// Ignored by default: the report folds every scenario to 60 years
    /// (100–150 s per arm in release, far longer in a debug test). Run with
    /// `cargo test --release -p shekyl-economics-sim -- --ignored
    /// matches_the_committed_fixture` (both arms).
    #[test]
    #[ignore = "full --stage2 report; ~150 s in release — run with --release --ignored"]
    fn stage2_narration_matches_the_committed_fixture() {
        assert_narration_matches(&PRODUCTION_ARM);
    }

    /// The control arm against its committed copy. This is the fixture that
    /// ties the re-based sim to the published tables: it is the report as it
    /// stood before the fee was rewired, plus the lines that name the arm
    /// and print its fee, and it moves only when a fold operand shared by
    /// both arms does.
    #[test]
    #[ignore = "full --stage2 report; ~100 s in release — run with --release --ignored"]
    fn stage2_narration_flat_control_matches_the_committed_fixture() {
        assert_narration_matches(&FLAT_CONTROL_ARM);
    }

    fn assert_narration_matches(arm: &PinnedArm) {
        let committed = std::fs::read_to_string(arm.fixture).expect("read committed narration");
        let current = stage2_narration(arm);
        if committed != current {
            let first = committed
                .lines()
                .zip(current.lines())
                .position(|(a, b)| a != b)
                .map_or_else(
                    || committed.lines().count().min(current.lines().count()) + 1,
                    |i| i + 1,
                );
            panic!(
                "--stage2 narration drifted from {}; first differing line {first} ({} \
                 committed lines, {} current). Regenerate with SHEKYL_REGEN_FIXTURES=1 and \
                 read the diff.",
                arm.fixture,
                committed.lines().count(),
                current.lines().count(),
            );
        }
    }

    /// Regenerate both committed narrations. Ignored by default; run with
    /// `SHEKYL_REGEN_FIXTURES=1 cargo test --release -p shekyl-economics-sim
    /// -- --ignored regen_stage2_narration_fixtures`.
    #[test]
    #[ignore = "regeneration helper; writes the committed fixtures"]
    fn regen_stage2_narration_fixtures() {
        assert_eq!(
            std::env::var("SHEKYL_REGEN_FIXTURES").as_deref(),
            Ok("1"),
            "set SHEKYL_REGEN_FIXTURES=1 to regenerate"
        );
        for arm in [&PRODUCTION_ARM, &FLAT_CONTROL_ARM] {
            std::fs::write(arm.fixture, stage2_narration(arm)).expect("write narration");
        }
    }
}

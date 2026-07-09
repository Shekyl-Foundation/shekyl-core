// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
//! F-B1c-c2 disposition-(b) reopen evidence — archival-funding
//! demand-insulation sim.
//!
//! **The question (rule-21 reopen, `REWARD_EMISSION_E3_GATING_ROUND.md` §9.9,
//! `docs/FOLLOWUPS.md` V3.0 pre-genesis queue).** The C-1 budget's staker
//! emission leg was fixed to **disposition (a)**: a share of verify's
//! *modulated* `base_reward` (release multiplier + weight penalty), making
//! `budget(E)` conservation-exact ("ledger minus coinbase") but
//! **demand-responsive** — archival funding throttles when tx volume is low.
//! **Disposition (b)** (a demand-*insulated* budget: the staker leg drawn from
//! the *unmodulated* subsidy) was rejected-now with a rule-21 reopen gated on
//! evidence. This sim is that evidence: it measures how much `budget(E)` swings
//! with tx volume under (a), against the (b) counterfactual, and whether the
//! swing plausibly starves the serving incentive in low-volume windows.
//!
//! **What varies between (a) and (b) — and what does not.** The *only*
//! per-block difference is the emission-leg operand:
//!
//! ```text
//! (a) emission leg = split_block_emission(effective_reward, share).staker   // release-modulated
//! (b) emission leg = split_block_emission(base_reward,       share).staker   // unmodulated subsidy
//! ```
//!
//! The fee leg (`compute_burn_split(...).staker_pool_amount`) is **identical**
//! under both — (b) only insulates the *emission* leg, not fees. The chain
//! itself is one real trajectory: `already_generated` advances by the modulated
//! `effective_reward` in both arms (the emission curve does not change; only the
//! staker-leg destination/quantity question is (a)-vs-(b)). So the funding delta
//! (b) would buy over (a) is, block for block, exactly the release multiplier
//! applied to the emission share of `base_reward`.
//!
//! **Bounded by construction.** `calc_release_multiplier` clamps to
//! `[release_min, release_max]` (0.8×–1.3×; `release.rs`). At the *lowest* tx
//! volume the emission leg sits at its `release_min` floor (0.8×), never zero —
//! so (b) can restore at most `(1.0 − 0.8)/0.8 = 25 %` of the emission leg in the
//! worst window. The sim quantifies where in that envelope real low-volume
//! regimes actually land, and how the emission-share decay (0.90/yr) shrinks the
//! (a)-vs-(b) gap toward zero as the chain enters the fee era.
//!
//! **Scope note — weight penalty.** The macro sim models the release-multiplier
//! channel only; it does not model per-block weight (all blocks sit at baseline
//! weight, penalty = 1.0). This is faithful to the low-volume-starvation
//! question: the weight penalty only bites on *oversized* blocks (high volume),
//! the opposite regime from the one that could starve archival funding.

use serde::Serialize;
use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
use shekyl_economics::{
    base_block_reward,
    burn::compute_burn_split,
    calc_burn_pct, calc_effective_emission_share, calc_release_multiplier,
    params::{EconomicParams, SCALE},
    release::apply_release_multiplier,
    split_block_emission,
};

use crate::engine::SimParams;

const COIN: f64 = 1_000_000_000.0;

/// A tx-volume regime to probe. `get_volume(block, blocks_per_year)` returns the
/// per-block tx count, exactly the `VolumeSchedule` shape the legacy engine uses.
pub struct BudgetScenario {
    pub name: String,
    pub description: String,
    pub sim_years: u64,
    pub get_volume: Box<dyn Fn(u64, u64) -> u64>,
    pub fee_per_tx: u64,
    pub initial_emitted_fraction: f64,
    pub genesis_height_offset: u64,
}

/// One settlement epoch's budget accounting under both dispositions.
#[derive(Debug, Clone, Serialize)]
pub struct EpochRecord {
    pub epoch: u64,
    /// Mean per-block tx volume observed over the epoch's blocks.
    pub mean_tx_volume: f64,
    /// Mean release multiplier (1.0 = neutral) over the epoch.
    pub release_mult_mean: f64,
    /// Minimum release multiplier reached in the epoch (the worst throttle).
    pub release_mult_min: f64,
    /// Effective staker emission share at the epoch's mid-block (post-decay).
    pub emission_share_pct: f64,
    // --- The two legs, in coins ---
    /// (a) modulated emission leg accrued to the budget over the epoch.
    pub emission_leg_a_coins: f64,
    /// (b) unmodulated emission leg (counterfactual).
    pub emission_leg_b_coins: f64,
    /// Fee leg (`staker_pool_amount`), identical under both dispositions.
    pub fee_leg_coins: f64,
    // --- Totals + the reopen gauges ---
    /// `budget(E)` under the shipped disposition (a).
    pub budget_a_coins: f64,
    /// `budget(E)` under the (b) counterfactual.
    pub budget_b_coins: f64,
    /// `budget_a / budget_b` — the fraction of the demand-insulated budget that
    /// (a) actually delivers this epoch (the "throttle depth"; 1.0 = no throttle).
    pub ratio_a_over_b: f64,
    /// `(budget_b − budget_a) / budget_a × 100` — the funding uplift (b) would
    /// buy this epoch. This is the magnitude the reopen weighs against the
    /// serving-incentive threshold.
    pub insulation_uplift_pct: f64,
}

/// Whole-scenario roll-up: the headline reopen gauges.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetScenarioResult {
    pub name: String,
    pub description: String,
    pub epochs: Vec<EpochRecord>,
    /// Worst (deepest) throttle across all epochs: `min(ratio_a_over_b)`.
    pub worst_ratio_a_over_b: f64,
    /// Largest funding uplift (b) would buy in any epoch, percent.
    pub max_insulation_uplift_pct: f64,
    /// At the deepest-throttle epoch, the emission leg's share of `budget_a` —
    /// i.e. how much of the (throttled) budget is even *exposed* to the
    /// (a)-vs-(b) choice. The fee leg is disposition-neutral, so `1 − this` is
    /// insulation (b) cannot buy. Low exposure ⇒ the throttle floor matters
    /// less to total funding than the 0.8× emission-leg floor suggests.
    pub emission_frac_at_worst_throttle: f64,
    /// Mean insulation uplift weighted by nothing (simple epoch mean), percent —
    /// the typical, not worst-case, gap. Negative when volume runs above
    /// baseline (release mult > 1 ⇒ (a) already exceeds (b)).
    pub mean_insulation_uplift_pct: f64,
}

/// Run one volume regime, accumulating the budget under (a) and (b) per epoch.
///
/// Mirrors the per-block economics of `engine::run_scenario` (same
/// `shekyl-economics` primitives, same operands) so the emission/fee/burn math
/// is the consensus model, not a re-derivation — then adds the single (b)
/// counterfactual line and the epoch-granular budget accounting the legacy
/// year-snapshot engine does not carry.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn run_budget_scenario(params: &SimParams, scenario: &BudgetScenario) -> BudgetScenarioResult {
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

    let money_supply = params.money_supply as u128;
    let mut already_generated: u128 =
        (params.money_supply as f64 * scenario.initial_emitted_fraction) as u128;
    let mut total_burned: u128 = 0;

    let total_blocks = params.blocks_per_year * scenario.sim_years;

    // Per-epoch accumulators (atomic units, u128 to be headroom-safe over 10k
    // blocks of full-supply-scale rewards).
    let mut emission_a_acc: u128 = 0;
    let mut emission_b_acc: u128 = 0;
    let mut fee_acc: u128 = 0;
    let mut vol_sum: u128 = 0;
    let mut mult_sum: u128 = 0;
    let mut mult_min: u64 = u64::MAX;
    let mut blocks_in_epoch: u64 = 0;
    let mut current_epoch: u64 = 0;

    let mut epochs: Vec<EpochRecord> = Vec::new();

    for block in 0..total_blocks {
        let abs_height = block + scenario.genesis_height_offset;
        let epoch = abs_height / SETTLEMENT_EPOCH_BLOCKS;

        // Flush on epoch rollover.
        if blocks_in_epoch > 0 && epoch != current_epoch {
            let mid_height = current_epoch * SETTLEMENT_EPOCH_BLOCKS + SETTLEMENT_EPOCH_BLOCKS / 2;
            epochs.push(build_epoch_record(
                current_epoch,
                emission_a_acc,
                emission_b_acc,
                fee_acc,
                vol_sum,
                mult_sum,
                mult_min,
                blocks_in_epoch,
                mid_height,
                params,
            ));
            emission_a_acc = 0;
            emission_b_acc = 0;
            fee_acc = 0;
            vol_sum = 0;
            mult_sum = 0;
            mult_min = u64::MAX;
            blocks_in_epoch = 0;
        }
        current_epoch = epoch;

        let remaining = money_supply.saturating_sub(already_generated);
        let base_reward =
            base_block_reward(already_generated.min(u64::MAX as u128) as u64, &economic)
                .expect("sim neutral trajectory stays within supply bounds");

        let tx_volume = (scenario.get_volume)(block, params.blocks_per_year);

        let multiplier = calc_release_multiplier(
            tx_volume,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        );

        // Real ledger advance uses the modulated reward (both arms share it).
        let mut effective_reward = apply_release_multiplier(base_reward, multiplier);
        let remaining_u64 = remaining.min(u64::MAX as u128) as u64;
        if effective_reward > remaining_u64 {
            effective_reward = remaining_u64;
        }

        let emission_share = calc_effective_emission_share(
            abs_height,
            0,
            params.staker_emission_share,
            params.staker_emission_decay,
            params.blocks_per_year,
        );

        // (a): staker emission leg from the MODULATED reward (shipped).
        let (_miner_a, staker_emission_a) = split_block_emission(effective_reward, emission_share);
        // (b): staker emission leg from the UNMODULATED subsidy (counterfactual).
        // Cap at `remaining` for symmetry with the ledger clamp, so the
        // counterfactual never claims more than the supply could pay.
        let base_unclamped = base_reward.min(remaining_u64);
        let (_miner_b, staker_emission_b) = split_block_emission(base_unclamped, emission_share);

        // Fee leg — identical under both dispositions.
        let circulating = (already_generated as u64).saturating_sub(total_burned as u64);
        let burn_pct = calc_burn_pct(
            tx_volume,
            params.tx_volume_baseline,
            circulating,
            params.money_supply,
            // stake_ratio: the macro budget sim does not model a stake schedule;
            // pass 0 (the stake term contributes <10^-3 to burn_pct per the
            // gate-7 read, and is disposition-neutral). The fee leg's volume
            // response — the demand-responsive part both arms share — is what
            // matters here.
            0,
            params.burn_base_rate,
            params.burn_cap,
        );
        let total_fees =
            (tx_volume as u128 * scenario.fee_per_tx as u128).min(u64::MAX as u128) as u64;
        let fee_split = compute_burn_split(total_fees, burn_pct, params.staker_pool_share);

        // Accumulate.
        emission_a_acc += staker_emission_a as u128;
        emission_b_acc += staker_emission_b as u128;
        fee_acc += fee_split.staker_pool_amount as u128;
        vol_sum += tx_volume as u128;
        mult_sum += multiplier as u128;
        mult_min = mult_min.min(multiplier);
        blocks_in_epoch += 1;

        // Advance the real ledger (modulated, both arms share it).
        already_generated += effective_reward as u128;
        if already_generated > money_supply {
            already_generated = money_supply;
        }
        total_burned += fee_split.actually_destroyed as u128;
    }

    // Flush the final partial epoch.
    if blocks_in_epoch > 0 {
        let mid_height = current_epoch * SETTLEMENT_EPOCH_BLOCKS + SETTLEMENT_EPOCH_BLOCKS / 2;
        epochs.push(build_epoch_record(
            current_epoch,
            emission_a_acc,
            emission_b_acc,
            fee_acc,
            vol_sum,
            mult_sum,
            mult_min,
            blocks_in_epoch,
            mid_height,
            params,
        ));
    }

    // Roll-up gauges.
    let worst_ratio = epochs
        .iter()
        .map(|e| e.ratio_a_over_b)
        .fold(f64::INFINITY, f64::min);
    let max_uplift = epochs
        .iter()
        .map(|e| e.insulation_uplift_pct)
        .fold(f64::NEG_INFINITY, f64::max);
    let mean_uplift = if epochs.is_empty() {
        0.0
    } else {
        epochs.iter().map(|e| e.insulation_uplift_pct).sum::<f64>() / epochs.len() as f64
    };
    // Emission-leg exposure at the deepest-throttle epoch.
    let emission_frac = epochs
        .iter()
        .min_by(|a, b| a.ratio_a_over_b.total_cmp(&b.ratio_a_over_b))
        .map(|e| {
            if e.budget_a_coins > 0.0 {
                e.emission_leg_a_coins / e.budget_a_coins
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    BudgetScenarioResult {
        name: scenario.name.clone(),
        description: scenario.description.clone(),
        epochs,
        worst_ratio_a_over_b: if worst_ratio.is_finite() {
            worst_ratio
        } else {
            1.0
        },
        max_insulation_uplift_pct: if max_uplift.is_finite() {
            max_uplift
        } else {
            0.0
        },
        emission_frac_at_worst_throttle: emission_frac,
        mean_insulation_uplift_pct: mean_uplift,
    }
}

#[allow(clippy::cast_precision_loss, clippy::too_many_arguments)]
fn build_epoch_record(
    epoch: u64,
    emission_a: u128,
    emission_b: u128,
    fee: u128,
    vol_sum: u128,
    mult_sum: u128,
    mult_min: u64,
    blocks: u64,
    abs_height_mid: u64,
    params: &SimParams,
) -> EpochRecord {
    let budget_a = emission_a + fee;
    let budget_b = emission_b + fee;
    let ratio = if budget_b > 0 {
        budget_a as f64 / budget_b as f64
    } else {
        1.0
    };
    let uplift = if budget_a > 0 {
        (budget_b as f64 - budget_a as f64) / budget_a as f64 * 100.0
    } else {
        0.0
    };
    let share = calc_effective_emission_share(
        abs_height_mid,
        0,
        params.staker_emission_share,
        params.staker_emission_decay,
        params.blocks_per_year,
    );
    EpochRecord {
        epoch,
        mean_tx_volume: vol_sum as f64 / blocks as f64,
        release_mult_mean: mult_sum as f64 / blocks as f64 / SCALE as f64,
        release_mult_min: mult_min as f64 / SCALE as f64,
        emission_share_pct: share as f64 / SCALE as f64 * 100.0,
        emission_leg_a_coins: emission_a as f64 / COIN,
        emission_leg_b_coins: emission_b as f64 / COIN,
        fee_leg_coins: fee as f64 / COIN,
        budget_a_coins: budget_a as f64 / COIN,
        budget_b_coins: budget_b as f64 / COIN,
        ratio_a_over_b: ratio,
        insulation_uplift_pct: uplift,
    }
}

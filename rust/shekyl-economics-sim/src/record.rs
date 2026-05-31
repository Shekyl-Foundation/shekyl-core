// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `RecordedChainFixture` recorder — the C4 test substrate generator.
//!
//! Per `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §5.4 (R5), the
//! `EconomicsEngine` differential test consumes a **sim-recorded**
//! fixture — never hand-authored expectations, never a `MockEconomics`.
//! This module is the recorder: it runs the baseline scenario over the
//! same `shekyl-economics` integer primitives the engine composes and
//! emits the **two-array** JSON schema (`records` + `neutral_milestones`)
//! that `shekyl-engine-core`'s differential deserializes.
//!
//! The recorder and the engine both call the canonical primitives
//! (`base_block_reward`, `calc_burn_pct_from_activity`,
//! `calc_release_multiplier`, …); the differential's value is therefore
//! **integration** coverage — that `LocalEconomics` wires the primitives
//! together exactly as the reference loop does, and that the
//! `params_digest` lineage round-trips. The independent-reference
//! consensus 0h gate is **7-base** C2a′ (already landed); C4 is
//! supplementary per §7.1.
//!
//! # Regenerating the committed fixture
//!
//! The fixture lives at `docs/test_vectors/economics/baseline_steady_state.json`.
//! Regenerate it (after an `economics_params.json` or scenario change)
//! with:
//!
//! ```text
//! SHEKYL_REGEN_FIXTURES=1 cargo test -p shekyl-economics-sim -- regen_baseline_fixture --ignored
//! ```
//!
//! The non-`--ignored` `committed_fixture_matches_recorder` test fails
//! loudly when the committed file drifts from the recorder output, so a
//! forgotten regen cannot silently pass.

use serde::{Deserialize, Serialize};
use shekyl_economics::burn::compute_burn_split;
use shekyl_economics::params::{EconomicParams, SCALE};
use shekyl_economics::{
    base_block_reward, base_emission_at, calc_burn_pct_from_activity,
    calc_effective_emission_share, calc_release_multiplier, params_digest,
    release::apply_release_multiplier, split_block_emission,
};

use crate::engine::SimParams;
use crate::scenarios::scenario_1_baseline;

/// One recorded per-block row (integer observables + integer
/// expectations). Heights are sampled (year boundaries + an early row),
/// not exhaustive — the differential is a spot-check across the
/// trajectory, not a per-block replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRow {
    pub height: u64,
    /// `already_generated` at the **start** of this block — the exact
    /// input the engine feeds `base_block_reward`.
    pub already_generated_coins: u64,
    pub base_block_reward: u64,
    /// `calc_release_multiplier(...) / 1000` (SCALE → milli).
    pub release_multiplier_milli: u64,
    pub tx_volume: u64,
    pub circulating_supply: u64,
    pub total_staked: u64,
    /// `calc_burn_pct_from_activity(...) / 100` (SCALE → basis points).
    pub burn_pct_bp: u64,
    /// Low / high 64 bits of the `u128` pool-weighted total — exercises
    /// the reconstruction the chain mirror performs at the LMDB/FFI
    /// boundary (§5.4).
    pub total_weighted_stake_lo: u64,
    pub total_weighted_stake_hi: u64,
    pub staker_emission: u64,
    pub staker_fee_pool: u64,
    pub actually_destroyed: u64,
}

/// One neutral-trajectory emission milestone (multiplier ≡ 1.0). Asserts
/// the engine's pure `base_emission_at` projection, which must **not** be
/// checked against realized-`ag` `records` rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeutralMilestone {
    pub height: u64,
    pub base_emission_at_neutral: u64,
    pub note: String,
}

/// The §5.4 two-array fixture: staleness-guard metadata + `records` +
/// `neutral_milestones`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedChainFixture {
    /// Calibration generation the rows were recorded under
    /// ([`shekyl_economics::CALIBRATION_GENERATION`]).
    pub calibration_generation: u32,
    /// `"blake2b:<hex>"` of the canonical [`params_digest`] — the
    /// staleness guard. Mismatch rejects the run instead of a silent
    /// pass.
    pub params_digest: String,
    pub scenario: String,
    /// `"live"` when any `records[]` row has `total_staked > 0` and the
    /// recording used real stake aggregation (G3); `"stub"` otherwise.
    pub staking_state: String,
    pub records: Vec<RecordedRow>,
    pub neutral_milestones: Vec<NeutralMilestone>,
}

/// `"blake2b:<lowercase-hex>"` encoding of a 32-byte digest. Hand-rolled
/// to keep the sim's dependency surface at `shekyl-economics` + serde
/// (the engine-side differential encodes identically and string-compares
/// — no hex *decode* is needed on either side).
#[must_use]
pub fn digest_label(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(8 + 64);
    s.push_str("blake2b:");
    for byte in digest {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Heights sampled into `records`: the last block of each simulated year
/// plus an early row (`height = 1`). Deterministic and small.
fn sample_heights(blocks_per_year: u64, sim_years: u64) -> Vec<u64> {
    let mut heights = vec![1u64];
    for year in 0..sim_years {
        heights.push(year * blocks_per_year + (blocks_per_year - 1));
    }
    heights
}

/// Record the `baseline_steady_state` scenario into a
/// [`RecordedChainFixture`] using the canonical `shekyl-economics`
/// primitives.
///
/// The per-block accumulation loop mirrors
/// [`crate::engine::run_scenario`]'s integer reward/emission math (so
/// `already_generated` tracks identically). It deliberately does **not**
/// adopt that modeling tool's emitted-minus-burned `circulating`: the
/// recorded `circulating_supply` is the **consensus burn-site quantity** —
/// prev-block `already_generated` (== `ag_start`) — per §5.3 R1 / design
/// §608–612, **not** `already_generated − total_burned`. Rows are captured
/// at [`sample_heights`].
#[must_use]
pub fn record_baseline_fixture() -> RecordedChainFixture {
    let sim = SimParams::default();
    let config = scenario_1_baseline(&sim);

    let params = EconomicParams {
        release_min: sim.release_min,
        release_max: sim.release_max,
        tx_volume_baseline: sim.tx_volume_baseline,
        burn_base_rate: sim.burn_base_rate,
        burn_cap: sim.burn_cap,
        staker_pool_share: sim.staker_pool_share,
        money_supply: sim.money_supply,
        emission_speed_factor_per_minute: sim.emission_speed_factor_per_minute,
        final_subsidy_per_minute: sim.final_subsidy_per_minute,
        daa_target_seconds: EconomicParams::default().daa_target_seconds,
    };

    let blocks_per_year = sim.blocks_per_year;
    let total_blocks = blocks_per_year * config.sim_years;
    let money_supply = sim.money_supply as u128;
    let samples = sample_heights(blocks_per_year, config.sim_years);

    let mut already_generated: u128 = 0;
    let mut records: Vec<RecordedRow> = Vec::with_capacity(samples.len());

    for block in 0..total_blocks {
        // `already_generated` at the start of this block is the
        // `base_block_reward` input — capture before mutating.
        let ag_start = already_generated.min(u128::from(u64::MAX)) as u64;
        let remaining = money_supply.saturating_sub(already_generated);

        let base_reward = base_block_reward(ag_start, &params)
            .expect("sim neutral trajectory stays within supply bounds");

        let tx_volume = (config.volume.get_volume)(block, blocks_per_year);
        // `circulating_supply` is the consensus burn-site quantity:
        // prev-block `already_generated` (== `ag_start`), matching
        // `validate_miner_transaction` — NOT `already_generated −
        // total_burned` (§5.3 R1 / design §608–612). stake_ratio,
        // total_staked, burn input, and the recorded row all use this
        // same quantity so the fixture exercises the consensus input.
        let circulating = ag_start;
        let stake_ratio = (config.stake.get_stake_ratio)(block, blocks_per_year, circulating);

        let multiplier = calc_release_multiplier(
            tx_volume,
            sim.tx_volume_baseline,
            sim.release_min,
            sim.release_max,
        );

        let mut effective_reward = apply_release_multiplier(base_reward, multiplier);
        let remaining_u64 = remaining.min(u128::from(u64::MAX)) as u64;
        if effective_reward > remaining_u64 {
            effective_reward = remaining_u64;
        }

        let emission_share = calc_effective_emission_share(
            block + config.genesis_height_offset,
            0,
            sim.staker_emission_share,
            sim.staker_emission_decay,
            blocks_per_year,
        );
        let (_miner_emission, staker_emission) =
            split_block_emission(effective_reward, emission_share);

        let total_staked = if stake_ratio > 0 && circulating > 0 {
            (u128::from(circulating) * u128::from(stake_ratio) / u128::from(SCALE)) as u64
        } else {
            0
        };

        // Engine-equivalent burn: the `from_activity` path forms
        // `stake_ratio` via the single shared helper (Bug-2 class), so
        // the recorded `burn_pct_bp` is reproducible by
        // `LocalEconomics::burn_amount`'s composition.
        let burn_pct = calc_burn_pct_from_activity(
            tx_volume,
            sim.tx_volume_baseline,
            circulating,
            total_staked,
            &params,
        );
        let total_fees = (u128::from(tx_volume) * u128::from(config.fee_per_tx))
            .min(u128::from(u64::MAX)) as u64;
        let fee_split = compute_burn_split(total_fees, burn_pct, sim.staker_pool_share);

        if samples.contains(&block) {
            // Pool-weighted total: at V3.0 the sim has no separate
            // weighted aggregate, so the principal `total_staked` stands
            // in. Recorded as lo/hi to exercise u128 reconstruction.
            let weighted = u128::from(total_staked);
            records.push(RecordedRow {
                height: block,
                already_generated_coins: ag_start,
                base_block_reward: base_reward,
                release_multiplier_milli: multiplier / 1000,
                tx_volume,
                circulating_supply: circulating,
                total_staked,
                burn_pct_bp: burn_pct / 100,
                total_weighted_stake_lo: weighted as u64,
                total_weighted_stake_hi: (weighted >> 64) as u64,
                staker_emission,
                staker_fee_pool: fee_split.staker_pool_amount,
                actually_destroyed: fee_split.actually_destroyed,
            });
        }

        already_generated += u128::from(effective_reward);
        if already_generated > money_supply {
            already_generated = money_supply;
        }
    }

    let neutral_milestones = [
        (blocks_per_year, "≈1 yr — early neutral trajectory"),
        (5 * blocks_per_year, "≈5 yr"),
        (10 * blocks_per_year, "≈10 yr"),
        (5_788_000, "≈50% emitted, ~yr 22 (ESF-22 milestone)"),
    ]
    .into_iter()
    .map(|(height, note)| NeutralMilestone {
        height,
        base_emission_at_neutral: base_emission_at(height, &params)
            .expect("neutral projection stays within supply bounds"),
        note: note.to_string(),
    })
    .collect();

    let staking_state = if records.iter().any(|r| r.total_staked > 0) {
        "live"
    } else {
        "stub"
    };

    RecordedChainFixture {
        calibration_generation: shekyl_economics::CALIBRATION_GENERATION,
        params_digest: digest_label(&params_digest(&params)),
        scenario: config.name,
        staking_state: staking_state.to_string(),
        records,
        neutral_milestones,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/test_vectors/economics/baseline_steady_state.json"
    );

    #[test]
    fn recorder_is_deterministic() {
        assert_eq!(record_baseline_fixture(), record_baseline_fixture());
    }

    #[test]
    fn recorder_marks_staking_live() {
        // The baseline scenario stakes from year 0, so any row with a
        // non-zero principal must report `staking_state: "live"` (G3).
        let fx = record_baseline_fixture();
        assert!(fx.records.iter().any(|r| r.total_staked > 0));
        assert_eq!(fx.staking_state, "live");
    }

    /// Regenerate the committed fixture. Ignored by default; run with
    /// `SHEKYL_REGEN_FIXTURES=1 cargo test -p shekyl-economics-sim -- \
    /// regen_baseline_fixture --ignored`.
    #[test]
    #[ignore = "regeneration helper; writes the committed fixture"]
    fn regen_baseline_fixture() {
        assert_eq!(
            std::env::var("SHEKYL_REGEN_FIXTURES").as_deref(),
            Ok("1"),
            "set SHEKYL_REGEN_FIXTURES=1 to regenerate"
        );
        let fx = record_baseline_fixture();
        let json = serde_json::to_string_pretty(&fx).expect("serialize fixture");
        std::fs::write(FIXTURE_PATH, json + "\n").expect("write fixture");
    }

    #[test]
    fn committed_fixture_matches_recorder() {
        let committed = std::fs::read_to_string(FIXTURE_PATH).expect("read committed fixture");
        let committed: RecordedChainFixture =
            serde_json::from_str(&committed).expect("deserialize committed fixture");
        assert_eq!(
            committed,
            record_baseline_fixture(),
            "committed fixture drifted from recorder; regenerate with SHEKYL_REGEN_FIXTURES=1"
        );
    }
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C4 engine-vs-sim differential for [`EconomicsEngine`] / [`LocalEconomics`].
//!
//! Per `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §5.4 (R5) / §7.1
//! (C4), this replays the **sim-recorded** `RecordedChainFixture`
//! (`docs/test_vectors/economics/baseline_steady_state.json`, produced by
//! `shekyl-economics-sim`'s recorder — never hand-authored, no
//! `MockEconomics`) through the **real** `LocalEconomics` path over a
//! [`ChainMirrorSource`]. The four trait methods are each exercised:
//!
//! - [`base_emission_at`](EconomicsEngine::base_emission_at) against the
//!   `neutral_milestones` array (pure projection; multiplier ≡ 1).
//! - [`burn_amount`](EconomicsEngine::burn_amount) against per-record
//!   `burn_pct_bp` (the `from_activity` composition).
//! - [`pool_weighted_total`](EconomicsEngine::pool_weighted_total) against
//!   the `lo`/`hi` u128 reconstruction.
//! - [`parameters_snapshot`](EconomicsEngine::parameters_snapshot)
//!   `CalibrationStamp` lineage.
//!
//! The fixture's `calibration_generation` + `params_digest` are the
//! staleness guard (§5.4): a mismatch fails the run loudly rather than
//! silently passing. This is **supplementary** coverage — the
//! independent-reference consensus 0h gate is 7-base C2a′ (already
//! landed), not this test.

use serde::Deserialize;

use shekyl_economics::params::mul_scale;
use shekyl_economics::{
    base_block_reward, calc_burn_pct_from_activity, params_digest, ActivityMetric, EconomicParams,
    CALIBRATION_GENERATION,
};

use super::chain_economics_source::ChainEconomicsSource;
use super::local_economics::LocalEconomics;
use super::traits::economics::EconomicsEngine;

/// The committed, sim-recorded fixture (path resolved from the crate
/// manifest so it is independent of this file's depth under `src/`).
const FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/test_vectors/economics/baseline_steady_state.json"
));

/// Deserialize mirror of the §5.4 schema. Intentionally **independent**
/// of the sim's `Serialize` type (decouples consumer from producer); only
/// the fields the trait differential consumes are named — serde ignores
/// the sim-internal block-split columns (`staker_emission`,
/// `actually_destroyed`, …) that the `EconomicsEngine` surface does not
/// expose.
#[derive(Debug, Deserialize)]
struct Fixture {
    calibration_generation: u32,
    params_digest: String,
    staking_state: String,
    records: Vec<Row>,
    neutral_milestones: Vec<Milestone>,
}

#[derive(Debug, Deserialize)]
struct Row {
    height: u64,
    already_generated_coins: u64,
    base_block_reward: u64,
    tx_volume: u64,
    circulating_supply: u64,
    total_staked: u64,
    burn_pct_bp: u64,
    total_weighted_stake_lo: u64,
    total_weighted_stake_hi: u64,
}

#[derive(Debug, Deserialize)]
struct Milestone {
    height: u64,
    base_emission_at_neutral: u64,
}

/// Test `ChainEconomicsSource` that echoes a recorded pool-weighted total
/// — the C4 substitute for the production `LedgerChainEconomicsSource`,
/// keeping `LocalEconomics` on its real code path (no `MockEconomics`).
struct ChainMirrorSource {
    weighted: u128,
}

impl ChainEconomicsSource for ChainMirrorSource {
    fn active_weighted_stake(&self) -> u128 {
        self.weighted
    }
}

/// `"blake2b:<lowercase-hex>"` — identical encoding to the sim recorder's
/// `digest_label`, so the staleness guard is a plain string compare (no
/// hex decode on either side).
fn digest_label(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(8 + 64);
    s.push_str("blake2b:");
    for byte in digest {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

fn load_fixture() -> Fixture {
    serde_json::from_str(FIXTURE_JSON).expect("committed economics fixture is valid JSON")
}

#[test]
fn economics_fixture_params_lineage_is_current() {
    let fx = load_fixture();
    let params = EconomicParams::default();
    // Staleness guard (§5.4): generation + digest must match the params
    // the engine resolves today, else the fixture is stale — fail loudly.
    assert_eq!(
        fx.calibration_generation, CALIBRATION_GENERATION,
        "fixture calibration_generation is stale; regenerate with SHEKYL_REGEN_FIXTURES=1"
    );
    assert_eq!(
        fx.params_digest,
        digest_label(&params_digest(&params)),
        "fixture params_digest does not match EconomicParams::default(); regenerate fixture"
    );
    // G3: the baseline scenario stakes from year 0.
    assert_eq!(fx.staking_state, "live");
}

#[test]
fn economics_differential_records_match_engine() {
    let fx = load_fixture();
    let params = EconomicParams::default();
    const FEE: u64 = 1_000_000_000;

    for row in &fx.records {
        // (1) base_block_reward primitive at the recorded `ag` — the
        // shared 0h math `base_emission_at` composes.
        assert_eq!(
            base_block_reward(row.already_generated_coins, &params).unwrap(),
            row.base_block_reward,
            "base_block_reward @ height {}",
            row.height
        );

        let weighted = u128::from(row.total_weighted_stake_lo)
            | (u128::from(row.total_weighted_stake_hi) << 64);
        let econ = LocalEconomics::with_params(params.clone(), ChainMirrorSource { weighted });

        // (2) pool_weighted_total round-trips the u128 lo/hi
        // reconstruction verbatim from the source.
        assert_eq!(
            econ.pool_weighted_total(),
            weighted,
            "pool_weighted_total @ height {}",
            row.height
        );

        // (3) burn_amount composes the shared `from_activity` path; the
        // recorded `burn_pct_bp` must be reproducible (Bug-2 class).
        let metric = ActivityMetric::new(
            row.tx_volume,
            row.circulating_supply,
            u128::from(row.total_staked),
            row.height,
        )
        .expect("fixture row is a valid ActivityMetric");
        let pct = calc_burn_pct_from_activity(
            row.tx_volume,
            params.tx_volume_baseline,
            row.circulating_supply,
            row.total_staked,
            &params,
        );
        assert_eq!(
            pct / 100,
            row.burn_pct_bp,
            "burn_pct_bp @ height {}",
            row.height
        );
        assert_eq!(
            econ.burn_amount(FEE, metric).unwrap(),
            mul_scale(FEE, pct),
            "burn_amount @ height {}",
            row.height
        );

        // (4) parameters_snapshot stamp lineage matches the resolved
        // params.
        let snap = econ.parameters_snapshot();
        assert_eq!(snap.as_of.generation, CALIBRATION_GENERATION);
        assert_eq!(snap.as_of.params_digest, params_digest(&params));
    }
}

#[test]
fn economics_differential_neutral_milestones_match_base_emission_at() {
    let fx = load_fixture();
    let params = EconomicParams::default();
    let econ = LocalEconomics::with_params(params, ChainMirrorSource { weighted: 0 });
    for m in &fx.neutral_milestones {
        assert_eq!(
            econ.base_emission_at(m.height).unwrap(),
            m.base_emission_at_neutral,
            "base_emission_at @ height {}",
            m.height
        );
    }
}

#[test]
fn economics_params_digest_round_trip() {
    let params = EconomicParams::default();
    let label = digest_label(&params_digest(&params));
    assert!(label.starts_with("blake2b:"));
    assert_eq!(label.len(), 8 + 64, "blake2b:<32-byte hex> is 72 chars");
    // Canonical encoder is deterministic across calls (§ digest.rs).
    assert_eq!(params_digest(&params), params_digest(&params));
}

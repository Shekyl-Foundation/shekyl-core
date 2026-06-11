use serde::Serialize;
use shekyl_economics::{
    base_block_reward,
    burn::{calc_burn_pct_from_activity, compute_burn_split},
    calc_burn_pct, calc_effective_emission_share, calc_release_multiplier,
    params::{calc_stake_ratio, EconomicParams, SCALE},
    release::apply_release_multiplier,
    split_block_emission,
};

#[derive(Debug, Clone, Serialize)]
pub struct YearSnapshot {
    pub year: u64,
    pub supply_emitted_pct: f64,
    pub block_reward_total: f64,
    pub block_reward_miner: f64,
    pub effective_burn_rate_pct: f64,
    pub staker_annual_yield_pct: f64,
    pub miner_income_pct_of_no_share: f64,
    pub total_burned: f64,
    pub circulating_supply: f64,
    pub stake_ratio_pct: f64,
    pub release_multiplier: f64,
    pub net_inflation_pct: f64,
    /// Derived archival-locked supply in coins (gate-7 scenarios only;
    /// absent — and skipped in JSON — on legacy asserted-stake scenarios).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_supply_coins: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub name: String,
    pub description: String,
    pub years: Vec<YearSnapshot>,
    pub final_supply_emitted_pct: f64,
    pub final_total_burned: f64,
    pub stuffing_profitable: Option<bool>,
}

pub struct VolumeSchedule {
    pub get_volume: Box<dyn Fn(u64, u64) -> u64>,
}

pub struct StakeSchedule {
    pub get_stake_ratio: Box<dyn Fn(u64, u64, u64) -> u64>,
}

/// Gate-7 derived archival-lock model (`STAKER_ARCHIVAL_SIM.md` §Iteration-5
/// scope). When present on a scenario, the asserted `StakeSchedule` is
/// ignored and locked supply is **derived** from the gate-4 bond floor:
///
/// ```text
/// locked(h) = bond_floor × replicas_per_shard × shards(h)  [+ admission_min × n_p]
/// shards(h) = genesis_shards + h / blocks_per_shard
/// ```
///
/// Per the pinned build constraint, the derived `stake_ratio` and the burn
/// input both denominate against the **consensus burn-site circulating**
/// (prev-block `already_generated`), matching the C4 recorder — not the
/// modeling loop's emitted-minus-burned gauge.
pub struct ArchivalLockModel {
    /// Per-shard-replica bonded collateral (gate-4 §8.1
    /// `ARCHIVAL_BOND_FLOOR_ATOMIC`; pinned 750_000_000).
    pub bond_floor_atomic: u64,
    /// Seated replicas per deep shard (`R_target`; L15 lean ≈ 6).
    pub replicas_per_shard: u64,
    /// Blocks of chain history per new deep shard. Shard segment geometry
    /// is **not yet consensus-pinned** (gate-2/3 `ShardId` wire open), so
    /// this is an explicit model parameter; default arm uses
    /// `SETTLEMENT_EPOCH_BLOCKS` (the staking sim's frontier-growth
    /// cadence), with a denser sensitivity arm.
    pub blocks_per_shard: u64,
    /// Bonded archiver population `N_P` (enters the admission arm only;
    /// L11 attractor envelope: lean ≈ 79, thick ≈ 154, fee-era-thin band
    /// 17–62).
    pub n_p: u64,
    /// Arm B hard admission lock per `P` (`ADMISSION_MIN_ATOMIC`
    /// candidate); `0` = arm A (bonds-only).
    pub admission_min_atomic: u64,
}

impl ArchivalLockModel {
    /// Total consensus-locked supply at height `h`, atomic units.
    #[must_use]
    pub fn locked_atomic(&self, height: u64) -> u128 {
        let shards = height.checked_div(self.blocks_per_shard).unwrap_or(0);
        u128::from(self.bond_floor_atomic)
            * u128::from(self.replicas_per_shard)
            * u128::from(shards)
            + u128::from(self.admission_min_atomic) * u128::from(self.n_p)
    }
}

pub struct ScenarioConfig {
    pub name: String,
    pub description: String,
    pub sim_years: u64,
    pub volume: VolumeSchedule,
    pub stake: StakeSchedule,
    pub fee_per_tx: u64,
    pub initial_emitted_fraction: f64,
    pub genesis_height_offset: u64,
    /// Gate-7 derived-lock model. `None` (all legacy scenarios) leaves the
    /// asserted `StakeSchedule` path byte-identical.
    pub archival_lock: Option<ArchivalLockModel>,
}

pub struct SimParams {
    pub money_supply: u64,
    pub emission_speed_factor_per_minute: u64,
    pub final_subsidy_per_minute: u64,
    pub blocks_per_year: u64,
    pub tx_volume_baseline: u64,
    pub release_min: u64,
    pub release_max: u64,
    pub burn_base_rate: u64,
    pub burn_cap: u64,
    pub staker_pool_share: u64,
    pub staker_emission_share: u64,
    pub staker_emission_decay: u64,
}

impl Default for SimParams {
    fn default() -> Self {
        Self {
            money_supply: 4_294_967_296_000_000_000,
            emission_speed_factor_per_minute: 22,
            final_subsidy_per_minute: 300_000_000,
            blocks_per_year: 262_800,
            tx_volume_baseline: 50,
            release_min: 800_000,
            release_max: 1_300_000,
            burn_base_rate: 500_000,
            burn_cap: 900_000,
            staker_pool_share: 250_000,
            staker_emission_share: 150_000,
            staker_emission_decay: 900_000,
        }
    }
}

const COIN: f64 = 1_000_000_000.0;

pub fn run_scenario(params: &SimParams, config: &ScenarioConfig) -> ScenarioResult {
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

    let mut already_generated: u128 =
        (params.money_supply as f64 * config.initial_emitted_fraction) as u128;
    let mut total_burned: u128 = 0;
    let mut staker_emission_earned_year: u128 = 0;
    let mut staker_fee_earned_year: u128 = 0;
    let mut year_start_circulating: u128 = 0;

    let mut snapshots = Vec::new();
    let money_supply = params.money_supply as u128;

    for block in 0..total_blocks {
        let year = block / params.blocks_per_year;
        let block_in_year = block % params.blocks_per_year;

        if block_in_year == 0 {
            staker_emission_earned_year = 0;
            staker_fee_earned_year = 0;
            year_start_circulating = already_generated.saturating_sub(total_burned);
        }

        let remaining = money_supply.saturating_sub(already_generated);
        let base_reward =
            base_block_reward(already_generated.min(u64::MAX as u128) as u64, &economic)
                .expect("sim neutral trajectory stays within supply bounds");

        let tx_volume = (config.volume.get_volume)(block, params.blocks_per_year);
        let circulating = (already_generated as u64).saturating_sub(total_burned as u64);
        // Consensus burn-site circulating: prev-block `already_generated`
        // alone, matching `validate_miner_transaction` / the C4 recorder
        // (pinned build constraint, STAKER_ARCHIVAL_SIM.md §Iteration-5).
        let circ_consensus = already_generated.min(u64::MAX as u128) as u64;
        let (stake_ratio, staked_atomic) = match &config.archival_lock {
            Some(model) => {
                let locked = model
                    .locked_atomic(block + config.genesis_height_offset)
                    .min(u128::from(circ_consensus)) as u64;
                (calc_stake_ratio(locked, circ_consensus), Some(locked))
            }
            None => (
                (config.stake.get_stake_ratio)(block, params.blocks_per_year, circulating),
                None,
            ),
        };

        let multiplier = calc_release_multiplier(
            tx_volume,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        );

        let mut effective_reward = apply_release_multiplier(base_reward, multiplier);
        let remaining_u64 = remaining.min(u64::MAX as u128) as u64;
        if effective_reward > remaining_u64 {
            effective_reward = remaining_u64;
        }

        let emission_share = calc_effective_emission_share(
            block + config.genesis_height_offset,
            0,
            params.staker_emission_share,
            params.staker_emission_decay,
            params.blocks_per_year,
        );

        let (miner_emission, staker_emission) =
            split_block_emission(effective_reward, emission_share);

        let total_fees_this_block = tx_volume as u128 * config.fee_per_tx as u128;
        let total_fees = total_fees_this_block.min(u64::MAX as u128) as u64;

        let burn_pct = match (&config.archival_lock, staked_atomic) {
            // Gate-7 path: the engine-equivalent composition over the
            // consensus circulating quantity (follows the recorder).
            (Some(_), Some(locked)) => calc_burn_pct_from_activity(
                tx_volume,
                params.tx_volume_baseline,
                circ_consensus,
                locked,
                &economic,
            ),
            // Legacy path: byte-identical to the pre-gate-7 modeling loop.
            _ => calc_burn_pct(
                tx_volume,
                params.tx_volume_baseline,
                circulating,
                params.money_supply,
                stake_ratio,
                params.burn_base_rate,
                params.burn_cap,
            ),
        };

        let fee_split = compute_burn_split(total_fees, burn_pct, params.staker_pool_share);

        already_generated += effective_reward as u128;
        if already_generated > money_supply {
            already_generated = money_supply;
        }
        total_burned += fee_split.actually_destroyed as u128;

        staker_emission_earned_year += staker_emission as u128;
        staker_fee_earned_year += fee_split.staker_pool_amount as u128;

        if block_in_year == params.blocks_per_year - 1 || block == total_blocks - 1 {
            let circ_now = already_generated.saturating_sub(total_burned) as f64 / COIN;
            let supply_emitted_pct = already_generated as f64 / money_supply as f64 * 100.0;

            let avg_block_reward = effective_reward as f64 / COIN;

            let staked_amount = match staked_atomic {
                Some(locked) => locked as f64 / COIN,
                None if stake_ratio > 0 && circulating > 0 => {
                    (circulating as u128 * stake_ratio as u128 / SCALE as u128) as f64 / COIN
                }
                None => 0.0,
            };

            let total_staker_income = staker_emission_earned_year + staker_fee_earned_year;
            let staker_yield = if staked_amount > 0.0 {
                total_staker_income as f64 / COIN / staked_amount * 100.0
            } else {
                0.0
            };

            let miner_no_share = effective_reward as f64;
            let miner_pct = if miner_no_share > 0.0 {
                miner_emission as f64 / miner_no_share * 100.0
            } else {
                100.0
            };

            let circ_start = year_start_circulating as f64 / COIN;
            let net_inflation = if circ_start > 0.0 {
                (circ_now - circ_start) / circ_start * 100.0
            } else {
                f64::INFINITY
            };

            snapshots.push(YearSnapshot {
                year,
                supply_emitted_pct,
                block_reward_total: avg_block_reward,
                block_reward_miner: miner_emission as f64 / COIN,
                effective_burn_rate_pct: burn_pct as f64 / SCALE as f64 * 100.0,
                staker_annual_yield_pct: staker_yield,
                miner_income_pct_of_no_share: miner_pct,
                total_burned: total_burned as f64 / COIN,
                circulating_supply: circ_now,
                stake_ratio_pct: stake_ratio as f64 / SCALE as f64 * 100.0,
                release_multiplier: multiplier as f64 / SCALE as f64,
                net_inflation_pct: if net_inflation.is_finite() {
                    net_inflation
                } else {
                    -1.0
                },
                locked_supply_coins: staked_atomic.map(|locked| locked as f64 / COIN),
            });
        }
    }

    ScenarioResult {
        name: config.name.clone(),
        description: config.description.clone(),
        final_supply_emitted_pct: already_generated as f64 / money_supply as f64 * 100.0,
        final_total_burned: total_burned as f64 / COIN,
        stuffing_profitable: None,
        years: snapshots,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        run_scenario, ArchivalLockModel, ScenarioConfig, SimParams, StakeSchedule, VolumeSchedule,
    };
    use serde_json::Value;

    fn tiny_lock_model(admission_min_atomic: u64) -> ArchivalLockModel {
        ArchivalLockModel {
            bond_floor_atomic: 750_000_000,
            replicas_per_shard: 6,
            blocks_per_shard: 100,
            n_p: 79,
            admission_min_atomic,
        }
    }

    #[test]
    fn locked_atomic_is_exact_integer_math() {
        let arm_a = tiny_lock_model(0);
        assert_eq!(arm_a.locked_atomic(0), 0);
        assert_eq!(arm_a.locked_atomic(99), 0);
        // one shard frozen: floor x replicas
        assert_eq!(arm_a.locked_atomic(100), 750_000_000u128 * 6);
        assert_eq!(arm_a.locked_atomic(1_000), 750_000_000u128 * 6 * 10);

        let arm_b = tiny_lock_model(750_000_000);
        // admission term is flat MIN x N_P on top of the bond term
        assert_eq!(arm_b.locked_atomic(0), 750_000_000u128 * 79);
        assert_eq!(
            arm_b.locked_atomic(100),
            750_000_000u128 * 6 + 750_000_000u128 * 79
        );
    }

    fn tiny_config(archival_lock: Option<ArchivalLockModel>) -> ScenarioConfig {
        ScenarioConfig {
            name: "tiny".into(),
            description: "test".into(),
            sim_years: 1,
            volume: VolumeSchedule {
                get_volume: Box::new(|_b, _bpy| 50),
            },
            stake: StakeSchedule {
                get_stake_ratio: Box::new(|_b, _bpy, _c| 250_000),
            },
            fee_per_tx: 100_000_000,
            initial_emitted_fraction: 0.0,
            genesis_height_offset: 0,
            archival_lock,
        }
    }

    #[test]
    fn gate7_path_reports_derived_lock_and_legacy_path_omits_it() {
        let params = SimParams {
            blocks_per_year: 10_000,
            ..SimParams::default()
        };

        let legacy = run_scenario(&params, &tiny_config(None));
        let last = legacy.years.last().expect("snapshot");
        assert_eq!(last.locked_supply_coins, None);
        // asserted schedule passes through untouched
        assert!((last.stake_ratio_pct - 25.0).abs() < 1e-9);

        let gate7 = run_scenario(&params, &tiny_config(Some(tiny_lock_model(0))));
        let last = gate7.years.last().expect("snapshot");
        let locked = last.locked_supply_coins.expect("derived lock reported");
        // snapshot at block 9_999: 99 shards x 6 replicas x 0.75 coin
        assert!((locked - 445.5).abs() < 1e-6);
        // derived ratio against multi-million-coin circulating is far below
        // the asserted 25%
        assert!(last.stake_ratio_pct < 0.01);
    }

    fn cfg_u64(cfg: &Value, key: &str) -> u64 {
        cfg.get(key)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("missing u64 key in economics config: {key}"))
    }

    #[test]
    fn sim_defaults_match_canonical_economics_config() {
        let cfg: Value =
            serde_json::from_str(include_str!("../../../config/economics_params.json"))
                .expect("economics_params.json must be valid JSON");
        let p = SimParams::default();

        assert_eq!(p.money_supply, cfg_u64(&cfg, "money_supply"));
        assert_eq!(
            p.emission_speed_factor_per_minute,
            cfg_u64(&cfg, "emission_speed_factor_per_minute")
        );
        assert_eq!(
            p.final_subsidy_per_minute,
            cfg_u64(&cfg, "final_subsidy_per_minute")
        );
        assert_eq!(p.blocks_per_year, cfg_u64(&cfg, "shekyl_blocks_per_year"));
        assert_eq!(
            p.tx_volume_baseline,
            cfg_u64(&cfg, "shekyl_tx_volume_baseline")
        );
        assert_eq!(p.release_min, cfg_u64(&cfg, "shekyl_release_min"));
        assert_eq!(p.release_max, cfg_u64(&cfg, "shekyl_release_max"));
        assert_eq!(p.burn_base_rate, cfg_u64(&cfg, "shekyl_burn_base_rate"));
        assert_eq!(p.burn_cap, cfg_u64(&cfg, "shekyl_burn_cap"));
        assert_eq!(
            p.staker_pool_share,
            cfg_u64(&cfg, "shekyl_staker_pool_share")
        );
        assert_eq!(
            p.staker_emission_share,
            cfg_u64(&cfg, "shekyl_staker_emission_share")
        );
        assert_eq!(
            p.staker_emission_decay,
            cfg_u64(&cfg, "shekyl_staker_emission_decay")
        );
    }
}

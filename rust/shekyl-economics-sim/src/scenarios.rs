use crate::engine::{ScenarioConfig, SimParams, StakeSchedule, VolumeSchedule};

fn default_stake_schedule() -> StakeSchedule {
    StakeSchedule {
        get_stake_ratio: Box::new(|block, blocks_per_year, _circ| {
            let year = block / blocks_per_year;
            match year {
                0 => 50_000,        // 5%
                1 => 100_000,       // 10%
                2..=4 => 150_000,   // 15%
                5..=9 => 200_000,   // 20%
                10..=14 => 250_000, // 25%
                15..=19 => 300_000, // 30%
                _ => 350_000,       // 35%
            }
        }),
    }
}

pub fn scenario_1_baseline(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "baseline_steady_state".into(),
        description: "Constant moderate transaction volume (1x baseline) over 10 years".into(),
        sim_years: 10,
        volume: VolumeSchedule {
            get_volume: Box::new(move |_block, _bpy| baseline),
        },
        stake: default_stake_schedule(),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_2_boom_bust(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "boom_bust_cycle".into(),
        description: "3x volume for 1 year, then 0.3x for 1 year, repeating over 10 years".into(),
        sim_years: 10,
        volume: VolumeSchedule {
            get_volume: Box::new(move |block, blocks_per_year| {
                let year = block / blocks_per_year;
                if year % 2 == 0 {
                    baseline * 3
                } else {
                    (baseline as f64 * 0.3) as u64
                }
            }),
        },
        stake: default_stake_schedule(),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_3_sustained_growth(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "sustained_growth".into(),
        description: "Volume increasing 20% per year for 20 years".into(),
        sim_years: 20,
        volume: VolumeSchedule {
            get_volume: Box::new(move |block, blocks_per_year| {
                let year = block / blocks_per_year;
                let growth = 1.2f64.powi(year as i32);
                (baseline as f64 * growth) as u64
            }),
        },
        stake: default_stake_schedule(),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_4_stuffing_attack(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "stuffing_attack".into(),
        description: "20% hash power miner generating 5x fake volume for 30 days (blocks 0-21600), then normal".into(),
        sim_years: 2,
        volume: VolumeSchedule {
            get_volume: Box::new(move |block, _bpy| {
                let attack_blocks = 21_600;
                if block < attack_blocks {
                    baseline * 5
                } else {
                    baseline
                }
            }),
        },
        stake: StakeSchedule {
            get_stake_ratio: Box::new(|_block, _bpy, _circ| 200_000),
        },
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_5_stake_concentration(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "stake_concentration".into(),
        description: "Single entity staking 30% of supply throughout 10 years".into(),
        sim_years: 10,
        volume: VolumeSchedule {
            get_volume: Box::new(move |_block, _bpy| baseline),
        },
        stake: StakeSchedule {
            get_stake_ratio: Box::new(|_block, _bpy, _circ| 300_000),
        },
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_6_mass_unstaking(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "mass_unstaking".into(),
        description: "80% of stakers unlock within one epoch (~35 days) at year 3".into(),
        sim_years: 5,
        volume: VolumeSchedule {
            get_volume: Box::new(move |_block, _bpy| baseline),
        },
        stake: StakeSchedule {
            get_stake_ratio: Box::new(|block, blocks_per_year, _circ| {
                let year = block / blocks_per_year;
                let block_in_year = block % blocks_per_year;
                if year < 3 {
                    250_000
                } else if year == 3 && block_in_year < 25_000 {
                    let progress = block_in_year as f64 / 25_000.0;
                    (250_000.0 * (1.0 - 0.8 * progress)) as u64
                } else if year == 3 {
                    50_000
                } else {
                    let recovery = (block_in_year as f64 / blocks_per_year as f64) * 150_000.0;
                    50_000 + recovery as u64
                }
            }),
        },
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_7_bootstrap(params: &SimParams) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    ScenarioConfig {
        name: "chain_bootstrap".into(),
        description:
            "First 2 years from genesis with very low organic transaction volume (10% of baseline)"
                .into(),
        sim_years: 5,
        volume: VolumeSchedule {
            get_volume: Box::new(move |block, blocks_per_year| {
                let year = block / blocks_per_year;
                match year {
                    0 => baseline / 10,
                    1 => baseline / 5,
                    2 => baseline / 2,
                    3 => baseline,
                    _ => baseline * 3 / 2,
                }
            }),
        },
        stake: StakeSchedule {
            get_stake_ratio: Box::new(|block, blocks_per_year, _circ| {
                let year = block / blocks_per_year;
                match year {
                    0 => 30_000,
                    1 => 80_000,
                    2 => 120_000,
                    3 => 180_000,
                    _ => 220_000,
                }
            }),
        },
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

pub fn scenario_8_late_tail(_params: &SimParams) -> ScenarioConfig {
    ScenarioConfig {
        name: "late_chain_tail".into(),
        description: "95%+ supply already emitted, high burn, fee-market-dominated economy over 5 years (starting at ~year 30)".into(),
        sim_years: 5,
        volume: VolumeSchedule {
            get_volume: Box::new(|block, blocks_per_year| {
                let year = block / blocks_per_year;
                match year {
                    0 => 200,
                    1 => 250,
                    2 => 180,
                    3 => 300,
                    _ => 220,
                }
            }),
        },
        stake: StakeSchedule {
            get_stake_ratio: Box::new(|_block, _bpy, _circ| 400_000),
        },
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.95,
        genesis_height_offset: 30 * 262_800, // ~year 30
    }
}

pub fn all_scenarios(params: &SimParams) -> Vec<ScenarioConfig> {
    vec![
        scenario_1_baseline(params),
        scenario_2_boom_bust(params),
        scenario_3_sustained_growth(params),
        scenario_4_stuffing_attack(params),
        scenario_5_stake_concentration(params),
        scenario_6_mass_unstaking(params),
        scenario_7_bootstrap(params),
        scenario_8_late_tail(params),
    ]
}

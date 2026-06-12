use crate::engine::{ArchivalLockModel, ScenarioConfig, SimParams, StakeSchedule, VolumeSchedule};
use shekyl_archival_retention::{ARCHIVAL_BOND_FLOOR_ATOMIC, SETTLEMENT_EPOCH_BLOCKS};

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
        archival_lock: None,
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
        archival_lock: None,
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
        archival_lock: None,
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
        archival_lock: None,
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
        archival_lock: None,
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
        archival_lock: None,
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
        archival_lock: None,
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
        archival_lock: None,
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

// ---------------------------------------------------------------------------
// Gate-7 locked-supply re-pricing (STAKER_ARCHIVAL_SIM.md §Iteration-5 scope).
//
// These scenarios replace the asserted `StakeSchedule` with the derived
// archival-lock model and run the full ~30-year mining-era horizon
// (timeframe 2). They are run via `--gate7` only; the legacy eight-scenario
// default output stays byte-identical.
// ---------------------------------------------------------------------------

/// Mining-era horizon for gate-7 arms (timeframe 2; ~30 years).
const GATE7_YEARS: u64 = 30;

/// `N_P` envelope from the L11 lean-equilibrium attractor (`bondA`
/// trajectories): lean fill ≈ 79, thick ≈ 154, fee-era-thinned band 17–62
/// (L13 servo band; midpoint 40 used here).
const NP_LEAN: u64 = 79;
const NP_THICK: u64 = 154;
const NP_THIN: u64 = 40;

/// Seated replicas per deep shard. Lean/thick arms hold full `R_target = 6`
/// coverage (L15); the fee-era-thin arm models partial deep coverage
/// (L13 shortfall ≈ 0.2 of target → ~4 seated replicas).
const R_FULL: u64 = 6;
const R_THIN: u64 = 4;

fn gate7_scenario(
    params: &SimParams,
    name: &str,
    description: &str,
    volume_growth: bool,
    model: ArchivalLockModel,
) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    let get_volume: Box<dyn Fn(u64, u64) -> u64> = if volume_growth {
        // Scenario-3 shape (20%/yr) stretched over the mining era: burn
        // sensitivity read under volume stress.
        Box::new(move |block, blocks_per_year| {
            let year = block / blocks_per_year;
            let growth = 1.2f64.powi(year.min(20) as i32);
            (baseline as f64 * growth) as u64
        })
    } else {
        Box::new(move |_block, _bpy| baseline)
    };
    ScenarioConfig {
        name: name.into(),
        description: description.into(),
        sim_years: GATE7_YEARS,
        volume: VolumeSchedule { get_volume },
        // Ignored when `archival_lock` is set; present to satisfy the config shape.
        stake: StakeSchedule {
            get_stake_ratio: Box::new(|_block, _bpy, _circ| 0),
        },
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
        archival_lock: Some(model),
    }
}

fn lock_model(
    replicas: u64,
    blocks_per_shard: u64,
    n_p: u64,
    admission_min: u64,
) -> ArchivalLockModel {
    ArchivalLockModel {
        bond_floor_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
        replicas_per_shard: replicas,
        blocks_per_shard,
        n_p,
        admission_min_atomic: admission_min,
    }
}

/// Comparator: the legacy asserted stake schedule over the same 30-year
/// horizon / baseline volume, so gauge deltas are read against the
/// assumption being re-priced rather than against a different horizon.
fn gate7_asserted_comparator(
    params: &SimParams,
    volume_growth: bool,
    name: &str,
) -> ScenarioConfig {
    let baseline = params.tx_volume_baseline;
    let get_volume: Box<dyn Fn(u64, u64) -> u64> = if volume_growth {
        Box::new(move |block, blocks_per_year| {
            let year = block / blocks_per_year;
            let growth = 1.2f64.powi(year.min(20) as i32);
            (baseline as f64 * growth) as u64
        })
    } else {
        Box::new(move |_block, _bpy| baseline)
    };
    ScenarioConfig {
        name: name.into(),
        description: "Comparator: legacy asserted stake schedule (5%→35%) over the gate-7 horizon"
            .into(),
        sim_years: GATE7_YEARS,
        volume: VolumeSchedule { get_volume },
        stake: default_stake_schedule(),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
        archival_lock: None,
    }
}

pub fn gate7_scenarios(params: &SimParams) -> Vec<ScenarioConfig> {
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let floor = ARCHIVAL_BOND_FLOOR_ATOMIC;
    vec![
        // Arm A (bonds-only) across the N_P envelope.
        gate7_scenario(
            params,
            "gate7_bonds_only_lean",
            "Arm A bonds-only; lean attractor (N_P=79, R=6, shard per SEB)",
            false,
            lock_model(R_FULL, seb, NP_LEAN, 0),
        ),
        gate7_scenario(
            params,
            "gate7_bonds_only_thick",
            "Arm A bonds-only; thick population (N_P=154, R=6)",
            false,
            lock_model(R_FULL, seb, NP_THICK, 0),
        ),
        gate7_scenario(
            params,
            "gate7_bonds_only_thin",
            "Arm A bonds-only; fee-era-thinned (N_P=40, R=4 partial deep coverage)",
            false,
            lock_model(R_THIN, seb, NP_THIN, 0),
        ),
        // Shard-geometry sensitivity: geometry is not consensus-pinned, so
        // show the read is robust to a 10x denser shard cadence.
        gate7_scenario(
            params,
            "gate7_bonds_only_lean_dense_shards",
            "Arm A bonds-only; 10x denser shard geometry (shard per 1_000 blocks)",
            false,
            lock_model(R_FULL, seb / 10, NP_LEAN, 0),
        ),
        // Arm B (hard admission lock) MIN grid, order-of-magnitude around the
        // bond floor, lean population.
        gate7_scenario(
            params,
            "gate7_admission_min_1x_lean",
            "Arm B hard lock; ADMISSION_MIN = 1x bond floor (0.75 coin) x N_P=79",
            false,
            lock_model(R_FULL, seb, NP_LEAN, floor),
        ),
        gate7_scenario(
            params,
            "gate7_admission_min_100x_lean",
            "Arm B hard lock; ADMISSION_MIN = 100x bond floor (75 coins) x N_P=79",
            false,
            lock_model(R_FULL, seb, NP_LEAN, floor * 100),
        ),
        gate7_scenario(
            params,
            "gate7_admission_min_10000x_lean",
            "Arm B hard lock; ADMISSION_MIN = 10_000x bond floor (7_500 coins) x N_P=79",
            false,
            lock_model(R_FULL, seb, NP_LEAN, floor * 10_000),
        ),
        // Volume-stress reads (burn gauge under load) for arm A and the
        // largest arm-B MIN.
        gate7_scenario(
            params,
            "gate7_bonds_only_lean_growth",
            "Arm A bonds-only; lean; 20%/yr volume growth (burn under load)",
            true,
            lock_model(R_FULL, seb, NP_LEAN, 0),
        ),
        gate7_scenario(
            params,
            "gate7_admission_min_10000x_lean_growth",
            "Arm B 10_000x MIN; lean; 20%/yr volume growth",
            true,
            lock_model(R_FULL, seb, NP_LEAN, floor * 10_000),
        ),
        // Comparators: the assumption being re-priced.
        gate7_asserted_comparator(params, false, "gate7_comparator_asserted_stake"),
        gate7_asserted_comparator(params, true, "gate7_comparator_asserted_stake_growth"),
    ]
}

//! FFI bridge between the C++ core and Rust modules.
//!
//! Exposes Rust functionality to C++ through a C-compatible ABI.
//! All public functions use `extern "C"` with `#[no_mangle]`.

use std::os::raw::c_char;
use std::sync::Mutex;

static CONSENSUS_REGISTRY: Mutex<Option<shekyl_consensus::ConsensusRegistry>> = Mutex::new(None);

// ─── Version / Init ─────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn shekyl_rust_version() -> *const c_char {
    static VERSION: &[u8] = b"2.0.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Initialize the Rust subsystem. Registers built-in consensus modules.
#[no_mangle]
pub extern "C" fn shekyl_rust_init() -> bool {
    let mut registry = shekyl_consensus::ConsensusRegistry::new();
    let randomx = shekyl_consensus::RandomXProof::new(120, 720);
    if registry.register(Box::new(randomx)).is_err() {
        return false;
    }
    if let Ok(mut guard) = CONSENSUS_REGISTRY.lock() {
        *guard = Some(registry);
    }
    true
}

/// Get the name of the active consensus module. Returns null-terminated C string.
#[no_mangle]
pub extern "C" fn shekyl_active_consensus_module() -> *const c_char {
    static RANDOMX: &[u8] = b"RandomX\0";
    static NONE: &[u8] = b"none\0";
    if let Ok(guard) = CONSENSUS_REGISTRY.lock() {
        if let Some(ref reg) = *guard {
            if reg.active().is_some() {
                return RANDOMX.as_ptr() as *const c_char;
            }
        }
    }
    NONE.as_ptr() as *const c_char
}

// ─── Economics: Release Rate ────────────────────────────────────────────────

/// Calculate the release multiplier from transaction volume.
///
/// Returns fixed-point value (SCALE=1_000_000). 1_000_000 = 1.0x.
#[no_mangle]
pub extern "C" fn shekyl_calc_release_multiplier(
    tx_volume_avg: u64,
    tx_volume_baseline: u64,
    release_min: u64,
    release_max: u64,
) -> u64 {
    shekyl_economics::release::calc_release_multiplier(
        tx_volume_avg,
        tx_volume_baseline,
        release_min,
        release_max,
    )
}

/// Apply a release multiplier to a base reward.
///
/// Returns: base_reward * multiplier / SCALE
#[no_mangle]
pub extern "C" fn shekyl_apply_release_multiplier(base_reward: u64, multiplier: u64) -> u64 {
    shekyl_economics::release::apply_release_multiplier(base_reward, multiplier)
}

// ─── Economics: Fee Burn ────────────────────────────────────────────────────

/// Calculate the burn percentage from chain state.
///
/// Returns fixed-point burn percentage (SCALE=1_000_000). 400_000 = 40%.
#[no_mangle]
pub extern "C" fn shekyl_calc_burn_pct(
    tx_volume: u64,
    tx_baseline: u64,
    circulating_supply: u64,
    total_supply: u64,
    stake_ratio: u64,
    burn_base_rate: u64,
    burn_cap: u64,
) -> u64 {
    shekyl_economics::burn::calc_burn_pct(
        tx_volume,
        tx_baseline,
        circulating_supply,
        total_supply,
        stake_ratio,
        burn_base_rate,
        burn_cap,
    )
}

/// Opaque result struct for the fee burn split, readable from C++.
#[repr(C)]
pub struct ShekylBurnSplit {
    pub miner_fee_income: u64,
    pub staker_pool_amount: u64,
    pub actually_destroyed: u64,
}

/// Compute the three-way fee split for a block.
#[no_mangle]
pub extern "C" fn shekyl_compute_burn_split(
    total_fees: u64,
    burn_pct: u64,
    staker_pool_share: u64,
) -> ShekylBurnSplit {
    let split =
        shekyl_economics::burn::compute_burn_split(total_fees, burn_pct, staker_pool_share);
    ShekylBurnSplit {
        miner_fee_income: split.miner_fee_income,
        staker_pool_amount: split.staker_pool_amount,
        actually_destroyed: split.actually_destroyed,
    }
}

// ─── Staking ────────────────────────────────────────────────────────────────

/// Compute the weighted stake for a single entry.
///
/// Returns: amount * yield_multiplier / SCALE
#[no_mangle]
pub extern "C" fn shekyl_stake_weight(amount: u64, tier_id: u8) -> u64 {
    use shekyl_staking::tiers::tier_by_id;
    let tier = match tier_by_id(tier_id) {
        Some(t) => t,
        None => return 0,
    };
    ((amount as u128 * tier.yield_multiplier as u128)
        / shekyl_economics::params::SCALE as u128) as u64
}

/// Get lock duration in blocks for a given tier.
///
/// Returns 0 if tier_id is invalid.
#[no_mangle]
pub extern "C" fn shekyl_stake_lock_blocks(tier_id: u8) -> u64 {
    use shekyl_staking::tiers::tier_by_id;
    match tier_by_id(tier_id) {
        Some(t) => t.lock_blocks,
        None => 0,
    }
}

/// Get the yield multiplier for a given tier (fixed-point SCALE).
///
/// Returns 0 if tier_id is invalid.
#[no_mangle]
pub extern "C" fn shekyl_stake_yield_multiplier(tier_id: u8) -> u64 {
    use shekyl_staking::tiers::tier_by_id;
    match tier_by_id(tier_id) {
        Some(t) => t.yield_multiplier,
        None => 0,
    }
}

/// Compute stake_ratio = total_staked / circulating_supply (fixed-point SCALE).
#[no_mangle]
pub extern "C" fn shekyl_calc_stake_ratio(total_staked: u64, circulating_supply: u64) -> u64 {
    if circulating_supply == 0 {
        return 0;
    }
    (total_staked as u128 * shekyl_economics::params::SCALE as u128
        / circulating_supply as u128) as u64
}

// ─── Emission Share (Component 4) ───────────────────────────────────────────

/// Calculate the effective staker emission share at a given block height.
///
/// Returns fixed-point SCALE value (e.g., 150_000 = 15%).
#[no_mangle]
pub extern "C" fn shekyl_calc_emission_share(
    current_height: u64,
    genesis_height: u64,
    initial_share: u64,
    annual_decay: u64,
    blocks_per_year: u64,
) -> u64 {
    shekyl_economics::emission_share::calc_effective_emission_share(
        current_height,
        genesis_height,
        initial_share,
        annual_decay,
        blocks_per_year,
    )
}

/// Split block emission between miner and staker pool.
#[repr(C)]
pub struct ShekylEmissionSplit {
    pub miner_emission: u64,
    pub staker_emission: u64,
}

#[no_mangle]
pub extern "C" fn shekyl_split_block_emission(
    block_emission: u64,
    effective_share: u64,
) -> ShekylEmissionSplit {
    let (miner, staker) =
        shekyl_economics::emission_share::split_block_emission(block_emission, effective_share);
    ShekylEmissionSplit {
        miner_emission: miner,
        staker_emission: staker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let ptr = shekyl_rust_version();
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(s.to_str().unwrap(), "2.0.0");
    }

    #[test]
    fn test_release_multiplier_ffi() {
        let m = shekyl_calc_release_multiplier(100, 100, 800_000, 1_300_000);
        assert_eq!(m, 1_000_000);
    }

    #[test]
    fn test_burn_split_ffi() {
        let split = shekyl_compute_burn_split(1_000_000_000, 400_000, 200_000);
        assert_eq!(split.miner_fee_income, 600_000_000);
        assert_eq!(split.staker_pool_amount, 80_000_000);
        assert_eq!(split.actually_destroyed, 320_000_000);
    }

    #[test]
    fn test_stake_weight_ffi() {
        assert_eq!(shekyl_stake_weight(1_000_000_000, 0), 1_000_000_000); // 1.0x
        assert_eq!(shekyl_stake_weight(1_000_000_000, 2), 2_000_000_000); // 2.0x
        assert_eq!(shekyl_stake_weight(1_000_000_000, 99), 0); // invalid tier
    }

    #[test]
    fn test_stake_ratio_ffi() {
        let ratio = shekyl_calc_stake_ratio(500_000_000, 1_000_000_000);
        assert_eq!(ratio, 500_000); // 0.5
    }

    #[test]
    fn test_emission_share_genesis() {
        let share = shekyl_calc_emission_share(0, 0, 150_000, 900_000, 262_800);
        assert_eq!(share, 150_000);
    }

    #[test]
    fn test_emission_share_year_1() {
        let share = shekyl_calc_emission_share(262_800, 0, 150_000, 900_000, 262_800);
        assert_eq!(share, 135_000);
    }

    #[test]
    fn test_emission_split_ffi() {
        let split = shekyl_split_block_emission(1_000_000_000, 150_000);
        assert_eq!(split.staker_emission, 150_000_000);
        assert_eq!(split.miner_emission, 850_000_000);
    }
}

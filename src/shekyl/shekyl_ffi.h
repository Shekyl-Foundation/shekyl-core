// C++ declarations for functions exported by the Rust shekyl-ffi crate.
// Link against libshekyl_ffi.a to resolve these symbols.

#pragma once

#include <cstdint>

extern "C" {

// Version / init
const char* shekyl_rust_version();
bool shekyl_rust_init();
const char* shekyl_active_consensus_module();

// Release rate
uint64_t shekyl_calc_release_multiplier(
    uint64_t tx_volume_avg,
    uint64_t tx_volume_baseline,
    uint64_t release_min,
    uint64_t release_max);

uint64_t shekyl_apply_release_multiplier(
    uint64_t base_reward,
    uint64_t multiplier);

// Fee burn
uint64_t shekyl_calc_burn_pct(
    uint64_t tx_volume,
    uint64_t tx_baseline,
    uint64_t circulating_supply,
    uint64_t total_supply,
    uint64_t stake_ratio,
    uint64_t burn_base_rate,
    uint64_t burn_cap);

struct ShekylBurnSplit {
    uint64_t miner_fee_income;
    uint64_t staker_pool_amount;
    uint64_t actually_destroyed;
};

ShekylBurnSplit shekyl_compute_burn_split(
    uint64_t total_fees,
    uint64_t burn_pct,
    uint64_t staker_pool_share);

// Staking
uint64_t shekyl_stake_weight(uint64_t amount, uint8_t tier_id);
uint64_t shekyl_stake_lock_blocks(uint8_t tier_id);
uint64_t shekyl_stake_yield_multiplier(uint8_t tier_id);
uint64_t shekyl_calc_stake_ratio(uint64_t total_staked, uint64_t circulating_supply);

} // extern "C"

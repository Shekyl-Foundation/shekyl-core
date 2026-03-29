// C++ declarations for functions exported by the Rust shekyl-ffi crate.
// Link against libshekyl_ffi.a to resolve these symbols.

#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

// Version / init
const char* shekyl_rust_version();
bool shekyl_rust_init();
const char* shekyl_active_consensus_module();

// Generic Rust-owned buffer
struct ShekylBuffer {
    uint8_t* ptr;
    size_t len;
};

void shekyl_buffer_free(uint8_t* ptr, size_t len);

// PQC: Hybrid signatures
struct ShekylPqcKeypair {
    ShekylBuffer public_key;
    ShekylBuffer secret_key;
    bool success;
};

struct ShekylPqcSignatureResult {
    ShekylBuffer signature;
    bool success;
};

ShekylPqcKeypair shekyl_pqc_keypair_generate();
ShekylPqcSignatureResult shekyl_pqc_sign(
    const uint8_t* secret_key_ptr,
    size_t secret_key_len,
    const uint8_t* message_ptr,
    size_t message_len);
bool shekyl_pqc_verify(
    const uint8_t* public_key_ptr,
    size_t public_key_len,
    const uint8_t* message_ptr,
    size_t message_len,
    const uint8_t* signature_ptr,
    size_t signature_len);

// Crypto: Hash functions
bool shekyl_cn_fast_hash(
    const uint8_t* data_ptr,
    size_t data_len,
    uint8_t* out_ptr);

bool shekyl_tree_hash(
    const uint8_t* hashes_ptr,
    size_t count,
    uint8_t* out_ptr);

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

// Emission share (Component 4)
uint64_t shekyl_calc_emission_share(
    uint64_t current_height,
    uint64_t genesis_height,
    uint64_t initial_share,
    uint64_t annual_decay,
    uint64_t blocks_per_year);

struct ShekylEmissionSplit {
    uint64_t miner_emission;
    uint64_t staker_emission;
};

ShekylEmissionSplit shekyl_split_block_emission(
    uint64_t block_emission,
    uint64_t effective_share);

} // extern "C"

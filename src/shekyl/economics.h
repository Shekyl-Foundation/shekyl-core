// Shekyl four-component economics helpers for C++ consensus code.
// Wraps FFI calls to the Rust shekyl-economics crate.

#pragma once

#include <cstdint>
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl {

// ─── Component 2: Fee Burn ──────────────────────────────────────────────────

struct BurnResult {
    uint64_t miner_fee_income;
    uint64_t staker_pool_amount;
    uint64_t actually_destroyed;
};

inline BurnResult compute_fee_burn(
    uint64_t total_fees,
    uint64_t tx_volume,
    uint64_t circulating_supply,
    uint64_t stake_ratio,
    uint8_t hf_version)
{
    if (hf_version < HF_VERSION_SHEKYL_NG || total_fees == 0)
    {
        return {total_fees, 0, 0};
    }

    uint64_t burn_pct = shekyl_calc_burn_pct(
        tx_volume,
        SHEKYL_TX_VOLUME_BASELINE,
        circulating_supply,
        MONEY_SUPPLY,
        stake_ratio,
        SHEKYL_BURN_BASE_RATE,
        SHEKYL_BURN_CAP);

    ShekylBurnSplit split = shekyl_compute_burn_split(
        total_fees, burn_pct, SHEKYL_STAKER_POOL_SHARE);

    return {split.miner_fee_income, split.staker_pool_amount, split.actually_destroyed};
}

// ─── Component 4: Emission Share ────────────────────────────────────────────

struct EmissionSplit {
    uint64_t miner_emission;
    uint64_t staker_emission;
};

inline EmissionSplit compute_emission_split(
    uint64_t block_emission,
    uint64_t current_height,
    uint64_t genesis_ng_height,
    uint8_t hf_version)
{
    if (hf_version < HF_VERSION_SHEKYL_NG || block_emission == 0)
    {
        return {block_emission, 0};
    }

    uint64_t effective_share = shekyl_calc_emission_share(
        current_height,
        genesis_ng_height,
        SHEKYL_STAKER_EMISSION_SHARE,
        SHEKYL_STAKER_EMISSION_DECAY,
        SHEKYL_BLOCKS_PER_YEAR);

    ShekylEmissionSplit split = shekyl_split_block_emission(
        block_emission, effective_share);

    return {split.miner_emission, split.staker_emission};
}

} // namespace shekyl

// Shekyl three-component economics helpers for C++ consensus code.
// Wraps FFI calls to the Rust shekyl-economics crate.

#pragma once

#include <cstdint>
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl {

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

} // namespace shekyl

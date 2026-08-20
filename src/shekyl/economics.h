// Shekyl four-component economics helpers for C++ consensus code.
// Wraps FFI calls to the Rust shekyl-economics crate.
//
// NO HARD-FORK GATING LIVES HERE, and the absence is deliberate. Both
// helpers used to open with `if (hf_version < HF_VERSION_SHEKYL_NG || …)`.
// That arm was unreachable on every network:
//
//   * HF_VERSION_SHEKYL_NG is 1 (cryptonote_config.h);
//   * mainnet/testnet/stagenet each declare exactly ONE fork entry,
//     `{ version 1, height 1, … }` (hardforks.cpp);
//   * blocks below the first fork take HardFork's `original_version`, which
//     all three Blockchain constructions pass as 1, and
//     CURRENT_BLOCK_MAJOR_VERSION is 1;
//   * construct_miner_tx defaults hard_fork_version to 1, and no caller
//     anywhere passes 0.
//
// So `hf_version < 1` was never true, and the `hf_version` parameters those
// branches justified are gone with them (rules 15 and 60: v3-from-genesis
// carries no pre-genesis ladder). Core tests that cross v1 -> v2 are
// unaffected — 2 >= 1 selected the same arm.
//
// REOPENING CRITERION (rule 21): a future hard fork that changes economics
// SEMANTICS reintroduces gating. When it does, the gate belongs in
// shekyl-economics next to the math it selects, per rule 20 — not as a new
// C++ branch here. Re-adding a parameter now to "keep the option open" is
// the pre-provisioned flexibility rule 21 rejects.

#pragma once

#include <cstdint>
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl {

// ─── Base block subsidy (0h) ────────────────────────────────────────────────
//
// There is no wrapper here any more. `base_subsidy_before_penalty` existed
// solely for `get_block_reward`, which now marshals the whole subsidy +
// weight-penalty calculation to `shekyl_block_reward` in one call. Callers
// that want the raw base curve call `shekyl_base_block_reward` directly, as
// the C2a′ KATs do.

// ─── Component 2: Fee Burn ──────────────────────────────────────────────────

struct BurnResult {
    uint64_t miner_fee_income;
    uint64_t staker_pool_amount;
    uint64_t actually_destroyed;
};

// frozen_segment_count is the D2 escalation operand n, read at PARENT-block
// state (Blockchain::parent_frozen_segment_count is the asserting read-point;
// see the FFI contract on shekyl_compute_burn_split_escalated). The share it
// selects is Rust-owned — derived in shekyl-economics from the shipped
// EconomicParams — so no share constant crosses this boundary.
inline BurnResult compute_fee_burn(
    uint64_t total_fees,
    uint64_t tx_volume,
    uint64_t circulating_supply,
    uint64_t frozen_segment_count)
{
    if (total_fees == 0)
    {
        return {total_fees, 0, 0};
    }

    uint64_t burn_pct = shekyl_calc_burn_pct(
        tx_volume,
        SHEKYL_TX_VOLUME_BASELINE,
        circulating_supply,
        MONEY_SUPPLY,
        SHEKYL_BURN_BASE_RATE,
        SHEKYL_BURN_CAP);

    ShekylBurnSplit split = shekyl_compute_burn_split_escalated(
        total_fees, burn_pct, frozen_segment_count);

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
    uint64_t genesis_ng_height)
{
    if (block_emission == 0)
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

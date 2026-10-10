// Shekyl four-component economics helpers for C++ consensus code.
// Wraps FFI calls to the Rust shekyl-economics crate.
//
// No version gating lives here. The block version is the constant 1 and
// these helpers take no version; the split epoch and the share constants
// are shekyl-economics' (rule 20).

#pragma once

#include <cstdint>
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_ffi.h"
#include "shekyl/tx_volume_window.h"

namespace shekyl {

// ─── Base block subsidy (0h) ────────────────────────────────────────────────
//
// There is no wrapper here any more. `base_subsidy_before_penalty` existed
// solely for `get_block_reward`, which now marshals the whole subsidy +
// weight-penalty calculation to `shekyl_block_reward` in one call. Callers
// that want the raw base curve call `shekyl_base_block_reward` directly, as
// the C2a′ KATs do.

// ─── Component 2: Fee Burn ──────────────────────────────────────────────────
//
// MARSHALING ONLY. Until E6 slice 4's precursor (CHAIN_RULES_SLICE_4.md
// §3.1 S1/S3/S15) this helper owned rule content: the zero-fee arm decided
// the burn outcome before any Rust ran, the pct→split composition was C++'s,
// and every caller defined the supply operand as `already_generated_coins`
// — gross emission ignoring burn, the definitional bug FL-R16c
// (FEE_LADDER_DERIVATION.md §8, review round 4) bound the implementing PR
// to correct. All of it is shekyl-economics::compute_fee_burn now. What
// crosses here is FACTS: the fee sum, the exact volume window, the two store
// facts the supply derives from, and the escalation operand — each read at
// PARENT-block state (Blockchain::parent_frozen_segment_count is the
// asserting read-point for n; coins_generated and total_burned come from
// the same pre-add_block state).

struct BurnResult {
    uint64_t miner_fee_income;
    uint64_t staker_pool_amount;
    uint64_t actually_destroyed;
};

// The two store facts circulating supply is DERIVED from (FL-R16c):
// circulating_supply = coins_generated − total_burned, computed in Rust,
// checked. C++ reads; Rust derives. No C++ code may subtract these two
// fields or define the supply another way — that is the two-site defect
// this struct replaces.
struct supply_facts
{
  uint64_t coins_generated = 0;
  uint64_t total_burned = 0;
};

inline BurnResult compute_fee_burn(
    uint64_t total_fees,
    tx_volume_window tx_volume,
    supply_facts supply,
    uint64_t frozen_segment_count)
{
    ShekylBurnSplit split{};
    const int32_t st = shekyl_compute_fee_burn(
        total_fees,
        tx_volume.tx_count_sum,
        tx_volume.blocks,
        supply.coins_generated,
        supply.total_burned,
        frozen_segment_count,
        &split);
    // A supply underflow is a store-invariant violation (total_burned above
    // coins_generated): halt, never proceed on a zero the burn would read as
    // "nothing emitted".
    CHECK_AND_ASSERT_THROW_MES(st == SHEKYL_ECONOMICS_OK,
        "shekyl_compute_fee_burn refused (status " << st << "): total_burned "
        << supply.total_burned << " vs coins_generated " << supply.coins_generated);
    return {split.miner_fee_income, split.staker_pool_amount, split.actually_destroyed};
}

// ─── Component 4: Emission Split ────────────────────────────────────────────
//
// MARSHALING ONLY (S4/S5/S6): the zero-emission arm, the share→split
// composition and the three constants are shekyl-economics'.

struct EmissionSplit {
    uint64_t miner_emission;
    uint64_t staker_emission;
};

inline EmissionSplit compute_emission_split(
    uint64_t block_emission,
    uint64_t current_height)
{
    const ShekylEmissionSplit split =
        shekyl_compute_emission_split(block_emission, current_height);
    return {split.miner_emission, split.staker_emission};
}

} // namespace shekyl

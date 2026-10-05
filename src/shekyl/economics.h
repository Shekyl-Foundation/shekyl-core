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
// So no version below HF_VERSION_SHEKYL_NG can reach these helpers, and the
// `hf_version` parameters those branches justified are gone with them (rules
// 15 and 60: v3-from-genesis carries no pre-genesis ladder). Core tests that
// cross v1 -> v2 are unaffected — version 2 selects the same arm.
//
// Deliberately phrased without the comparison spelled out as code. The
// consensus-invariants workflow greps `src/` for legacy version branches as
// TEXT, so a comment quoting the retired expression trips a gate that is
// otherwise exactly right to be strict. Describe the retired branch; do not
// reproduce it.
//
// REOPENING CRITERION (rule 21): a future hard fork that changes economics
// SEMANTICS reintroduces gating. When it does, the gate belongs in
// shekyl-economics next to the math it selects, per rule 20 — not as a new
// C++ branch here. Re-adding a parameter now to "keep the option open" is
// the pre-provisioned flexibility rule 21 rejects.

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
    uint64_t current_height,
    uint64_t genesis_ng_height)
{
    const ShekylEmissionSplit split =
        shekyl_compute_emission_split(block_emission, current_height, genesis_ng_height);
    return {split.miner_emission, split.staker_emission};
}

} // namespace shekyl

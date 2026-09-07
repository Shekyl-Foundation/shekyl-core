// Copyright (c) 2025-2026, The Shekyl Foundation
//
// C2a′ Layer 1/2 harness — STAGE_1_PR_7 §5.8 (7-base).
//
// WHAT THIS FILE IS. Two different things live here, and conflating them is
// what made the old names mislead:
//
//   1. CALL-PATH tests (`…CallPathMatchesFfiPrimitive…`). These drive the
//      production C++ entry points and cross-check them against the Rust FFI
//      primitives those entry points wrap. They validate the FFI boundary and
//      the generated-constant wiring — NOT economics math, which has no C++
//      implementation to test. `src/shekyl/economics.h` is a 97-line header
//      that delegates every calculation to `shekyl-economics`, and the
//      constants come from `config/economics_params.json` via
//      `economics_params_generated.h`. There is one implementation; these
//      tests check that C++ reaches it correctly and with the right operands.
//
//      They were previously named `…LegAMatchesRust`, which reads as "C++
//      implementation vs Rust implementation" and is why "why is C++ testing
//      economics?" kept being asked. Leg A is Rust underneath.
//
//   2. The PINNED weight-penalty vectors below. These are the one part of
//      this file that pins VALUES rather than agreement, and the one part
//      that covers arithmetic C++ still genuinely performs.
//
// WHERE LEG B IS. Leg A/B is a dual-oracle design (§5.8: "if leg A and leg B
// disagree, that is a consensus bug found pre-cutover"), but the two legs are
// not both in this file — leg B is `shekyl-economics-sim`, run by
// `scripts/ci/run_economics_c2a_prime.sh` as a separate `cargo test` step.
// Nothing here compares leg A to leg B.
//
// NAMING CONTRACT: the gate selects by `EconomicsC2aPrime.Layer1*` /
// `Layer2*`. The suite name and the `LayerN` prefix are load-bearing — a
// rename across them silently empties the filter, and only the gate's
// zero-count check (rule 47) would catch it.

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

namespace {

constexpr size_t kStandardBlockWeight =
    CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2;

TEST(EconomicsC2aPrime, Layer1SubsidyBaseCallPathMatchesFfiPrimitive) {
  const uint64_t grid[] = {
      0,
      UINT64_C(2048000000000),
      UINT64_C(2756434948434199641),
  };

  for (const uint64_t already_generated : grid) {
    uint64_t cpp_reward = 0;
    ASSERT_TRUE(get_block_reward(
        0, kStandardBlockWeight, already_generated, cpp_reward, 1));
    const uint64_t rust_base = shekyl_base_block_reward(already_generated);
    EXPECT_EQ(cpp_reward, rust_base) << "already_generated=" << already_generated;
  }
}

TEST(EconomicsC2aPrime, Layer1SubsidyWithReleaseCallPathMatchesFfiPrimitives) {
  const uint64_t grid[] = {0, UINT64_C(2048000000000)};

  for (const uint64_t already_generated : grid) {
    uint64_t cpp_reward = 0;
    ASSERT_TRUE(get_block_reward(
        0,
        kStandardBlockWeight,
        already_generated,
        cpp_reward,
        1,
        SHEKYL_TX_VOLUME_BASELINE));

    // FL-R12': the release multiplier composes INSIDE the one owner
    // (shekyl_block_reward); at baseline volume it is exactly 1, so the
    // M_r-neutral cross-check is the base primitive directly.
    const uint64_t rust_base = shekyl_base_block_reward(already_generated);
    EXPECT_EQ(cpp_reward, rust_base) << "already_generated=" << already_generated;
  }
}

TEST(EconomicsC2aPrime, Layer1PerQuantityCallPathComposesSplitAndCoinbase) {
  // Layer-1 leg A (STAGE_1_PR_7 §5.8) — per-quantity coverage for the derived
  // emission quantities beyond Q_subsidy: Q_full_emission →
  // {Q_miner_base, Q_staker_emission} → Q_miner_coinbase. Composes via the
  // production C++ helpers (compute_emission_split / compute_fee_burn) and
  // cross-checks them against the Rust FFI primitives those helpers wrap.
  const uint64_t ag_grid[] = {
      0, UINT64_C(2048000000000), UINT64_C(2756434948434199641)};
  const uint64_t height_grid[] = {1, 131400, 262800, 1314000};

  for (const uint64_t ag : ag_grid) {
    // Q_subsidy → Q_full_emission (release applied at empty-block volume 0).
    uint64_t q_full = 0;
    ASSERT_TRUE(get_block_reward(
        0, kStandardBlockWeight, ag, q_full, 1, /*tx_volume_avg=*/0));

    for (const uint64_t height : height_grid) {
      // Q_miner_base / Q_staker_emission via the production split.
      const shekyl::EmissionSplit split =
          shekyl::compute_emission_split(q_full, height, /*genesis_ng_height=*/0);
      const uint64_t q_miner_base = split.miner_emission;
      const uint64_t q_staker_emission = split.staker_emission;

      // Cross-check against the Rust FFI primitives the helper wraps.
      const uint64_t share = shekyl_calc_emission_share(
          height, 0, SHEKYL_STAKER_EMISSION_SHARE, SHEKYL_STAKER_EMISSION_DECAY,
          SHEKYL_BLOCKS_PER_YEAR);
      const ShekylEmissionSplit rust_split =
          shekyl_split_block_emission(q_full, share);
      EXPECT_EQ(q_miner_base, rust_split.miner_emission)
          << "ag=" << ag << " h=" << height;
      EXPECT_EQ(q_staker_emission, rust_split.staker_emission)
          << "ag=" << ag << " h=" << height;

      // Conservation: the split redistributes within Q_full_emission.
      EXPECT_EQ(q_miner_base + q_staker_emission, q_full)
          << "ag=" << ag << " h=" << height;

      // Q_miner_coinbase = Q_miner_base + miner fee income; fee-free collapses
      // to Q_miner_base (the Layer-3 empty-block scenario). Pin the fee-burn
      // legs to zero independently so the coinbase collapse is a real check:
      // a regression where compute_fee_burn returned a nonzero miner leg for
      // zero fees would now fail here rather than pass tautologically.
      const shekyl::BurnResult no_fee = shekyl::compute_fee_burn(0, 0, ag, /*frozen_segment_count=*/0);
      EXPECT_EQ(no_fee.miner_fee_income, UINT64_C(0))
          << "fee-free miner leg nonzero: ag=" << ag << " h=" << height;
      EXPECT_EQ(no_fee.staker_pool_amount, UINT64_C(0))
          << "fee-free staker pool nonzero: ag=" << ag << " h=" << height;
      EXPECT_EQ(no_fee.actually_destroyed, UINT64_C(0))
          << "fee-free burn nonzero: ag=" << ag << " h=" << height;
      const uint64_t q_miner_coinbase = q_miner_base + no_fee.miner_fee_income;
      EXPECT_EQ(q_miner_coinbase, q_miner_base)
          << "fee-free coinbase != Q_miner_base: ag=" << ag << " h=" << height;
    }
  }
}

TEST(EconomicsC2aPrime, Layer2FullEmissionAccumulationCallPathMatchesFfiPrimitive) {
  uint64_t ag_cpp = 0;
  uint64_t ag_rust = 0;

  for (unsigned height = 0; height < 1000; ++height) {
    uint64_t q_sub = 0;
    ASSERT_TRUE(get_block_reward(
        0,
        kStandardBlockWeight,
        ag_cpp,
        q_sub,
        1,
        SHEKYL_TX_VOLUME_BASELINE));

    // FL-R12': multiplier inside the one owner; 1 at baseline.
    const uint64_t q_rust = shekyl_base_block_reward(ag_rust);
    ASSERT_EQ(q_sub, q_rust);

    // No asymptote clamp (FL-R12': the accumulator passes through it;
    // these 1000 blocks never approach it anyway).
    ag_cpp += q_sub;
    ag_rust += q_rust;
  }

  EXPECT_EQ(ag_cpp, ag_rust);
}

TEST(EconomicsC2aPrime, Layer2MinerOnlyAccumulationDiffersFromFullEmission) {
  uint64_t ag_full = 0;
  uint64_t ag_miner = 0;

  for (unsigned height = 1; height <= 100; ++height) {
    uint64_t q_sub = 0;
    ASSERT_TRUE(get_block_reward(
        0, kStandardBlockWeight, ag_full, q_sub, 1, SHEKYL_TX_VOLUME_BASELINE));

    const shekyl::EmissionSplit split =
        shekyl::compute_emission_split(q_sub, height, 0);

    ag_full = std::min<uint64_t>(MONEY_SUPPLY, ag_full + q_sub);
    ag_miner = std::min<uint64_t>(MONEY_SUPPLY, ag_miner + split.miner_emission);
  }

  EXPECT_LT(ag_miner, ag_full);
}


// ─── Weight-penalty pinned vectors (transition KAT) ─────────────────────────
//
// WHY THIS EXISTS. The weight penalty in `get_block_reward`
// (cryptonote_basic_impl.cpp) is the last piece of economics ARITHMETIC that
// C++ still performs itself: `mul128` plus two `div128_64`, on an amount.
// Everything around it delegates to `shekyl-economics`. When it moves behind
// the FFI, this table is what proves the move changed no value.
//
// It is pinned because nothing else in the tree pins it:
//
//   * Every other C2a′ input sits where the penalty is IDENTITY. The other
//     tests here use median_weight = 0 (clamped up to the 300000 zone) with a
//     150000 block, so `current <= median` returns the base reward before
//     reaching `mul128`. The penalty branch was executed by no C2a′ test.
//   * `tests/unit_tests/block_reward.cpp` walks a good weight grid but its
//     assertions are purely RELATIONAL (`ASSERT_LT(reward, standard_reward)`)
//     against its own output, with already_generated_coins fixed at 0. A port
//     that truncated differently would satisfy every one of them.
//
// DERIVATION (two independent sources, required to agree). The expected values
// were computed in arbitrary-precision integer arithmetic from the documented
// formula — base = max((MONEY_SUPPLY - ag) >> esf, tail) with esf = 21 and
// tail = 600000000 for the 120 s DAA target, then
// reward = base * (2m - c) * c / m / m — and are asserted here against the
// C++ implementation. They are NOT transcribed from C++ output: if the
// derivation and the implementation disagree, this test fails, which is the
// point. `base(0) = 2048000000000` cross-checks the value already used as a
// grid operand in the tests above.
//
// WHAT DISCRIMINATES. The 128-bit intermediate is the real target: for the
// 2100000-median rows, base * multiplicand is ~6.8e24, far past u64, so a port
// that multiplies in 64 bits is caught by any penalty-bearing row. Note that
// division ORDER is not a discriminant — floor(floor(x/m)/m) == floor(x/(m*m))
// for positive integers, so the two-step divide is an identity, not a choice.
// The median = 0 rows pin the "make it soft" clamp itself: drop the clamp and
// only those rows move. The 2m and 2m+1 rows pin the zero-reward boundary and
// the block-REJECTION arm, which is consensus behaviour and must survive a
// port that has to decide how fallibility crosses the FFI.
//
// WHEN THE PENALTY MOVES TO RUST, this exact table lands as a `#[test]` in
// `shekyl-economics` as well. Vectors asserted only from C++ die with the C++
// tests; a cross-language KAT is what actually pins the contract.
struct WeightPenaltyVector {
    size_t median_weight;
    size_t current_block_weight;
    uint64_t already_generated_coins;
    bool expect_ok;
    uint64_t expect_reward; // meaningless when expect_ok is false
};

constexpr WeightPenaltyVector kWeightPenaltyVectors[] = {
    {0, 150000, UINT64_C(0), true, UINT64_C(2048000000000)},
    {0, 150000, UINT64_C(2048000000000), true, UINT64_C(2047999023437)},
    {0, 150000, UINT64_C(2756434948434199641), true, UINT64_C(733629392416)},
    {0, 300000, UINT64_C(0), true, UINT64_C(2048000000000)},
    {0, 300000, UINT64_C(2048000000000), true, UINT64_C(2047999023437)},
    {0, 300000, UINT64_C(2756434948434199641), true, UINT64_C(733629392416)},
    {0, 300001, UINT64_C(0), true, UINT64_C(2047999999977)},
    {0, 300001, UINT64_C(2048000000000), true, UINT64_C(2047999023414)},
    {0, 300001, UINT64_C(2756434948434199641), true, UINT64_C(733629392407)},
    {0, 337500, UINT64_C(0), true, UINT64_C(2016000000000)},
    {0, 337500, UINT64_C(2048000000000), true, UINT64_C(2015999038695)},
    {0, 337500, UINT64_C(2756434948434199641), true, UINT64_C(722166433159)},
    {0, 450000, UINT64_C(0), true, UINT64_C(1536000000000)},
    {0, 450000, UINT64_C(2048000000000), true, UINT64_C(1535999267577)},
    {0, 450000, UINT64_C(2756434948434199641), true, UINT64_C(550222044312)},
    {0, 562500, UINT64_C(0), true, UINT64_C(480000000000)},
    {0, 562500, UINT64_C(2048000000000), true, UINT64_C(479999771118)},
    {0, 562500, UINT64_C(2756434948434199641), true, UINT64_C(171944388847)},
    {0, 599999, UINT64_C(0), true, UINT64_C(13653310)},
    {0, 599999, UINT64_C(2048000000000), true, UINT64_C(13653304)},
    {0, 599999, UINT64_C(2756434948434199641), true, UINT64_C(4890854)},
    {0, 600000, UINT64_C(0), true, UINT64_C(0)},
    {0, 600000, UINT64_C(2048000000000), true, UINT64_C(0)},
    {0, 600000, UINT64_C(2756434948434199641), true, UINT64_C(0)},
    {0, 600001, UINT64_C(0), false, UINT64_C(0)},
    {0, 600001, UINT64_C(2048000000000), false, UINT64_C(0)},
    {0, 600001, UINT64_C(2756434948434199641), false, UINT64_C(0)},
    {300000, 150000, UINT64_C(0), true, UINT64_C(2048000000000)},
    {300000, 150000, UINT64_C(2048000000000), true, UINT64_C(2047999023437)},
    {300000, 150000, UINT64_C(2756434948434199641), true, UINT64_C(733629392416)},
    {300000, 300000, UINT64_C(0), true, UINT64_C(2048000000000)},
    {300000, 300000, UINT64_C(2048000000000), true, UINT64_C(2047999023437)},
    {300000, 300000, UINT64_C(2756434948434199641), true, UINT64_C(733629392416)},
    {300000, 300001, UINT64_C(0), true, UINT64_C(2047999999977)},
    {300000, 300001, UINT64_C(2048000000000), true, UINT64_C(2047999023414)},
    {300000, 300001, UINT64_C(2756434948434199641), true, UINT64_C(733629392407)},
    {300000, 337500, UINT64_C(0), true, UINT64_C(2016000000000)},
    {300000, 337500, UINT64_C(2048000000000), true, UINT64_C(2015999038695)},
    {300000, 337500, UINT64_C(2756434948434199641), true, UINT64_C(722166433159)},
    {300000, 450000, UINT64_C(0), true, UINT64_C(1536000000000)},
    {300000, 450000, UINT64_C(2048000000000), true, UINT64_C(1535999267577)},
    {300000, 450000, UINT64_C(2756434948434199641), true, UINT64_C(550222044312)},
    {300000, 562500, UINT64_C(0), true, UINT64_C(480000000000)},
    {300000, 562500, UINT64_C(2048000000000), true, UINT64_C(479999771118)},
    {300000, 562500, UINT64_C(2756434948434199641), true, UINT64_C(171944388847)},
    {300000, 599999, UINT64_C(0), true, UINT64_C(13653310)},
    {300000, 599999, UINT64_C(2048000000000), true, UINT64_C(13653304)},
    {300000, 599999, UINT64_C(2756434948434199641), true, UINT64_C(4890854)},
    {300000, 600000, UINT64_C(0), true, UINT64_C(0)},
    {300000, 600000, UINT64_C(2048000000000), true, UINT64_C(0)},
    {300000, 600000, UINT64_C(2756434948434199641), true, UINT64_C(0)},
    {300000, 600001, UINT64_C(0), false, UINT64_C(0)},
    {300000, 600001, UINT64_C(2048000000000), false, UINT64_C(0)},
    {300000, 600001, UINT64_C(2756434948434199641), false, UINT64_C(0)},
    {2100000, 1050000, UINT64_C(0), true, UINT64_C(2048000000000)},
    {2100000, 1050000, UINT64_C(2048000000000), true, UINT64_C(2047999023437)},
    {2100000, 1050000, UINT64_C(2756434948434199641), true, UINT64_C(733629392416)},
    {2100000, 2100000, UINT64_C(0), true, UINT64_C(2048000000000)},
    {2100000, 2100000, UINT64_C(2048000000000), true, UINT64_C(2047999023437)},
    {2100000, 2100000, UINT64_C(2756434948434199641), true, UINT64_C(733629392416)},
    {2100000, 2100001, UINT64_C(0), true, UINT64_C(2047999999999)},
    {2100000, 2100001, UINT64_C(2048000000000), true, UINT64_C(2047999023436)},
    {2100000, 2100001, UINT64_C(2756434948434199641), true, UINT64_C(733629392415)},
    {2100000, 2362500, UINT64_C(0), true, UINT64_C(2016000000000)},
    {2100000, 2362500, UINT64_C(2048000000000), true, UINT64_C(2015999038695)},
    {2100000, 2362500, UINT64_C(2756434948434199641), true, UINT64_C(722166433159)},
    {2100000, 3150000, UINT64_C(0), true, UINT64_C(1536000000000)},
    {2100000, 3150000, UINT64_C(2048000000000), true, UINT64_C(1535999267577)},
    {2100000, 3150000, UINT64_C(2756434948434199641), true, UINT64_C(550222044312)},
    {2100000, 3937500, UINT64_C(0), true, UINT64_C(480000000000)},
    {2100000, 3937500, UINT64_C(2048000000000), true, UINT64_C(479999771118)},
    {2100000, 3937500, UINT64_C(2756434948434199641), true, UINT64_C(171944388847)},
    {2100000, 4199999, UINT64_C(0), true, UINT64_C(1950475)},
    {2100000, 4199999, UINT64_C(2048000000000), true, UINT64_C(1950474)},
    {2100000, 4199999, UINT64_C(2756434948434199641), true, UINT64_C(698694)},
    {2100000, 4200000, UINT64_C(0), true, UINT64_C(0)},
    {2100000, 4200000, UINT64_C(2048000000000), true, UINT64_C(0)},
    {2100000, 4200000, UINT64_C(2756434948434199641), true, UINT64_C(0)},
    {2100000, 4200001, UINT64_C(0), false, UINT64_C(0)},
    {2100000, 4200001, UINT64_C(2048000000000), false, UINT64_C(0)},
    {2100000, 4200001, UINT64_C(2756434948434199641), false, UINT64_C(0)},
};

TEST(EconomicsC2aPrime, Layer1WeightPenaltyPinnedVectors) {
    size_t penalty_bearing = 0;
    size_t rejected = 0;

    for (const WeightPenaltyVector& v : kWeightPenaltyVectors) {
        uint64_t reward = UINT64_MAX;
        const bool ok = get_block_reward(
            v.median_weight, v.current_block_weight, v.already_generated_coins, reward, 1);

        ASSERT_EQ(ok, v.expect_ok)
            << "median=" << v.median_weight << " current=" << v.current_block_weight
            << " ag=" << v.already_generated_coins;

        if (!v.expect_ok) {
            ++rejected;
            continue; // reward is left untouched on the reject arm
        }

        EXPECT_EQ(reward, v.expect_reward)
            << "median=" << v.median_weight << " current=" << v.current_block_weight
            << " ag=" << v.already_generated_coins;

        if (reward != shekyl_base_block_reward(v.already_generated_coins)) {
            ++penalty_bearing;
        }
    }

    // The table must actually reach the arithmetic it claims to pin. A grid
    // that silently drifted into the identity region would pass every
    // assertion above while testing nothing — the failure mode this table was
    // written to close (47-gate-subject-assertion.mdc).
    EXPECT_GT(penalty_bearing, 0u) << "no vector exercises the weight penalty";
    EXPECT_GT(rejected, 0u) << "no vector exercises the >2*median reject arm";
}

} // namespace

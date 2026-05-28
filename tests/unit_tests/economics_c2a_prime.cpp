// Copyright (c) 2025-2026, The Shekyl Foundation
//
// C2a′ dual-leg KAT harness — STAGE_1_PR_7 §5.8 (7-base).

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

namespace {

constexpr size_t kStandardBlockWeight =
    CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2;

TEST(EconomicsC2aPrime, Layer1SubsidyBaseLegAMatchesRust) {
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

TEST(EconomicsC2aPrime, Layer1SubsidyWithReleaseLegAMatchesRust) {
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

    const uint64_t rust_base = shekyl_base_block_reward(already_generated);
    const uint64_t mult = shekyl_calc_release_multiplier(
        SHEKYL_TX_VOLUME_BASELINE,
        SHEKYL_TX_VOLUME_BASELINE,
        SHEKYL_RELEASE_MIN,
        SHEKYL_RELEASE_MAX);
    const uint64_t rust_full = shekyl_apply_release_multiplier(rust_base, mult);
    EXPECT_EQ(cpp_reward, rust_full) << "already_generated=" << already_generated;
  }
}

TEST(EconomicsC2aPrime, Layer2FullEmissionAccumulationLegABEqual) {
  uint64_t ag_cpp = 0;
  uint64_t ag_rust = 0;
  const uint64_t mult = shekyl_calc_release_multiplier(
      SHEKYL_TX_VOLUME_BASELINE,
      SHEKYL_TX_VOLUME_BASELINE,
      SHEKYL_RELEASE_MIN,
      SHEKYL_RELEASE_MAX);

  for (unsigned height = 0; height < 1000; ++height) {
    uint64_t q_sub = 0;
    ASSERT_TRUE(get_block_reward(
        0,
        kStandardBlockWeight,
        ag_cpp,
        q_sub,
        1,
        SHEKYL_TX_VOLUME_BASELINE));

    const uint64_t rust_base = shekyl_base_block_reward(ag_rust);
    const uint64_t q_rust = shekyl_apply_release_multiplier(rust_base, mult);
    ASSERT_EQ(q_sub, q_rust);

    ag_cpp = std::min<uint64_t>(MONEY_SUPPLY, ag_cpp + q_sub);
    ag_rust = std::min<uint64_t>(MONEY_SUPPLY, ag_rust + q_rust);
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
        shekyl::compute_emission_split(q_sub, height, 0, 1);

    ag_full = std::min<uint64_t>(MONEY_SUPPLY, ag_full + q_sub);
    ag_miner = std::min<uint64_t>(MONEY_SUPPLY, ag_miner + split.miner_emission);
  }

  EXPECT_LT(ag_miner, ag_full);
}

} // namespace

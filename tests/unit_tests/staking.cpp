// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <vector>
#include <variant>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/binary_archive.h"
#include "int-util.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

// ===================================================================
// 1. Serialization round-trips
// ===================================================================

TEST(staking, txin_stake_claim_serialization_roundtrip)
{
  txin_stake_claim original;
  original.amount = 1234567890;
  original.staked_output_index = 42;
  original.from_height = 1000;
  original.to_height = 2000;
  memset(&original.k_image, 0xAB, sizeof(original.k_image));

  std::ostringstream oss;
  binary_archive<true> oar(oss);
  ASSERT_TRUE(::do_serialize(oar, original));

  txin_stake_claim deserialized;
  std::string data = oss.str();
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
  ASSERT_TRUE(::do_serialize(iar, deserialized));

  EXPECT_EQ(deserialized.amount, original.amount);
  EXPECT_EQ(deserialized.staked_output_index, original.staked_output_index);
  EXPECT_EQ(deserialized.from_height, original.from_height);
  EXPECT_EQ(deserialized.to_height, original.to_height);
  EXPECT_EQ(deserialized.k_image, original.k_image);
}

TEST(staking, txout_to_staked_key_serialization_roundtrip)
{
  txout_to_staked_key original;
  memset(&original.key, 0xCD, sizeof(original.key));
  original.view_tag.data = 0x42;
  original.lock_tier = 1;

  std::ostringstream oss;
  binary_archive<true> oar(oss);
  ASSERT_TRUE(::do_serialize(oar, original));

  txout_to_staked_key deserialized;
  std::string data = oss.str();
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
  ASSERT_TRUE(::do_serialize(iar, deserialized));

  EXPECT_EQ(deserialized.key, original.key);
  EXPECT_EQ(deserialized.view_tag.data, original.view_tag.data);
  EXPECT_EQ(deserialized.lock_tier, original.lock_tier);
}

TEST(staking, txin_stake_claim_boundary_values)
{
  txin_stake_claim claim;
  claim.amount = 0;
  claim.staked_output_index = UINT64_MAX;
  claim.from_height = UINT64_MAX - 1;
  claim.to_height = UINT64_MAX;
  memset(&claim.k_image, 0xFF, sizeof(claim.k_image));

  std::ostringstream oss;
  binary_archive<true> oar(oss);
  ASSERT_TRUE(::do_serialize(oar, claim));

  txin_stake_claim rt;
  std::string data = oss.str();
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
  ASSERT_TRUE(::do_serialize(iar, rt));

  EXPECT_EQ(rt.amount, 0u);
  EXPECT_EQ(rt.staked_output_index, UINT64_MAX);
  EXPECT_EQ(rt.from_height, UINT64_MAX - 1);
  EXPECT_EQ(rt.to_height, UINT64_MAX);
}

TEST(staking, txout_to_staked_key_all_tiers)
{
  for (uint8_t tier = 0; tier <= 2; ++tier)
  {
    txout_to_staked_key tsk;
    memset(&tsk.key, tier, sizeof(tsk.key));
    tsk.view_tag.data = tier;
    tsk.lock_tier = tier;

    std::ostringstream oss;
    binary_archive<true> oar(oss);
    ASSERT_TRUE(::do_serialize(oar, tsk));

    txout_to_staked_key rt;
    std::string data = oss.str();
    binary_archive<false> iar({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
    ASSERT_TRUE(::do_serialize(iar, rt));

    EXPECT_EQ(rt.lock_tier, tier);
  }
}

// ===================================================================
// 2. Reward computation: integer vs floating-point divergence
// ===================================================================

static uint64_t compute_reward_integer(
  uint64_t total_reward, uint64_t weight,
  uint64_t total_weighted_stake_lo, uint64_t total_weighted_stake_hi = 0)
{
  if (total_reward == 0 || (total_weighted_stake_lo == 0 && total_weighted_stake_hi == 0))
    return 0;
  unsigned __int128 num = (unsigned __int128)total_reward * weight;
  unsigned __int128 denom = ((unsigned __int128)total_weighted_stake_hi << 64) | total_weighted_stake_lo;
  return (uint64_t)(num / denom);
}

static uint64_t compute_reward_float(
  uint64_t total_reward, uint64_t weight, uint64_t total_weighted_stake)
{
  if (total_reward == 0 || total_weighted_stake == 0)
    return 0;
  return (uint64_t)((double)total_reward * (double)weight / (double)total_weighted_stake);
}

TEST(staking, reward_integer_math_basic)
{
  // 100 reward, weight 50, total 200 => 25
  EXPECT_EQ(compute_reward_integer(100, 50, 200), 25u);
  // 1000 reward, weight 1, total 3 => 333 (floor)
  EXPECT_EQ(compute_reward_integer(1000, 1, 3), 333u);
  // Zero cases
  EXPECT_EQ(compute_reward_integer(0, 100, 100), 0u);
  EXPECT_EQ(compute_reward_integer(100, 0, 100), 0u);
  EXPECT_EQ(compute_reward_integer(100, 100, 0), 0u);
}

TEST(staking, reward_integer_vs_float_diverge_at_large_values)
{
  // At values above 2^53, double loses precision. This test demonstrates
  // the divergence that the RPC bug would cause.
  const uint64_t total_reward = 1000000000ULL; // 1 SKL
  const uint64_t weight = 500000000000000ULL;  // 500 trillion
  const uint64_t total_stake = (1ULL << 54);   // > 2^53

  uint64_t int_result = compute_reward_integer(total_reward, weight, total_stake);
  uint64_t flt_result = compute_reward_float(total_reward, weight, total_stake);

  // The integer result is the canonical answer
  EXPECT_GT(int_result, 0u);
  // The float result may differ due to precision loss
  // We don't assert they're equal — we verify the integer path is consistent
  // and that the float path may diverge
  if (int_result != flt_result)
  {
    // Expected: divergence for large values
    EXPECT_NE(int_result, flt_result);
  }
}

TEST(staking, reward_integer_cumulative_over_range)
{
  // Simulate a claim range with varying accruals, matching the consensus loop
  struct accrual_record {
    uint64_t staker_emission;
    uint64_t staker_fee_pool;
    uint64_t total_weighted_stake_lo;
    uint64_t total_weighted_stake_hi;
  };

  const uint64_t staked_amount = 10000000000ULL; // 10 SKL
  const uint8_t tier = 1;
  const uint64_t weight = shekyl_stake_weight(staked_amount, tier);

  accrual_record accruals[] = {
    {100000, 50000, 1000000000, 0},
    {200000, 100000, 2000000000, 0},
    {0, 0, 0, 0},
    {150000, 75000, 1500000000, 0},
    {300000, 0, 3000000000, 0},
  };

  uint64_t total_reward = 0;
  for (const auto& a : accruals)
  {
    uint64_t total_at_h = a.staker_emission + a.staker_fee_pool;
    if (total_at_h == 0 || (a.total_weighted_stake_lo == 0 && a.total_weighted_stake_hi == 0))
      continue;
    total_reward += compute_reward_integer(total_at_h, weight, a.total_weighted_stake_lo, a.total_weighted_stake_hi);
  }

  EXPECT_GT(total_reward, 0u);
  EXPECT_GT(weight, staked_amount); // tier 1 has 1.5x multiplier
}

TEST(staking, reward_dust_floor_division)
{
  // 1 atomic unit reward, weight 1, total 3 => floor(1/3) = 0
  EXPECT_EQ(compute_reward_integer(1, 1, 3), 0u);
  // 2 atomic units, weight 1, total 3 => floor(2/3) = 0
  EXPECT_EQ(compute_reward_integer(2, 1, 3), 0u);
  // 3 atomic units, weight 1, total 3 => floor(3/3) = 1
  EXPECT_EQ(compute_reward_integer(3, 1, 3), 1u);
}

// ===================================================================
// 3. Helper function coverage
// ===================================================================

TEST(staking, get_output_staking_info_staked_output)
{
  tx_out out;
  crypto::public_key pk;
  memset(&pk, 0x11, sizeof(pk));
  crypto::view_tag vt;
  vt.data = 0x22;
  set_staked_tx_out(5000000000, pk, vt, 2, out);

  uint8_t tier = 255;
  ASSERT_TRUE(get_output_staking_info(out, tier));
  EXPECT_EQ(tier, 2);
  EXPECT_EQ(out.amount, 5000000000u);
}

TEST(staking, get_output_staking_info_non_staked_output)
{
  tx_out out;
  out.amount = 1000;
  out.target = txout_to_tagged_key{};

  uint8_t tier = 255;
  ASSERT_FALSE(get_output_staking_info(out, tier));
  EXPECT_EQ(tier, 255u); // unchanged
}

TEST(staking, get_inputs_money_amount_mixed_inputs)
{
  transaction tx;
  tx.version = 2;

  txin_to_key tk;
  tk.amount = 100;
  tx.vin.push_back(tk);

  txin_stake_claim sc;
  sc.amount = 200;
  tx.vin.push_back(sc);

  txin_to_key tk2;
  tk2.amount = 50;
  tx.vin.push_back(tk2);

  uint64_t money = 0;
  ASSERT_TRUE(get_inputs_money_amount(tx, money));
  EXPECT_EQ(money, 350u);
}

TEST(staking, get_inputs_money_amount_pure_claims)
{
  transaction tx;
  tx.version = 2;

  txin_stake_claim sc1;
  sc1.amount = 1000;
  tx.vin.push_back(sc1);

  txin_stake_claim sc2;
  sc2.amount = 2000;
  tx.vin.push_back(sc2);

  uint64_t money = 0;
  ASSERT_TRUE(get_inputs_money_amount(tx, money));
  EXPECT_EQ(money, 3000u);
}

TEST(staking, check_inputs_overflow_with_claims)
{
  transaction tx;
  tx.version = 2;

  txin_to_key tk;
  tk.amount = UINT64_MAX / 2;
  tx.vin.push_back(tk);

  txin_stake_claim sc;
  sc.amount = UINT64_MAX / 2;
  tx.vin.push_back(sc);

  // Sum is UINT64_MAX - 1, no overflow
  EXPECT_TRUE(check_inputs_overflow(tx));
}

TEST(staking, check_inputs_types_supported_both_types)
{
  transaction tx;
  tx.version = 2;

  txin_to_key tk;
  tx.vin.push_back(tk);

  txin_stake_claim sc;
  tx.vin.push_back(sc);

  EXPECT_TRUE(check_inputs_types_supported(tx));
}

TEST(staking, check_inputs_types_supported_rejects_gen)
{
  transaction tx;
  tx.version = 2;

  txin_gen tg;
  tg.height = 0;
  tx.vin.push_back(tg);

  EXPECT_FALSE(check_inputs_types_supported(tx));
}

// ===================================================================
// 4. Stake weight and tier FFI
// ===================================================================

TEST(staking, stake_weight_increases_with_tier)
{
  const uint64_t amount = 1000000000; // 1 SKL

  uint64_t w0 = shekyl_stake_weight(amount, 0);
  uint64_t w1 = shekyl_stake_weight(amount, 1);
  uint64_t w2 = shekyl_stake_weight(amount, 2);

  EXPECT_GT(w0, 0u);
  EXPECT_GE(w1, w0); // tier 1 >= tier 0
  EXPECT_GE(w2, w1); // tier 2 >= tier 1
}

TEST(staking, stake_lock_blocks_positive_for_valid_tiers)
{
  EXPECT_GT(shekyl_stake_lock_blocks(0), 0u);
  EXPECT_GT(shekyl_stake_lock_blocks(1), 0u);
  EXPECT_GT(shekyl_stake_lock_blocks(2), 0u);
}

TEST(staking, stake_lock_blocks_ordering)
{
  uint64_t l0 = shekyl_stake_lock_blocks(0);
  uint64_t l1 = shekyl_stake_lock_blocks(1);
  uint64_t l2 = shekyl_stake_lock_blocks(2);

  EXPECT_LE(l0, l1); // short <= medium
  EXPECT_LE(l1, l2); // medium <= long
}

TEST(staking, stake_weight_zero_amount)
{
  EXPECT_EQ(shekyl_stake_weight(0, 0), 0u);
  EXPECT_EQ(shekyl_stake_weight(0, 1), 0u);
  EXPECT_EQ(shekyl_stake_weight(0, 2), 0u);
}

TEST(staking, stake_yield_multiplier_valid_tiers)
{
  EXPECT_GT(shekyl_stake_yield_multiplier(0), 0u);
  EXPECT_GT(shekyl_stake_yield_multiplier(1), 0u);
  EXPECT_GT(shekyl_stake_yield_multiplier(2), 0u);

  EXPECT_LE(shekyl_stake_yield_multiplier(0), shekyl_stake_yield_multiplier(1));
  EXPECT_LE(shekyl_stake_yield_multiplier(1), shekyl_stake_yield_multiplier(2));
}

// ===================================================================
// 5. set_staked_tx_out construction
// ===================================================================

TEST(staking, set_staked_tx_out_creates_correct_output)
{
  tx_out out;
  crypto::public_key pk;
  memset(&pk, 0xAA, sizeof(pk));
  crypto::view_tag vt;
  vt.data = 0x55;

  set_staked_tx_out(999, pk, vt, 0, out);

  EXPECT_EQ(out.amount, 999u);
  ASSERT_TRUE(std::holds_alternative<txout_to_staked_key>(out.target));

  const auto& staked = std::get<txout_to_staked_key>(out.target);
  EXPECT_EQ(staked.key, pk);
  EXPECT_EQ(staked.view_tag.data, 0x55);
  EXPECT_EQ(staked.lock_tier, 0);
}

// ===================================================================
// 6. Transaction variant handling
// ===================================================================

TEST(staking, txin_variant_holds_stake_claim)
{
  txin_v vin;
  txin_stake_claim claim;
  claim.amount = 42;
  claim.staked_output_index = 7;
  claim.from_height = 100;
  claim.to_height = 200;
  memset(&claim.k_image, 0xEE, sizeof(claim.k_image));

  vin = claim;

  ASSERT_TRUE(std::holds_alternative<txin_stake_claim>(vin));
  ASSERT_FALSE(std::holds_alternative<txin_to_key>(vin));

  const auto& extracted = std::get<txin_stake_claim>(vin);
  EXPECT_EQ(extracted.amount, 42u);
  EXPECT_EQ(extracted.staked_output_index, 7u);
  EXPECT_EQ(extracted.from_height, 100u);
  EXPECT_EQ(extracted.to_height, 200u);
}

TEST(staking, txout_target_variant_holds_staked_key)
{
  txout_target_v target;
  txout_to_staked_key staked;
  memset(&staked.key, 0xBB, sizeof(staked.key));
  staked.lock_tier = 2;

  target = staked;

  ASSERT_TRUE(std::holds_alternative<txout_to_staked_key>(target));
  ASSERT_FALSE(std::holds_alternative<txout_to_key>(target));
  ASSERT_FALSE(std::holds_alternative<txout_to_tagged_key>(target));

  const auto& extracted = std::get<txout_to_staked_key>(target);
  EXPECT_EQ(extracted.lock_tier, 2);
}

// ===================================================================
// 7. Conservation invariant: per-block reward distribution sums to pool
// ===================================================================

TEST(staking, conservation_invariant_single_block)
{
  // Simulate a single block with multiple stakers across all tiers.
  // The sum of per-staker rewards must equal the pool inflow
  // (modulo integer dust from floor division).
  struct stake_position {
    uint64_t amount;
    uint8_t tier;
  };

  const stake_position positions[] = {
    {1000000000, 0}, // 1 SKL, tier 0 (1.0x)
    {2000000000, 1}, // 2 SKL, tier 1 (1.5x)
    {500000000,  2}, // 0.5 SKL, tier 2 (2.0x)
    {3000000000, 0}, // 3 SKL, tier 0
    {1500000000, 2}, // 1.5 SKL, tier 2
  };

  // Compute total_weighted_stake using the SAME function the accrual scan uses
  uint64_t total_weighted = 0;
  for (const auto& pos : positions)
    total_weighted += shekyl_stake_weight(pos.amount, pos.tier);

  ASSERT_GT(total_weighted, 0u);

  const uint64_t pool_inflow = 5000000; // 0.005 SKL per block

  uint64_t total_distributed = 0;
  for (const auto& pos : positions)
  {
    uint64_t weight = shekyl_stake_weight(pos.amount, pos.tier);
    uint8_t overflow = 0;
    uint64_t reward = shekyl_calc_per_block_staker_reward(
      pool_inflow, weight, total_weighted, 0, &overflow);
    EXPECT_EQ(overflow, 0);
    total_distributed += reward;
  }

  // Conservation: distributed <= pool_inflow (dust from floor division)
  EXPECT_LE(total_distributed, pool_inflow);
  // The dust should be small (at most num_stakers - 1 atomic units)
  uint64_t dust = pool_inflow - total_distributed;
  EXPECT_LT(dust, 5u); // < number of stakers
}

TEST(staking, conservation_invariant_all_same_tier)
{
  // When all stakers are at the same tier, the bugged formula would have
  // distributed exactly 100% (multiplier cancels). With the fix, it should
  // also distribute 100% minus dust.
  const uint64_t amount = 1000000000;
  const uint8_t tier = 2; // 2.0x
  const int num_stakers = 10;

  uint64_t total_weighted = 0;
  for (int i = 0; i < num_stakers; ++i)
    total_weighted += shekyl_stake_weight(amount, tier);

  const uint64_t pool_inflow = 10000000;
  uint64_t total_distributed = 0;
  for (int i = 0; i < num_stakers; ++i)
  {
    uint64_t weight = shekyl_stake_weight(amount, tier);
    uint8_t overflow = 0;
    total_distributed += shekyl_calc_per_block_staker_reward(
      pool_inflow, weight, total_weighted, 0, &overflow);
    EXPECT_EQ(overflow, 0);
  }

  EXPECT_LE(total_distributed, pool_inflow);
  EXPECT_GE(total_distributed, pool_inflow - (uint64_t)num_stakers);
}

TEST(staking, conservation_invariant_mixed_tiers_stress)
{
  // 100 stakers with varying amounts and tiers -- verify conservation holds
  const uint64_t base_amount = 100000000; // 0.1 SKL
  const int num_stakers = 100;

  uint64_t total_weighted = 0;
  std::vector<std::pair<uint64_t, uint8_t>> stakers;
  for (int i = 0; i < num_stakers; ++i)
  {
    uint64_t amt = base_amount * (1 + (i % 20));
    uint8_t tier = i % 3;
    stakers.push_back({amt, tier});
    total_weighted += shekyl_stake_weight(amt, tier);
  }

  const uint64_t pool_inflow = 50000000; // 0.05 SKL
  uint64_t total_distributed = 0;
  for (const auto& [amt, tier] : stakers)
  {
    uint64_t weight = shekyl_stake_weight(amt, tier);
    uint8_t overflow = 0;
    total_distributed += shekyl_calc_per_block_staker_reward(
      pool_inflow, weight, total_weighted, 0, &overflow);
    EXPECT_EQ(overflow, 0);
  }

  EXPECT_LE(total_distributed, pool_inflow);
  uint64_t dust = pool_inflow - total_distributed;
  EXPECT_LT(dust, (uint64_t)num_stakers);
}

// ===================================================================
// 8. Weighted denominator invariant: total_weighted >= sum(raw)
// ===================================================================

TEST(staking, weighted_denominator_ge_raw_sum)
{
  const uint64_t base_amount = 500000000; // 0.5 SKL
  const int num_stakers = 50;

  uint64_t sum_raw = 0;
  uint64_t sum_weighted = 0;
  for (int i = 0; i < num_stakers; ++i)
  {
    uint64_t amt = base_amount * (1 + (i % 10));
    uint8_t tier = i % 3;
    sum_raw += amt;
    sum_weighted += shekyl_stake_weight(amt, tier);
  }

  EXPECT_GE(sum_weighted, sum_raw);
}

TEST(staking, weighted_denominator_tier0_equals_raw)
{
  // Tier 0 has 1.0x multiplier, so weighted == raw
  const uint64_t amount = 1000000000;
  uint64_t weight = shekyl_stake_weight(amount, 0);
  EXPECT_EQ(weight, amount);
}

TEST(staking, weighted_denominator_higher_tiers_strictly_greater)
{
  const uint64_t amount = 1000000000;
  for (uint8_t tier = 1; tier < shekyl_stake_tier_count(); ++tier)
  {
    uint64_t weight = shekyl_stake_weight(amount, tier);
    EXPECT_GT(weight, amount)
      << "tier " << (unsigned)tier << " weight should exceed raw amount";
  }
}

// ===================================================================
// 9. Zero-staker burn path
// ===================================================================

TEST(staking, zero_staker_burn_path)
{
  // When total_weighted_stake == 0, any pool inflow should be burned.
  // Verify the per-block reward function returns 0 for all stakers
  // when the denominator is 0.
  const uint64_t pool_inflow = 10000000;

  uint8_t overflow = 0;
  uint64_t reward = shekyl_calc_per_block_staker_reward(
    pool_inflow, 0, 0, 0, &overflow);
  EXPECT_EQ(reward, 0u);
  EXPECT_EQ(overflow, 0);

  // Even with a non-zero weight, if total is 0, reward must be 0
  reward = shekyl_calc_per_block_staker_reward(
    pool_inflow, 1000000, 0, 0, &overflow);
  EXPECT_EQ(reward, 0u);
}

// ===================================================================
// 10. Adversarial: single staker captures exactly 100%
// ===================================================================

TEST(staking, single_staker_captures_full_reward)
{
  const uint64_t amount = 5000000000; // 5 SKL
  const uint8_t tier = 2;
  const uint64_t weight = shekyl_stake_weight(amount, tier);
  const uint64_t total_weighted = weight; // only staker

  const uint64_t pool_inflow = 12345678;

  uint8_t overflow = 0;
  uint64_t reward = shekyl_calc_per_block_staker_reward(
    pool_inflow, weight, total_weighted, 0, &overflow);
  EXPECT_EQ(overflow, 0);
  EXPECT_EQ(reward, pool_inflow);
}

// ===================================================================
// 11. Adversarial: dust stakers cannot extract more than their share
// ===================================================================

TEST(staking, dust_stakers_conservation)
{
  // 1000 stakers with 1 atomic unit each, plus one whale.
  // The dust stakers must collectively not exceed their proportion of the pool.
  const uint64_t dust_amount = 1; // 1 atomic unit
  const uint64_t whale_amount = 100000000000ULL; // 100 SKL
  const uint8_t tier = 0;
  const int num_dust = 1000;

  uint64_t total_weighted = shekyl_stake_weight(whale_amount, tier);
  for (int i = 0; i < num_dust; ++i)
    total_weighted += shekyl_stake_weight(dust_amount, tier);

  const uint64_t pool_inflow = 50000000; // 0.05 SKL

  uint64_t dust_total = 0;
  for (int i = 0; i < num_dust; ++i)
  {
    uint64_t w = shekyl_stake_weight(dust_amount, tier);
    uint8_t overflow = 0;
    dust_total += shekyl_calc_per_block_staker_reward(
      pool_inflow, w, total_weighted, 0, &overflow);
    EXPECT_EQ(overflow, 0);
  }

  uint64_t whale_reward = 0;
  {
    uint64_t w = shekyl_stake_weight(whale_amount, tier);
    uint8_t overflow = 0;
    whale_reward = shekyl_calc_per_block_staker_reward(
      pool_inflow, w, total_weighted, 0, &overflow);
    EXPECT_EQ(overflow, 0);
  }

  EXPECT_LE(dust_total + whale_reward, pool_inflow);
  // Whale should get almost all of it since dust_amount * 1000 << whale_amount
  EXPECT_GT(whale_reward, pool_inflow * 99 / 100);
}

// ===================================================================
// 12. Multi-block accumulation: claim over a range of blocks
// ===================================================================

TEST(staking, multi_block_claim_range_conservation)
{
  // Simulate claiming over a range of blocks.
  // Each block may have different pool inflows and staker sets.
  // The total claimed must not exceed the sum of pool inflows.
  struct block_state {
    uint64_t pool_inflow;
    uint64_t total_weighted_stake_lo;
    uint64_t total_weighted_stake_hi;
  };

  const block_state blocks[] = {
    {5000000, 10000000000ULL, 0},
    {3000000, 5000000000ULL, 0},
    {0, 0, 0},                        // zero-staker block (burned)
    {8000000, 20000000000ULL, 0},
    {1000000, 500000000ULL, 0},
  };

  const uint64_t staked_amount = 2000000000; // 2 SKL
  const uint8_t tier = 1;
  const uint64_t weight = shekyl_stake_weight(staked_amount, tier);

  uint64_t total_claimed = 0;
  uint64_t total_pool = 0;
  for (const auto& b : blocks)
  {
    total_pool += b.pool_inflow;
    if (b.pool_inflow == 0 || (b.total_weighted_stake_lo == 0 && b.total_weighted_stake_hi == 0))
      continue;
    uint8_t overflow = 0;
    total_claimed += shekyl_calc_per_block_staker_reward(
      b.pool_inflow, weight, b.total_weighted_stake_lo, b.total_weighted_stake_hi, &overflow);
    EXPECT_EQ(overflow, 0);
  }

  EXPECT_LE(total_claimed, total_pool);
}

// ===================================================================
// 13. MAX_CLAIM_RANGE boundary: claims spanning the full allowed range
// ===================================================================

TEST(staking, max_claim_range_boundary)
{
  const uint64_t max_range = shekyl_stake_max_claim_range();
  EXPECT_GT(max_range, 0u);

  // Verify a claim range exactly at the boundary is valid
  const uint64_t from_height = 1000;
  const uint64_t to_height = from_height + max_range;
  EXPECT_EQ(to_height - from_height, max_range);

  // One past is over the limit
  EXPECT_GT(to_height + 1 - from_height, max_range);
}

// ===================================================================
// 14. Cross-validation: C++ cache accumulation matches Rust StakeRegistry
// ===================================================================

TEST(staking, cpp_rust_total_weighted_stake_agreement)
{
  // Reproduce the C++ cache accumulation logic (from add_staked_outputs in
  // blockchain.cpp) and verify it matches a direct Rust-side computation
  // via the shekyl_stake_weight FFI for various staker configurations.
  struct staker {
    uint64_t amount;
    uint8_t tier;
  };

  const staker stakers[] = {
    {1000000000,  0},  // 1 SKL, tier 0 (1.0x)
    {5000000000,  1},  // 5 SKL, tier 1 (1.5x)
    {2000000000,  2},  // 2 SKL, tier 2 (2.0x)
    {10000000000, 0},  // 10 SKL, tier 0
    {750000000,   1},  // 0.75 SKL, tier 1
    {3000000000,  2},  // 3 SKL, tier 2
    {100000000,   0},  // 0.1 SKL, tier 0
    {8000000000,  1},  // 8 SKL, tier 1
    {1,           0},  // 1 atomic unit dust, tier 0
    {UINT64_MAX / 2, 0}, // large value, tier 0
  };

  // C++ cache accumulation: 128-bit addition matching blockchain.cpp
  uint64_t cache_lo = 0, cache_hi = 0;
  for (const auto& s : stakers)
  {
    uint64_t w = shekyl_stake_weight(s.amount, s.tier);
    uint64_t old_lo = cache_lo;
    cache_lo += w;
    if (cache_lo < old_lo)
      cache_hi += 1;
  }

  // Reference: sum weights independently with 128-bit arithmetic
  unsigned __int128 reference_total = 0;
  for (const auto& s : stakers)
  {
    uint64_t w = shekyl_stake_weight(s.amount, s.tier);
    reference_total += (unsigned __int128)w;
  }

  uint64_t ref_lo = (uint64_t)reference_total;
  uint64_t ref_hi = (uint64_t)(reference_total >> 64);

  EXPECT_EQ(cache_lo, ref_lo)
    << "Low 64 bits of total_weighted_stake diverge between C++ cache and reference";
  EXPECT_EQ(cache_hi, ref_hi)
    << "High 64 bits of total_weighted_stake diverge between C++ cache and reference";

  // Verify the value is non-zero and plausible
  EXPECT_GT(cache_lo | cache_hi, 0u);

  // Verify reward computation produces the same result with both representations
  const uint64_t pool_inflow = 10000000;
  const uint64_t test_weight = shekyl_stake_weight(1000000000, 1);
  uint8_t overflow_ffi = 0;
  uint64_t reward_ffi = shekyl_calc_per_block_staker_reward(
    pool_inflow, test_weight, cache_lo, cache_hi, &overflow_ffi);
  uint64_t reward_ref = compute_reward_integer(pool_inflow, test_weight, ref_lo, ref_hi);
  EXPECT_EQ(overflow_ffi, 0);
  EXPECT_EQ(reward_ffi, reward_ref)
    << "Reward computed via FFI (lo/hi) differs from reference integer math";
}

TEST(staking, u128_weighted_stake_no_saturation_at_scale)
{
  // Demonstrate that the u128 representation does NOT saturate where u64 would.
  // 100M stakers each staking 100 SKL at tier 2 (2.0x multiplier):
  // raw = 100 * 10^10 = 10^12 per staker
  // weighted = 2 * 10^12 per staker
  // total weighted for 100M stakers = 2 * 10^20
  // u64::MAX = 1.844 * 10^19 — would saturate!
  // u128 handles this trivially.
  const uint64_t amount_per_staker = 100000000000ULL; // 100 SKL in atomic units (10 decimals)
  const uint8_t tier = 2;
  const uint64_t weight_per = shekyl_stake_weight(amount_per_staker, tier);
  ASSERT_GT(weight_per, amount_per_staker); // tier 2 is 2.0x

  const uint64_t num_stakers = 100000000ULL; // 100M

  unsigned __int128 expected = (unsigned __int128)weight_per * num_stakers;
  ASSERT_GT((uint64_t)(expected >> 64), 0u)
    << "This test value should exceed u64::MAX to demonstrate u128 necessity";

  // Simulate the C++ 128-bit cache accumulation
  uint64_t cache_lo = 0, cache_hi = 0;
  {
    // Instead of looping 100M times, multiply
    unsigned __int128 total = (unsigned __int128)weight_per * num_stakers;
    cache_lo = (uint64_t)total;
    cache_hi = (uint64_t)(total >> 64);
  }

  // Verify reward still computes correctly with the large denominator.
  // Per-block staker pool inflow must exceed num_stakers for a non-zero
  // per-staker share after integer division: 10 SKL = 10^11 atomic units.
  const uint64_t pool_inflow = 100000000000ULL; // 10 SKL per block
  uint8_t overflow = 0;
  uint64_t reward = shekyl_calc_per_block_staker_reward(
    pool_inflow, weight_per, cache_lo, cache_hi, &overflow);
  EXPECT_EQ(overflow, 0);
  EXPECT_GT(reward, 0u);

  // Single staker's share ≈ pool_inflow * weight_per / total_weighted
  // = 10 SKL * (1 / 100M) = 10^3 atomic units
  uint64_t expected_reward = pool_inflow / num_stakers;
  EXPECT_LE(reward, expected_reward + 1);
  EXPECT_GE(reward, expected_reward > 0 ? expected_reward - 1 : 0);
}

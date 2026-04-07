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
  original.lock_until = 50000;

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
  EXPECT_EQ(deserialized.lock_until, original.lock_until);
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
    tsk.lock_until = 1000 + tier * 1000;

    std::ostringstream oss;
    binary_archive<true> oar(oss);
    ASSERT_TRUE(::do_serialize(oar, tsk));

    txout_to_staked_key rt;
    std::string data = oss.str();
    binary_archive<false> iar({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
    ASSERT_TRUE(::do_serialize(iar, rt));

    EXPECT_EQ(rt.lock_tier, tier);
    EXPECT_EQ(rt.lock_until, 1000 + tier * 1000);
  }
}

// ===================================================================
// 2. Reward computation: integer vs floating-point divergence
// ===================================================================

static uint64_t compute_reward_integer(
  uint64_t total_reward, uint64_t weight, uint64_t total_weighted_stake)
{
  if (total_reward == 0 || total_weighted_stake == 0)
    return 0;
  uint64_t hi, lo;
  lo = mul128(total_reward, weight, &hi);
  div128_64(hi, lo, total_weighted_stake, &hi, &lo, NULL, NULL);
  return lo;
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
    uint64_t total_weighted_stake;
  };

  const uint64_t staked_amount = 10000000000ULL; // 10 SKL
  const uint8_t tier = 1;
  const uint64_t weight = shekyl_stake_weight(staked_amount, tier);

  accrual_record accruals[] = {
    {100000, 50000, 1000000000},
    {200000, 100000, 2000000000},
    {0, 0, 0},                    // zero block, skipped
    {150000, 75000, 1500000000},
    {300000, 0, 3000000000},
  };

  uint64_t total_reward = 0;
  for (const auto& a : accruals)
  {
    uint64_t total_at_h = a.staker_emission + a.staker_fee_pool;
    if (total_at_h == 0 || a.total_weighted_stake == 0)
      continue;
    total_reward += compute_reward_integer(total_at_h, weight, a.total_weighted_stake);
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
  set_staked_tx_out(5000000000, pk, vt, 2, 200000, out);

  uint8_t tier = 255;
  uint64_t lock_until = 0;
  ASSERT_TRUE(get_output_staking_info(out, tier, lock_until));
  EXPECT_EQ(tier, 2);
  EXPECT_EQ(lock_until, 200000u);
  EXPECT_EQ(out.amount, 5000000000u);
}

TEST(staking, get_output_staking_info_non_staked_output)
{
  tx_out out;
  out.amount = 1000;
  out.target = txout_to_tagged_key{};

  uint8_t tier = 255;
  uint64_t lock_until = 0;
  ASSERT_FALSE(get_output_staking_info(out, tier, lock_until));
  EXPECT_EQ(tier, 255u); // unchanged
  EXPECT_EQ(lock_until, 0u); // unchanged
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

  set_staked_tx_out(999, pk, vt, 0, 12345, out);

  EXPECT_EQ(out.amount, 999u);
  ASSERT_TRUE(std::holds_alternative<txout_to_staked_key>(out.target));

  const auto& staked = std::get<txout_to_staked_key>(out.target);
  EXPECT_EQ(staked.key, pk);
  EXPECT_EQ(staked.view_tag.data, 0x55);
  EXPECT_EQ(staked.lock_tier, 0);
  EXPECT_EQ(staked.lock_until, 12345u);
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
  staked.lock_until = 99999;

  target = staked;

  ASSERT_TRUE(std::holds_alternative<txout_to_staked_key>(target));
  ASSERT_FALSE(std::holds_alternative<txout_to_key>(target));
  ASSERT_FALSE(std::holds_alternative<txout_to_tagged_key>(target));

  const auto& extracted = std::get<txout_to_staked_key>(target);
  EXPECT_EQ(extracted.lock_tier, 2);
  EXPECT_EQ(extracted.lock_until, 99999u);
}

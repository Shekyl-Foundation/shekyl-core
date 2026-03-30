// Copyright (c) 2014-2022, The Monero Project
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

#include <array>
#include <vector>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "crypto/hash-ops.h"
#include "crypto/pow_registry.h"
#include "cryptonote_config.h"

namespace
{

TEST(mining_parity, release_multiplier_scales_reward)
{
  const size_t median_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const size_t current_block_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const uint64_t already_generated_coins = 1234567890;
  const uint8_t version = HF_VERSION_SHEKYL_NG;

  uint64_t base_reward = 0;
  uint64_t high_volume_reward = 0;
  uint64_t low_volume_reward = 0;
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, base_reward, version));
  ASSERT_GT(base_reward, 0u);

  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, high_volume_reward, version, SHEKYL_TX_VOLUME_BASELINE * 100));
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, low_volume_reward, version, 1));

  ASSERT_GT(high_volume_reward, base_reward);
  ASSERT_LT(low_volume_reward, base_reward);
}

TEST(mining_parity, reward_multiplier_is_neutral_at_baseline)
{
  const size_t median_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const size_t current_block_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const uint64_t already_generated_coins = 987654321;
  const uint8_t version = HF_VERSION_SHEKYL_NG;

  uint64_t base_reward = 0;
  uint64_t release_reward = 0;
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, base_reward, version));
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, release_reward, version, SHEKYL_TX_VOLUME_BASELINE));
  ASSERT_EQ(base_reward, release_reward);
}

TEST(mining_parity, pow_registry_selects_expected_schema)
{
  const cryptonote::IPowSchema& cn_schema = cryptonote::get_pow_for_height(100, 11);
  const cryptonote::IPowSchema& rx_schema = cryptonote::get_pow_for_height(100, RX_BLOCK_VERSION);
  ASSERT_STREQ("Cryptonight", cn_schema.name());
  ASSERT_STREQ("RandomX", rx_schema.name());
}

TEST(mining_parity, cryptonight_schema_hash_matches_legacy)
{
  std::array<uint8_t, 80> blob{};
  for (size_t i = 0; i < blob.size(); ++i)
    blob[i] = static_cast<uint8_t>((i * 17) & 0xff);

  const uint64_t height = 424242;
  const uint8_t major_version = 11; // Cryptonight variant path
  const int variant = cryptonote::get_cryptonight_variant_for_block(major_version);

  crypto::hash expected = crypto::null_hash;
  crypto::cn_slow_hash(blob.data(), blob.size(), expected, variant, height);

  crypto::hash actual = crypto::null_hash;
  const cryptonote::IPowSchema& schema = cryptonote::get_pow_for_height(height, major_version);
  ASSERT_TRUE(schema.hash(blob.data(), blob.size(), height, nullptr, 0, actual));
  ASSERT_EQ(expected, actual);
}

TEST(mining_parity, randomx_schema_hash_matches_legacy)
{
  std::vector<uint8_t> blob(120, 0x42);
  crypto::hash seed = crypto::null_hash;
  for (size_t i = 0; i < sizeof(seed.data); ++i)
    seed.data[i] = static_cast<unsigned char>(i);

  crypto::hash expected = crypto::null_hash;
  crypto::rx_slow_hash(seed.data, blob.data(), blob.size(), expected.data);

  crypto::hash actual = crypto::null_hash;
  const cryptonote::IPowSchema& schema = cryptonote::get_pow_for_height(500000, RX_BLOCK_VERSION);
  ASSERT_TRUE(schema.hash(blob.data(), blob.size(), 500000, &seed, 0, actual));
  ASSERT_EQ(expected, actual);
}

} // anonymous namespace

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
#include <cstring>
#include <string>
#include <vector>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "crypto/hash-ops.h"
#include "crypto/pow_registry.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

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

TEST(mining_parity, pow_registry_is_randomx_only)
{
  // Phase 3b collapsed get_pow_for_height to RandomX for every block version
  // (CryptoNight is deleted, rule 60). The dispatch is RandomX regardless of
  // the version argument now.
  ASSERT_STREQ("RandomX", cryptonote::get_pow_for_height(100, 11).name());
  ASSERT_STREQ("RandomX", cryptonote::get_pow_for_height(100, RX_BLOCK_VERSION).name());
}

TEST(mining_parity, randomx_schema_routes_through_v2_ffi)
{
  // Reuse the Phase 3a Hole-1 canonical KAT (tests/randomx_v2_parity/
  // randomx_v2_full_parity.cpp): seed 0x01..0x20 over a fixed ASCII blob has
  // this pinned RandomX v2 light-cache hash. The release-gate parity test
  // anchors the value against the C v2 full dataset; here we assert that the
  // registry-dispatched RandomX schema reproduces it, proving the C++ schema
  // wrapper routes through the v2 verifier (the same expected value also
  // appears in randomx_v2_full_parity.cpp's kFrozenKatHashHex — a drift in
  // either fails both).
  static const char* const kCanonicalKatHex =
    "34f8b0179159d837e463c17c8692c106d2d3536f7da325aeefeb3e22a136b651";

  crypto::hash seed = crypto::null_hash;
  for (size_t i = 0; i < sizeof(seed.data); ++i)
    seed.data[i] = static_cast<unsigned char>(i + 1); // 0x01..0x20

  const std::string blob_ascii =
    "Shekyl RandomX v2 full-dataset parity KAT (Phase 3a, pin aaafe71)";
  const std::vector<uint8_t> blob(blob_ascii.begin(), blob_ascii.end());

  std::array<uint8_t, 32> expected{};
  for (size_t i = 0; i < expected.size(); ++i)
    expected[i] = static_cast<uint8_t>(std::stoul(
      std::string(kCanonicalKatHex + 2 * i, 2), nullptr, 16));

  // The registry-dispatched RandomX schema (routes through the v2 FFI under
  // the cutover).
  crypto::hash via_schema = crypto::null_hash;
  const cryptonote::IPowSchema& schema =
    cryptonote::get_pow_for_height(500000, RX_BLOCK_VERSION);
  ASSERT_STREQ("RandomX", schema.name());
  ASSERT_TRUE(schema.hash(blob.data(), blob.size(), 500000, &seed, 0, via_schema));
  ASSERT_EQ(0, std::memcmp(via_schema.data, expected.data(), expected.size()));

  // A direct v2 FFI call must produce the same bytes, cross-checking the
  // verifier is reachable from this binary and the schema wrapper marshals
  // its arguments correctly.
  crypto::hash via_ffi = crypto::null_hash;
  ASSERT_EQ(SHEKYL_POW_RANDOMX_V2_OK,
            shekyl_pow_randomx_v2_hash(
              reinterpret_cast<const uint8_t (*)[32]>(seed.data),
              blob.data(),
              blob.size(),
              reinterpret_cast<uint8_t (*)[32]>(via_ffi.data)));
  ASSERT_EQ(via_ffi, via_schema);
}

} // anonymous namespace

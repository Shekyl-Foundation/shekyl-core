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
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "crypto/hash-ops.h"
#include "crypto/pow_registry.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

namespace
{

// Lowercase hex of a 32-byte hash (self-contained; avoids an epee string_tools
// include for one call site).
std::string hex32(const crypto::hash& h)
{
  static const char digits[] = "0123456789abcdef";
  std::string s;
  s.reserve(64);
  for (size_t i = 0; i < 32; ++i)
  {
    const unsigned char b = static_cast<unsigned char>(h.data[i]);
    s.push_back(digits[b >> 4]);
    s.push_back(digits[b & 0x0f]);
  }
  return s;
}

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

TEST(mining_parity, genesis_identity_is_pow_independent)
{
  // RANDOMX_V2_PHASE3_PLAN.md §3.2 / §8.3. The genesis block is mined at
  // difficulty 1, so find_nonce_for_given_block accepts the very first nonce
  // tried (GENESIS_NONCE) regardless of which PoW algorithm computes the
  // longhash, and the block id is Keccak(serialized header) — independent of the
  // longhash entirely. The RandomX v2 cutover (genesis longhash CryptoNight ->
  // RandomX, and the calculate_block_hash block-202612 fossil drop in c1611f4be)
  // therefore cannot move the genesis nonce or id. This also exercises
  // generate_genesis_block through the v2 verifier — the path Blockchain::init
  // runs on every daemon boot.
  //
  // frozen_id is a regression anchor. If a *legitimate* pre-genesis change to
  // GENESIS_TX or a header field moves it, set frozen_id to "" to re-capture the
  // printed value, then re-pin it. The mainnet id is independently anchored: it
  // equals the height-0 block_hash in
  // rust/shekyl-wire/tests/vectors/regtest_coinbase_hashes.json, captured from
  // the daemon by capture_coinbase.py before this cutover — two independent
  // derivations of the same PoW-independent genesis id.
  struct NetCase
  {
    cryptonote::network_type net;
    const char* name;
    const char* frozen_id;
  };
  const NetCase nets[] = {
    { cryptonote::MAINNET,  "mainnet",  "919f8db5a0696c4969af09755c1acc42ae95e4ec573cab0a095c2e7849a144c4" },
    { cryptonote::TESTNET,  "testnet",  "21b163229fc1a33c52d46452160ca4668d06bba54a72555d3978e04093a6e4a3" },
    { cryptonote::STAGENET, "stagenet", "a0cfacd95a96004935b450f1230336f280afd0d793357ef358430b9c0bce88bb" },
  };

  for (const NetCase& nc : nets)
  {
    const cryptonote::config_t& cfg = cryptonote::get_config(nc.net);
    cryptonote::block bl{};
    ASSERT_TRUE(cryptonote::generate_genesis_block(bl, cfg.GENESIS_TX, cfg.GENESIS_NONCE))
      << nc.name << ": generate_genesis_block failed";
    EXPECT_EQ(cfg.GENESIS_NONCE, bl.nonce)
      << nc.name << ": genesis nonce moved (difficulty-1 invariant broken)";

    crypto::hash id{};
    ASSERT_TRUE(cryptonote::get_block_hash(bl, id)) << nc.name << ": get_block_hash failed";
    const std::string got = hex32(id);
    if (std::string(nc.frozen_id).empty())
      std::printf("[genesis] %-8s nonce=%u id=%s  (CAPTURE: paste into frozen_id)\n",
                  nc.name, static_cast<unsigned>(bl.nonce), got.c_str());
    else
      EXPECT_EQ(std::string(nc.frozen_id), got) << nc.name << ": genesis block id changed";
  }
}

} // anonymous namespace

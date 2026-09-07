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
#include <variant>
#include <vector>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "crypto/hash-ops.h"
#include "crypto/pow_registry.h"
#include "cryptonote_config.h"
#include "shekyl/economics.h"
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

TEST(mining_parity, marshal_pins_the_signed_composition_at_the_tail)
{
  // The 6-arg get_block_reward is a marshaling shim ("C++ computes
  // nothing"), and the order checks above cannot pin the FL-R12'
  // composition: at the tail the two rejected orderings differ in VALUE,
  // not direction. These are the FFI-side pin's probes (legacy_tests.rs
  // block_reward_marshals_the_signed_composition) taken through the C++
  // overload, so the shim's own additions — version -> zone threading and
  // the status -> bool mapping — are inside the tested surface. Written
  // under the no-test-exists-means-write-the-test rule: this overload
  // crossed with the FL-R12' bundle carrying only directional coverage.
  const uint8_t version = HF_VERSION_SHEKYL_NG;
  const uint64_t tail = FINAL_SUBSIDY_PER_MINUTE * (SHEKYL_DAA_TARGET_SECONDS / 60);
  const size_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  uint64_t reward = 0;

  // Tail boundary under dormancy (v = 0 pins M_r at its 0.8 rail), no
  // penalty: the floor pays TAIL whole. The shipped pre-FL-R12' order
  // paid 480000000 here (the multiplier applied to the floored base).
  ASSERT_TRUE(cryptonote::get_block_reward(0, zone / 2, MONEY_SUPPLY - tail + 1, reward, version, 0));
  ASSERT_EQ(reward, tail);

  // Past the asymptote with x = 1/2: penalty AFTER the floor => TAIL*3/4.
  // Pre-FL-R12' this state was an error arm (FL-R16a).
  ASSERT_TRUE(cryptonote::get_block_reward(zone, zone + zone / 2, MONEY_SUPPLY + tail, reward, version, 0));
  ASSERT_EQ(reward, tail / 4 * 3);

  // Surge rail (M_r at 1.3) at the asymptote: rail-independent TAIL — the
  // axis that separates max(M_r*curve, TAIL) from a floor-inside-the-
  // operand rebuild (FL round 10, T-3).
  ASSERT_TRUE(cryptonote::get_block_reward(0, zone / 2, MONEY_SUPPLY, reward, version, SHEKYL_TX_VOLUME_BASELINE * 100));
  ASSERT_EQ(reward, tail);

  // Mid-curve dormancy, cross-checked against the DIRECT FFI call: the
  // marshal identity that pins the tx_volume_avg threading itself. The
  // three tail probes above are M_r-independent by contract, so only a
  // mid-curve probe can catch a shim that drops or rewrites the volume
  // argument on the way through.
  uint64_t expected = 0;
  uint64_t limit = 0;
  ASSERT_EQ(SHEKYL_BLOCK_REWARD_OK,
            shekyl_block_reward(0, zone / 2, MONEY_SUPPLY / 2, zone, 0, &expected, &limit));
  ASSERT_TRUE(cryptonote::get_block_reward(0, zone / 2, MONEY_SUPPLY / 2, reward, version, 0));
  ASSERT_EQ(reward, expected);
}

TEST(mining_parity, genesis_paid_reward_and_split_are_pinned)
{
  // The GENESIS-condition pin, and it lives HERE because the core test
  // that checked it (`gen_block_reward`, tests/core_tests/block_reward.cpp)
  // is NOT REGISTERED in chaingen_main.cpp — it was dropped with the v1
  // coinbase siblings, so a pin placed there executes never. Copilot
  // raised the tautology on that file (PR #640); this is the same pin in
  // a test that runs.
  //
  // Independent literals, derived from the frozen parameters rather than
  // read back from the owner under test: at genesis `curve(0) =
  // MONEY_SUPPLY >> esf` = 2 048 000 000 000; `tx_volume_avg = 0` pins
  // `M_r` at its 0.8 rail and the tail floor does not bind, so the paid
  // pre-penalty quantity is 1 638 400 000 000; the genesis emission share
  // is 15%, leaving the miner 1 392 640 000 000. A reward-math change
  // fails this even though the marshal still agrees with itself.
  uint64_t paid = 0;
  uint64_t limit = 0;
  ASSERT_EQ(SHEKYL_BLOCK_REWARD_OK,
            shekyl_block_reward(0, 1, 0, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
                                /*tx_volume_avg=*/0, &paid, &limit));
  ASSERT_EQ(paid, UINT64_C(1638400000000));

  const shekyl::EmissionSplit em = shekyl::compute_emission_split(paid, 0, 0);
  ASSERT_EQ(em.miner_emission, UINT64_C(1392640000000));
  ASSERT_EQ(em.miner_emission + em.staker_emission, paid);
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
  // printed value, then re-pin it. Each id is independently anchored by
  // `geblock block-id --network <net>` (rust/shekyl-genesis-tool), which derives
  // the same id in pure Rust from config/genesis_recipients.<net>.json; the
  // mainnet id is also CI-cross-anchored to the height-0 block_hash in
  // rust/shekyl-wire/tests/vectors/regtest_coinbase_hashes.json (daemon capture
  // via capture_coinbase.py; see coinbase_hash.rs MAINNET_GENESIS_BLOCK_ID) —
  // three independent derivations of the same PoW-independent genesis id.
  struct NetCase
  {
    cryptonote::network_type net;
    const char* name;
    const char* frozen_id;
  };
  const NetCase nets[] = {
    { cryptonote::MAINNET,  "mainnet",  "e623214c06d3ec19a8326c166ff4ee920fe85badbfadd67966c15a315ed7aa12" },
    { cryptonote::TESTNET,  "testnet",  "7cbb852932d7c1b35991e5880c8158da2a36c9101e4daf2620139c0585663280" },
    { cryptonote::STAGENET, "stagenet", "82ccf33577a4833d0bfd0eef768de21130cc2a9b66f83b9d32c8a91e6cedf7b4" },
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

// geblock (rust/shekyl-genesis-tool) emits genesis tx_extra in canonical order
// rather than porting sort_tx_extra. This test makes that claim fully
// executable against the C++ sorter and field parser:
//   1. fixed point of sort_tx_extra (input already canonical), and
//   2. explicit field sequence pubkey → KEM ciphertext → leaf hashes
//      (the pick order sort_tx_extra uses for the genesis field subset).
// Complements rust/shekyl-genesis-tool/tests/golden_kat.rs::extra_is_canonical_fixed_point.
TEST(mining_parity, genesis_tx_extra_is_sort_tx_extra_fixed_point)
{
  struct NetCase
  {
    cryptonote::network_type net;
    const char* name;
  };
  const NetCase nets[] = {
    { cryptonote::MAINNET,  "mainnet"  },
    { cryptonote::TESTNET,  "testnet"  },
    { cryptonote::STAGENET, "stagenet" },
  };

  for (const NetCase& nc : nets)
  {
    const cryptonote::config_t& cfg = cryptonote::get_config(nc.net);
    cryptonote::block bl{};
    ASSERT_TRUE(cryptonote::generate_genesis_block(bl, cfg.GENESIS_TX, cfg.GENESIS_NONCE))
      << nc.name << ": generate_genesis_block failed";

    std::vector<uint8_t> sorted_extra;
    ASSERT_TRUE(cryptonote::sort_tx_extra(bl.miner_tx.extra, sorted_extra))
      << nc.name << ": sort_tx_extra failed on the genesis extra";
    EXPECT_EQ(bl.miner_tx.extra, sorted_extra)
      << nc.name << ": genesis tx_extra is not a fixed point of sort_tx_extra "
                    "(geblock emit order vs C++ canonicalizer drift)";

    std::vector<cryptonote::tx_extra_field> fields;
    ASSERT_TRUE(cryptonote::parse_tx_extra(bl.miner_tx.extra, fields))
      << nc.name << ": parse_tx_extra failed on the genesis extra";
    ASSERT_EQ(3u, fields.size())
      << nc.name << ": genesis extra must carry exactly three fields "
                    "(0x01 pubkey, 0x06 KEM, 0x07 leaf hashes)";
    EXPECT_TRUE(std::holds_alternative<cryptonote::tx_extra_pub_key>(fields[0]))
      << nc.name << ": field 0 must be TX_EXTRA_TAG_PUBKEY (0x01)";
    EXPECT_TRUE(std::holds_alternative<cryptonote::tx_extra_pqc_kem_ciphertext>(fields[1]))
      << nc.name << ": field 1 must be TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT (0x06)";
    EXPECT_TRUE(std::holds_alternative<cryptonote::tx_extra_pqc_leaf_hashes>(fields[2]))
      << nc.name << ": field 2 must be TX_EXTRA_TAG_PQC_LEAF_HASHES (0x07)";
  }
}

} // anonymous namespace

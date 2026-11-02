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

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <variant>
#include <vector>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"

namespace
{

TEST(mining_parity, release_multiplier_scales_reward)
{
  const size_t median_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const size_t current_block_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const uint64_t already_generated_coins = 1234567890;

  uint64_t base_reward = 0;
  uint64_t high_volume_reward = 0;
  uint64_t low_volume_reward = 0;
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, base_reward));
  ASSERT_GT(base_reward, 0u);

  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, high_volume_reward, {SHEKYL_TX_VOLUME_BASELINE * 100, 1}));
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, low_volume_reward, {1, 1}));

  ASSERT_GT(high_volume_reward, base_reward);
  ASSERT_LT(low_volume_reward, base_reward);
}

TEST(mining_parity, reward_multiplier_is_neutral_at_baseline)
{
  const size_t median_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const size_t current_block_weight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const uint64_t already_generated_coins = 987654321;

  uint64_t base_reward = 0;
  uint64_t release_reward = 0;
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, base_reward));
  ASSERT_TRUE(cryptonote::get_block_reward(median_weight, current_block_weight, already_generated_coins, release_reward, {SHEKYL_TX_VOLUME_BASELINE, 1}));
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
  const uint64_t tail = FINAL_SUBSIDY_PER_MINUTE * (SHEKYL_DAA_TARGET_SECONDS / 60);
  const size_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  uint64_t reward = 0;

  // Tail boundary under dormancy (v = 0 pins M_r at its 0.8 rail), no
  // penalty: the floor pays TAIL whole. The shipped pre-FL-R12' order
  // paid 480000000 here (the multiplier applied to the floored base).
  ASSERT_TRUE(cryptonote::get_block_reward(0, zone / 2, SHEKYL_EMISSION_CURVE_ASYMPTOTE - tail + 1, reward, {}));
  ASSERT_EQ(reward, tail);

  // Past the asymptote with x = 1/2: penalty AFTER the floor => TAIL*3/4.
  // Pre-FL-R12' this state was an error arm (FL-R16a).
  ASSERT_TRUE(cryptonote::get_block_reward(zone, zone + zone / 2, SHEKYL_EMISSION_CURVE_ASYMPTOTE + tail, reward, {}));
  ASSERT_EQ(reward, tail / 4 * 3);

  // Surge rail (M_r at 1.3) at the asymptote: rail-independent TAIL — the
  // axis that separates max(M_r*curve, TAIL) from a floor-inside-the-
  // operand rebuild (FL round 10, T-3).
  ASSERT_TRUE(cryptonote::get_block_reward(0, zone / 2, SHEKYL_EMISSION_CURVE_ASYMPTOTE, reward, {SHEKYL_TX_VOLUME_BASELINE * 100, 1}));
  ASSERT_EQ(reward, tail);

  // Mid-curve dormancy, cross-checked against the DIRECT FFI call: the
  // marshal identity that pins the volume-window threading itself. The
  // three tail probes above are M_r-independent by contract, so only a
  // mid-curve probe can catch a shim that drops or rewrites the volume
  // argument on the way through.
  uint64_t expected = 0;
  uint64_t limit = 0;
  ASSERT_EQ(SHEKYL_BLOCK_REWARD_OK,
            shekyl_block_reward(0, zone / 2, SHEKYL_EMISSION_CURVE_ASYMPTOTE / 2, 0, 0, &expected, &limit));
  ASSERT_TRUE(cryptonote::get_block_reward(0, zone / 2, SHEKYL_EMISSION_CURVE_ASYMPTOTE / 2, reward, {}));
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
  // SHEKYL_EMISSION_CURVE_ASYMPTOTE >> esf` = 1 024 000 000 000 at the design's
  // ESF 22 per block; an empty volume window pins `M_r` at its 0.8 rail and
  // the tail floor does not bind, so the paid pre-penalty quantity is
  // 819 200 000 000; the emission share at block 1 is 15%, leaving the miner
  // 696 320 000 000, and at genesis (height 0) there is no staker share. A reward-math change fails this even though the marshal
  // still agrees with itself. (Re-derived 2026-10-04; at the per-minute
  // convention's 21 these were 1 638 400 000 000 and 1 392 640 000 000.)
  uint64_t paid = 0;
  uint64_t limit = 0;
  ASSERT_EQ(SHEKYL_BLOCK_REWARD_OK,
            shekyl_block_reward(0, 1, 0, /*tx_count_sum=*/0, /*window_blocks=*/0, &paid, &limit));
  ASSERT_EQ(paid, UINT64_C(819200000000));

  const shekyl::EmissionSplit em = shekyl::compute_emission_split(paid, 1);
  ASSERT_EQ(em.miner_emission, UINT64_C(696320000000));
  ASSERT_EQ(em.miner_emission + em.staker_emission, paid);

  const shekyl::EmissionSplit genesis = shekyl::compute_emission_split(paid, 0);
  ASSERT_EQ(genesis.miner_emission, paid);
  ASSERT_EQ(genesis.staker_emission, UINT64_C(0));
}

TEST(mining_parity, randomx_v2_ffi_reproduces_the_canonical_kat)
{
  // The Phase 3a Hole-1 canonical KAT (tests/randomx_v2_parity/
  // randomx_v2_full_parity.cpp kFrozenKatHashHex, and the miner KAT ctest):
  // seed 0x01..0x20 over a fixed ASCII blob has this pinned RandomX v2
  // light-cache hash. The release-gate parity test anchors the value against
  // the C v2 full dataset; here the verifier this binary links reproduces it
  // through the export the parity harness calls. The C++ dispatch that used
  // to sit in front of the export (`hash_pow_randomx`, `get_block_longhash`)
  // was deleted with the C++ chain: the daemon's PoW is the Rust ingest's.
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

  crypto::hash via_ffi = crypto::null_hash;
  ASSERT_EQ(SHEKYL_POW_RANDOMX_V2_OK,
            shekyl_pow_randomx_v2_hash(
              reinterpret_cast<const uint8_t (*)[32]>(seed.data),
              blob.data(),
              blob.size(),
              reinterpret_cast<uint8_t (*)[32]>(via_ffi.data)));
  ASSERT_EQ(0, std::memcmp(via_ffi.data, expected.data(), expected.size()));
}

// The genesis identity pin (`genesis_identity_is_pow_independent`: the three
// networks' genesis block ids, derived through the C++ `generate_genesis_block`)
// is not here. That constructor was deleted with the C++ chain; the ids are
// derived in pure Rust from the pinned GENESIS_TX and nonce by
// rust/shekyl-genesis-tool/tests/genesis_block_ids.rs, and the mainnet id is
// also derived from the captured h0 blob by
// rust/shekyl-wire/tests/coinbase_hash.rs (MAINNET_GENESIS_BLOCK_ID).
//
// The genesis extra's byte-identity proof is not here. It read the fields
// out of each network's genesis extra and handed them back to
// shekyl_coinbase_extra, requiring the same bytes out. Since the 0x0C draw
// commitment (SO-D12 increment 1) the writer draws its commitment in Rust
// and takes none from its caller, so C++ has nothing to hand back and the
// FFI writer cannot reproduce a fixed extra. The proof is in Rust, over the
// pure writer the FFI wraps and against the same GENESIS_TX pins:
// rust/shekyl-genesis-tool/tests/config_pin_gate.rs,
// the_pure_writer_reproduces_each_pinned_genesis_extra. Deleted here, not
// kept as a weaker check (rule 15).

} // anonymous namespace

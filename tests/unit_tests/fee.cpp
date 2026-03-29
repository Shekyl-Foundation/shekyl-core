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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "cryptonote_core/blockchain.h"

using namespace cryptonote;

namespace
{
  class fee : public ::testing::Test
  {
  };

  // Shekyl uses 2021 scaling from genesis (HF_VERSION_2021_SCALING == 1).
  // Formula: fee_per_byte = floor(0.95 * reward * ref_weight / median^2)
  // where ref_weight = DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT (3000).
  // Medians below min_block_weight are clamped to ZONE_V5 (300000).

  static constexpr uint8_t V = 1; // Shekyl hard-fork version

  TEST_F(fee, 10skl)
  {
    const uint64_t reward = 10 * COIN;
    // Median at or below ZONE_V5 is clamped to 300000
    // fee = floor(0.95 * 10e9 * 3000 / 300000^2) = 317
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, V), 317u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2, V), 317u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 1, V), 317u);

    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 600000, V), 79u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 3000000, V), 3u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 6000000, V), 1u);
  }

  TEST_F(fee, 1skl)
  {
    const uint64_t reward = COIN;
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, V), 32u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2, V), 32u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 1, V), 32u);

    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 600000, V), 8u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 3000000, V), 1u);
  }

  TEST_F(fee, dot3skl)
  {
    const uint64_t reward = 3 * COIN / 10;
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, V), 10u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2, V), 10u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 1, V), 10u);

    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 600000, V), 2u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(reward, 3000000, V), 1u);
  }

  TEST_F(fee, minimum_fee_floor)
  {
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(1, CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, V), 1u);
    ASSERT_EQ(Blockchain::get_dynamic_base_fee(COIN, 100000ull * CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, V), 1u);
  }
}

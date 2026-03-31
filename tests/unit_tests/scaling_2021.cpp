// Copyright (c) 2019-2022, The Monero Project
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

// Shekyl fee scaling tests.  All hard-fork features are active from genesis
// (HF1).  The 2021 scaling formula applies unconditionally:
//   fee_per_byte = floor(0.95 * reward * 3000 / median^2)

#define IN_UNIT_TESTS

#include "gtest/gtest.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_db/testdb.h"

namespace
{

class TestDB: public cryptonote::BaseTestDB
{
public:
  TestDB() { m_open = true; }
};

}

#define PREFIX_WINDOW(hf_version,window) \
  std::unique_ptr<cryptonote::Blockchain> bc; \
  cryptonote::tx_memory_pool txpool(*bc); \
  bc.reset(new cryptonote::Blockchain(txpool)); \
  struct get_test_options { \
    const std::pair<uint8_t, uint64_t> hard_forks[3]; \
    const cryptonote::test_options test_options = { \
      hard_forks, \
      window, \
    }; \
    get_test_options(): hard_forks{std::make_pair(1, (uint64_t)0), std::make_pair((uint8_t)hf_version, (uint64_t)1), std::make_pair((uint8_t)0, (uint64_t)0)} {} \
  } opts; \
  cryptonote::Blockchain *blockchain = bc.get(); \
  bool r = blockchain->init(new TestDB(), cryptonote::FAKECHAIN, true, &opts.test_options, 0, NULL); \
  ASSERT_TRUE(r)

#define PREFIX(hf_version) PREFIX_WINDOW(hf_version, TEST_LONG_TERM_BLOCK_WEIGHT_WINDOW)

TEST(fee_2021_scaling, relay_fee)
{
  // 10 SKL block reward, various medians
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(10ull * COIN, 300000, 1), 317u);
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(10ull * COIN, 600000, 1), 79u);
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(10ull * COIN, 3000000, 1), 3u);
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(10ull * COIN, 6000000, 1), 1u);

  // 1 SKL block reward
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(COIN, 300000, 1), 32u);
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(COIN, 600000, 1), 8u);
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(COIN, 3000000, 1), 1u);

  // Small medians are clamped to ZONE_V5 (300000)
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(10ull * COIN, 1, 1), 317u);
  ASSERT_EQ(cryptonote::Blockchain::get_dynamic_base_fee(10ull * COIN, 100000, 1), 317u);
}

TEST(fee_2021_scaling, wallet_fee_estimate)
{
  PREFIX_WINDOW(HF_VERSION_2021_SCALING, CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE);
  std::vector<uint64_t> fees;

  // 10 SKL reward, Mnw=Mlw=ZONE_V5
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 300000, 300000, fees);
  ASSERT_EQ(fees.size(), 4);
  ASSERT_EQ(fees[0], 340u);
  ASSERT_EQ(fees[1], 1400u);
  ASSERT_EQ(fees[2], 5400u);
  ASSERT_EQ(fees[3], 67000u);

  // 10 SKL reward, large Mnw
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 15000000, 300000, fees);
  ASSERT_EQ(fees.size(), 4);
  ASSERT_EQ(fees[0], 340u);
  ASSERT_EQ(fees[1], 1400u);
  ASSERT_EQ(fees[2], 5400u);
  ASSERT_EQ(fees[3], 22000u);

  // 10 SKL reward, Mnw=Mlw=1500000
  fees.clear();
  bc->get_dynamic_base_fee_estimate_2021_scaling(10, 10ull * COIN, 1500000, 1500000, fees);
  ASSERT_EQ(fees.size(), 4);
  ASSERT_EQ(fees[0], 13u);
  ASSERT_EQ(fees[1], 53u);
  ASSERT_EQ(fees[2], 1100u);
  ASSERT_EQ(fees[3], 14000u);
}

TEST(fee_2021_scaling, rounding)
{
  ASSERT_EQ(cryptonote::round_money_up("27810", 3), "27900.000000000");
  ASSERT_EQ(cryptonote::round_money_up("37.94", 3), "38.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.5555", 3), "0.556000000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 3), "0.002350000");

  ASSERT_EQ(cryptonote::round_money_up("27810", 2), "28000.000000000");
  ASSERT_EQ(cryptonote::round_money_up("37.94", 2), "38.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.5555", 2), "0.560000000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 2), "0.002400000");

  ASSERT_EQ(cryptonote::round_money_up("0", 8), "0.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.0", 8), "0.000000000");
  ASSERT_EQ(cryptonote::round_money_up("50.0", 8), "50.000000000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 8), "0.002342000");
  ASSERT_EQ(cryptonote::round_money_up("0.002342", 1), "0.003000000");
  ASSERT_EQ(cryptonote::round_money_up("12345", 8), "12345.000000000");
  ASSERT_EQ(cryptonote::round_money_up("45678", 1), "50000.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.234", 1), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.000001", 4), "1.001000000");
  ASSERT_EQ(cryptonote::round_money_up("1.002001", 4), "1.003000000");

  ASSERT_EQ(cryptonote::round_money_up("1.999999", 1), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 2), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 3), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 4), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 5), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 6), "2.000000000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 7), "1.999999000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 8), "1.999999000");
  ASSERT_EQ(cryptonote::round_money_up("1.999999", 9), "1.999999000");

  ASSERT_EQ(cryptonote::round_money_up("2.000001", 1), "3.000000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 2), "2.100000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 3), "2.010000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 4), "2.001000000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 5), "2.000100000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 6), "2.000010000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 7), "2.000001000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 8), "2.000001000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 9), "2.000001000");
  ASSERT_EQ(cryptonote::round_money_up("2.000001", 4000), "2.000001000");

  ASSERT_EQ(cryptonote::round_money_up("999", 2), "1000.000000000");

  ASSERT_THROW(cryptonote::round_money_up("1.23", 0), std::runtime_error);
  // Shekyl 9dp max: UINT64_MAX / 10^9 = 18446744073.709551615
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 1), std::runtime_error);
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 2), std::runtime_error);
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 12), std::runtime_error);
  ASSERT_THROW(cryptonote::round_money_up("18446744073.709551615", 19), std::runtime_error);
}

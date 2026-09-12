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

#define IN_UNIT_TESTS

#include "gtest/gtest.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_db/testdb.h"

#define TEST_LONG_TERM_BLOCK_WEIGHT_WINDOW 5000

namespace
{

class TestDB: public cryptonote::BaseTestDB
{
private:
  struct block_t
  {
    size_t weight;
    uint64_t long_term_weight;
  };

public:
  TestDB() { m_open = true; }

  virtual void add_block( const cryptonote::block& blk
                        , size_t block_weight
                        , uint64_t long_term_block_weight
                        , const cryptonote::difficulty_type& cumulative_difficulty
                        , const uint64_t& coins_generated
                        , uint64_t num_rct_outs
                        , const crypto::hash& blk_hash
                        ) override {
    blocks.push_back({block_weight, long_term_block_weight});
  }
  virtual uint64_t height() const override { return blocks.size(); }
  virtual size_t get_block_weight(const uint64_t &h) const override { return blocks[h].weight; }
  virtual uint64_t get_block_long_term_weight(const uint64_t &h) const override { return blocks[h].long_term_weight; }
  virtual std::vector<uint64_t> get_block_weights(uint64_t start_height, size_t count) const override {
    std::vector<uint64_t> ret;
    ret.reserve(count);
    while (count-- && start_height < blocks.size()) ret.push_back(blocks[start_height++].weight);
    return ret;
  }
  virtual std::vector<uint64_t> get_long_term_block_weights(uint64_t start_height, size_t count) const override {
    std::vector<uint64_t> ret;
    ret.reserve(count);
    while (count-- && start_height < blocks.size()) ret.push_back(blocks[start_height++].long_term_weight);
    return ret;
  }
  virtual crypto::hash get_block_hash_from_height(const uint64_t &height) const override {
    crypto::hash hash = crypto::null_hash;
    *(uint64_t*)&hash = height;
    return hash;
  }
  virtual crypto::hash top_block_hash(uint64_t *block_height = NULL) const override {
    uint64_t h = height();
    crypto::hash top = crypto::null_hash;
    if (h)
      *(uint64_t*)&top = h - 1;
    if (block_height)
      *block_height = h - 1;
    return top;
  }
  virtual void pop_block(cryptonote::block &blk, std::vector<cryptonote::transaction> &txs) override { blocks.pop_back(); }

private:
  std::vector<block_t> blocks;
};

static uint32_t lcg_seed = 0;

static uint32_t lcg()
{
  lcg_seed = (lcg_seed * 0x100000001b3 + 0xcbf29ce484222325) & 0xffffffff;
  return lcg_seed;
}

}

struct BlockchainAndPool
{
  cryptonote::tx_memory_pool txpool;
  cryptonote::Blockchain bc;
  // Circular reference: txpool and bc hold references to each other.
  // bc is not dereferenced during txpool construction.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
  BlockchainAndPool(): txpool(bc), bc(txpool) {}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
};

#define PREFIX_WINDOW(hf_version,window) \
  BlockchainAndPool bap; \
  cryptonote::Blockchain *bc = &bap.bc; \
  struct get_test_options { \
    const std::pair<uint8_t, uint64_t> hard_forks[3]; \
    const cryptonote::test_options test_options = { \
      hard_forks, \
      window, \
    }; \
    get_test_options(): hard_forks{std::make_pair(1, (uint64_t)0), std::make_pair((uint8_t)hf_version, (uint64_t)1), std::make_pair((uint8_t)0, (uint64_t)0)} {} \
  } opts; \
  TestDB *db = new TestDB(); \
  ASSERT_TRUE(bc->init(db, cryptonote::FAKECHAIN, true, &opts.test_options, 0))

#define PREFIX(hf_version) PREFIX_WINDOW(hf_version, TEST_LONG_TERM_BLOCK_WEIGHT_WINDOW)

namespace
{
  // Independent statement of C2-R2 Q3. Asserting the generated constant
  // against itself cannot fail.
  constexpr uint64_t RATIFIED_SURGE_FACTOR = 4;
  static_assert(RATIFIED_SURGE_FACTOR >= 3,
                "the below-ceiling case needs a weight strictly between zone and S*zone");

  void push_blocks(TestDB *db, size_t count, size_t weight, uint64_t long_term_weight)
  {
    for (size_t i = 0; i < count; ++i)
      db->add_block(cryptonote::block(), weight, long_term_weight,
                    cryptonote::difficulty_type(1), 0, 0, crypto::null_hash);
  }
}

TEST(long_term_block_weight, generated_macro_matches_the_ratified_factor)
{
  EXPECT_EQ(RATIFIED_SURGE_FACTOR, SHEKYL_BLOCK_WEIGHT_SHORT_TERM_SURGE_FACTOR);
}

TEST(long_term_block_weight, surge_ceiling_bounds_the_effective_median_at_the_ratified_factor)
{
  PREFIX(1);
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  push_blocks(db, CRYPTONOTE_REWARD_BLOCKS_WINDOW, zone * 100, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());

  EXPECT_EQ(RATIFIED_SURGE_FACTOR * zone, bc->get_current_cumulative_block_weight_median());
  EXPECT_EQ(2 * RATIFIED_SURGE_FACTOR * zone, bc->get_current_cumulative_block_weight_limit());
}

TEST(long_term_block_weight, a_short_term_median_below_the_ceiling_is_not_clamped)
{
  PREFIX(1);
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const uint64_t below_ceiling = zone * (RATIFIED_SURGE_FACTOR - 1);

  push_blocks(db, CRYPTONOTE_REWARD_BLOCKS_WINDOW, below_ceiling, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());

  EXPECT_EQ(below_ceiling, bc->get_current_cumulative_block_weight_median());
}

TEST(long_term_block_weight, a_quiet_chain_does_not_fall_below_the_long_term_median)
{
  PREFIX(1);
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  push_blocks(db, CRYPTONOTE_REWARD_BLOCKS_WINDOW, zone / 10, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());

  EXPECT_EQ(zone, bc->get_current_cumulative_block_weight_median());
}

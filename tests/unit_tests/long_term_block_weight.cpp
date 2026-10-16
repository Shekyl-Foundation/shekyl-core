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
  // A batch is the blocks added since its start; an abort discards them.
  virtual bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0) override { batch_from = blocks.size(); return true; }
  virtual void batch_abort() override { blocks.resize(batch_from); }

private:
  std::vector<block_t> blocks;
  size_t batch_from = 0;
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

#define PREFIX_WINDOW(window) \
  BlockchainAndPool bap; \
  cryptonote::Blockchain *bc = &bap.bc; \
  const cryptonote::test_options test_options = {window}; \
  TestDB *db = new TestDB(); \
  ASSERT_TRUE(bc->init(db, cryptonote::FAKECHAIN, true, &test_options, 0))

#define PREFIX() PREFIX_WINDOW(TEST_LONG_TERM_BLOCK_WEIGHT_WINDOW)

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
  PREFIX();
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  push_blocks(db, CRYPTONOTE_REWARD_BLOCKS_WINDOW, zone * 100, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());

  EXPECT_EQ(RATIFIED_SURGE_FACTOR * zone, bc->get_current_cumulative_block_weight_median());
  EXPECT_EQ(2 * RATIFIED_SURGE_FACTOR * zone, bc->get_current_cumulative_block_weight_limit());
}

TEST(long_term_block_weight, a_short_term_median_below_the_ceiling_is_not_clamped)
{
  PREFIX();
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const uint64_t below_ceiling = zone * (RATIFIED_SURGE_FACTOR - 1);

  push_blocks(db, CRYPTONOTE_REWARD_BLOCKS_WINDOW, below_ceiling, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());

  EXPECT_EQ(below_ceiling, bc->get_current_cumulative_block_weight_median());
}

TEST(long_term_block_weight, a_quiet_chain_does_not_fall_below_the_long_term_median)
{
  PREFIX();
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  push_blocks(db, CRYPTONOTE_REWARD_BLOCKS_WINDOW, zone / 10, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());

  EXPECT_EQ(zone, bc->get_current_cumulative_block_weight_median());
}

TEST(long_term_block_weight, a_block_contribution_is_bounded_to_the_17_10_band)
{
  PREFIX();
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  push_blocks(db, TEST_LONG_TERM_BLOCK_WEIGHT_WINDOW, zone, zone);

  EXPECT_EQ(zone, bc->get_next_long_term_block_weight(zone));
  EXPECT_EQ(zone * 10 / 17, bc->get_next_long_term_block_weight(zone / 10));
  EXPECT_EQ(zone + zone * 7 / 10, bc->get_next_long_term_block_weight(zone * 10));
}

// The Rust dialer's handshake carries the tip the core last published. The
// publish sits in update_next_cumulative_weight_limit, which init, a block
// added to the main chain, a pop, a rollback and a chain switch each call
// (blockchain.cpp: the six call sites). This pins the publish at that
// function, through the two of those entries this fixture can run: init,
// and pop_blocks; a block added is the fixture's push plus the recompute
// those callers make. The chain switch is pinned by reading, not run
// (Rick, 2026-10-13): switch_to_alternative_blockchain reaches
// update_next_cumulative_weight_limit at blockchain.cpp:1070, and
// rollback_blockchain_switching at :1003, so both publish through the one
// function this test exercises; no reorg fixture is needed. The height
// published is the block count, as get_payload_sync_data reports it, and
// the id is the top block's.
TEST(long_term_block_weight, every_tip_change_publishes_the_tip_the_dialer_announces)
{
  PREFIX();
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  const auto published = [](uint64_t& height, crypto::hash& top) {
    uint64_t lo = 0, hi = 0;
    return shekyl_core_published_tip(&height, &lo, &hi, reinterpret_cast<std::uint8_t*>(top.data)) == 1;
  };
  uint64_t height = 0;
  crypto::hash top{};

  // init: the genesis is the tip.
  ASSERT_TRUE(published(height, top));
  EXPECT_EQ(db->height(), height);
  EXPECT_EQ(db->top_block_hash(), top);

  // add: three blocks on the main chain, then the recompute every add makes.
  push_blocks(db, 3, zone, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());
  ASSERT_TRUE(published(height, top));
  EXPECT_EQ(db->height(), height);
  EXPECT_EQ(db->top_block_hash(), top);

  // pop: through the entry a reorg and a rollback use.
  ASSERT_TRUE(bc->pop_blocks(1));
  ASSERT_TRUE(published(height, top));
  EXPECT_EQ(db->height(), height);
  EXPECT_EQ(db->top_block_hash(), top);
}

// An aborted batch is a tip change too (Copilot on #1056). The blocks a
// batch connected publish their tip as each one is added; when a later
// block's add fails, cleanup_handle_incoming_blocks aborts the batch, and
// the tip the dialer announces must be the committed chain's again, not
// the discarded blocks'.
TEST(long_term_block_weight, an_aborted_batch_publishes_the_committed_tip_again)
{
  PREFIX();
  const uint64_t zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

  const auto published = [](uint64_t& height, crypto::hash& top) {
    uint64_t lo = 0, hi = 0;
    return shekyl_core_published_tip(&height, &lo, &hi, reinterpret_cast<std::uint8_t*>(top.data)) == 1;
  };
  uint64_t height = 0;
  crypto::hash top{};

  push_blocks(db, 2, zone, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());
  const uint64_t committed_height = db->height();
  const crypto::hash committed_top = db->top_block_hash();

  // Two blocks connect inside the batch, each publishing as it is added.
  bap.txpool.lock();
  ASSERT_TRUE(db->batch_start());
  bc->m_batch_success = true;
  push_blocks(db, 2, zone, zone);
  ASSERT_TRUE(bc->update_next_cumulative_weight_limit());
  ASSERT_TRUE(published(height, top));
  ASSERT_EQ(committed_height + 2, height);

  // A later block's add fails, and the batch is aborted.
  bc->m_batch_success = false;
  ASSERT_TRUE(bc->cleanup_handle_incoming_blocks());
  ASSERT_EQ(committed_height, db->height());
  ASSERT_TRUE(published(height, top));
  EXPECT_EQ(committed_height, height);
  EXPECT_EQ(committed_top, top);
}

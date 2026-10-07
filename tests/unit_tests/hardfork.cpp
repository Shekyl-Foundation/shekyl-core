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

#include <deque>
#include <limits>

#include "gtest/gtest.h"

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "blockchain_db/testdb.h"

using namespace cryptonote;

#define BLOCKS_PER_YEAR 525960
#define SECONDS_PER_YEAR 31557600

namespace
{

class TestDB: public cryptonote::BaseTestDB {
public:
  virtual uint64_t height() const override { return blocks.size(); }
  virtual void add_block( const block& blk
                        , size_t block_weight
                        , uint64_t long_term_block_weight
                        , const difficulty_type& cumulative_difficulty
                        , const uint64_t& coins_generated
                        , uint64_t num_rct_outs
                        , const crypto::hash& blk_hash
                        ) override {
    blocks.push_back(blk);
  }
  virtual void remove_block() override { blocks.pop_back(); }
  virtual block get_block_from_height(const uint64_t& height) const override {
    return blocks.at(height);
  }
  virtual void set_hard_fork_version(uint64_t height, uint8_t version) override {
    if (versions.size() <= height) 
      versions.resize(height+1); 
    versions[height] = version;
  }
  virtual uint8_t get_hard_fork_version(uint64_t height) const override {
    return versions.at(height);
  }

private:
  std::vector<block> blocks;
  std::deque<uint8_t> versions;
};

}

static cryptonote::block mkblock(uint8_t major_version, uint8_t minor_version = CURRENT_BLOCK_MINOR_VERSION)
{
  cryptonote::block b;
  b.major_version = major_version;
  b.minor_version = minor_version;
  return b;
}

// The major byte is whatever the schedule names at `height` while `height`
// is still the chain height, which is when a block is built.
static cryptonote::block mkblock(const HardFork &hf, uint64_t height)
{
  return mkblock(hf.get(height));
}

TEST(major, Only)
{
  TestDB db;
  HardFork hf(db);

  //                      v  h  t
  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  ASSERT_TRUE(hf.add_fork(2, 2, 1));
  hf.init();

  // Height 0 names version 1. Another major is refused, and so is a minor
  // other than the reserved constant: the byte is not a vote.
  ASSERT_FALSE(hf.check(mkblock(0)));
  ASSERT_FALSE(hf.check(mkblock(2)));
  ASSERT_FALSE(hf.check(mkblock(1, 1)));
  ASSERT_TRUE(hf.check(mkblock(1)));
  ASSERT_FALSE(hf.add(mkblock(0), 0));
  ASSERT_FALSE(hf.add(mkblock(2), 0));
  ASSERT_FALSE(hf.add(mkblock(1, 1), 0));
  ASSERT_TRUE(hf.add(mkblock(1), 0));
  db.add_block(mkblock(1), 0, 0, 0, 0, 0, crypto::hash());

  // Height 1 still names version 1. The next row starts at height 2.
  ASSERT_FALSE(hf.add(mkblock(0), 1));
  ASSERT_FALSE(hf.add(mkblock(2), 1));
  ASSERT_FALSE(hf.add(mkblock(1, 2), 1));
  ASSERT_TRUE(hf.add(mkblock(1), 1));
  db.add_block(mkblock(1), 0, 0, 0, 0, 0, crypto::hash());

  // Height 2 names version 2.
  ASSERT_FALSE(hf.add(mkblock(0), 2));
  ASSERT_FALSE(hf.add(mkblock(1), 2));
  ASSERT_FALSE(hf.add(mkblock(3), 2));
  ASSERT_FALSE(hf.add(mkblock(2, 2), 2));
  ASSERT_TRUE(hf.add(mkblock(2), 2));
  db.add_block(mkblock(2), 0, 0, 0, 0, 0, crypto::hash());

  ASSERT_EQ(hf.get(0), 1);
  ASSERT_EQ(hf.get(1), 1);
  ASSERT_EQ(hf.get(2), 2);
  // The chain height is the next block's height, still on version 2.
  ASSERT_EQ(hf.get_current_version(), 2);
}

TEST(empty_hardforks, Success)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  hf.init();
  ASSERT_TRUE(hf.get_state(time(NULL)) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(time(NULL) + 3600*24*400) == HardFork::Ready);

  for (uint64_t h = 0; h <= 10; ++h) {
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }
  ASSERT_EQ(hf.get(0), 1);
  ASSERT_EQ(hf.get(1), 1);
  ASSERT_EQ(hf.get(10), 1);
}

TEST(ordering, Success)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(2, 2, 1));
  ASSERT_FALSE(hf.add_fork(3, 3, 1));
  ASSERT_FALSE(hf.add_fork(3, 2, 2));
  ASSERT_FALSE(hf.add_fork(2, 3, 2));
  ASSERT_TRUE(hf.add_fork(3, 10, 2));
  ASSERT_TRUE(hf.add_fork(4, 20, 3));
  ASSERT_FALSE(hf.add_fork(5, 5, 4));
}

TEST(check_for_height, Success)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  ASSERT_TRUE(hf.add_fork(2, 5, 1));
  hf.init();

  for (uint64_t h = 0; h <= 4; ++h) {
    ASSERT_TRUE(hf.check_for_height(mkblock(1), h));
    ASSERT_FALSE(hf.check_for_height(mkblock(2), h));
    ASSERT_FALSE(hf.check_for_height(mkblock(1, 1), h));
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }

  for (uint64_t h = 5; h <= 10; ++h) {
    ASSERT_FALSE(hf.check_for_height(mkblock(1), h));
    ASSERT_TRUE(hf.check_for_height(mkblock(2), h));
    ASSERT_FALSE(hf.check_for_height(mkblock(2, 2), h));
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }
}

TEST(get, next_version)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  ASSERT_TRUE(hf.add_fork(2, 5, 1));
  ASSERT_TRUE(hf.add_fork(4, 10, 2));
  hf.init();

  for (uint64_t h = 0; h <= 4; ++h) {
    ASSERT_EQ(2, hf.get_next_version());
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }

  for (uint64_t h = 5; h <= 9; ++h) {
    ASSERT_EQ(4, hf.get_next_version());
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }

  for (uint64_t h = 10; h <= 15; ++h) {
    ASSERT_EQ(4, hf.get_next_version());
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }
}

TEST(states, Success)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  ASSERT_TRUE(hf.add_fork(2, BLOCKS_PER_YEAR, SECONDS_PER_YEAR));

  ASSERT_TRUE(hf.get_state(0) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR / 2) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR + HardFork::DEFAULT_UPDATE_TIME / 2) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR + (HardFork::DEFAULT_UPDATE_TIME + HardFork::DEFAULT_FORKED_TIME) / 2) == HardFork::UpdateNeeded);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR + HardFork::DEFAULT_FORKED_TIME * 2) == HardFork::LikelyForked);

  ASSERT_TRUE(hf.add_fork(3, BLOCKS_PER_YEAR * 5, SECONDS_PER_YEAR * 5));

  ASSERT_TRUE(hf.get_state(0) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR / 2) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR + HardFork::DEFAULT_UPDATE_TIME / 2) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR + (HardFork::DEFAULT_UPDATE_TIME + HardFork::DEFAULT_FORKED_TIME) / 2) == HardFork::Ready);
  ASSERT_TRUE(hf.get_state(SECONDS_PER_YEAR + HardFork::DEFAULT_FORKED_TIME * 2) == HardFork::Ready);
}

TEST(steps_asap, Success)
{
  TestDB db;
  HardFork hf(db);

  //                 v  h  t
  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  ASSERT_TRUE(hf.add_fork(4, 2, 1));
  ASSERT_TRUE(hf.add_fork(7, 4, 2));
  ASSERT_TRUE(hf.add_fork(9, 6, 3));
  hf.init();

  for (uint64_t h = 0; h < 10; ++h) {
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }

  ASSERT_EQ(hf.get(0), 1);
  ASSERT_EQ(hf.get(1), 1);
  ASSERT_EQ(hf.get(2), 4);
  ASSERT_EQ(hf.get(3), 4);
  ASSERT_EQ(hf.get(4), 7);
  ASSERT_EQ(hf.get(5), 7);
  ASSERT_EQ(hf.get(6), 9);
  ASSERT_EQ(hf.get(7), 9);
  ASSERT_EQ(hf.get(8), 9);
  ASSERT_EQ(hf.get(9), 9);
}

TEST(steps_1, Success)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  for (int n = 1; n < 10; ++n)
    ASSERT_TRUE(hf.add_fork(n + 1, n, n));
  hf.init();

  for (uint64_t h = 0; h < 10; ++h) {
    db.add_block(mkblock(hf, h), 0, 0, 0, 0, 0, crypto::hash());
    ASSERT_TRUE(hf.add(db.get_block_from_height(h), h));
  }

  // Index 0 is not consulted, so height 0 stays the original version.
  // Each later row is version h+1 at height h.
  ASSERT_EQ(hf.get(0), 1);
  for (uint64_t h = 1; h < 10; ++h)
    ASSERT_EQ(hf.get(h), h + 1);
  ASSERT_EQ(hf.get_current_version(), 10);
}

TEST(voting_info, reports_no_vote)
{
  TestDB db;
  HardFork hf(db);

  ASSERT_TRUE(hf.add_fork(1, 0, 0));
  ASSERT_TRUE(hf.add_fork(2, 5, 1));
  hf.init();

  uint32_t window = 9;
  uint32_t votes = 9;
  uint32_t threshold = 9;
  uint64_t earliest_height = 99;
  uint8_t voting = 0;

  // The chain is empty, so the schedule at the tip is still version 1.
  ASSERT_TRUE(hf.get_voting_info(1, window, votes, threshold, earliest_height, voting));
  ASSERT_EQ(window, 0u);
  ASSERT_EQ(votes, 0u);
  ASSERT_EQ(threshold, 0u);
  ASSERT_EQ(earliest_height, 0u);
  ASSERT_EQ(voting, 2);

  ASSERT_FALSE(hf.get_voting_info(2, window, votes, threshold, earliest_height, voting));
  ASSERT_EQ(window, 0u);
  ASSERT_EQ(votes, 0u);
  ASSERT_EQ(threshold, 0u);
  ASSERT_EQ(earliest_height, 5u);

  ASSERT_FALSE(hf.get_voting_info(3, window, votes, threshold, earliest_height, voting));
  ASSERT_EQ(earliest_height, std::numeric_limits<uint64_t>::max());
}

TEST(get, higher)
{
    TestDB db;
    HardFork hf(db);

    //                 v  h  t
    ASSERT_TRUE(hf.add_fork(1, 0, 0));
    ASSERT_TRUE(hf.add_fork(2, 2, 1));
    ASSERT_TRUE(hf.add_fork(3, 5, 2));
    hf.init();

    ASSERT_EQ(hf.get_ideal_version(0), 1);
    ASSERT_EQ(hf.get_ideal_version(1), 1);
    ASSERT_EQ(hf.get_ideal_version(2), 2);
    ASSERT_EQ(hf.get_ideal_version(3), 2);
    ASSERT_EQ(hf.get_ideal_version(4), 2);
    ASSERT_EQ(hf.get_ideal_version(5), 3);
    ASSERT_EQ(hf.get_ideal_version(6), 3);
    ASSERT_EQ(hf.get_ideal_version(7), 3);
}

TEST(get, earliest_ideal_height)
{
    TestDB db;
    HardFork hf(db);

    //                      v  h  t
    ASSERT_TRUE(hf.add_fork(1, 0, 0));
    ASSERT_TRUE(hf.add_fork(2, 2, 1));
    ASSERT_TRUE(hf.add_fork(5, 5, 2));
    ASSERT_TRUE(hf.add_fork(6, 10, 3));
    ASSERT_TRUE(hf.add_fork(9, 15, 4));
    hf.init();

    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(1), 0);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(2), 2);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(3), 5);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(4), 5);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(5), 5);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(6), 10);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(7), 15);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(8), 15);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(9), 15);
    ASSERT_EQ(hf.get_earliest_ideal_height_for_version(10), std::numeric_limits<uint64_t>::max());
}


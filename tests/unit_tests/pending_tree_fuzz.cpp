// Copyright (c) 2026, The Shekyl Project
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

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>
#include <array>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;

namespace {

static constexpr size_t LEAF_BYTES = 128;

struct TempLMDB {
  boost::filesystem::path tmpdir;
  BlockchainLMDB db;

  TempLMDB()
  {
    tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(tmpdir);
    db.open(tmpdir.string());
    db.set_batch_transactions(true);
  }

  ~TempLMDB()
  {
    try {
      db.close();
      boost::filesystem::remove_all(tmpdir);
    } catch (...) {}
  }
};

void make_leaf(uint8_t seed, uint8_t leaf[LEAF_BYTES])
{
  for (size_t i = 0; i < LEAF_BYTES; ++i)
    leaf[i] = static_cast<uint8_t>((seed + i) & 0xFF);
}

} // anonymous namespace

TEST(pending_tree_fuzz, add_remove_roundtrip)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  static constexpr uint64_t MAT_HEIGHT = 100;
  uint8_t leaf[LEAF_BYTES];
  make_leaf(0x42, leaf);

  db.add_pending_tree_leaf(MAT_HEIGHT, leaf);

  // Leaf should drain at exactly MAT_HEIGHT
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(MAT_HEIGHT - 1, drained);
  ASSERT_EQ(count, 0u);
  ASSERT_TRUE(drained.empty());

  count = db.drain_pending_tree_leaves(MAT_HEIGHT, drained);
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(drained.size(), LEAF_BYTES);
  ASSERT_EQ(memcmp(drained.data(), leaf, LEAF_BYTES), 0);

  db.batch_stop();
}

TEST(pending_tree_fuzz, add_remove_multiple_heights)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  for (uint64_t h = 10; h <= 15; ++h)
  {
    uint8_t leaf[LEAF_BYTES];
    make_leaf(static_cast<uint8_t>(h), leaf);
    db.add_pending_tree_leaf(h, leaf);
  }

  // Drain at height 12 should get leaves for 10, 11, 12
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(12, drained);
  ASSERT_EQ(count, 3u);
  ASSERT_EQ(drained.size(), 3 * LEAF_BYTES);

  // Drain at height 15 should get remaining 3
  drained.clear();
  count = db.drain_pending_tree_leaves(15, drained);
  ASSERT_EQ(count, 3u);
  ASSERT_EQ(drained.size(), 3 * LEAF_BYTES);

  // Nothing left
  drained.clear();
  count = db.drain_pending_tree_leaves(100, drained);
  ASSERT_EQ(count, 0u);

  db.batch_stop();
}

TEST(pending_tree_fuzz, drain_journal_entries)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  uint8_t leaf1[LEAF_BYTES], leaf2[LEAF_BYTES];
  make_leaf(0x01, leaf1);
  make_leaf(0x02, leaf2);

  db.add_pending_tree_drain_entry(50, 10, leaf1);
  db.add_pending_tree_drain_entry(50, 20, leaf2);

  auto entries = db.get_pending_tree_drain_entries(50);
  ASSERT_EQ(entries.size(), 2u);
  ASSERT_EQ(entries[0].first, 10u);
  ASSERT_EQ(entries[1].first, 20u);
  ASSERT_EQ(memcmp(entries[0].second.data(), leaf1, LEAF_BYTES), 0);
  ASSERT_EQ(memcmp(entries[1].second.data(), leaf2, LEAF_BYTES), 0);

  db.remove_pending_tree_drain_entries(50);
  entries = db.get_pending_tree_drain_entries(50);
  ASSERT_TRUE(entries.empty());

  db.batch_stop();
}

TEST(pending_tree_fuzz, randomized_add_pop_cycles)
{
  TempLMDB env;
  auto& db = env.db;

  std::mt19937 rng(12345);
  std::uniform_int_distribution<uint64_t> height_dist(1, 200);

  db.batch_start();

  struct PendingEntry {
    uint64_t maturity_height;
    std::array<uint8_t, LEAF_BYTES> leaf;
  };
  std::vector<PendingEntry> expected_pending;

  // Add 100 random leaves at random maturity heights
  for (int i = 0; i < 100; ++i)
  {
    PendingEntry e;
    e.maturity_height = height_dist(rng);
    make_leaf(static_cast<uint8_t>(i), e.leaf.data());
    db.add_pending_tree_leaf(e.maturity_height, e.leaf.data());
    expected_pending.push_back(e);
  }

  // Drain at various heights and verify counts
  uint64_t total_drained = 0;
  for (uint64_t h = 1; h <= 200; ++h)
  {
    uint64_t expected_count = 0;
    for (const auto& e : expected_pending)
      if (e.maturity_height == h) ++expected_count;

    std::vector<uint8_t> drained;
    uint64_t count = db.drain_pending_tree_leaves(h, drained);
    ASSERT_EQ(count, expected_count) << "Mismatch at height " << h;
    ASSERT_EQ(drained.size(), expected_count * LEAF_BYTES);
    total_drained += count;
  }

  ASSERT_EQ(total_drained, 100u);

  db.batch_stop();
}

TEST(pending_tree_fuzz, remove_pending_leaf)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  uint8_t leaf1[LEAF_BYTES], leaf2[LEAF_BYTES];
  make_leaf(0x10, leaf1);
  make_leaf(0x20, leaf2);

  db.add_pending_tree_leaf(100, leaf1);
  db.add_pending_tree_leaf(100, leaf2);

  // Remove one
  db.remove_pending_tree_leaf(100, leaf1);

  // Only leaf2 should drain
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(100, drained);
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(memcmp(drained.data(), leaf2, LEAF_BYTES), 0);

  db.batch_stop();
}

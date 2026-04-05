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

// ═══════════════════════════════════════════════════════════════════════════
// C1: Deferred insertion boundary
// Outputs appear in tree only at eligible_height, not before.
// ═══════════════════════════════════════════════════════════════════════════

TEST(deferred_insertion, outputs_not_drainable_before_maturity)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  // Add a leaf that matures at height 50
  uint8_t leaf[LEAF_BYTES];
  make_leaf(0xAA, leaf);
  db.add_pending_tree_leaf(50, leaf);

  // Verify it does NOT drain at heights < 50
  for (uint64_t h = 0; h < 50; ++h)
  {
    std::vector<uint8_t> drained;
    uint64_t count = db.drain_pending_tree_leaves(h, drained);
    ASSERT_EQ(count, 0u) << "Leaf drained too early at height " << h;
  }

  // At exactly height 50, the leaf should drain
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(50, drained);
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(drained.size(), LEAF_BYTES);
  ASSERT_EQ(memcmp(drained.data(), leaf, LEAF_BYTES), 0);

  db.batch_stop();
}

TEST(deferred_insertion, coinbase_maturity_window)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  // Simulate a coinbase output mined at height H=5.
  // Maturity height = H + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 5 + 60 = 65
  const uint64_t block_height = 5;
  const uint64_t maturity = block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
  uint8_t leaf[LEAF_BYTES];
  make_leaf(0x55, leaf);
  db.add_pending_tree_leaf(maturity, leaf);

  // Not drainable at maturity - 1
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(maturity - 1, drained);
  ASSERT_EQ(count, 0u);

  // Drainable at maturity
  count = db.drain_pending_tree_leaves(maturity, drained);
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(drained.size(), LEAF_BYTES);

  db.batch_stop();
}

TEST(deferred_insertion, regular_tx_maturity_window)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  // Simulate a regular tx output at height H=10.
  // Maturity height = H + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10 + 10 = 20
  const uint64_t block_height = 10;
  const uint64_t maturity = block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  uint8_t leaf[LEAF_BYTES];
  make_leaf(0x66, leaf);
  db.add_pending_tree_leaf(maturity, leaf);

  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(maturity - 1, drained);
  ASSERT_EQ(count, 0u);

  count = db.drain_pending_tree_leaves(maturity, drained);
  ASSERT_EQ(count, 1u);

  db.batch_stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// C2: pop_block atomicity (drain journal level)
// Add drain journal entries, retrieve them, remove them. Verify round-trip.
// Full pop_block atomicity is tested through core_tests with the FCMP++ tx
// helper (gen_fcmp_tx_valid covers the add path).
// ═══════════════════════════════════════════════════════════════════════════

TEST(deferred_insertion, drain_journal_atomicity)
{
  TempLMDB env;
  auto& db = env.db;

  db.batch_start();

  // Simulate: at block 100, we drained outputs that had maturity heights 50 and 60.
  uint8_t leaf1[LEAF_BYTES], leaf2[LEAF_BYTES];
  make_leaf(0x01, leaf1);
  make_leaf(0x02, leaf2);

  db.add_pending_tree_drain_entry(100, 50, leaf1);
  db.add_pending_tree_drain_entry(100, 60, leaf2);

  // Retrieve journal for block 100
  auto entries = db.get_pending_tree_drain_entries(100);
  ASSERT_EQ(entries.size(), 2u);

  // Entries should be (maturity_height, leaf_data) pairs
  ASSERT_EQ(entries[0].first, 50u);
  ASSERT_EQ(entries[1].first, 60u);
  ASSERT_EQ(memcmp(entries[0].second.data(), leaf1, LEAF_BYTES), 0);
  ASSERT_EQ(memcmp(entries[1].second.data(), leaf2, LEAF_BYTES), 0);

  // Simulate pop: remove drain entries and re-add leaves to pending
  for (const auto& [mat_h, leaf_arr] : entries)
    db.add_pending_tree_leaf(mat_h, leaf_arr.data());

  db.remove_pending_tree_drain_entries(100);

  // Journal should be empty
  entries = db.get_pending_tree_drain_entries(100);
  ASSERT_TRUE(entries.empty());

  // Leaves should be back in pending and drainable at their maturity heights
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(50, drained);
  ASSERT_EQ(count, 1u);

  drained.clear();
  count = db.drain_pending_tree_leaves(60, drained);
  ASSERT_EQ(count, 1u);

  db.batch_stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// C3: Insertion ordering determinism
// Two DB instances processing identical add/drain sequences produce the
// same drain output order.
// ═══════════════════════════════════════════════════════════════════════════

TEST(deferred_insertion, ordering_determinism)
{
  auto run_sequence = [](BlockchainLMDB& db) {
    db.batch_start();

    // Add multiple leaves at the same maturity height
    for (uint8_t i = 0; i < 10; ++i)
    {
      uint8_t leaf[LEAF_BYTES];
      make_leaf(i, leaf);
      db.add_pending_tree_leaf(100, leaf);
    }

    // Also add leaves at earlier heights to test mixed draining
    for (uint8_t i = 10; i < 15; ++i)
    {
      uint8_t leaf[LEAF_BYTES];
      make_leaf(i, leaf);
      db.add_pending_tree_leaf(50, leaf);
    }

    // Drain all
    std::vector<uint8_t> drained;
    db.drain_pending_tree_leaves(50, drained);
    db.drain_pending_tree_leaves(100, drained);

    db.batch_stop();
    return drained;
  };

  // Instance 1
  boost::filesystem::path dir1 = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  boost::filesystem::create_directories(dir1);
  BlockchainLMDB db1;
  db1.open(dir1.string());
  db1.set_batch_transactions(true);

  // Instance 2
  boost::filesystem::path dir2 = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  boost::filesystem::create_directories(dir2);
  BlockchainLMDB db2;
  db2.open(dir2.string());
  db2.set_batch_transactions(true);

  auto result1 = run_sequence(db1);
  auto result2 = run_sequence(db2);

  // Both must produce identical drain output
  ASSERT_EQ(result1.size(), result2.size());
  ASSERT_EQ(result1, result2);

  db1.close();
  db2.close();
  boost::filesystem::remove_all(dir1);
  boost::filesystem::remove_all(dir2);
}

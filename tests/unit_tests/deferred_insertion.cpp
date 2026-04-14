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
using shekyl::db::MaturityHeight;
using shekyl::db::OutputIndex;
using shekyl::db::BlockHeight;

namespace {

static constexpr size_t LEAF_BYTES = 128;
static uint64_t g_output_seq = 0;

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
  BlockchainDB& db = env.db;
  g_output_seq = 0;

  db.batch_start();

  uint8_t leaf[LEAF_BYTES];
  make_leaf(0xAA, leaf);
  db.add_pending_tree_leaf(MaturityHeight{50}, OutputIndex{g_output_seq++}, leaf);

  for (uint64_t h = 0; h < 50; ++h)
  {
    std::vector<uint8_t> drained;
    uint64_t count = db.drain_pending_tree_leaves(BlockHeight{h}, drained);
    ASSERT_EQ(count, 0u) << "Leaf drained too early at height " << h;
  }

  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(BlockHeight{50}, drained);
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(drained.size(), LEAF_BYTES);
  ASSERT_EQ(memcmp(drained.data(), leaf, LEAF_BYTES), 0);

  db.batch_stop();
}

TEST(deferred_insertion, coinbase_maturity_window)
{
  TempLMDB env;
  BlockchainDB& db = env.db;
  g_output_seq = 0;

  db.batch_start();

  const uint64_t block_height = 5;
  const uint64_t maturity = block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
  uint8_t leaf[LEAF_BYTES];
  make_leaf(0x55, leaf);
  db.add_pending_tree_leaf(MaturityHeight{maturity}, OutputIndex{g_output_seq++}, leaf);

  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(BlockHeight{maturity - 1}, drained);
  ASSERT_EQ(count, 0u);

  count = db.drain_pending_tree_leaves(BlockHeight{maturity}, drained);
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(drained.size(), LEAF_BYTES);

  db.batch_stop();
}

TEST(deferred_insertion, regular_tx_maturity_window)
{
  TempLMDB env;
  BlockchainDB& db = env.db;
  g_output_seq = 0;

  db.batch_start();

  const uint64_t block_height = 10;
  const uint64_t maturity = block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  uint8_t leaf[LEAF_BYTES];
  make_leaf(0x66, leaf);
  db.add_pending_tree_leaf(MaturityHeight{maturity}, OutputIndex{g_output_seq++}, leaf);

  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(BlockHeight{maturity - 1}, drained);
  ASSERT_EQ(count, 0u);

  count = db.drain_pending_tree_leaves(BlockHeight{maturity}, drained);
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
  BlockchainDB& db = env.db;
  g_output_seq = 0;

  db.batch_start();

  uint8_t leaf1[LEAF_BYTES], leaf2[LEAF_BYTES];
  make_leaf(0x01, leaf1);
  make_leaf(0x02, leaf2);

  db.add_pending_tree_drain_entry(BlockHeight{100}, OutputIndex{0}, MaturityHeight{50}, leaf1);
  db.add_pending_tree_drain_entry(BlockHeight{100}, OutputIndex{1}, MaturityHeight{60}, leaf2);

  auto entries = db.get_pending_tree_drain_entries(BlockHeight{100});
  ASSERT_EQ(entries.size(), 2u);

  ASSERT_EQ(entries[0].maturity.value, 50u);
  ASSERT_EQ(entries[1].maturity.value, 60u);
  ASSERT_EQ(memcmp(entries[0].leaf.data(), leaf1, LEAF_BYTES), 0);
  ASSERT_EQ(memcmp(entries[1].leaf.data(), leaf2, LEAF_BYTES), 0);

  for (const auto& entry : entries)
    db.add_pending_tree_leaf(entry.maturity, entry.output, entry.leaf.data());

  db.remove_pending_tree_drain_entries(BlockHeight{100});

  entries = db.get_pending_tree_drain_entries(BlockHeight{100});
  ASSERT_TRUE(entries.empty());

  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(BlockHeight{50}, drained);
  ASSERT_EQ(count, 1u);

  drained.clear();
  count = db.drain_pending_tree_leaves(BlockHeight{60}, drained);
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
  auto run_sequence = [](BlockchainDB& db) {
    uint64_t seq = 0;
    db.batch_start();

    for (uint8_t i = 0; i < 10; ++i)
    {
      uint8_t leaf[LEAF_BYTES];
      make_leaf(i, leaf);
      db.add_pending_tree_leaf(MaturityHeight{100}, OutputIndex{seq++}, leaf);
    }

    for (uint8_t i = 10; i < 15; ++i)
    {
      uint8_t leaf[LEAF_BYTES];
      make_leaf(i, leaf);
      db.add_pending_tree_leaf(MaturityHeight{50}, OutputIndex{seq++}, leaf);
    }

    std::vector<uint8_t> drained;
    db.drain_pending_tree_leaves(BlockHeight{50}, drained);
    db.drain_pending_tree_leaves(BlockHeight{100}, drained);

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

// ═══════════════════════════════════════════════════════════════════════════
// C4: Same-maturity leaf ordering by output index
// Multiple outputs at the same maturity height must drain in output_index
// order, not in leaf-content byte order.
// ═══════════════════════════════════════════════════════════════════════════

TEST(deferred_insertion, same_maturity_drain_order_by_output_index)
{
  TempLMDB env;
  BlockchainDB& db = env.db;
  g_output_seq = 0;

  db.batch_start();

  // Create leaves with different byte content but same maturity.
  // If DUPSORT were still in play, byte-sorted order would differ from
  // insertion order. Composite-key design guarantees output_index order.
  const size_t N = 10;
  std::vector<std::array<uint8_t, LEAF_BYTES>> leaves(N);
  for (size_t i = 0; i < N; ++i)
  {
    // Seed backwards so byte-sort would reverse the order
    make_leaf(static_cast<uint8_t>(N - 1 - i), leaves[i].data());
    db.add_pending_tree_leaf(MaturityHeight{100}, OutputIndex{g_output_seq++}, leaves[i].data());
  }

  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(BlockHeight{100}, drained);
  ASSERT_EQ(count, N);
  ASSERT_EQ(drained.size(), N * LEAF_BYTES);

  // Verify drain order matches insertion (output_index) order, not byte order
  for (size_t i = 0; i < N; ++i)
  {
    ASSERT_EQ(memcmp(drained.data() + i * LEAF_BYTES, leaves[i].data(), LEAF_BYTES), 0)
      << "Leaf at drain position " << i << " does not match output " << i
      << " -- drain order is not by output_index";
  }

  db.batch_stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// C5: Block pending journal round-trip
// Verify that add_block_pending_addition / get_block_pending_additions /
// remove_block_pending_additions round-trip correctly.
// ═══════════════════════════════════════════════════════════════════════════

TEST(deferred_insertion, block_pending_journal_round_trip)
{
  TempLMDB env;
  BlockchainDB& db = env.db;

  db.batch_start();

  db.add_block_pending_addition(BlockHeight{42}, OutputIndex{10}, MaturityHeight{100});
  db.add_block_pending_addition(BlockHeight{42}, OutputIndex{11}, MaturityHeight{110});
  db.add_block_pending_addition(BlockHeight{42}, OutputIndex{12}, MaturityHeight{100});

  auto entries = db.get_block_pending_additions(BlockHeight{42});
  ASSERT_EQ(entries.size(), 3u);

  // Should be ordered by output_index (composite key)
  ASSERT_EQ(entries[0].second.value, 10u);
  ASSERT_EQ(entries[1].second.value, 11u);
  ASSERT_EQ(entries[2].second.value, 12u);
  ASSERT_EQ(entries[0].first.value, 100u);
  ASSERT_EQ(entries[1].first.value, 110u);
  ASSERT_EQ(entries[2].first.value, 100u);

  // Unrelated block should be empty
  auto empty = db.get_block_pending_additions(BlockHeight{43});
  ASSERT_TRUE(empty.empty());

  // Remove
  db.remove_block_pending_additions(BlockHeight{42});
  entries = db.get_block_pending_additions(BlockHeight{42});
  ASSERT_TRUE(entries.empty());

  db.batch_stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// C6: Output↔Leaf mapping round-trip
// Verify bidirectional mapping tables work correctly.
// ═══════════════════════════════════════════════════════════════════════════

using shekyl::db::TreePosition;

TEST(deferred_insertion, output_leaf_mapping_round_trip)
{
  TempLMDB env;
  BlockchainDB& db = env.db;

  db.batch_start();

  db.add_output_leaf_mapping(OutputIndex{5}, TreePosition{0});
  db.add_output_leaf_mapping(OutputIndex{3}, TreePosition{1});
  db.add_output_leaf_mapping(OutputIndex{8}, TreePosition{2});

  // Forward lookup
  TreePosition pos{0};
  ASSERT_TRUE(db.get_output_leaf_index(OutputIndex{5}, pos));
  ASSERT_EQ(pos.value, 0u);
  ASSERT_TRUE(db.get_output_leaf_index(OutputIndex{3}, pos));
  ASSERT_EQ(pos.value, 1u);
  ASSERT_TRUE(db.get_output_leaf_index(OutputIndex{8}, pos));
  ASSERT_EQ(pos.value, 2u);

  // Reverse lookup
  OutputIndex out{0};
  ASSERT_TRUE(db.get_leaf_output_index(TreePosition{0}, out));
  ASSERT_EQ(out.value, 5u);
  ASSERT_TRUE(db.get_leaf_output_index(TreePosition{1}, out));
  ASSERT_EQ(out.value, 3u);
  ASSERT_TRUE(db.get_leaf_output_index(TreePosition{2}, out));
  ASSERT_EQ(out.value, 8u);

  // Nonexistent lookups
  ASSERT_FALSE(db.get_output_leaf_index(OutputIndex{99}, pos));
  ASSERT_FALSE(db.get_leaf_output_index(TreePosition{99}, out));

  // Remove with assertion
  db.remove_output_leaf_mapping(OutputIndex{3}, TreePosition{1});
  ASSERT_FALSE(db.get_output_leaf_index(OutputIndex{3}, pos));
  ASSERT_FALSE(db.get_leaf_output_index(TreePosition{1}, out));

  // Other mappings still intact
  ASSERT_TRUE(db.get_output_leaf_index(OutputIndex{5}, pos));
  ASSERT_EQ(pos.value, 0u);

  db.batch_stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// C7: Pop-block reversal via journal (unit-level)
// Add pending leaves for two blocks, drain at first block, then simulate
// pop_block by reading journals and reversing.
// ═══════════════════════════════════════════════════════════════════════════

TEST(deferred_insertion, pop_block_journal_reversal)
{
  TempLMDB env;
  BlockchainDB& db = env.db;
  g_output_seq = 0;

  db.batch_start();

  // Block 1: add 3 outputs with different maturities
  uint8_t leaf_a[LEAF_BYTES], leaf_b[LEAF_BYTES], leaf_c[LEAF_BYTES];
  make_leaf(0xA0, leaf_a);
  make_leaf(0xB0, leaf_b);
  make_leaf(0xC0, leaf_c);

  const OutputIndex oa{g_output_seq++}, ob{g_output_seq++}, oc{g_output_seq++};
  db.add_pending_tree_leaf(MaturityHeight{50}, oa, leaf_a);
  db.add_block_pending_addition(BlockHeight{1}, oa, MaturityHeight{50});
  db.add_pending_tree_leaf(MaturityHeight{50}, ob, leaf_b);
  db.add_block_pending_addition(BlockHeight{1}, ob, MaturityHeight{50});
  db.add_pending_tree_leaf(MaturityHeight{100}, oc, leaf_c);
  db.add_block_pending_addition(BlockHeight{1}, oc, MaturityHeight{100});

  // Drain at height 50 (only leaf_a, leaf_b mature)
  std::vector<uint8_t> drained;
  uint64_t count = db.drain_pending_tree_leaves(BlockHeight{50}, drained);
  ASSERT_EQ(count, 2u);

  // Now simulate pop_block for the drain at height 50:
  // 1. Read drain journal
  auto drain_entries = db.get_pending_tree_drain_entries(BlockHeight{50});
  ASSERT_EQ(drain_entries.size(), 2u);

  // 2. Restore drained leaves to pending
  for (const auto& entry : drain_entries)
    db.add_pending_tree_leaf(entry.maturity, entry.output, entry.leaf.data());
  db.remove_pending_tree_drain_entries(BlockHeight{50});

  // 3. Remove block 1's pending additions via journal
  auto additions = db.get_block_pending_additions(BlockHeight{1});
  ASSERT_EQ(additions.size(), 3u);
  for (const auto& [mat, out] : additions)
    db.remove_pending_tree_leaf(mat, out);
  db.remove_block_pending_additions(BlockHeight{1});

  // Verify: pending table is empty (all entries from block 1 removed)
  drained.clear();
  count = db.drain_pending_tree_leaves(BlockHeight{9999}, drained);
  ASSERT_EQ(count, 0u) << "Pending table should be empty after full pop reversal";

  // Journals should be empty too
  ASSERT_TRUE(db.get_pending_tree_drain_entries(BlockHeight{50}).empty());
  ASSERT_TRUE(db.get_block_pending_additions(BlockHeight{1}).empty());

  db.batch_stop();
}

// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// C2-R1b-Q1c: the prune watermark and the pop-refusal floor.
//
// Rick's three ratified vectors, decomposed to what a unit test can drive
// honestly (the derivation is in CONSENSUS_C2_R1_REORG.md §4b — the floor
// is quantized to settlement-epoch open heights, so the boundary vectors
// run against the SINGLE production predicate `pop_target_allowed`, and
// the belt is bitten through `BlockchainDB::pop_block` on a no-op double;
// F-2's no-revert guarantee is enforced structurally by the
// single-writer grep gate, since a real cross-boundary pop needs an
// SEB-scale chain no unit test can raise):
//
//   (ii)  pop to exactly `epoch_open_height(watermark)`  — allowed
//   (iii) one block below                                 — refused
//   belt: `pop_block` itself refuses (not only the pre-checks)
//
// Plus the writer's own contract: monotonic (lowering is a no-op, never
// an error), persistent across txn commit, write-txn-required.

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/testdb.h"
#include "shekyl/shekyl_ffi.h"

using cryptonote::BlockchainLMDB;

namespace
{

struct TempLMDB
{
  boost::filesystem::path tmpdir;
  BlockchainLMDB db;

  TempLMDB()
  {
    tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(tmpdir);
    db.open(tmpdir.string());
    db.set_batch_transactions(true);
    db.batch_start();
  }

  ~TempLMDB()
  {
    try {
      db.batch_stop();
      db.close();
      boost::filesystem::remove_all(tmpdir);
    } catch (...) {}
  }
};

// No-op double carrying only what the floor logic consumes: a height and a
// watermark. Everything else is BaseTestDB's inert stub, so a pop that gets
// PAST the belt completes silently — which is exactly the red this file was
// first observed with, before the belt landed.
class WatermarkTestDB : public cryptonote::BaseTestDB
{
public:
  uint64_t m_height = 0;
  uint64_t m_watermark = 0;

  uint64_t height() const override { return m_height; }
  uint64_t get_archival_prune_watermark_epoch() const override { return m_watermark; }
};

} // namespace

TEST(reorg_watermark, writer_is_monotonic_and_survives_commit)
{
  TempLMDB f;
  f.db.note_archival_prune_watermark_epoch(5);
  EXPECT_EQ(5u, f.db.get_archival_prune_watermark_epoch());
  // Lowering is a no-op, never an error: re-running an old prune must not
  // regress the floor (F-2: the receipt never retreats).
  f.db.note_archival_prune_watermark_epoch(3);
  EXPECT_EQ(5u, f.db.get_archival_prune_watermark_epoch());
  f.db.note_archival_prune_watermark_epoch(7);
  EXPECT_EQ(7u, f.db.get_archival_prune_watermark_epoch());
  // Persistence across the txn boundary the prune itself commits under.
  f.db.batch_stop();
  f.db.batch_start();
  EXPECT_EQ(7u, f.db.get_archival_prune_watermark_epoch());
}

TEST(reorg_watermark, writer_requires_write_txn)
{
  boost::filesystem::path tmpdir =
      boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  boost::filesystem::create_directories(tmpdir);
  BlockchainLMDB db;
  db.open(tmpdir.string());
  EXPECT_THROW(db.note_archival_prune_watermark_epoch(1), std::exception);
  db.close();
  boost::filesystem::remove_all(tmpdir);
}

TEST(reorg_watermark, predicate_boundary_vectors)
{
  WatermarkTestDB db;
  // No prune has ever run: every pop is journal-covered.
  db.m_watermark = 0;
  EXPECT_TRUE(db.pop_target_allowed(0));

  // Watermark epoch 1: the floor is that epoch's open height, from the SAME
  // FFI helper the prune uses.
  db.m_watermark = 1;
  const uint64_t open = shekyl_archival_epoch_open_height(1);
  ASSERT_GT(open, 0u);
  // Rick's vector (ii): pop landing exactly at the open height — allowed.
  EXPECT_TRUE(db.pop_target_allowed(open));
  // Rick's vector (iii): one block below — refused.
  EXPECT_FALSE(db.pop_target_allowed(open - 1));
}

TEST(reorg_watermark, pop_block_belt_refuses_below_floor)
{
  // The belt lives in BlockchainDB::pop_block itself (the single funnel all
  // four pop writers traverse), not only in the callers' pre-checks. On a
  // 5-block chain with watermark epoch 1 the floor is far above the tip, so
  // the very next pop must refuse — loudly, naming the watermark.
  WatermarkTestDB db;
  db.m_height = 5;
  db.m_watermark = 1;
  cryptonote::block blk;
  std::vector<cryptonote::transaction> txs;
  bool threw_with_watermark_message = false;
  try
  {
    db.pop_block(blk, txs);
  }
  catch (const std::exception& e)
  {
    threw_with_watermark_message =
        std::string(e.what()).find("prune watermark") != std::string::npos;
  }
  EXPECT_TRUE(threw_with_watermark_message)
      << "pop_block below the floor must refuse with a message naming the "
         "prune watermark (C2-R1b-Q1c belt)";
}

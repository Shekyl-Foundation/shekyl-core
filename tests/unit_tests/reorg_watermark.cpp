// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// C2-R1b-Q1c: the prune watermark and the pop-refusal floor.
//
// The floor's behaviour is pinned in Rust, where it is the lowest retained
// undo row: a pop at the floor lands and one below is a loud refusal that
// does not halt (shekyl-chain-store prune_tests.rs
// a_pop_below_the_undo_floor_is_a_refusal_not_si6; shekyl-chain-ingest
// switch_tests.rs pop_blocks_below_the_undo_floor_is_refused_before_any_pop).
// What stays here is the LMDB writer's own contract: monotonic (lowering is
// a no-op, never an error), persistent across txn commit,
// write-txn-required.

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"

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


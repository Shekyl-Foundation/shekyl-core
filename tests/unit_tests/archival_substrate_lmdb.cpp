// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <limits>
#include <vector>

#include "blockchain_db/lmdb/db_lmdb.h"

using namespace cryptonote;

namespace {

struct TempLMDB {
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

crypto::hash make_hash(uint8_t fill)
{
  crypto::hash h{};
  memset(h.data, fill, sizeof(h.data));
  return h;
}

} // namespace

TEST(archival_substrate_lmdb, bond_record_roundtrip)
{
  TempLMDB fixture;
  const crypto::hash p_id = make_hash(0x11);
  const std::vector<uint8_t> pubkey = {0x01, 0x02, 0x03, 0x04};
  const std::vector<uint64_t> shards = {7, 42};
  const std::vector<std::pair<uint64_t, uint64_t>> bad = {{5, 6}};

  BlockchainDB& db = fixture.db;
  db.put_archival_bond_record(p_id, pubkey, 3, shards, bad);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  std::vector<uint8_t> out_pubkey;
  ASSERT_TRUE(db.get_archival_bond_hybrid_pubkey(p_id, out_pubkey));
  EXPECT_EQ(out_pubkey, pubkey);
  EXPECT_EQ(db.archival_bond_join_epoch(p_id), 3u);
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 42, 0));
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 99, 0));
  EXPECT_TRUE(db.archival_bond_good_through(p_id, 4));
  EXPECT_FALSE(db.archival_bond_good_through(p_id, 3));
  EXPECT_FALSE(db.archival_bond_good_through(p_id, 5));

  db.remove_archival_bond_record(p_id);
  fixture.db.batch_stop();
  fixture.db.batch_start();
  EXPECT_FALSE(db.get_archival_bond_hybrid_pubkey(p_id, out_pubkey));
  EXPECT_EQ(db.archival_bond_join_epoch(p_id), std::numeric_limits<uint64_t>::max());
}

TEST(archival_substrate_lmdb, shard_registry_roundtrip)
{
  TempLMDB fixture;
  const crypto::hash rk = make_hash(0x22);
  BlockchainDB& db = fixture.db;
  db.put_archival_shard_segment(42, 100, rk, 26000);

  std::vector<uint8_t> scalars(128, 0x33);
  db.put_archival_shard_leaf_layer_scalars(42, 1234, scalars);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  crypto::hash out_rk{};
  uint64_t leaf_count = 0;
  EXPECT_FALSE(db.get_archival_shard_segment_at_height(42, 50, out_rk, leaf_count));
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(42, 100, out_rk, leaf_count));
  EXPECT_EQ(out_rk, rk);
  EXPECT_EQ(leaf_count, 26000u);

  std::vector<uint8_t> out_scalars;
  ASSERT_TRUE(db.get_archival_shard_leaf_layer_scalars(42, 1234, 100, out_scalars));
  EXPECT_EQ(out_scalars, scalars);
}

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
#include "blockchain_db/shekyl_types.h"

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

/// Minimum-length bond LMDB value with a non-v3 version byte.
///
/// `ArchivalBondValue::decode` rejects solely on `version != kVersion` once
/// `len >= 19`; no historical pre-v3 wire layout is load-bearing at genesis.
std::vector<uint8_t> non_v3_bond_blob(uint8_t version)
{
  std::vector<uint8_t> blob(19, 0);
  blob[0] = version;
  return blob;
}

} // namespace

TEST(archival_substrate_lmdb, bond_record_roundtrip)
{
  TempLMDB fixture;
  const crypto::hash p_id = make_hash(0x11);
  const std::vector<uint8_t> pubkey = {0x01, 0x02, 0x03, 0x04};
  const std::vector<uint64_t> shards = {7, 42};
  const std::vector<std::pair<uint64_t, uint64_t>> bad = {{5, 6}};
  const uint64_t bonded_total = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;

  BlockchainDB& db = fixture.db;
  db.put_archival_bond_record(p_id, pubkey, 3, bonded_total,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, shards, bad);
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

  shekyl::db::ArchivalBondValue roundtrip{};
  shekyl::db::ArchivalBondValue written{};
  written.hybrid_pubkey = pubkey;
  written.join_settlement_epoch = 3;
  written.bonded_total_atomic = bonded_total;
  written.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  written.held_shard_ids = shards;
  for (const auto& iv : bad)
  {
    shekyl::db::ArchivalBondValue::BadInterval entry{};
    entry.start_epoch = iv.first;
    entry.end_exclusive = iv.second;
    written.bad_intervals.push_back(entry);
  }
  const std::vector<uint8_t> encoded = written.encode();
  ASSERT_TRUE(shekyl::db::ArchivalBondValue::decode(encoded.data(), encoded.size(), roundtrip));
  EXPECT_EQ(roundtrip.bonded_total_atomic, bonded_total);

  db.remove_archival_bond_record(p_id);
  fixture.db.batch_stop();
  fixture.db.batch_start();
  EXPECT_FALSE(db.get_archival_bond_hybrid_pubkey(p_id, out_pubkey));
  EXPECT_EQ(db.archival_bond_join_epoch(p_id), std::numeric_limits<uint64_t>::max());
}

TEST(archival_substrate_lmdb, complete_tree_bond_holds_any_shard)
{
  TempLMDB fixture;
  const crypto::hash p_id = make_hash(0x44);
  const std::vector<uint8_t> pubkey = {0x05, 0x06};

  BlockchainDB& db = fixture.db;
  db.put_archival_bond_record(p_id, pubkey, 1, SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsCompleteTree, {}, {});
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, 0));
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 999, 0));
}

TEST(archival_substrate_lmdb, bond_reject_legacy_versions)
{
  shekyl::db::ArchivalBondValue decoded{};

  const std::vector<uint8_t> v1 = non_v3_bond_blob(1);
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(v1.data(), v1.size(), decoded));

  const std::vector<uint8_t> v2 = non_v3_bond_blob(2);
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(v2.data(), v2.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_reject_unknown_version)
{
  std::vector<uint8_t> blob = non_v3_bond_blob(1);
  blob[0] = 99;
  shekyl::db::ArchivalBondValue decoded{};
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(blob.data(), blob.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_v3_reject_truncated_after_join_epoch)
{
  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = {0x01, 0x02};
  bond.join_settlement_epoch = 7;
  bond.bonded_total_atomic = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  bond.held_shard_ids = {42};

  std::vector<uint8_t> encoded = bond.encode();
  ASSERT_GT(encoded.size(), 20u);
  encoded.resize(encoded.size() - 9);

  shekyl::db::ArchivalBondValue decoded{};
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(encoded.data(), encoded.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_v3_encode_version_byte)
{
  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = {0x0A};
  bond.join_settlement_epoch = 1;
  bond.bonded_total_atomic = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  bond.held_shard_ids = {7, 42};

  const std::vector<uint8_t> encoded = bond.encode();
  ASSERT_FALSE(encoded.empty());
  EXPECT_EQ(encoded[0], shekyl::db::ArchivalBondValue::kVersion);
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

// Storage-flow coverage for the gather → Rust compute → store epoch-close
// sweep. Exact R_market / Σwork arithmetic is pinned by the Rust KAT
// (consensus_state_kat_v1.json §epoch_close); this test asserts the LMDB
// orchestration: row gathering, missing-bond skips, stale-epoch filtering,
// persistence, revert, and replay determinism.
TEST(archival_substrate_lmdb, epoch_close_gather_compute_store_revert)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;

  // SETTLEMENT_EPOCH_BLOCKS is KAT-pinned at 10000; epoch E closes when the
  // first block of epoch E+1 connects.
  const uint64_t seb = 10000;
  const uint64_t settlement_epoch = 1;
  const uint64_t close_height = (settlement_epoch + 1) * seb;

  const crypto::hash p1 = make_hash(0x51);
  const crypto::hash p2 = make_hash(0x52);
  const crypto::hash p_missing = make_hash(0x53);
  const std::vector<uint8_t> pubkey = {0x01};

  db.put_archival_bond_record(p1, pubkey, 0, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
  db.put_archival_bond_record(p2, pubkey, 0, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7, 9}, {});

  // Aged segment for shard 7; shard 9 stays segment-less (age 0).
  db.put_archival_shard_segment(7, 0, make_hash(0x60), 26000);

  db.set_archival_serve_credit_bit(p1, 7, settlement_epoch);
  db.set_archival_serve_credit_bit(p2, 7, settlement_epoch);
  db.set_archival_serve_credit_bit(p2, 9, settlement_epoch);
  // Credit row without a bond record: gathered row is skipped, not fatal.
  db.set_archival_serve_credit_bit(p_missing, 7, settlement_epoch);
  // Credit row for a different epoch: filtered by the cursor pass.
  db.set_archival_serve_credit_bit(p1, 7, settlement_epoch + 1);

  // Non-boundary heights are no-ops.
  db.process_archival_epoch_close_at_height(close_height - 1);
  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 2u);
  EXPECT_EQ(db.get_archival_r_market(9, settlement_epoch), 1u);
  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch + 1), 0u);
  const uint64_t sigma = db.get_archival_sigma_work_milli(settlement_epoch);
  EXPECT_GT(sigma, 0u);

  db.revert_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 0u);
  EXPECT_EQ(db.get_archival_r_market(9, settlement_epoch), 0u);
  EXPECT_EQ(db.get_archival_sigma_work_milli(settlement_epoch), 0u);

  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 2u);
  EXPECT_EQ(db.get_archival_r_market(9, settlement_epoch), 1u);
  EXPECT_EQ(db.get_archival_sigma_work_milli(settlement_epoch), sigma);
}

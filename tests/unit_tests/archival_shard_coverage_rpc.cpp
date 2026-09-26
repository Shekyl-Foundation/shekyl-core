// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "gtest/gtest.h"

#include <limits>
#include <stdexcept>
#include <vector>

#include "archival_lmdb_test_helpers.h"
#include "rpc/archival_shard_coverage.h"
#include "rpc/archival_shard_fetch.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "shekyl/consensus_constants_generated.h"
#include "shekyl/shekyl_ffi.h"
#include "storages/portable_storage_template_helper.h"

using namespace cryptonote;

namespace {

/// Bond-record operands for `fill_archival_shard_coverage`. Ranking itself
/// stays in Rust (`shekyl-archival-retention`); this mock covers marshal
/// edges the C++ helper owns.
class FakeCoverageLMDB : public BlockchainLMDB
{
public:
  uint64_t fake_height = 0;
  uint64_t fake_leaf_count = 0;
  bool freeze_ok = true;
  uint64_t freeze_height = 0;
  std::vector<uint64_t> bonded;
  uint64_t budget = 0;
  uint64_t sigma = 0;

  uint64_t height() const override { return fake_height; }
  uint64_t get_curve_tree_leaf_count() const override { return fake_leaf_count; }
  bool archival_shard_freeze_height(uint64_t, uint64_t& out) const override
  {
    if (!freeze_ok)
      return false;
    out = freeze_height;
    return true;
  }
  void fold_archival_market_bonded_counts(std::vector<uint64_t>& bonded_count) const override
  {
    for (size_t i = 0; i < bonded_count.size() && i < bonded.size(); ++i)
      bonded_count[i] = bonded[i];
  }
  uint64_t get_archival_budget(uint64_t) const override { return budget; }
  uint64_t get_archival_sigma_work_milli(uint64_t) const override { return sigma; }
  uint64_t get_archival_r_market(uint64_t, uint64_t) const override { return 0; }
};

}  // namespace

TEST(archival_shard_coverage_rpc, fetch_is_typed_miss_until_scheduler)
{
  COMMAND_RPC_REQUEST_ARCHIVAL_SHARD::response res{};
  EXPECT_FALSE(rpc::fill_request_archival_shard(0, res));
  EXPECT_EQ(res.shard_id, 0u);
  EXPECT_TRUE(res.shard_hash.empty());
}

TEST(archival_shard_coverage_rpc, omitted_shard_id_is_sentinel_zero_is_real)
{
  COMMAND_RPC_REQUEST_ARCHIVAL_SHARD::request omitted{};
  ASSERT_TRUE(epee::serialization::load_t_from_json(omitted, "{}"));
  EXPECT_EQ(omitted.shard_id, std::numeric_limits<uint64_t>::max());

  COMMAND_RPC_REQUEST_ARCHIVAL_SHARD::request zero{};
  ASSERT_TRUE(epee::serialization::load_t_from_json(zero, "{\"shard_id\":0}"));
  EXPECT_EQ(zero.shard_id, 0u);
}

TEST(archival_shard_coverage_rpc, empty_frozen_universe_is_empty_list_at_tip)
{
  archival_test::TempArchivalLMDB<FakeCoverageLMDB> lmdb;
  FakeCoverageLMDB& db = lmdb.db;
  db.fake_height = 50000;
  db.fake_leaf_count = 0;

  COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::response res{};
  rpc::fill_archival_shard_coverage(db, res);
  EXPECT_EQ(res.as_of_height, 49999u);
  EXPECT_EQ(res.leaf_count, 0u);
  EXPECT_EQ(res.frozen_count, 0u);
  EXPECT_TRUE(res.shards.empty());
}

TEST(archival_shard_coverage_rpc, missing_freeze_row_throws)
{
  archival_test::TempArchivalLMDB<FakeCoverageLMDB> lmdb;
  FakeCoverageLMDB& db = lmdb.db;
  db.fake_height = 50000;
  db.fake_leaf_count = SHEKYL_ARCHIVAL_SEGMENT_LEAF_COUNT;
  db.freeze_ok = false;
  ASSERT_EQ(shekyl_archival_frozen_segment_count(db.fake_leaf_count), 1u);

  COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::response res{};
  EXPECT_THROW(rpc::fill_archival_shard_coverage(db, res), std::runtime_error);
}

TEST(archival_shard_coverage_rpc, marshal_orders_scarcer_shard_first)
{
  archival_test::TempArchivalLMDB<FakeCoverageLMDB> lmdb;
  FakeCoverageLMDB& db = lmdb.db;
  db.fake_height = 50000;
  db.fake_leaf_count = 2 * SHEKYL_ARCHIVAL_SEGMENT_LEAF_COUNT;
  db.freeze_ok = true;
  db.freeze_height = 1000;
  db.bonded = {4, 0};
  db.budget = 1000000;
  db.sigma = 1000;
  ASSERT_EQ(shekyl_archival_frozen_segment_count(db.fake_leaf_count), 2u);

  COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::response res{};
  rpc::fill_archival_shard_coverage(db, res);
  ASSERT_EQ(res.shards.size(), 2u);
  EXPECT_EQ(res.shards[0].shard_id, 1u);
  EXPECT_EQ(res.shards[1].shard_id, 0u);
  EXPECT_GT(res.shards[0].join_scarcity_micro, res.shards[1].join_scarcity_micro);
}

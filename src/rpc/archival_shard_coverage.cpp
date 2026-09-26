// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc/archival_shard_coverage.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{
namespace rpc
{

void fill_archival_shard_coverage(const BlockchainDB& db,
    COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::response& res)
{
  using cmd = COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE;

  // `db.height()` is the block count / next height. Age and last-settled
  // epoch are as of the included tip — the parent the next block will
  // connect on (`height() ? height()-1 : 0`). Passing the count itself
  // is one too high: at a settlement boundary the list would report an
  // epoch that has not closed.
  const uint64_t chain_height = db.height();
  const uint64_t tip_height = chain_height ? chain_height - 1 : 0;
  const uint64_t leaf_count = db.get_curve_tree_leaf_count();
  const uint64_t frozen_count = shekyl_archival_frozen_segment_count(leaf_count);
  const uint64_t settled = shekyl_archival_last_settled_epoch_as_of_parent(tip_height);
  const uint64_t budget = db.get_archival_budget(settled);
  const uint64_t sigma = db.get_archival_sigma_work_milli(settled);

  res.as_of_height = tip_height;
  res.leaf_count = leaf_count;
  res.frozen_count = frozen_count;
  res.settled_epoch = settled;
  res.budget_atomic = budget;
  res.sigma_work_milli = sigma;
  res.profit_estimate_available = sigma != 0;

  std::vector<uint64_t> bonded(frozen_count, 0);
  db.fold_archival_market_bonded_counts(bonded);

  std::vector<ShekylArchivalShardCoverageIn> ins(frozen_count);
  for (uint64_t shard_id = 0; shard_id < frozen_count; ++shard_id)
  {
    uint64_t freeze_height = 0;
    if (!db.archival_shard_freeze_height(shard_id, freeze_height))
    {
      // Frozen-universe membership is leaf-count geometry; a missing or
      // undecodable freeze row is inconsistency, not genesis height 0
      // (a real genesis freeze returns true with out=0). Ranking a hole
      // as oldest would lie.
      throw std::runtime_error(
          "missing freeze row for frozen shard " + std::to_string(shard_id));
    }
    ins[static_cast<size_t>(shard_id)] = ShekylArchivalShardCoverageIn{
      shard_id,
      bonded[static_cast<size_t>(shard_id)],
      db.get_archival_r_market(shard_id, settled),
      freeze_height,
    };
  }

  std::vector<ShekylArchivalShardCoverageOut> outs(frozen_count);
  size_t out_len = 0;
  const uint8_t rc = shekyl_archival_order_shard_coverage(
    tip_height,
    budget,
    sigma,
    frozen_count == 0 ? nullptr : ins.data(),
    static_cast<size_t>(frozen_count),
    frozen_count == 0 ? nullptr : outs.data(),
    outs.size(),
    &out_len);
  if (rc != SHEKYL_ARCHIVAL_SHARD_COVERAGE_OK)
    throw std::runtime_error("shard coverage order failed (rc=" + std::to_string(rc) + ")");
  if (out_len != frozen_count)
    throw std::runtime_error("shard coverage order length mismatch");

  res.shards.clear();
  res.shards.reserve(out_len);
  for (size_t i = 0; i < out_len; ++i)
  {
    cmd::coverage_row_t row{};
    row.shard_id = outs[i].shard_id;
    row.bonded_count = outs[i].bonded_count;
    row.served_count = outs[i].served_count;
    row.freeze_height = outs[i].freeze_height;
    row.join_scarcity_micro = outs[i].join_scarcity_micro;
    row.expected_profit_atomic = outs[i].expected_profit_atomic;
    res.shards.push_back(std::move(row));
  }
}

}  // namespace rpc
}  // namespace cryptonote

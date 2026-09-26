// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc/archival_shard_fetch.h"

#include <cstdint>
#include <cstring>

#include "crypto/hash.h"
#include "shekyl/shekyl_daemon_fetch.h"
#include "string_tools.h"

namespace cryptonote
{
namespace rpc
{

bool fill_request_archival_shard(
    uint64_t shard_id, COMMAND_RPC_REQUEST_ARCHIVAL_SHARD::response& res)
{
  res.shard_id = shard_id;
  res.shard_hash.clear();
  res.block_count = 0;
  res.tx_count = 0;
  res.output_count = 0;
  res.coinbase_output_count = 0;
  res.time_range_seconds = 0;

  ShekylArchivalShardAggregateOut out{};
  const uint8_t rc = shekyl_daemon_operator_shard_fetch(shard_id, &out);
  if (rc != SHEKYL_DAEMON_SHARD_FETCH_OK)
    return false;
  // Echo the request id. A scheduler that fills a different shard is a
  // bug, not a view of that other body.
  if (out.shard_id != shard_id)
    return false;

  crypto::hash rk{};
  std::memcpy(rk.data, out.shard_hash, sizeof(rk.data));
  res.shard_id = shard_id;
  res.shard_hash = epee::string_tools::pod_to_hex(rk);
  res.block_count = out.block_count;
  res.tx_count = out.tx_count;
  res.output_count = out.output_count;
  res.coinbase_output_count = out.coinbase_output_count;
  res.time_range_seconds = out.time_range_seconds;
  return true;
}

}  // namespace rpc
}  // namespace cryptonote

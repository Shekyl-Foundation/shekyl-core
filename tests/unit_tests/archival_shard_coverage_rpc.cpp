// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "gtest/gtest.h"

#include "rpc/archival_shard_fetch.h"
#include "rpc/core_rpc_server_commands_defs.h"

using namespace cryptonote;

TEST(archival_shard_coverage_rpc, fetch_is_typed_miss_until_scheduler)
{
  COMMAND_RPC_REQUEST_ARCHIVAL_SHARD::response res{};
  EXPECT_FALSE(rpc::fill_request_archival_shard(0, res));
  EXPECT_EQ(res.shard_id, 0u);
  EXPECT_TRUE(res.shard_hash.empty());
}

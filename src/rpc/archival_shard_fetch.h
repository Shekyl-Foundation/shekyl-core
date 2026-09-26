// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "rpc/core_rpc_server_commands_defs.h"

namespace cryptonote
{
namespace rpc
{

/// Operator view-fetch: names `shard_id` only (`ARCHIVAL_SHARD_FETCH.md` SF-D1).
///
/// Every node prunes. This is a marshal over
/// `shekyl_daemon_operator_shard_fetch` (staker hold, view-cache, or Tor
/// fetch when that scheduler is wired). Typed miss until then. Returns
/// false on miss.
bool fill_request_archival_shard(
    uint64_t shard_id, COMMAND_RPC_REQUEST_ARCHIVAL_SHARD::response& res);

}  // namespace rpc
}  // namespace cryptonote

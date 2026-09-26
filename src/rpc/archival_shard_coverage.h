// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "rpc/core_rpc_server_commands_defs.h"

namespace cryptonote
{

class BlockchainDB;

namespace rpc
{

/// Fill `get_archival_shard_coverage` from `db`.
///
/// C++ marshals **bond-record** operands (frozen universe, market bonded
/// counts, last-epoch served counts, freeze heights, budget/sigma) — not
/// shard bodies; every node prunes. Rust orders by join-adjusted scarcity
/// (`shekyl_archival_order_shard_coverage`). No `p_id` on the request; the
/// answer is identical for every caller (SL-D7). Throws on marshal failure
/// — the handler must catch and refuse the whole response.
void fill_archival_shard_coverage(const BlockchainDB& db,
    COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::response& res);

}  // namespace rpc
}  // namespace cryptonote

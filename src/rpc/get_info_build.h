// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// `get_info`'s computation, separated from its reads
// (docs/design/DAEMON_RPC_KV_GET_INFO.md §4.4, RK-5c commit 3).
//
// `on_get_info` holds policy, not only reads: a synchronized sentinel, the
// restricted stand-ins, a subtraction across two stores, the economics
// projection. An oracle vector captured by serializing a hand-built response
// would pin the serializer and none of that. So the handler gathers
// `get_info_facts` and `build_get_info` computes the reply from them, and the
// oracle emitter (tests/unit_tests/rpc_oracle_vectors.cpp) drives the same
// function from fixed facts.
//
// This exists to be captured. It is deleted with the handler when `get_info`
// is served from Rust.

#pragma once

#include <cstdint>
#include <string>

#include "crypto/hash.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_config.h"
#include "rpc/core_rpc_server_commands_defs.h"

namespace cryptonote
{
  // Everything `get_info` reads, and nothing it decides. Each member is one
  // read; none depends on who is asking.
  struct get_info_facts
  {
    // Chain. `height` is the chain count: the top block's height plus one.
    uint64_t height = 0;
    crypto::hash top_hash = crypto::null_hash;
    difficulty_type difficulty_for_next_block = 0;
    // Cumulative difficulty of the block at `height - 1`.
    difficulty_type cumulative_difficulty = 0;
    uint64_t difficulty_target = 0;
    uint64_t total_transactions = 0;
    uint64_t alt_blocks_count = 0;
    uint64_t block_weight_limit = 0;
    uint64_t block_weight_median = 0;
    uint64_t adjusted_time = 0;
    uint64_t database_size = 0;
    bool following_degraded = false;

    // Synchronization. The handler reads the one predicate twice, once for
    // the target sentinel and once for `synchronized`; both reads are kept.
    bool protocol_synchronized = false;
    bool core_ready = false;
    uint64_t core_target_height = 0;
    bool busy_syncing = false;

    // Pool, read both ways: every entry, and the broadcast set only.
    uint64_t pool_count_all = 0;
    uint64_t pool_count_broadcast = 0;

    // Peers. `public_connections` is the clearnet zone's total;
    // `public_outgoing_connections` its outbound sessions.
    uint64_t public_connections = 0;
    uint64_t public_outgoing_connections = 0;
    uint64_t public_incoming_sockets = 0;
    uint64_t public_outgoing_sockets = 0;
    uint64_t tor_incoming_sockets = 0;
    uint64_t tor_outgoing_sockets = 0;
    uint64_t white_peerlist_size = 0;
    uint64_t grey_peerlist_size = 0;

    // Node.
    network_type nettype = MAINNET;
    uint64_t start_time = 0;
    uint64_t free_space = 0;
    bool offline = false;
    std::string version;

    // Economics operands.
    uint64_t already_generated_coins = 0;
    uint64_t total_burned = 0;
    uint64_t tx_volume_count_sum = 0;
    uint64_t tx_volume_blocks = 0;
    uint64_t genesis_ng_height = 0;
  };

  // Compute the reply from the facts and the caller's posture. Reads nothing.
  void build_get_info(const get_info_facts& facts, bool restricted, COMMAND_RPC_GET_INFO::response& res);
}

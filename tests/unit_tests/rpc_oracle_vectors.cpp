// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// RK-5c oracle capture (docs/design/DAEMON_RPC_KV_GET_INFO.md §4.4;
// docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what the C++ answers for `get_info` before its handler and
// COMMAND_RPC_GET_INFO are deleted. Written for this slice and deleted with
// the struct it captures, as the vectors' README requires.
//
// **This emitter runs the handler's computation, not only its serializer.**
// Earlier emitters built a response by hand from fixed values, which was
// right for handlers that only read. `get_info` decides: the synchronized
// sentinel, the restricted stand-ins, a subtraction across two counts, the
// economics projection and its refusal. So each vector here is
// `build_get_info` over fixed facts — the same function `on_get_info` calls
// after gathering — and a change to that policy moves a vector.
//
// The vectors are stored LF (the README's 2026-09-05 ruling). epee emits
// CRLF, so both the write and the comparison normalise; nothing reads these
// bytes as bytes.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/get_info_build.h"
#include "storages/portable_storage_template_helper.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
  std::string lf(const std::string& text)
  {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i)
    {
      if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n')
        continue;
      out.push_back(text[i]);
    }
    return out;
  }

  void pin(const char* name, const std::string& json)
  {
    const std::string path = std::string(RPC_ORACLE_VECTOR_DIR) + "/" + name;
    const std::string wanted = lf(json);
    if (std::getenv("SHEKYL_WRITE_RPC_VECTORS"))
    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.good()) << "cannot write " << path;
      out << wanted;
      return;
    }
    std::ifstream in(path, std::ios::binary);
    ASSERT_TRUE(in.good()) << "missing oracle vector " << path
      << " (run with SHEKYL_WRITE_RPC_VECTORS=1 to capture)";
    std::stringstream buf;
    buf << in.rdbuf();
    EXPECT_EQ(buf.str(), wanted) << "oracle vector " << name << " drifted from the handler's output";
  }

  // Same generator as every earlier emitter's and the Rust parity test's.
  crypto::hash tagged_hash(uint8_t tag)
  {
    crypto::hash h;
    auto* bytes = reinterpret_cast<unsigned char*>(h.data);
    for (size_t i = 0; i < sizeof(h.data); ++i)
      bytes[i] = static_cast<unsigned char>((i * 7 + tag) & 0xff);
    return h;
  }

  std::string emit(cryptonote::COMMAND_RPC_GET_INFO::response& res)
  {
    std::string json;
    EXPECT_TRUE(epee::serialization::store_t_to_json(res, json));
    return json;
  }

  // A synchronized mainnet node with peers on both connectors. Every member
  // is non-zero and no two members that share a type share a value, so a
  // reply that swapped two reads does not equal its vector. Both
  // difficulties exceed 64 bits, so the `_top64` halves are exercised.
  cryptonote::get_info_facts synced_facts()
  {
    cryptonote::get_info_facts f;
    f.height = 1234567;
    f.top_hash = tagged_hash(1);
    f.difficulty_for_next_block = (cryptonote::difficulty_type(7) << 64) + 123456789;
    f.cumulative_difficulty = (cryptonote::difficulty_type(9) << 64) + 987654321;
    f.difficulty_target = 120;
    f.total_transactions = 1300000;
    f.alt_blocks_count = 3;
    f.block_weight_limit = 600000;
    f.block_weight_median = 300000;
    f.adjusted_time = 1700000123;
    // One byte over 7 GiB: a restricted reply rounds it up to 10 GiB.
    f.database_size = 7ull * 1024 * 1024 * 1024 + 1;
    f.following_degraded = false;

    f.protocol_synchronized = true;
    f.core_ready = true;
    f.core_target_height = 1234567;
    f.busy_syncing = false;

    f.pool_count_all = 12;
    f.pool_count_broadcast = 9;

    f.public_connections = 20;
    f.public_outgoing_connections = 8;
    f.public_incoming_sockets = 13;
    f.public_outgoing_sockets = 10;
    f.tor_incoming_sockets = 4;
    f.tor_outgoing_sockets = 2;
    f.white_peerlist_size = 500;
    f.grey_peerlist_size = 2500;

    f.nettype = cryptonote::MAINNET;
    f.start_time = 1699990000;
    f.free_space = 123456789012ull;
    f.offline = false;
    f.version = "3.1.0-oracle";

    f.already_generated_coins = 1444065674085133ull;
    f.total_burned = 4200000000ull;
    f.tx_volume_count_sum = 6000;
    f.tx_volume_blocks = 100;
    return f;
  }

  std::string get_info(const cryptonote::get_info_facts& facts, bool restricted)
  {
    cryptonote::COMMAND_RPC_GET_INFO::response res{};
    cryptonote::build_get_info(facts, restricted, res);
    return emit(res);
  }
}

// Synchronized, full disclosure. `target_height` is written 0: the sentinel.
TEST(rpc_oracle_vectors, get_info_synced)
{
  pin("get_info_synced_v1.json", get_info(synced_facts(), false));
}

// Not synchronized, with a target ahead of the chain: the real target is
// written. `following_degraded` and `busy_syncing` are set here so each has a
// vector in which it is true.
TEST(rpc_oracle_vectors, get_info_syncing)
{
  cryptonote::get_info_facts f = synced_facts();
  f.protocol_synchronized = false;
  f.core_ready = false;
  f.core_target_height = 1300000;
  f.busy_syncing = true;
  f.following_degraded = true;
  pin("get_info_syncing_v1.json", get_info(f, false));
}

// Just started, no peers, on a fakechain: not synchronized and the core has
// no target. `target_height` is 0 here too, for the other reason — the state
// the sentinel cannot be told from.
TEST(rpc_oracle_vectors, get_info_peerless_startup)
{
  cryptonote::get_info_facts f = synced_facts();
  f.nettype = cryptonote::FAKECHAIN;
  f.protocol_synchronized = false;
  f.core_ready = false;
  f.core_target_height = 0;
  f.public_connections = 0;
  f.public_outgoing_connections = 0;
  f.public_incoming_sockets = 0;
  f.public_outgoing_sockets = 0;
  f.tor_incoming_sockets = 0;
  f.tor_outgoing_sockets = 0;
  pin("get_info_peerless_startup_v1.json", get_info(f, false));
}

// The same facts as `get_info_synced`, asked by a restricted caller: every
// stand-in. Zeroed counts (alternative blocks, both connection counts, four
// socket counts, both peerlist sizes, start time), free space as u64::MAX,
// database size rounded up to 5 GiB, an empty version, and the pool counted
// over the broadcast set.
TEST(rpc_oracle_vectors, get_info_synced_restricted)
{
  pin("get_info_synced_restricted_v1.json", get_info(synced_facts(), true));
}

// More burned than generated: the burn computation refuses, the reply
// carries `burn_pct` 0 and the refusal is logged.
TEST(rpc_oracle_vectors, get_info_burn_refusal)
{
  cryptonote::get_info_facts f = synced_facts();
  f.total_burned = f.already_generated_coins + 1;
  pin("get_info_burn_refusal_v1.json", get_info(f, false));
}

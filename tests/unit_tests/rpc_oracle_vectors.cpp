// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// RK-5a oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what epee emits for `sync_info`, `/get_net_stats`, `/get_peer_list`
// and `get_connections` before their handlers and their COMMAND_RPC_ structs
// are deleted. Re-created for this slice; the RK-4c emitter was deleted with
// the structs it captured, as the vectors' README requires.
//
// What these four have that the earlier slices did not is **shape that lives
// outside the struct declaration**:
//
//   every empty sequence   -> omitted, not `[]` — white_list, gray_list,
//                             connections, peers, spans. Measured on a live
//                             regtest node: an idle daemon answers
//                             `/get_peer_list` with `{"status":"OK"}` and
//                             nothing else.
//   peer.pruning_seed      -> OPT 0, so it vanishes on an unpruned peer and
//                             appears on a pruned one. The populated vector
//                             carries one of each.
//   request public_only    -> OPT **true**, the one default in this slice
//                             that is not false: it is omitted when true and
//                             emitted when false, which is the inverse of
//                             every other OPT here.
//   connection_info.ssl    -> a member with **no KV row**. It never reaches
//                             the wire, which is why the console column fed
//                             by it printed a constant over RPC. Captured by
//                             its absence: the vector sets it true.
//   peer.ip vs
//   connection_info.ip     -> the same name, different types. `peer.ip` is a
//                             number (uint32, ipv4 only); `connection_info.ip`
//                             is a string. A mirror that picked one shape for
//                             both round-trips neither.
//
// The three address arms of `peer` are a construction-time branch, not a
// serialization one, so they are captured as three entries: ipv4 (host is the
// ip string, `ip` and `port` set), ipv6 (host is `host_str()`, `ip` zero,
// `port` set), and everything else (host is the whole `str()`, `ip` and
// `port` both zero).
//
// Deleted with the structs it captures, later in this slice.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
  void pin(const char* name, const std::string& json)
  {
    const std::string path = std::string(RPC_ORACLE_VECTOR_DIR) + "/" + name;
    if (std::getenv("SHEKYL_WRITE_RPC_VECTORS"))
    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.good()) << "cannot write " << path;
      out << json;
      return;
    }
    std::ifstream in(path, std::ios::binary);
    ASSERT_TRUE(in.good()) << "missing oracle vector " << path
      << " (run with SHEKYL_WRITE_RPC_VECTORS=1 to capture)";
    std::stringstream buf;
    buf << in.rdbuf();
    EXPECT_EQ(buf.str(), json) << "oracle vector " << name << " drifted from epee's output";
  }

  // Same generator as the RK-4c emitter's and the Rust parity test's: a value
  // that is a function of its tag, so a transposed field is visible.
  std::string tagged_hex(uint8_t tag)
  {
    crypto::hash h;
    auto* bytes = reinterpret_cast<unsigned char*>(h.data);
    for (size_t i = 0; i < sizeof(h.data); ++i)
      bytes[i] = static_cast<unsigned char>((i * 7 + tag) & 0xff);
    return epee::string_tools::pod_to_hex(h);
  }

  template <class T>
  std::string emit(T& obj)
  {
    std::string json;
    EXPECT_TRUE(epee::serialization::store_t_to_json(obj, json));
    return json;
  }

  // A fully-populated `connection_info`, shared by `get_connections` and
  // `sync_info` — the same C++ object appears in both, nested under `info` in
  // the second, and capturing it twice is what says the nesting is real.
  cryptonote::connection_info populated_connection()
  {
    cryptonote::connection_info info{};
    info.incoming = true;
    info.localhost = false;
    info.local_ip = true;
    // No KV row: set true here precisely so its absence from the vector is
    // asserted rather than assumed.
    info.ssl = true;
    info.address = "192.0.2.7:18080";
    info.host = "192.0.2.7";
    info.ip = "192.0.2.7";
    info.port = "18080";
    info.peer_id = "ee32594917a6a97e";
    info.recv_count = 405;
    info.recv_idle_time = 2;
    info.send_count = 338;
    info.send_idle_time = 3;
    info.state = "normal";
    info.live_time = 4242;
    info.avg_download = 11;
    info.current_download = 12;
    info.avg_upload = 13;
    info.current_upload = 14;
    info.support_flags = 3;
    info.connection_id = tagged_hex(21).substr(0, 32);
    info.height = 1234567;
    info.pruning_seed = 384;
    info.address_type = 1;
    return info;
  }
}

// ─── /get_net_stats ──────────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_net_stats_v1)
{
  // Five plain members: nothing here is OPT, so the shape is fixed and the
  // vector's job is field names, types and the parent's `status`.
  cryptonote::COMMAND_RPC_GET_NET_STATS::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.start_time = 1788202424;
  res.total_packets_in = 101;
  res.total_bytes_in = 202020;
  res.total_packets_out = 303;
  res.total_bytes_out = 404040;
  pin("get_net_stats_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_NET_STATS::response_t&>(res)));
}

// ─── /get_peer_list ──────────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_peer_list_request_v1)
{
  // Both members away from their defaults. `public_only` defaults **true**,
  // so "away from default" here means false — the pair with the vector below
  // is what pins the polarity.
  cryptonote::COMMAND_RPC_GET_PEER_LIST::request req{};
  req.public_only = false;
  req.include_blocked = true;
  pin("get_peer_list_request_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_PEER_LIST::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_peer_list_request_defaults_v1)
{
  // Both at their defaults, so both vanish and the document is empty of
  // members. An implementation that emitted `public_only: true` would be
  // emitting a document the daemon never produced.
  cryptonote::COMMAND_RPC_GET_PEER_LIST::request req{};
  req.public_only = true;
  req.include_blocked = false;
  pin("get_peer_list_request_defaults_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_PEER_LIST::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_peer_list_v1)
{
  // The three address arms, plus both `pruning_seed` states, in one document.
  cryptonote::COMMAND_RPC_GET_PEER_LIST::response res{};
  res.status = CORE_RPC_STATUS_OK;
  // ipv4: `host` is the ip string, `ip` is the number, `port` is set.
  res.white_list.emplace_back(
    static_cast<uint64_t>(0x1122334455667788ULL), static_cast<uint32_t>(0x0700200aU),
    static_cast<uint16_t>(18080), static_cast<uint64_t>(1750000001), static_cast<uint32_t>(0));
  // ipv6: `host` is `host_str()`, `ip` stays 0, `port` is set. Pruned, so
  // `pruning_seed` appears here and not on the entry above.
  res.white_list.emplace_back(
    static_cast<uint64_t>(0x99aabbccddeeff00ULL), std::string("2001:db8::1"),
    static_cast<uint16_t>(18081), static_cast<uint64_t>(1750000002), static_cast<uint32_t>(384));
  // Anything else (tor, i2p): `host` is the whole `str()`, and neither `ip`
  // nor `port` is carried.
  res.gray_list.emplace_back(
    static_cast<uint64_t>(0x0102030405060708ULL),
    std::string("abcdefghijklmnop.onion:18080"),
    static_cast<uint64_t>(1750000003), static_cast<uint32_t>(0));
  pin("get_peer_list_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_PEER_LIST::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_peer_list_empty_v1)
{
  // What an idle node actually answers. Both sequences are **omitted**, not
  // `[]` — measured live before this capture was written.
  cryptonote::COMMAND_RPC_GET_PEER_LIST::response res{};
  res.status = CORE_RPC_STATUS_OK;
  pin("get_peer_list_empty_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_PEER_LIST::response_t&>(res)));
}

// ─── get_connections ─────────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_connections_v1)
{
  cryptonote::COMMAND_RPC_GET_CONNECTIONS::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.connections.push_back(populated_connection());
  pin("get_connections_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_CONNECTIONS::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_connections_empty_v1)
{
  cryptonote::COMMAND_RPC_GET_CONNECTIONS::response res{};
  res.status = CORE_RPC_STATUS_OK;
  pin("get_connections_empty_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_CONNECTIONS::response_t&>(res)));
}

// ─── sync_info ───────────────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, sync_info_v1)
{
  // `peers` nests `connection_info` under an `info` key; `spans` is a
  // separate flat struct. Both populated so the nesting and the span field
  // names are pinned in one document.
  cryptonote::COMMAND_RPC_SYNC_INFO::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.height = 1234567;
  res.target_height = 1234600;
  res.next_needed_pruning_seed = 1;
  res.overview = "[<...m_o]";

  cryptonote::COMMAND_RPC_SYNC_INFO::peer peer{};
  peer.info = populated_connection();
  res.peers.push_back(peer);

  cryptonote::COMMAND_RPC_SYNC_INFO::span span{};
  span.start_block_height = 1234570;
  span.nblocks = 20;
  span.connection_id = tagged_hex(21).substr(0, 32);
  span.rate = 4096;
  span.speed = 75;
  span.size = 81920;
  span.remote_address = "192.0.2.7:18080";
  res.spans.push_back(span);

  pin("sync_info_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_SYNC_INFO::response_t&>(res)));
}

TEST(rpc_oracle_vectors, sync_info_empty_v1)
{
  // The idle case, measured live: `peers` and `spans` omitted entirely, and
  // `overview` present as the two-character empty rendering — a *string*
  // "[]", not an empty array, which is the one place in this reply where the
  // difference is easy to model wrongly.
  cryptonote::COMMAND_RPC_SYNC_INFO::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.height = 1;
  res.target_height = 0;
  res.next_needed_pruning_seed = 1;
  res.overview = "[]";
  pin("sync_info_empty_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_SYNC_INFO::response_t&>(res)));
}

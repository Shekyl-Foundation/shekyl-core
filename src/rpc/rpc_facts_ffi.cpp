// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc_facts_ffi.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "core_rpc_ffi_internal.h"
#include "cryptonote_core/cryptonote_core.h"
#include "net/net_utils_base.h"
#include "p2p/net_node.h"
#include "p2p/seam_board.h"
#include "p2p/seam_endpoint.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_ffi.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc.facts"

namespace daemon_rpc_facts {
// The strings are filled first and the views taken afterwards, because a
// pointer taken during the fill would dangle the moment a vector reallocated.
struct connections_owner
{
  std::vector<std::string> address;
  std::vector<std::string> host;
  std::vector<shekyl_rpc_connection_facts> entries;
}
;
} // namespace daemon_rpc_facts

extern "C" {

// Every export is an exception barrier: a throw from a P2P read is logged
// and becomes SHEKYL_RPC_FACTS_ERR_INTERNAL, never an unwind across the C
// ABI into Rust. What remains here is net stats and the board's connections.
// Chain and get_info reads go through the store; chain sync's view is the
// node's (CS-5 §7).

int shekyl_rpc_net_stats(core_rpc_handle* h, shekyl_rpc_net_stats_facts* out)
{
  if (!h || !h->core || !out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  try
  {
    std::memset(out, 0, sizeof(*out));
    out->start_time = static_cast<uint64_t>(h->core->get_start_time());
    shekyl_link_totals(&out->total_bytes_in, &out->total_packets_in,
      &out->total_bytes_out, &out->total_packets_out);
    return SHEKYL_RPC_FACTS_OK;
  }
  catch (const std::exception& e)
  {
    MERROR("net stats facts: exception: " << e.what());
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("net stats facts: unknown exception");
    std::memset(out, 0, sizeof(*out));
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
}

int shekyl_rpc_connections(core_rpc_handle* h, uint64_t* out_now,
  const shekyl_rpc_connection_facts** out, size_t* out_len, void** out_owner)
{
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->p2p || !out_now || !out || !out_len || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  *out_now = 0;
  std::unique_ptr<daemon_rpc_facts::connections_owner> owned;
  try
  {
    owned.reset(new daemon_rpc_facts::connections_owner());
    // **One clock read for the whole snapshot.** The C++ handler this
    // replaces read `time(NULL)` twice per connection, so a connection's
    // reported `live_time` and the divisor behind its own averages could come
    // from different seconds. Every elapsed quantity is now derived by the
    // caller against this one instant.
    const uint64_t now = static_cast<uint64_t>(time(NULL));
    // Address, direction, the handshake flag, and admission time come from
    // the board. Last receive and last send are unix time of the monotonic
    // byte stamps. The peer's claim and what chain sync is doing with the
    // session are the sync owner's view, read by the caller (CS-5 §7).
    for (const auto& row : shekyl::seam_board_snapshot())
    {
      const epee::net_utils::network_address address = shekyl::seam_network_address(row.endpoint);
      const boost::uuids::uuid id = shekyl::seam_connection_id(row.id);
      shekyl_rpc_connection_facts e;
      std::memset(&e, 0, sizeof(e));
      owned->address.push_back(address.str());
      owned->host.push_back(address.host_str());
      std::memcpy(e.connection_id, id.data, sizeof(e.connection_id));
      e.port = address.port();
      e.address_type = static_cast<uint8_t>(address.get_type_id());
      e.incoming = row.endpoint.direction == SHEKYL_DIRECTION_INBOUND ? 1 : 0;
      e.localhost = address.is_loopback() ? 1 : 0;
      e.local_ip = address.is_local() ? 1 : 0;
      e.started = row.started;
      if (row.id != 0)
      {
        std::uint64_t send_ms = 0;
        std::uint64_t recv_ms = 0;
        shekyl_link_unix_ms(row.id, &send_ms, &recv_ms);
        e.last_send = send_ms / 1000;
        e.last_recv = recv_ms / 1000;
        std::uint64_t up = 0;
        std::uint64_t down = 0;
        shekyl_link_connection(row.id, &up, &down);
        e.send_count = up;
        e.recv_count = down;
        std::uint64_t speed_up = 0;
        std::uint64_t speed_down = 0;
        shekyl_link_speed(row.id, &speed_up, &speed_down);
        e.current_speed_up = static_cast<double>(speed_up);
        e.current_speed_down = static_cast<double>(speed_down);
      }
      owned->entries.push_back(e);
    }

    for (size_t i = 0; i < owned->entries.size(); ++i)
    {
      owned->entries[i].address = owned->address[i].data();
      owned->entries[i].address_len = owned->address[i].size();
      owned->entries[i].host = owned->host[i].data();
      owned->entries[i].host_len = owned->host[i].size();
    }
    *out_now = now;
  }
  catch (const std::exception& e)
  {
    MERROR("connections facts: exception: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("connections facts: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  *out = owned->entries.empty() ? nullptr : owned->entries.data();
  *out_len = owned->entries.size();
  *out_owner = owned.release();
  return SHEKYL_RPC_FACTS_OK;
}

void shekyl_rpc_connections_free(void* owner)
{
  delete static_cast<daemon_rpc_facts::connections_owner*>(owner);
}

} // extern "C"

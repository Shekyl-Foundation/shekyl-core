// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "rpc_facts_ffi.h"

#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <string>
#include <map>
#include <mutex>
#include <vector>

#include "core_rpc_ffi_internal.h"
#include "core_rpc_server.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/block_queue.h"
#include "net/net_utils_base.h"
#include "p2p/net_node.h"
#include "p2p/seam_board.h"
#include "p2p/seam_endpoint.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_ffi.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc.facts"

namespace
{
  // Same derivation as the submit twins (daemon_submit_ffi.cpp) so both
  // languages compute identical per-field values from one seed.
  uint64_t field_value(uint64_t seed, uint64_t field)
  {
    if (seed == 0)
      return 0;
    if (seed == UINT64_MAX)
      return UINT64_MAX;
    uint64_t z = seed ^ (0x9E3779B97F4A7C15ULL * (field + 1));
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
}

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
struct sync_spans_owner
{
  std::vector<std::string> remote_address;
  std::vector<shekyl_rpc_sync_span_facts> entries;
}
;
} // namespace daemon_rpc_facts

extern "C" {

// Every export is an exception barrier: a throw from a P2P read is logged
// and becomes SHEKYL_RPC_FACTS_ERR_INTERNAL, never an unwind across the C
// ABI into Rust. What remains here is the sync half: net stats, connections,
// and sync spans. Chain and get_info reads go through the store.

int shekyl_rpc_net_stats(core_rpc_handle* h, shekyl_rpc_net_stats_facts* out)
{
  if (!h || !h->rpc || !out)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  try
  {
    std::memset(out, 0, sizeof(*out));
    out->start_time = static_cast<uint64_t>(h->rpc->get_core().get_start_time());
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
  if (!h || !h->rpc || !out_now || !out || !out_len || !out_owner)
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
    // `for_each_connection` is the node server's, and it is private there —
    // reachable only through `i_p2p_endpoint`, the interface `node_server`
    // publicly implements and the payload handler itself calls it through.
    // Upcasting to that interface is the sanctioned access, not a way around
    // one: it is the same entry point `get_connections()` uses.
    nodetool::i_p2p_endpoint<cryptonote::cryptonote_connection_context>& endpoint =
      h->rpc->get_p2p();
    // Address, direction, the handshake flag, and admission time come from
    // the board. Last receive and last send are unix time of the monotonic
    // byte stamps. Height, support flags, and the pull state are claims:
    // they take the strand hop. This thread is the operator's
    // (`spawn_blocking`, and `get_connections` / `sync_info` are
    // admin-only), so waiting on `then` is not the walk that deadlocks an
    // io worker on its own post.
    //
    // Two seconds is one missed strand hop. A dial in `idle_worker` occupies
    // a worker on this same pool, and a claim whose post has not landed is
    // unknown. That is the recorded defect until the dialer (P2P-3 slice 3)
    // leaves this pool. A row whose post has not landed leaves
    // `claims_known` at 0.
    constexpr auto kOperatorClaimWait = std::chrono::seconds(2);
    struct sync_bits
    {
      uint64_t height = 0;
      uint8_t state = 0;
    };
    auto bits = std::make_shared<std::map<boost::uuids::uuid, sync_bits>>();
    auto bits_mu = std::make_shared<std::mutex>();
    auto ready = std::make_shared<std::promise<void>>();
    endpoint.post_each(
      [bits, bits_mu](cryptonote::cryptonote_connection_context& ctx)
      {
        sync_bits row;
        row.height = ctx.m_remote_blockchain_height;
        row.state = static_cast<uint8_t>(ctx.m_state);
        std::lock_guard<std::mutex> lock(*bits_mu);
        (*bits)[ctx.m_connection_id] = row;
      },
      [ready]() {
        ready->set_value();
      });
    ready->get_future().wait_for(kOperatorClaimWait);

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
      {
        std::lock_guard<std::mutex> lock(*bits_mu);
        const auto found = bits->find(id);
        if (found != bits->end())
        {
          e.height = found->second.height;
          e.state = found->second.state;
          e.claims_known = 1;
        }
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

int shekyl_rpc_sync_spans(core_rpc_handle* h,
  const shekyl_rpc_sync_span_facts** out, size_t* out_len, void** out_owner)
{
  if (out_owner)
    *out_owner = nullptr;
  if (!h || !h->rpc || !out || !out_len || !out_owner)
    return SHEKYL_RPC_FACTS_ERR_NULL;
  *out = nullptr;
  *out_len = 0;
  std::unique_ptr<daemon_rpc_facts::sync_spans_owner> owned;
  try
  {
    owned.reset(new daemon_rpc_facts::sync_spans_owner());
    auto& payload = h->rpc->get_p2p().get_payload_object();
    const cryptonote::block_queue& queue = payload.get_block_queue();
    queue.foreach([&](const cryptonote::block_queue::span& span)
    {
      shekyl_rpc_sync_span_facts e;
      std::memset(&e, 0, sizeof(e));
      owned->remote_address.push_back(span.origin.str());
      e.start_block_height = span.start_block_height;
      e.nblocks = span.nblocks;
      e.size = span.size;
      std::memcpy(e.connection_id, span.connection_id.data, sizeof(e.connection_id));
      e.rate = span.rate;
      e.speed_fraction = queue.get_speed(span.connection_id);
      e.filled = span.blocks.empty() ? 0 : 1;
      owned->entries.push_back(e);
      return true;
    });

    for (size_t i = 0; i < owned->entries.size(); ++i)
    {
      owned->entries[i].remote_address = owned->remote_address[i].data();
      owned->entries[i].remote_address_len = owned->remote_address[i].size();
    }
  }
  catch (const std::exception& e)
  {
    MERROR("sync spans facts: exception: " << e.what());
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  catch (...)
  {
    MERROR("sync spans facts: unknown exception");
    return SHEKYL_RPC_FACTS_ERR_INTERNAL;
  }
  *out = owned->entries.empty() ? nullptr : owned->entries.data();
  *out_len = owned->entries.size();
  *out_owner = owned.release();
  return SHEKYL_RPC_FACTS_OK;
}

void shekyl_rpc_sync_spans_free(void* owner)
{
  delete static_cast<daemon_rpc_facts::sync_spans_owner*>(owner);
}

void shekyl_rpc_fee_estimate_facts_test_fill(shekyl_rpc_fee_estimate_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  // Field index 5 below is not a fee-slot index: it seeds a distinct value
  // for the count. The Rust twin (`ffi_exports.rs`) keeps the same index,
  // so both halves still fill identically.
  constexpr size_t kSlots = sizeof(out->fees) / sizeof(out->fees[0]);
  for (size_t i = 0; i < kSlots; ++i)
    out->fees[i] = field_value(seed, i);
  out->fee_count = static_cast<uint8_t>(field_value(seed, 5));
}

int shekyl_rpc_fee_estimate_facts_test_check(const shekyl_rpc_fee_estimate_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_fee_estimate_facts expected;
  shekyl_rpc_fee_estimate_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_info_chain_facts_test_fill(shekyl_rpc_info_chain_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->chain_height = field_value(seed, 0);
  for (size_t i = 0; i < sizeof(out->top_hash); ++i)
    out->top_hash[i] = static_cast<uint8_t>(field_value(seed, 1) >> ((i % 8) * 8));
  out->difficulty_lo = field_value(seed, 2);
  out->difficulty_hi = field_value(seed, 3);
  out->cumulative_difficulty_lo = field_value(seed, 4);
  out->cumulative_difficulty_hi = field_value(seed, 5);
  out->difficulty_target = field_value(seed, 6);
  out->total_transactions = field_value(seed, 7);
  out->block_weight_limit = field_value(seed, 8);
  out->block_weight_median = field_value(seed, 9);
  out->adjusted_time = field_value(seed, 10);
  out->already_generated_coins = field_value(seed, 11);
  out->total_burned = field_value(seed, 12);
  out->tx_volume_count_sum = field_value(seed, 13);
  out->tx_volume_blocks = field_value(seed, 14);
  out->core_target_height = field_value(seed, 15);
  out->synchronized = static_cast<uint8_t>(field_value(seed, 16));
  out->busy_syncing = static_cast<uint8_t>(field_value(seed, 17));
  out->offline = static_cast<uint8_t>(field_value(seed, 18));
  out->following_degraded = static_cast<uint8_t>(field_value(seed, 19));
  out->protocol_version = static_cast<uint8_t>(field_value(seed, 20));
}

int shekyl_rpc_info_chain_facts_test_check(const shekyl_rpc_info_chain_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_info_chain_facts expected;
  shekyl_rpc_info_chain_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_info_status_facts_test_fill(shekyl_rpc_info_status_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->start_time = field_value(seed, 0);
  out->free_space = field_value(seed, 1);
  out->alt_blocks_count = field_value(seed, 2);
}

int shekyl_rpc_info_status_facts_test_check(const shekyl_rpc_info_status_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_info_status_facts expected;
  shekyl_rpc_info_status_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_info_peers_facts_test_fill(shekyl_rpc_info_peers_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->public_incoming_sockets = field_value(seed, 0);
  out->public_outgoing_sockets = field_value(seed, 1);
  out->tor_incoming_sockets = field_value(seed, 2);
  out->tor_outgoing_sockets = field_value(seed, 3);
}

int shekyl_rpc_info_peers_facts_test_check(const shekyl_rpc_info_peers_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_info_peers_facts expected;
  shekyl_rpc_info_peers_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_net_stats_facts_test_fill(shekyl_rpc_net_stats_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->start_time = field_value(seed, 0);
  out->total_packets_in = field_value(seed, 1);
  out->total_bytes_in = field_value(seed, 2);
  out->total_packets_out = field_value(seed, 3);
  out->total_bytes_out = field_value(seed, 4);
}

int shekyl_rpc_net_stats_facts_test_check(const shekyl_rpc_net_stats_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_net_stats_facts expected;
  shekyl_rpc_net_stats_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_identity_facts_test_fill(shekyl_rpc_identity_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->nettype = static_cast<uint8_t>(field_value(seed, 0));
  for (size_t i = 0; i < sizeof(out->genesis_hash); ++i)
    out->genesis_hash[i] = static_cast<uint8_t>(field_value(seed, 1) >> ((i % 8) * 8));
}

int shekyl_rpc_identity_facts_test_check(const shekyl_rpc_identity_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_identity_facts expected;
  shekyl_rpc_identity_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_chain_tip_facts_test_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  out->chain_height = field_value(seed, 0);
  for (size_t i = 0; i < sizeof(out->top_hash); ++i)
    out->top_hash[i] = static_cast<uint8_t>(field_value(seed, 1) >> ((i % 8) * 8));
  out->target_height = field_value(seed, 2);
  out->synchronized = static_cast<uint8_t>(field_value(seed, 3));
  out->release_build = static_cast<uint8_t>(field_value(seed, 4));
}

int shekyl_rpc_chain_tip_facts_test_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_chain_tip_facts expected;
  shekyl_rpc_chain_tip_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_block_hash_facts_test_fill(shekyl_rpc_block_hash_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  for (size_t i = 0; i < sizeof(out->hash); ++i)
    out->hash[i] = static_cast<uint8_t>(field_value(seed, 0) >> ((i % 8) * 8));
  out->chain_height = field_value(seed, 1);
  out->found = static_cast<uint8_t>(field_value(seed, 2));
}

int shekyl_rpc_block_hash_facts_test_check(const shekyl_rpc_block_hash_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_block_hash_facts expected;
  shekyl_rpc_block_hash_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

void shekyl_rpc_block_header_facts_test_fill(shekyl_rpc_block_header_facts* out, uint64_t seed)
{
  if (!out)
    return;
  std::memset(out, 0, sizeof(*out));
  uint8_t* const hashes[] = {out->hash, out->prev_hash, out->miner_tx_hash,
    out->curve_tree_root, out->attestation_root, out->pow_hash};
  for (uint64_t f = 0; f < 6; ++f)
  {
    for (size_t i = 0; i < 32; ++i)
      hashes[f][i] = static_cast<uint8_t>(field_value(seed, f) >> ((i % 8) * 8));
  }
  out->height = field_value(seed, 6);
  out->depth = field_value(seed, 7);
  out->chain_height = field_value(seed, 8);
  out->timestamp = field_value(seed, 9);
  out->difficulty_lo = field_value(seed, 10);
  out->difficulty_hi = field_value(seed, 11);
  out->cumulative_difficulty_lo = field_value(seed, 12);
  out->cumulative_difficulty_hi = field_value(seed, 13);
  out->reward = field_value(seed, 14);
  out->block_weight = field_value(seed, 15);
  out->long_term_weight = field_value(seed, 16);
  out->num_txes = field_value(seed, 17);
  out->nonce = static_cast<uint32_t>(field_value(seed, 18));
  out->major_version = static_cast<uint8_t>(field_value(seed, 19));
  out->minor_version = static_cast<uint8_t>(field_value(seed, 20));
  out->orphan_status = static_cast<uint8_t>(field_value(seed, 21));
  out->pow_hash_filled = static_cast<uint8_t>(field_value(seed, 22));
  out->found = static_cast<uint8_t>(field_value(seed, 23));
}

int shekyl_rpc_block_header_facts_test_check(const shekyl_rpc_block_header_facts* facts, uint64_t seed)
{
  if (!facts)
    return -1;
  shekyl_rpc_block_header_facts expected;
  shekyl_rpc_block_header_facts_test_fill(&expected, seed);
  return std::memcmp(facts, &expected, sizeof(expected)) == 0 ? 0 : -1;
}

} // extern "C"

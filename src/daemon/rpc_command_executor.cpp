// Copyright (c) 2014-2022, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "string_tools.h"
#include "common/scoped_message_writer.h"
#include "daemon/rpc_command_executor.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/difficulty.h"
#include <boost/format.hpp>
#include <ctime>
#include <string>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

// Commands whose method has moved to Rust render there, on both arms
// (DAEMON_RPC_KV_CUTOVER.md §3.4): live core in-process, the RPC address
// when running as `shekyld <command>`. Output and failure are printed here
// so the console's writers stay in one place.
bool t_rpc_command_executor::run_rust_console(const std::vector<std::string>& argv)
{
  std::vector<const char*> ptrs;
  ptrs.reserve(argv.size());
  for (const auto& a : argv)
    ptrs.push_back(a.c_str());
  uint8_t* out_ptr = nullptr;
  size_t out_len = 0;
  const int32_t rc = shekyl_daemon_console_run(
    ptrs.data(), ptrs.size(),
    m_is_rpc ? nullptr : m_live,
    m_is_rpc ? m_rpc_client->address().c_str() : nullptr,
    tools::t_rpc_client::timeout_secs(),
    // This process's network, for the identity handshake on the remote arm
    // (VC-2). Ignored on the live arm, where every axis would compare a value
    // to itself.
    static_cast<uint8_t>(m_nettype),
    &out_ptr, &out_len);
  // A null/zero pair is the export's empty buffer; never hand a null pointer
  // to std::string's range constructor, even with a zero count.
  const std::string text = out_ptr ? std::string(reinterpret_cast<const char*>(out_ptr), out_len) : std::string();
  shekyl_daemon_ctl_free(out_ptr, out_len);
  if (rc == SHEKYL_DAEMON_CONSOLE_OK)
  {
    tools::success_msg_writer() << text;
    return true;
  }
  tools::fail_msg_writer() << (text.empty() ? ("console command failed (" + std::to_string(rc) + ")") : text);
  if (m_is_rpc)
    m_rpc_client->note_failure();
  return true;
}

t_rpc_command_executor::t_rpc_command_executor(
    uint32_t ip
  , uint16_t port
  , cryptonote::network_type nettype
  , bool is_rpc
  , void* live
  )
  : m_rpc_client(NULL), m_live(live)
{
  if (is_rpc)
  {
    m_rpc_client = new tools::t_rpc_client(ip, port);
  }
  else
  {
    if (live == NULL)
    {
      throw std::runtime_error("If not calling commands via RPC, live pointer must be non-null");
    }
  }

  m_is_rpc = is_rpc;
  m_nettype = nettype;
}

t_rpc_command_executor::~t_rpc_command_executor()
{
  if (m_rpc_client != NULL)
  {
    delete m_rpc_client;
  }
}

bool t_rpc_command_executor::print_peer_list(bool white, bool gray, size_t limit) {
  // No `pruned` selector: per-peer pruning state left with the stripe engine
  // (PDM-Q7), so the Rust console has nothing to filter on.
  return run_rust_console({"print_peer_list", white && gray ? "both" : (white ? "white" : "gray"),
    std::to_string(limit)});
}

bool t_rpc_command_executor::print_peer_list_stats() {
  return run_rust_console({"print_peer_list_stats"});
}

bool t_rpc_command_executor::show_difficulty() {
  // Rendered in Rust since `get_info` moved there (RK-5c).
  return run_rust_console({"diff"});
}


bool t_rpc_command_executor::show_status() {
  // The whole line renders in Rust. `/get_info` (RK-5c) and
  // `/mining_status` (RK-7) are still bridged,
  // and the "mining info unavailable" arm still belongs to the remote case
  // only — in-process a `/mining_status` that will not answer is this
  // daemon's own fault.
  return run_rust_console({"status"});
}

bool t_rpc_command_executor::print_connections() {
  return run_rust_console({"print_connections"});
}

bool t_rpc_command_executor::print_net_stats()
{
  return run_rust_console({"print_net_stats"});
}

bool t_rpc_command_executor::print_blockchain_info(int64_t start_block_index, uint64_t end_block_index) {
  // RK-5b: `get_block_headers_range` is served from Rust and renders there.
  // The parser has already resolved the negative form to (-n, n); resolving
  // it against the tip is a `get_info` read, native since RK-5c, so the
  // Rust side reads the tip beside the rest of the command.
  return run_rust_console({"print_blockchain_info",
    std::to_string(start_block_index), std::to_string(end_block_index)});
}

bool t_rpc_command_executor::print_height() {
  return run_rust_console({"print_height"});
}

bool t_rpc_command_executor::print_block_by_hash(crypto::hash block_hash, bool include_hex) {
  std::vector<std::string> argv{"print_block_by_hash", epee::string_tools::pod_to_hex(block_hash)};
  if (include_hex)
    argv.emplace_back("+hex");
  return run_rust_console(argv);
}

bool t_rpc_command_executor::print_block_by_height(uint64_t height, bool include_hex) {
  std::vector<std::string> argv{"print_block_by_height", std::to_string(height)};
  if (include_hex)
    argv.emplace_back("+hex");
  return run_rust_console(argv);
}

bool t_rpc_command_executor::print_transaction(crypto::hash transaction_hash,
  bool include_metadata,
  bool include_hex,
  bool include_json)
{
  // RK-4c: renders in Rust on both arms, as print_block does. The flags go
  // over as the console spells them, so one syntax is parsed in one place.
  std::vector<std::string> argv{"print_transaction",
    epee::string_tools::pod_to_hex(transaction_hash)};
  if (include_metadata) argv.push_back("+meta");
  if (include_hex) argv.push_back("+hex");
  if (include_json) argv.push_back("+json");
  return run_rust_console(argv);
}

bool t_rpc_command_executor::is_key_image_spent(const crypto::key_image &ki) {
  // RK-4c: renders in Rust on both arms.
  return run_rust_console({"is_key_image_spent", epee::string_tools::pod_to_hex(ki)});
}

bool t_rpc_command_executor::print_transaction_pool_stats() {
  return run_rust_console({"print_pool_stats"});
}

bool t_rpc_command_executor::stop_daemon()
{
  // One stop path. The console word asks; it does not stop the process
  // itself (DAEMON_CONFIG_CUTOVER.md §2.2). The remote arm posts the
  // Rust route. Neither arm builds a request struct.
  if (m_is_rpc)
  {
    std::string reason;
    if (!m_rpc_client->post_route("/stop_daemon", "{}", reason))
    {
      tools::fail_msg_writer() << "Daemon did not stop -- " << reason;
      return true;
    }
  }
  else
  {
    shekyl_daemon_request_stop();
  }
  tools::success_msg_writer() << "Stop signal sent";
  return true;
}

bool t_rpc_command_executor::print_status()
{
  if (!m_is_rpc)
  {
    tools::success_msg_writer() << "print_status makes no sense in interactive mode";
    return true;
  }

  bool daemon_is_alive = m_rpc_client->check_connection();

  if(daemon_is_alive) {
    tools::success_msg_writer() << "shekyld is running";
  }
  else {
    tools::fail_msg_writer() << "shekyld is NOT running";
  }

  return true;
}

bool t_rpc_command_executor::alt_chain_info(const std::string &tip, size_t above, uint64_t last_blocks)
{
  // RK-5b: `get_block_header_by_hash` is served from Rust and the whole
  // command renders there. `get_info` is native (RK-5c); only
  // `get_alternate_chains` is still bridged (RK-8). The length check on the
  // header batch is now a per-hash correspondence check, which is what the
  // per-element reply makes possible.
  return run_rust_console({"alt_chain_info", tip,
    std::to_string(above), std::to_string(last_blocks)});
}

bool t_rpc_command_executor::print_blockchain_dynamic_stats(uint64_t nblocks)
{
  // RK-5b: `get_fee_estimate` and `get_block_headers_range` are served from
  // Rust, and the whole command renders there.
  return run_rust_console({"print_blockchain_dynamic_stats", std::to_string(nblocks)});
}

bool t_rpc_command_executor::sync_info()
{
  return run_rust_console({"sync_info"});
}

bool t_rpc_command_executor::pop_blocks(uint64_t num_blocks)
{
  // The armed gate is in Rust, for both arms. The live arm admits under the
  // daemon's switch before the C++ handler runs; the remote arm posts and
  // that daemon's stamp admits. This stays a shim (rule 20).
  return run_rust_console({"pop_blocks", std::to_string(num_blocks)});
}

bool t_rpc_command_executor::version()
{
    // Rendered in Rust since `get_info` moved there (RK-5c). On the remote
    // arm it asks without the identity handshake: its job is to show the
    // operator what they reached (CLIENT_VERSION_CONSTANTS_VALIDATION.md
    // §3.6.2).
    return run_rust_console({"version"});
}

}// namespace daemonize

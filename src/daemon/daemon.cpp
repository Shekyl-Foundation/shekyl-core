// Copyright (c) 2018-2026, The Shekyl Foundation
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

#include "daemon/daemon.h"

#include <atomic>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <vector>

#include <boost/algorithm/string/split.hpp>

#include "common/password.h"
#include "common/util.h"
#include "cryptonote_basic/events.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "daemon/command_server.h"
#include "misc_log_ex.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_ffi.h"
#include "rpc/rpc_subject.h"
#include "shekyl/shekyl_ffi.h"
#include "version.h"

using namespace epee;

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

namespace {
  using t_protocol_raw = cryptonote::t_cryptonote_protocol_handler<cryptonote::core>;
  using t_node_server = nodetool::node_server<t_protocol_raw>;

}

// Lifetime order:
//   core        — constructed first, destructed last (LMDB env, etc.)
//   protocol    — holds a reference to core
//   p2p         — holds a reference to protocol
//   rpcs        — hold references to core and p2p
//
// This matches the original t_core/t_protocol/t_p2p/t_rpc destruction order
// from the deleted wrapper layer: rpcs go first, then p2p, then protocol,
// then core. The fields are declared in construction order below; destructors
// run in reverse declaration order, which gives the correct teardown.
struct t_internals {
  // Cryptonote core.
  cryptonote::core core;

  // Protocol handler bound to core.
  t_protocol_raw protocol;

  // P2P server bound to protocol.
  t_node_server p2p;

  // The two objects the Rust RPC's sync-half facts read. The listeners
  // are Rust's.
  rpc_subject subject;

  explicit t_internals(const ShekylDaemonSnapshot& snapshot)
    : core(nullptr)
    , protocol{core, nullptr, snapshot.offline}
    , p2p{protocol}
    , subject{nullptr, nullptr}
  {
    // === core ===
    MGINFO("Initializing core...");
    if (!core.init(snapshot))
    {
      throw std::runtime_error("Failed to initialize core");
    }
    MGINFO("Core initialized OK");

    // === protocol ===
    MGINFO("Initializing cryptonote protocol...");
    if (!protocol.init())
    {
      throw std::runtime_error("Failed to initialize cryptonote protocol.");
    }
    MGINFO("Cryptonote protocol initialized OK");

    // === p2p ===
    MGINFO("Initializing p2p server...");
    if (!p2p.init(snapshot))
    {
      throw std::runtime_error("Failed to initialize p2p server.");
    }
    MGINFO("p2p server initialized OK");

    // Wire core ↔ protocol ↔ p2p now that all three are constructed.
    protocol.set_p2p_endpoint(&p2p);
    core.set_cryptonote_protocol(&protocol);

    // The one RPC handle. Rust binds and serves the RPC section at the
    // remnant's one start call in run() (DAEMON_CONFIG_CUTOVER.md §2.3).
    // These two pointers are what the sync-half facts read.
    subject.core = &core;
    subject.p2p = &p2p;
  }

  ~t_internals()
  {
    // The Rust RPC is already stopped (shekyl_daemon_rpc_stop() in
    // Daemon::run()). No explicit RPC deinit step remains.

    MGINFO("Deinitializing p2p...");
    try { p2p.deinit(); }
    catch (...) { MERROR("Failed to deinitialize p2p..."); }

    MGINFO("Stopping cryptonote protocol...");
    try {
      protocol.deinit();
      protocol.set_p2p_endpoint(nullptr);
      MGINFO("Cryptonote protocol stopped successfully");
    }
    catch (...) { LOG_ERROR("Failed to stop cryptonote protocol!"); }

    MGINFO("Deinitializing core...");
    try {
      core.deinit();
      core.set_cryptonote_protocol(nullptr);
    }
    catch (...) { MERROR("Failed to deinitialize core..."); }
  }
};

namespace {
/// A stop was requested. Set once, before or while run() serves.
std::atomic<bool> g_stop_requested{false};
/// The daemon whose run() is serving, while it serves. The mutex, not an
/// atomic pointer alone, keeps request_stop() from signalling a daemon
/// that run() has already returned from and the caller is destroying.
std::mutex g_running_mutex;
Daemon* g_running = nullptr;
} // namespace

Daemon::Daemon(const ShekylDaemonSnapshot& snapshot)
  : mp_internals(new t_internals{snapshot})
{
}

Daemon::~Daemon() = default;
Daemon::Daemon(Daemon &&) = default;
Daemon & Daemon::operator=(Daemon &&) = default;

bool Daemon::run(bool interactive)
{
  if (nullptr == mp_internals)
  {
    throw std::runtime_error{"Can't run stopped daemon"};
  }

  // The stop is requested by the Rust signal owner through
  // `daemonize::request_stop` (DAEMON_CONFIG_CUTOVER.md §2.2 step 9): one
  // process has one signal owner. It signals this daemon directly once
  // run() has registered it; a stop that arrived before the registration
  // is seen here. No thread polls, so no wait here is timed on the wall
  // clock: the poll this replaces slept until wall time plus 100 ms, and a
  // clock set back a day made that sleep, and the join at exit, a day long.
  {
    std::lock_guard<std::mutex> lock(g_running_mutex);
    g_running = this;
    if (g_stop_requested.load())
      stop_p2p();
  }
  // Cleared before run() returns, so before ~t_internals: a stop that
  // arrives after this point signals nothing.
  epee::misc_utils::auto_scope_leave_caller unregister = epee::misc_utils::create_scope_leave_handler([](){
    std::lock_guard<std::mutex> lock(g_running_mutex);
    g_running = nullptr;
  });
  // Every exit from run() — the normal return, a caught exception, a throw
  // that escapes — stops the Rust RPC tasks before ~t_internals destroys the
  // core they hold pointers into. The normal path stops them explicitly
  // below so "Node stopped" follows the stop; this is the backstop for
  // every other path (a later listener refusing to start, the command
  // server or p2p.run() throwing).
  epee::misc_utils::auto_scope_leave_caller stop_rust_rpc = epee::misc_utils::create_scope_leave_handler([](){
    shekyl_daemon_rpc_stop();
  });

  try
  {
    // The one RPC start (DAEMON_CONFIG_CUTOVER.md §2.3): Rust reads its
    // section, binds every admin and view listener, loopback only, and
    // serves them; the refusal is logged there. Its completion is what the
    // Rust main() waits for before it starts what serves peers (§2.2 step
    // 8), so it is the last act of construction here.
    if (shekyl_daemon_rpc_start(static_cast<void*>(&mp_internals->subject)) != 0)
    {
      throw std::runtime_error("Failed to start the RPC; the reason is logged just above");
    }
    MGINFO("RPC started; each bound socket is logged by the Rust listener");

    std::unique_ptr<daemonize::t_command_server> rpc_commands;
    if (interactive)
    {
      // The first two ctor args are unused when the third is false.
      // The interactive console renders from the live core in this process,
      // so its identity handshake is skipped entirely (every axis would
      // compare a value to itself). The nettype is passed for signature
      // uniformity and read by nothing on this arm.
      rpc_commands.reset(new daemonize::t_command_server(
        0, 0,
        mp_internals->core.get_nettype(),
        false,
        &mp_internals->subject));
      // The console's `exit` asks the one stop owner (§2.2 step 9); the
      // remnant never stops itself.
      rpc_commands->start_handling([](){ shekyl_daemon_request_stop(); });
    }

    // RPC listeners are open now, and each server has a connection budget
    // that is not yet open. Re-derive so both are inside the ceiling.
    // `init` already derived once, before these sockets existed.

    // Every daemon runtime is on the ledger by here: the transport pool
    // is built at bind, Tor control at its start, and the RPC pools just
    // above. The D5 pin of those counts is still ahead of any measurement.
    // The report returns its full length. One retry covers a row that
    // appeared between the probe and the fill. A second short fill is
    // not printed.
    {
      const std::size_t needed = shekyl_thread_ledger_report(nullptr, 0);
      std::string budget(needed + 1, '\0');
      std::size_t full = shekyl_thread_ledger_report(budget.data(), budget.size());
      if (full >= budget.size())
      {
        budget.assign(full + 1, '\0');
        full = shekyl_thread_ledger_report(budget.data(), budget.size());
      }
      if (full < budget.size())
      {
        budget.resize(full);
        MGINFO(budget);
      }
    }

    MGINFO("Starting p2p net loop...");
    mp_internals->p2p.run(); // blocks until p2p goes down
    MGINFO("p2p net loop stopped");

    if (rpc_commands)
      rpc_commands->stop_handling();

    shekyl_daemon_rpc_stop();
    MGINFO("Node stopped.");
    return true;
  }
  catch (std::exception const & ex)
  {
    MFATAL("Uncaught exception! " << ex.what());
    return false;
  }
  catch (...)
  {
    MFATAL("Uncaught exception!");
    return false;
  }
}

void request_stop()
{
  std::lock_guard<std::mutex> lock(g_running_mutex);
  g_stop_requested.store(true);
  if (g_running != nullptr)
    g_running->stop_p2p();
}

void Daemon::stop_p2p()
{
  if (nullptr == mp_internals)
  {
    throw std::runtime_error{"Can't send stop signal to a stopped daemon"};
  }
  mp_internals->p2p.send_stop_signal();
}

} // namespace daemonize

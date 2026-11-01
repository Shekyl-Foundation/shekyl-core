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
#include <stdexcept>
#include <vector>

#include <boost/algorithm/string/split.hpp>
#include <boost/thread/thread.hpp>

#include "common/password.h"
#include "common/scoped_message_writer.h"
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
#include "cryptonote_config.h"
#include <boost/filesystem/operations.hpp>

#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>

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
    , protocol{core, nullptr}
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
  // process has one signal owner, and this loop only polls the flag.
  std::atomic<bool> stop(false);
  boost::thread stop_thread = boost::thread([&stop, this] {
    while (!stop && !g_stop_requested.load())
      epee::misc_utils::sleep_no_w(100);
    if (g_stop_requested.load())
      this->stop_p2p();
  });
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    stop = true;
    stop_thread.join();
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

std::atomic<bool> g_stop_requested{false};

void request_stop()
{
  g_stop_requested.store(true);
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

// The remnant's entry pair (DAEMON_CONFIG_CUTOVER.md §2.2, DC-Q19). Rust
// owns the process: `shekyld`'s Rust `main` reads the configuration, takes
// the lock, checks the marker, starts logging, makes the announcements and
// owns every signal; `shekyl_remnant_run` receives the snapshot of the
// values whose reader is still C++ and parses nothing.

namespace bf = boost::filesystem;

namespace {

#ifdef WIN32
bool isFat32(const wchar_t* root_path)
{
  std::vector<wchar_t> fs(MAX_PATH + 1);
  if (!::GetVolumeInformationW(root_path, nullptr, 0, nullptr, 0, nullptr, &fs[0], fs.size()))
  {
    MERROR("Failed to get '" << root_path << "' filesystem name. Error code: " << ::GetLastError());
    return false;
  }
  return wcscmp(L"FAT32", &fs[0]) == 0;
}
#endif

} // namespace

// The remnant's `run`: `noexcept`, every C++ exception caught and turned
// into a status. Takes what C++ still reads from the snapshot, runs the
// client command or the daemon, and returns. Imported by name by the Rust
// binary (`rust/shekyld/src/main.rs`, DC-Q19).
extern "C" int shekyl_remnant_run(const ShekylDaemonSnapshot* snapshot) noexcept
{
  try {
    if (snapshot == nullptr)
      return 1;
    if (shekyl_daemon_snapshot_field_count() != SHEKYL_DAEMON_SNAPSHOT_FIELDS)
    {
      std::cerr << "shekyld: the C++ reads a snapshot of " << SHEKYL_DAEMON_SNAPSHOT_FIELDS
                << " fields and Rust filled " << shekyl_daemon_snapshot_field_count()
                << "; the two sides were built from different definitions" << std::endl;
      return 1;
    }

    tools::on_startup();

    const bool testnet = snapshot->network == 1;
    const bool stagenet = snapshot->network == 2;
    const bool regtest = snapshot->network == 3;

    // Client mode: a command for a running daemon, at the admin endpoint
    // Rust resolved. No lock, no marker, no log file. The endpoint is four
    // octets and a port; this does not parse a string.
    if (snapshot->command.len > 0)
    {
      if (!snapshot->client_endpoint.present)
        return 1;
      std::vector<std::string> command;
      command.reserve(snapshot->command.len);
      for (size_t i = 0; i < snapshot->command.len; ++i)
        command.emplace_back(snapshot->command.items[i]);
      // Network order, the bit pattern inet_addr returns.
      uint32_t rpc_ip;
      std::memcpy(&rpc_ip, snapshot->client_endpoint.octets,
                  sizeof snapshot->client_endpoint.octets);
      uint16_t rpc_port = snapshot->client_endpoint.port;
      const cryptonote::network_type console_nettype =
        testnet ? cryptonote::TESTNET
        : stagenet ? cryptonote::STAGENET
        : regtest ? cryptonote::FAKECHAIN
        : cryptonote::MAINNET;
      daemonize::t_command_server rpc_commands{rpc_ip, rpc_port, console_nettype};
      if (rpc_commands.process_command_vec(command))
        return rpc_commands.rpc_request_failed() ? 1 : 0;
      PAUSE_READLINE();
      std::cerr << "Unknown command: " << command.front() << std::endl;
      return 1;
    }

    const bf::path data_dir(snapshot->data_dir);
#ifdef WIN32
    if (isFat32(data_dir.root_path().c_str()))
      MERROR("Data directory resides on FAT32 volume that has 4GiB file size limit, blockchain might get corrupted.");
#endif
    tools::create_directories_if_necessary(data_dir.string());

    // The tracing forwarder: C++ log calls reach the subscriber Rust
    // installed. Logging itself is Rust's (§2.2 step 5).
    {
      const int32_t fwd_rc = shekyl_log_install_tracing_forwarder();
      if (fwd_rc != SHEKYL_LOG_OK && fwd_rc != SHEKYL_LOG_ERR_ALREADY_INSTALLED)
        std::cerr << "Warning: tracing forwarder install failed (code " << fwd_rc
                  << "); C++ log events will be dropped" << std::endl;
    }

    MGINFO("Shekyl '" << SHEKYL_RELEASE_NAME << "' (v" << SHEKYL_VERSION_FULL << ")");

    MINFO("Constructing daemon.");
    daemonize::Daemon daemon{*snapshot};
    return daemon.run(snapshot->console) ? 0 : 1;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Exception in the daemon's run! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Exception in the daemon's run!");
  }
  return 1;
}

// The remnant's `stop`: requests the stop `run` is waiting for and returns
// at once. `noexcept`.
extern "C" void shekyl_remnant_stop() noexcept
{
  daemonize::request_stop();
}

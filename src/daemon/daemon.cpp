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
#include <memory>
#include <stdexcept>
#include <vector>

#include <boost/algorithm/string/split.hpp>
#include <boost/thread/thread.hpp>

#include "blocks/blocks.h"
#include "common/password.h"
#include "common/util.h"
#include "cryptonote_basic/events.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "daemon/command_line_args.h"
#include "daemon/command_server.h"
#include "misc_log_ex.h"
#include "net/net_ssl.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_ffi.h"
#include "rpc/core_rpc_server.h"
#include "shekyl/shekyl_ffi.h"
#include "version.h"

using namespace epee;

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

namespace {
  using t_protocol_raw = cryptonote::t_cryptonote_protocol_handler<cryptonote::core>;
  using t_node_server = nodetool::node_server<t_protocol_raw>;

  // Named RPC server instance (main RPC, or the optional restricted RPC).
  struct rpc_instance final {
    std::unique_ptr<cryptonote::core_rpc_server> server;
    std::string description;

    rpc_instance(cryptonote::core & core, t_node_server & p2p, std::string desc)
      : server(new cryptonote::core_rpc_server{core, p2p})
      , description(std::move(desc))
    {}
  };
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

  // One or more RPC servers (main, optionally a separate restricted one).
  std::vector<rpc_instance> rpcs;

  // Rust/Axum RPC handles, populated lazily by run().
  bool rust_rpc_enabled;
  std::vector<ShekylDaemonRpcHandle*> rust_rpc_handles;

  explicit t_internals(boost::program_options::variables_map const & vm)
    : core(nullptr)
    , protocol{core, nullptr, command_line::get_arg(vm, cryptonote::arg_offline)}
    , p2p{protocol}
    , rust_rpc_enabled{!command_line::get_arg(vm, daemon_args::arg_no_rust_rpc)}
  {
    // === core ===
    MGINFO("Initializing core...");
    if (command_line::is_arg_defaulted(vm, daemon_args::arg_proxy)
        && command_line::get_arg(vm, daemon_args::arg_proxy_allow_dns_leaks))
    {
      MLOG_RED(el::Level::Warning, "--" << daemon_args::arg_proxy_allow_dns_leaks.name
        << " is enabled, but --" << daemon_args::arg_proxy.name << " is not specified.");
    }
#if defined(PER_BLOCK_CHECKPOINT)
    cryptonote::GetCheckpointsCallback const & get_checkpoints = blocks::GetCheckpointsData;
#else
    cryptonote::GetCheckpointsCallback const & get_checkpoints = nullptr;
#endif
    const bool allow_dns = command_line::is_arg_defaulted(vm, daemon_args::arg_proxy)
      || command_line::get_arg(vm, daemon_args::arg_proxy_allow_dns_leaks);
    if (!core.init(vm, nullptr, get_checkpoints, allow_dns))
    {
      throw std::runtime_error("Failed to initialize core");
    }
    MGINFO("Core initialized OK");

    // === protocol ===
    MGINFO("Initializing cryptonote protocol...");
    if (!protocol.init(vm))
    {
      throw std::runtime_error("Failed to initialize cryptonote protocol.");
    }
    MGINFO("Cryptonote protocol initialized OK");

    // === p2p ===
    MGINFO("Initializing p2p server...");
    if (!p2p.init(vm,
        command_line::get_arg(vm, daemon_args::arg_proxy),
        command_line::get_arg(vm, daemon_args::arg_proxy_allow_dns_leaks)))
    {
      throw std::runtime_error("Failed to initialize p2p server.");
    }
    MGINFO("p2p server initialized OK");

    // Wire core ↔ protocol ↔ p2p now that all three are constructed.
    protocol.set_p2p_endpoint(&p2p);
    core.set_cryptonote_protocol(&protocol);

    // === rpc(s) ===
    const bool restricted = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc);
    auto const main_rpc_port = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
    auto const & restricted_rpc_port_arg = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
    const bool has_restricted_rpc_port_arg = !command_line::is_arg_defaulted(vm, restricted_rpc_port_arg);

    {
      rpcs.emplace_back(core, p2p, "core");
      auto const & proxy = command_line::get_arg(vm, daemon_args::arg_proxy);
      MGINFO("Initializing " << rpcs.back().description << " RPC server...");
      if (!rpcs.back().server->init(vm, restricted, main_rpc_port, !has_restricted_rpc_port_arg, proxy))
      {
        throw std::runtime_error("Failed to initialize " + rpcs.back().description + " RPC server.");
      }
      MGINFO(rpcs.back().description << " RPC server initialized OK on port: "
        << rpcs.back().server->get_binded_port());
    }

    if (has_restricted_rpc_port_arg)
    {
      auto const restricted_rpc_port = command_line::get_arg(vm, restricted_rpc_port_arg);
      auto const & proxy = command_line::get_arg(vm, daemon_args::arg_proxy);
      rpcs.emplace_back(core, p2p, "restricted");
      MGINFO("Initializing " << rpcs.back().description << " RPC server...");
      if (!rpcs.back().server->init(vm, true, restricted_rpc_port, true, proxy))
      {
        throw std::runtime_error("Failed to initialize " + rpcs.back().description + " RPC server.");
      }
      MGINFO(rpcs.back().description << " RPC server initialized OK on port: "
        << rpcs.back().server->get_binded_port());
    }
  }

  ~t_internals()
  {
    // rpcs: deinit via their own dtors below; explicit deinit for symmetry with
    // the old t_rpc::~t_rpc().
    for (auto & rpc : rpcs)
    {
      MGINFO("Deinitializing " << rpc.description << " RPC server...");
      try { rpc.server->deinit(); }
      catch (...) { MERROR("Failed to deinitialize " << rpc.description << " RPC server..."); }
    }

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

void Daemon::init_options(boost::program_options::options_description & option_spec)
{
  cryptonote::core::init_options(option_spec);
  t_node_server::init_options(option_spec);
  cryptonote::core_rpc_server::init_options(option_spec);
}

Daemon::Daemon(
    DaemonConfig const & config,
    boost::program_options::variables_map const & vm
  )
  : mp_internals(new t_internals{vm})
  , public_rpc_port(config.public_rpc_port)
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

  std::atomic<bool> stop(false), shutdown(false);
  boost::thread stop_thread = boost::thread([&stop, &shutdown, this] {
    while (!stop)
      epee::misc_utils::sleep_no_w(100);
    if (shutdown)
      this->stop_p2p();
  });
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    stop = true;
    stop_thread.join();
  });
  tools::signal_handler::install([&stop, &shutdown](int){ stop = shutdown = true; });

  try
  {
    if (mp_internals->rust_rpc_enabled)
    {
      for (auto & rpc : mp_internals->rpcs)
      {
        auto * server = rpc.server.get();
        std::string bind_addr = "127.0.0.1:" + std::to_string(server->get_binded_port());
        auto * rust_handle = shekyl_daemon_rpc_start(
          static_cast<void*>(server), bind_addr.c_str(), false);
        if (rust_handle)
        {
          MGINFO("Axum RPC listening on " << bind_addr << " (epee HTTP skipped)");
          mp_internals->rust_rpc_handles.push_back(rust_handle);
        }
        else
        {
          MERROR("Failed to start Axum RPC on " << bind_addr << ", falling back to epee");
          MGINFO("Starting " << rpc.description << " RPC server...");
          if (!rpc.server->run(2, false))
          {
            throw std::runtime_error("Failed to start " + rpc.description + " RPC server.");
          }
          MGINFO(rpc.description << " RPC server started ok");
        }
      }
    }
    else
    {
      for (auto & rpc : mp_internals->rpcs)
      {
        MGINFO("Starting " << rpc.description << " RPC server...");
        if (!rpc.server->run(2, false))
        {
          throw std::runtime_error("Failed to start " + rpc.description + " RPC server.");
        }
        MGINFO(rpc.description << " RPC server started ok");
      }
    }

    std::unique_ptr<daemonize::t_command_server> rpc_commands;
    if (interactive && !mp_internals->rpcs.empty())
    {
      // The first three ctor args are unused when the fourth is false.
      rpc_commands.reset(new daemonize::t_command_server(
        0, 0, std::nullopt,
        epee::net_utils::ssl_support_t::e_ssl_support_disabled,
        false,
        mp_internals->rpcs.front().server.get()));
      rpc_commands->start_handling(std::bind(&Daemon::stop_p2p, this));
    }

    if (public_rpc_port > 0)
    {
      MGINFO("Public RPC port " << public_rpc_port << " will be advertised to other peers over P2P");
      mp_internals->p2p.set_rpc_port(public_rpc_port);
    }

    MGINFO("Starting p2p net loop...");
    mp_internals->p2p.run(); // blocks until p2p goes down
    MGINFO("p2p net loop stopped");

    if (rpc_commands)
      rpc_commands->stop_handling();

    for (auto * rust_handle : mp_internals->rust_rpc_handles)
      shekyl_daemon_rpc_stop(rust_handle);
    mp_internals->rust_rpc_handles.clear();

    for (auto & rpc : mp_internals->rpcs)
    {
      MGINFO("Stopping " << rpc.description << " RPC server...");
      rpc.server->send_stop_signal();
      rpc.server->timed_wait_server_stop(5000);
    }
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

void Daemon::stop()
{
  if (nullptr == mp_internals)
  {
    throw std::runtime_error{"Can't stop stopped daemon"};
  }
  for (auto * rust_handle : mp_internals->rust_rpc_handles)
    shekyl_daemon_rpc_stop(rust_handle);
  mp_internals->rust_rpc_handles.clear();

  mp_internals->p2p.send_stop_signal();
  for (auto & rpc : mp_internals->rpcs)
  {
    rpc.server->send_stop_signal();
    rpc.server->timed_wait_server_stop(5000);
  }

  mp_internals.reset(nullptr);
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

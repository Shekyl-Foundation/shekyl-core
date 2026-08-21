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

// TODO(v3.2): delete this file alongside its header. See removed_flags.h
// for the rationale and lifecycle.

#include "common/removed_flags.h"

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

namespace shekyl { namespace cli {

namespace {

// Why a flag was removed — selects the migration message shown to the
// operator. Carrying the reason in the table (rather than a second list)
// preserves the single-source-of-truth property the docs rely on.
enum class removed_reason
{
  daemonizer,        // background execution / Windows service management (V3.1)
  rpc_tls_auth,      // shekyld inbound TLS/auth surface, moved off the daemon
  rust_rpc,          // transitional epee HTTP fallback and its opt-out flag
  bootstrap_daemon,  // silent third-party forward of wallet queries
  public_node,       // P2P advertisement as a foreign remote-RPC endpoint
};

struct removed_flag
{
  std::string_view name;
  removed_reason reason;
};

// Flags removed across the V3.1 daemon surface. This table is the single
// source of truth — CHANGELOG.md and FOLLOWUPS.md reference it by name
// rather than duplicating the list, so editing this array keeps the
// documentation in sync automatically.
constexpr std::array<removed_flag, 20> REMOVED_FLAGS = {{
  // Daemonizer, deleted in V3.1 (background execution / service management).
  {"detach",                       removed_reason::daemonizer},
  {"pidfile",                      removed_reason::daemonizer},
  {"install-service",              removed_reason::daemonizer},
  {"uninstall-service",            removed_reason::daemonizer},
  {"start-service",                removed_reason::daemonizer},
  {"stop-service",                 removed_reason::daemonizer},
  {"run-as-service",               removed_reason::daemonizer},
  // shekyld inbound TLS/auth surface: the daemon RPC listener is now
  // plaintext loopback; remote/authenticated access moves to an onion
  // service or reverse proxy. Wallet-RPC keeps its own copies of these
  // flags (registered there, so they never reach this shim).
  {"rpc-login",                    removed_reason::rpc_tls_auth},
  {"rpc-ssl",                      removed_reason::rpc_tls_auth},
  {"rpc-ssl-private-key",          removed_reason::rpc_tls_auth},
  {"rpc-ssl-certificate",          removed_reason::rpc_tls_auth},
  {"rpc-ssl-ca-certificates",      removed_reason::rpc_tls_auth},
  {"rpc-ssl-allowed-fingerprints", removed_reason::rpc_tls_auth},
  {"rpc-ssl-allow-chained",        removed_reason::rpc_tls_auth},
  {"rpc-ssl-allow-any-cert",       removed_reason::rpc_tls_auth},
  // Transitional epee HTTP fallback opt-out: the Rust (Axum) listener is
  // now the only RPC server.
  {"no-rust-rpc",                  removed_reason::rust_rpc},
  // Daemon-side silent forward of wallet queries to a third-party node.
  // RPC is operator-to-operator; a remote is the wallet's explicit choice.
  {"bootstrap-daemon-address",     removed_reason::bootstrap_daemon},
  {"bootstrap-daemon-login",       removed_reason::bootstrap_daemon},
  {"bootstrap-daemon-proxy",       removed_reason::bootstrap_daemon},
  // P2P advertisement of an RPC port for strangers' wallets. Restricted
  // RPC (a second listener for the operator's own wallet) remains.
  {"public-node",                  removed_reason::public_node},
}};

// boost::program_options::unknown_option::get_option_name() returns the
// offending flag without a leading "--" (it's stripped during parsing).
// Normalize defensively in case a future Boost version changes that.
std::string_view strip_leading_dashes(std::string_view s)
{
  while (!s.empty() && s.front() == '-') s.remove_prefix(1);
  return s;
}

removed_flag const * find_removed(std::string_view flag)
{
  for (removed_flag const & rf : REMOVED_FLAGS)
  {
    if (flag == rf.name) return &rf;
  }
  return nullptr;
}

} // namespace

bool handle_removed_flag(
    boost::program_options::unknown_option const & ex,
    char const * binary_name)
{
  // get_option_name() returns std::string by value; hold it in a named
  // variable so the string_view below doesn't dangle into a dead temporary.
  // Also strip any trailing "=value" suffix — Boost's unknown_option keeps
  // the full token verbatim when the parser can't dispatch to a descriptor.
  std::string const raw = ex.get_option_name();
  std::string_view view = strip_leading_dashes(raw);
  auto const eq = view.find('=');
  if (eq != std::string_view::npos) view = view.substr(0, eq);

  removed_flag const * const rf = find_removed(view);
  if (rf == nullptr) return false;

  switch (rf->reason)
  {
    case removed_reason::daemonizer:
      std::cerr <<
        "Error: '--" << view << "' was removed in V3.1. Background execution is now\n"
        "handled by systemd (Linux), launchd (macOS), Task Scheduler (Windows), or\n"
        "the Tauri sidecar (GUI wallet). Windows service management (install /\n"
        "uninstall / start / stop) is likewise delegated to the platform service\n"
        "manager. See docs/INSTALLATION_GUIDE.md for process-manager examples.\n";
      break;
    case removed_reason::rpc_tls_auth:
      std::cerr <<
        "Error: '--" << view << "' was removed in V3.1. The shekyld RPC listener is\n"
        "plaintext loopback with no built-in TLS or digest auth. For remote or\n"
        "authenticated access, front the daemon with an onion service or a reverse\n"
        "proxy outside the daemon (see docs/DAEMON_RPC_RUST.md and docs/USER_GUIDE.md).\n"
        "The wallet RPC server keeps its own --rpc-login / --rpc-ssl* flags.\n";
      break;
    case removed_reason::rust_rpc:
      std::cerr <<
        "Error: '--" << view << "' was removed in V3.1. The Rust (Axum) RPC listener\n"
        "is now the only RPC server; the transitional epee HTTP fallback was deleted,\n"
        "so this flag no longer has any effect (see docs/DAEMON_RPC_RUST.md).\n";
      break;
    case removed_reason::bootstrap_daemon:
      std::cerr <<
        "Error: '--" << view << "' was removed. shekyld no longer forwards wallet\n"
        "queries to a third-party node while the local chain is catching up.\n"
        "Point the wallet at a daemon you operate (this node, or another of yours\n"
        "via --daemon-address / onion) while IBD runs. See docs/DAEMON_RPC_RUST.md.\n";
      break;
    case removed_reason::public_node:
      std::cerr <<
        "Error: '--public-node' was removed. shekyld does not advertise an RPC\n"
        "port over P2P for other people's wallets. RPC is operator-to-operator:\n"
        "both ends are machines you control. Restricted RPC (--restricted-rpc,\n"
        "--rpc-restricted-bind-port) remains, for your own wallet on a less-\n"
        "privileged port. See docs/DAEMON_RPC_RUST.md.\n";
      break;
  }
  std::cerr << binary_name << " exiting.\n";
  return true;
}

}} // namespace shekyl::cli

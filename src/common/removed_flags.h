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

// TODO(v3.2): delete this file and its .cpp. Coordinated with the
// wallet_rpc_server Rust cutover (see docs/FOLLOWUPS.md §"removed_flags
// shim"). The shim exists only to give users a friendly migration message
// for --detach, --pidfile, and the Windows --*-service flags removed in
// V3.1 when the daemonizer was deleted. Call sites are the two main()
// functions in src/daemon/main.cpp and src/wallet/wallet_rpc_server.cpp;
// both disappear at V3.2 (shekyld keeps its caller, shekyl-wallet-rpc is
// replaced by the Rust binary).

#pragma once

#include <boost/program_options/errors.hpp>

namespace shekyl { namespace cli {

// If `ex` names one of the daemonizer flags removed in V3.1
// (--detach, --pidfile, --install-service, --uninstall-service,
// --start-service, --stop-service, --run-as-service), write a
// migration message to stderr pointing the operator at systemd /
// launchd / Task Scheduler / Tauri sidecar, then return true.
// Caller should exit nonzero.
//
// Otherwise returns false — caller should re-throw / print the normal
// parse error.
//
// `binary_name` is used verbatim in the message ("shekyld" or
// "shekyl-wallet-rpc"), so per-binary hints read naturally without
// branching in the caller.
bool handle_removed_flag(
    boost::program_options::unknown_option const & ex,
    char const * binary_name);

}} // namespace shekyl::cli

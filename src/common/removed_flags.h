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

// TODO(v3.2): delete this file and its .cpp (see docs/FOLLOWUPS.md
// §"removed_flags shim sunset"). The shim exists only to give users a
// friendly migration message for flags removed in V3.1: the daemonizer flags
// (--detach, --pidfile, the Windows --*-service set), shekyld's inbound RPC
// TLS/auth flags (--rpc-login, --rpc-ssl*), and the transitional
// --no-rust-rpc opt-out.
//
// There is now exactly one call site: the daemon main() in
// src/daemon/main.cpp. The second, the C++ wallet's
// src/wallet/wallet_args.cpp, was deleted at Phase 5 along with the rest of
// the C++ wallet stack. So the sunset no longer waits on any cutover — what
// remains is the judgement that V3.1's flags have been gone long enough that
// an operator passing one deserves a parser error rather than a migration
// note.

#pragma once

#include <boost/program_options/errors.hpp>

namespace shekyl { namespace cli {

// If `ex` names a flag shekyld no longer registers — the V3.1 daemonizer
// flags (--detach, --pidfile, --install-service, --uninstall-service,
// --start-service, --stop-service, --run-as-service), shekyld's inbound
// RPC TLS/auth flags (--rpc-login, --rpc-ssl and the --rpc-ssl-* set), the
// transitional --no-rust-rpc, the bootstrap-daemon forward
// (--bootstrap-daemon-address / -login / -proxy), or --public-node —
// write a migration message to stderr appropriate to that flag's removal
// reason, then return true. Caller should exit nonzero.
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

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

// Flags removed in V3.1 when the daemonizer was deleted. The table is
// the single source of truth — CHANGELOG.md and FOLLOWUPS.md reference
// it by name rather than duplicating the list, so editing this array
// keeps documentation in sync automatically.
constexpr std::array<std::string_view, 7> REMOVED_FLAGS = {
  "detach",
  "pidfile",
  "install-service",
  "uninstall-service",
  "start-service",
  "stop-service",
  "run-as-service",
};

// boost::program_options::unknown_option::get_option_name() returns the
// offending flag without a leading "--" (it's stripped during parsing).
// Normalize defensively in case a future Boost version changes that.
std::string_view strip_leading_dashes(std::string_view s)
{
  while (!s.empty() && s.front() == '-') s.remove_prefix(1);
  return s;
}

bool is_removed(std::string_view flag)
{
  for (std::string_view const & removed : REMOVED_FLAGS)
  {
    if (flag == removed) return true;
  }
  return false;
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

  if (!is_removed(view)) return false;

  std::cerr <<
    "Error: '--" << view << "' was removed in V3.1. Background execution is now\n"
    "handled by systemd (Linux), launchd (macOS), Task Scheduler (Windows), or\n"
    "the Tauri sidecar (GUI wallet). Windows service management (install /\n"
    "uninstall / start / stop) is likewise delegated to the platform service\n"
    "manager. See docs/INSTALLATION_GUIDE.md for process-manager examples.\n"
    << binary_name << " exiting.\n";
  return true;
}

}} // namespace shekyl::cli

// Copyright (c) 2025-2026, The Shekyl Foundation
// Copyright (c) 2014-2024, The Monero Project
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
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The daemon's `main`, and the C++ remnant's entry pair
// (DAEMON_CONFIG_CUTOVER.md §2.2, DC-Q13). Rust owns the process:
// `main` hands `shekyl_daemon_main` an entry holding the version strings and
// two functions, `run` and `stop`, and returns its status. Rust reads the
// arguments, the configuration file, takes the lock, checks the marker,
// starts logging, makes the announcements and owns every signal; `run`
// receives the snapshot of the values whose reader is still C++ and parses
// nothing.

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/operations.hpp>
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/miner.h"
#include "daemon/command_server.h"
#include "daemon/daemon.h"
#include "misc_log_ex.h"
#include "p2p/net_node.h"
#include "string_tools_lexical.h"
#include "rpc/core_rpc_server.h"
#include "cryptonote_config.h"
#include "version.h"
#ifdef STACK_TRACE
#include "common/stack_trace.h"
#endif // STACK_TRACE
#ifdef __linux__
#include <sys/prctl.h>
#endif
#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon"
#include "shekyl/shekyl_ffi.h"

#include <atomic>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

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

// The remnant's `run`: `noexcept`, every C++ exception caught and turned
// into a status. Takes what C++ still reads from the snapshot, runs the
// client command or the daemon, and returns.
int remnant_run(const ShekylDaemonSnapshot* snapshot) noexcept
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
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif

    const bool testnet = snapshot->network == 1;
    const bool stagenet = snapshot->network == 2;
    const bool regtest = snapshot->network == 3;

    // Client mode: a command for a running daemon, at the admin endpoint
    // Rust resolved. No lock, no marker, no log file.
    if (snapshot->command.len > 0)
    {
      if (snapshot->client_endpoint == nullptr)
        return 1;
      std::vector<std::string> command;
      command.reserve(snapshot->command.len);
      for (size_t i = 0; i < snapshot->command.len; ++i)
        command.emplace_back(snapshot->command.items[i]);
      const std::string endpoint(snapshot->client_endpoint);
      const size_t colon = endpoint.rfind(':');
      if (colon == std::string::npos)
        return 1;
      std::string host = endpoint.substr(0, colon);
      if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
      uint32_t rpc_ip;
      uint16_t rpc_port;
      if (!epee::string_tools::get_ip_int32_from_string(rpc_ip, host))
      {
        std::cerr << "shekyld: the console client reaches IPv4 admin endpoints only; " << endpoint << " is not one" << std::endl;
        return 1;
      }
      if (!epee::string_tools::get_xtype_from_string(rpc_port, endpoint.substr(colon + 1)))
        return 1;
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
void remnant_stop() noexcept
{
  daemonize::request_stop();
}


} // namespace

int main(int argc, char const * argv[])
{
  (void)argc;
  (void)argv;
  ShekylDaemonEntry entry;
  entry.release_name = SHEKYL_RELEASE_NAME;
  entry.version_full = SHEKYL_VERSION_FULL;
  entry.protocol_version = SHEKYL_PROTOCOL_VERSION;
  entry.run = &remnant_run;
  entry.stop = &remnant_stop;
  return shekyl_daemon_main(&entry);
}

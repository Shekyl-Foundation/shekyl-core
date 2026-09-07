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

#include <boost/filesystem/operations.hpp>

#include "common/command_line.h"
#include "common/removed_flags.h"
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/levin_notify.h"
#include "cryptonote_basic/miner.h"
#include "daemon/command_server.h"
#include "daemon/daemon.h"
#include "misc_log_ex.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_server.h"
#include "rpc/rpc_args.h"
#include "daemon/command_line_args.h"
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

namespace po = boost::program_options;
namespace bf = boost::filesystem;

#ifdef WIN32
bool isFat32(const wchar_t* root_path)
{
  std::vector<wchar_t> fs(MAX_PATH + 1);
  if (!::GetVolumeInformationW(root_path, nullptr, 0, nullptr, 0, nullptr, &fs[0], MAX_PATH))
  {
    MERROR("Failed to get '" << root_path << "' filesystem name. Error code: " << ::GetLastError());
    return false;
  }

  return wcscmp(L"FAT32", &fs[0]) == 0;
}
#endif

int main(int argc, char const * argv[])
{
  try {

    // TODO parse the debug options like set log level right here at start

    tools::on_startup();

#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif

    epee::string_tools::set_module_name_and_folder(argv[0]);

    // Build argument description
    po::options_description all_options("All");
    po::options_description hidden_options("Hidden");
    po::options_description visible_options("Options");
    po::options_description core_settings("Settings");
    po::positional_options_description positional_options;
    {
      // Misc Options

      command_line::add_arg(visible_options, command_line::arg_help);
      command_line::add_arg(visible_options, command_line::arg_version);
      command_line::add_arg(visible_options, daemon_args::arg_os_version);
      command_line::add_arg(visible_options, daemon_args::arg_config_file);

      // Settings
      command_line::add_arg(core_settings, daemon_args::arg_log_file);
      command_line::add_arg(core_settings, daemon_args::arg_log_level);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_file_size);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_files);
      command_line::add_arg(core_settings, daemon_args::arg_max_concurrency);
      command_line::add_arg(core_settings, daemon_args::arg_proxy);
      command_line::add_arg(visible_options, daemon_args::arg_non_interactive);

      daemonize::Daemon::init_options(core_settings);

      // Hidden options
      command_line::add_arg(hidden_options, daemon_args::arg_command);
      command_line::add_arg(hidden_options, daemon_args::arg_carrier_development);

      visible_options.add(core_settings);
      all_options.add(visible_options);
      all_options.add(hidden_options);

      // Positional
      positional_options.add(daemon_args::arg_command.name, -1); // -1 for unlimited arguments
    }

    // Do command line parsing
    po::variables_map vm;
    bool ok = command_line::handle_error_helper(visible_options, [&]()
    {
      try
      {
        boost::program_options::store(
          boost::program_options::command_line_parser(argc, argv)
            .options(all_options).positional(positional_options).run()
        , vm
        );
      }
      catch (boost::program_options::unknown_option const & e)
      {
        if (shekyl::cli::handle_removed_flag(e, "shekyld"))
        {
          return false;
        }
        throw;
      }

      return true;
    });
    if (!ok) return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
      std::cout << "Shekyl '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
      std::cout << "Usage: " + std::string{argv[0]} + " [options|settings] [daemon_command...]" << std::endl << std::endl;
      std::cout << visible_options << std::endl;
      return 0;
    }

    // Shekyl Version
    if (command_line::get_arg(vm, command_line::arg_version))
    {
      std::cout << "Shekyl '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL
                << ", protocol " << SHEKYL_PROTOCOL_VERSION << ")" << ENDL;
      return 0;
    }

    // OS
    if (command_line::get_arg(vm, daemon_args::arg_os_version))
    {
      std::cout << "OS: " << tools::get_os_version_string() << ENDL;
      return 0;
    }

    std::string config = command_line::get_arg(vm, daemon_args::arg_config_file);
    boost::filesystem::path config_path(config);
    boost::system::error_code ec;
    if (bf::exists(config_path, ec))
    {
      try
      {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), core_settings), vm);
      }
      catch (const po::unknown_option &e)
      {
        // A retired flag in the config file is refused by name with its
        // reason, the same as on the command line: every shipped unit file
        // sends its operator through --config-file.
        if (shekyl::cli::handle_removed_flag(e, "shekyld"))
          return 1;
        std::string unrecognized_option = e.get_option_name();
        if (all_options.find_nothrow(unrecognized_option, false))
        {
          std::cerr << "Option '" << unrecognized_option << "' is not allowed in the config file, please use it as a command line flag." << std::endl;
        }
        else
        {
          std::cerr << "Unrecognized option '" << unrecognized_option << "' in config file." << std::endl;
        }
        return 1;
      }
      catch (const std::exception &e)
      {
        // log system isn't initialized yet
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        throw;
      }
    }
    else if (!command_line::is_arg_defaulted(vm, daemon_args::arg_config_file))
    {
      std::cerr << "Can't find config file " << config << std::endl;
      return 1;
    }

    const bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    const bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    const bool regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
    if (testnet + stagenet + regtest > 1)
    {
      std::cerr << "Can't specify more than one of --tesnet and --stagenet and --regtest" << ENDL;
      return 1;
    }

    // data_dir
    //   default: e.g. ~/.shekyl/ or ~/.shekyl/testnet
    //   if data-dir argument given:
    //     absolute path
    //     relative path: relative to cwd

    // Create data dir if it doesn't exist
    boost::filesystem::path data_dir = boost::filesystem::absolute(
        command_line::get_arg(vm, cryptonote::arg_data_dir));

#ifdef WIN32
    if (isFat32(data_dir.root_path().c_str()))
    {
      MERROR("Data directory resides on FAT32 volume that has 4GiB file size limit, blockchain might get corrupted.");
    }
#endif

    bf::path relative_path_base = data_dir;

    po::notify(vm);

    // log_file_path
    //   default: ~/.shekyl/logs/<binary>.log, resolved via
    //     `mlog_get_default_log_path` so the file lives on the
    //     Rust-owned logs tree (`<home>/.shekyl/logs/`) rather than
    //     next to the blockchain data. On testnet / stagenet the
    //     base name is suffixed so the three networks can run
    //     side-by-side without clobbering each other's log file.
    //     This matches the V4 contract promised in
    //     `docs/USER_GUIDE.md` §"Logging" and is what the Rust FFI
    //     already returns from `shekyl_log_default_path` when
    //     shekyl-cli / shekyl-wallet-rpc default their paths.
    //   if `--log-file` argument given: use it as-is
    //     (absolute, or relative to data_dir).
    //
    // File rotation is driven by `--max-log-file-size` (default 100
    // MB minus 7.6 KB headroom, see `MAX_LOG_FILE_SIZE` in
    // `misc_log_ex.h`) and `--max-log-files` (default 50). POSIX
    // mode `0600` on the live file and every rotated archive is
    // enforced unconditionally by the Rust side; see the `init_file`
    // contract in `src/shekyl/shekyl_log.h`.
    bf::path log_file_path;
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
    {
      log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
    }
    else
    {
      std::string default_name = CRYPTONOTE_NAME;
      if (testnet)
        default_name += "-testnet";
      else if (stagenet)
        default_name += "-stagenet";
      else if (regtest)
        default_name += "-regtest";
      log_file_path = mlog_get_default_log_path(default_name.c_str());
    }
    if (!log_file_path.has_parent_path())
      log_file_path = bf::absolute(log_file_path, relative_path_base);
    mlog_configure(log_file_path.string(), true, command_line::get_arg(vm, daemon_args::arg_max_log_file_size), command_line::get_arg(vm, daemon_args::arg_max_log_files));

    // Wire the Rust-side tracing surface into the subscriber that
    // mlog_configure just installed. Required ordering: init (inside
    // mlog_configure) first, then install. ALREADY_INSTALLED is the
    // benign re-configure arm; anything else means daemon-rpc tracing
    // events would be dropped, which is worth a loud warning but not
    // an abort (C++-side logging is unaffected).
    {
      const int32_t fwd_rc = shekyl_log_install_tracing_forwarder();
      if (fwd_rc != SHEKYL_LOG_OK && fwd_rc != SHEKYL_LOG_ERR_ALREADY_INSTALLED)
        std::cerr << "Warning: tracing forwarder install failed (code " << fwd_rc
                  << "); Rust daemon-rpc log events will be dropped" << std::endl;
    }

    // Set log level
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_level))
    {
      mlog_set_log(command_line::get_arg(vm, daemon_args::arg_log_level).c_str());
    }

    // after logs initialized
    tools::create_directories_if_necessary(data_dir.string());

    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_max_concurrency))
      tools::set_max_concurrency(command_line::get_arg(vm, daemon_args::arg_max_concurrency));

    // logging is now set up
    MGINFO("Shekyl '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")");

    /* THE CARRIER OPT-IN, and it is read HERE for two reasons.

       After `mlog_configure`, because arming it changes this node's network
       posture and the warning below is the only thing that says so — read it
       before logging exists and the operator gets silence. And before the
       daemon is constructed, because the flag is process-wide state that
       `make_relay_zone` consults as each zone is built; set it after and the
       zones are already made.

       No `else` branch: OFF is the default in every build and needs no
       announcement. See `COVER_TRAFFIC_RESTORATION.md` §3.1 for why this is a
       development switch rather than a product one, and §3.1c for the
       measurement it exists to make runnable. */
    if (command_line::get_arg(vm, daemon_args::arg_carrier_development))
    {
      cryptonote::levin::set_carrier_development(true);
      MWARNING("--" << daemon_args::arg_carrier_development.name
               << " is set: the Dandelion++ noise carrier is ARMED on every "
                  "encrypted zone. This node now emits sustained cover traffic "
                  "(~16 KiB/s, ~42 GB/month) it does not emit by default, and "
                  "its traffic profile differs from an unarmed node's. This is "
                  "a DEVELOPMENT switch for the COVER_TRAFFIC_RESTORATION.md "
                  "§3.1c measurement, not an operator setting.");
    }

    // If there are positional options, we're running a daemon command
    {
      auto command = command_line::get_arg(vm, daemon_args::arg_command);

      if (command.size())
      {
        const cryptonote::rpc_args::descriptors arg{};
        auto rpc_ip_str = command_line::get_arg(vm, arg.rpc_bind_ip);
        auto rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);

        uint32_t rpc_ip;
        uint16_t rpc_port;
        if (!epee::string_tools::get_ip_int32_from_string(rpc_ip, rpc_ip_str))
        {
          std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
          return 1;
        }
        if (!epee::string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
        {
          std::cerr << "Invalid port: " << rpc_port_str << std::endl;
          return 1;
        }

        // The shekyld RPC listener is plaintext loopback with no digest auth
        // (rpc_args is registered with include_listener_tls_auth=false), so the
        // control client has no login or TLS to carry: the former --rpc-login /
        // --rpc-ssl* flags are not registered for shekyld. Remote/authenticated
        // access is fronted by an onion service or reverse proxy outside the
        // daemon (docs/DAEMON_RPC_RUST.md).
        daemonize::t_command_server rpc_commands{rpc_ip, rpc_port};
        if (rpc_commands.process_command_vec(command))
        {
          // A recognized command that could not get its answer from the
          // daemon (unreachable, refused, non-OK status) exits non-zero: the
          // failure is already on stderr, and a script must be able to see
          // it without parsing that text.
          return rpc_commands.rpc_request_failed() ? 1 : 0;
        }
        else
        {
          PAUSE_READLINE();
          std::cerr << "Unknown command: " << command.front() << std::endl;
          return 1;
        }
      }
    }

    MINFO("Constructing daemon.");

    LOG_PRINT_L0("Shekyl '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")");

    daemonize::Daemon daemon{vm};
    const bool interactive = !command_line::get_arg(vm, daemon_args::arg_non_interactive);
    return daemon.run(interactive) ? 0 : 1;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Exception in main! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Exception in main!");
  }
  return 1;
}

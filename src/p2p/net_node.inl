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

// IP blocking adapted from Boolberry

#include <algorithm>
#include <boost/bind/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem/operations.hpp>
#include <optional>
#include <boost/thread/thread.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include <atomic>
#include <functional>
#include <limits>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "version.h"
#include "string_tools.h"
#include "common/util.h"
#include "net/error.h"
#include "math_helper.h"
#include "misc_log_ex.h"
#include "p2p_protocol_defs.h"
#include "crypto/crypto.h"
#include "storages/levin_abstract_invoke2.h"
#include "net/levin_base.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"
#include "p2p/seam_board.h"
#include "cryptonote_core/cryptonote_core.h"
#include "net/parse.h"
#include "net/tor_address.h"

#include <miniupnp/miniupnpc/miniupnpc.h>
#include <miniupnp/miniupnpc/upnpcommands.h>
#include <miniupnp/miniupnpc/upnperrors.h>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "net.p2p"

#define NET_MAKE_IP(b1,b2,b3,b4)  ((LPARAM)(((DWORD)(b1)<<24)+((DWORD)(b2)<<16)+((DWORD)(b3)<<8)+((DWORD)(b4))))

static inline boost::asio::ip::address_v4 make_address_v4_from_v6(const boost::asio::ip::address_v6& a)
{
  const auto &bytes = a.to_bytes();
  uint32_t v4 = 0;
  v4 = (v4 << 8) | bytes[12];
  v4 = (v4 << 8) | bytes[13];
  v4 = (v4 << 8) | bytes[14];
  v4 = (v4 << 8) | bytes[15];
  return boost::asio::ip::address_v4(v4);
}

namespace nodetool
{
  template<class t_payload_net_handler>
  node_server<t_payload_net_handler>::~node_server()
  {
    // tcp server uses io_context in destructor, and every zone uses
    // io_service from public zone.
    for (auto current = m_network_zones.begin(); current != m_network_zones.end(); /* below */)
    {
      if (current->first != epee::net_utils::connector_id::clearnet)
        current = m_network_zones.erase(current);
      else
        ++current;
    }
  }
  //-----------------------------------------------------------------------------------
  inline bool append_net_address(std::vector<epee::net_utils::network_address> & seed_nodes, std::string const & addr, uint16_t default_port);
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_p2p_bind_ip);
    command_line::add_arg(desc, arg_p2p_bind_ipv6_address);
    command_line::add_arg(desc, arg_p2p_bind_port, false);
    command_line::add_arg(desc, arg_p2p_bind_port_ipv6, false);
    command_line::add_arg(desc, arg_p2p_use_ipv6);
    command_line::add_arg(desc, arg_p2p_ignore_ipv4);
    command_line::add_arg(desc, arg_p2p_external_port);
    command_line::add_arg(desc, arg_p2p_allow_local_ip);
    command_line::add_arg(desc, arg_p2p_add_peer);
    command_line::add_arg(desc, arg_p2p_add_exclusive_node);
    command_line::add_arg(desc, arg_tx_proxy);
    command_line::add_arg(desc, arg_anonymous_inbound);
    command_line::add_arg(desc, arg_no_ephemeral_tor);
    command_line::add_arg(desc, arg_small_network);
    command_line::add_arg(desc, arg_ban_list);
    command_line::add_arg(desc, arg_no_sync);
    command_line::add_arg(desc, arg_no_igd);
    command_line::add_arg(desc, arg_igd);
    command_line::add_arg(desc, arg_out_peers);
    command_line::add_arg(desc, arg_in_peers);
    command_line::add_arg(desc, arg_tos_flag);
    command_line::add_arg(desc, arg_limit_rate_up);
    command_line::add_arg(desc, arg_limit_rate_down);
    command_line::add_arg(desc, arg_limit_rate);
    command_line::add_arg(desc, arg_pad_transactions);
    command_line::add_arg(desc, arg_clearnet_transport_encrypt);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::init_config()
  {
    TRY_ENTRY();
    shekyl_dialer_open_address_file((m_config_folder + "/" + P2P_NET_DATA_FILENAME).c_str());

    network_zone& public_zone = m_network_zones[epee::net_utils::connector_id::clearnet];
    public_zone.m_config.m_support_flags = P2P_SUPPORT_FLAGS;

    CATCH_ENTRY_L0("node_server::init_config", false);
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  size_t node_server<t_payload_net_handler>::post_each(std::function<void(typename t_payload_net_handler::connection_context&, uint32_t)> note, std::function<void()> then)
  {
    // The count is stored before any post runs. The last strand calls
    // `then`. No connections calls it here. `n == 0` does not post.
    auto left = std::make_shared<std::atomic<size_t>>(0);
    auto ran = std::make_shared<std::atomic<bool>>(false);
    auto finish = std::make_shared<std::function<void()>>(std::move(then));
    std::vector<std::function<void()>> posts;
    for(auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().collect_context_posts(
        [note, left, ran, finish](p2p_connection_context& cntx){
          note(cntx, cntx.support_flags);
          if (left->fetch_sub(1, std::memory_order_acq_rel) == 1
              && !ran->exchange(true, std::memory_order_acq_rel)
              && *finish)
            (*finish)();
        }, posts);
    }
    left->store(posts.size(), std::memory_order_release);
    for (auto& post : posts)
      post();
    if (posts.empty() && !ran->exchange(true, std::memory_order_acq_rel) && *finish)
      (*finish)();
    return posts.size();
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::for_connection(const boost::uuids::uuid &connection_id, std::function<void(typename t_payload_net_handler::connection_context&, uint32_t)> f)
  {
    // True when some zone queued the callback. The callback runs on that
    // connection's strand. False means the id is not in a zone.
    for(auto& zone : m_network_zones)
    {
      const bool queued = zone.second.m_net_server.get_config_object().for_connection(connection_id, [f](p2p_connection_context& cntx){
        f(cntx, cntx.support_flags);
      });
      if (queued)
        return true;
    }
    return false;
  }
  //-----------------------------------------------------------------------------------
  namespace
  {
    bool ban_duration_ns(time_t seconds, std::uint64_t* out)
    {
      if (seconds <= 0)
        return false;
      const auto whole = static_cast<std::uint64_t>(seconds);
      if (whole > std::numeric_limits<std::uint64_t>::max() / 1000000000ull)
        return false;
      *out = whole * 1000000000ull;
      return true;
    }

    time_t remaining_seconds(std::uint64_t ns)
    {
      const std::uint64_t sec = (ns + 999999999ull) / 1000000000ull;
      if (sec > static_cast<std::uint64_t>(std::numeric_limits<time_t>::max()))
        return std::numeric_limits<time_t>::max();
      return static_cast<time_t>(sec);
    }

    std::vector<shekyl_ban_view> copy_bans()
    {
      std::vector<shekyl_ban_view> views;
      for (int attempt = 0; attempt < 3; ++attempt)
      {
        std::size_t count = 0;
        if (shekyl_bans_copy(nullptr, 0, &count) != 0 && count == 0)
          return {};
        views.resize(count);
        if (count == 0)
          return views;
        std::size_t again = 0;
        shekyl_bans_copy(views.data(), views.size(), &again);
        if (again <= views.size())
        {
          views.resize(again);
          return views;
        }
      }
      return {};
    }
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::is_remote_host_allowed(const epee::net_utils::network_address &address, time_t *t)
  {
    if (!address.is_blockable())
      return true;
    const std::string host = address.host_str();
    std::uint64_t left = 0;
    const int rc = shekyl_ban_remaining_ns(host.c_str(), &left);
    if (rc == 2)
    {
      if (t)
        *t = 0;
      return false;
    }
    if (rc != 1)
      return true;
    if (t)
      *t = remaining_seconds(left);
    return false;
  }
  //-----------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::block_host(epee::net_utils::network_address addr, time_t seconds, bool /*add_only*/)
  {
    if(!addr.is_blockable())
      return false;

    std::uint64_t duration_ns = 0;
    if (!ban_duration_ns(seconds, &duration_ns))
      return false;
    const std::string host_str = addr.host_str();
    // The list closes the sockets it drops. This does not walk the Levin
    // registry. A shorter duration does not shorten a ban already stored.
    if (shekyl_ban_for(host_str.c_str(), 0, duration_ns) != 0)
      return false;

    MCLOG_CYAN(el::Level::Info, "global", "Host " << host_str << " blocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::unblock_host(const epee::net_utils::network_address &address)
  {
    const std::string host_str = address.host_str();
    if (shekyl_ban_lift(host_str.c_str(), 0) != 0)
      return false;
    MCLOG_CYAN(el::Level::Info, "global", "Host " << host_str << " unblocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::block_subnet(const epee::net_utils::ipv4_network_subnet &subnet, time_t seconds)
  {
    std::uint64_t duration_ns = 0;
    if (!ban_duration_ns(seconds, &duration_ns))
      return false;
    const std::string host_str = subnet.host_str();
    if (shekyl_ban_for(host_str.c_str(), 1, duration_ns) != 0)
      return false;

    MCLOG_CYAN(el::Level::Info, "global", "Subnet " << host_str << " blocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::unblock_subnet(const epee::net_utils::ipv4_network_subnet &subnet)
  {
    const std::string host_str = subnet.host_str();
    if (shekyl_ban_lift(host_str.c_str(), 1) != 0)
      return false;
    MCLOG_CYAN(el::Level::Info, "global", "Subnet " << host_str << " unblocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::block_host_permanent(epee::net_utils::network_address addr)
  {
    if (!addr.is_blockable())
      return false;
    const std::string host_str = addr.host_str();
    if (shekyl_ban_permanent(host_str.c_str(), 0) != 0)
      return false;
    MCLOG_CYAN(el::Level::Info, "global", "Host " << host_str << " blocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::block_subnet_permanent(const epee::net_utils::ipv4_network_subnet &subnet)
  {
    const std::string host_str = subnet.host_str();
    if (shekyl_ban_permanent(host_str.c_str(), 1) != 0)
      return false;
    MCLOG_CYAN(el::Level::Info, "global", "Subnet " << host_str << " blocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::host_ban_is_permanent(const epee::net_utils::network_address &address) const
  {
    if (!address.is_blockable())
      return false;
    std::uint64_t left = 0;
    return shekyl_ban_remaining_ns(address.host_str().c_str(), &left) == 2;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  std::vector<shekyl_ban_view> node_server<t_payload_net_handler>::ban_list()
  {
    return copy_bans();
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::apply_managed_onion_publish(network_zone& zone, int publish_rc, const char* service_id, std::uint16_t virtual_port)
  {
    if (publish_rc != SHEKYL_DAEMON_TOR_OK || service_id == nullptr || service_id[0] == '\0')
      return;
    const auto our_address = net::tor_address::make(std::string{service_id} + ".onion", virtual_port);
    if (!our_address)
      return;
    zone.m_our_address = *our_address;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::is_host_blocked(const epee::net_utils::network_address &address, time_t *seconds)
  {
    return !is_remote_host_allowed(address, seconds);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  std::map<std::string, time_t> node_server<t_payload_net_handler>::get_blocked_hosts()
  {
    std::map<std::string, time_t> hosts;
    for (const auto& row : copy_bans())
    {
      if (row.kind != 1)
        continue;
      hosts.emplace(row.text, remaining_seconds(row.remaining_ns));
    }
    return hosts;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  std::map<epee::net_utils::ipv4_network_subnet, time_t> node_server<t_payload_net_handler>::get_blocked_subnets()
  {
    std::map<epee::net_utils::ipv4_network_subnet, time_t> subnets;
    for (const auto& row : copy_bans())
    {
      if (row.kind != 2)
        continue;
      const auto parsed = net::get_ipv4_subnet_address(row.text);
      if (!parsed)
        continue;
      subnets.emplace(*parsed, remaining_seconds(row.remaining_ns));
    }
    return subnets;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::add_host_fail(const epee::net_utils::network_address &address, unsigned int score)
  {
    if(!address.is_blockable())
      return false;

    CRITICAL_REGION_LOCAL(m_host_fails_score_lock);
    uint64_t fails = m_host_fails_score[address.host_str()] += score;
    MDEBUG("Host " << address.host_str() << " fail score=" << fails);
    if(fails > P2P_IP_FAILS_BEFORE_BLOCK)
    {
      auto it = m_host_fails_score.find(address.host_str());
      CHECK_AND_ASSERT_MES(it != m_host_fails_score.end(), false, "internal error");
      it->second = P2P_IP_FAILS_BEFORE_BLOCK/2;
      block_host(address);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::handle_command_line(
      const boost::program_options::variables_map& vm
    )
  {
    bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    m_nettype = testnet ? cryptonote::TESTNET : stagenet ? cryptonote::STAGENET : cryptonote::MAINNET;

    network_zone& public_zone = m_network_zones[epee::net_utils::connector_id::clearnet];
    public_zone.m_outbound = true;
    public_zone.m_bind_ip = command_line::get_arg(vm, arg_p2p_bind_ip);
    public_zone.m_bind_ipv6_address = command_line::get_arg(vm, arg_p2p_bind_ipv6_address);
    public_zone.m_port = command_line::get_arg(vm, arg_p2p_bind_port);
    public_zone.m_port_ipv6 = command_line::get_arg(vm, arg_p2p_bind_port_ipv6);
    public_zone.m_can_announce = true;
    m_external_port = command_line::get_arg(vm, arg_p2p_external_port);
    shekyl_peerlist_allow_local_ip(command_line::get_arg(vm, arg_p2p_allow_local_ip));
    if (command_line::get_arg(vm, arg_small_network))
      shekyl_peerlist_small_network();
    const bool has_no_igd = command_line::get_arg(vm, arg_no_igd);
    const std::string sigd = command_line::get_arg(vm, arg_igd);
    if (sigd == "enabled")
    {
      if (has_no_igd)
      {
        MFATAL("Cannot have both --" << arg_no_igd.name << " and --" << arg_igd.name << " enabled");
        return false;
      }
      m_igd = igd;
    }
    else if (sigd == "disabled")
    {
      m_igd =  no_igd;
    }
    else if (sigd == "delayed")
    {
      if (has_no_igd && !command_line::is_arg_defaulted(vm, arg_igd))
      {
        MFATAL("Cannot have both --" << arg_no_igd.name << " and --" << arg_igd.name << " delayed");
        return false;
      }
      m_igd = has_no_igd ? no_igd : delayed_igd;
    }
    else
    {
      MFATAL("Invalid value for --" << arg_igd.name << ", expected enabled, disabled or delayed");
      return false;
    }
    m_offline = command_line::get_arg(vm, cryptonote::arg_offline);
    m_use_ipv6 = command_line::get_arg(vm, arg_p2p_use_ipv6);
    m_require_ipv4 = !command_line::get_arg(vm, arg_p2p_ignore_ipv4);

    if (command_line::has_arg(vm, arg_p2p_add_peer))
    {
      std::vector<std::string> perrs = command_line::get_arg(vm, arg_p2p_add_peer);
      for(const std::string& pr_str: perrs)
      {
        nodetool::peerlist_entry pe = AUTO_VAL_INIT(pe);
        const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
        expect<epee::net_utils::network_address> adr = net::get_network_address(pr_str, default_port);
        if (adr)
        {
          add_zone(epee::net_utils::require_address_connector(*adr));
          pe.adr = std::move(*adr);
          m_command_line_peers.push_back(std::move(pe));
          continue;
        }
        CHECK_AND_ASSERT_MES(
          adr == net::error::unsupported_address, false, "Bad address (\"" << pr_str << "\"): " << adr.error().message()
        );

        std::vector<epee::net_utils::network_address> resolved_addrs;
        bool r = append_net_address(resolved_addrs, pr_str, default_port);
        CHECK_AND_ASSERT_MES(r, false, "Failed to parse or resolve address from string: " << pr_str);
        for (const epee::net_utils::network_address& addr : resolved_addrs)
        {
          pe.adr = addr;
          m_command_line_peers.push_back(pe);
        }
      }
    }

    if (command_line::has_arg(vm,arg_p2p_add_exclusive_node))
    {
      if (!parse_peers_and_add_to_container(vm, arg_p2p_add_exclusive_node, m_exclusive_peers))
        return false;
      shekyl::declare_exclusive_peers(m_exclusive_peers);
    }

    if (!command_line::is_arg_defaulted(vm, arg_ban_list))
    {
      const std::string ban_list = command_line::get_arg(vm, arg_ban_list);

      const boost::filesystem::path ban_list_path(ban_list);
      boost::system::error_code ec;
      if (!boost::filesystem::exists(ban_list_path, ec))
      {
        throw std::runtime_error("Can't find ban list file " + ban_list + " - " + ec.message());
      }

      std::string banned_ips;
      if (!epee::file_io_utils::load_file_to_string(ban_list_path.string(), banned_ips))
      {
        throw std::runtime_error("Failed to read ban list file " + ban_list);
      }

      std::istringstream iss(banned_ips);
      for (std::string line; std::getline(iss, line); )
      {
        // ignore comments after '#' character
        const size_t pound_idx = line.find('#');
        if (pound_idx != std::string::npos)
          line.resize(pound_idx);

        // trim whitespace and ignore empty lines
        boost::trim(line);
        if (line.empty())
          continue;

        auto subnet = net::get_ipv4_subnet_address(line);
        if (subnet)
        {
          if (!block_subnet_permanent(*subnet))
            MERROR("Could not ban " << line);
          continue;
        }
        const expect<epee::net_utils::network_address> parsed_addr = net::get_network_address(line, 0);
        if (parsed_addr)
        {
          if (!block_host_permanent(*parsed_addr))
            MERROR("Could not ban " << line);
          continue;
        }
        MERROR("Invalid IP address or IPv4 subnet: " << line);
      }
    }

    if (command_line::has_arg(vm, arg_no_sync))
      m_payload_handler.set_no_sync(true);

    if ( !set_max_out_peers(public_zone, command_line::get_arg(vm, arg_out_peers) ) )
      return false;
    else
      m_payload_handler.set_max_out_peers(epee::net_utils::connector_id::clearnet, shekyl_dialer_out_target(SHEKYL_CONNECTOR_CLEARNET));


    // Negative is unset. The ceiling is derived in `apply_inbound_ceiling`
    // after the listeners exist; storing the sentinel here would narrow it
    // into `uint32_t` and rebuild the unbounded interval.
    if ( !set_max_in_peers(public_zone, command_line::get_arg(vm, arg_in_peers)) )
      return false;

    if ( !set_tos_flag(vm, command_line::get_arg(vm, arg_tos_flag) ) )
      return false;

    if ( !set_rate_up_limit(vm, command_line::get_arg(vm, arg_limit_rate_up) ) )
      return false;

    if ( !set_rate_down_limit(vm, command_line::get_arg(vm, arg_limit_rate_down) ) )
      return false;

    if ( !set_rate_limit(vm, command_line::get_arg(vm, arg_limit_rate) ) )
      return false;


    auto proxies = get_proxies(vm);
    if (!proxies)
      return false;

    for (auto& proxy : *proxies)
    {
      network_zone& zone = add_zone(proxy.zone);
      if (zone.m_outbound)
      {
        MERROR("Listed --" << arg_tx_proxy.name << " twice with " << epee::net_utils::connector_id_to_string(proxy.zone));
        return false;
      }
      zone.m_outbound = true;
      zone.m_proxy_address = std::move(proxy.address);

      if (!set_max_out_peers(zone, proxy.max_connections))
        return false;
      else
        m_payload_handler.set_max_out_peers(proxy.zone, shekyl_dialer_out_target(SHEKYL_CONNECTOR_TOR));

      // No noise ARGUMENT here, and none to pass: the notifier has taken no
      // covert payload since #515 deleted the C++ carrier, and
      // `make_noise_notify` went with it. The carrier is Rust's
      // (`NoiseQueues` in `shekyl-relay`), turned on inside `make_relay_zone`
      // for an encrypted zone and only under `set_carrier_development` — a
      // process-wide runtime opt-in that DEFAULTS OFF, so a shipped daemon
      // still constructs every zone with the carrier dormant. The
      // configuration-B deletion removed the old switch from configuration
      // (see the `disable_noise` note in net_node.cpp);
      // COVER_TRAFFIC_RESTORATION.md §3.1 is why the replacement is a
      // development flag rather than an operator setting.
    }

    // A named onion creates the tor zone here, before the managed Tor exists.
    // That zone's SOCKS comes from add_ephemeral_tor_zone, not from --tx-proxy.
    // Refusing now is what made the default posture unable to dial one onion.
    const bool managed_tor_supplies_socks =
      !m_offline
      && m_nettype != cryptonote::FAKECHAIN
      && !command_line::get_arg(vm, arg_no_ephemeral_tor);
    for (const auto& zone : m_network_zones)
    {
      if (zone.second.m_outbound)
        continue;
      if (zone.first == epee::net_utils::connector_id::tor && managed_tor_supplies_socks)
        continue;
      MERROR("Set outgoing peer for " << epee::net_utils::connector_id_to_string(zone.first) << " but did not set --" << arg_tx_proxy.name);
      return false;
    }

    auto inbounds = get_anonymous_inbounds(vm);
    if (!inbounds)
      return false;

    const std::size_t tx_relay_zones = m_network_zones.size();
    for (auto& inbound : *inbounds)
    {
      network_zone& zone = add_zone(epee::net_utils::require_address_connector(inbound.our_address));

      if (!zone.m_bind_ip.empty())
      {
        MERROR("Listed --" << arg_anonymous_inbound.name << " twice with " << epee::net_utils::connector_id_to_string(epee::net_utils::require_address_connector(inbound.our_address)) << " network");
        return false;
      }

      if (!zone.m_outbound && tx_relay_zones <= 1)
      {
        MERROR("Listed --" << arg_anonymous_inbound.name << " without listing any --" << arg_tx_proxy.name << ". The latter is necessary for sending local txes over anonymity networks");
        return false;
      }

      zone.m_bind_ip = std::move(inbound.local_ip);
      zone.m_port = std::move(inbound.local_port);
      // The operator runs this onion and hands us its address. That is
      // configuration, not a publish result, and it is what peers are told.
      zone.m_our_address = shekyl::note_own_address(std::move(inbound.our_address));

      if (!set_max_in_peers(zone, inbound.max_connections))
        return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------
  inline bool append_net_address(
      std::vector<epee::net_utils::network_address> & seed_nodes
    , std::string const & addr
    , uint16_t default_port
    )
  {
    using namespace boost::asio;

    // Split addr string into host string and port string
    std::string host;
    std::string port = std::to_string(default_port);
    net::get_network_address_host_and_port(addr, host, port);
    MINFO("Resolving node address: host=" << host << ", port=" << port);

    boost::system::error_code ec;
    io_context io_srv;
    ip::tcp::resolver resolver(io_srv);
    const auto results = resolver.resolve(host, port, boost::asio::ip::tcp::resolver::canonical_name, ec);
    CHECK_AND_ASSERT_MES(!ec && !results.empty(), false, "Failed to resolve host name '" << host << "': " << ec.message() << ':' << ec.value());

    for (const auto& result : results)
    {
      const auto& endpoint = result.endpoint();
      if (endpoint.address().is_v4())
      {
        epee::net_utils::network_address na{epee::net_utils::ipv4_network_address{boost::asio::detail::socket_ops::host_to_network_long(endpoint.address().to_v4().to_uint()), endpoint.port()}};
        seed_nodes.push_back(na);
        MINFO("Added node: " << na.str());
      }
      else
      {
        epee::net_utils::network_address na{epee::net_utils::ipv6_network_address{endpoint.address().to_v6(), endpoint.port()}};
        seed_nodes.push_back(na);
        MINFO("Added node: " << na.str());
      }
    }
    return true;
  }

  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  typename node_server<t_payload_net_handler>::network_zone& node_server<t_payload_net_handler>::add_zone(const epee::net_utils::connector_id zone)
  {
    const auto zone_ = m_network_zones.lower_bound(zone);
    if (zone_ != m_network_zones.end() && zone_->first == zone)
      return zone_->second;

    network_zone& public_zone = m_network_zones[epee::net_utils::connector_id::clearnet];
    return m_network_zones.emplace_hint(zone_, std::piecewise_construct, std::make_tuple(zone), std::tie(public_zone.m_net_server.get_io_context()))->second;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::add_ephemeral_tor_zone(const boost::program_options::variables_map& vm)
  {
    // PWD-E7: skip-or-degrade only. send_txs fail-closes onto an existing
    // anonymity zone, so a start failure must leave NO tor zone in the map.
    if (m_offline || m_nettype == cryptonote::FAKECHAIN)
      return;
    const auto preexisting = m_network_zones.find(epee::net_utils::connector_id::tor);
    const bool zone_was_present = preexisting != m_network_zones.end();
    if (command_line::get_arg(vm, arg_no_ephemeral_tor))
    {
      // TB-1: declining Tor is a supported choice, and a node that made it
      // says so on every boot at a level that is read. An operator who
      // attached a Tor of their own has not declined Tor, only the managed one.
      //
      // These lines go to the "global" category on purpose. This file's own
      // category, net.p2p, is filtered to errors by the default log settings,
      // so a warning written there is one nobody sees -- which is how a node
      // came to run clearnet-only without its operator knowing.
      if (zone_was_present)
        MINFO("Managed Tor disabled by --" << arg_no_ephemeral_tor.name
            << "; the operator-provisioned Tor configuration is in use");
      else
        MCWARNING("global", "Tor is declined (--" << arg_no_ephemeral_tor.name << "): this node is clearnet-only. "
            "Its address is visible to its peers, and its own transactions are relayed over clearnet "
            "with no onion route. The clearnet link is encrypted only where --"
            << arg_clearnet_transport_encrypt.name << " is set on both ends. "
            "Remove the flag to run with Tor");
      return;
    }
    // --anonymous-inbound already owns the onion. --tx-proxy does not: it
    // names the SOCKS address dials use, and the per-boot onion still publishes.
    // A tor zone that exists only because a named onion was parsed is the same
    // case — the managed Tor has not started yet, so it is not operator SOCKS.
    if (zone_was_present && !preexisting->second.m_bind_ip.empty())
    {
      MINFO("Operator inbound onion (--" << arg_anonymous_inbound.name
          << ") owns the tor zone; ephemeral publish yields to it");
      return;
    }
    const bool socks_from_tx_proxy = zone_was_present && preexisting->second.m_outbound;

    constexpr uint16_t EPHEMERAL_TOR_MAX_STREAMS = 8;
    constexpr uint32_t EPHEMERAL_TOR_BOOTSTRAP_TIMEOUT_SECS = 300;

    char socks_addr[64] = {0};
    char error_msg[512] = {0};
    const int rc = shekyl_daemon_tor_start(
        nullptr, m_config_folder.c_str(), EPHEMERAL_TOR_BOOTSTRAP_TIMEOUT_SECS,
        socks_addr, sizeof (socks_addr), error_msg, sizeof (error_msg));
    switch (rc)
    {
    case SHEKYL_DAEMON_TOR_OK:
      MINFO("Pinned tor binary found; publishing ephemeral overlay inbound (PWD-E7)");
      break;
    case SHEKYL_DAEMON_TOR_NO_BINARY:
      // Not declined, and not present: the state TB-1 says a node is not
      // quietly in. It is a warning until the refusal (TB-2) lands.
      // `--tx-proxy` already installed a SOCKS dial, and this return leaves
      // that zone in place, so outbound is that proxy. Calling the node
      // clearnet-only would be false.
      if (socks_from_tx_proxy)
        MCWARNING("global", "No Tor bundle was found, so there is no per-boot onion for inbound. "
            "Outbound stays on the Tor proxy already configured (--" << arg_tx_proxy.name
            << "). Install the pinned Tor bundle in the tor/ directory beside the daemon or under "
            "/opt/shekyl/<bundle>-<target>/ (release packages carry it) to publish inbound as well");
      else
        MCWARNING("global", "No Tor was found, so this node is clearnet-only for this boot although Tor was not "
            "declined. Install the pinned Tor bundle in the tor/ directory beside the daemon or under "
            "/opt/shekyl/<bundle>-<target>/ (release packages carry it), or pass --"
            << arg_no_ephemeral_tor.name << " to run clearnet-only on purpose");
      return;
    case SHEKYL_DAEMON_TOR_BAD_BINARY:
      if (socks_from_tx_proxy)
        MCWARNING("global", "A Tor installation was found but is unusable: " << error_msg
            << ". Outbound stays on the Tor proxy already configured (--" << arg_tx_proxy.name
            << "). Inbound has no per-boot onion for this boot");
      else
        MCWARNING("global", "A Tor installation was found but is unusable: " << error_msg
            << ". This node is clearnet-only for this boot");
      return;
    case SHEKYL_DAEMON_TOR_UNAVAILABLE:
      if (socks_from_tx_proxy)
        MCWARNING("global", "Shekyl does not manage a Tor process on this platform (" << error_msg
            << "). Outbound stays on the Tor proxy already configured (--" << arg_tx_proxy.name
            << "). Inbound has no per-boot onion until you pass --" << arg_anonymous_inbound.name
            << " with an onion of your own");
      else
        MCWARNING("global", "Shekyl does not manage a Tor process on this platform (" << error_msg
            << "), so this node is clearnet-only unless you attach a Tor of your own: run tor, then pass --"
            << arg_tx_proxy.name << " for outbound and --" << arg_anonymous_inbound.name
            << " for inbound. Pass --" << arg_no_ephemeral_tor.name << " to run clearnet-only on purpose");
      return;
    default:
      MERROR("Ephemeral tor start failed (" << error_msg
          << "); continuing without the tor zone this boot");
      return;
    }

    const auto proxy_endpoint = net::socks::endpoint::get(std::string{socks_addr});
    if (!proxy_endpoint)
    {
      MERROR("Ephemeral tor returned an unparseable SOCKS address ('" << socks_addr << "'); tearing it down");
      shekyl_daemon_tor_shutdown();
      return;
    }

    // Bind the loopback forward target HERE on port 0 (OS-assigned). A guessed
    // port can already be taken, and the shared bind loop in init() aborts the
    // whole boot on collision. m_bind_ip stays empty so that loop skips this
    // already-bound server. A zone this function created is erased if the bind
    // fails; a zone a named onion already created is left, so the peer is not
    // dropped with the listener.
    network_zone& zone = add_zone(epee::net_utils::connector_id::tor);
    // listen_tor installs the managed SOCKS as the dial proxy. When --tx-proxy
    // already named one, init()'s dial_through_tor writes that address back,
    // so dials use the operator SOCKS and the onion stays on this managed Tor.
    if (!zone.m_net_server.listen_tor(proxy_endpoint->address, "", "", false,
        reinterpret_cast<const std::uint8_t*>(&m_network_id), transport_ceiling()))
    {
      MERROR("Cannot bind the ephemeral tor forward listener on 127.0.0.1 (OS-assigned port); tearing tor down");
      shekyl_daemon_tor_shutdown();
      if (!zone_was_present)
        m_network_zones.erase(epee::net_utils::connector_id::tor);
      return;
    }
    const uint16_t local_port = static_cast<uint16_t>(zone.m_net_server.get_binded_port());

    if (!socks_from_tx_proxy)
    {
      zone.m_proxy_address = *proxy_endpoint;
      zone.m_outbound = true;
      // Address-hiding outbound target: the dialer's compiled default for
      // Tor, the measured degree. `--out-peers` does not set it.
      m_payload_handler.set_max_out_peers(epee::net_utils::connector_id::tor, shekyl_dialer_out_target(SHEKYL_CONNECTOR_TOR));
      set_max_in_peers(zone, -1);
    }
    m_ephemeral_tor_alive = true;

    const uint16_t virtual_port =
        m_nettype == cryptonote::TESTNET ? ::config::testnet::P2P_DEFAULT_PORT :
        m_nettype == cryptonote::STAGENET ? ::config::stagenet::P2P_DEFAULT_PORT :
        ::config::P2P_DEFAULT_PORT;
    char service_id[64] = {0};
    const int publish_rc = shekyl_daemon_tor_publish(
        virtual_port, local_port, EPHEMERAL_TOR_MAX_STREAMS,
        service_id, sizeof (service_id), error_msg, sizeof (error_msg));
    if (publish_rc != SHEKYL_DAEMON_TOR_OK)
    {
      MCWARNING("global", "Ephemeral onion publish failed (" << error_msg
          << "); the tor zone stays outbound-only this boot (no overlay inbound; PWD-E7 ruled degrade)");
      return;
    }
    const auto before = zone.m_our_address;
    apply_managed_onion_publish(zone, publish_rc, service_id, virtual_port);
    if (zone.m_our_address == before)
    {
      MERROR("Ephemeral tor returned an unparseable service id ('" << service_id
          << "'); the tor zone stays outbound-only this boot");
      return;
    }
    m_ephemeral_tor_service_id = service_id;

    MLOG_GREEN(el::Level::Info, "Ephemeral overlay inbound published: " << service_id << ".onion:" << virtual_port
        << " -> 127.0.0.1:" << local_port << " (new address every boot; SOCKS " << socks_addr << ")");
    // The address stays in net.p2p, which the default log settings filter. That
    // Tor is up is said where an operator reads it, without the address.
    MGINFO("Tor is up: the managed tor is running and overlay inbound is published on a per-boot onion address");
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::init(const boost::program_options::variables_map& vm, const std::string& proxy)
  {
    bool res = handle_command_line(vm);
    CHECK_AND_ASSERT_MES(res, false, "Failed to handle command line");
    if (proxy.size())
    {
      const auto endpoint = net::socks::endpoint::get(proxy);
      CHECK_AND_ASSERT_MES(endpoint, false, "Failed to parse proxy: " << proxy << " - " << endpoint.error().message());
      network_zone& public_zone = m_network_zones[epee::net_utils::connector_id::clearnet];
      public_zone.m_outbound = true;
      public_zone.m_proxy_address = *endpoint;
      public_zone.m_can_announce = false;
    }

    {
      const auto id = cryptonote::get_config(m_nettype).NETWORK_ID;
      memcpy(&m_network_id, &id, 16);
    }

    m_config_folder = command_line::get_arg(vm, cryptonote::arg_data_dir);
    network_zone& public_zone = m_network_zones.at(epee::net_utils::connector_id::clearnet);

    if ((m_nettype == cryptonote::MAINNET && public_zone.m_port != std::to_string(::config::P2P_DEFAULT_PORT))
        || (m_nettype == cryptonote::TESTNET && public_zone.m_port != std::to_string(::config::testnet::P2P_DEFAULT_PORT))
        || (m_nettype == cryptonote::STAGENET && public_zone.m_port != std::to_string(::config::stagenet::P2P_DEFAULT_PORT))) {
      m_config_folder = m_config_folder + "/" + public_zone.m_port;
    }

    // PWD-E7 default posture -- after m_config_folder is final (the managed
    // tor's DataDirectory lives under it) and before the peerlist/bind loops
    // iterate m_network_zones (the ephemeral tor zone must be in the map by
    // then). Blocks for the tor bootstrap when the posture engages; every
    // failure inside degrades to no-overlay-inbound rather than failing init.
    add_ephemeral_tor_zone(vm);

    // Every failure below exits through a CHECK_AND_ASSERT_MES return, after
    // which the daemon shuts down without ever reaching deinit() -- which is
    // where the managed tor is normally torn down. Tear it down on those
    // paths too, deterministically, rather than leaning on process-exit
    // reaping (TAKEOWNERSHIP is the backstop for crashes, not the mechanism
    // for orderly failures). Disarmed on init's success returns; a no-op when
    // the posture never engaged (shutdown on a never-started tor does
    // nothing).
    struct ephemeral_tor_init_guard
    {
      bool armed = true;
      ~ephemeral_tor_init_guard() { if (armed) shekyl_daemon_tor_shutdown(); }
    } ephemeral_tor_guard;

    res = init_config();
    CHECK_AND_ASSERT_MES(res, false, "Failed to init config.");


    // `--add-peer` names CANDIDATES, not verified peers: operator-named
    // addresses enter the Rust gray list and earn white the way every other
    // address does, through a drawn dial the strand accepts (slice 1 brief
    // §3: seeds are ordinary peers; the compiled seeds enter from Rust).
    for(const auto& p: m_command_line_peers)
      shekyl::admit_operator_peer(p.adr);

    //configure self

    public_zone.m_net_server.set_threads_prefix("P2P"); // all zones use these threads/asio::io_service

    // from here onwards, it's online stuff
    if (m_offline)
    {
      if (!apply_inbound_ceiling(0))
        return false;
      ephemeral_tor_guard.armed = false;
      return res;
    }

    //try to bind
    // D7 ruling 4. Off through cutover. The flip deletes the option.
    const bool clearnet_encrypt = command_line::get_arg(vm, arg_clearnet_transport_encrypt);
    for (auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().set_handler(this);
      zone.second.m_net_server.get_config_object().m_invoke_timeout = std::chrono::milliseconds{P2P_DEFAULT_INVOKE_TIMEOUT};

      if (!zone.second.m_bind_ip.empty())
      {
        const shekyl_inbound_ceiling ceiling = transport_ceiling();
        const std::uint8_t* network_id = reinterpret_cast<const std::uint8_t*>(&m_network_id);
        if (zone.first == epee::net_utils::connector_id::tor)
        {
          MINFO("Binding tor forward on " << zone.second.m_bind_ip << ":" << zone.second.m_port);
          res = zone.second.m_net_server.listen_tor(zone.second.m_proxy_address.address, zone.second.m_bind_ip, zone.second.m_port, true, network_id, ceiling);
        }
        else
        {
          std::string ipv6_addr;
          std::string ipv6_port;
          MINFO("Binding (IPv4) on " << zone.second.m_bind_ip << ":" << zone.second.m_port);
          if (!zone.second.m_bind_ipv6_address.empty() && m_use_ipv6)
          {
            ipv6_addr = zone.second.m_bind_ipv6_address;
            ipv6_port = zone.second.m_port_ipv6;
            MINFO("Binding (IPv6) on " << zone.second.m_bind_ipv6_address << ":" << zone.second.m_port_ipv6);
          }
          const bool have_proxy = zone.second.m_proxy_address.address.port() != 0;
          res = zone.second.m_net_server.listen_clearnet(zone.second.m_bind_ip, zone.second.m_port, ipv6_addr, ipv6_port, m_use_ipv6 && !ipv6_addr.empty(),
              have_proxy ? &zone.second.m_proxy_address.address : nullptr, clearnet_encrypt, network_id, ceiling);
        }
        CHECK_AND_ASSERT_MES(res, false, "Failed to bind server");
      }
      else if (zone.first == epee::net_utils::connector_id::tor && zone.second.m_proxy_address.address.port() != 0)
      {
        // This branch installs the Tor dial path through the seam; the
        // managed onion, if any, is published from Rust.
        res = zone.second.m_net_server.dial_through_tor(zone.second.m_proxy_address.address,
            reinterpret_cast<const std::uint8_t*>(&m_network_id), transport_ceiling());
        CHECK_AND_ASSERT_MES(res, false, "Failed to install the tor proxy");
      }
    }

    m_listening_port = public_zone.m_net_server.get_binded_port();
    MLOG_GREEN(el::Level::Info, "Net service bound (IPv4) to " << public_zone.m_bind_ip << ":" << m_listening_port);
    if (m_use_ipv6)
    {
      m_listening_port_ipv6 = public_zone.m_net_server.get_binded_port_ipv6();
      MLOG_GREEN(el::Level::Info, "Net service bound (IPv6) to " << public_zone.m_bind_ipv6_address << ":" << m_listening_port_ipv6);
    }
    if(m_external_port)
      MDEBUG("External port defined as " << m_external_port);

    // add UPnP port mapping
    if(m_igd == igd)
    {
      add_upnp_port_mapping_v4(m_listening_port);
      if (m_use_ipv6)
      {
        add_upnp_port_mapping_v6(m_listening_port_ipv6);
      }
    }

    if (!apply_inbound_ceiling(0))
      return false;

    /* One relay, after every connector zone exists. The mask is which
       connectors are configured; the relay reads their declarations. */
    {
      std::vector<cryptonote::levin::connector_registry> registries;
      std::uint32_t configured = 0;
      for (auto& zone : m_network_zones)
      {
        const std::uint8_t connector = cryptonote::levin::notify::connector_byte(zone.first);
        configured |= std::uint32_t{1} << connector;
        registries.push_back(cryptonote::levin::connector_registry{
          connector, zone.second.m_net_server.get_config_shared()});
      }
      const bool pad_txs = command_line::get_arg(vm, arg_pad_transactions);
      network_zone& public_zone_for_relay = m_network_zones.at(epee::net_utils::connector_id::clearnet);
      m_notifier = cryptonote::levin::notify{
        public_zone_for_relay.m_net_server.get_io_context(),
        std::move(registries),
        configured,
        pad_txs,
        m_payload_handler.get_core()
      };
    }
    ephemeral_tor_guard.armed = false;
    return res;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  typename node_server<t_payload_net_handler>::payload_net_handler& node_server<t_payload_net_handler>::get_payload_object()
  {
    return m_payload_handler;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::run()
  {
    network_zone& public_zone = m_network_zones.at(epee::net_utils::connector_id::clearnet);
    public_zone.m_net_server.add_idle_handler(boost::bind(&node_server<t_payload_net_handler>::idle_worker, this), std::chrono::seconds{1});
    public_zone.m_net_server.add_idle_handler(boost::bind(&t_payload_net_handler::on_idle, &m_payload_handler), std::chrono::seconds{1});

    // Structural floor: one worker besides the lane idle_worker blocks on.
    // Unmeasured. The run record replaces this count.
    constexpr std::size_t executor_workers = 2;
    boost::thread::attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    MINFO("Run net_service loop( " << executor_workers << " threads)...");
    if(!public_zone.m_net_server.run(executor_workers, attrs))
    {
      LOG_ERROR("Failed to run net tcp server!");
    }

    MINFO("net_service loop stopped.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::deinit()
  {
    kill();

    // PWD-E7: the ephemeral posture dies with the process -- DEL_ONION plus a
    // bounded SIGTERM->SIGKILL reap of the managed tor. Idempotent no-op when
    // the posture never engaged this boot.
    if (shekyl_daemon_tor_shutdown())
      MINFO("Ephemeral tor torn down (the address is gone; a restart mints a new one)");

    if (!m_offline)
    {
      for(auto& zone : m_network_zones)
        zone.second.m_net_server.deinit_server();
      // remove UPnP port mapping
      if(m_igd == igd)
        delete_upnp_port_mapping(m_listening_port);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::send_stop_signal()
  {
    MDEBUG("[node] sending stop signal");
    for (auto& zone : m_network_zones)
        zone.second.m_net_server.send_stop_signal();
    MDEBUG("[node] Stop signal sent");

    const auto board = shekyl::seam_board_snapshot();
    for (auto& zone : m_network_zones)
    {
      const auto connector = static_cast<std::uint8_t>(zone.first);
      std::list<boost::uuids::uuid> connection_ids;
      for (const auto& row : board)
        if (row.endpoint.connector == connector)
          connection_ids.push_back(shekyl::seam_connection_id(row.id));
      for (const auto &connection_id: connection_ids)
        zone.second.m_net_server.get_config_object().close(connection_id);
    }
    m_payload_handler.stop();
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::do_peer_timed_sync(const epee::net_utils::connection_context_base& context_)
  {
    typename COMMAND_TIMED_SYNC::request arg = AUTO_VAL_INIT(arg);
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    network_zone& zone = m_network_zones.at(epee::net_utils::require_session_connector(context_.m_connector));
    bool r = epee::net_utils::async_invoke_remote_command2<typename COMMAND_TIMED_SYNC::response>(context_, COMMAND_TIMED_SYNC::ID, arg, zone.m_net_server.get_config_object(),
      [this](int code, const typename COMMAND_TIMED_SYNC::response& rsp, p2p_connection_context& context)
    {
      context.m_in_timedsync = false;
      if(code < 0)
      {
        LOG_WARNING_CC(context, "COMMAND_TIMED_SYNC invoke failed. (" << code <<  ", " << epee::levin::get_err_descr(code) << ")");
        return;
      }

      if(!handle_remote_peerlist(rsp.local_peerlist_new, context))
      {
        LOG_WARNING_CC(context, "COMMAND_TIMED_SYNC: failed to handle_remote_peerlist(...), closing connection.");
        m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector)).m_net_server.get_config_object().close(context.m_connection_id );
        add_host_fail(context.m_remote_address);
      }
      if (!m_payload_handler.process_payload_sync_data(rsp.payload_data, context, false))
      {
        m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector)).m_net_server.get_config_object().close(context.m_connection_id );
      }
    });

    if(!r)
    {
      LOG_WARNING_CC(context_, "COMMAND_TIMED_SYNC Failed");
      return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::detect_self_handshake(const epee::net_utils::connector_id zone, const std::array<uint8_t, 32>& nonce)
  {
    // Within-zone only, and erase-on-match: see the declaration. The zone
    // is the INBOUND connection's, never one the request claims.
    const auto found = m_network_zones.find(zone);
    if (found == m_network_zones.end())
      return false;
    return shekyl_dial_take_handshake_nonce(static_cast<std::uint32_t>(zone), nonce.data()) != 0;
  }





  //-----------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  size_t node_server<t_payload_net_handler>::get_incoming_connections_count(epee::net_utils::connector_id connector)
  {
    return static_cast<size_t>(shekyl_seam_board_count(
        static_cast<std::uint32_t>(connector), SHEKYL_DIRECTION_INBOUND));
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  size_t node_server<t_payload_net_handler>::get_outgoing_connections_count(epee::net_utils::connector_id connector)
  {
    return static_cast<size_t>(shekyl_seam_board_count(
        static_cast<std::uint32_t>(connector), SHEKYL_DIRECTION_OUTBOUND));
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  size_t node_server<t_payload_net_handler>::get_outgoing_connections_count()
  {
    return static_cast<size_t>(shekyl_seam_board_direction_count(SHEKYL_DIRECTION_OUTBOUND));
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  size_t node_server<t_payload_net_handler>::get_incoming_connections_count()
  {
    return static_cast<size_t>(shekyl_seam_board_direction_count(SHEKYL_DIRECTION_INBOUND));
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::idle_worker()
  {
    m_peer_handshake_idle_maker_interval.do_call(boost::bind(&node_server<t_payload_net_handler>::peer_sync_idle_maker, this));
    m_incoming_connections_interval.do_call(boost::bind(&node_server<t_payload_net_handler>::check_incoming_connections, this));
    m_ephemeral_tor_liveness_interval.do_call(boost::bind(&node_server<t_payload_net_handler>::check_ephemeral_tor_liveness, this));
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::check_ephemeral_tor_liveness()
  {
    // Only watches the managed ephemeral posture; operator-provisioned tor
    // (--tx-proxy / --anonymous-inbound) is the operator's own process to
    // supervise. Armed once at a successful shekyl_daemon_tor_start; the
    // flag clears on the death edge so the loss is logged exactly once.
    if (!m_ephemeral_tor_alive)
      return true;
    if (shekyl_daemon_tor_is_alive())
      return true;
    m_ephemeral_tor_alive = false;
    MERROR("The managed ephemeral tor died; overlay posture is gone for this boot (ruled: no respawn -- restart mints a fresh address). "
        << (m_ephemeral_tor_service_id.empty()
              ? std::string{"No onion was published, so only tor-zone outbound is lost"}
              : m_ephemeral_tor_service_id + ".onion is now unreachable")
        << ". Originated transactions stay FAIL-CLOSED on the tor zone (never diverted to clearnet), so transaction"
           " sending from this node is broken until the daemon restarts (or restarts with --no-ephemeral-tor for clearnet-only)");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::check_incoming_connections()
  {
    if (m_offline)
      return true;

    const auto public_zone = m_network_zones.find(epee::net_utils::connector_id::clearnet);
    if (public_zone == m_network_zones.end())
      return true;

    // PWD-E1 tier 1, DIAGNOSTIC HALF ONLY. Report the STATE; the operator
    // draws the line, the daemon does not. A verdict ("probably unreachable")
    // would need a threshold, and that threshold is PWD-E8's, deferred on its
    // own measurement -- so stating the observation is what lets this land
    // without inventing one.
    //
    // Three operands, because no one of them is readable alone: a count with
    // no window does not distinguish "unreachable" from "just started", and
    // neither tells an operator whether the port they forwarded is the port
    // this node actually advertises. That last one is the whole of the
    // PWD-I7 incident's diagnosis, in a line.
    //
    // This does NOT stop advertising, classify, or infer anything about a
    // remote peer -- all three are the deferred action half.
    const size_t inbound_now = get_incoming_connections_count(public_zone->first);
    const uint32_t announced = get_announced_port(epee::net_utils::connector_id::clearnet);
    const auto uptime_min = std::chrono::duration_cast<std::chrono::minutes>(
        std::chrono::steady_clock::now() - m_started_at).count();
    MGINFO("p2p inbound state: " << inbound_now << " connection(s) held, over "
        << uptime_min << " min of uptime; advertising "
        << (announced ? "port " + std::to_string(announced) : std::string("NO port"))
        << ", listening on " << m_listening_port);

    if (inbound_now == 0)
    {
      if (public_zone->second.m_config.m_net_config.max_in_connection_count == 0)
      {
        MGINFO("Incoming connections disabled, enable them for full connectivity");
      }
      else
      {
        if (m_igd == delayed_igd)
        {
          MWARNING("No incoming connections, trying to setup IGD");
          add_upnp_port_mapping(m_listening_port);
          m_igd = igd;
        }
        else
        {
          const el::Level level = el::Level::Warning;
          MCLOG_RED(level, "global", "No incoming connections - check firewalls/routers allow port " << get_this_peer_port());
        }
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::peer_sync_idle_maker()
  {
    MDEBUG("STARTED PEERLIST IDLE HANDSHAKE");
    // The other `foreach_connection`. The callback runs on the connection
    // strand: it writes `m_in_timedsync` and starts the timed sync there.
    // Nothing after this call reads a list the posts have not filled.
    for(auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().foreach_connection([this](p2p_connection_context& cntxt)
      {
        if(cntxt.session_established() && !cntxt.m_in_timedsync)
        {
          cntxt.m_in_timedsync = true;
          do_peer_timed_sync(cntxt);
        }
        return true;
      });
    }

    MDEBUG("FINISHED PEERLIST IDLE HANDSHAKE");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::handle_remote_peerlist(const std::vector<peerlist_entry>& peerlist, const epee::net_utils::connection_context_base& context)
  {
    return shekyl::received_peerlist(context.m_connection_id, peerlist);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::get_local_node_data(const epee::net_utils::connector_id zone_type, basic_node_data& node_data, const network_zone& zone) const
  {
    node_data.network_id = m_network_id;
    node_data.support_flags = zone.m_config.m_support_flags;
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  int node_server<t_payload_net_handler>::handle_get_support_flags(int command, COMMAND_REQUEST_SUPPORT_FLAGS::request& arg, COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp, p2p_connection_context& context)
  {
    rsp.support_flags = m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector)).m_config.m_support_flags;
    return 1;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::request_callback(const epee::net_utils::connection_context_base& context)
  {
    m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector)).m_net_server.get_config_object().request_callback(context.m_connection_id);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::relay_notify_to_list(int command, epee::levin::message_writer data_buff, std::vector<std::pair<epee::net_utils::connector_id, boost::uuids::uuid>> connections)
  {
    epee::byte_slice message = data_buff.finalize_notify(command);
    epee::byte_slice compressed = epee::levin::try_compress_message(message.clone());
    const bool use_compressed = (compressed.size() < message.size());

    std::sort(connections.begin(), connections.end());
    auto zone = m_network_zones.begin();
    for(const auto& c_id: connections)
    {
      for (;;)
      {
        if (zone == m_network_zones.end())
        {
           MWARNING("Unable to relay all messages, " << epee::net_utils::connector_id_to_string(c_id.first) << " not available");
           return false;
        }
        if (c_id.first <= zone->first)
          break;

        ++zone;
      }
      if (zone->first == c_id.first)
      {
        const auto& msg = use_compressed ? compressed : message;
        zone->second.m_net_server.get_config_object().send(msg.clone(), c_id.second);
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  std::string node_server<t_payload_net_handler>::stem_tallies_json() const
  {
    /* §55 TRANSIT, NOT STRUCTURE. One relay publishes the rows. Each row
       carries the connector the stem was forwarded on. Serialisation lives
       in `format_stem_tally_row_json` so the unit table and this merge
       cannot disagree on the label.

       The endpoint remains AdminOnly. A connector label is strictly more
       disclosive than the flattened peer list.

       Disappears with the p2p migration. */
    using row_t = cryptonote::levin::notify::stem_tally_row;
    std::vector<row_t> rows = m_notifier.stem_snapshot();
    std::sort(rows.begin(), rows.end(),
      [](const auto& a, const auto& b) {
        return std::lexicographical_compare(
          std::begin(a.peer), std::end(a.peer),
          std::begin(b.peer), std::end(b.peer));
      });

    /* §18.4: the below-floor diagnostic joins this snapshot as a sibling
       key rather than a row — rows are per-peer, this is per-connector.
       "No data" connectors are omitted, never zero-filled. */
    std::string out = "{\"floor\":[";
    bool wrote_floor = false;
    for (const epee::net_utils::connector_id connector : epee::net_utils::all_connectors)
    {
      const std::uint8_t connector_byte = static_cast<std::uint8_t>(connector);
      std::uint32_t achieved = 0, floor = 0;
      bool below = false;
      if (!m_notifier.floor_snapshot(connector_byte, achieved, floor, below))
        continue;
      if (wrote_floor)
        out += ',';
      wrote_floor = true;
      out += "{\"connector\":\"";
      out += epee::net_utils::connector_id_to_string(connector);
      out += "\",\"achieved_out_connections\":";
      out += std::to_string(achieved);
      out += ",\"floor\":";
      out += std::to_string(floor);
      out += ",\"below\":";
      out += below ? "true" : "false";
      out += '}';
    }
    out += "],\"tallies\":[";
    for (std::size_t i = 0; i < rows.size(); ++i)
    {
      if (i)
        out += ',';
      out += cryptonote::levin::format_stem_tally_row_json(rows[i]);
    }
    out += "]}";
    return out;
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::record_tx_arrivals(std::vector<cryptonote::blobdata> txs, const boost::uuids::uuid& from)
  {
    /* §46: every zone's watch, not the receiving zone's alone — a stem placed
       on one zone can return through another, and only the zone holding the
       pending entry can resolve it. Parse to canonical hashes **once** (F-9
       join key) and fan the shared hash vector; re-parsing the same batch in
       each zone's strand was pure zone-count waste. */
    auto hashes = std::make_shared<const std::vector<crypto::hash>>(
      cryptonote::levin::stem_watch_tx_hashes(txs));
    if (hashes->empty())
      return;
    m_notifier.record_arrival(hashes, from);
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::send_txs(std::vector<cryptonote::blobdata> txs, const boost::uuids::uuid& source, const cryptonote::relay_method tx_relay)
  {
    /* One relay. Hop 0 is inside it, and a fluff reaches every session. */
    return m_notifier.send_txs(std::move(txs), source, tx_relay);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::callback(p2p_connection_context& context)
  {
    m_payload_handler.on_callback(context);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::on_outbound_handshake(p2p_connection_context& context, const shekyl_seam_handshake_result& result)
  {
    cryptonote::CORE_SYNC_DATA payload{};
    payload.current_height = result.current_height;
    payload.cumulative_difficulty = result.cumulative_difficulty;
    payload.cumulative_difficulty_top64 = result.cumulative_difficulty_top64;
    std::memcpy(payload.top_id.data, result.top_id, sizeof(payload.top_id.data));
    if(!m_payload_handler.process_payload_sync_data(payload, context, true))
      return false;
    if (result.keep == 0)
      return true;
    shekyl_zone_session_established(shekyl::seam_socket_id(context.m_connection_id));
    m_notifier.on_session_established(context.m_connection_id, context.m_is_income, context.m_connector);
    context.support_flags = result.support_flags;
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::invoke_notify_to_peer(const int command, epee::levin::message_writer message, const epee::net_utils::connection_context_base& context)
  {
    network_zone& zone = m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector));
    epee::byte_slice msg = message.finalize_notify(command);
    msg = epee::levin::try_compress_message(std::move(msg));
    int res = zone.m_net_server.get_config_object().send(std::move(msg), context.m_connection_id);
    return res > 0;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::drop_connection(const epee::net_utils::connection_context_base& context)
  {
    m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector)).m_net_server.get_config_object().close(context.m_connection_id);
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::try_get_support_flags(const p2p_connection_context& context, std::function<void(p2p_connection_context&, const uint32_t&)> f)
  {
    COMMAND_REQUEST_SUPPORT_FLAGS::request support_flags_request;
    bool r = epee::net_utils::async_invoke_remote_command2<typename COMMAND_REQUEST_SUPPORT_FLAGS::response>
    (
      context,
      COMMAND_REQUEST_SUPPORT_FLAGS::ID, 
      support_flags_request, 
      m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector)).m_net_server.get_config_object(),
      [=](int code, const typename COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp, p2p_connection_context& context_)
      {  
        if(code < 0)
        {
          LOG_WARNING_CC(context_, "COMMAND_REQUEST_SUPPORT_FLAGS invoke failed. (" << code <<  ", " << epee::levin::get_err_descr(code) << ")");
          return;
        }
        
        f(context_, rsp.support_flags);
      },
      std::chrono::milliseconds{P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT}
    );

    return r;
  }  
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  int node_server<t_payload_net_handler>::handle_timed_sync(int command, typename COMMAND_TIMED_SYNC::request& arg, typename COMMAND_TIMED_SYNC::response& rsp, p2p_connection_context& context)
  {
    if(!m_payload_handler.process_payload_sync_data(arg.payload_data, context, false))
    {
      LOG_WARNING_CC(context, "Failed to process_payload_sync_data(), dropping connection");
      drop_connection(context);
      return 1;
    }

    //fill response
    const epee::net_utils::connector_id zone_type = epee::net_utils::require_session_connector(context.m_connector);
    network_zone& zone = m_network_zones.at(zone_type);

    rsp.local_peerlist_new = shekyl::disclose(context.m_connection_id);
    m_payload_handler.get_payload_sync_data(rsp.payload_data);

    LOG_DEBUG_CC(context, "COMMAND_TIMED_SYNC");
    return 1;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  int node_server<t_payload_net_handler>::handle_handshake(int command, typename COMMAND_HANDSHAKE::request& arg, typename COMMAND_HANDSHAKE::response& rsp, p2p_connection_context& context)
  {
    if(arg.node_data.network_id != m_network_id)
    {

      LOG_INFO_CC(context, "WRONG NETWORK AGENT CONNECTED! id=" << arg.node_data.network_id);
      drop_connection(context);
      add_host_fail(context.m_remote_address);
      return 1;
    }

    if(!context.m_is_income)
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came not from incoming connection");
      drop_connection(context);
      add_host_fail(context.m_remote_address);
      return 1;
    }

    if(context.session_established())
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came on a connection that already completed one (double COMMAND_HANDSHAKE?)");
      drop_connection(context);
      return 1;
    }

    const auto azone = epee::net_utils::require_session_connector(context.m_connector);
    network_zone& zone = m_network_zones.at(azone);

    // Self-connection: the request carries a nonce; one that THIS node put
    // in flight on THIS zone means the dialer is us. Comparison is
    // within-zone only -- the inherited warning stands: testing another
    // zone's window would let a peer replay a nonce it was handed on one
    // zone into another zone's listener and read the drop as a cross-zone
    // correlation oracle. Erased on match, so a replayed nonce cannot fire
    // twice; a within-zone replay confirms only what within-zone
    // correlation already concedes.
    if(detect_self_handshake(azone, arg.nonce))
    {
      LOG_DEBUG_CC(context, "Connection to self detected (in-flight handshake nonce), dropping connection");
      drop_connection(context);
      return 1;
    }

    if(!m_payload_handler.process_payload_sync_data(arg.payload_data, context, true))
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came, but process_payload_sync_data returned false, dropping connection.");
      drop_connection(context);
      return 1;
    }

    m_notifier.on_session_established(context.m_connection_id, context.m_is_income, context.m_connector);
    {
      std::uint64_t socket_id = 0;
      std::memcpy(&socket_id, context.m_connection_id.data + 8, sizeof(socket_id));
      shekyl_zone_session_established(socket_id);
    }

    context.m_in_timedsync = false;
    context.support_flags = arg.node_data.support_flags;

    if (context.support_flags == 0)
      try_get_support_flags(context, [](p2p_connection_context& flags_context, const uint32_t& support_flags) 
      {
        flags_context.support_flags = support_flags;
      });

    //fill response
    rsp.local_peerlist_new = shekyl::disclose(context.m_connection_id);
    get_local_node_data(azone, rsp.node_data, zone);
    m_payload_handler.get_payload_sync_data(rsp.payload_data);
    LOG_DEBUG_CC(context, "COMMAND_HANDSHAKE");
    return 1;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::log_connections()
  {
    MINFO("Connections: \r\n" << print_connections_container() );
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  std::string node_server<t_payload_net_handler>::print_connections_container()
  {

    std::stringstream ss;
    const auto board = shekyl::seam_board_snapshot();
    for (const auto& row : board)
    {
      ss << shekyl::seam_network_address(row.endpoint).str()
        << " \t\tconn_id " << shekyl::seam_connection_id(row.id)
        << (row.endpoint.direction == SHEKYL_DIRECTION_INBOUND ? " INC":" OUT")
        << std::endl;
    }
    std::string s = ss.str();
    return s;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::on_connection_new(p2p_connection_context& context)
  {
    MINFO("["<< epee::net_utils::print_connection_context(context) << "] NEW CONNECTION");
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::on_connection_close(p2p_connection_context& context)
  {
    network_zone& zone = m_network_zones.at(epee::net_utils::require_session_connector(context.m_connector));
    if (!zone.m_net_server.is_stop_signal_sent()) {
      m_notifier.on_connection_close(context.m_connection_id);
    }
    m_payload_handler.on_connection_close(context);

    MINFO("["<< epee::net_utils::print_connection_context(context) << "] CLOSE CONNECTION");
  }



  template<class t_payload_net_handler> template <class Container>
  bool node_server<t_payload_net_handler>::parse_peers_and_add_to_container(const boost::program_options::variables_map& vm, const command_line::arg_descriptor<std::vector<std::string> > & arg, Container& container)
  {
    std::vector<std::string> perrs = command_line::get_arg(vm, arg);

    for(const std::string& pr_str: perrs)
    {
      const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
      expect<epee::net_utils::network_address> adr = net::get_network_address(pr_str, default_port);
      if (adr)
      {
        add_zone(epee::net_utils::require_address_connector(*adr));
        container.push_back(std::move(*adr));
        continue;
      }
      std::vector<epee::net_utils::network_address> resolved_addrs;
      bool r = append_net_address(resolved_addrs, pr_str, default_port);
      CHECK_AND_ASSERT_MES(r, false, "Failed to parse or resolve address from string: " << pr_str);
      for (const epee::net_utils::network_address& addr : resolved_addrs)
      {
        container.push_back(addr);
      }
    }

    return true;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::set_max_out_peers(network_zone& zone, int64_t max)
  {
    // -1 is unset: the dialer's compiled default for the connector. A
    // positive cap below the F-8b floor is refused there, with the reason
    // logged; 0 stays legal and stops outbound entirely.
    if(max == -1)
      return true;
    return shekyl_dialer_set_out_peers(static_cast<std::uint32_t>(&zone == &m_network_zones.at(epee::net_utils::connector_id::clearnet) ? epee::net_utils::connector_id::clearnet : epee::net_utils::connector_id::tor), static_cast<std::uint32_t>(max)) == 0;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::set_max_in_peers(network_zone& zone, int64_t max)
  {
    // Negative is unset. It is not stored: assigning it to `uint32_t` is the
    // narrowing that made an unset `--in-peers` into `UINT32_MAX`.
    if (max < 0)
    {
      zone.m_inbound_cap_explicit = false;
      zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
      return true;
    }
    zone.m_inbound_cap_explicit = true;
    if (static_cast<uint64_t>(max) > std::numeric_limits<uint32_t>::max())
    {
      MWARNING("Inbound cap " << max << " exceeds the admission counter; storing the counter's maximum.");
      zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
      return true;
    }
    zone.m_config.m_net_config.max_in_connection_count = static_cast<uint32_t>(max);
    return true;
  }

  template<class t_payload_net_handler>
  std::uint64_t node_server<t_payload_net_handler>::descriptor_reservations(std::uint64_t reserved_beyond_p2p) const
  {
    std::uint64_t reserved = reserved_beyond_p2p;
    const auto add = [&reserved](std::uint64_t n)
    {
      if (reserved > std::numeric_limits<std::uint64_t>::max() - n)
        reserved = std::numeric_limits<std::uint64_t>::max();
      else
        reserved += n;
    };
    // RESERVE WHAT CANNOT BE COUNTED; COUNT WHAT CAN.
    //
    // Outbound sockets are promised but not yet open, so the only way to
    // keep descriptors for them is to subtract them here.
    //
    // Inbound on a non-public zone is the opposite case and must NOT be
    // reserved: the Rust admission table already charges every connector's
    // inbound sockets against the ceiling as they are accepted. Reserving
    // them too would subtract the same descriptors twice -- an
    // `--anonymous-inbound` cap of N would cost the process N descriptors of
    // headroom AND still consume N as the connections arrived, squeezing
    // public inbound by 2N. Each zone with an explicit cap is bounded by the
    // Rust admission table; the ceiling bounds the pool they all draw from.
    for (const auto& entry : m_network_zones)
      add(shekyl_dialer_out_target(static_cast<std::uint32_t>(entry.first)));
    return reserved;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::apply_inbound_ceiling(std::uint64_t reserved_beyond_p2p)
  {
    const auto found = m_network_zones.find(epee::net_utils::connector_id::clearnet);
    if (found == m_network_zones.end())
      return true;
    network_zone& public_zone = found->second;

    m_reserved_beyond_p2p = reserved_beyond_p2p;
    const std::uint64_t reserved = descriptor_reservations(reserved_beyond_p2p);
    const std::uint64_t inbound_held = shekyl_seam_inbound_held();
    shekyl_inbound_ceiling decision{};
    shekyl_inbound_ceiling_resolve(reserved, inbound_held, &decision);

    for (const auto& entry : m_network_zones)
    {
      std::uint32_t connector = SHEKYL_CONNECTOR_CLEARNET;
      if (entry.first == epee::net_utils::connector_id::tor)
        connector = SHEKYL_CONNECTOR_TOR;
      else if (entry.first != epee::net_utils::connector_id::clearnet)
        continue;
      // The cap lives on the process socket table, which outlives this zone.
      // An unset `--in-peers` is no cap. Leaving a previous zone's cap would
      // keep refusing inbound after this zone replaced it.
      if (!entry.second.m_inbound_cap_explicit)
      {
        shekyl_zone_clear_connector_cap(connector);
        continue;
      }
      const std::uint32_t cap = entry.second.m_config.m_net_config.max_in_connection_count;
      if (decision.kind == SHEKYL_INBOUND_CEILING_BOUNDED && cap > decision.ceiling)
      {
        MERROR("Inbound cap " << cap << " for " << epee::net_utils::connector_id_to_string(entry.first)
            << " exceeds the descriptor ceiling " << decision.ceiling
            << "; refusing to start.");
        return false;
      }
      shekyl_zone_set_connector_cap(connector, cap);
    }

    const bool announce = decision.kind != m_applied_ceiling_kind
      || decision.ceiling != m_applied_ceiling_value;
    m_applied_ceiling_kind = decision.kind;
    m_applied_ceiling_value = decision.ceiling;
    if (public_zone.m_inbound_cap_explicit)
    {
      // The operator cap bounds this connector. The derived decision still
      // bounds the sum of every connector, in the Rust admission table.
      shekyl_seam_set_ceiling(&decision);
      shekyl_zone_set_ceiling(&decision);
      return true;
    }

    // Descriptors already spent on ACCEPTED inbound connections are excluded
    // from the observation above, because this ceiling is what measures them.
    // At startup the count is zero and it made no difference; a runtime
    // re-derive (an `out_peers` change) runs with peers connected, and
    // leaving them inside the observed count would subtract each one from the
    // headroom AND then compare it against the smaller result — the ceiling
    // would fall as the node filled, so a routine outbound change on a busy
    // node could start refusing every new peer.
    switch (decision.kind)
    {
      case SHEKYL_INBOUND_CEILING_BOUNDED:
        public_zone.m_config.m_net_config.max_in_connection_count = decision.ceiling;
        if (announce)
        {
          MGINFO("Inbound ceiling derived from the descriptor limit: " << decision.ceiling
                 << " (limit " << decision.soft_limit << ", " << decision.held
                 << " already held, " << reserved << " reserved)");
          if (decision.ceiling == 0)
            MWARNING("No descriptor headroom for inbound connections. Raise LimitNOFILE, "
                     "lower --out-peers, or lower --rpc-max-connections; this node will accept no inbound peers.");
        }
        break;
      case SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT:
        public_zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
        if (announce)
          MWARNING("This platform exposes no per-process descriptor limit, so the "
                   "inbound ceiling is unbounded. Set --in-peers explicitly to bound it.");
        break;
      case SHEKYL_INBOUND_CEILING_UNLIMITED:
        public_zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
        if (announce)
          MWARNING("RLIMIT_NOFILE is unlimited, so no descriptor ceiling can be derived. "
                   "Set --in-peers explicitly to bound inbound.");
        break;
      case SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE:
        public_zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
        if (announce)
          MWARNING("Cannot read this platform's descriptor limit, so the inbound ceiling "
                   "is unbounded. Set --in-peers explicitly to bound it.");
        break;
      case SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE:
        public_zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
        if (announce)
          MWARNING("Cannot count this process's open descriptors, so the inbound ceiling "
                   "is unbounded. Set --in-peers explicitly to bound it.");
        break;
      case SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER:
        public_zone.m_config.m_net_config.max_in_connection_count = std::numeric_limits<uint32_t>::max();
        if (announce)
          MWARNING("Descriptor headroom does not fit the inbound counter, so a derived "
                   "ceiling would never fire. Set --in-peers explicitly to bound it.");
        break;
      default:
        public_zone.m_config.m_net_config.max_in_connection_count = 0;
        if (announce)
          MERROR("Unrecognized inbound ceiling kind " << decision.kind << "; refusing inbound.");
        break;
    }
    shekyl_seam_set_ceiling(&decision);
    shekyl_zone_set_ceiling(&decision);
    return true;
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::change_max_out_public_peers(size_t count)
  {
    // The runtime path (`out_peers` console command / RPC). The dialer
    // refuses a positive cap below the F-8b floor and logs why; the cap is
    // then unchanged. Lowering it closes the excess kept sessions there.
    const std::uint32_t previous = shekyl_dialer_out_target(SHEKYL_CONNECTOR_CLEARNET);
    if (shekyl_dialer_set_out_peers(SHEKYL_CONNECTOR_CLEARNET, static_cast<std::uint32_t>(count)) != 0)
      return;
    m_payload_handler.set_max_out_peers(epee::net_utils::connector_id::clearnet, count);
    // The outbound cap is a term in the inbound ceiling's reservation, so
    // changing it at runtime invalidates a ceiling derived against the old
    // one. Raising `out_peers` without this leaves inbound reserved against
    // a smaller outbound budget, and live outbound plus inbound can then
    // exceed the descriptor limit -- the exact exhaustion the ceiling
    // exists to prevent. Re-derives against the same non-p2p reservation
    // the last call used, so a caller that never knew the RPC budget does
    // not have to learn it. A cap the new ceiling cannot hold is refused
    // and the previous outbound cap is put back; lowering the cap is the
    // path that drops live connections, and that path widens the ceiling.
    if (!apply_inbound_ceiling(m_reserved_beyond_p2p))
    {
      shekyl_dialer_set_out_peers(SHEKYL_CONNECTOR_CLEARNET, previous);
      m_payload_handler.set_max_out_peers(epee::net_utils::connector_id::clearnet, previous);
      apply_inbound_ceiling(m_reserved_beyond_p2p);
    }
  }


  template<class t_payload_net_handler>
  epee::net_utils::network_address node_server<t_payload_net_handler>::get_announced_address(const epee::net_utils::connector_id zone) const
  {
    /* This node's own dialable address on this zone, or the zone's
       undialable placeholder when it is not reachable there. No handshake
       carries it (ruled 2026-10-09): it reaches peers only as one uniform
       member of this node's disclosure sample.
       On an anonymity zone run dialer-only this is the zone's CONSTANT
       unknown sentinel — equal for every node, carrying no entropy and
       linking nothing, which is the property the deleted per-zone
       `peer_id` sentinel existed to pin. */
    const auto found = m_network_zones.find(zone);
    if (found == m_network_zones.end())
      return {};
    // Announce only where a peer could actually reach us. There is no
    // dedicated advertisement flag; operator influence is the supported,
    // derived kind: `--in-peers 0` sets `max_in_connection_count` to zero
    // and thereby suppresses the announcement -- the decision follows from
    // the node's reachability, and an operator changes it by changing that
    // reachability, not by asserting a different answer.
    // `m_can_announce` is the PUBLIC zone's reachability flag (it is what the
    // deleted back-ping's pingback capability became). An anonymity zone's
    // reachability is its configured self-address instead: a serving zone has
    // one because `--anonymous-inbound` gave it one, so gating it on the
    // public flag would silently announce the unknown sentinel from a node
    // that is in fact reachable.
    const bool zone_is_reachable = (zone == epee::net_utils::connector_id::clearnet)
      ? found->second.m_can_announce
      : (found->second.m_our_address.get_type_id() != epee::net_utils::address_type::invalid);
    if (zone_is_reachable && found->second.m_config.m_net_config.max_in_connection_count > 0)
    {
      if (zone == epee::net_utils::connector_id::clearnet)
      {
        // The port this node listens on, with the host half zeroed: this
        // node does not know the host its peers see it at.
        const uint32_t port = m_external_port ? m_external_port : m_listening_port;
        return epee::net_utils::network_address{epee::net_utils::ipv4_network_address(0, port)};
      }
      else
        return found->second.m_our_address;
    }
    else
    {
      // Dialer-only on this zone: announce the zone's unknown-address
      // sentinel. Undialable, and never recorded by any receiver.
      switch (zone)
      {
        case epee::net_utils::connector_id::tor:
          return net::tor_address::unknown();
        default:
          return epee::net_utils::network_address{epee::net_utils::ipv4_network_address(0, 0)};
      }
    }
  }

  template<class t_payload_net_handler>
  uint32_t node_server<t_payload_net_handler>::get_announced_port(const epee::net_utils::connector_id zone) const
  {
    /* The port of `get_announced_address` for this zone.
       Named so the derived advertisement has something a test can observe:
       the decision has no dedicated flag any more, so there is nothing to
       assert on but the announced value itself. */
    const auto found = m_network_zones.find(zone);
    if (found == m_network_zones.end())
      return 0;
    return get_announced_address(zone).port();
  }

  template<class t_payload_net_handler>
  uint32_t node_server<t_payload_net_handler>::get_max_out_public_peers() const
  {
    return shekyl_dialer_out_target(SHEKYL_CONNECTOR_CLEARNET);
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::change_max_in_public_peers(size_t count)
  {
    auto public_zone = m_network_zones.find(epee::net_utils::connector_id::clearnet);
    if (public_zone != m_network_zones.end())
    {
      const uint32_t cap = count > std::numeric_limits<uint32_t>::max()
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(count);
      if (m_applied_ceiling_kind == SHEKYL_INBOUND_CEILING_BOUNDED && cap > m_applied_ceiling_value)
      {
        MERROR("Inbound cap " << cap << " exceeds the descriptor ceiling "
            << m_applied_ceiling_value << "; leaving the previous cap.");
        return;
      }
      // A runtime change is an explicit cap for this connector. The
      // descriptor ceiling still bounds the sum. A cap the descriptors
      // cannot hold was refused above, and the previous cap stays.
      public_zone->second.m_inbound_cap_explicit = true;
      shekyl_zone_set_connector_cap(SHEKYL_CONNECTOR_CLEARNET, cap);
      const auto current = public_zone->second.m_net_server.get_config_object().get_in_connections_count();
      public_zone->second.m_config.m_net_config.max_in_connection_count = cap;
      if(current > cap)
        public_zone->second.m_net_server.get_config_object().del_in_connections(current - cap);
    }
  }

  template<class t_payload_net_handler>
  uint32_t node_server<t_payload_net_handler>::get_max_in_public_peers() const
  {
    const auto public_zone = m_network_zones.find(epee::net_utils::connector_id::clearnet);
    if (public_zone == m_network_zones.end())
      return 0;
    return public_zone->second.m_config.m_net_config.max_in_connection_count;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::set_tos_flag(const boost::program_options::variables_map& vm, int flag)
  {
    (void)vm;
    if (flag == -1)
      return true;
    MERROR("--tos-flag is not offered");
    return false;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::set_rate_up_limit(const boost::program_options::variables_map& vm, int64_t limit)
  {
    if (limit == 0 || limit < -1)
    {
      MERROR("--limit-rate-up " << limit << " is not a rate. Use -1 for unlimited.");
      return false;
    }
    this->islimitup = limit >= 0;
    shekyl_link_set_up(limit);
    if (limit < 0)
      MINFO("Set limit-up to unlimited");
    else
      MINFO("Set limit-up to " << limit << " KiB/s");
    return true;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::set_rate_down_limit(const boost::program_options::variables_map& vm, int64_t limit)
  {
    if (limit == 0 || limit < -1)
    {
      MERROR("--limit-rate-down " << limit << " is not a rate. Use -1 for unlimited.");
      return false;
    }
    this->islimitdown = limit >= 0;
    shekyl_link_set_down(limit);
    if (limit < 0)
      MINFO("Set limit-down to unlimited");
    else
      MINFO("Set limit-down to " << limit << " KiB/s");
    return true;
  }

  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::set_rate_limit(const boost::program_options::variables_map& vm, int64_t limit)
  {
    // Applies only to a direction the operator did not set on its own.
    // -1 is unlimited. Zero is not a rate.
    if (limit == 0 || limit < -1)
    {
      MERROR("--limit-rate " << limit << " is not a rate. Use -1 for unlimited.");
      return false;
    }
    if(!this->islimitup)
      set_rate_up_limit(vm, limit);
    if(!this->islimitdown)
      set_rate_down_limit(vm, limit);
    return true;
  }


  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::add_upnp_port_mapping_impl(uint32_t port, bool ipv6) // if ipv6 false, do ipv4
  {
    std::string ipversion = ipv6 ? "(IPv6)" : "(IPv4)";
    MDEBUG("Attempting to add IGD port mapping " << ipversion << ".");
    int result;
    const int ipv6_arg = ipv6 ? 1 : 0;

#if MINIUPNPC_API_VERSION > 13
    // default according to miniupnpc.h
    unsigned char ttl = 2;
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, ttl, &result);
#else
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, &result);
#endif
    UPNPUrls urls;
    IGDdatas igdData;
    char lanAddress[64];
    result = UPNP_GetValidIGD(deviceList, &urls, &igdData, lanAddress, sizeof lanAddress);
    freeUPNPDevlist(deviceList);
    if (result > 0) {
      if (result == 1) {
        std::ostringstream portString;
        portString << port;

        // Delete the port mapping before we create it, just in case we have dangling port mapping from the daemon not being shut down correctly
        UPNP_DeletePortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(), "TCP", 0);

        int portMappingResult;
        portMappingResult = UPNP_AddPortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(), portString.str().c_str(), lanAddress, CRYPTONOTE_NAME, "TCP", 0, "0");
        if (portMappingResult != 0) {
          LOG_ERROR("UPNP_AddPortMapping failed, error: " << strupnperror(portMappingResult));
        } else {
          MLOG_GREEN(el::Level::Info, "Added IGD port mapping.");
        }
      } else if (result == 2) {
        MWARNING("IGD was found but reported as not connected.");
      } else if (result == 3) {
        MWARNING("UPnP device was found but not recognized as IGD.");
      } else {
        MWARNING("UPNP_GetValidIGD returned an unknown result code.");
      }

      FreeUPNPUrls(&urls);
    } else {
      MINFO("No IGD was found.");
    }
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::add_upnp_port_mapping_v4(uint32_t port)
  {
    add_upnp_port_mapping_impl(port, false);
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::add_upnp_port_mapping_v6(uint32_t port)
  {
    add_upnp_port_mapping_impl(port, true);
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::add_upnp_port_mapping(uint32_t port, bool ipv4, bool ipv6)
  {
    if (ipv4) add_upnp_port_mapping_v4(port);
    if (ipv6) add_upnp_port_mapping_v6(port);
  }


  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::delete_upnp_port_mapping_impl(uint32_t port, bool ipv6)
  {
    std::string ipversion = ipv6 ? "(IPv6)" : "(IPv4)";
    MDEBUG("Attempting to delete IGD port mapping " << ipversion << ".");
    int result;
    const int ipv6_arg = ipv6 ? 1 : 0;
#if MINIUPNPC_API_VERSION > 13
    // default according to miniupnpc.h
    unsigned char ttl = 2;
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, ttl, &result);
#else
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, &result);
#endif
    UPNPUrls urls;
    IGDdatas igdData;
    char lanAddress[64];
    result = UPNP_GetValidIGD(deviceList, &urls, &igdData, lanAddress, sizeof lanAddress);
    freeUPNPDevlist(deviceList);
    if (result > 0) {
      if (result == 1) {
        std::ostringstream portString;
        portString << port;

        int portMappingResult;
        portMappingResult = UPNP_DeletePortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(), "TCP", 0);
        if (portMappingResult != 0) {
          LOG_ERROR("UPNP_DeletePortMapping failed, error: " << strupnperror(portMappingResult));
        } else {
          MLOG_GREEN(el::Level::Info, "Deleted IGD port mapping.");
        }
      } else if (result == 2) {
        MWARNING("IGD was found but reported as not connected.");
      } else if (result == 3) {
        MWARNING("UPnP device was found but not recognized as IGD.");
      } else {
        MWARNING("UPNP_GetValidIGD returned an unknown result code.");
      }

      FreeUPNPUrls(&urls);
    } else {
      MINFO("No IGD was found.");
    }
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::delete_upnp_port_mapping_v4(uint32_t port)
  {
    delete_upnp_port_mapping_impl(port, false);
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::delete_upnp_port_mapping_v6(uint32_t port)
  {
    delete_upnp_port_mapping_impl(port, true);
  }

  template<class t_payload_net_handler>
  void node_server<t_payload_net_handler>::delete_upnp_port_mapping(uint32_t port)
  {
    delete_upnp_port_mapping_v4(port);
    delete_upnp_port_mapping_v6(port);
  }

  template<class t_payload_net_handler>
  shekyl_inbound_ceiling node_server<t_payload_net_handler>::transport_ceiling() const
  {
    shekyl_inbound_ceiling ceiling{};
    const std::uint64_t reserved = descriptor_reservations(m_reserved_beyond_p2p);
    shekyl_inbound_ceiling_resolve(reserved, 0, &ceiling);
    return ceiling;
  }

}

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
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::init_config()
  {
    TRY_ENTRY();
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
  bool node_server<t_payload_net_handler>::init(const ShekylDaemonSnapshot& snapshot)
  {
    // What this object reads from the snapshot (DAEMON_CONFIG_CUTOVER.md
    // §2.9): the network, offline, and the sync lever. The connectors, the
    // peers, the bans, the link bounds and the relay's posture are the Rust
    // owners' (§3), read from their sections.
    m_nettype = static_cast<cryptonote::network_type>(snapshot.network);
    (void)m_network_zones[epee::net_utils::connector_id::clearnet];
    m_offline = snapshot.offline;
    if (!snapshot.sync)
      m_payload_handler.set_no_sync(true);
    bool res = true;

    {
      const auto id = cryptonote::get_config(m_nettype).NETWORK_ID;
      memcpy(&m_network_id, &id, 16);
    }

    // Both zones exist whatever the posture: the Rust zone host decides
    // which connectors carry traffic, from its sections, and starts them
    // after this init has bound the seam (DAEMON_CONFIG_CUTOVER.md §2.2
    // step 8). This object is the levin side of each connector.
    network_zone& public_zone = m_network_zones.at(epee::net_utils::connector_id::clearnet);
    add_zone(epee::net_utils::connector_id::tor);

    res = init_config();
    CHECK_AND_ASSERT_MES(res, false, "Failed to init config.");

    public_zone.m_net_server.set_threads_prefix("P2P"); // all zones use these threads/asio::io_service

    // from here onwards, it's online stuff
    if (m_offline)
      return res;

    for (auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().set_handler(this);
      zone.second.m_net_server.get_config_object().m_invoke_timeout = std::chrono::milliseconds{P2P_DEFAULT_INVOKE_TIMEOUT};
      const std::uint32_t connector = zone.first == epee::net_utils::connector_id::tor ? SHEKYL_CONNECTOR_TOR : SHEKYL_CONNECTOR_CLEARNET;
      CHECK_AND_ASSERT_MES(zone.second.m_net_server.bind(connector), false, "Failed to bind the seam");
    }

    /* One relay, after every connector zone exists. Its identity (which
       connectors are configured) is the posture the Rust main() recorded. */
    {
      std::vector<cryptonote::levin::connector_registry> registries;
      for (auto& zone : m_network_zones)
      {
        const std::uint8_t connector = cryptonote::levin::notify::connector_byte(zone.first);
        registries.push_back(cryptonote::levin::connector_registry{
          connector, zone.second.m_net_server.get_config_shared()});
      }
      // `pad-transactions` is the relay lane's (INPUT_GRAMMAR.md §5, IG-Q4):
      // today's default, off, until that lane decides.
      const bool pad_txs = false;
      m_notifier = cryptonote::levin::notify{
        public_zone.m_net_server.get_io_context(),
        std::move(registries),
        pad_txs,
        m_payload_handler.get_core()
      };
    }
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

    if (!m_offline)
    {
      for(auto& zone : m_network_zones)
        zone.second.m_net_server.deinit_server();
    }
    return true;
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
    const auto uptime_min = std::chrono::duration_cast<std::chrono::minutes>(
        std::chrono::steady_clock::now() - m_started_at).count();
    MGINFO("p2p inbound state: " << inbound_now << " connection(s) held, over "
        << uptime_min << " min of uptime; the listen endpoints and the advertised"
           " address are the configuration's (clearnet-listen, clearnet-advertise)");

    if (inbound_now == 0)
    {
      const el::Level level = el::Level::Warning;
      MCLOG_RED(level, "global", "No incoming connections - check firewalls/routers allow the clearnet-listen endpoints");
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
  void node_server<t_payload_net_handler>::on_outbound_handshake(p2p_connection_context& context, const shekyl_seam_handshake_result& result)
  {
    cryptonote::CORE_SYNC_DATA payload{};
    payload.current_height = result.current_height;
    payload.cumulative_difficulty = result.cumulative_difficulty;
    payload.cumulative_difficulty_top64 = result.cumulative_difficulty_top64;
    std::memcpy(payload.top_id.data, result.top_id, sizeof(payload.top_id.data));
    m_payload_handler.process_payload_sync_data(payload, context, true);
    m_notifier.on_session_established(context.m_connection_id, context.m_is_income, context.m_connector);
    context.support_flags = result.support_flags;
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



























}

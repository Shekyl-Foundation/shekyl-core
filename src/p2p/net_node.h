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

// TODO(shekyl-v4): Migrate boost::posix_time and boost::thread types to
// std::chrono and std::thread. This header defines the P2P node; time-type
// changes cascade into connection_context and block_queue.
#pragma once
#include <array>
#include <atomic>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/thread.hpp>
#include <optional>
#include <boost/uuid/uuid.hpp>
#include <chrono>
#include <functional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_protocol/fwd.h"
#include "cryptonote_protocol/levin_notify.h"
#include "warnings.h"
#include "net/levin_protocol_handler.h"
#include "net/levin_protocol_handler_async.h"
#include "p2p_protocol_defs.h"
#include "storages/levin_abstract_invoke2.h"
#include "math_helper.h"
#include "net_node_common.h"
#include "net/enums.h"
#include "net/parse.h"
#include "common/command_line.h"
#include "shekyl/shekyl_ffi.h"
#include "p2p/zone_server.h"

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

namespace nodetool
{

  // There is no announced node identifier of any kind. The eclipse-oracle
  // doctrine that once pinned the anon-zone `peer_id` sentinel is preserved
  // as the rationale for the field's ABSENCE at `basic_node_data`
  // (`p2p_protocol_defs.h`): the handshake announces WHERE, never WHO.

  template<class base_type>
  struct p2p_connection_context_t: base_type //t_payload_net_handler::connection_context //public net_utils::connection_context_base
  {
    p2p_connection_context_t()
      : support_flags(0),
        m_in_timedsync(false)
    {}

    p2p_connection_context_t(boost::uuids::uuid connection_id, const epee::net_utils::network_address& remote_address, bool is_income, std::uint8_t connector = 0xff)
      : base_type(connection_id, remote_address, is_income, connector),
        support_flags(0),
        m_in_timedsync(false)
    {}

    uint32_t support_flags;
    bool m_in_timedsync;
    std::set<epee::net_utils::network_address> sent_addresses;
  };

  template<class t_payload_net_handler>
  class node_server: public epee::levin::levin_commands_handler<p2p_connection_context_t<typename t_payload_net_handler::connection_context> >,
                     public i_p2p_endpoint<typename t_payload_net_handler::connection_context>
  {
    struct by_conn_id{};
    struct by_addr{};

    typedef p2p_connection_context_t<typename t_payload_net_handler::connection_context> p2p_connection_context;

    typedef COMMAND_HANDSHAKE_T<typename t_payload_net_handler::payload_type> COMMAND_HANDSHAKE;
    typedef COMMAND_TIMED_SYNC_T<typename t_payload_net_handler::payload_type> COMMAND_TIMED_SYNC;
    static_assert(p2p_connection_context::handshake_command() == COMMAND_HANDSHAKE::ID, "invalid handshake command id");

    typedef shekyl::zone_server<epee::levin::async_protocol_handler<p2p_connection_context>> net_server;

    struct network_zone;
    struct config_t
    {
      config_t()
        : m_net_config(),
          m_support_flags(0)
      {}

      network_config m_net_config;
      uint32_t m_support_flags;
    };
    typedef epee::misc_utils::struct_init<config_t> config;

    struct network_zone
    {
      network_zone() : m_net_server(),
          m_config{}
      {
        set_config_defaults();
      }

      network_zone(boost::asio::io_context& public_service) : m_net_server(public_service),
          m_config{}
      {
        set_config_defaults();
      }

      net_server m_net_server;
      config m_config;

    private:
      void set_config_defaults() noexcept
      {
        // at this moment we have a hardcoded config
        m_config.m_net_config.handshake_interval = P2P_DEFAULT_HANDSHAKE_INTERVAL;
        m_config.m_net_config.packet_max_size = P2P_DEFAULT_PACKET_MAX_SIZE;
        m_config.m_net_config.config_id = 0;
        m_config.m_net_config.connection_timeout = P2P_DEFAULT_CONNECTION_TIMEOUT;
        m_config.m_net_config.ping_connection_timeout = std::chrono::milliseconds{P2P_DEFAULT_PING_CONNECTION_TIMEOUT};
        m_config.m_support_flags = 0; // only set in public zone
      }
    };


  public:
    //! §55: stem-outcome tallies across every zone, as one JSON array.
    //! Transit for a Rust->Rust readout -- see net_node.inl.
    std::string stem_tallies_json() const;
    typedef t_payload_net_handler payload_net_handler;

    node_server(t_payload_net_handler& payload_handler)
      : m_payload_handler(payload_handler),
        m_offline(false),
        m_network_id(),
        m_started_at(std::chrono::steady_clock::now())
    {}
    virtual ~node_server();


    bool run();
    network_zone& add_zone(epee::net_utils::connector_id zone);
    bool init(const ShekylDaemonSnapshot& snapshot);
    bool deinit();
    bool send_stop_signal();
    t_payload_net_handler& get_payload_object();

    // debug functions
    bool log_connections();


    //! True when `address` is banned with no deadline.
    bool host_ban_is_permanent(const epee::net_utils::network_address &address) const;
    //! Bans still in force. `permanent` is 1 when the row has no deadline.
    std::vector<shekyl_ban_view> ban_list();
    //! \return True exactly once per recorded nonce, and only on the zone it
    //! was recorded for: an arriving handshake carrying such a nonce IS this
    //! node. Erases on match, so a replayed nonce cannot fire twice; a
    //! cross-zone probe never matches — the drop would otherwise be a
    //! cross-zone correlation oracle.
    bool detect_self_handshake(epee::net_utils::connector_id zone, const std::array<uint8_t, 32>& nonce);

    virtual bool block_host(epee::net_utils::network_address address, time_t seconds = P2P_IP_BLOCKTIME, bool add_only = false);
    virtual bool unblock_host(const epee::net_utils::network_address &address);
    virtual bool block_subnet(const epee::net_utils::ipv4_network_subnet &subnet, time_t seconds = P2P_IP_BLOCKTIME);
    virtual bool unblock_subnet(const epee::net_utils::ipv4_network_subnet &subnet);
    bool block_host_permanent(epee::net_utils::network_address address);
    bool block_subnet_permanent(const epee::net_utils::ipv4_network_subnet &subnet);
    virtual bool is_host_blocked(const epee::net_utils::network_address &address, time_t *seconds);
    //! Host to seconds remaining on the monotonic deadline.
    virtual std::map<std::string, time_t> get_blocked_hosts();
    //! Subnet to seconds remaining on the monotonic deadline.
    virtual std::map<epee::net_utils::ipv4_network_subnet, time_t> get_blocked_subnets();

  private:

    CHAIN_LEVIN_INVOKE_MAP2(p2p_connection_context); //move levin_commands_handler interface invoke(...) callbacks into invoke map
    CHAIN_LEVIN_NOTIFY_MAP2(p2p_connection_context); //move levin_commands_handler interface notify(...) callbacks into nothing

    BEGIN_INVOKE_MAP2(node_server)
      // Which commands a session may carry is `DefinedCommand` in
      // rust/shekyl-levin/src/ingress.rs — one table, every connector.
      // The C++ allowlist that sat here kept only HANDSHAKE, TIMED_SYNC
      // and NOTIFY_NEW_TRANSACTIONS on a non-clearnet address. D-5
      // (2026-10-02): the receiver handshaked, learned height 87, and
      // stayed at 1 because support-flags came back empty and the chain
      // request never left.
      HANDLE_INVOKE_T2(COMMAND_HANDSHAKE, &node_server::handle_handshake)
      HANDLE_INVOKE_T2(COMMAND_TIMED_SYNC, &node_server::handle_timed_sync)
      HANDLE_INVOKE_T2(COMMAND_REQUEST_SUPPORT_FLAGS, &node_server::handle_get_support_flags)
      CHAIN_INVOKE_MAP_TO_OBJ_FORCE_CONTEXT(m_payload_handler, typename t_payload_net_handler::connection_context&)
    END_INVOKE_MAP2()

    //----------------- commands handlers ----------------------------------------------
    int handle_handshake(int command, typename COMMAND_HANDSHAKE::request& arg, typename COMMAND_HANDSHAKE::response& rsp, p2p_connection_context& context);
    int handle_timed_sync(int command, typename COMMAND_TIMED_SYNC::request& arg, typename COMMAND_TIMED_SYNC::response& rsp, p2p_connection_context& context);
    int handle_get_support_flags(int command, COMMAND_REQUEST_SUPPORT_FLAGS::request& arg, COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp, p2p_connection_context& context);
    bool init_config();
    bool make_default_config();


    //----------------- levin_commands_handler -------------------------------------------------------------
    virtual void on_connection_new(p2p_connection_context& context);
    virtual void on_connection_close(p2p_connection_context& context);
    virtual void callback(p2p_connection_context& context);
    bool on_outbound_handshake(p2p_connection_context& context, const shekyl_seam_handshake_result& result) override;
    //----------------- i_p2p_endpoint -------------------------------------------------------------
    virtual bool relay_notify_to_list(int command, epee::levin::message_writer message, std::vector<std::pair<epee::net_utils::connector_id, boost::uuids::uuid>> connections) final;
    virtual bool send_txs(std::vector<cryptonote::blobdata> txs, const boost::uuids::uuid& source, cryptonote::relay_method tx_relay);
    virtual void record_tx_arrivals(std::vector<cryptonote::blobdata> txs, const boost::uuids::uuid& from);
    virtual bool invoke_notify_to_peer(int command, epee::levin::message_writer message, const epee::net_utils::connection_context_base& context) final;
    virtual bool drop_connection(const epee::net_utils::connection_context_base& context);
    virtual void request_callback(const epee::net_utils::connection_context_base& context);
    virtual size_t post_each(std::function<void(typename t_payload_net_handler::connection_context&, uint32_t)> note, std::function<void()> then);
    virtual bool for_connection(const boost::uuids::uuid&, std::function<void(typename t_payload_net_handler::connection_context&, uint32_t)> f);
    virtual bool add_host_fail(const epee::net_utils::network_address &address, unsigned int score = 1);
    bool is_remote_host_allowed(const epee::net_utils::network_address &address, time_t *t = NULL);

    bool parse_peer_from_string(epee::net_utils::network_address& pe, const std::string& node_addr, uint16_t default_port = 0);
    bool idle_worker();
    bool handle_remote_peerlist(const std::vector<peerlist_entry>& peerlist, const epee::net_utils::connection_context_base& context);
    bool get_local_node_data(epee::net_utils::connector_id zone_type, basic_node_data& node_data, const network_zone& zone) const;
    //bool get_local_handshake_data(handshake_data& hshd);

    bool peer_sync_idle_maker();
    bool do_peer_timed_sync(const epee::net_utils::connection_context_base& context);

    bool try_get_support_flags(const p2p_connection_context& context, std::function<void(p2p_connection_context&, const uint32_t&)> f);

    size_t get_incoming_connections_count();
    size_t get_incoming_connections_count(epee::net_utils::connector_id connector);
    size_t get_outgoing_connections_count();
    size_t get_outgoing_connections_count(epee::net_utils::connector_id connector);

    bool check_incoming_connections();

    void kill() { ///< will be called e.g. from deinit()
      _info("Killing the net_node");
    }

    //debug functions
    std::string print_connections_container();


  public:

  private:

    bool m_offline;
    //critical_section m_connections_lock;
    //connections_indexed_container m_connections;

    //! One relay. Connection registries stay on each connector.
    cryptonote::levin::notify m_notifier;
    t_payload_net_handler& m_payload_handler;

    epee::math_helper::once_a_time_seconds<P2P_DEFAULT_HANDSHAKE_INTERVAL> m_peer_handshake_idle_maker_interval;
    epee::math_helper::once_a_time_seconds<3600, false> m_incoming_connections_interval;





    /* A `std::map` provides constant iterators and key/value pointers even with
    inserts/erases to _other_ elements. This makes the configuration step easier
    since references can safely be stored on the stack. Do not insert/erase
    after configuration and before destruction, lock safety would need to be
    added. `std::map::operator[]` WILL insert! */
    std::map<epee::net_utils::connector_id, network_zone> m_network_zones;


    epee::critical_section m_host_fails_score_lock;
    std::map<std::string, uint64_t> m_host_fails_score;


    boost::uuids::uuid m_network_id;

    //! Process start, for the E1 tier-1 diagnostic in `check_incoming_connections`.
    //! An inbound count is unreadable without the window it was observed over:
    //! zero inbound after 40 seconds says nothing, zero after six hours does.
    std::chrono::steady_clock::time_point m_started_at;
    cryptonote::network_type m_nettype;
  };



}

POP_WARNINGS


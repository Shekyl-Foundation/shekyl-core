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
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
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
  struct proxy
  {
    // There is deliberately no covert/"noise" flag here. The configuration-B
    // deletion removed the channel from configuration entirely; the rationale
    // lives at the `disable_noise` compatibility shim in net_node.cpp and in
    // docs/design/DAEMON_RELAY_PRIVACY.md §§25, 29-31, 41.
    proxy()
      : max_connections(-1),
        address(),
        zone(epee::net_utils::connector_id::tor)
    {}

    std::int64_t max_connections;
    net::socks::endpoint address;
    epee::net_utils::connector_id zone;
  };

  struct anonymous_inbound
  {
    anonymous_inbound()
      : max_connections(-1),
        local_ip(),
        local_port(),
        our_address(),
        default_remote()
    {}

    std::int64_t max_connections;
    std::string local_ip;
    std::string local_port;
    epee::net_utils::network_address our_address;
    epee::net_utils::network_address default_remote;
  };

  std::optional<std::vector<proxy>> get_proxies(const boost::program_options::variables_map& vm);
  std::optional<std::vector<anonymous_inbound>> get_anonymous_inbounds(const boost::program_options::variables_map& vm);

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
      network_zone()
        : m_outbound(false),
          m_net_server(),
          m_seed_nodes(),
          m_bind_ip(),
          m_bind_ipv6_address(),
          m_port(),
          m_port_ipv6(),
          m_our_address(),
          m_config{},
          m_proxy_address(),
          m_can_announce(false)
      {
        set_config_defaults();
      }

      network_zone(boost::asio::io_context& public_service)
        : m_outbound(false),
          m_net_server(public_service),
          m_seed_nodes(),
          m_bind_ip(),
          m_bind_ipv6_address(),
          m_port(),
          m_port_ipv6(),
          m_our_address(),
          m_config{},
          m_proxy_address(),
          m_can_announce(false)
      {
        set_config_defaults();
      }

      //! This zone dials out: the clearnet zone, a `--tx-proxy` zone, or the
      //! zone the managed Tor supplies SOCKS for. The dial itself is Rust's.
      bool m_outbound;
      net_server m_net_server;
      std::vector<epee::net_utils::network_address> m_seed_nodes;
      std::string m_bind_ip;
      std::string m_bind_ipv6_address;
      std::string m_port;
      std::string m_port_ipv6;
      epee::net_utils::network_address m_our_address; // in anonymity networks
      config m_config;
      net::socks::endpoint m_proxy_address;
      // This zone may announce an inbound endpoint (public port-only advert
      // or the zone's self-address). Renamed from m_can_pingback: the
      // back-ping that once verified announcements is deleted (PWD-B10);
      // the flag's surviving job is the announcement itself.
      bool m_can_announce;
      //! True when an operator set this zone's inbound cap, including zero.
      //! False leaves public inbound to `apply_inbound_ceiling` and leaves
      //! an anonymity zone with no zone cap of its own.
      bool m_inbound_cap_explicit = false;

    private:
      void set_config_defaults() noexcept
      {
        // at this moment we have a hardcoded config
        m_config.m_net_config.handshake_interval = P2P_DEFAULT_HANDSHAKE_INTERVAL;
        m_config.m_net_config.packet_max_size = P2P_DEFAULT_PACKET_MAX_SIZE;
        m_config.m_net_config.config_id = 0;
        m_config.m_net_config.connection_timeout = P2P_DEFAULT_CONNECTION_TIMEOUT;
        m_config.m_net_config.ping_connection_timeout = std::chrono::milliseconds{P2P_DEFAULT_PING_CONNECTION_TIMEOUT};
        m_config.m_net_config.send_peerlist_sz = P2P_DEFAULT_PEERS_IN_HANDSHAKE;
        m_config.m_support_flags = 0; // only set in public zone
      }
    };

    enum igd_t
    {
      no_igd,
      igd,
      delayed_igd,
    };

  public:
    //! §55: stem-outcome tallies across every zone, as one JSON array.
    //! Transit for a Rust->Rust readout -- see net_node.inl.
    std::string stem_tallies_json() const;
    typedef t_payload_net_handler payload_net_handler;

    node_server(t_payload_net_handler& payload_handler)
      : m_payload_handler(payload_handler),
        m_listening_port(0),
        m_listening_port_ipv6(0),
        m_external_port(0),
        m_igd(no_igd),
        m_offline(false),
        m_network_id(),
        m_started_at(std::chrono::steady_clock::now())
    {}
    virtual ~node_server();

    static void init_options(boost::program_options::options_description& desc);

    bool run();
    network_zone& add_zone(epee::net_utils::connector_id zone);
    bool init(const boost::program_options::variables_map& vm, const std::string& proxy = {});
    bool deinit();
    bool send_stop_signal();
    uint32_t get_this_peer_port(){return m_listening_port;}
    t_payload_net_handler& get_payload_object();

    // debug functions
    bool log_connections();


    uint32_t get_announced_port(epee::net_utils::connector_id zone) const;
    //! \return This node's own dialable address on `zone`, or its placeholder —
    //! the derived advertisement's observable (there is no dedicated flag,
    //! and no identifier, so the announced value is the only witness). On an
    //! anonymity zone run dialer-only it is the zone's CONSTANT unknown
    //! sentinel: equal for every node, carrying no entropy, linking nothing.
    epee::net_utils::network_address get_announced_address(epee::net_utils::connector_id zone) const;
    //! Advertise a managed-tor publish result. A failed publish or an
    //! unparseable service id leaves `zone.m_our_address` unchanged.
    void apply_managed_onion_publish(network_zone& zone, int publish_rc, const char* service_id, std::uint16_t virtual_port);
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

    void change_max_out_public_peers(size_t count);
    uint32_t get_max_out_public_peers() const;
    void change_max_in_public_peers(size_t count);
    uint32_t get_max_in_public_peers() const;
    //! When `--in-peers` was left unset, derive the public inbound ceiling
    //! from the process descriptor budget and store it. `reserved_beyond_p2p`
    //! is descriptors another subsystem has promised but not opened. An
    //! explicit cap is left as stored. The probe counts descriptors open at
    //! the call, so the daemon calls this again after RPC listeners bind.
    bool apply_inbound_ceiling(std::uint64_t reserved_beyond_p2p);
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
    bool islimitup=false;
    bool islimitdown=false;

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
    bool handle_command_line(
        const boost::program_options::variables_map& vm
      );
    //! PWD-E7 default posture: spawn a managed pinned tor, publish an
    //! ephemeral per-boot onion, and wire the tor zone (inbound bind +
    //! outbound SOCKS). Yields (no-op) when the operator configured the tor
    //! zone themselves, opted out, is offline, or no pinned tor binary is
    //! installed; a start failure logs loudly and continues with no tor zone
    //! (ruled: never aborts the daemon). A bind failure of the loopback
    //! forward listener erases the zone it inserted — leaving it would
    //! fail-close originated txs onto a dead overlay. Called from init()
    //! after m_config_folder is final and before zone iteration begins.
    void add_ephemeral_tor_zone(const boost::program_options::variables_map& vm);
    //! Idle-loop sweep for the ephemeral posture: on the alive->dead edge of
    //! the managed tor, log ONCE that overlay inbound is gone for this boot
    //! and that originated transactions now fail closed on the tor zone
    //! (anonymity-zone selection deliberately never falls back to clearnet).
    //! Per PWD-E7 there is no respawn; restart mints a new address.
    bool check_ephemeral_tor_liveness();
    bool idle_worker();
    bool handle_remote_peerlist(const std::vector<peerlist_entry>& peerlist, const epee::net_utils::connection_context_base& context);
    bool get_local_node_data(epee::net_utils::connector_id zone_type, basic_node_data& node_data, const network_zone& zone) const;
    //bool get_local_handshake_data(handshake_data& hshd);

    bool peer_sync_idle_maker();
    bool do_peer_timed_sync(const epee::net_utils::connection_context_base& context);

    void add_upnp_port_mapping_impl(uint32_t port, bool ipv6=false);
    void add_upnp_port_mapping_v4(uint32_t port);
    void add_upnp_port_mapping_v6(uint32_t port);
    void add_upnp_port_mapping(uint32_t port, bool ipv4=true, bool ipv6=false);
    void delete_upnp_port_mapping_impl(uint32_t port, bool ipv6=false);
    void delete_upnp_port_mapping_v4(uint32_t port);
    void delete_upnp_port_mapping_v6(uint32_t port);
    void delete_upnp_port_mapping(uint32_t port);
    bool try_get_support_flags(const p2p_connection_context& context, std::function<void(p2p_connection_context&, const uint32_t&)> f);
    template <class Container>
    bool parse_peers_and_add_to_container(const boost::program_options::variables_map& vm, const command_line::arg_descriptor<std::vector<std::string> > & arg, Container& container);

    bool set_max_out_peers(network_zone& zone, int64_t max);
    bool set_max_in_peers(network_zone& zone, int64_t max);
    //! Outbound caps on every zone, plus explicit inbound caps on zones
    //! other than public, plus `reserved_beyond_p2p`.
    std::uint64_t descriptor_reservations(std::uint64_t reserved_beyond_p2p) const;
    bool set_tos_flag(const boost::program_options::variables_map& vm, int limit);

    bool set_rate_up_limit(const boost::program_options::variables_map& vm, int64_t limit);
    bool set_rate_down_limit(const boost::program_options::variables_map& vm, int64_t limit);
    bool set_rate_limit(const boost::program_options::variables_map& vm, int64_t limit);

    size_t get_incoming_connections_count();
    size_t get_incoming_connections_count(epee::net_utils::connector_id connector);
    size_t get_outgoing_connections_count();
    size_t get_outgoing_connections_count(epee::net_utils::connector_id connector);
    //! Close the `how_many` newest outbound rows of `connector`. The board
    //! names the ids. The zone's handler is closed when it still holds one,
    //! and `shekyl_seam_close` drops a row the handler table does not.
    void release_outbound(epee::net_utils::connector_id connector, size_t how_many);

    bool check_incoming_connections();

    void kill() { ///< will be called e.g. from deinit()
      _info("Killing the net_node");
    }

    //debug functions
    std::string print_connections_container();


  public:

  private:
    std::string m_config_folder;

    //! 0 until bind.
    uint32_t m_listening_port{0};
    uint32_t m_listening_port_ipv6{0};
    uint32_t m_external_port{0};
    igd_t m_igd;
    bool m_offline;
    bool m_use_ipv6;
    bool m_require_ipv4;
    //critical_section m_connections_lock;
    //connections_indexed_container m_connections;

    //! One relay. Connection registries stay on each connector.
    cryptonote::levin::notify m_notifier;
    t_payload_net_handler& m_payload_handler;

    epee::math_helper::once_a_time_seconds<P2P_DEFAULT_HANDSHAKE_INTERVAL> m_peer_handshake_idle_maker_interval;
    epee::math_helper::once_a_time_seconds<3600, false> m_incoming_connections_interval;
    epee::math_helper::once_a_time_seconds<60> m_ephemeral_tor_liveness_interval;
    //! True while this boot's managed ephemeral tor is believed alive (set at
    //! a successful start in add_ephemeral_tor_zone; cleared by the liveness
    //! sweep on the death edge so the loss is logged exactly once).
    bool m_ephemeral_tor_alive = false;
    //! The published per-boot service id (56 base32 chars, no ".onion") --
    //! empty when the posture is inactive or degraded to outbound-only.
    std::string m_ephemeral_tor_service_id;

    std::vector<epee::net_utils::network_address> m_exclusive_peers;
    std::vector<nodetool::peerlist_entry> m_command_line_peers;


    shekyl_zone_params transport_spans() const;
    shekyl_inbound_ceiling transport_ceiling() const;


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
    //! What the last `apply_inbound_ceiling` reserved beyond p2p's own
    //! sockets (the RPC connection budget). Kept so a re-derive triggered by
    //! a p2p-side change does not have to rediscover it.
    std::uint64_t m_reserved_beyond_p2p = 0;
    //! Last decision `apply_inbound_ceiling` announced, so a second call
    //! with the same result does not repeat the warning. Zero is not a kind.
    std::uint32_t m_applied_ceiling_kind = 0;
    std::uint32_t m_applied_ceiling_value = 0;
    cryptonote::network_type m_nettype;
  };

    extern const command_line::arg_descriptor<std::string> arg_p2p_bind_ip;
    extern const command_line::arg_descriptor<std::string> arg_p2p_bind_ipv6_address;
    extern const command_line::arg_descriptor<std::string, false, true, 2> arg_p2p_bind_port;
    extern const command_line::arg_descriptor<std::string, false, true, 2> arg_p2p_bind_port_ipv6;
    extern const command_line::arg_descriptor<bool>        arg_p2p_use_ipv6;
    extern const command_line::arg_descriptor<bool>        arg_p2p_ignore_ipv4;
    extern const command_line::arg_descriptor<uint32_t>    arg_p2p_external_port;
    extern const command_line::arg_descriptor<bool>        arg_p2p_allow_local_ip;
    extern const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_peer;
    extern const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_exclusive_node;
    extern const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_seed_node;
    extern const command_line::arg_descriptor<std::vector<std::string> > arg_tx_proxy;
    extern const command_line::arg_descriptor<std::vector<std::string> > arg_anonymous_inbound;
    extern const command_line::arg_descriptor<bool> arg_no_ephemeral_tor;
    extern const command_line::arg_descriptor<std::string> arg_ban_list;
    extern const command_line::arg_descriptor<bool> arg_no_sync;

    extern const command_line::arg_descriptor<bool>        arg_no_igd;
    extern const command_line::arg_descriptor<std::string> arg_igd;
    extern const command_line::arg_descriptor<bool>        arg_offline;
    extern const command_line::arg_descriptor<int64_t>     arg_out_peers;
    extern const command_line::arg_descriptor<int64_t>     arg_in_peers;
    extern const command_line::arg_descriptor<int> arg_tos_flag;

    extern const command_line::arg_descriptor<int64_t> arg_limit_rate_up;
    extern const command_line::arg_descriptor<int64_t> arg_limit_rate_down;
    extern const command_line::arg_descriptor<int64_t> arg_limit_rate;
    extern const command_line::arg_descriptor<bool> arg_pad_transactions;
    extern const command_line::arg_descriptor<bool> arg_clearnet_transport_encrypt;
}

POP_WARNINGS


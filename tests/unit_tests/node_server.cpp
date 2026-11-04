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

// The handler's routes are private outside the unit tests.
#define IN_UNIT_TESTS
#include "gtest/gtest.h"
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "p2p/net_node.inl"
#include "cryptonote_core/i_core_events.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.inl"
#include "unit_tests_utils.h"
#include "shekyl/shekyl_ffi.h"

#define MAKE_IPV4_ADDRESS(a,b,c,d) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),0}
#define MAKE_IPV4_ADDRESS_PORT(a,b,c,d,e) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),e}
#define MAKE_IPV4_SUBNET(a,b,c,d,e) epee::net_utils::ipv4_network_subnet{MAKE_IP(a,b,c,d),e}

class test_core : public cryptonote::i_core_events
{
public:
  //! Chain sync's published state, as the shell reads it (CS-5 §3).
  bool synchronized = true;
  virtual bool is_synchronized() const final { return synchronized; }
  unsigned handle_incoming_tx_calls = 0;
  bool handle_incoming_tx_result = true;
  uint8_t handle_incoming_tx_verdict = SHEKYL_DROP_VERDICT_UNCLASSIFIED;
  bool handle_incoming_tx(const cryptonote::blobdata& tx_blob, cryptonote::tx_verification_context& tvc, cryptonote::relay_method tx_relay, bool relayed)
  {
    ++handle_incoming_tx_calls;
    if (handle_incoming_tx_result)
      return true;
    tvc.m_verifivation_failed = true;
    shekyl_drop_verdict_classify(&tvc.m_drop_verdict, handle_incoming_tx_verdict);
    return false;
  }
  virtual void on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, cryptonote::relay_method tx_relay, std::optional<std::uint8_t>) {}
  bool pool_has_tx(const crypto::hash &txid) const override { return false; }
  bool get_txpool_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes) { return false; }
  void stop() {}
};

typedef nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<test_core>> Server;

/// The ban list is the process socket table. A `node_server` used to own
/// its maps, so each test started empty. This drops what the previous
/// test left, and drops again when the test returns.
struct ban_isolate
{
  ban_isolate() { shekyl_bans_clear(); }
  ~ban_isolate() { shekyl_bans_clear(); }
};

// The handler routes the transaction commands and nothing else (CS-5 §6):
// 2002 and 2010 dispatch; the chain's commands are the Rust owner's or
// retired, and reach no route here. `handled` starts false because the
// invoke map sets it on a match and never clears it.
TEST(cryptonote_protocol_handler, routes_only_the_transaction_commands)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  cryptonote::cryptonote_connection_context context{};
  epee::byte_stream out;
  const epee::span<const uint8_t> empty{};

  for (const int command : {2001, 2003, 2004, 2006, 2007, 2008, 2009, 2011, 2012, 2013, 2014})
  {
    SCOPED_TRACE(command);
    bool handled = false;
    const int rc = cprotocol.handle_invoke_map(true, command, empty, out, context, handled);
    EXPECT_FALSE(handled);
    EXPECT_EQ(LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED, rc);
  }
  for (const int command : {cryptonote::NOTIFY_NEW_TRANSACTIONS::ID, cryptonote::NOTIFY_GET_TXPOOL_COMPLEMENT::ID})
  {
    SCOPED_TRACE(command);
    bool handled = false;
    cprotocol.handle_invoke_map(true, command, empty, out, context, handled);
    EXPECT_TRUE(handled);
  }
}

namespace nodetool { template class node_server<cryptonote::t_cryptonote_protocol_handler<test_core>>; }
namespace cryptonote { template class t_cryptonote_protocol_handler<test_core>; }

namespace
{
  //! A connection id that never varies between runs. `random_generator` would
  //! make the fixture non-reproducible for no gain -- nothing here depends on
  //! the ids being unpredictable, only on their being distinct.
  boost::uuids::uuid fixed_uuid(unsigned char n)
  {
    boost::uuids::uuid u{};
    u.data[15] = n;
    return u;
  }
}

namespace
{
  //! A `node_server` that records each drop instead of closing a socket the
  //! test never opened. Every other path, the ban list included, is the
  //! production one.
  struct dropping_server : public Server
  {
    using Server::Server;
    std::vector<boost::uuids::uuid> dropped;

    bool drop_connection(const epee::net_utils::connection_context_base &context) override
    {
      dropped.push_back(context.m_connection_id);
      return true;
    }
  };

  //! Answers from `shekyl_ban_remaining_ns`. Only `none` means the host
  //! is not banned. A deadline and a permanent ban cover it. `not_an_address`
  //! means the text was not a host, so it is not evidence of a clean list.
  enum class ban_cover : int
  {
    not_an_address = -2,
    none = 0,
    deadline = 1,
    permanent = 2,
  };

  //! The host this test named is not on the process ban list.
  void expect_host_not_banned(const char *host, unsigned step, const char *step_name)
  {
    std::uint64_t left = 0;
    const int answer = shekyl_ban_remaining_ns(host, &left);
    EXPECT_EQ(static_cast<int>(ban_cover::none), answer)
        << host << " after " << step_name << " " << step << " answered " << answer;
  }

  const char *const PEER_HOST = "203.0.113.7";
  const auto CLEARNET = static_cast<std::uint8_t>(epee::net_utils::connector_id::clearnet);

  epee::net_utils::network_address peer_address()
  {
    return epee::net_utils::network_address{
        epee::net_utils::ipv4_network_address{MAKE_IP(203, 0, 113, 7), 18080}};
  }
}

// No peer can make a ban (Rick, 2026-11-01): a clearnet peer whose
// handshake names another network is dropped every time and is never
// banned, however often it tries. The automatic ban banned it past ten
// fail points, the eleventh try. Red: run on the code before the
// deletion, where `add_host_fail` calls `block_host`.
TEST(node_server, a_peer_naming_another_network_is_dropped_every_time_and_never_banned)
{
  ban_isolate isolated;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  dropping_server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>::request request{};
  // The server is constructed, not `init()`'d, so its network id is the
  // nil uuid the constructor writes. This is another network.
  const boost::uuids::uuid another_network{{1}};
  request.node_data.network_id = another_network;
  epee::byte_slice body;
  ASSERT_TRUE(epee::serialization::store_t_to_binary(request, body));

  epee::levin::levin_commands_handler<nodetool::p2p_connection_context_t<cryptonote::cryptonote_connection_context>> &levin = server;
  for (std::uint8_t attempt = 1; attempt <= 11; ++attempt)
  {
    nodetool::p2p_connection_context_t<cryptonote::cryptonote_connection_context> context{
        fixed_uuid(attempt), peer_address(), /*is_income=*/true, CLEARNET};
    epee::byte_stream reply;
    levin.invoke(nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>::ID,
        epee::to_span(body), reply, context);
    ASSERT_EQ(attempt, server.dropped.size()) << "try " << unsigned{attempt} << ": drop count mismatch";
    expect_host_not_banned(PEER_HOST, attempt, "try");
  }
}

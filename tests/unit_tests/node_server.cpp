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

#include "gtest/gtest.h"
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "p2p/net_node.inl"
#include "cryptonote_core/i_core_events.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.inl"
#include "unit_tests_utils.h"
#include "net/tor_address.h"
#include <condition_variable>
#include <mutex>
#include <thread>
#include "p2p/seam_endpoint.h"
#include <set>
#include "shekyl/shekyl_ffi.h"
#include <cstdlib>

#define MAKE_IPV4_ADDRESS(a,b,c,d) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),0}
#define MAKE_IPV4_ADDRESS_PORT(a,b,c,d,e) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),e}
#define MAKE_IPV4_SUBNET(a,b,c,d,e) epee::net_utils::ipv4_network_subnet{MAKE_IP(a,b,c,d),e}

namespace cryptonote {
  class blockchain_storage;
}

class test_core : public cryptonote::i_core_events
{
public:
  virtual bool is_synchronized() const final { return true; }
  void on_synchronized(){}
  void safesyncmode(const bool){}
  virtual uint64_t get_current_blockchain_height() const final {return 1;}
  void set_target_blockchain_height(uint64_t) {}
  bool init(const boost::program_options::variables_map& vm) {return true ;}
  bool deinit(){return true;}
  bool get_short_chain_history(std::list<crypto::hash>& ids, uint64_t& current_height) const { return true; }
  // The blocks this core already has. Empty by default, so every test that
  // does not populate it sees the previous unconditional `false`. A test
  // driving `try_add_next_blocks` needs the span's parent to be known, which
  // is what gates reaching `prepare_handle_incoming_blocks`.
  std::vector<crypto::hash> blocks_we_have;
  bool have_block(const crypto::hash& id, int *where = NULL) const
  {return std::find(blocks_we_have.begin(), blocks_we_have.end(), id) != blocks_we_have.end();}
  bool have_block_unlocked(const crypto::hash& id, int *where = NULL) const {return false;}
  void get_blockchain_top(uint64_t& height, crypto::hash& top_id)const{height=0;top_id=crypto::null_hash;}
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
  bool handle_single_incoming_block(const cryptonote::blobdata& block_blob, const cryptonote::block *b, cryptonote::block_verification_context& bvc, cryptonote::block_connect_supplement& connect, bool update_miner_blocktemplate = true) { return true; }
  bool handle_incoming_block(const cryptonote::blobdata& block_blob, const cryptonote::block *block, cryptonote::block_verification_context& bvc, bool update_miner_blocktemplate = true) { return true; }
  bool handle_incoming_block(const cryptonote::blobdata& block_blob, const cryptonote::block *block, cryptonote::block_verification_context& bvc, cryptonote::block_connect_supplement& connect, bool update_miner_blocktemplate = true) { return true; }
  void pause_mine(){}
  void resume_mine(){}
  bool on_idle(){return true;}
  bool find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp){return true;}
  bool handle_get_objects(cryptonote::NOTIFY_REQUEST_GET_OBJECTS::request& arg, cryptonote::NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote::cryptonote_connection_context& context){return true;}
  cryptonote::blockchain_storage &get_blockchain_storage() { throw std::runtime_error("Called invalid member function: please never call get_blockchain_storage on the TESTING class test_core."); }
  bool get_test_drop_download() const {return true;}
  bool get_test_drop_download_height() const {return true;}
  bool prepare_handle_incoming_blocks_result = true;
  uint8_t prepare_handle_incoming_blocks_verdict = SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM;
  bool prepare_handle_incoming_blocks(const std::vector<cryptonote::block_complete_entry>  &blocks_entry, std::vector<cryptonote::block> &blocks, uint8_t *drop_verdict = nullptr)
  {
    if (drop_verdict)
    {
      *drop_verdict = prepare_handle_incoming_blocks_result
                          ? uint8_t(SHEKYL_DROP_VERDICT_UNCLASSIFIED)
                          : prepare_handle_incoming_blocks_verdict;
    }
    return prepare_handle_incoming_blocks_result;
  }
  bool cleanup_handle_incoming_blocks(bool force_sync = false) { return true; }
  bool check_incoming_block_size_result = true;
  bool check_incoming_block_size(const cryptonote::blobdata& block_blob) const { return check_incoming_block_size_result; }
  uint64_t get_target_blockchain_height() const { return 1; }
  size_t get_block_sync_size(uint64_t height) const { return BLOCKS_SYNCHRONIZING_DEFAULT_COUNT; }
  virtual void on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, cryptonote::relay_method tx_relay, std::optional<std::uint8_t>) {}
  virtual void on_stem_propagated(epee::span<const crypto::hash>) {}
  cryptonote::network_type get_nettype() const { return cryptonote::MAINNET; }
  bool get_pool_transaction(const crypto::hash& id, cryptonote::blobdata& tx_blob, cryptonote::relay_category tx_category) const { return false; }
  /*! Already here for the protocol-handler shim, and now also the
      `i_core_events` override — these fixtures never drive a carrier verdict,
      so the stub's existing answer stands rather than being second-guessed. */
  bool pool_has_tx(const crypto::hash &txid) const override { return false; }
  bool get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata, cryptonote::block>>& blocks, std::vector<cryptonote::blobdata>& txs) const { return false; }
  bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned = false) const { return false; }
  bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::transaction>& txs, std::vector<crypto::hash>& missed_txs) const { return false; }
  bool get_block_by_hash(const crypto::hash &h, cryptonote::block &blk, bool *orphan = NULL) const { return false; }
  cryptonote::blobdata get_block_attestation_witness(const cryptonote::block &blk) const { return {}; }
  uint64_t get_earliest_ideal_height_for_version(uint8_t version) const { return 0; }
  cryptonote::difficulty_type get_block_cumulative_difficulty(uint64_t height) const { return 0; }
  bool pad_transactions() { return false; }
  bool get_txpool_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes) { return false; }
  bool get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_unrelayed_txes = true) const { return false; }
  crypto::hash get_block_id_by_height(uint64_t height) const { return crypto::null_hash; }
  void stop() {}
};

//! Grants this file access to the protocol handler's private members. See the
//! `friend` declaration in `cryptonote_protocol_handler.h` for what it exists
//! for and when it retires.
struct cryptonote_protocol_handler_test_seam
{
  template<class T>
  static cryptonote::block_queue &queue(cryptonote::t_cryptonote_protocol_handler<T> &h)
  { return h.m_block_queue; }

  template<class T>
  static void drop_connections(cryptonote::t_cryptonote_protocol_handler<T> &h,
                               const epee::net_utils::network_address &addr)
  { h.drop_connections(addr); }

  template<class T>
  static int try_add_next_blocks(cryptonote::t_cryptonote_protocol_handler<T> &h,
                                 cryptonote::cryptonote_connection_context &ctx)
  { return h.try_add_next_blocks(ctx); }

  // Both notify handlers are private, and both gate on `is_synchronized()`
  // before reaching the arms PWD-B7 changed -- so the seam grants the flag
  // alongside them rather than leaving each test to discover that the handler
  // returned early and asserted nothing.
  template<class T>
  static void set_synchronized(cryptonote::t_cryptonote_protocol_handler<T> &h, bool v)
  { h.m_synchronized = v; }

  template<class T>
  static int handle_notify_new_transactions(cryptonote::t_cryptonote_protocol_handler<T> &h,
                                            cryptonote::NOTIFY_NEW_TRANSACTIONS::request &arg,
                                            cryptonote::cryptonote_connection_context &ctx)
  { return h.handle_notify_new_transactions(0, arg, ctx); }

  template<class T>
  static int handle_notify_new_compact_block(cryptonote::t_cryptonote_protocol_handler<T> &h,
                                            cryptonote::NOTIFY_NEW_COMPACT_BLOCK::request &arg,
                                            cryptonote::cryptonote_connection_context &ctx)
  { return h.handle_notify_new_compact_block(0, arg, ctx); }
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

static bool is_blocked(Server &server, const epee::net_utils::network_address &address, time_t *t = NULL)
{
  std::map<std::string, time_t> hosts = server.get_blocked_hosts();
  for (auto rec: hosts)
  {
    if (rec.first == address.host_str())
    {
      if (t)
        *t = rec.second;
      return true;
    }
  }

  if (address.get_type_id() != epee::net_utils::address_type::ipv4)
    return false;
  
  const epee::net_utils::ipv4_network_address ipv4_address = address.as<epee::net_utils::ipv4_network_address>();

  // check if in a blocked ipv4 subnet
  const std::map<epee::net_utils::ipv4_network_subnet, time_t> subnets = server.get_blocked_subnets();
  for (const auto &subnet : subnets)
    if (subnet.first.matches(ipv4_address))
      return true;

  return false;
}

// PWD-B6: 2008 is the sole block-announce command; 2001 is refused as unknown.
// `handled` starts false because the invoke map sets it on a match and never
// clears it. Live-daemon regtest is --offline and does not cover p2p relay.
TEST(cryptonote_protocol_handler, block_propagation_has_exactly_one_command)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  cryptonote::cryptonote_connection_context context{};
  epee::byte_stream out;

  cryptonote::NOTIFY_NEW_COMPACT_BLOCK::request compact{};
  compact.current_blockchain_height = 1;
  epee::byte_stream body;
  ASSERT_TRUE(epee::serialization::store_t_to_binary(compact, body));
  const epee::span<const uint8_t> in_buff{body.data(), body.size()};

  {
    bool handled = false;
    const int rc = cprotocol.handle_invoke_map(true, 2001, in_buff, out, context, handled);
    EXPECT_FALSE(handled) << "command 2001 is still dispatched somewhere";
    EXPECT_EQ(LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED, rc)
        << "2001 must be refused as an unknown command, not silently ignored";
  }

  {
    bool handled = false;
    cprotocol.handle_invoke_map(true, cryptonote::NOTIFY_NEW_COMPACT_BLOCK::ID,
                                in_buff, out, context, handled);
    EXPECT_TRUE(handled)
        << "NOTIFY_NEW_COMPACT_BLOCK must still dispatch — it is the only block path";
  }
}

TEST(ban, add)
{
  [[maybe_unused]] ban_isolate isolate;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  // starts empty
  ASSERT_TRUE(server.get_blocked_hosts().empty());
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // add an IP
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // add the same, should not change
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // remove an unblocked IP, should not change
  ASSERT_FALSE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // remove the IP, ends up empty
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 0);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // remove the IP from an empty list, still empty
  ASSERT_FALSE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 0);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // add two for known amounts of time, they're both blocked
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 1));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,5), 3));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 2);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,5)));

  // these tests would need to call is_remote_ip_allowed, which is private
#if 0
  // after two seconds, the first IP is unblocked, but not the second yet
  sleep(2);
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // after two more seconds, the second IP is also unblocked
  sleep(2);
  ASSERT_TRUE(server.get_blocked_hosts().size() == 0);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
#endif

  // add an IP again, then re-ban for longer, then shorter
  time_t t;
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 2));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4), &t));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(t >= 1);
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 9));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4), &t));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(t >= 8);
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 5));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4), &t));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(t >= 4);
}

TEST(ban, limit)
{
  [[maybe_unused]] ban_isolate isolate;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  // starts empty
  ASSERT_TRUE(server.get_blocked_hosts().empty());
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), std::numeric_limits<time_t>::max() - 1));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 1));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
}

TEST(node_server, managed_onion_is_advertised_only_after_publish)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  auto& zone = server.add_zone(epee::net_utils::connector_id::tor);
  zone.m_config.m_net_config.max_in_connection_count = 8;
  const char* service = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd";
  server.apply_managed_onion_publish(zone, 1, service, 18080);
  ASSERT_EQ(server.get_announced_address(epee::net_utils::connector_id::tor).host_str(),
    net::tor_address::unknown().host_str());

  server.apply_managed_onion_publish(zone, SHEKYL_DAEMON_TOR_OK, service, 18080);
  const auto expected = MONERO_UNWRAP(net::tor_address::make(std::string(service) + ".onion:18080"));
  ASSERT_EQ(server.get_announced_address(epee::net_utils::connector_id::tor).host_str(), expected.host_str());
}

namespace
{
  // A private --data-dir for a test that runs node_server::init. The
  // option's default is the operator's real data directory
  // (tools::get_default_data_dir()), whose p2pstate.bin init_config would
  // read and whose peerlist a test must neither depend on nor rewrite.
  boost::filesystem::path create_node_dir()
  {
    boost::system::error_code ec;
    auto path = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("daemon-%%%%%%%%%%%%%%%%", ec);
    if (ec)
      return boost::filesystem::path{};
    auto success = boost::filesystem::create_directory(path, ec);
    if (!ec && success)
      return path;
    return boost::filesystem::path{};
  }

  // Options for a node_server whose init must not open a listener. --offline
  // returns from init before the p2p bind (net_node.inl: "from here onwards,
  // it's online stuff"), after the command line, the ban list and the
  // peerlist have been processed — everything the ban tests exercise. Without
  // it, init bound the network default P2P_DEFAULT_PORT, so the suite went
  // red whenever a daemon was running on the same box, for a reason none of
  // these tests tests. A test that fails for a non-subject reason trains its
  // own dismissal: RK-5b hit that failure on every full run and two lanes
  // triaged it as environmental on the same day.
  //
  // TEST(node_server, bind_same_p2p_port) deliberately does not use this: a
  // listener is its subject.
  boost::program_options::variables_map offline_node_vm(const boost::filesystem::path& node_dir, std::vector<std::string> extra_args)
  {
    std::vector<std::string> args{"--data-dir", node_dir.string(), "--offline"};
    args.insert(args.end(), extra_args.begin(), extra_args.end());

    boost::program_options::options_description options_description{};
    cryptonote::core::init_options(options_description);
    Server::init_options(options_description);

    boost::program_options::variables_map vm;
    boost::program_options::store(
      boost::program_options::command_line_parser(args).options(options_description).run(), vm);
    // Production startup notifies (src/daemon/main.cpp), and so does every
    // other `init(vm)` site in this file. No option in `core::init_options` or
    // `Server::init_options` currently carries a notifier or `required()`, so
    // this is behaviour-neutral today — it is here so the harness keeps
    // matching production when one does, rather than diverging silently.
    boost::program_options::notify(vm);
    return vm;
  }
}

TEST(ban, subnet)
{
  [[maybe_unused]] ban_isolate isolate;
  // Formerly GTEST_SKIP'd as "intermittent allocator failure in constrained
  // environments; tracked for dedicated fix" — nothing in the tree tracked
  // it, and the stated cause was wrong on all three counts. The body called
  // boost::program_options::parse_command_line(0, nullptr, opts); boost's
  // parser builds std::vector<std::string>(argv+1, argv+argc), a reversed
  // range when argc == 0, and libstdc++ throws std::length_error
  // deterministically (older libstdc++ attempted the negative length and
  // raised bad_alloc — the "allocator failure"). So the test threw before
  // init ran. Had it parsed, it would have read the operator's real
  // p2pstate.bin (no --data-dir), bound P2P_DEFAULT_PORT (no --offline), and
  // never asserted init's result. All of that is gone; the assertion is
  // present.
  time_t seconds;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);

  const auto node_dir = create_node_dir();
  ASSERT_TRUE(!node_dir.empty());
  auto auto_remove_node_dir = epee::misc_utils::create_scope_leave_handler([&node_dir](){
      boost::filesystem::remove_all(node_dir);
    });

  ASSERT_TRUE(server.init(offline_node_vm(node_dir, {})));
  cprotocol.set_p2p_endpoint(&server);

  ASSERT_TRUE(server.block_subnet(MAKE_IPV4_SUBNET(1,2,3,4,24), 10));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,4), &seconds));
  ASSERT_TRUE(seconds >= 9);
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,255), &seconds));
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,0), &seconds));
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,4,0), &seconds));
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,2,0), &seconds));
  ASSERT_TRUE(server.unblock_subnet(MAKE_IPV4_SUBNET(1,2,3,8,24)));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 0);
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,255), &seconds));
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,0), &seconds));
  ASSERT_TRUE(server.block_subnet(MAKE_IPV4_SUBNET(1,2,3,4,8), 10));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,255,3,255), &seconds));
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,0,3,255), &seconds));
  ASSERT_FALSE(server.unblock_subnet(MAKE_IPV4_SUBNET(1,2,3,8,24)));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.block_subnet(MAKE_IPV4_SUBNET(1,2,3,4,8), 10));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.unblock_subnet(MAKE_IPV4_SUBNET(1,255,0,0,8)));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 0);
}

TEST(ban, file_entries_are_permanent)
{
  [[maybe_unused]] ban_isolate isolate;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);

  const auto node_dir = create_node_dir();
  ASSERT_TRUE(!node_dir.empty());
  auto auto_remove_node_dir = epee::misc_utils::create_scope_leave_handler([&node_dir](){
      boost::filesystem::remove_all(node_dir);
    });
  const auto ban_path = node_dir / "banlist.txt";
  ASSERT_TRUE(epee::file_io_utils::save_string_to_file(ban_path.string(), "1.2.3.4\n"));

  ASSERT_TRUE(server.init(offline_node_vm(node_dir, {"--ban-list", ban_path.string()})));
  const auto rows = server.ban_list();
  ASSERT_EQ(rows.size(), 1u);
  ASSERT_EQ(rows[0].permanent, 1);
  ASSERT_EQ(rows[0].remaining_ns, 0u);
  ASSERT_TRUE(server.host_ban_is_permanent(MAKE_IPV4_ADDRESS(1,2,3,4)));
}

TEST(node_server, operator_onion_is_advertised)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);

  const auto node_dir = create_node_dir();
  ASSERT_TRUE(!node_dir.empty());
  auto auto_remove_node_dir = epee::misc_utils::create_scope_leave_handler([&node_dir](){
      boost::filesystem::remove_all(node_dir);
    });

  const std::string onion =
    "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
  ASSERT_TRUE(server.init(offline_node_vm(node_dir, {
    // The count is omitted: an explicit count below the embargo floor
    // refuses to start, and the count is not what this test observes.
    "--tx-proxy", "tor,127.0.0.1:9050",
    "--anonymous-inbound", onion + ":18080,127.0.0.1:38123,8",
  })));
  const auto announced = server.get_announced_address(epee::net_utils::connector_id::tor);
  ASSERT_EQ(announced.host_str(), onion);
  ASSERT_EQ(announced.as<net::tor_address>().port(), 18080);
}

TEST(node_server, exclusive_onion_does_not_require_tx_proxy)
{
  // The managed Tor supplies SOCKS after the command line. Refusing here was
  // the default posture being unable to dial a named onion. A missing pin
  // degrades inbound; it must not be what rejects the option.
  const char *saved = std::getenv("SHEKYL_TOR_BINARY");
  const std::string saved_copy = saved ? saved : std::string{};
  ASSERT_EQ(::setenv("SHEKYL_TOR_BINARY", "/no/such/shekyl-tor", 1), 0);
  auto restore = epee::misc_utils::create_scope_leave_handler([&]() {
    if (saved)
      ::setenv("SHEKYL_TOR_BINARY", saved_copy.c_str(), 1);
    else
      ::unsetenv("SHEKYL_TOR_BINARY");
  });

  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);

  const auto node_dir = create_node_dir();
  ASSERT_TRUE(!node_dir.empty());
  auto auto_remove_node_dir = epee::misc_utils::create_scope_leave_handler([&node_dir]() {
    boost::filesystem::remove_all(node_dir);
  });

  const std::string onion =
    "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:12021";
  std::vector<std::string> args{
    "--data-dir", node_dir.string(),
    "--p2p-bind-ip", "127.0.0.1",
    "--p2p-bind-port", "48119",
    "--no-igd",
    "--add-exclusive-node", onion,
  };
  boost::program_options::options_description options_description{};
  cryptonote::core::init_options(options_description);
  Server::init_options(options_description);
  boost::program_options::variables_map vm;
  boost::program_options::store(
    boost::program_options::command_line_parser(args).options(options_description).run(), vm);
  boost::program_options::notify(vm);
  ASSERT_TRUE(server.init(vm));

  test_core offline_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> offline_protocol(offline_core, NULL);
  Server offline(offline_protocol);
  const auto offline_dir = create_node_dir();
  ASSERT_TRUE(!offline_dir.empty());
  auto auto_remove_offline = epee::misc_utils::create_scope_leave_handler([&offline_dir]() {
    boost::filesystem::remove_all(offline_dir);
  });
  ASSERT_FALSE(offline.init(offline_node_vm(offline_dir, {"--add-exclusive-node", onion})));
}

TEST(ban, ignores_port)
{
  [[maybe_unused]] ban_isolate isolate;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  // The span is the ordinary block time. A duration that does not fit in
  // nanoseconds is refused, and that refusal is ban.limit's subject.
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,6)));
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,6)));
}

TEST(ban, file_banlist)
{
  [[maybe_unused]] ban_isolate isolate;
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  const auto node_dir = create_node_dir();
  ASSERT_TRUE(!node_dir.empty());
  auto auto_remove_node_dir = epee::misc_utils::create_scope_leave_handler([&node_dir](){
      boost::filesystem::remove_all(node_dir);
    });

  ASSERT_TRUE(server.init(offline_node_vm(node_dir, {
    "--ban-list",
    (unit_test::data_dir / "node" / "banlist_1.txt").string()
  })));

  // Test cases (look in the banlist_1.txt file)

  // magicfolk
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(255,255,255,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(128,128,128,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(150,75,0,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(99,98,0,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(99,98,0,255,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(99,98,1,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(99,98,1,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(99,98,255,255,9999)) );
  EXPECT_FALSE( is_blocked(server, MAKE_IPV4_ADDRESS_PORT(99,99,0,0,9999)) );

  // personal enemies
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(1,2,3,4,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(6,7,8,9,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(1,0,0,7,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(1,0,0,7,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(100,98,1,13,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(100,98,1,0,9999)) );
  EXPECT_TRUE(  is_blocked(server, MAKE_IPV4_ADDRESS_PORT(100,98,1,255,9999)) );
  EXPECT_FALSE( is_blocked(server, MAKE_IPV4_ADDRESS_PORT(100,98,2,0,9999)) );
  EXPECT_FALSE( is_blocked(server, MAKE_IPV4_ADDRESS_PORT(100,98,0,255,9999)) );

  // angel
  EXPECT_FALSE( is_blocked(server, MAKE_IPV4_ADDRESS_PORT(007,007,007,007,9999)) );

  // random IP
  EXPECT_FALSE( is_blocked(server, MAKE_IPV4_ADDRESS_PORT(145,036,205,235,9999)) );
}

TEST(node_server, bind_same_p2p_port)
{
  struct test_data_t
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;

    test_data_t(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
  };

  const auto new_node = []() -> std::unique_ptr<test_data_t> {
    test_data_t *d = new test_data_t;
    return std::unique_ptr<test_data_t>(d);
  };

  const auto init = [](const std::unique_ptr<test_data_t>& server, const char* port) -> bool {
    boost::program_options::options_description desc_options("Command line options");
    cryptonote::core::init_options(desc_options);
    Server::init_options(desc_options);

    const char *argv[2] = {nullptr, nullptr};
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(1, argv, desc_options), vm);

    /*
    Reason for choosing '127.0.0.2' as the IP:

    A TCP local socket address that has been bound is unavailable for some time after closing, unless the SO_REUSEADDR flag has been set.
    That's why connections with automatically assigned source port 48080/58080 from previous test blocks the next to bind acceptor
    so solution is to either set reuse_addr option for each socket in all tests
    or use ip different from localhost for acceptors in order to not interfere with automatically assigned source endpoints

    Relevant part about REUSEADDR from man:
    https://www.man7.org/linux/man-pages/man7/ip.7.html

    For Mac OSX, set the following alias, before running the test, or else it will fail:
    sudo ifconfig lo0 alias 127.0.0.2
    */
    vm.find(nodetool::arg_p2p_bind_ip.name)->second   = boost::program_options::variable_value(std::string("127.0.0.2"), false);
    vm.find(nodetool::arg_p2p_bind_port.name)->second = boost::program_options::variable_value(std::string(port), false);

    boost::program_options::notify(vm);

    return server->server->init(vm);
  };

  constexpr char port[] = "48080";
  constexpr char port_another[] = "58080";

  const auto node = new_node();
  EXPECT_TRUE(init(node, port));

  EXPECT_FALSE(init(new_node(), port));
  EXPECT_TRUE(init(new_node(), port_another));
}

namespace nodetool { template class node_server<cryptonote::t_cryptonote_protocol_handler<test_core>>; }
namespace cryptonote { template class t_cryptonote_protocol_handler<test_core>; }

TEST(node_server, tx_proxy_outbound_floor_refuses_underprovisioned_counts)
{
  // F-8b: the relay embargo constant (`fluff_return_ms`) is derived from a
  // fluff first-passage measured at outbound degree 12. A `--tx-proxy` count
  // below that floor puts the zone's real first passage above the provisioned
  // value — the embargo would be under-provisioned in the privacy-losing
  // direction — so the parser must refuse it at startup, not warn and run.
  const auto parse = [](const char* proxy_arg) {
    boost::program_options::variables_map vm;
    boost::program_options::store(
      boost::program_options::command_line_parser({"--tx-proxy", proxy_arg})
        .options([]{
          boost::program_options::options_description options_description{};
          Server::init_options(options_description);
          return options_description;
        }())
        .run(),
      vm
    );
    return nodetool::get_proxies(vm);
  };

  const std::int64_t floor_value = shekyl_relay_zone_min_provisioned_out_peers();
  ASSERT_EQ(12, floor_value) << "the floor must match the degree fluff_return_ms was measured at";

  // The parser carries the count; the floor is enforced where the cap is
  // set, by the dialer (2026-10-13), so an under-floor count parses and
  // then refuses init (1..=11 all land in the guarded range; 4 is the
  // motivating operator practice).
  const auto under = parse("tor,127.0.0.1:9050,4");
  ASSERT_TRUE(under.has_value()) << "the parser carries the count";
  EXPECT_EQ(4, under->front().max_connections);
  // One server per init: a second init on the same server would refuse the
  // proxy as listed twice, and pass the under-floor case for the wrong reason.
  const auto init_with_proxy = [](const char* proxy_arg) -> bool {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
    Server server(cprotocol);
    const auto node_dir = create_node_dir();
    if (node_dir.empty())
      return false;
    auto auto_remove_node_dir = epee::misc_utils::create_scope_leave_handler([&node_dir](){
        boost::filesystem::remove_all(node_dir);
      });
    return server.init(offline_node_vm(node_dir, {"--tx-proxy", proxy_arg}));
  };
  EXPECT_FALSE(init_with_proxy("tor,127.0.0.1:9050,4"))
    << "an under-floor outbound count must refuse to start";
  EXPECT_FALSE(init_with_proxy("tor,127.0.0.1:9050,11"))
    << "one below the floor must still refuse";
  EXPECT_TRUE(init_with_proxy("tor,127.0.0.1:9050,12"))
    << "the floor itself is a valid count";

  // At the floor and above: accepted, with the count preserved.
  const auto at_floor = parse("tor,127.0.0.1:9050,12");
  ASSERT_TRUE(at_floor.has_value()) << "the floor itself is a valid count";
  ASSERT_EQ(1u, at_floor->size());
  EXPECT_EQ(12, at_floor->front().max_connections);

  // Omitted count: the default (-1 -> shekyl_p2p_default_out_peers()) resolves
  // at or above the floor — today they are EQUAL (12), so "above by
  // construction" would be false — and must keep parsing. The relation is
  // asserted, not assumed: if the floor ever rises past the default, the
  // default configuration itself becomes under-provisioned and this is the
  // test that says so. Both sides are now Rust-owned constants reached through
  // the FFI, so this is the one place their *relation* is checked at all.
  const std::int64_t default_out_peers =
    static_cast<std::int64_t>(shekyl_p2p_default_out_peers());
  EXPECT_LE(floor_value, default_out_peers)
    << "the default outbound count must satisfy the floor the embargo derivation assumes";
  const auto omitted = parse("tor,127.0.0.1:9050");
  ASSERT_TRUE(omitted.has_value());
  EXPECT_EQ(-1, omitted->front().max_connections);
}

TEST(node_server, anonymity_zone_announces_the_constant_unknown_address)
{
  // Successor of the Q12-R-W3 sentinel-peer_id pin, for the identifier-free
  // handshake (PWD-I1): nothing announced on an anonymity zone may carry
  // entropy. The handshake carries no address since 2026-10-09; what this
  // node would announce is `get_announced_address`, which reaches peers only
  // as one member of the disclosure sample. A dialer-only tor zone's value
  // there must be the zone's CONSTANT unknown sentinel — equal for every
  // node, linking nothing. A per-node value (an onion, a random address)
  // would correlate this node's hidden-service activity with its clearnet
  // identity exactly as a random peer_id did.
  struct test_data_t
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;

    test_data_t(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
  };

  test_data_t data;

  boost::program_options::options_description desc_options("Command line options");
  cryptonote::core::init_options(desc_options);
  Server::init_options(desc_options);

  const char* argv[2] = {nullptr, nullptr};
  boost::program_options::variables_map vm;
  boost::program_options::store(
    boost::program_options::parse_command_line(1, argv, desc_options), vm);

  // 127.0.0.2 for the same TIME_WAIT reason as bind_same_p2p_port above.
  vm.find(nodetool::arg_p2p_bind_ip.name)->second =
    boost::program_options::variable_value(std::string("127.0.0.2"), false);
  vm.find(nodetool::arg_p2p_bind_port.name)->second =
    boost::program_options::variable_value(std::string("48085"), false);
  // 12 outbound connections: the F-8b floor, so the zone is accepted.
  //
  // `find` is safe on an option absent from the command line because
  // `make_semantic` gives every vector-valued arg_descriptor an empty
  // `default_value` (src/common/command_line.h), so `store` inserts it into the
  // map regardless. Were that not so this would dereference `end()` rather than
  // fail an assertion — hence naming it here rather than relying on it quietly.
  vm.find(nodetool::arg_tx_proxy.name)->second =
    boost::program_options::variable_value(
      std::vector<std::string>{"tor,127.0.0.1:9050,12"}, false);

  boost::program_options::notify(vm);
  ASSERT_TRUE(data.server->init(vm));

  EXPECT_EQ(epee::net_utils::network_address{net::tor_address::unknown()},
            data.server->get_announced_address(epee::net_utils::connector_id::tor))
    << "a dialer-only anonymity zone must announce the constant unknown "
       "sentinel: any per-node value correlates the hidden service with the "
       "node's other identities";

  // Negative control, and the port-only public advert pinned at unit level:
  // the public zone announces ipv4 with the HOST HALF ZEROED — only the
  // port is the claim — so the two zones' announcements must differ and the
  // public one must carry no host.
  const auto pub = data.server->get_announced_address(epee::net_utils::connector_id::clearnet);
  ASSERT_EQ(epee::net_utils::ipv4_network_address::get_type_id(), pub.get_type_id());
  EXPECT_EQ(0u, pub.as<epee::net_utils::ipv4_network_address>().ip())
    << "the public advert is port-only; the host half must stay zeroed";
  EXPECT_EQ(data.server->get_announced_port(epee::net_utils::connector_id::clearnet), pub.port());

  data.server->deinit();
}

// `--add-peer` is an operator-supplied address this node has NEVER dialled, so
// it is a candidate, not a verified peer. It must land in gray.
//
// This is tested at the node_server level on purpose. The peerlist-manager
// tests construct `peerlist_types` or call the append methods directly, so
// reverting the routing line to `append_with_peer_white` leaves every one of
// them green — they cannot see which method the option path calls. The
// security property here is about the CALL SITE, so the test has to start
// where the operator's input does.
TEST(node_server, add_peer_enters_gray_not_white)
{
  struct test_data_t
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;

    test_data_t(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
  };

  test_data_t data;

  boost::program_options::options_description desc_options("Command line options");
  cryptonote::core::init_options(desc_options);
  Server::init_options(desc_options);

  const char* argv[2] = {nullptr, nullptr};
  boost::program_options::variables_map vm;
  boost::program_options::store(
    boost::program_options::parse_command_line(1, argv, desc_options), vm);

  // 127.0.0.2 for the same TIME_WAIT reason as bind_same_p2p_port above.
  vm.find(nodetool::arg_p2p_bind_ip.name)->second =
    boost::program_options::variable_value(std::string("127.0.0.2"), false);
  vm.find(nodetool::arg_p2p_bind_port.name)->second =
    boost::program_options::variable_value(std::string("48085"), false);
  vm.find(nodetool::arg_p2p_add_peer.name)->second =
    boost::program_options::variable_value(
      std::vector<std::string>{"203.0.113.9:18080"}, false);

  boost::program_options::notify(vm);
  ASSERT_TRUE(data.server->init(vm));

  // RFC 5737 documentation range, NOT loopback and NOT RFC1918: an
  // operator-named address is admitted whatever its range, but a global
  // one keeps this test independent of --allow-local-ip. The lists are the
  // Rust dialer's; the listing export reads them, white then gray. The
  // address is pushed before the first listen builds the dialer, so this
  // also pins that an early push is held for the build.
  const shekyl_rpc_peer_facts* rows = nullptr;
  std::size_t len = 0;
  void* owner = nullptr;
  ASSERT_EQ(shekyl_rpc_peer_list(0, &rows, &len, &owner), 0);
  bool in_gray = false;
  bool in_white = false;
  for (std::size_t i = 0; i < len; ++i)
  {
    const std::string host(rows[i].host, rows[i].host_len);
    if (host != "203.0.113.9")
      continue;
    (rows[i].white ? in_white : in_gray) = true;
  }
  shekyl_rpc_peer_list_free(owner);

  // The property: it is a candidate.
  EXPECT_TRUE(in_gray) << "--add-peer must enter the gray list";
  // The limb that actually pins the routing. Without it a change that put the
  // entry in BOTH lists, or in white only, would still satisfy the assertion
  // above or leave it unexercised -- and white is the list that is dialled
  // preferentially and disclosed onward.
  EXPECT_FALSE(in_white)
    << "--add-peer must NOT enter the white list: it has never been dialled, "
       "and white entries are disclosed to peers";

  data.server->deinit();
}

TEST(node_server, out_peers_floor_guards_public_zone_init_and_runtime)
{
  // F-8b, the public-zone half: `--tx-proxy` counts are floored at the parser
  // (test above), but the same outbound-degree quantity is also set by
  // `--out-peers` at init and by the `out_peers` console/RPC command at
  // runtime. The floor lives in the dialer, which both paths push the cap
  // to (2026-10-13): init refuses to start, and the runtime path refuses
  // the request and leaves the cap as it was — otherwise a NAT'd operator
  // at `--out-peers 2` runs a fluff degree far below any point
  // `fluff_return_ms` was measured at and the embargo is under-provisioned
  // in the privacy-losing direction.
  struct test_data_t
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;

    test_data_t(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
  };

  const auto init_with_out_peers = [](test_data_t& d, const std::int64_t out_peers) -> bool {
    boost::program_options::options_description desc_options("Command line options");
    cryptonote::core::init_options(desc_options);
    Server::init_options(desc_options);

    const char* argv[2] = {nullptr, nullptr};
    boost::program_options::variables_map vm;
    boost::program_options::store(
      boost::program_options::parse_command_line(1, argv, desc_options), vm);

    // 127.0.0.2 for the same TIME_WAIT reason as bind_same_p2p_port above.
    vm.find(nodetool::arg_p2p_bind_ip.name)->second =
      boost::program_options::variable_value(std::string("127.0.0.2"), false);
    vm.find(nodetool::arg_p2p_bind_port.name)->second =
      boost::program_options::variable_value(std::string("48083"), false);
    vm.find(nodetool::arg_out_peers.name)->second =
      boost::program_options::variable_value(out_peers, false);

    boost::program_options::notify(vm);
    return d.server->init(vm);
  };

  // Init with an under-floor cap: refused at startup.
  {
    test_data_t data;
    EXPECT_FALSE(init_with_out_peers(data, 4))
      << "--out-peers below the floor must refuse to start, exactly as --tx-proxy does";
  }

  // Init at the floor: accepted; then the runtime path clamps an under-floor
  // request and passes 0 (full outbound stop) and above-floor values through.
  {
    test_data_t data;
    ASSERT_TRUE(init_with_out_peers(data, 12));
    EXPECT_EQ(12u, data.server->get_max_out_public_peers());

    data.server->change_max_out_public_peers(4);
    EXPECT_EQ(12u, data.server->get_max_out_public_peers())
      << "a runtime under-floor request is refused and the cap is unchanged";

    data.server->change_max_out_public_peers(0);
    EXPECT_EQ(0u, data.server->get_max_out_public_peers())
      << "0 (no outbound at all) stays legal — loud isolation, not quiet degradation";

    data.server->change_max_out_public_peers(24);
    EXPECT_EQ(24u, data.server->get_max_out_public_peers());

    data.server->deinit();
  }
}

// ---------------------------------------------------------------------------
// Anonymity-zone address keying (fix/anon-zone-address-keying)
//
// Every inbound connection in an anonymity zone is handed the zone's
// `unknown()` sentinel as its remote address (`net_node.inl` `set_default_remote`,
// one call per zone). `is_same_host` used to report two such addresses as the
// same host, so `drop_connections(addr)` — which severs every connection
// sharing a host — severed the entire inbound anon population on one bad span.
// ---------------------------------------------------------------------------
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

  //! One serialized block whose parent is `crypto::null_hash`, so a `test_core`
  //! holding that hash reports the parent as known and `try_add_next_blocks`
  //! reaches `prepare_handle_incoming_blocks`.
  cryptonote::block_complete_entry one_block(const crypto::hash &parent = crypto::null_hash)
  {
    cryptonote::block b{};
    b.major_version = 1;
    b.minor_version = 1;
    b.prev_id = parent;
    b.miner_tx.version = 1;
    b.miner_tx.unlock_time = 0;
    cryptonote::block_complete_entry bce{};
    bce.block = cryptonote::t_serializable_object_to_blob(b);
    return bce;
  }

  //! The hash of a block that is never added to anything -- only used as a
  //! parent identity the queue can be told about.
  crypto::hash a_parent_hash()
  {
    cryptonote::block b{};
    b.major_version = 1;
    b.minor_version = 1;
    b.nonce = 0xabcdef;
    b.miner_tx.version = 1;
    return cryptonote::get_block_hash(b);
  }

  //! Records what the protocol handler asks the p2p layer to do.
  struct recording_endpoint final
    : nodetool::p2p_endpoint_stub<cryptonote::cryptonote_connection_context>
  {
    std::vector<cryptonote::cryptonote_connection_context> conns;
    std::vector<boost::uuids::uuid> dropped;
    //! Address AND score: the score is what distinguishes a caller that
    //! charges the peer from one that merely disconnects it, and several
    //! call sites differ only in that argument.
    std::vector<std::pair<epee::net_utils::network_address, unsigned>> host_fails;

    void add(const boost::uuids::uuid &id, const epee::net_utils::network_address &addr)
    {
      // `m_connection_id`, `m_remote_address` and `m_is_income` are declared
      // `const` (`contrib/epee/include/net/net_utils_base.h:368-370`), so
      // writing them through a `const_cast` is undefined behaviour. Assigning
      // the base subobject routes through the class's own `set_details`, which
      // rebuilds it by placement-new -- the same path production takes on every
      // connection copy.
      cryptonote::cryptonote_connection_context c{};
      static_cast<epee::net_utils::connection_context_base&>(c) =
        epee::net_utils::connection_context_base{id, addr, /*is_income=*/true, /*ssl=*/false};
      conns.push_back(std::move(c));
    }

    virtual size_t post_each(
      std::function<void(cryptonote::cryptonote_connection_context&, uint32_t)> note,
      std::function<void()> then) override
    {
      for (auto &c : conns)
        note(c, 0);
      if (then)
        then();
      return conns.size();
    }
    virtual bool for_connection(const boost::uuids::uuid &id,
      std::function<void(cryptonote::cryptonote_connection_context&, uint32_t)> f) override
    {
      // Production returns false only when the id is absent. The callback
      // runs on the connection strand and does not report the lookup.
      for (auto &c : conns)
        if (c.m_connection_id == id)
        {
          f(c, 0);
          return true;
        }
      return false;
    }
    virtual bool drop_connection(const epee::net_utils::connection_context_base &context) override
    {
      dropped.push_back(context.m_connection_id);
      return true;
    }
    virtual bool add_host_fail(const epee::net_utils::network_address &address, unsigned int score) override
    {
      // Fidelity: production's `node_server::add_host_fail` opens with
      // `if(!address.is_blockable()) return false;` (`net_node.inl:412`), so an
      // address that names no host is never scored regardless of the caller. A
      // double that recorded unconditionally would be MORE PERMISSIVE than the
      // real endpoint, and a limb asserting the difference would pin the mock
      // rather than the code.
      if (!address.is_blockable())
        return false;
      host_fails.emplace_back(address, score);
      return true;
    }
  };
}

TEST(anon_zone_address_keying, host_sweep_does_not_sever_a_zone)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto unknown_tor = epee::net_utils::network_address{net::tor_address::unknown()};
  const boost::uuids::uuid anon1 = fixed_uuid(1);
  const boost::uuids::uuid anon2 = fixed_uuid(2);
  endpoint.add(anon1, unknown_tor);
  endpoint.add(anon2, unknown_tor);

  // Negative limb: the sweep must sever NOTHING when handed an address that
  // names no host. Before the fix both anon connections were severed, because
  // `unknown()` compared equal to `unknown()`.
  cryptonote_protocol_handler_test_seam::drop_connections(cprotocol, unknown_tor);
  EXPECT_TRUE(endpoint.dropped.empty());
  // Scoring: the mock models production's `is_blockable` bail, so this limb is
  // guaranteed by the double rather than by the fix -- it documents the
  // contract, it does not pin A1. A1's independent observables are the
  // misleading `MWARNING` and the avoided scan; see the PR body.
  EXPECT_TRUE(endpoint.host_fails.empty());

  // Positive limb: the sweep still works where the address DOES name a host,
  // so a guard that over-reached into "never sever" fails loudly here. This is
  // the public-zone per-host cap's behaviour and it must be untouched.
  const auto ip = epee::net_utils::network_address{epee::net_utils::ipv4_network_address{0x0100007f, 18080}};
  const auto ip_other_port = epee::net_utils::network_address{epee::net_utils::ipv4_network_address{0x0100007f, 18081}};
  const boost::uuids::uuid clear1 = fixed_uuid(3);
  endpoint.add(clear1, ip_other_port);

  cryptonote_protocol_handler_test_seam::drop_connections(cprotocol, ip);
  ASSERT_EQ(1u, endpoint.dropped.size());
  EXPECT_EQ(clear1, endpoint.dropped.front());   // the same host, different port
  // The sweep scores the host, and `drop_connection(context, true, ...)` scores
  // each severed peer again, so the count is not 1 -- assert the contract
  // rather than a number: scoring happened, and it never names an address that
  // names no host.
  EXPECT_FALSE(endpoint.host_fails.empty());
  for (const auto &f : endpoint.host_fails)
    EXPECT_TRUE(f.first.is_blockable());
}

// The `prepare_handle_incoming_blocks` failure arm. The host sweep above is
// now a no-op on an anonymity zone, so this site must drop the origin and
// clear its spans by itself -- which is what its two siblings in the same
// function already do. Without that, the failed span stays at the head of the
// queue, `get_next_span` hands it out again, and sync stalls.
TEST(anon_zone_address_keying, prepare_failure_drops_only_the_origin_and_clears_its_spans)
{
  test_core pr_core;
  pr_core.prepare_handle_incoming_blocks_result = false;
  pr_core.blocks_we_have.push_back(crypto::null_hash);   // the span's parent
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto unknown_tor = epee::net_utils::network_address{net::tor_address::unknown()};
  const boost::uuids::uuid anon1 = fixed_uuid(1);
  const boost::uuids::uuid anon2 = fixed_uuid(2);
  endpoint.add(anon1, unknown_tor);
  endpoint.add(anon2, unknown_tor);

  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  // The span that fails, and a LATER one from the same peer. The later span is
  // what distinguishes dropping with `flush_all_spans = true` from the
  // `drop_connection(uuid)` overload's `false`: `remove_spans(id, start_height)`
  // only erases spans at or before `start_height`, so a peer dropped with
  // `false` would leave its higher spans behind.
  queue.add_blocks(1, {one_block()}, anon1, unknown_tor, 1.0f, 1);
  queue.add_blocks(100, {one_block()}, anon1, unknown_tor, 1.0f, 1);
  ASSERT_EQ(2u, queue.get_num_filled_spans());

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  // The offending peer is dropped -- by id, since the host sweep selected
  // nothing -- and the peer that shares its `unknown()` address is not.
  ASSERT_EQ(1u, endpoint.dropped.size());
  EXPECT_EQ(anon1, endpoint.dropped.front());
  EXPECT_EQ(0u, queue.get_num_filled_spans())
    << "the failed span, and every later span from the same peer, must leave "
       "the queue -- otherwise get_next_span hands the failure back forever";
}

// The same site when the peer is already gone: `for_connection` finds nothing,
// so the span must still be removed or it is stuck in the queue with no owner
// left to drop. This is the case the siblings' `remove_spans` call exists for.
TEST(anon_zone_address_keying, prepare_failure_clears_the_span_of_a_departed_peer)
{
  test_core pr_core;
  pr_core.prepare_handle_incoming_blocks_result = false;
  pr_core.blocks_we_have.push_back(crypto::null_hash);
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto unknown_tor = epee::net_utils::network_address{net::tor_address::unknown()};
  const boost::uuids::uuid survivor = fixed_uuid(2);
  const boost::uuids::uuid departed = fixed_uuid(9);   // owns the span, has no connection
  endpoint.add(survivor, unknown_tor);

  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  queue.add_blocks(1, {one_block()}, departed, unknown_tor, 1.0f, 1);
  ASSERT_EQ(1u, queue.get_num_filled_spans());

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  EXPECT_TRUE(endpoint.dropped.empty()) << "there is no such connection to drop";
  EXPECT_EQ(0u, queue.get_num_filled_spans())
    << "removed anyway, so other threads can wake up and get past it";
}

// A span whose start height contradicts the height the queue holds for its
// parent is rejected and its peer dropped -- but dropping by id flushes only
// EMPTY spans, and neither `on_connection_close` nor `flush_stale_spans`
// erases a filled one. Nothing removed this span, so if it sat lowest in the
// queue `get_next_span` re-served it on every call and sync could not pass it.
// Inherited; every sibling failure arm in the same loop already removes its
// span. Same validation surface as the anonymity-zone arm above.
TEST(block_sync_span_lifecycle, an_incorrect_height_span_leaves_the_queue_with_its_peer)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto unknown_tor = epee::net_utils::network_address{net::tor_address::unknown()};
  const boost::uuids::uuid liar = fixed_uuid(4);
  endpoint.add(liar, unknown_tor);

  // Reserve a span at height 50 whose one requested hash is the parent, then
  // fill it. The queue now believes that parent sits AT 50, while the span
  // delivered for it also starts at 50 -- so the block's parent would have to
  // be its own sibling. That is the contradiction the check rejects.
  const crypto::hash parent = a_parent_hash();
  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  const auto reserved = queue.reserve_span(50, 50, 1, liar, unknown_tor,
    /*blockchain_height=*/51, {{parent, 0}}, boost::date_time::min_date_time);
  ASSERT_EQ(50u, reserved.first);
  queue.add_blocks(50, {one_block(parent)}, liar, unknown_tor, 1.0f, 1);
  ASSERT_EQ(1u, queue.get_num_filled_spans());
  ASSERT_EQ(50u, queue.have_height(parent));

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  ASSERT_EQ(1u, endpoint.dropped.size());
  EXPECT_EQ(liar, endpoint.dropped.front());
  EXPECT_EQ(0u, queue.get_num_filled_spans())
    << "the rejected span must leave the queue, or get_next_span serves it "
       "again forever against a peer that is already gone";
}

// A prepare failure IS charged, and this test exists to keep it that way.
//
// `prepare_handle_incoming_blocks` returns false for six of OUR-state reasons
// (`m_cancel`, thread-pool `!waiter.wait()`) and for about as many
// SENDER-attributable ones -- unparseable block blob, unparseable transaction,
// duplicate transaction, duplicate key image, empty span. The boolean cannot
// say which fired, so declining to charge would let a peer feed malformed
// spans forever and reconnect with no score accumulating. An earlier revision
// of this test asserted the opposite, on the premise that the failure was
// always ours; that premise was wrong (review of #628).
//
// Run on a CLEARNET origin, because the endpoint refuses to score a non-host
// address at all and could not observe the difference on an anonymity zone.
TEST(block_sync_span_lifecycle, prepare_failure_charges_the_origin_it_disconnects)
{
  test_core pr_core;
  pr_core.prepare_handle_incoming_blocks_result = false;
  pr_core.blocks_we_have.push_back(crypto::null_hash);
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto ip = epee::net_utils::network_address{epee::net_utils::ipv4_network_address{0x0100007f, 18080}};
  const boost::uuids::uuid origin = fixed_uuid(5);
  endpoint.add(origin, ip);

  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  queue.add_blocks(1, {one_block()}, origin, ip, 1.0f, 1);

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  // Two properties, and the exact number pins both at once.
  //
  //   6 = the sweep's 5 for the host + 1 for the connection it severs.
  //
  // Lower than 6 means the path stopped charging -- the bypass: a peer that
  // reaches this failure with malformed input could then repeat it forever,
  // reconnecting each time with nothing accumulating.
  //
  // Higher than 6 means the origin was billed twice for one failure, because
  // the id-drop below the sweep also passed `add_fail`. The parse-failure
  // sibling passes false for exactly that reason, and an earlier revision of
  // this PR asserted 7 while claiming it was testing "not zero" -- the extra
  // point was redundant and the rationale did not match the assertion.
  unsigned total = 0;
  for (const auto &f : endpoint.host_fails)
    total += f.second;
  EXPECT_EQ(6u, total)
    << "the sweep must charge (an unchargeable failure is one a peer can "
       "repeat forever) and nothing may charge a second time for it";
  EXPECT_FALSE(endpoint.dropped.empty()) << "but the origin is still disconnected";
}

// The other half of the same site, and the reason PWD-B7 made the verdict a
// TYPE. A prepare failure that describes OUR OWN broken invariant --
// `tx_index is out of sync`, a tx missing from our own scan table, a worker
// that threw -- must neither disconnect the span's origin nor charge it. Under
// the boolean this was indistinguishable from a malformed span, so our own bug
// severed and billed an honest peer.
//
// Three assertions, because removing a punishment is not the whole change:
// the drop is gone, the charge is gone, AND the span still leaves the queue.
// That last one is the limb that matters most. `drop_connection` flushed the
// span as a SIDE EFFECT; now that we do not drop, nothing else would clear it,
// `get_next_span` would hand the same failed span back forever, and sync would
// stall on our own bug instead of recovering from it. The severing being
// removed WAS the recovery -- so the recovery is now explicit and asserted.
//
// Clearnet origin, because the endpoint refuses to score a non-host address
// and could not observe an absent charge on an anonymity zone.
TEST(block_sync_span_lifecycle, prepare_failure_on_our_own_invariant_neither_drops_nor_charges)
{
  test_core pr_core;
  pr_core.prepare_handle_incoming_blocks_result = false;
  pr_core.prepare_handle_incoming_blocks_verdict = SHEKYL_DROP_VERDICT_INTERNAL_FAILURE;
  pr_core.blocks_we_have.push_back(crypto::null_hash);
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto ip = epee::net_utils::network_address{epee::net_utils::ipv4_network_address{0x0100007f, 18080}};
  const boost::uuids::uuid origin = fixed_uuid(5);
  endpoint.add(origin, ip);

  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  queue.add_blocks(1, {one_block()}, origin, ip, 1.0f, 1);
  ASSERT_EQ(1u, queue.get_num_filled_spans());

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  EXPECT_TRUE(endpoint.dropped.empty())
    << "our own broken invariant must not disconnect the peer that happened "
       "to be feeding us when it broke";
  unsigned total = 0;
  for (const auto &f : endpoint.host_fails)
    total += f.second;
  EXPECT_EQ(0u, total) << "and it must not be charged for our bug either";
  EXPECT_EQ(0u, queue.get_num_filled_spans())
    << "but the span must STILL leave the queue -- the drop used to flush it "
       "as a side effect, and removing the drop must not remove the recovery";
}

// Our own cancellation, which is the routine member of the same class: a
// shutdown or a cancelled sync is not a defect and not the sender's, so it is
// neither loud nor chargeable. Separated from the test above because the two
// take different arms of the verdict and only agree on the outcome.
TEST(block_sync_span_lifecycle, prepare_failure_on_our_own_cancellation_neither_drops_nor_charges)
{
  test_core pr_core;
  pr_core.prepare_handle_incoming_blocks_result = false;
  pr_core.prepare_handle_incoming_blocks_verdict = SHEKYL_DROP_VERDICT_POLICY_OR_STATE;
  pr_core.blocks_we_have.push_back(crypto::null_hash);
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto ip = epee::net_utils::network_address{epee::net_utils::ipv4_network_address{0x0100007f, 18080}};
  const boost::uuids::uuid origin = fixed_uuid(5);
  endpoint.add(origin, ip);

  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  queue.add_blocks(1, {one_block()}, origin, ip, 1.0f, 1);

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  EXPECT_TRUE(endpoint.dropped.empty());
  unsigned total = 0;
  for (const auto &f : endpoint.host_fails)
    total += f.second;
  EXPECT_EQ(0u, total);
  EXPECT_EQ(0u, queue.get_num_filled_spans());
}

// And the guard on the whole design: an UNCLASSIFIED failure -- the value a
// `return false` added later carries until someone classifies it -- takes the
// safe arm. This is what "the type is the gate" buys; without it a new
// condition inherits whatever the default happens to be, which is exactly how
// our own storage errors ended up severing peers.
TEST(block_sync_span_lifecycle, an_unclassified_prepare_failure_does_not_drop)
{
  test_core pr_core;
  pr_core.prepare_handle_incoming_blocks_result = false;
  pr_core.prepare_handle_incoming_blocks_verdict = SHEKYL_DROP_VERDICT_UNCLASSIFIED;
  pr_core.blocks_we_have.push_back(crypto::null_hash);
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core, NULL);
  recording_endpoint endpoint;
  cprotocol.set_p2p_endpoint(&endpoint);

  const auto ip = epee::net_utils::network_address{epee::net_utils::ipv4_network_address{0x0100007f, 18080}};
  const boost::uuids::uuid origin = fixed_uuid(5);
  endpoint.add(origin, ip);

  auto &queue = cryptonote_protocol_handler_test_seam::queue(cprotocol);
  queue.add_blocks(1, {one_block()}, origin, ip, 1.0f, 1);

  ASSERT_EQ(1, cryptonote_protocol_handler_test_seam::try_add_next_blocks(cprotocol, endpoint.conns.front()));

  EXPECT_TRUE(endpoint.dropped.empty());
  EXPECT_EQ(0u, queue.get_num_filled_spans());
}

namespace
{
  cryptonote::NOTIFY_NEW_TRANSACTIONS::request two_txs()
  {
    cryptonote::NOTIFY_NEW_TRANSACTIONS::request arg{};
    arg.txs.push_back(cryptonote::blobdata(8, '\x01'));
    arg.txs.push_back(cryptonote::blobdata(8, '\x02'));
    return arg;
  }

  void arm_harness_post(void*, std::uint64_t id, std::uint32_t kind,
      const shekyl_seam_observed*, const std::uint8_t*, std::size_t, const shekyl_close_cause*)
  {
    if (kind != 1)
      return;
    // `open` posts this while it holds the hub lock, then waits until the
    // handler is armed. Arming from this stack would take that lock again.
    std::thread([id] { shekyl_seam_handler_armed(id, 1); }).detach();
  }

  void bind_harness_hub()
  {
    static int ctx = 0;
    shekyl_inbound_ceiling ceiling{};
    shekyl_inbound_ceiling_resolve(0, 0, &ceiling);
    shekyl_seam_bind(&ctx, arm_harness_post, &ceiling);
    shekyl_seam_install_loopback();
  }

  struct NotifyHarness
  {
    test_core core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    recording_endpoint endpoint;
    std::uint64_t socket_id = 0;

    explicit NotifyHarness(bool established = true) : cprotocol(core, NULL)
    {
      cprotocol.set_p2p_endpoint(&endpoint);
      cryptonote_protocol_handler_test_seam::set_synchronized(cprotocol, true);
      bind_harness_hub();
      shekyl_seam_address addr{};
      addr.connector = SHEKYL_CONNECTOR_CLEARNET;
      addr.address_type = SHEKYL_ADDR_IPV4;
      addr.port = 18080;
      addr.len = 4;
      addr.bytes[0] = 127;
      addr.bytes[3] = 1;
      const shekyl_seam_open_result opened = shekyl_seam_open(&addr, 1);
      socket_id = opened.id;
      EXPECT_NE(socket_id, 0u) << "loopback open cause " << static_cast<unsigned>(opened.cause_kind);
      const auto ip = epee::net_utils::network_address{
          epee::net_utils::ipv4_network_address{0x0100007f, 18080}};
      endpoint.add(shekyl::seam_connection_id(socket_id == 0 ? 1 : socket_id), ip);
      if (established && socket_id != 0)
      {
        shekyl_zone_session_established(socket_id);
        endpoint.conns.front().m_state = cryptonote::cryptonote_connection_context::state_normal;
      }
    }

    ~NotifyHarness()
    {
      if (socket_id != 0)
      {
        shekyl_seam_close(socket_id);
        shekyl_seam_reap(socket_id);
      }
      // The relay puppet has no hub. Leaving this one bound would make
      // its sessions look absent. The zone's next listen installs its own.
      shekyl_seam_bind(nullptr, nullptr, nullptr);
    }

    cryptonote::cryptonote_connection_context &ctx() { return endpoint.conns.front(); }

    int notify_txs()
    {
      auto arg = two_txs();
      return cryptonote_protocol_handler_test_seam::handle_notify_new_transactions(
          cprotocol, arg, ctx());
    }

    int notify_block(const cryptonote::blobdata &blob)
    {
      cryptonote::NOTIFY_NEW_COMPACT_BLOCK::request arg{};
      arg.b.block = blob;
      arg.current_blockchain_height = 1;
      return cryptonote_protocol_handler_test_seam::handle_notify_new_compact_block(
          cprotocol, arg, ctx());
    }
  };
}

namespace
{
  // One loopback session on the harness hub, in the direction asked for.
  // The peer lists read that direction from the board by this id.
  struct PeerlistSession
  {
    std::uint64_t socket_id = 0;

    explicit PeerlistSession(bool inbound)
    {
      bind_harness_hub();
      shekyl_seam_address addr{};
      addr.connector = SHEKYL_CONNECTOR_CLEARNET;
      addr.address_type = SHEKYL_ADDR_IPV4;
      addr.port = 18080;
      addr.len = 4;
      addr.bytes[0] = 127;
      addr.bytes[3] = 1;
      const shekyl_seam_open_result opened = shekyl_seam_open(&addr, inbound ? 1 : 0);
      socket_id = opened.id;
      EXPECT_NE(socket_id, 0u) << "loopback open cause " << static_cast<unsigned>(opened.cause_kind);
    }

    ~PeerlistSession()
    {
      if (socket_id != 0)
      {
        shekyl_seam_close(socket_id);
        shekyl_seam_reap(socket_id);
      }
      shekyl_seam_bind(nullptr, nullptr, nullptr);
    }

    bool receive(const std::vector<nodetool::peerlist_entry>& peers) const
    {
      return shekyl::received_peerlist(shekyl::seam_connection_id(socket_id), peers);
    }
  };

  // `count` distinct global addresses. `block` keeps one test's addresses
  // apart from another's: the Rust lists are one per process.
  std::vector<nodetool::peerlist_entry> global_peers(std::uint8_t block, std::size_t count)
  {
    std::vector<nodetool::peerlist_entry> peers;
    for (std::size_t i = 0; i < count; ++i)
      peers.push_back({MAKE_IPV4_ADDRESS_PORT(11, 7, block, static_cast<std::uint8_t>(i + 1), 18080), 100});
    return peers;
  }
}

// The C++ no longer judges a received peerlist. It hands the list to Rust
// as it arrived and closes only on Rust's refusal. A list of exactly the
// receiver limit is accepted and one more entry is refused, so no entry
// was dropped on the way; a bad entry refuses the list wherever it sits,
// so none was reordered away or filtered. `sanitize_peerlist` dropped the
// ip-0 and port-0 entries and kept the rest; under R4 one such entry is
// evidence about the sender and refuses the whole list.
TEST(node_server, a_received_peerlist_reaches_rust_unaltered_and_only_a_refusal_closes)
{
  PeerlistSession session(false);
  ASSERT_NE(session.socket_id, 0u);

  EXPECT_TRUE(session.receive({}));
  EXPECT_TRUE(session.receive(global_peers(1, 12)));
  EXPECT_FALSE(session.receive(global_peers(2, 13)));

  const std::vector<nodetool::peerlist_entry> bad = {
      {MAKE_IPV4_ADDRESS_PORT(0, 0, 0, 0, 18080), 100},      // ip 0
      {MAKE_IPV4_ADDRESS_PORT(5, 6, 7, 8, 0), 100},          // port 0
      {MAKE_IPV4_ADDRESS_PORT(192, 168, 1, 1, 18080), 100},  // private
      {MAKE_IPV4_ADDRESS_PORT(127, 0, 0, 1, 18080), 100},    // loopback
      {net::tor_address::unknown(), 100},                    // not this session's connector
  };
  for (const auto& entry : bad)
  {
    for (const std::size_t at : {std::size_t{0}, std::size_t{1}, std::size_t{2}})
    {
      std::vector<nodetool::peerlist_entry> peers = global_peers(3, 2);
      peers.insert(peers.begin() + at, entry);
      EXPECT_FALSE(session.receive(peers)) << entry.adr.str() << " at " << at;
    }
  }
}

// PWD-I2: a list on an inbound session admits nothing and is not a
// refusal, whatever it holds. The same lists are refused on the outbound
// session above, so the answer here is the direction's, read in Rust from
// the board: this call passes no direction.
// Every exchange is an exchange (Rick, 2026-10-13, §2.5): a list on a
// session the peer opened is admitted under the same limits as one on a
// session this node opened, and refused by the same rules. Records-was
// PWD-I2's direction rule, under which this session's lists admitted
// nothing and nothing closed it.
TEST(node_server, a_peerlist_on_an_inbound_session_is_admitted_under_the_same_limits)
{
  PeerlistSession session(true);
  ASSERT_NE(session.socket_id, 0u);

  EXPECT_TRUE(session.receive(global_peers(4, 12)));
  const shekyl_rpc_peer_facts* rows = nullptr;
  std::size_t len = 0;
  void* owner = nullptr;
  ASSERT_EQ(shekyl_rpc_peer_list(0, &rows, &len, &owner), 0);
  std::size_t admitted = 0;
  for (std::size_t i = 0; i < len; ++i)
    if (std::string(rows[i].host, rows[i].host_len).rfind("11.7.4.", 0) == 0 && rows[i].white == 0)
      ++admitted;
  shekyl_rpc_peer_list_free(owner);
  EXPECT_EQ(admitted, 12u) << "the twelve entered gray from the inbound session";

  EXPECT_FALSE(session.receive(global_peers(5, 13))) << "one over the receiver limit refuses";
  EXPECT_FALSE(session.receive({{MAKE_IPV4_ADDRESS_PORT(192, 168, 1, 1, 18080), 100}})) << "a non-global entry refuses (R4)";
  EXPECT_FALSE(session.receive({{net::tor_address::unknown(), 100}})) << "a foreign-connector entry refuses";
}

// A session the board does not hold has no known direction. Its list
// admits nothing and does not close anything.
TEST(node_server, a_peerlist_on_an_unknown_session_never_closes_it)
{
  PeerlistSession session(false);
  ASSERT_NE(session.socket_id, 0u);
  const boost::uuids::uuid stranger = shekyl::seam_connection_id(session.socket_id + 1000);
  EXPECT_TRUE(shekyl::received_peerlist(stranger, global_peers(6, 13)));
  EXPECT_EQ(shekyl_peerlist_admit_received(session.socket_id + 1000, nullptr, 0), SHEKYL_PEERLIST_NO_SESSION);
  EXPECT_EQ(shekyl_peerlist_admit_received(session.socket_id, nullptr, 0), SHEKYL_PEERLIST_ADMITTED);
  // A null pointer with a count is the caller's fault and closes nothing.
  EXPECT_EQ(shekyl_peerlist_admit_received(session.socket_id, nullptr, 3), SHEKYL_PEERLIST_BAD_ARGUMENT);
}

TEST(attributable_drop, a_form_failure_still_severs_and_abandons_the_batch)
{
  NotifyHarness h;
  h.core.handle_incoming_tx_result = false;
  h.core.handle_incoming_tx_verdict = SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM;
  ASSERT_EQ(1, h.notify_txs());
  EXPECT_EQ(1u, h.endpoint.dropped.size());
  EXPECT_EQ(1u, h.core.handle_incoming_tx_calls);
}

TEST(attributable_drop, an_internal_failure_neither_severs_nor_stops_the_batch)
{
  NotifyHarness h;
  h.core.handle_incoming_tx_result = false;
  h.core.handle_incoming_tx_verdict = SHEKYL_DROP_VERDICT_INTERNAL_FAILURE;
  ASSERT_EQ(1, h.notify_txs());
  EXPECT_TRUE(h.endpoint.dropped.empty());
  EXPECT_EQ(2u, h.core.handle_incoming_tx_calls);
}

TEST(attributable_drop, a_policy_or_state_rejection_neither_severs_nor_stops_the_batch)
{
  NotifyHarness h;
  h.core.handle_incoming_tx_result = false;
  h.core.handle_incoming_tx_verdict = SHEKYL_DROP_VERDICT_POLICY_OR_STATE;
  ASSERT_EQ(1, h.notify_txs());
  EXPECT_TRUE(h.endpoint.dropped.empty());
  EXPECT_EQ(2u, h.core.handle_incoming_tx_calls);
}

TEST(attributable_drop, an_unclassified_rejection_does_not_sever)
{
  NotifyHarness h;
  h.core.handle_incoming_tx_result = false;
  h.core.handle_incoming_tx_verdict = SHEKYL_DROP_VERDICT_UNCLASSIFIED;
  ASSERT_EQ(1, h.notify_txs());
  EXPECT_TRUE(h.endpoint.dropped.empty());
  EXPECT_EQ(2u, h.core.handle_incoming_tx_calls);
}

TEST(attributable_drop, an_oversized_announce_declines_without_severing)
{
  NotifyHarness h;
  h.core.check_incoming_block_size_result = false;
  ASSERT_EQ(1, h.notify_block(cryptonote::blobdata(16, '\x01')));
  EXPECT_TRUE(h.endpoint.dropped.empty());
}

TEST(attributable_drop, an_unparseable_announce_still_severs)
{
  NotifyHarness h;
  ASSERT_EQ(1, h.notify_block(cryptonote::blobdata(16, '\xff')));
  EXPECT_EQ(1u, h.endpoint.dropped.size());
}

// The ingress gate drops only a session that has not finished the
// handshake. A peer that is still synchronising, or paused in standby,
// has completed it, so the batch reaches the core. The node's own sync
// is a separate refusal and does not depend on that peer state.
TEST(tx_ingress, a_handshake_complete_peer_is_admitted)
{
  const cryptonote::cryptonote_connection_context::state states[] = {
    cryptonote::cryptonote_connection_context::state_synchronizing,
    cryptonote::cryptonote_connection_context::state_standby,
    cryptonote::cryptonote_connection_context::state_normal,
  };
  for (const auto state : states)
  {
    SCOPED_TRACE(static_cast<int>(state));
    NotifyHarness h;
    h.ctx().m_state = state;
    EXPECT_EQ(1, h.notify_txs());
    EXPECT_TRUE(h.endpoint.dropped.empty());
    EXPECT_EQ(2u, h.core.handle_incoming_tx_calls);
  }
}

TEST(tx_ingress, a_peer_before_handshake_does_not_reach_the_core)
{
  // The row is on the board and the handshake flag is clear. Covers the
  // gate's "row present, not established" arm. Does not cover a missing hub.
  NotifyHarness h(false);
  h.ctx().m_state = cryptonote::cryptonote_connection_context::state_before_handshake;
  EXPECT_EQ(1, h.notify_txs());
  EXPECT_EQ(0u, h.core.handle_incoming_tx_calls);
  EXPECT_TRUE(h.endpoint.dropped.empty());
}

TEST(tx_ingress, an_unsynchronised_node_ignores_the_batch)
{
  NotifyHarness h;
  cryptonote_protocol_handler_test_seam::set_synchronized(h.cprotocol, false);
  EXPECT_EQ(1, h.notify_txs());
  EXPECT_EQ(0u, h.core.handle_incoming_tx_calls);
  EXPECT_TRUE(h.endpoint.dropped.empty());
}

// The endpoint advertisement is DERIVED: no dedicated flag decides it, so the
// only witness is the announced value itself. Operator influence remains and is
// exercised below -- `--in-peers 0` suppresses the announcement BY DERIVATION,
// which is the supported control and the second limb of this test.
//
// The middle limb is the defect this replaced. `check_incoming_connections`
// has always treated "no inbound accepted" as "not advertising"; the
// announcement site asked only whether `--hide-my-port` was set, so a node run
// with `--in-peers 0` refused every inbound connection and still announced a
// port to attract them. Nothing in the tree observed that, which is why the
// two sites could diverge silently.
TEST(node_server, announced_port_is_derived_from_listener_and_zone)
{
  struct test_data_t
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;
    test_data_t(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
  };

  const auto announced = [](const std::string &port, const std::string &in_peers) {
    test_data_t data;
    boost::program_options::options_description desc_options("Command line options");
    cryptonote::core::init_options(desc_options);
    Server::init_options(desc_options);
    const char* argv[2] = {nullptr, nullptr};
    boost::program_options::variables_map vm;
    boost::program_options::store(
      boost::program_options::parse_command_line(1, argv, desc_options), vm);
    vm.find(nodetool::arg_p2p_bind_ip.name)->second =
      boost::program_options::variable_value(std::string("127.0.0.2"), false);
    vm.find(nodetool::arg_p2p_bind_port.name)->second =
      boost::program_options::variable_value(port, false);
    if (!in_peers.empty())
      vm.find(nodetool::arg_in_peers.name)->second =
        boost::program_options::variable_value(int64_t(std::stoll(in_peers)), false);
    boost::program_options::notify(vm);
    if (!data.server->init(vm))
      return uint32_t(0xffffffff);   // distinguishable from a real 0
    return data.server->get_announced_port(epee::net_utils::connector_id::clearnet);
  };

  // Accepting inbound on a pingback-capable zone: announce the listening port.
  EXPECT_EQ(48086u, announced("48086", ""))
    << "a reachable node must advertise, and nothing but the facts decides it";

  // The corrected divergence: no inbound accepted, so nothing to advertise.
  EXPECT_EQ(0u, announced("48087", "0"))
    << "a node that refuses every inbound connection must not announce a port "
       "for peers to attract themselves to";
}

// ---------------------------------------------------------------------------
// PWD-I7 — the inbound SAFETY bound
//
// `--in-peers` used to narrow its `-1` sentinel straight into a `uint32_t`,
// so an unset flag meant a ceiling of UINT32_MAX and the check never fired.
// That became the only inbound bound when the per-host cap was deleted.
//
// The replacement is a decision Rust returns from a descriptor probe.
// These tests pin the C++ half: an unset `--in-peers` stores that decision,
// and an explicit value — including `0` — is stored as given. `0` is a legal
// operator choice meaning "refuse every inbound connection" and cannot
// double as "unset", which is why the descriptor is signed.
// ---------------------------------------------------------------------------

namespace
{
  struct in_peers_fixture
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;

    in_peers_fixture(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }

    // The PRODUCTION init path: the real descriptor through the real parser.
    // `in_peers < 0` leaves the flag unset, so the sentinel stands.
    bool init(const char* port, const int in_peers)
    {
      boost::program_options::options_description desc_options("Command line options");
      cryptonote::core::init_options(desc_options);
      Server::init_options(desc_options);

      const char* argv[2] = {nullptr, nullptr};
      boost::program_options::variables_map vm;
      boost::program_options::store(
        boost::program_options::parse_command_line(1, argv, desc_options), vm);

      // 127.0.0.2 for the same TIME_WAIT reason as bind_same_p2p_port above.
      vm.find(nodetool::arg_p2p_bind_ip.name)->second =
        boost::program_options::variable_value(std::string("127.0.0.2"), false);
      vm.find(nodetool::arg_p2p_bind_port.name)->second =
        boost::program_options::variable_value(std::string(port), false);
      if (in_peers >= 0)
        vm.find(nodetool::arg_in_peers.name)->second =
          boost::program_options::variable_value(static_cast<std::int64_t>(in_peers), false);

      boost::program_options::notify(vm);
      return server->init(vm);
    }
  };
}

TEST(node_server, in_peers_sentinel_resolves_to_a_bounded_ceiling)
{
  // Red edit: make `apply_inbound_ceiling` return before storing a bounded
  // decision, so the unset sentinel stays at the counter maximum. This fails.
  in_peers_fixture d;
  ASSERT_TRUE(d.init("48090", -1));

  const uint32_t ceiling = d.server->get_max_in_public_peers();
  EXPECT_NE(std::numeric_limits<uint32_t>::max(), ceiling)
    << "an unset --in-peers must not resolve to an unbounded interval";
  EXPECT_GT(ceiling, 0u)
    << "a machine with a normal descriptor limit has inbound headroom";
}

TEST(node_server, in_peers_explicit_value_bypasses_the_derivation)
{
  // The operator's number is not a starting point for the bound -- it IS the
  // bound. A derivation that overrode it would silently discard the one
  // input that is a choice rather than a reading.
  in_peers_fixture d;
  ASSERT_TRUE(d.init("48091", 1));
  EXPECT_EQ(1u, d.server->get_max_in_public_peers());
}

TEST(node_server, in_peers_above_the_descriptor_ceiling_is_refused)
{
  in_peers_fixture probe;
  ASSERT_TRUE(probe.init("48094", -1));
  const uint32_t derived = probe.server->get_max_in_public_peers();
  if (derived == std::numeric_limits<uint32_t>::max())
    return;
  in_peers_fixture over;
  EXPECT_FALSE(over.init("48095", static_cast<int>(derived) + 1));
}

TEST(node_server, in_peers_zero_is_a_choice_and_not_the_sentinel)
{
  // The reason the descriptor is SIGNED. `0` means "refuse every inbound
  // connection", which is legal and distinct from "unset"; an unsigned type
  // could not carry both and the sentinel would have to steal a real value.
  in_peers_fixture d;
  ASSERT_TRUE(d.init("48092", 0));
  EXPECT_EQ(0u, d.server->get_max_in_public_peers())
    << "--in-peers 0 must survive as itself, not be re-derived";
}

TEST(node_server, in_peers_ceiling_re_derives_when_the_outbound_reserve_changes)
{
  // The outbound cap is a TERM in the inbound ceiling's reservation, so a
  // runtime `out_peers` change invalidates a ceiling derived against the old
  // one. Without the re-derive, raising out_peers leaves inbound reserved
  // against a smaller outbound budget and live outbound plus inbound can
  // exceed the descriptor limit — the exhaustion the ceiling exists to stop.
  //
  // Red edit: drop the `apply_inbound_ceiling` call at the end of
  // `change_max_out_public_peers`. The ceiling then does not move and the
  // first expectation fails.
  in_peers_fixture d;
  ASSERT_TRUE(d.init("48093", -1));

  const uint32_t before = d.server->get_max_in_public_peers();
  ASSERT_GT(before, 0u) << "the derivation must have produced a real ceiling";

  // Raise the outbound reserve. Every extra promised outbound descriptor is
  // one fewer the process may spend on inbound.
  const size_t raised = 256;
  d.server->change_max_out_public_peers(raised);
  const uint32_t after = d.server->get_max_in_public_peers();

  EXPECT_LT(after, before)
    << "raising the outbound reserve must lower the inbound ceiling";

  // And back down again, to the floor (the dialer refuses below it): the
  // reserve is recomputed, not ratcheted.
  d.server->change_max_out_public_peers(12);
  EXPECT_GT(d.server->get_max_in_public_peers(), after)
    << "lowering the outbound reserve must return the headroom";
}

// The relay harness unbinds the process hub when it returns. A listen
// that remembered the first bind and only refreshed the ceiling then
// found no hub, and every later fixed port in this suite failed at once.
// These two ports are otherwise unused here, so a leftover listener is
// not what a red result is reporting.
TEST(node_server, a_cleared_seam_is_bound_again_on_the_next_listen)
{
  {
    in_peers_fixture first;
    ASSERT_TRUE(first.init("48096", -1));
    first.server->deinit();
  }
  ASSERT_EQ(0, shekyl_seam_bind(nullptr, nullptr, nullptr));
  ASSERT_EQ(0, shekyl_seam_is_bound());

  in_peers_fixture second;
  ASSERT_TRUE(second.init("48097", -1))
    << "the next listen installs the hub again";
  second.server->deinit();
}

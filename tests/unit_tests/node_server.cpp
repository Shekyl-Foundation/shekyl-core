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
  bool init() {return true ;}
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

namespace
{
  // A private --data-dir for a test that runs node_server::init. The
  // daemon's default is the operator's real data directory, whose
  // p2pstate.bin init_config would read and whose peerlist a test must
  // neither depend on nor rewrite.
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
  /// The snapshot the real Rust parse builds from a test argument list
  /// (DAEMON_CONFIG_CUTOVER.md §2.9, rule 26 B2), in the grammar's
  /// spellings; freed with the holder.
  struct test_snapshot
  {
    ShekylDaemonSnapshot *snapshot = nullptr;
    explicit test_snapshot(const std::vector<std::string>& args)
    {
      std::vector<const char*> argv;
      argv.push_back("unit_tests");
      for (const auto& a : args)
        argv.push_back(a.c_str());
      const int rc = shekyl_daemon_snapshot_parse(static_cast<int>(argv.size()), argv.data(), &snapshot);
      if (rc != 0 || snapshot == nullptr)
        throw std::runtime_error("the test snapshot could not be built (status " + std::to_string(rc) + ")");
    }
    ~test_snapshot() { shekyl_daemon_snapshot_free(snapshot); }
    test_snapshot(const test_snapshot&) = delete;
    test_snapshot& operator=(const test_snapshot&) = delete;
    const ShekylDaemonSnapshot& get() const { return *snapshot; }
  };

  /// An offline node at `node_dir`: both connectors off, then `extra_args`.
  std::vector<std::string> offline_node_args(const boost::filesystem::path& node_dir, std::vector<std::string> extra_args)
  {
    std::vector<std::string> args{"--data-dir", node_dir.string(), "--clearnet", "off", "--tor", "off"};
    args.insert(args.end(), extra_args.begin(), extra_args.end());
    return args;
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

  const test_snapshot offline(offline_node_args(node_dir, {}));
  ASSERT_TRUE(server.init(offline.get()));
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

namespace nodetool { template class node_server<cryptonote::t_cryptonote_protocol_handler<test_core>>; }
namespace cryptonote { template class t_cryptonote_protocol_handler<test_core>; }

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
      std::function<void(cryptonote::cryptonote_connection_context&)> note,
      std::function<void()> then) override
    {
      for (auto &c : conns)
        note(c);
      if (then)
        then();
      return conns.size();
    }
    virtual bool for_connection(const boost::uuids::uuid &id,
      std::function<void(cryptonote::cryptonote_connection_context&)> f) override
    {
      // Production returns false only when the id is absent. The callback
      // runs on the connection strand and does not report the lookup.
      for (auto &c : conns)
        if (c.m_connection_id == id)
        {
          f(c);
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
    shekyl_seam_bind(&ctx, arm_harness_post);
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
      shekyl_seam_bind(nullptr, nullptr);
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
      shekyl_seam_bind(nullptr, nullptr);
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
      peers.push_back({MAKE_IPV4_ADDRESS_PORT(11, 7, block, static_cast<std::uint8_t>(i + 1), 18080)});
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
      {MAKE_IPV4_ADDRESS_PORT(0, 0, 0, 0, 18080)},      // ip 0
      {MAKE_IPV4_ADDRESS_PORT(5, 6, 7, 8, 0)},          // port 0
      {MAKE_IPV4_ADDRESS_PORT(192, 168, 1, 1, 18080)},  // private
      {MAKE_IPV4_ADDRESS_PORT(127, 0, 0, 1, 18080)},    // loopback
      {net::tor_address::unknown()},                    // not this session's connector
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
  EXPECT_FALSE(session.receive({{MAKE_IPV4_ADDRESS_PORT(192, 168, 1, 1, 18080)}})) << "a non-global entry refuses (R4)";
  EXPECT_FALSE(session.receive({{net::tor_address::unknown()}})) << "a foreign-connector entry refuses";
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

namespace
{
  struct init_fixture
  {
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
    std::unique_ptr<Server> server;
    init_fixture(): cprotocol(pr_core, NULL)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
    bool init()
    {
      // The defaults: mainnet, both connectors on; the harness binds no
      // seam and starts no zone, so nothing dials. The relay's posture is
      // the daemon's Rust main()'s to record; this harness records it, as
      // levin.cpp's does, so the init does not depend on an earlier test.
      shekyl_relay_posture_record(
        (std::uint32_t{1} << SHEKYL_CONNECTOR_CLEARNET) | (std::uint32_t{1} << SHEKYL_CONNECTOR_TOR), false);
      const test_snapshot defaults(std::vector<std::string>{});
      return server->init(defaults.get());
    }
  };
}

// The relay harness unbinds the process hub when it returns. A listen
// that remembered the first bind and only refreshed the ceiling then
// found no hub, and every later fixed port in this suite failed at once.
// These two ports are otherwise unused here, so a leftover listener is
// not what a red result is reporting.
TEST(node_server, a_cleared_seam_is_bound_again_on_the_next_init)
{
  {
    init_fixture first;
    ASSERT_TRUE(first.init());
    first.server->deinit();
  }
  ASSERT_EQ(0, shekyl_seam_bind(nullptr, nullptr));
  ASSERT_EQ(0, shekyl_seam_is_bound());

  init_fixture second;
  ASSERT_TRUE(second.init())
    << "the next init binds the hub again";
  ASSERT_NE(0, shekyl_seam_is_bound());
  second.server->deinit();
}

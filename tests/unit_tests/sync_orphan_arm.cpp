// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// C2-R1c-Q3b, the behavioral pin: the sync-loop orphan arm re-syncs and
// never punishes, while the queue-bookkeeping-mismatch arm keeps its
// teeth. The defect's race ("parent known at the span pre-check, gone at
// the add" -- a checkpoint-rollback discard or an operator pop between
// the two) cannot be scheduled deterministically through real state, so
// the scripted core reproduces its OBSERVABLE instead: have_block
// answers true at the pre-check and handle_incoming_block returns the
// orphan verdict, every run, no timing. Two vectors, and the pair is
// the point: vector 1 alone would pass a fix that stops punishing
// everywhere; vector 2 is what proves the SPLIT the ruling made.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <atomic>
#include <cstring>
#include <functional>
#include <stdexcept>

#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/nil_generator.hpp>

#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.inl"
#include "p2p/net_node_common.h"

namespace cryptonote {
  class blockchain_storage;
}

namespace
{

// The full member surface t_cryptonote_protocol_handler<t_core>
// instantiates (mirrors tests/unit_tests/node_server.cpp's test_core),
// with the five sync-span methods scriptable.
class scripted_core
{
public:
  // --- scripted members (the sync-span surface) ---
  std::function<bool(const crypto::hash&)> have_block_fn;
  std::function<void(cryptonote::block_verification_context&)> incoming_block_fn;
  uint64_t chain_height = 1;
  uint64_t target_height = 1;
  size_t prepare_calls = 0;
  size_t cleanup_calls = 0;
  size_t incoming_block_calls = 0;

  bool have_block(const crypto::hash& id, int *where = NULL) const
  { return have_block_fn ? have_block_fn(id) : false; }
  bool have_block_unlocked(const crypto::hash& id, int *where = NULL) const
  { return have_block(id, where); }
  uint64_t get_current_blockchain_height() const { return chain_height; }
  bool prepare_handle_incoming_blocks(const std::vector<cryptonote::block_complete_entry> &blocks_entry, std::vector<cryptonote::block> &blocks)
  { ++prepare_calls; return true; }
  bool cleanup_handle_incoming_blocks(bool force_sync = false)
  { ++cleanup_calls; return true; }
  bool handle_incoming_block(const cryptonote::blobdata& block_blob, const cryptonote::block *block, cryptonote::block_verification_context& bvc, cryptonote::block_connect_supplement& connect, bool update_miner_blocktemplate = true)
  {
    ++incoming_block_calls;
    if (incoming_block_fn) incoming_block_fn(bvc);
    return true;
  }
  bool handle_incoming_block(const cryptonote::blobdata& block_blob, const cryptonote::block *block, cryptonote::block_verification_context& bvc, bool update_miner_blocktemplate = true)
  {
    cryptonote::block_connect_supplement connect{};
    return handle_incoming_block(block_blob, block, bvc, connect, update_miner_blocktemplate);
  }

  // --- inert remainder, per node_server.cpp's test_core ---
  bool is_synchronized() const { return false; }
  void on_synchronized(){}
  void safesyncmode(const bool){}
  void set_target_blockchain_height(uint64_t) {}
  bool init(const boost::program_options::variables_map& vm) { return true; }
  bool deinit(){ return true; }
  bool get_short_chain_history(std::list<crypto::hash>& ids, uint64_t& current_height) const
  { ids.push_back(crypto::null_hash); current_height = chain_height; return true; }
  void get_blockchain_top(uint64_t& height, crypto::hash& top_id) const { height = chain_height ? chain_height - 1 : 0; top_id = crypto::null_hash; }
  bool handle_incoming_tx(const cryptonote::blobdata& tx_blob, cryptonote::tx_verification_context& tvc, cryptonote::relay_method tx_relay, bool relayed, epee::net_utils::zone origin_zone) { return true; }
  bool handle_single_incoming_block(const cryptonote::blobdata& block_blob, const cryptonote::block *b, cryptonote::block_verification_context& bvc, cryptonote::block_connect_supplement& connect, bool update_miner_blocktemplate = true) { return true; }
  void pause_mine(){}
  void resume_mine(){}
  bool on_idle(){ return true; }
  bool find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, bool clip_pruned, cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp){ return true; }
  bool handle_get_objects(cryptonote::NOTIFY_REQUEST_GET_OBJECTS::request& arg, cryptonote::NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote::cryptonote_connection_context& context){ return true; }
  cryptonote::blockchain_storage &get_blockchain_storage() { throw std::runtime_error("scripted_core: get_blockchain_storage must not be reached"); }
  bool get_test_drop_download() const { return true; }
  bool get_test_drop_download_height() const { return true; }
  bool check_incoming_block_size(const cryptonote::blobdata& block_blob) const { return true; }
  bool update_checkpoints(const bool skip_dns = false) { return true; }
  uint64_t get_target_blockchain_height() const { return target_height; }
  size_t get_block_sync_size(uint64_t height) const { return BLOCKS_SYNCHRONIZING_DEFAULT_COUNT; }
  void on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, cryptonote::relay_method tx_relay, epee::net_utils::zone) {}
  void on_stem_propagated(epee::span<const crypto::hash>) {}
  cryptonote::network_type get_nettype() const { return cryptonote::MAINNET; }
  bool get_pool_transaction(const crypto::hash& id, cryptonote::blobdata& tx_blob, cryptonote::relay_category tx_category) const { return false; }
  bool pool_has_tx(const crypto::hash &txid) const { return false; }
  bool get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata, cryptonote::block>>& blocks, std::vector<cryptonote::blobdata>& txs) const { return false; }
  bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned = false) const { return false; }
  bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::transaction>& txs, std::vector<crypto::hash>& missed_txs) const { return false; }
  bool get_block_by_hash(const crypto::hash &h, cryptonote::block &blk, bool *orphan = NULL) const { return false; }
  cryptonote::blobdata get_block_attestation_witness(const cryptonote::block &blk) const { return {}; }
  uint8_t get_ideal_hard_fork_version() const { return 0; }
  uint8_t get_ideal_hard_fork_version(uint64_t height) const { return 0; }
  uint8_t get_hard_fork_version(uint64_t height) const { return 0; }
  uint64_t get_earliest_ideal_height_for_version(uint8_t version) const { return 0; }
  cryptonote::difficulty_type get_block_cumulative_difficulty(uint64_t height) const { return 0; }
  bool pad_transactions() { return false; }
  uint32_t get_blockchain_pruning_seed() const { return 0; }
  bool prune_blockchain(uint32_t pruning_seed = 0) { return true; }
  bool get_txpool_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes) { return false; }
  bool get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_unrelayed_txes = true) const { return false; }
  crypto::hash get_block_id_by_height(uint64_t height) const { return crypto::null_hash; }
  void stop() {}
};

// Records every punitive endpoint call; serves a synthetic context so
// uuid-addressed drops exercise their lambda instead of vanishing.
struct recording_p2p : nodetool::p2p_endpoint_stub<cryptonote::cryptonote_connection_context>
{
  std::atomic<size_t> drops{0};
  std::atomic<size_t> host_fails{0};
  std::atomic<size_t> chain_requests{0};
  std::atomic<size_t> object_requests{0};
  cryptonote::cryptonote_connection_context lambda_ctx{};

  bool drop_connection(const epee::net_utils::connection_context_base& context) override
  { ++drops; return true; }
  bool invoke_notify_to_peer(int command, epee::levin::message_writer message, const epee::net_utils::connection_context_base& context) override
  {
    if (command == cryptonote::NOTIFY_REQUEST_CHAIN::ID)
      ++chain_requests;
    if (command == cryptonote::NOTIFY_REQUEST_GET_OBJECTS::ID)
      ++object_requests;
    return true;
  }
  bool add_host_fail(const epee::net_utils::network_address &address, unsigned int score) override
  { ++host_fails; return true; }
  bool for_connection(const boost::uuids::uuid&, std::function<bool(cryptonote::cryptonote_connection_context&, nodetool::peerid_type, uint32_t)> f) override
  { f(lambda_ctx, 0, 0); return true; }
};

cryptonote::block_complete_entry make_entry(uint64_t height, const crypto::hash& prev, crypto::hash* out_hash = nullptr)
{
  cryptonote::block b{};
  b.major_version = 3;
  b.minor_version = 3;
  b.timestamp = 1000 + height;
  b.prev_id = prev;
  b.miner_tx.version = 3;
  cryptonote::txin_gen in;
  in.height = height;
  b.miner_tx.vin.push_back(in);
  b.miner_tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
  if (out_hash)
    *out_hash = cryptonote::get_block_hash(b);
  cryptonote::block_complete_entry e;
  e.block = cryptonote::block_to_blob(b);
  return e;
}

struct rig
{
  scripted_core core;
  recording_p2p p2p;
  cryptonote::t_cryptonote_protocol_handler<scripted_core> handler;
  cryptonote::cryptonote_connection_context ctx{};

  rig() : handler(core, &p2p, /*offline=*/true)
  {
    ctx.m_state = cryptonote::cryptonote_connection_context::state_synchronizing;
  }
};

} // namespace

TEST(sync_orphan_arm, orphan_is_resync_not_misconduct)
{
  rig r;
  r.core.chain_height = 100;
  r.core.target_height = 500; // mid-IBD: the arm must put the download BACK in motion

  // A LIVE mid-sync context, not a fresh one: the pre-orphan negotiation
  // left needed-object hashes and a high last-response watermark behind.
  // If the arm re-enters the download without resetting them,
  // request_missing_objects continues requesting the detached window
  // instead of re-walking the chain from the current tip.
  r.ctx.m_remote_blockchain_height = 500;
  r.ctx.m_last_response_height = 460;
  for (int i = 0; i < 5; ++i)
  {
    crypto::hash stale;
    memset(&stale, 0x50 + i, sizeof(stale));
    r.ctx.m_needed_objects.emplace_back(stale, 101 + i);
  }

  crypto::hash parent;
  memset(&parent, 0x21, sizeof(parent));
  // Parent "known" at the span pre-check; the scripted orphan verdict at
  // the add is the race's observable (our store lost it in between).
  r.core.have_block_fn = [&](const crypto::hash& id) { return id == parent; };
  r.core.incoming_block_fn = [](cryptonote::block_verification_context& bvc) {
    bvc.m_marked_as_orphaned = true;
  };

  const boost::uuids::uuid span_id = {{1}};
  const epee::net_utils::network_address addr{};
  std::vector<cryptonote::block_complete_entry> span{ make_entry(100, parent) };
  r.handler.m_block_queue.add_blocks(100, span, span_id, addr, 0.0f, span[0].block.size());

  r.handler.try_add_next_blocks(r.ctx);

  EXPECT_EQ(1u, r.core.incoming_block_calls) << "the add was never driven -- the rig broke, not the arm";
  EXPECT_EQ(0u, r.p2p.drops.load())
      << "C2-R1c-Q3b: an in-loop orphan is OUR state (degradation/re-sync), never peer misconduct";
  EXPECT_EQ(0u, r.p2p.host_fails.load())
      << "no host-fail scoring on the orphan arm";
  EXPECT_GE(r.core.cleanup_calls, 1u) << "the arm must still clean up the incoming-blocks batch";
  uint64_t h; std::vector<cryptonote::block_complete_entry> b; boost::uuids::uuid u; epee::net_utils::network_address a;
  EXPECT_FALSE(r.handler.m_block_queue.get_next_span(h, b, u, a)) << "the span must be removed for re-request";
  // The Bugbot finding: not punishing is only half the arm's job -- the
  // download must be put BACK IN MOTION on this context, because the
  // response handler cleared m_last_request_time and the idle kicker
  // selects only contexts with a live request time; a bare return leaves
  // the connection synchronizing-and-silent forever. The arm must
  // re-enter the shared back-to-download path.
  EXPECT_GE(r.p2p.chain_requests.load(), 1u)
      << "the orphan arm must re-request the chain from the current tip";
  EXPECT_TRUE(r.ctx.m_last_request_time != boost::date_time::not_a_date_time)
      << "a live request time is what keeps the idle kicker able to see this context";
  // Round-2 Bugbot finding: without the sibling arm's context reset, the
  // stale pre-orphan hashes are requested as objects instead of the
  // chain being re-walked -- the download resumes on the detached window.
  EXPECT_EQ(0u, r.p2p.object_requests.load())
      << "stale pre-orphan needed-objects must not be re-requested";
  EXPECT_TRUE(r.ctx.m_needed_objects.empty())
      << "the arm must clear the dead negotiation's needed-objects";
}

TEST(sync_orphan_arm, bookkeeping_mismatch_keeps_teeth)
{
  rig r;
  r.core.chain_height = 100;

  // Parent unknown to the store, and the peer's OWN span data places it
  // at a height inconsistent with the span start: self-inconsistent peer
  // data, the one pre-add arm that is genuinely peer-attributable.
  crypto::hash parent_hash;
  memset(&parent_hash, 0x37, sizeof(parent_hash));
  const boost::uuids::uuid span_id = {{2}};
  const boost::uuids::uuid other_id = {{3}};
  const epee::net_utils::network_address addr{};
  r.core.have_block_fn = [](const crypto::hash&) { return false; };
  r.core.incoming_block_fn = [](cryptonote::block_verification_context&) {};

  // Plant the peer bookkeeping: `have_blocks` fills when a hashed
  // reservation is FILLED, so reserve a span at 299 whose hash list
  // names the parent there, then fill it -- the queue now "knows" the
  // parent at height 299 while the target span claims it at 99.
  r.handler.m_block_queue.reserve_span(299, 299, 1, other_id, addr,
      false, 0, 0, 400, {{parent_hash, 299}}, boost::posix_time::microsec_clock::universal_time());
  std::vector<cryptonote::block_complete_entry> filler{ make_entry(299, crypto::null_hash) };
  r.handler.m_block_queue.add_blocks(299, filler, other_id, addr, 0.0f, filler[0].block.size());

  // The target span at 100 (lowest height, processed first): its first
  // block's parent contradicts the queue's own record (299+1 != 100).
  std::vector<cryptonote::block_complete_entry> span{ make_entry(100, parent_hash) };
  r.handler.m_block_queue.add_blocks(100, span, span_id, addr, 0.0f, span[0].block.size());

  r.handler.try_add_next_blocks(r.ctx);

  // The scripted short-chain history is non-empty, so the skip path's
  // request_missing_objects cannot produce a confounding drop -- any
  // recorded consequence is attributable to the bookkeeping-mismatch
  // arm alone (the oracle sits on the defect's axis, not a side
  // effect's).
  EXPECT_GE(r.p2p.drops.load() + r.p2p.host_fails.load(), 1u)
      << "self-inconsistent span bookkeeping must keep its consequence (:1407)";
  EXPECT_EQ(0u, r.core.incoming_block_calls)
      << "the mismatch fires before any add -- no state race can beat it";
  EXPECT_EQ(0u, r.core.prepare_calls)
      << "the mismatch fires before the span is even prepared";
}

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

#pragma  once 

#include <memory>
#include <vector>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "net/net_utils_base.h"
#include "net/jsonrpc_structs.h"
#include "core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class core_rpc_server
  {
  public:

    //! §55: relay stem-outcome tallies + the §18.4 floor diagnostic, one JSON
    //! object ({"floor":[...],"tallies":[...]}). Admin-only at the
    //! Rust route (`if !restricted` — unrestricted listener): this endpoint
    //! is the anonymity graph, which Sharma Appendix B spends 50-100 probes
    //! per node to reconstruct. Must not be registered on the restricted
    //! (public) listener.
    std::string stem_tallies_json() const;

    static const command_line::arg_descriptor<std::string, false, true, 2> arg_rpc_bind_port;
    static const command_line::arg_descriptor<std::string> arg_rpc_restricted_bind_port;
    static const command_line::arg_descriptor<bool> arg_restricted_rpc;
    static const command_line::arg_descriptor<std::size_t> arg_rpc_max_connections_per_public_ip;
    static const command_line::arg_descriptor<std::size_t> arg_rpc_max_connections_per_private_ip;
    static const command_line::arg_descriptor<std::size_t> arg_rpc_max_connections;
    static const command_line::arg_descriptor<std::size_t> arg_rpc_response_soft_limit;

    typedef epee::net_utils::connection_context_base connection_context;

    core_rpc_server(
        core& cr
      , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
      );
    ~core_rpc_server();

    static void init_options(boost::program_options::options_description& desc);
    bool init(
        const boost::program_options::variables_map& vm,
        const bool restricted,
        const std::string& port
      );
    //! Reported as 0 here; the live count is owned by the Rust Axum listener
    //! (ConnTracker) and injected into get_info's rpc_connections_count there.
    size_t get_connections_count() const { return 0; }
    network_type nettype() const { return m_core.get_nettype(); }
    // Resolved listen host for this server, valid after init(). Passed to
    // Rust as --rpc-bind-ip / --rpc-restricted-bind-ip; Rust parses it.
    const std::string& get_rpc_bind_ip() const { return m_rpc_bind_ip; }
    // --rpc-bind-ipv6-address (or the restricted twin) when --rpc-use-ipv6 is
    // set; empty otherwise (and until init() runs). Passed to Rust as given.
    const std::string& get_rpc_bind_ipv6() const { return m_rpc_bind_ipv6; }
    const std::vector<std::string>& get_access_control_origins() const {
      return m_access_control_origins;
    }
    // Connection caps (0 = unlimited). Passed to the Rust Axum listener via
    // shekyl_daemon_rpc_start, which validates (ConnLimits::checked) and
    // enforces them; valid after init() runs.
    std::size_t get_rpc_max_connections() const { return m_rpc_max_connections; }
    std::size_t get_rpc_max_connections_per_public_ip() const { return m_rpc_max_connections_per_public_ip; }
    std::size_t get_rpc_max_connections_per_private_ip() const { return m_rpc_max_connections_per_private_ip; }
    // Core access for the Rust submit shims (daemon_submit_ffi.cpp), which
    // resolve pool/blockchain/protocol from the same handle the Axum
    // transport already holds. See DAEMON_SUBMIT_VERDICT.md §4.
    core& get_core() noexcept { return m_core; }
    // P2P access for the RPC facts shims (rpc_facts_ffi.cpp): sync state
    // lives in the protocol handler. See DAEMON_RPC_KV_CUTOVER.md §3.2.
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& get_p2p() noexcept { return m_p2p; }

    bool on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res, const connection_context *ctx = NULL);
    bool on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res, const connection_context *ctx = NULL);
    bool on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res, const connection_context *ctx = NULL);
    bool on_get_hashes(const COMMAND_RPC_GET_HASHES_FAST::request& req, COMMAND_RPC_GET_HASHES_FAST::response& res, const connection_context *ctx = NULL);
    bool on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res, const connection_context *ctx = NULL);
    bool on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res, const connection_context *ctx = NULL);
    bool on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res, const connection_context *ctx = NULL);
    bool on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res, const connection_context *ctx = NULL);
    bool on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res, const connection_context *ctx = NULL);
    bool on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res, const connection_context *ctx = NULL);
    bool on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, const connection_context *ctx = NULL);
    bool on_get_net_stats(const COMMAND_RPC_GET_NET_STATS::request& req, COMMAND_RPC_GET_NET_STATS::response& res, const connection_context *ctx = NULL);
    bool on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res, const connection_context *ctx = NULL);
    bool on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res, const connection_context *ctx = NULL);
    bool on_set_log_hash_rate(const COMMAND_RPC_SET_LOG_HASH_RATE::request& req, COMMAND_RPC_SET_LOG_HASH_RATE::response& res, const connection_context *ctx = NULL);
    bool on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res, const connection_context *ctx = NULL);
    bool on_set_log_categories(const COMMAND_RPC_SET_LOG_CATEGORIES::request& req, COMMAND_RPC_SET_LOG_CATEGORIES::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool_hashes_bin(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res, const connection_context *ctx = NULL);
    bool on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res, const connection_context *ctx = NULL);
    bool on_get_limit(const COMMAND_RPC_GET_LIMIT::request& req, COMMAND_RPC_GET_LIMIT::response& res, const connection_context *ctx = NULL);
    bool on_set_limit(const COMMAND_RPC_SET_LIMIT::request& req, COMMAND_RPC_SET_LIMIT::response& res, const connection_context *ctx = NULL);
    bool on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res, const connection_context *ctx = NULL);
    bool on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res, const connection_context *ctx = NULL);
    bool on_pop_blocks(const COMMAND_RPC_POP_BLOCKS::request& req, COMMAND_RPC_POP_BLOCKS::response& res, const connection_context *ctx = NULL);
    
    //json_rpc
    bool on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res, const connection_context *ctx = NULL);
    bool on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_getminerdata(const COMMAND_RPC_GETMINERDATA::request& req, COMMAND_RPC_GETMINERDATA::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_calcpow(const COMMAND_RPC_CALCPOW::request& req, COMMAND_RPC_CALCPOW::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_add_aux_pow(const COMMAND_RPC_ADD_AUX_POW::request& req, COMMAND_RPC_ADD_AUX_POW::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_generateblocks(const COMMAND_RPC_GENERATEBLOCKS::request& req, COMMAND_RPC_GENERATEBLOCKS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_inject_archival_serve_credit(const COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT::request& req, COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_hard_fork_info(const COMMAND_RPC_HARD_FORK_INFO::request& req, COMMAND_RPC_HARD_FORK_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_set_bans(const COMMAND_RPC_SETBANS::request& req, COMMAND_RPC_SETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_output_histogram(const COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request& req, COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_base_fee_estimate(const COMMAND_RPC_GET_BASE_FEE_ESTIMATE::request& req, COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_txpool_backlog(const COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_prune_blockchain(const COMMAND_RPC_PRUNE_BLOCKCHAIN::request& req, COMMAND_RPC_PRUNE_BLOCKCHAIN::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_curve_tree_path(const COMMAND_RPC_GET_CURVE_TREE_PATH::request& req, COMMAND_RPC_GET_CURVE_TREE_PATH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_curve_tree_info(const COMMAND_RPC_GET_CURVE_TREE_INFO::request& req, COMMAND_RPC_GET_CURVE_TREE_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_curve_tree_checkpoint(const COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT::request& req, COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_archival_emission_claim_source(const COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::request& req, COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    //-----------------------
    bool is_restricted() const { return m_restricted; }

private:
    bool check_core_busy();
    bool check_core_ready();
    bool add_host_fail(const connection_context *ctx, unsigned int score = 1);

    //utils
    uint64_t get_block_reward(const block& blk);
    bool fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash);
    bool get_block_template(const account_public_address &address, const cryptonote::blobdata &extra_nonce, size_t &reserved_offset, cryptonote::difficulty_type &difficulty, uint64_t &height, uint64_t &expected_reward, block &b, uint64_t &seed_height, crypto::hash &seed_hash, crypto::hash &next_seed_hash, epee::json_rpc::error &error_resp);

    core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& m_p2p;
    bool m_restricted;
    epee::critical_section m_host_fails_score_lock;
    std::map<std::string, uint64_t> m_host_fails_score;
    bool disable_rpc_ban;
    // Resolved listen hosts for this server (restricted variant uses its own).
    // Recorded in init(); Rust parses and binds.
    std::string m_rpc_bind_ip;
    std::string m_rpc_bind_ipv6; // empty = --rpc-use-ipv6 off
    // CORS allow-list from --rpc-access-control-origins (empty = deny).
    std::vector<std::string> m_access_control_origins;
    // Connection caps (0 = unlimited); set in init(), enforced by the Rust
    // Axum listener.
    std::size_t m_rpc_max_connections = 0;
    std::size_t m_rpc_max_connections_per_public_ip = 0;
    std::size_t m_rpc_max_connections_per_private_ip = 0;
  };
}

BOOST_CLASS_VERSION(nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >, 1);

// Copyright (c) 2025-2026, The Shekyl Foundation
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

#include <boost/preprocessor/stringize.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <filesystem>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "core_rpc_server.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/perf_timer.h"
#include "int-util.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"
#include "fcmp/ct_ops.h"
#include "cryptonote_basic/merge_mining.h"
#include "misc_language.h"
#include "net/local_ip.h"
#include "net/parse.h"
#include "crypto/hash.h"
#include "rpc/archival_claim_source.h"
#include "rpc/rpc_args.h"
#include "rpc/rpc_handler.h"
#include "core_rpc_server_error_codes.h"
#include "p2p/net_node.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc"

#define MAX_RESTRICTED_FAKE_OUTS_COUNT 40
#define MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT 5000

#define OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION (3 * 86400) // 3 days max, the wallet requests 1.8 days

#define RESTRICTED_BLOCK_HEADER_RANGE 1000
#define RESTRICTED_TRANSACTIONS_COUNT 100
#define RESTRICTED_SPENT_KEY_IMAGES_COUNT 5000
#define RESTRICTED_BLOCK_COUNT 1000

// Performance logging for RPC handlers. The credit/payment accounting that
// previously rode alongside this (the RPCTracker aggregation feeding the
// rpc_access_tracking endpoint) was removed with the RPC-payment subsystem;
// PERF_TIMER retains the per-handler timing log.
#define RPC_TRACKER(rpc) PERF_TIMER(rpc)

namespace
{
  uint64_t round_up(uint64_t value, uint64_t quantum)
  {
    return (value + quantum - 1) / quantum * quantum;
  }

  void store_128(boost::multiprecision::uint128_t value, uint64_t &slow64, std::string &swide, uint64_t &stop64)
  {
    slow64 = (value & 0xffffffffffffffff).convert_to<uint64_t>();
    swide = cryptonote::hex(value);
    stop64 = ((value >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  void store_difficulty(cryptonote::difficulty_type difficulty, uint64_t &sdiff, std::string &swdiff, uint64_t &stop64)
  {
    store_128(difficulty, sdiff, swdiff, stop64);
  }
}

namespace cryptonote
{

  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_rpc_restricted_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);
    // Daemon inbound RPC is Axum plaintext: no --rpc-login / --rpc-ssl*.
    cryptonote::rpc_args::init_options(desc, /*any_cert_option=*/false, /*include_listener_tls_auth=*/false);
    command_line::add_arg(desc, arg_rpc_max_connections_per_public_ip);
    command_line::add_arg(desc, arg_rpc_max_connections_per_private_ip);
    command_line::add_arg(desc, arg_rpc_max_connections);
    command_line::add_arg(desc, arg_rpc_response_soft_limit);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
    , disable_rpc_ban(false)
  {}
  core_rpc_server::~core_rpc_server()
  {
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::init(
      const boost::program_options::variables_map& vm
      , const bool restricted
      , const std::string& port
    )
  {
    m_restricted = restricted;

    // Daemon: no inbound login/ssl flags. The connection-cap flags are read
    // below and handed to the Rust listener, which validates
    // (ConnLimits::checked) and enforces them.
    auto rpc_config = cryptonote::rpc_args::process(vm, /*any_cert_option=*/false, /*include_listener_tls_auth=*/false);
    if (!rpc_config)
      return false;

    std::string bind_ip_str = rpc_config->bind_ip;
    std::string bind_ipv6_str = rpc_config->bind_ipv6_address;
    if (restricted)
    {
      const auto restricted_rpc_port_arg = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
      const bool has_restricted_rpc_port_arg = !command_line::is_arg_defaulted(vm, restricted_rpc_port_arg);
      if (has_restricted_rpc_port_arg && port == command_line::get_arg(vm, restricted_rpc_port_arg))
      {
        bind_ip_str = rpc_config->restricted_bind_ip;
        bind_ipv6_str = rpc_config->restricted_bind_ipv6_address;
      }
    }
    m_rpc_bind_ip = bind_ip_str;
    // Two fields on purpose: the family's enable and its address are separate
    // signals. An explicitly empty --rpc-bind-ipv6-address with --rpc-use-ipv6
    // set must reach Rust as the empty string and be refused there, not be
    // mistaken for "off" and silently dropped.
    m_rpc_bind_ipv6 = bind_ipv6_str;
    m_rpc_use_ipv6 = rpc_config->use_ipv6;
    m_access_control_origins = rpc_config->access_control_origins;
    disable_rpc_ban = rpc_config->disable_rpc_ban;

    // Connection-limit args go to the Rust Axum listener as given; it
    // validates them (ConnLimits::checked) where it enforces them, and logs
    // the reason if they contradict each other.
    m_rpc_max_connections = command_line::get_arg(vm, arg_rpc_max_connections);
    m_rpc_max_connections_per_public_ip = command_line::get_arg(vm, arg_rpc_max_connections_per_public_ip);
    m_rpc_max_connections_per_private_ip = command_line::get_arg(vm, arg_rpc_max_connections_per_private_ip);

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    if(!m_p2p.get_payload_object().is_synchronized())
    {
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::add_host_fail(const connection_context *ctx, unsigned int score)
  {
    if(!ctx || !ctx->m_remote_address.is_blockable() || disable_rpc_ban)
      return false;

    CRITICAL_REGION_LOCAL(m_host_fails_score_lock);
    uint64_t fails = m_host_fails_score[ctx->m_remote_address.host_str()] += score;
    MDEBUG("Host " << ctx->m_remote_address.host_str() << " fail score=" << fails);
    if(fails > RPC_IP_FAILS_BEFORE_BLOCK)
    {
      auto it = m_host_fails_score.find(ctx->m_remote_address.host_str());
      CHECK_AND_ASSERT_MES(it != m_host_fails_score.end(), false, "internal error");
      it->second = RPC_IP_FAILS_BEFORE_BLOCK/2;
      m_p2p.block_host(ctx->m_remote_address);
    }
    return true;
  }
#define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_info);
    const bool restricted = m_restricted && ctx;

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.top_block_hash = string_tools::pod_to_hex(top_hash);
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);
    res.target = m_core.get_blockchain_storage().get_difficulty_target();
    res.tx_count = m_core.get_blockchain_storage().get_total_transactions() - res.height; //without coinbase
    res.tx_pool_size = m_core.get_pool_transactions_count(!restricted);
    res.alt_blocks_count = restricted ? 0 : m_core.get_blockchain_storage().get_alternative_blocks_count();
    uint64_t total_conn = restricted ? 0 : m_p2p.get_public_connections_count();
    res.outgoing_connections_count = restricted ? 0 : m_p2p.get_public_outgoing_connections_count();
    res.incoming_connections_count = restricted ? 0 : (total_conn - res.outgoing_connections_count);
    res.rpc_connections_count = restricted ? 0 : get_connections_count();
    res.white_peerlist_size = restricted ? 0 : m_p2p.get_public_white_peers_count();
    res.grey_peerlist_size = restricted ? 0 : m_p2p.get_public_gray_peers_count();

    cryptonote::network_type net_type = nettype();
    res.mainnet = net_type == MAINNET;
    res.testnet = net_type == TESTNET;
    res.stagenet = net_type == STAGENET;
    res.nettype = net_type == MAINNET ? "mainnet" : net_type == TESTNET ? "testnet" : net_type == STAGENET ? "stagenet" : "fakechain";
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(res.height - 1),
        res.cumulative_difficulty, res.wide_cumulative_difficulty, res.cumulative_difficulty_top64);
    res.block_size_limit = res.block_weight_limit = m_core.get_blockchain_storage().get_current_cumulative_block_weight_limit();
    res.block_size_median = res.block_weight_median = m_core.get_blockchain_storage().get_current_cumulative_block_weight_median();
    res.adjusted_time = m_core.get_blockchain_storage().get_adjusted_time(res.height);

    res.start_time = restricted ? 0 : (uint64_t)m_core.get_start_time();
    res.free_space = restricted ? std::numeric_limits<uint64_t>::max() : m_core.get_free_space();
    res.offline = m_core.offline();
    res.database_size = m_core.get_blockchain_storage().get_db().get_database_size();
    if (restricted)
      res.database_size = round_up(res.database_size, 5ull* 1024 * 1024 * 1024);
    res.version = restricted ? "" : SHEKYL_VERSION_FULL;
    res.protocol_version = SHEKYL_PROTOCOL_VERSION;
    res.synchronized = check_core_ready();
    res.busy_syncing = m_p2p.get_payload_object().is_busy_syncing();
    res.restricted = restricted;

    // Chain-state inputs for economics calculations
    uint64_t already_generated = 0;
    if (res.height > 0)
      already_generated = m_core.get_blockchain_storage().get_db().get_block_already_generated_coins(res.height - 1);

    // Shekyl NG four-component economics fields
    const uint64_t tx_vol_avg = m_core.get_blockchain_storage().get_tx_volume_avg(res.height);
    res.release_multiplier = shekyl_calc_release_multiplier(
        tx_vol_avg, SHEKYL_TX_VOLUME_BASELINE, SHEKYL_RELEASE_MIN, SHEKYL_RELEASE_MAX);
    // Burn is a pure function of activity and supply — stake was deleted as a
    // burn input (ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md F-D).
    res.burn_pct = shekyl_calc_burn_pct(
        tx_vol_avg, SHEKYL_TX_VOLUME_BASELINE,
        already_generated, MONEY_SUPPLY,
        SHEKYL_BURN_BASE_RATE, SHEKYL_BURN_CAP);
    res.total_burned = m_core.get_blockchain_storage().get_db().get_total_burned();

    // Component 4: effective staker emission share at current height
    const uint64_t genesis_ng_height = m_core.get_blockchain_storage().get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG);
    res.staker_emission_share_effective = shekyl_calc_emission_share(
        res.height, genesis_ng_height, SHEKYL_STAKER_EMISSION_SHARE, SHEKYL_STAKER_EMISSION_DECAY, SHEKYL_BLOCKS_PER_YEAR);

    double emission_pct = (double)already_generated / (double)MONEY_SUPPLY;
    if (emission_pct < 0.30)
      res.emission_era = "Founding";
    else if (emission_pct < 0.60)
      res.emission_era = "Growth";
    else if (emission_pct < 0.85)
      res.emission_era = "Maturity";
    else
      res.emission_era = "Tail";

    res.tx_prune_height = m_core.get_blockchain_storage().get_db().get_last_pruned_tx_data_height();

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_net_stats(const COMMAND_RPC_GET_NET_STATS::request& req, COMMAND_RPC_GET_NET_STATS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_net_stats);
    res.start_time = (uint64_t)m_core.get_start_time();
    {
      CRITICAL_REGION_LOCAL(epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in);
      epee::net_utils::network_throttle_manager::get_global_throttle_in().get_stats(res.total_packets_in, res.total_bytes_in);
    }
    {
      CRITICAL_REGION_LOCAL(epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_out);
      epee::net_utils::network_throttle_manager::get_global_throttle_out().get_stats(res.total_packets_out, res.total_bytes_out);
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      bool r = tx.serialize_base(ar);
      if (!r) return false;
    END_SERIALIZE()
  };
  //------------------------------------------------------------------------------------------------------------------------------
    bool core_rpc_server::on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res, const connection_context *ctx)
    {
      RPC_TRACKER(get_alt_blocks_hashes);

      std::vector<block> blks;

      if(!m_core.get_alternative_blocks(blks))
      {
          res.status = "Failed";
          return true;
      }

      res.blks_hashes.reserve(blks.size());

      for (auto const& blk: blks)
      {
          res.blks_hashes.push_back(epee::string_tools::pod_to_hex(get_block_hash(blk)));
      }

      MDEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
      res.status = CORE_RPC_STATUS_OK;
      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_blocks_by_height);

    const bool restricted = m_restricted && ctx;
    if (restricted && req.heights.size() > RESTRICTED_BLOCK_COUNT)
    {
      res.status = "Too many blocks requested in restricted mode";
      return true;
    }

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    for (uint64_t height : req.heights)
    {
      block blk;
      try
      {
        blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
      }
      catch (...)
      {
        res.status = "Error retrieving block at height " + std::to_string(height);
        return true;
      }
      std::vector<transaction> txs;
      std::vector<crypto::hash> missed_txs;
      m_core.get_transactions(blk.tx_hashes, txs, missed_txs);
      res.blocks.resize(res.blocks.size() + 1);
      res.blocks.back().block = block_to_blob(blk);
      for (auto& tx : txs)
        res.blocks.back().txs.push_back({tx_to_blob(tx), crypto::null_hash});
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transactions);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;

    if (restricted && req.txs_hashes.size() > RESTRICTED_TRANSACTIONS_COUNT)
    {
      res.status = "Too many transactions requested in restricted mode";
      return true;
    }

    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.txs_hashes)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::vector<crypto::hash> missed_txs;
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> txs;
    bool r = m_core.get_split_transactions_blobs(vh, txs, missed_txs);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    // try the pool for any missing txes
    size_t found_in_pool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, tx_memory_pool::tx_details> per_tx_pool_tx_details;
    if (!missed_txs.empty())
    {
      std::vector<std::pair<crypto::hash, tx_memory_pool::tx_details>> pool_txs;
      bool r = m_core.get_pool_transactions_info(missed_txs, pool_txs, !request_has_rpc_origin || !restricted);
      if(r)
      {
        // sort to match original request
        std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> sorted_txs;
        std::vector<std::pair<crypto::hash, tx_memory_pool::tx_details>>::const_iterator i;
        unsigned txs_processed = 0;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.size() == txs_processed)
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (std::get<0>(txs[txs_processed]) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs[txs_processed]));
            ++txs_processed;
          }
          else if ((i = std::find_if(pool_txs.begin(), pool_txs.end(), [h](const std::pair<crypto::hash, tx_memory_pool::tx_details> &pt) { return h == pt.first; })) != pool_txs.end())
          {
            const tx_memory_pool::tx_details &td = i->second;
            std::stringstream ss;
            binary_archive<true> ba(ss);
            bool r = const_cast<cryptonote::transaction&>(td.tx).serialize_base(ba);
            if (!r)
            {
              res.status = "Failed to serialize transaction base";
              return true;
            }
            const cryptonote::blobdata pruned = ss.str();
            const crypto::hash prunable_hash = get_transaction_prunable_hash(td.tx);
            sorted_txs.push_back(std::make_tuple(h, pruned, prunable_hash, std::string(td.tx_blob, pruned.size())));
            missed_txs.erase(std::find(missed_txs.begin(), missed_txs.end(), h));
            pool_tx_hashes.insert(h);
            per_tx_pool_tx_details.insert(std::make_pair(h, td));
            ++found_in_pool;
          }
        }
        txs = sorted_txs;
      }
      LOG_PRINT_L2("Found " << found_in_pool << "/" << vh.size() << " transactions in the pool");
    }

    CHECK_AND_ASSERT_MES(txs.size() + missed_txs.size() == vh.size(), false, "mismatched number of txs");

    auto txhi = req.txs_hashes.cbegin();
    auto vhi = vh.cbegin();
    auto missedi = missed_txs.cbegin();

    for(auto& tx: txs)
    {
      res.txs.push_back(COMMAND_RPC_GET_TRANSACTIONS::entry());
      COMMAND_RPC_GET_TRANSACTIONS::entry &e = res.txs.back();

      while (missedi != missed_txs.end() && *missedi == *vhi)
      {
          ++vhi;
          ++txhi;
          ++missedi;
      }

      crypto::hash tx_hash = *vhi++;
      CHECK_AND_ASSERT_MES(tx_hash == std::get<0>(tx), false, "mismatched tx hash");
      e.tx_hash = *txhi++;
      e.prunable_hash = epee::string_tools::pod_to_hex(std::get<2>(tx));
      if (req.split || req.prune || std::get<3>(tx).empty())
      {
        // use splitted form with pruned and prunable (filled only when prune=false and the daemon has it), leaving as_hex as empty
        e.pruned_as_hex = string_tools::buff_to_hex_nodelimer(std::get<1>(tx));
        if (!req.prune)
          e.prunable_as_hex = string_tools::buff_to_hex_nodelimer(std::get<3>(tx));
        if (req.decode_as_json)
        {
          cryptonote::blobdata tx_data;
          cryptonote::transaction t;
          if (req.prune || std::get<3>(tx).empty())
          {
            // decode pruned tx to JSON
            tx_data = std::get<1>(tx);
            if (cryptonote::parse_and_validate_tx_base_from_blob(tx_data, t))
            {
              pruned_transaction pruned_tx{t};
              e.as_json = obj_to_json_str(pruned_tx);
            }
            else
            {
              res.status = "Failed to parse and validate pruned tx from blob";
              return true;
            }
          }
          else
          {
            // decode full tx to JSON
            tx_data = std::get<1>(tx) + std::get<3>(tx);
            if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
            {
              e.as_json = obj_to_json_str(t);
            }
            else
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
          }
        }
      }
      else
      {
        // use non-splitted form, leaving pruned_as_hex and prunable_as_hex as empty
        cryptonote::blobdata tx_data = std::get<1>(tx) + std::get<3>(tx);
        e.as_hex = string_tools::buff_to_hex_nodelimer(tx_data);
        if (req.decode_as_json)
        {
          cryptonote::transaction t;
          if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
          {
            e.as_json = obj_to_json_str(t);
          }
          else
          {
            res.status = "Failed to parse and validate tx from blob";
            return true;
          }
        }
      }
      e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
      if (e.in_pool)
      {
        e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
        e.confirmations = 0;
        auto it = per_tx_pool_tx_details.find(tx_hash);
        if (it != per_tx_pool_tx_details.end())
        {
          e.double_spend_seen = it->second.double_spend_seen;
          e.relayed = it->second.relayed;
          e.received_timestamp = it->second.receive_time;
        }
        else
        {
          MERROR("Failed to determine pool info for " << tx_hash);
          e.double_spend_seen = false;
          e.relayed = false;
          e.received_timestamp = 0;
        }
      }
      else
      {
        e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e.confirmations = m_core.get_current_blockchain_height() - e.block_height;
        e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
        e.received_timestamp = 0;
        e.double_spend_seen = false;
        e.relayed = false;
      }
      e.pruned = e.in_pool ? false
          : !m_core.get_blockchain_storage().get_db().tx_has_verification_data(tx_hash);

      // fill up old style responses too, in case an old wallet asks
      res.txs_as_hex.push_back(e.as_hex);
      if (req.decode_as_json)
        res.txs_as_json.push_back(e.as_json);

      // output indices too if not in pool
      if (pool_tx_hashes.find(tx_hash) == pool_tx_hashes.end())
      {
        bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
        if (!r)
        {
          res.status = "Failed";
          return true;
        }
      }
    }

    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(is_key_image_spent);

    const bool restricted = m_restricted && ctx;

    if (restricted && req.key_images.size() > RESTRICTED_SPENT_KEY_IMAGES_COUNT)
    {
      res.status = "Too many key images queried in restricted mode";
      return true;
    }

    // parse key images from request
    std::vector<crypto::key_image> key_images;
    for(const auto& ki_hex_str: req.key_images)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(ki_hex_str, b))
      {
        res.status = "Failed to parse hex representation of key image";
        return true;
      }
      if(b.size() != sizeof(crypto::key_image))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      key_images.emplace_back();
      crypto::key_image &ki = key_images.back();
      memcpy(&ki, b.data(), sizeof(crypto::key_image));
    }

    // check key images in blockchain
    std::vector<bool> spent_status;
    bool r = m_core.are_key_images_spent(key_images, spent_status);
    if (!r || spent_status.size() != key_images.size())
    {
      res.status = "Failed";
      return true;
    }
    res.spent_status.clear();
    res.spent_status.reserve(spent_status.size());
    for (size_t n = 0; n < spent_status.size(); ++n)
      res.spent_status.push_back(spent_status[n] ? COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN : COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT);

    // filter out known spent key images
    std::vector<crypto::key_image> filtered_key_images;
    std::vector<std::size_t> filtered_key_image_idxs;
    filtered_key_images.reserve(key_images.size());
    filtered_key_image_idxs.reserve(key_images.size());
    for (std::size_t i = 0; i < key_images.size(); ++i)
    {
      if (!spent_status.at(i))
      {
        filtered_key_images.push_back(key_images.at(i));
        filtered_key_image_idxs.push_back(i);
      }
    }
    if (filtered_key_images.size() != filtered_key_image_idxs.size())
    {
      res.status = "Failed";
      return true;
    }

    // check the pool too
    spent_status.clear();
    r = m_core.are_key_images_spent_in_pool(filtered_key_images, spent_status);
    if (!r || spent_status.size() != filtered_key_images.size())
    {
      res.status = "Failed";
      return true;
    }
    for (std::size_t i = 0; i < spent_status.size(); ++i)
    {
      if (spent_status.at(i))
      {
        const std::size_t res_idx = filtered_key_image_idxs.at(i);
        res.spent_status.at(res_idx) = COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL;
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(start_mining);
    CHECK_CORE_READY();
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, nettype(), req.miner_address))
    {
      res.status = "Failed, wrong address";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if (info.is_subaddress)
    {
      res.status = "Mining to subaddress isn't supported yet";
      LOG_PRINT_L0(res.status);
      return true;
    }

    unsigned int concurrency_count = boost::thread::hardware_concurrency() * 4;

    // if we couldn't detect threads, set it to a ridiculously high number
    if(concurrency_count == 0)
    {
      concurrency_count = 257;
    }

    // if there are more threads requested than the hardware supports
    // then we fail and log that.
    if(req.threads_count > concurrency_count)
    {
      res.status = "Failed, too many threads relative to CPU cores.";
      LOG_PRINT_L0(res.status);
      return true;
    }

    cryptonote::miner &miner= m_core.get_miner();
    if (miner.is_mining())
    {
      res.status = "Already mining";
      return true;
    }
    if(!miner.start(info.address, req.miner_address, static_cast<size_t>(req.threads_count), req.do_background_mining, req.ignore_battery))
    {
      res.status = "Failed, mining not started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(stop_mining);
    cryptonote::miner &miner= m_core.get_miner();
    if(!miner.is_mining())
    {
      res.status = "Mining never started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if(!miner.stop())
    {
      res.status = "Failed, mining not stopped";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(mining_status);

    const miner& lMiner = m_core.get_miner();
    res.active = lMiner.is_mining();
    res.is_background_mining_enabled = lMiner.get_is_background_mining_enabled();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);

    // RPC wire contract: mining_status.block_target is part of the public
    // JSON-RPC surface. The literal 120 (seconds per block) is pinned by
    // the contract. The round-trip regression test that pins the wire
    // bytes lives at tests/unit_tests/rpc_target_wire_contract.cpp; see
    // docs/completed/DAA_LWMA1_PHASE4_PREFLIGHT.md §16.4 for the rationale.
    static_assert(SHEKYL_DAA_TARGET_SECONDS == 120,
        "RPC wire contract: mining_status.block_target carries the block "
        "target time in seconds; 120 is pinned by the public JSON-RPC "
        "contract.");
    res.block_target = SHEKYL_DAA_TARGET_SECONDS;
    if ( lMiner.is_mining() ) {
      res.speed = lMiner.get_speed();
      res.threads_count = lMiner.get_threads_count();
      res.block_reward = lMiner.get_block_reward();
    }
    // The retained original string, not a struct re-encode: since the
    // fork-(ii) address layout the struct alone cannot re-encode an
    // address (no msg_sign_pk field).
    if (lMiner.is_mining() || lMiner.get_is_background_mining_enabled())
      res.address = lMiner.get_mining_address_str();
    const uint8_t major_version = m_core.get_blockchain_storage().get_current_hard_fork_version();
    const unsigned variant = major_version >= 7 ? major_version - 6 : 0;
    switch (variant)
    {
      case 0: res.pow_algorithm = "Cryptonight"; break;
      case 1: res.pow_algorithm = "CNv1 (Cryptonight variant 1)"; break;
      case 2: case 3: res.pow_algorithm = "CNv2 (Cryptonight variant 2)"; break;
      case 4: case 5: res.pow_algorithm = "CNv4 (Cryptonight variant 4)"; break;
      case 6: case 7: case 8: case 9: res.pow_algorithm = "RandomX"; break;
      default: res.pow_algorithm = "RandomX"; break; // assumed
    }
    if (res.is_background_mining_enabled)
    {
      res.bg_idle_threshold = lMiner.get_idle_threshold();
      res.bg_min_idle_seconds = lMiner.get_min_idle_seconds();
      res.bg_ignore_battery = lMiner.get_ignore_battery();
      res.bg_target = lMiner.get_mining_target();
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(save_bc);
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      res.status = "Error while storing blockchain";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_peer_list);
    std::vector<nodetool::peerlist_entry> white_list;
    std::vector<nodetool::peerlist_entry> gray_list;

    if (req.public_only)
    {
      m_p2p.get_public_peerlist(gray_list, white_list);
    }
    else
    {
      m_p2p.get_peerlist(gray_list, white_list);
    }

    for (auto & entry : white_list)
    {
      if (!req.include_blocked && m_p2p.is_host_blocked(entry.adr, NULL))
        continue;
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed);
      else
        res.white_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed);
    }

    for (auto & entry : gray_list)
    {
      if (!req.include_blocked && m_p2p.is_host_blocked(entry.adr, NULL))
        continue;
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed);
      else
        res.gray_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_hash_rate(const COMMAND_RPC_SET_LOG_HASH_RATE::request& req, COMMAND_RPC_SET_LOG_HASH_RATE::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_hash_rate);
    if(m_core.get_miner().is_mining())
    {
      m_core.get_miner().do_print_hashrate(req.visible);
      res.status = CORE_RPC_STATUS_OK;
    }
    else
    {
      res.status = CORE_RPC_STATUS_NOT_MINING;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_level);
    if (req.level < 0 || req.level > 4)
    {
      res.status = "Error: log level not valid";
      return true;
    }
    mlog_set_log_level(req.level);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_categories(const COMMAND_RPC_SET_LOG_CATEGORIES::request& req, COMMAND_RPC_SET_LOG_CATEGORIES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_categories);
    mlog_set_log(req.categories.c_str());
    res.categories = mlog_get_categories();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      m_core.get_pool_transactions_and_spent_keys_info(res.transactions, res.spent_key_images, allow_sensitive);
      for (tx_info& txi : res.transactions)
        txi.tx_blob = epee::string_tools::buff_to_hex_nodelimer(txi.tx_blob);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_hashes);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      std::vector<crypto::hash> tx_hashes;
      m_core.get_pool_transaction_hashes(tx_hashes, allow_sensitive);
      res.tx_hashes.reserve(tx_hashes.size());
      for (const crypto::hash &tx_hash: tx_hashes)
        res.tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_stats);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    m_core.get_pool_transaction_stats(res.pool_stats, !request_has_rpc_origin || !restricted);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(stop_daemon);
    // FIXME: replace back to original m_p2p.send_stop_signal() after
    // investigating why that isn't working quite right.
    m_p2p.send_stop_signal();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // equivalent of strstr, but with arbitrary bytes (ie, NULs)
  // This does not differentiate between "not found" and "found at offset 0"
  size_t slow_memmem(const void* start_buff, size_t buflen,const void* pat,size_t patlen)
  {
    const void* buf = start_buff;
    const void* end=(const char*)buf+buflen;
    if (patlen > buflen || patlen == 0) return 0;
    while(buflen>0 && (buf=memchr(buf,((const char*)pat)[0],buflen-patlen+1)))
    {
      if(memcmp(buf,pat,patlen)==0)
        return (const char*)buf - (const char*)start_buff;
      buf=(const char*)buf+1;
      buflen = (const char*)end - (const char*)buf;
    }
    return 0;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::get_block_template(const account_public_address &address, const cryptonote::blobdata &extra_nonce, size_t &reserved_offset, cryptonote::difficulty_type  &difficulty, uint64_t &height, uint64_t &expected_reward, block &b, uint64_t &seed_height, crypto::hash &seed_hash, crypto::hash &next_seed_hash, epee::json_rpc::error &error_resp)
  {
    b = boost::value_initialized<cryptonote::block>();
    if(!m_core.get_block_template(b, address, difficulty, height, expected_reward, extra_nonce, seed_height, seed_hash))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to create block template");
      return false;
    }
    blobdata block_blob = t_serializable_object_to_blob(b);
    crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(b.miner_tx);
    if(tx_pub_key == crypto::null_pkey)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to get tx pub key in coinbase extra");
      return false;
    }

    // seed_height was already filled by get_block_template above (same
    // height, same schedule); only the pre-announce needs computing.
    const uint64_t next_height = shekyl_pow_randomx_v2_next_seedheight(height);
    if (next_height != seed_height)
      next_seed_hash = m_core.get_block_id_by_height(next_height);
    else
      next_seed_hash = seed_hash;

    if (extra_nonce.empty())
    {
      reserved_offset = 0;
      return true;
    }

    reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if(!reserved_offset)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to find tx pub key in blockblob");
      return false;
    }
    reserved_offset += sizeof(tx_pub_key) + 2; //2 bytes: tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if(reserved_offset + extra_nonce.size() > block_blob.size())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to calculate offset for ");
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(getblocktemplate);

    if(!check_core_ready())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_CORE_BUSY;
      error_resp.message = "Core is busy";
      return false;
    }

    if(req.reserve_size > 255)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big reserved size, maximum 255";
      return false;
    }

    if(req.reserve_size && !req.extra_nonce.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Cannot specify both a reserve_size and an extra_nonce";
      return false;
    }

    if(req.extra_nonce.size() > 510)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big extra_nonce size, maximum 510 hex chars";
      return false;
    }

    cryptonote::address_parse_info info;

    if(!req.wallet_address.size() || !cryptonote::get_account_address_from_str(info, nettype(), req.wallet_address))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS;
      error_resp.message = "Failed to parse wallet address";
      return false;
    }
    if (info.is_subaddress)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_MINING_TO_SUBADDRESS;
      error_resp.message = "Mining to subaddress is not supported yet";
      return false;
    }

    block b;
    cryptonote::blobdata blob_reserve;
    size_t reserved_offset;
    if(!req.extra_nonce.empty())
    {
      if(!string_tools::parse_hexstr_to_binbuff(req.extra_nonce, blob_reserve))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Parameter extra_nonce should be a hex string";
        return false;
      }
    }
    else
      blob_reserve.resize(req.reserve_size, 0);
    cryptonote::difficulty_type wdiff;
    // `prev_block` is RESERVED / NOT SUPPORTED. The field is kept in the request
    // definition deliberately: epee ignores unknown fields, so REMOVING it would
    // make a Monero-lineage pool stack that still sends it get a tip-built
    // template silently -- a wrong answer to a precise question, surfacing later
    // as an unexplained orphan rate. Refuse loudly instead.
    if (!req.prev_block.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "prev_block templates are not supported; build on the tip";
      return false;
    }
    crypto::hash seed_hash, next_seed_hash;
    if (!get_block_template(info.address, blob_reserve, reserved_offset, wdiff, res.height, res.expected_reward, b, res.seed_height, seed_hash, next_seed_hash, error_resp))
      return false;
    res.seed_hash = string_tools::pod_to_hex(seed_hash);
    if (seed_hash != next_seed_hash)
      res.next_seed_hash = string_tools::pod_to_hex(next_seed_hash);

    res.reserved_offset = reserved_offset;
    store_difficulty(wdiff, res.difficulty, res.wide_difficulty, res.difficulty_top64);
    blobdata block_blob = t_serializable_object_to_blob(b);
    blobdata hashing_blob = get_block_hashing_blob(b);
    res.prev_hash = string_tools::pod_to_hex(b.prev_id);
    res.blocktemplate_blob = string_tools::buff_to_hex_nodelimer(block_blob);
    res.blockhashing_blob =  string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getminerdata(const COMMAND_RPC_GETMINERDATA::request& req, COMMAND_RPC_GETMINERDATA::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    if(!check_core_ready())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_CORE_BUSY;
      error_resp.message = "Core is busy";
      return false;
    }

    crypto::hash prev_id, seed_hash;
    difficulty_type difficulty;

    std::vector<tx_block_template_backlog_entry> tx_backlog;
    if (!m_core.get_miner_data(res.major_version, res.height, prev_id, seed_hash, difficulty, res.median_weight, res.already_generated_coins, tx_backlog))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to get miner data";
      LOG_ERROR("Failed to get miner data");
      return false;
    }

    res.tx_backlog.clear();
    res.tx_backlog.reserve(tx_backlog.size());

    for (const auto& entry : tx_backlog)
    {
      res.tx_backlog.emplace_back(COMMAND_RPC_GETMINERDATA::response::tx_backlog_entry{string_tools::pod_to_hex(entry.id), entry.weight, entry.fee});
    }

    res.prev_id = string_tools::pod_to_hex(prev_id);
    res.seed_hash = string_tools::pod_to_hex(seed_hash);
    res.difficulty = cryptonote::hex(difficulty);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_calcpow(const COMMAND_RPC_CALCPOW::request& req, COMMAND_RPC_CALCPOW::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(calcpow);

    blobdata blockblob;
    if(!string_tools::parse_hexstr_to_binbuff(req.block_blob, blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }

    if(!m_core.check_incoming_block_size(blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE;
      error_resp.message = "Block blob size is too big, rejecting block";
      return false;
    }
    crypto::hash seed_hash, pow_hash;
    std::string buf;
    if(req.seed_hash.size())
    {
      if (!string_tools::parse_hexstr_to_binbuff(req.seed_hash, buf) ||
        buf.size() != sizeof(crypto::hash))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Wrong seed hash";
        return false;
      }
      buf.copy(reinterpret_cast<char *>(&seed_hash), sizeof(crypto::hash));
    }

    try
    {
      cryptonote::get_block_longhash(&(m_core.get_blockchain_storage()), blockblob, pow_hash, req.height,
        req.major_version, req.seed_hash.size() ? &seed_hash : NULL, 0);
    }
    catch (const std::exception &e)
    {
      MERROR("Caught unexpected error while hashing in core_rpc_server::on_calc_pow: " << e.what());
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = e.what();
      return false;
    }
    res = string_tools::pod_to_hex(pow_hash);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_add_aux_pow(const COMMAND_RPC_ADD_AUX_POW::request& req, COMMAND_RPC_ADD_AUX_POW::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(add_aux_pow);

    if (req.aux_pow.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Empty aux pow hash vector";
      return false;
    }

    crypto::hash merkle_root;
    size_t merkle_tree_depth = 0;
    std::vector<std::pair<crypto::hash, crypto::hash>> aux_pow;
    std::vector<crypto::hash> aux_pow_raw;
    aux_pow.reserve(req.aux_pow.size());
    aux_pow_raw.reserve(req.aux_pow.size());
    for (const auto &s: req.aux_pow)
    {
      aux_pow.push_back({});
      if (!epee::string_tools::hex_to_pod(s.id, aux_pow.back().first))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid aux pow id";
        return false;
      }
      if (!epee::string_tools::hex_to_pod(s.hash, aux_pow.back().second))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid aux pow hash";
        return false;
      }
      aux_pow_raw.push_back(aux_pow.back().second);
    }

    size_t path_domain = 1;
    while ((1u << path_domain) < aux_pow.size())
      ++path_domain;
    uint32_t nonce;
    const uint32_t max_nonce = 65535;
    bool collision = true;
    for (nonce = 0; nonce <= max_nonce; ++nonce)
    {
      std::vector<bool> slots(aux_pow.size(), false);
      collision = false;
      for (size_t idx = 0; idx < aux_pow.size(); ++idx)
      {
        const uint32_t slot = cryptonote::get_aux_slot(aux_pow[idx].first, nonce, aux_pow.size());
        if (slot >= aux_pow.size())
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Computed slot is out of range";
          return false;
        }
        if (slots[slot])
        {
          collision = true;
          break;
        }
        slots[slot] = true;
      }
      if (!collision)
        break;
    }
    if (collision)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to find a suitable nonce";
      return false;
    }

    crypto::tree_hash((const char(*)[crypto::HASH_SIZE])aux_pow_raw.data(), aux_pow_raw.size(), merkle_root.data);
    res.merkle_root = epee::string_tools::pod_to_hex(merkle_root);
    res.merkle_tree_depth = cryptonote::encode_mm_depth(aux_pow.size(), nonce);

    blobdata blocktemplate_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.blocktemplate_blob, blocktemplate_blob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Invalid blocktemplate_blob";
      return false;
    }

    block b;
    if (!parse_and_validate_block_from_blob(blocktemplate_blob, b))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong blocktemplate_blob";
      return false;
    }

    if (!remove_field_from_tx_extra(b.miner_tx.extra, typeid(cryptonote::tx_extra_merge_mining_tag)))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Error removing existing merkle root";
      return false;
    }
    if (!add_mm_merkle_root_to_tx_extra(b.miner_tx.extra, merkle_root, merkle_tree_depth))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Error adding merkle root";
      return false;
    }
    b.invalidate_hashes();
    b.miner_tx.invalidate_hashes();

    const blobdata block_blob = t_serializable_object_to_blob(b);
    const blobdata hashing_blob = get_block_hashing_blob(b);

    res.blocktemplate_blob = string_tools::buff_to_hex_nodelimer(block_blob);
    res.blockhashing_blob = string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.aux_pow = req.aux_pow;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(submitblock);
    CHECK_CORE_READY();
    if(req.size()!=1)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Wrong param";
      return false;
    }
    blobdata blockblob;
    if(!string_tools::parse_hexstr_to_binbuff(req[0], blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }
    
    // Fixing of high orphan issue for most pools
    // Thanks Boolberry!
    block b;
    crypto::hash blk_id;
    if(!parse_and_validate_block_from_blob(blockblob, b, blk_id))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }

    // Fix from Boolberry neglects to check block
    // size, do that with the function below
    if(!m_core.check_incoming_block_size(blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE;
      error_resp.message = "Block bloc size is too big, rejecting block";
      return false;
    }

    block_verification_context bvc;
    if(!m_core.handle_block_found(b, bvc))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED;
      error_resp.message = "Block not accepted";
      return false;
    }
    res.block_id = epee::string_tools::pod_to_hex(blk_id);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_generateblocks(const COMMAND_RPC_GENERATEBLOCKS::request& req, COMMAND_RPC_GENERATEBLOCKS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(generateblocks);

    CHECK_CORE_READY();
    
    res.status = CORE_RPC_STATUS_OK;

    if(m_core.get_nettype() != FAKECHAIN)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_REGTEST_REQUIRED;
      error_resp.message = "Regtest required when generating blocks";      
      return false;
    }

    // RESERVED / NOT SUPPORTED -- refuse rather than silently generate on the
    // tip, so a caller who asked for a specific parent is told, not guessed at.
    if (!req.prev_block.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "prev_block templates are not supported; build on the tip";
      return false;
    }
    COMMAND_RPC_GETBLOCKTEMPLATE::request template_req;
    COMMAND_RPC_GETBLOCKTEMPLATE::response template_res;
    COMMAND_RPC_SUBMITBLOCK::request submit_req;
    COMMAND_RPC_SUBMITBLOCK::response submit_res;

    template_req.reserve_size = 1;
    template_req.wallet_address = req.wallet_address;
    submit_req.push_back(std::string{});
    res.height = m_core.get_blockchain_storage().get_current_blockchain_height();

    for(size_t i = 0; i < req.amount_of_blocks; i++)
    {
      bool r = on_getblocktemplate(template_req, template_res, error_resp, ctx);
      res.status = template_res.status;
      
      if (!r) return false;

      blobdata blockblob;
      if(!string_tools::parse_hexstr_to_binbuff(template_res.blocktemplate_blob, blockblob))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
        error_resp.message = "Wrong block blob";
        return false;
      }
      block b;
      if(!parse_and_validate_block_from_blob(blockblob, b))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
        error_resp.message = "Wrong block blob";
        return false;
      }
      b.nonce = req.starting_nonce;
      crypto::hash seed_hash = crypto::null_hash;
      if (!epee::string_tools::hex_to_pod(template_res.seed_hash, seed_hash))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error converting seed hash";
        return false;
      }
      miner::find_nonce_for_given_block([this](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, unsigned int threads, crypto::hash &hash) {
        return cryptonote::get_block_longhash(&(m_core.get_blockchain_storage()), b, hash, height, seed_hash, threads);
      }, b, template_res.difficulty, template_res.height, &seed_hash);

      submit_req.front() = string_tools::buff_to_hex_nodelimer(block_to_blob(b));
      r = on_submitblock(submit_req, submit_res, error_resp, ctx);
      res.status = submit_res.status;

      if (!r) return false;

      res.blocks.push_back(epee::string_tools::pod_to_hex(get_block_hash(b)));
      // Previously re-pointed the next template at the block just mined. After a
      // successful on_submitblock the tip IS that block, so tip-building is
      // equivalent -- and prev_block templates are gone (DRS/Stage-3a).
      res.height = template_res.height;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_inject_archival_serve_credit(const COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT::request& req, COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(inject_archival_serve_credit);

    CHECK_CORE_READY();

    if(m_core.get_nettype() != FAKECHAIN)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_REGTEST_REQUIRED;
      error_resp.message = "Regtest required when injecting archival serve credit";
      return false;
    }

    crypto::hash p_canonical_id;
    if (!epee::string_tools::hex_to_pod(req.p_canonical_id, p_canonical_id))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "p_canonical_id is not a 32-byte hex hash";
      return false;
    }

    // PC-D4: the tip index the row is attributed to is derived INSIDE the
    // injector, under the blockchain lock — a snapshot taken here would be
    // pre-lock and can go stale against a concurrent mine/pop. On refusal
    // (wrong nettype, empty chain) the daemon log names the reason.
    if (!m_core.get_blockchain_storage().regtest_inject_archival_serve_credit(
      p_canonical_id, req.shard_id, req.settlement_epoch))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Serve-credit injection failed";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  uint64_t core_rpc_server::get_block_reward(const block& blk)
  {
    uint64_t reward = 0;
    for(const tx_out& out: blk.miner_tx.vout)
    {
      reward += out.amount;
    }
    return reward;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash)
  {
    PERF_TIMER(fill_block_header_response);
    response.major_version = blk.major_version;
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = string_tools::pod_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = string_tools::pod_to_hex(hash);
    store_difficulty(m_core.get_blockchain_storage().block_difficulty(height),
        response.difficulty, response.wide_difficulty, response.difficulty_top64);
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height),
        response.cumulative_difficulty, response.wide_cumulative_difficulty, response.cumulative_difficulty_top64);
    response.reward = get_block_reward(blk);
    response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.num_txes = blk.tx_hashes.size();
    response.pow_hash = fill_pow_hash ? string_tools::pod_to_hex(get_block_longhash(&(m_core.get_blockchain_storage()), blk, height, 0)) : "";
    response.long_term_weight = m_core.get_blockchain_storage().get_db().get_block_long_term_weight(height);
    response.miner_tx_hash = string_tools::pod_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    response.curve_tree_root = string_tools::pod_to_hex(blk.curve_tree_root);
    response.attestation_root = string_tools::pod_to_hex(blk.attestation_root);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_last_block_header);

    CHECK_CORE_READY();
    uint64_t last_block_height;
    crypto::hash last_block_hash;
    m_core.get_blockchain_top(last_block_height, last_block_hash);
    block last_block;
    bool have_last_block = m_core.get_block_by_hash(last_block_hash, last_block);
    if (!have_last_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get last block.";
      return false;
    }
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(last_block, false, last_block_height, last_block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_header_by_hash);

    const bool restricted = m_restricted && ctx;
    if (restricted && req.hashes.size() > RESTRICTED_BLOCK_COUNT)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many block headers requested in restricted mode";
      return false;
    }

    auto get = [this](const std::string &hash, bool fill_pow_hash, block_header_response &block_header, bool restricted, epee::json_rpc::error& error_resp) -> bool {
      crypto::hash block_hash;
      bool hash_parsed = parse_hash256(hash, block_hash);
      if(!hash_parsed)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + hash + '.';
        return false;
      }
      block blk;
      bool orphan = false;
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by hash. Hash = " + hash + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = std::get<txin_gen>(blk.miner_tx.vin.front()).height;
      bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, block_header, fill_pow_hash && !restricted);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
      return true;
    };

    if (!req.hash.empty())
    {
      if (!get(req.hash, req.fill_pow_hash, res.block_header, restricted, error_resp))
        return false;
    }
    res.block_headers.reserve(req.hashes.size());
    for (const std::string &hash: req.hashes)
    {
      res.block_headers.push_back({});
      if (!get(hash, req.fill_pow_hash, res.block_headers.back(), restricted, error_resp))
        return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_headers_range);

    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = "Invalid start/end heights.";
      return false;
    }
    const bool restricted = m_restricted && ctx;
    if (restricted && req.end_height - req.start_height > RESTRICTED_BLOCK_HEADER_RANGE)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many block headers requested.";
      return false;
    }

    for (uint64_t h = req.start_height; h <= req.end_height; ++h)
    {
      crypto::hash block_hash = m_core.get_block_id_by_height(h);
      block blk;
      bool have_block = m_core.get_block_by_hash(block_hash, blk);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by height. Height = " + boost::lexical_cast<std::string>(h) + ". Hash = " + epee::string_tools::pod_to_hex(block_hash) + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = std::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong height";
        return false;
      }
      res.headers.push_back(block_header_response());
      bool response_filled = fill_block_header_response(blk, false, block_height, block_hash, res.headers.back(), req.fill_pow_hash && !restricted);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  std::string core_rpc_server::stem_tallies_json() const
  {
    return m_p2p.stem_tallies_json();
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_connections);

    res.connections = m_p2p.get_payload_object().get_connections();

    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    if (!on_get_info(req, res, ctx) || res.status != CORE_RPC_STATUS_OK)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = res.status;
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_hard_fork_info(const COMMAND_RPC_HARD_FORK_INFO::request& req, COMMAND_RPC_HARD_FORK_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(hard_fork_info);

    const Blockchain &blockchain = m_core.get_blockchain_storage();
    uint8_t version = req.version > 0 ? req.version : blockchain.get_next_hard_fork_version();
    res.version = blockchain.get_current_hard_fork_version();
    res.enabled = blockchain.get_hard_fork_voting_info(version, res.window, res.votes, res.threshold, res.earliest_height, res.voting);
    res.state = blockchain.get_hard_fork_state();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_bans);

    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first;
        b.ip = 0;
        uint32_t ip;
        if (epee::string_tools::get_ip_int32_from_string(ip, b.host))
          b.ip = ip;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets = m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i = blocked_subnets.begin(); i != blocked_subnets.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first.host_str();
        b.ip = 0;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    PERF_TIMER(on_banned);

    auto na_parsed = net::get_network_address(req.address, 0);
    if (!na_parsed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Unsupported host type";
      return false;
    }
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds))
    {
      res.banned = true;
      res.seconds = seconds;
    }
    else
    {
      res.banned = false;
      res.seconds = 0;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_bans(const COMMAND_RPC_SETBANS::request& req, COMMAND_RPC_SETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(set_bans);

    for (auto i = req.bans.begin(); i != req.bans.end(); ++i)
    {
      epee::net_utils::network_address na;

      // try subnet first
      if (!i->host.empty())
      {
        auto ns_parsed = net::get_ipv4_subnet_address(i->host);
        if (ns_parsed)
        {
          if (i->ban)
            m_p2p.block_subnet(*ns_parsed, i->seconds);
          else
            m_p2p.unblock_subnet(*ns_parsed);
          continue;
        }
      }

      // then host
      if (!i->host.empty())
      {
        auto na_parsed = net::get_network_address(i->host, 0);
        if (!na_parsed)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "Unsupported host/subnet type";
          return false;
        }
        na = std::move(*na_parsed);
      }
      else
      {
        if (!i->ip)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "No ip/host supplied";
          return false;
        }
        na = epee::net_utils::ipv4_network_address{i->ip, 0};
      }
      if (i->ban)
        m_p2p.block_host(na, i->seconds);
      else
        m_p2p.unblock_host(na);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(flush_txpool);

    bool failed = false;
    std::vector<crypto::hash> txids;
    if (req.txids.empty())
    {
      std::vector<transaction> pool_txs;
      bool r = m_core.get_pool_transactions(pool_txs, true);
      if (!r)
      {
        res.status = "Failed to get txpool contents";
        return true;
      }
      for (const auto &tx: pool_txs)
      {
        txids.push_back(cryptonote::get_transaction_hash(tx));
      }
    }
    else
    {
      for (const auto &str: req.txids)
      {
        crypto::hash txid;
        if(!epee::string_tools::hex_to_pod(str, txid))
        {
          failed = true;
        }
        else
        {
          txids.push_back(txid);
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_txes_from_pool(txids))
    {
      res.status = "Failed to remove one or more tx(es)";
      return true;
    }

    if (failed)
    {
      if (txids.empty())
        res.status = "Failed to parse txid";
      else
        res.status = "Failed to parse some of the txids";
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_histogram(const COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request& req, COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_output_histogram);

    const bool restricted = m_restricted && ctx;
    size_t amounts = req.amounts.size();
    if (restricted && amounts == 0)
    {
      res.status = "Restricted RPC will not serve histograms on the whole blockchain. Use your own node.";
      return true;
    }

    if (restricted && req.recent_cutoff > 0 && req.recent_cutoff < (uint64_t)time(NULL) - OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION)
    {
      res.status = "Recent cutoff is too old";
      return true;
    }

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
    try
    {
      histogram = m_core.get_blockchain_storage().get_output_histogram(req.amounts, req.unlocked, req.recent_cutoff, req.min_count);
    }
    catch (const std::exception &e)
    {
      res.status = "Failed to get output histogram";
      return true;
    }

    res.histogram.clear();
    res.histogram.reserve(histogram.size());
    for (const auto &i: histogram)
    {
      if (std::get<0>(i.second) >= req.min_count && (std::get<0>(i.second) <= req.max_count || req.max_count == 0))
        res.histogram.push_back(COMMAND_RPC_GET_OUTPUT_HISTOGRAM::entry(i.first, std::get<0>(i.second), std::get<1>(i.second), std::get<2>(i.second)));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_coinbase_tx_sum);
    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.height >= bc_height || req.count > bc_height)
    {
      res.status = "height or count is too large";
      return true;
    }
    std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> amounts = m_core.get_coinbase_tx_sum(req.height, req.count);
    store_128(amounts.first, res.emission_amount, res.wide_emission_amount, res.emission_amount_top64);
    store_128(amounts.second, res.fee_amount, res.wide_fee_amount, res.fee_amount_top64);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_base_fee_estimate(const COMMAND_RPC_GET_BASE_FEE_ESTIMATE::request& req, COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_base_fee_estimate);

    const uint8_t version = m_core.get_blockchain_storage().get_current_hard_fork_version();
    if (version >= HF_VERSION_2021_SCALING)
    {
      m_core.get_blockchain_storage().get_dynamic_base_fee_estimate_2021_scaling(req.grace_blocks, res.fees);
      res.fee = res.fees[0];
    }
    else
    {
      res.fee = m_core.get_blockchain_storage().get_dynamic_base_fee_estimate(req.grace_blocks);
    }
    res.quantization_mask = Blockchain::get_fee_quantization_mask();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_alternate_chains);
    try
    {
      std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: chains)
      {
        difficulty_type wdiff = i.first.cumulative_difficulty;
        res.chains.push_back(COMMAND_RPC_GET_ALTERNATE_CHAINS::chain_info{epee::string_tools::pod_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second.size(), 0, "", 0, {}, std::string()});
        store_difficulty(wdiff, res.chains.back().difficulty, res.chains.back().wide_difficulty, res.chains.back().difficulty_top64);
        res.chains.back().block_hashes.reserve(i.second.size());
        for (const crypto::hash &block_id: i.second)
          res.chains.back().block_hashes.push_back(epee::string_tools::pod_to_hex(block_id));
        if (i.first.height < i.second.size())
        {
          res.status = "Error finding alternate chain attachment point";
          return true;
        }
        cryptonote::block main_chain_parent_block;
        try { main_chain_parent_block = m_core.get_blockchain_storage().get_db().get_block_from_height(i.first.height - i.second.size()); }
        catch (const std::exception &e) { res.status = "Error finding alternate chain attachment point"; return true; }
        res.chains.back().main_chain_parent_block = epee::string_tools::pod_to_hex(get_block_hash(main_chain_parent_block));
      }
      res.status = CORE_RPC_STATUS_OK;
    }
    catch (...)
    {
      res.status = "Error retrieving alternate chains";
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_limit(const COMMAND_RPC_GET_LIMIT::request& req, COMMAND_RPC_GET_LIMIT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_limit);

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_limit(const COMMAND_RPC_SET_LIMIT::request& req, COMMAND_RPC_SET_LIMIT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_limit);
    // -1 = reset to default
    //  0 = do not modify

    if (req.limit_down > 0)
    {
      epee::net_utils::connection_basic::set_rate_down_limit(req.limit_down);
    }
    else if (req.limit_down < 0)
    {
      if (req.limit_down != -1)
      {
        res.status = "Invalid parameter";
        return true;
      }
      epee::net_utils::connection_basic::set_rate_down_limit(nodetool::default_limit_down);
    }

    if (req.limit_up > 0)
    {
      epee::net_utils::connection_basic::set_rate_up_limit(req.limit_up);
    }
    else if (req.limit_up < 0)
    {
      if (req.limit_up != -1)
      {
        res.status = "Invalid parameter";
        return true;
      }
      epee::net_utils::connection_basic::set_rate_up_limit(nodetool::default_limit_up);
    }

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(out_peers);
    if (req.set)
      m_p2p.change_max_out_public_peers(req.out_peers);
    res.out_peers = m_p2p.get_max_out_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(in_peers);
    if (req.set)
      m_p2p.change_max_in_public_peers(req.in_peers);
    res.in_peers = m_p2p.get_max_in_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_pop_blocks(const COMMAND_RPC_POP_BLOCKS::request& req, COMMAND_RPC_POP_BLOCKS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(pop_blocks);

    m_core.get_blockchain_storage().pop_blocks(req.nblocks);

    res.height = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(relay_tx);

    const bool restricted = m_restricted && ctx;

    bool failed = false;
    res.status = "";
    for (const auto &str: req.txids)
    {
      crypto::hash txid;
      if(!epee::string_tools::hex_to_pod(str, txid))
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("invalid transaction id: ") + str;
        failed = true;
        continue;
      }

      //TODO: The get_pool_transaction could have an optional meta parameter
      bool broadcasted = false;
      cryptonote::blobdata txblob;
      if ((broadcasted = m_core.get_pool_transaction(txid, txblob, relay_category::broadcasted)) || (!restricted && m_core.get_pool_transaction(txid, txblob, relay_category::all)))
      {
        // Q12-D5a residual absorption. Always passes `invalid`. Anything not
        // yet fluff/block (`local` AND `stem` — stem is outside
        // `relay_category::broadcasted`) is remapped to `local`, so
        // `once_at_origin_route` fail-closes onto the anonymity zone. A
        // transaction that rolled clearnet and is still stemming is
        // therefore re-decided onto anon: the zone chosen again after
        // origination, which once-at-origin forbids. Closing it needs the
        // pool meta at this RPC (TODO above). Until then this is a named
        // residual, not a silent p_own=1. FOLLOWUPS.
        NOTIFY_NEW_TRANSACTIONS::request r;
        r.txs.push_back(std::move(txblob));
        const auto tx_relay = broadcasted ? relay_method::fluff : relay_method::local;
        m_core.get_protocol()->relay_transactions(r, boost::uuids::nil_uuid(), epee::net_utils::zone::invalid, tx_relay);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("transaction not found in pool: ") + str;
        failed = true;
        continue;
      }
    }

    if (failed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = res.status;
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(sync_info);

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    res.next_needed_pruning_seed = m_p2p.get_payload_object().get_next_needed_pruning_stripe().second;

    for (const auto &c: m_p2p.get_payload_object().get_connections())
      res.peers.push_back({c});
    const cryptonote::block_queue &block_queue = m_p2p.get_payload_object().get_block_queue();
    block_queue.foreach([&](const cryptonote::block_queue::span &span) {
      const std::string span_connection_id = epee::string_tools::pod_to_hex(span.connection_id);
      uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
      res.spans.push_back({span.start_block_height, span.nblocks, span_connection_id, (uint32_t)(span.rate + 0.5f), speed, span.size, span.origin.str()});
      return true;
    });
    res.overview = block_queue.get_overview(res.height);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_txpool_backlog(const COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_txpool_backlog);

    if (!m_core.get_txpool_backlog(res.backlog))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get txpool backlog";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_prune_blockchain(const COMMAND_RPC_PRUNE_BLOCKCHAIN::request& req, COMMAND_RPC_PRUNE_BLOCKCHAIN::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(prune_blockchain);

    try
    {
      if (!(req.check ? m_core.check_blockchain_pruning() : m_core.prune_blockchain()))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = req.check ? "Failed to check blockchain pruning" : "Failed to prune blockchain";
        return false;
      }
      res.pruning_seed = m_core.get_blockchain_pruning_seed();
      res.pruned = res.pruning_seed != 0;
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to prune blockchain";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(flush_cache);
    if (req.bad_blocks)
      m_core.flush_invalid_blocks();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_curve_tree_path(const COMMAND_RPC_GET_CURVE_TREE_PATH::request& req, COMMAND_RPC_GET_CURVE_TREE_PATH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_curve_tree_path);

    static constexpr size_t MAX_OUTPUTS_PER_RPC_REQUEST = 64;

    if (req.output_indices.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "output_indices must not be empty";
      return false;
    }

    if (req.output_indices.size() > MAX_OUTPUTS_PER_RPC_REQUEST)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Too many output_indices (max " + std::to_string(MAX_OUTPUTS_PER_RPC_REQUEST) + ")";
      return false;
    }

    const auto &db = m_core.get_blockchain_storage().get_db();
    const uint8_t depth = db.get_curve_tree_depth();
    const uint64_t tip_leaf_count = db.get_curve_tree_leaf_count();

    if (tip_leaf_count == 0)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Curve tree is empty";
      return false;
    }

    const uint64_t height = m_core.get_current_blockchain_height();
    const uint64_t top_height = height - 1;
    const uint64_t min_anchor_age = FCMP_REFERENCE_BLOCK_MIN_AGE + 1;
    const uint64_t reference_height = top_height > min_anchor_age ? (top_height - min_anchor_age) : 0;
    const crypto::hash reference_hash = m_core.get_block_id_by_height(reference_height);
    res.reference_block = epee::string_tools::pod_to_hex(reference_hash);
    cryptonote::block ref_blk;
    m_core.get_blockchain_storage().get_block_by_hash(reference_hash, ref_blk);
    res.curve_tree_root = epee::string_tools::pod_to_hex(ref_blk.curve_tree_root);
    res.reference_height = reference_height;
    res.tree_depth = depth;

    // Compute the leaf count at reference_height (not tip) by subtracting
    // leaves drained into the tree after reference_height.
    uint64_t leaves_after_ref = 0;
    for (uint64_t h = reference_height + 1; h <= top_height; ++h)
      leaves_after_ref += db.get_pending_tree_drain_entries(shekyl::db::BlockHeight{h}).size();
    const uint64_t ref_leaf_count = tip_leaf_count - leaves_after_ref;

    res.leaf_count = ref_leaf_count;
    res.paths.clear();

    const uint32_t SELENE_CHUNK_WIDTH = shekyl_curve_tree_selene_chunk_width();
    const uint32_t HELIOS_CHUNK_WIDTH = shekyl_curve_tree_helios_chunk_width();
    static constexpr uint32_t SCALARS_PER_LEAF = 4;

    auto chunk_width = [&](uint8_t layer) -> uint32_t {
      if (layer == 0) return SELENE_CHUNK_WIDTH;
      return (layer % 2 == 0) ? SELENE_CHUNK_WIDTH : HELIOS_CHUNK_WIDTH;
    };

    for (const uint64_t output_idx : req.output_indices)
    {
      COMMAND_RPC_GET_CURVE_TREE_PATH::path_entry entry{};
      entry.output_index = output_idx;
      entry.tree_depth = depth;

      if (output_idx >= tip_leaf_count)
      {
        // Beyond the entire tree: the wallet only knows outputs up to the tip, so this
        // is a malformed request, not a timing race. Hard-fail (WRONG_PARAM) so a client
        // bug surfaces instead of being silently omitted like the not-yet-drained case.
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "output_index " + std::to_string(output_idx) +
                             " >= tip_leaf_count " + std::to_string(tip_leaf_count);
        return false;
      }
      if (output_idx >= ref_leaf_count)
      {
        // In the tree but not yet drained into the *reference* tree (still inside the
        // maturity + reorg window): skip this index rather than failing the whole batch.
        // A wallet legitimately requests paths for all its unspent outputs and matches
        // the returned paths by output_index, waiting for the rest. The omission is
        // unambiguous: an out-of-tree index hard-fails above, and a genuine fault (e.g.
        // the leaf read below) still `return false`s the whole call, so a missing index
        // in a *successful* response means only "not yet in the reference tree".
        continue;
      }

      std::string path_hex;

      // Layer 0: collect leaf scalars in the chunk, bounded by ref_leaf_count
      uint64_t chunk_idx = output_idx / SELENE_CHUNK_WIDTH;
      uint64_t chunk_start = chunk_idx * SELENE_CHUNK_WIDTH;
      uint64_t chunk_end = std::min(chunk_start + static_cast<uint64_t>(SELENE_CHUNK_WIDTH), ref_leaf_count);

      std::vector<uint8_t> path_bytes;
      uint16_t leaf_pos = static_cast<uint16_t>(output_idx - chunk_start);
      path_bytes.push_back(static_cast<uint8_t>(leaf_pos & 0xFF));
      path_bytes.push_back(static_cast<uint8_t>((leaf_pos >> 8) & 0xFF));

      std::vector<uint8_t> chunk_output_bytes;

      for (uint64_t i = chunk_start; i < chunk_end; ++i)
      {
        uint8_t leaf[128];
        if (!db.get_curve_tree_leaf_by_tree_position(i, leaf))
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Failed to read leaf at tree position " + std::to_string(i);
          return false;
        }
        path_bytes.insert(path_bytes.end(), leaf, leaf + 128);

        output_data_t od = db.get_output_key(0, i);
        chunk_output_bytes.insert(chunk_output_bytes.end(),
            reinterpret_cast<const uint8_t*>(od.pubkey.data),
            reinterpret_cast<const uint8_t*>(od.pubkey.data) + 32);

        ge_p3 hp;
        ct::key od_rct;
        memcpy(od_rct.bytes, od.pubkey.data, 32);
        ct::hash_to_p3(hp, od_rct);
        uint8_t ki_gen[32];
        ge_p3_tobytes(ki_gen, &hp);
        chunk_output_bytes.insert(chunk_output_bytes.end(), ki_gen, ki_gen + 32);

        chunk_output_bytes.insert(chunk_output_bytes.end(),
            reinterpret_cast<const uint8_t*>(od.commitment.bytes),
            reinterpret_cast<const uint8_t*>(od.commitment.bytes) + 32);

        chunk_output_bytes.insert(chunk_output_bytes.end(), leaf + 96, leaf + 128);
      }

      entry.chunk_outputs_blob = epee::string_tools::buff_to_hex_nodelimer(
        std::string(reinterpret_cast<const char*>(chunk_output_bytes.data()), chunk_output_bytes.size()));

      // Layers 1..depth: collect sibling hashes with boundary-chunk trimming.
      // The loop emits exactly `depth` branch layers (branch_count == depth), the
      // count the wallet's path parser / FCMP++ signer expect.
      uint64_t ref_nodes_at_prev_layer = ref_leaf_count;
      uint64_t cur_nodes_at_prev_layer = tip_leaf_count;
      uint64_t child_chunk = chunk_idx;

      for (uint8_t layer = 1; layer <= depth; ++layer)
      {
        uint32_t prev_cw = chunk_width(layer - 1);
        uint32_t cw = chunk_width(layer);

        uint64_t ref_chunks_below = (ref_nodes_at_prev_layer + prev_cw - 1) / prev_cw;
        uint64_t cur_chunks_below = (cur_nodes_at_prev_layer + prev_cw - 1) / prev_cw;
        uint64_t last_ref_chunk_below = (ref_chunks_below > 0) ? ref_chunks_below - 1 : 0;

        uint64_t parent_chunk = child_chunk / cw;
        uint64_t sib_start = parent_chunk * cw;
        uint16_t pos_in_parent = static_cast<uint16_t>(child_chunk - sib_start);

        path_bytes.push_back(static_cast<uint8_t>(pos_in_parent & 0xFF));
        path_bytes.push_back(static_cast<uint8_t>((pos_in_parent >> 8) & 0xFF));

        for (uint32_t c = 0; c < cw; ++c)
        {
          uint64_t sibling_chunk = sib_start + c;
          uint8_t hash[32] = {};

          if (sibling_chunk < ref_chunks_below)
          {
            if (!db.get_curve_tree_layer_hash(layer - 1, sibling_chunk, hash))
            {
              error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
              error_resp.message = "Internal error: missing layer hash at layer "
                + std::to_string(layer - 1) + " chunk " + std::to_string(sibling_chunk);
              return false;
            }

            // Trim boundary chunk that grew since reference_height
            if (sibling_chunk == last_ref_chunk_below &&
                ref_nodes_at_prev_layer != cur_nodes_at_prev_layer &&
                ref_nodes_at_prev_layer % prev_cw != 0)
            {
              uint64_t ref_in_chunk = ref_nodes_at_prev_layer - sibling_chunk * prev_cw;
              uint64_t cur_in_chunk = std::min(
                  cur_nodes_at_prev_layer - sibling_chunk * prev_cw,
                  static_cast<uint64_t>(prev_cw));

              if (cur_in_chunk > ref_in_chunk)
              {
                uint64_t scalars_per_entry = (layer == 1) ? SCALARS_PER_LEAF : 1;
                uint64_t trim_offset = ref_in_chunk * scalars_per_entry;
                uint64_t num_extra = cur_in_chunk - ref_in_chunk;
                uint64_t num_extra_scalars = num_extra * scalars_per_entry;

                std::vector<uint8_t> extra_data;
                if (layer == 1)
                {
                  for (uint64_t li = sibling_chunk * prev_cw + ref_in_chunk;
                       li < sibling_chunk * prev_cw + cur_in_chunk; ++li)
                  {
                    uint8_t lf[128];
                    if (db.get_curve_tree_leaf_by_tree_position(li, lf))
                      extra_data.insert(extra_data.end(), lf, lf + 128);
                    else
                      extra_data.insert(extra_data.end(), 128, 0);
                  }
                }
                else
                {
                  for (uint64_t li = sibling_chunk * prev_cw + ref_in_chunk;
                       li < sibling_chunk * prev_cw + cur_in_chunk; ++li)
                  {
                    uint8_t h[32] = {};
                    db.get_curve_tree_layer_hash(layer - 2, li, h);
                    extra_data.insert(extra_data.end(), h, h + 32);
                  }
                }

                uint8_t zero_scalar[32] = {};
                uint8_t trimmed[32];
                bool is_selene = (layer - 1) % 2 == 0;
                bool ok;
                if (is_selene)
                  ok = shekyl_curve_tree_hash_trim_selene(
                      hash, trim_offset, extra_data.data(),
                      num_extra_scalars, zero_scalar, trimmed);
                else
                  ok = shekyl_curve_tree_hash_trim_helios(
                      hash, trim_offset, extra_data.data(),
                      num_extra_scalars, zero_scalar, trimmed);

                if (ok)
                  memcpy(hash, trimmed, 32);
              }
            }
          }
          path_bytes.insert(path_bytes.end(), hash, hash + 32);
        }

        ref_nodes_at_prev_layer = ref_chunks_below;
        cur_nodes_at_prev_layer = cur_chunks_below;
        child_chunk = parent_chunk;
      }

      entry.path_blob = epee::string_tools::buff_to_hex_nodelimer(
        std::string(reinterpret_cast<const char*>(path_bytes.data()), path_bytes.size()));
      res.paths.push_back(std::move(entry));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_curve_tree_info(const COMMAND_RPC_GET_CURVE_TREE_INFO::request& req, COMMAND_RPC_GET_CURVE_TREE_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_curve_tree_info);

    const auto &db = m_core.get_blockchain_storage().get_db();
    const auto root = db.get_curve_tree_root();
    res.root = epee::string_tools::buff_to_hex_nodelimer(
      std::string(reinterpret_cast<const char*>(root.data()), root.size()));
    res.depth = db.get_curve_tree_depth();
    res.leaf_count = db.get_curve_tree_leaf_count();
    res.height = m_core.get_current_blockchain_height() - 1;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_curve_tree_checkpoint(const COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT::request& req, COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_curve_tree_checkpoint);

    const auto &db = m_core.get_blockchain_storage().get_db();
    std::vector<uint8_t> checkpoint_data;
    if (!db.get_curve_tree_checkpoint(req.block_height, checkpoint_data))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "No checkpoint at height " + std::to_string(req.block_height);
      return false;
    }

    if (checkpoint_data.size() < 41)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Corrupt checkpoint data";
      return false;
    }

    res.root = epee::string_tools::buff_to_hex_nodelimer(
      std::string(reinterpret_cast<const char*>(checkpoint_data.data()), 32));
    res.depth = checkpoint_data[32];
    memcpy(&res.leaf_count, checkpoint_data.data() + 33, sizeof(uint64_t));
    res.block_height = req.block_height;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_archival_emission_claim_source(const COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::request& req, COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_archival_emission_claim_source);

    // `p_id` is the ONLY request field (EMISSION_CLAIM_BUILDER.md §7.2):
    // the handler branches on nothing claimable-set-derived — the sole
    // request-dependent branch below is this well-formedness check.
    crypto::hash p_id;
    if (!parse_hash256(req.p_id, p_id))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "p_id must be 64 hex characters (32-byte P_canonical_id)";
      return false;
    }

    try
    {
      // One read view for the whole composite (§7.2 one-read-one-tip): the
      // tip height, the bond record, and every epoch snapshot come from the
      // same LMDB read transaction, so the response cannot straddle a block
      // connect.
      auto& db = m_core.get_blockchain_storage().get_db();
      db_rtxn_guard rtxn_guard(&db);
      rpc::fill_archival_emission_claim_source(db, p_id, res);
    }
    catch (const std::exception& e)
    {
      MERROR("Failed to gather emission claim source: " << e.what());
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to gather emission claim source";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  const command_line::arg_descriptor<std::string, false, true, 2> core_rpc_server::arg_rpc_bind_port = {
      "rpc-bind-port"
    , "Port for RPC server"
    , std::to_string(config::RPC_DEFAULT_PORT)
    , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_stagenet_on }}
    , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
        if (testnet_stagenet[0] && defaulted)
          return std::to_string(config::testnet::RPC_DEFAULT_PORT);
        else if (testnet_stagenet[1] && defaulted)
          return std::to_string(config::stagenet::RPC_DEFAULT_PORT);
        return val;
      }
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_rpc_restricted_bind_port = {
      "rpc-restricted-bind-port"
    , "Port for restricted RPC server"
    , ""
    };

  const command_line::arg_descriptor<bool> core_rpc_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Restrict RPC to view only commands and do not return privacy sensitive data in RPC calls"
    , false
    };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_max_connections_per_public_ip = {
      "rpc-max-connections-per-public-ip"
    , "Max RPC connections per public IP permitted"
    , DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP
  };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_max_connections_per_private_ip = {
      "rpc-max-connections-per-private-ip"
    , "Max RPC connections per private and localhost IP permitted"
    , DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP
  };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_max_connections = {
      "rpc-max-connections"
    , "Max RPC connections permitted"
    , DEFAULT_RPC_MAX_CONNECTIONS
  };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_response_soft_limit = {
      "rpc-response-soft-limit"
    , "Max response bytes that can be queued, enforced at next response attempt"
    , DEFAULT_RPC_SOFT_LIMIT_SIZE
  };
}  // namespace cryptonote

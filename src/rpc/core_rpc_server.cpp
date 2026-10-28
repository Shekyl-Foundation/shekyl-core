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
#include <limits>
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
#include "misc_language.h"
#include "net/local_ip.h"
#include "net/parse.h"
#include "crypto/hash.h"
#include "rpc/archival_claim_source.h"
#include "rpc/archival_shard_coverage.h"
#include "core_rpc_server_error_codes.h"
#include "p2p/net_node.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc"

#define RESTRICTED_BLOCK_HEADER_RANGE 1000
#define RESTRICTED_BLOCK_COUNT 1000

// Performance logging for RPC handlers. The credit/payment accounting that
// previously rode alongside this (the RPCTracker aggregation feeding the
// rpc_access_tracking endpoint) was removed with the RPC-payment subsystem;
// PERF_TIMER retains the per-handler timing log.
#define RPC_TRACKER(rpc) PERF_TIMER(rpc)

namespace
{
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

  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
  {}
  //-----------------------------------------------------------------------------------
  // The origins the bridge hands every bridged handler (core_rpc_ffi.cpp).
  // Two, so whether the caller is the host's administrator is an identity
  // and not a flag beside one context (RPC_CHANNEL.md §6.1: host-only data;
  // RT-O32: the origin carries the host flag only, and the grants stay in
  // Rust). Addresses default-constructed: an origin asserts "an RPC
  // client asked", never "this particular peer asked", and a context shared
  // by every caller must not carry an address anything could score against
  // (tests/unit_tests/rpc_restricted_gate.cpp).
  namespace
  {
    const core_rpc_server::connection_context host_origin{};
    const core_rpc_server::connection_context other_origin{};
  }
  const core_rpc_server::connection_context* rpc_origin(bool host)
  {
    return host ? &host_origin : &other_origin;
  }
  bool rpc_origin_is_host(const epee::net_utils::connection_context_base* ctx)
  {
    return ctx == &host_origin;
  }
  core_rpc_server::~core_rpc_server()
  {
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
#define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
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
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_hash_rate(const COMMAND_RPC_SET_LOG_HASH_RATE::request& req, COMMAND_RPC_SET_LOG_HASH_RATE::response& res, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool);

    const bool allow_sensitive = caller_is_host(ctx);

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

    const bool allow_sensitive = caller_is_host(ctx);

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

    m_core.get_pool_transaction_stats(res.pool_stats, caller_is_host(ctx));

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(stop_daemon);
    // The one stop owner (DAEMON_CONFIG_CUTOVER.md §2.2 step 9) stops the
    // RPC, drained, before the remnant; a stop from here would end run()
    // under the handler answering this request.
    shekyl_daemon_request_stop();
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
    // The coinbase nonce is always present and always SHEKYL_COINBASE_NONCE_BYTES
    // wide (the coinbase grammar, TXE-Q6'), so reserved_offset is always
    // meaningful: the grammar fixes the layout [0x01 pubkey(32), 0x02 len(1)
    // nonce(8), ...], so the nonce begins 34 bytes after the first pubkey
    // byte. The pubkey is fresh per template and locates the extra in the blob.
    blobdata block_blob = t_serializable_object_to_blob(b);
    crypto::public_key tx_pub_key;
    if (shekyl_tx_extra_tx_pubkey(
          b.miner_tx.extra.empty() ? nullptr : b.miner_tx.extra.data(), b.miner_tx.extra.size(),
          reinterpret_cast<uint8_t*>(&tx_pub_key)) != SHEKYL_TX_EXTRA_OK)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to get tx pub key in coinbase extra");
      return false;
    }
    reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if(!reserved_offset)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to find tx pub key in blockblob");
      return false;
    }
    // The grammar's distance from the pubkey byte to the nonce payload
    // (key, 0x02 tag, one-byte length). One source, in shekyl-wire.
    reserved_offset += shekyl_coinbase_nonce_offset_from_pubkey();
    if(reserved_offset + SHEKYL_COINBASE_NONCE_BYTES > block_blob.size())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Coinbase nonce offset past the end of the block blob");
      return false;
    }

    // seed_height was already filled by get_block_template above (same
    // height, same schedule); only the pre-announce needs computing.
    const uint64_t next_height = shekyl_pow_randomx_v2_next_seedheight(height);
    if (next_height != seed_height)
      next_seed_hash = m_core.get_block_id_by_height(next_height);
    else
      next_seed_hash = seed_hash;
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

    // The coinbase nonce is a fixed SHEKYL_COINBASE_NONCE_BYTES (the coinbase
    // grammar, TXE-Q6'): the daemon always reserves exactly that many bytes,
    // so `reserve_size` is accepted only up to it and `extra_nonce` only up
    // to that many bytes (zero-padded). More is a bound violation -- it was
    // the 0..255 free-text region that made the field a covert channel and a
    // length signal -- and is refused with its own code so a pool stack sees
    // the cause rather than a generic parameter error.
    // `extra_nonce` is hex: two digits per payload byte.
    constexpr size_t hex_digits_per_byte = 2;
    if (req.reserve_size > SHEKYL_COINBASE_NONCE_BYTES
        || req.extra_nonce.size() > hex_digits_per_byte * SHEKYL_COINBASE_NONCE_BYTES)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_COINBASE_NONCE_BOUND;
      error_resp.message = "reserve_size / extra_nonce exceed the coinbase nonce width of "
        + std::to_string(SHEKYL_COINBASE_NONCE_BYTES) + " bytes";
      return false;
    }

    if(req.reserve_size && !req.extra_nonce.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Cannot specify both a reserve_size and an extra_nonce";
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
    (void)req; (void)res;
    return false;
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
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_inject_archival_serve_credit(const COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT::request& req, COMMAND_RPC_INJECT_ARCHIVAL_SERVE_CREDIT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  std::string core_rpc_server::stem_tallies_json() const
  {
    return m_p2p.stem_tallies_json();
  }
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_bans);

    for (const auto& row : m_p2p.ban_list())
    {
      COMMAND_RPC_GETBANS::ban b;
      b.host = row.text;
      b.ip = 0;
      uint32_t ip;
      if (epee::string_tools::get_ip_int32_from_string(ip, b.host))
        b.ip = ip;
      b.permanent = row.permanent != 0;
      if (b.permanent)
        b.seconds = 0;
      else if (row.remaining_ns == 0)
        continue;
      else
      {
        const std::uint64_t sec = (row.remaining_ns + 999999999ull) / 1000000000ull;
        b.seconds = sec > std::numeric_limits<std::uint32_t>::max()
          ? std::numeric_limits<std::uint32_t>::max()
          : static_cast<std::uint32_t>(sec);
      }
      res.bans.push_back(std::move(b));
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
      res.permanent = m_p2p.host_ban_is_permanent(na);
      res.seconds = res.permanent ? 0 : static_cast<std::uint32_t>(std::min<std::uint64_t>(
        static_cast<std::uint64_t>(seconds), std::numeric_limits<std::uint32_t>::max()));
    }
    else
    {
      res.banned = false;
      res.permanent = false;
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
          {
            if (!m_p2p.block_subnet(*ns_parsed, i->seconds))
            {
              error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
              error_resp.message = "Ban duration does not fit the clock";
              return false;
            }
          }
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
      {
        if (!m_p2p.block_host(na, i->seconds))
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "Ban duration does not fit the clock";
          return false;
        }
      }
      else
        m_p2p.unblock_host(na);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
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
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_pop_blocks(const COMMAND_RPC_POP_BLOCKS::request& req, COMMAND_RPC_POP_BLOCKS::response& res, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(relay_tx);

    /* No grant check here, deliberately. `relay_tx` is in the `node` grant,
       and that is decided once — in Rust, at the only transport: the method
       table's policy column (`shekyl-rpc-types` `methods.rs`, RW-Q7), read by
       the request's authority before this function is entered. Every row's
       policy is pinned against RPC_CHANNEL.md §6.1 by a test written from the
       section, so moving `relay_tx` out of `node` fails a test rather than
       opening this path.

       This handler once computed `m_restricted && ctx` and skipped the
       `relay_category::all` arm when it held. That expression could not hold in
       any reachable state. It was not defence in depth, it was residue — and
       residue on a security-shaped expression costs more than it looks,
       because two reviewers and this author each read it as a live path and
       priced an exploit from it. RK-D6: who may call a method is
       single-sourced in Rust. */

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
      if ((broadcasted = m_core.get_pool_transaction(txid, txblob, relay_category::broadcasted)) || m_core.get_pool_transaction(txid, txblob, relay_category::all))
      {
        // A pool entry that is not yet broadcast is relayed as local.
        // Hop 0 inside the relay is the construction bit. This call does
        // not choose a connector. Closing the residual that a still-stemming
        // entry is re-sent as local needs the pool meta at this RPC (TODO
        // above). FOLLOWUPS.
        NOTIFY_NEW_TRANSACTIONS::request r;
        r.txs.push_back(std::move(txblob));
        const auto tx_relay = broadcasted ? relay_method::fluff : relay_method::local;
        m_core.get_protocol()->relay_transactions(r, boost::uuids::nil_uuid(), tx_relay);
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
  bool core_rpc_server::on_get_curve_tree_info(const COMMAND_RPC_GET_CURVE_TREE_INFO::request& req, COMMAND_RPC_GET_CURVE_TREE_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_curve_tree_checkpoint(const COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT::request& req, COMMAND_RPC_GET_CURVE_TREE_CHECKPOINT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_archival_emission_claim_source(const COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::request& req, COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)req; (void)res;
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_archival_shard_coverage(const COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::request& /*req*/, COMMAND_RPC_GET_ARCHIVAL_SHARD_COVERAGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    (void)res;
    (void)error_resp;
    (void)ctx;
    return false;
  }
}  // namespace cryptonote

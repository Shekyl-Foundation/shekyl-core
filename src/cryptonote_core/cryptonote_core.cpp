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

#include <boost/algorithm/string.hpp>
#include <boost/uuid/nil_generator.hpp>

#include "string_tools.h"
using namespace epee;

#include <unordered_set>
#include "cryptonote_core.h"
#include "common/util.h"
#include "common/threadpool.h"
#include "cryptonote_basic/events.h"
#include "warnings.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "file_io_utils.h"
#include <csignal>
#include "fcmp/ct_types.h"
#include "fcmp/ct_semantics.h"
#include "tx_verification_utils.h"
#include "version.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/drop_verdict.h"
#include "cryptonote_basic/block_ingest.h"

#include <cstring>

#include <boost/filesystem.hpp>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "cn"

DISABLE_VS_WARNINGS(4355)

#define MERROR_VER(x) MCERROR("verify", x)

// basically at least how many bytes the block itself serializes to without the miner tx
namespace {
cryptonote::core* shell_for_relay = nullptr;
}

/// The node's committed transaction, as bytes, for `levin_notify`.
/// RD deletes this with `levin_notify` (`DRS_X_STORE_FLIP.md` §2).
/// A call before `core::init` returns, or after `deinit`, does nothing.
extern "C" void shekyl_shell_relay_local(const std::uint8_t* blob, std::size_t len)
{
  if (shell_for_relay == nullptr || blob == nullptr || len == 0)
    return;
  auto* protocol = shell_for_relay->get_protocol();
  if (protocol == nullptr)
    return;
  cryptonote::NOTIFY_NEW_TRANSACTIONS::request request;
  request.txs.emplace_back(reinterpret_cast<const char*>(blob), len);
  protocol->relay_transactions(request, boost::uuids::nil_uuid(), cryptonote::relay_method::local);
}

namespace cryptonote
{

  //-----------------------------------------------------------------------------------------------
  core::core(i_cryptonote_protocol* pprotocol):
              m_starter_message_showed(false),
              m_target_blockchain_height(0),
              m_nettype(UNDEFINED)
  {
    set_cryptonote_protocol(pprotocol);
  }
  void core::set_cryptonote_protocol(i_cryptonote_protocol* pprotocol)
  {
    if(pprotocol)
      m_pprotocol = pprotocol;
    else
      m_pprotocol = &m_protocol_stub;
  }
  //-----------------------------------------------------------------------------------
  void core::stop()
  {
  }
  //-----------------------------------------------------------------------------------
  uint64_t core::get_current_blockchain_height() const
  {
    std::uint64_t count = 0;
    if (shekyl_core_height(&count) != 0)
      return 0;
    return count;
  }
  //-----------------------------------------------------------------------------------------------
  void core::get_blockchain_top(uint64_t& height, crypto::hash& top_id) const
  {
    std::uint64_t top = 0;
    std::uint8_t hash[32] = {};
    if (shekyl_core_top(&top, hash) != 0)
    {
      height = 0;
      top_id = crypto::null_hash;
      return;
    }
    height = top;
    std::memcpy(top_id.data, hash, sizeof(hash));
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks, std::vector<cryptonote::blobdata>& txs) const
{
    return {};
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks) const
{
    return {};
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<block>& blocks) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  namespace
  {
    void free_buffer(ShekylBuffer& buffer)
    {
      shekyl_buffer_free(buffer.ptr, buffer.len);
      buffer.ptr = nullptr;
      buffer.len = 0;
    }

    /// One snapshot of the node's chain, then the pool for whatever that
    /// snapshot does not hold. `pruned` is not a second read: a region this
    /// node discarded is missing.
    bool core_tx_blobs(const std::vector<crypto::hash>& ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed)
    {
      txs.clear();
      missed.clear();
      if (ids.empty())
        return true;
      std::vector<std::uint8_t> raw(ids.size() * sizeof(crypto::hash));
      for (std::size_t i = 0; i < ids.size(); ++i)
        std::memcpy(raw.data() + i * sizeof(crypto::hash), ids[i].data, sizeof(crypto::hash));
      ShekylBuffer packed{};
      if (shekyl_core_txs(raw.data(), ids.size(), &packed) != 0)
      {
        free_buffer(packed);
        return false;
      }
      const std::uint8_t* cursor = packed.ptr;
      const std::uint8_t* const end = packed.ptr == nullptr ? nullptr : packed.ptr + packed.len;
      for (const crypto::hash& id : ids)
      {
        if (cursor == nullptr || cursor >= end)
        {
          free_buffer(packed);
          return false;
        }
        const std::uint8_t tag = *cursor++;
        if (tag == 0)
        {
          missed.push_back(id);
          continue;
        }
        if (tag != 1 || static_cast<std::size_t>(end - cursor) < 4)
        {
          free_buffer(packed);
          return false;
        }
        const std::uint32_t len = static_cast<std::uint32_t>(cursor[0])
          | (static_cast<std::uint32_t>(cursor[1]) << 8)
          | (static_cast<std::uint32_t>(cursor[2]) << 16)
          | (static_cast<std::uint32_t>(cursor[3]) << 24);
        cursor += 4;
        if (static_cast<std::size_t>(end - cursor) < len)
        {
          free_buffer(packed);
          return false;
        }
        txs.emplace_back(reinterpret_cast<const char*>(cursor), static_cast<std::size_t>(len));
        cursor += len;
      }
      free_buffer(packed);
      return true;
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
  {
    (void)pruned;
    return core_tx_blobs(txs_ids, txs, missed_txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<transaction>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
  {
    (void)pruned;
    std::vector<cryptonote::blobdata> blobs;
    if (!core_tx_blobs(txs_ids, blobs, missed_txs))
      return false;
    txs.clear();
    txs.reserve(blobs.size());
    for (const auto& blob : blobs)
    {
      transaction tx;
      if (!parse_and_validate_tx_from_blob(blob, tx))
        return false;
      txs.push_back(std::move(tx));
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_alternative_blocks(std::vector<block>& blocks) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_alternative_blocks_count() const
{
    return 0;
  }
  //-----------------------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------------------
  bool parse_db_sync_mode(const std::string &spec, bool is_default,
                          db_sync_settings &out, std::string &error)
  {
    db_sync_settings parsed;

    std::string trimmed = spec;
    boost::trim(trimmed);

    // An empty specification is "not specified": the defaults below stand. The
    // pre-2026-09-13 form had an `options.size() == 0` branch for this, which
    // boost::split can never produce -- splitting "" yields one empty element,
    // not an empty vector -- so the branch was unreachable and the empty string
    // fell through to the silent-default `else` this function replaces.
    if (trimmed.empty())
    {
      parsed.db_flags = DBF_FAST;
      out = parsed;
      return true;
    }

    std::vector<std::string> options;
    boost::split(options, trimmed, boost::is_any_of(" :"));

    for (const auto &option : options)
      MDEBUG("option: " << option);

    bool safemode = false;
    if (options[0] == "safe")
    {
      safemode = true;
      parsed.db_flags = DBF_SAFE;
      parsed.sync_mode = is_default ? db_defaultsync : db_nosync;
    }
    else if (options[0] == "fast")
    {
      parsed.db_flags = DBF_FAST;
      parsed.sync_mode = is_default ? db_defaultsync : db_async;
    }
    else if (options[0] == "fastest")
    {
      parsed.db_flags = DBF_FASTEST;
      parsed.sync_threshold = 1000; // default to fastest:async:1000
      parsed.sync_mode = is_default ? db_defaultsync : db_async;
    }
    else
    {
      // FAIL CLOSED. The pre-2026-09-13 form was `else db_flags = DEFAULT_FLAGS;`
      // with no diagnostic, and DEFAULT_FLAGS is DBF_FAST, which db_lmdb maps to
      // MDB_NOSYNC -- so `--db-sync-mode=saf` silently selected the LEAST durable
      // mode. Pre-genesis there is no deployed base to break, so an unrecognised
      // token refuses to start instead.
      error = "unrecognised db sync mode \"" + options[0] + "\"; expected safe, fast or fastest";
      return false;
    }

    if (options.size() >= 2 && !safemode)
    {
      if (options[1] == "sync")
        parsed.sync_mode = is_default ? db_defaultsync : db_sync;
      else if (options[1] == "async")
        parsed.sync_mode = is_default ? db_defaultsync : db_async;
      else
      {
        // The same defect one field along, and it had no `else` at all: an
        // unrecognised options[1] was silently ignored, leaving whatever
        // options[0] had chosen. Same durability setting, same treatment.
        error = "unrecognised db sync policy \"" + options[1] + "\"; expected sync or async";
        return false;
      }
    }

    if (options.size() >= 3 && !safemode)
    {
      char *endptr;
      const uint64_t threshold = strtoull(options[2].c_str(), &endptr, 0);
      if (*endptr == '\0' || !strcmp(endptr, "blocks"))
      {
        parsed.sync_on_blocks = true;
        parsed.sync_threshold = threshold;
      }
      else if (!strcmp(endptr, "bytes"))
      {
        parsed.sync_on_blocks = false;
        parsed.sync_threshold = threshold;
      }
      else
      {
        // Unchanged: this token already refused. The two above now match it.
        error = "invalid db sync threshold \"" + options[2] + "\"; expected <n>, <n>blocks or <n>bytes";
        return false;
      }
    }

    out = parsed;
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::init(const ShekylDaemonSnapshot& snapshot, const cryptonote::test_options *test_options)
  {
    start_time = std::time(nullptr);

    // The snapshot's network code is `network_type`'s (DAEMON_CONFIG_CUTOVER.md
    // §2.9); a test's own options select FAKECHAIN as regtest does.
    const bool regtest = snapshot.network == static_cast<std::uint8_t>(FAKECHAIN);
    m_nettype = (test_options != NULL || regtest) ? FAKECHAIN : static_cast<network_type>(snapshot.network);
    m_config_folder = snapshot.data_dir;
    m_offline = snapshot.offline;

    // Seeds follow the network just settled, including FAKECHAIN. The id
    // derivation is pure (`get_config` builds every network's id on first
    // use), so it cannot carry this record.
    CHECK_AND_ASSERT_MES(
      shekyl_dialer_note_network(static_cast<std::uint8_t>(m_nettype)) == 0,
      false, "Failed to record the dialer's network");

    // The chain is the Rust store. This shell records the network and the
    // relay entry; it does not open a second database.
    block_sync_size = 0;
    shell_for_relay = this;
    return load_state_data();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::set_genesis_block(const block& b)
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::load_state_data()
  {
    // may be some code later
    return true;
  }
  //-----------------------------------------------------------------------------------------------
    bool core::deinit()
  {
    if (shell_for_relay == this)
      shell_for_relay = nullptr;
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx(const blobdata& tx_blob, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
  {
    tvc = {};
    (void)relayed;
    const int32_t outcome = shekyl_pool_admit(
      reinterpret_cast<const std::uint8_t*>(tx_blob.data()), tx_blob.size());
    switch (outcome)
    {
      case SHEKYL_POOL_ADMITTED:
        tvc.m_added_to_pool = true;
        tvc.m_relay = tx_relay;
        return true;
      case SHEKYL_POOL_HELD:
        return true;
      case SHEKYL_POOL_REFUSED_FORM:
        tvc.m_verifivation_failed = true;
        return reject_form(tvc);
      case SHEKYL_POOL_REFUSED_STATE:
        tvc.m_verifivation_failed = true;
        return reject_state(tvc);
      default:
        tvc.m_verifivation_failed = true;
        return reject_internal(tvc);
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_semantic(const transaction& tx, tx_verification_context& tvc)
  {
    if(!tx.vin.size())
    {
      MERROR_VER("tx with empty inputs, rejected for tx id= " << get_transaction_hash(tx));
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      MERROR_VER("unsupported input types for tx id= " << get_transaction_hash(tx));
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    if(!check_outs_valid(tx))
    {
      MERROR_VER("tx with invalid outputs, rejected for tx id= " << get_transaction_hash(tx));
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_output = true;
      return false;
    }
    if (tx.version > 1)
    {
      if (tx.ct_signatures.outPk.size() != tx.vout.size())
      {
        MERROR_VER("tx with mismatched vout/outPk count, rejected for tx id= " << get_transaction_hash(tx));
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_output = true;
        return false;
      }
    }

    // CEN-I19: the 0x06 / 0x07 fields are per-output consensus data (the
    // recipient's KEM ciphertext; the curve-tree leaf's fourth scalar). Their
    // count and length against vout.size() is checked here, on relay and on
    // block, with no kept_by_block exemption -- a leaf-construction
    // invariant, not relay policy. The DB collector below admission aborts
    // on the same shape rather than zero-filling (blockchain_db.cpp).
    {
      std::string why;
      if (!check_tx_extra_shape(tx, why))
      {
        MERROR_VER(why << ", rejected for tx id= " << get_transaction_hash(tx));
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_output = true;
        return false;
      }
    }

    if(!check_money_overflow(tx))
    {
      MERROR_VER("tx has money overflow, rejected for tx id= " << get_transaction_hash(tx));
      tvc.m_verifivation_failed = true;
      tvc.m_overspend = true;
      return false;
    }

    // FCMP++ signatures check verifies amounts match for v3+ transactions

    //check if tx use different key images
    if(!check_tx_inputs_keyimages_diff(tx))
    {
      MERROR_VER("tx uses a single key image more than once");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    if (!check_tx_inputs_ring_members_diff(tx))
    {
      MERROR_VER("tx uses duplicate ring members");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    if (!check_tx_inputs_keyimages_domain(tx))
    {
      MERROR_VER("tx uses key image not in the valid domain");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    if (!check_output_types(tx))
    {
      MERROR_VER("tx does not use valid output type(s)");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_output = true;
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::is_key_image_spent(const crypto::key_image &key_image) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_block_sync_size(uint64_t height) const
  {
    size_t res = block_sync_size > 0 ? block_sync_size : BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;

    // Single source for the effective epoch length: the same clamped
    // value the seed-epoch schedule itself uses (mainnet default, or
    // the SEEDHASH_EPOCH_BLOCKS regtest override). This replaces an
    // independent env parse with different clamp semantics (round-up,
    // unbounded) that could let a sync batch span a seed-epoch
    // boundary while the schedule silently ran the default.
    static size_t max_block_size = 0;
    if (max_block_size == 0)
      max_block_size = shekyl_pow_randomx_v2_seed_epoch_blocks();
    if (res > max_block_size)
    {
      static bool warned = false;
      if (!warned)
      {
        MWARNING("Clamping block sync size to " << max_block_size);
        warned = true;
      }
      res = max_block_size;
    }
    return res;
  }
  //-----------------------------------------------------------------------------------------------
  std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> core::get_coinbase_tx_sum(const uint64_t start_offset, const size_t count)
{
    return {};
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_keyimages_diff(const transaction& tx)
  {
    std::unordered_set<crypto::key_image> ki;
    for(const auto& in: tx.vin)
    {
      if (std::holds_alternative<txin_to_key>(in))
      {
        if(!ki.insert(std::get<txin_to_key>(in).k_image).second)
          return false;
      }
      else if (std::holds_alternative<txin_archival_serve_credit_response>(in))
      {
        continue;
      }
      else if (std::holds_alternative<txin_archival_bond_post>(in))
      {
        continue;
      }
      else if (std::holds_alternative<txin_archival_reward_emission>(in))
      {
        continue;
      }
      else
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
        if(!ki.insert(tokey_in.k_image).second)
          return false;
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_ring_members_diff(const transaction& tx)
  {
    for(const auto& in: tx.vin)
    {
      if (std::holds_alternative<txin_archival_serve_credit_response>(in))
        continue;
      if (std::holds_alternative<txin_archival_bond_post>(in))
        continue;
      if (std::holds_alternative<txin_archival_reward_emission>(in))
        continue;
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      for (size_t n = 1; n < tokey_in.key_offsets.size(); ++n)
        if (tokey_in.key_offsets[n] == 0)
          return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_keyimages_domain(const transaction& tx)
  {
    std::unordered_set<crypto::key_image> ki;
    for(const auto& in: tx.vin)
    {
      if (std::holds_alternative<txin_archival_serve_credit_response>(in))
        continue;
      if (std::holds_alternative<txin_archival_bond_post>(in))
        continue;
      if (std::holds_alternative<txin_archival_reward_emission>(in))
        continue;
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if (ct::ki2rct(tokey_in.k_image) == ct::identity())
        return false;
      if (!(ct::scalarmultKey(ct::ki2rct(tokey_in.k_image), ct::curveOrder()) == ct::identity()))
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
  {
    crypto::hash tx_hash = get_transaction_hash(tx);
    blobdata bl;
    t_serializable_object_to_blob(tx, bl);
    size_t tx_weight = get_transaction_weight(tx, bl.size());
    return add_new_tx(tx, tx_hash, bl, tx_weight, tvc, tx_relay, relayed);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_blockchain_total_transactions() const
{
    return 0;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, const crypto::hash& tx_hash, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::relay_txpool_transactions()
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::notify_txpool_event(const epee::span<const cryptonote::blobdata> tx_blobs, epee::span<const crypto::hash> tx_hashes, epee::span<const cryptonote::transaction> txs, const std::vector<bool> &just_broadcasted) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_stem_propagated(const epee::span<const crypto::hash> txids)
  {
    /* A pass-through by design. The verdict is the relay layer's, the entry
       class is the pool's, and this seam exists only because `notify` holds no
       pool reference — so it forwards and decides nothing. */
    std::vector<std::uint8_t> raw(txids.size() * sizeof(crypto::hash));
    for (std::size_t i = 0; i < txids.size(); ++i)
      std::memcpy(raw.data() + i * sizeof(crypto::hash), txids[i].data, sizeof(crypto::hash));
    if (!txids.empty())
      shekyl_pool_propagated(raw.data(), txids.size());
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_transactions_relayed(const epee::span<const cryptonote::blobdata> tx_blobs, const relay_method tx_relay, const std::optional<std::uint8_t> stem_connector)
  {
    (void)stem_connector;
    if (!matches_category(tx_relay, relay_category::broadcasted))
      return;
    for (const auto& blob : tx_blobs)
    {
      transaction tx;
      crypto::hash id;
      if (!parse_and_validate_tx_from_blob(blob, tx, id))
      {
        LOG_ERROR("Failed to parse relayed transaction");
        return;
      }
      shekyl_pool_fluffed(reinterpret_cast<const std::uint8_t*>(id.data));
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_template(block& b, const account_public_address& adr, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_miner_data(uint8_t& major_version, uint64_t& height, crypto::hash& prev_id, crypto::hash& seed_hash, difficulty_type& difficulty, uint64_t& median_weight, uint64_t& already_generated_coins, std::vector<tx_block_template_backlog_entry>& tx_backlog)
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
  {
    std::vector<std::uint8_t> ids;
    ids.reserve(qblock_ids.size() * sizeof(crypto::hash));
    for (const auto& id : qblock_ids)
      ids.insert(ids.end(), reinterpret_cast<const std::uint8_t*>(id.data), reinterpret_cast<const std::uint8_t*>(id.data) + sizeof(id.data));
    ShekylBuffer hashes{nullptr, 0};
    ShekylBuffer weights{nullptr, 0};
    std::uint64_t start = 0, total = 0, lo = 0, hi = 0;
    const int rc = shekyl_core_supplement(
      ids.empty() ? nullptr : ids.data(), qblock_ids.size(),
      &hashes, &weights, &start, &total, &lo, &hi);
    if (rc != 0)
    {
      shekyl_buffer_free(hashes.ptr, hashes.len);
      shekyl_buffer_free(weights.ptr, weights.len);
      return false;
    }
    resp.start_height = start;
    resp.total_height = total;
    resp.cumulative_difficulty = lo;
    resp.cumulative_difficulty_top64 = hi;
    resp.m_block_ids.clear();
    resp.m_block_weights.clear();
    const std::size_t n = hashes.len / sizeof(crypto::hash);
    resp.m_block_ids.resize(n);
    if (n)
      std::memcpy(resp.m_block_ids.data(), hashes.ptr, hashes.len);
    resp.m_block_weights.resize(weights.len / sizeof(std::uint64_t));
    if (!resp.m_block_weights.empty())
      std::memcpy(resp.m_block_weights.data(), weights.ptr, weights.len);
    shekyl_buffer_free(hashes.ptr, hashes.len);
    shekyl_buffer_free(weights.ptr, weights.len);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_block_found(block& b, block_verification_context &bvc)
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::is_synchronized() const
  {
    return m_pprotocol != nullptr && m_pprotocol->is_synchronized();
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_synchronized()
  {
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_block(const block& b, block_verification_context& bvc,
    block_connect_supplement& connect)
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_block(const blobdata& block_blob, const block *b,
    block_verification_context& bvc, bool update_miner_blocktemplate)
  {
    block_connect_supplement connect{};
    return handle_incoming_block(block_blob, b, bvc, connect, update_miner_blocktemplate);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_block(const blobdata& block_blob, const block *b,
    block_verification_context& bvc, block_connect_supplement& connect, bool update_miner_blocktemplate)
  {
    TRY_ENTRY();

    bvc = {};

    if (!check_incoming_block_size(block_blob))
    {
      return reject_block_state(bvc);
    }

    if (((size_t)-1) <= 0xffffffff && block_blob.size() >= 0x3fffffff)
      MWARNING("This block's size is " << block_blob.size() << ", closing on the 32 bit limit");

    block lb;
    if (!b)
    {
      crypto::hash block_hash;
      if(!parse_and_validate_block_from_blob(block_blob, lb, block_hash))
      {
        LOG_PRINT_L1("Failed to parse and validate new block");
        return reject_block_form(bvc);
      }
      b = &lb;
    }
    add_new_block(*b, bvc, connect);
    if(update_miner_blocktemplate && block_added(bvc))
       update_miner_block_template();
    return true;
    }
    catch(const std::exception& ex)
    {
      LOG_ERROR("Exception at [core::handle_incoming_block()], what=" << ex.what());
      reject_block_internal(bvc);
      return false;
    }
    catch(...)
    {
      LOG_ERROR("Exception at [core::handle_incoming_block()], generic exception \"...\"");
      reject_block_internal(bvc);
      return false;
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_single_incoming_block(const blobdata& block_blob,
    const block *b,
    block_verification_context& bvc,
    block_connect_supplement& connect,
    bool update_miner_blocktemplate)
  {
    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);
    return handle_incoming_block(block_blob, b, bvc, connect, update_miner_blocktemplate);
  }
  //-----------------------------------------------------------------------------------------------
  // Used by the RPC server to check the size of an incoming
  // block_blob
  bool core::check_incoming_block_size(const blobdata& block_blob) const
  {
    // The store applies the weight limit. This is only the absurd-size
    // refusal that used to sit in front of the C++ chain.
    if (block_blob.size() > 100 * 1024 * 1024)
    {
      LOG_PRINT_L1("WRONG BLOCK BLOB, sanity check failed on size " << block_blob.size() << ", rejected");
      return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_tail_id() const
  {
    uint64_t height = 0;
    crypto::hash top = crypto::null_hash;
    get_blockchain_top(height, top);
    return top;
  }
  //-----------------------------------------------------------------------------------------------
  difficulty_type core::get_block_cumulative_difficulty(uint64_t height) const
  {
    std::uint64_t lo = 0, hi = 0;
    if (shekyl_core_cumulative_difficulty(height, &lo, &hi) != 0)
      return 0;
    return (difficulty_type(hi) << 64) | lo;
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_pool_transactions_count(bool include_sensitive_txes) const
{
    return 0;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block_unlocked(const crypto::hash& id, int *where) const
  {
    std::int32_t found = SHEKYL_CORE_ABSENT;
    if (shekyl_core_have_block(reinterpret_cast<const std::uint8_t*>(id.data), &found) != 0)
      return false;
    if (found == SHEKYL_CORE_ABSENT)
      return false;
    if (where)
      *where = found;
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block(const crypto::hash& id, int *where) const
  {
    return have_block_unlocked(id, where);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions(std::vector<transaction>& txs, bool include_sensitive_data) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_data) const
  {
    ShekylBuffer buffer{nullptr, 0};
    if (shekyl_pool_hashes(include_sensitive_data ? 1 : 0, &buffer) != 0)
      return false;
    const bool ok = buffer.len % sizeof(crypto::hash) == 0;
    if (ok)
    {
      txs.resize(buffer.len / sizeof(crypto::hash));
      if (!txs.empty())
        std::memcpy(txs.data(), buffer.ptr, buffer.len);
    }
    shekyl_buffer_free(buffer.ptr, buffer.len);
    return ok;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction(const crypto::hash &id, cryptonote::blobdata& tx, relay_category tx_category) const
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::pool_has_tx(const crypto::hash &id) const
  {
    // Membership, stem included: the relay's question (i_core_events). A
    // compact block resolves shown bodies only, and does not call this.
    return shekyl_pool_has(reinterpret_cast<const std::uint8_t*>(id.data)) == 1;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_short_chain_history(std::list<crypto::hash>& ids, uint64_t& current_height) const
  {
    ShekylBuffer hashes{nullptr, 0};
    std::uint64_t count = 0;
    if (shekyl_core_short_history(&hashes, &count) != 0)
    {
      shekyl_buffer_free(hashes.ptr, hashes.len);
      return false;
    }
    current_height = count;
    ids.clear();
    for (std::size_t i = 0; i + sizeof(crypto::hash) <= hashes.len; i += sizeof(crypto::hash))
    {
      crypto::hash id = crypto::null_hash;
      std::memcpy(id.data, hashes.ptr + i, sizeof(id.data));
      ids.push_back(id);
    }
    shekyl_buffer_free(hashes.ptr, hashes.len);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote_connection_context& context)
  {
    (void)context;
    std::uint64_t height = 0;
    if (shekyl_core_height(&height) != 0)
      return false;
    rsp.current_blockchain_height = height;
    rsp.blocks.clear();
    rsp.missed_ids.clear();
    for (const crypto::hash& id : arg.blocks)
    {
      ShekylBuffer blob{};
      ShekylBuffer witness{};
      int32_t alt = 0;
      std::uint64_t weight = 0;
      const int32_t rc = shekyl_core_block(reinterpret_cast<const std::uint8_t*>(id.data), &blob, &witness, &alt, &weight);
      if (rc == SHEKYL_CORE_ABSENT)
      {
        shekyl_buffer_free(blob.ptr, blob.len);
        shekyl_buffer_free(witness.ptr, witness.len);
        rsp.missed_ids.push_back(id);
        continue;
      }
      if (rc != 0 || blob.ptr == nullptr)
      {
        shekyl_buffer_free(blob.ptr, blob.len);
        shekyl_buffer_free(witness.ptr, witness.len);
        return false;
      }
      block_complete_entry entry;
      entry.pruned = arg.prune;
      entry.block_weight = weight;
      entry.block.assign(reinterpret_cast<const char*>(blob.ptr), blob.len);
      if (witness.ptr != nullptr && witness.len != 0)
        entry.attestation_witness.assign(reinterpret_cast<const char*>(witness.ptr), witness.len);
      shekyl_buffer_free(blob.ptr, blob.len);
      shekyl_buffer_free(witness.ptr, witness.len);
      block parsed;
      if (!parse_and_validate_block_from_blob(entry.block, parsed))
        return false;
      std::vector<cryptonote::blobdata> tx_blobs;
      std::vector<crypto::hash> missed_txs;
      if (!get_transactions(parsed.tx_hashes, tx_blobs, missed_txs, false))
        return false;
      if (!missed_txs.empty())
      {
        rsp.missed_ids.insert(rsp.missed_ids.end(), missed_txs.begin(), missed_txs.end());
        return false;
      }
      entry.txs.reserve(tx_blobs.size());
      for (auto& tx : tx_blobs)
        entry.txs.emplace_back(std::move(tx), crypto::null_hash);
      rsp.blocks.push_back(std::move(entry));
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_block_id_by_height(uint64_t height) const
  {
    crypto::hash id = crypto::null_hash;
    std::uint8_t hash[32] = {};
    if (shekyl_core_hash_at(height, hash) != 0)
      return id;
    std::memcpy(id.data, hash, sizeof(hash));
    return id;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
  {
    ShekylBuffer blob{};
    ShekylBuffer witness{};
    int32_t alt = 0;
    std::uint64_t weight = 0;
    const int32_t rc = shekyl_core_block(reinterpret_cast<const std::uint8_t*>(h.data), &blob, &witness, &alt, &weight);
    cryptonote::blobdata bytes;
    if (rc == 0 && blob.ptr != nullptr)
      bytes.assign(reinterpret_cast<const char*>(blob.ptr), blob.len);
    shekyl_buffer_free(blob.ptr, blob.len);
    shekyl_buffer_free(witness.ptr, witness.len);
    if (rc != 0 || bytes.empty())
      return false;
    if (!parse_and_validate_block_from_blob(bytes, blk))
      return false;
    if (orphan)
      *orphan = alt != 0;
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  blobdata core::get_block_attestation_witness(const block &blk) const
  {
    const crypto::hash id = get_block_hash(blk);
    ShekylBuffer blob{};
    ShekylBuffer witness{};
    int32_t alt = 0;
    std::uint64_t weight = 0;
    const int32_t rc = shekyl_core_block(reinterpret_cast<const std::uint8_t*>(id.data), &blob, &witness, &alt, &weight);
    blobdata out;
    if (rc == 0 && witness.ptr != nullptr && witness.len != 0)
      out.assign(reinterpret_cast<const char*>(witness.ptr), witness.len);
    shekyl_buffer_free(blob.ptr, blob.len);
    shekyl_buffer_free(witness.ptr, witness.len);
    return out;
  }
  //-----------------------------------------------------------------------------------------------
  std::string core::print_pool(bool short_format) const
{
    return {};
  }
  //-----------------------------------------------------------------------------------------------
  bool core::update_miner_block_template()
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::on_idle()
  {
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_disk_space()
  {
    uint64_t free_space = get_free_space();
    if (free_space < 1ull * 1024 * 1024 * 1024) // 1 GB
    {
      const el::Level level = el::Level::Warning;
      MCLOG_RED(level, "global", "Free space is below 1 GB on " << m_config_folder);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_block_rate()
{
    return false;
  }
  //-----------------------------------------------------------------------------------------------
  void core::flush_invalid_blocks()
{
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_txpool_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes)
  {
    ShekylBuffer buffer{nullptr, 0};
    const int rc = shekyl_pool_complement(
      hashes.empty() ? nullptr : reinterpret_cast<const std::uint8_t*>(hashes.data()),
      hashes.size(), &buffer);
    if (rc != 0)
      return false;
    txes.clear();
    if (buffer.len == 0)
    {
      shekyl_buffer_free(buffer.ptr, buffer.len);
      return true;
    }
    const std::uint8_t* cursor = buffer.ptr;
    const std::uint8_t* const end = buffer.ptr + buffer.len;
    bool ok = true;
    while (ok && cursor != end)
    {
      if (static_cast<std::size_t>(end - cursor) < 4)
      {
        ok = false;
        break;
      }
      const std::uint32_t len = std::uint32_t(cursor[0])
        | (std::uint32_t(cursor[1]) << 8)
        | (std::uint32_t(cursor[2]) << 16)
        | (std::uint32_t(cursor[3]) << 24);
      cursor += 4;
      if (static_cast<std::size_t>(end - cursor) < len)
      {
        ok = false;
        break;
      }
      txes.emplace_back(reinterpret_cast<const char*>(cursor), len);
      cursor += len;
    }
    shekyl_buffer_free(buffer.ptr, buffer.len);
    return ok;
  }
  //-----------------------------------------------------------------------------------------------
  void core::set_target_blockchain_height(uint64_t target_blockchain_height)
  {
    m_target_blockchain_height = target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_target_blockchain_height() const
  {
    return m_target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_free_space() const
  {
    boost::filesystem::path path(m_config_folder);
    boost::filesystem::space_info si = boost::filesystem::space(path);
    return si.available;
  }
  //-----------------------------------------------------------------------------------------------
  std::time_t core::get_start_time() const
  {
    return start_time;
  }
  //-----------------------------------------------------------------------------------------------
  void core::graceful_exit()
  {
    raise(SIGTERM);
  }
}

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
#include "cryptonote_config.h"
#include "misc_language.h"
#include "file_io_utils.h"
#include <csignal>
#include "checkpoints/checkpoints.h"
#include "fcmp/ct_types.h"
#include "blockchain_db/blockchain_db.h"
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
#define BLOCK_SIZE_SANITY_LEEWAY 100

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
  // m_mempool and m_blockchain_storage hold references to each other.
  // m_blockchain_storage is not dereferenced during m_mempool construction,
  // so passing the not-yet-constructed reference is safe.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
  core::core(i_cryptonote_protocol* pprotocol):
              m_mempool(m_blockchain_storage),
              m_blockchain_storage(m_mempool),
              m_miner(this, [this](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, crypto::hash &hash) {
                return cryptonote::get_block_longhash(&m_blockchain_storage, b, hash, height, seed_hash);
              }),
              m_starter_message_showed(false),
              m_target_blockchain_height(0),
              m_nettype(UNDEFINED)
  {
    set_cryptonote_protocol(pprotocol);
  }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
  void core::set_cryptonote_protocol(i_cryptonote_protocol* pprotocol)
  {
    if(pprotocol)
      m_pprotocol = pprotocol;
    else
      m_pprotocol = &m_protocol_stub;
  }
  //-----------------------------------------------------------------------------------
  const checkpoints& core::get_checkpoints() const
  {
    return m_blockchain_storage.get_checkpoints();
  }
  void core::set_checkpoints(checkpoints&& chk_pts)
  {
    m_blockchain_storage.set_checkpoints(std::move(chk_pts));
  }
  //-----------------------------------------------------------------------------------
  void core::stop()
  {
    m_miner.stop();
    m_blockchain_storage.cancel();
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
    return m_blockchain_storage.get_blocks(start_offset, count, blocks, txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks) const
  {
    return m_blockchain_storage.get_blocks(start_offset, count, blocks);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<block>& blocks) const
  {
    std::vector<std::pair<cryptonote::blobdata, cryptonote::block>> bs;
    if (!m_blockchain_storage.get_blocks(start_offset, count, bs))
      return false;
    for (const auto &b: bs)
      blocks.push_back(b.second);
    return true;
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
  bool core::get_txpool_backlog(std::vector<tx_backlog_entry>& backlog, bool include_sensitive_txes) const
  {
    m_mempool.get_transaction_backlog(backlog, include_sensitive_txes);
    return true;
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
    return m_blockchain_storage.get_alternative_blocks(blocks);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_alternative_blocks_count() const
  {
    return m_blockchain_storage.get_alternative_blocks_count();
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
    // Uniform across every network (C2-R1b-Q2a, rule 71): checkpoint
    // wiring is identical on mainnet, testnet and stagenet. Data may
    // differ per network (the compiled-in list, when one ever exists);
    // the code path may not. The compiled-in table is the only source --
    // the data-dir checkpoints.json channel was deleted (PDM-Q-F23).
    {
      cryptonote::checkpoints checkpoints;
      if (!checkpoints.init_default_checkpoints(m_nettype))
      {
        throw std::runtime_error("Failed to initialize checkpoints");
      }
      set_checkpoints(std::move(checkpoints));
    }
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
    return m_blockchain_storage.reset_and_set_genesis_block(b);
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
    m_miner.stop();
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
    return m_blockchain_storage.have_tx_keyimg_as_spent(key_image);
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
    boost::multiprecision::uint128_t emission_amount = 0;
    boost::multiprecision::uint128_t total_fee_amount = 0;
    if (count)
    {
      const uint64_t end = start_offset + count - 1;
      m_blockchain_storage.for_blocks_range(start_offset, end,
        [this, &emission_amount, &total_fee_amount](uint64_t, const crypto::hash& hash, const block& b){
      std::vector<transaction> txs;
      std::vector<crypto::hash> missed_txs;
      uint64_t coinbase_amount = get_outs_money_amount(b.miner_tx);
      this->get_transactions(b.tx_hashes, txs, missed_txs, true);
      uint64_t tx_fee_amount = 0;
      for(const auto& tx: txs)
      {
        tx_fee_amount += get_tx_fee(tx);
      }
      
      emission_amount += coinbase_amount - tx_fee_amount;
      total_fee_amount += tx_fee_amount;
      return true;
      });
    }

    return std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t>(emission_amount, total_fee_amount);
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
    return m_blockchain_storage.get_total_transactions();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, const crypto::hash& tx_hash, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
  {
    if(m_mempool.have_tx(tx_hash, relay_category::broadcasted))
    {
      LOG_PRINT_L2("tx " << tx_hash << "already have transaction in tx_pool");
      return true;
    }

    if(m_blockchain_storage.have_tx(tx_hash))
    {
      LOG_PRINT_L2("tx " << tx_hash << " already have transaction in blockchain");
      return true;
    }

    const bool res = m_mempool.add_tx(tx, tx_hash, blob, tx_weight, tvc, tx_relay, relayed);

    // If new incoming tx passed verification and entered the pool, notify subscribers
    if (!tvc.m_verifivation_failed && tvc.m_added_to_pool && matches_category(tx_relay, relay_category::broadcasted))
    {
      txpool_event evt{};
      evt.tx = tx;
      evt.hash = tx_hash;
      evt.blob_size = blob.size();
      evt.weight = tx_weight;
      evt.res = true;
      m_blockchain_storage.notify_txpool_event({std::move(evt)});
    }

    return res;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::relay_txpool_transactions()
  {
    // we attempt to relay txes that should be relayed, but were not
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> txs;
    if (m_mempool.get_relayable_transactions(txs) && !txs.empty())
    {
      NOTIFY_NEW_TRANSACTIONS::request public_req{};
      NOTIFY_NEW_TRANSACTIONS::request private_req{};

      /* Q12-U2 deleted the `forward` arm here, and deliberately changed
         NOTHING else about this routing.

         The `stem` arm reads like a leak and is not one. A pool entry recorded
         `stem` reaches this loop only once its embargo has EXPIRED
         (`get_relayable_transactions` skips it until then), and embargo expiry
         IS the Dandelion++ stem→fluff transition. So it rides the fluff
         request by design: fluff is the deliberate exit from the anonymity
         zone, and a transaction that does not take it would be stranded in the
         anonymity subgraph (§59.1). Re-stemming it here on its arrival zone
         would let an entry re-stem indefinitely instead of diffusing.

         The leak the #427 tripwire recorded was the `forward` arm, which put
         still-stemming traffic onto the clearnet fluff request. Deleting
         the class closes it; there is nothing left here to route by origin. */
      for (auto& tx : txs)
      {
        switch (std::get<2>(tx))
        {
          default:
          case relay_method::none:
            break;
          case relay_method::local:
            private_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
          case relay_method::block:
          case relay_method::fluff:
          case relay_method::stem:
            public_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
        }
      }

      /* All txes are sent on randomized timers per connection in
         `src/cryptonote_protocol/levin_notify.cpp.` They are either sent with
         "white noise" delays or via  diffusion (Dandelion++ fluff). So
         re-relaying public and private _should_ be acceptable here. */
      const boost::uuids::uuid source = boost::uuids::nil_uuid();
      if (!public_req.txs.empty())
        get_protocol()->relay_transactions(public_req, source, relay_method::fluff);
      if (!private_req.txs.empty())
        /* `local` is the origin's record, including a missed submit nudge.
           Hop 0 inside the relay fail-closes when the construction bit is
           set and no eligible edge exists. */
        get_protocol()->relay_transactions(private_req, source, relay_method::local);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::notify_txpool_event(const epee::span<const cryptonote::blobdata> tx_blobs, epee::span<const crypto::hash> tx_hashes, epee::span<const cryptonote::transaction> txs, const std::vector<bool> &just_broadcasted) const
  {
    if (tx_blobs.size() != tx_hashes.size() || tx_blobs.size() != txs.size() || tx_blobs.size() != just_broadcasted.size())
      return false;

    /* Notify subscribers about txs "just broadcasted" by the daemon. Done here
       to guarantee notifications fire after the tx is visible in the pool and
       the daemon has/will broadcast to other nodes. Called when the user submits
       a tx in the "fluff" epoch relaying via a public network. */
    if (std::count(just_broadcasted.begin(), just_broadcasted.end(), true) == 0)
      return true;

    std::vector<txpool_event> results{};
    results.resize(tx_blobs.size());
    for (std::size_t i = 0; i < results.size(); ++i)
    {
      results[i].tx = std::move(txs[i]);
      results[i].hash = std::move(tx_hashes[i]);
      results[i].blob_size = tx_blobs[i].size();
      results[i].weight = results[i].tx.pruned ? get_pruned_transaction_weight(results[i].tx) : get_transaction_weight(results[i].tx, results[i].blob_size);
      results[i].res = just_broadcasted[i];
    }

    m_blockchain_storage.notify_txpool_event(std::move(results));

    return true;
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
    m_mempool.on_stem_propagated(txids);
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_transactions_relayed(const epee::span<const cryptonote::blobdata> tx_blobs, const relay_method tx_relay, const std::optional<std::uint8_t> stem_connector)
  {
    // lock ensures duplicate txs aren't notified twice
    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);

    std::vector<crypto::hash> tx_hashes{};
    tx_hashes.resize(tx_blobs.size());

    std::vector<cryptonote::transaction> txs{};
    txs.resize(tx_blobs.size());

    for (std::size_t i = 0; i < tx_blobs.size(); ++i)
    {
      if (!parse_and_validate_tx_from_blob(tx_blobs[i], txs[i], tx_hashes[i]))
      {
        LOG_ERROR("Failed to parse relayed transaction");
        return;
      }
    }

    std::vector<bool> just_broadcasted{};
    just_broadcasted.reserve(tx_hashes.size());

    m_mempool.set_relayed(epee::to_span(tx_hashes), tx_relay, stem_connector, just_broadcasted);

    if (matches_category(tx_relay, relay_category::broadcasted))
    {
      for (const crypto::hash& id : tx_hashes)
        shekyl_pool_fluffed(reinterpret_cast<const std::uint8_t*>(id.data));
      notify_txpool_event(tx_blobs, epee::to_span(tx_hashes), epee::to_span(txs), just_broadcasted);
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_template(block& b, const account_public_address& adr, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
  {
    return m_blockchain_storage.create_block_template(b, adr, diffic, height, expected_reward, ex_nonce, seed_height, seed_hash);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_miner_data(uint8_t& major_version, uint64_t& height, crypto::hash& prev_id, crypto::hash& seed_hash, difficulty_type& difficulty, uint64_t& median_weight, uint64_t& already_generated_coins, std::vector<tx_block_template_backlog_entry>& tx_backlog)
  {
    return m_blockchain_storage.get_miner_data(major_version, height, prev_id, seed_hash, difficulty, median_weight, already_generated_coins, tx_backlog);
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
    return m_blockchain_storage.get_tx_outputs_gindexs(tx_id, indexs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
  {
    return m_blockchain_storage.get_tx_outputs_gindexs(tx_id, n_txes, indexs);
  }
  //-----------------------------------------------------------------------------------------------
  void core::pause_mine()
  {
    m_miner.pause();
  }
  //-----------------------------------------------------------------------------------------------
  void core::resume_mine()
  {
    m_miner.resume();
  }
  //-----------------------------------------------------------------------------------------------
  block_complete_entry get_block_complete_entry(block& b, tx_memory_pool &pool)
  {
    block_complete_entry bce;
    bce.block = cryptonote::block_to_blob(b);
    bce.block_weight = 0; // we can leave it to 0, those txes aren't pruned
    for (const auto &tx_hash: b.tx_hashes)
    {
      cryptonote::blobdata txblob;
      CHECK_AND_ASSERT_THROW_MES(pool.get_transaction(tx_hash, txblob, relay_category::all), "Transaction not found in pool");
      bce.txs.push_back({txblob, crypto::null_hash});
    }
    return bce;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_block_found(block& b, block_verification_context &bvc)
  {
    bvc = {};
    m_miner.pause();
    std::vector<block_complete_entry> blocks;
    try
    {
      blocks.push_back(get_block_complete_entry(b, m_mempool));
    }
    catch (const std::exception &e)
    {
      m_miner.resume();
      return false;
    }
    std::vector<block> pblocks;
    if (!prepare_handle_incoming_blocks(blocks, pblocks))
    {
      MERROR("Block found, but failed to prepare to add");
      m_miner.resume();
      return false;
    }
    m_blockchain_storage.add_new_block(b, bvc);
    cleanup_handle_incoming_blocks(true);
    //anyway - update miner template
    update_miner_block_template();
    m_miner.resume();


    CHECK_AND_ASSERT_MES(!block_rejected(bvc), false, "mined block failed verification");
    if(block_added(bvc))
    {
      cryptonote_connection_context exclude_context = {};
      NOTIFY_NEW_COMPACT_BLOCK::request arg{};
      arg.current_blockchain_height = m_blockchain_storage.get_current_blockchain_height();
      std::vector<crypto::hash> missed_txs;
      for (const auto &tx_hash : b.tx_hashes)
      {
        if (m_blockchain_storage.have_tx(tx_hash))
          continue;
        missed_txs.push_back(tx_hash);
      }
      if(missed_txs.size() &&  m_blockchain_storage.get_block_id_by_height(get_block_height(b)) != get_block_hash(b))
      {
        LOG_PRINT_L1("Block found but, seems that reorganize just happened after that, do not relay this block");
        return true;
      }
      CHECK_AND_ASSERT_MES(!missed_txs.size(), false, "can't find some transactions in found block:" << get_block_hash(b)
        << " b.tx_hashes.size()=" << b.tx_hashes.size() << ", missed_txs.size()" << missed_txs.size());

      block_to_blob(b, arg.b.block);
      // Attach the credit-wire attestation witness the block connected with
      // (ARCHIVAL_CREDIT_WIRE.md §3, credit-wire CW-2). Read back from the DB rather
      // than carried separately: the block is on the main chain by here
      // (block_added, re-checked above), so its height row is the one
      // authority for what this block's witness is.
      //
      // This is the relay site for both locally mined blocks and RPC-submitted ones.
      // It reads empty today, and will keep reading empty until the CW-3 block-template
      // writer produces a witness AND the connect above (add_new_block's 2-arg overload,
      // which supplies none) carries it. Wiring a witness parameter through now would be
      // threading with no producer at either end — the same inert plumbing this PR had to
      // remove from the import path. Named here so the next maintainer sees the seam
      // rather than reading this line as a finished path.
      arg.b.attestation_witness = m_blockchain_storage.get_block_attestation_witness(b);
      // Compact announce: header only; peers request missing txs via 2009.
      arg.b.txs.clear();

      m_pprotocol->relay_block(arg, exclude_context);
    }
    return true;
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
  void core::safesyncmode(const bool onoff)
  {
    (void)onoff;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_block(const block& b, block_verification_context& bvc,
    block_connect_supplement& connect)
  {
    return m_blockchain_storage.add_new_block(b, bvc, connect);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::prepare_handle_incoming_blocks(const std::vector<block_complete_entry> &blocks_entry, std::vector<block> &blocks, uint8_t *drop_verdict)
  {
    m_incoming_tx_lock.lock();
    if (!m_blockchain_storage.prepare_handle_incoming_blocks(blocks_entry, blocks, drop_verdict))
    {
      cleanup_handle_incoming_blocks(false);
      return false;
    }
    return true;
  }

  //-----------------------------------------------------------------------------------------------
  bool core::cleanup_handle_incoming_blocks(bool force_sync)
  {
    bool success = false;
    try {
      success = m_blockchain_storage.cleanup_handle_incoming_blocks(force_sync);
    }
    catch (...) {}
    m_incoming_tx_lock.unlock();
    return success;
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
    // Note: this estimate can be quite far off since compact blocks won't contain all their
    // transactions in the payload, but also this value doesn't *need* to be super precise. It
    // is used to trigger database backing store syncing once it hits a threshold, and since
    // we under-count the byte size here, it might result in under-syncing the backing store.
    // If force refresh is enabled, though, which the user turns on if they are vigilant about
    // saving each block, then it doesn't matter either way: cleanup_handle_incoming_blocks()
    // always triggers a sync.
    // Counts the credit-wire attestation witness too, so this estimate and
    // m_block_queue's accounting size the same object the same way.
    size_t block_total_bytes = block_blob.size() + connect.attestation_witness.size();
    for (const auto &t : connect.pool.txs_by_txid)
      block_total_bytes += t.second.second.size();

    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);

    // Match each call to prepare_handle_incoming_block_no_preprocess() with a call to
    // cleanup_handle_incoming_blocks()
    m_blockchain_storage.prepare_handle_incoming_block_no_preprocess(block_total_bytes);
    const auto auto_cleanup = epee::misc_utils::create_scope_leave_handler([this](){
      this->m_blockchain_storage.cleanup_handle_incoming_blocks();
    });

    return handle_incoming_block(block_blob,
      b,
      bvc,
      connect,
      update_miner_blocktemplate);
  }
  //-----------------------------------------------------------------------------------------------
  // Used by the RPC server to check the size of an incoming
  // block_blob
  bool core::check_incoming_block_size(const blobdata& block_blob) const
  {
    // note: we assume block weight is always >= block blob size, so we check incoming
    // blob size against the block weight limit, which acts as a sanity check without
    // having to parse/weigh first; in fact, since the block blob is the block header
    // plus the tx hashes, the weight will typically be much larger than the blob size
    if(block_blob.size() > m_blockchain_storage.get_current_cumulative_block_weight_limit() + BLOCK_SIZE_SANITY_LEEWAY)
    {
      LOG_PRINT_L1("WRONG BLOCK BLOB, sanity check failed on size " << block_blob.size() << ", rejected");
      return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_tail_id() const
  {
    return m_blockchain_storage.get_tail_id();
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
    return m_mempool.get_transactions_count(include_sensitive_txes);
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
    m_mempool.get_transactions(txs, include_sensitive_data);
    return true;
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
  bool core::get_pool_transaction_stats(struct txpool_stats& stats, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_stats(stats, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction(const crypto::hash &id, cryptonote::blobdata& tx, relay_category tx_category) const
  {
    return m_mempool.get_transaction(id, tx, tx_category);
  }  
  //-----------------------------------------------------------------------------------------------
  bool core::pool_has_tx(const crypto::hash &id) const
  {
    // Membership, stem included: the relay's question (i_core_events). A
    // compact block resolves shown bodies only, and does not call this.
    return shekyl_pool_has(reinterpret_cast<const std::uint8_t*>(id.data)) == 1;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions_and_spent_keys_info(std::vector<tx_info>& tx_infos, std::vector<spent_key_image_info>& key_image_infos, bool include_sensitive_data) const
  {
    return m_mempool.get_transactions_and_spent_keys_info(tx_infos, key_image_infos, include_sensitive_data);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_for_rpc(std::vector<cryptonote::rpc::tx_in_pool>& tx_infos, cryptonote::rpc::key_images_with_tx_hashes& key_image_infos) const
  {
    return m_mempool.get_pool_for_rpc(tx_infos, key_image_infos);
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
    return m_mempool.print_pool(short_format);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::update_miner_block_template()
  {
    m_miner.on_block_chain_update();
    return true;
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
  double factorial(unsigned int n)
  {
    if (n <= 1)
      return 1.0;
    double f = n;
    while (n-- > 1)
      f *= n;
    return f;
  }
  //-----------------------------------------------------------------------------------------------
  static double probability1(unsigned int blocks, unsigned int expected)
  {
    // https://www.umass.edu/wsp/resources/poisson/#computing
    return pow(expected, blocks) / (factorial(blocks) * exp(expected));
  }
  //-----------------------------------------------------------------------------------------------
  static double probability(unsigned int blocks, unsigned int expected)
  {
    double p = 0.0;
    if (blocks <= expected)
    {
      for (unsigned int b = 0; b <= blocks; ++b)
        p += probability1(b, expected);
    }
    else if (blocks > expected)
    {
      for (unsigned int b = blocks; b <= expected * 3 /* close enough */; ++b)
        p += probability1(b, expected);
    }
    return p;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_block_rate()
  {
    if (m_offline || m_target_blockchain_height > get_current_blockchain_height() || m_target_blockchain_height == 0)
    {
      MDEBUG("Not checking block rate, offline or syncing");
      return true;
    }

    // LWMA-1 Phase 4 §7 calibration: the stall-detection thresholds
    // depend on the block-target time T. The 1/7200 false-positive rate
    // (one in 10 days) and the {45, 30, 15, 10, 5} expected-block counts
    // for the {5400, 3600, 1800, 1200, 600}-second windows assume
    // SHEKYL_DAA_TARGET_SECONDS == 120. If T ever changes, both the
    // threshold and the expected counts must be re-derived per
    // docs/completed/DAA_LWMA1.md §11, not silently scaled. The regression
    // test that pins this calibration lives at
    // tests/unit_tests/stall_detection_calibration.cpp; see
    // docs/completed/DAA_LWMA1_PHASE4_PREFLIGHT.md §7.
    static_assert(SHEKYL_DAA_TARGET_SECONDS == 120,
        "Stall-detection calibration: the 1/7200 false-positive "
        "threshold and the {45, 30, 15, 10, 5} expected-block counts "
        "assume the 120-second block target.");
    static constexpr double threshold = 1. / (864000 / SHEKYL_DAA_TARGET_SECONDS); // one false positive every 10 days
    static constexpr unsigned int max_blocks_checked = 150;

    const time_t now = time(NULL);
    const std::vector<time_t> timestamps = m_blockchain_storage.get_last_block_timestamps(max_blocks_checked);

    static const unsigned int seconds[] = { 5400, 3600, 1800, 1200, 600 };
    for (size_t n = 0; n < sizeof(seconds)/sizeof(seconds[0]); ++n)
    {
      unsigned int b = 0;
      const time_t time_boundary = now - static_cast<time_t>(seconds[n]);
      for (time_t ts: timestamps) b += ts >= time_boundary;
      const double p = probability(b, seconds[n] / SHEKYL_DAA_TARGET_SECONDS);
      MDEBUG("blocks in the last " << seconds[n] / 60 << " minutes: " << b << " (probability " << p << ")");
      if (p < threshold)
      {
        MWARNING("There were " << b << (b == max_blocks_checked ? " or more" : "") << " blocks in the last " << seconds[n] / 60 << " minutes, there might be large hash rate changes, or we might be partitioned, cut off from the Shekyl network or under attack, or your computer's time is off. Or it could be just sheer bad luck.");

        shekyl_notify_block_rate(seconds[n], b, seconds[n] / SHEKYL_DAA_TARGET_SECONDS);

        break; // no need to look further
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::flush_invalid_blocks()
  {
    m_blockchain_storage.flush_invalid_blocks();
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

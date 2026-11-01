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

#include "cryptonote_core.h"
#include "warnings.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "tx_verification_utils.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/drop_verdict.h"
#include "cryptonote_basic/block_ingest.h"

#include <cstring>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "cn"

DISABLE_VS_WARNINGS(4355)

namespace {
cryptonote::core* shell_for_relay = nullptr;
}

/// The node's committed transaction, as bytes, for `levin_notify`.
/// RD deletes this with `levin_notify` (`DRS_X_STORE_FLIP.md` §2).
/// Returns 1 when the relay took the transaction, 0 when there was no
/// route to hand it to: before `core::init` returns, after `deinit`, or
/// with no notifier bound (an offline node never constructs one). The
/// node applies RD's no-route fluff on 0 (Q9, amended 2026-10-29).
extern "C" int shekyl_shell_relay_local(const std::uint8_t* blob, std::size_t len)
{
  if (shell_for_relay == nullptr || blob == nullptr || len == 0)
    return 0;
  auto* protocol = shell_for_relay->get_protocol();
  if (protocol == nullptr)
    return 0;
  cryptonote::NOTIFY_NEW_TRANSACTIONS::request request;
  request.txs.emplace_back(reinterpret_cast<const char*>(blob), len);
  return protocol->relay_transactions(request, boost::uuids::nil_uuid(), cryptonote::relay_method::local) ? 1 : 0;
}

namespace cryptonote
{

  //-----------------------------------------------------------------------------------------------
  core::core(i_cryptonote_protocol* pprotocol):
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
  //-----------------------------------------------------------------------------------------------
  bool core::init(const ShekylDaemonSnapshot& snapshot)
  {
    start_time = std::time(nullptr);

    // The snapshot's network code is `network_type`'s (DAEMON_CONFIG_CUTOVER.md
    // §2.9).
    m_nettype = static_cast<network_type>(snapshot.network);

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
  bool core::is_synchronized() const
  {
    return m_pprotocol != nullptr && m_pprotocol->is_synchronized();
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_synchronized()
  {
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
    // The connect is the Rust ingest's (`shekyl_ingest_offer_span`); this
    // slot is CS-5's to delete with the handler's sync half (§1.4). Nothing
    // is added here and no template is rebuilt.
    (void)connect;
    (void)update_miner_blocktemplate;
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
  difficulty_type core::get_block_cumulative_difficulty(uint64_t height) const
  {
    std::uint64_t lo = 0, hi = 0;
    if (shekyl_core_cumulative_difficulty(height, &lo, &hi) != 0)
      return 0;
    return (difficulty_type(hi) << 64) | lo;
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
      // A served span is never pruned (PDM-Q7; the pruned band below the
      // checkpoint is PDM-Q5's, not this request's), whatever the request
      // carried: the entry's form is this daemon's, not the asker's. The
      // wire's `block_weight` is a pruned entry's: a full block carries
      // none, and the receiving handler drops a peer that sends one on a
      // full block ("returned a block weight for a non pruned block"), so
      // this is always 0, as the deleted C++ left it.
      entry.pruned = false;
      (void)weight;
      entry.block_weight = 0;
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
  bool core::on_idle()
  {
    return true;
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
  std::time_t core::get_start_time() const
  {
    return start_time;
  }
}

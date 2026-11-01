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
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/drop_verdict.h"

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
  //-----------------------------------------------------------------------------------------------
  void core::stop()
  {
  }
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
  bool core::is_synchronized() const
  {
    // Chain sync's published state (CS-5 §3): Synced only.
    return shekyl_node_is_synchronized() != 0;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::pool_has_tx(const crypto::hash &id) const
  {
    // Membership, stem included: the relay's question (i_core_events). A
    // compact block resolves shown bodies only, and does not call this.
    return shekyl_pool_has(reinterpret_cast<const std::uint8_t*>(id.data)) == 1;
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
  std::time_t core::get_start_time() const
  {
    return start_time;
  }
}

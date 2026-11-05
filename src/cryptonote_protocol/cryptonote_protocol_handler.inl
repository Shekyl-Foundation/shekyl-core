/// @file
/// @author rfree (current maintainer/user in monero.cc project - most of code is from CryptoNote)
/// @brief This is the original cryptonote protocol network-events handler, modified by us

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

// (may contain code and/or modifications by other developers)
// developer rfree: this code is caller of our new network code, and is modded; e.g. for rate limiting

#include <array>
#include <ctime>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_set>

#include "p2p/seam_endpoint.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "misc_log_ex.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "net.cn"

#define MLOG_P2P_MESSAGE(x) MCINFO("net.p2p.msg", context << x)
#define MLOGIF_P2P_MESSAGE(init, test, x) \
  do { \
    const std::uint8_t _p2p_level = SHEKYL_LOG_LEVEL_INFO; \
    const char *cat = "net.p2p.msg"; \
    if (::shekyl_log_level_enabled(_p2p_level, cat, std::strlen(cat))) { \
      init; \
      if (test) { \
        LOG_TO_STRING(x); \
        ::shekyl_log_emit( \
          _p2p_level, \
          cat, std::strlen(cat), \
          __FILE__, std::strlen(__FILE__), \
          static_cast<std::uint32_t>(__LINE__), \
          ELPP_FUNC, std::strlen(ELPP_FUNC), \
          str.data(), str.size()); \
      } \
    } \
  } while(0)

namespace cryptonote
{
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  t_cryptonote_protocol_handler<t_core>::t_cryptonote_protocol_handler(t_core& rcore, nodetool::i_p2p_endpoint<connection_context>* p_net_layout)
    : m_core(rcore), m_p2p(p_net_layout)
  {
    if(!m_p2p)
      m_p2p = &m_p2p_stub;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::init()
  {
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::deinit()
  {
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::set_p2p_endpoint(nodetool::i_p2p_endpoint<connection_context>* p2p)
  {
    if(p2p)
      m_p2p = p2p;
    else
      m_p2p = &m_p2p_stub;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::log_connections()
  {
    std::stringstream ss;
    ss.precision(1);

    ss << std::setw(30) << std::left << "Remote Host"
      << std::setw(30) << "Recv/Sent (inactive,sec)"
      << std::setw(20) << "Livetime(sec)"
      << std::setw(12) << "Down (kB/s)"
      << std::setw(14) << "Down(now)"
      << std::setw(10) << "Up (kB/s)"
      << std::setw(13) << "Up(now)"
      << ENDL;

    auto lines = std::make_shared<std::stringstream>();
    auto totals = std::make_shared<std::array<double, 4>>();
    auto guard = std::make_shared<std::mutex>();
    lines->copyfmt(ss);
    *lines << ss.str();
    m_p2p->post_each(
      [lines, totals, guard](const connection_context& cntxt)
      {
        const bool local_ip = cntxt.m_remote_address.is_local();
        const auto connection_time = time(NULL) - cntxt.m_started;
        std::stringstream row;
        row.copyfmt(*lines);
        row << std::setw(30) << std::left << std::string(cntxt.m_is_income ? " [INC]":"[OUT]") +
          cntxt.m_remote_address.str()
          << std::setw(30) << std::to_string(cntxt.m_recv_cnt)+ "(" + std::to_string(time(NULL) - cntxt.m_last_recv) + ")" + "/" + std::to_string(cntxt.m_send_cnt) + "(" + std::to_string(time(NULL) - cntxt.m_last_send) + ")"
          << std::setw(20) << std::to_string(time(NULL) - cntxt.m_started)
          << std::setw(12) << std::fixed << (connection_time == 0 ? 0.0 : cntxt.m_recv_cnt / connection_time / 1024)
          << std::setw(14) << std::fixed << cntxt.m_current_speed_down / 1024
          << std::setw(10) << std::fixed << (connection_time == 0 ? 0.0 : cntxt.m_send_cnt / connection_time / 1024)
          << std::setw(13) << std::fixed << cntxt.m_current_speed_up / 1024
          << (local_ip ? "[LAN]" : "")
          << std::left << (cntxt.m_remote_address.is_loopback() ? "[LOCALHOST]" : "")
          << ENDL;
        std::lock_guard<std::mutex> lock(*guard);
        *lines << row.str();
        if (connection_time > 1)
        {
          (*totals)[0] += (cntxt.m_recv_cnt / connection_time / 1024);
          (*totals)[2] += (cntxt.m_send_cnt / connection_time / 1024);
        }
        (*totals)[1] += (cntxt.m_current_speed_down / 1024);
        (*totals)[3] += (cntxt.m_current_speed_up / 1024);
      },
      [lines, totals]()
      {
        *lines << ENDL
          << std::setw(100) << " "
          << std::setw(12) << (*totals)[0]
          << std::setw(14) << (*totals)[1]
          << std::setw(10) << (*totals)[2]
          << std::setw(13) << (*totals)[3]
          << ENDL;
        LOG_PRINT_L0("Connections: " << ENDL << lines->str());
      });
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_GET_TXPOOL_COMPLEMENT (" << arg.hashes.size() << " txes)");
    // A session past its handshake is answered (CS-5 F3): the seam's flag,
    // set inbound after the C++ handshake and outbound on the dialer's
    // result. The request is the peer's own, at its transition to synced.
    if(!shekyl::seam_handshake_established(context.m_connection_id))
      return 1;

    std::vector<cryptonote::blobdata> txes;
    if (!m_core.get_txpool_complement(arg.hashes, txes))
    {
      LOG_ERROR_CCONTEXT("failed to get txpool complement");
      return 1;
    }

    NOTIFY_NEW_TRANSACTIONS::request new_txes;
    new_txes.txs = std::move(txes);

    MLOG_P2P_MESSAGE
    (
        "-->>NOTIFY_NEW_TRANSACTIONS: "
        << ", txs.size()=" << new_txes.txs.size()
    );

    post_notify<NOTIFY_NEW_TRANSACTIONS>(new_txes, context);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_NEW_TRANSACTIONS (" << arg.txs.size() << " txes)");
    std::unordered_set<blobdata> seen;
    for (const auto &blob: arg.txs)
    {
      if (seen.find(blob) != seen.end())
      {
        LOG_PRINT_CCONTEXT_L1("Duplicate transaction in notification, dropping connection");
        drop_connection(context);
        return 1;
      }
      seen.insert(blob);
    }

    // A handshake-complete peer that is still synchronising may relay.
    // Only a session that has not finished the handshake is dropped here.
    if(!shekyl::seam_handshake_established(context.m_connection_id))
      return 1;

    // A node not synced to its best verified chain ignores them: chain
    // sync's published state, through the shell (CS-5 §3).
    if(!m_core.is_synchronized())
    {
      LOG_DEBUG_CC(context, "Received new tx while syncing, ignored");
      return 1;
    }

    // Passed the duplicate drop and both gates. The pool can still refuse.
    // The parse exists for this line; it is a second pass, after the decision.
    for (const auto &blob: arg.txs)
    {
      MLOGIF_P2P_MESSAGE(cryptonote::transaction tx; crypto::hash hash; bool ret = cryptonote::parse_and_validate_tx_from_blob(blob, tx, hash);, ret, "Transaction accepted for admission " << hash);
    }

    /* §46: hand every arrived blob to every zone's stem-observation watch
       BEFORE pool admission — a returned tx the pool then rejects still
       proves the successor relayed it (propagation, not admission). */
    m_p2p->record_tx_arrivals(std::vector<blobdata>{arg.txs.begin(), arg.txs.end()}, context.m_connection_id);

    /* Q12-U2: an arrival is stemmed, whatever transport it arrived on.

       The inherited rule classed a non-public arrival `relay_method::forward`
       — hold it on a randomized timer, then broadcast to clearnet. That made
       the transport a routing input, and Q12-D3 rules it is not: the zone is a
       selectable path with a latency price, not a property a transaction
       inherits from the peer that handed it over.

       `forward` was refused propagation into `tvc.m_relay` (tx_pool.cpp), so
       the batching switch below dropped it and `relay_transactions` was
       never called at arrival with an anonymity origin. As `stem`, the
       arrival flows to `relay_transactions`. The session's notifier stems
       it; arrival-coherence is not a routing decision.

       `dandelionpp_fluff` is unchanged and still overrides below: a sender who
       disabled white noise over Tor is fluffing, and the receiving hidden
       service fluffs immediately — that is the deliberate exit from the
       anonymity zone (§59.1), not a routing inference about the transport. */

    relay_method tx_relay = relay_method::stem;

    std::vector<blobdata> stem_txs{};
    std::vector<blobdata> fluff_txs{};
    if (arg.dandelionpp_fluff)
    {
      tx_relay = relay_method::fluff;
      fluff_txs.reserve(arg.txs.size());
    }
    else
      stem_txs.reserve(arg.txs.size());

    for (auto& tx : arg.txs)
    {
      tx_verification_context tvc{};
      if (!m_core.handle_incoming_tx(tx, tvc, tx_relay, true))
      {
        if (shekyl_drop_verdict_severs(tvc.m_drop_verdict))
        {
          LOG_PRINT_CCONTEXT_L1("Tx verification failed, dropping connection");
          drop_connection(context);
          return 1;
        }
        if (shekyl_drop_verdict_is_internal_failure(tvc.m_drop_verdict))
        {
          LOG_ERROR_CCONTEXT("Tx rejected by an internal failure of ours, not the sender's fault; keeping the connection");
        }
      }

      switch (tvc.m_relay)
      {
        case relay_method::local:
        case relay_method::stem:
          stem_txs.push_back(std::move(tx));
          break;
        case relay_method::block:
        case relay_method::fluff:
          fluff_txs.push_back(std::move(tx));
          break;
        default:
        case relay_method::none:
          break;
      }
    }

    if (!stem_txs.empty())
    {
      //TODO: add announce usage here
      arg.dandelionpp_fluff = false;
      arg.txs = std::move(stem_txs);
      relay_transactions(arg, context.m_connection_id, relay_method::stem);
    }
    if (!fluff_txs.empty())
    {
      //TODO: add announce usage here
      arg.dandelionpp_fluff = true;
      arg.txs = std::move(fluff_txs);
      relay_transactions(arg, context.m_connection_id, relay_method::fluff);
    }
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& arg, const boost::uuids::uuid& source, relay_method tx_relay)
  {
    /* Push all outgoing transactions to this function. The relay decides
       the phase. Hop 0 is the construction bit inside the relay. */
    return m_p2p->send_txs(std::move(arg.txs), source, tx_relay);
  }
  //------------------------------------------------------------------------------------------------------------------------
  /// Drop the session. Scoring is gone (CS-Q5): a drop is the drop alone.
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connection(cryptonote_connection_context &context)
  {
    LOG_DEBUG_CC(context, "dropping connection id " << context.m_connection_id);
    m_p2p->drop_connection(context);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::stop()
  {
    m_core.stop();
  }
} // namespace

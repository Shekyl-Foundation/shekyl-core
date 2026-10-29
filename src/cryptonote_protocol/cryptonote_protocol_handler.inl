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
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <list>
#include <ctime>
#include <cstring>

#include "p2p/seam_board.h"
#include "p2p/seam_endpoint.h"
#include "ingest_offer.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "profile_tools.h"
#include "common/util.h"
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

#define MLOG_PEER_STATE(x) \
  MCINFO(SHEKYL_DEFAULT_LOG_CATEGORY, context << " state: " << x << " in state " << cryptonote::get_protocol_state_string(context.m_state))

#define BLOCK_QUEUE_NSPANS_MINIMUM             10  // minimum number of spans
#define BLOCK_QUEUE_SIZE_THRESHOLD (100*1024*1024) // MB
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY (5 * 1000000) // microseconds
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD (30 * 1000000) // microseconds
#define IDLE_PEER_KICK_TIME (240 * 1000000) // microseconds
#define NON_RESPONSIVE_PEER_KICK_TIME (20 * 1000000) // microseconds
#define PASSIVE_PEER_KICK_TIME (60 * 1000000) // microseconds
#define DROP_ON_SYNC_WEDGE_THRESHOLD (30 * 1000000000ull) // nanoseconds
#define LAST_ACTIVITY_STALL_THRESHOLD (2.0f) // seconds
#define DROP_PEERS_ON_SCORE -2

namespace cryptonote
{
  /*!
   * \brief Render a peer-supplied blob for a log line: digest and length, never content.
   *
   * A hex dump of a rejected blob is a remote-triggerable amplifier, and these
   * blobs are bounded only by what the transport accepts. A block blob in
   * `NOTIFY_RESPONSE_GET_OBJECTS` has no tighter bound than levin's
   * post-handshake `LEVIN_DEFAULT_MAX_PACKET_SIZE` (100 MB), and hex doubles
   * it, so one packet can write ~200 MB to an operator's disk -- and the peer
   * is free to reconnect and repeat, because these paths deliberately do not
   * score the drop (that is PWD-B7's tri-state, not this fix).
   *
   * A diagnostic needs to identify the blob and size it. It never needs the
   * bytes: an operator who has the blob can already run `cn_deserialize`, and
   * one who does not cannot obtain it from a log line either way. The digest
   * is what makes two reports of "the same bad block" comparable.
   */
  inline std::string describe_peer_blob(const blobdata& blob)
  {
    return epee::string_tools::pod_to_hex(get_blob_hash(blob))
      + " (" + std::to_string(blob.size()) + " bytes)";
  }

  //-----------------------------------------------------------------------------------------------------------------------
  // The connector byte the Rust sync verdicts take for a zone.
  inline std::uint32_t sync_connector_of(epee::net_utils::connector_id zone)
  {
    return zone == epee::net_utils::connector_id::tor ? SHEKYL_CONNECTOR_TOR : SHEKYL_CONNECTOR_CLEARNET;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
    t_cryptonote_protocol_handler<t_core>::t_cryptonote_protocol_handler(t_core& rcore, nodetool::i_p2p_endpoint<connection_context>* p_net_layout, bool offline):m_core(rcore),
                                                                                                              m_p2p(p_net_layout),
                                                                                                              m_syncronized_connections_count(0),
                                                                                                              m_synchronized(offline),
                                                                                                              m_ask_for_txpool_complement(true),
                                                                                                              m_stopping(false),
                                                                                                              m_no_sync(false),
                                                                                                              m_span_limit(BLOCK_QUEUE_NSPANS_MINIMUM)

  {
    if(!m_p2p)
      m_p2p = &m_p2p_stub;
    shekyl_ingest_bind(this, &t_cryptonote_protocol_handler<t_core>::ingest_post);
  }
  template<class t_core>
  t_cryptonote_protocol_handler<t_core>::~t_cryptonote_protocol_handler()
  {
    shekyl_ingest_bind(nullptr, nullptr);
  }
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::ingest_post(void* ctx, const shekyl_ingest_reply* reply,
      const std::uint64_t* indices, std::size_t indices_len)
  {
    if (ctx && reply)
      static_cast<t_cryptonote_protocol_handler<t_core>*>(ctx)->on_ingest_reply(*reply, indices, indices_len);
  }
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::on_ingest_reply(const shekyl_ingest_reply& reply,
      const std::uint64_t* indices, std::size_t indices_len)
  {
    // for_connection only enqueues onto the connection's strand.
    const boost::uuids::uuid id = shekyl::seam_connection_id(reply.connection);
    const std::vector<std::uint64_t> missing(indices, indices + indices_len);
    m_p2p->for_connection(id, [this, reply, missing](cryptonote_connection_context& context) {
      if (reply.kind == SHEKYL_INGEST_REFUSED)
      {
        LOG_PRINT_CCONTEXT_L0("Block verification failed, dropping connection");
        drop_connection(context, false, false);
        return;
      }
      if (reply.kind == SHEKYL_INGEST_CONNECTED || reply.kind == SHEKYL_INGEST_SWITCHED)
      {
        // An add ended: the sync wedge timer reads it, and the peer that
        // delivered the block holds at least that chain length (what the
        // deleted connect loop recorded per block).
        m_last_add_end_time = tools::get_tick_count();
        raise_remote_height(context, chain_length_of_accepted_block(reply.height));
        // A block a peer announced that is now this node's tip, while this
        // node is not behind, is announced on, as this handler did before
        // the door (the connect loop's relay). A block this node mined or
        // took through submit_block is not: that announcement is chain
        // sync's (`Sync::relays`), attached at its cutover (the register,
        // DRS_X_STORE_FLIP.md §3.1). The tip check keeps a late reply for a
        // solicited span from announcing a block behind the tip.
        if (context.m_state == cryptonote_connection_context::state_normal && is_synchronized()
            && reply.height + 1 == m_core.get_current_blockchain_height())
        {
          crypto::hash id;
          std::memcpy(&id, reply.hash, sizeof(id));
          block blk;
          if (m_core.get_block_by_hash(id, blk))
          {
            NOTIFY_NEW_COMPACT_BLOCK::request announce;
            announce.b.block = block_to_blob(blk);
            announce.b.attestation_witness = m_core.get_block_attestation_witness(blk);
            announce.current_blockchain_height = m_core.get_current_blockchain_height();
            relay_block(announce, context);
          }
        }
        return;
      }
      if (reply.kind == SHEKYL_INGEST_UNLINKED)
      {
        // An announced block whose parent this node lacks is the start of
        // a sync (the chain-sync ruling): ask the announcer for its chain.
        if (context.m_state == cryptonote_connection_context::state_normal)
          request_chain_history(context);
        return;
      }
      if (reply.kind != SHEKYL_INGEST_MISSING_BODIES || missing.empty())
        return;
      NOTIFY_REQUEST_COMPACT_MISSING_TX::request req;
      std::memcpy(&req.block_hash, reply.hash, sizeof(req.block_hash));
      req.current_blockchain_height = m_core.get_current_blockchain_height();
      req.missing_tx_indices = missing;
      post_notify<NOTIFY_REQUEST_COMPACT_MISSING_TX>(req, context);
    });
  }
  //-----------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::init()
  {
    m_sync_timer.pause();
    m_sync_timer.reset();
    m_add_timer.pause();
    m_add_timer.reset();
    m_last_add_end_time = 0;
    m_sync_spans_downloaded = 0;
    m_sync_old_spans_downloaded = 0;
    m_sync_bad_spans_downloaded = 0;
    m_sync_download_chain_size = 0;
    m_sync_download_objects_size = 0;

    // `block-download-max-size` and `span-limit` are refused
    // (P2P_3_CHAIN_SYNC_BRIEF.md CS-Q12): today's defaults until the
    // chain-sync cutover replaces these callers.
    m_block_download_max_size = 0;

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
  bool t_cryptonote_protocol_handler<t_core>::on_callback(cryptonote_connection_context& context)
  {
    LOG_PRINT_CCONTEXT_L2("callback fired");
    CHECK_AND_ASSERT_MES_CC( context.m_callback_request_count > 0, false, "false callback fired, but context.m_callback_request_count=" << context.m_callback_request_count);
    --context.m_callback_request_count;

    uint32_t notified = true;
    if (context.m_idle_peer_notification.compare_exchange_strong(notified, not notified))
    {
      if (context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time != boost::date_time::not_a_date_time)
      {
        const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
        const boost::posix_time::time_duration dt = now - context.m_last_request_time;
        const auto ms = dt.total_microseconds();
        if (ms > IDLE_PEER_KICK_TIME || (context.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
        {
          if (context.m_score-- >= 0)
          {
            MINFO(context << " kicking idle peer, last update " << (dt.total_microseconds() / 1.e6) << " seconds ago, expecting " << (int)context.m_expect_response);
            context.m_last_request_time = boost::date_time::not_a_date_time;
            context.m_expect_response = 0;
            context.m_expect_height = 0;
            context.m_requested_objects.clear();
            context.m_state = cryptonote_connection_context::state_standby; // we'll go back to adding, then (if we can't), download
          }
          else
          {
            MINFO(context << "dropping idle peer with negative score");
            drop_connection_with_score(context, context.m_expect_response == 0 ? 1 : 5, false);
            return false;
          }
        }
      }
    }

    if(context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time == boost::posix_time::not_a_date_time)
    {
      request_chain_history(context);
    }
    else if(context.m_state == cryptonote_connection_context::state_standby)
    {
      context.m_state = cryptonote_connection_context::state_synchronizing;
      try_add_next_blocks(context);
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::log_connections()
  {
    std::stringstream ss;
    ss.precision(1);

    ss << std::setw(30) << std::left << "Remote Host"
      << std::setw(30) << "Recv/Sent (inactive,sec)"
      << std::setw(25) << "State"
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
          << std::setw(25) << get_protocol_state_string(cntxt.m_state)
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
          << std::setw(125) << " "
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
  bool t_cryptonote_protocol_handler<t_core>::process_payload_sync_data(const CORE_SYNC_DATA& hshd, cryptonote_connection_context& context, bool is_inital)
  {
    if(context.m_state == cryptonote_connection_context::state_before_handshake && !is_inital)
      return true;

    if(context.m_state == cryptonote_connection_context::state_synchronizing)
      return true;

    if (hshd.current_height < context.m_remote_blockchain_height)
    {
      MINFO(context << "Claims " << hshd.current_height << ", claimed " << context.m_remote_blockchain_height << " before");
      hit_score(context, 1);
    }
    note_remote_height(context, hshd.current_height, is_inital
        ? cryptonote_connection_context::remote_height_source::handshake
        : cryptonote_connection_context::remote_height_source::timed_sync);

    uint64_t target = m_core.get_target_blockchain_height();
    if (target == 0)
      target = m_core.get_current_blockchain_height();

    if(m_core.have_block(hshd.top_id))
    {
      context.set_state_normal();
      if(is_inital  && hshd.current_height >= target && target == m_core.get_current_blockchain_height())
        on_connection_synchronized();
      return true;
    }

    if (hshd.current_height > target)
    {
    /* As I don't know if accessing hshd from core could be a good practice,
    I prefer pushing target height to the core at the same time it is pushed to the user.
    Nz. */
    int64_t diff = static_cast<int64_t>(hshd.current_height) - static_cast<int64_t>(m_core.get_current_blockchain_height());
    uint64_t abs_diff = std::abs(diff);
    MCLOG(is_inital ? el::Level::Info : el::Level::Debug, "global", el::Color::Yellow, context <<  "Sync data returned a new top block candidate: " << m_core.get_current_blockchain_height() << " -> " << hshd.current_height
      << " [Your node is " << abs_diff << " blocks (" << tools::get_human_readable_timespan(abs_diff * SHEKYL_DAA_TARGET_SECONDS) << ") "
      << (0 <= diff ? std::string("behind") : std::string("ahead"))
      << "] " << ENDL << "SYNCHRONIZATION started");
      if (m_core.get_target_blockchain_height() == 0) // only when sync starts
      {
        m_sync_timer.resume();
        m_sync_timer.reset();
        m_add_timer.pause();
        m_add_timer.reset();
        m_last_add_end_time = 0;
        // The estimates' origin (get_estimated_remaining_sync_seconds reads
        // both): where this sync started, in time and in height.
        m_sync_start_time = boost::posix_time::microsec_clock::universal_time();
        m_sync_start_height = m_core.get_current_blockchain_height();
        m_period_start_time = m_sync_start_time;
        m_sync_spans_downloaded = 0;
        m_sync_old_spans_downloaded = 0;
        m_sync_bad_spans_downloaded = 0;
        m_sync_download_chain_size = 0;
        m_sync_download_objects_size = 0;
      }
    m_core.set_target_blockchain_height((hshd.current_height));
    }
    MINFO(context << "Remote blockchain height: " << hshd.current_height << ", id: " << hshd.top_id);

    if (m_no_sync)
    {
      context.set_state_normal();
      return true;
    }

    context.m_state = cryptonote_connection_context::state_synchronizing;
    //let the socket to send response to handshake, but request callback, to let send request data after response
    LOG_PRINT_CCONTEXT_L2("requesting callback");
    ++context.m_callback_request_count;
    m_p2p->request_callback(context);
    MLOG_PEER_STATE("requesting callback");
    context.m_num_requested = 0;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::get_payload_sync_data(CORE_SYNC_DATA& hshd)
  {
    m_core.get_blockchain_top(hshd.current_height, hshd.top_id);
    difficulty_type wide_cumulative_difficulty = m_core.get_block_cumulative_difficulty(hshd.current_height);
    hshd.cumulative_difficulty = (wide_cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    hshd.cumulative_difficulty_top64 = ((wide_cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    hshd.current_height +=1;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
    template<class t_core>
    bool t_cryptonote_protocol_handler<t_core>::get_payload_sync_data(epee::byte_slice& data)
  {
    CORE_SYNC_DATA hsd = {};
    get_payload_sync_data(hsd);
    epee::serialization::store_t_to_binary(hsd, data);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_new_compact_block(int command, NOTIFY_NEW_COMPACT_BLOCK::request& arg, cryptonote_connection_context& context)
  {
    // If we are synchronizing the node or setting up this connection, then do nothing
    if(context.m_state != cryptonote_connection_context::state_normal)
      return 1;
    if(!is_synchronized()) // can happen if a peer connection goes to normal but another thread still hasn't finished adding queued blocks
    {
      LOG_DEBUG_CC(context, "Received new block while syncing, ignored");
      return 1;
    }

    // The door's Oversize is the size check (PR2-Q2). An unsolicited
    // announcement: Throttled closes the session and scores nothing.
    const int offered = cryptonote::offer_block_span(
        shekyl::seam_socket_id(context.m_connection_id), false, {arg.b});
    if (offered == SHEKYL_INGEST_THROTTLED)
    {
      LOG_PRINT_CCONTEXT_L1("Announced block past the session's bucket; dropping the connection");
      drop_connection(context, false, false);
    }
    else if (offered == SHEKYL_INGEST_OVERSIZE)
      LOG_PRINT_CCONTEXT_L1("Announced block blob exceeds the door's size bound; keeping the connection");
    else if (offered != SHEKYL_INGEST_ACCEPTED && offered != SHEKYL_INGEST_NO_ROOM)
      LOG_PRINT_CCONTEXT_L1("Announced block was not accepted (" << offered << "); keeping the connection");

    return 1;
  }  
  //------------------------------------------------------------------------------------------------------------------------  
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_request_compact_missing_tx(int command, NOTIFY_REQUEST_COMPACT_MISSING_TX::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_COMPACT_MISSING_TX (" << arg.missing_tx_indices.size() << " txes), block hash " << arg.block_hash);
    if (!shekyl::seam_handshake_established(context.m_connection_id))
    {
      LOG_ERROR_CCONTEXT("Requested compact missing tx before handshake, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    
    std::vector<std::pair<cryptonote::blobdata, block>> local_blocks;
    std::vector<cryptonote::blobdata> local_txs;

    block b;
    if (!m_core.get_block_by_hash(arg.block_hash, b))
    {
      LOG_ERROR_CCONTEXT("failed to find block: " << arg.block_hash << ", dropping connection");
      drop_connection(context, false, false);
      return 1;
    }

    std::vector<crypto::hash> txids;
    txids.reserve(b.tx_hashes.size());
    NOTIFY_NEW_COMPACT_BLOCK::request compact_response;
    compact_response.b.block = t_serializable_object_to_blob(b);
    // Re-attach the credit-wire attestation witness we hold for this block
    // (ARCHIVAL_CREDIT_WIRE.md §3, credit-wire CW-2). This response is rebuilt from
    // our own DB, so without this the requesting peer connects the block with no
    // witness, stores no row, and relays that gap to ITS peers — the loss is
    // permanent and spreads. Empty is omitted on the wire.
    compact_response.b.attestation_witness = m_core.get_block_attestation_witness(b);
    compact_response.current_blockchain_height = arg.current_blockchain_height;
    std::vector<bool> seen(b.tx_hashes.size(), false);
    for(auto& tx_idx: arg.missing_tx_indices)
    {
      if(tx_idx < b.tx_hashes.size())
      {
        MDEBUG("  tx " << b.tx_hashes[tx_idx]);
        if (seen[tx_idx])
        {
          LOG_ERROR_CCONTEXT
          (
            "Failed to handle request NOTIFY_REQUEST_COMPACT_MISSING_TX"
            << ", request is asking for duplicate tx "
            << ", tx index = " << tx_idx << ", block tx count " << b.tx_hashes.size()
            << ", block_height = " << arg.current_blockchain_height
            << ", dropping connection"
          );
          drop_connection(context, true, false);
          return 1;
        }
        txids.push_back(b.tx_hashes[tx_idx]);
        seen[tx_idx] = true;
      }
      else
      {
        LOG_ERROR_CCONTEXT
        (
          "Failed to handle request NOTIFY_REQUEST_COMPACT_MISSING_TX"
          << ", request is asking for a tx whose index is out of bounds "
          << ", tx index = " << tx_idx << ", block tx count " << b.tx_hashes.size()
          << ", block_height = " << arg.current_blockchain_height
          << ", dropping connection"
        );
        
        drop_connection(context, false, false);
        return 1;
      }
    }    

    std::vector<cryptonote::transaction> txs;
    std::vector<crypto::hash> missed;
    if (!m_core.get_transactions(txids, txs, missed))
    {
      LOG_ERROR_CCONTEXT("Failed to handle request NOTIFY_REQUEST_COMPACT_MISSING_TX, "
        << "failed to get requested transactions");
      drop_connection(context, false, false);
      return 1;
    }
    if (!missed.empty() || txs.size() != txids.size())
    {
      LOG_ERROR_CCONTEXT("Failed to handle request NOTIFY_REQUEST_COMPACT_MISSING_TX, "
        << missed.size() << " requested transactions not found" << ", dropping connection");
      drop_connection(context, false, false);
      return 1;
    }

    for(auto& tx: txs)
    {
      compact_response.b.txs.push_back({t_serializable_object_to_blob(tx), crypto::null_hash});
    }

    MLOG_P2P_MESSAGE
    (
        "-->>NOTIFY_NEW_COMPACT_BLOCK: " 
        << ", txs.size()=" << compact_response.b.txs.size()
        << ", rsp.current_blockchain_height=" << compact_response.current_blockchain_height
    );
           
    post_notify<NOTIFY_NEW_COMPACT_BLOCK>(compact_response, context);    
    return 1;        
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_GET_TXPOOL_COMPLEMENT (" << arg.hashes.size() << " txes)");
    if(context.m_state != cryptonote_connection_context::state_normal)
      return 1;

    std::vector<std::pair<cryptonote::blobdata, block>> local_blocks;
    std::vector<cryptonote::blobdata> local_txs;

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
        drop_connection(context, false, false);
        return 1;
      }
      seen.insert(blob);
    }

    // A handshake-complete peer that is still synchronising may relay.
    // Only a session that has not finished the handshake is dropped here.
    if(!shekyl::seam_handshake_established(context.m_connection_id))
      return 1;

    // while syncing, core will lock for a long time, so we ignore
    // those txes as they aren't really needed anyway, and avoid a
    // long block before replying
    if(!is_synchronized())
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
          drop_connection(context, false, false);
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
  int t_cryptonote_protocol_handler<t_core>::handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request& arg, cryptonote_connection_context& context)
  {
    if (!shekyl::seam_handshake_established(context.m_connection_id))
    {
      LOG_ERROR_CCONTEXT("Requested objects before handshake, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_GET_OBJECTS (" << arg.blocks.size() << " blocks)");
    if (arg.blocks.size() > CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT)
      {
        LOG_ERROR_CCONTEXT(
            "Requested objects count is too big ("
            << arg.blocks.size() << ") expected not more then "
            << CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT);
        drop_connection(context, false, false);
        return 1;
      }

    NOTIFY_RESPONSE_GET_OBJECTS::request rsp;
    if(!m_core.handle_get_objects(arg, rsp, context))
    {
      LOG_ERROR_CCONTEXT("failed to handle request NOTIFY_REQUEST_GET_OBJECTS, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
    MLOG_P2P_MESSAGE("-->>NOTIFY_RESPONSE_GET_OBJECTS: blocks.size()="
                     << rsp.blocks.size() << ", rsp.m_current_blockchain_height=" << rsp.current_blockchain_height
                     << ", missed_ids.size()=" << rsp.missed_ids.size());
    post_notify<NOTIFY_RESPONSE_GET_OBJECTS>(rsp, context);
    //handler_response_blocks_now(sizeof(rsp)); // XXX
    //handler_response_blocks_now(200);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------


  template<class t_core>
  double t_cryptonote_protocol_handler<t_core>::get_avg_block_size()
  {
    CRITICAL_REGION_LOCAL(m_buffer_mutex);
    if (m_avg_buffer.empty()) {
      MWARNING("m_avg_buffer.size() == 0");
      return 500;
    }
    double avg = 0;
    for (const auto &element : m_avg_buffer) avg += element;
    return avg / m_avg_buffer.size();
  }

  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_response_get_objects(int command, NOTIFY_RESPONSE_GET_OBJECTS::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_RESPONSE_GET_OBJECTS (" << arg.blocks.size() << " blocks)");
    MLOG_PEER_STATE("received objects");

    boost::posix_time::ptime request_time = context.m_last_request_time;
    context.m_last_request_time = boost::date_time::not_a_date_time;

    if (context.m_expect_response != NOTIFY_RESPONSE_GET_OBJECTS::ID)
    {
      LOG_ERROR_CCONTEXT("Got NOTIFY_RESPONSE_GET_OBJECTS out of the blue, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    context.m_expect_response = 0;

    // calculate size of request
    size_t size = 0;
    size_t blocks_size = 0;
    for (const auto &element : arg.blocks) {
      blocks_size += element.block.size();
      for (const auto &tx : element.txs)
        blocks_size += tx.blob.size();
      // The credit-wire attestation witness is held in RAM by m_block_queue for as
      // long as the rest of the span is, and blocks_size is the ONLY bound the sync
      // throttle has on that queue. Leaving it out would let a peer park up to one
      // cap's worth of witness per queued block while the daemon believes it is
      // under its size threshold.
      blocks_size += element.attestation_witness.size();
    }
    size += blocks_size;

    for (const auto &element : arg.missed_ids)
      size += sizeof(element.data);

    size += sizeof(arg.current_blockchain_height);
    {
      CRITICAL_REGION_LOCAL(m_buffer_mutex);
      m_avg_buffer.push_back(size);
    }
    ++m_sync_spans_downloaded;
    m_sync_download_objects_size += size;
    MDEBUG(context << " downloaded " << size << " bytes worth of blocks");

    /*using namespace boost::chrono;
      auto point = steady_clock::now();
      auto time_from_epoh = point.time_since_epoch();
      auto sec = duration_cast< seconds >( time_from_epoh ).count();*/

    if(arg.blocks.empty())
    {
      LOG_ERROR_CCONTEXT("sent wrong NOTIFY_HAVE_OBJECTS: no blocks");
      drop_connection(context, true, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }
    if(context.m_last_response_height > arg.current_blockchain_height)
    {
      LOG_ERROR_CCONTEXT("sent wrong NOTIFY_HAVE_OBJECTS: arg.m_current_blockchain_height=" << arg.current_blockchain_height
        << " < m_last_response_height=" << context.m_last_response_height << ", dropping connection");
      drop_connection(context, false, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }

    if (arg.current_blockchain_height < context.m_remote_blockchain_height)
    {
      MINFO(context << "Claims " << arg.current_blockchain_height << ", claimed " << context.m_remote_blockchain_height << " before");
      hit_score(context, 1);
    }
    note_remote_height(context, arg.current_blockchain_height,
        cryptonote_connection_context::remote_height_source::get_objects);
    if (context.m_remote_blockchain_height > m_core.get_target_blockchain_height())
      m_core.set_target_blockchain_height(context.m_remote_blockchain_height);

    std::vector<crypto::hash> block_hashes;
    block_hashes.reserve(arg.blocks.size());
    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    uint64_t start_height = std::numeric_limits<uint64_t>::max();
    crypto::hash previous{};
    cryptonote::block b;
    for(std::size_t i = 0; i < arg.blocks.size(); ++i)
    {
      if (m_stopping)
      {
        return 1;
      }

      crypto::hash block_hash;
      if(!parse_and_validate_block_from_blob(arg.blocks[i].block, b, block_hash))
      {
        LOG_ERROR_CCONTEXT("sent wrong block: failed to parse and validate block: "
          << describe_peer_blob(arg.blocks[i].block) << ", dropping connection");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }
      if (b.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(b.miner_tx.vin.front()))
      {
        LOG_ERROR_CCONTEXT("sent wrong block: block: miner tx does not have exactly one txin_gen input: "
          << describe_peer_blob(arg.blocks[i].block) << ", dropping connection");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }

      const auto this_height = std::get<txin_gen>(b.miner_tx.vin[0]).height;
      if (context.get_expected_hash(this_height) != block_hash)
      {
        LOG_ERROR_CCONTEXT("Sent invalid chain");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }

      // if first block
      if (start_height == std::numeric_limits<uint64_t>::max())
      {
        start_height = this_height;
        if (start_height > context.m_expect_height)
        {
          LOG_ERROR_CCONTEXT("sent block ahead of expected height, dropping connection");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }

        if (this_height == 0 || context.get_expected_hash(this_height - 1) != b.prev_id)
        {
          LOG_ERROR_CCONTEXT("Sent invalid chain");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }
      }
      else if (b.prev_id != previous)
      {
        LOG_ERROR_CCONTEXT("Sent invalid chain");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }
      previous = block_hash;

      if (start_height + i != this_height)
      {
        LOG_ERROR_CCONTEXT("Sent invalid chain");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }

      auto req_it = context.m_requested_objects.find(block_hash);
      if(req_it == context.m_requested_objects.end())
      {
        LOG_ERROR_CCONTEXT("sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id=" << epee::string_tools::pod_to_hex(get_blob_hash(arg.blocks[i].block))
          << " wasn't requested, dropping connection");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }
      if(b.tx_hashes.size() != arg.blocks[i].txs.size())
      {
        LOG_ERROR_CCONTEXT("sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id=" << epee::string_tools::pod_to_hex(get_blob_hash(arg.blocks[i].block))
          << ", tx_hashes.size()=" << b.tx_hashes.size() << " mismatch with block_complete_entry.m_txs.size()=" << arg.blocks[i].txs.size() << ", dropping connection");
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }

      context.m_requested_objects.erase(req_it);
      block_hashes.push_back(block_hash);
    }

    if(!context.m_requested_objects.empty())
    {
      MERROR(context << "returned not all requested objects (context.m_requested_objects.size()="
        << context.m_requested_objects.size() << "), dropping connection");
      drop_connection(context, false, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }

    // Pruned spans are never requested (the stripe engine is deleted, PDM-Q7;
    // a below-anchor skeleton sync is F28's wire, not this path), so a
    // pruned entry in a response is a protocol violation.
    {
      for (block_complete_entry& block_entry: arg.blocks)
      {
        if (block_entry.pruned)
        {
          MERROR(context << "returned a pruned block, dropping connection");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }
        if (block_entry.block_weight)
        {
          MERROR(context << "returned a block weight for a non pruned block, dropping connection");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }
        for (const tx_blob_entry &tx_entry: block_entry.txs)
        {
          if (tx_entry.prunable_hash != crypto::null_hash)
          {
            MERROR(context << "returned at least one pruned object which we did not expect, dropping connection");
            drop_connection(context, false, false);
            ++m_sync_bad_spans_downloaded;
            return 1;
          }
        }
      }
    }

    {
      MLOG_YELLOW(el::Level::Debug, context << " Got NEW BLOCKS inside of " << __FUNCTION__ << ": size: " << arg.blocks.size()
          << ", blocks: " << start_height << " - " << (start_height + arg.blocks.size() - 1) <<
          ")");

      // add that new span to the block queue
      const boost::posix_time::time_duration dt = now - request_time;
      const float rate = size * 1e6 / (dt.total_microseconds() + 1);
      MDEBUG(context << " adding span: " << arg.blocks.size() << " at height " << start_height << ", " << dt.total_microseconds()/1e6 << " seconds, " << (rate/1024) << " kB/s, size now " << (m_block_queue.get_data_size() + blocks_size) / 1048576.f << " MB");
      m_block_queue.add_blocks(start_height, arg.blocks, context.m_connection_id, context.m_remote_address, rate, blocks_size);

      const crypto::hash last_block_hash = cryptonote::get_block_hash(b);
      context.m_last_known_hash = last_block_hash;
    }

    try_add_next_blocks(context);
    return 1;
  }

  // Get an estimate for the remaining sync time from given current to target blockchain height, in seconds
  template<class t_core>
  uint64_t t_cryptonote_protocol_handler<t_core>::get_estimated_remaining_sync_seconds(uint64_t current_blockchain_height, uint64_t target_blockchain_height)
  {
    // The average sync speed varies so much, even averaged over quite long time periods like 10 minutes,
    // that using some sliding window would be difficult to implement without often leading to bad estimates.
    // The simplest strategy - always average sync speed over the maximum available interval i.e. since sync
    // started at all (from "m_sync_start_time" and "m_sync_start_height") - gives already useful results
    // and seems to be quite robust. Some quite special cases like "Internet connection suddenly becoming
    // much faster after syncing already a long time, and staying fast" are not well supported however.

    if (target_blockchain_height <= current_blockchain_height)
    {
      // Syncing stuck, or other special circumstance: Avoid errors, simply give back 0
      return 0;
    }

    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    const boost::posix_time::time_duration sync_time = now - m_sync_start_time;
    cryptonote::network_type nettype = m_core.get_nettype();

    // Don't simply use remaining number of blocks for the estimate but "sync weight" as provided by
    // "cumulative_block_sync_weight" which knows about strongly varying Monero mainnet block sizes
    uint64_t synced_weight = tools::cumulative_block_sync_weight(nettype, m_sync_start_height, current_blockchain_height - m_sync_start_height);
    float us_per_weight = (float)sync_time.total_microseconds() / (float)synced_weight;
    uint64_t remaining_weight = tools::cumulative_block_sync_weight(nettype, current_blockchain_height, target_blockchain_height - current_blockchain_height);
    float remaining_us = us_per_weight * (float)remaining_weight;
    return (uint64_t)(remaining_us / 1e6);
  }

  // Return a textual remaining sync time estimate, or the empty string if waiting period not yet over
  template<class t_core>
  std::string t_cryptonote_protocol_handler<t_core>::get_periodic_sync_estimate(uint64_t current_blockchain_height, uint64_t target_blockchain_height)
  {
    std::string text = "";
    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    boost::posix_time::time_duration period_sync_time = now - m_period_start_time;
    if (period_sync_time > boost::posix_time::minutes(2))
    {
      // Period is over, time to report another estimate
      uint64_t remaining_seconds = get_estimated_remaining_sync_seconds(current_blockchain_height, target_blockchain_height);
      text = tools::get_human_readable_timespan(remaining_seconds);

      // Start the new period
      m_period_start_time = now;
    }
    return text;
  }

  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::request_chain_history(cryptonote_connection_context& context)
  {
    // The one chain re-walk entry: clear the dead negotiation, mark the
    // context synchronizing, and request NOTIFY_REQUEST_CHAIN from the
    // node's CURRENT short history with a live request time (the idle
    // kicker's visibility condition). Shared by the fresh-block orphan
    // arm, on_callback's resume, and the sync-loop orphan arm (C2-R1c
    // Q3b) -- three hand-written copies of this block were a drift set.
    context.m_needed_objects.clear();
    context.m_state = cryptonote_connection_context::state_synchronizing;
    NOTIFY_REQUEST_CHAIN::request r = {};
    m_core.get_short_chain_history(r.block_ids, context.m_expect_height);
    handler_request_blocks_history( r.block_ids ); // change the limit(?), sleep(?)
    r.prune = false;
    context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
    context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
    MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << r.block_ids.size() );
    post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
    MLOG_PEER_STATE("requesting chain");
  }
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::try_add_next_blocks(cryptonote_connection_context& context)
  {
    bool force_next_span = false;
    const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
    if (!sync.owns_lock())
    {
      MINFO(context << "Failed to lock m_sync_lock, going back to download");
    }
    else
    {
      uint64_t start_height = 0;
      std::vector<cryptonote::block_complete_entry> blocks;
      boost::uuids::uuid span_connection_id{};
      epee::net_utils::network_address span_origin;
      if (m_block_queue.get_next_span(start_height, blocks, span_connection_id, span_origin) && !blocks.empty())
      {
        (void)span_origin;
        // A span this node asked for. The door connects it; this loop does not.
        const int offered = cryptonote::offer_block_span(
            shekyl::seam_socket_id(span_connection_id), true, blocks);
        if (offered == SHEKYL_INGEST_ACCEPTED || offered == SHEKYL_INGEST_OVERSIZE || offered == SHEKYL_INGEST_INVALID)
          m_block_queue.remove_spans(span_connection_id, start_height);
        if (offered == SHEKYL_INGEST_THROTTLED)
        {
          m_block_queue.remove_spans(span_connection_id, start_height);
          m_p2p->for_connection(span_connection_id, [this](cryptonote_connection_context& origin) {
            drop_connection(origin, false, true);
          });
        }
      }
      if (should_download_next_span(context, false))
        force_next_span = true;
    }
    if (!request_missing_objects(context, true, force_next_span))
    {
      LOG_ERROR_CCONTEXT("Failed to request missing objects, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::on_idle()
  {
    m_idle_peer_kicker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::kick_idle_peers, this));
    m_standby_checker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::check_standby_peers, this));
    m_sync_search_checker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::update_sync_search, this));
    return m_core.on_idle();
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::kick_idle_peers()
  {
    MTRACE("Checking for idle peers...");
    m_p2p->post_each([this](cryptonote_connection_context& context)
    {
      if (context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time != boost::date_time::not_a_date_time)
      {
        const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
        const boost::posix_time::time_duration dt = now - context.m_last_request_time;
        const auto ms = dt.total_microseconds();
        if (ms > IDLE_PEER_KICK_TIME || (context.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
        {
          context.m_idle_peer_notification = true;
          LOG_PRINT_CCONTEXT_L2("requesting callback");
          ++context.m_callback_request_count;
          m_p2p->request_callback(context);
          MLOG_PEER_STATE("requesting callback");
        }
      }
    }, {});

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::update_sync_search()
  {
    const uint64_t target = m_core.get_target_blockchain_height();
    const uint64_t height = m_core.get_current_blockchain_height();
    if (target > height) // if we're not synced yet, don't do it
      return true;

    MTRACE("Checking for outgoing syncing peers...");
    // The scan used to finish before the drop. It now finishes on the last
    // strand. Which synced peer is dropped stays arbitrary: the map walk
    // never had an order, and every candidate is already in `state_normal`.
    struct tally {
      std::mutex mu;
      std::unordered_map<epee::net_utils::connector_id, unsigned> n_syncing, n_synced;
      std::unordered_map<epee::net_utils::connector_id, boost::uuids::uuid> some_synced;
      std::vector<epee::net_utils::connector_id> zones;
    };
    auto counted = std::make_shared<tally>();
    m_p2p->post_each(
      [counted](cryptonote_connection_context& context)
      {
        if (!context.session_established() || context.m_is_income)
          return;
        const auto connector = epee::net_utils::connector_from_byte(context.m_connector);
        if (!connector)
          return;
        std::lock_guard<std::mutex> lock(counted->mu);
        const epee::net_utils::connector_id zone = *connector;
        if (counted->n_syncing.find(zone) == counted->n_syncing.end())
        {
          counted->n_syncing[zone] = 0;
          counted->n_synced[zone] = 0;
          counted->some_synced[zone] = boost::uuids::nil_uuid();
          counted->zones.push_back(zone);
        }
        if (context.m_state == cryptonote_connection_context::state_synchronizing)
          ++counted->n_syncing[zone];
        if (context.m_state == cryptonote_connection_context::state_normal)
        {
          ++counted->n_synced[zone];
          counted->some_synced[zone] = context.m_connection_id;
        }
      },
      [this, counted]()
      {
        for (const auto zone : counted->zones)
        {
          const unsigned syncing = counted->n_syncing[zone];
          const unsigned synced = counted->n_synced[zone];
          const boost::uuids::uuid drop_id = counted->some_synced[zone];
          MTRACE("[" << epee::net_utils::connector_id_to_string(zone) << "] " << syncing << " syncing, " << synced << " synced");
          // Whether the outbound slots are full with too few syncing is the
          // dialer's to say: it holds the target (DAEMON_CONFIG_CUTOVER.md §4.2).
          if (shekyl_sync_room_for_syncing_peer(sync_connector_of(zone), syncing, synced) && drop_id != boost::uuids::nil_uuid())
          {
            if (!m_p2p->for_connection(drop_id, [this, syncing, synced](cryptonote_connection_context& ctx){
              MINFO(ctx << "dropping synced peer, " << syncing << " syncing, " << synced << " synced");
              drop_connection(ctx, false, false);
            }))
              MDEBUG("Failed to find peer we wanted to drop");
          }
        }
      });

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::check_standby_peers()
  {
    m_p2p->post_each([this](cryptonote_connection_context& context)
    {
      if (context.m_state == cryptonote_connection_context::state_standby)
      {
        LOG_PRINT_CCONTEXT_L2("requesting callback");
        ++context.m_callback_request_count;
        m_p2p->request_callback(context);
      }
    }, {});
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_request_chain(int command, NOTIFY_REQUEST_CHAIN::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_CHAIN (" << arg.block_ids.size() << " blocks");
    if (!shekyl::seam_handshake_established(context.m_connection_id))
    {
      LOG_ERROR_CCONTEXT("Requested chain before handshake, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    NOTIFY_RESPONSE_CHAIN_ENTRY::request r;
    if(!m_core.find_blockchain_supplement(arg.block_ids, r))
    {
      LOG_ERROR_CCONTEXT("Failed to handle NOTIFY_REQUEST_CHAIN.");
      return 1;
    }
    if (r.m_block_ids.size() >= 2)
    {
      cryptonote::block b;
      if (!m_core.get_block_by_hash(r.m_block_ids[1], b))
      {
        LOG_ERROR_CCONTEXT("Failed to handle NOTIFY_REQUEST_CHAIN: first block not found");
        return 1;
      }
      r.first_block = cryptonote::block_to_blob(b);
    }
    MLOG_P2P_MESSAGE("-->>NOTIFY_RESPONSE_CHAIN_ENTRY: m_start_height=" << r.start_height << ", m_total_height=" << r.total_height << ", m_block_ids.size()=" << r.m_block_ids.size());
    post_notify<NOTIFY_RESPONSE_CHAIN_ENTRY>(r, context);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::should_download_next_span(cryptonote_connection_context& context, bool standby)
  {
    std::vector<crypto::hash> hashes;
    boost::posix_time::ptime request_time;
    boost::uuids::uuid connection_id;
    bool filled;

    const uint64_t blockchain_height = m_core.get_current_blockchain_height();
    if (context.m_remote_blockchain_height <= blockchain_height)
      return false;
    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    {
      if (!m_block_queue.has_next_span(blockchain_height, filled, request_time, connection_id))
      {
        MDEBUG(context << " we should download it as no peer reserved it");
        return true;
      }
      if (!filled)
      {
        const long dt = (now - request_time).total_microseconds();
        if (dt >= REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD)
        {
          MDEBUG(context << " we should download it as it's not been received yet after " << dt/1e6);
          return true;
        }

        // in standby, be ready to double download early since we're idling anyway
        // let the fastest peer trigger first
        const double dl_speed = context.m_max_speed_down;
        if (standby && dt >= REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY && dl_speed > 0)
        {
          // The other connection's last receive and its current speed are
          // seam observations. Reading them here keeps the decision on
          // this call. A later `request_missing_objects(..., true)` would
          // skip every recheck in that function on values that had gone stale.
          const auto board = shekyl::seam_board_snapshot();
          const auto other = std::find_if(board.begin(), board.end(), [&](const shekyl_seam_board_row& row) {
            return shekyl::seam_connection_id(row.id) == connection_id;
          });
          if (other == board.end())
          {
            MWARNING(context << " we should download it as the downloading peer is unexpectedly not known to us");
            return true;
          }
          std::uint64_t speed_up = 0;
          std::uint64_t speed_down = 0;
          shekyl_link_speed(other->id, &speed_up, &speed_down);
          std::uint64_t send_ms = 0;
          std::uint64_t recv_ms = 0;
          shekyl_link_activity(other->id, &send_ms, &recv_ms);
          const std::uint64_t now_ms = shekyl_monotonic_ms();
          const std::uint64_t mark = shekyl_recv_mark_ms(recv_ms, other->started_mono);
          const double since_s = now_ms >= mark ? static_cast<double>(now_ms - mark) / 1000.0 : 0.0;
          const float last_activity = std::min(static_cast<float>(since_s), dt / 1e6f);
          bool download = last_activity > LAST_ACTIVITY_STALL_THRESHOLD;
          if (!download)
          {
            const float max_multiplier = 10.f;
            const float min_multiplier = 1.25f;
            float multiplier = max_multiplier - (dt - REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY) * (max_multiplier - min_multiplier) / (REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD - REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY);
            multiplier = std::min(max_multiplier, std::max(min_multiplier, multiplier));
            download = dl_speed * .8f > static_cast<float>(speed_down) * multiplier;
          }
          if (download)
            return true;
        }
      }
    }

    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  size_t t_cryptonote_protocol_handler<t_core>::skip_unneeded_hashes(cryptonote_connection_context& context, bool check_block_queue) const
  {
    // take out blocks we already have
    size_t skip = 0;
    while (skip < context.m_needed_objects.size() && (m_core.have_block(context.m_needed_objects[skip].first) || (check_block_queue && m_block_queue.have(context.m_needed_objects[skip].first))))
    {
      // if we're popping the last hash, record it so we can ask again from that hash,
      // this prevents never being able to progress on peers we get old hash lists from
      if (skip + 1 == context.m_needed_objects.size())
        context.m_last_known_hash = context.m_needed_objects[skip].first;
      ++skip;
    }
    if (skip > 0)
    {
      MDEBUG(context << "skipping " << skip << "/" << context.m_needed_objects.size() << " blocks");
      context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>(context.m_needed_objects.begin() + skip, context.m_needed_objects.end());
    }
    return skip;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::request_missing_objects(cryptonote_connection_context& context, bool check_having_blocks, bool force_next_span)
  {
    // flush stale spans
    std::set<boost::uuids::uuid> live_connections;
    for (const auto& row : shekyl::seam_board_snapshot())
      live_connections.insert(shekyl::seam_connection_id(row.id));
    m_block_queue.flush_stale_spans(live_connections);

    // if we don't need to get next span, and the block queue is full enough, wait a bit
    if (!force_next_span)
    {
      do
      {
        const size_t nspans = m_block_queue.get_num_filled_spans();
        const size_t size = m_block_queue.get_data_size();
        const uint64_t bc_height = m_core.get_current_blockchain_height();
        const size_t block_queue_size_threshold = m_block_download_max_size ? m_block_download_max_size : BLOCK_QUEUE_SIZE_THRESHOLD;
        const bool queue_proceed_init = (nspans < m_span_limit.load()) && (size < block_queue_size_threshold);
        // get rid of blocks we already requested, or already have
        if (skip_unneeded_hashes(context, true) && context.m_needed_objects.empty() && context.m_num_requested == 0)
        {
          if (context.m_remote_blockchain_height > m_block_queue.get_next_needed_height(bc_height))
          {
            MERROR(context << "Nothing we can request from this peer, and we did not request anything previously");
            return false;
          }
          MDEBUG(context << "Nothing to get from this peer, and it's not ahead of us, all done");
          context.set_state_normal();
          if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
            on_connection_synchronized();
          return true;
        }
        const uint64_t next_needed_height = m_block_queue.get_next_needed_height(bc_height);
        const uint64_t next_block_height = context.m_needed_objects.empty()
          ? next_needed_height
          : context.m_last_response_height - context.m_needed_objects.size() + 1;
        const bool next_height_proceed = next_needed_height < std::max(next_block_height, bc_height + 1);
        // The immediate next block overrides a full queue: the chain cannot
        // advance while that span waits on the capacity gate.
        const bool queue_proceed = (next_needed_height == bc_height) ? next_height_proceed : queue_proceed_init;

        MDEBUG(context
               << "last_response_height " << context.m_last_response_height << ", m_needed_objects size " << context.m_needed_objects.size()
               << ", queue_proceed : " << queue_proceed
               << ", next_height_proceed : " << next_height_proceed
               << ", next_block_height/next_needed_height/bc_height : " << next_block_height << "/" << next_needed_height << "/" << bc_height
               << ", nspans/span_limit : " << nspans << "/" << m_span_limit
               << ", queue size/size_limit : " << size << "/" << block_queue_size_threshold);

        // if we're waiting for next span, try to get it before unblocking threads below,
        // or a runaway downloading of future spans might happen
        if (next_height_proceed && should_download_next_span(context, true))
        {
          MDEBUG(context << " we should try for that next span too, we think we could get it faster, resuming");
          force_next_span = true;
          MLOG_PEER_STATE("resuming");
          break;
        }

        if (queue_proceed)
        {
          if (context.m_state != cryptonote_connection_context::state_standby)
          {
            LOG_DEBUG_CC(context, "Block queue is " << nspans << " and " << size << ", resuming");
            MLOG_PEER_STATE("resuming");
          }
          break;
        }

        // this one triggers if all threads are in standby, which should not happen,
        // but happened at least once, so we unblock at least one thread if so
        boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
        if (sync.owns_lock())
        {
          bool filled = false;
          boost::posix_time::ptime time;
          boost::uuids::uuid connection_id;
          if (m_block_queue.has_next_span(m_core.get_current_blockchain_height(), filled, time, connection_id) && filled)
          {
            LOG_DEBUG_CC(context, "No other thread is adding blocks, and next span needed is ready, resuming");
            MLOG_PEER_STATE("resuming");
            context.m_state = cryptonote_connection_context::state_standby;
            ++context.m_callback_request_count;
            m_p2p->request_callback(context);
            return true;
          }
          else
          {
            sync.unlock();

            // if this has gone on for too long, drop incoming connection to guard against some wedge state
            if (!context.m_is_income)
            {
              const uint64_t now = tools::get_tick_count();
              const uint64_t dt = now - m_last_add_end_time;
              if (m_last_add_end_time && tools::ticks_to_ns(dt) >= DROP_ON_SYNC_WEDGE_THRESHOLD)
              {
                MDEBUG(context << "ns " << tools::ticks_to_ns(dt) << " from " << m_last_add_end_time << " and " << now);
                MDEBUG(context << "Block addition seems to have wedged, dropping connection");
                return false;
              }
            }
          }
        }

        if (context.m_state != cryptonote_connection_context::state_standby)
        {
          if (!queue_proceed)
            LOG_DEBUG_CC(context, "Block queue is " << nspans << " and " << size << ", pausing");
          context.m_state = cryptonote_connection_context::state_standby;
          MLOG_PEER_STATE("pausing");
        }

        return true;
      } while(0);
      context.m_state = cryptonote_connection_context::state_synchronizing;
    }

    MDEBUG(context << " request_missing_objects: check " << check_having_blocks << ", force_next_span " << force_next_span
        << ", m_needed_objects " << context.m_needed_objects.size() << " lrh " << context.m_last_response_height << ", chain "
        << m_core.get_current_blockchain_height());
    if(context.m_needed_objects.size() || force_next_span)
    {
      //we know objects that we need, request this objects
      NOTIFY_REQUEST_GET_OBJECTS::request req;
      bool is_next = false;
      size_t count = 0;
      const size_t l_m_bss = m_core.get_block_sync_size(m_core.get_current_blockchain_height());
      std::pair<uint64_t, uint64_t> span = std::make_pair(0, 0);
      if (force_next_span)
      {
        if (span.second == 0)
        {
          std::vector<crypto::hash> hashes;
          boost::uuids::uuid span_connection_id;
          boost::posix_time::ptime time;
          span = m_block_queue.get_next_span_if_scheduled(hashes, span_connection_id, time);
          if (span.second > 0)
          {
            is_next = true;
            req.blocks.reserve(hashes.size());
            for (const auto &hash: hashes)
            {
              req.blocks.push_back(hash);
              context.m_requested_objects.insert(hash);
            }
            m_block_queue.reset_next_span_time();
          }
        }
      }
      if (span.second == 0)
      {
        MDEBUG(context << " span size is 0");
        if (context.m_last_response_height + 1 < context.m_needed_objects.size())
        {
          MERROR(context << " ERROR: inconsistent context: lrh " << context.m_last_response_height << ", nos " << context.m_needed_objects.size());
          context.m_needed_objects.clear();
          context.m_last_response_height = 0;
          goto skip;
        }
        if (skip_unneeded_hashes(context, false) && context.m_needed_objects.empty() && context.m_num_requested == 0)
        {
          if (context.m_remote_blockchain_height > m_block_queue.get_next_needed_height(m_core.get_current_blockchain_height()))
          {
            MERROR(context << "Nothing we can request from this peer, and we did not request anything previously");
            return false;
          }
          MDEBUG(context << "Nothing to get from this peer, and it's not ahead of us, all done");
          context.set_state_normal();
          if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
            on_connection_synchronized();
          return true;
        }

        const uint64_t first_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
        span = m_block_queue.reserve_span(first_block_height, context.m_last_response_height, l_m_bss, context.m_connection_id, context.m_remote_address, context.m_remote_blockchain_height, context.m_needed_objects);
        MDEBUG(context << " span from " << first_block_height << ": " << span.first << "/" << span.second);
      }
      if (span.second == 0 && !force_next_span)
      {
        MDEBUG(context << " still no span reserved, we may be in the corner case of next span scheduled and everything else scheduled/filled");
        std::vector<crypto::hash> hashes;
        boost::uuids::uuid span_connection_id;
        boost::posix_time::ptime time;
        span = m_block_queue.get_next_span_if_scheduled(hashes, span_connection_id, time);
        if (span.second > 0)
        {
          is_next = true;
          req.blocks.reserve(hashes.size());
          for (const auto &hash: hashes)
          {
            req.blocks.push_back(hash);
            ++count;
            context.m_requested_objects.insert(hash);
            // that's atrocious O(n) wise, but this is rare
            auto i = std::find_if(context.m_needed_objects.begin(), context.m_needed_objects.end(),
                [&hash](const std::pair<crypto::hash, uint64_t> &o) { return o.first == hash; });
            if (i != context.m_needed_objects.end())
              context.m_needed_objects.erase(i);
          }
        }
      }
      MDEBUG(context << " span: " << span.first << "/" << span.second << " (" << span.first << " - " << (span.first + span.second - 1) << ")");
      if (span.second > 0)
      {
        if (!is_next)
        {
          const uint64_t first_context_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
          uint64_t skip = span.first - first_context_block_height;
          if (skip > context.m_needed_objects.size())
          {
            MERROR("ERROR: skip " << skip << ", m_needed_objects " << context.m_needed_objects.size() << ", first_context_block_height" << first_context_block_height);
            return false;
          }
          if (skip > 0)
            context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>(context.m_needed_objects.begin() + skip, context.m_needed_objects.end());
          if (context.m_needed_objects.size() < span.second)
          {
            MERROR("ERROR: span " << span.first << "/" << span.second << ", m_needed_objects " << context.m_needed_objects.size());
            return false;
          }

          req.blocks.reserve(req.blocks.size() + span.second);
          for (size_t n = 0; n < span.second; ++n)
          {
            req.blocks.push_back(context.m_needed_objects[n].first);
            ++count;
            context.m_requested_objects.insert(context.m_needed_objects[n].first);
          }
          context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>(context.m_needed_objects.begin() + span.second, context.m_needed_objects.end());
        }

        // Full data, always: pruned spans are never requested (PDM-Q7 deleted
        // the stripe engine; the wire flag stays for F28's skeleton sync).
        req.prune = false;
        context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
        context.m_expect_height = span.first;
        context.m_expect_response = NOTIFY_RESPONSE_GET_OBJECTS::ID;
        MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_GET_OBJECTS: blocks.size()=" << req.blocks.size()
            << "requested blocks count=" << count << " / " << l_m_bss << " from " << span.first << ", first hash " << req.blocks.front());
        context.m_num_requested += req.blocks.size();
        post_notify<NOTIFY_REQUEST_GET_OBJECTS>(req, context);
        MLOG_PEER_STATE("requesting objects");
        return true;
      }

      // we can do nothing, so drop this peer to make room for others unless we think we've downloaded all we need
      const uint64_t blockchain_height = m_core.get_current_blockchain_height();
      if (std::max(blockchain_height, m_block_queue.get_next_needed_height(blockchain_height)) >= m_core.get_target_blockchain_height())
      {
        context.set_state_normal();
        MLOG_PEER_STATE("Nothing to do for now, switching to normal state");
        return true;
      }
      MLOG_PEER_STATE("We can download nothing from this peer, dropping");
      return false;
    }

skip:
    context.m_needed_objects.clear();

    // we might have been called from the "received chain entry" handler, and end up
    // here because we can't use any of those blocks (maybe because all of them are
    // actually already requested). In this case, if we can add blocks instead, do so
    if (m_core.get_current_blockchain_height() < m_core.get_target_blockchain_height())
    {
      const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
      if (sync.owns_lock())
      {
        uint64_t start_height;
        std::vector<cryptonote::block_complete_entry> blocks;
        boost::uuids::uuid span_connection_id;
        epee::net_utils::network_address span_origin;
        if (m_block_queue.get_next_span(start_height, blocks, span_connection_id, span_origin, true))
        {
          LOG_DEBUG_CC(context, "No other thread is adding blocks, resuming");
          MLOG_PEER_STATE("will try to add blocks next");
          context.m_state = cryptonote_connection_context::state_standby;
          ++context.m_callback_request_count;
          m_p2p->request_callback(context);
          return true;
        }
      }
    }

    if(context.m_last_response_height < context.m_remote_blockchain_height-1)
    {//we have to fetch more objects ids, request blockchain entry

      NOTIFY_REQUEST_CHAIN::request r = {};
      m_core.get_short_chain_history(r.block_ids, context.m_expect_height);
      CHECK_AND_ASSERT_MES(!r.block_ids.empty(), false, "Short chain history is empty");

      // we'll want to start off from where we are on that peer, which may not be added yet
      if (context.m_last_known_hash != crypto::null_hash && r.block_ids.front() != context.m_last_known_hash)
      {
        context.m_expect_height = std::numeric_limits<uint64_t>::max();
        r.block_ids.push_front(context.m_last_known_hash);
      }

      handler_request_blocks_history( r.block_ids ); // change the limit(?), sleep(?)
      r.prune = false;

      //std::string blob; // for calculate size of request
      //epee::serialization::store_t_to_binary(r, blob);
      //LOG_PRINT_CCONTEXT_L1("r = " << 200);

      context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
      context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
      MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << r.block_ids.size());
      post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
      MLOG_PEER_STATE("requesting chain");
    }else
    {
      CHECK_AND_ASSERT_MES(context.m_last_response_height == context.m_remote_blockchain_height-1
                           && !context.m_needed_objects.size()
                           && !context.m_requested_objects.size(), false, "request_missing_blocks final condition failed!"
                           << "\r\nm_last_response_height=" << context.m_last_response_height
                           << "\r\nm_remote_blockchain_height=" << context.m_remote_blockchain_height
                           << "\r\nm_needed_objects.size()=" << context.m_needed_objects.size()
                           << "\r\nm_requested_objects.size()=" << context.m_requested_objects.size()
                           << "\r\non connection [" << epee::net_utils::print_connection_context_short(context)<< "]");

      context.set_state_normal();
      if (context.m_remote_blockchain_height >= m_core.get_target_blockchain_height())
      {
        if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
          on_connection_synchronized();
      }
      else
      {
        MINFO(context << " we've reached this peer's blockchain height (theirs " << context.m_remote_blockchain_height << ", our target " << m_core.get_target_blockchain_height());
      }
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::on_connection_synchronized()
  {
    bool val_expected = false;
    uint64_t current_blockchain_height = m_core.get_current_blockchain_height();
    if(m_synchronized.compare_exchange_strong(val_expected, true))
    {
      if ((current_blockchain_height > m_sync_start_height) && (m_sync_spans_downloaded > 0))
      {
        uint64_t synced_blocks = current_blockchain_height - m_sync_start_height;
        // Report only after syncing an "interesting" number of blocks:
        if (synced_blocks > 20)
        {
          const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
          uint64_t synced_seconds = (now - m_sync_start_time).total_seconds();
          if (synced_seconds == 0)
          {
            synced_seconds = 1;
          }
          const float blocks_per_second = (1000 * synced_blocks / synced_seconds) / 1000.0f;
          MGINFO_YELLOW("Synced " << synced_blocks << " blocks in "
            << tools::get_human_readable_timespan(synced_seconds) << " (" << blocks_per_second << " blocks per second)");
        }
      }
      MGINFO_YELLOW(ENDL << "**********************************************************************" << ENDL
        << "You are now synchronized with the network. You may now start shekyl-cli." << ENDL
        << ENDL
        << "Use the \"help\" command to see the list of available commands." << ENDL
        << "**********************************************************************");
      m_sync_timer.pause();
      if (ELPP->vRegistry()->allowed(el::Level::Info, "sync-info"))
      {
        const uint64_t sync_time = m_sync_timer.value();
        const uint64_t add_time = m_add_timer.value();
        if (sync_time && add_time)
        {
          MCLOG_YELLOW(el::Level::Info, "sync-info", "Sync time: " << sync_time/1e9/60 << " min, idle time " <<
              (100.f * (1.0f - add_time / (float)sync_time)) << "%" << ", " <<
              (10 * m_sync_download_objects_size / 1024 / 1024) / 10.f << " + " <<
              (10 * m_sync_download_chain_size / 1024 / 1024) / 10.f << " MB downloaded, " <<
              100.0f * m_sync_old_spans_downloaded / m_sync_spans_downloaded << "% old spans, " <<
              100.0f * m_sync_bad_spans_downloaded / m_sync_spans_downloaded << "% bad spans");
        }
      }
      m_core.on_synchronized();
    }

    // ask for txpool complement from any suitable node if we did not yet
    val_expected = true;
    if (m_ask_for_txpool_complement.compare_exchange_strong(val_expected, false))
    {
      auto asked = std::make_shared<std::atomic<bool>>(false);
      m_p2p->post_each([this, asked](cryptonote_connection_context& context)
      {
        if(context.m_state < cryptonote_connection_context::state_synchronizing)
        {
          MDEBUG(context << "not ready, ignoring");
          return;
        }
        // One ask. The strands run together, so the claim is the exclusion
        // the old early-return was. A refusal gives the claim back; a strand
        // that already lost it does not retry.
        bool claim = false;
        if (!asked->compare_exchange_strong(claim, true, std::memory_order_acq_rel))
          return;
        if (!request_txpool_complement(context))
        {
          MERROR(context << "Failed to request txpool complement");
          asked->store(false, std::memory_order_release);
          return;
        }
      }, [this, asked]() {
        // Every strand passed, or the one that claimed it failed after the
        // others had already passed. The flag was cleared before the walk.
        // Put it back so the next sync asks again, rather than waiting for
        // a disconnect.
        if (!asked->load(std::memory_order_acquire))
          m_ask_for_txpool_complement.store(true, std::memory_order_release);
      });
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_response_chain_entry(int command, NOTIFY_RESPONSE_CHAIN_ENTRY::request& arg, cryptonote_connection_context& context)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_RESPONSE_CHAIN_ENTRY: m_block_ids.size()=" << arg.m_block_ids.size()
      << ", m_start_height=" << arg.start_height << ", m_total_height=" << arg.total_height << ", expect height=" << context.m_expect_height);
    MLOG_PEER_STATE("received chain");

    if (context.m_expect_response != NOTIFY_RESPONSE_CHAIN_ENTRY::ID)
    {
      LOG_ERROR_CCONTEXT("Got NOTIFY_RESPONSE_CHAIN_ENTRY out of the blue, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    context.m_expect_response = 0;
    if (arg.start_height + 1 > context.m_expect_height) // we expect an overlapping block
    {
      LOG_ERROR_CCONTEXT("Got NOTIFY_RESPONSE_CHAIN_ENTRY past expected height, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }

    context.m_last_request_time = boost::date_time::not_a_date_time;

    m_sync_download_chain_size += arg.m_block_ids.size() * sizeof(crypto::hash);

    if(!arg.m_block_ids.size())
    {
      LOG_ERROR_CCONTEXT("sent empty m_block_ids, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    if (arg.total_height < arg.m_block_ids.size() || arg.start_height > arg.total_height - arg.m_block_ids.size())
    {
      LOG_ERROR_CCONTEXT("sent invalid start/nblocks/height, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    if (!arg.m_block_weights.empty() && arg.m_block_weights.size() != arg.m_block_ids.size())
    {
      LOG_ERROR_CCONTEXT("sent invalid block weight array, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    MDEBUG(context << "first block hash " << arg.m_block_ids.front() << ", last " << arg.m_block_ids.back());

    if (arg.total_height >= CRYPTONOTE_MAX_BLOCK_NUMBER || arg.m_block_ids.size() > BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT)
    {
      LOG_ERROR_CCONTEXT("sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with total_height=" << arg.total_height << " and block_ids=" << arg.m_block_ids.size());
      drop_connection(context, false, false);
      return 1;
    }
    if (arg.total_height < context.m_remote_blockchain_height)
    {
      MINFO(context << "Claims " << arg.total_height << ", claimed " << context.m_remote_blockchain_height << " before");
      hit_score(context, 1);
    }
    note_remote_height(context, arg.total_height,
        cryptonote_connection_context::remote_height_source::chain_entry);
    context.m_last_response_height = arg.start_height + arg.m_block_ids.size()-1;
    if(context.m_last_response_height > context.m_remote_blockchain_height)
    {
      LOG_ERROR_CCONTEXT("sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with m_total_height=" << arg.total_height
                                                                         << ", m_start_height=" << arg.start_height
                                                                         << ", m_block_ids.size()=" << arg.m_block_ids.size());
      drop_connection(context, false, false);
      return 1;
    }

    context.m_expected_heights_start = arg.start_height;

    context.m_expected_heights.clear();
    context.m_expected_heights.reserve(arg.m_block_ids.size());
    context.m_needed_objects.clear();
    context.m_needed_objects.reserve(arg.m_block_ids.size());
    std::unordered_set<crypto::hash> blocks_found;
    bool expect_unknown = false;
    for (size_t i = 0; i < arg.m_block_ids.size(); ++i)
    {
      if (!blocks_found.insert(arg.m_block_ids[i]).second)
      {
        LOG_ERROR_CCONTEXT("Duplicate blocks in chain entry response, dropping connection");
        drop_connection_with_score(context, 5, false);
        return 1;
      }
      int where;
      const bool have_block = m_core.have_block_unlocked(arg.m_block_ids[i], &where);
      if (i == 0)
      {
        // our outgoing chainlist only has proven blocks (i.e. downloaded)
        if (!have_block && m_block_queue.have_height(arg.m_block_ids[i]) != arg.start_height)
        {
          LOG_ERROR_CCONTEXT("First block hash is unknown, dropping connection");
          drop_connection_with_score(context, 5, false);
          return 1;
        }
        if (!have_block)
          expect_unknown = true;
      }
      if (0 < i)
      {
        // after the first, blocks may be known or unknown, but if they are known,
        // they should be at the same height if on the main chain
        if (have_block)
        {
          switch (where)
          {
            default:
            case HAVE_BLOCK_INVALID:
              LOG_ERROR_CCONTEXT("Block is invalid or known without known type, dropping connection");
              drop_connection(context, true, false);
              return 1;
            case HAVE_BLOCK_MAIN_CHAIN:
              if (expect_unknown)
              {
                LOG_ERROR_CCONTEXT("Block is on the main chain, but we did not expect a known block, dropping connection");
                drop_connection_with_score(context, 5, false);
                return 1;
              }
              if (m_core.get_block_id_by_height(arg.start_height + i) != arg.m_block_ids[i])
              {
                LOG_ERROR_CCONTEXT("Block is on the main chain, but not at the expected height, dropping connection");
                drop_connection_with_score(context, 5, false);
                return 1;
              }
              break;
            case HAVE_BLOCK_ALT_CHAIN:
              if (expect_unknown)
              {
                LOG_ERROR_CCONTEXT("Block is on the main chain, but we did not expect a known block, dropping connection");
                drop_connection_with_score(context, 5, false);
                return 1;
              }
              break;
          }
        }
        else
          expect_unknown = true;
      }
      const uint64_t block_weight = arg.m_block_weights.empty() ? 0 : arg.m_block_weights[i];
      context.m_expected_heights.push_back(arg.m_block_ids[i]);
      context.m_needed_objects.push_back(std::make_pair(arg.m_block_ids[i], block_weight));
    }

    if (!request_missing_objects(context, false))
    {
      LOG_ERROR_CCONTEXT("Failed to request missing objects, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }

    if (arg.total_height > m_core.get_target_blockchain_height())
      m_core.set_target_blockchain_height(arg.total_height);

    context.m_num_requested = 0;
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::relay_block(NOTIFY_NEW_COMPACT_BLOCK::request& arg, cryptonote_connection_context& exclude_context)
  {
    // Compact-block announce is the sole block path (PWD-B6), on every session.
    std::vector<std::pair<epee::net_utils::connector_id, boost::uuids::uuid>> connections;
    for (const auto& row : shekyl::seam_board_snapshot())
    {
      if (row.established == 0)
        continue;
      const boost::uuids::uuid id = shekyl::seam_connection_id(row.id);
      if (id == exclude_context.m_connection_id)
        continue;
      const auto connector = epee::net_utils::connector_from_byte(row.endpoint.connector);
      if (!connector)
        continue;
      connections.push_back({*connector, id});
    }

    if (!connections.empty())
    {
      epee::levin::message_writer blob{32 * 1024};
      epee::serialization::store_t_to_binary(arg, blob.buffer);
      m_p2p->relay_notify_to_list(NOTIFY_NEW_COMPACT_BLOCK::ID, std::move(blob), std::move(connections));
    }

    return true;
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
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::request_txpool_complement(cryptonote_connection_context &context)
  {
    NOTIFY_GET_TXPOOL_COMPLEMENT::request r = {};
    if (!m_core.get_pool_transaction_hashes(r.hashes, false))
    {
      MERROR("Failed to get txpool hashes");
      return false;
    }
    MLOG_P2P_MESSAGE("-->>NOTIFY_GET_TXPOOL_COMPLEMENT: hashes.size()=" << r.hashes.size() );
    post_notify<NOTIFY_GET_TXPOOL_COMPLEMENT>(r, context);
    MLOG_PEER_STATE("requesting txpool complement");
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::hit_score(cryptonote_connection_context &context, int32_t score)
  {
    if (score <= 0)
    {
      MERROR("Negative score hit");
      return;
    }
    context.m_score -= score;
    if (context.m_score <= DROP_PEERS_ON_SCORE)
      drop_connection_with_score(context, 5, false);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::needs_new_sync_connections(epee::net_utils::connector_id zone) const
  {
    const uint64_t target = m_core.get_target_blockchain_height();
    const uint64_t height = m_core.get_current_blockchain_height();
    if (target && target <= height)
      return false;
    const std::uint32_t n_out_peers = static_cast<std::uint32_t>(shekyl_seam_board_count(
        static_cast<std::uint32_t>(zone), SHEKYL_DIRECTION_OUTBOUND));
    return shekyl_sync_wants_more_outbound(sync_connector_of(zone), n_out_peers);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::is_busy_syncing()
  {
    const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
    return !sync.owns_lock();
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connection_with_score(cryptonote_connection_context &context, unsigned score, bool flush_all_spans)
  {
    LOG_DEBUG_CC(context, "dropping connection id " << context.m_connection_id << ", score " << score << ", flush_all_spans " << flush_all_spans);

    if (score > 0)
      m_p2p->add_host_fail(context.m_remote_address, score);

    m_block_queue.flush_spans(context.m_connection_id, flush_all_spans);

    m_p2p->drop_connection(context);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connection(cryptonote_connection_context &context, bool add_fail, bool flush_all_spans)
  {
    return drop_connection_with_score(context, add_fail ? 1 : 0, flush_all_spans);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connection(const boost::uuids::uuid& id)
  {
    m_p2p->for_connection(id, [this](cryptonote_connection_context& context){
      // This _could be_ outside of strand, so careful on actions
      drop_connection(context, true, false);
    });
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connections(const epee::net_utils::network_address address)
  {
    // Host-wide severing needs an address that names a host. Every inbound
    // connection on an anonymity zone carries the same per-zone `unknown()`
    // default (`net_node.inl` `set_default_remote`, one call per zone), so
    // "every connection sharing this host" is every inbound peer in the zone
    // -- on a Tor-only posture, near-total isolation triggered by one peer.
    //
    // `is_same_host` already refuses to equate such an address, so the loop
    // below would select nothing; returning early states the intent where the
    // sweep is issued and skips a misleading warning and a pointless scan.
    // Callers drop the originating connection by id, which stays correct.
    if (!address.is_blockable())
    {
      MINFO("not dropping connections by host for " << address.str()
        << ": this address names no host, so it cannot single out a peer -- every "
           "inbound connection in its zone carries the same value");
      return;
    }

    MWARNING("dropping connections to " << address.str());

    m_p2p->add_host_fail(address, 5);

    m_p2p->post_each([this, address](cryptonote_connection_context& context) {
      if (!address.is_same_host(context.m_remote_address))
        return;
      m_block_queue.flush_spans(context.m_connection_id, true);
      drop_connection(context, true, false);
    }, {});
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::on_connection_close(cryptonote_connection_context &context)
  {
    const boost::uuids::uuid closed_id = context.m_connection_id;
    const bool closed_was_past_handshake = context.m_state > cryptonote_connection_context::state_before_handshake;
    auto tallest = std::make_shared<std::atomic<uint64_t>>(0);
    m_p2p->post_each(
      [closed_id, tallest](const connection_context& cntxt)
      {
        if (cntxt.m_state < cryptonote_connection_context::state_synchronizing || cntxt.m_connection_id == closed_id)
          return;
        uint64_t seen = tallest->load(std::memory_order_relaxed);
        while (cntxt.m_remote_blockchain_height > seen
            && !tallest->compare_exchange_weak(seen, cntxt.m_remote_blockchain_height, std::memory_order_relaxed))
        {}
      },
      [this, tallest, closed_was_past_handshake]()
      {
        const uint64_t target = tallest->load(std::memory_order_relaxed);
        const uint64_t previous_target = m_core.get_target_blockchain_height();
        if (target < previous_target)
        {
          MINFO("Target height decreasing from " << previous_target << " to " << target);
          m_core.set_target_blockchain_height(target);
          if (target == 0 && closed_was_past_handshake && !m_stopping)
          {
            MCWARNING("global", "shekyld is now disconnected from the network");
            m_ask_for_txpool_complement = true;
          }
        }
      });

    m_block_queue.flush_spans(context.m_connection_id, false);
    // The door held state for this session (its arrival bucket): release it.
    cryptonote::ingest_session_closed(shekyl::seam_socket_id(closed_id));
    MLOG_PEER_STATE("closed");
  }

  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::stop()
  {
    m_stopping = true;
    m_core.stop();
  }
} // namespace


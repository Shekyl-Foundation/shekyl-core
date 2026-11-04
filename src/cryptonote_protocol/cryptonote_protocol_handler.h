/// @file
/// @author rfree (current maintainer/user in monero.cc project - most of code is from CryptoNote)
/// @brief This is the original cryptonote protocol network-events handler, modified by us

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

#pragma once

#include <string>

#include "byte_slice.h"
#include "storages/levin_abstract_invoke2.h"
#include "warnings.h"
#include "cryptonote_protocol_defs.h"
#include "cryptonote_protocol_handler_common.h"
#include "cryptonote_basic/connection_context.h"
#include "net/levin_base.h"
#include "p2p/net_node_common.h"

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

namespace cryptonote
{
  /// The transaction routes, RD's, after chain sync's cutover (CS-5). The
  /// chain, the blocks and their announcements are the Rust sync owner's;
  /// this handler keeps the pool's relay (2002) and serving the pool
  /// complement (2010) until RD's cutover deletes it.
  template<class t_core>
  class t_cryptonote_protocol_handler: public i_cryptonote_protocol
  {
  public:
    typedef cryptonote_connection_context connection_context;
    typedef t_cryptonote_protocol_handler<t_core> cryptonote_protocol_handler;
    typedef CORE_SYNC_DATA payload_type;

    t_cryptonote_protocol_handler(t_core& rcore, nodetool::i_p2p_endpoint<connection_context>* p_net_layout);

    BEGIN_INVOKE_MAP2(cryptonote_protocol_handler)
      HANDLE_NOTIFY_T2(NOTIFY_NEW_TRANSACTIONS, &cryptonote_protocol_handler::handle_notify_new_transactions)
      HANDLE_NOTIFY_T2(NOTIFY_GET_TXPOOL_COMPLEMENT, &cryptonote_protocol_handler::handle_notify_get_txpool_complement)
    END_INVOKE_MAP2()

    bool init();
    bool deinit();
    void set_p2p_endpoint(nodetool::i_p2p_endpoint<connection_context>* p2p);
    t_core& get_core(){return m_core;}
    void log_connections();
    void stop();

#ifndef IN_UNIT_TESTS
  private:
#endif
    //----------------- commands handlers ----------------------------------------------
    int handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& arg, cryptonote_connection_context& context);
    int handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_connection_context& context);

    //----------------- i_cryptonote_protocol ------------------------------------------
    virtual bool relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& arg, const boost::uuids::uuid& source, relay_method tx_relay);
    //----------------------------------------------------------------------------------
    void drop_connection(cryptonote_connection_context &context);

    t_core& m_core;

    nodetool::p2p_endpoint_stub<connection_context> m_p2p_stub;
    nodetool::i_p2p_endpoint<connection_context>* m_p2p;

    template<class t_parameter>
      bool post_notify(typename t_parameter::request& arg, cryptonote_connection_context& context)
      {
        LOG_PRINT_L2("[" << epee::net_utils::print_connection_context_short(context) << "] post " << typeid(t_parameter).name() << " -->");

        epee::levin::message_writer out{256 * 1024};
        epee::serialization::store_t_to_binary(arg, out.buffer);
        return m_p2p->invoke_notify_to_peer(t_parameter::ID, std::move(out), context);
      }
  };

} // namespace

POP_WARNINGS

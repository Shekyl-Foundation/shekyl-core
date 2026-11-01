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

#include <ctime>

#include <boost/function.hpp>

#include "cryptonote_basic/fwd.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_core/i_core_events.h"
#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "cryptonote_protocol/enums.h"
#include "syncobj.h"
#include "rpc/message_data_structs.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/connection_context.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "span.h"

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

   /**
    * @brief the thin C++ shell over the Rust node
    *
    * One method per call the transaction handler, `levin_notify` and the
    * daemon's entry still make (`DRS_X_STORE_FLIP.md` DX-Q1); each forwards
    * to a `shekyl_pool_*` or `shekyl_node_*` export. The chain, the pool
    * and chain sync are Rust's (CS-5).
    */
   class core final: public i_core_events
   {
   public:

      /**
       * @brief constructor
       *
       * sets member variables into a usable state
       *
       * @param pprotocol pre-constructed protocol object to store and use
       */
     core(i_cryptonote_protocol* pprotocol);

     /**
      * @brief handles an incoming transaction
      *
      * Parses an incoming transaction and, if nothing is obviously wrong,
      * passes it along to the transaction pool
      *
      * @param tx_blob the tx to handle
      * @param tvc metadata about the transaction's validity
      * @param tx_relay how the transaction was received
      * @param relayed whether or not the transaction was relayed to us
      *
      * @return true if the transaction was accepted, false otherwise
      */
     bool handle_incoming_tx(const blobdata& tx_blob, tx_verification_context& tvc, relay_method tx_relay, bool relayed);

     /**
      * @brief get the cryptonote protocol instance
      *
      * @return the instance
      */
     i_cryptonote_protocol* get_protocol(){return m_pprotocol;}

     /**
      * @brief called when a transaction is relayed.
      * @note Should only be invoked from `levin_notify`.
      */
     void on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, relay_method tx_relay, std::optional<std::uint8_t> stem_connector) final;



     /**
      * @brief records the network and the relay entry
      *
      * The chain is the Rust store; this opens no database. The snapshot's
      * network code selects FAKECHAIN as regtest does.
      *
      * @param snapshot the daemon's resolved configuration
      *
      * @return false if the dialer refuses the network record, otherwise true
      */
     bool init(const ShekylDaemonSnapshot& snapshot);

     /**
      * @brief clears the relay entry
      *
      * @return true
      */
     bool deinit();

     /**
      * @brief set the pointer to the cryptonote protocol object to use
      *
      * @param pprotocol the pointer to set ours as
      */
     void set_cryptonote_protocol(i_cryptonote_protocol* pprotocol);

     /**
      * @copydoc pool::have_tx
      *
      * @note see pool::have_tx
      */
     bool pool_has_tx(const crypto::hash &txid) const override;

     /**
      * @brief gets the core synchronization status
      *
      * @return core synchronization status
      */
     bool is_synchronized() const final;

     /**
      * @brief gets start_time
      *
      */
     std::time_t get_start_time() const;

     /**
      * @brief the handler's stop hook; the one stop path is the entry's (DX-Q6)
      */
     void stop();

     /**
      * @brief get the network type we're on
      *
      * @return which network are we on?
      */     
     network_type get_nettype() const { return m_nettype; };

     /**
      * @brief returns the set of transactions in the txpool which are not in the argument
      *
      * @param hashes hashes of transactions to exclude from the result
      *
      * @return true iff success, false otherwise
      */
     bool get_txpool_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes);

   private:

     i_cryptonote_protocol* m_pprotocol; //!< cryptonote protocol instance

     cryptonote_protocol_stub m_protocol_stub; //!< cryptonote protocol stub instance

     network_type m_nettype; //!< which network are we on?

     time_t start_time;
   };
}

POP_WARNINGS

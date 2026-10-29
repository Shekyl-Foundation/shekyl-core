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
#include "cryptonote_core/tx_verification_utils.h"
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

enum { HAVE_BLOCK_MAIN_CHAIN, HAVE_BLOCK_ALT_CHAIN, HAVE_BLOCK_INVALID };

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

   /**
    * @brief the thin C++ shell over the Rust node
    *
    * One method per call the protocol handler, `levin_notify` and the
    * daemon's entry still make (`DRS_X_STORE_FLIP.md` DX-Q1); each forwards
    * to a `shekyl_core_*` / `shekyl_pool_*` export or holds the handler's
    * own sync state. The chain and the pool are the Rust store's.
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
     * @copydoc Blockchain::handle_get_objects
     *
     * @note see Blockchain::handle_get_objects()
     * @param context connection context associated with the request
     */
     bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote_connection_context& context);

     /**
      * @brief calls various idle routines
      *
      * @note see miner::on_idle and pool::on_idle
      *
      * @return true
      */
     bool on_idle();

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
      * @brief handles a single incoming block
      *
      * Attempts to add the block to the Blockchain and, on success,
      * optionally updates the miner's block template.
      *
      * Unlike handle_incoming_block(), this call does not take the incoming
      * transaction lock around the add.
      *
      * @param block_blob the block to be added
      * @param block the block to be added, or NULL
      * @param bvc return-by-reference metadata context about the block's validity
      * @param extra_block_txs txs belonging to this block that may not be in the mempool
      * @param update_miner_blocktemplate whether or not to update the miner's block template
      *
      * @return false if the block is not added, otherwise true
      */
     bool handle_single_incoming_block(const blobdata& block_blob,
      const block *b,
      block_verification_context& bvc,
      block_connect_supplement& connect,
      bool update_miner_blocktemplate = true);

     /**
      * @brief handles an incoming block as part of a batch
      *
      * Attempts to add the block to the Blockchain and, on success,
      * optionally updates the miner's block template.
      *
      * @param block_blob the block to be added
      * @param block the block to be added, or NULL
      * @param bvc return-by-reference metadata context about the block's validity
      * @param extra_block_txs txs belonging to this block that may not be in the mempool
      * @param update_miner_blocktemplate whether or not to update the miner's block template
      *
      * @return false if the block is not added, otherwise true
      */
     bool handle_incoming_block(const blobdata& block_blob, const block *b,
       block_verification_context& bvc,
       bool update_miner_blocktemplate = true);

     bool handle_incoming_block(const blobdata& block_blob, const block *b,
       block_verification_context& bvc, block_connect_supplement& connect,
       bool update_miner_blocktemplate = true);

     /**
      * @brief check the size of a block against the current maximum
      *
      * @param block_blob the block to check
      *
      * @return whether or not the block is too big
      */
     bool check_incoming_block_size(const blobdata& block_blob) const;

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

     //! Hand the stem watch's propagation verdicts to the pool (F-10, §49).
     void on_stem_propagated(epee::span<const crypto::hash> txids) final;


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
      * @copydoc Blockchain::get_current_blockchain_height
      *
      * @note see Blockchain::get_current_blockchain_height()
      */
     uint64_t get_current_blockchain_height() const final;

     /**
      * @brief get the hash and height of the most recent block
      *
      * @param height return-by-reference height of the block
      * @param top_id return-by-reference hash of the block
      */
     void get_blockchain_top(uint64_t& height, crypto::hash& top_id) const;

     /**
      * @copydoc Blockchain::get_block_id_by_height
      *
      * @note see Blockchain::get_block_id_by_height
      */
     crypto::hash get_block_id_by_height(uint64_t height) const;

     /**
      * @copydoc Blockchain::get_transactions
      *
      * @note see Blockchain::get_transactions
      */
     bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned = false) const;

     /**
      * @copydoc Blockchain::get_transactions
      *
      * @note see Blockchain::get_transactions
      */
     bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<transaction>& txs, std::vector<crypto::hash>& missed_txs, bool pruned = false) const;

     /**
      * @copydoc Blockchain::get_block_by_hash
      *
      * @note see Blockchain::get_block_by_hash
      */
     bool get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan = NULL) const;

     /**
      * @copydoc Blockchain::get_block_attestation_witness
      *
      * @note see Blockchain::get_block_attestation_witness
      */
     blobdata get_block_attestation_witness(const block &blk) const;

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
      * @copydoc pool::get_transactions
      * @param include_sensitive_txes include private transactions
      *
      * @note see pool::get_transactions
      */
     bool get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_txes = false) const;

     /**
      * @copydoc Blockchain::have_block
      *
      * @note see Blockchain::have_block
      */
     bool have_block_unlocked(const crypto::hash& id, int *where = NULL) const;
     bool have_block(const crypto::hash& id, int *where = NULL) const;

     /**
      * @copydoc Blockchain::get_short_chain_history
      *
      * @note see Blockchain::get_short_chain_history
      */
     bool get_short_chain_history(std::list<crypto::hash>& ids, uint64_t& current_height) const;

     /**
      * @copydoc Blockchain::find_blockchain_supplement(const std::list<crypto::hash>&, NOTIFY_RESPONSE_CHAIN_ENTRY::request&) const
      *
      * @note see Blockchain::find_blockchain_supplement(const std::list<crypto::hash>&, NOTIFY_RESPONSE_CHAIN_ENTRY::request&) const
      */
     bool find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const;

     /**
      * @copydoc Blockchain::get_block_cumulative_difficulty
      *
      * @note see Blockchain::get_block_cumulative_difficulty
      */
     difficulty_type get_block_cumulative_difficulty(uint64_t height) const;

     /**
      * @brief gets the core synchronization status
      *
      * @return core synchronization status
      */
     bool is_synchronized() const final;

     /**
      * @copydoc miner::on_synchronized
      *
      * @note see miner::on_synchronized
      */
     void on_synchronized();

     /**
      * @brief sets the target blockchain height
      *
      * @param target_blockchain_height the height to set
      */
     void set_target_blockchain_height(uint64_t target_blockchain_height);

     /**
      * @brief gets the target blockchain height
      *
      * @param target_blockchain_height the target height
      */
     uint64_t get_target_blockchain_height() const;

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
      * @brief get the number of blocks to sync in one go
      *
      * @return the number of blocks to sync in one go
      */
     size_t get_block_sync_size(uint64_t height) const;

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

     epee::critical_section m_incoming_tx_lock; //!< incoming transaction lock

     cryptonote_protocol_stub m_protocol_stub; //!< cryptonote protocol stub instance

     uint64_t m_target_blockchain_height; //!< blockchain height target

     network_type m_nettype; //!< which network are we on?

     size_t block_sync_size;

     time_t start_time;
   };
}

POP_WARNINGS

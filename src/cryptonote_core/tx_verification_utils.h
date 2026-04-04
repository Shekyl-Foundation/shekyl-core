// Copyright (c) 2023, The Monero Project
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

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/verification_context.h"

namespace cryptonote
{

/**
 * @brief Get the maximum transaction weight for a given hardfork
 *
 * @param hf_version hard fork version
 * @return the maximum unconditional transaction weight
 */
uint64_t get_transaction_weight_limit(uint8_t hf_version);

/**
 * @brief Verify the semantics of a group of FCMP++ signatures as a batch (if applicable)
 *
 * Coinbase txs or other transaction with an RCT type of RCTTypeNull will fail to verify.
 *
 * @param rvv list of signatures to verify
 * @return true if all signatures verified semantics successfully, false otherwise
 */
bool ver_mixed_rct_semantics(std::vector<const rct::rctSig*> rvv);

/**
 * @brief Used to provide transaction info that skips the mempool to block handling code 
 */
struct pool_supplement
{
    // Map of supplemental tx info that we might need to validate a block
    // Maps TXID -> transaction and blob
    std::unordered_map<crypto::hash, std::pair<transaction, blobdata>> txs_by_txid;
    // If non-zero, then consider all the txs' non-input consensus (NIC) rules verified for this
    // hard fork. User: If you add an unverified transaction to txs_by_txid, set this field to zero!
    mutable std::uint8_t nic_verified_hf_version = 0;
};

/**
 * @brief Verify every non-input consensus rule for a group of non-coinbase transactions
 *
 * List of checks that we do for each transaction:
 *     1. Check tx blob size < get_max_tx_size()
 *     2. Check tx version != 0
 *     3. Check tx version is less than maximum for given hard fork version
 *     4. Check tx weight < get_transaction_weight_limit()
 *     5. Passes core::check_tx_semantic()
 *     6. Passes Blockchain::check_tx_outputs()
 *     7. Passes ver_mixed_rct_semantics() [Uses batch FCMP++ verification when applicable]
 *
 * For pool_supplement input:
 * We assume the structure of the pool supplement is already correct: for each value entry, the
 * cryptonote::transaction matches its corresponding blobdata and the TXID map key is correctly
 * calculated for that transaction. We use the .nic_verified_hf_version field to skip verification
 * for the pool supplement if hf_version matches, and we cache that version on success.
 *
 * @param tx single transaction to verify
 * @param pool_supplement pool supplement to verify
 * @param tvc relevant flags will be set for if/why verification failed
 * @param hf_version Hard fork version to run rules against
 * @return true if all relevant transactions verify, false otherwise
 */
bool ver_non_input_consensus(const transaction& tx, tx_verification_context& tvc,
    std::uint8_t hf_version);

bool ver_non_input_consensus(const pool_supplement& ps, tx_verification_context& tvc,
    std::uint8_t hf_version);

} // namespace cryptonote

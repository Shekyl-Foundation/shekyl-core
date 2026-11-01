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

#include <unordered_map>
#include <utility>

#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_basic.h"

// What remains of the C++ transaction-verification helpers: the two types
// the shell's `handle_incoming_block` connect overload still names. The
// verification itself (`ver_non_input_consensus`, `check_tx_semantic`, the
// PQC auth battery) was deleted with the C++ chain; the Rust owner is
// `shekyl-chain-rules` (DRS-X). CS-5 deletes this header with the overload.

namespace cryptonote
{

/**
 * @brief Transaction info that skips the mempool on the way to block handling.
 *
 * Tx-only. Block-level admission data rides [`block_connect_supplement`].
 */
struct pool_supplement
{
    // Maps TXID -> transaction and blob
    std::unordered_map<crypto::hash, std::pair<transaction, blobdata>> txs_by_txid;
    // If set, all the txs' non-input consensus (NIC) rules are verified.
    mutable bool nic_verified = false;
};

/**
 * @brief Block-level data that rides the connect path alongside the block itself.
 */
struct block_connect_supplement
{
    pool_supplement pool;
    // Per-block credit-wire attestation witness (ARCHIVAL_CREDIT_WIRE.md §3).
    // Opaque Rust-canonical bytes; empty means "no witness supplied".
    blobdata attestation_witness;
};

} // namespace cryptonote

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

#include <cstdint>

#include "cryptonote_protocol/enums.h"

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct tx_verification_context
  {
    static_assert(unsigned(relay_method::none) == 0, "default m_relay initialization is not to relay_method::none");

    relay_method m_relay; // gives indication on how tx should be relayed (if at all)
    bool m_verifivation_failed; //bad tx, tx should not enter mempool. Whether the connection is ALSO dropped is m_drop_verdict's question, not this flag's
    // PWD-B7. Opaque SHEKYL_DROP_VERDICT_* byte. Write through classify_drop /
    // reject_*; read through shekyl_drop_verdict_severs /
    // shekyl_drop_verdict_is_internal_failure. Zero is Unclassified and does
    // not sever (shekyl-peer-policy).
    uint8_t m_drop_verdict = 0;
    bool m_verifivation_impossible; //the transaction is related with an alternative blockchain
    bool m_added_to_pool; 
    bool m_double_spend;
    bool m_invalid_input;
    bool m_invalid_output;
    bool m_too_big;
    bool m_overspend;
    bool m_fee_too_low;
    bool m_too_few_outputs;
    bool m_tx_extra_too_big;
    bool m_nonzero_unlock_time;
  };

  struct block_verification_context
  {
    // Opaque SHEKYL_BLOCK_INGEST_* byte. Write non-reject arms through
    // record_block_ingest; rejections through reject_block_* (Rust pairs
    // the drop slot). P2P asks block_announce_action / block_sync_action,
    // not these bytes. Zero is Unclassified: not added, not rejected.
    uint8_t m_outcome = 0;
    // PWD-B7. Opaque SHEKYL_DROP_VERDICT_* byte. Write through reject_block_*
    // (paired) or classify_drop. Zero does not sever.
    uint8_t m_drop_verdict = 0;
  };
}

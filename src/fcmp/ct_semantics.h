// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

//#define DBG

#ifndef CT_SEMANTICS_H
#define CT_SEMANTICS_H

#include <cstddef>
#include <vector>
#include <tuple>

#include "crypto/generic-ops.h"

extern "C" {
#include "crypto/random.h"
#include "crypto/keccak.h"
}
#include "crypto/crypto.h"


#include "ct_types.h"
#include "ct_ops.h"

//Define this flag when debugging to get additional info on the console
#ifdef DBG
#define DP(x) dp(x)
#else
#define DP(x)
#endif

namespace hw {
    class device;
}


namespace ct {

    /** Dummy BP+, pseudo-outs, and ECDH so construct_tx can serialize/hash; wallet replaces via shekyl_sign_fcmp_transaction. */
    void fill_construct_tx_rct_stub(CtSig &rv, const key &message, xmr_amount txnFee,
        const crypto::hash &referenceBlock, const std::vector<xmr_amount> &inamounts,
        const std::vector<xmr_amount> &outamounts, const keyV &destinations);
    bool verCtSemanticsSimple(const CtSig & rv);
    bool verCtSemanticsSimple(const std::vector<const CtSig*> & rv);
    // Fee-only RCT (empty FCMP++ proof and pseudo-outs); used by archival serve-credit.
    bool verCtSemanticsFeeOnly(const CtSig &rv);
    // Bond-post CT balance: sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit
    // (gate-4 ARCHIVAL_BOND_GATE4.md section 3.2).
    bool verCtSemanticsBondPost(const CtSig &rv, uint64_t bond_credit, uint64_t bond_debit);
    // Archival emission CT balance: sum(pseudoOuts) + total_reward = sum(out masks) + fee —
    // the mint enters on the input side (the debit slot of the shared balance FFI). Fee
    // inputs are optional: the FCMP++ proof is present iff fee_input_count > 0
    // (REWARD_EMISSION_E3_GATING_ROUND.md §9.5 item 4).
    bool verCtSemanticsEmission(const CtSig &rv, uint64_t total_reward, size_t fee_input_count);
    key get_tx_prehash(const CtSig &rv, hw::device &hwdev);
}
#endif  /* CT_SEMANTICS_H */


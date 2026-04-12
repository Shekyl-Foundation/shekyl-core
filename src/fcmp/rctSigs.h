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

#ifndef RCTSIGS_H
#define RCTSIGS_H

#include <cstddef>
#include <vector>
#include <tuple>

#include "crypto/generic-ops.h"

extern "C" {
#include "crypto/random.h"
#include "crypto/keccak.h"
}
#include "crypto/crypto.h"


#include "rctTypes.h"
#include "rctOps.h"

//Define this flag when debugging to get additional info on the console
#ifdef DBG
#define DP(x) dp(x)
#else
#define DP(x)
#endif

namespace hw {
    class device;
}


namespace rct {

    // Per-output data in a leaf chunk (compressed Ed25519 points + PQC hash).
    struct fcmp_chunk_entry {
        key output_key;    // O
        key key_image_gen; // I = Hp(O)
        key commitment;    // C
        key h_pqc;         // H(pqc_pk)
    };

    // DEPRECATED: Production wallet code now uses shekyl_sign_fcmp_transaction (Rust FFI).
    // Retained only for core_tests/chaingen.cpp test infrastructure until that is migrated.
    // TODO(PR-wallet): migrate chaingen.cpp to shekyl_sign_fcmp_transaction and delete this.
    rctSig genRctFcmpPlusPlus(const key &message, const ctkeyV &inSk, const ctkeyV &inPk,
                               const keyV &destinations, const std::vector<xmr_amount> &inamounts,
                               const std::vector<xmr_amount> &outamounts,
                               const keyV &commitment_masks,
                               const std::vector<std::array<uint8_t, 9>> &enc_amounts_precomputed,
                               const keyV &spend_key_y,
                               xmr_amount txnFee, const crypto::hash &referenceBlock,
                               const key &tree_root, uint8_t tree_depth,
                               const std::vector<std::vector<uint8_t>> &tree_paths,
                               const std::vector<std::vector<fcmp_chunk_entry>> &leaf_chunk_entries,
                               const std::vector<key> &pqc_pk_hashes, hw::device &hwdev);

    /** Dummy BP+, pseudo-outs, and ECDH so construct_tx can serialize/hash; wallet replaces via shekyl_sign_fcmp_transaction. */
    void fill_construct_tx_rct_stub(rctSig &rv, const key &message, xmr_amount txnFee,
        const crypto::hash &referenceBlock, const std::vector<xmr_amount> &inamounts,
        const std::vector<xmr_amount> &outamounts, const keyV &destinations);
    bool verRctSemanticsSimple(const rctSig & rv);
    bool verRctSemanticsSimple(const std::vector<const rctSig*> & rv);
    key get_tx_prehash(const rctSig &rv, hw::device &hwdev);
}
#endif  /* RCTSIGS_H */


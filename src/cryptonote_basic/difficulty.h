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

// TODO(shekyl-v4): Evaluate replacing boost::multiprecision::uint128_t with
// compiler __uint128_t or a lightweight 128-bit integer library. The difficulty
// type is used pervasively in consensus-critical arithmetic.
#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <boost/multiprecision/cpp_int.hpp>
#include "crypto/hash.h"

namespace cryptonote
{
    typedef boost::multiprecision::uint128_t difficulty_type;

    /**
     * @brief checks if a hash fits the given difficulty
     *
     * The hash passes if (hash * difficulty) < 2^256.
     * Phrased differently, if (hash * difficulty) fits without overflow into
     * the least significant 256 bits of the 320 bit multiplication result.
     *
     * @param hash the hash to check
     * @param difficulty the difficulty to check against
     *
     * @return true if valid, else false
     */
    bool check_hash_64(const crypto::hash &hash, uint64_t difficulty);

    bool check_hash_128(const crypto::hash &hash, difficulty_type difficulty);
    bool check_hash(const crypto::hash &hash, difficulty_type difficulty);

    // Difficulty-adjustment selection: LWMA-1 is the canonical
    // post-genesis DAA. The inherited CryptoNote cut-windowed-average
    // `next_difficulty` and `next_difficulty_64` were deleted in Phase 4
    // of the LWMA-1 migration (`docs/design/DAA_LWMA1.md` §9.1, drift
    // F6 in `docs/design/DAA_LWMA1_PHASE4_PREFLIGHT.md` §2). Consumers
    // call `shekyl_difficulty_lwma1_next` via two pieces that live
    // together but distinctly:
    //
    //   * The `lwma1_next_difficulty` helper defined in the anonymous
    //     namespace of `src/cryptonote_core/blockchain.cpp` builds the
    //     FFI argument arrays and dispatches the call.
    //   * Non-zero FFI return codes are translated into the
    //     `cryptonote::difficulty_computation_error` exception declared
    //     in `src/cryptonote_core/difficulty_engine_error.h`.
    //
    // No DAA helper lives in this header any more; the only inhabitants
    // are the `check_hash*` PoW predicates and the `hex` formatter,
    // both of which are language-mechanical utilities orthogonal to
    // the algorithm choice.

    std::string hex(difficulty_type v);
}

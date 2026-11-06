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

#include "include_base_utils.h"
using namespace epee;

#include <stdexcept>

#include "cryptonote_basic_impl.h"
#include "string_tools.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"
#include "crypto/hash.h"
#include "int-util.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "cn"

namespace cryptonote {

  const crypto::hash& empty_attestation_root()
  {
    // Once-per-process: Rust owns the cSHAKE derivation (rule 20). Fail closed
    // if the FFI cannot produce the empty-set root — a header must never fall
    // back to null_hash for "empty".
    static const crypto::hash h = [] {
      crypto::hash out{};
      if (!shekyl_attestation_root_empty(reinterpret_cast<uint8_t*>(&out)))
        throw std::runtime_error("shekyl_attestation_root_empty failed");
      return out;
    }();
    return h;
  }

  /************************************************************************/
  /* Cryptonote helper functions                                          */
  /************************************************************************/
  //-----------------------------------------------------------------------------------------------
  size_t get_min_block_weight()
  {
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  }
  //-----------------------------------------------------------------------------------------------
  size_t get_max_tx_size()
  {
    return CRYPTONOTE_MAX_TX_SIZE;
  }
  //-----------------------------------------------------------------------------------------------
  bool get_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, uint64_t &reward) {
    // The M_r-NEUTRAL view: baseline volume pins the release multiplier at
    // exactly 1, so this equals the pre-FL-R12' unmodulated reward
    // bit-for-bit for every state at or below the emission-curve asymptote.
    // Production consumers are the fee/relay floors that must not track
    // demand (CEN-M3's held machinery); everything reward-paying calls the
    // volume-aware overload below.
    return get_block_reward(median_weight, current_block_weight, already_generated_coins, reward, shekyl::tx_volume_window{SHEKYL_TX_VOLUME_BASELINE, 1});
  }
  //-----------------------------------------------------------------------------------------------
  bool get_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, uint64_t &reward, shekyl::tx_volume_window tx_volume)
  {
    // Marshaling shim for THE one owner of the paid reward
    // (shekyl-economics `paid_block_reward`, FL-R12' signed composition):
    //
    //   paid = max(M_r * curve(remaining), TAIL) * penalty(x)
    //
    // The ordering is the ruling's most easily lost detail, so it is
    // stated here from the DESIGN, not the code: the release multiplier
    // applies to the CURVE (at a perpetual tail there is nothing to pace,
    // so the floor is not modulated — a multiplied floor would pay least
    // exactly when fees are lowest), and the weight penalty applies to the
    // PAID quantity, after the floor (floors belong to emission; penalties
    // apply to the paid quantity — a penalty composed before the floor
    // would be dead at the tail permanently, and there is no post-tail
    // era). Reversing either pair still compiles and still passes most
    // tests; the terminal_reward_legs_agree oracle and the FFI marshal
    // pins are what go red.
    //
    // There is no C++-side multiplier, supply cap, or flag path any more:
    // the former SHEKYL_TX_VOLUME_BASELINE > 0 gate silently flipped
    // terminal emission policy from a pacing knob (FL-V9) and the retired
    // cap encoded the losing side of FL-V8's twin clamps. C++ computes
    // nothing here.
    //
    // Values are pinned across the boundary by the 81-vector KAT asserted
    // from BOTH languages (M_r-neutral vectors, unchanged by FL-R12') and
    // the signed-composition marshal pins (M_r != 1 and both tail
    // boundaries).
    uint64_t computed = 0;
    uint64_t weight_limit = 0;
    const int32_t status = shekyl_block_reward(
        median_weight,
        current_block_weight,
        already_generated_coins,
        tx_volume.tx_count_sum,
        tx_volume.blocks,
        &computed,
        &weight_limit);

    if (status == SHEKYL_BLOCK_REWARD_BLOCK_TOO_BIG)
    {
      // weight_limit is the doubled EFFECTIVE median, written by the same call
      // that made the rejection — the message cannot disagree with the
      // decision, which a locally recomputed clamp could.
      //
      // "at most", not the inherited "less than": the limit is INCLUSIVE.
      // A block at exactly 2*median is accepted and earns a zero reward
      // (pinned by the 2m rows of the weight-penalty KAT); only above it is
      // rejected. The old wording named a bound one byte off from the rule it
      // described, which is a bad thing for an operator to read while
      // debugging a rejected block.
      MERROR("Block cumulative weight is too big: " << current_block_weight << ", expected at most " << weight_limit);
      return false;
    }

    if (status != SHEKYL_BLOCK_REWARD_OK)
    {
      MERROR("shekyl_block_reward rejected its arguments (status " << status << ")");
      return false;
    }

    reward = computed;
    return true;
  }
  //-----------------------------------------------------------------------
  bool is_coinbase(const transaction& tx)
  {
    if(tx.vin.size() != 1)
      return false;

    if(!std::holds_alternative<txin_gen>(tx.vin[0]))
      return false;

    return true;
  }
  //--------------------------------------------------------------------------------
  bool operator ==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
  }

  bool operator ==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
  }
}

//--------------------------------------------------------------------------------
bool parse_hash256(const std::string &str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != sizeof(crypto::hash))
  {
    MERROR("invalid hash format: " << str_hash);
    return false;
  }
  else
  {
    buf.copy(reinterpret_cast<char *>(&hash), sizeof(crypto::hash));
    return true;
  }
}

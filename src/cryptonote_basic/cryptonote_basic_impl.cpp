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

  static uint8_t nettype_to_ffi_network(network_type nettype)
  {
    switch (nettype)
    {
      case MAINNET: case FAKECHAIN: return 0;
      case TESTNET:  return 1;
      case STAGENET: return 2;
      default:       return 0;
    }
  }

  /************************************************************************/
  /* Cryptonote helper functions                                          */
  /************************************************************************/
  //-----------------------------------------------------------------------------------------------
  size_t get_min_block_weight(uint8_t /* version */)
  {
    // Shekyl activates all hard-fork features from genesis (HF1).
    // The legacy Monero version ladder (ZONE_V1, ZONE_V2) is unused.
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  }
  //-----------------------------------------------------------------------------------------------
  size_t get_max_tx_size()
  {
    return CRYPTONOTE_MAX_TX_SIZE;
  }
  //-----------------------------------------------------------------------------------------------
  bool get_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, uint64_t &reward, uint8_t version) {
    // Marshaling shim. The base subsidy curve, the "make it soft" median
    // clamp, the 2*median rejection and the 128-bit weight-penalty arithmetic
    // are all canonical in `shekyl-economics` and reached through
    // `shekyl_block_reward` (STAGE_1_PR_7 §5.8, C2c cutover). Nothing is
    // computed here.
    //
    // The penalty was the last economics ARITHMETIC C++ performed itself —
    // `mul128` plus two `div128_64` on an amount, which is rule 20's "integer
    // arithmetic on amounts" category verbatim. Its values are pinned across
    // the boundary by the 81-vector KAT asserted from BOTH languages
    // (EconomicsC2aPrime.Layer1WeightPenaltyPinnedVectors and
    // shekyl-economics' c2a_prime_layer1_weight_penalty_pinned_vectors).
    //
    // `get_min_block_weight` stays on this side and crosses as an argument:
    // CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 is a block-policy constant
    // with ~40 C++ consumers and no Rust consumer, so copying it into a Rust
    // constant would manufacture the C++/Rust drift pair that
    // config/consensus_constants.json exists to prevent.
    uint64_t computed = 0;
    uint64_t weight_limit = 0;
    const int32_t status = shekyl_block_reward(
        median_weight,
        current_block_weight,
        already_generated_coins,
        get_min_block_weight(version),
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
  //-----------------------------------------------------------------------------------------------
  bool get_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, uint64_t &reward, uint8_t version, uint64_t tx_volume_avg)
  {
    if (!get_block_reward(median_weight, current_block_weight, already_generated_coins, reward, version))
      return false;

    if (SHEKYL_TX_VOLUME_BASELINE > 0)
    {
      uint64_t multiplier = shekyl_calc_release_multiplier(
          tx_volume_avg, SHEKYL_TX_VOLUME_BASELINE, SHEKYL_RELEASE_MIN, SHEKYL_RELEASE_MAX);
      reward = shekyl_apply_release_multiplier(reward, multiplier);

      uint64_t remaining = MONEY_SUPPLY - already_generated_coins;
      if (reward > remaining)
        reward = remaining;
    }

    return true;
  }
  //------------------------------------------------------------------------------------
  std::string get_account_address_as_str(
      network_type nettype
    , bool /* subaddress -- ignored, Shekyl uses standard addresses only */
    , account_public_address const & adr
    )
  {
    // Struct-only re-encode is gone: `account_public_address` does not
    // carry `msg_sign_pk`, and we will not thicken the C++ struct to
    // hold a field the Rust address crate owns (rule 20). Live daemon
    // paths retain the caller's original encoded string (miner
    // start/status). Wallet-owned encode of *this* account is
    // `account_base::get_public_address_str` (blob-derived pk, same
    // `shekyl_address_encode` the mining RPC/FFI already call). Remaining
    // wallet2 display callers that only have a destination struct are
    // the Phase-5 deletion surface — they get an empty string, not a
    // theatrical FFI call that cannot succeed.
    (void)nettype;
    (void)adr;
    LOG_PRINT_L0("get_account_address_as_str: cannot encode from account_public_address (no msg_sign_pk); pass the original address string");
    return {};
  }
  //-----------------------------------------------------------------------
  // Shekyl has no integrated (payment-id) addresses; this is a compatibility
  // alias — prefer get_account_address_as_str for new code.
  std::string get_account_integrated_address_as_str(
      network_type nettype
    , account_public_address const & adr
    , crypto::hash8 const & /* payment_id -- ignored, Shekyl has no integrated addresses */
    )
  {
    return get_account_address_as_str(nettype, false, adr);
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
  //-----------------------------------------------------------------------
  bool get_account_address_from_str(
      address_parse_info& info
    , network_type nettype
    , std::string const & str
    )
  {
    uint8_t network_out = 0;
    uint8_t spend_key[32] = {};
    uint8_t view_key[32] = {};

    ShekylBuffer ml_kem_buf = shekyl_address_decode(
        str.c_str(), &network_out, spend_key, view_key);

    if (ml_kem_buf.ptr == nullptr)
    {
      LOG_PRINT_L2("Invalid Bech32m address format");
      return false;
    }

    uint8_t expected_net = nettype_to_ffi_network(nettype);
    if (network_out != expected_net)
    {
      LOG_PRINT_L1("Address network mismatch: address belongs to network "
          << (int)network_out << ", expected " << (int)expected_net);
      if (ml_kem_buf.len > 0)
        shekyl_buffer_free(ml_kem_buf.ptr, ml_kem_buf.len);
      return false;
    }

    memcpy(&info.address.m_spend_public_key, spend_key, 32);
    memcpy(&info.address.m_view_public_key, view_key, 32);

    if (ml_kem_buf.len > 0)
    {
      // Derive X25519 public key from Ed25519 view key via Edwards→Montgomery map.
      // m_pqc_public_key layout: X25519_pub[32] || ML-KEM_ek[1184] = 1216 bytes.
      // Canonical assembler: this function. See account_public_address field comment.
      uint8_t x25519_pk[32];
      if (!shekyl_view_pub_to_x25519_pub(
              reinterpret_cast<const uint8_t*>(&info.address.m_view_public_key), x25519_pk))
      {
        LOG_PRINT_L1("Failed to derive X25519 public key from view key");
        shekyl_buffer_free(ml_kem_buf.ptr, ml_kem_buf.len);
        return false;
      }

      info.address.m_pqc_public_key.clear();
      info.address.m_pqc_public_key.reserve(SHEKYL_X25519_PK_BYTES + ml_kem_buf.len);
      info.address.m_pqc_public_key.insert(
          info.address.m_pqc_public_key.end(), x25519_pk, x25519_pk + SHEKYL_X25519_PK_BYTES);
      info.address.m_pqc_public_key.insert(
          info.address.m_pqc_public_key.end(), ml_kem_buf.ptr, ml_kem_buf.ptr + ml_kem_buf.len);
      shekyl_buffer_free(ml_kem_buf.ptr, ml_kem_buf.len);

      CHECK_AND_ASSERT_MES(info.address.m_pqc_public_key.size() == SHEKYL_PQC_PUBLIC_KEY_BYTES,
        false, "m_pqc_public_key assembly error: expected " << SHEKYL_PQC_PUBLIC_KEY_BYTES
        << " bytes, got " << info.address.m_pqc_public_key.size());

      // Post-assembly tripwire. Delegates to the authoritative Rust check
      // (X25519 prefix is the Edwards→Montgomery image of view_pub; ML-KEM
      // suffix is a well-formed FIPS-203 encapsulation key). If this fails
      // the decoded bytes look syntactically valid but the triple is not a
      // legal canonical address, so we must not hand it to the wallet.
      //
      // Argument order: pqc_public_key (1216 B) first, view_pub (32 B)
      // second — matches the Rust definition. The original landing of this
      // call site (commit 0092a8da1) had the order reversed, which let
      // every decode trip the FIPS-203 well-formedness check on garbage
      // bytes; the 14 `uri.*` regressions were the symptom.
      if (!shekyl_account_public_address_check(
              info.address.m_pqc_public_key.data(),
              reinterpret_cast<const uint8_t*>(&info.address.m_view_public_key)))
      {
        LOG_PRINT_L1("Address failed v1 canonical invariant check (view_pub ↔ "
                     "X25519 prefix or malformed ML-KEM-768 encapsulation key)");
        return false;
      }
    }
    else
    {
      info.address.m_pqc_public_key.clear();
    }

    info.is_subaddress = false;
    info.has_payment_id = false;
    memset(&info.payment_id, 0, sizeof(info.payment_id));

    if (!crypto::check_key(info.address.m_spend_public_key) ||
        !crypto::check_key(info.address.m_view_public_key))
    {
      LOG_PRINT_L1("Failed to validate address keys");
      return false;
    }

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

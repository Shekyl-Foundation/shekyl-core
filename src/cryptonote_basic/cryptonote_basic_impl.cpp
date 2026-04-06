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

#include "cryptonote_basic_impl.h"
#include "string_tools.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "shekyl/shekyl_ffi.h"
#include "crypto/hash.h"
#include "int-util.h"
#include "common/dns_utils.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

namespace cryptonote {

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
    static_assert(DIFFICULTY_TARGET_V2%60==0,"difficulty target must be a multiple of 60");
    const int target = DIFFICULTY_TARGET_V2;
    const int target_minutes = target / 60;
    const int emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes-1);

    uint64_t base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor;
    if (base_reward < FINAL_SUBSIDY_PER_MINUTE*target_minutes)
    {
      base_reward = FINAL_SUBSIDY_PER_MINUTE*target_minutes;
    }

    uint64_t full_reward_zone = get_min_block_weight(version);

    //make it soft
    if (median_weight < full_reward_zone) {
      median_weight = full_reward_zone;
    }

    if (current_block_weight <= median_weight) {
      reward = base_reward;
      return true;
    }

    if(current_block_weight > 2 * median_weight) {
      MERROR("Block cumulative weight is too big: " << current_block_weight << ", expected less than " << 2 * median_weight);
      return false;
    }

    uint64_t product_hi;
    // BUGFIX: 32-bit saturation bug (e.g. ARM7), the result was being
    // treated as 32-bit by default.
    uint64_t multiplicand = 2 * median_weight - current_block_weight;
    multiplicand *= current_block_weight;
    uint64_t product_lo = mul128(base_reward, multiplicand, &product_hi);

    uint64_t reward_hi;
    uint64_t reward_lo;
    div128_64(product_hi, product_lo, median_weight, &reward_hi, &reward_lo, NULL, NULL);
    div128_64(reward_hi, reward_lo, median_weight, &reward_hi, &reward_lo, NULL, NULL);
    assert(0 == reward_hi);
    assert(reward_lo < base_reward);

    reward = reward_lo;
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
    uint8_t net = nettype_to_ffi_network(nettype);
    ShekylBuffer buf = shekyl_address_encode(
        net,
        reinterpret_cast<const uint8_t*>(adr.m_spend_public_key.data),
        reinterpret_cast<const uint8_t*>(adr.m_view_public_key.data),
        adr.m_pqc_public_key.data(),
        adr.m_pqc_public_key.size());
    if (!buf.ptr || buf.len == 0)
      return {};
    std::string result(reinterpret_cast<const char*>(buf.ptr), buf.len);
    shekyl_buffer_free(buf.ptr, buf.len);
    return result;
  }
  //-----------------------------------------------------------------------
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
      info.address.m_pqc_public_key.assign(
          ml_kem_buf.ptr, ml_kem_buf.ptr + ml_kem_buf.len);
      shekyl_buffer_free(ml_kem_buf.ptr, ml_kem_buf.len);
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
  bool get_account_address_from_str_or_url(
      address_parse_info& info
    , network_type nettype
    , const std::string& str_or_url
    , std::function<std::string(const std::string&, const std::vector<std::string>&, bool)> dns_confirm
    )
  {
    if (get_account_address_from_str(info, nettype, str_or_url))
      return true;
    bool dnssec_valid;
    std::string address_str = tools::dns_utils::get_account_address_as_str_from_url(str_or_url, dnssec_valid, dns_confirm);
    return !address_str.empty() &&
      get_account_address_from_str(info, nettype, address_str);
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

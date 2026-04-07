// Copyright (c) 2025-2026, The Shekyl Foundation
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
#include "chaingen.h"
#include "shekyl/shekyl_ffi.h"

// ====================================================================
// Base class with common callbacks for staking tests
// ====================================================================
class staking_test_base : public test_chain_unit_base
{
public:
  staking_test_base()
    : m_invalid_tx_index(0)
    , m_invalid_block_index(0)
  {
    REGISTER_CALLBACK_METHOD(staking_test_base, mark_invalid_tx);
    REGISTER_CALLBACK_METHOD(staking_test_base, mark_invalid_block);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_staking_output_in_chain);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_validation_basics);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_bad_range_inverted);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_bad_range_too_large);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_future_height);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_wrong_watermark);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_wrong_amount);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_on_non_staked_output);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_claim_output_not_in_tree);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_pool_balance_on_rollback);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_watermark_on_rollback);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_double_claim_key_image);
    REGISTER_CALLBACK_METHOD(staking_test_base, check_mempool_claim_key_image);
  }

  bool check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool tx_added, size_t event_idx, const cryptonote::transaction& /*tx*/)
  {
    if (m_invalid_tx_index == event_idx)
      return tvc.m_verifivation_failed;
    else
      return !tvc.m_verifivation_failed && tx_added;
  }

  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*block*/)
  {
    if (m_invalid_block_index == event_idx)
      return bvc.m_verifivation_failed;
    else
      return !bvc.m_verifivation_failed;
  }

  bool mark_invalid_block(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
  {
    m_invalid_block_index = ev_index + 1;
    return true;
  }

  bool mark_invalid_tx(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
  {
    m_invalid_tx_index = ev_index + 1;
    return true;
  }

  // Callback: verify a staked output exists in the chain
  bool check_staking_output_in_chain(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);

  // Callback: basic claim validation checks on the blockchain directly
  bool check_claim_validation_basics(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_bad_range_inverted(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_bad_range_too_large(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_future_height(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_wrong_watermark(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_wrong_amount(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_on_non_staked_output(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_claim_output_not_in_tree(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_pool_balance_on_rollback(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_watermark_on_rollback(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_double_claim_key_image(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_mempool_claim_key_image(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);

protected:
  size_t m_invalid_tx_index;
  size_t m_invalid_block_index;
};

// ====================================================================
// Helper: construct a tx with a staked output
// ====================================================================
bool construct_staked_tx(const std::vector<test_event_entry>& events,
                         cryptonote::transaction& tx,
                         const cryptonote::block& blk_head,
                         const cryptonote::account_base& from,
                         const cryptonote::account_base& to,
                         uint64_t amount,
                         uint8_t tier,
                         uint64_t lock_until);

// ====================================================================
// 2b. Happy path: full staking lifecycle
// ====================================================================
struct gen_staking_lifecycle : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// ====================================================================
// 2c. Invalid claim rejection
// ====================================================================
struct gen_claim_bad_range_inverted : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_bad_range_too_large : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_future_height : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_wrong_watermark : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_wrong_amount : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_on_non_staked_output : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_output_not_in_tree : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_exceeds_pool : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// ====================================================================
// 2d. Double-claim prevention
// ====================================================================
struct gen_claim_spent_key_image : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// ====================================================================
// 2e. Lock period enforcement
// ====================================================================
struct gen_staked_output_invalid_tier : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_staked_output_invalid_lock_until : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_staked_output_zero_lock : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// ====================================================================
// 2f. Reorg / Rollback correctness (callback-based)
// ====================================================================
struct gen_claim_rollback_restores_pool : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_claim_rollback_restores_watermark : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// ====================================================================
// 2g. Txpool / Mempool handling (callback-based)
// ====================================================================
struct gen_claim_mempool_key_image : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

// ====================================================================
// 2i. Adversarial / Edge cases
// ====================================================================
struct gen_claim_sorted_inputs : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_stake_all_tiers : public staking_test_base
{
  bool generate(std::vector<test_event_entry>& events) const;
};

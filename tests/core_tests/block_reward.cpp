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

#include "chaingen.h"
#include "block_reward.h"
#include "shekyl/economics.h"

using namespace epee;
using namespace cryptonote;

namespace
{
  bool construct_miner_tx_by_weight(transaction& miner_tx, uint64_t height, uint64_t already_generated_coins,
    const account_public_address& miner_address, std::vector<size_t>& block_weights, size_t target_tx_weight,
    size_t target_block_weight, uint64_t fee = 0)
  {
    if (!construct_miner_tx(height, misc_utils::median(block_weights), already_generated_coins, target_block_weight, fee, miner_address, miner_tx, blobdata(), 999, 1,
        /*tx_volume_avg=*/0, /*circulating_supply=*/already_generated_coins, /*stake_ratio=*/0, /*genesis_ng_height=*/0))
      return false;

    size_t current_weight = get_transaction_weight(miner_tx);
    size_t try_count = 0;
    while (target_tx_weight != current_weight)
    {
      ++try_count;
      if (10 < try_count)
        return false;

      if (target_tx_weight < current_weight)
      {
        size_t diff = current_weight - target_tx_weight;
        if (diff <= miner_tx.extra.size())
          miner_tx.extra.resize(miner_tx.extra.size() - diff);
        else
          return false;
      }
      else
      {
        size_t diff = target_tx_weight - current_weight;
        miner_tx.extra.resize(miner_tx.extra.size() + diff);
      }

      current_weight = get_transaction_weight(miner_tx);
    }

    return true;
  }

  bool construct_max_weight_block(test_generator& generator, block& blk, const block& blk_prev, const account_base& miner_account,
    size_t median_block_count = CRYPTONOTE_REWARD_BLOCKS_WINDOW)
  {
    std::vector<size_t> block_weights;
    generator.get_last_n_block_weights(block_weights, get_block_hash(blk_prev), median_block_count);

    size_t median = misc_utils::median(block_weights);
    median = std::max(median, static_cast<size_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1));

    transaction miner_tx;
    bool r = construct_miner_tx_by_weight(miner_tx, get_block_height(blk_prev) + 1, generator.get_already_generated_coins(blk_prev),
      miner_account.get_keys().m_account_address, block_weights, 2 * median, 2 * median);
    if (!r)
      return false;

    return generator.construct_block_manually(blk, blk_prev, miner_account, test_generator::bf_miner_tx, 0, 0, 0,
      crypto::hash(), 0, miner_tx);
  }

  bool rewind_blocks(std::vector<test_event_entry>& events, test_generator& generator, block& blk, const block& blk_prev,
    const account_base& miner_account, size_t block_count)
  {
    blk = blk_prev;
    for (size_t i = 0; i < block_count; ++i)
    {
      block blk_i;
      if (!construct_max_weight_block(generator, blk_i, blk, miner_account))
        return false;

      events.push_back(blk_i);
      blk = blk_i;
    }

    return true;
  }

  uint64_t get_tx_out_amount(const transaction& tx)
  {
    uint64_t amount = 0;
    for (auto& o : tx.vout)
      amount += o.amount;
    return amount;
  }
}

gen_block_reward::gen_block_reward()
  : m_invalid_block_index(0)
{
  REGISTER_CALLBACK_METHOD(gen_block_reward, mark_invalid_block);
  REGISTER_CALLBACK_METHOD(gen_block_reward, mark_checked_block);
  REGISTER_CALLBACK_METHOD(gen_block_reward, check_block_rewards);
}

bool gen_block_reward::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);
  DO_CALLBACK(events, "mark_checked_block");
  MAKE_ACCOUNT(events, bob_account);

  // Test: miner transactions without outputs (block reward == 0)
  block blk_0r;
  if (!rewind_blocks(events, generator, blk_0r, blk_0, miner_account, CRYPTONOTE_REWARD_BLOCKS_WINDOW))
    return false;

  // Test: block reward is calculated using median of the latest CRYPTONOTE_REWARD_BLOCKS_WINDOW blocks
  DO_CALLBACK(events, "mark_invalid_block");
  block blk_1_bad_1;
  if (!construct_max_weight_block(generator, blk_1_bad_1, blk_0r, miner_account, CRYPTONOTE_REWARD_BLOCKS_WINDOW + 1))
    return false;
  events.push_back(blk_1_bad_1);

  DO_CALLBACK(events, "mark_invalid_block");
  block blk_1_bad_2;
  if (!construct_max_weight_block(generator, blk_1_bad_2, blk_0r, miner_account, CRYPTONOTE_REWARD_BLOCKS_WINDOW - 1))
    return false;
  events.push_back(blk_1_bad_2);

  block blk_1;
  if (!construct_max_weight_block(generator, blk_1, blk_0r, miner_account))
    return false;
  events.push_back(blk_1);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner_account);
  DO_CALLBACK(events, "mark_checked_block");
  MAKE_NEXT_BLOCK(events, blk_3, blk_2, miner_account);
  DO_CALLBACK(events, "mark_checked_block");
  MAKE_NEXT_BLOCK(events, blk_4, blk_3, miner_account);
  DO_CALLBACK(events, "mark_checked_block");
  MAKE_NEXT_BLOCK(events, blk_5, blk_4, miner_account);
  DO_CALLBACK(events, "mark_checked_block");

  block blk_5r;
  if (!rewind_blocks(events, generator, blk_5r, blk_5, miner_account, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW))
    return false;

  // Test: fee increases block reward
  transaction tx_0(construct_tx_with_fee(events, blk_5, miner_account, bob_account, MK_COINS(1), 3 * TESTS_DEFAULT_FEE));
  MAKE_NEXT_BLOCK_TX1(events, blk_6, blk_5r, miner_account, tx_0);
  DO_CALLBACK(events, "mark_checked_block");

  // Test: fee from all block transactions increase block reward
  std::list<transaction> txs_0;
  txs_0.push_back(construct_tx_with_fee(events, blk_5, miner_account, bob_account, MK_COINS(1), 5 * TESTS_DEFAULT_FEE));
  txs_0.push_back(construct_tx_with_fee(events, blk_5, miner_account, bob_account, MK_COINS(1), 7 * TESTS_DEFAULT_FEE));
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_7, blk_6, miner_account, txs_0);
  DO_CALLBACK(events, "mark_checked_block");

  // Test: block reward == transactions fee
  {
    transaction tx_1 = construct_tx_with_fee(events, blk_5, miner_account, bob_account, MK_COINS(1), 11 * TESTS_DEFAULT_FEE);
    transaction tx_2 = construct_tx_with_fee(events, blk_5, miner_account, bob_account, MK_COINS(1), 13 * TESTS_DEFAULT_FEE);
    size_t txs_1_weight = get_transaction_weight(tx_1) + get_transaction_weight(tx_2);
    uint64_t txs_fee = get_tx_fee(tx_1) + get_tx_fee(tx_2);

    std::vector<size_t> block_weights;
    generator.get_last_n_block_weights(block_weights, get_block_hash(blk_7), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
    size_t median = misc_utils::median(block_weights);

    transaction miner_tx;
    bool r = construct_miner_tx_by_weight(miner_tx, get_block_height(blk_7) + 1, generator.get_already_generated_coins(blk_7),
      miner_account.get_keys().m_account_address, block_weights, 2 * median - txs_1_weight, 2 * median, txs_fee);
    if (!r)
      return false;

    std::vector<crypto::hash> txs_1_hashes;
    txs_1_hashes.push_back(get_transaction_hash(tx_1));
    txs_1_hashes.push_back(get_transaction_hash(tx_2));

    block blk_8;
    generator.construct_block_manually(blk_8, blk_7, miner_account, test_generator::bf_miner_tx | test_generator::bf_tx_hashes,
      0, 0, 0, crypto::hash(), 0, miner_tx, txs_1_hashes, txs_1_weight);

    events.push_back(blk_8);
    DO_CALLBACK(events, "mark_checked_block");
  }

  DO_CALLBACK(events, "check_block_rewards");

  return true;
}

bool gen_block_reward::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (m_invalid_block_index == event_idx)
  {
    m_invalid_block_index = 0;
    return bvc.m_verifivation_failed;
  }
  else
  {
    return !bvc.m_verifivation_failed;
  }
}

bool gen_block_reward::mark_invalid_block(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_invalid_block_index = ev_index + 1;
  return true;
}

bool gen_block_reward::mark_checked_block(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_checked_blocks_indices.push_back(ev_index - 1);
  return true;
}

bool gen_block_reward::check_block_rewards(cryptonote::core& /*c*/, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_reward::check_block_rewards");

  CHECK_TEST_CONDITION(m_checked_blocks_indices.size() == 8);

  // Verify genesis block (checked index 0) reward matches the Shekyl formula
  // Height 0, already_generated_coins = 0, fee = 0
  {
    static_assert(DIFFICULTY_TARGET_V2 % 60 == 0, "target must be a multiple of 60");
    const int target_minutes = DIFFICULTY_TARGET_V2 / 60;
    const int esf = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes - 1);

    uint64_t base_reward = MONEY_SUPPLY >> esf;
    if (base_reward < FINAL_SUBSIDY_PER_MINUTE * target_minutes)
      base_reward = FINAL_SUBSIDY_PER_MINUTE * target_minutes;

    uint64_t multiplier = shekyl_calc_release_multiplier(0, SHEKYL_TX_VOLUME_BASELINE, SHEKYL_RELEASE_MIN, SHEKYL_RELEASE_MAX);
    base_reward = shekyl_apply_release_multiplier(base_reward, multiplier);

    shekyl::EmissionSplit em = shekyl::compute_emission_split(base_reward, 0, 0, 1);

    block blk_0 = std::get<block>(events[m_checked_blocks_indices[0]]);
    CHECK_EQ(em.miner_emission, get_tx_out_amount(blk_0.miner_tx));
  }

  // Checked blocks 1-4 are sequential no-fee blocks. Verify positive and
  // weakly decreasing (reward decreases as cumulative coins increase).
  uint64_t prev_reward = std::numeric_limits<uint64_t>::max();
  for (size_t i = 1; i <= 4; ++i)
  {
    block blk_i = std::get<block>(events[m_checked_blocks_indices[i]]);
    uint64_t reward = get_tx_out_amount(blk_i.miner_tx);
    CHECK_TEST_CONDITION(reward > 0);
    CHECK_TEST_CONDITION(reward <= prev_reward);
    prev_reward = reward;
  }

  // Checked block 5: has 3 * TESTS_DEFAULT_FEE in fees
  // The miner gets base emission + miner_fee_income (fee minus burn).
  // With tx_volume_avg=0, burn_pct=0, so miner gets ALL fees.
  block blk_no_fee = std::get<block>(events[m_checked_blocks_indices[4]]);
  uint64_t base_no_fee = get_tx_out_amount(blk_no_fee.miner_tx);

  block blk_fee1 = std::get<block>(events[m_checked_blocks_indices[5]]);
  uint64_t reward_fee1 = get_tx_out_amount(blk_fee1.miner_tx);
  CHECK_TEST_CONDITION(reward_fee1 > base_no_fee);

  // Checked block 6: has (5 + 7) * TESTS_DEFAULT_FEE
  block blk_fee2 = std::get<block>(events[m_checked_blocks_indices[6]]);
  uint64_t reward_fee2 = get_tx_out_amount(blk_fee2.miner_tx);
  CHECK_TEST_CONDITION(reward_fee2 > reward_fee1);

  // Checked block 7: max-weight block with (11 + 13) * TESTS_DEFAULT_FEE
  block blk_fee3 = std::get<block>(events[m_checked_blocks_indices[7]]);
  uint64_t reward_fee3 = get_tx_out_amount(blk_fee3.miner_tx);
  CHECK_TEST_CONDITION(reward_fee3 > 0);

  return true;
}

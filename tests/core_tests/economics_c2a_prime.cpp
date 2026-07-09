// Copyright (c) 2025-2026, The Shekyl Foundation
//
// C2a′ Layer 3 pop-replay harness — STAGE_1_PR_7 §5.8 (7-base).

#include "economics_c2a_prime.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "economics_chain_helpers.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

economics_c2a_prime_layer3_pop_replay::economics_c2a_prime_layer3_pop_replay()
{
  m_miner.generate(crypto::secret_key{}, false, false, cryptonote::FAKECHAIN);
  REGISTER_CALLBACK("verify_pop_replay", economics_c2a_prime_layer3_pop_replay::verify_pop_replay);
}

bool economics_c2a_prime_layer3_pop_replay::generate(std::vector<test_event_entry>& events) const
{
  const uint64_t ts_start = 1338224400;

  MAKE_GENESIS_BLOCK(events, blk_0, m_miner, ts_start);
  DO_CALLBACK(events, "verify_pop_replay");

  return true;
}

bool economics_c2a_prime_layer3_pop_replay::verify_pop_replay(
    cryptonote::core& c,
    size_t /*ev_index*/,
    const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("economics_c2a_prime_layer3_pop_replay::verify_pop_replay");

  auto& bc = c.get_blockchain_storage();
  BlockchainDB& db = bc.get_db();
  CHECK_TEST_CONDITION(db.height() == 1);

  test_generator generator;
  std::vector<cryptonote::block> chain_blocks;
  chain_blocks.reserve(k_chain_blocks + 1);

  cryptonote::block prev = db.get_block_from_height(0);
  chain_blocks.push_back(prev);
  seed_generator_from_db_genesis(generator, db, prev);

  for (unsigned n = 0; n < k_chain_blocks; ++n)
  {
    const uint64_t height = db.height();
    const uint64_t already_generated = db.get_block_already_generated_coins(height - 1);

    cryptonote::block blk;
    CHECK_TEST_CONDITION(extend_chain_with_empty_block(c, generator, m_miner, prev, /*hf_ver=*/1, blk));
    const uint64_t ag_after = db.get_block_already_generated_coins(db.height() - 1);

    // Cap invariant (STAGE_1_PR_7 §5.8) — locks in fix α. The live
    // already_generated delta MUST equal the FULL block subsidy (miner emission
    // + staker emission), recomputed independently from the Rust 0h curve and
    // the release multiplier the chain applies to these empty blocks
    // (tx_volume_avg == 0 → RELEASE_MIN, since get_tx_volume_avg counts only
    // non-coinbase txs). If validate_miner_transaction's base_reward out-param is
    // ever overwritten with the miner-only emission again (the :1608 regression),
    // the connect path at blockchain.cpp :4945 accumulates the miner share
    // instead of the full subsidy and this equality fails.
    const uint64_t q_full = expected_full_subsidy(already_generated);
    CHECK_TEST_CONDITION(ag_after - already_generated == q_full);

    // Defense in depth: the staker emission share is carved out of the full
    // subsidy at these (pre-decay) heights, so the full emission strictly
    // exceeds the miner coinbase output. This confirms the split is real, i.e.
    // that the equality above is genuinely distinguishing full from miner-only.
    const uint64_t miner_coinbase = get_outs_money_amount(blk.miner_tx);
    CHECK_TEST_CONDITION(q_full > miner_coinbase);

    chain_blocks.push_back(blk);
    prev = blk;
  }

  const uint64_t height = db.height();
  CHECK_TEST_CONDITION(height == k_chain_blocks + 1);
  const uint64_t ag_before = db.get_block_already_generated_coins(height - 1);

  bc.pop_blocks(k_pop_count);
  CHECK_TEST_CONDITION(db.height() == height - k_pop_count);

  for (size_t i = chain_blocks.size() - k_pop_count; i < chain_blocks.size(); ++i)
  {
    CHECK_AND_ASSERT_MES(add_block_to_core(c, chain_blocks[i]), false,
        "[" << perr_context << "] " << "reconnect failed to restore block to main chain at height " << i);
  }

  CHECK_TEST_CONDITION(db.height() == height);
  CHECK_TEST_CONDITION(db.get_block_already_generated_coins(height - 1) == ag_before);

  return true;
}

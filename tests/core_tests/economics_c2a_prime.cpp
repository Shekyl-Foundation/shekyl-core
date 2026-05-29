// Copyright (c) 2025-2026, The Shekyl Foundation
//
// C2a′ Layer 3 pop-replay harness — STAGE_1_PR_7 §5.8 (7-base).

#include "economics_c2a_prime.h"

#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;

economics_c2a_prime_layer3_pop_replay::economics_c2a_prime_layer3_pop_replay()
{
  REGISTER_CALLBACK("verify_pop_replay", economics_c2a_prime_layer3_pop_replay::verify_pop_replay);
}

bool economics_c2a_prime_layer3_pop_replay::generate(std::vector<test_event_entry>& events) const
{
  GENERATE_ACCOUNT(miner);
  const uint64_t ts_start = 1338224400;

  MAKE_GENESIS_BLOCK(events, blk_0, miner, ts_start);
  REWIND_BLOCKS_N(events, blk_tip, blk_0, miner, k_chain_blocks);
  DO_CALLBACK(events, "verify_pop_replay");

  return true;
}

bool economics_c2a_prime_layer3_pop_replay::verify_pop_replay(
    cryptonote::core& c,
    size_t /*ev_index*/,
    const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("economics_c2a_prime_layer3_pop_replay::verify_pop_replay");

  std::vector<cryptonote::block> chain_blocks;
  chain_blocks.reserve(events.size());
  for (const test_event_entry& ev : events)
  {
    if (std::holds_alternative<cryptonote::block>(ev))
      chain_blocks.push_back(std::get<cryptonote::block>(ev));
  }

  CHECK_TEST_CONDITION(chain_blocks.size() >= k_pop_count + 1);

  auto& bc = c.get_blockchain_storage();
  BlockchainDB& db = bc.get_db();
  const uint64_t height = db.height();
  CHECK_TEST_CONDITION(height > k_pop_count);
  CHECK_TEST_CONDITION(height == chain_blocks.size());

  const uint64_t ag_before = db.get_block_already_generated_coins(height - 1);

  bc.pop_blocks(k_pop_count);
  CHECK_TEST_CONDITION(db.height() == height - k_pop_count);

  for (size_t i = chain_blocks.size() - k_pop_count; i < chain_blocks.size(); ++i)
  {
    const cryptonote::block& blk = chain_blocks[i];
    cryptonote::block_verification_context bvc = AUTO_VAL_INIT(bvc);
    cryptonote::blobdata bd = t_serializable_object_to_blob(blk);
    std::vector<cryptonote::block> pblocks;
    cryptonote::block_complete_entry bce;
    bce.pruned = false;
    bce.block = bd;
    bce.txs = {};
    CHECK_TEST_CONDITION(c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, bce), pblocks));
    CHECK_TEST_CONDITION(c.handle_incoming_block(bd, &blk, bvc));
    c.cleanup_handle_incoming_blocks();
    CHECK_TEST_CONDITION(!bvc.m_verifivation_failed);
  }

  CHECK_TEST_CONDITION(db.height() == height);
  CHECK_TEST_CONDITION(db.get_block_already_generated_coins(height - 1) == ag_before);

  return true;
}

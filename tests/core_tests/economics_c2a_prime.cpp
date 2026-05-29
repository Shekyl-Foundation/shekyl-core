// Copyright (c) 2025-2026, The Shekyl Foundation
//
// C2a′ Layer 3 pop-replay harness — STAGE_1_PR_7 §5.8 (7-base).

#include "economics_c2a_prime.h"

#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;

namespace {

bool add_block_to_core(cryptonote::core& c, const cryptonote::block& blk)
{
  cryptonote::block_verification_context bvc = AUTO_VAL_INIT(bvc);
  cryptonote::blobdata bd = t_serializable_object_to_blob(blk);
  std::vector<cryptonote::block> pblocks;
  cryptonote::block_complete_entry bce;
  bce.pruned = false;
  bce.block = bd;
  bce.txs = {};
  if (!c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, bce), pblocks))
    return false;
  if (!c.handle_incoming_block(bd, &blk, bvc))
    return false;
  c.cleanup_handle_incoming_blocks();
  return !bvc.m_verifivation_failed;
}

} // namespace

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

  {
    const uint64_t genesis_ag = db.get_block_already_generated_coins(0);
    std::vector<size_t> seed_weights;
    generator.add_block(prev, 0, seed_weights, 0, genesis_ag, prev.major_version);
  }

  for (unsigned n = 0; n < k_chain_blocks; ++n)
  {
    cryptonote::block blk;
    const uint64_t height = db.height();
    const uint64_t already_generated = db.get_block_already_generated_coins(height - 1);
    std::vector<size_t> block_weights;
    generator.get_last_n_block_weights(block_weights, get_block_hash(prev), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
    const uint64_t timestamp = prev.timestamp + current_difficulty_window();
    CHECK_TEST_CONDITION(generator.construct_block(
        blk,
        height,
        get_block_hash(prev),
        m_miner,
        timestamp,
        already_generated,
        block_weights,
        std::list<cryptonote::transaction>{}));
    CHECK_TEST_CONDITION(add_block_to_core(c, blk));
    const uint64_t ag_after = db.get_block_already_generated_coins(db.height() - 1);
    std::vector<size_t> resync_weights;
    generator.add_block(blk, 0, resync_weights, already_generated, ag_after - already_generated, blk.major_version);
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
    CHECK_TEST_CONDITION(add_block_to_core(c, chain_blocks[i]));
  }

  CHECK_TEST_CONDITION(db.height() == height);
  CHECK_TEST_CONDITION(db.get_block_already_generated_coins(height - 1) == ag_before);

  return true;
}

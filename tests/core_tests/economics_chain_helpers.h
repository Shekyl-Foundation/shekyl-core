// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Shared scaffold for the real-connect-path economics KATs
// (economics_c2a_prime Layer 3, archival_budget_conservation): ONE copy of
// the block-injection recipe, the independent subsidy recompute, and the
// empty-block chain-extension step, so the two CI lanes cannot drift apart.

#pragma once

#include <list>
#include <stdexcept>
#include <string>
#include <vector>

#include "chaingen.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

// Feeds one locally-constructed block through the REAL incoming-block path
// (prepare / handle_incoming_block / cleanup).
//
// cleanup_handle_incoming_blocks runs even when handle_incoming_block fails:
// prepare takes the txpool lock and opens the LMDB write batch, and cleanup
// is the only release — skipping it on the failure path (which is exactly
// where a DB-side regression throws, CATCH_ENTRY_L0 turning the throw into
// a false return) degrades the caller's pinpoint diagnostic into a teardown
// abort/hang. prepare-false needs no cleanup here: core's wrapper
// self-cleans on that path (cryptonote_core.cpp prepare_handle_incoming_blocks).
//
// Success requires the block to actually land on the main chain. A block
// that is accepted-but-orphaned or routed to an alt chain reports
// m_verifivation_failed == false with m_added_to_main_chain == false; for
// these fixtures that is a failure to report at the offending height, not
// a phantom success to surface later as an opaque BLOCK_DNE or an
// aggregate height mismatch.
inline bool add_block_to_core(cryptonote::core& c, const cryptonote::block& blk)
{
  cryptonote::block_verification_context bvc = AUTO_VAL_INIT(bvc);
  cryptonote::blobdata bd = cryptonote::t_serializable_object_to_blob(blk);
  std::vector<cryptonote::block> pblocks;
  cryptonote::block_complete_entry bce;
  bce.pruned = false;
  bce.block = bd;
  bce.txs = {};
  if (!c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, bce), pblocks))
    return false;
  const bool handled = c.handle_incoming_block(bd, &blk, bvc);
  c.cleanup_handle_incoming_blocks();
  return handled && !bvc.m_verifivation_failed && bvc.m_added_to_main_chain;
}

// Independent recompute of the paid pre-penalty quantity for an empty
// FAKECHAIN block (tx_volume_avg == 0). One owner: shekyl_block_reward
// (weight 1 < zone ⇒ no penalty). Deliberately NOT read back from the
// connect path — this is the conservation identity's independent leg.
inline uint64_t expected_full_subsidy(uint64_t already_generated)
{
  uint64_t computed = 0;
  uint64_t limit = 0;
  const int32_t st = shekyl_block_reward(
      0,
      1,
      already_generated,
      CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
      /*tx_volume_avg=*/0,
      &computed,
      &limit);
  // Fail LOUDLY. Returning 0 here would hand the conservation identity a
  // bogus subsidy: the identity could be satisfied trivially, or fail far
  // downstream with a misleading number, and either way the real fault —
  // a rejected FFI call — would be invisible (PR #640 review). This is a
  // test oracle; a refusal must reach the test, not be absorbed.
  if (st != SHEKYL_BLOCK_REWARD_OK)
    throw std::runtime_error(
        "expected_full_subsidy: shekyl_block_reward rejected the call (status " +
        std::to_string(st) + ") at already_generated=" + std::to_string(already_generated));
  return computed;
}

// Seeds `generator` bookkeeping with the already-connected genesis block
// read back from the core's DB.
inline void seed_generator_from_db_genesis(
    test_generator& generator,
    const cryptonote::BlockchainDB& db,
    const cryptonote::block& genesis)
{
  std::vector<size_t> seed_weights;
  generator.add_block(genesis, 0, seed_weights, 0,
      db.get_block_already_generated_coins(0), genesis.major_version);
}

// Constructs one empty block of `hf_ver` on top of `prev`, connects it
// through the real path, and resyncs `generator` bookkeeping from the DB's
// post-connect state. Returns false (with a logged, height-labeled message)
// on the first failing step.
inline bool extend_chain_with_empty_block(
    cryptonote::core& c,
    test_generator& generator,
    const cryptonote::account_base& miner,
    const cryptonote::block& prev,
    uint8_t hf_ver,
    cryptonote::block& blk_out)
{
  cryptonote::BlockchainDB& db = c.get_blockchain_storage().get_db();
  const uint64_t height = db.height();
  const uint64_t already_generated = db.get_block_already_generated_coins(height - 1);
  std::vector<size_t> block_weights;
  generator.get_last_n_block_weights(block_weights, cryptonote::get_block_hash(prev), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  const uint64_t timestamp = prev.timestamp + current_difficulty_window();
  CHECK_AND_ASSERT_MES(generator.construct_block(
      blk_out,
      height,
      cryptonote::get_block_hash(prev),
      miner,
      timestamp,
      already_generated,
      block_weights,
      std::list<cryptonote::transaction>{},
      hf_ver), false,
      "extend_chain_with_empty_block: construct_block failed at height " << height);
  CHECK_AND_ASSERT_MES(add_block_to_core(c, blk_out), false,
      "extend_chain_with_empty_block: block not connected to main chain at height " << height);
  const uint64_t ag_after = db.get_block_already_generated_coins(height);
  std::vector<size_t> resync_weights;
  generator.add_block(blk_out, 0, resync_weights, already_generated, ag_after - already_generated, blk_out.major_version);
  return true;
}

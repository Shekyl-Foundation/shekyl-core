// Copyright (c) 2025-2026, The Shekyl Foundation
//
// End-to-end supply-conservation KAT — C-1 budget fast-follow
// (REWARD_EMISSION_E3_GATING_ROUND.md §9.9; ARCHIVAL_BUDGET_SCHEDULE.md §2.2).
// See archival_budget_conservation.h for the full framing.

#include "archival_budget_conservation.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"

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

// The independent recompute of verify's modulated base_reward for an empty
// FAKECHAIN block (the economics_c2a_prime recipe): 0h curve + release
// multiplier at tx_volume_avg == 0 (empty blocks carry no non-coinbase txs)
// + the MONEY_SUPPLY cap. Deliberately NOT read back from the connect path —
// this is the identity's independent leg.
uint64_t expected_full_subsidy(uint64_t already_generated)
{
  const uint64_t raw_base = shekyl_base_block_reward(already_generated);
  const uint64_t release_mult = shekyl_calc_release_multiplier(
      /*tx_volume_avg=*/0, SHEKYL_TX_VOLUME_BASELINE, SHEKYL_RELEASE_MIN, SHEKYL_RELEASE_MAX);
  uint64_t q_full = shekyl_apply_release_multiplier(raw_base, release_mult);
  const uint64_t remaining = MONEY_SUPPLY - already_generated;
  if (q_full > remaining)
    q_full = remaining;
  return q_full;
}

// Per-height snapshot recorded during the build pass, replayed after
// pop+reconnect to assert byte-identical restoration.
struct height_row
{
  uint64_t already_generated;  // cumulative, as-of this height
  uint64_t accrual;            // archival_budget_accrual row
  uint64_t burn;               // block_burn row
};

} // namespace

archival_budget_conservation_boundary::archival_budget_conservation_boundary()
{
  m_miner.generate(crypto::secret_key{}, false, false, cryptonote::FAKECHAIN);
  REGISTER_CALLBACK("verify_conservation", archival_budget_conservation_boundary::verify_conservation);
}

bool archival_budget_conservation_boundary::generate(std::vector<test_event_entry>& events) const
{
  const uint64_t ts_start = 1338224400;

  MAKE_GENESIS_BLOCK(events, blk_0, m_miner, ts_start);
  DO_CALLBACK(events, "verify_conservation");

  return true;
}

bool archival_budget_conservation_boundary::verify_conservation(
    cryptonote::core& c,
    size_t /*ev_index*/,
    const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("archival_budget_conservation_boundary::verify_conservation");

  auto& bc = c.get_blockchain_storage();
  BlockchainDB& db = bc.get_db();
  CHECK_TEST_CONDITION(db.height() == 1);

  // Genesis exclusion (blockchain.cpp genesis guard): height 0's emission is
  // the hardcoded GENESIS_TX amount, fully paid to the coinbase — no staker
  // leg exists, so neither row may carry anything.
  CHECK_TEST_CONDITION(db.get_archival_budget_accrual(0) == 0);
  CHECK_TEST_CONDITION(db.get_block_burn(0) == 0);
  {
    const block genesis = db.get_block_from_height(0);
    CHECK_TEST_CONDITION(db.get_block_already_generated_coins(0)
        == get_outs_money_amount(genesis.miner_tx));
  }

  const uint64_t genesis_ng_height =
      bc.get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG);

  test_generator generator;
  std::vector<cryptonote::block> chain_blocks;
  std::vector<height_row> rows;
  chain_blocks.reserve(k_chain_blocks + 1);
  rows.reserve(k_chain_blocks + 1);

  cryptonote::block prev = db.get_block_from_height(0);
  chain_blocks.push_back(prev);
  rows.push_back(height_row{db.get_block_already_generated_coins(0), 0, 0});

  {
    std::vector<size_t> seed_weights;
    generator.add_block(prev, 0, seed_weights, 0, rows[0].already_generated, prev.major_version);
  }

  for (unsigned n = 0; n < k_chain_blocks; ++n)
  {
    const uint64_t height = db.height();
    const uint8_t hf_ver = height >= k_fork_height ? 2 : 1;
    const uint64_t already_generated = db.get_block_already_generated_coins(height - 1);

    cryptonote::block blk;
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
        std::list<cryptonote::transaction>{},
        hf_ver));
    CHECK_AND_ASSERT_MES(blk.major_version == hf_ver, false,
        "[" << perr_context << "] " << "fixture must cross the fork boundary");
    CHECK_TEST_CONDITION(add_block_to_core(c, blk));

    // ── The conservation identity, in labeled form ─────────────────────────
    // Independent recompute of every leg from the block's OWN operands
    // (height, major_version, prior cumulative supply). The redirect is a
    // pure destination switch, so the *sum* of the two rows is
    // branch-invariant; only row-level equality catches burn-when-should-
    // accrue (the F-B1b branch-selection class).
    const uint64_t q_full = expected_full_subsidy(already_generated);
    const shekyl::EmissionSplit em_split =
        shekyl::compute_emission_split(q_full, height, genesis_ng_height, blk.major_version);

    // Fee-free fixture: compute_fee_burn(total_fees == 0) is {0,0,0}, so the
    // staker leg is the emission share alone and the burn row carries only
    // the (pre-activation) redirected inflow.
    const uint64_t staker_inflow = em_split.staker_emission;
    const bool redirect_active = blk.major_version >= HF_VERSION_ARCHIVAL_EMISSION;
    const uint64_t expected_accrual = redirect_active ? staker_inflow : 0;
    const uint64_t expected_burn = redirect_active ? 0 : staker_inflow;

    const uint64_t ag_after = db.get_block_already_generated_coins(height);
    const uint64_t accrual_row = db.get_archival_budget_accrual(height);
    const uint64_t burn_row = db.get_block_burn(height);
    const uint64_t miner_coinbase = get_outs_money_amount(blk.miner_tx);

    // Ledger advance is the full modulated subsidy (fix alpha).
    CHECK_AND_ASSERT_MES(ag_after - already_generated == q_full, false,
        "[" << perr_context << "] " << "already_generated advance != independently recomputed subsidy at height " << height);
    // Coinbase carries exactly the miner leg (coinbase-foreclosure pin).
    CHECK_AND_ASSERT_MES(miner_coinbase == em_split.miner_emission, false,
        "[" << perr_context << "] " << "coinbase != miner_emission at height " << height);
    // Exactly one target, selected by the block's own version.
    CHECK_AND_ASSERT_MES(accrual_row == expected_accrual, false,
        "[" << perr_context << "] " << "accrual row mismatch at height " << height << " (v" << unsigned(blk.major_version)
        << "): got " << accrual_row << ", expected " << expected_accrual);
    CHECK_AND_ASSERT_MES(burn_row == expected_burn, false,
        "[" << perr_context << "] " << "burn row mismatch at height " << height << " (v" << unsigned(blk.major_version)
        << "): got " << burn_row << ", expected " << expected_burn);
    // Capstone sum: ledger = coinbase + (burned | accrued), no gap, no overlap.
    CHECK_AND_ASSERT_MES(miner_coinbase + accrual_row + burn_row == ag_after - already_generated, false,
        "[" << perr_context << "] " << "conservation identity broken at height " << height);
    // The split is real at these (pre-decay) heights — the staker leg is
    // nonzero, so the row assertions above genuinely distinguish targets.
    CHECK_TEST_CONDITION(staker_inflow > 0);

    std::vector<size_t> resync_weights;
    generator.add_block(blk, 0, resync_weights, already_generated, q_full, blk.major_version);
    chain_blocks.push_back(blk);
    rows.push_back(height_row{ag_after, accrual_row, burn_row});
    prev = blk;
  }

  const uint64_t top_height = db.height();
  CHECK_TEST_CONDITION(top_height == k_chain_blocks + 1);

  // ── Pop across the boundary, reconnect, assert byte-identical rows ──────
  // Accrual-row pop symmetry through the production path (§3.1: removal in
  // BlockchainDB::pop_block), and the boundary replayed through the rewound
  // fork machinery on reconnect.
  bc.pop_blocks(k_pop_count);
  CHECK_TEST_CONDITION(db.height() == top_height - k_pop_count);
  CHECK_TEST_CONDITION(db.height() - 1 < k_fork_height);  // rewound below the fork

  for (uint64_t h = db.height(); h < top_height; ++h)
  {
    CHECK_AND_ASSERT_MES(db.get_archival_budget_accrual(h) == 0, false,
        "[" << perr_context << "] " << "accrual row survived pop at height " << h);
    CHECK_AND_ASSERT_MES(db.get_block_burn(h) == 0, false,
        "[" << perr_context << "] " << "burn row survived pop at height " << h);
  }

  for (size_t i = chain_blocks.size() - k_pop_count; i < chain_blocks.size(); ++i)
  {
    CHECK_TEST_CONDITION(add_block_to_core(c, chain_blocks[i]));
  }

  CHECK_TEST_CONDITION(db.height() == top_height);
  for (uint64_t h = 0; h < top_height; ++h)
  {
    CHECK_AND_ASSERT_MES(db.get_block_already_generated_coins(h) == rows[h].already_generated, false,
        "[" << perr_context << "] " << "already_generated diverged after pop+reconnect at height " << h);
    CHECK_AND_ASSERT_MES(db.get_archival_budget_accrual(h) == rows[h].accrual, false,
        "[" << perr_context << "] " << "accrual row diverged after pop+reconnect at height " << h);
    CHECK_AND_ASSERT_MES(db.get_block_burn(h) == rows[h].burn, false,
        "[" << perr_context << "] " << "burn row diverged after pop+reconnect at height " << h);
  }

  return true;
}

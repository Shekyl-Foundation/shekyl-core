// Copyright (c) 2025-2026, The Shekyl Foundation
//
// End-to-end supply-conservation KAT — C-1 budget fast-follow
// (REWARD_EMISSION_E3_GATING_ROUND.md §9.9; ARCHIVAL_BUDGET_SCHEDULE.md §2.2).
// See archival_budget_conservation.h for the full framing.

#include "archival_budget_conservation.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "economics_chain_helpers.h"
#include "shekyl/economics.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

namespace {

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
  seed_generator_from_db_genesis(generator, db, prev);

  for (unsigned n = 0; n < k_chain_blocks; ++n)
  {
    const uint64_t height = db.height();
    const uint8_t hf_ver = height >= k_fork_height ? k_post_fork_version : 1;
    const uint64_t already_generated = db.get_block_already_generated_coins(height - 1);

    cryptonote::block blk;
    CHECK_TEST_CONDITION(extend_chain_with_empty_block(c, generator, m_miner, prev, hf_ver, blk));
    CHECK_AND_ASSERT_MES(blk.major_version == hf_ver, false,
        "[" << perr_context << "] " << "fixture must cross the fork boundary");

    // ── The conservation identity, in labeled form ─────────────────────────
    // Independent recompute of every leg from the block's OWN operands
    // (height, major_version, prior cumulative supply). The redirect is a
    // pure destination switch, so the *sum* of the two rows is
    // branch-invariant; only row-level equality catches burn-when-should-
    // accrue (the F-B1b branch-selection class).
    const uint64_t q_full = expected_full_subsidy(already_generated);
    const shekyl::EmissionSplit em_split =
        shekyl::compute_emission_split(q_full, height, genesis_ng_height, blk.major_version);

    // Fee-free fixture — a disclosed COVERAGE GAP, not just a fixture fact:
    // production's redirected quantity is
    //   staker_inflow = em_split.staker_emission + burn.staker_pool_amount
    // (blockchain.cpp connect site), but compute_fee_burn(total_fees == 0)
    // is {0,0,0}, so this fixture only ever exercises the emission half.
    // The fee-pool half has NO end-to-end coverage here: chaingen cannot
    // construct valid FCMP++ fee transactions (empty pqc_auths stubs are
    // rejected even in FAKECHAIN — see chaingen_main.cpp's disabled-tests
    // note), so a fee-bearing connect-path block waits on the E4/E5 regtest
    // e2e carrier (FOLLOWUPS V3.0 residue; wallet-built txs). Until then the
    // fee leg's guards are the unit-level B5 KATs
    // (economics_b5_fee_coinbase.cpp) and the F-B1c-c1 fix's operand pin.
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
    CHECK_AND_ASSERT_MES(add_block_to_core(c, chain_blocks[i]), false,
        "[" << perr_context << "] " << "reconnect failed to restore block to main chain at height " << i);
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

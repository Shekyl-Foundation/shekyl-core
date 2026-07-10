// Copyright (c) 2025-2026, The Shekyl Foundation
//
// End-to-end supply-conservation KAT with a fork-boundary block —
// the C-1 budget fast-follow (REWARD_EMISSION_E3_GATING_ROUND.md §9.9;
// ARCHIVAL_BUDGET_SCHEDULE.md §2.2 / §7 KAT B1's production-path
// counterpart). Drives the REAL connect path (handle_block_to_main_chain)
// across a multi-entry fork table and asserts, per block:
//
//   coinbase + accrual row + burn row == already_generated_coins advance
//
// in LABELED form: each row is checked against its own expected value. The
// labeled form is the load-bearing choice — a destination error (staker
// inflow routed into the burn row instead of the accrual row, the F-B1b
// class; the deleted pre-activation burn leg's shape) keeps the *sum*
// identity green, so only row-level equality catches it. The staker inflow
// accrues unconditionally (emission is a genesis fact; the burn leg is
// deleted per rule 60), so the expectations are unconditional: whole
// inflow in the accrual row, zero in the burn row (fee-free fixture).
//
// The fork table still crosses v1 -> v2 mid-chain on purpose: the block's
// major_version is a live operand of compute_emission_split /
// compute_fee_burn (the F-B1b operand pin), and the pop/reconnect leg
// replays the boundary through the rewound fork machinery — both remain
// exercised even with the burn-vs-accrue branch gone.
//
// Fee-leg coverage gap (disclosed): the fixture is fee-free, so only the
// emission half of production's staker_inflow
// (em_split.staker_emission + burn.staker_pool_amount) is exercised
// end-to-end. chaingen cannot construct valid FCMP++ fee transactions
// (chaingen_main.cpp disabled-tests note), so the fee-pool half rides the
// E4/E5 regtest-e2e carrier (FOLLOWUPS V3.0 residue); until then its
// guards are the unit-level B5 KATs and the F-B1c-c1 operand pin. See the
// fixture comment at the staker_inflow computation in the .cpp.

#pragma once

#include "chaingen.h"
#include "cryptonote_config.h"

class archival_budget_conservation_boundary : public test_chain_unit_base
{
public:
  archival_budget_conservation_boundary();

  bool generate(std::vector<test_event_entry>& events) const;

  bool verify_conservation(
      cryptonote::core& c,
      size_t ev_index,
      const std::vector<test_event_entry>& events);

  // First height whose block carries major_version k_post_fork_version (the
  // fork-table entry below). Mid-chain and epoch-unaligned on purpose: the
  // boundary block is the fixture requirement named in the FOLLOWUPS pin.
  static constexpr uint64_t k_fork_height = 8;
  // The fork table's top block version — the single source for the
  // fork-table entry and the per-block version selection in the .cpp.
  static constexpr uint8_t k_post_fork_version = 2;
  // Blocks connected on top of genesis. Short by design — the identity is
  // per block; epoch close (SETTLEMENT_EPOCH_BLOCKS = 10 000) is covered by
  // the unit-level F-B1a KAT, not re-proven here.
  static constexpr unsigned k_chain_blocks = 16;
  // Pop depth crossing the fork boundary (back to height 5 < k_fork_height),
  // so reconnect replays the boundary through the rewound fork machinery.
  static constexpr unsigned k_pop_count = 12;

private:
  mutable cryptonote::account_base m_miner;
};

template<>
struct get_test_options<archival_budget_conservation_boundary>
{
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {
    std::make_pair((uint8_t)1, (uint64_t)0),
    std::make_pair(archival_budget_conservation_boundary::k_post_fork_version,
                   archival_budget_conservation_boundary::k_fork_height),
    std::make_pair((uint8_t)0, (uint64_t)0)
  };
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

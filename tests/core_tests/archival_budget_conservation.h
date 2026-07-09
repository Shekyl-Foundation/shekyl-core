// Copyright (c) 2025-2026, The Shekyl Foundation
//
// End-to-end supply-conservation KAT with an activation-boundary block —
// the C-1 budget fast-follow (REWARD_EMISSION_E3_GATING_ROUND.md §9.9;
// ARCHIVAL_BUDGET_SCHEDULE.md §2.2 / §7 KAT B1's production-path
// counterpart). Drives the REAL connect path (handle_block_to_main_chain)
// across a multi-entry fork table and asserts, per block:
//
//   coinbase + accrual row + burn row == already_generated_coins advance
//
// in LABELED form: each row is checked against its expected value given the
// block's OWN major_version. The labeled form is the load-bearing choice —
// the redirect is a pure destination switch (same staker_inflow quantity,
// burn vs accrue), so the *sum* holds even when the wrong branch fires;
// only row-level equality catches the branch-selection class (F-B1b) that
// operand-identity construction and the grep tripwire cannot see.
//
// Genesis-posture note (§2.3): HF_VERSION_ARCHIVAL_EMISSION == 1 and block
// versions start at 1, so no pre-activation block is constructible through
// the real connect path today — the burn leg of the expectations is
// compile-alive but unexercised. The expectations are written against the
// constant generically: a post-genesis activation bump (constant > 1) arms
// the burn leg and the boundary straddle through this same fixture with no
// test change, because the fork table below already crosses v1 -> v2
// mid-chain.

#pragma once

#include "chaingen.h"

class archival_budget_conservation_boundary : public test_chain_unit_base
{
public:
  archival_budget_conservation_boundary();

  bool generate(std::vector<test_event_entry>& events) const;

  bool verify_conservation(
      cryptonote::core& c,
      size_t ev_index,
      const std::vector<test_event_entry>& events);

  // First height whose block carries major_version 2 (the fork-table entry
  // below). Mid-chain and epoch-unaligned on purpose: the boundary block is
  // the fixture requirement named in the FOLLOWUPS pin.
  static constexpr uint64_t k_fork_height = 8;
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
    std::make_pair((uint8_t)2, archival_budget_conservation_boundary::k_fork_height),
    std::make_pair((uint8_t)0, (uint64_t)0)
  };
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

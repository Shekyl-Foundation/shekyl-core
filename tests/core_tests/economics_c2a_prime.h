// Copyright (c) 2025-2026, The Shekyl Foundation
//
// C2a′ Layer 3 pop-replay harness — STAGE_1_PR_7 §5.8 (7-base).

#pragma once

#include "chaingen.h"

class economics_c2a_prime_layer3_pop_replay : public test_chain_unit_base
{
public:
  economics_c2a_prime_layer3_pop_replay();

  bool generate(std::vector<test_event_entry>& events) const;

  bool verify_pop_replay(
      cryptonote::core& c,
      size_t ev_index,
      const std::vector<test_event_entry>& events);

private:
  static constexpr unsigned k_chain_blocks = 100;
  static constexpr unsigned k_pop_count = 10;

  mutable cryptonote::account_base m_miner;
};

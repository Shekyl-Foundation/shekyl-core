// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "chaingen.h"

// C2-R1b F-1(a), the value-shaped leg: a watermark-refused NETWORK SWITCH
// is a local retention limitation, not block invalidity. The switch is
// refused, the node goes sticky-DEGRADED (false -> true, re-armed on every
// re-attempt, never cleared in-process), the triggering block stays in the
// alt store, and bvc carries NO failure -- so the P2P paths keep the honest
// peer that advertised the heavier chain.
//
//   main:  (0)-(1)-(2)-(3)              cum 4 at the tip (fixed difficulty 1)
//   alt:        \-(2a)-(3a)-(4a)-(5a)   4a reaches cum 5 > 4: verdict SWITCH
//
// The prune watermark (epoch 1) is armed by callback before the fork
// arrives, so the switch's rollback target (the fork parent at height 1)
// sits far below the floor and the switch MUST refuse. 5a re-attempts the
// switch and must be refused the same way (recurrence), with the flag still
// set (stickiness). Under the pre-fix code the refusal travelled the
// switch's false return into bvc.m_verifivation_failed, which fails this
// test's default block check -- the observed-red form of the defect.
class gen_reorg_watermark_refused_switch : public test_chain_unit_base
{
public:
  gen_reorg_watermark_refused_switch();

  bool generate(std::vector<test_event_entry>& events) const;

  bool arm_watermark(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_not_yet_degraded(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_degraded_first_refusal(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_degraded_recurrence(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);

private:
  bool check_top_unmoved(cryptonote::core& c, const std::vector<test_event_entry>& events,
      const char* where, size_t expected_alt_count);
};

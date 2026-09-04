// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "chaingen.h"

// C2-R1b-Q2b, the recovery path's own value test: an operator-checkpoint
// conflict LOW on the chain must complete its rollback, and a SECOND
// conflicting checkpoint above it must not blow up the walk.
//
//   main: (0)-(1)-(2)-(3)-(4)-(5)      height 6
//   checkpoints.json: wrong hash at height 2 AND at height 4
//
// The height-2 conflict's rollback target is floored at DB height 1 --
// genesis cannot be popped, so the previous `pt.first - 2 = 0` target
// aborted mid-rollback on the genesis guard ("Cannot pop the genesis
// block") with the batch txn open. And after the applied rollback the
// checkpoint walk must stop: the height-4 entry, tested against the
// PRE-rollback height, would read a block hash above the new tip and
// throw. Both failure forms were observed red before the fix; the fixed
// walk rolls back once, breaks, and reports the conflict resolved with
// the chain at genesis.
class gen_checkpoint_conflict_rollback : public test_chain_unit_base
{
public:
  gen_checkpoint_conflict_rollback();

  bool generate(std::vector<test_event_entry>& events) const;

  bool check_conflict_rollback(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

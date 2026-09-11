// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "chaingen.h"
#include "reorg_watermark_degraded.h"

#include "blockchain_db/lmdb/db_lmdb.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

namespace
{
  // Event indices, fixed by generate()'s construction order below.
  constexpr size_t EV_BLK_3 = 3;   // the main tip the node must stay on
}

gen_reorg_watermark_refused_switch::gen_reorg_watermark_refused_switch()
{
  REGISTER_CALLBACK("arm_watermark", gen_reorg_watermark_refused_switch::arm_watermark);
  REGISTER_CALLBACK("check_not_yet_degraded", gen_reorg_watermark_refused_switch::check_not_yet_degraded);
  REGISTER_CALLBACK("check_degraded_first_refusal", gen_reorg_watermark_refused_switch::check_degraded_first_refusal);
  REGISTER_CALLBACK("check_degraded_recurrence", gen_reorg_watermark_refused_switch::check_degraded_recurrence);
}

bool gen_reorg_watermark_refused_switch::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);  // ev 0, height 0, cum 1
  MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner_account);        // ev 1, height 1, cum 2
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner_account);        // ev 2, height 2, cum 3
  MAKE_NEXT_BLOCK(events, blk_3, blk_2, miner_account);        // ev 3, height 3, cum 4

  // Arm the prune watermark BEFORE the fork arrives; also asserts the
  // node starts un-degraded (the false half of the false -> true value).
  DO_CALLBACK(events, "arm_watermark");                        // ev 4

  // Alt fork off height 1. With difficulty fixed at 1, 2a/3a stay at or
  // below the main tip's cumulative difficulty (added as alternatives,
  // equality keeps the incumbent), so no switch is attempted yet.
  MAKE_NEXT_BLOCK(events, blk_2a, blk_1, miner_account);       // ev 5, height 2, cum 3
  MAKE_NEXT_BLOCK(events, blk_3a, blk_2a, miner_account);      // ev 6, height 3, cum 4
  DO_CALLBACK(events, "check_not_yet_degraded");               // ev 7

  // 4a takes the alt chain strictly heavier: verdict SWITCH, rollback
  // target height 1 below the floor -- the switch must refuse.
  MAKE_NEXT_BLOCK(events, blk_4a, blk_3a, miner_account);      // ev 8, height 4, cum 5
  DO_CALLBACK(events, "check_degraded_first_refusal");         // ev 9

  // A descendant re-attempts the switch: refused again, flag re-armed.
  MAKE_NEXT_BLOCK(events, blk_5a, blk_4a, miner_account);      // ev 10, height 5, cum 6
  DO_CALLBACK(events, "check_degraded_recurrence");            // ev 11

  return true;
}

bool gen_reorg_watermark_refused_switch::arm_watermark(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_reorg_watermark_refused_switch::arm_watermark");

  cryptonote::Blockchain& bcs = c.get_blockchain_storage();
  CHECK_TEST_CONDITION(!bcs.is_following_degraded());

  // The watermark writer is the LMDB store's; core_tests run on the real
  // LMDB backend (new_db()), so reach it through the concrete type. The
  // write simulates a retention prune's receipt without raising an
  // SEB-scale chain: epoch 1's open height is the resulting pop floor.
  cryptonote::BlockchainLMDB* lmdb = dynamic_cast<cryptonote::BlockchainLMDB*>(&bcs.get_db());
  CHECK_TEST_CONDITION(lmdb != nullptr);
  CHECK_TEST_CONDITION(lmdb->batch_start());
  lmdb->note_archival_prune_watermark_epoch(1);
  lmdb->batch_stop();
  CHECK_EQ(1, (int)lmdb->get_archival_prune_watermark_epoch());

  // The floor must sit above every height this test touches, or the
  // refusal below could not bind and the switch would silently succeed
  // (rule 47: assert the gate's subject exists).
  CHECK_TEST_CONDITION(shekyl_archival_epoch_open_height(1) > 6);

  return true;
}

bool gen_reorg_watermark_refused_switch::check_top_unmoved(cryptonote::core& c, const std::vector<test_event_entry>& events,
    const char* where, size_t expected_alt_count)
{
  DEFINE_TESTS_ERROR_CONTEXT(where);

  // Height 4 = genesis + three main blocks: the refused switches must not
  // have popped or promoted anything.
  CHECK_EQ(4, (int)c.get_current_blockchain_height());
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(std::get<block>(events[EV_BLK_3])));
  // The triggering blocks stay in the alt store (a refusal is not a purge).
  CHECK_EQ((int)expected_alt_count, (int)c.get_alternative_blocks_count());

  return true;
}

bool gen_reorg_watermark_refused_switch::check_not_yet_degraded(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_reorg_watermark_refused_switch::check_not_yet_degraded");

  // Two alt blocks stored, no switch attempted (2a lighter, 3a equal —
  // equality keeps the incumbent), so the flag must still be clear: it
  // marks refused switches, not the existence of an alt chain.
  CHECK_TEST_CONDITION(!c.get_blockchain_storage().is_following_degraded());
  return check_top_unmoved(c, events, "gen_reorg_watermark_refused_switch::check_not_yet_degraded", 2);
}

bool gen_reorg_watermark_refused_switch::check_degraded_first_refusal(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_reorg_watermark_refused_switch::check_degraded_first_refusal");

  // The false -> true transition: 4a's strictly-heavier chain forced a
  // switch attempt, the watermark refused it, and the node now says so.
  CHECK_TEST_CONDITION(c.get_blockchain_storage().is_following_degraded());
  return check_top_unmoved(c, events, "gen_reorg_watermark_refused_switch::check_degraded_first_refusal", 3);
}

bool gen_reorg_watermark_refused_switch::check_degraded_recurrence(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_reorg_watermark_refused_switch::check_degraded_recurrence");

  // Stickiness across a second refusal: 5a re-attempted the switch and
  // was refused the same way; the flag stays set and the chain state is
  // still exactly the pre-fork main chain.
  CHECK_TEST_CONDITION(c.get_blockchain_storage().is_following_degraded());
  return check_top_unmoved(c, events, "gen_reorg_watermark_refused_switch::check_degraded_recurrence", 4);
}

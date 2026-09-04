// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include <boost/filesystem.hpp>
#include <fstream>

#include "chaingen.h"
#include "checkpoint_conflict_rollback.h"

#include "string_tools.h"

using namespace cryptonote;

gen_checkpoint_conflict_rollback::gen_checkpoint_conflict_rollback()
{
  REGISTER_CALLBACK("check_conflict_rollback", gen_checkpoint_conflict_rollback::check_conflict_rollback);
}

bool gen_checkpoint_conflict_rollback::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);  // height 0
  MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner_account);        // height 1
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner_account);        // height 2
  MAKE_NEXT_BLOCK(events, blk_3, blk_2, miner_account);        // height 3
  MAKE_NEXT_BLOCK(events, blk_4, blk_3, miner_account);        // height 4
  MAKE_NEXT_BLOCK(events, blk_5, blk_4, miner_account);        // height 5

  DO_CALLBACK(events, "check_conflict_rollback");

  return true;
}

bool gen_checkpoint_conflict_rollback::check_conflict_rollback(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_checkpoint_conflict_rollback::check_conflict_rollback");

  cryptonote::Blockchain& bcs = c.get_blockchain_storage();
  CHECK_EQ(6, (int)c.get_current_blockchain_height());

  // Conflicting hashes derived from the real ones with one byte flipped,
  // so the mismatch is guaranteed without hardcoding chain hashes.
  crypto::hash wrong_2 = bcs.get_block_id_by_height(2);
  reinterpret_cast<char&>(wrong_2) ^= 1;
  crypto::hash wrong_4 = bcs.get_block_id_by_height(4);
  reinterpret_cast<char&>(wrong_4) ^= 1;
  const crypto::hash genesis = bcs.get_block_id_by_height(0);

  const boost::filesystem::path json_path =
      boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("ckpt-conflict-%%%%%%%%.json");
  {
    std::ofstream ofs(json_path.string());
    ofs << "{\"hashlines\":[";
    ofs << "{\"hash\":\"" << epee::string_tools::pod_to_hex(wrong_2) << "\",\"height\":2},";
    ofs << "{\"hash\":\"" << epee::string_tools::pod_to_hex(wrong_4) << "\",\"height\":4}";
    ofs << "]}";
  }

  // The walk must COMPLETE: the height-2 conflict rolls back to the
  // genesis-only chain (target floored at DB height 1), and the walk then
  // stops instead of testing the height-4 entry against the stale
  // pre-rollback height. Pre-fix, either arm escaped as an exception --
  // caught here so the red is a test verdict, not a crashed run.
  bool resolved = false;
  bool threw = false;
  std::string what;
  try
  {
    resolved = bcs.update_checkpoints(json_path.string());
  }
  catch (const std::exception& e)
  {
    threw = true;
    what = e.what();
  }
  boost::filesystem::remove(json_path);

  CHECK_AND_ASSERT_MES(!threw, false,
      "[" << perr_context << "] checkpoint conflict walk threw instead of completing: " << what);
  CHECK_AND_ASSERT_MES(resolved, false,
      "[" << perr_context << "] update_checkpoints reported an unresolvable conflict");

  // Rolled back to the genesis-only chain, and no deeper: genesis survives.
  CHECK_EQ(1, (int)c.get_current_blockchain_height());
  CHECK_TEST_CONDITION(c.get_tail_id() == genesis);

  return true;
}

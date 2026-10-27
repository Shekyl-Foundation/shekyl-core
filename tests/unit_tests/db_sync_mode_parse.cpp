// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// A4 — the durability control must FAIL CLOSED.
//
// The defect these tests pin: `--db-sync-mode` ended its options[0] chain with
// a bare `else db_flags = DEFAULT_FLAGS;` and no diagnostic. DEFAULT_FLAGS is
// DBF_FAST, which db_lmdb maps to MDB_NOSYNC, so a typo like `saf` silently
// selected the LEAST durable mode. A node cannot detect that from its own
// behaviour -- it looks exactly like a node that was asked for `fast`.
//
// Every refusal case below fails against the pre-fix parser: it returned
// success and wrote DBF_FAST.

#include "gtest/gtest.h"

#include "cryptonote_core/cryptonote_core.h"

using namespace cryptonote;

namespace
{
  // The accepted spellings still resolve, so the refusals below are not a
  // parser that rejects everything.
  TEST(DbSyncModeParse, AcceptedModesResolve)
  {
    db_sync_settings out;
    std::string err;

    ASSERT_TRUE(parse_db_sync_mode("safe", false, out, err)) << err;
    EXPECT_EQ(DBF_SAFE, out.db_flags);
    EXPECT_EQ(db_nosync, out.sync_mode);

    ASSERT_TRUE(parse_db_sync_mode("fast", false, out, err)) << err;
    EXPECT_EQ(DBF_FAST, out.db_flags);
    EXPECT_EQ(db_async, out.sync_mode);

    ASSERT_TRUE(parse_db_sync_mode("fastest", false, out, err)) << err;
    EXPECT_EQ(DBF_FASTEST, out.db_flags);
    EXPECT_EQ((uint64_t)1000, out.sync_threshold);
  }

  // What ships is DRS-D9's: the constant core::init opens the store with
  // parses, to the safe flags, and NOT as the default. db_defaultsync is what
  // lets Blockchain::safesyncmode switch MDB_NOSYNC on for a sync; db_nosync
  // leaves the fsync to the store on every commit.
  TEST(DbSyncModeParse, ShippedConstantIsSafeAndNotADefault)
  {
    db_sync_settings out;
    std::string err;
    ASSERT_TRUE(parse_db_sync_mode(SHIPPED_DB_SYNC_MODE, SHIPPED_DB_SYNC_MODE_IS_DEFAULT,
                                   out, err)) << err;
    EXPECT_EQ(DBF_SAFE, out.db_flags);
    EXPECT_EQ(db_nosync, out.sync_mode)
      << "a default sync mode lets a sync turn the fsync off";
    // core::init prints `(int)sync_mode`. BLOCKCHAIN_DB_SYNC_MODE in
    // scripts/bench/drs_artifact.py is this order.
    EXPECT_EQ(0, static_cast<int>(db_defaultsync));
    EXPECT_EQ(1, static_cast<int>(db_sync));
    EXPECT_EQ(2, static_cast<int>(db_async));
    EXPECT_EQ(3, static_cast<int>(db_nosync));
  }

  // THE SUBJECT. A typo for "safe" must not resolve to the least durable mode.
  TEST(DbSyncModeParse, TypoedModeRefusesInsteadOfSelectingNosync)
  {
    db_sync_settings out;
    std::string err;
    EXPECT_FALSE(parse_db_sync_mode("saf", false, out, err));
    EXPECT_NE(std::string::npos, err.find("saf"))
      << "the refusal must name the offending token, not just fail";
    EXPECT_NE(std::string::npos, err.find("safe"))
      << "the refusal must name the accepted set";
    // And the failure must not have written a posture.
    EXPECT_EQ((uint64_t)0, out.db_flags)
      << "a refused parse wrote settings anyway -- the caller would use them";
  }

  // The same defect one field along: options[1] had no `else` at all.
  TEST(DbSyncModeParse, TypoedSyncPolicyRefuses)
  {
    db_sync_settings out;
    std::string err;
    EXPECT_FALSE(parse_db_sync_mode("fast:asnyc", false, out, err));
    EXPECT_NE(std::string::npos, err.find("asnyc"));
  }

  // Already refused before this change; pinned so the three stay consistent.
  TEST(DbSyncModeParse, MalformedThresholdStillRefuses)
  {
    db_sync_settings out;
    std::string err;
    EXPECT_FALSE(parse_db_sync_mode("fast:async:100megabytes", false, out, err));
  }

  // `safe` short-circuits the later fields by design; a trailing typo after it
  // is not read, so it must not refuse -- pinned so the fail-closed change does
  // not quietly widen into a behaviour change.
  TEST(DbSyncModeParse, SafeIgnoresLaterFieldsAsBefore)
  {
    db_sync_settings out;
    std::string err;
    ASSERT_TRUE(parse_db_sync_mode("safe:asnyc:garbage", false, out, err)) << err;
    EXPECT_EQ(DBF_SAFE, out.db_flags);
  }
}

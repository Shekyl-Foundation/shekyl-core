// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The settlement-outcome table (SO-D2 / SO-D4 / SO-D6).
//
// These are the C++ half of the round's §10 evidence. The shadow cutover is
// unavailable by ruling — 2-of-3 over derived challenges is *supposed* to
// disagree with the self-served vin, so agreement would be evidence of a bug —
// which leaves KATs and red tests.
//
// One property is worth naming because it is not obvious from the assertions:
// **every test here is also the SO-D4 gate.** The settlement table is the 49th,
// and `mdb_env_set_maxdbs` was a hand-maintained `48` three hundred lines from
// the opens it counted. That overflow fails at runtime only — it compiles,
// links, and passes every test that never opens a fresh environment. Each
// fixture below opens a fresh environment, so a ceiling that stopped covering
// the table list fails here loudly rather than on someone's node.
//
// Verified by biting it: pinning maxdbs back to a literal 48 fails all six of
// these with MDB_DBS_FULL. Worth knowing what that failure looks like, because
// it does NOT name the table you added — it names `m_output_metadata`, the one
// that happens to be opened last. An overflow always accuses an innocent
// table, which is why the fix was to derive the ceiling rather than to raise
// it and trust the next reader to interpret the error.

#include <limits>
#include "gtest/gtest.h"

#include "archival_lmdb_test_helpers.h"

using archival_test::make_hash;
using archival_test::TempLMDB;

namespace
{
  constexpr uint64_t kShard = 7;
  constexpr uint64_t kEpoch = 3;

  // Mirrors the Rust encoding (shekyl-archival-retention/src/settlement_row.rs).
  // Duplicated as literals ON PURPOSE: this is the cross-language pin, and a
  // test that imported the producer's own constants could not detect the
  // producer changing them.
  constexpr uint8_t kOutcomeServed = 0x01;
  constexpr uint8_t kOutcomeMissed = 0x02;
  constexpr uint8_t kOutcomeNonObservation = 0x03;
}

// SO-D1's forcing case, at the storage layer: a pair whose challenges were all
// issued and none passed settles Missed, and that is a DIFFERENT stored byte
// from the absence an unissued pair leaves behind.
TEST(ArchivalSettlementTable, FullyIssuedFullyFailedStoresMissedNotNonObservation)
{
  TempLMDB t;
  const crypto::hash p = make_hash(0x51);

  t.db.set_archival_settlement(p, kShard, kEpoch, /*passes=*/0, /*issued=*/3);

  std::array<uint8_t, 3> row{};
  ASSERT_TRUE(t.db.get_archival_settlement(p, kShard, kEpoch, row));
  EXPECT_EQ(row[0], kOutcomeMissed)
    << "a fully-issued, fully-failed epoch must store Missed; NonObservation here is "
       "the slash escape SO-D1 exists to close";
  EXPECT_EQ(row[1], 0);
  EXPECT_EQ(row[2], 3);
}

// Absence means "never issued", never "missed" — the invariant SO-D1 makes a
// theorem about the writer rather than an inference about a regime.
TEST(ArchivalSettlementTable, AbsentRowReadsAsAbsentRatherThanAnyOutcome)
{
  TempLMDB t;
  std::array<uint8_t, 3> row{};
  EXPECT_FALSE(t.db.get_archival_settlement(make_hash(0x99), kShard, kEpoch, row));
}

TEST(ArchivalSettlementTable, ServedAndNonObservationAreStoredDistinguishably)
{
  TempLMDB t;
  const crypto::hash served = make_hash(0x61);
  const crypto::hash under_issued = make_hash(0x62);

  t.db.set_archival_settlement(served, kShard, kEpoch, /*passes=*/2, /*issued=*/3);
  t.db.set_archival_settlement(under_issued, kShard, kEpoch, /*passes=*/1, /*issued=*/1);

  std::array<uint8_t, 3> a{}, b{};
  ASSERT_TRUE(t.db.get_archival_settlement(served, kShard, kEpoch, a));
  ASSERT_TRUE(t.db.get_archival_settlement(under_issued, kShard, kEpoch, b));

  EXPECT_EQ(a[0], kOutcomeServed);
  EXPECT_EQ(b[0], kOutcomeNonObservation)
    << "a pair the urn could not reach twice is not a pair that failed (absolute-2)";
  // ...and the under-issued pair still gets a ROW. Auditability beats
  // absence-consistency: the capped regime is where the teeth degrade, and
  // silent degradation is unmeasured degradation.
  EXPECT_EQ(b[2], 1) << "the issued count survives storage — it is an (m, n) input";
}

// C++ never composes an outcome byte, so it cannot store one that contradicts
// its counts. A refused fold must refuse loudly rather than store anything.
TEST(ArchivalSettlementTable, ARefusedFoldStoresNothing)
{
  TempLMDB t;
  const crypto::hash p = make_hash(0x71);

  EXPECT_THROW(
    t.db.set_archival_settlement(p, kShard, kEpoch, /*passes=*/3, /*issued=*/2),
    std::runtime_error);

  std::array<uint8_t, 3> row{};
  EXPECT_FALSE(t.db.get_archival_settlement(p, kShard, kEpoch, row))
    << "a desynced accounting input must leave no row behind";
}

// SO-D6: settlement rows are a memoised derivation, so a reorg deletes them and
// lets the re-connect recompute. The delete must be epoch-scoped — it is a full
// scan filtering the epoch field, because SO-D2 puts the epoch last so the
// outer-window walk can range-scan one pair's epochs in order.
TEST(ArchivalSettlementTable, EpochRevertDropsOnlyThatEpoch)
{
  TempLMDB t;
  const crypto::hash p1 = make_hash(0x81);
  const crypto::hash p2 = make_hash(0x82);

  t.db.set_archival_settlement(p1, kShard, kEpoch, 0, 3);
  t.db.set_archival_settlement(p2, kShard, kEpoch, 2, 3);
  t.db.set_archival_settlement(p1, kShard, kEpoch + 1, 2, 3);
  t.db.set_archival_settlement(p1, kShard + 1, kEpoch, 0, 3);

  t.db.delete_archival_settlement_for_epoch(kEpoch);

  std::array<uint8_t, 3> row{};
  EXPECT_FALSE(t.db.get_archival_settlement(p1, kShard, kEpoch, row));
  EXPECT_FALSE(t.db.get_archival_settlement(p2, kShard, kEpoch, row));
  EXPECT_FALSE(t.db.get_archival_settlement(p1, kShard + 1, kEpoch, row))
    << "the revert is epoch-scoped across every shard, not per (P, shard)";
  EXPECT_TRUE(t.db.get_archival_settlement(p1, kShard, kEpoch + 1, row))
    << "a neighbouring epoch must survive the revert";
}

// The row a fresh write produces must read back byte-identically — the table
// stores what Rust folded, with no C++-side reinterpretation in between.
TEST(ArchivalSettlementTable, RowRoundTripsByteIdentically)
{
  TempLMDB t;
  const crypto::hash p = make_hash(0x91);

  for (uint32_t issued = 0; issued <= 3; ++issued)
  {
    for (uint32_t passes = 0; passes <= issued; ++passes)
    {
      const uint64_t e = 100 + issued * 10 + passes;
      t.db.set_archival_settlement(p, kShard, e, passes, issued);

      std::array<uint8_t, 3> row{};
      ASSERT_TRUE(t.db.get_archival_settlement(p, kShard, e, row));
      EXPECT_EQ(row[1], static_cast<uint8_t>(passes));
      EXPECT_EQ(row[2], static_cast<uint8_t>(issued));
      EXPECT_NE(row[0], 0x00) << "0x00 is reserved for 'not a settlement'";
    }
  }
}

// SO-D6, through the production revert path rather than by argument.
//
// The direct-delete test above proves the epoch-scoped delete works. This one
// proves it is WIRED: a real fold at a real height appends the epoch marker
// that revert_archival_slashes_at_height keys on, and the settlement rows for
// the epoch that fold covered must go with it.
//
// Note what is being asserted and what is not. Settlement rows are a memoised
// derivation over final chain state, so the revert deletes them and lets the
// re-connect recompute -- the close family's shape (r_market, sigma_work,
// budget), not the attestation-witness table's journal, which exists because
// *received* evidence cannot be reproduced on a losing branch.
TEST(ArchivalSettlementTable, SlashRevertDropsEveryEpochInTheFoldedSpanAndRewindsBelowIt)
{
  TempLMDB t;
  cryptonote::BlockchainDB& db = t.db;

  const crypto::hash p = make_hash(0xA1);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;

  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = {0x0A, 0x0B, 0x0C};
  bond.join_settlement_epoch = 2;
  bond.bonded_total_atomic = 2 * floor;
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  bond.held_shard_ids = {kShard};
  // Parallel to held_shard_ids and checked at encode -- the v6 coupling.
  bond.shard_add_epochs.assign(bond.held_shard_ids.size(), bond.join_settlement_epoch);
  db.put_archival_bond_value(p, bond);
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  // A height strictly past epoch kEpoch's slash deadline, so the fold covers
  // epochs 0..kEpoch ascending and leaves kEpoch as the height's epoch marker.
  const uint64_t fold_height = shekyl_archival_epoch_slash_deadline_height(kEpoch) + 1;
  db.process_archival_slash_at_height(fold_height);
  ASSERT_EQ(db.get_archival_last_slash_epoch(), kEpoch)
    << "fixture assumption: the fold must have advanced to kEpoch, or the revert "
       "below is not exercising the marker path at all";

  // A row for EVERY epoch the fold covered, not just the last one, plus a
  // later epoch the revert must not touch.
  //
  // Seeding only the last epoch is what let this pass while the revert was
  // scoped to a single epoch: the fold covers 0..kEpoch, and the marker used
  // to record only kEpoch, so every earlier epoch's rows survived a pop that
  // had just undone the slashes they were derived from.
  for (uint64_t e = 0; e <= kEpoch; ++e)
    t.db.set_archival_settlement(p, kShard, e, /*passes=*/0, /*issued=*/3);
  t.db.set_archival_settlement(p, kShard, kEpoch + 1, /*passes=*/2, /*issued=*/3);

  std::array<uint8_t, 3> row{};
  for (uint64_t e = 0; e <= kEpoch; ++e)
    ASSERT_TRUE(t.db.get_archival_settlement(p, kShard, e, row))
      << "fixture premise: epoch " << e << " must have a row before the revert";

  db.revert_archival_slashes_at_height(fold_height);

  for (uint64_t e = 0; e <= kEpoch; ++e)
    EXPECT_FALSE(t.db.get_archival_settlement(p, kShard, e, row))
      << "epoch " << e << "'s settlement row survived a revert of the height that "
         "folded it; a derived value outliving the state it derives from";
  EXPECT_TRUE(t.db.get_archival_settlement(p, kShard, kEpoch + 1, row))
    << "and only the folded span -- the revert is scoped to what this height did";

  // The other half of the same defect, and the consequential one: the rewind
  // must go below the FIRST epoch folded, not the last. Rewound to kEpoch - 1,
  // the reconnect restarts at kEpoch and never re-applies the slashes for
  // 0..kEpoch-1 that this same pop just undid.
  EXPECT_EQ(db.get_archival_last_slash_epoch(), std::numeric_limits<uint64_t>::max())
    << "the fold started at epoch 0, so the rewind must leave nothing folded; "
       "any other value means epochs were reverted and will never be redone";
}

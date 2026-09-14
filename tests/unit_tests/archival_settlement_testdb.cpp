// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The BlockchainDB test double's settlement surface (SO-D8 promotion,
// ARCHIVAL_SETTLEMENT_WRITER.md §12) must round-trip, refuse, and delete —
// not no-op. The defect this pins against (review, 2026-09-13): a double whose
// write is a silent no-op and whose read returns "absent" lets a test write a
// row, read it back missing, and PASS, because SO-D1 defines absence as
// NON-OBSERVATION — the most forgiving verdict. That is the SO-D5 inversion
// (failure_window.rs) surfacing in a test double: the serve-credit doubles may
// no-op because absence there is a MISS; the settlement doubles may not.
//
// Red edit for each test: revert BaseTestDB's four settlement overrides to
// `{}` / `return false`.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <array>
#include <stdexcept>

#include "blockchain_db/testdb.h"
#include "shekyl/shekyl_ffi.h"

namespace
{

struct SettlementTestDB final : public cryptonote::BaseTestDB {};

crypto::hash p_id_of(uint8_t fill)
{
  crypto::hash h{};
  std::memset(h.data, fill, sizeof(h.data));
  return h;
}

using row_t = std::array<uint8_t, SHEKYL_ARCHIVAL_SETTLEMENT_ROW_BYTES>;

} // namespace

TEST(archival_settlement_testdb, write_then_read_returns_the_row_that_was_written)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x11);

  row_t before{};
  ASSERT_FALSE(db.get_archival_settlement(p, 7, 3, before)) << "fresh double must report absent";

  db.set_archival_settlement(p, 7, 3, /*passes=*/2, /*issued=*/3);

  row_t stored{};
  ASSERT_TRUE(db.get_archival_settlement(p, 7, 3, stored))
    << "a written row read back as absent is SO-D1 non-observation produced silently";

  // The double folds through the same encoder LMDB does, so the stored bytes
  // are the canonical row for (2, 3) and re-validate as such.
  row_t expected{};
  ASSERT_EQ(0u, shekyl_archival_settlement_row(2, 3, expected.data()));
  EXPECT_EQ(expected, stored);
  EXPECT_EQ(0u, shekyl_archival_settlement_row_validate(stored[0], stored[1], stored[2]));
}

TEST(archival_settlement_testdb, key_is_the_full_pair_epoch_triple)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x22);
  db.set_archival_settlement(p, 7, 3, 2, 3);

  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p_id_of(0x23), 7, 3, out)) << "different P_id";
  EXPECT_FALSE(db.get_archival_settlement(p, 8, 3, out)) << "different shard";
  EXPECT_FALSE(db.get_archival_settlement(p, 7, 4, out)) << "different epoch";
  EXPECT_TRUE(db.get_archival_settlement(p, 7, 3, out));
}

TEST(archival_settlement_testdb, refuses_what_the_encoder_refuses)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x33);

  // passes > issued (code 2) and issued == 0 (code 4, SO-D1) both throw, and
  // the refused write leaves no row behind — C++ never composes an outcome.
  EXPECT_THROW(db.set_archival_settlement(p, 1, 1, /*passes=*/4, /*issued=*/3), std::runtime_error);
  EXPECT_THROW(db.set_archival_settlement(p, 1, 1, /*passes=*/0, /*issued=*/0), std::runtime_error);
  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p, 1, 1, out));
}

TEST(archival_settlement_testdb, delete_for_epoch_removes_exactly_that_epoch)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x44);
  db.set_archival_settlement(p, 1, 5, 3, 3);
  db.set_archival_settlement(p, 2, 5, 3, 3);
  db.set_archival_settlement(p, 1, 6, 3, 3);

  db.delete_archival_settlement_for_epoch(5);

  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p, 1, 5, out));
  EXPECT_FALSE(db.get_archival_settlement(p, 2, 5, out));
  EXPECT_TRUE(db.get_archival_settlement(p, 1, 6, out)) << "SO-D6 revert is per-epoch, not a wipe";
}

TEST(archival_settlement_testdb, delete_before_epoch_is_strictly_below)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x55);
  db.set_archival_settlement(p, 1, 4, 3, 3);
  db.set_archival_settlement(p, 1, 5, 3, 3);
  db.set_archival_settlement(p, 1, 6, 3, 3);

  db.delete_archival_settlement_before_epoch(5);

  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p, 1, 4, out));
  EXPECT_TRUE(db.get_archival_settlement(p, 1, 5, out)) << "prune_below_epoch is exclusive";
  EXPECT_TRUE(db.get_archival_settlement(p, 1, 6, out));
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// BaseTestDB is not a settlement store. Absence is SO-D1 non-observation —
// the most forgiving verdict — so a silent no-op write would let a test pass
// after a failed store. Write therefore throws; read stays absent; deletes
// are empty. Working-store KATs live on TempLMDB
// (tests/unit_tests/archival_settlement_table.cpp).
//
// Red edit: replace set_archival_settlement's body with `{}` (the fail-open
// double). Both EXPECT_THROW tests go red — that is this file catching the
// silent no-op it exists to refuse. The absent-read and empty-delete tests
// stay green under that edit, which is why they cannot carry the check alone.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <array>
#include <cstring>
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

TEST(archival_settlement_testdb, set_throws_on_a_canonical_fold)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x11);
  // A valid (passes, issued) pair — not an encoder refusal. The double is
  // not a store; TempLMDB is.
  EXPECT_THROW(db.set_archival_settlement(p, 7, 3, /*passes=*/2, /*issued=*/3),
    std::runtime_error);
}

TEST(archival_settlement_testdb, get_reports_absent)
{
  SettlementTestDB db;
  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p_id_of(0x22), 7, 3, out));
}

TEST(archival_settlement_testdb, a_thrown_write_leaves_no_row)
{
  SettlementTestDB db;
  const crypto::hash p = p_id_of(0x33);
  EXPECT_THROW(db.set_archival_settlement(p, 1, 1, 2, 3), std::runtime_error);
  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p, 1, 1, out))
    << "a refused write must not become SO-D1 non-observation of a stored row";
}

TEST(archival_settlement_testdb, deletes_are_empty)
{
  SettlementTestDB db;
  EXPECT_NO_THROW(db.delete_archival_settlement_for_epoch(5));
  EXPECT_NO_THROW(db.delete_archival_settlement_before_epoch(5));
  row_t out{};
  EXPECT_FALSE(db.get_archival_settlement(p_id_of(0x44), 1, 5, out));
}

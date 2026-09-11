// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// DRS-P0d: layout-independent logical state digest v0 against production
// LMDB. This bites against X; it does NOT cover Y:
//
//   X — the walker reads the three v0 families (height-ordered
//       block_info hashes, spent_keys set, live curve-tree root) and a
//       mutation of those families moves the digest (spent add/remove,
//       miner-only block, grow_curve_tree); a mutation of a named-
//       excluded table (txpool) does not; spent_keys add/remove is
//       pop-symmetric.
//   Y — archival-journal apply/revert (named exclusion, §7.1.1); P0e
//       totality; CHECKED-CONFORMANT promotion (P0f).

#include "gtest/gtest.h"

#include "archival_lmdb_test_helpers.h"
#include "blockchain_db/shekyl_types.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "net/enums.h"

#include <vector>

namespace {

crypto::key_image key_image_with_first_byte(uint8_t b)
{
  crypto::key_image ki{};
  ki.data[0] = static_cast<char>(b);
  return ki;
}

} // namespace

TEST(LogicalStateDigestV0, EmptyOpenIsStable)
{
  archival_test::TempLMDB fixture;
  const auto a = fixture.db.logical_state_digest_v0();
  const auto b = fixture.db.logical_state_digest_v0();
  EXPECT_EQ(a, b);
}

TEST(LogicalStateDigestV0, SpentKeyAddAndRemoveIsPopSymmetric)
{
  archival_test::TempLMDB fixture;
  const auto empty = fixture.db.logical_state_digest_v0();
  const crypto::key_image ki = key_image_with_first_byte(1);

  fixture.db.digest_v0_add_spent_key(ki);
  const auto with_ki = fixture.db.logical_state_digest_v0();
  EXPECT_NE(empty, with_ki);

  fixture.db.digest_v0_remove_spent_key(ki);
  const auto restored = fixture.db.logical_state_digest_v0();
  EXPECT_EQ(empty, restored);
}

TEST(LogicalStateDigestV0, SpentKeySetIsOrderIndependent)
{
  archival_test::TempLMDB ab;
  archival_test::TempLMDB ba;
  const crypto::key_image ki_a = key_image_with_first_byte(1);
  const crypto::key_image ki_b = key_image_with_first_byte(2);

  ab.db.digest_v0_add_spent_key(ki_a);
  ab.db.digest_v0_add_spent_key(ki_b);
  ba.db.digest_v0_add_spent_key(ki_b);
  ba.db.digest_v0_add_spent_key(ki_a);

  EXPECT_EQ(ab.db.logical_state_digest_v0(), ba.db.logical_state_digest_v0());
}

TEST(LogicalStateDigestV0, MinerOnlyBlockMovesTheChainComponent)
{
  archival_test::TempLMDB fixture;
  cryptonote::HardFork hf(fixture.db, 1, 0);
  hf.init();
  fixture.db.set_hard_fork(&hf);
  const auto before = fixture.db.logical_state_digest_v0();
  archival_test::append_minimal_blocks(fixture.db, 1);
  const auto after = fixture.db.logical_state_digest_v0();
  EXPECT_NE(before, after);
  EXPECT_EQ(1u, fixture.db.height());
}

TEST(LogicalStateDigestV0, GrowCurveTreeMovesTheRoot)
{
  archival_test::TempLMDB fixture;
  cryptonote::BlockchainDB& db = fixture.db;
  const auto before = fixture.db.logical_state_digest_v0();
  std::vector<uint8_t> leaf(shekyl::db::kLeafSize, 0x11);
  db.grow_curve_tree(leaf, 1);
  const auto after = fixture.db.logical_state_digest_v0();
  EXPECT_NE(before, after);
}

TEST(LogicalStateDigestV0, TxpoolWriteIsOutsideV0Coverage)
{
  // Named exclusion: txpool is not a v0 family. This bites against a
  // walker that accidentally hashed every table. It does NOT cover the
  // archival-journal exclusion — that stays a spec/gate claim until P0e.
  archival_test::TempLMDB fixture;
  const auto before = fixture.db.logical_state_digest_v0();

  crypto::hash txid{};
  txid.data[0] = 1;
  cryptonote::txpool_tx_meta_t meta{};
  meta.set_relay_method(cryptonote::relay_method::stem);
  const cryptonote::blobdata blob = "not-a-real-tx";
  fixture.db.add_txpool_tx(txid, cryptonote::blobdata_ref{blob}, meta);

  const auto after = fixture.db.logical_state_digest_v0();
  EXPECT_EQ(before, after);
}

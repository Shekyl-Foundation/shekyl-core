// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The tx_extra PQC field shape rule (GENESIS_TX_WIRE_FORMAT.md §9.6a as ruled
// 2026-09-05; census CEN-I19): with n = vout.size(), a transaction carries
// EXACTLY ONE 0x06 KEM-ciphertext field of 1120·n bytes and EXACTLY ONE 0x07
// leaf-hash field of 32·n bytes when n > 0, and neither field when n == 0.
//
// The rule's two admission gates, the relay/block semantic check and the
// coinbase prevalidation, reach the Rust owner of the rule
// (check_pqc_field_shape_of), and Rust pins every vector they carried:
// shekyl-wire's tx_extra tests (conforming_shapes_pass,
// rick_s_vectors_are_refused, over_parsed_fields_the_same_rule) and
// shekyl-chain-rules' tx_extra_tests.rs (the I19 rows at Lone, Listed and
// Miner, the parse arm included). What stays here is the third gate: the
// LMDB collector below admission, which the store flip deletes with it.

#include "gtest/gtest.h"

#include <cstdint>
#include <exception>

#include "cryptonote_basic/cryptonote_format_utils.h"

#include "archival_lmdb_test_helpers.h"
#include "pqc_spend_fixture.h"

using namespace cryptonote;
using archival_test::TempLMDB;
using archival_test::append_minimal_blocks;
using archival_test::connect_block_with_txs;

namespace
{

constexpr size_t KEM = SHEKYL_HYBRID_KEM_CT_BYTES;   // 1120
constexpr size_t LEAF = SHEKYL_PQC_LEAF_ENTRY_BYTES; // 64 (CM || record, PL-D3)

using shekyl_test_fixtures::append_pqc_kem_field;
using shekyl_test_fixtures::append_pqc_leaf_field;

void append_kem(transaction& tx, size_t bytes) { append_pqc_kem_field(tx, bytes); }
void append_leaf(transaction& tx, size_t bytes) { append_pqc_leaf_field(tx, bytes); }

transaction bare_spend()
{
  return shekyl_test_fixtures::make_pqc_spend(/*with_pqc_fields=*/false);
}

} // namespace

// ---- Gate 3: the DB collector, below admission ------------------------------

TEST(tx_extra_pqc_field_shape, db_collector_refuses_a_short_leaf_entry_field_instead_of_zero_filling)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  append_minimal_blocks(db, 3);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  transaction tx = bare_spend();
  append_kem(tx, KEM * tx.vout.size());
  append_leaf(tx, LEAF * (tx.vout.size() - 1));
  const uint64_t leaves_before = db.get_curve_tree_leaf_count();
  bool threw = false;
  try
  {
    connect_block_with_txs(db, {tx});
  }
  catch (const std::exception&)
  {
    threw = true;
  }
  fixture.db.batch_abort();
  EXPECT_TRUE(threw) << "the collector zero-filled a missing h_pqc into a leaf instead of aborting";
  fixture.db.batch_start();
  EXPECT_EQ(db.get_curve_tree_leaf_count(), leaves_before);
}

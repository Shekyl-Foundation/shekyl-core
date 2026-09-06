// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The tx_extra PQC field shape rule (GENESIS_TX_WIRE_FORMAT.md §9.6a as ruled
// 2026-09-05; census CEN-I19): with n = vout.size(), a transaction carries
// EXACTLY ONE 0x06 KEM-ciphertext field of 1120·n bytes and EXACTLY ONE 0x07
// leaf-hash field of 32·n bytes when n > 0, and neither field when n == 0.
//
// Why a rule and not a convention: 0x07 is the fourth scalar of every
// curve-tree leaf this transaction's outputs become, and 0x06 is the only way
// the recipient can find and decrypt them. Before this rule the DB zero-filled
// a missing or short 0x07 into the tree (a leaf whose PQ binding is to
// nothing -- unspendable, and a leaf set a faithful port would not have
// stored: a silent consensus split) and a short 0x06 simply left the recipient
// unable to see a payment the sender can prove. Both parsers took the FIRST of
// duplicate fields, so the same bytes had two readings.
//
// Three gates, each observed ACCEPTING every vector before the rule landed
// (red-first): the relay/block semantic check (core::check_tx_semantic), the
// coinbase prevalidation on a real-nettype chain (TestnetChain), and the DB
// collector below admission (the fail-open itself, now abort-unreachable).
// The serve-credit transaction (vout empty, extra empty) is the MUST-ACCEPT
// control: it is what proves the rule cannot halt the chain.

#include "gtest/gtest.h"

#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "string_tools.h"

#include "archival_lmdb_test_helpers.h"
#include "pqc_spend_fixture.h"
#include "testnet_chain_fixture.h"

using namespace cryptonote;
using shekyl_test_fixtures::TestnetChain;
using archival_test::TempLMDB;
using archival_test::append_minimal_blocks;
using archival_test::connect_block_with_txs;

namespace
{

constexpr size_t KEM = HYBRID_KEM_CT_BYTES;      // 1120
constexpr size_t LEAF = PQC_LEAF_HASH_BYTES;     // 32

using shekyl_test_fixtures::append_pqc_kem_field;
using shekyl_test_fixtures::append_pqc_leaf_field;
using shekyl_test_fixtures::strip_pqc_fields;

void append_kem(transaction& tx, size_t bytes) { append_pqc_kem_field(tx, bytes); }
void append_leaf(transaction& tx, size_t bytes) { append_pqc_leaf_field(tx, bytes); }

// The spend fixture is conforming as built (one field of each for its
// outputs). Every vector starts from the stripped shape and adds back exactly
// what it wants to test.
transaction conforming_spend()
{
  return shekyl_test_fixtures::make_pqc_spend();
}

transaction bare_spend()
{
  transaction tx = shekyl_test_fixtures::make_pqc_spend();
  strip_pqc_fields(tx);
  return tx;
}

bool semantic_accepts(const transaction& tx)
{
  tx_verification_context tvc{};
  return core::check_tx_semantic(tx, tvc, 1) && !tvc.m_verifivation_failed;
}

transaction load_serve_credit_fixture()
{
  std::ifstream ifs(SERVE_CREDIT_TX_PARITY_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing tx parity fixture at ") + SERVE_CREDIT_TX_PARITY_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  // Each accessor is guarded before it is used: rapidjson asserts (or worse,
  // in a release build) when a member is read off a non-object or a string is
  // read off a non-string. A malformed fixture must fail this test loudly and
  // by name -- the must-accept control silently degrading into "no fixture,
  // nothing checked" is the failure mode that matters here.
  const std::string where = SERVE_CREDIT_TX_PARITY_FIXTURE_PATH;
  if (doc.HasParseError() || !doc.IsObject())
    throw std::runtime_error("tx parity fixture is not a JSON object: " + where);
  if (!doc.HasMember("tx_hex") || !doc["tx_hex"].IsString())
    throw std::runtime_error("tx parity fixture has no string tx_hex: " + where);
  std::string blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(doc["tx_hex"].GetString(), blob))
    throw std::runtime_error("tx parity fixture tx_hex is not hex: " + where);
  transaction tx;
  if (!parse_and_validate_tx_from_blob(blob, tx))
    throw std::runtime_error("tx parity fixture tx does not parse: " + where);
  return tx;
}

} // namespace

// ---- Gate 1: the relay/block semantic check --------------------------------

TEST(tx_extra_pqc_field_shape, control_conforming_spend_is_accepted)
{
  EXPECT_TRUE(semantic_accepts(conforming_spend()));
}

TEST(tx_extra_pqc_field_shape, control_serve_credit_with_no_outputs_and_no_fields_is_accepted)
{
  const transaction tx = load_serve_credit_fixture();
  ASSERT_TRUE(tx.vout.empty());
  ASSERT_TRUE(tx.extra.empty());
  EXPECT_TRUE(semantic_accepts(tx));
}

// The zero-output arm, at the layer that reaches it. The Rust validator cannot
// exercise this: every zero-output shape it accepts is a serve-credit fee-only
// transaction, whose own arm refuses a mutated fixture first. Here the shape
// rule runs earlier, so it is the rule that speaks.
TEST(tx_extra_pqc_field_shape, rejects_a_pqc_field_on_a_transaction_with_no_outputs)
{
  transaction tx = load_serve_credit_fixture();
  ASSERT_TRUE(tx.vout.empty());
  append_leaf(tx, LEAF);
  EXPECT_FALSE(semantic_accepts(tx)) << "a zero-output tx carrying 0x07 was accepted";
}

TEST(tx_extra_pqc_field_shape, rejects_a_kem_field_on_a_transaction_with_no_outputs)
{
  transaction tx = load_serve_credit_fixture();
  ASSERT_TRUE(tx.vout.empty());
  append_kem(tx, KEM);
  EXPECT_FALSE(semantic_accepts(tx)) << "a zero-output tx carrying 0x06 was accepted";
}

TEST(tx_extra_pqc_field_shape, rejects_duplicate_leaf_hash_field)
{
  transaction tx = conforming_spend();
  append_leaf(tx, LEAF * tx.vout.size());
  EXPECT_FALSE(semantic_accepts(tx)) << "two 0x07 fields: the bytes admit two readings";
}

TEST(tx_extra_pqc_field_shape, rejects_duplicate_kem_field)
{
  transaction tx = conforming_spend();
  append_kem(tx, KEM * tx.vout.size());
  EXPECT_FALSE(semantic_accepts(tx)) << "two 0x06 fields";
}

TEST(tx_extra_pqc_field_shape, rejects_leaf_hash_field_one_output_long)
{
  transaction tx = bare_spend();
  append_kem(tx, KEM * tx.vout.size());
  append_leaf(tx, LEAF * (tx.vout.size() + 1));
  EXPECT_FALSE(semantic_accepts(tx)) << "0x07 at 32*(n+1)";
}

TEST(tx_extra_pqc_field_shape, rejects_leaf_hash_field_one_output_short)
{
  transaction tx = bare_spend();
  ASSERT_GE(tx.vout.size(), 1u);
  append_kem(tx, KEM * tx.vout.size());
  append_leaf(tx, LEAF * (tx.vout.size() - 1));
  EXPECT_FALSE(semantic_accepts(tx)) << "0x07 at 32*(n-1): the shape the DB used to zero-fill";
}

TEST(tx_extra_pqc_field_shape, rejects_kem_field_one_output_long)
{
  transaction tx = bare_spend();
  append_kem(tx, KEM * (tx.vout.size() + 1));
  append_leaf(tx, LEAF * tx.vout.size());
  EXPECT_FALSE(semantic_accepts(tx)) << "0x06 at 1120*(n+1)";
}

TEST(tx_extra_pqc_field_shape, rejects_kem_field_one_output_short)
{
  transaction tx = bare_spend();
  ASSERT_GE(tx.vout.size(), 1u);
  append_kem(tx, KEM * (tx.vout.size() - 1));
  append_leaf(tx, LEAF * tx.vout.size());
  EXPECT_FALSE(semantic_accepts(tx)) << "0x06 at 1120*(n-1): the recipient never sees the last output";
}

TEST(tx_extra_pqc_field_shape, rejects_both_fields_absent_with_outputs)
{
  const transaction tx = bare_spend();
  ASSERT_FALSE(tx.vout.empty());
  EXPECT_FALSE(semantic_accepts(tx)) << "outputs with neither field";
}

// ---- Gate 2: the coinbase, on a real-nettype chain --------------------------

TEST(tx_extra_pqc_field_shape, coinbase_with_duplicate_leaf_hash_field_is_rejected_before_writing)
{
  TestnetChain chain;
  block_verification_context bvc{};
  ASSERT_TRUE(chain.mine_next(bvc));
  const uint64_t height_before = chain.bc.get_current_blockchain_height();

  block b;
  ASSERT_TRUE(chain.make_template(b));
  append_leaf(b.miner_tx, LEAF * b.miner_tx.vout.size());
  EXPECT_FALSE(chain.submit(b, bvc)) << "a coinbase with two 0x07 fields connected";
  EXPECT_TRUE(bvc.m_verifivation_failed);
  EXPECT_EQ(chain.bc.get_current_blockchain_height(), height_before);

  ASSERT_TRUE(chain.mine_next(bvc)) << "the honest template after the rejected one";
}

// ---- Gate 3: the DB collector, below admission ------------------------------

TEST(tx_extra_pqc_field_shape, db_collector_refuses_a_short_leaf_hash_field_instead_of_zero_filling)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  HardFork hf(db, 1, 0);
  hf.init();
  db.set_hard_fork(&hf);
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

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "blockchain_db/shekyl_types.h"
#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "shekyl/consensus_constants_generated.h"
#include "shekyl/shekyl_ffi.h"
#include "string_tools.h"
#include "serialization/binary_archive.h"

#ifndef GATE4_KAT_FIXTURE_PATH
#define GATE4_KAT_FIXTURE_PATH "rust/shekyl-archival-retention/tests/fixtures/gate4_lifecycle_kat_v1.json"
#endif

using namespace cryptonote;

namespace {

struct Gate4Kat {
  std::string join_wire_hex;
};

Gate4Kat load_gate4_kat()
{
  std::ifstream ifs(GATE4_KAT_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing gate-4 KAT fixture at ") + GATE4_KAT_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("join"))
    throw std::runtime_error("invalid gate-4 KAT fixture");

  const auto& join = doc["join"];
  Gate4Kat kat{};
  kat.join_wire_hex = join["wire_hex"].GetString();
  return kat;
}

std::vector<uint8_t> bytes_from_hex(const std::string& hex)
{
  std::string bin;
  if (!epee::string_tools::parse_hexstr_to_binbuff(hex, bin))
    throw std::runtime_error("invalid hex blob");
  return {bin.begin(), bin.end()};
}

txin_archival_bond_post load_join_bond_vin(const std::string& wire_hex)
{
  const std::vector<uint8_t> wire = bytes_from_hex(wire_hex);
  if (wire.empty() || wire[0] != 0x03)
    throw std::runtime_error("expected bond-post vin tag 0x03");
  txin_v vin;
  binary_archive<false> iar({wire.data(), wire.size()});
  if (!::do_serialize(iar, vin) || !std::holds_alternative<txin_archival_bond_post>(vin))
    throw std::runtime_error("failed to deserialize bond-post vin");
  return std::get<txin_archival_bond_post>(vin);
}

class ArchivalBondPostIntegrationDB: public BaseTestDB
{
public:
  ArchivalBondPostIntegrationDB()
  {
    m_open = true;
  }

  bool get_archival_bond_hybrid_pubkey(const crypto::hash& p_id,
    std::vector<uint8_t>& out_pubkey) const override
  {
    const auto it = m_bonds.find(p_id);
    if (it == m_bonds.end())
      return false;
    out_pubkey = it->second.hybrid_pubkey;
    return !out_pubkey.empty();
  }

  bool get_archival_bond_value(const crypto::hash& p_id,
    shekyl::db::ArchivalBondValue& out) const override
  {
    const auto it = m_bonds.find(p_id);
    if (it == m_bonds.end())
      return false;
    out = it->second;
    return true;
  }

  void put_bond(const crypto::hash& p_id, shekyl::db::ArchivalBondValue bond)
  {
    m_bonds[p_id] = std::move(bond);
  }

private:
  struct HashLess {
    bool operator()(const crypto::hash& a, const crypto::hash& b) const
    {
      return memcmp(a.data, b.data, 32) < 0;
    }
  };

  std::map<crypto::hash, shekyl::db::ArchivalBondValue, HashLess> m_bonds;
};

struct BlockchainAndPool
{
  cryptonote::tx_memory_pool txpool;
  cryptonote::Blockchain bc;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
  BlockchainAndPool(): txpool(bc), bc(txpool) {}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
};

bool init_blockchain(Blockchain& bc, BlockchainDB* db)
{
  const cryptonote::test_options test_options = {5000};
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 0);
}

} // namespace

TEST(archival_bond_post, gate4_integration_rejects_p_id_hint_mismatch)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  memset(bond.p_canonical_id.data, 0xEE, sizeof(bond.p_canonical_id.data));

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, bond.hybrid_public_key, bap.bc.get_current_blockchain_height()));
}

TEST(archival_bond_post, gate4_integration_rejects_non_join_post_kind)
{
  txin_archival_bond_post bond = load_join_bond_vin(load_gate4_kat().join_wire_hex);
  bond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Reinstate);

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, bond.hybrid_public_key, bap.bc.get_current_blockchain_height()));
}

TEST(archival_bond_post, gate4_integration_rejects_oversized_hybrid_pubkey)
{
  txin_archival_bond_post bond = load_join_bond_vin(load_gate4_kat().join_wire_hex);
  bond.hybrid_public_key.push_back(0xFF);

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, bond.hybrid_public_key, bap.bc.get_current_blockchain_height()));
}

// The JoinMarket verify export refuses every call.
//
// Ruling on the review of PR #1046 (2026-10-12; docs/design/FN_DSA_HYBRID.md
// FND-17, FND-20): the receipt key is mandatory. A JoinMarket has one wire
// form (post_kind 5) and it commits a receipt key; this export's signature
// carries none, and the keyless kind this daemon builds (post_kind 0) is
// retired. So the Rust side verifies no JoinMarket from these arguments and
// answers ERR_POST_KIND whatever the post says. The daemon's JoinMarket branch
// in check_archival_bond_post_input is dead until DEL-008 removes it; this
// pins the refusal so nobody "fixes" it back into an accept.
//
// Was: ffi_maps_each_bond_post_error_code mapped a well-formed join to OK and
// each defect to its own code through this export. Those verdicts are the Rust
// validator's (shekyl-chain-rules, CEN-J12/J14/J28).
TEST(archival_bond_post, join_market_verify_ffi_refuses_every_call)
{
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t shard = 42;
  const std::vector<uint8_t> spend_pk(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xE5);
  const std::vector<uint8_t> endpoint(32, 0x0E);

  auto verify = [&](uint8_t post_kind, uint8_t holdings_kind, const uint64_t* shards, size_t shard_len,
    uint64_t total, uint64_t credit, uint64_t debit, uint8_t record_exists) {
    return shekyl_archival_verify_join_market_bond_post(
      post_kind, holdings_kind, shards, shard_len, spend_pk.data(), spend_pk.size(),
      endpoint.data(), endpoint.size(), total, credit, debit, record_exists);
  };
  // What was the accept, under the retired keyless kind and under kind 5.
  EXPECT_EQ(verify(0, 0, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  EXPECT_EQ(verify(5, 0, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  // Another kind's byte, and posts that used to be refused for their own reasons.
  EXPECT_EQ(verify(1, 0, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  EXPECT_EQ(verify(0, 99, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  EXPECT_EQ(verify(0, 0, &shard, 1, floor + 1, floor + 1, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  EXPECT_EQ(verify(0, 0, &shard, 1, floor, floor, 0, 1), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  EXPECT_NE(SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND, SHEKYL_ARCHIVAL_BOND_POST_OK);
}

// The one row of the old error-code table whose subject is still live: the
// Release export refuses a debit that carries a key (gate-4 §9.11 coupling).
// The JoinMarket rows that stood beside it are gone with the test above.
TEST(archival_bond_post, ffi_maps_each_bond_post_error_code)
{
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const std::vector<uint8_t> spend_pk(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xE5);
  EXPECT_EQ(shekyl_archival_verify_release_bond_post(
      static_cast<uint8_t>(archival_bond_post_kind::Release), 0, nullptr, 0,
      spend_pk.data(), spend_pk.size(), 0, 0, floor, 1, floor, 0, nullptr, 0,
      UINT64_MAX, 0),
    SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING);
}

TEST(archival_bond_post, serve_credit_epoch_ok_ffi_boundary)
{
  EXPECT_EQ(shekyl_archival_serve_credit_epoch_ok(0, 0), 0u);
  EXPECT_EQ(shekyl_archival_serve_credit_epoch_ok(1, 0), 1u);
  EXPECT_EQ(shekyl_archival_serve_credit_epoch_ok(0, 1), 0u);
  EXPECT_EQ(shekyl_archival_serve_credit_epoch_ok(UINT64_MAX, UINT64_MAX - 1), 1u);
  EXPECT_EQ(shekyl_archival_serve_credit_epoch_ok(UINT64_MAX - 1, UINT64_MAX - 1), 0u);
  EXPECT_EQ(shekyl_archival_serve_credit_epoch_ok(UINT64_MAX, UINT64_MAX), 0u);
}


// ── GF-1 debit authorization: the discriminating KATs ──────────────────────
//
// The enable flip's pin (gate-4 §3.5 + FOLLOWUPS): "enabled" must mean
// "authorized", not merely "un-rejected". These four arms prove the auth
// discriminates — the record's COMMITTED bond_spend_pk accepts, the identity
// key rejects, a foreign key rejects, and a record committing no key rejects
// everything (fail-closed, never identity fallback).

namespace {

// A never-served, in-good-standing record: the release cooldown and the
// slash-settlement watermark are both vacuously satisfied
// (release_cooldown.rs: None anchor => elapsed; slashes_settled_through:
// None anchor => settled), so the auth arm is the only live gate.
shekyl::db::ArchivalBondValue exited_candidate_record(
  const std::vector<uint8_t>& identity_pk, const std::vector<uint8_t>& committed_spend_pk)
{
  shekyl::db::ArchivalBondValue record{};
  record.hybrid_pubkey = identity_pk;
  record.bond_spend_pk = committed_spend_pk;
  record.join_settlement_epoch = 0;
  record.bonded_total_atomic = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  record.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  record.held_shard_ids = {7};
  record.shard_add_epochs = {0}; // v6 coupling
  return record;
}

txin_archival_bond_post full_release_vin(const std::vector<uint8_t>& identity_pk,
  const crypto::hash& p_id)
{
  txin_archival_bond_post bond{};
  bond.hybrid_public_key = identity_pk;
  bond.p_canonical_id = p_id;
  bond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
  bond.holdings.kind = archival_holdings_kind::ShardSetCompact;
  bond.bonded_total_atomic = 0;
  bond.bond_credit = 0;
  bond.bond_debit = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  return bond;
}

} // namespace

TEST(archival_bond_post, gf1_release_auth_discriminates_on_committed_key)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post join = load_join_bond_vin(kat.join_wire_hex);
  const std::vector<uint8_t>& identity_pk = join.hybrid_public_key;
  const crypto::hash p_id = join.p_canonical_id;
  const std::vector<uint8_t> committed(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xC7);
  const std::vector<uint8_t> foreign(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xD8);

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  db->put_bond(p_id, exited_candidate_record(identity_pk, committed));
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  const txin_archival_bond_post bond = full_release_vin(identity_pk, p_id);
  const uint64_t h = bap.bc.get_current_blockchain_height();

  // The committed debit authorizer accepts — Release verifies end-to-end.
  EXPECT_TRUE(bap.bc.check_archival_bond_post_input(bond, committed, h));
  // The identity key NEVER authorizes a value-out (GF-1 identity-only).
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, identity_pk, h));
  // A foreign key rejects.
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, foreign, h));
}

TEST(archival_bond_post, gf1_release_rejects_record_without_committed_key)
{
  // A record committing no bond_spend_pk (pre-GF-1 shape) authorizes
  // nothing: fail closed, never an identity-key fallback.
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post join = load_join_bond_vin(kat.join_wire_hex);
  const std::vector<uint8_t>& identity_pk = join.hybrid_public_key;
  const crypto::hash p_id = join.p_canonical_id;

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  db->put_bond(p_id, exited_candidate_record(identity_pk, {}));
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  const txin_archival_bond_post bond = full_release_vin(identity_pk, p_id);
  const uint64_t h = bap.bc.get_current_blockchain_height();

  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, identity_pk, h));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond, {}, h));
}


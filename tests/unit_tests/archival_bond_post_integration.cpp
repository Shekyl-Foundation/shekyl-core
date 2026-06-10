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
  std::string p_id_hex;
  std::string bond_pubkey_hex;
  uint64_t join_settlement_epoch = 0;
  uint64_t bond_credit = 0;
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
  kat.p_id_hex = join["p_canonical_id_hex"].GetString();
  kat.join_settlement_epoch = join["join_settlement_epoch"].GetUint64();
  kat.bond_credit = join["bond_credit"].GetUint64();
  if (doc.HasMember("serve_e_first") && doc["serve_e_first"].HasMember("bond_hybrid_pubkey_hex"))
    kat.bond_pubkey_hex = doc["serve_e_first"]["bond_hybrid_pubkey_hex"].GetString();
  return kat;
}

crypto::hash hash_from_hex(const std::string& hex)
{
  std::string bin;
  if (!epee::string_tools::parse_hexstr_to_binbuff(hex, bin) || bin.size() != 32)
    throw std::runtime_error("invalid 32-byte hash hex");
  crypto::hash h{};
  memcpy(h.data, bin.data(), 32);
  return h;
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
  if (wire.empty() || wire[0] != 0x05)
    throw std::runtime_error("expected bond-post vin tag 0x05");
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
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 0, nullptr);
}

} // namespace

TEST(archival_bond_post, gate4_integration_accepts_valid_join_market)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  EXPECT_EQ(bond.p_canonical_id, hash_from_hex(kat.p_id_hex));

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_TRUE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_both_bond_terms)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  bond.bond_debit = bond.bond_credit;

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_debit_without_credit)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  bond.bond_credit = 0;
  bond.bonded_total_atomic = 0;
  bond.bond_debit = 1;

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_existing_bond_record)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  const crypto::hash p_id = bond.p_canonical_id;

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  shekyl::db::ArchivalBondValue existing{};
  existing.hybrid_pubkey = bond.hybrid_public_key;
  existing.join_settlement_epoch = kat.join_settlement_epoch;
  existing.bonded_total_atomic = kat.bond_credit;
  existing.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  existing.held_shard_ids = bond.holdings.shard_ids;
  db->put_bond(p_id, std::move(existing));

  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_p_id_hint_mismatch)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  memset(bond.p_canonical_id.data, 0xEE, sizeof(bond.p_canonical_id.data));

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_floor_mismatch)
{
  const Gate4Kat kat = load_gate4_kat();
  txin_archival_bond_post bond = load_join_bond_vin(kat.join_wire_hex);
  bond.bond_credit += 1;
  bond.bonded_total_atomic = bond.bond_credit;

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_empty_shard_set)
{
  txin_archival_bond_post bond = load_join_bond_vin(load_gate4_kat().join_wire_hex);
  bond.holdings.shard_ids.clear();

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_complete_tree_with_shards)
{
  txin_archival_bond_post bond = load_join_bond_vin(load_gate4_kat().join_wire_hex);
  bond.holdings.kind = archival_holdings_kind::CompleteTree;
  bond.holdings.shard_ids = {1};
  bond.bonded_total_atomic = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.bond_credit = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_non_join_post_kind)
{
  txin_archival_bond_post bond = load_join_bond_vin(load_gate4_kat().join_wire_hex);
  bond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Rebond);

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, gate4_integration_rejects_oversized_hybrid_pubkey)
{
  txin_archival_bond_post bond = load_join_bond_vin(load_gate4_kat().join_wire_hex);
  bond.hybrid_public_key.push_back(0xFF);

  auto db = std::make_unique<ArchivalBondPostIntegrationDB>();
  BlockchainAndPool bap;
  ASSERT_TRUE(init_blockchain(bap.bc, db.release()));
  EXPECT_FALSE(bap.bc.check_archival_bond_post_input(bond));
}

TEST(archival_bond_post, ffi_maps_each_bond_post_error_code)
{
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t shard = 42;

  auto verify = [&](uint8_t post_kind, uint8_t holdings_kind, const uint64_t* shards, size_t shard_len,
    uint64_t total, uint64_t credit, uint64_t debit, uint8_t record_exists) {
    return shekyl_archival_verify_join_market_bond_post(
      post_kind, holdings_kind, shards, shard_len, total, credit, debit, record_exists);
  };

  EXPECT_EQ(verify(0, 0, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_OK);
  EXPECT_EQ(verify(1, 0, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND);
  EXPECT_EQ(verify(0, 0, nullptr, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR);
  EXPECT_EQ(verify(0, 99, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND);
  EXPECT_EQ(verify(0, 0, nullptr, 0, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY);
  EXPECT_EQ(verify(0, 1, &shard, 1, floor, floor, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS);
  EXPECT_EQ(verify(0, 0, &shard, 1, floor, floor, floor, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS);
  EXPECT_EQ(verify(0, 0, &shard, 1, 0, 0, 1, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO);
  EXPECT_EQ(verify(0, 0, &shard, 1, floor + 1, floor + 1, 0, 0), SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH);
  EXPECT_EQ(verify(0, 0, &shard, 1, floor, floor, 0, 1), SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS);
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

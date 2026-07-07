// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <array>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "blockchain_db/shekyl_types.h"
#include "blockchain_db/testdb.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "string_tools.h"
#include "serialization/binary_archive.h"

#ifndef GATE2_KAT_FIXTURE_PATH
#define GATE2_KAT_FIXTURE_PATH "rust/shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json"
#endif

using namespace cryptonote;

namespace {

struct IntegrationKat {
  std::string wire_hex;
  std::string p_id_hex;
  std::string seal_hash_hex;
  std::string bond_pubkey_hex;
  std::string leaf_scalars_hex;
  uint64_t shard_id = 0;
  uint64_t settlement_epoch = 0;
  uint64_t segment_leaf_count = 0;
  uint32_t leaf_index = 0;
  uint64_t freeze_height = 0;
  uint64_t h_seal = 0;
  uint64_t current_height = 0;
  uint64_t join_epoch = 0;
  uint64_t chunk_first_leaf_position = 0;
  uint64_t chunk_leaf_count = 0;
};

IntegrationKat load_integration_kat()
{
  std::ifstream ifs(GATE2_KAT_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing gate-2 KAT fixture at ") + GATE2_KAT_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("integration"))
    throw std::runtime_error("invalid gate-2 KAT fixture");

  const auto& i = doc["integration"];
  IntegrationKat kat{};
  kat.wire_hex = i["wire_hex"].GetString();
  kat.p_id_hex = i["p_canonical_id_hex"].GetString();
  kat.seal_hash_hex = i["block_hash_at_seal_hex"].GetString();
  kat.bond_pubkey_hex = i["bond_hybrid_pubkey_hex"].GetString();
  kat.leaf_scalars_hex = i["leaf_layer_scalars_hex"].GetString();
  kat.shard_id = i["shard_id"].GetUint64();
  kat.settlement_epoch = i["settlement_epoch"].GetUint64();
  kat.segment_leaf_count = i["segment_leaf_count"].GetUint64();
  kat.leaf_index = static_cast<uint32_t>(i["leaf_index_in_segment"].GetUint64());
  kat.freeze_height = i["freeze_height"].GetUint64();
  kat.h_seal = i["h_seal"].GetUint64();
  kat.current_height = i["current_height"].GetUint64();
  kat.join_epoch = i["join_settlement_epoch"].GetUint64();
  kat.chunk_first_leaf_position = i["chunk_first_leaf_position"].GetUint64();
  kat.chunk_leaf_count = i["chunk_leaf_count"].GetUint64();
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

class ArchivalServeCreditIntegrationDB: public BaseTestDB
{
public:
  ArchivalServeCreditIntegrationDB()
  {
    m_open = true;
  }

  void set_seal_hash(uint64_t height, const crypto::hash& hash)
  {
    m_block_hashes[height] = hash;
  }

  crypto::hash get_block_hash_from_height(const uint64_t& height) const override
  {
    const auto it = m_block_hashes.find(height);
    if (it != m_block_hashes.end())
      return it->second;
    crypto::hash h{};
    memset(h.data, 0, sizeof(h.data));
    return h;
  }

  bool has_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch) const override
  {
    return m_credit_bits.count({p_id, shard_id, settlement_epoch}) != 0;
  }

  void set_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch) override
  {
    m_credit_bits.insert({p_id, shard_id, settlement_epoch});
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

  bool archival_bond_holds_shard(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t /*at_height*/) const override
  {
    const auto it = m_bonds.find(p_id);
    return it != m_bonds.end() && it->second.holds_shard(shard_id);
  }

  bool archival_bond_good_through(const crypto::hash& p_id,
    uint64_t settlement_epoch) const override
  {
    const auto it = m_bonds.find(p_id);
    if (it == m_bonds.end())
      return false;
    // Same FFI path production uses: good_through lives in Rust only.
    std::vector<uint64_t> intervals_flat;
    intervals_flat.reserve(it->second.bad_intervals.size() * 2);
    for (const auto& iv : it->second.bad_intervals)
    {
      intervals_flat.push_back(iv.start_epoch);
      intervals_flat.push_back(iv.end_exclusive);
    }
    return shekyl_archival_good_through(it->second.join_settlement_epoch,
      settlement_epoch,
      intervals_flat.empty() ? nullptr : intervals_flat.data(),
      intervals_flat.size() / 2) != 0;
  }

  uint64_t archival_bond_join_epoch(const crypto::hash& p_id) const override
  {
    const auto it = m_bonds.find(p_id);
    if (it == m_bonds.end())
      return std::numeric_limits<uint64_t>::max();
    return it->second.join_settlement_epoch;
  }

  bool get_archival_shard_segment_at_height(uint64_t shard_id, uint64_t at_height,
    crypto::hash& out_rk, uint64_t& out_leaf_count) const override
  {
    const auto it = m_segments.find(shard_id);
    if (it == m_segments.end() || at_height < it->second.freeze_height)
      return false;
    memcpy(out_rk.data, it->second.segment_subroot_rk.data(), 32);
    out_leaf_count = it->second.segment_leaf_count;
    return out_leaf_count > 0;
  }

  // Consensus reads the challenge chunk straight from the curve-tree leaf
  // table (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §6.2); the test DB models
  // that table as a position → 128-byte-leaf map.
  bool get_curve_tree_leaf_by_tree_position(uint64_t tree_position,
    uint8_t* leaf_out) const override
  {
    const auto it = m_tree_leaves.find(tree_position);
    if (it == m_tree_leaves.end())
      return false;
    memcpy(leaf_out, it->second.data(), it->second.size());
    return true;
  }

  void put_bond(const crypto::hash& p_id, shekyl::db::ArchivalBondValue bond)
  {
    m_bonds[p_id] = std::move(bond);
  }

  void put_segment(uint64_t shard_id, shekyl::db::ArchivalShardSegmentValue segment)
  {
    m_segments[shard_id] = std::move(segment);
  }

  void put_tree_leaf(uint64_t tree_position, const uint8_t* leaf_128)
  {
    std::array<uint8_t, 128> leaf{};
    memcpy(leaf.data(), leaf_128, leaf.size());
    m_tree_leaves[tree_position] = leaf;
  }

private:
  struct HashLess {
    bool operator()(const crypto::hash& a, const crypto::hash& b) const
    {
      return memcmp(a.data, b.data, 32) < 0;
    }
  };

  struct CreditKey {
    crypto::hash p_id;
    uint64_t shard_id;
    uint64_t settlement_epoch;
    bool operator<(const CreditKey& other) const
    {
      if (memcmp(p_id.data, other.p_id.data, 32) != 0)
        return memcmp(p_id.data, other.p_id.data, 32) < 0;
      if (shard_id != other.shard_id)
        return shard_id < other.shard_id;
      return settlement_epoch < other.settlement_epoch;
    }
  };

  std::map<uint64_t, crypto::hash> m_block_hashes;
  std::set<CreditKey> m_credit_bits;
  std::map<crypto::hash, shekyl::db::ArchivalBondValue, HashLess> m_bonds;
  std::map<uint64_t, shekyl::db::ArchivalShardSegmentValue> m_segments;
  std::map<uint64_t, std::array<uint8_t, 128>> m_tree_leaves;
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

void seed_substrate(ArchivalServeCreditIntegrationDB& db, const IntegrationKat& kat,
  const txin_archival_serve_credit_response& resp)
{
  const crypto::hash p_id = hash_from_hex(kat.p_id_hex);
  const crypto::hash seal_hash = hash_from_hex(kat.seal_hash_hex);
  const crypto::hash segment_rk = resp.segment_subroot_rk;

  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = bytes_from_hex(kat.bond_pubkey_hex);
  bond.join_settlement_epoch = kat.join_epoch;
  bond.held_shard_ids = {kat.shard_id};
  db.put_bond(p_id, std::move(bond));

  shekyl::db::ArchivalShardSegmentValue segment{};
  segment.freeze_height = kat.freeze_height;
  segment.segment_leaf_count = kat.segment_leaf_count;
  memcpy(segment.segment_subroot_rk.data(), segment_rk.data, 32);
  db.put_segment(kat.shard_id, std::move(segment));

  // Seed the curve-tree leaf table at the chunk positions the consensus read
  // derives via the FFI — and pin that derivation against the fixture's
  // Rust-side values (cross-language tripwire on the chunk arithmetic).
  uint64_t chunk_first = 0;
  uint64_t chunk_leaves = 0;
  if (!shekyl_archival_challenge_leaf_chunk_bounds(kat.shard_id, kat.leaf_index,
        &chunk_first, &chunk_leaves))
    throw std::runtime_error("challenged index out of segment range");
  if (chunk_first != kat.chunk_first_leaf_position || chunk_leaves != kat.chunk_leaf_count)
    throw std::runtime_error("FFI chunk bounds disagree with fixture pin");

  const std::vector<uint8_t> leaf_scalars = bytes_from_hex(kat.leaf_scalars_hex);
  if (leaf_scalars.size() != chunk_leaves * 128)
    throw std::runtime_error("leaf chunk must be exactly chunk_leaf_count * 128 bytes");
  for (uint64_t i = 0; i < chunk_leaves; ++i)
    db.put_tree_leaf(chunk_first + i, leaf_scalars.data() + i * 128);

  db.set_seal_hash(kat.h_seal, seal_hash);
}

txin_archival_serve_credit_response load_serve_credit_vin(const std::string& wire_hex)
{
  const std::vector<uint8_t> wire = bytes_from_hex(wire_hex);
  txin_v vin;
  binary_archive<false> iar({wire.data(), wire.size()});
  if (!::do_serialize(iar, vin)
      || !std::holds_alternative<txin_archival_serve_credit_response>(vin))
  {
    throw std::runtime_error("failed to deserialize serve-credit vin");
  }
  return std::get<txin_archival_serve_credit_response>(vin);
}

} // namespace

TEST(archival_serve_credit, gate2_integration_check_archival_serve_credit_input)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat, resp);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  // init() takes ownership; ~Blockchain deletes the DB in deinit().
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0, nullptr));

  EXPECT_TRUE(bc->check_archival_serve_credit_input(resp, kat.current_height));
}

TEST(archival_serve_credit, gate2_integration_rejects_serve_at_join_epoch)
{
  const IntegrationKat kat = load_integration_kat();
  txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);
  resp.settlement_epoch = kat.join_epoch;

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat, resp);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0, nullptr));

  EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, kat.current_height));
}

TEST(archival_serve_credit, gate2_integration_rejects_duplicate_credit_bit)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);
  const crypto::hash p_id = hash_from_hex(kat.p_id_hex);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat, resp);
  db->set_archival_serve_credit_bit(p_id, kat.shard_id, kat.settlement_epoch);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0, nullptr));

  EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, kat.current_height));
}

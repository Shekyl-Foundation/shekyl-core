// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// ── Serve-credit equivalence audit — C++ leg ──────────────────────────────
//
// ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md §5: this leg drives the LIVE C++
// serve-credit decisions over the shared fixture
// (serve_credit_equivalence_kat_v1.json) and asserts the VERDICT (bool) only —
// that is the whole of what the C++ contract exposes, and accept/reject is
// what forks. The reason/branch column is asserted exclusively by the Rust
// mirror leg (rust/shekyl-archival-retention/tests/serve_credit_equivalence_kat.rs);
// no MERROR_VER log-parsing exists anywhere in this harness by design.
//
// Decision sites under audit (blockchain.cpp at the fixture's pinned
// substrate_commit):
//   D-SC-A  :4247        (P,s,E) dedup vs pre-block LMDB state (BE key)
//   D-SC-B  :4224–4396   check_archival_serve_credit_input (wide gate)
//   D-SC-C  :4889–4910   block-level (P,s,E) uniqueness (BE key, post-SCE-1)

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
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

#ifndef SERVE_CREDIT_EQUIVALENCE_KAT_FIXTURE_PATH
#define SERVE_CREDIT_EQUIVALENCE_KAT_FIXTURE_PATH \
  "rust/shekyl-archival-retention/tests/fixtures/serve_credit_equivalence_kat_v1.json"
#endif
#ifndef GATE2_KAT_FIXTURE_PATH
#define GATE2_KAT_FIXTURE_PATH \
  "rust/shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json"
#endif

using namespace cryptonote;

namespace {

// ── fixture plumbing ───────────────────────────────────────────────────────

rapidjson::Document load_json(const char* path)
{
  std::ifstream ifs(path);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing fixture at ") + path);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError())
    throw std::runtime_error(std::string("invalid JSON fixture at ") + path);
  return doc;
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

std::string hex_from_bytes(const uint8_t* data, size_t len)
{
  return epee::string_tools::buff_to_hex_nodelimer(
    std::string(reinterpret_cast<const char*>(data), len));
}

/// The gate-2 substrate the equivalence fixture's `gate.base` reuses verbatim
/// (wire bytes, bond pubkey, leaf chunk) — the equivalence fixture carries the
/// marshaled Rust-side view; the C++ leg needs the raw material to seed a DB.
struct Gate2Substrate {
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
};

Gate2Substrate load_gate2_substrate()
{
  const rapidjson::Document doc = load_json(GATE2_KAT_FIXTURE_PATH);
  if (!doc.HasMember("integration"))
    throw std::runtime_error("gate-2 fixture missing integration section");
  const auto& i = doc["integration"];
  Gate2Substrate s{};
  s.wire_hex = i["wire_hex"].GetString();
  s.p_id_hex = i["p_canonical_id_hex"].GetString();
  s.seal_hash_hex = i["block_hash_at_seal_hex"].GetString();
  s.bond_pubkey_hex = i["bond_hybrid_pubkey_hex"].GetString();
  s.leaf_scalars_hex = i["leaf_layer_scalars_hex"].GetString();
  s.shard_id = i["shard_id"].GetUint64();
  s.settlement_epoch = i["settlement_epoch"].GetUint64();
  s.segment_leaf_count = i["segment_leaf_count"].GetUint64();
  s.leaf_index = static_cast<uint32_t>(i["leaf_index_in_segment"].GetUint64());
  s.freeze_height = i["freeze_height"].GetUint64();
  s.h_seal = i["h_seal"].GetUint64();
  s.current_height = i["current_height"].GetUint64();
  s.join_epoch = i["join_settlement_epoch"].GetUint64();
  return s;
}

// ── test DB ────────────────────────────────────────────────────────────────

class EquivalenceTestDB: public BaseTestDB
{
public:
  EquivalenceTestDB()
  {
    m_open = true;
  }

  void set_seal_hash(uint64_t height, const crypto::hash& hash)
  {
    m_block_hashes[height] = hash;
  }

  /// LMDB throws BLOCK_DNE when a block hash is absent; the gate's seal read
  /// wraps that in a try/catch (blockchain.cpp `check_archival_serve_credit_input`,
  /// seal-hash step). The `unseeded_seal_throws` setup reproduces the throw.
  void set_throw_at_height(uint64_t height)
  {
    m_throw_height = height;
  }

  crypto::hash get_block_hash_from_height(const uint64_t& height) const override
  {
    if (m_throw_height && height == *m_throw_height)
      throw std::runtime_error("seal block hash unavailable (equivalence-KAT seeded throw)");
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

  // WS-1 as-of-height semantics, same shape as the gate-2 integration mock:
  // held at tip, or removed by a recorded event strictly above at_height.
  bool archival_bond_holds_shard(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t at_height) const override
  {
    const auto rem = m_shard_removed_at.find(shard_id);
    if (rem != m_shard_removed_at.end())
      return at_height < rem->second;
    const auto it = m_bonds.find(p_id);
    return it != m_bonds.end() && it->second.holds_shard(shard_id);
  }

  void set_shard_removed_at(uint64_t shard_id, uint64_t removal_height)
  {
    m_shard_removed_at[shard_id] = removal_height;
  }

  bool archival_bond_good_through(const crypto::hash& p_id,
    uint64_t settlement_epoch) const override
  {
    const auto it = m_bonds.find(p_id);
    if (it == m_bonds.end())
      return false;
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
  std::optional<uint64_t> m_throw_height;
  std::set<CreditKey> m_credit_bits;
  std::map<crypto::hash, shekyl::db::ArchivalBondValue, HashLess> m_bonds;
  std::map<uint64_t, shekyl::db::ArchivalShardSegmentValue> m_segments;
  std::map<uint64_t, std::array<uint8_t, 128>> m_tree_leaves;
  std::map<uint64_t, uint64_t> m_shard_removed_at;
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

/// The gate's own h_fire derivation from the fixture operands — same FFI chain
/// the C++ gate calls (WS-1 h_fire symmetry).
uint64_t derived_fire_height(const Gate2Substrate& s)
{
  const crypto::hash p_id = hash_from_hex(s.p_id_hex);
  const crypto::hash seal_hash = hash_from_hex(s.seal_hash_hex);
  const uint64_t h_open = shekyl_archival_epoch_open_height(s.settlement_epoch);
  const uint64_t h_close = shekyl_archival_epoch_close_height(s.settlement_epoch);
  return shekyl_archival_challenge_fire_height(h_open, h_close,
    reinterpret_cast<const uint8_t*>(seal_hash.data),
    reinterpret_cast<const uint8_t*>(p_id.data),
    s.shard_id, s.settlement_epoch);
}

/// One gate vector, one fresh chain: seed the substrate per `cpp_setup`,
/// apply the fixture's numeric overrides to the response, and return the live
/// gate's verdict. The `cpp_setup` string vocabulary is owned by the fixture;
/// an unknown value fails loudly (a new vector must land with its C++ setup).
bool run_gate_vector(const Gate2Substrate& s, const std::string& cpp_setup,
  const rapidjson::Value& overrides)
{
  txin_archival_serve_credit_response resp = load_serve_credit_vin(s.wire_hex);
  const crypto::hash p_id = hash_from_hex(s.p_id_hex);
  const crypto::hash seal_hash = hash_from_hex(s.seal_hash_hex);
  const uint64_t h_fire = derived_fire_height(s);
  if (h_fire == 0)
    throw std::runtime_error("fixture substrate derives h_fire == 0");

  bool seed_bond = true;
  bool seed_segment = true;
  bool seed_leaves = true;
  bool seed_seal = true;
  std::vector<shekyl::db::ArchivalBondValue::BadInterval> bad_intervals;

  auto db = std::make_unique<EquivalenceTestDB>();

  if (cpp_setup == "baseline" || cpp_setup == "deadline_boundary"
      || cpp_setup == "past_deadline" || cpp_setup == "epoch_at_join"
      || cpp_setup == "leaf_index_oob")
  {
    // Numeric overrides below carry the whole variation.
  }
  else if (cpp_setup == "inflate_c1_layers")
  {
    resp.path.c1_layers.assign(config::ARCHIVAL_MAX_PATH_LAYERS_PER_KIND + 1, {});
  }
  else if (cpp_setup == "fat_c1_branch")
  {
    resp.path.c1_layers.assign(1,
      std::vector<crypto::hash>(config::ARCHIVAL_MAX_BRANCH_SCALARS + 1));
  }
  else if (cpp_setup == "fat_c2_branch")
  {
    resp.path.c2_layers.assign(1,
      std::vector<crypto::hash>(config::ARCHIVAL_MAX_BRANCH_SCALARS + 1));
  }
  else if (cpp_setup == "fat_c1_and_c2_branch")
  {
    resp.path.c1_layers.assign(1,
      std::vector<crypto::hash>(config::ARCHIVAL_MAX_BRANCH_SCALARS + 1));
    resp.path.c2_layers.assign(1,
      std::vector<crypto::hash>(config::ARCHIVAL_MAX_BRANCH_SCALARS + 1));
  }
  else if (cpp_setup == "seed_credit_bit")
  {
    db->set_archival_serve_credit_bit(p_id, s.shard_id, s.settlement_epoch);
  }
  else if (cpp_setup == "omit_bond")
  {
    seed_bond = false;
  }
  else if (cpp_setup == "seed_bad_interval")
  {
    bad_intervals.push_back({s.settlement_epoch, s.settlement_epoch + 1});
  }
  else if (cpp_setup == "unseeded_seal_throws")
  {
    seed_seal = false;
    db->set_throw_at_height(s.h_seal);
  }
  else if (cpp_setup == "removed_at_fire")
  {
    db->set_shard_removed_at(s.shard_id, h_fire);
  }
  else if (cpp_setup == "removed_after_fire")
  {
    db->set_shard_removed_at(s.shard_id, h_fire + 1);
  }
  else if (cpp_setup == "omit_segment")
  {
    seed_segment = false;
  }
  else if (cpp_setup == "omit_leaf_chunk")
  {
    seed_leaves = false;
  }
  else if (cpp_setup == "corrupt_signature")
  {
    if (resp.hybrid_signature.empty())
      throw std::runtime_error("fixture wire carries no signature to corrupt");
    resp.hybrid_signature[0] ^= 0x01;
  }
  else
  {
    throw std::runtime_error("unknown cpp_setup: " + cpp_setup);
  }

  // Numeric overrides shared with the Rust leg (the marshaled-input view).
  uint64_t current_height = s.current_height;
  if (overrides.HasMember("current_height") && overrides["current_height"].IsUint64())
    current_height = overrides["current_height"].GetUint64();
  if (overrides.HasMember("settlement_epoch") && overrides["settlement_epoch"].IsUint64())
    resp.settlement_epoch = overrides["settlement_epoch"].GetUint64();
  if (overrides.HasMember("leaf_index_in_segment")
      && overrides["leaf_index_in_segment"].IsUint64())
    resp.leaf_index_in_segment =
      static_cast<uint32_t>(overrides["leaf_index_in_segment"].GetUint64());

  // Seed the substrate (gate-2 shape). Leaf placement always uses the
  // ORIGINAL challenged index — post-seed response mutations must not move
  // where the chunk actually lives.
  if (seed_bond)
  {
    shekyl::db::ArchivalBondValue bond{};
    bond.hybrid_pubkey = bytes_from_hex(s.bond_pubkey_hex);
    bond.join_settlement_epoch = s.join_epoch;
    bond.held_shard_ids = {s.shard_id};
    bond.shard_add_epochs.assign(bond.held_shard_ids.size(), s.join_epoch); // v6: join-time shards carry E_join
    bond.bad_intervals = std::move(bad_intervals);
    db->put_bond(p_id, std::move(bond));
  }
  if (seed_segment)
  {
    shekyl::db::ArchivalShardSegmentValue segment{};
    segment.freeze_height = s.freeze_height;
    segment.segment_leaf_count = s.segment_leaf_count;
    memcpy(segment.segment_subroot_rk.data(), resp.segment_subroot_rk.data, 32);
    db->put_segment(s.shard_id, std::move(segment));
  }
  if (seed_leaves)
  {
    uint64_t chunk_first = 0;
    uint64_t chunk_leaves = 0;
    if (!shekyl_archival_challenge_leaf_chunk_bounds(s.shard_id, s.leaf_index,
          &chunk_first, &chunk_leaves))
      throw std::runtime_error("fixture challenged index out of segment range");
    const std::vector<uint8_t> leaf_scalars = bytes_from_hex(s.leaf_scalars_hex);
    if (leaf_scalars.size() != chunk_leaves * 128)
      throw std::runtime_error("leaf chunk must be exactly chunk_leaf_count * 128 bytes");
    for (uint64_t i = 0; i < chunk_leaves; ++i)
      db->put_tree_leaf(chunk_first + i, leaf_scalars.data() + i * 128);
  }
  if (seed_seal)
    db->set_seal_hash(s.h_seal, seal_hash);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  if (!bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0, nullptr))
    throw std::runtime_error("Blockchain::init failed");

  return bc->check_archival_serve_credit_input(resp, current_height);
}

} // namespace

// ── D-SC-B (wide gate, composing D-SC-A): live verdict over gate vectors ──

TEST(serve_credit_equivalence, gate_vectors_live_cpp_verdict)
{
  const rapidjson::Document fixture = load_json(SERVE_CREDIT_EQUIVALENCE_KAT_FIXTURE_PATH);
  const Gate2Substrate substrate = load_gate2_substrate();

  // Tripwire: the fixture's marshaled base must be the gate-2 substrate and
  // the shared h_fire derivation, or every verdict below compares different
  // worlds.
  const auto& base = fixture["gate"]["base"];
  ASSERT_EQ(std::string(base["p_canonical_id_hex"].GetString()), substrate.p_id_hex);
  ASSERT_EQ(base["shard_id"].GetUint64(), substrate.shard_id);
  ASSERT_EQ(base["settlement_epoch"].GetUint64(), substrate.settlement_epoch);
  ASSERT_EQ(base["current_height"].GetUint64(), substrate.current_height);
  ASSERT_EQ(base["h_fire"].GetUint64(), derived_fire_height(substrate));

  // Vectors the integration harness structurally cannot reach (marshaling
  // failure paths that cannot be forced through the live gate): the fire-guard
  // window (heights come from the epoch FFI, not the fixture), do_serialize
  // failure on a well-formed variant, and the wire-tag checks (the gate
  // serializes the response itself, so the first byte is always the variant
  // tag). Enumerated here per §5 — recorded, not silently dropped; the Rust
  // mirror leg asserts these branches.
  const std::set<std::string> known_unreachable = {
    "B-13-fire-guard",
    "B-19-serialize-fail",
    "B-20-wrong-tag",
    "B-21-empty-wire",
  };

  size_t driven = 0;
  for (const auto& vec : fixture["gate"]["vectors"].GetArray())
  {
    const std::string id = vec["id"].GetString();
    if (!vec["cpp_reachable"].GetBool())
    {
      EXPECT_TRUE(known_unreachable.count(id) != 0)
        << id << ": new cpp-unreachable vector must be added to the enumerated list";
      continue;
    }
    const std::string cpp_setup = vec["cpp_setup"].GetString();
    const bool expected = vec["expected_verdict"].GetBool();
    bool verdict = false;
    ASSERT_NO_THROW(verdict = run_gate_vector(substrate, cpp_setup, vec["overrides"]))
      << id;
    EXPECT_EQ(verdict, expected) << id << " (cpp_setup=" << cpp_setup << ")";
    ++driven;
  }
  EXPECT_EQ(driven + known_unreachable.size(),
    fixture["gate"]["vectors"].GetArray().Size());
}

// ── D-SC-A: (P,s,E) key bytes pinned at the live ArchivalServeCreditKey ───

TEST(serve_credit_equivalence, dedup_vectors_key_bytes_and_membership)
{
  const rapidjson::Document fixture = load_json(SERVE_CREDIT_EQUIVALENCE_KAT_FIXTURE_PATH);

  for (const auto& vec : fixture["dedup"]["vectors"].GetArray())
  {
    const std::string id = vec["id"].GetString();
    const crypto::hash p_id = hash_from_hex(vec["p_canonical_id_hex"].GetString());
    const uint64_t shard_id = vec["shard_id"].GetUint64();
    const uint64_t epoch = vec["settlement_epoch"].GetUint64();

    // The exact type D-SC-A's LMDB accessors key with (shekyl_types.h).
    const shekyl::db::ArchivalServeCreditKey key(
      reinterpret_cast<const uint8_t*>(p_id.data), shard_id, epoch);
    const MDB_val v = key.as_mdb_val();
    ASSERT_EQ(v.mv_size, shekyl::db::kArchivalServeCreditKeySize) << id;
    const std::string key_hex =
      hex_from_bytes(static_cast<const uint8_t*>(v.mv_data), v.mv_size);
    EXPECT_EQ(key_hex, std::string(vec["expected_key_be_hex"].GetString())) << id;

    // Membership verdict: LMDB's exact-match get over the BE key bytes.
    std::set<std::string> preblock;
    for (const auto& k : vec["preblock_keys_hex"].GetArray())
      preblock.insert(k.GetString());
    EXPECT_EQ(preblock.count(key_hex) != 0, vec["expected_duplicate"].GetBool()) << id;
  }
}

// ── D-SC-C: block-level uniqueness (verbatim transcription) ────────────────
//
// The live pass is an inline loop in handle_block_to_main_chain
// (blockchain.cpp:4889–4910) and cannot be driven in isolation without
// connecting full blocks. Per §5 ("D-SC-C is trivially isolatable — pure, no
// DB") this leg runs a VERBATIM transcription of that loop: the same
// std::unordered_set<std::string> over the same 48-byte
// ArchivalServeCreditKey bytes (the unified big-endian encoding, post-SCE-1
// unify), first-collision-wins. The guard comment at the blockchain.cpp site
// names this test; an edit to the live loop must update both in the same
// commit.

namespace {

struct BlockUniqueOutcome {
  bool unique = true;
  size_t duplicate_index = 0;
  std::string first_key_hex;
};

BlockUniqueOutcome run_block_unique_transcription(
  const std::vector<std::tuple<crypto::hash, uint64_t, uint64_t>>& triples)
{
  BlockUniqueOutcome out{};
  std::unordered_set<std::string> block_serve_credits;
  block_serve_credits.reserve(triples.size());
  size_t index = 0;
  for (const auto& t : triples)
  {
    // Transcribed from blockchain.cpp:4898–4903 (D-SC-C key construction,
    // post-SCE-1-unify: ArchivalServeCreditKey, the D-SC-A encoding).
    const shekyl::db::ArchivalServeCreditKey credit_key(
      reinterpret_cast<const uint8_t*>(std::get<0>(t).data),
      std::get<1>(t), std::get<2>(t));
    std::string key(reinterpret_cast<const char*>(credit_key.bytes().data()),
      credit_key.bytes().size());
    if (index == 0)
      out.first_key_hex = hex_from_bytes(
        reinterpret_cast<const uint8_t*>(key.data()), key.size());
    if (!block_serve_credits.insert(std::move(key)).second)
    {
      out.unique = false;
      out.duplicate_index = index;
      return out;
    }
    ++index;
  }
  return out;
}

} // namespace

TEST(serve_credit_equivalence, block_unique_vectors_verdict_and_key_pin)
{
  const rapidjson::Document fixture = load_json(SERVE_CREDIT_EQUIVALENCE_KAT_FIXTURE_PATH);

  for (const auto& vec : fixture["block_unique"]["vectors"].GetArray())
  {
    const std::string id = vec["id"].GetString();
    std::vector<std::tuple<crypto::hash, uint64_t, uint64_t>> triples;
    for (const auto& t : vec["triples"].GetArray())
    {
      triples.emplace_back(hash_from_hex(t[0].GetString()),
        t[1].GetUint64(), t[2].GetUint64());
    }
    const BlockUniqueOutcome out = run_block_unique_transcription(triples);
    const std::string expected = vec["expected"].GetString();
    if (expected == "unique")
    {
      EXPECT_TRUE(out.unique) << id;
    }
    else
    {
      ASSERT_EQ(expected, "duplicate_at") << id;
      EXPECT_FALSE(out.unique) << id;
      EXPECT_EQ(out.duplicate_index, vec["duplicate_index"].GetUint64()) << id;
    }
    if (vec.HasMember("expected_first_key_be_hex"))
    {
      // Post-SCE-1-unify: the block key is the same BE ArchivalServeCreditKey
      // encoding D-SC-A persists (audit doc §6).
      EXPECT_EQ(out.first_key_hex,
        std::string(vec["expected_first_key_be_hex"].GetString())) << id;
    }
  }
}

// ── SCE-1: the A-vs-C key-encoding split, pinned from the C++ side ────────

TEST(serve_credit_equivalence, sce1_key_encoding_crosscheck)
{
  const rapidjson::Document fixture = load_json(SERVE_CREDIT_EQUIVALENCE_KAT_FIXTURE_PATH);
  const auto& x = fixture["sce1_crosscheck"];

  const crypto::hash p_id = hash_from_hex(x["p_canonical_id_hex"].GetString());
  const uint64_t shard_id = x["shard_id"].GetUint64();
  const uint64_t epoch = x["settlement_epoch"].GetUint64();

  const shekyl::db::ArchivalServeCreditKey be_key(
    reinterpret_cast<const uint8_t*>(p_id.data), shard_id, epoch);
  const MDB_val v = be_key.as_mdb_val();
  const std::string be_hex =
    hex_from_bytes(static_cast<const uint8_t*>(v.mv_data), v.mv_size);

  const BlockUniqueOutcome out =
    run_block_unique_transcription({{p_id, shard_id, epoch}});
  const std::string block_hex = out.first_key_hex;

  EXPECT_EQ(be_hex, std::string(x["key_be_hex"].GetString()));
  EXPECT_EQ(block_hex, std::string(x["key_block_hex"].GetString()));
  // Post-unify, expect_equal is true and load-bearing: the two decision
  // paths must key with the one ArchivalServeCreditKey encoding — a
  // reintroduced split (SCE-1, audit doc §6) fails here.
  EXPECT_EQ(be_hex == block_hex, x["expect_equal"].GetBool());
}

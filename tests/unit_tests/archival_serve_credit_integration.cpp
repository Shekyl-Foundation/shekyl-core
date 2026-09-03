// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <algorithm>
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

#ifndef SERVE_CREDIT_TX_PARITY_FIXTURE_PATH
#define SERVE_CREDIT_TX_PARITY_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json"
#endif
#ifndef GATE2_KAT_FIXTURE_PATH
#define GATE2_KAT_FIXTURE_PATH "rust/shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json"
#endif

using namespace cryptonote;

namespace {

struct IntegrationKat {
  std::string wire_hex;
  std::string p_id_hex;
  std::string seal_hash_hex;
  std::string prev_block_hash_hex;  // PC-D3: the block the index derives from
  std::string bond_pubkey_hex;
  std::string leaf_scalars_hex;
  std::string pruned_hex;      // RF-D1: this vin's pruned record
  std::string segment_rk_hex;  // verifier-derived R_k, recorded by the fixture
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
  kat.prev_block_hash_hex = i["prev_block_hash_hex"].GetString();
  kat.bond_pubkey_hex = i["bond_hybrid_pubkey_hex"].GetString();
  kat.leaf_scalars_hex = i["leaf_layer_scalars_hex"].GetString();
  kat.pruned_hex = i["pruned_hex"].GetString();
  kat.segment_rk_hex = i["segment_subroot_rk_hex"].GetString();
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

  // PC-D3: `check_tx_inputs` reads `height()` and derives the parent hash from
  // it. `BaseTestDB::height()` is a fixed 1, which would put the parent at
  // height 0 -- so a test exercising that read must be able to place the tip.
  void set_chain_height(uint64_t chain_height) { m_chain_height = chain_height; }
  uint64_t height() const override { return m_chain_height; }

  // Every queried height is captured so the seal-committed-guard KAT can assert
  // that an uncommitted-seal credit is rejected BEFORE this read is attempted
  // (the guard short-circuits), not by catching a throw from it.
  mutable std::vector<uint64_t> block_hash_queried_heights;

private:
  uint64_t m_chain_height = 1;

public:

  crypto::hash get_block_hash_from_height(const uint64_t& height) const override
  {
    block_hash_queried_heights.push_back(height);
    const auto it = m_block_hashes.find(height);
    if (it != m_block_hashes.end())
      return it->second;
    crypto::hash h{};
    memset(h.data, 0, sizeof(h.data));
    return h;
  }

  // PC-D4: the double stores per-CHALLENGE rows, keyed by the block too, and
  // answers the two questions separately -- exactly as the LMDB does. A double
  // that collapsed them would let the pair-epoch dedup pass while the real DB
  // failed it.
  bool has_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch, uint64_t block_height) const override
  {
    return m_credit_bits.count({p_id, shard_id, settlement_epoch, block_height}) != 0;
  }

  void set_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch, uint64_t block_height) override
  {
    m_credit_bits.insert({p_id, shard_id, settlement_epoch, block_height});
  }

  uint32_t archival_serve_credit_pass_count(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch) const override
  {
    uint32_t n = 0;
    for (const auto& row : m_credit_bits)
      if (memcmp(row.p_id.data, p_id.data, 32) == 0 && row.shard_id == shard_id
          && row.settlement_epoch == settlement_epoch)
        ++n;
    return n;
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

  // WS-1 (REWARD_EMISSION_E3_GATING_ROUND.md §5): mirror the production
  // as-of-height semantics — held at tip, or removed by a recorded event
  // strictly above at_height (production reconstructs the removal from the
  // slash log; the mock records it directly). Every queried at_height is
  // captured so the acceptance-gate KATs can assert the gate asks about the
  // challenge fire height, not the connect tip.
  bool archival_bond_holds_shard(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t at_height) const override
  {
    holds_shard_queried_heights.push_back(at_height);
    const auto rem = m_shard_removed_at.find(shard_id);
    if (rem != m_shard_removed_at.end())
      return at_height < rem->second;
    const auto it = m_bonds.find(p_id);
    return it != m_bonds.end() && it->second.holds_shard(shard_id);
  }

  /// Record that the bond's holding of `shard_id` was removed at
  /// `removal_height`: held at every height strictly below, not held at or
  /// above (holdings at h are the post-connect state of block h).
  void set_shard_removed_at(uint64_t shard_id, uint64_t removal_height)
  {
    m_shard_removed_at[shard_id] = removal_height;
  }

  mutable std::vector<uint64_t> holds_shard_queried_heights;

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

  // PC-D4: block_height LAST, mirroring the LMDB key's append order, so the
  // set's ordering matches the table's and a pair-epoch run is contiguous.
  struct CreditKey {
    crypto::hash p_id;
    uint64_t shard_id;
    uint64_t settlement_epoch;
    uint64_t block_height;
    bool operator<(const CreditKey& other) const
    {
      if (memcmp(p_id.data, other.p_id.data, 32) != 0)
        return memcmp(p_id.data, other.p_id.data, 32) < 0;
      if (shard_id != other.shard_id)
        return shard_id < other.shard_id;
      if (settlement_epoch != other.settlement_epoch)
        return settlement_epoch < other.settlement_epoch;
      return block_height < other.block_height;
    }
  };

  std::map<uint64_t, crypto::hash> m_block_hashes;
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

void seed_substrate(ArchivalServeCreditIntegrationDB& db, const IntegrationKat& kat)
{
  const crypto::hash p_id = hash_from_hex(kat.p_id_hex);
  const crypto::hash seal_hash = hash_from_hex(kat.seal_hash_hex);
  // RF-D6: R_k is the registry's, never the vin's; the fixture records it.
  const crypto::hash segment_rk = hash_from_hex(kat.segment_rk_hex);

  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = bytes_from_hex(kat.bond_pubkey_hex);
  bond.join_settlement_epoch = kat.join_epoch;
  bond.held_shard_ids = {kat.shard_id};
  bond.shard_add_epochs.assign(bond.held_shard_ids.size(), kat.join_epoch); // v6: join-time shards carry E_join
  db.put_bond(p_id, std::move(bond));

  shekyl::db::ArchivalShardSegmentValue segment{};
  segment.freeze_height = kat.freeze_height;
  segment.segment_leaf_count = kat.segment_leaf_count;
  memcpy(segment.segment_subroot_rk.data(), segment_rk.data, 32);
  db.put_segment(kat.shard_id, std::move(segment));

  // Seed the curve-tree leaf table at the chunk positions the consensus read
  // derives via the FFI — and pin that derivation against the fixture's
  // Rust-side values (cross-language tripwire on the chunk arithmetic).
  // PC-D3 cross-language pin, ahead of the chunk arithmetic: the C++ FFI call
  // must reproduce the fixture's index FROM THE SAME BLOCK. Without this the
  // only symptom of C++ passing the wrong hash (seal_hash is right there, and
  // is a different block) is that the opening fails to verify several hundred
  // lines later -- a prover-shaped failure for a marshaling defect. Asserted
  // on the index itself, which is the axis the defect lives on.
  uint32_t derived_leaf_index = 0;
  const crypto::hash prev_block_hash = hash_from_hex(kat.prev_block_hash_hex);
  const uint8_t leaf_index_rc = shekyl_archival_challenge_leaf_index(
    reinterpret_cast<const uint8_t*>(p_id.data), kat.shard_id, kat.settlement_epoch,
    reinterpret_cast<const uint8_t*>(prev_block_hash.data),
    kat.segment_leaf_count, &derived_leaf_index);
  if (leaf_index_rc != SHEKYL_ARCHIVAL_VERIFY_OK)
    throw std::runtime_error("FFI refused the leaf-index derivation");
  if (derived_leaf_index != kat.leaf_index)
    throw std::runtime_error("FFI leaf index disagrees with fixture pin");

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

// RF-D1 / rule 40: the fixture's `wire_hex` IS the vin's opaque
// `canonical_bytes` (the Rust codec's encoding, tag included); C++ wraps it,
// it does not parse it.
txin_archival_serve_credit_response load_serve_credit_vin(const std::string& wire_hex)
{
  txin_archival_serve_credit_response resp{};
  resp.canonical_bytes = bytes_from_hex(wire_hex);
  if (resp.canonical_bytes.size() < 2 || resp.canonical_bytes[0] != TXIN_ARCHIVAL_SERVE_CREDIT_WIRE_TAG)
    throw std::runtime_error("fixture wire_hex is not a serve-credit blob");
  return resp;
}

// Byte offset of the settlement-epoch varint inside the kept blob, valid while
// `shard_id` encodes as ONE varint byte (the fixture's does: 42): tag(1) +
// p_id(32) + shard(1). A test that needs a different epoch patches this byte
// rather than re-encoding -- C++ has no encoder for the Rust layout by design,
// and a one-byte patch under a pinned fixture is the honest test-only seam.
constexpr size_t KEPT_BLOB_EPOCH_OFFSET = 1 + 32 + 1;

} // namespace

TEST(archival_serve_credit, gate2_integration_check_archival_serve_credit_input)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  // init() takes ownership; ~Blockchain deletes the DB in deinit().
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

  EXPECT_TRUE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.current_height,
    hash_from_hex(kat.prev_block_hash_hex)));
}

/// **`PC-D3`'s production read — the only test that observes it.**
///
/// Every other test in this file calls `check_archival_serve_credit_input`
/// directly and hands it a `prev_block_hash` of its own. None of them touches
/// the read in `check_tx_inputs` that supplies that argument in production, so
/// replacing that read with the null hash leaves all of them green: the read
/// was the one thing the new code does that nothing verified. This test drives
/// the public entry point instead, so the hash comes from the chain.
///
/// It also demonstrates `PC-D2`'s next-block-only property directly: the same
/// record accepted against one tip is refused against another, with nothing on
/// the wire changed. That is the mechanism, not a failure mode.
///
/// The edit that makes this red is any change to which block the derivation
/// reads -- the null hash, the seal hash, `height()` instead of
/// `height() - 1`.
TEST(archival_serve_credit, gate2_check_tx_inputs_derives_the_block_hash_from_the_chain)
{
  const IntegrationKat kat = load_integration_kat();
  const crypto::hash prev_block_hash = hash_from_hex(kat.prev_block_hash_hex);

  // Build the serve-credit tx the way the wire carries it: the opaque kept
  // half on the vin, this vin's pruned record in the prunable region.
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;
  tx.vin.push_back(load_serve_credit_vin(kat.wire_hex));
  tx.ct_signatures.type = ct::CTTypeFcmpPlusPlusPqc;
  tx.ct_signatures.txnFee = 0;
  tx.ct_signatures.p.curve_trees_tree_depth = 0;
  tx.ct_signatures.p.serve_credit_pruned = {bytes_from_hex(kat.pruned_hex)};

  auto run_against_tip = [&](const crypto::hash& tip_hash) {
    auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
    seed_substrate(*db, kat);
    // The slot under validation is `kat.current_height`, so its parent -- the
    // block the derivation reads -- sits at `current_height - 1`.
    db->set_chain_height(kat.current_height);
    db->set_seal_hash(kat.current_height - 1, tip_hash);

    BlockchainAndPool bap;
    cryptonote::Blockchain* bc = &bap.bc;
    const std::pair<uint8_t, uint64_t> hard_forks[] = {
      std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
      std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
    };
    const cryptonote::test_options test_options = {hard_forks, 5000};
    if (!bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0))
      throw std::runtime_error("Blockchain::init failed");

    cryptonote::transaction tx_copy = tx;
    uint64_t max_used_block_height = 0;
    crypto::hash max_used_block_id{};
    cryptonote::tx_verification_context tvc{};
    return bc->check_tx_inputs(tx_copy, max_used_block_height, max_used_block_id, tvc);
  };

  EXPECT_TRUE(run_against_tip(prev_block_hash))
      << "the record does not verify against the block it was derived for; "
         "check_tx_inputs is not reading block_hash(h-1)";

  // A different parent is a different challenge. Nothing on the wire moved.
  crypto::hash other_tip = prev_block_hash;
  other_tip.data[0] ^= 0x01;
  EXPECT_FALSE(run_against_tip(other_tip))
      << "the record verified against a DIFFERENT parent block, so the index "
         "is not block-bound and one response would answer every challenge";
}

TEST(archival_serve_credit, gate2_integration_rejects_serve_at_join_epoch)
{
  const IntegrationKat kat = load_integration_kat();
  txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);
  ASSERT_LT(kat.join_epoch, 0x80u);
  resp.canonical_bytes.at(KEPT_BLOB_EPOCH_OFFSET) = static_cast<uint8_t>(kat.join_epoch);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

  EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.current_height,
    hash_from_hex(kat.prev_block_hash_hex)));
}

// The seal-committed guard: a credit whose challenge-seal block is not yet on
// chain (h_seal >= current_height, i.e. the seal index is at or past the tip) is
// rejected by the explicit predicate BEFORE the block-hash read is attempted —
// not by letting get_block_hash_from_height throw BLOCK_DNE and catching it. The
// accept/reject decision is unchanged (the FFI verifier already rejects any
// current_height <= H_fire, and H_fire > h_seal); this pins that the rejection
// happens at the predicate, and at exactly h_seal, via the read counter.
TEST(archival_serve_credit, gate2_seal_committed_guard_precedes_the_block_hash_read)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);

  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};

  // current_height == h_seal: the seal block's index is one past the tip, so the
  // guard rejects and the block-hash read is never reached.
  {
    auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
    seed_substrate(*db, kat);
    ArchivalServeCreditIntegrationDB* db_raw = db.get();
    BlockchainAndPool bap;
    cryptonote::Blockchain* bc = &bap.bc;
    ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

    db_raw->block_hash_queried_heights.clear(); // ignore any init-time reads
    EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.h_seal,
      hash_from_hex(kat.prev_block_hash_hex)));
    EXPECT_TRUE(db_raw->block_hash_queried_heights.empty());
  }

  // current_height == h_seal + 1: the seal block is now the committed tip, so the
  // guard passes and the read IS reached (the credit is still rejected further
  // downstream on H_fire timing — not what this KAT pins).
  {
    auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
    seed_substrate(*db, kat);
    ArchivalServeCreditIntegrationDB* db_raw = db.get();
    BlockchainAndPool bap;
    cryptonote::Blockchain* bc = &bap.bc;
    ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

    db_raw->block_hash_queried_heights.clear();
    // Guard passes at h_seal + 1 (the seal is now the committed tip), so the gate
    // reaches the seal read exactly once, for h_seal. The credit is still
    // rejected — downstream on H_fire timing (current_height <= H_fire), not by
    // this guard.
    EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.h_seal + 1,
      hash_from_hex(kat.prev_block_hash_hex)));
    ASSERT_EQ(db_raw->block_hash_queried_heights.size(), 1u);
    EXPECT_EQ(db_raw->block_hash_queried_heights[0], kat.h_seal);
  }
}

namespace {

/// The gate's own h_fire derivation, reproduced from the fixture operands.
/// blockchain.cpp (check_archival_serve_credit_input) and db_lmdb.cpp
/// (archival_challenge_failed_at_height) both derive it exactly this way from
/// the same deterministic inputs — the WS-1 h_fire symmetry the acceptance
/// KATs pin against.
uint64_t expected_fire_height(const IntegrationKat& kat)
{
  const crypto::hash p_id = hash_from_hex(kat.p_id_hex);
  const crypto::hash seal_hash = hash_from_hex(kat.seal_hash_hex);
  const uint64_t h_open = shekyl_archival_epoch_open_height(kat.settlement_epoch);
  const uint64_t h_close = shekyl_archival_epoch_close_height(kat.settlement_epoch);
  return shekyl_archival_challenge_fire_height(h_open, h_close,
    reinterpret_cast<const uint8_t*>(seal_hash.data),
    reinterpret_cast<const uint8_t*>(p_id.data),
    kat.shard_id, kat.settlement_epoch);
}

} // namespace

// ── WS-1 acceptance-gate KATs (REWARD_EMISSION_E3_GATING_ROUND.md §5.6 #2) ──
//
// The serve-credit gate must answer "did P hold the shard at the challenge
// fire height?" — not "does P hold it at the connect tip". These two KATs pin
// the gate's boundary on both sides of h_fire, and additionally assert the
// gate queried the accessor at exactly the deterministically derived h_fire
// (the height a slash-eligibility mirror derives from the same operands).
// The accessor's own at_height reconstruction against real LMDB state is
// pinned separately in archival_substrate_lmdb.cpp.

// Drop-after-fire: P held at h_fire, the holding was removed strictly above
// h_fire, tip no longer holds. The credit is legitimate — a tip read here was
// the M2-1 drop-after-serve escape (under-count on the reward side, and the
// symmetric slash-escape on the punishment side).
TEST(archival_serve_credit, gate2_accepts_credit_when_held_at_fire_but_dropped_by_tip)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);
  const uint64_t h_fire = expected_fire_height(kat);
  ASSERT_NE(h_fire, 0u);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat);
  // Removal strictly above the fire height: held at h_fire, gone at tip.
  db->set_shard_removed_at(kat.shard_id, h_fire + 1);
  ArchivalServeCreditIntegrationDB* db_raw = db.get();

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

  EXPECT_TRUE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.current_height,
    hash_from_hex(kat.prev_block_hash_hex)));
  // The gate asked the as-of-height question at exactly the derived h_fire.
  ASSERT_FALSE(db_raw->holds_shard_queried_heights.empty());
  for (const uint64_t queried : db_raw->holds_shard_queried_heights)
    EXPECT_EQ(queried, h_fire);
}

// Inverse boundary: the holding was removed at h_fire itself (holdings at h
// are the post-connect state of block h), so P did NOT hold at the fire
// height and the credit is rejected — even though nothing else about the
// response changed. Unreachable at the current shrink-only substrate without
// a slash (which the gate's good_through would also catch), but the gate must
// bottom out in the accessor's as-of-fire answer, not a tip read, for the
// boundary to hold once HoldingsUpdate makes holdings mutable.
TEST(archival_serve_credit, gate2_rejects_credit_when_not_held_at_fire)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);
  const uint64_t h_fire = expected_fire_height(kat);
  ASSERT_NE(h_fire, 0u);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat);
  db->set_shard_removed_at(kat.shard_id, h_fire);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

  EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.current_height,
    hash_from_hex(kat.prev_block_hash_hex)));
}

TEST(archival_serve_credit, gate2_integration_rejects_duplicate_credit_bit)
{
  const IntegrationKat kat = load_integration_kat();
  const txin_archival_serve_credit_response resp = load_serve_credit_vin(kat.wire_hex);
  const crypto::hash p_id = hash_from_hex(kat.p_id_hex);

  auto db = std::make_unique<ArchivalServeCreditIntegrationDB>();
  seed_substrate(*db, kat);
  // PC-D4: seeded at a DIFFERENT block than the one being validated. That is
  // what makes this test discriminate: the dedup is PAIR-EPOCH-wide, so a row
  // from an earlier block still rejects. Seeded at the validating height it
  // would pass under either rule and prove nothing.
  ASSERT_GT(kat.current_height, 0u);
  db->set_archival_serve_credit_bit(p_id, kat.shard_id, kat.settlement_epoch,
    kat.current_height - 1);

  BlockchainAndPool bap;
  cryptonote::Blockchain* bc = &bap.bc;
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  ASSERT_TRUE(bc->init(db.release(), cryptonote::FAKECHAIN, true, &test_options, 0));

  EXPECT_FALSE(bc->check_archival_serve_credit_input(resp, bytes_from_hex(kat.pruned_hex), kat.current_height,
    hash_from_hex(kat.prev_block_hash_hex)));
}

// ── Cross-language byte parity of the serve-credit TRANSACTION (RF-D1/RF-D9) ──
//
// Until this arm the serve-credit shape had never round-tripped in C++ at all
// (RF-D9), so there was no C++-authored byte string for Rust to match and the
// format was genuinely free. This establishes agreement for the first time:
// shekyl-wire (the Rust oracle of this wire) built the transaction around the
// gate-2 fixture's two blobs and pinned its bytes; C++ builds the same
// transaction, serializes it, and must produce the same bytes -- and must
// parse them back to the same object. A divergence in the fee-only ct
// encoding, the empty-pqc_auths rule, or the pruned-record framing fails here.
namespace {

struct TxParityKat {
  std::string kept_wire_hex;
  std::string pruned_hex;
  std::string tx_hex;
  std::string tx_hash_hex;
};

TxParityKat load_tx_parity_kat()
{
  std::ifstream ifs(SERVE_CREDIT_TX_PARITY_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing tx parity fixture at ") + SERVE_CREDIT_TX_PARITY_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("tx_hex"))
    throw std::runtime_error("invalid tx parity fixture");
  TxParityKat k{};
  k.kept_wire_hex = doc["kept_wire_hex"].GetString();
  k.pruned_hex = doc["pruned_hex"].GetString();
  k.tx_hex = doc["tx_hex"].GetString();
  k.tx_hash_hex = doc["tx_hash_hex"].GetString();
  return k;
}

} // namespace

TEST(archival_serve_credit, full_tx_bytes_match_the_rust_oracle)
{
  const TxParityKat k = load_tx_parity_kat();

  transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;
  txin_archival_serve_credit_response vin{};
  vin.canonical_bytes = bytes_from_hex(k.kept_wire_hex);
  tx.vin.push_back(vin);
  tx.ct_signatures.type = ct::CTTypeFcmpPlusPlusPqc;
  tx.ct_signatures.txnFee = 0;
  tx.ct_signatures.p.curve_trees_tree_depth = 0;
  tx.ct_signatures.p.serve_credit_pruned = {bytes_from_hex(k.pruned_hex)};

  blobdata blob;
  ASSERT_TRUE(t_serializable_object_to_blob(tx, blob));
  EXPECT_EQ(epee::string_tools::buff_to_hex_nodelimer(blob), k.tx_hex)
      << "C++ and shekyl-wire disagree on the serve-credit transaction's bytes";

  // The pinned bytes parse back, through the production entry point, to the
  // same transaction -- and the tx id agrees across languages too.
  transaction parsed;
  const std::vector<uint8_t> pinned = bytes_from_hex(k.tx_hex);
  const blobdata pinned_blob(reinterpret_cast<const char*>(pinned.data()), pinned.size());
  ASSERT_TRUE(parse_and_validate_tx_from_blob(pinned_blob, parsed))
      << "the Rust-authored bytes must be a transaction C++ can parse";
  ASSERT_EQ(parsed.vin.size(), 1u);
  ASSERT_TRUE(std::holds_alternative<txin_archival_serve_credit_response>(parsed.vin[0]));
  EXPECT_EQ(std::get<txin_archival_serve_credit_response>(parsed.vin[0]).canonical_bytes,
            bytes_from_hex(k.kept_wire_hex));
  ASSERT_EQ(parsed.ct_signatures.p.serve_credit_pruned.size(), 1u);
  EXPECT_EQ(parsed.ct_signatures.p.serve_credit_pruned[0], bytes_from_hex(k.pruned_hex));
  EXPECT_TRUE(parsed.pqc_auths.empty());
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_transaction_hash(parsed)), k.tx_hash_hex)
      << "tx id differs across languages";

  // The PRUNED identity on the 3-part (empty-pqc_auths) arm: mixing the
  // prunable digest back in via `get_pruned_transaction_hash` must reproduce
  // the cross-language txid -- the derivation a pruned daemon's reader
  // depends on, asserted here against the same pin the Rust leg's
  // `hash_with_supplied_prunable` asserts. The 4-part spend arm has its own
  // pin (`pruned_tx_hash_parity.cpp`).
  crypto::hash prunable_hash;
  ASSERT_TRUE(calculate_transaction_prunable_hash(parsed, nullptr, prunable_hash));
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_pruned_transaction_hash(parsed, prunable_hash)),
            k.tx_hash_hex)
      << "pruned identity (supplied digest) diverged from the txid";
}

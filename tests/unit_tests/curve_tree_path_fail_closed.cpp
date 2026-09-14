// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// FFI-seam coverage for `assemble_curve_tree_path`: the byte layout and
// fail-closed contract live in `shekyl-fcmp::rpc_path` and are pinned there.
// These tests confirm the C++ store callbacks refuse a hole the same way.

#include <set>
#include <string>

#include "gtest/gtest.h"

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/testdb.h"
#include "cryptonote_core/curve_tree_path.h"
#include "shekyl/shekyl_ffi.h"

namespace
{

class HoleyTreeDB : public cryptonote::BaseTestDB
{
public:
  uint64_t leaf_count = 0;
  std::set<uint64_t> missing_leaves;
  std::set<uint64_t> missing_layer0_chunks;
  std::set<uint64_t> missing_output_keys;
  /// Positions whose reads throw, as LMDB does when the env is closed or a
  /// read transaction cannot be opened -- the store failing, not a hole.
  std::set<uint64_t> throwing_leaves;
  std::set<uint64_t> throwing_layer0_chunks;

  uint8_t get_curve_tree_depth() const override { return 1; }
  uint64_t get_curve_tree_leaf_count() const override { return leaf_count; }

  bool get_curve_tree_leaf_by_tree_position(uint64_t pos, uint8_t* leaf_out) const override
  {
    if (throwing_leaves.count(pos))
      throw cryptonote::DB_ERROR("Attempted to read leaf on closed database");
    if (pos >= leaf_count || missing_leaves.count(pos))
      return false;
    for (size_t i = 0; i < 128; ++i)
      leaf_out[i] = static_cast<uint8_t>(pos + 1);
    return true;
  }

  bool get_curve_tree_layer_hash(uint8_t layer, uint64_t chunk, uint8_t* hash_out) const override
  {
    if (layer == 0 && throwing_layer0_chunks.count(chunk))
      throw cryptonote::DB_ERROR("Failed to create a read transaction for the db");
    if (layer == 0 && missing_layer0_chunks.count(chunk))
      return false;
    for (size_t i = 0; i < 32; ++i)
      hash_out[i] = static_cast<uint8_t>(0xA0 + chunk);
    return true;
  }

  cryptonote::output_data_t get_output_key(const uint64_t& /*amount*/, const uint64_t& index, bool /*include_commitmemt*/) const override
  {
    if (missing_output_keys.count(index))
      throw cryptonote::OUTPUT_DNE("missing output key");
    return cryptonote::output_data_t();
  }
};

bool assemble(const HoleyTreeDB& db, uint64_t idx, uint64_t ref, uint64_t tip,
              cryptonote::curve_tree_path_bytes& out, std::string& err)
{
  return cryptonote::assemble_curve_tree_path(
      db, idx, ref, tip, db.get_curve_tree_depth(), out, err);
}

} // namespace

TEST(curve_tree_path_fail_closed, missing_leaf_in_chunk_refuses_and_names_position)
{
  HoleyTreeDB db;
  db.leaf_count = 3;
  db.missing_leaves = {1};

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, 3, 3, out, err));
  EXPECT_NE(err.find("tree position 1"), std::string::npos) << err;
}

TEST(curve_tree_path_fail_closed, missing_layer_hash_refuses_and_names_chunk)
{
  HoleyTreeDB db;
  db.leaf_count = 3;
  db.missing_layer0_chunks = {0};

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, 3, 3, out, err));
  EXPECT_NE(err.find("layer 0 chunk 0"), std::string::npos) << err;
}

TEST(curve_tree_path_fail_closed, missing_leaf_in_boundary_trim_refuses)
{
  HoleyTreeDB db;
  db.leaf_count = 3;
  db.missing_leaves = {2};

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, /*ref=*/2, /*tip=*/3, out, err));
  EXPECT_NE(err.find("tree position 2"), std::string::npos) << err;
}

TEST(curve_tree_path_fail_closed, missing_output_key_refuses_and_names_position)
{
  HoleyTreeDB db;
  db.leaf_count = 3;
  db.missing_output_keys = {1};

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, 3, 3, out, err));
  EXPECT_NE(err.find("tree position 1"), std::string::npos) << err;
}

// The callbacks run inside a Rust `extern "C"` frame: an exception that
// escaped one would abort the process rather than produce the promised
// refusal. LMDB's read paths do throw (`check_open`, read-txn setup), so
// each store failure must come back as `false` with its message attached.
TEST(curve_tree_path_fail_closed, throwing_leaf_read_becomes_a_refusal_with_its_message)
{
  HoleyTreeDB db;
  db.leaf_count = 3;
  db.throwing_leaves = {1};

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, 3, 3, out, err));
  EXPECT_NE(err.find("tree position 1"), std::string::npos) << err;
  EXPECT_NE(err.find("closed database"), std::string::npos) << err;
}

TEST(curve_tree_path_fail_closed, throwing_layer_hash_read_becomes_a_refusal_with_its_message)
{
  HoleyTreeDB db;
  db.leaf_count = 3;
  db.throwing_layer0_chunks = {0};

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, 3, 3, out, err));
  EXPECT_NE(err.find("layer 0 chunk 0"), std::string::npos) << err;
  EXPECT_NE(err.find("read transaction"), std::string::npos) << err;
}

TEST(curve_tree_path_fail_closed, complete_store_yields_expected_shape)
{
  HoleyTreeDB db;
  db.leaf_count = 3;

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_TRUE(assemble(db, 1, 3, 3, out, err)) << err;

  const uint32_t layer1_cw = shekyl_curve_tree_helios_chunk_width();
  EXPECT_EQ(out.path.size(), 2u + 3u * 128u + 2u + layer1_cw * 32u);
  EXPECT_EQ(out.path[0], 1u);
  EXPECT_EQ(out.path[1], 0u);
  const size_t sib0 = 2 + 3 * 128 + 2;
  EXPECT_EQ(out.path[sib0], 0xA0u);
  EXPECT_EQ(out.path[sib0 + 32], 0u);
  EXPECT_EQ(out.chunk_outputs.size(), 3u * 128u);
}

TEST(curve_tree_path_fail_closed, published_depth_governs_layer_count)
{
  HoleyTreeDB db;
  db.leaf_count = 3;

  cryptonote::curve_tree_path_bytes d1;
  std::string err;
  ASSERT_TRUE(cryptonote::assemble_curve_tree_path(db, 0, 3, 3, 1, d1, err)) << err;
  cryptonote::curve_tree_path_bytes d2;
  ASSERT_TRUE(cryptonote::assemble_curve_tree_path(db, 0, 3, 3, 2, d2, err)) << err;
  EXPECT_GT(d2.path.size(), d1.path.size());
}

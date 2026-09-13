// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// PDM-Q-F9: `assemble_curve_tree_path` fails closed on every store read it
// makes. Before this contract the RPC assembler zero-filled a missing leaf and
// ignored a failed layer-hash read, emitting a well-formed path whose
// verification against R_k fails at the client with nothing pointing at the
// store. These tests drive the assembler over a stub store with one hole at a
// time and assert the call refuses, naming the position; the last test pins
// the happy-path shape so a refusal cannot be "fixed" by refusing everything.

#include <map>
#include <set>
#include <string>

#include "gtest/gtest.h"

#include "blockchain_db/testdb.h"
#include "cryptonote_core/curve_tree_path.h"
#include "shekyl/shekyl_ffi.h"

namespace
{

// A depth-1 tree: `leaf_count` leaves in layer-0 chunk 0, and layer-0 hashes
// for every chunk unless the chunk is in `missing_layer0_chunks`. Leaves are
// present unless their position is in `missing_leaves`.
class HoleyTreeDB : public cryptonote::BaseTestDB
{
public:
  uint64_t leaf_count = 0;
  std::set<uint64_t> missing_leaves;
  std::set<uint64_t> missing_layer0_chunks;

  uint8_t get_curve_tree_depth() const override { return 1; }
  uint64_t get_curve_tree_leaf_count() const override { return leaf_count; }

  bool get_curve_tree_leaf_by_tree_position(uint64_t pos, uint8_t* leaf_out) const override
  {
    if (pos >= leaf_count || missing_leaves.count(pos))
      return false;
    for (size_t i = 0; i < 128; ++i)
      leaf_out[i] = static_cast<uint8_t>(pos + 1);
    return true;
  }

  bool get_curve_tree_layer_hash(uint8_t layer, uint64_t chunk, uint8_t* hash_out) const override
  {
    if (layer != 0 || missing_layer0_chunks.count(chunk))
      return false;
    for (size_t i = 0; i < 32; ++i)
      hash_out[i] = static_cast<uint8_t>(0xA0 + chunk);
    return true;
  }
};

bool assemble(const HoleyTreeDB& db, uint64_t idx, uint64_t ref, uint64_t tip,
              cryptonote::curve_tree_path_bytes& out, std::string& err)
{
  return cryptonote::assemble_curve_tree_path(db, idx, ref, tip, out, err);
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

// The second F9 site: the boundary chunk grew after the reference height, so
// the trim reads the leaves that were appended since. One of them is missing.
TEST(curve_tree_path_fail_closed, missing_leaf_in_boundary_trim_refuses)
{
  HoleyTreeDB db;
  db.leaf_count = 3;      // tip holds 3 leaves ...
  db.missing_leaves = {2}; // ... but the one appended after the reference is gone

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_FALSE(assemble(db, 0, /*ref=*/2, /*tip=*/3, out, err));
  EXPECT_NE(err.find("tree position 2"), std::string::npos) << err;
}

TEST(curve_tree_path_fail_closed, complete_store_yields_expected_shape)
{
  HoleyTreeDB db;
  db.leaf_count = 3;

  cryptonote::curve_tree_path_bytes out;
  std::string err;
  ASSERT_TRUE(assemble(db, 1, 3, 3, out, err)) << err;

  const uint32_t layer1_cw = shekyl_curve_tree_helios_chunk_width();
  // [leaf_pos u16][3 leaves * 128] + [pos_in_parent u16][cw * 32]
  EXPECT_EQ(out.path.size(), 2u + 3u * 128u + 2u + layer1_cw * 32u);
  EXPECT_EQ(out.path[0], 1u);
  EXPECT_EQ(out.path[1], 0u);
  // Chunk 0 is the only reference chunk; every other sibling slot is zero padding.
  const size_t sib0 = 2 + 3 * 128 + 2;
  EXPECT_EQ(out.path[sib0], 0xA0u);
  EXPECT_EQ(out.path[sib0 + 32], 0u);
  // O ‖ I ‖ C ‖ h_pqc per leaf.
  EXPECT_EQ(out.chunk_outputs.size(), 3u * 128u);
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Segment-freeze pipeline suite (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §9):
// first-crossing, multi-segment single grow, R_k recomposition cross-check,
// O-3 pop-symmetry (bit-identical rows), missing-chunk loud abort, and the
// M1 count-pass integration against production-written rows.

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <vector>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/shekyl_types.h"
#include "shekyl/shekyl_ffi.h"
#include "shekyl/consensus_constants_generated.h"

using namespace cryptonote;

namespace {

constexpr uint64_t kE = SHEKYL_ARCHIVAL_SEGMENT_LEAF_COUNT; // 25 992
constexpr size_t kLeafBytes = 128;                          // 4 Selene scalars
constexpr uint64_t kSeleneWidth = 38;                       // leaf-layer chunk width
constexpr uint64_t kChunksPerSegment = kE / kSeleneWidth;   // 684 (E % 38 == 0)

struct TempLMDB {
  boost::filesystem::path tmpdir;
  BlockchainLMDB db;

  TempLMDB()
  {
    tmpdir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(tmpdir);
    db.open(tmpdir.string());
    db.set_batch_transactions(true);
    db.batch_start();
  }

  ~TempLMDB()
  {
    try {
      db.batch_stop();
      db.close();
      boost::filesystem::remove_all(tmpdir);
    } catch (...) {}
  }
};

/// Deterministic, distinct, canonical leaf bytes for global leaf index
/// `gi`: each of the 4 little-endian scalars keeps its top byte zero, so
/// every 32-byte repr is far below the Selene field modulus.
std::vector<uint8_t> make_leaves(uint64_t first_global_index, uint64_t count)
{
  std::vector<uint8_t> data(count * kLeafBytes, 0);
  for (uint64_t i = 0; i < count; ++i)
  {
    const uint64_t gi = first_global_index + i;
    for (int scalar = 0; scalar < 4; ++scalar)
    {
      uint8_t* s = data.data() + i * kLeafBytes + scalar * 32;
      for (int b = 0; b < 8; ++b)
        s[b] = static_cast<uint8_t>((gi >> (b * 8)) & 0xFF);
      s[8] = static_cast<uint8_t>(scalar + 1);
    }
  }
  return data;
}

void grow(BlockchainDB& db, uint64_t first_global_index, uint64_t count)
{
  db.grow_curve_tree(make_leaves(first_global_index, count), count);
}

} // namespace

TEST(archival_segment_freeze, first_crossing_writes_row_zero_at_exact_boundary)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  BlockchainDB& db = fixture.db;

  // E-1 leaves: no complete segment, no row.
  grow(db, 0, kE - 1);
  db.process_archival_segment_freezes_at_height(100);
  std::vector<uint8_t> raw;
  EXPECT_FALSE(lmdb.get_archival_shard_segment_raw_for_test(0, raw));
  EXPECT_EQ(lmdb.count_frozen_shards_at_close(100), 0u);

  // The crossing leaf: row 0 appears with this block's height.
  grow(db, kE - 1, 1);
  db.process_archival_segment_freezes_at_height(101);
  ASSERT_TRUE(lmdb.get_archival_shard_segment_raw_for_test(0, raw));
  crypto::hash rk{};
  uint64_t leaf_count = 0;
  EXPECT_FALSE(db.get_archival_shard_segment_at_height(0, 100, rk, leaf_count));
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(0, 101, rk, leaf_count));
  EXPECT_EQ(leaf_count, kE);

  // A later block with no boundary crossing does not move freeze_height
  // (first-crossing rule: the row is written once, never updated).
  const std::vector<uint8_t> row_at_101 = raw;
  grow(db, kE, 1);
  db.process_archival_segment_freezes_at_height(102);
  ASSERT_TRUE(lmdb.get_archival_shard_segment_raw_for_test(0, raw));
  EXPECT_EQ(raw, row_at_101);
  EXPECT_FALSE(lmdb.get_archival_shard_segment_raw_for_test(1, raw));
}

TEST(archival_segment_freeze, multi_segment_single_grow_writes_both_rows)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  BlockchainDB& db = fixture.db;

  // One block's drain crossing two boundaries: both rows, same
  // freeze_height, distinct R_k.
  grow(db, 0, 2 * kE);
  db.process_archival_segment_freezes_at_height(50);

  crypto::hash rk0{}, rk1{};
  uint64_t lc0 = 0, lc1 = 0;
  EXPECT_FALSE(db.get_archival_shard_segment_at_height(0, 49, rk0, lc0));
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(0, 50, rk0, lc0));
  EXPECT_FALSE(db.get_archival_shard_segment_at_height(1, 49, rk1, lc1));
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(1, 50, rk1, lc1));
  EXPECT_EQ(lc0, kE);
  EXPECT_EQ(lc1, kE);
  EXPECT_NE(rk0, rk1);

  // M1 integration (§9): the count pass over production-written rows equals
  // the pipeline's row count at and after the freeze height, zero before.
  EXPECT_EQ(lmdb.count_frozen_shards_at_close(49), 0u);
  EXPECT_EQ(lmdb.count_frozen_shards_at_close(50), 2u);
  EXPECT_EQ(lmdb.count_frozen_shards_at_close(51), 2u);
}

TEST(archival_segment_freeze, rk_matches_independent_recomposition)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  BlockchainDB& db = fixture.db;

  const std::vector<uint8_t> leaves = make_leaves(0, kE);
  db.grow_curve_tree(leaves, kE);
  db.process_archival_segment_freezes_at_height(7);

  crypto::hash rk{};
  uint64_t lc = 0;
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(0, 7, rk, lc));

  // Independent recomposition from the raw leaf bytes: hash each of the
  // segment's 684 leaf chunks from init, then let the Rust builder compose
  // the upper layers. The single layer-2 chunk over the segment IS R_0.
  std::vector<uint8_t> chunk_hashes(kChunksPerSegment * 32);
  for (uint64_t c = 0; c < kChunksPerSegment; ++c)
  {
    std::array<uint8_t, 32> init{};
    ASSERT_TRUE(shekyl_curve_tree_selene_hash_init(init.data()));
    const std::array<uint8_t, 32> zero_child{};
    ASSERT_TRUE(shekyl_curve_tree_hash_grow_selene(
      init.data(), 0, zero_child.data(),
      leaves.data() + c * kSeleneWidth * kLeafBytes,
      kSeleneWidth * 4,
      chunk_hashes.data() + c * 32));
  }

  std::vector<uint8_t> upper_chunks((kChunksPerSegment + 1) * 32);
  std::array<uint64_t, 16> layer_sizes = {};
  uint64_t num_upper_layers = 0;
  std::array<uint8_t, 32> root{};
  ASSERT_TRUE(shekyl_curve_tree_grow_upper_layers(
    chunk_hashes.data(), kChunksPerSegment,
    upper_chunks.data(), kChunksPerSegment + 1,
    layer_sizes.data(), layer_sizes.size(),
    &num_upper_layers, root.data()));

  // Chunk-width ladder for exactly one segment: 684 -> 38 (layer 1) -> 1
  // (layer 2). The last upper chunk is the layer-2 hash.
  ASSERT_EQ(num_upper_layers, 2u);
  ASSERT_EQ(layer_sizes[0], 38u);
  ASSERT_EQ(layer_sizes[1], 1u);
  const uint8_t* layer2 = upper_chunks.data() + layer_sizes[0] * 32;
  EXPECT_EQ(0, memcmp(rk.data, layer2, 32));
}

TEST(archival_segment_freeze, pop_symmetry_row_bit_identical_after_reapply)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  BlockchainDB& db = fixture.db;

  grow(db, 0, kE);
  db.process_archival_segment_freezes_at_height(7);
  std::vector<uint8_t> row_before;
  ASSERT_TRUE(lmdb.get_archival_shard_segment_raw_for_test(0, row_before));

  // Pop across the boundary: trim below E, revert deletes the row.
  db.trim_curve_tree(1);
  db.revert_archival_segment_freezes();
  std::vector<uint8_t> raw;
  EXPECT_FALSE(lmdb.get_archival_shard_segment_raw_for_test(0, raw));

  // Re-apply the same block: identical leaf, same height — the row must be
  // bit-identical (O-3: encoded bytes compared, not decoded fields).
  grow(db, kE - 1, 1);
  db.process_archival_segment_freezes_at_height(7);
  std::vector<uint8_t> row_after;
  ASSERT_TRUE(lmdb.get_archival_shard_segment_raw_for_test(0, row_after));
  EXPECT_EQ(row_after, row_before);
}

TEST(archival_segment_freeze, pop_above_boundary_leaves_row_untouched)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  BlockchainDB& db = fixture.db;

  grow(db, 0, kE + kSeleneWidth);
  db.process_archival_segment_freezes_at_height(7);
  std::vector<uint8_t> row_before;
  ASSERT_TRUE(lmdb.get_archival_shard_segment_raw_for_test(0, row_before));

  // Pop that stays above the boundary: leaf count back to exactly E — the
  // segment is still complete, the row survives byte-identically.
  db.trim_curve_tree(kSeleneWidth);
  db.revert_archival_segment_freezes();
  std::vector<uint8_t> row_after;
  ASSERT_TRUE(lmdb.get_archival_shard_segment_raw_for_test(0, row_after));
  EXPECT_EQ(row_after, row_before);
}

TEST(archival_segment_freeze, missing_layer2_chunk_aborts_loudly)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  BlockchainDB& db = fixture.db;

  grow(db, 0, kE);
  // Corrupt: remove the layer-2 chunk the freeze would read. A completed
  // segment whose sub-root is absent is tree/registry disagreement — the
  // connect hook must throw, not write a partial row.
  lmdb.remove_curve_tree_layer_chunk_for_corruption_test(2, 0);
  EXPECT_ANY_THROW(db.process_archival_segment_freezes_at_height(7));
  std::vector<uint8_t> raw;
  EXPECT_FALSE(lmdb.get_archival_shard_segment_raw_for_test(0, raw));
}

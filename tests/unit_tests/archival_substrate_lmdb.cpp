// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <limits>
#include <vector>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/shekyl_types.h"

using namespace cryptonote;

namespace {

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

crypto::hash make_hash(uint8_t fill)
{
  crypto::hash h{};
  memset(h.data, fill, sizeof(h.data));
  return h;
}

/// Minimum-length bond LMDB value with a non-v4 version byte.
///
/// `ArchivalBondValue::decode` rejects solely on `version != kVersion` once
/// `len >= 40` (the v4 structural minimum); no historical pre-v4 wire layout
/// is load-bearing at genesis.
std::vector<uint8_t> non_v4_bond_blob(uint8_t version)
{
  std::vector<uint8_t> blob(40, 0);
  blob[0] = version;
  return blob;
}

/// Splice an arbitrary claimed-epoch tail onto a valid v4 encoding that was
/// produced with an empty claimed set. The empty-set encoding always ends in
/// 12 bytes (`u32` count = 0, `u64` first_paying_emission_height), so the
/// crafted tail can bypass the encoder's well-formedness throw and exercise
/// the decode invariants directly.
std::vector<uint8_t> with_claimed_tail(std::vector<uint8_t> encoded_empty,
  const std::vector<uint64_t>& claimed, uint64_t first_paying_emission_height)
{
  encoded_empty.resize(encoded_empty.size() - 12);
  const uint32_t count = static_cast<uint32_t>(claimed.size());
  for (int i = 3; i >= 0; --i)
    encoded_empty.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
  for (const uint64_t epoch : claimed)
  {
    for (int i = 7; i >= 0; --i)
      encoded_empty.push_back(static_cast<uint8_t>((epoch >> (i * 8)) & 0xFF));
  }
  for (int i = 7; i >= 0; --i)
    encoded_empty.push_back(
      static_cast<uint8_t>((first_paying_emission_height >> (i * 8)) & 0xFF));
  return encoded_empty;
}

/// Valid v4 record with an empty claimed set, as a baseline for tail splicing.
shekyl::db::ArchivalBondValue baseline_bond()
{
  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = {0x01, 0x02};
  bond.join_settlement_epoch = 7;
  bond.bonded_total_atomic = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  bond.held_shard_ids = {42};
  return bond;
}

} // namespace

TEST(archival_substrate_lmdb, bond_record_roundtrip)
{
  TempLMDB fixture;
  const crypto::hash p_id = make_hash(0x11);
  const std::vector<uint8_t> pubkey = {0x01, 0x02, 0x03, 0x04};
  const std::vector<uint64_t> shards = {7, 42};
  const std::vector<std::pair<uint64_t, uint64_t>> bad = {{5, 6}};
  const uint64_t bonded_total = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;

  BlockchainDB& db = fixture.db;
  db.put_archival_bond_record(p_id, pubkey, 3, bonded_total,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, shards, bad);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  std::vector<uint8_t> out_pubkey;
  ASSERT_TRUE(db.get_archival_bond_hybrid_pubkey(p_id, out_pubkey));
  EXPECT_EQ(out_pubkey, pubkey);
  EXPECT_EQ(db.archival_bond_join_epoch(p_id), 3u);
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 42, 0));
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 99, 0));
  EXPECT_TRUE(db.archival_bond_good_through(p_id, 4));
  EXPECT_FALSE(db.archival_bond_good_through(p_id, 3));
  EXPECT_FALSE(db.archival_bond_good_through(p_id, 5));

  shekyl::db::ArchivalBondValue roundtrip{};
  shekyl::db::ArchivalBondValue written{};
  written.hybrid_pubkey = pubkey;
  written.join_settlement_epoch = 3;
  written.bonded_total_atomic = bonded_total;
  written.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  written.held_shard_ids = shards;
  for (const auto& iv : bad)
  {
    shekyl::db::ArchivalBondValue::BadInterval entry{};
    entry.start_epoch = iv.first;
    entry.end_exclusive = iv.second;
    written.bad_intervals.push_back(entry);
  }
  written.claimed_settlement_epochs = {100, 105, 126}; // span 26 = W, the legal max
  written.first_paying_emission_height = 1234567;
  const std::vector<uint8_t> encoded = written.encode();
  ASSERT_TRUE(shekyl::db::ArchivalBondValue::decode(encoded.data(), encoded.size(), roundtrip));
  EXPECT_EQ(roundtrip.bonded_total_atomic, bonded_total);
  EXPECT_EQ(roundtrip.claimed_settlement_epochs, written.claimed_settlement_epochs);
  EXPECT_EQ(roundtrip.first_paying_emission_height, written.first_paying_emission_height);

  db.remove_archival_bond_record(p_id);
  fixture.db.batch_stop();
  fixture.db.batch_start();
  EXPECT_FALSE(db.get_archival_bond_hybrid_pubkey(p_id, out_pubkey));
  EXPECT_EQ(db.archival_bond_join_epoch(p_id), std::numeric_limits<uint64_t>::max());
}

TEST(archival_substrate_lmdb, complete_tree_bond_holds_any_shard)
{
  TempLMDB fixture;
  const crypto::hash p_id = make_hash(0x44);
  const std::vector<uint8_t> pubkey = {0x05, 0x06};

  BlockchainDB& db = fixture.db;
  db.put_archival_bond_record(p_id, pubkey, 1, SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsCompleteTree, {}, {});
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, 0));
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 999, 0));
}

TEST(archival_substrate_lmdb, bond_reject_legacy_versions)
{
  shekyl::db::ArchivalBondValue decoded{};

  const std::vector<uint8_t> v1 = non_v4_bond_blob(1);
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(v1.data(), v1.size(), decoded));

  const std::vector<uint8_t> v2 = non_v4_bond_blob(2);
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(v2.data(), v2.size(), decoded));

  // Byte-exact v3 record: the v4 layout minus the 12-byte claimed tail,
  // with the version byte patched. Pre-genesis posture: rejected, no
  // migration path.
  std::vector<uint8_t> v3 = baseline_bond().encode();
  v3.resize(v3.size() - 12);
  v3[0] = 3;
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(v3.data(), v3.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_reject_unknown_version)
{
  std::vector<uint8_t> blob = non_v4_bond_blob(1);
  blob[0] = 99;
  shekyl::db::ArchivalBondValue decoded{};
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(blob.data(), blob.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_v4_reject_truncated_after_join_epoch)
{
  std::vector<uint8_t> encoded = baseline_bond().encode();
  ASSERT_GT(encoded.size(), 20u);
  encoded.resize(encoded.size() - 9);

  shekyl::db::ArchivalBondValue decoded{};
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(encoded.data(), encoded.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_v4_encode_version_byte)
{
  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = {0x0A};
  bond.join_settlement_epoch = 1;
  bond.bonded_total_atomic = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  bond.held_shard_ids = {7, 42};

  const std::vector<uint8_t> encoded = bond.encode();
  ASSERT_FALSE(encoded.empty());
  EXPECT_EQ(encoded[0], shekyl::db::ArchivalBondValue::kVersion);
}

TEST(archival_substrate_lmdb, bond_v4_empty_claimed_defaults)
{
  const std::vector<uint8_t> encoded = baseline_bond().encode();
  shekyl::db::ArchivalBondValue decoded{};
  ASSERT_TRUE(shekyl::db::ArchivalBondValue::decode(encoded.data(), encoded.size(), decoded));
  EXPECT_TRUE(decoded.claimed_settlement_epochs.empty());
  EXPECT_EQ(decoded.first_paying_emission_height, 0u);
}

TEST(archival_substrate_lmdb, bond_v4_claimed_cap_rejected_at_decode)
{
  // 33 entries — one over the §6.3 cap (W = 26 + 6 reorg slack = 32). Spaced
  // within the span bound is impossible at this count, but the cap check is
  // the one that must fire: it runs before any entry is read.
  std::vector<uint64_t> claimed;
  for (uint64_t e = 0; e < 33; ++e)
    claimed.push_back(e);
  const std::vector<uint8_t> blob = with_claimed_tail(baseline_bond().encode(), claimed, 0);

  shekyl::db::ArchivalBondValue decoded{};
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(blob.data(), blob.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_v4_claimed_non_monotone_rejected_at_decode)
{
  shekyl::db::ArchivalBondValue decoded{};

  const std::vector<uint8_t> descending =
    with_claimed_tail(baseline_bond().encode(), {7, 3}, 0);
  EXPECT_FALSE(
    shekyl::db::ArchivalBondValue::decode(descending.data(), descending.size(), decoded));

  const std::vector<uint8_t> duplicate =
    with_claimed_tail(baseline_bond().encode(), {5, 5}, 0);
  EXPECT_FALSE(
    shekyl::db::ArchivalBondValue::decode(duplicate.data(), duplicate.size(), decoded));
}

TEST(archival_substrate_lmdb, bond_v4_claimed_span_violation_rejected_at_decode)
{
  // Span 27 > W = 26: a correct writer prunes below `current − W`, so a wider
  // span is unreachable except through corruption or a writer bug.
  const std::vector<uint8_t> wide =
    with_claimed_tail(baseline_bond().encode(), {0, 27}, 0);
  shekyl::db::ArchivalBondValue decoded{};
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(wide.data(), wide.size(), decoded));

  // Span exactly W is legal.
  const std::vector<uint8_t> edge =
    with_claimed_tail(baseline_bond().encode(), {0, 26}, 0);
  EXPECT_TRUE(shekyl::db::ArchivalBondValue::decode(edge.data(), edge.size(), decoded));
  EXPECT_EQ(decoded.claimed_settlement_epochs, (std::vector<uint64_t>{0, 26}));
}

TEST(archival_substrate_lmdb, bond_v4_claimed_invariants_enforced_at_encode)
{
  shekyl::db::ArchivalBondValue over_cap = baseline_bond();
  for (uint64_t e = 0; e < 33; ++e)
    over_cap.claimed_settlement_epochs.push_back(e);
  EXPECT_THROW(over_cap.encode(), std::runtime_error);

  shekyl::db::ArchivalBondValue disorder = baseline_bond();
  disorder.claimed_settlement_epochs = {9, 4};
  EXPECT_THROW(disorder.encode(), std::runtime_error);

  shekyl::db::ArchivalBondValue wide_span = baseline_bond();
  wide_span.claimed_settlement_epochs = {0, 27};
  EXPECT_THROW(wide_span.encode(), std::runtime_error);
}

TEST(archival_substrate_lmdb, bond_v4_reject_truncated_claimed_tail)
{
  shekyl::db::ArchivalBondValue bond = baseline_bond();
  bond.claimed_settlement_epochs = {11, 12};
  bond.first_paying_emission_height = 50001;

  std::vector<uint8_t> encoded = bond.encode();
  shekyl::db::ArchivalBondValue decoded{};

  std::vector<uint8_t> missing_height = encoded;
  missing_height.resize(missing_height.size() - 8);
  EXPECT_FALSE(shekyl::db::ArchivalBondValue::decode(
    missing_height.data(), missing_height.size(), decoded));

  std::vector<uint8_t> short_one = encoded;
  short_one.resize(short_one.size() - 1);
  EXPECT_FALSE(
    shekyl::db::ArchivalBondValue::decode(short_one.data(), short_one.size(), decoded));
}

TEST(archival_substrate_lmdb, shard_registry_roundtrip)
{
  TempLMDB fixture;
  const crypto::hash rk = make_hash(0x22);
  BlockchainDB& db = fixture.db;
  db.put_archival_shard_segment(42, 100, rk, 26000);

  std::vector<uint8_t> scalars(128, 0x33);
  db.put_archival_shard_leaf_layer_scalars(42, 1234, scalars);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  crypto::hash out_rk{};
  uint64_t leaf_count = 0;
  EXPECT_FALSE(db.get_archival_shard_segment_at_height(42, 50, out_rk, leaf_count));
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(42, 100, out_rk, leaf_count));
  EXPECT_EQ(out_rk, rk);
  EXPECT_EQ(leaf_count, 26000u);

  std::vector<uint8_t> out_scalars;
  ASSERT_TRUE(db.get_archival_shard_leaf_layer_scalars(42, 1234, 100, out_scalars));
  EXPECT_EQ(out_scalars, scalars);
}

// Storage-flow coverage for the gather → Rust compute → store epoch-close
// sweep. Exact R_market / Σwork arithmetic is pinned by the Rust KAT
// (consensus_state_kat_v1.json §epoch_close); this test asserts the LMDB
// orchestration: row gathering, missing-bond skips, stale-epoch filtering,
// persistence, revert, and replay determinism.
TEST(archival_substrate_lmdb, epoch_close_gather_compute_store_revert)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;

  // SETTLEMENT_EPOCH_BLOCKS is KAT-pinned at 10000; epoch E closes when the
  // first block of epoch E+1 connects.
  const uint64_t seb = 10000;
  const uint64_t settlement_epoch = 1;
  const uint64_t close_height = (settlement_epoch + 1) * seb;

  const crypto::hash p1 = make_hash(0x51);
  const crypto::hash p2 = make_hash(0x52);
  const crypto::hash p_missing = make_hash(0x53);
  const std::vector<uint8_t> pubkey = {0x01};

  db.put_archival_bond_record(p1, pubkey, 0, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
  db.put_archival_bond_record(p2, pubkey, 0, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7, 9}, {});

  // Aged segment for shard 7; shard 9 stays segment-less (age 0).
  db.put_archival_shard_segment(7, 0, make_hash(0x60), 26000);

  db.set_archival_serve_credit_bit(p1, 7, settlement_epoch);
  db.set_archival_serve_credit_bit(p2, 7, settlement_epoch);
  db.set_archival_serve_credit_bit(p2, 9, settlement_epoch);
  // Credit row without a bond record: gathered row is skipped, not fatal.
  db.set_archival_serve_credit_bit(p_missing, 7, settlement_epoch);
  // Credit row for a different epoch: filtered by the cursor pass.
  db.set_archival_serve_credit_bit(p1, 7, settlement_epoch + 1);

  // Non-boundary heights are no-ops.
  db.process_archival_epoch_close_at_height(close_height - 1);
  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 2u);
  EXPECT_EQ(db.get_archival_r_market(9, settlement_epoch), 1u);
  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch + 1), 0u);
  const uint64_t sigma = db.get_archival_sigma_work_milli(settlement_epoch);
  EXPECT_GT(sigma, 0u);

  db.revert_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 0u);
  EXPECT_EQ(db.get_archival_r_market(9, settlement_epoch), 0u);
  EXPECT_EQ(db.get_archival_sigma_work_milli(settlement_epoch), 0u);

  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 2u);
  EXPECT_EQ(db.get_archival_r_market(9, settlement_epoch), 1u);
  EXPECT_EQ(db.get_archival_sigma_work_milli(settlement_epoch), sigma);
}

// ── F-S1: v4 fields survive the load-modify-store writers ───────────────────
//
// put_archival_bond_record rebuilds a fresh ArchivalBondValue from scalar args
// and cannot carry claimed_settlement_epochs / first_paying_emission_height.
// The slash apply/revert load-modify-store paths therefore write through the
// full-bond writer put_archival_bond_value; before that fix they silently wiped
// the v4 fields (REWARD_EMISSION_VIN_PLAN.md §1.5 F-S1 / F-E5). These tests pin
// that the v4 fields round-trip the writer and survive both a slash and its
// reorg revert.

namespace {

// Seed record carrying populated v4 fields. The claimed set {100,105,126} spans
// exactly W=26 (the legal max), and first_paying is a non-sentinel height.
shekyl::db::ArchivalBondValue bond_with_v4_fields(const std::vector<uint64_t>& shards,
  uint64_t bonded_total)
{
  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = {0x0A, 0x0B, 0x0C};
  bond.join_settlement_epoch = 2;
  bond.bonded_total_atomic = bonded_total;
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  bond.held_shard_ids = shards;
  bond.claimed_settlement_epochs = {100, 105, 126};
  bond.first_paying_emission_height = 1234567;
  return bond;
}

} // namespace

TEST(archival_substrate_lmdb, bond_v4_fields_survive_full_writer)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  const crypto::hash p_id = make_hash(0x71);

  const shekyl::db::ArchivalBondValue written =
    bond_with_v4_fields({7, 9}, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
  db.put_archival_bond_value(p_id, written);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  EXPECT_EQ(read.claimed_settlement_epochs, written.claimed_settlement_epochs);
  EXPECT_EQ(read.first_paying_emission_height, written.first_paying_emission_height);
  EXPECT_EQ(read.bonded_total_atomic, written.bonded_total_atomic);
  EXPECT_EQ(read.held_shard_ids, written.held_shard_ids);
}

TEST(archival_substrate_lmdb, bond_v4_fields_survive_load_modify_store)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x72);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t settlement_epoch = 3;
  const uint64_t slash_height = 5000;

  const shekyl::db::ArchivalBondValue seed = bond_with_v4_fields({7, 9}, 2 * floor);
  db.put_archival_bond_value(p_id, seed);
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(slash_height, seq, p_id, /*shard_id*/ 7, settlement_epoch, floor);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  // The slash mutation took effect: shard 7 dropped, per-P balance debited.
  EXPECT_EQ(read.bonded_total_atomic, floor);
  EXPECT_FALSE(read.holds_shard(7));
  EXPECT_TRUE(read.holds_shard(9));
  // The F-S1 regression: the v4 dedup fields survived the load-modify-store.
  EXPECT_EQ(read.claimed_settlement_epochs, seed.claimed_settlement_epochs);
  EXPECT_EQ(read.first_paying_emission_height, seed.first_paying_emission_height);
}

TEST(archival_substrate_lmdb, bond_v4_claimed_set_survives_reorg_revert)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x73);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t settlement_epoch = 3;
  const uint64_t slash_height = 6000;

  const shekyl::db::ArchivalBondValue seed = bond_with_v4_fields({7, 9}, 2 * floor);
  db.put_archival_bond_value(p_id, seed);
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(slash_height, seq, p_id, /*shard_id*/ 7, settlement_epoch, floor);
  db.revert_archival_slashes_at_height(slash_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  // The reorg revert restored the slash mutation.
  EXPECT_EQ(read.bonded_total_atomic, 2 * floor);
  EXPECT_TRUE(read.holds_shard(7));
  EXPECT_TRUE(read.holds_shard(9));
  // The v4 dedup state survived both the slash and its revert: the
  // "dedup reverts with pop_block" invariant (FOLLOWUPS.md:1652) holds.
  EXPECT_EQ(read.claimed_settlement_epochs, seed.claimed_settlement_epochs);
  EXPECT_EQ(read.first_paying_emission_height, seed.first_paying_emission_height);
}

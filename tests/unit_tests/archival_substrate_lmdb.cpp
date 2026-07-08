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
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "shekyl/shekyl_ffi.h"

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

// encode() must reject any holdings_kind decode() would reject, so a write
// cannot persist a record no read path can decode (encode/decode symmetry).
TEST(archival_substrate_lmdb, bond_encode_rejects_unknown_holdings_kind)
{
  shekyl::db::ArchivalBondValue unknown_kind = baseline_bond();
  unknown_kind.holdings_kind = 2; // neither ShardSetCompact (0) nor CompleteTree (1)
  EXPECT_THROW(unknown_kind.encode(), std::runtime_error);

  // The full-bond writer funnels through encode(), so it inherits the rejection
  // and cannot persist an undecodable record.
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  EXPECT_THROW(db.put_archival_bond_value(make_hash(0x74), unknown_kind), std::runtime_error);
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
  fixture.db.batch_stop();
  fixture.db.batch_start();

  crypto::hash out_rk{};
  uint64_t leaf_count = 0;
  EXPECT_FALSE(db.get_archival_shard_segment_at_height(42, 50, out_rk, leaf_count));
  ASSERT_TRUE(db.get_archival_shard_segment_at_height(42, 100, out_rk, leaf_count));
  EXPECT_EQ(out_rk, rk);
  EXPECT_EQ(leaf_count, 26000u);
}

// Storage-flow coverage for the gather → Rust compute → store epoch-close
// sweep. Exact R_market / Σwork arithmetic is pinned by the Rust KAT
// (consensus_state_kat_v1.json §epoch_close); this test asserts the LMDB
// orchestration: row gathering, missing-bond skips, stale-epoch filtering,
// persistence, revert, and replay determinism.
//
// PF-8 transposition pin: shekyl_archival_epoch_close_compute's three
// leading operands (settlement_epoch, close_block_height,
// frozen_shard_count) are consecutive u64s at an extern "C" boundary where
// a swap compiles silently on both sides, and the Rust KAT structurally
// cannot catch it (it injects EpochCloseInputs, never crossing FFI). This
// fixture is the only production-shaped traversal of the seam, so its
// values are chosen pairwise distinct AND swap-flipping:
//   S = 3, H = 40000, F = 2, with join_settlement_epoch = S-1 = 2 and
//   freeze_height = 100.
//   swap(S,F): Rust sees settlement_epoch = 2 < join+1 — every bond drops
//     out of membership; r_market and sigma collapse to zero, failing the
//     r_market assertions.
//   swap(S,H) / swap(H,F): Rust sees close_block_height ∈ {3, 2}, both
//     ≤ freeze_height = 100 — shard-7 age collapses 750 → 0 milli, so
//     sigma drops 3500 → 2000, failing the exact-sigma pin (a bare
//     sigma > 0 would NOT catch these two swaps; the exact pin is
//     load-bearing).
// Any single transposition therefore fails an assertion below.
TEST(archival_substrate_lmdb, epoch_close_gather_compute_store_revert)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;

  // SETTLEMENT_EPOCH_BLOCKS is KAT-pinned at 10000; epoch E closes when the
  // first block of epoch E+1 connects.
  const uint64_t seb = 10000;
  const uint64_t settlement_epoch = 3;
  const uint64_t close_height = (settlement_epoch + 1) * seb;
  // Membership starts exactly at the settlement epoch (join+1 == S): the
  // PF-8 S↔F swap check depends on this being tight.
  const uint64_t join_epoch = settlement_epoch - 1;

  const crypto::hash p1 = make_hash(0x51);
  const crypto::hash p2 = make_hash(0x52);
  const crypto::hash p_missing = make_hash(0x53);
  const std::vector<uint8_t> pubkey = {0x01};

  db.put_archival_bond_record(p1, pubkey, join_epoch, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
  db.put_archival_bond_record(p2, pubkey, join_epoch, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7, 9}, {});

  // Aged segment for shard 7; shard 9 stays segment-less (age 0). A second
  // segment row (shard 1234, no credits) makes frozen_shard_count = 2 —
  // pairwise distinct from S = 3 and H = 40000 (PF-8). freeze_height = 100
  // exceeds every swapped-in close_height candidate (S or F), so an H-swap
  // collapses shard age.
  db.put_archival_shard_segment(7, 100, make_hash(0x60), 26000);
  db.put_archival_shard_segment(1234, 100, make_hash(0x66), 26000);

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
  // Exact-sigma PF-8 pin (KAT-pinned constants: age_weight = 2000,
  // plateau = 8000/16000 milli, WORK_MILLI_SCALE = 1000):
  //   shard 7: age = floor(3/4 epochs · 1000) = 750, g = 1000 + 2000·750/1000
  //            = 2500, scarcity(r=2) = 1000·2500/2000 = 1250
  //   shard 9: no segment, age = 0, scarcity(r=1) = 1000
  //   work_p1 = 1250, work_p2 = 1250 + 1000 = 2250; both below the first
  //   curve breakpoint (4000), so Curve is identity: sigma = 3500.
  // An H-position swap collapses shard-7 age to 0 (scarcity 500), giving
  // sigma = 2000 — nonzero, so only this exact pin distinguishes it.
  const uint64_t sigma = db.get_archival_sigma_work_milli(settlement_epoch);
  EXPECT_EQ(sigma, 3500u);

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

// ── M-2/Q7 emission snapshot identity KATs ──────────────────────────────────
// (REWARD_EMISSION_E3_GATING_ROUND.md §3 item 2)
//
// Three properties over the same fixture as the epoch-close test above (its
// exact per-P arithmetic is derived in that test's PF-8 comment: work_p1 =
// 1250, work_p2 = 2250, both curve-identity, sigma = 3500):
//
// 1. Snapshot == close gather. The emission snapshot carries the
//    close-processing height the close ran at and the persisted Σwork(E),
//    and its rows — gathered by the same shared routine the close used —
//    drive shekyl_archival_emission_epoch_work to each P's exact term in
//    the persisted sigma.
// 2. Sum-of-capped == persisted sigma (M-2 supply conservation at the
//    substrate layer): Σ_P Curve(work_P) over the claimants equals the
//    stored denominator exactly.
// 3. Live-descriptor immunity (WS-1 §5): mutating tip holdings after the
//    close — the M2-1 drop-after-serve mutation — leaves every snapshot
//    output bit-identical. Holdings never enter the work channel.
TEST(archival_substrate_lmdb, emission_snapshot_identity_and_descriptor_immunity)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;

  const uint64_t seb = 10000;
  const uint64_t settlement_epoch = 3;
  const uint64_t close_height = (settlement_epoch + 1) * seb;
  const uint64_t join_epoch = settlement_epoch - 1;

  const crypto::hash p1 = make_hash(0x51);
  const crypto::hash p2 = make_hash(0x52);
  const crypto::hash p_no_credit = make_hash(0x53);
  const std::vector<uint8_t> pubkey = {0x01};

  db.put_archival_bond_record(p1, pubkey, join_epoch, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
  db.put_archival_bond_record(p2, pubkey, join_epoch, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7, 9}, {});
  // Bonded but never credited in E: claimant_bond_idx must come back as the
  // no-credit sentinel, zero work by construction.
  db.put_archival_bond_record(p_no_credit, pubkey, join_epoch,
    2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});

  db.put_archival_shard_segment(7, 100, make_hash(0x60), 26000);
  db.put_archival_shard_segment(1234, 100, make_hash(0x66), 26000);

  db.set_archival_serve_credit_bit(p1, 7, settlement_epoch);
  db.set_archival_serve_credit_bit(p2, 7, settlement_epoch);
  db.set_archival_serve_credit_bit(p2, 9, settlement_epoch);

  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  const uint64_t sigma = db.get_archival_sigma_work_milli(settlement_epoch);
  ASSERT_EQ(sigma, 3500u);

  // Gather + marshal + FFI compute for one claimant. The marshaling mirrors
  // what PR-E3's verify shim will do: FFI pointers into the snapshot's
  // vectors, by value, no callbacks (Q7).
  const auto emission_work = [&](const crypto::hash& p, uint64_t& out_work,
    uint64_t& out_capped, size_t& out_claimant_idx) {
    ArchivalEmissionEpochSnapshot snap;
    lmdb.gather_archival_emission_epoch_snapshot(p, settlement_epoch, snap);

    EXPECT_EQ(snap.settlement_epoch, settlement_epoch);
    EXPECT_EQ(snap.close_block_height, close_height);
    EXPECT_EQ(snap.sigma_work_milli, sigma);
    // Property 1, row identity with the close's gather: two credited bonds,
    // two credited shards (7 and 9 — never the credit-less 1234), three
    // credit pairs.
    EXPECT_EQ(snap.bonds.size(), 2u);
    EXPECT_EQ(snap.shards.size(), 2u);
    EXPECT_EQ(snap.credit_pairs.size(), 3u);
    out_claimant_idx = snap.claimant_bond_idx;

    std::vector<shekyl_archival_epoch_close_bond> bonds;
    bonds.reserve(snap.bonds.size());
    for (const ArchivalEmissionEpochSnapshot::BondRow& row : snap.bonds)
    {
      shekyl_archival_epoch_close_bond b{};
      b.join_settlement_epoch = row.join_settlement_epoch;
      b.is_foundation_complete_tree = row.is_foundation_complete_tree ? 1 : 0;
      b.bad_intervals_ptr = row.bad_intervals_flat.empty()
        ? nullptr : row.bad_intervals_flat.data();
      b.bad_intervals_len = row.bad_intervals_flat.size() / 2;
      bonds.push_back(b);
    }
    std::vector<shekyl_archival_epoch_close_shard> shards;
    shards.reserve(snap.shards.size());
    for (const ArchivalEmissionEpochSnapshot::ShardRow& row : snap.shards)
    {
      shekyl_archival_epoch_close_shard s{};
      s.shard_id = row.shard_id;
      s.freeze_height = row.freeze_height;
      s.has_segment = row.has_segment ? 1 : 0;
      shards.push_back(s);
    }
    std::vector<shekyl_archival_credit_pair> pairs;
    pairs.reserve(snap.credit_pairs.size());
    for (const ArchivalEmissionEpochSnapshot::CreditPair& pair : snap.credit_pairs)
      pairs.push_back({ pair.bond_idx, pair.shard_idx });

    shekyl_archival_emission_epoch_snapshot ffi{};
    ffi.settlement_epoch = snap.settlement_epoch;
    ffi.close_block_height = snap.close_block_height;
    ffi.sigma_work_milli = snap.sigma_work_milli;
    ffi.bonds_ptr = bonds.empty() ? nullptr : bonds.data();
    ffi.bonds_len = bonds.size();
    ffi.shards_ptr = shards.empty() ? nullptr : shards.data();
    ffi.shards_len = shards.size();
    ffi.credit_pairs_ptr = pairs.empty() ? nullptr : pairs.data();
    ffi.credit_pairs_len = pairs.size();
    ffi.claimant_bond_idx = snap.claimant_bond_idx;

    return shekyl_archival_emission_epoch_work(&ffi, &out_work, &out_capped);
  };

  uint64_t work_p1 = 0, capped_p1 = 0;
  uint64_t work_p2 = 0, capped_p2 = 0;
  uint64_t work_none = 0, capped_none = 0;
  size_t idx_p1 = 0, idx_p2 = 0, idx_none = 0;

  ASSERT_EQ(emission_work(p1, work_p1, capped_p1, idx_p1), SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
  ASSERT_EQ(emission_work(p2, work_p2, capped_p2, idx_p2), SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
  ASSERT_EQ(emission_work(p_no_credit, work_none, capped_none, idx_none),
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);

  // Property 1 exact per-P pins (arithmetic per the PF-8 comment above).
  EXPECT_NE(idx_p1, SIZE_MAX);
  EXPECT_NE(idx_p2, SIZE_MAX);
  EXPECT_NE(idx_p1, idx_p2);
  EXPECT_EQ(work_p1, 1250u);
  EXPECT_EQ(capped_p1, 1250u);
  EXPECT_EQ(work_p2, 2250u);
  EXPECT_EQ(capped_p2, 2250u);

  // No-credit claimant: sentinel index, zero outputs, OK status.
  EXPECT_EQ(idx_none, SIZE_MAX);
  EXPECT_EQ(work_none, 0u);
  EXPECT_EQ(capped_none, 0u);

  // Property 2: M-2 supply conservation — sum of capped terms is the
  // persisted denominator exactly.
  EXPECT_EQ(capped_p1 + capped_p2, sigma);

  // Property 3: live-descriptor immunity. p2 drops shard 9 from its tip
  // holdings after the close — the exact M2-1 drop-after-serve mutation.
  // Every snapshot output must be bit-identical: the work channel reads the
  // serve-credit ledger, never the holdings descriptor.
  db.put_archival_bond_record(p2, pubkey, join_epoch, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
  fixture.db.batch_stop();
  fixture.db.batch_start();

  uint64_t work_p2_after = 0, capped_p2_after = 0;
  size_t idx_p2_after = 0;
  ASSERT_EQ(emission_work(p2, work_p2_after, capped_p2_after, idx_p2_after),
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
  EXPECT_EQ(work_p2_after, work_p2);
  EXPECT_EQ(capped_p2_after, capped_p2);
  EXPECT_EQ(idx_p2_after, idx_p2);
}

// ── M1 reward gate: count pass + stored shape (ARCHIVAL_REWARD_GATE_M1.md) ──
//
// The Rust activation-boundary KAT (tests/reward_gate_kat.rs, G-1..G-10)
// injects frozen_shard_count and never executes the C++ operand reader, so
// the count-pass cases live here (§11.8 M3-1/M3-2, amended §11.11 for the
// O(1) counter): the freeze_height ≤ H_close frontier boundary (equality
// counts — an off-by-one here is a consensus fork at exactly the boundary
// class), the malformed-frontier loud abort (a lenient skip silently lowers
// the count on one node — a fork in the gating direction), counter/table
// divergence aborts, and the write-txn precondition.

TEST(archival_substrate_lmdb, frozen_shard_count_frontier_boundary)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const uint64_t h_close = 10000;

  // Production-shaped rows: dense IDs, per-branch-monotone freeze heights
  // (O-2), the frontier frozen exactly at the close.
  db.put_archival_shard_segment(0, h_close - 1, make_hash(0x61), 26000);
  db.put_archival_shard_segment(1, h_close, make_hash(0x62), 26000);

  // Equality counts (frontier freeze_height <= h_close, §1.1): the row
  // frozen AT the close boundary is frozen at the close.
  EXPECT_EQ(lmdb.count_frozen_shards_at_close(h_close), 2u);
  EXPECT_EQ(lmdb.count_frozen_shards_at_close(h_close + 5), 2u);

  // A frontier row above the close height is tree/registry disagreement —
  // impossible under the production writer (rows freeze at the writing
  // block's height, before the same-txn close) — and aborts loudly
  // (M1 §11.11: the fixture-branch "future rows are filtered out"
  // disposition is superseded; lenient filtering would mask a divergent
  // DB in the gating direction).
  EXPECT_THROW(lmdb.count_frozen_shards_at_close(h_close - 1), std::runtime_error);

  // Differential oracle (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4): the
  // full-decode walk agrees with the persisted counter.
  EXPECT_EQ(lmdb.count_frozen_shard_rows_by_walk_for_test(), 2u);
}

TEST(archival_substrate_lmdb, frozen_shard_count_malformed_frontier_aborts)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;

  db.put_archival_shard_segment(7, 100, make_hash(0x64), 26000);
  // Correct length, wrong version byte: decodable length, undecodable row.
  // Written at shard_id 8 > 7 so it is the MDB_LAST frontier the O(1)
  // reader probes.
  std::vector<uint8_t> bad(1 + 8 + 8 + 32, 0);
  bad[0] = 99;
  lmdb.put_archival_shard_segment_raw_for_corruption_test(8, bad);

  // Loud abort, never a lenient skip that returns 1 (§1.1 decode-failure
  // pin: two nodes disagreeing on the count is a fork in the gating
  // direction). The differential walk aborts on the same row.
  EXPECT_THROW(lmdb.count_frozen_shards_at_close(200), std::runtime_error);
  EXPECT_THROW(lmdb.count_frozen_shard_rows_by_walk_for_test(), std::runtime_error);

  // A truncated row aborts identically.
  std::vector<uint8_t> truncated(10, 0);
  truncated[0] = 1;
  lmdb.put_archival_shard_segment_raw_for_corruption_test(8, truncated);
  EXPECT_THROW(lmdb.count_frozen_shards_at_close(200), std::runtime_error);
}

TEST(archival_substrate_lmdb, frozen_shard_counter_table_divergence_aborts)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;

  // The raw corruption writer bypasses the counter: a decodable row with the
  // counter still at zero is exactly the rows-without-counter divergence the
  // reader must refuse (a silently-wrong operand is a consensus fork in the
  // gating direction).
  shekyl::db::ArchivalShardSegmentValue seg{};
  seg.freeze_height = 100;
  seg.segment_leaf_count = 26000;
  lmdb.put_archival_shard_segment_raw_for_corruption_test(0, seg.encode());
  EXPECT_THROW(lmdb.count_frozen_shards_at_close(200), std::runtime_error);
}

TEST(archival_substrate_lmdb, frozen_shard_count_requires_active_write_txn)
{
  TempLMDB fixture;
  BlockchainLMDB& lmdb = fixture.db;
  fixture.db.batch_stop();
  EXPECT_THROW(lmdb.count_frozen_shards_at_close(100), std::runtime_error);
  fixture.db.batch_start();
}

// Stored shape of an all-zero close + reorg round-trip (§5 round-2
// additions). Per §2.1 the store cannot represent gatedness: a gated close
// and a legitimately-zero close are bitwise-identical to every store reader.
// Pre-seal the production gate path is unreachable by construction (the §4
// sentinel is the gate-identity 0, and the FFI threads K_COVER verbatim), so
// this test drives the zero-output close through a legitimately-zero epoch —
// the identical stored shape the gate produces post-seal: sigma row PRESENT
// and zero (not NOTFOUND — the §2.1 never-skip-the-close pin), no r_market
// rows, close-log row written so revert stays symmetric.
TEST(archival_substrate_lmdb, zero_output_close_stored_shape_and_reorg_roundtrip)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;

  const uint64_t seb = 10000;
  const uint64_t settlement_epoch = 1;
  const uint64_t close_height = (settlement_epoch + 1) * seb;

  // Membership begins at join+1, so a bond joined AT the settlement epoch is
  // not yet a member: its credit rows yield r_market = 0 and sigma = 0.
  const crypto::hash p1 = make_hash(0x54);
  db.put_archival_bond_record(p1, {0x01}, settlement_epoch,
    2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC,
    shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact, {7}, {});
  db.put_archival_shard_segment(7, 0, make_hash(0x65), 26000);
  db.set_archival_serve_credit_bit(p1, 7, settlement_epoch);

  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  // Sigma row present-and-zero — distinguishable from NOTFOUND only through
  // the probe (get_archival_sigma_work_milli launders NOTFOUND to 0).
  EXPECT_TRUE(lmdb.has_archival_sigma_work_row(settlement_epoch));
  EXPECT_EQ(db.get_archival_sigma_work_milli(settlement_epoch), 0u);
  // No r_market rows (the store phase skips zero counts entirely).
  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 0u);

  // Revert keys on the close log: the sigma row disappearing proves the log
  // row was written (revert returns early on a missing log row).
  db.revert_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();
  EXPECT_FALSE(lmdb.has_archival_sigma_work_row(settlement_epoch));

  // Re-apply: bit-identical zero shape (close/revert/re-apply symmetry at a
  // zero-output close, the §9.4 pairing exercised on the gate's shape).
  db.process_archival_epoch_close_at_height(close_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();
  EXPECT_TRUE(lmdb.has_archival_sigma_work_row(settlement_epoch));
  EXPECT_EQ(db.get_archival_sigma_work_milli(settlement_epoch), 0u);
  EXPECT_EQ(db.get_archival_r_market(7, settlement_epoch), 0u);
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

// apply_archival_slash_one is public (scheduler + tests). Without an active
// write txn its mutating helpers would dereference a null *m_write_txn (UB);
// the precondition must reject that loudly instead.
TEST(archival_substrate_lmdb, apply_slash_requires_active_write_txn)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x75);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;

  db.put_archival_bond_value(p_id, bond_with_v4_fields({7, 9}, 2 * floor));
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);
  // Close the batch so no write txn is active when the public entry is called.
  fixture.db.batch_stop();

  uint32_t seq = 0;
  EXPECT_THROW(
    lmdb.apply_archival_slash_one(6000, seq, p_id, /*shard_id*/ 7, /*epoch*/ 3, floor),
    std::runtime_error);

  // Restore an active batch for TempLMDB teardown symmetry.
  fixture.db.batch_start();
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

// ── WS-1: as-of-height holdings accessor (REWARD_EMISSION_E3_GATING_ROUND.md §5) ──
//
// archival_bond_holds_shard(P, s, at_height) answers "did P hold s at
// at_height?", not "does P hold s now". Both consumers — serve-credit
// acceptance (blockchain.cpp, check_archival_serve_credit_input) and slash
// eligibility (db_lmdb.cpp, archival_challenge_failed_at_height) — pass the
// challenge fire height, so the accessor's boundary is the shared consensus
// boundary for reward and punishment alike. Holdings only shrink post-join at
// the current substrate (slash-apply's erase/demotion is the sole mutation,
// journaled per-block in the slash log), so the accessor reconstructs
// "held-at-height" from tip holdings plus logged removals strictly above
// at_height. The inverse boundary case — held at tip but NOT at h_fire — is
// structurally unrepresentable until a holdings-add path (HoldingsUpdate)
// lands; that path's pre-flight owns extending the reconstruction.

// Acceptance-gate KAT, accessor boundary (§5.6 #2): a shard removed by a
// slash at height H was held at every height < H and not held at ≥ H.
// This is the exact read the serve-credit acceptance gate performs at
// h_fire, and the read the slash-eligibility mirror bottoms out in — the
// tip-read defect ("drop after fire escapes accounting") is dead only if
// this boundary holds.
TEST(archival_substrate_lmdb, holds_shard_honors_at_height_across_slash_removal)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x76);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t slash_height = 6000;

  db.put_archival_bond_value(p_id, bond_with_v4_fields({7, 9}, 2 * floor));
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(slash_height, seq, p_id, /*shard_id*/ 7, /*epoch*/ 3, floor);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  // Tip no longer holds 7 (the slash erased it) — the old tip-read returned
  // false for every at_height, the drop-after-fire under-count/escape.
  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  EXPECT_FALSE(read.holds_shard(7));

  // Held at every height strictly below the slash …
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, slash_height - 1));
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, 0));
  // … and not held at the slash height or after (holdings at h are the
  // post-connect state of block h).
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 7, slash_height));
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 7, slash_height + 1000));

  // A shard never slashed reads from tip at any height.
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 9, 0));
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 9, slash_height + 1000));
  // A shard never held is not resurrected by someone else's log rows.
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 42, slash_height - 1));
}

// Complete-tree demotion reconstruction: the slash cleared *every* holding,
// so the pre-image held every shard. The v2 log row records the pre-slash
// holdings kind — without it the log could not distinguish "demoted
// complete-tree" from "compact bond that lost its last shard", and
// reconstruction (plus pop-revert, below) had to guess.
TEST(archival_substrate_lmdb, holds_shard_reconstructs_complete_tree_demotion)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x77);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t slash_height = 6000;

  shekyl::db::ArchivalBondValue seed{};
  seed.hybrid_pubkey = {0x0A};
  seed.join_settlement_epoch = 2;
  seed.bonded_total_atomic = 2 * floor;
  seed.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsCompleteTree;
  db.put_archival_bond_value(p_id, seed);
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(slash_height, seq, p_id, /*shard_id*/ 7, /*epoch*/ 3, floor);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  // Demoted at tip: compact, empty.
  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  EXPECT_FALSE(read.is_complete_tree());
  EXPECT_TRUE(read.held_shard_ids.empty());

  // Before the demotion the bond held every shard — including ones the
  // slash row does not name.
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, slash_height - 1));
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 999, slash_height - 1));
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 7, slash_height));
  EXPECT_FALSE(db.archival_bond_holds_shard(p_id, 999, slash_height));
}

// Pop-revert restores the recorded pre-image, not a heuristic's guess. The
// v1 log format forced the revert to infer the pre-slash shape from
// (slashed_amount == floor && holdings empty && !complete_tree) — which
// mis-restored a slashed single-shard compact bond to complete-tree
// whenever the amounts coincided. The v2 row records holdings_pre_kind, so
// the compact single-shard case round-trips exactly.
TEST(archival_substrate_lmdb, slash_revert_restores_single_shard_compact_bond)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x78);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t slash_height = 6000;

  // Single-shard compact bond slashed for exactly the floor: the v1
  // heuristic's trigger shape.
  db.put_archival_bond_value(p_id, bond_with_v4_fields({7}, 2 * floor));
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(slash_height, seq, p_id, /*shard_id*/ 7, /*epoch*/ 3, floor);
  db.revert_archival_slashes_at_height(slash_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  EXPECT_FALSE(read.is_complete_tree());
  EXPECT_EQ(read.held_shard_ids, std::vector<uint64_t>({7}));
  EXPECT_EQ(read.bonded_total_atomic, 2 * floor);
  // The revert also consumed the log row: reconstruction no longer sees a
  // removal, so as-of-height reads fall through to (restored) tip.
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, slash_height + 1));
}

// Complete-tree pop-revert restores the demotion from the recorded pre-kind
// (previously inferred from the amount/emptiness heuristic).
TEST(archival_substrate_lmdb, slash_revert_restores_complete_tree_demotion)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x79);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t slash_height = 6000;

  shekyl::db::ArchivalBondValue seed{};
  seed.hybrid_pubkey = {0x0A};
  seed.join_settlement_epoch = 2;
  seed.bonded_total_atomic = 2 * floor;
  seed.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsCompleteTree;
  db.put_archival_bond_value(p_id, seed);
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(slash_height, seq, p_id, /*shard_id*/ 7, /*epoch*/ 3, floor);
  db.revert_archival_slashes_at_height(slash_height);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_id, read));
  EXPECT_TRUE(read.is_complete_tree());
  EXPECT_EQ(read.bonded_total_atomic, 2 * floor);
  EXPECT_TRUE(db.archival_bond_holds_shard(p_id, 7, slash_height + 1));
}

namespace {

/// Append `count` minimal miner-only blocks (heights `height()` upward).
/// Each block carries a unique coinbase (txin_gen height) and no outputs, so
/// the curve-tree path is a no-op and the per-block cost is a handful of LMDB
/// puts — cheap enough to reach archival epoch heights (SEB = 10 000) in a
/// unit test. add_block runs the production connect hooks, including
/// process_archival_slash_at_height, which is the point: the slash KAT below
/// exercises the scheduler at its production call site, not via a test shim.
void append_minimal_blocks(BlockchainDB& db, uint64_t count)
{
  crypto::hash prev = db.height() == 0
    ? crypto::null_hash : db.get_block_hash_from_height(db.height() - 1);
  for (uint64_t i = 0; i < count; ++i)
  {
    const uint64_t height = db.height();
    block blk{};
    blk.major_version = 1;
    blk.minor_version = 1;
    blk.timestamp = 1500000000 + height;
    blk.prev_id = prev;
    blk.curve_tree_root = crypto::null_hash;
    blk.nonce = 0;

    transaction miner_tx{};
    miner_tx.version = 1;
    miner_tx.unlock_time = height + 60;
    txin_gen gen{};
    gen.height = height;
    miner_tx.vin.push_back(gen);
    blk.miner_tx = std::move(miner_tx);

    db.add_block(std::make_pair(blk, block_to_blob(blk)), 100, 100,
      height + 1, 0, {});
    prev = get_block_hash(blk);
  }
}

} // namespace

// ── WS-1 slash-side mirror KAT (REWARD_EMISSION_E3_GATING_ROUND.md §5.6) ──
//
// Full production path: blocks connect through add_block, whose slash hook
// crosses epoch 1's deadline and runs eligibility — good_through, the
// serve-credit bit, the slash-applied bit, then the h_fire derivation from
// the real seal-hash block and the as-of-fire holdings read (the same
// accessor and the same derived height the serve-credit acceptance gate
// uses). "Held at fire, didn't respond → slash" and "responded → no slash"
// are the two polarities of the shared boundary; the accessor fix that
// changed the reward side changed this consensus rule too, so it is
// validated here at its own production site.
TEST(archival_substrate_lmdb, slash_scheduler_slashes_missed_challenge_at_deadline)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t settlement_epoch = 1;

  HardFork hf(db, 1, 0);
  hf.init();
  db.set_hard_fork(&hf);

  // Two bonds, both joined at epoch 0 and holding shard 7 through epoch 1's
  // challenge. P_miss never responds; P_served earned the (P, 7, E=1) credit.
  const crypto::hash p_miss = make_hash(0x7B);
  const crypto::hash p_served = make_hash(0x7C);
  shekyl::db::ArchivalBondValue seed{};
  seed.hybrid_pubkey = {0x0A};
  seed.join_settlement_epoch = 0;
  seed.bonded_total_atomic = 2 * floor;
  seed.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
  seed.held_shard_ids = {7};
  db.put_archival_bond_value(p_miss, seed);
  db.put_archival_bond_value(p_served, seed);
  db.set_total_bonded_atomic(4 * floor);
  db.set_total_burned(0);
  db.set_archival_serve_credit_bit(p_served, 7, settlement_epoch);

  // Connect blocks through epoch 1's slash deadline. The deadline block's
  // connect hook processes the epoch-1 slash pass.
  const uint64_t h_deadline =
    shekyl_archival_epoch_slash_deadline_height(settlement_epoch);
  append_minimal_blocks(db, h_deadline + 2);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  // P_miss: held at the fire height (derivable from the real seal block) and
  // never responded — slashed. The bond lost the shard at tip, standing is
  // gone from E onward, and the stake was burned.
  shekyl::db::ArchivalBondValue read{};
  ASSERT_TRUE(db.get_archival_bond_value(p_miss, read));
  EXPECT_FALSE(read.holds_shard(7));
  EXPECT_EQ(read.bonded_total_atomic, 2 * floor - floor);
  EXPECT_FALSE(db.archival_bond_good_through(p_miss, settlement_epoch));
  EXPECT_EQ(db.get_total_burned(), floor);

  // The as-of-fire read the eligibility bottomed out in still answers "held"
  // for the fire height after the slash emptied the tip holdings — the
  // "regardless of tip holdings" half of the mirror, reconstructed from the
  // slash log the production pass just wrote.
  const uint64_t h_open = shekyl_archival_epoch_open_height(settlement_epoch);
  const uint64_t h_close = shekyl_archival_epoch_close_height(settlement_epoch);
  const uint64_t h_seal = shekyl_archival_challenge_seal_height(h_open);
  const crypto::hash seal_hash = db.get_block_hash_from_height(h_seal);
  const uint64_t h_fire = shekyl_archival_challenge_fire_height(
    h_open, h_close, reinterpret_cast<const uint8_t*>(seal_hash.data),
    reinterpret_cast<const uint8_t*>(p_miss.data), 7, settlement_epoch);
  ASSERT_NE(h_fire, 0u);
  ASSERT_LE(h_fire, h_close);
  EXPECT_TRUE(db.archival_bond_holds_shard(p_miss, 7, h_fire));

  // P_served: same holdings, same epoch — the serve-credit bit
  // short-circuits eligibility, so no slash and standing intact.
  ASSERT_TRUE(db.get_archival_bond_value(p_served, read));
  EXPECT_TRUE(read.holds_shard(7));
  EXPECT_EQ(read.bonded_total_atomic, 2 * floor);
  EXPECT_TRUE(db.archival_bond_good_through(p_served, settlement_epoch + 1));
}

// One-strike invariant (cascade guard): a slash for epoch E appends the
// open-ended bad interval [E, ∞), so good_through(E') is false for every
// E' ≥ E. With the tip-holdings pre-filter deleted from slash eligibility
// (WS-1: eligibility reads holdings as-of-fire), this interval — not the
// deleted tip read — is what makes a multi-epoch slash cascade against one
// missed challenge unreachable. If the interval semantics ever change, this
// KAT fails and the cascade question reopens.
TEST(archival_substrate_lmdb, slash_bad_interval_blocks_later_epochs)
{
  TempLMDB fixture;
  BlockchainDB& db = fixture.db;
  BlockchainLMDB& lmdb = fixture.db;
  const crypto::hash p_id = make_hash(0x7A);
  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  const uint64_t settlement_epoch = 3;

  db.put_archival_bond_value(p_id, bond_with_v4_fields({7, 9}, 2 * floor));
  db.set_total_bonded_atomic(2 * floor);
  db.set_total_burned(0);

  ASSERT_TRUE(db.archival_bond_good_through(p_id, settlement_epoch));

  uint32_t seq = 0;
  lmdb.apply_archival_slash_one(6000, seq, p_id, /*shard_id*/ 7, settlement_epoch, floor);
  fixture.db.batch_stop();
  fixture.db.batch_start();

  // Standing is gone from the slashed epoch onward — eligibility's
  // good_through gate rejects before any holdings question is asked.
  EXPECT_FALSE(db.archival_bond_good_through(p_id, settlement_epoch));
  EXPECT_FALSE(db.archival_bond_good_through(p_id, settlement_epoch + 1));
  EXPECT_FALSE(db.archival_bond_good_through(p_id, settlement_epoch + 100));
}

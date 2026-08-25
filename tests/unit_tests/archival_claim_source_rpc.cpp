// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// PR-1 tests for the emission claim-source RPC marshaling
// (`EMISSION_CLAIM_BUILDER.md` §7 / §8 PR 1), covering the two round-2
// watch items plus the wire contract:
//
//   1. **Single-gather operand fidelity** (§7.1, CB-1(b)'s daemon face):
//      every per-epoch field the marshal helper emits is a field-for-field
//      copy of a direct `gather_archival_emission_epoch_snapshot` call on
//      the same LMDB state. The helper reconstructs no operand — the test
//      compares the RPC response against the landed gather row by row.
//
//   2. **Transport cause-blindness** (§7.2): the response carries the full
//      `[claim_window_floor(settled), settled − 1]` window unconditionally.
//      A claimant with a bond and credited epochs and a `p_id` with no bond
//      record at all receive identically-shaped windows, and the request
//      struct carries `p_id` only (member-count-pinned below).
//
//   3. **Wire contract**: epee KV JSON round-trip, the `SIZE_MAX` →
//      `u64::MAX` no-credit sentinel, and epee's omit-empty-container
//      behavior — the behavior the Rust decode's absent-equals-empty rule
//      (`shekyl-engine-core/src/engine/emission_source.rs`) relies on.
//
// The LMDB fixture IS tests/unit_tests/archival_substrate_lmdb.cpp's
// emission-snapshot KAT, via the shared archival_lmdb_test_helpers.h seeder
// (single-sourced so the two cannot drift); the only synthetic element is
// the tip height, overridden so the settled epoch lands past the closed
// test epoch without minting 50k blocks. The gather, the bond reader, and
// the close path are the real landed LMDB code.

#include "gtest/gtest.h"

#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <rapidjson/document.h>

#include "archival_lmdb_test_helpers.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/shekyl_types.h"
#include "rpc/archival_claim_source.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "shekyl/shekyl_ffi.h"
#include "storages/portable_storage_template_helper.h"

using namespace cryptonote;

namespace {

using archival_test::make_hash;
using archival_test::EmissionSnapshotKat;

/// The real LMDB with a synthetic tip: `height()` is the only override, so
/// the settled-epoch operand can land past the closed test epoch while the
/// gather/bond/close paths stay the landed implementations.
class FakeTipLMDB : public BlockchainLMDB
{
public:
  uint64_t fake_height = 0;
  uint64_t height() const override { return fake_height; }
};

struct ClaimSourceFixture
{
  archival_test::TempArchivalLMDB<FakeTipLMDB> lmdb;
  FakeTipLMDB& db = lmdb.db;
  EmissionSnapshotKat kat;

  static constexpr uint64_t kSettlementEpoch = EmissionSnapshotKat::kSettlementEpoch;
  static constexpr uint64_t kTipHeight = 50000;  // settled epoch = 5 > 3

  crypto::hash p1;
  crypto::hash p_no_bond;

  ClaimSourceFixture()
  {
    // The shared emission-snapshot KAT shape — the same seed the substrate
    // KATs drive, so the fixture arithmetic below cannot drift from them.
    kat.seed(db);
    p1 = kat.p1;
    p_no_bond = make_hash(0x99);

    // Give p1 a claimed epoch through the full-bond writer so part A's
    // claimed_settlement_epochs marshaling is exercised non-empty (the
    // claimed set is not a close operand, so post-close mutation is
    // equivalent to pre-close seeding for every read below).
    shekyl::db::ArchivalBondValue bond{};
    EXPECT_TRUE(bdb().get_archival_bond_value(p1, bond));
    bond.claimed_settlement_epochs = {1};
    bdb().put_archival_bond_value(p1, bond);

    db.fake_height = kTipHeight;
  }

  /// The archival readers/writers are public on the interface only
  /// (private overrides on BlockchainLMDB) — seed/read through the base ref.
  BlockchainDB& bdb() { return db; }
};

using cmd = COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE;

} // anonymous namespace

// Watch item 1 (§7.1): every response field is a field-for-field copy of
// the single landed gather on the same DB state — the marshal helper owns
// no second gather path and reconstructs no operand.
//
// COVERS: what the marshaler *computes* — whether each field equals the value
// its landed source produces on this DB state. This is the SEMANTICS test, and
// it is the one that catches a mis-derived or unresolved operand (the storage
// sentinel shipped raw fails here).
// DOES NOT COVER: whether those values survive serialization. That is
// `wire_roundtrip_sentinel_and_omit_empty`, below, and the two are not
// substitutes — see its header for why.
TEST(archival_claim_source_rpc, fill_matches_single_gather_field_for_field)
{
  ClaimSourceFixture fx;

  cmd::response res{};
  rpc::fill_archival_emission_claim_source(fx.db, fx.p1, res);

  EXPECT_EQ(res.chain_height, ClaimSourceFixture::kTipHeight);
  const uint64_t settled =
    shekyl_archival_settlement_epoch_at_height(ClaimSourceFixture::kTipHeight);
  EXPECT_EQ(res.current_settled_epoch, settled);

  // Part A mirrors the bond record as the full-bond reader returns it.
  shekyl::db::ArchivalBondValue bond{};
  ASSERT_TRUE(fx.bdb().get_archival_bond_value(fx.p1, bond));
  EXPECT_TRUE(res.has_bond_record);
  EXPECT_EQ(res.join_settlement_epoch, bond.join_settlement_epoch);
  EXPECT_EQ(res.holdings_kind, bond.holdings_kind);
  EXPECT_EQ(res.held_shard_ids, bond.held_shard_ids);
  EXPECT_EQ(res.claimed_settlement_epochs, std::vector<uint64_t>{1});

  // The `Unbond` exit operands: same source, same fold, no second derivation.
  EXPECT_EQ(res.bonded_total_atomic, bond.bonded_total_atomic);
  // The cooldown anchor is whatever the verify arm's gather + the exported
  // Rust fold produce on this state — recomputed here through the SAME two
  // calls rather than restated, so the assertion cannot drift from the
  // marshaler by agreeing with a copy of its logic.
  const std::vector<uint64_t> served = bond.is_complete_tree()
    ? fx.bdb().archival_bond_all_last_served_epochs(fx.p1)
    : fx.bdb().archival_bond_last_served_epochs(fx.p1, bond.held_shard_ids);
  uint8_t want_present = 0;
  uint64_t want_epoch = 0;
  ASSERT_EQ(shekyl_archival_whole_record_last_served(
              served.empty() ? nullptr : served.data(),
              served.size(),
              &want_present,
              &want_epoch),
    SHEKYL_ARCHIVAL_BOND_POST_OK);
  EXPECT_EQ(res.has_last_served_epoch, want_present != 0);
  EXPECT_EQ(res.last_served_epoch, want_epoch);

  // The scheduler's storage sentinel is resolved here, never shipped raw: a
  // consumer must not have to know that u64 max means "nothing settled".
  const uint64_t watermark = fx.bdb().get_archival_last_slash_epoch();
  EXPECT_EQ(res.has_last_settled_slash_epoch, watermark != UINT64_MAX);
  if (res.has_last_settled_slash_epoch)
    EXPECT_EQ(res.last_settled_slash_epoch, watermark);
  else
    EXPECT_EQ(res.last_settled_slash_epoch, 0u)
      << "the sentinel must not leak through as a value";

  // Part B: the full window, ascending, one entry per epoch in
  // [claim_window_floor(settled), settled − 1].
  const uint64_t floor = shekyl_archival_claim_window_floor(settled);
  ASSERT_EQ(res.epochs.size(), settled - floor);

  for (size_t i = 0; i < res.epochs.size(); ++i)
  {
    const uint64_t epoch = floor + i;
    const auto& out = res.epochs[i];
    EXPECT_EQ(out.settlement_epoch, epoch);

    ArchivalEmissionEpochSnapshot snap;
    fx.bdb().gather_archival_emission_epoch_snapshot(fx.p1, epoch, snap);

    EXPECT_EQ(out.close_block_height, snap.close_block_height);
    EXPECT_EQ(out.sigma_work_milli, snap.sigma_work_milli);
    EXPECT_EQ(out.budget_atomic, snap.budget_atomic);
    EXPECT_EQ(out.has_budget_row, snap.has_budget_row);

    ASSERT_EQ(out.bonds.size(), snap.bonds.size());
    for (size_t b = 0; b < snap.bonds.size(); ++b)
    {
      EXPECT_EQ(out.bonds[b].join_settlement_epoch, snap.bonds[b].join_settlement_epoch);
      EXPECT_EQ(out.bonds[b].is_foundation_complete_tree, snap.bonds[b].is_foundation_complete_tree);
      EXPECT_EQ(out.bonds[b].bad_intervals_flat, snap.bonds[b].bad_intervals_flat);
    }
    ASSERT_EQ(out.shards.size(), snap.shards.size());
    for (size_t s = 0; s < snap.shards.size(); ++s)
    {
      EXPECT_EQ(out.shards[s].shard_id, snap.shards[s].shard_id);
      EXPECT_EQ(out.shards[s].freeze_height, snap.shards[s].freeze_height);
      EXPECT_EQ(out.shards[s].has_segment, snap.shards[s].has_segment);
    }
    ASSERT_EQ(out.credit_pairs.size(), snap.credit_pairs.size());
    for (size_t p = 0; p < snap.credit_pairs.size(); ++p)
    {
      EXPECT_EQ(out.credit_pairs[p].bond_idx, static_cast<uint64_t>(snap.credit_pairs[p].bond_idx));
      EXPECT_EQ(out.credit_pairs[p].shard_idx, static_cast<uint64_t>(snap.credit_pairs[p].shard_idx));
    }
    // SIZE_MAX sentinel → u64::MAX on the wire, exactly the verify shim's
    // decode contract.
    if (snap.claimant_bond_idx == SIZE_MAX)
      EXPECT_EQ(out.claimant_bond_idx, std::numeric_limits<uint64_t>::max());
    else
      EXPECT_EQ(out.claimant_bond_idx, static_cast<uint64_t>(snap.claimant_bond_idx));
  }

  // The closed epoch is the only one with rows: two credited bonds, one
  // credited shard, three credit pairs (fixture arithmetic per the
  // substrate KAT); every other window epoch rides out as an empty
  // has_budget_row=false row, never filtered (§7.2). Guard the index
  // derivation: if a claim-window resize ever pushes the floor past the
  // closed test epoch, fail loudly instead of underflowing size_t.
  ASSERT_GE(ClaimSourceFixture::kSettlementEpoch, floor);
  const size_t closed_i = ClaimSourceFixture::kSettlementEpoch - floor;
  ASSERT_LT(closed_i, res.epochs.size());
  EXPECT_TRUE(res.epochs[closed_i].has_budget_row);
  EXPECT_EQ(res.epochs[closed_i].bonds.size(), 2u);
  EXPECT_NE(res.epochs[closed_i].claimant_bond_idx, std::numeric_limits<uint64_t>::max());
  for (size_t i = 0; i < res.epochs.size(); ++i)
  {
    if (i == closed_i) continue;
    EXPECT_FALSE(res.epochs[i].has_budget_row);
    EXPECT_TRUE(res.epochs[i].bonds.empty());
  }
}

// Watch item 2 (§7.2): the window shape is identical for a bonded,
// credited claimant and a p_id with no bond record at all — nothing in
// the response layout is claimable-set-derived.
/// A complete-tree record's cooldown anchor must come from the all-shards scan,
/// not from folding its (necessarily empty) held-shard list.
///
/// This is the one divergence the twin comments in `archival_claim_source.cpp`
/// and `blockchain.cpp` warn about, and until this test existed the suite could
/// not see it: deleting the `is_complete_tree()` branch from the marshaler left
/// every other test in this file green. A complete-tree record stores NO shard
/// list, so the compact accessor returns empty and the fold reports "never
/// served" — which is the PERMISSIVE branch of both `release_cooldown_elapsed`
/// and `slashes_settled_through`, for a record that has served and is still
/// cooling down. The wallet would then report an irreversible exit as ready.
TEST(archival_claim_source_rpc, complete_tree_anchor_comes_from_the_all_shards_scan)
{
  ClaimSourceFixture fx;

  // Flip p1 to a complete-tree record, keeping the serve credit the KAT seeded
  // for it. Complete-tree records carry no held-shard list by construction,
  // which is exactly what makes the compact accessor the wrong source here.
  shekyl::db::ArchivalBondValue bond{};
  ASSERT_TRUE(fx.bdb().get_archival_bond_value(fx.p1, bond));
  bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsCompleteTree;
  // Both lists, together: the encoder requires them equal in length, and a
  // complete-tree record carries neither.
  bond.held_shard_ids.clear();
  bond.shard_add_epochs.clear();
  fx.bdb().put_archival_bond_value(fx.p1, bond);

  // Precondition, asserted rather than assumed: the two accessors must actually
  // disagree on this record, or the test would pass against the wrong branch.
  const std::vector<uint64_t> via_all =
    fx.bdb().archival_bond_all_last_served_epochs(fx.p1);
  const std::vector<uint64_t> via_held =
    fx.bdb().archival_bond_last_served_epochs(fx.p1, bond.held_shard_ids);
  ASSERT_FALSE(via_all.empty()) << "the KAT's serve credit must be visible to the scan";
  ASSERT_TRUE(via_held.empty()) << "a complete-tree record holds no shard list";

  cmd::response res{};
  rpc::fill_archival_emission_claim_source(fx.db, fx.p1, res);

  uint8_t want_present = 0;
  uint64_t want_epoch = 0;
  ASSERT_EQ(shekyl_archival_whole_record_last_served(
              via_all.data(), via_all.size(), &want_present, &want_epoch),
    SHEKYL_ARCHIVAL_BOND_POST_OK);
  ASSERT_EQ(want_present, 1);

  EXPECT_TRUE(res.has_last_served_epoch)
    << "a served complete-tree record must not report as never-served";
  EXPECT_EQ(res.last_served_epoch, want_epoch);
}

TEST(archival_claim_source_rpc, window_is_unconditional_and_cause_blind)
{
  ClaimSourceFixture fx;

  cmd::response with_bond{};
  rpc::fill_archival_emission_claim_source(fx.db, fx.p1, with_bond);
  cmd::response no_bond{};
  rpc::fill_archival_emission_claim_source(fx.db, fx.p_no_bond, no_bond);

  EXPECT_FALSE(no_bond.has_bond_record);
  EXPECT_TRUE(no_bond.held_shard_ids.empty());
  EXPECT_TRUE(no_bond.claimed_settlement_epochs.empty());
  // No record ⇒ no exit operands, and critically the FLAGS stay false. A
  // false flag with a zero value is "absent"; a true flag with a zero value
  // would assert a serve at epoch 0 — the earliest possible anchor, which
  // reads as maximally cooled-down.
  EXPECT_EQ(no_bond.bonded_total_atomic, 0u);
  EXPECT_FALSE(no_bond.has_last_served_epoch);
  EXPECT_EQ(no_bond.last_served_epoch, 0u);
  EXPECT_FALSE(no_bond.has_last_settled_slash_epoch);
  EXPECT_EQ(no_bond.last_settled_slash_epoch, 0u);

  // Same tip, same settled epoch, same window: entry count and epoch
  // sequence are byte-identical across claimant states.
  EXPECT_EQ(no_bond.chain_height, with_bond.chain_height);
  EXPECT_EQ(no_bond.current_settled_epoch, with_bond.current_settled_epoch);
  ASSERT_EQ(no_bond.epochs.size(), with_bond.epochs.size());
  for (size_t i = 0; i < no_bond.epochs.size(); ++i)
  {
    EXPECT_EQ(no_bond.epochs[i].settlement_epoch, with_bond.epochs[i].settlement_epoch);
    EXPECT_EQ(no_bond.epochs[i].has_budget_row, with_bond.epochs[i].has_budget_row);
    // The bond-less claimant's per-epoch rows are the same gather rows —
    // only claimant_bond_idx differs (no serve-credit row → sentinel).
    EXPECT_EQ(no_bond.epochs[i].bonds.size(), with_bond.epochs[i].bonds.size());
    EXPECT_EQ(no_bond.epochs[i].claimant_bond_idx, std::numeric_limits<uint64_t>::max());
  }
}

// Wire contract: epee KV JSON round-trip, the u64::MAX sentinel on the
// wire, and epee's omit-empty-container behavior (the Rust decode's
// absent-equals-empty rule pins against this).
//
// COVERS: TRANSPORT FIDELITY — that what the marshaler produced arrives
// unchanged, fields and presence flags alike. The flags matter here
// specifically: they are the only thing separating "the daemon says nothing has
// served" from "the field did not arrive", so a transport that dropped one
// would merge a permissive fact with a fail-closed one.
// DOES NOT COVER: whether the value was right to begin with. This test compares
// the decoded response to the SAME response it encoded, so a wrong value —
// including a storage sentinel shipped raw instead of resolved — round-trips
// perfectly and passes. That is correct for a transport test and a blind spot
// for a semantics one; `fill_matches_single_gather_field_for_field` is the
// other half. Observed, not assumed: biting the sentinel resolution failed that
// test and left this one green.
TEST(archival_claim_source_rpc, wire_roundtrip_sentinel_and_omit_empty)
{
  ClaimSourceFixture fx;

  cmd::response res{};
  rpc::fill_archival_emission_claim_source(fx.db, fx.p1, res);
  res.status = "OK";

  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(res, json));

  // The no-credit sentinel rides the wire as the u64 max literal.
  EXPECT_NE(json.find("18446744073709551615"), std::string::npos) << json;

  // epee omits empty containers: only the closed epoch carries rows, so
  // "bonds" (and "shards", "credit_pairs") each appear exactly once even
  // though the window has five epochs. This is the serializer behavior the
  // Rust decode's absent-as-empty rule mirrors.
  const auto count = [&json](const char* needle) {
    size_t n = 0;
    for (size_t pos = json.find(needle); pos != std::string::npos;
         pos = json.find(needle, pos + 1))
      ++n;
    return n;
  };
  EXPECT_EQ(count("\"bonds\""), 1u) << json;
  EXPECT_EQ(count("\"shards\""), 1u) << json;
  EXPECT_EQ(count("\"credit_pairs\""), 1u) << json;

  // Round-trip: the deserialized response matches the original field for
  // field on the populated epoch and the window scalars.
  cmd::response back{};
  ASSERT_TRUE(epee::serialization::load_t_from_json(back, json));
  EXPECT_EQ(back.chain_height, res.chain_height);
  EXPECT_EQ(back.current_settled_epoch, res.current_settled_epoch);
  EXPECT_EQ(back.has_bond_record, res.has_bond_record);
  EXPECT_EQ(back.join_settlement_epoch, res.join_settlement_epoch);
  EXPECT_EQ(back.holdings_kind, res.holdings_kind);
  EXPECT_EQ(back.held_shard_ids, res.held_shard_ids);
  EXPECT_EQ(back.claimed_settlement_epochs, res.claimed_settlement_epochs);
  // The exit operands, flags included. The flags are the whole reason the
  // wallet can tell "the daemon says nothing has served" from "the field did
  // not arrive" — the first is permissive at consensus, the second must be
  // fail-closed — so a transport that dropped them would silently merge the
  // two. Pinned on the wire, not just in the struct.
  EXPECT_EQ(back.bonded_total_atomic, res.bonded_total_atomic);
  EXPECT_EQ(back.has_last_served_epoch, res.has_last_served_epoch);
  EXPECT_EQ(back.last_served_epoch, res.last_served_epoch);
  EXPECT_EQ(back.has_last_settled_slash_epoch, res.has_last_settled_slash_epoch);
  EXPECT_EQ(back.last_settled_slash_epoch, res.last_settled_slash_epoch);
  ASSERT_EQ(back.epochs.size(), res.epochs.size());
  const uint64_t rt_floor = shekyl_archival_claim_window_floor(res.current_settled_epoch);
  ASSERT_GE(ClaimSourceFixture::kSettlementEpoch, rt_floor);
  const size_t ci = ClaimSourceFixture::kSettlementEpoch - rt_floor;
  ASSERT_LT(ci, res.epochs.size());
  EXPECT_EQ(back.epochs[ci].sigma_work_milli, res.epochs[ci].sigma_work_milli);
  EXPECT_EQ(back.epochs[ci].budget_atomic, res.epochs[ci].budget_atomic);
  EXPECT_EQ(back.epochs[ci].bonds.size(), res.epochs[ci].bonds.size());
  EXPECT_EQ(back.epochs[ci].bonds[0].bad_intervals_flat,
    res.epochs[ci].bonds[0].bad_intervals_flat);
  EXPECT_EQ(back.epochs[ci].claimant_bond_idx, res.epochs[ci].claimant_bond_idx);
}

// Watch item 2's request half (§7.2): the request carries `p_id` and
// nothing else — no field exists that could encode an epoch selection or
// the claimable subset. Pinned mechanically at the serialized member count
// so adding a request field trips this test, not just review.
TEST(archival_claim_source_rpc, request_carries_p_id_only)
{
  cmd::request req{};
  req.p_id = "aa";

  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(req, json));

  rapidjson::Document doc;
  doc.Parse(json.c_str());
  ASSERT_TRUE(doc.IsObject()) << json;
  ASSERT_EQ(doc.MemberCount(), 1u)
      << "the claim-source request must carry p_id ONLY "
         "(EMISSION_CLAIM_BUILDER.md §7.2 transport cause-blindness); got:\n"
      << json;
  EXPECT_TRUE(doc.HasMember("p_id")) << json;
}

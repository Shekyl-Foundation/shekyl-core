// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The `ArchivalBondValue` v7 cross-check corpus (DRS-E1 S-ARCH,
// `DRS_E1_SARCH.md` §7 commit 1; ruled on PR #840).
//
// The redb store's `BondRecord` (`shekyl-chain-store::codec::archival`) is
// *re-specified* from this C++ record — same semantics, its own encoding
// (`SAR-Q3`). A round trip of the new codec against itself proves it
// self-consistent, not that it is the same record; the only evidence of
// what LMDB actually holds is this decoder, and E4 deletes it. So this test
// pins, while the decoder lives:
//
//   1. five representative records, as C++ struct literals — the corpus's
//      source of truth for FIELDS;
//   2. their v7 `encode()` bytes, checked into `docs/test_vectors/
//      ARCHIVAL_BOND_RECORD_V7.json` beside the fields the C++ decoder reads
//      back from them;
//
// and asserts, every run, that the encoder still produces those bytes and
// the decoder still reads those fields. The Rust side
// (`shekyl-chain-store/src/codec/archival_tests.rs`) loads the same JSON,
// builds a `BondRecord` from each field set, and asserts nothing is lost —
// the semantic cross-check the round trip cannot give.
//
// Regenerate (only when the corpus itself changes, never to make a red pass):
//   SHEKYL_WRITE_V7_CORPUS=1 ./unit_tests --gtest_filter='archival_bond_record_v7_corpus*'

#include "gtest/gtest.h"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "blockchain_db/shekyl_types.h"
#include "string_tools.h"

#ifndef ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH
#define ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH "docs/test_vectors/ARCHIVAL_BOND_RECORD_V7.json"
#endif

namespace {

using shekyl::db::ArchivalBondValue;

struct Case {
  const char* name;
  ArchivalBondValue record;
};

std::vector<uint8_t> bytes_of(uint8_t fill, size_t n)
{
  return std::vector<uint8_t>(n, fill);
}

// The corpus. Each case exercises a shape the Rust re-specification must
// carry: the two holdings kinds, the interval log's two entry kinds
// (open bad standing; the zero-length clean-close marker), a full
// claimed-epoch set, both states of the set-once first-paying height, and
// the genesis-frozen caps at their bound.
std::vector<Case> corpus()
{
  std::vector<Case> out;

  // 1. A complete-tree foundation record at join: no shards listed, clean
  //    standing, nothing claimed, never paid (the 0 sentinel).
  {
    ArchivalBondValue r;
    r.hybrid_pubkey = bytes_of(0x11, 64);
    r.bond_spend_pk = bytes_of(0x22, 32);
    r.endpoint.fill(0x33);
    r.join_settlement_epoch = 3;
    r.bonded_total_atomic = 5'000'000'000ULL;
    r.holdings_kind = ArchivalBondValue::kHoldingsCompleteTree;
    r.first_paying_emission_height = 0;
    out.push_back({"complete_tree_at_join", r});
  }

  // 2. Compact holdings, two shards with distinct add-epochs in insertion
  //    (not sorted) order; an open bad interval; one claimed epoch; paid.
  {
    ArchivalBondValue r;
    r.hybrid_pubkey = bytes_of(0x44, 64);
    r.bond_spend_pk = bytes_of(0x55, 32);
    r.endpoint.fill(0x00); // zero is a value the vin carried, not an absence
    r.join_settlement_epoch = 7;
    r.bonded_total_atomic = 2'000'000ULL;
    r.holdings_kind = ArchivalBondValue::kHoldingsShardSetCompact;
    r.held_shard_ids = {42, 7};
    r.shard_add_epochs = {7, 9};
    r.bad_intervals.push_back({11, std::numeric_limits<uint64_t>::max()});
    r.claimed_settlement_epochs = {8};
    r.first_paying_emission_height = 90'000;
    out.push_back({"compact_open_bad_standing", r});
  }

  // 3. Compact holdings, one shard; a closed bad interval followed by the
  //    Release clean interval-close marker (start == end) — the entry kind
  //    the header warns must never be asserted non-empty.
  {
    ArchivalBondValue r;
    r.hybrid_pubkey = bytes_of(0x66, 64);
    r.bond_spend_pk = bytes_of(0x77, 32);
    r.endpoint.fill(0x88);
    r.join_settlement_epoch = 2;
    r.bonded_total_atomic = 1'000'000ULL;
    r.holdings_kind = ArchivalBondValue::kHoldingsShardSetCompact;
    r.held_shard_ids = {1000};
    r.shard_add_epochs = {2};
    r.bad_intervals.push_back({4, 6});
    r.bad_intervals.push_back({12, 12});
    r.first_paying_emission_height = 0;
    out.push_back({"compact_reinstated_then_clean_close", r});
  }

  // 4. A claimed-epoch set at the widest span the window admits — `W + 1`
  //    consecutive epochs spanning exactly `W` (the record refuses a wider
  //    span; the entry cap `W + 6` is reachable only with gaps) — on a
  //    complete tree that has been paid.
  {
    ArchivalBondValue r;
    r.hybrid_pubkey = bytes_of(0x99, 64);
    r.bond_spend_pk = bytes_of(0xaa, 32);
    r.endpoint.fill(0xbb);
    r.join_settlement_epoch = 1;
    r.bonded_total_atomic = 9'999'999'999ULL;
    r.holdings_kind = ArchivalBondValue::kHoldingsCompleteTree;
    for (uint64_t e = 2; e <= 2 + SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W; ++e)
      r.claimed_settlement_epochs.push_back(e);
    r.first_paying_emission_height = 30'000;
    out.push_back({"complete_tree_claimed_at_full_span", r});
  }

  // 5. The bad-interval log at its genesis-frozen cap (256 closed
  //    intervals), compact holdings at the shard cap (4096 shards).
  {
    ArchivalBondValue r;
    r.hybrid_pubkey = bytes_of(0xcc, 64);
    r.bond_spend_pk = bytes_of(0xdd, 32);
    r.endpoint.fill(0xee);
    r.join_settlement_epoch = 5;
    r.bonded_total_atomic = 123'456'789ULL;
    r.holdings_kind = ArchivalBondValue::kHoldingsShardSetCompact;
    for (uint64_t s = 0; s < ArchivalBondValue::kMaxHoldings; ++s)
    {
      r.held_shard_ids.push_back(s);
      r.shard_add_epochs.push_back(5 + (s % 3));
    }
    for (uint64_t i = 0; i < ArchivalBondValue::kMaxBadIntervals; ++i)
      r.bad_intervals.push_back({6 + 2 * i, 7 + 2 * i});
    r.first_paying_emission_height = 0;
    out.push_back({"caps_at_their_bound", r});
  }

  return out;
}

std::string hex(const std::vector<uint8_t>& b)
{
  return epee::string_tools::buff_to_hex_nodelimer(std::string(b.begin(), b.end()));
}

std::string hex(const std::array<uint8_t, 32>& b)
{
  return epee::string_tools::buff_to_hex_nodelimer(std::string(b.begin(), b.end()));
}

std::vector<uint8_t> unhex(const std::string& h)
{
  std::string bin;
  if (!epee::string_tools::parse_hexstr_to_binbuff(h, bin))
    throw std::runtime_error("corpus: invalid hex");
  return std::vector<uint8_t>(bin.begin(), bin.end());
}

template <typename T>
std::string u64_list(const std::vector<T>& v)
{
  std::ostringstream s;
  s << "[";
  for (size_t i = 0; i < v.size(); ++i)
    s << (i ? ", " : "") << static_cast<uint64_t>(v[i]);
  s << "]";
  return s.str();
}

// The fixture, written by hand-formatting: five records, and every field the
// C++ decoder reads, as the decoder read it. `u64::MAX` is emitted as a
// number (rapidjson and serde_json both read it exactly).
std::string render_corpus()
{
  std::ostringstream j;
  j << "{\n"
       "  \"_comment\": \"ArchivalBondValue v7 cross-check corpus (DRS-E1 S-ARCH, DRS_E1_SARCH.md §7 commit 1). "
       "`v7_hex` is the C++ encoder's output for the record; `fields` is what the C++ decoder reads back from those bytes. "
       "Generated by tests/unit_tests/archival_bond_record_v7_corpus.cpp (SHEKYL_WRITE_V7_CORPUS=1); "
       "asserted there every run while the C++ decoder exists, and by shekyl-chain-store's archival_tests.rs against the Rust BondRecord. "
       "Do not edit by hand.\",\n"
       "  \"record_version\": " << static_cast<unsigned>(ArchivalBondValue::kVersion) << ",\n"
       "  \"caps\": { \"max_holdings\": " << ArchivalBondValue::kMaxHoldings
    << ", \"max_bad_intervals\": " << ArchivalBondValue::kMaxBadIntervals
    << ", \"max_claimed_epochs\": " << ArchivalBondValue::kMaxClaimedEpochs
    << ", \"max_pubkey_len\": " << ArchivalBondValue::kMaxPubkeyLen
    << ", \"max_claim_age_w\": " << SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W << " },\n"
       "  \"cases\": [\n";
  const auto cases = corpus();
  for (size_t i = 0; i < cases.size(); ++i)
  {
    const auto& c = cases[i];
    const auto& r = c.record;
    std::vector<std::pair<uint64_t, uint64_t>> held;
    for (size_t k = 0; k < r.held_shard_ids.size(); ++k)
      held.emplace_back(r.held_shard_ids[k], r.shard_add_epochs[k]);
    j << "    {\n"
      << "      \"name\": \"" << c.name << "\",\n"
      << "      \"v7_hex\": \"" << hex(r.encode()) << "\",\n"
      << "      \"fields\": {\n"
      << "        \"hybrid_pubkey_hex\": \"" << hex(r.hybrid_pubkey) << "\",\n"
      << "        \"bond_spend_pk_hex\": \"" << hex(r.bond_spend_pk) << "\",\n"
      << "        \"endpoint_hex\": \"" << hex(r.endpoint) << "\",\n"
      << "        \"join_settlement_epoch\": " << r.join_settlement_epoch << ",\n"
      << "        \"bonded_total_atomic\": " << r.bonded_total_atomic << ",\n"
      << "        \"holdings_kind\": " << static_cast<unsigned>(r.holdings_kind) << ",\n"
      << "        \"held\": [";
    for (size_t k = 0; k < held.size(); ++k)
      j << (k ? ", " : "") << "[" << held[k].first << ", " << held[k].second << "]";
    j << "],\n"
      << "        \"bad_intervals\": [";
    for (size_t k = 0; k < r.bad_intervals.size(); ++k)
      j << (k ? ", " : "") << "[" << r.bad_intervals[k].start_epoch << ", "
        << r.bad_intervals[k].end_exclusive << "]";
    j << "],\n"
      << "        \"claimed_settlement_epochs\": " << u64_list(r.claimed_settlement_epochs) << ",\n"
      << "        \"first_paying_emission_height\": " << r.first_paying_emission_height
      << "\n      }\n"
      << "    }" << (i + 1 < cases.size() ? "," : "") << "\n";
  }
  j << "  ]\n}\n";
  return j.str();
}

rapidjson::Document load_corpus()
{
  std::ifstream ifs(ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing corpus at ") + ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH
      + " — SHEKYL_WRITE_V7_CORPUS=1 writes it");
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError())
    throw std::runtime_error("corpus is not valid JSON");
  return doc;
}

} // namespace

TEST(archival_bond_record_v7_corpus, the_encoder_and_decoder_still_agree_with_the_checked_in_corpus)
{
  if (std::getenv("SHEKYL_WRITE_V7_CORPUS"))
  {
    std::ofstream out(ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH, std::ios::trunc);
    ASSERT_TRUE(out.good()) << "cannot write " << ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH;
    out << render_corpus();
    // A regeneration run must not read as green (rule 47): fail loudly so
    // the operator re-runs without the variable to assert.
    FAIL() << "SHEKYL_WRITE_V7_CORPUS set: corpus written to "
           << ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH << "; re-run without it to assert";
  }

  const rapidjson::Document doc = load_corpus();
  ASSERT_TRUE(doc.IsObject());
  ASSERT_EQ(doc["record_version"].GetUint(), ArchivalBondValue::kVersion)
    << "the corpus was generated for a different ArchivalBondValue version";
  const auto& cases_json = doc["cases"];
  ASSERT_TRUE(cases_json.IsArray());
  const auto cases = corpus();
  ASSERT_EQ(cases_json.Size(), cases.size()) << "the corpus and this test's record set differ in size";

  for (size_t i = 0; i < cases.size(); ++i)
  {
    const auto& c = cases[i];
    const auto& cj = cases_json[static_cast<rapidjson::SizeType>(i)];
    SCOPED_TRACE(c.name);
    ASSERT_STREQ(cj["name"].GetString(), c.name);

    // The encoder still produces the checked-in bytes.
    const std::vector<uint8_t> encoded = c.record.encode();
    EXPECT_EQ(hex(encoded), std::string(cj["v7_hex"].GetString()))
      << "ArchivalBondValue::encode() changed; the corpus no longer describes what LMDB holds";

    // The decoder still reads the checked-in fields from the checked-in bytes.
    const std::vector<uint8_t> stored = unhex(cj["v7_hex"].GetString());
    ArchivalBondValue decoded{};
    ASSERT_TRUE(ArchivalBondValue::decode(stored.data(), stored.size(), decoded));
    const auto& f = cj["fields"];
    EXPECT_EQ(hex(decoded.hybrid_pubkey), std::string(f["hybrid_pubkey_hex"].GetString()));
    EXPECT_EQ(hex(decoded.bond_spend_pk), std::string(f["bond_spend_pk_hex"].GetString()));
    EXPECT_EQ(hex(decoded.endpoint), std::string(f["endpoint_hex"].GetString()));
    EXPECT_EQ(decoded.join_settlement_epoch, f["join_settlement_epoch"].GetUint64());
    EXPECT_EQ(decoded.bonded_total_atomic, f["bonded_total_atomic"].GetUint64());
    EXPECT_EQ(static_cast<unsigned>(decoded.holdings_kind), f["holdings_kind"].GetUint());
    const auto& held = f["held"];
    ASSERT_EQ(held.Size(), decoded.held_shard_ids.size());
    ASSERT_EQ(decoded.held_shard_ids.size(), decoded.shard_add_epochs.size());
    for (rapidjson::SizeType k = 0; k < held.Size(); ++k)
    {
      EXPECT_EQ(decoded.held_shard_ids[k], held[k][0].GetUint64());
      EXPECT_EQ(decoded.shard_add_epochs[k], held[k][1].GetUint64());
    }
    const auto& bad = f["bad_intervals"];
    ASSERT_EQ(bad.Size(), decoded.bad_intervals.size());
    for (rapidjson::SizeType k = 0; k < bad.Size(); ++k)
    {
      EXPECT_EQ(decoded.bad_intervals[k].start_epoch, bad[k][0].GetUint64());
      EXPECT_EQ(decoded.bad_intervals[k].end_exclusive, bad[k][1].GetUint64());
    }
    const auto& claimed = f["claimed_settlement_epochs"];
    ASSERT_EQ(claimed.Size(), decoded.claimed_settlement_epochs.size());
    for (rapidjson::SizeType k = 0; k < claimed.Size(); ++k)
      EXPECT_EQ(decoded.claimed_settlement_epochs[k], claimed[k].GetUint64());
    EXPECT_EQ(decoded.first_paying_emission_height, f["first_paying_emission_height"].GetUint64());

    // And the decoded record is the literal (the fields above are its
    // projection; this is the whole-value check).
    EXPECT_EQ(decoded.encode(), encoded);
  }
}

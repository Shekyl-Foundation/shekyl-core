// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Shared C2-R3 boundary vectors for the ruled timestamp rule
// (docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md §4.3, ratified 2026-09-01),
// consumed from docs/test_vectors/MTP_BOUNDARY_V1.json through the FFI
// boundary (`shekyl_difficulty_check_timestamp_rule`) — the exact entry
// point the C++ validator's marshaling shim consumes, so these tests pin
// the ONE implementation (shekyl-difficulty's `check_timestamp_rule`)
// end-to-end across the C ABI. The same file drives
// rust/shekyl-difficulty/tests/mtp_boundary_vectors.rs natively; the two
// consumers together pin the rule on both sides of the boundary.
//
// Every JSON access goes through the checked helpers below rather than
// rapidjson's raw operator[]: a drifted or malformed vector file must
// surface as a readable test failure naming the missing piece, never as a
// rapidjson assert aborting the binary.

#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "gtest/gtest.h"

#include "shekyl/consensus_constants_generated.h"
#include "shekyl/shekyl_ffi.h"

namespace
{

rapidjson::Document load_vectors()
{
  std::ifstream ifs(MTP_BOUNDARY_VECTOR_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing boundary vectors at ") + MTP_BOUNDARY_VECTOR_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.IsObject())
    throw std::runtime_error("MTP_BOUNDARY_V1.json is not valid JSON");
  return doc;
}

// Uncaught std::runtime_error is reported by gtest as a failure carrying
// the message — the readable failure mode the schema checks exist for.
[[noreturn]] void schema_fail(const std::string& what)
{
  throw std::runtime_error("MTP_BOUNDARY_V1.json schema drift: " + what);
}

const rapidjson::Value& section_cases(const rapidjson::Document& doc, const char* section)
{
  if (!doc.HasMember(section) || !doc[section].IsObject())
    schema_fail(std::string("missing section '") + section + "'");
  const auto& sec = doc[section];
  if (!sec.HasMember("cases") || !sec["cases"].IsArray())
    schema_fail(std::string("section '") + section + "' has no 'cases' array");
  return sec["cases"];
}

uint64_t u64_field(const rapidjson::Value& c, const char* name)
{
  if (!c.IsObject() || !c.HasMember(name) || !c[name].IsUint64())
    schema_fail(std::string("case field '") + name + "' missing or not a u64");
  return c[name].GetUint64();
}

bool bool_field(const rapidjson::Value& c, const char* name)
{
  if (!c.IsObject() || !c.HasMember(name) || !c[name].IsBool())
    schema_fail(std::string("case field '") + name + "' missing or not a bool");
  return c[name].GetBool();
}

std::string name_field(const rapidjson::Value& c)
{
  if (!c.IsObject() || !c.HasMember("name") || !c["name"].IsString())
    schema_fail("case has no string 'name'");
  return c["name"].GetString();
}

std::vector<uint64_t> u64_array_field(const rapidjson::Value& c, const char* name)
{
  if (!c.IsObject() || !c.HasMember(name) || !c[name].IsArray())
    schema_fail(std::string("case field '") + name + "' missing or not an array");
  std::vector<uint64_t> out;
  out.reserve(c[name].Size());
  for (const auto& v : c[name].GetArray())
  {
    if (!v.IsUint64())
      schema_fail(std::string("entry of '") + name + "' is not a u64");
    out.push_back(v.GetUint64());
  }
  return out;
}

} // anonymous namespace

// Every predicate case must match the rule owner exactly — including the
// `== median` rows, which are the consensus fork line this round ruled.
// FTL is held out of play (local_clock = candidate); genesis padding is
// unused (windows are exactly 11 wide). The pinned `median` field is also
// asserted against the function's out-parameter, so a vector edit cannot
// silently decouple `median` from `verdict`.
TEST(mtp_boundary, predicate_cases_match_rule_owner)
{
  const auto doc = load_vectors();
  const auto& cases = section_cases(doc, "predicate_cases");
  ASSERT_GT(cases.Size(), 0u);

  for (const auto& c : cases.GetArray())
  {
    const std::string name = name_field(c);
    const std::vector<uint64_t> window = u64_array_field(c, "window");
    ASSERT_EQ(SHEKYL_DAA_MTP_WINDOW, window.size()) << name;
    const uint64_t candidate = u64_field(c, "candidate");
    const bool expected = bool_field(c, "verdict");

    uint64_t median = 0;
    const int32_t verdict = shekyl_difficulty_check_timestamp_rule(
        candidate, window.data(), window.size(), /*genesis_ts=*/0,
        /*local_clock=*/candidate, &median);

    EXPECT_EQ(u64_field(c, "median"), median) << name;
    EXPECT_EQ(expected ? SHEKYL_TIMESTAMP_RULE_OK : SHEKYL_TIMESTAMP_RULE_NOT_ABOVE_MEDIAN, verdict) << name;
  }
}

// Assembly cases: fewer than 11 predecessors are right-padded with the
// genesis timestamp (C2-R3-Q2) inside the rule owner itself.
TEST(mtp_boundary, assembly_cases_pad_with_genesis_timestamp)
{
  const auto doc = load_vectors();
  const auto& cases = section_cases(doc, "assembly_cases");
  ASSERT_GT(cases.Size(), 0u);

  for (const auto& c : cases.GetArray())
  {
    const std::string name = name_field(c);
    const std::vector<uint64_t> history = u64_array_field(c, "history_newest_first");
    ASSERT_LE(history.size(), SHEKYL_DAA_MTP_WINDOW) << name;
    const uint64_t genesis_ts = u64_field(c, "genesis_ts");
    const uint64_t candidate = u64_field(c, "candidate");
    const bool expected = bool_field(c, "verdict");

    uint64_t median = 0;
    const int32_t verdict = shekyl_difficulty_check_timestamp_rule(
        candidate, history.data(), history.size(), genesis_ts,
        /*local_clock=*/candidate, &median);

    EXPECT_EQ(u64_field(c, "median"), median) << name;
    EXPECT_EQ(expected ? SHEKYL_TIMESTAMP_RULE_OK : SHEKYL_TIMESTAMP_RULE_NOT_ABOVE_MEDIAN, verdict) << name;
  }
}

// FTL cases pin only the future-time axis: the JSON verdict says whether
// the candidate clears local_clock + 540, so the assertion is exactly
// "above_ftl iff the FTL half fails" — the MTP half of the combined
// verdict is not re-derived here. The u64-boundary rows additionally pin
// the arithmetic SHAPE: the deadline must be computed saturating (the
// Rust twin's `saturating_sub` form), never as `local_clock + 540`, which
// wraps near the top of the domain and rejects an in-bound candidate.
TEST(mtp_boundary, ftl_cases_pin_the_future_time_axis)
{
  const auto doc = load_vectors();
  const auto& cases = section_cases(doc, "ftl_cases");
  ASSERT_GT(cases.Size(), 0u);

  const std::vector<uint64_t> zero_window(SHEKYL_DAA_MTP_WINDOW, 0);
  for (const auto& c : cases.GetArray())
  {
    const std::string name = name_field(c);
    const uint64_t candidate = u64_field(c, "candidate");
    const uint64_t local_clock = u64_field(c, "local_clock");
    const bool ftl_ok = bool_field(c, "verdict");

    uint64_t median = 1;
    const int32_t verdict = shekyl_difficulty_check_timestamp_rule(
        candidate, zero_window.data(), zero_window.size(), /*genesis_ts=*/0,
        local_clock, &median);

    EXPECT_EQ(!ftl_ok, verdict == SHEKYL_TIMESTAMP_RULE_ABOVE_FTL) << name;
    // The median out-parameter is set even on the FTL-fail arm — the
    // miner-template caller reads it unconditionally (C2-R3 §7.3).
    EXPECT_EQ(0u, median) << name;
  }
}

// The template-edge premise, pinned on the pure rule owner: when the
// window median sits exactly at the local FTL deadline, NO timestamp
// satisfies both bounds — the local clock fails MTP and median + 1 fails
// FTL. This empty constraint set is why create_block_template revalidates
// its median + 1 bump and refuses template creation at the edge instead
// of minting a self-rejecting template (blockchain.cpp, C2-R3-Q1 sub-b).
// One tick later the set is non-empty again — also asserted, because the
// refusal arm's legitimacy rests on the state being self-healing. (The
// arm itself runs against time(NULL); its deterministic harness needs the
// R9 clock-seam design and is recorded in the round doc, not skipped
// silently.)
TEST(mtp_boundary, template_edge_no_timestamp_satisfies_both_bounds)
{
  const uint64_t clock = 1000000;
  const uint64_t edge_median = clock + SHEKYL_DAA_FTL_SECONDS;
  const std::vector<uint64_t> edge_window(SHEKYL_DAA_MTP_WINDOW, edge_median);

  uint64_t median = 0;
  // The local clock itself is not above the median.
  EXPECT_EQ(SHEKYL_TIMESTAMP_RULE_NOT_ABOVE_MEDIAN,
            shekyl_difficulty_check_timestamp_rule(clock, edge_window.data(), edge_window.size(), 0, clock, &median));
  EXPECT_EQ(edge_median, median);
  // The smallest MTP-satisfying value busts FTL.
  EXPECT_EQ(SHEKYL_TIMESTAMP_RULE_ABOVE_FTL,
            shekyl_difficulty_check_timestamp_rule(edge_median + 1, edge_window.data(), edge_window.size(), 0, clock, &median));
  // Self-healing: one clock tick later the same bump is valid.
  EXPECT_EQ(SHEKYL_TIMESTAMP_RULE_OK,
            shekyl_difficulty_check_timestamp_rule(edge_median + 1, edge_window.data(), edge_window.size(), 0, clock + 1, &median));
}

// A window wider than 11 is a caller bug (the newest-11 selection is the
// caller's job, C2-R3-Q1 sub-a) and is refused loudly, never silently
// medianed. This is the assertion that goes red if the alt path's
// truncation is ever removed while the shared history it builds exceeds
// the window.
TEST(mtp_boundary, wider_window_is_refused)
{
  const std::vector<uint64_t> too_wide(SHEKYL_DAA_MTP_WINDOW + 1, 5);
  uint64_t median = 123;
  const int32_t verdict = shekyl_difficulty_check_timestamp_rule(
      /*candidate=*/999, too_wide.data(), too_wide.size(), /*genesis_ts=*/0,
      /*local_clock=*/999, &median);
  EXPECT_EQ(SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE, verdict);
  // The refusal arm pins median_out to 0 like every other arm ("set on
  // every arm" is the header contract) — assert it so no caller starts
  // leaning on a stale or uninitialized value here.
  EXPECT_EQ(0u, median);
}

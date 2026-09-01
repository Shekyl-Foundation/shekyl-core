// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Shared C2-R3 boundary vectors for the ruled timestamp rule
// (docs/design/CONSENSUS_C2_R3_TIMESTAMPS.md §4.3, ratified 2026-09-01),
// consumed from docs/test_vectors/MTP_BOUNDARY_V1.json against the live
// validator's rule owner `cryptonote::shekyl_check_timestamp_rule`. The
// same file drives rust/shekyl-difficulty/tests/mtp_boundary_vectors.rs
// against the rewrite's predicates — two implementations of one consensus
// rule that do not share vectors drift silently.

#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "gtest/gtest.h"

#include "cryptonote_core/blockchain.h"

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
  if (doc.HasParseError())
    throw std::runtime_error("MTP_BOUNDARY_V1.json is not valid JSON");
  return doc;
}

std::vector<uint64_t> u64_array(const rapidjson::Value& arr)
{
  std::vector<uint64_t> out;
  out.reserve(arr.Size());
  for (const auto& v : arr.GetArray())
    out.push_back(v.GetUint64());
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
  const auto& cases = doc["predicate_cases"]["cases"];
  ASSERT_GT(cases.Size(), 0u);

  for (const auto& c : cases.GetArray())
  {
    const std::string name = c["name"].GetString();
    const std::vector<uint64_t> window = u64_array(c["window"]);
    ASSERT_EQ(SHEKYL_DAA_MTP_WINDOW, window.size()) << name;
    const uint64_t candidate = c["candidate"].GetUint64();
    const bool expected = c["verdict"].GetBool();

    uint64_t median = 0;
    const auto verdict = cryptonote::shekyl_check_timestamp_rule(
        candidate, window, /*genesis_ts=*/0, /*local_clock=*/candidate, median);

    EXPECT_EQ(c["median"].GetUint64(), median) << name;
    if (expected)
      EXPECT_EQ(cryptonote::timestamp_rule_verdict::ok, verdict) << name;
    else
      EXPECT_EQ(cryptonote::timestamp_rule_verdict::not_above_median, verdict) << name;
  }
}

// Assembly cases: fewer than 11 predecessors are right-padded with the
// genesis timestamp (C2-R3-Q2) inside the rule owner itself.
TEST(mtp_boundary, assembly_cases_pad_with_genesis_timestamp)
{
  const auto doc = load_vectors();
  const auto& cases = doc["assembly_cases"]["cases"];
  ASSERT_GT(cases.Size(), 0u);

  for (const auto& c : cases.GetArray())
  {
    const std::string name = c["name"].GetString();
    const std::vector<uint64_t> history = u64_array(c["history_newest_first"]);
    ASSERT_LE(history.size(), SHEKYL_DAA_MTP_WINDOW) << name;
    const uint64_t genesis_ts = c["genesis_ts"].GetUint64();
    const uint64_t candidate = c["candidate"].GetUint64();
    const bool expected = c["verdict"].GetBool();

    uint64_t median = 0;
    const auto verdict = cryptonote::shekyl_check_timestamp_rule(
        candidate, history, genesis_ts, /*local_clock=*/candidate, median);

    EXPECT_EQ(c["median"].GetUint64(), median) << name;
    if (expected)
      EXPECT_EQ(cryptonote::timestamp_rule_verdict::ok, verdict) << name;
    else
      EXPECT_EQ(cryptonote::timestamp_rule_verdict::not_above_median, verdict) << name;
  }
}

// FTL cases pin only the future-time axis: the JSON verdict says whether
// the candidate clears local_clock + 540, so the assertion is exactly
// "above_ftl iff the FTL half fails" — the MTP half of the combined
// verdict is not re-derived here.
TEST(mtp_boundary, ftl_cases_pin_the_future_time_axis)
{
  const auto doc = load_vectors();
  const auto& cases = doc["ftl_cases"]["cases"];
  ASSERT_GT(cases.Size(), 0u);

  const std::vector<uint64_t> zero_window(SHEKYL_DAA_MTP_WINDOW, 0);
  for (const auto& c : cases.GetArray())
  {
    const std::string name = c["name"].GetString();
    const uint64_t candidate = c["candidate"].GetUint64();
    const uint64_t local_clock = c["local_clock"].GetUint64();
    const bool ftl_ok = c["verdict"].GetBool();

    uint64_t median = 1;
    const auto verdict = cryptonote::shekyl_check_timestamp_rule(
        candidate, zero_window, /*genesis_ts=*/0, local_clock, median);

    EXPECT_EQ(!ftl_ok, verdict == cryptonote::timestamp_rule_verdict::above_ftl) << name;
    // The median out-parameter is set even on the FTL-fail arm — the
    // miner-template caller reads it unconditionally (C2-R3 §7.3).
    EXPECT_EQ(0u, median) << name;
  }
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
  const auto verdict = cryptonote::shekyl_check_timestamp_rule(
      /*candidate=*/999, too_wide, /*genesis_ts=*/0, /*local_clock=*/999, median);
  EXPECT_EQ(cryptonote::timestamp_rule_verdict::window_too_wide, verdict);
}

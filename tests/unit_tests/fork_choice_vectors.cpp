// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// Shared C2-R1b vectors for the ruled fork-choice comparison and the
// CEN-D5 alt-window selection (docs/design/CONSENSUS_C2_R1_REORG.md §4b,
// ratified 2026-09-03), pinned END-TO-END through the FFI boundary the
// block-connect machinery consumes (shekyl_difficulty_fork_choice /
// shekyl_difficulty_alt_window_plan). The Rust suite
// (rust/shekyl-difficulty/tests/fork_choice_vectors.rs) pins the same
// sections natively; two consumers, one implementation, one vector file.

#include <fstream>
#include <stdexcept>
#include <string>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "gtest/gtest.h"

#include "shekyl/shekyl_ffi.h"

namespace
{

rapidjson::Document load_vectors()
{
  std::ifstream ifs(FORK_CHOICE_VECTOR_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing fork-choice vectors at ") + FORK_CHOICE_VECTOR_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.IsObject())
    throw std::runtime_error("FORK_CHOICE_V1.json is not valid JSON");
  return doc;
}

[[noreturn]] void schema_fail(const std::string& what)
{
  throw std::runtime_error("FORK_CHOICE_V1.json schema drift: " + what);
}

const rapidjson::Value& section_cases(const rapidjson::Document& doc, const char* section)
{
  if (!doc.HasMember(section) || !doc[section].IsObject())
    schema_fail(std::string("missing section '") + section + "'");
  const auto& sec = doc[section];
  if (!sec.HasMember("cases") || !sec["cases"].IsArray())
    schema_fail(std::string("section '") + section + "' has no 'cases' array");
  if (sec["cases"].Empty())
    schema_fail(std::string("section '") + section + "' lost its cases");
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
    schema_fail("case has no 'name'");
  return c["name"].GetString();
}

} // namespace

TEST(fork_choice_vectors, fork_choice_through_the_ffi)
{
  const auto doc = load_vectors();
  for (const auto& c : section_cases(doc, "fork_choice_cases").GetArray())
  {
    const std::string name = name_field(c);
    shekyl_u128 current{}, alternative{};
    current.lo = u64_field(c, "current_lo");
    current.hi = u64_field(c, "current_hi");
    alternative.lo = u64_field(c, "alternative_lo");
    alternative.hi = u64_field(c, "alternative_hi");
    int32_t verdict = -42;
    ASSERT_EQ(SHEKYL_DIFFICULTY_OK,
        shekyl_difficulty_fork_choice(current, alternative,
            bool_field(c, "checkpoint_match") ? 1 : 0, &verdict))
        << "case " << name;
    EXPECT_EQ(static_cast<int32_t>(u64_field(c, "verdict")), verdict)
        << "case " << name;
  }
}

TEST(fork_choice_vectors, alt_window_plan_through_the_ffi)
{
  const auto doc = load_vectors();
  for (const auto& c : section_cases(doc, "alt_window_cases").GetArray())
  {
    const std::string name = name_field(c);
    uint64_t main_start = ~0ull, main_stop = ~0ull, alt_take = ~0ull;
    const int32_t rc = shekyl_difficulty_alt_window_plan(
        u64_field(c, "bei_height"), u64_field(c, "alt_len"),
        u64_field(c, "first_alt_height"), &main_start, &main_stop, &alt_take);
    if (bool_field(c, "refused"))
    {
      EXPECT_EQ(SHEKYL_DIFFICULTY_ERR_WINDOW, rc) << "case " << name;
      continue;
    }
    ASSERT_EQ(SHEKYL_DIFFICULTY_OK, rc) << "case " << name;
    EXPECT_EQ(u64_field(c, "main_start"), main_start) << "case " << name;
    EXPECT_EQ(u64_field(c, "main_stop"), main_stop) << "case " << name;
    EXPECT_EQ(u64_field(c, "alt_take"), alt_take) << "case " << name;
  }
}

TEST(fork_choice_vectors, null_out_params_are_refused)
{
  shekyl_u128 a{}, b{};
  EXPECT_EQ(SHEKYL_DIFFICULTY_ERR_NULL_PTR,
      shekyl_difficulty_fork_choice(a, b, 0, nullptr));
  uint64_t x = 0;
  EXPECT_EQ(SHEKYL_DIFFICULTY_ERR_NULL_PTR,
      shekyl_difficulty_alt_window_plan(1, 0, 0, nullptr, &x, &x));
  EXPECT_EQ(SHEKYL_DIFFICULTY_ERR_NULL_PTR,
      shekyl_difficulty_alt_window_plan(1, 0, 0, &x, nullptr, &x));
  EXPECT_EQ(SHEKYL_DIFFICULTY_ERR_NULL_PTR,
      shekyl_difficulty_alt_window_plan(1, 0, 0, &x, &x, nullptr));
}

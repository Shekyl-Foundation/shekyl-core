// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// C2-R1b-Q2a's positive check (steering's addition to rule 71's gate):
// the grep gate only catches someone ADDING a nettype branch; this suite
// proves there is nothing left to branch on, by running the same
// checkpoint-mechanism assertions against every public network's
// parameters and requiring identical outcomes. If a per-network arm ever
// returns to the mechanism, one of these EXPECT_EQ pairs splits.
//
// (The wiring half — core::update_checkpoints and the init block running
// on every network — is enforced by deletion: those functions no longer
// consult m_nettype at all, and the rule-71 gate holds the fence.)

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>
#include <fstream>

#include "checkpoints/checkpoints.h"
#include "string_tools.h"
#include "cryptonote_config.h"

using cryptonote::checkpoints;
using cryptonote::network_type;

namespace
{

const network_type kPublicNets[] = {
    network_type::MAINNET, network_type::TESTNET, network_type::STAGENET};

constexpr const char* kHashA =
    "1111111111111111111111111111111111111111111111111111111111111111";
constexpr const char* kHashB =
    "2222222222222222222222222222222222222222222222222222222222222222";

std::string write_json(const std::string& body)
{
  auto path = boost::filesystem::temp_directory_path() /
              boost::filesystem::unique_path();
  std::ofstream f(path.string());
  f << body;
  f.close();
  return path.string();
}

} // namespace

TEST(checkpoint_uniformity, defaults_identical_across_public_networks)
{
  // init_default_checkpoints is per-network DATA selection; with no
  // compiled-in checkpoints, every network's default set is identically
  // empty — and stays comparable field-by-field if data is ever added.
  for (const auto net : kPublicNets)
  {
    checkpoints cp;
    ASSERT_TRUE(cp.init_default_checkpoints(net));
    EXPECT_TRUE(cp.get_points().empty())
        << "network " << static_cast<int>(net);
    EXPECT_EQ(0u, cp.get_max_height()) << "network " << static_cast<int>(net);
  }
}

TEST(checkpoint_uniformity, json_load_and_enforcement_identical)
{
  const std::string file = write_json(
      "{\"hashlines\":[{\"height\":7,\"hash\":\"" + std::string(kHashA) +
      "\"}]}");

  crypto::hash good{}, bad{};
  ASSERT_TRUE(epee::string_tools::hex_to_pod(kHashA, good));
  ASSERT_TRUE(epee::string_tools::hex_to_pod(kHashB, bad));

  for (const auto net : kPublicNets)
  {
    checkpoints cp;
    ASSERT_TRUE(cp.init_default_checkpoints(net));
    ASSERT_TRUE(cp.load_checkpoints_from_json(file));

    // Identical load result on every network...
    ASSERT_EQ(1u, cp.get_points().size()) << "network " << static_cast<int>(net);
    EXPECT_EQ(7u, cp.get_max_height());
    // ...and identical enforcement verdicts.
    EXPECT_TRUE(cp.check_block(7, good)) << "network " << static_cast<int>(net);
    EXPECT_FALSE(cp.check_block(7, bad)) << "network " << static_cast<int>(net);
    EXPECT_TRUE(cp.is_in_checkpoint_zone(5));
    EXPECT_FALSE(cp.is_in_checkpoint_zone(8));
    EXPECT_FALSE(cp.is_alternative_block_allowed(9, 6));
    EXPECT_TRUE(cp.is_alternative_block_allowed(9, 8));
  }

  boost::filesystem::remove(file);
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

#include "cryptonote_core/archival_pass_anchor.h"

namespace
{

crypto::hash tagged(uint8_t tag, uint64_t height)
{
  crypto::hash h{};
  std::memcpy(h.data, &height, sizeof(height));
  h.data[8] = tag;
  return h;
}

bool lookup(const std::map<uint64_t, crypto::hash>& chain, uint64_t height, crypto::hash& out)
{
  const auto it = chain.find(height);
  if (it == chain.end())
    return false;
  out = it->second;
  return true;
}

} // namespace

// A window that straddles a fork: heights below alt_from come from main,
// heights at/above it come from alt. This is the SF-D8 connecting-chain rule.
TEST(archival_pass_anchor, straddling_fork_reads_main_below_and_alt_at_or_above)
{
  const uint64_t first = 100;
  const size_t len = 5; // [100, 104]
  const uint64_t alt_from = 102;

  std::map<uint64_t, crypto::hash> main;
  main[100] = tagged(0x11, 100);
  main[101] = tagged(0x11, 101);
  main[102] = tagged(0x11, 102); // must NOT be used — alt owns 102+
  main[103] = tagged(0x11, 103);
  main[104] = tagged(0x11, 104);

  std::vector<crypto::hash> alt = {
    tagged(0xA2, 102),
    tagged(0xA2, 103),
    tagged(0xA2, 104),
    tagged(0xA2, 105),
  };

  std::vector<crypto::hash> out;
  ASSERT_TRUE(cryptonote::fill_connecting_anchor_hashes(
      first, len, alt_from, alt,
      [&](uint64_t h, crypto::hash& dst) { return lookup(main, h, dst); },
      out));
  ASSERT_EQ(out.size(), len);
  EXPECT_EQ(out[0], tagged(0x11, 100));
  EXPECT_EQ(out[1], tagged(0x11, 101));
  EXPECT_EQ(out[2], tagged(0xA2, 102));
  EXPECT_EQ(out[3], tagged(0xA2, 103));
  EXPECT_EQ(out[4], tagged(0xA2, 104));
}

TEST(archival_pass_anchor, empty_alt_reads_only_main)
{
  const uint64_t first = 50;
  const size_t len = 3;
  std::map<uint64_t, crypto::hash> main;
  main[50] = tagged(0x01, 50);
  main[51] = tagged(0x01, 51);
  main[52] = tagged(0x01, 52);

  std::vector<crypto::hash> out;
  ASSERT_TRUE(cryptonote::fill_connecting_anchor_hashes(
      first, len, /*alt_from=*/0, /*alt_hashes=*/{},
      [&](uint64_t h, crypto::hash& dst) { return lookup(main, h, dst); },
      out));
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0], tagged(0x01, 50));
  EXPECT_EQ(out[1], tagged(0x01, 51));
  EXPECT_EQ(out[2], tagged(0x01, 52));
}

TEST(archival_pass_anchor, whole_window_on_alt)
{
  const uint64_t first = 200;
  const size_t len = 2;
  const uint64_t alt_from = 190;
  std::vector<crypto::hash> alt(20);
  for (uint64_t h = alt_from; h < alt_from + alt.size(); ++h)
    alt[static_cast<size_t>(h - alt_from)] = tagged(0xAA, h);

  std::vector<crypto::hash> out;
  ASSERT_TRUE(cryptonote::fill_connecting_anchor_hashes(
      first, len, alt_from, alt,
      [](uint64_t, crypto::hash&) { return false; },
      out));
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0], tagged(0xAA, 200));
  EXPECT_EQ(out[1], tagged(0xAA, 201));
}

TEST(archival_pass_anchor, missing_alt_index_fails)
{
  std::vector<crypto::hash> out;
  EXPECT_FALSE(cryptonote::fill_connecting_anchor_hashes(
      /*first=*/10, /*len=*/2, /*alt_from=*/10, /*alt_hashes=*/{tagged(0xA0, 10)},
      [](uint64_t, crypto::hash&) { return false; },
      out));
}

TEST(archival_pass_anchor, missing_main_hash_fails)
{
  std::vector<crypto::hash> out;
  EXPECT_FALSE(cryptonote::fill_connecting_anchor_hashes(
      /*first=*/10, /*len=*/1, /*alt_from=*/99, /*alt_hashes=*/{},
      [](uint64_t, crypto::hash&) { return false; },
      out));
}

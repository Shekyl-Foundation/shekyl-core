// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"

#include <cstring>
#include <sstream>
#include <string>
#include <variant>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"
#include "serialization/binary_archive.h"

using namespace cryptonote;

namespace {

// Pinned `wire_hex` from gate2_serve_credit_kat_v1.json (synthetic_minimal_path).
constexpr const char* GATE2_KAT_WIRE_HEX =
  "0211111111111111111111111111111111111111111111111111111111111111112a0712d6b708c1964ef193f2fa2e0f2e2cd21d05c161ab86e84e1be3014ff88c9d3de82b35d6996d2b4907a61bc9e1dc46cbe583677d1976764b06b849002b8bb907";

} // namespace

TEST(archival_serve_credit, gate2_kat_vin_deserializes)
{
  // RF-D1 / rule 40: the fixture's `wire_hex` IS the vin's `canonical_bytes`
  // (the Rust codec's encoding, tag included). C++ transports it as an opaque
  // blob and reads (P, shard, E) back through the FFI -- the same path
  // consensus uses -- so this test pins the cross-language agreement on those
  // three fields, and nothing else, because nothing else is C++'s to read.
  std::string wire;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(GATE2_KAT_WIRE_HEX, wire));
  ASSERT_FALSE(wire.empty());
  EXPECT_EQ(static_cast<uint8_t>(wire[0]), TXIN_ARCHIVAL_SERVE_CREDIT_WIRE_TAG);
  // Kept side after RF-D6/RF-D8: tag + 32 + two one-byte varints + 64.
  EXPECT_EQ(wire.size(), 1u + 32u + 1u + 1u + 64u);

  txin_archival_serve_credit_response resp{};
  resp.canonical_bytes.assign(wire.begin(), wire.end());

  crypto::hash p_id{};
  uint64_t shard_id = 0, settlement_epoch = 0;
  ASSERT_TRUE(get_archival_serve_credit_key(resp, p_id, shard_id, settlement_epoch));
  EXPECT_EQ(shard_id, 42u);
  EXPECT_EQ(settlement_epoch, 7u);
  crypto::hash expected_p{};
  memset(&expected_p, 0x11, sizeof(expected_p));
  EXPECT_EQ(p_id, expected_p);
}

TEST(archival_serve_credit, txin_roundtrip_matches_kat_bytes)
{
  // The C++ variant encoding WRAPS the blob (tag ‖ varint len ‖ bytes); the
  // blob itself round-trips byte-identically through it.
  std::string wire;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(GATE2_KAT_WIRE_HEX, wire));
  txin_archival_serve_credit_response resp{};
  resp.canonical_bytes.assign(wire.begin(), wire.end());
  txin_v vin = resp;

  std::ostringstream oss;
  binary_archive<true> oar(oss);
  ASSERT_TRUE(::do_serialize(oar, vin));
  const std::string encoded = oss.str();

  txin_v back;
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size()});
  ASSERT_TRUE(::do_serialize(iar, back));
  ASSERT_TRUE(std::holds_alternative<txin_archival_serve_credit_response>(back));
  const auto& parsed = std::get<txin_archival_serve_credit_response>(back);
  EXPECT_EQ(std::string(parsed.canonical_bytes.begin(), parsed.canonical_bytes.end()), wire);
}

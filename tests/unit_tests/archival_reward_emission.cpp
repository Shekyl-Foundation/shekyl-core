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

// C-1 transport shim for txin_archival_reward_emission (dense variant tag
// 0x04; opaque canonical bytes owned by emission_wire.rs). These tests pin
// the *transport* contract only — the C++ side never parses inside the blob;
// semantic acceptance/rejection is the Rust parser's (emission_wire KATs).

#include "gtest/gtest.h"

#include <cstdint>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"

using namespace cryptonote;

namespace {

txin_archival_reward_emission make_vin(size_t payload_len, uint8_t first_byte = 0x04)
{
  txin_archival_reward_emission vin;
  vin.canonical_bytes.assign(payload_len, 0x5a);
  if (!vin.canonical_bytes.empty())
    vin.canonical_bytes[0] = first_byte;
  return vin;
}

bool serialize_vin(const txin_v& vin, std::string& out)
{
  std::ostringstream oss;
  binary_archive<true> oar(oss);
  txin_v copy = vin;
  const bool ok = ::do_serialize(oar, copy);
  out = oss.str();
  return ok;
}

bool deserialize_vin(const std::string& wire, txin_v& out)
{
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(wire.data()), wire.size()});
  return ::do_serialize(iar, out);
}

} // namespace

// Wire shape: leading epee variant tag is the dense 0x04 (F-C1b pin — equal
// to the Rust wire tag), and the round-trip is byte-identical.
TEST(archival_reward_emission, txin_variant_tag_is_dense_0x04_and_roundtrips)
{
  const txin_v vin = make_vin(64);

  std::string wire;
  ASSERT_TRUE(serialize_vin(vin, wire));
  ASSERT_FALSE(wire.empty());
  EXPECT_EQ(static_cast<uint8_t>(wire[0]), 0x04u);

  txin_v decoded;
  ASSERT_TRUE(deserialize_vin(wire, decoded));
  ASSERT_TRUE(std::holds_alternative<txin_archival_reward_emission>(decoded));
  EXPECT_EQ(std::get<txin_archival_reward_emission>(decoded).canonical_bytes,
    std::get<txin_archival_reward_emission>(vin).canonical_bytes);

  std::string wire2;
  ASSERT_TRUE(serialize_vin(decoded, wire2));
  EXPECT_EQ(wire2, wire);
}

// The blob's own leading byte must echo the Rust wire tag (0x04). A blob
// whose first byte differs is rejected at the transport layer on both
// serialize and deserialize — it cannot be a canonical emission encoding.
TEST(archival_reward_emission, txin_rejects_blob_without_rust_wire_tag_echo)
{
  const txin_v good = make_vin(64);
  std::string wire;
  ASSERT_TRUE(serialize_vin(good, wire));

  // Serialize-side: constructing the vin with a wrong leading byte fails.
  std::string unused;
  EXPECT_FALSE(serialize_vin(make_vin(64, 0x02), unused));

  // Deserialize-side: mutate the first payload byte inside otherwise-valid
  // wire. Layout is [variant tag][varint len][payload...]; the payload's
  // first byte is the last-but-63rd of the buffer.
  std::string tampered = wire;
  tampered[tampered.size() - 64] = 0x02;
  txin_v decoded;
  EXPECT_FALSE(deserialize_vin(tampered, decoded));
}

// Transport bounds: below the 2-byte floor and above the
// ARCHIVAL_EMISSION_VIN_MAX_BYTES allocation cap both fail closed.
TEST(archival_reward_emission, txin_rejects_out_of_bounds_blob_sizes)
{
  std::string unused;
  EXPECT_FALSE(serialize_vin(make_vin(0), unused));
  EXPECT_FALSE(serialize_vin(make_vin(1), unused));
  EXPECT_TRUE(serialize_vin(make_vin(2), unused));
  EXPECT_TRUE(serialize_vin(make_vin(config::ARCHIVAL_EMISSION_VIN_MAX_BYTES), unused));
  EXPECT_FALSE(serialize_vin(make_vin(config::ARCHIVAL_EMISSION_VIN_MAX_BYTES + 1), unused));
}

// C-1 block-4 activation: the input-type whitelist now admits the emission
// vin under the Q3 arity-1 / Q11 mixing rules (this test is the block-2
// gate-last tripwire, intentionally flipped by the activating cut).
TEST(archival_reward_emission, input_type_whitelist_admits_emission_vin_arity_1)
{
  transaction tx;
  tx.vin.push_back(make_vin(64));
  EXPECT_TRUE(check_inputs_types_supported(tx));

  // Q11: key-imaged txin_to_key fee inputs are the only permitted
  // co-residents.
  tx.vin.push_back(txin_to_key{});
  EXPECT_TRUE(check_inputs_types_supported(tx));
}

// Q3 arity 1: a second emission vin rejects.
TEST(archival_reward_emission, input_type_whitelist_rejects_two_emission_vins)
{
  transaction tx;
  tx.vin.push_back(make_vin(64));
  tx.vin.push_back(make_vin(64));
  EXPECT_FALSE(check_inputs_types_supported(tx));
}

// Q11 mixing: emission cannot co-reside with bond-post or serve-credit vins.
TEST(archival_reward_emission, input_type_whitelist_rejects_emission_mixes)
{
  {
    transaction tx;
    tx.vin.push_back(make_vin(64));
    tx.vin.push_back(txin_archival_bond_post{});
    EXPECT_FALSE(check_inputs_types_supported(tx));
  }
  {
    transaction tx;
    tx.vin.push_back(make_vin(64));
    tx.vin.push_back(txin_archival_serve_credit_response{});
    EXPECT_FALSE(check_inputs_types_supported(tx));
  }
}

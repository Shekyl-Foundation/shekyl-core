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

// RK-3 oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what epee emits for `get_block_header_by_height` — and with it the
// shared 24-field `block_header_response` that RK-3b and RK-5's three
// deferred header methods will reuse — from FIXED facts, before the C++
// handler and struct are deleted.
//
// Two cases, because the header's wire shape is not uniform:
//   * `full`     — every field populated: a 128-bit difficulty with a high
//                  word (exercising `wide_difficulty` / `difficulty_top64`),
//                  a filled `pow_hash`, non-zero weights, orphan status set.
//   * `defaults` — the OPT fields at their defaults, so `block_weight` and
//                  `long_term_weight` are OMITTED while `block_size` (not
//                  OPT, and filled from the same source) stays; `pow_hash`
//                  is the empty string a non-`fill_pow_hash` request gets.
//
// This file is deleted together with the struct it captures, in the next
// commit of the slice; the vectors are what survive.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them; without it the test
// asserts byte-equality against the committed files.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "cryptonote_basic/difficulty.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
  void pin(const char* name, const std::string& json)
  {
    const std::string path = std::string(RPC_ORACLE_VECTOR_DIR) + "/" + name;
    if (std::getenv("SHEKYL_WRITE_RPC_VECTORS"))
    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.good()) << "cannot write " << path;
      out << json;
      return;
    }
    std::ifstream in(path, std::ios::binary);
    ASSERT_TRUE(in.good()) << "missing oracle vector " << path
      << " (run with SHEKYL_WRITE_RPC_VECTORS=1 to capture)";
    std::stringstream buf;
    buf << in.rdbuf();
    EXPECT_EQ(buf.str(), json) << "oracle vector " << name << " drifted from epee's output";
  }

  // A hash that is a function of its tag, so each of the header's five hash
  // fields is visibly distinct in the vector.
  crypto::hash tagged_hash(uint8_t tag)
  {
    crypto::hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i)
      h.data[i] = static_cast<char>((i * 7 + tag) & 0xff);
    return h;
  }

  // The 128-bit difficulty split exactly as `store_difficulty` does it.
  void store(cryptonote::difficulty_type value,
    uint64_t& low, std::string& wide, uint64_t& top64)
  {
    low = (value & 0xffffffffffffffff).convert_to<uint64_t>();
    wide = cryptonote::hex(value);
    top64 = ((value >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }
}

TEST(rpc_oracle_vectors, get_block_header_by_height_full_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response res{};
  cryptonote::block_header_response& h = res.block_header;
  h.major_version = 1;
  h.minor_version = 2;
  h.timestamp = 1700000000;
  h.prev_hash = epee::string_tools::pod_to_hex(tagged_hash(3));
  h.nonce = 305419896; // 0x12345678
  h.orphan_status = true;
  h.height = 1234567;
  h.depth = 42;
  h.hash = epee::string_tools::pod_to_hex(tagged_hash(11));
  // A difficulty above 2^64, so the wide form and the top word both matter.
  cryptonote::difficulty_type difficulty = 1;
  difficulty <<= 70;
  difficulty += 12345;
  store(difficulty, h.difficulty, h.wide_difficulty, h.difficulty_top64);
  cryptonote::difficulty_type cumulative = 1;
  cumulative <<= 71;
  cumulative += 99;
  store(cumulative, h.cumulative_difficulty, h.wide_cumulative_difficulty,
    h.cumulative_difficulty_top64);
  h.reward = 600000000000;
  h.block_size = h.block_weight = 98765;
  h.num_txes = 7;
  h.pow_hash = epee::string_tools::pod_to_hex(tagged_hash(23));
  h.long_term_weight = 87654;
  h.miner_tx_hash = epee::string_tools::pod_to_hex(tagged_hash(31));
  h.curve_tree_root = epee::string_tools::pod_to_hex(tagged_hash(41));
  h.attestation_root = epee::string_tools::pod_to_hex(tagged_hash(53));
  res.status = CORE_RPC_STATUS_OK;

  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(
    static_cast<const cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response_t&>(res), json));
  pin("get_block_header_by_height_full_v1.json", json);
}

TEST(rpc_oracle_vectors, get_block_header_by_height_defaults_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response res{};
  cryptonote::block_header_response& h = res.block_header;
  h.major_version = 1;
  h.minor_version = 1;
  h.timestamp = 1500000000;
  h.prev_hash = epee::string_tools::pod_to_hex(crypto::null_hash);
  h.nonce = 0;
  h.orphan_status = false;
  h.height = 0;      // genesis
  h.depth = 0;
  h.hash = epee::string_tools::pod_to_hex(tagged_hash(11));
  store(1, h.difficulty, h.wide_difficulty, h.difficulty_top64);
  store(1, h.cumulative_difficulty, h.wide_cumulative_difficulty,
    h.cumulative_difficulty_top64);
  h.reward = 0;
  h.block_size = h.block_weight = 0;  // block_weight is OPT: omitted
  h.num_txes = 0;
  h.pow_hash = "";                    // no fill_pow_hash, or restricted
  h.long_term_weight = 0;             // OPT: omitted
  h.miner_tx_hash = epee::string_tools::pod_to_hex(tagged_hash(31));
  h.curve_tree_root = epee::string_tools::pod_to_hex(crypto::null_hash);
  h.attestation_root = epee::string_tools::pod_to_hex(crypto::null_hash);
  res.status = CORE_RPC_STATUS_OK;

  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(
    static_cast<const cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response_t&>(res), json));
  pin("get_block_header_by_height_defaults_v1.json", json);
}

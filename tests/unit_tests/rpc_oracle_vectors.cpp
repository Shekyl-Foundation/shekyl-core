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

// RK-3b oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what epee emits for `get_block` from FIXED facts, before the C++
// handler and COMMAND_RPC_GET_BLOCK are deleted.
//
// Three cases, because this reply's shape is not uniform:
//   * `full`      — a block with transactions, a filled `pow_hash`, and
//                   `orphan_status` set: the by-hash lookup can return an
//                   alt block, which is why that flag is a real value here
//                   and was a constant in RK-3 (RK-D8 §7, 2026-08-23).
//   * `no_txes`   — an empty `tx_hashes`, pinning whether epee emits `[]`
//                   or omits the member; and the header's OPT fields at
//                   their defaults, so `block_weight` / `long_term_weight`
//                   vanish while `block_size` stays.
//   * `by_hash`   — the same reply reached by hash rather than height, to
//                   pin that the lookup mode does not change the shape.
//
// `blob` and `json` are carried verbatim: `json` is epee's rendering of the
// whole block (RK-D11) and stays C++-rendered through RK-3b, so these
// vectors pin the *envelope* around it, not a Rust reimplementation of it.
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
#include <vector>

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

  // A hash that is a function of its tag, so every hash field in the vector
  // is visibly distinct. Same generator as the Rust parity test's.
  crypto::hash tagged_hash(uint8_t tag)
  {
    crypto::hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i)
      h.data[i] = static_cast<char>((i * 7 + tag) & 0xff);
    return h;
  }

  std::string tagged_hex(uint8_t tag)
  {
    return epee::string_tools::pod_to_hex(tagged_hash(tag));
  }

  // The 128-bit difficulty split exactly as `store_difficulty` does it.
  void store(cryptonote::difficulty_type value,
    uint64_t& low, std::string& wide, uint64_t& top64)
  {
    low = (value & 0xffffffffffffffff).convert_to<uint64_t>();
    wide = cryptonote::hex(value);
    top64 = ((value >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  // The header half, shared by the cases: RK-3 already pinned this struct on
  // its own, so here it is a populated backdrop for the fields `get_block`
  // adds around it.
  void fill_header(cryptonote::block_header_response& h, bool orphan, bool with_pow)
  {
    h.major_version = 1;
    h.minor_version = 2;
    h.timestamp = 1700000000;
    h.prev_hash = tagged_hex(3);
    h.nonce = 305419896; // 0x12345678
    h.orphan_status = orphan;
    h.height = 1234567;
    h.depth = 42;
    h.hash = tagged_hex(11);
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
    h.num_txes = 2;
    h.pow_hash = with_pow ? tagged_hex(23) : "";
    h.long_term_weight = 87654;
    h.miner_tx_hash = tagged_hex(31);
    h.curve_tree_root = tagged_hex(41);
    h.attestation_root = tagged_hex(53);
  }

  // A stand-in for the two carried-verbatim strings. Their *content* is the
  // C++ serializer's and epee's respectively (RK-D11); what these vectors
  // pin is that the envelope carries them unaltered, so fixed stand-ins say
  // more than a real block's would.
  const char* const BLOB_HEX = "0101a1b2c3d4e5f60708";
  const char* const BLOCK_JSON = "{\n  \"major_version\": 1, \n  \"nonce\": 305419896\n}";

  std::string emit(const cryptonote::COMMAND_RPC_GET_BLOCK::response& res)
  {
    std::string json;
    EXPECT_TRUE(epee::serialization::store_t_to_json(
      static_cast<const cryptonote::COMMAND_RPC_GET_BLOCK::response_t&>(res), json));
    return json;
  }
}

TEST(rpc_oracle_vectors, get_block_full_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCK::response res{};
  fill_header(res.block_header, /*orphan=*/true, /*with_pow=*/true);
  // The wire carries the miner tx hash twice — here and inside the header.
  // Duplication preserved; RK-W's to retire.
  res.miner_tx_hash = res.block_header.miner_tx_hash;
  res.tx_hashes.push_back(tagged_hex(61));
  res.tx_hashes.push_back(tagged_hex(67));
  res.blob = BLOB_HEX;
  res.json = BLOCK_JSON;
  res.status = CORE_RPC_STATUS_OK;
  pin("get_block_full_v1.json", emit(res));
}

TEST(rpc_oracle_vectors, get_block_no_txes_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCK::response res{};
  cryptonote::block_header_response& h = res.block_header;
  h.major_version = 1;
  h.minor_version = 1;
  h.timestamp = 1500000000;
  h.prev_hash = epee::string_tools::pod_to_hex(crypto::null_hash);
  h.nonce = 0;
  h.orphan_status = false;
  h.height = 0;      // genesis
  h.depth = 0;
  h.hash = tagged_hex(11);
  store(1, h.difficulty, h.wide_difficulty, h.difficulty_top64);
  store(1, h.cumulative_difficulty, h.wide_cumulative_difficulty,
    h.cumulative_difficulty_top64);
  h.reward = 0;
  h.block_size = h.block_weight = 0;  // block_weight is OPT: omitted
  h.num_txes = 0;
  h.pow_hash = "";                    // no fill_pow_hash, or restricted
  h.long_term_weight = 0;             // OPT: omitted
  h.miner_tx_hash = tagged_hex(31);
  h.curve_tree_root = epee::string_tools::pod_to_hex(crypto::null_hash);
  h.attestation_root = epee::string_tools::pod_to_hex(crypto::null_hash);
  res.miner_tx_hash = h.miner_tx_hash;
  // Left empty on purpose: this is the case that says whether an empty
  // `tx_hashes` is emitted as `[]` or dropped from the document.
  res.blob = BLOB_HEX;
  res.json = BLOCK_JSON;
  res.status = CORE_RPC_STATUS_OK;
  pin("get_block_no_txes_v1.json", emit(res));
}

TEST(rpc_oracle_vectors, get_block_by_hash_v1)
{
  // Reached by hash instead of by height. The reply must be shaped
  // identically — the lookup mode is a request concern, not a wire one — so
  // this vector exists to make a divergence visible if one is ever
  // introduced.
  cryptonote::COMMAND_RPC_GET_BLOCK::response res{};
  fill_header(res.block_header, /*orphan=*/false, /*with_pow=*/false);
  res.miner_tx_hash = res.block_header.miner_tx_hash;
  res.tx_hashes.push_back(tagged_hex(61));
  res.tx_hashes.push_back(tagged_hex(67));
  res.blob = BLOB_HEX;
  res.json = BLOCK_JSON;
  res.status = CORE_RPC_STATUS_OK;
  pin("get_block_by_hash_v1.json", emit(res));
}

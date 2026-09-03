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


// RK-5b oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what epee emits for `get_last_block_header`,
// `get_block_header_by_hash`, `get_block_headers_range`, `hard_fork_info` and
// `get_fee_estimate` before their handlers and COMMAND_RPC_ structs are
// deleted. Written for this slice and deleted with the structs it captures,
// as the vectors' README requires — that is a per-method fact, not a date,
// and these five are still standing.
//
// **RK-5b diverges from the C++ on purpose in four places**, so these `_v1`
// files are not what the daemon will emit afterwards. They are the *before*
// half of four `_v1`/`_v2` pairs, and each `_v2` is held honest by a delta
// test in `rpc_parity.rs` rather than hand-authored. Three of the four are
// mechanical — a deleted request field, a dropped `fee` scalar, one field
// split into two — and the fourth, `block_headers` becoming per-element
// slots, is a **shape** change with no subtraction from `_v1` that produces
// it, so its delta test derives `_v2` by transform instead of subtraction.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

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

  // Same generator as every earlier emitter's and the Rust parity test's.
  crypto::hash tagged_hash(uint8_t tag)
  {
    crypto::hash h;
    auto* bytes = reinterpret_cast<unsigned char*>(h.data);
    for (size_t i = 0; i < sizeof(h.data); ++i)
      bytes[i] = static_cast<unsigned char>((i * 7 + tag) & 0xff);
    return h;
  }

  std::string tagged_hex(uint8_t tag)
  {
    return epee::string_tools::pod_to_hex(tagged_hash(tag));
  }

  template <class T>
  std::string emit(T& obj)
  {
    std::string json;
    EXPECT_TRUE(epee::serialization::store_t_to_json(obj, json));
    return json;
  }

  // The same fixed header RK-3's vectors were captured from, so the RK-5b
  // pairs and the RK-3 ones describe one block rather than two.
  cryptonote::block_header_response vector_header(uint8_t tag, bool orphan, bool with_pow)
  {
    cryptonote::block_header_response h{};
    h.major_version = 1;
    h.minor_version = 2;
    h.timestamp = 1700000000;
    h.prev_hash = tagged_hex(3);
    h.nonce = 305419896;
    h.orphan_status = orphan;
    h.height = 1234567;
    h.depth = 42;
    h.hash = tagged_hex(tag);
    h.difficulty = 12345;
    h.wide_difficulty = "0x400000000000003039";
    h.difficulty_top64 = 64;
    h.cumulative_difficulty = 99;
    h.wide_cumulative_difficulty = "0x800000000000000063";
    h.cumulative_difficulty_top64 = 128;
    h.reward = 600000000000;
    h.block_size = h.block_weight = 98765;
    h.num_txes = 2;  // RK-3's shared fixture; these vectors describe ONE block
    h.pow_hash = with_pow ? tagged_hex(23) : "";
    h.long_term_weight = 87654;
    h.miner_tx_hash = tagged_hex(31);
    h.curve_tree_root = tagged_hex(41);
    h.attestation_root = tagged_hex(53);
    return h;
  }
}

// ─── get_last_block_header ───────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_last_block_header_v1)
{
  cryptonote::COMMAND_RPC_GET_LAST_BLOCK_HEADER::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.block_header = vector_header(11, false, false);
  pin("get_last_block_header_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_LAST_BLOCK_HEADER::response_t&>(res)));
}

// ─── get_block_header_by_hash ────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_block_header_by_hash_request_v1)
{
  // Both request shapes the C++ accepted, including the singular `hash` that
  // 3.26 deletes — captured so the `_v2` delta test can subtract exactly it.
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request req{};
  req.hash = tagged_hex(11);
  req.hashes = {tagged_hex(11), tagged_hex(12)};
  req.fill_pow_hash = true;
  pin("get_block_header_by_hash_request_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_block_header_by_hash_v1)
{
  // Two found headers. The C++ could not express a *missing* one — it
  // returned an error and discarded the batch — which is why the `_v2` delta
  // test extends this rather than subtracting from it.
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.block_headers.push_back(vector_header(11, false, false));
  res.block_headers.push_back(vector_header(12, true, false));
  pin("get_block_header_by_hash_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response_t&>(res)));
}

// ─── get_block_headers_range ─────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_block_headers_range_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.headers.push_back(vector_header(11, false, false));
  res.headers.push_back(vector_header(12, false, false));
  pin("get_block_headers_range_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response_t&>(res)));
}

// ─── hard_fork_info ──────────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, hard_fork_info_v1)
{
  // `version` here is `get_current_hard_fork_version()` — the collision 3.26
  // splits into `queried_version` and `active_version`. The values below are
  // deliberately *different* numbers so the split is checkable: a reply where
  // they coincided could not distinguish the two readings.
  cryptonote::COMMAND_RPC_HARD_FORK_INFO::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.version = 3;
  res.enabled = true;
  res.window = 10080;
  res.votes = 42;
  res.threshold = 0;
  res.voting = 9;
  res.state = 2;
  res.earliest_height = 1234000;
  pin("hard_fork_info_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_HARD_FORK_INFO::response_t&>(res)));
}

// ─── get_fee_estimate ────────────────────────────────────────────────────────

TEST(rpc_oracle_vectors, get_fee_estimate_v1)
{
  // `fee` is `fees[0]` under a second name; 3.26 drops it. Captured with
  // `fees` populated so the `_v2` delta test can subtract exactly `fee`.
  cryptonote::COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response res{};
  res.status = CORE_RPC_STATUS_OK;
  res.fees = {10, 20, 30, 40};
  res.fee = res.fees[0];
  res.quantization_mask = 8;
  pin("get_fee_estimate_v1.json",
    emit(static_cast<cryptonote::COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response_t&>(res)));
}

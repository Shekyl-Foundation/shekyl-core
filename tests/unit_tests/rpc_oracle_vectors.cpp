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

// RK-4a oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// The first BINARY captures. Everything pinned before this slice was epee's
// JSON; `/get_o_indexes.bin` speaks portable_storage, whose whole claim is
// byte-exactness, so these vectors are written and compared as **bytes**. A
// text pipe would translate a newline invisibly in the diff and fatally on
// the wire — checking a byte-exact claim through it tests the pipe.
//
// Three cases:
//   * `request`  — `{ txid: <32 raw bytes> }`. The txid is
//                  KV_SERIALIZE_VAL_POD_AS_BLOB, so it crosses as a 32-byte
//                  blob, not as hex. Getting that wrong is the single most
//                  likely way a hand-written Rust map diverges.
//   * `response` — `{ status: "OK", o_indexes: [u64 ...] }`.
//   * `empty`    — the same reply with no indexes, which pins that epee
//                  drops an empty sequence from the document entirely
//                  (§3.1). The wallet client already depends on this: it
//                  reads a missing `o_indexes` as an empty vector.
//
// This file is deleted together with the structs it captures, in the same
// slice; the vectors are what survive.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them; without it the test
// asserts byte-equality against the committed files.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "span.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
  // Byte-exact write/compare. Deliberately not the text `pin()` the JSON
  // vectors use: these files are binary and must round-trip unaltered.
  void pin_bin(const char* name, const std::string& bytes)
  {
    const std::string path = std::string(RPC_ORACLE_VECTOR_DIR) + "/" + name;
    if (std::getenv("SHEKYL_WRITE_RPC_VECTORS"))
    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.good()) << "cannot write " << path;
      out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
      return;
    }
    std::ifstream in(path, std::ios::binary);
    ASSERT_TRUE(in.good()) << "missing oracle vector " << path
      << " (run with SHEKYL_WRITE_RPC_VECTORS=1 to capture)";
    std::stringstream buf;
    buf << in.rdbuf();
    const std::string want = buf.str();
    ASSERT_EQ(want.size(), bytes.size()) << "oracle vector " << name << " changed length";
    EXPECT_EQ(0, std::memcmp(want.data(), bytes.data(), bytes.size()))
      << "oracle vector " << name << " drifted from epee's bytes";
  }

  crypto::hash tagged_hash(uint8_t tag)
  {
    crypto::hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i)
      h.data[i] = static_cast<char>((i * 7 + tag) & 0xff);
    return h;
  }

  template <class T>
  std::string to_binary(T& obj)
  {
    epee::byte_slice slice = epee::serialization::store_t_to_binary(obj);
    return std::string(reinterpret_cast<const char*>(slice.data()), slice.size());
  }
}

TEST(rpc_oracle_vectors, get_o_indexes_request_v1)
{
  cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request req{};
  req.txid = tagged_hash(31);
  pin_bin("get_o_indexes_request_v1.bin",
    to_binary(static_cast<cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_o_indexes_response_v1)
{
  cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response res{};
  res.o_indexes = {0, 1, 42, 4294967296ull, 18446744073709551615ull};
  res.status = CORE_RPC_STATUS_OK;
  pin_bin("get_o_indexes_response_v1.bin",
    to_binary(static_cast<cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_o_indexes_response_empty_v1)
{
  // A transaction with no outputs recorded yet. epee drops the empty
  // sequence from the document, which is why the wallet client reads a
  // missing `o_indexes` as an empty vector rather than as an error.
  cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response res{};
  res.status = CORE_RPC_STATUS_OK;
  pin_bin("get_o_indexes_response_empty_v1.bin",
    to_binary(static_cast<cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response_t&>(res)));
}

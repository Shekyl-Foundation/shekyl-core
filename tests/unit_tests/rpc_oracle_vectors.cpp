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

// RK-2 oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Builds the C++ replies that RK-2 migrates from FIXED facts (never a live
// chain), serializes them exactly as the daemon's JSON-RPC dispatch path
// does, and pins the bytes as committed vectors under
// rust/shekyl-rpc-types/tests/vectors/rpc/. The Rust parity tests read the
// same vectors and assert equality against the native handlers.
//
// This file exists for one commit: it is deleted together with the C++
// handlers and structs it captures (the next commit of the slice). The
// vectors are what survive — the oracle's memory after the oracle is gone.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write the vectors; without it
// the test asserts byte-equality against the committed files.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
  std::string vector_path(const char* name)
  {
    return std::string(RPC_ORACLE_VECTOR_DIR) + "/" + name;
  }

  // Pin `json` to `name`: write it when SHEKYL_WRITE_RPC_VECTORS is set,
  // otherwise require the committed file to be byte-identical.
  void pin(const char* name, const std::string& json)
  {
    const std::string path = vector_path(name);
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

  // The same patterned hash RK-1's capture used, so one hex string serves
  // every vector and the Rust side reproduces it with one helper.
  crypto::hash patterned_hash()
  {
    crypto::hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i)
      h.data[i] = static_cast<char>((i * 7 + 3) & 0xff);
    return h;
  }
}

// get_block_count (alias getblockcount): a KV response — chain height as
// `count`, plus the `status` every KV reply carries.
TEST(rpc_oracle_vectors, get_block_count_v1)
{
  cryptonote::COMMAND_RPC_GETBLOCKCOUNT::response res{};
  res.count = 1234567;
  res.status = CORE_RPC_STATUS_OK;
  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(
    static_cast<const cryptonote::COMMAND_RPC_GETBLOCKCOUNT::response_t&>(res), json));
  pin("get_block_count_v1.json", json);
}

// on_get_block_hash (alias on_getblockhash): the reply is NOT a KV object —
// `COMMAND_RPC_GETBLOCKHASH::response` is a bare `std::string`, and
// core_rpc_ffi.cpp's dispatcher emits it as the JSON-RPC `result` by wrapping
// it in quotes. The vector is that document: a lone JSON string, no `status`.
// Captured the way the dispatcher builds it, so the vector records what went
// on the wire rather than what a re-serialization would produce.
TEST(rpc_oracle_vectors, get_block_hash_v1)
{
  const cryptonote::COMMAND_RPC_GETBLOCKHASH::response res =
    epee::string_tools::pod_to_hex(patterned_hash());
  std::ostringstream oss;
  oss << '"' << res << '"';
  pin("get_block_hash_v1.json", oss.str());
}

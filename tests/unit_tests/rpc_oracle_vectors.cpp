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

// RK-4b oracle capture (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.5).
//
// Pins what epee emits for `/get_blocks_by_height.bin` before the C++
// handler and COMMAND_RPC_GET_BLOCKS_BY_HEIGHT are deleted. Bytes, not
// text — see RK-4a's capture for why.
//
// The interesting part is how much of `block_complete_entry` never reaches
// this wire. Its KV map has five members, and the handler
// (`on_get_blocks_by_height`) sets exactly two:
//
//   pruned              OPT false, never set  -> omitted
//   block               plain                 -> a string
//   block_weight        OPT 0, never set      -> omitted
//   txs                 shape depends on `pruned`: with it false the map
//                       serializes a std::vector<blobdata>, so an ARRAY OF
//                       STRINGS, and each entry's prunable_hash is dropped
//   attestation_witness OPT empty, never set  -> omitted
//
// So the array-of-objects form of `txs` — `tx_blob_entry` with its
// prunable_hash — is **not reachable through this endpoint**. Only the p2p
// path sets `pruned`, and that schema belongs to `shekyl-levin`. These
// vectors are what says so; without them a Rust map would reasonably model
// the union and carry a variant the daemon can never emit.
//
// Cases:
//   * `request`     — `{ heights: [u64 ...] }`.
//   * `response`    — two blocks, one with transactions and one without,
//                     which pins the array-of-strings shape and the
//                     omission of an empty `txs` in the same document.
//   * `response_empty` — no blocks at all: `blocks` omitted entirely.
//
// Deleted with the struct it captures, later in this slice.
//
// Run with SHEKYL_WRITE_RPC_VECTORS=1 to (re)write them.

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "span.h"

#ifndef RPC_ORACLE_VECTOR_DIR
#define RPC_ORACLE_VECTOR_DIR "rust/shekyl-rpc-types/tests/vectors/rpc"
#endif

namespace
{
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

  // A blob that is a function of its tag, so each one is distinguishable in
  // the capture and a transposed field is visible.
  std::string tagged_blob(uint8_t tag, size_t len)
  {
    std::string s(len, '\0');
    for (size_t i = 0; i < len; ++i)
      s[i] = static_cast<char>((i * 7 + tag) & 0xff);
    return s;
  }

  template <class T>
  std::string to_binary(T& obj)
  {
    epee::byte_slice slice = epee::serialization::store_t_to_binary(obj);
    return std::string(reinterpret_cast<const char*>(slice.data()), slice.size());
  }
}

TEST(rpc_oracle_vectors, get_blocks_by_height_request_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request req{};
  req.heights = {0, 1, 4294967296ull, 18446744073709551615ull};
  pin_bin("get_blocks_by_height_request_v1.bin",
    to_binary(static_cast<cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request_t&>(req)));
}

TEST(rpc_oracle_vectors, get_blocks_by_height_response_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response res{};
  res.blocks.resize(2);

  // A block with transactions. `pruned` is left false, which is what the
  // handler does, so `txs` goes out as an array of strings and the
  // prunable_hash set below is dropped — the capture is what proves it.
  res.blocks[0].block = tagged_blob(11, 24);
  res.blocks[0].txs.push_back({tagged_blob(31, 16), crypto::null_hash});
  res.blocks[0].txs.push_back({tagged_blob(41, 8), crypto::null_hash});

  // A block with none: `txs` is an empty sequence, which epee drops.
  res.blocks[1].block = tagged_blob(53, 12);

  res.status = CORE_RPC_STATUS_OK;
  pin_bin("get_blocks_by_height_response_v1.bin",
    to_binary(static_cast<cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response_t&>(res)));
}

TEST(rpc_oracle_vectors, get_blocks_by_height_response_empty_v1)
{
  cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response res{};
  res.status = CORE_RPC_STATUS_OK;
  pin_bin("get_blocks_by_height_response_empty_v1.bin",
    to_binary(static_cast<cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response_t&>(res)));
}

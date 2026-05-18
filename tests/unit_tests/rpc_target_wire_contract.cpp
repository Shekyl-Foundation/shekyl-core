// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// RPC wire-contract regression test for the block-target surface.
//
// Two public JSON-RPC fields carry the block target time in seconds:
//
//   * `mining_status.block_target` — uint32_t, sourced from
//     `SHEKYL_DAA_TARGET_SECONDS` at src/rpc/core_rpc_server.cpp:1452
//     (commit 6 of the LWMA-1 Phase 4 cutover rewired this).
//
//   * `get_info.target` — uint64_t, sourced from
//     `Blockchain::get_difficulty_target()` which returns
//     `SHEKYL_DAA_TARGET_SECONDS` (also rewired by commit 6).
//
// Both fields are pinned to the literal 120 by the public RPC contract.
// This test asserts:
//
//   1. `SHEKYL_DAA_TARGET_SECONDS` equals 120 (via a static_assert below);
//      a future JSON-authority change would trip the static_assert before
//      the daemon ever serializes a wrong value.
//   2. The epee KV-serialization layer emits the field with the byte
//      sequence `"block_target":120` (or `"target":120`).
//
// Property (1) protects against arithmetic drift in the Shekyl constant.
// Property (2) protects against a future epee change silently breaking the
// wire layout.
//
// The exact substring matched here is the pretty-printed form that
// `epee::serialization::store_t_to_json` emits by default (the same
// `indent=0, insert_newlines=true` path the daemon's JSON-RPC handlers
// take). The space after `:` is part of the wire contract: downstream
// JSON parsers MUST tolerate it but offline grep-based monitoring relies
// on the canonical form.
//
// See docs/design/DAA_LWMA1_PHASE4_PREFLIGHT.md §16.4 for the migration
// bridge rationale.

#include "gtest/gtest.h"

#include "cryptonote_config.h"           // SHEKYL_DAA_TARGET_SECONDS via
                                         //   shekyl/consensus_constants_generated.h
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"

namespace
{

// Post-cutover invariant (commit 7 deleted `DIFFICULTY_TARGET_V2`; the
// transitional bridge static_assert is gone with it).
static_assert(SHEKYL_DAA_TARGET_SECONDS == 120,
    "RPC wire contract: mining_status.block_target and get_info.target "
    "are pinned to 120 seconds by the public JSON-RPC contract. Changing "
    "the constant requires a coordinated wire-format bump.");

} // namespace

TEST(rpc_target_wire_contract, mining_status_block_target)
{
  cryptonote::COMMAND_RPC_MINING_STATUS::response res{};
  res.block_target = SHEKYL_DAA_TARGET_SECONDS;

  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(res, json));
  EXPECT_NE(json.find("\"block_target\": 120"), std::string::npos)
      << "mining_status wire response must carry `\"block_target\": 120`; "
         "got:\n"
      << json;
}

TEST(rpc_target_wire_contract, get_info_target)
{
  cryptonote::COMMAND_RPC_GET_INFO::response res{};
  res.target = SHEKYL_DAA_TARGET_SECONDS;

  std::string json;
  ASSERT_TRUE(epee::serialization::store_t_to_json(res, json));
  EXPECT_NE(json.find("\"target\": 120"), std::string::npos)
      << "get_info wire response must carry `\"target\": 120`; got:\n"
      << json;
}

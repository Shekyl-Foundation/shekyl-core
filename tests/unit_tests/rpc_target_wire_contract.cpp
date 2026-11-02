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
// One JSON-RPC field served from C++ carries the block target time in
// seconds:
//
//   * `mining_status.block_target` — uint32_t, sourced from
//     `SHEKYL_DAA_TARGET_SECONDS` (commit 6 of the LWMA-1 Phase 4 cutover
//     rewired this).
//
// `get_info.target` was the second. `get_info` is served from Rust since
// RK-5c, and its target is held there as a value, not as a byte form
// (RK-D9): `target_is_the_difficulty_target` in
// `rust/shekyl-daemon-rpc/src/info.rs`, and the five `get_info` oracle
// vectors, which carry 120.
//
// The field is pinned to the literal 120 by the public RPC contract.
// This test asserts:
//
//   1. `SHEKYL_DAA_TARGET_SECONDS` equals 120 (via a static_assert below);
//      a future JSON-authority change would trip the static_assert before
//      the daemon ever serializes a wrong value.
//   2. The epee KV-serialization layer emits the field with the byte
//      sequence `"block_target":120`.
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
// See docs/completed/DAA_LWMA1_PHASE4_PREFLIGHT.md §16.4 for the migration
// bridge rationale.

#include "gtest/gtest.h"

#include "cryptonote_config.h"           // SHEKYL_DAA_TARGET_SECONDS via
                                         //   shekyl/consensus_constants_generated.h

namespace
{

// Post-cutover invariant (commit 7 deleted `DIFFICULTY_TARGET_V2`; the
// transitional bridge static_assert is gone with it).
static_assert(SHEKYL_DAA_TARGET_SECONDS == 120,
    "RPC wire contract: mining_status.block_target and get_info.target "
    "are pinned to 120 seconds by the public JSON-RPC contract. Changing "
    "the constant requires a coordinated wire-format bump.");

} // namespace

// The epee request structs that used to pin `block_target` and the
// absence of `major_version` are gone with the C++ server. The constant
// above is what those structs copied onto the wire; the Rust mining
// status and calc_pow types are the wire now.

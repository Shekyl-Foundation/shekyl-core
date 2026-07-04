// Copyright (c) 2025-2026, The Shekyl Foundation
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

// Bidirectional FFI-struct round-trip for shekyl_submit_facts_ffi
// (docs/design/DAEMON_SUBMIT_VERDICT.md §4.5, F26): C++-writes/Rust-reads
// and Rust-writes/C++-reads, per-FIELD on both sides with seed-derived
// per-field values, so a width/offset disagreement between the two
// languages' views of the layout fails even where a memcpy echo would
// pass. Requires the unit_tests binary to link the daemon Rust image
// (SHEKYL_RUST_IMAGE_DAEMON; the Rust twins live in shekyl-daemon-rpc).

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "rpc/daemon_submit_ffi.h"

// The Rust twins (rust/shekyl-daemon-rpc/src/ffi_exports.rs). Declared here
// rather than in daemon_submit_ffi.h: they are test hooks with no
// production callers on either side.
extern "C" {
void shekyl_submit_facts_rust_fill(shekyl_submit_facts_ffi* out, uint64_t seed);
int shekyl_submit_facts_rust_check(const shekyl_submit_facts_ffi* facts, uint64_t seed);
}

namespace
{

// §4.5 edge values: zeroed (seed 0), max (seed UINT64_MAX; u64::MAX
// heights, 0xFF hashes), plus representative nontrivial seeds.
constexpr uint64_t seeds[] = {0, 1, 0xDEADBEEFCAFEF00DULL, UINT64_MAX};

TEST(daemon_submit_ffi_roundtrip, cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_submit_facts_ffi facts;
    shekyl_submit_facts_test_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_submit_facts_rust_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(daemon_submit_ffi_roundtrip, rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_submit_facts_ffi facts;
    shekyl_submit_facts_rust_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_submit_facts_test_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(daemon_submit_ffi_roundtrip, single_byte_perturbation_fails_both_readers)
{
  // Byte-level sensitivity across the whole struct: flip each byte in turn
  // and require both languages' readers to notice. Catches a reader that
  // ignores (or mis-offsets past) any region, including the reserved pad.
  const uint64_t seed = 0xDEADBEEFCAFEF00DULL;
  shekyl_submit_facts_ffi reference;
  shekyl_submit_facts_test_fill(&reference, seed);

  for (size_t i = 0; i < sizeof(reference); ++i)
  {
    shekyl_submit_facts_ffi mutated;
    std::memcpy(&mutated, &reference, sizeof(reference));
    reinterpret_cast<uint8_t*>(&mutated)[i] ^= 0x01;
    EXPECT_EQ(-1, shekyl_submit_facts_test_check(&mutated, seed)) << "byte " << i;
    EXPECT_EQ(-1, shekyl_submit_facts_rust_check(&mutated, seed)) << "byte " << i;
  }
}

TEST(daemon_submit_ffi_roundtrip, null_arguments_are_rejected)
{
  EXPECT_EQ(-1, shekyl_submit_facts_test_check(nullptr, 1));
  EXPECT_EQ(-1, shekyl_submit_facts_rust_check(nullptr, 1));
  // Fill with null out-pointers must be a harmless no-op on both sides.
  shekyl_submit_facts_test_fill(nullptr, 1);
  shekyl_submit_facts_rust_fill(nullptr, 1);
}

}  // anonymous namespace

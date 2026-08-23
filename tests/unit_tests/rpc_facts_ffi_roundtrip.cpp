// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Bidirectional layout pin for shekyl_rpc_chain_tip_facts
// (docs/design/DAEMON_RPC_KV_CUTOVER.md §3.2, RK-D3; the F26 pattern from
// daemon_submit_ffi_roundtrip.cpp): C++ fills / Rust checks and Rust fills /
// C++ checks, per field from one seed, so a width, order or padding
// disagreement between the two views fails even where a memcpy echo passes.

#include <gtest/gtest.h>
#include <cstdint>

#include "rpc/rpc_facts_ffi.h"

extern "C" {
void shekyl_rpc_chain_tip_facts_rust_fill(shekyl_rpc_chain_tip_facts* out, uint64_t seed);
int shekyl_rpc_chain_tip_facts_rust_check(const shekyl_rpc_chain_tip_facts* facts, uint64_t seed);
void shekyl_rpc_hardfork_entry_rust_fill(shekyl_rpc_hardfork_entry* out, uint64_t seed);
int shekyl_rpc_hardfork_entry_rust_check(const shekyl_rpc_hardfork_entry* entry, uint64_t seed);
void shekyl_rpc_block_hash_facts_rust_fill(shekyl_rpc_block_hash_facts* out, uint64_t seed);
int shekyl_rpc_block_hash_facts_rust_check(const shekyl_rpc_block_hash_facts* facts, uint64_t seed);
void shekyl_rpc_block_header_facts_rust_fill(shekyl_rpc_block_header_facts* out, uint64_t seed);
int shekyl_rpc_block_header_facts_rust_check(const shekyl_rpc_block_header_facts* facts, uint64_t seed);
}

namespace
{
  constexpr uint64_t seeds[] = {0, 1, 0xDEADBEEFCAFEF00DULL, UINT64_MAX};
}

TEST(rpc_facts_ffi_roundtrip, cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_chain_tip_facts facts;
    shekyl_rpc_chain_tip_facts_test_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_chain_tip_facts_rust_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_chain_tip_facts facts;
    shekyl_rpc_chain_tip_facts_rust_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_chain_tip_facts_test_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, hardfork_entry_cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_hardfork_entry entry;
    shekyl_rpc_hardfork_entry_test_fill(&entry, seed);
    EXPECT_EQ(0, shekyl_rpc_hardfork_entry_rust_check(&entry, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, hardfork_entry_rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_hardfork_entry entry;
    shekyl_rpc_hardfork_entry_rust_fill(&entry, seed);
    EXPECT_EQ(0, shekyl_rpc_hardfork_entry_test_check(&entry, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, block_hash_facts_cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_block_hash_facts facts;
    shekyl_rpc_block_hash_facts_test_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_block_hash_facts_rust_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, block_hash_facts_rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_block_hash_facts facts;
    shekyl_rpc_block_hash_facts_rust_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_block_hash_facts_test_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, block_header_facts_cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_block_header_facts facts;
    shekyl_rpc_block_header_facts_test_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_block_header_facts_rust_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, block_header_facts_rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_block_header_facts facts;
    shekyl_rpc_block_header_facts_rust_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_block_header_facts_test_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, pod_sizes_are_the_documented_ones)
{
  static_assert(sizeof(shekyl_rpc_chain_tip_facts) == 56, "chain-tip facts POD changed size");
  static_assert(sizeof(shekyl_rpc_hardfork_entry) == 16, "hardfork entry POD changed size");
  static_assert(sizeof(shekyl_rpc_block_hash_facts) == 48, "block-hash facts POD changed size");
  static_assert(sizeof(shekyl_rpc_block_header_facts) == 304, "block-header facts POD changed size");
}

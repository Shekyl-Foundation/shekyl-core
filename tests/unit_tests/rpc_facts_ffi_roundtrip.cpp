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
void shekyl_rpc_hard_fork_facts_rust_fill(shekyl_rpc_hard_fork_facts* out, uint64_t seed);
int shekyl_rpc_hard_fork_facts_rust_check(const shekyl_rpc_hard_fork_facts* facts, uint64_t seed);
void shekyl_rpc_fee_estimate_facts_rust_fill(shekyl_rpc_fee_estimate_facts* out, uint64_t seed);
int shekyl_rpc_fee_estimate_facts_rust_check(const shekyl_rpc_fee_estimate_facts* facts, uint64_t seed);
void shekyl_rpc_net_stats_facts_rust_fill(shekyl_rpc_net_stats_facts* out, uint64_t seed);
int shekyl_rpc_net_stats_facts_rust_check(const shekyl_rpc_net_stats_facts* facts, uint64_t seed);
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

TEST(rpc_facts_ffi_roundtrip, net_stats_facts_cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_net_stats_facts facts;
    shekyl_rpc_net_stats_facts_test_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_net_stats_facts_rust_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, net_stats_facts_rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_net_stats_facts facts;
    shekyl_rpc_net_stats_facts_rust_fill(&facts, seed);
    EXPECT_EQ(0, shekyl_rpc_net_stats_facts_test_check(&facts, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, hard_fork_facts_cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_hard_fork_facts f;
    shekyl_rpc_hard_fork_facts_test_fill(&f, seed);
    EXPECT_EQ(0, shekyl_rpc_hard_fork_facts_rust_check(&f, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, hard_fork_facts_rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_hard_fork_facts f;
    shekyl_rpc_hard_fork_facts_rust_fill(&f, seed);
    EXPECT_EQ(0, shekyl_rpc_hard_fork_facts_test_check(&f, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, fee_estimate_facts_cpp_writes_rust_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_fee_estimate_facts f;
    shekyl_rpc_fee_estimate_facts_test_fill(&f, seed);
    EXPECT_EQ(0, shekyl_rpc_fee_estimate_facts_rust_check(&f, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, fee_estimate_facts_rust_writes_cpp_reads)
{
  for (const uint64_t seed : seeds)
  {
    shekyl_rpc_fee_estimate_facts f;
    shekyl_rpc_fee_estimate_facts_rust_fill(&f, seed);
    EXPECT_EQ(0, shekyl_rpc_fee_estimate_facts_test_check(&f, seed)) << "seed " << seed;
  }
}

TEST(rpc_facts_ffi_roundtrip, pod_sizes_are_the_documented_ones)
{
  static_assert(sizeof(shekyl_rpc_chain_tip_facts) == 56, "chain-tip facts POD changed size");
  static_assert(sizeof(shekyl_rpc_hardfork_entry) == 16, "hardfork entry POD changed size");
  static_assert(sizeof(shekyl_rpc_block_hash_facts) == 48, "block-hash facts POD changed size");
  static_assert(sizeof(shekyl_rpc_block_header_facts) == 304, "block-header facts POD changed size");

  // The two pointer-bearing facts structs. A fill/check twin means nothing
  // for a pointer — there is no seed value to compare — so what is pinned is
  // the layout itself: size and every field offset, the same numbers on both
  // sides (rust/shekyl-daemon-rpc/src/ffi.rs). Drift on either side is what
  // makes the unsafe reads in `CoreRpc::blocks_by_height` interpret foreign
  // memory, and it is invisible to every other test here.
  static_assert(sizeof(shekyl_rpc_block_payload) == 48, "block payload changed size");
  static_assert(offsetof(shekyl_rpc_block_payload, blob) == 0, "blob offset");
  static_assert(offsetof(shekyl_rpc_block_payload, blob_len) == 8, "blob_len offset");
  static_assert(offsetof(shekyl_rpc_block_payload, json) == 16, "json offset");
  static_assert(offsetof(shekyl_rpc_block_payload, json_len) == 24, "json_len offset");
  static_assert(offsetof(shekyl_rpc_block_payload, tx_hashes) == 32, "tx_hashes offset");
  static_assert(offsetof(shekyl_rpc_block_payload, tx_hashes_len) == 40, "tx_hashes_len offset");

  static_assert(sizeof(shekyl_rpc_block_entry) == 40, "block entry changed size");
  static_assert(offsetof(shekyl_rpc_block_entry, block) == 0, "block offset");
  static_assert(offsetof(shekyl_rpc_block_entry, block_len) == 8, "block_len offset");
  static_assert(offsetof(shekyl_rpc_block_entry, txs) == 16, "txs offset");
  static_assert(offsetof(shekyl_rpc_block_entry, tx_lens) == 24, "tx_lens offset");
  static_assert(offsetof(shekyl_rpc_block_entry, tx_count) == 32, "tx_count offset");

  // RK-4c: one requested transaction's answer. Pointers have no seed value to
  // fill and compare, so the layout is what gets pinned — offsets, not just
  // sizeof, because a field that moves without changing the total size is
  // exactly the edit sizeof cannot see.
  static_assert(sizeof(shekyl_rpc_tx_entry) == 112, "tx entry changed size");
  static_assert(offsetof(shekyl_rpc_tx_entry, pruned) == 0, "pruned offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, pruned_len) == 8, "pruned_len offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, prunable) == 16, "prunable offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, prunable_len) == 24, "prunable_len offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, output_indices) == 32, "output_indices offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, output_indices_len) == 40, "output_indices_len offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, block_height) == 48, "block_height offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, block_timestamp) == 56, "block_timestamp offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, received_timestamp) == 64, "received_timestamp offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, prunable_hash) == 72, "prunable_hash offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, where) == 104, "where offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, pruned_flag) == 105, "pruned_flag offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, double_spend_seen) == 106, "double_spend_seen offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, relayed) == 107, "relayed offset");
  static_assert(offsetof(shekyl_rpc_tx_entry, reserved) == 108, "reserved offset");

  static_assert(sizeof(shekyl_rpc_net_stats_facts) == 40, "net-stats facts POD changed size");
  static_assert(sizeof(shekyl_rpc_hard_fork_facts) == 32, "hard-fork facts POD changed size");
  static_assert(sizeof(shekyl_rpc_fee_estimate_facts) == 48, "fee-estimate facts POD changed size");

  // RK-5a's three list PODs. Same reason as `shekyl_rpc_tx_entry` above: they
  // carry pointers, so a fill/check twin has nothing to compare and the
  // layout itself is what must agree with
  // `rust/shekyl-daemon-rpc/src/ffi.rs`.
  static_assert(sizeof(shekyl_rpc_connection_facts) == 136, "connection facts changed size");
  static_assert(offsetof(shekyl_rpc_connection_facts, address) == 0, "address offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, address_len) == 8, "address_len offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, host) == 16, "host offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, host_len) == 24, "host_len offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, connection_id) == 32, "connection_id offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, started) == 48, "started offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, last_recv) == 56, "last_recv offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, last_send) == 64, "last_send offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, recv_count) == 72, "recv_count offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, send_count) == 80, "send_count offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, current_speed_down) == 88, "current_speed_down offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, current_speed_up) == 96, "current_speed_up offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, height) == 104, "height offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, support_flags) == 112, "support_flags offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, pruning_seed) == 116, "pruning_seed offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, port) == 120, "port offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, state) == 122, "state offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, address_type) == 123, "address_type offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, incoming) == 124, "incoming offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, localhost) == 125, "localhost offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, local_ip) == 126, "local_ip offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, reserved) == 127, "reserved offset");

  static_assert(sizeof(shekyl_rpc_sync_span_facts) == 72, "sync span facts changed size");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, remote_address) == 0, "remote_address offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, remote_address_len) == 8, "remote_address_len offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, start_block_height) == 16, "start_block_height offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, nblocks) == 24, "nblocks offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, size) == 32, "size offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, connection_id) == 40, "connection_id offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, rate) == 56, "rate offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, speed_fraction) == 60, "speed_fraction offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, filled) == 64, "filled offset");
  static_assert(offsetof(shekyl_rpc_sync_span_facts, reserved) == 65, "reserved offset");

  static_assert(sizeof(shekyl_rpc_peer_facts) == 40, "peer facts changed size");
  static_assert(offsetof(shekyl_rpc_peer_facts, host) == 0, "host offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, host_len) == 8, "host_len offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, last_seen) == 16, "last_seen offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, ip) == 24, "ip offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, pruning_seed) == 28, "pruning_seed offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, port) == 32, "port offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, white) == 34, "white offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, blocked) == 35, "blocked offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, reserved) == 36, "reserved offset");
}

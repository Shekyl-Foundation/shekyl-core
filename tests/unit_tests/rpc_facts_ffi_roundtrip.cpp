// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Layout pin for the RPC fact PODs. The seeded fill/check twins are gone
// with the C++ chain facts; what remains is the size and the offset of
// every field the Rust side reads.

#include <gtest/gtest.h>
#include <cstddef>

#include "rpc/rpc_facts_ffi.h"
#include "shekyl/shekyl_ffi.h"

TEST(rpc_facts_ffi_roundtrip, pod_sizes_are_the_documented_ones)
{
  static_assert(sizeof(shekyl_rpc_chain_tip_facts) == 56, "chain-tip facts POD changed size");
  // VC-2's identity POD. 1 + 7 reserved + 32 = 40, and the offsets are pinned
  // rather than inferred: 8 is where the hash starts once the byte is padded
  // out, and an editor who removed `reserved` would keep the size and move
  // the field.
  static_assert(sizeof(shekyl_rpc_identity_facts) == 40, "identity facts POD changed size");
  static_assert(offsetof(shekyl_rpc_identity_facts, nettype) == 0, "nettype offset");
  static_assert(offsetof(shekyl_rpc_identity_facts, genesis_hash) == 8, "genesis_hash offset");
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

  static_assert(sizeof(shekyl_rpc_net_stats_facts) == 40, "net-stats facts POD changed size");

  // RK-5c. Mirrored by `const _: ()` asserts in `ffi.rs`.
  static_assert(sizeof(shekyl_rpc_info_chain_facts) == 160, "info-chain facts POD changed size");
  static_assert(alignof(shekyl_rpc_info_chain_facts) == 8, "info-chain facts alignment");
  static_assert(offsetof(shekyl_rpc_info_chain_facts, top_hash) == 8, "top_hash offset");
  static_assert(offsetof(shekyl_rpc_info_chain_facts, difficulty_lo) == 40, "difficulty_lo offset");
  static_assert(offsetof(shekyl_rpc_info_chain_facts, core_target_height) == 144,
    "core_target_height offset");
  static_assert(offsetof(shekyl_rpc_info_chain_facts, synchronized) == 152, "synchronized offset");
  static_assert(offsetof(shekyl_rpc_info_chain_facts, protocol_version) == 156,
    "protocol_version offset");
  static_assert(offsetof(shekyl_rpc_info_chain_facts, reserved) == 157, "reserved offset");
  static_assert(sizeof(shekyl_rpc_info_status_facts) == 24, "info-status facts POD changed size");
  static_assert(sizeof(shekyl_rpc_info_peers_facts) == 32, "info-peers facts POD changed size");
  static_assert(sizeof(shekyl_rpc_fee_estimate_facts) == 32, "fee-estimate facts POD changed size");

  // RK-5a's three list PODs. Pointers have no seed value to fill and
  // compare, so the layout is what gets pinned — offsets, not just sizeof,
  // because a field that moves without changing the total size is exactly
  // the edit sizeof cannot see — and it must agree with
  // `rust/shekyl-daemon-rpc/src/ffi.rs`.
  static_assert(sizeof(shekyl_rpc_connection_facts) == 120, "connection facts changed size");
  static_assert(sizeof(shekyl_rpc_connection_facts) ==
      offsetof(shekyl_rpc_connection_facts, claims_known) +
        sizeof(shekyl_rpc_connection_facts::claims_known),
    "connection facts ends on claims_known");
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
  static_assert(offsetof(shekyl_rpc_connection_facts, port) == 112, "port offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, state) == 114, "state offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, address_type) == 115, "address_type offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, incoming) == 116, "incoming offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, localhost) == 117, "localhost offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, local_ip) == 118, "local_ip offset");
  static_assert(offsetof(shekyl_rpc_connection_facts, claims_known) == 119, "claims_known offset");

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

  // `shekyl_rpc_peer_facts` is `shekyl_ffi.h`'s since the listing moved to
  // Rust (2026-10-13): no `last_seen`, 24 bytes, pinned on three sides.
  static_assert(sizeof(shekyl_rpc_peer_facts) == 24, "peer facts changed size");
  static_assert(offsetof(shekyl_rpc_peer_facts, host) == 0, "host offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, host_len) == 8, "host_len offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, ip) == 16, "ip offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, port) == 20, "port offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, white) == 22, "white offset");
  static_assert(offsetof(shekyl_rpc_peer_facts, blocked) == 23, "blocked offset");
}

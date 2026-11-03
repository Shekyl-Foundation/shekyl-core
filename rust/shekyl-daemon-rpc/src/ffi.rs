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

//! The C layouts of `src/rpc/core_rpc_ffi.h` and `src/rpc/rpc_facts_ffi.h`:
//! the opaque handle, the fact PODs, the return codes, each pinned by a
//! layout assert. The functions that fill them are not declared here: this
//! crate imports no symbol (DC-F43); it calls them through the
//! [`crate::seam::CoreSeam`] the binary installs.

use std::os::raw::c_char;

#[repr(C)]
pub struct CoreRpcHandle {
    _opaque: [u8; 0],
}

// ── RPC facts shims (src/rpc/rpc_facts_ffi.h; DAEMON_RPC_KV_CUTOVER.md §3.2) ──

/// `shekyl_rpc_chain_tip` succeeded / the facts POD is filled.
pub const SHEKYL_RPC_FACTS_OK: i32 = 0;
/// Null handle or null out pointer.
pub const SHEKYL_RPC_FACTS_ERR_NULL: i32 = -1;
/// The core is not initialized.
pub const SHEKYL_RPC_FACTS_ERR_NOT_READY: i32 = -2;
/// A core / P2P read threw inside the shim; logged there, reported here —
/// never an unwind across the C ABI.
pub const SHEKYL_RPC_FACTS_ERR_INTERNAL: i32 = -3;
/// The store reported a height it cannot produce the block for — a
/// data-integrity fault of this daemon, distinct from a read that threw.
pub const SHEKYL_RPC_FACTS_ERR_INCONSISTENT: i32 = -4;

/// Twin of `shekyl_rpc_identity_facts` (VC-2): what this daemon **is**, as
/// opposed to what its chain tip looks like right now.
///
/// Its own POD rather than two more fields on [`ChainTipFactsFfi`]
/// (`VC-R17`): `nettype` and the genesis hash are fixed at daemon start and
/// per network, while the tip changes every block, and five of the tip POD's
/// six callers want a tip. Splitting also keeps the tip POD's layout twins,
/// seeded fill indices and size pin exactly where they were.
///
/// The rules digest is not carried here — it is compiled into this image
/// from `config/`, so the handler reads `CONSENSUS_CONSTANTS_DIGEST` and
/// never asks C++ for it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityFactsFfi {
    /// `cryptonote::network_type`: MAINNET=0, TESTNET=1, STAGENET=2,
    /// FAKECHAIN=3.
    pub nettype: u8,
    pub reserved: [u8; 7],
    /// Block 0's id.
    pub genesis_hash: [u8; 32],
}

/// Twin of `shekyl_rpc_chain_tip_facts`. Layout pinned by
/// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTipFactsFfi {
    /// Top block height + 1.
    pub chain_height: u64,
    pub top_hash: [u8; 32],
    /// Raw core target height. The handlers forward it; they do not rewrite
    /// it to 0 when the node is synchronized.
    pub target_height: u64,
    pub synchronized: u8,
    pub release_build: u8,
    pub reserved: [u8; 6],
}

/// Twin of `shekyl_rpc_block_hash_facts` (RK-2). Layout pinned by
/// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHashFactsFfi {
    pub hash: [u8; 32],
    /// Chain height at the moment of the read (top block height + 1).
    pub chain_height: u64,
    /// `0` when `height` was at or past `chain_height` — `hash` is then zero.
    pub found: u8,
    pub reserved: [u8; 7],
}

/// Twin of `shekyl_rpc_block_entry`: one block of a by-height answer. Every
/// pointer borrows memory owned by the opaque owner the export returns.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockEntryFfi {
    pub block: *const u8,
    pub block_len: usize,
    pub txs: *const *const u8,
    pub tx_lens: *const usize,
    pub tx_count: usize,
}

const _: () = assert!(std::mem::size_of::<BlockEntryFfi>() == 40);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, block) == 0);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, block_len) == 8);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, txs) == 16);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, tx_lens) == 24);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, tx_count) == 32);

/// Twin of `shekyl_rpc_block_payload`: the variable-length half of a
/// block's facts. Every pointer borrows memory owned by the opaque owner the
/// export returns, and is invalid the moment `shekyl_rpc_block_free` runs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockPayloadFfi {
    pub blob: *const u8,
    pub blob_len: usize,
    pub json: *const std::os::raw::c_char,
    pub json_len: usize,
    /// `tx_hashes_len * 32` contiguous bytes.
    pub tx_hashes: *const u8,
    /// Number of hashes, not bytes.
    pub tx_hashes_len: usize,
}

// The C++ half of this twin is in tests/unit_tests/rpc_facts_ffi_roundtrip.cpp.
// Pointers have no seed value to fill and compare, so the layout itself is
// what gets pinned: a field reordered or widened on one side and not the
// other is what turns the unsafe reads below into reads of foreign memory.
const _: () = assert!(std::mem::size_of::<BlockPayloadFfi>() == 48);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, blob) == 0);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, blob_len) == 8);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, json) == 16);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, json_len) == 24);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, tx_hashes) == 32);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, tx_hashes_len) == 40);

impl Default for BlockPayloadFfi {
    fn default() -> Self {
        Self {
            blob: std::ptr::null(),
            blob_len: 0,
            json: std::ptr::null(),
            json_len: 0,
            tx_hashes: std::ptr::null(),
            tx_hashes_len: 0,
        }
    }
}

/// Twin of `shekyl_rpc_block_header_facts` (RK-3).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeaderFactsFfi {
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub miner_tx_hash: [u8; 32],
    pub curve_tree_root: [u8; 32],
    pub attestation_root: [u8; 32],
    pub pow_hash: [u8; 32],
    pub height: u64,
    pub depth: u64,
    pub chain_height: u64,
    pub timestamp: u64,
    pub difficulty_lo: u64,
    pub difficulty_hi: u64,
    pub cumulative_difficulty_lo: u64,
    pub cumulative_difficulty_hi: u64,
    pub reward: u64,
    pub block_weight: u64,
    pub long_term_weight: u64,
    pub num_txes: u64,
    pub nonce: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub orphan_status: u8,
    pub pow_hash_filled: u8,
    /// `0` means no such block: by height, `height >= chain_height`; by hash,
    /// a hash this chain does not hold. An in-range height the store cannot
    /// produce is `ERR_INCONSISTENT`, never `found == 0`.
    pub found: u8,
    pub reserved: [u8; 7],
}

/// Twin of `shekyl_rpc_fee_estimate_facts` (RK-5b).
///
/// `fees` is one slot per priced tier: `[economy, standard, priority]`.
/// `fee_count` reports how many the estimator actually wrote, so a change
/// to that contract is a refusal rather than a shorter answer read as a
/// base fee. The lattice the wallet rounds a fee to is
/// `shekyl_economics::FEE_QUANTIZATION_MASK`, a constant; it does not
/// cross here.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeEstimateFactsFfi {
    pub fees: [u64; 3],
    pub fee_count: u8,
    pub reserved: [u8; 7],
}

const _: () = assert!(std::mem::size_of::<FeeEstimateFactsFfi>() == 32);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, fees) == 0);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, fee_count) == 24);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, reserved) == 25);

/// Twin of `shekyl_rpc_net_stats_facts` (RK-5a). Layout pinned by
/// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetStatsFactsFfi {
    /// Unix seconds; the core's start.
    pub start_time: u64,
    pub total_packets_in: u64,
    pub total_bytes_in: u64,
    pub total_packets_out: u64,
    pub total_bytes_out: u64,
}

/// Twin of `shekyl_rpc_connection_facts` (RK-5a).
///
/// Raw, absolute values: the wire's elapsed quantities and rates are derived
/// from these against the `now` that `shekyl_rpc_connections` reports beside
/// the list. Pointers have no seed value, so this one is pinned by **layout**
/// — size and every offset, asserted on both sides.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectionFactsFfi {
    /// `network_address::str()`: "host:port" for ipv4, the onion for tor.
    pub address: *const c_char,
    pub address_len: usize,
    /// `network_address::host_str()`: the host alone.
    pub host: *const c_char,
    pub host_len: usize,
    pub connection_id: [u8; 16],
    /// Unix seconds.
    pub started: u64,
    pub last_recv: u64,
    pub last_send: u64,
    /// Bytes, absolute.
    pub recv_count: u64,
    pub send_count: u64,
    /// Bytes/s, raw — the clamp to an integer is this side's job.
    pub current_speed_down: f64,
    pub current_speed_up: f64,
    pub port: u16,
    /// epee type id: 1 ipv4, 2 ipv6, 4 tor, …
    pub address_type: u8,
    pub incoming: u8,
    pub localhost: u8,
    pub local_ip: u8,
    /// The board's half only: the claim and the session's mode are chain
    /// sync's view (CS-5 §7).
    pub reserved: [u8; 2],
}

/// Twin of `shekyl_rpc_info_chain_facts` (RK-5c): `get_info`'s health,
/// identity, chain and economics operands, read for every caller. Every
/// member from the chain store is read under one chain lock and carries its
/// own tip (RK-D20). Layout pinned both directions by
/// `shekyl_rpc_info_chain_facts_rust_{fill,check}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InfoChainFactsFfi {
    /// Top block height + 1.
    pub chain_height: u64,
    pub top_hash: [u8; 32],
    pub difficulty_lo: u64,
    pub difficulty_hi: u64,
    pub cumulative_difficulty_lo: u64,
    pub cumulative_difficulty_hi: u64,
    pub difficulty_target: u64,
    /// Coinbases included.
    pub total_transactions: u64,
    pub block_weight_limit: u64,
    pub block_weight_median: u64,
    pub adjusted_time: u64,
    pub already_generated_coins: u64,
    pub total_burned: u64,
    pub tx_volume_count_sum: u64,
    pub tx_volume_blocks: u64,
    /// 0: the core has no target.
    pub core_target_height: u64,
    pub synchronized: u8,
    pub busy_syncing: u8,
    pub offline: u8,
    pub following_degraded: u8,
    /// `shekyl_version::PROTOCOL_VERSION`, a Rust constant (DC-Q20); the
    /// node supplies it in its identity.
    pub protocol_version: u8,
    pub reserved: [u8; 3],
}

/// Twin of `shekyl_rpc_info_status_facts` (RK-5c): read only for a caller
/// who is shown Status. The store's size is not here; it has its own read.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InfoStatusFactsFfi {
    pub start_time: u64,
    pub free_space: u64,
    pub alt_blocks_count: u64,
}

/// Twin of `shekyl_rpc_info_peers_facts` (RK-5c): read only for a caller who
/// is shown Peers.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InfoPeersFactsFfi {
    pub public_incoming_sockets: u64,
    pub public_outgoing_sockets: u64,
    pub tor_incoming_sockets: u64,
    pub tor_outgoing_sockets: u64,
}

// RK-5c layout pins, with their `static_assert` counterparts in
// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp`.
const _: () = assert!(std::mem::size_of::<InfoChainFactsFfi>() == 160);
const _: () = assert!(std::mem::align_of::<InfoChainFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(InfoChainFactsFfi, top_hash) == 8);
const _: () = assert!(std::mem::offset_of!(InfoChainFactsFfi, difficulty_lo) == 40);
const _: () = assert!(std::mem::offset_of!(InfoChainFactsFfi, core_target_height) == 144);
const _: () = assert!(std::mem::offset_of!(InfoChainFactsFfi, synchronized) == 152);
const _: () = assert!(std::mem::offset_of!(InfoChainFactsFfi, protocol_version) == 156);
const _: () = assert!(std::mem::offset_of!(InfoChainFactsFfi, reserved) == 157);
const _: () = assert!(std::mem::size_of::<InfoStatusFactsFfi>() == 24);
const _: () = assert!(std::mem::size_of::<InfoPeersFactsFfi>() == 32);

// RK-5a layout pins. `ConnectionFactsFfi` carries pointers, so there is
// no fill/check twin to catch a disagreement — these asserts and their
// `static_assert` counterparts in
// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` are the whole pin.
// The peer-list row is not a C type on this side: `shekyl-ffi`'s
// `ShekylRpcPeerFacts` is the export's layout, and the RPC reads owned
// rows (`crate::p2p_reads`).
const _: () = assert!(std::mem::size_of::<NetStatsFactsFfi>() == 40);

// `port` (u16), the four flag bytes and `reserved` fill the slot after
// `current_speed_up`, so the POD ends on `reserved`. A tail pad would be a
// field it does not have.
const _: () = assert!(std::mem::size_of::<ConnectionFactsFfi>() == 112);
const _: () = assert!(
    std::mem::offset_of!(ConnectionFactsFfi, reserved) + std::mem::size_of::<[u8; 2]>() == 112
);
const _: () = assert!(std::mem::align_of::<ConnectionFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address) == 0);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address_len) == 8);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, host) == 16);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, host_len) == 24);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, connection_id) == 32);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, started) == 48);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, last_recv) == 56);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, last_send) == 64);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, recv_count) == 72);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, send_count) == 80);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, current_speed_down) == 88);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, current_speed_up) == 96);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, port) == 104);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address_type) == 106);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, incoming) == 107);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, localhost) == 108);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, local_ip) == 109);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, reserved) == 110);

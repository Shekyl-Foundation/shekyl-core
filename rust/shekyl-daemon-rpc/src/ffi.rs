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

//! Raw C FFI declarations matching `src/rpc/core_rpc_ffi.h` and
//! `src/rpc/rpc_facts_ffi.h`.

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
    /// The peer's claimed blockchain height.
    pub height: u64,
    pub port: u16,
    /// `cryptonote_connection_context::state`.
    pub state: u8,
    /// epee type id: 1 ipv4, 2 ipv6, 4 tor, …
    pub address_type: u8,
    pub incoming: u8,
    pub localhost: u8,
    pub local_ip: u8,
    /// 1 when `height` and `state` were read. 0 means those two are
    /// unknown.
    pub claims_known: u8,
}

/// Twin of `shekyl_rpc_sync_span_facts` (RK-5a). Pinned by layout.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyncSpanFactsFfi {
    /// `network_address::str()` of the span's origin.
    pub remote_address: *const c_char,
    pub remote_address_len: usize,
    pub start_block_height: u64,
    pub nblocks: u64,
    /// Bytes held for this span.
    pub size: u64,
    pub connection_id: [u8; 16],
    /// Bytes/s.
    pub rate: f32,
    /// 0..1; the wire carries 100x this.
    pub speed_fraction: f32,
    /// Whether the span's blocks have arrived, as opposed to being requested
    /// and still outstanding.
    pub filled: u8,
    pub reserved: [u8; 7],
}

/// Twin of `shekyl_rpc_peer_facts` (RK-5a), now `shekyl-ffi`'s
/// `ShekylRpcPeerFacts`, exported from the Rust peer lists. Pinned by
/// layout on both sides (24 bytes). No `last_seen`: the lists carry no
/// clock (3.51).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PeerFactsFfi {
    /// Already resolved per address arm by the adapter — the ip string for
    /// ipv4, the bare host for ipv6, the whole `host:port` for Tor.
    pub host: *const c_char,
    pub host_len: usize,
    /// The ipv4 address with its four octets in **network** order, as
    /// `ipv4_network_address::ip()` returns it; 0 for every other arm.
    pub ip: u32,
    /// 0 for the address arms that carry none.
    pub port: u16,
    /// 1 = white list, 0 = gray.
    pub white: u8,
    /// Filled unconditionally; applying `include_blocked` is this side's job.
    pub blocked: u8,
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
    /// `SHEKYL_PROTOCOL_VERSION`, which only C++ defines.
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

// RK-5a layout pins. `ConnectionFactsFfi`, `SyncSpanFactsFfi` and
// `PeerFactsFfi` carry pointers, so there is no fill/check twin to catch a
// disagreement — these asserts and their `static_assert` counterparts in
// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` are the whole pin.
const _: () = assert!(std::mem::size_of::<NetStatsFactsFfi>() == 40);

// `port` (u16) and the six trailing `u8`s fill the slot after `height`,
// so the POD ends on `claims_known`. A tail pad would be a field it does
// not have.
const _: () = assert!(std::mem::size_of::<ConnectionFactsFfi>() == 120);
const _: () = assert!(
    std::mem::offset_of!(ConnectionFactsFfi, claims_known) + std::mem::size_of::<u8>() == 120
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
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, height) == 104);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, port) == 112);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, state) == 114);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address_type) == 115);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, incoming) == 116);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, localhost) == 117);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, local_ip) == 118);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, claims_known) == 119);

const _: () = assert!(std::mem::size_of::<SyncSpanFactsFfi>() == 72);
const _: () = assert!(std::mem::align_of::<SyncSpanFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, remote_address) == 0);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, remote_address_len) == 8);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, start_block_height) == 16);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, nblocks) == 24);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, size) == 32);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, connection_id) == 40);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, rate) == 56);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, speed_fraction) == 60);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, filled) == 64);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, reserved) == 65);

// The twin is `shekyl-ffi`'s `ShekylRpcPeerFacts` and the C++
// `shekyl_rpc_peer_facts` in `shekyl_ffi.h`, each pinned to 24 bytes.
const _: () = assert!(std::mem::size_of::<PeerFactsFfi>() == 24);
const _: () = assert!(std::mem::align_of::<PeerFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, host) == 0);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, host_len) == 8);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, ip) == 16);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, port) == 20);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, white) == 22);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, blocked) == 23);

extern "C" {
    pub fn shekyl_rpc_net_stats(h: *mut CoreRpcHandle, out: *mut NetStatsFactsFfi) -> i32;
    /// Fills a C++-owned view of the live p2p connections plus the single
    /// instant they were read at; release the owner with
    /// `shekyl_rpc_connections_free`.
    pub fn shekyl_rpc_connections(
        h: *mut CoreRpcHandle,
        out_now: *mut u64,
        out: *mut *const ConnectionFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_connections_free(owner: *mut std::ffi::c_void);
    /// The block-download queue; release the owner with
    /// `shekyl_rpc_sync_spans_free`.
    pub fn shekyl_rpc_sync_spans(
        h: *mut CoreRpcHandle,
        out: *mut *const SyncSpanFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_sync_spans_free(owner: *mut std::ffi::c_void);
    /// White then gray peerlist entries in one array, discriminated by
    /// `white`, from the Rust peer lists (`shekyl-ffi`); release the owner
    /// with `shekyl_rpc_peer_list_free`. No core handle.
    pub fn shekyl_rpc_peer_list(
        public_only: u8,
        out: *mut *const PeerFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_peer_list_free(owner: *mut std::ffi::c_void);
    /// How many addresses the clearnet white and gray lists hold, from the
    /// Rust peer lists (`shekyl-ffi`). No core handle.
    pub fn shekyl_rpc_peerlist_sizes(out_white: *mut u64, out_gray: *mut u64) -> i32;
}

/// [`shekyl_seam_session_counts`] wrote the counts.
pub const SHEKYL_SEAM_COUNT_OK: i32 = 0;
/// No hub is bound in this process: there are no counts, which is not zeros.
pub const SHEKYL_SEAM_COUNT_ERR_NO_HUB: i32 = -2;

/// Twin of `shekyl-ffi`'s `ShekylSeamSessionCounts`: the board's handshaken
/// sessions per direction, over one snapshot. The layout is asserted on
/// both sides.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeamSessionCountsFfi {
    /// Handshaken sessions this node opened, on every connector.
    pub outbound: u64,
    /// Handshaken sessions opened to this node, on every connector.
    pub inbound: u64,
}

const _: () = {
    assert!(std::mem::offset_of!(SeamSessionCountsFfi, outbound) == 0);
    assert!(std::mem::offset_of!(SeamSessionCountsFfi, inbound) == 8);
    assert!(std::mem::size_of::<SeamSessionCountsFfi>() == 16);
};

extern "C" {
    /// The seam board's session counts, from one snapshot, written through
    /// `out`.
    ///
    /// **Rust on both sides.** The board is `shekyl-ffi`'s (it owns the
    /// process hub), this crate does not depend on that one, and the two
    /// share the daemon's link image, so the read crosses as a C symbol
    /// without visiting C++. The codes and the struct are restated above
    /// because the definitions cannot be imported; each side asserts the
    /// layout and `shekyl-ffi`'s own test pins the codes.
    pub fn shekyl_seam_session_counts(out: *mut SeamSessionCountsFfi) -> i32;
}

extern "C" {
    pub fn core_rpc_ffi_create(rpc_server_ptr: *mut std::ffi::c_void) -> *mut CoreRpcHandle;
    pub fn core_rpc_ffi_destroy(h: *mut CoreRpcHandle);

    /// §55: relay stem-outcome tallies as a JSON array. Caller frees.
    ///
    /// **Transit, not structure** — the tallies are Rust's (the relay zone
    /// owns them) and this consumer is Rust; the hop out to C++ and back
    /// exists only because C++ `net_node` owns the zone handles' lifetime.
    /// It disappears with the p2p migration, at which point this crate reads
    /// the zone directly. Do not build on the round trip. Deleter: RD, with
    /// `levin_notify` (`DRS_X_STORE_FLIP.md` FLIP-Q5).
    pub fn core_rpc_ffi_stem_tallies(h: *mut CoreRpcHandle) -> *mut std::os::raw::c_char;

    pub fn core_rpc_ffi_free_string(s: *mut c_char);

}

/// Link-time stubs for the crate's **unit** tests only.
///
/// The lib test binary links no C++ archive, and GNU ld resolves every
/// symbol a retained function references — the console's remote-arm tests
/// reach `FfiP2pFacts` through the same function as the live arm, so the
/// five symbols that path names must exist. Each stub is the "no core here"
/// answer: a null handle or the NULL error code. Only symbols a unit test
/// actually retains are stubbed; a new one shows up as a link error, never
/// as a silently-stubbed production path. Integration tests (`tests/*.rs`)
/// link the lib without `cfg(test)` and see none of this.
#[cfg(test)]
mod unit_test_link_stubs {
    use super::*;

    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_free_string(_s: *mut std::os::raw::c_char) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_net_stats(
        _h: *mut CoreRpcHandle,
        _out: *mut NetStatsFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_connections(
        _h: *mut CoreRpcHandle,
        _out_now: *mut u64,
        _out: *mut *const ConnectionFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_connections_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_sync_spans(
        _h: *mut CoreRpcHandle,
        _out_stripe: *mut u32,
        _out: *mut *const SyncSpanFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_sync_spans_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_peer_list(
        _public_only: u8,
        _out: *mut *const PeerFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_peer_list_free(_owner: *mut std::ffi::c_void) {}
    /// "No hub here", never counts: a stub that wrote zeros would let a
    /// handler's test read a process with no p2p layer as a node with no
    /// peers, which is the answer the real export exists to refuse.
    #[no_mangle]
    pub extern "C" fn shekyl_seam_session_counts(_out: *mut SeamSessionCountsFfi) -> i32 {
        SHEKYL_SEAM_COUNT_ERR_NO_HUB
    }
    /// "No lists here": a stub that wrote zeros would let a handler's test
    /// read a process with no dialer as a node with empty lists.
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_peerlist_sizes(_out_white: *mut u64, _out_gray: *mut u64) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_create(_p: *mut std::ffi::c_void) -> *mut CoreRpcHandle {
        std::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_destroy(_h: *mut CoreRpcHandle) {}
}

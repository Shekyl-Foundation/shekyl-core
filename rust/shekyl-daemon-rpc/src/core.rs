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

//! The sync-half facts handle: net stats, connections, sync spans, and
//! stem tallies. Chain and pool reads go through the store.

use crate::ffi;
use std::ffi::CStr;

/// Wrapper around the opaque `core_rpc_handle` pointer.
/// The handle borrows the daemon's `rpc_subject` (core and the p2p server).
///
/// Methods are `&self`. The reads they make are the sync half, and Axum
/// dispatches the blocking ones via `spawn_blocking`.
pub struct CoreRpc {
    handle: *mut ffi::CoreRpcHandle,
}

// The sync-half reads do not share mutable state through this handle.
unsafe impl Send for CoreRpc {}
unsafe impl Sync for CoreRpc {}

/// One request slot's answer from `shekyl_rpc_transactions`, copied out of
/// the C++ views before the owner is released.
///
/// Not a wire type: which of `pruned` / `prunable` the reply shows, and in
/// what form, is the handler's `(split, prune, decode_as_json)` matrix. This
/// is what the store held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxSlot {
    /// Neither the chain nor the pool had it.
    Missed,
    /// Not in the chain, and the pool is retired: whether the pool holds it
    /// has no answer. Only the Rust store backend retires its pool.
    PoolUnavailable,
    /// Found in a block.
    Chain {
        pruned: Vec<u8>,
        prunable: Vec<u8>,
        prunable_hash: [u8; 32],
        block_height: u64,
        block_timestamp: u64,
        output_indices: Vec<u64>,
        /// The store holds no verification data for it.
        pruned_flag: bool,
    },
    /// Found in the mempool.
    Pool {
        pruned: Vec<u8>,
        prunable: Vec<u8>,
        prunable_hash: [u8; 32],
        double_spend_seen: bool,
        relayed: bool,
        /// `None` where the pool keeps no receive time (the Rust pool, S7).
        received_timestamp: Option<u64>,
    },
}

/// One live p2p connection, copied out of the C++ view before its owner is
/// released.
///
/// Raw and absolute, deliberately: the wire's elapsed times and rates are
/// derived from these against the one `now` that came back beside the list,
/// so a connection's reported lifetime and the divisor behind its own
/// averages cannot come from different seconds.
// No `Eq`: the raw speeds are `f64`, and they are raw on purpose.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionFacts {
    /// `network_address::str()`: "host:port" for ipv4, the onion for tor.
    pub address: String,
    /// `network_address::host_str()`: the host alone.
    pub host: String,
    pub connection_id: [u8; 16],
    /// Unix seconds.
    pub started: u64,
    pub last_recv: u64,
    pub last_send: u64,
    /// Bytes, absolute.
    pub recv_count: u64,
    pub send_count: u64,
    /// Bytes/s, raw. Not yet an integer: `static_cast<uint64_t>` of a rate
    /// estimator's output is undefined for a NaN, an infinity, a negative or
    /// an out-of-range value, so the truncation happens here, clamped.
    pub current_speed_down: f64,
    pub current_speed_up: f64,
    /// The peer's claimed blockchain height.
    pub height: u64,
    pub port: u16,
    /// `cryptonote_connection_context::state`, unmapped — the name it renders
    /// to is the wire projection's business. Meaningful when `claims_known`.
    pub state: u8,
    /// The strand read height and state. False means those two have not
    /// landed and must not be rendered as zeroes.
    pub claims_known: bool,
    /// epee type id: 1 ipv4, 2 ipv6, 4 tor, …
    pub address_type: u8,
    pub incoming: bool,
    pub localhost: bool,
    pub local_ip: bool,
}

/// The live connections plus the single instant they were read at.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionsSnapshot {
    /// Unix seconds; one clock read for the whole list.
    pub now: u64,
    pub connections: Vec<ConnectionFacts>,
}

/// One span in the block-download queue, copied out of the C++ view.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncSpanFacts {
    /// `network_address::str()` of the span's origin.
    pub remote_address: String,
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
    pub filled: bool,
}

/// The download queue.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncSpansSnapshot {
    pub spans: Vec<SyncSpanFacts>,
}

/// A P2P read from a daemon that may have been started offline
/// (Rick, 2026-10-14). [`P2pRead::Offline`] carries nothing: the daemon has no
/// peers, connections or lists by configuration, and nothing stands in for
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pRead<T> {
    /// P2P runs; what was read.
    Running(T),
    /// The daemon was started offline.
    Offline,
}

/// Offline, when configure recorded it. The peer methods return this
/// before any dialer call. `None` when the daemon is online, so the
/// caller asks the dialer.
fn offline_answer<T>() -> Option<Result<P2pRead<T>, i32>> {
    if crate::ffi_exports::offline() {
        Some(Ok(P2pRead::Offline))
    } else {
        None
    }
}

/// One peerlist entry, copied out of the Rust peer lists' export. No
/// clock: the lists carry none (3.55). Named apart from
/// [`crate::info_facts::PeerFacts`], `get_info`'s Peers state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// Already resolved per address arm by the adapter.
    pub host: String,
    /// The ipv4 address packed as `epee`'s `ipv4_network_address::ip()`
    /// returns it: the four octets in **network** order. On a little-endian
    /// host that means 10.32.0.7 is `0x0700_200a`, which is the value in the
    /// oracle vector beside the host string it renders to. Zero for every
    /// non-ipv4 arm.
    pub ip: u32,
    /// 0 for the address arms that carry none.
    pub port: u16,
    /// Which list it came from.
    pub white: bool,
    /// Whether the host is currently blocked; applying `include_blocked` is
    /// this side's job.
    pub blocked: bool,
}

/// Copy a C++-owned string view into an owned `String`.
///
/// Lossy, as the other string copies at this seam are (`block_at`'s `json`,
/// `tx_to_json`): these are addresses and host names produced by epee's own
/// formatters, so a non-UTF-8 byte would be a fault in the formatter rather
/// than data a caller supplied, and there is no reply shape that could carry
/// it faithfully anyway — the wire is JSON.
///
/// # Safety
///
/// `ptr` must be null or point to `len` readable bytes that outlive the call.
unsafe fn borrowed_string(ptr: *const std::os::raw::c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr.cast::<u8>(), len)).into_owned()
}

/// Project one FFI entry onto its [`TxSlot`], or `None` when `where_found`
/// carries a discriminator the contract does not define.
///
/// Split out of the `unsafe` walk because that walk cannot be driven without a
/// live facts handle, and this is the part with a decision in it. The
/// pointer arithmetic stays at the call site; what crosses here is already
/// owned data.
///
/// `None` rather than a silent `Missed`: the contract permits 0/1/2 and nothing
/// more, so a fourth value is the export breaking it. Answering "not found"
/// would report success about a transaction this daemon may well hold — an ABI
/// violation rendered as a fact about the caller's request.
#[cfg(test)]
fn slot_of(
    e: &ffi::TxEntryFfi,
    pruned: Vec<u8>,
    prunable: Vec<u8>,
    output_indices: Vec<u64>,
) -> Option<TxSlot> {
    match e.where_found {
        0 => Some(TxSlot::Missed),
        1 => Some(TxSlot::Chain {
            pruned,
            prunable,
            prunable_hash: e.prunable_hash,
            block_height: e.block_height,
            block_timestamp: e.block_timestamp,
            output_indices,
            pruned_flag: e.pruned_flag != 0,
        }),
        2 => Some(TxSlot::Pool {
            pruned,
            prunable,
            prunable_hash: e.prunable_hash,
            double_spend_seen: e.double_spend_seen != 0,
            relayed: e.relayed != 0,
            received_timestamp: Some(e.received_timestamp),
        }),
        _ => None,
    }
}

impl CoreRpc {
    /// Wrap the daemon's `rpc_subject`.
    ///
    /// # Safety
    /// `subject_ptr` must point to a live `rpc_subject` that outlives this
    /// value, or be null. A subject missing either pointer yields `None`.
    pub unsafe fn from_raw(rpc_server_ptr: *mut std::ffi::c_void) -> Option<Self> {
        let handle = unsafe { ffi::core_rpc_ffi_create(rpc_server_ptr) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// §55: relay stem-outcome tallies as a JSON array string.
    ///
    /// The counts live in the relay zones. This is the readout while C++
    /// owns their lifetime.
    pub fn stem_tallies(&self) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        unsafe { consume_c_string(ffi::core_rpc_ffi_stem_tallies(self.handle)) }
    }

    /// Network throttle counters and the core's start time
    /// (`shekyl_rpc_net_stats`); `Err(code)` on a non-OK return.
    pub fn net_stats(&self) -> Result<ffi::NetStatsFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::NetStatsFactsFfi {
            start_time: 0,
            total_packets_in: 0,
            total_bytes_in: 0,
            total_packets_out: 0,
            total_bytes_out: 0,
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe { ffi::shekyl_rpc_net_stats(self.handle, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// The live p2p connections (`shekyl_rpc_connections`), copied out of the
    /// C++-owned view before it is released.
    pub fn connections(&self) -> Result<ConnectionsSnapshot, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::ConnectionFactsFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut now: u64 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; the four out pointers are valid; on OK the
        // view is valid until `shekyl_rpc_connections_free(owner)`, and every
        // copy below is taken before that call.
        unsafe {
            let rc = ffi::shekyl_rpc_connections(
                self.handle,
                &raw mut now,
                &raw mut rows,
                &raw mut len,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let mut connections = Vec::with_capacity(len);
            if !rows.is_null() {
                for e in std::slice::from_raw_parts(rows, len) {
                    connections.push(ConnectionFacts {
                        address: borrowed_string(e.address, e.address_len),
                        host: borrowed_string(e.host, e.host_len),
                        connection_id: e.connection_id,
                        started: e.started,
                        last_recv: e.last_recv,
                        last_send: e.last_send,
                        recv_count: e.recv_count,
                        send_count: e.send_count,
                        current_speed_down: e.current_speed_down,
                        current_speed_up: e.current_speed_up,
                        height: e.height,
                        port: e.port,
                        state: e.state,
                        claims_known: e.claims_known != 0,
                        address_type: e.address_type,
                        incoming: e.incoming != 0,
                        localhost: e.localhost != 0,
                        local_ip: e.local_ip != 0,
                    });
                }
            }
            ffi::shekyl_rpc_connections_free(owner);
            Ok(ConnectionsSnapshot { now, connections })
        }
    }

    /// The block-download queue (`shekyl_rpc_sync_spans`), copied out before
    /// the owner is released.
    pub fn sync_spans(&self) -> Result<SyncSpansSnapshot, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::SyncSpanFactsFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: as `connections` above.
        unsafe {
            let rc = ffi::shekyl_rpc_sync_spans(
                self.handle,
                &raw mut rows,
                &raw mut len,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let mut spans = Vec::with_capacity(len);
            if !rows.is_null() {
                for e in std::slice::from_raw_parts(rows, len) {
                    spans.push(SyncSpanFacts {
                        remote_address: borrowed_string(e.remote_address, e.remote_address_len),
                        start_block_height: e.start_block_height,
                        nblocks: e.nblocks,
                        size: e.size,
                        connection_id: e.connection_id,
                        rate: e.rate,
                        speed_fraction: e.speed_fraction,
                        filled: e.filled != 0,
                    });
                }
            }
            ffi::shekyl_rpc_sync_spans_free(owner);
            Ok(SyncSpansSnapshot { spans })
        }
    }

    /// The peerlist (`shekyl_rpc_peer_list`, exported by `shekyl-ffi` from
    /// the Rust peer lists), white entries then gray, copied out before the
    /// owner is released. No core handle: the lists are the dialer's.
    pub fn peer_list(&self, public_only: bool) -> Result<P2pRead<Vec<PeerEntry>>, i32> {
        if let Some(offline) = offline_answer() {
            return offline;
        }
        let mut rows: *const ffi::PeerFactsFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: as `connections` above.
        unsafe {
            let rc = ffi::shekyl_rpc_peer_list(
                u8::from(public_only),
                &raw mut rows,
                &raw mut len,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let mut peers = Vec::with_capacity(len);
            if !rows.is_null() {
                for e in std::slice::from_raw_parts(rows, len) {
                    peers.push(PeerEntry {
                        host: borrowed_string(e.host, e.host_len),
                        ip: e.ip,
                        port: e.port,
                        white: e.white != 0,
                        blocked: e.blocked != 0,
                    });
                }
            }
            ffi::shekyl_rpc_peer_list_free(owner);
            Ok(P2pRead::Running(peers))
        }
    }

    /// How many addresses the clearnet white and gray lists hold
    /// (`shekyl_rpc_peerlist_sizes`, exported by `shekyl-ffi` from the Rust
    /// peer lists), as `(white, gray)`. No core handle: the lists are the
    /// dialer's. [`P2pRead::Offline`] when configure recorded offline,
    /// before any dialer call.
    pub fn peerlist_sizes() -> Result<P2pRead<(u64, u64)>, i32> {
        if let Some(offline) = offline_answer() {
            return offline;
        }
        let mut white: u64 = 0;
        let mut gray: u64 = 0;
        // SAFETY: two valid out pointers.
        let rc = unsafe { ffi::shekyl_rpc_peerlist_sizes(&raw mut white, &raw mut gray) };
        match rc {
            ffi::SHEKYL_RPC_FACTS_OK => Ok(P2pRead::Running((white, gray))),
            fault => Err(fault),
        }
    }

    /// Whether P2P runs. Offline is the bit configure recorded. Anything
    /// else is running: the RPC is served only after configure, and a
    /// process that never configured still asks the dialer rather than
    /// inventing an offline state.
    pub fn p2p_state() -> Result<P2pRead<()>, i32> {
        offline_answer().unwrap_or(Ok(P2pRead::Running(())))
    }
}

impl Drop for CoreRpc {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::core_rpc_ffi_destroy(self.handle) };
        }
    }
}

#[cfg(test)]
impl CoreRpc {
    /// Null-handle stand-in reserved for future router tests that never reach FFI.
    #[allow(dead_code)]
    pub(crate) fn null_for_router_tests() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }
}

/// Take ownership of a C-allocated string, copy it into a Rust String, and free the C side.
unsafe fn consume_c_string(ptr: *mut std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::core_rpc_ffi_free_string(ptr) };
    Some(s)
}

#[cfg(test)]
mod slot_tests {
    use super::*;

    fn entry(where_found: u8) -> ffi::TxEntryFfi {
        ffi::TxEntryFfi {
            pruned: std::ptr::null(),
            pruned_len: 0,
            prunable: std::ptr::null(),
            prunable_len: 0,
            output_indices: std::ptr::null(),
            output_indices_len: 0,
            block_height: 3,
            block_timestamp: 1_700_000_000,
            received_timestamp: 1_700_000_001,
            prunable_hash: [0x5A; 32],
            where_found,
            pruned_flag: 0,
            double_spend_seen: 1,
            relayed: 1,
            reserved: [0; 4],
        }
    }

    /// The three values the contract defines map to their slots.
    #[test]
    fn defined_where_found_values_map_to_their_slots() {
        assert!(matches!(
            slot_of(&entry(0), Vec::new(), Vec::new(), Vec::new()),
            Some(TxSlot::Missed)
        ));
        assert!(matches!(
            slot_of(&entry(1), Vec::new(), Vec::new(), vec![7]),
            Some(TxSlot::Chain { .. })
        ));
        assert!(matches!(
            slot_of(&entry(2), Vec::new(), Vec::new(), Vec::new()),
            Some(TxSlot::Pool { .. })
        ));
    }

    /// **A fourth value is the export breaking its contract, not a miss.**
    ///
    /// Mapping it to `Missed` would answer the caller successfully — "no such
    /// transaction" — about one this daemon may well hold: an ABI violation
    /// rendered as a fact about their request. `None` is what makes the caller
    /// free the owner and raise an internal facts error instead.
    #[test]
    fn an_undefined_where_found_is_refused_not_read_as_missed() {
        for undefined in [3u8, 4, 255] {
            assert!(
                slot_of(&entry(undefined), Vec::new(), Vec::new(), Vec::new()).is_none(),
                "where_found={undefined} is outside the contract and must not \
                 project to a slot"
            );
        }
    }
}

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

//! Thread-safe wrapper over the C++ core_rpc_server FFI handle.

use crate::ffi;
use std::ffi::{CStr, CString};

/// Wrapper around the opaque `core_rpc_handle` pointer.
/// The handle borrows an existing `core_rpc_server` owned by the C++ daemon.
///
/// All methods are `&self` because the underlying C++ handlers are already
/// designed for concurrent access (epee's thread pool model). The FFI calls
/// block on the C++ side, so Axum dispatches them via `spawn_blocking`.
pub struct CoreRpc {
    handle: *mut ffi::CoreRpcHandle,
}

// The C++ core_rpc_server handlers use internal locks for thread safety.
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
        received_timestamp: u64,
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
    pub support_flags: u32,
    pub pruning_seed: u32,
    pub port: u16,
    /// `cryptonote_connection_context::state`, unmapped — the name it renders
    /// to is the wire projection's business.
    pub state: u8,
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

/// The download queue plus the stripe this node wants next.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncSpansSnapshot {
    /// A **stripe**, not a seed. The wire field it feeds is named
    /// `next_needed_pruning_seed`, an inherited misnomer carried on purpose.
    pub next_needed_pruning_stripe: u32,
    pub spans: Vec<SyncSpanFacts>,
}

/// One peerlist entry, copied out of the C++ view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFacts {
    /// Already resolved per address arm by the adapter.
    pub host: String,
    pub last_seen: u64,
    /// The ipv4 address packed as `epee`'s `ipv4_network_address::ip()`
    /// returns it: the four octets in **network** order. On a little-endian
    /// host that means 10.32.0.7 is `0x0700_200a`, which is the value in the
    /// oracle vector beside the host string it renders to. Zero for every
    /// non-ipv4 arm.
    pub ip: u32,
    pub pruning_seed: u32,
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
unsafe fn borrowed_string(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
}

/// Project one FFI entry onto its [`TxSlot`], or `None` when `where_found`
/// carries a discriminator the contract does not define.
///
/// Split out of the `unsafe` walk because that walk cannot be driven without a
/// live `core_rpc_server`, and this is the part with a decision in it. The
/// pointer arithmetic stays at the call site; what crosses here is already
/// owned data.
///
/// `None` rather than a silent `Missed`: the contract permits 0/1/2 and nothing
/// more, so a fourth value is the export breaking it. Answering "not found"
/// would report success about a transaction this daemon may well hold — an ABI
/// violation rendered as a fact about the caller's request.
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
            received_timestamp: e.received_timestamp,
        }),
        _ => None,
    }
}

impl CoreRpc {
    /// Wrap a raw `core_rpc_server*` obtained from C++.
    ///
    /// # Safety
    /// `rpc_server_ptr` must point to a live, fully-initialized `core_rpc_server`
    /// that outlives this `CoreRpc`.
    pub unsafe fn from_raw(rpc_server_ptr: *mut std::ffi::c_void) -> Option<Self> {
        let handle = unsafe { ffi::core_rpc_ffi_create(rpc_server_ptr) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// Dispatch a JSON REST endpoint (e.g. "/get_info").
    pub fn json_endpoint(&self, uri: &str, body: &str) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        let c_uri = CString::new(uri).ok()?;
        let c_body = CString::new(body).ok()?;
        unsafe {
            let ptr = ffi::core_rpc_ffi_json_endpoint(self.handle, c_uri.as_ptr(), c_body.as_ptr());
            consume_c_string(ptr)
        }
    }

    /// §55: relay stem-outcome tallies as a JSON array string.
    ///
    /// Not routed through [`Self::json_endpoint`] because the data does not
    /// live in `core_rpc_server` — it lives in the relay zones, and this is
    /// the shortest path to it while C++ owns their lifetime.
    pub fn stem_tallies(&self) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        unsafe { consume_c_string(ffi::core_rpc_ffi_stem_tallies(self.handle)) }
    }

    /// Raw handle for the submit shims (`crate::submit::ffi_shim`), which
    /// call the `shekyl_submit_*` FFI directly rather than through the
    /// string-dispatch surface above.
    pub(crate) fn raw_handle(&self) -> *mut ffi::CoreRpcHandle {
        self.handle
    }

    /// Chain-tip facts (`shekyl_rpc_chain_tip`); `Err(code)` on a non-OK
    /// return, including a null handle.
    pub fn chain_tip(&self) -> Result<ffi::ChainTipFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::ChainTipFactsFfi {
            chain_height: 0,
            top_hash: [0; 32],
            target_height: 0,
            synchronized: 0,
            release_build: 0,
            reserved: [0; 6],
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe { ffi::shekyl_rpc_chain_tip(self.handle, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// Block hash at `height` plus the tip as of the same read
    /// (`shekyl_rpc_block_hash_at`); `Err(code)` on a non-OK return.
    pub fn block_hash_at(&self, height: u64) -> Result<ffi::BlockHashFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::BlockHashFactsFfi {
            hash: [0; 32],
            chain_height: 0,
            found: 0,
            reserved: [0; 7],
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe { ffi::shekyl_rpc_block_hash_at(self.handle, height, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// The block-header projection, by hash or by height
    /// (`shekyl_rpc_block_header_at`); `Err(code)` on a non-OK return.
    ///
    /// `block_hash` selects the lookup, exactly as [`Self::block_at`]'s does.
    /// A hash reaches alt blocks, so `orphan_status` is a real value on that
    /// path and a constant on the other.
    pub fn block_header_at(
        &self,
        block_hash: Option<&[u8; 32]>,
        height: u64,
        fill_pow_hash: bool,
    ) -> Result<ffi::BlockHeaderFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::BlockHeaderFactsFfi::zeroed();
        // SAFETY: live handle; `pod` is a valid out pointer; `block_hash`, when
        // given, points at 32 readable bytes that outlive the call.
        let rc = unsafe {
            ffi::shekyl_rpc_block_header_at(
                self.handle,
                block_hash.map_or(std::ptr::null(), |h| h.as_ptr()),
                height,
                u8::from(fill_pow_hash),
                &raw mut pod,
            )
        };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
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
                        support_flags: e.support_flags,
                        pruning_seed: e.pruning_seed,
                        port: e.port,
                        state: e.state,
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

    /// The block-download queue and the next needed pruning stripe
    /// (`shekyl_rpc_sync_spans`), copied out before the owner is released.
    pub fn sync_spans(&self) -> Result<SyncSpansSnapshot, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::SyncSpanFactsFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut stripe: u32 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: as `connections` above.
        unsafe {
            let rc = ffi::shekyl_rpc_sync_spans(
                self.handle,
                &raw mut stripe,
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
            Ok(SyncSpansSnapshot {
                next_needed_pruning_stripe: stripe,
                spans,
            })
        }
    }

    /// The peerlist (`shekyl_rpc_peer_list`), white entries then gray, copied
    /// out before the owner is released.
    pub fn peer_list(&self, public_only: bool) -> Result<Vec<PeerFacts>, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::PeerFactsFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: as `connections` above.
        unsafe {
            let rc = ffi::shekyl_rpc_peer_list(
                self.handle,
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
                    peers.push(PeerFacts {
                        host: borrowed_string(e.host, e.host_len),
                        last_seen: e.last_seen,
                        ip: e.ip,
                        pruning_seed: e.pruning_seed,
                        port: e.port,
                        white: e.white != 0,
                        blocked: e.blocked != 0,
                    });
                }
            }
            ffi::shekyl_rpc_peer_list_free(owner);
            Ok(peers)
        }
    }

    /// The two compile-time peerlist capacities
    /// (`shekyl_rpc_peerlist_limits`), as `(white, gray)`.
    ///
    /// Not restated in Rust: a duplicated constant is drift waiting to
    /// happen, and these are p2p configuration the C++ owns.
    pub fn peerlist_limits() -> (u32, u32) {
        let mut white: u32 = 0;
        let mut gray: u32 = 0;
        // SAFETY: two valid out pointers; the export takes no handle and
        // writes two compile-time constants.
        unsafe { ffi::shekyl_rpc_peerlist_limits(&raw mut white, &raw mut gray) };
        (white, gray)
    }

    /// The stripe label `sync_info` prints beside a span
    /// (`shekyl_rpc_span_pruning_seed`).
    ///
    /// Handle-free, like [`Self::peerlist_limits`], and for the same reason:
    /// `shekyld sync_info` renders against a *remote* daemon with no core to
    /// ask, so a renderer's C++ constants must be reachable without one.
    pub fn span_pruning_seed(start_block_height: u64) -> u32 {
        // SAFETY: a pure function of its argument; no handle, no allocation.
        unsafe { ffi::shekyl_rpc_span_pruning_seed(start_block_height) }
    }

    /// Hard-fork voting info (`shekyl_rpc_hard_fork_info`). `requested_version`
    /// of 0 means "the next fork"; the export resolves it and reports which.
    pub fn hard_fork_info(&self, requested_version: u8) -> Result<ffi::HardForkFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::HardForkFactsFfi {
            earliest_height: 0,
            window: 0,
            votes: 0,
            threshold: 0,
            state: 0,
            queried_version: 0,
            active_version: 0,
            voting: 0,
            enabled: 0,
            reserved: [0; 4],
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc =
            unsafe { ffi::shekyl_rpc_hard_fork_info(self.handle, requested_version, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// The dynamic base-fee estimate (`shekyl_rpc_fee_estimate`).
    pub fn fee_estimate(&self, grace_blocks: u64) -> Result<ffi::FeeEstimateFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::FeeEstimateFactsFfi {
            fees: [0; 4],
            quantization_mask: 0,
            fee_count: 0,
            reserved: [0; 7],
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe { ffi::shekyl_rpc_fee_estimate(self.handle, grace_blocks, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// The hard-fork schedule (`shekyl_rpc_hardforks`), copied out of the
    /// C++-owned view before it is released.
    pub fn hardforks(&self) -> Result<Vec<ffi::HardforkEntryFfi>, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::HardforkEntryFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; the three out pointers are valid; on OK the
        // view is valid until `shekyl_rpc_hardforks_free(owner)`.
        unsafe {
            let rc =
                ffi::shekyl_rpc_hardforks(self.handle, &raw mut rows, &raw mut len, &raw mut owner);
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let copied = if rows.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(rows, len).to_vec()
            };
            ffi::shekyl_rpc_hardforks_free(owner);
            Ok(copied)
        }
    }

    /// A whole block by hash, or by height when `block_hash` is `None`.
    ///
    /// Returns the header POD alongside owned copies of the three
    /// variable-length payloads. The C++ owner is released **in this
    /// function**, before any of the fallible work above it can return early
    /// — the reason the copies are made rather than the borrows returned.
    #[allow(clippy::type_complexity)]
    pub fn block_at(
        &self,
        block_hash: Option<&[u8; 32]>,
        height: u64,
        fill_pow_hash: bool,
    ) -> Result<(ffi::BlockHeaderFactsFfi, Vec<u8>, String, Vec<[u8; 32]>), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut header = ffi::BlockHeaderFactsFfi::zeroed();
        let mut payload = ffi::BlockPayloadFfi::default();
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; the out pointers are valid for the call. On OK
        // with a found block the payload borrows memory owned by `owner`,
        // which is released below before this function returns — every copy
        // is taken first, and nothing fallible runs between.
        unsafe {
            let rc = ffi::shekyl_rpc_block_at(
                self.handle,
                block_hash.map_or(std::ptr::null(), |h| h.as_ptr()),
                height,
                u8::from(fill_pow_hash),
                &raw mut header,
                &raw mut payload,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let blob = if payload.blob.is_null() || payload.blob_len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(payload.blob, payload.blob_len).to_vec()
            };
            let json = if payload.json.is_null() || payload.json_len == 0 {
                String::new()
            } else {
                String::from_utf8_lossy(std::slice::from_raw_parts(
                    payload.json.cast::<u8>(),
                    payload.json_len,
                ))
                .into_owned()
            };
            // `len * 32` is the length handed to `from_raw_parts`, where a
            // wrong value is immediate UB rather than a bad answer — so it is
            // checked, and the pointer is checked before anything is sized
            // from the length. Nothing here returns early: the owner must be
            // released on every path out, so the verdict comes after the free.
            let tx_bytes = payload.tx_hashes_len.checked_mul(32);
            let tx_hashes: Vec<[u8; 32]> = match tx_bytes {
                Some(n) if n > 0 && !payload.tx_hashes.is_null() => {
                    std::slice::from_raw_parts(payload.tx_hashes, n)
                        .chunks_exact(32)
                        .map(|chunk| {
                            let mut one = [0u8; 32];
                            one.copy_from_slice(chunk);
                            one
                        })
                        .collect()
                }
                _ => Vec::new(),
            };
            ffi::shekyl_rpc_block_free(owner);
            if tx_bytes.is_none() {
                // Only reachable if the export ever reported a length no
                // allocation could have produced. Refuse rather than answer
                // with the block's transactions silently dropped.
                return Err(ffi::SHEKYL_RPC_FACTS_ERR_INTERNAL);
            }
            Ok((header, blob, json, tx_hashes))
        }
    }

    /// Global output indices of one transaction, and whether the store had
    /// the transaction at all.
    ///
    /// The owner is released in this function, after the copy and before any
    /// verdict, so no path out can lose the free.
    pub fn tx_output_indices(&self, txid: &[u8; 32]) -> Result<(Vec<u64>, bool), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const u64 = std::ptr::null();
        let mut len: usize = 0;
        let mut found: u8 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; every out pointer is valid for the call. On OK
        // the view borrows memory owned by `owner`, released below.
        unsafe {
            let rc = ffi::shekyl_rpc_tx_output_indices(
                self.handle,
                txid.as_ptr(),
                &raw mut rows,
                &raw mut len,
                &raw mut found,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let copied = if rows.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(rows, len).to_vec()
            };
            ffi::shekyl_rpc_tx_output_indices_free(owner);
            Ok((copied, found != 0))
        }
    }

    /// Blocks at `heights`, in order.
    ///
    /// Returns the entries gathered and, when the chain could not produce a
    /// height, that height alongside them.
    ///
    /// The two are not exclusive: a failure keeps the blocks read **before**
    /// it, because the C++ did — it cleared its list once before the loop and
    /// returned from the failure without clearing again, so `[0, past_tip]`
    /// carried block 0 with the error. The owner is released here, after the
    /// copies and before any verdict, so no path out can lose the free.
    pub fn blocks_by_height(
        &self,
        heights: &[u64],
    ) -> Result<(Vec<shekyl_rpc_types::BlockEntry>, Option<u64>), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::BlockEntryFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut failed_height: u64 = 0;
        let mut ok: u8 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; every out pointer is valid for the call. On OK
        // the views borrow memory owned by `owner`, released below before
        // this function returns, with every copy taken first.
        unsafe {
            let rc = ffi::shekyl_rpc_blocks_by_height(
                self.handle,
                if heights.is_empty() {
                    std::ptr::null()
                } else {
                    heights.as_ptr()
                },
                heights.len(),
                &raw mut rows,
                &raw mut len,
                &raw mut failed_height,
                &raw mut ok,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            // Past this point an owner may exist, so nothing returns until
            // it is released. The entries are copied whether or not `ok` is
            // set: on a failure they are the prefix the C++ also returned.
            let mut out = Vec::with_capacity(len);
            if !rows.is_null() {
                for entry in std::slice::from_raw_parts(rows, len) {
                    let block = if entry.block.is_null() || entry.block_len == 0 {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(entry.block, entry.block_len).to_vec()
                    };
                    let mut txs = Vec::with_capacity(entry.tx_count);
                    if !entry.txs.is_null() && !entry.tx_lens.is_null() {
                        let ptrs = std::slice::from_raw_parts(entry.txs, entry.tx_count);
                        let lens = std::slice::from_raw_parts(entry.tx_lens, entry.tx_count);
                        for (p, l) in ptrs.iter().zip(lens.iter()) {
                            txs.push(if p.is_null() || *l == 0 {
                                Vec::new()
                            } else {
                                std::slice::from_raw_parts(*p, *l).to_vec()
                            });
                        }
                    }
                    out.push(shekyl_rpc_types::BlockEntry { block, txs });
                }
            }
            ffi::shekyl_rpc_blocks_by_height_free(owner);
            Ok((out, (ok == 0).then_some(failed_height)))
        }
    }

    /// Transactions by hash, one answer per request slot, plus the tip the
    /// gather was taken against.
    ///
    /// `include_sensitive` decides whether a transaction the node has not
    /// broadcast is disclosed at all — not a field trim (§2.2). The caller
    /// passes `!restricted`; this function does not decide it.
    pub fn transactions(
        &self,
        txids: &[[u8; 32]],
        include_sensitive: bool,
    ) -> Result<(Vec<TxSlot>, u64), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let flat: Vec<u8> = txids.iter().flat_map(|h| h.iter().copied()).collect();
        let mut rows: *const ffi::TxEntryFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut chain_height: u64 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; every out pointer is valid for the call. On OK
        // the rows borrow memory owned by `owner`, released below before this
        // function returns, with every copy taken first.
        unsafe {
            let rc = ffi::shekyl_rpc_transactions(
                self.handle,
                if flat.is_empty() {
                    std::ptr::null()
                } else {
                    flat.as_ptr()
                },
                txids.len(),
                u8::from(include_sensitive),
                &raw mut rows,
                &raw mut len,
                &raw mut chain_height,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            // Past this point an owner may exist, so nothing returns until it
            // is released.
            let mut out = Vec::with_capacity(len);
            // Set by an entry carrying a discriminator the FFI contract does
            // not define. Recorded rather than returned on the spot, because the
            // owner is still live and nothing returns before it is freed.
            let mut undefined_where: Option<u8> = None;
            if !rows.is_null() {
                for e in std::slice::from_raw_parts(rows, len) {
                    let bytes = |p: *const u8, n: usize| -> Vec<u8> {
                        if p.is_null() || n == 0 {
                            Vec::new()
                        } else {
                            std::slice::from_raw_parts(p, n).to_vec()
                        }
                    };
                    let pruned = bytes(e.pruned, e.pruned_len);
                    let prunable = bytes(e.prunable, e.prunable_len);
                    let output_indices = if e.output_indices.is_null() || e.output_indices_len == 0
                    {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(e.output_indices, e.output_indices_len).to_vec()
                    };
                    match slot_of(e, pruned, prunable, output_indices) {
                        Some(slot) => out.push(slot),
                        None => {
                            undefined_where = Some(e.where_found);
                            out.push(TxSlot::Missed);
                        }
                    }
                }
            }
            ffi::shekyl_rpc_transactions_free(owner);
            if undefined_where.is_some() {
                return Err(ffi::SHEKYL_RPC_FACTS_ERR_INTERNAL);
            }
            Ok((out, chain_height))
        }
    }

    /// epee's JSON rendering of one transaction (RK-D11). `pruned` selects the
    /// base-only rendering, which is what the wire shows for a pruned reply.
    pub fn tx_to_json(&self, blob: &[u8], pruned: bool) -> Result<String, i32> {
        let mut out: *const std::os::raw::c_char = std::ptr::null();
        let mut len: usize = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: the out pointers are valid for the call; on OK the string
        // borrows `owner`, copied and then released before returning.
        unsafe {
            let rc = ffi::shekyl_rpc_tx_to_json(
                if blob.is_empty() {
                    std::ptr::null()
                } else {
                    blob.as_ptr()
                },
                blob.len(),
                u8::from(pruned),
                &raw mut out,
                &raw mut len,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let json = if out.is_null() || len == 0 {
                String::new()
            } else {
                String::from_utf8_lossy(std::slice::from_raw_parts(out.cast::<u8>(), len))
                    .into_owned()
            };
            ffi::shekyl_rpc_tx_json_free(owner);
            Ok(json)
        }
    }

    /// Key images, one status per request slot: 0 unspent, 1 spent in the
    /// chain, 2 spent in the pool.
    pub fn key_images_spent(&self, key_images: &[[u8; 32]]) -> Result<Vec<u8>, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let flat: Vec<u8> = key_images.iter().flat_map(|k| k.iter().copied()).collect();
        let mut status = vec![0u8; key_images.len()];
        // SAFETY: live handle; `status` is exactly `key_images.len()` bytes,
        // which is the length the export writes.
        let rc = unsafe {
            ffi::shekyl_rpc_key_images_spent(
                self.handle,
                if flat.is_empty() {
                    std::ptr::null()
                } else {
                    flat.as_ptr()
                },
                key_images.len(),
                status.as_mut_ptr(),
            )
        };
        if rc != ffi::SHEKYL_RPC_FACTS_OK {
            return Err(rc);
        }
        Ok(status)
    }

    /// Dispatch a JSON-RPC 2.0 method.
    /// Returns the raw response string from C++ (contains ok/error envelope).
    pub fn json_rpc(&self, method: &str, params: &str) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        let c_method = CString::new(method).ok()?;
        let c_params = CString::new(params).ok()?;
        unsafe {
            let ptr = ffi::core_rpc_ffi_json_rpc(self.handle, c_method.as_ptr(), c_params.as_ptr());
            consume_c_string(ptr)
        }
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

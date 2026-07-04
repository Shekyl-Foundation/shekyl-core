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
//! `src/rpc/daemon_submit_ffi.h`.

use std::os::raw::c_char;

#[repr(C)]
pub struct CoreRpcHandle {
    _opaque: [u8; 0],
}

// ── Submit shims (src/rpc/daemon_submit_ffi.h) ─────────────────────────────

/// Per-key-image conflict descriptor values (§4.1).
pub const SHEKYL_SUBMIT_KI_FREE: u8 = 0;
pub const SHEKYL_SUBMIT_KI_OWN_TX: u8 = 1;
pub const SHEKYL_SUBMIT_KI_OTHER: u8 = 2;

/// Shim return codes (shared by snapshot and commit).
pub const SHEKYL_SUBMIT_OK: i32 = 0;
pub const SHEKYL_SUBMIT_RACED: i32 = 1;
pub const SHEKYL_SUBMIT_PRUNED_ON_INSERT: i32 = 2;
pub const SHEKYL_SUBMIT_INTERNAL_FAULT: i32 = -1;

/// POD fact snapshot (`shekyl_submit_facts_ffi`) — same-build ABI (§4.5),
/// layout pinned by the const asserts below (mirroring the C++
/// static_asserts) plus the bidirectional runtime round-trip test.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitFactsFfi {
    pub in_pool: u8,
    pub in_chain: u8,
    pub ref_block_found: u8,
    pub tree_depth: u8,
    pub reserved: [u8; 4],
    pub ref_height: u64,
    pub root: [u8; 32],
    pub fee_per_byte: u64,
    pub fee_quantization_mask: u64,
    pub weight_limit: u64,
    pub chain_height: u64,
}

impl SubmitFactsFfi {
    /// All-zero snapshot for out-parameter initialization.
    pub const fn zeroed() -> Self {
        Self {
            in_pool: 0,
            in_chain: 0,
            ref_block_found: 0,
            tree_depth: 0,
            reserved: [0; 4],
            ref_height: 0,
            root: [0; 32],
            fee_per_byte: 0,
            fee_quantization_mask: 0,
            weight_limit: 0,
            chain_height: 0,
        }
    }
}

// §4.5 layout pins — the Rust twins of daemon_submit_ffi.cpp's
// static_asserts. A drift on either side fails that side's build.
const _: () = assert!(std::mem::size_of::<SubmitFactsFfi>() == 80);
const _: () = assert!(std::mem::align_of::<SubmitFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, in_pool) == 0);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, in_chain) == 1);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, ref_block_found) == 2);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, tree_depth) == 3);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, reserved) == 4);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, ref_height) == 8);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, root) == 16);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, fee_per_byte) == 48);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, fee_quantization_mask) == 56);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, weight_limit) == 64);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, chain_height) == 72);

extern "C" {
    pub fn core_rpc_ffi_create(rpc_server_ptr: *mut std::ffi::c_void) -> *mut CoreRpcHandle;
    pub fn core_rpc_ffi_destroy(h: *mut CoreRpcHandle);

    pub fn core_rpc_ffi_json_endpoint(
        h: *mut CoreRpcHandle,
        uri: *const c_char,
        body_json: *const c_char,
    ) -> *mut c_char;

    pub fn core_rpc_ffi_bin_endpoint(
        h: *mut CoreRpcHandle,
        uri: *const c_char,
        body: *const u8,
        body_len: usize,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;

    pub fn core_rpc_ffi_json_rpc(
        h: *mut CoreRpcHandle,
        method: *const c_char,
        params_json: *const c_char,
    ) -> *mut c_char;

    pub fn core_rpc_ffi_free_string(s: *mut c_char);
    pub fn core_rpc_ffi_free_buf(buf: *mut u8);

    // Submit shims (daemon_submit_ffi.h §4.1–§4.3). Contracts documented on
    // the C++ declarations; `FfiSubmitShim` is the only caller.
    pub fn shekyl_submit_snapshot_facts(
        h: *mut CoreRpcHandle,
        txid: *const u8,
        key_images: *const u8,
        n_key_images: usize,
        reference_block: *const u8,
        out_facts: *mut SubmitFactsFfi,
        out_ki_conflicts: *mut u8,
    ) -> i32;

    #[allow(clippy::too_many_arguments)]
    pub fn shekyl_submit_commit_tx(
        h: *mut CoreRpcHandle,
        blob: *const u8,
        blob_len: usize,
        txid: *const u8,
        tx_weight: u64,
        fee: u64,
        cert_ref_block: *const u8,
        cert_ref_height: u64,
        cert_root: *const u8,
        out_fresh_facts: *mut SubmitFactsFfi,
        out_fresh_ki_conflicts: *mut u8,
        n_key_images: usize,
    ) -> i32;

    pub fn shekyl_submit_relay_tx(h: *mut CoreRpcHandle, txid: *const u8) -> i32;

    // The §4.5 round-trip test hooks (C++ `shekyl_submit_facts_test_*`) are
    // deliberately not declared here: the bidirectional layout test is
    // C++-driven (tests/unit_tests/daemon_submit_ffi_roundtrip.cpp), which
    // calls the Rust twins exported from ffi_exports.rs. No Rust caller of
    // the C++ hooks exists.
}

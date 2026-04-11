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

//! Raw C FFI bindings to wallet2_ffi.h.
//!
//! These are unsafe and should only be called through the safe [`Wallet2`] wrapper.

use std::ffi::{c_char, c_int};

#[repr(C)]
pub struct Wallet2Handle {
    _opaque: [u8; 0],
}

extern "C" {
    pub fn wallet2_ffi_create(nettype: u8) -> *mut Wallet2Handle;
    pub fn wallet2_ffi_destroy(w: *mut Wallet2Handle);
    pub fn wallet2_ffi_init(
        w: *mut Wallet2Handle,
        daemon_address: *const c_char,
        daemon_username: *const c_char,
        daemon_password: *const c_char,
        trusted_daemon: bool,
    ) -> c_int;
    pub fn wallet2_ffi_refresh(w: *mut Wallet2Handle) -> c_int;
    pub fn wallet2_ffi_store(w: *mut Wallet2Handle) -> c_int;

    pub fn wallet2_ffi_last_error_code(w: *const Wallet2Handle) -> c_int;
    pub fn wallet2_ffi_last_error_msg(w: *const Wallet2Handle) -> *const c_char;
    pub fn wallet2_ffi_free_string(s: *mut c_char);

    pub fn wallet2_ffi_set_wallet_dir(w: *mut Wallet2Handle, dir: *const c_char);

    pub fn wallet2_ffi_create_wallet(
        w: *mut Wallet2Handle,
        filename: *const c_char,
        password: *const c_char,
        language: *const c_char,
    ) -> c_int;

    pub fn wallet2_ffi_open_wallet(
        w: *mut Wallet2Handle,
        filename: *const c_char,
        password: *const c_char,
    ) -> c_int;

    pub fn wallet2_ffi_close_wallet(w: *mut Wallet2Handle, autosave: bool) -> c_int;

    pub fn wallet2_ffi_restore_deterministic_wallet(
        w: *mut Wallet2Handle,
        filename: *const c_char,
        seed: *const c_char,
        password: *const c_char,
        language: *const c_char,
        restore_height: u64,
        seed_offset: *const c_char,
    ) -> *mut c_char;

    pub fn wallet2_ffi_generate_from_keys(
        w: *mut Wallet2Handle,
        filename: *const c_char,
        address: *const c_char,
        spendkey: *const c_char,
        viewkey: *const c_char,
        password: *const c_char,
        language: *const c_char,
        restore_height: u64,
    ) -> *mut c_char;

    pub fn wallet2_ffi_get_balance(w: *mut Wallet2Handle, account_index: u32) -> *mut c_char;

    pub fn wallet2_ffi_get_address(w: *mut Wallet2Handle, account_index: u32) -> *mut c_char;

    pub fn wallet2_ffi_query_key(w: *mut Wallet2Handle, key_type: *const c_char) -> *mut c_char;

    pub fn wallet2_ffi_get_version() -> u32;

    pub fn wallet2_ffi_transfer(
        w: *mut Wallet2Handle,
        destinations_json: *const c_char,
        priority: u32,
        account_index: u32,
    ) -> *mut c_char;

    pub fn wallet2_ffi_get_transfers(
        w: *mut Wallet2Handle,
        r#in: bool,
        out: bool,
        pending: bool,
        failed: bool,
        pool: bool,
        account_index: u32,
    ) -> *mut c_char;

    pub fn wallet2_ffi_stop(w: *mut Wallet2Handle) -> c_int;
    pub fn wallet2_ffi_is_open(w: *const Wallet2Handle) -> bool;
    pub fn wallet2_ffi_get_height(w: *const Wallet2Handle) -> u64;

    pub fn wallet2_ffi_json_rpc(
        w: *mut Wallet2Handle,
        method: *const c_char,
        params_json: *const c_char,
    ) -> *mut c_char;

    pub fn wallet2_ffi_prepare_transfer(
        w: *mut Wallet2Handle,
        destinations_json: *const c_char,
        priority: u32,
        account_index: u32,
    ) -> *mut c_char;

    pub fn wallet2_ffi_finalize_transfer(
        w: *mut Wallet2Handle,
        signed_proofs_json: *const c_char,
        tx_blob_hex: *const c_char,
    ) -> *mut c_char;

    pub fn wallet2_ffi_set_progress_callback(
        w: *mut Wallet2Handle,
        cb: Option<ProgressCallback>,
        user_data: *mut std::ffi::c_void,
    );

    /// Export keys needed by the Rust scanner as JSON.
    ///
    /// Returns a JSON string: `{"spend_secret":"hex","view_secret":"hex",
    /// "spend_public":"hex","view_public":"hex","x25519_sk":"hex",
    /// "ml_kem_dk":"hex"}`.
    ///
    /// Caller must free the returned string via `wallet2_ffi_free_string`.
    pub fn wallet2_ffi_get_scanner_keys(w: *mut Wallet2Handle) -> *mut c_char;
}

pub type ProgressCallback = extern "C" fn(
    event_type: *const c_char,
    current: u64,
    total: u64,
    detail: *const c_char,
    user_data: *mut std::ffi::c_void,
);

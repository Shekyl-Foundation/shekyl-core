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

//! Safe Rust wrapper around the wallet2 C FFI.
//!
//! All methods serialize/deserialize through JSON at the FFI boundary.

use crate::ffi;
use std::ffi::{CStr, CString};
use std::sync::mpsc;

#[derive(Debug)]
pub struct WalletError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wallet error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for WalletError {}

pub type WalletResult<T> = Result<T, WalletError>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProgressEvent {
    pub event_type: String,
    pub current: u64,
    pub total: u64,
    pub detail: Option<String>,
}

/// Safe handle to a C++ wallet2 instance. Not Send/Sync because wallet2 is single-threaded.
pub struct Wallet2 {
    handle: *mut ffi::Wallet2Handle,
    _progress_sender: Option<Box<mpsc::Sender<ProgressEvent>>>,
}

impl Wallet2 {
    /// Create a new wallet handle. `nettype`: 0=mainnet, 1=testnet, 2=stagenet.
    pub fn new(nettype: u8) -> WalletResult<Self> {
        let handle = unsafe { ffi::wallet2_ffi_create(nettype) };
        if handle.is_null() {
            return Err(WalletError {
                code: -1,
                message: "Failed to create wallet handle".into(),
            });
        }
        Ok(Self { handle, _progress_sender: None })
    }

    fn last_error(&self) -> WalletError {
        unsafe {
            let code = ffi::wallet2_ffi_last_error_code(self.handle);
            let msg_ptr = ffi::wallet2_ffi_last_error_msg(self.handle);
            let message = if msg_ptr.is_null() {
                String::new()
            } else {
                CStr::from_ptr(msg_ptr).to_string_lossy().into_owned()
            };
            WalletError { code, message }
        }
    }

    fn check_rc(&self, rc: i32) -> WalletResult<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(self.last_error())
        }
    }

    fn consume_json_ptr(&self, ptr: *mut std::ffi::c_char) -> WalletResult<serde_json::Value> {
        if ptr.is_null() {
            return Err(self.last_error());
        }
        let json_str = unsafe {
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            ffi::wallet2_ffi_free_string(ptr);
            s
        };
        serde_json::from_str(&json_str).map_err(|e| WalletError {
            code: -1,
            message: format!("JSON parse error: {e}"),
        })
    }

    pub fn init(
        &self,
        daemon_address: &str,
        daemon_username: &str,
        daemon_password: &str,
        trusted_daemon: bool,
    ) -> WalletResult<()> {
        let addr = CString::new(daemon_address).unwrap();
        let user = CString::new(daemon_username).unwrap();
        let pass = CString::new(daemon_password).unwrap();
        let rc = unsafe {
            ffi::wallet2_ffi_init(self.handle, addr.as_ptr(), user.as_ptr(), pass.as_ptr(), trusted_daemon)
        };
        self.check_rc(rc)
    }

    pub fn set_wallet_dir(&self, dir: &str) {
        let d = CString::new(dir).unwrap();
        unsafe { ffi::wallet2_ffi_set_wallet_dir(self.handle, d.as_ptr()) };
    }

    pub fn refresh(&self) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_refresh(self.handle) };
        self.check_rc(rc)
    }

    pub fn store(&self) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_store(self.handle) };
        self.check_rc(rc)
    }

    pub fn create_wallet(&self, filename: &str, password: &str, language: &str) -> WalletResult<()> {
        let f = CString::new(filename).unwrap();
        let p = CString::new(password).unwrap();
        let l = CString::new(language).unwrap();
        let rc = unsafe {
            ffi::wallet2_ffi_create_wallet(self.handle, f.as_ptr(), p.as_ptr(), l.as_ptr())
        };
        self.check_rc(rc)
    }

    pub fn open_wallet(&self, filename: &str, password: &str) -> WalletResult<()> {
        let f = CString::new(filename).unwrap();
        let p = CString::new(password).unwrap();
        let rc = unsafe { ffi::wallet2_ffi_open_wallet(self.handle, f.as_ptr(), p.as_ptr()) };
        self.check_rc(rc)
    }

    pub fn close_wallet(&self, autosave: bool) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_close_wallet(self.handle, autosave) };
        self.check_rc(rc)
    }

    pub fn restore_deterministic_wallet(
        &self,
        filename: &str,
        seed: &str,
        password: &str,
        language: &str,
        restore_height: u64,
        seed_offset: &str,
    ) -> WalletResult<serde_json::Value> {
        let f = CString::new(filename).unwrap();
        let s = CString::new(seed).unwrap();
        let p = CString::new(password).unwrap();
        let l = CString::new(language).unwrap();
        let o = CString::new(seed_offset).unwrap();
        let ptr = unsafe {
            ffi::wallet2_ffi_restore_deterministic_wallet(
                self.handle, f.as_ptr(), s.as_ptr(), p.as_ptr(), l.as_ptr(), restore_height, o.as_ptr(),
            )
        };
        self.consume_json_ptr(ptr)
    }

    pub fn generate_from_keys(
        &self,
        filename: &str,
        address: &str,
        spendkey: &str,
        viewkey: &str,
        password: &str,
        language: &str,
        restore_height: u64,
    ) -> WalletResult<serde_json::Value> {
        let f = CString::new(filename).unwrap();
        let a = CString::new(address).unwrap();
        let sk = CString::new(spendkey).unwrap();
        let vk = CString::new(viewkey).unwrap();
        let p = CString::new(password).unwrap();
        let l = CString::new(language).unwrap();
        let ptr = unsafe {
            ffi::wallet2_ffi_generate_from_keys(
                self.handle, f.as_ptr(), a.as_ptr(), sk.as_ptr(), vk.as_ptr(), p.as_ptr(), l.as_ptr(),
                restore_height,
            )
        };
        self.consume_json_ptr(ptr)
    }

    pub fn get_balance(&self, account_index: u32) -> WalletResult<serde_json::Value> {
        let ptr = unsafe { ffi::wallet2_ffi_get_balance(self.handle, account_index) };
        self.consume_json_ptr(ptr)
    }

    pub fn get_address(&self, account_index: u32) -> WalletResult<serde_json::Value> {
        let ptr = unsafe { ffi::wallet2_ffi_get_address(self.handle, account_index) };
        self.consume_json_ptr(ptr)
    }

    pub fn query_key(&self, key_type: &str) -> WalletResult<serde_json::Value> {
        let kt = CString::new(key_type).unwrap();
        let ptr = unsafe { ffi::wallet2_ffi_query_key(self.handle, kt.as_ptr()) };
        self.consume_json_ptr(ptr)
    }

    pub fn get_version() -> u32 {
        unsafe { ffi::wallet2_ffi_get_version() }
    }

    pub fn transfer(
        &self,
        destinations_json: &str,
        priority: u32,
        account_index: u32,
        ring_size: u32,
    ) -> WalletResult<serde_json::Value> {
        let d = CString::new(destinations_json).unwrap();
        let ptr = unsafe {
            ffi::wallet2_ffi_transfer(self.handle, d.as_ptr(), priority, account_index, ring_size)
        };
        self.consume_json_ptr(ptr)
    }

    pub fn get_transfers(
        &self,
        r#in: bool,
        out: bool,
        pending: bool,
        failed: bool,
        pool: bool,
        account_index: u32,
    ) -> WalletResult<serde_json::Value> {
        let ptr = unsafe {
            ffi::wallet2_ffi_get_transfers(self.handle, r#in, out, pending, failed, pool, account_index)
        };
        self.consume_json_ptr(ptr)
    }

    pub fn stop(&self) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_stop(self.handle) };
        self.check_rc(rc)
    }

    pub fn is_open(&self) -> bool {
        unsafe { ffi::wallet2_ffi_is_open(self.handle) }
    }

    pub fn get_height(&self) -> u64 {
        unsafe { ffi::wallet2_ffi_get_height(self.handle) }
    }

    /// Generic JSON-RPC dispatch for all methods (Phase 2 expansion).
    /// Routes to the C++ dispatcher which handles the full method surface.
    pub fn json_rpc_call(&self, method: &str, params_json: &str) -> WalletResult<serde_json::Value> {
        let m = CString::new(method).unwrap();
        let p = CString::new(params_json).unwrap();
        let ptr = unsafe { ffi::wallet2_ffi_json_rpc(self.handle, m.as_ptr(), p.as_ptr()) };
        self.consume_json_ptr(ptr)
    }

    /// Register a progress channel. The C++ callback bridge will send
    /// `ProgressEvent` messages through this channel whenever wallet2
    /// reports transfer stage, FCMP precompute, or PQC rederivation progress.
    pub fn set_progress_sender(&mut self, tx: mpsc::Sender<ProgressEvent>) {
        let mut boxed = Box::new(tx);
        let user_data = &mut *boxed as *mut mpsc::Sender<ProgressEvent> as *mut std::ffi::c_void;
        unsafe {
            ffi::wallet2_ffi_set_progress_callback(
                self.handle,
                Some(progress_trampoline),
                user_data,
            );
        }
        self._progress_sender = Some(boxed);
    }
}

extern "C" fn progress_trampoline(
    event_type: *const std::ffi::c_char,
    current: u64,
    total: u64,
    detail: *const std::ffi::c_char,
    user_data: *mut std::ffi::c_void,
) {
    if user_data.is_null() {
        return;
    }
    let tx = unsafe { &*(user_data as *const mpsc::Sender<ProgressEvent>) };
    let event_type_str = if event_type.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(event_type) }.to_string_lossy().into_owned()
    };
    let detail_str = if detail.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(detail) }.to_string_lossy().into_owned())
    };
    let _ = tx.send(ProgressEvent {
        event_type: event_type_str,
        current,
        total,
        detail: detail_str,
    });
}

impl Drop for Wallet2 {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::wallet2_ffi_destroy(self.handle) };
        }
    }
}

// Safety: Wallet2 wraps a C++ object behind a raw pointer. Thread safety is
// enforced at a higher level by the Mutex<Wallet2> in AppState. All access to
// the underlying wallet2 is serialized through that mutex.
unsafe impl Send for Wallet2 {}

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
//!
//! # Account-state invariant (SECURITY PROPERTY)
//!
//! This library has **no current-account state**. Every method that operates
//! on an account takes an explicit `account_index` parameter. There is no
//! `set_account`, no per-connection session default, no interior-mutable
//! current-account field.
//!
//! When a Rust wallet RPC server is built on top of this library, the same
//! invariant must hold: **every RPC method schema requires `account_index`
//! as a parameter; there is no `set_account` method.** Client-side defaults
//! are the client's responsibility (e.g. `ReplSession` in shekyl-cli).
//!
//! Rationale: server-side current-account state creates race conditions
//! between concurrent clients, produces non-deterministic audit logs, and
//! has been a persistent source of user-funds-loss bugs in the Bitcoin
//! `accounts` API (deprecated for exactly this reason). Do not reintroduce
//! this pattern.

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

#[cfg(feature = "native-sign")]
impl From<shekyl_tx_builder::TxBuilderError> for WalletError {
    fn from(e: shekyl_tx_builder::TxBuilderError) -> Self {
        WalletError {
            code: -100,
            message: e.to_string(),
        }
    }
}

pub type WalletResult<T> = Result<T, WalletError>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProgressEvent {
    pub event_type: String,
    pub current: u64,
    pub total: u64,
    pub detail: Option<String>,
}

/// FFI handle to a C++ wallet2 instance.
///
/// # Safety
/// This type wraps a raw C++ pointer and implements `Send` + `Sync` so it can
/// be shared across async Tokio tasks (the RPC server dispatches on a single-threaded
/// executor behind a `Mutex`). The `Mutex` in `AppState` serializes all access;
/// callers must never use this handle without holding the lock.
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
        Ok(Self {
            handle,
            _progress_sender: None,
        })
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

    fn to_cstring(s: &str) -> WalletResult<CString> {
        CString::new(s).map_err(|_| WalletError {
            code: -1,
            message: format!(
                "string contains interior NUL byte: {:?}",
                &s[..s.len().min(32)]
            ),
        })
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
        let addr = Self::to_cstring(daemon_address)?;
        let user = Self::to_cstring(daemon_username)?;
        let pass = Self::to_cstring(daemon_password)?;
        let rc = unsafe {
            ffi::wallet2_ffi_init(
                self.handle,
                addr.as_ptr(),
                user.as_ptr(),
                pass.as_ptr(),
                trusted_daemon,
            )
        };
        self.check_rc(rc)
    }

    pub fn refresh(&self) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_refresh(self.handle) };
        self.check_rc(rc)
    }

    pub fn store(&self) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_store(self.handle) };
        self.check_rc(rc)
    }

    pub fn create_wallet(
        &self,
        wallet_path: &str,
        password: &str,
        language: &str,
    ) -> WalletResult<()> {
        let f = Self::to_cstring(wallet_path)?;
        let p = Self::to_cstring(password)?;
        let l = Self::to_cstring(language)?;
        let rc = unsafe {
            ffi::wallet2_ffi_create_wallet(self.handle, f.as_ptr(), p.as_ptr(), l.as_ptr())
        };
        self.check_rc(rc)
    }

    pub fn open_wallet(&self, wallet_path: &str, password: &str) -> WalletResult<()> {
        let f = Self::to_cstring(wallet_path)?;
        let p = Self::to_cstring(password)?;
        let rc = unsafe { ffi::wallet2_ffi_open_wallet(self.handle, f.as_ptr(), p.as_ptr()) };
        self.check_rc(rc)
    }

    pub fn close_wallet(&self, autosave: bool) -> WalletResult<()> {
        let rc = unsafe { ffi::wallet2_ffi_close_wallet(self.handle, autosave) };
        self.check_rc(rc)
    }

    pub fn restore_deterministic_wallet(
        &self,
        wallet_path: &str,
        seed: &str,
        password: &str,
        language: &str,
        restore_height: u64,
        seed_offset: &str,
    ) -> WalletResult<serde_json::Value> {
        let f = Self::to_cstring(wallet_path)?;
        let s = Self::to_cstring(seed)?;
        let p = Self::to_cstring(password)?;
        let l = Self::to_cstring(language)?;
        let o = Self::to_cstring(seed_offset)?;
        let ptr = unsafe {
            ffi::wallet2_ffi_restore_deterministic_wallet(
                self.handle,
                f.as_ptr(),
                s.as_ptr(),
                p.as_ptr(),
                l.as_ptr(),
                restore_height,
                o.as_ptr(),
            )
        };
        self.consume_json_ptr(ptr)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_from_keys(
        &self,
        wallet_path: &str,
        address: &str,
        spendkey: &str,
        viewkey: &str,
        password: &str,
        language: &str,
        restore_height: u64,
    ) -> WalletResult<serde_json::Value> {
        let f = Self::to_cstring(wallet_path)?;
        let a = Self::to_cstring(address)?;
        let sk = Self::to_cstring(spendkey)?;
        let vk = Self::to_cstring(viewkey)?;
        let p = Self::to_cstring(password)?;
        let l = Self::to_cstring(language)?;
        let ptr = unsafe {
            ffi::wallet2_ffi_generate_from_keys(
                self.handle,
                f.as_ptr(),
                a.as_ptr(),
                sk.as_ptr(),
                vk.as_ptr(),
                p.as_ptr(),
                l.as_ptr(),
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
        let kt = Self::to_cstring(key_type)?;
        let ptr = unsafe { ffi::wallet2_ffi_query_key(self.handle, kt.as_ptr()) };
        self.consume_json_ptr(ptr)
    }

    /// Export scanner keys from the C++ wallet.
    ///
    /// Returns JSON with `spend_secret`, `view_secret`, `spend_public`,
    /// `view_public`, `x25519_sk`, `ml_kem_dk` as hex strings.
    pub fn get_scanner_keys(&self) -> WalletResult<serde_json::Value> {
        let ptr = unsafe { ffi::wallet2_ffi_get_scanner_keys(self.handle) };
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
    ) -> WalletResult<serde_json::Value> {
        let d = Self::to_cstring(destinations_json)?;
        let ptr =
            unsafe { ffi::wallet2_ffi_transfer(self.handle, d.as_ptr(), priority, account_index) };
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
            ffi::wallet2_ffi_get_transfers(
                self.handle,
                r#in,
                out,
                pending,
                failed,
                pool,
                account_index,
            )
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
    pub fn json_rpc_call(
        &self,
        method: &str,
        params_json: &str,
    ) -> WalletResult<serde_json::Value> {
        let m = Self::to_cstring(method)?;
        let p = Self::to_cstring(params_json)?;
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

    /// Native Rust transfer path (requires `native-sign` feature).
    ///
    /// Flow:
    /// 1. Call C++ `wallet2_ffi_prepare_transfer()` to get: tx prefix, selected
    ///    UTXOs with keys, tree paths, amounts — all as JSON.
    /// 2. Call `shekyl_tx_builder::sign_transaction()` directly in Rust.
    /// 3. Call C++ `wallet2_ffi_finalize_transfer()` to submit the signed tx.
    ///
    /// This eliminates the C++ → Rust → C++ → Rust FFI round-trips for proof
    /// generation. Uses `wallet2_ffi_prepare_transfer` (C++ data gathering) →
    /// `shekyl_tx_builder::sign_transaction` (Rust proofs) →
    /// `wallet2_ffi_finalize_transfer` (C++ insertion + broadcast).
    #[cfg(feature = "native-sign")]
    pub fn transfer_native(
        &self,
        destinations_json: &str,
        priority: u32,
        account_index: u32,
    ) -> WalletResult<serde_json::Value> {
        let dests = CString::new(destinations_json).map_err(|_| WalletError {
            code: -1,
            message: "invalid destinations JSON (contains null byte)".into(),
        })?;

        // Phase A: prepare (builds tx prefix, returns structured signing inputs)
        let prep_ptr = unsafe {
            ffi::wallet2_ffi_prepare_transfer(self.handle, dests.as_ptr(), priority, account_index)
        };
        let prep_json = self.consume_json_ptr(prep_ptr)?;

        // Extract signing inputs from the prepared data
        let tx_prefix_hash_hex =
            prep_json["tx_prefix_hash"]
                .as_str()
                .ok_or_else(|| WalletError {
                    code: -1,
                    message: "missing tx_prefix_hash in prepare response".into(),
                })?;

        let inputs: Vec<shekyl_tx_builder::SpendInput> =
            serde_json::from_value(prep_json["inputs"].clone()).map_err(|e| WalletError {
                code: -1,
                message: format!("failed to parse inputs: {e}"),
            })?;

        let outputs: Vec<shekyl_tx_builder::OutputInfo> =
            serde_json::from_value(prep_json["outputs"].clone()).map_err(|e| WalletError {
                code: -1,
                message: format!("failed to parse outputs: {e}"),
            })?;

        let fee = prep_json["fee"].as_u64().ok_or_else(|| WalletError {
            code: -1,
            message: "missing fee in prepare response".into(),
        })?;

        let tree: shekyl_tx_builder::TreeContext =
            serde_json::from_value(prep_json["tree"].clone()).map_err(|e| WalletError {
                code: -1,
                message: format!("failed to parse tree context: {e}"),
            })?;

        let mut tx_prefix_hash = [0u8; 32];
        hex_decode(tx_prefix_hash_hex, &mut tx_prefix_hash)?;

        // Phase B: sign (pure Rust, no FFI crossing)
        let proofs =
            shekyl_tx_builder::sign_transaction(tx_prefix_hash, &inputs, &outputs, fee, &tree)
                .map_err(WalletError::from)?;

        let proofs_json_str = serde_json::to_string(&proofs).map_err(|e| WalletError {
            code: -1,
            message: format!("failed to serialize proofs: {e}"),
        })?;

        let tx_blob_hex = prep_json["tx_blob"].as_str().ok_or_else(|| WalletError {
            code: -1,
            message: "missing tx_blob in prepare response".into(),
        })?;

        // Phase C: finalize (inserts proofs, PQC signs, broadcasts)
        let proofs_cstr = Self::to_cstring(&proofs_json_str)?;
        let tx_blob_cstr = Self::to_cstring(tx_blob_hex)?;
        let fin_ptr = unsafe {
            ffi::wallet2_ffi_finalize_transfer(
                self.handle,
                proofs_cstr.as_ptr(),
                tx_blob_cstr.as_ptr(),
            )
        };
        self.consume_json_ptr(fin_ptr)
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
        unsafe { CStr::from_ptr(event_type) }
            .to_string_lossy()
            .into_owned()
    };
    let detail_str = if detail.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(detail) }
                .to_string_lossy()
                .into_owned(),
        )
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

#[cfg(feature = "native-sign")]
fn hex_decode(hex_str: &str, out: &mut [u8; 32]) -> Result<(), WalletError> {
    if hex_str.len() != 64 {
        return Err(WalletError {
            code: -1,
            message: format!("expected 64-char hex string, got {}", hex_str.len()),
        });
    }
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| WalletError {
            code: -1,
            message: format!("invalid hex char at position {}", i * 2),
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| WalletError {
            code: -1,
            message: format!("invalid hex char at position {}", i * 2 + 1),
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

#[cfg(feature = "native-sign")]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

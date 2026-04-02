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
        let c_uri = CString::new(uri).ok()?;
        let c_body = CString::new(body).ok()?;
        unsafe {
            let ptr = ffi::core_rpc_ffi_json_endpoint(
                self.handle,
                c_uri.as_ptr(),
                c_body.as_ptr(),
            );
            consume_c_string(ptr)
        }
    }

    /// Dispatch a binary endpoint (e.g. "/get_blocks.bin").
    /// Returns `Ok(data)` on success, `Err(rc)` with the FFI error code on failure.
    /// rc -1 = bad request (parse failure), rc -2 = internal error.
    pub fn bin_endpoint(&self, uri: &str, body: &[u8]) -> Result<Vec<u8>, i32> {
        let c_uri = CString::new(uri).map_err(|_| -2i32)?;
        let mut out_buf: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        unsafe {
            let rc = ffi::core_rpc_ffi_bin_endpoint(
                self.handle,
                c_uri.as_ptr(),
                body.as_ptr(),
                body.len(),
                &mut out_buf,
                &mut out_len,
            );
            if rc != 0 || out_buf.is_null() {
                return Err(rc);
            }
            let data = std::slice::from_raw_parts(out_buf, out_len).to_vec();
            ffi::core_rpc_ffi_free_buf(out_buf);
            Ok(data)
        }
    }

    /// Dispatch a JSON-RPC 2.0 method.
    /// Returns the raw response string from C++ (contains ok/error envelope).
    pub fn json_rpc(&self, method: &str, params: &str) -> Option<String> {
        let c_method = CString::new(method).ok()?;
        let c_params = CString::new(params).ok()?;
        unsafe {
            let ptr = ffi::core_rpc_ffi_json_rpc(
                self.handle,
                c_method.as_ptr(),
                c_params.as_ptr(),
            );
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

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

//! Raw C FFI declarations matching `src/rpc/core_rpc_ffi.h`.

use std::os::raw::c_char;

#[repr(C)]
pub struct CoreRpcHandle {
    _opaque: [u8; 0],
}

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
}

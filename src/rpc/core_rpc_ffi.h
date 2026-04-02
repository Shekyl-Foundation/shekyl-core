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

// C FFI facade over core_rpc_server for consumption by Rust (shekyl-daemon-rpc).
// JSON endpoints return heap-allocated strings freed with core_rpc_ffi_free_string().
// Binary endpoints return heap-allocated buffers freed with core_rpc_ffi_free_buf().

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct core_rpc_handle core_rpc_handle;

// Wrap an existing, fully-initialized core_rpc_server.
// The pointer must remain valid for the lifetime of the handle.
core_rpc_handle* core_rpc_ffi_create(void* rpc_server_ptr);
void core_rpc_ffi_destroy(core_rpc_handle* h);

// True if the wrapped server was created with restricted=true.
bool core_rpc_ffi_is_restricted(const core_rpc_handle* h);

// JSON REST endpoints (/get_info, /send_raw_transaction, etc.).
// Returns serialized JSON response body, or NULL if the URI is unknown.
char* core_rpc_ffi_json_endpoint(core_rpc_handle* h,
    const char* uri, const char* body_json);

// Binary endpoints (/get_blocks.bin, /get_outs.bin, etc.).
// On success: sets *out_buf and *out_len, returns 0. Caller frees with core_rpc_ffi_free_buf.
// On failure: returns -1 (unknown URI or deserialization error).
int core_rpc_ffi_bin_endpoint(core_rpc_handle* h,
    const char* uri,
    const uint8_t* body, size_t body_len,
    uint8_t** out_buf, size_t* out_len);

// JSON-RPC 2.0 method dispatch.
// Returns a JSON string:
//   {"ok":true,"result":{...}}                     on success
//   {"ok":false,"error_code":N,"error_message":"..."} on handler error
// Returns NULL only if the method is completely unknown.
char* core_rpc_ffi_json_rpc(core_rpc_handle* h,
    const char* method, const char* params_json);

void core_rpc_ffi_free_string(char* s);
void core_rpc_ffi_free_buf(uint8_t* buf);

#ifdef __cplusplus
} // extern "C"
#endif

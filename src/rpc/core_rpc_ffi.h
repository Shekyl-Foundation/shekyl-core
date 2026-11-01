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

// C FFI for the sync-half facts handle and the stem-tally readout.
// The method tables are gone (DRS_X_STORE_FLIP.md DX-Q3).

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct core_rpc_handle core_rpc_handle;

// Copy the two pointers out of an rpc_subject. The subject must remain
// valid for the lifetime of the handle.
core_rpc_handle* core_rpc_ffi_create(void* subject_ptr);
void core_rpc_ffi_destroy(core_rpc_handle* h);

//! \brief §55: relay stem-outcome tallies as a JSON array (caller frees with
//!        core_rpc_ffi_free_string).
//!
//! TRANSIT, NOT STRUCTURE: a Rust-owned value forwarded to a Rust consumer,
//! hopping through C++ only because net_node owns the relay zone handles.
//! Disappears with the p2p migration.
char* core_rpc_ffi_stem_tallies(core_rpc_handle* h);

void core_rpc_ffi_free_string(char* s);

#ifdef __cplusplus
} // extern "C"
#endif

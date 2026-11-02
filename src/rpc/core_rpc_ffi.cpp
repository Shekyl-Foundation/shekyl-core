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

#include "core_rpc_ffi.h"
#include "core_rpc_ffi_internal.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>

#include "misc_log_ex.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "daemon.rpc"

// The method tables are gone with the C++ server (DRS_X_STORE_FLIP.md
// DX-Q3). What remains is the handle the sync-half facts and the stem
// tallies read.

extern "C" {

core_rpc_handle* core_rpc_ffi_create(void* subject_ptr)
{
    if (!subject_ptr) return nullptr;
    const rpc_subject* subject = static_cast<const rpc_subject*>(subject_ptr);
    if (!subject->core || !subject->p2p) return nullptr;
    auto* h = new(std::nothrow) core_rpc_handle;
    if (!h) return nullptr;
    h->core = subject->core;
    h->p2p = subject->p2p;
    return h;
}

void core_rpc_ffi_destroy(core_rpc_handle* h)
{
    delete h;
}

char* core_rpc_ffi_stem_tallies(core_rpc_handle* h)
{
    if (!h || !h->p2p) return nullptr;
    try {
        return strdup(h->p2p->stem_tallies_json().c_str());
    } catch (const std::exception& e) {
        MERROR("core_rpc_ffi_stem_tallies: " << e.what());
        return nullptr;
    }
}

void core_rpc_ffi_free_string(char* s) { free(s); }

} // extern "C"

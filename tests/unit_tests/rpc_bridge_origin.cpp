// Copyright (c) 2026, The Shekyl Foundation
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


// The origin context the C++ dispatch bridge hands every bridged handler
// (docs/design/DAEMON_RPC_KV_CUTOVER.md §7, 2026-08-26).
//
// Until that date `dispatch_json` / `dispatch_jsonrpc` / `dispatch_jsonrpc_we`
// passed `nullptr`, so `restricted = m_restricted && ctx` was false on every
// JSON route no matter how the listener was configured. That did not merely
// disable request caps: the pool reads compute
// `allow_sensitive = !request_has_rpc_origin || !restricted`, which was
// likewise always true, and `allow_sensitive` decides whether a transaction
// that is not `relay_category::broadcasted` — a stem-phase or locally
// submitted one — is disclosed at all. A restricted, public listener was
// answering with them.
//
// These two tests guard the fix's contracts. Neither can prove that the
// dispatch tables *call* `rpc_origin()` — that is what the live check in the
// commit message did — but both go red on the ways the helper itself can
// regress.

#include <gtest/gtest.h>

#include "rpc/core_rpc_ffi.h"

// The property the restricted gate rests on. Returning null here is exactly
// the bug that was fixed, and this test is what would have caught it.
TEST(rpc_bridge_origin, a_bridged_request_has_an_rpc_origin)
{
  EXPECT_TRUE(core_rpc_ffi_origin_is_present())
    << "a bridged request must carry a non-null connection context, or "
       "`m_restricted && ctx` is false on every route and no restricted "
       "policy can fire";
}

// The other half: having given the bridge a context, it must not be one that
// per-host ban scoring will act on. `add_host_fail` takes `ctx->m_remote_address`
// and scores it; a shared, default-constructed address is not any caller, so
// it must not be blockable.
TEST(rpc_bridge_origin, the_rpc_origin_is_not_a_bannable_host)
{
  EXPECT_FALSE(core_rpc_ffi_origin_is_blockable())
    << "the shared origin context must not be blockable, or every bridged "
       "request scores RPC ban points against one empty address";
}

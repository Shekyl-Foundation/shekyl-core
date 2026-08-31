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


// `pruned_transaction`: the serialization wrapper that makes epee render only
// a transaction's base, which is what `get_transactions` answers with when the
// caller asked for the pruned form (RK-D11 keeps that rendering in C++).
//
// It lived as a file-local class in core_rpc_server.cpp with exactly one user,
// `on_get_transactions`. RK-4c needs it from the facts shim as well, and a
// second copy of a serialization wrapper is the kind of duplicate that drifts
// silently — the two would render differently and only the cross-language
// parity test would notice. So it moved here rather than being copied.
//
// Its removal trigger is the FIELD, not that handler. RK-4c deletes
// `on_get_transactions` and this class outlives it, because `get_transactions`
// still answers with `as_json` and the facts shim renders it through
// `shekyl_rpc_tx_to_json`. The §5 register of `DAEMON_RPC_KV_CUTOVER.md` files
// `obj_to_json_str(pruned_tx)` and that field under **RK-W**, where the honest
// question is whether `as_json` should exist at all — it duplicates `as_hex` /
// `pruned_as_hex`, which carry the same transaction in the consensus encoding
// every in-tree client already parses. This class dies there, with the field.

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      bool r = tx.serialize_base(ar);
      if (!r) return false;
    END_SERIALIZE()
  };
}

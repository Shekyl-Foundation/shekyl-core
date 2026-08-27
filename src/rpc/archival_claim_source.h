// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "crypto/hash.h"
#include "rpc/core_rpc_server_commands_defs.h"

namespace cryptonote
{

class BlockchainDB;

namespace rpc
{

/// Fill the `get_archival_emission_claim_source` response from `db`
/// (`EMISSION_CLAIM_BUILDER.md` §7): part-A claim context from the bond
/// record, part-B per-epoch snapshots for **every** epoch in
/// `[claim_window_floor(settled), settled − 1]` — unconditionally, with no
/// claimable-set-derived branch (§7.2 transport cause-blindness). Every
/// per-epoch operand is a field-for-field copy of the single landed gather,
/// `gather_archival_emission_epoch_snapshot`; this function reconstructs no
/// operand and owns no second gather path (§7.1, CB-1(b)'s daemon face).
///
/// Extracted from the RPC handler so the LMDB operand-fidelity test can
/// drive the marshaling against the in-process gather on the same DB state
/// without constructing a core_rpc_server. The caller owns read-view
/// consistency (the handler wraps the call in a `db_rtxn_guard`, so the tip
/// height, bond record, and every epoch row come from one LMDB read view).
///
/// `res` must be freshly value-initialized: both transports dispatch
/// struct_init responses and the tests construct `response{}`, so bond-less
/// part-A fields stay zeroed without a per-field reset ladder here (which
/// would have to grow in lockstep with every future response field).
///
/// **Throws** on any gather or marshal failure, and the caller must catch: the
/// `BlockchainDB` accessors this composes throw `DB_ERROR`, and a non-OK return
/// from the cooldown-anchor fold throws here for the same reason. That is the
/// only error channel — deliberately, since a second one (a status return) would
/// leave callers handling both, and the one that is easy to forget is the one
/// that matters: a partially-filled response whose absent operands read as the
/// *permissive* branch of the exit predicates. Refusing the whole response is
/// the only answer that cannot be misread, so the handler catches and answers a
/// non-OK RPC status, which the wallet's decoder rejects before reading any
/// payload field.
void fill_archival_emission_claim_source(const BlockchainDB& db,
    const crypto::hash& p_id,
    COMMAND_RPC_GET_ARCHIVAL_EMISSION_CLAIM_SOURCE::response& res);

}  // namespace rpc
}  // namespace cryptonote

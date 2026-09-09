// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bridged `/get_info` and the DAA target the header commands render with.

use super::Source;

// ── RK-5b: the header console commands ──────────────────────────────────────
//
// Four commands, and every one of them crosses to a route this slice does not
// serve. All four read `/get_info`, which is RK-5c's; `alt_chain_info` also
// reads `get_alternate_chains` and `show_status` also reads `/mining_status`,
// which belong to RK-8 and RK-7. Every one of those three names is still in
// the C++ dispatch tables (`core_rpc_ffi.cpp:174`, `:180`, `:284`) — §2.1.1's
// condition — and the console tests drive all four commands on their remote
// arm, which is the other half of it.
//
// The slice plan said "one bridged `/get_info` leg per crosser", and two of
// the four carry a second leg. Recorded rather than quietly absorbed: a
// bridged leg is a dated liability, and the count is what says how much comes
// home when RK-7 and RK-8 land.

/// The `/get_info` reply, as much of it as the four commands above read.
///
/// **A bridged leg, on purpose** (§2.1.1). One struct rather than four,
/// because RK-5c changes this reply and one struct means one place to fix and
/// four commands that go red together rather than one that goes red and three
/// that go quiet.
///
/// **No field carries `#[serde(default)]`, and RK-5c is the reason.** Route
/// deletion is caught by the `ok_or_else` in [`fetch_get_info`]; a *renamed
/// or removed field* is the quiet failure, and a default would turn it into a
/// confident zero — `show_status` reporting height 0 on a synced daemon. The
/// failure this slice must hand RK-5c is a deserialization error naming the
/// field that moved. Every field below is `KV_SERIALIZE` (not `_OPT`) in
/// `COMMAND_RPC_GET_INFO::response_t`, so absence can only mean the contract
/// moved. Unknown fields are ignored on purpose — RK-5c *adding* a field is
/// not a break, and `/get_info` carries about thirty this console never reads.
///
/// It holds exactly the fields that have a reader, and gains one when a
/// command that reads it lands: a field with no reader is a claim about the
/// reply that nothing checks, and it would make the "four go red together"
/// property above weaker than it looks.
#[derive(serde::Deserialize)]
pub(super) struct GetInfoReplyProvisional {
    pub(super) status: shekyl_rpc_types::RpcStatus,
    pub(super) height: u64,
    pub(super) wide_difficulty: String,
    pub(super) wide_cumulative_difficulty: String,
    pub(super) target_height: u64,
    pub(super) testnet: bool,
    pub(super) stagenet: bool,
    /// Zero on a restricted listener, which does not disclose it. Required
    /// all the same — the daemon always sends the field — and the zero is
    /// handled where it is rendered, as the C++ did.
    pub(super) start_time: u64,
    pub(super) outgoing_connections_count: u64,
    pub(super) incoming_connections_count: u64,
}

/// Fetch `/get_info` over whichever arm this console is running on.
pub(super) fn fetch_get_info(src: &Source) -> Result<GetInfoReplyProvisional, String> {
    let reply: GetInfoReplyProvisional = match src {
        Source::Live(core) => {
            let raw = core
                .json_endpoint("/get_info", "{}")
                .ok_or_else(|| "no reply from /get_info".to_owned())?;
            serde_json::from_str(&raw)
        }
        Source::Remote { .. } => {
            let raw = src.post_remote("/get_info", b"{}".to_vec())?;
            serde_json::from_slice(&raw)
        }
    }
    .map_err(|e| format!("malformed get_info reply: {e}"))?;
    if reply.status.is_ok() {
        Ok(reply)
    } else {
        Err(reply.status.0)
    }
}

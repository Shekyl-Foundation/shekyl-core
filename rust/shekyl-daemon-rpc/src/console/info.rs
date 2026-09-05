// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bridged `/get_info` and the DAA target the header commands render with.

use super::Source;
use crate::ctl_client;

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
    /// The DAA's target block time, as **this daemon** reports it.
    ///
    /// **Not the authority.** `T` is genesis-frozen and single-sourced
    /// through `config/consensus_constants.json`, which generates both the
    /// C++ `shekyl/consensus_constants_generated.h` and this crate's
    /// [`crate::consensus::DAA_TARGET_SECONDS`]. The console renders from the
    /// generated value; this field exists so a disagreement can be *reported*
    /// rather than silently rendered from — see [`daa_target_seconds`].
    pub(super) target: u64,
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
        Source::Remote { address, timeout } => {
            let raw = ctl_client::post_blocking(address, "/get_info", b"{}".to_vec(), *timeout)
                .map_err(|(_, reason)| reason)?;
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

/// The DAA target this console renders with, and what to do when the daemon
/// disagrees.
///
/// **The authority is the generated constant, never the reply.** `T` is
/// genesis-frozen: `config/consensus_constants.json` generates the C++ header
/// and this crate's constant from one source, so a value arriving over the
/// wire is a second source for something that has exactly one — and on the
/// remote arm it is a second source supplied by a daemon that could report
/// anything.
///
/// The reported value is not ignored, though. If it differs, the interesting
/// fact is the *disagreement*: a daemon running a different `T` is running
/// different consensus rules, which is a different chain, not a display
/// difference. So this returns the authority plus a warning to print, and the
/// caller renders the warning beside its numbers rather than quietly using
/// one value or the other.
///
/// This is a narrow, local check. The general instrument — a version
/// handshake at connect, and a digest over the whole constants file so a
/// constant nobody thought to compare is still covered — is a separate round;
/// it is not built here, and this comment is not a claim that it is.
pub(super) fn daa_target_seconds(reported: u64) -> (u64, Option<String>) {
    let authority = crate::consensus::DAA_TARGET_SECONDS;
    if reported == authority {
        (authority, None)
    } else {
        (
            authority,
            Some(format!(
                "WARNING: this daemon reports a block target of {reported}s, but this \
                 build's consensus constants say {authority}s. Those are different \
                 consensus rules, so this is very likely a different chain or a \
                 mismatched binary. Figures below use {authority}s."
            )),
        )
    }
}

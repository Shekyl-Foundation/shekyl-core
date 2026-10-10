// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `/get_info`, as the console reads it.
//!
//! Four commands read this method: `status`, `print_blockchain_info` (its
//! negative-start form), `print_blockchain_dynamic_stats` and
//! `alt_chain_info`; and three that render almost nothing else: `diff`,
//! `version` and `print_pool_stats`. Until RK-5c they shared one bridged leg
//! and a provisional struct holding exactly the fields they read. The method
//! is native now, so they share the method itself and its one reply type
//! ([`shekyl_rpc_types::GetInfoResponse`]).
//!
//! The property the provisional struct was built to hand over is kept, and
//! is no longer this module's to keep: a renamed or removed member is a
//! decode error naming it, never a confident zero, because the shared type
//! defaults nothing.

use shekyl_rpc_types::{GetInfoResponse, RestErrorEnvelope};

use super::Source;
use crate::info::Disclosure;
use crate::info_facts::FfiInfoFacts;

/// One `get_info`, on whichever arm the console is running.
///
/// In-process, the method is called directly. The operator at the daemon's
/// own console is the host's administrator, so the disclosure is
/// [`Disclosure::FULL`]. There is no transport on that arm and so no
/// connection count to pass; no console command reads
/// `rpc_connections_count`, and `0` here is "not counted", not a count.
///
/// Remote, it is one `POST /get_info` to whichever listener the operator
/// named, which answers with what that listener discloses.
pub(super) fn fetch_get_info(src: &Source) -> Result<GetInfoResponse, String> {
    let reply = match src {
        Source::Live(core) => {
            let facts = FfiInfoFacts::new(core.clone());
            crate::info::get_info(&facts, Disclosure::FULL, 0).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { .. } => {
            let raw = src.post_remote("/get_info", b"{}".to_vec())?;
            return decode_get_info_ok(&raw);
        }
    };
    ok_or_status(reply)
}

/// A `/get_info` body decoded strictly, refused unless its status is OK.
///
/// For the one caller that fetches the body itself: `version`, which asks
/// without the identity handshake.
pub(super) fn decode_get_info_ok(raw: &[u8]) -> Result<GetInfoResponse, String> {
    ok_or_status(decode_get_info(raw)?)
}

fn ok_or_status(reply: GetInfoResponse) -> Result<GetInfoResponse, String> {
    if reply.status.is_ok() {
        Ok(reply)
    } else {
        Err(reply.status.0)
    }
}

/// The reply, else the daemon's error envelope, else a malformed-reply error
/// that says what did not decode. The serde message is kept because it names
/// the member: "missing field `height`" is what an operator on a version
/// skew needs to read.
fn decode_get_info(raw: &[u8]) -> Result<GetInfoResponse, String> {
    match serde_json::from_slice::<GetInfoResponse>(raw) {
        Ok(reply) => Ok(reply),
        Err(shape) => match serde_json::from_slice::<RestErrorEnvelope>(raw) {
            Ok(envelope) => Err(format!("get_info failed: {}", envelope.error)),
            Err(_) => Err(format!("malformed get_info reply: {shape}")),
        },
    }
}

/// The network's name as the status line prints it. A fakechain reads as
/// mainnet there, as it always has: the line distinguished testnet and
/// stagenet and called everything else mainnet.
pub(super) const fn network_label(nettype: shekyl_rpc_types::DaemonNetwork) -> &'static str {
    match nettype {
        shekyl_rpc_types::DaemonNetwork::Testnet => "testnet",
        shekyl_rpc_types::DaemonNetwork::Stagenet => "stagenet",
        shekyl_rpc_types::DaemonNetwork::Mainnet | shekyl_rpc_types::DaemonNetwork::Fakechain => {
            "mainnet"
        }
    }
}

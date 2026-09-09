// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Remote-arm identity handshake (`VC-3`).
//!
//! Comparison is [`shekyl_rpc_types::IdentityExpectation::check`]. This
//! module fetches `get_version` over the blocking control transport and
//! formats the refusal.

use shekyl_rpc_types::{
    core_rpc_version_string, DaemonNetwork, GetVersionResponse, IdentityExpectation,
    IdentityMismatch,
};

use crate::ctl_client;

use super::{json_rpc_result, Source};

impl Source {
    /// Run the identity handshake once, then reuse its verdict (`VC-3`).
    pub(super) fn ensure_identity(&self) -> Result<(), String> {
        match self {
            Source::Live(_) => Ok(()),
            Source::Remote { checked, .. } => checked.get_or_init(|| handshake(self)).clone(),
        }
    }

    /// POST on the remote arm. The identity handshake runs first.
    ///
    /// Live arm: an internal error — call the native method instead.
    pub(super) fn post_remote(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, String> {
        let (address, timeout) = match self {
            Source::Live(_) => {
                return Err("internal: remote POST on the live console arm".to_owned())
            }
            Source::Remote {
                address, timeout, ..
            } => (address.as_str(), *timeout),
        };
        self.ensure_identity()?;
        ctl_client::post_blocking(address, path, body, timeout).map_err(|(_, reason)| reason)
    }
}

fn handshake(src: &Source) -> Result<(), String> {
    let (address, timeout, nettype) = match src {
        Source::Live(_) => return Ok(()),
        Source::Remote {
            address,
            timeout,
            nettype,
            ..
        } => (address.as_str(), *timeout, *nettype),
    };
    let network = DaemonNetwork::from_cryptonote(nettype).ok_or_else(|| {
        format!(
            "refusing to render: this console was given network code {nettype}, which this \
             build does not know. It cannot say what it expects, so it will not compare."
        )
    })?;

    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": "0", "method": "get_version", "params": {},
    }))
    .map_err(|e| format!("cannot encode the handshake request: {e}"))?;
    let raw = ctl_client::post_blocking(address, "/json_rpc", body, timeout)
        .map_err(|(_, reason)| reason)?;

    let theirs: GetVersionResponse = match json_rpc_result(&raw, "get_version") {
        Ok(reply) => reply,
        Err(reason) if reason.starts_with("get_version failed:") => {
            return Err(reason);
        }
        Err(reason) => {
            return Err(console_identity_message(&IdentityMismatch::unreadable(
                reason,
            )))
        }
    };

    IdentityExpectation::exact(network)
        .check(&theirs)
        .map_err(|m| console_identity_message(&m))
}

fn console_identity_message(m: &IdentityMismatch) -> String {
    match m {
        IdentityMismatch::Wire { ours, theirs } => {
            let older = if theirs < ours {
                "daemon"
            } else {
                "this build"
            };
            format!(
                "refusing to render: RPC contract mismatch. This build is {}, the daemon is {} — \
                 the {older} is the older one; update it.",
                core_rpc_version_string(*ours),
                core_rpc_version_string(*theirs),
            )
        }
        IdentityMismatch::WireUnreadable { ours, evidence } => format!(
            "refusing to render: this daemon's `get_version` does not match the RPC \
             contract this build was compiled against, so the two are on different RPC \
             versions. This build is {}. The reply could not be read, so the daemon's \
             version cannot be named here; align the two builds. (evidence: {evidence})",
            core_rpc_version_string(*ours),
        ),
        IdentityMismatch::Rules { ours, theirs } => format!(
            "refusing to render: consensus-constant mismatch. This build's digest is {ours}, \
             the daemon's is {theirs}. The RPC contract matches, so neither side is a stale \
             release — one tree's config/ differs from the other, which is a different rule \
             set rather than a version skew. Compare config/consensus_constants.json and \
             config/economics_params.json between the two builds.",
        ),
        IdentityMismatch::Network { ours, theirs } => format!(
            "refusing to render: network mismatch. This console is for {ours}, the \
             daemon runs {theirs}. Point at a {ours} daemon, or pass the flag for \
             {theirs}."
        ),
        IdentityMismatch::Genesis {
            ours,
            theirs,
            network,
        } => format!(
            "refusing to render: genesis mismatch. This daemon's chain starts at {theirs}, \
             this build's {network} genesis is {ours}. Whatever else agrees, that is a \
             different chain."
        ),
    }
}

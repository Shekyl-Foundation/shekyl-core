// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Remote-arm identity handshake (`VC-3`).
//!
//! Decode and comparison are [`shekyl_rpc_types::IdentityExpectation::read`]. This
//! module fetches `get_version` over the blocking control transport and
//! formats the refusal.

use shekyl_rpc_types::{
    core_rpc_version_string, DaemonNetwork, IdentityExpectation, IdentityMismatch,
};

use super::{json_rpc_result, Source};

impl Source {
    /// Run the identity handshake once, then reuse its verdict (`VC-3`).
    pub(super) fn ensure_identity(&self) -> Result<(), String> {
        self.network().map(|_| ())
    }

    /// The daemon's network, from the one place a daemon names it (RK-Q6):
    /// what it answered `get_version` with, kept from the identity handshake.
    pub(super) fn network(&self) -> Result<DaemonNetwork, String> {
        self.checked
            .get_or_init(|| handshake(self.rpc(), self.nettype()))
            .clone()
    }

    /// POST. The identity handshake runs first.
    pub(super) fn post_remote(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, String> {
        self.ensure_identity()?;
        self.rpc()
            .post(path, body)
            .map_err(|error| error.to_string())
    }
}

/// The identity handshake against a remote daemon. Its verdict is the
/// network the daemon reported, which the expectation has checked is this
/// console's own.
fn handshake(rpc: &shekyl_rpc_transport::SyncDaemon, nettype: u8) -> Result<DaemonNetwork, String> {
    let network = DaemonNetwork::from_cryptonote(nettype).ok_or_else(|| {
        format!(
            "refusing to render: this console was given network code {nettype}, which this \
             build does not know. It cannot say what it expects, so it will not compare."
        )
    })?;

    let result = get_version_result(rpc)?;
    IdentityExpectation::exact(network)
        .read(&result)
        .map(|reply| reply.nettype)
        .map_err(|refusal| {
            let message = console_identity_message(&refusal.mismatch);
            match refusal.evidence {
                Some(evidence) => format!("{message} (evidence: {evidence})"),
                None => message,
            }
        })
}

/// `get_version`'s `result`, undecoded, with no identity check before it.
///
/// Undecoded because reading it is `shekyl_rpc_types`' (`RK-D25`): the
/// handshake hands it to [`IdentityExpectation::read`], and the `version`
/// command to [`shekyl_rpc_types::daemon_rpc_version`]. A daemon that
/// answers with a JSON-RPC error is reported in its own words.
pub(super) fn get_version_result(
    rpc: &shekyl_rpc_transport::SyncDaemon,
) -> Result<serde_json::Value, String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": "0", "method": "get_version", "params": {},
    }))
    .map_err(|e| format!("cannot encode the handshake request: {e}"))?;
    let raw = rpc
        .post("/json_rpc", body)
        .map_err(|error| error.to_string())?;
    json_rpc_result(&raw, "get_version").map_err(|reason| {
        if reason.starts_with("get_version failed:") {
            reason
        } else {
            format!(
                "{} (evidence: {reason})",
                console_identity_message(&IdentityMismatch::unreadable())
            )
        }
    })
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
        IdentityMismatch::WireUnreadable { ours } => format!(
            "refusing to render: this daemon's `get_version` does not match the RPC \
             contract this build was compiled against, so the two are on different RPC \
             versions. This build is {}. The reply could not be read, so the daemon's \
             version cannot be named here; align the two builds.",
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

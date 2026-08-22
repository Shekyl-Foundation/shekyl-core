// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-tip and version methods — the RK-1 slice of the daemon RPC KV
//! cutover (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.1).
//!
//! These are the single Rust definitions of the wire types that
//! `COMMAND_RPC_GET_HEIGHT` and `COMMAND_RPC_GET_VERSION` used to carry in
//! C++. Field names are the wire names; `u64` serializes as a JSON number
//! (as epee did); hashes are lowercase hex strings; every C++
//! `KV_SERIALIZE_OPT(field, default)` is mirrored by
//! `#[serde(default, skip_serializing_if = …)]` so an older client sees an
//! identical document. Unknown fields are tolerated on deserialize (no
//! `deny_unknown_fields`) — additive daemon-side evolution must not break an
//! older wallet. Parity against the captured epee output is pinned by
//! `tests/rpc_parity.rs` over `tests/vectors/rpc/` (RK-D4).

use serde::{Deserialize, Serialize};

/// `CORE_RPC_VERSION_MAJOR` — moved here from
/// `src/rpc/core_rpc_server_commands_defs.h` with `get_version`, its only
/// reader (RK-D8).
pub const CORE_RPC_VERSION_MAJOR: u32 = 3;
/// `CORE_RPC_VERSION_MINOR`. 3.22: `untrusted` dropped from every response,
/// `get_info` bootstrap fields dropped, `set_bootstrap_daemon` /
/// `get_public_nodes` deleted, advertised `rpc_port` / `rpc_credits_per_hash`
/// dropped from the peer readouts (PR #533). A wire change bumps this and is
/// recorded in the design doc; the KV cutover itself never does.
pub const CORE_RPC_VERSION_MINOR: u32 = 22;
/// `MAKE_CORE_RPC_VERSION(major, minor)` = `(major << 16) | minor`.
pub const CORE_RPC_VERSION: u32 = (CORE_RPC_VERSION_MAJOR << 16) | CORE_RPC_VERSION_MINOR;

/// The `status` string every daemon reply carries (`rpc_response_base`).
///
/// One type for the three values C++ spelled as three macros
/// (`CORE_RPC_STATUS_OK` / `BUSY` / `NOT MINING`) and for the free-text error
/// statuses handlers emit; clients branch on [`RpcStatus::is_ok`], never on a
/// string literal of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpcStatus(pub String);

impl RpcStatus {
    /// `"OK"`.
    pub const OK: &'static str = "OK";
    /// `"BUSY"` — the core is not ready to answer.
    pub const BUSY: &'static str = "BUSY";

    /// The success status.
    #[must_use]
    pub fn ok() -> Self {
        Self(Self::OK.to_owned())
    }

    /// Whether this reply succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.0 == Self::OK
    }
}

/// The REST error envelope a natively-served endpoint answers with when it
/// cannot produce its reply (HTTP 500): `status` is never `OK`, and `error`
/// names what failed (diagnostic text — RK-D8 scope — not contract). The
/// transport sends the body whatever the HTTP status, so a client that wants
/// the reason decodes this when the success type does not fit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestErrorEnvelope {
    pub status: RpcStatus,
    pub error: String,
}

/// Response of `GET|POST /get_height` (alias `/getheight`). The request body
/// is empty (and ignored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetHeightResponse {
    pub status: RpcStatus,
    /// Chain height: the top block's height **plus one** (a chain holding
    /// only the genesis block reports `1`).
    pub height: u64,
    /// The top block's hash, 64 lowercase hex characters.
    pub hash: String,
}

/// One row of [`GetVersionResponse::hard_forks`]: the version that activates
/// at `height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardForkEntry {
    pub hf_version: u8,
    pub height: u64,
}

/// Result of the `get_version` JSON-RPC method (no params).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetVersionResponse {
    pub status: RpcStatus,
    /// [`CORE_RPC_VERSION`] of the answering daemon.
    pub version: u32,
    /// Whether the daemon is a release build (`SHEKYL_VERSION_IS_RELEASE`).
    pub release: bool,
    /// Current chain height. Omitted on the wire when `0`
    /// (`KV_SERIALIZE_OPT(current_height, 0)`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub current_height: u64,
    /// Height the daemon is syncing towards; `0` — and omitted — once
    /// synchronized (`KV_SERIALIZE_OPT(target_height, 0)`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub target_height: u64,
    /// The hard-fork schedule. Omitted on the wire when empty
    /// (`KV_SERIALIZE_OPT(hard_forks, {})`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hard_forks: Vec<HardForkEntry>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero(v: &u64) -> bool {
    *v == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_rpc_version_packs_like_the_cpp_macro() {
        // MAKE_CORE_RPC_VERSION(3, 22) == 0x0003_0016 == 196630, the value the
        // captured get_version vectors carry.
        assert_eq!(CORE_RPC_VERSION, 196_630);
    }

    #[test]
    fn error_envelope_round_trips() {
        let e = RestErrorEnvelope {
            status: RpcStatus("ERROR".to_owned()),
            error: "chain facts unavailable".to_owned(),
        };
        let wire = serde_json::to_string(&e).unwrap();
        assert_eq!(
            wire,
            r#"{"status":"ERROR","error":"chain facts unavailable"}"#
        );
        let back: RestErrorEnvelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, e);
        assert!(!back.status.is_ok());
    }

    #[test]
    fn status_is_transparent_on_the_wire() {
        assert_eq!(serde_json::to_string(&RpcStatus::ok()).unwrap(), r#""OK""#);
        let busy: RpcStatus = serde_json::from_str(r#""BUSY""#).unwrap();
        assert!(!busy.is_ok());
        assert_eq!(busy.0, RpcStatus::BUSY);
    }
}

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

use crate::hash::HashHex;

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

/// JSON-RPC error code for a malformed request (`CORE_RPC_ERROR_CODE_WRONG_PARAM`).
///
/// This and [`CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT`] are the codes a client
/// branches on, so they live with the wire types. `src/rpc/core_rpc_server_error_codes.h`
/// still spells them for the ~26 handlers that remain in C++; that header is
/// deleted at RK-X, leaving these as the only definition.
pub const CORE_RPC_ERROR_CODE_WRONG_PARAM: i64 = -1;
/// JSON-RPC error code for a height at or past the chain tip
/// (`CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT`).
pub const CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT: i64 = -2;
/// JSON-RPC error code for a daemon-side failure the method has a contract
/// for (`CORE_RPC_ERROR_CODE_INTERNAL_ERROR`) — e.g. a store that reports a
/// height it cannot produce the block for.
pub const CORE_RPC_ERROR_CODE_INTERNAL_ERROR: i64 = -5;

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
    /// The top block's hash.
    pub hash: HashHex,
}

/// Result of the `get_block_count` JSON-RPC method (alias `getblockcount`).
/// Params are ignored, as the C++ handler ignored its positional list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockCountResponse {
    pub status: RpcStatus,
    /// Chain height — the block *count*, i.e. top block height plus one.
    pub count: u64,
}

/// Positional params of `on_get_block_hash` (alias `on_getblockhash`):
/// exactly one height, e.g. `[1234]`.
///
/// The arity and element type are the deserializer's job, not a hand-written
/// parser's: `[u64; 1]` refuses `[]`, `[1,2]`, `["1"]` and `[-1]` structurally,
/// and each of those is the method's `WRONG_PARAM` refusal.
///
/// The reply has no type of its own — `on_get_block_hash` answers with a bare
/// JSON string (the block hash as 64 lowercase hex characters), not an object,
/// and carries no `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockHashParams(pub [u64; 1]);

/// The daemon's block header — the wire's `block_header_response`, shared by
/// every header-bearing method (RK-3 serves `get_block_header_by_height`;
/// `get_block`, `get_last_block_header`, `…_by_hash` and `…_range` reuse this
/// type as they migrate).
///
/// The 128-bit difficulties are carried the way the C++ wire carried them:
/// the low 64 bits as a number, the whole value as `0x`-prefixed minimal
/// lowercase hex, and the top 64 bits separately — three fields, one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_hash: HashHex,
    pub nonce: u32,
    pub orphan_status: bool,
    pub height: u64,
    /// Distance from the tip: `chain_height - height - 1`.
    pub depth: u64,
    pub hash: HashHex,
    /// Low 64 bits of the block's difficulty.
    pub difficulty: u64,
    /// The whole 128-bit difficulty, `0x`-prefixed minimal lowercase hex.
    pub wide_difficulty: String,
    /// High 64 bits of the block's difficulty.
    pub difficulty_top64: u64,
    pub cumulative_difficulty: u64,
    pub wide_cumulative_difficulty: String,
    pub cumulative_difficulty_top64: u64,
    /// Sum of the miner transaction's outputs.
    pub reward: u64,
    /// Always equal to `block_weight`; kept because the wire carries both,
    /// and unlike `block_weight` it is not omitted at zero.
    pub block_size: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub block_weight: u64,
    pub num_txes: u64,
    /// `None` unless the request asked for it **and** the listener is
    /// unrestricted. epee renders that absence as `""`, not as a missing
    /// field — see [`empty_string_as_absent`](crate::hash::empty_string_as_absent).
    #[serde(with = "crate::hash::empty_string_as_absent")]
    pub pow_hash: Option<HashHex>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub long_term_weight: u64,
    pub miner_tx_hash: HashHex,
    pub curve_tree_root: HashHex,
    pub attestation_root: HashHex,
}

/// Params of `get_block_header_by_height` (alias `getblockheaderbyheight`).
///
/// Both fields default, reproducing epee's KV load: a field absent from the
/// request was left at its default rather than refused, so `{}` asks for
/// height 0. Making *that* strict is a wire change and belongs to RK-W.
///
/// Only absence defaults, though. epee also swallowed a field of the wrong
/// type — `KV_SERIALIZE` discards the load's result — and answered
/// `{"height": "nope"}` with the genesis header; the server refuses that
/// instead (`daemon_rpc::methods::block_header_request`), which is where the
/// object-only rule lives too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockHeaderByHeightRequest {
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub fill_pow_hash: bool,
}

/// Result of `get_block_header_by_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockHeaderByHeightResponse {
    pub status: RpcStatus,
    pub block_header: BlockHeader,
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

    /// The params type is the arity/type check: every shape the C++ handler
    /// answered `WRONG_PARAM` for is a deserialize failure here, and a valid
    /// `[height]` is the height. Widening the type (to `Vec<u64>`, say) turns
    /// the refusal cases green — which is the edit this guards.
    #[test]
    fn block_hash_params_accept_one_height_and_nothing_else() {
        let ok: GetBlockHashParams = serde_json::from_str("[1234]").unwrap();
        assert_eq!(ok.0[0], 1234);
        for bad in ["[]", "[1,2]", r#"["1"]"#, "[-1]", "1234", "{}", "null"] {
            assert!(
                serde_json::from_str::<GetBlockHashParams>(bad).is_err(),
                "{bad} must not parse as one height"
            );
        }
    }

    /// Absent fields take their defaults, as epee's KV load did — `{}` is a
    /// request for height 0, not a refusal.
    #[test]
    fn header_request_fields_default_like_the_kv_load() {
        let empty: GetBlockHeaderByHeightRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, GetBlockHeaderByHeightRequest::default());
        let only_height: GetBlockHeaderByHeightRequest =
            serde_json::from_str(r#"{"height":9}"#).unwrap();
        assert_eq!(only_height.height, 9);
        assert!(!only_height.fill_pow_hash);
    }

    #[test]
    fn status_is_transparent_on_the_wire() {
        assert_eq!(serde_json::to_string(&RpcStatus::ok()).unwrap(), r#""OK""#);
        let busy: RpcStatus = serde_json::from_str(r#""BUSY""#).unwrap();
        assert!(!busy.is_ok());
        assert_eq!(busy.0, RpcStatus::BUSY);
    }
}

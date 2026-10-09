// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_shard_view`: one archival shard's view as the wallet contract
//! returns it, and the mapping from the daemon's `request_archival_shard`
//! answer onto it (`docs/design/SHARD_VIEW_FETCH.md` §4 step 4).
//!
//! The wallet holds no archival bytes a daemon can read, so every view —
//! including a shard this wallet itself serves — is answered by the daemon
//! the wallet is configured with: it fetches the body from a holder, folds
//! the view hash (`SV-D1`) and returns the aggregate. The wallet forwards
//! `shard_id` and projects the answer. Nothing here renders; the renderer
//! (`shekyl-shard-visual`) takes the aggregate fields this result carries.
//!
//! The daemon's three refusals keep their meaning across the hop, each on
//! its own wallet code, so a viewer shows the state and never an empty
//! picture (rule 82): still open (`-29534`), closed but no holder served it
//! (`-29535`), and this daemon does not serve views at all (`-29536`). A
//! transport failure is the daemon-unreachable code every other method
//! uses; a malformed reply is the protocol-violation code.

use serde::{Deserialize, Serialize};
use shekyl_rpc_client::{JsonRpcRefusal, Rpc, RpcError};
use shekyl_rpc_types::{
    RequestArchivalShardRequest, RequestArchivalShardResponse,
    CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN, CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT,
    CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE, CORE_RPC_ERROR_CODE_RESTRICTED,
};

use crate::error::{from_daemon_fault, WalletRpcError};

/// The method's name in the contract — the one spelling the wallet server
/// dispatches on and an embedder's command adapter is held to.
pub const GET_SHARD_VIEW: &str = "get_shard_view";

/// `get_shard_view`'s parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetShardViewParams {
    /// The shard to view (`SHT-Q2`: the `W`-byte archival partition's id).
    pub shard_id: u64,
}

/// `get_shard_view`'s result: `request_archival_shard`'s aggregate without
/// the daemon's `status` envelope. Every field is a deterministic function
/// of the shard's body and the public skeleton (`SV-D4`); the renderer's
/// input type is held to the same admissibility rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardViewResult {
    /// The shard viewed.
    pub shard_id: u64,
    /// The view hash folded over the fetched archival bytes (`SV-D1`),
    /// lowercase hex of 32 bytes. What the picture is drawn from.
    pub shard_hash: String,
    /// Archival bytes the body carried.
    pub archival_len: u64,
    /// Blocks the shard's transactions span, inclusive.
    pub block_count: u64,
    /// Transactions in the shard.
    pub tx_count: u64,
    /// Outputs of those transactions plus the span's coinbase outputs.
    pub output_count: u64,
    /// Coinbase outputs across the span's blocks.
    pub coinbase_output_count: u64,
    /// Last block's timestamp minus the first's, in seconds.
    pub time_range_seconds: u64,
    /// The block that closed the shard. Two views of one id that differ
    /// here are views across a reorg; a viewer caching by id keys on this.
    pub close_height: u64,
}

impl From<RequestArchivalShardResponse> for ShardViewResult {
    fn from(r: RequestArchivalShardResponse) -> Self {
        Self {
            shard_id: r.shard_id,
            shard_hash: r.shard_hash.to_string(),
            archival_len: r.archival_len,
            block_count: r.block_count,
            tx_count: r.tx_count,
            output_count: r.output_count,
            coinbase_output_count: r.coinbase_output_count,
            time_range_seconds: r.time_range_seconds,
            close_height: r.close_height,
        }
    }
}

/// Why a daemon does not serve shard views (`-29536`'s `data.cause`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardViewNotOfferedCause {
    /// The method is admin-only (`SV-D6`) and the wallet reached a public
    /// listener. The wallet's own node, on its unrestricted listener,
    /// answers.
    Restricted,
    /// The daemon holds no archival skeleton and so serves no view
    /// (`SV-D9`): it runs on a store that cannot place a shard boundary.
    SkeletonAbsent,
}

impl ShardViewNotOfferedCause {
    /// The wire spelling, as `data.cause` carries it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restricted => "restricted",
            Self::SkeletonAbsent => "skeleton_absent",
        }
    }
}

/// The daemon method the wallet forwards to.
const REQUEST_ARCHIVAL_SHARD: &str = "request_archival_shard";

/// Ask `daemon` for one shard's view: the whole of `get_shard_view` after
/// parameter parsing, shared by the wallet server and an embedding wallet
/// so the two cannot map one daemon refusal to two wallet codes.
///
/// The call blocks for the fetch — the daemon draws a holder, pulls the
/// body and verifies it before it answers — so a caller holds no lock
/// across it.
pub async fn fetch_shard_view<D: Rpc>(
    daemon: &D,
    shard_id: u64,
) -> Result<ShardViewResult, WalletRpcError> {
    let params = serde_json::to_value(RequestArchivalShardRequest { shard_id }).map_err(|e| {
        WalletRpcError::InternalError(format!("encode {REQUEST_ARCHIVAL_SHARD}: {e}"))
    })?;
    shard_view_from_daemon(
        daemon
            .json_rpc_call_or_refusal::<RequestArchivalShardResponse>(
                REQUEST_ARCHIVAL_SHARD,
                Some(params),
            )
            .await,
    )
}

/// The daemon's `request_archival_shard` answer, mapped onto the contract.
///
/// `answer` is what [`shekyl_rpc_client::Rpc::json_rpc_call_or_refusal`]
/// returns: the outer `Err` is the transport, the inner the daemon's typed
/// refusal. A refusal code outside the method's three is the daemon
/// breaking its contract — `-29209`, never a guess at a nearer code.
pub fn shard_view_from_daemon(
    answer: Result<Result<RequestArchivalShardResponse, JsonRpcRefusal>, RpcError>,
) -> Result<ShardViewResult, WalletRpcError> {
    match answer {
        Ok(Ok(response)) => Ok(response.into()),
        Ok(Err(refusal)) => Err(shard_view_refusal(refusal)),
        Err(transport) => Err(from_daemon_fault(transport.fault(), &transport.to_string())),
    }
}

/// One daemon refusal to one wallet code.
fn shard_view_refusal(refusal: JsonRpcRefusal) -> WalletRpcError {
    let JsonRpcRefusal { code, message } = refusal;
    match code {
        CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN => {
            WalletRpcError::ShardStillOpen { detail: message }
        }
        CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE => {
            WalletRpcError::ShardUnavailable { detail: message }
        }
        CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT => WalletRpcError::ShardViewNotOffered {
            cause: ShardViewNotOfferedCause::SkeletonAbsent,
            detail: message,
        },
        CORE_RPC_ERROR_CODE_RESTRICTED => WalletRpcError::ShardViewNotOffered {
            cause: ShardViewNotOfferedCause::Restricted,
            detail: message,
        },
        other => {
            tracing::warn!(
                code = other,
                detail = %message,
                "request_archival_shard refused with a code outside its contract"
            );
            WalletRpcError::DaemonProtocolViolation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;
    use shekyl_rpc_types::{HashHex, RpcStatus};

    fn response() -> RequestArchivalShardResponse {
        RequestArchivalShardResponse {
            status: RpcStatus::ok(),
            shard_id: 3,
            shard_hash: HashHex::from_hex(&"ab".repeat(32)).unwrap(),
            archival_len: 3_000_000,
            block_count: 41,
            tx_count: 900,
            output_count: 1_900,
            coinbase_output_count: 41,
            time_range_seconds: 4_800,
            close_height: 12_345,
        }
    }

    #[test]
    fn the_result_is_the_daemon_aggregate_without_its_status() {
        let view = shard_view_from_daemon(Ok(Ok(response()))).unwrap();
        assert_eq!(
            view,
            ShardViewResult {
                shard_id: 3,
                shard_hash: "ab".repeat(32),
                archival_len: 3_000_000,
                block_count: 41,
                tx_count: 900,
                output_count: 1_900,
                coinbase_output_count: 41,
                time_range_seconds: 4_800,
                close_height: 12_345,
            }
        );
        // The wire carries no `status` member: a viewer deserializing into
        // the renderer's aggregate type sees only shard fields.
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("status").is_none());
        assert_eq!(json["close_height"], 12_345);
    }

    #[test]
    fn each_daemon_refusal_keeps_its_meaning_on_its_own_wallet_code() {
        let refused = |code: i64| {
            shard_view_from_daemon(Ok(Err(JsonRpcRefusal {
                code,
                message: format!("daemon said {code}"),
            })))
            .unwrap_err()
        };

        let open = refused(CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN);
        assert_eq!(open.code(), WalletRpcErrorCode::ShardStillOpen);
        assert_eq!(open.data().unwrap()["detail"], "daemon said -24");

        let miss = refused(CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE);
        assert_eq!(miss.code(), WalletRpcErrorCode::ShardUnavailable);

        let absent = refused(CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT);
        assert_eq!(absent.code(), WalletRpcErrorCode::ShardViewNotOffered);
        assert_eq!(absent.data().unwrap()["cause"], "skeleton_absent");

        let public = refused(CORE_RPC_ERROR_CODE_RESTRICTED);
        assert_eq!(public.code(), WalletRpcErrorCode::ShardViewNotOffered);
        assert_eq!(public.data().unwrap()["cause"], "restricted");
    }

    #[test]
    fn a_code_outside_the_contract_is_a_protocol_violation_not_a_guess() {
        let err = shard_view_from_daemon(Ok(Err(JsonRpcRefusal {
            code: -5,
            message: "internal".to_owned(),
        })))
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::DaemonProtocolViolation);
    }

    #[test]
    fn the_transport_is_the_daemon_unreachable_code() {
        let err = shard_view_from_daemon(Err(RpcError::ConnectionError("refused".to_owned())))
            .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::DaemonUnreachable);
    }

    #[test]
    fn params_take_exactly_the_shard_id() {
        let ok: GetShardViewParams = serde_json::from_str(r#"{"shard_id":9}"#).unwrap();
        assert_eq!(ok.shard_id, 9);
        assert!(serde_json::from_str::<GetShardViewParams>(r#"{"shard_id":9,"size":4}"#).is_err());
        assert!(serde_json::from_str::<GetShardViewParams>(r#"{}"#).is_err());
    }
}

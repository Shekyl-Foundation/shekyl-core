// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_shard_view`: one archival shard's view as the wallet contract
//! returns it, and the mapping from the daemon's `shard_fetch` answer onto
//! it (`docs/design/SHARD_VIEW_FETCH.md` §4 step 4).
//!
//! The wallet holds no archival bytes a daemon can read, so every view —
//! including a shard this wallet itself serves — is answered by the daemon
//! the wallet is configured with: it fetches the body from a holder, folds
//! the view hash (`SV-D1`) and returns the aggregate. The wallet forwards
//! `shard_id` and projects the answer. Nothing here renders; the renderer
//! (`shekyl-shard-visual`) takes the aggregate fields this result carries.
//!
//! The daemon's refusals keep their meaning across the hop, each on its
//! own wallet code, so a viewer shows the state and never an empty picture
//! (rule 82): still open (`shard.open`, `-29534`), closed but no holder
//! served it (`shard.unavailable`, `-29535`), this daemon does not serve
//! views to this wallet at all (`shard.tor-off`, or
//! the call outside the wallet's grant: `-29536`), and the daemon is
//! already fetching one for a bounded caller (`bound.shard`, `-29537`).
//! The refusal is read by its class and its dotted code, never its
//! message. A transport failure is the
//! daemon-unreachable code every other method uses; a malformed reply is
//! the protocol-violation code.

use serde::{Deserialize, Serialize};
use shekyl_rpc_client::{wire, ErrorClass, Refusal, Rpc, RpcError};
use shekyl_rpc_types::kinds::Integer;
use shekyl_rpc_types::wire::archival::{ShardId, ShardView};

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

/// `get_shard_view`'s result: `shard_fetch`'s aggregate, in the wallet
/// contract's names. Every field is a deterministic function
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
    /// The block that closed the shard: where it sits on the chain, and
    /// the height a rendering-spec version pins to. Not a cache key — a
    /// viewer keys on `(shard_id, shard_hash)`, because a reorg at this
    /// very height changes the hash and leaves the height where it was.
    pub close_height: u64,
}

impl From<ShardView> for ShardViewResult {
    fn from(r: ShardView) -> Self {
        Self {
            shard_id: r.id.0,
            shard_hash: r.hash.to_string(),
            archival_len: r.size.0,
            block_count: r.block_count.0,
            tx_count: r.tx_count.0,
            output_count: r.output_count.0,
            coinbase_output_count: r.coinbase_output_count.0,
            time_range_seconds: r.duration.0,
            close_height: r.closing_height.0,
        }
    }
}

/// Why a daemon does not serve shard views (`-29536`'s `data.cause`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardViewNotOfferedCause {
    /// The call is outside the wallet's grant on this daemon (`SV-D6`).
    /// The wallet's own node, on a connection that holds the grant,
    /// answers.
    Restricted,
    /// The daemon runs with Tor off and has no client to fetch a shard
    /// through (IG-Q90).
    TorOff,
}

impl ShardViewNotOfferedCause {
    /// The wire spelling, as `data.cause` carries it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restricted => "restricted",
            Self::TorOff => "tor_off",
        }
    }
}

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
    shard_view_from_daemon(
        daemon
            .call_or_refusal::<wire::ShardFetch>(ShardId {
                id: Integer(shard_id),
            })
            .await,
    )
}

/// The daemon's `shard_fetch` answer, mapped onto the contract.
///
/// `answer` is what [`shekyl_rpc_client::Rpc::call_or_refusal`] returns:
/// the outer `Err` is the transport, the inner the daemon's typed refusal.
/// A refusal outside the method's own is the daemon breaking its contract —
/// `-29209`, never a guess at a nearer code.
pub fn shard_view_from_daemon(
    answer: Result<Result<ShardView, Refusal>, RpcError>,
) -> Result<ShardViewResult, WalletRpcError> {
    match answer {
        Ok(Ok(view)) => Ok(view.into()),
        Ok(Err(refusal)) => Err(shard_view_refusal(&refusal)),
        Err(transport) => Err(from_daemon_fault(transport.fault(), &transport.to_string())),
    }
}

/// One daemon refusal to one wallet code, by its class and dotted code.
fn shard_view_refusal(refusal: &Refusal) -> WalletRpcError {
    let detail = refusal.diagnostic.message.clone();
    match (refusal.class, refusal.diagnostic.code.as_str()) {
        (ErrorClass::RefusedByMethod, "shard.open") => WalletRpcError::ShardStillOpen { detail },
        (ErrorClass::RefusedByMethod, "shard.unavailable") => {
            WalletRpcError::ShardUnavailable { detail }
        }
        (ErrorClass::RefusedByMethod, "shard.tor-off") => WalletRpcError::ShardViewNotOffered {
            cause: ShardViewNotOfferedCause::TorOff,
            detail,
        },
        (ErrorClass::OverResourceBound, "bound.shard") => WalletRpcError::ShardViewBusy { detail },
        (ErrorClass::OutsideTheGrant, _) => WalletRpcError::ShardViewNotOffered {
            cause: ShardViewNotOfferedCause::Restricted,
            detail,
        },
        (class, code) => {
            tracing::warn!(
                ?class,
                code,
                detail = %detail,
                "shard_fetch refused outside its contract"
            );
            WalletRpcError::DaemonProtocolViolation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;
    use shekyl_rpc_client::Diagnostic;
    use shekyl_rpc_types::hash::HashHex;
    use shekyl_rpc_types::kinds::{Count, Duration, Height, Size};

    fn view() -> ShardView {
        ShardView {
            id: Integer(3),
            hash: HashHex::from_hex(&"ab".repeat(32)).unwrap(),
            size: Size(3_000_000),
            block_count: Count(41),
            tx_count: Count(900),
            output_count: Count(1_900),
            coinbase_output_count: Count(41),
            duration: Duration(4_800),
            closing_height: Height(12_345),
        }
    }

    fn refused(class: ErrorClass, code: &str) -> WalletRpcError {
        shard_view_from_daemon(Ok(Err(Refusal::new(
            class,
            Diagnostic::new(code, format!("daemon said {code}")),
        ))))
        .unwrap_err()
    }

    #[test]
    fn the_result_is_the_daemon_aggregate_in_the_contracts_names() {
        let view = shard_view_from_daemon(Ok(Ok(view()))).unwrap();
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
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("status").is_none());
        assert_eq!(json["close_height"], 12_345);
    }

    /// Each refusal keeps its meaning on its own wallet code, read by class
    /// and dotted code. Red edit: map by message, fold `shard.tor-off` into
    /// `-29535`, or fold `bound.shard` into `-29535`.
    #[test]
    fn each_daemon_refusal_keeps_its_meaning_on_its_own_wallet_code() {
        let open = refused(ErrorClass::RefusedByMethod, "shard.open");
        assert_eq!(open.code(), WalletRpcErrorCode::ShardStillOpen);
        assert_eq!(open.data().unwrap()["detail"], "daemon said shard.open");

        let miss = refused(ErrorClass::RefusedByMethod, "shard.unavailable");
        assert_eq!(miss.code(), WalletRpcErrorCode::ShardUnavailable);

        let outside = refused(ErrorClass::OutsideTheGrant, "grant.outside");
        assert_eq!(outside.code(), WalletRpcErrorCode::ShardViewNotOffered);
        assert_eq!(outside.data().unwrap()["cause"], "restricted");

        let tor_off = refused(ErrorClass::RefusedByMethod, "shard.tor-off");
        assert_eq!(tor_off.code(), WalletRpcErrorCode::ShardViewNotOffered);
        assert_eq!(tor_off.data().unwrap()["cause"], "tor_off");

        let busy = refused(ErrorClass::OverResourceBound, "bound.shard");
        assert_eq!(busy.code(), WalletRpcErrorCode::ShardViewBusy);
        assert_eq!(busy.data().unwrap()["detail"], "daemon said bound.shard");
        assert_eq!(
            refused(ErrorClass::RefusedByMethod, "bound.shard").code(),
            WalletRpcErrorCode::DaemonProtocolViolation,
            "a bound under another class is outside the contract"
        );
    }

    #[test]
    fn a_refusal_outside_the_contract_is_a_protocol_violation_not_a_guess() {
        for (class, code) in [
            (ErrorClass::Internal, "daemon.internal"),
            (ErrorClass::RefusedByMethod, "shard.something-new"),
            // No daemon writes it: the skeleton-absent refusal is deleted.
            (ErrorClass::RefusedByMethod, "shard.view-absent"),
            (ErrorClass::NotReady, "shard.open"),
        ] {
            assert_eq!(
                refused(class, code).code(),
                WalletRpcErrorCode::DaemonProtocolViolation,
                "{class:?} {code}"
            );
        }
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

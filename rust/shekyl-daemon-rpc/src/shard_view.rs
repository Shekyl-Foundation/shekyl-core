// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The shard view's facts source (`SHARD_VIEW_FETCH.md` `SV-D3`, `SV-D9`).
//!
//! `request_archival_shard` asks one question — *this shard's view, or the
//! reason there is none* — and the answer comes through [`ShardViewFacts`],
//! a trait with one production implementation at a time (`RK-D7`). The
//! implementation that reads a body from a holder lives in the daemon
//! image, not here: this crate may not reach the fetch client
//! (`check_p_fetch_dep_cut.py` holds every `*rpc*` crate out of it), so the
//! RPC sees a view or a refusal and never a socket.
//!
//! The implementation this crate ships is [`SkeletonAbsent`]: the daemon
//! today runs on a store with no shard-range read and no bond-record read,
//! so no `ViewDesk` can be composed over it and the honest answer to every
//! request is that this daemon serves no shard view. That is a statement
//! about the daemon, made as a typed refusal with its own code — not a
//! "not yet" and not a MISS dressed as a fetch (`23-disposition-visibility`).
//! `SV-D9` names what lifts it.

use std::future::Future;
use std::pin::Pin;

use shekyl_rpc_types::{
    HashHex, RequestArchivalShardRequest, RequestArchivalShardResponse, RpcStatus,
    CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN, CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT,
    CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE,
};
use shekyl_types::{ArchivalLength, ShardId, ShardView};

use crate::chain_facts::FactsFault;
use crate::methods::{RpcFault, RpcRefusal};

/// The answer to one `request_archival_shard`, boxed so a trait object can
/// return it without an `async-trait` dependency.
pub type ShardViewFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ShardView, ShardViewRefusal>> + Send + 'a>>;

/// Why no view was produced. Each arm is a state a viewer shows, never a
/// blank (`SV-D5`, rule 82); each maps to its own JSON-RPC code in
/// `methods::request_archival_shard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardViewRefusal {
    /// The shard is still filling, or lies past the tip. Nothing was
    /// fetched. `remaining_to_close` is how many archival bytes the open
    /// shard still needs when `shard_id` *is* the open shard; `None` for an
    /// id beyond it.
    Open {
        shard_id: ShardId,
        open_shard: ShardId,
        remaining_to_close: Option<ArchivalLength>,
    },
    /// The shard is closed and no holder served it this time. `attempts`
    /// is how many dials were made; what each one returned is the daemon's
    /// log (`SF-D12`), not the wire's.
    Unavailable { shard_id: ShardId, attempts: usize },
    /// This daemon holds no archival skeleton and serves no shard view.
    SkeletonAbsent,
    /// The facts source itself failed; answered as the facts fault it is.
    Fault(FactsFault),
}

/// What `request_archival_shard` reads (`RK-D7`: one trait, one production
/// implementation, chosen by the composition root).
pub trait ShardViewFacts: Send + Sync {
    /// The view of `shard_id`, or why there is none.
    fn view(&self, shard_id: ShardId) -> ShardViewFuture<'_>;
}

/// The facts of a daemon that holds no archival skeleton.
///
/// Every request is refused as [`ShardViewRefusal::SkeletonAbsent`]. The
/// default when no composition root supplied another implementation —
/// which, until `SV-D9` lifts, is every daemon.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkeletonAbsent;

impl ShardViewFacts for SkeletonAbsent {
    fn view(&self, _shard_id: ShardId) -> ShardViewFuture<'_> {
        Box::pin(std::future::ready(Err(ShardViewRefusal::SkeletonAbsent)))
    }
}

/// Parse `request_archival_shard`'s params. `shard_id` is required: there
/// is no default shard, so a null or empty params object is a wrong
/// parameter, not a request for shard 0.
///
/// # Errors
///
/// [`RpcFault::Refused`] with `CORE_RPC_ERROR_CODE_WRONG_PARAM` when the
/// params are not an object carrying exactly `shard_id`.
pub fn request_archival_shard_request(
    params: &serde_json::Value,
) -> Result<RequestArchivalShardRequest, RpcFault> {
    const EXPECTED: &str = "Wrong parameters, expected an object with shard_id (an integer)";
    match params {
        serde_json::Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|_| RpcFault::Refused(RpcRefusal::wrong_param(EXPECTED))),
        _ => Err(RpcFault::Refused(RpcRefusal::wrong_param(EXPECTED))),
    }
}

/// `request_archival_shard` (`SV-D3`): the view of one closed shard, read
/// through `facts`, or one of the three typed refusals.
///
/// # Errors
///
/// - [`ShardViewRefusal::Open`] → `CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN`,
///   with how far the open shard is from closing when that is the shard asked
///   for;
/// - [`ShardViewRefusal::Unavailable`] → `CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE`;
/// - [`ShardViewRefusal::SkeletonAbsent`] → `CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT`;
/// - [`ShardViewRefusal::Fault`] → the facts fault, as every native method
///   reports one.
pub async fn request_archival_shard(
    facts: &dyn ShardViewFacts,
    request: RequestArchivalShardRequest,
) -> Result<RequestArchivalShardResponse, RpcFault> {
    match facts.view(ShardId::from_raw(request.shard_id)).await {
        Ok(view) => Ok(project(&view)),
        Err(refusal) => Err(refuse(&refusal)),
    }
}

fn project(view: &ShardView) -> RequestArchivalShardResponse {
    RequestArchivalShardResponse {
        status: RpcStatus::ok(),
        shard_id: view.shard_id.to_raw(),
        shard_hash: HashHex::from_bytes(view.shard_hash.to_bytes()),
        archival_len: view.archival_len.to_raw(),
        block_count: view.block_count.to_raw(),
        tx_count: view.tx_count,
        output_count: view.output_count,
        coinbase_output_count: view.coinbase_output_count,
        time_range_seconds: view.time_range_seconds,
        close_height: view.close_height.to_raw(),
    }
}

fn refuse(refusal: &ShardViewRefusal) -> RpcFault {
    match refusal {
        ShardViewRefusal::Open {
            shard_id,
            open_shard,
            remaining_to_close,
        } => RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN,
            message: match remaining_to_close {
                Some(remaining) => format!(
                    "shard {} is still filling: {} archival bytes to close",
                    shard_id.to_raw(),
                    remaining.to_raw()
                ),
                None => format!(
                    "shard {} does not exist yet: shard {} is the one filling",
                    shard_id.to_raw(),
                    open_shard.to_raw()
                ),
            },
        }),
        ShardViewRefusal::Unavailable { shard_id, attempts } => RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE,
            message: format!(
                "could not retrieve shard {} this time ({attempts} holder(s) tried)",
                shard_id.to_raw()
            ),
        }),
        ShardViewRefusal::SkeletonAbsent => RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT,
            message: "this daemon holds no archival skeleton and serves no shard view".to_owned(),
        }),
        ShardViewRefusal::Fault(fault) => RpcFault::Facts(*fault),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use shekyl_rpc_types::CORE_RPC_ERROR_CODE_WRONG_PARAM;
    use shekyl_types::{BlockCount, BlockHeight, ShardViewHash};

    /// A facts source scripted with one answer, so the method's mapping is
    /// tested against every arm without a scheduler behind it.
    struct Scripted(Result<ShardView, ShardViewRefusal>);

    impl ShardViewFacts for Scripted {
        fn view(&self, _shard_id: ShardId) -> ShardViewFuture<'_> {
            Box::pin(std::future::ready(self.0.clone()))
        }
    }

    fn view() -> ShardView {
        ShardView {
            shard_id: ShardId::from_raw(3),
            shard_hash: ShardViewHash::from_bytes([0x5a; 32]),
            archival_len: ArchivalLength::from_raw(3_000_000),
            block_count: BlockCount::from_raw(11),
            tx_count: 2,
            output_count: 13,
            coinbase_output_count: 11,
            time_range_seconds: 1_200,
            close_height: BlockHeight::from_raw(9_000),
        }
    }

    fn code_of(fault: &RpcFault) -> i64 {
        match fault {
            RpcFault::Refused(r) => r.code,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_absent_skeleton_refuses_every_shard_the_same_way() {
        let facts = SkeletonAbsent;
        for id in [0u64, 1, u64::MAX] {
            assert_eq!(
                facts.view(ShardId::from_raw(id)).await,
                Err(ShardViewRefusal::SkeletonAbsent)
            );
        }
    }

    #[test]
    fn shard_id_is_required_and_nothing_else_is_accepted() {
        for params in [
            json!(null),
            json!({}),
            json!([3]),
            json!({"shard_id": "3"}),
            json!({"shard_id": 3, "fill": true}),
            json!({"shard_id": -1}),
        ] {
            let fault = request_archival_shard_request(&params).unwrap_err();
            assert_eq!(code_of(&fault), CORE_RPC_ERROR_CODE_WRONG_PARAM, "{params}");
        }
        assert_eq!(
            request_archival_shard_request(&json!({"shard_id": 3})).unwrap(),
            RequestArchivalShardRequest { shard_id: 3 }
        );
    }

    #[tokio::test]
    async fn a_view_is_projected_field_for_field() {
        let facts = Scripted(Ok(view()));
        let response = request_archival_shard(&facts, RequestArchivalShardRequest { shard_id: 3 })
            .await
            .unwrap();
        assert_eq!(response.status, RpcStatus::ok());
        assert_eq!(response.shard_id, 3);
        assert_eq!(response.shard_hash, HashHex::from_bytes([0x5a; 32]));
        assert_eq!(response.archival_len, 3_000_000);
        assert_eq!(response.block_count, 11);
        assert_eq!(response.tx_count, 2);
        assert_eq!(response.output_count, 13);
        assert_eq!(response.coinbase_output_count, 11);
        assert_eq!(response.time_range_seconds, 1_200);
        assert_eq!(response.close_height, 9_000);
    }

    #[tokio::test]
    async fn each_refusal_has_its_own_code() {
        let cases = [
            (
                ShardViewRefusal::Open {
                    shard_id: ShardId::from_raw(4),
                    open_shard: ShardId::from_raw(4),
                    remaining_to_close: Some(ArchivalLength::from_raw(10)),
                },
                CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN,
            ),
            (
                ShardViewRefusal::Open {
                    shard_id: ShardId::from_raw(9),
                    open_shard: ShardId::from_raw(4),
                    remaining_to_close: None,
                },
                CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN,
            ),
            (
                ShardViewRefusal::Unavailable {
                    shard_id: ShardId::from_raw(3),
                    attempts: 3,
                },
                CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE,
            ),
            (
                ShardViewRefusal::SkeletonAbsent,
                CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT,
            ),
        ];
        for (refusal, code) in cases {
            let facts = Scripted(Err(refusal.clone()));
            let fault = request_archival_shard(&facts, RequestArchivalShardRequest { shard_id: 3 })
                .await
                .unwrap_err();
            assert_eq!(code_of(&fault), code, "{refusal:?}");
        }
    }

    #[tokio::test]
    async fn a_facts_fault_is_reported_as_one() {
        let facts = Scripted(Err(ShardViewRefusal::Fault(FactsFault::NotReady)));
        assert_eq!(
            request_archival_shard(&facts, RequestArchivalShardRequest { shard_id: 3 })
                .await
                .unwrap_err(),
            RpcFault::Facts(FactsFault::NotReady)
        );
    }
}

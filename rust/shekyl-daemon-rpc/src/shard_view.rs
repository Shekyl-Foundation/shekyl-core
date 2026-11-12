// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The shard view's facts source (`SHARD_VIEW_FETCH.md` `SV-D3`, `SV-D9`).
//!
//! `shard_fetch` asks one question — *this shard's view, or the
//! reason there is none* — and the answer comes through [`ShardViewFacts`],
//! a trait with one production implementation at a time (`RK-D7`). The
//! implementation that reads a body from a holder lives in the daemon
//! image, not here: this crate may not reach the fetch client
//! (`check_p_fetch_dep_cut.py` holds every `*rpc*` crate out of it), so the
//! RPC sees a view or a refusal and never a socket.
//!
//! The node composes the implementation: a view desk over its fetch
//! scheduler when it runs a Tor, and [`TorOff`] when it does not — a node
//! with no Tor has no client to read a shard through (IG-Q90). A bounded
//! caller's flight is bounded by the desk (`RPC_CHANNEL.md` §6.3), and a
//! refused one is [`ShardViewRefusal::Busy`].

use std::future::Future;
use std::pin::Pin;

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::kinds::{Count, Duration, Height, Integer, Size};
use shekyl_rpc_types::wire::archival;
use shekyl_rpc_types::HashHex;
use shekyl_types::{ArchivalLength, ShardId, ShardView};

use crate::chain_facts::FactsFault;
use crate::methods::RpcFault;

/// The shard view's diagnostic codes (`INPUT_GRAMMAR.md` IG-Q86).
pub mod codes {
    /// The shard is still filling, or lies past the tip.
    pub const OPEN: &str = "shard.open";
    /// The shard is closed and no holder served it this time.
    pub const UNAVAILABLE: &str = "shard.unavailable";
    /// This daemon holds no archival skeleton and serves no shard view.
    pub const VIEW_ABSENT: &str = "shard.view-absent";
    /// This node runs with Tor off and has no client to read a shard
    /// through (IG-Q90).
    pub const TOR_OFF: &str = "shard.tor-off";
}

/// The answer to one `shard_fetch`, boxed so a trait object can
/// return it without an `async-trait` dependency.
pub type ShardViewFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ShardView, ShardViewRefusal>> + Send + 'a>>;

/// Why no view was produced. Each arm is a state a viewer shows, never a
/// blank (`SV-D5`, rule 82); each maps to its own class and dotted code in
/// [`shard_fetch`].
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
    /// This node runs with Tor off: it has no client to read a shard
    /// through.
    TorOff,
    /// A bounded caller would open a flight while another bounded
    /// caller's holds the one permit (IG-Q90). Nothing was fetched or
    /// queued.
    Busy { shard_id: ShardId },
    /// The facts source itself failed; answered as the facts fault it is.
    Fault(FactsFault),
}

/// What `shard_fetch` reads (`RK-D7`: one trait, one production
/// implementation, chosen by the composition root).
pub trait ShardViewFacts: Send + Sync {
    /// The view of `shard_id`, or why there is none. A `bounded` caller
    /// that would open a flight takes the one bounded permit (IG-Q90).
    fn view(&self, shard_id: ShardId, bounded: bool) -> ShardViewFuture<'_>;
}

/// A shard-view handle.
pub type ShardViewHandle = std::sync::Arc<dyn ShardViewFacts>;

/// The facts of a daemon that holds no archival skeleton.
///
/// Every request is refused as [`ShardViewRefusal::SkeletonAbsent`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkeletonAbsent;

impl ShardViewFacts for SkeletonAbsent {
    fn view(&self, _shard_id: ShardId, _bounded: bool) -> ShardViewFuture<'_> {
        Box::pin(std::future::ready(Err(ShardViewRefusal::SkeletonAbsent)))
    }
}

/// The facts of a node that runs with Tor off: every request is refused
/// as [`ShardViewRefusal::TorOff`], never as an absent skeleton (IG-Q90).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TorOff;

impl ShardViewFacts for TorOff {
    fn view(&self, _shard_id: ShardId, _bounded: bool) -> ShardViewFuture<'_> {
        Box::pin(std::future::ready(Err(ShardViewRefusal::TorOff)))
    }
}

/// No node was supplied: every request is not ready, as every other
/// absent handle's is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShardViewAbsent;

impl ShardViewFacts for ShardViewAbsent {
    fn view(&self, _shard_id: ShardId, _bounded: bool) -> ShardViewFuture<'_> {
        Box::pin(std::future::ready(Err(ShardViewRefusal::Fault(
            FactsFault::NotReady,
        ))))
    }
}

/// `shard_fetch` (`SV-D3`): the view of one closed shard, read
/// through `facts`, or a typed refusal. `bounded` is the caller's
/// (`RPC_CHANNEL.md` §6.3).
///
/// # Errors
///
/// - [`ShardViewRefusal::Open`] → `RefusedByMethod`, `shard.open`, with how
///   far the open shard is from closing when that is the shard asked for;
/// - [`ShardViewRefusal::Unavailable`] → `RefusedByMethod`,
///   `shard.unavailable`;
/// - [`ShardViewRefusal::SkeletonAbsent`] → `RefusedByMethod`,
///   `shard.view-absent`;
/// - [`ShardViewRefusal::TorOff`] → `RefusedByMethod`, `shard.tor-off`;
/// - [`ShardViewRefusal::Busy`] → `OverResourceBound`, `bound.shard`;
/// - [`ShardViewRefusal::Fault`] → the facts fault, as every native method
///   reports one;
/// - a view whose `shard_id` is not the one asked for →
///   [`FactsFault::Inconsistent`]. The facts source answers for the shard it
///   was asked about; a view of another shard is the source contradicting
///   itself (a cache or adapter mix-up), and it is reported as this daemon's
///   fault rather than projected as a fact about the request.
pub async fn shard_fetch(
    facts: &dyn ShardViewFacts,
    request: archival::ShardId,
    bounded: bool,
) -> Result<archival::ShardView, RpcFault> {
    let asked = ShardId::from_raw(request.id.0);
    match facts.view(asked, bounded).await {
        Ok(view) if view.shard_id == asked => Ok(project(&view)),
        Ok(view) => {
            tracing::error!(
                asked = asked.to_raw(),
                answered = view.shard_id.to_raw(),
                "shard view facts answered for a different shard"
            );
            Err(RpcFault::Facts(FactsFault::Inconsistent))
        }
        Err(refusal) => Err(refuse(&refusal)),
    }
}

fn project(view: &ShardView) -> archival::ShardView {
    archival::ShardView {
        id: Integer(view.shard_id.to_raw()),
        hash: HashHex::from_bytes(view.shard_hash.to_bytes()),
        size: Size(view.archival_len.to_raw()),
        block_count: Count(view.block_count.to_raw()),
        tx_count: Count(view.tx_count),
        output_count: Count(view.output_count),
        coinbase_output_count: Count(view.coinbase_output_count),
        duration: Duration(view.time_range_seconds),
        closing_height: Height(view.close_height.to_raw()),
    }
}

fn refuse(refusal: &ShardViewRefusal) -> RpcFault {
    let refused = |code: &str, message: String| {
        RpcFault::Refused(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(code, message),
        ))
    };
    match refusal {
        ShardViewRefusal::Open {
            shard_id,
            open_shard,
            remaining_to_close,
        } => {
            let message = match remaining_to_close {
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
            };
            let mut diagnostic = Diagnostic::new(codes::OPEN, message)
                .param("id", shard_id.to_raw().to_string())
                .param("open", open_shard.to_raw().to_string());
            if let Some(remaining) = remaining_to_close {
                diagnostic = diagnostic.param("remaining", remaining.to_raw().to_string());
            }
            RpcFault::Refused(RpcError::new(ErrorClass::RefusedByMethod, diagnostic))
        }
        ShardViewRefusal::Unavailable { shard_id, attempts } => RpcFault::Refused(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(
                codes::UNAVAILABLE,
                format!(
                    "could not retrieve shard {} this time ({attempts} holder(s) tried)",
                    shard_id.to_raw()
                ),
            )
            .param("id", shard_id.to_raw().to_string())
            .param("attempts", attempts.to_string()),
        )),
        ShardViewRefusal::SkeletonAbsent => refused(
            codes::VIEW_ABSENT,
            "this daemon holds no archival skeleton and serves no shard view".to_owned(),
        ),
        ShardViewRefusal::TorOff => refused(
            codes::TOR_OFF,
            "this node runs with Tor off and has no client to fetch a shard through".to_owned(),
        ),
        ShardViewRefusal::Busy { shard_id } => RpcFault::Refused(RpcError::new(
            ErrorClass::OverResourceBound,
            Diagnostic::new(
                crate::methods::codes::BOUND_SHARD,
                format!(
                    "a bounded connection may have one shard fetch in flight, and one is; \
                     shard {} was not fetched",
                    shard_id.to_raw()
                ),
            )
            .param("id", shard_id.to_raw().to_string())
            // IG-Q79: one flight in total; this asked for a second.
            .param("bound", "1")
            .param("asked", "2"),
        )),
        ShardViewRefusal::Fault(fault) => RpcFault::Facts(*fault),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use shekyl_rpc_types::errors::ErrorClass;
    use shekyl_rpc_types::kinds::Integer;
    use shekyl_types::{BlockCount, BlockHeight, ShardViewHash};

    /// A facts source scripted with one answer, so the method's mapping is
    /// tested against every arm without a scheduler behind it.
    struct Scripted(Result<ShardView, ShardViewRefusal>);

    impl ShardViewFacts for Scripted {
        fn view(&self, _shard_id: ShardId, _bounded: bool) -> ShardViewFuture<'_> {
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

    fn shard(id: u64) -> archival::ShardId {
        archival::ShardId { id: Integer(id) }
    }

    #[tokio::test]
    async fn the_absent_skeleton_refuses_every_shard_the_same_way() {
        let facts = SkeletonAbsent;
        for id in [0u64, 1, u64::MAX] {
            assert_eq!(
                facts.view(ShardId::from_raw(id), true).await,
                Err(ShardViewRefusal::SkeletonAbsent)
            );
        }
    }

    /// A node with Tor off refuses as Tor off, for every caller, never as
    /// an absent skeleton (IG-Q90); no node at all is not ready.
    #[tokio::test]
    async fn tor_off_and_no_node_each_refuse_as_what_they_are() {
        for bounded in [false, true] {
            let error = shard_fetch(&TorOff, shard(3), bounded)
                .await
                .unwrap_err()
                .into_error();
            assert_eq!(
                (error.class, error.diagnostic.code.as_str()),
                (ErrorClass::RefusedByMethod, codes::TOR_OFF)
            );
            assert_eq!(
                shard_fetch(&ShardViewAbsent, shard(3), bounded).await,
                Err(RpcFault::Facts(FactsFault::NotReady))
            );
        }
    }

    /// `id` is required and nothing else is accepted: the request is the
    /// strict wire type, refused at the envelope as `rpc.params`.
    #[test]
    fn id_is_required_and_nothing_else_is_accepted() {
        for params in [
            json!(null),
            json!({}),
            // A positional array never reaches the type: the envelope refuses
            // it as `rpc.envelope` (`handlers::rpc` tests).
            json!({"id": "3"}),
            json!({"id": 3, "fill": true}),
            json!({"id": -1}),
            json!({"shard_id": 3}),
        ] {
            assert!(
                serde_json::from_value::<archival::ShardId>(params.clone()).is_err(),
                "{params}"
            );
        }
        assert_eq!(
            serde_json::from_value::<archival::ShardId>(json!({"id": 3})).unwrap(),
            shard(3)
        );
    }

    #[tokio::test]
    async fn a_view_is_projected_field_for_field() {
        let facts = Scripted(Ok(view()));
        let response = shard_fetch(&facts, shard(3), true).await.unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({
                "id": 3,
                "hash": "5a".repeat(32),
                "size": 3_000_000,
                "block_count": 11,
                "tx_count": 2,
                "output_count": 13,
                "coinbase_output_count": 11,
                "duration": 1_200,
                "closing_height": 9_000,
            })
        );
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
                codes::OPEN,
            ),
            (
                ShardViewRefusal::Open {
                    shard_id: ShardId::from_raw(9),
                    open_shard: ShardId::from_raw(4),
                    remaining_to_close: None,
                },
                codes::OPEN,
            ),
            (
                ShardViewRefusal::Unavailable {
                    shard_id: ShardId::from_raw(3),
                    attempts: 3,
                },
                codes::UNAVAILABLE,
            ),
            (ShardViewRefusal::SkeletonAbsent, codes::VIEW_ABSENT),
            (ShardViewRefusal::TorOff, codes::TOR_OFF),
        ];
        for (refusal, code) in cases {
            let facts = Scripted(Err(refusal.clone()));
            let error = shard_fetch(&facts, shard(3), true)
                .await
                .unwrap_err()
                .into_error();
            assert_eq!(error.class, ErrorClass::RefusedByMethod, "{refusal:?}");
            assert_eq!(error.diagnostic.code, code, "{refusal:?}");
        }
        // The bounded permit's refusal is a bound, not the method's.
        let facts = Scripted(Err(ShardViewRefusal::Busy {
            shard_id: ShardId::from_raw(3),
        }));
        let error = shard_fetch(&facts, shard(3), true)
            .await
            .unwrap_err()
            .into_error();
        assert_eq!(error.class, ErrorClass::OverResourceBound);
        assert_eq!(error.diagnostic.code, crate::methods::codes::BOUND_SHARD);
        assert_eq!(error.diagnostic.parameter["id"], "3");
        assert_eq!(error.diagnostic.parameter["bound"], "1");
        assert_eq!(error.diagnostic.parameter["asked"], "2");
    }

    #[tokio::test]
    async fn a_view_of_another_shard_is_the_facts_contradicting_themselves() {
        // The scripted source answers shard 3 to every question.
        let facts = Scripted(Ok(view()));
        assert_eq!(
            shard_fetch(&facts, shard(4), true).await.unwrap_err(),
            RpcFault::Facts(FactsFault::Inconsistent)
        );
    }

    #[tokio::test]
    async fn a_facts_fault_is_reported_as_one() {
        let facts = Scripted(Err(ShardViewRefusal::Fault(FactsFault::NotReady)));
        assert_eq!(
            shard_fetch(&facts, shard(3), true).await.unwrap_err(),
            RpcFault::Facts(FactsFault::NotReady)
        );
    }
}

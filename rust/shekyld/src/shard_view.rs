// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The shard view's RPC adapter (`SHARD_VIEW_FETCH.md` `SV-D9`).
//!
//! [`DeskViewFacts`] is the `ShardViewFacts` implementor the falsifier
//! names: a [`ViewDesk`] over the store-backed facts
//! (`shekyl_chain_ingest::shard_facts::{StoreShardFacts, StoreHolderSource}`),
//! mapped onto the RPC refusal type. The facts are the fetch scheduler's,
//! shared with the bundle producer's reads, so they live where the node's
//! store and the scheduler meet. Production `ServerConfig` still defaults
//! to [`SkeletonAbsent`](shekyl_daemon_rpc::shard_view::SkeletonAbsent)
//! until the daemon opens this store (`DRS-E3`).

use shekyl_archival_fetch_sched::{FactsFault, HolderSource, ShardFacts, ViewDesk, ViewRefusal};
use shekyl_daemon_rpc::shard_view::{ShardViewFacts, ShardViewFuture, ShardViewRefusal};
use shekyl_types::ShardId;

use shekyl_daemon_rpc::chain_facts::FactsFault as RpcFactsFault;

/// A [`ViewDesk`] answering `request_archival_shard` (`SV-D9`).
pub struct DeskViewFacts<F, H> {
    desk: ViewDesk<F, H>,
}

impl<F, H> DeskViewFacts<F, H> {
    /// The desk that produces the view.
    #[must_use]
    pub fn new(desk: ViewDesk<F, H>) -> Self {
        Self { desk }
    }

    /// The desk behind this adapter.
    pub fn desk(&self) -> &ViewDesk<F, H> {
        &self.desk
    }
}

impl<F, H> ShardViewFacts for DeskViewFacts<F, H>
where
    F: ShardFacts,
    H: HolderSource,
{
    fn view(&self, shard_id: ShardId) -> ShardViewFuture<'_> {
        Box::pin(async move { self.desk.view(shard_id).await.map_err(into_refusal) })
    }
}

fn into_refusal(refusal: ViewRefusal) -> ShardViewRefusal {
    match refusal {
        ViewRefusal::Open {
            shard_id,
            open_shard,
            remaining_to_close,
        } => ShardViewRefusal::Open {
            shard_id,
            open_shard,
            remaining_to_close,
        },
        ViewRefusal::Unavailable { shard_id, attempts } => ShardViewRefusal::Unavailable {
            shard_id,
            attempts: attempts.len(),
        },
        ViewRefusal::Local(shekyl_archival_fetch_sched::ReadFailure::Facts(fault)) => {
            ShardViewRefusal::Fault(rpc_fault(fault))
        }
        ViewRefusal::Local(_) => ShardViewRefusal::Fault(RpcFactsFault::Internal),
    }
}

fn rpc_fault(fault: FactsFault) -> RpcFactsFault {
    match fault {
        FactsFault::NotReady => RpcFactsFault::NotReady,
        FactsFault::Inconsistent => RpcFactsFault::Inconsistent,
        FactsFault::Internal => RpcFactsFault::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_ingest::shard_facts::{StoreHolderSource, StoreShardFacts};

    #[test]
    fn desk_view_facts_is_the_sv_d9_implementor() {
        fn assert_impl<T: ShardViewFacts>() {}
        assert_impl::<DeskViewFacts<StoreShardFacts, StoreHolderSource>>();
    }
}

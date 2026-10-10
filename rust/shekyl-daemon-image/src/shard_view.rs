// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! Store-backed shard-view facts (`SHARD_VIEW_FETCH.md` `SV-D9`).
//!
//! [`StoreShardFacts`] and [`StoreHolderSource`] read `shekyl-chain-store`
//! rows: the `SHT-Q2` fold, per-transaction `txid_parts`, and tip bond
//! holdings. [`DeskViewFacts`] is the `ShardViewFacts` implementor the
//! falsifier names — a [`ViewDesk`] over those two, mapped onto the RPC
//! refusal type. Production `ServerConfig` still defaults to
//! [`SkeletonAbsent`](shekyl_daemon_rpc::shard_view::SkeletonAbsent) until
//! the daemon opens this store (`DRS-E3`).

use std::sync::Arc;

use shekyl_archival_fetch_sched::{
    BlockSpan, ClosedShard, ExpectedShard, FactsFault, FetchTarget, Holder, HolderSource,
    ShardClose, ShardFacts, ShardStanding, ViewDesk, ViewRefusal,
};
use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{ChainStore, ErrorClass, ReadSnapshot, StoreError};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_daemon_rpc::shard_view::{ShardViewFacts, ShardViewFuture, ShardViewRefusal};
use shekyl_p_fetch::ServingEndpoint;
use shekyl_types::archival::Holdings;
use shekyl_types::{shard_of, ArchivalLength, BlockHash, BlockHeight, ShardId};
use shekyl_wire::{carries_archival_good, Transaction, TxidParts};

use shekyl_daemon_rpc::chain_facts::FactsFault as RpcFactsFault;

/// The skeleton, read from a chain-store snapshot per call.
pub struct StoreShardFacts {
    store: Arc<ChainStore>,
}

impl StoreShardFacts {
    /// Facts over `store`. Each read opens its own snapshot.
    #[must_use]
    pub fn new(store: Arc<ChainStore>) -> Self {
        Self { store }
    }

    fn snapshot(&self) -> Result<ReadSnapshot<'_>, FactsFault> {
        self.store.begin_read().map_err(|e| store_fault(&e))
    }
}

impl ShardFacts for StoreShardFacts {
    fn tip_height(&self) -> Result<BlockHeight, FactsFault> {
        Ok(self
            .snapshot()?
            .tip()
            .map_err(|e| store_fault(&e))?
            .recorded
            .map_or(BlockHeight::ZERO, |tip| tip.height))
    }

    fn block_hash_at(&self, height: BlockHeight) -> Result<Option<BlockHash>, FactsFault> {
        match self
            .snapshot()?
            .block_info(height)
            .map_err(|e| store_fault(&e))?
        {
            AtHeight::Recorded(info) => Ok(Some(info.hash)),
            AtHeight::AboveTip => Ok(None),
        }
    }

    fn shard(&self, shard_id: ShardId) -> Result<ShardStanding, FactsFault> {
        let snap = self.snapshot()?;
        let Some(tip) = snap.tip().map_err(|e| store_fault(&e))?.recorded else {
            return Ok(ShardStanding::Open {
                open_shard: ShardId::from_raw(0),
                archival_through_tip: ArchivalLength::ZERO,
            });
        };
        let through = recorded(snap.block_info(tip.height).map_err(|e| store_fault(&e))?)?
            .cumulative_archival_len;
        let open_shard = shard_of(through);
        if shard_id >= open_shard {
            return Ok(ShardStanding::Open {
                open_shard,
                archival_through_tip: through,
            });
        }
        let closed = closed_shard(&snap, shard_id, tip.height)?;
        Ok(ShardStanding::Closed(Box::new(closed)))
    }
}

/// Tip bond holdings: who lists `shard_id`, or a CompleteTree.
pub struct StoreHolderSource {
    store: Arc<ChainStore>,
}

impl StoreHolderSource {
    /// Holders over `store`. Each read opens its own snapshot.
    #[must_use]
    pub fn new(store: Arc<ChainStore>) -> Self {
        Self { store }
    }
}

impl HolderSource for StoreHolderSource {
    fn holders_of(&self, shard_id: ShardId) -> Result<Vec<Holder>, FactsFault> {
        let snap = self.store.begin_read().map_err(|e| store_fault(&e))?;
        let mut holders = Vec::new();
        for (id, record) in snap.bond_records().map_err(|e| store_fault(&e))? {
            if !holds_shard(&record.holdings, shard_id) {
                continue;
            }
            let verifying_key = HybridPublicKey::from_canonical_bytes(&record.hybrid_pubkey)
                .map_err(|_| FactsFault::Inconsistent)?;
            holders.push(Holder {
                id,
                target: FetchTarget {
                    endpoint: ServingEndpoint::from_record_bytes(record.endpoint),
                    verifying_key,
                },
            });
        }
        Ok(holders)
    }
}

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

fn holds_shard(holdings: &Holdings, shard_id: ShardId) -> bool {
    match holdings {
        Holdings::CompleteTree => true,
        Holdings::ShardSet(held) => held.iter().any(|h| h.shard == shard_id),
    }
}

fn closed_shard(
    snap: &ReadSnapshot<'_>,
    shard_id: ShardId,
    tip: BlockHeight,
) -> Result<ClosedShard, FactsFault> {
    let mut cum = ArchivalLength::ZERO;
    let mut txs = Vec::new();
    let mut first_cum = None;
    let mut first_h = None;
    let mut last_h = None;
    let mut first_ts = 0;
    let mut last_ts = 0;
    let mut tx_outputs = 0u64;

    for h in 0..=tip.to_raw() {
        let height = BlockHeight::from_raw(h);
        let info = recorded(snap.block_info(height).map_err(|e| store_fault(&e))?)?;
        let body = recorded(snap.block(height).map_err(|e| store_fault(&e))?)?;
        let mut in_domain = false;
        for hash in &body.block.transaction_hashes {
            let record = snap
                .tx_record(hash)
                .map_err(|e| store_fault(&e))?
                .ok_or(FactsFault::Inconsistent)?;
            if shard_of(cum) == shard_id
                && carries_archival_good(record.pqc_auth_hash, record.prunable_hash)
            {
                if first_cum.is_none() {
                    first_cum = Some(cum);
                }
                let outs = Transaction::from_bytes(record.pruned.as_bytes())
                    .map_err(|_| FactsFault::Inconsistent)?
                    .prefix
                    .outputs
                    .len();
                tx_outputs = tx_outputs
                    .checked_add(u64::try_from(outs).expect("output count fits u64"))
                    .ok_or(FactsFault::Inconsistent)?;
                txs.push(TxidParts {
                    hash: *hash,
                    pqc_auth_hash: record.pqc_auth_hash,
                    prunable_hash: record.prunable_hash,
                    archival_len: record.archival_len,
                });
                in_domain = true;
            }
            cum = cum
                .checked_add(record.archival_len)
                .ok_or(FactsFault::Inconsistent)?;
        }
        if in_domain {
            if first_h.is_none() {
                first_h = Some(height);
                first_ts = info.timestamp.to_raw();
            }
            last_h = Some(height);
            last_ts = info.timestamp.to_raw();
        }
    }

    let (first, last) = first_h.zip(last_h).ok_or(FactsFault::Inconsistent)?;
    let mut coinbase_outputs = 0u64;
    for h in first.to_raw()..=last.to_raw() {
        let body = recorded(
            snap.block(BlockHeight::from_raw(h))
                .map_err(|e| store_fault(&e))?,
        )?;
        let n = body.block.miner_transaction.prefix.outputs.len();
        coinbase_outputs = coinbase_outputs
            .checked_add(u64::try_from(n).expect("output count fits u64"))
            .ok_or(FactsFault::Inconsistent)?;
    }

    let expected = ExpectedShard::new(shard_id, first_cum.ok_or(FactsFault::Inconsistent)?, txs)
        .map_err(|_| FactsFault::Inconsistent)?;
    let last_info = recorded(snap.block_info(last).map_err(|e| store_fault(&e))?)?;
    Ok(ClosedShard {
        expected,
        span: BlockSpan {
            first,
            last,
            first_timestamp: first_ts,
            last_timestamp: last_ts,
            coinbase_outputs,
            tx_outputs,
        },
        close: ShardClose {
            height: last,
            hash: last_info.hash,
        },
    })
}

fn recorded<T>(at: AtHeight<T>) -> Result<T, FactsFault> {
    match at {
        AtHeight::Recorded(value) => Ok(value),
        AtHeight::AboveTip => Err(FactsFault::Inconsistent),
    }
}

fn store_fault(err: &StoreError) -> FactsFault {
    match err.class() {
        ErrorClass::Invariant => FactsFault::Inconsistent,
        ErrorClass::Engine | ErrorClass::Cannot => FactsFault::Internal,
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
    use shekyl_types::archival::SettlementEpochBlocks;

    fn empty_store() -> (StoreShardFacts, StoreHolderSource, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "shekyl-sv-d9-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(
            ChainStore::create(
                &path,
                SettlementEpochBlocks::new(10_000).expect("non-zero epoch"),
            )
            .expect("create empty store"),
        );
        (
            StoreShardFacts::new(Arc::clone(&store)),
            StoreHolderSource::new(store),
            path,
        )
    }

    #[test]
    fn an_empty_store_has_an_open_tip_shard_and_no_holders() {
        let (facts, holders, path) = empty_store();
        assert_eq!(facts.tip_height().expect("tip"), BlockHeight::ZERO);
        assert_eq!(facts.block_hash_at(BlockHeight::ZERO).expect("hash"), None);
        match facts.shard(ShardId::from_raw(0)).expect("standing") {
            ShardStanding::Open {
                open_shard,
                archival_through_tip,
            } => {
                assert_eq!(open_shard, ShardId::from_raw(0));
                assert_eq!(archival_through_tip, ArchivalLength::ZERO);
            }
            other => panic!("expected open, got {other:?}"),
        }
        assert!(holders
            .holders_of(ShardId::from_raw(0))
            .expect("holders")
            .is_empty());
        drop(facts);
        drop(holders);
        std::fs::remove_file(path).expect("remove temp store");
    }

    #[test]
    fn desk_view_facts_is_the_sv_d9_implementor() {
        fn assert_impl<T: ShardViewFacts>() {}
        assert_impl::<DeskViewFacts<StoreShardFacts, StoreHolderSource>>();
    }
}

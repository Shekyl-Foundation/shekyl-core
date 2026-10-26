// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! Store-backed facts for the daemon's fetch scheduler (`SHARD_VIEW_FETCH.md`
//! `SV-D9`).
//!
//! [`StoreShardFacts`] and [`StoreHolderSource`] read `shekyl-chain-store`
//! rows: the `SHT-Q2` fold, per-transaction `txid_parts`, and tip bond
//! holdings. They are the scheduler's production [`ShardFacts`] and
//! [`HolderSource`], read by both of the scheduler's daemon callers: the
//! shard view (`shekyl-daemon-image`'s `shard_view`, which maps a view onto
//! the RPC) and the bundle producer's challenge reads (`SO-D12` increment
//! 4c), which the node composes. Here, behind the `producer` feature,
//! because this crate is where the node's store and the scheduler meet; the
//! wallet-side image, which links this crate without it, has neither.

use std::sync::Arc;

use shekyl_archival_fetch_sched::{
    BlockSpan, ClosedShard, ExpectedShard, FactsFault, FetchTarget, Holder, HolderSource,
    ServingEndpoint, ShardClose, ShardFacts, ShardStanding,
};
use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{ChainStore, ErrorClass, ReadSnapshot, ShardFold, StoreError};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_types::archival::Holdings;
use shekyl_types::{BlockHash, BlockHeight, ShardId};

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
        standing(snap.shard_fold(shard_id).map_err(|e| store_fault(&e))?)
    }
}

/// Tip bond holdings. Drawn holders list the shard. A complete tree is
/// a support source, tried only after those (`ARCHIVAL_SUPPORT_DRAW.md` §7).
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
            if !holds_drawn(&record.holdings, shard_id) {
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

    fn support_holders_of(&self, shard_id: ShardId) -> Result<Vec<Holder>, FactsFault> {
        let snap = self.store.begin_read().map_err(|e| store_fault(&e))?;
        let mut holders = Vec::new();
        for (id, record) in snap.bond_records().map_err(|e| store_fault(&e))? {
            if !matches!(record.holdings, Holdings::CompleteTree) {
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
        let _ = shard_id;
        Ok(holders)
    }
}

fn holds_drawn(holdings: &Holdings, shard_id: ShardId) -> bool {
    match holdings {
        Holdings::CompleteTree => false,
        Holdings::ShardSet(held) => held.iter().any(|h| h.shard == shard_id),
    }
}

fn standing(fold: ShardFold) -> Result<ShardStanding, FactsFault> {
    match fold {
        ShardFold::Open {
            open_shard,
            archival_through_tip,
        } => Ok(ShardStanding::Open {
            open_shard,
            archival_through_tip,
        }),
        ShardFold::Closed(rows) => {
            let expected = ExpectedShard::new(rows.shard_id, rows.cum_before_first, rows.txs)
                .map_err(|_| FactsFault::Inconsistent)?;
            Ok(ShardStanding::Closed(Box::new(ClosedShard {
                expected,
                span: BlockSpan {
                    first: rows.first,
                    last: rows.last,
                    first_timestamp: rows.first_timestamp,
                    last_timestamp: rows.last_timestamp,
                    coinbase_outputs: rows.coinbase_outputs,
                    tx_outputs: rows.tx_outputs,
                },
                close: ShardClose {
                    height: rows.last,
                    hash: rows.close_hash,
                },
            })))
        }
    }
}

fn store_fault(err: &StoreError) -> FactsFault {
    match err.class() {
        ErrorClass::Invariant => FactsFault::Inconsistent,
        ErrorClass::Engine | ErrorClass::Cannot => FactsFault::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::archival::SettlementEpochBlocks;
    use shekyl_types::ArchivalLength;

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
}

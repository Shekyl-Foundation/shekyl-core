// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node's handle implementations. Each reads a slot [`crate::Node::stop`]
//! clears, so a handle held past the stop answers not ready instead of a
//! zero.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::service::{ArrivalTag, Door, Refusal, Reply, Rewinder, ServiceFault};
use shekyl_chain_ingest::{ProductionSubstrate, Rewound, TipChanged};
use shekyl_chain_sync::SyncState;
use shekyl_daemon_rpc::chain_facts::{
    BlockAt, BlockHashAt, BlockHeaderAt, BlockLookup, ChainFacts, ChainTip, DaemonIdentity,
    FactsFault, FeeEstimate,
};
use shekyl_daemon_rpc::handles::{BansFacts, DoorFacts, PoolFacts, StopFacts};
use shekyl_daemon_rpc::info_facts::{
    InfoChainFacts, InfoFacts, InfoStatusFacts, PeerFacts, PoolCounts, PoolScope, SessionCounts,
};
use shekyl_daemon_rpc::mining_facts::{LocalOutcome, Pending, PopOutcome};
use shekyl_daemon_rpc::read_facts::{
    AltChainFacts, ChainReadFacts, ClaimSource, CoinbaseRange, CurveTreeFacts, PowAt, PowSeed,
    ShardCoverage,
};
use shekyl_daemon_rpc::store_facts::{NodeFacts, StoreFacts, SyncFacts};
use shekyl_mempool::Pool;
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId};

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the chain store does not hold. It does not own the facts slot, so
/// dropping the facts drops this and not the other way round.
pub(crate) struct Surroundings {
    pub(crate) pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>,
    pub(crate) data_dir: PathBuf,
    pub(crate) offline: bool,
    /// Chain sync's state: the watch the follower reads.
    pub(crate) sync: tokio::sync::watch::Receiver<SyncState>,
}

impl NodeFacts for Surroundings {
    fn sync(&self) -> Result<SyncFacts, FactsFault> {
        // Chain sync's state, the one the follower posts on (DX-Q3, Q13).
        // `following_degraded` is the latch the flip writes into the store.
        let state = *self.sync.borrow();
        Ok(SyncFacts {
            target: None,
            synchronized: state == SyncState::Synced,
            busy_syncing: matches!(
                state,
                SyncState::Behind { .. } | SyncState::Following { .. }
            ),
            offline: self.offline,
            following_degraded: false,
        })
    }

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault> {
        let slot = lock(&self.pool);
        let Some(pool) = slot.as_ref() else {
            return Err(FactsFault::NotReady);
        };
        let pool = lock(pool);
        let broadcast = u64::try_from(pool.listing().count()).unwrap_or(u64::MAX);
        let unbroadcast = match scope {
            PoolScope::Broadcast => None,
            PoolScope::WithUnbroadcast => {
                let held = u64::try_from(pool.relay_view().len()).unwrap_or(u64::MAX);
                Some(held.saturating_sub(broadcast))
            }
        };
        Ok(PoolCounts {
            broadcast,
            unbroadcast,
        })
    }

    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        // The hub is the zone server's. This handle does not read it, and
        // a missing hub is not zero peers.
        Err(FactsFault::HubAbsent)
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        Err(FactsFault::HubAbsent)
    }

    fn free_space(&self) -> Result<u64, FactsFault> {
        free_bytes(&self.data_dir).map_err(|error| {
            tracing::error!(
                path = %self.data_dir.display(),
                %error,
                "the data directory's free space could not be read"
            );
            FactsFault::Internal
        })
    }

    fn now(&self) -> u64 {
        unix_now()
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn free_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    let stat = rustix::fs::statvfs(path)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

#[cfg(windows)]
fn free_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    shekyl_win_sec::free_bytes_available(path)
}

/// Chain reads over the facts slot.
pub(crate) struct ChainBridge {
    facts: Arc<Mutex<Option<Arc<StoreFacts>>>>,
}

impl ChainBridge {
    pub(crate) fn new(facts: Arc<Mutex<Option<Arc<StoreFacts>>>>) -> Self {
        Self { facts }
    }

    /// Clone the facts out of the slot and drop the lock before `read`.
    ///
    /// The guard covers the swap to absent. The read runs after it drops:
    /// `pow_hash` waits for a hasher permit and then hashes, and a read
    /// such as `block_at` or `coinbase_sum` takes its own time. A guard
    /// that spanned any of them would stall every chain read.
    fn with<T>(
        &self,
        read: impl FnOnce(&StoreFacts) -> Result<T, FactsFault>,
    ) -> Result<T, FactsFault> {
        let facts = {
            let slot = lock(&self.facts);
            match slot.as_ref() {
                Some(facts) => Arc::clone(facts),
                None => return Err(FactsFault::NotReady),
            }
        };
        read(&facts)
    }
}

impl ChainFacts for ChainBridge {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
        self.with(ChainFacts::chain_tip)
    }

    fn identity(&self) -> Result<DaemonIdentity, FactsFault> {
        self.with(ChainFacts::identity)
    }

    fn block_hash_at(&self, height: BlockHeight) -> Result<BlockHashAt, FactsFault> {
        self.with(|facts| facts.block_hash_at(height))
    }

    fn block_header_at(
        &self,
        at: BlockLookup,
        fill_pow_hash: bool,
    ) -> Result<BlockHeaderAt, FactsFault> {
        self.with(|facts| facts.block_header_at(at, fill_pow_hash))
    }

    fn fee_estimate(&self) -> Result<FeeEstimate, FactsFault> {
        self.with(ChainFacts::fee_estimate)
    }

    fn block_at(&self, at: BlockLookup, fill_pow_hash: bool) -> Result<BlockAt, FactsFault> {
        self.with(|facts| facts.block_at(at, fill_pow_hash))
    }
}

impl InfoFacts for ChainBridge {
    fn chain(&self) -> Result<InfoChainFacts, FactsFault> {
        self.with(InfoFacts::chain)
    }

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault> {
        self.with(|facts| facts.pool_counts(scope))
    }

    fn store_size(&self) -> Result<u64, FactsFault> {
        self.with(InfoFacts::store_size)
    }

    fn status(&self) -> Result<InfoStatusFacts, FactsFault> {
        self.with(InfoFacts::status)
    }

    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        self.with(InfoFacts::peers)
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        self.with(InfoFacts::sessions)
    }
}

impl ChainReadFacts for ChainBridge {
    fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault> {
        self.with(ChainReadFacts::alt_block_hashes)
    }

    fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault> {
        self.with(ChainReadFacts::alternate_chains)
    }

    fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault> {
        self.with(ChainReadFacts::curve_tree)
    }

    fn curve_tree_after(&self, height: BlockHeight) -> Result<Option<CurveTreeFacts>, FactsFault> {
        self.with(|facts| facts.curve_tree_after(height))
    }

    fn coinbase_sum(&self, start: BlockHeight, count: u64) -> Result<CoinbaseRange, FactsFault> {
        self.with(|facts| facts.coinbase_sum(start, count))
    }

    fn pow_hash(&self, pow_blob: &[u8], seed: PowSeed) -> Result<PowAt, FactsFault> {
        self.with(|facts| facts.pow_hash(pow_blob, seed))
    }

    fn emission_claim_source(&self, persona: &PCanonicalId) -> Result<ClaimSource, FactsFault> {
        self.with(|facts| facts.emission_claim_source(persona))
    }

    fn shard_coverage(&self) -> Result<ShardCoverage, FactsFault> {
        self.with(ChainReadFacts::shard_coverage)
    }
}

pub(crate) struct PoolBridge {
    pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>,
}

impl PoolBridge {
    pub(crate) fn new(pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>) -> Self {
        Self { pool }
    }
}

impl PoolFacts for PoolBridge {
    fn broadcast_count(&self) -> Result<u64, FactsFault> {
        let slot = lock(&self.pool);
        let Some(pool) = slot.as_ref() else {
            return Err(FactsFault::NotReady);
        };
        let pool = lock(pool);
        u64::try_from(pool.listing().count()).map_err(|_| FactsFault::Internal)
    }
}

pub(crate) struct DoorBridge {
    door: Arc<Mutex<Option<Door>>>,
    /// The connector's tip publications.
    tips: tokio::sync::watch::Receiver<TipChanged>,
    /// Pops blocks for `pop_blocks`.
    rewinder: Rewinder<ProductionSubstrate>,
    /// The tag each local offer carries, one more each time.
    tags: AtomicU64,
}

impl DoorBridge {
    pub(crate) fn new(
        door: Arc<Mutex<Option<Door>>>,
        tips: tokio::sync::watch::Receiver<TipChanged>,
        rewinder: Rewinder<ProductionSubstrate>,
    ) -> Self {
        Self {
            door,
            tips,
            rewinder,
            tags: AtomicU64::new(1),
        }
    }
}

/// The door's reply, as the RPC's outcome.
fn local_outcome(reply: Reply) -> LocalOutcome {
    match reply {
        Reply::Connected { height, hash } => LocalOutcome::Connected { height, hash },
        Reply::Switched { promoted, .. } => LocalOutcome::Switched {
            height: promoted
                .last()
                .map_or(BlockHeight::ZERO, |(height, _)| *height),
        },
        Reply::Refused(verdict)
        | Reply::PromotionRefused {
            refused: verdict, ..
        } => LocalOutcome::Refused {
            rule: verdict.rule.to_string(),
        },
        Reply::MissingBodies { indices } => LocalOutcome::MissingBodies { indices },
        Reply::Unlinked { .. } => LocalOutcome::Unlinked,
        Reply::AlreadyHeld => LocalOutcome::AlreadyHeld,
        Reply::Held { .. } => LocalOutcome::Held,
        Reply::BeyondCap(_) => LocalOutcome::BeyondCap,
        Reply::CannotFollow(_) => LocalOutcome::CannotFollow,
        // A span of one arrival has no earlier block to be cancelled by.
        Reply::Cancelled { by } => {
            tracing::error!("a local arrival alone in its span was cancelled by {by:?}");
            LocalOutcome::Stopped
        }
        Reply::Stopped => LocalOutcome::Stopped,
    }
}

impl DoorFacts for DoorBridge {
    fn room(&self) -> Result<usize, FactsFault> {
        lock(&self.door)
            .as_ref()
            .map(Door::room)
            .ok_or(FactsFault::NotReady)
    }

    fn offer_local(&self, block: Vec<u8>) -> Pending<'_, LocalOutcome> {
        let door = lock(&self.door).clone();
        let tag = ArrivalTag(self.tags.fetch_add(1, Ordering::Relaxed));
        Box::pin(async move {
            let Some(door) = door else {
                return Err(FactsFault::NotReady);
            };
            match door.offer_local(tag, block, Vec::new()).await {
                Ok(tagged) => Ok(local_outcome(tagged.reply)),
                Err(Refusal::Oversize) => Ok(LocalOutcome::Oversize),
                // The entry waits out a full window; a closed one is the
                // service stopping.
                Err(Refusal::NoRoom | Refusal::Throttled) => Ok(LocalOutcome::Stopped),
            }
        })
    }

    fn pop(&self, count: u64) -> Pending<'_, PopOutcome> {
        let rewinder = self.rewinder.clone();
        Box::pin(async move {
            match rewinder.pop_blocks(count).await {
                Ok(Rewound::Popped { tip, .. }) => Ok(PopOutcome::Popped { tip }),
                Ok(Rewound::Refused { tip, floor }) => Ok(PopOutcome::Refused { tip, floor }),
                Err(ServiceFault::Mailbox) => Err(FactsFault::NotReady),
                Err(fault) => {
                    tracing::error!("pop_blocks: {fault}");
                    Err(FactsFault::Internal)
                }
            }
        })
    }

    fn tip_at_least(&self, height: BlockHeight) -> Pending<'_, ()> {
        let mut tips = self.tips.clone();
        Box::pin(async move {
            tips.wait_for(|published| {
                published
                    .tip
                    .is_some_and(|tip| tip.count.tip() >= Some(height))
            })
            .await
            .map(|_| ())
            .map_err(|_| FactsFault::NotReady)
        })
    }
}

pub(crate) struct BansBridge;

impl BansFacts for BansBridge {
    fn ban_host(&self, host: IpAddr) -> Result<(), FactsFault> {
        // The process table after install is this node's, and a bound hub
        // finishes the sockets a new ban drops. One function, both states.
        shekyl_ffi::seam_ffi::bans::ban_host_permanent(host);
        Ok(())
    }

    fn banned(&self, host: IpAddr) -> Result<bool, FactsFault> {
        Ok(shekyl_ffi::seam_ffi::bans::host_is_banned(host))
    }
}

pub(crate) struct StopBridge {
    request: Arc<dyn Fn() + Send + Sync>,
}

impl StopBridge {
    pub(crate) fn new(request: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self { request }
    }
}

impl StopFacts for StopBridge {
    fn request_stop(&self) -> Result<(), FactsFault> {
        (self.request)();
        Ok(())
    }
}

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
use shekyl_daemon_rpc::handles::{
    BanLeftFacts, BanRow, BanTargetFacts, BansFacts, DoorFacts, PoolEntryFacts, PoolFacts,
    StopFacts,
};
use shekyl_daemon_rpc::info_facts::{
    InfoChainFacts, InfoFacts, InfoPeersFacts, InfoStatusFacts, PeerFacts, PoolCounts, PoolScope,
    SessionCounts,
};
use shekyl_daemon_rpc::mining_facts::{LocalOutcome, Pending, PopOutcome};
use shekyl_daemon_rpc::read_facts::{
    AltChainFacts, BlocksAt, ChainReadFacts, ClaimSource, CoinbaseRange, CurveTreeFacts, PowAt,
    PowSeed, ShardCoverage, SpentAt,
};
use shekyl_daemon_rpc::store_facts::{NodeFacts, StoreFacts, SyncFacts};
use shekyl_ffi::seam_ffi::bans::{BanPath, BanSpan, BanTarget};
use shekyl_mempool::Pool;
use shekyl_transport_layer::{BanLeft, Ipv4Subnet, ListedBan};
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId, TxHash};

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

    /// Only entries the pool shows: a stem-phase spend is not this node's
    /// to disclose (S6), so it answers unspent here.
    fn pool_spends(&self, key_images: &[shekyl_types::KeyImage]) -> Result<Vec<bool>, FactsFault> {
        let slot = lock(&self.pool);
        let Some(pool) = slot.as_ref() else {
            return Err(FactsFault::NotReady);
        };
        let pool = lock(pool);
        let shown: std::collections::BTreeSet<[u8; 32]> = pool
            .shown_entries()
            .flat_map(|entry| entry.key_images)
            .map(|image| *image.as_bytes())
            .collect();
        Ok(key_images
            .iter()
            .map(|image| shown.contains(image.as_bytes()))
            .collect())
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

    /// The bound hub's sockets and the dialer's lists. An offline node
    /// has no peers by configuration; before the hub binds, a missing hub
    /// is not zero peers.
    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        if self.offline {
            return Ok(PeerFacts::Offline);
        }
        let counts = shekyl_ffi::rpc_peerlist_ffi::peer_counts().ok_or(FactsFault::HubAbsent)?;
        Ok(PeerFacts::Running(InfoPeersFacts {
            public_incoming_sockets: counts.clearnet_in,
            public_outgoing_sockets: counts.clearnet_out,
            tor_incoming_sockets: counts.tor_in,
            tor_outgoing_sockets: counts.tor_out,
            white_peerlist_size: counts.white,
            grey_peerlist_size: counts.gray,
        }))
    }

    /// The bound hub board's handshaken sessions. The per-connection sync
    /// claims stay C++'s until chain sync's cutover and are not read here.
    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        if self.offline {
            return Ok(SessionCounts::NONE);
        }
        let (outbound, inbound) =
            shekyl_ffi::rpc_peerlist_ffi::session_counts().ok_or(FactsFault::HubAbsent)?;
        Ok(SessionCounts { outbound, inbound })
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
    fn blocks_by_height(&self, heights: &[BlockHeight]) -> Result<BlocksAt, FactsFault> {
        self.with(|facts| facts.blocks_by_height(heights))
    }

    fn output_indices(&self, txid: &TxHash) -> Result<Option<Vec<u64>>, FactsFault> {
        self.with(|facts| facts.output_indices(txid))
    }

    fn key_images_spent(
        &self,
        key_images: &[shekyl_types::KeyImage],
    ) -> Result<Vec<SpentAt>, FactsFault> {
        self.with(|facts| facts.key_images_spent(key_images))
    }

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

impl PoolBridge {
    /// The pool, while the node holds one.
    fn pool(&self) -> Result<Arc<Mutex<Pool>>, FactsFault> {
        lock(&self.pool).clone().ok_or(FactsFault::NotReady)
    }
}

/// An entry as the RPC reads it.
fn entry_facts(entry: shekyl_mempool::Entry<'_>) -> PoolEntryFacts {
    PoolEntryFacts {
        id: entry.id,
        blob: entry.tx.serialize(),
        weight: entry.weight,
        fee: entry.fee.to_raw(),
        shown: entry.shown,
        key_images: entry.key_images,
    }
}

impl PoolFacts for PoolBridge {
    fn broadcast_count(&self) -> Result<u64, FactsFault> {
        let pool = self.pool()?;
        let pool = lock(&pool);
        u64::try_from(pool.listing().count()).map_err(|_| FactsFault::Internal)
    }

    fn entries(&self, scope: PoolScope) -> Result<Vec<PoolEntryFacts>, FactsFault> {
        let pool = self.pool()?;
        let pool = lock(&pool);
        Ok(match scope {
            PoolScope::Broadcast => pool.shown_entries().map(entry_facts).collect(),
            PoolScope::WithUnbroadcast => pool.relay_view().entries().map(entry_facts).collect(),
        })
    }

    fn flush(&self, ids: &[TxHash]) -> Result<Vec<TxHash>, FactsFault> {
        let pool = self.pool()?;
        let mut pool = lock(&pool);
        let all: Vec<TxHash>;
        let ids = if ids.is_empty() {
            all = pool.relay_view().entries().map(|entry| entry.id).collect();
            &all
        } else {
            ids
        };
        let flushed = pool.flush(ids).map_err(|error| {
            tracing::error!("flush_txpool: the pool file: {error}");
            FactsFault::StoreUnreadable
        })?;
        Ok(flushed.into_iter().map(|(id, _)| id).collect())
    }
}

/// The service's two entries the RPC asks of: the door, and the rewinder
/// `pop_blocks` pops through. Both hold the service's store and pool, so
/// they live in the node's slot, which stop empties; a handle that held
/// either past stop would keep both files open.
#[derive(Clone)]
pub(crate) struct DoorEntry {
    pub(crate) door: Door,
    pub(crate) rewinder: Rewinder<ProductionSubstrate>,
}

pub(crate) struct DoorBridge {
    entry: Arc<Mutex<Option<DoorEntry>>>,
    /// The connector's tip publications.
    tips: tokio::sync::watch::Receiver<TipChanged>,
    /// The tag each local offer carries, one more each time.
    tags: AtomicU64,
}

impl DoorBridge {
    pub(crate) fn new(
        entry: Arc<Mutex<Option<DoorEntry>>>,
        tips: tokio::sync::watch::Receiver<TipChanged>,
    ) -> Self {
        Self {
            entry,
            tips,
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
        lock(&self.entry)
            .as_ref()
            .map(|entry| entry.door.room())
            .ok_or(FactsFault::NotReady)
    }

    fn offer_local(&self, block: Vec<u8>) -> Pending<'_, LocalOutcome> {
        let door = lock(&self.entry).as_ref().map(|entry| entry.door.clone());
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
        let rewinder = lock(&self.entry)
            .as_ref()
            .map(|entry| entry.rewinder.clone());
        Box::pin(async move {
            let Some(rewinder) = rewinder else {
                return Err(FactsFault::NotReady);
            };
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

/// The node's ban table through the one ban path: the bound hub while
/// there is one, otherwise the node's own socket table (DX-Q3, Q11).
pub(crate) struct BansBridge {
    path: BanPath,
}

impl BansBridge {
    pub(crate) const fn new(path: BanPath) -> Self {
        Self { path }
    }
}

/// A target as the ban path names it.
fn ban_target(target: BanTargetFacts) -> Result<BanTarget, FactsFault> {
    match target {
        BanTargetFacts::Host(host) => Ok(BanTarget::Host(host)),
        BanTargetFacts::Subnet { network, prefix } => Ipv4Subnet::new(network, prefix)
            .map(BanTarget::Subnet)
            .ok_or(FactsFault::Internal),
    }
}

/// Time left, as the RPC reads it: whole seconds, rounded up.
fn ban_left(left: BanLeft) -> BanLeftFacts {
    match left {
        BanLeft::Permanent => BanLeftFacts::Permanent,
        BanLeft::Remaining { nanos } => BanLeftFacts::Seconds(nanos.div_ceil(1_000_000_000)),
    }
}

impl BansFacts for BansBridge {
    fn ban(&self, target: BanTargetFacts, seconds: Option<u64>) -> Result<bool, FactsFault> {
        let span = seconds.map_or(BanSpan::Permanent, |seconds| {
            BanSpan::For(std::time::Duration::from_secs(seconds))
        });
        Ok(self.path.ban(ban_target(target)?, span))
    }

    fn lift(&self, target: BanTargetFacts) -> Result<bool, FactsFault> {
        Ok(self.path.lift(ban_target(target)?))
    }

    fn remaining(&self, host: IpAddr) -> Result<Option<BanLeftFacts>, FactsFault> {
        Ok(self.path.remaining(host).map(ban_left))
    }

    fn list(&self) -> Result<Vec<BanRow>, FactsFault> {
        Ok(self
            .path
            .listed()
            .into_iter()
            .map(|row| match row {
                ListedBan::Host { host, left } => BanRow {
                    target: BanTargetFacts::Host(host),
                    left: ban_left(left),
                },
                ListedBan::Subnet { subnet, left } => BanRow {
                    target: BanTargetFacts::Subnet {
                        network: subnet.network(),
                        prefix: subnet.prefix_len(),
                    },
                    left: ban_left(left),
                },
            })
            .collect())
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

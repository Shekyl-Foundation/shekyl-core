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

use shekyl_chain_ingest::service::{
    ArrivalTag, Door, PoolHealth, Refusal, Reply, Rewinder, ServiceFault,
};
use shekyl_chain_ingest::{ProductionSubstrate, Rewound, TipChanged};
use shekyl_chain_store::codec::FollowingDegraded;
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
    PoolState, SessionCounts,
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

/// Open the pool slot the way a chain read may answer it.
///
/// No pool in the slot is [`FactsFault::NotReady`]: the node is not up.
/// A retired pool is [`PoolState::Retired`]: the node follows the chain
/// and this pool has no answer. A read that cannot carry that answer uses
/// [`require_live`].
fn open_pool(
    slot: &Mutex<Option<Arc<Mutex<Pool>>>>,
    health: &PoolHealth,
) -> Result<PoolState<Arc<Mutex<Pool>>>, FactsFault> {
    if health.retired() {
        return Ok(PoolState::Retired);
    }
    lock(slot)
        .clone()
        .map(PoolState::Live)
        .ok_or(FactsFault::NotReady)
}

/// The live pool. A retired pool is not ready: the read cannot answer
/// without one, and must not treat "no answer" as an empty pool.
fn require_live(state: PoolState<Arc<Mutex<Pool>>>) -> Result<Arc<Mutex<Pool>>, FactsFault> {
    match state {
        PoolState::Live(pool) => Ok(pool),
        PoolState::Retired => Err(FactsFault::NotReady),
    }
}

/// What the chain store does not hold. It does not own the facts slot, so
/// dropping the facts drops this and not the other way round.
pub(crate) struct Surroundings {
    pub(crate) pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>,
    pub(crate) data_dir: PathBuf,
    pub(crate) offline: bool,
    /// Chain sync's state: the watch the follower reads.
    pub(crate) sync: tokio::sync::watch::Receiver<SyncState>,
    /// The connector's `following_degraded` latch. `None` is clear.
    /// Chain sync raises it; the connector is the one writer.
    pub(crate) latch: tokio::sync::watch::Receiver<Option<FollowingDegraded>>,
    /// The service's retirement flag: a pool whose file has faulted is
    /// not read here, as the pool handle does not read it.
    pub(crate) health: PoolHealth,
}

impl NodeFacts for Surroundings {
    fn sync(&self) -> Result<SyncFacts, FactsFault> {
        // Chain sync's state, the one the follower posts on (DX-Q3, Q13),
        // read by the follower's rule: a closed watch says nothing about
        // the chain, so it reads `NoView`, not its last value.
        // The target is the best verified chain's count, which chain sync
        // publishes with `Behind`. The latch is the store's, published by
        // the connector. A closed watch keeps its last value: the latch is
        // one-way until a resync.
        let state = if self.sync.has_changed().is_err() {
            SyncState::NoView
        } else {
            *self.sync.borrow()
        };
        Ok(SyncFacts {
            target: match state {
                SyncState::Behind { target, .. } => Some(target),
                _ => None,
            },
            synchronized: state == SyncState::Synced,
            busy_syncing: matches!(
                state,
                SyncState::Behind { .. } | SyncState::Following { .. }
            ),
            offline: self.offline,
            following_degraded: self.latch.borrow().is_some(),
        })
    }

    /// Only entries the pool shows: a stem-phase spend is not this node's
    /// to disclose (S6), so it answers unspent here.
    fn pool_spends(&self, key_images: &[shekyl_types::KeyImage]) -> Result<Vec<bool>, FactsFault> {
        let pool = require_live(open_pool(&self.pool, &self.health)?)?;
        let pool = lock(&pool);
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

    /// Read off one lock, in request order: what the pool shows for any
    /// caller, its stem entries too for the host (S6).
    fn pool_bodies(
        &self,
        ids: &[TxHash],
        scope: PoolScope,
    ) -> Result<PoolState<Vec<Option<shekyl_daemon_rpc::store_facts::PoolBody>>>, FactsFault> {
        let PoolState::Live(pool) = open_pool(&self.pool, &self.health)? else {
            return Ok(PoolState::Retired);
        };
        let pool = lock(&pool);
        let held: std::collections::BTreeMap<TxHash, shekyl_daemon_rpc::store_facts::PoolBody> =
            match scope {
                PoolScope::Broadcast => pool
                    .shown_entries()
                    .map(|entry| (entry.id, body_of(&entry)))
                    .collect(),
                PoolScope::WithUnbroadcast => pool
                    .relay_view()
                    .entries()
                    .map(|entry| (entry.id, body_of(&entry)))
                    .collect(),
            };
        Ok(PoolState::Live(
            ids.iter().map(|id| held.get(id).cloned()).collect(),
        ))
    }

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolState<PoolCounts>, FactsFault> {
        let PoolState::Live(pool) = open_pool(&self.pool, &self.health)? else {
            return Ok(PoolState::Retired);
        };
        let pool = lock(&pool);
        let broadcast = u64::try_from(pool.listing().count()).unwrap_or(u64::MAX);
        let unbroadcast = match scope {
            PoolScope::Broadcast => None,
            PoolScope::WithUnbroadcast => {
                let held = u64::try_from(pool.relay_view().len()).unwrap_or(u64::MAX);
                Some(held.saturating_sub(broadcast))
            }
        };
        Ok(PoolState::Live(PoolCounts {
            broadcast,
            unbroadcast,
        }))
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

/// Free space available to this process under `path`, in bytes: `statvfs`'s
/// `f_bavail` on Unix, `GetDiskFreeSpaceExW`'s available-to-caller figure on
/// Windows. An unreadable probe is an error, never a guess. The managed Tor's
/// pre-spawn check reads it too (`TOR_SUPERVISOR.md` §5).
#[cfg(unix)]
pub fn free_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    let stat = rustix::fs::statvfs(path)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// Windows half of [`free_bytes`].
#[cfg(windows)]
pub fn free_bytes(path: &std::path::Path) -> std::io::Result<u64> {
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

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolState<PoolCounts>, FactsFault> {
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
    fn transactions(
        &self,
        ids: &[TxHash],
        scope: PoolScope,
    ) -> Result<shekyl_daemon_rpc::read_facts::TransactionsAt, FactsFault> {
        self.with(|facts| facts.transactions(ids, scope))
    }

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
    /// The service's own retirement flag: a pool it has retired is not
    /// served here, and a fault met here retires it there.
    health: PoolHealth,
}

impl PoolBridge {
    pub(crate) fn new(pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>, health: PoolHealth) -> Self {
        Self { pool, health }
    }
}

impl PoolBridge {
    /// The live pool. Absent and retired are both not ready: these methods
    /// have no reply that can say the pool has no answer.
    fn pool(&self) -> Result<Arc<Mutex<Pool>>, FactsFault> {
        require_live(open_pool(&self.pool, &self.health)?)
    }
}

/// An entry's body as `get_transactions` reads it.
fn body_of(entry: &shekyl_mempool::Entry<'_>) -> shekyl_daemon_rpc::store_facts::PoolBody {
    shekyl_daemon_rpc::store_facts::PoolBody {
        tx: entry.tx.serialize(),
        shown: entry.shown,
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

    /// On a blocking thread: the flush writes the pool file under the
    /// pool's lock, which a runtime thread must not wait on.
    fn flush(&self, ids: Vec<TxHash>) -> Pending<'_, Vec<TxHash>> {
        let pool = self.pool();
        let health = self.health.clone();
        Box::pin(async move {
            let pool = pool?;
            tokio::task::spawn_blocking(move || {
                let mut pool = lock(&pool);
                let ids = if ids.is_empty() {
                    pool.relay_view().entries().map(|entry| entry.id).collect()
                } else {
                    ids
                };
                match pool.flush(&ids) {
                    Ok(flushed) => Ok(flushed.into_iter().map(|(id, _)| id).collect()),
                    Err(fault) => {
                        health.retire(&fault);
                        Err(FactsFault::StoreUnreadable)
                    }
                }
            })
            .await
            .map_err(|_| FactsFault::Internal)?
        })
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
    /// The tag each local offer carries, one more each time. It can repeat
    /// a tag the miner's sink or genesis gave: a local offer is a span of
    /// one, and a tag only tells apart the arrivals of one span.
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
                Err(Refusal::StoreUnreadable) => Err(FactsFault::StoreUnreadable),
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

    fn fits(&self, seconds: u64) -> Result<bool, FactsFault> {
        Ok(BanPath::fits(BanSpan::For(std::time::Duration::from_secs(
            seconds,
        ))))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A closed sync watch reads `NoView`, as the follower reads it, never
    /// its last value (the review of #1165). Red edit: read the last value.
    #[test]
    fn a_closed_sync_watch_reads_as_no_view() {
        let dir = tempfile::tempdir().expect("temp");
        let (sender, sync) = tokio::sync::watch::channel(SyncState::Synced);
        let (_latch_tx, latch) = tokio::sync::watch::channel(None);
        let surroundings = Surroundings {
            pool: Arc::new(Mutex::new(None)),
            data_dir: dir.path().to_path_buf(),
            offline: false,
            sync,
            latch,
            health: PoolHealth::unwired(),
        };
        assert!(surroundings.sync().expect("open").synchronized);
        drop(sender);
        let closed = surroundings.sync().expect("closed");
        assert!(!closed.synchronized, "a closed watch is not Synced");
        assert!(!closed.busy_syncing);
        assert!(!closed.following_degraded);
    }

    /// The facts read the connector's latch. A closed watch keeps the
    /// last evidence: the latch is one-way until a resync.
    #[test]
    fn the_sync_facts_read_the_latch() {
        let dir = tempfile::tempdir().expect("temp");
        let (_sync_tx, sync) = tokio::sync::watch::channel(SyncState::Synced);
        let evidence = FollowingDegraded {
            fork_at: BlockHeight::from_raw(3),
            tip: BlockHash::from_bytes([0x11; 32]),
            work: shekyl_difficulty::CumulativeDifficulty::from_raw(9),
        };
        let (latch_tx, latch) = tokio::sync::watch::channel(None);
        let surroundings = Surroundings {
            pool: Arc::new(Mutex::new(None)),
            data_dir: dir.path().to_path_buf(),
            offline: false,
            sync,
            latch,
            health: PoolHealth::unwired(),
        };
        assert!(!surroundings.sync().expect("open").following_degraded);
        latch_tx.send_replace(Some(evidence));
        assert!(surroundings.sync().expect("set").following_degraded);
        drop(latch_tx);
        assert!(
            surroundings.sync().expect("closed").following_degraded,
            "a closed latch watch keeps the evidence"
        );
    }

    /// The node's facts read what chain sync publishes into the node's one
    /// sync sender: `Behind` with its target, then `Synced` with none
    /// (CS-Q2 step 8). Red edit: answer `target: None` always.
    #[test]
    fn the_sync_facts_read_the_published_state_and_its_target() {
        let dir = tempfile::tempdir().expect("temp");
        let (sender, sync) = tokio::sync::watch::channel(SyncState::NoView);
        let (_latch_tx, latch) = tokio::sync::watch::channel(None);
        let surroundings = Surroundings {
            pool: Arc::new(Mutex::new(None)),
            data_dir: dir.path().to_path_buf(),
            offline: false,
            sync,
            latch,
            health: PoolHealth::unwired(),
        };
        let none = surroundings.sync().expect("open");
        assert_eq!(
            (none.target, none.synchronized, none.busy_syncing),
            (None, false, false)
        );
        let target = shekyl_types::ChainCount::from_raw(120);
        sender.send_replace(SyncState::Behind {
            have: shekyl_difficulty::CumulativeDifficulty::from_raw(80),
            best: shekyl_difficulty::CumulativeDifficulty::from_raw(120),
            target,
        });
        let behind = surroundings.sync().expect("open");
        assert_eq!(behind.target, Some(target));
        assert!(behind.busy_syncing && !behind.synchronized);
        sender.send_replace(SyncState::Synced);
        let synced = surroundings.sync().expect("open");
        assert_eq!(
            (synced.target, synced.synchronized, synced.busy_syncing),
            (None, true, false)
        );
    }
}

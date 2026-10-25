// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's one [`Node`] (`DRS_X_STORE_FLIP.md` DX-Q6, N1).
//!
//! Rust `main` builds it at start, after the network marker and before the
//! remnant's `run`. It owns the chain store, the ingest service, the pool,
//! the hasher budget, the cache store, the job board and the socket table.
//! Nothing is routed into it from C++: the C++ core keeps the live chain
//! and the live RPC until the flip. An empty store connects the pinned
//! genesis through the service's door, and that is the only block the
//! store holds until the flip routes arrivals.
//!
//! # Stop
//!
//! Dropping the node is one step of the daemon's `finish`, in this order
//! (`TOR_SUPERVISOR.md` §1; the dialer stops before Tor is torn down):
//!
//! 1. `network::stop` — the dialer and the zone host, so nothing new arrives.
//! 2. The RPC drains. It still reads the C++ core.
//! 3. The node is dropped. [`Drop`] calls [`Node::stop`]: the ingest service
//!    stops, the follower withdraws the job board, the connector finishes
//!    its current message, and the store closes. Durability is `Immediate`:
//!    there is no flush.
//! 4. The remnant's stop and the managed Tor's teardown run together.
//!
//! A second [`Node::stop`] is a no-op. [`Drop`] calls it, so every way out
//! of `main` stops the node, and `finish` drops it before the remnant joins.
//!
//! # Blocking threads
//!
//! Every blocking task the ingest service runs is one of three kinds, and
//! the runtime has a thread for each one that can be outstanding at once:
//!
//! - **A form**, which hashes holding a hasher permit: at most the
//!   budget's permits.
//! - **A span's one other task**: a permit wait
//!   ([`Budget::acquire_unless`](shekyl_hash_budget::Budget::acquire_unless)
//!   waits on its thread), a claim, or a pool step. A span runs one at a
//!   time, and every span holds a seat, so at most the arrival window.
//! - **The tip follower's one**: its pool step, or the template build,
//!   which takes no permit.
//!
//! A permit holder waits for a thread to form on, so the count must not be
//! one that permit waiters alone can fill: it is permits + window + 1. A
//! local arrival waits for its seat without a thread.
//!
//! # The board
//!
//! The tip follower posts the node's one template on the board
//! (`DRS_X_STORE_FLIP.md` DX-Q3, N2), paying the `mine-address` row's
//! keys, while chain sync's state reads `Synced`: from open on regtest,
//! and on every other network once chain sync's cutover publishes. With no
//! address it posts nothing, and [`Node::posting`] says why. The miner
//! ([`MiningControl`]) hashes what is posted; it is started on request,
//! never at open. Stop withdraws the board.

#![deny(unsafe_code)]

mod facts;
mod genesis;
mod mining;

pub use mining::{MiningControl, MiningRefused, MiningStatus, PostedJob};

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use shekyl_block_template::MinerKeys;
use shekyl_chain_ingest::follower::{JobSeat, MinerFeed, NoJob, Posting};
use shekyl_chain_ingest::service::{
    ArrivalTag, Follow, PoolWiring, Reply, Service, ServiceConfig, ServiceFault,
};
use shekyl_chain_ingest::{Chain, ChainRules, Metrics, ProductionSubstrate, SubstrateFault};
use shekyl_chain_rules::{AdmissionPolicy, FakechainSchedule, ReleaseAnchors, RuleSet};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::pool::PoolOpen;
use shekyl_chain_store::store::{ChainStore, Horizons, SnapshotView};
use shekyl_chain_sync::SyncState;
use shekyl_daemon_config::sections::{DaemonConfig, Dev};
use shekyl_daemon_rpc::handles::Handles;
use shekyl_daemon_rpc::store_facts::{NodeIdentity, RulesAt, StoreFacts};
use shekyl_hash_budget::Budget;
use shekyl_mempool::Pool;
use shekyl_miner::{JobBoard, MiningAddress};
use shekyl_pow_randomx::CacheStore;
use shekyl_runtime::{RuntimeBudget, ThreadName};
use shekyl_transport_layer::Sockets;
use shekyl_types::{BlockHeight, UnixSeconds};

use crate::facts::{
    BansBridge, ChainBridge, DoorBridge, DoorEntry, PoolBridge, StopBridge, Surroundings,
};
use crate::genesis::{daemon_network, pinned_genesis};
use shekyl_ffi::seam_ffi::bans::BanPath;

/// The runtime's blocking threads for `permits` hasher permits and an
/// arrival window of `window` (module docs, "Blocking threads").
fn blocking_threads(permits: NonZeroUsize, window: NonZeroUsize) -> NonZeroUsize {
    permits.saturating_add(window.get()).saturating_add(1)
}

/// Chain sync's state once the node has opened, published after genesis
/// has connected (`DRS_X_STORE_FLIP.md` DX-Q3, Q13): `Synced` on regtest,
/// which has no network to be behind, and `NoView` on every other network
/// until chain sync's cutover publishes. The network selects this value
/// and nothing else (rule 71).
const fn sync_at_open(network: shekyl_daemon_config::Network) -> SyncState {
    match network {
        shekyl_daemon_config::Network::Regtest => SyncState::Synced,
        shekyl_daemon_config::Network::Mainnet
        | shekyl_daemon_config::Network::Testnet
        | shekyl_daemon_config::Network::Stagenet => SyncState::NoView,
    }
}

/// After the service has joined, how long a leftover blocking task may run
/// before the runtime detaches it. The connector has already finished; this
/// bound is only the runtime's, and it is not a protocol constant.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

/// Why [`Node::open`] refused.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The network and its levers do not make a rule schedule.
    #[error("the chain rules refuse this configuration: {0}")]
    Rules(String),
    /// The data directory could not be created.
    #[error("the data directory: {0}")]
    Directory(std::io::Error),
    /// The store or a read of it failed.
    #[error("the chain store: {0}")]
    Store(#[from] shekyl_chain_store::store::StoreError),
    /// A layout-mismatched chain file could not be removed.
    #[error("the chain file could not be removed: {0}")]
    Wipe(std::io::Error),
    /// The pool file did not open.
    #[error("the pool did not open: {0}")]
    Pool(String),
    /// The node's runtime did not start.
    #[error("the runtime did not start: {0}")]
    Runtime(#[from] std::io::Error),
    /// The pinned genesis did not connect.
    #[error("genesis did not connect: {0}")]
    Genesis(String),
    /// The ingest service did not answer at open.
    #[error("the ingest service did not answer: {0}")]
    Service(String),
}

/// What [`Node::open`] needs from the composition root, which holds `main`.
pub struct OpenArgs<'a> {
    /// The resolved daemon configuration.
    pub config: &'a DaemonConfig,
    /// The build's version string.
    pub version: String,
    /// The p2p protocol version.
    pub protocol_version: u64,
    /// Whether this build is a release. The live `get_info` still reads the
    /// C++ flag; this is the staged facts' copy.
    pub release_build: bool,
    /// The stop latch. `shekyl-daemon` passes `signals::request_stop`,
    /// because this crate cannot depend on the binary.
    pub request_stop: Arc<dyn Fn() + Send + Sync>,
}

struct Slots {
    /// The facts, behind `Arc` so a read clones them and drops this lock
    /// before it runs. The guard covers the swap to absent. A read can
    /// wait (`pow_hash` takes a hasher permit, then hashes) or just take
    /// time, and either one stalls every other chain read if the guard
    /// spans it.
    facts: Arc<Mutex<Option<Arc<StoreFacts>>>>,
    pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>,
    door: Arc<Mutex<Option<DoorEntry>>>,
}

/// The daemon's one node (module docs).
pub struct Node {
    slots: Arc<Slots>,
    /// Chain sync's state, as the follower reads it. The node publishes
    /// the state at open; chain sync's cutover publishes from then on.
    sync: tokio::sync::watch::Sender<SyncState>,
    /// What the board holds, as the follower last left it.
    posting: tokio::sync::watch::Receiver<Posting>,
    mining: Arc<MiningControl>,
    /// The `dev-rpc` row: whether the armed test levers are served.
    armed: bool,
    sockets: Sockets,
    handles: Handles,
    service: Mutex<Option<Service<ProductionSubstrate>>>,
    runtime: Mutex<Option<shekyl_runtime::Pool>>,
    /// The hasher budget `pow_hash` acquires under. The facts-lock test
    /// holds its permits; production does not keep a second copy.
    #[cfg(test)]
    budget: Budget,
}

impl Node {
    /// Open the store, start ingest, and connect genesis when the store is empty.
    ///
    /// # Errors
    ///
    /// [`OpenError`]. A failure stops anything this call started.
    pub fn open(args: OpenArgs<'_>) -> Result<Self, OpenError> {
        let rules = rules_of(args.config)?;
        let horizons = Horizons::under(&rules.in_force(BlockHeight::ZERO))
            .map_err(|error| OpenError::Rules(format!("the store horizons: {error}")))?;
        let anchors = anchors_of(rules);
        std::fs::create_dir_all(&args.config.data_dir).map_err(OpenError::Directory)?;
        let store_path = args.config.data_dir.join("chain.db");
        let pool_path = args.config.data_dir.join("pool.db");
        let store = Arc::new(open_chain(&store_path, horizons, &anchors)?);
        let parallelism = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        let budget = Budget::new(parallelism);
        let caches = Arc::new(CacheStore::new());
        let substrate = Arc::new(ProductionSubstrate::new(
            Arc::clone(&caches),
            Arc::new(Metrics::new()),
        ));
        let pool = open_pool(&store, &pool_path, rules)?;
        let pool_slot = Arc::new(Mutex::new(Some(Arc::clone(&pool))));
        let sockets = Sockets::new();
        let board = Arc::new(JobBoard::new());
        let network = args.config.network;
        // No view until genesis has connected, so the follower never builds
        // a genesis of its own; the network's state at open is published
        // after (`sync_at_open`).
        let (sync, sync_rx) = tokio::sync::watch::channel(SyncState::NoView);
        let (found, found_inbox) = shekyl_miner::found_blocks();
        let (posting_tx, posting) =
            tokio::sync::watch::channel(Posting::Withdrawn(NoJob::Starting));
        let mine_address = args.config.mine.address.as_ref();
        let keys = mine_address.map(|address| MinerKeys {
            spend_public: address.spend,
            x25519_pk: address.x25519,
            ml_kem_ek: address.ml_kem.clone(),
        });
        let miner_address = mine_address
            .map(|address| MiningAddress::decode(&address.text, network.address_network()))
            .transpose()
            .map_err(|refused| OpenError::Rules(format!("the mine-address row: {refused}")))?;
        // Every template draws its `0x0C` commitment from this ring, and the
        // bundle producer files from it (`SO-D12` increment 4c).
        let witness = Arc::new(shekyl_bundle_producer::WitnessRing::new());
        let producer = producer_seat(args.config, &store, &witness, keys.is_some());
        let follow = Follow {
            job: Some(JobSeat {
                board: Arc::clone(&board),
                keys,
                miner: MinerFeed {
                    found: found_inbox,
                    sync: sync_rx.clone(),
                },
                posting: posting_tx,
                witness: Arc::clone(&witness),
            }),
            pool: Some(PoolWiring {
                pool,
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(wall_now),
            }),
            producer,
        };
        let service_config = ServiceConfig::default();
        let runtime = shekyl_runtime::runtime(
            // Permits + window + the follower's one (module docs).
            RuntimeBudget {
                workers: parallelism,
                blocking: blocking_threads(parallelism, service_config.room),
            },
            &ThreadName::new("shekyl-node").expect("the name is static"),
        )?;
        let started = runtime.block_on(async {
            let service = Service::start(
                Arc::clone(&store),
                rules,
                substrate,
                service_config,
                budget.clone(),
                follow,
            );
            if let Err(error) = connect_genesis(&service, network).await {
                if let Err(stop) = service.stop().await {
                    tracing::error!("genesis did not connect, and the service stopped on {stop}");
                }
                return Err(error);
            }
            Ok(service)
        });
        let service = match started {
            Ok(service) => service,
            Err(error) => {
                runtime.shutdown(RUNTIME_SHUTDOWN);
                return Err(error);
            }
        };
        let subscribed: Result<_, ServiceFault<SubstrateFault>> = runtime.block_on(async {
            let tips = service.watch_tip().await?;
            let latch = service.watch_latch().await?;
            Ok((tips, latch))
        });
        let (tips, latch) = match subscribed {
            Ok(pair) => pair,
            Err(error) => {
                if let Err(stop) = runtime.block_on(service.stop()) {
                    tracing::error!(
                        "a connector watch did not open, and the service stopped on {stop}"
                    );
                }
                runtime.shutdown(RUNTIME_SHUTDOWN);
                return Err(OpenError::Service(error.to_string()));
            }
        };
        let pool_health = service.pool_health();
        let rewinder = service.rewinder();
        let at_open = sync_at_open(network);
        tracing::info!(
            "chain sync's state at open: {at_open:?}; the node posts a template only while it reads Synced"
        );
        sync.send_replace(at_open);
        let door = service.door();
        let surroundings = Arc::new(Surroundings {
            pool: Arc::clone(&pool_slot),
            data_dir: args.config.data_dir.clone(),
            offline: args.config.offline(),
            sync: sync_rx,
            latch,
            health: pool_health.clone(),
        });
        let mining = Arc::new(MiningControl::new(
            Arc::clone(&board),
            Arc::clone(&caches),
            budget.clone(),
            found,
            miner_address,
            posting.clone(),
            pool_health.clone(),
        ));
        let started_at = facts::unix_now();
        #[cfg(test)]
        let test_budget = budget.clone();
        let facts = StoreFacts::new(
            store,
            store_path.clone(),
            Arc::new(RulesOf(rules)),
            surroundings,
            NodeIdentity {
                nettype: daemon_network(network),
                release_build: args.release_build,
                version: args.version,
                start_time: started_at,
                protocol_version: args.protocol_version,
            },
            caches,
            budget,
        );
        let facts_slot = Arc::new(Mutex::new(Some(Arc::new(facts))));
        let door_slot = Arc::new(Mutex::new(Some(DoorEntry { door, rewinder })));
        let handles = Handles {
            chain: Arc::new(ChainBridge::new(Arc::clone(&facts_slot))),
            pool: Arc::new(PoolBridge::new(Arc::clone(&pool_slot), pool_health.clone())),
            door: Arc::new(DoorBridge::new(Arc::clone(&door_slot), tips)),
            mining: Arc::clone(&mining) as _,
            bans: Arc::new(BansBridge::new(BanPath::over(sockets.clone()))),
            stop: Arc::new(StopBridge::new(Arc::clone(&args.request_stop))),
        };
        let slots = Arc::new(Slots {
            facts: facts_slot,
            pool: pool_slot,
            door: door_slot,
        });
        Ok(Self {
            slots,
            sync,
            posting,
            mining,
            armed: args.config.dev.rpc,
            sockets,
            handles,
            service: Mutex::new(Some(service)),
            runtime: Mutex::new(Some(runtime)),
            #[cfg(test)]
            budget: test_budget,
        })
    }

    /// The handles the RPC server carries. Live routes do not read them yet.
    #[must_use]
    pub fn handles(&self) -> Handles {
        self.handles.clone()
    }

    /// The socket table. `main` installs it as `process_sockets`'s table
    /// before anything else reads that function.
    #[must_use]
    pub fn sockets(&self) -> Sockets {
        self.sockets.clone()
    }

    /// What the board holds, and why not when it holds nothing.
    #[must_use]
    pub fn posting(&self) -> tokio::sync::watch::Receiver<Posting> {
        self.posting.clone()
    }

    /// Chain sync's state, which the follower posts a job on only while it
    /// reads `Synced`. Chain sync's cutover is its publisher.
    #[must_use]
    pub const fn sync(&self) -> &tokio::sync::watch::Sender<SyncState> {
        &self.sync
    }

    /// The node's one pool, while it runs: what the composition root hands
    /// the submit engine's shim (`RustPoolShim::new`), so the service and
    /// the shim share it. `None` after stop.
    #[must_use]
    pub fn pool(&self) -> Option<Arc<Mutex<Pool>>> {
        self.slots
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The node's miner.
    #[must_use]
    pub fn mining(&self) -> Arc<MiningControl> {
        Arc::clone(&self.mining)
    }

    /// Whether the node was started with `dev-rpc`: the switch the armed
    /// test levers are admitted under
    /// (`shekyl_daemon_rpc::mining_methods::admit_armed`).
    #[must_use]
    pub const fn armed_levers(&self) -> bool {
        self.armed
    }

    /// Stop the miner and the ingest service, clear the handles' slots, and
    /// shut the runtime down.
    ///
    /// The follower withdraws the job board on the way out. A second call
    /// does nothing. [`Drop`] calls this.
    ///
    /// # Panics
    ///
    /// In an asynchronous context. Stopping waits: the pool runs the service
    /// stop with `block_on`, then [`shekyl_runtime::Pool::shutdown`] with a
    /// non-zero bound. Tokio refuses either wait where blocking is not
    /// allowed: a task, or any thread that has entered a runtime. [`Drop`]
    /// calls this, so the node must not be dropped from that context
    /// either. Mining control stops the miner; it does not stop or drop
    /// the node.
    pub fn stop(&self) {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "Node::stop waits, and must not run inside a tokio runtime"
        );
        // The miner first: its workers hash on the board this stop withdraws,
        // and a handle may keep mining control alive past the node.
        self.mining.close();
        let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        if let Some(service) = self
            .service
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            if let Err(error) = runtime.block_on(service.stop()) {
                tracing::error!("the ingest service stopped on a fault: {error}");
            }
        }
        *self
            .slots
            .facts
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .slots
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .slots
            .door
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        runtime.shutdown(RUNTIME_SHUTDOWN);
    }

    /// The hasher budget the facts hash under. The lock test holds every
    /// permit, so `pow_hash` waits inside `acquire` with the slot lock
    /// already dropped.
    #[cfg(test)]
    fn budget(&self) -> Budget {
        self.budget.clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

struct RulesOf(ChainRules);

impl RulesAt for RulesOf {
    fn in_force(&self, height: BlockHeight) -> RuleSet {
        self.0.in_force(height)
    }
}

/// The bundle producer, for a node that mines and reads through a Tor
/// SOCKS endpoint (`SO-D12` increment 4c).
///
/// Only a mining daemon is a witness. The producer reads each drawn pair's
/// shard through the daemon's fetch scheduler over the store's facts, and
/// the scheduler dials through an operator's Tor (`tor-socks`). A managed
/// Tor publishes its SOCKS route to the network after the node opens, so a
/// node on one runs no producer yet; nor does a node with Tor off. Either
/// way the templates still draw from the ring, which keeps its bound, and
/// the node says once why it files nothing.
fn producer_seat(
    config: &DaemonConfig,
    store: &Arc<ChainStore>,
    witness: &Arc<shekyl_bundle_producer::WitnessRing>,
    mining: bool,
) -> Option<shekyl_chain_ingest::bundle_producer::ProducerSeat> {
    use shekyl_archival_fetch_sched::{FetchScheduler, NeedBudget, PFetchClient};
    use shekyl_chain_ingest::shard_facts::{StoreHolderSource, StoreShardFacts};
    use shekyl_daemon_config::sections::Tor;
    if !mining {
        return None;
    }
    let Tor::Operator { socks, .. } = &config.tor else {
        tracing::info!(
            "the bundle producer is off: it reads through an operator's Tor SOCKS \
             endpoint (tor-socks), and this node has none"
        );
        return None;
    };
    let scheduler = Arc::new(FetchScheduler::new(
        Arc::new(StoreShardFacts::new(Arc::clone(store))),
        Arc::new(StoreHolderSource::new(Arc::clone(store))),
        PFetchClient::new(socks.endpoint),
    ));
    Some(shekyl_chain_ingest::bundle_producer::ProducerSeat {
        witness: Arc::clone(witness),
        read: shekyl_chain_ingest::bundle_producer::read_through(scheduler, NeedBudget::DEFAULT),
    })
}

fn wall_now() -> UnixSeconds {
    UnixSeconds::from_raw(facts::unix_now())
}

fn rules_of(config: &DaemonConfig) -> Result<ChainRules, OpenError> {
    let chain = match config.network {
        shekyl_daemon_config::Network::Mainnet => Chain::Public(shekyl_address::Network::Mainnet),
        shekyl_daemon_config::Network::Testnet => Chain::Public(shekyl_address::Network::Testnet),
        shekyl_daemon_config::Network::Stagenet => Chain::Public(shekyl_address::Network::Stagenet),
        shekyl_daemon_config::Network::Regtest => Chain::Regtest,
    };
    let fixed = config
        .dev
        .difficulty
        .map(|n| std::num::NonZeroU128::new(u128::from(n)).expect("zero is refused at parse"));
    let schedule = schedule_of(&config.dev)?;
    ChainRules::new(chain, fixed, schedule).map_err(|error| OpenError::Rules(error.to_string()))
}

fn schedule_of(dev: &Dev) -> Result<FakechainSchedule, OpenError> {
    // Each omitted lever is the production value. `FakechainSchedule::new`
    // is the one check, including a single lever against the other side's
    // production value. `new` of the production pair equals `PRODUCTION`.
    let production = FakechainSchedule::PRODUCTION;
    let blocks = dev
        .settlement_epoch_blocks
        .unwrap_or_else(|| production.settlement().blocks().get());
    let cap = dev
        .archival_reorg_depth
        .unwrap_or_else(|| production.reorg_cap().to_raw());
    let epoch = shekyl_chain_rules::SettlementEpochBlocks::new(blocks)
        .ok_or_else(|| OpenError::Rules("the settlement epoch length is zero".to_owned()))?;
    FakechainSchedule::new(epoch, shekyl_types::BlockCount::from_raw(cap))
        .map_err(|error| OpenError::Rules(error.to_string()))
}

fn open_chain(
    path: &std::path::Path,
    horizons: Horizons,
    anchors: &ReleaseAnchors,
) -> Result<ChainStore, OpenError> {
    use shekyl_chain_store::store::{StoreCannot, StoreError};
    match ChainStore::with_release(path, ApplyPolicy::Full, horizons, anchors) {
        Ok(store) => Ok(store),
        Err(StoreError::Cannot(StoreCannot::SchemaVersionMismatch { found, expected })) => {
            tracing::warn!(
                %found,
                %expected,
                "the chain file is a layout this release does not speak; removing it and opening a fresh store"
            );
            std::fs::remove_file(path).map_err(OpenError::Wipe)?;
            Ok(ChainStore::with_release(
                path,
                ApplyPolicy::Full,
                horizons,
                anchors,
            )?)
        }
        Err(error) => Err(error.into()),
    }
}

fn anchors_of(rules: ChainRules) -> ReleaseAnchors {
    match rules {
        ChainRules::Scheduled(net) => ReleaseAnchors::for_network(net),
        ChainRules::Regtest { .. } => ReleaseAnchors::EMPTY,
    }
}

fn open_pool(
    store: &ChainStore,
    path: &std::path::Path,
    rules: ChainRules,
) -> Result<Arc<Mutex<Pool>>, OpenError> {
    let snap = store.begin_read()?;
    let tip = snap.tip()?;
    let height = tip
        .recorded
        .map(|recorded| recorded.height)
        .unwrap_or(BlockHeight::ZERO);
    let rule_set = rules.in_force(height);
    let view = SnapshotView::new(&snap);
    let (pool, opened, _) = Pool::open(
        path,
        wall_now(),
        &view,
        &rule_set,
        &AdmissionPolicy::GENESIS,
    )
    .map_err(|error| OpenError::Pool(format!("{error:?}")))?;
    if let PoolOpen::Recreated { from } = opened {
        tracing::warn!(
            %from,
            "the pool file is a layout this release does not speak; it was recreated empty"
        );
    }
    Ok(Arc::new(Mutex::new(pool)))
}

async fn connect_genesis(
    service: &Service<ProductionSubstrate>,
    network: shekyl_daemon_config::Network,
) -> Result<(), OpenError> {
    // A restart already holds genesis (or a longer chain). `AlreadyHeld` is
    // that case. An empty store connects it.
    let (block, hash) = pinned_genesis(network)?;
    let tagged = service
        .door()
        .offer_local(ArrivalTag(0), block.serialize(), Vec::new())
        .await
        .map_err(|error| OpenError::Genesis(format!("the door refused genesis: {error:?}")))?;
    match tagged.reply {
        Reply::Connected {
            hash: connected, ..
        } if connected == hash => Ok(()),
        Reply::AlreadyHeld => Ok(()),
        other => Err(OpenError::Genesis(format!("{other:?}"))),
    }
}

#[cfg(test)]
mod tests;

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
    ArrivalTag, Door, Follow, PoolWiring, Reply, Service, ServiceConfig,
};
use shekyl_chain_ingest::{Chain, ChainRules, Metrics, ProductionSubstrate};
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

use crate::facts::{BansBridge, ChainBridge, DoorBridge, PoolBridge, StopBridge, Surroundings};
use crate::genesis::{daemon_network, pinned_genesis};

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
    door: Arc<Mutex<Option<Door>>>,
}

/// The daemon's one node (module docs).
pub struct Node {
    slots: Arc<Slots>,
    board: Arc<JobBoard>,
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
        let follow = Follow {
            job: Some(JobSeat {
                board: Arc::clone(&board),
                keys,
                miner: MinerFeed {
                    found: found_inbox,
                    sync: sync_rx.clone(),
                },
                posting: posting_tx,
            }),
            pool: Some(PoolWiring {
                pool,
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(wall_now),
            }),
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
        let tips = match runtime.block_on(service.watch_tip()) {
            Ok(tips) => tips,
            Err(error) => {
                if let Err(stop) = runtime.block_on(service.stop()) {
                    tracing::error!(
                        "the tip watch did not open, and the service stopped on {stop}"
                    );
                }
                runtime.shutdown(RUNTIME_SHUTDOWN);
                return Err(OpenError::Service(error.to_string()));
            }
        };
        let pool_health = service.pool_health();
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
        });
        let mining = Arc::new(MiningControl::new(
            Arc::clone(&board),
            Arc::clone(&caches),
            budget.clone(),
            found,
            miner_address,
            posting.clone(),
            pool_health,
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
        let door_slot = Arc::new(Mutex::new(Some(door)));
        let handles = Handles {
            chain: Arc::new(ChainBridge::new(Arc::clone(&facts_slot))),
            pool: Arc::new(PoolBridge::new(Arc::clone(&pool_slot))),
            door: Arc::new(DoorBridge::new(Arc::clone(&door_slot), tips)),
            mining: Arc::clone(&mining) as _,
            bans: Arc::new(BansBridge),
            stop: Arc::new(StopBridge::new(Arc::clone(&args.request_stop))),
        };
        let slots = Arc::new(Slots {
            facts: facts_slot,
            pool: pool_slot,
            door: door_slot,
        });
        Ok(Self {
            slots,
            board,
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

    /// The job board: the node's one template, while one is posted. Stop
    /// withdraws it.
    #[must_use]
    pub fn board(&self) -> Arc<JobBoard> {
        Arc::clone(&self.board)
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
        self.mining.stop();
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
mod tests {
    use std::ffi::OsString;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use shekyl_chain_rules::ReleaseAnchors;
    use shekyl_chain_store::apply_policy::ApplyPolicy;
    use shekyl_chain_store::store::{ChainStore, Horizons};
    use shekyl_daemon_config::{load, Network, Platform, TABLE};
    use shekyl_daemon_rpc::chain_facts::FactsFault;
    use shekyl_daemon_rpc::handles::Handles;
    use shekyl_difficulty::Difficulty;
    use shekyl_miner::Job;
    use shekyl_options::read_cli;
    use shekyl_rpc_types::DaemonNetwork;
    use shekyl_timing_engine::Tick;
    use shekyl_types::{BlockHash, BlockHeight};

    use super::*;

    fn config_at(dir: &Path) -> DaemonConfig {
        dev_config(dir, &[])
    }

    /// Wait until the follower's posting reads `want`.
    fn wait_for_posting(posting: &mut tokio::sync::watch::Receiver<Posting>, want: &Posting) {
        let started = std::time::Instant::now();
        while *posting.borrow_and_update() != *want {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the posting stayed {:?}",
                *posting.borrow()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn open_at(dir: &Path, stop: Arc<dyn Fn() + Send + Sync>) -> Node {
        std::fs::create_dir_all(dir).expect("dir");
        let config = config_at(dir);
        Node::open(OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: stop,
        })
        .expect("node")
    }

    /// An empty store connects the pinned genesis, and the chain handle
    /// reads it back. Red edit: connect genesis through anything but the
    /// door, or answer the handle from a hard-coded hash.
    #[test]
    fn an_empty_store_holds_the_pinned_genesis_and_the_chain_handle_answers_it() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        let want =
            BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
        let identity = node.handles().chain.identity().expect("identity");
        assert_eq!(identity.genesis_hash, want);
        let at = node
            .handles()
            .chain
            .block_hash_at(BlockHeight::ZERO)
            .expect("height 0");
        assert_eq!(at.hash, Some(want));
        assert!(
            node.handles().door.room().expect("door") > 0,
            "a live door is not the absent handle"
        );
        assert!(!node.handles().mining.running().expect("mining"));
        assert_eq!(node.handles().pool.broadcast_count().expect("pool"), 0);
        node.stop();
    }

    /// `Node::stop` waits, so it refuses to run inside a tokio runtime
    /// (`# Panics`); afterwards the node still stops from outside one. Red
    /// edit: drop the `debug_assert`.
    #[cfg(debug_assertions)]
    #[test]
    fn stopping_the_node_inside_a_runtime_is_refused() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let inside = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async { node.stop() });
        }));
        let refusal = inside.expect_err("stop ran inside a runtime");
        let said = refusal
            .downcast_ref::<&str>()
            .map(|said| (*said).to_owned())
            .or_else(|| refusal.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(
            said.contains("Node::stop waits"),
            "the node's own refusal, not tokio's: {said}"
        );
        drop(runtime);
        node.stop();
        assert!(node.board().posted().is_none());
    }

    /// A regtest node mining to [`mining_address`] at difficulty one, with
    /// `extra` options, once its first template is posted.
    fn open_posted(dir: &Path, extra: &[&str]) -> Node {
        std::fs::create_dir_all(dir).expect("dir");
        let address = mining_address(shekyl_address::Network::Mainnet);
        let mut args = vec!["--mine-address", address.as_str(), "--dev-difficulty", "1"];
        args.extend(extra);
        let config = config_on(dir, "regtest", &args);
        let node = Node::open(OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: Arc::new(|| {}),
        })
        .expect("node");
        let mut posting = node.posting();
        let started = std::time::Instant::now();
        while !matches!(*posting.borrow_and_update(), Posting::Posted(_)) {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "nothing posted: {:?}",
                *posting.borrow()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        node
    }

    fn a_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
    }

    /// `get_block_template` reads the posted job (N2): eight zero bytes
    /// at `reserved_offset`, the hashing blob is the block's, and a block
    /// an outside miner makes by writing both nonces connects through
    /// `submit_block`. Red edit: report the header nonce's offset as the
    /// reserved one.
    #[test]
    fn a_block_made_from_the_template_connects_through_submit_block() {
        use shekyl_daemon_rpc::mining_methods::{get_block_template, submit_block};
        let dir = tempfile::tempdir().expect("temp");
        let node = open_posted(dir.path(), &[]);
        let handles = node.handles();
        let reply = get_block_template(&*handles.mining).expect("a template");
        assert_eq!(reply.height, 1);
        let genesis =
            BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
        assert_eq!(reply.prev_hash.to_bytes(), genesis.to_bytes());
        let mut blob = hex::decode(&reply.blocktemplate_blob).expect("hex");
        let extra = usize::try_from(reply.reserved_offset).expect("fits");
        assert_eq!(
            blob[extra..extra + 8],
            [0; 8],
            "the extra nonce is reserved, zeroed"
        );
        let block = shekyl_wire::Block::from_bytes(&blob).expect("a block");
        assert_eq!(
            hex::decode(&reply.blockhashing_blob).expect("hex"),
            block.pow_blob()
        );
        blob[extra..extra + 8].copy_from_slice(&[7; 8]);
        let nonce = usize::try_from(reply.nonce_offset).expect("fits");
        blob[nonce..nonce + 4].copy_from_slice(&42_u32.to_le_bytes());
        let made = shekyl_wire::Block::from_bytes(&blob).expect("still a block");
        assert_eq!(made.header.nonce, 42);
        let submitted = a_runtime()
            .block_on(submit_block(
                &*handles.door,
                shekyl_rpc_types::mining::SubmitBlockRequest {
                    body: hex::encode(&blob),
                },
            ))
            .expect("it connects");
        assert_eq!(submitted.block_id.to_bytes(), made.hash().to_bytes());
        let tip = handles.chain.chain_tip().expect("tip");
        assert_eq!(tip.top_hash, made.hash());
        node.stop();
    }

    /// A block listing a body the pool does not hold answers
    /// `MissingBodies` with its index, as RW-Q3's refused-by-the-method
    /// class. Red edit: answer every non-connect as `NotReady`.
    #[test]
    fn a_submitted_block_with_a_missing_body_names_its_index() {
        use shekyl_daemon_rpc::mining_methods::{codes, get_block_template, submit_block};
        let dir = tempfile::tempdir().expect("temp");
        let node = open_posted(dir.path(), &[]);
        let handles = node.handles();
        let reply = get_block_template(&*handles.mining).expect("a template");
        let mut block =
            shekyl_wire::Block::from_bytes(&hex::decode(&reply.blocktemplate_blob).expect("hex"))
                .expect("a block");
        block
            .transaction_hashes
            .push(shekyl_types::TxHash::from_bytes([0x5a; 32]));
        let refused = a_runtime()
            .block_on(submit_block(
                &*handles.door,
                shekyl_rpc_types::mining::SubmitBlockRequest {
                    body: hex::encode(block.serialize()),
                },
            ))
            .expect_err("a body is missing");
        assert_eq!(
            refused.class,
            shekyl_rpc_types::errors::ErrorClass::RefusedByMethod
        );
        assert_eq!(refused.diagnostic.code, codes::BLOCK_MISSING_BODIES);
        assert_eq!(
            refused.diagnostic.params,
            vec![("indices".to_owned(), "0".to_owned())]
        );
        node.stop();
    }

    /// With no job posted, the template reads answer `NotReady` with the
    /// node's reason, and `mining_status` carries the same diagnostic.
    /// Red edit: answer a posted-nothing board with an empty template.
    #[test]
    fn with_no_address_the_template_reads_say_why() {
        use shekyl_daemon_rpc::mining_methods::{
            codes, get_block_template, get_miner_data, mining_status, start_mining,
        };
        use shekyl_rpc_types::errors::ErrorClass;
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        let mut posting = node.posting();
        wait_for_posting(&mut posting, &Posting::Withdrawn(NoJob::NoAddress));
        let handles = node.handles();
        for refused in [
            get_block_template(&*handles.mining).map(|_| ()),
            get_miner_data(&*handles.mining).map(|_| ()),
        ] {
            let refused = refused.expect_err("no template");
            assert_eq!(refused.class, ErrorClass::NotReady);
            assert_eq!(refused.diagnostic.code, codes::NO_ADDRESS);
        }
        let status = mining_status(&*handles.mining).expect("status");
        assert!(!status.active);
        assert_eq!(
            status.no_template.map(|why| why.code),
            Some(codes::NO_ADDRESS.to_owned())
        );
        let refused = start_mining(
            &*handles.mining,
            shekyl_rpc_types::mining::StartMiningRequest::default(),
        )
        .expect_err("no address");
        assert_eq!(refused.class, ErrorClass::RefusedByMethod);
        assert_eq!(refused.diagnostic.code, codes::NO_ADDRESS);
        node.stop();
    }

    /// `start_mining`, `mining_status` and `stop_mining` over the node's
    /// mining control; a second stop is refused by the method. Red edit:
    /// answer `stop_mining` OK whether or not the miner ran.
    #[test]
    fn the_miner_starts_reports_and_stops_through_the_handlers() {
        use shekyl_daemon_rpc::mining_methods::{codes, mining_status, start_mining, stop_mining};
        let dir = tempfile::tempdir().expect("temp");
        let node = open_posted(dir.path(), &[]);
        let handles = node.handles();
        let one = shekyl_rpc_types::mining::StartMiningRequest {
            threads: shekyl_rpc_types::mining::MinerThreads::Count(
                std::num::NonZeroU32::new(1).expect("one"),
            ),
        };
        match start_mining(&*handles.mining, one) {
            Ok(_) => {}
            Err(refused) if refused.diagnostic.code == codes::ONE_PERMIT => {
                node.stop();
                return;
            }
            Err(other) => panic!("the miner did not start: {other:?}"),
        }
        let status = mining_status(&*handles.mining).expect("status");
        assert!(status.active);
        assert_eq!(status.threads_count, 1);
        assert!(status.height >= 1, "a job is posted");
        assert!(status.no_template.is_none());
        stop_mining(&*handles.mining).expect("it stops");
        let again = stop_mining(&*handles.mining).expect_err("not running");
        assert_eq!(again.diagnostic.code, codes::STOPPED);
        node.stop();
    }

    /// `generateblocks(3)`, armed, reaches the tip plus three and stops the
    /// miner it started; without `dev-rpc` it is refused outside the
    /// grant (DX-Q3, Q8). Red edit: leave the miner running.
    #[test]
    fn generateblocks_reaches_three_more_and_is_refused_unarmed() {
        use shekyl_daemon_rpc::mining_methods::{admit_armed, codes, generateblocks};
        use shekyl_rpc_types::errors::ErrorClass;
        let row = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
        let unarmed_dir = tempfile::tempdir().expect("temp");
        let unarmed = open_posted(unarmed_dir.path(), &[]);
        assert!(!unarmed.armed_levers());
        let refused = admit_armed(row, unarmed.armed_levers()).expect_err("unarmed");
        assert_eq!(refused.class, ErrorClass::OutsideTheGrant);
        unarmed.stop();

        let dir = tempfile::tempdir().expect("temp");
        let node = open_posted(dir.path(), &["--dev-rpc"]);
        let armed = admit_armed(row, node.armed_levers()).expect("armed");
        let handles = node.handles();
        let generated = a_runtime().block_on(generateblocks(
            &*handles.mining,
            &*handles.door,
            &*handles.chain,
            armed,
            shekyl_rpc_types::mining::GenerateBlocksRequest { count: 3 },
        ));
        let generated = match generated {
            Ok(generated) => generated,
            Err(refused) if refused.diagnostic.code == codes::ONE_PERMIT => {
                node.stop();
                return;
            }
            Err(other) => panic!("generateblocks: {other:?}"),
        };
        assert!(
            generated.height >= 4,
            "genesis and three: {}",
            generated.height
        );
        assert!(generated.blocks.len() >= 3);
        assert!(!node.mining().running(), "the miner it started is stopped");
        node.stop();
    }

    /// The blocking pool has a thread for every task that can be
    /// outstanding at once (module docs, "Blocking threads"): more than the
    /// permits and the window together, so permit waiters alone never fill
    /// it. Red edit: size it at the permits.
    #[test]
    fn the_blocking_pool_exceeds_the_permits_and_the_window() {
        for permits in [1, 2, 8, 64] {
            for window in [1, 32] {
                let threads = blocking_threads(
                    NonZeroUsize::new(permits).expect("nonzero"),
                    NonZeroUsize::new(window).expect("nonzero"),
                );
                assert!(threads.get() > permits + window, "{permits} + {window}");
            }
        }
    }

    /// A full address on `network`, from a fixed seed's keys.
    fn mining_address(network: shekyl_address::Network) -> String {
        use shekyl_crypto_pq::account::{rederive_account, DerivationNetwork, SeedFormat};
        let blob = rederive_account(&[0x5a; 64], DerivationNetwork::Mainnet, SeedFormat::Bip39)
            .expect("the keys");
        shekyl_address::ShekylAddress::new(
            network,
            *blob.spend_pk.as_canonical_bytes(),
            *blob.view_pk.as_canonical_bytes(),
            [0; shekyl_address::MSG_SIGN_PK_LEN],
            blob.ml_kem_ek.to_vec(),
        )
        .encode()
        .expect("encodes")
    }

    /// A node opened on `network` that mines to [`mining_address`].
    fn open_mining(dir: &Path, network: &str, address: shekyl_address::Network) -> Node {
        std::fs::create_dir_all(dir).expect("dir");
        let address = mining_address(address);
        let config = config_on(dir, network, &["--mine-address", &address]);
        Node::open(OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: Arc::new(|| {}),
        })
        .expect("node")
    }

    /// Regtest is synced at open (DX-Q3, Q13), so a node with an address
    /// posts the template for the block after genesis with no session at
    /// all, and `mining_status` reports the job. Red edit: open regtest at
    /// `NoView`.
    #[test]
    fn a_regtest_node_with_an_address_posts_its_template_with_no_sessions() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_mining(dir.path(), "regtest", shekyl_address::Network::Mainnet);
        let mut posting = node.posting();
        let started = std::time::Instant::now();
        while !matches!(*posting.borrow_and_update(), Posting::Posted(_)) {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "nothing posted: {:?}",
                *posting.borrow()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let (_, job) = node.board().posted().expect("the job");
        assert_eq!(job.height, BlockHeight::from_raw(1));
        let genesis =
            BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
        assert_eq!(job.block.header.previous, genesis);
        let status = node.mining().status();
        assert_eq!(status.no_job, None);
        assert_eq!(status.job.map(|posted| posted.height), Some(job.height));
        assert!(status.miner.is_none(), "the miner starts on request only");
        assert!(node
            .handles()
            .chain
            .chain_tip()
            .is_ok_and(|tip| tip.synchronized));
        node.stop();
    }

    /// Off regtest, nothing says the node is synced before chain sync's
    /// cutover: it posts nothing and says why, and publishing `Synced` on
    /// the node's watch posts (DX-Q3, Q13). Red edit: post without reading
    /// the watch.
    #[test]
    fn a_testnet_node_posts_nothing_until_chain_sync_says_synced() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_mining(dir.path(), "testnet", shekyl_address::Network::Testnet);
        let mut posting = node.posting();
        wait_for_posting(
            &mut posting,
            &Posting::Withdrawn(NoJob::NotSynced(SyncState::NoView)),
        );
        assert!(node.board().posted().is_none());
        let reason = node.mining().status().no_job.expect("a reason");
        assert_eq!(
            reason.to_string(),
            "no template: not synced (no sync owner before chain sync's cutover)"
        );
        assert!(node
            .handles()
            .chain
            .chain_tip()
            .is_ok_and(|tip| !tip.synchronized));
        node.sync().send_replace(SyncState::Synced);
        let started = std::time::Instant::now();
        while !matches!(*posting.borrow_and_update(), Posting::Posted(_)) {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "Synced did not post: {:?}",
                *posting.borrow()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(node.board().posted().is_some());
        node.stop();
    }

    /// Stopping the miner from a tokio task completes, and the node is still
    /// up after it: mining control never stops or drops the node (`stop`'s
    /// `# Panics`). Red edit: have `MiningControl::stop` stop the node.
    #[test]
    fn stopping_the_miner_from_a_task_leaves_the_node_running() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_mining(dir.path(), "regtest", shekyl_address::Network::Mainnet);
        let mining = node.mining();
        match mining.start(NonZeroUsize::new(1)) {
            Ok(()) => {}
            Err(MiningRefused::Start(shekyl_miner::MinerStartRefused::OnePermit)) => {
                // A one-permit host never mines; there is nothing to stop.
                node.stop();
                return;
            }
            Err(other) => panic!("the miner did not start: {other}"),
        }
        assert!(mining.running());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let stopped = runtime.block_on(async move {
            tokio::spawn(async move { mining.stop() })
                .await
                .expect("the stop task")
        });
        assert!(stopped, "it was running");
        assert!(!node.mining().running());
        assert!(
            node.handles().door.room().expect("door") > 0,
            "the node is still up"
        );
        node.stop();
    }

    /// Stop closes the store, withdraws the board, and a second stop is a
    /// no-op. A handle held past stop is not ready. Red edit: leave the
    /// facts slot filled, or skip the second stop.
    #[test]
    fn stop_closes_the_store_withdraws_the_board_and_a_second_stop_is_a_no_op() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        let (block, _) = pinned_genesis(Network::Regtest).expect("genesis");
        // The follower's first word, so it does not withdraw the job below:
        // no mine-address, no template.
        let mut posting = node.posting();
        wait_for_posting(&mut posting, &Posting::Withdrawn(NoJob::NoAddress));
        node.board().publish(Job {
            offsets: block
                .blob_offsets()
                .expect("genesis reserves the extra nonce"),
            next_seed: None,
            reward: shekyl_units::AtomicUnits::ZERO,
            median_weight: 0,
            already_generated: shekyl_units::AtomicUnits::ZERO,
            listed: Vec::new(),
            block,
            height: BlockHeight::from_raw(1),
            seed: BlockHash::from_bytes([1; 32]),
            difficulty: Difficulty::from_raw(1),
        });
        assert!(node.board().posted().is_some(), "the job was posted");
        node.stop();
        assert!(node.board().posted().is_none(), "stop withdraws the board");
        node.stop();
        let rules =
            ChainRules::new(Chain::Regtest, None, FakechainSchedule::PRODUCTION).expect("rules");
        let horizons = Horizons::under(&rules.in_force(BlockHeight::ZERO)).expect("horizons");
        let store = ChainStore::with_release(
            dir.path().join("chain.db"),
            ApplyPolicy::Full,
            horizons,
            &ReleaseAnchors::EMPTY,
        )
        .expect("the store closed, so it opens again");
        let snap = store.begin_read().expect("read");
        let tip = snap.tip().expect("tip").recorded.expect("genesis");
        let want =
            BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
        assert_eq!(tip.hash, want);
        assert_eq!(
            node.handles().chain.identity(),
            Err(FactsFault::NotReady),
            "the handle does not answer after the store closes"
        );
    }

    /// A `pow_hash` waiting on a hasher permit does not hold the facts
    /// lock: a chain read returns while that wait is in progress.
    ///
    /// [`shekyl_hash_budget::Budget::waiting`] is the signal. It rises
    /// inside `acquire`, which runs inside the read, so the chain read
    /// starts only once the slot guard would already be held. The permits
    /// stay held until that read returns, so a guard that spanned the wait
    /// fails `READ_BOUND`. Both bounds are failure limits: the enter loop
    /// returns when the wait is visible, and a read that finishes returns
    /// at once.
    ///
    /// Red edit: hold the slot mutex across `read`.
    #[test]
    fn a_pow_hash_in_flight_does_not_hold_the_facts_lock() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        use shekyl_daemon_rpc::chain_facts::ChainFacts;
        use shekyl_daemon_rpc::read_facts::{ChainReadFacts, PowSeed};
        use shekyl_hash_budget::Class;

        /// The hash thread has not reached `acquire`.
        const ENTER_BOUND: Duration = Duration::from_secs(5);
        /// The chain read shared the permit wait. The permits are still held.
        const READ_BOUND: Duration = Duration::from_secs(2);

        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        let budget = node.budget();
        // Every free permit. `pow_hash` then waits in `acquire` instead of
        // hashing, which is the wait a chain read must not share.
        let held: Vec<_> = (0..budget.permits())
            .map_while(|_| budget.try_acquire(Class::Chain))
            .collect();
        assert!(
            budget.try_acquire(Class::CalcPow).is_none(),
            "a calc_pow permit was still free"
        );
        let hashing = {
            let chain = Arc::clone(&node.handles().chain);
            std::thread::spawn(move || {
                ChainReadFacts::pow_hash(&*chain, &[], PowSeed::Given(BlockHash::NULL))
            })
        };
        let entered = Instant::now();
        while budget.waiting(Class::CalcPow) == 0 {
            if hashing.is_finished() {
                let finished = hashing.join().expect("pow thread");
                panic!("pow_hash finished without waiting for a permit: {finished:?}");
            }
            assert!(
                entered.elapsed() < ENTER_BOUND,
                "pow_hash did not wait for a permit"
            );
            std::thread::yield_now();
        }
        let (done, arrived) = mpsc::channel();
        let reading = {
            let chain = Arc::clone(&node.handles().chain);
            std::thread::spawn(move || {
                let _read = ChainFacts::chain_tip(&*chain).is_ok();
                let _sent = done.send(()).is_ok();
            })
        };
        assert!(
            arrived.recv_timeout(READ_BOUND).is_ok(),
            "a chain read waited on the pow hash, so the facts lock is held across the permit wait"
        );
        drop(held);
        let hashed = hashing.join().expect("pow thread");
        assert!(
            hashed.is_ok(),
            "the hash finishes once a permit is free: {hashed:?}"
        );
        reading.join().expect("the chain read");
    }

    /// A ban through the node is on the table `process_sockets` reads.
    /// Red edit: install a second table, or ban on a table the node does
    /// not hold.
    #[test]
    fn a_ban_through_the_node_is_on_the_process_socket_table() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        assert!(
            shekyl_ffi::seam_ffi::install_process_sockets(node.sockets()),
            "the table is installed once, before any reader"
        );
        let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        node.handles().bans.ban_host(host).expect("ban");
        assert!(
            shekyl_ffi::seam_ffi::process_sockets().is_banned(host, Tick::new(0)),
            "the FFI reader sees the node's table"
        );
        assert!(node.handles().bans.banned(host).expect("banned"));
        node.stop();
    }

    /// The node's stop handle is the latch `main` passed in. The absent
    /// handle is not ready, never a success. Red edit: call the latch from
    /// the absent handle, or ignore `request_stop`.
    #[test]
    fn the_stop_handle_asks_the_latch_and_the_absent_one_does_not() {
        let asked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&asked);
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(
            dir.path(),
            Arc::new(move || flag.store(true, Ordering::SeqCst)),
        );
        node.handles().stop.request_stop().expect("asks");
        assert!(asked.load(Ordering::SeqCst));
        assert_eq!(
            Handles::absent().stop.request_stop(),
            Err(FactsFault::NotReady)
        );
        node.stop();
    }

    fn genesis_hash() -> BlockHash {
        BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain))
    }

    fn put_chain_version(path: &std::path::Path, version: u64) {
        use shekyl_chain_store::codec::{PropertyCellBytes, SchemaVersion};
        use shekyl_chain_store::schema::PROPERTIES;
        use shekyl_store_codec::{Canonical, Raw};
        let db = redb::Database::open(path).expect("the chain file opens");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(PROPERTIES).expect("properties");
            let version = SchemaVersion::new(version);
            table
                .insert(
                    "schema_version",
                    Raw::<PropertyCellBytes>::new(&version.encode()),
                )
                .expect("version");
        }
        txn.commit().expect("commit");
    }

    fn put_pool_version(path: &std::path::Path, version: u64) {
        use shekyl_chain_store::codec::PropertyCellBytes;
        use shekyl_chain_store::pool::schema::POOL_HEADER;
        use shekyl_chain_store::pool::{PoolSchemaVersion, POOL_VERSION_KEY};
        use shekyl_store_codec::{Canonical, Raw};
        let db = redb::Database::open(path).expect("the pool file opens");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(POOL_HEADER).expect("header");
            let version = PoolSchemaVersion::new(version);
            table
                .insert(
                    POOL_VERSION_KEY,
                    Raw::<PropertyCellBytes>::new(&version.encode()),
                )
                .expect("version");
        }
        txn.commit().expect("commit");
    }

    /// A chain file at another layout is removed and a fresh store holds
    /// genesis. A file that is not a store is refused and left in place.
    /// Red edit: refuse the version mismatch, or wipe a corrupt header.
    #[test]
    fn a_foreign_chain_file_is_replaced_and_a_corrupt_one_is_kept() {
        use shekyl_chain_store::codec::SCHEMA_VERSION;
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        node.stop();
        let chain = dir.path().join("chain.db");
        put_chain_version(&chain, SCHEMA_VERSION.get() + 1);
        let node = open_at(dir.path(), Arc::new(|| {}));
        assert_eq!(
            node.handles()
                .chain
                .block_hash_at(BlockHeight::ZERO)
                .expect("height 0")
                .hash,
            Some(genesis_hash())
        );
        node.stop();
        put_chain_version(&chain, SCHEMA_VERSION.get());
        let garbage = b"not a chain store";
        std::fs::write(&chain, garbage).expect("overwrite");
        let config = config_at(dir.path());
        let opened = Node::open(OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: Arc::new(|| {}),
        });
        assert!(
            opened.is_err(),
            "a corrupt chain file is not a layout mismatch"
        );
        assert_eq!(std::fs::read(&chain).expect("still there"), garbage);
    }

    /// A pool file at another version is recreated and the node starts. A
    /// pool file that is not a pool file is refused and kept. Red edit:
    /// refuse the version, or delete the corrupt file.
    #[test]
    fn a_foreign_pool_file_is_recreated_and_a_corrupt_one_is_kept() {
        use shekyl_chain_store::pool::POOL_SCHEMA_VERSION;
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        node.stop();
        let pool = dir.path().join("pool.db");
        put_pool_version(&pool, POOL_SCHEMA_VERSION.get() + 1);
        let node = open_at(dir.path(), Arc::new(|| {}));
        assert_eq!(node.handles().pool.broadcast_count().expect("pool"), 0);
        node.stop();
        let garbage = b"not a pool file";
        std::fs::write(&pool, garbage).expect("overwrite");
        let config = config_at(dir.path());
        let opened = Node::open(OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: Arc::new(|| {}),
        });
        assert!(opened.is_err(), "a corrupt pool file is refused");
        assert_eq!(std::fs::read(&pool).expect("still there"), garbage);
    }

    fn dev_config(dir: &Path, extra: &[&str]) -> DaemonConfig {
        config_on(dir, "regtest", extra)
    }

    fn config_on(dir: &Path, network: &str, extra: &[&str]) -> DaemonConfig {
        let log = dir.join("shekyld.log");
        let mut args = vec![
            "--network",
            network,
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--data-dir",
            dir.to_str().expect("utf8"),
            "--log-file",
            log.to_str().expect("utf8"),
        ];
        args.extend(extra);
        let cli = read_cli(&TABLE, args.into_iter().map(OsString::from)).expect("cli");
        load(
            cli,
            &Platform {
                home: Some(dir.to_path_buf()),
                program_data: None,
            },
        )
        .expect("config")
        .config
    }

    /// One regtest lever is filled from production on the other side and
    /// the node opens. A cap that is not strictly inside the epoch is
    /// refused. Red edit: require the two levers to be set together, or
    /// accept a cap outside the epoch.
    #[test]
    fn one_archival_lever_opens_and_a_cap_outside_the_epoch_does_not() {
        let dir = tempfile::tempdir().expect("temp");
        let config = dev_config(dir.path(), &["--dev-archival-reorg-depth", "10"]);
        let node = Node::open(OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: Arc::new(|| {}),
        })
        .expect("one lever, the other side production");
        node.stop();
        let refused = dev_config(
            dir.path(),
            &[
                "--dev-settlement-epoch-blocks",
                "10",
                "--dev-archival-reorg-depth",
                "10",
            ],
        );
        let opened = Node::open(OpenArgs {
            config: &refused,
            version: "test".to_owned(),
            protocol_version: 1,
            release_build: false,
            request_stop: Arc::new(|| {}),
        });
        assert!(
            opened.is_err(),
            "a reorg cap that is not inside the epoch is refused"
        );
    }
}

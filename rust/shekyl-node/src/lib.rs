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
//! The runtime's blocking-thread count equals the hasher budget's permits.
//! [`Budget::acquire`](shekyl_hash_budget::Budget::acquire) waits on the
//! calling thread, so every permit waiter sits on a blocking thread. A
//! holder never waits for another thread: it hashes and drops the permit.
//! The two counts can stay equal. A later sizing that makes a holder wait
//! for a blocking thread has to split them, or a full set of waiters
//! deadlocks.
//!
//! # The board
//!
//! The node holds the job board and seats it with no miner. Nothing is
//! posted: there is no template and no sync owner yet. Stop withdraws the
//! board. PR 3b seats the miner on this board. The miner is not started
//! here.

#![deny(unsafe_code)]

mod facts;
mod genesis;

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use shekyl_chain_ingest::follower::JobSeat;
use shekyl_chain_ingest::service::{
    Arrival, ArrivalTag, Door, Follow, Origin, PoolWiring, Reply, Service, ServiceConfig,
};
use shekyl_chain_ingest::{Chain, ChainRules, Metrics, ProductionSubstrate};
use shekyl_chain_rules::{AdmissionPolicy, FakechainSchedule, ReleaseAnchors, RuleSet};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, Horizons, SnapshotView};
use shekyl_daemon_config::sections::{DaemonConfig, Dev};
use shekyl_daemon_rpc::handles::Handles;
use shekyl_daemon_rpc::store_facts::{NodeIdentity, RulesAt, StoreFacts};
use shekyl_hash_budget::Budget;
use shekyl_mempool::Pool;
use shekyl_miner::JobBoard;
use shekyl_pow_randomx::CacheStore;
use shekyl_runtime::{RuntimeBudget, ThreadName};
use shekyl_transport_layer::Sockets;
use shekyl_types::{BlockHeight, UnixSeconds};

use crate::facts::{
    BansBridge, ChainBridge, DoorBridge, MiningBridge, PoolBridge, StopBridge, Surroundings,
};
use crate::genesis::{daemon_network, pinned_genesis};

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
    facts: Arc<Mutex<Option<StoreFacts>>>,
    pool: Arc<Mutex<Option<Arc<Mutex<Pool>>>>>,
    door: Arc<Mutex<Option<Door>>>,
}

/// The daemon's one node (module docs).
pub struct Node {
    slots: Arc<Slots>,
    board: Arc<JobBoard>,
    sockets: Sockets,
    handles: Handles,
    service: Mutex<Option<Service<ProductionSubstrate>>>,
    runtime: Mutex<Option<shekyl_runtime::Pool>>,
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
        let follow = Follow {
            job: Some(JobSeat {
                board: Arc::clone(&board),
                miner: None,
            }),
            pool: Some(PoolWiring {
                pool,
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(wall_now),
            }),
        };
        let runtime = shekyl_runtime::runtime(
            // Blocking threads equal permits. See the module docs: a waiter
            // blocks its thread inside `acquire`, and a holder does not wait
            // for a thread.
            RuntimeBudget {
                workers: parallelism,
                blocking: parallelism,
            },
            &ThreadName::new("shekyl-node").expect("the name is static"),
        )?;
        let network = args.config.network;
        let started = runtime.block_on(async {
            let service = Service::start(
                Arc::clone(&store),
                rules,
                substrate,
                ServiceConfig::default(),
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
        let door = service.door();
        let surroundings = Arc::new(Surroundings {
            pool: Arc::clone(&pool_slot),
            data_dir: args.config.data_dir.clone(),
            offline: args.config.offline(),
        });
        let started_at = facts::unix_now();
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
        let facts_slot = Arc::new(Mutex::new(Some(facts)));
        let door_slot = Arc::new(Mutex::new(Some(door)));
        let handles = Handles {
            chain: Arc::new(ChainBridge::new(Arc::clone(&facts_slot))),
            pool: Arc::new(PoolBridge::new(Arc::clone(&pool_slot))),
            door: Arc::new(DoorBridge::new(Arc::clone(&door_slot))),
            mining: Arc::new(MiningBridge),
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
            sockets,
            handles,
            service: Mutex::new(Some(service)),
            runtime: Mutex::new(Some(runtime)),
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

    /// The job board. Empty until a miner is seated. Stop withdraws it.
    #[must_use]
    pub fn board(&self) -> Arc<JobBoard> {
        Arc::clone(&self.board)
    }

    /// Stop the ingest service, clear the handles' slots, and shut the runtime down.
    ///
    /// The follower withdraws the job board on the way out. A second call
    /// does nothing. [`Drop`] calls this.
    pub fn stop(&self) {
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
    let (pool, _, _) = Pool::open(
        path,
        wall_now(),
        &view,
        &rule_set,
        &AdmissionPolicy::GENESIS,
    )
    .map_err(|error| OpenError::Pool(format!("{error:?}")))?;
    Ok(Arc::new(Mutex::new(pool)))
}

async fn connect_genesis(
    service: &Service<ProductionSubstrate>,
    network: shekyl_daemon_config::Network,
) -> Result<(), OpenError> {
    // A restart already holds genesis (or a longer chain). `AlreadyHeld` is
    // that case. An empty store connects it.
    let (block, hash) = pinned_genesis(network)?;
    let ticket = service
        .door()
        .offer(Arrival {
            tag: ArrivalTag(0),
            origin: Origin::Local,
            block: block.serialize(),
            bodies: Vec::new(),
        })
        .map_err(|error| OpenError::Genesis(format!("the door refused genesis: {error:?}")))?;
    match ticket.reply().await.reply {
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

    /// Stop closes the store, withdraws the board, and a second stop is a
    /// no-op. A handle held past stop is not ready. Red edit: leave the
    /// facts slot filled, or skip the second stop.
    #[test]
    fn stop_closes_the_store_withdraws_the_board_and_a_second_stop_is_a_no_op() {
        let dir = tempfile::tempdir().expect("temp");
        let node = open_at(dir.path(), Arc::new(|| {}));
        let (block, _) = pinned_genesis(Network::Regtest).expect("genesis");
        node.board().publish(Job {
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
        let log = dir.join("shekyld.log");
        let mut args = vec![
            "--network",
            "regtest",
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

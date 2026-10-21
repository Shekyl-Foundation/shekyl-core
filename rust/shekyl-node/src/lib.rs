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
//! [`Node::stop`] is one step of the daemon's `finish`, in this order
//! (`TOR_SUPERVISOR.md` §1; the dialer stops before Tor is torn down):
//!
//! 1. `network::stop` — the dialer and the zone host, so nothing new arrives.
//! 2. The RPC drains. It still reads the C++ core.
//! 3. [`Node::stop`] — the ingest service stops, the follower withdraws the
//!    job board, the connector finishes its current message, and the store
//!    closes. Durability is `Immediate`: there is no flush.
//! 4. The remnant's stop and the managed Tor's teardown run together.
//!
//! A second [`Node::stop`] is a no-op.
//!
//! # The template
//!
//! The follower still takes a [`TemplateSource`](shekyl_chain_ingest::follower::TemplateSource).
//! This node gives it one that builds nothing, and holds the sync watch
//! closed (the node is behind until a sync owner exists), so the board
//! stays withdrawn. PR 3b deletes that source: the follower builds the one
//! template itself. The miner is not started here.

#![deny(unsafe_code)]

mod facts;
mod genesis;

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use shekyl_chain_ingest::connector::ChainFacts as TemplateChainFacts;
use shekyl_chain_ingest::follower::{MinerFeed, TemplateSource};
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
use shekyl_miner::{found_blocks, FoundBlocks, JobBoard};
use shekyl_pow_randomx::CacheStore;
use shekyl_runtime::{RuntimeBudget, ThreadName};
use shekyl_transport_layer::Sockets;
use shekyl_types::{BlockHeight, UnixSeconds};
use shekyl_wire::{Block, Transaction};
use tokio::sync::watch;

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
    /// Kept so the follower's sync watch stays open and reads `false`.
    _synced: watch::Sender<bool>,
    /// Kept so the found-block sink's sender outlives the service.
    _found: FoundBlocks,
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
        let store = Arc::new(ChainStore::with_release(
            &store_path,
            ApplyPolicy::Full,
            horizons,
            &anchors,
        )?);
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
        let (synced, synced_rx) = watch::channel(false);
        let (found, found_rx) = found_blocks();
        let follow = Follow {
            miner: Some(MinerFeed {
                board: Arc::clone(&board),
                source: Arc::new(NoTemplate),
                synced: synced_rx,
                found: found_rx,
            }),
            pool: Some(PoolWiring {
                pool,
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(wall_now),
            }),
        };
        let runtime = shekyl_runtime::runtime(
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
            bans: Arc::new(BansBridge::new(sockets.clone())),
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
            _synced: synced,
            _found: found,
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

    /// The job board. Withdrawn while the node is behind, which it is
    /// until a sync owner exists.
    #[must_use]
    pub fn board(&self) -> Arc<JobBoard> {
        Arc::clone(&self.board)
    }

    /// Stop (module docs). A second call does nothing.
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

struct RulesOf(ChainRules);

impl RulesAt for RulesOf {
    fn in_force(&self, height: BlockHeight) -> RuleSet {
        self.0.in_force(height)
    }
}

/// Builds nothing. PR 3b's follower posts the one template and this goes.
struct NoTemplate;

impl TemplateSource for NoTemplate {
    fn template(&self, _facts: &TemplateChainFacts) -> Option<(Block, Vec<Transaction>)> {
        None
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
    match (dev.settlement_epoch_blocks, dev.archival_reorg_depth) {
        (None, None) => Ok(FakechainSchedule::PRODUCTION),
        (Some(blocks), Some(cap)) => {
            let epoch =
                shekyl_chain_rules::SettlementEpochBlocks::new(blocks).ok_or_else(|| {
                    OpenError::Rules("the settlement epoch length is zero".to_owned())
                })?;
            FakechainSchedule::new(epoch, shekyl_types::BlockCount::from_raw(cap))
                .map_err(|error| OpenError::Rules(error.to_string()))
        }
        _ => Err(OpenError::Rules(
            "the settlement epoch and the archival reorg depth are set together".to_owned(),
        )),
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
        let log = dir.join("shekyld.log");
        let args = [
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
}

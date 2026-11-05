// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's one [`Node`] (`DRS_X_STORE_FLIP.md` DX-Q6, N1).
//!
//! Rust `main` builds it at start, after the network marker and before the
//! remnant's `run`. It owns the chain store, the ingest service, the pool,
//! the hasher budget, the cache store, the job board and the socket table.
//! The handler's block arrivals enter the ingest door, and its transactions
//! enter this pool. An empty store connects the pinned genesis through the
//! service's door.
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
//! ([`MiningControl`]) hashes what is posted. With `mine = on` the daemon's
//! sequence starts it once, after [`Node::open`] returns, with the
//! `mine-threads` count (`start(None)`); it idles until a job is posted.
//! Off, it starts on `start_mining`. Either way `start_mining` and
//! `stop_mining` act on the running node, and a restart returns to the
//! configuration. Stop withdraws the board.

#![deny(unsafe_code)]

mod facts;
mod genesis;
mod mining;
mod producer;
mod sync_owner;

pub use facts::free_bytes;
pub use mining::{MiningControl, MiningRefused, MiningStatus, PostedJob};
pub use producer::descriptors as producer_descriptors;
pub use shekyl_chain_sync::Declaration;
pub use shekyl_chain_sync_runtime::owner::{EndCause, Ended as SyncEnded};

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use shekyl_block_template::MinerKeys;
use shekyl_chain_ingest::follower::{JobSeat, MinerFeed, NoJob, Posting};
use shekyl_chain_ingest::service::{
    ArrivalTag, Follow, PoolWiring, Reply, Service, ServiceConfig, ServiceFault,
};
use shekyl_chain_ingest::{ChainRules, Metrics, ProductionSubstrate, SubstrateFault};
use shekyl_chain_rules::{AdmissionPolicy, FakechainSchedule, GenesisPin, RuleSet};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::pool::PoolOpen;
use shekyl_chain_store::store::{ChainStore, CutShort, Horizons, SnapshotView};
use shekyl_chain_sync::{Requesting, SyncState};
use shekyl_chain_sync_runtime::executor::Executor;
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
use tokio::sync::Notify;

use crate::facts::{
    BansBridge, ChainBridge, DoorBridge, DoorEntry, PoolBridge, StopBridge, Surroundings,
};
use crate::genesis::pinned_genesis;
use shekyl_ffi::seam_ffi::bans::BanPath;

/// The runtime's blocking threads for `permits` hasher permits and an
/// arrival window of `window` (module docs, "Blocking threads").
fn blocking_threads(permits: NonZeroUsize, window: NonZeroUsize) -> NonZeroUsize {
    permits.saturating_add(window.get()).saturating_add(1)
}

/// The operator's declaration of the node's network (CS-Q2 step 8), from
/// the resolved configuration: `Offline` when both connectors are off,
/// `Closed` when the peer list is closed, `Open` otherwise. Configuration,
/// never the network type (rule 71). Public so the daemon's start can say,
/// before the node opens, that an `Open` node's miner waits for a view
/// (`shekyl-daemon`'s mining notice, DC-F41).
#[must_use]
pub fn declaration(config: &DaemonConfig) -> Declaration {
    if config.offline() {
        Declaration::Offline
    } else if !config.p2p.closed_peers.is_empty() {
        Declaration::Closed
    } else {
        Declaration::Open
    }
}

/// After the service has joined, how long a leftover blocking task may run
/// before the runtime detaches it. The connector has already finished; this
/// bound is only the runtime's, and it is not a protocol constant.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

/// How long chain sync's blocking work (a proof or a store read) may run
/// after its owner is told to stop. Not a protocol constant.
const SYNC_OWNER_SHUTDOWN: Duration = Duration::from_secs(5);

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
    /// The chain file was written by a newer release than this binary. It
    /// is left as it is: removing it would destroy the newer node's data.
    #[error(
        "the chain file is layout {found}, newer than this binary's {expected}: this \
         binary is older than the store, so the store was left untouched. Run the release \
         that wrote it, or a newer one"
    )]
    NewerChainLayout {
        /// The layout the file was sealed at.
        found: shekyl_chain_store::codec::SchemaVersion,
        /// The layout this binary writes.
        expected: shekyl_chain_store::codec::SchemaVersion,
    },
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
    /// Chain sync's owner did not start.
    #[error("chain sync did not start: {0}")]
    Sync(String),
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
    /// The shell's relay entry, handed in the same way (DC-F43): `true`
    /// when the relay took the committed transaction's blob; `false` is no
    /// route (no notifier bound, whatever the reason), and the node shows
    /// the transaction at the origin. The binary passes the C++
    /// `shekyl_shell_relay_local`; a test passes [`no_relay`]. RD deletes
    /// it with `levin_notify`.
    pub relay_local: RelayLocal,
}

/// The shell's relay entry, as [`OpenArgs::relay_local`] takes it.
pub type RelayLocal = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// A [`RelayLocal`] with no route: an offline node's, and a test's. Every
/// transaction it is handed is shown at the origin.
#[must_use]
pub fn no_relay() -> RelayLocal {
    Arc::new(|_| false)
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
    /// Chain sync's state, as the follower reads it. The owner is its only
    /// publisher: the node hands it the one sender and keeps this receiver.
    sync: tokio::sync::watch::Receiver<SyncState>,
    /// What the board holds, as the follower last left it.
    posting: tokio::sync::watch::Receiver<Posting>,
    mining: Arc<MiningControl>,
    /// The `dev-rpc` row: whether the armed test levers are served.
    armed: bool,
    sockets: Sockets,
    handles: Handles,
    service: Mutex<Option<Service<ProductionSubstrate>>>,
    /// Chain sync's owner (CS-5 §2), the node's for its lifetime. It
    /// publishes into [`Self::sync`], and the seam's bind hands it the hub.
    sync_owner: Mutex<Option<sync_owner::Held>>,
    /// How chain sync's owner ended, once it has ([`Self::sync_ended`]).
    sync_ended: tokio::sync::watch::Receiver<Option<shekyl_chain_sync_runtime::owner::Ended>>,
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
        let genesis = genesis_pin_of(rules);
        std::fs::create_dir_all(&args.config.data_dir).map_err(OpenError::Directory)?;
        let store_path = args.config.data_dir.join("chain.db");
        let pool_path = args.config.data_dir.join("pool.db");
        let store = Arc::new(open_chain(&store_path, horizons, &genesis)?);
        tracing::info!("{}", store_durability_line());
        let parallelism = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        let budget = Budget::new(parallelism);
        let caches = Arc::new(CacheStore::new());
        let substrate = Arc::new(ProductionSubstrate::new(
            Arc::clone(&caches),
            Arc::new(Metrics::new()),
        ));
        let pool = open_pool(&store, &pool_path, rules)?;
        let submit_pool = Arc::clone(&pool);
        let complement_pool = Arc::clone(&pool);
        let sync_substrate = ProductionSubstrate::clone(&substrate);
        let departed = pool_departed();
        // Q9: fluff at this tip rebuilds the posted job. Same Notify the
        // follower waits on for parked bodies.
        let shown = Arc::new(Notify::new());
        let shown_hook: shekyl_ffi::pool_ffi::Shown = {
            let shown = Arc::clone(&shown);
            Arc::new(move || shown.notify_one())
        };
        shekyl_ffi::pool_ffi::install(
            Arc::clone(&store),
            Arc::clone(&pool),
            rules,
            AdmissionPolicy::GENESIS,
            Arc::clone(&departed),
            shown_hook,
        );
        let pool_slot = Arc::new(Mutex::new(Some(Arc::clone(&pool))));
        let sockets = Sockets::new();
        let board = Arc::new(JobBoard::new());
        let network = args.config.network;
        let declared = declaration(args.config);
        // No view until genesis has connected, so the follower never builds
        // a genesis of its own. The owner, started after genesis connects,
        // publishes the declaration's state at open and every state after.
        let (sync_tx, sync) = tokio::sync::watch::channel(SyncState::NoView);
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
            .map(|address| MiningAddress::decode(&address.text, network))
            .transpose()
            .map_err(|refused| OpenError::Rules(format!("the mine-address row: {refused}")))?;
        // Every template draws its `0x0C` commitment from this ring, and the
        // bundle producer files from it (`SO-D12` increment 4c).
        let witness = Arc::new(shekyl_bundle_producer::WitnessRing::new());
        let producer = producer::seat(args.config, &store, &witness);
        let follow = Follow {
            job: Some(JobSeat {
                board: Arc::clone(&board),
                keys,
                miner: MinerFeed {
                    found: found_inbox,
                    sync: sync.clone(),
                },
                posting: posting_tx,
                witness: Arc::clone(&witness),
            }),
            pool: Some(PoolWiring {
                pool,
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(wall_now),
                departed: Some(Arc::clone(&departed)),
            }),
            producer,
            shown: Some(shown),
            // The substrate's own sink, which the sync owner's executor
            // shares: every phase of the per-block profile in one place.
            metrics: Some(Arc::clone(substrate.metrics())),
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
                abandon_open(runtime, OpenUnwind::ServiceStopped);
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
                abandon_open(
                    runtime,
                    OpenUnwind::StillRunning {
                        service,
                        why: "a connector watch did not open",
                    },
                );
                return Err(OpenError::Service(error.to_string()));
            }
        };
        let sync_owner = match sync_owner::spawn(sync_owner::Parts {
            store: Arc::clone(&store),
            door: service.door(),
            alarm: service.alarm(),
            tips: tips.clone(),
            latch: latch.clone(),
            executor: Arc::new(Executor::new(budget.clone(), sync_substrate)),
            rules,
            requesting: if args.config.dev.sync {
                Requesting::On
            } else {
                Requesting::Off
            },
            declaration: declared,
            pool: complement_pool,
            state: sync_tx,
        }) {
            Ok(owner) => owner,
            Err(error) => {
                abandon_open(
                    runtime,
                    OpenUnwind::StillRunning {
                        service,
                        why: "chain sync did not start",
                    },
                );
                return Err(error);
            }
        };
        // DX-Q2 item 5: the dialer's outbound handshake is a consumer of the
        // one tip source. Publish the tip the watch holds now, then every
        // change; the task ends when the connector drops its sender.
        // The first tip is published here, before open returns: the seam
        // binds after, so no handshake, inbound or outbound, finds none
        // (CS-5 F4, `shekyl_p2p_handshake_tip`).
        let mut handshake_tips = tips.clone();
        if let Some(tip) = handshake_tips.borrow_and_update().tip {
            shekyl_ffi::dialer_ffi::publish_chain_tip(&tip);
        }
        // The ban timer is the table's, not the zone host's. An offline
        // node never starts a zone, and a finite ban would otherwise stay
        // in force after its deadline (OE-D9: a lookup does not end one).
        shekyl_ffi::seam_ffi::bans::start(runtime.handle(), sockets.clone());
        runtime.spawn(async move {
            while handshake_tips.changed().await.is_ok() {
                if let Some(tip) = handshake_tips.borrow_and_update().tip {
                    shekyl_ffi::dialer_ffi::publish_chain_tip(&tip);
                }
            }
        });
        let pool_health = service.pool_health();
        shekyl_daemon_rpc::submit::install_production(
            shekyl_daemon_rpc::submit::RustPoolShim::new(
                shekyl_daemon_rpc::submit::StoreChain::new(
                    Arc::clone(&store),
                    Arc::new(RulesOf(rules)),
                ),
                submit_pool,
                AdmissionPolicy::GENESIS,
                wall_now,
                rules.trust().network_id(),
            )
            .retiring(Arc::new({
                let health = pool_health.clone();
                move |fault| health.retire(fault)
            }))
            .nudging(Arc::new({
                // The shell answers `false` only when no relay exists: an
                // offline node never constructs one, so there is no network
                // to hide from and the transaction is shown at once (RX-2,
                // Rick 2026-10-29). With a relay, the answer is `true`
                // before the zone plans on its strand, so `NoOwnEdge` and
                // `AwaitSync` never reach this branch: the zone holds those
                // (`hold_origin`), neither fluffed nor shown. An empty blob
                // is nothing to relay.
                let relay_local = args.relay_local;
                move |txid, blob| {
                    if blob.is_empty() || !relay_local(blob) {
                        shekyl_ffi::pool_ffi::note_shown(*txid);
                    }
                }
            }))
            .departing(Arc::clone(&departed)),
        );
        let rewinder = service.rewinder();
        let at_open = declared.state_at_open();
        tracing::info!(
            "chain sync's state at open: {at_open:?} (declared {declared:?}); the node posts a template only while it reads Synced"
        );
        let door = service.door();
        let surroundings = Arc::new(Surroundings {
            pool: Arc::clone(&pool_slot),
            data_dir: args.config.data_dir.clone(),
            offline: args.config.offline(),
            sync: sync.clone(),
            latch,
            view: sync_owner.view(),
            health: pool_health.clone(),
        });
        let mining =
            Arc::new(MiningControl::new(
                Arc::clone(&board),
                Arc::clone(&caches),
                budget.clone(),
                found,
                mining::Configured {
                    address: miner_address,
                    // A u32 count fits a usize on every target the node builds
                    // for; one that did not would be a row's refusal, not a
                    // silent clamp.
                    threads: args.config.mine.threads.map(|count| {
                        NonZeroUsize::try_from(count).expect("a u32 count fits a usize")
                    }),
                },
                mining::Watched {
                    posting: posting.clone(),
                    tips: tips.clone(),
                },
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
                nettype: network,
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
        let node = Self {
            slots,
            sync,
            posting,
            mining,
            armed: args.config.dev.rpc,
            sockets,
            handles,
            service: Mutex::new(Some(service)),
            sync_ended: sync_owner.ended(),
            sync_owner: Mutex::new(Some(sync_owner)),
            runtime: Mutex::new(Some(runtime)),
            #[cfg(test)]
            budget: test_budget,
        };
        Ok(node)
    }

    /// The handles the RPC server carries.
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
    /// reads `Synced`. The owner is its only publisher; this is a reader.
    #[must_use]
    pub fn sync(&self) -> tokio::sync::watch::Receiver<SyncState> {
        self.sync.clone()
    }

    /// How chain sync's owner ended, once it has: `None` while it runs.
    /// An owner that ends on its own ([`SyncEnded::Failed`]) leaves a
    /// daemon that never syncs again, so the daemon stops on
    /// [`EndCause::text`]. The watch outlives the owner and the node's
    /// stop.
    #[must_use]
    pub fn sync_ended(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<shekyl_chain_sync_runtime::owner::Ended>> {
        self.sync_ended.clone()
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

    /// Ask chain sync to stop before the seam is torn down.
    ///
    /// [`Self::stop`] joins the owner afterwards. A second call, and a
    /// call after the owner has been taken, do nothing. The daemon's
    /// teardown calls this before it shuts the network down, which drops
    /// the hub the owner is waiting on.
    pub fn request_sync_stop(&self) {
        if let Some(owner) = self
            .sync_owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            owner.request_stop();
        }
    }

    /// Ask chain sync's owner to publish `state`.
    ///
    /// The owner is still the only publisher. The node's tests use this
    /// while the seam is unbound, which is before the owner accepts any
    /// other input. The runtime enables it from this crate's dev edge
    /// (`publish-for-test`); a shipped build has no such ask.
    #[cfg(test)]
    pub fn publish_sync_for_test(&self, state: SyncState) {
        if let Some(owner) = self
            .sync_owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            owner.publish_for_test(state);
        }
    }

    /// The node's miner.
    #[must_use]
    pub fn mining(&self) -> Arc<MiningControl> {
        Arc::clone(&self.mining)
    }

    /// Whether the node was started with `dev-rpc`: the switch the armed
    /// test levers are admitted under
    /// (`shekyl_rpc_types::methods::admit_armed`).
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
        // and a handle may keep mining control alive past the node. The
        // close parks them without the join gate, so it returns before the
        // hash; they hold no store handle, and what they finish now is
        // dropped before it becomes a block. A start that has published
        // its stop flag and not yet its threads is signaled here too, so
        // those threads deliver nothing after this returns. The join takes
        // that gate and is the last thing this stop does, so a stop already
        // inside the gate finishes before it.
        self.mining.close();
        // Before the doors. The seam, once bound, holds the hub, and so does
        // this node's lease until [`sync_owner::Held::stop`]. Either close
        // is a failure unless the stop is already asked.
        self.request_sync_stop();
        // The process doors hold the store (`Door::admission`); leave them
        // up and `chain.db` stays exclusive after this node has stopped.
        uninstall_process_doors();
        // Chain sync after the RPC's last read (the composition root stops
        // the RPC first) and before the service it offers into.
        if let Some(owner) = self
            .sync_owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            owner.stop(SYNC_OWNER_SHUTDOWN);
        }
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
        // The store has closed with the service and the slots: only now
        // wait for the stopped miner's last hashes.
        self.mining.join_drained();
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

/// Every id that leaves the pool releases its relay state in the zone
/// (`DRS_X_STORE_FLIP.md` §2): the zone's per-transaction state stays
/// bounded by the pool. The hook does not read the pool: a concurrent flush
/// can empty it between the release and any later count.
fn pool_departed() -> shekyl_chain_ingest::service::Departed {
    Arc::new(shekyl_ffi::relay_zone_ffi::note_departed)
}

fn rules_of(config: &DaemonConfig) -> Result<ChainRules, OpenError> {
    let fixed = config
        .dev
        .difficulty
        .map(|n| std::num::NonZeroU128::new(u128::from(n)).expect("zero is refused at parse"));
    let schedule = schedule_of(&config.dev)?;
    ChainRules::new(config.network, fixed, schedule)
        .map_err(|error| OpenError::Rules(error.to_string()))
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

/// Drop the process-wide doors that hold the chain store. `install` pairs
/// with this; a stop or a failed open that already installed must call it,
/// or the next open in this process meets `DatabaseAlreadyOpen`.
fn uninstall_process_doors() {
    shekyl_ffi::pool_ffi::uninstall();
    // Chain sync's hub sender is this node's lease, released in
    // [`sync_owner::Held::stop`]. Clearing the process slot here would end
    // an owner another node in this process still holds.
    shekyl_daemon_rpc::submit::clear_production();
}

/// How far [`Node::open`] got when it fails, so the service is stopped
/// once. Genesis connect stops the service itself before it returns.
enum OpenUnwind {
    /// The service already stopped.
    ServiceStopped,
    /// The service is still running.
    StillRunning {
        service: Service<ProductionSubstrate>,
        /// Named when that stop itself fails.
        why: &'static str,
    },
}

/// Uninstall the process doors, stop a service that is still running, and
/// shut the runtime down. The log line keeps the step that failed.
fn abandon_open(runtime: shekyl_runtime::Pool, unwind: OpenUnwind) {
    uninstall_process_doors();
    if let OpenUnwind::StillRunning { service, why } = unwind {
        if let Err(stop) = runtime.block_on(service.stop()) {
            tracing::error!("{why}, and the service stopped on {stop}");
        }
    }
    runtime.shutdown(RUNTIME_SHUTDOWN);
}

fn open_chain(
    path: &std::path::Path,
    horizons: Horizons,
    genesis: &GenesisPin,
) -> Result<ChainStore, OpenError> {
    use shekyl_chain_store::store::{StoreCannot, StoreError};
    match ChainStore::with_genesis(path, ApplyPolicy::Full, horizons, genesis) {
        Ok((store, cut)) => {
            log_chain_cut(cut);
            Ok(store)
        }
        Err(StoreError::Cannot(StoreCannot::SchemaVersionMismatch { found, expected }))
            if found > expected =>
        {
            Err(OpenError::NewerChainLayout { found, expected })
        }
        // TEMPORARY, pre-genesis only (FOLLOWUPS, trigger: before mainnet
        // genesis): an older layout is removed so an alpha starts on a fresh
        // store. The permanent policy ships each layout bump with its
        // migration and never deletes (`DAEMON_REDB_STORE.md` §11.1, S3).
        Err(StoreError::Cannot(StoreCannot::SchemaVersionMismatch { found, expected }))
            if found < expected =>
        {
            tracing::warn!(
                %found,
                %expected,
                "the chain file's layout is older than this release's layout; removing it and opening a fresh store"
            );
            std::fs::remove_file(path).map_err(OpenError::Wipe)?;
            let (store, cut) =
                ChainStore::with_genesis(path, ApplyPolicy::Full, horizons, genesis)?;
            log_chain_cut(cut);
            Ok(store)
        }
        Err(error) => Err(error.into()),
    }
}

/// The chain's half of the pool's creation log: a seal finished in place,
/// or an initialization moved aside.
fn log_chain_cut(cut: Option<CutShort>) {
    match cut {
        Some(CutShort::Unsealed) => tracing::info!(
            "the chain file's creation was cut short (a power loss on an earlier start); \
             it was finished empty"
        ),
        Some(CutShort::Uninitialized { to }) => tracing::warn!(
            moved_to = %to.display(),
            "the chain file was a creation cut short before the engine finished it (a power \
             loss on an earlier start); it was moved aside and a fresh store created"
        ),
        None => {}
    }
}

/// A4: the durability the store opened with, said by the node that opened
/// it. The DRS bench reads this line back (`scripts/bench/drs_artifact.py`
/// `STORE_DURABILITY_RE`): the marker is `Store durability: ` and the first
/// word after it is the policy.
fn store_durability_line() -> String {
    let durability = shekyl_chain_store::store::DURABILITY;
    format!(
        "Store durability: {} (an fsync per commit, DRS-D9; redb Durability::{durability:?})",
        format!("{durability:?}").to_lowercase()
    )
}

/// The store is held to the network's table genesis, every network alike
/// (NI-Q8): the pin `validate` holds block 0 to.
fn genesis_pin_of(rules: ChainRules) -> GenesisPin {
    GenesisPin::for_network(rules.network())
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
        &rules.trust().network_id(),
        &AdmissionPolicy::GENESIS,
    )
    .map_err(|error| OpenError::Pool(format!("{error:?}")))?;
    match opened {
        PoolOpen::Recreated { from } => tracing::warn!(
            %from,
            "the pool file is a layout this release does not speak; it was recreated empty"
        ),
        PoolOpen::Finished => tracing::info!(
            "the pool file's creation was cut short (a power loss on an earlier start); \
             it was finished empty"
        ),
        PoolOpen::SetAside { to } => tracing::warn!(
            moved_to = %to.display(),
            "the pool file was a creation cut short before the engine finished it (a power \
             loss on an earlier start); it was moved aside and a fresh pool created"
        ),
        PoolOpen::Created | PoolOpen::Opened => {}
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

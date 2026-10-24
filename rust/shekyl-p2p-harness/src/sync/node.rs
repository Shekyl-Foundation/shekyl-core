// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One node under test: a real store and ingest service, the daemon's
//! hasher budget and RandomX, the seam hub with the Rust router as its
//! post sink, and the sync owner on its own row.
//!
//! The C++ Levin handler is a stub on its own thread. It receives what the
//! router forwards, finishes each delivery from that thread (never from
//! inside the hub's post), refuses a delivery whose bucket header does not
//! read, as the C++ ingress does, and records the commands it was handed.
//!
//! The node's clock is a hand clock: a deadline fires only when a test
//! moves it ([`Node::advance`]).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use shekyl_chain_ingest::{Metrics, ProductionSubstrate};
use shekyl_chain_sync::SyncState;
use shekyl_chain_sync_runtime::executor::Executor;
use shekyl_chain_sync_runtime::owner::{self, OwnerParts, Running};
use shekyl_chain_sync_runtime::router::Router;
use shekyl_draw_rng::RelayRng;
use shekyl_hash_budget::Budget;
use shekyl_peer_policy::InboundCeiling;
use shekyl_pow_randomx::CacheStore;
use shekyl_seam::{Endpoint, Hub, Post, SocketId, SyncPayload};
use shekyl_timing_engine::{Clock, EngineService, ManualClock, OwnerClass, Tick};
use shekyl_transport_layer::{CloseKind, Direction, Sockets};

use super::chain::Chain;
use super::dial::{Buckets, PeerDial, SyncPeer};

/// What the stub C++ handler was handed.
#[derive(Debug, Default)]
pub struct StubLog {
    /// Every command forwarded to it, by session, in order.
    pub commands: Vec<(SocketId, u32)>,
    /// Deliveries it refused: a bucket header that does not read.
    pub refused: Vec<SocketId>,
    /// Handshake results it was handed.
    pub handshakes: Vec<SocketId>,
    /// Every delivery's bytes, as forwarded.
    pub delivered: Vec<(SocketId, Vec<u8>)>,
    /// Closes, with the cause that won.
    pub closed: Vec<(SocketId, CloseKind)>,
}

impl StubLog {
    /// Whether `id` was closed, and why.
    #[must_use]
    pub fn closed(&self, id: SocketId) -> Option<CloseKind> {
        self.closed
            .iter()
            .find(|(closed, _)| *closed == id)
            .map(|(_, kind)| *kind)
    }
}

/// The node (module docs).
pub struct Node {
    /// The node's store and service.
    pub chain: Chain,
    /// The seam.
    pub hub: Hub,
    /// The dialer whose channels end at scripted peers.
    pub dial: Arc<PeerDial>,
    /// The node's hand clock.
    pub clock: ManualClock,
    /// The substrate's measurements: one sink for ingest and the executor.
    pub metrics: Arc<Metrics>,
    /// What the stub handler recorded.
    pub stub: Arc<Mutex<StubLog>>,
    engine: EngineService<ManualClock>,
    running: Option<Running>,
    stub_thread: Option<JoinHandle<()>>,
    stub_tx: Option<mpsc::Sender<Option<Post>>>,
    next_ip: u8,
}

/// One process-wide cache store: each prepared cache is 256 MiB, and every
/// chain here shares the corpus's seed.
#[must_use]
pub fn caches() -> Arc<CacheStore> {
    static CELL: std::sync::OnceLock<Arc<CacheStore>> = std::sync::OnceLock::new();
    Arc::clone(CELL.get_or_init(|| Arc::new(CacheStore::new())))
}

/// A substrate over the shared caches with its own measurements.
#[must_use]
pub fn substrate() -> (ProductionSubstrate, Arc<Metrics>) {
    let metrics = Arc::new(Metrics::new());
    (
        ProductionSubstrate::new(caches(), Arc::clone(&metrics)),
        metrics,
    )
}

impl Node {
    /// Start a node over a fresh store under `rules`, holding the `before`
    /// steps first, drawing from `rng`. Call from inside a multi-thread
    /// runtime.
    ///
    /// # Panics
    ///
    /// A part does not start.
    pub async fn start<R>(
        tag: &str,
        rules: shekyl_chain_ingest::ChainRules,
        before: &[super::chain::Step],
        permits: usize,
        rng: R,
    ) -> Self
    where
        R: RelayRng + Send + 'static,
    {
        let (substrate, metrics) = substrate();
        let budget = Budget::new(NonZeroUsize::new(permits).expect("non-zero"));
        let chain = Chain::empty(tag, rules, Arc::new(substrate.clone()), budget.clone());
        chain.apply(before).await;

        let stub = Arc::new(Mutex::new(StubLog::default()));
        let (stub_tx, stub_rx) = mpsc::channel::<Option<Post>>();
        let forward_tx = Mutex::new(stub_tx.clone());
        let forward: shekyl_chain_sync_runtime::router::Forward = Arc::new(move |post| {
            let _gone = forward_tx.lock().expect("stub sender").send(Some(post));
        });
        let (routed_tx, routed_rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = Router::attached(forward, routed_tx).into_sink();
        let clock = ManualClock::new(Tick::new(1));
        let sockets = Sockets::new();
        let hub = Hub::new(
            sockets.clone(),
            InboundCeiling::Bounded(64),
            sink,
            Arc::new(clock.clone()),
        );
        let dial = Arc::new(PeerDial::new(sockets, 64 * 1024 * 1024));
        hub.install_dial(Arc::clone(&dial) as Arc<dyn shekyl_seam::Dial>);
        let stub_thread = {
            let hub = hub.clone();
            let stub = Arc::clone(&stub);
            std::thread::spawn(move || run_stub(&hub, &stub_rx, &stub))
        };

        let engine = EngineService::start(clock.clone());
        let timer = engine
            .handle()
            .register(OwnerClass::Sync)
            .expect("registered");
        let executor = Arc::new(Executor::new(budget, substrate));
        let parts = OwnerParts {
            store: Arc::clone(&chain.store),
            door: chain.service.door(),
            alarm: chain.service.alarm(),
            tips: chain.service.watch_tip().await.expect("the tip watch"),
            latch: chain.service.watch_latch().await.expect("the latch watch"),
            hub: Arc::new(hub.clone()),
            executor,
            timer,
            rules,
            rng,
            pool_hashes: Arc::new(Vec::new),
            routed: routed_rx,
        };
        // The owner's log lines carry the node's tag.
        let span = tracing::info_span!("node", tag);
        let running = span
            .in_scope(|| owner::spawn(parts))
            .expect("the owner row");
        Self {
            chain,
            hub,
            dial,
            clock,
            metrics,
            stub,
            engine,
            running: Some(running),
            stub_thread: Some(stub_thread),
            stub_tx: Some(stub_tx),
            next_ip: 1,
        }
    }

    /// Dial a scripted peer. `claim` is the outbound handshake's sync
    /// payload; `None` posts none.
    ///
    /// # Panics
    ///
    /// The channel was not admitted.
    pub fn connect(&mut self, peer: Box<dyn SyncPeer>, claim: Option<SyncPayload>) -> SocketId {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, self.next_ip));
        self.next_ip += 1;
        self.dial.expect(ip, peer);
        let endpoint = Endpoint::Clearnet {
            ip,
            port: 18080,
            direction: Direction::Outbound,
        };
        let attached = self.hub.connect(&endpoint).expect("admitted");
        if let Some(sync) = claim {
            self.hub
                .post_handshake_result(attached.id, endpoint.connector(), sync);
        }
        self.hub.drive(attached.id, attached.session);
        attached.id
    }

    /// The published sync state.
    ///
    /// # Panics
    ///
    /// The node was stopped.
    #[must_use]
    pub fn state(&self) -> SyncState {
        *self.running.as_ref().expect("running").state().borrow()
    }

    /// Whether the model reads the latch as set.
    ///
    /// # Panics
    ///
    /// The node was stopped.
    #[must_use]
    pub fn alarm(&self) -> bool {
        *self.running.as_ref().expect("running").alarm().borrow()
    }

    /// Wait until `done` holds, at most `limit`. `true` when it held.
    pub async fn wait(&self, limit: Duration, mut done: impl FnMut(&Self) -> bool) -> bool {
        let started = Instant::now();
        while !done(self) {
            if started.elapsed() > limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }

    /// The node's tip as a block count.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.chain.tip().map_or(0, |(count, _, _)| count)
    }

    /// Whether `id` was closed, and why: the stub's record, which
    /// outlives the hub's row.
    #[must_use]
    pub fn closed(&self, id: SocketId) -> Option<CloseKind> {
        self.stub.lock().expect("stub log").closed(id)
    }

    /// Move the hand clock by `by`, and have the engine read it.
    ///
    /// # Panics
    ///
    /// The engine is gone.
    pub fn advance(&self, by: Duration) {
        let now = self.clock.now();
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.clock.set(Tick::new(now.get().saturating_add(nanos)));
        // The engine blocks on a hand clock until a command arrives: an
        // owner of the test's arms past now, which wakes it to poll.
        let nudge = self
            .engine
            .handle()
            .register(OwnerClass::Sync)
            .expect("registered");
        nudge.arm(Tick::new(u64::MAX)).expect("armed");
        let _gone = nudge.deregister();
    }

    /// Push `frame` into `id`'s channel as its peer, from a blocking
    /// thread: the channel's send blocks.
    ///
    /// # Panics
    ///
    /// The blocking task panicked.
    pub async fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let hub = self.hub.clone();
        tokio::task::spawn_blocking(move || hub.inject(id, frame))
            .await
            .expect("the inject returns")
    }

    /// The RandomX hashes the node's substrate has run.
    #[must_use]
    pub fn hashes(&self) -> u64 {
        self.metrics.snapshot().hashes
    }

    /// Stop the owner, the hub, the stub and the service, and remove the
    /// store.
    pub async fn stop(mut self) {
        if let Some(running) = self.running.take() {
            tokio::task::spawn_blocking(move || running.stop(Duration::from_secs(10)))
                .await
                .expect("the owner stops");
        }
        let hub = self.hub.clone();
        tokio::task::spawn_blocking(move || hub.shutdown())
            .await
            .expect("the hub stops");
        if let Some(tx) = self.stub_tx.take() {
            let _gone = tx.send(None);
        }
        if let Some(thread) = self.stub_thread.take() {
            let _joined = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        self.engine.close();
        let Self { chain, .. } = self;
        chain.stop().await;
    }
}

fn run_stub(hub: &Hub, posts: &mpsc::Receiver<Option<Post>>, log: &Mutex<StubLog>) {
    let mut sessions: HashMap<SocketId, Buckets> = HashMap::new();
    while let Ok(Some(post)) = posts.recv() {
        match post {
            Post::Established { id, .. } => {
                sessions.insert(id, Buckets::default());
                hub.handler_armed(id, true);
            }
            Post::Deliver { id, bytes, .. } => {
                let buckets = sessions.entry(id).or_default();
                let commands = buckets.feed(&bytes);
                let broken = buckets.broken();
                let mut log = log.lock().expect("stub log");
                log.delivered.push((id, bytes.clone()));
                log.commands
                    .extend(commands.into_iter().map(|(command, _)| (id, command)));
                if broken {
                    log.refused.push(id);
                }
                drop(log);
                hub.delivery_finished(id, !broken);
            }
            Post::HandshakeResult { id, .. } => {
                log.lock().expect("stub log").handshakes.push(id);
            }
            Post::Closed { id, cause, .. } => {
                log.lock()
                    .expect("stub log")
                    .closed
                    .push((id, cause.kind()));
                sessions.remove(&id);
                hub.handler_gone(id);
                hub.reap(id);
            }
        }
    }
}

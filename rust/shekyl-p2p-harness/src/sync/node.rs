// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One node under test: a real store and ingest service, the daemon's
//! hasher budget and RandomX, the session layer over loopback channels,
//! and the sync owner on the layer's dispatch table through its port.
//!
//! The peers and relay owners are a recorder: nothing in these tests
//! reaches them but a session's establishment and its close, which the
//! recorder keeps so a test can ask how a session ended after its row has
//! left the board.
//!
//! The node's clock is a hand clock: a deadline fires only when a test
//! moves it ([`Node::advance`]).
//!
//! A node started with [`Node::start_mining`] also seats the tip
//! follower's job, reading the state the owner publishes, as the daemon's
//! node does (`shekyl-node`): the follower posts a template only while
//! that state is `Synced`.

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_block_template::MinerKeys;
use shekyl_bundle_producer::WitnessRing;
use shekyl_chain_ingest::follower::{JobSeat, MinerFeed, NoJob, Posting};
use shekyl_chain_ingest::service::Follow;
use shekyl_chain_ingest::{Metrics, ProductionSubstrate};
use shekyl_chain_sync::SyncState;
use shekyl_chain_sync_runtime::executor::Executor;
use shekyl_chain_sync_runtime::owner::{self, OwnerParts, Running};
use shekyl_chain_sync_runtime::port;
use shekyl_draw_rng::RelayRng;
use shekyl_hash_budget::Budget;
use shekyl_levin::{GetTxpoolComplement, NewTransactions, PeerlistEntry};
use shekyl_miner::{FoundBlocks, JobBoard};
use shekyl_p2p_session::{
    CoreSyncData, DialAim, DialOutcome, Endpoint, Established, Intervals, Owners, Parts, PeerOwner,
    PerConnector, ProbeArrival, ProbeSink, RelayOwner, SessionConfig, SessionFacts, SessionLayer,
    SocketId, Taken,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_pow_randomx::CacheStore;
use shekyl_timing_engine::{Clock, EngineService, ManualClock, OwnerClass, Tick};
use shekyl_transport_layer::{CloseKind, ConnectorId, DialEnd, Direction, Sockets};

use super::chain::Chain;
use super::dial::{empty_claim, PeerDial, SyncPeer};

/// The network every harness node and peer names in its handshake.
pub const NETWORK_ID: [u8; 16] = [0x5a; 16];

/// Each channel's outbound byte cap.
const SEND_CAP: usize = 64 * 1024 * 1024;

/// What the owners that are not under test were told (module docs).
#[derive(Debug, Default, Clone)]
pub struct Record {
    /// Sessions established, in order.
    pub established: Vec<SocketId>,
    /// Sessions a 2002 arrived on, one entry per batch, in order.
    pub transactions: Vec<SocketId>,
    /// Closes, with the cause that won.
    pub closed: Vec<(SocketId, CloseKind)>,
}

impl Record {
    /// Whether `id` was closed, and why.
    #[must_use]
    pub fn closed(&self, id: SocketId) -> Option<CloseKind> {
        self.closed
            .iter()
            .find(|(closed, _)| *closed == id)
            .map(|(_, kind)| *kind)
    }
}

/// The peers and relay owners, and the probe sink: a recorder.
#[derive(Default)]
struct Recorder {
    record: Mutex<Record>,
}

impl Recorder {
    fn record(&self) -> std::sync::MutexGuard<'_, Record> {
        self.record.lock().expect("the record")
    }
}

impl PeerOwner for Recorder {
    fn disclosure(&self, _connector: ConnectorId) -> Vec<PeerlistEntry> {
        Vec::new()
    }
    fn list_received(&self, _session: &Established, _list: Vec<PeerlistEntry>) {}
    fn on_established(&self, session: &Established) {
        self.record().established.push(session.id());
    }
    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        self.record().closed.push((facts.id, end.cause().kind()));
    }
}

impl RelayOwner for Recorder {
    fn new_transactions(&self, session: &Established, _batch: NewTransactions, taken: Taken) {
        self.record().transactions.push(session.id());
        drop(taken);
    }
    fn txpool_complement(
        &self,
        _session: &Established,
        _request: GetTxpoolComplement,
        taken: Taken,
    ) {
        drop(taken);
    }
}

impl ProbeSink for Recorder {
    fn probe_arrived(&self, _arrival: ProbeArrival) {}
}

/// The tip follower's job seat on a node that mines (module docs).
pub struct MinerSeat {
    /// The board the follower posts the node's template on.
    pub board: Arc<JobBoard>,
    /// What the follower says the board holds.
    pub posting: tokio::sync::watch::Receiver<Posting>,
    /// The miner's sender, held so the found-block sink stays open.
    _found: FoundBlocks,
}

/// The node (module docs).
pub struct Node {
    /// The node's store and service.
    pub chain: Chain,
    /// The session layer.
    pub layer: SessionLayer<ManualClock>,
    /// The connectors whose channels end at scripted peers.
    pub dial: Arc<PeerDial>,
    /// The node's hand clock.
    pub clock: ManualClock,
    /// The published sync state: the handle a node's consumers read.
    pub state: tokio::sync::watch::Sender<SyncState>,
    /// The substrate's measurements: one sink for ingest and the executor.
    pub metrics: Arc<Metrics>,
    /// The follower's job seat, on a node started to mine.
    pub miner: Option<MinerSeat>,
    recorder: Arc<Recorder>,
    engine: EngineService<ManualClock>,
    running: Option<Running>,
    /// What this node claims to its peers, as the layer sends it; the
    /// layer holds the receiver.
    tip: tokio::sync::watch::Sender<CoreSyncData>,
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
    /// steps first. `rng` is the sync owner's draw; `session_rng` is the
    /// session layer's, for its nonces and timed-sync jitter. They are two
    /// sequences: the layer's is not the owner's. Call from inside a
    /// multi-thread runtime.
    ///
    /// # Panics
    ///
    /// A part does not start.
    pub async fn start<R, S>(
        tag: &str,
        rules: shekyl_chain_ingest::ChainRules,
        before: &[super::chain::Step],
        permits: usize,
        rng: R,
        session_rng: S,
    ) -> Self
    where
        R: RelayRng + Send + 'static,
        S: RelayRng + Send + 'static,
    {
        Self::start_seated(tag, rules, before, permits, rng, session_rng, None).await
    }

    /// [`Node::start`], with the tip follower's job seated: templates pay
    /// `keys`, and the follower reads the state the owner publishes.
    ///
    /// # Panics
    ///
    /// A part does not start.
    pub async fn start_mining<R, S>(
        tag: &str,
        rules: shekyl_chain_ingest::ChainRules,
        before: &[super::chain::Step],
        permits: usize,
        rng: R,
        session_rng: S,
        keys: MinerKeys,
    ) -> Self
    where
        R: RelayRng + Send + 'static,
        S: RelayRng + Send + 'static,
    {
        Self::start_seated(tag, rules, before, permits, rng, session_rng, Some(keys)).await
    }

    async fn start_seated<R, S>(
        tag: &str,
        rules: shekyl_chain_ingest::ChainRules,
        before: &[super::chain::Step],
        permits: usize,
        rng: R,
        session_rng: S,
        keys: Option<MinerKeys>,
    ) -> Self
    where
        R: RelayRng + Send + 'static,
        S: RelayRng + Send + 'static,
    {
        let (substrate, metrics) = substrate();
        let budget = Budget::new(NonZeroUsize::new(permits).expect("non-zero"));
        // The published state, as the node's handle holds it.
        let state = tokio::sync::watch::Sender::new(SyncState::NoView);
        let (mut follow, miner) = match keys {
            None => (Follow::default(), None),
            Some(keys) => {
                let board = Arc::new(JobBoard::new());
                let (found, inbox) = shekyl_miner::found_blocks();
                let (posting_tx, posting) =
                    tokio::sync::watch::channel(Posting::Withdrawn(NoJob::Starting));
                let seat = JobSeat {
                    board: Arc::clone(&board),
                    keys: Some(keys),
                    miner: MinerFeed {
                        found: inbox,
                        sync: state.subscribe(),
                    },
                    posting: posting_tx,
                    witness: Arc::new(WitnessRing::new(rules.trust().network_id())),
                };
                let follow = Follow {
                    job: Some(seat),
                    ..Follow::default()
                };
                (
                    follow,
                    Some(MinerSeat {
                        board,
                        posting,
                        _found: found,
                    }),
                )
            }
        };
        // The substrate's sink, which the executor shares, as the daemon's
        // node wires it: the per-block profile's phases in one place.
        follow.metrics = Some(Arc::clone(&metrics));
        let chain = Chain::empty_following(
            tag,
            rules,
            Arc::new(substrate.clone()),
            budget.clone(),
            follow,
        );
        chain.apply(before).await;

        let clock = ManualClock::new(Tick::new(1));
        let engine = EngineService::start(clock.clone());
        let timing = engine.handle();
        let timer = timing.register(OwnerClass::Sync).expect("registered");
        let executor = Arc::new(Executor::new(budget, substrate));
        // No accept-rate gate: the harness admits at a fixed tick.
        let sockets = Sockets::with_clearnet_gate(None);
        let dial = Arc::new(PeerDial::new(
            sockets.clone(),
            NETWORK_ID,
            InboundCeiling::Bounded(64),
            SEND_CAP,
        ));
        let recorder = Arc::new(Recorder::default());
        let (sync_port, inbound) = port::port();
        // The handshake's tip, as the daemon's node publishes it: the
        // chain's tip, re-read on every change.
        let mut tips = chain.service.watch_tip().await.expect("the tip watch");
        let (tip_tx, tip_rx) =
            tokio::sync::watch::channel(core_sync_data(tips.borrow_and_update().tip));
        {
            let tip_tx = tip_tx.clone();
            tokio::spawn(async move {
                while tips.changed().await.is_ok() {
                    let tip = tips.borrow_and_update().tip;
                    tip_tx.send_replace(core_sync_data(tip));
                }
            });
        }
        let layer = SessionLayer::new(Parts {
            sockets,
            config: SessionConfig {
                network_id: NETWORK_ID,
                handshake_within: PerConnector::both(Duration::from_secs(24 * 3600)),
                // A hand clock: the timed sync never falls due on its own.
                intervals: Intervals {
                    invoke_timeout: Duration::from_secs(365 * 24 * 3600),
                    timed_sync_min: Duration::from_secs(365 * 24 * 3600),
                    timed_sync_jitter: Duration::from_secs(1),
                },
            },
            owners: Owners {
                peers: Arc::clone(&recorder) as Arc<dyn PeerOwner>,
                sync: Arc::new(sync_port),
                relay: Arc::clone(&recorder) as Arc<dyn RelayOwner>,
                probes: Some(Arc::clone(&recorder) as Arc<dyn ProbeSink>),
                sessions: None,
            },
            connectors: Arc::clone(&dial) as Arc<dyn shekyl_p2p_session::Dial>,
            timing: timing.clone(),
            tip: tip_rx,
            runtime: tokio::runtime::Handle::current(),
            rng: Box::new(session_rng),
        });
        let parts = OwnerParts {
            store: Arc::clone(&chain.store),
            door: chain.service.door(),
            alarm: chain.service.alarm(),
            tips: chain.service.watch_tip().await.expect("the tip watch"),
            latch: chain.service.watch_latch().await.expect("the latch watch"),
            executor,
            timer,
            rules,
            requesting: shekyl_chain_sync::Requesting::On,
            // A harness node is on an open network: no peer list is closed,
            // so it has no view until its opening resolves.
            declaration: shekyl_chain_sync::Declaration::Open,
            rng,
            pool_hashes: Arc::new(Vec::new),
            inbound,
            state: state.clone(),
        };
        // The owner's log lines carry the node's tag.
        let span = tracing::info_span!("node", tag);
        let running = span
            .in_scope(|| owner::spawn(parts))
            .expect("the owner row");
        Self {
            chain,
            layer,
            dial,
            clock,
            state,
            metrics,
            miner,
            recorder,
            engine,
            running: Some(running),
            tip: tip_tx,
            next_ip: 1,
        }
    }

    /// Dial a scripted peer and keep the session. `claim` is what the
    /// peer answers the handshake with; `None` claims this node's own tip,
    /// a peer level with us and so no source. Returns once the owners
    /// hold the session.
    ///
    /// # Panics
    ///
    /// The dial or the handshake failed.
    pub async fn connect(
        &mut self,
        peer: Box<dyn SyncPeer>,
        claim: Option<CoreSyncData>,
    ) -> SocketId {
        let (ip, endpoint) = self.next_endpoint(Direction::Outbound);
        self.dial
            .expect(ip, peer, claim.unwrap_or_else(|| self.level()));
        let dialed = self.layer.connect(endpoint).await.expect("admitted");
        let id = dialed.id();
        let outcome = dialed
            .handshake(DialAim::Keep)
            .await
            .expect("the handshake passes");
        assert!(matches!(outcome, DialOutcome::Kept { .. }));
        id
    }

    /// A scripted peer that dialed this node, its handshake request
    /// claiming `claim` (`None` claims this node's own tip, a peer level
    /// with us and so no source). Returns once the session is established.
    ///
    /// # Panics
    ///
    /// The channel was not admitted, or the handshake did not complete.
    pub async fn accept(
        &mut self,
        peer: Box<dyn SyncPeer>,
        claim: Option<CoreSyncData>,
    ) -> SocketId {
        let (_, endpoint) = self.next_endpoint(Direction::Inbound);
        // The far side's first frame is injected with a blocking send, so
        // the channel is opened off the runtime's worker threads.
        let dial = Arc::clone(&self.dial);
        let claim = claim.unwrap_or_else(|| self.level());
        let channel = tokio::task::spawn_blocking(move || dial.accept(endpoint, peer, claim))
            .await
            .expect("the accept thread ends")
            .expect("admitted");
        let id = channel.open.id();
        self.layer.adopt(channel);
        assert!(
            self.wait(Duration::from_secs(10), |node| node
                .layer
                .board()
                .get(id)
                .is_some_and(|row| row.established()))
                .await,
            "the inbound handshake did not complete"
        );
        id
    }

    /// The claim of a peer level with this node: its own tip, or genesis
    /// alone before the chain reports one. A claim of no chain at all is
    /// refused by the sync owner (`PayloadRefused::Height`), so a scripted
    /// peer that is to be no source claims this instead.
    fn level(&self) -> CoreSyncData {
        self.tip.borrow().clone()
    }

    fn next_endpoint(&mut self, direction: Direction) -> (IpAddr, Endpoint) {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, self.next_ip));
        self.next_ip += 1;
        (
            ip,
            Endpoint::Clearnet {
                ip,
                port: 18080,
                direction,
            },
        )
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

    /// The model's view (CS-5 §7), as the owner last published it.
    ///
    /// # Panics
    ///
    /// The node was stopped.
    #[must_use]
    pub fn view(&self) -> shekyl_chain_sync::SyncView<SocketId> {
        self.running
            .as_ref()
            .expect("running")
            .view()
            .borrow()
            .clone()
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

    /// Whether `id` was closed, and why: the recorder's, which outlives
    /// the board's row.
    #[must_use]
    pub fn closed(&self, id: SocketId) -> Option<CloseKind> {
        self.recorder.record().closed(id)
    }

    /// What the peers and relay owners were told, so far.
    #[must_use]
    pub fn record(&self) -> Record {
        self.recorder.record().clone()
    }

    /// Close `id` as this node's own close.
    pub fn close(&self, id: SocketId) {
        self.layer.close(id, DialEnd::local_close());
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

    /// How the node's owner ended, once it has: `None` while it runs.
    ///
    /// # Panics
    ///
    /// The node was stopped.
    #[must_use]
    pub fn ended(&self) -> tokio::sync::watch::Receiver<Option<owner::Ended>> {
        self.running.as_ref().expect("a running node").ended()
    }

    /// Close the node's timing engine under its running owner, as if the
    /// process's engine had gone: the owner ends on its own.
    pub fn close_engine(&self) {
        self.engine.close();
    }

    /// Push `frame` into `id`'s channel as its peer, from a blocking
    /// thread: the channel's send blocks.
    ///
    /// # Panics
    ///
    /// The blocking task panicked.
    pub async fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let dial = Arc::clone(&self.dial);
        tokio::task::spawn_blocking(move || dial.inject(id, frame))
            .await
            .expect("the inject returns")
    }

    /// The RandomX hashes the node's substrate has run.
    #[must_use]
    pub fn hashes(&self) -> u64 {
        self.metrics.snapshot().hashes
    }

    /// Stop the owner, the layer and the service, and remove the store.
    pub async fn stop(mut self) {
        if let Some(running) = self.running.take() {
            tokio::task::spawn_blocking(move || running.stop(Duration::from_secs(10)))
                .await
                .expect("the owner stops");
        }
        self.layer.shutdown();
        self.engine.close();
        let Self { chain, .. } = self;
        chain.stop().await;
    }
}

/// The chain tip as the handshake and timed sync carry it; no tip is the
/// empty claim.
fn core_sync_data(tip: Option<shekyl_chain_ingest::ChainTip>) -> CoreSyncData {
    tip.map_or_else(empty_claim, |tip| {
        let wide = tip.cumulative_difficulty.to_raw();
        CoreSyncData {
            current_height: tip.count.to_raw(),
            cumulative_difficulty: u64::try_from(wide & u128::from(u64::MAX))
                .expect("masked to the low 64 bits"),
            cumulative_difficulty_top64: u64::try_from(wide >> 64)
                .expect("a u128 shifted by 64 fits"),
            top_id: tip.top_id.to_bytes(),
        }
    })
}

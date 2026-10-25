// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sync owner (CS-3 §4.3): one task on its own runtime row, named
//! `chain-sync`, holding the one [`Model`]. Nothing else holds it.
//!
//! The owner turns what the router, the executor, the entry's tickets, the
//! tip watch, the latch and the timing engine report into [`Event`]s,
//! hands each to the model with a fresh store snapshot as `main`, and runs
//! the commands that come out, in order.
//!
//! - **Sessions** are `Session`s. [`shekyl_seam::SocketId`] does not order itself, and
//!   the model's maps need an order. `Session` orders by the admission
//!   number, and that order carries no meaning: draws are uniform over the
//!   set. The entry's [`SessionId`] is that number, and only at the door.
//! - **`now`** is the timing engine's clock as an [`Instant`]. Deadlines
//!   go to the engine as ticks on that same clock, and come back as
//!   [`Event::Deadline`]. The engine holds one deadline per owner, so the
//!   owner arms the earliest of its own and keeps the rest.
//! - **The wall** is the substrate's clock, read once per event.
//! - **Serving** a request reads the store on a blocking thread, one
//!   request at a time per session, in arrival order. A delivered chunk
//!   that carried only chain-sync messages is finished after the requests
//!   it carried are answered, so a peer's requests wait in the transport
//!   and not in this task. A chunk that also carried bytes for the C++
//!   handler is finished by that handler, so the queue is bounded here as
//!   well: a session holds at most one waiting request of each kind, and a
//!   later one replaces it. A requester asks again only after it gave the
//!   first up, so the later request is the one it reads. The queue bounds
//!   what waits. It does not schedule this task.
//! - **Turns.** Stop comes first. Then a proof, an entry reply, or a
//!   served response, then the tip and the latch, then one peer message.
//!   Peer bytes do not sit ahead of work this node has already finished.
//!   A deadline does not pass peer messages already queued, because one
//!   of them may be the response it would abandon (`on_headers` closes a
//!   session whose request the deadline already cleared). When the clock
//!   fires, those messages are taken and then the deadline runs.
//! - **Announcements** (2008, `NOTIFY_NEW_COMPACT_BLOCK`) come from the
//!   attached router and are the model's [`Event::Announce`].
//!   `RequestMissingTxs` is encoded and sent; a peer's own 2009 stays the
//!   C++ handler's until the cutover.
//! - **Relay** is the model's decision ([`Command::Relay`]): a block that
//!   connected as the new tip while this node, with it, is not `Behind`,
//!   however it arrived. [`crate::relay`] builds that compact announcement
//!   (the block and its witness, no transactions) and sends it as 2008 to
//!   every established session but the one that supplied it. That send
//!   moves behind RD's relay entry when it lands.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_chain_ingest::service::{
    Alarm, ArrivalTag, BoundArrival as EntryArrival, Door, Refusal, Reply, SessionId,
};
use shekyl_chain_ingest::{ChainRules, TipChanged};
use shekyl_chain_rules::Tip;
use shekyl_chain_store::codec::FollowingDegraded;
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::{
    notify, CoreSyncData, GetTxpoolComplement, HandshakeRequest, NewCompactBlock, PortableMap,
    RequestBodies, RequestCompactMissingTx, RequestHeaders, SyncCommand, TimedSyncRequest,
    TimedSyncResponse, HASH_SIZE, NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_REQUEST_COMPACT_MISSING_TX,
};
use shekyl_peer_policy::{Invalidate, SyncReply, SyncReplyAction};
use shekyl_runtime::{Pool, RuntimeBudget, ThreadName};
use shekyl_seam::{Hub, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle, Tick};
use shekyl_transport_layer::{declaration, Assessment};
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{BlockBody, TxBody};
use tokio::sync::{mpsc, watch};
use tracing::Instrument;

use crate::executor::Executor;
use crate::relay;
use crate::router::{Routed, Tapped};
use crate::serve::{serve_bodies, serve_headers};
use crate::session::Session;
use shekyl_chain_sync::{
    BoundArrival, ClaimError, Command, Event, Job, Outcome, PeerClaim, Proved, Sync as Model,
    SyncState,
};

/// The owner row's name in the thread ledger.
pub const ROW_NAME: &str = "chain-sync";

/// What the owner is built from.
pub struct OwnerParts<C: Clock + Clone, R> {
    /// The store `main` is read from, and served from.
    pub store: Arc<ChainStore>,
    /// The ingest entry.
    pub door: Door,
    /// The connector's latch writer.
    pub alarm: Alarm,
    /// `TipChanged`.
    pub tips: watch::Receiver<TipChanged>,
    /// The `following_degraded` latch.
    pub latch: watch::Receiver<Option<FollowingDegraded>>,
    /// The seam, for sends, closes and finished deliveries.
    pub hub: Arc<Hub>,
    /// The prove jobs' runner.
    pub executor: Arc<Executor>,
    /// The owner's registration on the timing engine, class `Sync`.
    pub timer: OwnerHandle<C>,
    /// The rule schedule.
    pub rules: ChainRules,
    /// The daemon's draw source.
    pub rng: R,
    /// The pool's transaction hashes, for the complement request.
    pub pool_hashes: Arc<dyn Fn() -> Vec<[u8; HASH_SIZE]> + Send + Sync>,
    /// The router's output.
    pub routed: mpsc::UnboundedReceiver<Routed>,
    /// Where the derived sync state is published (CS-Q2 step 8): the
    /// node's one sync sender (`shekyl_node::Node::sync()`, cloned), which
    /// the RPC's facts, the miner's follower and the relay gate read. The
    /// owner is its publisher and holds no other.
    pub state: watch::Sender<SyncState>,
}

/// The running owner.
#[must_use = "stop the owner from outside its pool"]
pub struct Running {
    pool: Pool,
    executor: Arc<Executor>,
    stop_tx: watch::Sender<bool>,
    state: watch::Receiver<SyncState>,
    alarm: watch::Receiver<bool>,
}

impl Running {
    /// The published sync state (CS-Q2 step 8's consumers read this).
    #[must_use]
    pub fn state(&self) -> watch::Receiver<SyncState> {
        self.state.clone()
    }

    /// Whether the model reads the latch as set.
    #[must_use]
    pub fn alarm(&self) -> watch::Receiver<bool> {
        self.alarm.clone()
    }

    /// Stop the owner and wait at most `timeout` for its blocking work.
    /// Call it from outside the owner's pool.
    pub fn stop(self, timeout: Duration) {
        self.executor.stop();
        self.stop_tx.send_replace(true);
        self.pool.shutdown(timeout);
    }
}

/// Start the owner on its own row, in the caller's tracing span.
///
/// [`Running::stop`] stops the executor too, so a permit wait ends with
/// the owner. The row's blocking-thread cap is derived: the hasher budget's
/// permits, the most proof items that can hash at once. Serving and the
/// cache derivations queue on the same threads. The workers are one: the
/// owner is one task.
///
/// # Errors
///
/// The runtime could not be built.
pub fn spawn<C, R>(parts: OwnerParts<C, R>) -> std::io::Result<Running>
where
    C: Clock + Clone + Send + Sync + 'static,
    R: RelayRng + Send + 'static,
{
    let blocking = std::num::NonZeroUsize::new(parts.executor.permits())
        .unwrap_or(std::num::NonZeroUsize::MIN);
    let name = ThreadName::new(ROW_NAME).expect("a fixed name");
    let pool = shekyl_runtime::runtime(
        RuntimeBudget {
            workers: std::num::NonZeroUsize::MIN,
            blocking,
        },
        &name,
    )?;
    let state = parts.state.subscribe();
    let (alarm_tx, alarm) = watch::channel(false);
    let (stop_tx, stop_rx) = watch::channel(false);
    let executor = Arc::clone(&parts.executor);
    // The owner's log lines carry the span it was started in.
    pool.spawn(run(parts, alarm_tx, stop_rx).instrument(tracing::Span::current()));
    Ok(Running {
        pool,
        executor,
        stop_tx,
        state,
        alarm,
    })
}

/// What the owner's own spawned work reports back.
enum Input {
    Proven {
        job: Job,
        results: Vec<Proved>,
    },
    Entry {
        tag: u64,
        reply: Reply,
    },
    Served {
        session: Session,
        bytes: Option<Vec<u8>>,
    },
}

/// An offer waiting on the entry.
struct Offered {
    /// The session that served the body.
    session: Session,
    /// A body this node requested. An announcement is not. An oversize
    /// solicited body invalidates its header; an oversize announcement
    /// does not. Relay does not read this: the model decides that.
    solicited: bool,
    /// The block the offer names. A switch is a connect when this is the
    /// chain's new tip, and [`Outcome::Noted`] otherwise.
    hash: BlockHash,
}

/// A request a session sent this node.
enum ServeRequest {
    Headers(RequestHeaders),
    Bodies(RequestBodies),
}

/// One session's serving queue: the request being served, and at most
/// one waiting request of each kind.
#[derive(Default)]
struct Serving {
    queue: VecDeque<ServeRequest>,
    busy: bool,
    /// Chunks the router handed back, finished when the queue drains.
    finishes: u32,
}

impl Serving {
    /// Queue `request`. A waiting request of the same kind is replaced in
    /// its place, however the peer packed its chunks (module docs).
    /// `true` when one was replaced.
    fn push(&mut self, request: ServeRequest) -> bool {
        let kind = std::mem::discriminant(&request);
        match self
            .queue
            .iter_mut()
            .find(|waiting| std::mem::discriminant(*waiting) == kind)
        {
            Some(waiting) => {
                *waiting = request;
                true
            }
            None => {
                self.queue.push_back(request);
                false
            }
        }
    }
}

/// What the owner keeps beside the model.
struct Owner<C: Clock + Clone, R> {
    sync: Model<Session, Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet + Send>>,
    store: Arc<ChainStore>,
    door: Door,
    alarm: Alarm,
    hub: Arc<Hub>,
    executor: Arc<Executor>,
    timer: Arc<OwnerHandle<C>>,
    rng: R,
    pool_hashes: Arc<dyn Fn() -> Vec<[u8; HASH_SIZE]> + Send + Sync>,
    inputs: mpsc::UnboundedSender<Input>,
    /// Engine ticks to the (session, request) pairs due then.
    deadlines: BTreeMap<Tick, Vec<(Session, u64)>>,
    armed: Option<Tick>,
    /// The engine clock's origin, read once at start.
    base: (Instant, Tick),
    /// Offered arrivals, by tag.
    offered: HashMap<u64, Offered>,
    serving: HashMap<Session, Serving>,
    seats: Option<usize>,
    state_tx: watch::Sender<SyncState>,
    alarm_tx: watch::Sender<bool>,
}

async fn run<C, R>(
    parts: OwnerParts<C, R>,
    alarm_tx: watch::Sender<bool>,
    mut stop: watch::Receiver<bool>,
) where
    C: Clock + Clone + Send + Sync + 'static,
    R: RelayRng + Send + 'static,
{
    let OwnerParts {
        store,
        door,
        alarm,
        mut tips,
        mut latch,
        hub,
        executor,
        timer,
        rules,
        rng,
        pool_hashes,
        mut routed,
        state: state_tx,
    } = parts;
    let (inputs, mut input_rx) = mpsc::unbounded_channel();
    let schedule: Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet + Send> =
        Box::new(move |height| rules.in_force(height));
    let base = (Instant::now(), timer.clock().now());
    let timer = Arc::new(timer);
    let wakes = Arc::clone(&timer);
    let mut owner = Owner {
        sync: Model::new(rules.trust(), schedule),
        store,
        door,
        alarm,
        hub,
        executor,
        timer,
        rng,
        pool_hashes,
        inputs,
        deadlines: BTreeMap::new(),
        armed: None,
        base,
        offered: HashMap::new(),
        serving: HashMap::new(),
        seats: None,
        state_tx,
        alarm_tx,
    };
    // The fill does not exist yet: the frontier is genesis (§4.7).
    owner.event(Event::Fill {
        frontier: BlockHeight::ZERO,
    });
    owner.latch(latch.borrow_and_update().is_some());
    let first = *tips.borrow_and_update();
    owner.tip(&first);
    owner.room();
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|stop| *stop) => break,
            input = input_rx.recv() => {
                if let Some(input) = input {
                    owner.input(input);
                }
            },
            changed = tips.changed() => {
                if changed.is_err() {
                    break;
                }
                let tip = *tips.borrow_and_update();
                owner.tip(&tip);
            },
            changed = latch.changed() => {
                if changed.is_err() {
                    break;
                }
                let set = latch.borrow_and_update().is_some();
                owner.latch(set);
            },
            routed_one = routed.recv() => {
                let Some(routed_one) = routed_one else {
                    break;
                };
                owner.routed(routed_one);
                // Messages already queued were sent before this wake was
                // observed. Take them before the deadline, so a response
                // in hand is applied before its request is cleared.
                match clock_ready(&wakes) {
                    Some(false) => {}
                    Some(true) => {
                        let pending = routed.len();
                        let mut closed = false;
                        for _ in 0..pending {
                            match routed.try_recv() {
                                Ok(routed_one) => owner.routed(routed_one),
                                Err(mpsc::error::TryRecvError::Empty) => break,
                                Err(mpsc::error::TryRecvError::Disconnected) => {
                                    closed = true;
                                    break;
                                }
                            }
                            pump_local(&mut owner, &mut input_rx, &mut tips, &mut latch);
                        }
                        if closed {
                            break;
                        }
                        owner.deadlines_due();
                    }
                    None => break,
                }
            },
            wake = wakes.wait_wake_async() => match wake {
                Ok(_) => owner.deadlines_due(),
                Err(err) => {
                    tracing::error!(?err, "the timing engine is gone: chain sync stops");
                    break;
                }
            },
        }
    }
    let _gone = owner.timer.deregister();
}

/// Whether the timing engine has delivered a wake. `Some` takes it, so the
/// select's wait does not also see it. `None` is the engine gone.
fn clock_ready<C: Clock>(timer: &OwnerHandle<C>) -> Option<bool> {
    match timer.poll_wake() {
        Ok(ready) => Some(ready.is_some()),
        Err(err) => {
            tracing::error!(?err, "the timing engine is gone: chain sync stops");
            None
        }
    }
}

/// Proofs, entry replies, the tip and the latch, when any are already
/// waiting. A deadline is not one of these: it runs after the peer
/// messages that were queued when the clock fired.
fn pump_local<C, R>(
    owner: &mut Owner<C, R>,
    input_rx: &mut mpsc::UnboundedReceiver<Input>,
    tips: &mut watch::Receiver<TipChanged>,
    latch: &mut watch::Receiver<Option<FollowingDegraded>>,
) where
    C: Clock + Clone + Send + Sync + 'static,
    R: RelayRng + Send + 'static,
{
    while let Ok(input) = input_rx.try_recv() {
        owner.input(input);
    }
    if tips.has_changed().unwrap_or(false) {
        let tip = *tips.borrow_and_update();
        owner.tip(&tip);
    }
    if latch.has_changed().unwrap_or(false) {
        let set = latch.borrow_and_update().is_some();
        owner.latch(set);
    }
}

impl<C, R> Owner<C, R>
where
    C: Clock + Clone + Send + Sync + 'static,
    R: RelayRng + Send + 'static,
{
    /// The engine's clock as an instant.
    fn now(&self) -> Instant {
        let (at, tick) = self.base;
        let since = self.timer.clock().now().get().saturating_sub(tick.get());
        at.checked_add(Duration::from_nanos(since)).unwrap_or(at)
    }

    /// An instant as a tick on the engine's clock.
    fn tick_of(&self, deadline: Instant) -> Tick {
        let (at, tick) = self.base;
        let since = deadline.saturating_duration_since(at).as_nanos();
        Tick::new(
            tick.get()
                .saturating_add(u64::try_from(since).unwrap_or(u64::MAX)),
        )
    }

    /// Hand one event to the model and run what it asks for.
    fn event(&mut self, event: Event<Session>) {
        let mut out = Vec::new();
        if let Ok(wall) = self.executor.wall() {
            self.sync.set_wall(wall);
        }
        let now = self.now();
        let result = match self.store.begin_read() {
            Ok(snap) => {
                let main = SnapshotView::new(&snap);
                self.sync.handle(event, &main, now, &mut self.rng, &mut out)
            }
            Err(err) => Err(err),
        };
        if let Err(err) = result {
            tracing::error!(%err, "the store could not be read: the event is dropped");
        }
        self.commands(out);
    }

    /// A copy of a handshake request or a timed sync (the router's claim
    /// tap): its sync payload is the session's claim. A copy that does not
    /// decode is the C++ handler's to judge, and gives no claim.
    fn tap(&mut self, session: Session, kind: Tapped, payload: &[u8]) {
        let core: Result<CoreSyncData, _> = match kind {
            Tapped::HandshakeRequest => {
                HandshakeRequest::load(payload).map(|message| message.payload_data)
            }
            Tapped::TimedSyncRequest => {
                TimedSyncRequest::load(payload).map(|message| message.payload_data)
            }
            Tapped::TimedSyncResponse => {
                TimedSyncResponse::load(payload).map(|message| message.payload_data)
            }
        };
        match core {
            Ok(core) => self.claim(
                session,
                SyncPayload {
                    current_height: core.current_height,
                    cumulative_difficulty: core.cumulative_difficulty,
                    cumulative_difficulty_top64: core.cumulative_difficulty_top64,
                    top_id: core.top_id,
                },
            ),
            Err(err) => {
                tracing::debug!(%session, ?kind, %err, "a tapped message that does not decode")
            }
        }
    }

    fn claim(&mut self, session: Session, sync: SyncPayload) {
        let claim = PeerClaim {
            count: ChainCount::from_raw(sync.current_height),
            work: CumulativeDifficulty::from_raw(
                (u128::from(sync.cumulative_difficulty_top64) << 64)
                    | u128::from(sync.cumulative_difficulty),
            ),
            top: shekyl_types::BlockHash::from_bytes(sync.top_id),
        };
        let mut out = Vec::new();
        let now = self.now();
        let result = match self.store.begin_read() {
            Ok(snap) => {
                let main = SnapshotView::new(&snap);
                self.sync
                    .claim(session, claim, &main, now, &mut self.rng, &mut out)
            }
            Err(err) => Err(ClaimError::View(err)),
        };
        match result {
            Ok(()) => {}
            Err(ClaimError::Refused(refused)) => {
                tracing::debug!(%session, ?refused, "a claim that cannot be a chain");
                self.close(session);
            }
            Err(ClaimError::View(err)) => {
                tracing::error!(%err, "the store could not be read: the claim is dropped");
            }
        }
        self.commands(out);
    }

    fn routed(&mut self, routed: Routed) {
        match routed {
            Routed::Established { id, connector } => {
                let session = Session::new(id);
                let transit = match declaration(connector.column()).transit_ms() {
                    Assessment::Assessed(ms) => Duration::from_millis(u64::from(ms.ms())),
                    Assessment::NotAssessed => Duration::ZERO,
                };
                self.event(Event::SessionOpened { session, transit });
            }
            Routed::Claim { id, sync } => self.claim(Session::new(id), sync),
            Routed::Announce { id, payload } => self.announce(Session::new(id), &payload),
            Routed::Tap { id, kind, payload } => self.tap(Session::new(id), kind, &payload),
            Routed::Message {
                id,
                command,
                payload,
            } => self.message(Session::new(id), command, payload),
            Routed::Finished { id } => {
                let session = Session::new(id);
                match self.serving.get_mut(&session) {
                    Some(serving) if serving.busy || !serving.queue.is_empty() => {
                        serving.finishes = serving.finishes.saturating_add(1);
                    }
                    _ => self.hub.delivery_finished(id, true),
                }
            }
            Routed::Closed { id } => {
                let session = Session::new(id);
                self.serving.remove(&session);
                self.door.session_closed(SessionId(session.socket().get()));
                self.event(Event::SessionClosed { session });
            }
        }
    }

    fn message(&mut self, session: Session, command: SyncCommand, payload: Vec<u8>) {
        match command {
            SyncCommand::ResponseHeaders => {
                tracing::trace!(%session, bytes = payload.len(), "a header response");
                self.event(Event::Headers {
                    session,
                    bytes: payload,
                });
            }
            SyncCommand::ResponseBodies => self.event(Event::Bodies {
                session,
                bytes: payload,
            }),
            SyncCommand::RequestHeaders => match RequestHeaders::decode(&payload) {
                Ok(request) => self.queue_serve(session, ServeRequest::Headers(request)),
                Err(err) => {
                    tracing::debug!(%session, %err, "a header request that does not decode");
                    self.close(session);
                }
            },
            SyncCommand::RequestBodies => match RequestBodies::decode(&payload) {
                Ok(request) => self.queue_serve(session, ServeRequest::Bodies(request)),
                Err(err) => {
                    tracing::debug!(%session, %err, "a body request that does not decode");
                    self.close(session);
                }
            },
        }
    }

    fn queue_serve(&mut self, session: Session, request: ServeRequest) {
        let serving = self.serving.entry(session).or_default();
        if serving.push(request) {
            tracing::debug!(%session, "a later request replaced a waiting one of its kind");
        }
        self.serve_next(session);
    }

    fn serve_next(&mut self, session: Session) {
        let Some(serving) = self.serving.get_mut(&session) else {
            return;
        };
        if serving.busy {
            return;
        }
        let Some(request) = serving.queue.pop_front() else {
            let finishes = std::mem::take(&mut serving.finishes);
            let id = session.socket();
            for _ in 0..finishes {
                self.hub.delivery_finished(id, true);
            }
            return;
        };
        serving.busy = true;
        let store = Arc::clone(&self.store);
        let inputs = self.inputs.clone();
        tokio::task::spawn_blocking(move || {
            let bytes = match request {
                ServeRequest::Headers(request) => serve_headers(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| {
                        response
                            .store()
                            .map(|payload| notify(SyncCommand::ResponseHeaders.wire_id(), &payload))
                            .map_err(|err| err.to_string())
                    }),
                ServeRequest::Bodies(request) => serve_bodies(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| {
                        response
                            .store()
                            .map(|payload| notify(SyncCommand::ResponseBodies.wire_id(), &payload))
                            .map_err(|err| err.to_string())
                    }),
            };
            let bytes = match bytes {
                Ok(bytes) => Some(bytes),
                Err(err) => {
                    tracing::error!(%err, "a request could not be served");
                    None
                }
            };
            let _gone = inputs.send(Input::Served { session, bytes });
        });
    }

    fn input(&mut self, input: Input) {
        match input {
            Input::Proven { job, results } => {
                tracing::trace!(?job, proved = results.len(), last = ?results.last().map(proved_kind), "a prove job answered");
                self.event(Event::Proven { job, results });
            }
            Input::Entry { tag, reply } => {
                let offered = self.offered.remove(&tag);
                tracing::trace!(
                    tag,
                    session = offered
                        .as_ref()
                        .map(|offered| offered.session.socket().get()),
                    ?reply,
                    "an entry reply"
                );
                // An offer the owner no longer holds was solicited: a switch
                // then cannot be the arrival, so it is noted.
                let solicited = offered.as_ref().is_none_or(|offered| offered.solicited);
                let arrival = offered.map(|offered| offered.hash);
                self.event(Event::Entry {
                    tag,
                    outcome: outcome_of(reply, solicited, arrival),
                });
                self.room();
            }
            Input::Served { session, bytes } => {
                if let Some(serving) = self.serving.get_mut(&session) {
                    serving.busy = false;
                }
                if let Some(bytes) = bytes {
                    // A refused send is the transport's close, not sync's.
                    let _sent = self.hub.send(session.socket(), bytes);
                }
                self.serve_next(session);
            }
        }
    }

    /// An announced block (2008): the block, the transactions it
    /// carried, and its witness. A payload that does not decode, or a
    /// pruned entry, is the sender's form failure.
    fn announce(&mut self, session: Session, payload: &[u8]) {
        let announced = match NewCompactBlock::load(payload) {
            Ok(announced) if !announced.b.pruned => announced,
            Ok(_) => {
                tracing::debug!(%session, "a pruned announcement");
                self.close(session);
                return;
            }
            Err(err) => {
                tracing::debug!(%session, %err, "an announcement that does not decode");
                self.close(session);
                return;
            }
        };
        let body = BlockBody {
            block: announced.b.block,
            txs: announced
                .b
                .txs
                .into_iter()
                .map(|tx| TxBody::Full(tx.blob))
                .collect(),
            attestation_witness: announced.b.attestation_witness,
        };
        self.event(Event::Announce { session, body });
    }

    /// Relay a block the model relays (module docs): the block with its
    /// witness and no transactions, as 2008, to every established session
    /// but `from`, its supplier.
    fn relay(&mut self, hash: BlockHash, from: Session) {
        let bytes = match relay::announcement(&self.store, &hash) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                tracing::debug!(?hash, "a relayed block is no longer on the main chain");
                return;
            }
            Err(relay::Fault::Store(err)) => {
                tracing::error!(%err, "the store could not be read: the relay is dropped");
                return;
            }
            Err(relay::Fault::Encode(err)) => {
                tracing::error!(%err, "a relayed block did not encode");
                return;
            }
        };
        relay::fan_out(&self.hub, from.socket(), &bytes);
    }

    fn tip(&mut self, changed: &TipChanged) {
        let Some(tip) = changed.tip else {
            return;
        };
        let Some(height) = tip.count.tip() else {
            return;
        };
        self.event(Event::Tip {
            tip: Tip {
                height,
                hash: tip.top_id,
            },
        });
    }

    fn latch(&mut self, set: bool) {
        self.event(Event::Latch { set });
        self.alarm_tx.send_replace(self.sync.alarm());
    }

    /// Report the door's room when it moved.
    fn room(&mut self) {
        let room = self.door.room();
        if self.seats == Some(room) {
            return;
        }
        self.seats = Some(room);
        self.event(Event::Room {
            seats: u32::try_from(room).unwrap_or(u32::MAX),
        });
    }

    fn close(&mut self, session: Session) {
        self.hub.close(session.socket());
    }

    fn arm(&mut self, deadline: Instant, session: Session, request: u64) {
        let tick = self.tick_of(deadline);
        self.deadlines
            .entry(tick)
            .or_default()
            .push((session, request));
        self.rearm();
    }

    fn rearm(&mut self) {
        let next = self.deadlines.keys().next().copied();
        if next == self.armed {
            return;
        }
        self.armed = next;
        let result = match next {
            Some(tick) => self.timer.arm(tick),
            None => self.timer.clear(),
        };
        if let Err(err) = result {
            tracing::error!(?err, "a sync deadline could not be armed");
        }
    }

    fn deadlines_due(&mut self) {
        self.armed = None;
        let now = self.timer.clock().now();
        let later = self
            .deadlines
            .split_off(&Tick::new(now.get().saturating_add(1)));
        let due = std::mem::replace(&mut self.deadlines, later);
        for (session, request) in due.into_values().flatten() {
            self.event(Event::Deadline { session, request });
        }
        self.rearm();
    }

    fn send(&mut self, session: Session, bytes: Vec<u8>) {
        // A refused send is the transport's close, not sync's.
        let _sent = self.hub.send(session.socket(), bytes);
    }

    fn commands(&mut self, out: Vec<Command<Session>>) {
        for command in out {
            match command {
                Command::Publish { state } => {
                    self.state_tx.send_replace(state);
                }
                Command::RequestHeaders {
                    session,
                    id,
                    request,
                    deadline,
                } => match request.store() {
                    Ok(payload) => {
                        tracing::trace!(
                            %session,
                            id,
                            locator = request.block_ids.len(),
                            "a header request"
                        );
                        self.send(
                            session,
                            notify(SyncCommand::RequestHeaders.wire_id(), &payload),
                        );
                        self.arm(deadline, session, id);
                    }
                    Err(err) => tracing::error!(%err, "a header request did not encode"),
                },
                Command::RequestBodies {
                    session,
                    id,
                    request,
                    deadline,
                } => match request.store() {
                    Ok(payload) => {
                        self.send(
                            session,
                            notify(SyncCommand::RequestBodies.wire_id(), &payload),
                        );
                        self.arm(deadline, session, id);
                    }
                    Err(err) => tracing::error!(%err, "a body request did not encode"),
                },
                Command::Prove {
                    job,
                    class,
                    cache,
                    items,
                } => {
                    tracing::trace!(?job, ?class, ?cache, items = items.len(), "a prove job");
                    let executor = Arc::clone(&self.executor);
                    let inputs = self.inputs.clone();
                    tokio::spawn(async move {
                        let results = crate::executor::prove(executor, class, cache, items).await;
                        let _gone = inputs.send(Input::Proven { job, results });
                    });
                }
                Command::Offer { arrivals } => self.offer(arrivals),
                Command::Close { session, cause } => {
                    tracing::debug!(%session, ?cause, "chain sync closes a session");
                    self.close(session);
                }
                Command::RaiseAlarm { fork_at, tip, work } => {
                    // The latch watch carries the write back as `Latch`.
                    let alarm = self.alarm.clone();
                    tokio::spawn(async move {
                        let evidence = FollowingDegraded { fork_at, tip, work };
                        if let Err(err) = alarm.raise(evidence).await {
                            tracing::error!(?err, "the latch could not be written");
                        }
                    });
                }
                Command::RequestComplement { session } => {
                    let request = GetTxpoolComplement {
                        hashes: (self.pool_hashes)(),
                    };
                    match request.store() {
                        Ok(payload) => {
                            self.send(session, notify(NOTIFY_GET_TXPOOL_COMPLEMENT, &payload));
                        }
                        Err(err) => tracing::error!(%err, "a complement request did not encode"),
                    }
                }
                Command::Relay { hash, from } => self.relay(hash, from),
                Command::RequestMissingTxs {
                    session,
                    block,
                    indices,
                } => {
                    let current = self
                        .store
                        .begin_read()
                        .ok()
                        .and_then(|snap| snap.tip().ok())
                        .and_then(|tip| tip.recorded)
                        .map_or(0, |tip| tip.height.to_raw().saturating_add(1));
                    let request = RequestCompactMissingTx {
                        block_hash: *block.as_bytes(),
                        current_blockchain_height: current,
                        missing_tx_indices: indices,
                    };
                    match request.store() {
                        Ok(payload) => {
                            self.send(session, notify(NOTIFY_REQUEST_COMPACT_MISSING_TX, &payload))
                        }
                        Err(err) => tracing::error!(%err, "a missing-tx request did not encode"),
                    }
                }
            }
        }
    }

    /// Offer bound arrivals to the entry. A refused span answers every
    /// arrival in it: no room is `NoRoom`, and an oversize arrival is
    /// `Oversize` while the rest of its span is wanted again.
    fn offer(&mut self, arrivals: Vec<BoundArrival<Session>>) {
        if arrivals.is_empty() {
            return;
        }
        let mut pending = Vec::with_capacity(arrivals.len());
        let span: Vec<EntryArrival> = arrivals
            .into_iter()
            .map(|arrival| {
                let BoundArrival {
                    tag,
                    session,
                    header,
                    body,
                    solicited,
                } = arrival;
                let hash = header.hash();
                pending.push((tag, session, solicited, hash));
                EntryArrival {
                    tag: ArrivalTag(tag),
                    session: SessionId(session.socket().get()),
                    solicited,
                    judged: header,
                    block: body.block,
                    bodies: body.txs,
                    attestation_witness: body.attestation_witness,
                }
            })
            .collect();
        // The door's own measure, so an arrival it would admit is never
        // called oversize here.
        let tags: Vec<(u64, Session, bool, BlockHash, usize)> = span
            .iter()
            .zip(pending)
            .map(|(arrival, (tag, session, solicited, hash))| {
                (tag, session, solicited, hash, arrival.bytes())
            })
            .collect();
        match self.door.offer_bound(span) {
            Ok(tickets) => {
                for (tag, session, solicited, hash, _) in &tags {
                    self.offered.insert(
                        *tag,
                        Offered {
                            session: *session,
                            solicited: *solicited,
                            hash: *hash,
                        },
                    );
                }
                for ticket in tickets {
                    let inputs = self.inputs.clone();
                    tokio::spawn(async move {
                        let tagged = ticket.reply().await;
                        let _gone = inputs.send(Input::Entry {
                            tag: tagged.tag.0,
                            reply: tagged.reply,
                        });
                    });
                }
                // The model spent these seats when it offered. A span that
                // finishes before the sample below can return the door to
                // the count last reported, and a suppressed sample would
                // leave the model short of the door.
                self.seats = None;
            }
            Err(refusal) => {
                let max = self
                    .door
                    .max_arrival_bytes()
                    .and_then(|max| usize::try_from(max).ok());
                for (tag, _, solicited, _, bytes) in tags {
                    let outcome = match refusal {
                        // No room and a dry bucket wait for a seat. An
                        // unreadable store does not: the service stops on
                        // that read, and a later seat report must not
                        // offer the body again.
                        Refusal::NoRoom | Refusal::Throttled => Outcome::NoRoom,
                        Refusal::StoreUnreadable => Outcome::StoreUnreadable,
                        Refusal::Oversize if max.is_some_and(|max| bytes > max) => {
                            // A requested body invalidates its header; an
                            // announced one does not.
                            Outcome::Oversize {
                                invalidate: solicited,
                            }
                        }
                        Refusal::Oversize => Outcome::Again,
                    };
                    self.event(Event::Entry { tag, outcome });
                }
            }
        }
        self.room();
    }
}

/// A prove result's kind, for the trace.
fn proved_kind(proved: &Proved) -> &'static str {
    match proved {
        Proved::Formed(_) => "formed",
        Proved::Refused(_) => "refused",
        Proved::NotHeld => "not held",
    }
}

/// The entry's reply as the model's outcome.
///
/// [`SyncReply::action`] is the authority for what the reply means.
/// `solicited` is a body this node requested. A bound body is; an
/// announcement is not. `arrival` is the block the offer named, and it is
/// absent when that offer is already gone. A switch is a connect when
/// `arrival` is the promoted tip, and [`Outcome::Noted`] otherwise: the
/// model has one relay path, and the reply carries no second one.
fn outcome_of(reply: Reply, solicited: bool, arrival: Option<BlockHash>) -> Outcome {
    let action = sync_reply(&reply).action(solicited);
    match (action, reply) {
        (SyncReplyAction::Advance, Reply::Connected { height, .. }) => {
            Outcome::Connected { height }
        }
        (SyncReplyAction::Invalidate(Invalidate::Refused), Reply::Refused(verdict)) => {
            Outcome::Refused { verdict }
        }
        (
            SyncReplyAction::Invalidate(Invalidate::PromotionRefused),
            Reply::PromotionRefused { hash, refused, .. },
        ) => Outcome::PromotionRefused {
            verdict: refused,
            block: hash,
        },
        (SyncReplyAction::Relocate, Reply::Unlinked { at }) => Outcome::Unlinked { at },
        (SyncReplyAction::RequestHeaders, Reply::BeyondCap(_)) => Outcome::BeyondCap,
        (SyncReplyAction::RequestMissing, Reply::MissingBodies { indices }) => {
            Outcome::MissingBodies {
                indices: indices
                    .into_iter()
                    .map(|index| u64::try_from(index).unwrap_or(u64::MAX))
                    .collect(),
            }
        }
        (SyncReplyAction::Again, Reply::Cancelled { .. } | Reply::Stopped) => Outcome::Again,
        (
            SyncReplyAction::None,
            Reply::AlreadyHeld | Reply::Held { .. } | Reply::CannotFollow(_),
        ) => Outcome::Noted,
        // The promoted blocks ascend, so the last is main's new tip. It is
        // a connect only when that tip is the arrival this offer named.
        (SyncReplyAction::None, Reply::Switched { promoted, .. }) => {
            match (promoted.last(), arrival) {
                (Some(&(height, tip)), Some(arrival)) if tip == arrival => {
                    Outcome::Connected { height }
                }
                _ => Outcome::Noted,
            }
        }
        (action, reply) => {
            tracing::error!(?action, ?reply, "an entry reply and its action disagree");
            Outcome::Noted
        }
    }
}

/// The peer-policy name of an entry reply. Exhaustive, so a new reply
/// cannot arrive here unnamed.
fn sync_reply(reply: &Reply) -> SyncReply {
    match reply {
        Reply::Connected { .. } => SyncReply::Connected,
        Reply::Refused(_) => SyncReply::Refused,
        Reply::PromotionRefused { .. } => SyncReply::PromotionRefused,
        Reply::Unlinked { .. } => SyncReply::Unlinked,
        Reply::AlreadyHeld => SyncReply::AlreadyHeld,
        Reply::Held { .. } => SyncReply::Held,
        Reply::Switched { .. } => SyncReply::Switched,
        Reply::BeyondCap(_) => SyncReply::BeyondCap,
        Reply::CannotFollow(_) => SyncReply::CannotFollow,
        Reply::MissingBodies { .. } => SyncReply::MissingBodies,
        Reply::Cancelled { .. } => SyncReply::Cancelled,
        Reply::Stopped => SyncReply::Stopped,
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;

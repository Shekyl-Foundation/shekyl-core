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
//!   `RequestMissingTxs` is encoded and sent as our own 2009, and a peer's
//!   2009 is served from the store like a header or body request
//!   ([`crate::serve::serve_missing_txs`]): its faults close the session.
//! - **Relay** is the model's decision ([`Command::Relay`]): a block that
//!   connected as the new tip while this node, with it, is not `Behind`,
//!   however it arrived. The owner builds that compact announcement (the
//!   block and its witness, no transactions) and sends it as 2008 to every
//!   established session but the one that supplied it. A block no session
//!   supplied, such as one this node mined, goes to every established
//!   session. That send moves behind RD's relay entry when it lands.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_chain_ingest::service::{
    Alarm, ArrivalTag, BoundArrival as EntryArrival, Door, Reply, SeedPair, SessionId,
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
    TimedSyncResponse, HASH_SIZE, NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_NEW_COMPACT_BLOCK,
    NOTIFY_REQUEST_COMPACT_MISSING_TX,
};
use shekyl_runtime::{Pool, RuntimeBudget, ThreadName};
use shekyl_seam::{Hub, SocketId, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle, Tick};
use shekyl_transport_layer::{declaration, Assessment};
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{BlockBody, TxBody};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::Instrument;

use crate::executor::Executor;
use crate::outcome;
use crate::relay;
use crate::router::{Routed, Tapped};
use crate::serve::{
    serve_bodies, serve_headers, serve_missing_txs, MissingTxsRefused, MissingTxsServed,
};
use crate::session::Session;
use crate::transit::{micros, Transit};
use shekyl_chain_sync::{
    BoundArrival, ClaimError, Command, Declaration, Event, Job, Outcome, PeerClaim, Proved,
    Requesting, Sync as Model, SyncState, SyncView,
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
    /// The seam, for sends, closes and finished deliveries. It arrives
    /// once the seam is bound, which is after the node opens: the bind
    /// attaches the router to this owner, mints the hub on it, and sends
    /// the hub here (`shekyl_ffi::chain_sync_ffi`). The owner handles
    /// nothing until it arrives. The router precedes every session, so no
    /// session's messages are lost while it waits. A sender dropped
    /// unsent is a node whose seam was never bound: the owner ends.
    pub hub: oneshot::Receiver<Arc<Hub>>,
    /// The prove jobs' runner.
    pub executor: Arc<Executor>,
    /// The owner's registration on the timing engine, class `Sync`.
    pub timer: OwnerHandle<C>,
    /// The rule schedule.
    pub rules: ChainRules,
    /// Whether the model requests anything from peers: the regtest
    /// `dev-sync` row. It still serves, relays and publishes when `Off`.
    pub requesting: Requesting,
    /// The operator's declaration of the node's network, read from the
    /// configuration once at open (CS-Q2 step 8).
    pub declaration: Declaration,
    /// The daemon's draw source.
    pub rng: R,
    /// The pool's transaction hashes, for the complement request.
    pub pool_hashes: Arc<dyn Fn() -> Vec<[u8; HASH_SIZE]> + Send + Sync>,
    /// The router's output.
    pub routed: mpsc::UnboundedReceiver<Routed>,
    /// Where the derived sync state is published (CS-Q2 step 8), which the
    /// RPC's facts, the miner's follower and the relay gate read. The owner
    /// is its only publisher: the node hands this sender over and keeps a
    /// receiver. [`spawn`] publishes the declaration's state at open
    /// before it returns; [`Running`] keeps a clone that never sends, so
    /// the watch does not close when the task ends, and the task publishes
    /// [`SyncState::NoView`] on every exit.
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
    view: watch::Receiver<SyncView<SocketId>>,
    ended: watch::Receiver<Option<Ended>>,
    /// Holds the state watch open after the task ends, so a reader sees
    /// the [`SyncState::NoView`] the task published, not a closed watch.
    /// Never sends.
    _state_open: watch::Sender<SyncState>,
}

impl Running {
    /// How the owner's task ended, once it has: `None` while it runs. The
    /// value stays after the task, so a reader that looks late still sees
    /// the cause.
    #[must_use]
    pub fn ended(&self) -> watch::Receiver<Option<Ended>> {
        self.ended.clone()
    }

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

    /// The model's view (CS-5 §7), published after every event: what
    /// `sync_info` renders. A session is named by its seam socket.
    #[must_use]
    pub fn view(&self) -> watch::Receiver<SyncView<SocketId>> {
        self.view.clone()
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
    // The state at open is the owner's first publish (CS-Q2 step 8), made
    // before this returns, so a reader of the node just opened reads it.
    parts.state.send_replace(parts.declaration.state_at_open());
    let state = parts.state.subscribe();
    let state_open = parts.state.clone();
    let (alarm_tx, alarm) = watch::channel(false);
    let (view_tx, view) = watch::channel(SyncView::empty());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (ended_tx, ended) = watch::channel(None);
    let executor = Arc::clone(&parts.executor);
    // The owner's log lines carry the span it was started in.
    let published = Published { alarm_tx, view_tx };
    pool.spawn(run(parts, published, stop_rx, ended_tx).instrument(tracing::Span::current()));
    Ok(Running {
        pool,
        executor,
        stop_tx,
        state,
        alarm,
        view,
        ended,
        _state_open: state_open,
    })
}

/// How the owner's task ended ([`Running::ended`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// [`Running::stop`] asked it to.
    Stopped,
    /// It ended on its own, and the cause names what closed under it. A
    /// daemon whose owner ends this way never syncs again, so the daemon
    /// stops with this cause.
    Failed(&'static str),
}

/// The cause a task end carries when no exit set one: only an unwind
/// leaves the task without setting its cause.
const PANICKED: &str = "the sync owner's task panicked";
/// The router's sender went: the seam's hub was dropped.
const ROUTER_CLOSED: &str = "the router closed";
/// The process timing engine went.
const ENGINE_CLOSED: &str = "the timing engine closed";

/// Reports the owner task's end, however it ends: a stop, a closed input
/// and a panic alike.
///
/// Once the owner has its hub (`syncing`), it publishes
/// [`SyncState::NoView`]. [`Running`] keeps the watch open, so the facts'
/// and the follower's closed-watch reading never fires; without this
/// publish they would keep the last state, including `Synced`, after the
/// owner is gone. Before the hub, the state at open stands: an owner that
/// never had a hub never changed it, and a node declared offline or closed
/// is `Synced` with no seam at all. It always sends [`Ended`] on
/// [`Running::ended`]: each exit sets `how` first, and an unwind leaves
/// [`PANICKED`]. Once a stop was asked, the end is
/// [`Ended::Stopped`] whatever `how` says: [`Running::stop`] shuts the
/// owner's runtime down, which can cancel the task before it reads the
/// request.
struct EndGuard {
    state: watch::Sender<SyncState>,
    ended: watch::Sender<Option<Ended>>,
    stop: watch::Receiver<bool>,
    how: Ended,
    /// The owner has its hub and publishes the state.
    syncing: bool,
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        if self.syncing {
            self.state.send_replace(SyncState::NoView);
        }
        let how = if *self.stop.borrow() {
            Ended::Stopped
        } else {
            self.how
        };
        self.ended.send_replace(Some(how));
    }
}

/// The watches the owner publishes on beside the node's state.
struct Published {
    alarm_tx: watch::Sender<bool>,
    view_tx: watch::Sender<SyncView<SocketId>>,
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
        served: Served,
    },
    /// The latch write a `RaiseAlarm` asked for was refused.
    AlarmRefused,
}

/// What a deadline on the owner's timer wakes.
#[derive(Clone, Copy, Debug)]
enum Wake {
    /// A request's or a draw's deadline: [`Event::Deadline`].
    Request(Session, u64),
    /// A refused latch write's retry: [`Event::AlarmRetry`].
    AlarmRetry,
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
    /// When it was offered: the entry's answer is timed from here.
    at: Instant,
}

/// A request a session sent this node.
enum ServeRequest {
    Headers(RequestHeaders),
    Bodies(RequestBodies),
    MissingTxs(RequestCompactMissingTx),
}

/// What serving one request came to.
enum Served {
    /// The answer, framed.
    Send(Vec<u8>),
    /// Nothing is sent: the store could not answer, or the block left the
    /// main chain after it was announced.
    Nothing,
    /// The request was the peer's fault: the session closes.
    Close(MissingTxsRefused),
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
    /// Engine ticks to the wakes due then.
    deadlines: BTreeMap<Tick, Vec<Wake>>,
    armed: Option<Tick>,
    /// The engine clock's origin, read once at start.
    base: (Instant, Tick),
    /// Offered arrivals, by tag.
    offered: HashMap<u64, Offered>,
    serving: HashMap<Session, Serving>,
    /// Header and body requests in flight, and seat waits. Records the
    /// profile is timed from. Nothing the owner decides reads them.
    transit: Transit,
    /// Sessions whose Levin handshake has completed ([`Routed::Opened`]).
    /// The owner sends to no other: a peer still waiting on the
    /// handshake's reply refuses anything else.
    opened: HashSet<Session>,
    seats: Option<usize>,
    /// The seed window's published pair, read when a proof found a seed
    /// absent (`Command::SeedNotHeld`). The loop waits on its own
    /// receiver of the same watch.
    seeds: watch::Receiver<Option<SeedPair>>,
    /// The pair the model was last told of. The attendant republishes the
    /// window at every tip; the model hears `Event::Seeds` when the pair
    /// differs.
    seen_seeds: Option<SeedPair>,
    state_tx: watch::Sender<SyncState>,
    published: Published,
}

async fn run<C, R>(
    parts: OwnerParts<C, R>,
    published: Published,
    mut stop: watch::Receiver<bool>,
    ended: watch::Sender<Option<Ended>>,
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
        requesting,
        declaration,
        rng,
        pool_hashes,
        mut routed,
        state: state_tx,
    } = parts;
    // Dropped with the task: every exit below sets `how` first.
    let mut end = EndGuard {
        state: state_tx.clone(),
        ended,
        stop: stop.clone(),
        how: Ended::Failed(PANICKED),
        syncing: false,
    };
    let hub = tokio::select! {
        biased;
        _ = stop.wait_for(|stop| *stop) => {
            end.how = Ended::Stopped;
            return;
        }
        hub = hub => match hub {
            Ok(hub) => hub,
            Err(_) => {
                end.how = Ended::Failed("the seam never bound, so chain sync never started");
                return;
            }
        },
    };
    end.syncing = true;
    let (inputs, mut input_rx) = mpsc::unbounded_channel();
    let schedule: Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet + Send> =
        Box::new(move |height| rules.in_force(height));
    let base = (Instant::now(), timer.clock().now());
    let timer = Arc::new(timer);
    let wakes = Arc::clone(&timer);
    let mut seeds = door.seeds();
    let seen_seeds = *seeds.borrow_and_update();
    let mut owner = Owner {
        sync: Model::new(rules.trust(), schedule)
            .with_requesting(requesting)
            .with_declaration(declaration),
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
        transit: Transit::default(),
        opened: HashSet::new(),
        seats: None,
        seeds: seeds.clone(),
        seen_seeds,
        state_tx,
        published,
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
            _ = stop.wait_for(|stop| *stop) => {
                end.how = Ended::Stopped;
                break;
            }
            input = input_rx.recv() => {
                if let Some(input) = input {
                    owner.input(input);
                }
            },
            changed = tips.changed() => {
                if changed.is_err() {
                    end.how = Ended::Failed("the connector's tip watch closed");
                    break;
                }
                let tip = *tips.borrow_and_update();
                owner.tip(&tip);
            },
            changed = latch.changed() => {
                if changed.is_err() {
                    end.how = Ended::Failed("the latch watch closed");
                    break;
                }
                let set = latch.borrow_and_update().is_some();
                owner.latch(set);
            },
            changed = seeds.changed() => {
                if changed.is_err() {
                    end.how = Ended::Failed("the seed watch closed");
                    break;
                }
                let pair = *seeds.borrow_and_update();
                owner.seeds_published(pair);
            },
            routed_one = routed.recv() => {
                let Some(routed_one) = routed_one else {
                    end.how = Ended::Failed(ROUTER_CLOSED);
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
                            end.how = Ended::Failed(ROUTER_CLOSED);
                            break;
                        }
                        owner.deadlines_due();
                    }
                    None => {
                        end.how = Ended::Failed(ENGINE_CLOSED);
                        break;
                    }
                }
            },
            wake = wakes.wait_wake_async() => match wake {
                Ok(_) => owner.deadlines_due(),
                Err(err) => {
                    tracing::info!(?err, "the timing engine closed: chain sync stops");
                    end.how = Ended::Failed(ENGINE_CLOSED);
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
            tracing::info!(?err, "the timing engine closed: chain sync stops");
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
            Routed::Opened { id, connector } => {
                let session = Session::new(id);
                let transit = match declaration(connector.column()).transit_ms() {
                    Assessment::Assessed(ms) => Duration::from_millis(u64::from(ms.ms())),
                    Assessment::NotAssessed => Duration::ZERO,
                };
                if self.opened.insert(session) {
                    self.event(Event::SessionOpened { session, transit });
                }
            }
            Routed::Claim { id, sync } => self.claim(Session::new(id), sync),
            Routed::Announce { id, .. }
            | Routed::MissingTxs { id, .. }
            | Routed::Message { id, .. }
                if !self.opened.contains(&Session::new(id)) =>
            {
                // Chain-sync traffic before the handshake has completed:
                // no peer that follows the protocol sends it.
                let session = Session::new(id);
                tracing::debug!(%session, "chain-sync traffic before the handshake");
                self.close(session);
            }
            Routed::Announce { id, payload } => self.announce(Session::new(id), &payload),
            Routed::MissingTxs { id, payload } => {
                let session = Session::new(id);
                match RequestCompactMissingTx::load(&payload) {
                    Ok(request) => self.queue_serve(session, ServeRequest::MissingTxs(request)),
                    Err(err) => {
                        tracing::debug!(%session, %err, "a missing-tx request that does not decode");
                        self.close(session);
                    }
                }
            }
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
                self.opened.remove(&session);
                self.transit.forget_session(session);
                self.serving.remove(&session);
                self.door.session_closed(SessionId(session.socket().get()));
                self.event(Event::SessionClosed { session });
            }
        }
    }

    fn message(&mut self, session: Session, command: SyncCommand, payload: Vec<u8>) {
        match command {
            SyncCommand::ResponseHeaders => {
                if let Some(sent) = self.transit.take_headers(session) {
                    let transit = sent.elapsed();
                    self.executor
                        .metrics()
                        .headers_transited(payload.len(), transit);
                    tracing::debug!(
                        %session,
                        kind = "headers",
                        bytes = payload.len(),
                        transit_us = micros(transit),
                        "a sync response"
                    );
                }
                self.event(Event::Headers {
                    session,
                    bytes: payload,
                });
            }
            SyncCommand::ResponseBodies => {
                if let Some((sent, blocks)) = self.transit.take_bodies(session) {
                    let transit = sent.elapsed();
                    self.executor
                        .metrics()
                        .transited(blocks, payload.len(), transit);
                    tracing::debug!(
                        %session,
                        kind = "bodies",
                        bytes = payload.len(),
                        items = blocks,
                        transit_us = micros(transit),
                        "a sync response"
                    );
                }
                self.event(Event::Bodies {
                    session,
                    bytes: payload,
                });
            }
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
            let served = match request {
                ServeRequest::Headers(request) => serve_headers(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| {
                        outcome::framed(SyncCommand::ResponseHeaders.wire_id(), &response)
                    })
                    .map(Served::Send),
                ServeRequest::Bodies(request) => serve_bodies(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| {
                        outcome::framed(SyncCommand::ResponseBodies.wire_id(), &response)
                    })
                    .map(Served::Send),
                ServeRequest::MissingTxs(request) => serve_missing_txs(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|served| match served {
                        MissingTxsServed::Answer(block) => {
                            outcome::framed(NOTIFY_NEW_COMPACT_BLOCK, &block).map(Served::Send)
                        }
                        MissingTxsServed::LeftMain => Ok(Served::Nothing),
                        MissingTxsServed::Refused(refused) => Ok(Served::Close(refused)),
                    }),
            };
            let served = served.unwrap_or_else(|err| {
                tracing::error!(%err, "a request could not be served");
                Served::Nothing
            });
            let _gone = inputs.send(Input::Served { session, served });
        });
    }

    fn input(&mut self, input: Input) {
        match input {
            Input::Proven { job, results } => {
                tracing::trace!(?job, proved = results.len(), last = ?results.last().map(outcome::proved_kind), "a prove job answered");
                self.event(Event::Proven { job, results });
            }
            Input::Entry { tag, reply } => {
                let offered = self.offered.remove(&tag);
                if let Some(offered) = &offered {
                    self.executor.metrics().entered(offered.at.elapsed());
                }
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
                    outcome: outcome::of_reply(reply, solicited, arrival),
                });
                self.room();
            }
            Input::AlarmRefused => self.event(Event::AlarmRefused),
            Input::Served { session, served } => {
                if let Some(serving) = self.serving.get_mut(&session) {
                    serving.busy = false;
                }
                match served {
                    // A refused send is the transport's close, not sync's.
                    Served::Send(bytes) => {
                        let _sent = self.hub.send(session.socket(), bytes);
                    }
                    Served::Nothing => {}
                    Served::Close(refused) => {
                        tracing::debug!(%session, ?refused, "a missing-tx request closes its session");
                        self.serving.remove(&session);
                        self.close(session);
                        return;
                    }
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
    /// but `from`, its supplier. A block no session supplied, such as one
    /// this node mined, goes to every established session.
    fn relay(&mut self, hash: BlockHash, from: Option<Session>) {
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
        relay::fan_out(
            &self.hub,
            self.opened.iter().map(|session| session.socket()),
            from.map(Session::socket),
            &bytes,
        );
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
        self.published.alarm_tx.send_replace(self.sync.alarm());
    }

    /// The seed window published `pair`. The model hears of it when it
    /// differs from the pair it was last told of: the attendant reinstalls
    /// the window at every tip, and the pair moves only at an epoch edge.
    fn seeds_published(&mut self, pair: Option<SeedPair>) {
        if self.seen_seeds == pair {
            return;
        }
        self.seen_seeds = pair;
        self.event(Event::Seeds);
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
        self.arm_wake(deadline, Wake::Request(session, request));
    }

    fn arm_wake(&mut self, deadline: Instant, wake: Wake) {
        let tick = self.tick_of(deadline);
        self.deadlines.entry(tick).or_default().push(wake);
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
        for wake in due.into_values().flatten() {
            match wake {
                Wake::Request(session, request) => {
                    self.event(Event::Deadline { session, request });
                }
                Wake::AlarmRetry => self.event(Event::AlarmRetry),
            }
        }
        self.rearm();
    }

    fn send(&mut self, session: Session, bytes: Vec<u8>) {
        // A refused send is the transport's close, not sync's.
        let _sent = self.hub.send(session.socket(), bytes);
    }

    /// Publish the model's view. The stall is logged once when it sets,
    /// at `warn`, and once when it clears (CS-5 F5, rule 82). Nothing here
    /// acts on it: new sessions clear it on their next event (CS-Q7).
    fn publish_view(&mut self) {
        let view = self.sync.view().map(Session::socket);
        let behind = matches!(
            self.published.view_tx.borrow().state,
            SyncState::Behind { .. }
        );
        if behind && matches!(view.state, SyncState::Synced | SyncState::Following { .. }) {
            // The per-block profile (CS-5 §8): every phase the node timed
            // since it opened, once each time a sync reaches the best chain.
            match self.executor.metrics().snapshot().to_json_line() {
                Ok(profile) => tracing::info!(
                    target_height = ?view.target.tip(),
                    %profile,
                    "sync reached the best chain; the phases so far"
                ),
                Err(err) => tracing::error!(%err, "the sync profile did not encode"),
            }
        }
        let was = self.published.view_tx.borrow().stalled;
        if view.stalled && !was {
            tracing::warn!(
                target_height = ?view.target.tip(),
                sessions = view.sessions.len(),
                "sync is stalled: no session's chain serves what the node still needs"
            );
        } else if was && !view.stalled {
            tracing::info!(sessions = view.sessions.len(), "sync is no longer stalled");
        }
        self.published.view_tx.send_if_modified(|current| {
            if *current == view {
                return false;
            }
            *current = view;
            true
        });
    }

    fn commands(&mut self, out: Vec<Command<Session>>) {
        // A proof that missed a seed the window now holds tells the model
        // the slots changed, after this batch. `seeds_published` would see
        // the pair as already told: the watch fired before the gate closed.
        let mut release_seed = None;
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
                        self.transit.note_headers(session, Instant::now());
                        self.arm(deadline, session, id);
                    }
                    Err(err) => tracing::error!(%err, "a header request did not encode"),
                },
                Command::ArmOpening {
                    session,
                    id,
                    deadline,
                }
                | Command::ArmDraw {
                    session,
                    id,
                    deadline,
                } => self.arm(deadline, session, id),
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
                        self.transit
                            .note_bodies(session, Instant::now(), request.hashes.len());
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
                Command::HeadersSpent { session, cause } => {
                    tracing::debug!(%session, ?cause, "a session's headers from H* yielded nothing");
                }
                Command::SeedNotHeld { session, seed } => {
                    // The lookup ran off the owner's task. A pair that holds
                    // the seed now was published between the lookup and
                    // this batch, and its change may already have been
                    // told before the model closed the gate.
                    let held = self.seeds.borrow().filter(|pair| pair.holds(&seed));
                    tracing::debug!(
                        %session,
                        ?seed,
                        held_now = held.is_some(),
                        "a session's headers hash under a seed the window does not hold"
                    );
                    if let Some(pair) = held {
                        release_seed = Some(pair);
                    }
                }
                Command::RaiseAlarm { fork_at, tip, work } => {
                    // The latch watch carries the write back as `Latch`; a
                    // refusal comes back as `AlarmRefused`, and the model
                    // retries it.
                    let alarm = self.alarm.clone();
                    let inputs = self.inputs.clone();
                    tokio::spawn(async move {
                        let evidence = FollowingDegraded { fork_at, tip, work };
                        if let Err(err) = alarm.raise(evidence).await {
                            tracing::error!(?err, "the latch could not be written; it is retried");
                            let _gone = inputs.send(Input::AlarmRefused);
                        }
                    });
                }
                Command::ArmAlarmRetry { deadline } => self.arm_wake(deadline, Wake::AlarmRetry),
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
        if let Some(pair) = release_seed {
            self.seen_seeds = Some(pair);
            // `Event::Seeds` does not emit `SeedNotHeld`, so this does not recur.
            self.event(Event::Seeds);
        }
        self.publish_view();
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
                // The span's seat wait: from the earliest refusal for room
                // among its arrivals to this offer, or none when the door
                // seated it first time. A record only (CS-5 §10's cap
                // sweep reads it); nothing below decides on it.
                let waited = self
                    .transit
                    .take_seat_wait(tags.iter().map(|(tag, _, _, _, _)| *tag));
                self.executor.metrics().seated(waited);
                if let Some((_, session, _, _, _)) = tags.first() {
                    tracing::debug!(
                        %session,
                        blocks = tags.len(),
                        waited_us = waited.map_or(0, micros),
                        waited = waited.is_some(),
                        "a body span seated"
                    );
                }
                for (tag, session, solicited, hash, _) in &tags {
                    self.offered.insert(
                        *tag,
                        Offered {
                            session: *session,
                            solicited: *solicited,
                            hash: *hash,
                            at: Instant::now(),
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
                let now = Instant::now();
                for (tag, session, solicited, _, bytes) in tags {
                    let outcome = outcome::of_refusal(refusal, solicited, bytes, max);
                    if outcome == Outcome::NoRoom {
                        // The wait is timed from the first refusal: a
                        // body refused again keeps its first.
                        self.transit.note_seat(tag, now, session);
                        // `NoRoom` froze the model's seats at zero until a
                        // `Room`. The sample below is suppressed while the
                        // door's count is the one last reported, and a
                        // refusal need not have moved it (a span the door
                        // would not seat at any count: seen 2026-11-02, a
                        // node `behind` for good with its seats frozen), so
                        // the count is forgotten here and the next sample
                        // is always a `Room`.
                        self.seats = None;
                    }
                    tracing::debug!(
                        %session,
                        tag,
                        ?refusal,
                        ?outcome,
                        solicited,
                        "the door refused an offer"
                    );
                    self.event(Event::Entry { tag, outcome });
                }
            }
        }
        self.room();
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;

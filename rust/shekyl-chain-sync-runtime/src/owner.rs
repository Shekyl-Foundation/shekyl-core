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
//! - **Sessions** are keyed by the admission id's number. [`SocketId`]
//!   does not order itself, and the model's maps need an order. The order
//!   carries no meaning: draws are uniform over the set.
//! - **`now`** is the timing engine's clock as an [`Instant`]. Deadlines
//!   go to the engine as ticks on that same clock, and come back as
//!   [`Event::Deadline`]. The engine holds one deadline per owner, so the
//!   owner arms the earliest of its own and keeps the rest.
//! - **The wall** is the substrate's clock, read once per event.
//! - **Serving** a request reads the store on a blocking thread, one
//!   request at a time per session, in arrival order. A delivered chunk
//!   that carried only chain-sync messages is finished after the requests
//!   it carried are answered, so a peer's requests wait in the transport
//!   and not in this task.
//! - **Announcements** (2008, `NOTIFY_NEW_COMPACT_BLOCK`) come from the
//!   attached router and are the model's [`Event::Announce`]. A connected
//!   one is relayed as the C++ `relay_block` does: compact, to every
//!   established session but its sender. That send moves behind RD's relay
//!   entry when it lands. `RequestMissingTxs` is encoded and sent; a peer's
//!   own 2009 stays the C++ handler's until the cutover.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_chain_ingest::service::{
    Alarm, ArrivalTag, BoundArrival as EntryArrival, Door, Refusal, Reply, SessionId,
};
use shekyl_chain_ingest::{ChainRules, TipChanged};
use shekyl_chain_rules::{InvalidBlock, Tip};
use shekyl_chain_store::codec::FollowingDegraded;
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::{
    notify, BlockCompleteEntry, GetTxpoolComplement, NewCompactBlock, PortableMap, RequestBodies,
    RequestCompactMissingTx, RequestHeaders, SyncCommand, HASH_SIZE, NOTIFY_GET_TXPOOL_COMPLEMENT,
    NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_REQUEST_COMPACT_MISSING_TX,
};
use shekyl_peer_policy::SyncReply;
use shekyl_runtime::{Pool, RuntimeBudget, ThreadName};
use shekyl_seam::{ConnectorId, Hub, SocketId, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle, Tick};
use shekyl_transport_layer::{declaration, Assessment};
use shekyl_types::{BlockHeight, ChainCount};
use shekyl_wire::{BlockBody, TxBody};
use tokio::sync::{mpsc, watch};
use tracing::Instrument;

use crate::executor::Executor;
use crate::router::Routed;
use crate::serve::{serve_bodies, serve_headers};
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
    /// node's handle, which the RPC, the miner and the relay gate read.
    pub state: watch::Sender<SyncState>,
}

/// The running owner.
#[must_use = "stop the owner from outside its pool"]
pub struct Running {
    pool: Pool,
    stop: Arc<AtomicBool>,
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
        self.stop.store(true, Ordering::Release);
        self.stop_tx.send_replace(true);
        self.pool.shutdown(timeout);
    }
}

/// Start the owner on its own row, in the caller's tracing span.
///
/// `stop` is shared with the executor, so a permit wait ends with the
/// owner. The row's blocking-thread cap is derived: the hasher budget's
/// permits, the most proof items that can hash at once. Serving and the
/// cache derivations queue on the same threads. The workers are one: the
/// owner is one task.
///
/// # Errors
///
/// The runtime could not be built.
pub fn spawn<C, R>(parts: OwnerParts<C, R>, stop: Arc<AtomicBool>) -> std::io::Result<Running>
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
    // The owner's log lines carry the span it was started in.
    pool.spawn(run(parts, alarm_tx, stop_rx).instrument(tracing::Span::current()));
    Ok(Running {
        pool,
        stop,
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
        session: u64,
        bytes: Option<Vec<u8>>,
    },
}

/// A request a session sent this node.
enum ServeRequest {
    Headers(RequestHeaders),
    Bodies(RequestBodies),
}

/// One session's serving queue.
#[derive(Default)]
struct Serving {
    queue: VecDeque<ServeRequest>,
    busy: bool,
    /// Chunks the router handed back, finished when the queue drains.
    finishes: u32,
}

/// What the owner keeps beside the model.
struct Owner<C: Clock + Clone, R> {
    sync: Model<u64, Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet + Send>>,
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
    deadlines: BTreeMap<Tick, Vec<(u64, u64)>>,
    armed: Option<Tick>,
    /// The engine clock's origin, read once at start.
    base: (Instant, Tick),
    /// Offered arrivals, by tag: who served them, and whether the body
    /// came unasked, for `from_reply`.
    offered: HashMap<u64, (u64, bool)>,
    /// The connector each session is on.
    connectors: HashMap<u64, ConnectorId>,
    serving: HashMap<u64, Serving>,
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
        connectors: HashMap::new(),
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
            routed = routed.recv() => match routed {
                Some(routed) => owner.routed(routed),
                None => break,
            },
            input = input_rx.recv() => {
                if let Some(input) = input {
                    owner.input(input);
                }
            }
            changed = tips.changed() => {
                if changed.is_err() {
                    break;
                }
                let tip = *tips.borrow_and_update();
                owner.tip(&tip);
            }
            changed = latch.changed() => {
                if changed.is_err() {
                    break;
                }
                let set = latch.borrow_and_update().is_some();
                owner.latch(set);
            }
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
    fn event(&mut self, event: Event<u64>) {
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

    fn claim(&mut self, session: u64, sync: SyncPayload) {
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
                tracing::debug!(session, ?refused, "a claim that cannot be a chain");
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
                let session = id.get();
                self.connectors.insert(session, connector);
                let transit = match declaration(connector.column()).transit_ms() {
                    Assessment::Assessed(ms) => Duration::from_millis(u64::from(ms.ms())),
                    Assessment::NotAssessed => Duration::ZERO,
                };
                self.event(Event::SessionOpened { session, transit });
            }
            Routed::Claim { id, sync } => self.claim(id.get(), sync),
            Routed::Announce { id, payload } => self.announce(id.get(), &payload),
            Routed::Message {
                id,
                command,
                payload,
            } => self.message(id.get(), command, payload),
            Routed::Finished { id } => {
                let session = id.get();
                match self.serving.get_mut(&session) {
                    Some(serving) if serving.busy || !serving.queue.is_empty() => {
                        serving.finishes = serving.finishes.saturating_add(1);
                    }
                    _ => self.hub.delivery_finished(id, true),
                }
            }
            Routed::Closed { id } => {
                let session = id.get();
                self.connectors.remove(&session);
                self.serving.remove(&session);
                self.door.session_closed(SessionId(session));
                self.event(Event::SessionClosed { session });
            }
        }
    }

    fn message(&mut self, session: u64, command: SyncCommand, payload: Vec<u8>) {
        match command {
            SyncCommand::ResponseHeaders => {
                tracing::trace!(session, bytes = payload.len(), "a header response");
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
                    tracing::debug!(session, %err, "a header request that does not decode");
                    self.close(session);
                }
            },
            SyncCommand::RequestBodies => match RequestBodies::decode(&payload) {
                Ok(request) => self.queue_serve(session, ServeRequest::Bodies(request)),
                Err(err) => {
                    tracing::debug!(session, %err, "a body request that does not decode");
                    self.close(session);
                }
            },
        }
    }

    fn queue_serve(&mut self, session: u64, request: ServeRequest) {
        let serving = self.serving.entry(session).or_default();
        serving.queue.push_back(request);
        self.serve_next(session);
    }

    fn serve_next(&mut self, session: u64) {
        let Some(serving) = self.serving.get_mut(&session) else {
            return;
        };
        if serving.busy {
            return;
        }
        let Some(request) = serving.queue.pop_front() else {
            let finishes = std::mem::take(&mut serving.finishes);
            if let Some(id) = SocketId::from_ffi(session) {
                for _ in 0..finishes {
                    self.hub.delivery_finished(id, true);
                }
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
                let session = offered.map(|(session, _)| session);
                let solicited = !offered.is_some_and(|(_, announced)| announced);
                tracing::trace!(tag, ?session, ?reply, "an entry reply");
                match outcome_of(reply, solicited) {
                    Some(outcome) => self.event(Event::Entry { tag, outcome }),
                    None => tracing::error!(tag, ?session, "an entry reply with no outcome"),
                }
                self.room();
            }
            Input::Served { session, bytes } => {
                if let Some(serving) = self.serving.get_mut(&session) {
                    serving.busy = false;
                }
                if let (Some(bytes), Some(id)) = (bytes, SocketId::from_ffi(session)) {
                    // A refused send is the transport's close, not sync's.
                    let _sent = self.hub.send(id, bytes);
                }
                self.serve_next(session);
            }
        }
    }

    /// An announced block (2008): the block, the transactions it
    /// carried, and its witness. A payload that does not decode, or a
    /// pruned entry, is the sender's form failure.
    fn announce(&mut self, session: u64, payload: &[u8]) {
        let announced = match NewCompactBlock::load(payload) {
            Ok(announced) if !announced.b.pruned => announced,
            Ok(_) => {
                tracing::debug!(session, "a pruned announcement");
                self.close(session);
                return;
            }
            Err(err) => {
                tracing::debug!(session, %err, "an announcement that does not decode");
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

    /// Relay a connected announcement the way the C++ `relay_block` does
    /// (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q10, until RD's relay entry lands):
    /// the block with its witness and no transactions, as 2008, to every
    /// established session but the one that announced it.
    fn relay(&mut self, hash: shekyl_types::BlockHash, from: u64) {
        let compact = match self.compact_block(hash) {
            Ok(Some(compact)) => compact,
            Ok(None) => {
                tracing::debug!(?hash, "a relayed block is no longer on the main chain");
                return;
            }
            Err(err) => {
                tracing::error!(%err, "the store could not be read: the relay is dropped");
                return;
            }
        };
        let bytes = match compact.store() {
            Ok(payload) => notify(NOTIFY_NEW_COMPACT_BLOCK, &payload),
            Err(err) => {
                tracing::error!(%err, "a relayed block did not encode");
                return;
            }
        };
        for row in self.hub.board().rows() {
            if row.established() && row.id().get() != from {
                // A refused send is the transport's close, not sync's.
                let _sent = self.hub.send(row.id(), bytes.clone());
            }
        }
    }

    /// The main chain's block `hash` as a compact block: no transactions.
    fn compact_block(
        &self,
        hash: shekyl_types::BlockHash,
    ) -> Result<Option<NewCompactBlock>, shekyl_chain_store::store::StoreError> {
        let snap = self.store.begin_read()?;
        let Some(height) = snap.height_of(&hash)? else {
            return Ok(None);
        };
        let shekyl_chain_rules::AtHeight::Recorded(body) = snap.block(height)? else {
            return Ok(None);
        };
        let attestation_witness = match snap.attestation_witness_at(height)? {
            shekyl_chain_rules::AtHeight::Recorded(Some(witness)) => witness,
            _ => Vec::new(),
        };
        let count = snap
            .tip()?
            .recorded
            .map_or(0, |tip| tip.height.to_raw().saturating_add(1));
        Ok(Some(NewCompactBlock {
            b: BlockCompleteEntry {
                pruned: false,
                block: body.block.serialize(),
                block_weight: 0,
                txs: Vec::new(),
                attestation_witness,
            },
            current_blockchain_height: count,
        }))
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

    fn close(&mut self, session: u64) {
        if let Some(id) = SocketId::from_ffi(session) {
            self.hub.close(id);
        }
    }

    fn arm(&mut self, deadline: Instant, session: u64, request: u64) {
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

    fn send(&mut self, session: u64, bytes: Vec<u8>) {
        if let Some(id) = SocketId::from_ffi(session) {
            // A refused send is the transport's close, not sync's.
            let _sent = self.hub.send(id, bytes);
        }
    }

    fn commands(&mut self, out: Vec<Command<u64>>) {
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
                            session,
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
                    tracing::debug!(session, ?cause, "chain sync closes a session");
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
    fn offer(&mut self, arrivals: Vec<BoundArrival<u64>>) {
        if arrivals.is_empty() {
            return;
        }
        let announced: Vec<bool> = arrivals.iter().map(|arrival| arrival.announced).collect();
        let span: Vec<EntryArrival> = arrivals
            .into_iter()
            .map(|arrival| EntryArrival {
                tag: ArrivalTag(arrival.tag),
                session: SessionId(arrival.session),
                judged: arrival.header,
                block: arrival.body.block,
                bodies: arrival
                    .body
                    .txs
                    .into_iter()
                    .filter_map(|tx| match tx {
                        TxBody::Full(bytes) => Some(bytes),
                        TxBody::Skeleton(_) => None,
                    })
                    .collect(),
                attestation_witness: arrival.body.attestation_witness,
            })
            .collect();
        // The door's own measure, so an arrival it would admit is never
        // called oversize here.
        let tags: Vec<(u64, u64, usize)> = span
            .iter()
            .map(|arrival| (arrival.tag.0, arrival.session.0, arrival.bytes()))
            .collect();
        match self.door.offer_bound(span) {
            Ok(tickets) => {
                for ((tag, session, _), announced) in tags.iter().zip(&announced) {
                    self.offered.insert(*tag, (*session, *announced));
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
            }
            Err(refusal) => {
                let max = self
                    .door
                    .max_arrival_bytes()
                    .and_then(|max| usize::try_from(max).ok());
                for ((tag, _, bytes), announced) in tags.into_iter().zip(announced) {
                    let outcome = match refusal {
                        Refusal::NoRoom | Refusal::Throttled => Outcome::NoRoom,
                        Refusal::Oversize if max.is_some_and(|max| bytes > max) => {
                            Outcome::Oversize {
                                invalidate: !announced,
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

/// The entry's reply as the model's outcome (`Outcome::from_reply`).
/// `solicited` is false for a body that came as an announcement.
fn outcome_of(reply: Reply, solicited: bool) -> Option<Outcome> {
    let null = shekyl_types::BlockHash::NULL;
    let (sync, at, block, indices, verdict): (_, _, _, _, Option<InvalidBlock>) = match reply {
        Reply::Connected { .. } => (SyncReply::Connected, null, null, Vec::new(), None),
        Reply::Refused(verdict) => (SyncReply::Refused, null, null, Vec::new(), Some(verdict)),
        Reply::Unlinked { at } => (SyncReply::Unlinked, at, null, Vec::new(), None),
        Reply::AlreadyHeld => (SyncReply::AlreadyHeld, null, null, Vec::new(), None),
        Reply::Held { .. } => (SyncReply::Held, null, null, Vec::new(), None),
        Reply::BeyondCap(_) => (SyncReply::BeyondCap, null, null, Vec::new(), None),
        Reply::Switched { .. } => (SyncReply::Switched, null, null, Vec::new(), None),
        Reply::PromotionRefused { hash, refused, .. } => (
            SyncReply::PromotionRefused,
            null,
            hash,
            Vec::new(),
            Some(refused),
        ),
        Reply::CannotFollow(_) => (SyncReply::CannotFollow, null, null, Vec::new(), None),
        Reply::MissingBodies { indices } => (
            SyncReply::MissingBodies,
            null,
            null,
            indices
                .into_iter()
                .map(|index| u64::try_from(index).unwrap_or(u64::MAX))
                .collect(),
            None,
        ),
        Reply::Cancelled { .. } => (SyncReply::Cancelled, null, null, Vec::new(), None),
        Reply::Stopped => (SyncReply::Stopped, null, null, Vec::new(), None),
    };
    Outcome::from_reply(sync, solicited, at, block, indices, verdict)
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;

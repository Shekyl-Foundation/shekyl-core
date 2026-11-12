// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sync owner (CS-3 §4.3): one task on its own runtime row, named
//! `chain-sync`, holding the one [`Model`]. Nothing else holds it.
//!
//! The owner turns what the session layer ([`crate::port`]), the executor,
//! the entry's tickets, the tip watch, the latch and the timing engine
//! report into [`Event`]s, hands each to the model with a fresh store
//! snapshot as `main`, and runs the commands that come out, in order.
//!
//! - **Sessions** are `Session`s. [`SocketId`] does not order itself, and
//!   the model's maps need an order. `Session` orders by the admission
//!   number, and that order carries no meaning: draws are uniform over the
//!   set. The entry's [`SessionId`] is that number, and only at the door.
//!   The owner reaches a session through the [`Established`] the layer
//!   handed it, which it keeps until the layer reports the close: only an
//!   established session is ever sent to, by type (brief §2 rule 2).
//! - **`now`** is the timing engine's clock as an [`Instant`]. Deadlines
//!   go to the engine as ticks on that same clock, and come back as
//!   [`Event::Deadline`]. The engine holds one deadline per owner, so the
//!   owner arms the earliest of its own and keeps the rest.
//! - **The wall** is the substrate's clock, read once per event.
//! - **Serving** a request reads the store on a blocking thread. The
//!   request's [`Taken`] is held until the answer is sent, so a session
//!   has at most one request being served, and its next frame waits in
//!   the transport and not in this task (brief §7.7: one message
//!   outstanding per session). The permit bounds what waits. It does not
//!   schedule this task.
//! - **Turns.** Stop comes first. Then a proof, an entry reply, or a
//!   served response, then the tip and the latch, then one peer message.
//!   Peer bytes do not sit ahead of work this node has already finished.
//!   A deadline does not pass peer messages already queued, because one
//!   of them may be the response it would abandon (`on_headers` closes a
//!   session whose request the deadline already cleared). When the clock
//!   fires, those messages are taken and then the deadline runs.
//! - **Claims** arrive decoded: the session layer reads the handshake and
//!   the timed sync in both directions and hands the peer's sync payload
//!   here ([`Inbound::Claim`]). There is no claim tap.
//! - **Announcements** (2008, `NOTIFY_NEW_COMPACT_BLOCK`) are the model's
//!   [`Event::Announce`]. `RequestMissingTxs` is sent as our own 2009, and
//!   a peer's 2009 is served from the store like a header or body request
//!   ([`crate::serve::serve_missing_txs`]): its faults close the session.
//! - **Relay** is the model's decision ([`Command::Relay`]): a block that
//!   connected as the new tip while this node, with it, is not `Behind`,
//!   however it arrived. The owner builds that compact announcement (the
//!   block and its bundle references, no transactions) and sends it as 2008 to every
//!   established session but the one that supplied it. A block no session
//!   supplied, such as one this node mined, goes to every established
//!   session.
//! - **Bundles** (2015–2017, [`crate::bundles`]) travel between queues. A
//!   peer's 2015 whose body is its reference's goes to the queue's
//!   admission through the door, off this task, with its permit held to
//!   the verdict; a bundle the queue admitted goes on as 2015 to every
//!   established session but its supplier. A bundle this node filed
//!   arrives on the door's feed and goes to every established session. A
//!   2016 is served from the body store like any other request. When the
//!   model asks for a block's bundle bodies (`RequestBundleBodies`), what
//!   the body store holds goes back at once and the rest is asked of the
//!   sender as 2016; its 2017 answers the oldest ask to that session and
//!   is accepted body by body, and a 2017 nothing asked for closes it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_chain_ingest::connector::{BundleOffered, FiledBundle};
use shekyl_chain_ingest::service::{
    Alarm, ArrivalTag, BoundArrival as EntryArrival, Door, Reply, SessionId, SlotPair,
};
use shekyl_chain_ingest::{ChainRules, TipChanged};
use shekyl_chain_rules::Tip;
use shekyl_chain_store::codec::FollowingDegraded;
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::{
    CoreSyncData, GetTxpoolComplement, NewCompactBlock, PortableMap, RequestBodies,
    RequestBundleBodies, RequestCompactMissingTx, RequestHeaders, HASH_SIZE,
};
use shekyl_p2p_session::{
    ClaimCarrier, CloseCause, CloseKind, Encoded, Established, Message, SocketId, SyncInbound,
    Taken,
};
use shekyl_runtime::{Pool, RuntimeBudget, ThreadName};
use shekyl_timing_engine::{Clock, OwnerHandle, Tick};
use shekyl_transport_layer::{declaration, Assessment};
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{BlockBody, TxBody};
use tokio::sync::{mpsc, watch};
use tracing::Instrument;

use crate::bundles::{relay_message, relayed, serve_bundle_bodies};
use crate::executor::Executor;
use crate::outcome;
use crate::port::Inbound;
use crate::relay;
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
    /// The session layer's calls, as [`crate::port::port`] hands them over.
    /// The port precedes every session, so no session's messages are lost
    /// before this task runs. The sender gone is the port dropped: the
    /// session layer is gone, and the owner ends.
    pub inbound: mpsc::UnboundedReceiver<Inbound>,
    /// Where the derived sync state is published (CS-Q2 step 8), which the
    /// RPC's facts, the miner's follower and the relay gate read. The owner
    /// is its only publisher: the node hands this sender over and keeps a
    /// receiver. [`spawn`] publishes the declaration's state at open
    /// before it returns. Every exit publishes [`SyncState::NoView`] and
    /// drops the sender, so the watch closes on that state.
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
    /// A test asks the task to publish. Production has no sender: the
    /// task publishes only what the model derives. `cfg(test)` does not
    /// cross into `shekyl-node`'s tests, so that crate enables
    /// `publish-for-test` from its dev-dependency edge.
    #[cfg(any(test, feature = "publish-for-test"))]
    publish_tx: mpsc::UnboundedSender<SyncState>,
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
    /// `sync_status` renders. A session is named by its admission id.
    #[must_use]
    pub fn view(&self) -> watch::Receiver<SyncView<SocketId>> {
        self.view.clone()
    }

    /// Ask the task to stop, without joining it.
    ///
    /// The session layer may close in the same breath. The task, and the
    /// guard that reports its end, read this first, so that close is a
    /// stop.
    pub fn request_stop(&self) {
        self.stop_tx.send_replace(true);
    }

    /// Ask the task to publish `state`. The task is the only publisher.
    ///
    /// A test sets the state the follower reads before any session
    /// exists. A send after the task has ended is ignored.
    #[cfg(any(test, feature = "publish-for-test"))]
    pub fn publish_for_test(&self, state: SyncState) {
        let _gone = self.publish_tx.send(state);
    }

    /// Stop the owner and wait at most `timeout` for its blocking work.
    /// Call it from outside the owner's pool.
    pub fn stop(self, timeout: Duration) {
        self.executor.stop();
        self.request_stop();
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
    let (alarm_tx, alarm) = watch::channel(false);
    let (view_tx, view) = watch::channel(SyncView::empty());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (ended_tx, ended) = watch::channel(None);
    #[cfg(any(test, feature = "publish-for-test"))]
    let (publish_tx, publish_rx) = mpsc::unbounded_channel();
    let executor = Arc::clone(&parts.executor);
    // The owner's log lines carry the span it was started in.
    let published = Published { alarm_tx, view_tx };
    pool.spawn(
        run(
            parts,
            published,
            stop_rx,
            ended_tx,
            #[cfg(any(test, feature = "publish-for-test"))]
            publish_rx,
        )
        .instrument(tracing::Span::current()),
    );
    Ok(Running {
        pool,
        executor,
        stop_tx,
        state,
        alarm,
        view,
        ended,
        #[cfg(any(test, feature = "publish-for-test"))]
        publish_tx,
    })
}

/// How the owner's task ended ([`Running::ended`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// [`Running::stop`] asked it to, or [`Running::request_stop`] did
    /// before the session layer closed under it.
    Stopped,
    /// It ended on its own. A daemon whose owner ends this way never
    /// syncs again, so the daemon stops with [`EndCause::text`].
    Failed(EndCause),
}

/// Why the owner's task ended on its own.
///
/// The daemon's stop latch records the variant. Callers match it;
/// [`Self::text`] is the prose the daemon's error line quotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndCause {
    /// The task unwound before an exit set a cause.
    Panicked,
    /// The port's sender went: the session layer dropped the owner.
    PortClosed,
    /// The process timing engine went.
    EngineClosed,
    /// The connector's tip watch closed.
    TipWatchClosed,
    /// The latch watch closed.
    LatchWatchClosed,
    /// The seed watch closed.
    SeedWatchClosed,
}

impl EndCause {
    /// The prose of this cause. The daemon's error line quotes it.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Panicked => "the sync owner's task panicked",
            Self::PortClosed => "the session layer dropped the sync owner",
            Self::EngineClosed => "the timing engine closed",
            Self::TipWatchClosed => "the connector's tip watch closed",
            Self::LatchWatchClosed => "the latch watch closed",
            Self::SeedWatchClosed => "the seed watch closed",
        }
    }
}

impl std::fmt::Display for EndCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.text())
    }
}

/// Reports the owner task's end, however it ends: a stop, a closed input
/// and a panic alike.
///
/// Every exit publishes [`SyncState::NoView`] and then drops this sender.
/// Facts and the follower read a closed watch as `NoView`; a reader that
/// only borrows sees the publish. The task holds the last sender, so the
/// watch closes when the guard drops. It always sends [`Ended`] on
/// [`Running::ended`]: each exit sets `how` first, and an unwind leaves
/// [`EndCause::Panicked`]. Once a stop was asked, the end is
/// [`Ended::Stopped`] whatever `how` says: [`Running::stop`] shuts the
/// owner's runtime down, which can cancel the task before it reads the
/// request, and the session layer can close before the task polls.
struct EndGuard {
    state: watch::Sender<SyncState>,
    ended: watch::Sender<Option<Ended>>,
    stop: watch::Receiver<bool>,
    how: Ended,
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        self.state.send_replace(SyncState::NoView);
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
    /// The queue's verdict on a bundle a session relayed, with the 2015
    /// that relays it on when it was queued.
    BundleOffered {
        session: Session,
        h: BlockHeight,
        offered: Result<BundleOffered, String>,
        relay: Option<Encoded>,
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
    BundleBodies(RequestBundleBodies),
}

/// Frame an answer on the serving thread, so the owner's task sends it
/// without encoding.
fn encode(message: &Message) -> Result<Encoded, String> {
    message.encode().map_err(|err| err.to_string())
}

/// What serving one request came to.
enum Served {
    /// The answer, framed.
    Send(Encoded),
    /// Nothing is sent: the store could not answer, or the block left the
    /// main chain after it was announced.
    Nothing,
    /// The request was the peer's fault: the session closes.
    Close(MissingTxsRefused),
}

/// What the owner keeps beside the model.
struct Owner<C: Clock + Clone, R> {
    sync: Model<Session, Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet + Send>>,
    store: Arc<ChainStore>,
    door: Door,
    alarm: Alarm,
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
    /// The request each session has being served, as the permit the
    /// session layer handed it with. Dropped when the answer is sent,
    /// which is when the session reads its next frame (module docs).
    serving: HashMap<Session, Taken>,
    /// Header and body requests in flight, and seat waits. Records the
    /// profile is timed from. Nothing the owner decides reads them.
    transit: Transit,
    /// The established sessions, as the session layer handed them. The
    /// owner sends to these and no other: there is no handle to a session
    /// whose handshake has not completed.
    sessions: BTreeMap<Session, Established>,
    seats: Option<usize>,
    /// The seeds the slots hold, read when a proof found a seed absent
    /// (`Command::SeedNotHeld`). The loop waits on its own receiver of
    /// the same watch.
    seeds: watch::Receiver<Option<SlotPair>>,
    /// The pair the model was last told of. It hears `Event::Seeds` when
    /// that pair differs: an epoch edge, or a seed a run or a branch
    /// prepared that the window does not name.
    seen_seeds: Option<SlotPair>,
    state_tx: watch::Sender<SyncState>,
    published: Published,
    /// The 2016s each session has been sent and not yet answered, oldest
    /// first: the block each asks for and the references it names. A
    /// session answers in the order it was asked, so a 2017 answers the
    /// first.
    bundle_asks: HashMap<Session, VecDeque<BundleAsk>>,
}

/// One 2016 this owner sent: the block whose section names the bodies, and
/// the references it asked for, opened.
struct BundleAsk {
    block: BlockHash,
    references: Vec<shekyl_archival_retention::BundleRef>,
}

/// The owner's `select`. Tokio 1.51 does not take `#[cfg]` on an arm, and
/// a closed receiver would be ready at once and spin. The test arm is
/// therefore chosen here, outside `select`: production waits on the real
/// inputs only. Stop stays first under `biased`.
#[cfg(any(test, feature = "publish-for-test"))]
macro_rules! owner_select {
    ($publish_rx:ident, $state:ident, $on_state:block, $($rest:tt)*) => {
        tokio::select! {
            biased;
            $($rest)*
            Some($state) = $publish_rx.recv() => $on_state,
        }
    };
}

#[cfg(not(any(test, feature = "publish-for-test")))]
macro_rules! owner_select {
    ($publish_rx:ident, $state:ident, $on_state:block, $($rest:tt)*) => {
        tokio::select! {
            biased;
            $($rest)*
        }
    };
}

async fn run<C, R>(
    parts: OwnerParts<C, R>,
    published: Published,
    mut stop: watch::Receiver<bool>,
    ended: watch::Sender<Option<Ended>>,
    #[cfg(any(test, feature = "publish-for-test"))] mut publish_rx: mpsc::UnboundedReceiver<
        SyncState,
    >,
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
        executor,
        timer,
        rules,
        requesting,
        declaration,
        rng,
        pool_hashes,
        mut inbound,
        state: state_tx,
    } = parts;
    // Dropped with the task: every exit below sets `how` first.
    let mut end = EndGuard {
        state: state_tx.clone(),
        ended,
        stop: stop.clone(),
        how: Ended::Failed(EndCause::Panicked),
    };
    let (inputs, mut input_rx) = mpsc::unbounded_channel();
    let schedule: Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet + Send> =
        Box::new(move |height| rules.in_force(height));
    let base = (Instant::now(), timer.clock().now());
    let timer = Arc::new(timer);
    let wakes = Arc::clone(&timer);
    let mut seeds = door.seeds();
    let seen_seeds = *seeds.borrow_and_update();
    let mut filed = Some(door.filed());
    let mut owner = Owner {
        sync: Model::new(rules.trust(), schedule)
            .with_requesting(requesting)
            .with_declaration(declaration),
        store,
        door,
        alarm,
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
        sessions: BTreeMap::new(),
        seats: None,
        seeds: seeds.clone(),
        seen_seeds,
        state_tx,
        published,
        bundle_asks: HashMap::new(),
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
        owner_select!(
            publish_rx,
            state,
            {
                owner.state_tx.send_replace(state);
            },
            _ = stop.wait_for(|asked| *asked) => {
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
                    end.how = Ended::Failed(EndCause::TipWatchClosed);
                    break;
                }
                let tip = *tips.borrow_and_update();
                owner.tip(&tip);
            },
            changed = latch.changed() => {
                if changed.is_err() {
                    end.how = Ended::Failed(EndCause::LatchWatchClosed);
                    break;
                }
                let set = latch.borrow_and_update().is_some();
                owner.latch(set);
            },
            changed = seeds.changed() => {
                if changed.is_err() {
                    end.how = Ended::Failed(EndCause::SeedWatchClosed);
                    break;
                }
                let pair = *seeds.borrow_and_update();
                owner.seeds_published(pair);
            },
            bundle = next_filed(&mut filed), if filed.is_some() => {
                if let Some(bundle) = bundle {
                    owner.relay_filed(&bundle);
                }
            },
            inbound_one = inbound.recv() => {
                let Some(inbound_one) = inbound_one else {
                    end.how = Ended::Failed(EndCause::PortClosed);
                    break;
                };
                owner.inbound(inbound_one);
                // Messages already queued were sent before this wake was
                // observed. Take them before the deadline, so a response
                // in hand is applied before its request is cleared.
                match clock_ready(&wakes) {
                    Some(false) => {}
                    Some(true) => {
                        let pending = inbound.len();
                        let mut closed = false;
                        for _ in 0..pending {
                            match inbound.try_recv() {
                                Ok(inbound_one) => owner.inbound(inbound_one),
                                Err(mpsc::error::TryRecvError::Empty) => break,
                                Err(mpsc::error::TryRecvError::Disconnected) => {
                                    closed = true;
                                    break;
                                }
                            }
                            pump_local(&mut owner, &mut input_rx, &mut tips, &mut latch);
                        }
                        if closed {
                            end.how = Ended::Failed(EndCause::PortClosed);
                            break;
                        }
                        owner.deadlines_due();
                    }
                    None => {
                        end.how = Ended::Failed(EndCause::EngineClosed);
                        break;
                    }
                }
            },
            wake = wakes.wait_wake_async() => match wake {
                Ok(_) => owner.deadlines_due(),
                Err(err) => {
                    tracing::info!(?err, "the timing engine closed: chain sync stops");
                    end.how = Ended::Failed(EndCause::EngineClosed);
                    break;
                }
            },
        );
    }
    let _gone = owner.timer.deregister();
}

/// The next bundle this node filed. A receiver that fell behind skips the
/// bundles it missed and says how many; a feed whose sender is gone is
/// the service stopping, and is not read again.
async fn next_filed(
    filed: &mut Option<tokio::sync::broadcast::Receiver<FiledBundle>>,
) -> Option<FiledBundle> {
    let receiver = filed.as_mut()?;
    match receiver.recv().await {
        Ok(bundle) => Some(bundle),
        Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
            tracing::warn!(missed, "the relay fell behind the bundles this node filed");
            None
        }
        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
            *filed = None;
            None
        }
    }
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

    /// A refused latch write, without a store snapshot. See
    /// [`Model::alarm_refused`].
    fn alarm_refused(&mut self) {
        let mut out = Vec::new();
        self.sync.alarm_refused(self.now(), &mut out);
        self.commands(out);
    }

    /// The retry of a refused latch write, without a store snapshot. See
    /// [`Model::alarm_retry`].
    fn alarm_retry(&mut self) {
        let mut out = Vec::new();
        self.sync.alarm_retry(&mut out);
        self.commands(out);
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

    /// A peer's sync payload, from either direction of the handshake or
    /// the timed sync: the session's claim.
    fn claim(&mut self, session: Session, sync: &CoreSyncData, carrier: ClaimCarrier) {
        tracing::trace!(%session, ?carrier, height = sync.current_height, "a claim");
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

    /// A session the layer established. The first `Inbound` of a session
    /// is its `Established`; a message or a claim that arrives for one not
    /// yet held is still an established session, by type, and is admitted
    /// the same way.
    fn opened(&mut self, established: &Established) -> Session {
        let session = Session::new(established.id());
        if self.sessions.contains_key(&session) {
            return session;
        }
        let transit = match declaration(established.connector().column()).transit_ms() {
            Assessment::Assessed(ms) => Duration::from_millis(u64::from(ms.ms())),
            Assessment::NotAssessed => Duration::ZERO,
        };
        self.sessions.insert(session, established.clone());
        self.event(Event::SessionOpened { session, transit });
        session
    }

    fn inbound(&mut self, inbound: Inbound) {
        match inbound {
            Inbound::Established(established) => {
                self.opened(&established);
            }
            Inbound::Claim {
                session,
                sync,
                carrier,
                taken,
            } => {
                let session = self.opened(&session);
                self.claim(session, &sync, carrier);
                drop(taken);
            }
            Inbound::Message {
                session,
                message,
                taken,
            } => {
                let session = self.opened(&session);
                self.message(session, message, taken);
            }
            Inbound::Closed(facts) => {
                let session = Session::new(facts.id);
                if self.sessions.remove(&session).is_none() {
                    // Closed before it was established: never this owner's.
                    return;
                }
                self.transit.forget_session(session);
                self.serving.remove(&session);
                self.bundle_asks.remove(&session);
                self.door.session_closed(SessionId(session.socket().get()));
                self.event(Event::SessionClosed { session });
            }
        }
    }

    /// One of the owner's nine commands. A response goes to the model
    /// now, and `taken` drops with it; a request is served, and `taken`
    /// is held until the answer is sent. A relayed bundle is held to the
    /// queue's verdict the same way.
    fn message(&mut self, session: Session, message: SyncInbound, taken: Taken) {
        match message {
            SyncInbound::NewCompactBlock(payload) => {
                self.announce(session, &payload);
                drop(taken);
            }
            SyncInbound::RequestCompactMissingTx(payload) => {
                match RequestCompactMissingTx::load(&payload) {
                    Ok(request) => self.serve(session, ServeRequest::MissingTxs(request), taken),
                    Err(err) => {
                        tracing::debug!(%session, %err, "a missing-tx request that does not decode");
                        self.close(session);
                    }
                }
            }
            SyncInbound::ResponseHeaders(payload) => {
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
                drop(taken);
            }
            SyncInbound::ResponseBodies(payload) => {
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
                drop(taken);
            }
            SyncInbound::RequestHeaders(payload) => match RequestHeaders::decode(&payload) {
                Ok(request) => self.serve(session, ServeRequest::Headers(request), taken),
                Err(err) => {
                    tracing::debug!(%session, %err, "a header request that does not decode");
                    self.close(session);
                }
            },
            SyncInbound::RequestBodies(payload) => match RequestBodies::decode(&payload) {
                Ok(request) => self.serve(session, ServeRequest::Bodies(request), taken),
                Err(err) => {
                    tracing::debug!(%session, %err, "a body request that does not decode");
                    self.close(session);
                }
            },
            SyncInbound::NewBundle(payload) => self.bundle_relayed(session, &payload, taken),
            SyncInbound::RequestBundleBodies(payload) => {
                match RequestBundleBodies::load(&payload) {
                    Ok(request) => {
                        self.serve(session, ServeRequest::BundleBodies(request), taken);
                    }
                    Err(err) => {
                        tracing::debug!(%session, %err, "a bundle body request that does not decode");
                        self.close(session);
                    }
                }
            }
            SyncInbound::ResponseBundleBodies(payload) => {
                drop(taken);
                self.bundle_bodies_answered(session, &payload);
            }
        }
    }

    /// A bundle a session relayed (2015): its body must be the one its
    /// reference names, or the session closes. The queue judges the rest,
    /// against this node's tip, off this task; `taken` is held until it
    /// answers, so a session has one bundle being judged at a time.
    fn bundle_relayed(&mut self, session: Session, payload: &[u8], taken: Taken) {
        let (reference, body) = match relayed(payload) {
            Ok(bundle) => bundle,
            Err(refused) => {
                tracing::debug!(%session, ?refused, "a relayed bundle that does not hold");
                drop(taken);
                self.close(session);
                return;
            }
        };
        let door = self.door.clone();
        let inputs = self.inputs.clone();
        let h = reference.h();
        tokio::spawn(async move {
            // Encoded before the offer takes the two: sent only if queued.
            let relay = encode(&relay_message(&reference, &body)).ok();
            let offered = door
                .offer_bundle(reference, body)
                .await
                .map_err(|fault| fault.to_string());
            let _gone = inputs.send(Input::BundleOffered {
                session,
                h,
                offered,
                relay,
            });
            drop(taken);
        });
    }

    /// A block's section names bodies its sender did not send (the model's
    /// `RequestBundleBodies`). What this node's body store holds is
    /// returned, for the model after the batch, with whether the rest was
    /// asked of `session` (2016, one block per request). The model reads
    /// the store's part as the store's, never as the session's answer, and
    /// counts the ask until that answer or until no 2016 went out.
    ///
    /// **The asks a session may leave unanswered are bounded**, at the
    /// model's own per-session bound ([`shekyl_chain_sync::AWAITING_PER_SESSION`]).
    /// A session answers every 2016, if only with nothing (`SCS-P27`), and
    /// the transport keeps its answers in order, so matching a 2017 to the
    /// oldest ask is sound. The model counts each ask until this owner
    /// matches its 2017, whether or not the block still waits, so it asks a
    /// session past the bound only after one of its asks has gone
    /// unanswered for [`shekyl_chain_sync::AWAITING_AGE`]. A session that
    /// already has that many asks unanswered is then not keeping up its
    /// side and is closed; dropping one ask instead would match its next
    /// answer to the wrong block. Over every session the asks are at most
    /// that bound times the sessions open.
    fn ask_bundle_bodies(
        &mut self,
        session: Session,
        block: BlockHash,
        references: &[Vec<u8>],
    ) -> Option<Event<Session>> {
        let mut held = Vec::new();
        let mut rest = Vec::new();
        let snapshot = self.store.begin_read();
        for (position, bytes) in references.iter().enumerate() {
            let Ok(reference) = shekyl_chain_rules::open_reference(position, bytes) else {
                continue;
            };
            let stored = snapshot
                .as_ref()
                .ok()
                .and_then(|snap| snap.bundle_body(reference.prunable_hash()).ok().flatten());
            match stored {
                Some(body) => held.push(body.as_bytes().to_vec()),
                None => rest.push(reference),
            }
        }
        drop(snapshot);
        let asked = !rest.is_empty() && self.send_bundle_ask(session, block, rest);
        // Asked with nothing held, the session's 2017 is all the model
        // hears of this command.
        if asked && held.is_empty() {
            return None;
        }
        Some(Event::HeldBundleBodies {
            session,
            block,
            bodies: held,
            asked,
        })
    }

    /// Send `session` a 2016 for `references`, `block`'s bodies the store
    /// does not hold, and queue it for its 2017. `false` when no 2016 went
    /// out: the session is gone, or is closed at the bound
    /// ([`Self::ask_bundle_bodies`]).
    fn send_bundle_ask(
        &mut self,
        session: Session,
        block: BlockHash,
        references: Vec<shekyl_archival_retention::BundleRef>,
    ) -> bool {
        if !self.sessions.contains_key(&session) {
            return false;
        }
        let outstanding = self.bundle_asks.get(&session).map_or(0, VecDeque::len);
        if outstanding >= shekyl_chain_sync::AWAITING_PER_SESSION {
            tracing::debug!(%session, outstanding, "a session left its bundle body requests unanswered");
            self.close(session);
            return false;
        }
        let request = RequestBundleBodies {
            hashes: references
                .iter()
                .map(|reference| *reference.prunable_hash())
                .collect(),
        };
        self.send(session, &Message::RequestBundleBodies(request));
        self.bundle_asks
            .entry(session)
            .or_default()
            .push_back(BundleAsk { block, references });
        true
    }

    /// A session's 2017. It answers the oldest 2016 this owner sent it; a
    /// 2017 with none outstanding is the sender's fault and closes the
    /// session, as does one that is not an answer to the references asked
    /// (`accept_bundle_bodies`). The bodies it carries go to the model,
    /// which decides what an empty answer means.
    fn bundle_bodies_answered(&mut self, session: Session, payload: &[u8]) {
        let Some(ask) = self
            .bundle_asks
            .get_mut(&session)
            .and_then(VecDeque::pop_front)
        else {
            tracing::debug!(%session, "a bundle body response nothing asked for");
            self.close(session);
            return;
        };
        let accepted = shekyl_levin::ResponseBundleBodies::load(payload)
            .map_err(|err| err.to_string())
            .and_then(|response| {
                crate::bundles::accept_bundle_bodies(&ask.references, &response)
                    .map_err(|refused| format!("{refused:?}"))
            });
        match accepted {
            Ok(bodies) => self.event(Event::BundleBodies {
                session,
                block: ask.block,
                bodies: bodies
                    .into_iter()
                    .map(|(_, body)| body.as_bytes().to_vec())
                    .collect(),
            }),
            Err(why) => {
                tracing::debug!(%session, %why, "a bundle body response that is not an answer");
                self.close(session);
            }
        }
    }

    /// Relay a bundle this node filed (2015) to every established session.
    fn relay_filed(&mut self, filed: &FiledBundle) {
        match encode(&relay_message(&filed.reference, &filed.body)) {
            Ok(encoded) => relay::fan_out(self.sessions.iter(), None, &encoded),
            Err(err) => tracing::error!(%err, "a filed bundle did not encode"),
        }
    }

    /// Serve `request` on a blocking thread. `taken` is held until the
    /// answer is sent ([`Input::Served`]), so the session's next frame
    /// waits in the transport (module docs). A request arriving while one
    /// is held cannot happen under the layer's one-permit bound; were it
    /// to, the earlier permit drops here and the later request is served.
    fn serve(&mut self, session: Session, request: ServeRequest, taken: Taken) {
        if self.serving.insert(session, taken).is_some() {
            tracing::debug!(%session, "a request arrived while one was being served");
        }
        let store = Arc::clone(&self.store);
        let inputs = self.inputs.clone();
        tokio::task::spawn_blocking(move || {
            let served = match request {
                ServeRequest::Headers(request) => serve_headers(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| encode(&Message::ResponseHeaders(response)))
                    .map(Served::Send),
                ServeRequest::Bodies(request) => serve_bodies(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| encode(&Message::ResponseBodies(response)))
                    .map(Served::Send),
                ServeRequest::BundleBodies(request) => serve_bundle_bodies(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|response| encode(&Message::ResponseBundleBodies(response)))
                    .map(Served::Send),
                ServeRequest::MissingTxs(request) => serve_missing_txs(&store, &request)
                    .map_err(|err| err.to_string())
                    .and_then(|served| match served {
                        MissingTxsServed::Answer(block) => {
                            encode(&Message::NewCompactBlock(block)).map(Served::Send)
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
            // The latch retry does not read the chain. Going through
            // `event` would drop it when the store cannot be read, and
            // `Idle` is the only state that accepts new evidence.
            Input::AlarmRefused => self.alarm_refused(),
            Input::BundleOffered {
                session,
                h,
                offered,
                relay,
            } => match offered {
                // Admitted against this node's tip: on to every other
                // session, as the supplier had it (`SCS-P25`).
                Ok(BundleOffered::Queued { .. }) => {
                    if let Some(encoded) = relay {
                        relay::fan_out(self.sessions.iter(), Some(session), &encoded);
                    }
                }
                // Already held, already revealed, or refused against this
                // node's tip: none of these is the sender's fault, since a
                // tip that differs from ours can admit what ours refuses.
                Ok(other) => {
                    tracing::debug!(%session, h = h.to_raw(), ?other, "a relayed bundle not queued");
                }
                Err(err) => {
                    tracing::error!(%err, h = h.to_raw(), "the queue did not answer a relayed bundle");
                }
            },
            Input::Served { session, served } => {
                match served {
                    // A refused send is the transport's close, not sync's.
                    Served::Send(encoded) => {
                        if let Some(handle) = self.sessions.get(&session) {
                            let _sent = handle.send_encoded(&encoded);
                        }
                    }
                    Served::Nothing => {}
                    Served::Close(refused) => {
                        tracing::debug!(%session, ?refused, "a missing-tx request closes its session");
                        self.close(session);
                    }
                }
                // The answer is sent (or the session closed): the session
                // may read its next frame.
                self.serving.remove(&session);
            }
        }
    }

    /// An announced block (2008): the block, the transactions it
    /// carried, and its bundle references. A payload that does not decode, or a
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
            bundle_references: announced.b.bundle_references,
            bundle_bodies: Vec::new(),
        };
        self.event(Event::Announce { session, body });
    }

    /// Relay a block the model relays (module docs): the block with its
    /// bundle references and no transactions, as 2008, to every established
    /// session but `from`, its supplier. A block no session supplied, such as one
    /// this node mined, goes to every established session.
    fn relay(&mut self, hash: BlockHash, from: Option<Session>) {
        let compact = match relay::announcement(&self.store, &hash) {
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
        // Encoded once, sent to every session.
        let encoded = match Message::NewCompactBlock(compact).encode() {
            Ok(encoded) => encoded,
            Err(err) => {
                tracing::error!(%err, "a relayed block did not encode");
                return;
            }
        };
        relay::fan_out(self.sessions.iter(), from, &encoded);
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

    /// The latch watch's report. Recording it does not read the chain: the
    /// watch is the store's answer. The plan that follows still wants a
    /// snapshot, and waits when that read fails. A dropped report would
    /// leave a write that landed in flight, where nothing retries it.
    fn latch(&mut self, set: bool) {
        let mut out = Vec::new();
        if let Ok(wall) = self.executor.wall() {
            self.sync.set_wall(wall);
        }
        let now = self.now();
        match self.store.begin_read() {
            Ok(snap) => {
                let main = SnapshotView::new(&snap);
                if let Err(err) =
                    self.sync
                        .handle(Event::Latch { set }, &main, now, &mut self.rng, &mut out)
                {
                    tracing::error!(%err, "the store could not be read: the event is dropped");
                }
            }
            Err(err) => {
                tracing::error!(
                    %err,
                    "the store could not be read: the latch is recorded and the plan waits"
                );
                self.sync.latch_reported(set);
            }
        }
        self.commands(out);
        self.published.alarm_tx.send_replace(self.sync.alarm());
    }

    /// The slots published `pair`. The model hears of it when it differs
    /// from the pair it was last told of. The pair moves when the slots do:
    /// at an epoch edge, and when a run or a branch prepares a seed the
    /// window does not name.
    fn seeds_published(&mut self, pair: Option<SlotPair>) {
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

    /// Close `session` for a fault of the peer's. The session layer
    /// records the close and tells every owner; this owner forgets the
    /// session on that call, not here.
    fn close(&mut self, session: Session) {
        if let Some(handle) = self.sessions.get(&session) {
            handle.close(CloseCause::new(CloseKind::LocalClose));
        }
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
                Wake::AlarmRetry => self.alarm_retry(),
            }
        }
        self.rearm();
    }

    fn send(&mut self, session: Session, message: &Message) {
        // A refused send is the transport's close, not sync's.
        if let Some(handle) = self.sessions.get(&session) {
            let _sent = handle.send(message);
        }
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
        // Bundle bodies the store held for a waiting block: told to the
        // model after this batch, as `Event::Seeds` is, so its handling
        // never runs while this batch is being drained.
        let mut held_bodies = Vec::new();
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
                } => {
                    tracing::trace!(
                        %session,
                        id,
                        locator = request.block_ids.len(),
                        "a header request"
                    );
                    self.send(session, &Message::RequestHeaders(request));
                    self.transit.note_headers(session, Instant::now());
                    self.arm(deadline, session, id);
                }
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
                } => {
                    let hashes = request.hashes.len();
                    self.send(session, &Message::RequestBodies(request));
                    self.transit.note_bodies(session, Instant::now(), hashes);
                    self.arm(deadline, session, id);
                }
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
                    self.send(session, &Message::GetTxpoolComplement(request));
                }
                Command::Relay { hash, from } => self.relay(hash, from),
                Command::RequestBundleBodies {
                    session,
                    block,
                    references,
                } => held_bodies.extend(self.ask_bundle_bodies(session, block, &references)),
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
                    self.send(session, &Message::RequestCompactMissingTx(request));
                }
            }
        }
        if let Some(pair) = release_seed {
            self.seen_seeds = Some(pair);
            // `Event::Seeds` does not emit `SeedNotHeld`, so this does not recur.
            self.event(Event::Seeds);
        }
        for held in held_bodies {
            self.event(held);
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
                    bundle_references: body.bundle_references,
                    bundle_bodies: body.bundle_bodies,
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

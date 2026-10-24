// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ingest service — the live arrival path (`DRS_X_STORE_FLIP.md` DX-Q2,
//! PR2-Q1).
//!
//! [`pipeline::run`](crate::pipeline::run) drives a pulled [`Source`] to
//! exhaustion, and a source has no path back to its producer, so it cannot
//! answer an arrival. The live daemon's arrivals come here instead: a
//! long-running service that owns the connector actor, the `form` workers
//! and the router, behind **one door**.
//!
//! # The door
//!
//! [`Door::offer_span`] takes a span of arrivals and returns at once:
//! either a refusal before acceptance ([`Refusal`]), or one [`Ticket`] per
//! arrival. **Each accepted arrival gets exactly one reply on its ticket,
//! tagged with the arrival.** That is structural: the reply slot an
//! accepted arrival carries sends [`Reply::Stopped`] if it is dropped
//! without a reply, so no path through the service can leave a ticket
//! unanswered. Who uses the door: the protocol handler's FFI entry,
//! `submit_block` and the miner's found-block sink. There is no second
//! path.
//!
//! **Room** ([`Door::room`]) is the count of arrivals the service will
//! accept now: a caller asks before sending, and a span offered without
//! room is [`Refusal::NoRoom`], never a peer fault. An accepted arrival is
//! never dropped while the service runs. At a stop (PR2-Q5), the connector
//! finishes its current message, and every accepted arrival not yet
//! connected replies [`Reply::Stopped`]: never a peer fault, and sync asks
//! again after the restart.
//!
//! # A span
//!
//! Each span is worked by its own task, so two sessions' spans race to the
//! one writer, and the router places on snapshots the other span's commits
//! can move (`router` module docs). Within a span, a run of blocks each
//! extending the one before it from the tip is formed in parallel, under
//! the hasher permits, and connected in order; an alternative arrival goes
//! through `OfferAlt` and, if it makes a switch due, the switch. A stale
//! placement — the connector's `HeightClaim`, a `Stale` claim, or an
//! `OfferAlt` whose parent became the tip — sends the arrival back to be
//! placed again, never to a verdict.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kameo::actor::{ActorRef, PreparedActor};
use shekyl_chain_rules::{AdmissionPolicy, InvalidBlock, Substrate};
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_hash_budget::Budget;
use shekyl_mempool::{Pool, PoolFault};
use shekyl_types::{BlockHash, BlockHeight, UnixSeconds};
use shekyl_wire::Transaction;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use crate::admission::{ArrivalBound, Buckets};
use crate::connector::{
    Connector, ConnectorArgs, PopBeyondReorgCap, PopBlocks, Rewound, RunFault, WatchTip,
};
use crate::follower::JobSeat;
use crate::schedule::ChainRules;

/// The caller's name for one arrival, carried on its reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArrivalTag(pub u64);

/// A peer session, as the caller numbers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// Where an arrival came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A peer's session. `solicited` is a block this node requested (a
    /// span chain sync asked for); otherwise it is an announcement.
    Peer {
        /// The session.
        session: SessionId,
        /// Whether this node asked for it.
        solicited: bool,
    },
    /// This node: `submit_block` or the miner's found-block sink.
    Local,
}

/// One arriving block: its bytes and the listed bodies it carried. A full
/// block carries every listed body; a compact one carries some or none,
/// and the rest are resolved from the pool's shown entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// The caller's name for it.
    pub tag: ArrivalTag,
    /// Where it came from.
    pub origin: Origin,
    /// The block blob.
    pub block: Vec<u8>,
    /// The listed bodies it carried, as blobs, in any order.
    pub bodies: Vec<Vec<u8>>,
}

/// The lengths of one arrival, which is all the door needs before the
/// bytes are copied. A reservation judged from these either accepts the
/// arrival or refuses it; the bytes are copied only after it accepts.
pub struct ArrivalLengths {
    /// The caller's name for it.
    pub tag: ArrivalTag,
    /// Where it came from.
    pub origin: Origin,
    /// The block blob's length.
    pub block_len: usize,
    /// Each carried body's length, in the order the caller listed them.
    pub body_lens: Vec<usize>,
}

impl ArrivalLengths {
    fn of(arrival: &Arrival) -> Self {
        Self {
            tag: arrival.tag,
            origin: arrival.origin,
            block_len: arrival.block.len(),
            body_lens: arrival.bodies.iter().map(Vec::len).collect(),
        }
    }
}

/// Why a span was not accepted. Never a peer fault; nothing was kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The service has no room for the span now ([`Door::room`]), or it is
    /// stopping.
    NoRoom,
    /// The session's bucket for unsolicited arrivals is dry
    /// (`admission` module docs). The handler may close the session: a
    /// close, never a score.
    Throttled,
    /// An arrival is larger than any valid block near this tip can be
    /// (`admission` module docs).
    Oversize,
    /// The door could not read the store to bound the arrival. The service
    /// meets the same read and stops on it, so waiting does not help.
    StoreUnreadable,
}

/// Why this node cannot follow a heavier chain it stored and judged: the
/// proven outcomes, apart from the door's [`Reply::BeyondCap`] hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CannotFollow {
    /// The stored alternative's fork is deeper than the cap (`D_max`):
    /// the store's `OfferAlt`, or the switch when the tip moved after the
    /// door's gate.
    BeyondCap(PopBeyondReorgCap),
    /// A pop met the undo floor (`StoreCannot::PopBelowFloor`).
    BelowFloor {
        /// The tip the pop met.
        tip: BlockHeight,
        /// The persisted undo floor.
        floor: BlockHeight,
    },
}

/// What became of one accepted arrival.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// It connected at `height`.
    Connected {
        /// Where.
        height: BlockHeight,
        /// Its identity.
        hash: BlockHash,
    },
    /// A verdict against the block: the one outcome that closes the serving
    /// session (DX-Q2 item 4).
    Refused(InvalidBlock),
    /// Its parent chain reaches no block this node holds; nothing was
    /// stored.
    Unlinked {
        /// The first unheld hash on that walk.
        at: BlockHash,
    },
    /// This node holds it already.
    AlreadyHeld,
    /// Stored as an alternative block; the incumbent stays.
    Held {
        /// Its height on its chain.
        height: BlockHeight,
    },
    /// The door's answer: the fork is deeper than the cap, judged before
    /// the block was stored or hashed. A hint, never proof of a heavier
    /// chain: one block nobody worked for earns it. Local: the session
    /// stays open, and it never sets `following_degraded` (DX-Q2 item 8).
    BeyondCap(PopBeyondReorgCap),
    /// Stored, and the chain switched onto its branch.
    Switched {
        /// The blocks popped, ascending.
        demoted: Vec<(BlockHeight, BlockHash)>,
        /// The blocks connected, ascending.
        promoted: Vec<(BlockHeight, BlockHash)>,
    },
    /// Stored, and the switch was refused: a promoted block failed
    /// (CEN-K5), and its suffix left the store.
    PromotionRefused {
        /// The refused block's height on the alternative chain.
        at: BlockHeight,
        /// The refused block.
        hash: BlockHash,
        /// The verdict.
        refused: InvalidBlock,
    },
    /// A heavier chain this node stored and cannot follow: the outcomes
    /// that set `following_degraded` at the flip (DX-Q2 item 8). Local;
    /// nothing moved.
    CannotFollow(CannotFollow),
    /// Listed bodies neither the arrival carried nor the pool shows, by
    /// their index in the block's list: ask for them and offer it again.
    MissingBodies {
        /// The indices, ascending.
        indices: Vec<usize>,
    },
    /// A block earlier in the same span was refused, and this one was not
    /// formed after it (PR2-Q2): never a peer fault. `by` is the refused
    /// arrival.
    Cancelled {
        /// The refused arrival.
        by: ArrivalTag,
    },
    /// The service stopped before the arrival connected. Never a peer
    /// fault.
    Stopped,
}

/// A reply with the arrival it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged {
    /// The arrival.
    pub tag: ArrivalTag,
    /// What became of it.
    pub reply: Reply,
}

/// The one reply an accepted arrival will get.
#[derive(Debug)]
pub struct Ticket {
    tag: ArrivalTag,
    reply: oneshot::Receiver<Reply>,
}

impl Ticket {
    /// The arrival this ticket answers for.
    #[must_use]
    pub const fn tag(&self) -> ArrivalTag {
        self.tag
    }

    /// Wait for the reply. A service gone without replying replied
    /// [`Reply::Stopped`] (module docs), so this always answers.
    pub async fn reply(self) -> Tagged {
        Tagged {
            tag: self.tag,
            reply: self.reply.await.unwrap_or(Reply::Stopped),
        }
    }
}

/// Where an accepted arrival's one reply goes. Dropped without a reply, it
/// sends [`Reply::Stopped`]. Either way the arrival's seat is given back
/// once, and **before** the reply goes out: a caller the reply wakes reads
/// the room it freed.
struct ReplySlot {
    sender: Option<oneshot::Sender<Reply>>,
    seat: Option<crate::room::Seat>,
}

impl ReplySlot {
    fn send(mut self, reply: Reply) {
        self.answer(reply);
    }

    /// Give the seat back and send `reply`, if this slot has not answered.
    fn answer(&mut self, reply: Reply) {
        if let Some(sender) = self.sender.take() {
            drop(self.seat.take());
            // The caller dropped its ticket: the reply has no reader, and
            // the arrival is answered all the same.
            let _unread = sender.send(reply);
        }
    }
}

impl Drop for ReplySlot {
    fn drop(&mut self) {
        self.answer(Reply::Stopped);
    }
}

/// An accepted arrival, parsed or not.
struct Accepted {
    slot: ReplySlot,
    tag: ArrivalTag,
    origin: Origin,
    block: Vec<u8>,
    bodies: Vec<Vec<u8>>,
}

/// The service's knobs, each with its reason. How many `form` workers hash
/// at once is not one: it is the daemon's one hasher [`Budget`], handed to
/// [`Service::start`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    /// The arrival window: arrivals accepted and not yet answered, at most.
    /// [`Door::room`] is what a sync caller can send, which keeps one seat
    /// for a block this node mined when the window holds more than one.
    pub room: NonZeroUsize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            room: crate::pipeline::PipelineConfig::DEFAULT_WINDOW,
        }
    }
}

/// Why the service ended other than by [`Service::stop`].
#[derive(Debug, thiserror::Error)]
pub enum ServiceFault<F> {
    /// The connector replied with a store-terminal fault, or could not be
    /// reached.
    #[error("connector: {0}")]
    Connector(RunFault),
    /// The connector's mailbox is gone.
    #[error("connector unreachable")]
    Mailbox,
    /// A store read outside the actor failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The verifier could not compute.
    #[error("substrate: {0:?}")]
    Substrate(F),
    /// The headers an alternative arrival's target window reads are
    /// corrupt on the store's own snapshot.
    #[error("a corrupt window at height {height}: {corrupt}")]
    Corrupt {
        /// The connecting height whose window it was.
        height: BlockHeight,
        /// What was observed.
        corrupt: shekyl_chain_rules::Corrupt,
    },
    /// The pool's chain view faulted. A pool-file fault does not use this
    /// arm: the file is discardable, and block ingest continues without it.
    #[error("pool: {0:?}")]
    Pool(PoolFault<StoreError>),
    /// The tip attendant ended while the service had not stopped, or it
    /// panicked. The miner must not keep hashing a job nothing will refresh.
    #[error("the tip follower ended")]
    FollowerEnded,
    /// An in-cap alternative named a seed below its fork that the window
    /// does not hold. The window's arithmetic says it cannot: a defect in
    /// this node, never a peer's doing (`cache_window` module docs).
    #[error("an in-cap alternative at height {height} named a below-fork seed outside the window")]
    SeedNotInWindow {
        /// The alternative's height on its chain.
        height: BlockHeight,
    },
    /// A form hashed under a seed this node had just prepared, and the
    /// substrate still had no cache for it.
    #[error("a prepared seed's cache was absent at height {height}")]
    PreparedSeedAbsent {
        /// The block's height on its chain.
        height: BlockHeight,
    },
    /// A block this node connected failed its own stateless rules when a
    /// switch formed it to demote it.
    #[error("the recorded block {hash:?} refused when formed for demotion: {refused}")]
    DemotionRefused {
        /// The block.
        hash: BlockHash,
        /// The verdict.
        refused: InvalidBlock,
    },
}

/// What every span task, and the tip attendant, shares.
pub(crate) struct Shared<S: Substrate> {
    store: Arc<ChainStore>,
    rules: ChainRules,
    substrate: Arc<S>,
    connector: ActorRef<Connector>,
    /// The daemon's one hasher budget.
    budget: Budget,
    /// Set with [`Self::request_stop`]. The budget's waiters load it.
    stop_flag: Arc<AtomicBool>,
    /// Set once: the service is stopping (a stop, or a fault).
    stop: tokio::sync::watch::Sender<bool>,
    /// The first fault a span task met; the service ends on it.
    fault: Mutex<Option<ServiceFault<S::Fault>>>,
    /// Serializes cache pins. Taken after a hasher permit, never before.
    pin_lock: Arc<Mutex<()>>,
    /// Serialises every form under a branch's own seed (B2): an alternative
    /// arrival's, and a switch that promotes past its branch's seed point.
    /// Taken before any permit, so the order is gate, permit, `pin_lock`.
    /// With one such form at a time, the live caches are the canonical, the
    /// transient, and at most one evicted cache a form still holds.
    branch_gate: tokio::sync::Mutex<()>,
    /// The seeds the two slots hold. `None` until the first install.
    seeds: tokio::sync::watch::Sender<Option<crate::cache_window::SeedPair>>,
    /// The last `TipChanged` publication the tip attendant acted on.
    followed: tokio::sync::watch::Sender<u64>,
    /// The pool, when one is wired.
    pool: Option<PoolWiring>,
    /// Cleared when the pool file faults. Block ingest does not stop.
    pool_live: Arc<AtomicBool>,
    /// Bodies a span parked because the tip moved under the pool door.
    pending: Mutex<Vec<Transaction>>,
    /// Wakes the attendant to judge [`pending`](Self::pending).
    pending_ready: Arc<tokio::sync::Notify>,
    /// A test makes this many of the next builds lose a listed body
    /// between the producer's locks.
    #[cfg(test)]
    pub(crate) bodies_gone: std::sync::atomic::AtomicUsize,
}

impl<S: Substrate> Shared<S>
where
    S::Fault: core::fmt::Debug,
{
    pub(crate) fn stopping(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    /// A receiver that reads `true` once the service is stopping.
    pub(crate) fn stop_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Stop the service and wake every hasher waiter.
    pub(crate) fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        self.stop.send_replace(true);
        self.budget.wake();
    }

    /// The tip attendant acted on publication `seq`.
    pub(crate) fn followed(&self, seq: u64) {
        self.followed.send_replace(seq);
    }

    /// The seeds the slots hold now, including while the service is stopping.
    pub(crate) fn published_seeds(&self) -> Option<crate::cache_window::SeedPair> {
        *self.seeds.borrow()
    }

    /// The seeds an arrival may hash under. `None` while the service is stopping.
    pub(crate) fn seed_now(&self) -> Option<crate::cache_window::SeedPair> {
        if self.stopping() {
            None
        } else {
            self.published_seeds()
        }
    }

    /// Wait until the slots hold a pair, or the service stops.
    pub(crate) async fn seed_pair(&self) -> Option<crate::cache_window::SeedPair> {
        let mut published = self.seeds.subscribe();
        let mut stopping = self.stop_signal();
        loop {
            if self.stopping() {
                return None;
            }
            if let Some(pair) = *published.borrow_and_update() {
                return Some(pair);
            }
            tokio::select! {
                changed = published.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
                _ = stopping.wait_for(|stop| *stop) => return None,
            }
        }
    }

    /// Record the seeds a pin just installed.
    pub(crate) fn note_pins(&self, pinned: &[BlockHash]) {
        window::note_pins(self, pinned);
    }

    /// A branch seed was prepared into the transient slot: the published
    /// pair says so, so the next window install sees the slot it lost.
    pub(crate) fn note_prepared(&self, seed: BlockHash) {
        if let Some(pair) = self.published_seeds() {
            if pair.canonical != seed {
                self.seeds.send_replace(Some(crate::cache_window::SeedPair {
                    canonical: pair.canonical,
                    transient: Some(seed),
                }));
            }
        }
    }

    /// The gate every form under a branch's own seed takes first.
    pub(crate) async fn branch_form(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.branch_gate.lock().await
    }

    pub(crate) const fn store(&self) -> &Arc<ChainStore> {
        &self.store
    }

    pub(crate) const fn rules(&self) -> ChainRules {
        self.rules
    }

    pub(crate) const fn substrate(&self) -> &Arc<S> {
        &self.substrate
    }

    /// The pool, locked, for a read that does not wait on anything.
    fn pool_guard(&self) -> Option<std::sync::MutexGuard<'_, Pool>> {
        if !self.pool_is_live() {
            return None;
        }
        self.pool.as_ref().map(|wiring| {
            wiring
                .pool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
    }

    /// The pool's shown bodies, when the pool is live.
    pub(crate) fn shown_pool(&self) -> Option<std::sync::MutexGuard<'_, Pool>> {
        self.pool_guard()
    }

    /// Whether a pool is wired and its file has not faulted.
    pub(crate) fn pool_is_live(&self) -> bool {
        self.pool.is_some() && self.pool_live.load(Ordering::Acquire)
    }

    /// The pool, when it is wired and live. A caller that also reads the
    /// chain begins its snapshot before it locks this, as [`with_pool`]
    /// does.
    pub(crate) fn live_pool(&self) -> Option<&Mutex<Pool>> {
        if !self.pool_is_live() {
            return None;
        }
        self.pool.as_ref().map(|wiring| &*wiring.pool)
    }

    /// Whether a pool is wired and its file has faulted.
    pub(crate) fn pool_retired(&self) -> bool {
        self.pool.is_some() && !self.pool_live.load(Ordering::Acquire)
    }

    /// The pool file faulted. Block ingest continues; the pool is not read
    /// or written again until a restart opens the file afresh. The file is
    /// discardable (`SPL-Q8`), but one this process cannot read is refused
    /// at open, never deleted, so the remedy is the operator's restart.
    pub(crate) fn pool_dead(&self, fault: &StoreError) {
        retire_pool(&self.pool_live, fault);
    }

    /// Park `bodies` for the attendant and wake it.
    pub(crate) fn hand_pending(&self, bodies: Vec<Transaction>) {
        if bodies.is_empty() {
            return;
        }
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(bodies);
        self.pending_ready.notify_one();
    }

    /// Park `bodies` without waking. The next tip, or the next handed
    /// batch, judges them. A tip that moved under this attempt must not
    /// notify itself.
    pub(crate) fn park_pending(&self, bodies: Vec<Transaction>) {
        if bodies.is_empty() {
            return;
        }
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(bodies);
    }

    /// Take the parked bodies.
    pub(crate) fn take_pending(&self) -> Vec<Transaction> {
        std::mem::take(
            &mut *self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The attendant waits on this beside the tip.
    pub(crate) fn pending_ready(&self) -> &tokio::sync::Notify {
        &self.pending_ready
    }

    /// Record `fault` if it is the first, and stop.
    pub(crate) fn fail(&self, fault: ServiceFault<S::Fault>) {
        let mut first = self
            .fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        first.get_or_insert(fault);
        drop(first);
        self.request_stop();
    }
}

/// A monotonic reading: the time since the service started.
pub type Clock = Arc<dyn Fn() -> Duration + Send + Sync>;

/// A failed door-side store read. The door still refuses the span.
type ReadFault = Arc<dyn Fn(shekyl_chain_rules::ViewRead<StoreError>) + Send + Sync>;

/// The door's checks before acceptance (`admission` module docs).
struct Admission {
    store: Arc<ChainStore>,
    /// The size bound, and the tip it was derived at.
    bound: Mutex<Option<(Option<BlockHash>, ArrivalBound)>>,
    buckets: Buckets,
    clock: Clock,
    /// Set once the service exists, so a failed read stops it.
    on_read_fault: Mutex<Option<ReadFault>>,
    /// A test makes the bound read fail; the chain store has no read
    /// fault of its own to inject.
    #[cfg(test)]
    refuse_reads: std::sync::atomic::AtomicBool,
}

/// The door: the one way in (module docs). Cheap to clone.
#[derive(Clone)]
pub struct Door {
    spans: mpsc::UnboundedSender<Vec<Accepted>>,
    room: Arc<crate::room::Room>,
    admission: Arc<Admission>,
}

impl Door {
    /// Seats a sync caller can take now. Zero when the door is closed.
    #[must_use]
    pub fn room(&self) -> usize {
        self.room.solicited_available()
    }

    /// Seats the window was opened with. No span longer than this is accepted.
    #[must_use]
    pub fn window(&self) -> usize {
        self.room.window()
    }

    /// The largest arrival, in bytes, accepted at the current tip.
    ///
    /// `None` is a store read the service has recorded. The caller answers
    /// as no room.
    #[must_use]
    pub fn max_arrival_bytes(&self) -> Option<u64> {
        self.admission.bound().ok().map(|bound| bound.0)
    }

    /// Close the door and wake a miner waiting for a seat.
    pub(crate) fn close(&self) {
        self.room.close();
    }

    /// The local-arrival entry (`DRS_X_STORE_FLIP.md` DX-Q3, Q6): a block this
    /// node mined, was submitted, or is connecting at genesis. It waits for
    /// the local seat while the window is full, offers the block as
    /// [`Origin::Local`], and awaits its one reply. A door that closes while
    /// it waits answers [`Reply::Stopped`]: the service is stopping, and the
    /// block was not accepted.
    ///
    /// The miner's sink, `submit_block`, `generateblocks` and the node's
    /// genesis connect all enter here, so a local block has one path in.
    ///
    /// # Errors
    ///
    /// [`Refusal::Oversize`]: the block is larger than any valid block near
    /// the tip; [`Refusal::StoreUnreadable`]: the door could not read the
    /// store. Waiting changes neither, so neither is waited out.
    pub async fn offer_local(
        &self,
        tag: ArrivalTag,
        block: Vec<u8>,
        bodies: Vec<Vec<u8>>,
    ) -> Result<Tagged, Refusal> {
        let arrival = Arrival {
            tag,
            origin: Origin::Local,
            block,
            bodies,
        };
        loop {
            match self.offer(arrival.clone()) {
                Ok(ticket) => return Ok(ticket.reply().await),
                Err(Refusal::NoRoom) => {
                    if !self.room.wait_local().await {
                        return Ok(Tagged {
                            tag,
                            reply: Reply::Stopped,
                        });
                    }
                }
                Err(refused) => return Err(refused),
            }
        }
    }

    /// Offer one arrival: a span of one.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn offer(&self, arrival: Arrival) -> Result<Ticket, Refusal> {
        let mut tickets = self.offer_span(vec![arrival])?;
        Ok(tickets.pop().expect("one arrival, one ticket"))
    }

    /// Forget `session`'s bucket: its connection closed.
    pub fn session_closed(&self, session: SessionId) {
        self.admission.buckets.forget(session);
    }

    /// Offer a span: every arrival in it is accepted, or none is.
    /// [`Door::reserve`] judges the lengths first. The bytes are copied by
    /// the caller only after that, and [`Reservation::commit`] sends them.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn offer_span(&self, span: Vec<Arrival>) -> Result<Vec<Ticket>, Refusal> {
        let lengths: Vec<ArrivalLengths> = span.iter().map(ArrivalLengths::of).collect();
        Ok(self.reserve(&lengths)?.commit(span))
    }
}

/// Which seat an arrival takes.
fn seat_kind(origin: Origin) -> crate::room::Kind {
    match origin {
        Origin::Local => crate::room::Kind::Local,
        Origin::Peer {
            solicited: true, ..
        } => crate::room::Kind::Solicited,
        Origin::Peer {
            solicited: false, ..
        } => crate::room::Kind::Unsolicited,
    }
}

/// Take one bucket charge per session in `lengths`. A later session that
/// is dry gives every earlier take back. The taken charges are the
/// reservation's to refund if the span is never committed.
fn take_unsolicited(
    buckets: &Buckets,
    lengths: &[ArrivalLengths],
    now: Duration,
) -> Result<Vec<(SessionId, u32)>, Refusal> {
    let mut owed: Vec<(SessionId, u32)> = Vec::new();
    for arrival in lengths {
        if let Origin::Peer {
            session,
            solicited: false,
        } = arrival.origin
        {
            match owed.iter_mut().find(|(id, _)| *id == session) {
                Some((_, count)) => *count += 1,
                None => owed.push((session, 1)),
            }
        }
    }
    let mut taken: Vec<(SessionId, u32)> = Vec::new();
    for (session, count) in owed {
        if !buckets.take(session, count, now) {
            for (session, count) in taken {
                buckets.give_back(session, count, now);
            }
            return Err(Refusal::Throttled);
        }
        taken.push((session, count));
    }
    Ok(taken)
}

/// What the service's tip follower feeds, beside the store
/// (`follower` module docs). Each part is optional: a service with
/// neither still publishes the tip. A job seat without a miner holds the
/// board until the service stops and posts nothing in between.
#[derive(Default)]
pub struct Follow {
    /// The board, and the miner when one is seated.
    pub job: Option<JobSeat>,
    /// The pool.
    pub pool: Option<PoolWiring>,
}

/// The pool, as a consumer of the connector (`DRS_X_STORE_FLIP.md` DX-Q5;
/// the brief's c6): reconciled by the tip follower after every committed
/// connect, pop and switch, before the miner's next job; offered a
/// switch's returned bodies and an admitted alternative block's stored
/// bodies by the span that made them; and read for a compact block's
/// bodies, shown entries only (PR2-Q4).
#[derive(Clone)]
pub struct PoolWiring {
    /// The pool.
    pub pool: Arc<Mutex<Pool>>,
    /// The admission policy its door runs.
    pub policy: AdmissionPolicy,
    /// The wall clock its door stamps arrivals with.
    pub wall: Arc<dyn Fn() -> UnixSeconds + Send + Sync>,
}

/// Pops blocks for `pop_blocks` (`DRS_X_STORE_FLIP.md` DX-Q3, Q7), held
/// apart from the service ([`Service::rewinder`]).
pub struct Rewinder<S: Substrate>
where
    S::Fault: core::fmt::Debug,
{
    shared: Arc<Shared<S>>,
}

impl<S: Substrate> Clone for Rewinder<S>
where
    S::Fault: core::fmt::Debug,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<S> Rewinder<S>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    /// Pop `count` blocks from the tip ([`PopBlocks`]). A count that would
    /// pop genesis or a retired block is refused before any pop, and the
    /// writer stays up. After a pop, the popped blocks' bodies are offered
    /// through the pool's door, as a switch's demoted bodies are.
    ///
    /// # Errors
    ///
    /// [`ServiceFault::Connector`] for a store fault; [`ServiceFault::Mailbox`]
    /// when the connector is gone.
    pub async fn pop_blocks(&self, count: u64) -> Result<Rewound, ServiceFault<S::Fault>> {
        let rewound = self
            .shared
            .connector
            .ask(PopBlocks { count })
            .await
            .map_err(|error| match error {
                kameo::error::SendError::HandlerError(fault) => ServiceFault::Connector(fault),
                _ => ServiceFault::Mailbox,
            })?;
        if let Rewound::Popped { bodies, .. } = &rewound {
            if !bodies.is_empty() {
                span::offer_carried(&self.shared, span::Carried::Bodies(bodies.clone())).await;
            }
        }
        Ok(rewound)
    }
}

/// The pool file faulted: the one retirement, whoever met the fault.
fn retire_pool(live: &AtomicBool, fault: &StoreError) {
    tracing::error!(
        "the pool file faulted: the node keeps following the chain without a \
         transaction pool until it restarts: {fault}"
    );
    live.store(false, Ordering::Release);
}

/// Whether the pool file has faulted ([`Service::pool_health`]), and the
/// way to say it has: a writer outside the service that meets a fault on
/// the pool file retires the service's pool, not a copy.
#[derive(Clone, Debug)]
pub struct PoolHealth {
    wired: bool,
    live: Arc<AtomicBool>,
}

impl PoolHealth {
    /// The health of a node with no pool wired: never retired.
    #[must_use]
    pub fn unwired() -> Self {
        Self {
            wired: false,
            live: Arc::new(AtomicBool::new(true)),
        }
    }

    /// A pool is wired and its file has faulted.
    #[must_use]
    pub fn retired(&self) -> bool {
        self.wired && !self.live.load(Ordering::Acquire)
    }

    /// The pool file faulted under a writer outside the service: the
    /// service reads and writes the pool no more, as when it meets the
    /// fault itself.
    pub fn retire(&self, fault: &StoreError) {
        retire_pool(&self.live, fault);
    }
}

/// The running service (module docs).
pub struct Service<S: Substrate>
where
    S::Fault: core::fmt::Debug,
{
    door: Door,
    shared: Arc<Shared<S>>,
    task: tokio::task::JoinHandle<()>,
    connector_task: tokio::task::JoinHandle<
        Result<(Connector, kameo::error::ActorStopReason), kameo::error::PanicError>,
    >,
}

impl<S> Service<S>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    /// Start the service over `store`: the connector actor that alone writes
    /// it, and the loop that works each accepted span.
    #[must_use]
    pub fn start(
        store: Arc<ChainStore>,
        rules: ChainRules,
        substrate: Arc<S>,
        config: ServiceConfig,
        budget: Budget,
        follow: Follow,
    ) -> Self {
        let started = std::time::Instant::now();
        Self::start_with_clock(
            store,
            rules,
            substrate,
            config,
            budget,
            follow,
            Arc::new(move || started.elapsed()),
        )
    }

    /// [`Self::start`] under `clock`, the reading the session buckets
    /// refill by: a test's clock it advances itself.
    #[must_use]
    pub fn start_with_clock(
        store: Arc<ChainStore>,
        rules: ChainRules,
        substrate: Arc<S>,
        config: ServiceConfig,
        budget: Budget,
        follow: Follow,
        clock: Clock,
    ) -> Self {
        let admission = Arc::new(Admission {
            store: Arc::clone(&store),
            bound: Mutex::new(None),
            buckets: Buckets::new(Duration::from_secs(shekyl_difficulty::T_SECONDS)),
            clock,
            on_read_fault: Mutex::new(None),
            #[cfg(test)]
            refuse_reads: std::sync::atomic::AtomicBool::new(false),
        });
        let prepared = PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
        let connector = prepared.actor_ref().clone();
        let connector_task = prepared.spawn(ConnectorArgs {
            store: Arc::clone(&store),
            rules,
        });
        let shared = Arc::new(Shared {
            store,
            rules,
            substrate,
            connector,
            budget,
            stop_flag: Arc::new(AtomicBool::new(false)),
            stop: tokio::sync::watch::Sender::new(false),
            fault: Mutex::new(None),
            pin_lock: Arc::new(Mutex::new(())),
            branch_gate: tokio::sync::Mutex::new(()),
            seeds: tokio::sync::watch::Sender::new(None),
            followed: tokio::sync::watch::Sender::new(0),
            pool: follow.pool,
            pool_live: Arc::new(AtomicBool::new(true)),
            pending: Mutex::new(Vec::new()),
            pending_ready: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            bodies_gone: std::sync::atomic::AtomicUsize::new(0),
        });
        {
            let shared = Arc::clone(&shared);
            admission.bind_read_fault(Arc::new(move |read| {
                window::record_store_read(&shared, read);
            }));
        }
        // The first pair is pinned before any span can hash. Later tips
        // reinstall from the attendant.
        if let Err(read) = window::install_blocking(&shared) {
            window::record_store_read(&shared, read);
        }
        let (spans_tx, mut incoming) = mpsc::unbounded_channel::<Vec<Accepted>>();
        let door = Door {
            spans: spans_tx,
            room: crate::room::Room::new(config.room.get()),
            admission,
        };
        let loop_shared = Arc::clone(&shared);
        let loop_door = door.clone();
        let mut stopped = shared.stop.subscribe();
        let attendant_shared = Arc::clone(&shared);
        let attendant_door = door.clone();
        let job = follow.job;
        let task = tokio::spawn(async move {
            let attendant = tokio::spawn(async move {
                let Ok(tips) = attendant_shared.connector.ask(WatchTip).await else {
                    if let Some(seat) = job.as_ref() {
                        seat.board.withdraw();
                    }
                    return;
                };
                crate::follower::follow(attendant_shared, attendant_door, tips, job).await;
            });
            tokio::pin!(attendant);
            let mut spans: JoinSet<()> = JoinSet::new();
            let mut attendant_ended = false;
            loop {
                tokio::select! {
                    next = incoming.recv() => {
                        let Some(span) = next else { break };
                        if loop_shared.stopping() {
                            drop(span);
                            continue;
                        }
                        spans.spawn(span::run_span(Arc::clone(&loop_shared), span));
                    }
                    Some(_done) = spans.join_next(), if !spans.is_empty() => {}
                    result = &mut attendant, if !attendant_ended => {
                        attendant_ended = true;
                        let panicked = result.is_err();
                        if panicked || !loop_shared.stopping() {
                            loop_shared.fail(ServiceFault::FollowerEnded);
                        }
                        break;
                    }
                    _ = stopped.wait_for(|stopping| *stopping) => break,
                }
            }
            // A stop or a fault: the door takes nothing more, so a caller
            // asking for room — the protocol handler, the miner's sink —
            // reads none instead of offering into a service that is gone.
            loop_door.close();
            // Every span still queued answers `Stopped`; every running one
            // finishes its current step and drops the rest.
            incoming.close();
            while let Some(span) = incoming.recv().await {
                drop(span);
            }
            while spans.join_next().await.is_some() {}
            if !attendant_ended {
                let result = attendant.await;
                if result.is_err()
                    && loop_shared
                        .fault
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .is_none()
                {
                    loop_shared.fail(ServiceFault::FollowerEnded);
                }
            }
        });
        Self {
            door,
            shared,
            task,
            connector_task,
        }
    }

    /// A receiver of `TipChanged` (`connector` module docs).
    ///
    /// # Errors
    ///
    /// The connector is gone.
    pub async fn watch_tip(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<crate::connector::TipChanged>, ServiceFault<S::Fault>>
    {
        self.shared
            .connector
            .ask(WatchTip)
            .await
            .map_err(|_| ServiceFault::Mailbox)
    }

    /// The last `TipChanged` publication the tip follower acted on: what a
    /// caller waits on to know the pool and the miner's job are the tip's.
    #[must_use]
    pub fn followed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.shared.followed.subscribe()
    }

    /// Whether the pool file faulted and the pool was retired: no relay,
    /// no compact-block resolution and no transactions in a template until
    /// a restart. What `get_info` and `mining_status` report (PR 3b).
    #[must_use]
    pub fn pool_retired(&self) -> bool {
        self.shared.pool_retired()
    }

    /// What pops blocks for `pop_blocks`, held apart from the service.
    #[must_use]
    pub fn rewinder(&self) -> Rewinder<S> {
        Rewinder {
            shared: Arc::clone(&self.shared),
        }
    }

    /// The same reading, held apart from the service: what the node's
    /// mining control reports after the service is gone.
    #[must_use]
    pub fn pool_health(&self) -> PoolHealth {
        PoolHealth {
            wired: self.shared.pool.is_some(),
            live: Arc::clone(&self.shared.pool_live),
        }
    }

    /// The door.
    #[must_use]
    pub fn door(&self) -> Door {
        self.door.clone()
    }

    /// The connector, for a caller that reads through it (the RPC, tests).
    #[must_use]
    pub fn connector(&self) -> &ActorRef<Connector> {
        &self.shared.connector
    }

    /// Stop (PR2-Q5): close the door, let every span finish its current
    /// step, answer the rest `Stopped`, then stop the connector once its
    /// current message is done and wait for the store it owns to drop.
    ///
    /// # Errors
    ///
    /// The fault that ended the service, if one did before the stop.
    pub async fn stop(self) -> Result<(), ServiceFault<S::Fault>> {
        self.door.close();
        self.shared.request_stop();
        let _joined = self.task.await;
        let _already_stopped = self.shared.connector.stop_gracefully().await.is_err();
        self.shared.connector.wait_for_shutdown().await;
        let _actor_and_reason = self.connector_task.await;
        let fault = self
            .shared
            .fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        fault.map_or(Ok(()), Err)
    }
}

#[path = "span.rs"]
mod span;

#[path = "window.rs"]
mod window;

pub use window::Reservation;
pub(crate) use window::{
    divide_pool_faults, install_window, record_store_read, with_pool, PoolDivision,
};

#[cfg(test)]
#[path = "service_tests.rs"]
pub(crate) mod service_tests;

#[cfg(test)]
#[path = "service_pool_tests.rs"]
mod service_pool_tests;

#[cfg(test)]
#[path = "service_seed_tests.rs"]
mod service_seed_tests;

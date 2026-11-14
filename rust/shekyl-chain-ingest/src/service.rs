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
//! `block_submit` and the miner's found-block sink. There is no second
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
use shekyl_chain_rules::{AdmissionPolicy, InvalidBlock};
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_hasher::Class;
use shekyl_mempool::{Pool, PoolFault};
use shekyl_types::{BlockHash, BlockHeight, TxHash, UnixSeconds};
use shekyl_wire::Transaction;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinSet;

use crate::admission::{ArrivalBound, Buckets};
use crate::connector::{
    BundleOffered, Connector, ConnectorArgs, FiledBundle, OfferBundle, OfferFault,
    PopBeyondReorgCap, PopBlocks, Rewound, RunFault, WatchTip, FILED_FEED_CAPACITY,
};
use crate::follower::JobSeat;
use crate::pow::Pow;
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
    /// This node: `block_submit` or the miner's found-block sink.
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
    /// The bundle references carried beside the block, undecoded; empty
    /// when none.
    pub bundle_references: Vec<Vec<u8>>,
    /// The bodies of those bundles it carried, unverified and in no set
    /// order; assembly matches each to its reference by hash. Empty when
    /// none were carried.
    pub bundle_bodies: Vec<Vec<u8>>,
}

/// One block chain sync has already proven: its header passed
/// `form_header` and `judge_header` in the sync owner, and its body was bound
/// to that header before the offer (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2 steps
/// 3 and 6; CS2-Q1). The service forms it with `form_judged`, which consumes
/// the proof and does not hash, so it takes no hasher permit and pins no
/// seed.
///
/// It is seated as a solicited arrival however the body reached the owner.
/// The owner admits an announcement itself (one unproved announce per
/// session, proved under the hasher's unsolicited class) and offers only
/// bodies on `H*`'s path within the room [`Door::room`] reported, so the
/// door's unsolicited share and bucket have nothing left to decide for it:
/// until 2026-11-02 they did decide, and a span of more announced bodies
/// than the share was `NoRoom` in an empty window (the sync owner's
/// `Event::Room` docs).
#[derive(Clone, Debug)]
pub struct BoundArrival {
    /// The caller's name for it.
    pub tag: ArrivalTag,
    /// The session that served the body.
    pub session: SessionId,
    /// The header the sync owner's proof accepted.
    pub judged: shekyl_chain_rules::HeaderJudged,
    /// The block blob.
    pub block: Vec<u8>,
    /// The listed bodies, as blobs, in the block's order.
    pub bodies: Vec<Vec<u8>>,
    /// The bundle references carried beside the block, undecoded; empty
    /// when the block admits no bundle.
    pub bundle_references: Vec<Vec<u8>>,
    /// The bodies of those bundles it carried, unverified and in no set
    /// order; assembly matches each to its reference by hash.
    pub bundle_bodies: Vec<Vec<u8>>,
}

impl BoundArrival {
    /// The bytes the door bounds for this arrival
    /// ([`ArrivalLengths::bytes`]).
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.lengths().bytes()
    }

    fn lengths(&self) -> ArrivalLengths {
        ArrivalLengths {
            tag: self.tag,
            origin: Origin::Peer {
                session: self.session,
                solicited: true,
            },
            block_len: self.block.len(),
            body_lens: self.bodies.iter().map(Vec::len).collect(),
            reference_count: self.bundle_references.len(),
            bundle_body_count: self.bundle_bodies.len(),
        }
    }
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
    /// How many bundle references were carried; zero when none were.
    /// Bounded by [`shekyl_types::archival::MAX_SECTION_REFERENCES`], not by
    /// [`crate::admission::ArrivalBound`].
    pub reference_count: usize,
    /// How many bundle bodies were carried: never more than a section has
    /// references, and, like the references, not block bytes.
    pub bundle_body_count: usize,
}

impl ArrivalLengths {
    /// The bytes the door bounds against [`Door::max_arrival_bytes`]: the
    /// block and the bodies it carried. The bundle references are a sidecar
    /// with their own cap, a count
    /// ([`shekyl_types::archival::MAX_SECTION_REFERENCES`]); their bytes
    /// are not these bytes. A section is not block weight (§7.1: a bundle
    /// is not a transaction), so a full block carrying one is not oversize,
    /// and a peer's arrival is already bounded by the packet it came in.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.body_lens
            .iter()
            .fold(self.block_len, |total, len| total.saturating_add(*len))
    }

    fn of(arrival: &Arrival) -> Self {
        Self {
            tag: arrival.tag,
            origin: arrival.origin,
            block_len: arrival.block.len(),
            body_lens: arrival.bodies.iter().map(Vec::len).collect(),
            reference_count: arrival.bundle_references.len(),
            bundle_body_count: arrival.bundle_bodies.len(),
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
        /// The block whose list they are: what the re-request names.
        hash: BlockHash,
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

/// How an accepted arrival is formed.
///
/// A hashed arrival takes one permit of its class. A judged arrival
/// carries the proof chain sync already paid for, and `form_judged`
/// consumes it without a hash.
#[derive(Clone)]
enum Proof {
    /// Hashed here, under one permit of `class`.
    Hash {
        /// The budget class the permit is taken from.
        class: Class,
    },
    /// Proven already.
    Judged(Box<shekyl_chain_rules::HeaderJudged>),
}

/// The hasher class an arrival's `form` waits in: a block this node asked
/// for or made is the chain's; an announcement is unsolicited.
const fn class_of(origin: Origin) -> Class {
    match origin {
        Origin::Peer {
            solicited: false, ..
        } => Class::Unsolicited,
        Origin::Peer {
            solicited: true, ..
        }
        | Origin::Local => Class::Chain,
    }
}

/// One arrival a reservation accepts, before its seat is attached.
struct Staged {
    tag: ArrivalTag,
    block: Vec<u8>,
    bodies: Vec<Vec<u8>>,
    proof: Proof,
    references: Vec<Vec<u8>>,
    bundle_bodies: Vec<Vec<u8>>,
}

impl Staged {
    fn hashed(arrival: Arrival) -> Self {
        Self {
            tag: arrival.tag,
            block: arrival.block,
            bodies: arrival.bodies,
            proof: Proof::Hash {
                class: class_of(arrival.origin),
            },
            references: arrival.bundle_references,
            bundle_bodies: arrival.bundle_bodies,
        }
    }

    fn judged(arrival: BoundArrival) -> Self {
        Self {
            tag: arrival.tag,
            block: arrival.block,
            bodies: arrival.bodies,
            proof: Proof::Judged(Box::new(arrival.judged)),
            references: arrival.bundle_references,
            bundle_bodies: arrival.bundle_bodies,
        }
    }
}

/// An accepted arrival, parsed or not.
struct Accepted {
    slot: ReplySlot,
    tag: ArrivalTag,
    block: Vec<u8>,
    bodies: Vec<Vec<u8>>,
    /// How this arrival is formed.
    proof: Proof,
    /// The bundle references carried beside the block; empty when none
    /// were.
    references: Vec<Vec<u8>>,
    /// The bundle bodies carried beside the block, unverified.
    bundle_bodies: Vec<Vec<u8>>,
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
    /// panicked, or a blocking task of the follower's panicked: the pool's
    /// judging, the template producer. The miner must not keep hashing a
    /// job nothing will refresh.
    #[error("the tip follower ended")]
    FollowerEnded,
    /// The ranker panicked: nothing tells the hasher which seeds the node
    /// needs any more. Reached only where a panic unwinds (the test
    /// profile); dev and release abort.
    #[error("the ranker ended")]
    RankerEnded,
    /// An in-cap alternative named a seed below its fork that the window
    /// does not hold. The window's arithmetic says it cannot: a defect in
    /// this node, never a peer's doing (`cache_window` module docs).
    #[error("an in-cap alternative at height {height} named a below-fork seed outside the window")]
    SeedNotInWindow {
        /// The alternative's height on its chain.
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

impl<F: core::fmt::Debug> ServiceFault<F> {
    /// This fault's own words. The error line and [`Service::ended`] both
    /// carry them, so a new variant reaches the daemon's exit line through
    /// its `thiserror` text and nowhere else.
    #[must_use]
    pub fn end(&self) -> ServiceEnd {
        ServiceEnd {
            cause: self.to_string(),
        }
    }
}

/// Why the service ended on its own ([`Service::ended`]): the
/// [`ServiceFault`]'s own words, owned so the process can exit with them.
///
/// The fault keeps its payload. This is that payload already rendered.
/// [`ServiceFault::end`] is how a running service builds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEnd {
    cause: String,
}

impl ServiceEnd {
    /// `cause` as a fault already said it. The stop-line tests name a
    /// sentence; a running service goes through [`ServiceFault::end`].
    #[must_use]
    pub fn words(cause: impl Into<String>) -> Self {
        Self {
            cause: cause.into(),
        }
    }
}

impl core::fmt::Display for ServiceEnd {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.cause)
    }
}

/// What every span task, and the tip attendant, shares.
pub(crate) struct Shared<P: Pow> {
    store: Arc<ChainStore>,
    rules: ChainRules,
    /// The proof-of-work boundary every hash goes through, inside a job.
    pow: Arc<P>,
    connector: ActorRef<Connector>,
    /// The bundles this node filed and queued, for the sync owner to relay.
    filed: tokio::sync::broadcast::Sender<FiledBundle>,
    /// Set with [`Self::request_stop`]. Every job's wait loads it.
    stop_flag: Arc<AtomicBool>,
    /// Set once: the service is stopping (a stop, or a fault).
    stop: tokio::sync::watch::Sender<bool>,
    /// The first fault a span task met; the service ends on it.
    fault: Mutex<Option<ServiceFault<P::Fault>>>,
    /// That fault's own words, published when it is recorded
    /// ([`Service::ended`]). `None` while the service runs, and after a
    /// stop that met no fault.
    ended: tokio::sync::watch::Sender<Option<ServiceEnd>>,
    /// Wakes the ranker (module docs, *The ranked list*). The connector
    /// fires it after every write that can change the seeds the node
    /// needs.
    ranked: Arc<Notify>,
    /// How many rankings have been asked for ([`Self::ranked_now`]).
    rank_asked: std::sync::atomic::AtomicU64,
    /// The highest ask a completed ranking has served: the ranker reads
    /// `rank_asked` before its snapshot and publishes that number once
    /// the list is sent.
    rank_served: tokio::sync::watch::Sender<u64>,
    /// The last `TipChanged` publication the tip attendant acted on.
    followed: tokio::sync::watch::Sender<u64>,
    /// The live phases' measurement sink ([`Follow::metrics`]).
    metrics: Option<Arc<crate::metrics::Metrics>>,
    /// The postings the follower has written and not yet dropped. The
    /// follower and the found-block sink share this map: a generation's
    /// job and the bodies it listed are one record.
    kept: crate::follower::Postings,
    /// The pool, when one is wired.
    pool: Option<PoolWiring>,
    /// Cleared when the pool file faults. Block ingest does not stop.
    pool_live: Arc<AtomicBool>,
    /// Bodies a span parked because the tip moved under the pool door.
    pending: Mutex<Vec<Transaction>>,
    /// Wakes the attendant: parked bodies, a shown-set change at this tip
    /// (Q9: once the relay marks an entry shown, the next template lists
    /// it — N2 rebuilds the posted job, not only on a tip move), and a
    /// bundle the queue admits at this tip (the connector fires it).
    pending_ready: Arc<Notify>,
    /// What a test does to the pool between the producer's two locks.
    /// The build clones it, so a test can replace it between wakes.
    #[cfg(test)]
    pub(crate) between_locks: Mutex<Option<Arc<crate::template::HeldBetweenLocks>>>,
}

impl<P: Pow> Shared<P> {
    pub(crate) fn stopping(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    /// A receiver that reads `true` once the service is stopping.
    pub(crate) fn stop_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Stop the service and wake every job waiting for a cache or a
    /// permit.
    pub(crate) fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        self.stop.send_replace(true);
        self.pow.wake();
    }

    /// Ask the ranker for a ranking and wait until one that began after
    /// this call has been sent to the hasher. The tip follower calls it
    /// before it builds a template: the miner's warm loan is granted only
    /// on a listed seed, so the list must name the new tip's seed before a
    /// job on it is posted. `false` when the service stopped first.
    pub(crate) async fn ranked_now(&self) -> bool {
        let mine = self.rank_asked.fetch_add(1, Ordering::AcqRel) + 1;
        let mut served = self.rank_served.subscribe();
        let mut stopping = self.stop_signal();
        self.ranked.notify_one();
        tokio::select! {
            reached = served.wait_for(|served| *served >= mine) => reached.is_ok(),
            _ = stopping.wait_for(|stop| *stop) => false,
        }
    }

    /// The ask count a ranking that starts now will have served.
    pub(crate) fn rank_asked(&self) -> u64 {
        self.rank_asked.load(Ordering::Acquire)
    }

    /// A ranking that read `asked` before its snapshot was sent.
    pub(crate) fn rank_served(&self, asked: u64) {
        self.rank_served.send_replace(asked);
    }

    /// The flag every job's wait loads.
    pub(crate) const fn stop_flag(&self) -> &Arc<AtomicBool> {
        &self.stop_flag
    }

    /// The tip attendant acted on publication `seq`.
    pub(crate) fn followed(&self, seq: u64) {
        self.followed.send_replace(seq);
    }

    /// The publication record the follower writes and the found-block sink
    /// reads.
    pub(crate) fn postings(&self) -> crate::follower::Postings {
        Arc::clone(&self.kept)
    }

    pub(crate) const fn store(&self) -> &Arc<ChainStore> {
        &self.store
    }

    pub(crate) const fn rules(&self) -> ChainRules {
        self.rules
    }

    pub(crate) const fn pow(&self) -> &Arc<P> {
        &self.pow
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

    /// The relay's hook for ids this reconcile took out of the pool.
    pub(crate) fn note_departed(&self, ids: &[TxHash]) {
        if ids.is_empty() {
            return;
        }
        if let Some(hook) = self
            .pool
            .as_ref()
            .and_then(|wiring| wiring.departed.as_ref())
        {
            hook(ids);
        }
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

    /// A shown-set change at this tip that did not come through the relay's
    /// hook: a body a pop or a switch returned to the pool, admitted public.
    /// Q9: the posted job is rebuilt on a shown-set change, not only on a
    /// tip move; the wake is the attendant's one pending `Notify`, so a
    /// batch of returns costs at most one rebuild in flight.
    pub(crate) fn shown_changed(&self) {
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

    /// The attendant waits on this beside the tip: parked bodies, a
    /// shown-set change at this tip (Q9), and a bundle the queue admits.
    pub(crate) fn pending_ready(&self) -> &Notify {
        &self.pending_ready
    }

    /// Record `fault` if it is the first, and stop.
    ///
    /// The first fault is logged at `error` here, in its own words, and
    /// those words are published on [`Service::ended`] for the daemon's
    /// exit line. A stopped service leaves the process up and the RPC
    /// answering from the old tip, so the line cannot wait for the
    /// process to exit (rule 82). A later fault is a consequence of the
    /// first and is logged at `debug`.
    pub(crate) fn fail(&self, fault: ServiceFault<P::Fault>) {
        let mut first = self
            .fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if first.is_none() {
            let cause = fault.end();
            tracing::error!("the ingest service stops on a fault: {cause}");
            self.ended.send_replace(Some(cause));
            *first = Some(fault);
        } else {
            tracing::debug!("the ingest service, already stopping, met: {fault}");
        }
        drop(first);
        self.request_stop();
    }
}

/// The sync owner's way to the `following_degraded` latch: the connector's
/// [`RaiseAlarm`](crate::connector::RaiseAlarm), cloneable.
#[derive(Clone)]
pub struct Alarm {
    connector: kameo::actor::ActorRef<Connector>,
}

/// Why an [`Alarm`] was not written.
#[derive(Debug, thiserror::Error)]
pub enum AlarmFault {
    /// The connector replied with a fault.
    #[error("connector: {0}")]
    Connector(RunFault),
    /// The connector's mailbox is gone.
    #[error("connector unreachable")]
    Mailbox,
}

impl Alarm {
    /// Write the latch with `evidence`. `true` when this call set it.
    ///
    /// # Errors
    ///
    /// [`AlarmFault`].
    pub async fn raise(
        &self,
        evidence: shekyl_chain_store::codec::FollowingDegraded,
    ) -> Result<bool, AlarmFault> {
        match self
            .connector
            .ask(crate::connector::RaiseAlarm(evidence))
            .await
        {
            Ok(set) => Ok(set),
            Err(kameo::error::SendError::HandlerError(fault)) => Err(AlarmFault::Connector(fault)),
            Err(_) => Err(AlarmFault::Mailbox),
        }
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
    connector: ActorRef<Connector>,
    filed: tokio::sync::broadcast::Sender<FiledBundle>,
    /// The follower's postings: a block mined on one is given its bundle
    /// section here ([`Door::offer_local`]).
    postings: crate::follower::Postings,
}

impl Door {
    /// Offer a bundle a peer relayed to the queue (§7.5). Admission is the
    /// bundle rule against the tip, the same rule this node's own bundles
    /// meet ([`OfferBundle`]); the verdict is the reply. Only an admitted
    /// bundle's body is stored.
    ///
    /// # Errors
    ///
    /// [`OfferFault`] when the connector faulted or has stopped.
    pub async fn offer_bundle(
        &self,
        reference: shekyl_archival_retention::BundleRef,
        body: shekyl_archival_retention::BundleBody,
    ) -> Result<BundleOffered, OfferFault> {
        match self.connector.ask(OfferBundle { reference, body }).await {
            Ok(offered) => Ok(offered),
            Err(kameo::error::SendError::HandlerError(fault)) => Err(OfferFault::Connector(fault)),
            Err(_) => Err(OfferFault::Stopped),
        }
    }

    /// File a bundle this node produced (§7.5): the queue's admission, and
    /// on admission the relay feed ([`Self::filed`]). The producer's task
    /// files through the same path.
    ///
    /// # Errors
    ///
    /// [`OfferFault`] when the connector faulted or has stopped.
    pub async fn file_bundle(
        &self,
        reference: shekyl_archival_retention::BundleRef,
        body: shekyl_archival_retention::BundleBody,
    ) -> Result<BundleOffered, OfferFault> {
        crate::connector::file_bundle(&self.connector, &self.filed, reference, body).await
    }

    /// The bundles this node files and queues from now on, for the sync
    /// owner to relay (`SCS-P25`). A receiver that falls more than
    /// [`FILED_FEED_CAPACITY`] behind misses the oldest.
    #[must_use]
    pub fn filed(&self) -> tokio::sync::broadcast::Receiver<FiledBundle> {
        self.filed.subscribe()
    }

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

    /// The bundle section of the posting `block` was mined on, as the block
    /// carries it: references, and bodies (`SO-D12` 4b, C4). A local block
    /// arrives as bytes — the built-in miner's and an outside miner's
    /// `submit_block` alike — and its header commits the section's root, so
    /// the posting with the same parent and the same root is the one it was
    /// mined on. A block whose root is no posting's, or the empty section's,
    /// carries none, and the validator judges its root against that.
    fn posted_section(&self, block: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let Ok(block) = shekyl_wire::Block::from_bytes(block) else {
            return (Vec::new(), Vec::new());
        };
        let header = &block.header;
        let kept = self
            .postings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        kept.values()
            .filter_map(|posting| {
                let posted = &posting.job.block.header;
                let section = posting.section.as_ref()?;
                (posted.previous == header.previous && posted.section_root == header.section_root)
                    .then(|| {
                        (
                            section.references.as_slice().to_vec(),
                            section
                                .bodies
                                .iter()
                                .map(|body| body.as_bytes().to_vec())
                                .collect(),
                        )
                    })
            })
            .next()
            .unwrap_or_default()
    }

    /// The local-arrival entry (`DRS_X_STORE_FLIP.md` DX-Q3, Q6): a block this
    /// node mined, was submitted, or is connecting at genesis. It waits for
    /// the local seat while the window is full, offers the block as
    /// [`Origin::Local`], and awaits its one reply. A door that closes while
    /// it waits answers [`Reply::Stopped`]: the service is stopping, and the
    /// block was not accepted.
    ///
    /// The miner's sink, `block_submit`, `dev_block_generate` and the node's
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
        let (bundle_references, bundle_bodies) = self.posted_section(&block);
        let arrival = Arrival {
            tag,
            origin: Origin::Local,
            block,
            bodies,
            bundle_references,
            bundle_bodies,
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

    /// Offer a span of [`BoundArrival`]s, chain sync's typed entry: every
    /// arrival is accepted, or none is, judged exactly as
    /// [`Door::offer_span`] judges a solicited span. An accepted arrival is
    /// formed with `form_judged`, never `form`, so no second longhash runs.
    /// The tickets and replies are the same.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn offer_bound(&self, span: Vec<BoundArrival>) -> Result<Vec<Ticket>, Refusal> {
        let lengths: Vec<ArrivalLengths> = span.iter().map(BoundArrival::lengths).collect();
        let staged = span.into_iter().map(Staged::judged).collect();
        Ok(self.reserve(&lengths)?.accept(staged))
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
    /// The bundle producer, when the node mines and has a fetch path
    /// (`SO-D12` increment 4c). It files from the job seat's ring.
    #[cfg(feature = "producer")]
    pub producer: Option<crate::bundle_producer::ProducerSeat>,
    /// Wakes the tip follower when the pool's shown set changes at this
    /// tip (`DRS_X_STORE_FLIP.md` Q9). The composition root hands the same
    /// [`Notify`] the pool door's fluff hook fires. The connector fires it
    /// too, when the bundle queue admits a bundle at the tip. `None` is a
    /// private notify: tests that admit through the pool lock wake it
    /// themselves.
    pub shown: Option<Arc<Notify>>,
    /// The measurement sink the live phases are timed into: each
    /// `form_judged`, and each run the connector applies
    /// (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-5, the per-block profile). The
    /// composition root hands the proof-of-work boundary's own sink. `None`
    /// times nothing.
    pub metrics: Option<Arc<crate::metrics::Metrics>>,
    /// Chain sync's header frontier, for the ranked list (module docs,
    /// *The ranked list*). The node creates the channel before either
    /// service starts, and chain sync's owner holds the sender. `None`,
    /// and a sender that has closed, both rank without a frontier: the
    /// owner's own end reaches the node as its own, so a closed sender is
    /// not a fault here.
    pub frontier: Option<tokio::sync::watch::Receiver<Option<Frontier>>>,
}

/// Told the ids that left the pool on a reconcile.
pub type Departed = Arc<dyn Fn(&[TxHash]) + Send + Sync>;

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
    /// Told the ids that left on this reconcile: evicted to make room, and
    /// removed because the chain took them or the door now refuses them.
    /// The relay releases its responsibility for each (`DRS_X_STORE_FLIP.md`
    /// §2). Absent in a test that does not track responsibilities.
    pub departed: Option<Departed>,
}

/// Pops blocks for `dev_chain_pop` (`DRS_X_STORE_FLIP.md` DX-Q3, Q7), held
/// apart from the service ([`Service::rewinder`]).
pub struct Rewinder<P: Pow> {
    shared: Arc<Shared<P>>,
}

impl<P: Pow> Clone for Rewinder<P> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<P> Rewinder<P>
where
    P: Pow,
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
    pub async fn pop_blocks(&self, count: u64) -> Result<Rewound, ServiceFault<P::Fault>> {
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
pub struct Service<P: Pow> {
    door: Door,
    shared: Arc<Shared<P>>,
    task: tokio::task::JoinHandle<()>,
    connector_task: tokio::task::JoinHandle<
        Result<(Connector, kameo::error::ActorStopReason), kameo::error::PanicError>,
    >,
}

impl<P> Service<P>
where
    P: Pow,
{
    /// Start the service over `store`: the connector actor that alone writes
    /// it, and the loop that works each accepted span.
    #[must_use]
    pub fn start(
        store: Arc<ChainStore>,
        rules: ChainRules,
        pow: Arc<P>,
        config: ServiceConfig,
        follow: Follow,
    ) -> Self {
        let started = std::time::Instant::now();
        Self::start_with_clock(
            store,
            rules,
            pow,
            config,
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
        pow: Arc<P>,
        config: ServiceConfig,
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
        // The follower's one wake: a shown pool transaction and a bundle
        // the queue admits both rebuild the posted job through it.
        let pending_ready = follow.shown.unwrap_or_else(|| Arc::new(Notify::new()));
        let ranked = Arc::new(Notify::new());
        let prepared = PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
        let connector = prepared.actor_ref().clone();
        let connector_task = prepared.spawn(ConnectorArgs {
            store: Arc::clone(&store),
            rules,
            bundle_queued: Some(Arc::clone(&pending_ready)),
            ranked: Some(Arc::clone(&ranked)),
        });
        let shared = Arc::new(Shared {
            store,
            rules,
            pow,
            connector,
            filed: tokio::sync::broadcast::Sender::new(FILED_FEED_CAPACITY),
            stop_flag: Arc::new(AtomicBool::new(false)),
            stop: tokio::sync::watch::Sender::new(false),
            fault: Mutex::new(None),
            ended: tokio::sync::watch::Sender::new(None),
            ranked,
            rank_asked: std::sync::atomic::AtomicU64::new(0),
            rank_served: tokio::sync::watch::Sender::new(0),
            followed: tokio::sync::watch::Sender::new(0),
            metrics: follow.metrics,
            kept: crate::follower::Postings::default(),
            pool: follow.pool,
            pool_live: Arc::new(AtomicBool::new(true)),
            pending: Mutex::new(Vec::new()),
            pending_ready,
            #[cfg(test)]
            between_locks: Mutex::new(None),
        });
        {
            let shared = Arc::clone(&shared);
            admission.bind_read_fault(Arc::new(move |read| {
                window::record_store_read(&shared, read);
            }));
        }
        let (spans_tx, mut incoming) = mpsc::unbounded_channel::<Vec<Accepted>>();
        let door = Door {
            spans: spans_tx,
            room: crate::room::Room::new(config.room.get()),
            admission,
            connector: shared.connector.clone(),
            filed: shared.filed.clone(),
            postings: shared.postings(),
        };
        let loop_shared = Arc::clone(&shared);
        let loop_door = door.clone();
        let mut stopped = shared.stop.subscribe();
        let ranker = tokio::spawn(window::rank(Arc::clone(&shared), follow.frontier));
        let attendant_shared = Arc::clone(&shared);
        let attendant_door = door.clone();
        let job = follow.job;
        #[cfg(feature = "producer")]
        let producing = follow.producer.map(|seat| {
            let parts = crate::bundle_producer::ProducerParts {
                connector: shared.connector.clone(),
                filed: shared.filed.clone(),
                store: Arc::clone(&shared.store),
                rules: shared.rules,
            };
            let stop = shared.stop_signal();
            tokio::spawn(async move {
                let Ok(tips) = parts.connector.ask(WatchTip).await else {
                    return;
                };
                let (progress, _) = tokio::sync::watch::channel(Default::default());
                crate::bundle_producer::run(parts, tips, stop, seat, progress).await;
            })
        });
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
            if let Err(join) = ranker.await {
                tracing::error!("the ranker ended on a panic: {join}");
                loop_shared.fail(ServiceFault::RankerEnded);
            }
            #[cfg(feature = "producer")]
            if let Some(producing) = producing {
                if let Err(join) = producing.await {
                    tracing::error!("the bundle producer ended on a panic: {join}");
                }
            }
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
    ) -> Result<tokio::sync::watch::Receiver<crate::connector::TipChanged>, ServiceFault<P::Fault>>
    {
        self.shared
            .connector
            .ask(WatchTip)
            .await
            .map_err(|_| ServiceFault::Mailbox)
    }

    /// A receiver of the `following_degraded` latch (`DRS_X_STORE_FLIP.md`
    /// DX-Q2 item 8): `None` is clear, `Some` is the evidence that set it.
    ///
    /// # Errors
    ///
    /// The connector is gone.
    pub async fn watch_latch(
        &self,
    ) -> Result<
        tokio::sync::watch::Receiver<Option<shekyl_chain_store::codec::FollowingDegraded>>,
        ServiceFault<P::Fault>,
    > {
        self.shared
            .connector
            .ask(crate::connector::WatchLatch)
            .await
            .map_err(|_| ServiceFault::Mailbox)
    }

    /// Chain sync's past-cap evidence (`P2P_3_CHAIN_SYNC_BRIEF.md` §A item
    /// 7): the connector writes the latch in its own transaction. `true`
    /// when this call set it; a latch already set keeps its first evidence.
    ///
    /// # Errors
    ///
    /// The connector is gone, or the store refused the write.
    pub async fn raise_alarm(
        &self,
        evidence: shekyl_chain_store::codec::FollowingDegraded,
    ) -> Result<bool, ServiceFault<P::Fault>> {
        self.alarm()
            .raise(evidence)
            .await
            .map_err(|fault| match fault {
                AlarmFault::Connector(fault) => ServiceFault::Connector(fault),
                AlarmFault::Mailbox => ServiceFault::Mailbox,
            })
    }

    /// A cloneable handle on [`Self::raise_alarm`], for the sync owner, which
    /// does not hold the service.
    #[must_use]
    pub fn alarm(&self) -> Alarm {
        Alarm {
            connector: self.shared.connector.clone(),
        }
    }

    /// Why the service ended on its own, once it has: `None` while it
    /// runs, and after a stop that met no fault. The value is the fault's
    /// own words, published when the fault is recorded. The node forwards
    /// them to its end watch, and the daemon's exit line quotes them.
    #[must_use]
    pub fn ended(&self) -> tokio::sync::watch::Receiver<Option<ServiceEnd>> {
        self.shared.ended.subscribe()
    }

    /// The last `TipChanged` publication the tip follower acted on: what a
    /// caller waits on to know the pool and the miner's job are the tip's.
    #[must_use]
    pub fn followed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.shared.followed.subscribe()
    }

    /// Whether the pool file faulted and the pool was retired: no relay,
    /// no compact-block resolution and no transactions in a template until
    /// a restart. What `daemon_status` and `mine_status` report (PR 3b).
    #[must_use]
    pub fn pool_retired(&self) -> bool {
        self.shared.pool_retired()
    }

    /// What pops blocks for `dev_chain_pop`, held apart from the service.
    #[must_use]
    pub fn rewinder(&self) -> Rewinder<P> {
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
    pub async fn stop(self) -> Result<(), ServiceFault<P::Fault>> {
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

pub use crate::cache_window::Frontier;
pub(crate) use window::{divide_pool_faults, record_store_read, with_pool, PoolDivision};

#[cfg(test)]
#[path = "log_capture.rs"]
mod log_capture;

#[cfg(test)]
#[path = "service_tests.rs"]
pub(crate) mod service_tests;

#[cfg(test)]
#[path = "service_pool_tests.rs"]
mod service_pool_tests;

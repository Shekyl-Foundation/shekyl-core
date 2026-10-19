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

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kameo::actor::{ActorRef, PreparedActor};
use kameo::error::SendError;
use shekyl_chain_rules::{
    form, Candidate, FormAttempt, InvalidBlock, StructurallyValid, Substrate,
};
use shekyl_chain_store::store::{AltCannot, ChainStore, StoreCannot, StoreError};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, Transaction};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;

use crate::connector::{
    Apply, Connector, ConnectorArgs, ObserveTarget, OfferAlt, Offered, PopBeyondReorgCap,
    RefusePromotion, Reorganize, RunFault, Switched,
};
use crate::plan_form::{form_plan, PlanStop};
use crate::router::{claim_alt, claim_run, place, ClaimStop, Claims, Placed};
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

/// Why a span was not accepted. Never a peer fault; nothing was kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The service has no room for the span now ([`Door::room`]), or it is
    /// stopping.
    NoRoom,
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
    /// Stored, and the switch it makes due is deeper than the cap: local.
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
    /// The switch met the undo floor: this node cannot follow the heavier
    /// chain. Local; nothing moved.
    BelowFloor {
        /// The tip the pop met.
        tip: u64,
        /// The persisted floor.
        floor: u64,
    },
    /// Listed bodies neither the arrival carried nor the pool shows, by
    /// their index in the block's list: ask for them and offer it again.
    MissingBodies {
        /// The indices, ascending.
        indices: Vec<usize>,
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
/// sends [`Reply::Stopped`]; either way the arrival's room is given back.
struct ReplySlot {
    sender: Option<oneshot::Sender<Reply>>,
    room: Arc<AtomicUsize>,
}

impl ReplySlot {
    fn send(mut self, reply: Reply) {
        if let Some(sender) = self.sender.take() {
            // The caller dropped its ticket: the reply has no reader, and
            // the arrival is answered all the same.
            let _unread = sender.send(reply);
        }
    }
}

impl Drop for ReplySlot {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _unread = sender.send(Reply::Stopped);
        }
        self.room.fetch_add(1, Ordering::AcqRel);
    }
}

/// An accepted arrival, parsed or not.
struct Accepted {
    slot: ReplySlot,
    origin: Origin,
    block: Vec<u8>,
    bodies: Vec<Vec<u8>>,
}

/// What a span task carries for an arrival once its bytes parsed.
struct Parsed {
    slot: ReplySlot,
    block: Block,
    /// The carried bodies, by the hash they claim to list.
    bodies: Vec<Transaction>,
}

impl Parsed {
    fn hash(&self) -> BlockHash {
        self.block.hash()
    }
}

/// The service's knobs, each with its reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Arrivals accepted and not yet answered, at most: what the service
    /// holds in memory before any is formed.
    pub room: NonZeroUsize,
    /// `form` workers hashing at once (`PipelineConfig::hashers`' reason).
    pub hashers: NonZeroUsize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        let pipeline = crate::pipeline::PipelineConfig::default();
        Self {
            room: pipeline.window,
            hashers: pipeline.hashers,
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

/// What every span task shares.
struct Shared<S: Substrate> {
    store: Arc<ChainStore>,
    rules: ChainRules,
    substrate: Arc<S>,
    connector: ActorRef<Connector>,
    hashers: Arc<Semaphore>,
    threads: usize,
    /// Set once: the service is stopping (a stop, or a fault).
    stop: tokio::sync::watch::Sender<bool>,
    /// The first fault a span task met; the service ends on it.
    fault: Mutex<Option<ServiceFault<S::Fault>>>,
    /// The seed last pinned on the substrate.
    pinned: Mutex<Option<BlockHash>>,
}

impl<S: Substrate> Shared<S>
where
    S::Fault: core::fmt::Debug,
{
    fn stopping(&self) -> bool {
        *self.stop.borrow()
    }

    /// Record `fault` if it is the first, and stop.
    fn fail(&self, fault: ServiceFault<S::Fault>) {
        let mut first = self
            .fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        first.get_or_insert(fault);
        self.stop.send_replace(true);
    }
}

/// The door: the one way in (module docs). Cheap to clone.
#[derive(Clone)]
pub struct Door {
    spans: mpsc::UnboundedSender<Vec<Accepted>>,
    room: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
}

impl Door {
    /// Arrivals the service will accept now.
    #[must_use]
    pub fn room(&self) -> usize {
        if self.closed.load(Ordering::Acquire) {
            return 0;
        }
        self.room.load(Ordering::Acquire)
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

    /// Offer a span: every arrival in it is accepted, or none is.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn offer_span(&self, span: Vec<Arrival>) -> Result<Vec<Ticket>, Refusal> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Refusal::NoRoom);
        }
        let n = span.len();
        if self
            .room
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |free| {
                free.checked_sub(n)
            })
            .is_err()
        {
            return Err(Refusal::NoRoom);
        }
        let mut tickets = Vec::with_capacity(n);
        let mut accepted = Vec::with_capacity(n);
        for arrival in span {
            let (sender, receiver) = oneshot::channel();
            tickets.push(Ticket {
                tag: arrival.tag,
                reply: receiver,
            });
            accepted.push(Accepted {
                slot: ReplySlot {
                    sender: Some(sender),
                    room: Arc::clone(&self.room),
                },
                origin: arrival.origin,
                block: arrival.block,
                bodies: arrival.bodies,
            });
        }
        // A service that has ended drops the span here, and each slot
        // answers `Stopped`.
        let _ended = self.spans.send(accepted);
        Ok(tickets)
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
    ) -> Self {
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
            hashers: Arc::new(Semaphore::new(config.hashers.get())),
            threads: config.hashers.get(),
            stop: tokio::sync::watch::Sender::new(false),
            fault: Mutex::new(None),
            pinned: Mutex::new(None),
        });
        let (spans, mut incoming) = mpsc::unbounded_channel::<Vec<Accepted>>();
        let door = Door {
            spans,
            room: Arc::new(AtomicUsize::new(config.room.get())),
            closed: Arc::new(AtomicBool::new(false)),
        };
        let loop_shared = Arc::clone(&shared);
        let mut stopped = shared.stop.subscribe();
        let task = tokio::spawn(async move {
            let mut spans: JoinSet<()> = JoinSet::new();
            loop {
                tokio::select! {
                    next = incoming.recv() => {
                        let Some(span) = next else { break };
                        if loop_shared.stopping() {
                            drop(span);
                            continue;
                        }
                        spans.spawn(run_span(Arc::clone(&loop_shared), span));
                    }
                    Some(_done) = spans.join_next(), if !spans.is_empty() => {}
                    _ = stopped.wait_for(|stopping| *stopping) => break,
                }
            }
            // Every span still queued answers `Stopped`; every running one
            // finishes its current step and drops the rest.
            incoming.close();
            while let Some(span) = incoming.recv().await {
                drop(span);
            }
            while spans.join_next().await.is_some() {}
        });
        Self {
            door,
            shared,
            task,
            connector_task,
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
        self.door.closed.store(true, Ordering::Release);
        self.shared.stop.send_replace(true);
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

/// A connector reply's error without the message type: the handler's
/// fault, or the mailbox.
enum Asked {
    Fault(RunFault),
    Mailbox,
}

impl<M> From<SendError<M, RunFault>> for Asked {
    fn from(err: SendError<M, RunFault>) -> Self {
        match err {
            SendError::HandlerError(fault) => Self::Fault(fault),
            SendError::ActorNotRunning(_)
            | SendError::ActorStopped
            | SendError::MailboxFull(_)
            | SendError::Timeout(_) => Self::Mailbox,
        }
    }
}

impl Asked {
    /// The service's fault for a reply that is not a stale placement.
    fn into_fault<F>(self) -> ServiceFault<F> {
        match self {
            Self::Fault(fault) => ServiceFault::Connector(fault),
            Self::Mailbox => ServiceFault::Mailbox,
        }
    }
}

/// A connector reply's error, as the service's fault.
fn unreachable_or<M, F>(err: SendError<M, RunFault>) -> ServiceFault<F> {
    Asked::from(err).into_fault()
}

/// Whether a connector fault is a stale placement: the arrival is placed
/// again (module docs), never refused.
const fn is_stale(fault: &RunFault) -> bool {
    matches!(
        fault,
        RunFault::HeightClaim { .. }
            | RunFault::StaleSeed { .. }
            | RunFault::StaleTarget { .. }
            | RunFault::StaleReference { .. }
            | RunFault::NotAlternative { .. }
    )
}

/// Parse one accepted arrival: the block and its carried bodies. A blob the
/// wire cannot parse is a verdict against the block (CEN-A6's holder); a
/// carried body that does not parse is a body the block's list cannot
/// pair (CEN-G2's).
fn parse(accepted: Accepted) -> Result<(Parsed, Origin), (ReplySlot, InvalidBlock)> {
    let Accepted {
        slot,
        origin,
        block,
        bodies,
    } = accepted;
    let Ok(block) = Block::from_bytes(&block) else {
        return Err((
            slot,
            InvalidBlock::new(
                shekyl_chain_rules::CenRow::A6,
                shekyl_chain_rules::Locus::Block,
            ),
        ));
    };
    let mut parsed = Vec::with_capacity(bodies.len());
    for body in &bodies {
        let Ok(tx) = Transaction::from_bytes(body) else {
            return Err((
                slot,
                InvalidBlock::new(
                    shekyl_chain_rules::CenRow::G2,
                    shekyl_chain_rules::Locus::Block,
                ),
            ));
        };
        parsed.push(tx);
    }
    Ok((
        Parsed {
            slot,
            block,
            bodies: parsed,
        },
        origin,
    ))
}

/// The candidate for `parsed`: its listed bodies in listed order, then any
/// carried body the list does not name (G2 refuses it in `form`); or the
/// indices of the listed bodies nothing supplies.
fn assemble(parsed: &Parsed) -> Result<Candidate, Vec<usize>> {
    let mut carried: Vec<Option<&Transaction>> = parsed.bodies.iter().map(Some).collect();
    let mut listed = Vec::with_capacity(parsed.block.transaction_hashes.len());
    let mut missing = Vec::new();
    for (index, txid) in parsed.block.transaction_hashes.iter().enumerate() {
        let found = carried
            .iter_mut()
            .find(|slot| slot.is_some_and(|tx| tx.txid_parts().hash == *txid))
            .and_then(Option::take);
        match found {
            Some(tx) => listed.push(tx.clone()),
            None => missing.push(index),
        }
    }
    if !missing.is_empty() {
        return Err(missing);
    }
    listed.extend(carried.into_iter().flatten().cloned());
    Ok(Candidate::new(parsed.block.clone(), listed))
}

/// Work one accepted span (module docs).
async fn run_span<S>(shared: Arc<Shared<S>>, span: Vec<Accepted>)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let mut queue: VecDeque<Parsed> = VecDeque::with_capacity(span.len());
    for accepted in span {
        match parse(accepted) {
            Ok((parsed, _origin)) => queue.push_back(parsed),
            Err((slot, refused)) => slot.send(Reply::Refused(refused)),
        }
    }
    while let Some(front) = queue.pop_front() {
        if shared.stopping() {
            return;
        }
        let candidate = match assemble(&front) {
            Ok(candidate) => candidate,
            Err(indices) => {
                front.slot.send(Reply::MissingBodies { indices });
                continue;
            }
        };
        let placed = match place(&shared.store, &front.block) {
            Ok(placed) => placed,
            Err(e) => return shared.fail(e.into()),
        };
        match placed {
            Placed::AlreadyHeld => front.slot.send(Reply::AlreadyHeld),
            Placed::Unlinked { at } => front.slot.send(Reply::Unlinked { at }),
            Placed::Alt => {
                if let Some(again) = offer_alt(&shared, front, candidate).await {
                    queue.push_front(again);
                }
            }
            Placed::Extend { height } => {
                // The run: this arrival, then each next one whose parent is
                // the one before it.
                let mut run = vec![(front, candidate)];
                while let Some(next) = queue.front() {
                    if next.block.header.previous != run[run.len() - 1].0.hash() {
                        break;
                    }
                    let Ok(next_candidate) = assemble(next) else {
                        break;
                    };
                    let next = queue.pop_front().expect("peeked");
                    run.push((next, next_candidate));
                }
                for again in extend_run(&shared, height, run).await.into_iter().rev() {
                    queue.push_front(again);
                }
            }
        }
    }
}

/// Pin `seed` on the substrate if it is not the pinned one: the pipeline's
/// seed claim is the one derivation the budget allows (PR2-Q3).
async fn pin<S>(shared: &Arc<Shared<S>>, seed: BlockHash)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    if seed == BlockHash::NULL {
        return;
    }
    {
        let pinned = shared
            .pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *pinned == Some(seed) {
            return;
        }
    }
    let substrate = Arc::clone(&shared.substrate);
    let _joined = tokio::task::spawn_blocking(move || substrate.pin_seed(&seed)).await;
    *shared
        .pinned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(seed);
}

/// `form` one block under a hasher permit, off the runtime's threads.
async fn form_one<S>(
    shared: &Arc<Shared<S>>,
    candidate: Candidate,
    claims: Claims,
) -> Result<Result<StructurallyValid, InvalidBlock>, S::Fault>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    pin(shared, claims.seed).await;
    let permit = Arc::clone(&shared.hashers)
        .acquire_owned()
        .await
        .expect("the hasher semaphore is never closed");
    let substrate = Arc::clone(&shared.substrate);
    tokio::task::spawn_blocking(move || {
        let verdict = form(
            candidate,
            &claims.rule_set,
            &*substrate,
            claims.seed,
            claims.target,
            &claims.references,
            FormAttempt::FIRST,
        );
        drop(permit);
        verdict
    })
    .await
    .expect("a form worker does not panic")
}

/// A run extending the tip from `first`: claims off one snapshot, every
/// block formed in parallel, connected in order. Returns the arrivals to
/// place again (a stale placement, or blocks after one), in order.
async fn extend_run<S>(
    shared: &Arc<Shared<S>>,
    first: BlockHeight,
    run: Vec<(Parsed, Candidate)>,
) -> Vec<Parsed>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let candidates: Vec<Candidate> = run.iter().map(|(_, c)| c.clone()).collect();
    let store = Arc::clone(&shared.store);
    let rules = shared.rules;
    let (claims, stop) =
        tokio::task::spawn_blocking(move || claim_run(&store, rules, first, &candidates))
            .await
            .expect("the claim reader does not panic");
    let claimed = claims.len();
    let mut arrivals: VecDeque<(Parsed, Candidate)> = run.into();
    // Form every claimed block at once; each waits for a permit.
    let mut forming = Vec::with_capacity(claimed);
    for (claim, (_, candidate)) in claims.into_iter().zip(arrivals.iter()) {
        let shared = Arc::clone(shared);
        let candidate = candidate.clone();
        let height = claim.height;
        forming.push((
            height,
            tokio::spawn(async move { form_one(&shared, candidate, claim).await }),
        ));
    }
    for (height, handle) in forming {
        let (arrival, _) = arrivals.pop_front().expect("one arrival per claim");
        if shared.stopping() {
            return Vec::new();
        }
        let formed = match handle.await.expect("a form task does not panic") {
            Ok(formed) => formed,
            Err(fault) => {
                shared.fail(ServiceFault::Substrate(fault));
                return Vec::new();
            }
        };
        let formed = match formed {
            Ok(formed) => formed,
            Err(refused) => {
                arrival.slot.send(Reply::Refused(refused));
                return arrivals.into_iter().map(|(a, _)| a).collect();
            }
        };
        match shared
            .connector
            .ask(Apply(vec![(height, Ok(formed))]))
            .await
        {
            Ok(applied) => match applied.refused {
                Some((_, refused)) => {
                    arrival.slot.send(Reply::Refused(refused));
                    return arrivals.into_iter().map(|(a, _)| a).collect();
                }
                None => {
                    let (height, hash) = applied.connected[0];
                    arrival.slot.send(Reply::Connected { height, hash });
                }
            },
            Err(SendError::HandlerError(fault)) if is_stale(&fault) => {
                let mut again = vec![arrival];
                again.extend(arrivals.into_iter().map(|(a, _)| a));
                return again;
            }
            Err(err) => {
                shared.fail(unreachable_or(err));
                return Vec::new();
            }
        }
    }
    match stop {
        None => Vec::new(),
        Some(ClaimStop::Refused { refused, .. }) => {
            let (arrival, _) = arrivals.pop_front().expect("the refused block is next");
            arrival.slot.send(Reply::Refused(refused));
            arrivals.into_iter().map(|(a, _)| a).collect()
        }
        Some(ClaimStop::Corrupt { height, .. }) => {
            // The writer re-derives the window over its own view and halts
            // on what it sees; a consistent view means the run's ledger was
            // the defect, and the arrivals are placed again.
            match shared.connector.ask(ObserveTarget { height }).await {
                Ok(()) => arrivals.into_iter().map(|(a, _)| a).collect(),
                Err(SendError::HandlerError(fault)) if is_stale(&fault) => {
                    arrivals.into_iter().map(|(a, _)| a).collect()
                }
                Err(err) => {
                    shared.fail(unreachable_or(err));
                    Vec::new()
                }
            }
        }
        Some(ClaimStop::Store(e)) => {
            shared.fail(e.into());
            Vec::new()
        }
    }
}

/// An alternative arrival: claims on its own chain, `form`, `OfferAlt`,
/// and the switch it makes due. Returns the arrival if it is to be placed
/// again.
async fn offer_alt<S>(
    shared: &Arc<Shared<S>>,
    arrival: Parsed,
    candidate: Candidate,
) -> Option<Parsed>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let store = Arc::clone(&shared.store);
    let rules = shared.rules;
    let for_claims = candidate.clone();
    let claims = tokio::task::spawn_blocking(move || claim_alt(&store, rules, &for_claims))
        .await
        .expect("the claim reader does not panic");
    let claims = match claims {
        Ok(claims) => claims,
        Err(ClaimStop::Refused { refused, .. }) => {
            arrival.slot.send(Reply::Refused(refused));
            return None;
        }
        // The parent left the store between the placement and the claim.
        Err(ClaimStop::Store(StoreError::Cannot(StoreCannot::Alt(AltCannot::Unlinked {
            ..
        })))) => return Some(arrival),
        Err(ClaimStop::Store(e)) => {
            shared.fail(e.into());
            return None;
        }
        // A corrupt window on the stitched view is the store's state, not
        // the arrival's: placing it again would read the same rows.
        Err(ClaimStop::Corrupt { height, corrupt }) => {
            shared.fail(ServiceFault::Corrupt { height, corrupt });
            return None;
        }
    };
    let formed = match form_one(shared, candidate, claims).await {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => {
            arrival.slot.send(Reply::Refused(refused));
            return None;
        }
        Err(fault) => {
            shared.fail(ServiceFault::Substrate(fault));
            return None;
        }
    };
    let offered = match shared.connector.ask(OfferAlt(formed)).await {
        Ok(offered) => offered,
        Err(SendError::HandlerError(fault)) if is_stale(&fault) => return Some(arrival),
        Err(err) => {
            shared.fail(unreachable_or(err));
            return None;
        }
    };
    let reply = match offered {
        Offered::Refused(refused) => Reply::Refused(refused),
        Offered::Unlinked { at } => Reply::Unlinked { at },
        Offered::AlreadyHeld => Reply::AlreadyHeld,
        Offered::Held { height } => Reply::Held { height },
        Offered::BeyondCap(beyond) => Reply::BeyondCap(beyond),
        Offered::SwitchDue(plan) => match carry_out(shared, plan).await {
            Some(reply) => reply,
            None => return None,
        },
    };
    arrival.slot.send(reply);
    None
}

/// Carry out a switch an arrival made due: form the plan's blocks off the
/// runtime, then `Reorganize` (or `RefusePromotion`). `None` when the
/// service failed.
async fn carry_out<S>(shared: &Arc<Shared<S>>, plan: crate::connector::SwitchPlan) -> Option<Reply>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let substrate = Arc::clone(&shared.substrate);
    let rules = shared.rules;
    let threads = shared.threads;
    let hashers = Arc::clone(&shared.hashers);
    let runtime = tokio::runtime::Handle::current();
    let (plan, formed) = tokio::task::spawn_blocking(move || {
        // The plan forms on scoped threads outside the runtime: each takes
        // its permit by blocking on the runtime's semaphore through the
        // handle taken here.
        let gate = move || -> Box<dyn Send> {
            Box::new(
                runtime
                    .block_on(Arc::clone(&hashers).acquire_owned())
                    .expect("the hasher semaphore is never closed"),
            )
        };
        let formed = form_plan(&plan, rules, &*substrate, threads, &gate);
        (plan, formed)
    })
    .await
    .expect("the plan's forming does not panic");
    let switched = match formed {
        Ok(formed) => shared
            .connector
            .ask(Reorganize {
                tip: plan.tip,
                alt_tip: plan.alt_tip,
                demoted: formed.demoted,
                promoted: formed.promoted,
            })
            .await
            .map_err(Asked::from),
        Err(PlanStop::Refused(refusal)) if refusal.demoted => {
            shared.fail(ServiceFault::DemotionRefused {
                hash: refusal.hash,
                refused: refusal.refused,
            });
            return None;
        }
        Err(PlanStop::Refused(refusal)) => shared
            .connector
            .ask(RefusePromotion {
                tip: plan.tip,
                alt_tip: plan.alt_tip,
                hash: refusal.hash,
                refused: refusal.refused,
            })
            .await
            .map_err(Asked::from),
        Err(PlanStop::Substrate(fault)) => {
            shared.fail(ServiceFault::Substrate(fault));
            return None;
        }
    };
    match switched {
        Ok(Switched::Done(done)) => Some(Reply::Switched {
            demoted: done.demoted,
            promoted: done.promoted,
        }),
        Ok(Switched::Refused {
            at, hash, refused, ..
        }) => Some(Reply::PromotionRefused { at, hash, refused }),
        Ok(Switched::BeyondCap(beyond)) => Some(Reply::BeyondCap(beyond)),
        Ok(Switched::BelowFloor { tip, floor }) => Some(Reply::BelowFloor { tip, floor }),
        // The tip moved while the plan formed: the stored block stays, and
        // the next arrival's offer makes the switch due again against the
        // new tip.
        Err(Asked::Fault(RunFault::StalePlan { .. })) => Some(Reply::Held {
            height: plan
                .promoted
                .last()
                .map_or(plan.root.height, |p| p.at.height),
        }),
        Err(err) => {
            shared.fail(err.into_fault());
            None
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod service_tests;

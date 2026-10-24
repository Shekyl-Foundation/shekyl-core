// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tip attendant: the ingest service's one consumer of [`TipChanged`]
//! (`DRS_X_STORE_FLIP.md` DX-Q2 item 5).
//!
//! One task always runs. Per publication, in order:
//! 1. the seed window: the two caches the reorg cap can name, pinned under
//!    one chain permit, transient then canonical. Published before any
//!    arrival hashes. An alternative never pins;
//! 2. the pool reconciled to the tip. File entries are judged outside the
//!    pool lock. Bodies a span parked because the tip moved are judged
//!    here. A pool-file fault retires the pool and does not stop ingest;
//! 3. the node's one template, built and posted while chain sync's state
//!    reads `Synced` and a `mine-address` is set (`template` module docs;
//!    `DRS_X_STORE_FLIP.md` DX-Q3, N2). The canonical seed is already
//!    `seed(connecting)`, which is the seed the job hashes under. The job
//!    does not pin. A seed the slots do not hold leaves the current job in
//!    place; the next publication tries again. Every other pass that posts
//!    nothing withdraws the job and says why ([`Posting`]).
//!
//! **The found-block sink.** A found block enters through the service's
//! one door as a local arrival. A full window waits for the reserved seat
//! instead of dropping the block. A closed door drops it. The service
//! closes the inbox on the way out, so the sink ends while a sender still
//! lives, and the thread is joined only after it has left the door.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_block_template::MinerKeys;
use shekyl_chain_rules::{
    Fault, HeaderView, InvalidBlock, StatelessPass, Substrate, Tip, ViewRead,
};
use shekyl_chain_store::store::{SnapshotView, StoreError};
use shekyl_chain_sync::SyncState;
use shekyl_economics::EconomicParams;
use shekyl_mempool::{stateless, PoolFault};
use shekyl_miner::{FoundInbox, Generation, JobBoard};
use shekyl_types::TxHash;
use shekyl_wire::Transaction;
use tokio::sync::watch;

use crate::connector::{FactsStop, TipChanged};
use crate::router::ClaimStop;
use crate::schedule::ChainRules;
use crate::service::{
    divide_pool_faults, install_window, with_pool, ArrivalTag, Door, PoolDivision, ServiceFault,
    Shared,
};
use crate::template::{produce, NoTemplate, Producer};

/// Why the board holds no job: what `mining_status` and
/// `get_block_template` say while nothing is posted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoJob {
    /// The follower has not acted on a tip yet.
    Starting,
    /// No `mine-address` row: there is no one for a coinbase to pay.
    NoAddress,
    /// Chain sync does not say this node is synced.
    NotSynced(SyncState),
    /// The pool file faulted. The node runs without a pool, and builds no
    /// template, until it restarts.
    PoolRetired,
    /// The template could not be built, and why.
    Unbuilt(Unbuilt),
    /// The service stopped.
    Stopped,
}

impl core::fmt::Display for NoJob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Starting => f.write_str("no template: the node is starting"),
            Self::NoAddress => f.write_str("no template: no mine-address is set"),
            Self::NotSynced(SyncState::NoView) => {
                f.write_str("no template: not synced (no sync owner before chain sync's cutover)")
            }
            Self::NotSynced(state) => write!(f, "no template: not synced ({})", state.name()),
            Self::PoolRetired => {
                f.write_str("no template: the pool file faulted; restart the node to reopen it")
            }
            Self::Unbuilt(why) => write!(f, "no template: {why}"),
            Self::Stopped => f.write_str("no template: the node is stopping"),
        }
    }
}

impl NoJob {
    /// Whether the next tip clears this reason.
    ///
    /// `generateblocks` keeps waiting while the board is withdrawn for one
    /// of these: the follower posts again when the tip moves, or when the
    /// first pass finishes.
    #[must_use]
    pub const fn transient(&self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Unbuilt(Unbuilt::PoolOnAnotherTip | Unbuilt::BodyGone)
        )
    }
}

/// Why a template could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unbuilt {
    /// The store faulted; the service is stopping.
    StoreFault,
    /// The store is corrupt; the service is stopping.
    StoreCorrupt,
    /// The pool's selection could not read the chain; the service is
    /// stopping.
    Selection,
    /// The node's clock could not be read.
    Clock,
    /// The OS random source failed.
    Random,
    /// The block could not be priced or assembled.
    Pricing,
    /// The built coinbase reserves no extra nonce.
    NoNonceSlot,
    /// The tip is the last height there is.
    LastHeight,
    /// The chain's own headers refuse the next block's target.
    TargetRefused,
    /// A seed block is not on the snapshot it was read from.
    SeedMissing,
    /// The pool was last judged against another tip; the follower builds
    /// again.
    PoolOnAnotherTip,
    /// A listed body left the pool between the producer's two locks; the
    /// follower builds again, without it.
    BodyGone,
    /// The template producer panicked; the service is stopping.
    ProducerPanicked,
}

impl core::fmt::Display for Unbuilt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::StoreFault => "the store faulted",
            Self::StoreCorrupt => "the store is corrupt",
            Self::Selection => "the pool's selection could not read the chain",
            Self::Clock => "the clock could not be read",
            Self::Random => "the OS random source failed",
            Self::Pricing => "the block could not be priced",
            Self::NoNonceSlot => "the coinbase reserves no extra nonce",
            Self::LastHeight => "the tip is the last height there is",
            Self::TargetRefused => "the chain's own headers refuse its target",
            Self::SeedMissing => "a seed block is not on the snapshot",
            Self::PoolOnAnotherTip => "the pool was judged against another tip",
            Self::BodyGone => "a listed body left the pool while the template was built",
            Self::ProducerPanicked => "the template producer panicked",
        })
    }
}

impl Unbuilt {
    /// The RPC `kind` parameter under `mine.unbuilt`.
    ///
    /// These spellings are the contract. A rename is a wire change.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StoreFault => "store_fault",
            Self::StoreCorrupt => "store_corrupt",
            Self::Selection => "selection",
            Self::Clock => "clock",
            Self::Random => "random",
            Self::Pricing => "pricing",
            Self::NoNonceSlot => "no_nonce_slot",
            Self::LastHeight => "last_height",
            Self::TargetRefused => "target_refused",
            Self::SeedMissing => "seed_missing",
            Self::PoolOnAnotherTip => "pool_on_another_tip",
            Self::BodyGone => "body_gone",
            Self::ProducerPanicked => "producer_panicked",
        }
    }
}

/// What the board holds, as the follower last left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Posting {
    /// A job, at this generation.
    Posted(Generation),
    /// No job, and why.
    Withdrawn(NoJob),
}

/// The miner's inbox and chain sync's state.
pub struct MinerFeed {
    /// Where found blocks arrive. Closed when the service stops, which
    /// ends the sink while a sender still lives. The last sender dropping
    /// ends it too.
    pub found: FoundInbox,
    /// Chain sync's state. The follower posts a job only while it reads
    /// [`SyncState::Synced`]; a closed watch reads as
    /// [`SyncState::NoView`].
    pub sync: watch::Receiver<SyncState>,
}

/// The board the follower posts the node's one template on
/// (`DRS_X_STORE_FLIP.md` DX-Q3, N2), and what it is built from.
pub struct JobSeat {
    /// The board the miner's workers and `get_block_template` read.
    pub board: Arc<JobBoard>,
    /// Whom the coinbase pays: the `mine-address` row's keys. `None`
    /// posts nothing.
    pub keys: Option<MinerKeys>,
    /// The miner's inbox and the sync watch.
    pub miner: MinerFeed,
    /// Where the follower says what the board holds.
    pub posting: watch::Sender<Posting>,
}

/// Jobs kept for the found-block sink: a found block's generation names
/// the bodies it was built with. A miner finds for the newest posting, so
/// only the last few are ever asked for.
const KEPT_JOBS: usize = 8;

/// The found-block sink's thread. Short enough for a platform thread name.
const FOUND_SINK_THREAD: &str = "shekyl-found";

/// Each posted generation's listed bodies.
pub(crate) type Postings = Arc<Mutex<BTreeMap<Generation, Vec<Transaction>>>>;

/// Withdraws the miner's job on every way out, including a panic, and
/// says so.
struct BoardGuard(Option<(Arc<JobBoard>, watch::Sender<Posting>)>);

impl Drop for BoardGuard {
    fn drop(&mut self) {
        if let Some((board, posting)) = self.0.take() {
            board.withdraw();
            posting.send_replace(Posting::Withdrawn(NoJob::Stopped));
        }
    }
}

/// The seat, once the inbox has been handed to the sink.
struct Seated {
    board: Arc<JobBoard>,
    keys: Option<MinerKeys>,
    sync: Option<watch::Receiver<SyncState>>,
    posting: watch::Sender<Posting>,
}

impl Seated {
    /// Withdraw the job, and say why.
    fn withdraw(&self, why: NoJob) {
        self.board.withdraw();
        self.posting.send_replace(Posting::Withdrawn(why));
    }
}

/// The sink thread, the inbox that closes it, and the signal it sends
/// when it leaves the loop. The await on `done` yields before the join,
/// so a ticket the sink holds can be answered by the service task.
struct SinkJoin {
    thread: std::thread::JoinHandle<()>,
    inbox: FoundInbox,
    done: tokio::sync::oneshot::Receiver<()>,
}

/// Run the attendant until the service stops (module docs).
pub(crate) async fn follow<S>(
    shared: Arc<Shared<S>>,
    door: Door,
    mut tips: watch::Receiver<TipChanged>,
    job: Option<JobSeat>,
) where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let postings: Postings = Arc::new(Mutex::new(BTreeMap::new()));
    let (mut seat, sink) = match job {
        Some(JobSeat {
            board,
            keys,
            miner: MinerFeed { found, sync },
            posting,
        }) => {
            let inbox = found.clone();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let thread = spawn_sink(found, door.clone(), Arc::clone(&postings), done_tx);
            posting.send_replace(Posting::Withdrawn(NoJob::Starting));
            (
                Some(Seated {
                    board,
                    keys,
                    sync: Some(sync),
                    posting,
                }),
                Some(SinkJoin {
                    thread,
                    inbox,
                    done: done_rx,
                }),
            )
        }
        None => (None, None),
    };
    let _board = BoardGuard(
        seat.as_ref()
            .map(|seat| (Arc::clone(&seat.board), seat.posting.clone())),
    );
    let mut stopping = shared.stop_signal();
    loop {
        if shared.stopping() {
            break;
        }
        let tip = *tips.borrow_and_update();
        if let Err(read) = install_window(&shared).await {
            crate::service::record_store_read(&shared, read);
            break;
        }
        if shared.stopping() {
            break;
        }
        // The pool, before the job, so a template never lists a transaction
        // the tip just mined.
        reconcile(&shared).await;
        if shared.stopping() {
            break;
        }
        if let Some(seat) = seat.as_mut() {
            // A closed watch still holds its last value; it reads as no
            // view from the moment it closes, whichever branch woke us.
            let state = match seat.sync.as_mut() {
                Some(sync) if sync.has_changed().is_ok() => *sync.borrow_and_update(),
                _ => {
                    seat.sync = None;
                    SyncState::NoView
                }
            };
            match (&seat.keys, state) {
                (None, _) => seat.withdraw(NoJob::NoAddress),
                (Some(_), SyncState::Synced) => post(&shared, seat, &postings).await,
                (Some(_), behind) => seat.withdraw(NoJob::NotSynced(behind)),
            }
        }
        shared.followed(tip.seq);
        let sync_changed = async {
            match seat.as_mut().and_then(|seat| seat.sync.as_mut()) {
                Some(sync) => sync.changed().await.is_err(),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            changed = tips.changed() => if changed.is_err() { break },
            // The sync owner is gone: nothing says this node is synced
            // any more. That is "behind" — the job is withdrawn on the
            // next pass — not a reason to stop following the chain.
            closed = sync_changed => if closed {
                if let Some(seat) = seat.as_mut() {
                    seat.sync = None;
                }
            },
            () = shared.pending_ready().notified() => {}
            _ = stopping.wait_for(|stop| *stop) => break,
        }
    }
    door.close();
    if let Some(SinkJoin {
        thread,
        inbox,
        done,
    }) = sink
    {
        // Close the inbox before waiting, so a sink blocked in `recv`
        // wakes while a sender still lives. The wait yields this task:
        // the service task can then answer a queued local arrival, which
        // a sink waits on in `offer_local`. The join is after that answer,
        // so it does not occupy the worker the reply needs.
        inbox.close();
        if done.await.is_err() {
            tracing::error!("the found-block sink ended without signalling");
        }
        if thread.join().is_err() {
            tracing::error!("the found-block sink panicked");
        }
    }
}

/// Step 1 for transactions judged outside the pool lock.
struct Planted {
    staged: Vec<(TxHash, Result<StatelessPass, InvalidBlock>)>,
    pending: Vec<(Transaction, Result<StatelessPass, InvalidBlock>)>,
}

enum PlantFault {
    Store(StoreError),
    Chain(Fault<StoreError>),
}

/// Reconcile the pool. File entries and parked bodies are judged before
/// the lock. A pool-file fault retires the pool. A chain fault stops the
/// service. A tip that moved parks the bodies without waking: the next tip
/// retries them.
async fn reconcile<S>(shared: &Arc<Shared<S>>)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    if !shared.pool_is_live() {
        return;
    }
    let pending = shared.take_pending();
    // Listed under the lock, verified outside it: entries with no pass yet,
    // and passes the new tip no longer supports (a reorg moved their
    // reference). The reconcile then verifies nothing while it holds the
    // pool, unless the tip moves again between the two.
    let unverified = match with_pool(shared, |pool, _, view, rule_set, _, _| {
        pool.needing_step1(view, rule_set)
    })
    .await
    {
        None => Vec::new(),
        Some(Ok(Ok(needing))) => needing,
        Some(Ok(Err(view)) | Err(view)) => return shared.fail(ServiceFault::Store(view)),
    };
    let planted = if unverified.is_empty() && pending.is_empty() {
        None
    } else {
        match plant(shared, unverified, pending).await {
            Ok(planted) => Some(planted),
            Err(PlantFault::Store(store)) => return shared.fail(store.into()),
            Err(PlantFault::Chain(fault)) => {
                return shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
            }
        }
    };
    let done = with_pool(shared, move |pool, _, view, rule_set, policy, now| {
        let mut division = PoolDivision::default();
        if let Some(planted) = planted {
            for (txid, step1) in planted.staged {
                pool.stage_step1(txid, step1);
            }
            if !planted.pending.is_empty() {
                let bodies: Vec<Transaction> =
                    planted.pending.iter().map(|(tx, _)| tx.clone()).collect();
                let offers = pool.offer_prepared(planted.pending, now, view, rule_set, policy);
                division = divide_pool_faults(offers.faults, &bodies);
            }
        }
        let reconciled = pool.reconcile(view, rule_set, policy).err();
        (division, reconciled)
    })
    .await;
    let (division, reconciled) = match done {
        None => return,
        Some(Err(store)) => return shared.fail(ServiceFault::Store(store)),
        Some(Ok(round)) => round,
    };
    if let Some(fault) = division.chain {
        shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
        return;
    }
    if let Some(PoolFault::Chain(fault)) = reconciled {
        shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
        return;
    }
    let file = match reconciled {
        Some(PoolFault::Store(store)) => Some(store),
        _ => division.file,
    };
    if let Some(store) = file {
        shared.pool_dead(&store);
        return;
    }
    // No wake: the next tip, or the next span that hands bodies, retries.
    shared.park_pending(division.parked);
}

async fn plant<S>(
    shared: &Arc<Shared<S>>,
    unverified: Vec<(TxHash, Transaction)>,
    pending: Vec<Transaction>,
) -> Result<Planted, PlantFault>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let store = std::sync::Arc::clone(shared.store());
    let rules = shared.rules();
    tokio::task::spawn_blocking(move || plant_blocking(&store, rules, unverified, pending))
        .await
        .expect("judging pool entries does not panic")
}

fn plant_blocking(
    store: &shekyl_chain_store::store::ChainStore,
    rules: ChainRules,
    unverified: Vec<(TxHash, Transaction)>,
    pending: Vec<Transaction>,
) -> Result<Planted, PlantFault> {
    let snap = store.begin_read().map_err(PlantFault::Store)?;
    let view = SnapshotView::new(&snap);
    let tip = HeaderView::tip(&view)
        .map_err(Fault::View)
        .map_err(PlantFault::Chain)?;
    let rule_set = rules.in_force(Tip::connecting_height(tip.as_ref()));
    let mut staged = Vec::with_capacity(unverified.len());
    for (txid, tx) in unverified {
        match stateless(&tx, &view, &rule_set, None) {
            Ok(step1) => staged.push((txid, step1)),
            Err(fault) => return Err(PlantFault::Chain(fault)),
        }
    }
    let mut prepared = Vec::with_capacity(pending.len());
    for tx in pending {
        match stateless(&tx, &view, &rule_set, None) {
            Ok(step1) => prepared.push((tx, step1)),
            Err(fault) => return Err(PlantFault::Chain(fault)),
        }
    }
    Ok(Planted {
        staged,
        pending: prepared,
    })
}

/// Build and post the job for the block after the tip (`template`
/// module docs). The window is already pinned. A seed the slots do not
/// hold leaves the current job; the next publication tries again.
///
/// The build runs on a blocking thread and takes no hasher permit: one
/// more blocking task than the permits (`shekyl-node`, "Blocking
/// threads").
async fn post<S>(shared: &Arc<Shared<S>>, seat: &Seated, postings: &Postings)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let Some(keys) = seat.keys.clone() else {
        return seat.withdraw(NoJob::NoAddress);
    };
    if shared.pool_retired() {
        return seat.withdraw(NoJob::PoolRetired);
    }
    let now = match shared.substrate().local_clock() {
        Ok(now) => now,
        Err(fault) => {
            tracing::error!("no template: the clock: {fault:?}");
            return seat.withdraw(NoJob::Unbuilt(Unbuilt::Clock));
        }
    };
    let Some(window) = shared.seed_now() else {
        return;
    };
    let reader = Arc::clone(shared);
    let produced = tokio::task::spawn_blocking(move || {
        let snap = reader.store().begin_read().map_err(Unposted::Store)?;
        let params = EconomicParams::default();
        let producer = Producer {
            rules: reader.rules(),
            keys: &keys,
            params: &params,
            now,
            #[cfg(test)]
            between_locks: None,
        };
        produce(&snap, &producer, reader.live_pool(), |seed| {
            window.holds(seed)
        })
        .map_err(Unposted::Template)
    })
    .await;
    // A panic in the producer is a defect, not a reason to take the
    // follower down with it: the job goes, and the service stops on it as
    // it does on any end of the follower. The workspace's dev and release
    // profiles abort on panic, so this arm is reached only where a panic
    // unwinds (the test profile).
    let produced = match produced {
        Ok(produced) => produced,
        Err(join) => {
            tracing::error!("the template producer panicked: {join}");
            seat.withdraw(NoJob::Unbuilt(Unbuilt::ProducerPanicked));
            shared.fail(ServiceFault::FollowerEnded);
            return;
        }
    };
    let produced = match produced {
        Ok(produced) => produced,
        Err(unposted) => {
            if let Some(why) = unposted.apply(shared) {
                seat.withdraw(why);
            }
            return;
        }
    };
    tracing::debug!(
        height = produced.job.height.to_raw(),
        bodies = produced.transactions.len(),
        block_weight = produced.block_weight,
        coinbase_weight = produced.coinbase_weight,
        block_reward = produced.block_reward.to_raw(),
        "posted the template"
    );
    if !produced.evicted.is_empty() {
        tracing::debug!("CEN-M10 evicted {:?}", produced.evicted);
    }
    // The sink reads the body list by generation. The insert happens
    // before `publish` returns, so a block the miner finds on this job
    // cannot observe an empty list. `publish` takes the board's lock, not
    // this one; the sink takes this one and not the board's.
    let mut kept = postings.lock().unwrap_or_else(PoisonError::into_inner);
    let generation = seat.board.publish(produced.job);
    kept.insert(generation, produced.transactions);
    while kept.len() > KEPT_JOBS {
        kept.pop_first();
    }
    drop(kept);
    seat.posting.send_replace(Posting::Posted(generation));
}

/// Why a pass posted nothing.
enum Unposted {
    Store(StoreError),
    Template(NoTemplate),
}

impl Unposted {
    /// A store fault or a corrupt store ends the service, as it does for
    /// any other reader; a chain fault in the pool's selection is the
    /// pool's chain fault; a pool-file fault retires the pool. Returns the
    /// reason to withdraw the job with, or `None` to leave it (a seed the
    /// slots do not hold yet).
    fn apply<S>(self, shared: &Shared<S>) -> Option<NoJob>
    where
        S: Substrate,
        S::Fault: core::fmt::Debug,
    {
        let why = |kind: Unbuilt| Some(NoJob::Unbuilt(kind));
        match self {
            Self::Store(store)
            | Self::Template(
                NoTemplate::Facts(FactsStop::Read(ViewRead::View(store)))
                | NoTemplate::Claim(ClaimStop::Store(store)),
            ) => {
                shared.fail(ServiceFault::Store(store));
                why(Unbuilt::StoreFault)
            }
            Self::Template(NoTemplate::Facts(FactsStop::Read(read @ ViewRead::Corrupt(_)))) => {
                crate::service::record_store_read(shared, read);
                why(Unbuilt::StoreCorrupt)
            }
            Self::Template(NoTemplate::Claim(ClaimStop::Corrupt { height, corrupt })) => {
                shared.fail(ServiceFault::Corrupt { height, corrupt });
                why(Unbuilt::StoreCorrupt)
            }
            Self::Template(NoTemplate::Selection(fault)) => {
                shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
                why(Unbuilt::Selection)
            }
            Self::Template(NoTemplate::PoolFile(store)) => {
                shared.pool_dead(&store);
                Some(NoJob::PoolRetired)
            }
            Self::Template(NoTemplate::SeedNotHeld) => None,
            Self::Template(NoTemplate::Facts(FactsStop::NoNextHeight { tip })) => {
                tracing::error!("no template: the tip {tip:?} is the last height there is");
                why(Unbuilt::LastHeight)
            }
            Self::Template(NoTemplate::Claim(ClaimStop::Refused { refused, .. })) => {
                tracing::error!(
                    "no template: the chain's own headers refuse its target: {refused:?}"
                );
                why(Unbuilt::TargetRefused)
            }
            Self::Template(NoTemplate::Claim(ClaimStop::Moved)) => {
                tracing::error!(
                    "no template: a seed block is not on the snapshot it was read from"
                );
                why(Unbuilt::SeedMissing)
            }
            Self::Template(NoTemplate::Random(error)) => {
                tracing::error!("no template: the OS random source failed: {error}");
                why(Unbuilt::Random)
            }
            Self::Template(NoTemplate::Build(error)) => {
                tracing::error!("no template: {error}");
                why(Unbuilt::Pricing)
            }
            Self::Template(NoTemplate::PoolOnAnotherTip) => {
                tracing::debug!("no template: the pool was judged against another tip");
                why(Unbuilt::PoolOnAnotherTip)
            }
            Self::Template(NoTemplate::NoNonceSlot) => {
                tracing::error!("no template: the coinbase reserves no extra nonce");
                why(Unbuilt::NoNonceSlot)
            }
        }
    }
}

/// What became of a block this node mined, when it did not join the chain.
fn say_mined(reply: &crate::service::Reply) {
    use crate::service::Reply;
    match reply {
        Reply::Connected { .. } | Reply::Switched { .. } | Reply::Stopped => {}
        Reply::Refused(verdict) => {
            tracing::error!("a block this node mined was refused: {verdict:?}");
        }
        other => tracing::warn!("a block this node mined did not connect: {other:?}"),
    }
}

/// Sends when the sink leaves its loop, including by a panic.
struct SignalDone(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for SignalDone {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            let _sent = done.send(());
        }
    }
}

/// The found-block sink. It ends when the inbox closes or the last sender
/// drops, and the queue is empty. Each block enters through the door's
            Self::Template(NoTemplate::BodyGone) => {
                tracing::debug!("no template: a listed body left the pool between the locks");
                why(Unbuilt::BodyGone)
            }
/// local-arrival entry ([`Door::offer_local`]) on the runtime it was
/// spawned from. Called from inside that runtime.
pub(crate) fn spawn_sink(
    found: FoundInbox,
    door: Door,
    postings: Postings,
    done: tokio::sync::oneshot::Sender<()>,
) -> std::thread::JoinHandle<()> {
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name(FOUND_SINK_THREAD.to_owned())
        .spawn(move || {
            let _done = SignalDone(Some(done));
            while let Some(found) = found.recv() {
                let bodies = postings
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&found.generation)
                    .cloned()
                    .unwrap_or_default();
                // The local-arrival entry waits out a full window. A closed
                // door answers `Stopped`. Anything else is this node's own
                // block not joining the chain, and it is said once.
                let offered = runtime.block_on(door.offer_local(
                    ArrivalTag(found.generation.to_raw()),
                    found.block.serialize(),
                    bodies.iter().map(Transaction::serialize).collect(),
                ));
                match offered {
                    Ok(tagged) => say_mined(&tagged.reply),
                    Err(refused) => tracing::error!(
                        "a block this node mined was not accepted at the door: {refused:?}"
                    ),
                }
            }
        })
        .expect("the found-block sink starts")
}

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
//! 3. the miner's next job, while the node is synced. The canonical seed
//!    is already `seed(connecting)`, which is the seed the job hashes
//!    under. The job does not pin. A seed the slots do not hold leaves the
//!    current job in place; the next publication tries again.
//!
//! **The template source is a seam.** The block a job carries is the
//! source's: in tests the scenario driver's template; at the flip, PR 3b's
//! `get_block_template` assembler. The producer claims the seed and the
//! target itself, on one snapshot.
//!
//! **The found-block sink.** A found block enters through the service's
//! one door as a local arrival. A full window waits for the reserved seat
//! instead of dropping the block. A closed door drops it. The service
//! closes the inbox on the way out, so the sink ends while a sender still
//! lives, and the thread is joined only after it has left the door.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_rules::{Fault, HeaderView, InvalidBlock, StatelessPass, Substrate, Tip};
use shekyl_chain_store::store::{SnapshotView, StoreError};
use shekyl_mempool::{stateless, PoolFault};
use shekyl_miner::{FoundInbox, Generation, Job, JobBoard};
use shekyl_types::TxHash;
use shekyl_wire::{Block, Transaction};
use tokio::sync::watch;

use crate::connector::{ChainFacts, TemplateFacts, TipChanged};
use crate::router::claim_next;
use crate::schedule::ChainRules;
use crate::service::{
    divide_pool_faults, install_window, with_pool, Arrival, ArrivalTag, Door, Origin, PoolDivision,
    ServiceFault, Shared,
};

/// Where the miner's blocks come from (module docs).
pub trait TemplateSource: Send + Sync + 'static {
    /// The block to mine after the tip `facts` describes, and its listed
    /// bodies; `None` when it cannot build one now.
    fn template(&self, facts: &ChainFacts) -> Option<(Block, Vec<Transaction>)>;
}

/// The miner, once one exists, and the sync owner it reads.
pub struct MinerFeed {
    /// What each job's block is.
    pub source: Arc<dyn TemplateSource>,
    /// Whether the node is synced: the sync owner's. While it reads
    /// `false`, the board is withdrawn on each pass.
    pub synced: watch::Receiver<bool>,
    /// Where found blocks arrive. Closed when the service stops, which
    /// ends the sink while a sender still lives. The last sender dropping
    /// ends it too.
    pub found: FoundInbox,
}

/// A board the attendant holds, and the miner when one is seated.
///
/// A seat with no miner is the node before a miner exists: the board is
/// withdrawn when the attendant ends, and nothing is posted in between.
pub struct JobSeat {
    /// The board the miner's workers read.
    pub board: Arc<JobBoard>,
    /// The miner and its sync owner. `None` until both exist.
    pub miner: Option<MinerFeed>,
}

/// Jobs kept for the found-block sink: a found block's generation names
/// the bodies it was built with. A miner finds for the newest posting, so
/// only the last few are ever asked for.
const KEPT_JOBS: usize = 8;

/// The found-block sink's thread. Short enough for a platform thread name.
const FOUND_SINK_THREAD: &str = "shekyl-found";

/// Each posted generation's listed bodies.
pub(crate) type Postings = Arc<Mutex<BTreeMap<Generation, Vec<Transaction>>>>;

/// Withdraws the miner's job on every way out, including a panic.
struct BoardGuard(Option<Arc<JobBoard>>);

impl BoardGuard {
    fn hold(board: Option<Arc<JobBoard>>) -> Self {
        Self(board)
    }
}

impl Drop for BoardGuard {
    fn drop(&mut self) {
        if let Some(board) = self.0.take() {
            board.withdraw();
        }
    }
}

/// The miner half of a seat, once the inbox has been handed to the sink.
struct SeatedMiner {
    source: Arc<dyn TemplateSource>,
    synced: Option<watch::Receiver<bool>>,
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
    let (board, mut miner, sink) = match job {
        Some(JobSeat {
            board,
            miner:
                Some(MinerFeed {
                    source,
                    synced,
                    found,
                }),
        }) => {
            let inbox = found.clone();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let thread = spawn_sink(found, door.clone(), Arc::clone(&postings), done_tx);
            (
                Some(board),
                Some(SeatedMiner {
                    source,
                    synced: Some(synced),
                }),
                Some(SinkJoin {
                    thread,
                    inbox,
                    done: done_rx,
                }),
            )
        }
        Some(JobSeat { board, miner: None }) => (Some(board), None, None),
        None => (None, None, None),
    };
    let _board = BoardGuard::hold(board.clone());
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
        if let (Some(board), Some(seated)) = (&board, miner.as_mut()) {
            let is_synced = seated
                .synced
                .as_mut()
                .is_some_and(|s| *s.borrow_and_update());
            if is_synced {
                post(&shared, board, seated.source.as_ref(), &postings).await;
            } else {
                board.withdraw();
            }
        }
        shared.followed(tip.seq);
        let sync_changed = async {
            match miner.as_mut().and_then(|seated| seated.synced.as_mut()) {
                Some(synced) => synced.changed().await.is_err(),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            changed = tips.changed() => if changed.is_err() { break },
            // The sync owner is gone: nothing says this node is synced
            // any more. That is "behind" — the job is withdrawn on the
            // next pass — not a reason to stop following the chain.
            closed = sync_changed => if closed {
                if let Some(seated) = miner.as_mut() {
                    seated.synced = None;
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
        // the service task can then drop a queued arrival, which answers
        // a sink blocked in `blocking_reply`. The join is after that
        // answer, so it does not occupy the worker the reply needs.
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

/// Post the job for the block after the tip. The window is already pinned.
/// A seed the slots do not hold leaves the current job; the next
/// publication tries again.
async fn post<S>(
    shared: &Arc<Shared<S>>,
    board: &JobBoard,
    source: &dyn TemplateSource,
    postings: &Postings,
) where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let Ok(facts) = shared.connector().ask(TemplateFacts).await else {
        board.withdraw();
        return;
    };
    let store = std::sync::Arc::clone(shared.store());
    let rules = shared.rules();
    let claimed = tokio::task::spawn_blocking(move || claim_next(&store, rules))
        .await
        .expect("the claim reader does not panic");
    let Ok((height, seed, target)) = claimed else {
        board.withdraw();
        return;
    };
    if height != facts.connecting {
        return;
    }
    let Some(window) = shared.seed_now() else {
        return;
    };
    if !window.holds(&seed) {
        return;
    }
    let Some((block, transactions)) = source.template(&facts) else {
        board.withdraw();
        return;
    };
    // The sink reads the body list by generation. The insert happens
    // before `publish` returns, so a block the miner finds on this job
    // cannot observe an empty list. `publish` takes the board's lock, not
    // this one; the sink takes this one and not the board's.
    let mut kept = postings.lock().unwrap_or_else(PoisonError::into_inner);
    let generation = board.publish(Job {
        block,
        height,
        seed,
        difficulty: target.difficulty(),
    });
    kept.insert(generation, transactions);
    while kept.len() > KEPT_JOBS {
        kept.pop_first();
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
/// drops, and the queue is empty. A full window waits for the reserved
/// seat. A closed door drops the block and the loop goes back to `recv`.
pub(crate) fn spawn_sink(
    found: FoundInbox,
    door: Door,
    postings: Postings,
    done: tokio::sync::oneshot::Sender<()>,
) -> std::thread::JoinHandle<()> {
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
                let arrival = Arrival {
                    tag: ArrivalTag(found.generation.to_raw()),
                    origin: Origin::Local,
                    block: found.block.serialize(),
                    bodies: bodies.iter().map(Transaction::serialize).collect(),
                };
                // A full window waits for the local seat. A closed door wakes
                // that wait and the offer is refused; the block is dropped.
                // Anything else is this node's own block not joining the chain,
                // and it is said once.
                loop {
                    match door.offer(arrival.clone()) {
                        Ok(ticket) => {
                            say_mined(&ticket.blocking_reply().reply);
                            break;
                        }
                        Err(crate::service::Refusal::NoRoom) => {
                            if !door.wait_for_local_seat() {
                                break;
                            }
                        }
                        Err(refused) => {
                            tracing::error!(
                                "a block this node mined was not accepted at the door: {refused:?}"
                            );
                            break;
                        }
                    }
                }
            }
        })
        .expect("the found-block sink starts")
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`MiningControl`]: the node's built-in miner, started and stopped over
//! the node's board, hasher budget and cache store
//! (`DRS_X_STORE_FLIP.md` DX-Q3, N2).
//!
//! The miner hashes the job the tip follower posts. It builds nothing and
//! pays no one itself: the template pays the `mine-address` row's keys.
//! Starting and stopping it never stops or drops the node (`Node::stop`'s
//! `# Panics`).

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::connector::TipChanged;
use shekyl_chain_ingest::follower::{NoJob, Posting, Unbuilt};
use shekyl_chain_ingest::service::PoolHealth;
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_daemon_rpc::handles::MiningFacts;
use shekyl_daemon_rpc::mining_facts::{
    BacklogEntry, MinerState, MiningState, Pending, PostedSummary, PostedTemplate,
};
use shekyl_daemon_rpc::mining_methods::codes;
use shekyl_hash_budget::Budget;
use shekyl_miner::{
    Draining, FoundBlocks, Job, JobBoard, Miner, MinerConfig, MinerStartRefused, MinerStatus,
    MiningAddress,
};
use shekyl_pow_randomx::{CacheStore, Seedhash};
use shekyl_rpc_types::errors::Diagnostic;
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;
use tokio::sync::watch;

/// Why the miner did not start.
#[derive(Debug)]
pub enum MiningRefused {
    /// No `mine-address` row: there is no one for a coinbase to pay.
    NoAddress,
    /// The miner is already running.
    Running,
    /// More threads than the host runs at once: each holds a ring and a
    /// stack, and a count past the host's parallelism only adds threads
    /// that wait.
    TooManyThreads {
        /// The count asked for.
        asked: usize,
        /// The host's parallelism.
        host: usize,
    },
    /// The node has stopped.
    NodeStopped,
    /// The miner refused to start.
    Start(MinerStartRefused),
}

impl core::fmt::Display for MiningRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoAddress => f.write_str("no mine-address is set; set it and restart the node"),
            Self::Running => f.write_str("the miner is already running"),
            Self::TooManyThreads { asked, host } => write!(
                f,
                "{asked} threads asked for; this host runs {host} at once"
            ),
            Self::NodeStopped => f.write_str("the node has stopped"),
            Self::Start(refused) => refused.fmt(f),
        }
    }
}

impl std::error::Error for MiningRefused {}

/// The posted job, as `mining_status` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostedJob {
    /// The height the job's block connects at.
    pub height: BlockHeight,
    /// The difficulty its longhash must meet.
    pub difficulty: u128,
    /// What its coinbase pays the miner.
    pub reward: AtomicUnits,
}

/// What `mining_status` reports.
#[derive(Clone, Debug, PartialEq)]
pub struct MiningStatus {
    /// The running miner's state; `None` when it is stopped.
    pub miner: Option<MinerStatus>,
    /// The job on the board, when one is posted.
    pub job: Option<PostedJob>,
    /// Why no job is posted, when none is.
    pub no_job: Option<NoJob>,
}

/// What the follower publishes that the miner's reads follow: the board's
/// posting state and the chain's tip.
pub(crate) struct Watched {
    pub(crate) posting: watch::Receiver<Posting>,
    pub(crate) tips: watch::Receiver<TipChanged>,
}

/// The node's miner (module docs).
pub struct MiningControl {
    /// The node's one job board; the crate's tests read it here.
    pub(crate) board: Arc<JobBoard>,
    caches: Arc<CacheStore>,
    budget: Budget,
    found: FoundBlocks,
    address: Option<MiningAddress>,
    posting: watch::Receiver<Posting>,
    /// The chain's tip, as the connector publishes it: a posted job is
    /// served only while it is the next block of this tip (N2, one
    /// template per tip). Between a block connecting and the follower's
    /// next post the board still holds the previous tip's job; the miner
    /// keeps hashing it, harmlessly, and the RPC answers not ready.
    tips: watch::Receiver<TipChanged>,
    pool: PoolHealth,
    miner: Mutex<Option<Miner>>,
    /// Stopped miners' workers still finishing the hash they were in. A
    /// stop does not wait for them; [`Self::start`] waits for those holding
    /// another seed's cache, and [`Node::stop`](crate::Node::stop) joins
    /// the rest after the store has closed.
    draining: Mutex<Vec<Draining>>,
    /// Set by [`Node::stop`](crate::Node::stop): no miner starts after it.
    closed: AtomicBool,
}

impl MiningControl {
    pub(crate) fn new(
        board: Arc<JobBoard>,
        caches: Arc<CacheStore>,
        budget: Budget,
        found: FoundBlocks,
        address: Option<MiningAddress>,
        watches: Watched,
        pool: PoolHealth,
    ) -> Self {
        Self {
            board,
            caches,
            budget,
            found,
            address,
            posting: watches.posting,
            tips: watches.tips,
            pool,
            miner: Mutex::new(None),
            draining: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// Stop the miner and refuse every later start: the node is stopping.
    /// Does not wait for the workers' hashes; [`Self::join_drained`] does,
    /// once the node has closed what it holds.
    pub(crate) fn close(&self) {
        let mut running = self.lock();
        self.closed.store(true, Ordering::Release);
        if let Some(miner) = running.take() {
            drop(running);
            self.park(miner.stop());
        }
    }

    /// Join every stopped miner's workers. Waits for the hashes they are
    /// still in: [`Node::stop`](crate::Node::stop) calls it last, after the
    /// store has closed.
    pub(crate) fn join_drained(&self) {
        let draining = std::mem::take(&mut *self.drain_lock());
        for workers in draining {
            workers.join();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Miner>> {
        self.miner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn drain_lock(&self) -> std::sync::MutexGuard<'_, Vec<Draining>> {
        self.draining.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keep a stopped miner's workers, and join any earlier ones that have
    /// already returned (their join does not wait).
    fn park(&self, workers: Draining) {
        let mut draining = self.drain_lock();
        reap_finished(&mut draining);
        draining.push(workers);
    }

    /// Before a start: join the stopped workers that still hold a cache for
    /// a seed other than the posted job's, or for any seed when no job is
    /// posted. Workers on the same seed share that cache with the new ones,
    /// so a stop and a start never keep two seeds' caches alive at once.
    /// Waits for at most one hash per worker joined.
    fn settle_drained(&self) {
        let seed = self
            .board
            .posted()
            .map(|(_, job)| Seedhash::from_bytes(*job.seed.as_bytes()));
        let mut draining = self.drain_lock();
        reap_finished(&mut draining);
        let (other, same): (Vec<_>, Vec<_>) = std::mem::take(&mut *draining)
            .into_iter()
            .partition(|workers| workers.holds_other_than(seed.as_ref()));
        *draining = same;
        drop(draining);
        for workers in other {
            workers.join();
        }
    }

    /// Start the miner with `threads` workers; `None` is the host's
    /// parallelism, which is also the most a count may ask for.
    ///
    /// # Errors
    ///
    /// [`MiningRefused`].
    pub fn start(&self, threads: Option<NonZeroUsize>) -> Result<(), MiningRefused> {
        let Some(address) = self.address.clone() else {
            return Err(MiningRefused::NoAddress);
        };
        let mut running = self.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(MiningRefused::NodeStopped);
        }
        if running.is_some() {
            return Err(MiningRefused::Running);
        }
        self.settle_drained();
        let host = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        let threads = threads.unwrap_or(host);
        if threads > host {
            return Err(MiningRefused::TooManyThreads {
                asked: threads.get(),
                host: host.get(),
            });
        }
        let miner = Miner::start(
            &MinerConfig { address, threads },
            Arc::clone(&self.board),
            Arc::clone(&self.caches),
            self.budget.clone(),
            self.found.clone(),
        )
        .map_err(MiningRefused::Start)?;
        *running = Some(miner);
        Ok(())
    }

    /// Stop the miner. `false` when it was not running. Returns without
    /// waiting for the workers' hashes: nothing they finish after this
    /// returns becomes a block. The node keeps running.
    pub fn stop(&self) -> bool {
        let Some(miner) = self.lock().take() else {
            return false;
        };
        self.park(miner.stop());
        true
    }

    /// Whether the miner is running.
    pub fn running(&self) -> bool {
        self.lock().is_some()
    }

    /// The miner's state, the posted job, and why none is posted.
    pub fn status(&self) -> MiningStatus {
        let miner = self.lock().as_ref().map(Miner::status);
        let job = self.board.posted().map(|(_, job)| PostedJob {
            height: job.height,
            difficulty: job.difficulty.to_raw(),
            reward: job.reward,
        });
        let no_job = match &*self.posting.borrow() {
            Posting::Posted(_) => None,
            Posting::Withdrawn(why) => Some(why.clone()),
        };
        MiningStatus { miner, job, no_job }
    }
}

/// Why no job is posted, as the RPC's typed diagnostic.
fn no_job_diagnostic(why: &NoJob) -> Diagnostic {
    let code = match why {
        NoJob::Starting => codes::STARTING,
        NoJob::NoAddress => codes::NO_ADDRESS,
        NoJob::NotSynced(_) => codes::NOT_SYNCED,
        NoJob::PoolRetired => codes::POOL_RETIRED,
        NoJob::Unbuilt(_) => codes::UNBUILT,
        NoJob::Stopped => codes::STOPPING,
    };
    let diagnostic = Diagnostic::new(code, why.to_string());
    match why {
        NoJob::NotSynced(state) => diagnostic.param("sync", state.name()),
        NoJob::Unbuilt(kind @ Unbuilt::Stuck { after }) => diagnostic
            .param("kind", kind.code())
            .param("after", after.code()),
        NoJob::Unbuilt(kind) => diagnostic.param("kind", kind.code()),
        _ => diagnostic,
    }
}

/// The job, as the RPC reads it.
/// Whether a job at `job_height` is the next block of a chain of
/// `tip_count` blocks: the one template per tip the RPC serves (N2). An
/// empty chain (`None`) has no job to serve.
pub(crate) fn job_is_for_tip(job_height: u64, tip_count: Option<u64>) -> bool {
    tip_count == Some(job_height)
}

fn posted_template(job: &Job) -> PostedTemplate {
    PostedTemplate {
        block: job.block.serialize(),
        hashing_blob: job.block.pow_blob(),
        major_version: job.block.header.major_version,
        height: job.height,
        prev_hash: job.block.header.previous,
        difficulty: job.difficulty.to_raw(),
        extra_nonce_offset: u64::try_from(job.offsets.extra_nonce()).unwrap_or(u64::MAX),
        nonce_offset: u64::try_from(job.offsets.header_nonce()).unwrap_or(u64::MAX),
        reward: job.reward.to_raw(),
        seed: job.seed,
        seed_height: shekyl_chain_rules::seed_height(job.height).unwrap_or(BlockHeight::ZERO),
        next_seed: job.next_seed,
        median_weight: job.median_weight,
        already_generated: job.already_generated.to_raw(),
        backlog: job
            .listed
            .iter()
            .map(|body| BacklogEntry {
                id: body.id,
                weight: body.weight,
                fee: body.fee.to_raw(),
            })
            .collect(),
    }
}

impl MiningFacts for MiningControl {
    fn running(&self) -> Result<bool, FactsFault> {
        Ok(Self::running(self))
    }

    fn template(&self) -> Result<Result<PostedTemplate, Diagnostic>, FactsFault> {
        if let Some((_, job)) = self.board.posted() {
            let tip_count = self.tips.borrow().tip.map(|tip| tip.count.to_raw());
            if job_is_for_tip(job.height.to_raw(), tip_count) {
                return Ok(Ok(posted_template(&job)));
            }
            // The tip moved under the job; the follower's next pass replaces it.
            return Ok(Err(no_job_diagnostic(&NoJob::Starting)));
        }
        let why = match &*self.posting.borrow() {
            Posting::Withdrawn(why) => why.clone(),
            // Posted, and withdrawn since: the follower is between passes.
            Posting::Posted(_) => NoJob::Starting,
        };
        Ok(Err(no_job_diagnostic(&why)))
    }

    fn start(&self, threads: Option<NonZeroUsize>) -> Result<Result<(), Diagnostic>, FactsFault> {
        Ok(Self::start(self, threads).map_err(|refused| {
            let code = match &refused {
                MiningRefused::NoAddress => codes::NO_ADDRESS,
                MiningRefused::Running => codes::RUNNING,
                MiningRefused::TooManyThreads { .. } => codes::TOO_MANY_THREADS,
                MiningRefused::NodeStopped => codes::STOPPING,
                MiningRefused::Start(MinerStartRefused::OnePermit) => codes::ONE_PERMIT,
                MiningRefused::Start(MinerStartRefused::Thread(_)) => codes::THREAD,
            };
            let diagnostic = Diagnostic::new(code, refused.to_string());
            match refused {
                MiningRefused::TooManyThreads { asked, host } => diagnostic
                    .param("threads", asked.to_string())
                    .param("parallelism", host.to_string()),
                _ => diagnostic,
            }
        }))
    }

    fn stop(&self) -> Result<bool, FactsFault> {
        Ok(Self::stop(self))
    }

    /// The refusal [`MiningFacts::withdrawn`] waits for, read now.
    /// `Ok(None)` while a job is posted or the withdrawal is one the next
    /// pass replaces.
    fn refusal(&self) -> Result<Option<Diagnostic>, FactsFault> {
        Ok(self.posting.borrow().refusal().map(no_job_diagnostic))
    }

    /// Resolves when [`MiningFacts::refusal`] is `Some`: `generateblocks`
    /// waits on the tip only while a miner can still make it move. A closed
    /// watch is a stop, as a withdrawal nobody will replace.
    fn withdrawn(&self) -> Pending<'_, Diagnostic> {
        let mut posting = self.posting.clone();
        Box::pin(async move {
            let why = match posting.wait_for(|now| now.refusal().is_some()).await {
                Ok(now) => now.refusal().cloned().unwrap_or(NoJob::Stopped),
                Err(_) => NoJob::Stopped,
            };
            Ok(no_job_diagnostic(&why))
        })
    }

    fn status(&self) -> Result<MiningState, FactsFault> {
        let status = Self::status(self);
        Ok(MiningState {
            miner: status.miner.as_ref().map(|miner| MinerState {
                threads: u32::try_from(miner.threads).unwrap_or(u32::MAX),
                hashes_per_second: miner
                    .rate
                    .hashes
                    .checked_div(miner.rate.window.as_secs())
                    .unwrap_or(0),
            }),
            address: self.address.as_ref().map(|a| a.encoded().to_owned()),
            posted: status.job.map(|job| PostedSummary {
                height: job.height,
                difficulty: job.difficulty,
                reward: job.reward.to_raw(),
            }),
            pool_retired: self.pool.retired(),
            absent: status.no_job.as_ref().map(no_job_diagnostic),
        })
    }
}

/// Join the stopped workers that have all returned. Their join does not
/// wait.
fn reap_finished(draining: &mut Vec<Draining>) {
    let (done, live): (Vec<_>, Vec<_>) = std::mem::take(draining)
        .into_iter()
        .partition(Draining::finished);
    *draining = live;
    for workers in done {
        workers.join();
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::{no_job_diagnostic, NoJob, Unbuilt};
    use shekyl_chain_ingest::follower::{Posting, Rebuild};

    /// A stuck build names itself and the reason that did not clear, so a
    /// caller refused by `generateblocks` can tell a body lost twice from a
    /// pool judged at another tip twice. The stuck posting is a refusal;
    /// the same reason still on its one rebuild is a wait.
    #[test]
    fn a_job_is_served_only_as_the_next_block_of_the_tip() {
        // One template per tip (N2). Seen on the quiet box: after a block
        // connected the previous tip's job was still served, listing bodies
        // that block had mined (`e2e_cxx_template_fills_to_its_median`).
        assert!(super::job_is_for_tip(5, Some(5)));
        assert!(
            !super::job_is_for_tip(5, Some(6)),
            "the tip moved under the job"
        );
        assert!(
            !super::job_is_for_tip(5, Some(4)),
            "a job ahead of the tip is not its next block"
        );
        assert!(
            !super::job_is_for_tip(0, None),
            "an empty chain serves no job"
        );
    }

    #[test]
    fn a_stuck_build_names_the_reason_that_did_not_clear() {
        let why = NoJob::Unbuilt(Unbuilt::Stuck {
            after: Rebuild::BodyGone,
        });
        let diagnostic = no_job_diagnostic(&why);
        assert_eq!(
            diagnostic.params,
            vec![
                ("kind".to_owned(), "stuck".to_owned()),
                ("after".to_owned(), "body_gone".to_owned()),
            ]
        );
        assert!(
            diagnostic.message.contains("left the pool") && diagnostic.message.contains("again"),
            "{}",
            diagnostic.message
        );
        assert!(!why.transient(), "a stuck build is a refusal, not a wait");
        assert!(Posting::Withdrawn(why).refusal().is_some());
        let retry = NoJob::Unbuilt(Unbuilt::Retry(Rebuild::BodyGone));
        assert!(retry.transient());
        assert!(Posting::Withdrawn(retry).refusal().is_none());
    }
}

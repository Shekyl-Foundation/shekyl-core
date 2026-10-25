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
    FoundBlocks, Job, JobBoard, Miner, MinerConfig, MinerStartRefused, MinerStatus, MiningAddress,
};
use shekyl_pow_randomx::CacheStore;
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

/// The node's miner (module docs).
pub struct MiningControl {
    /// The node's one job board; the crate's tests read it here.
    pub(crate) board: Arc<JobBoard>,
    caches: Arc<CacheStore>,
    budget: Budget,
    found: FoundBlocks,
    address: Option<MiningAddress>,
    posting: watch::Receiver<Posting>,
    pool: PoolHealth,
    miner: Mutex<Option<Miner>>,
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
        posting: watch::Receiver<Posting>,
        pool: PoolHealth,
    ) -> Self {
        Self {
            board,
            caches,
            budget,
            found,
            address,
            posting,
            pool,
            miner: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Stop the miner and refuse every later start: the node is stopping.
    pub(crate) fn close(&self) {
        let mut running = self.lock();
        self.closed.store(true, Ordering::Release);
        if let Some(miner) = running.take() {
            drop(running);
            miner.stop();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Miner>> {
        self.miner.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// Stop the miner and join its workers. `false` when it was not
    /// running. The node keeps running.
    pub fn stop(&self) -> bool {
        let running = self.lock().take();
        running.map(Miner::stop).is_some()
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
            return Ok(Ok(posted_template(&job)));
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

#[cfg(test)]
mod diagnostic_tests {
    use super::{no_job_diagnostic, NoJob, Unbuilt};
    use shekyl_chain_ingest::follower::{Posting, Rebuild};

    /// A stuck build names itself and the reason that did not clear, so a
    /// caller refused by `generateblocks` can tell a body lost twice from a
    /// pool judged at another tip twice. The stuck posting is a refusal;
    /// the same reason still on its one rebuild is a wait.
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

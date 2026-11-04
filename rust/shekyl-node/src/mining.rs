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
    DrainGate, FoundBlocks, Job, JobBoard, Miner, MinerConfig, MinerStartRefused, MinerStatus,
    MinerStop, MiningAddress, PreparedMiner,
};
use shekyl_pow_randomx::CacheStore;
use shekyl_rpc_types::errors::Diagnostic;
use shekyl_rpc_types::mining::MineSpeed;
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

/// The `mine-address` and `mine-threads` rows, as the miner takes them.
pub(crate) struct Configured {
    /// The address the miner pays; `None` posts nothing.
    pub(crate) address: Option<MiningAddress>,
    /// The `mine-threads` row's count: what a start that names none uses.
    /// `None` is `auto`, the host's parallelism.
    pub(crate) threads: Option<NonZeroUsize>,
}

/// One look at the stop flag, after it is in the slot and before any
/// worker exists.
#[cfg(test)]
type ArmHook = Box<dyn FnOnce(&MinerStop) + Send>;

/// What the follower publishes that the miner's reads follow: the board's
/// posting state and the chain's tip.
pub(crate) struct Watched {
    pub(crate) posting: watch::Receiver<Posting>,
    pub(crate) tips: watch::Receiver<TipChanged>,
}

/// What the miner slot holds. `Arming` is the stop flag, published before
/// any worker runs, so [`MiningControl::close`] can signal it without
/// waiting for the spawn. `Mining` is the running workers.
enum Resident {
    Arming(MinerStop),
    Mining(Miner),
}

/// The running miner. A poisoned lock still holds it: a panicked holder
/// must not hide the workers that have to be stopped.
fn lock_miner(miner: &Mutex<Option<Resident>>) -> std::sync::MutexGuard<'_, Option<Resident>> {
    miner.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Drops an `Arming` this start still owns. A panic while the threads are
/// being spawned must not leave a flag in the slot with nobody to park
/// the workers. A committed miner, and a flag [`MiningControl::close`]
/// already took, are left as they are.
///
/// Declare it before any later guard of the same mutex, and drop those
/// guards before it returns: the mutex is not reentrant, and this drop
/// locks it.
struct ClearArming<'a> {
    slot: &'a Mutex<Option<Resident>>,
}

impl Drop for ClearArming<'_> {
    fn drop(&mut self) {
        let mut slot = lock_miner(self.slot);
        if matches!(slot.as_ref(), Some(Resident::Arming(_))) {
            *slot = None;
        }
    }
}

/// The node's miner (module docs).
pub struct MiningControl {
    /// The node's one job board; the crate's tests read it here.
    pub(crate) board: Arc<JobBoard>,
    caches: Arc<CacheStore>,
    budget: Budget,
    found: FoundBlocks,
    address: Option<MiningAddress>,
    /// The `mine-threads` row's count: what a start that names none uses.
    /// `None` is `auto`, the host's parallelism.
    threads: Option<NonZeroUsize>,
    posting: watch::Receiver<Posting>,
    /// The chain's tip, as the connector publishes it: a posted job is
    /// served only while it is the next block of this tip (N2, one
    /// template per tip). Between a block connecting and the follower's
    /// next post the board still holds the previous tip's job; the miner
    /// keeps hashing it, harmlessly, and the RPC answers not ready.
    tips: watch::Receiver<TipChanged>,
    pool: PoolHealth,
    miner: Mutex<Option<Resident>>,
    /// Stopped workers, and the one gate every join takes ([`DrainGate`]).
    /// [`Self::close`] parks without the gate, so shutdown returns before a
    /// hash. A start and a stop hold the gate across their join.
    drain: DrainGate,
    /// Set by [`Self::close`]: no miner starts after the node has stopped.
    closed: AtomicBool,
    /// Runs after the stop flag is in the slot and before any worker
    /// exists. One start consumes it. The flag it receives is the one
    /// the workers will read.
    #[cfg(test)]
    arm_hook: Mutex<Option<ArmHook>>,
}

impl MiningControl {
    pub(crate) fn new(
        board: Arc<JobBoard>,
        caches: Arc<CacheStore>,
        budget: Budget,
        found: FoundBlocks,
        configured: Configured,
        watches: Watched,
        pool: PoolHealth,
    ) -> Self {
        Self {
            board,
            caches,
            budget,
            found,
            address: configured.address,
            threads: configured.threads,
            posting: watches.posting,
            tips: watches.tips,
            pool,
            miner: Mutex::new(None),
            drain: DrainGate::default(),
            closed: AtomicBool::new(false),
            #[cfg(test)]
            arm_hook: Mutex::new(None),
        }
    }

    /// Run `hook` once, after the next start has published its stop flag
    /// and before it spawns. The hook runs on the starting thread and is
    /// handed that flag.
    #[cfg(test)]
    pub(crate) fn on_arming(&self, hook: impl FnOnce(&MinerStop) + Send + 'static) {
        *self.arm_hook.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Stop the miner and refuse every later start. Does not take the join
    /// gate and does not wait for the hash in progress; [`Self::join_drained`]
    /// does, once the node has closed what it holds.
    pub(crate) fn close(&self) {
        let mut running = lock_miner(&self.miner);
        self.closed.store(true, Ordering::Release);
        match running.take() {
            Some(Resident::Mining(miner)) => {
                // The miner lock is held across the park, so a start cannot
                // publish between the take and it. `defer` does not take the
                // gate and does not join.
                self.drain.defer(miner.stop());
            }
            Some(Resident::Arming(flag)) => {
                // The threads are not spawned yet, or are still being
                // spawned by the start that holds the join gate. Signaling
                // here is what makes a block unable to leave after this
                // returns. That start parks the threads; deferring an
                // empty set here would be a second park.
                flag.signal();
            }
            None => {}
        }
    }

    /// Join every stopped set. Takes the join gate first, so a start or a
    /// stop already inside a join finishes, and a set parked while this
    /// waited is joined too. [`Node::stop`](crate::Node::stop) calls it
    /// last, after the store has closed.
    pub(crate) fn join_drained(&self) {
        self.drain.join_outstanding();
    }

    /// Start the miner with `threads` workers; `None` is the `mine-threads`
    /// row's count, and that row's `auto` is the host's parallelism, which
    /// is also the most a count may ask for.
    ///
    /// Joins the one stopped set still hashing, then spawns, holding the
    /// join gate across both. A restart waits out that one hash, and a
    /// second start cannot spawn beside it. The stop flag is in the slot
    /// before any worker runs, so a shutdown during the spawn signals it
    /// and nothing those workers finish is delivered.
    ///
    /// # Errors
    ///
    /// [`MiningRefused`].
    pub fn start(&self, threads: Option<NonZeroUsize>) -> Result<(), MiningRefused> {
        let Some(address) = self.address.clone() else {
            return Err(MiningRefused::NoAddress);
        };
        let host = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        let threads = threads.or(self.threads).unwrap_or(host);
        if threads > host {
            return Err(MiningRefused::TooManyThreads {
                asked: threads.get(),
                host: host.get(),
            });
        }
        let board = Arc::clone(&self.board);
        let caches = Arc::clone(&self.caches);
        let budget = self.budget.clone();
        let found = self.found.clone();
        // The closure borrows these fields on their own. A method on
        // `self` would borrow all of it, and `before_spawn` already
        // borrows the gate.
        let miner = &self.miner;
        let closed = &self.closed;
        let drain = &self.drain;
        #[cfg(test)]
        let arm_hook = &self.arm_hook;
        drain.before_spawn(|| {
            let prepared = {
                let running = lock_miner(miner);
                if closed.load(Ordering::Acquire) {
                    return Err(MiningRefused::NodeStopped);
                }
                if running.is_some() {
                    return Err(MiningRefused::Running);
                }
                drop(running);
                PreparedMiner::arm(
                    &MinerConfig { address, threads },
                    board,
                    caches,
                    budget,
                    found,
                )
                .map_err(MiningRefused::Start)?
            };
            let flag = prepared.stop_flag();
            {
                let mut running = lock_miner(miner);
                if closed.load(Ordering::Acquire) {
                    return Err(MiningRefused::NodeStopped);
                }
                if running.is_some() {
                    return Err(MiningRefused::Running);
                }
                *running = Some(Resident::Arming(flag.clone()));
            }
            // Past this, a panic drops the flag if this start still owns
            // it. Close may already have taken it.
            let _clear = ClearArming { slot: miner };
            #[cfg(test)]
            {
                let hook = arm_hook
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(hook) = hook {
                    hook(&flag);
                }
            }
            // The slot holds the clone shutdown signals. The hook, on test
            // builds, has already read this one.
            drop(flag);
            // The slot lock is not held across the spawn. A refused spawn
            // joins the workers it already made, and that join waits out a
            // hash, so it must not hold the miner lock either. Close can
            // signal the flag while this runs; it does not take the gate.
            let spawned = prepared.spawn();
            let mut running = lock_miner(miner);
            if !matches!(running.as_ref(), Some(Resident::Arming(_))) {
                drop(running);
                if let Ok(started) = spawned {
                    drain.defer(started.stop());
                }
                return Err(MiningRefused::NodeStopped);
            }
            match spawned {
                Ok(started) => {
                    *running = Some(Resident::Mining(started));
                    Ok(())
                }
                Err(refused) => {
                    *running = None;
                    Err(MiningRefused::Start(refused))
                }
            }
        })
    }

    /// Stop the miner. `false` when it was not running.
    ///
    /// The workers just stopped are parked, not joined: nothing they finish
    /// after this returns becomes a block. The set they displaced is joined
    /// before this returns, under the join gate, so a caller that does not
    /// wait still cannot start another miner until that join has finished.
    /// The node keeps running.
    pub fn stop(&self) -> bool {
        let miner = &self.miner;
        self.drain.retire(|| {
            let mut running = lock_miner(miner);
            let stopped = match running.take() {
                Some(Resident::Mining(miner)) => Some(miner.stop()),
                // The start that published this holds the gate `retire`
                // is waiting on, so this arm is the start's own panic
                // having left the flag. Signal it; there are no threads
                // in the slot to park.
                Some(Resident::Arming(flag)) => {
                    flag.signal();
                    None
                }
                None => None,
            };
            drop(running);
            stopped
        })
    }

    /// Whether the miner is running.
    pub fn running(&self) -> bool {
        matches!(lock_miner(&self.miner).as_ref(), Some(Resident::Mining(_)))
    }

    /// The miner's state, the posted job, and why none is posted.
    pub fn status(&self) -> MiningStatus {
        let miner = match lock_miner(&self.miner).as_ref() {
            Some(Resident::Mining(miner)) => Some(miner.status()),
            Some(Resident::Arming(_)) | None => None,
        };
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
            miner: status.miner.as_ref().map(miner_state),
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

/// The miner's [`shekyl_miner::HashRate`] as [`MineSpeed`]: `hashes` is
/// `count`, and the window's complete seconds are `window`.
fn miner_state(miner: &MinerStatus) -> MinerState {
    MinerState {
        threads: u32::try_from(miner.threads).unwrap_or(u32::MAX),
        speed: MineSpeed {
            count: miner.rate.hashes,
            window: miner.rate.window.as_secs(),
        },
    }
}

#[cfg(test)]
mod rate_tests {
    use super::{miner_state, MinerStatus};
    use shekyl_miner::HashRate;
    use shekyl_rpc_types::mining::MineSpeed;
    use std::time::Duration;

    /// Eight hashes in ten seconds stays eight hashes over ten seconds.
    /// The window is complete seconds, which is how the miner counts.
    #[test]
    fn the_facts_carry_the_miners_count_and_window() {
        let status = MinerStatus {
            active: true,
            threads: 1,
            address: String::new(),
            rate: HashRate {
                hashes: 8,
                window: Duration::from_secs(10),
            },
            per_thread: Vec::new(),
            not_lowered: 0,
        };
        let state = miner_state(&status);
        assert_eq!(state.threads, 1);
        assert_eq!(
            state.speed,
            MineSpeed {
                count: 8,
                window: 10
            }
        );
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

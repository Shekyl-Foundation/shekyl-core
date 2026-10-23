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
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::follower::{NoJob, Posting};
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_daemon_rpc::handles::MiningFacts;
use shekyl_hash_budget::Budget;
use shekyl_miner::{
    FoundBlocks, JobBoard, Miner, MinerConfig, MinerStartRefused, MinerStatus, MiningAddress,
};
use shekyl_pow_randomx::CacheStore;
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
    /// The miner refused to start.
    Start(MinerStartRefused),
}

impl core::fmt::Display for MiningRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoAddress => f.write_str("no mine-address is set; set it and restart the node"),
            Self::Running => f.write_str("the miner is already running"),
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
    board: Arc<JobBoard>,
    caches: Arc<CacheStore>,
    budget: Budget,
    found: FoundBlocks,
    address: Option<MiningAddress>,
    posting: watch::Receiver<Posting>,
    miner: Mutex<Option<Miner>>,
}

impl MiningControl {
    pub(crate) fn new(
        board: Arc<JobBoard>,
        caches: Arc<CacheStore>,
        budget: Budget,
        found: FoundBlocks,
        address: Option<MiningAddress>,
        posting: watch::Receiver<Posting>,
    ) -> Self {
        Self {
            board,
            caches,
            budget,
            found,
            address,
            posting,
            miner: Mutex::new(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Miner>> {
        self.miner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start the miner with `threads` workers; `None` is the host's
    /// parallelism less one, at least one.
    ///
    /// # Errors
    ///
    /// [`MiningRefused`].
    pub fn start(&self, threads: Option<NonZeroUsize>) -> Result<(), MiningRefused> {
        let Some(address) = self.address.clone() else {
            return Err(MiningRefused::NoAddress);
        };
        let mut running = self.lock();
        if running.is_some() {
            return Err(MiningRefused::Running);
        }
        let threads = threads.unwrap_or_else(|| {
            let host = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
            NonZeroUsize::new(host.saturating_sub(1)).unwrap_or(NonZeroUsize::MIN)
        });
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

impl MiningFacts for MiningControl {
    fn running(&self) -> Result<bool, FactsFault> {
        Ok(Self::running(self))
    }
}

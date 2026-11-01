// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`Miner`]: the workers, their status, and stopping them.

use std::io;
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use shekyl_difficulty::check_hash;
use shekyl_hash_budget::{Budget, Class};
use shekyl_pow_randomx::{compute_hash, CacheStore, Seedhash};
use shekyl_thread_ledger::{spawn_dedicated, DedicatedThread, ThreadName};
use shekyl_types::PowHash;

use crate::address::MiningAddress;
use crate::found::{Found, FoundBlocks};
use crate::job::{Claim, JobBoard, NONE_SEEN};
use crate::rate::{HashRate, RateRing};

/// Why [`Miner::start`] started nothing.
#[derive(Debug)]
pub enum MinerStartRefused {
    /// The budget holds one permit. The miner never takes the last free
    /// permit (`shekyl-hash-budget` module docs), so on this budget it would
    /// never hash: a miner reported active at zero. Refused instead.
    OnePermit,
    /// The OS refused a thread. The workers already started were stopped
    /// and joined.
    Thread(io::Error),
}

impl core::fmt::Display for MinerStartRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OnePermit => f.write_str(
                "this host has one hashing permit, and the miner never takes the last one; \
                 it would never hash",
            ),
            Self::Thread(e) => write!(f, "a miner thread could not start: {e}"),
        }
    }
}

impl std::error::Error for MinerStartRefused {}

/// The OS thread name and ledger label of every worker.
const WORKER_NAME: &str = "sk-miner";

/// What the miner is started with: where it pays and how many threads it
/// searches with.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    /// The address the template producer pays.
    pub address: MiningAddress,
    /// Worker threads.
    pub threads: NonZeroUsize,
}

/// The miner's state as `mining_status` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct MinerStatus {
    /// Workers are running (a stopped miner is not reported at all: it has
    /// been dropped).
    pub active: bool,
    /// Worker threads.
    pub threads: usize,
    /// The address mined to, as it was given.
    pub address: String,
    /// Every worker's hashes over the window, summed.
    pub rate: HashRate,
    /// Each worker's, in worker order.
    pub per_thread: Vec<HashRate>,
    /// Workers running at normal priority because the platform refused to
    /// lower them (`SH-3`'s count; `0` is the expected reading).
    pub not_lowered: usize,
}

struct Shared {
    board: Arc<JobBoard>,
    caches: Arc<CacheStore>,
    /// The daemon's one hasher budget: a permit per hash (PR2-Q3).
    budget: Budget,
    found: FoundBlocks,
    stop: AtomicBool,
    started: Instant,
    rates: Vec<RateRing>,
    not_lowered: AtomicUsize,
    /// Each worker's seed while it holds that seed's cache: set before the
    /// lookup and cleared after the cache is dropped, so a reader never
    /// sees a worker without a cache it holds.
    held: Vec<Mutex<Option<Seedhash>>>,
    /// Each worker has returned, or is about to: its join will not wait.
    exited: Vec<AtomicBool>,
}

impl Shared {
    fn second(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn hold(&self, index: usize, seed: Option<Seedhash>) {
        *self.held[index]
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = seed;
    }
}

/// Marks a worker exited when it returns, unwinding included.
struct Exiting<'a>(&'a AtomicBool);

impl Drop for Exiting<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The running miner. Dropping it stops and joins every worker;
/// [`Miner::stop`] stops it without waiting for them.
pub struct Miner {
    shared: Arc<Shared>,
    workers: Vec<DedicatedThread>,
    address: String,
}

/// Worker `index`'s slice of the nonce space: `threads` equal slices of
/// `0..=u32::MAX`, the last taking the remainder.
fn nonce_range(index: usize, threads: NonZeroUsize) -> RangeInclusive<u32> {
    let space = u64::from(u32::MAX) + 1;
    let n = u64::try_from(threads.get()).expect("a thread count fits u64");
    let i = u64::try_from(index).expect("a worker index fits u64");
    let span = space / n;
    let start = i * span;
    let end = if i + 1 == n {
        space - 1
    } else {
        start + span - 1
    };
    let narrow = |v: u64| u32::try_from(v).expect("inside the nonce space");
    narrow(start)..=narrow(end)
}

/// One worker: lower its priority, then mine each newer job until it is
/// superseded, solved, or the range runs out; stop when told.
fn work(shared: &Shared, index: usize, range: RangeInclusive<u32>) {
    let _exiting = Exiting(&shared.exited[index]);
    if let Err(refused) = shekyl_thread_priority::lower_current_thread() {
        let before = shared.not_lowered.fetch_add(1, Ordering::Relaxed);
        if before == 0 {
            tracing::warn!(
                %refused,
                "a miner thread runs at normal priority: the platform refused to lower it"
            );
        }
    }
    let rate = &shared.rates[index];
    let mut seen = NONE_SEEN;
    while let Some(posted) = shared.board.next_after(seen, &shared.stop) {
        seen = posted.generation;
        let seed = Seedhash::from_bytes(*posted.job.seed.as_bytes());
        // A derivation would publish into the transient slot and evict the
        // validator's spare, and the seed is the job's, not one this loop
        // pinned. `pin_canonical` is the fill. A template whose seed is not
        // held is the composition root's bug; this worker leaves the job.
        shared.hold(index, Some(seed));
        let Some(cache) = shared.caches.lookup(&seed) else {
            shared.hold(index, None);
            tracing::error!(
                seed = %posted.job.seed,
                height = %posted.job.height,
                generation = posted.generation.to_raw(),
                "the miner left a job whose seed is not held; it does not derive a cache"
            );
            continue;
        };
        let mut preimage = posted.preimage.clone();
        let at = posted.nonce_offset;
        for nonce in range.clone() {
            if shared.stop.load(Ordering::Relaxed) || !shared.board.searching(posted.generation) {
                break;
            }
            preimage[at..at + 4].copy_from_slice(&nonce.to_le_bytes());
            // One permit per hash, and never the last: a hash at nice 19
            // can run for about a minute, and the chain must not wait that
            // out. Stop unblocks the wait; an in-progress hash finishes.
            let Some(permit) = shared.budget.acquire_unless(Class::Miner, &shared.stop) else {
                break;
            };
            let pow = compute_hash(&cache, &preimage);
            drop(permit);
            // A stop does not wait for this hash: what it finished after
            // the stop is dropped here, and the claim below re-reads the
            // flag under the board's lock, where the stop sets it.
            if shared.stop.load(Ordering::Acquire) {
                break;
            }
            rate.record(shared.second());
            if !check_hash(&pow, posted.job.difficulty) {
                continue;
            }
            let mut block = posted.job.block.clone();
            block.header.nonce = nonce;
            let found = Found {
                block,
                height: posted.job.height,
                generation: posted.generation,
                pow: PowHash::from_bytes(pow),
            };
            match shared
                .board
                .claim_and_deliver(posted.generation, &shared.stop, || {
                    shared.found.deliver(found)
                }) {
                Claim::Delivered => tracing::info!(
                    height = %posted.job.height,
                    generation = posted.generation.to_raw(),
                    "the miner found a block"
                ),
                Claim::InboxClosed => tracing::error!(
                    height = %posted.job.height,
                    "the miner found a block and nothing receives it"
                ),
                Claim::Stopped | Claim::Superseded => {}
            }
            break;
        }
        drop(cache);
        shared.hold(index, None);
    }
}

impl Miner {
    /// Start `config.threads` workers on `board`, hashing with `caches`
    /// under `budget`'s permits and sending what they find to `found`.
    ///
    /// # Errors
    ///
    /// [`MinerStartRefused`]: a one-permit budget, before anything starts;
    /// or the OS refused a thread, and the workers already started are
    /// stopped and joined before this returns.
    pub fn start(
        config: &MinerConfig,
        board: Arc<JobBoard>,
        caches: Arc<CacheStore>,
        budget: Budget,
        found: FoundBlocks,
    ) -> Result<Self, MinerStartRefused> {
        if budget.permits() < 2 {
            return Err(MinerStartRefused::OnePermit);
        }
        let threads = config.threads;
        let shared = Arc::new(Shared {
            board,
            caches,
            budget,
            found,
            stop: AtomicBool::new(false),
            started: Instant::now(),
            rates: (0..threads.get()).map(|_| RateRing::new()).collect(),
            not_lowered: AtomicUsize::new(0),
            held: (0..threads.get()).map(|_| Mutex::new(None)).collect(),
            exited: (0..threads.get()).map(|_| AtomicBool::new(false)).collect(),
        });
        let name = ThreadName::new(WORKER_NAME).expect("a fixed, valid thread name");
        let mut miner = Self {
            shared,
            workers: Vec::with_capacity(threads.get()),
            address: config.address.encoded().to_owned(),
        };
        for index in 0..threads.get() {
            let shared = Arc::clone(&miner.shared);
            let range = nonce_range(index, threads);
            // On an error `miner` drops here, which stops and joins the
            // workers already running.
            let worker = spawn_dedicated(&name, move || work(&shared, index, range))
                .map_err(MinerStartRefused::Thread)?;
            miner.workers.push(worker);
        }
        Ok(miner)
    }

    /// What the miner is doing.
    #[must_use]
    pub fn status(&self) -> MinerStatus {
        let now = self.shared.second();
        let per_thread: Vec<HashRate> = self.shared.rates.iter().map(|r| r.rate(now)).collect();
        let rate = HashRate {
            hashes: per_thread.iter().map(|r| r.hashes).sum(),
            window: per_thread.first().map(|r| r.window).unwrap_or_default(),
        };
        MinerStatus {
            active: !self.shared.stop.load(Ordering::Acquire),
            threads: self.workers.len(),
            address: self.address.clone(),
            rate,
            per_thread,
            not_lowered: self.shared.not_lowered.load(Ordering::Relaxed),
        }
    }

    /// Stop every worker without waiting for them, and return them to be
    /// joined.
    ///
    /// A worker in a hash finishes it first, and a hash at nice 19 on a busy
    /// host can take most of a minute, so the stop does not wait: the
    /// returned [`Draining`] holds the workers. Nothing they finish after
    /// this returns reaches the found-block inbox ([`JobBoard`]'s claim
    /// reads the stop under the lock the stop sets it under).
    #[must_use = "the stopped workers are joined through what this returns"]
    pub fn stop(mut self) -> Draining {
        self.signal();
        Draining {
            shared: Arc::clone(&self.shared),
            workers: std::mem::take(&mut self.workers),
        }
    }

    fn signal(&self) {
        // The board flag first, then the budget: a worker blocked in
        // `acquire_unless` reads the flag only after `wake`, and a worker
        // between hashes sees the flag in `next_after`.
        self.shared.board.stop(&self.shared.stop);
        self.shared.budget.wake();
    }

    fn halt(&mut self) {
        self.signal();
        for worker in &mut self.workers {
            if worker.join().is_err() {
                tracing::error!("a miner thread panicked");
            }
        }
        self.workers.clear();
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.halt();
    }
}

/// A stopped miner's workers, still finishing the hashes they were in.
/// Each holds the cache of the seed it was mining until its hash ends.
/// Dropping it joins them.
pub struct Draining {
    shared: Arc<Shared>,
    workers: Vec<DedicatedThread>,
}

impl Draining {
    /// Every worker has returned: joining does not wait.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.shared
            .exited
            .iter()
            .all(|exited| exited.load(Ordering::Acquire))
    }

    /// A worker still holds a cache for a seed other than `seed`; with
    /// `None`, for any seed.
    #[must_use]
    pub fn holds_other_than(&self, seed: Option<&Seedhash>) -> bool {
        holds_other_than(&self.shared.held, seed)
    }

    /// Join every worker. Waits for the hashes they are still in.
    pub fn join(mut self) {
        self.join_all();
    }

    fn join_all(&mut self) {
        for worker in &mut self.workers {
            if worker.join().is_err() {
                tracing::error!("a miner thread panicked");
            }
        }
        self.workers.clear();
    }
}

impl Drop for Draining {
    fn drop(&mut self) {
        self.join_all();
    }
}

fn holds_other_than(held: &[Mutex<Option<Seedhash>>], seed: Option<&Seedhash>) -> bool {
    held.iter().any(|slot| {
        slot.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|holding| Some(holding) != seed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A start waits only for stopped workers holding another seed's cache:
    /// one on the same seed shares it, and none at all holds nothing.
    #[test]
    fn a_draining_worker_holds_only_the_seed_it_was_mining() {
        let a = Seedhash::from_bytes([1; 32]);
        let b = Seedhash::from_bytes([2; 32]);
        let held = vec![Mutex::new(None), Mutex::new(Some(a))];
        assert!(
            !holds_other_than(&held, Some(&a)),
            "the same seed is shared"
        );
        assert!(
            holds_other_than(&held, Some(&b)),
            "another seed is a second cache"
        );
        assert!(
            holds_other_than(&held, None),
            "with no job posted, any seed counts"
        );
        let idle = vec![Mutex::new(None), Mutex::new(None)];
        assert!(!holds_other_than(&idle, None), "workers that hold nothing");
    }

    #[test]
    fn the_nonce_ranges_partition_the_space() {
        for threads in [1usize, 2, 3, 7, 64] {
            let n = NonZeroUsize::new(threads).expect("non-zero");
            let ranges: Vec<_> = (0..threads).map(|i| nonce_range(i, n)).collect();
            assert_eq!(*ranges[0].start(), 0);
            assert_eq!(*ranges[threads - 1].end(), u32::MAX);
            for pair in ranges.windows(2) {
                assert_eq!(
                    u64::from(*pair[0].end()) + 1,
                    u64::from(*pair[1].start()),
                    "{threads} threads: adjacent and disjoint"
                );
            }
        }
    }
}

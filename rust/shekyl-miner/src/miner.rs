// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`Miner`]: the workers, their status, and stopping them.

use std::io;
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use shekyl_difficulty::check_hash;
use shekyl_pow_randomx::{compute_hash, CacheStore, Seedhash};
use shekyl_thread_ledger::{spawn_dedicated, DedicatedThread, ThreadName};
use shekyl_types::PowHash;

use crate::address::MiningAddress;
use crate::found::{Found, FoundBlocks};
use crate::job::{JobBoard, NONE_SEEN};
use crate::rate::{HashRate, RateRing};

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
    found: FoundBlocks,
    stop: AtomicBool,
    started: Instant,
    rates: Vec<RateRing>,
    not_lowered: AtomicUsize,
}

impl Shared {
    fn second(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

/// The running miner. Dropping it stops and joins every worker.
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
        let cache = shared.caches.lookup_or_derive(&seed);
        let mut preimage = posted.preimage.clone();
        let at = posted.nonce_offset;
        for nonce in range.clone() {
            if shared.stop.load(Ordering::Relaxed) || !shared.board.searching(posted.generation) {
                break;
            }
            preimage[at..at + 4].copy_from_slice(&nonce.to_le_bytes());
            let pow = compute_hash(&cache, &preimage);
            rate.record(shared.second());
            if !check_hash(&pow, posted.job.difficulty) {
                continue;
            }
            if shared.board.claim(posted.generation) {
                let mut block = posted.job.block.clone();
                block.header.nonce = nonce;
                let found = Found {
                    block,
                    height: posted.job.height,
                    generation: posted.generation,
                    pow: PowHash::from_bytes(pow),
                };
                tracing::info!(
                    height = %posted.job.height,
                    generation = posted.generation.to_raw(),
                    "the miner found a block"
                );
                if !shared.found.deliver(found) {
                    tracing::error!(
                        height = %posted.job.height,
                        "the miner found a block and nothing receives it"
                    );
                }
            }
            break;
        }
    }
}

impl Miner {
    /// Start `config.threads` workers on `board`, hashing with `caches`
    /// and sending what they find to `found`.
    ///
    /// # Errors
    ///
    /// The OS refused a thread. The workers already started are stopped
    /// and joined before this returns.
    pub fn start(
        config: &MinerConfig,
        board: Arc<JobBoard>,
        caches: Arc<CacheStore>,
        found: FoundBlocks,
    ) -> io::Result<Self> {
        let threads = config.threads;
        let shared = Arc::new(Shared {
            board,
            caches,
            found,
            stop: AtomicBool::new(false),
            started: Instant::now(),
            rates: (0..threads.get()).map(|_| RateRing::new()).collect(),
            not_lowered: AtomicUsize::new(0),
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
            let worker = spawn_dedicated(&name, move || work(&shared, index, range))?;
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

    /// Stop every worker and join it.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.shared.board.stop(&self.shared.stop);
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

#[cfg(test)]
mod tests {
    use super::*;

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

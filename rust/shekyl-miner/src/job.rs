// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`JobBoard`]: the template source. One posted job at a time, numbered by
//! a generation that every publish and withdrawal advances, so a worker
//! knows its job is superseded by one atomic read.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use shekyl_difficulty::Difficulty;
use shekyl_types::{BlockHash, BlockHeight, TxHash};
use shekyl_units::AtomicUnits;
use shekyl_wire::{BlobOffsets, Block};

/// What to mine: a block whose nonce is the search, the height it connects
/// at, the seed its longhash is computed under (CEN-D3) and the difficulty
/// its hash must meet (the validator's target, CEN-D4). The rest is what
/// a miner outside the node reads from the same posting
/// (`get_block_template`): where to write in the blob, the seed the chain
/// moves to next, and what the coinbase pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The template. Its nonce is overwritten by the search.
    pub block: Block,
    /// The height the block connects at.
    pub height: BlockHeight,
    /// The RandomX seed for that height.
    pub seed: BlockHash,
    /// The difficulty the longhash must satisfy.
    pub difficulty: Difficulty,
    /// Where the header nonce and the coinbase's reserved extra nonce sit
    /// in `block`'s blob.
    pub offsets: BlobOffsets,
    /// The seed of the next RandomX epoch, once the chain has it and it
    /// differs from `seed`.
    pub next_seed: Option<BlockHash>,
    /// What the coinbase pays the miner: its emission leg and its fee
    /// income after the burn.
    pub reward: AtomicUnits,
    /// The effective median block weight the block was priced against.
    pub median_weight: u64,
    /// The gross emission before this block.
    pub already_generated: AtomicUnits,
    /// The bodies the block lists, in its order.
    pub listed: Vec<ListedBody>,
}

/// One body a job's block lists, as a miner outside the node sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListedBody {
    /// The transaction's id.
    pub id: TxHash,
    /// Its weight.
    pub weight: u64,
    /// Its fee.
    pub fee: AtomicUnits,
}

/// A board's posting number. Every publish and withdrawal takes the next
/// one; a worker holding an older one is mining a superseded job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    /// The number.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }

    /// `raw` as a generation. The board mints the live ones; tests name one.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

/// A job as the workers read it: the preimage built once, with where its
/// nonce goes.
pub(crate) struct Posted {
    pub(crate) generation: Generation,
    pub(crate) job: Job,
    pub(crate) preimage: Vec<u8>,
    pub(crate) nonce_offset: usize,
}

struct State {
    posted: Option<Arc<Posted>>,
    next: u64,
}

/// The template source the miner's workers read (module docs).
pub struct JobBoard {
    state: Mutex<State>,
    changed: Condvar,
    /// The newest generation, readable without the lock.
    current: AtomicU64,
    /// The newest generation a worker found a block for.
    solved: AtomicU64,
}

impl Default for JobBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl JobBoard {
    /// An empty board: nothing to mine until a job is published.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                posted: None,
                next: 1,
            }),
            changed: Condvar::new(),
            current: AtomicU64::new(0),
            solved: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn advance(&self, state: &mut State, posted: Option<Job>) -> Generation {
        let generation = Generation(state.next);
        state.next += 1;
        state.posted = posted.map(|job| {
            let preimage = job.block.pow_blob();
            let nonce_offset = job.block.header.nonce_offset();
            Arc::new(Posted {
                generation,
                job,
                preimage,
                nonce_offset,
            })
        });
        self.current.store(generation.0, Ordering::Release);
        self.changed.notify_all();
        generation
    }

    /// Post `job`, superseding whatever was posted.
    pub fn publish(&self, job: Job) -> Generation {
        let mut state = self.lock();
        self.advance(&mut state, Some(job))
    }

    /// Post nothing, superseding whatever was posted: the workers stop and
    /// wait for the next job.
    pub fn withdraw(&self) -> Generation {
        let mut state = self.lock();
        self.advance(&mut state, None)
    }

    /// The job posted now and its generation; `None` while withdrawn or
    /// before the first posting.
    #[must_use]
    pub fn posted(&self) -> Option<(Generation, Job)> {
        self.lock()
            .posted
            .as_ref()
            .map(|posted| (posted.generation, posted.job.clone()))
    }

    /// The newest generation.
    #[must_use]
    pub fn generation(&self) -> Generation {
        Generation(self.current.load(Ordering::Acquire))
    }

    /// Whether a worker on `generation` should keep searching: the job is
    /// still the posted one and no worker has found its block.
    pub(crate) fn searching(&self, generation: Generation) -> bool {
        self.current.load(Ordering::Acquire) == generation.0
            && self.solved.load(Ordering::Acquire) != generation.0
    }

    /// Claim `generation`'s solution and hand it on with `deliver`, unless
    /// the miner has stopped or the generation is superseded or solved.
    ///
    /// Everything happens under the lock [`publish`](Self::publish) and
    /// [`stop`](Self::stop) hold, `deliver` included. A worker that has
    /// already passed [`searching`](Self::searching) cannot record a
    /// generation a newer posting has withdrawn: `current` moves only under
    /// this lock. And a block cannot leave after a stop has returned: the
    /// stop sets its flag under this lock, so either the claim saw the flag
    /// and delivers nothing, or the delivery finished before the stop could
    /// take the lock. `deliver` must not take this lock. `solved` stays an
    /// atomic so `searching` does not take it.
    pub(crate) fn claim_and_deliver(
        &self,
        generation: Generation,
        stop: &AtomicBool,
        deliver: impl FnOnce() -> bool,
    ) -> Claim {
        let _state = self.lock();
        if stop.load(Ordering::Acquire) {
            return Claim::Stopped;
        }
        let first = self.current.load(Ordering::Acquire) == generation.0
            && self
                .solved
                .fetch_max(generation.0, Ordering::AcqRel)
                .lt(&generation.0);
        if !first {
            return Claim::Superseded;
        }
        if deliver() {
            Claim::Delivered
        } else {
            Claim::InboxClosed
        }
    }

    /// The posted job newer than `seen`, waiting for one; `None` once
    /// `stop` is set. A posting that is a withdrawal is waited past.
    pub(crate) fn next_after(&self, seen: Generation, stop: &AtomicBool) -> Option<Arc<Posted>> {
        let mut state = self.lock();
        loop {
            if stop.load(Ordering::Acquire) {
                return None;
            }
            if let Some(posted) = &state.posted {
                if posted.generation > seen {
                    return Some(Arc::clone(posted));
                }
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Set `stop` under the board's lock and wake every waiter, so a worker
    /// cannot check the flag, miss the store and then sleep through it.
    pub(crate) fn stop(&self, stop: &AtomicBool) {
        let _state = self.lock();
        stop.store(true, Ordering::Release);
        self.changed.notify_all();
    }
}

/// What [`JobBoard::claim_and_deliver`] did with a solution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Claim {
    /// Claimed and handed on.
    Delivered,
    /// Claimed, and the inbox refused it: nothing will connect the block.
    InboxClosed,
    /// The miner had stopped: dropped before it was claimed.
    Stopped,
    /// A newer posting, or another worker's solution, came first.
    Superseded,
}

/// The generation before any posting: a worker starts having seen it.
pub(crate) const NONE_SEEN: Generation = Generation(0);

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// A stop that has returned lets nothing through: the claim reads the
    /// flag under the lock the stop set it under. Red edit: drop the
    /// flag check from `claim_and_deliver`.
    #[test]
    fn a_claim_after_the_stop_delivers_nothing() {
        let board = JobBoard::new();
        let generation = board.withdraw();
        let stop = AtomicBool::new(false);
        board.stop(&stop);
        let claimed = board.claim_and_deliver(generation, &stop, || {
            panic!("a stopped miner delivered a block")
        });
        assert_eq!(claimed, Claim::Stopped);
    }

    /// A worker between its claim and its hand-off holds the board's lock,
    /// so a stop cannot return in between: the delivery under way finishes
    /// first, and the next claim sees the stop. Red edit: release the lock
    /// before `deliver` (a check-then-deliver across it), and the stop
    /// returns while the worker is still handing its block on.
    #[test]
    fn a_stop_waits_out_a_delivery_already_under_way() {
        let board = Arc::new(JobBoard::new());
        let first = board.withdraw();
        let stop = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let worker = {
            let board = Arc::clone(&board);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                board.claim_and_deliver(first, &stop, || {
                    entered_tx.send(()).expect("the test waits");
                    release_rx.recv().expect("the test releases");
                    true
                })
            })
        };
        entered.recv().expect("the worker reached its hand-off");
        let (stopped_tx, stopped) = mpsc::channel();
        let stopper = {
            let board = Arc::clone(&board);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                board.stop(&stop);
                stopped_tx.send(()).expect("the test waits");
            })
        };
        assert!(
            stopped.recv_timeout(Duration::from_millis(200)).is_err(),
            "the stop returned while a claimed block was still being handed on"
        );
        release.send(()).expect("the worker waits");
        assert_eq!(worker.join().expect("the worker"), Claim::Delivered);
        stopped
            .recv_timeout(Duration::from_secs(10))
            .expect("the stop returns once the hand-off is done");
        stopper.join().expect("the stopper");
        let next = board.withdraw();
        assert_eq!(
            board.claim_and_deliver(next, &stop, || panic!("delivered after the stop")),
            Claim::Stopped
        );
    }

    /// A superseded generation, and a solved one, are not claimed.
    #[test]
    fn a_superseded_or_solved_generation_is_not_claimed() {
        let board = JobBoard::new();
        let stop = AtomicBool::new(false);
        let old = board.withdraw();
        let current = board.withdraw();
        assert_eq!(
            board.claim_and_deliver(old, &stop, || panic!("a superseded job delivered")),
            Claim::Superseded
        );
        assert_eq!(
            board.claim_and_deliver(current, &stop, || true),
            Claim::Delivered
        );
        assert_eq!(
            board.claim_and_deliver(current, &stop, || panic!("a second solution delivered")),
            Claim::Superseded
        );
        let closed = board.withdraw();
        assert_eq!(
            board.claim_and_deliver(closed, &stop, || false),
            Claim::InboxClosed
        );
    }
}

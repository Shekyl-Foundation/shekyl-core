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
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Block;

/// What to mine: a block whose nonce is the search, the height it connects
/// at, the seed its longhash is computed under (CEN-D3) and the difficulty
/// its hash must meet (the validator's target, CEN-D4).
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

    /// Claim `generation`'s solution. `true` for the first claimant only,
    /// and only while that generation is still the posted one.
    ///
    /// The check and the record share the lock [`publish`](Self::publish)
    /// holds. A worker that has already passed [`searching`](Self::searching)
    /// cannot record a generation a newer posting has withdrawn: `current`
    /// moves only under this lock. `solved` stays an atomic so `searching`
    /// does not take it.
    pub(crate) fn claim(&self, generation: Generation) -> bool {
        let _state = self.lock();
        self.current.load(Ordering::Acquire) == generation.0
            && self
                .solved
                .fetch_max(generation.0, Ordering::AcqRel)
                .lt(&generation.0)
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

/// The generation before any posting: a worker starts having seen it.
pub(crate) const NONE_SEEN: Generation = Generation(0);

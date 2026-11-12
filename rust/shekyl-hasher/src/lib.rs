// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one owner of every RandomX cache in the daemon
//! (`docs/design/RANDOMX_CACHE_ACTOR.md`, HA-R1…HA-R8).
//!
//! A cache is 256 MiB. Nothing outside this crate builds, holds or frees
//! one. What stays resident is computed from the seeds the node needs, the
//! ranked list ([`Hasher::rank`]), and from the jobs in flight: there is no
//! record of the slots to keep true, because there are no slots.
//!
//! # Places
//!
//! [`CAP`] places in all, counting warm caches, caches a job hashes under,
//! a build in progress, and a cache being dropped: a freed place is free
//! again only once its 256 MiB is returned, so the cap is the memory, not a
//! count. The ranked list's window, its first one or two
//! seeds, has a place reserved for each seed whether it is built or not,
//! and a job never frees one (HA-R7). The other places go to jobs whose
//! seed is outside the window, first in, first out (HA-R8); class orders
//! permits and nothing else. A place no job needs holds the list's third
//! seed (HA-R2). A job always gets its cache (HA-R1): one whose seed is not
//! warm waits for its build, inside the cap.
//!
//! # Jobs
//!
//! Work reaches a cache only through a job, and a job names one seed:
//!
//! - [`Hasher::run`] holds one permit for the job, which is one form.
//! - [`Hasher::lend`] holds none for the job; each [`Loan::hash`] takes one.
//!   A job that hashes on several threads, or many times, uses it: a
//!   switch's plan, a header-proof command, the evidence check.
//! - [`Hasher::lend_warm`] builds nothing and never waits for a place: the
//!   miner and `calc_pow`. Its lease is cancelled when its seed leaves the
//!   list, or when a queued job or a window build needs its place; a
//!   cancel ends a permit wait at once.
//!
//! [`Lent`] and [`Loan`] hand out hashes, never the cache. Neither is
//! `Clone`, and the `for<'job>` bound on each job keeps both from leaving
//! it, so no cache outlives the job that borrowed it.
//!
//! A job must not ask for another job while it holds one: it could wait for
//! a place behind itself. `run`, `lend` and `lend_warm` panic when called
//! from inside a job's closure on the same thread. A thread the job spawns
//! inside its closure is not covered.
//!
//! # Deadlock
//!
//! Never ask for a job while holding a budget permit. The builder takes a
//! permit to build the cache the job waits for; on a one-permit budget the
//! caller's own permit is the one it waits for. The crate cannot see this:
//! a permit belongs to no thread. Every consumer takes its permits through
//! the hasher (`run`, [`Loan::hash`]) and holds none of its own (doc §5.3).
//!
//! # Builds
//!
//! One builder thread derives one cache at a time, under one permit of the
//! build's class: the highest class waiting for it, `Chain` for a window
//! seed, and for the third the class of the job that pushed it out (§5.4).
//! When the class rises while the builder waits for its permit, the wait
//! ends and the builder asks again at the new class.
//!
//! # This crate has no end of its own
//!
//! Rule 25 asks a long-lived task the node starts to report its end through
//! `Node::ended()` when it can end on its own, by a fault or by a closed
//! input. This one cannot. `PreparedCache::derive` is infallible. An
//! allocation failure aborts in `Box::new_zeroed_slice`. Both production
//! profiles abort on panic. The list arrives by method call, not a channel,
//! so no input can close. A `NodeEnd` variant for it could never fire: a
//! check that cannot fail.
#![deny(unsafe_code)]

mod core;

use std::cell::Cell;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use shekyl_hash_budget::Budget;
pub use shekyl_hash_budget::Class;
use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};
use shekyl_thread_ledger::{spawn_dedicated, DedicatedThread, ThreadName};

use crate::core::{Core, Decision, LeaseId, WarmRefused};

/// Places in all (HA-R2): warm caches, caches a job hashes under, and a
/// build in progress.
pub const CAP: usize = 3;

/// The seeds the node needs, in rank order (doc §5.1): the window's one or
/// two seeds, canonical first, then the third with the class its jobs hash
/// at. Sent whole on every change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ranked {
    window: Vec<Seedhash>,
    third: Option<(Seedhash, Class)>,
}

impl Ranked {
    /// The list. A seed named twice is refused: this is the one place
    /// distinctness is checked.
    ///
    /// # Errors
    ///
    /// [`RepeatedSeed`] when two of the three are the same seed.
    pub fn new(
        canonical: Seedhash,
        other: Option<Seedhash>,
        third: Option<(Seedhash, Class)>,
    ) -> Result<Self, RepeatedSeed> {
        let mut seen = vec![canonical];
        for seed in other.into_iter().chain(third.map(|(seed, _)| seed)) {
            if seen.contains(&seed) {
                return Err(RepeatedSeed { seed });
            }
            seen.push(seed);
        }
        let window = std::iter::once(canonical).chain(other).collect();
        Ok(Self { window, third })
    }

    /// The window's seeds, canonical first.
    fn window(&self) -> &[Seedhash] {
        &self.window
    }

    /// The third seed and its class.
    const fn third(&self) -> Option<(Seedhash, Class)> {
        self.third
    }
}

/// A ranked list named one seed twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepeatedSeed {
    /// The seed named twice.
    pub seed: Seedhash,
}

impl fmt::Display for RepeatedSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the ranked list names seed {} twice", self.seed)
    }
}

impl std::error::Error for RepeatedSeed {}

/// What one place holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residency {
    /// Built, and no job holds it.
    Warm,
    /// Built, and at least one job hashes under it.
    Leased,
    /// Reserved for a build, or being derived.
    Building,
    /// Freed: its cache is being dropped. The place stays counted until the
    /// 256 MiB is returned.
    Retiring,
}

/// What is resident (doc §5.6), published after every change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resident {
    /// Each place in use: its seed and what it holds. The length is the
    /// live-cache count the memory budget is checked against (PB-R1).
    pub caches: Vec<(Seedhash, Residency)>,
    /// Caches derived since start.
    pub builds: u64,
    /// Nanoseconds those derives took, summed.
    pub build_ns: u64,
}

/// Why a [`Loan::hash`] did not hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unhashed {
    /// The caller's stop flag was set during the permit wait.
    Stopped,
    /// A warm loan's seed left the ranked list, or a queued job or a window
    /// build needs its place.
    Cancelled,
}

impl fmt::Display for Unhashed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stopped => "the caller stopped before a permit was granted",
            Self::Cancelled => {
                "the warm loan was cancelled: its seed left the list, or a job needs its place"
            }
        })
    }
}

impl std::error::Error for Unhashed {}

/// Why [`Hasher::lend_warm`] did not lend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Declined {
    /// The seed is not listed, not built, or is the third while a job waits
    /// for a place.
    NotWarm,
    /// The caller's stop flag was set, or the hasher is stopping.
    Stopped,
}

impl fmt::Display for Declined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotWarm => "no warm cache for this seed",
            Self::Stopped => "stopped",
        })
    }
}

impl std::error::Error for Declined {}

std::thread_local! {
    /// Set while this thread runs a job's closure.
    static IN_JOB: Cell<bool> = const { Cell::new(false) };
}

/// Marks this thread as inside a job until dropped.
struct InJob;

impl InJob {
    /// Panics when this thread is already inside a job: one job holds one
    /// lease at a time, and a nested request could wait for a place behind
    /// the job asking for it.
    fn check() {
        assert!(
            !IN_JOB.with(Cell::get),
            "a hasher job asked for another job: one job holds one lease at a time, \
             and a nested request can wait for a place behind itself"
        );
    }

    fn enter() -> Self {
        Self::check();
        IN_JOB.with(|cell| cell.set(true));
        Self
    }
}

impl Drop for InJob {
    fn drop(&mut self) {
        IN_JOB.with(|cell| cell.set(false));
    }
}

/// From [`Hasher::run`]: the job already holds its permit.
pub struct Lent<'job> {
    cache: &'job PreparedCache,
}

impl Lent<'_> {
    /// RandomX over `blob` under the job's seed.
    #[must_use]
    pub fn hash(&self, blob: &[u8]) -> [u8; 32] {
        compute_hash(self.cache, blob)
    }
}

/// From [`Hasher::lend`] and [`Hasher::lend_warm`]: one permit per hash.
pub struct Loan<'job> {
    cache: &'job PreparedCache,
    budget: &'job Budget,
    class: Class,
    stop: &'job AtomicBool,
    /// Set when a warm loan is cancelled. `None` for a job's loan, which is
    /// never cancelled (HA-R1).
    cancel: Option<&'job AtomicBool>,
}

impl Loan<'_> {
    /// RandomX over `blob` under the job's seed, under one permit of the
    /// job's class.
    ///
    /// # Errors
    ///
    /// [`Unhashed::Cancelled`] for a warm loan that was cancelled: before
    /// the permit wait, during it (the cancel ends the wait), or after it.
    /// [`Unhashed::Stopped`] when the caller's stop flag ended the wait.
    /// When both are set, the cancel is reported: the loan is over either
    /// way, and the cancel is the hasher's news to the caller.
    pub fn hash(&self, blob: &[u8]) -> Result<[u8; 32], Unhashed> {
        let cancelled = || self.cancel.is_some_and(|flag| flag.load(Ordering::Acquire));
        if cancelled() {
            return Err(Unhashed::Cancelled);
        }
        let permit = match self.cancel {
            Some(cancel) => self
                .budget
                .acquire_unless_either(self.class, self.stop, cancel),
            None => self.budget.acquire_unless(self.class, self.stop),
        };
        let Some(permit) = permit else {
            return Err(if cancelled() {
                Unhashed::Cancelled
            } else {
                Unhashed::Stopped
            });
        };
        if cancelled() {
            return Err(Unhashed::Cancelled);
        }
        let hash = compute_hash(self.cache, blob);
        drop(permit);
        Ok(hash)
    }
}

/// The handle every caller shares. Cheap to clone.
#[derive(Clone)]
pub struct Hasher {
    shared: Arc<Shared>,
}

/// The stop owner. Dropping it stops the hasher ([`Owner::stop`]).
pub struct Owner {
    shared: Arc<Shared>,
    builder: Option<DedicatedThread>,
}

struct Shared {
    budget: Budget,
    state: Mutex<State>,
    changed: Condvar,
    resident: tokio::sync::watch::Sender<Resident>,
    /// The builder's permit wait gives up when this is set: its build's
    /// class rose, the choice moved, or the hasher is stopping.
    raise: AtomicBool,
}

struct State {
    core: Core,
    caches: Vec<(Seedhash, Arc<PreparedCache>)>,
    cancels: Vec<(LeaseId, Arc<AtomicBool>)>,
    builds: u64,
    build_ns: u64,
    builder_exit: bool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        self.changed
            .wait(state)
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Act on `decisions` under the lock, publish the residency and wake
    /// every waiter. The caches it frees are returned, for
    /// [`retire`](Self::retire) after the lock is released: each place
    /// stays taken until then.
    #[must_use = "a freed cache's place is free only once retire reports its drop"]
    fn apply(&self, state: &mut State, decisions: Vec<Decision>) -> Freed {
        let mut freed = Vec::new();
        let mut cancelled = false;
        for decision in decisions {
            match decision {
                Decision::Free { seed } => {
                    let at = state
                        .caches
                        .iter()
                        .position(|(held, _)| *held == seed)
                        .expect("the core frees only a resident cache");
                    freed.push(state.caches.swap_remove(at));
                }
                Decision::Cancel { lease } => {
                    if let Some((_, flag)) = state.cancels.iter().find(|(id, _)| *id == lease) {
                        flag.store(true, Ordering::Release);
                        cancelled = true;
                    }
                }
                Decision::WakeBuilder => {
                    self.raise.store(true, Ordering::Release);
                    self.budget.wake();
                }
                Decision::Grant { .. } | Decision::Schedule { .. } => {}
            }
        }
        // After every flag is stored: a loan parked for a permit reads its
        // cancel under the budget's lock.
        if cancelled {
            self.budget.wake();
        }
        self.publish(state);
        self.changed.notify_all();
        freed
    }

    /// Drop each freed cache with no lock held, then report the drops to
    /// the core, which frees their places; what that frees in turn is
    /// dropped the same way. Called with no lock held, by every path that
    /// applies decisions.
    fn retire(&self, mut freed: Freed) {
        while !freed.is_empty() {
            let seeds: Vec<Seedhash> = freed.iter().map(|(seed, _)| *seed).collect();
            for (_, cache) in freed {
                // Each is the last holder: every lease's clone went back
                // before its return reached the core.
                debug_assert_eq!(
                    Arc::strong_count(&cache),
                    1,
                    "a freed cache is still held: a lease kept its clone past its return"
                );
                drop(cache);
            }
            let mut state = self.lock();
            let mut decisions = Vec::new();
            for seed in seeds {
                decisions.extend(state.core.retired(seed));
            }
            let more = self.apply(&mut state, decisions);
            drop(state);
            freed = more;
        }
    }

    fn publish(&self, state: &State) {
        let next = Resident {
            caches: state.core.residency(),
            builds: state.builds,
            build_ns: state.build_ns,
        };
        self.resident.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }

    fn cache(state: &State, seed: Seedhash) -> Arc<PreparedCache> {
        let (_, cache) = state
            .caches
            .iter()
            .find(|(held, _)| *held == seed)
            .expect("a granted lease's seed is resident");
        Arc::clone(cache)
    }

    /// Wait for a lease on `seed`. `None` when `stop` was set first, or the
    /// hasher is stopping.
    fn lease(self: &Arc<Self>, class: Class, seed: Seedhash, stop: &AtomicBool) -> Option<Lease> {
        let mut state = self.lock();
        // Read under the lock, before anything is asked of the core: a
        // stop set while this thread waited for the lock schedules nothing.
        if stop.load(Ordering::Acquire) {
            return None;
        }
        let (ticket, decisions) = state.core.request(seed, class)?;
        let mut freed = self.apply(&mut state, decisions);
        let lease = loop {
            // What this request freed is dropped before it waits: the place
            // it waits for may be that cache's.
            if !freed.is_empty() {
                drop(state);
                self.retire(std::mem::take(&mut freed));
                state = self.lock();
                continue;
            }
            // A grant made before a close stands: the stop waits for it.
            if let Some(lease) = state.core.take_grant(ticket) {
                break lease;
            }
            if stop.load(Ordering::Acquire) || state.core.closed() {
                let decisions = state.core.leave(ticket);
                let more = self.apply(&mut state, decisions);
                drop(state);
                self.retire(more);
                return None;
            }
            state = self.wait(state);
        };
        let cache = Self::cache(&state, seed);
        drop(state);
        Some(Lease {
            shared: Arc::clone(self),
            id: lease,
            cache: Some(cache),
        })
    }

    fn release(&self, lease: LeaseId) {
        let mut state = self.lock();
        state.cancels.retain(|(id, _)| *id != lease);
        let decisions = state.core.returned(lease);
        let freed = self.apply(&mut state, decisions);
        drop(state);
        self.retire(freed);
    }
}

/// Caches the core freed, with their seeds, to drop after the lock.
type Freed = Vec<(Seedhash, Arc<PreparedCache>)>;

/// One granted lease. Its clone of the cache goes before its return
/// reaches the core, so the core frees only caches nothing else holds.
struct Lease {
    shared: Arc<Shared>,
    id: LeaseId,
    cache: Option<Arc<PreparedCache>>,
}

impl Lease {
    fn cache(&self) -> &PreparedCache {
        self.cache.as_deref().expect("held until drop")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        drop(self.cache.take());
        self.shared.release(self.id);
    }
}

impl Hasher {
    /// The hasher over `budget`, and its stop owner. Spawns the builder.
    ///
    /// # Errors
    ///
    /// The OS refused the builder thread.
    pub fn start(budget: Budget) -> std::io::Result<(Self, Owner)> {
        let shared = Arc::new(Shared {
            budget,
            state: Mutex::new(State {
                core: Core::default(),
                caches: Vec::new(),
                cancels: Vec::new(),
                builds: 0,
                build_ns: 0,
                builder_exit: false,
            }),
            changed: Condvar::new(),
            resident: tokio::sync::watch::Sender::new(Resident::default()),
            raise: AtomicBool::new(false),
        });
        let name = ThreadName::new("shekyl-hasher-build").expect("the name is static");
        let worker = Arc::clone(&shared);
        let builder = spawn_dedicated(&name, move || build_loop(&worker))?;
        Ok((
            Self {
                shared: Arc::clone(&shared),
            },
            Owner {
                shared,
                builder: Some(builder),
            },
        ))
    }

    /// Replace the ranked list (doc §5.1: sent whole on every change).
    pub fn rank(&self, list: Ranked) {
        let mut state = self.shared.lock();
        let decisions = state.core.rank(list);
        let freed = self.shared.apply(&mut state, decisions);
        drop(state);
        self.shared.retire(freed);
    }

    /// Run `job` under `seed`'s cache and one permit of `class` held for the
    /// whole job, building the cache when it is not warm. The lease is
    /// taken first, then the permit. `None` when `stop` was set first, or
    /// the hasher is stopping.
    ///
    /// # Deadlock
    ///
    /// Do not call this while holding a budget permit: the build this job
    /// may wait for takes a permit, and on a one-permit budget that is the
    /// caller's (crate docs, *Deadlock*).
    ///
    /// # Panics
    ///
    /// When called from inside another job's closure on this thread.
    pub fn run<R>(
        &self,
        class: Class,
        seed: Seedhash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&Lent<'job>) -> R,
    ) -> Option<R> {
        InJob::check();
        let lease = self.shared.lease(class, seed, stop)?;
        let permit = self.shared.budget.acquire_unless(class, stop)?;
        let result = {
            let _in_job = InJob::enter();
            job(&Lent {
                cache: lease.cache(),
            })
        };
        drop(permit);
        drop(lease);
        Some(result)
    }

    /// Run `job` under `seed`'s cache with no permit held for the job: each
    /// [`Loan::hash`] takes one of `class`. Builds the cache when it is not
    /// warm. `None` when `stop` was set first, or the hasher is stopping.
    ///
    /// # Deadlock
    ///
    /// Do not call this while holding a budget permit: the build this job
    /// may wait for takes a permit, and on a one-permit budget that is the
    /// caller's (crate docs, *Deadlock*).
    ///
    /// # Panics
    ///
    /// When called from inside another job's closure on this thread.
    pub fn lend<R>(
        &self,
        class: Class,
        seed: Seedhash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&Loan<'job>) -> R,
    ) -> Option<R> {
        InJob::check();
        let lease = self.shared.lease(class, seed, stop)?;
        let result = {
            let _in_job = InJob::enter();
            job(&Loan {
                cache: lease.cache(),
                budget: &self.shared.budget,
                class,
                stop,
                cancel: None,
            })
        };
        drop(lease);
        Some(result)
    }

    /// [`lend`](Self::lend) that builds nothing and never waits for a
    /// place: the miner and `calc_pow`. Its loan is cancelled when `seed`
    /// leaves the ranked list, or when a queued job or a window build needs
    /// its place.
    ///
    /// # Errors
    ///
    /// [`Declined::NotWarm`] when `seed` is not listed, not built, or is
    /// the third while a job or a window seed waits for a place.
    /// [`Declined::Stopped`] when `stop` was set first, or the hasher is
    /// stopping.
    ///
    /// # Deadlock
    ///
    /// Do not call this while holding a budget permit. Each
    /// [`Loan::hash`] takes one; a caller that already holds the only one
    /// waits on itself (crate docs, *Deadlock*).
    ///
    /// # Panics
    ///
    /// When called from inside another job's closure on this thread.
    pub fn lend_warm<R>(
        &self,
        class: Class,
        seed: Seedhash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&Loan<'job>) -> R,
    ) -> Result<R, Declined> {
        InJob::check();
        if stop.load(Ordering::Acquire) {
            return Err(Declined::Stopped);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let lease = {
            let mut state = self.shared.lock();
            let id = state
                .core
                .request_warm(seed)
                .map_err(|refused| match refused {
                    WarmRefused::NotWarm => Declined::NotWarm,
                    WarmRefused::Closed => Declined::Stopped,
                })?;
            state.cancels.push((id, Arc::clone(&cancel)));
            let cache = Shared::cache(&state, seed);
            self.shared.publish(&state);
            Lease {
                shared: Arc::clone(&self.shared),
                id,
                cache: Some(cache),
            }
        };
        let result = {
            let _in_job = InJob::enter();
            job(&Loan {
                cache: lease.cache(),
                budget: &self.shared.budget,
                class,
                stop,
                cancel: Some(&cancel),
            })
        };
        drop(lease);
        Ok(result)
    }

    /// Wake every waiter to re-read its stop flag, and the budget's. The
    /// lock is taken before the notify, as `Budget::wake` does, so the wake
    /// cannot land between a waiter's stop check and its wait.
    pub fn wake(&self) {
        drop(self.shared.lock());
        self.shared.changed.notify_all();
        self.shared.budget.wake();
    }

    /// What is resident, published after every change.
    #[must_use]
    pub fn resident(&self) -> tokio::sync::watch::Receiver<Resident> {
        self.shared.resident.subscribe()
    }
}

impl Owner {
    /// Refuse new jobs, drop every request not yet granted (its caller
    /// returns stopped), wait for every lease already granted to return,
    /// let a running derive finish, free every cache, and join the builder.
    pub fn stop(self) {
        drop(self);
    }

    fn stop_in_place(&mut self) {
        let Some(mut builder) = self.builder.take() else {
            return;
        };
        let mut state = self.shared.lock();
        let decisions = state.core.close();
        let freed = self.shared.apply(&mut state, decisions);
        self.shared.budget.wake();
        drop(state);
        self.shared.retire(freed);
        let mut state = self.shared.lock();
        while !state.core.drained() {
            state = self.shared.wait(state);
        }
        state.builder_exit = true;
        self.shared.raise.store(true, Ordering::Release);
        self.shared.changed.notify_all();
        drop(state);
        self.shared.budget.wake();
        drop(builder.join());
        // A derive that was running when the stop came is resident now, and
        // nothing holds it.
        let mut state = self.shared.lock();
        let decisions = state.core.close();
        let freed = self.shared.apply(&mut state, decisions);
        drop(state);
        self.shared.retire(freed);
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stop_in_place();
    }
}

/// The builder: take the next build, a permit of its class, derive with no
/// lock held, report it built.
fn build_loop(shared: &Shared) {
    loop {
        let mut state = shared.lock();
        let claimed = loop {
            if state.builder_exit {
                return;
            }
            shared.raise.store(false, Ordering::Release);
            if let Some(claimed) = state.core.claim() {
                break claimed;
            }
            state = shared.wait(state);
        };
        drop(state);
        let permit = shared.budget.acquire_unless(claimed.1, &shared.raise);
        let mut state = shared.lock();
        let Some(permit) = permit else {
            state.core.unclaim();
            continue;
        };
        if !state.core.begin(claimed) {
            drop(state);
            drop(permit);
            continue;
        }
        shared.publish(&state);
        drop(state);
        let started = Instant::now();
        let cache = Arc::new(PreparedCache::derive(claimed.0));
        let took = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        drop(permit);
        let mut state = shared.lock();
        state.caches.push((claimed.0, cache));
        state.builds += 1;
        state.build_ns = state.build_ns.saturating_add(took);
        let decisions = state.core.built(claimed.0);
        let freed = shared.apply(&mut state, decisions);
        drop(state);
        shared.retire(freed);
    }
}

#[cfg(test)]
#[path = "shell_tests.rs"]
mod shell_tests;

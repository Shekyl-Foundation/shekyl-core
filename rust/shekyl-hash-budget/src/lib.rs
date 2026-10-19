// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's one RandomX hasher budget (`DRS_X_STORE_FLIP.md` DX-Q2
//! item 6, PR2-Q3).
//!
//! Light-mode RandomX is bound by cache and memory bandwidth, and each hash
//! holds a scratchpad: more hashers than cores thrash rather than hash
//! (RD-F11), and on the floor device (rule 76) the scratchpads are what the
//! memory holds. So every hasher in the daemon takes a permit from one
//! [`Budget`] of `available_parallelism` permits, derived at run time, never
//! provisioned as a constant.
//!
//! # Priority
//!
//! A free permit goes to the highest [`Class`] waiting, and a waiter is not
//! granted one while a higher class waits. Highest first:
//!
//! 1. [`Class::Chain`] — forming blocks on the chain or a span this node
//!    asked for;
//! 2. [`Class::HeaderPow`] — chain sync's header proof-of-work;
//! 3. [`Class::Unsolicited`] — blocks a peer announced unasked;
//! 4. [`Class::CalcPow`] — the RPC's `calc_pow`;
//! 5. [`Class::Miner`] — the built-in miner.
//!
//! **The miner never holds a permit a higher class waits for, and it never
//! takes the last free permit.** One hash at nice 19 can occupy a core for
//! about a minute of wall time, so a chain form must not wait that hash
//! out. The miner takes one permit per hash only while at least one other
//! permit stays free, and gives it back after. A higher class that starts
//! waiting during a hash is granted a free permit at once when one remains,
//! and the permit that hash frees otherwise. No miner worker is granted
//! another while a higher class waits. On a one-permit budget the miner
//! never hashes. The miner's threads keep nice 19, but priority is by
//! permit: nice does not arbitrate the cache and memory bandwidth
//! light-mode RandomX is bound by.
//!
//! A grant that leaves a permit free wakes the waiters. Taking a permit
//! drops the grantee's waiting count, and that drop is what can make a
//! lower class grantable. Without the wake, the lower class can go back to
//! sleep on the higher class's count and stay there while a permit sits
//! idle.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

/// Who is hashing, highest priority first (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Forming a block on the chain, or in a span this node requested.
    Chain,
    /// Chain sync's header proof-of-work.
    HeaderPow,
    /// Forming a block a peer announced unasked.
    Unsolicited,
    /// The RPC's `calc_pow`.
    CalcPow,
    /// The built-in miner.
    Miner,
}

impl Class {
    /// Every class, highest first.
    pub const ALL: [Self; 5] = [
        Self::Chain,
        Self::HeaderPow,
        Self::Unsolicited,
        Self::CalcPow,
        Self::Miner,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// How many permits must be free before this class may take one.
    ///
    /// Every class takes exactly one. The miner requires two free, so the
    /// last permit stays for a higher class (module docs).
    const fn free_needed(self) -> usize {
        match self {
            Self::Chain | Self::HeaderPow | Self::Unsolicited | Self::CalcPow => 1,
            Self::Miner => 2,
        }
    }
}

#[derive(Debug)]
struct State {
    free: usize,
    /// Threads waiting for a permit, per class.
    waiting: [usize; Class::ALL.len()],
    /// Permits held, per class.
    held: [usize; Class::ALL.len()],
}

impl State {
    /// Whether `class` may take a permit now: enough are free
    /// ([`Class::free_needed`]) and no higher class waits.
    fn grantable(&self, class: Class) -> bool {
        self.free >= class.free_needed() && self.waiting[..class.index()].iter().all(|&n| n == 0)
    }
}

#[derive(Debug)]
struct Inner {
    permits: usize,
    state: Mutex<State>,
    changed: Condvar,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The budget (module docs). Cheap to clone: every clone is the same
/// permits.
#[derive(Clone, Debug)]
pub struct Budget(Arc<Inner>);

impl Budget {
    /// A budget of `permits`.
    #[must_use]
    pub fn new(permits: NonZeroUsize) -> Self {
        Self(Arc::new(Inner {
            permits: permits.get(),
            state: Mutex::new(State {
                free: permits.get(),
                waiting: [0; Class::ALL.len()],
                held: [0; Class::ALL.len()],
            }),
            changed: Condvar::new(),
        }))
    }

    /// A budget of this host's parallelism, one when the platform will not
    /// say: read at run time (rule 76).
    #[must_use]
    pub fn of_host() -> Self {
        Self::new(std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN))
    }

    /// The permits there are.
    #[must_use]
    pub fn permits(&self) -> usize {
        self.0.permits
    }

    /// Take a permit for `class`, waiting until one is grantable. Blocking:
    /// call it from a thread that may block.
    #[must_use]
    pub fn acquire(&self, class: Class) -> Permit {
        let mut state = self.0.lock();
        state.waiting[class.index()] += 1;
        while !state.grantable(class) {
            state = self
                .0
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        self.grant(class, state)
    }

    /// Take a permit for `class`, or `None` once `stop` is set.
    ///
    /// The waiting count is dropped before `None`, and the waiters are
    /// woken: a stopped higher class must not keep a lower one asleep.
    /// `stop` is read under the budget lock, so a stop that lands before
    /// the wait begins is seen. Pair it with [`wake`](Self::wake) from the
    /// thread that sets `stop`, or this call stays in the condvar.
    #[must_use]
    pub fn acquire_unless(&self, class: Class, stop: &AtomicBool) -> Option<Permit> {
        let mut state = self.0.lock();
        state.waiting[class.index()] += 1;
        loop {
            if stop.load(Ordering::Acquire) {
                state.waiting[class.index()] -= 1;
                drop(state);
                // A dropped waiting count can make a lower class grantable.
                self.0.changed.notify_all();
                return None;
            }
            if state.grantable(class) {
                return Some(self.grant(class, state));
            }
            state = self
                .0
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// A permit for `class` if one is grantable now. Taking a permit never
    /// makes a waiter newly grantable, so this does not wake anyone.
    #[must_use]
    pub fn try_acquire(&self, class: Class) -> Option<Permit> {
        let mut state = self.0.lock();
        if !state.grantable(class) {
            return None;
        }
        state.free -= 1;
        state.held[class.index()] += 1;
        Some(Permit {
            budget: Arc::clone(&self.0),
            class,
        })
    }

    /// Wake every waiter so it re-checks [`acquire_unless`](Self::acquire_unless)'s
    /// stop flag, or a permit a grant left free.
    pub fn wake(&self) {
        self.0.changed.notify_all();
    }

    /// `class` is waiting and grantable. One permit, then a wake when one
    /// remains: dropping this class's waiting count is what lets a lower
    /// class through.
    fn grant(&self, class: Class, mut state: MutexGuard<'_, State>) -> Permit {
        state.waiting[class.index()] -= 1;
        state.free -= 1;
        state.held[class.index()] += 1;
        let spare = state.free > 0;
        drop(state);
        if spare {
            self.0.changed.notify_all();
        }
        Permit {
            budget: Arc::clone(&self.0),
            class,
        }
    }

    /// Permits `class` holds now.
    #[must_use]
    pub fn held(&self, class: Class) -> usize {
        self.0.lock().held[class.index()]
    }

    /// Threads of `class` waiting now.
    #[must_use]
    pub fn waiting(&self, class: Class) -> usize {
        self.0.lock().waiting[class.index()]
    }
}

/// One permit. Given back when dropped.
#[derive(Debug)]
pub struct Permit {
    budget: Arc<Inner>,
    class: Class,
}

impl Permit {
    /// The class it was granted to.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.budget.lock();
        state.free += 1;
        state.held[self.class.index()] -= 1;
        drop(state);
        // Every waiter re-checks: the highest class waiting takes it.
        self.budget.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    fn one() -> Budget {
        Budget::new(NonZeroUsize::MIN)
    }

    /// Spin until `f` holds, failing after a generous wait.
    fn until(f: impl Fn() -> bool) {
        let started = Instant::now();
        while !f() {
            assert!(started.elapsed() < Duration::from_secs(10), "timed out");
            std::thread::yield_now();
        }
    }

    #[test]
    fn the_permits_are_the_budget_and_come_back_when_dropped() {
        // Three, so the miner can take one beside the chain and still leave
        // the last permit free.
        let budget = Budget::new(NonZeroUsize::new(3).expect("three"));
        let a = budget.acquire(Class::Chain);
        let b = budget.acquire(Class::Miner);
        assert!(
            budget.try_acquire(Class::Miner).is_none(),
            "the miner leaves the last permit"
        );
        let spare = budget
            .try_acquire(Class::Chain)
            .expect("the last is for the chain");
        assert!(
            budget.try_acquire(Class::Chain).is_none(),
            "all three are held"
        );
        assert_eq!(
            (budget.held(Class::Chain), budget.held(Class::Miner)),
            (2, 1)
        );
        drop(b);
        let c = budget.try_acquire(Class::Chain).expect("one came back");
        drop((a, spare, c));
        assert_eq!(budget.held(Class::Chain), 0);
    }

    /// A freed permit goes to the highest class waiting, whatever order
    /// they began waiting in.
    #[test]
    fn a_freed_permit_goes_to_the_highest_class_waiting() {
        let budget = one();
        let held = budget.acquire(Class::Chain);
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut threads = Vec::new();
        // The miner is absent: a one-permit budget never grants it, so this
        // join would wait forever. Its place in the order is the next test.
        for class in [Class::CalcPow, Class::Unsolicited, Class::HeaderPow] {
            let (waiter, order) = (budget.clone(), Arc::clone(&order));
            threads.push(std::thread::spawn(move || {
                let permit = waiter.acquire(class);
                order.lock().expect("order").push(class);
                drop(permit);
            }));
            until(|| budget.waiting(class) == 1);
        }
        drop(held);
        for thread in threads {
            thread.join().expect("joins");
        }
        assert_eq!(
            *order.lock().expect("order"),
            vec![Class::HeaderPow, Class::Unsolicited, Class::CalcPow]
        );
    }

    /// The miner is the lowest class, and it still leaves the last permit.
    #[test]
    fn the_miner_leaves_the_last_permit_and_yields_to_a_higher_class() {
        let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
        let chain = budget.acquire(Class::Chain);
        assert!(
            budget.try_acquire(Class::Miner).is_none(),
            "one free is not enough for the miner"
        );
        drop(chain);
        let miner = budget
            .try_acquire(Class::Miner)
            .expect("two free: the miner takes one");
        assert!(
            budget.try_acquire(Class::Miner).is_none(),
            "the second miner would take the last"
        );
        let form = budget
            .try_acquire(Class::Chain)
            .expect("the last permit is the chain's");
        drop((miner, form));
        assert!(
            budget.try_acquire(Class::Miner).is_some(),
            "both permits are free again"
        );
    }

    /// A chain form never waits out a miner hash: the miner cannot hold
    /// every permit, so one stays grantable to the chain.
    #[test]
    fn a_chain_form_does_not_wait_out_a_miner_hash() {
        const HASH: Duration = Duration::from_millis(250);
        let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
        let stop = Arc::new(AtomicBool::new(false));
        let miners: Vec<_> = (0..2)
            .map(|_| {
                let budget = budget.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let Some(permit) = budget.acquire_unless(Class::Miner, &stop) else {
                            break;
                        };
                        std::thread::sleep(HASH);
                        drop(permit);
                    }
                })
            })
            .collect();
        until(|| budget.held(Class::Miner) == 1);
        let started = Instant::now();
        let permit = budget.acquire(Class::Chain);
        let waited = started.elapsed();
        assert!(
            waited < HASH,
            "the spare permit is granted without waiting out a hash: {waited:?}"
        );
        assert_eq!(
            budget.held(Class::Miner),
            1,
            "the miner still holds the other"
        );
        drop(permit);
        stop.store(true, Ordering::Release);
        budget.wake();
        for miner in miners {
            miner.join().expect("joins");
        }
    }

    /// A grant that leaves a permit free wakes a lower class that went back
    /// to sleep because the higher one was still waiting. The interleaving
    /// is the scheduler's, so the trial repeats until it has been seen or
    /// the wait says the wake is missing.
    #[test]
    fn a_grant_that_leaves_a_permit_wakes_the_lower_class() {
        let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
        for _ in 0..40 {
            let held_a = budget.acquire(Class::Chain);
            let held_b = budget.acquire(Class::Chain);
            let lower_done = Arc::new(AtomicBool::new(false));
            let higher = {
                let budget = budget.clone();
                let lower_done = Arc::clone(&lower_done);
                std::thread::spawn(move || {
                    let permit = budget.acquire(Class::HeaderPow);
                    // Stay holding it until the lower class is granted. If
                    // the grant left a permit and did not wake, this wait is
                    // the failure: the lower class can only proceed by the
                    // wake, because this permit is not dropped first.
                    let started = Instant::now();
                    while !lower_done.load(Ordering::Acquire) {
                        assert!(
                            started.elapsed() < Duration::from_millis(500),
                            "the lower class slept through a free permit"
                        );
                        std::thread::yield_now();
                    }
                    drop(permit);
                })
            };
            let lower = {
                let budget = budget.clone();
                let lower_done = Arc::clone(&lower_done);
                std::thread::spawn(move || {
                    let permit = budget.acquire(Class::CalcPow);
                    lower_done.store(true, Ordering::Release);
                    drop(permit);
                })
            };
            until(|| budget.waiting(Class::HeaderPow) == 1 && budget.waiting(Class::CalcPow) == 1);
            drop((held_a, held_b));
            let started = Instant::now();
            while !lower_done.load(Ordering::Acquire) {
                assert!(
                    started.elapsed() < Duration::from_millis(500),
                    "the lower class slept through a free permit"
                );
                std::thread::yield_now();
            }
            higher.join().expect("joins");
            lower.join().expect("joins");
        }
    }

    #[test]
    fn stopping_unblocks_a_waiter_and_drops_its_waiting_count() {
        let budget = one();
        let held = budget.acquire(Class::Chain);
        let stop = Arc::new(AtomicBool::new(false));
        let waiting = {
            let budget = budget.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || budget.acquire_unless(Class::HeaderPow, &stop))
        };
        until(|| budget.waiting(Class::HeaderPow) == 1);
        stop.store(true, Ordering::Release);
        budget.wake();
        assert!(waiting.join().expect("joins").is_none());
        assert_eq!(budget.waiting(Class::HeaderPow), 0);
        drop(held);
        assert!(budget.try_acquire(Class::CalcPow).is_some());
    }
}

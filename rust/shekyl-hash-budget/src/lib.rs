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
//! **The miner never holds a permit a higher class waits for.** It takes a
//! permit for each hash and gives it back after: a higher class that starts
//! waiting while a miner hash runs is granted the permit that hash frees,
//! within one hash, and no miner worker is granted another while it waits.
//! The miner's threads keep nice 19, but priority is by permit: nice does
//! not arbitrate the cache and memory bandwidth light-mode RandomX is bound
//! by.

use std::num::NonZeroUsize;
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
    /// Whether `class` may take a free permit now: one is free and no
    /// higher class waits for it.
    fn grantable(&self, class: Class) -> bool {
        self.free > 0 && self.waiting[..class.index()].iter().all(|&n| n == 0)
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

    /// Take a permit for `class`, waiting until one is free and no higher
    /// class waits. Blocking: call it from a thread that may block.
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
        state.waiting[class.index()] -= 1;
        state.free -= 1;
        state.held[class.index()] += 1;
        drop(state);
        // A grant can make a lower class grantable no longer, and never
        // makes one grantable; no wake is owed here.
        Permit {
            budget: Arc::clone(&self.0),
            class,
        }
    }

    /// A permit for `class` if one is grantable now.
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
        let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
        let a = budget.acquire(Class::Chain);
        let b = budget.acquire(Class::Miner);
        assert!(budget.try_acquire(Class::Chain).is_none(), "both are held");
        assert_eq!(
            (budget.held(Class::Chain), budget.held(Class::Miner)),
            (1, 1)
        );
        drop(b);
        let c = budget.try_acquire(Class::Chain).expect("one came back");
        drop((a, c));
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
        for class in [
            Class::Miner,
            Class::CalcPow,
            Class::Unsolicited,
            Class::HeaderPow,
        ] {
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
            vec![
                Class::HeaderPow,
                Class::Unsolicited,
                Class::CalcPow,
                Class::Miner
            ]
        );
    }

    /// The miner takes a permit per hash. With the miner hashing on every
    /// permit, a chain `form` that begins to wait is granted one within one
    /// hash — the next one a miner hash frees — and the miner then holds
    /// what is left.
    #[test]
    fn a_waiting_form_is_granted_within_one_miner_hash() {
        const HASH: Duration = Duration::from_millis(250);
        let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
        let stop = Arc::new(AtomicBool::new(false));
        let miners: Vec<_> = (0..2)
            .map(|_| {
                let budget = budget.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let permit = budget.acquire(Class::Miner);
                        std::thread::sleep(HASH);
                        drop(permit);
                    }
                })
            })
            .collect();
        until(|| budget.held(Class::Miner) == 2);
        let started = Instant::now();
        let permit = budget.acquire(Class::Chain);
        let waited = started.elapsed();
        // One hash, and the scheduling slack of a loaded host.
        assert!(
            waited <= HASH + Duration::from_millis(200),
            "granted within one hash: {waited:?}"
        );
        assert!(
            budget.held(Class::Miner) <= 1,
            "the form holds one of the two"
        );
        drop(permit);
        stop.store(true, Ordering::Release);
        for miner in miners {
            miner.join().expect("joins");
        }
    }
}

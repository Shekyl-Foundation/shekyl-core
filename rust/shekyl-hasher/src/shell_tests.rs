// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shell, with real caches: every build is a `PreparedCache::derive`,
//! 256 MiB each. Each test reads the published [`Resident`] and its
//! `builds` counter, the production surface, and never reaches into the
//! core.
//!
//! A test holds up to three caches, 768 MiB. They run one at a time: under
//! nextest by the `hasher-shell` test group (`.config/nextest.toml`), and
//! under a plain `cargo test` by [`serial`].

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use shekyl_hash_budget::Budget;
use shekyl_pow_randomx::Seedhash;

use crate::{Class, Declined, Hasher, Owner, Ranked, Residency, Resident, Unhashed};

/// How long any wait in these tests may take before it fails. A derive is
/// about 0.35 s on a development host and 2.1 s on the floor device.
const PATIENCE: Duration = Duration::from_secs(120);
/// How long a test waits to see that something does not happen.
const QUIET: Duration = Duration::from_millis(400);

/// One shell test at a time inside one test binary.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn s(n: u8) -> Seedhash {
    Seedhash::from_bytes([n; 32])
}

fn budget(permits: usize) -> Budget {
    Budget::new(NonZeroUsize::new(permits).expect("non-zero"))
}

fn start(permits: usize) -> (Hasher, Owner) {
    Hasher::start(budget(permits)).expect("the builder thread starts")
}

fn window(seeds: &[Seedhash]) -> Ranked {
    Ranked::new(seeds[0], seeds.get(1).copied(), None).expect("distinct")
}

/// Wait until the published residency satisfies `want`.
fn until(hasher: &Hasher, what: &str, want: impl Fn(&Resident) -> bool) -> Resident {
    let resident = hasher.resident();
    let deadline = Instant::now() + PATIENCE;
    loop {
        let now = resident.borrow().clone();
        if want(&now) {
            return now;
        }
        assert!(Instant::now() < deadline, "{what}: still {now:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn holds(resident: &Resident, seed: Seedhash, residency: Residency) -> bool {
    resident.caches.contains(&(seed, residency))
}

fn seeds(resident: &Resident) -> Vec<[u8; 32]> {
    let mut seeds: Vec<[u8; 32]> = resident.caches.iter().map(|(s, _)| *s.as_bytes()).collect();
    seeds.sort_unstable();
    seeds
}

/// A job on `seed` that hashes once, signals `started`, and holds its
/// lease until `release` is sent or dropped.
struct Held {
    started: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<Option<()>>,
}

fn hold(hasher: &Hasher, class: Class, seed: Seedhash) -> Held {
    let (started_tx, started) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let hasher = hasher.clone();
    let thread = std::thread::spawn(move || {
        let stop = AtomicBool::new(false);
        hasher.lend(class, seed, &stop, move |loan| {
            loan.hash(b"held").expect("a job's loan hashes");
            let _sent = started_tx.send(());
            let _released = release_rx.recv();
        })
    });
    Held {
        started,
        release,
        thread,
    }
}

impl Held {
    fn started(&self) -> bool {
        self.started.recv_timeout(QUIET).is_ok()
    }

    fn wait_started(&self) {
        self.started
            .recv_timeout(PATIENCE)
            .expect("the job was granted and ran");
    }

    fn finish(self) {
        drop(self.release);
        assert_eq!(self.thread.join().expect("the job returns"), Some(()));
    }
}

/// HA-R2 with real caches: three places, every one held by a job, and a
/// fourth job waits until one comes back.
///
/// Red edit: let `place_outside` reserve when the outside places are full.
#[test]
fn the_cap_holds_with_three_real_caches_and_a_fourth_job_waits() {
    let _serial = serial();
    let (hasher, owner) = start(4);
    hasher.rank(window(&[s(1)]));
    let b = hold(&hasher, Class::Chain, s(2));
    let c = hold(&hasher, Class::Chain, s(3));
    b.wait_started();
    c.wait_started();
    let full = until(&hasher, "a, b and c resident", |r| {
        holds(r, s(1), Residency::Warm)
            && holds(r, s(2), Residency::Leased)
            && holds(r, s(3), Residency::Leased)
    });
    assert_eq!(full.caches.len(), crate::CAP);
    let d = hold(&hasher, Class::Chain, s(4));
    assert!(!d.started(), "a fourth seed waits for a place");
    assert!(hasher.resident().borrow().caches.len() <= crate::CAP);
    b.finish();
    d.wait_started();
    let after = until(&hasher, "b freed for d", |r| {
        holds(r, s(4), Residency::Leased)
    });
    assert!(after.caches.len() <= crate::CAP);
    assert!(!after.caches.iter().any(|(seed, _)| *seed == s(2)));
    c.finish();
    d.finish();
    owner.stop();
}

/// HA-R8 with real caches: an evidence check waits for the one header-proof
/// job ahead of it, and the stream of header proofs behind it waits for
/// the check.
///
/// Red edit: in `Core::request`, skip the queue when the job's seed is
/// resident.
#[test]
fn an_evidence_check_runs_before_the_stream_of_header_proofs_behind_it() {
    let _serial = serial();
    let (hasher, owner) = start(4);
    hasher.rank(window(&[s(1), s(2)]));
    let first = hold(&hasher, Class::HeaderPow, s(10));
    first.wait_started();
    let order = Arc::new(Mutex::new(Vec::new()));
    let run = |seed: Seedhash, class: Class, tag: &'static str| {
        let (hasher, order) = (hasher.clone(), Arc::clone(&order));
        std::thread::spawn(move || {
            let stop = AtomicBool::new(false);
            hasher.lend(class, seed, &stop, |_| {
                order.lock().expect("order").push(tag)
            })
        })
    };
    let evidence = run(s(20), Class::Evidence, "evidence");
    std::thread::sleep(QUIET);
    let stream: Vec<_> = (0..3)
        .map(|_| run(s(10), Class::HeaderPow, "header"))
        .collect();
    std::thread::sleep(QUIET);
    assert!(
        order.lock().expect("order").is_empty(),
        "nothing passes the first job"
    );
    first.finish();
    assert_eq!(evidence.join().expect("returns"), Some(()));
    for job in stream {
        assert_eq!(job.join().expect("returns"), Some(()));
    }
    let order = order.lock().expect("order").clone();
    assert_eq!(order.first(), Some(&"evidence"), "{order:?}");
    owner.stop();
}

/// HA-R7: with two window seeds there is one outside place, and two outside
/// jobs share it; neither frees a window seed.
///
/// Red edit: let `free_one_outside` consider window entries.
#[test]
fn two_outside_jobs_share_the_one_outside_place_and_free_no_window_seed() {
    let _serial = serial();
    let (hasher, owner) = start(4);
    hasher.rank(window(&[s(1), s(2)]));
    until(&hasher, "the window built", |r| {
        holds(r, s(1), Residency::Warm) && holds(r, s(2), Residency::Warm)
    });
    let x = hold(&hasher, Class::Evidence, s(10));
    x.wait_started();
    let y = hold(&hasher, Class::HeaderPow, s(11));
    assert!(!y.started(), "the second outside job waits");
    let held = hasher.resident().borrow().clone();
    assert!(
        held.caches.iter().any(|(seed, _)| *seed == s(1)),
        "{held:?}"
    );
    assert!(
        held.caches.iter().any(|(seed, _)| *seed == s(2)),
        "{held:?}"
    );
    x.finish();
    y.wait_started();
    let held = hasher.resident().borrow().clone();
    assert!(
        held.caches.iter().any(|(seed, _)| *seed == s(1)),
        "{held:?}"
    );
    assert!(
        held.caches.iter().any(|(seed, _)| *seed == s(2)),
        "{held:?}"
    );
    y.finish();
    owner.stop();
}

/// The miner's warm loan is cancelled when its seed leaves the list, with a
/// real hash in flight; the cache goes when the loan returns.
///
/// Red edit: drop the `Cancel` decisions in `Core::rank`.
#[test]
fn a_warm_loan_is_cancelled_mid_hash_and_its_cache_freed_when_it_returns() {
    let _serial = serial();
    let (hasher, owner) = start(4);
    hasher.rank(window(&[s(1)]));
    until(&hasher, "a built", |r| holds(r, s(1), Residency::Warm));
    let (hashing_tx, hashing) = mpsc::channel();
    let miner = {
        let hasher = hasher.clone();
        std::thread::spawn(move || {
            let stop = AtomicBool::new(false);
            hasher.lend_warm(Class::Miner, s(1), &stop, |loan| {
                let mut hashed = 0u64;
                loop {
                    match loan.hash(&hashed.to_le_bytes()) {
                        Ok(_) => {
                            hashed += 1;
                            let _sent = hashing_tx.send(());
                        }
                        Err(why) => return (hashed, why),
                    }
                }
            })
        })
    };
    hashing.recv_timeout(PATIENCE).expect("the miner hashes");
    hasher.rank(window(&[s(2)]));
    let (hashed, why) = miner.join().expect("returns").expect("lent");
    assert!(hashed >= 1);
    assert_eq!(why, Unhashed::Cancelled);
    until(&hasher, "a freed, b built", |r| {
        !r.caches.iter().any(|(seed, _)| *seed == s(1)) && holds(r, s(2), Residency::Warm)
    });
    owner.stop();
}

/// `lend_warm` never builds: a seed that is not listed, or not built, is
/// declined, and the build count does not move.
///
/// Red edit: let `Core::request_warm` reserve a build for a seed it
/// declines.
#[test]
fn a_warm_loan_builds_nothing() {
    let _serial = serial();
    let (hasher, owner) = start(4);
    hasher.rank(window(&[s(1)]));
    let built = until(&hasher, "a built", |r| holds(r, s(1), Residency::Warm));
    let stop = AtomicBool::new(false);
    assert_eq!(
        hasher.lend_warm(Class::CalcPow, s(9), &stop, |_| ()).err(),
        Some(Declined::NotWarm)
    );
    assert!(hasher
        .lend_warm(Class::CalcPow, s(1), &stop, |loan| loan.hash(b"x"))
        .is_ok());
    std::thread::sleep(QUIET);
    assert_eq!(hasher.resident().borrow().builds, built.builds, "no build");
    owner.stop();
}

/// HA-R5 with real caches: after jobs on several seeds and two lists, the
/// quiet hasher holds what a fresh hasher holds for the same list.
///
/// Red edit: skip step 4 (the third's refill) in `Core::settle_once`.
#[test]
fn a_quiet_hasher_holds_what_a_fresh_one_holds_for_the_same_list() {
    let _serial = serial();
    let list = Ranked::new(s(1), Some(s(2)), Some((s(3), Class::HeaderPow))).expect("distinct");
    let quiet = |r: &Resident| {
        r.caches.len() == 3
            && r.caches
                .iter()
                .all(|(_, residency)| *residency == Residency::Warm)
    };
    let worked = {
        let (hasher, owner) = start(4);
        hasher.rank(window(&[s(5)]));
        let stop = AtomicBool::new(false);
        assert!(hasher
            .run(Class::Chain, s(6), &stop, |lent| lent.hash(b"x"))
            .is_some());
        hasher.rank(list.clone());
        assert!(hasher
            .run(Class::Evidence, s(7), &stop, |lent| lent.hash(b"x"))
            .is_some());
        let worked = until(&hasher, "quiet on the list", quiet);
        owner.stop();
        worked
    };
    let fresh = {
        let (hasher, owner) = start(4);
        hasher.rank(list);
        let fresh = until(&hasher, "quiet on the list", quiet);
        owner.stop();
        fresh
    };
    assert_eq!(seeds(&worked), seeds(&fresh));
}

/// §5.4 on a one-permit budget: a refill of the third waits for the permit
/// at the third's class; a `Chain` job for that seed raises it, and the
/// builder waits at `Chain` instead.
///
/// Red edit: drop the `WakeBuilder` decision in `Core::settle`.
#[test]
fn a_refill_whose_class_rises_waits_for_its_permit_at_the_new_class() {
    let _serial = serial();
    let budget = budget(1);
    let (hasher, owner) = Hasher::start(budget.clone()).expect("starts");
    hasher.rank(window(&[s(1)]));
    until(&hasher, "a built", |r| holds(r, s(1), Residency::Warm));
    let permit = budget.acquire(Class::Chain);
    hasher.rank(Ranked::new(s(1), None, Some((s(3), Class::Evidence))).expect("distinct"));
    let waits_at = |class: Class| {
        let deadline = Instant::now() + PATIENCE;
        while budget.waiting(class) != 1 {
            assert!(
                Instant::now() < deadline,
                "the builder never waited at {class:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    waits_at(Class::Evidence);
    let job = {
        let hasher = hasher.clone();
        std::thread::spawn(move || {
            let stop = AtomicBool::new(false);
            hasher.run(Class::Chain, s(3), &stop, |lent| lent.hash(b"x"))
        })
    };
    waits_at(Class::Chain);
    assert_eq!(
        budget.waiting(Class::Evidence),
        0,
        "the low-class wait ended"
    );
    drop(permit);
    assert!(job.join().expect("returns").is_some());
    owner.stop();
}

/// `Owner::stop` with a waiter parked: the waiter returns stopped, the stop
/// waits for the leases out, and every cache is freed.
///
/// Red edit: in `Shared::lease`, do not re-check `core.closed()` in the
/// wait loop.
#[test]
fn a_stop_returns_a_parked_waiter_waits_for_the_leases_and_frees_every_cache() {
    let _serial = serial();
    let (hasher, owner) = start(4);
    hasher.rank(window(&[s(1)]));
    let x = hold(&hasher, Class::Chain, s(10));
    let y = hold(&hasher, Class::Chain, s(11));
    x.wait_started();
    y.wait_started();
    let (parked_tx, parked) = mpsc::channel();
    {
        let hasher = hasher.clone();
        std::thread::spawn(move || {
            let stop = AtomicBool::new(false);
            let ran = hasher.run(Class::Chain, s(12), &stop, |lent| lent.hash(b"x"));
            let _sent = parked_tx.send(ran);
        });
    }
    std::thread::sleep(QUIET);
    let (stopped_tx, stopped) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        owner.stop();
        let _sent = stopped_tx.send(());
    });
    assert_eq!(
        parked
            .recv_timeout(PATIENCE)
            .expect("the parked waiter returns"),
        None,
        "the parked waiter is stopped"
    );
    assert!(
        stopped.recv_timeout(QUIET).is_err(),
        "the stop waits for the leases out"
    );
    x.finish();
    y.finish();
    stopped.recv_timeout(PATIENCE).expect("the stop completes");
    stopper.join().expect("joins");
    assert!(
        hasher.resident().borrow().caches.is_empty(),
        "every cache freed"
    );
    let stop = AtomicBool::new(false);
    assert_eq!(
        hasher.run(Class::Chain, s(1), &stop, |_| ()),
        None,
        "refused after the stop"
    );
}

/// `Hasher::wake` takes the lock before it notifies, so it cannot land
/// between a waiter's stop check and its wait. This pins the mechanism the
/// budget's `a_wake_cannot_land_between_a_waiters_stop_check_and_its_wait`
/// pins, without a hook in production code: the test holds the lock, and a
/// wake must not return while it does. A waiter parked in the gap would need
/// a hook.
///
/// Red edit: remove the `lock()` from `Hasher::wake`.
#[test]
fn a_wake_takes_the_lock_so_it_cannot_land_between_a_stop_check_and_a_wait() {
    let _serial = serial();
    let (hasher, owner) = start(2);
    let stop = Arc::new(AtomicBool::new(false));
    let held = hasher.shared.lock();
    let waiter = {
        let (hasher, stop) = (hasher.clone(), Arc::clone(&stop));
        std::thread::spawn(move || hasher.run(Class::Chain, s(1), &stop, |_| ()))
    };
    std::thread::sleep(QUIET);
    stop.store(true, Ordering::Release);
    let (woke_tx, woke) = mpsc::channel();
    let waker = {
        let hasher = hasher.clone();
        std::thread::spawn(move || {
            hasher.wake();
            let _sent = woke_tx.send(());
        })
    };
    assert!(
        woke.recv_timeout(QUIET).is_err(),
        "the wake returned while the lock was held"
    );
    drop(held);
    woke.recv_timeout(PATIENCE)
        .expect("the wake returns once the lock is free");
    waker.join().expect("joins");
    assert_eq!(
        waiter.join().expect("returns"),
        None,
        "the waiter saw the stop"
    );
    assert_eq!(
        hasher.resident().borrow().builds,
        0,
        "a stopped request builds nothing"
    );
    owner.stop();
}

/// A `lend` job hashing from as many scoped threads as the budget has
/// permits, each hash under its own permit: on one permit the threads take
/// turns, on four they share. Holding a permit for the whole job, as `run`
/// does, would deadlock the one-permit case (doc §5.3, the switch).
///
/// Red edit: take a permit for the whole job in `Hasher::lend`.
#[test]
fn a_lend_job_hashes_from_scoped_threads_on_one_permit_and_on_four() {
    let _serial = serial();
    for permits in [1, 4] {
        let (hasher, owner) = start(permits);
        hasher.rank(window(&[s(1)]));
        let (done_tx, done) = mpsc::channel();
        let job = {
            let hasher = hasher.clone();
            std::thread::spawn(move || {
                let stop = AtomicBool::new(false);
                let hashes = hasher.lend(Class::Chain, s(1), &stop, |loan| {
                    std::thread::scope(|scope| {
                        let workers: Vec<_> = (0..permits * 2)
                            .map(|_| scope.spawn(|| loan.hash(b"blob").expect("hashes")))
                            .collect();
                        workers
                            .into_iter()
                            .map(|w| w.join().expect("a worker returns"))
                            .collect::<Vec<_>>()
                    })
                });
                let _sent = done_tx.send(hashes);
            })
        };
        let hashes = done
            .recv_timeout(PATIENCE)
            .expect("the job finishes: no thread waits on the job's own permit")
            .expect("lent");
        job.join().expect("joins");
        assert_eq!(hashes.len(), permits * 2);
        assert!(
            hashes.windows(2).all(|pair| pair[0] == pair[1]),
            "one seed, one blob"
        );
        owner.stop();
    }
}

/// A job that asks for another job while it holds one panics, naming the
/// invariant: it could wait for a place behind itself.
///
/// Red edit: make `InJob::check`'s assertion always pass.
#[test]
fn a_job_asking_for_another_job_panics() {
    let _serial = serial();
    let (hasher, owner) = start(2);
    hasher.rank(window(&[s(1)]));
    let stop = AtomicBool::new(false);
    let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hasher.run(Class::Chain, s(1), &stop, |_| {
            hasher.run(Class::Chain, s(1), &stop, |_| ())
        })
    }));
    let message = nested.expect_err("the nested job panics");
    let text = message
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| message.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(text.contains("one job holds one lease at a time"), "{text}");
    assert!(
        hasher.run(Class::Chain, s(1), &stop, |_| ()).is_some(),
        "the lease came back"
    );
    owner.stop();
}

#[test]
fn a_ranked_list_naming_a_seed_twice_is_refused() {
    assert_eq!(
        Ranked::new(s(1), Some(s(1)), None).err().map(|e| e.seed),
        Some(s(1))
    );
    assert_eq!(
        Ranked::new(s(1), Some(s(2)), Some((s(2), Class::Chain)))
            .err()
            .map(|e| e.seed),
        Some(s(2))
    );
    assert!(Ranked::new(s(1), Some(s(2)), Some((s(3), Class::Chain))).is_ok());
}

/// The core's property test, driven through the real shell: many threads
/// asking for jobs of every kind and class on a small pool of seeds, lists
/// changing under them, some waiters stopping. The residency never holds
/// more than [`crate::CAP`] places, every job that did not stop returns,
/// and the quiet hasher holds what a fresh one holds for the final list.
/// The shell's own faults are what the core's test cannot see: a lost
/// wake-up, a lease kept past its return (the strong-count assertion at
/// every free), a deadlock between the lock and the budget.
///
/// Hundreds of real derives, so it runs nightly in release, by the
/// `hasher-ignored` lane (`scripts/ci/ignored_set_hasher.sh`).
///
/// Red edit: remove the `notify_all` from `Shared::apply`; a waiter granted
/// by another thread's return sleeps, and the run never finishes.
#[test]
#[ignore = "hundreds of real 256 MiB derives; run nightly in release by hasher-ignored (scripts/ci/ignored_set_hasher.sh)"]
fn a_long_random_sequence_through_the_shell_keeps_the_cap_and_quiesces_to_the_list() {
    let _serial = serial();
    /// Ops per run, and the job threads alive at once.
    const OPS: usize = 300;
    const LIVE: usize = 8;
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    let pool = |n: u64| s(u8::try_from(n).expect("small") + 1);
    let classes = Class::ALL;
    let (hasher, owner) = start(4);
    let watching = Arc::new(AtomicBool::new(true));
    let watcher = {
        let (hasher, watching) = (hasher.clone(), Arc::clone(&watching));
        std::thread::spawn(move || {
            let resident = hasher.resident();
            let mut most = 0;
            while watching.load(Ordering::Acquire) {
                most = most.max(resident.borrow().caches.len());
                std::thread::sleep(Duration::from_micros(200));
            }
            most
        })
    };
    let random_list = |next: &mut dyn FnMut(u64) -> u64| {
        let a = next(5);
        let b = (a + 1 + next(4)) % 5;
        let c = (0..5).find(|n| *n != a && *n != b).expect("five seeds");
        let other = (next(2) == 0).then(|| pool(b));
        let third =
            (next(2) == 0).then(|| (pool(c), classes[usize::try_from(next(6)).expect("small")]));
        Ranked::new(pool(a), other, third).expect("distinct")
    };
    let mut jobs: std::collections::VecDeque<std::thread::JoinHandle<()>> =
        std::collections::VecDeque::new();
    let mut last = random_list(&mut next);
    hasher.rank(last.clone());
    for _ in 0..OPS {
        match next(20) {
            0..=2 => {
                last = random_list(&mut next);
                hasher.rank(last.clone());
            }
            3..=16 => {
                let (seed, class) = (
                    pool(next(5)),
                    classes[usize::try_from(next(6)).expect("small")],
                );
                let (kind, hold) = (next(3), Duration::from_millis(next(30)));
                let stop_after = (next(5) == 0).then(|| Duration::from_millis(next(40)));
                let hasher = hasher.clone();
                jobs.push_back(std::thread::spawn(move || {
                    let stop = Arc::new(AtomicBool::new(false));
                    if let Some(after) = stop_after {
                        let (stop, hasher) = (Arc::clone(&stop), hasher.clone());
                        std::thread::spawn(move || {
                            std::thread::sleep(after);
                            stop.store(true, Ordering::Release);
                            hasher.wake();
                        });
                    }
                    let stopped = stop_after.is_some();
                    match kind {
                        0 => {
                            let ran = hasher.run(class, seed, &stop, |lent| {
                                let _hash = lent.hash(b"run");
                                std::thread::sleep(hold);
                            });
                            assert!(ran.is_some() || stopped, "a run that did not stop returns");
                        }
                        1 => {
                            let lent = hasher.lend(class, seed, &stop, |loan| {
                                let _hash = loan.hash(b"lend");
                                std::thread::sleep(hold);
                            });
                            assert!(
                                lent.is_some() || stopped,
                                "a lend that did not stop returns"
                            );
                        }
                        _ => {
                            let _warm = hasher.lend_warm(class, seed, &stop, |loan| {
                                let _hash = loan.hash(b"warm");
                                std::thread::sleep(hold);
                            });
                        }
                    }
                }));
                while jobs.len() > LIVE {
                    jobs.pop_front()
                        .expect("a job")
                        .join()
                        .expect("a job returns");
                }
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    for job in jobs {
        job.join().expect("a job returns");
    }
    let listed = 1 + usize::from(last.window.len() == 2) + usize::from(last.third.is_some());
    let quiet = |r: &Resident| {
        r.caches.len() == listed
            && r.caches
                .iter()
                .all(|(_, residency)| *residency == Residency::Warm)
    };
    let worked = until(&hasher, "quiet on the last list", quiet);
    watching.store(false, Ordering::Release);
    let most = watcher.join().expect("the watcher returns");
    assert!(most <= crate::CAP, "{most} places seen at once");
    owner.stop();
    let (fresh_hasher, fresh_owner) = start(4);
    fresh_hasher.rank(last);
    let fresh = until(
        &fresh_hasher,
        "a fresh hasher quiet on the same list",
        quiet,
    );
    fresh_owner.stop();
    assert_eq!(seeds(&worked), seeds(&fresh));
}

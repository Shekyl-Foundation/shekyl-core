// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`DrainGate`]: stopped miners, and the one gate every join takes.
//!
//! A worker finishes the hash it is in. That hash is not cancellable, and
//! at nice 19 it can run for most of a minute, so a stop does not wait for
//! it. The gate is what keeps the wait from becoming a pile of sets. A
//! start joins the one draining set before it spawns. A stop joins the set
//! it displaces before it returns. Both hold the gate across that join, so
//! a caller that does not wait — `generateblocks` detaches its stop — still
//! cannot spawn or park another generation until the join has returned.
//! Shutdown parks without the gate ([`DrainGate::defer`]) and joins
//! afterwards ([`DrainGate::join_outstanding`]), which takes the gate and
//! therefore waits out a join already in progress.
//!
//! Two generations hold a cache only while a stop is joining the set it
//! displaced. The gate refuses a third. There is no same-seed exception:
//! a restarted miner waits out the hash rather than overlapping it.

use std::sync::{Mutex, MutexGuard, PoisonError};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use shekyl_thread_ledger::DedicatedThread;

/// A stopped miner's workers, still finishing the hash they are in.
/// Dropping it joins them.
#[must_use = "dropping it joins the workers"]
pub struct Draining {
    workers: Vec<DedicatedThread>,
}

impl Draining {
    pub(crate) fn from_workers(workers: Vec<DedicatedThread>) -> Self {
        Self { workers }
    }

    /// Join every worker. Waits for the hash they are still in.
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

/// The sets a stop or a shutdown has parked and not yet joined.
///
/// `draining` is the one set still finishing a hash. `deferred` is the set
/// [`DrainGate::defer`] displaced out of it, and there is only one: a
/// second is an invariant break. Both move under this one lock, which is
/// never held across a join.
#[derive(Default)]
struct Parked {
    draining: Option<Draining>,
    deferred: Option<Draining>,
}

impl Parked {
    /// Park `stopped` in the draining slot. The set it displaced is
    /// returned for the caller to join after this lock is dropped.
    fn displace(&mut self, stopped: Draining) -> Option<Draining> {
        self.draining.replace(stopped)
    }

    fn take_draining(&mut self) -> Option<Draining> {
        self.draining.take()
    }

    /// Park `stopped` without joining. The set already draining is kept
    /// in [`Self::deferred`].
    fn defer(&mut self, stopped: Draining) {
        let Some(earlier) = self.draining.replace(stopped) else {
            return;
        };
        assert!(
            self.deferred.is_none(),
            "shutdown displaced two draining sets"
        );
        self.deferred = Some(earlier);
    }

    /// Take both sets. Empty means nothing is parked at this instant.
    fn take_outstanding(&mut self) -> (Option<Draining>, Option<Draining>) {
        (self.draining.take(), self.deferred.take())
    }
}

/// The parked sets, and the gate that joins them (module docs).
#[derive(Default)]
pub struct DrainGate {
    /// Held for the whole of a join. [`Self::defer`] does not take it, so
    /// shutdown can park a miner and return before the hash.
    gate: Mutex<()>,
    /// [`Parked`]. Dropped before any join, so a park waits only for the
    /// pointer swap.
    parked: Mutex<Parked>,
    /// How many times [`Self::join_outstanding`] has taken a non-empty pair
    /// and dropped the slot lock, before it joins. Tests wait on it so a
    /// park during that join is ordered after the take.
    #[cfg(test)]
    joins_begun: AtomicUsize,
}

impl DrainGate {
    fn gate(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn parked(&self) -> MutexGuard<'_, Parked> {
        self.parked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Park `stopped` and join the set it displaces, under the gate.
    ///
    /// `take` runs under the gate and must drop its own locks before it
    /// returns: the join happens after `take` returns, still under the
    /// gate, and a join waits out a hash. The slot lock ends with the
    /// statement that parks, so a park ([`Self::defer`]) does not wait on
    /// it. `false` when `take` found no running miner. The set just parked
    /// stays until the next [`Self::before_spawn`] or [`Self::join_outstanding`].
    ///
    /// `take` must not call back into this gate. The gate lock is held.
    pub fn retire(&self, take: impl FnOnce() -> Option<Draining>) -> bool {
        let _gate = self.gate();
        let Some(stopped) = take() else {
            return false;
        };
        // The guard ends with this block. The join below waits out a hash
        // and must not hold the slot.
        let earlier = {
            let mut parked = self.parked();
            parked.displace(stopped)
        };
        if let Some(set) = earlier {
            set.join();
        }
        true
    }

    /// Join the draining set, then run `spawn`, both under the gate.
    ///
    /// A second start or stop blocks on the gate until `spawn` returns, so
    /// it cannot install another generation beside this join. The slot
    /// lock ends before the join. `spawn` must not call [`Self::retire`],
    /// [`Self::before_spawn`], or [`Self::join_outstanding`]: those take
    /// the gate, and this already holds it. [`Self::defer`] does not, and
    /// is the shutdown path's way to park a miner `spawn` built after the
    /// node had closed.
    pub fn before_spawn<T>(&self, spawn: impl FnOnce() -> T) -> T {
        let _gate = self.gate();
        let draining = {
            let mut parked = self.parked();
            parked.take_draining()
        };
        if let Some(set) = draining {
            set.join();
        }
        spawn()
    }

    /// Park `stopped` without waiting. The set already draining is kept
    /// for [`Self::join_outstanding`].
    ///
    /// Does not take the gate. Shutdown calls it while it still holds the
    /// running miner, and must return before the hash. A set already
    /// deferred is an invariant break: [`Self::retire`] and
    /// [`Self::before_spawn`] hold the gate across their joins, so shutdown
    /// meets a second displaced set only if two parks raced without it.
    pub fn defer(&self, stopped: Draining) {
        self.parked().defer(stopped);
    }

    /// Join the draining set and the deferred set. Takes the gate first, so
    /// a stop or a start already inside a join finishes, and a set parked
    /// while this join waits is taken on the next pass. Both sets are taken
    /// under the one slot lock, which is dropped before the join.
    /// [`Self::defer`] does not take the gate, so a shutdown that parks
    /// during this wait is picked up by the loop rather than left in the slot.
    pub fn join_outstanding(&self) {
        let _gate = self.gate();
        loop {
            let (draining, deferred) = {
                let mut parked = self.parked();
                parked.take_outstanding()
            };
            if draining.is_none() && deferred.is_none() {
                break;
            }
            #[cfg(test)]
            self.joins_begun.fetch_add(1, Ordering::SeqCst);
            if let Some(set) = draining {
                set.join();
            }
            if let Some(set) = deferred {
                set.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    use shekyl_thread_ledger::{spawn_dedicated, ThreadName};

    const THREADS: usize = 3;
    const WORKER: &str = "sk-miner";
    /// Long enough that a start which did not wait would have spawned, and
    /// short of a blocked hash finishing on its own.
    const NOT_YET: Duration = Duration::from_millis(200);
    /// A join that is going to finish, once its workers are released.
    const JOIN_BOUND: Duration = Duration::from_secs(5);

    /// `workers` threads that block until their release is dropped, counting
    /// themselves in `live` for the whole of that wait.
    fn blocked(live: &Arc<AtomicUsize>) -> (Draining, Vec<mpsc::Sender<()>>) {
        let name = ThreadName::new(WORKER).expect("a fixed, valid thread name");
        let mut workers = Vec::with_capacity(THREADS);
        let mut releases = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let (release, wait) = mpsc::channel::<()>();
            let live = Arc::clone(live);
            live.fetch_add(1, Ordering::SeqCst);
            workers.push(
                spawn_dedicated(&name, move || {
                    // A send and a dropped sender both release the worker.
                    match wait.recv() {
                        Ok(()) | Err(mpsc::RecvError) => {}
                    }
                    live.fetch_sub(1, Ordering::SeqCst);
                })
                .expect("a thread"),
            );
            releases.push(release);
        }
        (Draining { workers }, releases)
    }

    fn wait_until(live: &AtomicUsize, count: usize) {
        let deadline = std::time::Instant::now() + JOIN_BOUND;
        while live.load(Ordering::SeqCst) != count {
            assert!(
                std::time::Instant::now() < deadline,
                "live workers stayed at {}, wanted {count}",
                live.load(Ordering::SeqCst)
            );
            std::thread::yield_now();
        }
    }

    /// The composition the node runs: a detached stop holds the gate while
    /// it joins the set it displaced, and a start blocked on that gate does
    /// not spawn. When the gate frees, the start joins the parked set before
    /// its closure runs. Two starts serialize on the same gate, so only one
    /// installs a miner.
    ///
    /// Red edits: join the displaced set after dropping the gate — the probe
    /// stop takes the gate while that set is still blocked. Skip the join
    /// in `before_spawn` — once the displaced set has finished, a start
    /// spawns while the parked set is still blocked.
    #[test]
    fn a_start_during_a_stop_waits_for_the_gate_and_then_joins() {
        let live = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(DrainGate::default());
        let running = Arc::new(Mutex::new(None));

        let (first, release_first) = blocked(&live);
        *running.lock().expect("the running miner") = Some(first);
        assert!(gate.retire(|| running.lock().expect("the running miner").take()));
        wait_until(&live, THREADS);

        let (second, release_second) = blocked(&live);
        *running.lock().expect("the running miner") = Some(second);
        // Set once `retire` has taken the running miner and still holds the
        // gate, so the starts below block on the join rather than racing in
        // before it.
        let taken = Arc::new(AtomicBool::new(false));
        let stopper = {
            let (gate, running, taken) =
                (Arc::clone(&gate), Arc::clone(&running), Arc::clone(&taken));
            std::thread::spawn(move || {
                assert!(gate.retire(|| {
                    let set = running.lock().expect("the running miner").take();
                    taken.store(true, Ordering::SeqCst);
                    set
                }));
            })
        };
        let deadline = std::time::Instant::now() + JOIN_BOUND;
        while !taken.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the stop did not take the running miner"
            );
            std::thread::yield_now();
        }
        wait_until(&live, 2 * THREADS);

        // Nothing else is waiting on the gate yet. A join that ran after
        // the gate was dropped lets this stop through while the displaced
        // set is still blocked.
        let (entered_tx, entered) = mpsc::channel();
        let probe = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let parked = gate.retire(|| {
                    entered_tx.send(()).expect("the test waits");
                    None
                });
                assert!(!parked, "the probe had no miner to park");
            })
        };
        assert!(
            entered.recv_timeout(NOT_YET).is_err(),
            "another stop took the gate while a set was still being joined"
        );

        let (spawned_tx, spawned) = mpsc::channel();
        let start = |gate: Arc<DrainGate>, running: Arc<Mutex<Option<Draining>>>| {
            let live = Arc::clone(&live);
            let spawned_tx = spawned_tx.clone();
            std::thread::spawn(move || {
                gate.before_spawn(|| {
                    let mut slot = running.lock().expect("the running miner");
                    if slot.is_some() {
                        return;
                    }
                    let (set, releases) = blocked(&live);
                    *slot = Some(set);
                    spawned_tx.send(releases).expect("the test waits");
                });
            })
        };
        let starter = start(Arc::clone(&gate), Arc::clone(&running));
        let other = start(Arc::clone(&gate), Arc::clone(&running));
        assert!(
            spawned.recv_timeout(NOT_YET).is_err(),
            "a start spawned while a stop held the join gate"
        );
        assert_eq!(live.load(Ordering::SeqCst), 2 * THREADS);

        drop(release_first);
        // The displaced set has left. The parked set is the only one still
        // hashing, and the start joins it before its closure runs.
        wait_until(&live, THREADS);
        assert!(
            spawned.recv_timeout(NOT_YET).is_err(),
            "a start spawned before it had joined the parked set"
        );

        drop(release_second);
        let release_spawned = spawned
            .recv_timeout(JOIN_BOUND)
            .expect("the start runs once the parked set has joined");
        stopper.join().expect("the stopper");
        wait_until(&live, THREADS);
        assert!(
            spawned.recv_timeout(NOT_YET).is_err(),
            "a second start installed another miner"
        );
        starter.join().expect("the starter");
        other.join().expect("the other start");
        probe.join().expect("the probe stop");

        drop(release_spawned);
        drop(running.lock().expect("the running miner").take());
        wait_until(&live, 0);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    /// Shutdown's final join takes the gate, so a stop already inside a
    /// join cannot outlive it. The parked set is joined after that stop
    /// returns, not lost because the stop took it out of a slot.
    ///
    /// Red edit: `join_outstanding` does not take the gate, and it returns
    /// while the stop is still joining and the parked set is still blocked.
    #[test]
    fn the_final_join_waits_out_a_stop_already_joining() {
        let live = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(DrainGate::default());
        let running = Mutex::new(None);

        let (first, release_first) = blocked(&live);
        *running.lock().expect("the running miner") = Some(first);
        assert!(gate.retire(|| running.lock().expect("the running miner").take()));

        let (second, release_second) = blocked(&live);
        *running.lock().expect("the running miner") = Some(second);
        let taken = Arc::new(AtomicBool::new(false));
        let stopper = {
            let (gate, taken) = (Arc::clone(&gate), Arc::clone(&taken));
            std::thread::spawn(move || {
                assert!(gate.retire(|| {
                    let set = running.lock().expect("the running miner").take();
                    taken.store(true, Ordering::SeqCst);
                    set
                }));
            })
        };
        let deadline = std::time::Instant::now() + JOIN_BOUND;
        while !taken.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the stop did not take the running miner"
            );
            std::thread::yield_now();
        }
        wait_until(&live, 2 * THREADS);

        let (done_tx, done) = mpsc::channel();
        let joining = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.join_outstanding();
                done_tx.send(()).expect("the test waits");
            })
        };
        assert!(
            done.recv_timeout(NOT_YET).is_err(),
            "the final join returned while a stop still held the gate"
        );

        drop(release_first);
        assert!(
            done.recv_timeout(NOT_YET).is_err(),
            "the final join returned before the parked set had finished"
        );
        drop(release_second);
        done.recv_timeout(JOIN_BOUND)
            .expect("the final join returns once both sets have finished");
        stopper.join().expect("the stopper");
        joining.join().expect("the final join");
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    /// A set parked while the final join is already inside a hash is taken
    /// on the next pass. The counter trips after the slot lock is dropped
    /// and before that hash is joined, so the second park lands in the
    /// empty slot.
    ///
    /// Red edit: take the slots once and return. The final join then
    /// finishes when the first set is released, and the second is still
    /// blocked.
    #[test]
    fn the_final_join_picks_up_a_set_parked_while_it_joins() {
        let live = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(DrainGate::default());
        let (first, release_first) = blocked(&live);
        gate.defer(first);

        let (done_tx, done) = mpsc::channel();
        let joining = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.join_outstanding();
                done_tx.send(()).expect("the test waits");
            })
        };
        let deadline = std::time::Instant::now() + JOIN_BOUND;
        while gate.joins_begun.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the final join did not take the parked set"
            );
            std::thread::yield_now();
        }

        let (second, release_second) = blocked(&live);
        gate.defer(second);
        assert!(
            done.recv_timeout(NOT_YET).is_err(),
            "the final join returned while the first set was still blocked"
        );
        drop(release_first);
        assert!(
            done.recv_timeout(NOT_YET).is_err(),
            "the final join returned without the set parked during it"
        );
        drop(release_second);
        done.recv_timeout(JOIN_BOUND)
            .expect("the final join returns once both sets have finished");
        joining.join().expect("the final join");
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    /// Shutdown parks without waiting, including the set it displaces, and
    /// the final join is what waits for both.
    ///
    /// Red edit: `defer` joins, and the park does not return within the
    /// bound while the workers are blocked.
    #[test]
    fn shutdown_parks_without_waiting_and_keeps_the_set_it_displaces() {
        let live = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(DrainGate::default());
        let (first, release_first) = blocked(&live);
        gate.defer(first);
        let (second, release_second) = blocked(&live);
        let parked = std::time::Instant::now();
        gate.defer(second);
        assert!(
            parked.elapsed() < NOT_YET,
            "shutdown waited for a hash it was supposed to park"
        );
        assert_eq!(live.load(Ordering::SeqCst), 2 * THREADS);

        let (done_tx, done) = mpsc::channel();
        let joining = std::thread::spawn(move || {
            gate.join_outstanding();
            done_tx.send(()).expect("the test waits");
        });
        assert!(
            done.recv_timeout(NOT_YET).is_err(),
            "the final join returned while both parked sets were still blocked"
        );
        drop(release_first);
        assert!(
            done.recv_timeout(NOT_YET).is_err(),
            "the final join returned with a set still blocked"
        );
        drop(release_second);
        done.recv_timeout(JOIN_BOUND)
            .expect("the final join returns once both sets have finished");
        joining.join().expect("the final join");
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

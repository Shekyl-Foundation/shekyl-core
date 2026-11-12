// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hasher's decisions, as a state machine with no clock, no threads, no
//! caches and no I/O (`RANDOMX_CACHE_ACTOR.md` §5.2, §5.4, §5.5).
//!
//! The shell runs it under one lock and acts on what it returns: it wakes a
//! waiter whose request was granted, drops a freed cache, raises a warm
//! lease's cancel flag, and wakes the builder. The builder asks it for the
//! next build and reports the build's start and end. Production runs this
//! core; nothing here is a test lever.
//!
//! # Terms
//!
//! - **W**, the window: the ranked list's first one or two seeds. Each has a
//!   place reserved whether or not it is built.
//! - **The third:** the list's third seed, with the class its jobs hash at.
//! - **An entry:** a seed that is resident, or has a build reserved for it.
//! - **Outside:** an entry or a job whose seed is not in W. The outside
//!   places are [`CAP`] minus the window's length.
//! - **A lease:** a granted job. A warm lease (`lend_warm`) can be
//!   cancelled; a job's lease cannot (HA-R1).

use std::collections::VecDeque;

use shekyl_hash_budget::Class;
use shekyl_pow_randomx::Seedhash;

use crate::{Ranked, CAP};

/// One request that has not been granted yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Ticket(u64);

/// One granted job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LeaseId(u64);

/// What the shell does after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// The request holding `ticket` was granted `lease`. Its thread takes
    /// the grant with [`Core::take_grant`].
    Grant { ticket: Ticket, lease: LeaseId },
    /// A build of `seed` was reserved. The builder takes it with
    /// [`Core::claim`].
    Schedule { seed: Seedhash },
    /// `seed`'s cache is no longer held: drop it.
    Free { seed: Seedhash },
    /// The warm lease's seed left the list: its next hash is refused.
    Cancel { lease: LeaseId },
    /// The build the builder claimed is no longer the next one, or its class
    /// rose: stop its permit wait and ask again.
    WakeBuilder,
}

/// Why a warm-only request was refused at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WarmRefused {
    /// The seed is not warm for this caller (doc §5.3, the brief's §4.4).
    NotWarm,
    /// The hasher is stopping.
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryState {
    /// A build is reserved and has not begun its derive.
    Queued,
    /// The builder is deriving it.
    Deriving,
    /// Built and held.
    Resident,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    seed: Seedhash,
    state: EntryState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitFor {
    /// In the queue for an outside place (HA-R8).
    Fifo,
    /// Waiting for its seed's build: one it joined or reserved, or a
    /// window seed's build that waits for room.
    Seed,
}

#[derive(Clone, Copy, Debug)]
struct Waiter {
    ticket: Ticket,
    seed: Seedhash,
    class: Class,
    /// Arrival order: builds a waiter needs are taken in the order their
    /// first waiter asked, and a waiter moved back into the queue keeps it.
    seq: u64,
    wait: WaitFor,
}

#[derive(Clone, Copy, Debug)]
struct Lease {
    id: LeaseId,
    seed: Seedhash,
    warm: bool,
    cancelled: bool,
}

/// The state machine (module docs).
#[derive(Debug, Default)]
pub(crate) struct Core {
    list: Option<Ranked>,
    entries: Vec<Entry>,
    waiters: Vec<Waiter>,
    fifo: VecDeque<Ticket>,
    leases: Vec<Lease>,
    granted: Vec<(Ticket, LeaseId)>,
    /// The build the builder took and has not begun: its seed and class.
    claim: Option<(Seedhash, Class)>,
    builder_woken: bool,
    /// The job that last pushed the third out, and its class: the class
    /// that third's refill is paid at (§5.4).
    third_pushed_by: Option<(Seedhash, Class)>,
    next_id: u64,
    closed: bool,
}

impl Core {
    fn next(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn window(&self) -> &[Seedhash] {
        self.list.as_ref().map_or(&[], Ranked::window)
    }

    fn third(&self) -> Option<(Seedhash, Class)> {
        self.list.as_ref().and_then(Ranked::third)
    }

    fn in_window(&self, seed: &Seedhash) -> bool {
        self.window().contains(seed)
    }

    fn listed(&self, seed: &Seedhash) -> bool {
        self.in_window(seed) || self.third().is_some_and(|(third, _)| third == *seed)
    }

    fn entry(&self, seed: &Seedhash) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.seed == *seed)
    }

    fn outside_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| !self.in_window(&entry.seed))
            .count()
    }

    fn outside_places(&self) -> usize {
        CAP - self.window().len()
    }

    fn leases_on(&self, seed: &Seedhash) -> usize {
        self.leases
            .iter()
            .filter(|lease| lease.seed == *seed)
            .count()
    }

    fn waiters_on(&self, seed: &Seedhash) -> impl Iterator<Item = &Waiter> {
        let seed = *seed;
        self.waiters
            .iter()
            .filter(move |waiter| waiter.wait == WaitFor::Seed && waiter.seed == seed)
    }

    /// A resident entry nothing holds or waits for: it may be freed.
    fn idle(&self, entry: &Entry) -> bool {
        entry.state == EntryState::Resident
            && self.leases_on(&entry.seed) == 0
            && self.waiters_on(&entry.seed).next().is_none()
    }

    /// A window seed has no entry and every place is taken: it waits for
    /// room, and no outside job takes or joins a place meanwhile.
    fn window_short(&self) -> bool {
        self.entries.len() >= CAP && self.window().iter().any(|seed| self.entry(seed).is_none())
    }

    // ----- requests -------------------------------------------------------

    /// A `run` or `lend` request (doc §5.2, the brief's §4.1–§4.2).
    pub(crate) fn request(
        &mut self,
        seed: Seedhash,
        class: Class,
    ) -> Option<(Ticket, Vec<Decision>)> {
        if self.closed {
            return None;
        }
        let ticket = Ticket(self.next());
        let seq = self.next_id;
        let mut out = Vec::new();
        if self.in_window(&seed) {
            match self.entry(&seed).map(|entry| entry.state) {
                Some(EntryState::Resident) => {
                    self.grant(ticket, seed, false, &mut out);
                }
                _ => self.waiters.push(Waiter {
                    ticket,
                    seed,
                    class,
                    seq,
                    wait: WaitFor::Seed,
                }),
            }
        } else {
            let waiter = Waiter {
                ticket,
                seed,
                class,
                seq,
                wait: WaitFor::Fifo,
            };
            // A stream for one seed must not pass a job waiting for another:
            // a non-empty queue takes every newcomer.
            if self.fifo.is_empty() && !self.window_short() {
                if !self.place_outside(waiter, &mut out) {
                    self.enqueue(waiter);
                }
            } else {
                self.enqueue(waiter);
            }
        }
        self.settle(&mut out);
        Some((ticket, out))
    }

    /// A `lend_warm` request: granted only on a warm cache, never a build or
    /// a wait (the brief's §4.4).
    pub(crate) fn request_warm(&mut self, seed: Seedhash) -> Result<LeaseId, WarmRefused> {
        if self.closed {
            return Err(WarmRefused::Closed);
        }
        let warm = self.listed(&seed)
            && self
                .entry(&seed)
                .is_some_and(|entry| entry.state == EntryState::Resident)
            && (self.in_window(&seed) || self.fifo.is_empty());
        if !warm {
            return Err(WarmRefused::NotWarm);
        }
        let lease = LeaseId(self.next());
        // A lease only holds an entry longer; nothing else moves, so there
        // is nothing to settle.
        self.leases.push(Lease {
            id: lease,
            seed,
            warm: true,
            cancelled: false,
        });
        Ok(lease)
    }

    /// The lease `ticket` was granted, if it has been. Taken once.
    pub(crate) fn take_grant(&mut self, ticket: Ticket) -> Option<LeaseId> {
        let at = self.granted.iter().position(|(t, _)| *t == ticket)?;
        Some(self.granted.swap_remove(at).1)
    }

    /// A waiter left on its stop flag before it was granted.
    pub(crate) fn leave(&mut self, ticket: Ticket) -> Vec<Decision> {
        self.waiters.retain(|waiter| waiter.ticket != ticket);
        self.fifo.retain(|queued| *queued != ticket);
        let mut out = Vec::new();
        self.settle(&mut out);
        out
    }

    /// A lease came back: its job returned, or its waiter stopped after
    /// the grant.
    pub(crate) fn returned(&mut self, lease: LeaseId) -> Vec<Decision> {
        self.leases.retain(|held| held.id != lease);
        let mut out = Vec::new();
        self.settle(&mut out);
        out
    }

    /// The ranked list, sent whole (doc §5.1).
    pub(crate) fn rank(&mut self, list: Ranked) -> Vec<Decision> {
        let mut out = Vec::new();
        self.list = Some(list);
        if let Some((pushed, _)) = self.third_pushed_by {
            if self.third().is_none_or(|(third, _)| third != pushed) {
                self.third_pushed_by = None;
            }
        }
        // A warm lease is cancelled when its seed leaves the list. A job's
        // lease keeps its cache for the job's scope whatever the list says.
        for at in 0..self.leases.len() {
            let lease = self.leases[at];
            if lease.warm && !lease.cancelled && !self.listed(&lease.seed) {
                self.leases[at].cancelled = true;
                out.push(Decision::Cancel { lease: lease.id });
            }
        }
        // A queued job whose seed joined W leaves the queue: a window seed's
        // job never waits for an outside place. A window job whose seed left
        // W with nothing built is now an outside job without a place, and
        // joins the queue in its arrival order.
        for at in 0..self.waiters.len() {
            let waiter = self.waiters[at];
            let in_window = self.in_window(&waiter.seed);
            match waiter.wait {
                WaitFor::Fifo if in_window => {
                    self.fifo.retain(|queued| *queued != waiter.ticket);
                    self.waiters[at].wait = WaitFor::Seed;
                }
                WaitFor::Seed if !in_window && self.entry(&waiter.seed).is_none() => {
                    self.waiters[at].wait = WaitFor::Fifo;
                    self.insert_in_order(waiter.ticket, waiter.seq);
                }
                _ => {}
            }
        }
        self.settle(&mut out);
        out
    }

    /// Refuse new requests and stop scheduling builds. A build in progress
    /// finishes; every cache goes once no lease holds it.
    pub(crate) fn close(&mut self) -> Vec<Decision> {
        self.closed = true;
        let mut out = Vec::new();
        self.settle(&mut out);
        out
    }

    // ----- the builder ----------------------------------------------------

    /// The build to make next and its class, which the builder takes a
    /// permit of. `None` when nothing is queued.
    pub(crate) fn claim(&mut self) -> Option<(Seedhash, Class)> {
        let next = self.next_build();
        self.claim = next;
        self.builder_woken = false;
        next
    }

    /// The builder holds a permit for `claimed`. `true` when it is still the
    /// next build at that class: its derive begins. `false` when the choice
    /// moved: the builder asks again.
    pub(crate) fn begin(&mut self, claimed: (Seedhash, Class)) -> bool {
        let current = self.next_build();
        self.claim = None;
        if current != Some(claimed) {
            return false;
        }
        if let Some(entry) = self.entries.iter_mut().find(|e| e.seed == claimed.0) {
            entry.state = EntryState::Deriving;
        }
        true
    }

    /// The builder's permit wait gave up without a permit.
    pub(crate) fn unclaim(&mut self) {
        self.claim = None;
    }

    /// The derive of `seed` finished: it is resident, and every job waiting
    /// for it is granted.
    pub(crate) fn built(&mut self, seed: Seedhash) -> Vec<Decision> {
        let mut out = Vec::new();
        if let Some(entry) = self.entries.iter_mut().find(|e| e.seed == seed) {
            entry.state = EntryState::Resident;
        }
        let mut waiting: Vec<Waiter> = self.waiters_on(&seed).copied().collect();
        waiting.sort_by_key(|waiter| waiter.seq);
        for waiter in waiting {
            self.waiters.retain(|w| w.ticket != waiter.ticket);
            self.grant(waiter.ticket, seed, false, &mut out);
        }
        self.settle(&mut out);
        out
    }

    /// Whether the hasher is stopping and no lease or waiter is left: a
    /// stop may join the builder.
    pub(crate) fn drained(&self) -> bool {
        self.closed && self.leases.is_empty() && self.waiters.is_empty()
    }

    /// Whether the hasher is stopping.
    pub(crate) const fn closed(&self) -> bool {
        self.closed
    }

    /// The entries, for the published residency: each seed, and whether it
    /// is building, leased or warm.
    pub(crate) fn residency(&self) -> Vec<(Seedhash, crate::Residency)> {
        self.entries
            .iter()
            .map(|entry| {
                let residency = match entry.state {
                    EntryState::Queued | EntryState::Deriving => crate::Residency::Building,
                    EntryState::Resident if self.leases_on(&entry.seed) > 0 => {
                        crate::Residency::Leased
                    }
                    EntryState::Resident => crate::Residency::Warm,
                };
                (entry.seed, residency)
            })
            .collect()
    }

    // ----- inside -----------------------------------------------------------

    fn grant(&mut self, ticket: Ticket, seed: Seedhash, warm: bool, out: &mut Vec<Decision>) {
        let lease = LeaseId(self.next());
        self.leases.push(Lease {
            id: lease,
            seed,
            warm,
            cancelled: false,
        });
        self.granted.push((ticket, lease));
        out.push(Decision::Grant { ticket, lease });
    }

    fn enqueue(&mut self, mut waiter: Waiter) {
        waiter.wait = WaitFor::Fifo;
        self.waiters.push(waiter);
        self.fifo.push_back(waiter.ticket);
    }

    fn insert_in_order(&mut self, ticket: Ticket, seq: u64) {
        let at = self
            .fifo
            .iter()
            .position(|queued| {
                self.waiters
                    .iter()
                    .find(|waiter| waiter.ticket == *queued)
                    .is_some_and(|waiter| waiter.seq > seq)
            })
            .unwrap_or(self.fifo.len());
        self.fifo.insert(at, ticket);
    }

    /// Rule 2 without its first step: join the seed's entry, take a free
    /// outside place, or free the lowest-ranked idle outside entry. `false`
    /// when none of the three is open. A waiter not yet in `self.waiters`
    /// is added when it must wait for a build.
    fn place_outside(&mut self, waiter: Waiter, out: &mut Vec<Decision>) -> bool {
        let seed_wait = |core: &mut Self| {
            let mut waiter = waiter;
            waiter.wait = WaitFor::Seed;
            match core.waiters.iter_mut().find(|w| w.ticket == waiter.ticket) {
                Some(held) => *held = waiter,
                None => core.waiters.push(waiter),
            }
        };
        match self.entry(&waiter.seed).map(|entry| entry.state) {
            Some(EntryState::Resident) => {
                self.waiters.retain(|w| w.ticket != waiter.ticket);
                self.grant(waiter.ticket, waiter.seed, false, out);
                return true;
            }
            Some(EntryState::Queued | EntryState::Deriving) => {
                seed_wait(self);
                return true;
            }
            None => {}
        }
        if self.outside_count() >= self.outside_places()
            && !self.free_one_outside(Some(waiter.class), out)
        {
            return false;
        }
        self.reserve(waiter.seed, out);
        seed_wait(self);
        true
    }

    /// Free the lowest-ranked idle outside entry: unlisted before the
    /// third. `pushed_by` is the class of the job that needs the place, or
    /// `None` for a window build. `false` when no outside entry is idle.
    fn free_one_outside(&mut self, pushed_by: Option<Class>, out: &mut Vec<Decision>) -> bool {
        let third = self.third().map(|(seed, _)| seed);
        let candidate = self
            .entries
            .iter()
            .filter(|entry| !self.in_window(&entry.seed) && self.idle(entry))
            .min_by_key(|entry| Some(entry.seed) == third)
            .map(|entry| entry.seed);
        let Some(seed) = candidate else {
            return false;
        };
        if Some(seed) == third {
            self.third_pushed_by = pushed_by.map(|class| (seed, class));
        }
        self.free(seed, out);
        true
    }

    fn free(&mut self, seed: Seedhash, out: &mut Vec<Decision>) {
        let state = self.entry(&seed).map(|entry| entry.state);
        self.entries.retain(|entry| entry.seed != seed);
        if state == Some(EntryState::Resident) {
            out.push(Decision::Free { seed });
        }
    }

    fn reserve(&mut self, seed: Seedhash, out: &mut Vec<Decision>) {
        self.entries.push(Entry {
            seed,
            state: EntryState::Queued,
        });
        out.push(Decision::Schedule { seed });
    }

    /// No outside entry may be freed while a lease is out on it. A warm
    /// lease never holds off a job or a window build that waits for a place
    /// (the brief's §4.4): those leases are cancelled, and the place frees
    /// when their in-flight hash returns.
    fn cancel_warm_outside(&mut self, out: &mut Vec<Decision>) {
        for at in 0..self.leases.len() {
            let lease = self.leases[at];
            if lease.warm && !lease.cancelled && !self.in_window(&lease.seed) {
                self.leases[at].cancelled = true;
                out.push(Decision::Cancel { lease: lease.id });
            }
        }
    }

    /// The class a refill of the third is paid at: the class of the job
    /// that pushed it out, or the list's class for it when no job did
    /// (§5.4). A low-class job cannot buy a high-class build.
    fn third_refill_class(&self) -> Option<(Seedhash, Class)> {
        let (third, list_class) = self.third()?;
        let class = match self.third_pushed_by {
            Some((pushed, class)) if pushed == third => class,
            _ => list_class,
        };
        Some((third, class))
    }

    /// The build class of a queued entry, `None` when nothing asks for it:
    /// the highest (earliest in `Class::ALL`) of each waiting job's class,
    /// `Chain` for a window seed, and the third's refill class for the
    /// third (§5.4).
    fn build_class(&self, entry: &Entry) -> Option<Class> {
        let waiting = self.waiters_on(&entry.seed).map(|waiter| waiter.class);
        let window = self.in_window(&entry.seed).then_some(Class::Chain);
        let third = self
            .third_refill_class()
            .filter(|(third, _)| *third == entry.seed)
            .map(|(_, class)| class);
        waiting.chain(window).chain(third).min()
    }

    /// The next build: those a waiting job needs, in the order their first
    /// waiter asked, then refills by rank (the brief's §4.7).
    fn next_build(&self) -> Option<(Seedhash, Class)> {
        let rank = |seed: &Seedhash| {
            self.window()
                .iter()
                .position(|window| window == seed)
                .unwrap_or(CAP)
        };
        self.entries
            .iter()
            .filter(|entry| entry.state == EntryState::Queued)
            .filter_map(|entry| {
                let class = self.build_class(entry)?;
                let first_waiter = self.waiters_on(&entry.seed).map(|w| w.seq).min();
                Some((
                    (first_waiter.is_none(), first_waiter, rank(&entry.seed)),
                    (entry.seed, class),
                ))
            })
            .min_by_key(|(order, _)| *order)
            .map(|(_, build)| build)
    }

    /// Bring the state to what the list and the jobs ask for, after every
    /// event (the brief's §4.3 and §4.6).
    fn settle(&mut self, out: &mut Vec<Decision>) {
        // Each pass either changes an entry or the queue, or stops; the
        // entries, the queue and the waiters are finite.
        for _ in 0..(CAP + self.fifo.len() + self.waiters.len() + 4) * 4 {
            if !self.settle_once(out) {
                break;
            }
        }
        if let Some(claim) = self.claim {
            if self.next_build() != Some(claim) && !self.builder_woken {
                self.builder_woken = true;
                out.push(Decision::WakeBuilder);
            }
        }
    }

    fn settle_once(&mut self, out: &mut Vec<Decision>) -> bool {
        // 0. A job that waits for a seed that is resident is granted. A
        //    queued job whose seed joined the window finds it built.
        if let Some(waiter) = self.waiters.iter().copied().find(|waiter| {
            waiter.wait == WaitFor::Seed
                && self
                    .entry(&waiter.seed)
                    .is_some_and(|entry| entry.state == EntryState::Resident)
        }) {
            self.waiters.retain(|w| w.ticket != waiter.ticket);
            self.grant(waiter.ticket, waiter.seed, false, out);
            return true;
        }
        // 1. Free what nothing lists, holds or waits for; drop a reserved
        //    build that has not begun and that nothing asks for any more. A
        //    reserved build of the third gives way to a queued job.
        let unwanted: Vec<Seedhash> = self
            .entries
            .iter()
            .filter(|entry| match entry.state {
                EntryState::Resident => {
                    (self.closed || !self.listed(&entry.seed)) && self.idle(entry)
                }
                EntryState::Queued => {
                    let asked = self.waiters_on(&entry.seed).next().is_some();
                    let listed = self.listed(&entry.seed) && !self.closed;
                    let third_gives_way = !self.in_window(&entry.seed) && !self.fifo.is_empty();
                    !asked && (!listed || third_gives_way)
                }
                EntryState::Deriving => false,
            })
            .map(|entry| entry.seed)
            .collect();
        if let Some(&seed) = unwanted.first() {
            self.free(seed, out);
            return true;
        }
        if self.closed {
            return false;
        }
        // 2. A window seed with nothing reserved takes its reserved place.
        //    When every place is taken (the list grew while outside leases
        //    were out), the lowest-ranked idle outside entry is freed; when
        //    none is idle, the build waits for the first outside lease to
        //    come back, and no outside job takes that place meanwhile.
        let missing = self
            .window()
            .iter()
            .copied()
            .find(|seed| self.entry(seed).is_none());
        if let Some(seed) = missing {
            if self.entries.len() < CAP {
                self.reserve(seed, out);
                return true;
            }
            if self.free_one_outside(None, out) {
                return true;
            }
            self.cancel_warm_outside(out);
        }
        // 3. The queue's head, judged by rule 2 without its first step.
        if !self.window_short() {
            if let Some(&head) = self.fifo.front() {
                let waiter = self
                    .waiters
                    .iter()
                    .copied()
                    .find(|waiter| waiter.ticket == head)
                    .expect("a queued ticket has its waiter");
                if self.place_outside(waiter, out) {
                    self.fifo.pop_front();
                    return true;
                }
                self.cancel_warm_outside(out);
                return false;
            }
        }
        // 4. The third, once no job waits for a place (HA-R3).
        if self.fifo.is_empty() && !self.window_short() {
            if let Some((third, _)) = self.third() {
                if self.entry(&third).is_none() && self.outside_count() < self.outside_places() {
                    self.reserve(third, out);
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;

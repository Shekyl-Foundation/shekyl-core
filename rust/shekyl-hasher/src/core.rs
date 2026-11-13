// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hasher's decisions, as a state machine with no clock, no threads, no
//! caches and no I/O (`RANDOMX_CACHE_ACTOR.md` §5.2, §5.4, §5.5).
//!
//! The shell runs it under one lock. A [`Decision`] is a command it
//! performs: drop a freed cache, cancel a warm lease, or wake the builder
//! off its permit wait. A grant is not a command. It is recorded on the
//! core, and the waiting thread reads it with [`Core::take_grant`] after
//! the wake. A reserved build is an entry in [`EntryState::Queued`], and
//! the builder reads the next one with [`Core::claim`]. Production runs
//! this core; nothing here is a test lever.
//!
//! # Terms
//!
//! - **W**, the window: the ranked list's first one or two seeds. Each has a
//!   place reserved whether or not it is built.
//! - **The third:** the list's third seed, with the class its jobs hash at.
//! - **An entry:** a seed that is resident, has a build reserved for it, or
//!   is retiring: freed by the core, its cache not yet dropped by the shell.
//!   A retiring entry still takes its place (HA-R2 is a memory cap), is
//!   never granted and never rebuilt; the place is free once the shell
//!   reports the drop ([`Core::retired`]).
//! - **Outside:** an entry or a job whose seed is not in W. The outside
//!   places are [`CAP`] minus the window's length.
//! - **The queue:** two collections, and a job is in one of them.
//!   [`Queue::fifo`] is outside jobs in arrival order (HA-R8). [`Queue::seed`]
//!   is jobs waiting on a build. Ticket order is arrival order.
//! - **A lease:** a granted job. A warm lease (`lend_warm`) can be
//!   cancelled; a job's lease cannot (HA-R1).

use std::collections::VecDeque;

use shekyl_hash_budget::Class;
use shekyl_pow_randomx::Seedhash;

use crate::{Ranked, CAP};

/// One request that has not been granted yet. Minted once, when the job
/// asks. Its order is the job's arrival order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Ticket(u64);

/// One granted job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LeaseId(u64);

/// A command the shell performs. A grant and a reserved build are state
/// the waiter and the builder read; they are not variants here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// `seed`'s cache is no longer held: drop it with no lock held, then
    /// report the drop with [`Core::retired`]. Until then its place stays
    /// taken.
    Free { seed: Seedhash },
    /// The warm lease's seed left the list, or a queued job or a window
    /// build needs its place: its permit wait ends and its next hash is
    /// refused.
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
    /// Freed: the shell drops the cache and reports it. Takes its place
    /// until then.
    Retiring,
}

/// What [`Core::place_outside`] did with an outside job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Placed {
    /// Granted, joined a build, or reserved one. The job is not in the fifo.
    Taken,
    /// It freed an idle outside entry: the place is free once that cache is
    /// dropped. The job stays at the head of the fifo.
    Freeing,
    /// A place is already on its way back (an outside entry, or the job's
    /// own seed, is retiring). The job stays at the head of the fifo.
    Waits,
    /// No place is free or freeing: only a warm lease's return can make one.
    /// The job stays at the head of the fifo.
    Short,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    seed: Seedhash,
    state: EntryState,
}

/// One job that has not been granted. It lives in exactly one of
/// [`Queue`]'s collections.
#[derive(Clone, Copy, Debug)]
struct Waiter {
    ticket: Ticket,
    seed: Seedhash,
    class: Class,
}

/// Jobs that have not been granted (module docs, *The queue*).
#[derive(Clone, Debug, Default)]
struct Queue {
    /// Outside jobs waiting for a place, earliest arrival at the front.
    fifo: VecDeque<Waiter>,
    /// Jobs waiting on their seed's build: a window job, or an outside job
    /// that has joined or reserved one.
    seed: Vec<Waiter>,
}

impl Queue {
    fn is_empty(&self) -> bool {
        self.fifo.is_empty() && self.seed.is_empty()
    }

    /// Both collections. The settle bound counts a fifo job twice, once
    /// here and once for the move between the collections.
    fn len(&self) -> usize {
        self.fifo.len() + self.seed.len()
    }

    /// The job the place queue will consider next.
    fn head(&self) -> Option<Waiter> {
        self.fifo.front().copied()
    }

    /// An outside job joins the back. It is not already queued.
    fn enqueue(&mut self, waiter: Waiter) {
        self.fifo.push_back(waiter);
    }

    /// Drop `ticket` from whichever collection holds it.
    fn remove(&mut self, ticket: Ticket) {
        self.fifo.retain(|waiter| waiter.ticket != ticket);
        self.seed.retain(|waiter| waiter.ticket != ticket);
    }

    fn clear(&mut self) {
        self.fifo.clear();
        self.seed.clear();
    }

    /// `waiter` is waiting on its seed's build, and is not in the fifo.
    fn move_to_seed(&mut self, waiter: Waiter) {
        self.fifo.retain(|queued| queued.ticket != waiter.ticket);
        if let Some(held) = self
            .seed
            .iter_mut()
            .find(|held| held.ticket == waiter.ticket)
        {
            *held = waiter;
        } else {
            self.seed.push(waiter);
        }
    }

    /// `waiter` is an outside job again, at its arrival position.
    fn insert_fifo_by_arrival(&mut self, waiter: Waiter) {
        self.seed.retain(|held| held.ticket != waiter.ticket);
        self.fifo.retain(|queued| queued.ticket != waiter.ticket);
        let at = self
            .fifo
            .iter()
            .position(|queued| queued.ticket > waiter.ticket)
            .unwrap_or(self.fifo.len());
        self.fifo.insert(at, waiter);
    }

    fn seed_on(&self, seed: Seedhash) -> impl Iterator<Item = &Waiter> {
        self.seed.iter().filter(move |waiter| waiter.seed == seed)
    }

    fn any_seed_on(&self, seed: &Seedhash) -> bool {
        self.seed.iter().any(|waiter| waiter.seed == *seed)
    }

    /// The jobs waiting on `seed`'s build, earliest arrival first, removed
    /// from this collection.
    fn take_seed_on(&mut self, seed: Seedhash) -> Vec<Waiter> {
        let mut waiting: Vec<Waiter> = self.seed_on(seed).copied().collect();
        waiting.sort_by_key(|waiter| waiter.ticket);
        self.seed.retain(|waiter| waiter.seed != seed);
        waiting
    }

    /// A seed-wait whose seed is outside the window and has no entry behind
    /// it joins the fifo at its arrival position. `window` and `backed`
    /// are the seeds that still hold it.
    fn requeue_unbacked(&mut self, window: &[Seedhash], backed: &[Seedhash]) {
        let mut index = 0;
        while index < self.seed.len() {
            let waiter = self.seed[index];
            let held = window.contains(&waiter.seed) || backed.contains(&waiter.seed);
            if held {
                index += 1;
            } else {
                self.seed.remove(index);
                self.insert_fifo_by_arrival(waiter);
            }
        }
    }

    /// A fifo job whose seed joined the window waits on that build instead.
    fn promote_window(&mut self, in_window: impl Fn(&Seedhash) -> bool) {
        let mut index = 0;
        while index < self.fifo.len() {
            if in_window(&self.fifo[index].seed) {
                let waiter = self.fifo.remove(index).expect("the index was just checked");
                self.move_to_seed(waiter);
            } else {
                index += 1;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lease {
    id: LeaseId,
    seed: Seedhash,
    warm: bool,
    cancelled: bool,
}

/// How many times a settle may walk the rules and still be moving.
///
/// One pass grants, frees, reserves, or moves one job. A job that moves
/// from the fifo onto a build, and a place that is freed and then reserved,
/// take more than one pass. Four cycles of that is the bound the property
/// test holds. The fifo is counted twice on purpose: once as a waiting job,
/// once as a move between the collections.
const SETTLE_CYCLES: usize = 4;
/// Class-rise wakes and the third's refill are not a place or a job.
const SETTLE_SLACK: usize = 4;

/// The state machine (module docs).
#[derive(Debug, Default)]
pub(crate) struct Core {
    list: Option<Ranked>,
    entries: Vec<Entry>,
    queue: Queue,
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

    /// A resident entry nothing holds or waits for: it may be freed.
    fn idle(&self, entry: &Entry) -> bool {
        entry.state == EntryState::Resident
            && self.leases_on(&entry.seed) == 0
            && !self.queue.any_seed_on(&entry.seed)
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
        let waiter = Waiter {
            ticket,
            seed,
            class,
        };
        let mut out = Vec::new();
        if self.in_window(&seed) {
            match self.entry(&seed).map(|entry| entry.state) {
                Some(EntryState::Resident) => self.grant(ticket, seed),
                _ => self.queue.move_to_seed(waiter),
            }
        } else if self.queue.fifo.is_empty() && !self.window_short() {
            // A stream for one seed must not pass a job waiting for another:
            // a non-empty fifo takes every newcomer, above.
            if self.place_outside(waiter, &mut out) != Placed::Taken {
                self.queue.enqueue(waiter);
            }
        } else {
            self.queue.enqueue(waiter);
        }
        self.settle(&mut out);
        Some((ticket, out))
    }

    /// A `lend_warm` request: granted only on a warm cache, never a build or
    /// a wait (the brief's §4.4). An outside seed (the third) is lent only
    /// while nothing waits for a place: no queued job, and no window seed
    /// short of one. A lease there would hold the place they wait for, and a
    /// stream of overlapping warm loans would hold it for ever.
    pub(crate) fn request_warm(&mut self, seed: Seedhash) -> Result<LeaseId, WarmRefused> {
        if self.closed {
            return Err(WarmRefused::Closed);
        }
        if !self.warm_lendable(&seed) {
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

    /// Whether [`request_warm`](Self::request_warm) would lend on `seed`
    /// now: listed and resident, and, outside the window, nothing waiting
    /// for a place.
    fn warm_lendable(&self, seed: &Seedhash) -> bool {
        self.listed(seed)
            && self
                .entry(seed)
                .is_some_and(|entry| entry.state == EntryState::Resident)
            && (self.in_window(seed) || (self.queue.fifo.is_empty() && !self.window_short()))
    }

    /// The lease `ticket` was granted, if it has been. Taken once.
    pub(crate) fn take_grant(&mut self, ticket: Ticket) -> Option<LeaseId> {
        let at = self.granted.iter().position(|(held, _)| *held == ticket)?;
        Some(self.granted.swap_remove(at).1)
    }

    /// A waiter left on its stop flag before it was granted.
    pub(crate) fn leave(&mut self, ticket: Ticket) -> Vec<Decision> {
        self.queue.remove(ticket);
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
        // A queued job whose seed joined W leaves the fifo: a window seed's
        // job never waits for an outside place.
        let window: Vec<Seedhash> = self.window().to_vec();
        self.queue.promote_window(|seed| window.contains(seed));
        self.requeue_unbacked();
        self.settle(&mut out);
        out
    }

    /// The shell dropped `seed`'s cache, which [`Decision::Free`] named:
    /// its place is free.
    ///
    /// # Panics
    ///
    /// When `seed` is not retiring: the shell reports only what the core
    /// freed, once.
    pub(crate) fn retired(&mut self, seed: Seedhash) -> Vec<Decision> {
        let at = self
            .entries
            .iter()
            .position(|entry| entry.seed == seed && entry.state == EntryState::Retiring)
            .expect("the shell reports the drop of a cache the core freed, once");
        self.entries.remove(at);
        self.requeue_unbacked();
        let mut out = Vec::new();
        self.settle(&mut out);
        out
    }

    /// Refuse new requests and stop scheduling builds. Every request not
    /// yet granted is dropped: its thread sees the close and returns
    /// stopped, and no build that finishes later grants it. A lease already
    /// granted stands, and the stop waits for it. A build in progress
    /// finishes; every cache goes once no lease holds it.
    pub(crate) fn close(&mut self) -> Vec<Decision> {
        self.closed = true;
        self.queue.clear();
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
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.seed == claimed.0)
        {
            entry.state = EntryState::Deriving;
        }
        true
    }

    /// The builder's permit wait gave up without a permit.
    pub(crate) fn unclaim(&mut self) {
        self.claim = None;
    }

    /// The derive of `seed` finished: it is resident, and every job waiting
    /// for it is granted, earliest arrival first.
    pub(crate) fn built(&mut self, seed: Seedhash) -> Vec<Decision> {
        let mut out = Vec::new();
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.seed == seed) {
            entry.state = EntryState::Resident;
        }
        for waiter in self.queue.take_seed_on(seed) {
            self.grant(waiter.ticket, seed);
        }
        self.settle(&mut out);
        out
    }

    /// Whether the hasher is stopping, no lease or waiter is left, and every
    /// freed cache has been dropped: a stop may join the builder.
    pub(crate) fn drained(&self) -> bool {
        self.closed
            && self.leases.is_empty()
            && self.queue.is_empty()
            && self
                .entries
                .iter()
                .all(|entry| entry.state != EntryState::Retiring)
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
                    EntryState::Retiring => crate::Residency::Retiring,
                };
                (entry.seed, residency)
            })
            .collect()
    }

    // ----- inside -----------------------------------------------------------

    /// Record a grant of `ticket` on the resident `seed`. The shell's wake
    /// is the notify that follows every apply; the waiter reads the grant
    /// with [`take_grant`](Self::take_grant).
    ///
    /// # Panics
    ///
    /// When the hasher is stopping. [`close`](Self::close) has dropped every
    /// waiter, so a grant now would start a job during a stop.
    fn grant(&mut self, ticket: Ticket, seed: Seedhash) {
        assert!(
            !self.closed,
            "a grant after close: close drops every waiter"
        );
        let lease = LeaseId(self.next());
        self.leases.push(Lease {
            id: lease,
            seed,
            warm: false,
            cancelled: false,
        });
        self.granted.push((ticket, lease));
    }

    /// A job that waits for its seed's build, whose seed is not in W and
    /// has no build or cache to wait for (its seed left W before anything
    /// was built, or its cache is retiring), is an outside job without a
    /// place: it joins the fifo at its arrival position.
    fn requeue_unbacked(&mut self) {
        let window: Vec<Seedhash> = self.window().to_vec();
        let backed: Vec<Seedhash> = self
            .entries
            .iter()
            .filter(|entry| entry.state != EntryState::Retiring)
            .map(|entry| entry.seed)
            .collect();
        self.queue.requeue_unbacked(&window, &backed);
    }

    /// Rule 2 without its first step: join the seed's entry, take a free
    /// outside place, or free the lowest-ranked idle outside entry, whose
    /// place is free once its cache is dropped. A freed place is never
    /// taken in the step that frees it. A job that must wait for a build
    /// is moved into [`Queue::seed`].
    fn place_outside(&mut self, waiter: Waiter, out: &mut Vec<Decision>) -> Placed {
        match self.entry(&waiter.seed).map(|entry| entry.state) {
            Some(EntryState::Resident) => {
                self.queue.remove(waiter.ticket);
                self.grant(waiter.ticket, waiter.seed);
                return Placed::Taken;
            }
            Some(EntryState::Queued | EntryState::Deriving) => {
                self.queue.move_to_seed(waiter);
                return Placed::Taken;
            }
            Some(EntryState::Retiring) => return Placed::Waits,
            None => {}
        }
        if self.outside_count() < self.outside_places() {
            self.reserve(waiter.seed);
            self.queue.move_to_seed(waiter);
            return Placed::Taken;
        }
        if self.outside_retiring() {
            return Placed::Waits;
        }
        if self.free_one_outside(Some(waiter.class), out) {
            return Placed::Freeing;
        }
        Placed::Short
    }

    /// An outside entry is retiring: an outside place is on its way back.
    fn outside_retiring(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.state == EntryState::Retiring && !self.in_window(&entry.seed))
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

    /// A resident entry retires: its place stays taken until the shell
    /// drops the cache. A reserved build that has not begun has no cache,
    /// and goes at once.
    fn free(&mut self, seed: Seedhash, out: &mut Vec<Decision>) {
        let Some(at) = self.entries.iter().position(|entry| entry.seed == seed) else {
            return;
        };
        match self.entries[at].state {
            EntryState::Resident => {
                self.entries[at].state = EntryState::Retiring;
                out.push(Decision::Free { seed });
            }
            EntryState::Queued => {
                self.entries.remove(at);
            }
            EntryState::Deriving | EntryState::Retiring => {
                unreachable!("only a resident entry or an unbegun build is freed")
            }
        }
    }

    fn reserve(&mut self, seed: Seedhash) {
        self.entries.push(Entry {
            seed,
            state: EntryState::Queued,
        });
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
    /// third (§5.4). A job still in the fifo has not joined the build.
    fn build_class(&self, entry: &Entry) -> Option<Class> {
        let waiting = self.queue.seed_on(entry.seed).map(|waiter| waiter.class);
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
                let first_waiter = self
                    .queue
                    .seed_on(entry.seed)
                    .map(|waiter| waiter.ticket)
                    .min();
                Some((
                    (first_waiter.is_none(), first_waiter, rank(&entry.seed)),
                    (entry.seed, class),
                ))
            })
            .min_by_key(|(order, _)| *order)
            .map(|(_, build)| build)
    }

    /// Passes that still move something before the settle is a core fault.
    fn settle_bound(&self) -> usize {
        let movers = CAP + self.queue.fifo.len() + self.queue.len() + SETTLE_SLACK;
        movers * SETTLE_CYCLES
    }

    /// Bring the state to what the list and the jobs ask for, after every
    /// event (the brief's §4.3 and §4.6).
    ///
    /// # Panics
    ///
    /// When the passes run out with the last one still moving something.
    /// Each pass changes an entry or the queue, and both are finite, so this
    /// is a core fault; a silent return would leave a waiter that nothing
    /// wakes.
    fn settle(&mut self, out: &mut Vec<Decision>) {
        let bound = self.settle_bound();
        let mut settled = false;
        for _ in 0..bound {
            if !self.settle_once(out) {
                settled = true;
                break;
            }
        }
        assert!(
            settled,
            "settle reaches a fixpoint: {bound} passes each moved something"
        );
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
        if let Some(waiter) = self.queue.seed.iter().copied().find(|waiter| {
            self.entry(&waiter.seed)
                .is_some_and(|entry| entry.state == EntryState::Resident)
        }) {
            self.queue.remove(waiter.ticket);
            self.grant(waiter.ticket, waiter.seed);
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
                    let asked = self.queue.any_seed_on(&entry.seed);
                    let listed = self.listed(&entry.seed) && !self.closed;
                    let third_gives_way =
                        !self.in_window(&entry.seed) && !self.queue.fifo.is_empty();
                    !asked && (!listed || third_gives_way)
                }
                EntryState::Deriving | EntryState::Retiring => false,
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
        //    come back. The queue and the third are not judged in that
        //    case: an outside job must not take the place the window waits
        //    for. A place that is retiring comes back when its cache is
        //    dropped, and nothing else is freed meanwhile.
        let missing = self
            .window()
            .iter()
            .copied()
            .find(|seed| self.entry(seed).is_none());
        if let Some(seed) = missing {
            if self.entries.len() < CAP {
                self.reserve(seed);
                return true;
            }
            let retiring = self
                .entries
                .iter()
                .any(|entry| entry.state == EntryState::Retiring);
            if !retiring {
                if self.free_one_outside(None, out) {
                    return true;
                }
                self.cancel_warm_outside(out);
            }
            return false;
        }
        // 3. The fifo's head, judged by rule 2 without its first step.
        if let Some(head) = self.queue.head() {
            match self.place_outside(head, out) {
                Placed::Taken | Placed::Freeing => return true,
                Placed::Waits => return false,
                Placed::Short => {
                    self.cancel_warm_outside(out);
                    return false;
                }
            }
        }
        // 4. The third, once no job waits for a place (HA-R3).
        if self.queue.fifo.is_empty() {
            if let Some((third, _)) = self.third() {
                if self.entry(&third).is_none() && self.outside_count() < self.outside_places() {
                    self.reserve(third);
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

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The timing engine from `P2P_TIMING_ENGINE.md`.
//!
//! The core stores wake hints ordered by time and hands back the ones that
//! are due. A newer arming drops the older one by generation. The clock is
//! passed in. [`EngineService`] is the thread around that core: homes send
//! commands and never wait for them to be applied.
//!
//! A [`Tick`] is nanoseconds since the clock's origin. [`MonotonicClock`] is
//! the production clock. [`ManualClock`] is the one tests move by hand.

#![deny(unsafe_code)]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Nanoseconds since the clock's origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(u64);

impl Tick {
    pub const fn new(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    fn saturating_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// Something that can say what time it is.
///
/// `wait_for` is how the service thread sleeps. `set_now` is how a test
/// moves a hand clock. A clock that advances by itself ignores `set_now`.
pub trait Clock {
    fn now(&self) -> Tick;

    /// How long to sleep before `deadline`.
    ///
    /// `Some(Duration::ZERO)` means the deadline is already due.
    /// `Some(wait)` means this clock moves by itself. `None` means it does
    /// not: block until the next command.
    fn wait_for(&self, deadline: Tick) -> Option<Duration>;

    fn set_now(&self, now: Tick) {
        let _ = now;
    }
}

/// A clock the test moves by hand. Not behind a cargo feature.
///
/// A clone shares the instant. Homes and the engine read the same one.
#[derive(Clone, Debug)]
pub struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    pub fn new(now: Tick) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now.get())),
        }
    }

    pub fn set(&self, now: Tick) {
        self.set_now(now);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Tick {
        Tick::new(self.now.load(Ordering::Acquire))
    }

    fn wait_for(&self, deadline: Tick) -> Option<Duration> {
        if deadline.get() <= self.now().get() {
            Some(Duration::ZERO)
        } else {
            None
        }
    }

    fn set_now(&self, now: Tick) {
        self.now.store(now.get(), Ordering::Release);
    }
}

/// Production clock. The origin is the moment of construction.
///
/// `Instant` on Linux is `CLOCK_MONOTONIC`. That clock does not advance
/// while the system is suspended, so a deadline is not late by the time
/// the machine spent suspended.
#[derive(Clone, Debug)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Tick {
        let nanos = self.origin.elapsed().as_nanos();
        Tick(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    fn wait_for(&self, deadline: Tick) -> Option<Duration> {
        let now = self.now().get();
        let deadline = deadline.get();
        if deadline <= now {
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_nanos(deadline - now))
        }
    }
}

/// Why an owner exists. Lateness is kept per class, not per fire.
///
/// Housekeeping is the only class that may later take timer slack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OwnerClass {
    Relay,
    Transport,
    TimedSync,
    Peerlist,
    Discovery,
    Housekeeping,
    Interim,
}

const CLASS_COUNT: usize = 7;

impl OwnerClass {
    const fn index(self) -> usize {
        match self {
            Self::Relay => 0,
            Self::Transport => 1,
            Self::TimedSync => 2,
            Self::Peerlist => 3,
            Self::Discovery => 4,
            Self::Housekeeping => 5,
            Self::Interim => 6,
        }
    }

    #[cfg(test)]
    fn from_index(index: u8) -> Self {
        match index % 7 {
            0 => Self::Relay,
            1 => Self::Transport,
            2 => Self::TimedSync,
            3 => Self::Peerlist,
            4 => Self::Discovery,
            5 => Self::Housekeeping,
            _ => Self::Interim,
        }
    }
}

/// One owner. Read off an [`OwnerMint`].
///
/// The field stays private. There is no public constructor, and
/// [`Engine::register`] does not accept an [`OwnerId`]. Copying an id
/// does not confer the right to register it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerId(u64);

/// One-shot right to register an [`OwnerId`].
///
/// [`IdSource::mint`] is the only production constructor. [`Engine::register`]
/// consumes the token. The id can be copied off; the token cannot. A stale
/// heap hint therefore cannot be revived by registering that id again.
#[derive(Debug)]
pub struct OwnerMint(OwnerId);

impl OwnerMint {
    /// The id this token registers. Copying it does not copy the token.
    pub fn id(&self) -> OwnerId {
        self.0
    }

    /// End the token and return its id.
    fn take(self) -> OwnerId {
        self.0
    }

    /// A second token for an id the live map may already hold.
    ///
    /// Production minting cannot build one. Passing an id that was
    /// deregistered would revive its stale hint: the map no longer holds
    /// it, and this token is the hole the type otherwise closes. Tests
    /// use it only for an id that is still live.
    #[cfg(test)]
    fn duplicate(id: OwnerId) -> Self {
        Self(id)
    }
}

/// Hands out [`OwnerMint`]s from an atomic counter, starting at 1.
///
/// The service handle holds one, so registering is not a round trip.
/// The core's own bench holds one too, because it calls [`Engine::register`]
/// directly. The counter stops when the next mint would wrap, so an id
/// is never issued twice.
#[derive(Clone, Debug)]
pub struct IdSource {
    /// Next id to issue. `0` means the space is exhausted: `0` itself is
    /// never an id, and it is what remains after `u64::MAX` is issued.
    next: Arc<AtomicU64>,
}

impl IdSource {
    pub fn new() -> Self {
        Self {
            next: Arc::new(AtomicU64::new(1)),
        }
    }

    /// The next id, or [`EngineError::IdsExhausted`] when the counter
    /// has already issued `u64::MAX`.
    pub fn mint(&self) -> Result<OwnerMint, EngineError> {
        loop {
            let current = self.next.load(Ordering::Relaxed);
            if current == 0 {
                return Err(EngineError::IdsExhausted);
            }
            if self
                .next
                .compare_exchange_weak(
                    current,
                    current.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(OwnerMint(OwnerId(current)));
            }
        }
    }

    /// `next` is the counter [`mint`](Self::mint) reads. `0` is exhausted.
    #[cfg(test)]
    fn with_next(next: u64) -> Self {
        Self {
            next: Arc::new(AtomicU64::new(next)),
        }
    }
}

impl Default for IdSource {
    fn default() -> Self {
        Self::new()
    }
}

/// One arming. A later arming of the same owner makes the earlier one stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A due hint, for the caller to deliver to the owner's home.
///
/// When several owners are due at the same [`Tick`], the lower [`OwnerId`]
/// comes first. That order is fixed. It is not a fairness policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wake {
    pub owner: OwnerId,
    pub class: OwnerClass,
    pub generation: Generation,
    pub deadline: Tick,
    pub fired_at: Tick,
}

/// How many power-of-two buckets each lateness histogram has.
///
/// Bucket 0 counts a delay of exactly 0. Bucket `k` for `k` in `1..=62`
/// counts delays in `[2^(k-1), 2^k)`. Bucket 63 counts delays of at least
/// `2^62` nanoseconds. A tail summed from a power-of-two threshold is exact.
pub const LATENESS_BUCKETS: usize = 64;

/// Which histogram bucket holds `delay`. See [`LATENESS_BUCKETS`].
#[must_use]
pub fn lateness_bucket(delay: u64) -> usize {
    if delay == 0 {
        0
    } else {
        usize::try_from(delay.ilog2())
            .unwrap_or(LATENESS_BUCKETS - 1)
            .saturating_add(1)
            .min(LATENESS_BUCKETS - 1)
    }
}

/// Lateness for one [`OwnerClass`].
///
/// The sums give the mean. The buckets and the maximum give the tail:
/// how often a wake was late by at least a power-of-two threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassLateness {
    pub fires: u64,
    pub wake_delay: u64,
    pub max_wake_delay: u64,
    pub wake_buckets: [u64; LATENESS_BUCKETS],
    pub home_reports: u64,
    pub home_delay: u64,
    pub max_home_delay: u64,
    pub home_buckets: [u64; LATENESS_BUCKETS],
    /// A new wake replaced one whose home had not reported.
    pub replaced_wakes: u64,
}

impl Default for ClassLateness {
    fn default() -> Self {
        Self {
            fires: 0,
            wake_delay: 0,
            max_wake_delay: 0,
            wake_buckets: [0; LATENESS_BUCKETS],
            home_reports: 0,
            home_delay: 0,
            max_home_delay: 0,
            home_buckets: [0; LATENESS_BUCKETS],
            replaced_wakes: 0,
        }
    }
}

impl ClassLateness {
    /// Fires whose bucket starts at or above `delay`.
    ///
    /// Exact when `delay` is 0 or a power of two. A threshold inside a
    /// bucket also counts the smaller delays that share that bucket.
    #[must_use]
    pub fn wakes_at_least(&self, delay: u64) -> u64 {
        tail(&self.wake_buckets, delay)
    }

    /// Home reports whose bucket starts at or above `delay`. Same rule as
    /// [`Self::wakes_at_least`].
    #[must_use]
    pub fn homes_at_least(&self, delay: u64) -> u64 {
        tail(&self.home_buckets, delay)
    }
}

fn tail(buckets: &[u64; LATENESS_BUCKETS], delay: u64) -> u64 {
    buckets[lateness_bucket(delay)..]
        .iter()
        .copied()
        .fold(0, u64::saturating_add)
}

fn record_sample(sum: &mut u64, max: &mut u64, buckets: &mut [u64; LATENESS_BUCKETS], delay: u64) {
    *sum = sum.saturating_add(delay);
    *max = (*max).max(delay);
    let index = lateness_bucket(delay);
    buckets[index] = buckets[index].saturating_add(1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    UnknownOwner,
    /// This id is already in the live map. A second [`OwnerMint`] for it
    /// was consumed.
    DuplicateOwner,
    /// [`IdSource`] has issued `u64::MAX` and will not wrap.
    IdsExhausted,
    Closed,
    /// `polled_at` is before the wake was handed out.
    HomeBeforeFire,
    /// No outstanding wake matches this owner and generation.
    NoSuchWake,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Hint {
    when: Tick,
    owner: OwnerId,
    generation: u64,
}

impl Ord for Hint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.when
            .cmp(&other.when)
            .then(self.owner.cmp(&other.owner))
            .then(self.generation.cmp(&other.generation))
    }
}

impl PartialOrd for Hint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

struct Owner {
    class: OwnerClass,
    generation: u64,
    /// The live hint, if this owner is armed.
    deadline: Option<Tick>,
    /// The one wake whose home has not reported.
    pending: Option<PendingHome>,
}

#[derive(Clone, Copy)]
struct PendingHome {
    generation: u64,
    fired_at: Tick,
}

/// Wake hints. The clock is owned here so a test clock cannot be a feature flag.
pub struct Engine<C: Clock> {
    clock: C,
    closed: bool,
    /// Owners whose `deadline` is `Some`. Maintained, never scanned.
    live: usize,
    /// Owners with an outstanding home report.
    pending_count: usize,
    owners: HashMap<OwnerId, Owner>,
    heap: BinaryHeap<Reverse<Hint>>,
    by_class: [ClassLateness; CLASS_COUNT],
}

impl<C: Clock> Engine<C> {
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            closed: false,
            live: 0,
            pending_count: 0,
            owners: HashMap::new(),
            heap: BinaryHeap::new(),
            by_class: std::array::from_fn(|_| ClassLateness::default()),
        }
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    /// Consume `minted` and accept its id.
    ///
    /// The token is spent on every path, including [`EngineError::Closed`].
    /// A stale hint for a deregistered id stays in the heap until it
    /// reaches the front, and it cannot match a new owner because that
    /// owner holds a different id. A second token for an id the map still
    /// holds is [`EngineError::DuplicateOwner`].
    pub fn register(&mut self, minted: OwnerMint, class: OwnerClass) -> Result<(), EngineError> {
        let id = minted.take();
        if self.closed {
            return Err(EngineError::Closed);
        }
        if self.owners.contains_key(&id) {
            return Err(EngineError::DuplicateOwner);
        }
        self.owners.insert(
            id,
            Owner {
                class,
                generation: 0,
                deadline: None,
                pending: None,
            },
        );
        Ok(())
    }

    /// Forget an owner. Its one outstanding wake goes with it. Hints still
    /// in the heap are dropped when they reach the front.
    pub fn deregister(&mut self, owner: OwnerId) -> Result<(), EngineError> {
        let Some(removed) = self.owners.remove(&owner) else {
            return Err(EngineError::UnknownOwner);
        };
        if removed.deadline.is_some() {
            self.live -= 1;
        }
        if removed.pending.is_some() {
            self.pending_count -= 1;
        }
        self.compact_if_stale();
        Ok(())
    }

    /// Arm `deadline`.
    ///
    /// If this owner is already armed at `deadline` or earlier, this is a
    /// no-op and returns the current generation. A later deadline is not a
    /// new hint. An owner that is not armed (it fired, or it was cleared)
    /// takes `deadline` as its first hint.
    pub fn arm(&mut self, owner: OwnerId, deadline: Tick) -> Result<Generation, EngineError> {
        if self.closed {
            return Err(EngineError::Closed);
        }
        let slot = self
            .owners
            .get_mut(&owner)
            .ok_or(EngineError::UnknownOwner)?;
        if let Some(current) = slot.deadline {
            if deadline >= current {
                return Ok(Generation(slot.generation));
            }
        }
        let was_armed = slot.deadline.is_some();
        slot.generation = slot.generation.saturating_add(1);
        let generation = slot.generation;
        slot.deadline = Some(deadline);
        if !was_armed {
            self.live += 1;
        }
        self.heap.push(Reverse(Hint {
            when: deadline,
            owner,
            generation,
        }));
        self.compact_if_stale();
        Ok(Generation(generation))
    }

    /// Drop this owner's hint. A later pop of an older arming is ignored.
    pub fn clear(&mut self, owner: OwnerId) -> Result<(), EngineError> {
        if self.closed {
            return Err(EngineError::Closed);
        }
        let slot = self
            .owners
            .get_mut(&owner)
            .ok_or(EngineError::UnknownOwner)?;
        if slot.deadline.is_none() {
            return Ok(());
        }
        slot.generation = slot.generation.saturating_add(1);
        slot.deadline = None;
        self.live -= 1;
        self.compact_if_stale();
        Ok(())
    }

    /// Refuse new owners and new armings. Due hints are dropped, not delivered.
    pub fn close(&mut self) {
        self.closed = true;
        self.heap.clear();
        self.live = 0;
        self.pending_count = 0;
        for owner in self.owners.values_mut() {
            owner.deadline = None;
            owner.pending = None;
        }
    }

    /// The earliest live deadline, after stale hints at the front are discarded.
    ///
    /// `None` means there is nothing to wait for. That is how long the engine thread sleeps.
    pub fn next_deadline(&mut self) -> Option<Tick> {
        if self.closed {
            return None;
        }
        self.discard_stale_front();
        self.heap.peek().map(|Reverse(hint)| hint.when)
    }

    /// Hand back every live hint that is due.
    ///
    /// Equal deadlines come out in [`OwnerId`] order, oldest first. An owner
    /// has one outstanding wake: a new one replaces an unreported one, and
    /// that replacement is counted on the owner's class.
    pub fn poll(&mut self) -> Vec<Wake> {
        if self.closed {
            return Vec::new();
        }
        let now = self.clock.now();
        let mut due = Vec::new();
        while let Some(Reverse(hint)) = self.heap.peek().copied() {
            if hint.when > now {
                break;
            }
            self.heap.pop();
            let Some(owner) = self.owners.get_mut(&hint.owner) else {
                continue;
            };
            if owner.deadline.is_none() || owner.generation != hint.generation {
                continue;
            }
            owner.deadline = None;
            let class = owner.class;
            let replaced = owner.pending.is_some();
            owner.pending = Some(PendingHome {
                generation: hint.generation,
                fired_at: now,
            });
            self.live -= 1;
            if replaced {
                self.by_class[class.index()].replaced_wakes = self.by_class[class.index()]
                    .replaced_wakes
                    .saturating_add(1);
            } else {
                self.pending_count += 1;
            }
            let wake_delay = now.saturating_since(hint.when);
            let totals = &mut self.by_class[class.index()];
            totals.fires = totals.fires.saturating_add(1);
            record_sample(
                &mut totals.wake_delay,
                &mut totals.max_wake_delay,
                &mut totals.wake_buckets,
                wake_delay,
            );
            due.push(Wake {
                owner: hint.owner,
                class,
                generation: Generation(hint.generation),
                deadline: hint.when,
                fired_at: now,
            });
        }
        // Firing lowers the live count and leaves superseded hints behind
        // the deadlines that are not yet due. Those hints are not at the
        // front, so the next sleep cannot see them.
        self.compact_if_stale();
        due
    }

    /// The owner's home has polled this generation.
    pub fn note_home(
        &mut self,
        owner: OwnerId,
        generation: Generation,
        polled_at: Tick,
    ) -> Result<(), EngineError> {
        let slot = self
            .owners
            .get_mut(&owner)
            .ok_or(EngineError::UnknownOwner)?;
        let Some(pending) = slot.pending else {
            return Err(EngineError::NoSuchWake);
        };
        if pending.generation != generation.get() {
            return Err(EngineError::NoSuchWake);
        }
        if polled_at < pending.fired_at {
            return Err(EngineError::HomeBeforeFire);
        }
        let class = slot.class;
        let delay = polled_at.saturating_since(pending.fired_at);
        slot.pending = None;
        self.pending_count -= 1;
        let totals = &mut self.by_class[class.index()];
        totals.home_reports = totals.home_reports.saturating_add(1);
        record_sample(
            &mut totals.home_delay,
            &mut totals.max_home_delay,
            &mut totals.home_buckets,
            delay,
        );
        Ok(())
    }

    pub fn lateness(&self, class: OwnerClass) -> &ClassLateness {
        &self.by_class[class.index()]
    }

    /// Wakes handed out whose home has not reported yet. At most one per owner.
    pub fn pending_homes(&self) -> usize {
        self.pending_count
    }

    fn is_live(&self, hint: &Hint) -> bool {
        self.owners
            .get(&hint.owner)
            .is_some_and(|owner| owner.deadline.is_some() && owner.generation == hint.generation)
    }

    fn discard_stale_front(&mut self) {
        while let Some(Reverse(hint)) = self.heap.peek().copied() {
            if self.is_live(&hint) {
                break;
            }
            self.heap.pop();
        }
    }

    /// Rebuild when stale hints outnumber live ones: one rebuild per doubling.
    ///
    /// The new heap is allocated for the live hints only. Filtering the old
    /// vector in place would keep the capacity those stale hints occupied.
    fn compact_if_stale(&mut self) {
        if self.heap.len() <= self.live.saturating_mul(2) {
            return;
        }
        let stale = std::mem::take(&mut self.heap).into_vec();
        let mut keep = Vec::with_capacity(self.live);
        for Reverse(hint) in stale {
            if self.is_live(&hint) {
                keep.push(Reverse(hint));
            }
        }
        self.heap = BinaryHeap::from(keep);
    }
}

mod service;

pub use service::{EngineService, Handle, OwnerHandle};

#[cfg(test)]
mod model;

#[cfg(test)]
mod engine_tests;

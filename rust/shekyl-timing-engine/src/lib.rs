// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The timing-engine core from `P2P_TIMING_ENGINE.md`.
//!
//! An owner lives somewhere else and polls itself there. This crate stores
//! wake hints ordered by time, and hands back the ones that are due. A newer
//! arming drops the older one by generation. The clock is passed in.
//!
//! A [`Tick`] is nanoseconds since the clock's origin. [`MonotonicClock`] is
//! the production clock. [`ManualClock`] is the one tests move by hand.

#![deny(unsafe_code)]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::Instant;

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

/// Something that can say what time it is, and nothing else.
pub trait Clock {
    fn now(&self) -> Tick;
}

/// A clock the test moves by hand. Not behind a cargo feature.
#[derive(Clone, Debug)]
pub struct ManualClock {
    now: Tick,
}

impl ManualClock {
    pub const fn new(now: Tick) -> Self {
        Self { now }
    }

    pub fn set(&mut self, now: Tick) {
        self.now = now;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Tick {
        self.now
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

/// One owner. Minted by [`Engine::register`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerId(u64);

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
    next_id: u64,
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
            next_id: 1,
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

    pub fn register(&mut self, class: OwnerClass) -> Result<OwnerId, EngineError> {
        if self.closed {
            return Err(EngineError::Closed);
        }
        let id = OwnerId(self.next_id);
        self.next_id += 1;
        self.owners.insert(
            id,
            Owner {
                class,
                generation: 0,
                deadline: None,
                pending: None,
            },
        );
        Ok(id)
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
    fn compact_if_stale(&mut self) {
        if self.heap.len() <= self.live.saturating_mul(2) {
            return;
        }
        let mut keep = Vec::with_capacity(self.live);
        while let Some(Reverse(hint)) = self.heap.pop() {
            if self.is_live(&hint) {
                keep.push(Reverse(hint));
            }
        }
        self.heap = keep.into();
    }
}

#[cfg(test)]
mod model;

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_at(now: u64) -> Engine<ManualClock> {
        Engine::new(ManualClock::new(Tick::new(now)))
    }

    fn owner(engine: &mut Engine<ManualClock>) -> OwnerId {
        engine.register(OwnerClass::Housekeeping).unwrap()
    }

    #[test]
    fn a_future_hint_is_not_due() {
        let mut engine = engine_at(10);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(11)).unwrap();
        assert!(engine.poll().is_empty());
        assert_eq!(engine.next_deadline(), Some(Tick::new(11)));
    }

    #[test]
    fn a_due_hint_is_handed_back_with_lateness() {
        let mut engine = engine_at(10);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(8)).unwrap();
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].deadline, Tick::new(8));
        assert_eq!(wakes[0].fired_at, Tick::new(10));
        let totals = engine.lateness(OwnerClass::Housekeeping);
        assert_eq!(totals.wake_delay, 2);
        assert_eq!(totals.fires, 1);
        assert_eq!(totals.max_wake_delay, 2);
        assert_eq!(totals.wake_buckets[lateness_bucket(2)], 1);
        assert_eq!(totals.wakes_at_least(2), 1);
        assert_eq!(totals.wakes_at_least(4), 0);
    }

    #[test]
    fn a_later_arm_is_a_no_op() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        let first = engine.arm(id, Tick::new(5)).unwrap();
        let second = engine.arm(id, Tick::new(9)).unwrap();
        assert_eq!(first, second);
        assert_eq!(engine.heap.len(), 1);
        engine.clock_mut().set(Tick::new(5));
        assert_eq!(engine.poll()[0].deadline, Tick::new(5));
    }

    #[test]
    fn rearming_earlier_fires_at_the_new_time() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(9)).unwrap();
        let earlier = engine.arm(id, Tick::new(4)).unwrap();
        assert_eq!(engine.next_deadline(), Some(Tick::new(4)));
        engine.clock_mut().set(Tick::new(4));
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].deadline, Tick::new(4));
        assert_eq!(wakes[0].generation, earlier);
    }

    #[test]
    fn clear_removes_the_deadline() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(5)).unwrap();
        engine.clear(id).unwrap();
        assert_eq!(engine.next_deadline(), None);
        assert_eq!(engine.live, 0);
        engine.clock_mut().set(Tick::new(5));
        assert!(engine.poll().is_empty());
    }

    #[test]
    fn two_owners_due_together_both_fire() {
        let mut engine = engine_at(0);
        let first = owner(&mut engine);
        let second = owner(&mut engine);
        engine.arm(first, Tick::new(10)).unwrap();
        engine.arm(second, Tick::new(10)).unwrap();
        engine.clock_mut().set(Tick::new(10));
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 2);
        assert_eq!(wakes[0].owner, first);
        assert_eq!(wakes[1].owner, second);
    }

    #[test]
    fn only_the_earliest_owner_fires() {
        let mut engine = engine_at(0);
        let mut ids = Vec::new();
        for i in 0..32 {
            let id = owner(&mut engine);
            engine.arm(id, Tick::new(100 + i)).unwrap();
            ids.push(id);
        }
        engine.clock_mut().set(Tick::new(100));
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].owner, ids[0]);
        assert_eq!(engine.live, 31);
    }

    #[test]
    fn next_deadline_skips_a_stale_hint() {
        let mut engine = engine_at(0);
        let early = owner(&mut engine);
        let later = owner(&mut engine);
        engine.arm(early, Tick::new(3)).unwrap();
        engine.arm(later, Tick::new(8)).unwrap();
        engine.clear(early).unwrap();
        assert_eq!(engine.next_deadline(), Some(Tick::new(8)));
    }

    #[test]
    fn deregister_drops_the_owner_and_its_pending_wake() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(4)).unwrap();
        engine.clock_mut().set(Tick::new(4));
        assert_eq!(engine.poll().len(), 1);
        assert_eq!(engine.pending_homes(), 1);
        engine.deregister(id).unwrap();
        assert_eq!(engine.pending_homes(), 0);
        assert_eq!(engine.next_deadline(), None);
        assert_eq!(
            engine.arm(id, Tick::new(5)).unwrap_err(),
            EngineError::UnknownOwner
        );
    }

    #[test]
    fn a_second_wake_replaces_an_unreported_one() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        let first = engine.arm(id, Tick::new(1)).unwrap();
        engine.clock_mut().set(Tick::new(1));
        engine.poll();
        engine.arm(id, Tick::new(3)).unwrap();
        engine.clock_mut().set(Tick::new(3));
        let second = engine.poll()[0].generation;
        assert_eq!(engine.pending_homes(), 1);
        assert_eq!(engine.lateness(OwnerClass::Housekeeping).replaced_wakes, 1);
        assert_eq!(
            engine.note_home(id, first, Tick::new(3)).unwrap_err(),
            EngineError::NoSuchWake
        );
        engine.note_home(id, second, Tick::new(3)).unwrap();
        assert_eq!(engine.pending_homes(), 0);
    }

    #[test]
    fn home_delay_matches_the_generation() {
        let mut engine = engine_at(10);
        let id = engine.register(OwnerClass::TimedSync).unwrap();
        let generation = engine.arm(id, Tick::new(10)).unwrap();
        let wake = engine.poll()[0];
        engine.note_home(id, generation, Tick::new(14)).unwrap();
        assert_eq!(wake.generation, generation);
        let totals = engine.lateness(OwnerClass::TimedSync);
        assert_eq!(totals.wake_delay, 0);
        assert_eq!(totals.home_delay, 4);
        assert_eq!(totals.home_buckets[lateness_bucket(4)], 1);
        assert_eq!(engine.pending_homes(), 0);
    }

    #[test]
    fn repeated_fires_do_not_grow_a_sample_log() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        for n in 1..=64 {
            engine.arm(id, Tick::new(n)).unwrap();
            engine.clock_mut().set(Tick::new(n));
            let wake = engine.poll()[0];
            engine.note_home(id, wake.generation, Tick::new(n)).unwrap();
        }
        assert_eq!(engine.pending_homes(), 0);
        assert_eq!(engine.lateness(OwnerClass::Housekeeping).fires, 64);
        assert_eq!(engine.owners.len(), 1);
    }

    #[test]
    fn a_partial_poll_compacts_hints_left_behind() {
        let mut engine = engine_at(0);
        for i in 0..3 {
            let id = owner(&mut engine);
            engine.arm(id, Tick::new(100 + i)).unwrap();
            engine.arm(id, Tick::new(10 + i)).unwrap();
        }
        engine.clock_mut().set(Tick::new(11));
        assert_eq!(engine.poll().len(), 2);
        assert_eq!(engine.live, 1);
        assert!(engine.heap.len() <= engine.live.saturating_mul(2).saturating_add(1));
        assert_eq!(engine.next_deadline(), Some(Tick::new(12)));
    }

    #[test]
    fn rearming_earlier_compacts_stale_hints() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        for n in (1..=8).rev() {
            engine.arm(id, Tick::new(n)).unwrap();
        }
        assert!(engine.heap.len() <= 2);
        assert_eq!(engine.live, 1);
        assert_eq!(engine.next_deadline(), Some(Tick::new(1)));
    }

    #[test]
    fn a_closed_engine_drops_hints_and_refuses_arming() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(1)).unwrap();
        engine.close();
        engine.clock_mut().set(Tick::new(1));
        assert!(engine.poll().is_empty());
        assert_eq!(engine.next_deadline(), None);
        assert_eq!(
            engine.register(OwnerClass::Relay).unwrap_err(),
            EngineError::Closed
        );
        assert_eq!(
            engine.arm(id, Tick::new(2)).unwrap_err(),
            EngineError::Closed
        );
        assert_eq!(engine.clear(id).unwrap_err(), EngineError::Closed);
    }

    #[test]
    fn an_unknown_owner_is_refused() {
        let mut engine = engine_at(0);
        let err = engine.arm(OwnerId(99), Tick::new(1)).unwrap_err();
        assert_eq!(err, EngineError::UnknownOwner);
    }

    #[test]
    fn the_monotonic_clock_does_not_go_backwards() {
        let clock = MonotonicClock::new();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The timing-engine core from `P2P_TIMING_ENGINE.md`.
//!
//! An owner lives somewhere else and polls itself there. This crate stores
//! wake hints ordered by time, and hands back the ones that are due. A newer
//! arming drops the older one by generation. The clock is passed in.

#![deny(unsafe_code)]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

/// A monotonic instant. The unit belongs to the clock that minted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(u64);

impl Tick {
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wake {
    pub owner: OwnerId,
    pub class: OwnerClass,
    pub generation: Generation,
    pub deadline: Tick,
    pub fired_at: Tick,
}

/// Lateness for one [`OwnerClass`], summed across fires.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClassLateness {
    pub fires: u64,
    pub wake_delay: u64,
    pub home_reports: u64,
    pub home_delay: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    UnknownOwner,
    Closed,
    /// `polled_at` is before the wake was handed out.
    HomeBeforeFire,
    /// No handed-out wake matches this owner and generation.
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
    armed: bool,
}

struct PendingHome {
    class: OwnerClass,
    fired_at: Tick,
}

/// Wake hints. The clock is owned here so a test clock cannot be a feature flag.
pub struct Engine<C: Clock> {
    clock: C,
    next_id: u64,
    closed: bool,
    owners: HashMap<OwnerId, Owner>,
    heap: BinaryHeap<Reverse<Hint>>,
    pending: HashMap<(OwnerId, u64), PendingHome>,
    by_class: [ClassLateness; CLASS_COUNT],
}

impl<C: Clock> Engine<C> {
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            next_id: 1,
            closed: false,
            owners: HashMap::new(),
            heap: BinaryHeap::new(),
            pending: HashMap::new(),
            by_class: [ClassLateness::default(); CLASS_COUNT],
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
                armed: false,
            },
        );
        Ok(id)
    }

    /// Forget an owner. Hints still in the heap are dropped when they reach the front.
    pub fn deregister(&mut self, owner: OwnerId) -> Result<(), EngineError> {
        if self.owners.remove(&owner).is_none() {
            return Err(EngineError::UnknownOwner);
        }
        self.pending.retain(|(id, _), _| *id != owner);
        self.compact_if_stale();
        Ok(())
    }

    /// Replace this owner's hint. Call only when the owner's earliest deadline moves earlier.
    pub fn arm(&mut self, owner: OwnerId, deadline: Tick) -> Result<Generation, EngineError> {
        if self.closed {
            return Err(EngineError::Closed);
        }
        let generation = self.bump(owner)?;
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
        self.bump(owner)?;
        if let Some(slot) = self.owners.get_mut(&owner) {
            slot.armed = false;
        }
        self.compact_if_stale();
        Ok(())
    }

    /// Refuse new owners and new armings. Due hints are dropped, not delivered.
    pub fn close(&mut self) {
        self.closed = true;
        self.heap.clear();
        self.pending.clear();
        for owner in self.owners.values_mut() {
            owner.armed = false;
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

    /// Hand back every live hint that is due. Stale hints are discarded only at the front.
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
            if owner.generation != hint.generation {
                continue;
            }
            owner.armed = false;
            let class = owner.class;
            let wake_delay = now.saturating_since(hint.when);
            let totals = &mut self.by_class[class.index()];
            totals.fires = totals.fires.saturating_add(1);
            totals.wake_delay = totals.wake_delay.saturating_add(wake_delay);
            self.pending.insert(
                (hint.owner, hint.generation),
                PendingHome {
                    class,
                    fired_at: now,
                },
            );
            due.push(Wake {
                owner: hint.owner,
                class,
                generation: Generation(hint.generation),
                deadline: hint.when,
                fired_at: now,
            });
        }
        due
    }

    /// The owner's home has polled this generation.
    pub fn note_home(
        &mut self,
        owner: OwnerId,
        generation: Generation,
        polled_at: Tick,
    ) -> Result<(), EngineError> {
        let pending = self
            .pending
            .remove(&(owner, generation.get()))
            .ok_or(EngineError::NoSuchWake)?;
        if polled_at < pending.fired_at {
            self.pending.insert((owner, generation.get()), pending);
            return Err(EngineError::HomeBeforeFire);
        }
        let totals = &mut self.by_class[pending.class.index()];
        totals.home_reports = totals.home_reports.saturating_add(1);
        totals.home_delay = totals
            .home_delay
            .saturating_add(polled_at.saturating_since(pending.fired_at));
        Ok(())
    }

    pub fn lateness(&self, class: OwnerClass) -> ClassLateness {
        self.by_class[class.index()]
    }

    /// Wakes handed out whose home has not reported yet.
    pub fn pending_homes(&self) -> usize {
        self.pending.len()
    }

    fn bump(&mut self, owner: OwnerId) -> Result<u64, EngineError> {
        let slot = self
            .owners
            .get_mut(&owner)
            .ok_or(EngineError::UnknownOwner)?;
        slot.generation = slot.generation.saturating_add(1);
        slot.armed = true;
        Ok(slot.generation)
    }

    fn discard_stale_front(&mut self) {
        while let Some(Reverse(hint)) = self.heap.peek().copied() {
            if self.owners.get(&hint.owner).map(|owner| owner.generation) == Some(hint.generation) {
                break;
            }
            self.heap.pop();
        }
    }

    /// Rebuild when stale hints outnumber the ones that can still fire.
    fn compact_if_stale(&mut self) {
        let live = self.owners.values().filter(|owner| owner.armed).count();
        if self.heap.len() <= live.saturating_mul(2) {
            return;
        }
        let mut keep = Vec::with_capacity(live);
        while let Some(Reverse(hint)) = self.heap.pop() {
            if self.owners.get(&hint.owner).map(|owner| owner.generation) == Some(hint.generation) {
                keep.push(Reverse(hint));
            }
        }
        self.heap = keep.into();
    }
}

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
        assert_eq!(engine.lateness(OwnerClass::Housekeeping).wake_delay, 2);
        assert_eq!(engine.lateness(OwnerClass::Housekeeping).fires, 1);
    }

    #[test]
    fn a_later_rearm_drops_the_earlier_hint() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(5)).unwrap();
        engine.arm(id, Tick::new(9)).unwrap();
        engine.clock_mut().set(Tick::new(5));
        assert!(engine.poll().is_empty());
        assert_eq!(engine.next_deadline(), Some(Tick::new(9)));
        engine.clock_mut().set(Tick::new(9));
        assert_eq!(engine.poll()[0].deadline, Tick::new(9));
    }

    #[test]
    fn rearming_earlier_fires_at_the_new_time() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(9)).unwrap();
        engine.arm(id, Tick::new(4)).unwrap();
        assert_eq!(engine.next_deadline(), Some(Tick::new(4)));
        engine.clock_mut().set(Tick::new(4));
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].deadline, Tick::new(4));
    }

    #[test]
    fn clear_removes_the_deadline() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(5)).unwrap();
        engine.clear(id).unwrap();
        assert_eq!(engine.next_deadline(), None);
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
    }

    #[test]
    fn next_deadline_skips_a_stale_hint() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(3)).unwrap();
        engine.arm(id, Tick::new(8)).unwrap();
        assert_eq!(engine.next_deadline(), Some(Tick::new(8)));
    }

    #[test]
    fn deregister_drops_the_owner() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(4)).unwrap();
        engine.deregister(id).unwrap();
        assert_eq!(engine.next_deadline(), None);
        engine.clock_mut().set(Tick::new(4));
        assert!(engine.poll().is_empty());
        assert_eq!(
            engine.arm(id, Tick::new(5)).unwrap_err(),
            EngineError::UnknownOwner
        );
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
    }

    #[test]
    fn rearming_compacts_stale_hints() {
        let mut engine = engine_at(0);
        let id = owner(&mut engine);
        for n in 1..=8 {
            engine.arm(id, Tick::new(n)).unwrap();
        }
        assert!(engine.heap.len() <= 2);
        assert_eq!(engine.next_deadline(), Some(Tick::new(8)));
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
    }

    #[test]
    fn an_unknown_owner_is_refused() {
        let mut engine = engine_at(0);
        let err = engine.arm(OwnerId(99), Tick::new(1)).unwrap_err();
        assert_eq!(err, EngineError::UnknownOwner);
    }
}

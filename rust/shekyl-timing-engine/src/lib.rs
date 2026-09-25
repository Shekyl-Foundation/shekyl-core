// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The timing-engine core from `P2P_TIMING_ENGINE.md`.
//!
//! An owner lives somewhere else and polls itself there. This crate stores
//! one wake hint per arming, ordered by time, and hands back the hints that
//! are due. A newer arming drops the older one by generation, without a scan.
//! The clock is passed in. Tests use [`ManualClock`].

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

/// One owner. Minted by [`Engine::register`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerId(u64);

/// One arming. A later arming of the same owner makes the earlier one stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

/// A due hint, for the caller to deliver to the owner's home.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wake {
    pub owner: OwnerId,
    pub generation: Generation,
    pub deadline: Tick,
    pub fired_at: Tick,
}

/// How late a wake was, in the clock's ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lateness {
    pub owner: OwnerId,
    pub generation: Generation,
    pub deadline: Tick,
    pub fired_at: Tick,
    /// `fired_at` minus the deadline. Zero when the wake was not late.
    pub wake_delay: u64,
    /// Set when the owner's home reports that it polled.
    pub home_delay: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    UnknownOwner,
    /// `polled_at` is before the wake was handed out.
    HomeBeforeFire,
    /// No handed-out wake matches this owner and fire time.
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

/// Wake hints. The clock is owned here so a test clock cannot be a feature flag.
pub struct Engine<C: Clock> {
    clock: C,
    next_id: u64,
    current: HashMap<OwnerId, u64>,
    heap: BinaryHeap<Reverse<Hint>>,
    samples: Vec<Lateness>,
}

impl<C: Clock> Engine<C> {
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            next_id: 1,
            current: HashMap::new(),
            heap: BinaryHeap::new(),
            samples: Vec::new(),
        }
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    pub fn register(&mut self) -> OwnerId {
        let id = OwnerId(self.next_id);
        self.next_id += 1;
        self.current.insert(id, 0);
        id
    }

    /// Replace this owner's hint. Returns the generation that will be delivered.
    ///
    /// The caller does this only when the owner's earliest deadline changed.
    pub fn arm(&mut self, owner: OwnerId, deadline: Tick) -> Result<Generation, EngineError> {
        let generation = self.bump(owner)?;
        self.heap.push(Reverse(Hint {
            when: deadline,
            owner,
            generation,
        }));
        Ok(Generation(generation))
    }

    /// Drop this owner's hint. A later pop of an older arming is ignored.
    pub fn clear(&mut self, owner: OwnerId) -> Result<(), EngineError> {
        self.bump(owner)?;
        Ok(())
    }

    /// Hand back every hint that is due at the clock's current time.
    ///
    /// Stale generations are discarded here, and only when they reach the
    /// front. Owners that are not due are not visited.
    pub fn poll(&mut self) -> Vec<Wake> {
        let now = self.clock.now();
        let mut due = Vec::new();
        while let Some(Reverse(hint)) = self.heap.peek().copied() {
            if hint.when > now {
                break;
            }
            self.heap.pop();
            if self.current.get(&hint.owner).copied() != Some(hint.generation) {
                continue;
            }
            let wake_delay = now.saturating_since(hint.when);
            self.samples.push(Lateness {
                owner: hint.owner,
                generation: Generation(hint.generation),
                deadline: hint.when,
                fired_at: now,
                wake_delay,
                home_delay: None,
            });
            due.push(Wake {
                owner: hint.owner,
                generation: Generation(hint.generation),
                deadline: hint.when,
                fired_at: now,
            });
        }
        due
    }

    /// The owner's home has polled. `home_delay` is `polled_at` minus `fired_at`.
    pub fn note_home(
        &mut self,
        owner: OwnerId,
        fired_at: Tick,
        polled_at: Tick,
    ) -> Result<(), EngineError> {
        if polled_at < fired_at {
            return Err(EngineError::HomeBeforeFire);
        }
        let sample = self
            .samples
            .iter_mut()
            .rev()
            .find(|sample| {
                sample.owner == owner && sample.fired_at == fired_at && sample.home_delay.is_none()
            })
            .ok_or(EngineError::NoSuchWake)?;
        sample.home_delay = Some(polled_at.saturating_since(fired_at));
        Ok(())
    }

    pub fn lateness(&self) -> &[Lateness] {
        &self.samples
    }

    fn bump(&mut self, owner: OwnerId) -> Result<u64, EngineError> {
        let slot = self
            .current
            .get_mut(&owner)
            .ok_or(EngineError::UnknownOwner)?;
        *slot += 1;
        Ok(*slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_at(now: u64) -> Engine<ManualClock> {
        Engine::new(ManualClock::new(Tick::new(now)))
    }

    #[test]
    fn a_future_hint_is_not_due() {
        let mut engine = engine_at(10);
        let owner = engine.register();
        engine.arm(owner, Tick::new(11)).unwrap();
        assert!(engine.poll().is_empty());
    }

    #[test]
    fn a_due_hint_is_handed_back_with_lateness() {
        let mut engine = engine_at(10);
        let owner = engine.register();
        engine.arm(owner, Tick::new(8)).unwrap();
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].owner, owner);
        assert_eq!(wakes[0].deadline, Tick::new(8));
        assert_eq!(wakes[0].fired_at, Tick::new(10));
        assert_eq!(engine.lateness()[0].wake_delay, 2);
    }

    #[test]
    fn a_newer_arming_drops_the_older_one() {
        let mut engine = engine_at(0);
        let owner = engine.register();
        engine.arm(owner, Tick::new(5)).unwrap();
        engine.arm(owner, Tick::new(9)).unwrap();
        engine.clock_mut().set(Tick::new(5));
        assert!(engine.poll().is_empty());
        engine.clock_mut().set(Tick::new(9));
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].deadline, Tick::new(9));
    }

    #[test]
    fn only_the_earliest_owner_fires() {
        let mut engine = engine_at(0);
        let mut ids = Vec::new();
        for i in 0..32 {
            let id = engine.register();
            engine.arm(id, Tick::new(100 + i)).unwrap();
            ids.push(id);
        }
        engine.clock_mut().set(Tick::new(100));
        let wakes = engine.poll();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].owner, ids[0]);
        assert_eq!(engine.poll().len(), 0);
    }

    #[test]
    fn home_delay_is_separate_from_wake_delay() {
        let mut engine = engine_at(10);
        let owner = engine.register();
        engine.arm(owner, Tick::new(10)).unwrap();
        let wake = engine.poll()[0];
        engine
            .note_home(owner, wake.fired_at, Tick::new(14))
            .unwrap();
        assert_eq!(engine.lateness()[0].wake_delay, 0);
        assert_eq!(engine.lateness()[0].home_delay, Some(4));
    }

    #[test]
    fn an_unknown_owner_is_refused() {
        let mut engine = engine_at(0);
        let err = engine.arm(OwnerId(99), Tick::new(1)).unwrap_err();
        assert_eq!(err, EngineError::UnknownOwner);
    }
}

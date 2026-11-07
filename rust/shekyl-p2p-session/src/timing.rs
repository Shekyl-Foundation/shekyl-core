// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A session's deadlines on its one timing-engine owner (brief §7.6).
//!
//! Each session registers one owner under [`OwnerClass::TimedSync`] and
//! arms it for the earliest of its live deadlines. A wake is read against
//! the clock, not trusted: the session asks which deadlines are due at the
//! moment it woke, acts on each, and re-arms. A wake for a deadline that
//! was cleared meanwhile is a wake that finds nothing due.

use std::time::Duration;

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_timing_engine::{Clock, OwnerHandle, Tick};

pub use shekyl_timing_engine::OwnerClass;

/// How long an inbound session may sit in `Handshaking` before it is
/// closed; the connector profile's `handshake_within`, in the layer's
/// [`crate::SessionConfig`].
///
/// How long a request may wait for its response (brief §7.6): the Levin
/// handler's `LEVIN_DEFAULT_TIMEOUT_PRECONDITION`, kept.
pub const INVOKE_TIMEOUT: Duration = Duration::from_secs(120);

/// The timed-sync draw's floor (brief §7.6, Assumption for Ruling B):
/// `TIMED_SYNC_MIN + U(0, TIMED_SYNC_JITTER)` has the mean PWD-B2 fixed,
/// the inherited 60 s handshake interval.
pub const TIMED_SYNC_MIN: Duration = Duration::from_secs(45);

/// The timed-sync draw's uniform width (brief §7.6).
pub const TIMED_SYNC_JITTER: Duration = Duration::from_secs(30);

/// The intervals one session layer runs its sessions under. The defaults
/// are the brief's; a test narrows them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intervals {
    /// The invoke deadline, armed at each request this node sends.
    pub invoke_timeout: Duration,
    /// The timed-sync draw's floor.
    pub timed_sync_min: Duration,
    /// The timed-sync draw's width; `0` is a fixed interval.
    pub timed_sync_jitter: Duration,
}

impl Default for Intervals {
    fn default() -> Self {
        Self {
            invoke_timeout: INVOKE_TIMEOUT,
            timed_sync_min: TIMED_SYNC_MIN,
            timed_sync_jitter: TIMED_SYNC_JITTER,
        }
    }
}

impl Intervals {
    /// One timed-sync draw: `min + U(0, jitter)` in ticks, `0` a valid
    /// draw when `min` is zero (PWD-B2).
    pub(crate) fn draw_timed_sync<R: RelayRng + ?Sized>(&self, rng: &mut R) -> Tick {
        let jitter = bounded_uniform(rng, ticks(self.timed_sync_jitter).get());
        Tick::new(ticks(self.timed_sync_min).get().saturating_add(jitter))
    }
}

/// `duration` as the engine's tick, saturating past `u64::MAX` ns.
pub(crate) fn ticks(duration: Duration) -> Tick {
    Tick::new(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
}

/// `now + span`, saturating.
pub(crate) fn after(now: Tick, span: Tick) -> Tick {
    Tick::new(now.get().saturating_add(span.get()))
}

/// Which deadline a wake found due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Due {
    /// An inbound handshake did not complete in time.
    Handshake,
    /// A request's response did not arrive in time.
    Invoke,
    /// This session's own timed sync is to be sent.
    TimedSync,
}

/// The three deadlines one session may hold, and the owner they share.
pub(crate) struct Deadlines<C: Clock> {
    owner: OwnerHandle<C>,
    handshake: Option<Tick>,
    invoke: Option<Tick>,
    timed_sync: Option<Tick>,
}

impl<C: Clock> Deadlines<C> {
    pub(crate) const fn new(owner: OwnerHandle<C>) -> Self {
        Self {
            owner,
            handshake: None,
            invoke: None,
            timed_sync: None,
        }
    }

    pub(crate) const fn owner(&self) -> &OwnerHandle<C> {
        &self.owner
    }

    pub(crate) fn now(&self) -> Tick {
        self.owner.clock().now()
    }

    /// Whether a request is outstanding.
    pub(crate) const fn invoke_pending(&self) -> bool {
        self.invoke.is_some()
    }

    pub(crate) fn set_handshake(&mut self, at: Tick) {
        self.handshake = Some(at);
        self.rearm();
    }

    pub(crate) fn clear_handshake(&mut self) {
        self.handshake = None;
        self.rearm();
    }

    pub(crate) fn set_invoke(&mut self, at: Tick) {
        self.invoke = Some(at);
        self.rearm();
    }

    pub(crate) fn clear_invoke(&mut self) {
        self.invoke = None;
        self.rearm();
    }

    pub(crate) fn set_timed_sync(&mut self, at: Tick) {
        self.timed_sync = Some(at);
        self.rearm();
    }

    /// The deadlines at or before `now`, each taken out of the table as
    /// it is reported. The caller acts on each and sets what follows.
    pub(crate) fn due(&mut self, now: Tick) -> Vec<Due> {
        let mut due = Vec::new();
        if self.handshake.is_some_and(|at| at.get() <= now.get()) {
            self.handshake = None;
            due.push(Due::Handshake);
        }
        if self.invoke.is_some_and(|at| at.get() <= now.get()) {
            self.invoke = None;
            due.push(Due::Invoke);
        }
        if self.timed_sync.is_some_and(|at| at.get() <= now.get()) {
            self.timed_sync = None;
            due.push(Due::TimedSync);
        }
        due
    }

    /// The earliest live deadline, for the tests.
    pub(crate) fn earliest(&self) -> Option<Tick> {
        [self.handshake, self.invoke, self.timed_sync]
            .into_iter()
            .flatten()
            .min_by_key(|at| at.get())
    }

    /// Clear the owner and arm it for the earliest live deadline. The
    /// owner accepts only an earlier deadline than the one it holds, so a
    /// deadline that moved later is armed by clearing first. A closed or
    /// deregistered engine is the daemon stopping: the session then ends
    /// by its stream or its stop, not by a wake.
    fn rearm(&self) {
        ignore(self.owner.clear());
        if let Some(at) = self.earliest() {
            ignore(self.owner.arm(at));
        }
    }
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_engine_closing) = result {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second, as the tick's unit.
    const fn seconds(n: u64) -> Tick {
        Tick::new(n * 1_000_000_000)
    }
    use shekyl_draw_rng::SplitMix64;

    #[test]
    fn the_defaults_are_the_briefs() {
        let intervals = Intervals::default();
        assert_eq!(intervals.invoke_timeout, Duration::from_secs(120));
        assert_eq!(intervals.timed_sync_min, Duration::from_secs(45));
        assert_eq!(intervals.timed_sync_jitter, Duration::from_secs(30));
    }

    #[test]
    fn the_timed_sync_draw_is_min_plus_a_bounded_jitter_with_the_pwd_b2_mean() {
        let intervals = Intervals::default();
        let mut rng = SplitMix64::new(7);
        let mut sum = 0u128;
        let n = 20_000u32;
        for _ in 0..n {
            let draw = intervals.draw_timed_sync(&mut rng);
            assert!(draw.get() >= seconds(45).get(), "below the floor");
            assert!(draw.get() <= seconds(75).get(), "above min + jitter");
            sum += u128::from(draw.get());
        }
        let mean = sum / u128::from(n);
        let target = u128::from(seconds(60).get());
        let tolerance = u128::from(seconds(1).get());
        assert!(
            mean.abs_diff(target) < tolerance,
            "mean {mean} is not within a second of 60 s"
        );
    }

    #[test]
    fn a_zero_min_and_zero_jitter_draw_zero() {
        let intervals = Intervals {
            invoke_timeout: Duration::ZERO,
            timed_sync_min: Duration::ZERO,
            timed_sync_jitter: Duration::ZERO,
        };
        let mut rng = SplitMix64::new(1);
        assert_eq!(intervals.draw_timed_sync(&mut rng), Tick::new(0));
    }
}

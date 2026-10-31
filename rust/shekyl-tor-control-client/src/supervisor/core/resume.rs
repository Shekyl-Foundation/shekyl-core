// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Windows count awake time on every platform (`TOR_SUPERVISOR.md` §5,
//! "Resumed from suspend"; Rick, 2026-10-30).
//!
//! Rust's `Instant` stops during a sleep on Linux and macOS and counts
//! through it on Windows (`TSR-M8`). On Windows every window armed before a
//! sleep had silently included it at wake, and two misfired: a stall window
//! held across the sleep was already past its bound, and a probe in flight
//! had missed its own. The core sees a resume once: some deadline is always
//! armed while Tor is live, and a deadline found later than
//! `Policy::resumed_after` (`control::RESUMED_AFTER`) means the process could
//! not run, so the machine slept. It is checked at every input and every
//! deadline, before either is judged, so a reply or an event that arrives
//! first after the wake is not judged against windows that include the
//! sleep. The reply bound is the control layer's (`control::ask_timed`) and
//! follows the same rule there.
//!
//! On a resume every window starts again from the wake: the bootstrap's
//! stall window and the stranded check's byte mark, the probe's bound, the
//! quiet stretch, and an open round's waits. The sample and liveness
//! cadences re-arm from the wake, so nothing that came due in the sleep
//! fires, and one sample is asked at once: the §5 row's "re-evaluate now".
//! A respawn backoff and a repeated announcement are left as they are: a
//! pin check for an absent Tor and a line that repeats the current state
//! are what the wake should do anyway.
//!
//! On Linux and macOS the clock stopped, no deadline is late, and nothing
//! here runs: the windows resumed where they stood, and none fires in a
//! burst on either.

use super::{duration_ns, Action, Core, Phase};

impl Core {
    /// Restart the windows when a deadline is found late enough to mean the
    /// machine slept. The returned actions come before the input's own.
    pub(super) fn resume_if_slept(&mut self, now: u64) -> Vec<Action> {
        let Some(due) = self.deadline() else {
            return Vec::new();
        };
        let late = now.saturating_sub(due);
        if late <= duration_ns(self.policy.resumed_after) {
            return Vec::new();
        }
        if self.sample_at.is_some() {
            self.arm_sample(now);
        }
        if self.alive_at.is_some() {
            self.arm_alive(now);
        }
        self.progress.resumed(now);
        self.jump.resumed(now);
        self.dials.restart(now);
        self.probe_resumed(now);
        let mut actions = vec![Action::Resumed {
            late_by: std::time::Duration::from_nanos(late),
        }];
        if matches!(
            self.phase,
            Phase::Bootstrapping { .. } | Phase::Running { .. }
        ) {
            actions.push(Action::Sample);
        }
        actions
    }
}

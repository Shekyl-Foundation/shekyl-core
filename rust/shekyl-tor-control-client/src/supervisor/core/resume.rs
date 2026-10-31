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
//! had missed its own.
//!
//! The core does not decide that the machine slept. A deadline left in the
//! past while the driver was awaiting Tor is ordinary: a control ask may
//! take the whole reply bound, and the drive loop does not poll its other
//! deadlines until that ask returns. The driver says so, with
//! [`Input::Resumed`], only when a timer it was waiting on fired more than
//! [`crate::control::RESUMED_AFTER`] late ([`crate::control::resume_lateness`]):
//! the select wake, or the reply bound ([`crate::control::ask_timed`]). It
//! folds that input before the reply the slept ask produced, so the reply
//! is judged on windows that start at the wake.
//!
//! On a resume every window starts again from the wake: the bootstrap's
//! stall window and the stranded check's byte mark, the probe's bound, the
//! quiet stretch, and an open round's waits. The sample and liveness
//! cadences re-arm from the wake, so nothing that came due in the sleep
//! fires, and one sample is asked at once: the §5 row's "re-evaluate now".
//! A respawn backoff and a repeated announcement are left as they are: a
//! pin check for an absent Tor and a line that repeats the current state
//! are what the wake should do anyway.

use std::time::Duration;

use super::{Action, Core, Phase};

impl Core {
    /// The machine slept. Restart the windows from `now`. `late_by` is how
    /// late the waited timer was, and it is said once.
    pub(super) fn resumed(&mut self, now: u64, late_by: Duration) -> Vec<Action> {
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
        let mut actions = vec![Action::Resumed { late_by }];
        if matches!(
            self.phase,
            Phase::Bootstrapping { .. } | Phase::Running { .. }
        ) {
            actions.push(Action::Sample);
        }
        actions
    }
}

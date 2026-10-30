// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A bootstrap stranded by a clock jump (`TOR_SUPERVISOR.md` §4.4; the VM
//! clock run of 2026-10-30; Rick, 2026-10-30).
//!
//! With the clock three days ahead Tor could not bootstrap. When the clock
//! was set back, Tor reported the jump, moved one percent, and then sat with
//! no connection for 25 minutes: its retries had been scheduled on the clock
//! that was wrong. A respawn into the kept directory bootstrapped in 7 s.
//!
//! A slow bootstrap is not a fault (Rick, 2026-10-19), and this rule keeps
//! that: it respawns only when Tor itself reported `CLOCK_JUMPED` during
//! this bootstrap, and since the jump both the percent and `traffic/read`
//! have stood still for `Policy::jump_stall_after`. A slow directory mirror
//! always had bytes arriving. Both conditions are Tor's statements.
//!
//! The jump is held for the rest of the bootstrap, not cleared at the next
//! percent: in the stranded run Tor moved from 14 % to 15 % after the jump
//! and then stopped.

use super::super::posture::Cause;
use super::{duration_ns, Action, Core, Phase};

/// The bootstrap's clock-jump evidence and `traffic/read`'s last movement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct JumpWatch {
    /// When Tor reported `CLOCK_JUMPED` during this bootstrap.
    jumped_at: Option<u64>,
    /// The last `traffic/read`, and when it last grew.
    read: Option<u64>,
    read_moved_at: u64,
}

impl JumpWatch {
    pub(super) const fn new(now: u64) -> Self {
        Self {
            jumped_at: None,
            read: None,
            read_moved_at: now,
        }
    }

    /// Tor reported `CLOCK_JUMPED`.
    pub(super) fn jumped(&mut self, now: u64) {
        self.jumped_at = Some(now);
    }

    /// A sample's `traffic/read`. A count that grew, or the first one, moves
    /// the mark; one that went backwards starts the count again.
    pub(super) fn note_read(&mut self, read: Option<u64>, now: u64) {
        let Some(bytes) = read else {
            return;
        };
        if self.read.is_none_or(|before| bytes != before) {
            self.read_moved_at = now;
        }
        self.read = Some(bytes);
    }
}

impl Core {
    /// The stranded-bootstrap check, at each sample and live deadline while
    /// bootstrapping. A process fault (respawn into the kept directory) when
    /// a reported jump is followed by `jump_stall_after` with neither the
    /// percent nor the bytes moving.
    pub(super) fn stranded_after_jump(&mut self, now: u64) -> Option<Vec<Action>> {
        if !matches!(self.phase, Phase::Bootstrapping { .. }) {
            return None;
        }
        let jumped_at = self.jump.jumped_at?;
        let bound = duration_ns(self.policy.jump_stall_after);
        let percent_still = now.saturating_sub(jumped_at.max(self.progress.moved_at()));
        let bytes_still = now.saturating_sub(jumped_at.max(self.jump.read_moved_at));
        (percent_still >= bound && bytes_still >= bound)
            .then(|| self.process_fault(now, Cause::StrandedAfterClockJump, false))
    }
}

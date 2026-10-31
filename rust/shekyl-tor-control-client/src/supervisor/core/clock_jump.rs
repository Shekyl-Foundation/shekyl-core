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
//! this bootstrap, and since the jump both the percent and a known
//! `traffic/read` have stood still for `Policy::jump_stall_after`. A slow
//! directory mirror always had bytes arriving. Both conditions are Tor's
//! statements, and a count Tor did not give is no statement.
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
    /// The last `traffic/read`, `None` while unknown, and when it last
    /// changed or became unknown.
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
    /// the mark; one that went backwards starts the count again. A reply
    /// without a count is unknown, never zero (`control/traffic.rs`): bytes
    /// that cannot be read are not bytes that stood still, so it moves the
    /// mark too, and the next known count starts the bound again.
    pub(super) fn note_read(&mut self, read: Option<u64>, now: u64) {
        if read.is_none() || read != self.read {
            self.read_moved_at = now;
        }
        self.read = read;
    }
}

impl Core {
    /// The stranded-bootstrap check, at each sample while bootstrapping and
    /// nowhere else: the sample is what reads the percent and the bytes, so
    /// the check never judges marks older than the reply it just folded.
    /// Samples run every `sample_every` through a bootstrap; a sample that
    /// never returns is the reply bound's process fault. A process fault
    /// (respawn into the kept directory) when a reported jump is followed by
    /// `jump_stall_after` with neither the percent nor a known byte count
    /// moving.
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

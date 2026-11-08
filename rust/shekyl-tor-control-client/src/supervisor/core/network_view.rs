// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tor's sampled view of its network (`TOR_SUPERVISOR.md` §4.2).
//!
//! An event overwrites whatever cause is standing. A sample does not: it
//! names a blocked link only while Running, and only when nothing else is
//! named, and it clears only the causes about reaching the network.

use super::super::posture::Cause;
use super::announce::Cadence;
use super::{Action, Core};
use crate::control::NetworkView;

impl Core {
    /// Whether a sample asks for the network view. Only while Running:
    /// during a bootstrap no circuit is built yet, and that is not a
    /// statement about the network.
    #[must_use]
    pub fn reads_network(&self) -> bool {
        matches!(self.phase, super::Phase::Running { .. })
    }

    /// Fold one sampled view. Unknown says nothing. A negative answer names
    /// the blocked link when no cause is set. Both affirmative answers clear
    /// the network causes.
    pub(super) fn network_view(&mut self, now: u64, view: NetworkView) -> Vec<Action> {
        if !self.reads_network() {
            return Vec::new();
        }
        if view.reports_blocked() && self.cause == Cause::None {
            return self.external(now, Cause::ExternalBlocked);
        }
        if view.reports_blocked() {
            return Vec::new();
        }
        if view.reports_reachable() {
            return self.external_cleared(now);
        }
        Vec::new()
    }

    /// Name an external cause. The process stays up.
    pub(super) fn external(&mut self, now: u64, cause: Cause) -> Vec<Action> {
        self.set_cause(cause);
        self.say(now, Cadence::Due)
    }

    /// Tor says it reaches its network. Its judgment governs the causes
    /// about reaching the network (`TSR-Q14`): a blocked link and an
    /// unreachable directory clear. A clock report and the open-file limit
    /// are other kinds, each with its own evidence. The recovery is said at
    /// once.
    pub(super) fn external_cleared(&mut self, now: u64) -> Vec<Action> {
        if !matches!(
            self.cause,
            Cause::ExternalBlocked | Cause::DirectoryUnreachable
        ) {
            return Vec::new();
        }
        self.set_cause(Cause::None);
        self.say(now, Cadence::Now)
    }
}

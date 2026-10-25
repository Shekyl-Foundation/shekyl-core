// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor dials show (`TOR_SUPERVISOR.md` §4.2, "every Tor
//! dial's outcome"). Display only: never a cause, never a respawn
//! (`TSR-Q14`, Tor does Tor).
//!
//! When Tor says nothing about its network and yet no Tor connection is
//! open and none opens, the posture line says exactly that, a neutral fact
//! with no fix: not "this machine cannot reach the Tor network", which Tor
//! alone may say, and which a planted onion could otherwise make the node
//! say.

use std::time::Duration;

use super::Policy;

/// The dialer's tally of this node's Tor dials. The supervisor never sees
/// an address or a reply code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialTally {
    /// Tor dials whose stream opened. Only grows.
    pub opened: u64,
    /// Tor dials that ended without a stream since the last one opened.
    pub unopened: u32,
    /// Tor sessions this node holds now.
    pub held: u32,
}

/// The supervisor's reading of the tally.
#[derive(Debug)]
pub(super) struct Dials {
    last: DialTally,
    /// When a Tor stream last opened, or when this Tor reached Running.
    opened_at: u64,
    /// The quiet stretch at the last evaluation, when the line stands.
    line: Option<Duration>,
}

impl Dials {
    pub(super) fn new(now: u64) -> Self {
        Self {
            last: DialTally::default(),
            opened_at: now,
            line: None,
        }
    }

    /// Fold a tally. An opened stream starts the stretch again.
    pub(super) fn fold(&mut self, tally: DialTally, now: u64) {
        if tally.opened > self.last.opened {
            self.opened_at = now;
        }
        self.last = tally;
    }

    /// A Tor reached Running: its stretch starts now.
    pub(super) fn restart(&mut self, now: u64) {
        self.opened_at = now;
        self.line = None;
    }

    /// Re-read the stretch at `now`. `true` when the line has just begun to
    /// stand, which is the one time it is said.
    pub(super) fn evaluate(&mut self, now: u64, policy: &Policy) -> bool {
        let quiet = Duration::from_nanos(now.saturating_sub(self.opened_at));
        let stands = self.last.held == 0 && self.last.unopened > 0 && quiet >= policy.quiet_after;
        let began = stands && self.line.is_none();
        self.line = stands.then_some(quiet);
        began
    }

    /// How long no Tor connection has been open or opened, while that holds.
    pub(super) fn line(&self) -> Option<Duration> {
        self.line
    }
}

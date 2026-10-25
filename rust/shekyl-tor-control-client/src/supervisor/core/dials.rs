// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor dials say about the link (`TOR_SUPERVISOR.md`
//! §4.2, "every Tor dial's outcome").
//!
//! The dialer classes each dial by the SOCKS reply table and counts; this
//! module reads its tally. A run of link failures, or timeouts across
//! distinct destinations, with no opened stream between them, is the link
//! down: an External cause, never a respawn. A process fault comes only
//! from the process and the control connection. One opened stream ends the
//! run.

use super::Policy;

/// The dialer's tally of this node's Tor dials. The supervisor never sees
/// an address or a reply code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialTally {
    /// Tor dials whose stream opened. Only grows.
    pub opened: u64,
    /// Link failures since the last opened stream: SOCKS replies `0x01`,
    /// `0x02`, `0x03`, `0x06`, or this node's SOCKS port refusing.
    pub link_failures: u32,
    /// Distinct destinations that timed out since the last opened stream.
    pub timed_out_destinations: u32,
}

/// What a new tally means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DialVerdict {
    /// A stream opened since the last tally: the link carries.
    Opened,
    /// The run since the last opened stream reached a threshold.
    Down,
    /// Neither.
    Quiet,
}

/// The supervisor's reading of the tally.
#[derive(Debug)]
pub(super) struct Dials {
    last: DialTally,
    /// Counts already in the tally when the current reading began, at
    /// Running and when Tor says its network is back: a failure from
    /// before is not evidence about the link now.
    floor: (u32, u32),
}

impl Dials {
    pub(super) fn new() -> Self {
        Self {
            last: DialTally::default(),
            floor: (0, 0),
        }
    }

    /// Fold `tally` and judge the run since the last opened stream.
    pub(super) fn fold(&mut self, tally: DialTally, policy: &Policy) -> DialVerdict {
        let previous = std::mem::replace(&mut self.last, tally);
        if tally.opened > previous.opened {
            self.floor = (0, 0);
            return DialVerdict::Opened;
        }
        let links = tally.link_failures.saturating_sub(self.floor.0);
        let timeouts = tally.timed_out_destinations.saturating_sub(self.floor.1);
        if links >= policy.link_down_after || timeouts >= policy.timeouts_down_after {
            DialVerdict::Down
        } else {
            DialVerdict::Quiet
        }
    }

    /// Start a new reading: what the tally holds now is history.
    pub(super) fn rebase(&mut self) {
        self.floor = (self.last.link_failures, self.last.timed_out_destinations);
    }
}

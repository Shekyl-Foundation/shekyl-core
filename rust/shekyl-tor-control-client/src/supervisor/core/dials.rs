// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor dials show (`TOR_SUPERVISOR.md` §4.2, "every Tor
//! dial's outcome"). Display only: never a cause, never a respawn
//! (`TSR-Q14`, Tor does Tor).
//!
//! The posture line reports the dialer judge's last sign that the Tor link
//! worked (`DIALER_OUTAGE_EVIDENCE.md` §6): a stream that opened, or a byte
//! a Tor session received. When none has come for Tor's window plus the
//! judge's bracket, and a Tor dial has failed since, the line says what the
//! judge observed, a neutral fact with no fix: not "this machine cannot
//! reach the Tor network", which Tor alone may say, and which a planted
//! onion could otherwise make the node say.

use std::time::Duration;

use super::super::posture::{Cause, TorQuiet};
use super::{Action, Core, Phase, Policy};

/// The dialer's tally of this node's Tor dials. The supervisor never sees
/// an address or a reply code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialTally {
    /// Tor dials whose stream opened. Only grows.
    pub opened: u64,
    /// Tor dials that ended without a stream since the last one opened.
    pub unopened: u32,
    /// When the dialer's judge last saw the Tor link work, in nanoseconds on
    /// the process clock the supervisor runs on. `None` until the first.
    pub last_sign_of_life: Option<u64>,
    /// The latest launch among Tor dials that ended without a stream, on
    /// that same clock (`attempt_began`, `DIALER_OUTAGE_EVIDENCE.md` §6.1).
    /// `None` until the first.
    pub failed_attempt_began: Option<u64>,
    /// The Tor addresses the dialer holds at its latest census, white and
    /// gray with the cooling ones. `None` until the first census.
    pub known: Option<u32>,
}

/// The supervisor's reading of the tally.
#[derive(Debug)]
pub(super) struct Dials {
    last: DialTally,
    /// When this Tor reached Running, or the node woke from a sleep.
    running_at: u64,
    /// The line at the last evaluation, when it stands.
    line: Option<TorQuiet>,
}

impl Dials {
    pub(super) fn new(now: u64) -> Self {
        Self {
            last: DialTally::default(),
            running_at: now,
            line: None,
        }
    }

    /// Fold a tally. The cell keeps only the latest one, so it can carry a
    /// failure and a later sign of life together; each is read by its own
    /// instant, never by when the tally arrived. The tally already in the
    /// cell when this supervisor started is folded the same way: its
    /// failures were launched before this supervisor's Tor ran, and the
    /// stretch rule leaves them out on its own.
    pub(super) fn fold(&mut self, tally: DialTally) {
        self.last = tally;
    }

    /// A Tor reached Running, or the node woke: the clock starts now.
    pub(super) fn restart(&mut self, now: u64) {
        self.running_at = now;
        self.line = None;
    }

    /// Re-read the span at `now`. The quiet stretch runs from the judge's
    /// last sign of life or from [`Self::restart`], whichever is later, and
    /// the line stands once it reaches `quiet_after` with a Tor dial that
    /// failed and was launched inside the stretch
    /// (`DIALER_OUTAGE_EVIDENCE.md` §6.1). A dial sent to the Tor before a
    /// respawn, or before a wake, runs out its window inside the stretch
    /// and did not test the link since; only failures are filtered, and a
    /// stream that opens counts through the sign of life whatever its
    /// launch. `true` when the line has just begun to stand, which is the
    /// one time it is said.
    pub(super) fn evaluate(&mut self, now: u64, policy: &Policy) -> bool {
        let since = self
            .last
            .last_sign_of_life
            .map_or(self.running_at, |life| life.max(self.running_at));
        let quiet = Duration::from_nanos(now.saturating_sub(since));
        let failed = self
            .last
            .failed_attempt_began
            .is_some_and(|began| began >= since);
        // What the dialer knows splits the line (Rick, 2026-11-10): with no
        // address held there is nothing to dial, which is not a peer that
        // did not answer.
        let line = if quiet < policy.quiet_after {
            None
        } else if self.last.known == Some(0) {
            Some(TorQuiet::NoPeersKnown)
        } else if failed {
            Some(TorQuiet::Unanswered(quiet))
        } else {
            None
        };
        let kind = |line: &Option<TorQuiet>| line.as_ref().map(std::mem::discriminant);
        let began = line.is_some() && kind(&line) != kind(&self.line);
        self.line = line;
        began
    }

    /// The line, while it stands.
    pub(super) fn line(&self) -> Option<TorQuiet> {
        self.line
    }
}

impl Core {
    /// The dialer's tally moved. Display only (`TSR-Q14`): which reply a
    /// failed onion dial gets is the destination's to choose as much as the
    /// link's, so this never sets a cause. While nothing comes through a
    /// running Tor, the posture line says so once.
    pub(super) fn dial_evidence(&mut self, tally: DialTally, now: u64) -> Vec<Action> {
        self.dials.fold(tally);
        self.quiet_line(now)
    }

    /// Re-read the quiet span. The line is said once, when it begins to
    /// stand, and only while no cause is named.
    pub(super) fn quiet_line(&mut self, now: u64) -> Vec<Action> {
        if !matches!(self.phase, Phase::Running { .. }) {
            return Vec::new();
        }
        if self.dials.evaluate(now, &self.policy) && self.cause == Cause::None {
            vec![Action::SayProgress]
        } else {
            Vec::new()
        }
    }
}

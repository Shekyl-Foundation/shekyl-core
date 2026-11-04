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

use super::super::posture::Cause;
use super::{Action, Core, Phase, Policy};

/// The dialer's tally of this node's Tor dials. The supervisor never sees
/// an address or a reply code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialTally {
    /// Tor dials whose stream opened. Only grows.
    pub opened: u64,
    /// Tor dials that ended without a stream since the last one opened.
    pub unopened: u32,
    /// Tor sessions this node holds now: outbound sessions the dialer kept,
    /// plus inbound sessions on the board.
    pub held: u32,
    /// When the dialer's judge last saw the Tor link work, in nanoseconds on
    /// the process clock the supervisor runs on. `None` until the first.
    pub last_sign_of_life: Option<u64>,
    /// When a Tor dial last ended without a stream, on that same clock.
    /// `None` when the tally does not say: the fold then dates the failure
    /// when the tally arrives.
    pub last_unopened_at: Option<u64>,
}

/// The supervisor's reading of the tally.
#[derive(Debug)]
pub(super) struct Dials {
    last: DialTally,
    /// When this Tor reached Running, or the node woke from a sleep.
    running_at: u64,
    /// When a Tor dial last failed, as folded here.
    failed_at: Option<u64>,
    /// The quiet span at the last evaluation, when the line stands.
    line: Option<Duration>,
}

impl Dials {
    pub(super) fn new(now: u64) -> Self {
        Self {
            last: DialTally::default(),
            running_at: now,
            failed_at: None,
            line: None,
        }
    }

    /// Mark the tally already in the cell when this supervisor started
    /// watching. Its failures are not this Tor's: none is folded.
    pub(super) fn seed(&mut self, tally: DialTally) {
        self.last = tally;
    }

    /// Fold a tally. A dial that ended without a stream, since the last
    /// tally, is a failure dated when the dialer counted it. The watch
    /// keeps only the latest tally, so that tally can also carry a sign of
    /// life from after the failure; dating the failure at arrival would
    /// put it after the byte. A tally that carries no instant is dated
    /// when it arrives.
    pub(super) fn fold(&mut self, tally: DialTally, now: u64) {
        let failed = tally.unopened > self.last.unopened
            || (tally.opened > self.last.opened && tally.unopened > 0);
        if failed {
            self.failed_at = Some(tally.last_unopened_at.unwrap_or(now));
        }
        self.last = tally;
    }

    /// A Tor reached Running, or the node woke: the clock starts now.
    pub(super) fn restart(&mut self, now: u64) {
        self.running_at = now;
        self.line = None;
    }

    /// Re-read the span at `now`. It runs from the judge's last sign of
    /// life or from [`Self::restart`], whichever is later, and the line
    /// stands once it reaches `quiet_after` with a Tor dial failed since
    /// that sign of life. `true` when the line has just begun to stand,
    /// which is the one time it is said.
    pub(super) fn evaluate(&mut self, now: u64, policy: &Policy) -> bool {
        let life = self.last.last_sign_of_life;
        let since = life.map_or(self.running_at, |life| life.max(self.running_at));
        let quiet = Duration::from_nanos(now.saturating_sub(since));
        let failed = self
            .failed_at
            .is_some_and(|failed| life.is_none_or(|life| failed >= life));
        let stands = failed && quiet >= policy.quiet_after;
        let began = stands && self.line.is_none();
        self.line = stands.then_some(quiet);
        began
    }

    /// How long nothing has come through Tor, while the line stands.
    pub(super) fn line(&self) -> Option<Duration> {
        self.line
    }
}

impl Core {
    /// The tally already watched when this supervisor started. It sets what
    /// has been seen and folds no failure.
    pub(super) fn dial_baseline(&mut self, tally: DialTally) -> Vec<Action> {
        self.dials.seed(tally);
        Vec::new()
    }

    /// The dialer's tally moved. Display only (`TSR-Q14`): which reply a
    /// failed onion dial gets is the destination's to choose as much as the
    /// link's, so this never sets a cause. While nothing comes through a
    /// running Tor, the posture line says so once.
    pub(super) fn dial_evidence(&mut self, tally: DialTally, now: u64) -> Vec<Action> {
        self.dials.fold(tally, now);
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

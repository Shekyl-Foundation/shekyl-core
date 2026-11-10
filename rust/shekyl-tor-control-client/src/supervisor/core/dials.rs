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
//! judge's bracket, the line says what the dialer's census holds. An empty
//! census says no peer is known. A non-empty run says peers are known and
//! none has answered, for the time since that run began or since the quiet
//! stretch, whichever is later, and only after a Tor dial launched in that
//! span failed. A census that has not arrived says nothing. The line is a
//! neutral fact with no fix: not "this machine cannot reach the Tor
//! network", which Tor alone may say, and which a planted onion could
//! otherwise make the node say.

use std::time::Duration;

use super::super::posture::{Cause, TorQuiet};
use super::{Action, Core, Phase, Policy};

/// The Tor connector's census, on the supervisor's clock
/// (`DIALER_OUTAGE_EVIDENCE.md` §6). The dialer's census mapped at the
/// daemon: `since` is nanoseconds on the process clock.
///
/// [`Self::Pending`] is no census yet. [`Self::Empty`] holds no address.
/// [`Self::Held`] is a non-empty run opened at `since`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TorCensus {
    /// No wake has censused the Tor connector.
    #[default]
    Pending,
    /// The latest census holds no Tor address.
    Empty,
    /// The latest census holds `seats` Tor addresses. `since` opened this
    /// non-empty run, in nanoseconds on the process clock.
    Held { seats: u32, since: u64 },
}

/// The fact a quiet line states. [`TorQuiet::Unanswered`]'s duration is how
/// long that fact has stood. A longer span of the same fact is not said
/// again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuietFact {
    NoPeersKnown,
    Unanswered,
}

fn quiet_fact(line: TorQuiet) -> QuietFact {
    match line {
        TorQuiet::NoPeersKnown => QuietFact::NoPeersKnown,
        TorQuiet::Unanswered(_) => QuietFact::Unanswered,
    }
}

/// [`TorQuiet::Unanswered`] when a dial launched inside the held span
/// failed and that span has reached `quiet_after`. The span starts at the
/// later of the quiet stretch and the non-empty run.
fn unanswered(
    tally: DialTally,
    now: u64,
    stretch: u64,
    held_since: u64,
    policy: &Policy,
) -> Option<TorQuiet> {
    let from = stretch.max(held_since);
    let span = Duration::from_nanos(now.saturating_sub(from));
    let failed = tally
        .failed_attempt_began
        .is_some_and(|began| began >= from);
    (span >= policy.quiet_after && failed).then_some(TorQuiet::Unanswered(span))
}

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
    /// The Tor connector's latest census. [`TorCensus::Pending`] until the
    /// first.
    pub census: TorCensus,
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

    /// Re-read the span at `now`.
    ///
    /// The quiet stretch runs from the judge's last sign of life or from
    /// [`Self::restart`], whichever is later (`DIALER_OUTAGE_EVIDENCE.md`
    /// §6.1). A dial sent to the Tor before a respawn, or before a wake,
    /// runs out its window inside the stretch and did not test the link
    /// since. Only failures are filtered by launch. A stream that opens
    /// counts through the sign of life whatever its launch.
    ///
    /// The census then picks the line, once the stretch has reached
    /// `quiet_after`:
    ///
    /// - [`TorCensus::Pending`] says nothing. A failed dial is not a census.
    /// - [`TorCensus::Empty`] stands as [`TorQuiet::NoPeersKnown`]. There
    ///   is nothing to dial, so no failure is required.
    /// - [`TorCensus::Held`] stands as [`TorQuiet::Unanswered`] when a Tor
    ///   dial launched at or after `max(stretch start, run start)` has
    ///   failed, and that span has reached `quiet_after`. The spoken
    ///   duration is that span: time peers have been held without an
    ///   answer, not time that passed while the census was empty.
    ///
    /// Returns `true` when the line's fact has just begun or has changed
    /// from the other fact. A longer duration of the same fact is the same
    /// line and is not said again.
    pub(super) fn evaluate(&mut self, now: u64, policy: &Policy) -> bool {
        let stretch = self
            .last
            .last_sign_of_life
            .map_or(self.running_at, |life| life.max(self.running_at));
        let quiet = Duration::from_nanos(now.saturating_sub(stretch));
        let line = if quiet < policy.quiet_after {
            None
        } else {
            match self.last.census {
                TorCensus::Pending => None,
                TorCensus::Empty => Some(TorQuiet::NoPeersKnown),
                TorCensus::Held { since, .. } => unanswered(self.last, now, stretch, since, policy),
            }
        };
        let began = line.map(quiet_fact) != self.line.map(quiet_fact) && line.is_some();
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

    /// Re-read the quiet span. The line is said when its fact begins, and
    /// again when the fact changes, and only while no cause is named.
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

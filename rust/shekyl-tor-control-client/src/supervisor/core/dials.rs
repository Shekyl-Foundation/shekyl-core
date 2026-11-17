// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet line (`TOR_SUPERVISOR.md` §4.2; `DIALER_OUTAGE_EVIDENCE.md`
//! §6, as ruled 2026-11-15): display only, never a cause, never a respawn
//! (`TSR-Q14`).
//!
//! The line stands only when the manager's own onion-path reading is
//! impaired, peers are known, and a Tor dial launched since that reading
//! failed. What the line needs from the dialer, whether peers are known
//! and when a failed dial was launched, is the Tor connector's copy of the
//! dialer's per-connector tally. The line is a neutral fact with no fix:
//! not "this machine cannot reach the Tor network", which Tor alone may
//! say, and which it says through its own cause.

use super::super::posture::{Cause, TorQuiet};
use super::onion_path::{OnionPath, PathReading};
use super::{Action, Core, Phase};

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

/// The Tor connector's copy of the dialer's tally. The supervisor never
/// sees an address or a reply code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialTally {
    /// The latest launch among Tor dials that ended without a stream, in
    /// nanoseconds on the process clock the supervisor runs on
    /// (`attempt_began`, `DIALER_OUTAGE_EVIDENCE.md` §6.1). `None` until
    /// the first.
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

    /// Fold a tally. The cell keeps only the latest one; its failure is
    /// read by its launch, never by when the tally arrived.
    pub(super) fn fold(&mut self, tally: DialTally) {
        self.last = tally;
    }

    /// A Tor reached Running, or the node woke: a reading or a failure from
    /// before it does not stand the line.
    pub(super) fn restart(&mut self, now: u64) {
        self.running_at = now;
        self.line = None;
    }

    /// Re-read the line against the manager's `path` reading.
    ///
    /// It stands as [`TorQuiet::Unreached`] when the reading is impaired and
    /// learned since [`Self::restart`], the census holds peers, and a Tor
    /// dial launched at or after the later of the reading and the census's
    /// run failed (`DIALER_OUTAGE_EVIDENCE.md` §6.1: only failures are
    /// filtered by launch). The line carries the reading's instant.
    ///
    /// Returns `true` when the line has just begun.
    pub(super) fn evaluate(&mut self, path: Option<PathReading>) -> bool {
        let line = path
            .filter(|reading| reading.path == OnionPath::Impaired && reading.at >= self.running_at)
            .and_then(|reading| match self.last.census {
                TorCensus::Held { since, .. } => {
                    let from = reading.at.max(since);
                    self.last
                        .failed_attempt_began
                        .is_some_and(|began| began >= from)
                        .then_some(TorQuiet::Unreached { since: reading.at })
                }
                TorCensus::Pending | TorCensus::Empty => None,
            });
        let began = line.is_some() && self.line.is_none();
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
    /// path's, so this never sets a cause.
    pub(super) fn dial_evidence(&mut self, tally: DialTally) -> Vec<Action> {
        self.dials.fold(tally);
        self.quiet_line()
    }

    /// Re-read the quiet line. It is said when it begins, and only while
    /// no cause is named.
    pub(super) fn quiet_line(&mut self) -> Vec<Action> {
        if !matches!(self.phase, Phase::Running { .. }) {
            return Vec::new();
        }
        if self.dials.evaluate(self.path.latest()) && self.cause == Cause::None {
            vec![Action::SayProgress]
        } else {
            Vec::new()
        }
    }
}

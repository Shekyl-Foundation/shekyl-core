// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether the onion path works: the Tor Manager's one reading
//! (`TOR_SUPERVISOR.md` §4.5a; Rick, 2026-11-15). The dialer's judge asks
//! the Tor connector, and the connector's readings come from here.
//!
//! - **Working**, from: a check in which the probe came back and the
//!   directory check passed; an outbound onion dial that completed; a new
//!   inbound Tor session.
//! - **Impaired**, from: Tor's own statements (it cannot reach its network,
//!   no directory answers); a failed check, which is the two-miss verdict.
//! - **Never** from a failed peer dial, a byte on a held session, or a
//!   session merely held.
//!
//! Asked for a reading after an instant it has no fact for, the manager
//! runs its check if the last one began at least [`CHECK_SPACING`] ago;
//! otherwise the answer waits for the next check or the next fact. One check
//! runs at a time. A fact answers every failure before its own instant, and
//! the open want is the latest failure still unanswered, so a fact between
//! two failures answers the earlier and leaves the later one waiting. A
//! check is judged when it ends, after every failure already waiting, so
//! that result answers all of them. While Tor says it cannot reach its
//! network, the answer is impaired, and no check runs. The probe is not a
//! monitor of each circuit (`TSR-Q14`, restated): when asked, the manager
//! is the best-placed component to say whether the onion path works, and
//! it answers.

use std::time::Duration;

use super::super::posture::Cause;
use super::{duration_ns, Action, Core, Phase, HELD_PROBE_LONGEST, PROBE_LONGEST};

/// The least time between the start of one check and the start of a check
/// run on demand, 15 minutes (Rick, 2026-11-15). **Assumption** (§97,
/// "On-demand check spacing"). Basis: tor 0.4.9.14's own client does not
/// ask one directory for one onion again within 15 minutes
/// (`REND_HID_SERV_DIR_REQUERY_PERIOD`, `src/feature/hs/hs_common.h:263`),
/// and each check asks every directory of its round, so a check run no
/// sooner asks none of them more often than Tor's own client would. Tor
/// imposes no spacing of its own on the check: a fetch that names its
/// directory skips that memory and is not recorded in it
/// (`hs_client_launch_v3_desc_fetch`, `src/feature/hs/hs_client.c:499`), a
/// successful connection clears it (`hs_client.c:384`), and tor never
/// emits `QUERY_RATE_LIMITED`. Each check costs the probe's introduction
/// and rendezvous circuits and one circuit per directory, all through this
/// node's guard. Re-checked at every Tor re-pin.
pub const CHECK_SPACING: Duration = Duration::from_secs(15 * 60);

/// How long one check typically runs, from its schedule to its verdict,
/// 300 s. The first probe is a `HELD_PROBE_LONGEST`: its delay is armed at
/// the schedule, and one round still young when that delay ends holds the
/// launch for up to `ROUND_WAIT`, then the bound. The second probe is a
/// `PROBE_LONGEST`, its delay and its bound, with no hold. A round already
/// open at the schedule overlaps the first delay, and the check is shorter.
/// A round that opens again for the second probe holds that one too; this
/// span does not count it. It is not a hard bound. A directory fetch's
/// answer window runs from Tor's acceptance of it, and fetches wait their
/// turn behind the request queue's replies, so a check can run longer. The
/// wait built on it errs toward excusing: a reading after it is not waited
/// for.
///
/// Not `REPUBLISH_AFTER`. That span is the round's wait and then two
/// unheld probes, measured from the round about to be judged. This one is
/// measured from the schedule, and its `ROUND_WAIT` is the in-check hold.
pub const CHECK_LONGEST: Duration = HELD_PROBE_LONGEST.saturating_add(PROBE_LONGEST);

/// How long the Tor connector declares the judge waits for a reading after
/// a failure, 20 minutes: the spacing plus one check (Rick, 2026-11-15).
/// **Assumption** (§97, "Tor path-reading wait") until the floor device
/// measures it. A failure that arrives just after a check began waits out
/// the spacing, then one check.
pub const READING_WAIT: Duration = CHECK_SPACING.saturating_add(CHECK_LONGEST);

/// What the reading says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnionPath {
    /// The onion path worked.
    Working,
    /// The onion path did not work.
    Impaired,
}

/// The reading: the latest fact, and the instant it was learned, in
/// nanoseconds on the process clock this core runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathReading {
    /// What the latest fact says.
    pub path: OnionPath,
    /// When it was learned.
    pub at: u64,
}

/// The reading's state.
#[derive(Debug, Default)]
pub(super) struct PathState {
    /// The latest fact. `None` until the first.
    latest: Option<PathReading>,
    /// The latest failure a reading is still wanted after. A fact answers
    /// every failure before it, so the want ends only when a fact is after
    /// this instant.
    wanted_after: Option<u64>,
    /// The draw the waiting check will use for its delay.
    draw: Option<u64>,
    /// When the last check began, scheduled or on demand.
    last_check_began: Option<u64>,
    /// A check waits for the spacing to pass, due then.
    due: Option<u64>,
}

impl PathState {
    /// The reading now, for the driver to publish.
    pub(super) const fn latest(&self) -> Option<PathReading> {
        self.latest
    }
}

impl Core {
    /// A fact about the onion path, learned at `at`. A fact older than the
    /// latest one changes nothing. A fact answers every failure before it.
    /// The open want is the latest failure still unanswered, so the want
    /// ends only when this fact is after that failure. A fact between two
    /// waiting failures answers the earlier ones and leaves the later one
    /// waiting.
    pub(super) fn path_fact(&mut self, path: OnionPath, at: u64) -> Vec<Action> {
        if self.path.latest.is_some_and(|latest| latest.at > at) {
            return Vec::new();
        }
        let reading = PathReading { path, at };
        if self.path.latest == Some(reading) {
            return Vec::new();
        }
        self.path.latest = Some(reading);
        if self.path.wanted_after.is_some_and(|after| at > after) {
            self.path.wanted_after = None;
            self.path.draw = None;
            self.path.due = None;
        }
        let mut actions = vec![Action::PathReading(reading)];
        actions.extend(self.quiet_line());
        actions
    }

    /// The connector asks for a reading after `after`, with `draw` for a
    /// check's delay. A fact after it already answers. While Tor says it
    /// cannot reach its network the answer is impaired now, and no check
    /// runs. Otherwise the want waits, and a check starts now if the last
    /// one began at least the spacing ago, or when it has.
    pub(super) fn path_wanted(&mut self, now: u64, after: u64, draw: u64) -> Vec<Action> {
        if self.path.latest.is_some_and(|latest| latest.at > after) {
            return Vec::new();
        }
        if self.tor_says_unreachable() {
            return self.path_fact(OnionPath::Impaired, now);
        }
        // The open want is the latest failure. An earlier one arriving
        // after it is already covered by whatever answers the later one,
        // and it does not replace that failure's draw.
        if self.path.wanted_after.is_none_or(|waiting| after > waiting) {
            self.path.wanted_after = Some(after);
            self.path.draw = Some(draw);
        }
        self.start_wanted_check(now)
    }

    /// Start the check a waiting failure wants, when one may run: none in
    /// hand, and the last begun at least the spacing ago. Whenever a want
    /// waits and no check starts now, the next instant one could is due:
    ///
    /// - **A check in hand** answers the want if it ends with a fact. If it
    ///   ends without one (the probe alone decided, or the check was
    ///   dropped), the want is asked again once the spacing from that
    ///   check's start has passed.
    /// - **Inside the spacing**, at the spacing's end.
    /// - **The check's own gates refuse it** (a stop, or standing down while
    ///   a republish cannot help, §4.5): asked again one check's span later
    ///   ([`CHECK_LONGEST`]), so a check runs once the gates clear. No probe
    ///   was scheduled, so no round held one. The span still includes that
    ///   hold: the want is not asked again sooner than a check that did
    ///   start could have answered. That is not a check, so the spacing
    ///   does not move.
    ///
    /// Nothing is due again at an instant already past, so the deadline
    /// never spins.
    fn start_wanted_check(&mut self, now: u64) -> Vec<Action> {
        let (Some(_), Some(draw)) = (self.path.wanted_after, self.path.draw) else {
            return Vec::new();
        };
        let retry = now.saturating_add(duration_ns(CHECK_LONGEST));
        let spaced = self
            .path
            .last_check_began
            .map(|began| began.saturating_add(duration_ns(CHECK_SPACING)))
            .filter(|at| now < *at);
        if self.check_in_hand() {
            self.path.due = Some(spaced.unwrap_or(retry));
            return Vec::new();
        }
        if let Some(at) = spaced {
            self.path.due = Some(at);
            return Vec::new();
        }
        let actions = self.wanted_check(now, draw);
        self.path.due = (!self.check_in_hand()).then_some(retry);
        actions
    }

    /// When a check a failure wants is next due.
    pub(super) fn path_due(&self) -> Option<u64> {
        self.path.due
    }

    /// The spacing passed for a check a failure wants.
    pub(super) fn on_path_deadline(&mut self, now: u64) -> Vec<Action> {
        self.path.due = None;
        self.start_wanted_check(now)
    }

    /// A check began, scheduled or on demand.
    pub(super) fn check_began(&mut self, now: u64) {
        self.path.last_check_began = Some(now);
    }

    /// When the latest check began. The schedule records it and emits
    /// nothing: the probe's delay is armed then, and the directory list is
    /// drawn when the probe goes out. The tests read the start here.
    #[cfg(test)]
    pub(super) fn last_check_began(&self) -> Option<u64> {
        self.path.last_check_began
    }

    /// Whether Tor itself says it cannot reach its network, or that no
    /// directory answers, while it runs.
    pub(super) fn tor_says_unreachable(&self) -> bool {
        matches!(self.phase, Phase::Running { .. })
            && matches!(
                self.cause,
                Cause::ExternalBlocked | Cause::DirectoryUnreachable
            )
    }
}

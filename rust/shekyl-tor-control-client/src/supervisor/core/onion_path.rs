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
//! runs at a time, and its result answers every waiting failure. While Tor
//! says it cannot reach its network, the answer is impaired, and no check
//! runs. The probe is not a monitor of each circuit (`TSR-Q14`, restated):
//! when asked, the manager is the best-placed component to say whether the
//! onion path works, and it answers.

use std::time::Duration;

use super::super::posture::Cause;
use super::{duration_ns, Action, Core, Phase, PROBE_AFTER_MAX, PROBE_WITHIN};

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

/// The longest one check runs, from its start to its verdict, 240 s: the
/// two-miss rule's two probes, each at its longest delay and its bound
/// (§4.5). The directory fetches run inside the first probe's span, each at
/// most its own longest delay and its answer window.
pub const CHECK_LONGEST: Duration = {
    let one_probe = PROBE_AFTER_MAX.saturating_add(PROBE_WITHIN);
    one_probe.saturating_add(one_probe)
};

/// How long the Tor connector declares the judge waits for a reading after
/// a failure, 19 minutes: the spacing plus one check (Rick, 2026-11-15).
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
    /// The earliest failure a reading is wanted after, while one waits.
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
    /// latest one changes nothing. A fact newer than the earliest waiting
    /// failure answers every waiting failure, so the want ends.
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
        self.path.wanted_after = Some(self.path.wanted_after.map_or(after, |at| at.min(after)));
        self.path.draw = Some(draw);
        self.start_wanted_check(now)
    }

    /// Start the check a waiting failure wants, when one may run: none in
    /// hand, and the last begun at least the spacing ago. Before then, the
    /// check is due when the spacing has passed.
    fn start_wanted_check(&mut self, now: u64) -> Vec<Action> {
        let (Some(_), Some(draw)) = (self.path.wanted_after, self.path.draw) else {
            return Vec::new();
        };
        if self.check_in_hand() {
            return Vec::new();
        }
        let spaced = self
            .path
            .last_check_began
            .map(|began| began.saturating_add(duration_ns(CHECK_SPACING)));
        if let Some(at) = spaced.filter(|at| now < *at) {
            self.path.due = Some(at);
            return Vec::new();
        }
        self.path.due = None;
        self.wanted_check(now, draw)
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

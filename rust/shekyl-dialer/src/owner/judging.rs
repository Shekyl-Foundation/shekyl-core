// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge in the owner (`DIALER_OUTAGE_EVIDENCE.md` §4.1, `OE-D8`;
//! §3.3 as ruled 2026-11-15): each connector's source of path readings,
//! the waiting verdict, and clearing. [`fn@crate::judge`] decides; this asks
//! the dialing connector and performs what it decides through
//! [`Peerlist::apply`](shekyl_peerlist::Peerlist::apply).
//!
//! - **The source.** Each connector supplies its own
//!   ([`Dialer::set_path_source`]); until it does, the connector has none
//!   ([`NoReadings`]) and every uncertain failure on it is excused at once.
//!   The source is asked for a reading taken after the failure. Asking is
//!   the request: the source may start work toward one, and rings the
//!   dialer's bell when a reading arrives.
//! - **The waiting verdict** holds no in-flight slot and no target place:
//!   the attempt finished, and the address is not drawn again meanwhile. A
//!   working reading counts it; an impaired one, or none by the source's
//!   wait, excuses it. A verdict performed late can therefore err only
//!   toward excusing. The connector's owner loop arms its wake for the
//!   earliest deadline, and a reading rings its bell.
//! - **Clearing.** A working reading on a connector after an excusal
//!   clears the excusals of its addresses with no counted failure.
//! - **At stop** a verdict still waiting is not performed: the failure
//!   counts against nothing, and its seat is stored as it stands.

use std::sync::Arc;

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{ConnectorId, DialOutcome, Tick, Verdict};
use shekyl_timing_engine::{Clock, Stamp};
use shekyl_transport_layer::{NoReadings, PathReady, PathSource};

use super::{Dialer, Shared};
use crate::judge::{judge, settle, Judgement};

/// A failed test whose verdict waits for its connector's path reading.
#[derive(Clone, Debug)]
pub(super) struct PendingVerdict {
    pub(super) connector: ConnectorId,
    pub(super) outcome: DialOutcome,
    /// When the test's final attempt failed, on the process clock.
    pub(super) failed: Stamp,
    /// When the connector's wait runs out, on the engine's clock: with no
    /// reading by then, the failure is excused.
    pub(super) deadline: Tick,
}

/// What the judge keeps per connector: where it asks, and whether an
/// excusal was applied since its last working reading.
pub(super) struct PathJudging {
    pub(super) source: Arc<dyn PathSource>,
    pub(super) excused_since: bool,
}

impl PathJudging {
    pub(super) fn none() -> Self {
        Self {
            source: Arc::new(NoReadings),
            excused_since: false,
        }
    }
}

impl<C: Clock + Clone + Send + Sync + 'static> Dialer<C> {
    /// Ask `connector`'s `source` for its path readings from now on. The
    /// network supplies each connector's own; one supplied again replaces
    /// the last. Verdicts already waiting are asked of the new source.
    pub fn set_path_source(&self, connector: ConnectorId, source: Arc<dyn PathSource>) {
        self.shared().paths[connector.index()].source = source;
        self.bell.ring();
    }

    /// Judge a failed test, failed at `failed`, or leave its verdict to
    /// its connector's path reading. A test that is not a failure is
    /// performed as it is. A failure that asks is asked at once, so the
    /// source can start toward a reading now.
    pub(super) fn judge_outcome<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        failed: Stamp,
        now: Stamp,
        rng: &mut R,
    ) {
        let failure = match outcome {
            DialOutcome::DialFailed(_, failure) => *failure,
            DialOutcome::SessionAccepted(_)
            | DialOutcome::Confirmed(_)
            | DialOutcome::PayloadRefused(_) => {
                shared
                    .lists
                    .apply(outcome, now.tick(), Verdict::Counted, rng);
                return;
            }
        };
        match judge(failure) {
            Judgement::Now(verdict) => Self::perform(shared, connector, outcome, now, verdict, rng),
            Judgement::AskThePath => {
                let wait = shared.paths[connector.index()].source.wait_nanos();
                shared.pending.push(PendingVerdict {
                    connector,
                    outcome: outcome.clone(),
                    failed,
                    deadline: Tick::new(failed.tick().get().saturating_add(wait)),
                });
                Self::apply_due_verdicts(shared, now, rng);
            }
        }
    }

    /// Ask each waiting verdict's connector for a reading after its
    /// failure, and perform every one that is decided: counted on a
    /// working reading, excused on an impaired one or when its wait has
    /// run out.
    pub(super) fn apply_due_verdicts<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        now: Stamp,
        rng: &mut R,
    ) {
        let ready = Arc::clone(&shared.ready);
        let mut decided = Vec::new();
        shared.pending.retain(|pending| {
            let source = &shared.paths[pending.connector.index()].source;
            let reading = source.reading_after(pending.failed, now, &ready);
            match settle(reading, now.tick() >= pending.deadline) {
                Some(verdict) => {
                    decided.push((pending.connector, pending.outcome.clone(), verdict));
                    false
                }
                None => true,
            }
        });
        for (connector, outcome, verdict) in decided {
            Self::perform(shared, connector, &outcome, now, verdict, rng);
        }
    }

    /// Perform every waiting verdict that is decided. Each wake and each
    /// bell does this first, as the owner loop does.
    pub fn apply_verdicts<R: RelayRng + ?Sized>(&self, rng: &mut R) {
        let at = self.stamp();
        Self::apply_due_verdicts(&mut self.shared(), at, rng);
    }

    /// Perform `verdict`. A counted uncertain failure is a working
    /// reading, which clears the connector's excusals made since the last
    /// one; an excusal is noted for the next.
    fn perform<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Stamp,
        verdict: Verdict,
        rng: &mut R,
    ) {
        let paths = &mut shared.paths[connector.index()];
        match verdict {
            Verdict::Excused => paths.excused_since = true,
            Verdict::Counted if std::mem::take(&mut paths.excused_since) => {
                shared.lists.clear_excused(connector);
            }
            Verdict::Counted | Verdict::Drop => {}
        }
        shared.lists.apply(outcome, now.tick(), verdict, rng);
    }

    /// When the owner loop next wakes for `connector`'s waiting verdicts,
    /// on the engine's clock: the earliest deadline. A reading that
    /// arrives sooner rings the bell.
    #[must_use]
    pub fn next_verdict_due(&self, connector: ConnectorId) -> Option<Tick> {
        self.shared()
            .pending
            .iter()
            .filter(|pending| pending.connector == connector)
            .map(|pending| pending.deadline)
            .min()
    }

    /// The verdicts waiting on `connector`, for tests and the operator
    /// view.
    #[must_use]
    pub fn pending_verdicts(&self, connector: ConnectorId) -> usize {
        self.shared()
            .pending
            .iter()
            .filter(|pending| pending.connector == connector)
            .count()
    }
}

/// The bell a source rings when it has a reading.
pub(super) fn ready_rings(bell: &Arc<super::ready::Bell>) -> PathReady {
    let bell = Arc::clone(bell);
    Arc::new(move || bell.ring())
}

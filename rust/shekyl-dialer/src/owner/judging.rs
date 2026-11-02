// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge in the owner (`DIALER_OUTAGE_EVIDENCE.md` §4.1, `OE-D8`):
//! what the dialer observes of each connector's link, the deferred
//! verdict, and clearing. [`crate::judge`] decides; this keeps its inputs
//! and performs what it decides through [`Peerlist::apply`].
//!
//! - **Observations.** A stream that opened is noted when its attempt
//!   ends, after that attempt was judged, so it never corroborates its own
//!   failure. A corroborating session's received bytes are read off the
//!   board with the inbound rows ([`Dialer::with_inbound`]): sessions whose
//!   handshake finished, inbound included only where the connector counts
//!   inbound. The probe of this node's own onion is dropped in that
//!   handshake, so it is never one of them (§3.3, the brief's test 7).
//! - **The deferred verdict** holds no in-flight slot and no target place:
//!   the attempt finished, and the address is not drawn again meanwhile.
//!   A sign of life inside its bracket counts it when the dialer sees it
//!   ([`closes_the_bracket`]); the deadline only excuses. A verdict
//!   performed late can therefore err only toward excusing. The
//!   connector's owner loop arms its wake for the earliest deadline.
//! - **Clearing.** The first sign of life on a connector after an excusal
//!   clears the excusals of its addresses with no counted failure.
//! - **At stop** a verdict still waiting is not performed: the failure
//!   counts against nothing, and its seat is stored as it stands.

use std::sync::Arc;

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{dial_profile, ConnectorId, DialOutcome, Tick, Verdict};
use shekyl_seam::{Board, Direction};
use shekyl_transport_layer::SessionTraffic;

use super::{Dialer, Shared};
use crate::judge::{closes_the_bracket, judge, Judgement, Observations};
use crate::reach::{attempt_stream, AttemptStream};

/// The clock the judge reads, and each session's last received byte on it:
/// the byte-stamp clock (`monotonic_ms`) and the node gate's stamps in
/// production. Never an engine `Tick`.
#[derive(Clone)]
pub(super) struct LifeClock {
    pub(super) now_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(super) received_ms: Arc<dyn Fn(u64) -> u64 + Send + Sync>,
}

impl LifeClock {
    pub(super) fn production() -> Self {
        Self {
            now_ms: Arc::new(shekyl_transport_layer::monotonic_ms),
            received_ms: Arc::new(|conn| shekyl_capped_stream::node_gate().activity(conn).1),
        }
    }
}

/// A failed test whose verdict waits for its bracket's after side.
#[derive(Clone, Debug)]
pub(super) struct PendingVerdict {
    pub(super) connector: ConnectorId,
    pub(super) outcome: DialOutcome,
    /// When the test's final attempt failed, on the byte-stamp clock.
    pub(super) failed_ms: u64,
    /// When the bracket closes, on the byte-stamp clock.
    pub(super) deadline_ms: u64,
    /// A sign of life inside the bracket was seen: the failure counts.
    pub(super) counted: bool,
}

/// What the judge keeps per connector.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct LinkEvidence {
    pub(super) observed: Observations,
    /// The latest sign of life already acted on: a later one is the next.
    pub(super) seen: Option<u64>,
    /// An excusal was applied since the last sign of life.
    pub(super) excused_since: bool,
}

impl Dialer {
    /// Read each connector's corroborating sessions off `board`: the latest
    /// byte any of them received. A byte that arrived is kept when its
    /// session later closes; it did arrive.
    pub(super) fn observe_sessions(board: &Board, shared: &mut Shared, now: Tick) {
        for &connector in ConnectorId::ALL {
            let traffic = dial_profile(connector)
                .judging
                .corroboration
                .session_traffic;
            let received = Arc::clone(&shared.life_clock.received_ms);
            let latest = board
                .rows()
                .iter()
                .filter(|row| {
                    row.established()
                        && row.connector() == connector
                        && (traffic == SessionTraffic::AnySession
                            || row.direction() == Direction::Outbound)
                })
                .map(|row| received(row.id().get()))
                .filter(|&ms| ms > 0)
                .max();
            shared.evidence[connector.index()]
                .observed
                .note_session(latest);
            Self::note_life(shared, connector, now);
        }
    }

    /// A finished attempt's stream, noted after its own failure was judged,
    /// at `at_ms`: when the stream opened, and never later than the instant
    /// that failure was judged at, so the stream cannot close its own
    /// bracket.
    pub(super) fn note_stream(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        at_ms: u64,
        now: Tick,
    ) {
        if attempt_stream(outcome) == AttemptStream::Opened {
            shared.evidence[connector.index()]
                .observed
                .note_stream(at_ms);
            Self::note_life(shared, connector, now);
        }
    }

    /// A sign of life the judge has not acted on yet counts every pending
    /// failure whose bracket it falls inside, clears the excusals made
    /// since the last one, and on Tor is published for the posture line
    /// (§6).
    fn note_life(shared: &mut Shared, connector: ConnectorId, now: Tick) {
        let judging = dial_profile(connector).judging;
        let evidence = &mut shared.evidence[connector.index()];
        let life = evidence.observed.last_life(judging.corroboration);
        if life <= evidence.seen {
            return;
        }
        evidence.seen = life;
        if let Some(life_ms) = life {
            for pending in shared
                .pending
                .iter_mut()
                .filter(|pending| pending.connector == connector)
            {
                pending.counted |= closes_the_bracket(judging, pending.failed_ms, life_ms);
            }
        }
        let evidence = &mut shared.evidence[connector.index()];
        if std::mem::take(&mut evidence.excused_since) {
            shared.lists.clear_excused(connector);
        }
        shared.tor_link.life(connector, now);
    }

    /// Judge a failed test at `failed_ms`, or defer its verdict. A test
    /// that is not a failure is performed as it is.
    pub(super) fn judge_outcome<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        failed_ms: u64,
        now: Tick,
        rng: &mut R,
    ) {
        let failure = match outcome {
            DialOutcome::DialFailed(_, failure) => *failure,
            DialOutcome::SessionAccepted(_)
            | DialOutcome::Confirmed(_)
            | DialOutcome::PayloadRefused(_) => {
                shared.lists.apply(outcome, now, Verdict::Counted, rng);
                return;
            }
        };
        let judging = dial_profile(connector).judging;
        let observed = shared.evidence[connector.index()].observed;
        match judge(failure, judging, observed, failed_ms) {
            Judgement::Now(verdict) => Self::perform(shared, connector, outcome, now, verdict, rng),
            Judgement::AtBracketEnd { deadline_ms } => {
                shared.pending.push(PendingVerdict {
                    connector,
                    outcome: outcome.clone(),
                    failed_ms,
                    deadline_ms,
                    counted: false,
                });
            }
        }
    }

    /// Every deferred verdict a sign of life counted, and every one whose
    /// deadline has passed with nothing counting it, performed: counted, or
    /// excused.
    pub(super) fn apply_due_verdicts<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        now: Tick,
        rng: &mut R,
    ) {
        let now_ms = (shared.life_clock.now_ms)();
        let (due, waiting): (Vec<PendingVerdict>, Vec<PendingVerdict>) =
            std::mem::take(&mut shared.pending)
                .into_iter()
                .partition(|pending| pending.counted || pending.deadline_ms <= now_ms);
        shared.pending = waiting;
        for pending in due {
            let verdict = if pending.counted {
                Verdict::Counted
            } else {
                Verdict::Excused
            };
            Self::perform(
                shared,
                pending.connector,
                &pending.outcome,
                now,
                verdict,
                rng,
            );
        }
    }

    /// Perform every deferred verdict that is decided: counted by a sign of
    /// life inside its bracket, or excused at its deadline. Each wake does
    /// this first, as the owner loop does.
    pub fn apply_verdicts<R: RelayRng + ?Sized>(&self, rng: &mut R) {
        let now = self.hub.now();
        self.with_inbound(|shared| Self::apply_due_verdicts(shared, now, rng));
    }

    fn perform<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
        verdict: Verdict,
        rng: &mut R,
    ) {
        if verdict == Verdict::Excused {
            shared.evidence[connector.index()].excused_since = true;
        }
        shared.lists.apply(outcome, now, verdict, rng);
    }

    /// When the owner loop next wakes for `connector`'s deferred verdicts,
    /// on the engine's clock: now for one a sign of life has counted,
    /// otherwise now plus what the byte-stamp clock still has to run to the
    /// earliest deadline. One clock decides the deadline, so the wake never
    /// comes before it and never re-arms for a due already past.
    #[must_use]
    pub fn next_verdict_due(&self, connector: ConnectorId) -> Option<Tick> {
        let shared = self.shared();
        let now_ms = (shared.life_clock.now_ms)();
        let wait_ms = shared
            .pending
            .iter()
            .filter(|pending| pending.connector == connector)
            .map(|pending| {
                if pending.counted {
                    0
                } else {
                    pending.deadline_ms.saturating_sub(now_ms)
                }
            })
            .min()?;
        drop(shared);
        let wait_nanos = wait_ms.saturating_mul(1_000_000);
        Some(Tick::new(self.hub.now().get().saturating_add(wait_nanos)))
    }

    /// The deferred verdicts waiting on `connector`, for tests and the
    /// operator view.
    #[must_use]
    pub fn pending_verdicts(&self, connector: ConnectorId) -> usize {
        self.shared()
            .pending
            .iter()
            .filter(|pending| pending.connector == connector)
            .count()
    }

    /// Drive the judge's clock and each session's received byte from the
    /// caller, in place of the byte-stamp clock and the node gate.
    #[cfg(feature = "test-seams")]
    pub fn set_life_clock(
        &self,
        now_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
        received_ms: Arc<dyn Fn(u64) -> u64 + Send + Sync>,
    ) {
        self.shared().life_clock = LifeClock {
            now_ms,
            received_ms,
        };
    }
}

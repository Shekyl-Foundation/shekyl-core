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
//!   the attempt finished, and only the seat stays outstanding, so it is not
//!   drawn again. The connector's owner loop arms its wake for the earliest
//!   deadline.
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
use crate::judge::{judge, judge_at_bracket_end, Judgement, Observations};
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
    /// The same deadline on the engine's clock, for the owner's wake.
    pub(super) due: Tick,
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
            let observed = &mut shared.evidence[connector.index()].observed;
            observed.session_received_ms = observed.session_received_ms.max(latest);
            Self::note_life(shared, connector, now);
        }
    }

    /// A finished attempt's stream, noted after its own failure was judged.
    pub(super) fn note_stream(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
    ) {
        if attempt_stream(outcome) == AttemptStream::Opened {
            let at = (shared.life_clock.now_ms)();
            shared.evidence[connector.index()].observed.stream_opened_ms = Some(at);
            Self::note_life(shared, connector, now);
        }
    }

    /// A sign of life the judge has not acted on yet clears the excusals
    /// made since the last one, and on Tor it is published for the posture
    /// line (§6).
    fn note_life(shared: &mut Shared, connector: ConnectorId, now: Tick) {
        let corroboration = dial_profile(connector).judging.corroboration;
        let evidence = &mut shared.evidence[connector.index()];
        let life = evidence.observed.last_life(corroboration);
        if life <= evidence.seen {
            return;
        }
        evidence.seen = life;
        if std::mem::take(&mut evidence.excused_since) {
            shared.lists.clear_excused(connector);
        }
        if connector == ConnectorId::Tor {
            shared.tor_link.life(now);
        }
    }

    /// Judge a failed test, or defer its verdict. A test that is not a
    /// failure is performed as it is.
    pub(super) fn judge_outcome<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
        rng: &mut R,
    ) {
        let failure = match outcome {
            DialOutcome::DialFailed(_, failure) | DialOutcome::PeerlistRefused(_, failure) => {
                *failure
            }
            DialOutcome::SessionAccepted(_)
            | DialOutcome::Confirmed(_)
            | DialOutcome::PayloadRefused(_) => {
                shared.lists.apply(outcome, now, Verdict::Counted, rng);
                return;
            }
        };
        let judging = dial_profile(connector).judging;
        let failed_ms = (shared.life_clock.now_ms)();
        let observed = shared.evidence[connector.index()].observed;
        match judge(failure, judging, observed, failed_ms) {
            Judgement::Now(verdict) => Self::perform(shared, connector, outcome, now, verdict, rng),
            Judgement::AtBracketEnd { deadline_ms } => {
                let due = Tick::new(now.get().saturating_add(judging.bracket_nanos));
                shared.pending.push(PendingVerdict {
                    connector,
                    outcome: outcome.clone(),
                    failed_ms,
                    deadline_ms,
                    due,
                });
            }
        }
    }

    /// Every deferred verdict whose bracket has closed, judged on its after
    /// side and performed.
    pub(super) fn apply_due_verdicts<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        now: Tick,
        rng: &mut R,
    ) {
        let now_ms = (shared.life_clock.now_ms)();
        let (due, waiting): (Vec<PendingVerdict>, Vec<PendingVerdict>) =
            std::mem::take(&mut shared.pending)
                .into_iter()
                .partition(|pending| pending.deadline_ms <= now_ms);
        shared.pending = waiting;
        for pending in due {
            let judging = dial_profile(pending.connector).judging;
            let observed = shared.evidence[pending.connector.index()].observed;
            let verdict = judge_at_bracket_end(judging, observed, pending.failed_ms);
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

    /// Perform every deferred verdict whose bracket has closed. Each wake
    /// does this first, as the owner loop does.
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

    /// When `connector`'s earliest deferred verdict is due, on the engine's
    /// clock.
    pub(super) fn earliest_verdict(&self, connector: ConnectorId) -> Option<Tick> {
        self.shared()
            .pending
            .iter()
            .filter(|pending| pending.connector == connector)
            .map(|pending| pending.due)
            .min()
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

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet's **operator alarm channel** (OA-1) — the surface a human reads
//! when a guarantee the wallet cannot restore by itself has been lost.
//!
//! Producers already publish alarm-shaped state and nothing consumes it.
//! `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` §3c calls
//! [`TorPosture::Degraded`](shekyl_tor::service::TorPosture::Degraded) "the
//! operator-alarm hook (rule 82)" and specifies how an alarm layer must render
//! it — and no alarm layer exists. This module is that layer, and
//! [`tor_posture`] is its first producer.
//!
//! # Why this is not a `DiagnosticSink`
//!
//! `shekyl-engine-core`'s `engine::diagnostics::DiagnosticSink` is the wallet's
//! other reporting surface, and reusing it here was the obvious move. Its own
//! contract rules it out — this is not a taste call. It pins
//! "**infallible at the trait surface**", "implementors that need to drop on
//! backpressure **do so silently**", and "**restart-amnesia is deliberate**".
//! All three are correct for producer-side observability, where every event is
//! re-derivable from state on the next attempt, and all three are wrong for a
//! condition whose evidence disappears while its consequence does not. A
//! droppable alarm is not an alarm.
//!
//! # A snapshot, not a stream — because absence of events is silence
//!
//! The channel's primary surface is a [`watch`] of [`AlarmBoard`], not an event
//! stream, and that is forced by one requirement: a check that is **not
//! currently running** must read as *disarmed*, never as healthy. A stream
//! cannot express that — a disarmed check emits nothing, and so does a healthy
//! one. So arming is a per-condition row on the snapshot ([`Arming`]), which is
//! the only shape in which "we are not watching this right now" is a value the
//! operator can be shown rather than an absence they must infer.
//!
//! # Latching is what makes a *coalescing* channel safe
//!
//! A [`watch`] keeps only the latest value, so a raise and a clear inside one
//! tick collapse to nothing. For an [`AlarmLifetime::Episode`] that is correct
//! and deliberate — coalescing a flap *is* the §3c "render
//! `Degraded ∪ Ready{recovering}` as one continuous incident" rule. For a
//! condition whose observable clears while the damage stands, losing the edge
//! would lose the only report of it. [`AlarmLifetime::LatchedRederived`] closes
//! that: the alarm stays on the board after the producer reports the condition
//! gone, so it cannot be missed by a consumer that was slow. **The latch is
//! what lets one lossy snapshot channel carry both classes**, which is why
//! there is one channel here and not two.
//!
//! # Emission cadence is a covert channel
//!
//! `shekyl-engine-core`'s `RefreshDiagnostic::SuppressedRateLimit`
//! exists because a producer that re-emits per tick leaks its own cadence; it
//! answers that with one notice then silence. This channel inherits the
//! constraint and answers it structurally instead: an incident is raised once
//! and cleared once, and a producer that re-reports a live condition updates
//! the open incident in place rather than emitting again. There is no rate
//! limiter here because there is nothing to rate-limit — and a future "just
//! re-raise every tick, it is simpler" edit reintroduces the leak this
//! paragraph forbids.
//!
//! # What the tor control [`EventSink`](shekyl_tor::control::EventSink) is not
//!
//! It is **not** this channel's input, and an earlier plan to make it one
//! rested on a premise the code refutes: no production call site issues
//! `SETEVENTS`, so tor never sends the async `650` events the sink carries, so
//! in production the sink receives nothing at all. (`ControlReply` is also a
//! raw, deliberately forensic surface — "parse it, never log it" — not an
//! alarm vocabulary.) The wallet's honest production value for
//! `TorServiceConfig::events` is
//! [`EventSink::unsubscribed`](shekyl_tor::control::EventSink::unsubscribed),
//! which names that fact at the construction site; the alarm input is the
//! posture watch, which is where the supervisor's liveness policy actually
//! publishes.

#![forbid(unsafe_code)]

pub mod tor_posture;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::watch;

/// A condition the wallet watches on the operator's behalf.
///
/// One row per condition on the [`AlarmBoard`] — the unit that is armed or
/// disarmed, and the unit an incident is opened against. Deliberately coarser
/// than [`OperatorAlarm`]: several alarms can describe the same condition
/// (the vanguard set has three distinct integrity faults), and an operator
/// looking at "is my guard topology intact" wants one row, not three.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlarmCondition {
    /// Whether the wallet's tor transport is up and staying up (§3c).
    TransportLiveness,
    /// Whether the persona's vanguard set — the guard topology behind every
    /// circuit it builds — is intact and will survive a restart.
    VanguardIntegrity,
}

/// Whether a condition's tripwire can currently fire.
///
/// The reason this is on the board at all: a check that cannot fire and a check
/// that fired clean are both *quiet*, and rendering them the same way is how a
/// stopped watchdog reads as good news.
///
/// `#[non_exhaustive]` to match [`DisarmedReason`]: the set of ways a check can
/// be off grows as producers arrive, and an embedder living outside this
/// workspace would otherwise take a compile break it gets no warning about here.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arming {
    /// The check is running; a raised alarm for this condition means the
    /// condition is live, and no raised alarm means it was checked and clean.
    Armed,
    /// The check exists but cannot fire right now. Render as "not checking" —
    /// **never** as healthy.
    Disarmed(DisarmedReason),
}

/// Why a condition's tripwire is currently disarmed.
///
/// Bounded tags, no free text: this reaches a user-facing surface (rule 82) and
/// the set of ways a check can be off is a design fact, not a message.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisarmedReason {
    /// There is no live tor incarnation to report on. Vanguard state is
    /// observable only on
    /// [`TorPosture::Ready`](shekyl_tor::service::TorPosture::Ready) — the
    /// `warning` field exists on that variant and nowhere else — so while tor
    /// is starting, bootstrapping, retrying or degraded, the wallet genuinely
    /// does not know whether the guard topology is intact.
    TransportNotReady,
    /// The tor supervisor is gone: its posture channel closed, which §3c
    /// defines as the clean-shutdown signal. Nothing is being watched, and
    /// nothing will be until a supervisor is spawned again.
    TransportStopped,
}

/// How a raised alarm's **observable** behaves once the condition is raised.
///
/// This is the axis a severity ladder gets wrong. `Info`/`Warn`/`Critical`
/// *can* express the distinction, but nothing stops a later variant from being
/// filed at the wrong rung by a field assignment; here the class is derived
/// from the variant by an exhaustive match in [`OperatorAlarm::lifetime`], so a
/// new alarm does not compile until someone answers the question.
///
/// `#[non_exhaustive]` **deliberately**, and this is the one place it is a
/// prediction rather than a hedge: the reopening criterion on
/// [`AlarmLifetime::LatchedRederived`] names a third class that is expected to
/// arrive with the serving conditions. An embedder that matches exhaustively
/// today would break in its own repository, where nothing in this workspace's
/// gates would warn it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmLifetime {
    /// The observable tracks the condition: when the producer reports it gone,
    /// the alarm leaves the board. Re-reports while it is open update the
    /// incident in place, so one fault is one incident however many times it is
    /// observed.
    Episode,
    /// The observable can clear while the consequence stands, so the alarm is
    /// **held** after the producer reports the condition gone, until an
    /// operator acknowledges it — **and** the producer re-detects the condition
    /// on every wallet start, so the in-memory latch is a convenience rather
    /// than the system of record.
    ///
    /// # The reopening criterion (rule 21)
    ///
    /// A condition whose consequence outlives its *evidence* — nothing
    /// re-detects it after a restart, so an in-memory latch is the only record
    /// there will ever be — is **not** this variant and must not be filed under
    /// it. Such a condition needs durable acknowledgment state, which this
    /// channel does not have; the known candidate is the serving host's dropped
    /// pins (`AlreadyPruned` bytes are gone until a replay, while
    /// `members_missing_pins` reads clean again the moment `refresh` re-pins).
    /// Adding it is a third variant plus durable state, not a reclassification
    /// — and the exhaustive match is what forces that decision into review.
    LatchedRederived,
}

/// The bounded operator-alarm vocabulary.
///
/// No `String` payloads: the memory-amplifier closure that governs
/// `shekyl-engine-core`'s `RefreshDiagnostic` carries here verbatim, and these
/// values additionally live in a cloned snapshot that every subscriber holds. Causes are projected onto tags rather than collapsed,
/// because *which* fault it is decides what the operator does about it
/// (rule 82) — reinstalling a rejected tor bundle and waiting out a bootstrap
/// timeout are not the same instruction.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAlarm {
    /// §3c: the restart limit tripped (or a trust failure occurred) and the
    /// supervisor is retrying at the backoff cap. **Not terminal** — there is
    /// no give-up state — so this is "a human should look", not "the transport
    /// is finished".
    TransportDegraded {
        /// The most recent failure, or `None` when the episode was already open
        /// before this translator attached to the posture channel and the
        /// failure that opened it was published before anyone was listening.
        /// Reporting the incident without a cause beats reporting nothing.
        cause: Option<DegradedCause>,
    },
    /// Persisted vanguard state was unusable, so the set was **drawn fresh**.
    /// The re-draw has already happened: this is the restart-driven rotation
    /// the vanguard module exists to prevent, and it repeats on every start
    /// until the operator clears the file.
    VanguardStateRedrawn,
    /// The live vanguard set is correct but could not be written, so the *next*
    /// process start would re-draw. Nothing has rotated yet — this is the
    /// warning before the loss, not the loss.
    VanguardStateUnpersisted,
    /// Departure-based repair was skipped this pass because part of the
    /// consensus view did not decode, so a pinned relay that has genuinely left
    /// the network keeps its slot. Selection and clock rotation are unaffected.
    VanguardRepairSkipped {
        /// Entries whose identity decoded.
        decoded: usize,
        /// Entries the consensus reply announced.
        announced: usize,
    },
}

impl OperatorAlarm {
    /// This alarm's lifetime class.
    ///
    /// Exhaustive by construction: a new [`OperatorAlarm`] variant fails to
    /// compile until it is classified here, which is the whole mechanism by
    /// which the [`AlarmLifetime::LatchedRederived`] reopening criterion gets
    /// read rather than assumed. Each variant's *reason* for landing where it
    /// does is on the variant itself, and pinned per-variant by
    /// `lifetime_classification_is_pinned_per_variant` — so a reclassification
    /// is a test diff, not a silently-moved match arm.
    #[must_use]
    pub fn lifetime(&self) -> AlarmLifetime {
        match self {
            // The one whose damage outlives its evidence: the set has already
            // been drawn fresh, and the next successful write makes the warning
            // disappear while that rotation stands.
            Self::VanguardStateRedrawn => AlarmLifetime::LatchedRederived,
            // The rest genuinely end when their condition does — sustained
            // recovery, a successful write, a complete consensus view.
            Self::TransportDegraded { .. }
            | Self::VanguardStateUnpersisted
            | Self::VanguardRepairSkipped { .. } => AlarmLifetime::Episode,
        }
    }

    /// The condition this alarm reports on.
    #[must_use]
    pub fn condition(&self) -> AlarmCondition {
        match self {
            Self::TransportDegraded { .. } => AlarmCondition::TransportLiveness,
            Self::VanguardStateRedrawn
            | Self::VanguardStateUnpersisted
            | Self::VanguardRepairSkipped { .. } => AlarmCondition::VanguardIntegrity,
        }
    }
}

/// Why the tor supervisor entered its degraded episode.
///
/// One tag per [`ServiceFailure`](shekyl_tor::service::ServiceFailure) variant,
/// deliberately not collapsed — see [`OperatorAlarm`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedCause {
    /// The SP-T0c binary gate refused the tor binary, or discovery found none.
    /// Retries continue at the slow trust cadence and will keep failing until
    /// the operator reinstalls the pinned bundle — the one cause where waiting
    /// is definitely not the fix.
    BinaryRejected,
    /// The control channel failed.
    ControlChannelFailed,
    /// Tor bootstrapped but reported no TCP SOCKS listener — a usable-looking
    /// tor with nothing to dial.
    NoSocksListener,
    /// Tor did not reach bootstrap 100% within the deadline.
    BootstrapTimeout,
    /// The incarnation (actor or child process) died.
    Exited,
    /// A supervisor-internal fault — not a tor failure.
    Internal,
    /// The persona's onion service could not be published, so the full serving
    /// posture was never reached on that incarnation.
    OnionPublishFailed,
    /// Pinning or rotating the vanguard set failed, which is refused rather
    /// than published as a weaker serving posture.
    VanguardsFailed,
}

/// Identifies one continuous incident.
///
/// Needed because the board coalesces: a subscriber that samples
/// `Degraded → Ready{recovering} → Degraded` cannot otherwise tell one
/// continuing incident from a re-raise, and §3c requires exactly that
/// distinction ("render as **one continuous incident** (no flapping)"). It is
/// also what makes [`OperatorAlarms::acknowledge`] safe against a race: an
/// acknowledgment names the incident the operator actually looked at, so it
/// cannot silently dismiss a newer one that opened in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IncidentId(u64);

impl IncidentId {
    /// The raw counter value, for rendering and correlation only.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// An open alarm on the [`AlarmBoard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaisedAlarm {
    alarm: OperatorAlarm,
    incident: IncidentId,
    condition_cleared: bool,
}

impl RaisedAlarm {
    /// What is wrong.
    #[must_use]
    pub fn alarm(self) -> OperatorAlarm {
        self.alarm
    }

    /// Which continuous incident this is. Stable across an episode's
    /// interruptions; a new incident means a genuinely new fault.
    #[must_use]
    pub fn incident(self) -> IncidentId {
        self.incident
    }

    /// `true` once the producer has reported the underlying condition gone
    /// while the alarm is still held for acknowledgment.
    ///
    /// Only reachable for [`AlarmLifetime::LatchedRederived`]: an
    /// [`AlarmLifetime::Episode`] leaves the board at that moment instead. This
    /// is the flag a UI uses to say "resolved, unacknowledged" rather than
    /// "happening now".
    #[must_use]
    pub fn condition_cleared(self) -> bool {
        self.condition_cleared
    }

    /// This alarm's lifetime class.
    #[must_use]
    pub fn lifetime(self) -> AlarmLifetime {
        self.alarm.lifetime()
    }
}

/// One condition's row on the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionState {
    arming: Arming,
    raised: Option<RaisedAlarm>,
}

impl ConditionState {
    /// Whether this condition's tripwire can currently fire.
    #[must_use]
    pub fn arming(self) -> Arming {
        self.arming
    }

    /// The open alarm, if any.
    ///
    /// A latched alarm survives its condition being disarmed — the guard
    /// topology was re-drawn whether or not tor is up to be asked about it now.
    #[must_use]
    pub fn raised(self) -> Option<RaisedAlarm> {
        self.raised
    }
}

/// The operator-visible snapshot: every watched condition, its arming, and its
/// open alarm.
///
/// An empty board means **nothing is being watched yet**, not that everything
/// is fine: rows appear when a producer starts reporting. A consumer that
/// renders "all clear" for a board with no rows has made the mistake this
/// module exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlarmBoard {
    conditions: BTreeMap<AlarmCondition, ConditionState>,
}

impl AlarmBoard {
    /// One condition's row, or `None` if no producer has reported it yet.
    #[must_use]
    pub fn condition(&self, condition: AlarmCondition) -> Option<ConditionState> {
        self.conditions.get(&condition).copied()
    }

    /// Every reported condition, in a stable order.
    pub fn conditions(&self) -> impl Iterator<Item = (AlarmCondition, ConditionState)> + '_ {
        self.conditions.iter().map(|(c, s)| (*c, *s))
    }

    /// Every open alarm, in a stable order.
    pub fn raised(&self) -> impl Iterator<Item = (AlarmCondition, RaisedAlarm)> + '_ {
        self.conditions
            .iter()
            .filter_map(|(c, s)| s.raised.map(|r| (*c, r)))
    }

    /// The row this condition should have, created armed-and-quiet if absent.
    fn entry(&mut self, condition: AlarmCondition) -> &mut ConditionState {
        self.conditions.entry(condition).or_insert(ConditionState {
            arming: Arming::Armed,
            raised: None,
        })
    }
}

/// The alarm channel: producers write, the embedder subscribes.
///
/// Held behind an [`Arc`](std::sync::Arc) by whoever spawns producers. Writes
/// are `pub(crate)` — the vocabulary is public so an embedder can render and
/// match on it, but raising an alarm is a statement about a condition the
/// wallet observed, and the observation sites are in this crate.
#[derive(Debug)]
pub struct OperatorAlarms {
    board: watch::Sender<AlarmBoard>,
    next_incident: AtomicU64,
}

impl Default for OperatorAlarms {
    fn default() -> Self {
        Self {
            board: watch::Sender::new(AlarmBoard::default()),
            next_incident: AtomicU64::new(1),
        }
    }
}

impl OperatorAlarms {
    /// A channel with an empty board.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to the board.
    ///
    /// The receiver's initial value is the current board, so a late subscriber
    /// sees open incidents immediately rather than waiting for the next change
    /// — the property that makes a snapshot channel safe to attach to at any
    /// time.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<AlarmBoard> {
        self.board.subscribe()
    }

    /// The board as it stands.
    #[must_use]
    pub fn board(&self) -> AlarmBoard {
        self.board.borrow().clone()
    }

    /// Acknowledge a **resolved, latched** alarm, removing it from the board.
    ///
    /// Returns `false` — changing nothing — when the named incident is not the
    /// open one, or when the underlying condition is still live. Both refusals
    /// are load-bearing:
    ///
    /// - The incident check means an acknowledgment applies to the incident the
    ///   operator actually read, so one that opened while they were reading
    ///   cannot be dismissed unseen.
    /// - Refusing to acknowledge a **live** condition keeps this from becoming
    ///   a mute button. Silencing a fault that is still happening is a UI
    ///   concern, and an embedder that wants it must implement it as muting,
    ///   not by telling the board the operator handled something they did not.
    ///
    /// [`AlarmLifetime::Episode`] alarms are never acknowledgeable: they clear
    /// themselves, so an acknowledgment would race the producer.
    pub fn acknowledge(&self, condition: AlarmCondition, incident: IncidentId) -> bool {
        let mut applied = false;
        self.board.send_if_modified(|board| {
            let Some(state) = board.conditions.get_mut(&condition) else {
                return false;
            };
            let Some(raised) = state.raised else {
                return false;
            };
            if raised.incident != incident || !raised.condition_cleared {
                return false;
            }
            state.raised = None;
            applied = true;
            true
        });
        applied
    }

    /// Whether this condition currently has an open alarm.
    ///
    /// For producers that must distinguish "continue the open incident" from
    /// "open one" without disturbing the incident's payload — see
    /// [`tor_posture`], where a translator attaching mid-episode has no failure
    /// to report but must not leave the board reading healthy.
    pub(crate) fn is_raised(&self, condition: AlarmCondition) -> bool {
        self.board
            .borrow()
            .condition(condition)
            .is_some_and(|s| s.raised.is_some())
    }

    /// Mark a condition's tripwire as able to fire.
    pub(crate) fn arm(&self, condition: AlarmCondition) {
        self.set_arming(condition, Arming::Armed);
    }

    /// Mark a condition's tripwire as unable to fire, and say why.
    ///
    /// Does **not** touch a raised alarm: a latched one outlives the ability to
    /// re-observe it, which is the entire point of latching.
    pub(crate) fn disarm(&self, condition: AlarmCondition, reason: DisarmedReason) {
        self.set_arming(condition, Arming::Disarmed(reason));
    }

    fn set_arming(&self, condition: AlarmCondition, arming: Arming) {
        self.board.send_if_modified(|board| {
            let state = board.entry(condition);
            if state.arming == arming {
                return false;
            }
            state.arming = arming;
            true
        });
    }

    /// Report a condition as live.
    ///
    /// Opens an incident if none is open for this condition. If one is open for
    /// the **same** alarm, the payload is updated in place and the incident id
    /// is kept — that is the "one fault, one incident" rule, and it is why a
    /// producer may call this every tick without leaking a cadence. A
    /// *different* alarm on the same condition is a different fault: the old
    /// incident closes and a new one opens.
    pub(crate) fn raise(&self, alarm: OperatorAlarm) {
        let condition = alarm.condition();
        self.board.send_if_modified(|board| {
            let state = board.entry(condition);
            match state.raised {
                Some(existing)
                    if std::mem::discriminant(&existing.alarm)
                        == std::mem::discriminant(&alarm) =>
                {
                    // Same fault, still open. Re-reporting it must not mint a
                    // new incident, and a re-report is also proof the condition
                    // is live again, so a latch that was awaiting
                    // acknowledgment goes back to unresolved.
                    if existing.alarm == alarm && !existing.condition_cleared {
                        return false;
                    }
                    state.raised = Some(RaisedAlarm {
                        alarm,
                        incident: existing.incident,
                        condition_cleared: false,
                    });
                    true
                }
                _ => {
                    state.raised = Some(RaisedAlarm {
                        alarm,
                        incident: IncidentId(self.next_incident.fetch_add(1, Ordering::Relaxed)),
                        condition_cleared: false,
                    });
                    true
                }
            }
        });
    }

    /// Report a condition as no longer live.
    ///
    /// An [`AlarmLifetime::Episode`] alarm leaves the board. A
    /// [`AlarmLifetime::LatchedRederived`] one stays, marked
    /// [`RaisedAlarm::condition_cleared`], until it is acknowledged — the
    /// producer saying "it is fine now" is exactly the moment the evidence
    /// disappears, so it is the last moment at which dropping the report would
    /// be safe.
    pub(crate) fn clear(&self, condition: AlarmCondition) {
        self.board.send_if_modified(|board| {
            let Some(state) = board.conditions.get_mut(&condition) else {
                return false;
            };
            let Some(raised) = state.raised else {
                return false;
            };
            match raised.lifetime() {
                AlarmLifetime::Episode => {
                    state.raised = None;
                    true
                }
                AlarmLifetime::LatchedRederived => {
                    if raised.condition_cleared {
                        return false;
                    }
                    state.raised = Some(RaisedAlarm {
                        condition_cleared: true,
                        ..raised
                    });
                    true
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redrawn() -> OperatorAlarm {
        OperatorAlarm::VanguardStateRedrawn
    }

    fn degraded(cause: DegradedCause) -> OperatorAlarm {
        OperatorAlarm::TransportDegraded { cause: Some(cause) }
    }

    fn raised_for(alarms: &OperatorAlarms, condition: AlarmCondition) -> Option<RaisedAlarm> {
        alarms
            .board()
            .condition(condition)
            .and_then(ConditionState::raised)
    }

    /// Pins every variant's classification. A reclassification is then a diff
    /// in this test, which is where the reopening criterion gets read.
    #[test]
    fn lifetime_classification_is_pinned_per_variant() {
        assert_eq!(
            OperatorAlarm::TransportDegraded { cause: None }.lifetime(),
            AlarmLifetime::Episode,
        );
        assert_eq!(
            OperatorAlarm::VanguardStateRedrawn.lifetime(),
            AlarmLifetime::LatchedRederived,
            "the fresh guard draw has already happened and the warning clears without it",
        );
        assert_eq!(
            OperatorAlarm::VanguardStateUnpersisted.lifetime(),
            AlarmLifetime::Episode,
            "nothing has rotated: a successful write genuinely ends this one",
        );
        assert_eq!(
            OperatorAlarm::VanguardRepairSkipped {
                decoded: 1,
                announced: 2
            }
            .lifetime(),
            AlarmLifetime::Episode,
        );
    }

    #[test]
    fn an_empty_board_is_not_an_all_clear() {
        let alarms = OperatorAlarms::new();
        assert!(alarms
            .board()
            .condition(AlarmCondition::TransportLiveness)
            .is_none());
        assert_eq!(alarms.board().raised().count(), 0);
    }

    #[test]
    fn re_reporting_a_live_condition_keeps_one_incident() {
        let alarms = OperatorAlarms::new();
        alarms.raise(degraded(DegradedCause::Exited));
        let first = raised_for(&alarms, AlarmCondition::TransportLiveness).expect("raised");

        // Same fault, re-reported with a fresher cause: one incident, updated.
        alarms.raise(degraded(DegradedCause::BootstrapTimeout));
        let again = raised_for(&alarms, AlarmCondition::TransportLiveness).expect("raised");
        assert_eq!(again.incident(), first.incident());
        assert_eq!(
            again.alarm(),
            degraded(DegradedCause::BootstrapTimeout),
            "the payload must follow the newest failure",
        );
    }

    #[test]
    fn a_different_fault_on_the_same_condition_opens_a_new_incident() {
        let alarms = OperatorAlarms::new();
        alarms.raise(OperatorAlarm::VanguardStateUnpersisted);
        let first = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");

        alarms.raise(redrawn());
        let second = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert_ne!(second.incident(), first.incident());
        assert_eq!(second.alarm(), redrawn());
    }

    #[test]
    fn an_episode_leaves_the_board_when_its_condition_clears() {
        let alarms = OperatorAlarms::new();
        alarms.raise(degraded(DegradedCause::Exited));
        alarms.clear(AlarmCondition::TransportLiveness);
        assert!(raised_for(&alarms, AlarmCondition::TransportLiveness).is_none());
    }

    #[test]
    fn a_latch_outlives_its_condition_clearing() {
        let alarms = OperatorAlarms::new();
        alarms.raise(redrawn());
        let open = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert!(!open.condition_cleared());

        // The producer reports it fine — which for this fault means only that
        // the *evidence* is gone. The re-draw stands.
        alarms.clear(AlarmCondition::VanguardIntegrity);
        let held = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("still raised");
        assert!(held.condition_cleared());
        assert_eq!(held.incident(), open.incident());
    }

    #[test]
    fn a_latch_outlives_its_condition_being_disarmed() {
        let alarms = OperatorAlarms::new();
        alarms.raise(redrawn());
        alarms.disarm(
            AlarmCondition::VanguardIntegrity,
            DisarmedReason::TransportStopped,
        );
        let state = alarms
            .board()
            .condition(AlarmCondition::VanguardIntegrity)
            .expect("row");
        assert_eq!(
            state.arming(),
            Arming::Disarmed(DisarmedReason::TransportStopped),
        );
        assert!(
            state.raised().is_some(),
            "losing the ability to re-observe a fault is not evidence it did not happen",
        );
    }

    #[test]
    fn acknowledging_a_live_condition_is_refused() {
        let alarms = OperatorAlarms::new();
        alarms.raise(redrawn());
        let open = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert!(
            !alarms.acknowledge(AlarmCondition::VanguardIntegrity, open.incident()),
            "acknowledgment is not a mute button",
        );
        assert!(raised_for(&alarms, AlarmCondition::VanguardIntegrity).is_some());
    }

    #[test]
    fn acknowledging_a_resolved_latch_clears_it() {
        let alarms = OperatorAlarms::new();
        alarms.raise(redrawn());
        alarms.clear(AlarmCondition::VanguardIntegrity);
        let held = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert!(alarms.acknowledge(AlarmCondition::VanguardIntegrity, held.incident()));
        assert!(raised_for(&alarms, AlarmCondition::VanguardIntegrity).is_none());
    }

    #[test]
    fn acknowledging_a_stale_incident_cannot_dismiss_the_open_one() {
        let alarms = OperatorAlarms::new();
        alarms.raise(redrawn());
        let first = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        alarms.clear(AlarmCondition::VanguardIntegrity);
        assert!(alarms.acknowledge(AlarmCondition::VanguardIntegrity, first.incident()));

        // A second, genuinely new occurrence opens while the operator is still
        // holding the id they read a moment ago.
        alarms.raise(redrawn());
        alarms.clear(AlarmCondition::VanguardIntegrity);
        let second = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert_ne!(second.incident(), first.incident());
        assert!(
            !alarms.acknowledge(AlarmCondition::VanguardIntegrity, first.incident()),
            "an acknowledgment names the incident the operator read",
        );
        assert!(raised_for(&alarms, AlarmCondition::VanguardIntegrity).is_some());
    }

    #[test]
    fn a_latch_re_reported_while_resolved_becomes_live_again() {
        let alarms = OperatorAlarms::new();
        alarms.raise(redrawn());
        alarms.clear(AlarmCondition::VanguardIntegrity);
        alarms.raise(redrawn());
        let live = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert!(
            !live.condition_cleared(),
            "a re-report is proof the condition is live, not a resolved leftover",
        );
    }

    #[test]
    fn a_changed_payload_on_a_resolved_latch_also_makes_it_live_again() {
        let alarms = OperatorAlarms::new();
        alarms.raise(OperatorAlarm::VanguardRepairSkipped {
            decoded: 1,
            announced: 2,
        });
        alarms.clear(AlarmCondition::VanguardIntegrity);

        // Episode, so the clear removed it — re-raising with different counts
        // is a fresh incident, and nothing is left marked resolved.
        alarms.raise(OperatorAlarm::VanguardRepairSkipped {
            decoded: 3,
            announced: 9,
        });
        let live = raised_for(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert!(!live.condition_cleared());
        assert_eq!(
            live.alarm(),
            OperatorAlarm::VanguardRepairSkipped {
                decoded: 3,
                announced: 9
            },
        );

        // The same path on a genuine latch: resolved, then re-reported with a
        // *different* payload. It takes the update branch rather than the
        // early return, so it must un-resolve there too.
        let alarms = OperatorAlarms::new();
        alarms.raise(degraded(DegradedCause::Exited));
        let opened = raised_for(&alarms, AlarmCondition::TransportLiveness).expect("raised");
        alarms.raise(degraded(DegradedCause::BinaryRejected));
        let updated = raised_for(&alarms, AlarmCondition::TransportLiveness).expect("raised");
        assert_eq!(updated.incident(), opened.incident());
        assert!(!updated.condition_cleared());
    }

    #[test]
    fn a_late_subscriber_sees_the_open_incident_immediately() {
        let alarms = OperatorAlarms::new();
        alarms.raise(degraded(DegradedCause::BinaryRejected));
        let rx = alarms.subscribe();
        assert_eq!(
            rx.borrow()
                .condition(AlarmCondition::TransportLiveness)
                .and_then(ConditionState::raised)
                .map(RaisedAlarm::alarm),
            Some(degraded(DegradedCause::BinaryRejected)),
        );
    }
}

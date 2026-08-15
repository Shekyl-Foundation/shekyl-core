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
//! that: when the producer reports the condition gone, the alarm moves to
//! [`AlarmBoard::unacknowledged`] instead of leaving, so it cannot be missed by
//! a consumer that was slow. **The latch is what lets one lossy snapshot
//! channel carry both classes**, which is why there is one channel here and not
//! two.
//!
//! Live status and outstanding faults are separate shapes on the board rather
//! than one slot per condition, and that is not tidiness: several faults can
//! share an [`AlarmCondition`] while only one of them latches, so a single slot
//! would have to choose between the fault the operator has not seen yet and the
//! unrelated one that happened after it. See [`AlarmBoard`].
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

pub mod serve_set;
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
    /// Whether the shards this persona is bonded to serve are still pinned in
    /// the wallet's store, and whether the set is still being refreshed against
    /// the chain. A drifting or unrefreshed serve-set ends in the wallet's own
    /// node pruning bonded bytes — `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6
    /// item 4's slash, which is silent until it happens.
    ServeSetIntegrity,
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
    /// The wallet is still catching up to the chain, so the serve-set staleness
    /// tripwire is not armed.
    ///
    /// The tripwire measures ingest since the last successful refresh, and
    /// during catch-up that advances at whatever rate the wallet can ingest —
    /// far faster than the steady-state rate the bound is sized for, so an
    /// armed check would fire on every healthy catch-up. Arming only in steady
    /// state is what makes the bound derivable at all. **Rendered as "not
    /// checking yet", never as healthy** — that distinction is the entire
    /// reason this channel is a snapshot.
    CatchingUp,
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
    /// The serve-set has not been refreshed within its bound: the wallet has
    /// ingested `lag` blocks since the pins were last established. The refresh
    /// loop has stopped or is wedged — holdings that move now go unpinned, and
    /// unpinned bonded bytes are prunable.
    ServeSetStale {
        /// Blocks ingested since the last successful re-pin.
        lag: u64,
    },
    /// Consecutive refresh attempts are failing. Distinct from
    /// [`Self::ServeSetStale`]: that one is "nothing is trying", this one is
    /// "something is trying and not succeeding" — the curve-tree actor
    /// fail-stopping freezes ingest and pinning together, a common mode no
    /// store-derived reading can see.
    ServeSetRefreshFailing {
        /// Consecutive failed refresh attempts.
        consecutive: u32,
    },
    /// Pin rows for bonded members are gone from the store — a tree rollback
    /// deleted them (`truncate_from_tree_position`). **Recoverable:** the next
    /// successful refresh re-pins them, and the leaf bytes are still present.
    /// It is an alarm because the store's own reading self-clears the moment
    /// refresh runs, so a slow consumer could otherwise miss the window in
    /// which the bytes were prunable.
    ServeSetPinsDropped {
        /// Members with no pin row.
        dropped: u32,
        /// Members the serve-set claims.
        claimed: u32,
    },
    /// The wallet's ingest tip moved **below** the height the pins were minted
    /// at — a chain rollback (`rollback_to_fork`). Recoverable: re-ingest past
    /// the fork and the next refresh re-pins. It is reported rather than folded
    /// into [`Self::ServeSetStale`] because the two want different operator
    /// responses — a rollback resolves itself, a stale set means nothing is
    /// refreshing — and because the rollback is what *deletes* pin rows, so
    /// this is the precursor to [`Self::ServeSetPinsDropped`] rather than
    /// another way of saying it.
    ServeSetRolledBack {
        /// The ingest tip when the pins were established.
        minted_at_tip: u64,
        /// The ingest tip now.
        tip: u64,
    },
    /// Bonded leaf bytes are **gone** — frozen and already pruned, so no pin
    /// can bring them back. The store must be rebuilt by chain replay before
    /// this persona can serve those shards.
    ///
    /// The one irreversible condition on this board, and the reason it can be
    /// [`AlarmLifetime::LatchedRederived`] rather than needing durable state:
    /// it re-derives at every start, *more loudly than an alarm*.
    /// `PinnedServeSet::acquire` refuses outright
    /// (`PinError::MembersAlreadyPruned`) so the host does not start, while
    /// `refreshed` records it so one dead member cannot wedge every later
    /// refresh for the members that are still fine.
    ServeSetBytesPruned {
        /// Members whose leaf bytes were already gone at the last pin.
        members: u32,
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
            // The two whose damage outlives their evidence. The vanguard set
            // has already been drawn fresh, and the next successful write makes
            // the warning disappear while that rotation stands; pruned leaf
            // bytes are gone until a chain replay, and a re-pin reports success
            // for every member it *could* pin. Both re-derive at the next start
            // — the vanguard load fails again, and `acquire` refuses outright —
            // so an in-memory latch is a convenience, not the record.
            Self::VanguardStateRedrawn | Self::ServeSetBytesPruned { .. } => {
                AlarmLifetime::LatchedRederived
            }
            // The rest genuinely end when their condition does — sustained
            // recovery, a successful write, a complete consensus view, a
            // refresh that runs and re-pins.
            Self::TransportDegraded { .. }
            | Self::VanguardStateUnpersisted
            | Self::VanguardRepairSkipped { .. }
            | Self::ServeSetStale { .. }
            | Self::ServeSetRefreshFailing { .. }
            | Self::ServeSetPinsDropped { .. }
            | Self::ServeSetRolledBack { .. } => AlarmLifetime::Episode,
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
            Self::ServeSetStale { .. }
            | Self::ServeSetRefreshFailing { .. }
            | Self::ServeSetPinsDropped { .. }
            | Self::ServeSetRolledBack { .. }
            | Self::ServeSetBytesPruned { .. } => AlarmCondition::ServeSetIntegrity,
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

/// An alarm on the [`AlarmBoard`] — either currently live on its condition's
/// row, or sitting in the acknowledgment queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaisedAlarm {
    alarm: OperatorAlarm,
    incident: IncidentId,
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

    /// The condition this alarm reports on.
    #[must_use]
    pub fn condition(self) -> AlarmCondition {
        self.alarm.condition()
    }

    /// This alarm's lifetime class.
    #[must_use]
    pub fn lifetime(self) -> AlarmLifetime {
        self.alarm.lifetime()
    }
}

/// One condition's row on the board: whether it is being watched, and what is
/// wrong with it **right now**.
///
/// At most one live alarm, because that is what the producers can report — the
/// tor supervisor's `warning` is one `Option<ServiceWarning>` and its
/// `Degraded` is one state, so "two things wrong with this condition
/// simultaneously" is not an observation any producer can make. Faults that
/// happened and are awaiting acknowledgment are **not** here; see
/// [`AlarmBoard::unacknowledged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionState {
    arming: Arming,
    live: Option<RaisedAlarm>,
}

impl ConditionState {
    /// Whether this condition's tripwire can currently fire.
    #[must_use]
    pub fn arming(self) -> Arming {
        self.arming
    }

    /// The alarm live on this condition right now, if any.
    #[must_use]
    pub fn live(self) -> Option<RaisedAlarm> {
        self.live
    }
}

/// The operator-visible snapshot: every watched condition with its arming and
/// its live alarm, plus the queue of resolved faults awaiting acknowledgment.
///
/// An empty board means **nothing is being watched yet**, not that everything
/// is fine: rows appear when a producer starts reporting. A consumer that
/// renders "all clear" for a board with no rows has made the mistake this
/// module exists to prevent.
///
/// # Why the acknowledgment queue is not a per-condition field
///
/// A live alarm is a *status* — it belongs to a condition, and there is one of
/// it. A resolved latch is a *fact awaiting acknowledgment*, and several can be
/// outstanding at once: the vanguard set has three distinct integrity faults on
/// one [`AlarmCondition`], of which one latches, so a per-condition slot would
/// have to choose between the re-draw the operator has not seen yet and the
/// unrelated fault that happened afterwards. Keeping them in separate shapes is
/// what makes that choice not exist.
///
/// It also makes two properties structural rather than checked. A latch
/// survives its condition being disarmed, because it does not live on the
/// condition's row. And [`OperatorAlarms::acknowledge`] cannot be used to
/// silence a fault that is still happening, because a live alarm is not in the
/// queue to be acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlarmBoard {
    conditions: BTreeMap<AlarmCondition, ConditionState>,
    unacknowledged: Vec<RaisedAlarm>,
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

    /// Every currently-live alarm, in a stable order.
    pub fn live(&self) -> impl Iterator<Item = (AlarmCondition, RaisedAlarm)> + '_ {
        self.conditions
            .iter()
            .filter_map(|(c, s)| s.live.map(|r| (*c, r)))
    }

    /// Faults whose condition has cleared but which have not been acknowledged.
    ///
    /// Only [`AlarmLifetime::LatchedRederived`] alarms reach here — an
    /// [`AlarmLifetime::Episode`] leaves the board when its condition clears.
    /// Ordered oldest incident first: this is a queue a human works through, and
    /// the fault they have been unaware of longest is the one to show first.
    #[must_use]
    pub fn unacknowledged(&self) -> &[RaisedAlarm] {
        &self.unacknowledged
    }

    /// Nothing live and nothing outstanding. **Not** the same as an empty board
    /// — see the type docs.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.unacknowledged.is_empty() && self.conditions.values().all(|s| s.live.is_none())
    }

    /// The row this condition should have, created armed-and-quiet if absent.
    fn entry(&mut self, condition: AlarmCondition) -> &mut ConditionState {
        self.conditions.entry(condition).or_insert(ConditionState {
            arming: Arming::Armed,
            live: None,
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

    /// Acknowledge a resolved fault, removing it from the acknowledgment queue.
    ///
    /// Returns `false`, changing nothing, when no outstanding fault carries that
    /// [`IncidentId`]. Naming the incident is what makes an acknowledgment apply
    /// to the fault the operator actually read: one that arrived while they were
    /// reading cannot be dismissed unseen.
    ///
    /// **This is not a mute button, and that is structural rather than
    /// enforced.** A fault that is still happening is live on its condition's
    /// row and is not in this queue at all, so there is nothing here to
    /// acknowledge it with. Silencing a live fault is a UI concern; an embedder
    /// that wants it must implement muting, not tell the board an operator
    /// handled something they did not.
    ///
    /// [`AlarmLifetime::Episode`] alarms are never acknowledgeable for the same
    /// structural reason: they leave the board when their condition clears, so
    /// they never enter the queue.
    pub fn acknowledge(&self, incident: IncidentId) -> bool {
        let mut applied = false;
        self.board.send_if_modified(|board| {
            let Some(at) = board
                .unacknowledged
                .iter()
                .position(|r| r.incident == incident)
            else {
                return false;
            };
            board.unacknowledged.remove(at);
            applied = true;
            true
        });
        applied
    }

    /// Whether this condition currently has a live alarm.
    ///
    /// For producers that must distinguish "continue the open incident" from
    /// "open one" without disturbing the incident's payload — see
    /// [`tor_posture`], where a translator attaching mid-episode has no failure
    /// to report but must not leave the board reading healthy.
    pub(crate) fn is_live(&self, condition: AlarmCondition) -> bool {
        self.board
            .borrow()
            .condition(condition)
            .is_some_and(|s| s.live.is_some())
    }

    /// Mark a condition's tripwire as able to fire.
    pub(crate) fn arm(&self, condition: AlarmCondition) {
        self.set_arming(condition, Arming::Armed);
    }

    /// Mark a condition's tripwire as unable to fire, and say why.
    ///
    /// Does **not** touch the acknowledgment queue, and cannot: a latched fault
    /// does not live on the condition's row, so losing the ability to re-observe
    /// a condition can no longer discard the record of what it already did.
    pub(crate) fn disarm(&self, condition: AlarmCondition, reason: DisarmedReason) {
        self.set_arming(condition, Arming::Disarmed(reason));
    }

    /// Report a condition as live.
    ///
    /// Opens an incident if none is live for this condition. If one is live for
    /// the **same** alarm, the payload is updated in place and the incident id
    /// is kept — that is the "one fault, one incident" rule, and it is why a
    /// producer may call this every tick without leaking a cadence. A
    /// *different* alarm on the same condition replaces what is live, because a
    /// producer reporting B is reporting that A is no longer what is wrong.
    ///
    /// Replacing what is **live** never discards an outstanding fault: those are
    /// in the acknowledgment queue, which this does not touch except to *reclaim*
    /// a recurrence. A latched fault that is re-reported is the same unfixed
    /// problem observed again — `LatchedRederived` means exactly that the
    /// producer re-detects it on every start — so it returns to live carrying
    /// its original [`IncidentId`] rather than queueing a duplicate beside
    /// itself.
    pub(crate) fn raise(&self, alarm: OperatorAlarm) {
        let condition = alarm.condition();
        self.board.send_if_modified(|board| {
            // A recurrence of something still awaiting acknowledgment: take it
            // back out of the queue and keep its incident.
            let reclaimed = board
                .unacknowledged
                .iter()
                .position(|r| r.alarm == alarm)
                .map(|at| board.unacknowledged.remove(at).incident);

            let state = board.entry(condition);
            match state.live {
                Some(live) if same_fault(live.alarm, alarm) => {
                    if live.alarm == alarm && reclaimed.is_none() {
                        return false;
                    }
                    state.live = Some(RaisedAlarm {
                        alarm,
                        incident: live.incident,
                    });
                    true
                }
                _ => {
                    let incident = reclaimed.unwrap_or_else(|| {
                        IncidentId(self.next_incident.fetch_add(1, Ordering::Relaxed))
                    });
                    state.live = Some(RaisedAlarm { alarm, incident });
                    true
                }
            }
        });
    }

    /// Report a condition as no longer live.
    ///
    /// An [`AlarmLifetime::Episode`] alarm leaves the board. A
    /// [`AlarmLifetime::LatchedRederived`] one moves to the acknowledgment
    /// queue: the producer saying "it is fine now" is exactly the moment the
    /// evidence disappears, so it is the last moment at which dropping the
    /// report would be safe.
    pub(crate) fn clear(&self, condition: AlarmCondition) {
        self.board.send_if_modified(|board| {
            let Some(state) = board.conditions.get_mut(&condition) else {
                return false;
            };
            let Some(live) = state.live.take() else {
                return false;
            };
            match live.lifetime() {
                AlarmLifetime::Episode => true,
                AlarmLifetime::LatchedRederived => {
                    // Queue order is incident order, and incidents are minted
                    // monotonically, so pushing keeps oldest-first.
                    board.unacknowledged.push(live);
                    true
                }
            }
        });
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
}

/// Whether two alarms are the *same fault* — same variant, payload aside.
///
/// The payload is deliberately excluded: `TransportDegraded`'s cause is updated
/// on every failed retry, and a fresher cause for a fault that never stopped is
/// not a new fault.
fn same_fault(a: OperatorAlarm, b: OperatorAlarm) -> bool {
    std::mem::discriminant(&a) == std::mem::discriminant(&b)
}

// Test suite extracted so NEW_FILE_CAP / the 1k review bar measure the
// vocabulary and board, not their tests. Same pattern as the engine
// decomposition ratchet's EXCLUDE'd `#[path]` siblings.
#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

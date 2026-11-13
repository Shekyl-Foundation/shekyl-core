// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The typed read (`TSR-Q12`). Its words are `shekyl_tor_status`'s: the
//! supervisor's snapshot puts this read in the wire's shape, and that
//! crate's renderer is the one place it becomes words (`TSR-Q13`).

/// The connector settings the posture is read from. Not a config key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorSetting {
    /// `Tor::Off`.
    Off,
    /// `Tor::Managed`.
    Managed,
    /// `Tor::Operator`.
    Operator,
}

/// What the node was configured to connect with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connectors {
    /// The Tor setting.
    pub tor: TorSetting,
    /// Whether clearnet is on.
    pub clearnet_on: bool,
}

/// The relay's hop-0 verdict for a local origin, folded into this supervisor.
///
/// The relay names the same three states. This crate does not depend on the
/// relay: the daemon maps one onto the other, variant for variant.
///
/// [`Self::Absent`]: no outbound session hides this node's address.
/// [`Self::Connected`]: one does, and a local origin does not leave on it.
/// [`Self::Routable`]: a local origin leaves on one.
///
/// Health is [`Self::hides_address`]. `OwnTx` reads [`Self::origin_leaves`].
/// The pin stays off health (`RPC_CHANNEL.md` §6.1): a peer who held `health`
/// and was this node's own edge could otherwise watch the boolean flip on
/// its own disconnect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OriginVerdict {
    /// No outbound session hides this node's address.
    #[default]
    Absent,
    /// An outbound session hides this node's address, and a local origin
    /// does not leave on it.
    Connected,
    /// A local origin leaves on a session that hides this node's address.
    Routable,
}

impl OriginVerdict {
    /// An outbound session hides this node's address now.
    #[must_use]
    pub const fn hides_address(self) -> bool {
        !matches!(self, Self::Absent)
    }

    /// A local origin leaves on such a session now.
    #[must_use]
    pub const fn origin_leaves(self) -> bool {
        matches!(self, Self::Routable)
    }
}

/// What the node does with its own transactions (`TSR-Q11`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnTx {
    /// [`OriginVerdict::Routable`]: a local origin leaves on a session that
    /// hides this node's address.
    AddressHiding,
    /// The verdict does not route, and Tor is managed or an operator's Tor.
    /// Health may still be true ([`OriginVerdict::Connected`]). The
    /// transaction is held on this node, not sent.
    Held,
    /// The operator set Tor off and clearnet on.
    ClearnetOnly,
    /// Tor off and clearnet off.
    Offline,
}

/// A fix the posture offers. The wire carries the variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedTorFix {
    /// Stay managed and restore a bundle that passes the pin.
    RestoreManaged,
    /// Use a Tor the operator runs.
    Operator,
    /// Turn clearnet on. Tor stays managed.
    ClearnetOn,
    /// Turn Tor off and send over clearnet.
    ClearnetOnly,
}

/// The phase the posture line shows (§4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// Starting again after a process fault.
    Restarting,
    /// The spawn is waiting out the cap. A pin, a missing bundle, or no
    /// managed Tor on this platform.
    RestartingHeld,
    /// Tor has not reached a usable outbound link yet.
    Bootstrapping,
    /// The outbound link is usable.
    Usable,
    /// Tor is up and a facet is down.
    Degraded,
}

/// Why this node's onion is not reachable (`TOR_SUPERVISOR.md` §4.4,
/// Service class).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundCause {
    /// The probe of this node's own onion did not arrive within its bound.
    ProbeTimedOut,
    /// More than half of the latest round's directories refused its upload
    /// (`HS_DESC FAILED REASON=UPLOAD_REJECTED`): they hold a copy whose
    /// revision counter is not below this one's. A republish cannot help
    /// (§4.5, "Refused rounds").
    UploadsRefused,
    /// This computer's clock is behind the consensus's `valid-after` by more
    /// than the tolerance (§4.2; Rick, 2026-11-01). Tor numbers each
    /// descriptor from its own clock, so the directories refuse what this
    /// node uploads. `behind` is that lag, a lower bound, and
    /// [`Status::clock_behind`] is this field.
    ClockBehind {
        /// How far behind `valid-after` the wall clock was, at the latest
        /// sample that still named it.
        behind: std::time::Duration,
    },
    /// The probe arrived through this node's own copy of the descriptor,
    /// but the directories its uploads reached no longer had it (§4.5, the
    /// directory check).
    DescriptorNotFound,
}

/// Can peers reach this node's onion (`TOR_SUPERVISOR.md` §4.1), in the
/// caller's clock. Beside the outbound projection, never folded into
/// [`Cause`]: a blocked link and an unreachable onion can stand together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// No onion is offered in this posture, or none has been published yet.
    NotOffered,
    /// The onion is published, and no probe has arrived on this Tor yet;
    /// since `since`, in the core's clock.
    Publishing {
        /// When the onion became published, or the facet unknown again.
        since: u64,
    },
    /// The last probe arrived, at `evidence_at`.
    Reachable {
        /// When the probe's nonce came back.
        evidence_at: u64,
    },
    /// Not reachable since `since`, for `cause`. The onion is being
    /// published again.
    Unreachable {
        /// Why.
        cause: InboundCause,
        /// When the facet went down.
        since: u64,
    },
}

/// Tor's `CLOCK_SKEW` figure, in seconds. Negative is behind the network,
/// positive is ahead. Zero is said ahead: Tor did not report a direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportedSkew {
    /// `SKEW=`: Tor measured the difference.
    Measured(i64),
    /// `MIN_SKEW=`: Tor gave a lower bound, not a measure.
    AtLeast(i64),
}

impl ReportedSkew {
    /// The reported difference, in seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        match self {
            Self::Measured(seconds) | Self::AtLeast(seconds) => seconds,
        }
    }

    /// Behind the network. Zero and ahead are not.
    #[must_use]
    pub const fn is_behind(self) -> bool {
        self.seconds() < 0
    }
}

/// Why the phase is what it is. The detail is the variant (`TSR-Q12`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Nothing is wrong.
    None,
    /// Discovery found no bundle.
    BundleMissing,
    /// The pin refused the binary. It was not executed.
    PinRefused,
    /// This build has no managed Tor.
    Unavailable,
    /// A spawn that passed the pin did not come up.
    FailedStart,
    /// The process ended. `exit_code` is present when the reap reported one.
    Died {
        /// The process exit code, when the reap reported one.
        exit_code: Option<i32>,
    },
    /// The data directory could not be used (§5, "Data directory unusable").
    DirectoryUnusable {
        /// The shortfall, when the pre-spawn check found too little space.
        /// `None` when the directory itself could not be created or used.
        space: Option<Space>,
    },
    /// This machine cannot reach the Tor network.
    ExternalBlocked,
    /// No directory Tor knows answered.
    DirectoryUnreachable,
    /// Tor reported this computer's clock off by [`ReportedSkew`].
    ClockSkew {
        /// Tor's figure.
        skew: ReportedSkew,
    },
    /// Tor logged relays' certificates as expired or not yet valid, from
    /// enough distinct relays within the window that the clock, not a relay,
    /// is the cause (§4.2). Tor stated no offset.
    CertificatesOutOfDate,
    /// Tor hit the open-file limit.
    TooManyFiles {
        /// How many sockets Tor reported open.
        open: u64,
    },
    /// A control reply missed its bound.
    ReplyLate,
    /// The consensus does not recommend this Tor.
    DangerousVersion,
    /// Tor refused to publish this node's onion again after the onion was
    /// found unreachable (§4.4: a Service remedy whose control command
    /// failed escalates to a respawn).
    OnionRefused,
    /// Tor reported a clock jump during its bootstrap, and then neither its
    /// percent nor the bytes it read moved for the policy's bound: its
    /// retries were scheduled on the clock that was wrong. It is started
    /// again (§4.4).
    StrandedAfterClockJump,
}

/// Free space under Tor's data directory against what a spawn needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    /// Bytes this process can write there.
    pub available: u64,
    /// Bytes the spawn needs.
    pub needed: u64,
}

/// Whether the node is syncing, and over what (`TSR-Q12`): each connector
/// that holds a session now. Every session runs the timed sync, so one
/// held is the node in sync with a peer over that connector. Read live
/// from the session layer, never from the configuration: a clearnet that
/// is on and that no peer accepts carries nothing (alpha.11 finding 9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Syncing {
    /// A clearnet session is held.
    pub clearnet: bool,
    /// A Tor session is held.
    pub tor: bool,
}

/// The sessions each connector holds, as the session layer reports them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sessions {
    /// Clearnet sessions whose handshake has finished.
    pub clearnet: u32,
    /// Tor sessions whose handshake has finished.
    pub tor: u32,
}

impl Sessions {
    /// What the node syncs over: each connector that holds one.
    #[must_use]
    pub const fn syncing(self) -> Syncing {
        Syncing {
            clearnet: self.clearnet > 0,
            tor: self.tor > 0,
        }
    }
}

/// How a bootstrap is going, as of the last progress line (`TOR_SUPERVISOR.md`
/// §5, "Waiting on the Tor directory"): how long the percent has held, and
/// how much Tor read in the window. Bytes moving with the percent held is a
/// slow directory mirror; nothing moving is one that is not answering.
///
/// [`Self::pace`] classifies the line over the policy window
/// (`Policy::alive_every`). The measured [`Self::window`] can run longer
/// when a control ask held the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapLine {
    /// How long the percent has been unchanged.
    pub held_for: std::time::Duration,
    /// Bytes Tor read across [`Self::window`]. `None` when no sample reported
    /// a count: unknown, never zero.
    pub received: Option<u64>,
    /// The span [`Self::received`] covers: from the sample the window opens
    /// on to the moment the line was read. Not the policy interval: a
    /// control ask that held the driver makes it longer. It slides with
    /// every sample, so a client that polls Status reads it current to
    /// within one sample.
    pub window: std::time::Duration,
    /// The policy window this line is read over (`Policy::alive_every`).
    span: std::time::Duration,
}

impl BootstrapLine {
    /// The pace of this line over its policy window. The percent moving
    /// inside that window is [`BootstrapPace::Advancing`]. A full window of
    /// nothing is [`BootstrapPace::Stalled`]. Bytes arriving while the
    /// percent holds is [`BootstrapPace::SlowButNormal`]. `None` when no
    /// count was reported, or the quiet stretch is shorter than the window.
    #[must_use]
    pub fn pace(self) -> Option<BootstrapPace> {
        if self.held_for < self.span {
            return Some(BootstrapPace::Advancing);
        }
        match self.received {
            Some(0) if self.window >= self.span => Some(BootstrapPace::Stalled),
            Some(arrived) if arrived > 0 => Some(BootstrapPace::SlowButNormal),
            _ => None,
        }
    }
}

/// How a bootstrap is going, in one word a client can show (Rick,
/// 2026-10-24). A description, never a cause: it stands beside
/// [`Status::cause`], so "stalled" while Tor reports outbound blocked shows
/// both the stall and the fix. `shekyl_tor_status::render` composes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapPace {
    /// The percent moved within the window.
    Advancing,
    /// The percent held through the window and bytes arrived: a slow
    /// directory mirror can hold a bootstrap for minutes. Normal.
    SlowButNormal,
    /// A full window of samples in which nothing arrived.
    Stalled,
}

/// One `traffic/read` sample: when it was taken, and the cumulative count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReadMark {
    at: u64,
    bytes: u64,
}

/// The progress line's evidence: the percent, when it last moved, and the
/// recent `traffic/read` samples the sliding window reads.
///
/// The supervisor owns one of these per incarnation. The Tor connector never
/// sees it: the line is said from the control connection's samples
/// (`TSR-Q9`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressWindow {
    percent: u8,
    /// When `percent` last changed, in the caller's clock.
    progress_at: u64,
    /// The window the line reads over (`Policy::alive_every`).
    span: std::time::Duration,
    /// Samples that carried a count, oldest first. After [`Self::retain`],
    /// the front is the mark the window opens on.
    marks: std::collections::VecDeque<ReadMark>,
    /// Whether the line has begun: from the first progress deadline on, so
    /// the first line covers a whole window.
    begun: bool,
    line: Option<BootstrapLine>,
}

impl ProgressWindow {
    /// A new incarnation reading over `window`. The percent is 0 and no byte
    /// count has been seen.
    #[must_use]
    pub fn start(now: u64, window: std::time::Duration) -> Self {
        Self {
            percent: 0,
            progress_at: now,
            span: window,
            marks: std::collections::VecDeque::new(),
            begun: false,
            line: None,
        }
    }

    /// When the percent last changed, in the caller's clock.
    #[must_use]
    pub const fn moved_at(&self) -> u64 {
        self.progress_at
    }

    /// The last percent a sample or a bootstrap notice reported.
    #[must_use]
    pub const fn percent(&self) -> u8 {
        self.percent
    }

    /// The line as of the last refresh. `None` before the first progress
    /// deadline.
    #[must_use]
    pub const fn line(&self) -> Option<BootstrapLine> {
        self.line
    }

    /// The percent moved, or was confirmed. A confirmation does not reset
    /// how long the percent has held.
    pub fn note_percent(&mut self, percent: u8, now: u64) {
        if percent != self.percent {
            self.progress_at = now;
        }
        self.percent = percent;
        self.refresh(now);
    }

    /// A directory sample reported `traffic/read`. `None` adds no mark: a
    /// missing count is not a zero. A count that moved backwards starts the
    /// marks again rather than reading as a wrap.
    pub fn note_read(&mut self, read: Option<u64>, now: u64) {
        if let Some(bytes) = read {
            if self.marks.back().is_some_and(|mark| bytes < mark.bytes) {
                self.marks.clear();
            }
            self.marks.push_back(ReadMark { at: now, bytes });
        }
        self.refresh(now);
    }

    /// The machine slept (§5, "Resumed from suspend"): the percent's hold
    /// and the byte window start again from the wake, so the sleep reads as
    /// neither a held percent nor a window with nothing arriving.
    pub fn resumed(&mut self, now: u64) {
        self.progress_at = now;
        self.marks.clear();
        self.refresh(now);
    }

    /// The progress deadline: the line begins here and is said. From now on
    /// every sample keeps it current.
    pub fn speak(&mut self, now: u64) {
        self.begun = true;
        self.refresh(now);
    }

    /// Re-read the window as of `now`. [`Self::retain`] leaves the opening
    /// mark at the front: the newest sample at least one window old, or the
    /// oldest when every sample is later. The bytes run from that mark to
    /// the latest one, and the clock runs to `now`. At a sample, now is the
    /// sample.
    fn refresh(&mut self, now: u64) {
        self.retain(now.saturating_sub(self.span_ns()));
        if !self.begun {
            return;
        }
        let held = now.saturating_sub(self.progress_at);
        let (received, measured) = match self.marks.front().copied().zip(self.marks.back().copied())
        {
            Some((opening, latest)) => (
                Some(latest.bytes.saturating_sub(opening.bytes)),
                now.saturating_sub(opening.at),
            ),
            None => (None, 0),
        };
        self.line = Some(BootstrapLine {
            held_for: std::time::Duration::from_nanos(held),
            received,
            window: std::time::Duration::from_nanos(measured),
            span: self.span,
        });
    }

    /// Index of the mark the window opens on. The newest at or before
    /// `open`, or the oldest when every mark is later. `None` when no
    /// sample has carried a count.
    fn opening(&self, open: u64) -> Option<usize> {
        if self.marks.is_empty() {
            return None;
        }
        Some(
            self.marks
                .iter()
                .rposition(|mark| mark.at <= open)
                .unwrap_or(0),
        )
    }

    /// Drop marks older than [`Self::opening`], so the front is that mark.
    fn retain(&mut self, open: u64) {
        if let Some(index) = self.opening(open) {
            self.marks.drain(..index);
        }
    }

    fn span_ns(&self) -> u64 {
        u64::try_from(self.span.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// What the quiet line says, by the dialer's census (`TOR_SUPERVISOR.md`
/// §4.2; Rick, 2026-11-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorQuiet {
    /// The dialer holds no Tor address: no peer is known yet, so there is
    /// nothing to dial.
    NoPeersKnown,
    /// Peers are known, and none has answered through Tor since `since`, in
    /// nanoseconds on the core's clock: a Tor dial launched in the span
    /// failed. A reading, so the span is taken at the ask.
    Unanswered {
        /// When the held span began.
        since: u64,
    },
}

/// One typed read of the supervisor (`TSR-Q12`). No message text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// [`OriginVerdict::hides_address`]: an outbound session hides this
    /// node's address now. Not the link: [`Self::shown`] is the link.
    /// `health` can be true while [`Self::own_tx`] is [`OwnTx::Held`].
    pub health: bool,
    /// The §4.3 projection.
    pub shown: Shown,
    /// What the Tor behind the link carries now: the outbound facet, not
    /// the projection. An onion peers cannot reach, or a cause that is not
    /// an outbound one, leaves it carrying.
    pub carriage: Carriage,
    /// The typed cause.
    pub cause: Cause,
    /// When `shown` last changed, in the caller's clock units.
    pub since: u64,
    /// Process-fault respawns this boot.
    pub respawn_count: u32,
    /// What the node is syncing over.
    pub sync: Syncing,
    /// What happens to the node's own transactions.
    pub own_tx: OwnTx,
    /// Fixes offered for an install cause. Empty otherwise.
    pub fixes: Vec<ManagedTorFix>,
    /// The last bootstrap percent. Telemetry for the posture line.
    pub progress: u8,
    /// The bootstrap's progress line. Only while bootstrapping, once the
    /// first window has passed.
    pub bootstrap: Option<BootstrapLine>,
    /// How the bootstrap is going, beside [`Self::cause`], never instead of
    /// it. Only while bootstrapping, once the first window has passed.
    pub pace: Option<BootstrapPace>,
    /// The quiet line, while Tor runs and names no cause (§4.2).
    /// [`TorQuiet::NoPeersKnown`] is an empty census once `quiet_after` has
    /// passed. [`TorQuiet::Unanswered`] is a non-empty run whose held span
    /// has reached `quiet_after` with a Tor dial launched inside it that
    /// failed. A neutral fact, never a cause. [`TorQuiet::Unanswered`]
    /// carries when that held span began.
    pub tor_quiet: Option<TorQuiet>,
    /// Whether peers can reach this node's onion (§4.1). Its cause stands
    /// beside [`Self::cause`], never instead of it.
    pub inbound: Inbound,
    /// Descriptor rounds this boot that were still open after five minutes:
    /// uploads with neither `UPLOADED` nor `FAILED`, none of the events lost
    /// on our side. Telemetry for the soak, never a cause (§10).
    pub stuck_upload_rounds: u32,
    /// How far this computer's clock is behind the consensus's
    /// `valid-after` while [`InboundCause::ClockBehind`] stands: a lower
    /// bound. `None` otherwise.
    pub clock_behind: Option<std::time::Duration>,
}

/// `OwnTx` from the relay's hop-0 verdict and the connector settings.
///
/// [`OriginVerdict::Routable`] is [`OwnTx::AddressHiding`]. Every other
/// state follows the connector pair.
#[must_use]
pub fn own_tx(verdict: OriginVerdict, connectors: Connectors) -> OwnTx {
    if verdict.origin_leaves() {
        return OwnTx::AddressHiding;
    }
    match (connectors.tor, connectors.clearnet_on) {
        (TorSetting::Off, true) => OwnTx::ClearnetOnly,
        (TorSetting::Off, false) => OwnTx::Offline,
        (TorSetting::Managed | TorSetting::Operator, _) => OwnTx::Held,
    }
}

/// Fixes for an install cause (§5). Empty for every other cause, including
/// a Tor that is bootstrapping, degraded, or restarting after a process fault.
#[must_use]
pub fn fixes(cause: &Cause, connectors: Connectors) -> Vec<ManagedTorFix> {
    if connectors.tor != TorSetting::Managed || !install_cause(cause) {
        return Vec::new();
    }
    let mut offered = vec![ManagedTorFix::RestoreManaged, ManagedTorFix::Operator];
    if !connectors.clearnet_on {
        offered.push(ManagedTorFix::ClearnetOn);
    }
    offered.push(ManagedTorFix::ClearnetOnly);
    offered
}

/// The install rows that carry `ManagedTorFix` (§5). A missing directory
/// does not: the row names no fix.
fn install_cause(cause: &Cause) -> bool {
    matches!(
        cause,
        Cause::BundleMissing | Cause::PinRefused | Cause::Unavailable
    )
}

/// What the Tor behind the link carries (`TSR-Q12`). The core reads it
/// from the phase and the outbound facet, never from [`Shown`]: the
/// projection shows an unreachable onion, or a cause that is no outbound
/// one, as degraded while the link still carries everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carriage {
    /// The outbound facet is usable: Tor runs, the route is installed, and
    /// no outbound cause stands. The link carries traffic, and the node is
    /// not waiting for Tor whatever its onion's reachability or a cause
    /// such as a version warning says.
    Carries,
    /// Tor runs with its route installed, and an outbound cause stands: the
    /// Tor that holds the open connections is still running, and a sentence
    /// that it carries the traffic would contradict the cause that follows
    /// (the VM suspend, 2026-10-30).
    OpenOnly,
    /// Tor is not running with its route installed: restarting,
    /// bootstrapping a new process, or rebuilding after a clock jump. The
    /// connections the earlier link held carry nothing, and the node is
    /// held until Tor is back, as the verdict will say once the relay sees
    /// the sessions close.
    Gone,
}

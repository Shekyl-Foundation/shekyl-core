// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The typed read and the one renderer (`TSR-Q12`, `TSR-Q13`).
//!
//! The wire carries the variants. [`render`] is the only place those
//! variants become words.

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
        /// The directory, the daemon's data directory Tor's lives under.
        path: std::path::PathBuf,
        /// The shortfall, when the pre-spawn check found too little space.
        /// `None` when the directory itself could not be created or used.
        space: Option<Space>,
    },
    /// This machine cannot reach the Tor network.
    ExternalBlocked,
    /// No directory Tor knows answered.
    DirectoryUnreachable,
    /// A source reported the clock this far off, in seconds.
    ClockSkew {
        /// The reported difference, in seconds.
        seconds: i64,
    },
    /// Tor hit the open-file limit.
    TooManyFiles {
        /// How many sockets Tor reported open.
        open: u64,
    },
    /// A control reply missed its bound.
    ReplyLate,
    /// The consensus does not recommend this Tor.
    DangerousVersion,
}

/// Free space under Tor's data directory against what a spawn needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    /// Bytes this process can write there.
    pub available: u64,
    /// Bytes the spawn needs.
    pub needed: u64,
}

/// Whether the node is syncing, and over what (`TSR-Q12`).
///
/// `clearnet` is the configured clearnet connector and `tor` is health.
/// A chain-sync feed replaces those two reads in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syncing {
    /// Syncing over clearnet.
    pub clearnet: bool,
    /// Syncing over Tor.
    pub tor: bool,
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
        BootstrapReading::classify(Some(self)).pace()
    }
}

/// How a bootstrap is going, in one word a client can show (Rick,
/// 2026-10-24). A description, never a cause: it stands beside
/// [`Status::cause`], so "stalled" while Tor reports outbound blocked shows
/// both the stall and the fix. [`render`] composes them.
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

/// One typed read of the supervisor (`TSR-Q12`). No message text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// [`OriginVerdict::hides_address`]: an outbound session hides this
    /// node's address now. Not the link: [`Self::shown`] is the link.
    /// `health` can be true while [`Self::own_tx`] is [`OwnTx::Held`].
    pub health: bool,
    /// The §4.3 projection.
    pub shown: Shown,
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
    /// How long no Tor connection has been open and none has opened, while
    /// Tor runs, names no cause, and this node's Tor dials keep failing
    /// (§4.2). A neutral fact for the posture line, never a cause.
    pub tor_quiet: Option<std::time::Duration>,
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

/// The words for an install cause: a missing bundle, a refused pin, or no
/// managed Tor on this platform.
///
/// [`render`] and the daemon's pin warning both speak these. `None` for
/// every other cause, whose sentence reads the rest of a [`Status`]. The
/// paths a missed discovery searched are not a cause field; the pin error
/// carries them, and the warning prints that error beside this sentence.
#[must_use]
pub fn install_sentence(cause: &Cause) -> Option<&'static str> {
    match cause {
        Cause::BundleMissing => Some("No Tor was found beside the daemon."),
        Cause::PinRefused => {
            Some("The Tor that was found failed its check, so it was not started.")
        }
        Cause::Unavailable => Some("This release has no Tor for this platform yet."),
        Cause::None
        | Cause::FailedStart
        | Cause::Died { .. }
        | Cause::DirectoryUnusable { .. }
        | Cause::ExternalBlocked
        | Cause::DirectoryUnreachable
        | Cause::ClockSkew { .. }
        | Cause::TooManyFiles { .. }
        | Cause::ReplyLate
        | Cause::DangerousVersion => None,
    }
}

/// The line, classified once. [`BootstrapLine::pace`] and the bootstrap
/// sentence both read this, so the word and the prose cannot disagree.
enum BootstrapReading {
    /// No line yet: the percent, and nothing about bytes.
    Fetching,
    /// The percent moved inside the span. Bytes are said only when some arrived.
    Advancing {
        arrived: Option<u64>,
        window: std::time::Duration,
    },
    /// The percent held, and this many bytes arrived.
    SlowButNormal {
        arrived: u64,
        held_for: std::time::Duration,
        window: std::time::Duration,
    },
    /// A full span in which nothing arrived.
    Stalled {
        held_for: std::time::Duration,
        window: std::time::Duration,
    },
    /// The percent held, and the bytes cannot be called.
    Held { held_for: std::time::Duration },
}

impl BootstrapReading {
    fn classify(line: Option<BootstrapLine>) -> Self {
        let Some(line) = line else {
            return Self::Fetching;
        };
        if line.held_for < line.span {
            return Self::Advancing {
                arrived: line.received.filter(|bytes| *bytes > 0),
                window: line.window,
            };
        }
        match line.received {
            Some(0) if line.window >= line.span => Self::Stalled {
                held_for: line.held_for,
                window: line.window,
            },
            Some(arrived) if arrived > 0 => Self::SlowButNormal {
                arrived,
                held_for: line.held_for,
                window: line.window,
            },
            _ => Self::Held {
                held_for: line.held_for,
            },
        }
    }

    fn pace(self) -> Option<BootstrapPace> {
        match self {
            Self::Fetching | Self::Held { .. } => None,
            Self::Advancing { .. } => Some(BootstrapPace::Advancing),
            Self::SlowButNormal { .. } => Some(BootstrapPace::SlowButNormal),
            Self::Stalled { .. } => Some(BootstrapPace::Stalled),
        }
    }

    fn sentence(self, progress: u8) -> String {
        let fetching = format!("Tor is fetching the network directory ({progress}%)");
        match self {
            Self::Fetching | Self::Advancing { arrived: None, .. } => format!("{fetching}."),
            Self::Advancing {
                arrived: Some(bytes),
                window,
            } => format!(
                "{fetching}. {} arrived in the last {}.",
                spoken_bytes(bytes),
                spoken_duration(window)
            ),
            Self::SlowButNormal {
                arrived,
                held_for,
                window,
            } => format!(
                "{fetching}, unchanged for {}. {} arrived in the last {}; a slow directory mirror can hold this for minutes.",
                spoken_duration(held_for),
                spoken_bytes(arrived),
                spoken_duration(window)
            ),
            Self::Stalled { held_for, window } => format!(
                "{fetching}, unchanged for {}. Nothing arrived in the last {}.",
                spoken_duration(held_for),
                spoken_duration(window)
            ),
            Self::Held { held_for } => {
                format!("{fetching}, unchanged for {}.", spoken_duration(held_for))
            }
        }
    }
}

/// The one renderer (`TSR-Q13`). Behaviour, then a named cause, then the
/// bootstrap line, then the fixes, in the posture table's order.
///
/// The bootstrap line is its own clause. A named cause shows the phase as
/// degraded, and the line is what still marks the bootstrap, so the stall
/// follows the cause and its fix.
#[must_use]
pub fn render(status: &Status) -> String {
    let mut text = behaviour(status);
    if let Some(cause) = named_cause(status) {
        append(&mut text, &cause);
    } else if let Some(quiet) = quiet_sentence(status) {
        append(&mut text, &quiet);
    }
    if speaks_bootstrap(status) {
        append(
            &mut text,
            &BootstrapReading::classify(status.bootstrap).sentence(status.progress),
        );
    }
    if !status.fixes.is_empty() {
        append(&mut text, &fixes_sentence(&status.fixes));
    }
    text
}

/// The bootstrap sentence is said while the phase shows bootstrapping, and
/// while a progress line is present.
fn speaks_bootstrap(status: &Status) -> bool {
    status.bootstrap.is_some() || status.shown == Shown::Bootstrapping
}

fn behaviour(status: &Status) -> String {
    match status.own_tx {
        OwnTx::AddressHiding => "Tor is carrying this node's traffic.".to_owned(),
        OwnTx::Held => held_sentence(status.sync),
        OwnTx::ClearnetOnly => "This node is syncing and sending over the open network. Until the encrypted link is in place, that network is unencrypted.".to_owned(),
        OwnTx::Offline => "This node is offline.".to_owned(),
    }
}

fn append(text: &mut String, sentence: &str) {
    text.push(' ');
    text.push_str(sentence);
}

fn spoken_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds} s")
    } else {
        format!("{} min {} s", seconds / 60, seconds % 60)
    }
}

fn spoken_bytes(bytes: u64) -> String {
    // CLIPPY: a display figure; a byte count below 2^52 is exact in f64.
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes < 1_000 {
        format!("{bytes} bytes")
    } else if bytes < 1_000_000 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{:.1} MB", value / 1e6)
    }
}

/// The `Held` sentence. The node is "waiting for Tor" only while the link
/// is not usable; a held origin beside a usable link (no address-hiding peer
/// yet, or the epoch's pin exhausted) is holding, not waiting. What the node
/// syncs over is read from `sync`, never assumed from the hold; the typed
/// reason for the hold is `GS-C2`'s (IG-Q72).
///
/// [`render`] speaks this for a held status. The daemon's pin warning
/// speaks it too, with `tor` false: the link is not up, and `clearnet` is
/// the connector.
#[must_use]
pub fn held_sentence(sync: Syncing) -> String {
    let syncing = match (sync.tor, sync.clearnet) {
        (true, true) => "It is syncing over Tor and clearnet.",
        (true, false) => "It is syncing over Tor.",
        (false, true) => "It is syncing over clearnet.",
        (false, false) => "It is not syncing.",
    };
    if sync.tor {
        format!("This node is holding its own transactions. {syncing}")
    } else {
        format!("This node is waiting for Tor and holding its own transactions. {syncing}")
    }
}

/// The quiet fact, said only when the bootstrap line is not. A running Tor
/// that still shows as bootstrapping keeps the fetching sentence.
fn quiet_sentence(status: &Status) -> Option<String> {
    if speaks_bootstrap(status) {
        return None;
    }
    status.tor_quiet.map(|quiet| {
        format!(
            "No connection through Tor is open, and none has opened in {}.",
            spoken_duration(quiet)
        )
    })
}

/// The named cause. [`Cause::None`] is the absence of one: the bootstrap
/// line and the quiet fact are [`render`]'s other clauses.
fn named_cause(status: &Status) -> Option<String> {
    match &status.cause {
        Cause::None => None,
        Cause::BundleMissing | Cause::PinRefused | Cause::Unavailable => {
            install_sentence(&status.cause).map(str::to_owned)
        }
        Cause::FailedStart => Some("Tor did not start.".to_owned()),
        Cause::Died { exit_code } => Some(died_sentence(status.respawn_count, *exit_code)),
        Cause::DirectoryUnusable { path, space } => Some(match space {
            Some(space) => format!(
                "Tor's data directory {} has {} free and Tor needs {}. Free space there.",
                path.display(),
                spoken_bytes(space.available),
                spoken_bytes(space.needed)
            ),
            None => format!("Tor's data directory {} could not be used.", path.display()),
        }),
        Cause::ExternalBlocked | Cause::DirectoryUnreachable => Some(
            "This machine cannot reach the Tor network. Check the firewall or the network."
                .to_owned(),
        ),
        Cause::ClockSkew { seconds } => Some(format!(
            "The clock is off by {seconds} seconds. Check time sync."
        )),
        Cause::TooManyFiles { open } => Some(format!(
            "Tor reached the open-file limit ({open} open). Raise the limit."
        )),
        Cause::ReplyLate => Some("Tor stopped answering and is being started again.".to_owned()),
        Cause::DangerousVersion => {
            Some("Upgrade Shekyl when a release updates the bundled Tor.".to_owned())
        }
    }
}

fn died_sentence(count: u32, exit_code: Option<i32>) -> String {
    if count <= 1 {
        return "Tor stopped and is being started again.".to_owned();
    }
    match exit_code {
        Some(code) => format!(
            "Tor has stopped {count} times. The last exit code was {code}. It is being started again."
        ),
        None => format!("Tor has stopped {count} times and is being started again."),
    }
}

fn fixes_sentence(fixes: &[ManagedTorFix]) -> String {
    let mut parts = Vec::new();
    for fix in fixes {
        parts.push(match fix {
            ManagedTorFix::RestoreManaged => {
                "Restore the bundled Tor, or name one that passes its check."
            }
            ManagedTorFix::Operator => "Or use a Tor you run yourself.",
            ManagedTorFix::ClearnetOn => "Or turn clearnet on and keep Tor managed.",
            ManagedTorFix::ClearnetOnly => {
                "Or turn Tor off and send over the open network. Until the encrypted link is in place, that network is unencrypted."
            }
        });
    }
    parts.join(" ")
}

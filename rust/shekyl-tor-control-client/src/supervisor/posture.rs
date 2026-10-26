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
    span: u64,
    /// `(when, traffic/read)` for the samples that carried a count, oldest
    /// first: those inside the window and the newest one before it.
    marks: std::collections::VecDeque<(u64, u64)>,
    /// Whether the line has begun: from the first progress deadline on, so
    /// the first line covers a whole window.
    begun: bool,
    line: Option<BootstrapLine>,
    pace: Option<BootstrapPace>,
}

impl ProgressWindow {
    /// A new incarnation reading over `window`. The percent is 0 and no byte
    /// count has been seen.
    #[must_use]
    pub fn start(now: u64, window: std::time::Duration) -> Self {
        Self {
            percent: 0,
            progress_at: now,
            span: u64::try_from(window.as_nanos()).unwrap_or(u64::MAX),
            marks: std::collections::VecDeque::new(),
            begun: false,
            line: None,
            pace: None,
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

    /// The pace as of the last refresh. `None` before the first progress
    /// deadline, and while the evidence cannot tell.
    #[must_use]
    pub const fn pace(&self) -> Option<BootstrapPace> {
        self.pace
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
            if self.marks.back().is_some_and(|&(_, last)| bytes < last) {
                self.marks.clear();
            }
            self.marks.push_back((now, bytes));
            let open = now.saturating_sub(self.span);
            while self.marks.len() > 1 && self.marks[1].0 <= open {
                self.marks.pop_front();
            }
        }
        self.refresh(now);
    }

    /// The progress deadline: the line begins here and is said. From now on
    /// every sample keeps it current.
    pub fn speak(&mut self, now: u64) {
        self.begun = true;
        self.refresh(now);
    }

    /// Re-read the window as of `now`. The window opens on the newest
    /// sample at least one window old (the oldest, until there is one) and
    /// runs to `now`, the moment the line is read: the bytes from that
    /// sample to the latest one, the clock to now. At a sample, now is the
    /// sample.
    fn refresh(&mut self, now: u64) {
        if !self.begun {
            return;
        }
        let held = now.saturating_sub(self.progress_at);
        let open = now.saturating_sub(self.span);
        let opening = self
            .marks
            .iter()
            .rev()
            .find(|&&(at, _)| at <= open)
            .or_else(|| self.marks.front());
        let (received, window) = match (opening, self.marks.back()) {
            (Some(&(opened, then)), Some(&(_, read))) => {
                (Some(read.saturating_sub(then)), now.saturating_sub(opened))
            }
            _ => (None, 0),
        };
        self.line = Some(BootstrapLine {
            held_for: std::time::Duration::from_nanos(held),
            received,
            window: std::time::Duration::from_nanos(window),
        });
        self.pace = if held < self.span {
            Some(BootstrapPace::Advancing)
        } else {
            match received {
                Some(0) if window >= self.span => Some(BootstrapPace::Stalled),
                Some(bytes) if bytes > 0 => Some(BootstrapPace::SlowButNormal),
                _ => None,
            }
        };
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

/// The one renderer (`TSR-Q13`). Behaviour, then the cause, then the fixes
/// in the posture table's order.
#[must_use]
pub fn render(status: &Status) -> String {
    let mut text = String::new();
    match status.own_tx {
        OwnTx::AddressHiding => text.push_str("Tor is carrying this node's traffic."),
        OwnTx::Held => text.push_str(&held_sentence(status.sync)),
        OwnTx::ClearnetOnly => text.push_str(
            "This node is syncing and sending over the open network. Until the encrypted link is in place, that network is unencrypted.",
        ),
        OwnTx::Offline => text.push_str("This node is offline."),
    }
    if let Some(cause) = cause_sentence(status) {
        text.push(' ');
        text.push_str(&cause);
    }
    if !status.fixes.is_empty() {
        text.push(' ');
        text.push_str(&fixes_sentence(&status.fixes));
    }
    text
}

fn bootstrap_sentence(
    progress: u8,
    line: Option<BootstrapLine>,
    pace: Option<BootstrapPace>,
) -> String {
    let Some(line) = line else {
        return format!("Tor is fetching the network directory ({progress}%).");
    };
    let window = spoken_duration(line.window);
    match (pace, line.received) {
        (Some(BootstrapPace::Advancing), Some(bytes)) if bytes > 0 => format!(
            "Tor is fetching the network directory ({progress}%). {} arrived in the last {window}.",
            spoken_bytes(bytes)
        ),
        (Some(BootstrapPace::Advancing), _) => {
            format!("Tor is fetching the network directory ({progress}%).")
        }
        (Some(BootstrapPace::SlowButNormal), Some(bytes)) => format!(
            "Tor is fetching the network directory ({progress}%, unchanged for {}). {} arrived in the last {window}; a slow directory mirror can hold this for minutes.",
            spoken_duration(line.held_for),
            spoken_bytes(bytes)
        ),
        (Some(BootstrapPace::Stalled), _) => format!(
            "Tor is fetching the network directory ({progress}%, unchanged for {}). Nothing arrived in the last {window}.",
            spoken_duration(line.held_for)
        ),
        _ => format!(
            "Tor is fetching the network directory ({progress}%, unchanged for {}).",
            spoken_duration(line.held_for)
        ),
    }
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

fn cause_sentence(status: &Status) -> Option<String> {
    let sentence = match &status.cause {
        Cause::None if status.shown == Shown::Bootstrapping => Some(bootstrap_sentence(
            status.progress,
            status.bootstrap,
            status.pace,
        )),
        Cause::None => status.tor_quiet.map(|quiet| {
            format!(
                "No connection through Tor is open, and none has opened in {}.",
                spoken_duration(quiet)
            )
        }),
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
    };
    // The pace stands beside a cause, never instead of it: a bootstrap that
    // has stalled while Tor reports the network blocked says the cause, its
    // fix, and the stall. The line exists only while bootstrapping; a named
    // external cause shows the phase as Degraded, so the phase is read from
    // the line, not from `shown`.
    match (sentence, &status.cause, status.bootstrap) {
        (Some(cause), named, Some(line)) if *named != Cause::None => Some(format!(
            "{cause} {}",
            bootstrap_sentence(status.progress, Some(line), status.pace)
        )),
        (sentence, ..) => sentence,
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

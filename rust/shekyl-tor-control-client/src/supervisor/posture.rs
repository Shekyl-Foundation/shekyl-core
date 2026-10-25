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
    /// Bytes Tor read across [`Self::window`]. `None` when no sample in that
    /// span reported a count: unknown, never zero.
    pub received: Option<u64>,
    /// The span [`Self::received`] covers, from the byte mark to the moment
    /// this line was said. Not the policy interval: a control ask that held
    /// the driver makes the span longer than the deadline.
    pub window: std::time::Duration,
}

/// The progress line's evidence. The percent, when it last moved, and the
/// byte mark the next line measures from.
///
/// The supervisor owns one of these per incarnation. The Tor connector never
/// sees it: the line is said from the control connection's samples
/// (`TSR-Q9`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressWindow {
    percent: u8,
    /// When `percent` last changed, in the caller's clock.
    progress_at: u64,
    /// When the current byte window opened.
    opened_at: u64,
    /// Latest `traffic/read` this incarnation.
    latest: Option<u64>,
    /// `traffic/read` at `opened_at`.
    baseline: Option<u64>,
    line: Option<BootstrapLine>,
}

impl ProgressWindow {
    /// A new incarnation. The percent is 0 and no byte count has been seen.
    #[must_use]
    pub const fn start(now: u64) -> Self {
        Self {
            percent: 0,
            progress_at: now,
            opened_at: now,
            latest: None,
            baseline: None,
            line: None,
        }
    }

    /// The last percent a sample or a bootstrap notice reported.
    #[must_use]
    pub const fn percent(self) -> u8 {
        self.percent
    }

    /// The last line [`Self::speak`] produced.
    #[must_use]
    pub const fn line(self) -> Option<BootstrapLine> {
        self.line
    }

    /// The percent moved, or was confirmed. A confirmation does not reset
    /// how long the percent has held.
    pub fn note_percent(&mut self, percent: u8, now: u64) {
        if percent != self.percent {
            self.progress_at = now;
        }
        self.percent = percent;
    }

    /// A directory sample reported `traffic/read`. `None` leaves the marks
    /// where they are: a missing count is not a zero, and it is not a new
    /// window. The first count opens the window at `now`.
    pub fn note_read(&mut self, read: Option<u64>, now: u64) {
        let Some(bytes) = read else {
            return;
        };
        self.latest = Some(bytes);
        if self.baseline.is_none() {
            self.baseline = Some(bytes);
            self.opened_at = now;
        }
    }

    /// Say the line as of `now`. `received` and `window` are the same span:
    /// from the open mark to `now`. The next line measures from here.
    /// A count that moved backwards saturates to nothing rather than wrapping.
    pub fn speak(&mut self, now: u64) {
        let received = match (self.latest, self.baseline) {
            (Some(read), Some(then)) => Some(read.saturating_sub(then)),
            _ => None,
        };
        self.line = Some(BootstrapLine {
            held_for: std::time::Duration::from_nanos(now.saturating_sub(self.progress_at)),
            received,
            window: std::time::Duration::from_nanos(now.saturating_sub(self.opened_at)),
        });
        self.baseline = self.latest;
        self.opened_at = now;
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

fn bootstrap_sentence(progress: u8, line: Option<BootstrapLine>) -> String {
    let Some(line) = line else {
        return format!("Tor is fetching the network directory ({progress}%).");
    };
    let mut text = format!(
        "Tor is fetching the network directory ({progress}%, unchanged for {}).",
        spoken_duration(line.held_for)
    );
    let window = spoken_duration(line.window);
    match line.received {
        Some(0) => text.push_str(&format!(" Nothing arrived in the last {window}.")),
        Some(bytes) => text.push_str(&format!(
            " {} arrived in the last {window}; a slow directory mirror can hold this for minutes.",
            spoken_bytes(bytes)
        )),
        None => {}
    }
    text
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
        Cause::None if status.shown == Shown::Bootstrapping => {
            Some(bootstrap_sentence(status.progress, status.bootstrap))
        }
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
    sentence
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

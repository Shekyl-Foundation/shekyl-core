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

/// What the node does with its own transactions (`TSR-Q11`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnTx {
    /// Health is true: originated traffic goes out over Tor.
    AddressHiding,
    /// Health is false and Tor is managed or an operator's Tor.
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
    /// The data directory could not be used.
    DirectoryUnusable,
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

/// One typed read of the supervisor (`TSR-Q12`). No message text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// True when the Tor link's outbound facet is usable.
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
}

/// `OwnTx` from health and the connector settings.
#[must_use]
pub fn own_tx(health: bool, connectors: Connectors) -> OwnTx {
    if health {
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

/// What the node does with its own transactions while Tor is not carrying
/// them and Tor was asked for (`OwnTx::Held`).
///
/// `clearnet_on` is the clearnet connector, the same bit [`Syncing::clearnet`]
/// reads until a chain-sync feed replaces it. The daemon's pin warning uses
/// this sentence too: at the warning, Tor is not up yet.
#[must_use]
pub const fn held_sentence(clearnet_on: bool) -> &'static str {
    if clearnet_on {
        "This node is syncing over clearnet and holding its own transactions."
    } else {
        "This node is waiting for Tor and holding its own transactions. It is not syncing."
    }
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
        | Cause::DirectoryUnusable
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
        OwnTx::Held => text.push_str(held_sentence(status.sync.clearnet)),
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

fn cause_sentence(status: &Status) -> Option<String> {
    let sentence = match &status.cause {
        Cause::None if status.shown == Shown::Bootstrapping => Some(format!(
            "Tor is fetching the network directory ({progress}%).",
            progress = status.progress
        )),
        Cause::None => None,
        Cause::BundleMissing | Cause::PinRefused | Cause::Unavailable => {
            install_sentence(&status.cause).map(str::to_owned)
        }
        Cause::FailedStart => Some("Tor did not start.".to_owned()),
        Cause::Died { exit_code } => Some(died_sentence(status.respawn_count, *exit_code)),
        Cause::DirectoryUnusable => Some("Tor's data directory could not be used.".to_owned()),
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

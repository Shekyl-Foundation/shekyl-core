// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The supervisor's status in the wire's shape
//! (`docs/design/TOR_STATUS_CRATE.md` §5).
//!
//! [`snapshot`] is the one place the supervisor's typed read becomes
//! `shekyl_tor_status::TorStatus`. Its clock readings (when the state began,
//! when the onion's state began, when the last probe came back) become ages
//! at `now`, the moment the status is asked, on the clock the supervisor's
//! own windows run on: awake time (IG-Q93, IG-Q96). Nothing it returns is a
//! clock reading.

use shekyl_tor_status::{self as wire, TorStatus};

use super::posture::{
    BootstrapPace, Carriage, Cause, Connectors, Inbound, InboundCause, ManagedTorFix, OwnTx,
    ReportedSkew, Shown, Status, TorQuiet, TorSetting,
};

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Whole seconds from `since` to `now`, both in the core's clock.
fn age(since: u64, now: u64) -> u64 {
    now.saturating_sub(since) / NANOS_PER_SECOND
}

/// `status`, read at `now`, under `connectors`, in the wire's shape.
#[must_use]
pub fn snapshot(status: &Status, connectors: Connectors, now: u64) -> TorStatus {
    TorStatus {
        posture: wire::Posture {
            tor: tor_setting(connectors.tor),
            clearnet: if connectors.clearnet_on {
                wire::Clearnet::On
            } else {
                wire::Clearnet::Off
            },
        },
        origination: origination(status),
        sync_connector: [
            (status.sync.clearnet, wire::Connector::Clearnet),
            (status.sync.tor, wire::Connector::Tor),
        ]
        .into_iter()
        .filter_map(|(on, connector)| on.then_some(connector))
        .collect(),
        tor_quiet: status.tor_quiet.map(|quiet| match quiet {
            TorQuiet::NoPeersKnown => wire::TorQuiet::Empty,
            TorQuiet::Unanswered(span) => wire::TorQuiet::Failing {
                age: span.as_secs(),
            },
        }),
        tor: (connectors.tor == TorSetting::Managed).then(|| managed(status, now)),
    }
}

fn tor_setting(setting: TorSetting) -> wire::TorSetting {
    match setting {
        TorSetting::Managed => wire::TorSetting::Managed,
        TorSetting::Operator => wire::TorSetting::Operator,
        TorSetting::Off => wire::TorSetting::Off,
    }
}

/// `OwnTx`, with `Held` split by the relay's verdict: a session that hides
/// the address and an exhausted pin is rebuilding; none is connecting
/// (IG-Q68).
fn origination(status: &Status) -> wire::Origination {
    match status.own_tx {
        OwnTx::AddressHiding => wire::Origination::AddressHiding,
        OwnTx::Held if status.health => wire::Origination::Rebuilding,
        OwnTx::Held => wire::Origination::Connecting,
        OwnTx::ClearnetOnly => wire::Origination::ClearnetOnly,
        OwnTx::Offline => wire::Origination::Offline,
    }
}

fn managed(status: &Status, now: u64) -> wire::ManagedTor {
    // The bootstrap is spoken of while the state is bootstrapping and while
    // a reading stands; the percent is on the wire exactly then, because
    // the renderer reads it then.
    let speaks_bootstrap = status.bootstrap.is_some() || status.shown == Shown::Bootstrapping;
    wire::ManagedTor {
        state: match status.shown {
            Shown::Restarting => wire::TorState::Restarting,
            Shown::RestartingHeld => wire::TorState::Waiting,
            Shown::Bootstrapping => wire::TorState::Bootstrapping,
            Shown::Usable => wire::TorState::Usable,
            Shown::Degraded => wire::TorState::Impaired,
        },
        cause: wire_cause(&status.cause),
        age: age(status.since, now),
        respawn_count: status.respawn_count,
        progress: speaks_bootstrap.then_some(status.progress),
        flagged: status.cause == Cause::DangerousVersion,
        fix: status
            .fixes
            .iter()
            .map(|fix| match fix {
                ManagedTorFix::RestoreManaged => wire::Fix::RestoreManaged,
                ManagedTorFix::Operator => wire::Fix::Operator,
                ManagedTorFix::ClearnetOn => wire::Fix::ClearnetOn,
                ManagedTorFix::ClearnetOnly => wire::Fix::ClearnetOnly,
            })
            .collect(),
        onion: onion(status.inbound, now),
        bootstrap: status.bootstrap.map(|line| wire::Bootstrap {
            pace: match status.pace {
                Some(BootstrapPace::Advancing) => wire::Pace::Advancing,
                Some(BootstrapPace::SlowButNormal) => wire::Pace::Slow,
                Some(BootstrapPace::Stalled) => wire::Pace::Stalled,
                None => wire::Pace::Held,
            },
            unchanged: line.held_for.as_secs(),
            download: line.received,
            window: line.window.as_secs(),
        }),
        carriage: match status.carriage {
            Carriage::Carries => wire::Carriage::Carries,
            Carriage::OpenOnly => wire::Carriage::OpenOnly,
            Carriage::Gone => wire::Carriage::Gone,
        },
    }
}

/// The supervisor's cause as the wire's: `None` for no cause, and for the
/// version flag, which is `flagged` and not a cause (IG-Q70).
#[must_use]
pub fn wire_cause(cause: &Cause) -> Option<wire::TorCause> {
    Some(match cause {
        Cause::None | Cause::DangerousVersion => return None,
        Cause::BundleMissing => wire::TorCause::Missing,
        Cause::PinRefused { path } => wire::TorCause::InstallDefect(path.display().to_string()),
        Cause::Unavailable => wire::TorCause::Unavailable,
        Cause::FailedStart => wire::TorCause::LaunchFailed,
        Cause::Died { exit_code } => wire::TorCause::Exited(*exit_code),
        Cause::DirectoryUnusable { space, .. } => {
            wire::TorCause::Unusable(space.map(|space| wire::Unusable::Exhausted {
                free: space.available,
                needed: space.needed,
            }))
        }
        Cause::ExternalBlocked => wire::TorCause::OutboundBlocked,
        Cause::DirectoryUnreachable => wire::TorCause::DirectoryUnreachable,
        Cause::ClockSkew { skew } => wire::TorCause::ClockSkew(Some(match skew {
            ReportedSkew::Measured(seconds) => wire::Skew::Measured(*seconds),
            ReportedSkew::AtLeast(seconds) => wire::Skew::Minimum(*seconds),
        })),
        Cause::CertificatesOutOfDate => wire::TorCause::ClockSkew(None),
        Cause::TooManyFiles { open } => wire::TorCause::DescriptorLimit(*open),
        Cause::ReplyLate => wire::TorCause::Unanswered,
        Cause::OnionRefused => wire::TorCause::OnionRefused,
        Cause::StrandedAfterClockJump => wire::TorCause::Stranded,
    })
}

fn onion(inbound: Inbound, now: u64) -> Option<wire::Onion> {
    Some(match inbound {
        Inbound::NotOffered => return None,
        Inbound::Publishing { since } => wire::Onion {
            state: wire::OnionState::Publishing,
            age: age(since, now),
            cause: None,
        },
        Inbound::Reachable { evidence_at } => wire::Onion {
            state: wire::OnionState::Reachable,
            age: age(evidence_at, now),
            cause: None,
        },
        Inbound::Unreachable { cause, since } => wire::Onion {
            state: wire::OnionState::Unreachable,
            age: age(since, now),
            cause: Some(match cause {
                InboundCause::ProbeTimedOut => wire::OnionCause::ProbeMissed,
                InboundCause::UploadsRefused => wire::OnionCause::UploadsRefused,
                InboundCause::DescriptorNotFound => wire::OnionCause::DescriptorMissing,
                InboundCause::ClockBehind { behind } => {
                    wire::OnionCause::ClockBehind(behind.as_secs())
                }
            }),
        },
    })
}

impl super::core::Core {
    /// The status at `now`, in the wire's shape: what a status ask is
    /// answered with, and what the daemon's log line renders.
    #[must_use]
    pub fn view(&self, now: u64) -> TorStatus {
        snapshot(&self.status(), self.connectors(), now)
    }
}

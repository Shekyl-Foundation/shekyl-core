// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Control events the supervisor acts on (`TOR_SUPERVISOR.md` §4.2).
//!
//! Anything this module does not name is `None`. The core never sees it.

use crate::control::{
    Bootstrap, ClientStatus, GeneralStatus, HsDescAction, Liveness, Recommendation, TorEvent,
};

use super::core::Input;

/// Events the core acts on (`TOR_SUPERVISOR.md` §4.2). Anything else is `None`.
///
/// | Event | Input |
/// | --- | --- |
/// | `BOOTSTRAP` with `WARNING` or `REASON`, and `RECOMMENDATION=warn` | [`Input::ExternalBlocked`] |
/// | `NETWORK_LIVENESS DOWN` | [`Input::ExternalBlocked`] |
/// | `DIR_ALL_UNREACHABLE` | [`Input::DirectoryUnreachable`] |
/// | `CLOCK_SKEW` | [`Input::ClockSkew`] |
/// | `CLOCK_JUMPED` | [`Input::ClockJumped`] |
/// | `TOO_MANY_CONNECTIONS` | [`Input::TooManyFiles`] |
/// | `DANGEROUS_VERSION` | [`Input::DangerousVersion`] |
/// | `HS_DESC FAILED` for an upload | [`Input::DescriptorFailed`] |
/// | `HS_DESC UPLOADED` | [`Input::DescriptorUploaded`] |
///
/// A bootstrap problem Tor has not yet marked `warn` is not outbound-blocked.
/// Tor sends `warn` from the tenth problem at a phase (§4.2).
#[must_use]
pub fn input_of(event: &TorEvent) -> Option<Input> {
    match event {
        TorEvent::NetworkLiveness(Liveness::Down) => Some(Input::ExternalBlocked),
        TorEvent::General { status, .. } => match status {
            GeneralStatus::DirAllUnreachable => Some(Input::DirectoryUnreachable),
            GeneralStatus::ClockSkew { skew, .. } => skew.as_ref().map(|skew| Input::ClockSkew {
                seconds: match skew {
                    crate::control::ClockSkew::Measured(seconds)
                    | crate::control::ClockSkew::AtLeast(seconds) => *seconds,
                },
            }),
            GeneralStatus::ClockJumped { .. } => Some(Input::ClockJumped),
            GeneralStatus::TooManyConnections { current } => Some(Input::TooManyFiles {
                open: current.unwrap_or(0),
            }),
            GeneralStatus::DangerousVersion { .. } => Some(Input::DangerousVersion),
            GeneralStatus::Other => None,
        },
        TorEvent::Client { status, .. } => match status {
            ClientStatus::Bootstrap(Bootstrap {
                problem: Some(problem),
                ..
            }) if outbound_blocked(problem) => Some(Input::ExternalBlocked),
            _ => None,
        },
        TorEvent::HsDesc(event) => match event.action {
            HsDescAction::Failed if event.descriptor_id.is_none() => Some(Input::DescriptorFailed),
            HsDescAction::Uploaded => Some(Input::DescriptorUploaded),
            _ => None,
        },
        TorEvent::Log(_) | TorEvent::Unsubscribed | TorEvent::NetworkLiveness(_) => None,
    }
}

/// §4.2's named external cause: a bootstrap problem Tor has marked `warn`,
/// carrying `WARNING` or `REASON`.
fn outbound_blocked(problem: &crate::control::BootstrapProblem) -> bool {
    problem.recommendation == Recommendation::Warn
        && (problem.warning.is_some() || problem.reason.is_some())
}

#[cfg(test)]
mod tests {
    use super::input_of;
    use crate::control::{
        Bootstrap, BootstrapProblem, ClientStatus, Recommendation, Severity, TorEvent,
    };
    use crate::supervisor::Input;

    /// §4.2: a bootstrap problem Tor has marked `warn`, with `WARNING` or
    /// `REASON`, is outbound blocked. A problem it still says to ignore is
    /// not. Treating every `REASON` as blocked fails the second half.
    #[test]
    fn a_warned_bootstrap_problem_is_outbound_blocked() {
        let warned = TorEvent::Client {
            severity: Severity::Warn,
            status: ClientStatus::Bootstrap(Bootstrap {
                progress: Some(25),
                tag: Some("conn".to_owned()),
                problem: Some(BootstrapProblem {
                    warning: Some("connection refused".to_owned()),
                    reason: Some("CONNECTREFUSED".to_owned()),
                    count: Some(10),
                    recommendation: Recommendation::Warn,
                }),
            }),
        };
        assert!(matches!(input_of(&warned), Some(Input::ExternalBlocked)));
        let TorEvent::Client {
            status: ClientStatus::Bootstrap(Bootstrap { problem, .. }),
            ..
        } = &warned
        else {
            panic!("the fixture is a bootstrap event");
        };
        let mut ignored = problem.clone().expect("a problem");
        ignored.recommendation = Recommendation::Ignore;
        let early = TorEvent::Client {
            severity: Severity::Notice,
            status: ClientStatus::Bootstrap(Bootstrap {
                progress: Some(25),
                tag: Some("conn".to_owned()),
                problem: Some(ignored),
            }),
        };
        assert!(input_of(&early).is_none());
    }
}

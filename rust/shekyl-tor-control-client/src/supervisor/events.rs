// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Control events the supervisor acts on (`TOR_SUPERVISOR.md` §4.2).
//!
//! Anything this module does not name is `None`. The core never sees it.

use crate::control::{
    Bootstrap, ClientStatus, GeneralStatus, Liveness, Recommendation, RoundMark, TorEvent,
};

use super::core::{Input, RoundEnd};

/// Events the core acts on (`TOR_SUPERVISOR.md` §4.2). Anything else is `None`.
///
/// | Event | Input |
/// | --- | --- |
/// | `BOOTSTRAP` with `WARNING` or `REASON`, and `RECOMMENDATION=warn` | [`Input::ExternalBlocked`] |
/// | `NETWORK_LIVENESS DOWN` | [`Input::ExternalBlocked`] |
/// | `NETWORK_LIVENESS UP` | [`Input::ExternalCleared`] |
/// | `CIRCUIT_NOT_ESTABLISHED REASON=DIR_ALL_UNREACHABLE` | [`Input::DirectoryUnreachable`] |
/// | `CIRCUIT_NOT_ESTABLISHED` with any other reason, or none | [`Input::ExternalBlocked`] |
/// | `CIRCUIT_ESTABLISHED` | [`Input::ExternalCleared`] |
/// | `DIR_ALL_UNREACHABLE` | [`Input::DirectoryUnreachable`] |
/// | `CLOCK_SKEW` | [`Input::ClockSkew`] |
/// | `CLOCK_JUMPED` | [`Input::ClockJumped`] |
/// | `TOO_MANY_CONNECTIONS` | [`Input::TooManyFiles`] |
/// | `DANGEROUS_VERSION` | [`Input::DangerousVersion`] |
///
/// `HS_DESC` is not mapped one event at a time. The driver coalesces this
/// node's own onion's events into rounds (`UploadRounds`, `TSR-Q5`) and
/// folds each round's marks with [`round_inputs`]: one failed upload in a
/// normal round is not evidence (`TSR-M7` saw 1 of 13 fail).
///
/// A bootstrap problem Tor has not yet marked `warn` is not outbound-blocked.
/// Tor sends `warn` from the tenth problem at a phase (§4.2).
/// `CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED` is nothing here: the
/// `STATUS_GENERAL CLOCK_JUMPED` that comes with it is the input. These are
/// Tor's own statements about its network, and only they name it
/// (`TSR-Q14`).
#[must_use]
pub fn input_of(event: &TorEvent) -> Option<Input> {
    match event {
        TorEvent::NetworkLiveness(Liveness::Down) => Some(Input::ExternalBlocked),
        TorEvent::NetworkLiveness(Liveness::Up) => Some(Input::ExternalCleared),
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
            ClientStatus::CircuitNotEstablished { reason } => match reason.as_deref() {
                Some("CLOCK_JUMPED") => None,
                Some("DIR_ALL_UNREACHABLE") => Some(Input::DirectoryUnreachable),
                _ => Some(Input::ExternalBlocked),
            },
            ClientStatus::CircuitEstablished => Some(Input::ExternalCleared),
            _ => None,
        },
        TorEvent::HsDesc(_)
        | TorEvent::Log(_)
        | TorEvent::Unsubscribed
        | TorEvent::NetworkLiveness(Liveness::Other) => None,
    }
}

/// The inputs a round's marks carry (§4.5, §4.4). A round's end is
/// [`Input::UploadRoundEnded`], with one `draw()` for the probe's delay: a
/// round with an upload that succeeded schedules the probe, one in which no
/// upload succeeded and at least one failed is Service-class evidence, and
/// one whose ends were lost (`unfinished` only) is neither. A round's start
/// and its first upload are inputs too: the probe follows the round's end,
/// or `Policy::round_wait` after its first upload, whichever comes first
/// (Rick, 2026-10-29), and a round open too long is counted. Each of the
/// first upload and the end carries its own draw.
pub fn round_inputs(marks: &[RoundMark], mut draw: impl FnMut() -> u64) -> Vec<Input> {
    marks
        .iter()
        .map(|mark| match *mark {
            RoundMark::Started => Input::UploadRoundStarted,
            RoundMark::FirstUploaded => Input::FirstUploaded { draw: draw() },
            RoundMark::Ended {
                uploaded, failed, ..
            } => Input::UploadRoundEnded {
                end: if uploaded > 0 {
                    RoundEnd::Uploaded
                } else if failed > 0 {
                    RoundEnd::FailedAll
                } else {
                    RoundEnd::Unknown
                },
                draw: draw(),
            },
        })
        .collect()
}

/// §4.2's named external cause: a bootstrap problem Tor has marked `warn`,
/// carrying `WARNING` or `REASON`.
fn outbound_blocked(problem: &crate::control::BootstrapProblem) -> bool {
    problem.recommendation == Recommendation::Warn
        && (problem.warning.is_some() || problem.reason.is_some())
}

#[cfg(test)]
mod tests {
    use super::{input_of, round_inputs};
    use crate::control::RoundMark;
    use crate::control::{
        Bootstrap, BootstrapProblem, ClientStatus, Liveness, Recommendation, Severity, TorEvent,
    };
    use crate::supervisor::{Input, RoundEnd};

    /// A round's marks become the core's inputs: its start, its first upload
    /// and its end, each upload and end with a draw of its own. A round with a
    /// success ends as the probe's trigger, one with no success and a failure
    /// as the Service evidence, and one whose ends were lost as neither.
    /// Mapping every `HS_DESC FAILED` to a republish, or treating lost ends
    /// as failures, fails this.
    #[test]
    fn a_rounds_marks_are_its_start_first_upload_and_end() {
        let mut draws = 0_u64..;
        let mut draw = || draws.next().expect("endless");
        let inputs = round_inputs(
            &[
                RoundMark::Started,
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 12,
                    failed: 1,
                    unfinished: 3,
                },
            ],
            &mut draw,
        );
        assert_eq!(
            inputs,
            [
                Input::UploadRoundStarted,
                Input::FirstUploaded { draw: 0 },
                Input::UploadRoundEnded {
                    end: RoundEnd::Uploaded,
                    draw: 1
                }
            ]
        );
        let failed = round_inputs(
            &[RoundMark::Ended {
                uploaded: 0,
                failed: 16,
                unfinished: 0,
            }],
            &mut draw,
        );
        assert_eq!(
            failed,
            [Input::UploadRoundEnded {
                end: RoundEnd::FailedAll,
                draw: 2
            }]
        );
        let lost = round_inputs(
            &[RoundMark::Ended {
                uploaded: 0,
                failed: 0,
                unfinished: 16,
            }],
            &mut draw,
        );
        assert_eq!(
            lost,
            [Input::UploadRoundEnded {
                end: RoundEnd::Unknown,
                draw: 3
            }]
        );
        assert_eq!(
            round_inputs(&[RoundMark::FirstUploaded], &mut draw),
            [Input::FirstUploaded { draw: 4 }]
        );
    }

    /// Tor saying whether it has a circuit names or clears the network
    /// cause; a clock jump is the general event's.
    #[test]
    fn tors_circuit_statements_name_and_clear_the_network_cause() {
        let not = |reason: Option<&str>| TorEvent::Client {
            severity: Severity::Warn,
            status: ClientStatus::CircuitNotEstablished {
                reason: reason.map(str::to_owned),
            },
        };
        assert!(matches!(
            input_of(&not(Some("EXTERNAL_ADDRESS"))),
            Some(Input::ExternalBlocked)
        ));
        assert!(matches!(input_of(&not(None)), Some(Input::ExternalBlocked)));
        assert!(matches!(
            input_of(&not(Some("DIR_ALL_UNREACHABLE"))),
            Some(Input::DirectoryUnreachable)
        ));
        assert!(input_of(&not(Some("CLOCK_JUMPED"))).is_none());
        let established = TorEvent::Client {
            severity: Severity::Notice,
            status: ClientStatus::CircuitEstablished,
        };
        assert!(matches!(
            input_of(&established),
            Some(Input::ExternalCleared)
        ));
    }

    /// `NETWORK_LIVENESS` turns the external cause on and off (§4.2). `UP`
    /// was dropped, so a Running Tor kept "cannot reach the Tor network"
    /// after the network came back. An unknown word is nothing.
    #[test]
    fn network_liveness_turns_the_external_cause_on_and_off() {
        assert!(matches!(
            input_of(&TorEvent::NetworkLiveness(Liveness::Down)),
            Some(Input::ExternalBlocked)
        ));
        assert!(matches!(
            input_of(&TorEvent::NetworkLiveness(Liveness::Up)),
            Some(Input::ExternalCleared)
        ));
        assert!(input_of(&TorEvent::NetworkLiveness(Liveness::Other)).is_none());
    }

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

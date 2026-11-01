// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Control events the supervisor acts on (`TOR_SUPERVISOR.md` §4.2).
//!
//! Anything this module does not name is `None`. The core never sees it.

use crate::control::{
    Bootstrap, ClientStatus, GeneralStatus, HsDescAction, HsDescContent, HsDescEvent, Liveness,
    Recommendation, RoundMark, TorEvent,
};

use super::core::{DirectoryAnswer, Input, RoundEnd};

/// A fetch of this node's onion, as the directory check reads it (§4.5).
/// The caller keeps only events for its own address. `REQUESTED` names the
/// directory and the descriptor Tor's client asks for; a line missing
/// either is not a fetch this check sent. `FAILED` with a descriptor id is
/// a directory's answer, except an upload's refusal (`UPLOAD_REJECTED`),
/// which carries the id too and is the round coalescer's. `REASON=NOT_FOUND` is the directory not having it;
/// any other reason says nothing about the descriptor. `RECEIVED` is not
/// the answer: the copy's counter is, and it comes in the
/// `HS_DESC_CONTENT` Tor sends right after (tor 0.4.9.14
/// `hs_client.c:1685-1689`), read by [`directory_content_input_of`].
#[must_use]
pub fn directory_input_of(event: &HsDescEvent) -> Option<Input> {
    let answer = match event.action {
        HsDescAction::Requested => {
            return Some(Input::DirectoryAsked {
                hsdir: event.hsdir?,
                descriptor_id: event.descriptor_id.clone()?,
            });
        }
        // An upload's refusal carries the descriptor id too
        // (`dirclient.c:2815`); it is the round coalescer's, never an answer.
        HsDescAction::Failed if event.reason.as_deref() == Some("UPLOAD_REJECTED") => {
            return None;
        }
        HsDescAction::Failed if event.descriptor_id.is_some() => {
            if event.reason.as_deref() == Some("NOT_FOUND") {
                DirectoryAnswer::NotFound
            } else {
                DirectoryAnswer::Other
            }
        }
        _ => return None,
    };
    Some(Input::DirectoryAnswered {
        hsdir: event.hsdir?,
        descriptor_id: event.descriptor_id.clone(),
        answer,
    })
}

/// The copy a directory returned for a fetch Tor stored (`HS_DESC_CONTENT`),
/// as the directory check reads it (§4.5): its revision counter against
/// this service's. Tor sends it for every copy it decoded, also one its
/// cache then discards for a lower counter (`hs_cache.c:837-842`), so each
/// directory's copy is seen. The caller keeps only events for its own
/// address. A decode failure sends `FAILED REASON=BAD_DESC` first, which
/// already answered that directory.
#[must_use]
pub fn directory_content_input_of(content: &HsDescContent) -> Option<Input> {
    Some(Input::DirectoryAnswered {
        hsdir: content.hsdir?,
        descriptor_id: content.descriptor_id.clone(),
        answer: DirectoryAnswer::Received {
            revision_counter: content.revision_counter,
        },
    })
}

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
        | TorEvent::HsDescContent(_)
        | TorEvent::Log(_)
        | TorEvent::Unsubscribed
        | TorEvent::NetworkLiveness(Liveness::Other) => None,
    }
}

/// The evidence that names the clock from relays' certificates (§4.2,
/// [`Input::CertificateOutOfDate`], [`Input::HandshakeClosed`]). The core
/// pairs them; none of them names a cause alone.
///
/// | Event | Input |
/// | --- | --- |
/// | a log line carrying one of [`CERTIFICATE_OUT_OF_DATE`] | [`Input::CertificateOutOfDate`] |
/// | `BOOTSTRAP` problem with `REASON=DONE` and a `HOSTID` | [`Input::HandshakeClosed`] |
///
/// This is the one place Tor's free log text is read (`TSR-Q14` applied to
/// it on purpose: the strings are Tor's own statements, pinned to the
/// bundled source by `the_certificate_lines_are_tors_own_text` and
/// re-checked at every re-pin, `RELEASE_CHECKLIST.md`). A problem event
/// carries both this input and, from the tenth problem, [`input_of`]'s
/// blocked link; the driver folds this one first.
#[must_use]
pub fn clock_evidence_of(event: &TorEvent) -> Option<Input> {
    match event {
        TorEvent::Log(log)
            if CERTIFICATE_OUT_OF_DATE
                .iter()
                .any(|line| log.message.contains(line)) =>
        {
            Some(Input::CertificateOutOfDate)
        }
        TorEvent::Client {
            status:
                ClientStatus::Bootstrap(Bootstrap {
                    problem: Some(problem),
                    ..
                }),
            ..
        } if problem.reason.as_deref() == Some(HANDSHAKE_CLOSED_REASON) => {
            problem.host.map(|relay| Input::HandshakeClosed { relay })
        }
        _ => None,
    }
}

/// Tor's log text for a relay certificate outside its lifetime by this
/// computer's clock (tor 0.4.9.14, the bundled pin):
///
/// - `src/feature/relay/torcert.c`, `or_handshake_certs_ed25519_ok`:
///   "Received a bad CERTS cell: At least one certificate expired." (the
///   clock-ahead VM run, §7);
/// - `src/lib/tls/x509_openssl.c`, `log_cert_lifetime`: "Certificate %s.
///   Either their clock is set wrong, or your clock is wrong." with
///   "already expired" or "not yet valid".
///
/// Both log at `warn` only for a directory authority's handshake, and at
/// protocol-warn (`info` unless `ProtocolWarnings` is set) otherwise
/// (`src/core/or/channeltls.c`), so the lines this supervisor hears come
/// from authorities; the relays the problems name may be any.
pub const CERTIFICATE_OUT_OF_DATE: [&str; 3] = [
    "Received a bad CERTS cell: At least one certificate expired.",
    "Certificate already expired. Either their clock is set wrong, or your clock is wrong.",
    "Certificate not yet valid. Either their clock is set wrong, or your clock is wrong.",
];

/// The `REASON` of a handshake problem whose TLS completed before Tor
/// closed the connection (`orconn_end_reason_to_control_string`, `DONE`).
const HANDSHAKE_CLOSED_REASON: &str = "DONE";

/// The inputs a round's marks carry (§4.5, §4.4). A round's end is
/// [`Input::UploadRoundEnded`], with one `draw()` for the probe's delay: a
/// round with an upload that succeeded schedules the probe, and one with
/// none is not uploaded. Either carries its uploads and how many of them a
/// directory refused: more than half refused is the clock's signature,
/// and no republish follows it (Rick, 2026-11-01). Uploads that never
/// reported an end count among the uploads and not among the refused: a
/// refusal is reported within seconds (the clock VM run of 2026-11-01), so
/// an unfinished upload is unknown, and a round that is not a refused
/// majority on what it reported is not called one. A round's start and its first upload
/// are inputs too: the probe follows the round's end, or
/// `Policy::round_wait` after its first upload, whichever comes first
/// (Rick, 2026-10-29), and a round open too long is counted. Each of the
/// first upload and the end carries its own draw.
pub fn round_inputs(marks: &[RoundMark], mut draw: impl FnMut() -> u64) -> Vec<Input> {
    marks
        .iter()
        .map(|mark| match *mark {
            RoundMark::Started => Input::UploadRoundStarted,
            RoundMark::FirstUploaded => Input::FirstUploaded { draw: draw() },
            RoundMark::Ended {
                uploaded,
                failed,
                refused,
                unfinished,
            } => Input::UploadRoundEnded {
                end: if uploaded > 0 {
                    RoundEnd::Uploaded
                } else {
                    RoundEnd::NotUploaded
                },
                uploads: uploaded.saturating_add(failed).saturating_add(unfinished),
                refused,
                draw: draw(),
            },
        })
        .collect()
}

/// The `REASON` Tor gives a bootstrap problem caused by a clock difference
/// (tor 0.4.9.14: "Clock skew -259201 in directory from DIRSERV;
/// CLOCK_SKEW"). Tor names the clock in its own `CLOCK_SKEW` status event
/// beside it, with the seconds.
const CLOCK_SKEW_REASON: &str = "CLOCK_SKEW";

/// §4.2's named external cause: a bootstrap problem Tor has marked `warn`,
/// carrying `WARNING` or `REASON`. A problem whose reason is the clock is
/// not a blocked link: Tor's `CLOCK_SKEW` event names that cause, and
/// mapping the problem to "blocked" overwrote it at every problem, so the
/// node alternated between "the clock is off" and "check the firewall"
/// (§7, the clock-behind VM run of 2026-10-30).
fn outbound_blocked(problem: &crate::control::BootstrapProblem) -> bool {
    problem.recommendation == Recommendation::Warn
        && problem.reason.as_deref() != Some(CLOCK_SKEW_REASON)
        && (problem.warning.is_some() || problem.reason.is_some())
}

#[cfg(test)]
mod tests {
    use super::{
        clock_evidence_of, directory_content_input_of, directory_input_of, input_of, round_inputs,
        CERTIFICATE_OUT_OF_DATE,
    };
    use crate::control::RoundMark;
    use crate::control::{
        Bootstrap, BootstrapProblem, ClientStatus, Liveness, Recommendation, Severity, TorEvent,
    };
    use crate::supervisor::{Input, RoundEnd};

    /// A round's marks become the core's inputs: its start, its first upload
    /// and its end, each upload and end with a draw of its own. A round with a
    /// success ends as the probe's trigger, and one without as not uploaded.
    /// Each end carries every upload the round began, and the refused ones
    /// among the failed: the core weighs the refusals against all of them
    /// (Rick, 2026-11-01). Fails if `round_inputs` counts only the ended
    /// uploads (a resync's open ones then let a minority of refusals pass as
    /// a majority), or drops `refused`.
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
                    refused: 0,
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
                    uploads: 16,
                    refused: 0,
                    draw: 1
                }
            ]
        );
        // The clock VM run's rounds: 7 of 8 refused per descriptor, one
        // accepted.
        let refused = round_inputs(
            &[RoundMark::Ended {
                uploaded: 2,
                failed: 14,
                refused: 14,
                unfinished: 0,
            }],
            &mut draw,
        );
        assert_eq!(
            refused,
            [Input::UploadRoundEnded {
                end: RoundEnd::Uploaded,
                uploads: 16,
                refused: 14,
                draw: 2
            }]
        );
        // A stuck round, or a resync, reports the uploads that never ended.
        // They count among the round's uploads.
        let open = round_inputs(
            &[RoundMark::Ended {
                uploaded: 0,
                failed: 6,
                refused: 6,
                unfinished: 10,
            }],
            &mut draw,
        );
        assert_eq!(
            open,
            [Input::UploadRoundEnded {
                end: RoundEnd::NotUploaded,
                uploads: 16,
                refused: 6,
                draw: 3
            }]
        );
        assert_eq!(
            round_inputs(&[RoundMark::FirstUploaded], &mut draw),
            [Input::FirstUploaded { draw: 4 }]
        );
    }

    /// **A bootstrap problem caused by the clock is not a blocked link**
    /// (the clock-behind VM run of 2026-10-30). The line is the problem Tor
    /// sent there, its `CLOCK_SKEW` reason beside the `CLOCK_SKEW` status
    /// event that names the cause; mapping it to blocked made the node
    /// alternate between the clock and the firewall. The clock-ahead run's
    /// problem (`DONE`, a handshake closed on an expired certificate) still
    /// names the blocked link, whose words now put the clock first. Mapping
    /// every `warn` problem to blocked again fails this.
    #[test]
    fn a_clock_skew_bootstrap_problem_is_not_a_blocked_link() {
        use crate::control::{parse_event, ReplyFramer};
        let parse = |line: &str| {
            let mut framer = ReplyFramer::default();
            framer.push_bytes(format!("650 {line}\r\n").as_bytes());
            let reply = framer.next_reply().expect("frames").expect("a reply");
            parse_event(&reply).expect("an event")
        };
        let skew = parse(
            "STATUS_CLIENT WARN BOOTSTRAP PROGRESS=40 TAG=loading_keys \
             SUMMARY=\"Loading authority key certs\" \
             WARNING=\"Clock skew -259201 in directory from DIRSERV\" REASON=CLOCK_SKEW \
             COUNT=8 RECOMMENDATION=warn HOSTID=\"?\" HOSTADDR=\"192.0.2.1:443\"",
        );
        assert!(input_of(&skew).is_none(), "{skew:?}");
        let done = parse(
            "STATUS_CLIENT WARN BOOTSTRAP PROGRESS=14 TAG=handshake \
             SUMMARY=\"Handshaking with a relay\" WARNING=DONE REASON=DONE COUNT=32 \
             RECOMMENDATION=warn HOSTID=\"0E6E048E32E6CCE9B99F415FBA60584B06117B23\" \
             HOSTADDR=\"192.0.2.2:9001\"",
        );
        assert!(
            matches!(input_of(&done), Some(Input::ExternalBlocked)),
            "{done:?}"
        );
    }

    fn parsed(line: &str) -> TorEvent {
        use crate::control::{parse_event, ReplyFramer};
        let mut framer = ReplyFramer::default();
        framer.push_bytes(format!("650 {line}\r\n").as_bytes());
        let reply = framer.next_reply().expect("frames").expect("a reply");
        parse_event(&reply).expect("an event")
    }

    /// The certificate lines are Tor 0.4.9.14's own text: the clock-ahead
    /// run's line as Tor sent it, and `log_cert_lifetime`'s format filled
    /// with each of its two problems (`x509_openssl.c`). A reworded Tor
    /// fails this at the re-pin (`RELEASE_CHECKLIST.md`). A different bad
    /// CERTS cell is not a clock statement.
    #[test]
    fn the_certificate_lines_are_tors_own_text() {
        let lifetime = |problem: &str| {
            format!(
                "Certificate {problem}. Either their clock is set wrong, or your clock is wrong."
            )
        };
        let lines = [
            "WARN Received a bad CERTS cell: At least one certificate expired.".to_owned(),
            format!("WARN {}", lifetime("already expired")),
            format!("NOTICE {}", lifetime("not yet valid")),
        ];
        for line in &lines {
            assert_eq!(
                clock_evidence_of(&parsed(line)),
                Some(Input::CertificateOutOfDate),
                "{line}"
            );
        }
        assert_eq!(CERTIFICATE_OUT_OF_DATE.len(), lines.len());
        for other in [
            "WARN Received a bad CERTS cell: The link certificate didn't match the TLS public key",
            "WARN Problem bootstrapping. Stuck at 14% (handshake): Handshaking with a relay.",
        ] {
            assert_eq!(clock_evidence_of(&parsed(other)), None, "{other}");
        }
    }

    /// A handshake problem whose TLS completed (`REASON=DONE`) names its
    /// relay as clock evidence; a refused or unrouted connection does not,
    /// and neither does a problem with no relay. Counting every problem's
    /// relay would let a blocked network supply the relays.
    #[test]
    fn a_closed_handshake_names_its_relay_and_nothing_else_does() {
        let problem = |reason: &str, host: &str| {
            parsed(&format!(
                "STATUS_CLIENT WARN BOOTSTRAP PROGRESS=14 TAG=handshake \
                 SUMMARY=\"Handshaking with a relay\" WARNING={reason} REASON={reason} \
                 COUNT=3 RECOMMENDATION=ignore HOSTID=\"{host}\" HOSTADDR=\"192.0.2.2:9001\""
            ))
        };
        let relay = "0E6E048E32E6CCE9B99F415FBA60584B06117B23";
        assert_eq!(
            clock_evidence_of(&problem("DONE", relay)),
            Some(Input::HandshakeClosed {
                relay: crate::control::RelayFingerprint::parse(relay).expect("a fingerprint"),
            })
        );
        assert_eq!(clock_evidence_of(&problem("CONNECTREFUSED", relay)), None);
        assert_eq!(clock_evidence_of(&problem("NOROUTE", relay)), None);
        assert_eq!(clock_evidence_of(&problem("DONE", "?")), None);
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
                    host: None,
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

    /// Tor's own words for a fetch of this onion, as the directory check
    /// reads them, from the lines the VM run of 2026-11-01 recorded: a
    /// `REQUESTED` names the descriptor asked for; `FAILED` with an id is an
    /// answer, `NOT_FOUND` the only reason that says the directory lacks it;
    /// an upload's `FAILED` (no id) is not an answer. `RECEIVED` is not an
    /// answer either: the copy's `HS_DESC_CONTENT`, with its counter, is
    /// (`a_directorys_copy_is_the_checks_answer`). Mapping every `FAILED` to
    /// `NotFound`, reading an upload's end as an answer, or answering at
    /// `RECEIVED` (a stale copy would count as found) fails this.
    #[test]
    fn a_fetchs_events_are_the_directory_checks_inputs() {
        use crate::control::{parse_event, RelayFingerprint, ReplyFramer};
        use crate::supervisor::DirectoryAnswer;
        let onion = "dslbwwu6sfukamiltaij744ly3aqhtl3lbi7e6mdzv6m6hha425mmhqd";
        let dir = "$95B556218614D4F2A3B0F24329AD31103D31FFF6~relay";
        let key = "nFQ9sNMB8qvVnYKG0QxhL4hxuVM0a4gzzBIB+Eb04/E";
        let read = |line: String| {
            let mut framer = ReplyFramer::default();
            framer.push_bytes(format!("{line}\r\n").as_bytes());
            let reply = framer
                .next_reply()
                .expect("frames")
                .expect("one complete reply");
            match parse_event(&reply) {
                Some(TorEvent::HsDesc(desc)) => directory_input_of(&desc),
                other => panic!("not HS_DESC: {other:?}"),
            }
        };
        let hsdir =
            RelayFingerprint::parse("95B556218614D4F2A3B0F24329AD31103D31FFF6").expect("hex");
        assert_eq!(
            read(format!(
                "650 HS_DESC REQUESTED {onion} NO_AUTH {dir} {key} HSDIR_INDEX=00"
            )),
            Some(Input::DirectoryAsked {
                hsdir,
                descriptor_id: key.to_owned(),
            })
        );
        assert_eq!(
            read(format!("650 HS_DESC RECEIVED {onion} NO_AUTH {dir} {key}")),
            None,
            "the copy's counter answers, in the event that follows"
        );
        assert_eq!(
            read(format!(
                "650 HS_DESC FAILED {onion} NO_AUTH {dir} {key} REASON=NOT_FOUND"
            )),
            Some(Input::DirectoryAnswered {
                hsdir,
                descriptor_id: Some(key.to_owned()),
                answer: DirectoryAnswer::NotFound,
            })
        );
        assert_eq!(
            read(format!(
                "650 HS_DESC FAILED {onion} NO_AUTH {dir} {key} REASON=QUERY_RATE_LIMITED"
            )),
            Some(Input::DirectoryAnswered {
                hsdir,
                descriptor_id: Some(key.to_owned()),
                answer: DirectoryAnswer::Other,
            })
        );
        assert_eq!(
            read(format!(
                "650 HS_DESC FAILED {onion} NO_AUTH {dir} {key} REASON=UPLOAD_REJECTED"
            )),
            None,
            "an upload's refusal, which carries the id, is the round coalescer's"
        );
        assert_eq!(
            read(format!("650 HS_DESC UPLOADED {onion} UNKNOWN {dir}")),
            None
        );
    }

    /// **A directory's copy is the check's answer, with its counter** (Rick,
    /// 2026-11-01): the `HS_DESC_CONTENT` Tor sends after it stored a fetch
    /// names the directory and carries the copy, and its `revision-counter`
    /// is what the core compares with ours. A decode failure's empty body
    /// carries no counter. Fails if `directory_content_input_of` drops the
    /// counter or the directory.
    #[test]
    fn a_directorys_copy_is_the_checks_answer() {
        use crate::control::{parse_event, RelayFingerprint, ReplyFramer};
        use crate::supervisor::DirectoryAnswer;
        let onion = "dslbwwu6sfukamiltaij744ly3aqhtl3lbi7e6mdzv6m6hha425mmhqd";
        let dir = "$95B556218614D4F2A3B0F24329AD31103D31FFF6~relay";
        let key = "nFQ9sNMB8qvVnYKG0QxhL4hxuVM0a4gzzBIB+Eb04/E";
        let read = |body: &str| {
            let mut framer = ReplyFramer::default();
            framer.push_bytes(
                format!("650+HS_DESC_CONTENT {onion} {key} {dir}\r\n{body}.\r\n650 OK\r\n")
                    .as_bytes(),
            );
            let reply = framer
                .next_reply()
                .expect("frames")
                .expect("one complete reply");
            match parse_event(&reply) {
                Some(TorEvent::HsDescContent(content)) => directory_content_input_of(&content),
                other => panic!("not HS_DESC_CONTENT: {other:?}"),
            }
        };
        let hsdir =
            RelayFingerprint::parse("95B556218614D4F2A3B0F24329AD31103D31FFF6").expect("hex");
        assert_eq!(
            read("hs-descriptor 3\r\nrevision-counter 3929208370\r\nsignature x\r\n"),
            Some(Input::DirectoryAnswered {
                hsdir,
                descriptor_id: Some(key.to_owned()),
                answer: DirectoryAnswer::Received {
                    revision_counter: Some(3_929_208_370),
                },
            })
        );
        assert_eq!(
            read(""),
            Some(Input::DirectoryAnswered {
                hsdir,
                descriptor_id: Some(key.to_owned()),
                answer: DirectoryAnswer::Received {
                    revision_counter: None,
                },
            })
        );
    }
}

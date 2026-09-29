// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Diff two runs of one seed.
//!
//! A difference in a [`Field`] other than [`Field::ByteBounds`] is a finding.
//! [`DeferredInvariant`] names stack differences this transcript cannot
//! observe; after cutover they become standalone CI checks on the Rust
//! transport. They are not a filter on [`Field`].

use crate::script::{script, AfterHandshake, Script};
use crate::transcript::{Event, Role, Transcript};

/// Wire bytes and the session outcome, plus the bookkeeping that makes a
/// comparison well-formed. Goldens keep the parity variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    PeerSent,
    PeerRecv,
    PeerEnd,
    HostDelivered,
    HostSent,
    HostSession,
    Events,
    Role,
    Version,
    Seed,
    Run,
    /// Seed 32: epee accepted one byte past the seam send queue.
    ByteBounds,
}

impl Field {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerSent => "peer-sent",
            Self::PeerRecv => "peer-recv",
            Self::PeerEnd => "peer-end",
            Self::HostDelivered => "host-delivered",
            Self::HostSent => "host-sent",
            Self::HostSession => "host-session",
            Self::Events => "events",
            Self::Role => "role",
            Self::Version => "version",
            Self::Seed => "seed",
            Self::Run => "run",
            Self::ByteBounds => "byte-bounds",
        }
    }

    pub fn is_parity(self) -> bool {
        matches!(
            self,
            Self::PeerSent
                | Self::PeerRecv
                | Self::PeerEnd
                | Self::HostDelivered
                | Self::HostSent
                | Self::HostSession
                | Self::Seed
        )
    }
}

/// Stack differences the loopback transcript does not record.
///
/// After cutover these become CI invariants on the Rust transport (the epee
/// host is gone). [`Field::ByteBounds`] is the one observed now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredInvariant {
    FinAfterZeroBytes,
    TypedCauseFirstWins,
    AdmissionReservation,
    DerivedDeadline,
    NoTimerSplit,
    NoTos,
}

impl DeferredInvariant {
    pub const ALL: [Self; 6] = [
        Self::FinAfterZeroBytes,
        Self::TypedCauseFirstWins,
        Self::AdmissionReservation,
        Self::DerivedDeadline,
        Self::NoTimerSplit,
        Self::NoTos,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FinAfterZeroBytes => "fin-after-zero-bytes",
            Self::TypedCauseFirstWins => "typed-cause-first-wins",
            Self::AdmissionReservation => "admission-reservation",
            Self::DerivedDeadline => "derived-deadline",
            Self::NoTimerSplit => "no-timer-split",
            Self::NoTos => "no-tos",
        }
    }
}

/// One mismatch. `seed` is the replay key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub seed: u64,
    pub field: Field,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "seed {} {}", self.seed, self.field.as_str())
    }
}

/// Two hosts, each with the peer's transcript and the host's transcript.
pub struct Run {
    pub peer: Transcript,
    pub host: Transcript,
}

/// Parity differences. [`Field::ByteBounds`] is the classified exception.
pub fn diff(left: &Run, right: &Run) -> Vec<Finding> {
    let seed = left.peer.seed;
    let mut findings = Vec::new();
    push_run(&mut findings, left);
    push_run(&mut findings, right);
    if left.peer.version != right.peer.version || left.host.version != right.host.version {
        findings.push(Finding {
            seed,
            field: Field::Version,
        });
    }
    if left.peer.seed != right.peer.seed || left.host.seed != seed || right.host.seed != seed {
        findings.push(Finding {
            seed,
            field: Field::Seed,
        });
    }
    push_bytes(
        &mut findings,
        seed,
        Field::PeerSent,
        &left.peer.sent,
        &right.peer.sent,
    );
    push_bytes(
        &mut findings,
        seed,
        Field::PeerRecv,
        &left.peer.recv,
        &right.peer.recv,
    );
    if left.peer.end != right.peer.end {
        findings.push(Finding {
            seed,
            field: Field::PeerEnd,
        });
    }
    push_bytes(
        &mut findings,
        seed,
        Field::HostDelivered,
        &left.host.recv,
        &right.host.recv,
    );
    push_bytes(
        &mut findings,
        seed,
        Field::HostSent,
        &left.host.sent,
        &right.host.sent,
    );
    if left.host.end != right.host.end {
        findings.push(Finding {
            seed,
            field: Field::HostSession,
        });
    }
    if event_kinds(&left.peer) != event_kinds(&right.peer)
        || event_kinds(&left.host) != event_kinds(&right.host)
    {
        findings.push(Finding {
            seed,
            field: Field::Events,
        });
    }
    findings
}

/// Seed 32 may carry extra bytes past the seam send queue. That suffix is
/// [`Field::ByteBounds`] only when both sides still start with the script's
/// handshake response. A difference inside that prefix stays a parity field.
fn classify_bytes(seed: u64, field: Field, left: &[u8], right: &[u8]) -> Field {
    if !matches!(field, Field::HostSent | Field::PeerRecv) {
        return field;
    }
    let Ok(plan) = script(seed) else {
        return field;
    };
    if plan.after != AfterHandshake::SendOver {
        return field;
    }
    let expected = plan.expected_recv();
    if expected.is_empty() {
        return field;
    }
    if left.starts_with(&expected) && right.starts_with(&expected) {
        Field::ByteBounds
    } else {
        field
    }
}

fn event_kinds(transcript: &Transcript) -> Vec<&'static str> {
    transcript.events.iter().map(Event::kind).collect()
}

fn push_bytes(findings: &mut Vec<Finding>, seed: u64, field: Field, left: &[u8], right: &[u8]) {
    if left == right {
        return;
    }
    let field = classify_bytes(seed, field, left, right);
    if field != Field::ByteBounds {
        findings.push(Finding { seed, field });
    }
}

fn push_run(findings: &mut Vec<Finding>, run: &Run) {
    if run.peer.role != Role::Peer || run.host.role != Role::Host {
        findings.push(Finding {
            seed: run.peer.seed,
            field: Field::Role,
        });
    }
    if run.peer.version != run.host.version {
        findings.push(Finding {
            seed: run.peer.seed,
            field: Field::Version,
        });
    }
    if !directions_hold(run) {
        findings.push(Finding {
            seed: run.peer.seed,
            field: Field::Run,
        });
    }
}

/// One run's peer and host describe the same connection.
///
/// Seed 32's host may send bytes the peer has not read yet. Those bytes
/// are a suffix of what the host sent. Any other disagreement is a
/// malformed run, not a stack difference.
fn directions_hold(run: &Run) -> bool {
    if run.peer.sent != run.host.recv || run.peer.end != run.host.end {
        return false;
    }
    if run.peer.recv == run.host.sent {
        return true;
    }
    matches!(
        script(run.peer.seed).map(|plan| plan.after),
        Ok(AfterHandshake::SendOver)
    ) && run.host.sent.starts_with(&run.peer.recv)
}

/// The peer and the host of one run agree on the bytes and the outcome.
pub fn run_agrees(run: &Run) -> bool {
    run.peer.role == Role::Peer
        && run.host.role == Role::Host
        && run.peer.seed == run.host.seed
        && run.peer.sent == run.host.recv
        && run.peer.recv == run.host.sent
        && run.peer.end == run.host.end
}

/// [`run_agrees`] plus the script's expected end and bytes.
pub fn run_matches_script(run: &Run, plan: &Script) -> bool {
    run_agrees(run) && run.peer.end == plan.end && plan.recv_matches(&run.peer.recv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::NamedSeed;
    use crate::transcript::{End, Role, Transcript, TranscriptVersion};

    fn empty_run(seed: u64, peer_role: Role, host_role: Role) -> Run {
        let transcript = |role: Role| Transcript {
            version: TranscriptVersion::V1,
            seed,
            role,
            sent: vec![1],
            recv: vec![1],
            end: End::Established,
            events: vec![],
        };
        Run {
            peer: Transcript {
                role: peer_role,
                recv: vec![1],
                sent: vec![1],
                ..transcript(peer_role)
            },
            host: Transcript {
                role: host_role,
                recv: vec![1],
                sent: vec![1],
                ..transcript(host_role)
            },
        }
    }

    #[test]
    fn parity_fields_are_not_byte_bounds() {
        for field in [
            Field::PeerSent,
            Field::PeerRecv,
            Field::PeerEnd,
            Field::HostDelivered,
            Field::HostSent,
            Field::HostSession,
        ] {
            assert!(field.is_parity(), "{}", field.as_str());
            assert_ne!(field, Field::ByteBounds);
        }
        assert!(!Field::ByteBounds.is_parity());
    }

    #[test]
    fn deferred_invariants_are_the_unobserved_names() {
        assert_eq!(
            DeferredInvariant::ALL.map(DeferredInvariant::as_str),
            [
                "fin-after-zero-bytes",
                "typed-cause-first-wins",
                "admission-reservation",
                "derived-deadline",
                "no-timer-split",
                "no-tos",
            ]
        );
    }

    #[test]
    fn swapped_roles_are_a_finding() {
        let run = empty_run(1, Role::Host, Role::Peer);
        assert!(diff(&run, &run)
            .iter()
            .any(|finding| finding.field == Field::Role));
    }

    fn send_over_pair(peer_recv: Vec<u8>, host_sent: Vec<u8>) -> Run {
        let seed = NamedSeed::SendOver.as_u64();
        let inbound = vec![1, 2];
        Run {
            peer: Transcript {
                version: TranscriptVersion::V1,
                seed,
                role: Role::Peer,
                sent: inbound.clone(),
                recv: peer_recv,
                end: End::Established,
                events: vec![],
            },
            host: Transcript {
                version: TranscriptVersion::V1,
                seed,
                role: Role::Host,
                sent: host_sent,
                recv: inbound,
                end: End::Established,
                events: vec![],
            },
        }
    }

    #[test]
    fn send_over_host_sent_suffix_is_byte_bounds() {
        let expected = script(NamedSeed::SendOver.as_u64())
            .expect("script")
            .expected_recv();
        let mut extra = expected.clone();
        extra.push(0x04);
        let findings = diff(
            &send_over_pair(expected.clone(), expected),
            &send_over_pair(extra.clone(), extra),
        );
        assert!(
            findings.is_empty(),
            "byte-bounds should be classified away: {findings:?}"
        );
    }

    #[test]
    fn send_over_handshake_mismatch_stays_a_parity_finding() {
        let expected = script(NamedSeed::SendOver.as_u64())
            .expect("script")
            .expected_recv();
        let wrong = vec![0x09];
        let findings = diff(
            &send_over_pair(expected.clone(), expected),
            &send_over_pair(wrong.clone(), wrong),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.field == Field::HostSent),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.field == Field::PeerRecv),
            "{findings:?}"
        );
    }

    #[test]
    fn handshake_host_sent_mismatch_is_a_finding() {
        let seed = NamedSeed::Handshake.as_u64();
        let peer = Transcript {
            version: TranscriptVersion::V1,
            seed,
            role: Role::Peer,
            sent: vec![1],
            recv: vec![2],
            end: End::Established,
            events: vec![],
        };
        let host = Transcript {
            version: TranscriptVersion::V1,
            seed,
            role: Role::Host,
            sent: vec![2],
            recv: vec![1],
            end: End::Established,
            events: vec![],
        };
        let mut broken = host.clone();
        broken.sent = vec![9];
        let mut broken_peer = peer.clone();
        broken_peer.recv = vec![9];
        let findings = diff(
            &Run {
                peer: peer.clone(),
                host,
            },
            &Run {
                peer: broken_peer,
                host: broken,
            },
        );
        assert!(findings
            .iter()
            .any(|finding| finding.field == Field::HostSent));
        assert!(findings
            .iter()
            .any(|finding| finding.field == Field::PeerRecv));
    }
}

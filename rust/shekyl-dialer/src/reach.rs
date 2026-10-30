// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether an attempt reached a peer. One classification for every
//! connector.
//!
//! The Tor posture tally reads [`attempt_stream`]. The quiet stretch reads
//! [`quiet_evidence`]. They agree, except on this node's own close: the
//! tally does not count it as a failed Tor dial, and the quiet stretch
//! does, because the lists cool that test. A connector stamps its own
//! close cause; this module names no network. A later connector, I2P
//! included, arrives as the same [`DialOutcome`]. The dialer dispatches.
//! The connector has already said whether its channel existed.

use shekyl_peerlist::{CloseKind, DialOutcome};

/// What one attempt did about a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptStream {
    /// The attempt reached a peer. The quiet stretch starts again, and
    /// the Tor tally counts an open.
    Opened,
    /// A dial ended before a channel existed. The Tor tally counts it
    /// unopened. The quiet stretch does not start again.
    Unopened,
    /// Not a dial, for the Tor tally. A payload refusal names a session
    /// already counted. This node's own close is not a failed Tor dial.
    /// The quiet stretch does not read this variant for that close: the
    /// lists cool the test, so [`quiet_evidence`] counts it unopened.
    NotADial,
}

/// What one outcome does to the quiet count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuietEvidence {
    /// A stream opened. The unopened count resets and the span starts again.
    Opened,
    /// A test ended with no stream. The lists cool it, so it counts,
    /// including this node's own close.
    Unopened,
    /// Not a test. A payload refusal names a session already counted.
    NotATest,
}

/// Sort `outcome`. The match is total and names no connector.
pub(crate) fn attempt_stream(outcome: &DialOutcome) -> AttemptStream {
    match outcome {
        DialOutcome::PayloadRefused(_) => AttemptStream::NotADial,
        // A stream that opened is an open even when this node then closed
        // it. [`CloseKind::LocalClose`] applies in every phase, so it never
        // reports a stream, and it is not a failed dial.
        DialOutcome::DialFailed(_, cause) if cause.opened_a_stream() => AttemptStream::Opened,
        DialOutcome::DialFailed(_, cause) if cause.kind() == CloseKind::LocalClose => {
            AttemptStream::NotADial
        }
        DialOutcome::DialFailed(_, _) => AttemptStream::Unopened,
        DialOutcome::PeerlistRefused(..)
        | DialOutcome::Confirmed(_)
        | DialOutcome::SessionAccepted(_) => AttemptStream::Opened,
    }
}

/// What the quiet guard counts. A failed test that opened no stream adds
/// to the unopened count, including [`CloseKind::LocalClose`]: the lists
/// cool that test, and a connect this node could not make is the evidence
/// the guard exists to read. A payload refusal is not a test. The Tor
/// tally keeps [`attempt_stream`], which does not count a local close.
pub(crate) fn quiet_evidence(outcome: &DialOutcome) -> QuietEvidence {
    match attempt_stream(outcome) {
        AttemptStream::Opened => QuietEvidence::Opened,
        AttemptStream::Unopened => QuietEvidence::Unopened,
        AttemptStream::NotADial => {
            if matches!(outcome, DialOutcome::DialFailed(_, _)) {
                QuietEvidence::Unopened
            } else {
                QuietEvidence::NotATest
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shekyl_peerlist::{CloseCause, CloseKind, DialOutcome, NetworkAddress};

    use super::{attempt_stream, quiet_evidence, AttemptStream, QuietEvidence};

    fn address() -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(203, 0, 113, 7),
            port: 18080,
        }
    }

    fn failed(kind: CloseKind) -> DialOutcome {
        DialOutcome::DialFailed(address(), CloseCause::new(kind))
    }

    #[test]
    fn an_attempt_sorts_without_naming_a_connector() {
        let address = address();
        assert_eq!(
            attempt_stream(&DialOutcome::SessionAccepted(address.clone())),
            AttemptStream::Opened
        );
        assert_eq!(
            attempt_stream(&DialOutcome::Confirmed(address.clone())),
            AttemptStream::Opened
        );
        assert_eq!(
            attempt_stream(&DialOutcome::PeerlistRefused(
                address.clone(),
                CloseCause::new(CloseKind::LevinHandshakeRejected)
            )),
            AttemptStream::Opened,
            "a refused list was a peer we reached"
        );
        assert_eq!(
            attempt_stream(&failed(CloseKind::LevinHandshakeRejected)),
            AttemptStream::Opened
        );
        assert_eq!(
            attempt_stream(&failed(CloseKind::PeerClosed)),
            AttemptStream::Opened,
            "a retry after the channel existed still reached a peer"
        );
        assert_eq!(
            attempt_stream(&DialOutcome::DialFailed(
                address.clone(),
                CloseCause::proxy_refused(0x06, 0)
            )),
            AttemptStream::Unopened
        );
        assert_eq!(
            attempt_stream(&failed(CloseKind::TransportTimeout)),
            AttemptStream::Unopened
        );
        assert_eq!(
            attempt_stream(&failed(CloseKind::LocalClose)),
            AttemptStream::NotADial
        );
        assert_eq!(
            attempt_stream(&DialOutcome::PayloadRefused(address)),
            AttemptStream::NotADial
        );
    }

    /// This node's own close is not a failed Tor dial, and it is quiet
    /// evidence: the lists cool it. A payload refusal is neither.
    #[test]
    fn a_local_close_counts_for_the_quiet_guard_and_not_the_tally() {
        let local = failed(CloseKind::LocalClose);
        assert_eq!(attempt_stream(&local), AttemptStream::NotADial);
        assert_eq!(quiet_evidence(&local), QuietEvidence::Unopened);
        let refused = DialOutcome::PayloadRefused(address());
        assert_eq!(quiet_evidence(&refused), QuietEvidence::NotATest);
        assert_eq!(
            quiet_evidence(&failed(CloseKind::TransportTimeout)),
            QuietEvidence::Unopened
        );
        assert_eq!(
            quiet_evidence(&failed(CloseKind::LevinHandshakeRejected)),
            QuietEvidence::Opened
        );
    }
}

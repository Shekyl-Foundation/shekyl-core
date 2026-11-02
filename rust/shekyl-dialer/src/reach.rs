// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether an attempt reached a peer. One classification for every
//! connector.
//!
//! The Tor posture tally reads [`attempt_stream`], and the judge notes a
//! stream that opened from it (`crate::judge`). It reads how far the
//! attempt got ([`Reached`]), which the layer that observed the failure stamped; this
//! module names no network. A later connector, I2P included, arrives as
//! the same [`DialOutcome`].

use shekyl_peerlist::DialOutcome;
use shekyl_transport_layer::Reached;

/// What one attempt did about a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptStream {
    /// The attempt reached a peer. The Tor tally counts an open, and
    /// where the connector declares stream opens as corroboration the
    /// judge notes a sign of life.
    Opened,
    /// A dial ended before a stream opened. The Tor tally counts it
    /// unopened, whatever its evidence: it is a failed dial.
    Unopened,
    /// Not a dial: a payload refusal names a session already counted.
    NotADial,
}

/// Sort `outcome`. The match is total and names no connector.
pub(crate) fn attempt_stream(outcome: &DialOutcome) -> AttemptStream {
    match outcome {
        DialOutcome::PayloadRefused(_) => AttemptStream::NotADial,
        // A stream that opened is an open even when this node then closed
        // it.
        DialOutcome::DialFailed(_, failure) if failure.reached() == Reached::StreamOpened => {
            AttemptStream::Opened
        }
        DialOutcome::DialFailed(_, _) => AttemptStream::Unopened,
        DialOutcome::Confirmed(_) | DialOutcome::SessionAccepted(_) => AttemptStream::Opened,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shekyl_peerlist::{ConnectorId, DialOutcome, NetworkAddress};
    use shekyl_transport_layer::{DialEnd, DialFailure, Reached, Retry};

    use super::{attempt_stream, AttemptStream};

    fn address() -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(203, 0, 113, 7),
            port: 18080,
        }
    }

    fn failed(failure: DialFailure) -> DialOutcome {
        DialOutcome::DialFailed(address(), failure)
    }

    /// The sort reads only how far the attempt got. The edit that makes
    /// this red is reading the evidence, or a connector, instead.
    #[test]
    fn an_attempt_sorts_by_how_far_it_got() {
        let address = address();
        let opened = Reached::StreamOpened;
        assert_eq!(
            attempt_stream(&DialOutcome::SessionAccepted(address.clone())),
            AttemptStream::Opened
        );
        assert_eq!(
            attempt_stream(&DialOutcome::Confirmed(address.clone())),
            AttemptStream::Opened
        );
        assert_eq!(
            attempt_stream(&failed(DialFailure::refused_by_peer(
                ConnectorId::Clearnet,
                opened
            ))),
            AttemptStream::Opened,
            "a refusal after the stream opened reached a peer"
        );
        assert_eq!(
            attempt_stream(&failed(DialFailure::uncertain(Retry::Again, opened))),
            AttemptStream::Opened,
            "a retry after the stream opened still reached a peer"
        );
        assert_eq!(
            attempt_stream(&failed(shekyl_tor::stamp_reply(0x06))),
            AttemptStream::Unopened
        );
        assert_eq!(
            attempt_stream(&failed(DialEnd::local_close().failure())),
            AttemptStream::Unopened,
            "this node's own close is a failed dial"
        );
        assert_eq!(
            attempt_stream(&DialOutcome::PayloadRefused(address)),
            AttemptStream::NotADial
        );
    }
}

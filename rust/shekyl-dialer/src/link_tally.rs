// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor dials show, for the managed-Tor supervisor's
//! posture line (`TOR_SUPERVISOR.md` §4.2, "every Tor dial's outcome").
//!
//! Display only, never a verdict on the link (`TSR-Q14`: Tor does Tor).
//! Which reply a failed onion dial gets is the destination's to choose as
//! much as the link's: a live service that refuses its port answers `0x01`,
//! one that blackholes it answers `0x06`, as a blocked link does. So the
//! tally says only what is plainly so: whether streams open, and whether
//! the node holds a Tor session now. The supervisor never sees an address
//! or a reply code.

use std::sync::Arc;

use shekyl_peerlist::{CloseKind, ConnectorId, DialOutcome};

/// What this node's Tor dials show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TorLinkTally {
    /// Tor dials whose stream opened, since the dialer started. Only grows.
    pub opened: u64,
    /// Tor dials that ended without a stream since the last one opened.
    pub unopened: u32,
    /// Tor sessions this node holds now.
    pub held: u32,
}

/// Where the tally goes. Called under the dialer's lock: it must not block.
pub type TallySink = Arc<dyn Fn(TorLinkTally) + Send + Sync>;

/// The running fold over Tor dial outcomes.
pub(crate) struct LinkFold {
    tally: TorLinkTally,
    sink: Option<TallySink>,
}

impl LinkFold {
    pub(crate) fn new() -> Self {
        Self {
            tally: TorLinkTally::default(),
            sink: None,
        }
    }

    /// Send every later tally to `sink`, and the current one now.
    pub(crate) fn set_sink(&mut self, sink: TallySink) {
        sink(self.tally);
        self.sink = Some(sink);
    }

    pub(crate) fn tally(&self) -> TorLinkTally {
        self.tally
    }

    /// Fold one dial outcome when it is a Tor dial. Anything that reached a
    /// peer opened a stream; a dial this node closed itself is not a dial
    /// that failed.
    pub(crate) fn observe(&mut self, connector: ConnectorId, outcome: &DialOutcome, held: usize) {
        if connector != ConnectorId::Tor {
            return;
        }
        let mut next = self.tally;
        match outcome {
            DialOutcome::DialFailed(_, cause) if !cause.opened_a_stream() => {
                if cause.kind() != CloseKind::LocalClose {
                    next.unopened = next.unopened.saturating_add(1);
                }
            }
            DialOutcome::DialFailed(..)
            | DialOutcome::PeerlistRefused(_)
            | DialOutcome::PayloadRefused(_)
            | DialOutcome::Confirmed(_)
            | DialOutcome::SessionAccepted(_) => {
                next.opened = next.opened.saturating_add(1);
                next.unopened = 0;
            }
        }
        next.held = u32::try_from(held).unwrap_or(u32::MAX);
        self.publish(next);
    }

    /// A Tor session ended: the count of those held moves.
    pub(crate) fn held(&mut self, connector: ConnectorId, held: usize) {
        if connector != ConnectorId::Tor {
            return;
        }
        let mut next = self.tally;
        next.held = u32::try_from(held).unwrap_or(u32::MAX);
        self.publish(next);
    }

    fn publish(&mut self, next: TorLinkTally) {
        if next == self.tally {
            return;
        }
        self.tally = next;
        if let Some(sink) = &self.sink {
            sink(next);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use shekyl_peerlist::{CloseCause, NetworkAddress};

    use super::*;

    fn onion(n: u8) -> NetworkAddress {
        let host = format!("{}.onion", char::from(b'a' + n).to_string().repeat(56));
        NetworkAddress::Tor { host, port: 12021 }
    }

    fn failed(n: u8, cause: CloseCause) -> DialOutcome {
        DialOutcome::DialFailed(onion(n), cause)
    }

    /// Every reply Tor gives a failed dial is one unopened dial, whatever
    /// its byte: `0x01`, `0x06`, the extended codes and the dial deadline
    /// alike. A stream that opened, even one the peer then refused, resets
    /// the count.
    #[test]
    fn any_dial_without_a_stream_is_unopened_and_an_opened_one_resets() {
        let mut fold = LinkFold::new();
        for reply in [0x01, 0x06, 0xF0, 0xF2, 0xF3, 0xF7] {
            fold.observe(
                ConnectorId::Tor,
                &failed(0, CloseCause::proxy_refused(reply)),
                0,
            );
        }
        fold.observe(
            ConnectorId::Tor,
            &failed(1, CloseCause::new(CloseKind::TransportTimeout)),
            0,
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(2, CloseCause::new(CloseKind::ProxyUnavailable)),
            0,
        );
        assert_eq!(
            fold.tally(),
            TorLinkTally {
                opened: 0,
                unopened: 8,
                held: 0,
            }
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(3, CloseCause::new(CloseKind::LevinHandshakeRejected)),
            0,
        );
        assert_eq!(
            fold.tally().opened,
            1,
            "a rejected handshake reached a peer"
        );
        assert_eq!(fold.tally().unopened, 0);
    }

    /// This node's own close is not a failed dial, and another connector's
    /// dials say nothing about Tor.
    #[test]
    fn own_closes_and_other_connectors_leave_the_tally_alone() {
        let mut fold = LinkFold::new();
        fold.observe(
            ConnectorId::Tor,
            &failed(0, CloseCause::new(CloseKind::LocalClose)),
            0,
        );
        let clearnet = NetworkAddress::Ipv4 {
            ip: std::net::Ipv4Addr::new(203, 0, 113, 7),
            port: 11021,
        };
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::DialFailed(clearnet.clone(), CloseCause::new(CloseKind::DialFailed)),
            3,
        );
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::SessionAccepted(clearnet),
            3,
        );
        fold.held(ConnectorId::Clearnet, 3);
        assert_eq!(fold.tally(), TorLinkTally::default());
    }

    /// The count of held sessions follows accepts and closes, and the sink
    /// hears only changes.
    #[test]
    fn held_sessions_follow_accepts_and_closes_and_only_changes_are_sent() {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let sink_heard = Arc::clone(&heard);
        let mut fold = LinkFold::new();
        fold.set_sink(Arc::new(move |tally| {
            sink_heard.lock().expect("heard").push(tally);
        }));
        fold.observe(ConnectorId::Tor, &DialOutcome::SessionAccepted(onion(0)), 1);
        fold.held(ConnectorId::Tor, 1);
        fold.held(ConnectorId::Tor, 0);
        let heard = heard.lock().expect("heard");
        assert_eq!(heard.len(), 3, "the initial tally, the accept, the close");
        assert_eq!(heard[1].held, 1);
        assert_eq!(heard[2].held, 0);
    }
}

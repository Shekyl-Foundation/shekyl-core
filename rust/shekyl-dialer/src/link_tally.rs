// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor dials say about its link to the Tor network
//! (`TOR_SUPERVISOR.md` §4.2, "every Tor dial's outcome").
//!
//! The class of each outcome is [`CloseCause::link_evidence`]'s; this module
//! only counts. The managed-Tor supervisor reads the tally and decides: it
//! never sees an address or a reply code. Counting distinct destinations
//! happens here, because the rate rule is about destinations and only the
//! dialer holds them: link-down is timeouts across **distinct** destinations
//! with no opened stream between them, never a count of replies.

use std::collections::BTreeSet;
use std::sync::Arc;

use shekyl_peerlist::{ConnectorId, DialOutcome, LinkEvidence, NetworkAddress};

/// Distinct destinations remembered since the last opened stream. Past
/// this the count holds: any threshold the supervisor uses is far below it.
const TIMED_OUT_DESTINATIONS_HELD: usize = 64;

/// The Tor link's evidence from this node's dials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TorLinkTally {
    /// Tor dials whose stream opened, since the dialer started. Only grows.
    pub opened: u64,
    /// Link failures since the last opened stream.
    pub link_failures: u32,
    /// Distinct destinations that timed out since the last opened stream.
    pub timed_out_destinations: u32,
}

/// Where the tally goes. Called under the dialer's lock: it must not block.
pub type TallySink = Arc<dyn Fn(TorLinkTally) + Send + Sync>;

/// The running fold over Tor dial outcomes.
pub(crate) struct LinkFold {
    tally: TorLinkTally,
    timed_out: BTreeSet<NetworkAddress>,
    sink: Option<TallySink>,
}

impl LinkFold {
    pub(crate) fn new() -> Self {
        Self {
            tally: TorLinkTally::default(),
            timed_out: BTreeSet::new(),
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

    /// Fold one dial outcome when it is a Tor dial; any other connector's
    /// says nothing about the Tor link. Anything that reached a peer is an
    /// opened stream; a failed dial is its cause's class.
    pub(crate) fn observe(&mut self, connector: ConnectorId, outcome: &DialOutcome) {
        if connector != ConnectorId::Tor {
            return;
        }
        let before = self.tally;
        match outcome {
            DialOutcome::DialFailed(address, cause) => match cause.link_evidence() {
                LinkEvidence::Opened => self.opened(),
                LinkEvidence::LinkFailed => {
                    self.tally.link_failures = self.tally.link_failures.saturating_add(1);
                }
                LinkEvidence::TimedOut => self.timed_out(address),
                LinkEvidence::Destination | LinkEvidence::OurRequest | LinkEvidence::Silent => {}
            },
            DialOutcome::PeerlistRefused(_)
            | DialOutcome::PayloadRefused(_)
            | DialOutcome::Confirmed(_)
            | DialOutcome::SessionAccepted(_) => self.opened(),
        }
        if self.tally != before {
            if let Some(sink) = &self.sink {
                sink(self.tally);
            }
        }
    }

    fn opened(&mut self) {
        self.tally.opened = self.tally.opened.saturating_add(1);
        self.tally.link_failures = 0;
        self.tally.timed_out_destinations = 0;
        self.timed_out.clear();
    }

    fn timed_out(&mut self, address: &NetworkAddress) {
        if self.timed_out.len() < TIMED_OUT_DESTINATIONS_HELD {
            self.timed_out.insert(address.clone());
        }
        self.tally.timed_out_destinations = u32::try_from(self.timed_out.len()).unwrap_or(u32::MAX);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use shekyl_peerlist::{CloseCause, CloseKind};

    use super::*;

    fn onion(n: u8) -> NetworkAddress {
        let host = format!("{}.onion", char::from(b'a' + n).to_string().repeat(56));
        NetworkAddress::Tor { host, port: 12021 }
    }

    fn failed(n: u8, cause: CloseCause) -> DialOutcome {
        DialOutcome::DialFailed(onion(n), cause)
    }

    /// The rule a reviewer can break (§4.2): `0xF7` from one destination
    /// many times leaves one timed-out destination; the same count spread
    /// across distinct destinations counts each. Counting replies instead
    /// of destinations fails the first half.
    #[test]
    fn timeouts_count_distinct_destinations_not_replies() {
        let timeout = CloseCause::proxy_refused(0xF7);
        let mut one = LinkFold::new();
        for _ in 0..10 {
            one.observe(ConnectorId::Tor, &failed(0, timeout));
        }
        assert_eq!(one.tally().timed_out_destinations, 1);
        let mut spread = LinkFold::new();
        for n in 0..10 {
            spread.observe(ConnectorId::Tor, &failed(n, timeout));
        }
        assert_eq!(spread.tally().timed_out_destinations, 10);
        spread.observe(
            ConnectorId::Tor,
            &failed(3, CloseCause::new(CloseKind::TransportTimeout)),
        );
        assert_eq!(
            spread.tally().timed_out_destinations,
            10,
            "the same destination"
        );
    }

    /// An opened stream ends the run: failures before it are not counted
    /// after it, and `opened` grows so a reader sees the success even if it
    /// missed the zeroed counts.
    #[test]
    fn an_opened_stream_ends_the_run_of_failures() {
        let mut fold = LinkFold::new();
        fold.observe(
            ConnectorId::Tor,
            &failed(0, CloseCause::proxy_refused(0x01)),
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(1, CloseCause::new(CloseKind::ProxyUnavailable)),
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(2, CloseCause::proxy_refused(0xF3)),
        );
        assert_eq!(
            fold.tally(),
            TorLinkTally {
                opened: 0,
                link_failures: 2,
                timed_out_destinations: 1,
            }
        );
        fold.observe(ConnectorId::Tor, &DialOutcome::SessionAccepted(onion(4)));
        assert_eq!(
            fold.tally(),
            TorLinkTally {
                opened: 1,
                link_failures: 0,
                timed_out_destinations: 0,
            }
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(5, CloseCause::new(CloseKind::PeerClosed)),
        );
        assert_eq!(
            fold.tally().opened,
            2,
            "a peer close needed an opened stream"
        );
    }

    /// Only Tor dials count: a clearnet failure, even one whose class would
    /// be a link failure on Tor, leaves the Tor tally alone.
    #[test]
    fn another_connectors_dials_say_nothing_about_tor() {
        let mut fold = LinkFold::new();
        let clearnet = NetworkAddress::Ipv4 {
            ip: std::net::Ipv4Addr::new(203, 0, 113, 7),
            port: 11021,
        };
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::DialFailed(clearnet.clone(), CloseCause::new(CloseKind::DialFailed)),
        );
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::SessionAccepted(clearnet),
        );
        assert_eq!(fold.tally(), TorLinkTally::default());
        fold.observe(
            ConnectorId::Tor,
            &failed(0, CloseCause::proxy_refused(0x01)),
        );
        assert_eq!(fold.tally().link_failures, 1);
    }

    /// Destination replies and this node's own requests are never link
    /// evidence, and the sink hears only changes.
    #[test]
    fn destination_and_request_replies_leave_the_tally_alone() {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let sink_heard = Arc::clone(&heard);
        let mut fold = LinkFold::new();
        fold.set_sink(Arc::new(move |tally| {
            sink_heard.lock().expect("heard").push(tally);
        }));
        for reply in [0x04, 0x05, 0xF0, 0xF1, 0xF2, 0x07, 0x08, 0xF4, 0xF5, 0xF6] {
            fold.observe(
                ConnectorId::Tor,
                &failed(0, CloseCause::proxy_refused(reply)),
            );
        }
        fold.observe(
            ConnectorId::Tor,
            &failed(0, CloseCause::new(CloseKind::LocalClose)),
        );
        assert_eq!(fold.tally(), TorLinkTally::default());
        fold.observe(
            ConnectorId::Tor,
            &failed(0, CloseCause::proxy_refused(0x06)),
        );
        let heard = heard.lock().expect("heard");
        assert_eq!(heard.len(), 2, "the initial tally and the one change");
        assert_eq!(heard[1].link_failures, 1);
    }
}

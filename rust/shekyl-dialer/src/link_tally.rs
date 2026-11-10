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
//! tally says only what is plainly so: whether streams open, and when the
//! link last showed life. The supervisor never sees an address
//! or a reply code. How many sessions each connector holds is the session
//! layer's to publish, from its board.

use std::sync::Arc;

use shekyl_peerlist::{ConnectorId, DialOutcome};
use shekyl_timing_engine::Stamp;

use crate::reach::{attempt_stream, AttemptStream};

/// What this node's Tor dials show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TorLinkTally {
    /// Tor dials whose stream opened, since the dialer started. Only grows.
    pub opened: u64,
    /// Tor dial attempts that ended without a stream since the last one
    /// opened. Each attempt counts when it ends, including a failed one
    /// whose test goes on to a retry (revision 4 of the in-flight bound,
    /// Rick 2026-10-26).
    pub unopened: u32,
    /// When the dialer's judge last saw the link work: a stream that
    /// opened, or a byte a session received (`DIALER_OUTAGE_EVIDENCE.md`
    /// §4.1). `None` until the first.
    pub last_sign_of_life: Option<Stamp>,
    /// The latest `attempt_began` among Tor dials that ended without a
    /// stream (`DIALER_OUTAGE_EVIDENCE.md` §6.1): when the dialer launched
    /// the attempt, not when it was counted. A dial sent to an old Tor, or
    /// before a wake, fails after the quiet stretch begins, and its launch
    /// says it did not test the link since. `None` until the first. An
    /// opened stream does not clear it.
    pub failed_attempt_began: Option<Stamp>,
    /// The Tor addresses the dialer holds, white and gray seats with the
    /// cooling ones, at its latest census of the Tor connector. `None`
    /// until the first. The posture line says "no peers known yet" from a
    /// zero here, and "peers are known; none has answered" otherwise (Rick,
    /// 2026-11-10).
    pub known: Option<u32>,
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

    /// Fold one dial attempt's outcome when it is a Tor dial: the test's
    /// outcome, or a failed attempt deferred for a retry. Anything that
    /// reached a peer opened a stream, whenever its attempt `began`. Every
    /// other failure, this node's own included, is a dial that ended
    /// without one, and the tally keeps the latest `began` among those. A
    /// payload refusal is not a dial: it names a kept session the payload
    /// owner declined, and that stream was counted when the dial was
    /// accepted. An opened stream does not clear the failure's launch.
    pub(crate) fn observe(&mut self, connector: ConnectorId, outcome: &DialOutcome, began: Stamp) {
        if connector != ConnectorId::Tor {
            return;
        }
        let mut next = self.tally;
        match attempt_stream(outcome) {
            AttemptStream::NotADial => {}
            AttemptStream::Opened => {
                next.opened = next.opened.saturating_add(1);
                next.unopened = 0;
            }
            AttemptStream::Unopened => {
                next.unopened = next.unopened.saturating_add(1);
                next.failed_attempt_began = next.failed_attempt_began.max(Some(began));
            }
        }
        self.publish(next);
    }

    /// The judge saw `connector`'s link work `at`: the tally's last sign
    /// of life when it is the Tor link.
    pub(crate) fn life(&mut self, connector: ConnectorId, at: Stamp) {
        if connector != ConnectorId::Tor {
            return;
        }
        let mut next = self.tally;
        next.last_sign_of_life = Some(at);
        self.publish(next);
    }

    /// A census of `connector`'s seats: the tally's known addresses when it
    /// is the Tor link.
    pub(crate) fn census(&mut self, connector: ConnectorId, known: usize) {
        if connector != ConnectorId::Tor {
            return;
        }
        let mut next = self.tally;
        next.known = Some(u32::try_from(known).unwrap_or(u32::MAX));
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

    use shekyl_peerlist::NetworkAddress;
    use shekyl_timing_engine::{Clock, ManualClock, Tick};
    use shekyl_transport_layer::{DialFailure, Reached, Retry};

    use super::*;

    fn onion(n: u8) -> NetworkAddress {
        let host = format!("{}.onion", char::from(b'a' + n).to_string().repeat(56));
        NetworkAddress::Tor { host, port: 12021 }
    }

    fn failed(n: u8, failure: DialFailure) -> DialOutcome {
        DialOutcome::DialFailed(onion(n), failure)
    }

    /// The process clock read at `nanos`.
    fn at(nanos: u64) -> Stamp {
        ManualClock::new(Tick::new(nanos)).stamp()
    }

    /// Every failed dial with no stream is one unopened dial, whatever its
    /// evidence: each reply, the dial deadline and this node's own proxy
    /// alike. A stream that opened, even one the peer then refused, resets
    /// the count.
    #[test]
    fn any_dial_without_a_stream_is_unopened_and_an_opened_one_resets() {
        let mut fold = LinkFold::new();
        for reply in [0x01, 0x06, 0xF0, 0xF2, 0xF3, 0xF7] {
            fold.observe(
                ConnectorId::Tor,
                &failed(0, shekyl_tor::stamp_reply(reply)),
                at(0),
            );
        }
        fold.observe(
            ConnectorId::Tor,
            &failed(1, shekyl_tor::Observed::Deadline.end().failure()),
            at(0),
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(2, shekyl_tor::Observed::ProxyUnavailable.end().failure()),
            at(0),
        );
        assert_eq!(
            fold.tally(),
            TorLinkTally {
                opened: 0,
                unopened: 8,
                last_sign_of_life: None,
                failed_attempt_began: Some(at(0)),
                known: None,
            }
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(
                3,
                DialFailure::refused_by_peer(ConnectorId::Tor, Reached::StreamOpened),
            ),
            at(0),
        );
        assert_eq!(
            fold.tally().opened,
            1,
            "a rejected handshake reached a peer"
        );
        assert_eq!(fold.tally().unopened, 0);
    }

    /// A payload refusal is the close of a session already counted. It
    /// leaves the dial counts where the open and the failures since it put
    /// them.
    #[test]
    fn a_payload_refusal_is_not_another_open() {
        let mut fold = LinkFold::new();
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::SessionAccepted(onion(0)),
            at(0),
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(1, shekyl_tor::stamp_reply(0x06)),
            at(1),
        );
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::PayloadRefused(onion(0)),
            at(2),
        );
        assert_eq!(fold.tally().opened, 1, "the close is not a new stream");
        assert_eq!(fold.tally().unopened, 1, "failed dials since the open stay");
    }

    /// A census of the Tor connector sets the known count, and only a
    /// change is published; another connector's census leaves it.
    #[test]
    fn a_tor_census_sets_the_known_count() {
        let published = Arc::new(Mutex::new(Vec::new()));
        let mut fold = LinkFold::new();
        let sink = Arc::clone(&published);
        fold.set_sink(Arc::new(move |tally| {
            sink.lock().expect("sink").push(tally.known)
        }));
        fold.census(ConnectorId::Tor, 0);
        fold.census(ConnectorId::Tor, 0);
        fold.census(ConnectorId::Clearnet, 5);
        fold.census(ConnectorId::Tor, 6);
        assert_eq!(
            *published.lock().expect("sink"),
            vec![None, Some(0), Some(6)],
            "the first tally at the sink, then each change"
        );
    }

    /// Another connector's dials say nothing about Tor.
    #[test]
    fn other_connectors_leave_the_tally_alone() {
        let mut fold = LinkFold::new();
        let clearnet = NetworkAddress::Ipv4 {
            ip: std::net::Ipv4Addr::new(203, 0, 113, 7),
            port: 11021,
        };
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::DialFailed(
                clearnet.clone(),
                DialFailure::destination(Retry::Again, Reached::NoStream),
            ),
            at(0),
        );
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::SessionAccepted(clearnet),
            at(0),
        );
        fold.life(ConnectorId::Clearnet, at(5));
        assert_eq!(fold.tally(), TorLinkTally::default());
    }

    /// The sink hears the tally at install and then only changes.
    #[test]
    fn the_sink_hears_the_tally_at_install_and_then_only_changes() {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let sink_heard = Arc::clone(&heard);
        let mut fold = LinkFold::new();
        fold.set_sink(Arc::new(move |tally| {
            sink_heard.lock().expect("heard").push(tally);
        }));
        fold.life(ConnectorId::Tor, at(3));
        fold.life(ConnectorId::Tor, at(3));
        let heard = heard.lock().expect("heard");
        assert_eq!(heard.len(), 2, "the initial tally, then the one change");
        assert_eq!(heard[1].last_sign_of_life, Some(at(3)));
    }

    /// The tally keeps the latest launch among failed dials, not the last
    /// one counted. A dial launched early and counted late does not move
    /// the launch back; later life and a later open leave it alone.
    /// Taking the counted attempt's launch instead of the latest fails the
    /// second assertion.
    #[test]
    fn a_failed_dial_keeps_the_latest_launch_among_failures() {
        let mut fold = LinkFold::new();
        fold.observe(
            ConnectorId::Tor,
            &failed(0, shekyl_tor::stamp_reply(0x01)),
            at(10),
        );
        assert_eq!(fold.tally().failed_attempt_began, Some(at(10)));
        fold.observe(
            ConnectorId::Tor,
            &failed(1, shekyl_tor::stamp_reply(0x01)),
            at(4),
        );
        assert_eq!(
            fold.tally().failed_attempt_began,
            Some(at(10)),
            "an older launch counted later does not move the latest back"
        );
        fold.life(ConnectorId::Tor, at(20));
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::SessionAccepted(onion(2)),
            at(30),
        );
        assert_eq!(fold.tally().unopened, 0, "an open resets the count");
        assert_eq!(
            fold.tally().failed_attempt_began,
            Some(at(10)),
            "life and an open leave the failure's launch"
        );
    }
}

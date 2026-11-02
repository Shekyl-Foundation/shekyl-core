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

use shekyl_peerlist::{ConnectorId, DialOutcome, Tick};

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
    /// Tor sessions this node holds now: outbound sessions the dialer
    /// kept, plus inbound sessions on the board.
    pub held: u32,
    /// When the dialer's judge last saw the link work, on the process
    /// clock: a stream that opened, or a byte a session received
    /// (`DIALER_OUTAGE_EVIDENCE.md` §4.1). `None` until the first.
    pub last_sign_of_life: Option<Tick>,
    /// When a Tor dial last ended without a stream, on the process clock.
    /// The quiet line dates that failure here: the tally the supervisor
    /// receives can also carry a later sign of life, and the watch keeps
    /// only the latest value. `None` until the first. An opened stream
    /// does not clear it.
    pub last_unopened_at: Option<Tick>,
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
    /// reached a peer opened a stream; every other failure, this node's own
    /// included, is a dial that ended without one, dated at `now`. A
    /// payload refusal is not a dial: it names a kept session the payload
    /// owner declined, and that stream was counted when the dial was
    /// accepted. An opened stream does not clear the failure's instant.
    pub(crate) fn observe(
        &mut self,
        connector: ConnectorId,
        outcome: &DialOutcome,
        held: usize,
        now: Tick,
    ) {
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
                next.last_unopened_at = Some(now);
            }
        }
        next.held = u32::try_from(held).unwrap_or(u32::MAX);
        self.publish(next);
    }

    /// The judge saw `connector`'s link work at `now`: the tally's last
    /// sign of life when it is the Tor link.
    pub(crate) fn life(&mut self, connector: ConnectorId, now: Tick) {
        if connector != ConnectorId::Tor {
            return;
        }
        let mut next = self.tally;
        next.last_sign_of_life = Some(now);
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

    use shekyl_peerlist::NetworkAddress;
    use shekyl_transport_layer::{DialFailure, Reached, Retry};

    use super::*;

    fn onion(n: u8) -> NetworkAddress {
        let host = format!("{}.onion", char::from(b'a' + n).to_string().repeat(56));
        NetworkAddress::Tor { host, port: 12021 }
    }

    fn failed(n: u8, failure: DialFailure) -> DialOutcome {
        DialOutcome::DialFailed(onion(n), failure)
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
                0,
                Tick::new(0),
            );
        }
        fold.observe(
            ConnectorId::Tor,
            &failed(1, shekyl_tor::Observed::Deadline.end().failure()),
            0,
            Tick::new(0),
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(2, shekyl_tor::Observed::ProxyUnavailable.end().failure()),
            0,
            Tick::new(0),
        );
        assert_eq!(
            fold.tally(),
            TorLinkTally {
                opened: 0,
                unopened: 8,
                held: 0,
                last_sign_of_life: None,
                last_unopened_at: Some(Tick::new(0)),
            }
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(
                3,
                DialFailure::refused_by_peer(ConnectorId::Tor, Reached::StreamOpened),
            ),
            0,
            Tick::new(0),
        );
        assert_eq!(
            fold.tally().opened,
            1,
            "a rejected handshake reached a peer"
        );
        assert_eq!(fold.tally().unopened, 0);
    }

    /// A payload refusal is the close of a session already counted. It
    /// moves the held count and leaves the dial counts where the open
    /// and the failures since it put them.
    #[test]
    fn a_payload_refusal_is_a_close_and_not_another_open() {
        let mut fold = LinkFold::new();
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::SessionAccepted(onion(0)),
            1,
            Tick::new(0),
        );
        fold.observe(
            ConnectorId::Tor,
            &failed(1, shekyl_tor::stamp_reply(0x06)),
            1,
            Tick::new(1),
        );
        let opened = fold.tally();
        assert_eq!(opened.opened, 1);
        assert_eq!(opened.unopened, 1);
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::PayloadRefused(onion(0)),
            0,
            Tick::new(2),
        );
        assert_eq!(fold.tally().opened, 1, "the close is not a new stream");
        assert_eq!(fold.tally().unopened, 1, "failed dials since the open stay");
        assert_eq!(fold.tally().held, 0);
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
            3,
            Tick::new(0),
        );
        fold.observe(
            ConnectorId::Clearnet,
            &DialOutcome::SessionAccepted(clearnet),
            3,
            Tick::new(0),
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
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::SessionAccepted(onion(0)),
            1,
            Tick::new(0),
        );
        fold.held(ConnectorId::Tor, 1);
        fold.held(ConnectorId::Tor, 0);
        let heard = heard.lock().expect("heard");
        assert_eq!(heard.len(), 3, "the initial tally, the accept, the close");
        assert_eq!(heard[1].held, 1);
        assert_eq!(heard[2].held, 0);
    }

    /// An unopened dial is dated when it ends. A later sign of life, and a
    /// stream that opens after it, leave that date: the quiet line reads it
    /// from the tally the watch delivers, which can carry both.
    #[test]
    fn an_unopened_dial_keeps_the_instant_it_ended() {
        let mut fold = LinkFold::new();
        let ended = Tick::new(10);
        fold.observe(
            ConnectorId::Tor,
            &failed(0, shekyl_tor::stamp_reply(0x01)),
            0,
            ended,
        );
        assert_eq!(fold.tally().last_unopened_at, Some(ended));
        fold.life(ConnectorId::Tor, Tick::new(20));
        assert_eq!(fold.tally().last_sign_of_life, Some(Tick::new(20)));
        assert_eq!(
            fold.tally().last_unopened_at,
            Some(ended),
            "a later byte does not move the failure"
        );
        fold.observe(
            ConnectorId::Tor,
            &DialOutcome::SessionAccepted(onion(1)),
            1,
            Tick::new(30),
        );
        assert_eq!(fold.tally().unopened, 0, "an open resets the count");
        assert_eq!(
            fold.tally().last_unopened_at,
            Some(ended),
            "an open does not forget when the last failure ended"
        );
    }
}

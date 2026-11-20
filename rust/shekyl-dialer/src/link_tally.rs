// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one connector's dials show, for that connector's status line
//! (`DIALER_OUTAGE_EVIDENCE.md` §6): whether peers are known, and when a
//! dial that ended without a stream was launched. Published per connector
//! under connector-neutral names; the daemon wires each copy where it is
//! read (the Tor connector's to the Tor Manager).
//!
//! Display only, never a verdict on the path: whether the path works is the
//! connector's own reading (`shekyl_transport_layer::PathSource`), and
//! which reply a failed dial gets is the destination's to choose as much as
//! the path's. The tally carries no address and no reply code.

use std::sync::Arc;

use shekyl_peerlist::DialOutcome;
use shekyl_timing_engine::Stamp;

use crate::reach::{attempt_stream, AttemptStream};

/// A connector's latest census of the addresses it could dial.
///
/// [`Self::Pending`] is no census yet. [`Self::Empty`] is a census that
/// holds no address: zero is an answer. [`Self::Held`] is a non-empty run,
/// and `since` is the clock time of the census that opened it. A later
/// empty census ends the run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkCensus {
    /// No wake has censused the connector.
    #[default]
    Pending,
    /// The latest census holds no address.
    Empty,
    /// The latest census holds `seats` addresses, white and gray, cooling
    /// included. `since` opened this non-empty run.
    Held { seats: u32, since: Stamp },
}

/// What one connector's dials show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkTally {
    /// The latest `attempt_began` among dials that ended without a stream
    /// (`DIALER_OUTAGE_EVIDENCE.md` §6.1): when the dialer launched the
    /// attempt, not when it was counted. A dial sent before a respawn, or
    /// before a wake, fails after the reader's stretch begins, and its
    /// launch says it did not test the path since. `None` until the first.
    /// An opened stream does not clear it.
    pub failed_attempt_began: Option<Stamp>,
    /// The connector's latest census. [`LinkCensus::Pending`] until the first
    /// wake of that connector, including a wake that only resumes a retry
    /// (Rick, 2026-11-10).
    pub census: LinkCensus,
}

/// Where a connector's tally goes. Called under the dialer's lock: it must
/// not block.
pub type TallySink = Arc<dyn Fn(LinkTally) + Send + Sync>;

/// The running fold over one connector's dial outcomes.
pub(crate) struct LinkFold {
    tally: LinkTally,
    sink: Option<TallySink>,
}

impl LinkFold {
    pub(crate) fn new() -> Self {
        Self {
            tally: LinkTally::default(),
            sink: None,
        }
    }

    /// Send every later tally to `sink`, and the current one now.
    pub(crate) fn set_sink(&mut self, sink: TallySink) {
        sink(self.tally);
        self.sink = Some(sink);
    }

    pub(crate) fn tally(&self) -> LinkTally {
        self.tally
    }

    /// Fold one dial attempt's outcome: the test's outcome, or a failed
    /// attempt deferred for a retry. A dial that ended without a stream,
    /// this node's own failures included, moves the latest launch among
    /// those to `began` when it is later. A stream that opened, and a
    /// payload refusal (the close of a session already counted), leave it.
    pub(crate) fn observe(&mut self, outcome: &DialOutcome, began: Stamp) {
        if attempt_stream(outcome) == AttemptStream::Unopened {
            let mut next = self.tally;
            next.failed_attempt_began = next.failed_attempt_began.max(Some(began));
            self.publish(next);
        }
    }

    /// A census of `seats` at `at`. Zero seats is [`LinkCensus::Empty`]. A
    /// positive count continues the open run, or opens one at `at`.
    pub(crate) fn census(&mut self, seats: usize, at: Stamp) {
        let seats = seats_held(seats);
        let census = if seats == 0 {
            LinkCensus::Empty
        } else {
            let since = match self.tally.census {
                LinkCensus::Held { since, .. } => since,
                LinkCensus::Pending | LinkCensus::Empty => at,
            };
            LinkCensus::Held { seats, since }
        };
        let mut next = self.tally;
        next.census = census;
        self.publish(next);
    }

    fn publish(&mut self, next: LinkTally) {
        if next == self.tally {
            return;
        }
        self.tally = next;
        if let Some(sink) = &self.sink {
            sink(next);
        }
    }
}

/// A seat count for the census. A count past `u32` saturates. Saturation
/// is still a non-empty run: [`LinkCensus::Pending`] and [`LinkCensus::Empty`] are
/// the states that are not a count.
fn seats_held(seats: usize) -> u32 {
    u32::try_from(seats).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use shekyl_peerlist::NetworkAddress;
    use shekyl_timing_engine::{Clock, ManualClock, Tick};
    use shekyl_transport_layer::{DialFailure, Reached, Retry};

    use super::*;

    fn peer(n: u8) -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: std::net::Ipv4Addr::new(203, 0, 113, n),
            port: 11021,
        }
    }

    fn failed(n: u8, failure: DialFailure) -> DialOutcome {
        DialOutcome::DialFailed(peer(n), failure)
    }

    /// The process clock read at `nanos`.
    fn at(nanos: u64) -> Stamp {
        ManualClock::new(Tick::new(nanos)).stamp()
    }

    /// Every dial that ended without a stream is a failed launch, whatever
    /// its evidence. A stream that opened, even one the peer then refused,
    /// and a payload refusal leave the launch where it was. Counting an
    /// opened stream as a failure fails this.
    #[test]
    fn only_a_dial_without_a_stream_is_a_failed_launch() {
        let mut fold = LinkFold::new();
        for (n, failure) in [
            DialFailure::destination(Retry::Again, Reached::NoStream),
            DialFailure::uncertain(Retry::AgainInsideWindow, Reached::NoStream),
            DialFailure::local(Retry::Again, Reached::NoStream),
        ]
        .into_iter()
        .enumerate()
        {
            let n = u8::try_from(n).expect("three");
            fold.observe(&failed(n, failure), at(u64::from(n) + 1));
        }
        assert_eq!(fold.tally().failed_attempt_began, Some(at(3)));
        fold.observe(
            &failed(
                4,
                DialFailure::uncertain(Retry::Again, Reached::StreamOpened),
            ),
            at(9),
        );
        fold.observe(&DialOutcome::SessionAccepted(peer(5)), at(10));
        fold.observe(&DialOutcome::PayloadRefused(peer(5)), at(11));
        assert_eq!(
            fold.tally().failed_attempt_began,
            Some(at(3)),
            "a stream that opened is not a failed launch"
        );
    }

    /// A census sets the census, and only a change is published. A later
    /// positive count keeps the run's `since`; an empty census ends the
    /// run, and the next positive count opens a new one. Resetting `since`
    /// on every census, or treating a repeat as a change, fails this.
    #[test]
    fn a_census_sets_the_run_and_keeps_its_start() {
        let published = Arc::new(Mutex::new(Vec::new()));
        let mut fold = LinkFold::new();
        let sink = Arc::clone(&published);
        fold.set_sink(Arc::new(move |tally| {
            sink.lock().expect("sink").push(tally.census);
        }));
        let opened = at(10);
        let later = at(40);
        let reopened = at(70);
        fold.census(0, opened);
        fold.census(0, later);
        fold.census(6, opened);
        fold.census(7, later);
        fold.census(0, later);
        fold.census(2, reopened);
        assert_eq!(
            *published.lock().expect("sink"),
            vec![
                LinkCensus::Pending,
                LinkCensus::Empty,
                LinkCensus::Held {
                    seats: 6,
                    since: opened,
                },
                LinkCensus::Held {
                    seats: 7,
                    since: opened,
                },
                LinkCensus::Empty,
                LinkCensus::Held {
                    seats: 2,
                    since: reopened,
                },
            ],
            "the first tally at the sink, then each change of the run"
        );
    }

    /// The tally keeps the latest launch among failed dials, not the last
    /// one counted: a dial launched early and counted late does not move
    /// the launch back. Taking the counted attempt's launch fails this.
    #[test]
    fn a_failed_dial_keeps_the_latest_launch_among_failures() {
        let mut fold = LinkFold::new();
        let lost = || DialFailure::uncertain(Retry::Again, Reached::NoStream);
        fold.observe(&failed(0, lost()), at(10));
        fold.observe(&failed(1, lost()), at(4));
        assert_eq!(
            fold.tally().failed_attempt_began,
            Some(at(10)),
            "an older launch counted later does not move the latest back"
        );
    }
}

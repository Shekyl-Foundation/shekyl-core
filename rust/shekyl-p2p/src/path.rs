// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Each connector's source of path readings
//! (`shekyl_transport_layer::PathSource`; `DIALER_OUTAGE_EVIDENCE.md` §3.3,
//! Rick 2026-11-15), and what the Tor connector tells the Tor Manager.
//!
//! - **Tor** asks the Tor Manager. The manager publishes its one reading
//!   through [`crate::Network::publish_onion_path`]; a failure with no
//!   reading after it is posted to the manager as a want, and the reading
//!   that answers it rings the dialer's bell. The Tor connector also tells
//!   the manager each outbound onion dial that completed and each new
//!   inbound Tor session. The dialer is not involved in either.
//! - **Clearnet** reads its own outbound sessions: a byte received on one
//!   after the failure is a working reading. The byte's stamp is the
//!   byte-stamp clock, captured once at the first ask
//!   ([`ByteMarks`]), and a byte counts only strictly after that mark.
//!   Inbound sessions do not count: an inbound peer chose this node, and a
//!   party that blocks this node's outbound connects can let established
//!   inbound flows continue.

use std::sync::{Arc, Mutex};

use shekyl_p2p_session::SessionLayer;
use shekyl_timing_engine::{MonotonicClock, Stamp};
use shekyl_transport_layer::{
    monotonic_ms, ConnectorId, Direction, PathReading, PathReady, PathSource,
};

/// What the Tor connector tells the Tor Manager about the onion path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathFact {
    /// An outbound onion dial completed: its stream opened.
    OnionDialOpened(Stamp),
    /// A new inbound Tor session finished its handshake. The probe of this
    /// node's own onion is dropped in that handshake, so it is never one.
    InboundTorSession(Stamp),
    /// A failed dial at this instant waits for a reading after it.
    Wanted(Stamp),
}

/// Where the Tor connector's facts go: the Tor Manager. Must not block.
pub type PathFactsSink = Arc<dyn Fn(PathFact) + Send + Sync>;

#[derive(Default)]
struct OnionState {
    /// The manager's latest reading, and the instant it was learned on the
    /// process clock, in nanoseconds.
    latest: Option<(PathReading, u64)>,
    /// The latest failure posted as a want, in nanoseconds.
    asked: Option<u64>,
    /// What the last ask gave to ring.
    ready: Option<PathReady>,
}

/// The Tor connector's source: the Tor Manager's reading.
pub(crate) struct OnionPathSource {
    state: Mutex<OnionState>,
    facts: Option<PathFactsSink>,
    wait_nanos: u64,
}

impl OnionPathSource {
    /// A source that posts wants to `facts`, with `wait_nanos` as its
    /// declared wait. With no manager (`facts` is `None`) it has no
    /// reading, and every uncertain failure is excused at once.
    pub(crate) fn new(facts: Option<PathFactsSink>, wait_nanos: u64) -> Self {
        let wait_nanos = if facts.is_some() { wait_nanos } else { 0 };
        Self {
            state: Mutex::default(),
            facts,
            wait_nanos,
        }
    }

    /// The manager's reading, learned at `at_nanos` on the process clock.
    /// A reading older than the one held changes nothing. A newer one
    /// rings the dialer's bell.
    pub(crate) fn publish(&self, reading: PathReading, at_nanos: u64) {
        let ready = {
            let mut state = self.state.lock().expect("onion path");
            if state.latest.is_some_and(|(_, at)| at > at_nanos) {
                return;
            }
            state.latest = Some((reading, at_nanos));
            state.ready.clone()
        };
        if let Some(ready) = ready {
            ready();
        }
    }
}

impl PathSource for OnionPathSource {
    fn reading_after(&self, failed: Stamp, _now: Stamp, ready: &PathReady) -> Option<PathReading> {
        let failed_nanos = failed.tick().get();
        let post = {
            let mut state = self.state.lock().expect("onion path");
            state.ready = Some(Arc::clone(ready));
            if let Some((reading, _)) = state.latest.filter(|(_, at)| *at > failed_nanos) {
                return Some(reading);
            }
            let post = state.asked.is_none_or(|asked| failed_nanos > asked);
            if post {
                state.asked = Some(failed_nanos);
            }
            post
        };
        if post {
            if let Some(facts) = &self.facts {
                facts(PathFact::Wanted(failed));
            }
        }
        None
    }

    fn wait_nanos(&self) -> u64 {
        self.wait_nanos
    }
}

/// One failure's place on the byte-stamp clock.
struct OpenFailure {
    /// The failure, in nanoseconds on the process clock.
    failed: u64,
    /// [`monotonic_ms`] at the first ask for this failure.
    at_ms: u64,
}

/// The byte-stamp mark of each failure still inside its wait.
///
/// Byte stamps are [`monotonic_ms`]. That clock is not the process clock:
/// on Windows `Instant` counts through S3 sleep and the process clock does
/// not (`P2P_TIMING_ENGINE.md` §8). An age on one minus an age on the other
/// dates a byte on the wrong side of a failure after suspend. The mark is
/// the byte clock at the first ask, and every later ask for that failure
/// reads the same mark. The dialer asks in the turn that records the
/// failure, so the mark is that failure on this clock. A received byte
/// counts only when its stamp is strictly after the mark.
struct ByteMarks {
    open: Vec<OpenFailure>,
    /// How long the judge keeps asking, on the process clock. A mark older
    /// than this is dropped on the next ask for some other failure. The
    /// failure being asked is kept, so the ask that meets its deadline
    /// still reads the mark taken at the first ask.
    wait_nanos: u64,
}

impl ByteMarks {
    fn new(wait_nanos: u64) -> Self {
        Self {
            open: Vec::new(),
            wait_nanos,
        }
    }

    /// The byte-clock mark of `failed`, taken as `byte_now` on the first
    /// ask. `now` is the process clock at this ask, and it drops marks
    /// whose wait has elapsed.
    fn mark(&mut self, failed: u64, now: u64, byte_now: u64) -> u64 {
        let at_ms = if let Some(failure) = self.open.iter().find(|failure| failure.failed == failed)
        {
            failure.at_ms
        } else {
            self.open.push(OpenFailure {
                failed,
                at_ms: byte_now,
            });
            byte_now
        };
        let wait = self.wait_nanos;
        self.open.retain(|failure| {
            failure.failed == failed || now.saturating_sub(failure.failed) <= wait
        });
        at_ms
    }
}

/// A byte stamped at `received_ms` arrived after the failure's mark.
/// Zero is no byte: [`monotonic_ms`] is never zero, and a mark taken from
/// it is not either.
fn byte_after(received_ms: u64, mark_ms: u64) -> bool {
    received_ms > mark_ms
}

/// Whether this row is one of `connector`'s established outbound sessions.
/// Inbound sessions do not count, and neither does a handshake still open.
fn outbound_session(
    established: bool,
    connector: ConnectorId,
    direction: Direction,
    want: ConnectorId,
) -> bool {
    established && connector == want && direction == Direction::Outbound
}

/// A working reading when any received byte is strictly after `mark_ms`.
fn reading_of(mut received: impl Iterator<Item = u64>, mark_ms: u64) -> Option<PathReading> {
    received
        .any(|received_ms| byte_after(received_ms, mark_ms))
        .then_some(PathReading::Working)
}

/// A connector's source read from its own outbound sessions: a byte one of
/// them received after the failure is a working reading. With none within
/// the connector's wait the failure is excused. Clearnet's source.
///
/// There is no bell for a byte. The owner loop asks again on its wake, and
/// the mark stays the first ask's, so a byte that arrives between asks is
/// still after the failure when the next ask reads it.
pub(crate) struct OutboundSessions {
    layer: SessionLayer<MonotonicClock>,
    connector: ConnectorId,
    wait_nanos: u64,
    marks: Mutex<ByteMarks>,
}

impl OutboundSessions {
    pub(crate) fn new(
        layer: SessionLayer<MonotonicClock>,
        connector: ConnectorId,
        wait_nanos: u64,
    ) -> Self {
        Self {
            layer,
            connector,
            wait_nanos,
            marks: Mutex::new(ByteMarks::new(wait_nanos)),
        }
    }
}

impl PathSource for OutboundSessions {
    fn reading_after(&self, failed: Stamp, now: Stamp, _: &PathReady) -> Option<PathReading> {
        let mark = self.marks.lock().expect("byte marks").mark(
            failed.tick().get(),
            now.tick().get(),
            monotonic_ms(),
        );
        let gate = shekyl_capped_stream::node_gate();
        let want = self.connector;
        reading_of(
            self.layer
                .board()
                .rows()
                .iter()
                .filter(|row| {
                    outbound_session(row.established(), row.connector(), row.direction(), want)
                })
                .map(|row| gate.activity(row.id().get()).1),
            mark,
        )
    }

    fn wait_nanos(&self) -> u64 {
        self.wait_nanos
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use shekyl_timing_engine::{Clock, ManualClock, Tick};

    use super::*;

    fn at(nanos: u64) -> Stamp {
        ManualClock::new(Tick::new(nanos)).stamp()
    }

    /// A source posting into a recorded list, and a bell that counts rings.
    fn source() -> (
        OnionPathSource,
        Arc<Mutex<Vec<PathFact>>>,
        PathReady,
        Arc<AtomicUsize>,
    ) {
        let posted = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&posted);
        let facts: PathFactsSink = Arc::new(move |fact| sink.lock().expect("posted").push(fact));
        let rings = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&rings);
        let ready: PathReady = Arc::new(move || {
            counter.fetch_add(1, Ordering::AcqRel);
        });
        (OnionPathSource::new(Some(facts), 60), posted, ready, rings)
    }

    /// **A failure with no reading after it is posted to the manager once,
    /// and the reading that answers it rings the dialer's bell.** Asking
    /// again for the same failure posts nothing; a later failure posts its
    /// own want. The edits that make this red: posting on every ask, never
    /// posting, or a publish that rings nothing.
    #[test]
    fn a_want_is_posted_once_and_the_answer_rings() {
        let (source, posted, ready, rings) = source();
        assert_eq!(source.reading_after(at(10), at(11), &ready), None);
        assert_eq!(source.reading_after(at(10), at(12), &ready), None);
        assert_eq!(
            *posted.lock().expect("posted"),
            vec![PathFact::Wanted(at(10))],
            "one want for the failure"
        );
        source.publish(PathReading::Working, 20);
        assert_eq!(rings.load(Ordering::Acquire), 1, "the answer rings");
        assert_eq!(
            source.reading_after(at(10), at(21), &ready),
            Some(PathReading::Working)
        );
        assert_eq!(source.reading_after(at(30), at(31), &ready), None);
        assert_eq!(
            posted.lock().expect("posted").last(),
            Some(&PathFact::Wanted(at(30))),
            "a later failure posts its own want"
        );
    }

    /// **Only a reading after the failure answers it**, and an older
    /// publish never replaces a newer reading. The edits that make this
    /// red: answering from a reading at or before the failure, or taking
    /// the last publish whatever its instant.
    #[test]
    fn only_a_reading_after_the_failure_answers_it() {
        let (source, _, ready, _) = source();
        source.publish(PathReading::Impaired, 50);
        assert_eq!(source.reading_after(at(50), at(51), &ready), None);
        assert_eq!(
            source.reading_after(at(49), at(51), &ready),
            Some(PathReading::Impaired)
        );
        source.publish(PathReading::Working, 40);
        assert_eq!(
            source.reading_after(at(49), at(52), &ready),
            Some(PathReading::Impaired),
            "the older publish changed nothing"
        );
    }

    /// **With no manager there is no reading and no wait**: the judge
    /// excuses at once. The edit that makes this red is a wait with no one
    /// to answer it.
    #[test]
    fn with_no_manager_there_is_no_reading_and_no_wait() {
        let source = OnionPathSource::new(None, 60);
        let ready: PathReady = Arc::new(|| {});
        assert_eq!(source.wait_nanos(), 0);
        assert_eq!(source.reading_after(at(1), at(2), &ready), None);
    }

    /// **The first ask freezes the byte-clock mark**, and a later ask for
    /// the same failure reads it back. Each failure has its own mark. The
    /// edit that makes this red is taking the byte clock again on every
    /// ask, or one mark shared by every failure.
    #[test]
    fn the_first_ask_freezes_the_byte_mark() {
        let mut marks = ByteMarks::new(1_000);
        assert_eq!(marks.mark(10, 20, 100), 100);
        assert_eq!(
            marks.mark(10, 21, 999),
            100,
            "the later byte clock is ignored"
        );
        assert_eq!(
            marks.mark(15, 21, 140),
            140,
            "the next failure has its own mark"
        );
        assert_eq!(marks.mark(10, 22, 999), 100);
    }

    /// **A byte counts only strictly after the mark.** The stamp at the
    /// mark is the ask itself, and zero is no byte. The edit that makes
    /// this red is counting a byte from before the failure, or comparing
    /// the byte's age on this clock with the failure's age on the process
    /// clock.
    #[test]
    fn a_byte_counts_only_strictly_after_the_mark() {
        assert!(!byte_after(0, 100), "no byte yet");
        assert!(!byte_after(100, 100), "the mark itself is the ask");
        assert!(byte_after(101, 100));
        assert_eq!(reading_of([0, 100].into_iter(), 100), None);
        assert_eq!(
            reading_of([50, 101].into_iter(), 100),
            Some(PathReading::Working)
        );
    }

    /// **The ask that meets the deadline still reads the original mark**,
    /// and the next failure's ask drops a mark whose wait has elapsed.
    /// The edit that makes this red is moving the mark forward on the late
    /// ask, or keeping every mark for the life of the process.
    #[test]
    fn a_late_ask_keeps_its_mark_and_the_next_ask_drops_one_past_its_wait() {
        let wait = 1_000;
        let mut marks = ByteMarks::new(wait);
        assert_eq!(marks.mark(10, 10, 100), 100);
        let late = 10 + wait + 5;
        assert_eq!(
            marks.mark(10, late, 500),
            100,
            "the deadline ask is the first mark"
        );
        assert_eq!(marks.mark(80, late, 200), 200);
        assert_eq!(
            marks.mark(10, late, 300),
            300,
            "the mark past its wait was dropped"
        );
    }

    /// **Only an established outbound session of this connector counts.**
    /// An inbound session, another connector, and a handshake still open
    /// do not. The edit that makes this red is counting any of those.
    #[test]
    fn only_an_established_outbound_session_of_this_connector_counts() {
        let want = ConnectorId::Clearnet;
        assert!(outbound_session(
            true,
            ConnectorId::Clearnet,
            Direction::Outbound,
            want
        ));
        assert!(!outbound_session(
            true,
            ConnectorId::Clearnet,
            Direction::Inbound,
            want
        ));
        assert!(!outbound_session(
            true,
            ConnectorId::Tor,
            Direction::Outbound,
            want
        ));
        assert!(!outbound_session(
            false,
            ConnectorId::Clearnet,
            Direction::Outbound,
            want
        ));
    }
}

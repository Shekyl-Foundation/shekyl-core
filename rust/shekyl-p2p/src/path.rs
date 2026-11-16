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
//!   after the failure is a working reading. Inbound sessions do not count:
//!   an inbound peer chose this node, and a party that blocks this node's
//!   outbound connects can let established inbound flows continue.

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

/// A connector's source read from its own outbound sessions: a byte one of
/// them received after the failure is a working reading. With none within
/// the connector's wait the failure is excused. Clearnet's source.
pub(crate) struct OutboundSessions {
    layer: SessionLayer<MonotonicClock>,
    connector: ConnectorId,
    wait_nanos: u64,
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
        }
    }
}

impl PathSource for OutboundSessions {
    /// The byte stamps are on their own clock (`monotonic_ms`), so the
    /// comparison is by age, read at one instant: a byte whose age is less
    /// than the time since the failure arrived after it.
    fn reading_after(&self, failed: Stamp, now: Stamp, _: &PathReady) -> Option<PathReading> {
        let since_failure_ms = now.tick().get().saturating_sub(failed.tick().get()) / 1_000_000;
        let now_ms = monotonic_ms();
        let gate = shekyl_capped_stream::node_gate();
        self.layer
            .board()
            .rows()
            .iter()
            .filter(|row| {
                row.established()
                    && row.connector() == self.connector
                    && row.direction() == Direction::Outbound
            })
            .map(|row| gate.activity(row.id().get()).1)
            .any(|received_ms| {
                received_ms > 0 && now_ms.saturating_sub(received_ms) < since_failure_ms
            })
            .then_some(PathReading::Working)
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
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! White is known-working (Rick, 2026-10-26). A white address whose test
//! fails, while the link shows it works, moves to gray and cools on the
//! ladder: on clearnet after one redial, on Tor after its attempts. A
//! failure the link does not corroborate is excused, and the address stays
//! white (`DIALER_OUTAGE_EVIDENCE.md` §4.1). These tests use the attempt
//! rig.

use std::sync::Arc;
use std::time::Duration;

use shekyl_dialer::Dialer;
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{ConnectorId, NetworkAddress, Tick};
use shekyl_seam::{Dial, Hub, SocketId};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::DialEnd;
use shekyl_transport_layer::Sockets;

use super::life::Life;
use super::{dialer_on, onions, peer, reply, HeldDial, CLEARNET, NETWORK, TOR, TOR_WINDOW};

/// One rig for white is known-working (Rick, 2026-10-26): `count` addresses
/// on `connector`, each made white by a kept session that the peer then
/// closed, so every one is white and none is held.
struct WhiteRig {
    clock: ManualClock,
    hub: Hub,
    dial: Arc<HeldDial>,
    dialer: Arc<Dialer>,
    connector: ConnectorId,
    white: Vec<NetworkAddress>,
    life: Life,
    rng: SplitMix64,
}

impl WhiteRig {
    fn new(connector: ConnectorId, seed: u64, count: usize) -> Self {
        let clock = ManualClock::new(Tick::new(1_000_000_000));
        let sockets = Sockets::new();
        let dial = Arc::new(HeldDial::answering(
            sockets.clone(),
            std::iter::repeat_n(reply(NETWORK), count).collect(),
        ));
        let (hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
        dialer.set_window(TOR, Some(TOR_WINDOW));
        let life = Life::install(&dialer, &clock);
        let mut rng = SplitMix64::new(seed);
        let addresses: Vec<NetworkAddress> = match connector {
            ConnectorId::Tor => onions(count),
            ConnectorId::Clearnet => (1..=count)
                .map(|n| peer(700 + u16::try_from(n).expect("small")))
                .collect(),
        };
        for address in &addresses {
            dialer
                .admit_operator(address, Tick::new(1), &mut rng)
                .expect("admitted");
        }
        for _ in 0..count {
            assert!(dialer.wake(connector, &mut rng), "a keep");
        }
        for address in &addresses {
            assert!(dialer.shared().lists.is_white(address), "{address:?} white");
        }
        let rig = Self {
            clock,
            hub,
            dial,
            dialer,
            connector,
            white: addresses,
            life,
            rng,
        };
        for id in rig.dial.opened() {
            rig.close(id);
        }
        assert_eq!(rig.dialer.kept_sessions(connector), 0, "none held");
        rig
    }

    /// The peer closes `id`'s session.
    fn close(&self, id: SocketId) {
        let end = crate::tables::peer_closed(self.connector);
        self.hub.finish(id, end);
        self.dialer
            .session_closed_from_seam(id, end, &mut SplitMix64::new(0));
    }

    fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).expect("a short span");
        self.clock.set(Tick::new(self.clock.now().get() + by));
    }

    /// One attempt at the drawable white address, refused with `cause`
    /// after `took`.
    fn attempt(&mut self, cause: DialEnd, took: Duration) {
        self.dial.refuse_after(&self.clock, cause, took);
        assert!(self.dialer.wake(self.connector, &mut self.rng), "a draw");
    }

    fn is_white(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_white(address)
    }

    fn is_cooling(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_cooling(address)
    }

    /// The cause, the time it takes, and the attempts one failed test of a
    /// white address makes, each an uncertain failure the judge weighs
    /// against the link: Tor's `0x06` at the window, final at once; a
    /// clearnet connect this node cannot read, then its one redial.
    fn failing_test(&self) -> (DialEnd, Duration, usize) {
        match self.connector {
            ConnectorId::Tor => (shekyl_tor::reply_end(0x06), TOR_WINDOW, 1),
            ConnectorId::Clearnet => (
                shekyl_clearnet::Observed::ConnectUncertain.end(),
                Duration::ZERO,
                2,
            ),
        }
    }

    /// Keep one more session to a white address, and return it with the
    /// white address that is not held. Its bytes are what the test shows.
    fn hold_one(&mut self) -> (SocketId, NetworkAddress) {
        let before = self.dial.opened();
        self.dial
            .answers
            .lock()
            .expect("answers")
            .push_back(reply(NETWORK));
        assert!(
            self.dialer.wake(self.connector, &mut self.rng),
            "a keep, held"
        );
        let held = self.dialer.shared().kept_addresses(self.connector);
        assert_eq!(held.len(), 1, "one held");
        let id = self
            .dial
            .opened()
            .into_iter()
            .find(|id| !before.contains(id))
            .expect("the held session");
        let failing = self
            .white
            .iter()
            .find(|address| !held.contains(*address))
            .cloned()
            .expect("one not held");
        (id, failing)
    }

    /// Past the bracket of the last failure, and its verdict performed.
    fn close_the_bracket(&mut self) {
        let bracket = shekyl_peerlist::dial_profile(self.connector)
            .judging
            .bracket_nanos;
        self.advance(Duration::from_nanos(bracket + 1_000_000));
        self.dialer.apply_verdicts(&mut self.rng);
    }

    fn fail_one_test(&mut self) {
        let (cause, took, attempts) = self.failing_test();
        for _ in 0..attempts {
            self.attempt(cause, took);
            self.advance(PAST_EVERY_RETRY_WAIT);
        }
    }
}

/// Past the longest retry wait (20 s + U(0, 10 s)).
const PAST_EVERY_RETRY_WAIT: Duration = Duration::from_secs(31);

/// **A white address failing its test is gray and cooling** (white is
/// known-working, Rick 2026-10-26), on a link a held session shows works.
/// On clearnet after its one redial: the first failure only waits; on Tor
/// after its three attempts, or at once when the attempt used Tor's whole
/// window. The verdict waits for its bracket to close.
#[test]
fn a_white_address_failing_its_test_is_gray_and_cooling() {
    let dial_failed = shekyl_clearnet::Observed::ConnectRefused.end();
    let mut rig = WhiteRig::new(CLEARNET, 71, 2);
    let (_, address) = rig.hold_one();
    rig.life.keep_alive();
    rig.attempt(dial_failed, Duration::ZERO);
    assert!(
        rig.is_white(&address),
        "clearnet: the first failure waits for its redial"
    );
    rig.advance(PAST_EVERY_RETRY_WAIT);
    rig.attempt(dial_failed, Duration::ZERO);
    assert_eq!(
        rig.dialer.pending_verdicts(CLEARNET),
        0,
        "a refused connect is the destination's answer: counted at once"
    );
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "clearnet: after the redial"
    );

    let early = shekyl_tor::reply_end(0xF0);
    let mut rig = WhiteRig::new(TOR, 72, 2);
    let (_, address) = rig.hold_one();
    rig.life.keep_alive();
    for attempt in 1..=2 {
        rig.attempt(early, Duration::from_secs(5));
        assert!(
            rig.is_white(&address),
            "Tor: attempt {attempt} waits for the next"
        );
        rig.advance(PAST_EVERY_RETRY_WAIT);
    }
    rig.attempt(early, Duration::from_secs(5));
    rig.close_the_bracket();
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "Tor: after its three"
    );

    let mut rig = WhiteRig::new(TOR, 73, 2);
    let (_, address) = rig.hold_one();
    rig.life.keep_alive();
    rig.attempt(shekyl_tor::reply_end(0x06), TOR_WINDOW);
    rig.close_the_bracket();
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "Tor: a full-window failure is already retried"
    );
}

/// **A clearnet white address whose redial succeeds stays white.**
#[test]
fn a_clearnet_white_address_whose_redial_succeeds_stays_white() {
    let mut rig = WhiteRig::new(CLEARNET, 74, 1);
    let address = rig.white[0].clone();
    rig.attempt(
        shekyl_clearnet::Observed::ConnectRefused.end(),
        Duration::ZERO,
    );
    rig.advance(PAST_EVERY_RETRY_WAIT);
    rig.dial
        .answers
        .lock()
        .expect("answers")
        .push_back(reply(NETWORK));
    assert!(rig.dialer.wake(CLEARNET, &mut rig.rng), "the redial");
    assert!(
        rig.is_white(&address) && !rig.is_cooling(&address),
        "it stays white"
    );
}

/// **With no sign of life a white failure is excused**: nothing held, and
/// nothing opened or received within the bracket before the failure, so
/// the failure says nothing about the address. It stays white, with no
/// verdict waiting. Both connectors. The edit that makes this red is
/// counting an uncorroborated failure.
#[test]
fn with_no_sign_of_life_a_white_failure_is_excused() {
    for (connector, seed) in [(TOR, 75), (CLEARNET, 76)] {
        let mut rig = WhiteRig::new(connector, seed, 1);
        let address = rig.white[0].clone();
        // The keeps' streams opened at the start: past the bracket now.
        rig.advance(PAST_EVERY_RETRY_WAIT);
        rig.fail_one_test();
        assert_eq!(rig.dialer.pending_verdicts(connector), 0, "{connector:?}");
        assert!(
            rig.is_white(&address) && !rig.is_cooling(&address),
            "{connector:?}: white survives a failure the link does not corroborate"
        );
    }
}

/// **A clearnet white redial is decided by the clearnet window** (the dial
/// profile brief, test 3). Clearnet's window is its dial deadline: a white
/// test whose first attempt times out at the deadline has used the whole
/// window, so it demotes with no redial; a refused connect is not a
/// timeout and waits for its redial. A publish does not move that
/// deadline: it is protocol data.
#[test]
fn a_clearnet_white_redial_is_decided_by_the_clearnet_window() {
    let profile = shekyl_peerlist::dial_profile(CLEARNET);
    assert_eq!(
        profile.window,
        shekyl_transport_layer::WindowSource::Deadline
    );
    let deadline = Duration::from_nanos(profile.dial_deadline_nanos);
    let mut rig = WhiteRig::new(CLEARNET, 79, 2);
    let (_, address) = rig.hold_one();
    rig.life.keep_alive();
    assert_eq!(rig.dialer.window(CLEARNET), Some(deadline));
    rig.dialer
        .set_window(CLEARNET, Some(Duration::from_secs(600)));
    assert_eq!(
        rig.dialer.window(CLEARNET),
        Some(deadline),
        "a publish does not move the deadline"
    );
    rig.attempt(shekyl_clearnet::Observed::Deadline.end(), deadline);
    rig.close_the_bracket();
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "a full-window timeout demotes with no redial"
    );
}

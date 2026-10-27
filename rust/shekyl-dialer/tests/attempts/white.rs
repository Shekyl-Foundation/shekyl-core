// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! White is known-working (Rick, 2026-10-26). A white address whose test
//! fails moves to gray and cools on the ladder: on clearnet after one
//! redial, on Tor after its attempts. In the quiet stretch it stays white.
//! These tests use the attempt rig.

use std::sync::Arc;
use std::time::Duration;

use shekyl_dialer::Dialer;
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{CloseCause, CloseKind, ConnectorId, NetworkAddress, Tick};
use shekyl_seam::{Dial, Hub, SocketId};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::Sockets;

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
        let cause = CloseCause::new(CloseKind::PeerClosed);
        self.hub.finish(id, cause);
        self.dialer
            .session_closed_from_seam(id, cause, &mut SplitMix64::new(0));
    }

    fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).expect("a short span");
        self.clock.set(Tick::new(self.clock.now().get() + by));
    }

    /// One attempt at the drawable white address, refused with `cause`
    /// after `took`.
    fn attempt(&mut self, cause: CloseCause, took: Duration) {
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
    /// white address makes: Tor's `0x06` at the window, final at once; a
    /// clearnet dial failure, then its one redial.
    fn failing_test(&self) -> (CloseCause, Duration, usize) {
        match self.connector {
            ConnectorId::Tor => (shekyl_tor::refused(0x06), TOR_WINDOW, 1),
            ConnectorId::Clearnet => (CloseCause::new(CloseKind::DialFailed), Duration::ZERO, 2),
        }
    }

    /// The quiet guard's evidence, with nothing held: S passes, then K
    /// fresh gray addresses each fail at once (gray is drawn while white is
    /// under its floor), and stay cooling while the white test runs.
    fn prime_quiet(&mut self) {
        let quiet = shekyl_peerlist::dial_profile(self.connector).quiet;
        self.advance(Duration::from_nanos(quiet.span_nanos));
        let k = usize::try_from(quiet.attempts).expect("small");
        let (primers, cause): (Vec<NetworkAddress>, CloseCause) = match self.connector {
            ConnectorId::Tor => (
                onions(self.white.len() + k).split_off(self.white.len()),
                shekyl_tor::refused(0xF1),
            ),
            ConnectorId::Clearnet => (
                (1..=k)
                    .map(|n| peer(900 + u16::try_from(n).expect("small")))
                    .collect(),
                CloseCause::new(CloseKind::DialFailed),
            ),
        };
        for address in &primers {
            self.dialer
                .admit_operator(address, self.clock.now(), &mut self.rng)
                .expect("admitted");
        }
        for _ in 0..k {
            self.attempt(cause, Duration::ZERO);
        }
        for address in &primers {
            assert!(self.is_cooling(address), "{address:?}: a primer failed");
        }
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
/// known-working, Rick 2026-10-26). On clearnet after its one redial: the
/// first failure only waits; on Tor after its three attempts, or at once
/// when the attempt used Tor's whole window.
#[test]
fn a_white_address_failing_its_test_is_gray_and_cooling() {
    let dial_failed = CloseCause::new(CloseKind::DialFailed);
    let mut rig = WhiteRig::new(CLEARNET, 71, 1);
    let address = rig.white[0].clone();
    rig.attempt(dial_failed, Duration::ZERO);
    assert!(
        rig.is_white(&address),
        "clearnet: the first failure waits for its redial"
    );
    rig.advance(PAST_EVERY_RETRY_WAIT);
    rig.attempt(dial_failed, Duration::ZERO);
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "clearnet: after the redial"
    );

    let early = shekyl_tor::refused(0xF0);
    let mut rig = WhiteRig::new(TOR, 72, 1);
    let address = rig.white[0].clone();
    for attempt in 1..=2 {
        rig.attempt(early, Duration::from_secs(5));
        assert!(
            rig.is_white(&address),
            "Tor: attempt {attempt} waits for the next"
        );
        rig.advance(PAST_EVERY_RETRY_WAIT);
    }
    rig.attempt(early, Duration::from_secs(5));
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "Tor: after its three"
    );

    let mut rig = WhiteRig::new(TOR, 73, 1);
    let address = rig.white[0].clone();
    rig.attempt(shekyl_tor::refused(0x06), TOR_WINDOW);
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
    rig.attempt(CloseCause::new(CloseKind::DialFailed), Duration::ZERO);
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

/// **In a quiet stretch white failures do not demote**: nothing held, the
/// last K attempts unopened and S passed, so the failures say nothing about
/// the address. Both connectors.
#[test]
fn in_a_quiet_stretch_white_failures_do_not_demote() {
    for (connector, seed) in [(TOR, 75), (CLEARNET, 76)] {
        let mut rig = WhiteRig::new(connector, seed, 1);
        let address = rig.white[0].clone();
        rig.prime_quiet();
        rig.fail_one_test();
        assert!(
            rig.is_white(&address) && !rig.is_cooling(&address),
            "{connector:?}: white survives the quiet stretch"
        );
    }
}

/// **With one session held, white failures demote**, though S has passed:
/// the held session says the link works. Both connectors.
#[test]
fn with_one_session_held_white_failures_demote() {
    for (connector, seed) in [(TOR, 77), (CLEARNET, 78)] {
        let mut rig = WhiteRig::new(connector, seed, 2);
        rig.dial
            .answers
            .lock()
            .expect("answers")
            .push_back(reply(NETWORK));
        assert!(rig.dialer.wake(connector, &mut rig.rng), "a keep, held");
        let held = rig.dialer.shared().kept_addresses(connector);
        assert_eq!(held.len(), 1, "one held");
        let failing = rig
            .white
            .iter()
            .find(|address| !held.contains(*address))
            .cloned()
            .expect("one not held");
        let span = shekyl_peerlist::dial_profile(connector).quiet.span_nanos;
        rig.advance(Duration::from_nanos(span));
        rig.fail_one_test();
        assert!(
            !rig.is_white(&failing) && rig.is_cooling(&failing),
            "{connector:?}: a held session lets the failure demote"
        );
    }
}

/// **A clearnet white redial is decided by the clearnet window** (the dial
/// profile brief, test 3). Clearnet's window is its dial deadline: a white
/// test whose first attempt times out at the deadline has used the whole
/// window, so it demotes with no redial; a refused connect is not a
/// timeout and waits for its redial. The connector refuses a published
/// window: its profile is protocol data.
#[test]
fn a_clearnet_white_redial_is_decided_by_the_clearnet_window() {
    let deadline = match shekyl_peerlist::dial_profile(CLEARNET).window {
        shekyl_transport_layer::WindowSource::DialDeadline(nanos) => Duration::from_nanos(nanos),
        shekyl_transport_layer::WindowSource::Published => {
            panic!("clearnet's window is its deadline")
        }
    };
    let mut rig = WhiteRig::new(CLEARNET, 79, 1);
    let address = rig.white[0].clone();
    assert_eq!(rig.dialer.window(CLEARNET), Some(deadline));
    rig.dialer
        .set_window(CLEARNET, Some(Duration::from_secs(600)));
    assert_eq!(
        rig.dialer.window(CLEARNET),
        Some(deadline),
        "a published window is refused"
    );
    rig.attempt(CloseCause::new(CloseKind::TransportTimeout), deadline);
    assert!(
        !rig.is_white(&address) && rig.is_cooling(&address),
        "a full-window timeout demotes with no redial"
    );
}

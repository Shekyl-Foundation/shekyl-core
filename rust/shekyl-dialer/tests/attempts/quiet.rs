// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet stretch (Rick, 2026-10-26). With no session held and none
//! opened for the stretch, a failed test cools at the first step, on
//! both connectors. These tests use the attempt rig.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_dialer::{Dialer, QUIET_AFTER_NANOS};
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{CloseCause, CloseKind, ConnectorId, NetworkAddress, Tick};
use shekyl_seam::{Dial, Endpoint, Hub};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::Sockets;

use super::{dialer_on, onions, peer, reply, HeldDial, CLEARNET, NETWORK, TOR, TOR_WINDOW};

/// One rig for the quiet stretch: five addresses on `connector`, each
/// failing every dial at once with a final cause (Tor's `0xF1`, an
/// unusable descriptor; a clearnet dial failure, one attempt per test), so
/// a round draws each address exactly once. With `keep_one`, the first dial
/// is answered and its session kept.
struct QuietRig {
    clock: ManualClock,
    hub: Hub,
    dial: Arc<HeldDial>,
    dialer: Arc<Dialer>,
    connector: ConnectorId,
    failing: Vec<NetworkAddress>,
    cause: CloseCause,
    took: Duration,
    rng: SplitMix64,
}

/// Past the longest cooldown, the hour and its jitter: every cooling seat
/// thaws.
const PAST_EVERY_COOLDOWN: Duration = Duration::from_secs(2 * 3600);

impl QuietRig {
    fn new(connector: ConnectorId, seed: u64, keep_one: bool) -> Self {
        let clock = ManualClock::new(Tick::new(1_000_000_000));
        let sockets = Sockets::new();
        let answers = if keep_one {
            vec![reply(NETWORK)]
        } else {
            Vec::new()
        };
        let dial = Arc::new(HeldDial::answering(sockets.clone(), answers));
        let (hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
        dialer.set_tor_window(Some(TOR_WINDOW));
        let mut rng = SplitMix64::new(seed);
        let (mut addresses, cause, took) = match connector {
            ConnectorId::Tor => (onions(5), shekyl_tor::refused(0xF1), Duration::ZERO),
            ConnectorId::Clearnet => (
                (1..=5).map(|n| peer(600 + n)).collect(),
                CloseCause::new(CloseKind::DialFailed),
                Duration::ZERO,
            ),
        };
        for address in &addresses {
            dialer
                .admit_operator(address, Tick::new(1), &mut rng)
                .expect("admitted");
        }
        if keep_one {
            assert!(dialer.wake(connector, &mut rng), "the first dial");
            let kept = addresses
                .iter()
                .position(|address| dialer.shared().lists.is_white(address))
                .expect("one session kept");
            addresses.remove(kept);
            assert_eq!(dialer.kept_sessions(connector), 1);
        }
        Self {
            clock,
            hub,
            dial,
            dialer,
            connector,
            failing: addresses,
            cause,
            took,
            rng,
        }
    }

    fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).expect("a short span");
        self.clock.set(Tick::new(self.clock.now().get() + by));
    }

    /// One round: every failing address is drawn once and fails its test.
    fn fail_each_once(&mut self) {
        for _ in 0..self.failing.len() {
            self.dial.refuse_after(&self.clock, self.cause, self.took);
            assert!(self.dialer.wake(self.connector, &mut self.rng), "a draw");
        }
        for address in &self.failing {
            assert!(
                self.dialer.shared().lists.is_cooling(address),
                "{address:?} failed and cools"
            );
        }
    }

    fn failed_tests(&self) -> Vec<u32> {
        self.failing
            .iter()
            .map(|address| self.dialer.shared().lists.failed_tests(address))
            .collect()
    }

    fn cooling(&self) -> usize {
        self.failing
            .iter()
            .filter(|address| self.dialer.shared().lists.is_cooling(address))
            .count()
    }
}

const QUIET_AFTER: Duration = Duration::from_nanos(QUIET_AFTER_NANOS);

/// **A block with no sessions keeps every cooled address at the first
/// step** (the quiet stretch, Rick 2026-10-26, test 1), on both
/// connectors. Nothing is held and nothing opens for the quiet stretch;
/// four rounds of failures leave every address at one failed test.
#[test]
fn a_block_with_no_sessions_keeps_every_cooled_address_at_the_first_step() {
    for (connector, seed) in [(TOR, 51), (CLEARNET, 52)] {
        let mut rig = QuietRig::new(connector, seed, false);
        rig.advance(QUIET_AFTER);
        for _ in 0..4 {
            rig.fail_each_once();
            rig.advance(PAST_EVERY_COOLDOWN);
        }
        assert_eq!(rig.failed_tests(), vec![1; 5], "{connector:?}: no climb");
    }
}

/// **With one session held, failures climb as today** (test 2), on both
/// connectors; and without one, a failure inside the quiet stretch climbs
/// too: outside the condition the ladder steps as it always does.
#[test]
fn with_one_session_held_failures_climb_as_today() {
    for (connector, seed) in [(TOR, 53), (CLEARNET, 54)] {
        let mut rig = QuietRig::new(connector, seed, true);
        rig.advance(QUIET_AFTER);
        for _ in 0..4 {
            rig.fail_each_once();
            rig.advance(PAST_EVERY_COOLDOWN);
        }
        assert_eq!(
            rig.failed_tests(),
            vec![4; 4],
            "{connector:?}: a held session climbs"
        );
    }
    // Nothing held, but inside the quiet stretch: two clearnet failures
    // three minutes apart climb.
    let mut rig = QuietRig::new(CLEARNET, 55, false);
    rig.fail_each_once();
    rig.advance(Duration::from_secs(181));
    rig.fail_each_once();
    assert_eq!(
        rig.failed_tests(),
        vec![2; 5],
        "inside the stretch: a climb"
    );
}

/// **After the block, a cooled address is drawable within one first-step
/// cooldown** (test 3): the first step is 2 min with up to half again of
/// jitter, so three minutes after the last failure of a long block every
/// address has thawed: a wake draws one, and only that one cools again.
#[test]
fn after_the_block_a_cooled_address_is_drawable_within_one_first_step_cooldown() {
    for (connector, seed) in [(TOR, 56), (CLEARNET, 57)] {
        let first_step = shekyl_peerlist::dial_profile(connector)
            .cooldown
            .first_nanos;
        let first_step_and_jitter = Duration::from_nanos(first_step + first_step / 2);
        let mut rig = QuietRig::new(connector, seed, false);
        rig.advance(QUIET_AFTER);
        for _ in 0..4 {
            rig.fail_each_once();
            rig.advance(PAST_EVERY_COOLDOWN);
        }
        rig.fail_each_once();
        rig.advance(first_step_and_jitter + Duration::from_secs(1));
        // The wake thaws what is due and draws one address, which fails
        // and cools again: every other one is drawable.
        rig.dial.refuse_after(&rig.clock, rig.cause, rig.took);
        assert!(
            rig.dialer.wake(rig.connector, &mut rig.rng),
            "{connector:?}: an address is drawable"
        );
        assert_eq!(
            rig.cooling(),
            1,
            "{connector:?}: only the one just drawn cools"
        );
    }
}

/// **An inbound session alone keeps the ladder climbing** (Copilot's review
/// of #1203). The held count is the connector's, outbound or inbound: an
/// accepted session on the board, with nothing kept outbound, is a session
/// held, so failures climb as today. Both connectors.
#[test]
fn an_inbound_session_alone_keeps_the_ladder_climbing() {
    for (connector, seed) in [(TOR, 62), (CLEARNET, 63)] {
        let mut rig = QuietRig::new(connector, seed, false);
        let inbound = match connector {
            ConnectorId::Tor => Endpoint::TorInbound,
            ConnectorId::Clearnet => Endpoint::Clearnet {
                ip: Ipv4Addr::new(11, 17, 9, 9).into(),
                port: 40_000,
                direction: shekyl_peerlist::Direction::Inbound,
            },
        };
        let _attached = rig.hub.connect(&inbound).expect("accepted");
        assert_eq!(
            rig.hub
                .board()
                .count(connector, shekyl_peerlist::Direction::Inbound),
            1
        );
        assert_eq!(rig.dialer.kept_sessions(connector), 0, "nothing outbound");
        rig.advance(QUIET_AFTER);
        for _ in 0..4 {
            rig.fail_each_once();
            rig.advance(PAST_EVERY_COOLDOWN);
        }
        assert_eq!(
            rig.failed_tests(),
            vec![4; 5],
            "{connector:?}: an inbound session climbs"
        );
    }
}

/// **A stream that opens restarts the stretch, kept or not** (Copilot's
/// review of #1203). Deep in a quiet stretch, one dial reaches its peer and
/// is rejected at the handshake: a stream opened, nothing is kept. For the
/// next quiet stretch failures climb; once it has passed with nothing
/// opened, they stop climbing again. Both connectors.
#[test]
fn a_stream_that_opens_restarts_the_stretch_kept_or_not() {
    for (connector, seed) in [(TOR, 64), (CLEARNET, 65)] {
        let mut rig = QuietRig::new(connector, seed, false);
        rig.advance(QUIET_AFTER + PAST_EVERY_COOLDOWN);
        // One draw reaches its peer and is rejected: opened, not kept.
        rig.dial.refuse_after(
            &rig.clock,
            CloseCause::new(CloseKind::LevinHandshakeRejected),
            Duration::ZERO,
        );
        assert!(rig.dialer.wake(rig.connector, &mut rig.rng), "a draw");
        assert_eq!(rig.dialer.kept_sessions(connector), 0, "nothing kept");
        let opened: Vec<NetworkAddress> = rig
            .failing
            .iter()
            .filter(|address| rig.dialer.shared().lists.failed_tests(address) == 1)
            .cloned()
            .collect();
        assert_eq!(opened.len(), 1, "{connector:?}: one draw was rejected");
        // Three minutes on, inside the new stretch: every address fails and
        // the ladder climbs, so the rejected one steps to two.
        rig.advance(Duration::from_secs(181));
        rig.fail_each_once();
        for address in &rig.failing {
            let expected = if opened.contains(address) { 2 } else { 1 };
            assert_eq!(
                rig.dialer.shared().lists.failed_tests(address),
                expected,
                "{connector:?}: inside the restarted stretch the ladder climbs"
            );
        }
        // Past the stretch with nothing opened: no further climb.
        rig.advance(PAST_EVERY_COOLDOWN);
        let before = rig.failed_tests();
        rig.fail_each_once();
        assert_eq!(rig.failed_tests(), before, "{connector:?}: quiet again");
    }
}

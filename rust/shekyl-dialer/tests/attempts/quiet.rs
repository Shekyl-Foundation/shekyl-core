// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet stretch (Rick, 2026-10-26), counted as evidence (the dial
//! profile, 2026-10-27): with no session held, the connector's last K
//! attempts unopened, and S passed since one opened, a failed test cools at
//! the first step, on both connectors. These tests use the attempt rig.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_dialer::Dialer;
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
        Self::sized(connector, seed, 5, keep_one)
    }

    /// A rig of `count` addresses.
    fn sized(connector: ConnectorId, seed: u64, count: usize, keep_one: bool) -> Self {
        let clock = ManualClock::new(Tick::new(1_000_000_000));
        let sockets = Sockets::new();
        let answers = if keep_one {
            vec![reply(NETWORK)]
        } else {
            Vec::new()
        };
        let dial = Arc::new(HeldDial::answering(sockets.clone(), answers));
        let (hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
        dialer.set_window(TOR, Some(TOR_WINDOW));
        let mut rng = SplitMix64::new(seed);
        let (mut addresses, cause, took) = match connector {
            ConnectorId::Tor => (onions(count), shekyl_tor::refused(0xF1), Duration::ZERO),
            ConnectorId::Clearnet => (
                (1..=count)
                    .map(|n| peer(600 + u16::try_from(n).expect("small")))
                    .collect(),
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

    /// The connector's quiet threshold: K attempts and the span S.
    fn threshold(&self) -> (u32, Duration) {
        let quiet = shekyl_peerlist::dial_profile(self.connector).quiet;
        (quiet.attempts, Duration::from_nanos(quiet.span_nanos))
    }

    /// Rounds of failures, each followed by the longest cooldown, until the
    /// guard's evidence is in: at least K unopened attempts, and S passed.
    /// Returns the counts as the guard switches on.
    fn go_quiet(&mut self) -> Vec<u32> {
        let (attempts, _) = self.threshold();
        let rounds = usize::try_from(attempts)
            .expect("small")
            .div_ceil(self.failing.len());
        for _ in 0..rounds {
            self.fail_each_once();
            self.advance(PAST_EVERY_COOLDOWN);
        }
        self.failed_tests()
    }

    /// One failing attempt, and how far the counts moved: 1 on a climb, 0 on
    /// the first step. Every address here has failed before (a count of at
    /// least one), so the first step leaves the count where it was.
    fn fail_one(&mut self) -> u32 {
        let before: u32 = self.failed_tests().iter().sum();
        assert!(
            self.failed_tests().iter().all(|count| *count >= 1),
            "every address has failed before"
        );
        self.dial.refuse_after(&self.clock, self.cause, self.took);
        assert!(self.dialer.wake(self.connector, &mut self.rng), "a draw");
        self.failed_tests().iter().sum::<u32>() - before
    }

    /// One dial reaches its peer and is rejected at the handshake: a stream
    /// opened, nothing is kept. The guard's evidence starts again.
    fn open_one(&mut self) {
        self.dial.refuse_after(
            &self.clock,
            CloseCause::new(CloseKind::LevinHandshakeRejected),
            Duration::ZERO,
        );
        assert!(self.dialer.wake(self.connector, &mut self.rng), "a draw");
        assert_eq!(self.dialer.kept_sessions(self.connector), 0, "nothing kept");
    }

    fn cooling(&self) -> usize {
        self.failing
            .iter()
            .filter(|address| self.dialer.shared().lists.is_cooling(address))
            .count()
    }
}

/// **A block with no sessions keeps every cooled address at the first
/// step** (the quiet stretch, Rick 2026-10-26, test 1), on both
/// connectors. Once nothing is held and the evidence is in (K unopened
/// attempts across S), four more rounds of failures climb no address.
#[test]
fn a_block_with_no_sessions_keeps_every_cooled_address_at_the_first_step() {
    for (connector, seed) in [(TOR, 51), (CLEARNET, 52)] {
        let mut rig = QuietRig::new(connector, seed, false);
        let quiet = rig.go_quiet();
        for _ in 0..4 {
            rig.fail_each_once();
            rig.advance(PAST_EVERY_COOLDOWN);
        }
        assert_eq!(rig.failed_tests(), quiet, "{connector:?}: no climb");
    }
}

/// **With one session held, failures climb as today** (test 2), on both
/// connectors, though K attempts fail across S; and without one, fewer than
/// K failures climb too: outside the condition the ladder steps as it
/// always does.
#[test]
fn with_one_session_held_failures_climb_as_today() {
    for (connector, seed) in [(TOR, 53), (CLEARNET, 54)] {
        let mut rig = QuietRig::new(connector, seed, true);
        let (_, span) = rig.threshold();
        rig.advance(span);
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
    // Nothing held, S passed, but fewer than K failures: eight clearnet
    // failures, four addresses twice, three minutes apart, all climb.
    let mut rig = QuietRig::sized(CLEARNET, 55, 4, false);
    rig.fail_each_once();
    rig.advance(Duration::from_secs(181));
    rig.fail_each_once();
    assert_eq!(
        rig.failed_tests(),
        vec![2; 4],
        "fewer than K failures: a climb"
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
        rig.go_quiet();
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
        let (_, span) = rig.threshold();
        rig.advance(span);
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

/// **A stream that opens restarts the evidence, kept or not** (Copilot's
/// review of #1203). Deep in a quiet stretch, one dial reaches its peer and
/// is rejected at the handshake: a stream opened, nothing is kept. Every
/// failure after it climbs until the evidence is in again; then the climb
/// stops. Both connectors.
#[test]
fn a_stream_that_opens_restarts_the_stretch_kept_or_not() {
    for (connector, seed) in [(TOR, 64), (CLEARNET, 65)] {
        let mut rig = QuietRig::new(connector, seed, false);
        rig.go_quiet();
        let before_open = rig.failed_tests();
        rig.open_one();
        let opened: Vec<NetworkAddress> = rig
            .failing
            .iter()
            .zip(&before_open)
            .filter(|(address, before)| {
                rig.dialer.shared().lists.failed_tests(address) == *before + 1
            })
            .map(|(address, _)| address.clone())
            .collect();
        assert_eq!(opened.len(), 1, "{connector:?}: the rejected draw climbed");
        // Past every cooldown, the evidence restarted: every address fails
        // and climbs, fewer than K failures since the open.
        rig.advance(PAST_EVERY_COOLDOWN);
        let before = rig.failed_tests();
        rig.fail_each_once();
        let climbed: Vec<u32> = before.iter().map(|count| count + 1).collect();
        assert_eq!(
            rig.failed_tests(),
            climbed,
            "{connector:?}: after an open the ladder climbs"
        );
        // The evidence in again: no further climb.
        rig.advance(PAST_EVERY_COOLDOWN);
        let quiet = rig.go_quiet();
        rig.fail_each_once();
        assert_eq!(rig.failed_tests(), quiet, "{connector:?}: quiet again");
    }
}

/// **The guard counts evidence** (the dial profile brief, test 4), on each
/// connector, with K + 1 addresses each failed once and the evidence
/// started again by an opened stream:
/// K failures inside S climb; with S passed, K − 1 failures climb and the
/// K-th takes the first step; one opened stream in between, and the next
/// failure climbs.
#[test]
fn the_guard_needs_k_unopened_attempts_across_s() {
    for (connector, seed) in [(TOR, 67), (CLEARNET, 68)] {
        let attempts = shekyl_peerlist::dial_profile(connector).quiet.attempts;
        let k = usize::try_from(attempts).expect("small");
        let mut rig = QuietRig::sized(connector, seed, k + 1, false);
        rig.fail_each_once();
        rig.advance(PAST_EVERY_COOLDOWN);
        // K failures inside S: the evidence count is in, the span is not.
        rig.open_one();
        for n in 1..=k {
            let moved = rig.fail_one();
            assert_eq!(moved, 1, "{connector:?}: failure {n} of K inside S climbs");
        }
        // S passed, the evidence started again: K - 1 failures climb, the
        // K-th takes the first step.
        rig.advance(PAST_EVERY_COOLDOWN);
        rig.open_one();
        rig.advance(PAST_EVERY_COOLDOWN);
        for n in 1..k {
            let moved = rig.fail_one();
            assert_eq!(moved, 1, "{connector:?}: failure {n} of K - 1 climbs");
        }
        let moved = rig.fail_one();
        assert_eq!(
            moved, 0,
            "{connector:?}: the K-th failure takes the first step"
        );
        // One opened stream in between: the count starts again, so the
        // next failure climbs even once S has passed.
        rig.advance(PAST_EVERY_COOLDOWN);
        rig.open_one();
        rig.advance(PAST_EVERY_COOLDOWN);
        let moved = rig.fail_one();
        assert_eq!(
            moved, 1,
            "{connector:?}: after an open the next failure climbs"
        );
    }
}

/// **One session held, the evidence in: the failure climbs** (test 4).
#[test]
fn with_a_session_held_the_evidence_does_not_hold_the_ladder() {
    for (connector, seed) in [(TOR, 69), (CLEARNET, 70)] {
        let attempts = shekyl_peerlist::dial_profile(connector).quiet.attempts;
        let k = usize::try_from(attempts).expect("small");
        let mut rig = QuietRig::sized(connector, seed, k + 1, true);
        rig.fail_each_once();
        rig.advance(PAST_EVERY_COOLDOWN);
        let moved = rig.fail_one();
        assert_eq!(moved, 1, "{connector:?}: a held session climbs");
    }
}

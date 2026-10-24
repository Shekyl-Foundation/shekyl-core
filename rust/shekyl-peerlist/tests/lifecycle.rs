// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The gray lifecycle (Rick, 2026-10-24): an address leaves gray only on
//! authenticated proof of misbehaviour, never for a connection problem,
//! and every restart is a fresh look.
//!
//! Item 1, white expiry follows the connection: a kept session is contact,
//! so expiry skips an address with a live one and counts from the close.
//! Item 4, the cooldown in place of the drop: a failed test that proves no
//! misbehaviour cools the address, doubling per consecutive failure and
//! capped at an hour, and a restart retests every cooled address. Each
//! test here is red at the base this PR was cut from.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    BanQuery, CloseCause, CloseKind, ConnectorId, DialOutcome, NetworkAddress, Peerlist,
    RefusedSet, Source, Tick, COOLDOWN_CAP_NANOS, COOLDOWN_FIRST_NANOS, EXPIRATION_PERIOD_NANOS,
};

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const HOUR: u64 = 60 * 60 * 1_000_000_000;
const MINUTE: u64 = 60 * 1_000_000_000;

fn v4(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 0, 1, n),
        port: 18080,
    }
}

fn at(nanos: u64) -> Tick {
    Tick::new(nanos)
}

fn at_hours(h: u64) -> Tick {
    at(h * HOUR)
}

/// No bans, and the given addresses as live kept sessions: what the dialer
/// answers from the seam's board.
struct Live(BTreeSet<NetworkAddress>);

impl BanQuery for Live {
    fn is_banned(&mut self, _host: IpAddr, _now: Tick) -> bool {
        false
    }

    fn has_live_session(&mut self, address: &NetworkAddress) -> bool {
        self.0.contains(address)
    }
}

fn nobody() -> Live {
    Live(BTreeSet::new())
}

fn live(address: &NetworkAddress) -> Live {
    Live(BTreeSet::from([address.clone()]))
}

/// Draw from gray until `address` is the outstanding draw, as the dialer
/// would when the uniform draw lands on it.
fn draw_until(list: &mut Peerlist, address: &NetworkAddress, now: Tick, rng: &mut SplitMix64) {
    for _ in 0..10_000 {
        match list.draw_gray(CLEARNET, rng) {
            Some(drawn) if drawn == *address => return,
            Some(other) => list.apply(&DialOutcome::PayloadRefused(other), now, rng),
            None => panic!("gray ran out before {address:?} was drawn"),
        }
    }
    panic!("{address:?} was never drawn");
}

/// Admit `address`, draw it, and keep it at `now`: a white address whose
/// clock reads `now`.
fn kept_at(list: &mut Peerlist, address: &NetworkAddress, now: Tick, rng: &mut SplitMix64) {
    assert_eq!(
        list.admit_gray(address, Source::Operator, now, &mut nobody(), rng),
        Ok(true)
    );
    draw_until(list, address, now, rng);
    list.apply(&DialOutcome::SessionAccepted(address.clone()), now, rng);
    assert!(list.is_white(address));
}

/// A connection problem on clearnet: a cause that proves nothing.
fn connection_problem(address: &NetworkAddress) -> DialOutcome {
    DialOutcome::DialFailed(
        address.clone(),
        CloseCause::new(CloseKind::TransportTimeout),
    )
}

/// Settle the list at `now` with `query` and say whether `address` is white.
fn white_after_settle(
    list: &mut Peerlist,
    address: &NetworkAddress,
    now: Tick,
    query: &mut dyn BanQuery,
    rng: &mut SplitMix64,
) -> bool {
    list.white_count(CLEARNET, now, query, rng);
    list.is_white(address)
}

#[test]
fn a_session_held_for_thirty_hours_stays_white() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let peer = v4(1);
    kept_at(&mut list, &peer, at_hours(0), &mut rng);
    // Thirty hours in, the session is still up: the address is contact,
    // not a stale entry, whatever its clock reads.
    assert!(white_after_settle(
        &mut list,
        &peer,
        at_hours(30),
        &mut live(&peer),
        &mut rng
    ));
    // The same clock with no live session is six hours past expiry.
    assert!(!white_after_settle(
        &mut list,
        &peer,
        at_hours(30),
        &mut nobody(),
        &mut rng
    ));
}

#[test]
fn an_address_expires_twenty_four_hours_after_its_session_closes() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let peer = v4(2);
    kept_at(&mut list, &peer, at_hours(0), &mut rng);
    // The session ends at hour 30: the clock moves to the close.
    assert!(list.session_ended(&peer, at_hours(30)));
    assert!(white_after_settle(
        &mut list,
        &peer,
        at(30 * HOUR + EXPIRATION_PERIOD_NANOS - 1),
        &mut nobody(),
        &mut rng
    ));
    assert!(!white_after_settle(
        &mut list,
        &peer,
        at(30 * HOUR + EXPIRATION_PERIOD_NANOS),
        &mut nobody(),
        &mut rng
    ));
    assert!(list.is_gray(&peer), "expired to gray, not dropped");
}

#[test]
fn a_confirm_dial_still_holds_the_clock() {
    let mut rng = SplitMix64::new(3);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let peer = v4(3);
    kept_at(&mut list, &peer, at_hours(0), &mut rng);
    assert!(list.session_ended(&peer, at_hours(1)));
    // A confirm-and-close at hour 20 does not extend the lifetime (brief
    // §5); the clock still reads the close at hour 1.
    list.apply(
        &DialOutcome::Confirmed(peer.clone()),
        at_hours(20),
        &mut rng,
    );
    assert!(!white_after_settle(
        &mut list,
        &peer,
        at(HOUR + EXPIRATION_PERIOD_NANOS),
        &mut nobody(),
        &mut rng
    ));
    // The clock of an address that is not white does not move.
    assert!(!list.session_ended(&peer, at_hours(40)));
}

/// 2, 4, 8, 16, 32 and 60 minutes, each stretched by up to half again, and
/// the address is never dropped: a connection problem is never proof.
#[test]
fn a_clearnet_address_failing_every_test_cools_on_the_ladder_and_is_never_dropped() {
    let mut rng = SplitMix64::new(4);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let peer = v4(4);
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at(0), &mut nobody(), &mut rng),
        Ok(true)
    );
    assert_eq!(COOLDOWN_FIRST_NANOS, 2 * MINUTE);
    assert_eq!(COOLDOWN_CAP_NANOS, 60 * MINUTE);
    let rungs = [2u64, 4, 8, 16, 32, 60, 60, 60];
    let mut now = 0u64;
    for (failures, minutes) in (1u32..).zip(rungs) {
        // The test fails at `now`.
        draw_until(&mut list, &peer, at(now), &mut rng);
        list.apply(&connection_problem(&peer), at(now), &mut rng);
        assert!(list.is_gray(&peer), "failure {failures}: still gray");
        assert!(list.is_cooling(&peer), "failure {failures}: cooling");
        assert_eq!(list.failed_tests(&peer), failures);
        let base = minutes * MINUTE;
        // Not drawable at the rung's base, drawable past its jitter.
        list.white_count(CLEARNET, at(now + base - 1), &mut nobody(), &mut rng);
        assert!(
            list.is_cooling(&peer),
            "failure {failures}: still cooling just before {minutes} min"
        );
        assert!(list.draw_gray(CLEARNET, &mut rng).is_none());
        now += base + base / 2 + 1;
        list.white_count(CLEARNET, at(now), &mut nobody(), &mut rng);
        assert!(
            !list.is_cooling(&peer),
            "failure {failures}: thawed after {minutes} min and the jitter"
        );
    }
    assert!(list.is_gray(&peer), "eight failed tests, never dropped");
    // A completed handshake clears the ladder.
    draw_until(&mut list, &peer, at(now), &mut rng);
    list.apply(&DialOutcome::Confirmed(peer.clone()), at(now), &mut rng);
    assert_eq!(list.failed_tests(&peer), 0);
}

#[test]
fn a_restart_retests_every_cooled_address() {
    let mut rng = SplitMix64::new(5);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let cooled = v4(5);
    let fresh = v4(6);
    for peer in [&cooled, &fresh] {
        assert_eq!(
            list.admit_gray(peer, Source::Operator, at(0), &mut nobody(), &mut rng),
            Ok(true)
        );
    }
    for _ in 0..3 {
        draw_until(&mut list, &cooled, at(0), &mut rng);
        list.apply(&connection_problem(&cooled), at(0), &mut rng);
        list.white_count(CLEARNET, at(2 * HOUR), &mut nobody(), &mut rng);
    }
    draw_until(&mut list, &cooled, at(2 * HOUR), &mut rng);
    list.apply(&connection_problem(&cooled), at(2 * HOUR), &mut rng);
    assert!(list.is_cooling(&cooled));
    assert_eq!(list.failed_tests(&cooled), 4);

    // The file carries the address and nothing about its cooldown.
    let bytes = list.to_file_bytes();
    let mut restarted = Peerlist::new(RefusedSet::NON_GLOBAL);
    let admitted = restarted
        .restore_file(&bytes, &mut rng)
        .expect("the file reads");
    assert_eq!(admitted, 2);
    assert!(restarted.is_gray(&cooled));
    assert!(!restarted.is_cooling(&cooled), "a fresh look: no cooldown");
    assert_eq!(restarted.failed_tests(&cooled), 0, "no ladder either");
    // Both are drawable at once.
    let mut drawn = BTreeSet::new();
    for _ in 0..2 {
        drawn.insert(restarted.draw_gray(CLEARNET, &mut rng).expect("drawable"));
    }
    assert_eq!(drawn, BTreeSet::from([cooled, fresh]));
}

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
use shekyl_peerlist::address_file::decode;
use shekyl_peerlist::{
    BanQuery, CloseCause, CloseKind, ConnectorId, DialOutcome, NetworkAddress, Peerlist,
    RefusedSet, Source, Tick, COOLDOWN_CAP_NANOS, COOLDOWN_FIRST_NANOS, EXPIRATION_PERIOD_NANOS,
    GRAY_CAP,
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

/// The `n`th of many distinct global addresses, for filling gray to its cap.
fn v4_many(n: usize) -> NetworkAddress {
    let [_, b, c, d] = u32::try_from(n).expect("fits").to_be_bytes();
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(12, b, c, d),
        port: 18080,
    }
}

fn onion(n: u8) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
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
    let bytes = list.to_file_bytes(&mut nobody(), at(2 * HOUR));
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

/// A ban on the given hosts until `until`, as the transport layer's list
/// would answer; nothing is live.
struct BannedUntil(BTreeSet<IpAddr>, Tick);

impl BanQuery for BannedUntil {
    fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool {
        self.0.contains(&host) && now.get() < self.1.get()
    }
}

/// Admit `count` addresses to gray and fail a test of each, so every one
/// is cooling at `now`.
fn fill_cooling(
    list: &mut Peerlist,
    count: usize,
    now: Tick,
    rng: &mut SplitMix64,
) -> Vec<NetworkAddress> {
    let addresses: Vec<NetworkAddress> = (0..count).map(v4_many).collect();
    for address in &addresses {
        assert_eq!(
            list.admit_gray(address, Source::Operator, now, &mut nobody(), rng),
            Ok(true)
        );
    }
    for _ in 0..count {
        let drawn = list.draw_gray(CLEARNET, rng).expect("a drawable seat");
        list.apply(&connection_problem(&drawn), now, rng);
    }
    for address in &addresses {
        assert!(list.is_cooling(address));
    }
    addresses
}

/// **Cooling seats are evictable (Rick, 2026-10-24).** Gray full of cooling
/// seats takes a hundred more admissions and stays at the cap: a cooldown
/// is a delay, not protection. Dead addresses fed within D-S1 would
/// otherwise accumulate immune to eviction and push the honest ones out.
#[test]
fn gray_full_of_cooling_seats_stays_at_the_cap_under_more_admissions() {
    let mut rng = SplitMix64::new(6);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let cooling = fill_cooling(&mut list, GRAY_CAP, at(0), &mut rng);
    assert_eq!(list.gray_count(CLEARNET), GRAY_CAP);
    for n in 0..100 {
        let fresh = v4_many(GRAY_CAP + n);
        assert_eq!(
            list.admit_gray(&fresh, Source::Operator, at(0), &mut nobody(), &mut rng),
            Ok(true)
        );
        assert!(list.is_gray(&fresh), "the address just admitted stays");
    }
    assert_eq!(list.gray_count(CLEARNET), GRAY_CAP, "bounded by the cap");
    let still = cooling.iter().filter(|a| list.is_cooling(a)).count();
    assert!(still < GRAY_CAP, "some cooling seats were evicted");
    assert!(still >= GRAY_CAP - 100);
}

/// Half the seats cooling and half drawable: evictions hit both in
/// proportion. Each admission over the cap evicts one uniform seat among
/// every evictable one, so after a thousand admissions each half has lost
/// about the same number, within a statistical bound.
#[test]
fn evictions_hit_cooling_and_drawable_seats_in_proportion() {
    let mut rng = SplitMix64::new(7);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let half = GRAY_CAP / 2;
    let cooling = fill_cooling(&mut list, half, at(0), &mut rng);
    let drawable: Vec<NetworkAddress> = (half..GRAY_CAP).map(v4_many).collect();
    for address in &drawable {
        assert_eq!(
            list.admit_gray(address, Source::Operator, at(0), &mut nobody(), &mut rng),
            Ok(true)
        );
    }
    assert_eq!(list.gray_count(CLEARNET), GRAY_CAP);
    let admitted = 1000;
    for n in 0..admitted {
        let fresh = v4_many(GRAY_CAP + n);
        assert_eq!(
            list.admit_gray(&fresh, Source::Operator, at(0), &mut nobody(), &mut rng),
            Ok(true)
        );
    }
    assert_eq!(list.gray_count(CLEARNET), GRAY_CAP);
    let cooling_lost = cooling.iter().filter(|a| !list.is_gray(a)).count();
    let drawable_lost = drawable.iter().filter(|a| !list.is_gray(a)).count();
    // Each half expects about half the evictions that fall on the original
    // seats (a little under 500 each, the fresh seats taking the rest).
    // The bound is loose: a difference of 150 is over six standard
    // deviations for a thousand uniform picks.
    assert!(cooling_lost >= 300, "cooling lost {cooling_lost}");
    assert!(drawable_lost >= 300, "drawable lost {drawable_lost}");
    assert!(
        cooling_lost.abs_diff(drawable_lost) < 150,
        "cooling lost {cooling_lost}, drawable lost {drawable_lost}"
    );
}

/// **Banned addresses are not written to the file (Rick ruled (ii),
/// 2026-10-24).** A clearnet address under an active ban at the moment of
/// the write is left out; the ban itself is never in the file; the list
/// still holds the address. The file carries addresses, never judgements.
#[test]
fn a_clearnet_address_under_an_active_ban_is_absent_from_the_file() {
    let mut rng = SplitMix64::new(8);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let banned = v4(7);
    let free = v4(8);
    for peer in [&banned, &free] {
        assert_eq!(
            list.admit_gray(peer, Source::Operator, at(0), &mut nobody(), &mut rng),
            Ok(true)
        );
    }
    let mut bans = BannedUntil(
        BTreeSet::from([IpAddr::V4(Ipv4Addr::new(11, 0, 1, 7))]),
        at(100),
    );
    let written = decode(&list.to_file_bytes(&mut bans, at(50))).expect("the file reads");
    assert_eq!(written, vec![free], "the banned address is left out");
    assert!(list.is_gray(&banned), "the list still holds it");
}

#[test]
fn a_clearnet_address_whose_ban_has_expired_is_written() {
    let mut rng = SplitMix64::new(9);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let peer = v4(9);
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at(0), &mut nobody(), &mut rng),
        Ok(true)
    );
    let mut bans = BannedUntil(
        BTreeSet::from([IpAddr::V4(Ipv4Addr::new(11, 0, 1, 9))]),
        at(100),
    );
    assert_eq!(
        decode(&list.to_file_bytes(&mut bans, at(99))).expect("reads"),
        vec![]
    );
    assert_eq!(
        decode(&list.to_file_bytes(&mut bans, at(100))).expect("reads"),
        vec![peer]
    );
}

/// Nothing on Tor can be banned (D7: only an address with an IP), so a
/// query that bans every host leaves every onion in the file.
#[test]
fn a_tor_address_is_unaffected_by_bans_in_the_file() {
    struct EveryHost;
    impl BanQuery for EveryHost {
        fn is_banned(&mut self, _host: IpAddr, _now: Tick) -> bool {
            true
        }
    }
    let mut rng = SplitMix64::new(10);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let tor = onion(1);
    assert_eq!(
        list.admit_gray(&tor, Source::Operator, at(0), &mut nobody(), &mut rng),
        Ok(true)
    );
    assert_eq!(
        list.admit_gray(&v4(10), Source::Operator, at(0), &mut nobody(), &mut rng),
        Ok(true)
    );
    let written = decode(&list.to_file_bytes(&mut EveryHost, at(0))).expect("reads");
    assert_eq!(written, vec![tor]);
}

/// A cooldown that has ended frees the seat for a targeted draw too, with
/// no settle in between: a direct dial past the cooldown draws the address
/// (the dialer's `dial` draws through `draw_gray_where`).
#[test]
fn a_targeted_draw_past_the_cooldown_draws_the_address() {
    let mut rng = SplitMix64::new(11);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let peer = v4(11);
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at(0), &mut nobody(), &mut rng),
        Ok(true)
    );
    draw_until(&mut list, &peer, at(0), &mut rng);
    list.apply(&connection_problem(&peer), at(0), &mut rng);
    assert!(list.is_cooling(&peer));
    let target = peer.clone();
    assert_eq!(
        list.draw_gray_where(CLEARNET, at(MINUTE), &mut |a| *a == target, &mut rng),
        None,
        "inside the cooldown"
    );
    assert_eq!(
        list.draw_gray_where(CLEARNET, at(2 * HOUR), &mut |a| *a == target, &mut rng),
        Some(peer),
        "past it, with no settle between"
    );
}

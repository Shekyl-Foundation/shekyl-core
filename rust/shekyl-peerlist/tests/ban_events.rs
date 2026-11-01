// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bans as events (Rick, 2026-10-31; #1235): the ban list posts each ban
//! and each lift, and the peer list holds the active entries it was given,
//! with no expiries. A seat any entry covers is barred on both lists: never
//! drawn, in no count, refused at the door. A lift returns it as drawable
//! gray on its rung, unless another entry still covers it.

use std::net::Ipv4Addr;

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    BanEntry, CloseCause, CloseKind, ConnectorId, DialOutcome, Ipv4Subnet, Ladder, NetworkAddress,
    NoBans, NoSessions, Peerlist, Refusal, RefusedSet, Source, Tick,
};

const CLEARNET: ConnectorId = ConnectorId::Clearnet;

fn v4(c: u8, d: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 0, c, d),
        port: 18080,
    }
}

fn host(address: &NetworkAddress) -> BanEntry {
    BanEntry::Host(address.ip().expect("an IP address"))
}

fn subnet(c: u8) -> BanEntry {
    BanEntry::Subnet(Ipv4Subnet::new(Ipv4Addr::new(11, 0, c, 0), 24).expect("a /24"))
}

fn now() -> Tick {
    Tick::new(0)
}

fn admitted(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    assert_eq!(
        list.admit_gray(address, Source::Operator, now(), &mut NoBans, rng),
        Ok(true)
    );
}

/// Draw from gray until `address` is the outstanding draw, releasing every
/// other draw on its rung.
fn draw_until(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    for _ in 0..10_000 {
        match list.draw_gray(CLEARNET, rng) {
            Some(drawn) if drawn == *address => return,
            Some(other) => list.release_draw(&other),
            None => panic!("gray ran out before {address:?} was drawn"),
        }
    }
    panic!("{address:?} was never drawn");
}

/// Every address the gray draw returns, until it returns none. Each is
/// released afterwards, so the lists are as they were.
fn every_gray_draw(list: &mut Peerlist, rng: &mut SplitMix64) -> Vec<NetworkAddress> {
    let mut drawn = Vec::new();
    while let Some(address) = list.draw_gray(CLEARNET, rng) {
        drawn.push(address);
    }
    for address in &drawn {
        list.release_draw(address);
    }
    drawn
}

/// The census as the fill reads it, every address eligible.
fn census(list: &mut Peerlist, rng: &mut SplitMix64) -> shekyl_peerlist::SeatCensus {
    list.settle(CLEARNET, now(), &mut NoBans, &mut NoSessions, rng)
        .census(&mut |_| true)
}

/// Fail `address`'s test once, so it cools on rung one.
fn failed_once(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    draw_until(list, address, rng);
    list.apply(
        &DialOutcome::DialFailed(address.clone(), CloseCause::new(CloseKind::DialFailed)),
        now(),
        Ladder::Climb,
        rng,
    );
    assert_eq!(list.failed_tests(address), 1);
}

/// A ban event bars a drawable seat on both lists: a white seat is demoted
/// and barred, a gray one barred; the draw never returns either, and no
/// count includes them. The edit that makes this red is leaving a barred
/// seat in the drawable phase, or in `gray_count`.
#[test]
fn a_ban_event_bars_a_seat_on_both_lists() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let gray = v4(0, 1);
    let white = v4(0, 2);
    let free = v4(0, 3);
    for address in [&gray, &white, &free] {
        admitted(&mut list, address, &mut rng);
    }
    draw_until(&mut list, &white, &mut rng);
    list.apply(
        &DialOutcome::Confirmed(white.clone()),
        now(),
        Ladder::Climb,
        &mut rng,
    );
    assert!(list.is_white(&white));

    assert_eq!(list.ban(host(&gray), &mut rng), 1);
    assert_eq!(list.ban(host(&white), &mut rng), 1);

    assert!(!list.is_white(&white), "a ban demotes a white seat");
    assert_eq!(
        list.gray_count(CLEARNET),
        1,
        "only the free seat is counted"
    );
    let counted = census(&mut list, &mut rng);
    assert_eq!(counted.white, 0);
    assert_eq!(counted.gray, 1);
    assert_eq!(counted.gray_candidates, 1);
    assert_eq!(counted.white_candidates, 0);
    for _ in 0..64 {
        assert_eq!(every_gray_draw(&mut list, &mut rng), vec![free.clone()]);
    }
}

/// The lift returns a barred seat as drawable gray on its rung: a seat
/// that cooled on rung one comes back drawable at once, still on rung one.
#[test]
fn the_lift_returns_a_barred_seat_as_drawable_gray_on_its_rung() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let address = v4(0, 1);
    admitted(&mut list, &address, &mut rng);
    failed_once(&mut list, &address, &mut rng);
    assert!(list.is_cooling(&address));

    list.ban(host(&address), &mut rng);
    assert!(every_gray_draw(&mut list, &mut rng).is_empty());
    assert_eq!(list.lift(host(&address)), 1);

    assert!(!list.is_cooling(&address), "the lift returns it drawable");
    assert_eq!(list.failed_tests(&address), 1, "on its rung");
    assert_eq!(every_gray_draw(&mut list, &mut rng), vec![address]);
}

/// A subnet ban bars every seat it covers and leaves the rest, and the door
/// refuses a new address inside it, from any source.
#[test]
fn a_subnet_ban_bars_every_seat_it_covers_and_the_door_refuses_inside_it() {
    let mut rng = SplitMix64::new(3);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let inside: Vec<NetworkAddress> = (1..=5).map(|d| v4(7, d)).collect();
    let outside = v4(8, 1);
    for address in inside.iter().chain([&outside]) {
        admitted(&mut list, address, &mut rng);
    }

    assert_eq!(list.ban(subnet(7), &mut rng), inside.len());

    assert_eq!(every_gray_draw(&mut list, &mut rng), vec![outside.clone()]);
    assert_eq!(list.gray_count(CLEARNET), 1);
    assert_eq!(
        list.admit_gray(&v4(7, 9), Source::Operator, now(), &mut NoBans, &mut rng),
        Err(Refusal::Banned)
    );
    assert_eq!(
        list.admit_gray(&v4(9, 9), Source::Operator, now(), &mut NoBans, &mut rng),
        Ok(true)
    );
}

/// A dial refused for a ban moves no ladder, and its seat ends barred
/// whichever arrives first, the ban event or the refusal (the dialer's
/// release of the draw). The edit that makes this red is barring only a
/// seat the event finds already settled.
#[test]
fn a_refused_dial_moves_no_ladder_and_ends_barred_in_either_order() {
    for event_first in [true, false] {
        let mut rng = SplitMix64::new(4);
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let address = v4(0, 1);
        let other = v4(0, 2);
        admitted(&mut list, &address, &mut rng);
        admitted(&mut list, &other, &mut rng);
        failed_once(&mut list, &address, &mut rng);
        list.ban(host(&address), &mut rng);
        list.lift(host(&address));
        draw_until(&mut list, &address, &mut rng);

        if event_first {
            list.ban(host(&address), &mut rng);
            list.release_draw(&address);
        } else {
            list.release_draw(&address);
            list.ban(host(&address), &mut rng);
        }

        assert_eq!(list.failed_tests(&address), 1, "the ladder did not move");
        assert_eq!(
            every_gray_draw(&mut list, &mut rng),
            vec![other.clone()],
            "barred, event first: {event_first}"
        );
        assert_eq!(list.lift(host(&address)), 1, "event first: {event_first}");
    }
}

/// A host lifted inside a banned subnet stays barred until the subnet is
/// lifted too: the peer list holds the entries, not a flag per seat.
#[test]
fn a_host_lifted_inside_a_banned_subnet_stays_barred() {
    let mut rng = SplitMix64::new(5);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let address = v4(7, 1);
    admitted(&mut list, &address, &mut rng);
    list.ban(host(&address), &mut rng);
    list.ban(subnet(7), &mut rng);

    assert_eq!(list.lift(host(&address)), 0, "the subnet still covers it");
    assert!(every_gray_draw(&mut list, &mut rng).is_empty());
    assert_eq!(list.lift(subnet(7)), 1);
    assert_eq!(every_gray_draw(&mut list, &mut rng), vec![address]);
}

/// The seed at build applies each entry as a ban event, and a host entry
/// covers an IPv6 seat while a subnet never does, as the ban list matches.
#[test]
fn the_seed_bars_as_events_do_and_a_subnet_covers_ipv4_only() {
    let mut rng = SplitMix64::new(6);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let v6 = NetworkAddress::Ipv6 {
        ip: "2001:4860::1".parse().expect("v6"),
        port: 18080,
    };
    let inside = v4(7, 1);
    admitted(&mut list, &v6, &mut rng);
    admitted(&mut list, &inside, &mut rng);

    let barred = list.seed_bans([subnet(7)], &mut rng);
    assert_eq!(barred, 1, "the subnet covers the IPv4 seat only");
    assert_eq!(every_gray_draw(&mut list, &mut rng), vec![v6.clone()]);

    list.seed_bans([host(&v6)], &mut rng);
    assert!(every_gray_draw(&mut list, &mut rng).is_empty());
}

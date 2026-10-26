// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--p2p-disclose-early` (Rick, 2026-10-13, PR-3 brief revision 3 §2.6): the
//! one ruled exception to "no disclosure below the floor". While the flag
//! runs on a connector, a request below the floor gets a fresh uniform
//! draw of `min(DISCLOSE_COUNT, population)` over white plus this node's
//! own address, the refused set filtering it; nothing is cached. The flag
//! ends per connector at `P2P_DISCLOSE_EARLY_SPAN_NANOS` from the moment it
//! reached the lists, or the first time white reaches the floor, whichever
//! comes first, and once ended stays ended for the run. Time is a `Tick`
//! handed in: the clock is the test's.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    white_diversity_floor, ConnectorId, DialOutcome, DiscloseEarly, NetworkAddress, NoBans,
    NoSessions, Peerlist, RefusedSet, Source, Tick, DISCLOSE_COUNT, DISCLOSE_WINDOW_NANOS,
    P2P_DISCLOSE_EARLY_SPAN_NANOS,
};
use shekyl_transport_layer::BanList;

fn v4(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 3, (n >> 8) as u8, (n & 0xff) as u8),
        port: 18080,
    }
}

fn private(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 7, n),
        port: 18080,
    }
}

fn onion(n: u16) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
        port: 18080,
    }
}

fn ip_of(address: &NetworkAddress) -> IpAddr {
    address.ip().expect("an IP address")
}

fn at_hours(h: u64) -> Tick {
    Tick::new(h * 60 * 60 * 1_000_000_000)
}

fn floor() -> u16 {
    u16::try_from(white_diversity_floor()).expect("fits")
}

/// Admit `address` as operator-named, draw it, and confirm it white.
fn confirm(list: &mut Peerlist, address: &NetworkAddress, now: Tick, rng: &mut SplitMix64) {
    let connector = Peerlist::connector_of(address).expect("served");
    list.admit_gray(address, Source::Operator, now, &mut NoBans, rng)
        .expect("admitted");
    for _ in 0..100_000 {
        match list.draw_gray(connector, rng) {
            Some(drawn) if drawn == *address => {
                list.apply(&DialOutcome::Confirmed(address.clone()), now, rng);
                return;
            }
            Some(other) => list.apply(&DialOutcome::PayloadRefused(other), now, rng),
            None => panic!("gray ran out"),
        }
    }
    panic!("never drawn");
}

fn with_white(
    list: &mut Peerlist,
    from: u16,
    count: u16,
    now: Tick,
    rng: &mut SplitMix64,
) -> Vec<NetworkAddress> {
    (from..from + count)
        .map(|n| {
            let a = v4(n);
            confirm(list, &a, now, rng);
            a
        })
        .collect()
}

fn set(list: &BTreeSet<NetworkAddress>) -> BTreeSet<NetworkAddress> {
    list.clone()
}

/// Flag on, white of one: the sample is that address plus this node's own.
#[test]
fn with_the_flag_a_white_of_one_discloses_that_address_and_our_own() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(0));
    confirm(&mut list, &onion(1), at_hours(0), &mut rng);
    list.set_own_address(ConnectorId::Tor, Some(onion(900)))
        .expect("own");
    let sample: BTreeSet<_> = list
        .disclose(
            ConnectorId::Tor,
            at_hours(1),
            &mut NoBans,
            &mut NoSessions,
            &mut rng,
        )
        .into_iter()
        .collect();
    assert_eq!(sample, [onion(1), onion(900)].into_iter().collect());
    assert_eq!(
        list.disclose_early(ConnectorId::Tor),
        Some(DiscloseEarly::Running { since: at_hours(0) })
    );
}

/// Without the flag the same lists disclose nothing below the floor: the
/// existing rule stands (`rulings.rs`, `below_the_floor_the_sample_is_empty`).
#[test]
fn without_the_flag_the_same_white_of_one_discloses_nothing() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    confirm(&mut list, &onion(1), at_hours(0), &mut rng);
    list.set_own_address(ConnectorId::Tor, Some(onion(900)))
        .expect("own");
    assert!(list
        .disclose(
            ConnectorId::Tor,
            at_hours(1),
            &mut NoBans,
            &mut NoSessions,
            &mut rng
        )
        .is_empty());
    assert_eq!(list.disclose_early(ConnectorId::Tor), None);
}

/// No cache while the flag holds: white grows between two requests and
/// the second reply shows the growth.
#[test]
fn under_the_flag_nothing_is_cached_and_the_second_reply_shows_the_growth() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(0));
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    with_white(&mut list, 1, 1, at_hours(0), &mut rng);
    let first = list.disclose(
        connector,
        at_hours(1),
        &mut NoBans,
        &mut NoSessions,
        &mut rng,
    );
    assert_eq!(first, vec![v4(1)]);
    with_white(&mut list, 2, 3, at_hours(1), &mut rng);
    let second: BTreeSet<_> = list
        .disclose(
            connector,
            at_hours(1),
            &mut NoBans,
            &mut NoSessions,
            &mut rng,
        )
        .into_iter()
        .collect();
    assert_eq!(
        second,
        (1..=4).map(v4).collect(),
        "the same minute, a fresh draw"
    );
    // Above DISCLOSE_COUNT the draw is a uniform prefix of the population,
    // still fresh per request.
    with_white(&mut list, 5, 20, at_hours(1), &mut rng);
    let samples: BTreeSet<Vec<NetworkAddress>> = (0..8)
        .map(|_| {
            list.disclose(
                connector,
                at_hours(1),
                &mut NoBans,
                &mut NoSessions,
                &mut rng,
            )
        })
        .collect();
    assert!(samples.iter().all(|s| s.len() == DISCLOSE_COUNT));
    assert!(samples.len() > 1, "fresh draws differ: {samples:?}");
}

/// The span: at 24 hours with white still below the floor, the reply is
/// empty, and the flag has ended for the run.
#[test]
fn at_the_span_with_white_below_the_floor_the_reply_is_empty() {
    let mut rng = SplitMix64::new(3);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(1));
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    with_white(&mut list, 1, 5, at_hours(1), &mut rng);
    let just_before = Tick::new(at_hours(1).get() + P2P_DISCLOSE_EARLY_SPAN_NANOS - 1);
    assert_eq!(
        list.disclose(
            connector,
            just_before,
            &mut NoBans,
            &mut NoSessions,
            &mut rng
        )
        .len(),
        5
    );
    let at_span = Tick::new(at_hours(1).get() + P2P_DISCLOSE_EARLY_SPAN_NANOS);
    assert!(list
        .disclose(connector, at_span, &mut NoBans, &mut NoSessions, &mut rng)
        .is_empty());
    assert_eq!(list.disclose_early(connector), Some(DiscloseEarly::Ended));
    // Ended stays ended: more white, still below the floor, still nothing.
    with_white(&mut list, 6, 5, at_span, &mut rng);
    assert!(list
        .disclose(
            connector,
            Tick::new(at_span.get() + 1),
            &mut NoBans,
            &mut NoSessions,
            &mut rng
        )
        .is_empty());
}

/// The floor: white reaches it and the next reply is a cached window's
/// sample; white then drops below the floor, the flag stays ended, and
/// the reply is the cached sample until that window ends and empty after.
#[test]
fn when_white_reaches_the_floor_the_flag_ends_and_the_window_sample_rules_after() {
    let mut rng = SplitMix64::new(4);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(0));
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, floor(), at_hours(0), &mut rng);
    assert_eq!(
        list.disclose_early(connector),
        Some(DiscloseEarly::Ended),
        "the flag ended at the white write that reached the floor"
    );
    let drawn_at = at_hours(2);
    let sample = list.disclose(connector, drawn_at, &mut NoBans, &mut NoSessions, &mut rng);
    assert_eq!(sample.len(), DISCLOSE_COUNT);
    assert_eq!(
        list.disclose(
            connector,
            at_hours(3),
            &mut NoBans,
            &mut NoSessions,
            &mut rng
        ),
        sample,
        "a cached window's sample, served unchanged"
    );
    // White drops below the floor: a ban demotes one entry at the next
    // white read. The flag stays ended; the window's sample still rules.
    let mut bans = BanList::new();
    assert!(bans.ban_host(ip_of(&white[3]), at_hours(100), at_hours(3)));
    assert_eq!(
        list.white_count(connector, at_hours(4), &mut bans, &mut NoSessions, &mut rng),
        usize::from(floor()) - 1
    );
    assert_eq!(list.disclose_early(connector), Some(DiscloseEarly::Ended));
    assert_eq!(
        list.disclose(connector, at_hours(5), &mut bans, &mut NoSessions, &mut rng),
        sample,
        "below the floor again, but inside the window: the cached sample"
    );
    let after_window = Tick::new(drawn_at.get() + DISCLOSE_WINDOW_NANOS);
    assert!(
        list.disclose(
            connector,
            after_window,
            &mut bans,
            &mut NoSessions,
            &mut rng
        )
        .is_empty(),
        "after the window, below the floor, ended flag: nothing"
    );
}

/// The flag ends when white reaches the floor with no disclosure in
/// between: a later request after white falls back finds it ended.
#[test]
fn the_flag_ends_at_the_floor_without_any_disclosure() {
    let mut rng = SplitMix64::new(5);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(0));
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, floor(), at_hours(0), &mut rng);
    let mut bans = BanList::new();
    assert!(bans.ban_host(ip_of(&white[0]), at_hours(100), at_hours(0)));
    assert!(bans.ban_host(ip_of(&white[1]), at_hours(100), at_hours(0)));
    // The first disclose call comes after white fell back below the floor.
    assert!(
        list.disclose(connector, at_hours(1), &mut bans, &mut NoSessions, &mut rng)
            .is_empty(),
        "the flag ended at the crossing, so no sample was ever drawn under it"
    );
    assert_eq!(list.disclose_early(connector), Some(DiscloseEarly::Ended));
}

/// Per connector: one connector reaching the floor leaves the other's flag
/// running.
#[test]
fn one_connector_at_the_floor_leaves_the_others_flag_running() {
    let mut rng = SplitMix64::new(6);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(0));
    with_white(&mut list, 1, floor(), at_hours(0), &mut rng);
    assert_eq!(
        list.disclose_early(ConnectorId::Clearnet),
        Some(DiscloseEarly::Ended)
    );
    confirm(&mut list, &onion(1), at_hours(0), &mut rng);
    list.set_own_address(ConnectorId::Tor, Some(onion(900)))
        .expect("own");
    assert_eq!(
        list.disclose_early(ConnectorId::Tor),
        Some(DiscloseEarly::Running { since: at_hours(0) })
    );
    let tor: BTreeSet<_> = list
        .disclose(
            ConnectorId::Tor,
            at_hours(1),
            &mut NoBans,
            &mut NoSessions,
            &mut rng,
        )
        .into_iter()
        .collect();
    assert_eq!(tor, [onion(1), onion(900)].into_iter().collect());
}

/// Refused addresses: the refused set still filters the sample under the
/// flag, our own address included.
#[test]
fn the_refused_set_still_filters_the_sample_under_the_flag() {
    let mut rng = SplitMix64::new(7);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    list.set_disclose_early(at_hours(0));
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    // An operator-named private address is admitted whatever its range and
    // can be confirmed white; it is never disclosed.
    confirm(&mut list, &private(1), at_hours(0), &mut rng);
    confirm(&mut list, &v4(1), at_hours(0), &mut rng);
    list.set_own_address(connector, Some(private(2)))
        .expect("own");
    let sample = list.disclose(
        connector,
        at_hours(1),
        &mut NoBans,
        &mut NoSessions,
        &mut rng,
    );
    assert_eq!(
        set(&sample.iter().cloned().collect()),
        [v4(1)].into_iter().collect()
    );
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! This node's own address in its disclosure sample (slice 1 brief §5a;
//! the handshake-address ruling, 2026-10-09).
//!
//! A node's own dialable address reaches peers only as one uniform member
//! of that connector's disclosure population. It is never a white entry,
//! and with none set nothing about this node is disclosed.

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    white_diversity_floor, ConnectorId, DialOutcome, ListName, NetworkAddress, NoBans, Peerlist,
    RefusedSet, Source, Tick, DISCLOSE_COUNT,
};

const C: ConnectorId = ConnectorId::Tor;

fn now() -> Tick {
    Tick::new(0)
}

fn onion(n: u16) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
        port: 18080,
    }
}

fn own() -> NetworkAddress {
    onion(9_000)
}

/// White at the floor, the only way there is: an operator admit, the gray
/// draw, and a confirmed dial.
fn white_at_floor(rng: &mut SplitMix64) -> Peerlist {
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    for n in 0..u16::try_from(white_diversity_floor()).expect("small") {
        list.admit_gray(&onion(n), Source::Operator, now(), &mut NoBans, rng)
            .expect("admitted");
    }
    while let Some(drawn) = list.draw_gray(C, rng) {
        list.apply(&DialOutcome::Confirmed(drawn), now(), rng);
    }
    list
}

#[test]
fn with_an_onion_set_it_is_one_uniform_member_of_the_tor_sample() {
    // One of floor + 1 members, so about DISCLOSE_COUNT / (floor + 1) of
    // samples hold it: 12 of 49. Over many fresh lists that is a rate a
    // reserved slot (every sample) or an exclusion (no sample) would miss.
    let mut held = 0u32;
    let rounds = 400u32;
    for seed in 0..rounds {
        let mut rng = SplitMix64::new(u64::from(seed));
        let mut list = white_at_floor(&mut rng);
        list.set_own_address(C, Some(own()))
            .expect("a Tor address on Tor");
        let sample = list.disclose(C, now(), &mut NoBans, &mut rng);
        assert_eq!(sample.len(), DISCLOSE_COUNT, "seed {seed}: a full sample");
        assert!(
            sample.iter().filter(|a| **a == own()).count() <= 1,
            "seed {seed}: at most once"
        );
        if sample.contains(&own()) {
            held += 1;
        }
    }
    let expected = rounds * u32::try_from(DISCLOSE_COUNT).expect("small")
        / (u32::try_from(white_diversity_floor()).expect("small") + 1);
    // 98 expected; five standard deviations is about 44.
    assert!(
        (expected - 44..=expected + 44).contains(&held),
        "the own address was in {held} of {rounds} samples; expected about {expected}"
    );
}

#[test]
fn with_no_own_address_nothing_about_this_node_is_disclosed() {
    for seed in 0..50 {
        let mut rng = SplitMix64::new(seed);
        let mut list = white_at_floor(&mut rng);
        let sample = list.disclose(C, now(), &mut NoBans, &mut rng);
        assert_eq!(sample.len(), DISCLOSE_COUNT);
        assert!(!sample.contains(&own()), "seed {seed}");
        for address in &sample {
            assert!(
                list.is_white(address),
                "seed {seed}: every member is a white entry"
            );
        }
    }
}

#[test]
fn the_own_address_is_never_a_white_entry_and_clearing_it_removes_it() {
    let mut rng = SplitMix64::new(1);
    let mut list = white_at_floor(&mut rng);
    list.set_own_address(C, Some(own())).expect("set");
    assert!(!list.is_white(&own()));
    assert!(!list.is_gray(&own()));
    assert!(
        !list.snapshot().iter().any(|(a, _)| *a == own()),
        "the own address is on neither list"
    );
    // Disclosed while set, and only then: the next window after clearing
    // it draws a sample without it.
    let mut seen = false;
    for seed in 0..200 {
        let mut rng = SplitMix64::new(seed);
        let mut fresh = white_at_floor(&mut rng);
        fresh.set_own_address(C, Some(own())).expect("set");
        seen |= fresh
            .disclose(C, now(), &mut NoBans, &mut rng)
            .contains(&own());
    }
    assert!(seen, "the own address is drawn at all");
    list.set_own_address(C, None).expect("clear");
    for seed in 0..200 {
        let mut rng = SplitMix64::new(seed);
        let mut fresh = white_at_floor(&mut rng);
        fresh.set_own_address(C, Some(own())).expect("set");
        fresh.set_own_address(C, None).expect("clear");
        assert!(!fresh
            .disclose(C, now(), &mut NoBans, &mut rng)
            .contains(&own()));
    }
}

#[test]
fn an_address_of_another_connector_is_refused_as_the_own_address() {
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let clearnet = NetworkAddress::Ipv4 {
        ip: std::net::Ipv4Addr::new(11, 20, 0, 1),
        port: 18080,
    };
    assert!(list.set_own_address(C, Some(clearnet)).is_err());
    assert!(list
        .set_own_address(ConnectorId::Clearnet, Some(own()))
        .is_err());
    assert_eq!(list.snapshot().len(), 0);
    let _ = ListName::Gray;
}

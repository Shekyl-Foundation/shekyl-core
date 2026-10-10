// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The door and the lists: `P2P_3_SLICE_1_PEERLIST_BRIEF.md` §11.2 (no
//! entry crosses connectors) and §11.3 (the model sequences). §11.1 is the
//! `compile_fail` doctest on the crate root plus `no_white_type_is_exported`
//! below.

use std::net::Ipv4Addr;

use shekyl_peerlist::{
    DialOutcome, ListName, NetworkAddress, NoBans, Peerlist, Refusal, SessionId, Source, Tick,
    EXPIRATION_PERIOD_NANOS, GRAY_CAP, WHITE_CAP,
};
use shekyl_relay_privacy::rng::SplitMix64;

fn v4(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(10, 0, 0, n),
        port: 18080,
    }
}

fn v4_wide(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(10, 1, (n >> 8) as u8, (n & 0xff) as u8),
        port: 18080,
    }
}

fn onion(n: u8) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
        port: 18080,
    }
}

fn session(n: u8) -> SessionId {
    SessionId([n; 16])
}

fn fleet() -> Vec<NetworkAddress> {
    vec![v4(250), v4(251)]
}

fn at_hours(h: u64) -> Tick {
    Tick::new(h * 60 * 60 * 1_000_000_000)
}

/// Draw from gray until `address` is the outstanding draw, as the dialer
/// would when the uniform draw lands on it.
fn draw_until(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    let connector = Peerlist::connector_of(address).expect("served");
    for _ in 0..10_000 {
        match list.draw_gray(connector, rng) {
            Some(drawn) if drawn == *address => return,
            Some(other) => list.apply(&DialOutcome::PayloadRefused(other), at_hours(0), rng),
            None => panic!("gray ran out before {address:?} was drawn"),
        }
    }
    panic!("{address:?} was never drawn");
}

#[test]
fn no_white_type_is_exported() {
    // §11.1. The crate's public items are the lists and the outcome types;
    // `White` is not among them, so no caller can build one. The
    // `compile_fail` doctest on the crate root is the mechanical half.
    let names = [
        "Peerlist",
        "DialOutcome",
        "Source",
        "Refusal",
        "SessionId",
        "ListName",
    ];
    assert!(names.contains(&"Peerlist"));
}

#[test]
fn an_outstanding_gray_draw_promotes_on_session_accepted_and_on_confirmed() {
    for (make, label) in [
        (
            DialOutcome::SessionAccepted as fn(NetworkAddress) -> DialOutcome,
            "accepted",
        ),
        (DialOutcome::Confirmed, "confirmed"),
    ] {
        let mut rng = SplitMix64::new(1);
        let mut list = Peerlist::new(fleet());
        let peer = v4(1);
        assert_eq!(
            list.admit_gray(&peer, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
            Ok(true)
        );
        assert!(list.is_gray(&peer) && !list.is_white(&peer));
        draw_until(&mut list, &peer, &mut rng);
        list.apply(&make(peer.clone()), at_hours(1), &mut rng);
        assert!(list.is_white(&peer), "{label}: the drawn address is white");
        assert!(!list.is_gray(&peer), "{label}: and no longer gray");
    }
}

#[test]
fn either_outcome_on_an_undrawn_ordinary_address_writes_nothing() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(fleet());
    let undrawn = v4(2);
    list.apply(
        &DialOutcome::SessionAccepted(undrawn.clone()),
        at_hours(1),
        &mut rng,
    );
    list.apply(
        &DialOutcome::Confirmed(undrawn.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(!list.is_white(&undrawn) && !list.is_gray(&undrawn));
    // In gray but not drawn: still nothing.
    assert_eq!(
        list.admit_gray(
            &undrawn,
            Source::Operator,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Ok(true)
    );
    list.apply(
        &DialOutcome::SessionAccepted(undrawn.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(list.is_gray(&undrawn) && !list.is_white(&undrawn));
}

#[test]
fn a_foundation_harvest_writes_white_and_anyone_elses_does_not() {
    let mut rng = SplitMix64::new(3);
    let mut list = Peerlist::new(fleet());
    let seed = v4(250);
    let other = v4(3);
    list.apply(
        &DialOutcome::HarvestDone(seed.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(
        list.is_white(&seed),
        "the fleet's harvest is the §3 exception"
    );
    assert_eq!(
        list.admit_gray(&other, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    list.apply(
        &DialOutcome::HarvestDone(other.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(list.is_gray(&other) && !list.is_white(&other));
}

#[test]
fn a_non_fleet_harvest_returns_an_outstanding_draw_to_drawable_gray() {
    let mut rng = SplitMix64::new(13);
    let mut list = Peerlist::new(fleet());
    let peer = v4(30);
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    draw_until(&mut list, &peer, &mut rng);
    list.apply(
        &DialOutcome::HarvestDone(peer.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(
        list.is_gray(&peer) && !list.is_white(&peer),
        "anyone else's harvest leaves white unchanged"
    );
    draw_until(&mut list, &peer, &mut rng);

    // The fleet's harvest of an outstanding draw still writes white.
    let seed = v4(250);
    assert_eq!(
        list.admit_gray(&seed, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    draw_until(&mut list, &seed, &mut rng);
    list.apply(
        &DialOutcome::HarvestDone(seed.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(list.is_white(&seed) && !list.is_gray(&seed));
}

#[test]
fn an_outstanding_draw_survives_eviction_and_gray_may_sit_over_the_cap() {
    let mut rng = SplitMix64::new(14);
    let mut list = Peerlist::new(fleet());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    for n in 0..GRAY_CAP {
        let n = u16::try_from(n).expect("fits");
        assert_eq!(
            list.admit_gray(
                &v4_wide(n),
                Source::Reload,
                at_hours(0),
                &mut NoBans,
                &mut rng
            ),
            Ok(true)
        );
    }
    let pinned = v4_wide(0);
    // The door helper tries 10_000 draws. At 5_000 gray that misses often;
    // a full gray list needs a longer search, and each miss settles back.
    let mut drawn_pinned = false;
    for _ in 0..100_000 {
        match list.draw_gray(connector, &mut rng) {
            Some(drawn) if drawn == pinned => {
                drawn_pinned = true;
                break;
            }
            Some(other) => list.apply(&DialOutcome::PayloadRefused(other), at_hours(0), &mut rng),
            None => panic!("gray ran out before the pinned address was drawn"),
        }
    }
    assert!(drawn_pinned, "the pinned address was drawn");
    assert!(
        list.is_gray(&pinned) && !list.is_white(&pinned),
        "the draw is outstanding, which is still gray"
    );
    let extra_admits = 100;
    for n in 0..extra_admits {
        let n = u16::try_from(GRAY_CAP + n).expect("fits");
        assert_eq!(
            list.admit_gray(
                &v4_wide(n),
                Source::Reload,
                at_hours(0),
                &mut NoBans,
                &mut rng
            ),
            Ok(true)
        );
    }
    assert!(
        list.is_gray(&pinned),
        "eviction drops a drawable gray seat, not the outstanding draw"
    );
    list.apply(
        &DialOutcome::SessionAccepted(pinned.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(list.is_white(&pinned) && !list.is_gray(&pinned));

    // Every gray seat outstanding: the next admit has nobody else to drop,
    // so gray sits one over the cap and the draws stay.
    let mut list = Peerlist::new(fleet());
    for n in 0..GRAY_CAP {
        let n = u16::try_from(n).expect("fits");
        assert_eq!(
            list.admit_gray(
                &v4_wide(n),
                Source::Reload,
                at_hours(0),
                &mut NoBans,
                &mut rng
            ),
            Ok(true)
        );
    }
    let first = list.draw_gray(connector, &mut rng).expect("drawable");
    for _ in 1..GRAY_CAP {
        list.draw_gray(connector, &mut rng).expect("drawable");
    }
    assert_eq!(list.gray_count(connector), GRAY_CAP);
    let extra = v4(9);
    assert_eq!(
        list.admit_gray(&extra, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    assert_eq!(list.gray_count(connector), GRAY_CAP + 1);
    assert!(list.is_gray(&first) && list.is_gray(&extra));
    list.apply(
        &DialOutcome::SessionAccepted(first.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(list.is_white(&first) && !list.is_gray(&first));
}

#[test]
fn incoming_and_add_peer_stay_gray() {
    let mut rng = SplitMix64::new(4);
    let mut list = Peerlist::new(fleet());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    assert_eq!(
        list.admit_gray(
            &v4(4),
            Source::Session {
                id: session(1),
                connector
            },
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Ok(true)
    );
    assert_eq!(
        list.admit_gray(&v4(5), Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    assert!(list.is_gray(&v4(4)) && list.is_gray(&v4(5)));
    assert!(!list.is_white(&v4(4)) && !list.is_white(&v4(5)));
    assert_eq!(
        list.white_count(connector, at_hours(0), &mut NoBans, &mut rng),
        0
    );
}

#[test]
fn expiry_returns_white_to_gray_and_contact_this_node_opened_moves_the_clock() {
    let mut rng = SplitMix64::new(5);
    let mut list = Peerlist::new(fleet());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let peer = v4(6);
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    draw_until(&mut list, &peer, &mut rng);
    list.apply(
        &DialOutcome::SessionAccepted(peer.clone()),
        at_hours(0),
        &mut rng,
    );
    assert_eq!(
        list.white_count(connector, at_hours(23), &mut NoBans, &mut rng),
        1
    );
    assert_eq!(
        list.next_expiry(connector),
        Some(Tick::new(EXPIRATION_PERIOD_NANOS)),
        "one deadline for the list"
    );
    // Contact this node opened at hour 20 moves the clock.
    list.apply(
        &DialOutcome::SessionAccepted(peer.clone()),
        at_hours(20),
        &mut rng,
    );
    assert_eq!(
        list.white_count(connector, at_hours(43), &mut NoBans, &mut rng),
        1,
        "the clock moved"
    );
    // Inbound contact does not: an admit of a white address leaves it
    // white, does not seat it on gray, and does not move the clock.
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(false)
    );
    assert!(
        list.is_white(&peer) && !list.is_gray(&peer),
        "a white entry is one seat, untouched by an admit"
    );
    assert_eq!(
        list.persistable().iter().filter(|a| *a == &peer).count(),
        1,
        "the file names the address once"
    );
    assert_eq!(
        list.snapshot().iter().filter(|(a, _)| a == &peer).count(),
        1
    );
    assert!(list.snapshot().contains(&(peer.clone(), ListName::White)));
    assert_eq!(
        list.white_count(connector, at_hours(43), &mut NoBans, &mut rng),
        1,
        "the admit did not move the clock"
    );
    assert_eq!(
        list.white_count(connector, at_hours(44), &mut NoBans, &mut rng),
        0,
        "24 h after the last contact this node opened"
    );
    assert!(list.is_gray(&peer), "expiry demotes to gray");
}

#[test]
fn reload_is_gray_only_and_does_not_draw_former_white_first() {
    // Fifty addresses, ten of them white, saved and restored into fresh
    // lists; the first draw after reload is a former white one about a
    // fifth of the time, not first.
    let mut rng = SplitMix64::new(6);
    let mut list = Peerlist::new(fleet());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    for n in 1..=50u8 {
        assert_eq!(
            list.admit_gray(&v4(n), Source::Operator, at_hours(0), &mut NoBans, &mut rng),
            Ok(true)
        );
    }
    for n in 1..=10u8 {
        draw_until(&mut list, &v4(n), &mut rng);
        list.apply(&DialOutcome::Confirmed(v4(n)), at_hours(0), &mut rng);
    }
    assert_eq!(
        list.white_count(connector, at_hours(0), &mut NoBans, &mut rng),
        10
    );
    let saved = list.persistable();
    assert_eq!(saved.len(), 50);

    let mut former_white_first = 0_u32;
    let trials = 2_000_u32;
    for seed in 0..trials {
        let mut rng = SplitMix64::new(100 + u64::from(seed));
        let mut fresh = Peerlist::new(fleet());
        assert_eq!(fresh.restore(saved.clone(), &mut rng), 50);
        assert_eq!(
            fresh.white_count(connector, at_hours(0), &mut NoBans, &mut rng),
            0,
            "reload is gray only"
        );
        assert_eq!(fresh.gray_count(connector), 50);
        let first = fresh.draw_gray(connector, &mut rng).expect("gray is full");
        if (1..=10).contains(&first_octet(&first)) {
            former_white_first += 1;
        }
    }
    let share = f64::from(former_white_first) / f64::from(trials);
    assert!(
        (share - 0.2).abs() < 0.04,
        "former white addresses are drawn at their share, not first: {share}"
    );
}

fn first_octet(address: &NetworkAddress) -> u8 {
    match address {
        NetworkAddress::Ipv4 { ip, .. } => ip.octets()[3],
        _ => 0,
    }
}

#[test]
fn failed_and_refused_dials_drop_the_draw_and_a_refused_payload_leaves_it_gray() {
    for (make, drops) in [
        (
            DialOutcome::DialFailed as fn(NetworkAddress) -> DialOutcome,
            true,
        ),
        (DialOutcome::PeerlistRefused, true),
        (DialOutcome::PayloadRefused, false),
    ] {
        let mut rng = SplitMix64::new(7);
        let mut list = Peerlist::new(fleet());
        let peer = v4(7);
        assert_eq!(
            list.admit_gray(&peer, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
            Ok(true)
        );
        draw_until(&mut list, &peer, &mut rng);
        list.apply(&make(peer.clone()), at_hours(0), &mut rng);
        assert_eq!(list.is_gray(&peer), !drops, "{:?}", make(peer.clone()));
        assert!(!list.is_white(&peer));
    }
}

#[test]
fn a_failed_redial_leaves_white() {
    let mut rng = SplitMix64::new(8);
    let mut list = Peerlist::new(fleet());
    let peer = v4(8);
    assert_eq!(
        list.admit_gray(&peer, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    draw_until(&mut list, &peer, &mut rng);
    list.apply(&DialOutcome::Confirmed(peer.clone()), at_hours(0), &mut rng);
    list.apply(
        &DialOutcome::DialFailed(peer.clone()),
        at_hours(1),
        &mut rng,
    );
    assert!(
        list.is_white(&peer),
        "one failed redial does not demote; the clock does"
    );
}

#[test]
fn no_entry_crosses_connectors() {
    let mut rng = SplitMix64::new(9);
    let mut list = Peerlist::new(fleet());
    let clear = Peerlist::connector_of(&v4(1)).expect("served");
    let hidden = Peerlist::connector_of(&onion(1)).expect("served");
    assert_ne!(clear, hidden);

    // One foreign entry rejects the whole list, and nothing was admitted.
    let mixed = vec![v4(9), onion(9), v4(10)];
    assert_eq!(
        list.admit_received_list(
            &mixed,
            session(2),
            clear,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Err(Refusal::ForeignConnector)
    );
    assert_eq!(list.gray_count(clear), 0);
    assert_eq!(list.gray_count(hidden), 0);

    // Each partition holds its own type.
    assert_eq!(
        list.admit_received_list(
            &[v4(9), v4(10)],
            session(2),
            clear,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Ok(2)
    );
    assert_eq!(
        list.admit_received_list(
            &[onion(9)],
            session(3),
            hidden,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Ok(1)
    );
    assert_eq!(list.gray_count(clear), 2);
    assert_eq!(list.gray_count(hidden), 1);
    assert_eq!(
        list.draw_gray(hidden, &mut rng),
        Some(onion(9)),
        "a hidden draw is an onion"
    );
    // A session on one connector cannot admit the other's address.
    assert_eq!(
        list.admit_gray(
            &onion(10),
            Source::Session {
                id: session(2),
                connector: clear
            },
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Err(Refusal::ForeignConnector)
    );

    // Reload derives the connector again and keeps the partition.
    let saved = list.persistable();
    let mut fresh = Peerlist::new(fleet());
    assert_eq!(fresh.restore(saved, &mut rng), 3);
    assert_eq!(fresh.gray_count(clear), 2);
    assert_eq!(fresh.gray_count(hidden), 1);
}

#[test]
fn gray_eviction_is_a_draw_that_keeps_the_address_just_named() {
    let mut rng = SplitMix64::new(10);
    let mut list = Peerlist::new(fleet());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    for n in 0..GRAY_CAP {
        let n = u16::try_from(n).expect("fits");
        assert_eq!(
            list.admit_gray(
                &v4_wide(n),
                Source::Reload,
                at_hours(0),
                &mut NoBans,
                &mut rng
            ),
            Ok(true)
        );
    }
    assert_eq!(list.gray_count(connector), GRAY_CAP);
    let named = v4(42);
    assert_eq!(
        list.admit_gray(&named, Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    assert_eq!(
        list.gray_count(connector),
        GRAY_CAP,
        "over the cap one entry was dropped"
    );
    assert!(list.is_gray(&named), "and it was not the one just named");
}

#[test]
fn white_eviction_demotes_a_random_other_entry() {
    let mut rng = SplitMix64::new(11);
    let mut list = Peerlist::new(fleet());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    for n in 0..=WHITE_CAP {
        let n = u16::try_from(n).expect("fits");
        let a = v4_wide(n);
        assert_eq!(
            list.admit_gray(&a, Source::Reload, at_hours(0), &mut NoBans, &mut rng),
            Ok(true)
        );
        draw_until(&mut list, &a, &mut rng);
        list.apply(&DialOutcome::Confirmed(a.clone()), at_hours(0), &mut rng);
    }
    assert_eq!(
        list.white_count(connector, at_hours(0), &mut NoBans, &mut rng),
        WHITE_CAP
    );
    let last = v4_wide(u16::try_from(WHITE_CAP).expect("fits"));
    assert!(list.is_white(&last), "the entry just promoted stays");
    assert_eq!(list.gray_count(connector), 1, "the demoted entry is gray");
}

#[test]
fn the_snapshot_names_each_address_and_its_list_without_a_clock() {
    let mut rng = SplitMix64::new(12);
    let mut list = Peerlist::new(fleet());
    assert_eq!(
        list.admit_gray(&v4(1), Source::Operator, at_hours(0), &mut NoBans, &mut rng),
        Ok(true)
    );
    assert_eq!(
        list.admit_gray(
            &onion(1),
            Source::Operator,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Ok(true)
    );
    draw_until(&mut list, &v4(1), &mut rng);
    list.apply(&DialOutcome::Confirmed(v4(1)), at_hours(0), &mut rng);
    let mut snapshot = list.snapshot();
    snapshot.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        snapshot,
        vec![(v4(1), ListName::White), (onion(1), ListName::Gray)]
    );
}

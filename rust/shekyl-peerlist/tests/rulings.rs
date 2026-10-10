// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The 2026-10-09 rulings: D3 (the cached sample), D4 (a ban demotes),
//! D-S1 (the per-session intake cap), and the §11.5 additions
//! (`P2P_3_SLICE_1_PEERLIST_BRIEF.md`).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_peerlist::{
    white_diversity_floor, BanQuery, DialOutcome, NetworkAddress, NoBans, Peerlist, Refusal,
    SessionId, Source, Tick, DISCLOSE_COUNT, DISCLOSE_WINDOW_NANOS, SESSION_INTAKE_CAP,
    WHITE_REFILL_LINE,
};
use shekyl_relay_privacy::rng::SplitMix64;
use shekyl_transport_layer::BanList;

fn v4(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(10, 2, (n >> 8) as u8, (n & 0xff) as u8),
        port: 18080,
    }
}

fn ip_of(address: &NetworkAddress) -> IpAddr {
    address.ip().expect("an IP address")
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

fn at_hours(h: u64) -> Tick {
    Tick::new(h * 60 * 60 * 1_000_000_000)
}

fn draw_until(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    let connector = Peerlist::connector_of(address).expect("served");
    for _ in 0..100_000 {
        match list.draw_gray(connector, rng) {
            Some(drawn) if drawn == *address => return,
            Some(other) => list.apply(&DialOutcome::PayloadRefused(other), at_hours(0), rng),
            None => panic!("gray ran out"),
        }
    }
    panic!("never drawn");
}

/// `count` white clearnet addresses numbered from `from`, confirmed at hour 0.
fn with_white(
    list: &mut Peerlist,
    from: u16,
    count: u16,
    rng: &mut SplitMix64,
) -> Vec<NetworkAddress> {
    let mut made = Vec::new();
    for n in from..from + count {
        let a = v4(n);
        assert_eq!(
            list.admit_gray(&a, Source::Operator, at_hours(0), &mut NoBans, rng),
            Ok(true)
        );
        draw_until(list, &a, rng);
        list.apply(&DialOutcome::Confirmed(a.clone()), at_hours(0), rng);
        made.push(a);
    }
    made
}

// ---------------------------------------------------------------- D3

#[test]
fn below_the_floor_the_sample_is_empty() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let floor = u16::try_from(white_diversity_floor()).expect("fits");
    with_white(&mut list, 1, floor - 1, &mut rng);
    assert!(list
        .disclose(connector, at_hours(1), &mut NoBans, &mut rng)
        .is_empty());
    with_white(&mut list, 1000, 1, &mut rng);
    assert_eq!(
        list.disclose(connector, at_hours(1), &mut NoBans, &mut rng)
            .len(),
        DISCLOSE_COUNT,
        "at the floor the sample is DISCLOSE_COUNT addresses"
    );
}

#[test]
fn the_sample_is_cached_for_the_window_and_redrawn_after_it() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    with_white(&mut list, 1, 100, &mut rng);
    let first = list.disclose(connector, at_hours(1), &mut NoBans, &mut rng);
    assert_eq!(first.len(), DISCLOSE_COUNT);
    assert_eq!(
        first.iter().collect::<BTreeSet<_>>().len(),
        DISCLOSE_COUNT,
        "distinct"
    );
    for h in [2, 10, 23] {
        assert_eq!(
            list.disclose(connector, at_hours(h), &mut NoBans, &mut rng),
            first,
            "every requester in the window gets the same sample, unchanged"
        );
    }
    // Keep white alive past its own 24-hour expiry, then cross the window:
    // 24 h after the draw a new sample is drawn.
    for n in 1..=100 {
        list.apply(&DialOutcome::Confirmed(v4(n)), at_hours(23), &mut rng);
    }
    let later = list.disclose(
        connector,
        Tick::new(at_hours(1).get() + DISCLOSE_WINDOW_NANOS),
        &mut NoBans,
        &mut rng,
    );
    assert_eq!(later.len(), DISCLOSE_COUNT);
    assert_ne!(later, first, "a fresh uniform draw");
}

#[test]
fn the_sample_is_uniform_over_white_with_our_own_address_as_one_member() {
    // 59 white plus our own address: a population of 60, twelve drawn per
    // window. Over many fresh windows every member, ours included, appears
    // about a fifth of the time.
    let mut rng = SplitMix64::new(3);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 59, &mut rng);
    let own = v4(9_999);
    list.set_own_address(connector, Some(own.clone()));
    let mut own_seen = 0_u32;
    let mut each: Vec<u32> = vec![0; 59];
    let windows = 3_000_u32;
    for w in 0..windows {
        let now = Tick::new(u64::from(w) * DISCLOSE_WINDOW_NANOS + 1);
        // Keep white alive across windows: re-confirm everything.
        for a in &white {
            list.apply(&DialOutcome::Confirmed(a.clone()), now, &mut rng);
        }
        let sample = list.disclose(connector, now, &mut NoBans, &mut rng);
        assert_eq!(sample.len(), DISCLOSE_COUNT);
        if sample.contains(&own) {
            own_seen += 1;
        }
        for (i, a) in white.iter().enumerate() {
            if sample.contains(a) {
                each[i] += 1;
            }
        }
        assert!(
            !list.is_white(&own),
            "our own address is never a white entry"
        );
    }
    let expect = f64::from(u32::try_from(DISCLOSE_COUNT).expect("fits")) / 60.0;
    let own_share = f64::from(own_seen) / f64::from(windows);
    assert!(
        (own_share - expect).abs() < 0.03,
        "our own address is one uniform member: {own_share} vs {expect}"
    );
    for (i, count) in each.iter().enumerate() {
        let share = f64::from(*count) / f64::from(windows);
        assert!(
            (share - expect).abs() < 0.04,
            "white {i}: {share} vs {expect}"
        );
    }
}

#[test]
fn a_received_list_longer_than_disclose_count_is_refused_whole() {
    let mut rng = SplitMix64::new(4);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let long: Vec<NetworkAddress> = (1..=13).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &long,
            session(1),
            connector,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
    assert_eq!(list.gray_count(connector), 0, "not trimmed and kept");
    let exact: Vec<NetworkAddress> = (1..=12).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &exact,
            session(1),
            connector,
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Ok(12)
    );
}

#[test]
fn the_sample_carries_no_gray_and_no_clock() {
    let mut rng = SplitMix64::new(5);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    with_white(&mut list, 1, 60, &mut rng);
    for n in 500..600 {
        assert_eq!(
            list.admit_gray(&v4(n), Source::Operator, at_hours(0), &mut NoBans, &mut rng),
            Ok(true)
        );
    }
    let sample = list.disclose(connector, at_hours(1), &mut NoBans, &mut rng);
    assert!(
        sample.iter().all(|a| list.is_white(a)),
        "gray is never in the message"
    );
    // The value is a Vec<NetworkAddress>: there is no field for a clock.
    let _: &Vec<NetworkAddress> = &sample;
}

// ---------------------------------------------------------------- D4

#[test]
fn a_banned_white_entry_is_demoted_on_the_next_white_read_and_the_floor_drops() {
    let mut rng = SplitMix64::new(6);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 50, &mut rng);
    let mut bans = BanList::new();
    assert_eq!(list.white_count(connector, at_hours(1), &mut bans), 50);
    let banned = white[7].clone();
    assert!(bans.ban_host(ip_of(&banned), at_hours(10), at_hours(1)));
    // The transport layer wrote nothing in the peer list: still white until
    // white is next read.
    assert!(list.is_white(&banned));
    assert_eq!(
        list.white_count(connector, at_hours(2), &mut bans),
        49,
        "the floor count drops with it"
    );
    assert!(
        !list.is_white(&banned) && list.is_gray(&banned),
        "demoted to gray, not removed"
    );
    assert!(
        list.below_refill_line(connector, at_hours(2), &mut bans) == (49 < WHITE_REFILL_LINE),
        "the refill line counts white as it stands"
    );
}

#[test]
fn a_demoted_entry_is_ordinary_gray_evictable_skipped_at_dial_and_refused_at_admission() {
    let mut rng = SplitMix64::new(7);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 10, &mut rng);
    let banned = white[3].clone();
    let mut bans = BanList::new();
    assert!(bans.ban_host(ip_of(&banned), at_hours(10), at_hours(1)));
    assert_eq!(list.white_count(connector, at_hours(1), &mut bans), 9);
    assert!(list.is_gray(&banned));
    // Skipped by the pre-dial check during the ban.
    assert!(!Peerlist::pre_dial_check(&banned, at_hours(2), &mut bans));
    assert!(Peerlist::pre_dial_check(&white[0], at_hours(2), &mut bans));
    // Refused at gray admission if gossiped back in.
    assert_eq!(
        list.admit_gray(
            &banned,
            Source::Session {
                id: session(1),
                connector
            },
            at_hours(2),
            &mut bans,
            &mut rng
        ),
        Err(Refusal::Banned)
    );
    // Evictable from gray with no protection: fill gray past the cap and
    // the demoted entry is dropped at its share.
    let mut dropped = 0_u32;
    let trials = 5_u32;
    for seed in 0..trials {
        let mut rng = SplitMix64::new(100 + u64::from(seed));
        let mut list = Peerlist::new(Vec::new());
        let white = with_white(&mut list, 1, 10, &mut rng);
        let banned = white[3].clone();
        let mut bans = BanList::new();
        assert!(bans.ban_host(ip_of(&banned), at_hours(10), at_hours(1)));
        assert_eq!(list.white_count(connector, at_hours(1), &mut bans), 9);
        // 20 000 evictions, each a uniform draw over about 5 000 entries:
        // the demoted one is hit with probability about 0.98 per trial.
        for n in 1000..1000 + 25_000u16 {
            let _admitted =
                list.admit_gray(&v4(n), Source::Reload, at_hours(1), &mut NoBans, &mut rng);
        }
        if !list.is_gray(&banned) {
            dropped += 1;
        }
    }
    assert!(dropped > 0, "an ordinary gray entry is evicted sometimes");
    // After the ban expires it is drawn, dialled, and re-earns white only
    // through the normal door.
    assert!(Peerlist::pre_dial_check(&banned, at_hours(11), &mut bans));
    assert!(list.is_gray(&banned));
    list.apply(
        &DialOutcome::Confirmed(banned.clone()),
        at_hours(11),
        &mut rng,
    );
    assert!(!list.is_white(&banned), "not drawn: no promotion");
    draw_until(&mut list, &banned, &mut rng);
    list.apply(
        &DialOutcome::Confirmed(banned.clone()),
        at_hours(11),
        &mut rng,
    );
    assert!(
        list.is_white(&banned),
        "drawn and confirmed: the normal door"
    );
}

#[test]
fn a_ban_does_not_rebuild_the_cached_sample_and_tor_never_demotes() {
    let mut rng = SplitMix64::new(8);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 60, &mut rng);
    let mut bans = BanList::new();
    let sample = list.disclose(connector, at_hours(1), &mut bans, &mut rng);
    let in_sample = sample[0].clone();
    assert!(bans.ban_host(ip_of(&in_sample), at_hours(10), at_hours(1)));
    assert_eq!(
        list.disclose(connector, at_hours(2), &mut bans, &mut rng),
        sample,
        "the cached sample is not rebuilt on a ban"
    );
    assert!(
        list.is_gray(&in_sample),
        "though the entry itself was demoted at the read"
    );
    let _ = white;
    // Tor: no bannable address, nothing demotes.
    let hidden = Peerlist::connector_of(&onion(1)).expect("served");
    struct BanAll;
    impl BanQuery for BanAll {
        fn is_banned(&mut self, _host: IpAddr, _now: Tick) -> bool {
            true
        }
    }
    for n in 1..=3 {
        assert_eq!(
            list.admit_gray(
                &onion(n),
                Source::Operator,
                at_hours(0),
                &mut BanAll,
                &mut rng
            ),
            Ok(true)
        );
        draw_until(&mut list, &onion(n), &mut rng);
        list.apply(&DialOutcome::Confirmed(onion(n)), at_hours(0), &mut rng);
    }
    assert_eq!(
        list.white_count(hidden, at_hours(1), &mut BanAll),
        3,
        "D7: Tor has no bannable address"
    );
}

// ---------------------------------------------------------------- D-S1

#[test]
fn the_twenty_fifth_distinct_address_from_one_session_in_a_day_is_a_violation() {
    let mut rng = SplitMix64::new(9);
    let mut list = Peerlist::new(Vec::new());
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let s = session(1);
    let first: Vec<NetworkAddress> = (1..=12).map(v4).collect();
    let second: Vec<NetworkAddress> = (13..=24).map(v4).collect();
    assert_eq!(
        list.admit_received_list(&first, s, connector, at_hours(0), &mut NoBans, &mut rng),
        Ok(12)
    );
    // The same sample again within the window counts once.
    assert_eq!(
        list.admit_received_list(&first, s, connector, at_hours(1), &mut NoBans, &mut rng),
        Ok(0)
    );
    assert_eq!(list.intake_count(connector, s, at_hours(1)), 12);
    assert_eq!(
        list.admit_received_list(&second, s, connector, at_hours(12), &mut NoBans, &mut rng),
        Ok(12)
    );
    assert_eq!(
        list.intake_count(connector, s, at_hours(12)),
        SESSION_INTAKE_CAP
    );
    // The 25th distinct address within 24 hours.
    assert_eq!(
        list.admit_gray(
            &v4(25),
            Source::Session { id: s, connector },
            at_hours(13),
            &mut NoBans,
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
    assert!(!list.is_gray(&v4(25)));
    // Another session is not charged for it.
    assert_eq!(
        list.admit_gray(
            &v4(25),
            Source::Session {
                id: session(2),
                connector
            },
            at_hours(13),
            &mut NoBans,
            &mut rng
        ),
        Ok(true)
    );
    // The span is sliding: once the first twelve are a day old, room returns.
    assert_eq!(list.intake_count(connector, s, at_hours(25)), 12);
    assert_eq!(
        list.admit_gray(
            &v4(26),
            Source::Session { id: s, connector },
            at_hours(25),
            &mut NoBans,
            &mut rng
        ),
        Ok(true)
    );
    // Operator and reload sources are not capped.
    for n in 100..200 {
        assert_eq!(
            list.admit_gray(
                &v4(n),
                Source::Operator,
                at_hours(13),
                &mut NoBans,
                &mut rng
            ),
            Ok(true)
        );
    }
    // A forgotten session starts over.
    list.forget_session(connector, s);
    assert_eq!(list.intake_count(connector, s, at_hours(25)), 0);
}

#[test]
fn the_intake_cap_is_the_same_on_every_connector() {
    let mut rng = SplitMix64::new(10);
    let mut list = Peerlist::new(Vec::new());
    let hidden = Peerlist::connector_of(&onion(1)).expect("served");
    let s = session(3);
    for n in 1..=24u8 {
        assert_eq!(
            list.admit_gray(
                &onion(n),
                Source::Session {
                    id: s,
                    connector: hidden
                },
                at_hours(0),
                &mut NoBans,
                &mut rng
            ),
            Ok(true)
        );
    }
    assert_eq!(
        list.admit_gray(
            &onion(25),
            Source::Session {
                id: s,
                connector: hidden
            },
            at_hours(0),
            &mut NoBans,
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The 2026-10-09 rulings: D3 (the cached sample), D4 (a ban demotes),
//! D-S1 (the per-session intake cap), and the §11.5 additions
//! (`P2P_3_SLICE_1_PEERLIST_BRIEF.md`).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    white_diversity_floor, BanEntry, ConnectionId, DialOutcome, Ladder, NetworkAddress, NoSessions,
    Peerlist, Refusal, RefusedSet, SessionRow, Source, Tick, DISCLOSE_COUNT, DISCLOSE_WINDOW_NANOS,
    GRAY_CAP, SESSION_INTAKE_CAP, WHITE_REFILL_LINE,
};
use shekyl_transport_layer::Ipv4Subnet;

fn v4(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 2, (n >> 8) as u8, (n & 0xff) as u8),
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

fn session(n: u8) -> ConnectionId {
    ConnectionId([n; 16])
}

fn at_hours(h: u64) -> Tick {
    Tick::new(h * 60 * 60 * 1_000_000_000)
}

fn draw_until(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    let connector = Peerlist::connector_of(address).expect("served");
    for _ in 0..100_000 {
        match list.draw_gray(connector, rng) {
            Some(drawn) if drawn == *address => return,
            Some(other) => list.apply(
                &DialOutcome::PayloadRefused(other),
                at_hours(0),
                Ladder::Climb,
                rng,
            ),
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
            list.admit_gray(&a, Source::Operator, at_hours(0), rng),
            Ok(true)
        );
        draw_until(list, &a, rng);
        list.apply(
            &DialOutcome::Confirmed(a.clone()),
            at_hours(0),
            Ladder::Climb,
            rng,
        );
        made.push(a);
    }
    made
}

// ---------------------------------------------------------------- D3

#[test]
fn below_the_floor_the_sample_is_empty() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let floor = u16::try_from(white_diversity_floor()).expect("fits");
    with_white(&mut list, 1, floor - 1, &mut rng);
    assert!(list
        .disclose(connector, at_hours(1), &mut NoSessions, &mut rng)
        .is_empty());
    with_white(&mut list, 1000, 1, &mut rng);
    assert_eq!(
        list.disclose(connector, at_hours(1), &mut NoSessions, &mut rng)
            .len(),
        DISCLOSE_COUNT,
        "at the floor the sample is DISCLOSE_COUNT addresses"
    );
}

#[test]
fn the_sample_is_cached_for_the_window_and_redrawn_after_it() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    with_white(&mut list, 1, 100, &mut rng);
    let first = list.disclose(connector, at_hours(1), &mut NoSessions, &mut rng);
    assert_eq!(first.len(), DISCLOSE_COUNT);
    assert_eq!(
        first.iter().collect::<BTreeSet<_>>().len(),
        DISCLOSE_COUNT,
        "distinct"
    );
    for h in [2, 10, 23] {
        assert_eq!(
            list.disclose(connector, at_hours(h), &mut NoSessions, &mut rng),
            first,
            "every requester in the window gets the same sample, unchanged"
        );
    }
    // A kept session moves the clock, so white outlives its own 24-hour
    // expiry. A confirm-and-close would not. Then cross the window: 24 h
    // after the draw a new sample is drawn.
    for n in 1..=100 {
        list.apply(
            &DialOutcome::SessionAccepted(v4(n)),
            at_hours(23),
            Ladder::Climb,
            &mut rng,
        );
    }
    let later = list.disclose(
        connector,
        Tick::new(at_hours(1).get() + DISCLOSE_WINDOW_NANOS),
        &mut NoSessions,
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
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 59, &mut rng);
    let own = v4(9_999);
    assert_eq!(list.set_own_address(connector, Some(own.clone())), Ok(()));
    let mut own_seen = 0_u32;
    let mut each: Vec<u32> = vec![0; 59];
    let windows = 3_000_u32;
    for w in 0..windows {
        let now = Tick::new(u64::from(w) * DISCLOSE_WINDOW_NANOS + 1);
        // A kept session moves the clock. A confirm-and-close would let
        // white expire and the sample go empty.
        for a in &white {
            list.apply(
                &DialOutcome::SessionAccepted(a.clone()),
                now,
                Ladder::Climb,
                &mut rng,
            );
        }
        let sample = list.disclose(connector, now, &mut NoSessions, &mut rng);
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
fn own_address_must_belong_to_the_connector() {
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let clear = Peerlist::connector_of(&v4(1)).expect("served");
    let hidden = Peerlist::connector_of(&onion(1)).expect("served");
    // Refused before the partition stores it.
    assert_eq!(
        list.set_own_address(clear, Some(onion(1))),
        Err(Refusal::ForeignConnector)
    );
    assert!(!list.is_gray(&onion(1)) && !list.is_white(&onion(1)));
    assert_eq!(list.set_own_address(clear, Some(v4(9))), Ok(()));
    assert_eq!(list.set_own_address(clear, None), Ok(()));
    assert_eq!(list.set_own_address(hidden, Some(onion(2))), Ok(()));
    assert_eq!(
        list.set_own_address(hidden, Some(v4(9))),
        Err(Refusal::ForeignConnector)
    );
}

#[test]
fn a_received_list_longer_than_disclose_count_is_refused_whole() {
    let mut rng = SplitMix64::new(4);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let long: Vec<NetworkAddress> = (1..=13).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &long,
            SessionRow {
                id: session(1),
                connector
            },
            at_hours(0),
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
    assert_eq!(list.gray_count(connector), 0, "not trimmed and kept");
    let exact: Vec<NetworkAddress> = (1..=12).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &exact,
            SessionRow {
                id: session(1),
                connector
            },
            at_hours(0),
            &mut rng
        ),
        Ok(12)
    );
}

#[test]
fn the_sample_carries_no_gray_and_no_clock() {
    let mut rng = SplitMix64::new(5);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    with_white(&mut list, 1, 60, &mut rng);
    for n in 500..600 {
        assert_eq!(
            list.admit_gray(&v4(n), Source::Operator, at_hours(0), &mut rng),
            Ok(true)
        );
    }
    let sample = list.disclose(connector, at_hours(1), &mut NoSessions, &mut rng);
    assert!(
        sample.iter().all(|a| list.is_white(a)),
        "gray is never in the message"
    );
    // The value is a Vec<NetworkAddress>: there is no field for a clock.
    let _: &Vec<NetworkAddress> = &sample;
}

// ---------------------------------------------------------------- D4

#[test]
fn a_banned_white_entry_is_demoted_when_its_ban_arrives_and_the_floor_drops() {
    let mut rng = SplitMix64::new(6);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 50, &mut rng);
    assert_eq!(
        list.white_count(connector, at_hours(1), &mut NoSessions, &mut rng),
        50
    );
    let banned = white[7].clone();
    // The ban event demotes it to gray at once (Rick, 2026-10-31).
    assert_eq!(list.ban(BanEntry::Host(ip_of(&banned))), 1);
    assert_eq!(
        list.white_count(connector, at_hours(2), &mut NoSessions, &mut rng),
        49,
        "the floor count drops with it"
    );
    assert!(
        !list.is_white(&banned) && list.is_gray(&banned),
        "demoted to gray, not removed"
    );
    assert!(
        list.below_refill_line(connector, at_hours(2), &mut NoSessions, &mut rng)
            == (49 < WHITE_REFILL_LINE),
        "the refill line counts white as it stands"
    );
}

#[test]
fn a_demoted_entry_is_barred_evictable_never_drawn_and_refused_at_admission() {
    let mut rng = SplitMix64::new(7);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 10, &mut rng);
    let banned = white[3].clone();
    list.ban(BanEntry::Host(ip_of(&banned)));
    assert_eq!(
        list.white_count(connector, at_hours(1), &mut NoSessions, &mut rng),
        9
    );
    assert!(list.is_gray(&banned));
    // Never drawn while the ban holds: its seat is barred.
    assert!(list.is_banned(&banned));
    for _ in 0..200 {
        let drawn = list.draw_gray(connector, &mut rng);
        assert_ne!(drawn.as_ref(), Some(&banned), "a barred seat was drawn");
        if let Some(address) = drawn {
            list.release_draw(&address);
        }
    }
    // Refused at gray admission if gossiped back in.
    assert_eq!(
        list.admit_gray(
            &banned,
            Source::Session {
                id: session(1),
                connector
            },
            at_hours(2),
            &mut rng
        ),
        Err(Refusal::Banned)
    );
    // Evictable from gray with no protection: fill gray past the cap and
    // the barred entry is dropped at its share.
    let mut dropped = 0_u32;
    let trials = 5_u32;
    for seed in 0..trials {
        let mut rng = SplitMix64::new(100 + u64::from(seed));
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let white = with_white(&mut list, 1, 10, &mut rng);
        let banned = white[3].clone();
        list.ban(BanEntry::Host(ip_of(&banned)));
        assert_eq!(
            list.white_count(connector, at_hours(1), &mut NoSessions, &mut rng),
            9
        );
        // 20 000 evictions, each a uniform draw over about 5 000 entries:
        // the demoted one is hit with probability about 0.98 per trial.
        for n in 1000..1000 + 25_000u16 {
            let _admitted = list.admit_gray(&v4(n), Source::Reload, at_hours(1), &mut rng);
        }
        if !list.is_gray(&banned) {
            dropped += 1;
        }
    }
    assert!(dropped > 0, "an ordinary gray entry is evicted sometimes");
    // When the ban list's timer ends the ban, its lift frees the seat: it
    // is drawn, dialled, and re-earns white only through the normal door.
    assert_eq!(list.lift(BanEntry::Host(ip_of(&banned))), 1);
    assert!(!list.is_banned(&banned));
    assert!(list.is_gray(&banned));
    list.apply(
        &DialOutcome::Confirmed(banned.clone()),
        at_hours(11),
        Ladder::Climb,
        &mut rng,
    );
    assert!(!list.is_white(&banned), "not drawn: no promotion");
    draw_until(&mut list, &banned, &mut rng);
    list.apply(
        &DialOutcome::Confirmed(banned.clone()),
        at_hours(11),
        Ladder::Climb,
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
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let white = with_white(&mut list, 1, 60, &mut rng);
    let sample = list.disclose(connector, at_hours(1), &mut NoSessions, &mut rng);
    let in_sample = sample[0].clone();
    list.ban(BanEntry::Host(ip_of(&in_sample)));
    assert_eq!(
        list.disclose(connector, at_hours(2), &mut NoSessions, &mut rng),
        sample,
        "the cached sample is not rebuilt on a ban"
    );
    assert!(
        list.is_gray(&in_sample),
        "though the entry itself was demoted when its ban arrived"
    );
    let _ = white;
    // Tor: no bannable address. A ban entry is a host or an IPv4 subnet,
    // and the widest one covers no onion.
    let hidden = Peerlist::connector_of(&onion(1)).expect("served");
    let everything = Ipv4Subnet::new(Ipv4Addr::UNSPECIFIED, 0).expect("prefix 0");
    for n in 1..=3 {
        assert_eq!(
            list.admit_gray(&onion(n), Source::Operator, at_hours(0), &mut rng),
            Ok(true)
        );
        draw_until(&mut list, &onion(n), &mut rng);
        list.apply(
            &DialOutcome::Confirmed(onion(n)),
            at_hours(0),
            Ladder::Climb,
            &mut rng,
        );
    }
    list.ban(BanEntry::Subnet(everything));
    assert_eq!(
        list.white_count(hidden, at_hours(1), &mut NoSessions, &mut rng),
        3,
        "D7: Tor has no bannable address"
    );
}

// ---------------------------------------------------------------- D-S1

#[test]
fn the_twenty_fifth_distinct_address_from_one_session_in_a_day_is_a_violation() {
    let mut rng = SplitMix64::new(9);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let s = session(1);
    let first: Vec<NetworkAddress> = (1..=12).map(v4).collect();
    let second: Vec<NetworkAddress> = (13..=24).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &first,
            SessionRow { id: s, connector },
            at_hours(0),
            &mut rng
        ),
        Ok(12)
    );
    // The same sample again within the window counts once.
    assert_eq!(
        list.admit_received_list(
            &first,
            SessionRow { id: s, connector },
            at_hours(1),
            &mut rng
        ),
        Ok(0)
    );
    assert_eq!(list.intake_count(connector, s, at_hours(1)), 12);
    assert_eq!(
        list.admit_received_list(
            &second,
            SessionRow { id: s, connector },
            at_hours(12),
            &mut rng
        ),
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
            &mut rng
        ),
        Ok(true)
    );
    // The span is sliding: once the first twelve are a day old, room returns.
    // They are still gray, so offering them again is not a new charge.
    assert_eq!(list.intake_count(connector, s, at_hours(25)), 12);
    assert_eq!(
        list.admit_received_list(
            &first,
            SessionRow { id: s, connector },
            at_hours(25),
            &mut rng
        ),
        Ok(0),
        "still seated: a re-offer after the span is not a new gray entry"
    );
    assert_eq!(list.intake_count(connector, s, at_hours(25)), 12);
    assert_eq!(
        list.admit_gray(
            &v4(26),
            Source::Session { id: s, connector },
            at_hours(25),
            &mut rng
        ),
        Ok(true)
    );
    // Operator and reload sources are not capped.
    for n in 100..200 {
        assert_eq!(
            list.admit_gray(&v4(n), Source::Operator, at_hours(13), &mut rng),
            Ok(true)
        );
    }
    // A forgotten session starts over.
    list.forget_session(connector, s);
    assert_eq!(list.intake_count(connector, s, at_hours(25)), 0);
}

#[test]
fn a_seated_address_is_not_a_new_intake_charge() {
    let mut rng = SplitMix64::new(31);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let session_id = session(4);
    let white = with_white(&mut list, 1, 12, &mut rng);
    assert_eq!(
        list.admit_gray(
            &white[0],
            Source::Session {
                id: session_id,
                connector
            },
            at_hours(1),
            &mut rng
        ),
        Ok(false),
        "white already sits"
    );
    assert_eq!(
        list.intake_count(connector, session_id, at_hours(1)),
        0,
        "a seat the session did not open is not a charge"
    );
    // Two legal lists: a received list longer than DISCLOSE_COUNT is
    // refused whole, which is a different refusal from the intake cap.
    let first: Vec<NetworkAddress> = (100..112).map(v4).collect();
    let second: Vec<NetworkAddress> = (112..124).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &first,
            SessionRow {
                id: session_id,
                connector
            },
            at_hours(1),
            &mut rng
        ),
        Ok(DISCLOSE_COUNT)
    );
    assert_eq!(
        list.admit_received_list(
            &second,
            SessionRow {
                id: session_id,
                connector
            },
            at_hours(1),
            &mut rng
        ),
        Ok(DISCLOSE_COUNT)
    );
    assert_eq!(
        list.admit_received_list(
            &white,
            SessionRow {
                id: session_id,
                connector
            },
            at_hours(2),
            &mut rng
        ),
        Ok(0),
        "a session at the cap, offering only seated addresses, is not refused"
    );
    assert_eq!(
        list.intake_count(connector, session_id, at_hours(2)),
        SESSION_INTAKE_CAP
    );
    assert!(list.is_white(&white[0]) && !list.is_gray(&white[0]));
}

#[test]
fn the_intake_cap_is_the_same_on_every_connector() {
    let mut rng = SplitMix64::new(10);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
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
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
}

// ---------------------------------------------------------------- F1–F3 (Rick, 2026-10-09)

/// F1: a window's sample, once drawn, is served until the window ends;
/// the floor is checked only when drawing.
#[test]
fn a_drawn_sample_is_served_unchanged_when_white_drops_below_the_floor_mid_window() {
    let mut rng = SplitMix64::new(21);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let floor = u16::try_from(white_diversity_floor()).expect("fits");
    let white = with_white(&mut list, 1, floor, &mut rng);
    let sample = list.disclose(connector, at_hours(1), &mut NoSessions, &mut rng);
    assert_eq!(
        sample.len(),
        DISCLOSE_COUNT,
        "at the floor a sample is drawn"
    );
    // Mid-window, white drops below the floor: a ban demotes one entry
    // when it arrives.
    list.ban(BanEntry::Host(ip_of(&white[0])));
    assert_eq!(
        list.white_count(connector, at_hours(2), &mut NoSessions, &mut rng),
        white_diversity_floor() - 1
    );
    assert_eq!(
        list.disclose(connector, at_hours(3), &mut NoSessions, &mut rng),
        sample,
        "the reply is unchanged for the rest of the window"
    );
    assert_eq!(
        list.disclose(connector, at_hours(24), &mut NoSessions, &mut rng),
        sample,
        "to the window's last tick"
    );
    // At the next draw the floor is checked: still below it, nothing.
    // The kept sessions move the clock, so the empty sample is the floor
    // and not an expiry of every white address.
    for a in &white[1..] {
        list.apply(
            &DialOutcome::SessionAccepted(a.clone()),
            at_hours(24),
            Ladder::Climb,
            &mut rng,
        );
    }
    assert!(
        list.disclose(
            connector,
            Tick::new(at_hours(1).get() + DISCLOSE_WINDOW_NANOS),
            &mut NoSessions,
            &mut rng
        )
        .is_empty(),
        "a new window below the floor draws nothing"
    );
}

/// F2: the session cap is checked for the whole list before any entry is
/// admitted.
#[test]
fn a_list_that_would_cross_the_session_cap_admits_nothing() {
    let mut rng = SplitMix64::new(22);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    let s = session(7);
    let first: Vec<NetworkAddress> = (1..=12).map(v4).collect();
    let second: Vec<NetworkAddress> = (13..=20).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &first,
            SessionRow { id: s, connector },
            at_hours(0),
            &mut rng
        ),
        Ok(12)
    );
    assert_eq!(
        list.admit_received_list(
            &second,
            SessionRow { id: s, connector },
            at_hours(1),
            &mut rng
        ),
        Ok(8)
    );
    assert_eq!(list.intake_count(connector, s, at_hours(1)), 20);
    let before = list.gray_count(connector);
    // Twelve fresh addresses would take the session to 32: refused whole.
    let crossing: Vec<NetworkAddress> = (100..=111).map(v4).collect();
    assert_eq!(
        list.admit_received_list(
            &crossing,
            SessionRow { id: s, connector },
            at_hours(2),
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
    assert_eq!(list.gray_count(connector), before, "nothing was admitted");
    assert!(crossing.iter().all(|a| !list.is_gray(a)));
    assert_eq!(
        list.intake_count(connector, s, at_hours(2)),
        20,
        "and nothing was charged"
    );
    // Four fresh plus eight re-offers is exactly the cap: admitted.
    let mut exact: Vec<NetworkAddress> = (200..=203).map(v4).collect();
    exact.extend(second.iter().cloned());
    assert_eq!(
        list.admit_received_list(
            &exact,
            SessionRow { id: s, connector },
            at_hours(2),
            &mut rng
        ),
        Ok(4)
    );
    assert_eq!(
        list.intake_count(connector, s, at_hours(2)),
        SESSION_INTAKE_CAP
    );
    // A banned entry in a list is not counted against the cap.
    let banned = v4(300);
    list.ban(BanEntry::Host(ip_of(&banned)));
    assert_eq!(
        list.admit_received_list(
            &[banned],
            SessionRow { id: s, connector },
            at_hours(3),
            &mut rng
        ),
        Ok(0),
        "a banned entry is skipped, not a refusal of the list, and not charged"
    );
}

/// F3: an expiry demotion goes through the capped gray insert, so a mass
/// expiry leaves gray at or below its cap. A ban moves white straight to
/// barred gray with no eviction (Rick, 2026-11-01): gray sits over its cap
/// by those seats, at most the white cap, until the next gray insert
/// evicts it back.
#[test]
fn an_expiry_sweep_keeps_gray_at_its_cap_and_a_ban_sweep_until_the_next_insert() {
    let mut rng = SplitMix64::new(23);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let connector = Peerlist::connector_of(&v4(1)).expect("served");
    // 200 white, confirmed at hour 0.
    let white = with_white(&mut list, 1, 200, &mut rng);
    // Gray filled to its cap with reloaded addresses.
    for n in 10_000..10_000 + u16::try_from(GRAY_CAP).expect("fits") {
        let _admitted = list.admit_gray(&v4(n), Source::Reload, at_hours(0), &mut rng);
    }
    assert_eq!(list.gray_count(connector), GRAY_CAP);
    assert_eq!(
        list.white_count(connector, at_hours(1), &mut NoSessions, &mut rng),
        200
    );
    // The expiry sweep demotes all 200 into a full gray list.
    assert_eq!(
        list.white_count(connector, at_hours(25), &mut NoSessions, &mut rng),
        0
    );
    assert!(
        list.gray_count(connector) <= GRAY_CAP,
        "gray is at or below its cap after 200 demotions: {}",
        list.gray_count(connector)
    );
    assert_eq!(list.gray_count(connector), GRAY_CAP);
    let demoted_in_gray = white.iter().filter(|a| list.is_gray(a)).count();
    assert!(
        demoted_in_gray >= 190,
        "the demoted entries are the ones kept, bar the few a later demotion evicted: {demoted_in_gray}"
    );
    // A ban on every white host.
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let white = with_white(&mut list, 1, 200, &mut rng);
    for n in 10_000..10_000 + u16::try_from(GRAY_CAP).expect("fits") {
        let _admitted = list.admit_gray(&v4(n), Source::Reload, at_hours(0), &mut rng);
    }
    for a in &white {
        list.ban(BanEntry::Host(ip_of(a)));
    }
    assert_eq!(
        list.white_count(connector, at_hours(1), &mut NoSessions, &mut rng),
        0
    );
    // Every former white seat is barred gray and nothing was evicted: gray
    // is over its cap by the 200, which the white cap bounds.
    let barred = |list: &Peerlist| white.iter().filter(|a| list.is_gray(a)).count();
    assert_eq!(barred(&list), 200);
    assert!(white.iter().all(|a| list.is_banned(a)));
    assert_eq!(list.gray_count(connector), GRAY_CAP);
    // The next gray insert evicts back to the cap, barred seats first: they
    // cannot be dialled while the ban holds, and no peer can make a ban, so
    // the order cannot be steered. Red edit: evict uniformly over drawable,
    // cooling and barred seats alike.
    assert_eq!(
        list.admit_gray(&v4(9_999), Source::Reload, at_hours(1), &mut rng),
        Ok(true)
    );
    assert_eq!(barred(&list), 0, "every barred seat went first");
    assert_eq!(list.gray_count(connector), GRAY_CAP);
    assert!(list.is_gray(&v4(9_999)), "the address just admitted stays");
}

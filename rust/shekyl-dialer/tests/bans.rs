// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer applies the ban list's events (Rick, 2026-10-31): its
//! subscription starts with every entry in force, taken with the
//! registration under one hold of the table's lock, and then carries each
//! ban and lift in order. Every read of the lists drains it under the
//! dialer's lock (`Dialer::shared`): a ban bars the seats its entry covers,
//! a lift frees them.

#[path = "support/rig.rs"]
mod rig;
#[path = "support/tables.rs"]
mod tables;

use std::net::{IpAddr, Ipv4Addr};

use rig::{Build, Rig};
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{ConnectorId, NetworkAddress, Source, Tick};
use shekyl_timing_engine::ManualClock;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 16, 0, n),
        port: 18080,
    }
}

fn host(n: u8) -> IpAddr {
    peer(n).ip().expect("clearnet")
}

/// A rig whose dialer subscribed to `prepare`'s table state: the bans in
/// force at subscription are its seed.
fn rig_after(prepare: impl FnOnce(&shekyl_transport_layer::Sockets)) -> Rig {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    Rig::build_with(Build::on(&clock), prepare)
}

/// Every gray address the draw can reach now, sorted; each draw released.
fn drawable(rig: &Rig, rng: &mut SplitMix64) -> Vec<NetworkAddress> {
    let mut shared = rig.dialer.shared();
    let mut drawn = Vec::new();
    while let Some(address) = shared.lists.draw_gray(ConnectorId::Clearnet, rng) {
        drawn.push(address);
    }
    for address in &drawn {
        shared.lists.release_draw(address);
    }
    drawn.sort();
    drawn
}

/// A ban in force when the dialer subscribed and lifted before its first
/// read leaves the host admissible; a ban made after the subscription bars
/// its seat; its lift frees it. Red edits: do not register the queue in
/// `BanList::subscribe` (the seed is applied and the lift is lost, so the
/// door refuses the first host), or apply no queued event in
/// `Dialer::shared` (the later ban never bars).
#[test]
fn the_dialer_bars_what_the_ban_list_posts_and_frees_what_it_lifts() {
    let mut rng = SplitMix64::new(11);
    let rig = rig_after(|sockets| {
        assert!(sockets.ban_host_permanent(host(1)).is_empty());
    });
    let (sockets, dialer) = (&rig.sockets, &rig.dialer);
    assert!(
        sockets.lift_host(host(1)),
        "lifted after the seed was taken"
    );
    // Onto the lists as a reload puts them, through the lists' own door,
    // which refuses an address a held ban covers.
    for n in 1..=3 {
        let admitted =
            dialer
                .shared()
                .lists
                .admit_gray(&peer(n), Source::Reload, Tick::new(1), &mut rng);
        assert!(admitted.is_ok(), "{admitted:?}");
    }
    assert!(sockets.ban_host_permanent(host(2)).is_empty());
    assert_eq!(drawable(&rig, &mut rng), vec![peer(1), peer(3)]);

    assert!(sockets.lift_host(host(2)));
    assert_eq!(drawable(&rig, &mut rng), vec![peer(1), peer(2), peer(3)]);
}

/// Every read of the lists goes through `Dialer::shared`, which applies
/// the queued ban events first: a ban posted just before a read is in it,
/// with no owner loop draining and no other call between. Red edit: lock
/// the state in `shared` without applying the queue.
#[test]
fn a_ban_posted_just_before_a_read_is_in_it() {
    let mut rng = SplitMix64::new(12);
    let rig = rig_after(|_sockets| {});
    let (sockets, dialer) = (&rig.sockets, &rig.dialer);
    let admitted =
        dialer
            .shared()
            .lists
            .admit_gray(&peer(4), Source::Reload, Tick::new(1), &mut rng);
    assert!(admitted.is_ok(), "{admitted:?}");
    assert!(sockets.ban_host_permanent(host(4)).is_empty());
    assert!(dialer.shared().lists.is_banned(&peer(4)), "the ban is read");
    assert!(sockets.lift_host(host(4)));
    assert!(
        !dialer.shared().lists.is_banned(&peer(4)),
        "the lift is read"
    );
}

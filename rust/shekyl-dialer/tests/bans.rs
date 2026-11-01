// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer applies the ban list's events (Rick, 2026-10-31): its
//! subscription starts with every entry in force, taken with the
//! registration under one hold of the table's lock, and then carries each
//! ban and lift in order. The dialer drains it under its own lock: a ban
//! bars the seats its entry covers, a lift frees them.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use shekyl_dialer::Dialer;
use shekyl_draw_rng::SplitMix64;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, NetworkAddress, RefusedSet, Source, Tick};
use shekyl_seam::{Hub, SyncPayload};
use shekyl_timing_engine::ManualClock;
use shekyl_transport_layer::Sockets;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 16, 0, n),
        port: 18080,
    }
}

fn host(n: u8) -> IpAddr {
    peer(n).ip().expect("clearnet")
}

fn dialer_over(sockets: Sockets) -> Dialer {
    let hub = Hub::new(
        sockets,
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(ManualClock::new(Tick::new(1_000_000_000))),
    );
    Dialer::new(
        hub,
        RefusedSet::NON_GLOBAL,
        Arc::new(|| {
            Some(SyncPayload {
                current_height: 1,
                cumulative_difficulty: 1,
                cumulative_difficulty_top64: 0,
                top_id: [0; 32],
            })
        }),
    )
}

/// Every gray address the draw can reach now, sorted; each draw released.
fn drawable(dialer: &Dialer, rng: &mut SplitMix64) -> Vec<NetworkAddress> {
    let mut shared = dialer.shared();
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

/// A ban in force when the dialer subscribed, lifted before the dialer
/// first drains, frees its seat; a ban made after the subscription bars
/// its seat; its lift frees it. Red edits: do not register the queue in
/// `BanList::subscribe` (the seed is applied and the lift is lost, so the
/// first host stays barred), or drop the drain from `apply_completions`
/// (the later ban never bars).
#[test]
fn the_dialer_bars_what_the_ban_list_posts_and_frees_what_it_lifts() {
    let mut rng = SplitMix64::new(11);
    let sockets = Sockets::new();
    assert!(sockets.ban_host_permanent(host(1)).is_empty());
    let dialer = dialer_over(sockets.clone());
    // Onto the lists as a reload puts them, before the dialer first drains:
    // the dialer's door would refuse the banned host.
    for n in 1..=3 {
        let admitted =
            dialer
                .shared()
                .lists
                .admit_gray(&peer(n), Source::Reload, Tick::new(1), &mut rng);
        assert!(admitted.is_ok(), "{admitted:?}");
    }
    assert!(
        sockets.lift_host(host(1)),
        "lifted after the seed was taken"
    );
    assert!(sockets.ban_host_permanent(host(2)).is_empty());

    let _applied = dialer.apply_completions(ConnectorId::Clearnet, &mut rng);
    assert_eq!(drawable(&dialer, &mut rng), vec![peer(1), peer(3)]);

    assert!(sockets.lift_host(host(2)));
    let _applied = dialer.apply_completions(ConnectorId::Clearnet, &mut rng);
    assert_eq!(drawable(&dialer, &mut rng), vec![peer(1), peer(2), peer(3)]);
}

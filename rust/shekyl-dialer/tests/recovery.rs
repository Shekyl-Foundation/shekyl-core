// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Recovery (Rick, 2026-10-14): a connector whose wake finds no kept
//! session, nothing in flight and no drawable white or gray candidate
//! re-admits its configured addresses to gray as operator-named: the
//! compiled seeds and `--add-peer`, or, when a closed network is declared,
//! that list alone. The wake that re-admits dials nothing; the next draws.
//!
//! The hub here has no connector installed, so every dial fails at once
//! as a local close: the failed draw leaves gray, as a real failure does,
//! and a local close marks nothing in the failed-address memory.

use std::net::Ipv4Addr;
use std::sync::Arc;

use shekyl_dialer::{DialAim, Dialer};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::SupportFlags;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, ListName, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{Hub, SyncPayload};
use shekyl_timing_engine::ManualClock;
use shekyl_transport_layer::Sockets;

const CLEARNET: ConnectorId = ConnectorId::Clearnet;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 15, 0, n),
        port: 18080,
    }
}

fn dialer() -> Arc<Dialer> {
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(ManualClock::new(Tick::new(1))),
    );
    let dialer = Arc::new(Dialer::new(
        hub,
        RefusedSet::NON_GLOBAL,
        SupportFlags::ADVERTISED.bits(),
        Arc::new(|| {
            Some(SyncPayload {
                current_height: 1,
                cumulative_difficulty: 1,
                cumulative_difficulty_top64: 0,
                top_id: [0; 32],
            })
        }),
    ));
    dialer.set_network_id([7; 16]);
    dialer
}

/// The clearnet gray list, as addresses.
fn gray(dialer: &Dialer) -> Vec<NetworkAddress> {
    dialer
        .shared()
        .lists
        .snapshot()
        .into_iter()
        .filter(|(address, list)| {
            *list == ListName::Gray
                && shekyl_peerlist::Peerlist::connector_of(address) == Some(CLEARNET)
        })
        .map(|(address, _)| address)
        .collect()
}

/// Dial `address` once: with no connector it fails, and leaves gray.
fn fail_out(dialer: &Dialer, address: &NetworkAddress, rng: &mut SplitMix64) {
    assert!(
        gray(dialer).contains(address),
        "{address:?} is in gray to fail"
    );
    assert!(
        dialer.dial(CLEARNET, address, DialAim::Keep, rng).is_none(),
        "no connector: the dial fails at once"
    );
    assert!(!gray(dialer).contains(address), "{address:?} left gray");
}

#[test]
fn a_stranded_connector_re_admits_its_configured_addresses_and_dials() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(1);
    let named = peer(1);
    dialer
        .admit_operator(&named, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &named, &mut rng);
    assert!(gray(&dialer).is_empty(), "the failed draw left gray");

    // Stranded: this wake re-admits and dials nothing.
    assert!(dialer.choose(CLEARNET, &mut rng).is_none());
    assert_eq!(
        gray(&dialer),
        vec![named.clone()],
        "re-admitted as configured"
    );

    // The next wake draws it.
    let (drawn, _aim, _nonce) = dialer
        .choose(CLEARNET, &mut rng)
        .expect("a stranded connector dials what it re-admitted");
    assert_eq!(drawn, named);
}

#[test]
fn a_healthy_connector_does_not_re_admit_a_dead_add_peer() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(2);
    let dead = peer(1);
    dialer
        .admit_operator(&dead, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &dead, &mut rng);

    // A candidate is drawable, so the connector is not stranded.
    let live = peer(2);
    dialer
        .admit_operator(&live, Tick::new(1), &mut rng)
        .expect("admitted");
    let (drawn, _aim, _nonce) = dialer.choose(CLEARNET, &mut rng).expect("a draw");
    assert_eq!(drawn, live);
    assert!(
        !gray(&dialer).contains(&dead),
        "a healthy connector leaves a dead --add-peer out"
    );
}

#[test]
fn a_declared_closed_network_re_admits_only_its_list() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(3);
    // Named before the declaration, and failed out of gray.
    let outside = peer(9);
    dialer
        .admit_operator(&outside, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &outside, &mut rng);

    let population = vec![peer(1), peer(2)];
    dialer.set_exclusive(population.clone(), Tick::new(1), &mut rng);
    for address in &population {
        fail_out(&dialer, address, &mut rng);
    }
    assert!(gray(&dialer).is_empty());

    assert!(
        dialer.choose(CLEARNET, &mut rng).is_none(),
        "the stranded wake re-admits"
    );
    let mut readmitted = gray(&dialer);
    readmitted.sort();
    assert_eq!(
        readmitted, population,
        "the closed network's list, and not the address named outside it"
    );
}

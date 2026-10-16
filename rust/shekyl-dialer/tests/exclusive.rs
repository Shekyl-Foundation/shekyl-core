// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A closed network (`--add-exclusive-node`): the declared addresses are
//! the dialer's whole candidate population, and nothing else is drawn.
//! Not a dialer arm: the fill rules and the candidate filter still apply
//! inside the population.
//!
//! A draw begins an attempt, and one attempt is in flight per connector,
//! so each draw here is the first draw of a fresh dialer under its own
//! seed.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use shekyl_dialer::Dialer;
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::SupportFlags;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{Hub, SyncPayload};
use shekyl_timing_engine::ManualClock;
use shekyl_transport_layer::Sockets;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 14, 0, n),
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

/// The first draw of a fresh dialer under `seed`, after `prepare` set it
/// up: the gray list holds peers 1 to 6 as operator-named addresses.
fn first_draw(seed: u64, prepare: impl Fn(&Dialer, &mut SplitMix64)) -> Option<NetworkAddress> {
    let dialer = dialer();
    let mut rng = SplitMix64::new(seed);
    for n in 1..=6 {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    prepare(&dialer, &mut rng);
    dialer
        .choose(ConnectorId::Clearnet, &mut rng)
        .map(|(address, _aim, _nonce)| address)
}

/// The first draws of `rounds` fresh dialers.
fn drawn(rounds: u64, prepare: impl Fn(&Dialer, &mut SplitMix64)) -> BTreeSet<NetworkAddress> {
    (1..=rounds)
        .filter_map(|seed| first_draw(seed, &prepare))
        .collect()
}

#[test]
fn with_no_population_declared_every_named_address_can_be_drawn() {
    let drawn = drawn(40, |_dialer, _rng| {});
    assert!(
        drawn.len() > 1,
        "the control: an open network draws from more than one address, drew {drawn:?}"
    );
    assert!(drawn.iter().all(|a| (1..=6).any(|n| *a == peer(n))));
}

#[test]
fn a_declared_population_is_the_only_source_of_draws() {
    let drawn = drawn(40, |dialer, rng| {
        dialer.set_exclusive(vec![peer(7), peer(8)], Tick::new(1), rng);
    });
    assert_eq!(
        drawn,
        [peer(7), peer(8)].into_iter().collect(),
        "every draw is a declared address, and both are drawn"
    );
}

#[test]
fn declaring_the_population_seats_its_addresses_in_gray() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(1);
    assert!(!dialer.shared().lists.is_gray(&peer(9)));
    dialer.set_exclusive(vec![peer(9)], Tick::new(1), &mut rng);
    assert!(dialer.shared().lists.is_gray(&peer(9)));
    assert!(!dialer.shared().lists.is_white(&peer(9)));
}

#[test]
fn the_candidate_filter_still_applies_inside_the_population() {
    let declared = drawn(10, |dialer, rng| {
        dialer.set_exclusive(vec![peer(7)], Tick::new(1), rng);
    });
    assert_eq!(declared, [peer(7)].into_iter().collect());
    // Our own address is never a candidate, declared or not: with the one
    // declared address ours, nothing is drawn, and the six gray addresses
    // outside the population do not fill in.
    let own = drawn(10, |dialer, rng| {
        dialer.set_exclusive(vec![peer(7)], Tick::new(1), rng);
        dialer.set_own_addresses(ConnectorId::Clearnet, vec![peer(7)]);
    });
    assert!(own.is_empty(), "drew {own:?}");
}

/// One owner loop per connector. The ephemeral-tor listen and the
/// proxy-only zone branch both asked for Tor's loop on the same boot
/// (2026-10-13, the §4 run: two `p2p-dial-tor` threads), so the claim is
/// the dialer's: the first start takes it, a second finds it taken and
/// starts nothing, and one connector's claim says nothing about another's.
#[test]
fn a_connector_has_one_owner_loop() {
    let dialer = dialer();
    assert!(
        dialer.claim_owner(ConnectorId::Tor),
        "the first start claims it"
    );
    assert!(
        !dialer.claim_owner(ConnectorId::Tor),
        "a second start finds the loop claimed"
    );
    assert!(
        dialer.claim_owner(ConnectorId::Clearnet),
        "another connector's loop is its own claim"
    );
    assert!(!dialer.claim_owner(ConnectorId::Clearnet));
}

/// An empty declaration is no declaration. The C++ option parser calls
/// the declaration on every boot, with an empty list when no exclusive
/// node was named; read as a population of nothing, it held every dial
/// of every daemon (found by the §4 run, 2026-10-13). Empty opens the
/// population; it also reopens one declared earlier.
#[test]
fn an_empty_declaration_is_no_closed_network() {
    let open = first_draw(3, |dialer, rng| {
        for n in 1..=6 {
            dialer
                .admit_operator(&peer(n), Tick::new(1), rng)
                .expect("named");
        }
        dialer.set_exclusive(Vec::new(), Tick::new(1), rng);
    });
    assert!(open.is_some(), "an empty declaration holds nothing back");
    let reopened = drawn(64, |dialer, rng| {
        for n in 1..=6 {
            dialer
                .admit_operator(&peer(n), Tick::new(1), rng)
                .expect("named");
        }
        dialer.set_exclusive(vec![peer(9)], Tick::new(1), rng);
        dialer.set_exclusive(Vec::new(), Tick::new(1), rng);
    });
    assert!(
        reopened.iter().any(|address| *address != peer(9)),
        "the population is open again after an empty declaration: {reopened:?}"
    );
}

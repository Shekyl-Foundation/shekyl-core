// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PWD-I2: peerlist records are accepted only on sessions this node
//! initiated.
//!
//! A peer that connects to us chooses to connect and chooses what it
//! says. If its list entered gray, connecting would be a way to fill our
//! gray list (Shi et al. §III-A). A list on an inbound session admits
//! nothing. It is also not a refusal: the peer is not scored or closed
//! for it, whatever the list holds.

use std::net::Ipv4Addr;

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    ConnectionId, ConnectorId, Direction, NetworkAddress, NoBans, Peerlist, Refusal, RefusedSet,
    SessionRow, Source, Tick, DISCLOSE_COUNT,
};

fn now() -> Tick {
    Tick::new(0)
}

fn session() -> ConnectionId {
    ConnectionId([3; 16])
}

fn global(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 5, 0, n),
        port: 18080,
    }
}

fn receive(
    list: &mut Peerlist,
    addresses: &[NetworkAddress],
    direction: Direction,
    rng: &mut SplitMix64,
) -> Result<usize, Refusal> {
    list.admit_received_list(
        addresses,
        SessionRow {
            id: session(),
            connector: ConnectorId::Clearnet,
            direction,
        },
        now(),
        &mut NoBans,
        rng,
    )
}

#[test]
fn a_peerlist_received_on_an_inbound_session_admits_nothing() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let good: Vec<NetworkAddress> = (1..=10).map(global).collect();

    assert_eq!(
        receive(&mut list, &good, Direction::Inbound, &mut rng),
        Ok(0)
    );
    assert_eq!(list.gray_count(ConnectorId::Clearnet), 0);
    assert_eq!(
        list.intake_count(ConnectorId::Clearnet, session(), now()),
        0,
        "nothing is charged to the session either"
    );

    // The control: the same list on a session this node opened is admitted.
    assert_eq!(
        receive(&mut list, &good, Direction::Outbound, &mut rng),
        Ok(10)
    );
    assert_eq!(list.gray_count(ConnectorId::Clearnet), 10);
}

#[test]
fn an_inbound_list_is_never_a_refusal_whatever_it_holds() {
    let mut rng = SplitMix64::new(2);
    let too_long: Vec<NetworkAddress> = (0..=u8::try_from(DISCLOSE_COUNT).expect("small"))
        .map(global)
        .collect();
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 1, 1),
        port: 18080,
    };
    let onion = NetworkAddress::Tor {
        host: format!("{:0>56}.onion", 1),
        port: 18080,
    };
    for (bad, why) in [
        (too_long, "longer than DISCLOSE_COUNT"),
        (vec![global(1), private], "a non-global entry"),
        (vec![global(1), onion], "a foreign-connector entry"),
    ] {
        // Each is a refusal on an outbound session, so the inbound answer
        // below is PWD-I2's and not the list being acceptable.
        let mut outbound = Peerlist::new(RefusedSet::NON_GLOBAL);
        assert!(
            receive(&mut outbound, &bad, Direction::Outbound, &mut rng).is_err(),
            "{why}: refused on an outbound session"
        );

        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        assert_eq!(
            receive(&mut list, &bad, Direction::Inbound, &mut rng),
            Ok(0),
            "{why}: admits nothing and is not a refusal"
        );
        assert_eq!(list.gray_count(ConnectorId::Clearnet), 0, "{why}");
    }
}

#[test]
fn one_address_from_an_inbound_session_is_refused_at_the_door() {
    let mut rng = SplitMix64::new(3);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let inbound = Source::Session {
        id: session(),
        connector: ConnectorId::Clearnet,
        direction: Direction::Inbound,
    };
    assert_eq!(
        list.admit_gray(&global(1), inbound, now(), &mut NoBans, &mut rng),
        Err(Refusal::InboundSession)
    );
    assert!(!list.is_gray(&global(1)));
    assert_eq!(
        list.intake_count(ConnectorId::Clearnet, session(), now()),
        0
    );
}

// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every peerlist exchange is an exchange (Rick, 2026-10-13, PR-3 brief
//! §2.5): a received list is admitted on any session, inbound or
//! outbound, under the limits that bind every session — D3, D-S1, address
//! validity and R4, the foreign-connector rule. *Records-was* PWD-I2's
//! direction rule, under which a list on an inbound session admitted
//! nothing: it made discovery circular, since a node's own address
//! travels only in its own sample, and that sample was accepted only by
//! peers that had already dialled it. Reopen: §99 PM-2a.

use std::net::Ipv4Addr;

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    white_diversity_floor, ConnectionId, ConnectorId, DialOutcome, NetworkAddress, NoBans,
    Peerlist, Refusal, RefusedSet, SessionRow, Source, Tick, DISCLOSE_COUNT, SESSION_INTAKE_CAP,
};

fn now() -> Tick {
    Tick::new(0)
}

/// The disclosure count as an address index.
fn count() -> u8 {
    u8::try_from(DISCLOSE_COUNT).expect("small")
}

fn session(n: u8) -> ConnectionId {
    ConnectionId([n; 16])
}

fn global(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 8, 0, n),
        port: 18080,
    }
}

fn receive(
    list: &mut Peerlist,
    addresses: &[NetworkAddress],
    session: ConnectionId,
    rng: &mut SplitMix64,
) -> Result<usize, Refusal> {
    list.admit_received_list(
        addresses,
        SessionRow {
            id: session,
            connector: ConnectorId::Clearnet,
        },
        now(),
        &mut NoBans,
        rng,
    )
}

/// The session's direction is not an input: the row carries none, so the
/// same call stands for a session the peer opened and one this node did.
#[test]
fn a_list_received_on_an_inbound_session_is_admitted_under_the_same_limits() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let full: Vec<_> = (1..=count()).map(global).collect();
    assert_eq!(
        receive(&mut list, &full, session(1), &mut rng),
        Ok(DISCLOSE_COUNT)
    );
    for address in &full {
        assert!(list.is_gray(address));
        assert!(
            !list.is_white(address),
            "white only through this node's own dials"
        );
    }
    // D3 binds it: one over the count refuses the whole list.
    let over: Vec<_> = (20..=20 + count()).map(global).collect();
    assert_eq!(
        receive(&mut list, &over, session(2), &mut rng),
        Err(Refusal::PeerlistRefused)
    );
    assert!(over.iter().all(|a| !list.is_gray(a)));
    // R4 binds it: one non-global entry refuses the whole list.
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 1, 1),
        port: 18080,
    };
    assert_eq!(
        receive(
            &mut list,
            &[global(40), private, global(41)],
            session(3),
            &mut rng
        ),
        Err(Refusal::PeerlistRefused)
    );
    assert!(!list.is_gray(&global(40)));
    // The foreign-connector rule binds it.
    let onion = NetworkAddress::Tor {
        host: format!("{:0>56}.onion", 1),
        port: 18080,
    };
    assert_eq!(
        receive(&mut list, &[global(42), onion], session(4), &mut rng),
        Err(Refusal::ForeignConnector)
    );
    // One address at the door, from a session, the same way.
    assert_eq!(
        list.admit_gray(
            &global(50),
            Source::Session {
                id: session(5),
                connector: ConnectorId::Clearnet,
            },
            now(),
            &mut NoBans,
            &mut rng,
        ),
        Ok(true)
    );
}

/// D-S1 is what bounds a session now that direction does not: the 25th
/// distinct address from one session within 24 hours is a refusal, and
/// the list that would carry it admits nothing.
#[test]
fn the_25th_distinct_address_from_one_session_in_24_hours_is_refused() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    assert_eq!(SESSION_INTAKE_CAP, 24);
    let first: Vec<_> = (1..=count()).map(global).collect();
    let second: Vec<_> = (13..=24).map(global).collect();
    assert_eq!(
        receive(&mut list, &first, session(1), &mut rng),
        Ok(DISCLOSE_COUNT)
    );
    assert_eq!(
        receive(&mut list, &second, session(1), &mut rng),
        Ok(DISCLOSE_COUNT)
    );
    // The 24 already seen are not a new charge; a 25th is.
    assert_eq!(receive(&mut list, &second, session(1), &mut rng), Ok(0));
    assert_eq!(
        receive(&mut list, &[global(25)], session(1), &mut rng),
        Err(Refusal::PeerlistRefused)
    );
    assert!(!list.is_gray(&global(25)));
    // A list carrying the 25th admits none of its others either (F2).
    assert_eq!(
        receive(&mut list, &[global(26), global(27)], session(1), &mut rng),
        Err(Refusal::PeerlistRefused)
    );
    assert!(!list.is_gray(&global(26)));
    // Another session has its own cap.
    assert_eq!(
        receive(&mut list, &[global(25)], session(2), &mut rng),
        Ok(1)
    );
}

/// Discovery: a node's own address, set and present in its sample, enters
/// the lists of a peer that has never dialled it — the peer received the
/// sample on a session the node opened to it. Under the retired direction
/// rule this list admitted nothing, and a node named to no one stayed
/// unknown.
#[test]
fn a_nodes_own_address_in_its_sample_enters_a_peer_that_never_dialled_it() {
    let mut rng = SplitMix64::new(3);
    const C: ConnectorId = ConnectorId::Tor;
    let onion = |n: u16| NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
        port: 18080,
    };
    // The sender: white at the floor, its own onion set.
    let mut sender = Peerlist::new(RefusedSet::NON_GLOBAL);
    for n in 0..u16::try_from(white_diversity_floor()).expect("small") {
        sender
            .admit_gray(&onion(n), Source::Operator, now(), &mut NoBans, &mut rng)
            .expect("admitted");
    }
    while let Some(drawn) = sender.draw_gray(C, &mut rng) {
        sender.apply(&DialOutcome::Confirmed(drawn), now(), &mut rng);
    }
    let own = onion(9_000);
    sender.set_own_address(C, Some(own.clone())).expect("set");
    // A sample that holds the own address; the sender dials the receiver,
    // so the receiver sees the list on a session it did not open.
    let mut sample;
    let mut seed = 10;
    loop {
        let mut rng_sample = SplitMix64::new(seed);
        let mut fresh = Peerlist::new(RefusedSet::NON_GLOBAL);
        for n in 0..u16::try_from(white_diversity_floor()).expect("small") {
            fresh
                .admit_gray(
                    &onion(n),
                    Source::Operator,
                    now(),
                    &mut NoBans,
                    &mut rng_sample,
                )
                .expect("admitted");
        }
        while let Some(drawn) = fresh.draw_gray(C, &mut rng_sample) {
            fresh.apply(&DialOutcome::Confirmed(drawn), now(), &mut rng_sample);
        }
        fresh.set_own_address(C, Some(own.clone())).expect("set");
        sample = fresh.disclose(C, now(), &mut NoBans, &mut rng_sample);
        if sample.contains(&own) {
            break;
        }
        seed += 1;
        assert!(seed < 200, "a sample holding the own address is drawn");
    }
    let mut receiver = Peerlist::new(RefusedSet::NON_GLOBAL);
    assert!(!receiver.is_gray(&own));
    let admitted = receiver
        .admit_received_list(
            &sample,
            SessionRow {
                id: session(7),
                connector: C,
            },
            now(),
            &mut NoBans,
            &mut rng,
        )
        .expect("admitted");
    assert_eq!(admitted, sample.len());
    assert!(
        receiver.is_gray(&own),
        "the sender is now known to a peer it dialled"
    );
    assert!(
        !receiver.is_white(&own),
        "known, not confirmed: white is the receiver's own dial"
    );
}

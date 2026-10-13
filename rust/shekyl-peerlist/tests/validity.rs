// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Address validity: `P2P_3_SLICE_1_PEERLIST_BRIEF.md` §2 and §11.6.
//!
//! A network-learned address in the refused set is refused at the door,
//! and a received list that carries one is refused whole (R4). The same
//! address named by the operator is admitted, is never disclosed, and is
//! never written to the file. `--allow-local-ip` is the empty set, and it
//! lifts all of that together.
//!
//! The refused addresses are enumerated from `REFUSED_V4` and
//! `REFUSED_V6`, the tables the check reads.

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    white_diversity_floor, ConnectionId, ConnectorId, DialOutcome, Direction, NetworkAddress,
    NoBans, Peerlist, RangeV4, RangeV6, Refusal, RefusedSet, SessionRow, Source, Tick,
    DISCLOSE_COUNT, REFUSED_V4, REFUSED_V6,
};

const PORT: u16 = 18080;

fn now() -> Tick {
    Tick::new(0)
}

fn session() -> ConnectionId {
    ConnectionId([7; 16])
}

fn clearnet_session() -> Source {
    Source::Session {
        id: session(),
        connector: ConnectorId::Clearnet,
        direction: Direction::Outbound,
    }
}

fn tor_session() -> Source {
    Source::Session {
        id: session(),
        connector: ConnectorId::Tor,
        direction: Direction::Outbound,
    }
}

/// A global IPv4 address, distinct per `n`.
fn global(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 3, (n >> 8) as u8, (n & 0xff) as u8),
        port: PORT,
    }
}

fn onion(port: u16) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{:0>56}.onion", 1),
        port,
    }
}

/// The first address of a range and the last one.
fn ends_v4(range: &RangeV4) -> [Ipv4Addr; 2] {
    let base = u32::from_be_bytes(range.base);
    let span = u32::MAX.checked_shr(u32::from(range.prefix)).unwrap_or(0);
    [Ipv4Addr::from(base), Ipv4Addr::from(base | span)]
}

fn ends_v6(range: &RangeV6) -> [Ipv6Addr; 2] {
    let base = u128::from_be_bytes(range.base);
    let span = u128::MAX.checked_shr(u32::from(range.prefix)).unwrap_or(0);
    [Ipv6Addr::from(base), Ipv6Addr::from(base | span)]
}

/// Every refused clearnet address the tests offer: both ends of every
/// table range, port 0 on a global address of each family, and the named
/// cases of §11.6. Each carries the reason a failure message prints.
fn refused_clearnet() -> Vec<(NetworkAddress, String)> {
    // Rule 47: an empty table would make every loop below pass over nothing.
    assert!(!REFUSED_V4.is_empty(), "REFUSED_V4 is the check's table");
    assert!(!REFUSED_V6.is_empty(), "REFUSED_V6 is the check's table");
    let mut out = Vec::new();
    for range in REFUSED_V4 {
        for ip in ends_v4(range) {
            out.push((
                NetworkAddress::Ipv4 { ip, port: PORT },
                range.name.to_owned(),
            ));
        }
    }
    for range in REFUSED_V6 {
        for ip in ends_v6(range) {
            out.push((
                NetworkAddress::Ipv6 { ip, port: PORT },
                range.name.to_owned(),
            ));
        }
    }
    let named: [(NetworkAddress, &str); 6] = [
        (
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(11, 3, 0, 1),
                port: 0,
            },
            "port 0 on a global IPv4",
        ),
        (
            NetworkAddress::Ipv6 {
                ip: "2a00:1450::1".parse().expect("v6"),
                port: 0,
            },
            "port 0 on a global IPv6",
        ),
        (
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(198, 19, 0, 1),
                port: PORT,
            },
            "IPv4 benchmarking",
        ),
        (
            NetworkAddress::Ipv6 {
                ip: "2001:2::1".parse().expect("v6"),
                port: PORT,
            },
            "IPv6 benchmarking",
        ),
        (
            NetworkAddress::Ipv6 {
                ip: Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped(),
                port: PORT,
            },
            "IPv4-mapped private",
        ),
        (
            NetworkAddress::Ipv6 {
                ip: Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped(),
                port: PORT,
            },
            "IPv4-mapped public",
        ),
    ];
    out.extend(named.into_iter().map(|(a, why)| (a, why.to_owned())));
    out
}

/// Put `address` in white the only way there is: an operator admit, the
/// uniform gray draw, and a kept session.
fn promote(list: &mut Peerlist, address: &NetworkAddress, rng: &mut SplitMix64) {
    assert_eq!(
        list.admit_gray(address, Source::Operator, now(), &mut NoBans, rng),
        Ok(true),
        "{address:?}"
    );
    let connector = Peerlist::connector_of(address).expect("served");
    loop {
        let drawn = list.draw_gray(connector, rng).expect("gray holds it");
        if drawn == *address {
            break;
        }
        list.apply(&DialOutcome::PayloadRefused(drawn), now(), rng);
    }
    list.apply(&DialOutcome::SessionAccepted(address.clone()), now(), rng);
    assert!(list.is_white(address), "{address:?} is white");
}

/// White at the floor with global addresses, plus `extra`.
fn white_list(refused: RefusedSet, extra: &NetworkAddress, rng: &mut SplitMix64) -> Peerlist {
    let mut list = Peerlist::new(refused);
    for n in 0..u16::try_from(white_diversity_floor()).expect("small") {
        promote(&mut list, &global(n), rng);
    }
    promote(&mut list, extra, rng);
    list
}

#[test]
fn a_network_learned_address_in_the_refused_set_is_refused_at_the_door() {
    let mut rng = SplitMix64::new(1);
    for (address, why) in refused_clearnet() {
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        assert_eq!(
            list.admit_gray(&address, clearnet_session(), now(), &mut NoBans, &mut rng),
            Err(Refusal::NotGlobal),
            "{why}: {address:?}"
        );
        assert!(!list.is_gray(&address), "{why}: nothing entered gray");
        assert_eq!(
            list.intake_count(ConnectorId::Clearnet, session(), now()),
            0,
            "{why}: a refused address is not an intake charge"
        );
    }
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    assert_eq!(
        list.admit_gray(&onion(0), tor_session(), now(), &mut NoBans, &mut rng),
        Err(Refusal::NotGlobal),
        "port 0 on an onion address"
    );
    assert_eq!(
        list.admit_gray(&onion(PORT), tor_session(), now(), &mut NoBans, &mut rng),
        Ok(true),
        "an onion address with a port is not in the set"
    );
}

#[test]
fn the_address_beside_each_private_range_is_admitted() {
    let mut rng = SplitMix64::new(2);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    for ip in [
        [9, 255, 255, 255],
        [11, 0, 0, 0],
        [100, 63, 255, 255],
        [100, 128, 0, 0],
        [172, 15, 255, 255],
        [172, 32, 0, 0],
        [192, 167, 255, 255],
        [192, 169, 0, 0],
        [198, 17, 255, 255],
        [198, 20, 0, 0],
        [223, 255, 255, 255],
    ] {
        let address = NetworkAddress::Ipv4 {
            ip: Ipv4Addr::from(ip),
            port: PORT,
        };
        // Operator-free: a session offer, one address per session so the
        // intake cap is not what answers.
        let source = Source::Session {
            id: ConnectionId([
                ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            connector: ConnectorId::Clearnet,
            direction: Direction::Outbound,
        };
        assert_eq!(
            list.admit_gray(&address, source, now(), &mut NoBans, &mut rng),
            Ok(true),
            "{address:?} is global"
        );
    }
    let v6 = NetworkAddress::Ipv6 {
        ip: "2a00:1450::1".parse().expect("v6"),
        port: PORT,
    };
    assert_eq!(
        list.admit_gray(&v6, clearnet_session(), now(), &mut NoBans, &mut rng),
        Ok(true)
    );
}

#[test]
fn one_refused_entry_refuses_the_whole_received_list() {
    let mut rng = SplitMix64::new(3);
    for (bad, why) in refused_clearnet() {
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let received = vec![global(1), global(2), bad, global(3)];
        assert_eq!(
            list.admit_received_list(
                &received,
                SessionRow {
                    id: session(),
                    connector: ConnectorId::Clearnet,
                    direction: Direction::Outbound
                },
                now(),
                &mut NoBans,
                &mut rng
            ),
            Err(Refusal::PeerlistRefused),
            "{why}"
        );
        assert_eq!(
            list.gray_count(ConnectorId::Clearnet),
            0,
            "{why}: none of the list's global entries were admitted"
        );
    }
}

#[test]
fn the_operator_may_name_a_refused_address() {
    let mut rng = SplitMix64::new(4);
    for (address, why) in refused_clearnet() {
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        assert_eq!(
            list.admit_gray(&address, Source::Operator, now(), &mut NoBans, &mut rng),
            Ok(true),
            "{why}: {address:?}"
        );
        assert!(list.is_gray(&address));
    }
}

#[test]
fn a_refused_address_in_white_is_never_disclosed() {
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 1, 1),
        port: PORT,
    };
    // Unfiltered, the private address would be in about one sample in
    // five (12 of 49), so 200 seeds separate the two outcomes.
    for seed in 0..200 {
        let mut rng = SplitMix64::new(seed);
        let mut list = white_list(RefusedSet::NON_GLOBAL, &private, &mut rng);
        let sample = list.disclose(ConnectorId::Clearnet, now(), &mut NoBans, &mut rng);
        assert_eq!(sample.len(), DISCLOSE_COUNT, "seed {seed}: a full sample");
        assert!(
            !sample.contains(&private),
            "seed {seed}: the private address was disclosed"
        );
        assert!(
            sample
                .iter()
                .all(|a| RefusedSet::NON_GLOBAL.refuses(a).is_none()),
            "seed {seed}: every disclosed address is global"
        );
    }
}

#[test]
fn a_refused_own_address_is_never_disclosed() {
    let own = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(10, 0, 0, 9),
        port: PORT,
    };
    for seed in 0..200 {
        let mut rng = SplitMix64::new(seed);
        let mut list = white_list(RefusedSet::NON_GLOBAL, &global(9000), &mut rng);
        list.set_own_address(ConnectorId::Clearnet, Some(own.clone()))
            .expect("clearnet address");
        let sample = list.disclose(ConnectorId::Clearnet, now(), &mut NoBans, &mut rng);
        assert!(!sample.contains(&own), "seed {seed}");
    }
}

#[test]
fn allow_local_ip_admits_the_session_offer_and_discloses_it() {
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 1, 1),
        port: PORT,
    };
    let mut rng = SplitMix64::new(5);
    for (address, why) in refused_clearnet() {
        let mut list = Peerlist::new(RefusedSet::EMPTY);
        assert_eq!(
            list.admit_gray(&address, clearnet_session(), now(), &mut NoBans, &mut rng),
            Ok(true),
            "{why}: admitted under the empty set"
        );
    }
    let mut list = Peerlist::new(RefusedSet::EMPTY);
    assert_eq!(
        list.admit_received_list(
            &[global(1), private.clone()],
            SessionRow {
                id: session(),
                connector: ConnectorId::Clearnet,
                direction: Direction::Outbound
            },
            now(),
            &mut NoBans,
            &mut rng
        ),
        Ok(2)
    );
    let disclosed = (0..200).any(|seed| {
        let mut rng = SplitMix64::new(seed);
        let mut list = white_list(RefusedSet::EMPTY, &private, &mut rng);
        list.disclose(ConnectorId::Clearnet, now(), &mut NoBans, &mut rng)
            .contains(&private)
    });
    assert!(disclosed, "the private address appears in a sample");
}

#[test]
fn the_file_holds_no_refused_address_and_restore_refuses_one() {
    let mut rng = SplitMix64::new(6);
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(10, 0, 0, 5),
        port: PORT,
    };

    // Operator-named, so it is in the lists; the file still leaves it out.
    let mut strict = Peerlist::new(RefusedSet::NON_GLOBAL);
    for address in [global(1), private.clone()] {
        strict
            .admit_gray(&address, Source::Operator, now(), &mut NoBans, &mut rng)
            .expect("operator");
    }
    assert_eq!(strict.persistable(), vec![global(1)]);

    // Under the flag it is written.
    let mut open = Peerlist::new(RefusedSet::EMPTY);
    for address in [global(1), private.clone()] {
        open.admit_gray(&address, Source::Operator, now(), &mut NoBans, &mut rng)
            .expect("operator");
    }
    let mut file = open.persistable();
    file.sort_by_key(|a| format!("{a:?}"));
    assert_eq!(file.len(), 2);
    assert!(file.contains(&private));

    // That file does not seed a node started without the flag.
    let mut restarted = Peerlist::new(RefusedSet::NON_GLOBAL);
    assert_eq!(restarted.restore(file.clone(), &mut rng), 1);
    assert!(restarted.is_gray(&global(1)));
    assert!(!restarted.is_gray(&private));

    // With the flag it round-trips whole.
    let mut reopened = Peerlist::new(RefusedSet::EMPTY);
    assert_eq!(reopened.restore(file, &mut rng), 2);
    assert!(reopened.is_gray(&private));
}

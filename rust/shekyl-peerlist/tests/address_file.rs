// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The address file: `P2P_3_SLICE_1_PEERLIST_BRIEF.md` §7.
//!
//! It round-trips the set of addresses and nothing else, so a restart
//! puts every address on gray. A file this build cannot read is dropped
//! whole.

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::address_file::{
    decode, encode, AddressFileError, ADDRESS_FILE_MAGIC, ADDRESS_FILE_VERSION, MAX_ENTRIES,
};
use shekyl_peerlist::{
    ConnectorId, DialOutcome, NetworkAddress, NoBans, Peerlist, RefusedSet, Source, Tick,
};

fn now() -> Tick {
    Tick::new(0)
}

fn v4(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 4, 0, n),
        port: 18080,
    }
}

fn v6(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv6 {
        ip: Ipv6Addr::new(0x2a00, 0x1450, 0, 0, 0, 0, 0, n),
        port: 18080,
    }
}

fn onion(n: u8) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
        port: 18080,
    }
}

fn mixed() -> Vec<NetworkAddress> {
    vec![v4(1), onion(1), v6(1), v4(2), onion(2), v6(2)]
}

fn sorted(mut addresses: Vec<NetworkAddress>) -> Vec<NetworkAddress> {
    addresses.sort_by_key(|a| format!("{a:?}"));
    addresses
}

/// A header for `version` declaring `count` entries, with no entries.
fn header(version: u32, count: u32) -> Vec<u8> {
    let mut out = ADDRESS_FILE_MAGIC.to_vec();
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out
}

#[test]
fn the_file_round_trips_the_set_of_addresses() {
    let decoded = decode(&encode(&mixed())).expect("this build's file");
    assert_eq!(sorted(decoded), sorted(mixed()));
    assert_eq!(
        decode(&encode(&[])),
        Ok(Vec::new()),
        "an empty set is a file"
    );
}

#[test]
fn the_bytes_do_not_depend_on_the_order_or_on_duplicates() {
    let forward = encode(&mixed());
    let mut reversed = mixed();
    reversed.reverse();
    assert_eq!(encode(&reversed), forward);
    let mut doubled = mixed();
    doubled.extend(mixed());
    assert_eq!(encode(&doubled), forward);
}

#[test]
fn a_restart_puts_every_address_on_gray() {
    let mut rng = SplitMix64::new(1);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    for address in mixed() {
        list.admit_gray(&address, Source::Operator, now(), &mut NoBans, &mut rng)
            .expect("admitted");
    }
    // One address reaches white, the only way there is.
    let white = loop {
        let drawn = list
            .draw_gray(ConnectorId::Clearnet, &mut rng)
            .expect("gray");
        if drawn == v4(1) {
            break drawn;
        }
        list.apply(&DialOutcome::PayloadRefused(drawn), now(), &mut rng);
    };
    list.apply(
        &DialOutcome::SessionAccepted(white.clone()),
        now(),
        &mut rng,
    );
    assert!(list.is_white(&white));

    let file = list.to_file_bytes(&mut NoBans, Tick::new(0));
    let mut restarted = Peerlist::new(RefusedSet::NON_GLOBAL);
    assert_eq!(restarted.restore_file(&file, &mut rng), Ok(mixed().len()));
    for address in mixed() {
        assert!(restarted.is_gray(&address), "{address:?} is gray");
        assert!(!restarted.is_white(&address), "{address:?} is not white");
    }
    assert_eq!(
        sorted(restarted.persistable(&mut NoBans, Tick::new(0))),
        sorted(mixed()),
        "the same set comes back"
    );
}

#[test]
fn a_file_of_another_version_is_dropped_whole() {
    let mut rng = SplitMix64::new(2);
    let good = encode(&mixed());
    for other in [
        0,
        ADDRESS_FILE_VERSION - 1,
        ADDRESS_FILE_VERSION + 1,
        u32::MAX,
    ] {
        if other == ADDRESS_FILE_VERSION {
            continue;
        }
        // The same entries under another version number.
        let mut file = good.clone();
        file[8..12].copy_from_slice(&other.to_le_bytes());
        assert_eq!(
            decode(&file),
            Err(AddressFileError::Version { found: other })
        );

        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        list.admit_gray(&v4(9), Source::Operator, now(), &mut NoBans, &mut rng)
            .expect("admitted");
        assert_eq!(
            list.restore_file(&file, &mut rng),
            Err(AddressFileError::Version { found: other })
        );
        assert_eq!(
            list.persistable(&mut NoBans, Tick::new(0)),
            vec![v4(9)],
            "version {other}: nothing of the file was admitted"
        );
    }
}

#[test]
fn bytes_that_are_not_an_address_file_are_dropped_whole() {
    // The C++ p2pstate.bin is a boost portable binary archive; its first
    // bytes are not the magic. Neither is an empty or a short file.
    for bytes in [
        &b""[..],
        &b"SKL"[..],
        &b"\x01\x00\x00\x00\x00\x00\x00\x00serialization::archive"[..],
        &b"sklpeers\x01\x00\x00\x00\x00\x00\x00\x00"[..],
    ] {
        assert_eq!(decode(bytes), Err(AddressFileError::NotAnAddressFile));
    }
}

#[test]
fn every_truncation_of_a_file_is_an_error_and_never_a_shorter_list() {
    let file = encode(&mixed());
    for cut in 0..file.len() {
        assert!(
            decode(&file[..cut]).is_err(),
            "the first {cut} of {} bytes decoded",
            file.len()
        );
    }
    let mut longer = file.clone();
    longer.push(0);
    assert_eq!(decode(&longer), Err(AddressFileError::TrailingBytes));
}

#[test]
fn a_count_over_the_cap_is_refused_before_any_entry_is_read() {
    let over = u32::try_from(MAX_ENTRIES + 1).expect("fits");
    assert_eq!(
        decode(&header(ADDRESS_FILE_VERSION, over)),
        Err(AddressFileError::TooManyEntries { declared: over })
    );
    assert_eq!(
        decode(&header(ADDRESS_FILE_VERSION, u32::MAX)),
        Err(AddressFileError::TooManyEntries { declared: u32::MAX })
    );
    // At the cap the count is accepted and the missing entries are what fails.
    let at = u32::try_from(MAX_ENTRIES).expect("fits");
    assert_eq!(
        decode(&header(ADDRESS_FILE_VERSION, at)),
        Err(AddressFileError::Truncated)
    );
}

#[test]
fn an_unknown_tag_and_a_bad_host_drop_the_file() {
    let mut unknown = header(ADDRESS_FILE_VERSION, 1);
    unknown.extend_from_slice(&[9, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        decode(&unknown),
        Err(AddressFileError::UnknownTag { tag: 9 })
    );

    let mut bad_host = header(ADDRESS_FILE_VERSION, 1);
    bad_host.extend_from_slice(&[3, 2, 0xff, 0xfe, 0x90, 0x1f]);
    assert_eq!(decode(&bad_host), Err(AddressFileError::HostNotUtf8));
}

#[test]
fn the_file_carries_no_refused_address_without_the_flag() {
    let mut rng = SplitMix64::new(3);
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 7, 7),
        port: 18080,
    };
    let mut strict = Peerlist::new(RefusedSet::NON_GLOBAL);
    let mut open = Peerlist::new(RefusedSet::EMPTY);
    for list in [&mut strict, &mut open] {
        for address in [v4(1), private.clone()] {
            list.admit_gray(&address, Source::Operator, now(), &mut NoBans, &mut rng)
                .expect("operator");
        }
    }
    assert_eq!(
        decode(&strict.to_file_bytes(&mut NoBans, Tick::new(0))),
        Ok(vec![v4(1)])
    );
    let written = decode(&open.to_file_bytes(&mut NoBans, Tick::new(0))).expect("file");
    assert!(written.contains(&private), "written under the flag");

    // The flagged file does not seed a node started without the flag.
    let mut restarted = Peerlist::new(RefusedSet::NON_GLOBAL);
    assert_eq!(
        restarted.restore_file(&open.to_file_bytes(&mut NoBans, Tick::new(0)), &mut rng),
        Ok(1)
    );
    assert!(!restarted.is_gray(&private));
}

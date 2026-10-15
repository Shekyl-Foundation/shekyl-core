// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake frame bound is derived (Rick, 2026-10-13): the largest
//! entry this codec writes, times the disclosure count, plus the largest
//! fixed part. These tests encode those objects and pin the two sizes
//! the bound is built from, so a codec change that moves either reds here
//! before it can move the bound silently.
//!
//! The entry's size is what one more entry adds to a message that already
//! carries one — its bytes inside the array, without the array's own
//! envelope — and the fixed part of a message that carries a list includes
//! that envelope. Measured that way, a full disclosure fits the bound and
//! one entry more does not.

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_levin::{
    ingress_payload_cap, BasicNodeData, CoreSyncData, Flags, HandshakeRequest, HandshakeResponse,
    NetworkAddress, PeerlistEntry, PortableMap, SupportFlags, TimedSyncRequest, TimedSyncResponse,
    COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC, HANDSHAKE_FIXED_MAX_BYTES,
    PEERLIST_ENTRY_MAX_ENCODED_BYTES,
};
use shekyl_peer_bounds::DISCLOSE_COUNT;

/// The largest entry: a v3 onion host (56 base32 characters and `.onion`)
/// and the largest port. The entry is its address (PR-3: `last_seen` is
/// gone from the wire).
fn largest_entry() -> PeerlistEntry {
    PeerlistEntry {
        adr: NetworkAddress::Tor {
            host: format!("{}.onion", "a".repeat(56)),
            port: u16::MAX,
        },
    }
}

fn node() -> BasicNodeData {
    BasicNodeData {
        network_id: [0xff; 16],
        support_flags: SupportFlags::from_bits(u32::MAX),
    }
}

/// Every optional field at a value that is stored.
fn sync_data() -> CoreSyncData {
    CoreSyncData {
        current_height: u64::MAX,
        cumulative_difficulty: u64::MAX,
        cumulative_difficulty_top64: u64::MAX,
        top_id: [0xff; 32],
    }
}

fn encoded_len<T: PortableMap>(value: &T) -> u64 {
    u64::try_from(value.store().expect("encodes").len()).expect("fits")
}

fn response_with(entries: usize) -> HandshakeResponse {
    HandshakeResponse {
        node_data: node(),
        payload_data: sync_data(),
        local_peerlist_new: (0..entries).map(|_| largest_entry()).collect(),
    }
}

fn timed_response_with(entries: usize) -> TimedSyncResponse {
    TimedSyncResponse {
        payload_data: sync_data(),
        local_peerlist_new: (0..entries).map(|_| largest_entry()).collect(),
    }
}

/// What one more largest entry adds to a message that already carries one.
fn entry_delta() -> u64 {
    encoded_len(&response_with(2)) - encoded_len(&response_with(1))
}

#[test]
fn the_largest_peerlist_entry_adds_the_pinned_size_to_a_message() {
    assert_eq!(entry_delta(), PEERLIST_ENTRY_MAX_ENCODED_BYTES);
    assert_eq!(
        encoded_len(&timed_response_with(2)) - encoded_len(&timed_response_with(1)),
        PEERLIST_ENTRY_MAX_ENCODED_BYTES,
        "the entry costs the same in a timed sync"
    );
    // The other arms are smaller: the pin is the maximum, not one arm's size.
    let added_by = |adr: NetworkAddress| {
        let mut with = response_with(1);
        with.local_peerlist_new.push(PeerlistEntry { adr });
        encoded_len(&with) - encoded_len(&response_with(1))
    };
    assert!(
        added_by(NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(255, 255, 255, 255),
            port: u16::MAX,
        }) < PEERLIST_ENTRY_MAX_ENCODED_BYTES
    );
    assert!(
        added_by(NetworkAddress::Ipv6 {
            ip: Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            port: u16::MAX,
        }) < PEERLIST_ENTRY_MAX_ENCODED_BYTES
    );
}

/// The fixed part is everything but the entries: for a message that
/// carries a list, the list's own envelope is part of it, so it is
/// measured from a one-entry message with the entry's delta taken off.
#[test]
fn the_largest_fixed_part_encodes_to_the_pinned_size() {
    let request = HandshakeRequest {
        node_data: node(),
        payload_data: sync_data(),
        nonce: [0xff; 32],
    };
    let timed_request = TimedSyncRequest {
        payload_data: sync_data(),
    };
    let delta = entry_delta();
    let largest = [
        encoded_len(&request),
        encoded_len(&response_with(1)) - delta,
        encoded_len(&timed_request),
        encoded_len(&timed_response_with(1)) - delta,
    ]
    .into_iter()
    .max()
    .expect("four");
    assert_eq!(largest, HANDSHAKE_FIXED_MAX_BYTES);
}

/// A full message — `DISCLOSE_COUNT` largest entries beside the largest
/// fixed part — fits the cap, and one more entry does not: the bound is
/// tight to the count, not an envelope with room for a 13th.
#[test]
fn a_full_disclosure_fits_the_cap_and_one_more_entry_does_not() {
    let cap = ingress_payload_cap(COMMAND_HANDSHAKE, Flags::RESPONSE).expect("defined");
    assert_eq!(
        cap,
        ingress_payload_cap(COMMAND_TIMED_SYNC, Flags::RESPONSE).expect("defined")
    );
    for (full, one_more) in [
        (
            encoded_len(&response_with(DISCLOSE_COUNT)),
            encoded_len(&response_with(DISCLOSE_COUNT + 1)),
        ),
        (
            encoded_len(&timed_response_with(DISCLOSE_COUNT)),
            encoded_len(&timed_response_with(DISCLOSE_COUNT + 1)),
        ),
    ] {
        assert!(full <= cap, "{full} > {cap}");
        assert!(one_more > cap, "{one_more} <= {cap}");
    }
}

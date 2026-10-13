// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The address file on disk (slice 1 brief §7): named at start and read
//! back into gray; written every [`STORE_INTERVAL_NANOS`] by the owner
//! loop and once more at stop; a file this build cannot read is dropped
//! whole and replaced at the next store.
//!
//! The loop's call is `store_if_due` at each wake; the interval is pinned
//! here on that function, and the loop's call site is read, not run.

use std::net::Ipv4Addr;
use std::sync::Arc;

use shekyl_dialer::{AddressStore, Dialer, LoadError, STORE_INTERVAL_NANOS};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::SupportFlags;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::address_file::AddressFileError;
use shekyl_peerlist::{ConnectorId, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{Hub, SyncPayload};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::Sockets;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 15, 0, n),
        port: 18080,
    }
}

fn dialer() -> (Arc<Dialer>, ManualClock) {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(clock.clone()),
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
    (dialer, clock)
}

#[test]
fn a_missing_file_is_a_first_start_and_the_first_store_creates_it() {
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("p2pstate.bin");
    let (dialer, _clock) = dialer();
    let mut rng = SplitMix64::new(1);
    assert_eq!(
        dialer
            .open_address_file(path.clone(), &mut rng)
            .expect("opened"),
        0
    );
    assert!(!path.exists(), "opening does not create the file");
    dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    assert!(dialer.store_addresses().expect("stored"));
    assert_eq!(
        AddressStore::new(path).load().expect("readable"),
        vec![peer(1)]
    );
}

#[test]
fn a_fresh_open_of_a_stored_file_puts_every_address_on_gray() {
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("p2pstate.bin");
    let mut rng = SplitMix64::new(2);
    {
        let (dialer, _clock) = dialer();
        dialer
            .open_address_file(path.clone(), &mut rng)
            .expect("opened");
        for n in 1..=5 {
            dialer
                .admit_operator(&peer(n), Tick::new(1), &mut rng)
                .expect("admitted");
        }
        assert!(dialer.store_addresses().expect("stored"));
    }
    let (restarted, _clock) = dialer();
    assert_eq!(
        restarted.open_address_file(path, &mut rng).expect("opened"),
        5
    );
    let shared = restarted.shared();
    for n in 1..=5 {
        assert!(shared.lists.is_gray(&peer(n)), "peer {n} is gray");
        assert!(!shared.lists.is_white(&peer(n)), "peer {n} is not white");
    }
}

#[test]
fn no_store_was_named_so_nothing_is_written() {
    let (dialer, _clock) = dialer();
    assert!(!dialer.store_addresses().expect("no store"));
    assert!(!dialer.store_if_due(Tick::new(u64::MAX)).expect("no store"));
}

#[test]
fn a_file_this_build_cannot_read_is_dropped_whole_and_replaced_at_the_next_store() {
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("p2pstate.bin");
    // The C++ peerlist's file, as a previous build left it: not the magic.
    std::fs::write(&path, b"\x01\x00\x00\x00boost archive bytes").expect("written");
    let (dialer, _clock) = dialer();
    let mut rng = SplitMix64::new(3);
    dialer
        .admit_operator(&peer(9), Tick::new(1), &mut rng)
        .expect("admitted");
    match dialer.open_address_file(path.clone(), &mut rng) {
        Err(LoadError::Dropped(AddressFileError::NotAnAddressFile)) => {}
        other => panic!("expected the file dropped as not an address file, got {other:?}"),
    }
    let shared = dialer.shared();
    assert!(
        shared.lists.is_gray(&peer(9)),
        "the lists are left as they were"
    );
    assert_eq!(shared.lists.gray_count(ConnectorId::Clearnet), 1);
    drop(shared);
    assert!(dialer.store_addresses().expect("stored"));
    assert_eq!(
        AddressStore::new(path).load().expect("readable now"),
        vec![peer(9)],
        "the next store replaced the unreadable file"
    );
}

#[test]
fn the_store_is_due_one_interval_after_the_open_and_stop_writes_once_more() {
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("p2pstate.bin");
    let (dialer, clock) = dialer();
    let mut rng = SplitMix64::new(4);
    let opened_at = clock.now();
    dialer
        .open_address_file(path.clone(), &mut rng)
        .expect("opened");
    dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let load = || AddressStore::new(path.clone()).load().expect("readable");

    // Not yet due: nothing written.
    let before = Tick::new(opened_at.get() + STORE_INTERVAL_NANOS - 1);
    assert!(!dialer.store_if_due(before).expect("not due"));
    assert!(!path.exists());

    // Due: written, and the clock of the last store moves.
    let due = Tick::new(opened_at.get() + STORE_INTERVAL_NANOS);
    clock.set(due);
    assert!(dialer.store_if_due(due).expect("due"));
    assert_eq!(load(), vec![peer(1)]);
    dialer
        .admit_operator(&peer(2), Tick::new(1), &mut rng)
        .expect("admitted");
    assert!(!dialer
        .store_if_due(Tick::new(due.get() + 1))
        .expect("not due again"));
    assert_eq!(
        load(),
        vec![peer(1)],
        "the second address waits for the next interval"
    );

    // Stop writes once more, whatever the clock.
    dialer.stop();
    assert_eq!(load(), vec![peer(1), peer(2)]);
}

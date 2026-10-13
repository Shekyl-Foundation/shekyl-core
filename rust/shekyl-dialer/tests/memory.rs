// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The failed-address memory: which reports write it, on which
//! connector, for how long, and what clears it.

use std::net::Ipv4Addr;

use shekyl_dialer::memory::{window_nanos, FIRST_WINDOW_NANOS, WINDOW_CAP_NANOS};
use shekyl_dialer::FailedAddresses;
use shekyl_peerlist::{CloseCause, CloseKind, DialOutcome, NetworkAddress, Tick};

const SECOND: u64 = 1_000_000_000;

fn clearnet(port: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 9, 0, 1),
        port,
    }
}

fn onion(port: u16) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{:0>56}.onion", 4),
        port,
    }
}

fn at(nanos: u64) -> Tick {
    Tick::new(nanos)
}

/// Every cause a dial can end with: each kind, and every proxy reply.
fn every_cause() -> Vec<CloseCause> {
    let mut out: Vec<CloseCause> = CloseKind::ALL
        .iter()
        .filter(|kind| **kind != CloseKind::ProxyRefused)
        .map(|kind| CloseCause::new(*kind))
        .collect();
    out.extend((0u16..=0x0100).map(CloseCause::proxy_refused));
    out
}

#[test]
fn no_clearnet_report_writes_the_memory() {
    let mut memory = FailedAddresses::new();
    let address = clearnet(18080);
    for cause in every_cause() {
        memory.observe(&DialOutcome::DialFailed(address.clone(), cause), at(SECOND));
    }
    memory.observe(&DialOutcome::PeerlistRefused(address.clone()), at(SECOND));
    memory.observe(&DialOutcome::PayloadRefused(address.clone()), at(SECOND));
    assert!(
        memory.is_empty(),
        "R2: clearnet writes nothing, for every cause"
    );
    assert!(!memory.is_recently_failed(&address, at(SECOND)));
}

#[test]
fn on_tor_only_a_rejection_and_the_five_replies_write_the_memory() {
    let mut writers = Vec::new();
    for cause in every_cause() {
        let mut memory = FailedAddresses::new();
        memory.observe(&DialOutcome::DialFailed(onion(18080), cause), at(SECOND));
        if memory.is_recently_failed(&onion(18080), at(SECOND)) {
            writers.push((cause.kind(), cause.reply_code()));
        }
    }
    assert_eq!(
        writers,
        vec![
            (CloseKind::LevinHandshakeRejected, 0),
            (CloseKind::ProxyRefused, 0x04),
            (CloseKind::ProxyRefused, 0x05),
            (CloseKind::ProxyRefused, 0xF0),
            (CloseKind::ProxyRefused, 0xF1),
            (CloseKind::ProxyRefused, 0xF2),
        ]
    );

    // A refused peerlist is the same close as a rejected handshake.
    let mut memory = FailedAddresses::new();
    memory.observe(&DialOutcome::PeerlistRefused(onion(18080)), at(SECOND));
    assert!(memory.is_recently_failed(&onion(18080), at(SECOND)));

    // A refused payload is not a failure of the address: the peer answered.
    let mut memory = FailedAddresses::new();
    memory.observe(&DialOutcome::PayloadRefused(onion(18080)), at(SECOND));
    assert!(memory.is_empty());
}

#[test]
fn the_key_is_host_and_port() {
    let mut memory = FailedAddresses::new();
    let refused = DialOutcome::DialFailed(onion(18080), CloseCause::proxy_refused(0x05));
    memory.observe(&refused, at(SECOND));
    assert!(memory.is_recently_failed(&onion(18080), at(SECOND)));
    assert!(
        !memory.is_recently_failed(&onion(18081), at(SECOND)),
        "a refused port does not suppress another port on that host"
    );
}

#[test]
fn the_window_starts_short_doubles_and_is_capped_at_the_hour() {
    assert_eq!(FIRST_WINDOW_NANOS, 240 * SECOND);
    assert_eq!(WINDOW_CAP_NANOS, 3600 * SECOND);
    let seconds: Vec<u64> = (1..=8).map(|n| window_nanos(n) / SECOND).collect();
    assert_eq!(seconds, vec![240, 480, 960, 1920, 3600, 3600, 3600, 3600]);
    assert_eq!(
        window_nanos(0),
        FIRST_WINDOW_NANOS,
        "no failure is not a longer window"
    );
    assert_eq!(window_nanos(u32::MAX), WINDOW_CAP_NANOS);
}

#[test]
fn an_address_is_suppressed_through_the_last_nanosecond_of_its_window() {
    let mut memory = FailedAddresses::new();
    let address = onion(18080);
    let failed = DialOutcome::DialFailed(address.clone(), CloseCause::proxy_refused(0x04));
    let start = 10 * SECOND;

    memory.observe(&failed, at(start));
    assert!(memory.is_recently_failed(&address, at(start + FIRST_WINDOW_NANOS)));
    assert!(!memory.is_recently_failed(&address, at(start + FIRST_WINDOW_NANOS + 1)));

    // A second failure in a row doubles the window, counted from it.
    let second = start + 1_000 * SECOND;
    memory.observe(&failed, at(second));
    assert!(memory.is_recently_failed(&address, at(second + 2 * FIRST_WINDOW_NANOS)));
    assert!(!memory.is_recently_failed(&address, at(second + 2 * FIRST_WINDOW_NANOS + 1)));

    // Thousands of failures later the window is the hour, not the short one.
    for _ in 0..5_000 {
        memory.observe(&failed, at(second));
    }
    assert!(memory.is_recently_failed(&address, at(second + WINDOW_CAP_NANOS)));
    assert!(!memory.is_recently_failed(&address, at(second + WINDOW_CAP_NANOS + 1)));
}

#[test]
fn a_confirmed_or_accepted_dial_clears_the_address_and_its_count() {
    for clear in [
        DialOutcome::Confirmed as fn(NetworkAddress) -> DialOutcome,
        DialOutcome::SessionAccepted,
    ] {
        let mut memory = FailedAddresses::new();
        let address = onion(18080);
        let failed = DialOutcome::DialFailed(address.clone(), CloseCause::proxy_refused(0xF2));
        memory.observe(&failed, at(SECOND));
        memory.observe(&failed, at(SECOND));
        assert!(memory.is_recently_failed(&address, at(SECOND)));

        memory.observe(&clear(address.clone()), at(2 * SECOND));
        assert!(!memory.is_recently_failed(&address, at(2 * SECOND)));
        assert!(memory.is_empty());

        // The history is gone: the next failure earns the short window.
        memory.observe(&failed, at(3 * SECOND));
        assert!(!memory.is_recently_failed(&address, at(3 * SECOND + FIRST_WINDOW_NANOS + 1)));
    }
}

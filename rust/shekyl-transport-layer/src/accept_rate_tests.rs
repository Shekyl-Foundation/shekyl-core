// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use shekyl_timing_engine::Tick;

use super::*;
use crate::declaration::{declaration, BannableInbound};

const SECOND: u64 = 1_000_000_000;

/// A test shape, not a ruled value: the mechanism is exercised with rates
/// the table does not hold.
const fn rate(token_every_nanos: u64, burst: u32) -> AcceptRate {
    AcceptRate {
        token_every_nanos,
        burst,
    }
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
}

fn gate(connector: AcceptRate, host: AcceptRate) -> AcceptGate {
    AcceptGate::new(connector, host).expect("a rate")
}

#[test]
fn a_host_spends_its_burst_then_waits_one_interval_per_token() {
    let mut gate = gate(rate(1, 1_000), rate(SECOND, 3));
    for spend in 0..3 {
        assert!(
            gate.admit(v4(1), Tick::new(0)),
            "spend {spend} of the burst"
        );
    }
    assert!(!gate.admit(v4(1), Tick::new(0)), "the burst is spent");
    assert!(
        !gate.admit(v4(1), Tick::new(SECOND - 1)),
        "one nanosecond early"
    );
    assert!(
        gate.admit(v4(1), Tick::new(SECOND)),
        "one interval refills one token"
    );
    assert!(!gate.admit(v4(1), Tick::new(SECOND)));
}

#[test]
fn an_idle_bucket_refills_to_its_burst_and_no_further() {
    let mut gate = gate(rate(1, 1_000), rate(SECOND, 2));
    assert!(gate.admit(v4(1), Tick::new(0)));
    assert!(gate.admit(v4(1), Tick::new(0)));
    let later = Tick::new(100 * SECOND);
    assert!(gate.admit(v4(1), later));
    assert!(gate.admit(v4(1), later));
    assert!(
        !gate.admit(v4(1), later),
        "a long idle is still a burst of two"
    );
}

#[test]
fn a_host_refused_by_its_own_bucket_does_not_drain_the_connector() {
    let mut gate = gate(rate(SECOND, 4), rate(SECOND, 1));
    assert!(gate.admit(v4(1), Tick::new(0)));
    for _ in 0..10 {
        assert!(!gate.admit(v4(1), Tick::new(0)));
    }
    for other in 2..5 {
        assert!(
            gate.admit(v4(other), Tick::new(0)),
            "host {other} still finds the connector's tokens"
        );
    }
    assert!(
        !gate.admit(v4(9), Tick::new(0)),
        "the connector's burst is four"
    );
}

#[test]
fn a_connector_refusal_leaves_no_host_entry() {
    let mut gate = gate(rate(SECOND, 1), rate(SECOND, 5));
    assert!(gate.admit(v4(1), Tick::new(0)));
    assert!(!gate.admit(v4(2), Tick::new(0)));
    assert_eq!(gate.host_entries(), 1);
    assert!(
        gate.admit(v4(2), Tick::new(SECOND)),
        "the refused host spent nothing"
    );
}

#[test]
fn an_ipv4_address_carried_in_ipv6_is_that_ipv4_host() {
    let mapped = |last: u8| IpAddr::V6(Ipv4Addr::new(192, 0, 2, last).to_ipv6_mapped());
    assert_eq!(HostKey::of(mapped(7)), HostKey::of(v4(7)));
    assert_ne!(
        HostKey::of(mapped(7)),
        HostKey::of(mapped(8)),
        "two IPv4 hosts behind a dual-stack listener are two hosts, not one /64"
    );
    let mut gate = gate(rate(1, 1_000), rate(SECOND, 1));
    assert!(gate.admit(v4(7), Tick::new(0)));
    assert!(!gate.admit(mapped(7), Tick::new(0)));
    assert!(gate.admit(mapped(8), Tick::new(0)));
}

#[test]
fn an_ipv6_host_is_its_64() {
    let a = v6([0x2001, 0xdb8, 1, 2, 0, 0, 0, 1]);
    let same_64 = v6([0x2001, 0xdb8, 1, 2, 0xffff, 0xffff, 0xffff, 0xffff]);
    let next_64 = v6([0x2001, 0xdb8, 1, 3, 0, 0, 0, 1]);
    assert_eq!(HostKey::of(a), HostKey::of(same_64));
    assert_ne!(HostKey::of(a), HostKey::of(next_64));
    let mut gate = gate(rate(1, 1_000), rate(SECOND, 1));
    assert!(gate.admit(a, Tick::new(0)));
    assert!(
        !gate.admit(same_64, Tick::new(0)),
        "walking the low 64 bits is one host"
    );
    assert!(gate.admit(next_64, Tick::new(0)));
}

/// A flooder walking a fresh /64 on every connection, far faster than the
/// connector admits, for ten simulated minutes: the host table never holds
/// more than twice the live bound, plus the sweep floor.
#[test]
fn a_flood_of_fresh_64s_cannot_grow_the_host_table_past_its_bound() {
    let mut gate = gate(rate(SECOND / 20, 40), rate(10 * SECOND, 3));
    let ceiling = usize::try_from(gate.live_host_bound()).expect("small") * 2 + SWEEP_FLOOR;
    let mut admitted = 0u64;
    let step = SECOND / 1_000;
    for i in 0..600_000u64 {
        let [a, b, c, d] = (u32::try_from(i % u64::from(u32::MAX)).expect("fits")).to_be_bytes();
        let host = v6([
            0x2001,
            0xdb8,
            u16::from_be_bytes([a, b]),
            u16::from_be_bytes([c, d]),
            0,
            0,
            0,
            1,
        ]);
        if gate.admit(host, Tick::new(i * step)) {
            admitted += 1;
        }
        assert!(
            gate.host_entries() <= ceiling,
            "at {i}: {} entries over {ceiling}",
            gate.host_entries()
        );
    }
    // The connector's rate, 20 a second, over the ten minutes, plus its burst.
    assert_eq!(admitted, 600 * 20 + 40 - 1);
}

#[test]
fn a_rate_with_no_interval_or_no_burst_is_not_a_rate() {
    assert!(AcceptGate::new(rate(0, 1), rate(SECOND, 1)).is_none());
    assert!(AcceptGate::new(rate(SECOND, 1), rate(SECOND, 0)).is_none());
    assert!(AcceptGate::new(rate(SECOND, 1), rate(SECOND, 1)).is_some());
}

/// A refill instant past the clock's end refuses rather than saturating:
/// a saturated bucket would never move again and would pay for every
/// later connection.
#[test]
fn the_end_of_the_clock_refuses_instead_of_saturating() {
    let mut gate = gate(rate(SECOND, 2), rate(SECOND, 2));
    assert!(gate.admit(v4(1), Tick::new(u64::MAX - 2 * SECOND)));
    assert!(gate.admit(v4(1), Tick::new(u64::MAX - 2 * SECOND)));
    assert!(
        !gate.admit(v4(1), Tick::new(u64::MAX - 2 * SECOND)),
        "the burst is spent"
    );
    let end = Tick::new(u64::MAX);
    assert!(
        !gate.admit(v4(2), end),
        "no refill instant exists past the end"
    );
    assert!(!gate.admit(v4(2), end));
}

/// The row follows the declaration: a connector whose inbound peers are
/// the zone has no daemon-side limiter, and one whose peers have an
/// observable address is never given the onion's defence instead.
#[test]
fn each_connector_s_bound_matches_what_its_declaration_observes() {
    for connector in ConnectorId::ALL {
        let observed = declaration(connector.column()).bannable_inbound();
        let bound = accept_bound(*connector);
        match observed {
            Assessment::Assessed(BannableInbound::NoAddress) => {
                assert_eq!(
                    bound,
                    Assessment::Assessed(AcceptBound::OnionPow),
                    "{connector:?}"
                );
            }
            Assessment::Assessed(BannableInbound::Yes) | Assessment::NotAssessed => {
                assert_ne!(
                    bound,
                    Assessment::Assessed(AcceptBound::OnionPow),
                    "{connector:?}"
                );
            }
        }
        if let Assessment::Assessed(AcceptBound::ConnectorAndHost { connector: c, host }) = bound {
            assert!(c.is_rate() && host.is_rate(), "{connector:?}");
        }
    }
}

/// The linger cap is what the connector admits in one span: its burst plus
/// one per interval across the span.
#[test]
fn the_linger_cap_is_what_the_connector_admits_in_one_span() {
    let gate = gate(rate(SECOND / 10, 4), rate(SECOND, 1));
    assert_eq!(gate.linger_cap(Tick::new(1_426_000_000)), 4 + 14);
    assert_eq!(gate.linger_cap(Tick::new(0)), 4);
}

/// The reservation's figure and the gate's cap are one formula over the
/// row: a row with a limiter gives the gate's cap, and a row without one
/// (Tor's proof-of-work, or not assessed) reserves nothing.
#[test]
fn the_row_s_linger_cap_is_the_gate_s() {
    let span = Tick::new(1_426_000_000);
    let row = Assessment::Assessed(AcceptBound::ConnectorAndHost {
        connector: rate(SECOND / 10, 4),
        host: rate(SECOND, 1),
    });
    let gate = AcceptGate::for_bound(row).expect("a rate");
    assert_eq!(linger_cap(row, span), 18);
    assert_eq!(
        usize::try_from(linger_cap(row, span)).expect("small"),
        gate.linger_cap(span)
    );
    assert_eq!(
        linger_cap(Assessment::Assessed(AcceptBound::OnionPow), span),
        0
    );
    assert_eq!(linger_cap(Assessment::NotAssessed, span), 0);
    for connector in ConnectorId::ALL {
        let gate = AcceptGate::for_bound(accept_bound(*connector));
        assert_eq!(
            linger_cap(accept_bound(*connector), span),
            gate.map_or(0, |g| u64::try_from(g.linger_cap(span)).expect("small")),
            "{connector:?}"
        );
    }
}
